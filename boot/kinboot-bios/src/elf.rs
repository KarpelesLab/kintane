//! What stage 2 needs from the kernel's ELF file, and nothing more.
//!
//! The kernel is read from disk in chunks and each chunk is copied straight to where it
//! belongs, so the file is never held whole anywhere. That shapes the interface:
//! [`Image::parse`] validates everything from the file's first chunk, and
//! [`Image::copy_plan`] then says, for any later chunk, which bytes go where.
//!
//! The file is **untrusted input**. A disk can be corrupt, or built by something other
//! than `kbuild`. Every check below exists so that a bad kernel stops the loader with
//! a named reason instead of writing over the loader itself, the IVT or firmware memory:
//!
//! - an ELF32, little-endian, `EM_386`, `ET_EXEC` file with 32-byte program headers;
//! - at most [`MAX_SEGMENTS`] headers, all inside the first chunk;
//! - every `PT_LOAD` has `filesz <= memsz`, lies inside the file, does not wrap 4 GiB, and loads at
//!   or above the floor the loader gives (1 MiB: below it are the loader, its buffers and the
//!   BIOS);
//! - a Multiboot 1 header in the first 8 KiB, with a valid checksum and no required feature this
//!   loader does not provide.
//!
//! Whether the load addresses are actually RAM is checked separately, against the
//! firmware's map, by [`Image::check_placement`].

use crate::memmap::MemoryMap;

/// Program headers kept. A linked kernel has three or four loadable segments.
pub const MAX_SEGMENTS: usize = 16;

/// Where the Multiboot 1 specification requires its header to be: within the first
/// 8192 bytes, aligned to 4.
const MULTIBOOT_SEARCH: usize = 8192;
const MULTIBOOT_HEADER_MAGIC: u32 = 0x1BAD_B002;
/// Required-feature bits this loader honours: page-aligned modules (trivially, since it
/// loads none) and memory information (it always supplies a map).
const MULTIBOOT_SUPPORTED: u32 = (1 << 0) | (1 << 1);
/// The a.out kludge. Its load addresses replace the ELF's, and this loader loads ELF.
const MULTIBOOT_AOUT_KLUDGE: u32 = 1 << 16;

const PT_LOAD: u32 = 1;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Error {
    /// The first chunk cannot hold the ELF header and program headers.
    Truncated,
    NotElf,
    /// Not ELF32 little-endian.
    WrongClass,
    /// Not an `EM_386` executable.
    WrongMachine(u16),
    NotExecutable(u16),
    BadPhentsize(u16),
    TooManySegments(u16),
    /// A loadable segment claims more file bytes than it has memory, or bytes past the
    /// end of the file.
    SegmentBounds {
        index: usize,
    },
    /// A loadable segment wraps past 4 GiB.
    SegmentWraps {
        index: usize,
    },
    /// A loadable segment would be written below the loader's floor.
    BelowFloor {
        index: usize,
        paddr: u32,
    },
    /// A loadable segment is not entirely inside usable RAM.
    NotRam {
        index: usize,
        paddr: u32,
    },
    NoLoadableSegment,
    NoMultibootHeader,
    MultibootChecksum,
    /// The header requires a feature this loader does not provide.
    MultibootUnsupported(u32),
}

/// One `PT_LOAD` segment.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Segment {
    pub offset: u32,
    pub paddr: u32,
    pub filesz: u32,
    pub memsz: u32,
}

/// A validated kernel image.
#[derive(Clone, Copy, Debug)]
pub struct Image {
    pub entry: u32,
    segments: [Segment; MAX_SEGMENTS],
    count: usize,
}

/// One copy stage 2 must make from the chunk it holds.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Copy {
    /// Offset into the chunk.
    pub from: usize,
    pub len: usize,
    /// Physical destination.
    pub to: u32,
}

fn le16(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}

fn le32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

impl Image {
    /// Validate the image from its first `first.len()` bytes. `file_len` is the whole
    /// file's length, from the disk header; `floor` is the lowest address a segment may
    /// load at.
    pub fn parse(first: &[u8], file_len: u32, floor: u32) -> Result<Image, Error> {
        if first.len() < 52 {
            return Err(Error::Truncated);
        }
        if first[0..4] != *b"\x7fELF" {
            return Err(Error::NotElf);
        }
        // EI_CLASS 1 is 32-bit, EI_DATA 1 is little-endian.
        if first[4] != 1 || first[5] != 1 {
            return Err(Error::WrongClass);
        }
        let e_type = le16(first, 16);
        let machine = le16(first, 18);
        if machine != 3 {
            return Err(Error::WrongMachine(machine));
        }
        if e_type != 2 {
            return Err(Error::NotExecutable(e_type));
        }
        let entry = le32(first, 24);
        let phoff = le32(first, 28) as usize;
        let phentsize = le16(first, 42);
        let phnum = le16(first, 44);
        if phentsize != 32 {
            return Err(Error::BadPhentsize(phentsize));
        }
        if phnum as usize > MAX_SEGMENTS {
            return Err(Error::TooManySegments(phnum));
        }
        let ph_end = phoff
            .checked_add(phnum as usize * 32)
            .ok_or(Error::Truncated)?;
        if ph_end > first.len() {
            return Err(Error::Truncated);
        }

        let mut image = Image {
            entry,
            segments: [Segment::default(); MAX_SEGMENTS],
            count: 0,
        };
        for i in 0..phnum as usize {
            let ph = &first[phoff + i * 32..phoff + (i + 1) * 32];
            if le32(ph, 0) != PT_LOAD {
                continue;
            }
            let seg = Segment {
                offset: le32(ph, 4),
                paddr: le32(ph, 12),
                filesz: le32(ph, 16),
                memsz: le32(ph, 20),
            };
            let index = image.count;
            if seg.memsz == 0 {
                continue;
            }
            if seg.filesz > seg.memsz
                || seg
                    .offset
                    .checked_add(seg.filesz)
                    .is_none_or(|e| e > file_len)
            {
                return Err(Error::SegmentBounds { index });
            }
            if seg.paddr.checked_add(seg.memsz).is_none() {
                return Err(Error::SegmentWraps { index });
            }
            if seg.paddr < floor {
                return Err(Error::BelowFloor {
                    index,
                    paddr: seg.paddr,
                });
            }
            image.segments[image.count] = seg;
            image.count += 1;
        }
        if image.count == 0 {
            return Err(Error::NoLoadableSegment);
        }
        check_multiboot_header(first)?;
        Ok(image)
    }

    pub fn segments(&self) -> &[Segment] {
        &self.segments[..self.count]
    }

    /// Every segment must land in RAM the firmware says is free.
    pub fn check_placement(&self, map: &MemoryMap) -> Result<(), Error> {
        for (index, s) in self.segments().iter().enumerate() {
            if !map.is_usable(s.paddr as u64, s.memsz as u64) {
                return Err(Error::NotRam {
                    index,
                    paddr: s.paddr,
                });
            }
        }
        Ok(())
    }

    /// The copies a chunk of the file at `chunk_offset` calls for, into `out`. Returns
    /// how many were written.
    ///
    /// A chunk can hold the end of one segment and the start of the next, and a segment
    /// can span many chunks; both come out right because each segment is intersected
    /// with the chunk independently.
    pub fn copy_plan(
        &self,
        chunk_offset: u32,
        chunk: &[u8],
        out: &mut [Copy; MAX_SEGMENTS],
    ) -> usize {
        let c_start = chunk_offset as u64;
        let c_end = c_start + chunk.len() as u64;
        let mut n = 0;
        for s in self.segments() {
            let s_start = s.offset as u64;
            let s_end = s_start + s.filesz as u64;
            let start = s_start.max(c_start);
            let end = s_end.min(c_end);
            if start >= end {
                continue;
            }
            out[n] = Copy {
                from: (start - c_start) as usize,
                len: (end - start) as usize,
                to: s.paddr + (start - s_start) as u32,
            };
            n += 1;
        }
        n
    }
}

/// Find and check the Multiboot 1 header.
fn check_multiboot_header(first: &[u8]) -> Result<(), Error> {
    let limit = first.len().min(MULTIBOOT_SEARCH);
    let mut at = 0;
    while at + 12 <= limit {
        if le32(first, at) == MULTIBOOT_HEADER_MAGIC {
            let flags = le32(first, at + 4);
            let checksum = le32(first, at + 8);
            if MULTIBOOT_HEADER_MAGIC
                .wrapping_add(flags)
                .wrapping_add(checksum)
                != 0
            {
                return Err(Error::MultibootChecksum);
            }
            let required = flags & 0xFFFF & !MULTIBOOT_SUPPORTED;
            if required != 0 || flags & MULTIBOOT_AOUT_KLUDGE != 0 {
                return Err(Error::MultibootUnsupported(flags));
            }
            return Ok(());
        }
        at += 4;
    }
    Err(Error::NoMultibootHeader)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal kernel in the shape `kbuild` links: segments at 1 MiB, a multiboot
    /// header at the start of the first one.
    fn kernel(segments: &[(u32, u32, u32, u32)], mb_flags: u32) -> Vec<u8> {
        let mut f = vec![0u8; 0x3000];
        f[0..4].copy_from_slice(b"\x7fELF");
        f[4] = 1;
        f[5] = 1;
        f[6] = 1;
        f[16..18].copy_from_slice(&2u16.to_le_bytes());
        f[18..20].copy_from_slice(&3u16.to_le_bytes());
        f[24..28].copy_from_slice(&0x10_000Cu32.to_le_bytes());
        f[28..32].copy_from_slice(&52u32.to_le_bytes());
        f[42..44].copy_from_slice(&32u16.to_le_bytes());
        f[44..46].copy_from_slice(&(segments.len() as u16).to_le_bytes());
        for (i, &(off, paddr, filesz, memsz)) in segments.iter().enumerate() {
            let ph = 52 + i * 32;
            f[ph..ph + 4].copy_from_slice(&PT_LOAD.to_le_bytes());
            f[ph + 4..ph + 8].copy_from_slice(&off.to_le_bytes());
            f[ph + 12..ph + 16].copy_from_slice(&paddr.to_le_bytes());
            f[ph + 16..ph + 20].copy_from_slice(&filesz.to_le_bytes());
            f[ph + 20..ph + 24].copy_from_slice(&memsz.to_le_bytes());
        }
        // The multiboot header, where the kernel's link script puts it.
        let mb = 0x1000;
        f[mb..mb + 4].copy_from_slice(&MULTIBOOT_HEADER_MAGIC.to_le_bytes());
        f[mb + 4..mb + 8].copy_from_slice(&mb_flags.to_le_bytes());
        let sum = 0u32
            .wrapping_sub(MULTIBOOT_HEADER_MAGIC)
            .wrapping_sub(mb_flags);
        f[mb + 8..mb + 12].copy_from_slice(&sum.to_le_bytes());
        f
    }

    const MIB: u32 = 0x10_0000;

    fn good() -> Vec<u8> {
        kernel(
            &[
                (0x1000, MIB, 0x1000, 0x1000),
                (0x2000, MIB + 0x1000, 0x800, 0x4000),
            ],
            0,
        )
    }

    #[test]
    fn a_kernel_shaped_image_parses() {
        let f = good();
        let img = Image::parse(&f, f.len() as u32, MIB).unwrap();
        assert_eq!(img.entry, 0x10_000C);
        assert_eq!(img.segments().len(), 2);
        assert_eq!(img.segments()[1].memsz, 0x4000);
    }

    #[test]
    fn header_rejections() {
        let f = good();
        let len = f.len() as u32;
        assert_eq!(Image::parse(&f[..40], len, MIB).unwrap_err(), Error::Truncated);

        let mut bad = f.clone();
        bad[1] = b'X';
        assert_eq!(Image::parse(&bad, len, MIB).unwrap_err(), Error::NotElf);

        let mut bad = f.clone();
        bad[4] = 2;
        assert_eq!(Image::parse(&bad, len, MIB).unwrap_err(), Error::WrongClass);

        let mut bad = f.clone();
        bad[18] = 62; // EM_X86_64: the unconverted x86_64 image
        assert_eq!(Image::parse(&bad, len, MIB).unwrap_err(), Error::WrongMachine(62));

        let mut bad = f.clone();
        bad[16] = 3;
        assert_eq!(Image::parse(&bad, len, MIB).unwrap_err(), Error::NotExecutable(3));

        let mut bad = f.clone();
        bad[42] = 56;
        assert_eq!(Image::parse(&bad, len, MIB).unwrap_err(), Error::BadPhentsize(56));

        let mut bad = f.clone();
        bad[44..46].copy_from_slice(&17u16.to_le_bytes());
        assert_eq!(Image::parse(&bad, len, MIB).unwrap_err(), Error::TooManySegments(17));

        // Program headers that run past the chunk the loader read.
        let mut bad = f.clone();
        bad[28..32].copy_from_slice(&0x2FF0u32.to_le_bytes());
        assert_eq!(Image::parse(&bad, len, MIB).unwrap_err(), Error::Truncated);
    }

    #[test]
    fn segment_rejections() {
        let file = |segs: &[(u32, u32, u32, u32)]| kernel(segs, 0);

        let f = file(&[(0x1000, MIB, 0x2000, 0x1000)]);
        assert_eq!(
            Image::parse(&f, f.len() as u32, MIB).unwrap_err(),
            Error::SegmentBounds { index: 0 }
        );

        let f = file(&[(0x1000, MIB, 0x1000, 0x1000)]);
        assert_eq!(Image::parse(&f, 0x1800, MIB).unwrap_err(), Error::SegmentBounds { index: 0 });

        let f = file(&[(0xFFFF_F000, MIB, 0x2000, 0x2000)]);
        assert_eq!(Image::parse(&f, u32::MAX, MIB).unwrap_err(), Error::SegmentBounds { index: 0 });

        let f = file(&[(0x1000, 0xFFFF_F000, 0x1000, 0x2000)]);
        assert_eq!(
            Image::parse(&f, f.len() as u32, MIB).unwrap_err(),
            Error::SegmentWraps { index: 0 }
        );

        // Loading over the loader, the IVT or the BIOS is refused before any byte moves.
        let f = file(&[(0x1000, 0x7E00, 0x1000, 0x1000)]);
        assert_eq!(
            Image::parse(&f, f.len() as u32, MIB).unwrap_err(),
            Error::BelowFloor {
                index: 0,
                paddr: 0x7E00
            }
        );

        let f = file(&[]);
        assert_eq!(Image::parse(&f, f.len() as u32, MIB).unwrap_err(), Error::NoLoadableSegment);
    }

    #[test]
    fn empty_and_non_load_segments_are_skipped() {
        let mut f = kernel(&[(0x1000, MIB, 0x1000, 0x1000), (0, 0, 0, 0)], 0);
        // Turn the second header into PT_GNU_STACK.
        f[52 + 32..52 + 36].copy_from_slice(&0x6474_E551u32.to_le_bytes());
        assert_eq!(
            Image::parse(&f, f.len() as u32, MIB)
                .unwrap()
                .segments()
                .len(),
            1
        );
    }

    #[test]
    fn multiboot_header_checks() {
        let mut f = good();
        f[0x1008] ^= 1;
        assert_eq!(Image::parse(&f, f.len() as u32, MIB).unwrap_err(), Error::MultibootChecksum);

        // Bit 2 (video mode) is a required feature we do not provide.
        let f = kernel(&[(0x1000, MIB, 0x1000, 0x1000)], 1 << 2);
        assert_eq!(
            Image::parse(&f, f.len() as u32, MIB).unwrap_err(),
            Error::MultibootUnsupported(4)
        );

        let f = kernel(&[(0x1000, MIB, 0x1000, 0x1000)], MULTIBOOT_AOUT_KLUDGE);
        assert!(matches!(
            Image::parse(&f, f.len() as u32, MIB).unwrap_err(),
            Error::MultibootUnsupported(_)
        ));

        // Optional bits above 16 other than the kludge, and bits 0 and 1, are fine.
        let f = kernel(&[(0x1000, MIB, 0x1000, 0x1000)], 0b11);
        assert!(Image::parse(&f, f.len() as u32, MIB).is_ok());

        let mut f = good();
        f[0x1000..0x1004].fill(0);
        assert_eq!(Image::parse(&f, f.len() as u32, MIB).unwrap_err(), Error::NoMultibootHeader);
    }

    #[test]
    fn placement_is_checked_against_the_map() {
        use crate::memmap::Entry;
        let f = good();
        let img = Image::parse(&f, f.len() as u32, MIB).unwrap();
        let mut map = MemoryMap::new();
        map.push(Entry {
            base: MIB as u64,
            len: 0x2000,
            kind: 1,
        })
        .unwrap();
        assert_eq!(
            img.check_placement(&map),
            Err(Error::NotRam {
                index: 1,
                paddr: MIB + 0x1000
            })
        );
        map.push(Entry {
            base: MIB as u64 + 0x2000,
            len: 0x10_0000,
            kind: 1,
        })
        .unwrap();
        assert_eq!(img.check_placement(&map), Ok(()));
    }

    /// Stream the file through `copy_plan` in chunks of every size from 1 to 5000 bytes
    /// and check the result equals copying each segment whole.
    #[test]
    fn streaming_copies_equal_whole_segment_copies() {
        let mut f = kernel(
            &[
                (0x1000, MIB, 0xA00, 0xA00),
                (0x1A00, MIB + 0x2000, 0x5FF, 0x1000),
                (0x2000, MIB + 0x4000, 0x1000, 0x1000),
            ],
            0,
        );
        for (i, b) in f.iter_mut().enumerate().skip(0x1100) {
            *b = (i * 13 % 251) as u8;
        }
        let img = Image::parse(&f, f.len() as u32, MIB).unwrap();

        let mut want = vec![0u8; 0x5000];
        for s in img.segments() {
            let to = (s.paddr - MIB) as usize;
            want[to..to + s.filesz as usize]
                .copy_from_slice(&f[s.offset as usize..(s.offset + s.filesz) as usize]);
        }

        for chunk in [1usize, 7, 512, 1000, 4096, 5000] {
            let mut got = vec![0u8; 0x5000];
            let mut plan = [Copy {
                from: 0,
                len: 0,
                to: 0,
            }; MAX_SEGMENTS];
            for (k, c) in f.chunks(chunk).enumerate() {
                let n = img.copy_plan((k * chunk) as u32, c, &mut plan);
                for p in &plan[..n] {
                    let to = (p.to - MIB) as usize;
                    got[to..to + p.len].copy_from_slice(&c[p.from..p.from + p.len]);
                }
            }
            assert_eq!(got, want, "chunk size {chunk}");
        }
    }
}

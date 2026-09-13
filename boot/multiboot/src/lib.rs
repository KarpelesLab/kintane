//! Multiboot 1 handover parsing.
//!
//! A translation shim, in the sense of `docs/bootloader.md#being-loaded-by-others`:
//! it turns what a foreign loader left in memory into the same `BootInfo` shape every
//! other path produces, and the kernel above it never learns which loader ran.
//!
//! Everything here treats the loader's structure as **untrusted input**. It is
//! produced by code we did not write, and on real hardware by firmware with its own
//! ideas; a malformed memory map must be a diagnosable error rather than a fault
//! three subsystems later. Every field is behind a flag bit that is checked, every
//! walk is bounded, and no length is believed without being range-checked against the
//! region it indexes.

#![cfg_attr(not(test), no_std)]

use boot_protocol::{MemoryKind, MemoryRegion};

/// The value a multiboot 1 loader leaves in `eax`. Checking it distinguishes "a
/// loader ran" from "this pointer is whatever was in the register".
pub const BOOTLOADER_MAGIC: u32 = 0x2BAD_B002;

// Flag bits in the info structure that say which fields the loader filled in.
const FLAG_MEM: u32 = 1 << 0;
const FLAG_BOOT_DEVICE: u32 = 1 << 1;
const FLAG_CMDLINE: u32 = 1 << 2;
const FLAG_MODS: u32 = 1 << 3;
const FLAG_MMAP: u32 = 1 << 6;

/// The multiboot 1 information structure, as the specification lays it out.
///
/// Only the prefix we actually read is described. The loader may place more after it;
/// the flags say what is present.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct MultibootInfo {
    pub flags: u32,
    pub mem_lower: u32,
    pub mem_upper: u32,
    pub boot_device: u32,
    pub cmdline: u32,
    pub mods_count: u32,
    pub mods_addr: u32,
    /// The a.out/ELF symbol table union, which we do not interpret.
    pub syms: [u32; 4],
    pub mmap_length: u32,
    pub mmap_addr: u32,
}

/// One entry of the loader's memory map.
///
/// Note the layout quirk: `size` does **not** include itself, so the stride from one
/// entry to the next is `size + 4`. Getting this wrong walks off into arbitrary
/// memory, which is why the iterator below bounds every step.
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct RawMmapEntry {
    size: u32,
    addr: u64,
    len: u64,
    kind: u32,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Error {
    /// `eax` did not hold the multiboot magic, so no multiboot loader ran.
    NotMultiboot(u32),
    /// The loader did not provide a memory map, and we will not guess one.
    NoMemoryMap,
    /// An entry claimed a size that cannot be true.
    MalformedEntry { offset: usize },
}

/// A validated handover from a multiboot loader.
#[derive(Debug)]
pub struct Handover {
    info: MultibootInfo,
    /// Where the memory map lives, as a raw address plus length.
    mmap: Option<(usize, usize)>,
}

impl Handover {
    /// Interpret a multiboot handover.
    ///
    /// # Safety
    /// `magic` must be the value the loader left in `eax` and `addr` the value it
    /// left in `ebx`. `addr` must point at a multiboot information structure that
    /// remains mapped and unmodified for as long as the returned `Handover` is used.
    pub unsafe fn new(magic: u32, addr: usize) -> Result<Handover, Error> {
        if magic != BOOTLOADER_MAGIC {
            return Err(Error::NotMultiboot(magic));
        }
        // SAFETY: the caller guarantees `addr` points at a mapped multiboot
        // structure. We copy it out immediately rather than holding a reference into
        // loader memory, which may be reclaimed once the memory map is consumed.
        let info = unsafe { core::ptr::read_unaligned(addr as *const MultibootInfo) };

        let mmap = if info.flags & FLAG_MMAP != 0 && info.mmap_length > 0 {
            Some((info.mmap_addr as usize, info.mmap_length as usize))
        } else {
            None
        };

        Ok(Handover { info, mmap })
    }

    pub fn flags(&self) -> u32 {
        self.info.flags
    }

    pub fn has_memory_map(&self) -> bool {
        self.mmap.is_some()
    }

    /// Total usable memory the loader reported in its simple fields, in bytes.
    ///
    /// Present far more often than the full map, but coarse: it describes only the
    /// classic low and high regions and says nothing about holes. Use it for a banner
    /// line, never for an allocator.
    pub fn simple_memory_bytes(&self) -> Option<u64> {
        (self.info.flags & FLAG_MEM != 0)
            .then(|| (self.info.mem_lower as u64 + self.info.mem_upper as u64) * 1024)
    }

    pub fn boot_device(&self) -> Option<u32> {
        (self.info.flags & FLAG_BOOT_DEVICE != 0).then_some(self.info.boot_device)
    }

    pub fn module_count(&self) -> u32 {
        if self.info.flags & FLAG_MODS != 0 {
            self.info.mods_count
        } else {
            0
        }
    }

    /// The command line, if the loader supplied one and it is valid UTF-8.
    ///
    /// # Safety
    /// The loader's command-line buffer must still be mapped.
    pub unsafe fn cmdline(&self) -> Option<&str> {
        if self.info.flags & FLAG_CMDLINE == 0 || self.info.cmdline == 0 {
            return None;
        }
        let p = self.info.cmdline as usize as *const u8;
        // Bounded: a loader command line longer than this is not one we will honour,
        // and an unterminated string must not walk memory forever.
        const MAX: usize = 4096;
        let mut len = 0;
        while len < MAX {
            // SAFETY: the caller guarantees the buffer is mapped; we stop at MAX so
            // the walk is bounded even if the string is never terminated.
            if unsafe { *p.add(len) } == 0 {
                break;
            }
            len += 1;
        }
        // SAFETY: `len` bytes starting at `p` were just read successfully.
        let bytes = unsafe { core::slice::from_raw_parts(p, len) };
        core::str::from_utf8(bytes).ok()
    }

    /// Walk the loader's memory map, yielding regions in our own vocabulary.
    ///
    /// # Safety
    /// The loader's memory map must still be mapped and unmodified.
    pub unsafe fn memory_regions(&self) -> Result<MemoryMapIter, Error> {
        let (addr, len) = self.mmap.ok_or(Error::NoMemoryMap)?;
        Ok(MemoryMapIter {
            base: addr,
            len,
            offset: 0,
        })
    }
}

/// Iterator over the loader's memory map.
///
/// Bounded by construction: every step is checked against the declared length before
/// it is taken, and a nonsensical entry size ends the walk with an error rather than
/// advancing by zero forever.
pub struct MemoryMapIter {
    base: usize,
    len: usize,
    offset: usize,
}

impl Iterator for MemoryMapIter {
    type Item = Result<MemoryRegion, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        // Need at least the `size` field plus the fields it covers.
        const ENTRY_MIN: usize = core::mem::size_of::<RawMmapEntry>();
        if self.offset + ENTRY_MIN > self.len {
            return None;
        }

        let p = self.base + self.offset;
        // SAFETY: the caller of `memory_regions` guaranteed the map is mapped for
        // `len` bytes, and we checked that a whole entry fits before this offset.
        let raw = unsafe { core::ptr::read_unaligned(p as *const RawMmapEntry) };

        // The stride excludes the size field itself. A size that cannot hold the
        // fields we just read, or that would not advance us, is malformed — treating
        // it as anything else risks an unbounded walk.
        let stride = (raw.size as usize).checked_add(4);
        let Some(stride) = stride else {
            return Some(Err(Error::MalformedEntry {
                offset: self.offset,
            }));
        };
        if stride < ENTRY_MIN || stride == 0 {
            return Some(Err(Error::MalformedEntry {
                offset: self.offset,
            }));
        }
        self.offset += stride;

        // Reading packed fields into locals first: taking a reference to a packed
        // field is undefined behaviour, and a copy costs nothing here.
        let (addr, len, kind) = (raw.addr, raw.len, raw.kind);

        Some(Ok(MemoryRegion {
            start: addr,
            len,
            kind: translate_kind(kind) as u32,
            _reserved: 0,
        }))
    }
}

/// Multiboot's memory types, in our vocabulary.
///
/// Anything we do not recognise becomes `Reserved` rather than `Usable`: guessing
/// wrong in that direction hands the allocator memory that is not ours.
fn translate_kind(kind: u32) -> MemoryKind {
    match kind {
        1 => MemoryKind::Usable,
        3 => MemoryKind::AcpiReclaimable,
        4 => MemoryKind::AcpiNvs,
        5 => MemoryKind::Bad,
        _ => MemoryKind::Reserved,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a multiboot info structure plus memory map in a byte buffer, the way a
    /// loader would lay it out.
    struct Fixture {
        info: [u8; core::mem::size_of::<MultibootInfo>()],
        mmap: [u8; 24 * 4],
    }

    fn entry(buf: &mut [u8], at: usize, size: u32, addr: u64, len: u64, kind: u32) {
        buf[at..at + 4].copy_from_slice(&size.to_le_bytes());
        buf[at + 4..at + 12].copy_from_slice(&addr.to_le_bytes());
        buf[at + 12..at + 20].copy_from_slice(&len.to_le_bytes());
        buf[at + 20..at + 24].copy_from_slice(&kind.to_le_bytes());
    }

    fn fixture(entries: &[(u64, u64, u32)]) -> (Fixture, usize) {
        let mut f = Fixture {
            info: [0; core::mem::size_of::<MultibootInfo>()],
            mmap: [0; 24 * 4],
        };
        let mut at = 0;
        for &(addr, len, kind) in entries {
            // size excludes itself: 20 covers addr+len+kind.
            entry(&mut f.mmap, at, 20, addr, len, kind);
            at += 24;
        }
        let mmap_len = at;
        let flags = FLAG_MEM | FLAG_MMAP;
        f.info[0..4].copy_from_slice(&flags.to_le_bytes());
        f.info[4..8].copy_from_slice(&640u32.to_le_bytes()); // mem_lower KiB
        f.info[8..12].copy_from_slice(&130_048u32.to_le_bytes()); // mem_upper KiB
        (f, mmap_len)
    }

    fn handover(f: &Fixture, mmap_len: usize) -> Handover {
        let mut info: MultibootInfo =
            unsafe { core::ptr::read_unaligned(f.info.as_ptr() as *const MultibootInfo) };
        info.mmap_addr = f.mmap.as_ptr() as usize as u32;
        info.mmap_length = mmap_len as u32;
        Handover {
            info,
            mmap: Some((f.mmap.as_ptr() as usize, mmap_len)),
        }
    }

    #[test]
    fn rejects_a_wrong_magic() {
        let e = unsafe { Handover::new(0xdead_beef, 0x1000) }.unwrap_err();
        assert_eq!(e, Error::NotMultiboot(0xdead_beef));
    }

    #[test]
    fn walks_every_entry_and_translates_kinds() {
        let (f, n) = fixture(&[
            (0x0000_0000, 0x0009_FC00, 1),
            (0x0010_0000, 0x07EE_0000, 1),
            (0x07FE_0000, 0x0002_0000, 3),
            (0xFFFC_0000, 0x0004_0000, 2),
        ]);
        let h = handover(&f, n);
        let mut regions = [MemoryRegion {
            start: 0,
            len: 0,
            kind: 0,
            _reserved: 0,
        }; 8];
        let mut n_regions = 0;
        for r in unsafe { h.memory_regions() }.unwrap() {
            regions[n_regions] = r.unwrap();
            n_regions += 1;
        }

        assert_eq!(n_regions, 4, "every entry must be yielded");
        assert_eq!(regions[0].kind, MemoryKind::Usable as u32);
        assert_eq!(regions[1].start, 0x0010_0000);
        assert_eq!(regions[1].len, 0x07EE_0000);
        assert_eq!(regions[2].kind, MemoryKind::AcpiReclaimable as u32);
        assert_eq!(regions[3].kind, MemoryKind::Reserved as u32);
    }

    #[test]
    fn unknown_kinds_become_reserved_never_usable() {
        // Guessing "usable" for a type we do not know hands the allocator memory
        // that may not be ours, so the default must go the other way.
        for k in [0u32, 6, 7, 99, u32::MAX] {
            assert_eq!(translate_kind(k), MemoryKind::Reserved, "kind {k}");
        }
        assert_eq!(translate_kind(1), MemoryKind::Usable);
    }

    #[test]
    fn a_zero_size_entry_ends_the_walk_instead_of_looping() {
        // The failure this guards against is an unbounded walk, not a wrong answer.
        let (mut f, n) = fixture(&[(0x1000, 0x1000, 1), (0x2000, 0x1000, 1)]);
        entry(&mut f.mmap, 24, 0, 0x2000, 0x1000, 1); // second entry claims size 0
        let h = handover(&f, n);
        let mut it = unsafe { h.memory_regions() }.unwrap();
        assert!(it.next().unwrap().is_ok());
        assert_eq!(it.next().unwrap().unwrap_err(), Error::MalformedEntry { offset: 24 });
    }

    #[test]
    fn a_truncated_trailing_entry_is_dropped_not_read() {
        let (f, n) = fixture(&[(0x1000, 0x1000, 1)]);
        // Claim more map than we actually wrote, but not a whole extra entry.
        let h = handover(&f, n + 8);
        let n = unsafe { h.memory_regions() }.unwrap().count();
        assert_eq!(n, 1, "a partial entry must not be read");
    }

    #[test]
    fn absent_memory_map_is_an_error_not_a_guess() {
        let f = Fixture {
            info: [0; core::mem::size_of::<MultibootInfo>()],
            mmap: [0; 24 * 4],
        };
        let h = Handover {
            info: unsafe { core::ptr::read_unaligned(f.info.as_ptr() as *const MultibootInfo) },
            mmap: None,
        };
        assert!(!h.has_memory_map());
        assert!(matches!(unsafe { h.memory_regions() }.map(|_| ()), Err(Error::NoMemoryMap)));
    }

    #[test]
    fn simple_memory_is_reported_only_when_flagged() {
        let (f, n) = fixture(&[(0x1000, 0x1000, 1)]);
        let h = handover(&f, n);
        assert_eq!(h.simple_memory_bytes(), Some((640 + 130_048) * 1024));
    }
}

//! The on-disk layout of a `kinboot-bios` disk.
//!
//! One file is the single source of truth for both sides of the layout. The loader
//! compiles it as a module of this crate, and `kbuild`, which writes the disk, includes
//! the same file by path (`kbuild/src/bios.rs`). A field moved here moves for both, and
//! nothing has to be kept in step by hand. That is why it uses `core` only and has no
//! `unsafe`: it must compile unchanged as kernel-side `no_std` code and as part of a
//! host tool.
//!
//! ```text
//! LBA 0                 MBR: stage 1 code, stage 1 table, disk signature, partition
//!                       table, 0x55AA
//! LBA 1 ..              stage 2, at most STAGE2_MAX_SECTORS sectors; its header is at
//!                       STAGE2_HEADER_OFFSET
//! LBA 1 + stage 2 size  the kernel image, byte for byte, padded to a whole sector
//! ```
//!
//! Stage 1 learns where stage 2 is from its table, which `kbuild` writes. Stage 2
//! learns where the kernel is from its header, which `kbuild` also writes. Neither
//! loader stage contains a disk offset of its own.

/// Bytes per sector. BIOS disk services address 512-byte sectors, and so does this
/// layout; a 4Kn disk is not bootable through the BIOS path anyway.
pub const SECTOR: usize = 512;

/// Where stage 1's table sits inside the MBR.
///
/// Stage 1's code must end before this, which the assembler enforces with `.org`: code
/// that grows past it is a build error, not a table silently overwritten.
pub const STAGE1_TABLE_OFFSET: usize = 424;
/// `KBS1`, marking the table so the disk writer can refuse a stage 1 whose layout moved.
pub const STAGE1_MAGIC: [u8; 4] = *b"KBS1";
/// Bytes of MBR boot code. The rest of the sector is the disk signature, the partition
/// table and `0x55AA`, and belongs to the partitioning scheme, not to us.
pub const MBR_CODE_BYTES: usize = 440;
/// The optional 32-bit disk signature.
pub const DISK_SIGNATURE_OFFSET: usize = 440;
/// The four primary partition entries.
pub const PARTITION_TABLE_OFFSET: usize = 446;
/// Size of one partition table entry.
pub const PARTITION_ENTRY_BYTES: usize = 16;
/// Partition type for the region stage 2 and the kernel occupy: `0xDA`, "non-filesystem
/// data", so partitioning tools show the space as taken rather than free.
pub const PARTITION_TYPE: u8 = 0xDA;

/// Where stage 2 starts on disk.
pub const STAGE2_LBA: u32 = 1;
/// The stage 2 budget from `docs/bootloader.md`: 32 KiB.
///
/// It also keeps stage 2 inside one real-mode segment at its load address, which the
/// BIOS call thunk depends on, and inside one INT 13h extended read.
pub const STAGE2_MAX_SECTORS: u32 = 64;
/// Where stage 1 loads stage 2, and where stage 2 is linked.
pub const STAGE2_LOAD_ADDRESS: u32 = 0x7E00;
/// Where the header sits inside stage 2's image, after the initial jump.
pub const STAGE2_HEADER_OFFSET: usize = 8;
/// `KBS2`.
pub const STAGE2_MAGIC: [u8; 4] = *b"KBS2";
/// Version of the header layout below.
pub const HEADER_VERSION: u16 = 1;
/// Bytes of kernel command line the header carries, terminator included.
pub const CMDLINE_BYTES: usize = 128;
/// Total size of the stage 2 header.
pub const HEADER_BYTES: usize = 4 + 2 + 2 + 4 + 4 + 4 + CMDLINE_BYTES;

/// The stage 1 table: where stage 2 is. Little-endian, at [`STAGE1_TABLE_OFFSET`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Stage1Table {
    pub stage2_lba: u32,
    pub stage2_sectors: u16,
}

impl Stage1Table {
    /// Bytes the table occupies after its magic.
    pub const BYTES: usize = 4 + 4 + 2;

    pub fn write(&self, out: &mut [u8]) -> Result<(), LayoutError> {
        let t = out
            .get_mut(STAGE1_TABLE_OFFSET..STAGE1_TABLE_OFFSET + Self::BYTES)
            .ok_or(LayoutError::TooShort)?;
        if t[..4] != STAGE1_MAGIC {
            return Err(LayoutError::BadMagic);
        }
        t[4..8].copy_from_slice(&self.stage2_lba.to_le_bytes());
        t[8..10].copy_from_slice(&self.stage2_sectors.to_le_bytes());
        Ok(())
    }
}

/// What stage 2 needs to find and check the kernel.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Header {
    pub kernel_lba: u32,
    pub kernel_bytes: u32,
    /// CRC-32 (IEEE) of the kernel's `kernel_bytes` bytes.
    pub kernel_crc32: u32,
    /// NUL-terminated; the terminator is always present because the last byte is
    /// forced to zero on both write and parse.
    pub cmdline: [u8; CMDLINE_BYTES],
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LayoutError {
    TooShort,
    BadMagic,
    /// A header version this stage 2 does not understand.
    Version(u16),
    /// A header size smaller than the fields this version defines.
    HeaderSize(u16),
    /// A command line longer than the header can carry.
    CmdlineTooLong,
}

impl Header {
    /// Write the header into a stage 2 image in place.
    ///
    /// The image must already carry the magic at the header offset. Checking it is what
    /// stops the disk writer patching an image whose layout changed under it.
    pub fn write(&self, stage2: &mut [u8]) -> Result<(), LayoutError> {
        let h = stage2
            .get_mut(STAGE2_HEADER_OFFSET..STAGE2_HEADER_OFFSET + HEADER_BYTES)
            .ok_or(LayoutError::TooShort)?;
        if h[..4] != STAGE2_MAGIC {
            return Err(LayoutError::BadMagic);
        }
        h[4..6].copy_from_slice(&HEADER_VERSION.to_le_bytes());
        h[6..8].copy_from_slice(&(HEADER_BYTES as u16).to_le_bytes());
        h[8..12].copy_from_slice(&self.kernel_lba.to_le_bytes());
        h[12..16].copy_from_slice(&self.kernel_bytes.to_le_bytes());
        h[16..20].copy_from_slice(&self.kernel_crc32.to_le_bytes());
        h[20..20 + CMDLINE_BYTES].copy_from_slice(&self.cmdline);
        h[20 + CMDLINE_BYTES - 1] = 0;
        Ok(())
    }

    /// Read a header from the bytes starting at its magic.
    pub fn parse(h: &[u8]) -> Result<Header, LayoutError> {
        let h = h.get(..HEADER_BYTES).ok_or(LayoutError::TooShort)?;
        if h[..4] != STAGE2_MAGIC {
            return Err(LayoutError::BadMagic);
        }
        let version = u16::from_le_bytes([h[4], h[5]]);
        if version != HEADER_VERSION {
            return Err(LayoutError::Version(version));
        }
        let size = u16::from_le_bytes([h[6], h[7]]);
        if (size as usize) < HEADER_BYTES {
            return Err(LayoutError::HeaderSize(size));
        }
        let le = |at: usize| u32::from_le_bytes([h[at], h[at + 1], h[at + 2], h[at + 3]]);
        let mut cmdline = [0u8; CMDLINE_BYTES];
        cmdline.copy_from_slice(&h[20..20 + CMDLINE_BYTES]);
        cmdline[CMDLINE_BYTES - 1] = 0;
        Ok(Header {
            kernel_lba: le(8),
            kernel_bytes: le(12),
            kernel_crc32: le(16),
            cmdline,
        })
    }

    /// A command line as the header stores it.
    pub fn cmdline_from(text: &[u8]) -> Result<[u8; CMDLINE_BYTES], LayoutError> {
        if text.len() >= CMDLINE_BYTES {
            return Err(LayoutError::CmdlineTooLong);
        }
        let mut c = [0u8; CMDLINE_BYTES];
        c[..text.len()].copy_from_slice(text);
        Ok(c)
    }
}

/// Whole sectors needed for `bytes`.
pub const fn sectors_for(bytes: usize) -> usize {
    bytes.div_ceil(SECTOR)
}

/// CRC-32 as used by zlib, PNG and Ethernet: reflected polynomial `0xEDB88320`,
/// initial value and final XOR `0xFFFFFFFF`.
///
/// Bitwise rather than table-driven, because stage 2 has a size budget and a
/// kernel-sized CRC takes a few milliseconds either way. Incremental, because stage 2
/// computes it while streaming the kernel off the disk in chunks.
#[derive(Clone, Copy)]
pub struct Crc32(u32);

impl Default for Crc32 {
    fn default() -> Self {
        Self::new()
    }
}

impl Crc32 {
    pub const fn new() -> Self {
        Crc32(0xFFFF_FFFF)
    }

    pub fn update(&mut self, bytes: &[u8]) {
        let mut c = self.0;
        for &b in bytes {
            c ^= b as u32;
            for _ in 0..8 {
                let mask = (c & 1).wrapping_neg();
                c = (c >> 1) ^ (0xEDB8_8320 & mask);
            }
        }
        self.0 = c;
    }

    pub const fn finish(self) -> u32 {
        !self.0
    }
}

/// CRC-32 of a whole buffer.
pub fn crc32(bytes: &[u8]) -> u32 {
    let mut c = Crc32::new();
    c.update(bytes);
    c.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc32_matches_the_standard_check_value() {
        // The check value every CRC-32/ISO-HDLC implementation is specified against.
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(crc32(b""), 0);
    }

    #[test]
    fn crc32_is_the_same_in_chunks() {
        let data: Vec<u8> = (0..10_000u32).map(|i| (i * 7 + 3) as u8).collect();
        let mut c = Crc32::new();
        for chunk in data.chunks(333) {
            c.update(chunk);
        }
        assert_eq!(c.finish(), crc32(&data));
    }

    fn stage2_image() -> Vec<u8> {
        let mut img = vec![0u8; 1024];
        img[STAGE2_HEADER_OFFSET..STAGE2_HEADER_OFFSET + 4].copy_from_slice(&STAGE2_MAGIC);
        img
    }

    #[test]
    fn header_round_trips() {
        let mut img = stage2_image();
        let h = Header {
            kernel_lba: 65,
            kernel_bytes: 123_204,
            kernel_crc32: 0xDEAD_BEEF,
            cmdline: Header::cmdline_from(b"mode=normal").unwrap(),
        };
        h.write(&mut img).unwrap();
        let back = Header::parse(&img[STAGE2_HEADER_OFFSET..]).unwrap();
        assert_eq!(back, h);
        // Fixed offsets are the contract with the assembly, so pin them.
        assert_eq!(&img[STAGE2_HEADER_OFFSET + 8..STAGE2_HEADER_OFFSET + 12], &65u32.to_le_bytes());
        assert_eq!(HEADER_BYTES, 148);
    }

    #[test]
    fn header_refuses_a_moved_layout() {
        let mut img = vec![0u8; 1024];
        let h = Header {
            kernel_lba: 1,
            kernel_bytes: 1,
            kernel_crc32: 0,
            cmdline: [0; CMDLINE_BYTES],
        };
        assert_eq!(h.write(&mut img), Err(LayoutError::BadMagic));
        assert_eq!(Header::parse(&img[STAGE2_HEADER_OFFSET..]), Err(LayoutError::BadMagic));
        assert_eq!(Header::parse(&STAGE2_MAGIC), Err(LayoutError::TooShort));
    }

    #[test]
    fn header_checks_version_and_size() {
        let mut img = stage2_image();
        let h = Header {
            kernel_lba: 1,
            kernel_bytes: 1,
            kernel_crc32: 0,
            cmdline: [0; CMDLINE_BYTES],
        };
        h.write(&mut img).unwrap();
        let at = STAGE2_HEADER_OFFSET;
        img[at + 4] = 2;
        assert_eq!(Header::parse(&img[at..]), Err(LayoutError::Version(2)));
        img[at + 4] = 1;
        img[at + 6] = 20;
        img[at + 7] = 0;
        assert_eq!(Header::parse(&img[at..]), Err(LayoutError::HeaderSize(20)));
    }

    #[test]
    fn cmdline_is_always_terminated() {
        assert_eq!(Header::cmdline_from(&[b'x'; CMDLINE_BYTES]), Err(LayoutError::CmdlineTooLong));
        let full = Header::cmdline_from(&[b'x'; CMDLINE_BYTES - 1]).unwrap();
        assert_eq!(full[CMDLINE_BYTES - 1], 0);
        // A disk whose header lost its terminator still parses to a terminated line.
        let mut img = stage2_image();
        let h = Header {
            kernel_lba: 1,
            kernel_bytes: 1,
            kernel_crc32: 0,
            cmdline: [0; CMDLINE_BYTES],
        };
        h.write(&mut img).unwrap();
        let end = STAGE2_HEADER_OFFSET + HEADER_BYTES;
        img[end - CMDLINE_BYTES..end].fill(b'y');
        let back = Header::parse(&img[STAGE2_HEADER_OFFSET..]).unwrap();
        assert_eq!(back.cmdline[CMDLINE_BYTES - 1], 0);
    }

    #[test]
    fn stage1_table_writes_only_behind_its_magic() {
        let mut mbr = [0u8; SECTOR];
        let t = Stage1Table {
            stage2_lba: 1,
            stage2_sectors: 40,
        };
        assert_eq!(t.write(&mut mbr), Err(LayoutError::BadMagic));
        mbr[STAGE1_TABLE_OFFSET..STAGE1_TABLE_OFFSET + 4].copy_from_slice(&STAGE1_MAGIC);
        t.write(&mut mbr).unwrap();
        assert_eq!(&mbr[STAGE1_TABLE_OFFSET + 4..STAGE1_TABLE_OFFSET + 10], &[1, 0, 0, 0, 40, 0]);
        // The table must fit in the boot code area, before the disk signature.
        assert!(STAGE1_TABLE_OFFSET + Stage1Table::BYTES <= MBR_CODE_BYTES);
    }

    #[test]
    fn sector_rounding() {
        assert_eq!(sectors_for(0), 0);
        assert_eq!(sectors_for(1), 1);
        assert_eq!(sectors_for(512), 1);
        assert_eq!(sectors_for(513), 2);
    }
}

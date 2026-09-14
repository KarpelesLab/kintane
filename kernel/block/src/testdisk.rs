//! The disk image test builds attach, and what the kernel expects to find on it.
//!
//! kbuild writes the image and the kernel reads it, and neither may depend on the other,
//! so the format is written down twice: here and in `kbuild/src/testdisk.rs`. What keeps
//! the two in step is [`PINNED`] and [`PINNED_BIG`] — a handful of bytes computed once and
//! asserted by both sides' tests. A change to either side's content fails that side's test
//! rather than a boot under QEMU that reports a mismatched sector.
//!
//! # Three regions
//!
//! * **The pattern**, sectors `0` to [`FS_START`]: a header in the first bytes of sector 0, and
//!   every other byte a function of its position, so any sector can be verified without the image
//!   in hand and a sector read from the wrong place is detected by content, not only by a checksum.
//! * **The scratch area**, the pattern's last [`SCRATCH_SECTORS`] sectors, which tests may
//!   overwrite. Everything below it is only ever read, so a write that lands in the wrong place is
//!   caught by the next read of the pattern rather than hidden by being overwritten again.
//! * **A FAT16 volume**, from [`FS_START`] to the end, holding the files named below and, when the
//!   configuration builds one, the user program at [`PROGRAM_PATH`].
//!
//! The scratch area sits between the pattern and the volume rather than at the end of the
//! disk, so the sectors the block check and the block workload already read — below
//! [`SCRATCH_START`] — are the pattern exactly as they were before the volume existed.

/// The first eight bytes of sector 0.
pub const MAGIC: &[u8; 8] = b"KTBLKDSK";
/// The format version, in the four bytes after the magic, little-endian. Version 2 added
/// the volume.
pub const VERSION: u32 = 2;
/// Bytes of sector 0 the header takes; the pattern starts after them.
pub const HEADER_BYTES: usize = 16;
/// The logical sector size the image is laid out in.
pub const SECTOR: usize = 512;
/// The first sector of the scratch area.
pub const SCRATCH_START: u64 = 4096;
/// Sectors tests may overwrite.
pub const SCRATCH_SECTORS: u64 = 256;
/// The volume's first sector, right after the scratch area. Every sector below it is the
/// pattern.
pub const FS_START: u64 = SCRATCH_START + SCRATCH_SECTORS;
/// Sectors in the volume: 4 MiB with one sector per cluster.
pub const FS_SECTORS: u64 = 8192;
/// Sectors in the image.
pub const SECTORS: u64 = FS_START + FS_SECTORS;

/// `/HELLO.TXT`'s content.
pub const HELLO: &[u8] = b"hello from the KinTane test disk\n";
/// `/SUB/NESTED.TXT`'s content.
pub const NESTED: &[u8] = b"a file in a directory\n";
/// `/BIG.BIN`'s length: two hundred clusters, so reading it walks a chain.
pub const BIG_LEN: usize = 100_000;
/// Where the user program is, when the image carries one.
pub const PROGRAM_PATH: &str = "/KINTANE/INIT.ELF";

/// The byte at `offset` of sector `sector`, for a sector below [`FS_START`].
///
/// A multiplicative hash of the position, so neighbouring sectors differ in every byte
/// and a read that is off by one sector — or by one byte within a sector — matches
/// nothing.
pub const fn pattern(sector: u64, offset: usize) -> u8 {
    let s = (sector as u32).wrapping_mul(2_654_435_761);
    let o = (offset as u32).wrapping_mul(40_503);
    (s.wrapping_add(o).wrapping_add(sector as u32 >> 3) >> 13) as u8
}

/// The byte at offset `i` of `/BIG.BIN`.
///
/// A different hash from [`pattern`]'s, so a read of the file that walked its chain into
/// the pattern region, or into another file, matches nothing.
pub const fn big_byte(i: usize) -> u8 {
    let x = (i as u32)
        .wrapping_mul(2_246_822_519)
        .wrapping_add(i as u32 >> 7);
    (x >> 17) as u8
}

/// `(sector, offset, byte)` triples both sides assert.
pub const PINNED: [(u64, usize, u8); 4] = [
    (0, 16, 0x4f),
    (7, 0, 0x22),
    (1000, 511, 0x79),
    (4095, 200, 0xf9),
];

/// `(offset, byte)` of `/BIG.BIN`, which both sides assert.
pub const PINNED_BIG: [(usize, u8); 6] = [
    (0, 0x00),
    (511, 0xd4),
    (512, 0xca),
    (4096, 0x53),
    (65535, 0x45),
    (99999, 0xf2),
];

/// Fill `sector` of the image into `into`, header included for sector 0. Meaningful only
/// below [`FS_START`]: the volume's sectors are FAT's, not the pattern's.
pub fn fill_sector(sector: u64, into: &mut [u8]) {
    for (i, b) in into.iter_mut().enumerate() {
        *b = pattern(sector, i);
    }
    if sector == 0 && into.len() >= HEADER_BYTES {
        into[..8].copy_from_slice(MAGIC);
        into[8..12].copy_from_slice(&VERSION.to_le_bytes());
        into[12..16].copy_from_slice(&(SECTORS as u32).to_le_bytes());
    }
}

/// Where a sector read from the image first differs from what it should hold.
pub fn first_mismatch(sector: u64, bytes: &[u8]) -> Option<usize> {
    let mut want = [0u8; SECTOR];
    let want = &mut want[..bytes.len().min(SECTOR)];
    fill_sector(sector, want);
    bytes.iter().zip(want.iter()).position(|(a, b)| a != b)
}

/// Whether sector 0 carries this format's header, and for how many sectors.
pub fn header(sector0: &[u8]) -> Option<u64> {
    if sector0.len() < HEADER_BYTES || &sector0[..8] != MAGIC {
        return None;
    }
    let version = u32::from_le_bytes([sector0[8], sector0[9], sector0[10], sector0[11]]);
    let sectors = u32::from_le_bytes([sector0[12], sector0[13], sector0[14], sector0[15]]);
    (version == VERSION).then_some(u64::from(sectors))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_pinned_bytes_are_what_the_pattern_gives() {
        for (sector, offset, byte) in PINNED {
            assert_eq!(pattern(sector, offset), byte, "sector {sector} offset {offset}");
        }
        for (offset, byte) in PINNED_BIG {
            assert_eq!(big_byte(offset), byte, "BIG.BIN offset {offset}");
        }
    }

    #[test]
    fn the_regions_are_contiguous_and_the_pinned_sectors_are_the_pattern() {
        assert_eq!(FS_START, SCRATCH_START + SCRATCH_SECTORS, "the volume follows scratch");
        assert_eq!(SECTORS, FS_START + FS_SECTORS, "and runs to the end");
        for (sector, _, _) in PINNED {
            assert!(sector < FS_START, "sector {sector} is pattern, not volume");
        }
    }

    #[test]
    fn neighbouring_sectors_and_offsets_differ() {
        let mut a = [0u8; SECTOR];
        let mut b = [0u8; SECTOR];
        fill_sector(10, &mut a);
        fill_sector(11, &mut b);
        let same = a.iter().zip(b.iter()).filter(|(x, y)| x == y).count();
        assert!(same < SECTOR / 16, "{same} of {SECTOR} bytes equal between neighbours");
        assert_eq!(first_mismatch(11, &a), Some(0), "sector 10 does not pass as 11");
    }

    #[test]
    fn big_bin_is_not_the_sector_pattern() {
        // A chain walk that strayed into the pattern region must not pass for the file.
        let same = (0..SECTOR)
            .filter(|&i| big_byte(i) == pattern(FS_START - 1, i))
            .count();
        assert!(same < SECTOR / 16, "{same} of {SECTOR} bytes equal");
    }

    #[test]
    fn a_header_round_trips_and_a_wrong_one_is_refused() {
        let mut s0 = [0u8; SECTOR];
        fill_sector(0, &mut s0);
        assert_eq!(header(&s0), Some(SECTORS));
        assert_eq!(first_mismatch(0, &s0), None);
        s0[0] = b'X';
        assert_eq!(header(&s0), None);
    }
}

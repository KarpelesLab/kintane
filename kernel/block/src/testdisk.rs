//! The disk image test builds attach, and what the kernel expects to find on it.
//!
//! kbuild writes the image and the kernel reads it, and neither may depend on the other,
//! so the format is written down twice: here and in `kbuild/src/testdisk.rs`. What keeps
//! the two in step is [`PINNED`] — a handful of bytes computed once and asserted by both
//! sides' tests. A change to the pattern on one side fails that side's test rather than a
//! boot under QEMU that reports a mismatched sector.
//!
//! The format is deliberately trivial: a header in the first bytes of sector 0, and
//! every other byte a function of its position, so any sector can be verified without
//! the image in hand and a sector read from the wrong place is detected by content, not
//! only by a checksum.

/// The first eight bytes of sector 0.
pub const MAGIC: &[u8; 8] = b"KTBLKDSK";
/// The format version, in the four bytes after the magic, little-endian.
pub const VERSION: u32 = 1;
/// Bytes of sector 0 the header takes; the pattern starts after them.
pub const HEADER_BYTES: usize = 16;
/// The logical sector size the pattern is laid out in.
pub const SECTOR: usize = 512;
/// Sectors in the image: 2 MiB.
pub const SECTORS: u64 = 4096;
/// The last sectors of the image, which tests may overwrite. The first part of the disk
/// is only ever read, so a write that lands in the wrong place is caught by the next read
/// of the pattern rather than hidden by being overwritten again.
pub const SCRATCH_SECTORS: u64 = 256;
/// The first sector of the scratch area.
pub const SCRATCH_START: u64 = SECTORS - SCRATCH_SECTORS;

/// The byte at `offset` of sector `sector`.
///
/// A multiplicative hash of the position, so neighbouring sectors differ in every byte
/// and a read that is off by one sector — or by one byte within a sector — matches
/// nothing.
pub const fn pattern(sector: u64, offset: usize) -> u8 {
    let s = (sector as u32).wrapping_mul(2_654_435_761);
    let o = (offset as u32).wrapping_mul(40_503);
    (s.wrapping_add(o).wrapping_add(sector as u32 >> 3) >> 13) as u8
}

/// `(sector, offset, byte)` triples both sides assert.
pub const PINNED: [(u64, usize, u8); 4] = [
    (0, 16, 0x4f),
    (7, 0, 0x22),
    (1000, 511, 0x79),
    (4095, 200, 0xf9),
];

/// Fill `sector` of the image into `into`, header included for sector 0.
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
    fn a_header_round_trips_and_a_wrong_one_is_refused() {
        let mut s0 = [0u8; SECTOR];
        fill_sector(0, &mut s0);
        assert_eq!(header(&s0), Some(SECTORS));
        assert_eq!(first_mismatch(0, &s0), None);
        s0[0] = b'X';
        assert_eq!(header(&s0), None);
    }
}

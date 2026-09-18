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
/// The second volume's first sector, right after the first volume. It is FAT32, which a
/// volume is by its cluster count and nothing else: the specification's boundary is 65 525
/// clusters, so the smallest honest one is about 34 MiB.
pub const FS32_START: u64 = FS_START + FS_SECTORS;
pub const FS32_SECTORS: u64 = 66_600;
/// Sectors in the image.
pub const SECTORS: u64 = FS32_START + FS32_SECTORS;

/// Sectors in the second disk's image.
///
/// The second disk carries no volume — both volumes stay on the first, where the filesystem
/// checks and the crash campaign already expect them — so it is pattern all the way down and
/// ends where the first disk's volume would begin. Its bytes are [`pattern_on`]'s for disk 1,
/// which share no byte with disk 0's, so a read served by the wrong device's binding is caught
/// by content.
pub const SECTORS2: u64 = FS_START;

/// The second disk's index in [`pattern_on`]'s hash; mirrors `kbuild/src/testdisk.rs`'s `DISK2`.
///
/// This is which *image* a disk carries, not which slot it was bound in. The two are the same on
/// PCI, where enumeration follows the order the drives were attached, and different on
/// virtio-mmio, where QEMU fills the slots downwards and the volume's disk lands in the higher
/// one. Keying expected contents by slot therefore reads the right bytes on one port and the
/// wrong ones on the other.
pub const DISK2: usize = 1;

/// Sectors in the third disk's image.
///
/// The third disk carries no volume either, and unlike the second it is never written: it is
/// attached read-only, so it has no scratch area and ends where one would begin. That is also
/// what gives it a length of its own, which is what lets a header tell it from the second disk.
pub const SECTORS3: u64 = SCRATCH_START;

/// The third disk's index in [`pattern_on`]'s hash; mirrors `kbuild/src/testdisk.rs`'s `DISK3`.
pub const DISK3: usize = 2;

/// Each image's length in sectors, indexed by image.
///
/// A disk's header names its own length, so this table is what turns what a disk *says* it is
/// into which image it carries ([`image_named`]) — identity read off the medium rather than
/// inferred from the slot it was bound in. The lengths must stay pairwise distinct: two images
/// of one length would be two disks no header could tell apart.
pub const IMAGE_SECTORS: [u64; 3] = [SECTORS, SECTORS2, SECTORS3];

/// Which image a disk whose header names `sectors` carries, if it is one of this format's.
///
/// `None` for a disk carrying something else, which is a disk to report rather than one to
/// check against another image's bytes.
pub fn image_named(sectors: u64) -> Option<usize> {
    IMAGE_SECTORS.iter().position(|&n| n == sectors)
}

/// `/HELLO.TXT`'s content.
pub const HELLO: &[u8] = b"hello from the KinTane test disk\n";
/// `/SUB/NESTED.TXT`'s content.
pub const NESTED: &[u8] = b"a file in a directory\n";
/// `/BIG.BIN`'s length: two hundred clusters, so reading it walks a chain.
pub const BIG_LEN: usize = 100_000;
/// Where the user program is, when the image carries one.
pub const PROGRAM_PATH: &str = "/KINTANE/INIT.ELF";
/// What the FAT32 volume holds; mirrors `kbuild/src/testdisk.rs`.
pub const HELLO32: &[u8] = b"hello from the KinTane FAT32 volume\n";
pub const NESTED32: &[u8] = b"a file in a directory on FAT32\n";
/// `/BIG32.BIN`'s length, whose bytes are [`big_byte`]'s: eighty clusters, so reading it
/// walks a chain of 32-bit entries.
pub const BIG32_LEN: usize = 40_000;

/// Where the static Linux program is, when the image carries one. In the program's own
/// directory, so the root lists exactly what it did before the Linux personality.
pub const LINUX_PROGRAM_PATH: &str = "/KINTANE/LINUX.ELF";
/// Where the file server's write check leaves a file for kbuild to read after the guest
/// exits, how long it is, and the seed of its bytes ([`out_byte`]). kbuild writes neither
/// file: the kernel does, and kbuild checks it did.
pub const NATIVE_OUT_PATH: &str = "/KINTANE/NATIVE.OUT";
pub const NATIVE_OUT_LEN: usize = 1000;
pub const NATIVE_OUT_SEED: u8 = 0x4e;
/// The same for the Linux program's files mode.
pub const LINUX_OUT_PATH: &str = "/KINTANE/LINUX.OUT";
pub const LINUX_OUT_LEN: usize = 2000;
pub const LINUX_OUT_SEED: u8 = 0x4c;

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

/// The byte at `offset` of sector `sector` on disk `disk`.
///
/// The disk's index is folded into the same hash before its shift, so each disk's pattern is
/// its own: a sector read from the wrong disk matches nothing, which is what makes a read
/// served through the wrong device's binding detectable by content rather than by trusting
/// the binding. Disk 0 adds zero and so is [`pattern`] exactly — the first disk's image is
/// byte for byte what it was before there was a second.
pub const fn pattern_on(disk: usize, sector: u64, offset: usize) -> u8 {
    let s = (sector as u32).wrapping_mul(2_654_435_761);
    let o = (offset as u32).wrapping_mul(40_503);
    let d = (disk as u32).wrapping_mul(0x9E37_79B9);
    (s.wrapping_add(o)
        .wrapping_add(sector as u32 >> 3)
        .wrapping_add(d)
        >> 13) as u8
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

/// The byte at offset `i` of a file a writing check leaves on the volume, for a check of
/// `seed`'s. Unlike [`pattern`] and [`big_byte`] in shape, so a file that ends up holding
/// another's bytes, or the pattern region's, matches nothing.
pub const fn out_byte(seed: u8, i: usize) -> u8 {
    let x = (i as u32).wrapping_mul(2_654_435_761) ^ (seed as u32).wrapping_mul(0x9E37_79B9);
    (x >> 23) as u8 ^ seed
}

/// `(seed, offset, byte)` of [`out_byte`], which both sides assert.
pub const PINNED_OUT: [(u8, usize, u8); 8] = [
    (0x4e, 0, 0x27),
    (0x4e, 1, 0x1b),
    (0x4e, 511, 0x86),
    (0x4e, 999, 0xf3),
    (0x4c, 0, 0xbc),
    (0x4c, 1, 0x80),
    (0x4c, 511, 0x1d),
    (0x4c, 999, 0x68),
];

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
    fill_sector_on(0, sector, into);
}

/// Fill `sector` of disk `disk`'s image into `into`, header included for sector 0.
///
/// Each disk's header records its own length, so a device that answered with another disk's
/// sector 0 is caught by the geometry the header names as well as by the pattern around it.
pub fn fill_sector_on(disk: usize, sector: u64, into: &mut [u8]) {
    for (i, b) in into.iter_mut().enumerate() {
        *b = pattern_on(disk, sector, i);
    }
    if sector == 0 && into.len() >= HEADER_BYTES {
        into[..8].copy_from_slice(MAGIC);
        into[8..12].copy_from_slice(&VERSION.to_le_bytes());
        into[12..16].copy_from_slice(&(IMAGE_SECTORS[disk] as u32).to_le_bytes());
    }
}

/// Where a sector read from the image first differs from what it should hold.
pub fn first_mismatch(sector: u64, bytes: &[u8]) -> Option<usize> {
    first_mismatch_on(0, sector, bytes)
}

/// Where a sector read from disk `disk` first differs from what that disk should hold.
pub fn first_mismatch_on(disk: usize, sector: u64, bytes: &[u8]) -> Option<usize> {
    let mut want = [0u8; SECTOR];
    let want = &mut want[..bytes.len().min(SECTOR)];
    fill_sector_on(disk, sector, want);
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
    fn the_pinned_bytes_of_a_written_file_are_what_out_byte_gives() {
        for (seed, offset, byte) in PINNED_OUT {
            assert_eq!(out_byte(seed, offset), byte, "seed {seed:#x} offset {offset}");
        }
    }

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
        assert_eq!(FS32_START, FS_START + FS_SECTORS, "the second volume follows the first");
        assert_eq!(SECTORS, FS32_START + FS32_SECTORS, "and it runs to the end");
        assert!(FS32_SECTORS > 65_525, "a volume this small could not be FAT32");
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
    fn the_first_disks_pattern_is_unchanged_by_there_being_a_second() {
        // Disk 0 folds in zero, so the image kbuild has always written is untouched.
        for (sector, offset, byte) in PINNED {
            assert_eq!(pattern_on(0, sector, offset), byte, "sector {sector} offset {offset}");
        }
        for sector in [0, 1, 7, 1000, FS_START - 1] {
            for offset in [0, 1, 255, 511] {
                assert_eq!(pattern_on(0, sector, offset), pattern(sector, offset));
            }
        }
    }

    #[test]
    fn a_sector_from_the_wrong_disk_matches_nothing() {
        // What the wrong-binding check rests on: the same sector on any two of the disks
        // shares almost no byte, so a read served by another device is caught by content.
        // Every sector compared is below the shortest image, so all three disks have it.
        let mut a = [0u8; SECTOR];
        let mut b = [0u8; SECTOR];
        for sector in [1, 7, 1000, SECTORS3 - 1] {
            for i in 0..IMAGE_SECTORS.len() {
                for j in 0..IMAGE_SECTORS.len() {
                    if i == j {
                        continue;
                    }
                    fill_sector_on(i, sector, &mut a);
                    fill_sector_on(j, sector, &mut b);
                    let same = a.iter().zip(b.iter()).filter(|(x, y)| x == y).count();
                    assert!(same < SECTOR / 16, "sector {sector}, images {i}/{j}: {same} equal");
                    assert_eq!(
                        first_mismatch_on(j, sector, &a),
                        Some(0),
                        "image {i} passes as {j}"
                    );
                }
            }
        }
    }

    #[test]
    fn each_disks_header_names_its_own_length() {
        let mut s0 = [0u8; SECTOR];
        fill_sector_on(0, 0, &mut s0);
        assert_eq!(header(&s0), Some(SECTORS));
        fill_sector_on(DISK2, 0, &mut s0);
        assert_eq!(header(&s0), Some(SECTORS2), "the second disk names its own length");
        fill_sector_on(DISK3, 0, &mut s0);
        assert_eq!(header(&s0), Some(SECTORS3), "and the third names its own");
        assert_eq!(SECTORS2, FS_START, "the second disk is pattern only");
        assert_eq!(SECTORS3, SCRATCH_START, "and the third is pattern that is never written");
    }

    #[test]
    fn a_header_says_which_image_the_disk_carries() {
        // The identity key: what a disk carries is read off the disk rather than inferred from
        // the slot it was bound in. Two images of one length would be two disks no header could
        // tell apart, so the lengths are pairwise distinct and `image_named` is their inverse.
        for (image, &sectors) in IMAGE_SECTORS.iter().enumerate() {
            let mut s0 = [0u8; SECTOR];
            fill_sector_on(image, 0, &mut s0);
            assert_eq!(header(&s0), Some(sectors), "image {image} names its own length");
            assert_eq!(image_named(sectors), Some(image), "and that length names it back");
        }
        for i in 0..IMAGE_SECTORS.len() {
            for j in 0..i {
                assert_ne!(IMAGE_SECTORS[i], IMAGE_SECTORS[j], "images {i} and {j} share a length");
            }
        }
        assert_eq!(image_named(SECTORS + 1), None, "a length no image has names none");
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

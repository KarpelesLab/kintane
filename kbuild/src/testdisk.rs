//! The disk image test builds attach to a virtio-blk device.
//!
//! The kernel's side of the format is `kernel/block/src/testdisk.rs`; neither may depend on
//! the other, so the format is written twice and pinned by [`PINNED`] and [`PINNED_BIG`],
//! which both sides' tests assert. See that file for why the format is what it is.
//!
//! Three regions, in this order:
//!
//! - **the pattern**, from sector 0 (whose first bytes are the header) up to the volume: every
//!   byte a function of its position, so the block check can verify any sector without the image;
//! - **the scratch area**, the pattern region's last sectors, which tests may overwrite;
//! - **a FAT16 volume**, from [`crate::fat16`], holding known files and — when the configuration
//!   builds one — the user program, so the kernel can load a program from a disk.
//!
//! The image is a pure function of its constants and the program's bytes, so it is
//! byte-identical on every build. A run attaches a fresh copy of it (see `diskcheck`), so a
//! test run's writes never reach the file and every boot starts from the same bytes, and kbuild
//! reads the copy back after the guest exits to check what the kernel wrote.

use std::path::{Path, PathBuf};

use crate::fat16::{self, File, Params};
use crate::fat32;

const MAGIC: &[u8; 8] = b"KTBLKDSK";
const VERSION: u32 = 2;
const HEADER_BYTES: usize = 16;
pub const SECTOR: usize = 512;
const SCRATCH_START: u64 = 4096;
const SCRATCH_SECTORS: u64 = 256;
/// The volume's first sector: right after the scratch area.
pub const FS_START: u64 = SCRATCH_START + SCRATCH_SECTORS;
/// 4 MiB of FAT16 with one sector per cluster, which is 8 095 clusters: FAT16 by the
/// specification's count, and small enough to write on every build.
const FS_SECTORS: u64 = 8192;
/// The second volume's first sector, right after the first volume.
pub const FS32_START: u64 = FS_START + FS_SECTORS;
/// The second volume, FAT32. A volume is FAT32 by its cluster count and nothing else, and
/// the specification's boundary is 65 525, so the smallest honest FAT32 volume is about
/// 34 MiB. That is what the format costs, and what a volume pretending to be FAT32 would
/// not test.
const FS32_SECTORS: u64 = 66_600;
pub const SECTORS: u64 = FS32_START + FS32_SECTORS;

/// Sectors in the second disk's image; mirrors the kernel's `SECTORS2`.
///
/// The second disk carries no volume — both stay on the first, where the filesystem checks and
/// the crash campaign expect them — so it is pattern all the way down and ends where the first
/// disk's volume would begin.
pub const SECTORS2: u64 = FS_START;

/// Sectors in the third disk's image; mirrors the kernel's `SECTORS3`.
///
/// The third disk carries no volume either, and unlike the second it is never written: it is
/// attached read-only, so it has no scratch area and ends where one would begin. That is also
/// what gives it a length of its own, which is what lets a header tell it from the second disk.
pub const SECTORS3: u64 = SCRATCH_START;

/// The config symbol that attaches the disk.
pub const SYMBOL: &str = "QEMU_BLOCK_TEST";

/// The file name, next to the image in the build's output directory.
pub const FILE: &str = "testdisk.img";

/// The second disk's file name. Its own file, not a second attachment of the first: two
/// `-drive`s on one image make QEMU refuse the run with `Failed to get shared "write" lock`.
pub const FILE2: &str = "testdisk2.img";

/// The third disk's file name, for the function on the PCIe bus. Its own image rather than a
/// second attachment of the second disk's: a disk is told from another by the length its header
/// names, so a function sharing an image with a memory-mapped slot would be a disk no header
/// could tell from it.
pub const FILE3: &str = "testdisk3.img";

/// `/HELLO.TXT`: one cluster.
const HELLO: &[u8] = b"hello from the KinTane test disk\n";
/// `/SUB/NESTED.TXT`: one cluster, one directory down.
const NESTED: &[u8] = b"a file in a directory\n";
/// `/BIG.BIN`'s length: two hundred clusters, so reading it walks a chain.
const BIG_LEN: usize = 100_000;
/// What the FAT32 volume holds; mirrors the kernel's copy.
pub const HELLO32: &[u8] = b"hello from the KinTane FAT32 volume\n";
pub const NESTED32: &[u8] = b"a file in a directory on FAT32\n";
/// `/BIG32.BIN`'s length: eighty clusters, so reading it walks a chain of 32-bit entries.
pub const BIG32_LEN: usize = 40_000;

/// Where the user program goes.
const PROGRAM: &str = "KINTANE/INIT.ELF";
/// Where the static Linux program goes; mirrors `LINUX_PROGRAM_PATH` in the kernel's copy.
const LINUX_PROGRAM: &str = "KINTANE/LINUX.ELF";
/// What the kernel's writing checks leave on the volume, which kbuild reads back from the
/// disk after the guest exits; mirrors `NATIVE_OUT_*` and `LINUX_OUT_*` in the kernel's copy.
pub const NATIVE_OUT: (&str, usize, u8) = ("KINTANE/NATIVE.OUT", 1000, 0x4e);
pub const LINUX_OUT: (&str, usize, u8) = ("KINTANE/LINUX.OUT", 2000, 0x4c);
/// Names the writing checks make and remove again, which must be gone.
pub const REMOVED: [&str; 5] = [
    "KINTANE/NWTMP.TXT",
    "KINTANE/NWREN.TXT",
    "KINTANE/NWDIR",
    "KINTANE/LXTMP.TXT",
    "KINTANE/LXDIR",
];

/// The byte at offset `i` of a file a writing check of `seed`'s leaves on the volume.
pub const fn out_byte(seed: u8, i: usize) -> u8 {
    let x = (i as u32).wrapping_mul(2_654_435_761) ^ (seed as u32).wrapping_mul(0x9E37_79B9);
    (x >> 23) as u8 ^ seed
}

const fn pattern(sector: u64, offset: usize) -> u8 {
    let s = (sector as u32).wrapping_mul(2_654_435_761);
    let o = (offset as u32).wrapping_mul(40_503);
    (s.wrapping_add(o).wrapping_add(sector as u32 >> 3) >> 13) as u8
}

/// The byte at `offset` of sector `sector` on disk `disk`; mirrors the kernel's `pattern_on`.
///
/// The disk's index is folded into the same hash before its shift, so each disk's pattern is
/// its own and a sector read from the wrong disk matches nothing. Disk 0 adds zero and so is
/// [`pattern`] exactly — the first disk's image is byte for byte what it was before there was
/// a second, and every pinned byte still holds.
pub const fn pattern_on(disk: usize, sector: u64, offset: usize) -> u8 {
    let s = (sector as u32).wrapping_mul(2_654_435_761);
    let o = (offset as u32).wrapping_mul(40_503);
    let d = (disk as u32).wrapping_mul(0x9E37_79B9);
    (s.wrapping_add(o)
        .wrapping_add(sector as u32 >> 3)
        .wrapping_add(d)
        >> 13) as u8
}

/// The byte at offset `i` of `/BIG.BIN`. Unlike the sector pattern in shape, so a read of
/// the file that lands in the pattern region matches nothing.
pub const fn big_byte(i: usize) -> u8 {
    let x = (i as u32)
        .wrapping_mul(2_246_822_519)
        .wrapping_add(i as u32 >> 7);
    (x >> 17) as u8
}

/// The volume's shape.
const VOLUME: Params = Params {
    sectors: FS_SECTORS as u32,
    sectors_per_cluster: 1,
    reserved_sectors: 1,
    fats: 2,
    root_entries: 512,
    hidden_sectors: FS_START as u32,
    label: *b"KTTESTDISK ",
    volume_id: 0x4B54_4453,
    what: "the test disk's volume",
};

/// The second volume's shape: one sector per cluster, and a reserved region with room for
/// the FSInfo sector and a backup boot sector, as FAT32 has.
const VOLUME32: fat32::Params = fat32::Params {
    sectors: FS32_SECTORS as u32,
    sectors_per_cluster: 1,
    reserved_sectors: 32,
    fats: 2,
    hidden_sectors: FS32_START as u32,
    label: *b"KTFAT32    ",
    volume_id: 0x4654_3332,
    what: "the test disk's FAT32 volume",
};

/// The whole image. `program` is the user program to place on the volume, if there is one,
/// and `linux` the static Linux program.
pub fn image(program: Option<&[u8]>, linux: Option<&[u8]>) -> Result<Vec<u8>, String> {
    let mut disk = vec![0u8; SECTORS as usize * SECTOR];
    let pattern_bytes = FS_START as usize * SECTOR;
    for (sector, bytes) in disk[..pattern_bytes].chunks_exact_mut(SECTOR).enumerate() {
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = pattern(sector as u64, i);
        }
    }
    disk[..8].copy_from_slice(MAGIC);
    disk[8..12].copy_from_slice(&VERSION.to_le_bytes());
    disk[12..HEADER_BYTES].copy_from_slice(&(SECTORS as u32).to_le_bytes());

    let big: Vec<u8> = (0..BIG_LEN).map(big_byte).collect();
    let mut files = vec![
        File {
            path: "HELLO.TXT",
            data: HELLO,
        },
        File {
            path: "BIG.BIN",
            data: &big,
        },
        File {
            path: "SUB/NESTED.TXT",
            data: NESTED,
        },
    ];
    if let Some(program) = program {
        files.push(File {
            path: PROGRAM,
            data: program,
        });
    }
    if let Some(linux) = linux {
        files.push(File {
            path: LINUX_PROGRAM,
            data: linux,
        });
    }
    let volume = fat16::volume(&files, &VOLUME)?;
    let fs32_at = FS32_START as usize * SECTOR;
    disk[pattern_bytes..fs32_at].copy_from_slice(&volume);

    let big32: Vec<u8> = (0..BIG32_LEN).map(big_byte).collect();
    let files32 = [
        File {
            path: "HELLO32.TXT",
            data: HELLO32,
        },
        File {
            path: "BIG32.BIN",
            data: &big32,
        },
        File {
            path: "SUB32/NESTED.TXT",
            data: NESTED32,
        },
    ];
    let volume32 = fat32::volume(&files32, &VOLUME32)?;
    disk[fs32_at..].copy_from_slice(&volume32);
    Ok(disk)
}

/// A pattern-only image of `sectors` sectors, carrying image `disk`'s bytes: header and
/// pattern, no volume.
///
/// A pure function of its arguments like [`image`], so it is byte-identical on every build.
/// The header names this image's own length, which is how the kernel tells one pattern-only
/// disk from another without trusting the slot it was bound in.
fn pattern_image(disk: usize, sectors: u64) -> Vec<u8> {
    let mut image = vec![0u8; sectors as usize * SECTOR];
    for (sector, bytes) in image.chunks_exact_mut(SECTOR).enumerate() {
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = pattern_on(disk, sector as u64, i);
        }
    }
    image[..8].copy_from_slice(MAGIC);
    image[8..12].copy_from_slice(&VERSION.to_le_bytes());
    image[12..HEADER_BYTES].copy_from_slice(&(sectors as u32).to_le_bytes());
    image
}

/// The second disk's image: header and pattern, no volume.
pub fn image2() -> Vec<u8> {
    pattern_image(DISK2, SECTORS2)
}

/// The third disk's image, for the function on the PCIe bus: header and pattern, no volume and
/// no scratch area, since nothing writes it.
pub fn image3() -> Vec<u8> {
    pattern_image(DISK3, SECTORS3)
}

/// The second disk's index, in [`pattern_on`]'s terms.
pub const DISK2: usize = 1;

/// The third disk's index, in [`pattern_on`]'s terms; mirrors the kernel's `DISK3`.
pub const DISK3: usize = 2;

/// Write `bytes` into `out/name`, unless the file already holds exactly them.
fn write_bytes(out: &Path, name: &str, bytes: &[u8]) -> Result<PathBuf, String> {
    let path = out.join(name);
    if std::fs::read(&path).is_ok_and(|existing| existing == bytes) {
        return Ok(path);
    }
    std::fs::write(&path, bytes).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(path)
}

/// Write the second disk's image into `out`, unless the file already holds these bytes.
pub fn write2(out: &Path) -> Result<PathBuf, String> {
    write_bytes(out, FILE2, &image2())
}

/// Write the third disk's image into `out`, unless the file already holds these bytes.
pub fn write3(out: &Path) -> Result<PathBuf, String> {
    write_bytes(out, FILE3, &image3())
}

/// Write the image into `out`, unless the file already holds exactly these bytes. With
/// `program`, that file's bytes go on the volume as `/KINTANE/INIT.ELF`; with `linux`, as
/// `/KINTANE/LINUX.ELF`.
pub fn write(out: &Path, program: Option<&Path>, linux: Option<&Path>) -> Result<PathBuf, String> {
    let path = out.join(FILE);
    let read = |p: &Path| std::fs::read(p).map_err(|e| format!("{}: {e}", p.display()));
    let program = program.map(read).transpose()?;
    let linux = linux.map(read).transpose()?;
    let bytes = image(program.as_deref(), linux.as_deref())?;
    if std::fs::read(&path).is_ok_and(|existing| existing == bytes) {
        return Ok(path);
    }
    std::fs::write(&path, &bytes).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `(seed, offset, byte)` of `out_byte`: the same triples the kernel's side pins.
    const PINNED_OUT: [(u8, usize, u8); 8] = [
        (0x4e, 0, 0x27),
        (0x4e, 1, 0x1b),
        (0x4e, 511, 0x86),
        (0x4e, 999, 0xf3),
        (0x4c, 0, 0xbc),
        (0x4c, 1, 0x80),
        (0x4c, 511, 0x1d),
        (0x4c, 999, 0x68),
    ];

    #[test]
    fn the_pinned_bytes_of_a_written_file_match_the_kernels_side() {
        for (seed, offset, byte) in PINNED_OUT {
            assert_eq!(out_byte(seed, offset), byte, "seed {seed:#x} offset {offset}");
        }
    }

    /// `(sector, offset, byte)`: the same triples `kernel/block/src/testdisk.rs` pins.
    const PINNED: [(u64, usize, u8); 4] = [
        (0, 16, 0x4f),
        (7, 0, 0x22),
        (1000, 511, 0x79),
        (4095, 200, 0xf9),
    ];

    /// `(offset, byte)` of `/BIG.BIN`: the same pairs the kernel's side pins.
    const PINNED_BIG: [(usize, u8); 6] = [
        (0, 0x00),
        (511, 0xd4),
        (512, 0xca),
        (4096, 0x53),
        (65535, 0x45),
        (99999, 0xf2),
    ];

    #[test]
    fn the_pinned_bytes_match_the_kernels_side() {
        let disk = image(None, None).unwrap();
        for (sector, offset, byte) in PINNED {
            let at = sector as usize * SECTOR + offset;
            assert_eq!(disk[at], byte, "sector {sector} offset {offset}");
        }
        for (offset, byte) in PINNED_BIG {
            assert_eq!(big_byte(offset), byte, "BIG.BIN offset {offset}");
        }
    }

    #[test]
    fn the_first_disks_image_is_unchanged_by_there_being_a_second() {
        // Disk 0 folds in zero: every pinned byte of the first image still holds.
        let disk = image(None, None).unwrap();
        for (sector, offset, byte) in PINNED {
            let at = sector as usize * SECTOR + offset;
            assert_eq!(disk[at], byte, "sector {sector} offset {offset}");
            assert_eq!(pattern_on(0, sector, offset), pattern(sector, offset));
        }
    }

    #[test]
    fn the_second_disk_shares_no_sector_with_the_first() {
        let first = image(None, None).unwrap();
        let second = image2();
        assert_eq!(second.len(), SECTORS2 as usize * SECTOR);
        assert_eq!(&second[..8], MAGIC, "the second disk carries the same format");
        assert_eq!(
            u32::from_le_bytes(second[12..16].try_into().unwrap()),
            SECTORS2 as u32,
            "and names its own length, so a swap is caught by geometry too"
        );
        // Past the header, the two disks share almost no byte of any sector.
        for sector in [1usize, 7, 1000, SECTORS2 as usize - 1] {
            let a = &first[sector * SECTOR..][..SECTOR];
            let b = &second[sector * SECTOR..][..SECTOR];
            let same = a.iter().zip(b.iter()).filter(|(x, y)| x == y).count();
            assert!(same < SECTOR / 16, "sector {sector}: {same} of {SECTOR} bytes equal");
        }
    }

    #[test]
    fn the_second_disks_image_is_the_same_on_every_build() {
        assert_eq!(image2(), image2());
    }

    #[test]
    fn the_third_disk_shares_no_sector_with_the_others_and_names_its_own_length() {
        let first = image(None, None).unwrap();
        let second = image2();
        let third = image3();
        assert_eq!(third.len(), SECTORS3 as usize * SECTOR);
        assert_eq!(&third[..8], MAGIC, "the third disk carries the same format");
        assert_eq!(
            u32::from_le_bytes(third[12..16].try_into().unwrap()),
            SECTORS3 as u32,
            "and names its own length, which is how a header tells it from the second disk"
        );
        // Pairwise distinct lengths. Two images of one length would be two disks no header
        // could tell apart — which is what the PCIe function was, while it shared FILE2.
        assert_ne!(SECTORS, SECTORS2);
        assert_ne!(SECTORS, SECTORS3);
        assert_ne!(SECTORS2, SECTORS3);
        // Past the header, no two of the three share a sector.
        for sector in [1usize, 7, 1000, SECTORS3 as usize - 1] {
            for (what, a, b) in [
                ("first/third", &first, &third),
                ("second/third", &second, &third),
            ] {
                let a = &a[sector * SECTOR..][..SECTOR];
                let b = &b[sector * SECTOR..][..SECTOR];
                let same = a.iter().zip(b.iter()).filter(|(x, y)| x == y).count();
                assert!(same < SECTOR / 16, "{what} sector {sector}: {same} of {SECTOR} equal");
            }
        }
    }

    #[test]
    fn the_third_disks_image_is_the_same_on_every_build() {
        assert_eq!(image3(), image3());
    }

    #[test]
    fn the_header_is_where_the_kernel_reads_it() {
        let disk = image(None, None).unwrap();
        assert_eq!(&disk[..8], MAGIC);
        assert_eq!(u32::from_le_bytes(disk[8..12].try_into().unwrap()), VERSION);
        assert_eq!(u32::from_le_bytes(disk[12..16].try_into().unwrap()), SECTORS as u32);
        assert_eq!(disk.len(), SECTORS as usize * SECTOR);
    }

    #[test]
    fn the_volume_starts_where_the_kernel_mounts_it() {
        let disk = image(None, None).unwrap();
        let boot = &disk[FS_START as usize * SECTOR..][..SECTOR];
        assert_eq!(&boot[510..512], &[0x55, 0xAA], "a boot sector at FS_START");
        assert_eq!(&boot[54..62], b"FAT16   ");
        assert_eq!(
            u32::from_le_bytes(boot[28..32].try_into().unwrap()),
            FS_START as u32,
            "the boot sector records where the volume sits"
        );
        assert_eq!(u32::from_le_bytes(boot[32..36].try_into().unwrap()), FS_SECTORS as u32);
        // The last pattern sector is still the pattern: the volume did not start early.
        let before = &disk[(FS_START as usize - 1) * SECTOR..][..SECTOR];
        assert_eq!(before[0], pattern(FS_START - 1, 0));
    }

    #[test]
    fn the_program_is_placed_on_the_volume_when_there_is_one() {
        let program: Vec<u8> = (0..20_000u32).map(|i| (i * 7 + 3) as u8).collect();
        let with = image(Some(&program), None).unwrap();
        let without = image(None, None).unwrap();
        let volume = &with[FS_START as usize * SECTOR..];
        assert!(
            volume.windows(64).any(|w| w == &program[..64]),
            "the program's bytes are on the volume"
        );
        assert_eq!(
            &with[..FS_START as usize * SECTOR],
            &without[..FS_START as usize * SECTOR],
            "a program changes the volume and nothing before it"
        );
    }

    #[test]
    fn the_image_is_the_same_bytes_every_time() {
        assert_eq!(image(None, None).unwrap(), image(None, None).unwrap());
        let program = [0x7Fu8, b'E', b'L', b'F', 1, 2, 3];
        assert_eq!(image(Some(&program), None).unwrap(), image(Some(&program), None).unwrap());
    }
}

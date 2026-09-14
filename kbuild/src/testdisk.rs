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
//! byte-identical on every build. QEMU attaches it with `snapshot=on`, so a test run's
//! writes never reach the file and every boot starts from the same bytes.

use std::path::{Path, PathBuf};

use crate::fat16::{self, File, Params};

const MAGIC: &[u8; 8] = b"KTBLKDSK";
const VERSION: u32 = 2;
const HEADER_BYTES: usize = 16;
const SECTOR: usize = 512;
const SCRATCH_START: u64 = 4096;
const SCRATCH_SECTORS: u64 = 256;
/// The volume's first sector: right after the scratch area.
const FS_START: u64 = SCRATCH_START + SCRATCH_SECTORS;
/// 4 MiB of FAT16 with one sector per cluster, which is 8 095 clusters: FAT16 by the
/// specification's count, and small enough to write on every build.
const FS_SECTORS: u64 = 8192;
pub const SECTORS: u64 = FS_START + FS_SECTORS;

/// The config symbol that attaches the disk.
pub const SYMBOL: &str = "QEMU_BLOCK_TEST";

/// The file name, next to the image in the build's output directory.
pub const FILE: &str = "testdisk.img";

/// `/HELLO.TXT`: one cluster.
const HELLO: &[u8] = b"hello from the KinTane test disk\n";
/// `/SUB/NESTED.TXT`: one cluster, one directory down.
const NESTED: &[u8] = b"a file in a directory\n";
/// `/BIG.BIN`'s length: two hundred clusters, so reading it walks a chain.
const BIG_LEN: usize = 100_000;
/// Where the user program goes.
const PROGRAM: &str = "KINTANE/INIT.ELF";

const fn pattern(sector: u64, offset: usize) -> u8 {
    let s = (sector as u32).wrapping_mul(2_654_435_761);
    let o = (offset as u32).wrapping_mul(40_503);
    (s.wrapping_add(o).wrapping_add(sector as u32 >> 3) >> 13) as u8
}

/// The byte at offset `i` of `/BIG.BIN`. Unlike the sector pattern in shape, so a read of
/// the file that lands in the pattern region matches nothing.
const fn big_byte(i: usize) -> u8 {
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

/// The whole image. `program` is the user program to place on the volume, if there is one.
pub fn image(program: Option<&[u8]>) -> Result<Vec<u8>, String> {
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
    let volume = fat16::volume(&files, &VOLUME)?;
    disk[pattern_bytes..].copy_from_slice(&volume);
    Ok(disk)
}

/// Write the image into `out`, unless the file already holds exactly these bytes. With
/// `program`, that file's bytes go on the volume as `/KINTANE/INIT.ELF`.
pub fn write(out: &Path, program: Option<&Path>) -> Result<PathBuf, String> {
    let path = out.join(FILE);
    let program = program
        .map(|p| std::fs::read(p).map_err(|e| format!("{}: {e}", p.display())))
        .transpose()?;
    let bytes = image(program.as_deref())?;
    if std::fs::read(&path).is_ok_and(|existing| existing == bytes) {
        return Ok(path);
    }
    std::fs::write(&path, &bytes).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(path)
}

/// The image's path, for a QEMU command line, given the kernel image QEMU boots.
pub fn beside(image: &Path) -> PathBuf {
    image.parent().unwrap_or(Path::new(".")).join(FILE)
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let disk = image(None).unwrap();
        for (sector, offset, byte) in PINNED {
            let at = sector as usize * SECTOR + offset;
            assert_eq!(disk[at], byte, "sector {sector} offset {offset}");
        }
        for (offset, byte) in PINNED_BIG {
            assert_eq!(big_byte(offset), byte, "BIG.BIN offset {offset}");
        }
    }

    #[test]
    fn the_header_is_where_the_kernel_reads_it() {
        let disk = image(None).unwrap();
        assert_eq!(&disk[..8], MAGIC);
        assert_eq!(u32::from_le_bytes(disk[8..12].try_into().unwrap()), VERSION);
        assert_eq!(u32::from_le_bytes(disk[12..16].try_into().unwrap()), SECTORS as u32);
        assert_eq!(disk.len(), SECTORS as usize * SECTOR);
    }

    #[test]
    fn the_volume_starts_where_the_kernel_mounts_it() {
        let disk = image(None).unwrap();
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
        let with = image(Some(&program)).unwrap();
        let without = image(None).unwrap();
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
        assert_eq!(image(None).unwrap(), image(None).unwrap());
        let program = [0x7Fu8, b'E', b'L', b'F', 1, 2, 3];
        assert_eq!(image(Some(&program)).unwrap(), image(Some(&program)).unwrap());
    }
}

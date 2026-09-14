//! The disk image test builds attach to a virtio-blk device.
//!
//! The kernel's side of the format is `kernel/block/src/testdisk.rs`; neither may depend on
//! the other, so the format is written twice and pinned by [`PINNED`], which both sides'
//! tests assert. See that file for why the format is what it is.
//!
//! The image is a pure function of its constants, so it is byte-identical on every build.
//! QEMU attaches it with `snapshot=on`, so a test run's writes never reach the file and
//! every boot starts from the same bytes.

use std::path::{Path, PathBuf};

const MAGIC: &[u8; 8] = b"KTBLKDSK";
const VERSION: u32 = 1;
const HEADER_BYTES: usize = 16;
const SECTOR: usize = 512;
pub const SECTORS: u64 = 4096;

/// The config symbol that attaches the disk.
pub const SYMBOL: &str = "QEMU_BLOCK_TEST";

/// The file name, next to the image in the build's output directory.
pub const FILE: &str = "testdisk.img";

const fn pattern(sector: u64, offset: usize) -> u8 {
    let s = (sector as u32).wrapping_mul(2_654_435_761);
    let o = (offset as u32).wrapping_mul(40_503);
    (s.wrapping_add(o).wrapping_add(sector as u32 >> 3) >> 13) as u8
}

/// The whole image.
pub fn image() -> Vec<u8> {
    let mut disk = vec![0u8; SECTORS as usize * SECTOR];
    for (sector, bytes) in disk.chunks_exact_mut(SECTOR).enumerate() {
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = pattern(sector as u64, i);
        }
    }
    disk[..8].copy_from_slice(MAGIC);
    disk[8..12].copy_from_slice(&VERSION.to_le_bytes());
    disk[12..HEADER_BYTES].copy_from_slice(&(SECTORS as u32).to_le_bytes());
    disk
}

/// Write the image into `out`, unless the file already holds exactly these bytes.
pub fn write(out: &Path) -> Result<PathBuf, String> {
    let path = out.join(FILE);
    let bytes = image();
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

    #[test]
    fn the_pinned_bytes_match_the_kernels_side() {
        let disk = image();
        for (sector, offset, byte) in PINNED {
            let at = sector as usize * SECTOR + offset;
            assert_eq!(disk[at], byte, "sector {sector} offset {offset}");
        }
    }

    #[test]
    fn the_header_is_where_the_kernel_reads_it() {
        let disk = image();
        assert_eq!(&disk[..8], MAGIC);
        assert_eq!(u32::from_le_bytes(disk[8..12].try_into().unwrap()), VERSION);
        assert_eq!(u32::from_le_bytes(disk[12..16].try_into().unwrap()), SECTORS as u32);
        assert_eq!(disk.len(), 2 * 1024 * 1024);
    }

    #[test]
    fn the_image_is_the_same_bytes_every_time() {
        assert_eq!(image(), image());
    }
}

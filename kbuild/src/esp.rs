//! EFI system partition disk images, written from scratch.
//!
//! A UEFI machine boots from a FAT file system on a partition marked as an EFI system
//! partition. The volume itself comes from [`crate::fat16`], which also writes the test
//! disk's; what is particular to the ESP is its shape and the disk around it:
//!
//! - an MBR with one partition of type `0xEF`;
//! - FAT16, with a fixed 32 MiB size and 2 KiB clusters, which gives 16 000-odd clusters,
//!   comfortably inside FAT16's range at both ends;
//! - 8.3 names only. The firmware looks up `\EFI\BOOT\BOOTX64.EFI` and the loader looks up
//!   `\KINTANE\KERNEL.ELF`, and neither needs a long-name entry.
//!
//! The image is **reproducible**: see [`crate::fat16`] for why the volume is, and the MBR
//! below has no field that depends on when or where it was written.
//!
//! MBR rather than GPT because the UEFI specification requires firmware to accept both,
//! OVMF does, and an MBR is 66 bytes where a GPT is two headers, two partition arrays
//! and four CRCs. GPT becomes worth it with a second partition to describe.

pub use crate::fat16::File;
#[cfg(test)]
use crate::fat16::short_name;
use crate::fat16::{self, Params};

const SECTOR: usize = fat16::SECTOR;
/// The partition starts at 1 MiB, the alignment every partitioning tool uses.
const PARTITION_START: u32 = 2048;
/// 32 MiB of FAT16.
const PARTITION_SECTORS: u32 = 65536;
const SECTORS_PER_CLUSTER: u8 = 4;
#[cfg(test)]
const CLUSTER: usize = SECTOR * SECTORS_PER_CLUSTER as usize;
#[cfg(test)]
const ATTR_VOLUME_ID: u8 = 0x08;
#[cfg(test)]
const ATTR_DIRECTORY: u8 = 0x10;

/// The ESP's shape. Every value is what it was when this module wrote its own volume, so
/// the image's bytes did not change when the writer moved to `fat16`.
const ESP: Params = Params {
    sectors: PARTITION_SECTORS,
    sectors_per_cluster: SECTORS_PER_CLUSTER,
    reserved_sectors: 1,
    fats: 2,
    root_entries: 512,
    hidden_sectors: PARTITION_START,
    label: *b"KINTANE    ",
    volume_id: 0x4B49_4E54,
    what: "the EFI system partition",
};

/// A whole disk: an MBR, then one EFI system partition holding `files`.
pub fn disk_image(files: &[File<'_>]) -> Result<Vec<u8>, String> {
    let volume = fat16::volume(files, &ESP)?;
    let mut disk = vec![0u8; PARTITION_START as usize * SECTOR];
    mbr(&mut disk[..SECTOR]);
    disk.extend_from_slice(&volume);
    Ok(disk)
}

fn mbr(s: &mut [u8]) {
    // Disk signature, a constant for reproducibility.
    s[440..444].copy_from_slice(&0x544E_494Bu32.to_le_bytes());
    let p = &mut s[446..462];
    // Not active: UEFI ignores the flag, and BIOS has nothing to boot here.
    p[0] = 0x00;
    // CHS fields saturated, which says "use the LBA fields" to anything that looks.
    p[1..4].copy_from_slice(&[0xFE, 0xFF, 0xFF]);
    p[4] = 0xEF;
    p[5..8].copy_from_slice(&[0xFE, 0xFF, 0xFF]);
    p[8..12].copy_from_slice(&PARTITION_START.to_le_bytes());
    p[12..16].copy_from_slice(&PARTITION_SECTORS.to_le_bytes());
    s[510..512].copy_from_slice(&[0x55, 0xAA]);
}

/// The ESP volume's layout, for the tests below that check it against the specification.
#[cfg(test)]
fn geometry() -> fat16::Layout {
    fat16::layout(&ESP).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An independent reader: follows the MBR, the boot sector's geometry, directory
    /// entries and FAT chains back to a file's bytes. Written against the FAT
    /// specification's field offsets, not against the writer's constants.
    fn read(disk: &[u8], path: &str) -> Option<Vec<u8>> {
        let u16_at = |b: &[u8], at: usize| u16::from_le_bytes([b[at], b[at + 1]]) as usize;
        let u32_at =
            |b: &[u8], at: usize| u32::from_le_bytes(b[at..at + 4].try_into().unwrap()) as usize;
        assert_eq!(&disk[510..512], &[0x55, 0xAA]);
        assert_eq!(disk[446 + 4], 0xEF, "partition type is EFI system partition");
        let part = &disk[u32_at(disk, 446 + 8) * 512..];
        let bps = u16_at(part, 11);
        let spc = part[13] as usize;
        let reserved = u16_at(part, 14);
        let fats = part[16] as usize;
        let root_entries = u16_at(part, 17);
        let fat_sz = u16_at(part, 22);
        let total = u32_at(part, 32);
        assert_eq!(&part[54..62], b"FAT16   ");
        let fat = &part[reserved * bps..];
        let root_at = (reserved + fats * fat_sz) * bps;
        let root_sectors = (root_entries * 32).div_ceil(bps);
        let data_at = root_at + root_sectors * bps;
        let clusters = (total - reserved - fats * fat_sz - root_sectors) / spc;
        assert!((4085..65525).contains(&clusters), "{clusters} clusters is FAT16");

        let chain = |mut c: usize| {
            let mut out = Vec::new();
            while (2..0xFFF8).contains(&c) {
                let at = data_at + (c - 2) * spc * bps;
                out.extend_from_slice(&part[at..at + spc * bps]);
                c = u16_at(fat, c * 2);
            }
            out
        };

        let mut dir = part[root_at..root_at + root_entries * 32].to_vec();
        let components: Vec<&str> = path.split('/').collect();
        for (i, want) in components.iter().enumerate() {
            let name = short_name(want).unwrap();
            // The volume label is an entry too, and shares the name `KINTANE` with a
            // directory; a reader skips it, as every FAT driver does.
            let e = dir
                .chunks(32)
                .take_while(|e| e[0] != 0)
                .find(|e| e[11] & ATTR_VOLUME_ID == 0 && e[..11] == name)?;
            let (attr, cluster, size) = (e[11], u16_at(e, 26), u32_at(e, 28));
            if i + 1 == components.len() {
                assert_eq!(attr & ATTR_DIRECTORY, 0);
                let mut data = chain(cluster);
                data.truncate(size);
                return Some(data);
            }
            assert_ne!(attr & ATTR_DIRECTORY, 0);
            dir = chain(cluster);
            assert_eq!(&dir[..11], b".          ");
            assert_eq!(u16_at(&dir, 26), cluster, "`.` names the directory itself");
        }
        None
    }

    fn bytes(n: usize, seed: u8) -> Vec<u8> {
        (0..n)
            .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
            .collect()
    }

    #[test]
    fn files_read_back_through_directories_and_fat_chains() {
        let loader = bytes(40_000, 1);
        let kernel = bytes(CLUSTER * 3, 2);
        let tiny = bytes(1, 3);
        let disk = disk_image(&[
            File {
                path: "EFI/BOOT/BOOTX64.EFI",
                data: &loader,
            },
            File {
                path: "KINTANE/KERNEL.ELF",
                data: &kernel,
            },
            File {
                path: "KINTANE/EMPTY",
                data: &[],
            },
            File {
                path: "tiny.txt",
                data: &tiny,
            },
        ])
        .unwrap();
        assert_eq!(read(&disk, "EFI/BOOT/BOOTX64.EFI").unwrap(), loader);
        assert_eq!(read(&disk, "KINTANE/KERNEL.ELF").unwrap(), kernel);
        assert_eq!(read(&disk, "KINTANE/EMPTY").unwrap(), Vec::<u8>::new());
        assert_eq!(read(&disk, "TINY.TXT").unwrap(), tiny, "names are case-insensitive");
        assert_eq!(read(&disk, "EFI/BOOT/MISSING.EFI"), None);
        assert_eq!(disk.len(), (2048 + 65536) * 512);
    }

    #[test]
    fn a_subdirectorys_parent_entry_names_its_parent() {
        let disk = disk_image(&[File {
            path: "A/B/C/F",
            data: b"x",
        }])
        .unwrap();
        assert_eq!(read(&disk, "A/B/C/F").unwrap(), b"x");
        // A's `..` is the root, which FAT spells as cluster 0.
        let part = &disk[2048 * 512..];
        let g = geometry();
        let root_at = (1 + 2 * g.fat_sectors as usize) * 512;
        let a = &part[root_at + 32..root_at + 64];
        assert_eq!(&a[..11], b"A          ");
        let a_cluster = u16::from_le_bytes([a[26], a[27]]) as usize;
        let a_at = (g.data_start as usize + (a_cluster - 2) * 4) * 512;
        assert_eq!(&part[a_at + 32..a_at + 43], b"..         ");
        assert_eq!(&part[a_at + 58..a_at + 60], &[0, 0]);
    }

    #[test]
    fn the_same_inputs_give_the_same_bytes() {
        let k = bytes(5000, 9);
        let files = [
            File {
                path: "KINTANE/KERNEL.ELF",
                data: &k,
            },
            File {
                path: "EFI/BOOT/BOOTX64.EFI",
                data: b"MZ",
            },
        ];
        let reordered = [
            File {
                path: "EFI/BOOT/BOOTX64.EFI",
                data: b"MZ",
            },
            File {
                path: "KINTANE/KERNEL.ELF",
                data: &k,
            },
        ];
        assert!(disk_image(&files).unwrap() == disk_image(&reordered).unwrap());
    }

    #[test]
    fn names_that_fat_cannot_store_as_8_3_are_refused() {
        for bad in [
            "TOOLONGNAME.EFI",
            "A.TOOL",
            "",
            "SP ACE",
            "A.B.C",
            ".HIDDEN",
        ] {
            assert!(short_name(bad).is_err(), "{bad:?}");
        }
        assert_eq!(&short_name("bootx64.efi").unwrap(), b"BOOTX64 EFI");
        assert_eq!(&short_name("KINTANE").unwrap(), b"KINTANE    ");
    }

    #[test]
    fn a_path_used_twice_or_as_both_file_and_directory_is_an_error() {
        assert!(
            disk_image(&[
                File {
                    path: "A",
                    data: b"1"
                },
                File {
                    path: "A",
                    data: b"2"
                }
            ])
            .is_err()
        );
        assert!(
            disk_image(&[
                File {
                    path: "A",
                    data: b"1"
                },
                File {
                    path: "A/B",
                    data: b"2"
                }
            ])
            .is_err()
        );
        assert!(
            disk_image(&[
                File {
                    path: "A/B",
                    data: b"1"
                },
                File {
                    path: "A",
                    data: b"2"
                }
            ])
            .is_err()
        );
    }

    #[test]
    fn content_larger_than_the_partition_is_refused() {
        let huge = vec![0u8; 40 * 1024 * 1024];
        let e = disk_image(&[File {
            path: "BIG",
            data: &huge,
        }])
        .unwrap_err();
        assert!(e.contains("full"), "{e}");
    }

    #[test]
    fn the_geometry_is_fat16_and_the_fat_covers_every_cluster() {
        let g = geometry();
        assert!((4085..65525).contains(&g.clusters), "{}", g.clusters);
        assert!(g.fat_sectors as u32 * 512 / 2 >= g.clusters + 2);
        // And is the smallest such FAT: one sector less would not cover them.
        let smaller = g.fat_sectors as u32 - 1;
        let data_start = 1 + 2 * smaller + g.root_sectors;
        let clusters = (PARTITION_SECTORS - data_start) / 4;
        assert!(smaller * 512 / 2 < clusters + 2);
    }
}

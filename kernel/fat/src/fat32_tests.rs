//! FAT32: the three places it differs from FAT16, and the crash rule on a volume of its own.
//!
//! The builder below writes an empty FAT32 volume from the specification's field offsets, as
//! the FAT16 builders in the other two test modules do. A volume is genuinely FAT32 — its
//! cluster count is above the specification's boundary — so it is 34 MiB of memory per test.
//! That is the price of testing the format rather than a small volume pretending to be it.
//!
//! What is checked here and nowhere else:
//!
//! * the root is a chain, so it grows when its first cluster is full, which FAT16's fixed region
//!   cannot;
//! * a table entry is 28 bits, so a cluster number above 65 535 round-trips through the entry's two
//!   halves, and the four bits above the 28 are left as they were found;
//! * the FSInfo sector's free count is this driver's own after a sync, whatever it held before.

use std::cell::RefCell;

use block::{BlockDevice, Error as BlockError, Geometry};
use vfs::{Error, FileSystem, Kind, OpenFlags, Vfs};

use crate::{Consistency, Fat, Format};

const SECTOR: usize = 512;
/// One sector per cluster: the smallest volume that is FAT32 by its cluster count.
const SPC: usize = 1;
/// FAT32 reserves more than one sector: the FSInfo sector and a backup boot sector live here.
const RESERVED: usize = 32;
const FATS: usize = 2;
/// Just above the boundary the specification draws between FAT16 and FAT32.
const CLUSTERS: usize = 65_540;
const ENTRY: usize = 32;
/// Where the FSInfo sector sits, counted from the volume's first sector.
const FSINFO_SECTOR: usize = 1;
/// The root's first cluster, as the boot sector names it.
const ROOT_CLUSTER: u32 = 2;
const END: u32 = 0x0FFF_FFFF;

fn fat_sectors() -> usize {
    ((CLUSTERS + 2) * 4).div_ceil(SECTOR)
}

fn total_sectors() -> usize {
    RESERVED + FATS * fat_sectors() + CLUSTERS * SPC
}

fn fat_at(copy: usize, cluster: u32) -> usize {
    (RESERVED + copy * fat_sectors()) * SECTOR + cluster as usize * 4
}

fn data_start() -> usize {
    (RESERVED + FATS * fat_sectors()) * SECTOR
}

fn cluster_at(cluster: u32) -> usize {
    data_start() + (cluster as usize - 2) * SPC * SECTOR
}

/// An empty FAT32 volume: a boot sector, an FSInfo sector, two tables holding their reserved
/// entries and the root's, and a root of one zeroed cluster.
fn format32() -> Vec<u8> {
    let mut v = vec![0u8; total_sectors() * SECTOR];
    let fat = fat_sectors();
    {
        let s = &mut v[..SECTOR];
        s[0..3].copy_from_slice(&[0xEB, 0x58, 0x90]);
        s[3..11].copy_from_slice(b"KINTANE ");
        s[11..13].copy_from_slice(&(SECTOR as u16).to_le_bytes());
        s[13] = SPC as u8;
        s[14..16].copy_from_slice(&(RESERVED as u16).to_le_bytes());
        s[16] = FATS as u8;
        // A FAT32 volume's root is a chain, so the fixed-region count is zero, and its table
        // size is the 32-bit field.
        s[17..19].copy_from_slice(&0u16.to_le_bytes());
        s[19..21].copy_from_slice(&0u16.to_le_bytes());
        s[21] = 0xF8;
        s[22..24].copy_from_slice(&0u16.to_le_bytes());
        s[32..36].copy_from_slice(&(total_sectors() as u32).to_le_bytes());
        s[36..40].copy_from_slice(&(fat as u32).to_le_bytes());
        s[44..48].copy_from_slice(&ROOT_CLUSTER.to_le_bytes());
        s[48..50].copy_from_slice(&(FSINFO_SECTOR as u16).to_le_bytes());
        s[50..52].copy_from_slice(&6u16.to_le_bytes());
        s[54..62].copy_from_slice(b"FAT32   ");
        s[510..512].copy_from_slice(&[0x55, 0xAA]);
    }
    write_fsinfo(&mut v, 0xFFFF_FFFF);
    for copy in 0..FATS {
        put32(&mut v, fat_at(copy, 0), 0x0FFF_FFF8);
        put32(&mut v, fat_at(copy, 1), END);
        put32(&mut v, fat_at(copy, ROOT_CLUSTER), END);
    }
    v
}

/// Put `free` in the FSInfo sector, with the signatures a reader checks.
fn write_fsinfo(v: &mut [u8], free: u32) {
    let at = FSINFO_SECTOR * SECTOR;
    put32(v, at, 0x4161_5252);
    put32(v, at + 484, 0x6141_7272);
    put32(v, at + 488, free);
    put32(v, at + 492, 0xFFFF_FFFF);
    put32(v, at + 508, 0xAA55_0000);
}

fn put32(v: &mut [u8], at: usize, value: u32) {
    v[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

fn get32(v: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([v[at], v[at + 1], v[at + 2], v[at + 3]])
}

/// A disk in memory that records every block written to it.
struct Disk {
    data: RefCell<Vec<u8>>,
    log: RefCell<Vec<(u64, Vec<u8>)>>,
}

impl Disk {
    fn new(image: Vec<u8>) -> Disk {
        Disk {
            data: RefCell::new(image),
            log: RefCell::new(Vec::new()),
        }
    }

    fn image(&self) -> Vec<u8> {
        self.data.borrow().clone()
    }
}

impl BlockDevice for Disk {
    fn geometry(&self) -> Geometry {
        Geometry::new(SECTOR, (self.data.borrow().len() / SECTOR) as u64).unwrap()
    }

    fn max_transfer_blocks(&self) -> u64 {
        16
    }

    fn read_blocks(&self, lba: u64, into: &mut [u8]) -> Result<(), BlockError> {
        self.geometry().range(lba, into.len())?;
        let at = lba as usize * SECTOR;
        into.copy_from_slice(&self.data.borrow()[at..at + into.len()]);
        Ok(())
    }

    fn write_blocks(&self, lba: u64, from: &[u8]) -> Result<(), BlockError> {
        self.geometry().range(lba, from.len())?;
        let at = lba as usize * SECTOR;
        self.data.borrow_mut()[at..at + from.len()].copy_from_slice(from);
        self.log.borrow_mut().push((lba, from.to_vec()));
        Ok(())
    }

    fn flush(&self) -> Result<(), BlockError> {
        Ok(())
    }
}

/// Run `f` on the volume `disk` holds, through a cache of `slots` blocks.
fn with_volume<R>(disk: &Disk, slots: usize, f: impl FnOnce(&mut Fat<'_, '_>) -> R) -> R {
    let mut slot_array = vec![bcache::Slot::EMPTY; slots];
    let mut data = vec![0u8; slots * SECTOR];
    let cache = bcache::Cache::new(&mut slot_array, &mut data, SECTOR).unwrap();
    let mut fat = Fat::mount(disk, cache, 0).unwrap();
    f(&mut fat)
}

fn consistency(fat: &mut Fat<'_, '_>) -> Result<Consistency, Error> {
    let mut seen = vec![0u8; (fat.clusters() as usize + 2).div_ceil(8)];
    fat.check_consistency(&mut seen)
}

/// Consistent, nothing lost, the tables the same, nothing left unwritten.
fn assert_clean(fat: &mut Fat<'_, '_>) -> Consistency {
    assert_eq!(fat.dirty_blocks(), 0, "a synced volume holds nothing back");
    fat.check_cache().unwrap();
    let c = consistency(fat).unwrap();
    assert_eq!(c.lost, 0, "a volume written without a crash loses nothing: {c:?}");
    assert_eq!(c.fats_differ, 0, "the table copies agree once synced: {c:?}");
    c
}

fn write_file(ns: &mut Vfs<'_, 1, 4>, path: &str, bytes: &[u8]) {
    let flags = OpenFlags {
        write: true,
        create: true,
        truncate: true,
        ..OpenFlags::READ
    };
    let fd = ns.open_with(path, flags).unwrap();
    let mut done = 0;
    let mut piece = 1;
    while done < bytes.len() {
        let take = piece.min(bytes.len() - done);
        assert_eq!(ns.write(fd, &bytes[done..done + take]).unwrap(), take);
        done += take;
        piece = piece * 3 + 7;
    }
    ns.close(fd).unwrap();
}

fn read_file(ns: &mut Vfs<'_, 1, 4>, path: &str) -> Vec<u8> {
    let mut buf = vec![0u8; 1 << 16];
    let n = ns.read_all(path, &mut buf).unwrap();
    buf.truncate(n);
    buf
}

fn pattern(seed: u8, len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u8).wrapping_mul(seed).wrapping_add(seed ^ 0x5A))
        .collect()
}

#[test]
fn the_cluster_count_makes_it_fat32_and_its_geometry_reads_back() {
    let disk = Disk::new(format32());
    with_volume(&disk, 8, |fat| {
        assert_eq!(fat.format(), Format::Fat32);
        assert_eq!(fat.clusters(), CLUSTERS as u32);
        // Every cluster but the root's is free on a volume with nothing on it.
        assert_eq!(fat.free_count(), CLUSTERS as u32 - 1);
        // And the namespace hears the same numbers in its own unit.
        let s = FileSystem::statfs(fat).unwrap();
        assert_eq!(s.block_size, (SPC * SECTOR) as u64);
        assert_eq!((s.blocks, s.free), (CLUSTERS as u64, CLUSTERS as u64 - 1));
        let c = consistency(fat).unwrap();
        assert_eq!((c.files, c.dirs, c.lost), (0, 0, 0));
        assert_eq!(c.claimed, 1, "the root's own cluster is claimed, not lost");
        assert_eq!(c.free, CLUSTERS as u32 - 1);
    });
}

/// FAT16's root is a fixed region and fills up; FAT32's is a chain and grows. Sixteen entries
/// fit one 512-byte cluster, so forty files need three of them.
#[test]
fn the_root_grows_past_its_first_cluster() {
    let disk = Disk::new(format32());
    with_volume(&disk, 32, |fat| {
        let mut ns = Vfs::<1, 4>::new();
        ns.mount("/", fat).unwrap();
        for i in 0..40 {
            write_file(&mut ns, &format!("/F{i}.TXT"), format!("file {i}").as_bytes());
        }
        for i in 0..40 {
            assert_eq!(read_file(&mut ns, &format!("/f{i}.txt")), format!("file {i}").as_bytes());
        }
        let mut listed = 0;
        while ns.readdir("/", listed).unwrap().is_some() {
            listed += 1;
        }
        assert_eq!(listed, 40, "every name is in the root, which grew to hold them");
        ns.sync().unwrap();
        ns.unmount("/").unwrap();
    });
    // Mounted again from what reached the device: the root's chain is still whole.
    with_volume(&disk, 8, |fat| {
        let c = assert_clean(fat);
        assert_eq!(c.files, 40);
        assert!(c.claimed >= 3 + 40, "the root's clusters and each file's: {c:?}");
        let mut ns = Vfs::<1, 4>::new();
        ns.mount("/", fat).unwrap();
        assert_eq!(read_file(&mut ns, "/F39.TXT"), b"file 39");
    });
}

/// A cluster number above 65 535 does not fit the entry field FAT16 uses, and lives in two
/// halves of a directory entry. The volume starts with its low clusters already taken — what a
/// crash leaves as lost clusters — so the allocator reaches a high one without writing 33 MiB.
#[test]
fn a_cluster_above_sixteen_bits_round_trips_through_both_halves() {
    let mut image = format32();
    for cluster in 3..=0x1_0000u32 {
        for copy in 0..FATS {
            put32(&mut image, fat_at(copy, cluster), END);
        }
    }
    let disk = Disk::new(image);
    let data = pattern(9, 1500);
    with_volume(&disk, 32, |fat| {
        let root = fat.root();
        let node = fat.create(root, b"HIGH.BIN", Kind::File).unwrap();
        fat.write_at(node, 0, &data).unwrap();
        fat.sync().unwrap();
        let mut buf = vec![0u8; data.len()];
        assert_eq!(fat.read_at(node, 0, &mut buf).unwrap(), data.len());
        assert_eq!(buf, data, "read back through a chain of high clusters");
    });

    // The entry on the device names its first cluster in both halves.
    let image = disk.image();
    let at = cluster_at(ROOT_CLUSTER);
    let entry = &image[at..at + ENTRY];
    assert_eq!(&entry[..8], b"HIGH    ", "the file's entry is the root's first");
    let low = u16::from_le_bytes([entry[26], entry[27]]) as u32;
    let high = u16::from_le_bytes([entry[20], entry[21]]) as u32;
    let first = (high << 16) | low;
    assert!(first > 0xFFFF, "the file starts at cluster {first}, which needs both halves");
    assert_ne!(high, 0, "the high half carries the cluster's top bits");

    with_volume(&disk, 16, |fat| {
        let c = consistency(fat).unwrap();
        assert_eq!(c.files, 1);
        assert_eq!(c.fats_differ, 0);
        // The clusters marked taken before the mount belong to no chain: lost, not corrupt.
        assert_eq!(c.lost, 0x1_0000 - 2);
    });
}

/// The four bits above a FAT32 entry's 28 are the volume's, not this driver's.
#[test]
fn the_bits_above_a_table_entry_are_left_as_they_were() {
    let mut image = format32();
    // Cluster 3 is the first the allocator will take; mark its spare bits in both copies.
    for copy in 0..FATS {
        put32(&mut image, fat_at(copy, 3), 0xF000_0000);
    }
    let disk = Disk::new(image);
    with_volume(&disk, 16, |fat| {
        let root = fat.root();
        let node = fat.create(root, b"A.BIN", Kind::File).unwrap();
        fat.write_at(node, 0, &[7u8; 400]).unwrap();
        fat.sync().unwrap();
    });
    let image = disk.image();
    let entry = get32(&image, fat_at(0, 3));
    assert_eq!(entry >> 28, 0xF, "the spare bits survived the allocation");
    assert_eq!(entry & 0x0FFF_FFFF, 0x0FFF_FFFF, "and the chain ends there");
}

/// The specification lets FSInfo's count be stale. This driver does not: it counts the table
/// at mount and writes its own count at every sync.
#[test]
fn the_free_count_in_fsinfo_is_the_tables_after_a_sync() {
    let mut image = format32();
    // A count no volume ever had, as a crash might have left behind.
    write_fsinfo(&mut image, 12_345);
    let disk = Disk::new(image);
    let mut expected = 0;
    with_volume(&disk, 32, |fat| {
        assert_eq!(fat.free_count(), CLUSTERS as u32 - 1, "counted from the table, not read");
        let root = fat.root();
        let node = fat.create(root, b"B.BIN", Kind::File).unwrap();
        fat.write_at(node, 0, &pattern(3, 4000)).unwrap();
        fat.sync().unwrap();
        expected = fat.free_count();
        let c = assert_clean(fat);
        assert_eq!(c.free, expected, "the walk counts what the driver counts");
        assert_eq!(c.fsinfo_free, Some(expected), "and FSInfo says the same");
    });
    let image = disk.image();
    assert_eq!(
        get32(&image, FSINFO_SECTOR * SECTOR + 488),
        expected,
        "the sector on the device holds the count too"
    );
    // Eight clusters for 4 000 bytes of file, and the root's: the rest is free.
    assert_eq!(expected, CLUSTERS as u32 - 1 - 8);
}

/// A volume whose FSInfo sector holds something else is refused rather than written over.
#[test]
fn an_fsinfo_sector_without_its_signatures_is_refused() {
    let mut image = format32();
    put32(&mut image, FSINFO_SECTOR * SECTOR, 0xDEAD_BEEF);
    let disk = Disk::new(image);
    let mut slots = vec![bcache::Slot::EMPTY; 8];
    let mut data = vec![0u8; 8 * SECTOR];
    let cache = bcache::Cache::new(&mut slots, &mut data, SECTOR).unwrap();
    let err = Fat::mount(&disk, cache, 0).map(|_| ()).unwrap_err();
    assert_eq!(err, Error::Corrupt("an FSInfo sector without its signatures"));
}

/// The crash rule, on a volume whose root is a chain: every point the device could have
/// stopped leaves a volume that mounts and walks.
#[test]
fn every_point_a_crash_could_stop_the_device_leaves_fat32_consistent() {
    let base = format32();
    let disk = Disk::new(base.clone());
    with_volume(&disk, 16, |fat| {
        let mut ns = Vfs::<1, 4>::new();
        ns.mount("/", fat).unwrap();
        ns.mkdir("/SUB").unwrap();
        write_file(&mut ns, "/SUB/A.BIN", &pattern(5, 2500));
        write_file(&mut ns, "/B.BIN", &pattern(6, 900));
        ns.rename("/B.BIN", "/C.BIN").unwrap();
        let fd = ns.open("/SUB/A.BIN").unwrap();
        ns.truncate(fd, 700).unwrap();
        ns.close(fd).unwrap();
        ns.unlink("/C.BIN").unwrap();
        ns.sync().unwrap();
        ns.unmount("/").unwrap();
    });

    let log = disk.log.borrow().clone();
    assert!(log.len() > 20, "the workload wrote {} blocks", log.len());
    // Every cut point would be 34 MiB copied; a spread of them covers the same rule.
    let step = (log.len() / 12).max(1);
    for cut in (0..=log.len()).step_by(step) {
        let mut image = base.clone();
        for (lba, bytes) in &log[..cut] {
            let at = *lba as usize * SECTOR;
            image[at..at + bytes.len()].copy_from_slice(bytes);
        }
        let crashed = Disk::new(image);
        let walked = with_volume(&crashed, 8, consistency);
        match walked {
            Ok(_) => {}
            Err(e) => {
                panic!("after {cut} of {} writes the volume is inconsistent: {e:?}", log.len())
            }
        }
    }
}

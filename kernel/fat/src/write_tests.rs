//! Writing, against volumes formatted empty and filled through the driver itself.
//!
//! Two kinds of claim. The first is what any filesystem owes its caller: what was written
//! reads back, a truncated file reads zeros past its old end, a removed name is gone and its
//! clusters come back. The second is the one a crash tests: the device below records every
//! block the cache writes, in order, and every prefix of that sequence — every point at which
//! power could have been cut — is mounted fresh and must pass the consistency walk.

use std::cell::RefCell;

use block::{BlockDevice, Error as BlockError, Geometry};
use vfs::{Error, FileSystem, Kind, OpenFlags, Vfs};

use crate::{Consistency, Fat};

const SECTOR: usize = 512;
/// One sector per cluster: a 4 200-sector volume is FAT16 by its cluster count and small
/// enough to copy once per crash point.
const TOTAL: usize = 4200;
const ROOT_ENTRIES: usize = 32;
const RESERVED: usize = 1;
const FATS: usize = 2;

fn fat_sectors() -> usize {
    let root = ROOT_ENTRIES * 32 / SECTOR;
    let mut fat = 1;
    loop {
        let clusters = TOTAL - RESERVED - FATS * fat - root;
        if fat * SECTOR / 2 >= clusters + 2 {
            return fat;
        }
        fat += 1;
    }
}

/// An empty volume: a boot sector, two tables with only their reserved entries, and an empty
/// root.
fn format() -> Vec<u8> {
    let mut v = vec![0u8; TOTAL * SECTOR];
    let fat = fat_sectors();
    let s = &mut v[..SECTOR];
    s[0..3].copy_from_slice(&[0xEB, 0x3C, 0x90]);
    s[11..13].copy_from_slice(&(SECTOR as u16).to_le_bytes());
    s[13] = 1;
    s[14..16].copy_from_slice(&(RESERVED as u16).to_le_bytes());
    s[16] = FATS as u8;
    s[17..19].copy_from_slice(&(ROOT_ENTRIES as u16).to_le_bytes());
    s[19..21].copy_from_slice(&(TOTAL as u16).to_le_bytes());
    s[21] = 0xF8;
    s[22..24].copy_from_slice(&(fat as u16).to_le_bytes());
    s[510..512].copy_from_slice(&[0x55, 0xAA]);
    for copy in 0..FATS {
        let at = (RESERVED + copy * fat) * SECTOR;
        v[at..at + 4].copy_from_slice(&[0xF8, 0xFF, 0xFF, 0xFF]);
    }
    v
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

/// A clean volume: consistent, nothing lost, both tables the same, nothing left unwritten.
fn assert_clean(fat: &mut Fat<'_, '_>) -> Consistency {
    assert_eq!(fat.dirty_blocks(), 0, "a synced volume holds nothing back");
    fat.check_cache().unwrap();
    let c = consistency(fat).unwrap();
    assert_eq!(c.lost, 0, "a volume written without a crash loses nothing: {c:?}");
    assert_eq!(c.fats_differ, 0, "the table copies agree once synced: {c:?}");
    c
}

fn pattern(seed: u8, len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u8).wrapping_mul(seed).wrapping_add(seed ^ 0x5A))
        .collect()
}

fn read_file(ns: &mut Vfs<'_, 1, 4>, path: &str) -> Vec<u8> {
    let mut buf = vec![0u8; 1 << 20];
    let n = ns.read_all(path, &mut buf).unwrap();
    buf.truncate(n);
    buf
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
    // In uneven pieces, so writes start and end mid-sector and mid-cluster.
    let mut piece = 1;
    while done < bytes.len() {
        let take = piece.min(bytes.len() - done);
        assert_eq!(ns.write(fd, &bytes[done..done + take]).unwrap(), take);
        done += take;
        piece = piece * 3 + 7;
    }
    ns.close(fd).unwrap();
}

#[test]
fn a_file_written_through_the_namespace_reads_back() {
    let disk = Disk::new(format());
    with_volume(&disk, 16, |fat| {
        let mut ns = Vfs::<1, 4>::new();
        ns.mount("/", fat).unwrap();
        let big = pattern(7, 3 * SECTOR + 100);
        write_file(&mut ns, "/big.bin", &big);
        write_file(&mut ns, "/empty.txt", b"");
        assert_eq!(read_file(&mut ns, "/BIG.BIN"), big);
        assert_eq!(ns.stat("/empty.txt").unwrap().len, 0);

        // Overwrite the middle, across a cluster boundary, and append.
        let fd = ns.open("/big.bin").unwrap();
        ns.seek(fd, vfs::Whence::Start, 500).unwrap();
        ns.write(fd, &[0xEE; 30]).unwrap();
        ns.close(fd).unwrap();
        let append = OpenFlags {
            write: true,
            append: true,
            ..OpenFlags::READ
        };
        let fd = ns.open_with("/big.bin", append).unwrap();
        ns.write(fd, b"tail").unwrap();
        ns.close(fd).unwrap();
        let mut want = big.clone();
        want[500..530].fill(0xEE);
        want.extend_from_slice(b"tail");
        assert_eq!(read_file(&mut ns, "/big.bin"), want);
        ns.sync().unwrap();
        ns.unmount("/").unwrap();
    });
    // Mounted again with a cold cache, from what reached the device.
    with_volume(&disk, 4, |fat| {
        let c = assert_clean(fat);
        assert_eq!(c.files, 2);
        let mut ns = Vfs::<1, 4>::new();
        ns.mount("/", fat).unwrap();
        assert_eq!(read_file(&mut ns, "/big.bin").len(), 3 * SECTOR + 104);
    });
}

#[test]
fn a_write_past_the_end_leaves_zeros_between() {
    let disk = Disk::new(format());
    with_volume(&disk, 8, |fat| {
        let root = fat.root();
        let node = fat.create(root, b"HOLE.BIN", Kind::File).unwrap();
        fat.write_at(node, 0, b"start").unwrap();
        fat.write_at(node, 1500, b"end").unwrap();
        let mut buf = vec![0xAAu8; 1503];
        assert_eq!(fat.read_at(node, 0, &mut buf).unwrap(), 1503);
        assert_eq!(&buf[..5], b"start");
        assert!(buf[5..1500].iter().all(|&b| b == 0));
        assert_eq!(&buf[1500..], b"end");
        fat.sync().unwrap();
        assert_clean(fat);
    });
}

#[test]
fn truncating_frees_clusters_and_growing_reads_zeros() {
    let disk = Disk::new(format());
    with_volume(&disk, 8, |fat| {
        let root = fat.root();
        let node = fat.create(root, b"T.BIN", Kind::File).unwrap();
        fat.write_at(node, 0, &pattern(3, 5000)).unwrap();
        fat.sync().unwrap();
        assert_eq!(assert_clean(fat).claimed, 10);

        fat.truncate(node, 700).unwrap();
        fat.sync().unwrap();
        assert_eq!(assert_clean(fat).claimed, 2, "the clusters past the new end came back");
        fat.truncate(node, 1200).unwrap();
        let mut buf = vec![0xAAu8; 1200];
        assert_eq!(fat.read_at(node, 0, &mut buf).unwrap(), 1200);
        assert_eq!(buf[..700], pattern(3, 5000)[..700]);
        assert!(buf[700..].iter().all(|&b| b == 0), "grown bytes read as zeros");
        fat.truncate(node, 0).unwrap();
        assert_eq!(fat.stat(node).unwrap().len, 0);
        fat.sync().unwrap();
        assert_eq!(assert_clean(fat).claimed, 0);
    });
}

#[test]
fn directories_are_made_filled_past_a_cluster_and_removed_only_empty() {
    let disk = Disk::new(format());
    with_volume(&disk, 16, |fat| {
        let mut ns = Vfs::<1, 4>::new();
        ns.mount("/", fat).unwrap();
        ns.mkdir("/sub").unwrap();
        assert_eq!(ns.mkdir("/SUB"), Err(Error::Exists));
        // Sixteen entries fit one cluster, `.` and `..` among them: twenty files grow it.
        for i in 0..20 {
            write_file(&mut ns, &format!("/sub/f{i}.txt"), format!("file {i}").as_bytes());
        }
        for i in 0..20 {
            assert_eq!(
                read_file(&mut ns, &format!("/SUB/F{i}.TXT")),
                format!("file {i}").as_bytes()
            );
        }
        let mut listed = 0;
        while ns.readdir("/sub", listed).unwrap().is_some() {
            listed += 1;
        }
        assert_eq!(listed, 20);
        assert_eq!(ns.unlink("/sub"), Err(Error::NotEmpty));
        for i in 0..20 {
            ns.unlink(&format!("/sub/f{i}.txt")).unwrap();
        }
        assert_eq!(ns.stat("/sub/f3.txt"), Err(Error::NotFound));
        ns.mkdir("/sub/deeper").unwrap();
        ns.unlink("/sub/deeper").unwrap();
        ns.unlink("/sub").unwrap();
        ns.sync().unwrap();
        ns.unmount("/").unwrap();
        assert_eq!(assert_clean(fat).claimed, 0, "every cluster came back");
    });
}

#[test]
fn a_rename_keeps_the_bytes_and_replacing_frees_the_old_file() {
    let disk = Disk::new(format());
    with_volume(&disk, 16, |fat| {
        let mut ns = Vfs::<1, 4>::new();
        ns.mount("/", fat).unwrap();
        write_file(&mut ns, "/a.txt", &pattern(1, 900));
        write_file(&mut ns, "/b.txt", &pattern(2, 2000));
        ns.rename("/a.txt", "/c.txt").unwrap();
        assert_eq!(ns.stat("/a.txt"), Err(Error::NotFound));
        assert_eq!(read_file(&mut ns, "/c.txt"), pattern(1, 900));
        ns.rename("/c.txt", "/b.txt").unwrap();
        assert_eq!(read_file(&mut ns, "/b.txt"), pattern(1, 900));
        ns.rename("/b.txt", "/B.txt").unwrap();
        ns.mkdir("/d").unwrap();
        assert_eq!(ns.rename("/b.txt", "/d"), Err(Error::IsADirectory));
        ns.mkdir("/e").unwrap();
        write_file(&mut ns, "/e/x", b"x");
        assert_eq!(ns.rename("/d", "/e"), Err(Error::NotEmpty));
        // Out of the root and into `/e`: the name moves, and the bytes move with it.
        ns.rename("/b.txt", "/e/b.txt").unwrap();
        assert_eq!(ns.stat("/b.txt"), Err(Error::NotFound));
        assert_eq!(read_file(&mut ns, "/e/b.txt"), pattern(1, 900));
        ns.sync().unwrap();
        ns.unmount("/").unwrap();
        let c = assert_clean(fat);
        assert_eq!((c.files, c.dirs), (2, 2));
        // b.txt's 900 bytes, x's one, and the two directories' clusters.
        assert_eq!(c.claimed, 2 + 1 + 2);
    });
}

#[test]
fn names_that_are_not_eight_three_are_refused() {
    let disk = Disk::new(format());
    with_volume(&disk, 8, |fat| {
        let root = fat.root();
        for bad in [
            &b"toolongname.txt"[..],
            b"a.long",
            b".hidden",
            b"a b",
            b"a.b.c",
            b"x.",
            b".",
        ] {
            assert_eq!(fat.create(root, bad, Kind::File), Err(Error::BadPath), "{bad:?}");
        }
        let node = fat.create(root, b"lower.txt", Kind::File).unwrap();
        assert_eq!(fat.lookup(root, b"LOWER.TXT").unwrap(), node);
        let entry = fat.readdir(root, 0).unwrap().unwrap();
        assert_eq!(entry.name(), b"LOWER.TXT", "stored as FAT stores a short name");
        assert_eq!(fat.create(root, b"LOWER.txt", Kind::File), Err(Error::Exists));
    });
}

#[test]
fn a_full_root_and_a_full_volume_are_refused_and_leave_it_consistent() {
    let disk = Disk::new(format());
    with_volume(&disk, 16, |fat| {
        let root = fat.root();
        for i in 0..ROOT_ENTRIES {
            fat.create(root, format!("F{i}").as_bytes(), Kind::File)
                .unwrap();
        }
        assert_eq!(fat.create(root, b"ONEMORE", Kind::File), Err(Error::Full));
        fat.unlink(root, b"F0").unwrap();
        let node = fat.lookup(root, b"F1").unwrap();
        let huge = vec![0x11u8; TOTAL * SECTOR];
        assert_eq!(fat.write_at(node, 0, &huge), Err(Error::Full));
        assert_eq!(fat.stat(node).unwrap().len, 0, "a refused write changes nothing");
        // Fill it exactly, then one byte more.
        let clusters = fat.clusters() as usize;
        fat.write_at(node, 0, &vec![0x22u8; clusters * SECTOR])
            .unwrap();
        let other = fat.lookup(root, b"F2").unwrap();
        assert_eq!(fat.write_at(other, 0, b"!"), Err(Error::Full));
        fat.sync().unwrap();
        assert_clean(fat);
    });
}

#[test]
fn a_read_only_file_is_not_written() {
    let mut image = format();
    // The first root entry, marked read-only, with no clusters.
    let fat = fat_sectors();
    let root = (RESERVED + FATS * fat) * SECTOR;
    image[root..root + 11].copy_from_slice(b"LOCKED  TXT");
    image[root + 11] = 0x01;
    let disk = Disk::new(image);
    with_volume(&disk, 8, |fat| {
        let root = fat.root();
        let node = fat.lookup(root, b"LOCKED.TXT").unwrap();
        assert_eq!(fat.write_at(node, 0, b"no"), Err(Error::ReadOnly));
        assert_eq!(fat.truncate(node, 5), Err(Error::ReadOnly));
    });
}

/// A workload that creates, grows, overwrites, truncates, renames and removes, with a sync
/// in the middle and one at the end.
fn workload(fat: &mut Fat<'_, '_>) {
    let mut ns = Vfs::<1, 4>::new();
    ns.mount("/", fat).unwrap();
    ns.mkdir("/dir").unwrap();
    write_file(&mut ns, "/dir/one.bin", &pattern(5, 2600));
    write_file(&mut ns, "/two.bin", &pattern(9, 700));
    for i in 0..18 {
        write_file(&mut ns, &format!("/dir/n{i}"), &pattern(i as u8, 40 + i * 30));
    }
    ns.sync().unwrap();
    let fd = ns.open("/two.bin").unwrap();
    ns.truncate(fd, 100).unwrap();
    ns.seek(fd, vfs::Whence::End, 0).unwrap();
    ns.write(fd, &pattern(11, 3000)).unwrap();
    ns.close(fd).unwrap();
    ns.rename("/two.bin", "/three.bin").unwrap();
    write_file(&mut ns, "/four.bin", &pattern(4, 1000));
    ns.rename("/four.bin", "/three.bin").unwrap();
    for i in (0..18).step_by(2) {
        ns.unlink(&format!("/dir/n{i}")).unwrap();
    }
    ns.unlink("/dir/one.bin").unwrap();
    ns.sync().unwrap();
    ns.unmount("/").unwrap();
}

#[test]
fn every_point_a_crash_could_stop_the_writes_leaves_a_consistent_volume() {
    let base = format();
    let disk = Disk::new(base.clone());
    // A small cache, so memory pressure writes blocks back in the middle of operations too.
    with_volume(&disk, 6, workload);
    with_volume(&disk, 8, |fat| {
        assert_clean(fat);
    });
    let log = disk.log.borrow().clone();
    assert!(log.len() > 100, "the workload wrote {} blocks", log.len());
    let mut worst_lost = 0;
    let mut differing = 0;
    for cut in 0..=log.len() {
        let mut image = base.clone();
        for (lba, bytes) in &log[..cut] {
            let at = *lba as usize * SECTOR;
            image[at..at + bytes.len()].copy_from_slice(bytes);
        }
        let crashed = Disk::new(image);
        with_volume(&crashed, 8, |fat| {
            let c = consistency(fat)
                .unwrap_or_else(|e| panic!("after {cut} of {} writes: {e:?}", log.len()));
            worst_lost = worst_lost.max(c.lost);
            differing += usize::from(c.fats_differ != 0);
        });
    }
    // The crash points must reach the states the ordering exists for, or this test proves
    // nothing about them.
    assert!(worst_lost > 0, "no crash point left a lost cluster");
    assert!(differing > 0, "no crash point caught the table copies apart");
}

#[test]
fn the_walk_refuses_a_cross_link_and_a_chain_into_a_free_cluster() {
    let disk = Disk::new(format());
    with_volume(&disk, 8, |fat| {
        let root = fat.root();
        let a = fat.create(root, b"A", Kind::File).unwrap();
        let b = fat.create(root, b"B", Kind::File).unwrap();
        fat.write_at(a, 0, &[1u8; 1024]).unwrap();
        fat.write_at(b, 0, &[2u8; 1024]).unwrap();
        fat.sync().unwrap();
        assert_clean(fat);
    });
    let fat_start = RESERVED * SECTOR;
    let root = (RESERVED + FATS * fat_sectors()) * SECTOR;
    // A's chain is clusters 2 and 3, B's 4 and 5: point B's entry at 3, inside A's chain.
    {
        let mut data = disk.data.borrow_mut();
        data[root + 32 + 26..root + 32 + 28].copy_from_slice(&3u16.to_le_bytes());
    }
    with_volume(&disk, 8, |fat| {
        assert_eq!(
            consistency(fat),
            Err(Error::Corrupt("a cluster claimed twice: a cross-link or a loop"))
        );
    });
    {
        let mut data = disk.data.borrow_mut();
        data[root + 32 + 26..root + 32 + 28].copy_from_slice(&4u16.to_le_bytes());
        // Free cluster 5 in the first table while B's chain still runs into it.
        data[fat_start + 10..fat_start + 12].copy_from_slice(&0u16.to_le_bytes());
    }
    with_volume(&disk, 8, |fat| {
        assert_eq!(consistency(fat), Err(Error::Corrupt("a chain through a free cluster")));
    });
}

/// Where the entry named `name` sits in `image`, found by its eleven stored bytes.
fn entry_at(image: &[u8], name: &[u8; 11]) -> usize {
    image
        .windows(11)
        .position(|w| w == name)
        .unwrap_or_else(|| panic!("no entry named {:?} on the volume", core::str::from_utf8(name)))
}

/// The first cluster the entry at `at` names, on a FAT16 volume.
fn first_cluster_at(image: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([image[at + 26], image[at + 27]])
}

/// A rename that crosses directories moves the name and follows it with `..`.
#[test]
fn a_name_moves_between_directories_and_a_directorys_dotdot_follows() {
    let disk = Disk::new(format());
    let data = pattern(11, 1500);
    with_volume(&disk, 16, |fat| {
        let mut ns = Vfs::<1, 4>::new();
        ns.mount("/", fat).unwrap();
        ns.mkdir("/A").unwrap();
        ns.mkdir("/B").unwrap();
        write_file(&mut ns, "/A/F.BIN", &data);
        ns.rename("/A/F.BIN", "/B/G.BIN").unwrap();
        assert_eq!(ns.stat("/A/F.BIN"), Err(Error::NotFound), "gone from where it was");
        assert_eq!(read_file(&mut ns, "/B/G.BIN"), data, "and holds what it held");

        ns.mkdir("/A/SUB").unwrap();
        ns.rename("/A/SUB", "/B/SUB").unwrap();
        assert_eq!(ns.stat("/B/SUB").unwrap().kind, Kind::Dir);
        assert_eq!(ns.stat("/A/SUB"), Err(Error::NotFound));
        // A directory moved into itself, or below itself, is a loop.
        assert_eq!(ns.rename("/B", "/B/SUB/B"), Err(Error::BadPath));
        ns.sync().unwrap();
        ns.unmount("/").unwrap();
    });

    // `..` in the moved directory names its new parent, not the one it came from.
    let image = disk.image();
    let b = first_cluster_at(&image, entry_at(&image, b"B          "));
    let sub = first_cluster_at(&image, entry_at(&image, b"SUB        "));
    // The data region starts after the reserved sector, both tables and the root's own
    // region, which a FAT16 volume has and which this forgot at first.
    let data_start = RESERVED + FATS * fat_sectors() + ROOT_ENTRIES * 32 / SECTOR;
    let sub_at = (data_start + (sub as usize - 2)) * SECTOR;
    assert_eq!(&image[sub_at + 32..sub_at + 34], b"..", "the second entry is `..`");
    assert_eq!(
        first_cluster_at(&image, sub_at + 32),
        b,
        "`..` names the directory it was moved into"
    );

    with_volume(&disk, 8, |fat| {
        let c = assert_clean(fat);
        assert_eq!((c.files, c.dirs), (1, 3), "one file, /A, /B and /B/SUB: {c:?}");
    });
}

/// Growing a file past a cluster boundary reads as zeros, whatever it held before.
#[test]
fn a_file_grown_past_a_cluster_boundary_reads_zeros() {
    let disk = Disk::new(format());
    with_volume(&disk, 16, |fat| {
        let root = fat.root();
        let node = fat.create(root, b"G.BIN", Kind::File).unwrap();
        fat.write_at(node, 0, b"head").unwrap();
        // Four sectors past the end: the file had one cluster and needs five.
        fat.truncate(node, 5 * SECTOR as u64).unwrap();
        assert_eq!(fat.stat(node).unwrap().len, 5 * SECTOR as u64);
        let mut buf = vec![0xAAu8; 5 * SECTOR];
        assert_eq!(fat.read_at(node, 0, &mut buf).unwrap(), 5 * SECTOR);
        assert_eq!(&buf[..4], b"head");
        assert!(buf[4..].iter().all(|&b| b == 0), "every grown byte reads as zero");
        fat.sync().unwrap();
        let c = assert_clean(fat);
        assert_eq!(c.claimed, 5, "five clusters hold it: {c:?}");
    });
}

/// What the volume is, and what is left of it.
#[test]
fn statfs_counts_the_volumes_clusters_and_what_is_free() {
    let disk = Disk::new(format());
    with_volume(&disk, 16, |fat| {
        assert_eq!(fat.format(), crate::Format::Fat16);
        let clusters = fat.clusters();
        let free_before = fat.free_count();
        assert_eq!(free_before, clusters, "nothing is on an empty volume");
        let s = FileSystem::statfs(fat).unwrap();
        assert_eq!(s.block_size, SECTOR as u64, "a cluster is the unit it allocates in");
        assert_eq!((s.blocks, s.free), (u64::from(clusters), u64::from(free_before)));

        let root = fat.root();
        let node = fat.create(root, b"S.BIN", Kind::File).unwrap();
        fat.write_at(node, 0, &pattern(4, 3 * SECTOR)).unwrap();
        fat.sync().unwrap();
        assert_eq!(fat.clusters(), clusters);
        assert_eq!(fat.free_count(), free_before - 3, "three clusters hold the file");
        assert_eq!(consistency(fat).unwrap().free, fat.free_count(), "the walk agrees");

        fat.unlink(root, b"S.BIN").unwrap();
        fat.sync().unwrap();
        assert_eq!(fat.free_count(), free_before, "and they come back");
    });
}

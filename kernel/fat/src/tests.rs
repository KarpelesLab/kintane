//! The reader against volumes the tests build byte by byte.
//!
//! The builder below is written from the FAT specification's field offsets rather than
//! from the reader's constants, and it is the second writer of this format in the tree —
//! kbuild's is the first. A volume it produces is what the reader must understand; a
//! volume it deliberately damages is what the reader must refuse.
//!
//! What these tests cannot show is that the reader agrees with *kbuild's* writer. That is
//! the boot check's job, against the disk kbuild actually writes.

use std::cell::{Cell, RefCell};

use bcache::Storage;
use block::{BlockDevice, Error as BlockError, Geometry};
use vfs::{Error, FileSystem, Kind, Vfs};

use crate::Fat16;

const SECTOR: usize = 512;
/// One sector per cluster, which is what makes a 4 000-cluster volume small enough for a
/// test to hold in memory and still be FAT16 by the specification's cluster count.
const SPC: usize = 1;
const RESERVED: usize = 1;
const FATS: usize = 1;
const ROOT_ENTRIES: usize = 64;
const TOTAL: usize = 4200;
const ENTRY: usize = 32;
const END: u16 = 0xFFFF;

struct Layout {
    fat_sectors: usize,
    data_start: usize,
    clusters: usize,
}

fn layout() -> Layout {
    let root_sectors = ROOT_ENTRIES * ENTRY / SECTOR;
    let mut fat_sectors = 1;
    loop {
        let data_start = RESERVED + FATS * fat_sectors + root_sectors;
        let clusters = (TOTAL - data_start) / SPC;
        if fat_sectors * SECTOR / 2 >= clusters + 2 {
            return Layout {
                fat_sectors,
                data_start,
                clusters,
            };
        }
        fat_sectors += 1;
    }
}

/// An 8.3 name as the eleven bytes an entry stores.
fn short_name(name: &str) -> [u8; 11] {
    // `.` and `..` are the two names whose dots are not a separator. Splitting them as a
    // base and an extension gives an entry with no name at all, which is what a volume
    // written by a tool that forgot this looks like.
    if name == "." || name == ".." {
        let mut out = [b' '; 11];
        out[..name.len()].copy_from_slice(name.as_bytes());
        return out;
    }
    let (base, ext) = name.split_once('.').unwrap_or((name, ""));
    let mut out = [b' '; 11];
    out[..base.len()].copy_from_slice(base.to_ascii_uppercase().as_bytes());
    out[8..8 + ext.len()].copy_from_slice(ext.to_ascii_uppercase().as_bytes());
    out
}

fn entry(name: [u8; 11], attr: u8, cluster: u16, size: u32) -> [u8; ENTRY] {
    let mut e = [0u8; ENTRY];
    e[..11].copy_from_slice(&name);
    e[11] = attr;
    e[26..28].copy_from_slice(&cluster.to_le_bytes());
    e[28..32].copy_from_slice(&size.to_le_bytes());
    e
}

/// A volume under construction.
struct Builder {
    bytes: Vec<u8>,
    fat: Vec<u16>,
    next: u16,
    layout: Layout,
}

impl Builder {
    fn new() -> Builder {
        let layout = layout();
        Builder {
            bytes: vec![0u8; TOTAL * SECTOR],
            fat: vec![0u16; layout.clusters + 2],
            next: 2,
            layout,
        }
    }

    fn chain(&mut self, bytes: usize) -> u16 {
        let n = bytes.div_ceil(SPC * SECTOR);
        if n == 0 {
            return 0;
        }
        let first = self.next;
        for i in 0..n - 1 {
            self.fat[first as usize + i] = first + i as u16 + 1;
        }
        self.fat[first as usize + n - 1] = END;
        self.next += n as u16;
        first
    }

    fn cluster_off(&self, cluster: u16) -> usize {
        (self.layout.data_start + (cluster as usize - 2) * SPC) * SECTOR
    }

    fn put(&mut self, first: u16, data: &[u8]) {
        let at = self.cluster_off(first);
        self.bytes[at..at + data.len()].copy_from_slice(data);
    }

    fn root_off(&self) -> usize {
        (RESERVED + FATS * self.layout.fat_sectors) * SECTOR
    }

    /// Boot sector and table, once everything is placed.
    fn finish(mut self) -> Vec<u8> {
        let s = &mut self.bytes[..SECTOR];
        s[0..3].copy_from_slice(&[0xEB, 0x3C, 0x90]);
        s[3..11].copy_from_slice(b"KINTANE ");
        s[11..13].copy_from_slice(&(SECTOR as u16).to_le_bytes());
        s[13] = SPC as u8;
        s[14..16].copy_from_slice(&(RESERVED as u16).to_le_bytes());
        s[16] = FATS as u8;
        s[17..19].copy_from_slice(&(ROOT_ENTRIES as u16).to_le_bytes());
        s[19..21].copy_from_slice(&(TOTAL as u16).to_le_bytes());
        s[21] = 0xF8;
        s[22..24].copy_from_slice(&(self.layout.fat_sectors as u16).to_le_bytes());
        s[54..62].copy_from_slice(b"FAT16   ");
        s[510..512].copy_from_slice(&[0x55, 0xAA]);

        let fat: Vec<u8> = self.fat.iter().flat_map(|c| c.to_le_bytes()).collect();
        let at = RESERVED * SECTOR;
        self.bytes[at..at + fat.len()].copy_from_slice(&fat);
        self.bytes
    }
}

/// A volume holding `files`, whose paths are `NAME.EXT` or `DIR/NAME.EXT` with one level
/// of directory.
fn volume(files: &[(&str, &[u8])]) -> Vec<u8> {
    volume_with(files, true)
}

/// A volume as [`volume`] builds it, with or without the volume label a formatter usually,
/// but not always, writes as the root's first entry.
fn volume_with(files: &[(&str, &[u8])], label: bool) -> Vec<u8> {
    let mut b = Builder::new();
    let mut root: Vec<[u8; ENTRY]> = Vec::new();
    if label {
        root.push(entry(short_name("KINTANE"), 0x08, 0, 0));
    }
    let mut dirs: Vec<(&str, Vec<[u8; ENTRY]>)> = Vec::new();

    for (path, data) in files {
        let first = b.chain(data.len());
        if first != 0 {
            b.put(first, data);
        }
        let e = |name: &str| entry(short_name(name), 0x20, first, data.len() as u32);
        match path.split_once('/') {
            None => root.push(e(path)),
            Some((dir, name)) => {
                if let Some(slot) = dirs.iter_mut().find(|(d, _)| *d == dir) {
                    slot.1.push(e(name));
                } else {
                    dirs.push((dir, vec![e(name)]));
                }
            }
        }
    }

    for (name, files) in dirs {
        // `.` and `..` come first, as they do on a real volume.
        let cluster = b.chain((files.len() + 2) * ENTRY);
        let mut entries = vec![
            entry(short_name("."), 0x10, cluster, 0),
            entry(short_name(".."), 0x10, 0, 0),
        ];
        entries.extend(files);
        let bytes: Vec<u8> = entries.iter().flatten().copied().collect();
        b.put(cluster, &bytes);
        root.push(entry(short_name(name), 0x10, cluster, 0));
    }

    let at = b.root_off();
    for (i, e) in root.iter().enumerate() {
        b.bytes[at + i * ENTRY..at + (i + 1) * ENTRY].copy_from_slice(e);
    }
    b.finish()
}

/// A device holding a volume, with room before it so the tests read one that does not
/// start at block zero — which is where it lives on the real disk.
struct MockDisk {
    data: RefCell<Vec<u8>>,
    reads: Cell<u64>,
}

/// The block the volume starts at.
const START: u64 = 64;

impl MockDisk {
    fn with(volume: &[u8]) -> MockDisk {
        let mut data = vec![0xCDu8; START as usize * SECTOR];
        data.extend_from_slice(volume);
        MockDisk {
            data: RefCell::new(data),
            reads: Cell::new(0),
        }
    }

    /// A device holding all but the last `missing` sectors of `volume`: a truncated
    /// image, whose boot sector is intact and describes more than is there.
    fn truncated(volume: &[u8], missing: usize) -> MockDisk {
        let mut data = vec![0xCDu8; START as usize * SECTOR];
        data.extend_from_slice(&volume[..volume.len() - missing * SECTOR]);
        MockDisk {
            data: RefCell::new(data),
            reads: Cell::new(0),
        }
    }

    /// Damage one byte of the volume, for the tests that refuse a corrupt one.
    fn poke(&self, offset: usize, byte: u8) {
        self.data.borrow_mut()[START as usize * SECTOR + offset] = byte;
    }

    /// Rewrite a table entry, for the tests that break a chain.
    fn set_fat(&self, cluster: usize, value: u16) {
        let at = START as usize * SECTOR + RESERVED * SECTOR + cluster * 2;
        self.data.borrow_mut()[at..at + 2].copy_from_slice(&value.to_le_bytes());
    }
}

impl BlockDevice for MockDisk {
    fn geometry(&self) -> Geometry {
        Geometry::new(SECTOR, (self.data.borrow().len() / SECTOR) as u64).unwrap()
    }

    fn max_transfer_blocks(&self) -> u64 {
        8
    }

    fn read_blocks(&self, lba: u64, into: &mut [u8]) -> Result<(), BlockError> {
        self.geometry().range(lba, into.len())?;
        self.reads.set(self.reads.get() + 1);
        let at = lba as usize * SECTOR;
        into.copy_from_slice(&self.data.borrow()[at..at + into.len()]);
        Ok(())
    }

    fn write_blocks(&self, lba: u64, from: &[u8]) -> Result<(), BlockError> {
        self.geometry().range(lba, from.len())?;
        let at = lba as usize * SECTOR;
        self.data.borrow_mut()[at..at + from.len()].copy_from_slice(from);
        Ok(())
    }

    fn flush(&self) -> Result<(), BlockError> {
        Ok(())
    }
}

/// A file long enough to need several clusters, whose every byte says where it belongs.
fn big(len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u32).wrapping_mul(2_654_435_761).to_le_bytes()[1])
        .collect()
}

macro_rules! mounted {
    ($disk:ident, $fat:ident, $volume:expr) => {
        let $disk = MockDisk::with(&$volume);
        let mut storage = Storage::<8, SECTOR>::new();
        let mut $fat = Fat16::mount(&$disk, storage.cache().unwrap(), START).unwrap();
    };
}

#[test]
fn a_file_in_the_root_reads_back() {
    let v = volume(&[("hello.txt", b"hello")]);
    mounted!(disk, fat, v);

    let root = fat.root();
    let node = fat.lookup(root, b"HELLO.TXT").unwrap();
    assert_eq!(fat.stat(node).unwrap().len, 5);
    let mut buf = [0u8; 8];
    assert_eq!(fat.read_at(node, 0, &mut buf).unwrap(), 5);
    assert_eq!(&buf[..5], b"hello");
    assert_eq!(fat.read_at(node, 5, &mut buf).unwrap(), 0, "at the end, nothing");
    assert_eq!(fat.read_at(node, 2, &mut buf).unwrap(), 3);
    assert_eq!(&buf[..3], b"llo");
}

#[test]
fn a_name_is_matched_whatever_case_it_is_asked_for() {
    let v = volume(&[("hello.txt", b"hello")]);
    mounted!(disk, fat, v);
    let root = fat.root();
    for want in [&b"hello.txt"[..], b"HELLO.TXT", b"Hello.Txt"] {
        assert!(fat.lookup(root, want).is_ok(), "{:?}", core::str::from_utf8(want));
    }
    assert_eq!(fat.lookup(root, b"hello").unwrap_err(), Error::NotFound, "no extension");
    assert_eq!(fat.lookup(root, b"hello.tx").unwrap_err(), Error::NotFound);
}

#[test]
fn a_file_of_many_clusters_reads_back_at_every_offset() {
    let data = big(5000);
    let v = volume(&[("big.bin", &data)]);
    mounted!(disk, fat, v);
    let root = fat.root();
    let node = fat.lookup(root, b"BIG.BIN").unwrap();
    assert_eq!(fat.stat(node).unwrap().len, 5000);

    // The whole file, in one call and in pieces, and a read that starts inside the third
    // cluster and ends inside the fourth: the chain walk is what each of these exercises.
    let mut whole = vec![0u8; 5000];
    let mut done = 0;
    while done < 5000 {
        let n = fat.read_at(node, done as u64, &mut whole[done..]).unwrap();
        assert_ne!(n, 0);
        done += n;
    }
    assert_eq!(whole, data);

    let mut piece = [0u8; 700];
    fat.read_at(node, 1200, &mut piece).unwrap();
    assert_eq!(&piece[..], &data[1200..1900]);
    let mut tail = [0u8; 64];
    assert_eq!(fat.read_at(node, 4980, &mut tail).unwrap(), 20, "short at the end");
    assert_eq!(&tail[..20], &data[4980..]);
}

#[test]
fn a_directory_lists_what_is_in_it_and_not_dot_or_the_label() {
    let v = volume(&[
        ("hello.txt", b"hello"),
        ("sub/nested.txt", b"nested"),
        ("sub/other.bin", b"other"),
    ]);
    mounted!(disk, fat, v);
    let root = fat.root();

    let mut names = Vec::new();
    let mut i = 0;
    while let Some(e) = fat.readdir(root, i).unwrap() {
        names.push(String::from_utf8(e.name().to_vec()).unwrap());
        i += 1;
    }
    names.sort();
    assert_eq!(names, vec!["HELLO.TXT", "SUB"], "the volume label is not an entry");

    let sub = fat.lookup(root, b"sub").unwrap();
    assert_eq!(fat.stat(sub).unwrap().kind, Kind::Dir);
    let mut names = Vec::new();
    let mut i = 0;
    while let Some(e) = fat.readdir(sub, i).unwrap() {
        names.push(String::from_utf8(e.name().to_vec()).unwrap());
        i += 1;
    }
    names.sort();
    assert_eq!(names, vec!["NESTED.TXT", "OTHER.BIN"], "`.` and `..` are not reported");
}

#[test]
fn a_directory_is_not_a_file_and_a_file_is_not_a_directory() {
    let v = volume(&[("hello.txt", b"hello"), ("sub/nested.txt", b"nested")]);
    mounted!(disk, fat, v);
    let root = fat.root();
    let sub = fat.lookup(root, b"sub").unwrap();
    let hello = fat.lookup(root, b"hello.txt").unwrap();

    let mut buf = [0u8; 4];
    assert_eq!(fat.read_at(sub, 0, &mut buf).unwrap_err(), Error::IsADirectory);
    assert_eq!(fat.read_at(root, 0, &mut buf).unwrap_err(), Error::IsADirectory);
    assert_eq!(fat.readdir(hello, 0).map(|_| ()).unwrap_err(), Error::NotADirectory);
    assert_eq!(fat.lookup(hello, b"x").unwrap_err(), Error::NotADirectory);
}

#[test]
fn a_volume_another_writer_built_is_written_in_place() {
    // One table copy, as this builder writes: the driver keeps every copy there is.
    let v = volume(&[("hello.txt", b"hello"), ("sub/nested.txt", b"nested")]);
    mounted!(disk, fat, v);
    let root = fat.root();
    let node = fat.lookup(root, b"hello.txt").unwrap();
    assert_eq!(fat.write_at(node, 5, b", world").unwrap(), 7);
    let sub = fat.lookup(root, b"sub").unwrap();
    let made = fat.create(sub, b"made.txt", Kind::File).unwrap();
    fat.write_at(made, 0, b"made here").unwrap();
    fat.sync().unwrap();
    let mut buf = [0u8; 16];
    assert_eq!(fat.read_at(node, 0, &mut buf).unwrap(), 12);
    assert_eq!(&buf[..12], b"hello, world");
    assert_eq!(fat.read_at(made, 0, &mut buf).unwrap(), 9);
    let mut seen = vec![0u8; 1024];
    let c = fat.check_consistency(&mut seen).unwrap();
    assert_eq!((c.files, c.dirs, c.lost, c.fats_differ), (3, 1, 0, 0));
}

#[test]
fn the_namespace_walks_a_path_on_a_real_volume() {
    let data = big(3000);
    let v = volume(&[("hello.txt", b"hello"), ("sub/nested.txt", &data)]);
    mounted!(disk, fat, v);
    let mut vfs = Vfs::<2, 4>::new();
    vfs.mount("/disk", &mut fat).unwrap();

    assert_eq!(vfs.stat("/disk/hello.txt").unwrap().len, 5);
    let mut buf = vec![0u8; 3000];
    assert_eq!(vfs.read_all("/disk/sub/nested.txt", &mut buf).unwrap(), 3000);
    assert_eq!(buf, data);
    assert_eq!(vfs.open("/disk/sub/missing").unwrap_err(), Error::NotFound);
    assert_eq!(vfs.open_count(), 0);
}

#[test]
fn reads_go_through_the_cache() {
    let data = big(3000);
    let v = volume(&[("big.bin", &data)]);
    mounted!(disk, fat, v);
    let root = fat.root();
    let node = fat.lookup(root, b"BIG.BIN").unwrap();

    let before = disk.reads.get();
    let mut buf = [0u8; 16];
    fat.read_at(node, 0, &mut buf).unwrap();
    fat.read_at(node, 16, &mut buf).unwrap();
    fat.read_at(node, 32, &mut buf).unwrap();
    assert_eq!(disk.reads.get(), before + 1, "one sector, read once");
    let stats = fat.cache_stats();
    assert!(stats.hits >= 2, "{stats:?}");
    fat.check_cache().unwrap();

    fat.invalidate_cache();
    fat.read_at(node, 0, &mut buf).unwrap();
    assert!(disk.reads.get() > before + 1, "after invalidating, the device again");
}

#[test]
fn a_volume_that_is_not_fat16_is_refused_by_name() {
    let v = volume(&[("hello.txt", b"hello")]);

    let cases: [(usize, u8, &str); 5] = [
        (510, 0x00, "no boot-sector signature"),
        (13, 0, "sectors per cluster"),
        (16, 0, "file allocation table count"),
        (17, 0, "root directory entries"),
        (22, 0, "sectors per file allocation table"),
    ];
    for (offset, byte, want) in cases {
        let disk = MockDisk::with(&v);
        disk.poke(offset, byte);
        let mut storage = Storage::<4, SECTOR>::new();
        let err = Fat16::mount(&disk, storage.cache().unwrap(), START)
            .map(|_| ())
            .unwrap_err();
        assert_eq!(err, Error::Corrupt(want), "poking {offset}");
    }

    // A cluster count below FAT16's range is FAT12, whatever the boot sector says it is.
    let disk = MockDisk::with(&v);
    disk.poke(13, 64); // 64 sectors per cluster leaves ~65 clusters
    let mut storage = Storage::<4, SECTOR>::new();
    let err = Fat16::mount(&disk, storage.cache().unwrap(), START)
        .map(|_| ())
        .unwrap_err();
    assert_eq!(err, Error::Corrupt("not FAT16: the cluster count is another type's"));
}

#[test]
fn a_volume_that_runs_past_the_device_is_refused() {
    let v = volume(&[("hello.txt", b"hello")]);
    // The volume says it has TOTAL sectors; the device stops eight short of that.
    let disk = MockDisk::truncated(&v, 8);
    let mut storage = Storage::<4, SECTOR>::new();
    let err = Fat16::mount(&disk, storage.cache().unwrap(), START)
        .map(|_| ())
        .unwrap_err();
    assert_eq!(err, Error::Corrupt("a volume that runs past the end of the device"));
}

#[test]
fn a_chain_that_loops_is_refused_rather_than_walked_for_ever() {
    let data = big(5000);
    let v = volume(&[("big.bin", &data)]);
    let disk = MockDisk::with(&v);
    // The file's first cluster is 2; point its third at its second.
    disk.set_fat(4, 3);
    let mut storage = Storage::<8, SECTOR>::new();
    let mut fat = Fat16::mount(&disk, storage.cache().unwrap(), START).unwrap();
    let root = fat.root();
    let node = fat.lookup(root, b"BIG.BIN").unwrap();

    // Reading the tail walks the loop. The walk takes one step per cluster of the offset
    // asked for, so it ends: that this test returns at all is the property under test.
    // What it lands on is a cluster the loop passes through rather than the file's ninth,
    // so the bytes must not be the ones at that offset — a reader that returned them
    // would mean the chain had been ignored rather than walked.
    let mut buf = [0u8; 64];
    match fat.read_at(node, 4900, &mut buf) {
        Ok(n) => assert_ne!(
            &buf[..n],
            &data[4900..4900 + n],
            "a looping chain must not somehow yield the file's own bytes"
        ),
        Err(e) => assert!(matches!(e, Error::Corrupt(_)), "{e:?}"),
    }
}

#[test]
fn a_chain_entry_outside_the_volume_is_refused() {
    let data = big(3000);
    let v = volume(&[("big.bin", &data)]);
    let disk = MockDisk::with(&v);
    disk.set_fat(2, 60000); // past the last cluster of this volume
    let mut storage = Storage::<8, SECTOR>::new();
    let mut fat = Fat16::mount(&disk, storage.cache().unwrap(), START).unwrap();
    let root = fat.root();
    let node = fat.lookup(root, b"BIG.BIN").unwrap();
    let mut buf = [0u8; 16];
    assert_eq!(
        fat.read_at(node, 600, &mut buf).unwrap_err(),
        Error::Corrupt("a chain entry outside the volume")
    );
}

#[test]
fn a_file_whose_chain_ends_early_is_corrupt_not_short() {
    let data = big(3000);
    let v = volume(&[("big.bin", &data)]);
    let disk = MockDisk::with(&v);
    // End the chain after its first cluster, leaving the size claiming six.
    disk.set_fat(2, 0xFFFF);
    let mut storage = Storage::<8, SECTOR>::new();
    let mut fat = Fat16::mount(&disk, storage.cache().unwrap(), START).unwrap();
    let root = fat.root();
    let node = fat.lookup(root, b"BIG.BIN").unwrap();
    let mut buf = [0u8; 16];
    assert_eq!(
        fat.read_at(node, 1000, &mut buf).unwrap_err(),
        Error::Corrupt("a chain shorter than the file it holds")
    );
}

#[test]
fn a_deleted_entry_is_skipped_and_a_never_used_one_ends_the_directory() {
    let v = volume(&[("a.txt", b"a"), ("b.txt", b"b"), ("c.txt", b"c")]);
    let disk = MockDisk::with(&v);
    // Delete `B.TXT`: entry 0 is the volume label, so it is entry 2.
    let root_at = (RESERVED + FATS * layout().fat_sectors) * SECTOR;
    disk.poke(root_at + 2 * ENTRY, 0xE5);
    let mut storage = Storage::<8, SECTOR>::new();
    let mut fat = Fat16::mount(&disk, storage.cache().unwrap(), START).unwrap();
    let root = fat.root();

    let mut names = Vec::new();
    let mut i = 0;
    while let Some(e) = fat.readdir(root, i).unwrap() {
        names.push(String::from_utf8(e.name().to_vec()).unwrap());
        i += 1;
    }
    assert_eq!(names, vec!["A.TXT", "C.TXT"], "the deleted entry is gone, the rest remain");
    assert_eq!(fat.lookup(root, b"b.txt").unwrap_err(), Error::NotFound);
}

#[test]
fn a_long_name_entry_is_skipped_and_its_short_name_still_works() {
    let v = volume(&[("a.txt", b"a"), ("b.txt", b"b")]);
    let disk = MockDisk::with(&v);
    // Make `A.TXT`'s entry a long-name one: it must vanish from the listing, and the
    // reader must carry on to the entries after it rather than stopping.
    let root_at = (RESERVED + FATS * layout().fat_sectors) * SECTOR;
    disk.poke(root_at + ENTRY + 11, 0x0F);
    let mut storage = Storage::<8, SECTOR>::new();
    let mut fat = Fat16::mount(&disk, storage.cache().unwrap(), START).unwrap();
    let root = fat.root();

    let mut names = Vec::new();
    let mut i = 0;
    while let Some(e) = fat.readdir(root, i).unwrap() {
        names.push(String::from_utf8(e.name().to_vec()).unwrap());
        i += 1;
    }
    assert_eq!(names, vec!["B.TXT"]);
}

#[test]
fn an_empty_file_has_no_chain_and_reads_nothing() {
    let v = volume(&[("empty.txt", b"")]);
    mounted!(disk, fat, v);
    let root = fat.root();
    let node = fat.lookup(root, b"EMPTY.TXT").unwrap();
    assert_eq!(fat.stat(node).unwrap().len, 0);
    let mut buf = [0u8; 4];
    assert_eq!(fat.read_at(node, 0, &mut buf).unwrap(), 0);
}

/// A volume whose root starts with a file rather than a label.
///
/// Every other volume here, and the one kbuild writes, has the label in the root's first
/// entry, which a reader skips. So a reader that started one entry late would still list
/// everything on those volumes: it would skip the label by accident instead of on purpose.
/// Found by mutating the reader that way and watching every other check pass. This is the
/// volume on which starting late loses a file.
#[test]
fn the_first_root_entry_is_read_when_there_is_no_label() {
    let v = volume_with(&[("a.txt", b"a"), ("b.txt", b"b")], false);
    mounted!(disk, fat, v);
    let root = fat.root();

    let mut names = Vec::new();
    let mut i = 0;
    while let Some(e) = fat.readdir(root, i).unwrap() {
        names.push(String::from_utf8(e.name().to_vec()).unwrap());
        i += 1;
    }
    assert_eq!(names, vec!["A.TXT", "B.TXT"], "the first entry is a file, and it is listed");
    let a = fat.lookup(root, b"a.txt").unwrap();
    let mut buf = [0u8; 4];
    assert_eq!(fat.read_at(a, 0, &mut buf).unwrap(), 1);
    assert_eq!(buf[0], b'a');
}

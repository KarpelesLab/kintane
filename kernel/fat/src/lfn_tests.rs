//! Long names: the pieces on their own, and names written and read back through the driver.
//!
//! The pure functions are checked against the format's own arithmetic — the checksum, the
//! ordinals, the case bits — and the driver against what a caller sees: a name goes in and
//! comes back, its alias is a name of its own, and removing it leaves the directory with no
//! trace of either.

use std::cell::RefCell;

use block::{BlockDevice, Error as BlockError, Geometry};
use vfs::{Error, Kind, OpenFlags, Vfs};

use crate::{Consistency, Fat, lfn};

const SECTOR: usize = 512;
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

/// An empty FAT16 volume, as `write_tests` formats one.
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

struct Disk(RefCell<Vec<u8>>);

impl BlockDevice for Disk {
    fn geometry(&self) -> Geometry {
        Geometry::new(SECTOR, (self.0.borrow().len() / SECTOR) as u64).unwrap()
    }

    fn max_transfer_blocks(&self) -> u64 {
        16
    }

    fn read_blocks(&self, lba: u64, into: &mut [u8]) -> Result<(), BlockError> {
        self.geometry().range(lba, into.len())?;
        let at = lba as usize * SECTOR;
        into.copy_from_slice(&self.0.borrow()[at..at + into.len()]);
        Ok(())
    }

    fn write_blocks(&self, lba: u64, from: &[u8]) -> Result<(), BlockError> {
        self.geometry().range(lba, from.len())?;
        let at = lba as usize * SECTOR;
        self.0.borrow_mut()[at..at + from.len()].copy_from_slice(from);
        Ok(())
    }

    fn flush(&self) -> Result<(), BlockError> {
        Ok(())
    }
}

fn with_volume<R>(disk: &Disk, f: impl FnOnce(&mut Fat<'_, '_>) -> R) -> R {
    let mut slots = vec![bcache::Slot::EMPTY; 16];
    let mut data = vec![0u8; 16 * SECTOR];
    let cache = bcache::Cache::new(&mut slots, &mut data, SECTOR).unwrap();
    let mut fat = Fat::mount(disk, cache, 0).unwrap();
    f(&mut fat)
}

fn consistency(fat: &mut Fat<'_, '_>) -> Result<Consistency, Error> {
    let mut seen = vec![0u8; (fat.clusters() as usize + 2).div_ceil(8)];
    fat.check_consistency(&mut seen)
}

/// Every name the root lists.
fn listing(ns: &mut Vfs<'_, 1, 4>) -> Vec<String> {
    let mut names = Vec::new();
    let mut index = 0;
    while let Some(entry) = ns.readdir("/", index).unwrap() {
        names.push(String::from_utf8(entry.name().to_vec()).unwrap());
        index += 1;
    }
    names
}

fn create(ns: &mut Vfs<'_, 1, 4>, path: &str, bytes: &[u8]) {
    let flags = OpenFlags {
        write: true,
        create: true,
        truncate: true,
        ..OpenFlags::READ
    };
    let fd = ns.open_with(path, flags).unwrap();
    if !bytes.is_empty() {
        assert_eq!(ns.write(fd, bytes).unwrap(), bytes.len());
    }
    ns.close(fd).unwrap();
}

// ---- the pieces ---------------------------------------------------------------------------

#[test]
fn the_checksum_is_the_one_the_format_defines() {
    // Worked by hand from the specification's rotate-and-add over the eleven bytes.
    assert_eq!(lfn::checksum(b"HELLO   TXT"), {
        let mut sum = 0u8;
        for &c in b"HELLO   TXT" {
            sum = sum.rotate_right(1).wrapping_add(c);
        }
        sum
    });
    // It depends on every byte: a name differing anywhere gives a different sum, which is
    // what makes it worth checking a set against its short entry.
    assert_ne!(lfn::checksum(b"HELLO   TXT"), lfn::checksum(b"HELLO   TXU"));
    assert_ne!(lfn::checksum(b"HELLO   TXT"), lfn::checksum(b"HELLP   TXT"));
}

#[test]
fn a_short_name_needs_no_long_entries_and_records_its_case() {
    let (short, flags) = lfn::short_of(b"README.TXT").unwrap();
    assert_eq!(&short, b"README  TXT");
    assert_eq!(flags, 0, "an upper-case name records nothing");

    let (short, flags) = lfn::short_of(b"readme.txt").unwrap();
    assert_eq!(&short, b"README  TXT", "stored upper-case whatever the case asked for");
    assert_eq!(flags, lfn::BASE_LOWER | lfn::EXT_LOWER);

    let (short, flags) = lfn::short_of(b"readme.TXT").unwrap();
    assert_eq!(flags, lfn::BASE_LOWER, "each half is recorded on its own");
    let mut out = [0u8; 12];
    let len = lfn::rendered(&short, flags, &mut out);
    assert_eq!(&out[..len], b"readme.TXT", "and comes back as it went in");

    // Mixed case within one half has no bit to record it, so it needs a long name.
    assert!(lfn::short_of(b"ReadMe.txt").is_none());
    // And so does anything too long, or with more than one dot.
    assert!(lfn::short_of(b"averylongname.txt").is_none());
    assert!(lfn::short_of(b"name.tar.gz").is_none());
    assert!(lfn::short_of(b"name.text").is_none());
}

#[test]
fn a_name_this_driver_will_not_write_is_refused() {
    assert!(lfn::writable_name(b"a long name.txt").is_ok());
    for bad in [
        &b""[..],
        b".",
        b"..",
        b"ends with a dot.",
        b"ends with a space ",
        b"a:colon",
        b"a*star",
        b"a?question",
        b"a\\backslash",
        b"a\"quote",
        b"a|pipe",
        b"a<less",
        b"a>greater",
        &[0x01][..],
        &[0x80][..],
    ] {
        assert_eq!(
            lfn::writable_name(bad),
            Err(Error::BadPath),
            "{:?} is not a name this writes",
            std::str::from_utf8(bad)
        );
    }
    // Longer than the namespace's own limit.
    let too_long = vec![b'a'; vfs::MAX_NAME + 1];
    assert_eq!(lfn::writable_name(&too_long), Err(Error::BadPath));
    assert!(lfn::writable_name(&vec![b'a'; vfs::MAX_NAME]).is_ok());
}

#[test]
fn a_long_name_round_trips_through_its_entries() {
    for name in [
        &b"a"[..],
        b"twelve chars",
        b"thirteen char",
        b"fourteen chars",
        b"a name of twenty-six chars",
        b"a considerably longer name than that one.txt",
    ] {
        let total = lfn::entries_for(name);
        assert!(total >= 1 && total <= lfn::MAX_ENTRIES);
        let sum = lfn::checksum(b"ALIAS~1    ");
        let mut joined = [0u8; vfs::MAX_NAME];
        let mut len = 0;
        // On disk the set runs backwards, so a reader meets the last entry first.
        for index in (0..total).rev() {
            let e = lfn::entry(name, index, sum);
            assert_eq!(e[11], lfn::ATTR_LONG_NAME);
            assert_eq!(e[13], sum, "every entry carries the short name's checksum");
            assert_eq!(e[0] & !lfn::LAST, index as u8 + 1, "ordinals are one-based");
            assert_eq!(
                e[0] & lfn::LAST != 0,
                index + 1 == total,
                "only the entry holding the end of the name is marked last"
            );
            let at = index * lfn::CHARS;
            let end = lfn::chars_of(&e, &mut joined, at).unwrap();
            if index + 1 == total {
                len = end;
            }
        }
        assert_eq!(&joined[..len], name, "the name joins back together");
    }
}

#[test]
fn an_alias_is_a_short_name_with_a_tail() {
    let a = lfn::alias(b"a long name.txt", 1);
    assert_eq!(&a, b"ALONGN~1TXT");
    // The number grows into the base, which shortens to make room.
    assert_eq!(&lfn::alias(b"a long name.txt", 42), b"ALONG~42TXT");
    assert_eq!(&lfn::alias(b"a long name.txt", 123_456), b"A~123456TXT");
    // Characters an alias may not hold become `_`, and spaces and dots are dropped.
    assert_eq!(&lfn::alias(b"we+i rd.n me", 1), b"WE_IRD~1N_M");
    // The extension is what follows the last dot.
    assert_eq!(&lfn::alias(b"archive.tar.gz", 1), b"ARCHIV~1GZ ");
    // A name with no dot gets no extension.
    assert_eq!(&lfn::alias(b"no extension here", 1), b"NOEXTE~1   ");
}

// ---- through the driver -------------------------------------------------------------------

#[test]
fn a_long_name_is_written_and_read_back() {
    let disk = Disk(RefCell::new(format()));
    with_volume(&disk, |fat| {
        let mut ns = Vfs::<1, 4>::new();
        ns.mount("/", fat).unwrap();
        create(&mut ns, "/a long name.txt", b"contents");
        create(&mut ns, "/readme.txt", b"lower");
        create(&mut ns, "/SHORT.TXT", b"upper");

        let names = listing(&mut ns);
        assert!(names.contains(&"a long name.txt".to_string()), "{names:?}");
        assert!(names.contains(&"readme.txt".to_string()), "lower case kept: {names:?}");
        assert!(names.contains(&"SHORT.TXT".to_string()), "{names:?}");

        // Found again by the name it was created with, and by the alias the set carries.
        let mut buf = [0u8; 16];
        let n = ns.read_all("/a long name.txt", &mut buf).unwrap();
        assert_eq!(&buf[..n], b"contents");
        let n = ns.read_all("/ALONGN~1.TXT", &mut buf).unwrap();
        assert_eq!(&buf[..n], b"contents", "the alias names the same file");
        // And case-insensitively, as FAT matches.
        let n = ns.read_all("/A LONG NAME.TXT", &mut buf).unwrap();
        assert_eq!(&buf[..n], b"contents");
        ns.sync().unwrap();
        ns.unmount("/").unwrap();
    });
    // From what reached the device, with a cold cache.
    with_volume(&disk, |fat| {
        let mut ns = Vfs::<1, 4>::new();
        ns.mount("/", fat).unwrap();
        let names = listing(&mut ns);
        assert!(names.contains(&"a long name.txt".to_string()), "{names:?}");
        ns.unmount("/").unwrap();
        let c = consistency(fat).unwrap();
        assert_eq!(c.lost, 0, "{c:?}");
        assert_eq!(c.fats_differ, 0, "{c:?}");
    });
}

#[test]
fn an_alias_never_takes_a_name_something_else_answers_to() {
    let disk = Disk(RefCell::new(format()));
    with_volume(&disk, |fat| {
        let mut ns = Vfs::<1, 4>::new();
        ns.mount("/", fat).unwrap();
        // The short name the first long name would alias to, taken first.
        create(&mut ns, "/ALONGN~1.TXT", b"first");
        create(&mut ns, "/a long name.txt", b"second");
        create(&mut ns, "/a long name two.txt", b"third");

        let mut buf = [0u8; 16];
        let n = ns.read_all("/ALONGN~1.TXT", &mut buf).unwrap();
        assert_eq!(&buf[..n], b"first", "the name that was there is untouched");
        let n = ns.read_all("/a long name.txt", &mut buf).unwrap();
        assert_eq!(&buf[..n], b"second");
        let n = ns.read_all("/a long name two.txt", &mut buf).unwrap();
        assert_eq!(&buf[..n], b"third");

        let names = listing(&mut ns);
        assert_eq!(names.len(), 3, "three names, each its own: {names:?}");
        ns.sync().unwrap();
        ns.unmount("/").unwrap();
    });
}

#[test]
fn removing_a_long_name_frees_every_entry_of_its_set() {
    let disk = Disk(RefCell::new(format()));
    with_volume(&disk, |fat| {
        let mut ns = Vfs::<1, 4>::new();
        ns.mount("/", fat).unwrap();
        // Long enough to need three entries of its own.
        let long = "/a name long enough to need three entries.txt";
        create(&mut ns, long, b"x");
        assert_eq!(listing(&mut ns).len(), 1);
        // Its alias names it while it is there.
        assert!(ns.stat("/ANAMEL~1.TXT").is_ok());
        ns.unlink(long).unwrap();
        assert_eq!(listing(&mut ns), Vec::<String>::new(), "nothing is left");
        assert_eq!(ns.stat(long), Err(Error::NotFound));
        // The short entry went with the long ones: neither name finds anything.
        assert_eq!(ns.stat("/ANAMEL~1.TXT"), Err(Error::NotFound));
        // And the next long name takes the alias, which a set still on the disk would hold.
        create(&mut ns, "/a name long enough to need three entries.bin", b"z");
        assert_eq!(listing(&mut ns).len(), 1);
        assert!(ns.stat("/ANAMEL~1.BIN").is_ok(), "the first alias was free again");
        ns.unlink("/a name long enough to need three entries.bin").unwrap();

        // The slots come back: the same name written again fits where the first one was.
        create(&mut ns, long, b"y");
        assert_eq!(listing(&mut ns).len(), 1);
        ns.sync().unwrap();
        ns.unmount("/").unwrap();
        let c = consistency(fat).unwrap();
        assert_eq!(c.lost, 0, "{c:?}");
    });
}

#[test]
fn a_long_name_survives_a_rename_and_a_directory() {
    let disk = Disk(RefCell::new(format()));
    with_volume(&disk, |fat| {
        let mut ns = Vfs::<1, 4>::new();
        ns.mount("/", fat).unwrap();
        ns.mkdir("/a directory with a long name").unwrap();
        create(&mut ns, "/a directory with a long name/inside it.txt", b"deep");

        assert_eq!(
            ns.stat("/a directory with a long name").unwrap().kind,
            Kind::Dir
        );
        let mut buf = [0u8; 16];
        let n = ns
            .read_all("/a directory with a long name/inside it.txt", &mut buf)
            .unwrap();
        assert_eq!(&buf[..n], b"deep");

        // Renamed within the directory, and then out of it.
        ns.rename(
            "/a directory with a long name/inside it.txt",
            "/a directory with a long name/renamed to something longer.txt",
        )
        .unwrap();
        assert_eq!(
            ns.stat("/a directory with a long name/inside it.txt"),
            Err(Error::NotFound)
        );
        ns.rename(
            "/a directory with a long name/renamed to something longer.txt",
            "/moved out.txt",
        )
        .unwrap();
        let n = ns.read_all("/moved out.txt", &mut buf).unwrap();
        assert_eq!(&buf[..n], b"deep");
        assert_eq!(listing(&mut ns).len(), 2, "the directory and the moved file");
        ns.sync().unwrap();
        ns.unmount("/").unwrap();
        let c = consistency(fat).unwrap();
        assert_eq!(c.lost, 0, "{c:?}");
        assert_eq!(c.fats_differ, 0, "{c:?}");
    });
}

#[test]
fn a_name_the_driver_will_not_write_is_refused_rather_than_shortened() {
    let disk = Disk(RefCell::new(format()));
    with_volume(&disk, |fat| {
        let mut ns = Vfs::<1, 4>::new();
        ns.mount("/", fat).unwrap();
        for bad in ["/a:colon.txt", "/a*star.txt", "/ends with a dot."] {
            let flags = OpenFlags {
                write: true,
                create: true,
                ..OpenFlags::READ
            };
            assert_eq!(
                ns.open_with(bad, flags).err(),
                Some(Error::BadPath),
                "{bad} is refused"
            );
        }
        assert_eq!(listing(&mut ns), Vec::<String>::new(), "and nothing was made");
        ns.unmount("/").unwrap();
    });
}

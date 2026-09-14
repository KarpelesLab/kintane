//! The namespace against the in-memory filesystem.
//!
//! Every test here is about the namespace's own rules — path walking, mounts, handles,
//! positions — with the filesystem below it reduced to something a test can hold in its
//! hand. What the on-disk filesystem does with the same trait is that unit's business.

use crate::memfs::MemFs;
use crate::{Error, Fd, FileSystem, Kind, Vfs, Whence};

/// A filesystem with `/hello.txt`, `/sub/`, and `/sub/nested.txt`.
struct Fixture {
    hello: [u8; 32],
    nested: [u8; 16],
}

impl Fixture {
    fn new() -> Fixture {
        let mut hello = [0u8; 32];
        hello[..5].copy_from_slice(b"hello");
        let mut nested = [0u8; 16];
        nested[..6].copy_from_slice(b"nested");
        Fixture { hello, nested }
    }

    fn build<'a>(&'a mut self) -> MemFs<'a, 8> {
        let mut fs = MemFs::<8>::new();
        let root = fs.root();
        fs.create_file(root, b"hello.txt", &mut self.hello, 5)
            .unwrap();
        let sub = fs.create_dir(root, b"sub").unwrap();
        fs.create_file(sub, b"nested.txt", &mut self.nested, 6)
            .unwrap();
        fs
    }
}

fn read_to_end<const M: usize, const O: usize>(vfs: &mut Vfs<'_, M, O>, fd: Fd) -> Vec<u8> {
    let mut out = Vec::new();
    let mut buf = [0u8; 4];
    loop {
        match vfs.read(fd, &mut buf).unwrap() {
            0 => return out,
            n => out.extend_from_slice(&buf[..n]),
        }
    }
}

#[test]
fn a_path_walks_to_the_file_it_names() {
    let mut f = Fixture::new();
    let mut fs = f.build();
    let mut vfs = Vfs::<2, 4>::new();
    vfs.mount("/", &mut fs).unwrap();

    let fd = vfs.open("/hello.txt").unwrap();
    assert_eq!(read_to_end(&mut vfs, fd), b"hello");
    vfs.close(fd).unwrap();

    let fd = vfs.open("/sub/nested.txt").unwrap();
    assert_eq!(read_to_end(&mut vfs, fd), b"nested");
    vfs.close(fd).unwrap();
    assert_eq!(vfs.open_count(), 0, "every handle was given back");
}

#[test]
fn redundant_separators_and_dot_name_the_same_node() {
    let mut f = Fixture::new();
    let mut fs = f.build();
    let mut vfs = Vfs::<2, 4>::new();
    vfs.mount("/", &mut fs).unwrap();

    for path in [
        "/sub/nested.txt",
        "//sub//nested.txt",
        "/./sub/./nested.txt",
    ] {
        let fd = vfs.open(path).unwrap();
        assert_eq!(read_to_end(&mut vfs, fd), b"nested", "{path}");
        vfs.close(fd).unwrap();
    }
    // A trailing slash on a directory is the directory.
    assert_eq!(vfs.stat("/sub/").unwrap().kind, Kind::Dir);
}

#[test]
fn a_path_that_is_not_a_path_is_refused() {
    let mut f = Fixture::new();
    let mut fs = f.build();
    let mut vfs = Vfs::<2, 4>::new();
    vfs.mount("/", &mut fs).unwrap();

    assert_eq!(vfs.open("").unwrap_err(), Error::BadPath, "empty");
    assert_eq!(vfs.open("hello.txt").unwrap_err(), Error::BadPath, "relative");
    assert_eq!(vfs.open("/nope").unwrap_err(), Error::NotFound);
    assert_eq!(
        vfs.open("/hello.txt/inside").unwrap_err(),
        Error::NotADirectory,
        "a file is not a directory"
    );
    let long = format!("/{}", "x".repeat(crate::MAX_NAME + 1));
    assert_eq!(vfs.open(&long).unwrap_err(), Error::BadPath, "component too long");
}

#[test]
fn the_longest_mount_prefix_wins_and_shadows_the_root() {
    let mut f = Fixture::new();
    let mut root_fs = f.build();
    let mut other = [0u8; 8];
    other[..4].copy_from_slice(b"disk");
    let mut disk_fs = MemFs::<4>::new();
    let disk_root = disk_fs.root();
    disk_fs
        .create_file(disk_root, b"hello.txt", &mut other, 4)
        .unwrap();

    let mut vfs = Vfs::<2, 4>::new();
    vfs.mount("/", &mut root_fs).unwrap();
    vfs.mount("/disk", &mut disk_fs).unwrap();

    // `/hello.txt` is the root mount's; `/disk/hello.txt` is the disk's, and the prefix
    // is consumed rather than looked up as a directory.
    let fd = vfs.open("/hello.txt").unwrap();
    assert_eq!(read_to_end(&mut vfs, fd), b"hello");
    vfs.close(fd).unwrap();
    let fd = vfs.open("/disk/hello.txt").unwrap();
    assert_eq!(read_to_end(&mut vfs, fd), b"disk");
    vfs.close(fd).unwrap();
    // A name that merely starts with the prefix is not under it.
    assert_eq!(vfs.open("/diskette").unwrap_err(), Error::NotFound);
}

#[test]
fn a_mount_cannot_be_removed_while_a_file_on_it_is_open() {
    let mut f = Fixture::new();
    let mut fs = f.build();
    let mut vfs = Vfs::<2, 4>::new();
    vfs.mount("/", &mut fs).unwrap();

    let fd = vfs.open("/hello.txt").unwrap();
    assert_eq!(vfs.unmount("/").unwrap_err(), Error::TooManyOpen);
    vfs.close(fd).unwrap();
    vfs.unmount("/").unwrap();
    assert_eq!(vfs.open("/hello.txt").unwrap_err(), Error::NoSuchMount);
}

#[test]
fn a_closed_handle_does_not_name_the_file_that_takes_its_slot() {
    let mut f = Fixture::new();
    let mut fs = f.build();
    let mut vfs = Vfs::<2, 2>::new();
    vfs.mount("/", &mut fs).unwrap();

    let stale = vfs.open("/hello.txt").unwrap();
    vfs.close(stale).unwrap();
    let fresh = vfs.open("/sub/nested.txt").unwrap();
    assert_eq!(stale.raw() & 0xffff, fresh.raw() & 0xffff, "the same slot was reused");
    assert_ne!(stale, fresh, "with a different generation");

    let mut buf = [0u8; 4];
    assert_eq!(vfs.read(stale, &mut buf).unwrap_err(), Error::BadHandle);
    assert_eq!(vfs.close(stale).unwrap_err(), Error::BadHandle);
    assert_eq!(vfs.read(fresh, &mut buf).unwrap(), 4);
    vfs.close(fresh).unwrap();
}

#[test]
fn the_open_table_fills_and_reports_it() {
    let mut f = Fixture::new();
    let mut fs = f.build();
    let mut vfs = Vfs::<2, 2>::new();
    vfs.mount("/", &mut fs).unwrap();

    let a = vfs.open("/hello.txt").unwrap();
    let b = vfs.open("/hello.txt").unwrap();
    assert_eq!(vfs.open_count(), 2);
    assert_eq!(vfs.open("/hello.txt").unwrap_err(), Error::TooManyOpen);
    vfs.close(a).unwrap();
    let c = vfs.open("/hello.txt").unwrap();
    vfs.close(b).unwrap();
    vfs.close(c).unwrap();
    assert_eq!(vfs.open_count(), 0);
}

#[test]
fn seeking_moves_where_the_next_read_starts() {
    let mut f = Fixture::new();
    let mut fs = f.build();
    let mut vfs = Vfs::<2, 4>::new();
    vfs.mount("/", &mut fs).unwrap();
    let fd = vfs.open("/hello.txt").unwrap();

    let mut buf = [0u8; 3];
    assert_eq!(vfs.read(fd, &mut buf).unwrap(), 3);
    assert_eq!(&buf, b"hel");
    assert_eq!(vfs.tell(fd).unwrap(), 3);
    assert_eq!(vfs.seek(fd, Whence::Start, 1).unwrap(), 1);
    assert_eq!(vfs.read(fd, &mut buf).unwrap(), 3);
    assert_eq!(&buf, b"ell");
    assert_eq!(vfs.seek(fd, Whence::End, 0).unwrap(), 5);
    assert_eq!(vfs.read(fd, &mut buf).unwrap(), 0, "at the end there is nothing");
    assert_eq!(vfs.seek(fd, Whence::Current, -2).unwrap(), 3);
    assert_eq!(vfs.read(fd, &mut buf).unwrap(), 2, "short at the end");
    assert_eq!(&buf[..2], b"lo");
    // Past the end is allowed and reads nothing; below zero is not.
    assert_eq!(vfs.seek(fd, Whence::Start, 100).unwrap(), 100);
    assert_eq!(vfs.read(fd, &mut buf).unwrap(), 0);
    assert_eq!(vfs.seek(fd, Whence::Start, -1).unwrap_err(), Error::OutOfRange);
    vfs.close(fd).unwrap();
}

#[test]
fn a_directory_is_not_read_as_a_file_and_lists_its_entries() {
    let mut f = Fixture::new();
    let mut fs = f.build();
    let mut vfs = Vfs::<2, 4>::new();
    vfs.mount("/", &mut fs).unwrap();

    let fd = vfs.open("/sub").unwrap();
    let mut buf = [0u8; 4];
    assert_eq!(vfs.read(fd, &mut buf).unwrap_err(), Error::IsADirectory);
    vfs.close(fd).unwrap();

    let mut names: Vec<Vec<u8>> = Vec::new();
    let mut i = 0;
    while let Some(e) = vfs.readdir("/", i).unwrap() {
        names.push(e.name().to_vec());
        i += 1;
    }
    names.sort();
    assert_eq!(names, vec![b"hello.txt".to_vec(), b"sub".to_vec()]);
    assert_eq!(vfs.readdir("/sub", 0).unwrap().unwrap().name(), b"nested.txt");
    assert_eq!(vfs.readdir("/sub", 1).unwrap().map(|e| e.node), None);
    assert_eq!(vfs.readdir("/hello.txt", 0).map(|_| ()).unwrap_err(), Error::NotADirectory);
}

#[test]
fn writing_extends_a_file_up_to_its_storage_and_no_further() {
    let mut hello = [0u8; 8];
    let mut fs = MemFs::<4>::new();
    let root = fs.root();
    fs.create_file(root, b"f", &mut hello, 0).unwrap();
    let mut vfs = Vfs::<1, 2>::new();
    vfs.mount("/", &mut fs).unwrap();

    let fd = vfs.open("/f").unwrap();
    assert_eq!(vfs.write(fd, b"abcd").unwrap(), 4);
    assert_eq!(vfs.stat("/f").unwrap().len, 4);
    assert_eq!(vfs.seek(fd, Whence::Start, 0).unwrap(), 0);
    let mut buf = [0u8; 4];
    assert_eq!(vfs.read(fd, &mut buf).unwrap(), 4);
    assert_eq!(&buf, b"abcd");
    // Past the end of the storage is refused, and the file is unchanged.
    assert_eq!(vfs.seek(fd, Whence::Start, 4).unwrap(), 4);
    assert_eq!(vfs.write(fd, b"efghi").unwrap_err(), Error::Full);
    assert_eq!(vfs.stat("/f").unwrap().len, 4);
    vfs.close(fd).unwrap();
}

#[test]
fn read_all_fills_a_buffer_or_says_why_not() {
    let mut f = Fixture::new();
    let mut fs = f.build();
    let mut vfs = Vfs::<2, 4>::new();
    vfs.mount("/", &mut fs).unwrap();

    let mut buf = [0u8; 16];
    assert_eq!(vfs.read_all("/hello.txt", &mut buf).unwrap(), 5);
    assert_eq!(&buf[..5], b"hello");
    let mut small = [0u8; 4];
    assert_eq!(
        vfs.read_all("/hello.txt", &mut small).unwrap_err(),
        Error::OutOfRange,
        "a file that does not fit is refused rather than truncated"
    );
    assert_eq!(vfs.read_all("/sub", &mut buf).unwrap_err(), Error::IsADirectory);
}

/// A filesystem whose `stat` claims more than its `read_at` will give: what a corrupt
/// directory entry looks like from above. `read_all` must refuse rather than hand back a
/// buffer with a tail nobody wrote.
#[test]
fn read_all_refuses_a_file_shorter_than_its_own_length() {
    struct Liar;
    impl FileSystem for Liar {
        /// A filesystem that lies about everything else tells the truth about being empty.
        fn statfs(&mut self) -> Result<crate::StatFs, Error> {
            Ok(crate::StatFs {
                block_size: 1,
                blocks: 0,
                free: 0,
                name_max: crate::MAX_NAME as u32,
            })
        }

        fn root(&self) -> crate::NodeId {
            0
        }
        fn lookup(&mut self, _: crate::NodeId, _: &[u8]) -> Result<crate::NodeId, Error> {
            Err(Error::NotFound)
        }
        fn stat(&mut self, _: crate::NodeId) -> Result<crate::Stat, Error> {
            Ok(crate::Stat {
                kind: Kind::File,
                len: 64,
            })
        }
        fn read_at(&mut self, _: crate::NodeId, _: u64, _: &mut [u8]) -> Result<usize, Error> {
            Ok(0)
        }
        fn readdir(&mut self, _: crate::NodeId, _: usize) -> Result<Option<crate::Entry>, Error> {
            Ok(None)
        }
    }

    let mut liar = Liar;
    let mut vfs = Vfs::<1, 1>::new();
    vfs.mount("/", &mut liar).unwrap();
    let mut buf = [0u8; 64];
    assert_eq!(
        vfs.read_all("/", &mut buf).unwrap_err(),
        Error::Corrupt("file ended before its recorded length")
    );
}

#[test]
fn mounting_refuses_a_prefix_that_is_not_one() {
    // One filesystem per attempt: a mount borrows its filesystem for as long as the
    // namespace lives, and a refused one has taken the borrow just the same.
    let mut relative = MemFs::<2>::new();
    let mut trailing = MemFs::<2>::new();
    let mut disk = MemFs::<2>::new();
    let mut other = MemFs::<2>::new();
    let mut vfs = Vfs::<2, 1>::new();
    assert_eq!(vfs.mount("disk", &mut relative).unwrap_err(), Error::BadPath, "not absolute");
    assert_eq!(vfs.mount("/disk/", &mut trailing).unwrap_err(), Error::BadPath, "trailing");
    vfs.mount("/disk", &mut disk).unwrap();
    assert_eq!(
        vfs.mount("/disk", &mut other).unwrap_err(),
        Error::MountFull,
        "the same prefix twice"
    );
    assert_eq!(vfs.unmount("/nope").unwrap_err(), Error::NoSuchMount);
}

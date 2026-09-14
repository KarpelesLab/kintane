//! The namespace's writing operations against the in-memory filesystem: creating on open,
//! handles that may not write, appending, and the path rules for making, removing and
//! renaming names.

use crate::memfs::MemFs;
use crate::{Error, FileSystem, Kind, OpenFlags, Vfs, Whence};

fn create_write() -> OpenFlags {
    OpenFlags {
        write: true,
        create: true,
        ..OpenFlags::READ
    }
}

#[test]
fn a_handle_opened_to_read_cannot_write() {
    let mut storage = [0u8; 16];
    let mut fs = MemFs::<4>::new();
    let root = fs.root();
    fs.create_file(root, b"f", &mut storage, 3).unwrap();
    let mut vfs = Vfs::<1, 4>::new();
    vfs.mount("/", &mut fs).unwrap();
    let fd = vfs.open_with("/f", OpenFlags::READ).unwrap();
    assert_eq!(vfs.write(fd, b"x"), Err(Error::ReadOnly));
    assert_eq!(vfs.truncate(fd, 0), Err(Error::ReadOnly));
    vfs.close(fd).unwrap();
    let fd = vfs.open("/f").unwrap();
    assert_eq!(vfs.write(fd, b"abc!"), Ok(4));
    vfs.close(fd).unwrap();
}

#[test]
fn opening_with_create_makes_the_file_and_exclusive_refuses_one_that_exists() {
    let mut fs = MemFs::<4>::new();
    let mut vfs = Vfs::<1, 4>::new();
    vfs.mount("/", &mut fs).unwrap();
    assert_eq!(vfs.open_with("/new", OpenFlags::READ), Err(Error::NotFound));
    let fd = vfs.open_with("/new", create_write()).unwrap();
    vfs.close(fd).unwrap();
    assert_eq!(vfs.stat("/new").unwrap().kind, Kind::File);
    let exclusive = OpenFlags {
        exclusive: true,
        ..create_write()
    };
    assert_eq!(vfs.open_with("/new", exclusive), Err(Error::Exists));
    assert_eq!(vfs.open_with("/missing/new", create_write()), Err(Error::NotFound));
    assert_eq!(vfs.open_count(), 0);
}

#[test]
fn a_full_open_table_creates_nothing() {
    let mut fs = MemFs::<4>::new();
    let mut vfs = Vfs::<1, 1>::new();
    vfs.mount("/", &mut fs).unwrap();
    let held = vfs.open("/").unwrap();
    assert_eq!(vfs.open_with("/f", create_write()), Err(Error::TooManyOpen));
    vfs.close(held).unwrap();
    assert_eq!(vfs.stat("/f"), Err(Error::NotFound));
}

#[test]
fn an_appending_handle_writes_at_the_end_wherever_it_was() {
    let mut storage = [0u8; 16];
    let mut fs = MemFs::<4>::new();
    let root = fs.root();
    fs.create_file(root, b"log", &mut storage, 0).unwrap();
    let mut vfs = Vfs::<1, 4>::new();
    vfs.mount("/", &mut fs).unwrap();
    let plain = vfs.open("/log").unwrap();
    vfs.write(plain, b"one").unwrap();
    let append = OpenFlags {
        write: true,
        append: true,
        ..OpenFlags::READ
    };
    let fd = vfs.open_with("/log", append).unwrap();
    vfs.seek(fd, Whence::Start, 0).unwrap();
    vfs.write(fd, b"two").unwrap();
    assert_eq!(vfs.tell(fd), Ok(6));
    vfs.close(fd).unwrap();
    vfs.close(plain).unwrap();
    let truncate = OpenFlags {
        write: true,
        truncate: true,
        ..OpenFlags::READ
    };
    let fd = vfs.open_with("/log", truncate).unwrap();
    vfs.close(fd).unwrap();
    assert_eq!(vfs.stat("/log").unwrap().len, 0);
}

#[test]
fn directories_are_made_removed_and_renamed_by_path() {
    let mut fs = MemFs::<8>::new();
    let mut vfs = Vfs::<1, 4>::new();
    vfs.mount("/", &mut fs).unwrap();
    vfs.mkdir("/a").unwrap();
    vfs.mkdir("/a/b/").unwrap();
    assert_eq!(vfs.mkdir("/a"), Err(Error::Exists));
    assert_eq!(vfs.mkdir("/"), Err(Error::BadPath));
    assert_eq!(vfs.mkdir("/a/."), Err(Error::BadPath));
    assert_eq!(vfs.unlink("/a"), Err(Error::NotEmpty));
    vfs.rename("/a/b", "/a/c").unwrap();
    assert_eq!(vfs.stat("/a/c").unwrap().kind, Kind::Dir);
    assert_eq!(vfs.rename("/a/c", "/c"), Err(Error::BadPath), "not across directories");
    vfs.unlink("/a/c").unwrap();
    vfs.unlink("/a").unwrap();
    assert_eq!(vfs.stat("/a"), Err(Error::NotFound));
    vfs.sync().unwrap();
}

#[test]
fn a_name_that_is_a_mount_point_is_not_the_covered_directorys() {
    let mut outer = MemFs::<4>::new();
    let outer_root = outer.root();
    outer.create_dir(outer_root, b"disk").unwrap();
    let mut inner = MemFs::<4>::new();
    let mut vfs = Vfs::<2, 4>::new();
    vfs.mount("/", &mut outer).unwrap();
    vfs.mount("/disk", &mut inner).unwrap();
    assert_eq!(vfs.unlink("/disk"), Err(Error::BadPath));
    vfs.mkdir("/disk/inside").unwrap();
    assert_eq!(vfs.stat("/disk/inside").unwrap().kind, Kind::Dir);
}

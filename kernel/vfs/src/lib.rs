//! The file namespace: paths, mount points, open files, and what a filesystem must do.
//!
//! One structure, [`Vfs`], holds the mount table and the open-file table. Everything a
//! caller does goes through a path or an [`Fd`], and everything a filesystem must provide
//! is [`FileSystem`]: five operations over an opaque [`NodeId`].
//!
//! # Why it looks like this
//!
//! * **No allocation.** Both tables are fixed arrays sized by const parameters, and a filesystem is
//!   borrowed rather than owned. A namespace that allocates cannot be built before the heap is, and
//!   the kernel mounts its first filesystem during bring-up.
//! * **`&mut self` on the filesystem.** A real filesystem reads its device through a cache, which
//!   it must be able to update. Making the trait immutable would force every implementation to hide
//!   a lock inside itself, which is exactly the decision the caller should make.
//! * **Errors are values.** A storage stack that panics on a bad disk cannot report a bad disk.
//!   Every operation returns [`Error`], including the ones that describe a corrupt volume.
//! * **A generation on every handle.** A closed [`Fd`] whose slot has been reused names a different
//!   file, which is the confusion handle generations exist to prevent everywhere else in this
//!   kernel ([`kobject`](../kobject/index.html) does the same for objects).
//!
//! # What a path may say
//!
//! A path is absolute, and `.` and empty components (`//`, a trailing slash) name the
//! directory they are in. `..` is **not** resolved: it is looked up like any other name
//! and a filesystem that does not report one — the on-disk reader hides `.` and `..` —
//! answers [`Error::NotFound`]. Resolving it means deciding what it does at a mount point
//! and what it does at the root, and nothing needs it yet.
//!
//! # A service over channels, later
//!
//! [`docs/architecture.md`](../../docs/architecture.md) has the VFS as a service reached
//! over channels. That front end is a wrapper: it would decode a message into one of the
//! calls below, run it, and encode what came back. Nothing here knows about channels,
//! processes or rights, so nothing here has to change when it arrives — and the kernel can
//! mount and read a filesystem during bring-up, long before a channel exists.

#![cfg_attr(not(test), no_std)]
#![deny(unsafe_code)]

pub mod memfs;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod write_tests;

/// The longest single path component, and the longest name a directory entry can report.
/// Eight-and-three names fit in twelve bytes; this leaves room for a filesystem with
/// longer ones without making an entry large.
pub const MAX_NAME: usize = 64;

/// The longest path a caller may pass. A path is walked component by component, so this
/// bounds the walk rather than any storage.
pub const MAX_PATH: usize = 256;

/// Why an operation could not be done.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Error {
    /// No file or directory of that name.
    NotFound,
    /// A component of the path is not a directory.
    NotADirectory,
    /// The operation needs a file and was given a directory.
    IsADirectory,
    /// The path is empty, not absolute, or has a component that is too long.
    BadPath,
    /// No mount point covers the path.
    NoSuchMount,
    /// The mount table is full, or the prefix is already mounted.
    MountFull,
    /// The open-file table is full.
    TooManyOpen,
    /// The handle names a slot that has been reused, or was never issued.
    BadHandle,
    /// The offset is past the end of the file, or the seek would go below zero.
    OutOfRange,
    /// This filesystem does not support writing, or the file cannot grow.
    ReadOnly,
    /// The filesystem has no room for what was asked.
    Full,
    /// Something already has the name a creation asked for.
    Exists,
    /// A directory to be removed, or replaced by a rename, still names something.
    NotEmpty,
    /// The two paths of a rename are on different filesystems, which no rename can cross.
    CrossDevice,
    /// The volume does not hold what its format requires. The string names the field, so
    /// a console with no formatter can still say what was wrong.
    Corrupt(&'static str),
    /// The device below the filesystem failed.
    Device(&'static str),
}

/// What a node is.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    File,
    Dir,
}

/// What is known about a node without reading it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Stat {
    pub kind: Kind,
    /// Bytes in a file; zero for a directory, whose size is not a byte count.
    pub len: u64,
}

/// What a whole filesystem is, as [`FileSystem::statfs`] reports it.
///
/// Sizes are in the unit the filesystem allocates in — a cluster, a block — because that is
/// what a caller asking how much room is left needs, and what `statfs` reports everywhere
/// else.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct StatFs {
    /// Bytes in one allocation unit.
    pub block_size: u64,
    /// Units the filesystem has, and how many of them nothing claims.
    pub blocks: u64,
    pub free: u64,
    /// The longest name this filesystem can hold.
    pub name_max: u32,
}

/// A filesystem's own name for a node, opaque to everything above it.
///
/// A filesystem may encode whatever it likes: an inode number, the offset of a directory
/// entry, a cluster. Only [`Vfs`] and the filesystem itself ever see one, and it is
/// meaningful only to the filesystem that issued it.
pub type NodeId = u64;

/// One entry of a directory, as [`FileSystem::readdir`] reports it.
#[derive(Clone, Copy)]
pub struct Entry {
    name: [u8; MAX_NAME],
    len: usize,
    pub node: NodeId,
    pub kind: Kind,
}

impl Entry {
    /// Build an entry, refusing a name that does not fit.
    pub fn new(name: &[u8], node: NodeId, kind: Kind) -> Result<Entry, Error> {
        if name.is_empty() || name.len() > MAX_NAME {
            return Err(Error::BadPath);
        }
        let mut bytes = [0u8; MAX_NAME];
        bytes[..name.len()].copy_from_slice(name);
        Ok(Entry {
            name: bytes,
            len: name.len(),
            node,
            kind,
        })
    }

    pub fn name(&self) -> &[u8] {
        &self.name[..self.len]
    }
}

/// What a filesystem must do.
///
/// Everything is by [`NodeId`]: the namespace resolves paths, so an implementation never
/// parses one. `readdir` is by index rather than by a cursor object, so a caller can walk a
/// directory without holding anything, at the cost of a filesystem that must be able to
/// find its `n`th entry — which every format below can, and a format that cannot may cache
/// its own position.
pub trait FileSystem {
    /// The node every path on this filesystem starts from.
    fn root(&self) -> NodeId;

    /// The node `name` names inside `dir`.
    fn lookup(&mut self, dir: NodeId, name: &[u8]) -> Result<NodeId, Error>;

    fn stat(&mut self, node: NodeId) -> Result<Stat, Error>;

    /// Read into `into` from `offset`, returning how much was read. Short at the end of
    /// the file, and zero once `offset` is at or past it.
    fn read_at(&mut self, node: NodeId, offset: u64, into: &mut [u8]) -> Result<usize, Error>;

    /// Write `from` at `offset`, returning how much was written. Writing past the end
    /// grows the file, with the bytes between its old end and `offset` reading as zeros.
    /// Read-only by default: every operation that changes a filesystem is, so a filesystem
    /// that only reads implements none of them.
    fn write_at(&mut self, node: NodeId, offset: u64, from: &[u8]) -> Result<usize, Error> {
        let _ = (node, offset, from);
        Err(Error::ReadOnly)
    }

    /// Create `name` in `dir`, an empty file or an empty directory. [`Error::Exists`] if
    /// `dir` already names something `name`.
    fn create(&mut self, dir: NodeId, name: &[u8], kind: Kind) -> Result<NodeId, Error> {
        let _ = (dir, name, kind);
        Err(Error::ReadOnly)
    }

    /// Make a file `len` bytes long: shorter gives back what is past it, longer reads as
    /// zeros.
    fn truncate(&mut self, node: NodeId, len: u64) -> Result<(), Error> {
        let _ = (node, len);
        Err(Error::ReadOnly)
    }

    /// Remove `name` from `dir`. A directory must be empty ([`Error::NotEmpty`]).
    fn unlink(&mut self, dir: NodeId, name: &[u8]) -> Result<(), Error> {
        let _ = (dir, name);
        Err(Error::ReadOnly)
    }

    /// Move `from`, in `from_dir`, to the name `to` in `to_dir`, replacing what `to` named:
    /// a file by a file, or an empty directory by a directory.
    ///
    /// The two directories may differ: the namespace resolves both and refuses only a rename
    /// that crosses filesystems ([`Error::CrossDevice`]), since a filesystem can move a name
    /// within itself and none here can move one between two.
    fn rename(
        &mut self,
        from_dir: NodeId,
        from: &[u8],
        to_dir: NodeId,
        to: &[u8],
    ) -> Result<(), Error> {
        let _ = (from_dir, from, to_dir, to);
        Err(Error::ReadOnly)
    }

    /// What the filesystem is: its allocation unit, how many it has and how many are free.
    /// Read-side, like `stat`, so every filesystem answers it.
    fn statfs(&mut self) -> Result<StatFs, Error>;

    /// Make everything written so far durable. A filesystem that holds nothing back has
    /// nothing to do.
    fn sync(&mut self) -> Result<(), Error> {
        Ok(())
    }

    /// The `index`th entry of `dir`, or `None` once there are no more. `.` and `..` are
    /// the filesystem's business: an implementation may report them or not, and the
    /// namespace does not need them, since it resolves paths from a mount's root.
    fn readdir(&mut self, dir: NodeId, index: usize) -> Result<Option<Entry>, Error>;
}

/// A handle to an open file.
///
/// Copyable, because it is a name rather than a resource: closing is explicit, and a
/// handle to a closed slot is refused by its generation rather than by ownership.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Fd {
    index: u16,
    generation: u16,
}

impl Fd {
    pub fn raw(self) -> u32 {
        (u32::from(self.generation) << 16) | u32::from(self.index)
    }
}

/// How [`Vfs::open_with`] opens a path.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct OpenFlags {
    /// Writes through the handle are allowed. Without it they are [`Error::ReadOnly`].
    pub write: bool,
    /// Create the file if nothing has the name.
    pub create: bool,
    /// With `create`, refuse a name that already exists ([`Error::Exists`]).
    pub exclusive: bool,
    /// With `write`, empty the file on opening it.
    pub truncate: bool,
    /// With `write`, every write goes at the end of the file, wherever the position is.
    pub append: bool,
}

impl OpenFlags {
    /// Reading only.
    pub const READ: OpenFlags = OpenFlags {
        write: false,
        create: false,
        exclusive: false,
        truncate: false,
        append: false,
    };
    /// Reading and writing a file that exists.
    pub const READ_WRITE: OpenFlags = OpenFlags {
        write: true,
        ..OpenFlags::READ
    };
}

/// Where a seek counts from.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Whence {
    Start,
    Current,
    End,
}

struct Open {
    /// Which mount the node belongs to.
    mount: usize,
    node: NodeId,
    kind: Kind,
    pos: u64,
    generation: u16,
    used: bool,
    writable: bool,
    append: bool,
}

impl Open {
    const EMPTY: Open = Open {
        mount: 0,
        node: 0,
        kind: Kind::File,
        pos: 0,
        generation: 0,
        used: false,
        writable: false,
        append: false,
    };
}

struct Mount<'fs> {
    /// The prefix this filesystem is reached through: `/` or `/name`, without a trailing
    /// slash. Stored rather than borrowed so a caller's string need not outlive the mount.
    prefix: [u8; MAX_NAME],
    prefix_len: usize,
    fs: &'fs mut dyn FileSystem,
}

/// The namespace: what is mounted where, and what is open.
///
/// `MOUNTS` and `OPEN` size the two tables. A filesystem is borrowed for as long as the
/// namespace lives, which is what lets this hold no allocation and still reach a
/// filesystem that owns a cache and a device.
pub struct Vfs<'fs, const MOUNTS: usize, const OPEN: usize> {
    mounts: [Option<Mount<'fs>>; MOUNTS],
    open: [Open; OPEN],
    /// Bumped for every slot that is reused, so a stale handle cannot name a new file.
    next_generation: u16,
}

impl<'fs, const MOUNTS: usize, const OPEN: usize> Default for Vfs<'fs, MOUNTS, OPEN> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'fs, const MOUNTS: usize, const OPEN: usize> Vfs<'fs, MOUNTS, OPEN> {
    pub const fn new() -> Self {
        Vfs {
            mounts: [const { None }; MOUNTS],
            open: [const { Open::EMPTY }; OPEN],
            next_generation: 1,
        }
    }

    /// Mount `fs` at `prefix`, which must be absolute and have no trailing slash beyond
    /// the root's own.
    pub fn mount(&mut self, prefix: &str, fs: &'fs mut dyn FileSystem) -> Result<(), Error> {
        let bytes = prefix.as_bytes();
        if bytes.first() != Some(&b'/') || bytes.len() > MAX_NAME {
            return Err(Error::BadPath);
        }
        if bytes.len() > 1 && bytes.last() == Some(&b'/') {
            return Err(Error::BadPath);
        }
        if self.mount_named(bytes).is_some() {
            return Err(Error::MountFull);
        }
        let slot = self
            .mounts
            .iter()
            .position(|m| m.is_none())
            .ok_or(Error::MountFull)?;
        let mut stored = [0u8; MAX_NAME];
        stored[..bytes.len()].copy_from_slice(bytes);
        self.mounts[slot] = Some(Mount {
            prefix: stored,
            prefix_len: bytes.len(),
            fs,
        });
        Ok(())
    }

    /// Remove the mount at `prefix`. Refused while any file on it is open, because an
    /// open file names a node of a filesystem that would be gone.
    pub fn unmount(&mut self, prefix: &str) -> Result<(), Error> {
        let slot = self
            .mount_named(prefix.as_bytes())
            .ok_or(Error::NoSuchMount)?;
        if self.open.iter().any(|o| o.used && o.mount == slot) {
            return Err(Error::TooManyOpen);
        }
        self.mounts[slot] = None;
        Ok(())
    }

    fn mount_named(&self, prefix: &[u8]) -> Option<usize> {
        self.mounts.iter().position(|m| match m {
            Some(m) => &m.prefix[..m.prefix_len] == prefix,
            None => false,
        })
    }

    /// The mount covering `path`, and the rest of the path after its prefix.
    ///
    /// The longest prefix wins, so `/disk` shadows `/` for everything under it, which is
    /// what every namespace does and what makes mounting a second filesystem useful.
    fn mount_for<'p>(&mut self, path: &'p [u8]) -> Result<(usize, &'p [u8]), Error> {
        let mut best: Option<(usize, usize)> = None;
        for (i, m) in self.mounts.iter().enumerate() {
            let Some(m) = m else { continue };
            let prefix = &m.prefix[..m.prefix_len];
            let covers = if prefix == b"/" {
                true
            } else {
                path.starts_with(prefix) && matches!(path.get(prefix.len()), None | Some(&b'/'))
            };
            if covers && best.is_none_or(|(_, len)| prefix.len() > len) {
                best = Some((i, prefix.len()));
            }
        }
        let (slot, len) = best.ok_or(Error::NoSuchMount)?;
        // The root mount's prefix is one byte and is itself a separator; a longer prefix
        // is followed by one, or by nothing at all.
        let rest = if len == 1 { &path[1..] } else { &path[len..] };
        Ok((slot, rest))
    }

    /// Walk `path` to a node.
    fn resolve(&mut self, path: &str) -> Result<(usize, NodeId, Stat), Error> {
        let bytes = path.as_bytes();
        if bytes.is_empty() || bytes[0] != b'/' || bytes.len() > MAX_PATH {
            return Err(Error::BadPath);
        }
        let (slot, rest) = self.mount_for(bytes)?;
        // Reborrowed rather than moved out: the mount keeps its filesystem, and the walk
        // below needs it only for as long as it runs.
        let fs = &mut *self.mounts[slot].as_mut().ok_or(Error::NoSuchMount)?.fs;
        let mut node = fs.root();
        let mut stat = fs.stat(node)?;
        for component in rest.split(|&b| b == b'/') {
            // Empty components come from `//` and from a trailing slash, and `.` is this
            // directory: both name what we already have.
            if component.is_empty() || component == b"." {
                continue;
            }
            if component.len() > MAX_NAME {
                return Err(Error::BadPath);
            }
            if stat.kind != Kind::Dir {
                return Err(Error::NotADirectory);
            }
            node = fs.lookup(node, component)?;
            stat = fs.stat(node)?;
        }
        Ok((slot, node, stat))
    }

    /// Walk `path` to the directory holding its last component, and that component.
    ///
    /// The last component must be a name: the root, a path ending in `.` or a component too
    /// long is [`Error::BadPath`]. Trailing slashes are ignored, so `/dir/` names `dir`.
    fn resolve_parent<'p>(&mut self, path: &'p str) -> Result<(usize, NodeId, &'p [u8]), Error> {
        let trimmed = path.trim_end_matches('/');
        let cut = trimmed.rfind('/').ok_or(Error::BadPath)?;
        let name = &trimmed.as_bytes()[cut + 1..];
        if name.is_empty() || name == b"." || name == b".." || name.len() > MAX_NAME {
            return Err(Error::BadPath);
        }
        let parent = if cut == 0 { "/" } else { &trimmed[..cut] };
        let (mount, dir, stat) = self.resolve(parent)?;
        if stat.kind != Kind::Dir {
            return Err(Error::NotADirectory);
        }
        // A name that is itself a mount point belongs to the mount, not to the directory
        // it covers.
        let (covering, _) = self.mount_for(trimmed.as_bytes())?;
        if covering != mount {
            return Err(Error::BadPath);
        }
        Ok((mount, dir, name))
    }

    /// What `path` names, without opening it.
    pub fn stat(&mut self, path: &str) -> Result<Stat, Error> {
        self.resolve(path).map(|(_, _, stat)| stat)
    }

    /// Open `path`: a file for reading and writing, a directory for reading. Directories
    /// open so a caller can read them with [`readdir`](Self::readdir); reading one as a
    /// file is refused, and so is a write on a filesystem that does not write.
    pub fn open(&mut self, path: &str) -> Result<Fd, Error> {
        let flags = match self.resolve(path)?.2.kind {
            Kind::Dir => OpenFlags::READ,
            Kind::File => OpenFlags::READ_WRITE,
        };
        self.open_with(path, flags)
    }

    /// Open `path` as `flags` say: creating it, emptying it, or refusing writes through the
    /// handle.
    pub fn open_with(&mut self, path: &str, flags: OpenFlags) -> Result<Fd, Error> {
        if !self.open.iter().any(|o| !o.used) {
            // Refused before anything is created, so a full table leaves no file behind.
            return Err(Error::TooManyOpen);
        }
        let (mount, node, stat) = match self.resolve(path) {
            Ok(_) if flags.create && flags.exclusive => return Err(Error::Exists),
            Ok(found) => found,
            Err(Error::NotFound) if flags.create => {
                let (mount, dir, name) = self.resolve_parent(path)?;
                let fs = self.fs_of(mount)?;
                let node = fs.create(dir, name, Kind::File)?;
                let stat = fs.stat(node)?;
                (mount, node, stat)
            }
            Err(e) => return Err(e),
        };
        if flags.write && stat.kind == Kind::Dir {
            return Err(Error::IsADirectory);
        }
        if flags.write && flags.truncate && stat.len != 0 {
            self.fs_of(mount)?.truncate(node, 0)?;
        }
        let index = self
            .open
            .iter()
            .position(|o| !o.used)
            .ok_or(Error::TooManyOpen)?;
        let generation = self.next_generation;
        // Wrapping is fine and never collides with a live handle: a slot's generation
        // changes on every open, so a stale handle matches only after 65 535 opens of the
        // same slot, and the index must match too.
        self.next_generation = self.next_generation.wrapping_add(1).max(1);
        self.open[index] = Open {
            mount,
            node,
            kind: stat.kind,
            pos: 0,
            generation,
            used: true,
            writable: flags.write,
            append: flags.write && flags.append,
        };
        Ok(Fd {
            index: index as u16,
            generation,
        })
    }

    pub fn close(&mut self, fd: Fd) -> Result<(), Error> {
        let index = self.slot_of(fd)?;
        self.open[index].used = false;
        Ok(())
    }

    /// How many files are open. The accounting a caller checks to prove nothing leaked.
    pub fn open_count(&self) -> usize {
        self.open.iter().filter(|o| o.used).count()
    }

    fn slot_of(&self, fd: Fd) -> Result<usize, Error> {
        let index = usize::from(fd.index);
        match self.open.get(index) {
            Some(o) if o.used && o.generation == fd.generation => Ok(index),
            _ => Err(Error::BadHandle),
        }
    }

    fn fs_of(&mut self, mount: usize) -> Result<&mut dyn FileSystem, Error> {
        Ok(&mut *self.mounts[mount].as_mut().ok_or(Error::NoSuchMount)?.fs)
    }

    /// Read at the handle's position, advancing it by what was read.
    pub fn read(&mut self, fd: Fd, into: &mut [u8]) -> Result<usize, Error> {
        let index = self.slot_of(fd)?;
        let (mount, node, pos, kind) = {
            let o = &self.open[index];
            (o.mount, o.node, o.pos, o.kind)
        };
        if kind != Kind::File {
            return Err(Error::IsADirectory);
        }
        let n = self.fs_of(mount)?.read_at(node, pos, into)?;
        self.open[index].pos = pos.saturating_add(n as u64);
        Ok(n)
    }

    /// Write at the handle's position, advancing it by what was written. A handle opened
    /// to append writes at the end of the file, and its position follows.
    pub fn write(&mut self, fd: Fd, from: &[u8]) -> Result<usize, Error> {
        let index = self.slot_of(fd)?;
        let (mount, node, mut pos, kind, writable, append) = {
            let o = &self.open[index];
            (o.mount, o.node, o.pos, o.kind, o.writable, o.append)
        };
        if kind != Kind::File {
            return Err(Error::IsADirectory);
        }
        if !writable {
            return Err(Error::ReadOnly);
        }
        let fs = self.fs_of(mount)?;
        if append {
            pos = fs.stat(node)?.len;
        }
        let n = fs.write_at(node, pos, from)?;
        self.open[index].pos = pos.saturating_add(n as u64);
        Ok(n)
    }

    /// Make the handle's file `len` bytes long. The position does not move.
    pub fn truncate(&mut self, fd: Fd, len: u64) -> Result<(), Error> {
        let index = self.slot_of(fd)?;
        let o = &self.open[index];
        let (mount, node, kind, writable) = (o.mount, o.node, o.kind, o.writable);
        if kind != Kind::File {
            return Err(Error::IsADirectory);
        }
        if !writable {
            return Err(Error::ReadOnly);
        }
        self.fs_of(mount)?.truncate(node, len)
    }

    /// Make everything written to the handle's filesystem durable.
    pub fn fsync(&mut self, fd: Fd) -> Result<(), Error> {
        let mount = self.open[self.slot_of(fd)?].mount;
        self.fs_of(mount)?.sync()
    }

    /// Make everything written to every mounted filesystem durable.
    pub fn sync(&mut self) -> Result<(), Error> {
        let mut first = Ok(());
        for m in self.mounts.iter_mut().flatten() {
            if let Err(e) = m.fs.sync() {
                first = first.and(Err(e));
            }
        }
        first
    }

    /// Create an empty directory at `path`.
    pub fn mkdir(&mut self, path: &str) -> Result<(), Error> {
        let (mount, dir, name) = self.resolve_parent(path)?;
        self.fs_of(mount)?.create(dir, name, Kind::Dir).map(|_| ())
    }

    /// Remove the file or empty directory at `path`.
    pub fn unlink(&mut self, path: &str) -> Result<(), Error> {
        let (mount, dir, name) = self.resolve_parent(path)?;
        self.fs_of(mount)?.unlink(dir, name)
    }

    /// Rename `from` to `to`, which may be in another directory of the same filesystem.
    ///
    /// Across two filesystems it is [`Error::CrossDevice`]: the bytes would have to be copied,
    /// and a caller that wants them copied can do that itself, knowing what it costs.
    pub fn rename(&mut self, from: &str, to: &str) -> Result<(), Error> {
        let (mount, dir, old) = self.resolve_parent(from)?;
        let (to_mount, to_dir, new) = self.resolve_parent(to)?;
        if mount != to_mount {
            return Err(Error::CrossDevice);
        }
        self.fs_of(mount)?.rename(dir, old, to_dir, new)
    }

    /// What the filesystem covering `path` is: its allocation unit, and how much of it is free.
    pub fn statfs(&mut self, path: &str) -> Result<StatFs, Error> {
        let (mount, _, _) = self.resolve(path)?;
        self.fs_of(mount)?.statfs()
    }

    /// Move the handle's position. Seeking past the end is allowed and reads there return
    /// nothing, as every file interface does; seeking below zero is refused.
    pub fn seek(&mut self, fd: Fd, whence: Whence, offset: i64) -> Result<u64, Error> {
        let index = self.slot_of(fd)?;
        let (mount, node, pos) = {
            let o = &self.open[index];
            (o.mount, o.node, o.pos)
        };
        let base = match whence {
            Whence::Start => 0,
            Whence::Current => pos,
            Whence::End => self.fs_of(mount)?.stat(node)?.len,
        };
        let next = if offset >= 0 {
            base.checked_add(offset as u64)
        } else {
            base.checked_sub(offset.unsigned_abs())
        }
        .ok_or(Error::OutOfRange)?;
        self.open[index].pos = next;
        Ok(next)
    }

    /// What the handle's file is now: its size after every write so far.
    pub fn fstat(&mut self, fd: Fd) -> Result<Stat, Error> {
        let o = &self.open[self.slot_of(fd)?];
        let (mount, node) = (o.mount, o.node);
        self.fs_of(mount)?.stat(node)
    }

    /// The handle's position, without moving it.
    pub fn tell(&self, fd: Fd) -> Result<u64, Error> {
        self.slot_of(fd).map(|i| self.open[i].pos)
    }

    /// What the filesystem the handle's file is on is, as [`Vfs::statfs`] reports it of a path.
    ///
    /// The handle already names its mount, so this asks that filesystem rather than resolving
    /// a path again: a caller holding an open file may have no path to give, and the file may
    /// have been renamed or removed since it was opened.
    pub fn statfs_fd(&mut self, fd: Fd) -> Result<StatFs, Error> {
        let mount = self.open[self.slot_of(fd)?].mount;
        self.fs_of(mount)?.statfs()
    }

    /// The `index`th entry of the directory an open handle names.
    ///
    /// By index rather than by a cursor, exactly as [`FileSystem::readdir`] is, so the handle
    /// holds no listing state and a caller may ask for the same entry twice. A caller that
    /// wants a cursor has one already: the handle's position, moved with [`seek`](Self::seek)
    /// and read with [`tell`](Self::tell), which nothing else uses on a directory.
    ///
    /// # What an index promises, and what it costs
    ///
    /// An index names a position in the directory as it is **now**, not a name. Nothing here
    /// can promise more: a filesystem this kernel mounts has no stable cookie per entry — FAT
    /// numbers its entries by where they sit, so removing one moves every entry after it down.
    /// A caller that lists a directory while something removes from it may therefore see a
    /// name twice or not at all, and only a caller that does not remove while listing is
    /// promised each name once. The same is true of every `readdir` by index, and saying so is
    /// cheaper than a cookie no filesystem below could honour.
    ///
    /// The cost is that a filesystem finds its `index`th entry by counting from the first, so
    /// listing a directory of *n* entries reads *n²/2* of them. Directories here hold tens of
    /// names, not thousands.
    pub fn readdir_fd(&mut self, fd: Fd, index: usize) -> Result<Option<Entry>, Error> {
        let slot = self.slot_of(fd)?;
        let (mount, node, kind) = {
            let o = &self.open[slot];
            (o.mount, o.node, o.kind)
        };
        if kind != Kind::Dir {
            return Err(Error::NotADirectory);
        }
        self.fs_of(mount)?.readdir(node, index)
    }

    /// The `index`th entry of the directory at `path`.
    pub fn readdir(&mut self, path: &str, index: usize) -> Result<Option<Entry>, Error> {
        let (mount, node, stat) = self.resolve(path)?;
        if stat.kind != Kind::Dir {
            return Err(Error::NotADirectory);
        }
        self.fs_of(mount)?.readdir(node, index)
    }

    /// Read the whole of a file into `into`, refusing one that does not fit.
    ///
    /// The kernel's own reason for a namespace at bring-up: a program is loaded in one
    /// call, into a buffer whose size is the caller's bound on what it will accept.
    pub fn read_all(&mut self, path: &str, into: &mut [u8]) -> Result<usize, Error> {
        let (mount, node, stat) = self.resolve(path)?;
        if stat.kind != Kind::File {
            return Err(Error::IsADirectory);
        }
        if stat.len > into.len() as u64 {
            return Err(Error::OutOfRange);
        }
        let want = stat.len as usize;
        let mut done = 0;
        while done < want {
            let n = self
                .fs_of(mount)?
                .read_at(node, done as u64, &mut into[done..want])?;
            if n == 0 {
                // The file is shorter than its own size says: a corrupt directory entry,
                // or a chain that ended early. Either way the caller asked for bytes that
                // are not there, and a short read reported as success would hand a loader
                // a truncated program.
                return Err(Error::Corrupt("file ended before its recorded length"));
            }
            done += n;
        }
        Ok(done)
    }
}

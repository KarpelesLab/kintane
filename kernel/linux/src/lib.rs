//! The Linux personality's machine-independent half.
//!
//! A process the loader tags `linux` makes Linux system calls, and the kernel answers them
//! on its own objects: the calls land in `kernel/main/src/personality.rs`, which owns the fd table
//! and the process. What that file needs and can be written without a process is here:
//!
//! * **The table.** [`TABLE_X86_64`] is an in-tree copy of Linux's own `syscall_64.tbl` format, and
//!   [`name`] reads it, so an unimplemented call is logged by the name Linux gives it. The numbers
//!   the kernel dispatches on are the constants in [`nr`], and a host test pins each to its name in
//!   the table, so the dispatch and the table cannot drift apart.
//! * **Errors.** [`Failure`] is every way the personality's calls fail, and [`errno`] is the one
//!   place each becomes a Linux error number. The roadmap asks for this mapping to be reviewed
//!   rather than accreted: it is a single exhaustive `match`, so a new failure does not compile
//!   until someone decides what Linux calls it.
//! * **The initial stack.** [`initial_stack`] lays out what a Linux program finds at its stack
//!   pointer when it starts: `argc`, `argv`, `envp` and the auxiliary vector, with the strings and
//!   `AT_RANDOM`'s bytes above them.
//! * **Structures.** [`stat_bytes`] and [`utsname`], the two layouts a static program's start-up
//!   and the check's program read.
//!
//! Everything is data or a pure function of data, so it is host-tested and depends on
//! nothing.

#![cfg_attr(not(test), no_std)]
#![deny(unsafe_code)]

#[cfg(test)]
mod tests;

/// The x86_64 system call table, in the format of Linux's `syscall_64.tbl`.
pub const TABLE_X86_64: &str = include_str!("../syscalls_x86_64.tbl");

/// The x86_64 numbers the personality dispatches on. Linux's, and so fixed forever; each is
/// checked against [`TABLE_X86_64`] by a host test.
pub mod nr {
    pub const READ: u64 = 0;
    pub const WRITE: u64 = 1;
    pub const CLOSE: u64 = 3;
    pub const FSTAT: u64 = 5;
    pub const MMAP: u64 = 9;
    pub const MUNMAP: u64 = 11;
    pub const BRK: u64 = 12;
    pub const GETPID: u64 = 39;
    pub const EXIT: u64 = 60;
    pub const UNAME: u64 = 63;
    pub const ARCH_PRCTL: u64 = 158;
    pub const GETTID: u64 = 186;
    pub const SET_TID_ADDRESS: u64 = 218;
    pub const EXIT_GROUP: u64 = 231;
    pub const OPENAT: u64 = 257;

    /// Every number above, with the name the table must give it.
    pub const IMPLEMENTED: [(u64, &str); 15] = [
        (READ, "read"),
        (WRITE, "write"),
        (CLOSE, "close"),
        (FSTAT, "fstat"),
        (MMAP, "mmap"),
        (MUNMAP, "munmap"),
        (BRK, "brk"),
        (GETPID, "getpid"),
        (EXIT, "exit"),
        (UNAME, "uname"),
        (ARCH_PRCTL, "arch_prctl"),
        (GETTID, "gettid"),
        (SET_TID_ADDRESS, "set_tid_address"),
        (EXIT_GROUP, "exit_group"),
        (OPENAT, "openat"),
    ];
}

/// The name `table` gives system call `number`, for the 64-bit ABI. `None` for a number the
/// table does not list.
///
/// Reads the table text each time. It is consulted only on the cold path, to log a call the
/// personality does not implement, and a parse at build time would be a generator this crate
/// does not need.
pub fn name(table: &str, number: u64) -> Option<&str> {
    table.lines().find_map(|line| {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            return None;
        }
        let mut fields = line.split_whitespace();
        let n: u64 = fields.next()?.parse().ok()?;
        let abi = fields.next()?;
        let name = fields.next()?;
        (n == number && (abi == "common" || abi == "64")).then_some(name)
    })
}

/// `arch_prctl`'s code for setting the `FS` base, the thread pointer on x86_64.
pub const ARCH_SET_FS: u64 = 0x1002;

/// `openat`'s "relative to the working directory".
pub const AT_FDCWD: i64 = -100;
/// `open`'s access mode bits, and read-only.
pub const O_ACCMODE: u64 = 3;
pub const O_RDONLY: u64 = 0;
/// `open`'s "must be a directory".
pub const O_DIRECTORY: u64 = 0o200000;

/// `mmap`'s protections and flags, as far as the personality reads them.
pub const PROT_READ: u64 = 1;
pub const PROT_WRITE: u64 = 2;
pub const PROT_EXEC: u64 = 4;
pub const MAP_PRIVATE: u64 = 0x02;
pub const MAP_FIXED: u64 = 0x10;
pub const MAP_ANONYMOUS: u64 = 0x20;

/// Linux error numbers the personality returns. Linux's values.
pub mod errno {
    pub const ENOENT: i64 = 2;
    pub const EIO: i64 = 5;
    pub const EBADF: i64 = 9;
    pub const ENOMEM: i64 = 12;
    pub const EACCES: i64 = 13;
    pub const EFAULT: i64 = 14;
    pub const ENOTDIR: i64 = 20;
    pub const EISDIR: i64 = 21;
    pub const EINVAL: i64 = 22;
    pub const EMFILE: i64 = 24;
    pub const ENOSPC: i64 = 28;
    pub const EROFS: i64 = 30;
    pub const ENAMETOOLONG: i64 = 36;
    pub const ENOSYS: i64 = 38;
}

/// Every way a call the personality implements can fail, before it is a Linux number.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Failure {
    /// A path names nothing.
    NotFound,
    /// A path's prefix is a file, or `O_DIRECTORY` named a file.
    NotADirectory,
    /// A read or an open for writing named a directory.
    IsADirectory,
    /// A path the filesystem cannot represent: too long, or a component it will not hold.
    NameTooLong,
    /// A descriptor that names nothing, or names something the call cannot use.
    BadDescriptor,
    /// Every descriptor slot, or every open file, is in use.
    TooManyOpen,
    /// A user address could not be read or written.
    Fault,
    /// An argument is out of range or a combination the call does not accept.
    InvalidArgument,
    /// No memory for the mapping or the break.
    NoMemory,
    /// The call is refused on this object: a writable open on a read-only volume.
    ReadOnly,
    /// The object refuses the operation for a reason that is not the caller's to fix, such as
    /// a mapping asked to be executable, which W^X does not grant.
    AccessDenied,
    /// The storage behind a file failed, or is corrupt.
    Io,
    /// No room left on the volume.
    NoSpace,
    /// The call is not implemented.
    NotImplemented,
}

/// The Linux error number for `f`. One exhaustive `match`, reviewed as a whole.
pub const fn errno(f: Failure) -> i64 {
    use errno::*;
    match f {
        Failure::NotFound => ENOENT,
        Failure::NotADirectory => ENOTDIR,
        Failure::IsADirectory => EISDIR,
        // Linux reports a component or path longer than it holds this way; a FAT 8.3 name
        // that does not fit is the same failure from the program's side.
        Failure::NameTooLong => ENAMETOOLONG,
        Failure::BadDescriptor => EBADF,
        Failure::TooManyOpen => EMFILE,
        Failure::Fault => EFAULT,
        Failure::InvalidArgument => EINVAL,
        Failure::NoMemory => ENOMEM,
        Failure::ReadOnly => EROFS,
        // Not `EPERM`: Linux uses `EACCES` for a mapping whose protections the object refuses.
        Failure::AccessDenied => EACCES,
        Failure::Io => EIO,
        Failure::NoSpace => ENOSPC,
        Failure::NotImplemented => ENOSYS,
    }
}

/// A result as the one return register carries it: the value, or the negated error number.
pub const fn ret(r: Result<u64, Failure>) -> u64 {
    match r {
        Ok(v) => v,
        Err(f) => (-errno(f)) as u64,
    }
}

// ---- the auxiliary vector -------------------------------------------------------------

pub const AT_NULL: u64 = 0;
pub const AT_PHDR: u64 = 3;
pub const AT_PHENT: u64 = 4;
pub const AT_PHNUM: u64 = 5;
pub const AT_PAGESZ: u64 = 6;
pub const AT_ENTRY: u64 = 9;
pub const AT_UID: u64 = 11;
pub const AT_EUID: u64 = 12;
pub const AT_GID: u64 = 13;
pub const AT_EGID: u64 = 14;
pub const AT_SECURE: u64 = 23;
pub const AT_RANDOM: u64 = 25;
pub const AT_EXECFN: u64 = 31;

/// What a program is started with.
pub struct StartInfo<'a> {
    pub argv: &'a [&'a [u8]],
    pub envp: &'a [&'a [u8]],
    /// Auxiliary vector entries other than `AT_RANDOM`, `AT_EXECFN` and `AT_NULL`, which
    /// [`initial_stack`] adds itself because it places what they point to.
    pub auxv: &'a [(u64, u64)],
    /// The sixteen bytes `AT_RANDOM` points to.
    pub random: [u8; 16],
}

/// Why a start-up stack could not be laid out.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum StackError {
    /// The buffer cannot hold the strings and vectors.
    TooSmall,
    /// A string contains a NUL, which would end it early.
    EmbeddedNul,
}

const WORD: usize = 8;

/// Lay out a Linux start-up stack in `buf`, which the program sees at user addresses
/// `[top - buf.len(), top)`. Returns the stack pointer the program starts with: the address
/// of `argc`, aligned to 16 bytes as the x86_64 and aarch64 ABIs require at entry.
///
/// From the top down: the `argv` strings, the `envp` strings, `AT_RANDOM`'s sixteen bytes,
/// alignment, then `argc`, the `argv` pointers and a null, the `envp` pointers and a null, and
/// the auxiliary vector ending in `AT_NULL`. `AT_EXECFN` points at `argv[0]` when there is one.
pub fn initial_stack(buf: &mut [u8], top: u64, info: &StartInfo) -> Result<u64, StackError> {
    let len = buf.len();
    let bottom = top.checked_sub(len as u64).ok_or(StackError::TooSmall)?;
    // Where the next byte goes, as an offset into `buf`, growing down.
    let mut cursor = len;

    let mut place = |bytes: &[u8], nul: bool, cursor: &mut usize| -> Result<u64, StackError> {
        let need = bytes.len() + usize::from(nul);
        let start = cursor.checked_sub(need).ok_or(StackError::TooSmall)?;
        buf[start..start + bytes.len()].copy_from_slice(bytes);
        if nul {
            buf[start + bytes.len()] = 0;
        }
        *cursor = start;
        Ok(bottom + start as u64)
    };

    let mut argv_at = [0u64; 32];
    let mut envp_at = [0u64; 32];
    if info.argv.len() > argv_at.len() || info.envp.len() > envp_at.len() {
        return Err(StackError::TooSmall);
    }
    for (i, s) in info.argv.iter().enumerate() {
        if s.contains(&0) {
            return Err(StackError::EmbeddedNul);
        }
        argv_at[i] = place(s, true, &mut cursor)?;
    }
    for (i, s) in info.envp.iter().enumerate() {
        if s.contains(&0) {
            return Err(StackError::EmbeddedNul);
        }
        envp_at[i] = place(s, true, &mut cursor)?;
    }
    let random_at = place(&info.random, false, &mut cursor)?;

    let execfn = info.argv.first().map(|_| argv_at[0]);
    let aux_entries = info.auxv.len() + 1 + usize::from(execfn.is_some()) + 1;
    let words = 1 + (info.argv.len() + 1) + (info.envp.len() + 1) + 2 * aux_entries;
    let vectors = words * WORD;
    let sp_offset = cursor
        .checked_sub(vectors)
        .ok_or(StackError::TooSmall)?
        // Down to a 16-byte boundary of the address the program sees, not of the offset.
        .checked_sub(((bottom as usize).wrapping_add(cursor - vectors)) % 16)
        .ok_or(StackError::TooSmall)?;

    let mut w = sp_offset;
    let mut push = |v: u64, w: &mut usize| {
        buf[*w..*w + WORD].copy_from_slice(&v.to_le_bytes());
        *w += WORD;
    };
    push(info.argv.len() as u64, &mut w);
    for &a in &argv_at[..info.argv.len()] {
        push(a, &mut w);
    }
    push(0, &mut w);
    for &e in &envp_at[..info.envp.len()] {
        push(e, &mut w);
    }
    push(0, &mut w);
    for &(key, value) in info.auxv {
        push(key, &mut w);
        push(value, &mut w);
    }
    push(AT_RANDOM, &mut w);
    push(random_at, &mut w);
    if let Some(execfn) = execfn {
        push(AT_EXECFN, &mut w);
        push(execfn, &mut w);
    }
    push(AT_NULL, &mut w);
    push(0, &mut w);
    Ok(bottom + sp_offset as u64)
}

// ---- structures -------------------------------------------------------------------------

/// What a file descriptor is, for `st_mode`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FileKind {
    Regular,
    Directory,
    CharDevice,
}

/// x86_64's `struct stat`, which is 144 bytes.
pub const STAT_BYTES: usize = 144;

/// A `struct stat` for a file of `kind` and `size` bytes, inode `ino`. Read-only
/// permissions: every file the personality opens today is on a read-only volume, and the
/// console is the process's only writable descriptor.
pub fn stat_bytes(kind: FileKind, size: u64, ino: u64) -> [u8; STAT_BYTES] {
    let mut s = [0u8; STAT_BYTES];
    let mode: u32 = match kind {
        FileKind::Regular => 0o100444,
        FileKind::Directory => 0o040555,
        FileKind::CharDevice => 0o020620,
    };
    s[0..8].copy_from_slice(&1u64.to_le_bytes()); // st_dev
    s[8..16].copy_from_slice(&ino.to_le_bytes()); // st_ino
    s[16..24].copy_from_slice(&1u64.to_le_bytes()); // st_nlink
    s[24..28].copy_from_slice(&mode.to_le_bytes()); // st_mode
    // st_uid, st_gid, padding, st_rdev: zero.
    s[48..56].copy_from_slice(&size.to_le_bytes()); // st_size
    s[56..64].copy_from_slice(&512u64.to_le_bytes()); // st_blksize
    s[64..72].copy_from_slice(&size.div_ceil(512).to_le_bytes()); // st_blocks
    s
}

/// `struct utsname`: six fields of 65 bytes.
pub const UTSNAME_BYTES: usize = 6 * UTS_FIELD;
const UTS_FIELD: usize = 65;

/// The kernel's release, as `uname` reports it. `sysname` is `Linux`, which is what a
/// program probing for the ABI it is on needs to read; the release says whose it is.
pub const RELEASE: &str = "6.1.0-kintane";

/// A `struct utsname` for `machine`.
pub fn utsname(machine: &str) -> [u8; UTSNAME_BYTES] {
    let mut u = [0u8; UTSNAME_BYTES];
    let fields = ["Linux", "kintane", RELEASE, "#1 KinTane", machine, "(none)"];
    for (i, f) in fields.iter().enumerate() {
        let at = i * UTS_FIELD;
        let n = f.len().min(UTS_FIELD - 1);
        u[at..at + n].copy_from_slice(&f.as_bytes()[..n]);
    }
    u
}

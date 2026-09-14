//! The Linux personality's machine-independent half.
//!
//! A process the loader tags `linux` makes Linux system calls, and the kernel answers them
//! on its own objects: the calls land in `kernel/main/src/personality.rs`, which owns the fd table
//! and the process. What that file needs and can be written without a process is here:
//!
//! * **The tables.** [`TABLE_X86_64`] and [`TABLE_AARCH64`] are in-tree copies of Linux's own table
//!   format for each architecture, and [`name`] reads them, so an unimplemented call is logged by
//!   the name Linux gives it. The calls the kernel dispatches on are [`Call`]s, each with its
//!   number under each [`Abi`], and a host test pins every number to its name in that ABI's table,
//!   so the dispatch and the tables cannot drift apart.
//! * **Errors.** [`Failure`] is every way the personality's calls fail, and [`errno`] is the one
//!   place each becomes a Linux error number. The roadmap asks for this mapping to be reviewed
//!   rather than accreted: it is a single exhaustive `match`, so a new failure does not compile
//!   until someone decides what Linux calls it.
//! * **The initial stack.** [`initial_stack`] lays out what a Linux program finds at its stack
//!   pointer when it starts: `argc`, `argv`, `envp` and the auxiliary vector, with the strings and
//!   `AT_RANDOM`'s bytes above them. The layout is the same on both architectures.
//! * **Structures.** [`stat_bytes`] and [`utsname`], the two layouts a static program's start-up
//!   and the check's program read. `struct stat` differs between the two ABIs.
//! * **Signals.** [`signal`]: the numbers and their default actions, `struct sigaction`, and the
//!   signal frame each architecture pushes and `rt_sigreturn` reads back, validated there.
//!
//! Everything is data or a pure function of data, so it is host-tested and depends on
//! nothing.

#![cfg_attr(not(test), no_std)]
#![deny(unsafe_code)]

#[cfg(test)]
mod tests;

pub mod signal;

/// The x86_64 system call table, in the format of Linux's `syscall_64.tbl`.
pub const TABLE_X86_64: &str = include_str!("../syscalls_x86_64.tbl");
/// The aarch64 system call table, in the format of Linux's generic `syscall.tbl`.
pub const TABLE_AARCH64: &str = include_str!("../syscalls_aarch64.tbl");

/// A Linux system call ABI: the numbering, and the few layouts that differ with it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Abi {
    X86_64,
    Aarch64,
}

impl Abi {
    /// The ABI of programs built for ELF machine `machine`, if it is one the personality
    /// speaks.
    pub const fn for_machine(machine: u16) -> Option<Abi> {
        match machine {
            62 => Some(Abi::X86_64),
            183 => Some(Abi::Aarch64),
            _ => None,
        }
    }

    /// Its table, for [`name`].
    pub const fn table(self) -> &'static str {
        match self {
            Abi::X86_64 => TABLE_X86_64,
            Abi::Aarch64 => TABLE_AARCH64,
        }
    }

    /// `uname`'s machine.
    pub const fn machine(self) -> &'static str {
        match self {
            Abi::X86_64 => "x86_64",
            Abi::Aarch64 => "aarch64",
        }
    }

    /// `open`'s "must be a directory", which arm64 numbers differently from the generic
    /// value x86_64 uses.
    pub const fn o_directory(self) -> u64 {
        match self {
            Abi::X86_64 => 0o200000,
            Abi::Aarch64 => 0o40000,
        }
    }

    /// `clone`'s arguments as `(flags, stack, parent_tid, child_tid, tls)`. x86_64 passes the
    /// thread pointer last; aarch64, like most architectures, before the child's tid.
    pub const fn clone_args(self, a: [u64; 6]) -> [u64; 5] {
        match self {
            Abi::X86_64 => [a[0], a[1], a[2], a[3], a[4]],
            Abi::Aarch64 => [a[0], a[1], a[2], a[4], a[3]],
        }
    }
}

/// A system call the personality implements.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Call {
    Read,
    Write,
    Close,
    Fstat,
    Mmap,
    Munmap,
    Brk,
    Pipe,
    Pipe2,
    SchedYield,
    Getpid,
    Gettid,
    SetTidAddress,
    Clone,
    Fork,
    Execve,
    Exit,
    ExitGroup,
    Wait4,
    Uname,
    ArchPrctl,
    Futex,
    Openat,
    RtSigaction,
    RtSigprocmask,
    RtSigreturn,
    RtSigpending,
    Sigaltstack,
    Kill,
    Tgkill,
    Socket,
    Connect,
    Accept,
    Accept4,
    Bind,
    Listen,
    Sendto,
    Recvfrom,
    Shutdown,
    Getsockname,
    Getpeername,
    Setsockopt,
    Getsockopt,
}

impl Call {
    /// Every call, for the host tests and [`decode`].
    pub const ALL: [Call; 43] = [
        Call::Read,
        Call::Write,
        Call::Close,
        Call::Fstat,
        Call::Mmap,
        Call::Munmap,
        Call::Brk,
        Call::Pipe,
        Call::Pipe2,
        Call::SchedYield,
        Call::Getpid,
        Call::Gettid,
        Call::SetTidAddress,
        Call::Clone,
        Call::Fork,
        Call::Execve,
        Call::Exit,
        Call::ExitGroup,
        Call::Wait4,
        Call::Uname,
        Call::ArchPrctl,
        Call::Futex,
        Call::Openat,
        Call::RtSigaction,
        Call::RtSigprocmask,
        Call::RtSigreturn,
        Call::RtSigpending,
        Call::Sigaltstack,
        Call::Kill,
        Call::Tgkill,
        Call::Socket,
        Call::Connect,
        Call::Accept,
        Call::Accept4,
        Call::Bind,
        Call::Listen,
        Call::Sendto,
        Call::Recvfrom,
        Call::Shutdown,
        Call::Getsockname,
        Call::Getpeername,
        Call::Setsockopt,
        Call::Getsockopt,
    ];

    /// The name the tables give it.
    pub const fn name(self) -> &'static str {
        match self {
            Call::Read => "read",
            Call::Write => "write",
            Call::Close => "close",
            Call::Fstat => "fstat",
            Call::Mmap => "mmap",
            Call::Munmap => "munmap",
            Call::Brk => "brk",
            Call::Pipe => "pipe",
            Call::Pipe2 => "pipe2",
            Call::SchedYield => "sched_yield",
            Call::Getpid => "getpid",
            Call::Gettid => "gettid",
            Call::SetTidAddress => "set_tid_address",
            Call::Clone => "clone",
            Call::Fork => "fork",
            Call::Execve => "execve",
            Call::Exit => "exit",
            Call::ExitGroup => "exit_group",
            Call::Wait4 => "wait4",
            Call::Uname => "uname",
            Call::ArchPrctl => "arch_prctl",
            Call::Futex => "futex",
            Call::Openat => "openat",
            Call::RtSigaction => "rt_sigaction",
            Call::RtSigprocmask => "rt_sigprocmask",
            Call::RtSigreturn => "rt_sigreturn",
            Call::RtSigpending => "rt_sigpending",
            Call::Sigaltstack => "sigaltstack",
            Call::Kill => "kill",
            Call::Tgkill => "tgkill",
            Call::Socket => "socket",
            Call::Connect => "connect",
            Call::Accept => "accept",
            Call::Accept4 => "accept4",
            Call::Bind => "bind",
            Call::Listen => "listen",
            Call::Sendto => "sendto",
            Call::Recvfrom => "recvfrom",
            Call::Shutdown => "shutdown",
            Call::Getsockname => "getsockname",
            Call::Getpeername => "getpeername",
            Call::Setsockopt => "setsockopt",
            Call::Getsockopt => "getsockopt",
        }
    }

    /// Its number under `abi`: Linux's, and so fixed forever. `None` where that architecture
    /// has no such call.
    pub const fn number(self, abi: Abi) -> Option<u64> {
        let (x86_64, aarch64) = match self {
            Call::Read => (0, 63),
            Call::Write => (1, 64),
            Call::Close => (3, 57),
            Call::Fstat => (5, 80),
            Call::Mmap => (9, 222),
            Call::Munmap => (11, 215),
            Call::Brk => (12, 214),
            Call::Pipe => (22, NONE),
            Call::Pipe2 => (293, 59),
            Call::SchedYield => (24, 124),
            Call::Getpid => (39, 172),
            Call::Gettid => (186, 178),
            Call::SetTidAddress => (218, 96),
            Call::Clone => (56, 220),
            Call::Fork => (57, NONE),
            Call::Execve => (59, 221),
            Call::Exit => (60, 93),
            Call::ExitGroup => (231, 94),
            Call::Wait4 => (61, 260),
            Call::Uname => (63, 160),
            Call::ArchPrctl => (158, NONE),
            Call::Futex => (202, 98),
            Call::Openat => (257, 56),
            Call::RtSigaction => (13, 134),
            Call::RtSigprocmask => (14, 135),
            Call::RtSigreturn => (15, 139),
            Call::RtSigpending => (127, 136),
            Call::Sigaltstack => (131, 132),
            Call::Kill => (62, 129),
            Call::Tgkill => (234, 131),
            Call::Socket => (41, 198),
            Call::Connect => (42, 203),
            Call::Accept => (43, 202),
            Call::Accept4 => (288, 242),
            Call::Bind => (49, 200),
            Call::Listen => (50, 201),
            Call::Sendto => (44, 206),
            Call::Recvfrom => (45, 207),
            Call::Shutdown => (48, 210),
            Call::Getsockname => (51, 204),
            Call::Getpeername => (52, 205),
            Call::Setsockopt => (54, 208),
            Call::Getsockopt => (55, 209),
        };
        let n = match abi {
            Abi::X86_64 => x86_64,
            Abi::Aarch64 => aarch64,
        };
        if n == NONE { None } else { Some(n) }
    }
}

/// No such call on that architecture.
const NONE: u64 = u64::MAX;

/// The implemented call `number` names under `abi`, or `None` for one the personality does
/// not implement.
pub fn decode(abi: Abi, number: u64) -> Option<Call> {
    Call::ALL
        .iter()
        .copied()
        .find(|c| c.number(abi) == Some(number))
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
/// `open`'s and `pipe2`'s "close on `execve`", the same on both architectures.
pub const O_CLOEXEC: u64 = 0o2000000;
/// `open`'s and `pipe2`'s "never block", the same on both architectures.
pub const O_NONBLOCK: u64 = 0o4000;

/// `mmap`'s protections and flags, as far as the personality reads them.
pub const PROT_READ: u64 = 1;
pub const PROT_WRITE: u64 = 2;
pub const PROT_EXEC: u64 = 4;
pub const MAP_PRIVATE: u64 = 0x02;
pub const MAP_FIXED: u64 = 0x10;
pub const MAP_ANONYMOUS: u64 = 0x20;

/// `clone`'s flags, as far as the personality reads them.
pub mod clone {
    /// The low byte: the signal a child's exit sends its parent.
    pub const CSIGNAL: u64 = 0xff;
    pub const VM: u64 = 0x100;
    pub const FS: u64 = 0x200;
    pub const FILES: u64 = 0x400;
    pub const SIGHAND: u64 = 0x800;
    pub const VFORK: u64 = 0x4000;
    pub const THREAD: u64 = 0x10000;
    pub const SYSVSEM: u64 = 0x40000;
    pub const SETTLS: u64 = 0x80000;
    pub const PARENT_SETTID: u64 = 0x100000;
    pub const CHILD_CLEARTID: u64 = 0x200000;
    pub const CHILD_SETTID: u64 = 0x1000000;
    /// Every flag a thread library's `clone` passes, and which the personality honours.
    pub const THREAD_FLAGS: u64 = VM
        | FS
        | FILES
        | SIGHAND
        | THREAD
        | SYSVSEM
        | SETTLS
        | PARENT_SETTID
        | CHILD_CLEARTID
        | CHILD_SETTID;
}

/// The signal a child's exit sends, which `fork` implies.
pub const SIGCHLD: u64 = 17;

/// `futex`'s operations and the flags that modify them.
pub const FUTEX_WAIT: u64 = 0;
pub const FUTEX_WAKE: u64 = 1;
pub const FUTEX_PRIVATE_FLAG: u64 = 128;
pub const FUTEX_CLOCK_REALTIME: u64 = 256;

/// `wait4`'s "do not wait".
pub const WNOHANG: u64 = 1;

/// The socket calls' constants, and `struct sockaddr_in`, as far as the personality reads them.
/// The values are the same on x86_64 and aarch64.
pub mod socket {
    use super::Failure;

    pub const AF_INET: u64 = 2;
    pub const SOCK_STREAM: u64 = 1;
    /// The bits of `socket`'s type that name the type; the rest are flags.
    pub const SOCK_TYPE_MASK: u64 = 0xf;
    /// `socket`'s and `accept4`'s flags, which are `open`'s values.
    pub const SOCK_NONBLOCK: u64 = super::O_NONBLOCK;
    pub const SOCK_CLOEXEC: u64 = super::O_CLOEXEC;
    pub const IPPROTO_TCP: u64 = 6;

    pub const SOL_SOCKET: u64 = 1;
    pub const SO_REUSEADDR: u64 = 2;
    pub const SO_TYPE: u64 = 3;
    pub const SO_ERROR: u64 = 4;
    pub const SO_KEEPALIVE: u64 = 9;
    pub const TCP_NODELAY: u64 = 1;

    pub const MSG_DONTWAIT: u64 = 0x40;
    pub const MSG_NOSIGNAL: u64 = 0x4000;

    pub const SHUT_RD: u64 = 0;
    pub const SHUT_WR: u64 = 1;
    pub const SHUT_RDWR: u64 = 2;

    /// Bytes of `struct sockaddr_in`: the family, the port and the address, then eight of
    /// padding.
    pub const SOCKADDR_IN_LEN: usize = 16;

    /// `ip`:`port` as a `struct sockaddr_in`: the family in the machine's byte order, the port
    /// and the address in the network's.
    pub fn sockaddr_in(ip: [u8; 4], port: u16) -> [u8; SOCKADDR_IN_LEN] {
        let mut a = [0u8; SOCKADDR_IN_LEN];
        a[0..2].copy_from_slice(&(AF_INET as u16).to_le_bytes());
        a[2..4].copy_from_slice(&port.to_be_bytes());
        a[4..8].copy_from_slice(&ip);
        a
    }

    /// The address and port a `struct sockaddr_in` of `bytes` names.
    pub fn parse_sockaddr_in(bytes: &[u8]) -> Result<([u8; 4], u16), Failure> {
        let (Some(family), Some(port), Some(ip)) =
            (bytes.get(0..2), bytes.get(2..4), bytes.get(4..8))
        else {
            return Err(Failure::InvalidArgument);
        };
        if u16::from_le_bytes([family[0], family[1]]) != AF_INET as u16 {
            return Err(Failure::AddressFamilyNotSupported);
        }
        Ok(([ip[0], ip[1], ip[2], ip[3]], u16::from_be_bytes([port[0], port[1]])))
    }
}

/// The status `wait4` reports for a child that exited with `code`: the low 8 bits, shifted
/// into place.
pub const fn exited_status(code: u64) -> u32 {
    ((code & 0xff) as u32) << 8
}

/// The status `wait4` reports for a child the kernel killed for a reason no signal names, such
/// as a system call under LINUX_ENOSYS_FATAL: `SIGKILL`'s, which is what the kernel did. A child
/// a signal ended reports that signal ([`signal::status`]).
pub const KILLED_STATUS: u32 = 9;

/// Linux error numbers the personality returns. Linux's values.
pub mod errno {
    pub const ENOENT: i64 = 2;
    pub const ESRCH: i64 = 3;
    pub const EINTR: i64 = 4;
    pub const EIO: i64 = 5;
    pub const ENOEXEC: i64 = 8;
    pub const EBADF: i64 = 9;
    pub const ECHILD: i64 = 10;
    pub const EAGAIN: i64 = 11;
    pub const ENOMEM: i64 = 12;
    pub const EACCES: i64 = 13;
    pub const EFAULT: i64 = 14;
    pub const ENOTDIR: i64 = 20;
    pub const EISDIR: i64 = 21;
    pub const EINVAL: i64 = 22;
    pub const EMFILE: i64 = 24;
    pub const ENOSPC: i64 = 28;
    pub const EROFS: i64 = 30;
    pub const EPIPE: i64 = 32;
    pub const ENAMETOOLONG: i64 = 36;
    pub const ENOSYS: i64 = 38;
    pub const ENOTSOCK: i64 = 88;
    pub const ENOPROTOOPT: i64 = 92;
    pub const EPROTONOSUPPORT: i64 = 93;
    pub const EOPNOTSUPP: i64 = 95;
    pub const EAFNOSUPPORT: i64 = 97;
    pub const EADDRINUSE: i64 = 98;
    pub const EADDRNOTAVAIL: i64 = 99;
    pub const ENETDOWN: i64 = 100;
    pub const ECONNRESET: i64 = 104;
    pub const EISCONN: i64 = 106;
    pub const ENOTCONN: i64 = 107;
    pub const ETIMEDOUT: i64 = 110;
    pub const ECONNREFUSED: i64 = 111;
    pub const EALREADY: i64 = 114;
    pub const EINPROGRESS: i64 = 115;
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
    /// Not now: a futex whose value has already changed, a non-blocking descriptor with
    /// nothing to give, or no process slot or thread for a `fork` or `clone`.
    TryAgain,
    /// `wait4` named no child of the caller.
    NoChild,
    /// A write to a pipe no one can read.
    BrokenPipe,
    /// `execve` named a file that is not a program this kernel runs as a Linux one.
    NotExecutable,
    /// A wait with a timeout, such as a futex's, ran out.
    TimedOut,
    /// The call is not implemented.
    NotImplemented,
    /// A blocking call was interrupted by a signal with a handler to run, and is not restarted.
    Interrupted,
    /// `kill` or `tgkill` named no Linux process or thread.
    NoProcess,
    /// A socket call named a descriptor that is not a socket.
    NotASocket,
    /// A socket of an address family other than IPv4.
    AddressFamilyNotSupported,
    /// A socket type or protocol other than TCP's byte stream.
    ProtocolNotSupported,
    /// A socket option the personality does not know.
    NoProtocolOption,
    /// A flag or mode the call has but the personality does not offer, such as `MSG_PEEK`.
    OperationNotSupported,
    /// A port already bound or listened on, or no free connection to make.
    AddressInUse,
    /// An address that is not this machine's.
    AddressNotAvailable,
    /// No started network card.
    NetworkDown,
    /// The peer reset the connection.
    ConnectionReset,
    /// `connect` on a socket that is connected.
    AlreadyConnected,
    /// A send, receive or peer name on a socket with no connection.
    NotConnected,
    /// Nobody listens at the address `connect` named.
    ConnectionRefused,
    /// A non-blocking `connect` already under way.
    Already,
    /// A non-blocking `connect` begun, and not yet finished.
    InProgress,
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
        // Linux's own answer to a `fork` past the process limit, as well as to the futex and
        // non-blocking cases.
        Failure::TryAgain => EAGAIN,
        Failure::NoChild => ECHILD,
        // The writer is sent `SIGPIPE` as well, whose default action ends it before it sees this.
        Failure::BrokenPipe => EPIPE,
        Failure::NotExecutable => ENOEXEC,
        Failure::TimedOut => ETIMEDOUT,
        Failure::NotImplemented => ENOSYS,
        Failure::Interrupted => EINTR,
        Failure::NoProcess => ESRCH,
        Failure::NotASocket => ENOTSOCK,
        Failure::AddressFamilyNotSupported => EAFNOSUPPORT,
        Failure::ProtocolNotSupported => EPROTONOSUPPORT,
        Failure::NoProtocolOption => ENOPROTOOPT,
        Failure::OperationNotSupported => EOPNOTSUPP,
        Failure::AddressInUse => EADDRINUSE,
        Failure::AddressNotAvailable => EADDRNOTAVAIL,
        Failure::NetworkDown => ENETDOWN,
        Failure::ConnectionReset => ECONNRESET,
        Failure::AlreadyConnected => EISCONN,
        Failure::NotConnected => ENOTCONN,
        Failure::ConnectionRefused => ECONNREFUSED,
        Failure::Already => EALREADY,
        Failure::InProgress => EINPROGRESS,
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
    /// Either end of a pipe.
    Fifo,
    Socket,
}

/// The largest `struct stat`: x86_64's, 144 bytes. aarch64's, the generic layout, is 128.
pub const STAT_BYTES: usize = 144;

impl Abi {
    /// Bytes of this ABI's `struct stat`.
    pub const fn stat_len(self) -> usize {
        match self {
            Abi::X86_64 => 144,
            Abi::Aarch64 => 128,
        }
    }
}

/// A `struct stat` in `abi`'s layout for a file of `kind` and `size` bytes, inode `ino`: the
/// first [`Abi::stat_len`] bytes of the result. Read-only permissions for files, since every
/// file the personality opens is on a read-only volume.
pub fn stat_bytes(abi: Abi, kind: FileKind, size: u64, ino: u64) -> [u8; STAT_BYTES] {
    let mut s = [0u8; STAT_BYTES];
    let mode: u32 = match kind {
        FileKind::Regular => 0o100444,
        FileKind::Directory => 0o040555,
        FileKind::CharDevice => 0o020620,
        FileKind::Fifo => 0o010600,
        FileKind::Socket => 0o140777,
    };
    s[0..8].copy_from_slice(&1u64.to_le_bytes()); // st_dev
    s[8..16].copy_from_slice(&ino.to_le_bytes()); // st_ino
    match abi {
        Abi::X86_64 => {
            s[16..24].copy_from_slice(&1u64.to_le_bytes()); // st_nlink
            s[24..28].copy_from_slice(&mode.to_le_bytes()); // st_mode
            // st_uid, st_gid, padding, st_rdev: zero.
            s[56..64].copy_from_slice(&512u64.to_le_bytes()); // st_blksize
        }
        Abi::Aarch64 => {
            s[16..20].copy_from_slice(&mode.to_le_bytes()); // st_mode
            s[20..24].copy_from_slice(&1u32.to_le_bytes()); // st_nlink
            // st_uid, st_gid, st_rdev, padding: zero.
            s[56..60].copy_from_slice(&512u32.to_le_bytes()); // st_blksize
        }
    }
    // The size and the block count sit at the same offsets in both.
    s[48..56].copy_from_slice(&size.to_le_bytes()); // st_size
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

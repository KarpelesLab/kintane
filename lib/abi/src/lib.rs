//! The native system call ABI: the one definition the kernel and userspace share.
//!
//! Everything a system call is lives in [`table`], in one invocation of the
//! [`syscalls!`] macro: its number, its name, its arguments and their types, and its
//! documentation. From that one table the macro generates
//!
//! * [`number`], the numbering;
//! * [`Handler`], the trait the kernel implements, one method per call;
//! * [`dispatch`], which decodes and validates the raw argument registers into the typed arguments
//!   a [`Handler`] method takes, and refuses an unknown number;
//! * [`call`], the userspace bindings, one function per call;
//! * [`TABLE`], the table as data, for tests and documentation.
//!
//! So a call cannot be numbered one way in the kernel and another way in a program, and an
//! argument cannot be decoded as a handle on one side and an address on the other.
//!
//! # Why a declarative macro and not `#[syscall]`
//!
//! `docs/userspace-abi.md` describes dispatch "generated from `#[syscall]` attributes".
//! An attribute that generates code is a procedural macro, and a procedural macro is a
//! host-compiled compiler plugin: kbuild calls `rustc` one crate at a time and has no
//! machinery for building and loading one. The two alternatives were a generator in
//! kbuild reading an in-tree table, or a `macro_rules!` table in a crate both sides link.
//! The macro wins on what matters here: the table is Rust, so a type named in it is
//! checked against the real type on both sides, and changing a signature is a compile
//! error in whichever side did not follow. A kbuild generator would produce the same code
//! from a format nothing type-checks until it is expanded. What the macro cannot do is
//! produce the documentation page the doc also promises; [`TABLE`] is the data that page
//! will be generated from.
//!
//! # The calling convention
//!
//! | | x86_64 | aarch64 |
//! |---|---|---|
//! | trap | `syscall` | `svc #0` |
//! | number | `rax` | `x8` |
//! | arguments | `rdi rsi rdx r10 r8 r9` | `x0`–`x5` |
//! | status | `rax` | `x0` |
//! | value | `rdx` | `x1` |
//! | clobbered | `rcx r11` | nothing else |
//!
//! # Errors are values
//!
//! Every call returns two registers: a status, zero for success or an [`Error`] code, and
//! a value that means something only on success. That is the discriminated result the
//! design asks for, with no `errno` and no negative-number convention to confuse with a
//! large unsigned result.

#![cfg_attr(not(test), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

mod macros;
pub mod table;

#[cfg(test)]
mod tests;

// The trap instruction is per architecture, and chosen here, at module level. On an
// architecture with no userspace port the bindings still compile, and every call reports
// `Unsupported`, so that the crate builds everywhere the ABI's types are needed.
#[cfg(target_arch = "x86_64")]
#[path = "raw_x86_64.rs"]
mod raw;
#[cfg(target_arch = "aarch64")]
#[path = "raw_aarch64.rs"]
mod raw;
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
#[path = "raw_none.rs"]
mod raw;

pub use table::{Handler, TABLE, call, dispatch, number};

/// Why a system call did not succeed. The code is what travels in the status register.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u64)]
#[non_exhaustive]
pub enum Error {
    /// No system call has this number.
    NoSuchCall = 1,
    /// The handle does not name a live object in the caller's table. Also what a guessed
    /// or forged handle value gets: the table cannot tell the two apart, and must not.
    BadHandle = 2,
    /// The handle names an object of the wrong kind for this call.
    WrongType = 3,
    /// The handle lacks a right the call needs.
    AccessDenied = 4,
    /// A user address could not be read or written: outside the user address range, or not
    /// backed by memory the process may access that way.
    Fault = 5,
    /// An argument is out of range for the call.
    InvalidArgument = 6,
    /// The kernel could not find the memory the call needs.
    NoMemory = 7,
    /// Nothing is ready yet; the same call may succeed later.
    ShouldWait = 8,
    /// The other end of a channel is closed.
    PeerClosed = 9,
    /// A message or buffer larger than the call accepts.
    TooLarge = 10,
    /// A queue or table has no room.
    Full = 11,
    /// This kernel does not implement the call on this machine.
    Unsupported = 12,
    /// A wait ran out before what it waited for happened.
    TimedOut = 13,
    /// A status this version of the ABI does not know. Never sent by a kernel that shares
    /// this crate's version; it exists so decoding is total.
    Unknown = 0xffff,
}

impl Error {
    /// Every error, in code order, except [`Error::Unknown`].
    pub const ALL: [Error; 13] = [
        Error::NoSuchCall,
        Error::BadHandle,
        Error::WrongType,
        Error::AccessDenied,
        Error::Fault,
        Error::InvalidArgument,
        Error::NoMemory,
        Error::ShouldWait,
        Error::PeerClosed,
        Error::TooLarge,
        Error::Full,
        Error::Unsupported,
        Error::TimedOut,
    ];

    pub const fn code(self) -> u64 {
        self as u64
    }

    /// The error a status register names. Never zero: zero is success.
    pub fn from_code(code: u64) -> Error {
        Error::ALL
            .into_iter()
            .find(|e| e.code() == code)
            .unwrap_or(Error::Unknown)
    }
}

/// The two return registers for a result.
pub const fn encode(result: Result<u64, Error>) -> (u64, u64) {
    match result {
        Ok(value) => (0, value),
        Err(e) => (e.code(), 0),
    }
}

/// The result two return registers describe.
pub fn decode(status: u64, value: u64) -> Result<u64, Error> {
    if status == 0 {
        Ok(value)
    } else {
        Err(Error::from_code(status))
    }
}

/// The rights a handle can carry, as the bits of the mask `channel_send` narrows a moved
/// handle with.
///
/// The kernel's `kobject::Rights` is the definition; these are its bit positions for a
/// program, which cannot link a kernel crate. `kernel/main/src/userproc.rs` asserts at
/// compile time that the two agree, so a renumbering in one fails the build rather than
/// quietly granting the wrong right.
pub mod rights {
    pub const READ: u32 = 1 << 0;
    pub const WRITE: u32 = 1 << 1;
    pub const EXECUTE: u32 = 1 << 2;
    pub const DUPLICATE: u32 = 1 << 3;
    pub const TRANSFER: u32 = 1 << 4;
    pub const WAIT: u32 = 1 << 5;
    pub const SIGNAL: u32 = 1 << 6;
    pub const MAP: u32 = 1 << 7;
    pub const DESTROY: u32 = 1 << 8;
    pub const INSPECT: u32 = 1 << 9;
    pub const ALL: u32 = (1 << 10) - 1;
}

/// A handle value as a program holds it: an opaque number the kernel issued. Only the
/// kernel's table knows what, if anything, it names.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(transparent)]
pub struct Handle(pub u32);

/// An address in the caller's address space, as the caller passed it. Nothing about it is
/// trusted: the kernel checks the range, and reads or writes through it only with a
/// fault-safe copy.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(transparent)]
pub struct UserPtr(pub u64);

/// A type a system call argument can be: how it is checked on the way in, and how a
/// program puts it in a register.
pub trait Arg: Sized {
    /// Validate a raw register. An error here ends the call before any handler runs.
    fn decode(raw: u64) -> Result<Self, Error>;
    fn encode(self) -> u64;
}

impl Arg for u64 {
    fn decode(raw: u64) -> Result<u64, Error> {
        Ok(raw)
    }
    fn encode(self) -> u64 {
        self
    }
}

impl Arg for usize {
    fn decode(raw: u64) -> Result<usize, Error> {
        usize::try_from(raw).map_err(|_| Error::InvalidArgument)
    }
    fn encode(self) -> u64 {
        self as u64
    }
}

impl Arg for Handle {
    /// A handle is 32 bits. Anything wider cannot name a handle, so it is refused as one.
    fn decode(raw: u64) -> Result<Handle, Error> {
        u32::try_from(raw).map(Handle).map_err(|_| Error::BadHandle)
    }
    fn encode(self) -> u64 {
        u64::from(self.0)
    }
}

impl Arg for UserPtr {
    fn decode(raw: u64) -> Result<UserPtr, Error> {
        Ok(UserPtr(raw))
    }
    fn encode(self) -> u64 {
        self.0
    }
}

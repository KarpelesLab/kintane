//! The native runtime: the ABI with its sharp edges covered.
//!
//! `lib/abi` is the contract, and it is deliberately thin: every call is exactly one trap,
//! errors are values, and nothing waits. That is right for a contract and wrong for a
//! program, which would otherwise spell out the same loops and the same byte-packing every
//! time. This crate is where those live, so a program says what it wants and the kernel's
//! interface stays honest about what it does.
//!
//! # Blocking is the runtime's, not the kernel's
//!
//! No system call here blocks. [`completion_wait`] and [`recv`] loop over the call that
//! reports `ShouldWait`, yielding between attempts, and that loop is this crate's. The
//! kernel therefore has no wait queues yet: a thread waiting is a thread the scheduler
//! keeps running, which costs a slice each time round. It is the honest shape of what
//! exists rather than a wrapper that pretends otherwise, and when the kernel grows a
//! blocking `completion_wait` this is the one place that changes.
//!
//! # Why there is no slice indexing here
//!
//! A user program is linked at the bottom of the user half — 512 GiB up on x86_64 — while
//! `core` is built for the kernel's small code model, whose 32-bit relocations cannot reach
//! that far. Nothing here may therefore instantiate `core`'s panicking paths: no `a[i]`, no
//! range slicing, no `copy_from_slice`. Every read below is `get`, and every conversion is
//! from a fixed-size array, so the linker never has to reach `slice_index_fail` and its
//! formatting machinery. A program that breaks this rule does not fail to compile; it fails
//! to *link*, with a relocation out of range in `libcore`.

#![no_std]
#![deny(unsafe_code)]

pub use abi::{Error, Handle, UserPtr, call};

/// A finished asynchronous operation: the key its requester chose, and what it produced.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Completion {
    pub key: u64,
    pub value: u64,
}

/// Give the CPU up once. Every wait in this crate goes through here, so a program that
/// waits is always a program that lets something else run.
pub fn yield_now() {
    let _ = call::thread_yield();
}

/// End this process with `code`.
pub fn exit(code: u64) -> ! {
    let _ = call::process_exit(code);
    // Only reached if the kernel returned from an exit, which its own checks treat as a
    // process that never ended. Spin rather than fall off the end of the program.
    loop {
        yield_now();
    }
}

/// Write `bytes` to the debug console. `console` must carry `WRITE`.
pub fn print(console: Handle, bytes: &[u8]) -> Result<usize, Error> {
    call::debug_write(console, UserPtr(bytes.as_ptr() as u64), bytes.len()).map(|n| n as usize)
}

/// The eight bytes at `at` in `buf`, as a little-endian `u64`. `None` if they are not all
/// there — see the note on slice indexing in the crate documentation.
fn u64_at(buf: &[u8], at: usize) -> Option<u64> {
    let mut value = 0u64;
    let mut i = 0;
    while i < 8 {
        let byte = *buf.get(at + i)?;
        value |= (byte as u64) << (8 * i);
        i += 1;
    }
    Some(value)
}

/// As [`u64_at`], for a little-endian `u32`.
fn u32_at(buf: &[u8], at: usize) -> Option<u32> {
    let mut value = 0u32;
    let mut i = 0;
    while i < 4 {
        let byte = *buf.get(at + i)?;
        value |= (byte as u32) << (8 * i);
        i += 1;
    }
    Some(value)
}

/// Whether the first `len` bytes of `buf` are `want`.
pub fn starts_with(buf: &[u8], len: usize, want: &[u8]) -> bool {
    if len != want.len() {
        return false;
    }
    let mut i = 0;
    while i < len {
        match (buf.get(i), want.get(i)) {
            (Some(a), Some(b)) if a == b => i += 1,
            _ => return false,
        }
    }
    true
}

/// Create a channel: two endpoints in this process's table.
pub fn channel() -> Result<(Handle, Handle), Error> {
    let mut pair = [0u8; 8];
    call::channel_create(UserPtr(pair.as_mut_ptr() as u64))?;
    let a = u32_at(&pair, 0).ok_or(Error::Fault)?;
    let b = u32_at(&pair, 4).ok_or(Error::Fault)?;
    Ok((Handle(a), Handle(b)))
}

/// Send `bytes` on `channel`, which must carry `WRITE`.
pub fn send(channel: Handle, bytes: &[u8]) -> Result<(), Error> {
    call::channel_write(channel, UserPtr(bytes.as_ptr() as u64), bytes.len()).map(|_| ())
}

/// Receive into `buf` without waiting. `ShouldWait` means nothing has arrived.
pub fn try_recv(channel: Handle, buf: &mut [u8]) -> Result<usize, Error> {
    call::channel_read(channel, UserPtr(buf.as_mut_ptr() as u64), buf.len()).map(|n| n as usize)
}

/// Receive into `buf`, yielding until a message arrives or the peer closes.
pub fn recv(channel: Handle, buf: &mut [u8]) -> Result<usize, Error> {
    loop {
        match try_recv(channel, buf) {
            Err(Error::ShouldWait) => yield_now(),
            other => return other,
        }
    }
}

/// Take one completion without waiting. `ShouldWait` means the queue is empty.
pub fn try_completion(queue: Handle) -> Result<Completion, Error> {
    let mut out = [0u8; 16];
    call::completion_poll(queue, UserPtr(out.as_mut_ptr() as u64))?;
    let key = u64_at(&out, 0).ok_or(Error::Fault)?;
    let value = u64_at(&out, 8).ok_or(Error::Fault)?;
    Ok(Completion { key, value })
}

/// Wait for one completion, yielding until something finishes.
pub fn completion_wait(queue: Handle) -> Result<Completion, Error> {
    loop {
        match try_completion(queue) {
            Err(Error::ShouldWait) => yield_now(),
            other => return other,
        }
    }
}

/// Make a completion queue.
pub fn completion_queue() -> Result<Handle, Error> {
    call::completion_create().map(|h| Handle(h as u32))
}

/// A process under construction, and then running.
pub struct Process {
    pub handle: Handle,
}

impl Process {
    /// Build a process from the program `image` holds. It has no threads yet: give it what
    /// it needs first, then [`start`](Process::start) it.
    pub fn create(image: Handle) -> Result<Process, Error> {
        call::process_create(image).map(|h| Process {
            handle: Handle(h as u32),
        })
    }

    /// Move `handle` into this process. Returns the value it has there, which is what the
    /// program must be told to use: a handle value means nothing outside its own table.
    pub fn give(&self, handle: Handle) -> Result<Handle, Error> {
        call::process_transfer(self.handle, handle).map(|v| Handle(v as u32))
    }

    /// Map `region` into this process, at an address the kernel chooses.
    pub fn map(&self, region: Handle) -> Result<u64, Error> {
        call::vm_map_in(self.handle, region)
    }

    /// Start a thread at the program's entry point, with `arg` in its first argument
    /// register.
    pub fn start(&self, arg: u64) -> Result<Handle, Error> {
        call::thread_create(self.handle, 0, arg).map(|h| Handle(h as u32))
    }

    /// Ask for this process's exit to be posted to `queue` under `key`.
    pub fn wait_on(&self, queue: Handle, key: u64) -> Result<(), Error> {
        call::process_wait(self.handle, queue, key).map(|_| ())
    }

    /// Wait for this process to end and return its exit code. Completions under other keys
    /// are not consumed.
    pub fn join(&self, queue: Handle, key: u64) -> Result<u64, Error> {
        loop {
            let c = completion_wait(queue)?;
            if c.key == key {
                return Ok(c.value);
            }
        }
    }
}

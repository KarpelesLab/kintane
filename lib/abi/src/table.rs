//! The native system call table. The whole ABI surface is this file.
//!
//! Numbers are unstable until Phase 6 completes; see `docs/userspace-abi.md#stability`.

use crate::{Handle, UserPtr};

crate::syscalls! {
    /// End the calling process: every thread in it, and every handle it holds. Does not
    /// return to the caller.
    0 => fn process_exit(code: u64);
    /// End the calling thread. A process whose last thread exits ends with `code`. Does
    /// not return to the caller.
    1 => fn thread_exit(code: u64);
    /// Offer the CPU to another thread that is ready to run. Always succeeds.
    2 => fn thread_yield();
    /// Write `len` bytes at `bytes` to the kernel's debug console. `console` must name the
    /// console with `WRITE`. Returns the number of bytes written.
    3 => fn debug_write(console: Handle, bytes: UserPtr, len: usize);
    /// Reserve `len` bytes of zeroed anonymous memory, readable and writable, somewhere in
    /// the caller's address space. `len` is rounded up to whole pages; pages are provided
    /// when first touched. Returns the address.
    4 => fn vm_map(len: usize);
    /// Create a channel and install both endpoints in the caller's table. The two handle
    /// values are written as two little-endian `u32`s at `out`.
    5 => fn channel_create(out: UserPtr);
    /// Send `len` bytes at `bytes` on the endpoint `channel` names, which needs `WRITE`.
    /// A full queue is `Full`; nothing blocks.
    6 => fn channel_write(channel: Handle, bytes: UserPtr, len: usize);
    /// Receive the message at the front of `channel`'s queue into `cap` bytes at `buf`,
    /// which needs `READ`. An empty queue is `ShouldWait`. Returns the message's length.
    7 => fn channel_read(channel: Handle, buf: UserPtr, cap: usize);
    /// Remove `handle` from the caller's table.
    8 => fn handle_close(handle: Handle);
}

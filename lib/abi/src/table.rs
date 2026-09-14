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

    // ---- explicit construction ----------------------------------------------------------
    //
    // There is no `fork`. A process is built piece by piece by whoever has the handles to
    // build it with: an image to load, memory to map, handles to give it, and finally a
    // thread to run it. Every step is a handle the caller must already hold, so a program
    // can create exactly as much as it was given the authority to create.

    /// Create a process from the program `image` names, which must be a memory region
    /// holding an executable and carry `READ`. The process has an address space, its
    /// program loaded, and no threads. Returns a handle to it with every right.
    9 => fn process_create(image: Handle);
    /// Move `handle` out of the caller's table and into the table of the process `process`
    /// names. `process` needs `WRITE` and `handle` needs `TRANSFER`. Returns the value the
    /// handle has in the destination, which is what the new process must be told to use.
    10 => fn process_transfer(process: Handle, handle: Handle);
    /// Create a thread in the process `process` names, which needs `WRITE`, and start it.
    /// `entry` is an address in that process, or 0 for its program's entry point; `arg` is
    /// the value its first argument register holds. Returns a handle to the thread.
    11 => fn thread_create(process: Handle, entry: u64, arg: u64);
    /// Ask for `key` and the exit code to be posted to `completion` when the process
    /// `process` names ends. `process` needs `WAIT`, `completion` needs `WRITE`. A process
    /// that has already ended posts at once. One waiter per process; a second is `Full`.
    12 => fn process_wait(process: Handle, completion: Handle, key: u64);
    /// Create a completion queue: where finished asynchronous operations report. Returns a
    /// handle to it with every right.
    13 => fn completion_create();
    /// Take the oldest completion from the queue `completion` names, which needs `READ`,
    /// and write its key and value at `out` as two little-endian `u64`s. An empty queue is
    /// `ShouldWait`; nothing blocks, and a blocking wait belongs to the runtime.
    14 => fn completion_poll(completion: Handle, out: UserPtr);
    /// Create an anonymous memory region of `len` bytes, rounded up to whole pages, that
    /// nothing maps yet. Returns a handle to it with every right.
    15 => fn vm_region_create(len: usize);
    /// Map the region `region` names, which needs `MAP`, into the process `process` names,
    /// which needs `WRITE`. Pages are provided when first touched. Returns the address the
    /// region has in that process.
    16 => fn vm_map_in(process: Handle, region: Handle);
}

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

    // ---- waiting ------------------------------------------------------------------------
    //
    // A timeout is nanoseconds of the kernel's monotonic clock. Zero answers at once without
    // waiting, with `ShouldWait` if nothing is ready, and `u64::MAX` waits for as long as it
    // takes. A wait that runs out is `TimedOut` and leaves the object as it found it: nothing
    // is half-received. A wait ends early with `PeerClosed` when another thread ends the
    // process, so that the waiting thread can end too.

    /// Send `len` bytes at `bytes` on `channel` (`WRITE`), moving the `count` handles described
    /// at `handles` out of the caller's table with the message. Each is eight bytes: the handle
    /// as a little-endian `u32`, then a `u32` mask of the rights the receiver may keep. Rights
    /// only narrow. All or nothing: on any error every handle is still the caller's. At most two
    /// handles and 64 bytes. Wakes a thread waiting to receive.
    17 => fn channel_send(channel: Handle, bytes: UserPtr, len: usize, handles: UserPtr, count: usize);
    /// Receive the front message on `channel` (`READ`) into `cap` bytes at `buf`, install the
    /// handles it carries in the caller's table, and write their values at `handles` as
    /// little-endian `u32`s, with room for `hcap`. Waits up to `timeout_ns` for a message.
    /// Returns the message's length in the low 32 bits and its handle count in the high 32.
    18 => fn channel_recv(channel: Handle, buf: UserPtr, cap: usize, handles: UserPtr, hcap: usize, timeout_ns: u64);
    /// As `completion_poll`, waiting up to `timeout_ns` for a completion. A timer delivering to
    /// this queue ends the wait when it expires.
    19 => fn completion_wait(completion: Handle, out: UserPtr, timeout_ns: u64);
    /// Create an event: a latch one thread signals and another waits on. Returns a handle with
    /// every right.
    20 => fn event_create();
    /// Signal `event` (`SIGNAL`), waking a thread waiting on it. Signalling a signalled event
    /// changes nothing: an event records that something happened, not how often.
    21 => fn event_signal(event: Handle);
    /// Wait up to `timeout_ns` for `event` (`WAIT`) to be signalled, and consume the signal.
    22 => fn event_wait(event: Handle, timeout_ns: u64);
    /// Create a timer, disarmed, that delivers to `completion` (`WRITE`) under `key`. Returns a
    /// handle with every right.
    23 => fn timer_create(completion: Handle, key: u64);
    /// Arm `timer` (`WRITE`) to expire `delay_ns` from now and then, if `period_ns` is not
    /// zero, every `period_ns`. Each delivery's value is how many expirations it reports.
    /// Arming an armed timer replaces its schedule.
    24 => fn timer_set(timer: Handle, delay_ns: u64, period_ns: u64);
    /// Disarm `timer` (`WRITE`). Expirations already delivered stay delivered.
    25 => fn timer_cancel(timer: Handle);
    /// The kernel's monotonic clock, in nanoseconds.
    26 => fn clock_now();

    // ---- sockets ------------------------------------------------------------------------
    //
    // A socket is a handle to a TCP endpoint of the kernel's network stack. An address is one
    // word: the IPv4 address in bits 47..16, most significant byte first, and the port in bits
    // 15..0 (see `socket::address`). Timeouts are as above. Sending and receiving need the
    // socket connected; every call that waits looks at the network at least every few
    // milliseconds while it waits.

    /// Create a socket of `kind`, which must be `socket::STREAM`. It is neither bound nor
    /// connected. Returns a handle to it with every right.
    27 => fn socket_create(kind: u64);
    /// Give `socket` (`WRITE`) the local port in `address`, for `socket_listen`; the address
    /// part must be zero or this machine's. A socket that connects without being bound is given
    /// an ephemeral port.
    28 => fn socket_bind(socket: Handle, address: u64);
    /// Connect `socket` (`WRITE`) to `address`, waiting up to `timeout_ns` for the handshake.
    /// `PeerClosed` if the peer refused, `TimedOut` if it never answered.
    29 => fn socket_connect(socket: Handle, address: u64, timeout_ns: u64);
    /// Listen on `socket`'s bound port (`WRITE`). `backlog` is advisory; the stack's own bound
    /// applies.
    30 => fn socket_listen(socket: Handle, backlog: u64);
    /// Wait up to `timeout_ns` for a connection on the listening `socket` (`READ`). Returns a
    /// handle to the connected socket with every right.
    31 => fn socket_accept(socket: Handle, timeout_ns: u64);
    /// Queue up to `len` bytes at `bytes` for sending on `socket` (`WRITE`), waiting up to
    /// `timeout_ns` for room for at least one. At most 512 bytes a call. Returns how many were
    /// queued; delivery is the stack's to complete. `PeerClosed` once the connection is reset.
    32 => fn socket_send(socket: Handle, bytes: UserPtr, len: usize, timeout_ns: u64);
    /// Receive up to `cap` bytes into `buf` from `socket` (`READ`), waiting up to `timeout_ns`
    /// for at least one. At most 512 bytes a call. Returns how many; zero is the end of the
    /// stream, after the peer's orderly close.
    33 => fn socket_recv(socket: Handle, buf: UserPtr, cap: usize, timeout_ns: u64);
    /// Close `socket`'s sending half (`WRITE`): a FIN follows what is queued. Waits up to
    /// `timeout_ns` for the peer to acknowledge everything, FIN included. Receiving goes on.
    /// Closing the handle closes the connection in order too, without waiting.
    34 => fn socket_shutdown(socket: Handle, timeout_ns: u64);
}

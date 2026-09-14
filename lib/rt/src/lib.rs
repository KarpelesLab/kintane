//! The native runtime: the ABI with its sharp edges covered.
//!
//! `lib/abi` is the contract, and it is deliberately thin: every call is exactly one trap and
//! errors are values. That is right for a contract and wrong for a program, which would
//! otherwise spell out the same byte-packing every time. This crate is where that lives, so a
//! program says what it wants and the kernel's interface stays honest about what it does.
//!
//! # Waiting is the kernel's
//!
//! [`recv`], [`completion_wait`], [`Event::wait`] and [`Process::join`] block in the kernel:
//! the thread is off every run queue until what it waits for happens or its timeout passes.
//! This crate used to spell those as loops of a non-blocking call and a yield, which spent a
//! slice per attempt; the non-blocking forms remain as [`try_recv`] and [`try_completion`].
//! A timeout is nanoseconds; [`FOREVER`] waits for as long as it takes, and [`NO_WAIT`] not
//! at all.
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

/// A timeout that never runs out.
pub const FOREVER: u64 = u64::MAX;
/// A timeout of nothing: answer at once.
pub const NO_WAIT: u64 = 0;

/// A finished asynchronous operation: the key its requester chose, and what it produced.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Completion {
    pub key: u64,
    pub value: u64,
}

/// Give the CPU up once.
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

/// End this thread with `code`. The process goes on while it has other threads.
pub fn exit_thread(code: u64) -> ! {
    let _ = call::thread_exit(code);
    loop {
        yield_now();
    }
}

/// The kernel's monotonic clock, in nanoseconds.
pub fn now_ns() -> u64 {
    call::clock_now().unwrap_or(0)
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

/// Write `value` little-endian at `at` in `buf`, as far as `buf` reaches.
fn put_u32(buf: &mut [u8], at: usize, value: u32) {
    let mut i = 0;
    while i < 4 {
        if let Some(byte) = buf.get_mut(at + i) {
            *byte = (value >> (8 * i)) as u8;
        }
        i += 1;
    }
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

// ---- channels -----------------------------------------------------------------------------

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

/// Send `bytes` on `channel`, moving `handles` with it. Each handle arrives with at most the
/// rights in its mask, a set of bits as `kobject::Rights` numbers them. At most two handles.
pub fn send_handles(channel: Handle, bytes: &[u8], handles: &[(Handle, u32)]) -> Result<(), Error> {
    let mut raw = [0u8; 16];
    let mut i = 0;
    while i < handles.len() && i < 2 {
        if let Some(&(handle, mask)) = handles.get(i) {
            put_u32(&mut raw, 8 * i, handle.0);
            put_u32(&mut raw, 8 * i + 4, mask);
        }
        i += 1;
    }
    call::channel_send(
        channel,
        UserPtr(bytes.as_ptr() as u64),
        bytes.len(),
        UserPtr(raw.as_ptr() as u64),
        handles.len(),
    )
    .map(|_| ())
}

/// Receive into `buf` without waiting. `ShouldWait` means nothing has arrived.
pub fn try_recv(channel: Handle, buf: &mut [u8]) -> Result<usize, Error> {
    call::channel_read(channel, UserPtr(buf.as_mut_ptr() as u64), buf.len()).map(|n| n as usize)
}

/// Receive into `buf`, waiting until a message arrives or the peer closes.
pub fn recv(channel: Handle, buf: &mut [u8]) -> Result<usize, Error> {
    recv_timeout(channel, buf, FOREVER)
}

/// Receive into `buf`, waiting up to `timeout_ns`.
pub fn recv_timeout(channel: Handle, buf: &mut [u8], timeout_ns: u64) -> Result<usize, Error> {
    let packed = call::channel_recv(
        channel,
        UserPtr(buf.as_mut_ptr() as u64),
        buf.len(),
        UserPtr(0),
        0,
        timeout_ns,
    )?;
    Ok((packed & 0xffff_ffff) as usize)
}

/// What [`recv_with_handles`] delivered: bytes into the buffer, handles into the list.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Received {
    pub bytes: usize,
    pub handles: usize,
}

/// Receive into `buf` and `handles`, waiting up to `timeout_ns`. The handles are this
/// process's own values for what the sender moved.
pub fn recv_with_handles(
    channel: Handle,
    buf: &mut [u8],
    handles: &mut [Handle],
    timeout_ns: u64,
) -> Result<Received, Error> {
    let mut raw = [0u8; 8];
    let room = if handles.len() < 2 { handles.len() } else { 2 };
    let packed = call::channel_recv(
        channel,
        UserPtr(buf.as_mut_ptr() as u64),
        buf.len(),
        UserPtr(raw.as_mut_ptr() as u64),
        room,
        timeout_ns,
    )?;
    let count = (packed >> 32) as usize;
    let mut i = 0;
    while i < count {
        if let (Some(slot), Some(value)) = (handles.get_mut(i), u32_at(&raw, 4 * i)) {
            *slot = Handle(value);
        }
        i += 1;
    }
    Ok(Received {
        bytes: (packed & 0xffff_ffff) as usize,
        handles: count,
    })
}

// ---- completions ----------------------------------------------------------------------------

fn completion_from(out: &[u8; 16]) -> Result<Completion, Error> {
    let key = u64_at(out, 0).ok_or(Error::Fault)?;
    let value = u64_at(out, 8).ok_or(Error::Fault)?;
    Ok(Completion { key, value })
}

/// Take one completion without waiting. `ShouldWait` means the queue is empty.
pub fn try_completion(queue: Handle) -> Result<Completion, Error> {
    let mut out = [0u8; 16];
    call::completion_poll(queue, UserPtr(out.as_mut_ptr() as u64))?;
    completion_from(&out)
}

/// Wait for one completion.
pub fn completion_wait(queue: Handle) -> Result<Completion, Error> {
    completion_wait_timeout(queue, FOREVER)
}

/// Wait up to `timeout_ns` for one completion.
pub fn completion_wait_timeout(queue: Handle, timeout_ns: u64) -> Result<Completion, Error> {
    let mut out = [0u8; 16];
    call::completion_wait(queue, UserPtr(out.as_mut_ptr() as u64), timeout_ns)?;
    completion_from(&out)
}

/// Make a completion queue.
pub fn completion_queue() -> Result<Handle, Error> {
    call::completion_create().map(|h| Handle(h as u32))
}

// ---- events and timers ----------------------------------------------------------------------

/// A latch one thread signals and another waits on.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Event {
    pub handle: Handle,
}

impl Event {
    pub fn create() -> Result<Event, Error> {
        call::event_create().map(|h| Event {
            handle: Handle(h as u32),
        })
    }

    pub fn signal(&self) -> Result<(), Error> {
        call::event_signal(self.handle).map(|_| ())
    }

    /// Wait up to `timeout_ns` for a signal, and consume it.
    pub fn wait(&self, timeout_ns: u64) -> Result<(), Error> {
        call::event_wait(self.handle, timeout_ns).map(|_| ())
    }
}

/// A timer delivering to a completion queue.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Timer {
    pub handle: Handle,
}

impl Timer {
    /// A disarmed timer that will deliver to `queue` under `key`.
    pub fn create(queue: Handle, key: u64) -> Result<Timer, Error> {
        call::timer_create(queue, key).map(|h| Timer {
            handle: Handle(h as u32),
        })
    }

    /// Expire `delay_ns` from now, and every `period_ns` after if that is not zero.
    pub fn set(&self, delay_ns: u64, period_ns: u64) -> Result<(), Error> {
        call::timer_set(self.handle, delay_ns, period_ns).map(|_| ())
    }

    pub fn cancel(&self) -> Result<(), Error> {
        call::timer_cancel(self.handle).map(|_| ())
    }
}

// ---- processes --------------------------------------------------------------------------------

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

    /// Start a thread at `entry`, an address in this process, with `arg`. The thread gets a
    /// stack of its own.
    pub fn start_at(&self, entry: u64, arg: u64) -> Result<Handle, Error> {
        call::thread_create(self.handle, entry, arg).map(|h| Handle(h as u32))
    }

    /// Ask for this process's exit to be posted to `queue` under `key`.
    pub fn wait_on(&self, queue: Handle, key: u64) -> Result<(), Error> {
        call::process_wait(self.handle, queue, key).map(|_| ())
    }

    /// Wait for this process to end and return its exit code. Completions under other keys
    /// are consumed and ignored.
    pub fn join(&self, queue: Handle, key: u64) -> Result<u64, Error> {
        loop {
            let c = completion_wait(queue)?;
            if c.key == key {
                return Ok(c.value);
            }
        }
    }
}

// ---- sockets ------------------------------------------------------------------------------

/// A TCP connection: a socket handle, connected.
pub struct TcpStream {
    handle: Handle,
}

/// A socket listening for connections.
pub struct TcpListener {
    handle: Handle,
}

/// A new stream socket, closed again if `then` fails, so a failed setup leaks no handle.
fn socket_then(then: impl FnOnce(Handle) -> Result<(), Error>) -> Result<Handle, Error> {
    let handle = Handle(call::socket_create(abi::socket::STREAM)? as u32);
    match then(handle) {
        Ok(()) => Ok(handle),
        Err(e) => {
            let _ = call::handle_close(handle);
            Err(e)
        }
    }
}

impl TcpStream {
    /// Connect to `ip`:`port`, waiting up to `timeout_ns` for the handshake.
    pub fn connect(ip: [u8; 4], port: u16, timeout_ns: u64) -> Result<TcpStream, Error> {
        let address = abi::socket::address(ip, port);
        socket_then(|h| call::socket_connect(h, address, timeout_ns).map(|_| ()))
            .map(|handle| TcpStream { handle })
    }

    pub fn handle(&self) -> Handle {
        self.handle
    }

    /// Queue what fits of `bytes`, waiting up to `timeout_ns` for room. Returns how much.
    pub fn send(&self, bytes: &[u8], timeout_ns: u64) -> Result<usize, Error> {
        call::socket_send(self.handle, UserPtr(bytes.as_ptr() as u64), bytes.len(), timeout_ns)
            .map(|n| n as usize)
    }

    /// Queue all of `bytes`, each piece waiting up to `timeout_ns` for room.
    pub fn send_all(&self, bytes: &[u8], timeout_ns: u64) -> Result<(), Error> {
        let mut sent = 0;
        // `get` rather than a range slice: see the note on slice indexing above.
        while let Some(rest) = bytes.get(sent..) {
            if rest.is_empty() {
                break;
            }
            sent += self.send(rest, timeout_ns)?;
        }
        Ok(())
    }

    /// Receive into `buf`, waiting up to `timeout_ns` for something. Zero is the end of the
    /// stream.
    pub fn recv(&self, buf: &mut [u8], timeout_ns: u64) -> Result<usize, Error> {
        call::socket_recv(self.handle, UserPtr(buf.as_mut_ptr() as u64), buf.len(), timeout_ns)
            .map(|n| n as usize)
    }

    /// Close the sending half, waiting up to `timeout_ns` for the peer to acknowledge it.
    pub fn shutdown(&self, timeout_ns: u64) -> Result<(), Error> {
        call::socket_shutdown(self.handle, timeout_ns).map(|_| ())
    }

    /// Let go of the connection. The kernel closes it in order, without the caller waiting.
    pub fn close(self) -> Result<(), Error> {
        call::handle_close(self.handle).map(|_| ())
    }
}

impl TcpListener {
    /// Listen on `port`.
    pub fn bind(port: u16) -> Result<TcpListener, Error> {
        socket_then(|h| {
            call::socket_bind(h, abi::socket::address([0; 4], port))?;
            call::socket_listen(h, 0).map(|_| ())
        })
        .map(|handle| TcpListener { handle })
    }

    /// Wait up to `timeout_ns` for a connection.
    pub fn accept(&self, timeout_ns: u64) -> Result<TcpStream, Error> {
        call::socket_accept(self.handle, timeout_ns).map(|h| TcpStream {
            handle: Handle(h as u32),
        })
    }

    pub fn close(self) -> Result<(), Error> {
        call::handle_close(self.handle).map(|_| ())
    }
}

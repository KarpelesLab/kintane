//! Linux's socket calls, answered on the kernel's socket objects (`crate::sockets`).
//!
//! # The descriptor
//!
//! A socket descriptor names an entry of [`TABLE`]: one socket object in the object store, and
//! how many descriptors in every process name it, counted as a pipe's ends are. A `fork`'s copy
//! adds one; `close`, `execve`'s close-on-exec and a process's end take one away. The last one
//! retires the object, and the store's destroy closes its connection in order
//! (`sockets::release`), as closing a native socket's last handle does.
//!
//! # Waiting
//!
//! A call that has to wait — `connect` for the handshake, `accept` for a connection, `recv` for
//! bytes, `send` for room — waits on the socket calls' queue, which the card's interrupt handler
//! wakes once it has run the stack over what arrived, and looks again at the stack's next TCP
//! timer (`sockets::next_look`). `O_NONBLOCK` on the descriptor, or `MSG_DONTWAIT` on the call,
//! makes it fail with `EAGAIN` instead. A non-blocking `connect` starts the handshake and fails
//! with `EINPROGRESS`; called again it fails with `EALREADY` until the connection is established
//! and `EISCONN` after, and `getsockopt(SO_ERROR)` reports why one failed.
//!
//! A wait ends when the process does. Signals will end one too, with `EINTR`; [`interrupted`] is
//! where they plug in.
//!
//! # What there is, and what is refused
//!
//! IPv4 TCP byte streams: `socket(AF_INET, SOCK_STREAM)` with `SOCK_NONBLOCK` and `SOCK_CLOEXEC`,
//! `bind` to a port of this machine's, `listen`, `accept` and `accept4`, `connect`, `send`,
//! `sendto` and `write`, `recv`, `recvfrom` and `read`, `shutdown` of the sending half,
//! `getsockname`, `getpeername`, and the options a simple client sets: `SO_REUSEADDR`,
//! `SO_KEEPALIVE` and `TCP_NODELAY` are accepted and change nothing — the stack reuses a port
//! as soon as nothing holds it, sends no keepalives, and never delays a segment — and
//! `getsockopt` answers `SO_TYPE`, `SO_ERROR` and `TCP_NODELAY`. Refused, with Linux's errors:
//! other families (`EAFNOSUPPORT`), datagram and raw sockets (`EPROTONOSUPPORT`), other options
//! (`ENOPROTOOPT`), `MSG_PEEK` and the other message flags, and shutting down the receiving half
//! (`EOPNOTSUPP`), and binding port zero (`EINVAL`: bind a port, or connect without binding).
//! There is no `SIGPIPE`: a send after the connection closed fails with `EPIPE`, and that is all.

use core::cell::SyncUnsafeCell;

use arch::Cpu;
use elf::Program;
use hal::EarlyConsole;
use kobject::ObjectId;
use linux::Failure;
use linux::socket::{
    AF_INET, IPPROTO_TCP, MSG_DONTWAIT, MSG_NOSIGNAL, SHUT_RD, SHUT_RDWR, SHUT_WR, SO_ERROR,
    SO_KEEPALIVE, SO_REUSEADDR, SO_TYPE, SOCK_CLOEXEC, SOCK_NONBLOCK, SOCK_STREAM, SOCK_TYPE_MASK,
    SOCKADDR_IN_LEN, SOL_SOCKET, TCP_NODELAY,
};
use sync::SpinLock;
use sync::lockdep::LockClass;
use time::{Duration, Instant};

use super::{Descriptor, MAX_IO, descriptor_of, from_user, locked, to_user};
use crate::objects::{self, Object};
use crate::sockets::CHUNK;
use crate::userproc::MAX_PROCS;
use crate::{Check, preempt, spawn, timekeeping, userproc, write_hex, write_usize};

/// Sockets Linux processes can hold at once, however many descriptors name each.
const SOCKETS: usize = 8;

#[derive(Clone, Copy)]
struct Entry {
    /// The socket object, or `None` for a free entry.
    id: Option<ObjectId>,
    /// Descriptors naming it, in every process.
    refs: u32,
}

static TABLE_CLASS: LockClass = LockClass::new("linux.sockets");
/// Every Linux socket. Held only to look at or change an entry: never while waiting, and
/// nothing is taken inside it.
static TABLE: SpinLock<[Entry; SOCKETS], Cpu> =
    SpinLock::with_class([Entry { id: None, refs: 0 }; SOCKETS], &TABLE_CLASS);

/// Give the new socket object `id` an entry with one descriptor's count. Retires the object if
/// no entry is free.
fn adopt(id: ObjectId) -> Result<usize, Failure> {
    let free = {
        let mut table = TABLE.lock_irqsave();
        let free = table.iter().position(|e| e.id.is_none());
        if let Some(i) = free {
            table[i] = Entry {
                id: Some(id),
                refs: 1,
            };
        }
        free
    };
    free.ok_or_else(|| {
        objects::retire(id);
        Failure::TooManyOpen
    })
}

/// One more descriptor names socket `i`: a `fork`'s copy.
pub(super) fn add_ref(i: usize) {
    if let Some(e) = TABLE.lock_irqsave().get_mut(i) {
        e.refs += 1;
    }
}

/// A descriptor naming socket `i` is gone. The last one retires the object, which closes its
/// connection once nothing else is using it.
pub(super) fn drop_ref(i: usize) {
    let gone = TABLE.lock_irqsave().get_mut(i).and_then(|e| {
        e.refs = e.refs.saturating_sub(1);
        if e.refs == 0 { e.id.take() } else { None }
    });
    if let Some(id) = gone {
        objects::retire(id);
    }
}

fn id_of(i: usize) -> Result<ObjectId, Failure> {
    TABLE
        .lock_irqsave()
        .get(i)
        .and_then(|e| e.id)
        .ok_or(Failure::BadDescriptor)
}

/// The socket descriptor `fd` names, and whether calls on it never block.
fn socket_of(slot: usize, fd: u64) -> Result<(usize, bool), Failure> {
    match descriptor_of(slot, fd)? {
        (Descriptor::Socket(i), nonblock) => Ok((i, nonblock)),
        _ => Err(Failure::NotASocket),
    }
}

/// Why a blocking socket call must stop waiting, other than its process ending: a signal with
/// a handler to run, which ends the wait with `EINTR` the way it ends a pipe read's.
fn interrupted(slot: usize) -> Option<Failure> {
    super::signals::interrupting(slot).then(|| {
        super::signals::blocked_call_interrupted();
        Failure::Interrupted
    })
}

/// Run `attempt` until it has an answer, waiting on the network between tries; see the module
/// documentation. With `nonblock`, one try, and `EAGAIN` for no answer.
fn wait<R>(
    slot: usize,
    nonblock: bool,
    mut attempt: impl FnMut() -> Result<Option<R>, Failure>,
) -> Result<R, Failure> {
    if let Some(r) = attempt()? {
        return Ok(r);
    }
    if nonblock {
        return Err(Failure::TryAgain);
    }
    let queue = crate::sockets::waits();
    loop {
        let due = crate::sockets::next_look().map(Instant::from_nanos);
        let got = queue.wait_once(due, || {
            if userproc::exiting(slot) {
                return Some(Err(Failure::Io));
            }
            if let Some(why) = interrupted(slot) {
                return Some(Err(why));
            }
            attempt().transpose()
        });
        if let Some(result) = got {
            return result;
        }
        // Before the scheduler runs nothing moves the network, and a wait cannot block.
        if !preempt::scheduled() {
            return Err(Failure::TryAgain);
        }
    }
}

/// The failure a native socket error is, for most calls. `connect` and `send` read two of them
/// their own way.
fn failure(e: abi::Error) -> Failure {
    use abi::Error as E;
    match e {
        E::ShouldWait => Failure::TryAgain,
        E::TimedOut => Failure::TimedOut,
        E::PeerClosed => Failure::ConnectionReset,
        E::Full => Failure::AddressInUse,
        E::InvalidArgument => Failure::InvalidArgument,
        E::BadHandle | E::WrongType => Failure::BadDescriptor,
        E::Unsupported => Failure::NetworkDown,
        _ => Failure::Io,
    }
}

/// A connection's failure as `connect` and `SO_ERROR` report it: one that never opened was
/// refused.
fn connect_failure(e: abi::Error) -> Failure {
    match e {
        abi::Error::PeerClosed => Failure::ConnectionRefused,
        e => failure(e),
    }
}

/// The `struct sockaddr_in` of `len` bytes at user address `at`.
fn read_sockaddr(at: u64, len: u64) -> Result<([u8; 4], u16), Failure> {
    if len < SOCKADDR_IN_LEN as u64 {
        return Err(Failure::InvalidArgument);
    }
    let mut bytes = [0u8; SOCKADDR_IN_LEN];
    from_user(at, &mut bytes)?;
    linux::socket::parse_sockaddr_in(&bytes)
}

/// Write `ip`:`port` to user address `at` as a `struct sockaddr_in`, cut to the length the `u32`
/// at `len_at` allows, and the whole length back there.
fn write_sockaddr(at: u64, len_at: u64, ip: [u8; 4], port: u16) -> Result<(), Failure> {
    let mut len = [0u8; 4];
    from_user(len_at, &mut len)?;
    let room = (u32::from_le_bytes(len) as usize).min(SOCKADDR_IN_LEN);
    let address = linux::socket::sockaddr_in(ip, port);
    if room > 0 {
        to_user(at, &address[..room])?;
    }
    to_user(len_at, &(SOCKADDR_IN_LEN as u32).to_le_bytes())
}

/// What socket `i` is ready for, as `poll` events, taking nothing: a listener with a
/// connection to accept is readable, as are queued bytes and the peer's close; room in the send
/// ring is writable. A socket whose object is gone reports an error rather than waiting.
pub(super) fn ready(i: usize) -> u16 {
    use abi::ready;
    use linux::poll;
    let Ok(id) = id_of(i) else {
        return poll::POLLNVAL;
    };
    if let Ok((listener, _)) = crate::sockets::listener(id) {
        return if crate::sockets::pending(listener) {
            poll::POLLIN
        } else {
            0
        };
    }
    let Ok(conn) = crate::sockets::connection(id) else {
        // Made but neither connected nor listening: nothing changes until the program acts.
        return 0;
    };
    let bits = crate::sockets::readiness(conn);
    let mut events = 0;
    if bits & ready::READ != 0 {
        events |= poll::POLLIN;
    }
    if bits & ready::WRITE != 0 {
        events |= poll::POLLOUT;
    }
    if bits & ready::CLOSED != 0 {
        events |= poll::POLLRDHUP;
    }
    if bits & ready::ERROR != 0 {
        events |= poll::POLLERR;
    }
    events
}

pub(super) fn socket(slot: usize, domain: u64, kind: u64, protocol: u64) -> Result<u64, Failure> {
    if domain != AF_INET {
        return Err(Failure::AddressFamilyNotSupported);
    }
    let flags = kind & !SOCK_TYPE_MASK;
    if flags & !(SOCK_NONBLOCK | SOCK_CLOEXEC) != 0 {
        return Err(Failure::InvalidArgument);
    }
    if kind & SOCK_TYPE_MASK != SOCK_STREAM || !(protocol == 0 || protocol == IPPROTO_TCP) {
        return Err(Failure::ProtocolNotSupported);
    }
    if !crate::sockets::available() {
        return Err(Failure::NetworkDown);
    }
    let socket = Object::Socket {
        port: 0,
        conn: None,
        listening: false,
    };
    let id = objects::create(socket).ok_or(Failure::TooManyOpen)?;
    let i = adopt(id)?;
    let placed = locked(slot, |_, s| s.place(Descriptor::Socket(i), flags));
    if placed.is_err() {
        drop_ref(i);
    }
    placed.map(|fd| fd as u64)
}

pub(super) fn connect(slot: usize, fd: u64, addr: u64, len: u64) -> Result<u64, Failure> {
    let (i, nonblock) = socket_of(slot, fd)?;
    let (ip, port) = read_sockaddr(addr, len)?;
    let id = id_of(i)?;
    let earlier = crate::sockets::connection(id).ok();
    let conn = match earlier {
        Some(conn) => conn,
        None => {
            crate::sockets::connect(id, abi::socket::address(ip, port)).map_err(connect_failure)?
        }
    };
    let done = crate::sockets::connected(conn).map_err(connect_failure)?;
    match (earlier, done) {
        (Some(_), Some(_)) => return Err(Failure::AlreadyConnected),
        (Some(_), None) if nonblock => return Err(Failure::Already),
        (None, None) if nonblock => return Err(Failure::InProgress),
        (_, Some(_)) => return Ok(0),
        (_, None) => {}
    }
    wait(slot, false, || crate::sockets::connected(conn).map_err(connect_failure)).map(|_| 0)
}

pub(super) fn bind(slot: usize, fd: u64, addr: u64, len: u64) -> Result<u64, Failure> {
    let (i, _) = socket_of(slot, fd)?;
    let (ip, port) = read_sockaddr(addr, len)?;
    if ip != [0; 4] && ip != crate::net::CONFIG.ip {
        return Err(Failure::AddressNotAvailable);
    }
    crate::sockets::bind(id_of(i)?, abi::socket::address(ip, port)).map_err(failure)
}

pub(super) fn listen(slot: usize, fd: u64, _backlog: u64) -> Result<u64, Failure> {
    let (i, _) = socket_of(slot, fd)?;
    crate::sockets::listen(id_of(i)?).map_err(failure)
}

pub(super) fn accept4(
    slot: usize,
    fd: u64,
    addr: u64,
    len_at: u64,
    flags: u64,
) -> Result<u64, Failure> {
    let (i, nonblock) = socket_of(slot, fd)?;
    if flags & !(SOCK_NONBLOCK | SOCK_CLOEXEC) != 0 {
        return Err(Failure::InvalidArgument);
    }
    let (listener, port) =
        crate::sockets::listener(id_of(i)?).map_err(|_| Failure::InvalidArgument)?;
    // Checked first, so the connection taken below is never lost to a bad address.
    if addr != 0 {
        write_sockaddr(addr, len_at, [0; 4], 0)?;
    }
    let accepted =
        wait(slot, nonblock, || crate::sockets::accept(listener, port).map_err(failure))?;
    let j = adopt(accepted)?;
    let placed = match locked(slot, |_, s| s.place(Descriptor::Socket(j), flags)) {
        Ok(fd) => fd,
        Err(e) => {
            drop_ref(j);
            return Err(e);
        }
    };
    if addr != 0
        && let Ok((_, Some((ip, peer)))) = crate::sockets::endpoints(accepted)
    {
        write_sockaddr(addr, len_at, ip, peer)?;
    }
    Ok(placed as u64)
}

/// Send what fits of `count` bytes at `buf` on socket `i`: all of it, waiting for room, unless
/// `nonblock`, when as much as there is room for, or `EAGAIN` for none.
pub(super) fn send(
    slot: usize,
    i: usize,
    nonblock: bool,
    buf: u64,
    count: usize,
) -> Result<u64, Failure> {
    let conn = crate::sockets::connection(id_of(i)?).map_err(|_| Failure::NotConnected)?;
    let count = count.min(MAX_IO);
    let mut done = 0;
    while done < count {
        let n = (count - done).min(CHUNK);
        let mut chunk = [0u8; CHUNK];
        from_user(buf.checked_add(done as u64).ok_or(Failure::Fault)?, &mut chunk[..n])?;
        let sent = wait(slot, nonblock, || {
            crate::sockets::send(conn, &chunk[..n]).map_err(|e| match e {
                // Closed for sending: this end shut down or closed, or the connection ended.
                abi::Error::InvalidArgument => Failure::BrokenPipe,
                e => failure(e),
            })
        });
        match sent {
            Ok(k) => done += k as usize,
            // Linux's rule: what was sent is the answer, and the error waits for the next call.
            Err(e) if done == 0 => return Err(e),
            Err(_) => break,
        }
    }
    Ok(done as u64)
}

/// Receive what has arrived on socket `i`, up to `count` bytes, into `buf`: waiting for some,
/// unless `nonblock`. Zero at the end of the stream.
pub(super) fn recv(
    slot: usize,
    i: usize,
    nonblock: bool,
    buf: u64,
    count: usize,
) -> Result<u64, Failure> {
    let conn = crate::sockets::connection(id_of(i)?).map_err(|_| Failure::NotConnected)?;
    let n = count.min(CHUNK);
    if n == 0 {
        return Ok(0);
    }
    // Written first, so its pages are present: bytes taken from the connection and then
    // refused their copy would be lost.
    to_user(buf, &[0u8; CHUNK][..n])?;
    let mut bytes = [0u8; CHUNK];
    let got =
        wait(slot, nonblock, || crate::sockets::recv(conn, &mut bytes[..n]).map_err(failure))?;
    to_user(buf, &bytes[..got])?;
    Ok(got as u64)
}

pub(super) fn sendto(
    slot: usize,
    fd: u64,
    buf: u64,
    count: u64,
    flags: u64,
) -> Result<u64, Failure> {
    let (i, nonblock) = socket_of(slot, fd)?;
    if flags & !(MSG_DONTWAIT | MSG_NOSIGNAL) != 0 {
        return Err(Failure::OperationNotSupported);
    }
    // The address, if any, is ignored, as Linux ignores it on a connected stream.
    let count = usize::try_from(count).unwrap_or(MAX_IO);
    send(slot, i, nonblock || flags & MSG_DONTWAIT != 0, buf, count)
}

pub(super) fn recvfrom(
    slot: usize,
    fd: u64,
    buf: u64,
    count: u64,
    flags: u64,
    len_at: u64,
) -> Result<u64, Failure> {
    let (i, nonblock) = socket_of(slot, fd)?;
    if flags & !MSG_DONTWAIT != 0 {
        return Err(Failure::OperationNotSupported);
    }
    let count = usize::try_from(count).unwrap_or(MAX_IO);
    let got = recv(slot, i, nonblock || flags & MSG_DONTWAIT != 0, buf, count)?;
    // A stream names no sender: Linux reports an address of no bytes.
    if len_at != 0 {
        to_user(len_at, &0u32.to_le_bytes())?;
    }
    Ok(got)
}

pub(super) fn shutdown(slot: usize, fd: u64, how: u64) -> Result<u64, Failure> {
    let (i, _) = socket_of(slot, fd)?;
    match how {
        SHUT_WR | SHUT_RDWR => {}
        SHUT_RD => return Err(Failure::OperationNotSupported),
        _ => return Err(Failure::InvalidArgument),
    }
    let conn = crate::sockets::connection(id_of(i)?).map_err(|_| Failure::NotConnected)?;
    crate::sockets::shutdown(conn).map_err(failure)?;
    Ok(0)
}

/// `getsockname`, or with `peer` `getpeername`.
pub(super) fn name(
    slot: usize,
    fd: u64,
    addr: u64,
    len_at: u64,
    peer: bool,
) -> Result<u64, Failure> {
    let (i, _) = socket_of(slot, fd)?;
    let (local, remote) = crate::sockets::endpoints(id_of(i)?).map_err(failure)?;
    let (ip, port) = match (peer, remote) {
        (true, Some(remote)) => remote,
        (true, None) => return Err(Failure::NotConnected),
        // Connected, it is this machine's address; bound or listening, any of them.
        (false, Some(_)) => (crate::net::CONFIG.ip, local),
        (false, None) => ([0; 4], local),
    };
    write_sockaddr(addr, len_at, ip, port)?;
    Ok(0)
}

pub(super) fn setsockopt(
    slot: usize,
    fd: u64,
    level: u64,
    option: u64,
    value: u64,
    len: u64,
) -> Result<u64, Failure> {
    socket_of(slot, fd)?;
    match (level, option) {
        (SOL_SOCKET, SO_REUSEADDR | SO_KEEPALIVE) | (IPPROTO_TCP, TCP_NODELAY) => {}
        _ => return Err(Failure::NoProtocolOption),
    }
    if len < 4 {
        return Err(Failure::InvalidArgument);
    }
    // Read, so an unreadable value is `EFAULT` as it would be on Linux; see the module
    // documentation for why it changes nothing.
    let mut v = [0u8; 4];
    from_user(value, &mut v)?;
    Ok(0)
}

pub(super) fn getsockopt(
    slot: usize,
    fd: u64,
    level: u64,
    option: u64,
    value: u64,
    len_at: u64,
) -> Result<u64, Failure> {
    let (i, _) = socket_of(slot, fd)?;
    let answer: i32 = match (level, option) {
        (SOL_SOCKET, SO_TYPE) => SOCK_STREAM as i32,
        // Never delayed: the stack sends each segment when it can.
        (IPPROTO_TCP, TCP_NODELAY) => 1,
        (SOL_SOCKET, SO_ERROR) => match crate::sockets::connection(id_of(i)?) {
            Ok(conn) => match crate::sockets::connected(conn) {
                Err(e) => linux::errno(connect_failure(e)) as i32,
                Ok(_) => 0,
            },
            Err(_) => 0,
        },
        _ => return Err(Failure::NoProtocolOption),
    };
    let mut len = [0u8; 4];
    from_user(len_at, &mut len)?;
    let room = (u32::from_le_bytes(len) as usize).min(4);
    to_user(value, &answer.to_le_bytes()[..room])?;
    to_user(len_at, &(room as u32).to_le_bytes())?;
    Ok(0)
}

// ---- the check ----------------------------------------------------------------------------

/// The exit codes of the program's `tcp` and `serve` modes when every step behaved; mirror
/// `TCP_SUCCESS` and `SERVE_SUCCESS` in `user/linux-hello/src/main.rs`.
const TCP_SUCCESS: u64 = 48;
const SERVE_SUCCESS: u64 = 49;
/// The port `serve` listens on, which kbuild forwards a loopback port to: `INBOUND_PORT` in
/// the program and `NET_GUEST_TCP_PORT` in `kbuild/src/qemu.rs`.
const INBOUND_PORT: u16 = 7777;
/// What tells kbuild the listener is up, to kbuild's datagram peer: `NET_TCP_LISTENING` in
/// `kbuild/src/qemu.rs`, then a number kbuild connects in once for. The number is this boot's
/// ([`listening_message`]), so a repeat of the datagram is not a second request, and a machine
/// that restarts under the same kbuild, as the boot counter test's does, is served again.
const LISTENING: &[u8] = b"kintane-tcp-listening ";
/// How often it is repeated while the listener is up, in case one is lost.
const ANNOUNCE_EVERY: Duration = Duration::from_nanos(500_000_000);
/// How long the connections the program let go of get to finish closing.
const SETTLE: Duration = Duration::from_nanos(10_000_000_000);

const SERVE_ARGV: [&[u8]; 2] = [b"hello", b"serve"];
const POLL_ARGV: [&[u8]; 2] = [b"hello", b"poll"];

/// What the program's `poll` mode exits with when every step behaved; mirrors `POLL_SUCCESS`
/// in `user/linux-hello/src/main.rs`.
const POLL_SUCCESS: u64 = 51;

/// How long into the poll run the second listener number is announced, so kbuild makes its
/// two connections one after the other rather than at once.
const SECOND_CONNECTION_AFTER: Duration = Duration::from_nanos(1_000_000_000);

/// kbuild's TCP port in decimal, and the `tcp` mode's `argv` naming it.
///
/// SAFETY INVARIANT: written only by [`check`], before the process that reads them is built,
/// and never while a Linux process runs.
static PORT_DIGITS: SyncUnsafeCell<[u8; 5]> = SyncUnsafeCell::new([0; 5]);
static TCP_ARGV: SyncUnsafeCell<[&[u8]; 3]> = SyncUnsafeCell::new([b"hello", b"tcp", b""]);

/// [`LISTENING`] and this boot's number into `buf`: the scheduler clock's nanoseconds when the
/// check runs, which two boots of one machine do not share, cut to the sixteen digits kbuild
/// takes. Its length.
fn listening_message(buf: &mut [u8; 40]) -> usize {
    let mut digits = [0u8; 16];
    let mut first = digits.len();
    let mut v = timekeeping::now().as_nanos() % 10_000_000_000_000_000;
    loop {
        first -= 1;
        if let Some(d) = digits.get_mut(first) {
            *d = b'0' + (v % 10) as u8;
        }
        v /= 10;
        if v == 0 || first == 0 {
            break;
        }
    }
    let mut n = 0;
    for (to, &from) in buf
        .iter_mut()
        .zip(LISTENING.iter().chain(digits.get(first..).unwrap_or(&[])))
    {
        *to = from;
        n += 1;
    }
    n
}

/// Whether every entry of the table is free: what a moment with no Linux socket open shows.
fn table_empty() -> bool {
    TABLE.lock_irqsave().iter().all(|e| e.id.is_none())
}

/// Run the kept program in its socket modes with the scheduler, and grade them: a client of
/// kbuild's TCP service, and a server kbuild connects to once the check tells it the listener is
/// up. On the boot thread.
pub(super) fn check(c: &dyn EarlyConsole) -> Check {
    c.write_str("\n  linux net  ");
    let Some(program) = super::kept_program() else {
        c.write_str("skipped: the linux check kept no program");
        return Check::Skipped;
    };
    if !crate::sockets::available() {
        if kconfig::QEMU_NET_TEST {
            c.write_str("NO STARTED NETWORK CARD, though the run attached one");
            return Check::Failed;
        }
        c.write_str("skipped: no network card");
        return Check::Skipped;
    }
    let (Some(port), Some(peer)) = (crate::net::tcp_port(), crate::net::peer()) else {
        c.write_str("KBUILD'S PORTS WERE NEVER LEARNED by the net check");
        return Check::Failed;
    };
    if userproc::with_frames(|f| f.alloc.stats().free).is_none() {
        c.write_str("skipped: no frames for processes");
        return Check::Skipped;
    }
    let interrupt = crate::net::serve_by_interrupt();
    spawn::use_stacks(&super::STACKS);
    let frames_before = super::free_frames();
    let objects_before = objects::live();
    let wakes_before = crate::sockets::wakes();

    // SAFETY: see `PORT_DIGITS`: no Linux process runs, and none is built yet.
    let argv: &'static [&'static [u8]] = unsafe {
        let digits: &'static mut [u8; 5] = &mut *PORT_DIGITS.get();
        let mut n = 0;
        for d in [10_000u16, 1_000, 100, 10, 1] {
            if (port >= d || d == 1)
                && let Some(digit) = digits.get_mut(n)
            {
                *digit = b'0' + ((port / d) % 10) as u8;
                n += 1;
            }
        }
        let written: &'static [u8] = &*PORT_DIGITS.get();
        let argv = &mut *TCP_ARGV.get();
        argv[2] = written.get(..n).unwrap_or(b"");
        &*TCP_ARGV.get()
    };
    let client = run_mode(&program, argv, || {});

    let mut message = [0u8; 40];
    let message_len = listening_message(&mut message);
    let message = message.get(..message_len).unwrap_or(LISTENING);
    let mut last: Option<Instant> = None;
    let mut told = 0u32;
    let server = run_mode(&program, &SERVE_ARGV, || {
        let now = timekeeping::now();
        if last.is_some_and(|t| now < t.saturating_add(ANNOUNCE_EVERY))
            || !crate::sockets::listening_on(INBOUND_PORT)
        {
            return;
        }
        last = Some(now);
        let sent = crate::net::with_stack(|s, card, t| {
            s.udp_send(card, peer.0, crate::net::PORT, peer.1, message, t)
                .is_ok()
        });
        if sent == Some(true) {
            told += 1;
        }
    });

    // The same listener, announced under two numbers: kbuild connects once per number it has
    // not seen, so the program's `poll` mode has two connections to serve and a listener to
    // watch at the same time.
    let mut first = [0u8; 40];
    let first_len = listening_message(&mut first);
    let first = first.get(..first_len).unwrap_or(LISTENING);
    let mut second = [0u8; 40];
    let second_len = listening_message(&mut second);
    let second = second.get(..second_len).unwrap_or(LISTENING);
    let started_at = timekeeping::now();
    let mut last_poll: Option<Instant> = None;
    let mut poll_told = 0u32;
    let polled = run_mode(&program, &POLL_ARGV, || {
        let now = timekeeping::now();
        if last_poll.is_some_and(|t| now < t.saturating_add(ANNOUNCE_EVERY))
            || !crate::sockets::listening_on(INBOUND_PORT)
        {
            return;
        }
        last_poll = Some(now);
        let mut announce = |message: &[u8]| {
            let sent = crate::net::with_stack(|s, card, t| {
                s.udp_send(card, peer.0, crate::net::PORT, peer.1, message, t)
                    .is_ok()
            });
            if sent == Some(true) {
                poll_told += 1;
            }
        };
        announce(first);
        if now >= started_at.saturating_add(SECOND_CONNECTION_AFTER) && first != second {
            announce(second);
        }
    });

    let give_up = timekeeping::now().saturating_add(SETTLE);
    let settled = loop {
        let quiet = crate::net::with_stack(|s, _, _| s.tcp_rings_held() == 0 && s.balanced());
        if quiet == Some(true) {
            break true;
        }
        if timekeeping::now() >= give_up {
            break false;
        }
        preempt::sleep_until(timekeeping::now().saturating_add(super::POLL));
    };
    let w = crate::sockets::wakes();
    let (woken, timers, polls) = (
        w.woken - wakes_before.woken,
        w.timers - wakes_before.timers,
        w.polls - wakes_before.polls,
    );
    let frames = frames_before.saturating_sub(super::free_frames());
    let leaked = objects::live().saturating_sub(objects_before);
    let emptied = table_empty() && super::poll::table_empty();

    report(c, "tcp client", client, TCP_SUCCESS);
    c.write_str("; ");
    report(c, "server", server, SERVE_SUCCESS);
    c.write_str("; ");
    report(c, "poll", polled, POLL_SUCCESS);
    c.write_str(" (two connections, ");
    write_usize(c, poll_told as usize);
    c.write_str(" announcements)");
    c.write_str(" (kbuild told of its listener ");
    write_usize(c, told as usize);
    c.write_str(if told == 1 { " time)" } else { " times)" });
    c.write_str("; waits woken by the card ");
    write_usize(c, woken as usize);
    c.write_str(", armed for a TCP timer ");
    write_usize(c, timers as usize);
    c.write_str(", polled ");
    write_usize(c, polls as usize);
    let woken_ok = !interrupt || (woken > 0 && polls == 0);
    if !interrupt {
        c.write_str(" (no interrupt route for the card)");
    } else if !woken_ok {
        c.write_str(", NOT WOKEN BY THE CARD'S INTERRUPT");
    }
    c.write_str(if settled {
        "; closed in order, every buffer back"
    } else {
        "; A CONNECTION NEVER FINISHED CLOSING, OR A BUFFER IS MISSING"
    });
    if !emptied {
        c.write_str("; A LINUX SOCKET OR EPOLL SET WAS NEVER LET GO OF");
    }
    c.write_str("; ");
    write_usize(c, leaked);
    c.write_str(if leaked == 0 {
        " objects left"
    } else {
        " OBJECTS LEAKED"
    });
    c.write_str(", ");
    write_usize(c, frames);
    c.write_str(if frames == 0 {
        " frames left ok"
    } else {
        " FRAMES LEAKED"
    });
    Check::from_ok(
        client.code == Some(TCP_SUCCESS)
            && server.code == Some(SERVE_SUCCESS)
            && polled.code == Some(POLL_SUCCESS)
            && client.ended
            && server.ended
            && polled.ended
            && woken_ok
            && settled
            && emptied
            && leaked == 0
            && frames == 0,
    )
}

/// How one run of the program went.
#[derive(Clone, Copy)]
struct Run {
    started: bool,
    code: Option<u64>,
    /// Every thread ended, so its processes were torn down.
    ended: bool,
}

/// Start the kept program with `argv`, call `during` every poll while it runs, wait for it to
/// end, and tear its processes down.
fn run_mode(
    program: &Program<'static>,
    argv: &'static [&'static [u8]],
    mut during: impl FnMut(),
) -> Run {
    let started = userproc::start_linux(super::SLOT, program, super::start_with(argv));
    let give_up = timekeeping::now().saturating_add(super::PATIENCE);
    let running = || {
        started.is_some_and(preempt::alive)
            || (0..MAX_PROCS).any(|slot| userproc::threads_live(slot) != 0)
    };
    while running() && timekeeping::now() < give_up {
        during();
        preempt::sleep_until(timekeeping::now().saturating_add(super::POLL));
    }
    let code = if running() {
        None
    } else {
        userproc::slot(super::SLOT).and_then(|p| p.exit)
    };
    let ended = spawn::end_threads();
    if ended {
        for slot in 0..MAX_PROCS {
            userproc::teardown(slot);
        }
    }
    Run {
        started: started.is_some(),
        code,
        ended,
    }
}

fn report(c: &dyn EarlyConsole, mode: &str, run: Run, success: u64) {
    c.write_str(mode);
    match (run.started, run.code) {
        (false, _) => c.write_str(" NEVER STARTED"),
        (true, None) => c.write_str(" NEVER EXITED"),
        (true, Some(code)) if code == success => c.write_str(" ok"),
        (true, Some(code)) => {
            c.write_str(" exited ");
            write_hex(c, code);
            c.write_str(", WRONG");
        }
    }
    if !run.ended {
        c.write_str(", A THREAD NEVER ENDED");
    }
}

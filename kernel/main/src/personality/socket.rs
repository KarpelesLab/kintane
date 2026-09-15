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
//! IPv4, in byte streams and in datagrams.
//!
//! A datagram socket — `socket(AF_INET, SOCK_DGRAM)` — holds no connection: `bind` gives it the
//! port it receives on, `connect` names the one address it sends to and takes datagrams from
//! without a handshake, and a socket that has neither is given a port by its first send.
//! `sendto`, `send`, `write`, `sendmsg`, `recvfrom`, `recv`, `read` and `recvmsg` carry the
//! datagrams, one to a call. A receive answers the length that fit, or, with `MSG_TRUNC`, the
//! length the datagram had; either way the rest is gone, because a datagram is taken whole or
//! not at all. `listen`, `accept` and `shutdown` refuse one (`EOPNOTSUPP`), and a datagram past
//! what the stack keeps is `EMSGSIZE`. `SO_RCVTIMEO` and `SO_SNDTIMEO` bound a wait on either
//! kind, and a wait that runs out is `EAGAIN`.
//!
//! For streams: `socket(AF_INET, SOCK_STREAM)` with `SOCK_NONBLOCK` and `SOCK_CLOEXEC`,
//! `bind` to a port of this machine's, `listen`, `accept` and `accept4`, `connect`, `send`,
//! `sendto` and `write`, `recv`, `recvfrom` and `read`, `shutdown` of the sending half,
//! `getsockname`, `getpeername`, and the options a simple client sets: `SO_REUSEADDR`,
//! `SO_KEEPALIVE` and `TCP_NODELAY` are accepted and change nothing — the stack reuses a port
//! as soon as nothing holds it, sends no keepalives, and never delays a segment — and
//! `getsockopt` answers `SO_TYPE`, `SO_ERROR` and `TCP_NODELAY`. Refused, with Linux's errors:
//! other families (`EAFNOSUPPORT`), raw sockets (`EPROTONOSUPPORT`), other options
//! (`ENOPROTOOPT`), the message flags beyond `MSG_PEEK`, `MSG_TRUNC`, `MSG_WAITALL`,
//! `MSG_DONTWAIT` and `MSG_NOSIGNAL`, and shutting down the receiving half (`EOPNOTSUPP`), and
//! binding port zero (`EINVAL`: bind a port, or connect without binding).
//!
//! `MSG_PEEK` copies what has arrived and leaves it: the receive after a peek reads the same
//! bytes, or takes the same datagram, because neither the ring's head nor the inbox's slot
//! moves. `MSG_WAITALL` waits for the whole count on a stream and means nothing on a datagram,
//! which is taken whole or not at all. `sendmsg` and `recvmsg` carry up to four buffers: a
//! datagram is gathered into one message however many it was written from, and one receive is
//! spread over them in order. More buffers than that is `EOPNOTSUPP` rather than a half-carried
//! message.
//! There is no `SIGPIPE`: a send after the connection closed fails with `EPIPE`, and that is all.

use core::cell::SyncUnsafeCell;

use arch::Cpu;
use elf::Program;
use hal::EarlyConsole;
use kobject::ObjectId;
use linux::Failure;
use linux::socket::{
    AF_INET, IOVEC_LEN, IPPROTO_TCP, IPPROTO_UDP, MSG_DONTWAIT, MSG_NOSIGNAL, MSG_PEEK, MSG_TRUNC,
    MSG_WAITALL, MSGHDR_IOV, MSGHDR_IOVLEN, MSGHDR_LEN, MSGHDR_NAME, MSGHDR_NAMELEN, SHUT_RD,
    SHUT_RDWR, SHUT_WR, SO_BROADCAST, SO_ERROR, SO_KEEPALIVE, SO_RCVTIMEO, SO_REUSEADDR,
    SO_SNDTIMEO, SO_TYPE, SOCK_CLOEXEC, SOCK_DGRAM, SOCK_NONBLOCK, SOCK_STREAM, SOCK_TYPE_MASK,
    SOCKADDR_IN_LEN, SOL_SOCKET, TCP_NODELAY, TIMEVAL_LEN, word,
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
    /// How long a receive and a send wait before giving up, in nanoseconds; zero waits until
    /// it has an answer. `SO_RCVTIMEO` and `SO_SNDTIMEO` set them, and an expiry is `EAGAIN`,
    /// as Linux reports one.
    rcv_ns: u64,
    snd_ns: u64,
}

impl Entry {
    const FREE: Entry = Entry {
        id: None,
        refs: 0,
        rcv_ns: 0,
        snd_ns: 0,
    };
}

/// How long socket `i`'s receives and sends wait.
fn timeouts(i: usize) -> (u64, u64) {
    TABLE
        .lock_irqsave()
        .get(i)
        .map_or((0, 0), |e| (e.rcv_ns, e.snd_ns))
}

static TABLE_CLASS: LockClass = LockClass::new("linux.sockets");
/// Every Linux socket. Held only to look at or change an entry: never while waiting, and
/// nothing is taken inside it.
static TABLE: SpinLock<[Entry; SOCKETS], Cpu> =
    SpinLock::with_class([Entry::FREE; SOCKETS], &TABLE_CLASS);

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
                ..Entry::FREE
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
///
/// `timeout_ns` is what `SO_RCVTIMEO` or `SO_SNDTIMEO` set, or zero to wait until there is an
/// answer. A wait that runs out answers `EAGAIN`, which is what Linux gives a socket whose
/// timeout expired.
fn wait<R>(
    slot: usize,
    nonblock: bool,
    timeout_ns: u64,
    mut attempt: impl FnMut() -> Result<Option<R>, Failure>,
) -> Result<R, Failure> {
    if let Some(r) = attempt()? {
        return Ok(r);
    }
    if nonblock {
        return Err(Failure::TryAgain);
    }
    let until = (timeout_ns != 0)
        .then(|| timekeeping::now().saturating_add(Duration::from_nanos(timeout_ns)));
    let queue = crate::sockets::waits();
    loop {
        let due = match (crate::sockets::next_look().map(Instant::from_nanos), until) {
            (Some(look), Some(until)) => Some(look.min(until)),
            (look, until) => look.or(until),
        };
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
        if until.is_some_and(|until| timekeeping::now() >= until) {
            return Err(Failure::TryAgain);
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

/// A datagram socket's failure, which differs in one place. A datagram has no connection and so
/// no peer to close, so `PeerClosed` from one of these can only be the destination-unreachable
/// message the stack matched to the port that sent: `ECONNREFUSED`, which is what Linux answers
/// a connected datagram socket whose peer refused it, rather than the reset [`failure`] would
/// report.
fn datagram_failure(e: abi::Error) -> Failure {
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
    let datagram = match (kind & SOCK_TYPE_MASK, protocol) {
        (SOCK_STREAM, 0) | (SOCK_STREAM, IPPROTO_TCP) => false,
        (SOCK_DGRAM, 0) | (SOCK_DGRAM, IPPROTO_UDP) => true,
        _ => return Err(Failure::ProtocolNotSupported),
    };
    if !crate::sockets::available() {
        return Err(Failure::NetworkDown);
    }
    let id = if datagram {
        crate::sockets::datagram_create().map_err(failure)?
    } else {
        objects::create(Object::Socket {
            port: 0,
            conn: None,
            listening: false,
        })
        .ok_or(Failure::TooManyOpen)?
    };
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
    // A datagram socket's connect is a note of where it sends: there is no handshake to wait
    // for, and it can be made again to point the socket somewhere else.
    if crate::sockets::is_datagram(id) {
        return crate::sockets::datagram_connect(id, abi::socket::address(ip, port))
            .map_err(failure);
    }
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
    wait(slot, false, 0, || crate::sockets::connected(conn).map_err(connect_failure)).map(|_| 0)
}

pub(super) fn bind(slot: usize, fd: u64, addr: u64, len: u64) -> Result<u64, Failure> {
    let (i, _) = socket_of(slot, fd)?;
    let (ip, port) = read_sockaddr(addr, len)?;
    if ip != [0; 4] && ip != crate::net::CONFIG.ip {
        return Err(Failure::AddressNotAvailable);
    }
    let id = id_of(i)?;
    let address = abi::socket::address(ip, port);
    if crate::sockets::is_datagram(id) {
        return crate::sockets::datagram_bind(id, address).map_err(failure);
    }
    crate::sockets::bind(id, address).map_err(failure)
}

pub(super) fn listen(slot: usize, fd: u64, _backlog: u64) -> Result<u64, Failure> {
    let (i, _) = socket_of(slot, fd)?;
    let id = id_of(i)?;
    // Nothing connects to a datagram socket, so nothing can be listened for on one.
    if crate::sockets::is_datagram(id) {
        return Err(Failure::OperationNotSupported);
    }
    crate::sockets::listen(id).map_err(failure)
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
        wait(slot, nonblock, 0, || crate::sockets::accept(listener, port).map_err(failure))?;
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
    let id = id_of(i)?;
    // A datagram socket sends one datagram, to the address it connected to.
    if crate::sockets::is_datagram(id) {
        return send_datagram(slot, i, id, nonblock, 0, buf, count);
    }
    let conn = crate::sockets::connection(id).map_err(|_| Failure::NotConnected)?;
    let count = count.min(MAX_IO);
    let (_, snd) = timeouts(i);
    let mut done = 0;
    while done < count {
        let n = (count - done).min(CHUNK);
        let mut chunk = [0u8; CHUNK];
        from_user(buf.checked_add(done as u64).ok_or(Failure::Fault)?, &mut chunk[..n])?;
        let sent = wait(slot, nonblock, snd, || {
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
    recv_with(slot, i, nonblock, buf, count, 0, 0, 0)
}

/// [`recv`], with the message flags, and where to write the sender's address for a datagram.
#[allow(clippy::too_many_arguments)]
fn recv_with(
    slot: usize,
    i: usize,
    nonblock: bool,
    buf: u64,
    count: usize,
    flags: u64,
    addr: u64,
    len_at: u64,
) -> Result<u64, Failure> {
    let id = id_of(i)?;
    // A datagram socket takes one datagram, and says nothing about where it came from.
    if crate::sockets::is_datagram(id) {
        return recv_datagram(slot, i, id, nonblock, buf, count, flags, addr, len_at);
    }
    let conn = crate::sockets::connection(id).map_err(|_| Failure::NotConnected)?;
    let n = count.min(CHUNK);
    if n == 0 {
        return Ok(0);
    }
    // Written first, so its pages are present: bytes taken from the connection and then
    // refused their copy would be lost.
    to_user(buf, &[0u8; CHUNK][..n])?;
    let mut bytes = [0u8; CHUNK];
    let (rcv, _) = timeouts(i);
    // `MSG_WAITALL` waits for the whole count; without it, for the first bytes to arrive.
    let want = if flags & MSG_WAITALL != 0 { n } else { 1 };
    // A peek reads the ring without taking from it, so it answers the same bytes every time:
    // whether there are enough yet is decided inside the wait, which otherwise would never
    // sleep and would spin on what it had already seen.
    if flags & MSG_PEEK != 0 {
        let got = wait(slot, nonblock, rcv, || {
            match crate::sockets::peek(conn, &mut bytes[..n]).map_err(failure)? {
                // Enough to answer with, or the end of the stream, which waiting cannot add to.
                Some(k) if k >= want || k == 0 => Ok(Some(k)),
                _ => Ok(None),
            }
        })?;
        to_user(buf, &bytes[..got])?;
        return Ok(got as u64);
    }
    let mut got = 0;
    while got < want {
        let taken = wait(slot, nonblock, rcv, || {
            crate::sockets::recv(conn, &mut bytes[got..n]).map_err(failure)
        });
        match taken {
            Ok(0) => break,
            Ok(k) => got += k,
            // What has been taken is the answer; the error waits for the next call.
            Err(e) if got == 0 => return Err(e),
            Err(_) => break,
        }
    }
    to_user(buf, &bytes[..got])?;
    Ok(got as u64)
}

/// Send one datagram from socket `i` to `to`, or to the address it connected to when `to` is
/// zero.
fn send_datagram(
    slot: usize,
    i: usize,
    id: ObjectId,
    nonblock: bool,
    to: u64,
    buf: u64,
    count: usize,
) -> Result<u64, Failure> {
    if count > crate::sockets::MAX_DATAGRAM {
        return Err(Failure::MessageTooLong);
    }
    let mut bytes = [0u8; CHUNK];
    from_user(buf, &mut bytes[..count])?;
    let (_, snd) = timeouts(i);
    wait(slot, nonblock, snd, || {
        match crate::sockets::datagram_send(id, to, &bytes[..count]) {
            Ok(n) => Ok(Some(n)),
            // The next hop is being resolved, or every buffer is held: both pass with a poll.
            Err(abi::Error::ShouldWait) => Ok(None),
            // Nowhere to send it: no address given, and none connected to.
            Err(abi::Error::InvalidArgument) if to == 0 => Err(Failure::NotConnected),
            Err(e) => Err(failure(e)),
        }
    })
}

/// Take one datagram for socket `i` into `buf`, writing where it came from to `addr` unless
/// that is null. Answers the length that fit, or the length the datagram had under `MSG_TRUNC`.
#[allow(clippy::too_many_arguments)]
fn recv_datagram(
    slot: usize,
    i: usize,
    id: ObjectId,
    nonblock: bool,
    buf: u64,
    count: usize,
    flags: u64,
    addr: u64,
    len_at: u64,
) -> Result<u64, Failure> {
    let cap = count.min(CHUNK);
    // Written first, for the reason `recv` gives: a datagram taken and then refused its copy
    // is gone, and nothing can ask for it again.
    to_user(buf, &[0u8; CHUNK][..cap])?;
    let (rcv, _) = timeouts(i);
    let peek = flags & MSG_PEEK != 0;
    let (from, copied, whole) = wait(slot, nonblock, rcv, || {
        let mut bytes = [0u8; CHUNK];
        // A peek leaves the datagram in the inbox, so the receive after it takes the same one.
        let taken = if peek {
            crate::sockets::datagram_peek(id, &mut bytes[..cap])
        } else {
            crate::sockets::datagram_recv(id, &mut bytes[..cap])
        };
        let Some((from, copied, whole)) = taken.map_err(datagram_failure)? else {
            return Ok(None);
        };
        to_user(buf, bytes.get(..copied).unwrap_or(&[]))?;
        Ok(Some((from, copied, whole)))
    })?;
    if addr != 0 {
        write_sockaddr(addr, len_at, abi::socket::ip(from), abi::socket::port(from))?;
    } else if len_at != 0 {
        to_user(len_at, &0u32.to_le_bytes())?;
    }
    Ok(if flags & MSG_TRUNC != 0 {
        whole as u64
    } else {
        copied as u64
    })
}

#[allow(clippy::too_many_arguments)]
pub(super) fn sendto(
    slot: usize,
    fd: u64,
    buf: u64,
    count: u64,
    flags: u64,
    addr: u64,
    addr_len: u64,
) -> Result<u64, Failure> {
    let (i, nonblock) = socket_of(slot, fd)?;
    if flags & !(MSG_DONTWAIT | MSG_NOSIGNAL) != 0 {
        return Err(Failure::OperationNotSupported);
    }
    let nonblock = nonblock || flags & MSG_DONTWAIT != 0;
    let count = usize::try_from(count).unwrap_or(MAX_IO);
    let id = id_of(i)?;
    if crate::sockets::is_datagram(id) {
        // Where it goes: the address this call names, or the one the socket connected to.
        let to = if addr == 0 {
            0
        } else {
            let (ip, port) = read_sockaddr(addr, addr_len)?;
            abi::socket::address(ip, port)
        };
        return send_datagram(slot, i, id, nonblock, to, buf, count);
    }
    // On a connected stream the address is ignored, as it is on Linux.
    send(slot, i, nonblock, buf, count)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn recvfrom(
    slot: usize,
    fd: u64,
    buf: u64,
    count: u64,
    flags: u64,
    addr: u64,
    len_at: u64,
) -> Result<u64, Failure> {
    let (i, nonblock) = socket_of(slot, fd)?;
    if flags & !(MSG_DONTWAIT | MSG_TRUNC | MSG_PEEK | MSG_WAITALL) != 0 {
        return Err(Failure::OperationNotSupported);
    }
    let nonblock = nonblock || flags & MSG_DONTWAIT != 0;
    let count = usize::try_from(count).unwrap_or(MAX_IO);
    let id = id_of(i)?;
    if crate::sockets::is_datagram(id) {
        // `MSG_WAITALL` says nothing on a datagram: one is taken whole or not at all.
        return recv_datagram(slot, i, id, nonblock, buf, count, flags, addr, len_at);
    }
    if flags & MSG_TRUNC != 0 {
        // Nothing is truncated in a stream: the rest of it is still there to read.
        return Err(Failure::OperationNotSupported);
    }
    let got = recv_with(slot, i, nonblock, buf, count, flags, 0, 0)?;
    // A stream names no sender: Linux reports an address of no bytes.
    if len_at != 0 {
        to_user(len_at, &0u32.to_le_bytes())?;
    }
    Ok(got)
}

/// Buffers one message may be spread over. A message of more is refused rather than half
/// carried, which is what `UIO_MAXIOV` bounds on Linux; this bound is the personality's own.
const MAX_IOV: usize = 4;

/// One buffer of a message: where it is in the program, and how long.
#[derive(Clone, Copy)]
struct Buffer {
    base: u64,
    len: u64,
}

/// The buffers, the address and the flags of the `struct msghdr` at `at`: what `sendmsg` and
/// `recvmsg` carry. Each `iovec` is one buffer of the one message — a datagram goes whole,
/// however many buffers it was gathered from, and arrives into as many as it fills.
fn message(at: u64) -> Result<([Buffer; MAX_IOV], usize, u64, u64), Failure> {
    let mut header = [0u8; MSGHDR_LEN];
    from_user(at, &mut header)?;
    let (name, name_len) = (word(&header, MSGHDR_NAME), word(&header, MSGHDR_NAMELEN));
    let (iov, iov_len) = (word(&header, MSGHDR_IOV), word(&header, MSGHDR_IOVLEN));
    let count = usize::try_from(iov_len).unwrap_or(usize::MAX);
    if count > MAX_IOV {
        return Err(Failure::OperationNotSupported);
    }
    let mut buffers = [Buffer { base: 0, len: 0 }; MAX_IOV];
    for (i, b) in buffers.iter_mut().enumerate().take(count) {
        let at = iov
            .checked_add((i * IOVEC_LEN) as u64)
            .ok_or(Failure::Fault)?;
        let mut vector = [0u8; IOVEC_LEN];
        from_user(at, &mut vector)?;
        *b = Buffer {
            base: word(&vector, 0),
            len: word(&vector, 8),
        };
    }
    Ok((buffers, count, name, name_len))
}

/// The bytes of `buffers`, copied out of the program into `into`: what a send gathers.
fn gather(buffers: &[Buffer], into: &mut [u8]) -> Result<usize, Failure> {
    let mut done = 0;
    for b in buffers {
        let n = usize::try_from(b.len)
            .unwrap_or(usize::MAX)
            .min(into.len() - done);
        if n == 0 {
            continue;
        }
        from_user(b.base, &mut into[done..done + n])?;
        done += n;
        if done == into.len() {
            break;
        }
    }
    Ok(done)
}

/// `from`, copied into `buffers` in turn: what a receive scatters. Answers the bytes placed,
/// which is all of them unless the buffers hold less than arrived.
fn scatter(buffers: &[Buffer], from: &[u8]) -> Result<usize, Failure> {
    let mut done = 0;
    for b in buffers {
        if done == from.len() {
            break;
        }
        let n = usize::try_from(b.len)
            .unwrap_or(usize::MAX)
            .min(from.len() - done);
        if n == 0 {
            continue;
        }
        to_user(b.base, &from[done..done + n])?;
        done += n;
    }
    Ok(done)
}

pub(super) fn sendmsg(slot: usize, fd: u64, at: u64, flags: u64) -> Result<u64, Failure> {
    let (buffers, count, name, name_len) = message(at)?;
    let buffers = &buffers[..count];
    // One buffer goes straight from the program's memory, as `sendto` sends it.
    if let [only] = buffers {
        return sendto(slot, fd, only.base, only.len, flags, name, name_len);
    }
    // Several are gathered into one message first: a datagram is one datagram whatever it was
    // written from, and a stream keeps the order the buffers are in.
    let mut bytes = [0u8; CHUNK];
    let n = gather(buffers, &mut bytes)?;
    let (i, nonblock) = socket_of(slot, fd)?;
    if flags & !(MSG_DONTWAIT | MSG_NOSIGNAL) != 0 {
        return Err(Failure::OperationNotSupported);
    }
    let nonblock = nonblock || flags & MSG_DONTWAIT != 0;
    let id = id_of(i)?;
    let to = if name == 0 {
        0
    } else {
        let (ip, port) = read_sockaddr(name, name_len)?;
        abi::socket::address(ip, port)
    };
    send_bytes(slot, i, id, nonblock, to, &bytes[..n])
}

pub(super) fn recvmsg(slot: usize, fd: u64, at: u64, flags: u64) -> Result<u64, Failure> {
    let (buffers, count, name, _) = message(at)?;
    let buffers = &buffers[..count];
    // The address's length goes back in the header, where `msg_namelen` is, rather than at a
    // pointer of its own as `recvfrom` takes it.
    let len_at = at
        .checked_add(MSGHDR_NAMELEN as u64)
        .ok_or(Failure::Fault)?;
    if let [only] = buffers {
        return recvfrom(slot, fd, only.base, only.len, flags, name, len_at);
    }
    // Several buffers take one receive between them: the message arrives once, into the
    // personality's own buffer, and is spread over them in order.
    let want = buffers
        .iter()
        .map(|b| usize::try_from(b.len).unwrap_or(usize::MAX))
        .fold(0usize, |a, n| a.saturating_add(n))
        .min(CHUNK);
    let mut bytes = [0u8; CHUNK];
    let (got, reported) = recv_into(slot, fd, &mut bytes[..want], flags, name, len_at)?;
    scatter(buffers, &bytes[..got])?;
    // What the call answers is what arrived, which `MSG_TRUNC` makes the whole datagram's
    // length; what was placed is bounded by the buffers, and a short set loses the rest.
    Ok(reported)
}

/// Send `bytes`, already out of the program's memory, on socket `i`: one datagram to `to`, or
/// as much of a stream as it takes. What [`sendmsg`] gathers goes out through this.
fn send_bytes(
    slot: usize,
    i: usize,
    id: ObjectId,
    nonblock: bool,
    to: u64,
    bytes: &[u8],
) -> Result<u64, Failure> {
    let (_, snd) = timeouts(i);
    if crate::sockets::is_datagram(id) {
        if bytes.len() > crate::sockets::MAX_DATAGRAM {
            return Err(Failure::MessageTooLong);
        }
        return wait(slot, nonblock, snd, || match crate::sockets::datagram_send(id, to, bytes) {
            Ok(n) => Ok(Some(n)),
            Err(abi::Error::ShouldWait) => Ok(None),
            Err(abi::Error::InvalidArgument) if to == 0 => Err(Failure::NotConnected),
            Err(e) => Err(failure(e)),
        });
    }
    let conn = crate::sockets::connection(id).map_err(|_| Failure::NotConnected)?;
    let mut done = 0;
    while done < bytes.len() {
        let sent = wait(slot, nonblock, snd, || {
            crate::sockets::send(conn, &bytes[done..]).map_err(|e| match e {
                abi::Error::InvalidArgument => Failure::BrokenPipe,
                e => failure(e),
            })
        });
        match sent {
            Ok(k) => done += k as usize,
            Err(e) if done == 0 => return Err(e),
            Err(_) => break,
        }
    }
    Ok(done as u64)
}

/// Receive one message into `into`, which is the personality's own memory rather than the
/// program's: the bytes copied, and what the call answers with, which `MSG_TRUNC` makes the
/// whole datagram's length. What [`recvmsg`] scatters comes in through this.
fn recv_into(
    slot: usize,
    fd: u64,
    into: &mut [u8],
    flags: u64,
    addr: u64,
    len_at: u64,
) -> Result<(usize, u64), Failure> {
    let (i, nonblock) = socket_of(slot, fd)?;
    if flags & !(MSG_DONTWAIT | MSG_TRUNC | MSG_PEEK | MSG_WAITALL) != 0 {
        return Err(Failure::OperationNotSupported);
    }
    let nonblock = nonblock || flags & MSG_DONTWAIT != 0;
    let id = id_of(i)?;
    let (rcv, _) = timeouts(i);
    let peek = flags & MSG_PEEK != 0;
    if crate::sockets::is_datagram(id) {
        let (from, copied, whole) = wait(slot, nonblock, rcv, || {
            let taken = if peek {
                crate::sockets::datagram_peek(id, into)
            } else {
                crate::sockets::datagram_recv(id, into)
            };
            taken.map_err(datagram_failure)
        })?;
        if addr != 0 {
            write_sockaddr(addr, len_at, abi::socket::ip(from), abi::socket::port(from))?;
        } else if len_at != 0 {
            to_user(len_at, &0u32.to_le_bytes())?;
        }
        let reported = if flags & MSG_TRUNC != 0 {
            whole
        } else {
            copied
        };
        return Ok((copied, reported as u64));
    }
    if flags & MSG_TRUNC != 0 {
        // Nothing is truncated in a stream: the rest of it is still there to read.
        return Err(Failure::OperationNotSupported);
    }
    let conn = crate::sockets::connection(id).map_err(|_| Failure::NotConnected)?;
    let want = if flags & MSG_WAITALL != 0 {
        into.len()
    } else {
        1
    };
    // As in `recv_with`: a peek sees the same bytes until they are taken, so the wait itself
    // decides whether there are enough, rather than looping on them.
    let mut got = 0;
    if peek {
        got = wait(slot, nonblock, rcv, || {
            match crate::sockets::peek(conn, into).map_err(failure)? {
                Some(k) if k >= want || k == 0 => Ok(Some(k)),
                _ => Ok(None),
            }
        })?;
    } else {
        while got < want {
            let taken = wait(slot, nonblock, rcv, || {
                crate::sockets::recv(conn, &mut into[got..]).map_err(failure)
            });
            match taken {
                Ok(0) => break,
                Ok(k) => got += k,
                Err(e) if got == 0 => return Err(e),
                Err(_) => break,
            }
        }
    }
    // A stream names no sender: Linux reports an address of no bytes.
    if len_at != 0 {
        to_user(len_at, &0u32.to_le_bytes())?;
    }
    Ok((got, got as u64))
}

pub(super) fn shutdown(slot: usize, fd: u64, how: u64) -> Result<u64, Failure> {
    let (i, _) = socket_of(slot, fd)?;
    match how {
        SHUT_WR | SHUT_RDWR => {}
        SHUT_RD => return Err(Failure::OperationNotSupported),
        _ => return Err(Failure::InvalidArgument),
    }
    let id = id_of(i)?;
    // A datagram socket has no half to shut: nothing is owed to a peer it never agreed with.
    if crate::sockets::is_datagram(id) {
        return Err(Failure::OperationNotSupported);
    }
    let conn = crate::sockets::connection(id).map_err(|_| Failure::NotConnected)?;
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
    let id = id_of(i)?;
    if crate::sockets::is_datagram(id) {
        let (port, connected) = crate::sockets::datagram_endpoints(id).map_err(failure)?;
        let (ip, port) = match (peer, connected) {
            (true, Some(peer)) => (abi::socket::ip(peer), abi::socket::port(peer)),
            (true, None) => return Err(Failure::NotConnected),
            (false, _) if port != 0 => (crate::net::CONFIG.ip, port),
            (false, _) => ([0; 4], 0),
        };
        write_sockaddr(addr, len_at, ip, port)?;
        return Ok(0);
    }
    let (local, remote) = crate::sockets::endpoints(id).map_err(failure)?;
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
    let (i, _) = socket_of(slot, fd)?;
    // The two that do something: how long a receive and a send wait.
    if level == SOL_SOCKET && (option == SO_RCVTIMEO || option == SO_SNDTIMEO) {
        if len < TIMEVAL_LEN as u64 {
            return Err(Failure::InvalidArgument);
        }
        let mut timeval = [0u8; TIMEVAL_LEN];
        from_user(value, &mut timeval)?;
        let (seconds, micros) = (word(&timeval, 0), word(&timeval, 8));
        if micros >= 1_000_000 {
            return Err(Failure::InvalidArgument);
        }
        let ns = seconds
            .saturating_mul(1_000_000_000)
            .saturating_add(micros.saturating_mul(1_000));
        let mut table = TABLE.lock_irqsave();
        let entry = table.get_mut(i).ok_or(Failure::BadDescriptor)?;
        if option == SO_RCVTIMEO {
            entry.rcv_ns = ns;
        } else {
            entry.snd_ns = ns;
        }
        return Ok(0);
    }
    match (level, option) {
        (SOL_SOCKET, SO_REUSEADDR | SO_KEEPALIVE) | (IPPROTO_TCP, TCP_NODELAY) => {}
        // Nothing here sends to a broadcast address, and a program that asked to should hear
        // so rather than find its datagrams going to one host.
        (SOL_SOCKET, SO_BROADCAST) => return Err(Failure::NoProtocolOption),
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
        (SOL_SOCKET, SO_TYPE) if crate::sockets::is_datagram(id_of(i)?) => SOCK_DGRAM as i32,
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
/// The `udp` mode's, which mirrors `UDP_SUCCESS` in `user/linux-hello/src/main.rs`.
const UDP_SUCCESS: u64 = 52;
/// What the same mode exits with where the quiet port was *refused* rather than left to time
/// out: `UDP_REFUSED` there. Only kbuild's own peer sends the destination-unreachable message
/// that produces it, so every other network still earns [`UDP_SUCCESS`].
const UDP_REFUSED: u64 = 53;

/// The `peek` mode's, which mirrors `PEEK_SUCCESS` in `user/linux-hello/src/main.rs`.
const PEEK_SUCCESS: u64 = 59;
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

/// The `udp` mode's one argument, `<service>,<quiet>`, and the `argv` naming it. Written and
/// read under the same rule as `PORT_DIGITS`.
static UDP_DIGITS: SyncUnsafeCell<[u8; 12]> = SyncUnsafeCell::new([0; 12]);
static PEEK_DIGITS: SyncUnsafeCell<[u8; 12]> = SyncUnsafeCell::new([0; 12]);
static UDP_ARGV: SyncUnsafeCell<[&[u8]; 3]> = SyncUnsafeCell::new([b"hello", b"udp", b""]);
static PEEK_ARGV: SyncUnsafeCell<[&[u8]; 3]> = SyncUnsafeCell::new([b"hello", b"peek", b""]);

/// `<service>,<quiet>` into `buf`, which is what the `udp` mode parses. Its length.
fn two_ports(buf: &mut [u8; 12], service: u16, quiet: u16) -> usize {
    let mut n = 0;
    let mut put = |b: u8, n: &mut usize| {
        if let Some(slot) = buf.get_mut(*n) {
            *slot = b;
            *n += 1;
        }
    };
    for (i, port) in [service, quiet].into_iter().enumerate() {
        if i == 1 {
            put(b',', &mut n);
        }
        let mut started = false;
        for d in [10_000u16, 1_000, 100, 10, 1] {
            let digit = (port / d) % 10;
            if digit != 0 || started || d == 1 {
                started = true;
                put(b'0' + digit as u8, &mut n);
            }
        }
    }
    n
}

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
    // Then datagrams: the same program against kbuild's datagram service and the port it leaves
    // unbound.
    let datagram = match (crate::net::udp_service_port(), crate::net::quiet_port()) {
        (Some(service), Some(quiet)) => {
            // SAFETY: see `PORT_DIGITS`: no Linux process runs, and the next is not built yet.
            let argv: &'static [&'static [u8]] = unsafe {
                let digits: &'static mut [u8; 12] = &mut *UDP_DIGITS.get();
                let n = two_ports(digits, service, quiet);
                let written: &'static [u8] = &*UDP_DIGITS.get();
                let argv = &mut *UDP_ARGV.get();
                argv[2] = written.get(..n).unwrap_or(b"");
                &*UDP_ARGV.get()
            };
            Some(run_mode(&program, argv, || {}))
        }
        // kbuild announces its datagram service beside its TCP service, so a run that heard one
        // and not the other heard half of what it was told.
        _ => None,
    };
    // With kbuild as the whole network the quiet port answers a refusal, and the program must
    // have been refused; on every other network nobody sends one, so the timeout stands and
    // either outcome is accepted.
    let datagram_ok = match datagram {
        Some(run) => {
            let wanted = if kconfig::QEMU_NET_PEER {
                run.code == Some(UDP_REFUSED)
            } else {
                run.code == Some(UDP_SUCCESS) || run.code == Some(UDP_REFUSED)
            };
            wanted && run.ended
        }
        None => !kconfig::QEMU_NET_TEST,
    };

    // Then what a peek leaves behind, and messages of several buffers, against the same
    // datagram service and kbuild's TCP service.
    let peeked = match (crate::net::udp_service_port(), crate::net::tcp_port()) {
        (Some(service), Some(tcp)) => {
            // SAFETY: as the datagram mode's argv above: no Linux process runs, and the next
            // is not built yet.
            let argv: &'static [&'static [u8]] = unsafe {
                let digits: &'static mut [u8; 12] = &mut *PEEK_DIGITS.get();
                let n = two_ports(digits, service, tcp);
                let written: &'static [u8] = &*PEEK_DIGITS.get();
                let argv = &mut *PEEK_ARGV.get();
                argv[2] = written.get(..n).unwrap_or(b"");
                &*PEEK_ARGV.get()
            };
            Some(run_mode(&program, argv, || {}))
        }
        _ => None,
    };
    let peek_ok = match peeked {
        Some(run) => run.code == Some(PEEK_SUCCESS) && run.ended,
        None => !kconfig::QEMU_NET_TEST,
    };

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
    c.write_str("; ");
    match datagram {
        // Where kbuild is the whole network the quiet port answers a refusal, and that is the
        // code the mode ends with; elsewhere nobody sends the message and the timeout stands.
        Some(run) => report(
            c,
            "udp",
            run,
            if kconfig::QEMU_NET_PEER {
                UDP_REFUSED
            } else {
                UDP_SUCCESS
            },
        ),
        None => c.write_str("udp skipped: kbuild announced no datagram service"),
    }
    c.write_str("; ");
    match peeked {
        Some(run) => report(c, "peek", run, PEEK_SUCCESS),
        None => c.write_str("peek skipped: kbuild announced no datagram service"),
    }
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
        datagram_ok
            && peek_ok
            && client.code == Some(TCP_SUCCESS)
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

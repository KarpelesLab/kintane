//! Sockets: the network stack's TCP and UDP, as objects a program names with handles.
//!
//! # The object
//!
//! A socket is an [`Object::Socket`] in the object store, and a program holds it the way it holds
//! anything: through a handle with rights. `socket_create` makes one with every right, neither
//! bound nor connected. `socket_connect` gives it a connection, `socket_bind` and
//! `socket_listen` make it a listener, and `socket_accept` makes a new socket for each
//! connection a listener takes. Sending, connecting, binding, listening and shutting down need
//! `WRITE`; receiving and accepting need `READ`. So a program can hand another a socket it may
//! only read from, as it can a channel.
//!
//! When the last handle to a socket goes — closed, or its process torn down — the store destroys
//! the object, and its connection is closed in order ([`release`]): a FIN after whatever is still
//! queued, and the connection's buffers back in the stack's pool once the close completes. A
//! connection with unread data is reset instead, as TCP asks.
//!
//! A datagram socket is an [`Object::Datagram`] instead, and holds no connection, because UDP
//! has none. What it holds is a local port — bound, or given to it by its first send — and,
//! once connected, the one address it sends to and takes datagrams from. Its port goes back
//! when the object is destroyed ([`release_port`]), together with anything still waiting for
//! that port in the stack's inbox, which nothing else would ever take.
//!
//! # Waiting
//!
//! Every call that can wait — connect, accept, send, receive, shutdown — blocks on [`WAITS`], a
//! Phase 6a wait queue, with the caller's timeout. From the first socket check on, the card's
//! interrupt handler runs the stack over every frame that arrives and wakes the queue
//! (`net::serve_by_interrupt`), so a waiter looks again when a segment has moved the connection
//! it waits on, and not before. The one other thing that can move a connection without a frame
//! is a TCP timer — a retransmission, TIME-WAIT's end — so a waiter also looks again when the
//! stack's earliest timer runs out ([`next_look`]). Closing or shutting a socket down wakes the
//! queue too, for another thread of the same process waiting on it.
//!
//! [`wakes`] counts both kinds of look, and the check requires the first. On a port with no
//! interrupt route for the card nothing can wake the queue, and a waiter falls back to looking
//! every [`LOOK_EVERY_NS`]; those looks are counted as polls, and on a port that has a route the
//! check requires that there were none.
//!
//! # Linux's calls
//!
//! The Linux personality's socket calls (`personality::socket`) are a layer over the functions
//! here, as the native calls are: a Linux socket descriptor names a socket object like the one
//! a handle names, and waits on the same queue, datagram sockets included. `SHUT_RD` and
//! readiness through `poll` or `epoll` need more than exists.
//!
//! # The check
//!
//! [`check`] runs `user/tcp-client`, a native program, on the scheduler. It is given the console
//! and kbuild's TCP address, connects through QEMU's user network, sends a request, reads the
//! reply up to kbuild's close, closes its socket and exits with a code this grades. kbuild drops
//! the connection's first data segment once, so the program's request reaches kbuild only
//! because the kernel sent it again. What must hold:
//!
//! * the program exits with [`SUCCESS`], which it returns only if its reply was the one asked for
//!   and the stream ended in order;
//! * a data segment was retransmitted while it ran;
//! * once it has exited, the connection it let go of finishes closing, and every stack buffer is
//!   back in the pool;
//! * every object and frame is back.
//!
//! Then [`datagram_run`] runs `user/udp-client` on the same slot and stacks, against kbuild's
//! datagram service and the port kbuild leaves unbound. It must report a reply from the service,
//! a truncated datagram whose reported length is the length it had, a datagram from anywhere but
//! its peer refused, and nothing at all from the unbound port — which is a timeout, because this
//! stack turns no ICMP message into an error on a socket.

use core::sync::atomic::Ordering;

use abi::Error;
use hal::EarlyConsole;
use kobject::ObjectId;
use net::tcp::{State, Status};
use net::{Conn, TcpError};
use time::{Duration, Instant};

use crate::objects::{self, Object};
use crate::preempt::{self, sleep_until};
use crate::wait::WaitQueue;
use crate::{AtomicU32, AtomicU64, Check, spawn, timekeeping, userproc, write_hex, write_usize};

/// The most one send or receive moves: what the kernel copies on its own stack.
pub const CHUNK: usize = 512;

/// The largest datagram a socket carries: what the stack's inbox keeps of one, so a datagram
/// that is sent is one that could have been received.
pub const MAX_DATAGRAM: usize = net::stack::UDP_MAX;

/// How often a waiting call looks at the network where nothing can wake it: a port with no
/// interrupt route for the card. See the module documentation.
pub const LOOK_EVERY_NS: u64 = 2_000_000;

/// The soonest a wait armed for a TCP timer looks again, so a timer already due costs a look a
/// millisecond rather than a spin.
const TIMER_FLOOR_NS: u64 = 1_000_000;

/// Every socket call waits here.
static WAITS: WaitQueue = WaitQueue::new();

/// Waiting threads the card's handler woke, waits armed for a TCP timer, and waits armed on
/// the fixed interval. See [`wakes`].
static WOKEN: AtomicU64 = AtomicU64::new(0);
static TIMERS: AtomicU64 = AtomicU64::new(0);
static POLLS: AtomicU64 = AtomicU64::new(0);

pub fn waits() -> &'static WaitQueue {
    &WAITS
}

/// When a waiting call must look again even if nothing wakes it: the stack's next TCP timer
/// where the card's handler wakes the queue, and a fixed interval where nothing can.
pub fn next_look() -> Option<u64> {
    let now = timekeeping::now().as_nanos();
    if !crate::net::by_interrupt() {
        POLLS.fetch_add(1, Ordering::Relaxed);
        return Some(now.saturating_add(LOOK_EVERY_NS));
    }
    let due = crate::net::tcp_next_deadline()?;
    TIMERS.fetch_add(1, Ordering::Relaxed);
    Some(due.max(now.saturating_add(TIMER_FLOOR_NS)))
}

/// The card's handler has run the stack over what arrived: wake every waiting call.
pub fn wake_from_interrupt() {
    crate::readiness::wake();
    let woke = WAITS.wake_all();
    WOKEN.fetch_add(woke as u64, Ordering::Relaxed);
}

/// Wait on the network as a socket call does, for a kernel thread with no socket: until the
/// card's handler has run the stack since `seen` was read, the stack's next TCP timer, or the
/// end of the caller's wait. `false`, having waited for nothing, where nothing wakes the queue.
pub fn await_activity(seen: crate::net::Seen) -> bool {
    if !crate::net::by_interrupt() {
        return false;
    }
    let now = timekeeping::now().as_nanos();
    let until = match seen.due {
        Some(due) => {
            TIMERS.fetch_add(1, Ordering::Relaxed);
            due.max(now.saturating_add(TIMER_FLOOR_NS)).min(seen.until)
        }
        None => seen.until,
    };
    let _ = WAITS.wait_once(Some(Instant::from_nanos(until)), || {
        (crate::net::generation() != seen.generation).then_some(())
    });
    true
}

/// What the network's waiters have done since boot.
#[derive(Clone, Copy)]
pub struct Wakes {
    /// Blocked waiters the card's interrupt handler made runnable.
    pub woken: u64,
    /// Waits armed to look again at the stack's next TCP timer.
    pub timers: u64,
    /// Waits armed to look again on the fixed interval, because nothing could wake them.
    pub polls: u64,
}

impl Wakes {
    fn since(self, before: Wakes) -> Wakes {
        Wakes {
            woken: self.woken - before.woken,
            timers: self.timers - before.timers,
            polls: self.polls - before.polls,
        }
    }
}

pub fn wakes() -> Wakes {
    Wakes {
        woken: WOKEN.load(Ordering::Relaxed),
        timers: TIMERS.load(Ordering::Relaxed),
        polls: POLLS.load(Ordering::Relaxed),
    }
}

/// Whether this machine has a started card for sockets to use.
pub fn available() -> bool {
    crate::net::nic().is_some()
}

fn error(e: TcpError) -> Error {
    match e {
        TcpError::NoRoom | TcpError::PortInUse => Error::Full,
        TcpError::BadConnection => Error::BadHandle,
        TcpError::WrongState => Error::InvalidArgument,
        TcpError::Reset => Error::PeerClosed,
        TcpError::TimedOut => Error::TimedOut,
        TcpError::WouldBlock => Error::ShouldWait,
    }
}

/// Run `f` on the network stack, after polling it.
fn stack<R>(
    f: impl FnOnce(&mut net::Stack, &virtio_net::VirtioNet<crate::Locks>, u64) -> R,
) -> Result<R, Error> {
    crate::net::with_stack(f).ok_or(Error::Unsupported)
}

/// A socket's connection, its bound port, and whether it is a listener.
fn state_of(id: ObjectId) -> Result<(Option<Conn>, u16, bool), Error> {
    objects::with(id, |o| match o {
        Object::Socket {
            port,
            conn,
            listening,
        } => Ok((conn.map(Conn::from_raw), *port, *listening)),
        _ => Err(Error::WrongType),
    })
    .ok_or(Error::BadHandle)?
}

/// The connection of a connected socket.
pub fn connection(id: ObjectId) -> Result<Conn, Error> {
    match state_of(id)? {
        (Some(conn), _, false) => Ok(conn),
        _ => Err(Error::InvalidArgument),
    }
}

/// The listener of a listening socket, and its port.
pub fn listener(id: ObjectId) -> Result<(Conn, u16), Error> {
    match state_of(id)? {
        (Some(conn), port, true) => Ok((conn, port)),
        _ => Err(Error::InvalidArgument),
    }
}

/// Give socket `id` the port in `address`.
pub fn bind(id: ObjectId, address: u64) -> Result<u64, Error> {
    let (ip, port) = (abi::socket::ip(address), abi::socket::port(address));
    let ours = ip == [0; 4] || ip == crate::net::CONFIG.ip;
    if !abi::socket::well_formed(address) || port == 0 || !ours {
        return Err(Error::InvalidArgument);
    }
    objects::with(id, |o| match o {
        Object::Socket {
            port: bound,
            conn: None,
            ..
        } if *bound == 0 => {
            *bound = port;
            Ok(0)
        }
        Object::Socket { .. } => Err(Error::InvalidArgument),
        _ => Err(Error::WrongType),
    })
    .ok_or(Error::BadHandle)?
}

/// Record `conn` as socket `id`'s, or close it again if the socket gained one meanwhile.
fn keep(id: ObjectId, conn: Conn, listening: bool) -> Result<(), Error> {
    let kept = objects::with(id, |o| match o {
        Object::Socket {
            conn: slot @ None,
            listening: l,
            ..
        } => {
            *slot = Some(conn.raw());
            *l = listening;
            true
        }
        _ => false,
    })
    .unwrap_or(false);
    if kept {
        Ok(())
    } else {
        release(conn.raw());
        Err(Error::InvalidArgument)
    }
}

/// Begin connecting socket `id` to `address`, or return the attempt already under way.
pub fn connect(id: ObjectId, address: u64) -> Result<Conn, Error> {
    let (ip, port) = (abi::socket::ip(address), abi::socket::port(address));
    if !abi::socket::well_formed(address) || port == 0 {
        return Err(Error::InvalidArgument);
    }
    match state_of(id)? {
        (Some(conn), _, false) => return Ok(conn),
        (Some(_), _, true) => return Err(Error::InvalidArgument),
        (None, _, _) => {}
    }
    let conn = stack(|s, card, t| s.tcp_connect(card, ip, port, t))?.map_err(error)?;
    keep(id, conn, false)?;
    Ok(conn)
}

/// `Some` once `conn` is established, `None` while the handshake goes on.
pub fn connected(conn: Conn) -> Result<Option<u64>, Error> {
    let status = stack(|s, _, _| s.tcp_status(conn))?.ok_or(Error::BadHandle)?;
    match status {
        Status { error: Some(e), .. } => Err(error(e)),
        Status {
            state: State::SynSent | State::SynReceived,
            ..
        } => Ok(None),
        _ => Ok(Some(0)),
    }
}

/// Make socket `id` a listener on its bound port.
pub fn listen(id: ObjectId) -> Result<u64, Error> {
    let (conn, port, _) = state_of(id)?;
    if conn.is_some() || port == 0 {
        return Err(Error::InvalidArgument);
    }
    let listener = stack(|s, _, _| s.tcp_listen(port))?.map_err(error)?;
    keep(id, listener, true)?;
    Ok(0)
}

/// Socket `id`'s local port, and its peer's address and port once it has a connection.
#[cfg_attr(
    not(CONFIG_ABI_LINUX),
    expect(dead_code, reason = "the Linux personality's names are its only users")
)]
pub fn endpoints(id: ObjectId) -> Result<(u16, Option<(net::Ipv4Addr, u16)>), Error> {
    match state_of(id)? {
        (Some(conn), _, false) => {
            let (local, ip, port) =
                stack(|s, _, _| s.tcp_endpoints(conn))?.ok_or(Error::BadHandle)?;
            Ok((local, Some((ip, port))))
        }
        (_, port, _) => Ok((port, None)),
    }
}

/// Whether something listens on `port`.
#[cfg_attr(
    not(CONFIG_ABI_LINUX),
    expect(dead_code, reason = "the Linux socket check is its only user")
)]
pub fn listening_on(port: u16) -> bool {
    crate::net::with_stack(|s, _, _| s.tcp_listening(port)).unwrap_or(false)
}

/// A new socket object for a connection `listener` has, or `None` while it has none.
pub fn accept(listener: Conn, port: u16) -> Result<Option<ObjectId>, Error> {
    let conn = match stack(|s, _, _| s.tcp_accept(listener))? {
        Ok(conn) => conn,
        Err(TcpError::WouldBlock) => return Ok(None),
        Err(e) => return Err(error(e)),
    };
    let socket = Object::Socket {
        port,
        conn: Some(conn.raw()),
        listening: false,
    };
    match objects::create(socket) {
        Some(id) => Ok(Some(id)),
        None => {
            release(conn.raw());
            Err(Error::Full)
        }
    }
}

/// Queue what fits of `data`; `None` while nothing fits.
pub fn send(conn: Conn, data: &[u8]) -> Result<Option<u64>, Error> {
    match stack(|s, card, t| s.tcp_send(card, conn, data, t))? {
        Ok(n) => Ok(Some(n as u64)),
        Err(TcpError::WouldBlock) => Ok(None),
        Err(e) => Err(error(e)),
    }
}

/// Read what has arrived into `into`: `Some(0)` at the end of the stream, `None` while nothing
/// has arrived.
pub fn recv(conn: Conn, into: &mut [u8]) -> Result<Option<usize>, Error> {
    match stack(|s, card, t| s.tcp_recv(card, conn, into, t))? {
        Ok(n) => Ok(Some(n)),
        Err(TcpError::WouldBlock) => Ok(None),
        Err(e) => Err(error(e)),
    }
}

/// Queue a FIN after what is queued.
pub fn shutdown(conn: Conn) -> Result<(), Error> {
    let done = stack(|s, card, t| s.tcp_shutdown(card, conn, t))?.map_err(error);
    // Another thread may wait on this connection, for what the shutdown ends.
    WAITS.wake_all();
    done
}

/// `Some` once everything `conn` sent, its FIN included, is acknowledged.
pub fn shut(conn: Conn) -> Result<Option<u64>, Error> {
    let status = stack(|s, _, _| s.tcp_status(conn))?.ok_or(Error::BadHandle)?;
    if let Some(e) = status.error {
        return Err(error(e));
    }
    Ok((status.fin_acknowledged && status.unacknowledged == 0).then_some(0))
}

/// Whether `listener` has a connection an accept would take, without taking it: what a wait
/// over a set asks about a listening socket (`crate::readiness`).
pub fn pending(listener: Conn) -> bool {
    crate::net::with_stack(|s, _, _| s.tcp_pending(listener)).unwrap_or(false)
}

/// A connected socket's readiness, taking nothing: bytes waiting — or the peer's close, which
/// a receive answers at once with the end of the stream — room in the send ring, and a
/// connection that has failed.
pub fn readiness(conn: Conn) -> u32 {
    use abi::ready;
    let Some(Some(status)) = crate::net::with_stack(|s, _, _| s.tcp_status(conn)) else {
        // The stack has let the connection go: every call on it now answers rather than waits.
        return ready::ERROR | ready::CLOSED;
    };
    let mut bits = 0;
    if status.error.is_some() {
        bits |= ready::ERROR;
    }
    if status.readable > 0 || status.peer_closed {
        bits |= ready::READ;
    }
    if status.peer_closed {
        bits |= ready::CLOSED;
    }
    if status.writable > 0 {
        bits |= ready::WRITE;
    }
    bits
}

/// Let go of a destroyed socket's connection: closed in order, and freed once it is over.
pub fn release(conn: u64) {
    let _ = crate::net::with_stack(|s, card, t| s.tcp_close(card, Conn::from_raw(conn), t));
    WAITS.wake_all();
}

// ---- datagram sockets ---------------------------------------------------------------------
//
// A datagram socket holds no connection: UDP has none. What it holds is a local port, which is
// how the stack's inbox tells its datagrams from anyone else's, and — once it has connected —
// the one address it sends to and takes datagrams from. Everything else a call needs is in the
// datagram itself.
//
// Sending and receiving never block on the stack for room the way TCP does: a datagram is sent
// or refused, and one that has arrived is taken whole or not at all. What a caller waits for is
// a datagram to arrive, which is the socket calls' queue again.

/// Datagram sockets that may hold a port at once. Each is one entry of [`PORTS`].
const DATAGRAM_PORTS: usize = 8;

/// The local ports datagram sockets hold, zero for a free entry. Two sockets cannot hold one
/// port, and [`ephemeral`] hands out none of these.
static PORTS: [AtomicU32; DATAGRAM_PORTS] = [const { AtomicU32::new(0) }; DATAGRAM_PORTS];

/// Where [`ephemeral`] looks first, seeded from the clock when the first socket asks. Two boots
/// of one machine start from different ports, so a datagram still in flight from the last one,
/// which QEMU's network may yet deliver, does not arrive on a socket of this one.
static NEXT_EPHEMERAL: AtomicU32 = AtomicU32::new(0);

/// The range [`ephemeral`] hands out, which is Linux's.
const EPHEMERAL_FIRST: u32 = 49152;
const EPHEMERAL_LAST: u32 = 65535;

/// Claim `port` for a datagram socket. `false` if another already holds it, or if no entry is
/// free.
fn claim_port(port: u16) -> bool {
    if port == 0
        || PORTS
            .iter()
            .any(|p| p.load(Ordering::Acquire) == u32::from(port))
    {
        return false;
    }
    PORTS.iter().any(|p| {
        p.compare_exchange(0, u32::from(port), Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    })
}

/// Give `port` back, and drop whatever was still waiting for it. Called when a datagram
/// socket's object is destroyed.
///
/// The inbox is shared by every port, and nothing else would ever take these: a datagram
/// addressed to a socket that is gone would hold its slot for the rest of the boot, and eight
/// of them would leave no room for anyone. A connected socket that passed over a datagram from
/// elsewhere, and then closed, is exactly how one gets there.
pub fn release_port(port: u16) {
    for p in &PORTS {
        if p.compare_exchange(u32::from(port), 0, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            break;
        }
    }
    let _ = crate::net::with_stack(|s, _, _| {
        let mut sink = [0u8; 1];
        while s.udp_recv_from(port, &mut sink).is_some() {}
    });
}

/// A free port to send from, for a socket that never bound one. `None` if every port in the
/// range is held, which takes [`DATAGRAM_PORTS`] sockets to arrange.
fn ephemeral() -> Option<u16> {
    let seeded = NEXT_EPHEMERAL.load(Ordering::Acquire);
    if seeded == 0 {
        let span = EPHEMERAL_LAST - EPHEMERAL_FIRST + 1;
        let seed = EPHEMERAL_FIRST + (timekeeping::now().as_nanos() % u64::from(span)) as u32;
        let _ = NEXT_EPHEMERAL.compare_exchange(0, seed, Ordering::AcqRel, Ordering::Acquire);
    }
    for _ in 0..=(EPHEMERAL_LAST - EPHEMERAL_FIRST) {
        let next = NEXT_EPHEMERAL.fetch_add(1, Ordering::AcqRel);
        let port = EPHEMERAL_FIRST
            + (next.wrapping_sub(EPHEMERAL_FIRST)) % (EPHEMERAL_LAST - EPHEMERAL_FIRST + 1);
        // The kernel's own check and the Linux program's listener own two ports of their own.
        if port == u32::from(crate::net::PORT) || port == 7777 {
            continue;
        }
        if claim_port(port as u16) {
            return Some(port as u16);
        }
    }
    None
}

/// Whether `id` names a datagram socket rather than a stream one: which calls it answers, and
/// which refuse it.
pub fn is_datagram(id: ObjectId) -> bool {
    objects::with(id, |o| matches!(o, Object::Datagram { .. })).unwrap_or(false)
}

/// A datagram socket's local port and the peer it connected to.
fn datagram_state(id: ObjectId) -> Result<(u16, Option<u64>), Error> {
    objects::with(id, |o| match o {
        Object::Datagram { port, peer } => Ok((*port, *peer)),
        _ => Err(Error::WrongType),
    })
    .ok_or(Error::BadHandle)?
}

/// A new datagram socket, neither bound nor connected.
pub fn datagram_create() -> Result<ObjectId, Error> {
    objects::create(Object::Datagram {
        port: 0,
        peer: None,
    })
    .ok_or(Error::Full)
}

/// Give socket `id` the port in `address` to receive on.
pub fn datagram_bind(id: ObjectId, address: u64) -> Result<u64, Error> {
    let (ip, port) = (abi::socket::ip(address), abi::socket::port(address));
    let ours = ip == [0; 4] || ip == crate::net::CONFIG.ip;
    if !abi::socket::well_formed(address) || port == 0 || !ours {
        return Err(Error::InvalidArgument);
    }
    if !claim_port(port) {
        return Err(Error::Full);
    }
    let bound = objects::with(id, |o| match o {
        Object::Datagram { port: slot, .. } if *slot == 0 => {
            *slot = port;
            true
        }
        _ => false,
    })
    .unwrap_or(false);
    if !bound {
        release_port(port);
        return Err(Error::InvalidArgument);
    }
    Ok(0)
}

/// Give socket `id` a port of its own if it has none, and answer with it.
fn port_of(id: ObjectId) -> Result<u16, Error> {
    let (port, _) = datagram_state(id)?;
    if port != 0 {
        return Ok(port);
    }
    let fresh = ephemeral().ok_or(Error::Full)?;
    let kept = objects::with(id, |o| match o {
        Object::Datagram { port: slot, .. } if *slot == 0 => {
            *slot = fresh;
            fresh
        }
        // It was given one while this call looked: that one stands, and this one goes back.
        Object::Datagram { port: slot, .. } => *slot,
        _ => 0,
    })
    .unwrap_or(0);
    if kept != fresh {
        release_port(fresh);
    }
    (kept != 0).then_some(kept).ok_or(Error::BadHandle)
}

/// Point socket `id` at `address`: what it sends to without one, and the only address its
/// datagrams are taken from.
pub fn datagram_connect(id: ObjectId, address: u64) -> Result<u64, Error> {
    if !abi::socket::well_formed(address) || abi::socket::port(address) == 0 {
        return Err(Error::InvalidArgument);
    }
    // Given a port here, so a connected socket's `getsockname` names one before it has sent.
    port_of(id)?;
    objects::with(id, |o| match o {
        Object::Datagram { peer, .. } => {
            *peer = Some(address);
            Ok(0)
        }
        _ => Err(Error::WrongType),
    })
    .ok_or(Error::BadHandle)?
}

/// Socket `id`'s local port, and the peer it connected to.
pub fn datagram_endpoints(id: ObjectId) -> Result<(u16, Option<u64>), Error> {
    datagram_state(id)
}

/// Send `data` from socket `id` to `address`, or to the peer it connected to when `address` is
/// zero. A socket that has no port is given one.
pub fn datagram_send(id: ObjectId, address: u64, data: &[u8]) -> Result<u64, Error> {
    if data.len() > MAX_DATAGRAM {
        return Err(Error::InvalidArgument);
    }
    let (_, peer) = datagram_state(id)?;
    let to = match (address, peer) {
        (0, Some(peer)) => peer,
        (0, None) => return Err(Error::InvalidArgument),
        (address, _) => address,
    };
    if !abi::socket::well_formed(to) || abi::socket::port(to) == 0 {
        return Err(Error::InvalidArgument);
    }
    // Here as well as in the receive: a program that sends steadily and receives rarely would
    // otherwise let kbuild's probes fill the inbox between its receives, and the reply it is
    // about to wait for would find no room. See `net::drain_probes`.
    crate::net::drain_probes();
    let port = port_of(id)?;
    let (ip, dst) = (abi::socket::ip(to), abi::socket::port(to));
    match stack(|s, card, t| s.udp_send(card, ip, port, dst, data, t))? {
        Ok(()) => Ok(data.len() as u64),
        // The next hop is not resolved yet, or every buffer is held: both pass with a poll,
        // which is what the caller's wait does between tries.
        Err(net::NetError::Unresolved | net::NetError::NoBuffer) => Err(Error::ShouldWait),
        Err(net::NetError::TooLarge) => Err(Error::InvalidArgument),
        Err(net::NetError::Nic) => Err(Error::Unsupported),
    }
}

/// Take the oldest datagram waiting for socket `id` into `into`: where it came from, the bytes
/// copied, and the length it had. `None` while none is waiting.
///
/// A connected socket passes over datagrams from anywhere but its peer, which are dropped as
/// they are taken: a datagram nobody asked for is not kept for someone who might.
pub fn datagram_recv(id: ObjectId, into: &mut [u8]) -> Result<Option<(u64, usize, usize)>, Error> {
    let (port, peer) = datagram_state(id)?;
    if port == 0 {
        // Nothing can have arrived: a socket with no port has never been addressable.
        return Ok(None);
    }
    // kbuild's probes land in the same inbox, and nothing else drains them once the boot's
    // checks are over; see `net::drain_probes`.
    crate::net::drain_probes();
    // A refusal the peer sent for a datagram of ours: the port it named is this one, and the
    // call that was waiting is the one it belongs to. Nothing on the networks these checks
    // run against ever sends one — see `net`'s notes on QEMU's user-mode stack — so this is
    // proven by host tests rather than by a boot.
    if stack(|s, _, _| s.take_refusal(port))? {
        return Err(Error::PeerClosed);
    }
    stack(|s, _, _| {
        loop {
            let (ip, src, copied, whole) = s.udp_recv_from(port, into)?;
            let from = abi::socket::address(ip, src);
            match peer {
                Some(peer) if peer != from => continue,
                _ => return Some((from, copied, whole)),
            }
        }
    })
}

/// The socket the stress run's datagram rounds use: made once by [`datagram_setup`], before any
/// workload runs, and held for the whole run. Zero until then, which is never an identity the
/// store issues.
///
/// One socket rather than one a round, because the number of live objects is the whole
/// kernel's: a socket made and retired inside a round changes it while another workload's audit
/// is comparing it (`waits`), and that audit is right to call an object that appeared from
/// nowhere a leak. Held from before the first audit, it is part of what every audit sees.
static ROUND_SOCKET: AtomicU64 = AtomicU64::new(0);

/// Make that socket. Called once, before the workloads start; `false` if none could be made.
pub fn datagram_setup() -> bool {
    if ROUND_SOCKET.load(Ordering::Acquire) != 0 {
        return true;
    }
    let Ok(id) = datagram_create() else {
        return false;
    };
    if ROUND_SOCKET
        .compare_exchange(0, id.raw(), Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        // Another caller was first: this one goes back, so only ever one socket is held.
        objects::retire(id);
    }
    true
}

/// One request and its reply with kbuild's datagram service, through the socket above: what the
/// stress run exercises the datagram calls with, on a kernel thread rather than in a process.
pub fn datagram_round(service: u16, n: u32, timeout_ns: u64) -> bool {
    let raw = ROUND_SOCKET.load(Ordering::Acquire);
    if raw == 0 {
        return false;
    }
    datagram_exchange(ObjectId::from_raw(raw), service, n, timeout_ns)
}

/// Send round `n`'s request and wait for the reply that names it.
fn datagram_exchange(id: ObjectId, service: u16, n: u32, timeout_ns: u64) -> bool {
    let mut request = [0u8; 32];
    let request_len = crate::net::numbered(&mut request, crate::net::UDP_REQUEST, n);
    let mut expected = [0u8; 32];
    let expected_len = crate::net::numbered(&mut expected, crate::net::UDP_REPLY, n);
    let to = abi::socket::address(crate::net::GATEWAY, service);
    let give_up = timekeeping::now().saturating_add(Duration::from_nanos(timeout_ns));
    let mut sent = false;
    let mut got = [0u8; MAX_DATAGRAM];
    while timekeeping::now() < give_up {
        if !sent {
            sent = datagram_send(id, to, request.get(..request_len).unwrap_or(&[])).is_ok();
        } else {
            match datagram_recv(id, &mut got) {
                // A reply that names this round, whole: anything else on the port — a probe,
                // an answer to a round that timed out — is taken and passed over.
                Ok(Some((_, copied, whole))) if copied == whole => {
                    if got.get(..copied) == expected.get(..expected_len) {
                        return true;
                    }
                }
                Ok(_) => {}
                Err(_) => return false,
            }
        }
        sleep_until(timekeeping::now().saturating_add(POLL));
    }
    false
}

// ---- the check ----------------------------------------------------------------------------

/// The programs, embedded like `user/child`.
static TCP_ELF: &[u8] = include_bytes!(env!("KINTANE_USER_USERTCP"));
static UDP_ELF: &[u8] = include_bytes!(env!("KINTANE_USER_USERUDP"));

/// What `user/tcp-client` exits with when everything behaved. Mirrors its `SUCCESS`.
const SUCCESS: u64 = 0x7c;
/// What `user/udp-client` exits with when everything behaved. Mirrors its `SUCCESS`.
const UDP_SUCCESS: u64 = 0x7d;

/// The process slot, and the scheduler stack slots its thread runs on: `waits` has torn its
/// process down and reaped its threads by the time this runs.
const SLOT: usize = 0;
const STACKS: [usize; 3] = [1, 2, 3];

/// The longest the program gets: a handshake, a retransmission, a reply and two closes.
const PATIENCE: Duration = Duration::from_nanos(20_000_000_000);
/// How long the connection the program let go of gets to finish closing.
const SETTLE: Duration = Duration::from_nanos(10_000_000_000);
const POLL: Duration = Duration::from_nanos(5_000_000);

/// Run the check. On the boot thread, with the scheduler running.
pub fn check(c: &dyn EarlyConsole) -> Check {
    c.write_str("\n  sockets    ");
    objects::init();
    if !available() {
        if kconfig::QEMU_NET_TEST {
            c.write_str("NO STARTED NETWORK CARD, though the run attached one");
            return Check::Failed;
        }
        c.write_str("skipped: no network card");
        return Check::Skipped;
    }
    // From here on the card's handler runs the stack and wakes the socket calls' queue.
    let interrupt = crate::net::serve_by_interrupt();
    let Some(port) = crate::net::tcp_port() else {
        c.write_str("NO TCP PORT: the net check never heard kbuild announce one");
        return Check::Failed;
    };
    if userproc::with_frames(|f| f.alloc.stats().free).is_none() {
        c.write_str("skipped: no frames for processes");
        return Check::Skipped;
    }
    let Some(program) = userproc::parse(TCP_ELF) else {
        c.write_str("the TCP program does not load");
        return Check::Failed;
    };
    spawn::use_stacks(&STACKS);
    let frames_before = free_frames();
    let objects_before = objects::live();
    let before = crate::net::with_stack(|s, _, _| s.tcp_counters());
    let wakes_before = wakes();

    let address = abi::socket::address(crate::net::GATEWAY, port);
    let (started, code) = run(&program, TCP_ELF, address, 0);
    let woke = wakes().since(wakes_before);

    let ended = spawn::end_threads();
    if ended {
        userproc::teardown(SLOT);
    }
    // Then datagrams, on the slot and stacks the stream program's threads have just given up.
    let datagram = datagram_run();
    let datagram_ok = match datagram {
        Some(d) => d.code == Some(UDP_SUCCESS) && d.ended,
        // kbuild announces its datagram service beside its TCP service, so a run that heard
        // one and not the other heard half of what it was told.
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
        sleep_until(timekeeping::now().saturating_add(POLL));
    };
    let after = crate::net::with_stack(|s, _, _| s.tcp_counters());
    let (retransmits, established) = match (before, after) {
        (Some(b), Some(a)) => {
            (a.data_retransmits - b.data_retransmits, a.established - b.established)
        }
        _ => (0, 0),
    };
    let frames = frames_before.saturating_sub(free_frames());
    let leaked = objects::live().saturating_sub(objects_before);

    match code {
        Some(SUCCESS) => {
            c.write_str("tcp-client connected, sent, read its reply to kbuild's close")
        }
        Some(code) => {
            c.write_str("tcp-client exited ");
            write_hex(c, code);
            c.write_str(", WRONG");
        }
        None if !started => c.write_str("tcp-client NEVER STARTED"),
        None => c.write_str("tcp-client NEVER EXITED"),
    }
    c.write_str("; ");
    write_usize(c, established as usize);
    c.write_str(" established, ");
    write_usize(c, retransmits as usize);
    c.write_str(" data retransmits");
    if retransmits == 0 {
        c.write_str(", NONE, though kbuild drops the first data segment");
    }
    c.write_str("; waits woken by the card ");
    write_usize(c, woke.woken as usize);
    c.write_str(", armed for a TCP timer ");
    write_usize(c, woke.timers as usize);
    c.write_str(", polled ");
    write_usize(c, woke.polls as usize);
    // Where the card has an interrupt route, a wait is ended by it or by a TCP timer, never by
    // a look on a fixed interval.
    let woken_ok = !interrupt || (woke.woken > 0 && woke.polls == 0);
    if !interrupt {
        c.write_str(" (no interrupt route for the card)");
    } else if !woken_ok {
        c.write_str(", NOT WOKEN BY THE CARD'S INTERRUPT");
    }
    c.write_str("; ");
    match datagram {
        None => c.write_str("no datagram service was announced"),
        Some(d) => {
            match (d.started, d.code) {
                (false, _) => c.write_str("udp-client NEVER STARTED"),
                (true, None) => c.write_str("udp-client NEVER EXITED"),
                (true, Some(UDP_SUCCESS)) => c.write_str(
                    "udp-client: a reply from the service, a truncation reported whole, a foreign datagram refused, nothing on the quiet port",
                ),
                (true, Some(code)) => {
                    c.write_str("udp-client exited ");
                    write_hex(c, code);
                    c.write_str(", WRONG");
                }
            }
            if !d.ended {
                c.write_str(", A THREAD NEVER ENDED");
            }
            // What the stack made of it, so a datagram that never left is told from one that
            // left and was never answered.
            if let Some(counters) = crate::net::with_stack(|s, _, _| s.counters()) {
                c.write_str(" (");
                write_usize(c, counters.udp_sent as usize);
                c.write_str(" sent, ");
                write_usize(c, counters.udp_received as usize);
                c.write_str(" received, ");
                write_usize(c, counters.inbox_full as usize);
                c.write_str(" with the inbox full, ");
                write_usize(c, counters.no_buffer as usize);
                c.write_str(" for want of a buffer)");
            }
        }
    }
    c.write_str(if settled {
        "; closed in order, every buffer back"
    } else {
        "; THE CONNECTION NEVER FINISHED CLOSING, OR A BUFFER IS MISSING"
    });
    if !ended {
        c.write_str("; A THREAD NEVER ENDED, its process left in place");
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
        code == Some(SUCCESS)
            && established > 0
            && retransmits > 0
            && woken_ok
            && settled
            && ended
            && leaked == 0
            && frames == 0
            && datagram_ok,
    )
}

/// How the datagram program went.
#[derive(Clone, Copy)]
struct Datagram {
    started: bool,
    code: Option<u64>,
    /// Every thread ended, so its process was torn down.
    ended: bool,
}

/// Run `user/udp-client` against kbuild's datagram service and the port kbuild leaves unbound.
/// `None` where neither was announced, which is every run without kbuild on the other end.
///
/// Never inlined: this runs on the boot stack, under `check`'s own frame, and inlined its
/// locals — a parsed program among them — would sit there beside the stream phase's for the
/// whole check rather than being given back when it returns. The boot's stack-depth check
/// caught exactly that, at 90% of 16 KiB.
#[inline(never)]
fn datagram_run() -> Option<Datagram> {
    let (service, quiet) = (crate::net::udp_service_port()?, crate::net::quiet_port()?);
    let program = userproc::parse(UDP_ELF)?;
    spawn::use_stacks(&STACKS);
    let (started, code) = run(
        &program,
        UDP_ELF,
        abi::socket::address(crate::net::GATEWAY, service),
        abi::socket::address(crate::net::GATEWAY, quiet),
    );
    let ended = spawn::end_threads();
    if ended {
        userproc::teardown(SLOT);
    }
    Some(Datagram {
        started,
        code,
        ended,
    })
}

/// Build `program` from `image`, hand it the console and two addresses, start it, and wait for
/// it to end. Returns whether it started and the code it exited with.
fn run(
    program: &elf::Program,
    image: &'static [u8],
    first: u64,
    second: u64,
) -> (bool, Option<u64>) {
    if userproc::build(SLOT, program).is_none() {
        return (false, None);
    }
    let Some(p) = userproc::slot(SLOT) else {
        return (false, None);
    };
    p.image = Some(image);
    let Some(console) = p.console_handle() else {
        return (false, None);
    };
    let args = [console.raw() as usize, first as usize, second as usize, 0];
    let Some(main) = userproc::start(SLOT, 0, args) else {
        return (false, None);
    };
    let give_up = timekeeping::now().saturating_add(PATIENCE);
    while (preempt::alive(main) || userproc::threads_live(SLOT) != 0)
        && timekeeping::now() < give_up
    {
        sleep_until(timekeeping::now().saturating_add(POLL));
    }
    if preempt::alive(main) || userproc::threads_live(SLOT) != 0 {
        return (true, None);
    }
    // Every thread has ended, so nothing else borrows the process.
    (true, userproc::slot(SLOT).and_then(|p| p.exit))
}

fn free_frames() -> usize {
    userproc::with_frames(|f| f.alloc.stats().free).unwrap_or(0)
}

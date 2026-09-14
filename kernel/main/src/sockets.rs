//! Sockets: the network stack's TCP, as objects a program names with handles.
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
//! # Waiting
//!
//! Every call that can wait — connect, accept, send, receive, shutdown — blocks on [`WAITS`], a
//! Phase 6a wait queue, with the caller's timeout. Nothing wakes that queue when a frame arrives:
//! the card's interrupt does not reach it yet. Instead a waiter looks again every
//! [`LOOK_EVERY_NS`], polling the card and the stack as it does, and a timeout ends the wait as
//! for any other object. That is a poll with a blocked thread between looks, not a busy wait,
//! and it is stated here rather than dressed up as interrupt-driven.
//!
//! # Where Linux's calls would land
//!
//! No Linux socket call is implemented: the Linux personality answers each with `-ENOSYS`. When
//! it gains them, each is a thin layer over one of the native calls, as its file descriptors are
//! already a view over handles:
//!
//! * `socket(AF_INET, SOCK_STREAM, 0)` → `socket_create(STREAM)`, the descriptor naming the handle;
//! * `bind` → `socket_bind`, the `sockaddr_in` packed into one address word; `listen` →
//!   `socket_listen`; `accept` and `accept4` → `socket_accept`, with `O_NONBLOCK` a zero timeout
//!   and `ShouldWait` as `-EAGAIN`;
//! * `connect` → `socket_connect`, with `PeerClosed` as `-ECONNREFUSED` and `TimedOut` as
//!   `-ETIMEDOUT`;
//! * `send`, `sendto` without an address, and `write` → `socket_send`, looping past its 512-byte
//!   chunk; `recv`, `recvfrom` and `read` → `socket_recv`, whose zero at the end of the stream is
//!   Linux's too;
//! * `shutdown(SHUT_WR)` → `socket_shutdown`; `close` → `handle_close`.
//!
//! Socket options, `SHUT_RD`, datagram sockets, and readiness through `poll` or `epoll` need
//! more than exists.
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

use abi::Error;
use hal::EarlyConsole;
use kobject::ObjectId;
use net::tcp::{State, Status};
use net::{Conn, TcpError};
use time::Duration;

use crate::objects::{self, Object};
use crate::preempt::{self, sleep_until};
use crate::wait::WaitQueue;
use crate::{Check, spawn, timekeeping, userproc, write_hex, write_usize};

/// The most one send or receive moves: what the kernel copies on its own stack.
pub const CHUNK: usize = 512;

/// How often a waiting call looks at the network. See the module documentation.
pub const LOOK_EVERY_NS: u64 = 2_000_000;

/// Every socket call waits here.
static WAITS: WaitQueue = WaitQueue::new();

pub fn waits() -> &'static WaitQueue {
    &WAITS
}

/// When a waiting call must look again, whatever wakes it.
pub fn next_look() -> Option<u64> {
    Some(timekeeping::now().as_nanos().saturating_add(LOOK_EVERY_NS))
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
    stack(|s, card, t| s.tcp_shutdown(card, conn, t))?.map_err(error)
}

/// `Some` once everything `conn` sent, its FIN included, is acknowledged.
pub fn shut(conn: Conn) -> Result<Option<u64>, Error> {
    let status = stack(|s, _, _| s.tcp_status(conn))?.ok_or(Error::BadHandle)?;
    if let Some(e) = status.error {
        return Err(error(e));
    }
    Ok((status.fin_acknowledged && status.unacknowledged == 0).then_some(0))
}

/// Let go of a destroyed socket's connection: closed in order, and freed once it is over.
pub fn release(conn: u64) {
    let _ = crate::net::with_stack(|s, card, t| s.tcp_close(card, Conn::from_raw(conn), t));
}

// ---- the check ----------------------------------------------------------------------------

/// The program, embedded like `user/child`.
static TCP_ELF: &[u8] = include_bytes!(env!("KINTANE_USER_USERTCP"));

/// What `user/tcp-client` exits with when everything behaved. Mirrors its `SUCCESS`.
const SUCCESS: u64 = 0x7c;

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

    let address = abi::socket::address(crate::net::GATEWAY, port);
    let (started, code) = run(&program, address);

    let ended = spawn::end_threads();
    if ended {
        userproc::teardown(SLOT);
    }
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
            && settled
            && ended
            && leaked == 0
            && frames == 0,
    )
}

/// Build the program, hand it the console and kbuild's address, start it, and wait for it to
/// end. Returns whether it started and the code it exited with.
fn run(program: &elf::Program, address: u64) -> (bool, Option<u64>) {
    if userproc::build(SLOT, program).is_none() {
        return (false, None);
    }
    let Some(p) = userproc::slot(SLOT) else {
        return (false, None);
    };
    p.image = Some(TCP_ELF);
    let Some(console) = p.console_handle() else {
        return (false, None);
    };
    let args = [console.raw() as usize, address as usize, 0, 0];
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

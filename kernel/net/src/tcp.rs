//! TCP: reliable byte streams over the stack's IPv4, with retransmission on a timer.
//!
//! # What is implemented
//!
//! * **The state machine of RFC 793**, every state: an active open (SYN-SENT) and a passive one
//!   (LISTEN, SYN-RECEIVED) through the three-way handshake, including a simultaneous open; data in
//!   both directions with cumulative acknowledgements; an orderly close begun from either side, or
//!   both at once (FIN-WAIT-1, FIN-WAIT-2, CLOSING, TIME-WAIT; CLOSE-WAIT, LAST-ACK); and resets,
//!   sent and received.
//! * **Retransmission on a timer.** One timer per connection, armed while anything that occupies
//!   sequence space — a SYN, data, a FIN — is unacknowledged. When it runs out, sending goes back
//!   to the oldest unacknowledged byte and resends from there (go-back-N), the timeout doubles from
//!   [`RTO_INITIAL_NS`] up to [`RTO_MAX_NS`], and after [`RETRIES`] expirations in a row the
//!   connection is aborted with a reset and reports [`TcpError::TimedOut`].
//! * **Sequence checks.** A segment is acceptable only if it overlaps the receive window (RFC 793
//!   §3.9); one that is not is answered with an acknowledgement and dropped. A reset ends a
//!   connection only when its sequence number is exactly the next expected one; an in-window reset
//!   or SYN on a synchronised connection gets a challenge acknowledgement instead (RFC 5961 §3,
//!   §4). An acknowledgement for data never sent is answered and ignored.
//! * **A fixed receive window.** Each connection receives into a ring of [`RING`] bytes, and the
//!   window it advertises is that ring's free space, never scaled: no window-scale option is sent
//!   or understood. A window that had closed below one segment is announced again when the program
//!   reads.
//! * **The peer's window is respected**, and a window it shuts is probed one byte at a time on the
//!   retransmission timer.
//! * **The maximum segment size option**, sent on a SYN ([`MSS`]) and honoured when received; 536
//!   when the peer sends none (RFC 1122 §4.2.2.6).
//!
//! # What is not, stated rather than discovered
//!
//! * **No congestion control.** No slow start, no congestion window, no fast retransmit or fast
//!   recovery, no Nagle. The stated minimum is this: nothing is sent beyond the peer's window or
//!   beyond one segment of [`MSS`] at a time, a timeout sends one segment again from the oldest
//!   unacknowledged byte, and consecutive timeouts back off exponentially. On a real congested path
//!   that is not a good citizen; on QEMU's user network, whose far end is a host socket, it is
//!   enough to be correct.
//! * **No round-trip-time estimation.** The timeout starts at [`RTO_INITIAL_NS`] for every
//!   connection and only backs off; there is no smoothed estimate (RFC 6298), so Karn's rule holds
//!   trivially.
//! * **No out-of-order queue.** A segment that starts beyond the next expected byte is dropped and
//!   answered with an acknowledgement for what did arrive, so a reordered stream is repaired by the
//!   sender's retransmission. A segment that overlaps what arrived already is trimmed.
//! * **No delayed acknowledgements**: every segment that carries data or a FIN is acknowledged at
//!   once. **No urgent data, SACK, timestamps or window scaling.**
//! * **A short TIME-WAIT.** [`TIME_WAIT_NS`], not four minutes, and a connection in TIME-WAIT whose
//!   program has let go of it is given up early when every slot is needed. Its buffers are back in
//!   the pool the moment it enters TIME-WAIT; only its slot waits.
//! * **Initial sequence numbers** come from the clock mixed with the ports, not from the keyed hash
//!   RFC 6528 asks for, so they are predictable to an observer.
//!
//! # Memory
//!
//! [`CONNECTIONS`] slots, fixed. A connection that can carry data holds two buffers from the
//! stack's [`Pool`] for its whole life — a receive ring and a send ring — and gives both back
//! when it is closed and its program has let go of it ([`Tcp::reap`]). A listener holds none,
//! and a SYN waiting for its connection holds none either: its buffers are taken when the
//! connection is made, and a SYN that finds the pool empty is dropped for the peer to send
//! again. So at any moment the pool's books show exactly two buffers per connection that
//! holds rings, which [`Tcp::rings_held`] reports for an owner to check.
//!
//! # How it is driven
//!
//! Nothing here touches a device. [`crate::Stack`] hands each received segment to [`Tcp::input`],
//! which changes state and says what payload to copy into which ring ([`Deliver`]) — the frame and
//! the ring are both pool buffers, which the stack borrows together. The stack then asks each
//! connection for what it has to send ([`Tcp::next_segment`]) and sends it, and runs the timers
//! ([`Tcp::timers`]) with whatever clock its caller passes.

use crate::pool::Pool;
use crate::wire::{self, Ipv4Addr, TCP_ACK, TCP_FIN, TCP_PSH, TCP_RST, TCP_SYN, TcpHeader};

/// Connection slots, listeners included.
pub const CONNECTIONS: usize = 4;
/// Bytes in each receive and send ring: one pool buffer.
pub const RING: usize = wire::FRAME_MAX;
/// The largest segment payload this stack sends or announces: an Ethernet frame's worth.
pub const MSS: u16 = (wire::ETH_MTU - wire::IPV4_HEADER - wire::TCP_HEADER) as u16;
/// The segment size assumed for a peer that announces none (RFC 1122 §4.2.2.6).
const DEFAULT_MSS: u16 = 536;
/// The first retransmission timeout, and the most it backs off to.
pub const RTO_INITIAL_NS: u64 = 300_000_000;
pub const RTO_MAX_NS: u64 = 4_000_000_000;
/// Timeouts in a row after which a connection is given up.
pub const RETRIES: u32 = 7;
/// How long a connection stays in TIME-WAIT.
pub const TIME_WAIT_NS: u64 = 1_000_000_000;
/// Connections a listener holds that the program has not accepted yet, handshakes in
/// progress included.
pub const BACKLOG: usize = 2;
/// Resets for segments that match no connection, waiting to be sent.
const RESETS: usize = 4;
const EPHEMERAL_FIRST: u16 = 49152;
/// A ring holding no buffer.
const NO_BUFFER: usize = usize::MAX;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum State {
    Closed = 0,
    Listen,
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
}

impl State {
    /// This state's bit in [`Status::visited`].
    pub const fn bit(self) -> u16 {
        1 << self as u8
    }

    /// Whether both ends' initial sequence numbers are known.
    fn synchronized(self) -> bool {
        !matches!(self, State::Closed | State::Listen | State::SynSent | State::SynReceived)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TcpError {
    /// Every connection slot is taken, or the pool has no buffers for another connection.
    NoRoom,
    /// Another listener has the port, or no ephemeral port is free.
    PortInUse,
    /// The connection is gone: closed and reaped, and its slot perhaps reused.
    BadConnection,
    /// Not in this state: sending after a close, accepting on a connection that is not listening.
    WrongState,
    /// The peer refused the connection or reset it.
    Reset,
    /// Retransmissions ran out before the peer acknowledged.
    TimedOut,
    /// Nothing to read, no room to write, nothing to accept, or not connected yet.
    WouldBlock,
}

/// A connection, as its owner names it: a slot and the generation of whatever holds that slot,
/// so a name kept past its connection's end names nothing rather than a later connection.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Conn {
    index: usize,
    generation: u32,
}

impl Conn {
    /// A word that carries this name, for an owner that stores it opaquely.
    pub const fn raw(self) -> u64 {
        (self.index as u64) << 32 | self.generation as u64
    }

    pub const fn from_raw(raw: u64) -> Conn {
        Conn {
            index: (raw >> 32) as usize,
            generation: raw as u32,
        }
    }
}

/// What TCP has seen and done since the stack was made.
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub struct Counters {
    pub segments_in: u64,
    pub segments_out: u64,
    /// Active opens begun, and connections that reached ESTABLISHED either way.
    pub connects: u64,
    pub established: u64,
    /// Retransmission timer expirations that sent something again.
    pub retransmit_timeouts: u64,
    /// Segments carrying data sent a second time or more.
    pub data_retransmits: u64,
    /// Segments wholly or partly old, or outside the window: answered and dropped or trimmed.
    pub duplicates: u64,
    /// Segments that started beyond the next expected byte, dropped for want of a queue.
    pub out_of_order: u64,
    pub resets_sent: u64,
    pub resets_received: u64,
    /// SYNs dropped for want of a slot, a buffer or backlog room.
    pub syns_refused: u64,
    /// Connections given up after [`RETRIES`] timeouts.
    pub timeouts: u64,
}

/// A connection as its owner can see it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Status {
    pub state: State,
    /// Every state the connection has been in, as [`State::bit`]s.
    pub visited: u16,
    pub error: Option<TcpError>,
    /// Bytes waiting to be read.
    pub readable: usize,
    /// Room in the send ring, or zero where sending is no longer allowed.
    pub writable: usize,
    /// Bytes in the send ring: not yet sent, or sent and not acknowledged.
    pub unacknowledged: usize,
    /// The peer's FIN has arrived: once `readable` is zero, a read reports the end.
    pub peer_closed: bool,
    /// This end's FIN has been sent and acknowledged.
    pub fin_acknowledged: bool,
}

/// A segment for the stack to send.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Segment {
    pub remote_ip: Ipv4Addr,
    pub header: TcpHeader,
    /// The payload: which pool buffer holds the send ring, where in it the payload starts,
    /// and how long it is. It may wrap around the ring's end.
    pub data: Option<(usize, usize, usize)>,
}

/// Payload [`Tcp::input`] accepted: copy `len` bytes from offset `from` in the received frame
/// to position `at` of the ring in pool buffer `ring`, wrapping at its end.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Deliver {
    pub ring: usize,
    pub at: usize,
    pub from: usize,
    pub len: usize,
}

#[derive(Clone, Copy)]
struct Ring {
    buf: usize,
    head: usize,
    len: usize,
}

impl Ring {
    const NONE: Ring = Ring {
        buf: NO_BUFFER,
        head: 0,
        len: 0,
    };

    const fn on(buf: usize) -> Ring {
        Ring {
            buf,
            head: 0,
            len: 0,
        }
    }

    fn free(&self) -> usize {
        if self.buf == NO_BUFFER {
            0
        } else {
            RING - self.len
        }
    }
}

#[derive(Clone, Copy)]
struct Tcb {
    active: bool,
    generation: u32,
    state: State,
    visited: u16,
    local_port: u16,
    remote_ip: Ipv4Addr,
    remote_port: u16,
    iss: u32,
    /// The oldest unacknowledged sequence number, the next to send, and the highest sent.
    snd_una: u32,
    snd_nxt: u32,
    snd_max: u32,
    snd_wnd: u16,
    mss: u16,
    rcv_nxt: u32,
    rx: Ring,
    tx: Ring,
    /// The sequence number of the send ring's first byte.
    tx_seq: u32,
    /// The program has closed its end: a FIN follows the data in the send ring.
    fin_queued: bool,
    /// The sequence number the FIN was given, once it has been sent.
    fin_seq: Option<u32>,
    peer_fin: bool,
    ack_now: bool,
    rst_now: bool,
    rto: u64,
    deadline: Option<u64>,
    /// The peer's window is shut and the timer ran out: send one byte past it.
    probe: bool,
    retries: u32,
    time_wait_until: u64,
    error: Option<TcpError>,
    /// The owner has let go: the slot and its buffers are freed once the connection is over.
    released: bool,
    /// The listener a passively opened connection belongs to until it is accepted.
    parent: Option<usize>,
    accepted: bool,
}

const EMPTY: Tcb = Tcb {
    active: false,
    generation: 0,
    state: State::Closed,
    visited: 0,
    local_port: 0,
    remote_ip: [0; 4],
    remote_port: 0,
    iss: 0,
    snd_una: 0,
    snd_nxt: 0,
    snd_max: 0,
    snd_wnd: 0,
    mss: DEFAULT_MSS,
    rcv_nxt: 0,
    rx: Ring::NONE,
    tx: Ring::NONE,
    tx_seq: 0,
    fin_queued: false,
    fin_seq: None,
    peer_fin: false,
    ack_now: false,
    rst_now: false,
    rto: RTO_INITIAL_NS,
    deadline: None,
    probe: false,
    retries: 0,
    time_wait_until: 0,
    error: None,
    released: false,
    parent: None,
    accepted: false,
};

/// A SYN for a listener, waiting for the stack to make its connection.
#[derive(Clone, Copy)]
pub struct Syn {
    listener: usize,
    remote_ip: Ipv4Addr,
    remote_port: u16,
    local_port: u16,
    irs: u32,
    window: u16,
    mss: u16,
}

/// `a` comes before `b` in sequence space.
fn lt(a: u32, b: u32) -> bool {
    a != b && b.wrapping_sub(a) < 1 << 31
}

fn le(a: u32, b: u32) -> bool {
    a == b || lt(a, b)
}

/// Whether a segment of `len` at `seq` overlaps a window of `wnd` at `rcv_nxt` (RFC 793 §3.9).
/// With the window shut, only a segment at exactly `rcv_nxt` is let through, so its
/// acknowledgement and any reset are still seen (RFC 793 p69).
fn acceptable(rcv_nxt: u32, wnd: u32, seq: u32, len: u32) -> bool {
    let inside = |s: u32| s.wrapping_sub(rcv_nxt) < wnd;
    match (len, wnd) {
        (_, 0) => seq == rcv_nxt,
        (0, _) => inside(seq),
        _ => inside(seq) || inside(seq.wrapping_add(len - 1)),
    }
}

/// Copy `data` into `ring` from position `at`, wrapping at its end.
pub fn ring_write(ring: &mut [u8; RING], at: usize, data: &[u8]) {
    let at = at % RING;
    let data = &data[..data.len().min(RING)];
    let first = data.len().min(RING - at);
    ring[at..at + first].copy_from_slice(&data[..first]);
    ring[..data.len() - first].copy_from_slice(&data[first..]);
}

/// Fill `into` from `ring` starting at position `at`, wrapping at its end.
pub fn ring_read(ring: &[u8; RING], at: usize, into: &mut [u8]) {
    let at = at % RING;
    let n = into.len().min(RING);
    let first = n.min(RING - at);
    into[..first].copy_from_slice(&ring[at..at + first]);
    into[first..n].copy_from_slice(&ring[..n - first]);
}

/// Take two buffers, or none.
fn take_two(pool: &mut Pool) -> Option<(usize, usize)> {
    let a = pool.take()?;
    match pool.take() {
        Some(b) => Some((a, b)),
        None => {
            pool.give(a);
            None
        }
    }
}

impl Tcb {
    fn enter(&mut self, state: State) {
        self.state = state;
        self.visited |= state.bit();
        if matches!(state, State::Closed | State::TimeWait) {
            self.deadline = None;
        }
    }

    fn established(&mut self, counters: &mut Counters) {
        self.enter(State::Established);
        counters.established += 1;
        if self.fin_queued {
            self.enter(State::FinWait1);
        }
    }

    /// Account for sending `n` units of sequence space from `snd_nxt`.
    fn advance(&mut self, n: usize, now: u64) {
        self.snd_nxt = self.snd_nxt.wrapping_add(n as u32);
        if lt(self.snd_max, self.snd_nxt) {
            self.snd_max = self.snd_nxt;
        }
        if self.deadline.is_none() {
            self.deadline = Some(now.saturating_add(self.rto));
        }
    }

    /// Take in an acknowledgement for `ack`, which lies after `snd_una` and no later than
    /// `snd_max`.
    fn acknowledge(&mut self, ack: u32, now: u64) {
        let mut n = ack.wrapping_sub(self.snd_una) as usize;
        if self.snd_una == self.iss {
            // The SYN's one unit of sequence space.
            n -= 1;
        }
        let data = n.min(self.tx.len);
        self.tx.head = (self.tx.head + data) % RING;
        self.tx.len -= data;
        self.tx_seq = self.tx_seq.wrapping_add(data as u32);
        self.snd_una = ack;
        if lt(self.snd_nxt, ack) {
            self.snd_nxt = ack;
        }
        self.retries = 0;
        self.rto = RTO_INITIAL_NS;
        self.probe = false;
        self.deadline = if self.snd_una == self.snd_max {
            None
        } else {
            Some(now.saturating_add(self.rto))
        };
    }

    fn fin_acknowledged(&self) -> bool {
        self.fin_seq
            .is_some_and(|f| le(f.wrapping_add(1), self.snd_una))
    }

    fn matches(&self, src: Ipv4Addr, seg: &wire::Tcp<'_>) -> bool {
        self.active
            && self.state != State::Listen
            && self.local_port == seg.dst_port
            && self.remote_port == seg.src_port
            && self.remote_ip == src
    }
}

/// What one segment did to its connection, beyond its state.
#[derive(Default)]
struct Outcome {
    deliver: Option<Deliver>,
    /// Answer with a reset, as for a segment no connection could take.
    reset: bool,
}

/// Every connection, and what is waiting to be sent for segments that matched none.
pub struct Tcp {
    tcbs: [Tcb; CONNECTIONS],
    syns: [Option<Syn>; BACKLOG],
    resets: [Option<Segment>; RESETS],
    next_port: u16,
    counters: Counters,
}

impl Default for Tcp {
    fn default() -> Self {
        Self::new()
    }
}

impl Tcp {
    pub const fn new() -> Tcp {
        Tcp {
            tcbs: [EMPTY; CONNECTIONS],
            syns: [None; BACKLOG],
            resets: [None; RESETS],
            // Zero until the first connection chooses where to start: see `ephemeral`.
            next_port: 0,
            counters: Counters {
                segments_in: 0,
                segments_out: 0,
                connects: 0,
                established: 0,
                retransmit_timeouts: 0,
                data_retransmits: 0,
                duplicates: 0,
                out_of_order: 0,
                resets_sent: 0,
                resets_received: 0,
                syns_refused: 0,
                timeouts: 0,
            },
        }
    }

    pub fn counters(&self) -> Counters {
        self.counters
    }

    /// Count a segment the stack handed to the device.
    pub fn sent(&mut self) {
        self.counters.segments_out += 1;
    }

    fn get(&self, c: Conn) -> Result<&Tcb, TcpError> {
        self.tcbs
            .get(c.index)
            .filter(|t| t.active && t.generation == c.generation)
            .ok_or(TcpError::BadConnection)
    }

    fn get_mut(&mut self, c: Conn) -> Result<&mut Tcb, TcpError> {
        self.tcbs
            .get_mut(c.index)
            .filter(|t| t.active && t.generation == c.generation)
            .ok_or(TcpError::BadConnection)
    }

    /// Pool buffers connections hold as rings right now.
    pub fn rings_held(&self) -> usize {
        self.tcbs
            .iter()
            .filter(|t| t.active)
            .map(|t| usize::from(t.rx.buf != NO_BUFFER) + usize::from(t.tx.buf != NO_BUFFER))
            .sum()
    }

    /// Slots in use, listeners and TIME-WAIT included.
    pub fn slots_in_use(&self) -> usize {
        self.tcbs.iter().filter(|t| t.active).count()
    }

    pub fn status(&self, c: Conn) -> Option<Status> {
        let t = self.get(c).ok()?;
        let open = matches!(t.state, State::Established | State::CloseWait) && !t.fin_queued;
        Some(Status {
            state: t.state,
            visited: t.visited,
            error: t.error,
            readable: t.rx.len,
            writable: if open { t.tx.free() } else { 0 },
            unacknowledged: t.tx.len,
            peer_closed: t.peer_fin,
            fin_acknowledged: t.fin_acknowledged(),
        })
    }

    /// `c`'s local port, and its peer's address and port.
    pub fn endpoints(&self, c: Conn) -> Option<(u16, Ipv4Addr, u16)> {
        let t = self.get(c).ok()?;
        Some((t.local_port, t.remote_ip, t.remote_port))
    }

    /// Whether a listener is on `port`.
    pub fn listening(&self, port: u16) -> bool {
        self.tcbs
            .iter()
            .any(|t| t.active && t.state == State::Listen && t.local_port == port)
    }

    /// The earliest instant any timer runs out, for an owner deciding how long to sleep.
    pub fn next_deadline(&self) -> Option<u64> {
        self.tcbs
            .iter()
            .filter(|t| t.active)
            .flat_map(|t| {
                let wait = (t.state == State::TimeWait).then_some(t.time_wait_until);
                [t.deadline, wait]
            })
            .flatten()
            .min()
    }

    /// A free slot, giving up the TIME-WAIT connection nearest its end if none is.
    fn slot(&mut self) -> Option<usize> {
        if let Some(i) = self.tcbs.iter().position(|t| !t.active) {
            return Some(i);
        }
        let i = self
            .tcbs
            .iter()
            .enumerate()
            .filter(|(_, t)| {
                t.state == State::TimeWait
                    && t.released
                    && t.rx.buf == NO_BUFFER
                    && t.tx.buf == NO_BUFFER
            })
            .min_by_key(|(_, t)| t.time_wait_until)
            .map(|(i, _)| i)?;
        self.tcbs[i].active = false;
        Some(i)
    }

    fn port_in_use(&self, port: u16) -> bool {
        self.tcbs.iter().any(|t| t.active && t.local_port == port)
    }

    /// A free ephemeral port. The first is chosen from the clock at the first connection, so a
    /// machine that restarts does not open its first connections from the ports it used last
    /// time, which the peer may still hold, in TIME-WAIT or otherwise; after that they are taken
    /// in turn.
    fn ephemeral(&mut self, now: u64) -> Option<u16> {
        if self.next_port == 0 {
            let span = u64::from(u16::MAX - EPHEMERAL_FIRST) + 1;
            let offset = now.wrapping_mul(0x9e37_79b9_7f4a_7c15) % span;
            self.next_port = EPHEMERAL_FIRST + offset as u16;
        }
        for _ in EPHEMERAL_FIRST..=u16::MAX {
            let port = self.next_port;
            self.next_port = if port == u16::MAX {
                EPHEMERAL_FIRST
            } else {
                port + 1
            };
            if !self.port_in_use(port) {
                return Some(port);
            }
        }
        None
    }

    /// The initial sequence number: RFC 793's clock, a tick every four microseconds, mixed with
    /// the ports. Predictable; see the module documentation.
    fn iss(now: u64, local: u16, remote: u16) -> u32 {
        let clock = (now / 4_000) as u32;
        clock ^ (u32::from(local) << 16 | u32::from(remote)).wrapping_mul(0x9e37_79b9)
    }

    /// Fill slot `i` with a fresh connection and return its name.
    fn install(&mut self, i: usize, tcb: Tcb) -> Conn {
        let generation = self.tcbs[i].generation.wrapping_add(1);
        self.tcbs[i] = Tcb {
            generation,
            active: true,
            ..tcb
        };
        Conn {
            index: i,
            generation,
        }
    }

    /// Begin an active open to `remote_ip`:`remote_port` from an ephemeral port. The SYN goes
    /// out with the stack's next flush.
    pub fn connect(
        &mut self,
        pool: &mut Pool,
        remote_ip: Ipv4Addr,
        remote_port: u16,
        now: u64,
    ) -> Result<Conn, TcpError> {
        let i = self.slot().ok_or(TcpError::NoRoom)?;
        let port = self.ephemeral(now).ok_or(TcpError::PortInUse)?;
        let (rx, tx) = take_two(pool).ok_or(TcpError::NoRoom)?;
        let iss = Self::iss(now, port, remote_port);
        self.counters.connects += 1;
        Ok(self.install(
            i,
            Tcb {
                state: State::SynSent,
                visited: State::SynSent.bit(),
                local_port: port,
                remote_ip,
                remote_port,
                iss,
                snd_una: iss,
                snd_nxt: iss,
                snd_max: iss,
                tx_seq: iss.wrapping_add(1),
                rx: Ring::on(rx),
                tx: Ring::on(tx),
                ..EMPTY
            },
        ))
    }

    /// Listen on `port`.
    pub fn listen(&mut self, port: u16) -> Result<Conn, TcpError> {
        let taken = self
            .tcbs
            .iter()
            .any(|t| t.active && t.state == State::Listen && t.local_port == port);
        if port == 0 || taken {
            return Err(TcpError::PortInUse);
        }
        let i = self.slot().ok_or(TcpError::NoRoom)?;
        Ok(self.install(
            i,
            Tcb {
                state: State::Listen,
                visited: State::Listen.bit(),
                local_port: port,
                ..EMPTY
            },
        ))
    }

    /// A connection `listener` has completed the handshake for, taken off its backlog.
    pub fn accept(&mut self, listener: Conn) -> Result<Conn, TcpError> {
        if self.get(listener)?.state != State::Listen {
            return Err(TcpError::WrongState);
        }
        let i = self
            .tcbs
            .iter()
            .position(|t| {
                t.active
                    && t.parent == Some(listener.index)
                    && !t.accepted
                    && t.state.synchronized()
            })
            .ok_or(TcpError::WouldBlock)?;
        let t = &mut self.tcbs[i];
        t.accepted = true;
        t.parent = None;
        Ok(Conn {
            index: i,
            generation: t.generation,
        })
    }

    /// Queue as much of `data` as the send ring has room for. The stack's next flush sends it.
    pub fn send(&mut self, pool: &mut Pool, c: Conn, data: &[u8]) -> Result<usize, TcpError> {
        let t = self.get_mut(c)?;
        if let Some(e) = t.error {
            return Err(e);
        }
        match t.state {
            State::Established | State::CloseWait if !t.fin_queued => {}
            State::SynSent | State::SynReceived if !t.fin_queued => {
                return Err(TcpError::WouldBlock);
            }
            _ => return Err(TcpError::WrongState),
        }
        let n = data.len().min(t.tx.free());
        if n == 0 {
            return if data.is_empty() {
                Ok(0)
            } else {
                Err(TcpError::WouldBlock)
            };
        }
        let ring = pool.buffer(t.tx.buf).ok_or(TcpError::BadConnection)?;
        ring_write(ring, t.tx.head + t.tx.len, &data[..n]);
        t.tx.len += n;
        Ok(n)
    }

    /// Read what has arrived into `into`. Zero is the end of the stream: the peer's FIN has
    /// arrived and everything before it has been read.
    pub fn recv(&mut self, pool: &mut Pool, c: Conn, into: &mut [u8]) -> Result<usize, TcpError> {
        let t = self.get_mut(c)?;
        let n = into.len().min(t.rx.len);
        if n > 0 {
            let ring = pool.buffer(t.rx.buf).ok_or(TcpError::BadConnection)?;
            ring_read(ring, t.rx.head, &mut into[..n]);
            let before = t.rx.free();
            t.rx.head = (t.rx.head + n) % RING;
            t.rx.len -= n;
            // A window that had shrunk below a segment is announced open again; otherwise a
            // peer waiting on it waits for its own probe.
            let segment = usize::from(MSS);
            if before < segment && t.rx.free() >= segment {
                t.ack_now = true;
            }
            return Ok(n);
        }
        if into.is_empty() || t.peer_fin {
            return Ok(0);
        }
        if let Some(e) = t.error {
            return Err(e);
        }
        match t.state {
            State::Listen => Err(TcpError::WrongState),
            State::Closed | State::TimeWait => Ok(0),
            _ => Err(TcpError::WouldBlock),
        }
    }

    /// Close this end for sending: a FIN follows whatever is still in the send ring. Reading
    /// goes on until the peer closes too.
    pub fn shutdown(&mut self, c: Conn) -> Result<(), TcpError> {
        let t = self.get_mut(c)?;
        match t.state {
            State::Listen => t.enter(State::Closed),
            State::SynSent | State::SynReceived => t.fin_queued = true,
            State::Established => {
                t.fin_queued = true;
                t.enter(State::FinWait1);
            }
            State::CloseWait => {
                t.fin_queued = true;
                t.enter(State::LastAck);
            }
            _ => {}
        }
        Ok(())
    }

    /// Let go of `c`: close it in order, and free its slot and buffers once it is over. Unread
    /// data makes it an abort, as RFC 1122 §4.2.2.13 asks, since a peer that thinks what it sent
    /// was delivered would be wrong. A listener's connections nobody accepted are reset.
    pub fn close(&mut self, c: Conn) -> Result<(), TcpError> {
        let t = self.get(c)?;
        if t.state == State::Listen {
            for child in self.tcbs.iter_mut() {
                if child.active && child.parent == Some(c.index) && !child.accepted {
                    child.rst_now = child.state != State::Closed;
                    child.enter(State::Closed);
                }
            }
        }
        let t = self.get_mut(c)?;
        if t.rx.len > 0 {
            return self.abort(c);
        }
        t.released = true;
        match t.state {
            State::SynSent | State::Listen => {
                t.enter(State::Closed);
                Ok(())
            }
            _ => self.shutdown(c),
        }
    }

    /// Reset `c` and let go of it.
    pub fn abort(&mut self, c: Conn) -> Result<(), TcpError> {
        let t = self.get_mut(c)?;
        t.rst_now = t.state.synchronized() || t.state == State::SynReceived;
        t.released = true;
        t.enter(State::Closed);
        Ok(())
    }

    /// Give back the buffers of connections that are over and let go of, and free their slots.
    /// A connection in TIME-WAIT gives its buffers back and keeps its slot until its timer runs
    /// out.
    pub fn reap(&mut self, pool: &mut Pool) {
        for t in self.tcbs.iter_mut().filter(|t| t.active) {
            let owned = t.released || (t.parent.is_some() && !t.accepted);
            let over = matches!(t.state, State::Closed | State::TimeWait) && !t.rst_now;
            if !(owned && over) {
                continue;
            }
            for ring in [&mut t.rx, &mut t.tx] {
                if ring.buf != NO_BUFFER {
                    pool.give(ring.buf);
                    *ring = Ring::NONE;
                }
            }
            if t.state == State::Closed {
                t.active = false;
            }
        }
    }

    /// Run the timers: TIME-WAIT's end, and retransmission.
    pub fn timers(&mut self, now: u64) {
        for t in self.tcbs.iter_mut().filter(|t| t.active) {
            if t.state == State::TimeWait && now >= t.time_wait_until {
                t.enter(State::Closed);
            }
            let Some(deadline) = t.deadline else {
                continue;
            };
            if now < deadline {
                continue;
            }
            if t.snd_una == t.snd_max {
                // Nothing in flight: this was the window probe's timer.
                t.probe = true;
                t.deadline = None;
                continue;
            }
            t.retries += 1;
            if t.retries > RETRIES {
                self.counters.timeouts += 1;
                t.error = Some(TcpError::TimedOut);
                t.rst_now = t.state.synchronized();
                t.enter(State::Closed);
                continue;
            }
            self.counters.retransmit_timeouts += 1;
            t.snd_nxt = t.snd_una;
            t.rto = t.rto.saturating_mul(2).min(RTO_MAX_NS);
            t.deadline = Some(now.saturating_add(t.rto));
        }
    }

    /// Take in a segment that arrived from `src`, whose payload starts `from` bytes into the
    /// frame it came in. Returns the copy the stack must make, if any payload was accepted.
    pub fn input(
        &mut self,
        src: Ipv4Addr,
        seg: &wire::Tcp<'_>,
        from: usize,
        now: u64,
    ) -> Option<Deliver> {
        self.counters.segments_in += 1;
        let Some(i) = self.tcbs.iter().position(|t| t.matches(src, seg)) else {
            self.unmatched(src, seg);
            return None;
        };
        let outcome = segment(&mut self.tcbs[i], &mut self.counters, seg, from, now);
        if outcome.reset {
            self.queue_reset(src, seg);
        }
        outcome.deliver
    }

    /// A segment for no connection: a SYN for a listener waits for its connection to be made,
    /// and anything else but a reset is answered with one.
    fn unmatched(&mut self, src: Ipv4Addr, seg: &wire::Tcp<'_>) {
        let flags = seg.flags;
        let listener = self
            .tcbs
            .iter()
            .position(|t| t.active && t.state == State::Listen && t.local_port == seg.dst_port);
        match listener {
            Some(listener) if flags & (TCP_SYN | TCP_ACK | TCP_RST) == TCP_SYN => {
                let syn = Syn {
                    listener,
                    remote_ip: src,
                    remote_port: seg.src_port,
                    local_port: seg.dst_port,
                    irs: seg.seq,
                    window: seg.window,
                    mss: seg.mss.unwrap_or(DEFAULT_MSS),
                };
                let repeat = self.syns.iter().flatten().any(|s| {
                    (s.remote_ip, s.remote_port, s.local_port)
                        == (syn.remote_ip, syn.remote_port, syn.local_port)
                });
                if repeat {
                    return;
                }
                match self.syns.iter_mut().find(|s| s.is_none()) {
                    Some(slot) => *slot = Some(syn),
                    None => self.counters.syns_refused += 1,
                }
            }
            _ => self.queue_reset(src, seg),
        }
    }

    /// Queue the reset RFC 793 answers a segment with, unless it was a reset itself.
    fn queue_reset(&mut self, src: Ipv4Addr, seg: &wire::Tcp<'_>) {
        if seg.flags & TCP_RST != 0 {
            return;
        }
        let (seq, ack, flags) = if seg.flags & TCP_ACK != 0 {
            (seg.ack, 0, TCP_RST)
        } else {
            let len = seg.payload.len() as u32
                + u32::from(seg.flags & TCP_SYN != 0)
                + u32::from(seg.flags & TCP_FIN != 0);
            (0, seg.seq.wrapping_add(len), TCP_RST | TCP_ACK)
        };
        let reset = Segment {
            remote_ip: src,
            header: TcpHeader {
                src_port: seg.dst_port,
                dst_port: seg.src_port,
                seq,
                ack,
                flags,
                window: 0,
                mss: None,
            },
            data: None,
        };
        if let Some(slot) = self.resets.iter_mut().find(|r| r.is_none()) {
            *slot = Some(reset);
        }
    }

    /// The next reset waiting to be sent for a segment that matched no connection.
    pub fn take_reset(&mut self) -> Option<Segment> {
        let reset = self.resets.iter_mut().find_map(Option::take)?;
        self.counters.resets_sent += 1;
        Some(reset)
    }

    /// The next SYN waiting for its connection.
    pub fn take_syn(&mut self) -> Option<Syn> {
        self.syns.iter_mut().find_map(Option::take)
    }

    /// Make the connection a waiting SYN asked for, in SYN-RECEIVED, with rings from `pool`.
    /// Returns whether it was made; a SYN that was not is dropped and counted, and the peer
    /// sends it again.
    pub fn open_passive(&mut self, pool: &mut Pool, syn: Syn, now: u64) -> bool {
        let listening = self.tcbs.get(syn.listener).is_some_and(|t| {
            t.active && t.state == State::Listen && t.local_port == syn.local_port
        });
        let waiting = self
            .tcbs
            .iter()
            .filter(|t| t.active && t.parent == Some(syn.listener) && !t.accepted)
            .count();
        if !listening || waiting >= BACKLOG {
            self.counters.syns_refused += 1;
            return false;
        }
        let Some(i) = self.slot() else {
            self.counters.syns_refused += 1;
            return false;
        };
        let Some((rx, tx)) = take_two(pool) else {
            self.counters.syns_refused += 1;
            return false;
        };
        let iss = Self::iss(now, syn.local_port, syn.remote_port);
        self.install(
            i,
            Tcb {
                state: State::SynReceived,
                visited: State::Listen.bit() | State::SynReceived.bit(),
                local_port: syn.local_port,
                remote_ip: syn.remote_ip,
                remote_port: syn.remote_port,
                iss,
                snd_una: iss,
                snd_nxt: iss,
                snd_max: iss,
                snd_wnd: syn.window,
                mss: syn.mss.clamp(1, MSS),
                rcv_nxt: syn.irs.wrapping_add(1),
                tx_seq: iss.wrapping_add(1),
                rx: Ring::on(rx),
                tx: Ring::on(tx),
                parent: Some(syn.listener),
                ..EMPTY
            },
        );
        true
    }

    /// The next segment connection slot `i` has to send, with its state updated as though it
    /// was sent: a segment the device then refuses is a lost segment, which retransmission
    /// repairs. `None` when it has nothing.
    pub fn next_segment(&mut self, i: usize, now: u64) -> Option<Segment> {
        let t = self.tcbs.get_mut(i).filter(|t| t.active)?;
        let window = t.rx.free().min(usize::from(u16::MAX)) as u16;
        let mut header = TcpHeader {
            src_port: t.local_port,
            dst_port: t.remote_port,
            seq: t.snd_nxt,
            ack: t.rcv_nxt,
            flags: TCP_ACK,
            window,
            mss: None,
        };
        let remote_ip = t.remote_ip;
        let plain = |header| {
            Some(Segment {
                remote_ip,
                header,
                data: None,
            })
        };
        if t.rst_now {
            t.rst_now = false;
            self.counters.resets_sent += 1;
            header.flags = TCP_RST | TCP_ACK;
            return plain(header);
        }
        match t.state {
            State::Closed | State::Listen => return None,
            State::SynSent | State::SynReceived => {
                t.ack_now = false;
                if t.snd_nxt != t.iss {
                    return None;
                }
                header.seq = t.iss;
                header.mss = Some(MSS);
                if t.state == State::SynSent {
                    header.flags = TCP_SYN;
                    header.ack = 0;
                } else {
                    header.flags = TCP_SYN | TCP_ACK;
                }
                t.advance(1, now);
                return plain(header);
            }
            _ => {}
        }
        let sending = matches!(
            t.state,
            State::Established
                | State::CloseWait
                | State::FinWait1
                | State::Closing
                | State::LastAck
        );
        if sending {
            let sent = t.snd_nxt.wrapping_sub(t.tx_seq) as usize;
            let unsent = t.tx.len.saturating_sub(sent);
            if unsent > 0 {
                let limit = t.snd_una.wrapping_add(u32::from(t.snd_wnd));
                let mut usable = if lt(t.snd_nxt, limit) {
                    limit.wrapping_sub(t.snd_nxt) as usize
                } else {
                    0
                };
                if usable == 0 && t.probe {
                    usable = 1;
                }
                let n = unsent.min(usable).min(usize::from(t.mss));
                if n > 0 {
                    t.probe = false;
                    t.ack_now = false;
                    if lt(t.snd_nxt, t.snd_max) {
                        self.counters.data_retransmits += 1;
                    }
                    header.flags = TCP_ACK | TCP_PSH;
                    let at = (t.tx.head + sent) % RING;
                    let ring = t.tx.buf;
                    t.advance(n, now);
                    return Some(Segment {
                        remote_ip,
                        header,
                        data: Some((ring, at, n)),
                    });
                }
                if t.deadline.is_none() {
                    // The window is shut with nothing in flight: probe when this runs out.
                    t.deadline = Some(now.saturating_add(t.rto));
                }
            }
            let drained = t.snd_nxt == t.tx_seq.wrapping_add(t.tx.len as u32);
            if t.fin_queued && drained && t.fin_seq.is_none_or(|f| f == t.snd_nxt) {
                t.ack_now = false;
                t.fin_seq = Some(t.snd_nxt);
                header.flags = TCP_FIN | TCP_ACK;
                t.advance(1, now);
                return plain(header);
            }
        }
        if t.ack_now {
            t.ack_now = false;
            return plain(header);
        }
        None
    }
}

/// Take in one segment for connection `t` (RFC 793 §3.9, "SEGMENT ARRIVES").
fn segment(
    t: &mut Tcb,
    counters: &mut Counters,
    seg: &wire::Tcp<'_>,
    from: usize,
    now: u64,
) -> Outcome {
    let syn = seg.flags & TCP_SYN != 0;
    let fin = seg.flags & TCP_FIN != 0;
    let rst = seg.flags & TCP_RST != 0;
    let ack = seg.flags & TCP_ACK != 0;
    let mut out = Outcome::default();

    if t.state == State::SynSent {
        if ack && seg.ack != t.iss.wrapping_add(1) {
            out.reset = !rst;
            return out;
        }
        if rst {
            if ack {
                counters.resets_received += 1;
                t.error = Some(TcpError::Reset);
                t.enter(State::Closed);
            }
            return out;
        }
        if !syn {
            return out;
        }
        t.rcv_nxt = seg.seq.wrapping_add(1);
        t.mss = seg.mss.unwrap_or(DEFAULT_MSS).clamp(1, MSS);
        t.snd_wnd = seg.window;
        t.ack_now = true;
        if ack {
            t.acknowledge(seg.ack, now);
            t.established(counters);
        } else {
            // Both ends opened at once: answer with our SYN again, acknowledging theirs.
            t.enter(State::SynReceived);
            t.snd_nxt = t.iss;
        }
        return out;
    }
    if matches!(t.state, State::Closed | State::Listen) {
        out.reset = !rst;
        return out;
    }

    let len = seg.payload.len() as u32 + u32::from(syn) + u32::from(fin);
    if !acceptable(t.rcv_nxt, t.rx.free() as u32, seg.seq, len) {
        if !rst {
            t.ack_now = true;
            if t.state == State::SynReceived && syn {
                // The peer did not see our SYN-ACK: send that again, not a bare acknowledgement.
                t.snd_nxt = t.iss;
            }
        }
        counters.duplicates += 1;
        return out;
    }
    if rst {
        if seg.seq == t.rcv_nxt {
            counters.resets_received += 1;
            t.error = Some(TcpError::Reset);
            t.enter(State::Closed);
        } else {
            t.ack_now = true;
        }
        return out;
    }
    if syn {
        t.ack_now = true;
        return out;
    }
    if !ack {
        return out;
    }
    if t.state == State::SynReceived {
        if !(lt(t.snd_una, seg.ack) && le(seg.ack, t.snd_max)) {
            out.reset = true;
            return out;
        }
        t.snd_wnd = seg.window;
        t.acknowledge(seg.ack, now);
        t.established(counters);
    } else if lt(t.snd_max, seg.ack) {
        t.ack_now = true;
        return out;
    } else {
        if lt(t.snd_una, seg.ack) {
            t.acknowledge(seg.ack, now);
        }
        if le(t.snd_una, seg.ack) {
            t.snd_wnd = seg.window;
        }
    }
    let fin_acked = t.fin_acknowledged();
    match t.state {
        State::FinWait1 if fin_acked => t.enter(State::FinWait2),
        State::Closing if fin_acked => {
            t.enter(State::TimeWait);
            t.time_wait_until = now.saturating_add(TIME_WAIT_NS);
        }
        State::LastAck if fin_acked => {
            t.enter(State::Closed);
            return out;
        }
        _ => {}
    }

    let mut taken_to = seg.seq.wrapping_add(seg.payload.len() as u32);
    let receiving = matches!(t.state, State::Established | State::FinWait1 | State::FinWait2);
    if !seg.payload.is_empty() && receiving {
        if lt(t.rcv_nxt, seg.seq) {
            // Ahead of what is expected, with no queue to hold it: acknowledge what did arrive,
            // and the sender's retransmission fills the gap.
            counters.out_of_order += 1;
            t.ack_now = true;
            return out;
        }
        let skip = t.rcv_nxt.wrapping_sub(seg.seq) as usize;
        if skip > 0 {
            counters.duplicates += 1;
        }
        let take = seg.payload.len().saturating_sub(skip).min(t.rx.free());
        if take > 0 {
            out.deliver = Some(Deliver {
                ring: t.rx.buf,
                at: (t.rx.head + t.rx.len) % RING,
                from: from + skip,
                len: take,
            });
            t.rx.len += take;
            t.rcv_nxt = t.rcv_nxt.wrapping_add(take as u32);
        }
        t.ack_now = true;
        taken_to = seg.seq.wrapping_add((skip + take) as u32);
    }
    let whole = taken_to == seg.seq.wrapping_add(seg.payload.len() as u32);
    if fin && whole && taken_to == t.rcv_nxt {
        t.rcv_nxt = t.rcv_nxt.wrapping_add(1);
        t.peer_fin = true;
        t.ack_now = true;
        match t.state {
            State::Established => t.enter(State::CloseWait),
            State::FinWait1 if fin_acked => t.enter(State::TimeWait),
            State::FinWait1 => t.enter(State::Closing),
            State::FinWait2 => t.enter(State::TimeWait),
            _ => {}
        }
        if t.state == State::TimeWait {
            t.time_wait_until = now.saturating_add(TIME_WAIT_NS);
        }
    }
    out
}

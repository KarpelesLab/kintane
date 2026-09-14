//! The stack: one interface, one address, one gateway, and the dispatch between the layers.

use crate::arp::Cache;
use crate::pool::Pool;
use crate::tcp::{self, Conn, Deliver, Segment, Tcp, TcpError};
use crate::wire::{
    self, ARP_REPLY, ARP_REQUEST, Arp, BROADCAST, ETH_HEADER, ETHERTYPE_ARP, ETHERTYPE_IPV4, Frame,
    ICMP_ECHO_REPLY, ICMP_ECHO_REQUEST, IPV4_HEADER, Ipv4Addr, Mac, PROTO_ICMP, PROTO_TCP,
    PROTO_UDP, UDP_HEADER, WireError,
};

/// What the stack needs from a network device.
pub trait Nic {
    /// The device's hardware address.
    fn mac(&self) -> Mac;

    /// Hand a complete frame, without its frame check sequence, to the device.
    fn send(&self, frame: &[u8]) -> Result<(), NicError>;

    /// Copy the next received frame into `into`, returning its length, or `None` when none
    /// is waiting.
    fn recv(&self, into: &mut [u8]) -> Option<usize>;
}

/// The device refused a frame: full, too large, or not running.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct NicError;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum NetError {
    /// The next hop's hardware address is not known yet; a request has been sent, and the
    /// caller tries again after polling.
    Unresolved,
    /// Every pool buffer is held.
    NoBuffer,
    /// The payload does not fit one frame.
    TooLarge,
    /// The device refused the frame.
    Nic,
}

/// One interface's addresses.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Config {
    pub ip: Ipv4Addr,
    pub netmask: Ipv4Addr,
    pub gateway: Ipv4Addr,
}

/// What the stack has seen and done. Every dropped frame is counted by why, so a check can
/// say which layer refused it rather than that nothing arrived.
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub struct Counters {
    pub rx_frames: u64,
    pub tx_frames: u64,
    pub arp_requests_sent: u64,
    pub arp_replies_sent: u64,
    pub arp_learned: u64,
    pub echo_replies_sent: u64,
    pub echo_replies_received: u64,
    pub udp_received: u64,
    pub udp_sent: u64,
    pub dropped_ethernet: u64,
    pub dropped_arp: u64,
    pub dropped_ipv4: u64,
    pub dropped_icmp: u64,
    pub dropped_udp: u64,
    pub dropped_tcp: u64,
    /// Addressed to another host, or a protocol this stack does not speak.
    pub not_for_us: u64,
    /// A datagram larger than the inbox holds, or with the inbox full.
    pub inbox_full: u64,
    /// A frame that could not be received or answered for want of a pool buffer.
    pub no_buffer: u64,
}

/// Echo replies remembered for a caller to collect.
const REPLIES: usize = 8;
/// Datagrams held for a caller to collect.
const INBOX: usize = 4;
/// The largest UDP payload the inbox keeps.
pub const UDP_MAX: usize = 256;
/// Frames one poll handles at most, so a flood cannot hold the caller's lock for ever.
const FRAMES_PER_POLL: usize = 16;
/// Segments one connection sends in one flush at most.
const SEGMENTS_PER_FLUSH: usize = 8;
/// How often an unanswered ARP request is repeated.
const ARP_RETRY_NS: u64 = 200_000_000;

#[derive(Clone, Copy)]
struct Datagram {
    src_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    len: usize,
    data: [u8; UDP_MAX],
}

/// Everything but the pool, so a received frame (in the pool) and the state it updates can
/// be borrowed at once.
struct State {
    config: Config,
    mac: Mac,
    arp: Cache,
    /// The last ARP request sent, and when, so an unanswered one is not repeated every poll.
    last_request: Option<(Ipv4Addr, u64)>,
    replies: [Option<(u16, u16, Ipv4Addr)>; REPLIES],
    /// The next slot [`State::replies`] overwrites when it is full.
    next_reply: usize,
    inbox: [Option<Datagram>; INBOX],
    counters: Counters,
    ip_id: u16,
    tcp: Tcp,
}

pub struct Stack {
    pool: Pool,
    st: State,
}

impl Stack {
    /// A stack for `config`. The hardware address is learned from the device at the first
    /// poll or send; a `const fn` so the stack can be a static rather than a boot-stack
    /// value, since its pool alone is several KiB.
    pub const fn new(config: Config) -> Stack {
        Stack::with_arp(config, Cache::new())
    }

    /// A stack with a given ARP cache, for tests of expiry.
    pub const fn with_arp(config: Config, arp: Cache) -> Stack {
        Stack {
            pool: Pool::new(),
            st: State {
                config,
                mac: [0; 6],
                arp,
                last_request: None,
                replies: [None; REPLIES],
                next_reply: 0,
                inbox: [None; INBOX],
                counters: Counters {
                    rx_frames: 0,
                    tx_frames: 0,
                    arp_requests_sent: 0,
                    arp_replies_sent: 0,
                    arp_learned: 0,
                    echo_replies_sent: 0,
                    echo_replies_received: 0,
                    udp_received: 0,
                    udp_sent: 0,
                    dropped_ethernet: 0,
                    dropped_arp: 0,
                    dropped_ipv4: 0,
                    dropped_icmp: 0,
                    dropped_udp: 0,
                    dropped_tcp: 0,
                    not_for_us: 0,
                    inbox_full: 0,
                    no_buffer: 0,
                },
                ip_id: 1,
                tcp: Tcp::new(),
            },
        }
    }

    pub fn config(&self) -> Config {
        self.st.config
    }

    pub fn counters(&self) -> Counters {
        self.st.counters
    }

    /// Pool buffers held right now.
    pub fn buffers_in_use(&self) -> usize {
        self.pool.in_use()
    }

    /// Pool buffers taken and returned since the stack was made.
    pub fn buffer_books(&self) -> (u64, u64) {
        self.pool.books()
    }

    /// Nothing held and every take returned: what an owner checks at a quiet moment.
    pub fn balanced(&self) -> bool {
        self.pool.balanced()
    }

    /// The live ARP entry for `ip`.
    pub fn arp_entry(&self, ip: Ipv4Addr, now: u64) -> Option<Mac> {
        self.st.arp.lookup(ip, now)
    }

    /// Forget `ip`'s hardware address, so the next [`resolve`](Self::resolve) asks for it.
    ///
    /// The retry limit is kept: forgetting is not a way to send requests faster than
    /// [`ARP_RETRY_NS`].
    pub fn forget(&mut self, ip: Ipv4Addr) {
        self.st.arp.forget(ip);
    }

    /// Receive and handle what the device has, answering what needs an answer, then run the
    /// TCP timers and send what every connection has to send. Returns how many frames were
    /// handled. Every buffer taken for a frame is given back before this returns; the only
    /// buffers still held are connections' rings.
    pub fn poll<N: Nic>(&mut self, nic: &N, now: u64) -> usize {
        self.st.mac = nic.mac();
        self.st.tcp.timers(now);
        let mut handled = 0;
        while handled < FRAMES_PER_POLL {
            let Some(rx) = self.pool.take() else {
                self.st.counters.no_buffer += 1;
                break;
            };
            // A reply buffer is optional: a frame that needs no answer is still handled
            // without one, and one that does is counted as refused for want of a buffer.
            let tx = self.pool.take();
            let got = match tx.and_then(|tx| self.pool.pair(rx, tx)) {
                Some((rx_buf, tx_buf)) => nic.recv(rx_buf).map(|len| {
                    self.st
                        .handle(nic, &rx_buf[..len.min(rx_buf.len())], Some(tx_buf), now)
                }),
                None => match self.pool.buffer(rx) {
                    Some(rx_buf) => nic.recv(rx_buf).map(|len| {
                        self.st
                            .handle(nic, &rx_buf[..len.min(rx_buf.len())], None, now)
                    }),
                    None => None,
                },
            };
            if let Some(Some(d)) = got {
                self.deliver(rx, d);
            }
            if let Some(tx) = tx {
                self.pool.give(tx);
            }
            self.pool.give(rx);
            if got.is_none() {
                break;
            }
            handled += 1;
        }
        self.tcp_flush(nic, now);
        handled
    }

    /// Copy a segment's accepted payload from the frame in pool buffer `rx` into its ring.
    fn deliver(&mut self, rx: usize, d: Deliver) {
        if let Some((frame, ring)) = self.pool.pair(rx, d.ring)
            && let Some(payload) = frame.get(d.from..d.from + d.len)
        {
            tcp::ring_write(ring, d.at, payload);
        }
    }

    /// Make connections for waiting SYNs, send what every connection has to send, send the
    /// resets owed, and give back the buffers of connections that are over.
    fn tcp_flush<N: Nic>(&mut self, nic: &N, now: u64) {
        while let Some(syn) = self.st.tcp.take_syn() {
            self.st.tcp.open_passive(&mut self.pool, syn, now);
        }
        for i in 0..tcp::CONNECTIONS {
            for _ in 0..SEGMENTS_PER_FLUSH {
                let Some(seg) = self.st.tcp.next_segment(i, now) else {
                    break;
                };
                self.send_segment(nic, &seg, now);
            }
        }
        while let Some(seg) = self.st.tcp.take_reset() {
            self.send_segment(nic, &seg, now);
        }
        self.st.tcp.reap(&mut self.pool);
    }

    /// Send one segment. A segment that cannot be sent — its next hop unresolved, no buffer,
    /// the device full — is lost, and retransmission sends it again.
    fn send_segment<N: Nic>(&mut self, nic: &N, seg: &Segment, now: u64) -> bool {
        let Some(mac) = self.resolve(nic, seg.remote_ip, now) else {
            return false;
        };
        let Some(tx) = self.pool.take() else {
            self.st.counters.no_buffer += 1;
            return false;
        };
        let (src, dst, h) = (self.st.config.ip, seg.remote_ip, seg.header);
        let result = match seg.data {
            Some((ring, at, len)) => match self.pool.pair(tx, ring) {
                Some((buf, ring)) => self.st.send_ip(nic, buf, mac, dst, PROTO_TCP, |p| {
                    let start = wire::tcp_header_len(&h);
                    let payload = p.get_mut(start..start + len).ok_or(WireError::TooLarge)?;
                    tcp::ring_read(ring, at, payload);
                    wire::write_tcp_header(p, src, dst, &h, len)
                }),
                None => Err(NetError::NoBuffer),
            },
            None => match self.pool.buffer(tx) {
                Some(buf) => self.st.send_ip(nic, buf, mac, dst, PROTO_TCP, |p| {
                    wire::write_tcp(p, src, dst, &h, &[])
                }),
                None => Err(NetError::NoBuffer),
            },
        };
        self.pool.give(tx);
        if result.is_ok() {
            self.st.tcp.sent();
        }
        result.is_ok()
    }

    // ---- TCP -------------------------------------------------------------------------------
    //
    // Each call changes the connection and then flushes, so what it queued is on the wire when
    // it returns, as far as the peer's window and the next hop allow.

    /// Open a connection to `dst`:`port`. It is usable once [`Stack::tcp_status`] shows it
    /// established.
    pub fn tcp_connect<N: Nic>(
        &mut self,
        nic: &N,
        dst: Ipv4Addr,
        port: u16,
        now: u64,
    ) -> Result<Conn, TcpError> {
        self.st.mac = nic.mac();
        let c = self.st.tcp.connect(&mut self.pool, dst, port, now)?;
        self.tcp_flush(nic, now);
        Ok(c)
    }

    /// Listen for connections on `port`.
    pub fn tcp_listen(&mut self, port: u16) -> Result<Conn, TcpError> {
        self.st.tcp.listen(port)
    }

    /// A connection that arrived on `listener`, or [`TcpError::WouldBlock`].
    pub fn tcp_accept(&mut self, listener: Conn) -> Result<Conn, TcpError> {
        self.st.tcp.accept(listener)
    }

    /// Queue as much of `data` as fits and send what the peer's window allows.
    pub fn tcp_send<N: Nic>(
        &mut self,
        nic: &N,
        c: Conn,
        data: &[u8],
        now: u64,
    ) -> Result<usize, TcpError> {
        self.st.mac = nic.mac();
        let n = self.st.tcp.send(&mut self.pool, c, data)?;
        self.tcp_flush(nic, now);
        Ok(n)
    }

    /// Read what has arrived; zero at the end of the stream. A read that opens a shut window
    /// announces it.
    pub fn tcp_recv<N: Nic>(
        &mut self,
        nic: &N,
        c: Conn,
        into: &mut [u8],
        now: u64,
    ) -> Result<usize, TcpError> {
        self.st.mac = nic.mac();
        let n = self.st.tcp.recv(&mut self.pool, c, into)?;
        self.tcp_flush(nic, now);
        Ok(n)
    }

    /// Send a FIN after what is queued; keep reading.
    pub fn tcp_shutdown<N: Nic>(&mut self, nic: &N, c: Conn, now: u64) -> Result<(), TcpError> {
        self.st.mac = nic.mac();
        self.st.tcp.shutdown(c)?;
        self.tcp_flush(nic, now);
        Ok(())
    }

    /// Let go of `c`, closing it in order; see [`tcp::Tcp::close`].
    pub fn tcp_close<N: Nic>(&mut self, nic: &N, c: Conn, now: u64) -> Result<(), TcpError> {
        self.st.mac = nic.mac();
        self.st.tcp.close(c)?;
        self.tcp_flush(nic, now);
        Ok(())
    }

    /// Reset `c` and let go of it.
    pub fn tcp_abort<N: Nic>(&mut self, nic: &N, c: Conn, now: u64) -> Result<(), TcpError> {
        self.st.mac = nic.mac();
        self.st.tcp.abort(c)?;
        self.tcp_flush(nic, now);
        Ok(())
    }

    pub fn tcp_status(&self, c: Conn) -> Option<tcp::Status> {
        self.st.tcp.status(c)
    }

    pub fn tcp_counters(&self) -> tcp::Counters {
        self.st.tcp.counters()
    }

    /// Pool buffers held as connections' rings. With nothing else using the stack, this is
    /// exactly [`Stack::buffers_in_use`].
    pub fn tcp_rings_held(&self) -> usize {
        self.st.tcp.rings_held()
    }

    /// Connection slots in use, listeners and TIME-WAIT included.
    pub fn tcp_slots_in_use(&self) -> usize {
        self.st.tcp.slots_in_use()
    }

    /// `c`'s local port, and its peer's address and port.
    pub fn tcp_endpoints(&self, c: Conn) -> Option<(u16, Ipv4Addr, u16)> {
        self.st.tcp.endpoints(c)
    }

    /// Whether a listener is on `port`.
    pub fn tcp_listening(&self, port: u16) -> bool {
        self.st.tcp.listening(port)
    }

    /// When the next TCP timer runs out, for a caller deciding how long it may sleep.
    pub fn tcp_next_deadline(&self) -> Option<u64> {
        self.st.tcp.next_deadline()
    }

    /// Every buffer that is held is a connection's ring, and the books agree with what is
    /// held: what an owner checks while connections are open.
    pub fn books_consistent(&self) -> bool {
        let (taken, returned) = self.pool.books();
        self.pool.in_use() == self.st.tcp.rings_held()
            && taken.checked_sub(returned) == Some(self.pool.in_use() as u64)
    }

    /// The next hop's hardware address for `ip`, sending a request (at most every
    /// [`ARP_RETRY_NS`]) when it is not known.
    pub fn resolve<N: Nic>(&mut self, nic: &N, ip: Ipv4Addr, now: u64) -> Option<Mac> {
        self.st.mac = nic.mac();
        let hop = self.st.next_hop(ip);
        if let Some(mac) = self.st.arp.lookup(hop, now) {
            return Some(mac);
        }
        let due = match self.st.last_request {
            Some((asked, at)) => asked != hop || now.saturating_sub(at) >= ARP_RETRY_NS,
            None => true,
        };
        if due {
            if let Some(tx) = self.pool.take() {
                if let Some(buf) = self.pool.buffer(tx) {
                    let request = Arp {
                        operation: ARP_REQUEST,
                        sender_mac: self.st.mac,
                        sender_ip: self.st.config.ip,
                        target_mac: [0; 6],
                        target_ip: hop,
                    };
                    if self.st.send_arp(nic, buf, BROADCAST, &request) {
                        self.st.counters.arp_requests_sent += 1;
                        self.st.last_request = Some((hop, now));
                    }
                }
                self.pool.give(tx);
            } else {
                self.st.counters.no_buffer += 1;
            }
        }
        None
    }

    /// Send an echo request to `dst`.
    pub fn ping<N: Nic>(
        &mut self,
        nic: &N,
        dst: Ipv4Addr,
        id: u16,
        seq: u16,
        now: u64,
    ) -> Result<(), NetError> {
        let mac = self.resolve(nic, dst, now).ok_or(NetError::Unresolved)?;
        let tx = self.pool.take().ok_or(NetError::NoBuffer)?;
        let result = match self.pool.buffer(tx) {
            Some(buf) => {
                let mut data = [0u8; 16];
                for (i, b) in data.iter_mut().enumerate() {
                    *b = (i as u8) ^ (seq as u8);
                }
                self.st.send_ip(nic, buf, mac, dst, PROTO_ICMP, |p| {
                    wire::write_icmp_echo(p, ICMP_ECHO_REQUEST, id, seq, &data)
                })
            }
            None => Err(NetError::NoBuffer),
        };
        self.pool.give(tx);
        result
    }

    /// The source of an echo reply with this id and sequence number, once one has arrived.
    /// Taking it forgets it.
    pub fn take_echo_reply(&mut self, id: u16, seq: u16) -> Option<Ipv4Addr> {
        let slot = self
            .st
            .replies
            .iter_mut()
            .find(|r| r.is_some_and(|(i, s, _)| i == id && s == seq))?;
        slot.take().map(|(_, _, from)| from)
    }

    /// Send a UDP datagram.
    pub fn udp_send<N: Nic>(
        &mut self,
        nic: &N,
        dst: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
        payload: &[u8],
        now: u64,
    ) -> Result<(), NetError> {
        if ETH_HEADER + IPV4_HEADER + UDP_HEADER + payload.len() > wire::FRAME_MAX {
            return Err(NetError::TooLarge);
        }
        let mac = self.resolve(nic, dst, now).ok_or(NetError::Unresolved)?;
        let tx = self.pool.take().ok_or(NetError::NoBuffer)?;
        let src = self.st.config.ip;
        let result = match self.pool.buffer(tx) {
            Some(buf) => self.st.send_ip(nic, buf, mac, dst, PROTO_UDP, |p| {
                wire::write_udp(p, src, dst, src_port, dst_port, payload)
            }),
            None => Err(NetError::NoBuffer),
        };
        if result.is_ok() {
            self.st.counters.udp_sent += 1;
        }
        self.pool.give(tx);
        result
    }

    /// The oldest datagram received for `port`, copied into `into`: its source address,
    /// source port and length. Taking it forgets it.
    pub fn udp_recv(&mut self, port: u16, into: &mut [u8]) -> Option<(Ipv4Addr, u16, usize)> {
        let slot = self
            .st
            .inbox
            .iter_mut()
            .find(|d| d.is_some_and(|d| d.dst_port == port))?;
        let d = slot.take()?;
        let n = d.len.min(into.len());
        into[..n].copy_from_slice(&d.data[..n]);
        Some((d.src_ip, d.src_port, n))
    }
}

impl State {
    fn next_hop(&self, ip: Ipv4Addr) -> Ipv4Addr {
        let on_link = (0..4)
            .all(|i| ip[i] & self.config.netmask[i] == self.config.ip[i] & self.config.netmask[i]);
        if on_link { ip } else { self.config.gateway }
    }

    /// Handle one received frame. Returns the payload copy a TCP segment needs, which the
    /// caller makes, since the frame and the connection's ring are both pool buffers.
    fn handle<N: Nic>(
        &mut self,
        nic: &N,
        frame: &[u8],
        tx: Option<&mut [u8; wire::FRAME_MAX]>,
        now: u64,
    ) -> Option<Deliver> {
        self.counters.rx_frames += 1;
        let (eth, inner) = match wire::parse_frame(frame) {
            Ok(parsed) => parsed,
            Err(e) => {
                self.count_drop(frame, e);
                return None;
            }
        };
        if eth.dst != self.mac && eth.dst != BROADCAST {
            self.counters.not_for_us += 1;
            return None;
        }
        if let Frame::Tcp(ip, seg) = inner {
            if ip.dst != self.config.ip {
                self.counters.not_for_us += 1;
                return None;
            }
            let from = (seg.payload.as_ptr() as usize).wrapping_sub(frame.as_ptr() as usize);
            return self.tcp.input(ip.src, &seg, from, now);
        }
        self.handle_other(nic, eth, inner, tx, now);
        None
    }

    fn handle_other<N: Nic>(
        &mut self,
        nic: &N,
        eth: wire::Ethernet<'_>,
        inner: Frame<'_>,
        tx: Option<&mut [u8; wire::FRAME_MAX]>,
        now: u64,
    ) {
        match inner {
            Frame::Arp(arp) => self.handle_arp(nic, &arp, tx, now),
            Frame::Echo(ip, echo) => {
                if ip.dst != self.config.ip {
                    self.counters.not_for_us += 1;
                } else if echo.kind == ICMP_ECHO_REQUEST {
                    let Some(buf) = tx else {
                        self.counters.no_buffer += 1;
                        return;
                    };
                    let (id, seq) = (echo.id, echo.seq);
                    let sent = self.send_ip(nic, buf, eth.src, ip.src, PROTO_ICMP, |p| {
                        wire::write_icmp_echo(p, ICMP_ECHO_REPLY, id, seq, echo.data)
                    });
                    if sent.is_ok() {
                        self.counters.echo_replies_sent += 1;
                    }
                } else {
                    self.counters.echo_replies_received += 1;
                    self.replies[self.next_reply] = Some((echo.id, echo.seq, ip.src));
                    self.next_reply = (self.next_reply + 1) % REPLIES;
                }
            }
            Frame::Udp(ip, udp) => {
                if ip.dst != self.config.ip {
                    self.counters.not_for_us += 1;
                    return;
                }
                let free = self.inbox.iter_mut().find(|d| d.is_none());
                match free {
                    Some(slot) if udp.payload.len() <= UDP_MAX => {
                        let mut data = [0u8; UDP_MAX];
                        data[..udp.payload.len()].copy_from_slice(udp.payload);
                        *slot = Some(Datagram {
                            src_ip: ip.src,
                            src_port: udp.src_port,
                            dst_port: udp.dst_port,
                            len: udp.payload.len(),
                            data,
                        });
                        self.counters.udp_received += 1;
                    }
                    _ => self.counters.inbox_full += 1,
                }
            }
            // Taken by `handle` before it gets here.
            Frame::Tcp(..) => {}
            Frame::OtherIpv4(_) | Frame::OtherEthernet(_) => self.counters.not_for_us += 1,
        }
    }

    fn handle_arp<N: Nic>(
        &mut self,
        nic: &N,
        arp: &Arp,
        tx: Option<&mut [u8; wire::FRAME_MAX]>,
        now: u64,
    ) {
        if arp.target_ip != self.config.ip {
            self.counters.not_for_us += 1;
            return;
        }
        // Whoever asked for, or answered about, this address is a neighbour worth knowing:
        // learning from a request is what saves the round trip of asking back.
        self.arp.insert(arp.sender_ip, arp.sender_mac, now);
        if arp.operation == ARP_REPLY {
            self.counters.arp_learned += 1;
            return;
        }
        let Some(buf) = tx else {
            self.counters.no_buffer += 1;
            return;
        };
        let reply = Arp {
            operation: ARP_REPLY,
            sender_mac: self.mac,
            sender_ip: self.config.ip,
            target_mac: arp.sender_mac,
            target_ip: arp.sender_ip,
        };
        if self.send_arp(nic, buf, arp.sender_mac, &reply) {
            self.counters.arp_replies_sent += 1;
        }
    }

    fn count_drop(&mut self, frame: &[u8], e: WireError) {
        let c = &mut self.counters;
        match wire::parse_ethernet(frame) {
            Err(_) => c.dropped_ethernet += 1,
            Ok(eth) => match (eth.ethertype, e) {
                (ETHERTYPE_ARP, _) => c.dropped_arp += 1,
                (ETHERTYPE_IPV4, _) => match wire::parse_ipv4(eth.payload) {
                    Err(_) => c.dropped_ipv4 += 1,
                    Ok(ip) if ip.protocol == PROTO_ICMP => c.dropped_icmp += 1,
                    Ok(ip) if ip.protocol == PROTO_TCP => c.dropped_tcp += 1,
                    Ok(_) => c.dropped_udp += 1,
                },
                _ => c.dropped_ethernet += 1,
            },
        }
    }

    fn send_arp<N: Nic>(
        &mut self,
        nic: &N,
        buf: &mut [u8; wire::FRAME_MAX],
        dst: Mac,
        arp: &Arp,
    ) -> bool {
        let written = wire::write_ethernet(buf, dst, self.mac, ETHERTYPE_ARP)
            .and_then(|()| wire::write_arp(&mut buf[ETH_HEADER..], arp));
        let Ok(n) = written else { return false };
        if nic.send(&buf[..ETH_HEADER + n]).is_ok() {
            self.counters.tx_frames += 1;
            true
        } else {
            false
        }
    }

    /// Build and send an IPv4 packet whose payload `body` writes.
    fn send_ip<N: Nic>(
        &mut self,
        nic: &N,
        buf: &mut [u8; wire::FRAME_MAX],
        dst_mac: Mac,
        dst: Ipv4Addr,
        protocol: u8,
        body: impl FnOnce(&mut [u8]) -> Result<usize, WireError>,
    ) -> Result<(), NetError> {
        let start = ETH_HEADER + IPV4_HEADER;
        let n = body(&mut buf[start..]).map_err(|_| NetError::TooLarge)?;
        self.ip_id = self.ip_id.wrapping_add(1);
        wire::write_ipv4(&mut buf[ETH_HEADER..], self.config.ip, dst, protocol, self.ip_id, n)
            .map_err(|_| NetError::TooLarge)?;
        wire::write_ethernet(buf, dst_mac, self.mac, ETHERTYPE_IPV4)
            .map_err(|_| NetError::TooLarge)?;
        nic.send(&buf[..start + n]).map_err(|_| NetError::Nic)?;
        self.counters.tx_frames += 1;
        Ok(())
    }
}

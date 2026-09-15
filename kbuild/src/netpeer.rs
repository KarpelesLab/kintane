//! kbuild as the whole network, for `QEMU_NET_PEER`.
//!
//! `-netdev dgram` hands us one raw Ethernet frame per datagram and expects the same back:
//! no NAT, no gateway, nothing that answers unless this module answers it. That is the
//! point — QEMU's user-mode network offers only `MSS` on a SYN and never sends an ICMP
//! destination-unreachable, so selective acknowledgement and a refused datagram cannot be
//! exercised in a guest behind it, however the frames in flight are mutated.
//!
//! Unlike [`crate::qemu`]'s relay chardevs, which are byte streams carrying a four-byte length
//! before each frame, a datagram *is* the frame: its length is the datagram's.
//!
//! Built in stages, because the guest's `net` check gates on three TCP rounds and an inbound
//! connection into its own listener — a TCP endpoint that both accepts and originates.
//!
//! - **Stage one** answered ARP and counted what crossed, which proved the socket carries
//!   frames both ways.
//! - **Stage two** was the datagram half: echo replies, the datagrams that tell the guest
//!   which ports to use, an acknowledgement for each echo it returns, a service that answers a
//!   request at the gateway's address, a port that answers nothing, and one datagram sent as two
//!   IPv4 fragments. Without a NAT there is nowhere else for those services to live: under
//!   `-netdev user` they are loopback sockets QEMU forwards to, and here the frames are all
//!   there is.
//! - **Stage three** was TCP accepting: the two close orders, and a bulk round whose dropped
//!   first segment leaves the three behind it drawing the duplicate acknowledgements the
//!   guest's fast retransmit needs.
//! - **Stage four** was the other direction: this end opens a connection into the guest's
//!   listener, sends the request that server waits for, judges its reply and closes. It is the
//!   last thing the `net` and `linux net` checks wait on.
//! - **Stage five**, here, is the pair of things the user-mode network cannot do at all:
//!   `SACK-permitted` on the SYN with selective acknowledgements behind it, so the guest's
//!   sending half resends the hole and steps over what this end says it holds; and an ICMP
//!   destination-unreachable for the quiet port, so a connected datagram socket is refused
//!   rather than left to time out. Both halves of the guest's selective acknowledgement were
//!   written against host tests and had never met a peer that asked for blocks or sent one.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use crate::qemu::{
    NET_ACK, NET_ECHO, NET_FRAGMENT_PATTERN, NET_GUEST_PORT, NET_GUEST_TCP_PORT, NET_PROBE,
    NET_TCP_ANNOUNCE, NET_TCP_INBOUND, NET_TCP_INBOUND_REPLY, NET_TCP_INBOUND_VERIFIED,
    NET_TCP_INBOUND_WRONG, NET_TCP_LISTENING, NET_TCP_REPLY, NET_TCP_REQUEST, NET_UDP_ANNOUNCE,
    NET_UDP_FRAGMENTED, NET_UDP_QUIET, NET_UDP_REPLY, NET_UDP_REQUEST, NetPorts, fragment_datagram,
    ipv4_checksum, ipv4_header,
};

/// The address the guest is configured to reach, and the hardware address this peer answers
/// from: `kernel/main/src/net.rs`'s `GATEWAY`, and the MAC QEMU's own gateway uses, so a guest
/// that hard-codes neither sees what it saw before.
const GATEWAY: [u8; 4] = [10, 0, 2, 2];
const PEER_MAC: [u8; 6] = [0x52, 0x55, 0x0a, 0x00, 0x02, 0x02];

/// The one guest's address: `kernel/main/src/net.rs`'s `CONFIG.ip`.
const GUEST: [u8; 4] = [10, 0, 2, 15];

const ETHERTYPE_ARP: [u8; 2] = [0x08, 0x06];
const ETHERTYPE_IPV4: [u8; 2] = [0x08, 0x00];
const ARP_REQUEST: u16 = 1;
const ARP_REPLY: u16 = 2;

const PROTO_ICMP: u8 = 1;
const PROTO_UDP: u8 = 17;
const PROTO_TCP: u8 = 6;

const TCP_FIN: u8 = 0x01;
const TCP_SYN: u8 = 0x02;
const TCP_RST: u8 = 0x04;
const TCP_PSH: u8 = 0x08;
const TCP_ACK: u8 = 0x10;

/// TCP option kinds, as `kernel/net/src/wire.rs` spells them.
const TCP_OPT_END: u8 = 0;
const TCP_OPT_NOP: u8 = 1;
const TCP_OPT_MSS: u8 = 2;
const TCP_OPT_SACK_PERMITTED: u8 = 4;
const TCP_OPT_SACK: u8 = 5;

/// Runs one selective acknowledgement names. Three, because that is what the guest's receiver
/// writes and reads (`wire::SACK_BLOCKS`), and a fourth would be ignored at the other end.
const SACK_BLOCKS: usize = 3;

/// The segment size this peer offers, which is the guest's own: both sit behind one
/// 1500-byte Ethernet, so neither has reason to offer less.
const PEER_MSS: u16 = 1460;

/// What this end advertises it can take. Large enough that the guest is never held back by
/// the receiver, since what the rounds measure is loss and reordering, not flow control.
const PEER_WINDOW: u16 = 0xffff;
const ICMP_ECHO_REQUEST: u8 = 8;
const ICMP_ECHO_REPLY: u8 = 0;
/// Destination unreachable, and the code that says the port has nobody on it (RFC 792). The
/// message quotes the offending IPv4 header and the eight bytes behind it, which for UDP is
/// the ports — and those are what name the socket the refusal belongs to.
const ICMP_UNREACHABLE: u8 = 3;
const ICMP_PORT_UNREACHABLE: u8 = 3;

/// How often the announcements go out, matching the slirp path's probe: a guest that is not
/// listening yet has missed nothing that will not come again.
const ANNOUNCE_EVERY: Duration = Duration::from_millis(250);

/// The first port this end gives a connection it opens, above the range the guest draws its own
/// from, so a connection this end opened is recognisable in a capture.
const FIRST_LOCAL_PORT: u16 = 49_152;

/// What crossed the socket, and what this peer did about it.
#[derive(Default)]
struct Seen {
    frames: u64,
    arp_requests: u64,
    arp_answered: u64,
    echoes_answered: u64,
    acks_sent: u64,
    service_replies: u64,
    announcements: u64,
    connections: u64,
    dropped_first: u64,
    duplicate_acks: u64,
    replies_reversed: u64,
    opened: u64,
    verdicts: u64,
    /// Acknowledgements this end sent carrying selective blocks, and the runs named in them.
    selective_acks: u64,
    blocks_sent: u64,
    /// Acknowledgements the guest sent carrying blocks of its own: its *receiving* half, which
    /// stays silent for a peer that never offered `SACK-permitted` — so nothing before this
    /// peer could draw one out.
    guest_blocks: u64,
    /// Data segments the guest sent a second time, and the bytes in them. What go-back-N costs
    /// over selective recovery is the difference between this and the holes actually missing.
    guest_retransmits: u64,
    guest_retransmit_bytes: u64,
    /// Datagrams to the quiet port answered with a destination-unreachable message.
    refusals: u64,
}

/// One connection the guest opened to the service, and what this end owes it.
///
/// There is no listen backlog and no reassembly beyond what the rounds need: the guest opens
/// one connection at a time, sends one request, and closes in the order its mode names.
struct Conn {
    guest_port: u16,
    /// This end's port. The service's for a connection the guest opened; one of this end's
    /// choosing for a connection it opened itself, which is what tells `poll`'s two apart —
    /// both reach the same listener, so the guest's port is that listener's for either.
    local_port: u16,
    /// The next sequence number this end will send.
    snd_nxt: u32,
    /// Everything below this has arrived in order; what an acknowledgement names.
    rcv_nxt: u32,
    /// Segments that arrived past a hole, held until it fills. Holding them rather than
    /// dropping them is what keeps a lost segment costing one retransmission instead of a
    /// window's worth.
    held: Vec<(u32, Vec<u8>)>,
    /// The first in-order data segment of every connection is dropped, once. With one segment
    /// the guest's timer sends it again; with four, the three behind it draw the three
    /// duplicate acknowledgements its fast retransmit needs. Under `-netdev user` a relay
    /// between the guest and the network does this; here there is no between, so the peer
    /// does it by choosing what to answer.
    dropped: bool,
    /// The request line, however many segments carried it.
    request: Vec<u8>,
    replied: bool,
    fin_sent: bool,
    /// The guest's own FIN has arrived and been acknowledged. A connection is forgotten only
    /// once both ends have finished: the guest acknowledges this end's FIN before sending its
    /// own, and forgetting it in between leaves that FIN unanswered and the guest in LAST-ACK.
    fin_seen: bool,
    /// The guest offered `SACK-permitted` on its SYN, so blocks may be sent to it. Nothing is
    /// sent to an end that did not ask — the rule the guest's own receiver keeps, and the one
    /// a falsification turns off to watch the blocks stop.
    sack_ok: bool,
    /// Frames the last reply held back, sent when the guest next says anything. Holding the
    /// front half of a reply for a round trip is what leaves the half behind it out of order
    /// long enough for the guest's *receiver* to report it: sent in one batch, as they were
    /// before, the hole closed in the same poll and there was never a block to send.
    pending: Vec<Vec<u8>>,
    /// One past the highest byte of the guest's this end has seen, dropped segments included.
    /// A segment starting below it is one the guest is sending again, which is how a
    /// retransmission is told from new data without keeping every segment.
    seen_through: u32,
    /// Set when this end opened the connection into the guest's listener, which reverses who
    /// speaks first and who closes: this end sends the request, judges the reply, and finishes.
    opened: Option<Opened>,
}

/// A connection this end opened, and how far through the exchange it has come.
struct Opened {
    /// The number the guest announced its listener with; every line of the exchange carries it.
    tag: Vec<u8>,
    /// The guest answered the SYN, so the request has gone.
    established: bool,
    /// The verdict has gone, so nothing is owed but the close.
    judged: bool,
}

/// The network, as far as the guest is concerned.
struct Peer {
    ports: NetPorts,
    /// Learned from the first frame that arrives; nothing can be addressed until it is known,
    /// and the guest's first act is an ARP request, so it is known almost at once.
    guest_mac: Option<[u8; 6]>,
    /// Distinct per datagram, as a sender's ought to be; a fragmented datagram's two frames
    /// share theirs, which is what marks them as one datagram's parts.
    ip_id: u16,
    /// Open connections, and those in the moments after a close; a connection is forgotten
    /// once both ends have finished with it.
    conns: Vec<Conn>,
    /// The listener numbers already connected to, so a repeated announcement is not a second
    /// request. The guest repeats it for as long as its listener is up.
    tags: Vec<Vec<u8>>,
    /// The next port of this end's own choosing, for a connection it opens.
    next_local: u16,
    seen: Seen,
}

/// Serve the guest's network until `stop`.
pub fn serve(ports: NetPorts, stop: Arc<AtomicBool>) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let socket = match std::net::UdpSocket::bind(("127.0.0.1", ports.peer_local)) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("  net peer: cannot bind {}: {e}", ports.peer_local);
                return;
            }
        };
        if socket
            .set_read_timeout(Some(Duration::from_millis(50)))
            .is_err()
        {
            return;
        }
        let to = ("127.0.0.1", ports.peer_remote);
        let mut peer = Peer {
            ports,
            guest_mac: None,
            ip_id: 1,
            conns: Vec::new(),
            tags: Vec::new(),
            next_local: FIRST_LOCAL_PORT,
            seen: Seen::default(),
        };
        let mut last: Option<Instant> = None;
        let mut buf = [0u8; 2048];
        while !stop.load(Ordering::Relaxed) {
            if peer.guest_mac.is_some() && last.is_none_or(|t| t.elapsed() >= ANNOUNCE_EVERY) {
                for frame in peer.announcements() {
                    let _ = socket.send_to(&frame, to);
                }
                peer.seen.announcements += 1;
                last = Some(Instant::now());
            }
            // A timeout is the ordinary case: the guest has nothing to say yet.
            let Ok(n) = socket.recv(&mut buf) else {
                continue;
            };
            peer.seen.frames += 1;
            for frame in peer.answer(&buf[..n]) {
                let _ = socket.send_to(&frame, to);
            }
        }
        let s = &peer.seen;
        eprintln!(
            "  net peer: {} frames in, {} ARP requests, {} answered, {} echoes answered, \
             {} acknowledgements, {} service replies, {} rounds of announcements, \
             {} connections, {} first segments dropped, {} duplicate acknowledgements, \
             {} replies sent back to front, {} connections opened, {} verdicts sent, \
             {} selective acknowledgements naming {} runs, {} acknowledgements with blocks of \
             the guest's own, {} segments the guest sent again ({} bytes), {} datagrams refused",
            s.frames,
            s.arp_requests,
            s.arp_answered,
            s.echoes_answered,
            s.acks_sent,
            s.service_replies,
            s.announcements,
            s.connections,
            s.dropped_first,
            s.duplicate_acks,
            s.replies_reversed,
            s.opened,
            s.verdicts,
            s.selective_acks,
            s.blocks_sent,
            s.guest_blocks,
            s.guest_retransmits,
            s.guest_retransmit_bytes,
            s.refusals,
        );
    })
}

impl Peer {
    /// What to send the guest in answer to `frame`, which may be nothing.
    fn answer(&mut self, frame: &[u8]) -> Vec<Vec<u8>> {
        if let Some(mac) = frame.get(6..12) {
            self.guest_mac = mac.try_into().ok();
        }
        match frame.get(12..14) {
            Some(t) if t == ETHERTYPE_ARP => {
                let reply = self.arp_reply(frame);
                if reply.is_some() {
                    self.seen.arp_answered += 1;
                }
                reply.into_iter().collect()
            }
            Some(t) if t == ETHERTYPE_IPV4 => match frame.get(23) {
                Some(&PROTO_ICMP) => {
                    let reply = self.echo_reply(frame);
                    if reply.is_some() {
                        self.seen.echoes_answered += 1;
                    }
                    reply.into_iter().collect()
                }
                Some(&PROTO_UDP) => self.udp(frame),
                Some(&PROTO_TCP) => self.tcp(frame),
                _ => Vec::new(),
            },
            _ => Vec::new(),
        }
    }

    /// The ARP reply `frame` asks for, if it is a request for [`GATEWAY`].
    ///
    /// The guest's check forgets the gateway and counts replies to *its own* request, so learning
    /// the address from someone else's traffic is rejected: this must answer the request, not
    /// merely announce.
    fn arp_reply(&mut self, frame: &[u8]) -> Option<Vec<u8>> {
        if frame.len() < 42 {
            return None;
        }
        let opcode = u16::from_be_bytes([*frame.get(20)?, *frame.get(21)?]);
        if opcode != ARP_REQUEST {
            return None;
        }
        self.seen.arp_requests += 1;
        if frame.get(38..42)? != GATEWAY {
            return None;
        }
        let sender_mac = frame.get(22..28)?;
        let sender_ip = frame.get(28..32)?;
        let mut out = Vec::with_capacity(42);
        out.extend_from_slice(sender_mac); // to the asker
        out.extend_from_slice(&PEER_MAC);
        out.extend_from_slice(&ETHERTYPE_ARP);
        out.extend_from_slice(&[0, 1]); // Ethernet
        out.extend_from_slice(&[0x08, 0x00]); // IPv4
        out.extend_from_slice(&[6, 4]);
        out.extend_from_slice(&ARP_REPLY.to_be_bytes());
        out.extend_from_slice(&PEER_MAC);
        out.extend_from_slice(&GATEWAY);
        out.extend_from_slice(sender_mac);
        out.extend_from_slice(sender_ip);
        Some(out)
    }

    /// The echo reply for an echo request addressed to [`GATEWAY`].
    ///
    /// The identifier and sequence come back untouched because the whole of the request's body
    /// is echoed, which is what the guest matches on: it sends with one identifier and waits for
    /// the reply naming the sequence it asked about.
    fn echo_reply(&mut self, frame: &[u8]) -> Option<Vec<u8>> {
        let (ihl, total) = ipv4_header(frame)?;
        if frame.get(30..34)? != GATEWAY || frame.get(14 + ihl)? != &ICMP_ECHO_REQUEST {
            return None;
        }
        let body = frame.get(14 + ihl..14 + total)?;
        let mac = self.guest_mac?;
        let mut f = Vec::with_capacity(14 + total);
        f.extend_from_slice(&mac);
        f.extend_from_slice(&PEER_MAC);
        f.extend_from_slice(&ETHERTYPE_IPV4);
        f.extend_from_slice(frame.get(14..14 + ihl)?);
        // Back the way it came: our address as the sender, the sender's as the destination.
        f[26..30].copy_from_slice(&GATEWAY);
        f[30..34].copy_from_slice(frame.get(26..30)?);
        f[22] = 64; // a fresh hop count, since this is our datagram rather than theirs
        f.extend_from_slice(body);
        f[24..26].copy_from_slice(&[0, 0]);
        let sum = ipv4_checksum(f.get(14..14 + ihl)?);
        f[24..26].copy_from_slice(&sum.to_be_bytes());
        let icmp = 14 + ihl;
        f[icmp] = ICMP_ECHO_REPLY;
        f[icmp + 2..icmp + 4].copy_from_slice(&[0, 0]);
        let sum = ipv4_checksum(f.get(icmp..)?);
        f[icmp + 2..icmp + 4].copy_from_slice(&sum.to_be_bytes());
        Some(f)
    }

    /// The answer to a datagram, if it is one this peer answers.
    ///
    /// Three ports matter: the one the announcements come from, where an echo earns its
    /// acknowledgement; the service's, where a request earns its reply; and the quiet one, which
    /// earns nothing at all — that silence is the point of the guest's check that sends there.
    fn udp(&mut self, frame: &[u8]) -> Vec<Vec<u8>> {
        let Some((from, to, payload)) = self.datagram(frame) else {
            return Vec::new();
        };
        if to == self.ports.udp
            && let Some(number) = payload.strip_prefix(NET_ECHO)
        {
            self.seen.acks_sent += 1;
            let ack = [NET_ACK, number].concat();
            return self
                .udp_frame(self.ports.udp, from, &ack)
                .into_iter()
                .collect();
        }
        if to == self.ports.udp_service
            && let Some(tag) = payload.strip_prefix(NET_UDP_REQUEST)
        {
            self.seen.service_replies += 1;
            let reply = [NET_UDP_REPLY, tag].concat();
            return self
                .udp_frame(self.ports.udp_service, from, &reply)
                .into_iter()
                .collect();
        }
        if to == self.ports.udp
            && let Some(tag) = payload.strip_prefix(NET_TCP_LISTENING)
        {
            let tag = tag.to_vec();
            return self.listening(&tag);
        }
        // The port nothing binds. Silence was all a guest behind the user-mode network could
        // ever get here; a real network says so, and a connected socket is refused rather than
        // left waiting out its timeout.
        if to == self.ports.quiet {
            self.seen.refusals += 1;
            return self.unreachable(frame).into_iter().collect();
        }
        Vec::new()
    }

    /// The destination-unreachable message for `frame`, a datagram addressed to the quiet port.
    ///
    /// RFC 792 has the message carry the offending IPv4 header and the eight bytes behind it,
    /// which for UDP is its ports — and those are what tell the guest's stack which of its own
    /// sockets the refusal belongs to. Quoting anything else must refuse nothing, which is one
    /// of the things a falsification checks.
    fn unreachable(&mut self, frame: &[u8]) -> Option<Vec<u8>> {
        let (ihl, _) = ipv4_header(frame)?;
        let quoted = frame.get(14..14 + ihl + 8)?.to_vec();
        let mac = self.guest_mac?;
        let total = 20 + 8 + quoted.len();
        let mut f = Vec::with_capacity(14 + total);
        f.extend_from_slice(&mac);
        f.extend_from_slice(&PEER_MAC);
        f.extend_from_slice(&ETHERTYPE_IPV4);
        f.push(0x45);
        f.push(0);
        f.extend_from_slice(&u16::try_from(total).ok()?.to_be_bytes());
        f.extend_from_slice(&self.next_id().to_be_bytes());
        f.extend_from_slice(&[0, 0]);
        f.push(64);
        f.push(PROTO_ICMP);
        f.extend_from_slice(&[0, 0]);
        f.extend_from_slice(&GATEWAY);
        f.extend_from_slice(&GUEST);
        let sum = ipv4_checksum(f.get(14..34)?);
        f[24..26].copy_from_slice(&sum.to_be_bytes());
        f.push(ICMP_UNREACHABLE);
        f.push(ICMP_PORT_UNREACHABLE);
        f.extend_from_slice(&[0, 0]); // the checksum, once the body is whole
        f.extend_from_slice(&[0, 0, 0, 0]); // unused, per RFC 792
        f.extend_from_slice(&quoted);
        let sum = ipv4_checksum(f.get(34..)?);
        f[36..38].copy_from_slice(&sum.to_be_bytes());
        Some(f)
    }

    /// The ports and payload of a datagram addressed to [`GATEWAY`], or nothing.
    fn datagram(&self, frame: &[u8]) -> Option<(u16, u16, Vec<u8>)> {
        let (ihl, total) = ipv4_header(frame)?;
        if frame.get(30..34)? != GATEWAY {
            return None;
        }
        let udp = 14 + ihl;
        let from = u16::from_be_bytes([*frame.get(udp)?, *frame.get(udp + 1)?]);
        let to = u16::from_be_bytes([*frame.get(udp + 2)?, *frame.get(udp + 3)?]);
        Some((from, to, frame.get(udp + 8..14 + total)?.to_vec()))
    }

    /// A listener the guest has announced: open a connection to it, once per number.
    ///
    /// The guest repeats the announcement while its listener is up, and that repetition is what
    /// makes a lost SYN recoverable — an announcement whose connection has not finished its
    /// handshake is answered with the SYN again. It is also what makes `poll`'s two numbers two
    /// connections: a number not seen before earns one, a number already served earns nothing.
    fn listening(&mut self, tag: &[u8]) -> Vec<Vec<u8>> {
        if let Some(i) = self.conns.iter().position(|c| {
            c.opened
                .as_ref()
                .is_some_and(|o| o.tag == tag && !o.established)
        }) {
            let (port, local, snd) = {
                let c = &self.conns[i];
                (c.guest_port, c.local_port, c.snd_nxt.wrapping_sub(1))
            };
            return self
                .tcp_frame(local, port, snd, 0, TCP_SYN, &[])
                .into_iter()
                .collect();
        }
        if self.tags.iter().any(|t| t == tag) {
            return Vec::new();
        }
        self.tags.push(tag.to_vec());
        self.open(tag)
    }

    /// Open a connection into the guest's listener: the SYN, and the state to answer it with.
    fn open(&mut self, tag: &[u8]) -> Vec<Vec<u8>> {
        let local = self.next_local;
        self.next_local = self.next_local.checked_add(1).unwrap_or(FIRST_LOCAL_PORT);
        // Distinct per connection, so a segment of one cannot be taken for another's.
        let isn = 0x5000_0000u32.wrapping_add(u32::from(local) << 8);
        self.conns.push(Conn {
            guest_port: NET_GUEST_TCP_PORT,
            local_port: local,
            snd_nxt: isn.wrapping_add(1),
            rcv_nxt: 0,
            held: Vec::new(),
            dropped: false,
            request: Vec::new(),
            replied: false,
            fin_sent: false,
            fin_seen: false,
            // Settled by the guest's SYN-ACK, which this end has not seen yet.
            sack_ok: false,
            pending: Vec::new(),
            seen_through: 0,
            opened: Some(Opened {
                tag: tag.to_vec(),
                established: false,
                judged: false,
            }),
        });
        self.seen.opened += 1;
        self.tcp_frame(local, NET_GUEST_TCP_PORT, isn, 0, TCP_SYN, &[])
            .into_iter()
            .collect()
    }

    /// Finish the handshake of a connection this end opened, and send its request.
    fn established(&mut self, i: usize, seq: u32, sack_ok: bool) -> Vec<Vec<u8>> {
        let tag = {
            let c = &mut self.conns[i];
            let Some(o) = c.opened.as_mut() else {
                return Vec::new();
            };
            if o.established {
                return Vec::new();
            }
            o.established = true;
            let tag = o.tag.clone();
            c.rcv_nxt = seq.wrapping_add(1);
            // The guest's SYN-ACK settles whether blocks may be sent to it.
            c.sack_ok = sack_ok;
            c.seen_through = c.rcv_nxt;
            tag
        };
        let (port, local, snd, rcv) = {
            let c = &self.conns[i];
            (c.guest_port, c.local_port, c.snd_nxt, c.rcv_nxt)
        };
        let request = [NET_TCP_INBOUND, &tag, b"\n"].concat();
        let mut out = Vec::new();
        out.extend(self.tcp_frame(local, port, snd, rcv, TCP_ACK, &[]));
        out.extend(self.tcp_frame(local, port, snd, rcv, TCP_ACK | TCP_PSH, &request));
        self.conns[i].snd_nxt = snd.wrapping_add(request.len() as u32);
        out
    }

    /// Judge the guest's reply, say so, and close.
    ///
    /// The server requires the verdict to name its own tag and then an end of stream it can read
    /// as zero bytes, so the verdict and the FIN go out together — the data first, the FIN behind
    /// it, which is the order they arrive in.
    fn judge(&mut self, i: usize) -> Vec<Vec<u8>> {
        let (tag, whole, judged) = {
            let c = &self.conns[i];
            let Some(o) = c.opened.as_ref() else {
                return Vec::new();
            };
            (o.tag.clone(), c.request.clone(), o.judged)
        };
        if judged || !whole.ends_with(b"\n") {
            return Vec::new();
        }
        let expected = [NET_TCP_INBOUND_REPLY, &tag, b"\n"].concat();
        let verdict = if whole == expected {
            NET_TCP_INBOUND_VERIFIED
        } else {
            NET_TCP_INBOUND_WRONG
        };
        let line = [verdict, &tag, b"\n"].concat();
        let (port, local, snd, rcv) = {
            let c = &self.conns[i];
            (c.guest_port, c.local_port, c.snd_nxt, c.rcv_nxt)
        };
        let mut out = Vec::new();
        out.extend(self.tcp_frame(local, port, snd, rcv, TCP_ACK | TCP_PSH, &line));
        let after = snd.wrapping_add(line.len() as u32);
        out.extend(self.tcp_frame(local, port, after, rcv, TCP_ACK | TCP_FIN, &[]));
        let c = &mut self.conns[i];
        c.snd_nxt = after.wrapping_add(1);
        c.fin_sent = true;
        if let Some(o) = c.opened.as_mut() {
            o.judged = true;
        }
        self.seen.verdicts += 1;
        out
    }

    /// The datagrams the guest cannot learn any other way: a probe to answer, the ports of the
    /// TCP service, of the datagram service and of the port nothing answers, and one datagram
    /// carrying a pattern, sent as two IPv4 fragments.
    ///
    /// Under `-netdev user` the fragmenting is done by kbuild's downstream relay, on frames the
    /// network sends the guest. Here there is no network to sit between, so the peer sends the
    /// two fragments itself — which is the same thing seen from the other side.
    fn announcements(&mut self) -> Vec<Vec<u8>> {
        let tcp = [NET_TCP_ANNOUNCE, self.ports.tcp.to_string().as_bytes()].concat();
        let service = [
            NET_UDP_ANNOUNCE,
            self.ports.udp_service.to_string().as_bytes(),
        ]
        .concat();
        let quiet = [NET_UDP_QUIET, self.ports.quiet.to_string().as_bytes()].concat();
        let mut out = Vec::new();
        for payload in [NET_PROBE, &tcp, &service, &quiet] {
            out.extend(self.udp_frame(self.ports.udp, NET_GUEST_PORT, payload));
        }
        let pattern: Vec<u8> = (0..NET_FRAGMENT_PATTERN)
            .map(|i| (i as u8) ^ 0x5a)
            .collect();
        let fragmented = [NET_UDP_FRAGMENTED, b"1 ", &pattern].concat();
        if let Some(frame) = self.udp_frame(self.ports.udp, NET_GUEST_PORT, &fragmented)
            && let Some(fragments) = fragment_datagram(&frame)
        {
            out.extend(fragments);
        }
        out
    }

    /// One datagram to the guest, from [`GATEWAY`], with both checksums.
    fn udp_frame(&mut self, from: u16, to: u16, payload: &[u8]) -> Option<Vec<u8>> {
        let mac = self.guest_mac?;
        let total = 20 + 8 + payload.len();
        let mut f = Vec::with_capacity(14 + total);
        f.extend_from_slice(&mac);
        f.extend_from_slice(&PEER_MAC);
        f.extend_from_slice(&ETHERTYPE_IPV4);
        f.push(0x45); // version 4, a header of five words
        f.push(0);
        f.extend_from_slice(&u16::try_from(total).ok()?.to_be_bytes());
        f.extend_from_slice(&self.next_id().to_be_bytes());
        f.extend_from_slice(&[0, 0]); // whole, and at offset zero
        f.push(64);
        f.push(PROTO_UDP);
        f.extend_from_slice(&[0, 0]); // the checksum, once the header is whole
        f.extend_from_slice(&GATEWAY);
        f.extend_from_slice(&GUEST);
        let sum = ipv4_checksum(f.get(14..34)?);
        f[24..26].copy_from_slice(&sum.to_be_bytes());
        f.extend_from_slice(&from.to_be_bytes());
        f.extend_from_slice(&to.to_be_bytes());
        f.extend_from_slice(&u16::try_from(8 + payload.len()).ok()?.to_be_bytes());
        f.extend_from_slice(&[0, 0]);
        f.extend_from_slice(payload);
        let sum = udp_checksum(&f);
        f[40..42].copy_from_slice(&sum.to_be_bytes());
        Some(f)
    }

    /// Drive one connection a step, given a segment addressed to the service.
    ///
    /// The guest's check gates on what a lossy network produces, so this end produces it
    /// deliberately: each connection's first in-order data segment is dropped, later segments
    /// are held past the hole and answered with a duplicate acknowledgement, and the reply
    /// goes out back to front so a segment is held out of order and then joined.
    fn tcp(&mut self, frame: &[u8]) -> Vec<Vec<u8>> {
        let Some(seg) = self.segment(frame) else {
            return Vec::new();
        };
        if seg.flags & TCP_RST != 0 {
            // Nothing is owed to a connection the guest has torn down, and answering one
            // would be a segment arriving after the rounds are over.
            self.conns
                .retain(|c| c.guest_port != seg.guest_port || c.local_port != seg.local_port);
            return Vec::new();
        }
        if seg.flags & TCP_SYN != 0 && seg.flags & TCP_ACK == 0 {
            return self
                .accept(seg.guest_port, seg.seq, seg.sack_permitted)
                .into_iter()
                .collect();
        }
        let Some(i) = self
            .conns
            .iter()
            .position(|c| c.guest_port == seg.guest_port && c.local_port == seg.local_port)
        else {
            return Vec::new();
        };
        // The answer to a SYN this end sent: the handshake finishes and the request goes.
        if seg.flags & TCP_SYN != 0 {
            return self.established(i, seg.seq, seg.sack_permitted);
        }
        // Blocks of the guest's own: its receiver reporting what it holds past a hole, which it
        // sends only to an end that offered `SACK-permitted`.
        if seg.blocks > 0 {
            self.seen.guest_blocks += 1;
        }
        // Whatever the last reply held back goes now: the guest has spoken, so the run in front
        // of it has been out of order for a round trip and reported.
        let mut out: Vec<Vec<u8>> = core::mem::take(&mut self.conns[i].pending);
        if !seg.payload.is_empty() {
            out.extend(self.data(i, seg.seq, &seg.payload));
        }
        if seg.flags & TCP_FIN != 0 {
            out.extend(self.closing(i, seg.seq, &seg.payload));
        }
        if seg.flags & TCP_ACK != 0 {
            let done = {
                let c = &self.conns[i];
                c.fin_sent && seg.ack == c.snd_nxt && c.fin_seen
            };
            if done {
                self.conns
                    .retain(|c| c.guest_port != seg.guest_port || c.local_port != seg.local_port);
            }
        }
        out
    }

    /// Answer a SYN: the handshake, with the segment size this end offers.
    ///
    /// A SYN for a connection already open is the guest sending it again, so the same answer
    /// goes back rather than a second connection appearing.
    fn accept(&mut self, guest_port: u16, seq: u32, sack_ok: bool) -> Option<Vec<u8>> {
        if let Some(c) = self.conns.iter().find(|c| c.guest_port == guest_port) {
            let (snd, rcv, local) = (c.snd_nxt.wrapping_sub(1), c.rcv_nxt, c.local_port);
            return self.tcp_frame(local, guest_port, snd, rcv, TCP_SYN | TCP_ACK, &[]);
        }
        // Distinct per connection, so a segment from a previous round cannot be mistaken for
        // one of this round's.
        let isn = 0x2000_0000u32.wrapping_add(u32::from(guest_port) << 8);
        self.conns.push(Conn {
            guest_port,
            local_port: self.ports.tcp,
            snd_nxt: isn.wrapping_add(1),
            rcv_nxt: seq.wrapping_add(1),
            held: Vec::new(),
            dropped: false,
            request: Vec::new(),
            replied: false,
            fin_sent: false,
            fin_seen: false,
            sack_ok,
            pending: Vec::new(),
            seen_through: seq.wrapping_add(1),
            opened: None,
        });
        self.seen.connections += 1;
        let local = self.ports.tcp;
        self.tcp_frame(local, guest_port, isn, seq.wrapping_add(1), TCP_SYN | TCP_ACK, &[])
    }

    /// Take one data segment, and answer it.
    fn data(&mut self, i: usize, seq: u32, payload: &[u8]) -> Vec<Vec<u8>> {
        // A segment starting below everything seen so far is one the guest is sending again.
        // Counted before the drop below, so the segment this end withholds is still on record
        // as having been seen: what comes back for it is a retransmission, not new data.
        let end = seq.wrapping_add(payload.len() as u32);
        let again = {
            let c = &self.conns[i];
            c.seen_through != 0 && before(seq, c.seen_through)
        };
        if again {
            self.seen.guest_retransmits += 1;
            self.seen.guest_retransmit_bytes += payload.len() as u64;
        }
        {
            let c = &mut self.conns[i];
            if c.seen_through == 0 || before(c.seen_through, end) {
                c.seen_through = end;
            }
        }
        let c = &mut self.conns[i];
        // The dropped first segment is the service's disturbance. A connection this end opened
        // carries the guest's reply, and losing that would slow the exchange with no check
        // asking for it.
        if c.opened.is_none() && seq == c.rcv_nxt && !c.dropped {
            // The one segment this connection loses. Silence, not a refusal: a lost segment
            // is one that never arrived, and the guest must notice by itself.
            c.dropped = true;
            self.seen.dropped_first += 1;
            return Vec::new();
        }
        if seq == c.rcv_nxt {
            c.rcv_nxt = c.rcv_nxt.wrapping_add(payload.len() as u32);
            c.request.extend_from_slice(payload);
            // Whatever was held past the hole now follows on, in order.
            while let Some(k) = c.held.iter().position(|(at, _)| *at == c.rcv_nxt) {
                let (_, held) = c.held.remove(k);
                c.rcv_nxt = c.rcv_nxt.wrapping_add(held.len() as u32);
                c.request.extend_from_slice(&held);
            }
        } else if seq.wrapping_sub(c.rcv_nxt) < u32::MAX / 2 {
            // Past the hole: held, and acknowledged with what is still missing — which is the
            // duplicate acknowledgement the guest counts towards its fast retransmit.
            if !c.held.iter().any(|(at, _)| *at == seq) {
                c.held.push((seq, payload.to_vec()));
            }
            self.seen.duplicate_acks += 1;
        }
        let (port, local, snd, rcv) = (c.guest_port, c.local_port, c.snd_nxt, c.rcv_nxt);
        // What is held past the hole, named so the guest resends the hole and steps over the
        // rest. Without these the same acknowledgement says only "still waiting", and the
        // guest has nothing to go on but go-back-N.
        let blocks = held_blocks(&self.conns[i]);
        if !blocks.is_empty() {
            self.seen.selective_acks += 1;
            self.seen.blocks_sent += blocks.len() as u64;
        }
        let mut out: Vec<Vec<u8>> = self
            .tcp_frame_with(local, port, snd, rcv, TCP_ACK, &blocks, &[])
            .into_iter()
            .collect();
        out.extend(self.reply(i));
        out
    }

    /// The reply, once the request line is whole: two segments, the second sent first.
    ///
    /// One segment would leave nothing to hold: the guest's check requires a segment held out
    /// of order and later joined to the stream, which under `-netdev user` its relay arranges
    /// by swapping a pair. Here the peer arranges it by choosing the order it sends.
    fn reply(&mut self, i: usize) -> Vec<Vec<u8>> {
        // A connection this end opened is owed a verdict on its reply, not a reply of its own.
        if self.conns[i].opened.is_some() {
            return self.judge(i);
        }
        let c = &self.conns[i];
        if c.replied || !c.request.ends_with(b"\n") {
            return Vec::new();
        }
        let Some(rest) = c.request.strip_prefix(NET_TCP_REQUEST) else {
            return Vec::new();
        };
        let reply = [NET_TCP_REPLY, rest].concat();
        let peer_closes = rest.starts_with(b"peer-closes ");
        let (port, local, snd, rcv) = (c.guest_port, c.local_port, c.snd_nxt, c.rcv_nxt);
        let split = reply.len() / 2;
        let (first, second) = reply.split_at(split);
        let (first, second) = (first.to_vec(), second.to_vec());
        let second_at = snd.wrapping_add(first.len() as u32);
        let mut out = Vec::new();
        // The half in front is held back until the guest has spoken again, so the half behind
        // it sits out of order for a whole round trip — long enough for the guest's receiver to
        // report it in blocks of its own, which is the half of selective acknowledgement no
        // boot had ever drawn out. Sent together, as they were before, the hole closed in the
        // same poll and there was nothing left to report.
        out.extend(self.tcp_frame(local, port, second_at, rcv, TCP_ACK | TCP_PSH, &second));
        let mut held_back: Vec<Vec<u8>> = Vec::new();
        held_back.extend(self.tcp_frame(local, port, snd, rcv, TCP_ACK | TCP_PSH, &first));
        let c = &mut self.conns[i];
        c.snd_nxt = c.snd_nxt.wrapping_add(reply.len() as u32);
        c.replied = true;
        self.seen.replies_reversed += 1;
        if peer_closes {
            c.fin_sent = true;
            let (port, local, snd, rcv) = (c.guest_port, c.local_port, c.snd_nxt, c.rcv_nxt);
            // Behind the half it follows, or the guest would hold a FIN past a hole — which its
            // stack does not remember, so it would have to be sent again.
            held_back.extend(self.tcp_frame(local, port, snd, rcv, TCP_ACK | TCP_FIN, &[]));
            self.conns[i].snd_nxt = snd.wrapping_add(1);
        }
        self.conns[i].pending = held_back;
        out
    }

    /// Acknowledge the guest's FIN, and send this end's if it has not gone already.
    fn closing(&mut self, i: usize, seq: u32, payload: &[u8]) -> Vec<Vec<u8>> {
        let c = &mut self.conns[i];
        let fin_at = seq.wrapping_add(payload.len() as u32);
        if fin_at != c.rcv_nxt {
            // A FIN past a hole: acknowledged when the hole fills, not before.
            return Vec::new();
        }
        c.rcv_nxt = c.rcv_nxt.wrapping_add(1);
        c.fin_seen = true;
        let send_fin = !c.fin_sent;
        if send_fin {
            c.fin_sent = true;
        }
        let (port, local, snd, rcv) = (c.guest_port, c.local_port, c.snd_nxt, c.rcv_nxt);
        let mut out: Vec<Vec<u8>> = Vec::new();
        if send_fin {
            out.extend(self.tcp_frame(local, port, snd, rcv, TCP_ACK | TCP_FIN, &[]));
            self.conns[i].snd_nxt = snd.wrapping_add(1);
        } else {
            out.extend(self.tcp_frame(local, port, snd, rcv, TCP_ACK, &[]));
        }
        out
    }

    /// One TCP segment to the guest, from `from`, with both checksums.
    fn tcp_frame(
        &mut self,
        from: u16,
        guest_port: u16,
        seq: u32,
        ack: u32,
        flags: u8,
        payload: &[u8],
    ) -> Option<Vec<u8>> {
        self.tcp_frame_with(from, guest_port, seq, ack, flags, &[], payload)
    }

    /// One TCP segment, naming `blocks` as a selective acknowledgement.
    #[allow(clippy::too_many_arguments)]
    fn tcp_frame_with(
        &mut self,
        from: u16,
        guest_port: u16,
        seq: u32,
        ack: u32,
        flags: u8,
        blocks: &[(u32, u32)],
        payload: &[u8],
    ) -> Option<Vec<u8>> {
        let mac = self.guest_mac?;
        // The segment size and `SACK-permitted` go on a SYN, by custom and because that is the
        // only segment the guest reads them from; blocks go on everything else, since a SYN has
        // nothing held to report. Each option is padded to a whole header word.
        let mut options: Vec<u8> = Vec::new();
        if flags & TCP_SYN != 0 {
            options.extend_from_slice(&[TCP_OPT_MSS, 4, (PEER_MSS >> 8) as u8, PEER_MSS as u8]);
            options.extend_from_slice(&[TCP_OPT_NOP, TCP_OPT_NOP, TCP_OPT_SACK_PERMITTED, 2]);
        } else if !blocks.is_empty() {
            let named = &blocks[..blocks.len().min(SACK_BLOCKS)];
            let len = 2 + 8 * named.len();
            options.extend_from_slice(&[TCP_OPT_NOP, TCP_OPT_NOP, TCP_OPT_SACK, len as u8]);
            for (start, end) in named {
                options.extend_from_slice(&start.to_be_bytes());
                options.extend_from_slice(&end.to_be_bytes());
            }
        }
        let options = &options[..];
        let header = 20 + options.len();
        let total = 20 + header + payload.len();
        let mut f = Vec::with_capacity(14 + total);
        f.extend_from_slice(&mac);
        f.extend_from_slice(&PEER_MAC);
        f.extend_from_slice(&ETHERTYPE_IPV4);
        f.push(0x45);
        f.push(0);
        f.extend_from_slice(&u16::try_from(total).ok()?.to_be_bytes());
        f.extend_from_slice(&self.next_id().to_be_bytes());
        f.extend_from_slice(&[0, 0]);
        f.push(64);
        f.push(PROTO_TCP);
        f.extend_from_slice(&[0, 0]);
        f.extend_from_slice(&GATEWAY);
        f.extend_from_slice(&GUEST);
        let sum = ipv4_checksum(f.get(14..34)?);
        f[24..26].copy_from_slice(&sum.to_be_bytes());
        f.extend_from_slice(&from.to_be_bytes());
        f.extend_from_slice(&guest_port.to_be_bytes());
        f.extend_from_slice(&seq.to_be_bytes());
        f.extend_from_slice(&ack.to_be_bytes());
        f.push(((header / 4) as u8) << 4);
        f.push(flags);
        f.extend_from_slice(&PEER_WINDOW.to_be_bytes());
        f.extend_from_slice(&[0, 0]);
        f.extend_from_slice(&[0, 0]);
        f.extend_from_slice(options);
        f.extend_from_slice(payload);
        let sum = tcp_checksum(&f);
        f[50..52].copy_from_slice(&sum.to_be_bytes());
        Some(f)
    }

    /// The parts of a segment addressed to the service or to a connection this end opened, or
    /// nothing if it is neither.
    fn segment(&self, frame: &[u8]) -> Option<Segment> {
        let (ihl, total) = ipv4_header(frame)?;
        if frame.get(30..34)? != GATEWAY {
            return None;
        }
        let at = 14 + ihl;
        let guest_port = u16::from_be_bytes([*frame.get(at)?, *frame.get(at + 1)?]);
        let to = u16::from_be_bytes([*frame.get(at + 2)?, *frame.get(at + 3)?]);
        if to != self.ports.tcp && !self.conns.iter().any(|c| c.local_port == to) {
            return None;
        }
        let seq = u32::from_be_bytes(frame.get(at + 4..at + 8)?.try_into().ok()?);
        let ack = u32::from_be_bytes(frame.get(at + 8..at + 12)?.try_into().ok()?);
        let header = usize::from(frame.get(at + 12)? >> 4) * 4;
        if header < 20 {
            return None;
        }
        let flags = *frame.get(at + 13)?;
        let (sack_permitted, blocks) = tcp_options(frame.get(at + 20..at + header)?);
        let payload = frame.get(at + header..14 + total)?.to_vec();
        Some(Segment {
            guest_port,
            local_port: to,
            seq,
            ack,
            flags,
            sack_permitted,
            blocks,
            payload,
        })
    }

    fn next_id(&mut self) -> u16 {
        self.ip_id = self.ip_id.wrapping_add(1);
        self.ip_id
    }
}

/// One segment, parsed far enough to drive a connection.
struct Segment {
    guest_port: u16,
    local_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    /// The guest offered selective acknowledgement on this SYN.
    sack_permitted: bool,
    /// Runs the guest says it holds past its own hole: its receiving half speaking.
    blocks: usize,
    payload: Vec<u8>,
}

/// `a` comes before `b` in sequence space, which wraps.
fn before(a: u32, b: u32) -> bool {
    a != b && b.wrapping_sub(a) < 1 << 31
}

/// Whether the options offer `SACK-permitted`, and how many selective blocks they carry.
///
/// Every option's length is checked against the bytes actually there before it is stepped
/// over, so a malformed one ends the walk rather than reading past the header.
fn tcp_options(opts: &[u8]) -> (bool, usize) {
    let (mut permitted, mut blocks) = (false, 0);
    let mut at = 0;
    while at < opts.len() {
        match opts[at] {
            TCP_OPT_END => break,
            TCP_OPT_NOP => at += 1,
            kind => {
                let Some(&len) = opts.get(at + 1) else { break };
                let n = usize::from(len);
                if n < 2 || at + n > opts.len() {
                    break;
                }
                if kind == TCP_OPT_SACK_PERMITTED && n == 2 {
                    permitted = true;
                }
                // Whole blocks and nothing else, as the guest's own parser requires.
                if kind == TCP_OPT_SACK && n >= 10 && (n - 2) % 8 == 0 {
                    blocks = (n - 2) / 8;
                }
                at += n;
            }
        }
    }
    (permitted, blocks)
}

/// The runs `c` holds past its hole, coalesced and nearest first: what a selective
/// acknowledgement names.
///
/// Empty for a guest that never offered `SACK-permitted`, because blocks belong to the end
/// that asked for them — the same rule the guest's own receiver keeps.
fn held_blocks(c: &Conn) -> Vec<(u32, u32)> {
    if !c.sack_ok || c.held.is_empty() {
        return Vec::new();
    }
    let mut held: Vec<(u32, u32)> = c
        .held
        .iter()
        .map(|(at, bytes)| (*at, at.wrapping_add(bytes.len() as u32)))
        .collect();
    // In sequence order from the hole, so runs that meet are joined and the nearest — the one
    // the guest's stream needs first — is named first.
    held.sort_by_key(|(at, _)| at.wrapping_sub(c.rcv_nxt));
    let mut runs: Vec<(u32, u32)> = Vec::new();
    for (start, end) in held {
        match runs.last_mut() {
            Some(last) if last.1 == start => last.1 = end,
            _ => runs.push((start, end)),
        }
    }
    runs.truncate(SACK_BLOCKS);
    runs
}

/// A segment's checksum over the IPv4 pseudo-header, for a frame whose IPv4 header is five
/// words. Unlike a datagram's, a segment's is mandatory, so a zero sum is sent as it comes.
fn tcp_checksum(frame: &[u8]) -> u16 {
    let tcp = 34;
    let len = frame.len() - tcp;
    let mut all = Vec::with_capacity(12 + len);
    all.extend_from_slice(&frame[26..30]);
    all.extend_from_slice(&frame[30..34]);
    all.push(0);
    all.push(PROTO_TCP);
    all.extend_from_slice(&(len as u16).to_be_bytes());
    all.extend_from_slice(&frame[tcp..]);
    ipv4_checksum(&all)
}

/// A datagram's checksum over the IPv4 pseudo-header, for a frame whose header is five words.
///
/// Zero means "not computed" to a receiver, so a sum that comes out zero is sent as all ones,
/// which has the same value under one's-complement arithmetic (RFC 768).
fn udp_checksum(frame: &[u8]) -> u16 {
    let udp = 34;
    let len = frame.len() - udp;
    let mut all = Vec::with_capacity(12 + len);
    all.extend_from_slice(&frame[26..30]);
    all.extend_from_slice(&frame[30..34]);
    all.push(0);
    all.push(PROTO_UDP);
    all.extend_from_slice(&(len as u16).to_be_bytes());
    all.extend_from_slice(&frame[udp..]);
    match ipv4_checksum(&all) {
        0 => 0xffff,
        sum => sum,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GUEST_MAC: [u8; 6] = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];

    fn ports() -> NetPorts {
        NetPorts {
            udp: 40001,
            tcp: 40002,
            relay_out: 0,
            relay_in: 0,
            down_out: 0,
            down_in: 0,
            inbound: 0,
            udp_service: 40003,
            quiet: 40004,
            peer_local: 0,
            peer_remote: 0,
        }
    }

    fn peer() -> Peer {
        Peer {
            ports: ports(),
            guest_mac: Some(GUEST_MAC),
            ip_id: 1,
            conns: Vec::new(),
            tags: Vec::new(),
            next_local: FIRST_LOCAL_PORT,
            seen: Seen::default(),
        }
    }

    fn request(target: [u8; 4]) -> Vec<u8> {
        let mut f = Vec::new();
        f.extend_from_slice(&[0xff; 6]);
        f.extend_from_slice(&GUEST_MAC);
        f.extend_from_slice(&ETHERTYPE_ARP);
        f.extend_from_slice(&[0, 1, 0x08, 0x00, 6, 4]);
        f.extend_from_slice(&ARP_REQUEST.to_be_bytes());
        f.extend_from_slice(&GUEST_MAC);
        f.extend_from_slice(&GUEST);
        f.extend_from_slice(&[0; 6]);
        f.extend_from_slice(&target);
        f
    }

    /// A datagram from the guest to `to` at `dst`, carrying `payload`.
    fn datagram(dst: [u8; 4], from: u16, to: u16, payload: &[u8]) -> Vec<u8> {
        let total = 20 + 8 + payload.len();
        let mut f = Vec::new();
        f.extend_from_slice(&PEER_MAC);
        f.extend_from_slice(&GUEST_MAC);
        f.extend_from_slice(&ETHERTYPE_IPV4);
        f.push(0x45);
        f.push(0);
        f.extend_from_slice(&(total as u16).to_be_bytes());
        f.extend_from_slice(&[0, 7]);
        f.extend_from_slice(&[0, 0]);
        f.push(64);
        f.push(PROTO_UDP);
        f.extend_from_slice(&[0, 0]);
        f.extend_from_slice(&GUEST);
        f.extend_from_slice(&dst);
        f.extend_from_slice(&from.to_be_bytes());
        f.extend_from_slice(&to.to_be_bytes());
        f.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        f.extend_from_slice(&[0, 0]);
        f.extend_from_slice(payload);
        f
    }

    /// An echo request from the guest to `dst`, with `id` and `seq`.
    fn echo(dst: [u8; 4], id: u16, seq: u16) -> Vec<u8> {
        let total = 20 + 8 + 4;
        let mut f = Vec::new();
        f.extend_from_slice(&PEER_MAC);
        f.extend_from_slice(&GUEST_MAC);
        f.extend_from_slice(&ETHERTYPE_IPV4);
        f.push(0x45);
        f.push(0);
        f.extend_from_slice(&(total as u16).to_be_bytes());
        f.extend_from_slice(&[0, 9]);
        f.extend_from_slice(&[0, 0]);
        f.push(64);
        f.push(PROTO_ICMP);
        f.extend_from_slice(&[0, 0]);
        f.extend_from_slice(&GUEST);
        f.extend_from_slice(&dst);
        f.push(ICMP_ECHO_REQUEST);
        f.push(0);
        f.extend_from_slice(&[0, 0]);
        f.extend_from_slice(&id.to_be_bytes());
        f.extend_from_slice(&seq.to_be_bytes());
        f.extend_from_slice(b"abcd");
        f
    }

    /// The payload of a datagram frame, and the ports it carries.
    fn udp_parts(frame: &[u8]) -> (u16, u16, Vec<u8>) {
        let (ihl, total) = ipv4_header(frame).expect("a whole datagram");
        let udp = 14 + ihl;
        (
            u16::from_be_bytes([frame[udp], frame[udp + 1]]),
            u16::from_be_bytes([frame[udp + 2], frame[udp + 3]]),
            frame[udp + 8..14 + total].to_vec(),
        )
    }

    #[test]
    fn a_request_for_the_gateway_is_answered_from_its_own_address() {
        let mut p = peer();
        let reply = p.arp_reply(&request(GATEWAY)).expect("answered");
        assert_eq!(reply.len(), 42);
        assert_eq!(&reply[0..6], &GUEST_MAC); // to the asker
        assert_eq!(&reply[6..12], &PEER_MAC);
        assert_eq!(u16::from_be_bytes([reply[20], reply[21]]), ARP_REPLY);
        assert_eq!(&reply[22..28], &PEER_MAC);
        assert_eq!(&reply[28..32], &GATEWAY);
        assert_eq!(&reply[38..42], &GUEST); // back to the guest
        assert_eq!(p.seen.arp_requests, 1);
    }

    #[test]
    fn a_request_for_another_address_is_not_answered() {
        let mut p = peer();
        assert!(p.arp_reply(&request([10, 0, 2, 99])).is_none());
        assert_eq!(p.seen.arp_requests, 1, "counted, but not ours to answer");
    }

    #[test]
    fn a_reply_is_not_mistaken_for_a_request() {
        let mut p = peer();
        let mut f = request(GATEWAY);
        f[20..22].copy_from_slice(&ARP_REPLY.to_be_bytes());
        assert!(p.arp_reply(&f).is_none());
        assert_eq!(p.seen.arp_requests, 0);
    }

    #[test]
    fn a_short_frame_is_refused_rather_than_indexed_past() {
        let mut p = peer();
        assert!(p.arp_reply(&[0u8; 20]).is_none());
        assert!(p.echo_reply(&[0u8; 20]).is_none());
        assert!(p.udp(&[0u8; 20]).is_empty());
        assert!(p.answer(&[0u8; 8]).is_empty());
    }

    #[test]
    fn an_echo_request_is_answered_with_its_own_identifier_and_sequence() {
        let mut p = peer();
        let reply = p.echo_reply(&echo(GATEWAY, 0x4b54, 3)).expect("answered");
        let (ihl, _) = ipv4_header(&reply).expect("a whole datagram");
        let icmp = 14 + ihl;
        assert_eq!(reply[icmp], ICMP_ECHO_REPLY);
        assert_eq!(u16::from_be_bytes([reply[icmp + 4], reply[icmp + 5]]), 0x4b54);
        assert_eq!(u16::from_be_bytes([reply[icmp + 6], reply[icmp + 7]]), 3);
        assert_eq!(&reply[icmp + 8..icmp + 12], b"abcd", "the body comes back");
        assert_eq!(&reply[26..30], &GATEWAY, "from the gateway");
        assert_eq!(&reply[30..34], &GUEST, "to the asker");
        // A checksum computed over a datagram that carries its own is zero when it is right.
        assert_eq!(ipv4_checksum(&reply[14..14 + ihl]), 0);
        assert_eq!(ipv4_checksum(&reply[icmp..]), 0);
    }

    #[test]
    fn an_echo_request_for_another_address_is_not_answered() {
        let mut p = peer();
        assert!(p.echo_reply(&echo([10, 0, 2, 99], 0x4b54, 1)).is_none());
    }

    #[test]
    fn an_echo_earns_the_acknowledgement_that_names_it() {
        let mut p = peer();
        let frame = datagram(GATEWAY, NET_GUEST_PORT, p.ports.udp, b"kintane-udp-echo 7");
        let answer = p.udp(&frame);
        assert_eq!(answer.len(), 1, "one acknowledgement");
        let reply = &answer[0];
        let (from, to, payload) = udp_parts(&reply);
        assert_eq!(payload, b"kintane-udp-ack 7");
        assert_eq!(from, ports().udp, "from the port the probe came from");
        assert_eq!(to, NET_GUEST_PORT);
        assert_eq!(p.seen.acks_sent, 1);
    }

    #[test]
    fn a_request_to_the_service_earns_the_reply_that_names_its_tag() {
        let mut p = peer();
        let frame = datagram(GATEWAY, 49152, p.ports.udp_service, b"kintane-udp-request 42");
        let answer = p.udp(&frame);
        assert_eq!(answer.len(), 1, "one reply");
        let reply = &answer[0];
        let (from, to, payload) = udp_parts(&reply);
        assert_eq!(payload, b"kintane-udp-reply 42");
        assert_eq!(from, ports().udp_service);
        assert_eq!(to, 49152, "back to the port that asked");
    }

    #[test]
    fn the_quiet_port_refuses_rather_than_answering() {
        let mut p = peer();
        let quiet = p.ports.quiet;
        let frame = datagram(GATEWAY, 49152, quiet, b"kintane-udp-request 42");
        let out = p.udp(&frame);
        assert_eq!(out.len(), 1, "a refusal, not a reply");
        assert_eq!(p.seen.service_replies, 0, "nothing answered the datagram itself");
        assert_eq!(p.seen.refusals, 1);
        let m = &out[0];
        assert_eq!(m[23], PROTO_ICMP);
        let (ihl, total) = ipv4_header(m).expect("a whole datagram");
        let icmp = 14 + ihl;
        assert_eq!(m[icmp], ICMP_UNREACHABLE);
        assert_eq!(m[icmp + 1], ICMP_PORT_UNREACHABLE);
        assert_eq!(&m[26..30], &GATEWAY, "from the gateway");
        assert_eq!(&m[30..34], &GUEST, "to the guest");
        // A checksum computed over a message that carries its own is zero when it is right.
        assert_eq!(ipv4_checksum(&m[14..14 + ihl]), 0);
        assert_eq!(ipv4_checksum(&m[icmp..14 + total]), 0);
        // The quoted header and the eight bytes behind it, which is what names the socket the
        // refusal belongs to: our datagram, and the two ports it carried.
        let quoted = icmp + 8;
        assert_eq!(&m[quoted + 12..quoted + 16], &GUEST, "the datagram was the guest's");
        assert_eq!(&m[quoted + 16..quoted + 20], &GATEWAY);
        let ports = quoted + 20;
        assert_eq!(u16::from_be_bytes([m[ports], m[ports + 1]]), 49152, "from");
        assert_eq!(u16::from_be_bytes([m[ports + 2], m[ports + 3]]), quiet, "to");
    }

    #[test]
    fn a_datagram_for_another_address_is_not_answered() {
        let mut p = peer();
        let frame = datagram([10, 0, 2, 99], NET_GUEST_PORT, p.ports.udp, b"kintane-udp-echo 1");
        assert!(p.udp(&frame).is_empty());
    }

    /// The parts of a segment, for a test that needs to look inside one.
    fn tcp_parts(frame: &[u8]) -> (u16, u16, u32, u32, u8, Vec<u8>) {
        let (ihl, total) = ipv4_header(frame).expect("a whole datagram");
        let at = 14 + ihl;
        let from = u16::from_be_bytes([frame[at], frame[at + 1]]);
        let to = u16::from_be_bytes([frame[at + 2], frame[at + 3]]);
        let seq = u32::from_be_bytes(frame[at + 4..at + 8].try_into().unwrap());
        let ack = u32::from_be_bytes(frame[at + 8..at + 12].try_into().unwrap());
        let header = usize::from(frame[at + 12] >> 4) * 4;
        let flags = frame[at + 13];
        (from, to, seq, ack, flags, frame[at + header..14 + total].to_vec())
    }

    /// The guest's announcement that a listener is up, carrying `tag`.
    fn listening(p: &Peer, tag: &[u8]) -> Vec<u8> {
        let payload = [NET_TCP_LISTENING, tag].concat();
        datagram(GATEWAY, NET_GUEST_PORT, p.ports.udp, &payload)
    }

    /// The guest's answer to a SYN, for the connection `syn` opened.
    fn syn_ack(syn: &[u8], guest_isn: u32) -> Vec<u8> {
        let (from, to, seq, _, _, _) = tcp_parts(syn);
        // The guest answers from the port the SYN was addressed to, back to the one it came
        // from: this end's chosen port.
        segment_from(to, from, guest_isn, seq.wrapping_add(1), TCP_SYN | TCP_ACK, &[])
    }

    /// One segment from the guest, as `-netdev dgram` would hand it over.
    fn segment_from(from: u16, to: u16, seq: u32, ack: u32, flags: u8, payload: &[u8]) -> Vec<u8> {
        let total = 20 + 20 + payload.len();
        let mut f = Vec::with_capacity(14 + total);
        f.extend_from_slice(&PEER_MAC);
        f.extend_from_slice(&GUEST_MAC);
        f.extend_from_slice(&ETHERTYPE_IPV4);
        f.push(0x45);
        f.push(0);
        f.extend_from_slice(&(total as u16).to_be_bytes());
        f.extend_from_slice(&[0, 1]);
        f.extend_from_slice(&[0, 0]);
        f.push(64);
        f.push(PROTO_TCP);
        f.extend_from_slice(&[0, 0]);
        f.extend_from_slice(&GUEST);
        f.extend_from_slice(&GATEWAY);
        f.extend_from_slice(&from.to_be_bytes());
        f.extend_from_slice(&to.to_be_bytes());
        f.extend_from_slice(&seq.to_be_bytes());
        f.extend_from_slice(&ack.to_be_bytes());
        f.push(5 << 4);
        f.push(flags);
        f.extend_from_slice(&[0xff, 0xff]);
        f.extend_from_slice(&[0, 0]);
        f.extend_from_slice(&[0, 0]);
        f.extend_from_slice(payload);
        f
    }

    /// The four option bytes that offer selective acknowledgement, padded as they go on a SYN.
    const SACK_PERMITTED_OPT: [u8; 4] = [TCP_OPT_NOP, TCP_OPT_NOP, TCP_OPT_SACK_PERMITTED, 2];

    /// One segment from the guest carrying `options`, which must be a whole number of words.
    #[allow(clippy::too_many_arguments)]
    fn segment_opts(
        from: u16,
        to: u16,
        seq: u32,
        ack: u32,
        flags: u8,
        options: &[u8],
        payload: &[u8],
    ) -> Vec<u8> {
        assert_eq!(options.len() % 4, 0, "a header is a whole number of words");
        let header = 20 + options.len();
        let total = 20 + header + payload.len();
        let mut f = Vec::with_capacity(14 + total);
        f.extend_from_slice(&PEER_MAC);
        f.extend_from_slice(&GUEST_MAC);
        f.extend_from_slice(&ETHERTYPE_IPV4);
        f.push(0x45);
        f.push(0);
        f.extend_from_slice(&(total as u16).to_be_bytes());
        f.extend_from_slice(&[0, 1]);
        f.extend_from_slice(&[0, 0]);
        f.push(64);
        f.push(PROTO_TCP);
        f.extend_from_slice(&[0, 0]);
        f.extend_from_slice(&GUEST);
        f.extend_from_slice(&GATEWAY);
        f.extend_from_slice(&from.to_be_bytes());
        f.extend_from_slice(&to.to_be_bytes());
        f.extend_from_slice(&seq.to_be_bytes());
        f.extend_from_slice(&ack.to_be_bytes());
        f.push(((header / 4) as u8) << 4);
        f.push(flags);
        f.extend_from_slice(&[0xff, 0xff]);
        f.extend_from_slice(&[0, 0]);
        f.extend_from_slice(&[0, 0]);
        f.extend_from_slice(options);
        f.extend_from_slice(payload);
        f
    }

    /// The selective blocks a segment this end sent names.
    fn blocks_of(frame: &[u8]) -> Vec<(u32, u32)> {
        let (ihl, _) = ipv4_header(frame).expect("a whole datagram");
        let at = 14 + ihl;
        let header = usize::from(frame[at + 12] >> 4) * 4;
        let opts = &frame[at + 20..at + header];
        let mut out = Vec::new();
        let mut i = 0;
        while i < opts.len() {
            match opts[i] {
                TCP_OPT_END => break,
                TCP_OPT_NOP => i += 1,
                kind => {
                    let n = usize::from(opts[i + 1]);
                    if kind == TCP_OPT_SACK {
                        let mut b = i + 2;
                        while b + 8 <= i + n {
                            let word =
                                |o: usize| u32::from_be_bytes(opts[o..o + 4].try_into().unwrap());
                            out.push((word(b), word(b + 4)));
                            b += 8;
                        }
                    }
                    i += n;
                }
            }
        }
        out
    }

    #[test]
    fn the_handshake_offers_selective_acknowledgement() {
        let mut p = peer();
        let service = p.ports.tcp;
        let syn = segment_opts(40000, service, 500, 0, TCP_SYN, &SACK_PERMITTED_OPT, &[]);
        let out = p.tcp(&syn);
        assert_eq!(out.len(), 1, "the handshake");
        let (ihl, _) = ipv4_header(&out[0]).expect("a whole datagram");
        let at = 14 + ihl;
        let header = usize::from(out[0][at + 12] >> 4) * 4;
        let (permitted, blocks) = tcp_options(&out[0][at + 20..at + header]);
        assert!(permitted, "the guest is told it may act on blocks");
        assert_eq!(blocks, 0, "a SYN has nothing held to report");
        // The segment size is still offered beside it: 1460, high byte first.
        assert_eq!(&out[0][at + 20..at + 24], &[TCP_OPT_MSS, 4, 0x05, 0xb4]);
    }

    #[test]
    fn the_runs_held_past_a_hole_are_named_nearest_first_and_joined() {
        let mut p = peer();
        let (guest, isn) = (40001u16, 900u32);
        let service = p.ports.tcp;
        let syn = segment_opts(guest, service, isn, 0, TCP_SYN, &SACK_PERMITTED_OPT, &[]);
        assert_eq!(p.tcp(&syn).len(), 1);
        let first = isn + 1;
        let seg = |n: u32, body: &'static [u8]| {
            segment_opts(guest, service, first + n, 0, TCP_ACK | TCP_PSH, &[], body)
        };
        // The first in-order segment is the one this end drops, so everything behind it lands
        // past a hole and has somewhere to be held.
        assert!(p.tcp(&seg(0, b"aa")).is_empty(), "dropped, and in silence");
        let out = p.tcp(&seg(4, b"ee"));
        assert_eq!(blocks_of(&out[0]), vec![(first + 4, first + 6)], "the one run held");
        // A run that meets the one already held is joined to it rather than named twice.
        let out = p.tcp(&seg(2, b"cc"));
        assert_eq!(
            blocks_of(&out[0]),
            vec![(first + 2, first + 6)],
            "adjacent runs are one block, and the nearest comes first"
        );
        assert_eq!(p.seen.selective_acks, 2);
    }

    #[test]
    fn a_guest_that_offered_nothing_is_sent_no_blocks() {
        let mut p = peer();
        let (guest, isn) = (40003u16, 700u32);
        let service = p.ports.tcp;
        // A SYN with no options at all: this guest never asked for selective acknowledgement,
        // so nothing may be sent to it however much is held.
        assert_eq!(
            p.tcp(&segment_from(guest, service, isn, 0, TCP_SYN, &[]))
                .len(),
            1
        );
        let first = isn + 1;
        assert!(
            p.tcp(&segment_from(guest, service, first, 0, TCP_ACK | TCP_PSH, b"aa"))
                .is_empty()
        );
        let out = p.tcp(&segment_from(guest, service, first + 4, 0, TCP_ACK | TCP_PSH, b"ee"));
        assert!(blocks_of(&out[0]).is_empty(), "it never asked for them");
        assert_eq!(p.seen.blocks_sent, 0);
    }

    #[test]
    fn blocks_the_guest_sends_of_its_own_are_counted() {
        let mut p = peer();
        let (guest, isn) = (40004u16, 300u32);
        let service = p.ports.tcp;
        let syn = segment_opts(guest, service, isn, 0, TCP_SYN, &SACK_PERMITTED_OPT, &[]);
        assert_eq!(p.tcp(&syn).len(), 1);
        // The guest's own receiver reporting a run it holds past a hole of its own.
        let mut option = vec![TCP_OPT_NOP, TCP_OPT_NOP, TCP_OPT_SACK, 10];
        option.extend_from_slice(&100u32.to_be_bytes());
        option.extend_from_slice(&200u32.to_be_bytes());
        let _ = p.tcp(&segment_opts(guest, service, isn + 1, 0, TCP_ACK, &option, &[]));
        assert_eq!(p.seen.guest_blocks, 1);
    }

    #[test]
    fn an_announced_listener_earns_a_connection_to_it() {
        let mut p = peer();
        let out = p.udp(&listening(&p, b"12345"));
        assert_eq!(out.len(), 1, "the SYN");
        let (from, to, _, ack, flags, _) = tcp_parts(&out[0]);
        assert_eq!(flags, TCP_SYN, "a SYN alone: this end opens the connection");
        assert_eq!(ack, 0, "nothing to acknowledge yet");
        assert_eq!(to, NET_GUEST_TCP_PORT, "to the guest's listener");
        assert_eq!(from, FIRST_LOCAL_PORT, "from a port of this end's own");
        assert_eq!(p.seen.opened, 1);
    }

    #[test]
    fn the_same_listener_announced_again_is_not_a_second_connection() {
        let mut p = peer();
        let first = p.udp(&listening(&p, b"12345"));
        assert_eq!(first.len(), 1);
        // Established, so a repeat has nothing left to do.
        let established = syn_ack(&first[0], 0x9000);
        let _ = p.tcp(&established);
        let again = p.udp(&listening(&p, b"12345"));
        assert!(again.is_empty(), "the number was already served");
        assert_eq!(p.seen.opened, 1, "one connection, not two");
    }

    #[test]
    fn an_unanswered_syn_is_sent_again_when_the_listener_is_announced_again() {
        let mut p = peer();
        let first = p.udp(&listening(&p, b"12345"));
        assert_eq!(first.len(), 1);
        // No answer to the SYN, so the repeat is the guest's own retry prompt.
        let again = p.udp(&listening(&p, b"12345"));
        assert_eq!(again.len(), 1, "the SYN goes again");
        assert_eq!(p.seen.opened, 1, "still one connection");
        let (from_a, _, seq_a, _, flags_a, _) = tcp_parts(&first[0]);
        let (from_b, _, seq_b, _, flags_b, _) = tcp_parts(&again[0]);
        assert_eq!((from_a, seq_a, flags_a), (from_b, seq_b, flags_b), "the same SYN");
    }

    #[test]
    fn two_numbers_are_two_connections_on_ports_of_their_own() {
        let mut p = peer();
        let one = p.udp(&listening(&p, b"111"));
        let two = p.udp(&listening(&p, b"222"));
        assert_eq!((one.len(), two.len()), (1, 1));
        let (from_one, to_one, ..) = tcp_parts(&one[0]);
        let (from_two, to_two, ..) = tcp_parts(&two[0]);
        assert_eq!(
            (to_one, to_two),
            (NET_GUEST_TCP_PORT, NET_GUEST_TCP_PORT),
            "both reach the one listener"
        );
        assert_ne!(from_one, from_two, "so only this end's port tells them apart");
        assert_eq!(p.seen.opened, 2);
    }

    #[test]
    fn the_handshake_is_followed_by_the_request_the_server_waits_for() {
        let mut p = peer();
        let syn = p.udp(&listening(&p, b"12345"));
        let out = p.tcp(&syn_ack(&syn[0], 0x9000));
        assert_eq!(out.len(), 2, "the acknowledgement, then the request");
        let (.., flags, empty) = tcp_parts(&out[0]);
        assert_eq!(flags, TCP_ACK);
        assert!(empty.is_empty());
        let (.., payload) = tcp_parts(&out[1]);
        assert_eq!(payload, b"kintane-tcp-inbound 12345\n");
    }

    #[test]
    fn the_reply_earns_the_verdict_that_names_its_tag_and_then_the_close() {
        let mut p = peer();
        let syn = p.udp(&listening(&p, b"12345"));
        let (local, _, ..) = tcp_parts(&syn[0]);
        let handshake = p.tcp(&syn_ack(&syn[0], 0x9000));
        let (.., request) = tcp_parts(&handshake[1]);
        let reply = b"kintane-tcp-inbound-reply 12345\n";
        let out =
            p.tcp(&segment_from(NET_GUEST_TCP_PORT, local, 0x9001, 0, TCP_ACK | TCP_PSH, reply));
        let lines: Vec<Vec<u8>> = out.iter().map(|f| tcp_parts(f).5).collect();
        assert!(
            lines
                .iter()
                .any(|l| l == b"kintane-tcp-inbound-verified 12345\n"),
            "the verdict names the tag: {lines:?}"
        );
        assert!(
            out.iter().any(|f| tcp_parts(f).4 & TCP_FIN != 0),
            "and the close follows it, which is the end of stream the server reads"
        );
        assert_eq!(p.seen.verdicts, 1);
        assert_eq!(request, b"kintane-tcp-inbound 12345\n");
    }

    #[test]
    fn a_reply_that_names_another_tag_is_judged_wrong() {
        let mut p = peer();
        let syn = p.udp(&listening(&p, b"12345"));
        let (local, _, ..) = tcp_parts(&syn[0]);
        let _ = p.tcp(&syn_ack(&syn[0], 0x9000));
        let out = p.tcp(&segment_from(
            NET_GUEST_TCP_PORT,
            local,
            0x9001,
            0,
            TCP_ACK | TCP_PSH,
            b"kintane-tcp-inbound-reply 99999\n",
        ));
        let lines: Vec<Vec<u8>> = out.iter().map(|f| tcp_parts(f).5).collect();
        assert!(
            lines
                .iter()
                .any(|l| l.starts_with(b"kintane-tcp-inbound-wrong ")),
            "a reply for another listener is refused, not accepted: {lines:?}"
        );
    }

    #[test]
    fn the_announcements_name_every_port_the_guest_cannot_guess() {
        let mut p = peer();
        let frames = p.announcements();
        // Four whole datagrams and the fragmented one as two.
        assert_eq!(frames.len(), 6);
        let whole: Vec<Vec<u8>> = frames[..4].iter().map(|f| udp_parts(f).2).collect();
        assert_eq!(whole[0], NET_PROBE);
        assert_eq!(whole[1], b"kintane-tcp-port 40002");
        assert_eq!(whole[2], b"kintane-udp-port 40003");
        assert_eq!(whole[3], b"kintane-udp-quiet 40004");
        for frame in &frames[..4] {
            let (from, to, _) = udp_parts(frame);
            assert_eq!((from, to), (ports().udp, NET_GUEST_PORT));
        }
    }

    #[test]
    fn the_fragmented_announcement_is_two_fragments_of_one_datagram() {
        let mut p = peer();
        let frames = p.announcements();
        let (first, second) = (&frames[4], &frames[5]);
        let flags = |f: &[u8]| u16::from_be_bytes([f[20], f[21]]);
        assert_eq!(flags(first) & 0x2000, 0x2000, "more to come");
        assert_eq!(flags(first) & 0x1fff, 0, "at the start");
        assert_eq!(flags(second) & 0x2000, 0, "the last one");
        assert_ne!(flags(second) & 0x1fff, 0, "further along");
        assert_eq!(first[18..20], second[18..20], "one datagram's parts carry one identifier");
        // Put back together, the payload is the datagram the guest checks byte for byte.
        let payload = |f: &[u8]| {
            let ihl = usize::from(f[14] & 0x0f) * 4;
            let total = usize::from(u16::from_be_bytes([f[16], f[17]]));
            f[14 + ihl..14 + total].to_vec()
        };
        let mut whole = payload(first);
        whole.extend(payload(second));
        let datagram = &whole[8..]; // past the UDP header the first fragment carries
        let rest = datagram
            .strip_prefix(NET_UDP_FRAGMENTED)
            .expect("the marker");
        let pattern = &rest[2..]; // the number and its space
        assert_eq!(pattern.len(), NET_FRAGMENT_PATTERN);
        assert!(
            pattern
                .iter()
                .enumerate()
                .all(|(i, b)| *b == (i as u8) ^ 0x5a)
        );
    }

    #[test]
    fn a_datagram_carries_a_checksum_a_receiver_can_check() {
        let mut p = peer();
        let frame = p
            .udp_frame(p.ports.udp, NET_GUEST_PORT, NET_PROBE)
            .expect("built");
        assert_eq!(ipv4_checksum(&frame[14..34]), 0, "the header's own");
        let mut all = Vec::new();
        all.extend_from_slice(&frame[26..30]);
        all.extend_from_slice(&frame[30..34]);
        all.push(0);
        all.push(PROTO_UDP);
        all.extend_from_slice(&((frame.len() - 34) as u16).to_be_bytes());
        all.extend_from_slice(&frame[34..]);
        assert_eq!(ipv4_checksum(&all), 0, "and the datagram's");
    }

    #[test]
    fn nothing_is_addressed_before_the_guest_has_been_heard_from() {
        let mut p = peer();
        p.guest_mac = None;
        assert!(p.announcements().is_empty());
        assert!(p.udp_frame(1, 2, b"x").is_none());
    }
}

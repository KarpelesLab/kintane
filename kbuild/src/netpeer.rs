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
//! - **Stage two**, here, is the datagram half: echo replies, the datagrams that tell the guest
//!   which ports to use, an acknowledgement for each echo it returns, a service that answers a
//!   request at the gateway's address, a port that answers nothing, and one datagram sent as two
//!   IPv4 fragments. Without a NAT there is nowhere else for those services to live: under
//!   `-netdev user` they are loopback sockets QEMU forwards to, and here the frames are all
//!   there is.
//!
//! The preset that turns it on is outside the gate's list until the peer can finish a TCP round.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use crate::qemu::{
    NET_ACK, NET_ECHO, NET_FRAGMENT_PATTERN, NET_GUEST_PORT, NET_PROBE, NET_TCP_ANNOUNCE,
    NET_UDP_ANNOUNCE, NET_UDP_FRAGMENTED, NET_UDP_QUIET, NET_UDP_REPLY, NET_UDP_REQUEST, NetPorts,
    fragment_datagram, ipv4_checksum, ipv4_header,
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
const ICMP_ECHO_REQUEST: u8 = 8;
const ICMP_ECHO_REPLY: u8 = 0;

/// How often the announcements go out, matching the slirp path's probe: a guest that is not
/// listening yet has missed nothing that will not come again.
const ANNOUNCE_EVERY: Duration = Duration::from_millis(250);

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
             {} acknowledgements, {} service replies, {} rounds of announcements",
            s.frames,
            s.arp_requests,
            s.arp_answered,
            s.echoes_answered,
            s.acks_sent,
            s.service_replies,
            s.announcements,
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
                Some(&PROTO_UDP) => self.udp(frame).into_iter().collect(),
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
    fn udp(&mut self, frame: &[u8]) -> Option<Vec<u8>> {
        let (ihl, total) = ipv4_header(frame)?;
        if frame.get(30..34)? != GATEWAY {
            return None;
        }
        let udp = 14 + ihl;
        let from = u16::from_be_bytes([*frame.get(udp)?, *frame.get(udp + 1)?]);
        let to = u16::from_be_bytes([*frame.get(udp + 2)?, *frame.get(udp + 3)?]);
        let payload = frame.get(udp + 8..14 + total)?;
        if to == self.ports.udp
            && let Some(number) = payload.strip_prefix(NET_ECHO)
        {
            self.seen.acks_sent += 1;
            let ack = [NET_ACK, number].concat();
            return self.udp_frame(self.ports.udp, from, &ack);
        }
        if to == self.ports.udp_service
            && let Some(tag) = payload.strip_prefix(NET_UDP_REQUEST)
        {
            self.seen.service_replies += 1;
            let reply = [NET_UDP_REPLY, tag].concat();
            return self.udp_frame(self.ports.udp_service, from, &reply);
        }
        None
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

    fn next_id(&mut self) -> u16 {
        self.ip_id = self.ip_id.wrapping_add(1);
        self.ip_id
    }
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
        assert!(p.udp(&[0u8; 20]).is_none());
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
        let reply = p.udp(&frame).expect("acknowledged");
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
        let reply = p.udp(&frame).expect("answered");
        let (from, to, payload) = udp_parts(&reply);
        assert_eq!(payload, b"kintane-udp-reply 42");
        assert_eq!(from, ports().udp_service);
        assert_eq!(to, 49152, "back to the port that asked");
    }

    #[test]
    fn the_quiet_port_answers_nothing() {
        let mut p = peer();
        let frame = datagram(GATEWAY, 49152, p.ports.quiet, b"kintane-udp-request 42");
        assert!(p.udp(&frame).is_none());
        assert_eq!(p.seen.service_replies, 0);
    }

    #[test]
    fn a_datagram_for_another_address_is_not_answered() {
        let mut p = peer();
        let frame = datagram([10, 0, 2, 99], NET_GUEST_PORT, p.ports.udp, b"kintane-udp-echo 1");
        assert!(p.udp(&frame).is_none());
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

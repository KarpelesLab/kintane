//! The whole stack against a simulated gateway, on the host.
//!
//! [`Link`] is both ends of a wire: the stack's device, and a peer that answers the way
//! QEMU's user-mode gateway does — ARP for its address, echo replies to pings, and a UDP
//! echo service on port 7. Knobs make the peer misbehave the ways a network can.

use core::cell::{Cell, RefCell};
use std::collections::VecDeque;

use crate::arp::Cache;
use crate::wire::{self, ARP_REPLY, ARP_REQUEST, Arp, BROADCAST, ETH_HEADER, ETHERTYPE_ARP, Frame};
use crate::{Config, NetError, Nic, NicError, Stack};

const US: [u8; 4] = [10, 0, 2, 15];
const GATEWAY: [u8; 4] = [10, 0, 2, 2];
const OFF_LINK: [u8; 4] = [192, 0, 2, 1];
const OUR_MAC: [u8; 6] = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
const GATEWAY_MAC: [u8; 6] = [0x52, 0x55, 0x0a, 0x00, 0x02, 0x02];
const MS: u64 = 1_000_000;

fn config() -> Config {
    Config {
        ip: US,
        netmask: [255, 255, 255, 0],
        gateway: GATEWAY,
    }
}

#[derive(Default)]
struct Link {
    /// Frames on their way to the stack.
    to_stack: RefCell<VecDeque<Vec<u8>>>,
    /// Frames the stack sent, as the peer saw them.
    sent: RefCell<Vec<Vec<u8>>>,
    /// Refuse every send, as a device with a full queue does.
    refuse: Cell<bool>,
    /// Corrupt the IPv4 header checksum of every packet the peer sends.
    bad_ip_checksum: Cell<bool>,
    /// Answer ARP requests with this operation instead of a reply.
    arp_operation: Cell<u16>,
    /// Do not answer anything.
    silent: Cell<bool>,
}

impl Link {
    fn new() -> Link {
        let l = Link::default();
        l.arp_operation.set(ARP_REPLY);
        l
    }

    fn deliver(&self, frame: Vec<u8>) {
        self.to_stack.borrow_mut().push_back(frame);
    }

    /// The peer's answer to one frame the stack sent.
    fn answer(&self, frame: &[u8]) {
        if self.silent.get() {
            return;
        }
        let Ok((eth, inner)) = wire::parse_frame(frame) else {
            return;
        };
        let mut out = [0u8; wire::FRAME_MAX];
        match inner {
            Frame::Arp(arp) if arp.operation == ARP_REQUEST && arp.target_ip == GATEWAY => {
                let reply = Arp {
                    operation: self.arp_operation.get(),
                    sender_mac: GATEWAY_MAC,
                    sender_ip: GATEWAY,
                    target_mac: arp.sender_mac,
                    target_ip: arp.sender_ip,
                };
                wire::write_ethernet(&mut out, eth.src, GATEWAY_MAC, ETHERTYPE_ARP).unwrap();
                let n = wire::write_arp(&mut out[ETH_HEADER..], &reply).unwrap();
                self.deliver(out[..ETH_HEADER + n].to_vec());
            }
            Frame::Echo(ip, echo) if echo.kind == wire::ICMP_ECHO_REQUEST => {
                let n = wire::write_icmp_echo(
                    &mut out[34..],
                    wire::ICMP_ECHO_REPLY,
                    echo.id,
                    echo.seq,
                    echo.data,
                )
                .unwrap();
                self.ip_reply(&mut out, eth.src, ip.src, ip.dst, wire::PROTO_ICMP, n);
            }
            Frame::Udp(ip, udp) if udp.dst_port == 7 => {
                let n =
                    wire::write_udp(&mut out[34..], ip.dst, ip.src, 7, udp.src_port, udp.payload)
                        .unwrap();
                self.ip_reply(&mut out, eth.src, ip.src, ip.dst, wire::PROTO_UDP, n);
            }
            _ => {}
        }
    }

    fn ip_reply(
        &self,
        out: &mut [u8; wire::FRAME_MAX],
        to_mac: [u8; 6],
        to: [u8; 4],
        from: [u8; 4],
        proto: u8,
        n: usize,
    ) {
        wire::write_ipv4(&mut out[ETH_HEADER..], from, to, proto, 7, n).unwrap();
        if self.bad_ip_checksum.get() {
            out[ETH_HEADER + 10] ^= 0x5a;
        }
        wire::write_ethernet(out, to_mac, GATEWAY_MAC, wire::ETHERTYPE_IPV4).unwrap();
        self.deliver(out[..34 + n].to_vec());
    }
}

impl Nic for Link {
    fn mac(&self) -> [u8; 6] {
        OUR_MAC
    }

    fn send(&self, frame: &[u8]) -> Result<(), NicError> {
        if self.refuse.get() {
            return Err(NicError);
        }
        self.sent.borrow_mut().push(frame.to_vec());
        self.answer(frame);
        Ok(())
    }

    fn recv(&self, into: &mut [u8]) -> Option<usize> {
        let frame = self.to_stack.borrow_mut().pop_front()?;
        let n = frame.len().min(into.len());
        into[..n].copy_from_slice(&frame[..n]);
        Some(n)
    }
}

fn stack() -> Box<Stack> {
    Box::new(Stack::new(config()))
}

/// Resolve the gateway: the first call sends a request, a poll takes the reply.
fn resolved(s: &mut Stack, link: &Link) -> [u8; 6] {
    assert_eq!(s.resolve(link, GATEWAY, 0), None, "nothing is known before a reply");
    s.poll(link, MS);
    s.resolve(link, GATEWAY, 2 * MS)
        .expect("the gateway answered")
}

#[test]
fn checksum_matches_rfc_1071_examples() {
    // RFC 1071 §3: the sum of these words is 0xddf2, so the checksum is its complement.
    let data = [0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7];
    assert_eq!(wire::checksum(&[&data]), !0xddf2);
    // Split at an odd boundary, the result is the same as over the whole.
    assert_eq!(wire::checksum(&[&data[..3], &data[3..]]), !0xddf2);
}

#[test]
fn a_written_ipv4_header_verifies_and_parses_back() {
    let mut buf = [0u8; 64];
    wire::write_ipv4(&mut buf, US, GATEWAY, wire::PROTO_UDP, 9, 12).unwrap();
    let ip = wire::parse_ipv4(&buf[..32]).unwrap();
    assert_eq!(
        (ip.src, ip.dst, ip.protocol, ip.payload.len()),
        (US, GATEWAY, wire::PROTO_UDP, 12)
    );
}

#[test]
fn a_bad_ipv4_checksum_is_refused() {
    let mut buf = [0u8; 40];
    wire::write_ipv4(&mut buf, US, GATEWAY, wire::PROTO_UDP, 9, 20).unwrap();
    buf[10] ^= 1;
    assert_eq!(wire::parse_ipv4(&buf), Err(wire::WireError::BadChecksum));
}

#[test]
fn a_fragment_is_refused_not_reassembled() {
    let mut buf = [0u8; 40];
    wire::write_ipv4(&mut buf, US, GATEWAY, wire::PROTO_UDP, 9, 20).unwrap();
    // More-fragments set, then the checksum made right again so only the flag is wrong.
    buf[6] = 0x20;
    buf[10..12].copy_from_slice(&[0, 0]);
    let sum = wire::checksum(&[&buf[..20]]);
    buf[10..12].copy_from_slice(&sum.to_be_bytes());
    assert_eq!(wire::parse_ipv4(&buf), Err(wire::WireError::Fragmented));
}

#[test]
fn lengths_are_believed_only_after_they_are_checked() {
    let mut buf = [0u8; 40];
    wire::write_ipv4(&mut buf, US, GATEWAY, wire::PROTO_UDP, 9, 20).unwrap();
    assert_eq!(wire::parse_ipv4(&buf[..30]), Err(wire::WireError::BadTotalLength));
    buf[0] = 0x4f; // a header length of 60 bytes in a 40-byte packet
    assert_eq!(wire::parse_ipv4(&buf), Err(wire::WireError::BadHeaderLength));
    let mut udp = [0u8; 16];
    wire::write_udp(&mut udp, US, GATEWAY, 1, 2, &[7; 8]).unwrap();
    udp[4..6].copy_from_slice(&40u16.to_be_bytes());
    assert_eq!(wire::parse_udp(&udp, US, GATEWAY), Err(wire::WireError::BadUdpLength));
    assert_eq!(wire::parse_ethernet(&[0; 13]), Err(wire::WireError::Short));
}

#[test]
fn a_udp_checksum_covers_the_pseudo_header() {
    let mut udp = [0u8; 16];
    wire::write_udp(&mut udp, US, GATEWAY, 1, 2, &[7; 8]).unwrap();
    assert!(wire::parse_udp(&udp, US, GATEWAY).is_ok());
    // The same bytes claimed to come from somewhere else no longer verify.
    assert_eq!(wire::parse_udp(&udp, OFF_LINK, GATEWAY), Err(wire::WireError::BadChecksum));
}

#[test]
fn the_gateway_is_resolved_and_the_request_is_not_repeated_every_call() {
    let link = Link::new();
    let mut s = stack();
    assert_eq!(s.resolve(&link, GATEWAY, 0), None);
    assert_eq!(s.resolve(&link, GATEWAY, MS), None);
    assert_eq!(s.counters().arp_requests_sent, 1, "a second call within the retry is quiet");
    s.poll(&link, 2 * MS);
    assert_eq!(s.resolve(&link, GATEWAY, 3 * MS), Some(GATEWAY_MAC));
    assert_eq!(s.counters().arp_learned, 1);
    let request = &link.sent.borrow()[0];
    let (eth, Frame::Arp(arp)) = wire::parse_frame(request).unwrap() else {
        panic!("the first frame is an ARP request");
    };
    assert_eq!((eth.dst, arp.operation, arp.target_ip), (BROADCAST, ARP_REQUEST, GATEWAY));
    assert!(s.balanced());
}

#[test]
fn a_forgotten_address_is_asked_for_again_but_not_sooner_than_the_retry_limit() {
    let link = Link::new();
    let mut s = stack();
    resolved(&mut s, &link);
    assert_eq!(s.counters().arp_learned, 1);
    s.forget(GATEWAY);
    assert_eq!(s.arp_entry(GATEWAY, 3 * MS), None);
    assert_eq!(s.resolve(&link, GATEWAY, 3 * MS), None);
    assert_eq!(s.counters().arp_requests_sent, 1, "the request at 0 ms still holds the retry");
    assert_eq!(s.resolve(&link, GATEWAY, 300 * MS), None);
    assert_eq!(s.counters().arp_requests_sent, 2);
    s.poll(&link, 301 * MS);
    assert_eq!(s.resolve(&link, GATEWAY, 302 * MS), Some(GATEWAY_MAC));
    assert_eq!(s.counters().arp_learned, 2, "resolved by a second reply, counted");
}

#[test]
fn an_off_link_address_resolves_through_the_gateway() {
    let link = Link::new();
    let mut s = stack();
    resolved(&mut s, &link);
    assert_eq!(s.resolve(&link, OFF_LINK, 3 * MS), Some(GATEWAY_MAC));
}

#[test]
fn an_arp_answer_with_the_wrong_operation_teaches_nothing() {
    let link = Link::new();
    link.arp_operation.set(3);
    let mut s = stack();
    assert_eq!(s.resolve(&link, GATEWAY, 0), None);
    s.poll(&link, MS);
    assert_eq!(s.resolve(&link, GATEWAY, 2 * MS), None);
    assert_eq!(s.counters().dropped_arp, 1);
    assert!(s.balanced());
}

#[test]
fn an_arp_entry_expires_and_is_asked_for_again() {
    let link = Link::new();
    let mut s = Box::new(Stack::with_arp(config(), Cache::with_ttl(100 * MS)));
    resolved(&mut s, &link);
    assert!(s.arp_entry(GATEWAY, 50 * MS).is_some());
    assert_eq!(s.arp_entry(GATEWAY, 500 * MS), None, "past its lifetime");
    assert_eq!(s.resolve(&link, GATEWAY, 500 * MS), None);
    assert_eq!(s.counters().arp_requests_sent, 2);
}

#[test]
fn a_ping_gets_the_reply_with_its_own_sequence_number() {
    let link = Link::new();
    let mut s = stack();
    assert_eq!(s.ping(&link, GATEWAY, 0x4b54, 1, 0), Err(NetError::Unresolved));
    s.poll(&link, MS);
    for seq in 1..=4 {
        s.ping(&link, GATEWAY, 0x4b54, seq, 2 * MS).unwrap();
    }
    s.poll(&link, 3 * MS);
    assert_eq!(s.take_echo_reply(0x4b54, 5), None, "no reply for a ping never sent");
    for seq in 1..=4 {
        assert_eq!(s.take_echo_reply(0x4b54, seq), Some(GATEWAY));
    }
    assert_eq!(s.take_echo_reply(0x4b54, 1), None, "taking a reply forgets it");
    assert_eq!(s.counters().echo_replies_received, 4);
    assert!(s.balanced());
}

#[test]
fn replies_with_a_bad_ip_checksum_are_dropped_and_counted() {
    let link = Link::new();
    let mut s = stack();
    resolved(&mut s, &link);
    link.bad_ip_checksum.set(true);
    s.ping(&link, GATEWAY, 1, 1, 3 * MS).unwrap();
    s.poll(&link, 4 * MS);
    assert_eq!(s.take_echo_reply(1, 1), None);
    assert_eq!(s.counters().dropped_ipv4, 1);
}

#[test]
fn a_udp_round_trip() {
    let link = Link::new();
    let mut s = stack();
    resolved(&mut s, &link);
    s.udp_send(&link, GATEWAY, 40000, 7, b"kintane-udp", 3 * MS)
        .unwrap();
    s.poll(&link, 4 * MS);
    let mut buf = [0u8; 64];
    let (from, port, n) = s.udp_recv(40000, &mut buf).expect("the echo arrived");
    assert_eq!((from, port, &buf[..n]), (GATEWAY, 7, &b"kintane-udp"[..]));
    assert_eq!(s.udp_recv(40000, &mut buf), None);
    assert!(s.balanced());
}

#[test]
fn the_stack_answers_arp_and_pings_addressed_to_it() {
    let link = Link::new();
    link.silent.set(true);
    let mut s = stack();
    // Someone asks who has our address.
    let mut out = [0u8; wire::FRAME_MAX];
    let ask = Arp {
        operation: ARP_REQUEST,
        sender_mac: GATEWAY_MAC,
        sender_ip: GATEWAY,
        target_mac: [0; 6],
        target_ip: US,
    };
    wire::write_ethernet(&mut out, BROADCAST, GATEWAY_MAC, ETHERTYPE_ARP).unwrap();
    let n = wire::write_arp(&mut out[ETH_HEADER..], &ask).unwrap();
    link.deliver(out[..ETH_HEADER + n].to_vec());
    // And then pings us.
    let n = wire::write_icmp_echo(&mut out[34..], wire::ICMP_ECHO_REQUEST, 9, 3, b"hi").unwrap();
    link.ip_reply(&mut out, OUR_MAC, US, GATEWAY, wire::PROTO_ICMP, n);
    s.poll(&link, MS);
    let c = s.counters();
    assert_eq!((c.arp_replies_sent, c.echo_replies_sent), (1, 1));
    let sent = link.sent.borrow();
    let (_, Frame::Arp(reply)) = wire::parse_frame(&sent[0]).unwrap() else {
        panic!("an ARP reply first");
    };
    assert_eq!((reply.operation, reply.target_ip), (ARP_REPLY, GATEWAY));
    let (_, Frame::Echo(ip, echo)) = wire::parse_frame(&sent[1]).unwrap() else {
        panic!("then an echo reply");
    };
    assert_eq!(
        (ip.dst, echo.kind, echo.id, echo.seq, echo.data),
        (GATEWAY, wire::ICMP_ECHO_REPLY, 9, 3, &b"hi"[..])
    );
    assert!(s.balanced());
}

#[test]
fn frames_for_other_hosts_are_ignored() {
    let link = Link::new();
    let mut s = stack();
    let mut out = [0u8; wire::FRAME_MAX];
    let n = wire::write_icmp_echo(&mut out[34..], wire::ICMP_ECHO_REQUEST, 1, 1, b"").unwrap();
    // To our MAC but another IP, then to another MAC entirely.
    link.ip_reply(&mut out, OUR_MAC, OFF_LINK, GATEWAY, wire::PROTO_ICMP, n);
    link.ip_reply(&mut out, [2; 6], US, GATEWAY, wire::PROTO_ICMP, n);
    s.poll(&link, MS);
    assert_eq!(s.counters().not_for_us, 2);
    assert_eq!(link.sent.borrow().len(), 0, "nothing answered");
}

#[test]
fn a_refused_send_is_an_error_and_holds_no_buffer() {
    let link = Link::new();
    let mut s = stack();
    resolved(&mut s, &link);
    link.refuse.set(true);
    assert_eq!(s.udp_send(&link, GATEWAY, 1, 7, b"x", 3 * MS), Err(NetError::Nic));
    assert_eq!(s.ping(&link, GATEWAY, 1, 1, 3 * MS), Err(NetError::Nic));
    assert!(s.balanced(), "a failed send gives its buffer back");
}

#[test]
fn a_datagram_too_large_for_one_frame_is_refused() {
    let link = Link::new();
    let mut s = stack();
    resolved(&mut s, &link);
    assert_eq!(s.udp_send(&link, GATEWAY, 1, 7, &[0; 1500], 3 * MS), Err(NetError::TooLarge));
}

#[test]
fn a_full_inbox_counts_what_it_could_not_keep() {
    let link = Link::new();
    let mut s = stack();
    resolved(&mut s, &link);
    for _ in 0..10 {
        s.udp_send(&link, GATEWAY, 5000, 7, b"fill", 3 * MS)
            .unwrap();
    }
    s.poll(&link, 4 * MS);
    let c = s.counters();
    assert_eq!((c.udp_received, c.inbox_full), (8, 2));
}

#[test]
fn a_truncated_datagram_reports_the_length_it_had() {
    let link = Link::new();
    let mut s = stack();
    resolved(&mut s, &link);
    s.udp_send(&link, GATEWAY, 40000, 7, b"0123456789", 3 * MS)
        .unwrap();
    s.poll(&link, 4 * MS);
    let mut small = [0u8; 4];
    let got = s.udp_recv_from(40000, &mut small);
    assert_eq!(got, Some((GATEWAY, 7, 4, 10)), "four copied, ten arrived");
    assert_eq!(&small, b"0123");
    // The rest went with it: a datagram is taken whole or not at all.
    assert_eq!(s.udp_recv_from(40000, &mut small), None);
    assert!(s.balanced());
}

#[test]
fn a_datagram_is_taken_by_the_port_it_was_sent_to() {
    let link = Link::new();
    let mut s = stack();
    resolved(&mut s, &link);
    // The link echoes each datagram back to the port it came from, so these land on two.
    s.udp_send(&link, GATEWAY, 40000, 7, b"first", 3 * MS)
        .unwrap();
    s.udp_send(&link, GATEWAY, 40001, 7, b"second", 3 * MS)
        .unwrap();
    s.poll(&link, 4 * MS);
    let mut buf = [0u8; 64];
    let (_, _, n, _) = s.udp_recv_from(40001, &mut buf).expect("the second arrived");
    assert_eq!(&buf[..n], b"second", "a port takes its own datagram, not the other's");
    let (_, _, n, _) = s.udp_recv_from(40000, &mut buf).expect("the first waited");
    assert_eq!(&buf[..n], b"first");
    assert_eq!(s.udp_recv_from(40002, &mut buf), None, "and no port takes another's");
    assert!(s.balanced());
}

#[test]
fn a_flood_is_handled_in_bounded_polls() {
    let link = Link::new();
    link.silent.set(true);
    let mut s = stack();
    // Shorter than an Ethernet header, so each is a drop at the first layer.
    for _ in 0..40 {
        link.deliver(vec![0u8; 10]);
    }
    let first = s.poll(&link, MS);
    assert!(first < 40, "one poll does not drain an unbounded queue");
    while s.poll(&link, MS) > 0 {}
    assert_eq!(s.counters().dropped_ethernet, 40);
    assert!(s.balanced());
}

#[test]
fn the_pool_refuses_a_double_give_and_hands_out_disjoint_pairs() {
    let mut p = crate::pool::Pool::new();
    let a = p.take().unwrap();
    let b = p.take().unwrap();
    {
        let (x, y) = p.pair(a, b).unwrap();
        x[0] = 1;
        y[0] = 2;
    }
    assert_eq!(p.buffer(a).unwrap()[0], 1);
    assert!(p.pair(a, a).is_none());
    assert!(p.give(a));
    assert!(!p.give(a), "a second give of the same buffer is refused");
    assert!(p.give(b));
    assert!(p.balanced());
}

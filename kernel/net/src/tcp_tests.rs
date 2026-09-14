//! TCP against a scripted peer, on the host.
//!
//! [`Wire`] is the stack's device and nothing more: it answers ARP so segments can leave, and
//! otherwise records what the stack sends and delivers what a test writes. Every segment the
//! peer sends is spelled out in the test that sends it, so loss is a segment the test does not
//! answer, duplication is one it delivers twice, and reordering is two it delivers out of turn.

use core::cell::RefCell;
use std::collections::VecDeque;

use crate::tcp::{
    BACKLOG, CONNECTIONS, Conn, DUP_ACK_THRESHOLD, INITIAL_WINDOW, MSS, OOO_SEGMENTS, RETRIES,
    RING, RTO_INITIAL_NS, RTO_MIN_NS, State, TIME_WAIT_NS,
};
use crate::wire::{
    self, ARP_REPLY, ARP_REQUEST, Arp, ETH_HEADER, ETHERTYPE_ARP, ETHERTYPE_IPV4, Frame, PROTO_TCP,
    TCP_ACK, TCP_FIN, TCP_PSH, TCP_RST, TCP_SYN, TcpHeader,
};
use crate::{Config, Nic, NicError, Stack, TcpError};

const US: [u8; 4] = [10, 0, 2, 15];
const PEER: [u8; 4] = [10, 0, 2, 2];
const OUR_MAC: [u8; 6] = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
const PEER_MAC: [u8; 6] = [0x52, 0x55, 0x0a, 0x00, 0x02, 0x02];
const PORT: u16 = 5556;
const PEER_ISS: u32 = 1000;
const MS: u64 = 1_000_000;

#[derive(Default)]
struct Wire {
    to_stack: RefCell<VecDeque<Vec<u8>>>,
    sent: RefCell<VecDeque<Vec<u8>>>,
}

/// A segment the stack sent, as the peer saw it.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Seg {
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    window: u16,
    mss: Option<u16>,
    payload: Vec<u8>,
}

impl Nic for Wire {
    fn mac(&self) -> [u8; 6] {
        OUR_MAC
    }

    fn send(&self, frame: &[u8]) -> Result<(), NicError> {
        if let Ok((_, Frame::Arp(arp))) = wire::parse_frame(frame)
            && arp.operation == ARP_REQUEST
        {
            let reply = Arp {
                operation: ARP_REPLY,
                sender_mac: PEER_MAC,
                sender_ip: arp.target_ip,
                target_mac: arp.sender_mac,
                target_ip: arp.sender_ip,
            };
            let mut out = [0u8; 64];
            wire::write_ethernet(&mut out, OUR_MAC, PEER_MAC, ETHERTYPE_ARP).unwrap();
            let n = wire::write_arp(&mut out[ETH_HEADER..], &reply).unwrap();
            self.to_stack
                .borrow_mut()
                .push_back(out[..ETH_HEADER + n].to_vec());
            return Ok(());
        }
        self.sent.borrow_mut().push_back(frame.to_vec());
        Ok(())
    }

    fn recv(&self, into: &mut [u8]) -> Option<usize> {
        let frame = self.to_stack.borrow_mut().pop_front()?;
        into[..frame.len()].copy_from_slice(&frame);
        Some(frame.len())
    }
}

impl Wire {
    /// Every TCP segment the stack sent since the last look.
    fn take(&self) -> Vec<Seg> {
        self.sent
            .borrow_mut()
            .drain(..)
            .map(|frame| match wire::parse_frame(&frame) {
                Ok((_, Frame::Tcp(ip, t))) => {
                    assert_eq!((ip.src, ip.dst), (US, PEER));
                    Seg {
                        src_port: t.src_port,
                        dst_port: t.dst_port,
                        seq: t.seq,
                        ack: t.ack,
                        flags: t.flags,
                        window: t.window,
                        mss: t.mss,
                        payload: t.payload.to_vec(),
                    }
                }
                other => panic!("the stack sent something other than TCP: {other:?}"),
            })
            .collect()
    }

    /// The one segment the stack sent since the last look.
    fn one(&self) -> Seg {
        let mut segs = self.take();
        assert_eq!(segs.len(), 1, "expected exactly one segment, got {segs:?}");
        segs.remove(0)
    }

    fn nothing(&self) {
        let segs = self.take();
        assert!(segs.is_empty(), "expected silence, got {segs:?}");
    }

    /// Deliver a segment from the peer to the stack.
    fn peer(&self, to_port: u16, seq: u32, ack: u32, flags: u8, payload: &[u8]) {
        self.peer_with(PORT, to_port, seq, ack, flags, 8192, None, payload);
    }

    #[allow(clippy::too_many_arguments)]
    fn peer_with(
        &self,
        from_port: u16,
        to_port: u16,
        seq: u32,
        ack: u32,
        flags: u8,
        window: u16,
        mss: Option<u16>,
        payload: &[u8],
    ) {
        let h = TcpHeader {
            src_port: from_port,
            dst_port: to_port,
            seq,
            ack,
            flags,
            window,
            mss,
        };
        let mut buf = vec![0u8; wire::FRAME_MAX];
        let n = wire::write_tcp(&mut buf[34..], PEER, US, &h, payload).unwrap();
        wire::write_ipv4(&mut buf[ETH_HEADER..], PEER, US, PROTO_TCP, 1, n).unwrap();
        wire::write_ethernet(&mut buf, OUR_MAC, PEER_MAC, ETHERTYPE_IPV4).unwrap();
        buf.truncate(34 + n);
        self.to_stack.borrow_mut().push_back(buf);
    }
}

fn stack() -> Box<Stack> {
    Box::new(Stack::new(Config {
        ip: US,
        netmask: [255, 255, 255, 0],
        gateway: PEER,
    }))
}

/// A stack with the peer's address resolved, so no segment waits on ARP.
fn ready() -> (Box<Stack>, Wire) {
    let (mut s, w) = (stack(), Wire::default());
    assert_eq!(s.resolve(&w, PEER, 0), None);
    s.poll(&w, 0);
    assert!(s.resolve(&w, PEER, 0).is_some());
    (s, w)
}

/// An established connection, and the SYN that opened it.
fn open(s: &mut Stack, w: &Wire) -> (Conn, Seg) {
    let c = s.tcp_connect(w, PEER, PORT, 0).unwrap();
    let syn = w.one();
    assert_eq!(syn.flags, TCP_SYN, "{syn:?}");
    assert_eq!(syn.mss, Some(MSS));
    assert_eq!(s.tcp_status(c).unwrap().state, State::SynSent);
    w.peer_with(
        PORT,
        syn.src_port,
        PEER_ISS,
        syn.seq.wrapping_add(1),
        TCP_SYN | TCP_ACK,
        8192,
        Some(1460),
        &[],
    );
    s.poll(w, MS);
    let ack = w.one();
    assert_eq!((ack.flags, ack.seq, ack.ack), (TCP_ACK, syn.seq.wrapping_add(1), PEER_ISS + 1));
    assert_eq!(s.tcp_status(c).unwrap().state, State::Established);
    assert!(s.books_consistent());
    (c, syn)
}

fn read_all(s: &mut Stack, w: &Wire, c: Conn) -> Vec<u8> {
    let mut out = Vec::new();
    let mut buf = [0u8; 64];
    loop {
        match s.tcp_recv(w, c, &mut buf, MS) {
            Ok(0) | Err(TcpError::WouldBlock) => return out,
            Ok(n) => out.extend_from_slice(&buf[..n]),
            Err(e) => panic!("{e:?}"),
        }
    }
}

// ---- the wire format ----------------------------------------------------------------------

#[test]
fn a_written_segment_parses_back_with_its_option() {
    let h = TcpHeader {
        src_port: 1,
        dst_port: 2,
        seq: 0xdead_beef,
        ack: 7,
        flags: TCP_SYN | TCP_ACK,
        window: 512,
        mss: Some(1400),
    };
    let mut buf = [0u8; 64];
    let n = wire::write_tcp(&mut buf, US, PEER, &h, b"hi").unwrap();
    let t = wire::parse_tcp(&buf[..n], US, PEER).unwrap();
    assert_eq!(
        (t.src_port, t.dst_port, t.seq, t.ack, t.flags, t.window, t.mss, t.payload),
        (1, 2, 0xdead_beef, 7, TCP_SYN | TCP_ACK, 512, Some(1400), &b"hi"[..])
    );
    // The checksum covers the pseudo-header: the same bytes between other hosts do not verify.
    assert_eq!(wire::parse_tcp(&buf[..n], US, US), Err(wire::WireError::BadChecksum));
}

#[test]
fn a_bad_data_offset_or_option_length_is_refused() {
    let h = TcpHeader {
        src_port: 1,
        dst_port: 2,
        seq: 0,
        ack: 0,
        flags: TCP_SYN,
        window: 0,
        mss: Some(536),
    };
    let fix = |buf: &mut [u8]| {
        buf[16..18].copy_from_slice(&[0, 0]);
        let len = buf.len() as u16;
        let mut pseudo = [0u8; 12];
        pseudo[0..4].copy_from_slice(&US);
        pseudo[4..8].copy_from_slice(&PEER);
        pseudo[9] = PROTO_TCP;
        pseudo[10..12].copy_from_slice(&len.to_be_bytes());
        let sum = wire::checksum(&[&pseudo, buf]);
        buf[16..18].copy_from_slice(&sum.to_be_bytes());
    };
    let mut buf = [0u8; 24];
    wire::write_tcp(&mut buf, US, PEER, &h, &[]).unwrap();
    // A data offset of 60 bytes in a 24-byte segment.
    buf[12] = 0xf0;
    fix(&mut buf);
    assert_eq!(wire::parse_tcp(&buf, US, PEER), Err(wire::WireError::BadTcpHeader));
    // An option whose length runs past the header.
    buf[12] = 0x60;
    buf[21] = 9;
    fix(&mut buf);
    assert_eq!(wire::parse_tcp(&buf, US, PEER), Err(wire::WireError::BadTcpHeader));
    // A data offset below the fixed header.
    buf[12] = 0x40;
    fix(&mut buf);
    assert_eq!(wire::parse_tcp(&buf, US, PEER), Err(wire::WireError::BadTcpHeader));
    assert_eq!(wire::parse_tcp(&buf[..19], US, PEER), Err(wire::WireError::Short));
}

// ---- opening, exchanging, closing ---------------------------------------------------------

#[test]
fn a_round_trip_closed_by_us_first() {
    let (mut s, w) = ready();
    let (c, syn) = open(&mut s, &w);
    let (me, iss) = (syn.src_port, syn.seq);

    assert_eq!(s.tcp_send(&w, c, b"hello", 2 * MS), Ok(5));
    let data = w.one();
    assert_eq!(
        (data.flags, data.seq, data.ack, &data.payload[..]),
        (TCP_ACK | TCP_PSH, iss + 1, PEER_ISS + 1, &b"hello"[..])
    );
    // The peer acknowledges and answers in one segment.
    w.peer(me, PEER_ISS + 1, iss + 6, TCP_ACK | TCP_PSH, b"world");
    s.poll(&w, 3 * MS);
    let ack = w.one();
    assert_eq!((ack.flags, ack.seq, ack.ack), (TCP_ACK, iss + 6, PEER_ISS + 6));
    assert_eq!(read_all(&mut s, &w, c), b"world");
    assert_eq!(s.tcp_status(c).unwrap().unacknowledged, 0);

    s.tcp_close(&w, c, 4 * MS).unwrap();
    let fin = w.one();
    assert_eq!((fin.flags, fin.seq), (TCP_FIN | TCP_ACK, iss + 6));
    w.peer(me, PEER_ISS + 6, iss + 7, TCP_ACK, &[]);
    s.poll(&w, 5 * MS);
    w.nothing();
    assert_eq!(s.tcp_status(c).unwrap().state, State::FinWait2);
    w.peer(me, PEER_ISS + 6, iss + 7, TCP_FIN | TCP_ACK, &[]);
    s.poll(&w, 6 * MS);
    let last = w.one();
    assert_eq!((last.flags, last.ack), (TCP_ACK, PEER_ISS + 7));
    let status = s.tcp_status(c).unwrap();
    assert_eq!(status.state, State::TimeWait);
    for state in [
        State::SynSent,
        State::Established,
        State::FinWait1,
        State::FinWait2,
    ] {
        assert_ne!(status.visited & state.bit(), 0, "never in {state:?}");
    }
    // Both rings are back the moment the connection is in TIME-WAIT; the slot waits.
    assert!(s.balanced());
    assert_eq!(s.tcp_slots_in_use(), 1);
    s.poll(&w, 6 * MS + TIME_WAIT_NS);
    assert_eq!(s.tcp_slots_in_use(), 0);
    assert!(s.tcp_status(c).is_none(), "a reaped connection's name names nothing");
    assert!(s.balanced());
}

#[test]
fn a_round_trip_closed_by_the_peer_first() {
    let (mut s, w) = ready();
    let (c, syn) = open(&mut s, &w);
    let (me, iss) = (syn.src_port, syn.seq);
    s.tcp_send(&w, c, b"request", 2 * MS).unwrap();
    w.one();
    w.peer(me, PEER_ISS + 1, iss + 8, TCP_ACK | TCP_PSH | TCP_FIN, b"reply");
    s.poll(&w, 3 * MS);
    let ack = w.one();
    assert_eq!(ack.ack, PEER_ISS + 1 + 5 + 1, "the reply and the FIN are both acknowledged");
    assert_eq!(s.tcp_status(c).unwrap().state, State::CloseWait);
    assert_eq!(read_all(&mut s, &w, c), b"reply");
    let mut buf = [0u8; 8];
    assert_eq!(s.tcp_recv(&w, c, &mut buf, 3 * MS), Ok(0), "the end of the stream");
    s.tcp_close(&w, c, 4 * MS).unwrap();
    let fin = w.one();
    assert_eq!((fin.flags, fin.seq), (TCP_FIN | TCP_ACK, iss + 8));
    assert_eq!(s.tcp_status(c).unwrap().state, State::LastAck);
    assert_eq!(s.tcp_rings_held(), 2, "not over until the FIN is acknowledged");
    w.peer(me, PEER_ISS + 7, iss + 9, TCP_ACK, &[]);
    s.poll(&w, 5 * MS);
    assert!(s.tcp_status(c).is_none());
    assert_eq!(s.tcp_slots_in_use(), 0);
    assert!(s.balanced());
}

#[test]
fn both_ends_closing_at_once_pass_through_closing() {
    let (mut s, w) = ready();
    let (c, syn) = open(&mut s, &w);
    let (me, iss) = (syn.src_port, syn.seq);
    s.tcp_close(&w, c, 2 * MS).unwrap();
    assert_eq!(w.one().flags, TCP_FIN | TCP_ACK);
    // The peer's FIN crosses ours: it does not acknowledge ours yet.
    w.peer(me, PEER_ISS + 1, iss + 1, TCP_FIN | TCP_ACK, &[]);
    s.poll(&w, 3 * MS);
    assert_eq!(w.one().ack, PEER_ISS + 2);
    assert_eq!(s.tcp_status(c).unwrap().state, State::Closing);
    w.peer(me, PEER_ISS + 2, iss + 2, TCP_ACK, &[]);
    s.poll(&w, 4 * MS);
    assert_eq!(s.tcp_status(c).unwrap().state, State::TimeWait);
    assert!(s.balanced());
}

#[test]
fn a_listener_accepts_a_connection_and_answers_it() {
    let (mut s, w) = ready();
    let l = s.tcp_listen(80).unwrap();
    assert_eq!(s.tcp_accept(l), Err(TcpError::WouldBlock));
    w.peer_with(40000, 80, 5000, 0, TCP_SYN, 8192, Some(1000), &[]);
    s.poll(&w, MS);
    let synack = w.one();
    assert_eq!((synack.flags, synack.ack, synack.dst_port), (TCP_SYN | TCP_ACK, 5001, 40000));
    assert_eq!(s.tcp_accept(l), Err(TcpError::WouldBlock), "not before the handshake ends");
    w.peer_with(40000, 80, 5001, synack.seq + 1, TCP_ACK | TCP_PSH, 8192, None, b"ping");
    s.poll(&w, 2 * MS);
    assert_eq!(w.one().ack, 5005);
    let c = s.tcp_accept(l).unwrap();
    assert_eq!(read_all(&mut s, &w, c), b"ping");
    s.tcp_send(&w, c, b"pong", 3 * MS).unwrap();
    assert_eq!(w.one().payload, b"pong");
    // Closing the listener leaves an accepted connection alone.
    s.tcp_close(&w, l, 4 * MS).unwrap();
    assert_eq!(s.tcp_status(c).unwrap().state, State::Established);
    assert!(s.books_consistent());
}

#[test]
fn a_listener_backlog_is_bounded_and_closing_it_resets_the_unaccepted() {
    let (mut s, w) = ready();
    let l = s.tcp_listen(80).unwrap();
    for port in 0..BACKLOG as u16 + 1 {
        w.peer_with(40000 + port, 80, 5000, 0, TCP_SYN, 8192, None, &[]);
        s.poll(&w, MS);
    }
    let answered = w.take();
    assert_eq!(answered.len(), BACKLOG, "one SYN past the backlog is dropped: {answered:?}");
    assert_eq!(s.tcp_counters().syns_refused, 1);
    s.tcp_close(&w, l, 2 * MS).unwrap();
    let resets = w.take();
    assert_eq!(resets.len(), BACKLOG);
    assert!(resets.iter().all(|r| r.flags & TCP_RST != 0));
    assert_eq!(s.tcp_slots_in_use(), 0);
    assert!(s.balanced());
}

// ---- loss, duplication, reordering --------------------------------------------------------

#[test]
fn a_lost_data_segment_is_sent_again_when_the_timer_runs_out() {
    let (mut s, w) = ready();
    let (c, syn) = open(&mut s, &w);
    let (me, iss) = (syn.src_port, syn.seq);
    s.tcp_send(&w, c, b"lost", 10 * MS).unwrap();
    let first = w.one();
    // The timeout is what the handshake's round trip works out to, not a fixed wait.
    let rto = s.tcp_status(c).unwrap().rto_ns;
    let sent_at = 10 * MS;
    // The peer never sees it. Nothing is sent again before the timeout...
    s.poll(&w, sent_at + rto - 1);
    w.nothing();
    // ...and exactly the same segment is at it.
    s.poll(&w, sent_at + rto);
    let again = w.one();
    assert_eq!((again.seq, &again.payload), (first.seq, &first.payload));
    let counters = s.tcp_counters();
    assert_eq!((counters.retransmit_timeouts, counters.data_retransmits), (1, 1));
    // Lost again: the timeout has doubled, and the estimate is left alone, since a
    // measurement of a segment sent twice would belong to neither copy (Karn's rule).
    let second = sent_at + rto;
    s.poll(&w, second + 2 * rto - 1);
    w.nothing();
    s.poll(&w, second + 2 * rto);
    assert_eq!(w.one().seq, iss + 1);
    // Acknowledged at last: the timer stops.
    w.peer(me, PEER_ISS + 1, iss + 5, TCP_ACK, &[]);
    s.poll(&w, second + 2 * rto + MS);
    s.poll(&w, second + 100 * rto);
    w.nothing();
    assert_eq!(s.tcp_counters().data_retransmits, 2);
}

#[test]
fn a_lost_syn_is_sent_again() {
    let (mut s, w) = ready();
    let c = s.tcp_connect(&w, PEER, PORT, 0).unwrap();
    let syn = w.one();
    s.poll(&w, RTO_INITIAL_NS);
    let again = w.one();
    assert_eq!((again.flags, again.seq), (TCP_SYN, syn.seq));
    assert_eq!(s.tcp_counters().data_retransmits, 0, "a SYN carries no data");
    assert_eq!(s.tcp_status(c).unwrap().state, State::SynSent);
}

#[test]
fn go_back_n_resends_from_the_oldest_unacknowledged_byte() {
    let (mut s, w) = ready();
    let (c, syn) = open(&mut s, &w);
    let (me, iss) = (syn.src_port, syn.seq);
    s.tcp_send(&w, c, b"aaaa", 2 * MS).unwrap();
    s.tcp_send(&w, c, b"bbbb", 2 * MS).unwrap();
    let sent = w.take();
    assert_eq!(sent.len(), 2);
    // Only the first arrives. Its acknowledgement restarts the timer (RFC 6298 §5.3).
    w.peer(me, PEER_ISS + 1, iss + 5, TCP_ACK, &[]);
    s.poll(&w, 3 * MS);
    w.nothing();
    let rto = s.tcp_status(c).unwrap().rto_ns;
    s.poll(&w, 3 * MS + rto - 1);
    w.nothing();
    s.poll(&w, 3 * MS + rto);
    let again = w.one();
    assert_eq!((again.seq, &again.payload[..]), (iss + 5, &b"bbbb"[..]));
}

#[test]
fn a_duplicated_segment_is_acknowledged_and_delivered_once() {
    let (mut s, w) = ready();
    let (c, syn) = open(&mut s, &w);
    let (me, iss) = (syn.src_port, syn.seq);
    w.peer(me, PEER_ISS + 1, iss + 1, TCP_ACK | TCP_PSH, b"once");
    s.poll(&w, 2 * MS);
    assert_eq!(w.one().ack, PEER_ISS + 5);
    // The duplicate is answered too, since the peer's copy of that ACK may be what was lost.
    w.peer(me, PEER_ISS + 1, iss + 1, TCP_ACK | TCP_PSH, b"once");
    s.poll(&w, 2 * MS);
    assert_eq!(w.one().ack, PEER_ISS + 5);
    assert_eq!(read_all(&mut s, &w, c), b"once");
    assert_eq!(s.tcp_counters().duplicates, 1);
    // A segment that overlaps what arrived is trimmed, not taken twice.
    w.peer(me, PEER_ISS + 3, iss + 1, TCP_ACK | TCP_PSH, b"ce more");
    s.poll(&w, 3 * MS);
    assert_eq!(w.one().ack, PEER_ISS + 10);
    assert_eq!(read_all(&mut s, &w, c), b" more");
}

#[test]
fn a_reordered_segment_is_held_and_the_stream_comes_out_in_order() {
    let (mut s, w) = ready();
    let (c, syn) = open(&mut s, &w);
    let (me, iss) = (syn.src_port, syn.seq);
    // The second segment arrives first: held, and acknowledged with what is still expected,
    // which is what tells the peer which segment to send again.
    w.peer(me, PEER_ISS + 4, iss + 1, TCP_ACK | TCP_PSH, b"def");
    s.poll(&w, 2 * MS);
    assert_eq!(w.one().ack, PEER_ISS + 1);
    assert_eq!(read_all(&mut s, &w, c), b"", "nothing is readable across a hole");
    let counters = s.tcp_counters();
    assert_eq!((counters.out_of_order, counters.out_of_order_queued), (1, 1));
    assert_eq!(s.tcp_status(c).unwrap().held_out_of_order, 1);
    // The hole is filled: both runs are the stream now, acknowledged together and read in
    // order, without the peer sending the second one again.
    w.peer(me, PEER_ISS + 1, iss + 1, TCP_ACK | TCP_PSH, b"abc");
    s.poll(&w, 3 * MS);
    assert_eq!(w.one().ack, PEER_ISS + 7);
    assert_eq!(read_all(&mut s, &w, c), b"abcdef");
    assert_eq!(s.tcp_counters().out_of_order_delivered, 1);
    assert_eq!(s.tcp_status(c).unwrap().held_out_of_order, 0);
    // A copy the peer sent again anyway is old news: acknowledged, and delivered to nobody.
    w.peer(me, PEER_ISS + 4, iss + 1, TCP_ACK | TCP_PSH, b"def");
    s.poll(&w, 4 * MS);
    assert_eq!(w.one().ack, PEER_ISS + 7);
    assert_eq!(read_all(&mut s, &w, c), b"");
    assert!(s.books_consistent());
}

#[test]
fn a_fin_ahead_of_missing_data_waits_for_it() {
    let (mut s, w) = ready();
    let (c, syn) = open(&mut s, &w);
    let (me, iss) = (syn.src_port, syn.seq);
    w.peer(me, PEER_ISS + 4, iss + 1, TCP_ACK | TCP_FIN, b"end");
    s.poll(&w, 2 * MS);
    assert_eq!(w.one().ack, PEER_ISS + 1);
    assert_eq!(s.tcp_status(c).unwrap().state, State::Established);
    w.peer(me, PEER_ISS + 1, iss + 1, TCP_ACK | TCP_FIN, b"abcend");
    s.poll(&w, 3 * MS);
    assert_eq!(w.one().ack, PEER_ISS + 8);
    assert_eq!(s.tcp_status(c).unwrap().state, State::CloseWait);
}

#[test]
fn retransmissions_run_out_and_the_connection_is_reset() {
    let (mut s, w) = ready();
    let (c, _) = open(&mut s, &w);
    s.tcp_send(&w, c, b"into the void", 0).unwrap();
    w.take();
    let mut now = 0;
    for _ in 0..=RETRIES {
        now += 10 * RTO_INITIAL_NS * 100;
        s.poll(&w, now);
    }
    let segs = w.take();
    assert_eq!(segs.last().map(|r| r.flags), Some(TCP_RST | TCP_ACK), "{segs:?}");
    let status = s.tcp_status(c).unwrap();
    assert_eq!((status.state, status.error), (State::Closed, Some(TcpError::TimedOut)));
    assert_eq!(s.tcp_send(&w, c, b"x", now), Err(TcpError::TimedOut));
    assert_eq!(s.tcp_counters().timeouts, 1);
    // Its rings are held until its owner lets go.
    assert_eq!(s.tcp_rings_held(), 2);
    s.tcp_close(&w, c, now).unwrap();
    assert!(s.balanced());
    assert_eq!(s.tcp_slots_in_use(), 0);
}

// ---- sequence checks -----------------------------------------------------------------------

#[test]
fn a_wrong_acknowledgement_to_our_syn_is_answered_with_a_reset() {
    let (mut s, w) = ready();
    let c = s.tcp_connect(&w, PEER, PORT, 0).unwrap();
    let syn = w.one();
    w.peer(syn.src_port, PEER_ISS, syn.seq.wrapping_add(2), TCP_SYN | TCP_ACK, &[]);
    s.poll(&w, MS);
    let rst = w.one();
    assert_eq!((rst.flags, rst.seq), (TCP_RST, syn.seq.wrapping_add(2)));
    assert_eq!(s.tcp_status(c).unwrap().state, State::SynSent, "the attempt goes on");
}

#[test]
fn a_refused_connection_reports_the_reset() {
    let (mut s, w) = ready();
    let c = s.tcp_connect(&w, PEER, PORT, 0).unwrap();
    let syn = w.one();
    w.peer(syn.src_port, 0, syn.seq + 1, TCP_RST | TCP_ACK, &[]);
    s.poll(&w, MS);
    w.nothing();
    let status = s.tcp_status(c).unwrap();
    assert_eq!((status.state, status.error), (State::Closed, Some(TcpError::Reset)));
    s.tcp_close(&w, c, MS).unwrap();
    assert!(s.balanced());
}

#[test]
fn only_an_exact_reset_ends_a_connection() {
    let (mut s, w) = ready();
    let (c, syn) = open(&mut s, &w);
    let (me, iss) = (syn.src_port, syn.seq);
    // In the window but not the next expected byte: a challenge ACK, and nothing else.
    w.peer(me, PEER_ISS + 100, iss + 1, TCP_RST, &[]);
    s.poll(&w, 2 * MS);
    assert_eq!(w.one().flags, TCP_ACK);
    assert_eq!(s.tcp_status(c).unwrap().state, State::Established);
    // Outside the window: dropped.
    w.peer(me, PEER_ISS + 1 + RING as u32 + 10, iss + 1, TCP_RST, &[]);
    s.poll(&w, 3 * MS);
    w.nothing();
    // A SYN on an established connection is challenged, not obeyed.
    w.peer(me, PEER_ISS + 1, 0, TCP_SYN, &[]);
    s.poll(&w, 4 * MS);
    assert_eq!(w.one().flags, TCP_ACK);
    assert_eq!(s.tcp_status(c).unwrap().state, State::Established);
    w.peer(me, PEER_ISS + 1, iss + 1, TCP_RST, &[]);
    s.poll(&w, 5 * MS);
    w.nothing();
    assert_eq!(s.tcp_status(c).unwrap().error, Some(TcpError::Reset));
    assert_eq!(s.tcp_counters().resets_received, 1);
}

#[test]
fn an_acknowledgement_for_unsent_data_is_answered_and_ignored() {
    let (mut s, w) = ready();
    let (c, syn) = open(&mut s, &w);
    let (me, iss) = (syn.src_port, syn.seq);
    s.tcp_send(&w, c, b"abc", 2 * MS).unwrap();
    w.one();
    w.peer(me, PEER_ISS + 1, iss + 100, TCP_ACK, &[]);
    s.poll(&w, 3 * MS);
    assert_eq!(w.one().flags, TCP_ACK);
    assert_eq!(s.tcp_status(c).unwrap().unacknowledged, 3, "nothing was taken as delivered");
    s.poll(&w, 2 * MS + RTO_INITIAL_NS);
    assert_eq!(w.one().payload, b"abc");
}

#[test]
fn a_segment_for_no_connection_is_reset_and_a_reset_is_not() {
    let (mut s, w) = ready();
    w.peer_with(7777, 9999, 42, 0, TCP_SYN, 8192, None, &[]);
    s.poll(&w, MS);
    let rst = w.one();
    assert_eq!((rst.flags, rst.ack, rst.dst_port), (TCP_RST | TCP_ACK, 43, 7777));
    w.peer_with(7777, 9999, 42, 9, TCP_ACK, 8192, None, b"data");
    s.poll(&w, 2 * MS);
    let rst = w.one();
    assert_eq!((rst.flags, rst.seq), (TCP_RST, 9 + 0));
    assert_eq!(rst.seq, 9);
    w.peer_with(7777, 9999, 42, 9, TCP_RST, 8192, None, &[]);
    s.poll(&w, 3 * MS);
    w.nothing();
    assert!(s.balanced());
}

// ---- windows and memory --------------------------------------------------------------------

#[test]
fn the_receive_window_is_the_ring_and_a_read_announces_it_again() {
    let (mut s, w) = ready();
    let (c, syn) = open(&mut s, &w);
    let (me, iss) = (syn.src_port, syn.seq);
    let chunk = vec![7u8; 1000];
    w.peer(me, PEER_ISS + 1, iss + 1, TCP_ACK, &chunk);
    s.poll(&w, 2 * MS);
    assert_eq!(w.one().window as usize, RING - 1000);
    // More than fits: the ring takes what it can, and the window shuts.
    w.peer(me, PEER_ISS + 1001, iss + 1, TCP_ACK, &chunk);
    s.poll(&w, 3 * MS);
    let ack = w.one();
    assert_eq!((ack.ack, ack.window), (PEER_ISS + 1 + RING as u32, 0));
    // With the window shut, a segment is not taken, but its acknowledgement still is.
    s.tcp_send(&w, c, b"x", 4 * MS).unwrap();
    w.one();
    w.peer(me, PEER_ISS + 1 + RING as u32, iss + 2, TCP_ACK, b"no room");
    s.poll(&w, 5 * MS);
    assert_eq!(w.one().window, 0);
    assert_eq!(s.tcp_status(c).unwrap().unacknowledged, 0);
    let mut buf = vec![0u8; RING];
    assert_eq!(s.tcp_recv(&w, c, &mut buf, 6 * MS), Ok(RING));
    let update = w.one();
    assert_eq!((update.flags, update.window as usize), (TCP_ACK, RING));
}

#[test]
fn the_peers_window_and_segment_size_are_respected_and_a_shut_window_is_probed() {
    let (mut s, w) = ready();
    let c = s.tcp_connect(&w, PEER, PORT, 0).unwrap();
    let syn = w.one();
    let (me, iss) = (syn.src_port, syn.seq);
    w.peer_with(PORT, me, PEER_ISS, iss + 1, TCP_SYN | TCP_ACK, 250, Some(100), &[]);
    s.poll(&w, MS);
    w.one();
    s.tcp_send(&w, c, &[1u8; 400], 2 * MS).unwrap();
    let segs = w.take();
    let lens: Vec<usize> = segs.iter().map(|s| s.payload.len()).collect();
    assert_eq!(lens, [100, 100, 50], "a 100-byte segment size and a 250-byte window");
    // Everything acknowledged, and the window shut.
    w.peer_with(PORT, me, PEER_ISS + 1, iss + 251, TCP_ACK, 0, None, &[]);
    s.poll(&w, 3 * MS);
    w.nothing();
    s.poll(&w, 3 * MS + RTO_INITIAL_NS);
    let probe = w.one();
    assert_eq!((probe.seq, probe.payload.len()), (iss + 251, 1));
    w.peer_with(PORT, me, PEER_ISS + 1, iss + 252, TCP_ACK, 1000, None, &[]);
    s.poll(&w, 4 * MS + RTO_INITIAL_NS);
    let rest = w.take();
    assert_eq!(rest.iter().map(|s| s.payload.len()).sum::<usize>(), 149);
}

#[test]
fn connections_hold_two_buffers_each_and_the_pool_bounds_them() {
    let (mut s, w) = ready();
    let mut conns = Vec::new();
    for _ in 0..CONNECTIONS {
        conns.push(s.tcp_connect(&w, PEER, PORT, 0).unwrap());
        assert!(s.books_consistent());
    }
    assert_eq!(s.tcp_rings_held(), 2 * CONNECTIONS);
    assert_eq!(s.tcp_connect(&w, PEER, PORT, 0), Err(TcpError::NoRoom));
    assert_eq!(s.tcp_listen(80), Err(TcpError::NoRoom));
    assert_eq!(w.take().len(), CONNECTIONS, "a SYN for each");
    // Frames still move while every connection holds its rings.
    assert!(s.ping(&w, PEER, 1, 1, MS).is_ok());
    let echo = w
        .sent
        .borrow_mut()
        .pop_front()
        .expect("the echo request was sent");
    assert!(matches!(wire::parse_frame(&echo), Ok((_, Frame::Echo(..)))));
    for c in conns {
        s.tcp_close(&w, c, MS).unwrap();
    }
    assert!(s.balanced());
    assert_eq!(s.tcp_slots_in_use(), 0);
}

#[test]
fn a_name_kept_past_its_connection_names_nothing() {
    let (mut s, w) = ready();
    let old = s.tcp_connect(&w, PEER, PORT, 0).unwrap();
    s.tcp_close(&w, old, 0).unwrap();
    let new = s.tcp_connect(&w, PEER, PORT, 0).unwrap();
    assert_ne!(old, new);
    let mut buf = [0u8; 4];
    assert_eq!(s.tcp_recv(&w, old, &mut buf, 0), Err(TcpError::BadConnection));
    assert_eq!(s.tcp_close(&w, old, 0), Err(TcpError::BadConnection));
    assert!(s.tcp_status(new).is_some());
}

#[test]
fn closing_with_unread_data_resets() {
    let (mut s, w) = ready();
    let (c, syn) = open(&mut s, &w);
    w.peer(syn.src_port, PEER_ISS + 1, syn.seq + 1, TCP_ACK, b"unread");
    s.poll(&w, 2 * MS);
    w.one();
    s.tcp_close(&w, c, 3 * MS).unwrap();
    assert_eq!(w.one().flags, TCP_RST | TCP_ACK);
    assert!(s.balanced());
}

// ---- congestion control --------------------------------------------------------------------
//
// A hundred-byte segment size throughout, so a window of a few segments is a few hundred bytes
// and every number below is one a reader can check by hand.

/// An established connection whose peer announced `window` and a segment size of `mss`: the
/// connection, the port it opened from, and its initial sequence number.
fn open_with(s: &mut Stack, w: &Wire, window: u16, mss: u16) -> (Conn, u16, u32) {
    let c = s.tcp_connect(w, PEER, PORT, 0).unwrap();
    let syn = w.one();
    let (me, iss) = (syn.src_port, syn.seq);
    w.peer_with(PORT, me, PEER_ISS, iss + 1, TCP_SYN | TCP_ACK, window, Some(mss), &[]);
    s.poll(w, MS);
    w.one();
    assert_eq!(s.tcp_status(c).unwrap().state, State::Established);
    (c, me, iss)
}

#[test]
fn the_congestion_window_starts_at_four_segments_and_bounds_what_is_sent() {
    let (mut s, w) = ready();
    let (c, _, _) = open_with(&mut s, &w, 8192, 100);
    assert_eq!(s.tcp_status(c).unwrap().cwnd, INITIAL_WINDOW as usize * 100);
    // A thousand bytes queued and a window of four segments: four go, though the peer's
    // window would take all of it.
    s.tcp_send(&w, c, &[7u8; 1000], 2 * MS).unwrap();
    let sent = w.take();
    assert_eq!(sent.len(), INITIAL_WINDOW as usize, "{sent:?}");
    assert!(sent.iter().all(|s| s.payload.len() == 100), "{sent:?}");
}

#[test]
fn in_slow_start_each_acknowledgement_is_worth_another_segment() {
    let (mut s, w) = ready();
    let (c, me, iss) = open_with(&mut s, &w, 8192, 100);
    s.tcp_send(&w, c, &[7u8; 1000], 2 * MS).unwrap();
    w.take();
    // One segment acknowledged: the window grows by one, so two more go out — the one the
    // acknowledgement made room for, and the one the window grew by.
    w.peer_with(PORT, me, PEER_ISS + 1, iss + 101, TCP_ACK, 8192, None, &[]);
    s.poll(&w, 3 * MS);
    assert_eq!(s.tcp_status(c).unwrap().cwnd, 500);
    let sent = w.take();
    assert_eq!(sent.len(), 2, "{sent:?}");
}

#[test]
fn three_duplicate_acknowledgements_resend_the_lost_segment_without_waiting_for_the_timer() {
    let (mut s, w) = ready();
    let (c, me, iss) = open_with(&mut s, &w, 8192, 100);
    s.tcp_send(&w, c, &[9u8; 1000], 2 * MS).unwrap();
    assert_eq!(w.take().len(), INITIAL_WINDOW as usize);
    // The first segment is lost, so each one after it draws the same acknowledgement. Two
    // duplicates are reordering as far as the sender knows, and nothing is sent again.
    for _ in 1..DUP_ACK_THRESHOLD {
        w.peer_with(PORT, me, PEER_ISS + 1, iss + 1, TCP_ACK, 8192, None, &[]);
        s.poll(&w, 3 * MS);
        w.nothing();
    }
    // The third says the segment is gone.
    w.peer_with(PORT, me, PEER_ISS + 1, iss + 1, TCP_ACK, 8192, None, &[]);
    s.poll(&w, 3 * MS);
    let again = w.one();
    assert_eq!((again.seq, again.payload.len()), (iss + 1, 100), "the oldest, at once");
    let st = s.tcp_status(c).unwrap();
    // Half the flight of four hundred, and three segments for the three that left the network.
    assert_eq!((st.ssthresh, st.cwnd), (200, 500));
    let counters = s.tcp_counters();
    assert_eq!((counters.fast_retransmits, counters.dup_acks), (1, 3));
    assert_eq!(counters.retransmit_timeouts, 0, "the timer never ran out");
    // Everything outstanding when the loss was found is acknowledged: out of recovery and
    // back to the threshold.
    w.peer_with(PORT, me, PEER_ISS + 1, iss + 401, TCP_ACK, 8192, None, &[]);
    s.poll(&w, 4 * MS);
    assert_eq!(s.tcp_status(c).unwrap().cwnd, 200);
    w.take();
    // Above the threshold, growth is congestion avoidance: a segment per round trip, which
    // for a hundred-byte segment and a two-hundred-byte window is half a segment per
    // acknowledgement.
    w.peer_with(PORT, me, PEER_ISS + 1, iss + 501, TCP_ACK, 8192, None, &[]);
    s.poll(&w, 5 * MS);
    assert_eq!(s.tcp_status(c).unwrap().cwnd, 250);
}

#[test]
fn a_timeout_collapses_the_window_to_one_segment_and_halves_the_threshold() {
    let (mut s, w) = ready();
    let (c, _, _) = open_with(&mut s, &w, 8192, 100);
    s.tcp_send(&w, c, &[1u8; 1000], 2 * MS).unwrap();
    assert_eq!(w.take().len(), INITIAL_WINDOW as usize);
    let rto = s.tcp_status(c).unwrap().rto_ns;
    s.poll(&w, 2 * MS + rto);
    let again = w.one();
    assert_eq!(again.payload.len(), 100, "one segment, from the oldest byte");
    let st = s.tcp_status(c).unwrap();
    assert_eq!((st.cwnd, st.ssthresh), (100, 200));
    assert_eq!(s.tcp_counters().retransmit_timeouts, 1);
}

#[test]
fn the_timeout_follows_the_round_trip_estimate_once_there_is_one() {
    let (mut s, w) = ready();
    // Nothing measured yet: the initial timeout stands.
    let c = s.tcp_connect(&w, PEER, PORT, 0).unwrap();
    let syn = w.one();
    assert_eq!(s.tcp_status(c).unwrap().rto_ns, RTO_INITIAL_NS);
    assert_eq!(s.tcp_counters().rtt_samples, 0);
    // The handshake is a measurement, and the timeout follows it, down to its floor.
    w.peer_with(
        PORT,
        syn.src_port,
        PEER_ISS,
        syn.seq + 1,
        TCP_SYN | TCP_ACK,
        8192,
        Some(1460),
        &[],
    );
    s.poll(&w, 5 * MS);
    w.one();
    let st = s.tcp_status(c).unwrap();
    assert_eq!(st.state, State::Established);
    assert_eq!(st.rto_ns, RTO_MIN_NS, "a five-millisecond round trip is under the floor");
    assert_eq!(s.tcp_counters().rtt_samples, 1);
}

#[test]
fn a_held_run_the_stream_overtakes_is_forgotten_rather_than_delivered_again() {
    let (mut s, w) = ready();
    let (c, syn) = open(&mut s, &w);
    let (me, iss) = (syn.src_port, syn.seq);
    let base = PEER_ISS + 1;
    // A hole of ten bytes, and four bytes held past it.
    w.peer(me, base + 10, iss + 1, TCP_ACK | TCP_PSH, b"jklm");
    s.poll(&w, 2 * MS);
    assert_eq!(w.one().ack, base);
    assert_eq!(s.tcp_status(c).unwrap().held_out_of_order, 1);
    // The peer sends one segment covering the hole *and* the bytes held past it, so the
    // stream overtakes the run: those bytes are already in it, and the run is simply gone.
    w.peer(me, base, iss + 1, TCP_ACK | TCP_PSH, b"abcdefghijklmn");
    s.poll(&w, 3 * MS);
    assert_eq!(w.one().ack, base + 14);
    assert_eq!(read_all(&mut s, &w, c), b"abcdefghijklmn", "each byte once, in order");
    assert_eq!(s.tcp_status(c).unwrap().held_out_of_order, 0);
    assert!(s.books_consistent());
}

#[test]
fn held_runs_are_bounded_and_the_furthest_gives_way_to_a_nearer_one() {
    let (mut s, w) = ready();
    let (c, syn) = open(&mut s, &w);
    let (me, iss) = (syn.src_port, syn.seq);
    let base = PEER_ISS + 1;
    // A hole, and then runs with gaps between them, so no two merge into one.
    for i in 0..OOO_SEGMENTS as u32 {
        w.peer(me, base + 10 + i * 10, iss + 1, TCP_ACK | TCP_PSH, b"abcd");
        s.poll(&w, 2 * MS);
        assert_eq!(w.one().ack, base, "still asking for the byte the hole starts at");
    }
    assert_eq!(s.tcp_status(c).unwrap().held_out_of_order, OOO_SEGMENTS);
    assert_eq!(s.tcp_counters().out_of_order_queued, OOO_SEGMENTS as u64);
    // Further ahead than everything held, with every run taken: this is the one dropped.
    w.peer(me, base + 200, iss + 1, TCP_ACK | TCP_PSH, b"zzzz");
    s.poll(&w, 3 * MS);
    w.one();
    assert_eq!(s.tcp_status(c).unwrap().held_out_of_order, OOO_SEGMENTS);
    assert_eq!(s.tcp_counters().out_of_order_dropped, 1);
    // Nearer than the furthest run held: it takes that run's place, because the stream needs
    // the nearest bytes first.
    w.peer(me, base + 5, iss + 1, TCP_ACK | TCP_PSH, b"ab");
    s.poll(&w, 4 * MS);
    w.one();
    assert_eq!(s.tcp_counters().out_of_order_dropped, 2);
    assert_eq!(s.tcp_status(c).unwrap().held_out_of_order, OOO_SEGMENTS);
    // The hole is filled: what is contiguous from the first byte comes out in order, and the
    // runs still separated by holes stay held.
    w.peer(me, base, iss + 1, TCP_ACK | TCP_PSH, b"xxxxx");
    s.poll(&w, 5 * MS);
    assert_eq!(w.one().ack, base + 7);
    assert_eq!(read_all(&mut s, &w, c), b"xxxxxab");
    assert!(s.books_consistent());
}

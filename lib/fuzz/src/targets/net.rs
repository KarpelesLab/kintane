//! Ethernet, ARP, IPv4, ICMP and UDP: what anything on a network can send the kernel.
//!
//! Two levels. The parsers in `net::wire` run on the input directly, and whatever they
//! accept is checked for consistency: every payload they hand back lies inside the bytes it
//! came from, and an ARP message written back out parses to the same message. Then the whole
//! stack is given the input as one received frame, on a card that records what the stack
//! sends: it must not panic, every buffer must be back in its pool afterwards, and every
//! frame it sends in answer must parse with its own parser.
//!
//! Seeded from `corpus/net/`: a gateway's ARP reply, an echo request and a datagram to the
//! stack, each with correct checksums, since a checksum is exactly the check random bytes do
//! not pass. The generator also builds frames with the stack's own writers, so the valid
//! shapes stay reachable however far mutation wanders from the seeds.

use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;
use core::cell::{Cell, RefCell};

use net::wire::{self, Arp, Frame, WireError};
use net::{Config, Ipv4Addr, Mac, Nic, NicError, Stack};

use crate::{Mutator, Rng};

const OURS: Config = Config {
    ip: [10, 0, 2, 15],
    netmask: [255, 255, 255, 0],
    gateway: [10, 0, 2, 2],
};
const OUR_MAC: Mac = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
const PEER_MAC: Mac = [0x52, 0x55, 10, 0, 2, 2];

/// A seed or a frame built from scratch, then usually corrupted.
pub fn generate(rng: &mut Rng, seeds: &[Vec<u8>]) -> Vec<u8> {
    let mut bytes = if !seeds.is_empty() && rng.one_in(2) {
        rng.pick(seeds).clone()
    } else {
        build(rng)
    };
    // Sometimes exactly what a sender wrote, so the valid case stays reachable.
    if !rng.one_in(8) {
        Mutator::mutate(rng, &mut bytes);
    }
    bytes
}

/// A well-formed frame of a random kind, addressed to the stack or near it.
fn build(rng: &mut Rng) -> Vec<u8> {
    let mut buf = vec![0u8; wire::FRAME_MAX];
    let src: Ipv4Addr = *rng.pick(&[[10, 0, 2, 2], [10, 0, 2, 3], [192, 168, 7, 1]]);
    let dst: Ipv4Addr = *rng.pick(&[OURS.ip, [10, 0, 2, 99], [255, 255, 255, 255]]);
    let dst_mac = *rng.pick(&[OUR_MAC, wire::BROADCAST, [2, 0, 0, 0, 0, 9]]);
    let id = rng.next_u32() as u16;
    let seq = rng.next_u32() as u16;
    let data: Vec<u8> = (0..rng.below(96)).map(|i| i as u8).collect();
    let len = match rng.below(3) {
        0 => {
            let arp = Arp {
                operation: *rng.pick(&[wire::ARP_REQUEST, wire::ARP_REPLY, 3]),
                sender_mac: PEER_MAC,
                sender_ip: src,
                target_mac: *rng.pick(&[OUR_MAC, [0; 6]]),
                target_ip: dst,
            };
            let header = wire::write_ethernet(&mut buf, dst_mac, PEER_MAC, wire::ETHERTYPE_ARP);
            match (header, wire::write_arp(&mut buf[wire::ETH_HEADER..], &arp)) {
                (Ok(()), Ok(n)) => wire::ETH_HEADER + n,
                _ => 0,
            }
        }
        1 => {
            let kind = *rng.pick(&[wire::ICMP_ECHO_REQUEST, wire::ICMP_ECHO_REPLY]);
            ip_frame(&mut buf, dst_mac, src, dst, wire::PROTO_ICMP, |p| {
                wire::write_icmp_echo(p, kind, id, seq, &data)
            })
        }
        _ => {
            let port = *rng.pick(&[5555, 7, seq]);
            ip_frame(&mut buf, dst_mac, src, dst, wire::PROTO_UDP, |p| {
                wire::write_udp(p, src, dst, id, port, &data)
            })
        }
    };
    buf.truncate(len);
    buf
}

/// An IPv4 frame whose payload `body` writes. Returns the frame's length, zero if it did not
/// fit.
fn ip_frame(
    buf: &mut [u8],
    dst_mac: Mac,
    src: Ipv4Addr,
    dst: Ipv4Addr,
    protocol: u8,
    body: impl FnOnce(&mut [u8]) -> Result<usize, WireError>,
) -> usize {
    let at = wire::ETH_HEADER + wire::IPV4_HEADER;
    let Ok(n) = body(&mut buf[at..]) else {
        return 0;
    };
    if wire::write_ethernet(buf, dst_mac, PEER_MAC, wire::ETHERTYPE_IPV4).is_err() {
        return 0;
    }
    match wire::write_ipv4(&mut buf[wire::ETH_HEADER..], src, dst, protocol, 7, n) {
        Ok(header) => wire::ETH_HEADER + header + n,
        Err(_) => 0,
    }
}

pub fn run(input: &[u8]) {
    parsers(input);
    stack(input);
}

/// Whatever the parsers accept is consistent with the bytes it came from.
fn parsers(input: &[u8]) {
    let Ok((eth, frame)) = wire::parse_frame(input) else {
        return;
    };
    assert!(inside(input, eth.payload), "the Ethernet payload is outside the frame");
    match frame {
        Frame::Arp(arp) => {
            let mut out = [0u8; wire::ARP_LEN];
            let n = wire::write_arp(&mut out, &arp).expect("an ARP message fits its own length");
            assert_eq!(
                wire::parse_arp(&out[..n]).ok(),
                Some(arp),
                "an ARP message did not survive being written back out"
            );
        }
        Frame::Echo(ip, echo) => {
            assert!(inside(eth.payload, ip.payload), "the IPv4 payload is outside the packet");
            assert!(inside(ip.payload, echo.data), "the echo data is outside the message");
        }
        Frame::Udp(ip, udp) => {
            assert!(inside(eth.payload, ip.payload), "the IPv4 payload is outside the packet");
            assert!(inside(ip.payload, udp.payload), "the UDP payload is outside the datagram");
        }
        Frame::OtherIpv4(ip) => {
            assert!(inside(eth.payload, ip.payload), "the IPv4 payload is outside the packet");
        }
        Frame::OtherEthernet(_) => {}
    }
}

/// Whether `part` lies inside `whole`.
fn inside(whole: &[u8], part: &[u8]) -> bool {
    let (w, p) = (whole.as_ptr() as usize, part.as_ptr() as usize);
    p >= w && p + part.len() <= w + whole.len()
}

/// A card that delivers one frame and records what is sent.
struct OneFrame<'a> {
    frame: Cell<Option<&'a [u8]>>,
    sent: RefCell<Vec<Vec<u8>>>,
}

impl Nic for OneFrame<'_> {
    fn mac(&self) -> Mac {
        OUR_MAC
    }

    fn send(&self, frame: &[u8]) -> Result<(), NicError> {
        self.sent.borrow_mut().push(frame.to_vec());
        Ok(())
    }

    fn recv(&self, into: &mut [u8]) -> Option<usize> {
        let frame = self.frame.take()?;
        let n = frame.len().min(into.len());
        into[..n].copy_from_slice(&frame[..n]);
        Some(n)
    }
}

/// The stack takes the frame, gives every buffer back, and answers only with frames that
/// parse.
fn stack(input: &[u8]) {
    let card = OneFrame {
        frame: Cell::new(Some(input)),
        sent: RefCell::new(Vec::new()),
    };
    let mut stack = Box::new(Stack::new(OURS));
    stack.poll(&card, 1);
    assert!(stack.balanced(), "a buffer was not back in the pool after one frame");
    for frame in card.sent.borrow().iter() {
        assert!(
            frame.len() <= wire::FRAME_MAX,
            "the stack sent a frame longer than Ethernet allows"
        );
        assert!(
            wire::parse_frame(frame).is_ok(),
            "the stack sent a frame its own parser refuses"
        );
    }
}

/// A frame whose layers parse down to a protocol this stack speaks.
pub fn accepts(input: &[u8]) -> bool {
    !matches!(wire::parse_frame(input), Err(_) | Ok((_, Frame::OtherEthernet(_))))
}

#[cfg(test)]
mod tests {
    use net::wire::{self, Frame};

    use crate::Rng;

    #[test]
    fn the_committed_seeds_are_what_their_names_say() {
        let arp = include_bytes!("../../corpus/net/seed-arp-reply.bin");
        assert!(matches!(
            wire::parse_frame(arp),
            Ok((_, Frame::Arp(a))) if a.operation == wire::ARP_REPLY
        ));
        let echo = include_bytes!("../../corpus/net/seed-echo-request.bin");
        assert!(matches!(
            wire::parse_frame(echo),
            Ok((_, Frame::Echo(_, e))) if e.kind == wire::ICMP_ECHO_REQUEST
        ));
        let udp = include_bytes!("../../corpus/net/seed-udp.bin");
        assert!(matches!(
            wire::parse_frame(udp),
            Ok((_, Frame::Udp(_, u))) if u.payload == b"kintane-udp-probe"
        ));
    }

    #[test]
    fn frames_built_from_scratch_parse() {
        let mut rng = Rng::new(3);
        for _ in 0..300 {
            let frame = super::build(&mut rng);
            match wire::parse_frame(&frame) {
                Ok((_, Frame::OtherEthernet(_))) => {
                    panic!("the generator built a frame of no kind")
                }
                Ok(_) => {}
                // The one frame built to be refused: an ARP message with no such operation.
                Err(wire::WireError::ArpOperation(3)) => {}
                Err(e) => panic!("a frame built with the stack's writers did not parse: {e:?}"),
            }
        }
    }

    #[test]
    fn generated_inputs_run_clean() {
        let mut rng = Rng::new(11);
        for _ in 0..2000 {
            let input = super::generate(&mut rng, &[]);
            super::run(&input);
        }
    }
}

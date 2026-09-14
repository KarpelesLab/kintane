//! Datagrams, and the addresses a program hands the socket calls.
//!
//! Two things read bytes nobody in the kernel wrote, and both are here:
//!
//! * **The receive path.** The input becomes a UDP datagram addressed to the stack, which polls it
//!   in and holds it in its inbox. Taking it back out must not panic, whatever the length was: what
//!   is copied never passes the buffer it is copied into, the length reported is the length the
//!   datagram had, and every pool buffer is back afterwards.
//! * **`struct sockaddr_in`.** The Linux personality parses one from whatever a program passes it.
//!   A parse that succeeds must round-trip: writing the address and port back out gives the bytes'
//!   own address and port again, so no address is quietly changed on its way through.
//!
//! Seeded from `corpus/dgram/`: one valid `sockaddr_in`, since a family field random bytes
//! rarely hit is exactly what the parser checks first.

use alloc::vec;
use alloc::vec::Vec;
use core::cell::RefCell;

use net::wire::{self, ETH_HEADER, IPV4_HEADER, PROTO_UDP};
use net::{Config, Ipv4Addr, Mac, Nic, NicError, Stack};

use crate::{Mutator, Rng};

const OURS: Config = Config {
    ip: [10, 0, 2, 15],
    netmask: [255, 255, 255, 0],
    gateway: [10, 0, 2, 2],
};
const OUR_MAC: Mac = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
const PEER_MAC: Mac = [0x52, 0x55, 10, 0, 2, 2];
const PEER: Ipv4Addr = [10, 0, 2, 2];
/// The port the datagram is addressed to, and the one it claims to come from.
const TO: u16 = 5555;
const FROM: u16 = 40000;

/// A card that hands the stack one frame and keeps whatever it sends.
struct Once {
    frame: RefCell<Option<Vec<u8>>>,
}

impl Nic for Once {
    fn mac(&self) -> Mac {
        OUR_MAC
    }

    fn send(&self, _frame: &[u8]) -> Result<(), NicError> {
        Ok(())
    }

    fn recv(&self, into: &mut [u8]) -> Option<usize> {
        let frame = self.frame.borrow_mut().take()?;
        let n = frame.len().min(into.len());
        into.get_mut(..n)?.copy_from_slice(frame.get(..n)?);
        Some(n)
    }
}

/// A datagram carrying `payload`, or `None` when it does not fit one frame.
fn datagram(payload: &[u8]) -> Option<Vec<u8>> {
    let mut buf = [0u8; wire::FRAME_MAX];
    let n = wire::write_udp(&mut buf[ETH_HEADER + IPV4_HEADER..], PEER, OURS.ip, FROM, TO, payload)
        .ok()?;
    wire::write_ipv4(&mut buf[ETH_HEADER..], PEER, OURS.ip, PROTO_UDP, 1, n).ok()?;
    wire::write_ethernet(&mut buf, OUR_MAC, PEER_MAC, wire::ETHERTYPE_IPV4).ok()?;
    Some(buf[..ETH_HEADER + IPV4_HEADER + n].to_vec())
}

/// A seed, a `sockaddr_in`, or a datagram payload, then usually corrupted.
pub fn generate(rng: &mut Rng, seeds: &[Vec<u8>]) -> Vec<u8> {
    let mut bytes = if !seeds.is_empty() && rng.one_in(2) {
        rng.pick(seeds).clone()
    } else if rng.one_in(2) {
        // A `sockaddr_in`: the family, a port and an address, and eight bytes of padding.
        let mut a = vec![0u8; 16];
        a[0] = 2;
        a[2..4].copy_from_slice(&rng.next_u64().to_be_bytes()[6..]);
        a[4..8].copy_from_slice(&[10, 0, 2, 2]);
        a
    } else {
        // A payload of some length, including lengths either side of what the inbox keeps.
        let len = match rng.below(4) {
            0 => rng.below(8),
            1 => 255 + rng.below(4),
            2 => rng.below(600),
            _ => rng.below(1600),
        };
        (0..len).map(|i| (i as u8) ^ 0x5a).collect()
    };
    Mutator::mutate(rng, &mut bytes);
    bytes
}

/// Whether the input is an address the personality's parser takes.
pub fn accepts(input: &[u8]) -> bool {
    linux::socket::parse_sockaddr_in(input).is_ok()
}

pub fn run(input: &[u8]) {
    // 1. An address a program hands a socket call.
    if let Ok((ip, port)) = linux::socket::parse_sockaddr_in(input) {
        let written = linux::socket::sockaddr_in(ip, port);
        assert_eq!(
            linux::socket::parse_sockaddr_in(&written),
            Ok((ip, port)),
            "an address that parses must survive being written back out"
        );
    }

    // 2. The same bytes as a datagram, taken back out of the stack's inbox.
    let Some(frame) = datagram(input) else {
        return;
    };
    let card = Once {
        frame: RefCell::new(Some(frame)),
    };
    let mut stack = Stack::new(OURS);
    stack.poll(&card, 1);
    // Into a buffer smaller than the largest datagram the inbox keeps, so truncation is the
    // common case rather than the rare one.
    let mut into = [0u8; 64];
    if let Some((from, src, copied, whole)) = stack.udp_recv_from(TO, &mut into) {
        assert_eq!((from, src), (PEER, FROM), "a datagram names where it came from");
        assert!(copied <= into.len(), "more was copied than there was room for");
        assert!(copied <= whole, "more was copied than the datagram held");
        assert_eq!(copied, whole.min(into.len()), "what fit was copied");
    }
    assert!(
        stack.balanced(),
        "a datagram taken out of the inbox leaves every pool buffer back in the pool"
    );
}

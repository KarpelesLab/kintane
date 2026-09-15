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
//! connection into its own listener — a TCP endpoint that both accepts and originates. This is
//! stage one: answer ARP, and count what crosses. The preset that turns it on is outside the
//! gate's list until the peer can finish a round.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::qemu::NetPorts;

/// The address the guest is configured to reach, and the hardware address this peer answers
/// from: `kernel/main/src/net.rs`'s `GATEWAY`, and the MAC QEMU's own gateway uses, so a guest
/// that hard-codes neither sees what it saw before.
const GATEWAY: [u8; 4] = [10, 0, 2, 2];
const PEER_MAC: [u8; 6] = [0x52, 0x55, 0x0a, 0x00, 0x02, 0x02];

const ETHERTYPE_ARP: [u8; 2] = [0x08, 0x06];
const ARP_REQUEST: u16 = 1;
const ARP_REPLY: u16 = 2;

/// What crossed the socket, which is what stage one exists to establish.
#[derive(Default)]
struct Seen {
    frames: u64,
    arp_requests: u64,
    arp_answered: u64,
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
            .set_read_timeout(Some(std::time::Duration::from_millis(50)))
            .is_err()
        {
            return;
        }
        let to = ("127.0.0.1", ports.peer_remote);
        let mut seen = Seen::default();
        let mut buf = [0u8; 2048];
        while !stop.load(Ordering::Relaxed) {
            // A timeout is the ordinary case: the guest has nothing to say yet.
            let Ok(n) = socket.recv(&mut buf) else {
                continue;
            };
            seen.frames += 1;
            if let Some(reply) = arp_reply(&buf[..n], &mut seen)
                && socket.send_to(&reply, to).is_ok()
            {
                seen.arp_answered += 1;
            }
        }
        eprintln!(
            "  net peer: {} frames in, {} ARP requests, {} answered",
            seen.frames, seen.arp_requests, seen.arp_answered
        );
    })
}

/// The ARP reply `frame` asks for, if it is a request for [`GATEWAY`].
///
/// The guest's check forgets the gateway and counts replies to *its own* request, so learning
/// the address from someone else's traffic is rejected: this must answer the request, not
/// merely announce.
fn arp_reply(frame: &[u8], seen: &mut Seen) -> Option<Vec<u8>> {
    if frame.len() < 42 || frame.get(12..14)? != ETHERTYPE_ARP {
        return None;
    }
    let opcode = u16::from_be_bytes([*frame.get(20)?, *frame.get(21)?]);
    if opcode != ARP_REQUEST {
        return None;
    }
    seen.arp_requests += 1;
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

#[cfg(test)]
mod tests {
    use super::*;

    fn request(target: [u8; 4]) -> Vec<u8> {
        let guest_mac = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
        let mut f = Vec::new();
        f.extend_from_slice(&[0xff; 6]);
        f.extend_from_slice(&guest_mac);
        f.extend_from_slice(&ETHERTYPE_ARP);
        f.extend_from_slice(&[0, 1, 0x08, 0x00, 6, 4]);
        f.extend_from_slice(&ARP_REQUEST.to_be_bytes());
        f.extend_from_slice(&guest_mac);
        f.extend_from_slice(&[10, 0, 2, 15]);
        f.extend_from_slice(&[0; 6]);
        f.extend_from_slice(&target);
        f
    }

    #[test]
    fn a_request_for_the_gateway_is_answered_from_its_own_address() {
        let mut seen = Seen::default();
        let reply = arp_reply(&request(GATEWAY), &mut seen).expect("answered");
        assert_eq!(reply.len(), 42);
        assert_eq!(&reply[0..6], &[0x52, 0x54, 0x00, 0x12, 0x34, 0x56]); // to the asker
        assert_eq!(&reply[6..12], &PEER_MAC);
        assert_eq!(u16::from_be_bytes([reply[20], reply[21]]), ARP_REPLY);
        assert_eq!(&reply[22..28], &PEER_MAC);
        assert_eq!(&reply[28..32], &GATEWAY);
        assert_eq!(&reply[38..42], &[10, 0, 2, 15]); // back to the guest
        assert_eq!(seen.arp_requests, 1);
    }

    #[test]
    fn a_request_for_another_address_is_not_answered() {
        let mut seen = Seen::default();
        assert!(arp_reply(&request([10, 0, 2, 99]), &mut seen).is_none());
        assert_eq!(seen.arp_requests, 1, "counted, but not ours to answer");
    }

    #[test]
    fn a_reply_is_not_mistaken_for_a_request() {
        let mut seen = Seen::default();
        let mut f = request(GATEWAY);
        f[20..22].copy_from_slice(&ARP_REPLY.to_be_bytes());
        assert!(arp_reply(&f, &mut seen).is_none());
        assert_eq!(seen.arp_requests, 0);
    }

    #[test]
    fn a_short_frame_is_refused_rather_than_indexed_past() {
        let mut seen = Seen::default();
        assert!(arp_reply(&[0u8; 20], &mut seen).is_none());
    }
}

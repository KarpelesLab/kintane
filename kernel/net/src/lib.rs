//! A minimal network stack: Ethernet, ARP, IPv4, ICMP echo, UDP and TCP.
//!
//! # What it is, and what it is not
//!
//! Enough to put a kernel on a network and prove it is there: it resolves a neighbour's
//! hardware address, answers and sends pings, sends and receives UDP datagrams, and carries
//! TCP connections, opened from either end, with retransmission ([`tcp`] says exactly how
//! much of TCP that is). It is written against a [`Nic`] trait rather than a driver, so every
//! path — parsing, the ARP cache, the buffer pool, dispatch, the TCP state machine — is
//! host-tested against a simulated gateway and a scripted TCP peer.
//!
//! Deliberately absent, and stated rather than discovered:
//!
//! * **IPv4 fragmentation.** A fragment is refused, not reassembled, and counted. Everything the
//!   stack sends is marked don't-fragment and fits one frame.
//! * **IPv6, DHCP, routing beyond one gateway, IP options.** One address, one netmask, one gateway,
//!   from a [`Config`].
//! * **Sockets.** Callers use [`Stack::udp_send`], [`Stack::tcp_connect`] and their kin directly.
//!   The kernel builds its socket objects on these; this crate knows nothing of handles.
//!
//! # No allocation on the receive path
//!
//! Frames are received into a fixed [`pool`] of Ethernet-sized buffers, handled, and given
//! back before [`Stack::poll`] returns, so at rest the pool's books balance: every buffer
//! taken was returned. Replies are built in a second pool buffer, never on the stack of
//! whoever is polling, because a frame is 1514 bytes and a kernel's boot stack is a few KiB.
//!
//! # Concurrency
//!
//! None, on purpose: every method takes `&mut self`. The owner holds whatever lock its
//! context needs, exactly as `kernel/time`'s clock and timer queue leave locking to theirs.
//!
//! References: RFC 894 (IPv4 over Ethernet), RFC 826 (ARP), RFC 791 (IPv4), RFC 792
//! (ICMP), RFC 768 (UDP), RFC 1071 (the Internet checksum), RFC 793, RFC 1122 §4.2 and RFC
//! 5961 (TCP).

#![cfg_attr(not(test), no_std)]
#![deny(unsafe_code)]

pub mod arp;
pub mod pool;
pub mod stack;
pub mod tcp;
pub mod wire;

#[cfg(test)]
mod tcp_tests;
#[cfg(test)]
mod tests;

pub use stack::{Config, Counters, NetError, Nic, NicError, Stack};
pub use tcp::{Conn, TcpError};
pub use wire::{Ipv4Addr, Mac};

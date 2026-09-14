//! A minimal network stack: Ethernet, ARP, IPv4, ICMP echo and UDP.
//!
//! # What it is, and what it is not
//!
//! Enough to put a kernel on a network and prove it is there: it resolves a neighbour's
//! hardware address, answers and sends pings, and sends and receives UDP datagrams. It is
//! written against a [`Nic`] trait rather than a driver, so every path — parsing, the ARP
//! cache, the buffer pool, dispatch — is host-tested against a simulated gateway.
//!
//! Deliberately absent, and stated rather than discovered:
//!
//! * **TCP.** Out of scope for the first round; nothing here assumes it will or will not arrive.
//! * **IPv4 fragmentation.** A fragment is refused, not reassembled, and counted. Everything the
//!   stack sends is marked don't-fragment and fits one frame.
//! * **IPv6, DHCP, routing beyond one gateway, IP options.** One address, one netmask, one gateway,
//!   from a [`Config`].
//! * **A socket API.** Callers use [`Stack::udp_send`] and [`Stack::udp_recv`] directly; a socket
//!   layer needs blocking calls userspace does not have yet.
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
//! (ICMP), RFC 768 (UDP), RFC 1071 (the Internet checksum).

#![cfg_attr(not(test), no_std)]
#![deny(unsafe_code)]

pub mod arp;
pub mod pool;
pub mod stack;
pub mod wire;

#[cfg(test)]
mod tests;

pub use stack::{Config, Counters, NetError, Nic, NicError, Stack};
pub use wire::{Ipv4Addr, Mac};

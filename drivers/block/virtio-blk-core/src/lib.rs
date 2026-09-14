//! virtio-blk's protocol, written once for every place the driver runs.
//!
//! The virtqueue, the status handshake, feature negotiation and the block requests are here,
//! over [`hwproxy`]'s traits and nothing else. So this crate compiles into the kernel image,
//! where `drivers/block/virtio-blk` wraps it in a lock family and the block layer, and into an
//! unprivileged driver domain, where `user/hwdomain` drives it alone. That is Phase 5's claim
//! — the same driver source, either way — made for a driver that has state and does DMA, and
//! layering is what makes it checkable: this crate sits at the `user` layer, so nothing it
//! links can be kernel code.
//!
//! What its hosts add is only what each host alone has:
//!
//! * **The kernel** binds the device through the device model, tracks requests as the block layer's
//!   tickets, takes a lock so several CPUs can have requests in flight, and runs the interrupt
//!   handler the platform registers.
//! * **A domain** has a grant: a register window and a DMA buffer the kernel mapped into its
//!   address space, and — with an IOMMU — into the device's.
//!
//! # Memory the device writes
//!
//! A descriptor carries the address the *device* uses, which is not the one the CPU uses.
//! [`mem::Dma`] carries both and keeps them apart; handing a device a virtual address is a
//! mistake the host tests catch, because the fake device's memory is at a different offset.
//! Behind an IOMMU the device's address is an I/O virtual address the IOMMU translates, and
//! nothing here changes: it was never assumed to be physical.
//!
//! Reference: Virtual I/O Device (VIRTIO) Version 1.1, §2.6 (virtqueues), §4.1 (PCI), §4.2
//! (MMIO), §5.2 (block devices), §6 (reserved feature bits).

#![cfg_attr(not(test), no_std)]
#![deny(unsafe_code)]

pub mod engine;
pub mod mem;
pub mod mmio;
pub mod pci;
pub mod queue;
pub mod transport;

#[cfg(test)]
mod test_support;

#[cfg(test)]
mod tests;

pub use engine::{Engine, Facts, Op, RequestError, SubmitError};

/// Descriptors in the device's queue: a power of two, as the split virtqueue requires, and
/// large enough for every request [`IN_FLIGHT`] allows to be outstanding at once.
pub const QUEUE_SIZE: u16 = 16;

/// The device's request queue: virtio-blk has exactly one (virtio 1.1 §5.2.2).
pub const QUEUE_INDEX: u16 = 0;

/// A virtio-blk request header (virtio 1.1 §5.2.6).
pub const HEADER_BYTES: usize = 16;

/// The sector size the *protocol* uses, whatever the device's logical block size is.
pub const PROTOCOL_SECTOR: usize = 512;

/// Request types.
pub const T_IN: u32 = 0;
pub const T_OUT: u32 = 1;
pub const T_FLUSH: u32 = 4;

/// Feature bits of a block device (virtio 1.1 §5.2.3).
pub const F_BLK_SIZE: u32 = 1 << 6;
pub const F_FLUSH: u32 = 1 << 9;
pub const F_RO: u32 = 1 << 5;

/// Device configuration offsets (virtio 1.1 §5.2.4).
pub const CFG_CAPACITY: usize = 0;
pub const CFG_BLK_SIZE: usize = 20;

/// Polls of the used ring before a request is called lost.
///
/// A bound rather than a spin for ever: a device that has stopped answering must be an
/// error a caller can report, not a host that stops. Under QEMU a request completes in a few
/// hundred polls; the bound is far above that and still finite.
pub const POLL_LIMIT: u32 = 50_000_000;

/// Requests that may be in flight at once, each with its own header, status byte and
/// bounce buffer.
pub const IN_FLIGHT: usize = 4;

/// Descriptors one request's chain can take: its header, its data, and its status byte.
pub const DESCRIPTORS_PER_REQUEST: usize = 3;

/// Every slot must be able to publish its chain at once, or a request that found a free slot
/// would be refused by a full ring. Checked at build time, because a queue of eight — what
/// this once was — holds only two full requests, and nothing short of three requests
/// outstanding together would ever show it.
const _: () = assert!(
    IN_FLIGHT * DESCRIPTORS_PER_REQUEST <= QUEUE_SIZE as usize,
    "QUEUE_SIZE cannot hold a full chain for every request IN_FLIGHT allows"
);

/// The bytes of DMA the driver needs: the rings, then a header, a status byte and a bounce
/// buffer for each request that can be outstanding, with room for the alignment between
/// them.
pub const fn dma_bytes(bounce: usize) -> usize {
    transport::queue_bytes(QUEUE_SIZE) + IN_FLIGHT * (HEADER_BYTES + 1 + 32 + bounce)
}

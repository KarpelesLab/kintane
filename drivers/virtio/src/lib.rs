//! What every virtio driver shares, for every place a driver runs.
//!
//! The split virtqueue ([`queue`]), the status handshake and feature negotiation
//! ([`transport`]), the memory-mapped and PCI transports ([`mmio`], [`pci`]) and the memory a
//! device reads and writes ([`mem`]). The transports are generic over [`hwproxy::Regs`], so
//! the kernel drives them over its mapping of a claimed window and a driver domain over its
//! grant. None of it is about blocks or frames: `virtio-blk-core` builds the block protocol on
//! it, and `virtio-net` the network card.
//!
//! The kernel's glue — binding a device from a probe, the MSI-X table claim, a transport over
//! the claimed window — is `virtio-bind`, because it needs the device model, which a
//! `user`-layer crate may not reach.
//!
//! Reference: Virtual I/O Device (VIRTIO) Version 1.1, §2 (basic facilities), §4.1 (PCI),
//! §4.2 (MMIO).

#![cfg_attr(not(test), no_std)]
#![deny(unsafe_code)]

// The fake device is host-only code that needs `Vec`. A host build of this no_std crate for
// another crate's tests gets `std` explicitly; an image build compiles neither.
#[cfg(all(CONFIG_MOCK_ARCH, not(test)))]
extern crate std;

pub mod mem;
pub mod mmio;
pub mod pci;
pub mod queue;
pub mod transport;

#[cfg(any(test, CONFIG_MOCK_ARCH))]
pub mod fake;

use hwproxy::Direct;
use transport::Transport;

/// A virtio transport, of whichever kind this machine has, over the kernel's mapping of the
/// claimed window.
pub enum AnyTransport {
    Mmio(mmio::Mmio<Direct>),
    Pci(pci::Pci<Direct>),
}

impl Transport for AnyTransport {
    fn device_id(&self) -> u32 {
        match self {
            AnyTransport::Mmio(t) => t.device_id(),
            AnyTransport::Pci(t) => t.device_id(),
        }
    }
    fn status(&self) -> u8 {
        match self {
            AnyTransport::Mmio(t) => t.status(),
            AnyTransport::Pci(t) => t.status(),
        }
    }
    fn set_status(&self, value: u8) {
        match self {
            AnyTransport::Mmio(t) => t.set_status(value),
            AnyTransport::Pci(t) => t.set_status(value),
        }
    }
    fn device_features(&self, select: u32) -> u32 {
        match self {
            AnyTransport::Mmio(t) => t.device_features(select),
            AnyTransport::Pci(t) => t.device_features(select),
        }
    }
    fn set_driver_features(&self, select: u32, value: u32) {
        match self {
            AnyTransport::Mmio(t) => t.set_driver_features(select, value),
            AnyTransport::Pci(t) => t.set_driver_features(select, value),
        }
    }
    fn queue_max(&self, index: u16) -> u16 {
        match self {
            AnyTransport::Mmio(t) => t.queue_max(index),
            AnyTransport::Pci(t) => t.queue_max(index),
        }
    }
    fn setup_queue(&self, index: u16, size: u16, desc: u64, avail: u64, used: u64) {
        match self {
            AnyTransport::Mmio(t) => t.setup_queue(index, size, desc, avail, used),
            AnyTransport::Pci(t) => t.setup_queue(index, size, desc, avail, used),
        }
    }
    fn notify(&self, index: u16) {
        match self {
            AnyTransport::Mmio(t) => t.notify(index),
            AnyTransport::Pci(t) => t.notify(index),
        }
    }
    fn ack_interrupt(&self) -> u32 {
        match self {
            AnyTransport::Mmio(t) => t.ack_interrupt(),
            AnyTransport::Pci(t) => t.ack_interrupt(),
        }
    }
    fn set_config_vector(&self, vector: u16) -> u16 {
        match self {
            AnyTransport::Mmio(t) => t.set_config_vector(vector),
            AnyTransport::Pci(t) => t.set_config_vector(vector),
        }
    }
    fn set_queue_vector(&self, index: u16, vector: u16) -> u16 {
        match self {
            AnyTransport::Mmio(t) => t.set_queue_vector(index, vector),
            AnyTransport::Pci(t) => t.set_queue_vector(index, vector),
        }
    }
    fn config_read8(&self, offset: usize) -> u8 {
        match self {
            AnyTransport::Mmio(t) => t.config_read8(offset),
            AnyTransport::Pci(t) => t.config_read8(offset),
        }
    }
    fn config_read32(&self, offset: usize) -> u32 {
        match self {
            AnyTransport::Mmio(t) => t.config_read32(offset),
            AnyTransport::Pci(t) => t.config_read32(offset),
        }
    }
}

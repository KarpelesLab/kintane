//! The PCI transport, as the kernel finds it: the layout read out of the capability list
//! enumeration recorded.
//!
//! The transport itself is `virtio_blk_core::pci`, over the proxy layer, so a domain drives
//! the same code over its own mapping of the BAR. What stays here is the one thing only the
//! kernel can do — turning a [`Function`] into a [`Layout`] — because a driver is handed the
//! node its `Origin::Pci` borrows and the only place with configuration space is the
//! enumerator. See `device::pci::Capability`.

use device::pci::Function;
pub use virtio_blk_core::pci::{
    DEVICE_MODERN_BLOCK, DEVICE_TRANSITIONAL_BLOCK, Layout, Pci, Place, VENDOR, VendorCapability,
    cap, cfg_type,
};

/// Whether a function is a virtio block device of either kind.
pub fn is_block_device(f: &Function) -> bool {
    f.vendor == VENDOR && (f.device == DEVICE_MODERN_BLOCK || f.device == DEVICE_TRANSITIONAL_BLOCK)
}

/// Where a function's structures are: `virtio-bind`'s, which the probe uses.
pub use virtio_bind::layout_of;

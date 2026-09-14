//! The PCI transport, as the kernel finds it: the layout read out of the capability list
//! enumeration recorded.
//!
//! The transport itself is `virtio_blk_core::pci`, over the proxy layer, so a domain drives
//! the same code over its own mapping of the BAR. What stays here is the one thing only the
//! kernel can do — turning a [`Function`] into a [`Layout`] — because a driver is handed the
//! node its `Origin::Pci` borrows and the only place with configuration space is the
//! enumerator. See `device::pci::Capability`.

use device::pci::{self, Function};
pub use virtio_blk_core::pci::{
    DEVICE_MODERN_BLOCK, DEVICE_TRANSITIONAL_BLOCK, Layout, Pci, Place, VENDOR, VendorCapability,
    cap, cfg_type,
};

use crate::transport::Error;

/// Whether a function is a virtio block device of either kind.
pub fn is_block_device(f: &Function) -> bool {
    f.vendor == VENDOR && (f.device == DEVICE_MODERN_BLOCK || f.device == DEVICE_TRANSITIONAL_BLOCK)
}

/// Where `f`'s structures are, from its vendor capabilities.
///
/// `Err(Legacy)` when the device offers no modern structures at all, which is what a
/// pre-1.0 device looks like from here.
pub fn layout_of(f: &Function) -> Result<Layout, Error> {
    Layout::from_capabilities(
        f.capabilities()
            .into_iter()
            .filter(|c| c.id == pci::CAP_VENDOR)
            .map(|c| VendorCapability {
                cfg_type: c.byte(cap::CFG_TYPE_BYTE),
                place: Place {
                    bar: c.byte(cap::BAR_BYTE),
                    offset: c.word(cap::OFFSET_WORD),
                    length: c.word(cap::LENGTH_WORD),
                },
                notify_multiplier: c.word(cap::NOTIFY_MULTIPLIER_WORD),
            }),
    )
}

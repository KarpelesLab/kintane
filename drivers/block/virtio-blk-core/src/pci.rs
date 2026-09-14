//! The PCI transport (virtio 1.1 §4.1): the same device, with its registers spread across a
//! function's BARs instead of gathered in one window.
//!
//! # Where the registers are is a question the device answers
//!
//! A memory-mapped virtio device has one window at a fixed layout. A PCI one has four
//! structures — common configuration, notification, interrupt status, device-specific
//! configuration — and says where each is through vendor-specific capabilities in its
//! configuration space: a BAR index, an offset into it, and a length. [`Layout`] is that
//! answer, as data. Reading the capabilities needs configuration space, which only the
//! kernel's enumerator has, so the kernel builds the layout (`drivers/block/virtio-blk`'s
//! `layout_of`) and a domain is *told* it; [`Layout::from_capabilities`] is the rule both
//! apply.
//!
//! # Why there is no legacy path
//!
//! A transitional device also offers the pre-1.0 register layout in an I/O BAR, with a
//! different queue-setup protocol. The driver speaks virtio 1.x only, so a device that
//! offers no modern capabilities is [`Error::Legacy`] — the same refusal the memory-mapped
//! transport makes for a version-1 slot, and for the same reason: mis-driving a device is
//! worse than not driving it.

use hwproxy::Regs;

use crate::transport::{Error, Transport};

/// Virtio's own capability types (virtio 1.1 §4.1.4).
pub mod cfg_type {
    pub const COMMON: u8 = 1;
    pub const NOTIFY: u8 = 2;
    pub const ISR: u8 = 3;
    pub const DEVICE: u8 = 4;
}

/// Where each field sits in a virtio vendor capability (virtio 1.1 §4.1.4): bytes for the
/// two in the first word, word indices for the rest.
pub mod cap {
    /// The structure this capability describes.
    pub const CFG_TYPE_BYTE: usize = 3;
    /// Which BAR it lives in.
    pub const BAR_BYTE: usize = 4;
    /// Its offset into that BAR.
    pub const OFFSET_WORD: usize = 2;
    /// Its length.
    pub const LENGTH_WORD: usize = 3;
    /// Only on the notification capability: the stride between queues' notify addresses.
    pub const NOTIFY_MULTIPLIER_WORD: usize = 4;
}

/// Common configuration register offsets (virtio 1.1 §4.1.4.3).
mod common {
    pub const DEVICE_FEATURE_SELECT: usize = 0x00;
    pub const DEVICE_FEATURE: usize = 0x04;
    pub const DRIVER_FEATURE_SELECT: usize = 0x08;
    pub const DRIVER_FEATURE: usize = 0x0c;
    /// The MSI-X vector for configuration-change interrupts.
    pub const MSIX_CONFIG: usize = 0x10;
    pub const DEVICE_STATUS: usize = 0x14;
    pub const QUEUE_SELECT: usize = 0x16;
    pub const QUEUE_SIZE: usize = 0x18;
    /// The MSI-X vector for the selected queue's interrupts.
    pub const QUEUE_MSIX_VECTOR: usize = 0x1a;
    pub const QUEUE_ENABLE: usize = 0x1c;
    pub const QUEUE_NOTIFY_OFF: usize = 0x1e;
    pub const QUEUE_DESC: usize = 0x20;
    pub const QUEUE_DRIVER: usize = 0x28;
    pub const QUEUE_DEVICE: usize = 0x30;
}

/// The least a common configuration structure can be for the fields above to exist.
const COMMON_BYTES: u32 = 0x38;

/// Virtio's PCI vendor ID, and the device IDs a block device answers to: the modern range is
/// 0x1040 plus the virtio device type, and 0x1001 is the transitional block device.
pub const VENDOR: u16 = 0x1af4;
pub const DEVICE_MODERN_BLOCK: u16 = 0x1042;
pub const DEVICE_TRANSITIONAL_BLOCK: u16 = 0x1001;

/// One structure's place: which BAR, how far into it, and how long.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Place {
    pub bar: u8,
    pub offset: u32,
    pub length: u32,
}

impl Place {
    fn found(&self) -> bool {
        self.length != 0
    }
}

/// One virtio vendor capability, as the enumerator recorded it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct VendorCapability {
    pub cfg_type: u8,
    pub place: Place,
    /// Meaningful only on the notification capability.
    pub notify_multiplier: u32,
}

/// Where each of a device's structures lives, as its capabilities describe them.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Layout {
    pub common: Place,
    pub notify: Place,
    pub isr: Place,
    pub device: Place,
    /// The stride between one queue's notification address and the next.
    pub notify_multiplier: u32,
}

impl Layout {
    /// The layout a device's vendor capabilities describe.
    ///
    /// `Err(Legacy)` when the device offers no modern structures at all, which is what a
    /// pre-1.0 device looks like from here.
    pub fn from_capabilities(
        caps: impl IntoIterator<Item = VendorCapability>,
    ) -> Result<Layout, Error> {
        let mut layout = Layout::default();
        for c in caps {
            if !c.place.found() {
                continue;
            }
            match c.cfg_type {
                cfg_type::COMMON => layout.common = c.place,
                cfg_type::NOTIFY => {
                    layout.notify = c.place;
                    layout.notify_multiplier = c.notify_multiplier;
                }
                cfg_type::ISR => layout.isr = c.place,
                cfg_type::DEVICE => layout.device = c.place,
                _ => {}
            }
        }
        if !layout.common.found() || !layout.notify.found() || !layout.isr.found() {
            return Err(Error::Legacy);
        }
        if layout.common.length < COMMON_BYTES {
            return Err(Error::NotVirtio);
        }
        Ok(layout)
    }

    /// Every BAR index the layout names, so a host knows which ones to claim or grant.
    pub fn bars(&self) -> [u8; 4] {
        [
            self.common.bar,
            self.notify.bar,
            self.isr.bar,
            self.device.bar,
        ]
    }

    /// The one BAR every structure is in, if they share one. QEMU's virtio-pci puts all four
    /// in the same BAR; a device that spreads them is refused, because one window is what a
    /// host maps.
    pub fn single_bar(&self) -> Option<u8> {
        let bar = self.common.bar;
        self.bars().iter().all(|b| *b == bar).then_some(bar)
    }
}

/// A virtio device behind PCI, over the register window of the one BAR its structures are in.
pub struct Pci<R: Regs> {
    bar: R,
    layout: Layout,
    /// The device ID the function reported, which is what the transport's `device_id`
    /// answers: a PCI virtio device says what it is in configuration space, not in a register.
    device_id: u32,
}

impl<R: Regs> Pci<R> {
    /// The transport over `bar`, the window of BAR `bar_index`.
    ///
    /// Every structure the layout names must be in that BAR and inside the window; a device
    /// that spreads them over several BARs is refused, because only one is mapped.
    pub fn new(layout: &Layout, bar_index: u8, bar: R, device_id: u32) -> Result<Pci<R>, Error> {
        let fits = |p: &Place| {
            p.bar == bar_index
                && (p.offset as usize)
                    .checked_add(p.length as usize)
                    .is_some_and(|end| end <= bar.len())
        };
        if !fits(&layout.common) || !fits(&layout.notify) || !fits(&layout.isr) {
            return Err(Error::NotVirtio);
        }
        let mut layout = *layout;
        if layout.device.found() && !fits(&layout.device) {
            layout.device = Place::default();
        }
        Ok(Pci {
            bar,
            layout,
            device_id,
        })
    }

    /// The window's offset for `size` bytes at `offset` into structure `p`, if it is inside it.
    fn at(p: &Place, offset: usize, size: usize) -> Option<usize> {
        let end = offset.checked_add(size)?;
        (p.found() && end <= p.length as usize).then(|| p.offset as usize + offset)
    }

    fn common8(&self, offset: usize) -> u8 {
        Self::at(&self.layout.common, offset, 1).map_or(u8::MAX, |o| self.bar.read8(o))
    }
    fn common16(&self, offset: usize) -> u16 {
        Self::at(&self.layout.common, offset, 2).map_or(u16::MAX, |o| self.bar.read16(o))
    }
    fn common32(&self, offset: usize) -> u32 {
        Self::at(&self.layout.common, offset, 4).map_or(u32::MAX, |o| self.bar.read32(o))
    }
    fn set_common8(&self, offset: usize, value: u8) {
        if let Some(o) = Self::at(&self.layout.common, offset, 1) {
            self.bar.write8(o, value);
        }
    }
    fn set_common16(&self, offset: usize, value: u16) {
        if let Some(o) = Self::at(&self.layout.common, offset, 2) {
            self.bar.write16(o, value);
        }
    }
    fn set_common32(&self, offset: usize, value: u32) {
        if let Some(o) = Self::at(&self.layout.common, offset, 4) {
            self.bar.write32(o, value);
        }
    }

    /// A 64-bit field of the common configuration, written as two 32-bit halves: virtio's own
    /// rule (virtio 1.1 §4.1.3.1). Every 64-bit field this driver writes is written before the
    /// device is told to look at it, so a torn value is never observed.
    fn set_common64(&self, offset: usize, value: u64) {
        self.set_common32(offset, value as u32);
        self.set_common32(offset + 4, (value >> 32) as u32);
    }
}

impl<R: Regs> Transport for Pci<R> {
    fn device_id(&self) -> u32 {
        self.device_id
    }

    fn status(&self) -> u8 {
        self.common8(common::DEVICE_STATUS)
    }

    fn set_status(&self, value: u8) {
        self.set_common8(common::DEVICE_STATUS, value);
    }

    fn device_features(&self, select: u32) -> u32 {
        self.set_common32(common::DEVICE_FEATURE_SELECT, select);
        self.common32(common::DEVICE_FEATURE)
    }

    fn set_driver_features(&self, select: u32, value: u32) {
        self.set_common32(common::DRIVER_FEATURE_SELECT, select);
        self.set_common32(common::DRIVER_FEATURE, value);
    }

    fn queue_max(&self, index: u16) -> u16 {
        self.set_common16(common::QUEUE_SELECT, index);
        self.common16(common::QUEUE_SIZE)
    }

    fn setup_queue(&self, index: u16, size: u16, desc: u64, avail: u64, used: u64) {
        self.set_common16(common::QUEUE_SELECT, index);
        self.set_common16(common::QUEUE_SIZE, size);
        self.set_common64(common::QUEUE_DESC, desc);
        self.set_common64(common::QUEUE_DRIVER, avail);
        self.set_common64(common::QUEUE_DEVICE, used);
        self.set_common16(common::QUEUE_ENABLE, 1);
    }

    fn notify(&self, index: u16) {
        // Where to write is the queue's own notification offset times the device's stride,
        // which is why the queue is selected first: the answer is per queue, not fixed.
        self.set_common16(common::QUEUE_SELECT, index);
        let off = u32::from(self.common16(common::QUEUE_NOTIFY_OFF));
        let at = off.saturating_mul(self.layout.notify_multiplier) as usize;
        if let Some(o) = Self::at(&self.layout.notify, at, 2) {
            self.bar.write16(o, index);
        }
    }

    fn ack_interrupt(&self) -> u32 {
        // The ISR status register clears on read, which is the acknowledgement: a second read
        // would report nothing pending and lose the reason for the first.
        Self::at(&self.layout.isr, 0, 1).map_or(0, |o| u32::from(self.bar.read8(o)))
    }

    fn set_config_vector(&self, vector: u16) -> u16 {
        self.set_common16(common::MSIX_CONFIG, vector);
        self.common16(common::MSIX_CONFIG)
    }

    fn set_queue_vector(&self, index: u16, vector: u16) -> u16 {
        // The queue must be selected first: the vector register is per queue, like its size.
        self.set_common16(common::QUEUE_SELECT, index);
        self.set_common16(common::QUEUE_MSIX_VECTOR, vector);
        self.common16(common::QUEUE_MSIX_VECTOR)
    }

    fn config_read8(&self, offset: usize) -> u8 {
        Self::at(&self.layout.device, offset, 1).map_or(0, |o| self.bar.read8(o))
    }

    fn config_read32(&self, offset: usize) -> u32 {
        Self::at(&self.layout.device, offset, 4).map_or(0, |o| self.bar.read32(o))
    }
}

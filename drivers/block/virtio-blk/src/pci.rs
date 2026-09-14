//! The PCI transport (virtio 1.1 §4.1): the same device, with its registers spread across
//! a function's BARs instead of gathered in one window.
//!
//! # Where the registers are is a question the device answers
//!
//! A memory-mapped virtio device has one window at a fixed layout. A PCI one has four
//! structures — common configuration, notification, interrupt status, device-specific
//! configuration — and says where each is through vendor-specific capabilities in its
//! configuration space: a BAR index, an offset into it, and a length. So this transport is
//! built by *reading* the device rather than by knowing a layout, and [`Layout::read`] is
//! that read. A device that leaves one out is refused rather than guessed at.
//!
//! # Why there is no legacy path
//!
//! A transitional device also offers the pre-1.0 register layout in an I/O BAR, with a
//! different queue-setup protocol. The driver speaks virtio 1.x only, so a device that
//! offers no modern capabilities is [`Error::Legacy`] — the same refusal the memory-mapped
//! transport makes for a version-1 slot, and for the same reason: mis-driving a device is
//! worse than not driving it.

// The promise a claimed BAR is mapped is the caller's, made once in `Pci::new`, exactly as
// the memory-mapped transport makes it.
#![allow(unsafe_code)]

use device::pci::{self, Function};

use crate::mem::Window;
use crate::transport::{Error, Transport};

/// Virtio's own capability types (virtio 1.1 §4.1.4).
mod cfg_type {
    pub const COMMON: u8 = 1;
    pub const NOTIFY: u8 = 2;
    pub const ISR: u8 = 3;
    pub const DEVICE: u8 = 4;
}

/// Where each field sits in a virtio vendor capability (virtio 1.1 §4.1.4): bytes for the
/// two in the first word, word indices for the rest.
mod cap {
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
    pub const DEVICE_STATUS: usize = 0x14;
    pub const QUEUE_SELECT: usize = 0x16;
    pub const QUEUE_SIZE: usize = 0x18;
    pub const QUEUE_NOTIFY_OFF: usize = 0x1e;
    pub const QUEUE_DESC: usize = 0x20;
    pub const QUEUE_DRIVER: usize = 0x28;
    pub const QUEUE_DEVICE: usize = 0x30;
    pub const QUEUE_ENABLE: usize = 0x1c;
}

/// The least a common configuration structure can be for the fields above to exist.
const COMMON_BYTES: u64 = 0x38;

/// Virtio's PCI vendor ID, and the device IDs a block device answers to: the modern range
/// is 0x1040 plus the virtio device type, and 0x1001 is the transitional block device.
pub const VENDOR: u16 = 0x1af4;
pub const DEVICE_MODERN_BLOCK: u16 = 0x1042;
pub const DEVICE_TRANSITIONAL_BLOCK: u16 = 0x1001;

/// Whether a function is a virtio block device of either kind.
pub fn is_block_device(f: &Function) -> bool {
    f.vendor == VENDOR
        && (f.device == DEVICE_MODERN_BLOCK || f.device == DEVICE_TRANSITIONAL_BLOCK)
}

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
    /// Where `f`'s structures are, from the capability list enumeration recorded.
    ///
    /// Read from the [`Function`] rather than from configuration space, because a driver
    /// is handed the node its `Origin::Pci` borrows and has no way back to the bus: the
    /// one place with `ConfigSpace` is the enumerator. See `device::pci::Capability`.
    ///
    /// `Err(Legacy)` when the device offers no modern structures at all, which is what a
    /// pre-1.0 device looks like from here.
    pub fn read(f: &Function) -> Result<Layout, Error> {
        let mut layout = Layout::default();
        for c in f.capabilities() {
            if c.id != pci::CAP_VENDOR {
                continue;
            }
            let place = Place {
                bar: c.byte(cap::BAR_BYTE),
                offset: c.word(cap::OFFSET_WORD),
                length: c.word(cap::LENGTH_WORD),
            };
            if place.length == 0 {
                continue;
            }
            match c.byte(cap::CFG_TYPE_BYTE) {
                cfg_type::COMMON => layout.common = place,
                cfg_type::NOTIFY => {
                    layout.notify = place;
                    layout.notify_multiplier = c.word(cap::NOTIFY_MULTIPLIER_WORD);
                }
                cfg_type::ISR => layout.isr = place,
                cfg_type::DEVICE => layout.device = place,
                _ => {}
            }
        }
        if !layout.common.found() || !layout.notify.found() || !layout.isr.found() {
            return Err(Error::Legacy);
        }
        if u64::from(layout.common.length) < COMMON_BYTES {
            return Err(Error::NotVirtio);
        }
        Ok(layout)
    }

    /// Every BAR index the layout names, so a probe knows which ones to claim.
    pub fn bars(&self) -> [u8; 4] {
        [
            self.common.bar,
            self.notify.bar,
            self.isr.bar,
            self.device.bar,
        ]
    }
}

/// A virtio device behind PCI, with each structure as its own window.
pub struct Pci {
    common: Window,
    notify: Window,
    isr: Window,
    device: Option<Window>,
    notify_multiplier: u32,
    /// The device ID the function reported, which is what the transport's `device_id`
    /// answers: a PCI virtio device says what it is in configuration space, not in a
    /// register.
    device_id: u32,
}

impl Pci {
    /// Build the transport over a BAR mapped at `bar_base`.
    ///
    /// Every structure of `layout` must be in BAR `bar_index`; a device that spreads them
    /// over several BARs is refused, because only the claimed one is mapped. QEMU's
    /// virtio-pci puts all four in one.
    ///
    /// # Safety
    /// `[bar_base, bar_base + bar_len)` must be the claimed BAR, mapped as device memory,
    /// and this must be the only transport for that device.
    pub unsafe fn new(
        layout: &Layout,
        bar_index: u8,
        bar_base: usize,
        bar_len: usize,
        device_id: u32,
    ) -> Result<Pci, Error> {
        // SAFETY: the caller's contract is this function's.
        let bar = unsafe { Window::new(bar_base, bar_len) };
        let sub = |p: &Place| -> Option<Window> {
            if p.bar != bar_index || !p.found() {
                return None;
            }
            bar.sub(p.offset as usize, p.length as usize)
        };
        let common = sub(&layout.common).ok_or(Error::NotVirtio)?;
        let notify = sub(&layout.notify).ok_or(Error::NotVirtio)?;
        let isr = sub(&layout.isr).ok_or(Error::NotVirtio)?;
        Ok(Pci {
            common,
            notify,
            isr,
            device: sub(&layout.device),
            notify_multiplier: layout.notify_multiplier,
            device_id,
        })
    }
}

impl Transport for Pci {
    fn device_id(&self) -> u32 {
        self.device_id
    }

    fn status(&self) -> u8 {
        self.common.read8(common::DEVICE_STATUS)
    }

    fn set_status(&self, value: u8) {
        self.common.write8(common::DEVICE_STATUS, value);
    }

    fn device_features(&self, select: u32) -> u32 {
        self.common.write32(common::DEVICE_FEATURE_SELECT, select);
        self.common.read32(common::DEVICE_FEATURE)
    }

    fn set_driver_features(&self, select: u32, value: u32) {
        self.common.write32(common::DRIVER_FEATURE_SELECT, select);
        self.common.write32(common::DRIVER_FEATURE, value);
    }

    fn queue_max(&self, index: u16) -> u16 {
        self.common.write16(common::QUEUE_SELECT, index);
        self.common.read16(common::QUEUE_SIZE)
    }

    fn setup_queue(&self, index: u16, size: u16, desc: u64, avail: u64, used: u64) {
        self.common.write16(common::QUEUE_SELECT, index);
        self.common.write16(common::QUEUE_SIZE, size);
        self.common.write64(common::QUEUE_DESC, desc);
        self.common.write64(common::QUEUE_DRIVER, avail);
        self.common.write64(common::QUEUE_DEVICE, used);
        self.common.write16(common::QUEUE_ENABLE, 1);
    }

    fn notify(&self, index: u16) {
        // Where to write is the queue's own notification offset times the device's stride,
        // which is why the queue is selected first: the answer is per queue, not fixed.
        self.common.write16(common::QUEUE_SELECT, index);
        let off = u32::from(self.common.read16(common::QUEUE_NOTIFY_OFF));
        let at = (off * self.notify_multiplier) as usize;
        if at + 2 <= self.notify.len() {
            self.notify.write16(at, index);
        }
    }

    fn ack_interrupt(&self) -> u32 {
        // The ISR status register clears on read, which is the acknowledgement: a second
        // read would report nothing pending and lose the reason for the first.
        u32::from(self.isr.read8(0))
    }

    fn config_read8(&self, offset: usize) -> u8 {
        self.device.as_ref().map_or(0, |w| w.read8(offset))
    }

    fn config_read32(&self, offset: usize) -> u32 {
        self.device.as_ref().map_or(0, |w| w.read32(offset))
    }
}

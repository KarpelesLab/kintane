//! The memory-mapped transport (virtio 1.1 §4.2): one window of registers per device,
//! which a device tree describes as `virtio,mmio`.
//!
//! # Why enumeration is not probing
//!
//! QEMU's `virt` machines describe **thirty-two** `virtio,mmio` slots whether or not
//! anything is plugged into them, and nothing in the tree says which are occupied: the
//! answer is in the slot's own `DeviceID` register. So which slot holds a disk is a
//! question only a read of the hardware answers, and [`identify`] is that read.
//!
//! It is deliberately *not* part of `Driver::probe`, whose contract is that a probe
//! touches no hardware, because nothing is mapped on a driver's behalf until every probe
//! has run. [`identify`] is called by the platform, on the boot identity map, the way
//! `pci::enumerate` reads configuration space — enumerators read a machine to find out
//! what is there; drivers drive what they were bound to. The platform then binds this
//! driver to the one slot that answered "block device".

// `identify` reads a window nobody has claimed yet, and `Mmio::new` is the promise a
// claimed window is mapped: both are the caller's contract, stated where they are made.
#![allow(unsafe_code)]

use crate::mem::Window;
use crate::transport::Transport;

/// Register offsets (virtio 1.1 §4.2.2).
mod reg {
    pub const MAGIC: usize = 0x000;
    pub const VERSION: usize = 0x004;
    pub const DEVICE_ID: usize = 0x008;
    pub const DEVICE_FEATURES: usize = 0x010;
    pub const DEVICE_FEATURES_SEL: usize = 0x014;
    pub const DRIVER_FEATURES: usize = 0x020;
    pub const DRIVER_FEATURES_SEL: usize = 0x024;
    pub const QUEUE_SEL: usize = 0x030;
    pub const QUEUE_NUM_MAX: usize = 0x034;
    pub const QUEUE_NUM: usize = 0x038;
    pub const QUEUE_READY: usize = 0x044;
    pub const QUEUE_NOTIFY: usize = 0x050;
    pub const INTERRUPT_STATUS: usize = 0x060;
    pub const INTERRUPT_ACK: usize = 0x064;
    pub const STATUS: usize = 0x070;
    pub const QUEUE_DESC_LOW: usize = 0x080;
    pub const QUEUE_DRIVER_LOW: usize = 0x090;
    pub const QUEUE_DEVICE_LOW: usize = 0x0a0;
    pub const CONFIG: usize = 0x100;
}

/// `"virt"` little-endian, in every virtio-mmio device's first register.
pub const MAGIC: u32 = 0x7472_6976;
/// The version of the register layout this driver speaks. Version 1 is the legacy
/// layout, whose queue setup is a different protocol.
pub const VERSION_MODERN: u32 = 2;

/// The least the register window must be for the fields above to exist.
pub const MIN_WINDOW: u64 = 0x200;

/// What a slot holds.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Slot {
    /// Not a virtio-mmio device: the magic is wrong.
    NotVirtio,
    /// A slot with nothing plugged in — `DeviceID` zero, which QEMU's unused slots read.
    Empty,
    /// A legacy device, which this driver refuses rather than mis-drives.
    Legacy { device_id: u32 },
    /// A modern device of this type.
    Device { device_id: u32 },
}

/// Read a slot's identification registers.
///
/// # Safety
/// `[base, base + len)` must be the device's register window, mapped as device memory.
pub unsafe fn identify(base: usize, len: usize) -> Slot {
    // SAFETY: the caller's contract is this function's.
    let w = unsafe { Window::new(base, len) };
    if w.read32(reg::MAGIC) != MAGIC {
        return Slot::NotVirtio;
    }
    let version = w.read32(reg::VERSION);
    let device_id = w.read32(reg::DEVICE_ID);
    match (version, device_id) {
        (_, 0) => Slot::Empty,
        (VERSION_MODERN, device_id) => Slot::Device { device_id },
        (_, device_id) => Slot::Legacy { device_id },
    }
}

/// A virtio device behind a memory-mapped register window.
pub struct Mmio {
    window: Window,
}

impl Mmio {
    /// # Safety
    /// `window` must be the device's register window, mapped as device memory, and this
    /// must be the only transport for that device.
    pub const unsafe fn new(window: Window) -> Mmio {
        Mmio { window }
    }
}

impl Transport for Mmio {
    fn device_id(&self) -> u32 {
        self.window.read32(reg::DEVICE_ID)
    }

    fn status(&self) -> u8 {
        self.window.read32(reg::STATUS) as u8
    }

    fn set_status(&self, value: u8) {
        self.window.write32(reg::STATUS, u32::from(value));
    }

    fn device_features(&self, select: u32) -> u32 {
        self.window.write32(reg::DEVICE_FEATURES_SEL, select);
        self.window.read32(reg::DEVICE_FEATURES)
    }

    fn set_driver_features(&self, select: u32, value: u32) {
        self.window.write32(reg::DRIVER_FEATURES_SEL, select);
        self.window.write32(reg::DRIVER_FEATURES, value);
    }

    fn queue_max(&self, index: u16) -> u16 {
        self.window.write32(reg::QUEUE_SEL, u32::from(index));
        // A queue larger than 32768 is not one the protocol allows; clamping rather than
        // truncating keeps a device that reports nonsense from producing a tiny queue.
        self.window.read32(reg::QUEUE_NUM_MAX).min(32768) as u16
    }

    fn setup_queue(&self, index: u16, size: u16, desc: u64, avail: u64, used: u64) {
        self.window.write32(reg::QUEUE_SEL, u32::from(index));
        self.window.write32(reg::QUEUE_NUM, u32::from(size));
        self.window.write64(reg::QUEUE_DESC_LOW, desc);
        self.window.write64(reg::QUEUE_DRIVER_LOW, avail);
        self.window.write64(reg::QUEUE_DEVICE_LOW, used);
        self.window.write32(reg::QUEUE_READY, 1);
    }

    fn notify(&self, index: u16) {
        self.window.write32(reg::QUEUE_NOTIFY, u32::from(index));
    }

    fn ack_interrupt(&self) -> u32 {
        let pending = self.window.read32(reg::INTERRUPT_STATUS);
        if pending != 0 {
            self.window.write32(reg::INTERRUPT_ACK, pending);
        }
        pending
    }

    fn config_read8(&self, offset: usize) -> u8 {
        self.window.read8(reg::CONFIG + offset)
    }

    fn config_read32(&self, offset: usize) -> u32 {
        self.window.read32(reg::CONFIG + offset)
    }
}

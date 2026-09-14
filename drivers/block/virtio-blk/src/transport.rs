//! What the driver needs from a virtio transport, and the bring-up sequence written
//! against it.
//!
//! virtio devices appear on several buses — memory-mapped registers on a device tree
//! machine, PCI on a PC — and the difference is entirely in *where the registers are*.
//! The device's own protocol (status handshake, feature negotiation, queue setup) is the
//! same, so it is written once here, and [`Transport`] is the seam: two dozen lines per
//! bus, and no bus knowledge above it.

use crate::mem::Dma;
use crate::queue::Ring;

/// Device status bits (virtio 1.1 §2.1).
pub mod status {
    pub const ACKNOWLEDGE: u8 = 1;
    pub const DRIVER: u8 = 2;
    pub const DRIVER_OK: u8 = 4;
    pub const FEATURES_OK: u8 = 8;
    pub const NEEDS_RESET: u8 = 64;
    pub const FAILED: u8 = 128;
}

/// `VIRTIO_F_VERSION_1`: bit 32, so bit 0 of feature word 1. A device that does not offer
/// it is a legacy device, which this driver does not drive.
pub const VERSION_1_WORD: u32 = 1;
pub const VERSION_1_BIT: u32 = 1 << 0;

/// The virtio device type for a block device (virtio 1.1 §5.2).
pub const DEVICE_ID_BLOCK: u32 = 2;

/// Why bring-up failed. Each is a distinct thing that can be wrong with a device, because
/// "the disk did not come up" is not a diagnosis.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Error {
    /// The registers do not look like a virtio device at all.
    NotVirtio,
    /// A legacy (pre-1.0) device, or one that will not offer `VIRTIO_F_VERSION_1`.
    Legacy,
    /// Not the device type this driver drives.
    WrongDevice { id: u32 },
    /// The device refused the features the driver asked for.
    FeaturesRefused,
    /// The device reset, or refused a step of the handshake.
    Refused { status: u8 },
    /// The device offers no queue, or one too small to work with.
    BadQueue { max: u16 },
    /// The DMA region cannot hold the rings and buffers.
    NoRoom,
    /// The device's configuration describes a geometry no driver can use.
    BadGeometry,
    /// The device did not answer a request in time.
    Timeout,
}

/// Where a virtio device's registers are, and how to reach them.
pub trait Transport {
    /// The device type (virtio 1.1 §5): 2 for a block device.
    fn device_id(&self) -> u32;

    fn status(&self) -> u8;
    fn set_status(&self, value: u8);

    /// Feature word `select`: bits `32 * select ..`.
    fn device_features(&self, select: u32) -> u32;
    fn set_driver_features(&self, select: u32, value: u32);

    /// The largest queue the device will give for queue `index`, or 0 if it has none.
    fn queue_max(&self, index: u16) -> u16;

    /// Point queue `index` at a ring of `size` and enable it.
    fn setup_queue(&self, index: u16, size: u16, desc: u64, avail: u64, used: u64);

    /// Tell the device that queue `index` has new buffers.
    fn notify(&self, index: u16);

    /// Read and acknowledge the interrupt status, returning what was pending. Zero when
    /// the device did not raise the interrupt, which is how a shared line is shared.
    fn ack_interrupt(&self) -> u32;

    /// A byte of the device-specific configuration.
    fn config_read8(&self, offset: usize) -> u8;

    fn config_read32(&self, offset: usize) -> u32;

    fn config_read64(&self, offset: usize) -> u64 {
        u64::from(self.config_read32(offset)) | (u64::from(self.config_read32(offset + 4)) << 32)
    }
}

/// Reset the device and walk the status handshake up to `FEATURES_OK`, negotiating
/// `VIRTIO_F_VERSION_1` and whichever of `wanted` the device offers.
///
/// Returns the features that were accepted, as two words. The caller finishes bring-up
/// with [`finish`] after its queues are set up, because `DRIVER_OK` is the promise that
/// the driver is ready for interrupts.
pub fn negotiate(
    transport: &dyn Transport,
    device: u32,
    wanted: [u32; 2],
) -> Result<[u32; 2], Error> {
    if transport.device_id() != device {
        return Err(Error::WrongDevice {
            id: transport.device_id(),
        });
    }

    // Reset, and see the reset take: a device that does not read back zero is not
    // answering, and every step after this would be written into the void.
    transport.set_status(0);
    if transport.status() != 0 {
        return Err(Error::Refused {
            status: transport.status(),
        });
    }
    transport.set_status(status::ACKNOWLEDGE);
    transport.set_status(status::ACKNOWLEDGE | status::DRIVER);

    let offered = [transport.device_features(0), transport.device_features(1)];
    if offered[VERSION_1_WORD as usize] & VERSION_1_BIT == 0 {
        transport.set_status(status::FAILED);
        return Err(Error::Legacy);
    }
    let accepted = [
        offered[0] & wanted[0],
        (offered[1] & wanted[1]) | VERSION_1_BIT,
    ];
    transport.set_driver_features(0, accepted[0]);
    transport.set_driver_features(1, accepted[1]);

    let asked = status::ACKNOWLEDGE | status::DRIVER | status::FEATURES_OK;
    transport.set_status(asked);
    // The one handshake step a device may refuse: re-reading the status is how the driver
    // learns it did (virtio 1.1 §3.1.1 step 6).
    if transport.status() & status::FEATURES_OK == 0 {
        transport.set_status(status::FAILED);
        return Err(Error::FeaturesRefused);
    }
    Ok(accepted)
}

/// Set up queue `index` over `ring` and tell the device about it.
pub fn setup_queue(transport: &dyn Transport, index: u16, ring: &Ring) -> Result<(), Error> {
    let max = transport.queue_max(index);
    if max == 0 || max < ring.size() {
        return Err(Error::BadQueue { max });
    }
    transport.setup_queue(
        index,
        ring.size(),
        ring.desc_phys(),
        ring.avail_phys(),
        ring.used_phys(),
    );
    Ok(())
}

/// The last step: the driver is ready, and the device may use the queues.
pub fn finish(transport: &dyn Transport) -> Result<(), Error> {
    let all = status::ACKNOWLEDGE | status::DRIVER | status::FEATURES_OK | status::DRIVER_OK;
    transport.set_status(all);
    let status = transport.status();
    if status & status::DRIVER_OK == 0 || status & (status::FAILED | status::NEEDS_RESET) != 0 {
        return Err(Error::Refused { status });
    }
    Ok(())
}

/// How much device-visible memory a queue of `size` needs, with each part on its own
/// alignment. Used to size the DMA region before anything is carved out of it.
pub const fn queue_bytes(size: u16) -> usize {
    let (d, a, u) = Ring::sizes(size);
    // Each part is aligned to 16 bytes at most, so a whole extra alignment per part is a
    // sufficient bound for the padding between them.
    d + a + u + 3 * 16
}

/// Carve the three ring regions out of `region`, aligned as virtio requires.
pub fn carve_ring(region: &mut Dma, size: u16) -> Result<Ring, Error> {
    let (d, a, u) = Ring::sizes(size);
    let desc = region.take(d, 16).ok_or(Error::NoRoom)?;
    let avail = region.take(a, 2).ok_or(Error::NoRoom)?;
    let used = region.take(u, 4).ok_or(Error::NoRoom)?;
    Ring::new(desc, avail, used, size).map_err(|e| match e {
        crate::queue::Error::TooSmall => Error::NoRoom,
        _ => Error::BadQueue { max: size },
    })
}

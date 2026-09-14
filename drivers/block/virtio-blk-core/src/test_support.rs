//! A virtio-blk device on the other side of the rings, so the driver's protocol can be tested
//! on a laptop rather than only under QEMU.
//!
//! The device side of a queue — [`Backing`], [`FakeDevice`] — is every virtio driver's, in
//! `virtio::fake`. What a block device does with a chain is here: [`serve_block`] answers
//! virtio-blk requests against a RAM disk, and [`FakeTransport`] plays the registers around
//! it, which is what lets the whole driver, up to and including `BlockDevice::read_blocks`,
//! run as a host test.

use core::cell::{Cell, RefCell};

pub use virtio::fake::{Backing, FakeDevice, View};

use crate::transport::{self, Transport, status};
use crate::{F_BLK_SIZE, F_FLUSH};

/// Bytes in a protocol sector.
pub const SECTOR: usize = 512;

/// Answer one virtio-blk request against `disk`, as QEMU's device would.
///
/// Returns `false` if the driver published nothing. The status byte is the last
/// buffer of the chain, and the request header the first, which is the layout virtio
/// 1.1 §5.2.6 requires and this therefore checks.
pub fn serve_block(device: &mut FakeDevice, disk: &mut [u8], fail: bool) -> bool {
    const SECTOR: usize = 512;
    let Some(chain) = device.take_available() else {
        return false;
    };
    assert!(chain.buffers.len() >= 2, "a request is at least a header and a status");
    let header = chain.buffers[0];
    assert_eq!(header.len, 16, "the header is 16 bytes");
    assert!(!header.device_writes, "the device reads the header");
    let h = device.region(header.phys, 16);
    let kind = h.read32(0);
    let sector = u64::from(h.read32(8)) | (u64::from(h.read32(12)) << 32);

    let status = *chain.buffers.last().expect("checked above");
    assert_eq!(status.len, 1, "the status is one byte");
    assert!(status.device_writes, "the device writes the status");

    let data = &chain.buffers[1..chain.buffers.len() - 1];
    let mut at = usize::try_from(sector).unwrap() * SECTOR;
    let mut written = 0u32;
    let mut ok = true;
    for buf in data {
        let len = buf.len as usize;
        let region = device.region(buf.phys, len);
        match kind {
            // VIRTIO_BLK_T_IN: the device writes the data.
            0 => {
                assert!(buf.device_writes, "a read's data buffer must be device-writable");
                if at + len > disk.len() {
                    ok = false;
                    break;
                }
                let bytes: Vec<u8> = disk[at..at + len].to_vec();
                region.write_bytes(0, &bytes);
                written += buf.len;
            }
            // VIRTIO_BLK_T_OUT: the device reads it.
            1 => {
                assert!(!buf.device_writes, "a write's data buffer must be device-readable");
                if at + len > disk.len() {
                    ok = false;
                    break;
                }
                let mut bytes = vec![0u8; len];
                region.read_bytes(0, &mut bytes);
                disk[at..at + len].copy_from_slice(&bytes);
            }
            // VIRTIO_BLK_T_FLUSH: nothing to do for a RAM disk.
            4 => {}
            _ => ok = false,
        }
        at += len;
    }
    let status_region = device.region(status.phys, 1);
    // 0 is OK, 1 is IOERR (virtio 1.1 §5.2.6).
    status_region.write8(0, if ok && !fail { 0 } else { 1 });
    device.complete(chain.head, written + 1);
    true
}

/// The registers, played: it records the status and features a driver writes, and learns
/// the ring addresses from queue setup. Its `notify` serves the request at once, which a real
/// device is allowed to do, so a driver's first look at the used ring finds the completion.
/// Knobs make it misbehave the ways a device can.
///
/// Shared by this crate's tests and `drivers/block/virtio-blk`'s, which include this file:
/// the engine and the kernel's wrapper around it are tested against the same device.
pub struct FakeTransport {
    pub view: View,
    pub device_id: u32,
    pub status: Cell<u8>,
    pub offered: [u32; 2],
    pub accepted: Cell<[u32; 2]>,
    pub feature_sel: Cell<u32>,
    pub queue_max: u16,
    pub capacity_sectors: u64,
    pub blk_size: u32,
    pub device: RefCell<Option<FakeDevice>>,
    pub disk: RefCell<Vec<u8>>,
    /// Refuse FEATURES_OK, as a device that cannot do what was negotiated does.
    pub refuse_features: bool,
    /// Report an I/O error in every request's status byte.
    pub fail_io: Cell<bool>,
    /// Take requests off the ring and never answer.
    pub silent: Cell<bool>,
    pub notifies: Cell<u32>,
    /// Entries in the MSI-X table; 0 for a device without one, which refuses every vector.
    pub msix_entries: u16,
    pub queue_vector: Cell<u16>,
    pub config_vector: Cell<u16>,
    /// The queue's vector when the queue was set up, which is when it must already be set.
    pub vector_at_setup: Cell<Option<u16>>,
    /// Reads of the interrupt status register.
    pub isr_reads: Cell<u32>,
}

impl FakeTransport {
    pub fn new(backing: &Backing, sectors: u64) -> FakeTransport {
        FakeTransport {
            view: backing.view(),
            device_id: transport::DEVICE_ID_BLOCK,
            status: Cell::new(0),
            offered: [F_BLK_SIZE | F_FLUSH, transport::VERSION_1_BIT],
            accepted: Cell::new([0, 0]),
            feature_sel: Cell::new(0),
            queue_max: 256,
            capacity_sectors: sectors,
            blk_size: 512,
            device: RefCell::new(None),
            disk: RefCell::new(
                (0..sectors as usize * SECTOR)
                    .map(|i| ((i / SECTOR) as u8).wrapping_mul(7) ^ (i as u8))
                    .collect(),
            ),
            refuse_features: false,
            fail_io: Cell::new(false),
            silent: Cell::new(false),
            notifies: Cell::new(0),
            msix_entries: 2,
            queue_vector: Cell::new(transport::NO_VECTOR),
            config_vector: Cell::new(transport::NO_VECTOR),
            vector_at_setup: Cell::new(None),
            isr_reads: Cell::new(0),
        }
    }

    /// What a device answers to a vector: kept when it is in the table, refused otherwise.
    fn take_vector(&self, vector: u16) -> u16 {
        if vector < self.msix_entries {
            vector
        } else {
            transport::NO_VECTOR
        }
    }
}

impl Transport for FakeTransport {
    fn device_id(&self) -> u32 {
        self.device_id
    }

    fn status(&self) -> u8 {
        self.status.get()
    }

    fn set_status(&self, value: u8) {
        if value == 0 {
            // A reset forgets the vectors, as it forgets everything else.
            self.queue_vector.set(transport::NO_VECTOR);
            self.config_vector.set(transport::NO_VECTOR);
        }
        if value & status::FEATURES_OK != 0 && self.refuse_features {
            // A device refusing the features leaves FEATURES_OK clear.
            self.status.set(value & !status::FEATURES_OK);
            return;
        }
        self.status.set(value);
    }

    fn device_features(&self, select: u32) -> u32 {
        self.feature_sel.set(select);
        self.offered.get(select as usize).copied().unwrap_or(0)
    }

    fn set_driver_features(&self, select: u32, value: u32) {
        let mut a = self.accepted.get();
        if let Some(w) = a.get_mut(select as usize) {
            *w = value;
        }
        self.accepted.set(a);
    }

    fn queue_max(&self, _index: u16) -> u16 {
        self.queue_max
    }

    fn setup_queue(&self, _index: u16, size: u16, desc: u64, avail: u64, used: u64) {
        self.vector_at_setup.set(Some(self.queue_vector.get()));
        *self.device.borrow_mut() = Some(FakeDevice::at(self.view, desc, avail, used, size));
    }

    fn notify(&self, _index: u16) {
        self.notifies.set(self.notifies.get() + 1);
        let mut device = self.device.borrow_mut();
        let device = device
            .as_mut()
            .expect("notified before the queue was set up");
        if self.silent.get() {
            device.take_available();
            return;
        }
        serve_block(device, &mut self.disk.borrow_mut(), self.fail_io.get());
    }

    fn ack_interrupt(&self) -> u32 {
        // Nothing pending, ever: what a device delivering on an MSI-X vector reports.
        self.isr_reads.set(self.isr_reads.get() + 1);
        0
    }

    fn set_config_vector(&self, vector: u16) -> u16 {
        self.config_vector.set(self.take_vector(vector));
        self.config_vector.get()
    }

    fn set_queue_vector(&self, _index: u16, vector: u16) -> u16 {
        self.queue_vector.set(self.take_vector(vector));
        self.queue_vector.get()
    }

    fn config_read8(&self, _offset: usize) -> u8 {
        0
    }

    fn config_read32(&self, offset: usize) -> u32 {
        match offset {
            0 => self.capacity_sectors as u32,
            4 => (self.capacity_sectors >> 32) as u32,
            20 => self.blk_size,
            _ => 0,
        }
    }
}

//! The whole driver, from the status handshake to `BlockDevice::read_blocks`, against a
//! device that answers on the other side of the rings.
//!
//! [`FakeTransport`] plays the registers: it records the status and features the driver
//! writes, and learns the ring addresses from queue setup. Its `notify` serves the request
//! at once, which a real device is allowed to do, so the driver's polling loop finds the
//! completion on its first look. Knobs make it misbehave the ways a device can.

use core::cell::{Cell, RefCell};

use block::{BlockDevice, Error as BlockError};
use hal::mock::MockFull;
use sync::Spin;

use crate::test_support::{Backing, FakeDevice, View};
use crate::transport::{self, Error, Transport, status};
use crate::{F_BLK_SIZE, F_FLUSH, F_RO, VirtioBlk, dma_bytes};

const SECTOR: usize = 512;

struct FakeTransport {
    view: View,
    device_id: u32,
    status: Cell<u8>,
    offered: [u32; 2],
    accepted: Cell<[u32; 2]>,
    feature_sel: Cell<u32>,
    queue_max: u16,
    capacity_sectors: u64,
    blk_size: u32,
    device: RefCell<Option<FakeDevice>>,
    disk: RefCell<Vec<u8>>,
    /// Refuse FEATURES_OK, as a device that cannot do what was negotiated does.
    refuse_features: bool,
    /// Report an I/O error in every request's status byte.
    fail_io: Cell<bool>,
    /// Take requests off the ring and never answer.
    silent: Cell<bool>,
    notifies: Cell<u32>,
}

impl FakeTransport {
    fn new(backing: &Backing, sectors: u64) -> FakeTransport {
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
        crate::test_support::serve_block(device, &mut self.disk.borrow_mut(), self.fail_io.get());
    }

    fn ack_interrupt(&self) -> u32 {
        0
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

type Blk = VirtioBlk<Spin<MockFull>, FakeTransport>;

/// A started driver over a fake device of `sectors`, with a bounce buffer of `bounce`.
fn started(backing: &mut Backing, sectors: u64, bounce: usize) -> Result<Blk, Error> {
    let dma = backing.take(dma_bytes(bounce), 4096);
    let transport = FakeTransport::new(backing, sectors);
    Blk::bring_up(transport, dma)
}

#[test]
fn bring_up_walks_the_handshake_and_reads_the_geometry() {
    let mut backing = Backing::new(256 * 1024);
    let blk = started(&mut backing, 2048, 8 * SECTOR).unwrap();
    let t = &blk.transport;
    assert_eq!(
        t.status.get(),
        status::ACKNOWLEDGE | status::DRIVER | status::FEATURES_OK | status::DRIVER_OK
    );
    let accepted = t.accepted.get();
    assert_ne!(accepted[1] & transport::VERSION_1_BIT, 0, "VERSION_1 negotiated");
    assert_ne!(accepted[0] & F_FLUSH, 0, "FLUSH taken when offered");
    assert_eq!(accepted[0] & F_RO, 0, "RO never asked for");
    assert!(t.device.borrow().is_some(), "the queue was set up");

    let g = blk.geometry();
    assert_eq!((g.block_size, g.capacity), (512, 2048));
    assert_eq!(blk.max_transfer_blocks(), 8);
}

#[test]
fn a_device_of_another_type_is_refused() {
    let mut backing = Backing::new(256 * 1024);
    let dma = backing.take(dma_bytes(SECTOR), 4096);
    let mut t = FakeTransport::new(&backing, 64);
    t.device_id = 1; // a network card
    assert_eq!(Blk::bring_up(t, dma).err(), Some(Error::WrongDevice { id: 1 }));
}

#[test]
fn a_legacy_device_is_refused_rather_than_mis_driven() {
    let mut backing = Backing::new(256 * 1024);
    let dma = backing.take(dma_bytes(SECTOR), 4096);
    let mut t = FakeTransport::new(&backing, 64);
    t.offered = [F_FLUSH, 0];
    assert_eq!(Blk::bring_up(t, dma).err(), Some(Error::Legacy));
}

#[test]
fn a_device_that_refuses_the_features_is_an_error() {
    let mut backing = Backing::new(256 * 1024);
    let dma = backing.take(dma_bytes(SECTOR), 4096);
    let mut t = FakeTransport::new(&backing, 64);
    t.refuse_features = true;
    assert_eq!(Blk::bring_up(t, dma).err(), Some(Error::FeaturesRefused));
}

#[test]
fn a_queue_smaller_than_the_driver_needs_is_refused() {
    let mut backing = Backing::new(256 * 1024);
    let dma = backing.take(dma_bytes(SECTOR), 4096);
    let mut t = FakeTransport::new(&backing, 64);
    t.queue_max = 2;
    assert_eq!(Blk::bring_up(t, dma).err(), Some(Error::BadQueue { max: 2 }));
}

#[test]
fn a_region_too_small_for_the_rings_is_refused_at_bring_up() {
    let mut backing = Backing::new(256 * 1024);
    let dma = backing.take(128, 4096);
    let t = FakeTransport::new(&backing, 64);
    assert_eq!(Blk::bring_up(t, dma).err(), Some(Error::NoRoom));
}

#[test]
fn sectors_read_back_what_the_disk_holds() {
    let mut backing = Backing::new(256 * 1024);
    let blk = started(&mut backing, 64, 4 * SECTOR).unwrap();
    let mut buf = vec![0u8; 3 * SECTOR];
    blk.read_blocks(5, &mut buf).unwrap();
    let disk = blk.transport.disk.borrow();
    assert_eq!(&buf[..], &disk[5 * SECTOR..8 * SECTOR]);
}

#[test]
fn a_write_reads_back_and_leaves_its_neighbours_alone() {
    let mut backing = Backing::new(256 * 1024);
    let blk = started(&mut backing, 64, 4 * SECTOR).unwrap();
    let before: Vec<u8> = blk.transport.disk.borrow().clone();
    let out: Vec<u8> = (0..2 * SECTOR).map(|i| (i as u8) ^ 0x5a).collect();
    blk.write_blocks(10, &out).unwrap();
    blk.flush().unwrap();
    let mut back = vec![0u8; 2 * SECTOR];
    blk.read_blocks(10, &mut back).unwrap();
    assert_eq!(back, out);

    let disk = blk.transport.disk.borrow();
    assert_eq!(&disk[..10 * SECTOR], &before[..10 * SECTOR], "blocks before");
    assert_eq!(&disk[12 * SECTOR..], &before[12 * SECTOR..], "blocks after");
}

#[test]
fn a_transfer_larger_than_the_bounce_buffer_goes_through_the_block_layer_in_pieces() {
    let mut backing = Backing::new(512 * 1024);
    let blk = started(&mut backing, 128, 3 * SECTOR).unwrap();
    let out: Vec<u8> = (0..10 * SECTOR).map(|i| (i * 13) as u8).collect();
    assert!(
        blk.write_blocks(0, &out).is_err(),
        "the driver itself refuses more than it can bounce"
    );
    block::write(&blk, 20, &out).unwrap();
    let mut back = vec![0u8; 10 * SECTOR];
    block::read(&blk, 20, &mut back).unwrap();
    assert_eq!(back, out);
    assert_eq!(blk.transport.notifies.get(), 8, "four pieces each way");
}

#[test]
fn a_read_past_the_end_is_refused_before_the_device_sees_it() {
    let mut backing = Backing::new(256 * 1024);
    let blk = started(&mut backing, 16, 4 * SECTOR).unwrap();
    let mut buf = vec![0u8; SECTOR];
    assert!(matches!(
        blk.read_blocks(16, &mut buf),
        Err(BlockError::OutOfRange { lba: 16, .. })
    ));
    assert_eq!(blk.transport.notifies.get(), 0, "nothing was submitted");
}

#[test]
fn a_device_error_is_an_error_and_the_queue_recovers() {
    let mut backing = Backing::new(256 * 1024);
    let blk = started(&mut backing, 64, 4 * SECTOR).unwrap();
    blk.transport.fail_io.set(true);
    let mut buf = vec![0u8; SECTOR];
    assert_eq!(
        blk.read_blocks(0, &mut buf),
        Err(BlockError::Device("the device reported an I/O error"))
    );
    blk.transport.fail_io.set(false);
    blk.read_blocks(0, &mut buf)
        .expect("the next request works");
    let (issued, completed, in_flight, clean) = blk.counters();
    assert_eq!((issued, completed, in_flight), (2, 2, 0));
    assert!(clean, "every descriptor came back, and the books balance");
}

#[test]
fn a_device_that_never_answers_times_out_and_leaks_no_request() {
    let mut backing = Backing::new(256 * 1024);
    let blk = started(&mut backing, 64, 4 * SECTOR)
        .unwrap()
        .with_poll_limit(1000);
    blk.transport.silent.set(true);
    let mut buf = vec![0u8; SECTOR];
    assert_eq!(blk.read_blocks(0, &mut buf), Err(BlockError::Timeout));
    let (issued, completed, in_flight, _) = blk.counters();
    assert_eq!((issued, completed, in_flight), (1, 1, 0), "recorded as failed, not lost");
}

#[test]
fn many_requests_leak_no_descriptor() {
    let mut backing = Backing::new(256 * 1024);
    let blk = started(&mut backing, 64, 4 * SECTOR).unwrap();
    let mut buf = vec![0u8; 2 * SECTOR];
    for i in 0..500u64 {
        let lba = i % 60;
        blk.read_blocks(lba, &mut buf).unwrap();
        blk.write_blocks(lba, &buf).unwrap();
    }
    blk.flush().unwrap();
    let (issued, completed, in_flight, clean) = blk.counters();
    assert_eq!((issued, completed, in_flight), (1001, 1001, 0));
    assert!(clean, "a descriptor leak would leave the ring short after a thousand requests");
}

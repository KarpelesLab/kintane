//! The engine against a device on the other side of the rings: the single-threaded path a
//! driver domain takes, and completions the device reports out of order.

use crate::engine::{RequestError, Slot, status_byte};
use crate::queue::{Buf, Ring};
use crate::test_support::{Backing, FakeDevice, FakeTransport, SECTOR};
use crate::transport::{self, Error, status};
use crate::{Engine, F_FLUSH, IN_FLIGHT, QUEUE_SIZE, dma_bytes};

/// A started engine over a fake device of `sectors`, with a bounce buffer of `bounce`.
fn started(backing: &mut Backing, sectors: u64, bounce: usize) -> (Engine, FakeTransport) {
    let dma = backing.take(dma_bytes(bounce), 4096);
    let t = FakeTransport::new(backing, sectors);
    let engine = Engine::bring_up(&t, dma).expect("bring-up");
    (engine, t)
}

#[test]
fn bring_up_walks_the_handshake_and_reads_the_geometry() {
    let mut backing = Backing::new(256 * 1024);
    let (engine, t) = started(&mut backing, 2048, 8 * SECTOR);
    assert_eq!(
        t.status.get(),
        status::ACKNOWLEDGE | status::DRIVER | status::FEATURES_OK | status::DRIVER_OK
    );
    let accepted = t.accepted.get();
    assert_ne!(accepted[1] & transport::VERSION_1_BIT, 0, "VERSION_1 negotiated");
    assert_ne!(accepted[0] & F_FLUSH, 0, "FLUSH taken when offered");
    let f = engine.facts();
    assert_eq!((f.block_size, f.capacity, f.max_transfer), (512, 2048, 8));
    assert!(!f.platform_iommu, "not offered, so not negotiated");
}

#[test]
fn the_platform_iommu_feature_is_accepted_only_when_offered() {
    let mut backing = Backing::new(256 * 1024);
    let dma = backing.take(dma_bytes(SECTOR), 4096);
    let mut t = FakeTransport::new(&backing, 64);
    t.offered[1] |= transport::ACCESS_PLATFORM_BIT;
    let engine = Engine::bring_up(&t, dma).unwrap();
    assert_ne!(t.accepted.get()[1] & transport::ACCESS_PLATFORM_BIT, 0);
    assert!(engine.facts().platform_iommu);
}

#[test]
fn a_device_of_another_type_is_refused() {
    let mut backing = Backing::new(256 * 1024);
    let dma = backing.take(dma_bytes(SECTOR), 4096);
    let mut t = FakeTransport::new(&backing, 64);
    t.device_id = 1;
    assert_eq!(Engine::bring_up(&t, dma).err(), Some(Error::WrongDevice { id: 1 }));
}

#[test]
fn a_polled_read_and_write_round_trip() {
    let mut backing = Backing::new(256 * 1024);
    let (mut engine, t) = started(&mut backing, 64, 4 * SECTOR);
    let mut buf = vec![0u8; 3 * SECTOR];
    engine.read_blocks(&t, 5, &mut buf).unwrap();
    assert_eq!(&buf[..], &t.disk.borrow()[5 * SECTOR..8 * SECTOR]);

    let out: Vec<u8> = (0..2 * SECTOR).map(|i| (i as u8) ^ 0x5a).collect();
    engine.write_blocks(&t, 10, &out).unwrap();
    engine.flush(&t).unwrap();
    let mut back = vec![0u8; 2 * SECTOR];
    engine.read_blocks(&t, 10, &mut back).unwrap();
    assert_eq!(back, out);
    assert!(engine.all_descriptors_free(), "every descriptor came back");
}

#[test]
fn a_polled_request_refuses_what_the_device_cannot_take_before_submitting() {
    let mut backing = Backing::new(256 * 1024);
    let (mut engine, t) = started(&mut backing, 16, 4 * SECTOR);
    let mut one = vec![0u8; SECTOR];
    assert_eq!(engine.read_blocks(&t, 16, &mut one), Err(RequestError::OutOfRange));
    let mut odd = vec![0u8; SECTOR + 1];
    assert_eq!(engine.read_blocks(&t, 0, &mut odd), Err(RequestError::Misaligned));
    assert_eq!(t.notifies.get(), 0, "nothing reached the device");
}

#[test]
fn a_device_error_comes_back_as_its_status_and_the_queue_recovers() {
    let mut backing = Backing::new(256 * 1024);
    let (mut engine, t) = started(&mut backing, 64, 4 * SECTOR);
    t.fail_io.set(true);
    let mut buf = vec![0u8; SECTOR];
    assert_eq!(
        engine.read_blocks(&t, 0, &mut buf),
        Err(RequestError::Device(status_byte::IOERR))
    );
    t.fail_io.set(false);
    engine.read_blocks(&t, 0, &mut buf).unwrap();
    assert!(engine.all_descriptors_free());
}

#[test]
fn a_raw_read_names_the_address_it_was_given() {
    let mut backing = Backing::new(256 * 1024);
    let (mut engine, t) = started(&mut backing, 64, 4 * SECTOR);
    let target = backing.take(SECTOR, 16);
    let slot = engine
        .submit_raw_read(&t, 3, target.phys(), SECTOR as u32)
        .unwrap();
    // The fake device served it on notify, writing wherever the descriptor pointed.
    assert_eq!(engine.wait_polled(slot, None, 10), Ok(()));
    let mut landed = vec![0u8; SECTOR];
    target.read_bytes(0, &mut landed);
    assert_eq!(
        &landed[..],
        &t.disk.borrow()[3 * SECTOR..4 * SECTOR],
        "the device wrote the caller's address, not a slot's bounce buffer"
    );
    assert!(engine.all_descriptors_free());
}

/// An engine over host memory with every slot idle, without a transport.
fn idle(backing: &mut Backing) -> Engine {
    let (d, a, u) = Ring::sizes(QUEUE_SIZE);
    let ring =
        Ring::new(backing.take(d, 16), backing.take(a, 2), backing.take(u, 4), QUEUE_SIZE).unwrap();
    let slots: [Slot; IN_FLIGHT] = core::array::from_fn(|_| Slot {
        header: backing.take(16, 16),
        status: backing.take(1, 1),
        bounce: backing.take(512, 16),
        head: None,
        done: false,
    });
    Engine {
        ring,
        slots,
        facts: crate::Facts {
            block_size: 512,
            capacity: 64,
            max_transfer: 1,
            read_only: false,
            flush_supported: true,
            platform_iommu: false,
        },
    }
}

/// Publish a two-buffer chain through `slot` and return its head descriptor.
fn publish(engine: &mut Engine, slot: usize) -> u16 {
    let s = &engine.slots[slot];
    let chain = [
        Buf {
            phys: s.header.phys(),
            len: 16,
            device_writes: false,
        },
        Buf {
            phys: s.status.phys(),
            len: 1,
            device_writes: true,
        },
    ];
    let head = engine.ring.add(&chain).unwrap();
    engine.slots[slot].head = Some(head);
    head
}

#[test]
fn a_completion_marks_the_request_it_names_not_the_first_one_in_flight() {
    let mut backing = Backing::new(256 * 1024);
    let mut engine = idle(&mut backing);
    let first = publish(&mut engine, 0);
    let second = publish(&mut engine, 1);
    let mut device = FakeDevice::new(&backing, &engine.ring);

    device.complete(second, 1);
    assert_eq!(engine.drain(), 1);
    assert!(engine.slots[1].done, "the completion named the second request");
    assert!(!engine.slots[0].done, "the first request is still outstanding");
    assert_eq!(engine.slots[0].head, Some(first));

    device.complete(first, 1);
    assert_eq!(engine.drain(), 1);
    assert!(engine.slots[0].done);
    assert!(engine.all_descriptors_free(), "both chains came back");
}

#[test]
fn several_completions_at_once_each_reach_their_own_request() {
    let mut backing = Backing::new(256 * 1024);
    let mut engine = idle(&mut backing);
    let heads: Vec<u16> = (0..3).map(|s| publish(&mut engine, s)).collect();
    let mut device = FakeDevice::new(&backing, &engine.ring);
    for &h in heads.iter().rev() {
        device.complete(h, 1);
    }
    assert_eq!(engine.drain(), 3, "one drain collects everything outstanding");
    for (slot, &h) in heads.iter().enumerate() {
        assert!(engine.slots[slot].done, "slot {slot} (head {h}) was completed");
        assert_eq!(engine.slots[slot].head, None);
    }
    assert!(!engine.slots[3].done, "a slot that published nothing is not marked");
}

#[test]
fn a_completion_naming_no_request_marks_nothing() {
    let mut backing = Backing::new(256 * 1024);
    let mut engine = idle(&mut backing);
    let head = publish(&mut engine, 0);
    let mut device = FakeDevice::new(&backing, &engine.ring);
    device.complete_raw(u32::from(QUEUE_SIZE) + 3, 1);
    let _ = engine.drain();
    assert!(engine.slots.iter().all(|s| !s.done), "an invented completion is nobody's");
    assert_eq!(engine.slots[0].head, Some(head), "the real request is still outstanding");
}

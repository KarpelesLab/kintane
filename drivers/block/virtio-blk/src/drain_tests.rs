//! `Inner::drain` against completions the device reports out of order.
//!
//! With several requests outstanding the device finishes them in whatever order it likes,
//! and each used element names the chain it finished. Matching a completion to its request
//! by that head, and never by position, is what keeps one caller from being handed another
//! caller's result — the difference between a concurrent driver and one that merely worked
//! while it had a single request in flight.

use block::Queue as RequestQueue;

use crate::queue::{Buf, Ring};
use crate::test_support::{Backing, FakeDevice};
use crate::{Inner, QUEUE_SIZE, Slot};

/// A driver's state over host memory, with every slot idle.
fn inner(backing: &mut Backing) -> Inner {
    let (d, a, u) = Ring::sizes(QUEUE_SIZE);
    let ring =
        Ring::new(backing.take(d, 16), backing.take(a, 2), backing.take(u, 4), QUEUE_SIZE).unwrap();
    let slots = core::array::from_fn(|_| Slot {
        header: backing.take(16, 16),
        status: backing.take(1, 1),
        bounce: backing.take(512, 16),
        head: None,
        done: false,
    });
    Inner {
        ring,
        slots,
        requests: RequestQueue::new(),
        interrupt_driven: false,
        interrupts: 0,
        interrupt_completions: 0,
        polled_completions: 0,
        peak_in_flight: 0,
    }
}

/// Publish a request through `slot`, as `request` does, and return its head descriptor.
fn publish(inner: &mut Inner, slot: usize) -> u16 {
    let s = &inner.slots[slot];
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
    let head = inner.ring.add(&chain).unwrap();
    inner.slots[slot].head = Some(head);
    head
}

#[test]
fn a_completion_marks_the_request_it_names_not_the_first_one_in_flight() {
    let mut backing = Backing::new(256 * 1024);
    let mut inner = inner(&mut backing);
    let first = publish(&mut inner, 0);
    let second = publish(&mut inner, 1);
    let mut device = FakeDevice::new(&backing, &inner.ring);

    // The device finishes the second request before the first.
    device.complete(second, 1);
    assert_eq!(inner.drain(), 1);
    assert!(inner.slots[1].done, "the completion named the second request");
    assert!(!inner.slots[0].done, "the first request is still outstanding");
    assert_eq!(inner.slots[0].head, Some(first));

    device.complete(first, 1);
    assert_eq!(inner.drain(), 1);
    assert!(inner.slots[0].done);
    assert_eq!(
        inner.ring.free_descriptors(),
        QUEUE_SIZE,
        "both chains' descriptors are back on the free list"
    );
}

#[test]
fn several_completions_at_once_each_reach_their_own_request() {
    let mut backing = Backing::new(256 * 1024);
    let mut inner = inner(&mut backing);
    let heads: Vec<u16> = (0..3).map(|s| publish(&mut inner, s)).collect();
    let mut device = FakeDevice::new(&backing, &inner.ring);

    // All three finish before anyone looks, in reverse.
    for &h in heads.iter().rev() {
        device.complete(h, 1);
    }
    assert_eq!(inner.drain(), 3, "one drain collects everything outstanding");
    for (slot, &h) in heads.iter().enumerate() {
        assert!(inner.slots[slot].done, "slot {slot} (head {h}) was completed");
        assert_eq!(inner.slots[slot].head, None);
    }
    assert!(!inner.slots[3].done, "a slot that published nothing is not marked");
}

#[test]
fn a_completion_naming_no_request_marks_nothing() {
    let mut backing = Backing::new(256 * 1024);
    let mut inner = inner(&mut backing);
    let head = publish(&mut inner, 0);
    let mut device = FakeDevice::new(&backing, &inner.ring);

    // A descriptor id past the queue: a device inventing a completion must not make the
    // driver mark somebody's request done.
    device.complete_raw(u32::from(QUEUE_SIZE) + 3, 1);
    let _ = inner.drain();
    assert!(inner.slots.iter().all(|s| !s.done), "an invented completion is nobody's");
    assert_eq!(inner.slots[0].head, Some(head), "the real request is still outstanding");
}

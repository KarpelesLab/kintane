//! The block layer against a RAM disk, which is the whole point of having the layer be
//! this thin: everything here would otherwise only be testable under QEMU with a real
//! device attached.

use core::cell::{Cell, RefCell};

use super::*;

/// A RAM disk, with a per-request limit small enough that splitting is exercised, and a
/// switch for failing.
struct Ram {
    geometry: Geometry,
    max: u64,
    data: RefCell<Vec<u8>>,
    /// Fail the Nth request and every one after it.
    fail_from: Cell<Option<usize>>,
    requests: Cell<usize>,
    flushes: Cell<usize>,
}

impl Ram {
    fn new(block_size: usize, capacity: u64, max: u64) -> Ram {
        Ram {
            geometry: Geometry::new(block_size, capacity).unwrap(),
            max,
            data: RefCell::new(vec![0u8; (capacity as usize) * block_size]),
            fail_from: Cell::new(None),
            requests: Cell::new(0),
            flushes: Cell::new(0),
        }
    }

    /// Whether this request should fail, counting it either way.
    fn failing(&self) -> bool {
        let n = self.requests.get();
        self.requests.set(n + 1);
        self.fail_from.get().is_some_and(|from| n >= from)
    }

    fn at(&self, lba: u64) -> usize {
        (lba as usize) * self.geometry.block_size
    }
}

impl BlockDevice for Ram {
    fn geometry(&self) -> Geometry {
        self.geometry
    }

    fn max_transfer_blocks(&self) -> u64 {
        self.max
    }

    fn read_blocks(&self, lba: u64, into: &mut [u8]) -> Result<(), Error> {
        let blocks = self.geometry.range(lba, into.len())?;
        assert!(blocks <= self.max, "the layer split beyond the device's limit");
        if self.failing() {
            return Err(Error::Device("injected"));
        }
        let at = self.at(lba);
        into.copy_from_slice(&self.data.borrow()[at..at + into.len()]);
        Ok(())
    }

    fn write_blocks(&self, lba: u64, from: &[u8]) -> Result<(), Error> {
        let blocks = self.geometry.range(lba, from.len())?;
        assert!(blocks <= self.max, "the layer split beyond the device's limit");
        if self.failing() {
            return Err(Error::Device("injected"));
        }
        let at = self.at(lba);
        self.data.borrow_mut()[at..at + from.len()].copy_from_slice(from);
        Ok(())
    }

    fn flush(&self) -> Result<(), Error> {
        if self.failing() {
            return Err(Error::Device("injected"));
        }
        self.flushes.set(self.flushes.get() + 1);
        Ok(())
    }
}

fn pattern(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
        .collect()
}

#[test]
fn a_geometry_a_device_cannot_have_is_refused_at_its_source() {
    assert_eq!(Geometry::new(0, 8), None, "a zero block size");
    assert_eq!(Geometry::new(520, 8), None, "not a power of two");
    assert_eq!(Geometry::new(512, 0), None, "no blocks");
    assert!(Geometry::new(512, 2048).is_some());
    assert_eq!(Geometry::new(512, 2048).unwrap().bytes(), 1024 * 1024);
}

#[test]
fn a_range_is_checked_against_the_device_not_the_buffer() {
    let g = Geometry::new(512, 16).unwrap();
    assert_eq!(g.range(0, 512), Ok(1));
    assert_eq!(g.range(15, 512), Ok(1), "the last block");
    assert_eq!(
        g.range(16, 512),
        Err(Error::OutOfRange {
            lba: 16,
            blocks: 1,
            capacity: 16
        }),
        "one block past the end"
    );
    assert_eq!(
        g.range(15, 1024),
        Err(Error::OutOfRange {
            lba: 15,
            blocks: 2,
            capacity: 16
        }),
        "a transfer that starts inside and ends outside"
    );
    // The arithmetic that a range check exists to survive.
    assert!(matches!(g.range(u64::MAX, 512), Err(Error::OutOfRange { .. })));
    assert_eq!(
        g.range(0, 0),
        Err(Error::Misaligned {
            bytes: 0,
            block_size: 512
        })
    );
    assert_eq!(
        g.range(0, 513),
        Err(Error::Misaligned {
            bytes: 513,
            block_size: 512
        })
    );
}

#[test]
fn a_transfer_larger_than_the_device_takes_is_split_and_covers_the_buffer_exactly() {
    let g = Geometry::new(512, 64).unwrap();
    let mut pieces: Vec<(u64, core::ops::Range<usize>)> = Vec::new();
    for_each_chunk(g, 3, 10, 512 * 8, |lba, range| {
        pieces.push((lba, range));
        Ok(())
    })
    .unwrap();
    assert_eq!(
        pieces,
        vec![
            (10, 0..3 * 512),
            (13, 3 * 512..6 * 512),
            (16, 6 * 512..8 * 512),
        ],
        "three pieces, the last short, starting where the previous ended"
    );

    // Every byte of the buffer is covered exactly once, which is the property a split
    // that is off by one block would break.
    let mut covered = vec![0u8; 512 * 8];
    for (_, range) in pieces {
        for b in &mut covered[range] {
            *b += 1;
        }
    }
    assert!(covered.iter().all(|&n| n == 1));
}

#[test]
fn a_device_that_takes_no_blocks_is_an_error_not_an_endless_loop() {
    let g = Geometry::new(512, 8).unwrap();
    assert_eq!(
        for_each_chunk(g, 0, 0, 512, |_, _| Ok(())),
        Err(Error::Device("the device takes no blocks per request"))
    );
    let ram = Ram::new(512, 8, 0);
    assert!(read(&ram, 0, &mut [0u8; 512]).is_err());
}

#[test]
fn what_was_written_reads_back_across_a_split() {
    let ram = Ram::new(512, 64, 3);
    let out = pattern(512 * 8, 7);
    write(&ram, 10, &out).unwrap();
    let mut back = vec![0u8; 512 * 8];
    read(&ram, 10, &mut back).unwrap();
    assert_eq!(back, out);
    assert_eq!(ram.requests.get(), 6, "three pieces each way");

    // Neighbouring blocks are untouched: a split that wrote to the wrong offset would
    // show up here rather than in the round trip above.
    let mut before = vec![0u8; 512];
    read(&ram, 9, &mut before).unwrap();
    assert!(before.iter().all(|&b| b == 0));
    let mut after = vec![0u8; 512];
    read(&ram, 18, &mut after).unwrap();
    assert!(after.iter().all(|&b| b == 0));
}

#[test]
fn a_failing_device_is_an_error_at_the_piece_that_failed() {
    let ram = Ram::new(512, 64, 2);
    ram.fail_from.set(Some(1));
    let out = pattern(512 * 6, 3);
    assert_eq!(write(&ram, 0, &out), Err(Error::Device("injected")));
    assert_eq!(ram.requests.get(), 2, "stopped at the failing piece");
    assert_eq!(ram.flush(), Err(Error::Device("injected")));
}

#[test]
fn a_ticket_for_a_reused_slot_names_the_old_request() {
    let mut q: Queue<2> = Queue::new();
    let a = q.submit(Op::Read, 0, 1).unwrap();
    q.complete(a, Ok(())).unwrap();
    assert_eq!(q.take(a), Ok(Ok(())));
    let b = q.submit(Op::Write, 99, 1).unwrap();
    assert_eq!(b.slot, a.slot, "the slot was reused");
    assert_ne!(b.serial, a.serial);
    assert_eq!(q.ready(a), Err(Error::Stale), "the old ticket misses");
    assert_eq!(q.take(a), Err(Error::Stale));
    assert_eq!(q.request(b), Ok((Op::Write, 99, 1)));
}

#[test]
fn a_request_in_flight_is_pending_not_successful() {
    let mut q: Queue<4> = Queue::new();
    let t = q.submit(Op::Read, 5, 2).unwrap();
    assert_eq!(q.ready(t), Ok(false));
    assert_eq!(q.take(t), Err(Error::Pending));
    q.complete(t, Err(Error::Timeout)).unwrap();
    assert_eq!(q.ready(t), Ok(true));
    assert_eq!(q.take(t), Ok(Err(Error::Timeout)));
    assert_eq!(q.failed(), 1);
}

#[test]
fn completing_twice_is_refused() {
    let mut q: Queue<2> = Queue::new();
    let t = q.submit(Op::Flush, 0, 0).unwrap();
    q.complete(t, Ok(())).unwrap();
    assert_eq!(q.complete(t, Ok(())), Err(Error::Stale));
    assert_eq!(q.completed(), 1, "the second did not count");
}

#[test]
fn a_full_queue_is_an_error_and_stays_usable() {
    let mut q: Queue<2> = Queue::new();
    let a = q.submit(Op::Read, 0, 1).unwrap();
    let _b = q.submit(Op::Read, 1, 1).unwrap();
    assert_eq!(q.submit(Op::Read, 2, 1), Err(Error::NoRoom));
    assert_eq!(q.in_flight(), 2);
    assert_eq!(q.occupied(), 2);
    q.complete(a, Ok(())).unwrap();
    q.take(a).unwrap().unwrap();
    assert!(q.submit(Op::Read, 2, 1).is_ok(), "room again");
}

#[test]
fn the_books_balance_through_submission_completion_and_draining() {
    let mut q: Queue<4> = Queue::new();
    assert!(q.balanced());
    let a = q.submit(Op::Read, 0, 1).unwrap();
    let _b = q.submit(Op::Write, 1, 1).unwrap();
    assert!(q.balanced(), "two in flight");
    q.complete(a, Ok(())).unwrap();
    assert!(q.balanced(), "completed but not collected");
    assert_eq!((q.in_flight(), q.occupied()), (1, 2), "done with the device, still a slot");
    q.take(a).unwrap().unwrap();
    assert!(q.balanced());
    assert_eq!(q.drain(Error::Device("gone")), 1, "the one still in flight");
    assert!(q.balanced());
    assert_eq!(q.failed(), 1);
    assert_eq!(q.issued(), 2);
}

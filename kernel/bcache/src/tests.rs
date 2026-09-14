//! The cache against a device that counts what it is asked for.
//!
//! What is being tested is not "does a read return the right bytes" — the device below
//! would give those with no cache at all — but the claims the cache makes on top: that a
//! hit does not touch the device, that a write is visible immediately, that a device
//! error leaves no slot holding the wrong bytes, and that its own books balance.

use std::cell::{Cell, RefCell};

use block::{BlockDevice, Error, Geometry};

use crate::{Cache, Slot, Storage};

const BS: usize = 512;

/// A disk in memory that counts requests and can be told to fail one block.
struct MockDisk {
    data: RefCell<Vec<u8>>,
    reads: Cell<u64>,
    writes: Cell<u64>,
    fail_lba: Cell<Option<u64>>,
}

impl MockDisk {
    /// `blocks` blocks, each filled with a byte that is a function of its number, so a
    /// block read from the wrong place is wrong in every byte.
    fn new(blocks: usize) -> MockDisk {
        let mut data = vec![0u8; blocks * BS];
        for (lba, block) in data.chunks_exact_mut(BS).enumerate() {
            for (i, b) in block.iter_mut().enumerate() {
                *b = (lba as u8).wrapping_mul(31).wrapping_add(i as u8);
            }
        }
        MockDisk {
            data: RefCell::new(data),
            reads: Cell::new(0),
            writes: Cell::new(0),
            fail_lba: Cell::new(None),
        }
    }

    fn byte(lba: u64, i: usize) -> u8 {
        (lba as u8).wrapping_mul(31).wrapping_add(i as u8)
    }
}

impl BlockDevice for MockDisk {
    fn geometry(&self) -> Geometry {
        Geometry::new(BS, (self.data.borrow().len() / BS) as u64).unwrap()
    }

    fn max_transfer_blocks(&self) -> u64 {
        8
    }

    fn read_blocks(&self, lba: u64, into: &mut [u8]) -> Result<(), Error> {
        if self.fail_lba.get() == Some(lba) {
            return Err(Error::Device("the mock was told to fail this block"));
        }
        self.geometry().range(lba, into.len())?;
        self.reads
            .set(self.reads.get() + into.len() as u64 / BS as u64);
        let at = lba as usize * BS;
        into.copy_from_slice(&self.data.borrow()[at..at + into.len()]);
        Ok(())
    }

    fn write_blocks(&self, lba: u64, from: &[u8]) -> Result<(), Error> {
        if self.fail_lba.get() == Some(lba) {
            return Err(Error::Device("the mock was told to fail this block"));
        }
        self.geometry().range(lba, from.len())?;
        self.writes
            .set(self.writes.get() + from.len() as u64 / BS as u64);
        let at = lba as usize * BS;
        self.data.borrow_mut()[at..at + from.len()].copy_from_slice(from);
        Ok(())
    }

    fn flush(&self) -> Result<(), Error> {
        Ok(())
    }
}

#[test]
fn a_second_read_of_a_block_does_not_reach_the_device() {
    let disk = MockDisk::new(64);
    let mut storage = Storage::<4, BS>::new();
    let mut cache = storage.cache().unwrap();

    let mut buf = [0u8; 16];
    cache.read_at(&disk, 0, &mut buf).unwrap();
    assert_eq!(buf[0], MockDisk::byte(0, 0));
    assert_eq!(disk.reads.get(), 1);
    // Another byte of the same block, and the whole block again: both from the slot.
    cache.read_at(&disk, 100, &mut buf).unwrap();
    assert_eq!(buf[0], MockDisk::byte(0, 100));
    cache.read_at(&disk, 0, &mut buf).unwrap();
    assert_eq!(disk.reads.get(), 1, "the device was read once");
    assert_eq!(cache.stats().hits, 2);
    assert_eq!(cache.stats().misses, 1);
    cache.check().unwrap();
}

#[test]
fn a_read_across_blocks_is_assembled_from_each() {
    let disk = MockDisk::new(64);
    let mut storage = Storage::<4, BS>::new();
    let mut cache = storage.cache().unwrap();

    // From 8 bytes before a block boundary to 8 bytes after it.
    let mut buf = [0u8; 16];
    cache.read_at(&disk, BS as u64 - 8, &mut buf).unwrap();
    for (i, b) in buf.iter().enumerate() {
        let want = if i < 8 {
            MockDisk::byte(0, BS - 8 + i)
        } else {
            MockDisk::byte(1, i - 8)
        };
        assert_eq!(*b, want, "byte {i}");
    }
    assert_eq!(cache.stats().misses, 2, "one per block");
    cache.check().unwrap();
}

#[test]
fn the_least_recently_used_slot_is_the_one_replaced() {
    let disk = MockDisk::new(64);
    let mut storage = Storage::<2, BS>::new();
    let mut cache = storage.cache().unwrap();
    let mut buf = [0u8; 1];

    cache.read_at(&disk, 0, &mut buf).unwrap(); // block 0
    cache.read_at(&disk, BS as u64, &mut buf).unwrap(); // block 1
    cache.read_at(&disk, 0, &mut buf).unwrap(); // touch 0, so 1 is oldest
    cache.read_at(&disk, 2 * BS as u64, &mut buf).unwrap(); // block 2 replaces 1
    assert_eq!(cache.stats().evictions, 1);

    let before = disk.reads.get();
    cache.read_at(&disk, 0, &mut buf).unwrap();
    assert_eq!(disk.reads.get(), before, "block 0 was kept");
    cache.read_at(&disk, BS as u64, &mut buf).unwrap();
    assert_eq!(disk.reads.get(), before + 1, "block 1 was replaced");
    cache.check().unwrap();
}

#[test]
fn a_write_is_what_the_next_read_sees() {
    let disk = MockDisk::new(64);
    let mut storage = Storage::<4, BS>::new();
    let mut cache = storage.cache().unwrap();

    // Cache block 3 first, so the write has a stale copy to correct.
    let mut buf = [0u8; 4];
    cache.read_at(&disk, 3 * BS as u64, &mut buf).unwrap();
    let block = [0xABu8; BS];
    cache.write_block(&disk, 3, &block).unwrap();
    assert_eq!(disk.writes.get(), 1, "write-through: the device took it");

    let reads = disk.reads.get();
    cache.read_at(&disk, 3 * BS as u64, &mut buf).unwrap();
    assert_eq!(buf, [0xAB; 4], "the cached copy was updated, not left stale");
    assert_eq!(disk.reads.get(), reads, "and it was answered from the slot");
    // And the bytes really reached the device: forget the slot and read again.
    cache.invalidate(3);
    cache.read_at(&disk, 3 * BS as u64, &mut buf).unwrap();
    assert_eq!(buf, [0xAB; 4]);
    assert_eq!(disk.reads.get(), reads + 1, "invalidate forces a device read");
    cache.check().unwrap();
}

#[test]
fn a_write_the_device_refuses_does_not_change_the_cached_copy() {
    let disk = MockDisk::new(64);
    let mut storage = Storage::<4, BS>::new();
    let mut cache = storage.cache().unwrap();
    let mut buf = [0u8; 4];
    cache.read_at(&disk, 5 * BS as u64, &mut buf).unwrap();
    let before = buf;

    disk.fail_lba.set(Some(5));
    let block = [0x77u8; BS];
    assert!(cache.write_block(&disk, 5, &block).is_err());
    disk.fail_lba.set(None);

    cache.read_at(&disk, 5 * BS as u64, &mut buf).unwrap();
    assert_eq!(buf, before, "the refused write left the cache holding the device's bytes");
    cache.check().unwrap();
}

#[test]
fn a_read_the_device_refuses_leaves_no_slot_claiming_that_block() {
    let disk = MockDisk::new(64);
    let mut storage = Storage::<2, BS>::new();
    let mut cache = storage.cache().unwrap();
    let mut buf = [0u8; 4];

    disk.fail_lba.set(Some(9));
    assert!(cache.read_at(&disk, 9 * BS as u64, &mut buf).is_err());
    assert!(
        !cache.slots.iter().any(|s| s.valid && s.lba == 9),
        "a failed read must not leave a slot holding another block's bytes under block 9"
    );
    disk.fail_lba.set(None);
    cache.read_at(&disk, 9 * BS as u64, &mut buf).unwrap();
    assert_eq!(buf[0], MockDisk::byte(9, 0));
}

#[test]
fn misaligned_block_operations_are_refused() {
    let disk = MockDisk::new(64);
    let mut storage = Storage::<2, BS>::new();
    let mut cache = storage.cache().unwrap();

    let mut odd = [0u8; BS + 1];
    assert!(matches!(cache.read_blocks(&disk, 0, &mut odd), Err(Error::Misaligned { .. })));
    assert!(matches!(cache.write_block(&disk, 0, &odd), Err(Error::Misaligned { .. })));
}

#[test]
fn storage_that_does_not_describe_whole_blocks_is_refused() {
    let mut slots = [Slot::EMPTY; 2];
    let mut short = [0u8; BS];
    assert!(Cache::new(&mut slots, &mut short, BS).is_none(), "one block for two slots");
    let mut none: [Slot; 0] = [];
    let mut empty: [u8; 0] = [];
    assert!(Cache::new(&mut none, &mut empty, BS).is_none(), "no slots");
    let mut data = [0u8; 2 * 100];
    assert!(Cache::new(&mut slots, &mut data, 100).is_none(), "not a power of two");
}

#[test]
fn the_books_catch_two_slots_holding_one_block() {
    let disk = MockDisk::new(64);
    let mut storage = Storage::<2, BS>::new();
    let mut cache = storage.cache().unwrap();
    let mut buf = [0u8; 4];
    cache.read_at(&disk, 0, &mut buf).unwrap();
    cache.read_at(&disk, BS as u64, &mut buf).unwrap();
    cache.check().unwrap();

    // What a lookup that failed to find a valid slot would leave behind: one block in two
    // places, one of which will go stale the moment the other is written.
    cache.slots[1].lba = cache.slots[0].lba;
    assert_eq!(cache.check().unwrap_err(), "two slots hold the same block");
}

#[test]
fn every_miss_reads_the_device_exactly_once() {
    let disk = MockDisk::new(64);
    let mut storage = Storage::<4, BS>::new();
    let mut cache = storage.cache().unwrap();
    let mut buf = [0u8; 8];
    for lba in 0..16u64 {
        cache.read_at(&disk, lba * BS as u64, &mut buf).unwrap();
        cache.read_at(&disk, lba * BS as u64 + 8, &mut buf).unwrap();
    }
    let s = cache.stats();
    assert_eq!(s.misses, 16);
    assert_eq!(s.hits, 16);
    assert_eq!(s.device_reads, s.misses);
    assert_eq!(s.evictions, 12, "four slots, sixteen blocks");
    cache.check().unwrap();
}

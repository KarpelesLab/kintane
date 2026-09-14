//! Write-back: the order blocks reach the device, and what memory pressure does to it.
//!
//! What matters here is not that bytes arrive — a write-through cache delivers those — but
//! when and in what order, since that order is what a filesystem's crash consistency is
//! built on. So the device records every block it is given, in order.

use std::cell::RefCell;

use block::{BlockDevice, Error, Geometry};

use crate::Storage;

const BS: usize = 512;

/// A disk in memory that records the order blocks are written to it, and can be told to
/// refuse one.
struct Disk {
    data: RefCell<Vec<u8>>,
    log: RefCell<Vec<u64>>,
    reads: RefCell<u64>,
    fail: RefCell<Option<u64>>,
}

impl Disk {
    fn new(blocks: usize) -> Disk {
        Disk {
            data: RefCell::new((0..blocks * BS).map(|i| (i % 251) as u8).collect()),
            log: RefCell::new(Vec::new()),
            reads: RefCell::new(0),
            fail: RefCell::new(None),
        }
    }

    fn block(&self, lba: usize) -> Vec<u8> {
        self.data.borrow()[lba * BS..(lba + 1) * BS].to_vec()
    }

    fn log(&self) -> Vec<u64> {
        self.log.borrow().clone()
    }
}

impl BlockDevice for Disk {
    fn geometry(&self) -> Geometry {
        Geometry::new(BS, (self.data.borrow().len() / BS) as u64).unwrap()
    }

    fn max_transfer_blocks(&self) -> u64 {
        8
    }

    fn read_blocks(&self, lba: u64, into: &mut [u8]) -> Result<(), Error> {
        self.geometry().range(lba, into.len())?;
        *self.reads.borrow_mut() += 1;
        let at = lba as usize * BS;
        into.copy_from_slice(&self.data.borrow()[at..at + into.len()]);
        Ok(())
    }

    fn write_blocks(&self, lba: u64, from: &[u8]) -> Result<(), Error> {
        if *self.fail.borrow() == Some(lba) {
            return Err(Error::Device("told to refuse this block"));
        }
        self.geometry().range(lba, from.len())?;
        let at = lba as usize * BS;
        self.data.borrow_mut()[at..at + from.len()].copy_from_slice(from);
        self.log.borrow_mut().push(lba);
        Ok(())
    }

    fn flush(&self) -> Result<(), Error> {
        Ok(())
    }
}

fn at(lba: u64) -> u64 {
    lba * BS as u64
}

#[test]
fn a_write_back_is_read_back_before_it_reaches_the_device() {
    let disk = Disk::new(16);
    let before = disk.block(3);
    let mut storage = Storage::<4, BS>::new();
    let mut cache = storage.cache().unwrap();
    cache.write_at(&disk, at(3) + 10, b"abc").unwrap();
    assert!(disk.log().is_empty(), "nothing reaches the device before it has to");
    assert_eq!(cache.dirty(), 1);
    let mut back = [0u8; 5];
    cache.read_at(&disk, at(3) + 9, &mut back).unwrap();
    assert_eq!(back[1..4], *b"abc");
    assert_eq!(back[0], before[9], "the rest of a partly written block is kept");
    cache.sync(&disk).unwrap();
    assert_eq!(disk.log(), vec![3]);
    assert_eq!(cache.dirty(), 0);
    assert_eq!(&disk.block(3)[10..13], b"abc");
    cache.check().unwrap();
}

#[test]
fn a_block_a_write_covers_whole_is_not_read_first() {
    let disk = Disk::new(16);
    let mut storage = Storage::<4, BS>::new();
    let mut cache = storage.cache().unwrap();
    cache.write_at(&disk, at(2), &[7u8; 2 * BS]).unwrap();
    assert_eq!(*disk.reads.borrow(), 0);
    assert_eq!(cache.stats().claims, 2);
    cache.check().unwrap();
}

#[test]
fn dirty_blocks_reach_the_device_in_the_order_barriers_put_them() {
    let disk = Disk::new(16);
    let mut storage = Storage::<8, BS>::new();
    let mut cache = storage.cache().unwrap();
    // Three steps, each dirtying a block whose number runs against the step order.
    cache.write_at(&disk, at(9), b"data").unwrap();
    cache.barrier();
    cache.write_at(&disk, at(5), b"fat1").unwrap();
    cache.barrier();
    cache.write_at(&disk, at(1), b"entry").unwrap();
    cache.sync(&disk).unwrap();
    assert_eq!(disk.log(), vec![9, 5, 1]);
}

#[test]
fn a_block_dirty_from_an_earlier_step_is_written_before_it_changes_again() {
    let disk = Disk::new(16);
    let mut storage = Storage::<8, BS>::new();
    let mut cache = storage.cache().unwrap();
    cache.write_at(&disk, at(4), b"first").unwrap();
    cache.write_at(&disk, at(6), b"also first").unwrap();
    cache.barrier();
    cache.write_at(&disk, at(2), b"second").unwrap();
    cache.barrier();
    // Block 4 again. Its first-step bytes, and the rest of the first step, reach the device
    // before the change: otherwise the change would arrive ahead of block 2.
    cache.write_at(&disk, at(4), b"THIRD").unwrap();
    assert_eq!(disk.log(), vec![4, 6]);
    assert_eq!(&disk.block(4)[..5], b"first");
    cache.sync(&disk).unwrap();
    assert_eq!(disk.log(), vec![4, 6, 2, 4]);
    assert_eq!(&disk.block(4)[..5], b"THIRD");
}

#[test]
fn a_full_cache_of_dirty_blocks_writes_the_oldest_step_out_to_make_room() {
    let disk = Disk::new(64);
    let mut storage = Storage::<3, BS>::new();
    let mut cache = storage.cache().unwrap();
    for (byte, lba) in [(1u8, 10u64), (2, 20), (3, 30)] {
        cache.write_at(&disk, at(lba), &[byte; BS]).unwrap();
        cache.barrier();
    }
    assert_eq!(cache.dirty(), 3);
    // A fourth block needs a slot: the oldest step goes out, and only it.
    cache.write_at(&disk, at(40), &[4u8; BS]).unwrap();
    assert_eq!(disk.log(), vec![10]);
    assert_eq!(cache.stats().pressure_writes, 1);
    // A read of an uncached block under the same pressure does the same.
    let mut buf = [0u8; BS];
    cache.read_blocks(&disk, 7, &mut buf).unwrap();
    assert_eq!(disk.log(), vec![10, 20]);
    cache.sync(&disk).unwrap();
    assert_eq!(disk.log(), vec![10, 20, 30, 40]);
    for (lba, byte) in [(10usize, 1u8), (20, 2), (30, 3), (40, 4)] {
        assert!(disk.block(lba).iter().all(|&b| b == byte));
    }
    cache.check().unwrap();
}

#[test]
fn forgetting_blocks_keeps_the_dirty_ones() {
    let disk = Disk::new(16);
    let mut storage = Storage::<4, BS>::new();
    let mut cache = storage.cache().unwrap();
    cache.write_at(&disk, 1, b"x").unwrap();
    cache.invalidate_all();
    cache.invalidate(0);
    assert_eq!(cache.dirty(), 1);
    let mut b = [0u8; 1];
    cache.read_at(&disk, 1, &mut b).unwrap();
    assert_eq!(b, *b"x", "a forgotten dirty block would read back what the device has");
    cache.check().unwrap();
}

#[test]
fn a_write_through_never_overtakes_a_dirty_block() {
    let disk = Disk::new(16);
    let mut storage = Storage::<4, BS>::new();
    let mut cache = storage.cache().unwrap();
    cache.write_at(&disk, at(8), b"back").unwrap();
    cache.write_block(&disk, 2, &[1u8; BS]).unwrap();
    assert_eq!(disk.log(), vec![8, 2]);
    assert_eq!(cache.dirty(), 0);
}

#[test]
fn a_failed_write_back_leaves_the_block_dirty() {
    let disk = Disk::new(16);
    let mut storage = Storage::<4, BS>::new();
    let mut cache = storage.cache().unwrap();
    cache.write_at(&disk, at(5), b"keep").unwrap();
    *disk.fail.borrow_mut() = Some(5);
    assert!(cache.sync(&disk).is_err());
    assert_eq!(cache.dirty(), 1);
    *disk.fail.borrow_mut() = None;
    cache.sync(&disk).unwrap();
    assert_eq!(cache.dirty(), 0);
    assert_eq!(&disk.block(5)[..4], b"keep");
}

//! Block I/O against the test disk, alongside everything else.
//!
//! One thread writes a random run of sectors inside the disk's scratch area, reads it back
//! and compares, reads a random sector of the untouched part and checks it against the
//! pattern kbuild wrote, and flushes now and then. At a checkpoint it holds nothing: every
//! request it made has completed, so the driver must report nothing in flight and every
//! descriptor back on its ring, which is the leak a descriptor that is freed twice or not
//! at all would show.
//!
//! Present only when the machine has the disk. On one without, the workload is not
//! spawned and the auditor does not ask it for progress; the audit of the driver's books
//! has nothing to look at and passes.

use core::cell::SyncUnsafeCell;
use core::sync::atomic::{AtomicU64, Ordering};

use block::testdisk::{self, SCRATCH_SECTORS, SCRATCH_START, SECTOR};

use super::{Parked, Rng, Workload, after_ms, checkpoint, fail, park_requested, progress};
use crate::preempt::{begin, sleep_until};

/// The longest run of sectors one iteration writes. Larger than the driver's bounce
/// buffer takes in one request on the smallest region it is given, so the block layer's
/// split is exercised under load too.
const MAX_RUN: usize = 32;

/// How many block threads the run has, each with its own buffers and half of the scratch
/// area.
const THREADS: usize = 2;

/// SAFETY INVARIANT: element `i` is touched only by the [`worker`] thread started with
/// argument `i`, and there is one such thread per element.
static WRITE_BUF: [SyncUnsafeCell<[u8; MAX_RUN * SECTOR]>; THREADS] =
    [const { SyncUnsafeCell::new([0; MAX_RUN * SECTOR]) }; THREADS];
/// SAFETY INVARIANT: as [`WRITE_BUF`].
static READ_BUF: [SyncUnsafeCell<[u8; MAX_RUN * SECTOR]>; THREADS] =
    [const { SyncUnsafeCell::new([0; MAX_RUN * SECTOR]) }; THREADS];

/// Requests the workload has made, for the heartbeat.
static REQUESTS: AtomicU64 = AtomicU64::new(0);

/// Whether the machine has the disk this workload uses.
pub fn present() -> bool {
    crate::block::disk().is_some()
}

/// The most requests the disk has had outstanding at once.
pub fn peak_in_flight() -> usize {
    crate::block::disk().map_or(0, |d| d.peak_in_flight())
}

pub fn requests() -> u64 {
    REQUESTS.load(Ordering::Relaxed)
}

/// Ready to run: a started disk with nothing outstanding.
pub fn setup() -> Result<(), &'static str> {
    let Some(disk) = crate::block::disk() else {
        return Ok(());
    };
    let (issued, completed, in_flight, clean) = disk.counters();
    if issued != completed || in_flight != 0 || !clean {
        return Err("the disk has requests outstanding before the run");
    }
    Ok(())
}

/// Nothing in flight and every descriptor free. Called with the thread parked.
pub fn audit() -> Result<(), &'static str> {
    let Some(disk) = crate::block::disk() else {
        return Ok(());
    };
    let (issued, completed, in_flight, clean) = disk.counters();
    if in_flight != 0 || issued != completed {
        return Err("a request is outstanding with the workload parked (a lost completion)");
    }
    if !clean {
        return Err("descriptors are missing from the ring with nothing in flight (a leak)");
    }
    Ok(())
}

/// The byte a written run holds: a function of its tag and position that the disk's own
/// pattern never produces at the same place by more than chance.
fn written(tag: u8, lba: u64, i: usize) -> u8 {
    (i as u8).wrapping_mul(29) ^ tag ^ (lba as u8).rotate_left(3)
}

pub extern "C" fn worker(which: usize) -> ! {
    begin();
    let which = which.min(THREADS - 1);
    let w = if which == 0 {
        Workload::Block
    } else {
        Workload::BlockB
    };
    let mut rng = Rng::new(0x800 + which as u64);
    // This thread's half of the scratch area. The two halves do not overlap, so each
    // thread's read-back sees only its own writes however the requests interleave.
    let half = SCRATCH_SECTORS / THREADS as u64;
    let base = SCRATCH_START + which as u64 * half;
    let Some(disk) = crate::block::disk() else {
        fail(w, "spawned without a disk");
        loop {
            sleep_until(after_ms(1000));
        }
    };
    // SAFETY: this thread is the only one that touches element `which`; see the invariant.
    let (out, back) = unsafe { (&mut *WRITE_BUF[which].get(), &mut *READ_BUF[which].get()) };
    let mut iterations = 0u64;
    loop {
        if park_requested() {
            // Between iterations every request has completed, so there is nothing to
            // hold: the driver's books must show that.
            checkpoint(w, Parked::Empty);
        }

        // A run inside the scratch area, written and read back.
        let run = 1 + rng.below(MAX_RUN as u64) as usize;
        let lba = base + rng.below(half - run as u64 + 1);
        let tag = rng.next() as u8;
        let bytes = run * SECTOR;
        for (i, b) in out[..bytes].iter_mut().enumerate() {
            *b = written(tag, lba, i);
        }
        REQUESTS.fetch_add(1, Ordering::Relaxed);
        if block::write(disk, lba, &out[..bytes]).is_err() {
            fail(w, "a write to the scratch area failed");
        }
        back[..bytes].fill(0);
        REQUESTS.fetch_add(1, Ordering::Relaxed);
        if block::read(disk, lba, &mut back[..bytes]).is_err() {
            fail(w, "a read of the scratch area failed");
        } else if back[..bytes] != out[..bytes] {
            fail(w, "the scratch area did not read back what was written");
        }

        // A sector of the part nothing writes, against the pattern kbuild wrote.
        let sector = 1 + rng.below(SCRATCH_START - 1);
        let piece = &mut back[..SECTOR];
        REQUESTS.fetch_add(1, Ordering::Relaxed);
        match block::read(disk, sector, piece) {
            Ok(()) if testdisk::first_mismatch(sector, piece).is_none() => {}
            Ok(()) => fail(w, "a sector outside the scratch area no longer holds the pattern"),
            Err(_) => fail(w, "a read outside the scratch area failed"),
        }

        iterations += 1;
        if iterations % 8 == 0 {
            REQUESTS.fetch_add(1, Ordering::Relaxed);
            if block::BlockDevice::flush(disk).is_err() {
                fail(w, "a flush failed");
            }
        }
        progress(w);
        sleep_until(after_ms(1));
    }
}

//! Sleeps to random deadlines on the kernel's timer queue.
//!
//! The highest workload, so its timer interrupt switches straight to it. It must never
//! wake before its deadline. It may wake late, because the busy threads below it hold
//! locks with interrupts masked and an emulator delivers interrupts when it can, but
//! not by more than [`MAX_LATE`], which is generous enough to survive a loaded CI host
//! and still far below what a lost wake-up looks like: the auditor's next checkpoint
//! request, a second later, would find this thread never parked.

use core::sync::atomic::{AtomicU64, Ordering};

use time::Duration;

use super::{Parked, Rng, Workload, after_ms, checkpoint, fail, progress};
use crate::preempt::{begin, sleep_until};
use crate::timekeeping;

/// The longest sleep.
const LONGEST_MS: u64 = 50;

/// How late a wake-up may be before the workload asks why.
const MAX_LATE: Duration = Duration::from_nanos(500_000_000);

/// Slices this thread must have been passed over for, while ready, to call a late wake-up
/// the scheduler's doing. It is the most urgent workload, so an interrupt that found it
/// ready and ran something no more urgent is a scheduler that did not reach it; two of them
/// is a pattern rather than one unlucky interrupt.
const LATE_PASSES: u64 = 2;

/// Late wake-ups where the scheduler never passed this thread over: nobody ran on that CPU,
/// which under an emulator means the host was not running it.
static LATE_ELSEWHERE: AtomicU64 = AtomicU64::new(0);

pub fn host_late() -> u64 {
    LATE_ELSEWHERE.load(Ordering::Relaxed)
}

/// The latest any wake-up has been, in nanoseconds.
static WORST_LATE: AtomicU64 = AtomicU64::new(0);

pub fn worst_late() -> Duration {
    Duration::from_nanos(WORST_LATE.load(Ordering::Relaxed))
}

pub extern "C" fn worker(_: usize) -> ! {
    begin();
    let w = Workload::Sleep;
    let mut rng = Rng::new(0x200);
    loop {
        checkpoint(w, Parked::Empty);
        let deadline = after_ms(1 + rng.below(LONGEST_MS));
        let before = super::slices_of(w).map_or(0, |s| s.passed);
        sleep_until(deadline);
        let now = timekeeping::now();
        if now < deadline {
            fail(w, "a sleep woke before its deadline");
        }
        let late = now.saturating_duration_since(deadline);
        WORST_LATE.fetch_max(late.as_nanos(), Ordering::Relaxed);
        if late > MAX_LATE {
            // Lateness is wall time, and under an emulator the guest's clock follows the
            // host's: a vCPU the host stopped running wakes late with nothing wrong here.
            // What is the kernel's own is what it did with the interrupts it took. This is
            // the most urgent workload, so an interrupt that found it ready and ran
            // something no more urgent is the scheduler failing to reach it; a wake-up late
            // with no such interrupt at all is the host, and is counted rather than failed.
            let passed = super::slices_of(w).map_or(0, |s| s.passed.wrapping_sub(before));
            if passed >= LATE_PASSES {
                fail(w, "a sleep woke late after the scheduler passed it over while ready");
            } else {
                LATE_ELSEWHERE.fetch_add(1, Ordering::Relaxed);
            }
        }
        progress(w);
    }
}

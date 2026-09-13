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

/// How late a wake-up may be.
const MAX_LATE: Duration = Duration::from_nanos(500_000_000);

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
        sleep_until(deadline);
        let now = timekeeping::now();
        if now < deadline {
            fail(w, "a sleep woke before its deadline");
        }
        let late = now.saturating_duration_since(deadline);
        WORST_LATE.fetch_max(late.as_nanos(), Ordering::Relaxed);
        if late > MAX_LATE {
            fail(w, "a sleep woke more than half a second after its deadline");
        }
        progress(w);
    }
}

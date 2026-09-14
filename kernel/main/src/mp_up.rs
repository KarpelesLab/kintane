//! The scheduler's multiprocessor seam, for a kernel with one CPU: nothing.
//!
//! One run queue, no scheduler lock, no IPIs, no shootdowns. Interrupts masked on the
//! only CPU are all the exclusion the thread table needs, which is what it had before
//! there was an SMP scheduler, and this module is how a uniprocessor build keeps paying
//! exactly that. `mp_smp.rs` is the other half, selected by `SMP`.

use hal::EarlyConsole;

use crate::Check;

/// Run queues in the thread table.
pub const CPUS: usize = 1;

/// Take the scheduler lock: masked interrupts already are it.
pub fn lock() {}

/// Release the scheduler lock.
///
/// # Safety
/// None needed here; `unsafe` so both halves of the seam have one signature.
pub unsafe fn unlock() {}

/// Ask CPU `cpu` to reschedule. There is no other CPU to ask.
pub fn reschedule(_cpu: usize) -> bool {
    false
}

/// Hand the other CPUs to the scheduler. There are none.
///
/// # Safety
/// None needed here; `unsafe` so both halves of the seam have one signature.
pub unsafe fn release(_entry: fn(usize) -> !) {}

/// The shootdown check: nothing to shoot at.
pub fn check_shootdown<L>(c: &dyn EarlyConsole, _live: L) -> Check {
    c.write_str("skipped: one CPU, so a local flush is the whole shootdown");
    Check::Skipped
}

/// Shootdowns requested, flushes answered, and mismatches: all zero.
#[cfg_attr(
    not(CONFIG_MM_PAGED),
    expect(
        dead_code,
        reason = "read only by the stress run, which needs MM_PAGED"
    )
)]
pub fn shootdown_stats() -> (usize, usize, usize) {
    (0, 0, 0)
}

/// Answer TLB shootdowns while spinning on a lock: on one CPU there are none to answer.
#[cfg_attr(
    not(CONFIG_USERSPACE),
    expect(
        dead_code,
        reason = "used only by the process locks, which need USERSPACE"
    )
)]
pub fn answer_shootdowns() {}

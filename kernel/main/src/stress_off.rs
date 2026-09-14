//! The stress mode's place on a kernel without an MMU: nothing.
//!
//! The stress run pages a kernel `Vm` in and out, which needs translation, so
//! `STRESS_TEST` depends on `MM_PAGED` and a flat kernel never selects it. This keeps
//! the calls `kmain` makes the same on both memory models.

use hal::EarlyConsole;

use crate::{Check, finish};

/// No workload, so no stack beyond the scheduler's own; `preempt`'s compile-time check on
/// `KERNEL_THREAD_SLOTS` reads this from whichever half of the seam is built.
pub const EXTRA_STACKS: usize = 0;

/// No pools to take. `Passed`: there is nothing to have failed.
pub fn reserve<F, M, L>(_c: &dyn EarlyConsole, _frames: F, _map: M, _live: L) -> Check {
    Check::Passed
}

/// No run of frames was taken.
pub fn region() -> (u64, u64) {
    (0, 0)
}

/// Unreachable: the configuration refuses `STRESS_TEST` without `MM_PAGED`.
pub fn run(c: &dyn EarlyConsole) -> ! {
    c.write_str("\nstress mode needs MM_PAGED\n");
    finish(false)
}

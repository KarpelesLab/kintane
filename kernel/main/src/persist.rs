//! The kernel after bring-up: the scheduler owns the CPU for good.
//!
//! Everything `kmain` runs before this point assumes one thread with interrupts masked:
//! the boot checks (which run the scheduler and then stop the timer again), the in-kernel
//! suite, the test modes that end the run from a fault handler, and a deliberate crash.
//! They stay there, rather than becoming threads, because each of them either ends the
//! run or reads the machine in a state no other thread may change underneath it. The
//! in-kernel suite builds its own frame pool over memory the loader reported free, and
//! a stack-guard test has to be the thing that faults, not something a preempting
//! thread did first. So they finish first, and only then does [`run`] hand over.
//!
//! From there boot is one thread among the others the scheduler has, at the priority
//! the boot checks gave it. First it runs the checks that need every CPU scheduling, if the
//! image has any ([`SCHEDULED_CHECKS`]); a test image then reports and stops. What it does with
//! its time after that depends on the image. A stress
//! image runs the stress auditor ([`crate::stress`]), which ends the run itself. Any
//! other image has nothing left to do, so boot sleeps, and says every [`UPTIME_EVERY`]
//! that the kernel is still up. That line is how a boot with no result channel shows it
//! did not just halt.

use hal::EarlyConsole;
use time::Duration;

use crate::{Check, finish, preempt, stress, timekeeping, write_usize};

/// Whether this image has checks that need the scheduler on every CPU. They run here, after
/// [`preempt::resume`], and gate a test image's verdict as the boot checks do.
pub const SCHEDULED_CHECKS: bool = crate::blockdomain::SCHEDULED_CHECK;

/// How often an image with nothing else to do says it is still running.
const UPTIME_EVERY: Duration = Duration::from_nanos(10_000_000_000);

/// Hand the CPU to the scheduler and never come back to `kmain`.
pub fn run(c: &dyn EarlyConsole) -> ! {
    if !preempt::resume() {
        c.write_str("\nno scheduler to hand over to\n");
        finish(false);
    }
    c.write_str("\nscheduler running for good\n");
    if SCHEDULED_CHECKS {
        let scheduled = crate::blockdomain::smp_check(c);
        c.write_str("\n");
        if kconfig::QEMU_EXIT && !kconfig::STRESS_TEST {
            finish(scheduled != Check::Failed);
        }
        if scheduled == Check::Failed {
            c.write_str("a check with every CPU scheduled failed; not starting the stress run\n");
            finish(false);
        }
    }
    if kconfig::STRESS_TEST {
        stress::run(c)
    }
    let start = timekeeping::now();
    let mut next = start;
    loop {
        next = next.saturating_add(UPTIME_EVERY);
        preempt::sleep_until(next);
        c.write_str("uptime ");
        write_usize(
            c,
            (timekeeping::now()
                .saturating_duration_since(start)
                .as_nanos()
                / 1_000_000_000) as usize,
        );
        c.write_str(" s\n");
    }
}

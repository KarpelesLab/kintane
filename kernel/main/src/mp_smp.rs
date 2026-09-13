//! The scheduler's multiprocessor seam, for a kernel with `SMP`: one run queue per CPU,
//! the scheduler lock that spans a context switch, reschedule IPIs, and TLB shootdown.
//!
//! Everything here reaches the architecture through `hal::HasIpi`, so a second SMP port
//! plugs in by implementing that trait, and nothing in this file changes.

use arch::Cpu;
use hal::{EarlyConsole, HasIpi, HasSmp, Ipi};
use sync::SpinLock;
use sync::lockdep::LockClass;

use crate::Check;

/// Run queues in the thread table: the configuration's CPU limit, or the port's if lower.
pub const CPUS: usize = {
    let port = <Cpu as HasSmp>::MAX_CPUS;
    if kconfig::NR_CPUS < port {
        kconfig::NR_CPUS
    } else {
        port
    }
};

static CLASS: LockClass = LockClass::new("sched.table");

/// The scheduler lock. See `preempt`'s module docs: it is held across a context switch,
/// so it has no guard and holds no data.
static LOCK: SpinLock<(), Cpu> = SpinLock::with_class((), &CLASS);

/// Take the scheduler lock. Interrupts must already be masked: the timer interrupt takes
/// it too.
pub fn lock() {
    LOCK.lock_handoff();
}

/// Release the scheduler lock.
///
/// # Safety
/// Held, on this CPU, by the thread calling or by the thread whose switch resumed it.
pub unsafe fn unlock() {
    // SAFETY: forwarded; the caller's contract is `unlock_handoff`'s.
    unsafe { LOCK.unlock_handoff() };
}

/// Ask CPU `cpu` to reschedule. `false` if it cannot be reached.
pub fn reschedule(cpu: usize) -> bool {
    Cpu::send_ipi(cpu, Ipi::Reschedule)
}

/// Hand every online secondary to the scheduler, each entering `entry`, with shootdowns
/// on so that no mapping change can go stale on a CPU a thread may migrate to.
///
/// # Safety
/// Once, from the boot CPU, with the scheduler built.
pub unsafe fn release(entry: fn(usize) -> !) {
    crate::shootdown::install();
    // SAFETY: forwarded; the caller's contract is `release_secondaries`'.
    unsafe { Cpu::release_secondaries(entry) };
}

/// The shootdown check, on the boot path with the secondaries up. See `shootdown`.
pub fn check_shootdown(c: &dyn EarlyConsole, live: crate::Live) -> Check {
    crate::shootdown::check(c, live)
}

/// Shootdowns requested, flushes answered, and mismatches found, since boot.
pub fn shootdown_stats() -> (usize, usize, usize) {
    crate::shootdown::stats()
}

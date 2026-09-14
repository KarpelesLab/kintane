//! The Linux personality, configured out (ABI_LINUX off, or no userspace).
//!
//! The loader refuses a program with no KinTane ABI note instead of tagging it `linux`, so
//! no process ever calls through [`syscalls`] and no teardown reaches [`release`]. They
//! exist so `userproc` names one table, one release and one set of hooks in every
//! configuration.

use hal::EarlyConsole;

use crate::Check;

/// No Linux personality: a program with no KinTane note is refused at load.
#[cfg_attr(
    not(CONFIG_USERSPACE),
    expect(dead_code, reason = "only userspace tags programs")
)]
pub(crate) const ENABLED: bool = false;

/// Never installed: nothing is tagged `linux` without the personality.
#[cfg_attr(
    not(CONFIG_USERSPACE),
    expect(dead_code, reason = "only userspace has system call tables")
)]
pub(crate) fn syscalls<F>(_slot: usize, _: &mut F) {}

/// Never reached: no process is a Linux one.
#[cfg_attr(
    not(CONFIG_USERSPACE),
    expect(dead_code, reason = "only userspace tears processes down")
)]
pub(crate) fn release(_slot: usize) {}

/// No Linux queues to wake.
#[cfg_attr(
    not(CONFIG_USERSPACE),
    expect(dead_code, reason = "only userspace ends processes")
)]
pub(crate) fn wake_all_waiters() {}

/// No Linux process to report: a trap kills a native process, recorded as `userproc::KILLED`,
/// all ones.
#[cfg_attr(
    not(CONFIG_USERSPACE),
    expect(dead_code, reason = "only userspace traps processes")
)]
pub(crate) fn killed_by<P>(_personality: P) -> u64 {
    u64::MAX
}

/// No Linux parent to tell.
#[cfg_attr(
    not(CONFIG_USERSPACE),
    expect(dead_code, reason = "only userspace ends processes")
)]
pub(crate) fn process_ended(_slot: usize, _code: u64) {}

/// Nothing to check. `Passed`, and silent, so the banner of a kernel without the
/// personality is unchanged.
pub fn check<F, L>(_c: &dyn EarlyConsole, _frames: F, _live: L) -> Check {
    Check::Passed
}

/// Nothing to check with the scheduler either, and just as silent.
#[cfg_attr(
    not(CONFIG_USERSPACE),
    expect(dead_code, reason = "only userspace runs the scheduled checks")
)]
pub fn scheduled_check(_c: &dyn EarlyConsole) -> Check {
    Check::Passed
}

/// No Linux processes for the stress run to start.
#[cfg_attr(
    not(CONFIG_USERSPACE),
    expect(
        dead_code,
        reason = "only userspace drives processes in the stress run"
    )
)]
pub fn stress_cycle(_round: u64) -> Result<(), &'static str> {
    Ok(())
}

#[cfg_attr(
    not(CONFIG_USERSPACE),
    expect(
        dead_code,
        reason = "only userspace drives processes in the stress run"
    )
)]
pub fn stress_cycles() -> u64 {
    0
}

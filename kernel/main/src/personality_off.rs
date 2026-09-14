//! The Linux personality, configured out (ABI_LINUX off, or no userspace).
//!
//! The loader refuses a program with no KinTane ABI note instead of tagging it `linux`, so
//! no process ever calls through [`syscalls`] and no teardown reaches [`release`]. They
//! exist so `userproc` names one table and one release in every configuration.

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
pub(crate) fn syscalls<P, F>(_: &mut P, _: &mut F) {}

/// Never reached: no process is a Linux one.
#[cfg_attr(
    not(CONFIG_USERSPACE),
    expect(dead_code, reason = "only userspace tears processes down")
)]
pub(crate) fn release(_slot: usize) {}

/// Nothing to check. `Passed`, and silent, so the banner of a kernel without the
/// personality is unchanged.
pub fn check<F, L>(_c: &dyn EarlyConsole, _frames: F, _live: L) -> Check {
    Check::Passed
}

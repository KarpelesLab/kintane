//! The stall point's place in a kernel that does not want one.
//!
//! Without `WAIT_RACE_TEST` there is no stall and no check: [`stall`] is an empty inline
//! function, so the wait path carries neither a branch nor a symbol for it, and [`check`]
//! passes without a word. See `waitrace.rs` for what the other build does and why.

use hal::EarlyConsole;

use crate::Check;

/// No window to park in.
///
/// Dead on a kernel without userspace: nothing there blocks on a wait queue, so `wait_once`
/// is never reached and neither is this. Expected rather than allowed, so a port that starts
/// waiting fails the build instead of quietly carrying an unused function.
#[cfg_attr(
    not(CONFIG_USERSPACE),
    expect(
        dead_code,
        reason = "only WaitQueue::wait_once calls this, and nothing waits without USERSPACE"
    )
)]
#[inline(always)]
pub fn stall() {}

/// Nothing to check: the hook this check needs is not in this kernel.
pub fn check(c: &dyn EarlyConsole) -> Check {
    let _ = c;
    Check::Passed
}

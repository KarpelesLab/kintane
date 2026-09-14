//! The stall point's place in a kernel that does not want one.
//!
//! Without `WAIT_RACE_TEST` there is no stall and no check: [`stall`] is an empty inline
//! function, so the wait path carries neither a branch nor a symbol for it, and [`check`]
//! passes without a word. See `waitrace.rs` for what the other build does and why.

use hal::EarlyConsole;

use crate::Check;

/// No window to park in.
#[inline(always)]
pub fn stall() {}

/// Nothing to check: the hook this check needs is not in this kernel.
pub fn check(c: &dyn EarlyConsole) -> Check {
    let _ = c;
    Check::Passed
}

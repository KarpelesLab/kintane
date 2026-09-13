//! The no-op `selftest` provider.
//!
//! Selected in every build without `INKERNEL_TESTS`, so a production image does not
//! merely skip the tests — it does not contain them.

#![cfg_attr(not(test), no_std)]

use hal::{Arch, EarlyConsole};

/// Whether this build contains in-kernel tests.
pub const PRESENT: bool = false;

/// Runs nothing and reports success, so the caller needs no special case.
pub fn run_all<A: Arch>(_c: &dyn EarlyConsole, _boot_arg: u64, _reserved: &[(u64, u64)]) -> bool {
    true
}

//! The PCIe check's place on a build without one.
//!
//! Only aarch64 with `PCIE` looks for a host bridge; everywhere else there is none to find
//! and nothing to report, so the check is skipped rather than passed. A skip says "not asked
//! for"; a pass would say "asked for and found", which on these builds is untrue.
//!
//! The signature mirrors `pcie.rs`, the two being chosen by `#[cfg]` in `main.rs`: one
//! drifting from the other breaks exactly the builds that take this one and no others.

use hal::EarlyConsole;

use crate::Check;

/// No bridge was asked for, so nothing was discovered.
pub fn check(_c: &dyn EarlyConsole) -> Check {
    Check::Skipped
}

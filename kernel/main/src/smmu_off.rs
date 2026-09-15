//! The SMMUv3 check's place on a build without one.
//!
//! Only aarch64 with `SMMUV3` looks for an Arm SMMUv3; everywhere else there is no unit to
//! find and nothing to report, so the check is skipped rather than passed. A skip says "not
//! asked for"; a pass would say "asked for and found", which on these builds is untrue.
//!
//! The signature mirrors `smmu.rs`, the two being chosen by `#[cfg]` in `main.rs`: one
//! drifting from the other breaks exactly the builds that take this one and no others.

use hal::EarlyConsole;

use crate::Check;

/// No SMMU was asked for, so nothing was discovered.
pub fn check(_c: &dyn EarlyConsole) -> Check {
    Check::Skipped
}

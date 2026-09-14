//! The driver-isolation check's place where there is no isolation to run.
//!
//! A domain is an address space with one device window in it, so the prototype needs an
//! MMU, a userspace port and a machine with a memory-mapped device to grant. Where any of
//! those is missing the calls still exist and do nothing, so `kmain` reads the same on
//! every port. See `docs/isolation.md` for what the PCs are waiting for.

use hal::EarlyConsole;

use crate::Check;

/// Guarded stack slots this check claims, for `preempt`'s build-time count: none.
pub const STACKS: usize = 0;

/// Nothing to isolate. `Skipped`: no claim was checked, which is not the same as one that
/// held.
pub fn check(c: &dyn EarlyConsole) -> Check {
    c.write_str("skipped: no driver domain on this configuration");
    Check::Skipped
}

//! The block-domain check's place where there is no driver domain to serve the disk.
//!
//! Serving the disk from an isolated domain needs an IOMMU to confine its DMA, a userspace
//! port, and the block device itself, which only `BLOCK_DOMAIN` (x86_64 behind VT-d) has. The
//! calls still exist and do nothing, so `kmain` and the disk's interrupt handler read the same
//! on every port. See `docs/isolation.md`.

use hal::EarlyConsole;

use crate::Check;

/// Guarded stack slots this check claims, for `preempt`'s build-time count: none.
pub const STACKS: usize = 0;

/// No domain owns the disk's interrupt here, so the handler never forwards it.
pub fn forward_interrupt() -> bool {
    false
}

/// Nothing to serve from a domain. `Skipped`: no claim was checked, which is not the same as
/// one that held.
pub fn check(c: &dyn EarlyConsole) -> Check {
    c.write_str("skipped: no block driver domain on this configuration");
    Check::Skipped
}

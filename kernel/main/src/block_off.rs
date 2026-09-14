//! The block check's place on a kernel without an MMU: nothing.
//!
//! The driver's DMA region is mapped through the kernel's direct map, which a flat kernel
//! does not build, so `QEMU_BLOCK_TEST` depends on `MM_PAGED`. This keeps the call
//! `kmain` makes the same on both memory models.

use hal::EarlyConsole;

use crate::Check;

/// Skipped: there is no device to check on this memory model.
pub fn check<F, L>(c: &dyn EarlyConsole, _frames: F, _live: L) -> Check {
    c.write_str("\n  block      skipped: needs MM_PAGED");
    Check::Skipped
}

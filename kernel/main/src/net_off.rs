//! The network check's place on a kernel without an MMU: nothing.
//!
//! The driver's DMA region is mapped through the kernel's direct map, which a flat kernel
//! does not build, so `QEMU_NET_TEST` depends on `MM_PAGED`. This keeps the calls `kmain`
//! makes the same on both memory models.

use hal::EarlyConsole;

use crate::Check;

/// Skipped: there is no card to bring up on this memory model.
pub fn bring_up<F, L>(c: &dyn EarlyConsole, _frames: F, _live: L) -> Check {
    c.write_str("\n  nic        skipped: needs MM_PAGED");
    Check::Skipped
}

/// Skipped: no card, so nothing to exchange frames through.
pub fn check(c: &dyn EarlyConsole) -> Check {
    c.write_str("skipped: needs MM_PAGED");
    Check::Skipped
}

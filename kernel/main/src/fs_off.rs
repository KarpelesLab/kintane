//! The filesystem check's place on a kernel without an MMU: nothing.
//!
//! The volume sits on the test disk, which only the block check brings up, and that needs
//! the kernel's direct map (see `block_off.rs`). This keeps the call `kmain` makes the
//! same on both memory models.

use hal::EarlyConsole;

use crate::Check;

/// Skipped: there is no disk to mount a volume from on this memory model.
pub fn check<F, L>(c: &dyn EarlyConsole, _frames: F, _live: L) -> Check {
    c.write_str("\n  fs         skipped: needs MM_PAGED");
    Check::Skipped
}

//! What this port contributes to kernel memory layout — which, with no MMU, is almost
//! nothing.
//!
//! There is no kernel address space to build. Physical addresses are the only addresses,
//! every device is reachable the moment the kernel starts, and nothing can be unmapped.
//! Two consequences worth stating plainly:
//!
//! * **[`device_windows`] is empty.** It exists so `kernel/platform/none` has one signature on
//!   every port; nothing maps these windows here, because nothing maps anything.
//! * **Thread stacks have no guard.** [`claim_thread_stack`] hands out the same slot layout the MMU
//!   ports use, and the bottom page of each slot is still left unused, but nothing faults when a
//!   thread writes into it. An overflow corrupts the stack of the thread below. Physical Memory
//!   Protection could turn those pages into faults — M-mode can lock PMP entries against itself —
//!   and is the stretch this port has not reached. The stack-guard test modes depend on `MM_PAGED`
//!   in the configuration for exactly this reason.

use core::sync::atomic::{AtomicUsize, Ordering};

use hal::KernAddr;
use hal::paging::DeviceWindow;

/// Device memory to map once the kernel's own tables are live: none, since there are none.
pub fn device_windows() -> &'static [DeviceWindow] {
    &[]
}

/// Slots handed out so far. A stack is never given back.
static CLAIMED: AtomicUsize = AtomicUsize::new(0);

/// A kernel thread stack from the image's thread-stack array.
///
/// Returns `(slot, top, size)`, or `None` once every slot is taken. `_owner` names the
/// thread on the MMU ports, whose guard-page reports print it; there is no such report
/// here, because the page below the stack is **not** protected (see the module doc).
pub fn claim_thread_stack(_owner: &'static str) -> Option<(usize, KernAddr, usize)> {
    let t = crate::image_sections().thread_stacks;
    let slot = CLAIMED
        .try_update(Ordering::SeqCst, Ordering::SeqCst, |n| (n < t.count()).then_some(n + 1))
        .ok()?;
    let (bottom, top) = t.stack_range(slot)?;
    Some((slot, KernAddr::new(top as usize), (top - bottom) as usize))
}

//! Page faults the kernel can resolve: decoding a #PF and handing it to the kernel.
//!
//! `arch` may not depend on `mm` (layering), so the kernel registers a
//! [`PageFaultHook`] and the #PF handler asks it before reporting the fault as fatal.
//! This file decodes the error code into neutral terms and nothing more. Deciding
//! whether an address is demand-paged belongs to the kernel.
//!
//! The same decoding as x86-64 at half the width. Only faults the kernel could mean are
//! offered to the hook: not one from ring 3, and not a reserved-bit violation, which means
//! a malformed table.

use core::sync::atomic::{AtomicPtr, Ordering};

use hal::fault::{Access, PageFault, PageFaultHook};

/// The registered hook, as a type-erased function pointer. Null means none.
static HOOK: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

/// #PF error code: the fault came from user mode.
const USER: u32 = 1 << 2;
/// #PF error code: a reserved bit was set in a paging-structure entry.
const RESERVED: u32 = 1 << 3;
/// #PF error code: the access was a store.
const WRITE: u32 = 1 << 1;
/// #PF error code: the access was an instruction fetch. Only reported with NX enabled,
/// which QEMU's default 32-bit CPU does not have.
const FETCH: u32 = 1 << 4;

/// Register the function page faults are offered to, or remove it with `None`.
///
/// Also loads the IDT if nothing has yet. On this port nothing does until the interrupt
/// selftest, and a hook registered before then would be reached by a #PF that has no gate
/// to arrive through: a triple fault and a silent reset. `interrupt::init` is idempotent
/// and leaves every line masked.
pub fn set_page_fault_hook(hook: Option<PageFaultHook>) {
    crate::interrupt::init();
    let raw = match hook {
        Some(f) => f as *mut (),
        None => core::ptr::null_mut(),
    };
    HOOK.store(raw, Ordering::Release);
}

/// Offer the #PF with this CR2 and error code to the hook. `true` means it was resolved
/// and the faulting instruction should be retried.
pub(crate) fn route(cr2: u32, code: u32) -> bool {
    let raw = HOOK.load(Ordering::Acquire);
    if raw.is_null() || code & (USER | RESERVED) != 0 {
        return false;
    }
    // SAFETY: `HOOK` holds null, excluded above, or a `PageFaultHook` stored by
    // `set_page_fault_hook`. Function and data pointers have the same size and
    // representation on this target, so the cast back is the identity.
    let hook = unsafe { core::mem::transmute::<*mut (), PageFaultHook>(raw) };
    let access = if code & FETCH != 0 {
        Access::Execute
    } else if code & WRITE != 0 {
        Access::Write
    } else {
        Access::Read
    };
    #[allow(clippy::as_conversions)]
    let addr = cr2 as usize;
    hook(PageFault { addr, access })
}

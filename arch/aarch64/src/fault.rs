//! Page faults the kernel can resolve: decoding an abort and handing it to the kernel.
//!
//! `arch` may not depend on `mm` (layering), so the kernel registers a
//! [`PageFaultHook`] and the synchronous exception path asks it before reporting an
//! abort as fatal. This file decodes the syndrome into neutral terms and nothing more.
//!
//! Offered to the hook: data and instruction aborts taken **from EL1**, whose fault
//! status says *translation fault* or *permission fault*, at any level. Everything else
//! is left to the reporter:
//!
//! * An access flag fault: every leaf this kernel writes has AF set, so one means a table written
//!   by something else.
//! * An alignment, external, or TLB-conflict abort: none of those is a question about what the
//!   tables should say.
//! * An abort whose FAR is not valid (`FnV`): there is no address to resolve.
//!
//! Reference: Arm ARM D17.2.40 (`ESR_EL1`), the ISS encodings for EC 0x21 and 0x25.

use core::sync::atomic::{AtomicPtr, Ordering};

use hal::fault::{Access, PageFault, PageFaultHook};

/// The registered hook, as a type-erased function pointer. Null means none.
static HOOK: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

/// Exception class: instruction abort taken without a change in exception level.
const EC_INSTRUCTION_ABORT_SAME_EL: u64 = 0x21;
/// Exception class: data abort taken without a change in exception level.
const EC_DATA_ABORT_SAME_EL: u64 = 0x25;
/// ISS bit: for a data abort, the access was a write (`WnR`).
const ISS_WNR: u64 = 1 << 6;
/// ISS bit: FAR is not valid (`FnV`).
const ISS_FNV: u64 = 1 << 10;

/// Register the function page faults are offered to, or remove it with `None`.
///
/// The vector table is installed before the MMU is enabled, so unlike on i686 there is
/// nothing to install here.
pub fn set_page_fault_hook(hook: Option<PageFaultHook>) {
    let raw = match hook {
        Some(f) => f as *mut (),
        None => core::ptr::null_mut(),
    };
    HOOK.store(raw, Ordering::Release);
}

/// Offer a synchronous exception with this ESR and FAR to the hook. `true` means it was
/// resolved and the faulting instruction should be retried.
pub(crate) fn route(esr: u64, far: u64) -> bool {
    let raw = HOOK.load(Ordering::Acquire);
    if raw.is_null() {
        return false;
    }
    let access = match (esr >> 26) & 0x3f {
        EC_DATA_ABORT_SAME_EL if esr & ISS_WNR != 0 => Access::Write,
        EC_DATA_ABORT_SAME_EL => Access::Read,
        EC_INSTRUCTION_ABORT_SAME_EL => Access::Execute,
        _ => return false,
    };
    // Translation fault, levels 0-3, or permission fault, levels 0-3.
    let resolvable = matches!(esr & 0x3f, 0x04..=0x07 | 0x0c..=0x0f);
    if !resolvable || esr & ISS_FNV != 0 {
        return false;
    }
    // SAFETY: `HOOK` holds null, excluded above, or a `PageFaultHook` stored by
    // `set_page_fault_hook`. Function and data pointers have the same size and
    // representation on this target, so the cast back is the identity.
    let hook = unsafe { core::mem::transmute::<*mut (), PageFaultHook>(raw) };
    #[allow(clippy::as_conversions)]
    let addr = far as usize;
    hook(PageFault { addr, access })
}

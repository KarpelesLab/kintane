//! Page faults, in architecture-neutral terms.
//!
//! An architecture decodes its own syndrome — CR2 and the #PF error code on x86, FAR
//! and ESR on AArch64 — into a [`PageFault`], and hands it to whatever the kernel
//! registered. `arch` cannot call into `mm` (layering), so the kernel registers a
//! [`PageFaultHook`] and the exception path calls it before deciding a fault is fatal.

/// What the faulting instruction was trying to do.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Access {
    /// A load from the address.
    Read,
    /// A store to the address.
    Write,
    /// An instruction fetch from the address.
    Execute,
}

/// One page fault, as the architecture reports it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PageFault {
    /// The address that faulted, not rounded to a page.
    pub addr: usize,
    /// What the access was.
    pub access: Access,
}

/// The kernel's answer to a page fault: `true` when it has changed the tables so the
/// faulting instruction will succeed if re-executed, `false` when the fault is not one
/// it can resolve and the exception path should report it as fatal.
///
/// Called with interrupts masked, on the stack the fault was taken on. It must not
/// fault itself, and it must not return `true` without having changed something (or
/// flushed a stale translation), because returning re-executes the instruction.
pub type PageFaultHook = fn(PageFault) -> bool;

//! The context switch contract.
//!
//! A context switch is where the scheduler's policy meets the architecture's calling
//! convention, and it is the one place a kernel cannot be written generically: which
//! registers survive a call is a fact about the ABI, not a choice. So, as with paging,
//! the split is drawn where the difference actually is. The architecture supplies the
//! **mechanism** — what a suspended thread's state looks like, how to start a fresh one,
//! and how to swap between two. Everything above it — which thread runs next, when,
//! and for how long — is policy, written once, and testable on the host.
//!
//! # Why a switch is a function call
//!
//! `switch` is called like an ordinary function and returns like one, just into a
//! different thread. That shape is load-bearing: because the caller has made a call, it
//! has already assumed every **caller-saved** register is clobbered, so the switch need
//! only preserve the **callee-saved** ones. That is a much smaller set, and it is exactly
//! the set each port must name. Getting it wrong is silent until a thread resumes with
//! a register some other thread was using.
//!
//! The consequences differ by architecture, and each port records its own:
//!
//! * **x86-64 SysV**: rbx, rbp, r12–r15 and the stack pointer. No vector registers are
//!   callee-saved.
//! * **i386 SysV**: ebx, esi, edi, ebp and the stack pointer. The XMM registers are all
//!   caller-saved — which matters here, because the i686 kernel has SSE enabled and LLVM emits
//!   vector instructions in ordinary code (see `docs/targets.md#i686`). Because they are
//!   caller-saved they need no saving across a switch.
//! * **AArch64 AAPCS64**: x19–x29, the link register, the stack pointer — **and the low 64 bits of
//!   d8–d15**, which *are* callee-saved. A port that saves only the general registers is correct
//!   exactly as long as nothing in the kernel touches the vector registers, and then silently
//!   corrupts them.
//!
//! # Interrupts
//!
//! A switch is performed with interrupts masked. An interrupt taken halfway through
//! would run on a stack that belongs to neither thread. Masking is the caller's job,
//! because the caller is the scheduler and it has to hold its own state consistent
//! across the switch anyway.

use crate::{Arch, KernAddr};

/// The entry point of a new kernel thread.
///
/// Diverging on purpose. A thread that returns has nowhere to return *to* — the frame
/// above its entry point was fabricated by [`HasContextSwitch::init`], not pushed by a
/// caller — so returning is a jump to garbage. Exiting is an explicit call into the
/// scheduler.
pub type ThreadEntry = extern "C" fn(arg: usize) -> !;

/// An architecture that can suspend a thread and resume another.
pub trait HasContextSwitch: Arch {
    /// The saved state of a suspended thread.
    ///
    /// Opaque to everything above the architecture. `Default` gives an empty context,
    /// which is what the thread that is *currently running* saves into on its first
    /// switch away — there is no need to construct the boot thread's state by hand,
    /// because switching away from it fills it in.
    type Context: Default;

    /// Bytes a stack must provide below its top for [`init`](Self::init) to lay down
    /// the first frame. A stack smaller than this cannot start a thread.
    const MIN_STACK: usize;

    /// Required stack alignment, in bytes, at the point a function is entered.
    ///
    /// Stated rather than assumed because it is not uniform and getting it wrong is
    /// deferred: 16 on x86-64 and AArch64, and a misaligned stack works until the first
    /// function that uses an aligned vector instruction, which on i686 is LLVM's own
    /// output rather than anything the author wrote.
    const STACK_ALIGN: usize;

    /// Prepare `ctx` so that switching to it begins executing `entry(arg)` on a stack
    /// whose highest address is `stack_top`.
    ///
    /// # Safety
    /// `stack_top` must be the top of a region of at least [`Self::MIN_STACK`] bytes that
    /// is mapped, writable, owned exclusively by this thread, and not in use. The region
    /// must stay valid for as long as the thread can run.
    unsafe fn init(ctx: &mut Self::Context, stack_top: KernAddr, entry: ThreadEntry, arg: usize);

    /// Save the running thread's state into `from` and resume the thread in `to`.
    ///
    /// Returns when something later switches back to `from`.
    ///
    /// # Safety
    /// Interrupts must be masked. `from` must be writable and must not alias `to`.
    /// `to` must hold a context previously filled in by [`init`](Self::init) or by an
    /// earlier `switch`, whose stack is still valid and which is not running on any
    /// CPU. Violating any of these resumes execution at an arbitrary address.
    unsafe fn switch(from: *mut Self::Context, to: *const Self::Context);
}

/// Where a stack pointer must start for an architecture, given the top of a region.
///
/// Rounded *down*, because a stack grows downward and rounding up would place the
/// first frame past the end of the region. Free function for the same reason as
/// `paging::level_size`: it is the same arithmetic everywhere, and three ports each
/// writing it is three chances to round the wrong way.
pub fn aligned_stack_top<A: HasContextSwitch>(top: KernAddr) -> KernAddr {
    top.align_down(A::STACK_ALIGN)
}

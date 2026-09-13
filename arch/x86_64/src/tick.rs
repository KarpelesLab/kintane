//! The scheduler tick: the PIT as a periodic interrupt, and the one hook it calls.
//!
//! `arch` may not depend on the scheduler (layering), so the scheduler registers a plain
//! `fn()` and the timer interrupt calls it. The hook runs in interrupt context with
//! interrupts masked, and it is allowed to switch threads. That is sound only because of
//! three facts, which hold here and which anyone changing this path has to keep:
//!
//! * **The hook runs after the EOI.** A switch can leave the interrupted thread suspended for any
//!   length of time, and the 8259A delivers nothing at or below an in-service line until that line
//!   is acknowledged. A hook called before the EOI would give the next thread exactly one tick: its
//!   first, and last.
//! * **The timer gate uses no IST.** Each thread's interrupt frame, the CPU's frame plus whatever
//!   the `x86-interrupt` prologue saved, sits on that thread's own stack, so a thread that switches
//!   away takes its frame with it. On an IST stack the next interrupt would reuse the same stack
//!   while the first frame was still in use.
//! * **Gates are interrupt gates**, so IF is clear for the whole handler and nothing nests inside
//!   it. The `iretq` that ends a preempted thread's handler restores its IF from the frame. A
//!   thread resumed through a voluntary switch restores its own saved state. A fresh thread starts
//!   with IF clear, and enabling interrupts is its first act.

use core::sync::atomic::{AtomicPtr, Ordering};

use crate::{interrupt, pit};

/// The registered hook, as a type-erased `fn()`. Null means none.
static HOOK: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

/// Register the function the timer interrupt calls after acknowledging each tick, or
/// remove it with `None`.
pub fn set_hook(hook: Option<fn()>) {
    let raw = match hook {
        Some(f) => f as *mut (),
        None => core::ptr::null_mut(),
    };
    HOOK.store(raw, Ordering::Release);
}

/// Call the registered hook, if there is one. Called from the timer IRQ, after EOI.
pub(crate) fn run_hook() {
    let raw = HOOK.load(Ordering::Acquire);
    if raw.is_null() {
        return;
    }
    // SAFETY: `HOOK` is written only by `set_hook`, which stores either null, excluded
    // above, or a `fn()` cast to a data pointer. Function and data pointers have the
    // same size and representation on this target, so the cast back is the identity.
    let hook = unsafe { core::mem::transmute::<*mut (), fn()>(raw) };
    hook();
}

/// Start the timer at approximately `hz` and unmask its line. Returns the rate
/// actually programmed, which the divisor's rounding makes approximate.
///
/// # Safety
/// Interrupts must be masked, and no one else may be programming the PIT. The hook can
/// run as soon as the caller enables interrupts.
pub unsafe fn start(hz: u32) -> u32 {
    interrupt::init();
    // SAFETY: forwarded; the caller guarantees nothing else is programming the PIT.
    let divisor = unsafe { pit::start_periodic(hz) };
    interrupt::irq_chip().enable(interrupt::TIMER_IRQ);
    // A divisor of 0 means 65536 to the chip.
    let effective = if divisor == 0 {
        65_536
    } else {
        u32::from(divisor)
    };
    pit::INPUT_HZ / effective
}

/// Mask the timer line. Ticks already pending are not delivered.
pub fn stop() {
    interrupt::irq_chip().disable(interrupt::TIMER_IRQ);
}

/// Timer interrupts taken since boot.
pub fn ticks() -> u64 {
    interrupt::TICKS.load(Ordering::Relaxed)
}

/// Enable interrupts.
///
/// # Safety
/// The IDT must be loaded and every unmasked line must have a handler, which
/// [`interrupt::init`] guarantees. The caller must not be inside a masked region whose
/// state it has to restore.
pub unsafe fn enable_interrupts() {
    // SAFETY: the caller's contract.
    unsafe { core::arch::asm!("sti", options(nomem, nostack, preserves_flags)) };
}

/// Halt until an interrupt has been taken, and return with interrupts enabled.
///
/// Called with interrupts **masked**, so that checking for work and halting cannot be
/// separated by the interrupt that brings the work. `sti` enables interrupts only after
/// the instruction that follows it, so `sti; hlt` enters the halt before anything can be
/// delivered, and the interrupt that ends the halt is the one taken.
///
/// # Safety
/// As [`enable_interrupts`].
pub unsafe fn wait_for_interrupt() {
    // SAFETY: the caller's contract; see above for why the pair is atomic.
    unsafe { core::arch::asm!("sti", "hlt", options(nomem, nostack, preserves_flags)) };
}

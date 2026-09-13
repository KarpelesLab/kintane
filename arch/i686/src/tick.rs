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
//! * **The frame lives on the interrupted thread's stack.** The timer gate is a ring-0 interrupt
//!   gate, not a task gate, so the CPU pushes its frame on the current stack. The `x86-interrupt`
//!   prologue saves every register it and its callees can clobber there too, the SSE registers
//!   included, since this kernel runs with SSE on. A thread that switches away takes that frame
//!   with it.
//! * **Gates are interrupt gates**, so IF is clear for the whole handler and nothing nests inside
//!   it. The `iretd` that ends a preempted thread's handler restores its IF from the frame. A
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

/// Start the timer as a one-shot and unmask its line, without arming it. Returns the
/// longest delay one arming can cover, in nanoseconds: 54.9 ms, all the 8254's 16-bit
/// counter holds.
///
/// That limit is why the PIT is an interim one-shot timer. An idle period longer than
/// it takes one interrupt per 54.9 ms rather than one in total. The local APIC timer
/// has a 32-bit count and a divider and removes the limit. It comes with the APIC
/// driver, which also owns the interrupt path this port still routes through the 8259A.
///
/// # Safety
/// As [`start`].
pub unsafe fn start_oneshot() -> u64 {
    interrupt::init();
    interrupt::irq_chip().enable(interrupt::TIMER_IRQ);
    count_to_ns(pit::MAX_COUNT)
}

/// Raise one timer interrupt `ns` nanoseconds from now, replacing any deadline already
/// armed. Delays beyond what [`start_oneshot`] returned are cut to it, and the caller
/// re-arms from the interrupt. Rounded up to the counter's 838 ns resolution, so the
/// interrupt is never early.
///
/// # Safety
/// Interrupts must be masked, and no one else may be programming the PIT.
pub unsafe fn arm_ns(ns: u64) {
    // Clamped before multiplying: 55 ms times 1.19 MHz is far inside a u64, and the
    // clamp keeps an absurd `ns` from overflowing.
    let ns = ns.min(count_to_ns(pit::MAX_COUNT));
    let count = (ns * u64::from(pit::INPUT_HZ)).div_ceil(1_000_000_000);
    // SAFETY: forwarded; the caller's contract.
    unsafe { pit::start_oneshot(count as u32) };
}

/// The delay `count` input cycles make, in nanoseconds, rounded down.
fn count_to_ns(count: u32) -> u64 {
    u64::from(count) * 1_000_000_000 / u64::from(pit::INPUT_HZ)
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

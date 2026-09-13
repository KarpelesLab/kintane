//! The scheduler's timer: APB timer 0 as a one-shot interrupt, and the one hook it calls.
//!
//! `arch` may not depend on the scheduler, so the scheduler registers a plain `fn()`.
//! Every other port calls it from the timer's handler. This one cannot, and
//! `preempt.rs` says why and what it does instead: the timer's handler acknowledges the
//! interrupt, counts it and pends PendSV, and PendSV arranges for the hook to run in
//! thread mode, where a thread switch is an ordinary function call.

use core::sync::atomic::{AtomicBool, AtomicPtr, Ordering};

use crate::counter::Counter;
use crate::{Armv7m, scs, timer};

/// The registered hook, as a type-erased `fn()`. Null means none.
static HOOK: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

/// Set by the timer's handler when a hook is registered, and cleared just before the hook
/// runs. PendSV reads it to tell a tick that needs the hook from a pend that only resumes
/// a thread; see `preempt.rs`.
#[unsafe(no_mangle)]
pub(crate) static ARMV7M_HOOK_DUE: AtomicBool = AtomicBool::new(false);

/// Timer interrupts taken since boot.
pub static TIMER_TICKS: Counter = Counter::new();

/// The longest delay one arming is asked to cover: a minute, well inside the 32-bit
/// counter's 171 s at 25 MHz.
const MAX_ONESHOT_NS: u64 = 60 * 1_000_000_000;

/// Register the function the timer interrupt runs in thread mode after acknowledging
/// itself, or remove it with `None`.
pub fn set_hook(hook: Option<fn()>) {
    let raw = match hook {
        Some(f) => f as *mut (),
        None => core::ptr::null_mut(),
    };
    HOOK.store(raw, Ordering::Release);
}

/// Call the registered hook, if there is one. Called from `preempt.rs`'s trampoline, in
/// thread mode with interrupts masked.
pub(crate) fn run_hook() {
    let raw = HOOK.load(Ordering::Acquire);
    if raw.is_null() {
        return;
    }
    // SAFETY: `HOOK` is written only by `set_hook`, which stores null, excluded above, or
    // a `fn()` cast to a data pointer. The two have the same representation here.
    let hook = unsafe { core::mem::transmute::<*mut (), fn()>(raw) };
    hook();
}

/// APB timer 0's interrupt.
#[unsafe(no_mangle)]
extern "C" fn armv7m_timer0() {
    // SAFETY: the timer's own handler.
    unsafe { timer::disarm() };
    TIMER_TICKS.increment();
    if !HOOK.load(Ordering::Acquire).is_null() {
        ARMV7M_HOOK_DUE.store(true, Ordering::Release);
        // SAFETY: ICSR.PENDSVSET is write-one-to-set; nothing else in the write acts.
        unsafe { scs::write(scs::ICSR, scs::ICSR_PENDSVSET) };
    }
}

/// Enable the timer interrupt as a one-shot, without arming it. Returns the longest
/// delay one arming covers, in nanoseconds.
///
/// # Safety
/// Interrupts must be masked. The hook can run once the caller unmasks them and a
/// deadline is armed.
pub unsafe fn start_oneshot() -> u64 {
    // SAFETY: masked, per the contract.
    unsafe { timer::disarm() };
    timer::set_enabled(true);
    MAX_ONESHOT_NS
}

/// Raise one timer interrupt `ns` nanoseconds from now, replacing any deadline already
/// armed. Rounded up to a whole count, so never early.
///
/// # Safety
/// Interrupts must be masked.
pub unsafe fn arm_ns(ns: u64) {
    // SAFETY: masked, per the contract.
    unsafe { timer::arm(timer::ticks_for(ns.min(MAX_ONESHOT_NS))) };
}

/// Stop the timer and disable its interrupt.
pub fn stop() {
    timer::set_enabled(false);
    let irq = <Armv7m as hal::Arch>::irq_save();
    // SAFETY: masked.
    unsafe { timer::disarm() };
    // SAFETY: pairs with the `irq_save` above.
    unsafe { <Armv7m as hal::Arch>::irq_restore(irq) };
}

/// Timer interrupts taken since boot.
pub fn ticks() -> u64 {
    TIMER_TICKS.get()
}

/// Unmask interrupts.
///
/// # Safety
/// The vector table must be installed and every enabled source must have a handler. The
/// caller must not be inside a masked region whose state it has to restore.
pub unsafe fn enable_interrupts() {
    // SAFETY: the caller's contract. Not `nomem`: a handler may run.
    unsafe { core::arch::asm!("cpsie i", options(nostack)) };
}

/// Wait until an interrupt has been taken, and return with interrupts unmasked.
///
/// Called with interrupts **masked**, so checking for work and waiting cannot be
/// separated by the interrupt that brings the work. `wfi` returns when an interrupt is
/// pending that would preempt were `PRIMASK` clear, so one that arrives in the gap is
/// not lost: `wfi` returns at once and unmasking takes it.
///
/// # Safety
/// As [`enable_interrupts`].
pub unsafe fn wait_for_interrupt() {
    // SAFETY: the caller's contract; see above for why nothing is lost between the two.
    unsafe { core::arch::asm!("wfi", "cpsie i", options(nostack)) };
}

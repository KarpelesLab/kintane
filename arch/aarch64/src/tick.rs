//! The scheduler tick: the generic timer as a periodic interrupt, and the one hook it
//! calls.
//!
//! `arch` may not depend on the scheduler (layering), so the scheduler registers a plain
//! `fn()` and the timer interrupt calls it. The hook runs in interrupt context with IRQs
//! masked, and it is allowed to switch threads. That is sound only because of three
//! facts, which hold here and which anyone changing this path has to keep:
//!
//! * **The hook runs after every claimed interrupt has had its EOI.** On a GIC, EOI drops the
//!   running priority. A thread suspended before the EOI would leave the CPU running at the timer's
//!   priority, and the next thread would never receive a tick.
//! * **The whole trap frame lives on the interrupted thread's stack**: `x0`–`x30`, and `ELR_EL1`
//!   and `SPSR_EL1` too (see `exception`). Those two are banked per exception level, not per
//!   thread. The next thread's own IRQ overwrites them, so the frame, not the register, has to
//!   carry them across a switch.
//! * **IRQs stay masked for the whole handler**, because exception entry sets `DAIF` and nothing
//!   here clears it, so nothing nests. The `eret` that ends a preempted thread's handler restores
//!   that thread's mask from its saved `SPSR`. A thread resumed through a voluntary switch restores
//!   its own saved `DAIF`. A fresh thread starts masked, and enabling IRQs is its first act.
//!
//! The generic timer is one-shot, so "periodic" means re-arming it from the interrupt.
//! Each period is measured from the moment the handler runs, not from the previous
//! deadline, so the tick drifts late by the handler latency. That suits a scheduler
//! tick and would not suit a clock.

use core::sync::atomic::{AtomicPtr, AtomicU32, Ordering};

use hal::IrqNumber;

use crate::{irq, timer};

/// The registered hook, as a type-erased `fn()`. Null means none.
static HOOK: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

/// Counter ticks between timer interrupts while the tick runs; zero when it does not,
/// which tells the handler to stop the timer instead of re-arming it.
static PERIOD: AtomicU32 = AtomicU32::new(0);

/// Register the function the timer interrupt calls after acknowledging each tick, or
/// remove it with `None`.
pub fn set_hook(hook: Option<fn()>) {
    let raw = match hook {
        Some(f) => f as *mut (),
        None => core::ptr::null_mut(),
    };
    HOOK.store(raw, Ordering::Release);
}

/// Call the registered hook, if there is one. Called from the IRQ path, after EOI.
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

/// The re-arm period, or zero if the tick is not running.
pub(crate) fn period() -> u32 {
    PERIOD.load(Ordering::Acquire)
}

/// Start the timer at approximately `hz` and enable its interrupt. Returns the rate
/// programmed, or 0 if there is no interrupt controller or no counter frequency to
/// program it from.
///
/// # Safety
/// IRQs must be masked. The hook can run as soon as the caller unmasks them.
pub unsafe fn start(hz: u32) -> u32 {
    let Some(chip) = irq::chip() else { return 0 };
    let freq = timer::frequency();
    let period = match freq.checked_div(u64::from(hz)).map(u32::try_from) {
        Some(Ok(p)) if p > 0 => p,
        _ => return 0,
    };
    PERIOD.store(period, Ordering::Release);
    chip.enable(IrqNumber(timer::PPI));
    timer::arm(period);
    (freq / u64::from(period)) as u32
}

/// Stop the timer and disable its interrupt.
pub fn stop() {
    PERIOD.store(0, Ordering::Release);
    timer::stop();
    if let Some(chip) = irq::chip() {
        chip.disable(IrqNumber(timer::PPI));
    }
}

/// Timer interrupts taken since boot.
pub fn ticks() -> u64 {
    irq::timer_ticks()
}

/// Unmask IRQs.
///
/// # Safety
/// The vector table must be installed and every enabled source must have a handler. The
/// caller must not be inside a masked region whose state it has to restore.
pub unsafe fn enable_interrupts() {
    // SAFETY: the caller's contract.
    unsafe { core::arch::asm!("msr daifclr, #2", options(nomem, nostack, preserves_flags)) };
}

/// Wait until an interrupt has been taken, and return with IRQs unmasked.
///
/// Called with IRQs **masked**, so that checking for work and waiting cannot be separated
/// by the interrupt that brings the work. `wfi` wakes on a pending physical IRQ whether
/// or not `PSTATE.I` masks it. So the interrupt that arrives in the gap is not lost: `wfi`
/// returns at once, and unmasking takes it.
///
/// # Safety
/// As [`enable_interrupts`].
pub unsafe fn wait_for_interrupt() {
    // SAFETY: the caller's contract; see above for why nothing is lost between the two.
    unsafe {
        core::arch::asm!("wfi", "msr daifclr, #2", options(nomem, nostack, preserves_flags));
    }
}

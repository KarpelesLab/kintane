//! The scheduler's timer: the CLINT's `mtimecmp` as a one-shot interrupt, and the one
//! hook it calls.
//!
//! `arch` may not depend on the scheduler, so the scheduler registers a plain `fn()`
//! and the timer interrupt calls it, in trap context with interrupts masked. The hook
//! may switch threads. That is sound for the reasons `trap` states, which anyone
//! changing this path has to keep:
//!
//! * **The interrupt is deasserted before the hook runs.** `mtimecmp` is moved to the end of time
//!   first, so a thread switched to does not immediately take the same interrupt again.
//! * **`mepc` and `mstatus` travel in the trap frame on the interrupted thread's stack**, so
//!   another thread's trap cannot overwrite what this one returns through.
//! * **Traps do not nest**: entry clears `mstatus.MIE` and nothing in the handler sets it. A new
//!   thread starts with it clear too, since switches happen masked, and enabling interrupts is its
//!   first act.
//!
//! One-shot is the CLINT's only shape. `mtimecmp` is 64 bits of ticks, so one arming
//! reaches further than anything will ask; [`start_oneshot`] reports an hour, so a
//! miscomputed delay cannot arm a deadline past the lifetime of the machine.

use core::sync::atomic::{AtomicPtr, Ordering};

use crate::{clint, trap};

/// The registered hook, as a type-erased `fn()`. Null means none.
static HOOK: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

/// `mie.MTIE`: machine timer interrupts enabled.
const MTIE: usize = 1 << 7;

/// The longest delay one arming is asked to cover, in nanoseconds.
const MAX_ONESHOT_NS: u64 = 3600 * 1_000_000_000;

/// Register the function the timer interrupt calls after deasserting itself, or remove
/// it with `None`.
pub fn set_hook(hook: Option<fn()>) {
    let raw = match hook {
        Some(f) => f as *mut (),
        None => core::ptr::null_mut(),
    };
    HOOK.store(raw, Ordering::Release);
}

/// Call the registered hook, if there is one. Called from the trap path.
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

/// Enable the timer interrupt as a one-shot, without arming it. Returns the longest
/// delay one arming covers, in nanoseconds.
///
/// # Safety
/// Interrupts must be masked. The hook can run once the caller unmasks them and a
/// deadline is armed.
pub unsafe fn start_oneshot() -> u64 {
    // SAFETY: masked, per the contract.
    unsafe { clint::disarm() };
    set_mie(true);
    MAX_ONESHOT_NS
}

/// Raise one timer interrupt `ns` nanoseconds from now, replacing any deadline already
/// armed. Rounded up to a whole tick, so never early.
///
/// # Safety
/// Interrupts must be masked; `mtimecmp` is written in halves.
pub unsafe fn arm_ns(ns: u64) {
    const NS: u64 = 1_000_000_000;
    let ns = ns.min(MAX_ONESHOT_NS);
    let freq = clint::FREQUENCY;
    // Whole seconds and the remainder apart: `(ns % NS) * freq` is below 10^16, and no
    // 128-bit division, which `compiler_builtins` does not provide, is emitted.
    let ticks = (ns / NS)
        .saturating_mul(freq)
        .saturating_add(((ns % NS) * freq).div_ceil(NS))
        .max(1);
    // SAFETY: masked, per the contract.
    unsafe { clint::set_deadline(clint::now().saturating_add(ticks)) };
}

/// Stop the timer and disable its interrupt.
pub fn stop() {
    set_mie(false);
    let irq = <crate::Riscv32 as hal::Arch>::irq_save();
    // SAFETY: masked for the two writes.
    unsafe { clint::disarm() };
    // SAFETY: pairs with the `irq_save` above.
    unsafe { <crate::Riscv32 as hal::Arch>::irq_restore(irq) };
}

/// Timer interrupts taken since boot.
pub fn ticks() -> u64 {
    trap::TIMER_TICKS.get()
}

/// Unmask interrupts.
///
/// # Safety
/// `mtvec` must be installed and every enabled source must have a handler. The caller
/// must not be inside a masked region whose state it has to restore.
pub unsafe fn enable_interrupts() {
    // SAFETY: the caller's contract. Not `nomem`: a handler may run; see `irq_restore`.
    unsafe { core::arch::asm!("csrsi mstatus, 0x8", options(nostack)) };
}

/// Wait until an interrupt has been taken, and return with interrupts unmasked.
///
/// Called with interrupts **masked**, so checking for work and waiting cannot be
/// separated by the interrupt that brings the work. `wfi` returns when an interrupt
/// enabled in `mie` is pending, whatever `mstatus.MIE` says, so one that arrives in the
/// gap is not lost: `wfi` returns at once and unmasking takes it.
///
/// # Safety
/// As [`enable_interrupts`].
pub unsafe fn wait_for_interrupt() {
    // SAFETY: the caller's contract; see above for why nothing is lost between the two.
    // Not `nomem`: the handler runs; see `irq_restore`.
    unsafe { core::arch::asm!("wfi", "csrsi mstatus, 0x8", options(nostack)) };
}

/// Set or clear `mie.MTIE`.
pub(crate) fn set_mie(on: bool) {
    // SAFETY: `mie` is writable in M-mode; only the timer bit is touched.
    unsafe {
        if on {
            core::arch::asm!("csrs mie, {}", in(reg) MTIE, options(nomem, nostack));
        } else {
            core::arch::asm!("csrc mie, {}", in(reg) MTIE, options(nomem, nostack));
        }
    }
}

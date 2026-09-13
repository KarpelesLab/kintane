//! The scheduler tick: the timer interrupt, and the one hook it calls.
//!
//! Two timers can drive it. The local APIC timer, once discovery has installed one with
//! [`set_event_timer`], is the one-shot timer a tickless kernel wants: 32 bits of count and a
//! divider, reaching over a minute under QEMU. Until then, and on a machine without one, the
//! PIT does, with its 55 ms reach. The periodic tick ([`start`]) stays on the PIT, which is
//! what the interrupt and clock checks measure.
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

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicPtr, Ordering};

use hal::EventTimer;

use crate::{interrupt, pit};

/// Write-once storage for the event timer discovery installed.
struct TimerSlot(UnsafeCell<Option<&'static dyn EventTimer>>);

// SAFETY: written at most once, by `set_event_timer`, during single-threaded boot with
// interrupts masked and before any secondary CPU exists; read-only afterwards.
unsafe impl Sync for TimerSlot {}

static TIMER: TimerSlot = TimerSlot(UnsafeCell::new(None));

/// Install `timer` as the one-shot tick source, in place of the PIT.
///
/// Its interrupt must arrive on [`interrupt::TIMER_VECTOR`], which is where the local APIC
/// driver is told to deliver it.
///
/// # Safety
/// At most once, during single-threaded boot with interrupts masked, before the tick is
/// started and before any secondary CPU is.
pub unsafe fn set_event_timer(timer: &'static dyn EventTimer) {
    // SAFETY: the caller's contract is the `TimerSlot` invariant.
    unsafe { *TIMER.0.get() = Some(timer) };
}

/// The installed event timer, if discovery found one that can reach anywhere.
pub fn event_timer() -> Option<&'static dyn EventTimer> {
    // SAFETY: by the `TimerSlot` invariant the only write happened before any reader.
    unsafe { *TIMER.0.get() }.filter(|t| t.reach_ns() > 0)
}

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

/// Start the timer as a one-shot, without arming it. Returns the longest delay one arming
/// can cover, in nanoseconds.
///
/// With a local APIC timer installed that is its reach, and IRQ 0 is masked so the PIT
/// cannot tick alongside it. Without one it is the PIT's 54.9 ms, all its 16-bit counter
/// holds, and an idle period longer than that takes one interrupt per 54.9 ms rather than
/// one in total.
///
/// # Safety
/// As [`start`].
pub unsafe fn start_oneshot() -> u64 {
    interrupt::init();
    if let Some(timer) = event_timer() {
        interrupt::irq_chip().disable(interrupt::TIMER_IRQ);
        timer.stop();
        return timer.reach_ns();
    }
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
    if let Some(timer) = event_timer() {
        // SAFETY: forwarded; the caller's contract, on the boot CPU whose local APIC the
        // driver prepared at installation.
        unsafe { timer.arm_ns(ns) };
        return;
    }
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

/// Stop the tick: mask the PIT's line, and stop the event timer if there is one. Ticks
/// already pending are not delivered.
pub fn stop() {
    interrupt::irq_chip().disable(interrupt::TIMER_IRQ);
    if let Some(timer) = event_timer() {
        timer.stop();
    }
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

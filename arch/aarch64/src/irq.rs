//! The interrupt dispatch path: from the IRQ vector, through whichever controller was
//! found at boot, to whoever owns the line.
//!
//! Two things live here. The first is the slot holding the selected controller, which
//! is where the seam in `docs/portability.md` becomes concrete — the type is
//! `&'static dyn IrqChip`, chosen at run time, and [`dispatch`] calls through the
//! vtable without knowing or caring which driver answered.
//!
//! The second is the handler table, which in Phase 0 has exactly one entry: the timer.
//! A real registry keyed by IRQ number belongs to the device framework, not to `arch`,
//! and arrives with it in Phase 3.
//!
//! # Concurrency
//!
//! There is none. The build is uniprocessor, the controller is installed once with
//! interrupts masked, and nothing ever replaces it. The tick counter is an atomic
//! anyway, because it is written by an interrupt handler and read by the code that was
//! interrupted, and the compiler must not be allowed to conclude the read is loop-
//! invariant.

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU64, Ordering};

use hal::{IrqChip, IrqNumber};

/// Write-once storage for the interrupt controller this machine turned out to have.
///
/// A plain `static` cannot hold it — the value is not known until boot — and
/// `static mut` is forbidden by `docs/coding-standards.md`. An `UnsafeCell` with a
/// stated invariant is what the standards point at instead. It cannot be an
/// `AtomicPtr` either: `&dyn IrqChip` is a fat pointer and does not fit in one.
struct ChipSlot(UnsafeCell<Option<&'static dyn IrqChip>>);

// SAFETY: the invariant is that `ChipSlot` is written exactly once, by `set_chip`,
// before any interrupt is enabled and therefore before any reader can exist, and is
// read-only for the rest of the machine's life. Both references it can hold are to
// `static` drivers that are `Sync` themselves. When SMP arrives the write still happens
// before the secondaries are released, so the property survives; if that ever stops
// being true this becomes a `OnceLock` and the comment becomes wrong first.
unsafe impl Sync for ChipSlot {}

static CHIP: ChipSlot = ChipSlot(UnsafeCell::new(None));

/// Number of timer interrupts observed. The selftest's evidence that a handler ran.
static TIMER_TICKS: AtomicU64 = AtomicU64::new(0);

/// Install the interrupt controller for this machine.
///
/// # Safety
/// Must be called at most once, with interrupts masked, before any interrupt source is
/// enabled. `chip` must already have been initialised.
pub unsafe fn set_chip(chip: &'static dyn IrqChip) {
    // SAFETY: the caller guarantees this is the only write and that no reader exists
    // yet, because no interrupt can be delivered with the masks set and nothing else
    // calls `chip()` before the selftest does.
    unsafe { *CHIP.0.get() = Some(chip) };
}

/// The interrupt controller in use, once one has been selected.
pub fn chip() -> Option<&'static dyn IrqChip> {
    // SAFETY: by the invariant on `ChipSlot` the write happened before any reader
    // could run, so this read cannot race with it and the value is stable thereafter.
    unsafe { *CHIP.0.get() }
}

/// How many timer interrupts have been taken since boot.
pub fn timer_ticks() -> u64 {
    TIMER_TICKS.load(Ordering::Acquire)
}

/// Service every interrupt the controller is currently offering.
///
/// Called from the IRQ vector with interrupts masked — the CPU masks them on entry and
/// this code does not unmask, so no interrupt nests inside another. That is a
/// deliberate Phase 0 simplification: prioritised, preemptible interrupt handling needs
/// a per-CPU stack and a running-priority discipline that do not exist yet.
pub(crate) fn dispatch() {
    let Some(chip) = chip() else {
        // An IRQ was delivered with no controller installed, which means something
        // enabled a source behind this module's back. There is nothing to acknowledge
        // it with; returning leaves it asserted and the machine will livelock, which is
        // at least a visible failure rather than a silent one.
        return;
    };

    // Bounded rather than `while let`: a source that is never quieted by its handler
    // would otherwise spin here forever with interrupts masked, which is
    // indistinguishable from a hang. Anything still pending is taken on the next entry.
    for _ in 0..MAX_PER_ENTRY {
        let Some(irq) = chip.claim() else { return };
        handle(irq);
        chip.eoi(irq);
    }
}

/// Interrupts serviced in one trip through the vector before giving the interrupted
/// code a chance to run again.
const MAX_PER_ENTRY: u32 = 16;

fn handle(irq: IrqNumber) {
    if irq.0 == crate::timer::PPI {
        // The timer's condition is level-sensitive: without this the line stays
        // asserted, EOI re-delivers immediately, and the machine never leaves the
        // handler. Re-arming rather than stopping is what a real tick does; Phase 0
        // wants exactly one.
        crate::timer::stop();
        TIMER_TICKS.fetch_add(1, Ordering::Release);
        return;
    }

    // No handler. It has already been claimed, so it will be acknowledged by the
    // caller and will not be redelivered; a source nobody owns should not have been
    // enabled, and in Phase 0 nothing can enable one.
}

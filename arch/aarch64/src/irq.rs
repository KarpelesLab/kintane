//! The interrupt dispatch path: from the IRQ vector, through whichever controller was
//! found at boot, to whoever owns the line.
//!
//! Two things live here. The first is the slot holding the selected controller, which
//! is where the seam in `docs/portability.md` becomes concrete — the type is
//! `&'static dyn IrqChip`, chosen at run time by the device tree, installed by
//! `kernel/platform/fdt`, and [`dispatch`] calls through the vtable without knowing or
//! caring which driver answered.
//!
//! The second is what happens to an interrupt that is neither an IPI nor the timer: it
//! goes to the device model's handler table, through a function the platform installs
//! here with [`set_device_dispatch`]. `arch` is below `device` and may not name it, so
//! the seam is a function pointer and the table, its lock and the probe-phase tokens that
//! gate registration all stay in `kernel/platform`.
//!
//! # Concurrency
//!
//! Every CPU dispatches through here, each with its own interrupts masked. The controller
//! is installed once, before any secondary is started, and never replaced, so readers on
//! every CPU see one value. The tick counter is the boot CPU's. Until `smp::release`, so
//! is the hook: a timer interrupt on a secondary is counted in that CPU's block by `smp`
//! and goes no further. After it, every CPU's timer interrupts and reschedule IPIs run
//! the hook on the CPU that took them. SGIs are the IPIs `smp` sends, and are handled
//! there on whichever CPU took them.

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

/// Write-once storage for the device model's dispatch, on the same terms as [`ChipSlot`].
struct DispatchSlot(UnsafeCell<Option<fn(IrqNumber) -> bool>>);

// SAFETY: the invariant is [`ChipSlot`]'s. `set_device_dispatch` writes once, on the boot
// CPU with interrupts masked, before any device line is enabled and so before any reader
// can exist, and nothing writes again.
unsafe impl Sync for DispatchSlot {}

static DEVICE_DISPATCH: DispatchSlot = DispatchSlot(UnsafeCell::new(None));

/// Send interrupts that are neither IPIs nor the timer to `dispatch`, which returns
/// whether it found a handler for the line.
///
/// # Safety
/// At most once, with interrupts masked, before any device line is enabled.
pub unsafe fn set_device_dispatch(dispatch: fn(IrqNumber) -> bool) {
    // SAFETY: the caller guarantees this is the only write and that no reader exists yet:
    // with the masks set no interrupt can be delivered, and no line is enabled.
    unsafe { *DEVICE_DISPATCH.0.get() = Some(dispatch) };
}

/// The device model's dispatch, once the platform has installed it.
fn device_dispatch() -> Option<fn(IrqNumber) -> bool> {
    // SAFETY: by the invariant the write happened before any reader could run.
    unsafe { *DEVICE_DISPATCH.0.get() }
}

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
    let mut ticked = false;
    for _ in 0..MAX_PER_ENTRY {
        let Some(claimed) = chip.claim() else { break };
        ticked |= handle(chip, chip.id(claimed));
        // The claimed value, not the ID: a GICv2 SGI is acknowledged with its sender.
        chip.eoi(claimed);
    }
    // After the loop, so every interrupt claimed on this entry has had its EOI before
    // the hook can switch threads. See `tick`.
    if ticked {
        crate::tick::run_hook();
    }
}

/// Interrupts serviced in one trip through the vector before giving the interrupted
/// code a chance to run again.
const MAX_PER_ENTRY: u32 = 16;

/// Handle one claimed interrupt. Returns whether the scheduler's hook should run after
/// it: a timer tick, or a reschedule IPI once the scheduler owns every CPU.
fn handle(chip: &dyn IrqChip, irq: IrqNumber) -> bool {
    if irq.0 < crate::smp::SGI_LIMIT {
        return crate::smp::on_ipi(irq.0);
    }
    if irq.0 == crate::timer::PPI {
        // A secondary's generic timer is its own until the scheduler is given the CPU, and
        // counting its ticks there, not below, keeps `TIMER_TICKS` the boot CPU's alone.
        // Once released, a secondary's tick reaches the hook too.
        if let Some(run_hook) = crate::smp::on_secondary_tick() {
            return run_hook;
        }
        // The timer's condition is level-sensitive: without this the line stays
        // asserted, EOI re-delivers immediately, and the machine never leaves the
        // handler. Re-arming moves the deadline into the future, which deasserts it as
        // surely as stopping does. The interrupt selftest wants exactly one tick; the
        // scheduler tick wants them to keep coming.
        match crate::tick::period() {
            0 => crate::timer::stop(),
            period => crate::timer::arm(period),
        }
        TIMER_TICKS.fetch_add(1, Ordering::Release);
        return true;
    }

    // Everything else belongs to a device, which means to the device model: a driver
    // registered for this line when the platform bound it.
    if let Some(dispatch) = device_dispatch() {
        if dispatch(irq) {
            DEVICE_IRQS.fetch_add(1, Ordering::Release);
            return false;
        }
    }

    // No handler. It has been claimed and will be acknowledged, but a level-triggered
    // source that nobody quiets is asserted again the moment it is: left enabled, it would
    // hold this CPU in the interrupt path for good. So the line is masked, and counted,
    // and whoever enabled a line without a handler finds out from the count rather than
    // from a machine that stopped. Found by registering a UART's handler for the wrong
    // line, which hung the boot until this.
    chip.disable(irq);
    SPURIOUS.fetch_add(1, Ordering::Release);
    false
}

/// Device interrupts a registered handler ran for, and ones that reached no handler.
static DEVICE_IRQS: AtomicU64 = AtomicU64::new(0);
static SPURIOUS: AtomicU64 = AtomicU64::new(0);

/// How many device interrupts have been dispatched to a handler.
pub fn device_irqs() -> u64 {
    DEVICE_IRQS.load(Ordering::Acquire)
}

/// How many interrupts arrived for a line with no enabled handler. Each such line was
/// masked when it did.
pub fn unhandled_irqs() -> u64 {
    SPURIOUS.load(Ordering::Acquire)
}

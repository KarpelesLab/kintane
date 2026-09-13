//! The Arm generic counter as the kernel's clock source, and the timer interrupts the
//! clock check waits through.
//!
//! The *virtual* counter, `CNTVCT_EL0`, and not the physical one that `timer.rs` reads.
//! EL1 may always read the virtual counter, while the physical counter is readable only
//! if EL2 allows it. Under a hypervisor the virtual counter is the physical one minus
//! an offset the hypervisor keeps, which is what a guest's notion of elapsed time
//! should be. Both count at `CNTFRQ_EL0`.
//!
//! This file reads counters and nothing more. Converting to nanoseconds is
//! `kernel/time`'s job, and so is deciding what to do with a deadline.
//!
//! Reference: Arm Architecture Reference Manual for A-profile, DDI 0487, D11.

use hal::{ClockSource, IrqNumber};

use crate::{irq, timer};

/// The system counter, read through the virtual view.
pub struct GenericCounter;

pub static COUNTER: GenericCounter = GenericCounter;

impl ClockSource for GenericCounter {
    fn name(&self) -> &'static str {
        "cntvct"
    }

    fn read(&self) -> u64 {
        let count: u64;
        // SAFETY: CNTVCT_EL0 is readable at EL1 unconditionally and reading it has no
        // side effects. The `isb` before the read, as in `timer::counter`, stops a
        // speculatively early sample.
        unsafe {
            core::arch::asm!(
                "isb",
                "mrs {}, cntvct_el0",
                out(reg) count,
                options(nomem, nostack, preserves_flags)
            );
        }
        count
    }

    /// 56, not 64. The architecture requires the counter to be at least 56 bits wide,
    /// and a wider counter read as 56 bits still gives correct differences, while a
    /// narrower one read as 64 would not.
    fn bits(&self) -> u32 {
        56
    }

    fn frequency_hz(&self) -> u64 {
        timer::frequency()
    }
}

/// The machine's clock source, or `None` if firmware left the counter frequency unset.
pub fn clock_source() -> Option<&'static dyn ClockSource> {
    if timer::frequency() == 0 {
        return None;
    }
    Some(&COUNTER)
}

/// Busy-wait with interrupts enabled until `wanted` timer interrupts have been taken.
///
/// Returns how many were taken and the nominal interval between them in nanoseconds.
/// Each interrupt comes from its own one-shot, `1 / PERIOD_DIVISOR` of a second long,
/// because the handler stops the timer after every interrupt. The wait is bounded by the counter,
/// so a timer that never fires shows up as a short count, not a hang.
///
/// Leaves interrupts masked and the timer stopped and disabled, as `interrupt_selftest`
/// leaves them. Requires that check to have installed the controller; without one this
/// returns zero interrupts.
pub fn spin_with_timer_interrupts(wanted: u64) -> (u64, u64) {
    let freq = timer::frequency();
    let Some(chip) = irq::chip() else {
        return (0, 0);
    };
    if freq == 0 {
        return (0, 0);
    }
    let period = (freq / PERIOD_DIVISOR).max(1);
    let period_ns = period * 1_000_000_000 / freq;
    let start = irq::timer_ticks();

    chip.enable(IrqNumber(timer::PPI));
    // SAFETY: the vector table and controller were installed by `interrupt_selftest`,
    // the only enabled source is the timer, whose handler stops and acknowledges it,
    // and the mask is set again below before returning.
    unsafe {
        core::arch::asm!("msr daifclr, #2", options(nomem, nostack, preserves_flags));
    }

    // A generous wall-clock bound: ten times the whole wait.
    let limit = timer::counter().wrapping_add(period.saturating_mul(wanted).saturating_mul(10));
    let mut taken = 0;
    while taken < wanted {
        let before = irq::timer_ticks();
        timer::arm(period as u32);
        while irq::timer_ticks() == before && timer::counter() < limit {
            core::hint::spin_loop();
        }
        if irq::timer_ticks() == before {
            break;
        }
        taken = irq::timer_ticks().wrapping_sub(start);
    }

    // SAFETY: restores the mask cleared above.
    unsafe {
        core::arch::asm!("msr daifset, #2", options(nomem, nostack, preserves_flags));
    }
    timer::stop();
    chip.disable(IrqNumber(timer::PPI));
    (irq::timer_ticks().wrapping_sub(start), period_ns)
}

/// Timer interrupts during the wait are this fraction of a second apart: 2 ms.
pub const PERIOD_DIVISOR: u64 = 500;

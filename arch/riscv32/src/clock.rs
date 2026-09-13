//! The CLINT's `mtime` as the kernel's clock source, and the timer interrupts the clock
//! check waits through.
//!
//! This file reads a counter and nothing more. Converting to nanoseconds is
//! `kernel/time`'s job.

use hal::{Arch, ClockSource};

use crate::{Riscv32, clint, tick, trap};

/// `mtime`.
pub struct MachineTimer;

pub static COUNTER: MachineTimer = MachineTimer;

impl ClockSource for MachineTimer {
    fn name(&self) -> &'static str {
        "mtime"
    }

    fn read(&self) -> u64 {
        clint::now()
    }

    /// A full 64-bit register, which on `virt` at 10 MHz outlasts everything.
    fn bits(&self) -> u32 {
        64
    }

    fn frequency_hz(&self) -> u64 {
        clint::FREQUENCY
    }
}

/// The machine's clock source.
pub fn clock_source() -> Option<&'static dyn ClockSource> {
    Some(&COUNTER)
}

/// Timer interrupts during the wait are this fraction of a second apart: 2 ms.
pub const PERIOD_DIVISOR: u64 = 500;

/// Busy-wait with interrupts enabled until `wanted` timer interrupts have been taken.
///
/// Returns how many were taken and the nominal interval between them in nanoseconds.
/// Each comes from its own one-shot, since the handler disarms the timer every time.
/// Bounded by the counter, so a timer that never fires is a short count, not a hang.
/// Leaves interrupts masked and the timer disabled.
pub fn spin_with_timer_interrupts(wanted: u64) -> (u64, u64) {
    let period = (clint::FREQUENCY / PERIOD_DIVISOR).max(1);
    let period_ns = period * 1_000_000_000 / clint::FREQUENCY;
    let start = trap::TIMER_TICKS.get();

    tick::set_mie(true);
    let limit = clint::now().wrapping_add(period.saturating_mul(wanted).saturating_mul(10));
    let mut taken = 0;
    while taken < wanted {
        let before = trap::TIMER_TICKS.get();
        // Masked on entry — the caller's state — and again at the bottom of each round.
        let _ = Riscv32::irq_save();
        // SAFETY: masked for the write, and the handler disarms it again.
        unsafe { clint::set_deadline(clint::now() + period) };
        // SAFETY: `mtvec` is installed, the only enabled source is the timer, whose handler
        // disarms and counts it, and the mask is set again below before returning.
        unsafe { tick::enable_interrupts() };
        while trap::TIMER_TICKS.get() == before && clint::now() < limit {
            core::hint::spin_loop();
        }
        let _ = Riscv32::irq_save();
        if trap::TIMER_TICKS.get() == before {
            break;
        }
        taken = trap::TIMER_TICKS.get().wrapping_sub(start);
    }
    tick::stop();
    (trap::TIMER_TICKS.get().wrapping_sub(start), period_ns)
}

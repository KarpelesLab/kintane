//! CMSDK APB timer 0: the scheduler's one-shot interrupt.
//!
//! SysTick is the core's own timer, and this port spends it on the clock (`clock.rs`):
//! it has one counter, and a counter that is also reprogrammed for every deadline is not
//! a clock. The AN385 image has two 32-bit APB timers besides; timer 0, at interrupt 8,
//! is the one-shot.
//!
//! The CMSDK timer counts `VALUE` down at the peripheral clock's rate, raises its
//! interrupt at zero and reloads from `RELOAD`. A one-shot is that with the timer
//! disabled again in the handler.

use core::ptr::{read_volatile, write_volatile};

use crate::scs;

/// APB timer 0 on the AN385 image.
const TIMER0: usize = 0x4000_0000;
/// Its interrupt number.
pub const IRQ: u32 = 8;

const CTRL: usize = 0x00;
const VALUE: usize = 0x04;
const RELOAD: usize = 0x08;
const INTCLEAR: usize = 0x0C;

const CTRL_ENABLE: u32 = 1 << 0;
const CTRL_IRQ_ENABLE: u32 = 1 << 3;

/// The AN385's peripheral clock, which the timer counts.
pub const FREQUENCY: u64 = 25_000_000;

/// # Safety
/// `off` must be one of the offsets above.
unsafe fn write(off: usize, v: u32) {
    // SAFETY: the timer's registers are always present at `TIMER0` on the AN385, and
    // there is no translation.
    unsafe { write_volatile((TIMER0 + off) as *mut u32, v) };
}

/// The count left before the interrupt.
pub fn remaining() -> u32 {
    // SAFETY: reading VALUE has no side effects.
    unsafe { read_volatile((TIMER0 + VALUE) as *const u32) }
}

/// Raise the interrupt `ticks` counts from now, replacing any deadline already armed.
///
/// # Safety
/// Interrupts must be masked, so the handler cannot run between the writes.
pub unsafe fn arm(ticks: u32) {
    let ticks = ticks.max(1);
    // SAFETY: masked, per the contract; stopped before it is reloaded, so the old count
    // cannot expire between the writes.
    unsafe {
        write(CTRL, 0);
        write(INTCLEAR, 1);
        write(RELOAD, ticks);
        write(VALUE, ticks);
        write(CTRL, CTRL_ENABLE | CTRL_IRQ_ENABLE);
    }
}

/// Stop the timer and acknowledge anything it raised. This is the port's EOI: the
/// interrupt is level-sensitive, and a hook that switches threads must not leave it
/// asserted for the next thread to take again.
///
/// # Safety
/// Interrupts must be masked, or this must be the timer's own handler.
pub unsafe fn disarm() {
    // SAFETY: the caller's contract.
    unsafe {
        write(CTRL, 0);
        write(INTCLEAR, 1);
    }
    // SAFETY: ICPR is write-one-to-clear; this clears only the timer's own pending bit,
    // which a level that is now low would otherwise leave latched.
    unsafe { scs::write(scs::NVIC_ICPR, 1 << IRQ) };
}

/// Enable or disable the timer's line at the NVIC.
pub(crate) fn set_enabled(on: bool) {
    // SAFETY: ISER and ICER are write-one-to-act; only this interrupt's bit is written.
    unsafe { scs::write(if on { scs::NVIC_ISER } else { scs::NVIC_ICER }, 1 << IRQ) };
}

/// Ticks for `ns` nanoseconds, rounded up, saturating at the register's width.
pub fn ticks_for(ns: u64) -> u32 {
    const NS: u64 = 1_000_000_000;
    // Whole seconds and the remainder apart, so no 128-bit division is emitted.
    let t = (ns / NS)
        .saturating_mul(FREQUENCY)
        .saturating_add(((ns % NS) * FREQUENCY).div_ceil(NS));
    u32::try_from(t).unwrap_or(u32::MAX)
}

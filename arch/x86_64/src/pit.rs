//! The 8254 programmable interval timer, channel 0.
//!
//! The oldest timer on the platform and the only one that needs no discovery: fixed
//! ports, fixed input frequency, wired to IRQ 0 on every PC ever built. That makes it
//! the right thing to prove the interrupt path with, and the wrong thing to keep as
//! the system clock — it is slow to program, has no per-CPU instance, and its
//! interrupt goes through the PIC. The scheduler's one-shot tick is the local APIC timer,
//! calibrated against the TSC, once `kernel/platform/acpi` installs the APIC driver; the
//! PIT stays the timer the interrupt and clock checks measure, and the fallback.
//!
//! Reference: Intel 8254 datasheet, and the PC/AT wiring that fixes the input clock
//! at one third of the 3.579545 MHz NTSC colourburst frequency, because in 1981 that
//! crystal was the cheap one.

use crate::serial::outb;

/// Channel 0's counter port. Its output is wired to IRQ 0.
const CHANNEL0: u16 = 0x40;
/// The mode/command register.
const COMMAND: u16 = 0x43;

/// Input frequency in Hz: 1.193182 MHz.
pub const INPUT_HZ: u32 = 1_193_182;

/// Command byte: channel 0, access low byte then high byte, mode 2, binary counting.
///
/// Mode 2 is the rate generator: the counter reloads itself and pulses the output
/// every `divisor` input cycles, so one write gives a periodic interrupt. Mode 3
/// (square wave) also works and is what a real timekeeping driver would use for its
/// slightly better duty cycle; mode 2's period is the one that is easier to reason
/// about, and this is a test.
const CMD_CHANNEL0_RATE: u8 = 0x34;

/// Command byte: channel 0, low byte then high byte, mode 0, binary counting.
///
/// Mode 0 is "interrupt on terminal count": writing the command drives the output low,
/// the counter counts down once from the value written, and the output rises when it
/// reaches zero and stays high. The rising edge is one interrupt, and nothing follows
/// it until the next write. That is a one-shot timer, which is what a tickless kernel
/// programs.
const CMD_CHANNEL0_ONESHOT: u8 = 0x30;

/// The largest count channel 0 holds. Written as 0, since a 16-bit register cannot
/// hold 65536 itself.
pub const MAX_COUNT: u32 = 0x1_0000;

/// Start channel 0 ticking at approximately `hz`, returning the divisor programmed.
///
/// The rate is approximate because the divisor is an integer: the caller gets the
/// divisor back so it can compute the exact period rather than assume its request was
/// honoured. Rates below 19 Hz are not representable in 16 bits and are clamped to
/// the slowest the chip can do.
///
/// # Safety
/// Writes the shared PIT command register, so it must not race with anything else
/// programming another channel. Channel 2 is the PC speaker and channel 1 was DRAM
/// refresh; neither has a driver in this kernel, so today the only requirement is
/// that this is not re-entered.
pub unsafe fn start_periodic(hz: u32) -> u16 {
    let divisor = match INPUT_HZ.checked_div(hz) {
        Some(d) if d >= 1 && d <= 0xffff => d as u16,
        // 0 means 65536 in the chip's arithmetic, which is the slowest rate; a
        // caller asking for something unrepresentable gets the nearest legal thing
        // rather than an undefined counter.
        Some(_) => 0,
        None => 0,
    };
    // SAFETY: the 8254 command/data sequence on channel 0's fixed ports. The command
    // byte selects two-byte access, so the two writes that follow are the low and
    // high halves of one reload value and must not be separated by another access to
    // the same channel — which the `unsafe` contract above is what guarantees.
    unsafe {
        outb(COMMAND, CMD_CHANNEL0_RATE);
        outb(CHANNEL0, (divisor & 0xff) as u8);
        outb(CHANNEL0, (divisor >> 8) as u8);
    }
    divisor
}

/// Raise IRQ 0 once, `count` input cycles from now, clamped to `1..=MAX_COUNT`.
///
/// A write in mode 0 restarts the count, so calling this again before the interrupt
/// replaces the deadline instead of adding a second one.
///
/// # Safety
/// As [`start_periodic`].
pub unsafe fn start_oneshot(count: u32) {
    let count = count.clamp(1, MAX_COUNT);
    // 65536 is written as 0; see `MAX_COUNT`.
    let reload = (count & 0xffff) as u16;
    // SAFETY: as in `start_periodic`: the command selects two-byte access, and the two
    // writes that follow are one reload value that nothing else may split.
    unsafe {
        outb(COMMAND, CMD_CHANNEL0_ONESHOT);
        outb(CHANNEL0, (reload & 0xff) as u8);
        outb(CHANNEL0, (reload >> 8) as u8);
    }
}

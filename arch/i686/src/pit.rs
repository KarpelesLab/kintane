//! The 8254 programmable interval timer, channel 0.
//!
//! The oldest timer on the platform and the only one that needs no discovery: fixed
//! ports, fixed input frequency, wired to IRQ 0 on every PC ever built. That makes it
//! the right thing to prove the interrupt path with, and the wrong thing to keep as
//! the system clock — it is slow to program, has no per-CPU instance, and its
//! interrupt goes through the PIC. The real timekeeping source is the local APIC
//! timer, calibrated against the TSC, which is Phase 3 work alongside the APIC driver.
//!
//! As with `pic.rs`, this is deliberately a second copy of the x86-64 file rather than
//! a shared one: the two `arch` crates are separate units and may not depend on each
//! other, and the right destination for both is `drivers/` once the device framework
//! can register and find a driver.
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

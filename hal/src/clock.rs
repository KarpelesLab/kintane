//! Clock sources: free-running counters, and nothing about what time it is.
//!
//! A clock source is a device, not an architecture capability. A PC may count with the
//! TSC, the HPET or the ACPI PM timer; an Arm board has the generic counter; a
//! Cortex-M has SysTick, whose counter is 24 bits and counts *down*. Which one a
//! machine has and trusts is a runtime answer, so this trait is object-safe and used as
//! `&dyn ClockSource`, like [`crate::IrqChip`].
//!
//! The trait describes the counter and nothing else. Turning counter values into
//! nanoseconds — the multiply-and-shift scale, wrap handling, and holding the clock
//! monotonic when a counter briefly steps backwards — is written once, in
//! `kernel/time`, and is tested on a laptop against counters that behave like each
//! class of hardware.

/// A free-running counter that increases at a fixed rate.
pub trait ClockSource: Sync {
    /// Name for diagnostics, e.g. "tsc" or "cntvct".
    fn name(&self) -> &'static str;

    /// The counter's current value.
    ///
    /// Only the low [`bits`](ClockSource::bits) bits are meaningful: the counter wraps
    /// from `2^bits - 1` to zero, and anything above that width is ignored. A counter
    /// that counts down must be inverted here, so callers only ever see one direction.
    fn read(&self) -> u64;

    /// Width of the counter in bits, from 1 to 64.
    fn bits(&self) -> u32;

    /// Counter increments per second.
    ///
    /// Only as accurate as whatever measured it. The TSC's rate is calibrated against
    /// another timer, and the Arm counter's comes from firmware. Neither can be checked
    /// independently at boot, so this is a claim and not a measurement.
    fn frequency_hz(&self) -> u64;
}

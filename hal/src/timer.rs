//! Event timers: a per-CPU source of interrupts at a programmed time.
//!
//! The counterpart of [`crate::ClockSource`]. A clock source is read; an event timer
//! interrupts. They are separate traits because they are separate devices on most
//! machines: a PC reads the TSC and is interrupted by the local APIC timer, and a Cortex-M
//! may read one counter and be woken by another.
//!
//! Like a clock source, an event timer is a device and not an architecture capability, so
//! the trait is object-safe and used as `&dyn EventTimer`: which timer a machine has is
//! decided by discovery, and the architecture's tick path holds whatever was installed.
//!
//! An event timer is **per CPU**. Every method acts on the timer of the CPU that calls it,
//! which is what the local APIC timer and the Arm generic timer are. Arming one CPU's
//! timer from another is not something either can do, and nothing here pretends to.

/// A timer that raises an interrupt on the calling CPU after a programmed delay.
pub trait EventTimer: Sync {
    /// Name for diagnostics, e.g. "local APIC timer".
    fn name(&self) -> &'static str;

    /// The longest delay one arming covers, in nanoseconds. Zero means the timer is not
    /// usable, for example because it could not be calibrated.
    fn reach_ns(&self) -> u64;

    /// Raise one interrupt `ns` nanoseconds from now, replacing any deadline already
    /// armed. Rounded up, so the interrupt is never early. A delay beyond
    /// [`reach_ns`](EventTimer::reach_ns) is cut to it, and the caller re-arms from the
    /// interrupt.
    ///
    /// # Safety
    /// On the CPU whose timer is armed, with its interrupts masked, after that CPU's part of
    /// the interrupt controller has been prepared.
    unsafe fn arm_ns(&self, ns: u64);

    /// Interrupt every `ns` nanoseconds until stopped, replacing any deadline. Returns the
    /// period actually programmed, or `None` when the timer cannot run periodically at
    /// that period.
    ///
    /// # Safety
    /// As [`arm_ns`](EventTimer::arm_ns).
    unsafe fn start_periodic_ns(&self, ns: u64) -> Option<u64>;

    /// Stop the calling CPU's timer. An interrupt already pending may still be delivered.
    fn stop(&self);
}

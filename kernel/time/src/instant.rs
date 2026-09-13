//! Points and spans on the kernel's monotonic timeline, in nanoseconds.
//!
//! Both are a `u64` of nanoseconds, which lasts 584 years from boot. Nanoseconds and
//! not ticks, so that no caller has to know what counter the machine has. A `u64`
//! and not a `u128`, because 128-bit arithmetic on a 32-bit core is a runtime library
//! call, and this type appears in the interrupt path.
//!
//! There are no `+` and `-` operators. Every arithmetic operation is checked or
//! saturating, and the name says which. An overflowing deadline in a timer is the
//! difference between "fire in 10 ms" and "fire immediately", and that is a choice
//! the caller should make on purpose.

/// Nanoseconds in one second.
pub const NANOS_PER_SEC: u64 = 1_000_000_000;

/// A span of time.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Default)]
pub struct Duration(u64);

impl Duration {
    pub const ZERO: Duration = Duration(0);
    pub const MAX: Duration = Duration(u64::MAX);

    pub const fn from_nanos(ns: u64) -> Duration {
        Duration(ns)
    }

    pub const fn from_micros(us: u64) -> Option<Duration> {
        match us.checked_mul(1_000) {
            Some(ns) => Some(Duration(ns)),
            None => None,
        }
    }

    pub const fn from_millis(ms: u64) -> Option<Duration> {
        match ms.checked_mul(1_000_000) {
            Some(ns) => Some(Duration(ns)),
            None => None,
        }
    }

    pub const fn from_secs(s: u64) -> Option<Duration> {
        match s.checked_mul(NANOS_PER_SEC) {
            Some(ns) => Some(Duration(ns)),
            None => None,
        }
    }

    pub const fn as_nanos(self) -> u64 {
        self.0
    }

    pub const fn is_zero(self) -> bool {
        self.0 == 0
    }

    pub const fn checked_add(self, other: Duration) -> Option<Duration> {
        match self.0.checked_add(other.0) {
            Some(ns) => Some(Duration(ns)),
            None => None,
        }
    }

    pub const fn checked_sub(self, other: Duration) -> Option<Duration> {
        match self.0.checked_sub(other.0) {
            Some(ns) => Some(Duration(ns)),
            None => None,
        }
    }

    pub const fn saturating_sub(self, other: Duration) -> Duration {
        Duration(self.0.saturating_sub(other.0))
    }

    pub const fn checked_mul(self, n: u64) -> Option<Duration> {
        match self.0.checked_mul(n) {
            Some(ns) => Some(Duration(ns)),
            None => None,
        }
    }
}

/// A point on the monotonic timeline, measured from an arbitrary origin near boot.
///
/// Only comparable with instants from the same clock. There is one clock per kernel,
/// so in practice that is all of them.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Default)]
pub struct Instant(u64);

impl Instant {
    /// The clock's origin.
    pub const ZERO: Instant = Instant(0);
    /// The last representable instant. Also the saturation point of the clock.
    pub const MAX: Instant = Instant(u64::MAX);

    pub const fn from_nanos(ns: u64) -> Instant {
        Instant(ns)
    }

    pub const fn as_nanos(self) -> u64 {
        self.0
    }

    pub const fn checked_add(self, d: Duration) -> Option<Instant> {
        match self.0.checked_add(d.0) {
            Some(ns) => Some(Instant(ns)),
            None => None,
        }
    }

    pub const fn saturating_add(self, d: Duration) -> Instant {
        Instant(self.0.saturating_add(d.0))
    }

    pub const fn checked_sub(self, d: Duration) -> Option<Instant> {
        match self.0.checked_sub(d.0) {
            Some(ns) => Some(Instant(ns)),
            None => None,
        }
    }

    /// Time from `earlier` to `self`, or `None` if `earlier` is in fact later.
    pub const fn checked_duration_since(self, earlier: Instant) -> Option<Duration> {
        match self.0.checked_sub(earlier.0) {
            Some(ns) => Some(Duration(ns)),
            None => None,
        }
    }

    /// Time from `earlier` to `self`, or zero if `earlier` is later.
    pub const fn saturating_duration_since(self, earlier: Instant) -> Duration {
        Duration(self.0.saturating_sub(earlier.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constructors_refuse_rather_than_wrap() {
        assert_eq!(Duration::from_secs(3), Some(Duration::from_nanos(3 * NANOS_PER_SEC)));
        assert_eq!(Duration::from_millis(5).unwrap().as_nanos(), 5_000_000);
        assert_eq!(Duration::from_micros(7).unwrap().as_nanos(), 7_000);
        // 2^64 ns is about 584 years; 600 years of seconds does not fit.
        assert_eq!(Duration::from_secs(600 * 365 * 24 * 3600), None);
        assert_eq!(Duration::from_millis(u64::MAX), None);
        assert_eq!(Duration::from_micros(u64::MAX), None);
    }

    #[test]
    fn instant_arithmetic_is_checked_at_both_ends() {
        let t = Instant::from_nanos(100);
        assert_eq!(t.checked_add(Duration::from_nanos(5)), Some(Instant::from_nanos(105)));
        assert_eq!(Instant::MAX.checked_add(Duration::from_nanos(1)), None);
        assert_eq!(Instant::MAX.saturating_add(Duration::from_nanos(1)), Instant::MAX);
        assert_eq!(t.checked_sub(Duration::from_nanos(101)), None);
        assert_eq!(t.checked_sub(Duration::from_nanos(100)), Some(Instant::ZERO));
    }

    #[test]
    fn duration_since_does_not_invent_negative_time() {
        let a = Instant::from_nanos(10);
        let b = Instant::from_nanos(25);
        assert_eq!(b.checked_duration_since(a), Some(Duration::from_nanos(15)));
        assert_eq!(a.checked_duration_since(b), None);
        assert_eq!(a.saturating_duration_since(b), Duration::ZERO);
    }

    #[test]
    fn duration_arithmetic_is_checked() {
        let d = Duration::from_nanos(u64::MAX / 2 + 1);
        assert_eq!(d.checked_add(d), None);
        assert_eq!(d.checked_mul(2), None);
        assert_eq!(Duration::from_nanos(3).checked_mul(4), Some(Duration::from_nanos(12)));
        assert_eq!(Duration::ZERO.checked_sub(Duration::from_nanos(1)), None);
        assert_eq!(Duration::ZERO.saturating_sub(Duration::from_nanos(1)), Duration::ZERO);
        assert!(Duration::ZERO.is_zero());
    }
}

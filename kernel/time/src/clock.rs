//! Turning a free-running counter into monotonic nanoseconds.
//!
//! # The conversion
//!
//! Nanoseconds from counter ticks is `ticks * 10^9 / hz`. Computing that division on
//! every read is out: on a 32-bit core, dividing 64-bit values is a runtime-library call
//! that loops over bits, and clocks are read in interrupt handlers. So the division is
//! done once, at setup, as a fixed-point factor:
//!
//! ```text
//!   ns = (ticks * mult) >> shift        where  mult = round(10^9 * 2^shift / hz)
//! ```
//!
//! The multiply is the one thing that can go wrong. `ticks * mult` must fit in 64 bits,
//! so a larger `shift` (more precision) means fewer ticks can be converted in one step.
//! [`Scale`] chooses the largest shift that still converts [`FAST_PATH_SECS`] seconds
//! of ticks in one multiply. A longer gap between reads is still converted exactly, by
//! a slower path that divides once. An idle machine reaches that path; an interrupt
//! handler does not.
//!
//! # Exactness
//!
//! The bits shifted off are not thrown away. [`Clock`] carries them (`frac`) into the
//! next conversion, so advancing a clock in one large step and in a thousand small
//! ones gives the same instant, to the nanosecond. Without that, a clock read often
//! would run measurably slow compared with one read rarely, because each read would
//! drop up to a nanosecond.
//!
//! What remains is the rounding of `mult` itself, a fixed rate error of at most
//! `hz / (10^9 * 2^(shift+1))`. For the machines we target that is below one part per
//! million, which is less than the error in the crystal. Correcting it against an
//! outside reference is NTP's job, and it belongs to a later phase.
//!
//! # Wrap, and counters that step backwards
//!
//! A counter narrower than 64 bits wraps, and the difference between two reads is taken
//! modulo its width. That is only unambiguous if reads are less than one wrap apart.
//! A difference in the *upper* half of the range is therefore treated as the counter
//! having stepped backwards, which a TSC can do across CPUs or after firmware touches
//! it, and not as an enormous jump forward. Time does not move for that read. The
//! price is that a clock must be read at least once per half-wrap. [`Clock::max_idle`]
//! reports that bound, so that a tickless idle loop can respect it.

use hal::ClockSource;

use crate::instant::{Duration, Instant, NANOS_PER_SEC};

/// Seconds of counter ticks that the fast path converts with a single multiply.
///
/// Ten, because a periodic tick or any wakeup reads the clock far more often than
/// that, and more range costs precision. At ten seconds both a 62.5 MHz and a
/// 32.768 kHz counter get a shift of 30, and since both rates divide 10^9 * 2^30, their
/// factors are exact. `the_scale_prefers_precision_within_its_range` checks the
/// rounding for other rates against 1 ppm.
pub const FAST_PATH_SECS: u64 = 10;

/// The largest shift considered. `10^9 << 32` still fits in a `u64`, and so does the
/// fractional remainder.
const MAX_SHIFT: u32 = 32;

/// Why a counter cannot be used as a clock.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ClockError {
    /// The counter claims not to count.
    ZeroFrequency,
    /// Width outside 1..=64 bits.
    BadWidth,
    /// Faster than 2^32 ticks per nanosecond, so no factor exists. No real counter is.
    FrequencyTooHigh,
}

/// A fixed-point factor from counter ticks to nanoseconds.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Scale {
    mult: u64,
    shift: u32,
    /// The most ticks one multiply may convert without overflowing, including room
    /// for a carried fraction.
    max_delta: u64,
}

impl Scale {
    /// The most precise factor for a counter running at `hz` whose fast path still covers
    /// `range_secs` seconds.
    ///
    /// If no factor covers the range, the one with the largest range is used instead.
    /// That only happens for multi-gigahertz counters asked to cover very long ranges,
    /// and it costs speed, not correctness: longer deltas take the slow path.
    pub fn new(hz: u64, range_secs: u64) -> Result<Scale, ClockError> {
        if hz == 0 {
            return Err(ClockError::ZeroFrequency);
        }
        let wanted = hz.saturating_mul(range_secs).max(1);
        let mut widest: Option<Scale> = None;

        let mut shift = MAX_SHIFT + 1;
        while shift > 0 {
            shift -= 1;
            // Division is fine here: this runs once per clock, at setup.
            let Some(rounded) = (NANOS_PER_SEC << shift).checked_add(hz / 2) else {
                continue;
            };
            let mult = rounded / hz;
            if mult == 0 {
                continue;
            }
            let frac_max = (1u64 << shift) - 1;
            let max_delta = (u64::MAX - frac_max) / mult;
            let scale = Scale {
                mult,
                shift,
                max_delta,
            };
            if max_delta >= wanted {
                return Ok(scale);
            }
            // Shifts only get smaller from here, so each valid one has a wider range.
            widest = Some(scale);
        }
        widest.ok_or(ClockError::FrequencyTooHigh)
    }

    pub const fn mult(self) -> u64 {
        self.mult
    }

    pub const fn shift(self) -> u32 {
        self.shift
    }

    pub const fn max_delta(self) -> u64 {
        self.max_delta
    }

    const fn frac_mask(self) -> u64 {
        (1u64 << self.shift) - 1
    }

    /// Convert `ticks`, carrying `frac` in and out. Returns whole nanoseconds, which
    /// saturate at `u64::MAX`, and the new fraction.
    fn convert(self, ticks: u64, frac: u64) -> (u64, u64) {
        if ticks <= self.max_delta {
            // The fast path: one multiply and one shift. `ticks * mult + frac` cannot
            // overflow, because `max_delta` was chosen to leave room for exactly this.
            let acc = ticks * self.mult + frac;
            return (acc >> self.shift, acc & self.frac_mask());
        }
        self.convert_long(ticks, frac)
    }

    /// The slow path, for gaps longer than [`FAST_PATH_SECS`]: split the delta into `q`
    /// full chunks of `max_delta` ticks and a remainder.
    ///
    /// Exact, because the fractional parts of the chunks are summed before shifting,
    /// not rounded one chunk at a time. `q * chunk_frac` fits in 64 bits because both
    /// factors are below 2^32: the fraction by construction, and `q` because a larger
    /// `q` means at least `2^32 * max_delta` ticks, which is more nanoseconds than a
    /// `u64` holds, and saturates first.
    #[cold]
    fn convert_long(self, ticks: u64, frac: u64) -> (u64, u64) {
        let q = ticks / self.max_delta;
        let r = ticks % self.max_delta;
        if q > u64::from(u32::MAX) {
            return (u64::MAX, 0);
        }
        let chunk = self.max_delta * self.mult;
        let chunk_ns = chunk >> self.shift;
        let chunk_frac = chunk & self.frac_mask();

        let Some(whole) = q.checked_mul(chunk_ns) else {
            return (u64::MAX, 0);
        };
        let acc = q * chunk_frac + frac;
        let (rest_ns, frac) = self.convert(r, acc & self.frac_mask());
        let ns = whole
            .saturating_add(acc >> self.shift)
            .saturating_add(rest_ns);
        (ns, frac)
    }
}

/// A monotonic clock over one counter.
///
/// Holds no reference to the hardware: callers pass counter values in. That keeps the
/// arithmetic testable with made-up values, and keeps locking out of this type. The
/// kernel's clock is read from interrupt context and from threads, and how those share
/// it depends on whether the machine has more than one CPU. That decision belongs to
/// the code that owns the shared clock, not to the arithmetic.
#[derive(Clone, Copy, Debug)]
pub struct Clock {
    scale: Scale,
    mask: u64,
    /// Counter value at the last fold, already masked to the counter's width.
    last: u64,
    /// Nanoseconds at the last fold.
    base: u64,
    /// Sub-nanosecond remainder at the last fold, in units of `2^-shift` ns.
    frac: u64,
}

impl Clock {
    /// A clock reading [`Instant::ZERO`] at counter value `now`.
    pub fn new(hz: u64, bits: u32, now: u64) -> Result<Clock, ClockError> {
        if bits == 0 || bits > 64 {
            return Err(ClockError::BadWidth);
        }
        let mask = if bits == 64 {
            u64::MAX
        } else {
            (1u64 << bits) - 1
        };
        Ok(Clock {
            scale: Scale::new(hz, FAST_PATH_SECS)?,
            mask,
            last: now & mask,
            base: 0,
            frac: 0,
        })
    }

    /// A clock over `source`, reading zero now.
    pub fn from_source(source: &dyn ClockSource) -> Result<Clock, ClockError> {
        Clock::new(source.frequency_hz(), source.bits(), source.read())
    }

    /// Ticks since the last fold, or zero if the counter appears to have gone back.
    fn delta(&self, now: u64) -> u64 {
        let d = (now & self.mask).wrapping_sub(self.last) & self.mask;
        if d > self.mask >> 1 { 0 } else { d }
    }

    /// Fold counter value `now` into the clock and return the time it represents.
    ///
    /// Never earlier than any instant this clock has returned before, whatever `now` is.
    /// A backwards step leaves the clock where it was, and `last` is not moved back
    /// either. Moving it back would count the same interval twice once the counter
    /// recovers.
    pub fn advance(&mut self, now: u64) -> Instant {
        let d = self.delta(now);
        if d != 0 {
            let (ns, frac) = self.scale.convert(d, self.frac);
            self.base = self.base.saturating_add(ns);
            self.frac = frac;
            self.last = now & self.mask;
        }
        Instant::from_nanos(self.base)
    }

    /// The time counter value `now` represents, without changing the clock.
    ///
    /// Monotonic across [`advance`](Clock::advance) calls and across peeks at an
    /// increasing counter. Two peeks at a counter that stepped backwards between them
    /// can go backwards, because nothing records the first one. Callers that need the
    /// stronger guarantee use `advance`.
    pub fn peek(&self, now: u64) -> Instant {
        let (ns, _) = self.scale.convert(self.delta(now), self.frac);
        Instant::from_nanos(self.base.saturating_add(ns))
    }

    /// The longest the clock may go unread before a wrap becomes ambiguous.
    ///
    /// Half the counter's wrap period, by the rule in the module documentation. A
    /// tickless idle must wake within this, whether or not a timer is due.
    pub fn max_idle(&self) -> Duration {
        let (ns, _) = self.scale.convert(self.mask >> 1, 0);
        Duration::from_nanos(ns)
    }

    pub fn scale(&self) -> Scale {
        self.scale
    }
}

#[cfg(test)]
mod tests {
    use hal::mock::{MockClock, MockFull, MockTiny};

    use super::*;

    /// One second of ticks, for either profile's counter, must come out within 1 ppm
    /// of a second.
    fn one_second_is_a_second<P: MockClock>() {
        let src = P::counter();
        let hz = src.frequency_hz();
        let mut clock = Clock::from_source(&src).unwrap();
        src.advance(hz);
        let t = clock.advance(src.read()).as_nanos();
        let err = t.abs_diff(NANOS_PER_SEC);
        assert!(err <= 1_000, "{} ns off after one second", err);
    }

    #[test]
    fn one_second_is_a_second_full() {
        one_second_is_a_second::<MockFull>();
    }

    #[test]
    fn one_second_is_a_second_tiny() {
        one_second_is_a_second::<MockTiny>();
    }

    /// Many small steps and one large step must reach the same instant exactly. That is
    /// what carrying the fraction buys.
    fn small_steps_and_one_big_step_agree<P: MockClock>() {
        let a = P::counter();
        let b = P::counter();
        let mut many = Clock::from_source(&a).unwrap();
        let mut once = Clock::from_source(&b).unwrap();
        // An awkward step size that does not divide evenly into anything.
        let step = 7_919;
        let steps = 5_000;
        for _ in 0..steps {
            a.advance(step);
            many.advance(a.read());
        }
        // Too wide for one step on a narrow counter, so advance `once` in half-wrap
        // strides; the claim is about stride size, and these are still far larger.
        let mut left = step * steps;
        let stride = (1u64 << (b.bits().min(63) - 1)) - 1;
        while left > 0 {
            let s = left.min(stride);
            b.advance(s);
            once.advance(b.read());
            left -= s;
        }
        assert_eq!(many.advance(a.read()), once.advance(b.read()));
    }

    #[test]
    fn small_steps_and_one_big_step_agree_full() {
        small_steps_and_one_big_step_agree::<MockFull>();
    }

    #[test]
    fn small_steps_and_one_big_step_agree_tiny() {
        small_steps_and_one_big_step_agree::<MockTiny>();
    }

    /// Across the counter's wrap, the elapsed time is the ticks that actually passed.
    fn wrap_is_not_a_jump<P: MockClock>() {
        let src = P::counter();
        let top = if src.bits() == 64 {
            u64::MAX
        } else {
            (1u64 << src.bits()) - 1
        };
        src.set(top - 9);
        let mut clock = Clock::from_source(&src).unwrap();
        src.advance(20); // wraps on either profile
        let wrapped = clock.advance(src.read());

        let fresh = P::counter();
        let mut reference = Clock::from_source(&fresh).unwrap();
        fresh.advance(20);
        assert_eq!(wrapped, reference.advance(fresh.read()));
        assert!(wrapped > Instant::ZERO);
    }

    #[test]
    fn wrap_is_not_a_jump_full() {
        wrap_is_not_a_jump::<MockFull>();
    }

    #[test]
    fn wrap_is_not_a_jump_tiny() {
        wrap_is_not_a_jump::<MockTiny>();
    }

    /// A counter that steps backwards must not move the clock back, and must not make it
    /// leap forward by nearly a whole wrap either. Once the counter recovers, the
    /// interval is counted once.
    fn backwards_steps_are_held<P: MockClock>() {
        let src = P::counter();
        src.set(1_000_000);
        let mut clock = Clock::from_source(&src).unwrap();
        src.set(1_000_500);
        let t1 = clock.advance(src.read());
        src.set(1_000_400); // backwards
        let t2 = clock.advance(src.read());
        assert_eq!(t2, t1, "a backwards step must hold the clock, not move it");
        src.set(1_000_600);
        let t3 = clock.advance(src.read());

        let fresh = P::counter();
        let mut reference = Clock::new(fresh.frequency_hz(), fresh.bits(), 0).unwrap();
        assert_eq!(t3, reference.advance(600), "the recovered interval is counted once");
    }

    #[test]
    fn backwards_steps_are_held_full() {
        backwards_steps_are_held::<MockFull>();
    }

    #[test]
    fn backwards_steps_are_held_tiny() {
        backwards_steps_are_held::<MockTiny>();
    }

    /// Bits above the counter's width are ignored.
    #[test]
    fn stray_high_bits_are_ignored_tiny() {
        let src = MockTiny::counter();
        let mut clock = Clock::from_source(&src).unwrap();
        src.set(0xFF00_0000 | 32_768);
        let t = clock.advance(src.read());
        assert!(t.as_nanos().abs_diff(NANOS_PER_SEC) <= 1_000);
    }

    #[test]
    fn max_idle_is_half_a_wrap() {
        // 2^23 ticks at 32768 Hz is exactly 256 seconds.
        let src = MockTiny::counter();
        let clock = Clock::from_source(&src).unwrap();
        let idle = clock.max_idle().as_nanos();
        assert!(idle.abs_diff(256 * NANOS_PER_SEC) <= 256_000, "{idle}");

        // 2^63 ticks at 62.5 MHz is about 4,700 years, more nanoseconds than a u64 holds.
        // It must saturate, not wrap around to something small.
        let src = MockFull::counter();
        let clock = Clock::from_source(&src).unwrap();
        assert_eq!(clock.max_idle(), Duration::MAX);
    }

    #[test]
    fn peek_matches_advance_and_changes_nothing() {
        let src = MockFull::counter();
        let mut clock = Clock::from_source(&src).unwrap();
        src.advance(123_456_789);
        let seen = clock.peek(src.read());
        assert_eq!(clock.peek(src.read()), seen);
        assert_eq!(clock.advance(src.read()), seen);
    }

    #[test]
    fn the_slow_path_is_exact_and_saturates() {
        // The PIT's rate, whose factor is inexact so every chunk leaves a fraction, with
        // the range forced to one second so a long gap needs several chunks. The slow
        // path must agree exactly with stepping chunk by chunk, carried fraction included.
        let scale = Scale::new(1_193_182, 1).unwrap();
        let ticks = scale.max_delta() * 3 + 17;
        let carried = (1 << scale.shift()) / 3;
        let (long, long_frac) = scale.convert(ticks, carried);
        assert_ne!(long_frac, 0, "the test needs a fraction to carry");

        let mut ns = 0u64;
        let mut frac = carried;
        let mut left = ticks;
        while left > 0 {
            let s = left.min(scale.max_delta());
            let (n, f) = scale.convert(s, frac);
            ns += n;
            frac = f;
            left -= s;
        }
        assert_eq!((long, long_frac), (ns, frac));
        let exact = (u128::from(ticks) * 1_000_000_000 / 1_193_182) as u64;
        assert!(long.abs_diff(exact) <= exact / 1_000_000, "{long} vs {exact}");

        // More nanoseconds than a u64 holds saturates rather than wrapping.
        let slow = Scale::new(1, 1).unwrap();
        assert_eq!(slow.convert(u64::MAX, 0).0, u64::MAX);
    }

    #[test]
    fn the_scale_prefers_precision_within_its_range() {
        // The figures FAST_PATH_SECS's documentation quotes.
        for hz in [62_500_000, 32_768] {
            let s = Scale::new(hz, FAST_PATH_SECS).unwrap();
            assert_eq!(s.shift(), 30);
            assert_eq!(s.mult() * hz, NANOS_PER_SEC << 30, "{hz} Hz: exact factor");
        }
        for hz in [
            1,
            1_000,
            32_768,
            1_193_182,
            62_500_000,
            1_000_000_000,
            3_000_000_000,
        ] {
            let s = Scale::new(hz, FAST_PATH_SECS).unwrap();
            assert!(s.max_delta() >= hz * FAST_PATH_SECS, "{hz} Hz: range too short");
            assert!(s.shift() <= MAX_SHIFT);
            // One more bit of shift would not have covered the range, or was not allowed.
            if s.shift() < MAX_SHIFT {
                let tighter_mult = ((NANOS_PER_SEC << (s.shift() + 1)) + hz / 2) / hz;
                let frac_max = (1u64 << (s.shift() + 1)) - 1;
                assert!((u64::MAX - frac_max) / tighter_mult < hz * FAST_PATH_SECS);
            }
            // And the rate error is within a part per million.
            let (ns, _) = s.convert(hz, 0);
            assert!(ns.abs_diff(NANOS_PER_SEC) <= 1_000, "{hz} Hz: {ns}");
        }
    }

    #[test]
    fn unusable_counters_are_refused() {
        assert_eq!(Clock::new(0, 32, 0).unwrap_err(), ClockError::ZeroFrequency);
        assert_eq!(Clock::new(1_000, 0, 0).unwrap_err(), ClockError::BadWidth);
        assert_eq!(Clock::new(1_000, 65, 0).unwrap_err(), ClockError::BadWidth);
        assert_eq!(Scale::new(u64::MAX, 1).unwrap_err(), ClockError::FrequencyTooHigh);
    }
}

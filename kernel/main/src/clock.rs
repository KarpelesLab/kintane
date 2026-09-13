//! The monotonic clock, checked on the machine it will run on.
//!
//! The host tests prove the arithmetic against made-up counters. What they cannot
//! prove is that a real counter is readable, counts forwards, and was given the right
//! rate, whether that rate came from firmware on aarch64 or from calibration on x86.
//! This check measures a wait in two independent ways: with the clock, and by counting
//! timer interrupts of a known period. It fails if they disagree grossly.
//!
//! Grossly, because under emulation both depend on how the host schedules QEMU, and a
//! check that flakes under load gets ignored. The bounds are wide enough for a busy CI
//! machine and still catch every plausible real mistake: a rate wrong by a
//! factor of a thousand (Hz vs kHz), a counter that does not move, a scale that
//! overflows, or interrupts that never arrive.

use hal::{ClockSource, EarlyConsole};
use time::Clock;

use crate::Check;

/// Timer interrupts to wait through. Ten at 1-2 ms each is quick, and long enough that
/// one early or late interrupt is a small part of the total.
const TICKS: u64 = 10;

/// Consecutive raw reads checked for a backwards step.
const READS: u32 = 10_000;

/// The measured wait may be this many times shorter than the interrupts imply...
const TOO_FAST: u64 = 2;
/// ...or this many times longer, since a stalled host lengthens it without delivering
/// more interrupts.
const TOO_SLOW: u64 = 50;

pub fn check(c: &dyn EarlyConsole) -> Check {
    let Some(src) = arch::clock_source() else {
        c.write_str("no clock source on this port");
        return Check::Skipped;
    };
    c.write_str(src.name());
    c.write_str(" at ");
    write_u64(c, src.frequency_hz());
    c.write_str(" Hz");

    let mut clock = match Clock::from_source(src) {
        Ok(clock) => clock,
        Err(_) => {
            c.write_str(", which no scale can convert");
            return Check::Failed;
        }
    };

    // The clock holds time still when the counter goes backwards, so its output cannot
    // show a backwards step. Check the raw counter, which is the hardware's claim.
    let forwards = raw_counter_is_monotonic(src);
    if !forwards {
        c.write_str(", counter stepped backwards");
    }

    let t0 = clock.advance(src.read());
    let (taken, period_ns) = arch::spin_with_timer_interrupts(TICKS);
    let t1 = clock.advance(src.read());
    let elapsed = t1.saturating_duration_since(t0).as_nanos();

    c.write_str(", ");
    write_u64(c, taken);
    c.write_str(" timer interrupts over ");
    write_u64(c, elapsed / 1_000);
    c.write_str(" us");

    // After `taken` interrupts at least `taken - 1` full periods passed, since the first
    // may have arrived at once. At most `taken + 1` passed while waiting for the last.
    let least = taken.saturating_sub(1) * period_ns;
    let most = (taken + 1) * period_ns;
    let enough = taken >= TICKS;
    let advanced = elapsed > 0;
    let plausible = elapsed >= least / TOO_FAST && elapsed <= most.saturating_mul(TOO_SLOW);

    if !enough {
        c.write_str(", expected ");
        write_u64(c, TICKS);
    }
    if !advanced {
        c.write_str(", clock did not advance");
    } else if !plausible {
        c.write_str(", disagrees with the timer (");
        write_u64(c, least / 1_000);
        c.write_str("..");
        write_u64(c, most / 1_000);
        c.write_str(" us)");
    }

    let ok = forwards && enough && advanced && plausible;
    c.write_str(if ok { " ok" } else { " FAILED" });
    Check::from_ok(ok)
}

fn raw_counter_is_monotonic(src: &dyn ClockSource) -> bool {
    let mask = if src.bits() >= 64 {
        u64::MAX
    } else {
        (1u64 << src.bits()) - 1
    };
    let mut prev = src.read() & mask;
    for _ in 0..READS {
        let now = src.read() & mask;
        // A step in the upper half of the range is backwards, the same rule `Clock` uses.
        if now.wrapping_sub(prev) & mask > mask >> 1 {
            return false;
        }
        prev = now;
    }
    true
}

fn write_u64(c: &dyn EarlyConsole, mut v: u64) {
    let mut buf = [0u8; 20];
    let mut i = buf.len();
    loop {
        i -= 1;
        buf[i] = b'0' + (v % 10) as u8;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    c.write_bytes(&buf[i..]);
}

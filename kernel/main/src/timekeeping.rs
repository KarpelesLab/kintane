//! The kernel's one clock and one timer queue, and the one-shot timer programmed from
//! them.
//!
//! `kernel/time` supplies the pieces, a [`Clock`] and a [`TimerQueue`], and deliberately
//! leaves ownership and locking to someone else. This module is that owner. Each piece
//! sits behind its own lock from the kernel's lock family, with its own lock class, so
//! any thread or the timer interrupt can read the time or arm a timer. The two locks are
//! never held together, so neither is ordered against the other.
//!
//! # Tickless
//!
//! Nothing here ticks. The timer interrupt is a one-shot, armed for whichever comes
//! first: the earliest timer, or the end of the running thread's time slice when
//! another thread is waiting for the CPU. An idle CPU with one sleeper 500 ms away
//! takes one interrupt at 500 ms, not one every slice. The hardware bounds how far one
//! arming reaches: 54.9 ms for the x86 PIT, 2.15 s for the Arm generic timer at 1 GHz.
//! A deadline further away than that costs one interrupt per arming, and the hook
//! re-arms. [`Clock::max_idle`] bounds it as well, so a wrapping counter is always read
//! in time.
//!
//! The decision "is a slice needed" belongs to the scheduler, which knows who is
//! waiting. It passes the answer to [`program`].

use arch::Cpu;
use hal::ClockSource;
use sched::ThreadId;
use sync::lockdep::LockClass;
use sync::{CasOnce, LockFamily};
use time::{Clock, Duration, Instant, TimerQueue};

use crate::Locks;

/// Timers the kernel can have armed at once. Every sleeping thread holds one.
pub const TIMERS: usize = 16;

/// What a timer does when it expires: make a sleeping thread runnable.
pub type Timers = TimerQueue<ThreadId, TIMERS>;

static CLOCK_CLASS: LockClass = LockClass::new("time.clock");
static TIMERS_CLASS: LockClass = LockClass::new("time.timers");

struct Timekeeping {
    source: &'static dyn ClockSource,
    clock: Clock,
    /// The longest one arming of the timer interrupt reaches, in nanoseconds.
    max_oneshot: u64,
}

type Lock<T> = <Locks as LockFamily>::Lock<T>;

static CLOCK: CasOnce<Lock<Timekeeping>, Cpu> = CasOnce::new();
static QUEUE: CasOnce<Lock<Timers>, Cpu> = CasOnce::new();

/// Why [`init`] could not set the clock up.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Error {
    /// The port has no clock source.
    NoClock,
    /// The clock source's rate cannot be converted.
    BadRate,
    /// The port has no timer that can raise a one-shot interrupt.
    NoTimer,
}

/// Build the clock and the timer queue, and put the timer interrupt in one-shot mode.
/// Idempotent: a second call returns the first call's result without reprogramming.
///
/// # Safety
/// Interrupts must be masked, and nothing else may program the timer from here on.
pub unsafe fn init() -> Result<(), Error> {
    if CLOCK.get().is_some() {
        return Ok(());
    }
    let source = arch::clock_source().ok_or(Error::NoClock)?;
    let clock = Clock::from_source(source).map_err(|_| Error::BadRate)?;
    // SAFETY: forwarded; the caller's contract.
    let max_oneshot = unsafe { arch::tick::start_oneshot() };
    if max_oneshot == 0 {
        return Err(Error::NoTimer);
    }
    QUEUE.call_once(|| Locks::new(Timers::new(), &TIMERS_CLASS));
    CLOCK.call_once(|| {
        Locks::new(
            Timekeeping {
                source,
                clock,
                max_oneshot,
            },
            &CLOCK_CLASS,
        )
    });
    Ok(())
}

/// The current time. [`Instant::ZERO`] before [`init`] has succeeded, which no caller
/// that sleeps can observe, since sleeping needs the timer queue [`init`] creates.
pub fn now() -> Instant {
    match CLOCK.get() {
        Some(lock) => Locks::with(lock, |t| {
            let raw = t.source.read();
            t.clock.advance(raw)
        }),
        None => Instant::ZERO,
    }
}

/// Run `f` on the timer queue. `None` before [`init`].
pub fn with_timers<R>(f: impl FnOnce(&mut Timers) -> R) -> Option<R> {
    QUEUE.get().map(|lock| Locks::with(lock, f))
}

/// Arm the timer interrupt for the earliest timer, or for `slice` from now if that is
/// sooner. `slice` is `Some` when another thread is waiting for the CPU.
///
/// Returns the delay armed, in nanoseconds. Never longer than one arming can reach or
/// than the clock may go unread.
///
/// # Safety
/// Interrupts must be masked, so the handler cannot run between reading the queue and
/// programming the hardware.
pub unsafe fn program(slice: Option<Duration>) -> u64 {
    let Some(lock) = CLOCK.get() else {
        return 0;
    };
    let (now, limit) = Locks::with(lock, |t| {
        let raw = t.source.read();
        let now = t.clock.advance(raw);
        let limit = t.clock.max_idle().as_nanos().min(t.max_oneshot);
        (now, limit)
    });
    let mut delay = with_timers(|q| q.idle_budget(now, Duration::from_nanos(limit)))
        .map(|d| d.as_nanos())
        .unwrap_or(limit);
    if let Some(slice) = slice {
        delay = delay.min(slice.as_nanos());
    }
    // SAFETY: forwarded; the caller's contract, and `init` has put the timer in
    // one-shot mode, which `CLOCK` being set proves.
    unsafe { arch::tick::arm_ns(delay) };
    delay
}

/// The longest one arming reaches, in nanoseconds. Zero before [`init`].
pub fn max_oneshot() -> u64 {
    CLOCK
        .get()
        .map(|lock| Locks::with(lock, |t| t.max_oneshot))
        .unwrap_or(0)
}

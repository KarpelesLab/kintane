//! Time: the monotonic clock and timers.
//!
//! Three pieces, each usable without the others:
//!
//! * [`instant`] — [`Instant`] and [`Duration`], nanoseconds in a `u64`, with only checked and
//!   saturating arithmetic.
//! * [`clock`] — [`Clock`], which turns a hardware counter into monotonic nanoseconds with a
//!   multiply and a shift, across wraps and backwards steps.
//! * [`timer`] — [`TimerQueue`], one-shot and periodic timers in deadline order, with handles that
//!   cannot cancel the wrong timer, and the next deadline a tickless kernel needs.
//!
//! # What is not here
//!
//! Reading a counter and programming a timer interrupt. Counters are
//! `hal::ClockSource` devices supplied by the architecture or a driver. Programming
//! the interrupt for [`TimerQueue::next_deadline`] is the scheduler's tick, which
//! belongs with the code that owns the interrupt. This crate reads no hardware and
//! takes no locks, which is why all of it can be tested on the host.
//!
//! It also does not know the time of day. The origin is an arbitrary point near boot.
//! Wall-clock time is an offset applied on top, and that offset can jump when it is
//! corrected. Keeping it out of the monotonic clock is the whole point of having one.

#![cfg_attr(not(test), no_std)]
#![deny(unsafe_code)]

pub mod clock;
pub mod instant;
pub mod timer;

pub use clock::{Clock, ClockError, Scale};
pub use instant::{Duration, Instant, NANOS_PER_SEC};
pub use timer::{Expired, TimerId, TimerQueue};

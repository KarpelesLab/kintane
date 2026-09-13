//! Scheduling policy.
//!
//! This crate decides **who runs next** and nothing else. It never touches a register,
//! never switches a stack, and never masks an interrupt. That work belongs to the
//! architecture, through `hal::HasContextSwitch`, and the split is deliberate: the
//! mechanism of a context switch cannot be written generically, because which registers
//! survive a call is a fact about each ABI, while the policy of choosing a thread can be
//! written once and tested on a laptop. Keeping them apart is what lets the policy have
//! real tests at all — a scheduler whose only tests run inside an emulator is a scheduler
//! whose corner cases get tested rarely.
//!
//! It depends on nothing, not even `hal`. A run queue has no business knowing what
//! machine it is on, and the absence of that dependency is the proof that it does not.
//!
//! # The policy: fixed priority, round robin within a level
//!
//! The highest-priority runnable thread always runs. Threads of equal priority take
//! turns in arrival order. This is the policy `docs/architecture.md` names for real-time
//! and embedded builds, and it is also the right *first* scheduler for any build,
//! because its behaviour is completely predictable.
//!
//! Its well-known cost is stated rather than discovered: **a busy high-priority thread
//! starves every lower one indefinitely.** That is not a bug in this policy, it is the
//! policy. A general-purpose fair scheduler is a separate implementation that SMP builds
//! select; it does not replace this one.

#![cfg_attr(not(test), no_std)]
#![deny(unsafe_code)]

pub mod runqueue;

pub use runqueue::{Error, Priority, RunQueue, ThreadId};

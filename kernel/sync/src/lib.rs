//! Mutual exclusion, chosen by what the machine can do.
//!
//! There is one rule in this unit and everything follows from it: **a lock's
//! implementation is selected by a capability bound, and code that names a lock
//! states the hardware it is assuming in its own signature.** No `#ifdef CONFIG_SMP`
//! appears here, and neither does a runtime check for the number of CPUs.
//!
//! # The three profiles
//!
//! `docs/architecture.md` lists three, and this unit answers each with a type:
//!
//! | Machine | Type | Mechanism |
//! |---|---|---|
//! | [`hal::HasCas`] + [`hal::HasSmp`] | [`SpinLock`] | ticket lock over compare-and-swap |
//! | [`hal::HasCas`], one CPU | [`SpinLock`] | the same lock; its barriers are redundant |
//! | no CAS (therefore one CPU) | [`IrqLock`] | mask interrupts around the section |
//!
//! The first two rows share an implementation on purpose. A ticket lock is correct on
//! a uniprocessor — it is simply never contended, because the only way to reach it
//! twice is to re-enter from an interrupt handler, which is a deadlock rather than a
//! race. Writing a second, barrier-free lock for that row would double the code that
//! has to be right in exchange for one `dmb` on an uncontended acquire.
//!
//! The third row is a different mechanism, not a tuning of the first: there is no CAS
//! to build a lock out of, so exclusion comes from the fact that nothing else can run.
//!
//! # `IrqLock` and SMP
//!
//! Masking interrupts on one CPU says nothing about the other three. An `IrqLock` on a
//! multiprocessor is not a slow lock, it is not a lock at all, and the failure is
//! silent memory corruption under load. That is too serious to leave to a doc comment,
//! so [`IrqLock`] is bounded by [`UniProcessor`] — a marker an architecture asserts
//! about itself, exactly the way the capability traits in `hal` work, except that this
//! one asserts the *absence* of a capability. See that trait for what the bound does
//! and does not guarantee; the honest limits are written down there rather than
//! implied here.
//!
//! # Locking discipline
//!
//! Rules for callers, in the absence of a lock validator (`docs/coding-standards.md`
//! asks for one; it arrives with the scheduler, when there is a lock order worth
//! checking):
//!
//! 1. **A lock shared with an interrupt handler is taken with interrupts masked** —
//!    [`SpinLock::lock_irqsave`] or [`IrqLock::lock`], never [`SpinLock::lock`]. The classic
//!    deadlock is one CPU taking a lock, being interrupted, and the handler taking the same lock;
//!    no amount of spinning resolves it because the holder cannot be scheduled.
//! 2. **No lock is held across a call that can block or sleep.** Nothing in this unit sleeps;
//!    sleeping locks arrive with the scheduler and are a different type.
//! 3. **Guards are released on the CPU that took them.** Enforced: every guard here is `!Send`, so
//!    a guard cannot be moved to another thread or CPU. For the interrupt-masking guards this is a
//!    soundness requirement — a saved interrupt state belongs to the CPU that saved it — and not
//!    merely a convention.
//! 4. **Re-entering a held lock is a bug, and it is treated as one.** [`IrqLock`] detects it and
//!    stops the CPU rather than handing out a second `&mut` to the same data, which would be
//!    undefined behaviour. [`SpinLock`] cannot detect it without an owner field and deadlocks
//!    instead, like every other kernel's spinlock.
//!
//! # Memory ordering
//!
//! Stated once, here, because this is the area where being wrong passes every test we
//! can run: QEMU's TCG does not model aarch64's memory model, so a missing barrier is
//! green in CI and corrupt on silicon (`docs/testing.md#what-qemu-will-not-catch`).
//!
//! What this unit relies on:
//!
//! - **Rust's atomic orderings, not [`hal::Arch::memory_barrier`].** `Acquire` and `Release` on the
//!   lock word are what order the critical section's *ordinary* loads and stores, on every
//!   architecture, and they are honoured by the compiler as well as the hardware. `memory_barrier`
//!   is a full hardware fence for ordering the compiler's model cannot express at all — MMIO and
//!   DMA — and using it here would be both too strong and, on its own, too weak: it does not stop
//!   the optimiser hoisting a plain load out of a critical section.
//! - **Acquire on the way in, Release on the way out.** The releasing store synchronises-with the
//!   acquiring load that observes it, which is what makes the next holder see everything the
//!   previous one wrote. Every ordering in this unit is justified at its call site; none is
//!   `SeqCst`, because a lock needs pairwise synchronisation and not a total order, and `SeqCst`
//!   would hide which pairing was intended.
//! - **Nothing relies on `irq_save` being a compiler barrier.** It may well be one on every
//!   architecture we have, but that is a property of somebody else's inline assembly. Where
//!   interrupt masking is the exclusion mechanism, the flag protecting the data still carries
//!   `Acquire`/`Release` (see [`irq::IrqLock`]).
//!
//! None of this is verified by the host tests below, and it cannot be: the host is
//! x86-64 and TSO hides exactly these mistakes. It is verified by review, which is why
//! the reasoning is written down next to the code rather than kept in someone's head.
//!
//! # `unsafe`
//!
//! Allowed here by `docs/coding-standards.md`, and unavoidable: a lock is precisely a
//! safe interface over an [`UnsafeCell`](core::cell::UnsafeCell) plus a proof that
//! only one guard exists at a time. It is confined to the three lock types, every
//! block carries the invariant it depends on, and no public API is `unsafe` except
//! the marker trait, whose unsafety *is* the point.

// `no_std` except under the host test harness, which needs `std` to link `libtest`.
#![cfg_attr(not(test), no_std)]

pub mod irq;
pub mod once;
pub mod spin;

#[cfg(test)]
mod testing;

/// Re-exported from `hal`, where the capability traits live.
///
/// It was first written here, next to its only user, which made it unimplementable by
/// any real architecture — see the note on its definition. The bound keeps its name,
/// so nothing else in this unit changed when it moved.
pub use hal::UniProcessor;
pub use irq::{IrqGuard, IrqLock, IrqLockGuard};
pub use once::{CasGate, CasOnce, Claim, IrqGate, IrqOnce, Once, OnceGate};
pub use spin::{SpinGuard, SpinIrqGuard, SpinLock};

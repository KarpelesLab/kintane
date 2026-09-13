//! Which lock a channel takes, chosen by what the machine can do.
//!
//! `sync` offers two exclusion mechanisms and states the hardware each assumes in its
//! bound: [`SpinLock`] needs [`HasCas`], [`IrqLock`] needs [`UniProcessor`]. A lock
//! used directly names one of them. A *generic subsystem* — this one — cannot, because
//! it does not know which machine it is being built for, and it cannot pick by bound
//! either:
//!
//! - `impl<A: HasCas> Channel<A>` and `impl<A: UniProcessor> Channel<A>` with the same method names
//!   are rejected (E0592 / E0119). Coherence ignores where-clauses, and a machine with both
//!   capabilities — an ARMv7-M part, uniprocessor with CAS — is real, so the impls genuinely
//!   overlap. Picking "CAS wins" is specialisation, which is not available.
//!
//! That is exactly the problem `sync::Once` already met, and this module answers it the
//! same way `sync::OnceGate` does: the mechanism is a **type parameter naming a lock
//! family**, and the family's own bound checks it against the architecture.
//!
//! ```text
//! Channel<Spin<A>, ..>   A: Arch + HasCas     — ticket spinlock, interrupts masked
//! Channel<Irq<A>, ..>    A: UniProcessor      — interrupt mask is the whole lock
//! ```
//!
//! The choice therefore propagates upward as a type parameter until something that is
//! allowed to name the architecture — the kernel image — names it once. A subsystem
//! never decides; it only states that it needs *some* exclusion.
//!
//! # Why this lives here and should not
//!
//! Every generic subsystem that locks will need this same trait, and each writing its
//! own is how two subsystems end up disagreeing about whether a spinlock masks
//! interrupts. It belongs in `sync` beside `OnceGate`. It is here only because this
//! change does not own `sync`; moving it is mechanical.
//!
//! # Interrupts
//!
//! Both families take the lock with interrupts masked on the running CPU. For
//! [`IrqLock`] that is the mechanism; for [`SpinLock`] it is
//! [`SpinLock::lock_irqsave`], chosen because a channel is a plausible thing for an
//! interrupt handler to send on (a driver posting an event), and `sync`'s locking
//! discipline rule 1 is that such a lock is always taken with interrupts masked. The
//! families would otherwise differ in whether a send from a handler deadlocks, which is
//! not a difference a caller of a generic channel could reason about.

use core::marker::PhantomData;

use hal::{Arch, HasCas, UniProcessor};
use sync::{IrqLock, SpinLock};

/// A way of protecting a value, selected by architecture capability.
///
/// Sealed: the set of exclusion mechanisms is `sync`'s decision, not a caller's.
pub trait LockFamily: sealed::Sealed + 'static {
    /// The lock type this family uses for a value of type `T`.
    type Lock<T: Send>: Send + Sync;

    /// Wrap `value` in an unlocked lock.
    fn new<T: Send>(value: T) -> Self::Lock<T>;

    /// Run `f` with exclusive access to the protected value.
    ///
    /// Scoped rather than guard-returning so the two families present one shape, and so
    /// no guard can escape to be held across something that must not run under a lock.
    /// `f` must not re-enter the same lock: on [`Irq`] that stops the CPU, on [`Spin`] it
    /// deadlocks.
    fn with<T: Send, R>(lock: &Self::Lock<T>, f: impl FnOnce(&mut T) -> R) -> R;
}

mod sealed {
    /// Not nameable outside this crate.
    pub trait Sealed {}
}

/// Ticket spinlock, taken with interrupts masked. Any machine with compare-and-swap.
pub struct Spin<A>(PhantomData<fn() -> A>);

impl<A: Arch + HasCas> sealed::Sealed for Spin<A> {}

impl<A: Arch + HasCas> LockFamily for Spin<A> {
    type Lock<T: Send> = SpinLock<T, A>;

    fn new<T: Send>(value: T) -> SpinLock<T, A> {
        SpinLock::new(value)
    }

    fn with<T: Send, R>(lock: &SpinLock<T, A>, f: impl FnOnce(&mut T) -> R) -> R {
        let mut guard = lock.lock_irqsave();
        f(&mut guard)
    }
}

/// Interrupt masking as the whole lock. Only machines asserting [`UniProcessor`].
pub struct Irq<A>(PhantomData<fn() -> A>);

impl<A: UniProcessor> sealed::Sealed for Irq<A> {}

impl<A: UniProcessor> LockFamily for Irq<A> {
    type Lock<T: Send> = IrqLock<T, A>;

    fn new<T: Send>(value: T) -> IrqLock<T, A> {
        IrqLock::new(value)
    }

    fn with<T: Send, R>(lock: &IrqLock<T, A>, f: impl FnOnce(&mut T) -> R) -> R {
        let mut guard = lock.lock();
        f(&mut guard)
    }
}

//! A lock chosen by what the machine can do, for code that does not know the machine.
//!
//! This unit offers two exclusion mechanisms and states the hardware each assumes in
//! its bound: [`SpinLock`] needs [`HasCas`], [`IrqLock`] needs [`UniProcessor`]. A lock
//! used directly names one of them. A *generic subsystem* cannot, because it does not
//! know which machine it is being built for, and it cannot pick by bound either:
//!
//! - `impl<A: HasCas> Channel<A>` and `impl<A: UniProcessor> Channel<A>` with the same method names
//!   are rejected (E0592 / E0119). Coherence ignores where-clauses, and a machine with both
//!   capabilities — an ARMv7-M part, uniprocessor with CAS — is real, so the impls genuinely
//!   overlap. Picking "CAS wins" is specialisation, which is not available.
//!
//! That is the problem [`crate::Once`] already met, answered the same way
//! [`crate::OnceGate`] answers it: the mechanism is a **type parameter naming a lock
//! family**, and the family's own bound checks it against the architecture.
//!
//! ```text
//! Subsystem<Spin<A>>   A: Arch + HasCas     — ticket spinlock, interrupts masked
//! Subsystem<Irq<A>>    A: UniProcessor      — interrupt mask is the whole lock
//! ```
//!
//! The choice propagates upward as a type parameter until something that is allowed to
//! name the architecture — the kernel image — names it once. A subsystem never decides;
//! it only states that it needs *some* exclusion.
//!
//! It lives here rather than in the first subsystem that needed it (`ipc`, which wrote
//! it first) because every generic subsystem that locks needs the same trait. Each
//! writing its own is how two subsystems end up disagreeing about whether a spinlock
//! masks interrupts.
//!
//! # Interrupts
//!
//! Both families run the critical section with interrupts masked on the running CPU.
//! For [`IrqLock`] that is the mechanism; for [`SpinLock`] it is
//! [`SpinLock::lock_irqsave`]. A generic subsystem cannot know whether some interrupt
//! handler will one day take its lock, and locking discipline rule 1 (crate docs) says
//! such a lock is always taken masked. Without this the families would differ in whether
//! a caller from a handler deadlocks, which is not a difference generic code could reason
//! about.
//!
//! # Classes
//!
//! [`LockFamily::new`] takes a [`LockClass`]: every lock a generic subsystem creates is
//! one lock-order checking can see. See [`crate::lockdep`].

use core::marker::PhantomData;

use hal::UniProcessor;
#[cfg(target_has_atomic = "32")]
use hal::{Arch, HasCas};

use crate::IrqLock;
use crate::lockdep::LockClass;
#[cfg(target_has_atomic = "32")]
use crate::spin::SpinLock;

/// A way of protecting a value, selected by architecture capability.
///
/// Sealed: the set of exclusion mechanisms is this unit's decision, not a caller's.
pub trait LockFamily: sealed::Sealed + 'static {
    /// The lock type this family uses for a value of type `T`.
    type Lock<T: Send>: Send + Sync;

    /// Wrap `value` in an unlocked lock of class `class`.
    fn new<T: Send>(value: T, class: &'static LockClass) -> Self::Lock<T>;

    /// Run `f` with exclusive access to the protected value.
    ///
    /// Scoped rather than guard-returning so the two families present one shape, and so
    /// no guard can escape to be held across something that must not run under a lock.
    /// `f` must not re-enter the same lock: on [`Irq`] that stops the CPU; on [`Spin`] it
    /// deadlocks, or stops the CPU when lock-order checking is built in.
    fn with<T: Send, R>(lock: &Self::Lock<T>, f: impl FnOnce(&mut T) -> R) -> R;
}

mod sealed {
    /// Not nameable outside this crate.
    pub trait Sealed {}
}

/// Ticket spinlock, taken with interrupts masked. Any machine with compare-and-swap.
#[cfg(target_has_atomic = "32")]
pub struct Spin<A>(PhantomData<fn() -> A>);

#[cfg(target_has_atomic = "32")]
impl<A: Arch + HasCas> sealed::Sealed for Spin<A> {}

#[cfg(target_has_atomic = "32")]
impl<A: Arch + HasCas> LockFamily for Spin<A> {
    type Lock<T: Send> = SpinLock<T, A>;

    fn new<T: Send>(value: T, class: &'static LockClass) -> SpinLock<T, A> {
        SpinLock::with_class(value, class)
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

    fn new<T: Send>(value: T, class: &'static LockClass) -> IrqLock<T, A> {
        IrqLock::with_class(value, class)
    }

    fn with<T: Send, R>(lock: &IrqLock<T, A>, f: impl FnOnce(&mut T) -> R) -> R {
        let mut guard = lock.lock();
        f(&mut guard)
    }
}

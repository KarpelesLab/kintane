//! Exclusion by masking interrupts.
//!
//! Two things live here, and they are not the same thing:
//!
//! - [`IrqGuard`] — an RAII interrupt mask. Available on *every* architecture, because every
//!   architecture can mask its own interrupts. It gives exclusion against interrupt handlers **on
//!   the CPU it runs on**, and nothing more. On a multiprocessor that is still useful and still
//!   necessary: it is half of [`SpinLock::lock_irqsave`](crate::SpinLock::lock_irqsave), the other
//!   half being a lock that handles the other CPUs.
//! - [`IrqLock`] — a whole lock built out of nothing but that mask, for machines with no
//!   compare-and-swap to build a real one from. Correct only where the mask is the whole story,
//!   which is why it is bounded by [`UniProcessor`] rather than by [`Arch`].
//!
//! Confusing the two is the bug the bound exists to prevent.

use core::cell::UnsafeCell;
use core::marker::PhantomData;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicBool, Ordering};

use hal::Arch;

use crate::UniProcessor;

/// Interrupts masked on this CPU until this value is dropped.
///
/// Nests correctly: each guard restores the state it found rather than blindly
/// enabling interrupts, so an inner guard dropped inside an outer critical section
/// leaves interrupts masked. Restoring unconditionally is a classic way to re-enable
/// interrupts in the middle of someone else's critical section.
///
/// `!Send`, and that is a soundness property rather than a lint: [`Arch::irq_restore`]
/// requires the state to be restored on the CPU that saved it, and a guard that could
/// be moved to another thread could not promise that.
pub struct IrqGuard<A: Arch> {
    state: A::IrqState,
    /// Removes `Send` (and `Sync`, which a guard has no use for). A raw pointer is the
    /// stable way to say this; `impl !Send` is not stable and is not on the permitted
    /// features list in `toolchain.toml`.
    _not_send: PhantomData<*const ()>,
}

impl<A: Arch> IrqGuard<A> {
    /// Mask interrupts on this CPU, remembering whether they were enabled.
    #[must_use = "interrupts are unmasked again the instant the guard is dropped"]
    pub fn mask() -> Self {
        IrqGuard {
            state: A::irq_save(),
            _not_send: PhantomData,
        }
    }
}

impl<A: Arch> Drop for IrqGuard<A> {
    fn drop(&mut self) {
        // SAFETY: `state` came from the `irq_save` in `mask`, which is the only
        // constructor. It is restored exactly once, because `Drop::drop` runs once and
        // the field is not `Copy`-able out of the guard by anyone else. It is restored
        // on the CPU that saved it, because the guard is `!Send` and so cannot have
        // crossed to another thread or CPU between the two calls.
        unsafe { A::irq_restore(self.state) };
    }
}

/// A lock whose entire mechanism is "nothing else can run".
///
/// On a machine with one CPU and no compare-and-swap, this is the only mutual
/// exclusion available: masking interrupts stops the only other thing that could
/// observe the data — an interrupt handler on this same CPU. There is no atomic
/// read-modify-write anywhere in this type, because the targets it exists for do not
/// have one. `held` is written with plain atomic stores, which ARMv6-M and `rv32i`
/// both have.
///
/// # Not a spinlock
///
/// It never spins, it cannot block, and acquiring it is a handful of instructions.
/// It is also not a lock in any sense that survives a second CPU appearing, which is
/// what [`UniProcessor`] is for. See that trait for exactly how much the bound
/// guarantees.
///
/// # Re-entering it
///
/// Interrupts are masked for the whole critical section, so the only way to arrive at
/// `lock` while the lock is held is to call it from inside its own critical section.
/// That would hand out a second `&mut` to the same data, which is undefined behaviour,
/// so it stops the CPU instead ([`Arch::halt`]). This is the narrow definition of a
/// panic in `docs/coding-standards.md` — an invariant is broken and continuing would
/// be unsafe — expressed in the only way available to code that may not call `panic!`.
/// [`IrqLock::try_lock`] is there for callers who would rather find out than die.
pub struct IrqLock<T, A: UniProcessor> {
    /// Recursion detection only. It is not what provides exclusion — the interrupt
    /// mask is — and on an SMP machine it would provide nothing at all, since two
    /// CPUs can both read `false` before either writes `true`. That is exactly the
    /// race [`UniProcessor`] asserts cannot happen.
    held: AtomicBool,
    data: UnsafeCell<T>,
    /// `fn() -> A` rather than `A`: the architecture is a tag, never stored, and the
    /// lock's auto traits should not depend on what the marker type happens to be.
    _arch: PhantomData<fn() -> A>,
}

// SAFETY: the only path to `&T` or `&mut T` is through a guard, and a guard can only
// exist while interrupts are masked on the single CPU this architecture has (asserted
// by `UniProcessor`), so at most one guard exists at a time. Sharing the lock between
// contexts therefore only ever moves the `T` between them, which is what `T: Send`
// means. `T: Sync` is not required, because two references never coexist.
unsafe impl<T: Send, A: UniProcessor> Sync for IrqLock<T, A> {}
// SAFETY: moving the lock moves the `T` inside it, and nothing else.
unsafe impl<T: Send, A: UniProcessor> Send for IrqLock<T, A> {}

impl<T, A: UniProcessor> IrqLock<T, A> {
    /// A new, unlocked lock. `const`, so it can be a `static` without an initialiser
    /// running first — which matters, since this is a type for machines whose whole
    /// heap may be a few kilobytes.
    pub const fn new(value: T) -> Self {
        IrqLock {
            held: AtomicBool::new(false),
            data: UnsafeCell::new(value),
            _arch: PhantomData,
        }
    }

    /// Mask interrupts and take the lock.
    ///
    /// Stops the CPU if the lock is already held; see the type's documentation.
    pub fn lock(&self) -> IrqLockGuard<'_, T, A> {
        match self.try_lock() {
            Some(g) => g,
            // Reached only by re-entering the critical section from inside itself:
            // with interrupts masked, nothing else on this machine runs.
            None => A::halt(),
        }
    }

    /// Mask interrupts and take the lock, or give the interrupts back and return
    /// `None` if it is already held.
    pub fn try_lock(&self) -> Option<IrqLockGuard<'_, T, A>> {
        // Mask first. Testing the flag with interrupts enabled would leave a window
        // between the test and the set in which an interrupt handler could take the
        // lock, which is the race this whole type is meant not to have.
        let irq = IrqGuard::mask();

        // `Acquire`/`Release` on `held` rather than `Relaxed`. On one CPU the hardware
        // needs no barrier — but the *compiler* does: `Relaxed` orders nothing, so the
        // optimiser would be free to sink a store from inside the critical section
        // past the release of the flag, where a handler that then took the lock could
        // see stale data. This does not rest on `irq_save` happening to be a compiler
        // barrier in the architecture's inline assembly (see the crate docs).
        if self.held.load(Ordering::Acquire) {
            return None;
        }
        // Plain `Relaxed`: this store publishes nothing — the data it guards is
        // written *after* it — and the acquire above has already fenced the critical
        // section from what came before.
        self.held.store(true, Ordering::Relaxed);

        Some(IrqLockGuard {
            lock: self,
            _irq: irq,
            _not_send: PhantomData,
        })
    }

    /// Whether the lock is currently held. For assertions and diagnostics only: by the
    /// time a caller acts on the answer it can be stale, unless the caller is itself
    /// the holder.
    pub fn is_locked(&self) -> bool {
        self.held.load(Ordering::Relaxed)
    }
}

/// Exclusive access to an [`IrqLock`]'s contents, with interrupts masked.
///
/// Dropping it releases the lock and *then* restores the interrupt state, in that
/// order — the reverse would leave a window where a handler could take a lock the
/// interrupted code still thinks it holds.
#[must_use = "the lock is released and interrupts unmasked the instant this is dropped"]
pub struct IrqLockGuard<'a, T, A: UniProcessor> {
    lock: &'a IrqLock<T, A>,
    /// Dropped after this guard's own `Drop::drop` body has released the lock, because
    /// Rust runs the explicit destructor before the fields'.
    _irq: IrqGuard<A>,
    /// See [`IrqGuard`]: an interrupt state may only be restored on the CPU that saved
    /// it, so neither the mask nor anything holding one may cross threads.
    _not_send: PhantomData<*const ()>,
}

impl<T, A: UniProcessor> Deref for IrqLockGuard<'_, T, A> {
    type Target = T;

    fn deref(&self) -> &T {
        // SAFETY: the guard exists, so the lock is held and interrupts are masked on
        // the machine's only CPU; no other reference to the data can exist while it
        // does, and the borrow checker ties this `&T` to the guard's lifetime.
        unsafe { &*self.lock.data.get() }
    }
}

impl<T, A: UniProcessor> DerefMut for IrqLockGuard<'_, T, A> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: as `deref`, and `&mut self` proves this is the only outstanding
        // borrow *of the guard*, which is the only path to the data.
        unsafe { &mut *self.lock.data.get() }
    }
}

impl<T, A: UniProcessor> Drop for IrqLockGuard<'_, T, A> {
    fn drop(&mut self) {
        // `Release` publishes everything written inside the critical section to
        // whoever acquires the flag next — on this machine, an interrupt handler on
        // this CPU. It also stops the compiler from sinking those writes past here.
        self.lock.held.store(false, Ordering::Release);
        // `_irq` is dropped immediately after this body returns, unmasking interrupts.
    }
}

#[cfg(test)]
mod tests {
    use hal::mock::{MockFull, MockTiny};

    use super::*;
    use crate::testing::{interrupts_enabled, serial};

    // Every test in this module asserts on interrupt state, and the mocks keep that
    // state in a process-wide static (`hal/src/mock.rs`). The test harness runs tests
    // on several threads, so they take `serial()` — a shared flag is exactly the thing
    // that cannot be tested in parallel.

    #[test]
    fn a_mask_nests_and_restores_what_it_found_full() {
        let _s = serial();
        assert!(interrupts_enabled::<MockFull>());
        {
            let _outer = IrqGuard::<MockFull>::mask();
            assert!(!interrupts_enabled::<MockFull>());
            {
                let _inner = IrqGuard::<MockFull>::mask();
                assert!(!interrupts_enabled::<MockFull>());
            }
            // The inner guard restored "masked", not "enabled". Getting this wrong
            // re-enables interrupts inside someone else's critical section.
            assert!(!interrupts_enabled::<MockFull>());
        }
        assert!(interrupts_enabled::<MockFull>());
    }

    #[test]
    fn a_mask_nests_and_restores_what_it_found_tiny() {
        let _s = serial();
        assert!(interrupts_enabled::<MockTiny>());
        {
            let _outer = IrqGuard::<MockTiny>::mask();
            assert!(!interrupts_enabled::<MockTiny>());
            {
                let _inner = IrqGuard::<MockTiny>::mask();
                assert!(!interrupts_enabled::<MockTiny>());
            }
            assert!(!interrupts_enabled::<MockTiny>());
        }
        assert!(interrupts_enabled::<MockTiny>());
    }

    // `IrqLock` is instantiated only with `MockTiny`. `IrqLock<u32, MockFull>` does not
    // compile — `MockFull` implements `HasSmp` and has not asserted `UniProcessor` —
    // and that missing test is the guarantee this unit is here to provide.

    #[test]
    fn uncontended_acquire_and_release_tiny() {
        let _s = serial();
        let lock: IrqLock<u32, MockTiny> = IrqLock::new(7);
        assert!(!lock.is_locked());
        assert!(interrupts_enabled::<MockTiny>());

        let mut g = lock.lock();
        assert_eq!(*g, 7);
        *g = 9;
        assert!(lock.is_locked());
        // The critical section runs with interrupts masked; that *is* the exclusion.
        assert!(!interrupts_enabled::<MockTiny>());

        drop(g);
        assert!(!lock.is_locked());
        assert!(interrupts_enabled::<MockTiny>());
        assert_eq!(*lock.lock(), 9);
        assert!(interrupts_enabled::<MockTiny>());
    }

    #[test]
    fn the_guard_releases_on_drop_even_when_it_is_a_temporary_tiny() {
        let _s = serial();
        let lock: IrqLock<u32, MockTiny> = IrqLock::new(1);
        // A temporary guard is dropped at the end of the statement; if the interrupt
        // state were not restored there, this second statement would run masked.
        assert_eq!(*lock.lock(), 1);
        assert!(interrupts_enabled::<MockTiny>());
        assert!(!lock.is_locked());
    }

    #[test]
    fn try_lock_reports_a_held_lock_and_gives_the_interrupts_back_tiny() {
        let _s = serial();
        let lock: IrqLock<u32, MockTiny> = IrqLock::new(0);
        let held = lock.lock();
        // A failed `try_lock` must not leave interrupts masked: it takes the mask to
        // test the flag, so the early return has to drop it.
        assert!(lock.try_lock().is_none());
        assert!(!interrupts_enabled::<MockTiny>(), "the first guard is still held");
        drop(held);
        assert!(interrupts_enabled::<MockTiny>());
        assert!(lock.try_lock().is_some());
        assert!(interrupts_enabled::<MockTiny>());
    }

    #[test]
    fn re_entering_the_lock_stops_the_cpu_tiny() {
        let _s = serial();
        let lock: IrqLock<u32, MockTiny> = IrqLock::new(0);
        let _held = lock.lock();
        // `MockTiny::halt()` panics, which is how a host test observes "this CPU
        // stopped". In a kernel image it does not return at all, so the alternative
        // — handing out a second `&mut` to the same data — never happens either way.
        // The hook is silenced so an expected stop does not print a backtrace into an
        // otherwise green run; `serial()` keeps that from affecting other tests.
        let previous = std::panic::take_hook();
        std::panic::set_hook(std::boxed::Box::new(|_| {}));
        let stopped = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _second = lock.lock();
        }));
        std::panic::set_hook(previous);
        assert!(stopped.is_err(), "a recursive lock must not be handed out");
    }
}

//! A ticket spinlock, for machines that have compare-and-swap.
//!
//! # Why a ticket lock
//!
//! The alternative considered was test-and-test-and-set: spin on a relaxed load until
//! the word looks free, then try one CAS. It is smaller, and uncontended it is one
//! CAS either way. The ticket lock was chosen anyway, for one reason:
//!
//! **Acquisition is FIFO, so waiting is bounded.** Under contention a TTAS lock hands
//! the lock to whichever CPU's CAS happens to land first, and a CPU can lose that race
//! arbitrarily many times — on a machine where one core is closer to the cache line
//! than the others, systematically so. In a kernel that matters more than in an
//! application, because [`SpinLock::lock_irqsave`] spins with interrupts masked: an
//! unbounded wait for the lock is an unbounded interrupt latency, and interrupt
//! latency is a number this project intends to be able to state.
//!
//! What that costs, stated rather than discovered later:
//!
//! - Every waiter spins on the same cache line (`now_serving`), so a release invalidates it on all
//!   of them: O(n) coherence traffic per handoff. An MCS lock fixes this by giving each waiter its
//!   own line to spin on, at the price of a per-waiter queue node — which needs either an allocator
//!   or per-CPU storage, and this unit is below both. It is the right upgrade when a lock shows up
//!   in a profile, not before.
//! - A ticket lock cannot be abandoned: a holder that is descheduled stalls everyone behind it.
//!   Kernel spinlocks are held with preemption disabled, so this does not apply here, and it is why
//!   this type must never be handed to userspace.
//! - Two words instead of one.
//!
//! # Which machines get this
//!
//! Anything with [`HasCas`], whether or not it has [`hal::HasSmp`]. On a uniprocessor
//! the lock is never contended — the only way to reach it twice is from an interrupt
//! handler, and that is a deadlock rather than a race — so the acquire/release
//! barriers it emits are redundant. They are also nearly free, and the alternative is
//! a second implementation of the same algorithm whose only difference is which
//! barriers it omits. One lock that is right on both is worth more than two locks that
//! are each right on one.

use core::cell::UnsafeCell;
use core::hint::spin_loop;
use core::marker::PhantomData;
use core::ops::{Deref, DerefMut};
use core::ptr;
use core::sync::atomic::{AtomicUsize, Ordering};

use hal::{Arch, HasCas};

use crate::irq::IrqGuard;
use crate::lockdep::{self, ClassTag, LockClass};

/// A mutual-exclusion lock that spins, built on compare-and-swap.
///
/// # Interrupts
///
/// [`SpinLock::lock`] does not touch the interrupt mask, which makes it the wrong
/// choice for any lock an interrupt handler also takes: the handler interrupts the
/// holder, spins for a lock the holder cannot release, and the CPU is gone. Use
/// [`SpinLock::lock_irqsave`] for those, and see the crate-level locking discipline.
pub struct SpinLock<T, A: Arch + HasCas> {
    /// The next ticket to hand out.
    next: AtomicUsize,
    /// The ticket whose turn it is. Only the holder writes this.
    now_serving: AtomicUsize,
    /// Its lock-order class. Zero-sized in a build without lock-order checking.
    class: ClassTag,
    data: UnsafeCell<T>,
    /// `fn() -> A` rather than `A`: a tag, never stored, and the lock's auto traits
    /// should not depend on what the marker type happens to be.
    _arch: PhantomData<fn() -> A>,
}

// SAFETY: the only path to the data is a guard, and the ticket protocol below hands
// out at most one guard at a time (`now_serving` names exactly one ticket, and the
// holder is the only writer of it). Sharing the lock therefore only ever moves the `T`
// between threads, which is what `T: Send` means; `T: Sync` is not required because
// two references to the data never coexist.
unsafe impl<T: Send, A: Arch + HasCas> Sync for SpinLock<T, A> {}
// SAFETY: moving the lock moves the `T` inside it, and nothing else.
unsafe impl<T: Send, A: Arch + HasCas> Send for SpinLock<T, A> {}

impl<T, A: Arch + HasCas> SpinLock<T, A> {
    /// A new, unlocked lock that lock-order checking does not see. `const`, so it can
    /// be a `static` with no initialiser.
    pub const fn new(value: T) -> Self {
        Self::build(value, None)
    }

    /// A new, unlocked lock of class `class`, checked for lock order in debug builds.
    pub const fn with_class(value: T, class: &'static LockClass) -> Self {
        Self::build(value, Some(class))
    }

    const fn build(value: T, class: Option<&'static LockClass>) -> Self {
        SpinLock {
            next: AtomicUsize::new(0),
            now_serving: AtomicUsize::new(0),
            class: ClassTag::new(class),
            data: UnsafeCell::new(value),
            _arch: PhantomData,
        }
    }

    /// This lock's identity for lock-order checking. Stable while it matters: a held
    /// lock is borrowed by its guard, so it cannot move.
    fn instance(&self) -> usize {
        ptr::from_ref(self).addr()
    }

    /// Take the lock, spinning until it is this caller's turn.
    ///
    /// Leaves interrupts alone; see the type's documentation for when that is wrong.
    pub fn lock(&self) -> SpinGuard<'_, T, A> {
        // Before drawing a ticket: re-taking a held lock is caught here and stops the
        // CPU, instead of spinning for ever below. A no-op without a class.
        lockdep::acquire::<A>(&self.class, self.instance());

        // `Relaxed` on the ticket draw. Drawing a ticket orders nothing by itself and
        // publishes nothing: it is a queue position, and the data the lock guards is
        // not touched until the wait below succeeds. The synchronisation happens
        // entirely at that `Acquire` load.
        //
        // `fetch_add` wraps, which is correct rather than merely accepted: tickets are
        // modular and only their difference is meaningful, so the protocol survives
        // `usize` wrapping as long as fewer than `usize::MAX` waiters queue at once.
        let ticket = self.next.fetch_add(1, Ordering::Relaxed);

        // `Acquire`, and this is the load the whole type depends on. It synchronises
        // with the `Release` store in `SpinGuard::drop`, which is what makes
        // everything the previous holder wrote inside its critical section visible
        // here. `Relaxed` would pass every test we can run — the host is x86 and QEMU's
        // TCG does not model aarch64's memory model — and would corrupt data on real
        // ARM silicon. See `docs/testing.md#what-qemu-will-not-catch`.
        while self.now_serving.load(Ordering::Acquire) != ticket {
            // A hint, not a barrier: `yield` on aarch64, `pause` on x86. It exists to
            // stop the core burning issue slots and power while it waits.
            spin_loop();
        }

        SpinGuard {
            lock: self,
            ticket,
            _not_send: PhantomData,
        }
    }

    /// Take the lock if it is free right now, without spinning.
    pub fn try_lock(&self) -> Option<SpinGuard<'_, T, A>> {
        // The lock is free exactly when nobody is queued, i.e. `next == now_serving`.
        // `Relaxed` here because this load only chooses which ticket to bid for; the
        // bid itself is the compare-exchange, and that is where the ordering lives.
        let ticket = self.now_serving.load(Ordering::Relaxed);

        // `Acquire` on success, for the same reason as the wait loop above: it is this
        // operation that publishes the previous holder's writes to us. `Acquire` on
        // failure costs nothing and keeps one rule instead of two; nothing is read
        // from the lock on the failure path.
        self.next
            .compare_exchange(ticket, ticket.wrapping_add(1), Ordering::Acquire, Ordering::Acquire)
            .ok()
            .map(|_| {
                lockdep::acquire_try::<A>(&self.class, self.instance());
                SpinGuard {
                    lock: self,
                    ticket,
                    _not_send: PhantomData,
                }
            })
    }

    /// Mask interrupts on this CPU, then take the lock.
    ///
    /// This is the form to use for any lock that is also taken by an interrupt
    /// handler, and it is why [`IrqGuard`] is a separate type from [`crate::IrqLock`]: on a
    /// multiprocessor both halves are needed, one for this CPU's handlers and one for
    /// the other CPUs.
    ///
    /// Interrupts stay masked for as long as the guard lives, so the critical section
    /// should be short — this is the code that decides the machine's interrupt
    /// latency.
    pub fn lock_irqsave(&self) -> SpinIrqGuard<'_, T, A> {
        // Mask first, then spin. The other order is the classic deadlock: an interrupt
        // arriving between acquiring and masking runs a handler that waits for a lock
        // this CPU already holds.
        let irq = IrqGuard::mask();
        SpinIrqGuard {
            guard: self.lock(),
            _irq: irq,
        }
    }

    /// Whether the lock is held. For assertions and diagnostics: the answer is stale
    /// the moment it is returned, unless the caller is the holder.
    pub fn is_locked(&self) -> bool {
        self.next.load(Ordering::Relaxed) != self.now_serving.load(Ordering::Relaxed)
    }
}

impl<A: Arch + HasCas> SpinLock<(), A> {
    /// Take the lock with no guard, for a critical section one thread enters and another
    /// leaves.
    ///
    /// That is a scheduler's lock: taken by the thread that switches away, held across the
    /// context switch it protects, and released by whichever thread the switch resumes. A
    /// guard cannot express that, because the guard belongs to the first thread's stack
    /// and the release happens on the second's. So this lock holds no data, and the
    /// critical section is bracketed by this and [`SpinLock::unlock_handoff`].
    ///
    /// Spins with interrupts as they are, like [`SpinLock::lock`]. A lock an interrupt
    /// handler also takes must be taken with interrupts already masked.
    pub fn lock_handoff(&self) {
        core::mem::forget(self.lock());
    }

    /// Release a lock taken with [`SpinLock::lock_handoff`].
    ///
    /// # Safety
    /// The lock must be held through a `lock_handoff` whose critical section this ends,
    /// and the release must happen on the CPU that took it: lock-order checking keeps its
    /// held locks per CPU, and a thread switched to on the same CPU is the only other
    /// thread that may end the section.
    pub unsafe fn unlock_handoff(&self) {
        lockdep::release::<A>(&self.class, self.instance());
        // The holder is the only writer of `now_serving`, and it observed its own ticket
        // there through the `Acquire` load that admitted it, so this read-modify-write
        // reads the value it is about to replace. `Release` for the same reason as
        // `SpinGuard::drop`.
        let serving = self.now_serving.load(Ordering::Relaxed);
        self.now_serving
            .store(serving.wrapping_add(1), Ordering::Release);
    }
}

/// Exclusive access to a [`SpinLock`]'s contents. Releases the lock when dropped.
///
/// `!Send`: a lock released from a different CPU than took it is a lock whose
/// critical section spanned two CPUs, which is never what the caller meant.
#[must_use = "the lock is released the instant the guard is dropped"]
pub struct SpinGuard<'a, T, A: Arch + HasCas> {
    lock: &'a SpinLock<T, A>,
    /// The ticket this guard holds. Kept so that releasing is a single store of a
    /// value we already know, rather than a read-modify-write of `now_serving`.
    ticket: usize,
    _not_send: PhantomData<*const ()>,
}

impl<T, A: Arch + HasCas> Deref for SpinGuard<'_, T, A> {
    type Target = T;

    fn deref(&self) -> &T {
        // SAFETY: this guard exists, so `now_serving` names this guard's ticket and no
        // other guard for this lock can exist until `drop` advances it. The borrow
        // checker ties the returned reference to the guard's lifetime, so it cannot
        // outlive the critical section.
        unsafe { &*self.lock.data.get() }
    }
}

impl<T, A: Arch + HasCas> DerefMut for SpinGuard<'_, T, A> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: as `deref`, plus `&mut self`, which proves this is the only
        // outstanding borrow of the guard — and the guard is the only path to the data.
        unsafe { &mut *self.lock.data.get() }
    }
}

impl<T, A: Arch + HasCas> Drop for SpinGuard<'_, T, A> {
    fn drop(&mut self) {
        // While still held. Released first, another CPU could take the lock and report
        // it before this record is gone.
        lockdep::release::<A>(&self.lock.class, self.lock.instance());

        // `Release`: everything written inside the critical section must be visible to
        // the next holder *before* it observes its turn, and this store is what that
        // holder's `Acquire` load synchronises with. This is the one line where a
        // wrong ordering is invisible on x86 (its stores are already release-ordered)
        // and fatal on aarch64.
        //
        // A plain store is enough — no read-modify-write — because only the holder
        // ever writes `now_serving`, and there is exactly one holder.
        self.lock
            .now_serving
            .store(self.ticket.wrapping_add(1), Ordering::Release);
    }
}

/// Exclusive access to a [`SpinLock`]'s contents with interrupts masked on this CPU.
///
/// Dropping it releases the lock and then restores the interrupt state, in that order.
/// Doing it the other way round would leave a window in which a handler could run and
/// take a lock the interrupted code believes it still holds.
#[must_use = "the lock is released and interrupts unmasked the instant this is dropped"]
pub struct SpinIrqGuard<'a, T, A: Arch + HasCas> {
    /// Dropped first: Rust drops fields in declaration order, so the lock is released
    /// before the interrupts come back. The order is load-bearing, which is why these
    /// two are fields of one struct rather than two locals the caller must sequence.
    guard: SpinGuard<'a, T, A>,
    _irq: IrqGuard<A>,
}

impl<T, A: Arch + HasCas> Deref for SpinIrqGuard<'_, T, A> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.guard
    }
}

impl<T, A: Arch + HasCas> DerefMut for SpinIrqGuard<'_, T, A> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.guard
    }
}

#[cfg(test)]
mod tests {
    use hal::mock::MockFull;

    use super::*;
    use crate::testing::{interrupts_enabled, serial};

    // `SpinLock<T, MockTiny>` does not compile: `MockTiny` has no `HasCas`, so there is
    // no compare-and-swap to build this out of. That is the bound doing its job, and
    // it is why these tests are `_full` only — the tiny profile's answer to the same
    // problem is `IrqLock`, tested in `crate::irq`.

    #[test]
    fn uncontended_acquire_and_release_full() {
        let lock: SpinLock<u32, MockFull> = SpinLock::new(41);
        assert!(!lock.is_locked());

        let mut g = lock.lock();
        assert_eq!(*g, 41);
        *g = 42;
        assert!(lock.is_locked());
        drop(g);

        assert!(!lock.is_locked());
        assert_eq!(*lock.lock(), 42);
        assert!(!lock.is_locked(), "the temporary guard released at end of statement");
    }

    #[test]
    fn the_guard_releases_on_drop_full() {
        let lock: SpinLock<u32, MockFull> = SpinLock::new(0);
        for i in 0..8 {
            // If `drop` did not advance `now_serving`, the second iteration would spin
            // for ever rather than fail — which is why this loop runs more than twice.
            let mut g = lock.lock();
            *g = i;
        }
        assert_eq!(*lock.lock(), 7);
    }

    #[test]
    fn a_handoff_lock_is_released_by_unlock_handoff_full() {
        let lock: SpinLock<(), MockFull> = SpinLock::new(());
        for _ in 0..8 {
            // A release that did not advance `now_serving` would hang the next take.
            lock.lock_handoff();
            assert!(lock.is_locked());
            assert!(lock.try_lock().is_none(), "held, with no guard anywhere");
            // SAFETY: taken just above, on this thread.
            unsafe { lock.unlock_handoff() };
            assert!(!lock.is_locked());
        }
        assert!(lock.try_lock().is_some(), "and an ordinary guard works afterwards");
    }

    #[test]
    fn try_lock_does_not_take_a_held_lock_full() {
        let lock: SpinLock<u32, MockFull> = SpinLock::new(3);
        let held = lock.lock();
        assert!(lock.try_lock().is_none());
        drop(held);

        let taken = lock.try_lock();
        assert!(taken.is_some());
        // A failed `try_lock` must not have drawn a ticket: if it had, the queue would
        // have advanced past the lock and this acquire would hang.
        drop(taken);
        assert_eq!(*lock.lock(), 3);
    }

    #[test]
    fn tickets_are_served_in_order_full() {
        // The ordering claim, checked at the level the host can check it: acquiring
        // and releasing repeatedly must keep `next` and `now_serving` in step, and a
        // ticket must be served exactly once.
        let lock: SpinLock<usize, MockFull> = SpinLock::new(0);
        for expected in 1..=32usize {
            let mut g = lock.lock();
            let seen = *g;
            *g = seen.wrapping_add(1);
            assert_eq!(*g, expected);
        }
        assert!(!lock.is_locked());
    }

    #[test]
    fn lock_irqsave_masks_for_the_critical_section_and_restores_full() {
        let _s = serial();
        assert!(interrupts_enabled::<MockFull>());

        let lock: SpinLock<u32, MockFull> = SpinLock::new(5);
        {
            let mut g = lock.lock_irqsave();
            assert!(!interrupts_enabled::<MockFull>());
            assert!(lock.is_locked());
            *g = 6;
        }

        // Both halves released, and in the right order: the lock first, then the mask.
        assert!(interrupts_enabled::<MockFull>());
        assert!(!lock.is_locked());
        assert_eq!(*lock.lock(), 6);
    }

    #[test]
    fn lock_irqsave_nests_with_a_plain_mask_full() {
        let _s = serial();
        let outer = IrqGuard::<MockFull>::mask();
        assert!(!interrupts_enabled::<MockFull>());

        let lock: SpinLock<u32, MockFull> = SpinLock::new(0);
        {
            let _g = lock.lock_irqsave();
            assert!(!interrupts_enabled::<MockFull>());
        }
        // Restored to what it found — masked — rather than to "enabled".
        assert!(!interrupts_enabled::<MockFull>());
        drop(outer);
        assert!(interrupts_enabled::<MockFull>());
    }

    #[test]
    fn contended_acquires_do_not_lose_an_update_full() {
        // The host cannot check the barriers (x86 is TSO and hides the mistake), but
        // it can check the protocol: four threads, each incrementing through the lock,
        // must produce exactly the number of increments. A ticket handed out twice, or
        // a release that advanced the queue by the wrong amount, shows up here.
        const THREADS: usize = 4;
        const EACH: usize = 5_000;

        let lock: SpinLock<usize, MockFull> = SpinLock::new(0);
        std::thread::scope(|s| {
            for _ in 0..THREADS {
                s.spawn(|| {
                    for _ in 0..EACH {
                        let mut g = lock.lock();
                        let seen = *g;
                        *g = seen.wrapping_add(1);
                    }
                });
            }
        });

        assert_eq!(*lock.lock(), THREADS * EACH);
        assert!(!lock.is_locked());
    }

    #[test]
    fn a_lock_guards_a_compound_value_full() {
        // The lock is generic over `T`, not over the integer that was easiest to test
        // with: a guard must give mutable access to the whole value, fields included.
        #[derive(PartialEq, Debug)]
        struct Counters {
            hits: u32,
            misses: u32,
        }

        let lock: SpinLock<Counters, MockFull> = SpinLock::new(Counters { hits: 0, misses: 0 });
        {
            let mut g = lock.lock();
            g.hits = 9;
        }
        assert_eq!(*lock.lock(), Counters { hits: 9, misses: 0 });
    }
}

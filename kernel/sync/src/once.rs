//! One-time initialisation, on machines with and without compare-and-swap.
//!
//! [`Once<T, G>`](Once) holds the state machine and the storage; `G` says how this
//! machine performs the single read-modify-write the state machine needs. There are
//! exactly two, matching the two exclusion mechanisms this unit offers:
//!
//! ```text
//! CasOnce<T, A>  =  Once<T, CasGate<A>>   A: Arch + HasCas   — compare-exchange
//! IrqOnce<T, A>  =  Once<T, IrqGate<A>>   A: UniProcessor    — interrupts masked
//! ```
//!
//! # Why the mechanism is a type parameter
//!
//! Because it cannot be a bound. The natural spelling is one `Once<T, A: Arch>` with
//! two `call_once` implementations, one for `A: HasCas` and one for `A: UniProcessor`
//! — and that is rejected: rustc reports E0592 for two inherent methods of the same
//! name whose impls could overlap, and E0119 for the trait-based version. Coherence
//! does not consider where-clauses, and an architecture that is *both* uniprocessor
//! and CAS-capable (an ARMv7-M part, say) is not hypothetical, so the two impls really
//! do overlap. Choosing "CAS wins where both apply" is specialisation, which is not
//! stable and is not on the permitted-features list in `toolchain.toml`.
//!
//! Naming the gate at the type is the honest alternative: the caller states which
//! machine it is assuming, in the type, and the compiler checks the assumption against
//! the architecture's capabilities. It is the same bargain the rest of the unit makes,
//! one level in.
//!
//! # What the two gates do differently, and why
//!
//! Contention means different things on the two machines, and the gates say so:
//!
//! - With CAS, a caller that loses the race is another CPU, which will be able to use the value
//!   shortly. It waits.
//! - With interrupts masked on a single-CPU machine, nothing else *can* be running, so a caller
//!   that finds an initialisation in progress can only be the initialiser itself, re-entering
//!   through its own closure. Nobody will ever finish it. Waiting would hang the machine in a loop
//!   that looks like progress, so it stops the CPU instead ([`Arch::halt`]).
//!
//! That difference is not a tuning knob; it follows from the capability, which is the
//! whole argument of `docs/portability.md` in four lines of code.

use core::cell::UnsafeCell;
#[cfg(target_has_atomic = "8")]
use core::hint::spin_loop;
use core::marker::PhantomData;
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicU8, Ordering};

#[cfg(target_has_atomic = "8")]
use hal::{Arch, HasCas};

use crate::UniProcessor;
use crate::irq::IrqGuard;

/// Nothing has happened yet.
const UNINIT: u8 = 0;
/// Someone is running the initialiser and has not published a value.
const RUNNING: u8 = 1;
/// The value is written, and was published with a `Release` store.
const DONE: u8 = 2;

/// What [`OnceGate::claim`] found.
///
/// Generic over what winning produces, because winning means "hold this until you are
/// finished": nothing at all for a CAS machine, and an interrupt mask for a machine
/// whose exclusion *is* that mask.
pub enum Claim<C> {
    /// This caller may run the initialiser, and must keep `C` alive until it has
    /// published the value.
    Won(C),
    /// A value is already published.
    Done,
    /// Someone else holds the claim. What that means depends on the machine; see
    /// [`OnceGate::settle`].
    Contended,
}

/// How an architecture performs the one read-modify-write that [`Once`] needs.
///
/// Sealed: the two implementations below are the two mechanisms this unit has, and a
/// third is a design decision for this unit rather than a knob for a caller.
pub trait OnceGate: sealed::Sealed {
    /// Whatever the winner must hold until the value is published.
    type Claimed;

    /// Try to move the state from `UNINIT` to `RUNNING`.
    ///
    /// Must be atomic with respect to everything else that can run on this machine,
    /// and must observe a published value with at least `Acquire` ordering, so that a
    /// caller receiving [`Claim::Done`] can read the value immediately.
    fn claim(state: &AtomicU8) -> Claim<Self::Claimed>;

    /// Resolve a [`Claim::Contended`]: return only once `state` is `DONE` and has
    /// been observed with at least `Acquire` ordering — or do not return.
    fn settle(state: &AtomicU8);
}

mod sealed {
    /// Not nameable outside this crate, so [`super::OnceGate`] cannot be implemented
    /// outside it either.
    pub trait Sealed {}
}

/// One-time initialisation with compare-and-swap: the racers are other CPUs, and a
/// caller that loses waits for them.
#[cfg(target_has_atomic = "8")]
pub struct CasGate<A>(PhantomData<fn() -> A>);

#[cfg(target_has_atomic = "8")]
impl<A: Arch + HasCas> sealed::Sealed for CasGate<A> {}

#[cfg(target_has_atomic = "8")]
impl<A: Arch + HasCas> OnceGate for CasGate<A> {
    /// Nothing: with CAS, holding the claim is the `RUNNING` state itself.
    type Claimed = ();

    fn claim(state: &AtomicU8) -> Claim<()> {
        // `Acquire` on failure is the load that synchronises with the `Release` store
        // of `DONE` in `call_once`, which is what makes the value the winner wrote
        // visible to the loser that reads it. `Acquire` on success could be `Relaxed`
        // — the winner synchronises with nothing, since it found `UNINIT` — but one
        // ordering on one operation is easier to review than two, and the difference
        // is not measurable next to the initialiser it guards.
        match state.compare_exchange(UNINIT, RUNNING, Ordering::Acquire, Ordering::Acquire) {
            Ok(_) => Claim::Won(()),
            Err(DONE) => Claim::Done,
            Err(_) => Claim::Contended,
        }
    }

    fn settle(state: &AtomicU8) {
        // The winner may be on another CPU and may take a while. `Acquire` again: this
        // is the load that publishes its writes to us.
        while state.load(Ordering::Acquire) != DONE {
            spin_loop();
        }
    }
}

/// One-time initialisation on a machine with one CPU and no CAS: the initialiser runs
/// with interrupts masked, so nothing else can observe a half-built value.
pub struct IrqGate<A>(PhantomData<fn() -> A>);

impl<A: UniProcessor> sealed::Sealed for IrqGate<A> {}

impl<A: UniProcessor> OnceGate for IrqGate<A> {
    /// The interrupt mask, held for as long as the initialiser runs. Handing it to the
    /// caller rather than dropping it here is the point: it means an interrupt handler
    /// can never see `RUNNING`, which is what makes [`Self::settle`]'s conclusion
    /// sound.
    type Claimed = IrqGuard<A>;

    fn claim(state: &AtomicU8) -> Claim<IrqGuard<A>> {
        let irq = IrqGuard::mask();
        // `Acquire`, as in the CAS gate, and for the same reason: it orders the read
        // of the value against the store of `DONE`. On one CPU the hardware needs no
        // barrier for that, but the compiler does — `Relaxed` would leave it free to
        // hoist the read of the value above this load.
        match state.load(Ordering::Acquire) {
            DONE => Claim::Done,
            UNINIT => {
                // `Relaxed`: this publishes nothing. Nobody can observe it — the only
                // other agent on this machine is an interrupt handler, and interrupts
                // are masked by `irq` for as long as the caller holds the claim.
                state.store(RUNNING, Ordering::Relaxed);
                Claim::Won(irq)
            }
            _ => Claim::Contended,
        }
    }

    fn settle(_state: &AtomicU8) {
        // `RUNNING` was observed with interrupts masked on a machine with one CPU.
        // The only code that could have set it is this call's own ancestor: an
        // initialiser that called `call_once` on the `Once` it is initialising. It
        // cannot finish, because this call is what it is waiting on. Spinning would
        // hang the machine inside something that looks like a lock; returning would
        // mean handing back a reference to uninitialised memory. Stopping is the
        // remaining option, and it is the narrow case `docs/coding-standards.md`
        // allows: an invariant is broken and continuing would be unsafe.
        A::halt()
    }
}

/// A value initialised at most once, by whichever caller gets there first.
///
/// The reader's path is a single `Acquire` load and no lock, which is what makes this
/// usable for things read on every syscall and written once during boot.
///
/// # A failed initialiser
///
/// If the closure never returns — it stops the CPU, or under the host test harness it
/// panics — the `Once` stays claimed for ever and later callers wait or stop. There is
/// no poisoning and no retry: the kernel builds with `panic=abort`, so an initialiser
/// that cannot finish has already ended the machine, and inventing a recovery path
/// here would be inventing a case that cannot occur in the configuration that ships.
pub struct Once<T, G: OnceGate> {
    state: AtomicU8,
    value: UnsafeCell<MaybeUninit<T>>,
    _gate: PhantomData<fn() -> G>,
}

// SAFETY: the value is written exactly once, by the caller that `claim` selected, and
// is published with a `Release` store that every reader observes with an `Acquire`
// load before forming a reference. So the write happens-before every read, and no two
// callers ever hold a `&mut` to it. Sharing a `&Once` between threads therefore shares
// `&T` (hence `T: Sync`) and moves the initialiser's `T` into whichever thread won
// (hence `T: Send`).
unsafe impl<T: Send + Sync, G: OnceGate> Sync for Once<T, G> {}
// SAFETY: moving the `Once` moves the `T` inside it, and nothing else.
unsafe impl<T: Send, G: OnceGate> Send for Once<T, G> {}

impl<T, G: OnceGate> Once<T, G> {
    /// An empty `Once`. `const`, so it can be a `static` with no initialiser — which
    /// is the only way it is ever useful.
    pub const fn new() -> Self {
        Once {
            state: AtomicU8::new(UNINIT),
            value: UnsafeCell::new(MaybeUninit::uninit()),
            _gate: PhantomData,
        }
    }

    /// The value, if it has been initialised. Never runs an initialiser and never
    /// waits for one.
    pub fn get(&self) -> Option<&T> {
        // `Acquire`: this is the load that pairs with the `Release` store of `DONE`
        // below. It is what makes the initialiser's writes — including whatever the
        // value points at — visible to this reader on a weakly ordered machine.
        if self.state.load(Ordering::Acquire) == DONE {
            // SAFETY: `DONE` was observed with `Acquire`, so the value was fully
            // written before this load, and it is never written again or moved out.
            Some(unsafe { self.value_ref() })
        } else {
            None
        }
    }

    /// Whether the value is initialised.
    ///
    /// For diagnostics. A caller that wants the value should ask for it: `false` here
    /// can be stale by the time it is acted on.
    pub fn is_completed(&self) -> bool {
        self.state.load(Ordering::Acquire) == DONE
    }

    /// Return the value, running `f` to produce it if nobody has yet.
    ///
    /// `f` runs at most once across the life of the `Once`, however many callers
    /// arrive and from however many CPUs. Callers that did not run it get the value
    /// the caller that did produced.
    ///
    /// Re-entering this from inside `f`, for the same `Once`, is a bug: on a CAS
    /// machine it spins for ever, and on a uniprocessor it stops the CPU. Neither
    /// hands out a reference to memory that has not been written.
    pub fn call_once<F: FnOnce() -> T>(&self, f: F) -> &T {
        match G::claim(&self.state) {
            Claim::Won(claim) => {
                let value = f();
                let slot = self.value.get();
                // SAFETY: this caller holds the claim, so the state is `RUNNING` and
                // no other caller can reach this line for this `Once`; readers form no
                // reference to the value until they observe `DONE`, which is stored
                // below. The slot is `MaybeUninit`, so writing over it drops nothing
                // that was never initialised.
                unsafe { (*slot).write(value) };
                // `Release`, and this is the store the whole type depends on:
                // everything written by `f`, and the write of the value itself, must
                // be visible to any CPU that observes `DONE`. `Relaxed` here would
                // pass every test we can run and would hand another core a
                // half-written value on real aarch64 hardware
                // (`docs/testing.md#what-qemu-will-not-catch`).
                self.state.store(DONE, Ordering::Release);
                // Explicit, so the order is on the page: the value is published before
                // the claim — on a uniprocessor, an interrupt mask — is given up.
                drop(claim);
            }
            Claim::Done => {}
            // Returns only once the state is `DONE`, or does not return.
            Claim::Contended => G::settle(&self.state),
        }

        // SAFETY: every arm above leaves the state at `DONE`, observed with `Acquire`
        // ordering (in `claim`, in `settle`, or established by this thread's own
        // `Release` store, which it trivially happens-after). So the value is written
        // and will not be written again.
        unsafe { self.value_ref() }
    }

    /// # Safety
    ///
    /// The state must be `DONE`, and that must have been observed by this thread with
    /// at least `Acquire` ordering, or established by this thread's own write.
    unsafe fn value_ref(&self) -> &T {
        // SAFETY: the caller guarantees the value has been written and published; the
        // returned reference borrows `self`, so it cannot outlive the storage.
        unsafe { (*self.value.get()).assume_init_ref() }
    }
}

impl<T, G: OnceGate> Default for Once<T, G> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T, G: OnceGate> Drop for Once<T, G> {
    fn drop(&mut self) {
        // `&mut self` means no other reference exists, so the state cannot change
        // under us and a plain read of it is enough.
        if *self.state.get_mut() == DONE {
            // SAFETY: `DONE` means the value was written and never moved out, so this
            // is the one and only drop of it. Any other state means the storage is
            // still uninitialised and there is nothing to drop.
            unsafe { self.value.get_mut().assume_init_drop() };
        }
    }
}

/// [`Once`] on a machine with compare-and-swap, where several CPUs may race.
#[cfg(target_has_atomic = "8")]
pub type CasOnce<T, A> = Once<T, CasGate<A>>;

/// [`Once`] on a uniprocessor with no compare-and-swap, where the initialiser runs
/// with interrupts masked.
pub type IrqOnce<T, A> = Once<T, IrqGate<A>>;

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicUsize;

    use hal::mock::{MockFull, MockTiny};

    use super::*;
    use crate::testing::{interrupts_enabled, serial};

    // Both profiles run the same test bodies. The gate is the only difference, which
    // is the claim this module is making: the state machine is written once.

    fn initialises_exactly_once<G: OnceGate>() {
        let runs = AtomicUsize::new(0);
        let once: Once<u32, G> = Once::new();

        assert!(!once.is_completed());
        assert!(once.get().is_none());

        let first = *once.call_once(|| {
            runs.fetch_add(1, Ordering::Relaxed);
            17
        });
        assert_eq!(first, 17);
        assert!(once.is_completed());

        // Four more calls, each with an initialiser that would give a different answer
        // if it ever ran.
        for _ in 0..4 {
            let again = *once.call_once(|| {
                runs.fetch_add(1, Ordering::Relaxed);
                99
            });
            assert_eq!(again, 17, "the second initialiser must not have run");
        }

        assert_eq!(runs.load(Ordering::Relaxed), 1);
        assert_eq!(once.get().copied(), Some(17));
    }

    #[test]
    fn initialises_exactly_once_full() {
        initialises_exactly_once::<CasGate<MockFull>>();
    }

    #[test]
    fn initialises_exactly_once_tiny() {
        let _s = serial();
        initialises_exactly_once::<IrqGate<MockTiny>>();
    }

    fn the_value_can_own_something<G: OnceGate>() {
        // A `T` with a destructor, to check the storage is treated as initialised
        // memory once and only once.
        let once: Once<std::vec::Vec<u8>, G> = Once::new();
        assert_eq!(once.call_once(|| std::vec![1, 2, 3]).len(), 3);
        assert_eq!(once.call_once(std::vec::Vec::new).len(), 3);
        drop(once); // Would leak, or double-drop, if `Drop` were wrong.
    }

    #[test]
    fn the_value_can_own_something_full() {
        the_value_can_own_something::<CasGate<MockFull>>();
    }

    #[test]
    fn the_value_can_own_something_tiny() {
        let _s = serial();
        the_value_can_own_something::<IrqGate<MockTiny>>();
    }

    #[test]
    fn a_race_still_initialises_exactly_once_full() {
        // The case the CAS gate exists for: several CPUs arriving at once. Every
        // loser must take the `settle` path and come back with the winner's value,
        // and the initialiser must have run once. This is the closest the host gets
        // to the multiprocessor profile — it is real concurrency, on a machine whose
        // memory model is too strong to catch a missing barrier.
        const THREADS: usize = 8;

        let runs = AtomicUsize::new(0);
        let once: CasOnce<usize, MockFull> = Once::new();
        let ready = std::sync::Barrier::new(THREADS);

        std::thread::scope(|s| {
            for id in 0..THREADS {
                let runs = &runs;
                let once = &once;
                let ready = &ready;
                s.spawn(move || {
                    // Start together, so the race is a race rather than a sequence.
                    ready.wait();
                    let value = *once.call_once(|| {
                        runs.fetch_add(1, Ordering::Relaxed);
                        // Whoever wins, everyone must see that same winner's value.
                        id.wrapping_add(1000)
                    });
                    assert!((1000..1000 + THREADS).contains(&value));
                    assert_eq!(value, *once.call_once(|| 0));
                });
            }
        });

        assert_eq!(runs.load(Ordering::Relaxed), 1);
        assert!(once.is_completed());
    }

    #[test]
    fn an_uninitialised_once_drops_nothing_full() {
        // No value was ever written, so `Drop` must not touch the storage. Under
        // Miri this would be the difference between a pass and a use of uninitialised
        // memory; here it at least pins the intent.
        let once: CasOnce<std::vec::Vec<u8>, MockFull> = Once::new();
        assert!(once.get().is_none());
        drop(once);
    }

    #[test]
    fn initialisation_runs_with_interrupts_masked_tiny() {
        let _s = serial();
        assert!(interrupts_enabled::<MockTiny>());

        let once: IrqOnce<bool, MockTiny> = Once::new();
        // The mask is held across the initialiser, not just across the claim. That is
        // what makes an interrupt handler unable to observe `RUNNING`, which is what
        // lets `IrqGate::settle` conclude that contention can only be recursion.
        let masked_during_init = *once.call_once(|| !interrupts_enabled::<MockTiny>());
        assert!(masked_during_init);

        // And handed back afterwards.
        assert!(interrupts_enabled::<MockTiny>());
        // A call that finds the value already there must not leave interrupts masked
        // either — `claim` takes the mask to read the state even on that path.
        assert!(*once.call_once(|| false));
        assert!(interrupts_enabled::<MockTiny>());
    }

    #[test]
    fn initialisation_does_not_touch_interrupts_full() {
        let _s = serial();
        assert!(interrupts_enabled::<MockFull>());
        let once: CasOnce<bool, MockFull> = Once::new();
        // The CAS gate has no business with the interrupt mask: on a machine with
        // several CPUs, masking this one's interrupts would buy nothing and cost
        // latency, and the compare-exchange is the whole mechanism.
        assert!(*once.call_once(|| interrupts_enabled::<MockFull>()));
        assert!(interrupts_enabled::<MockFull>());
    }
}

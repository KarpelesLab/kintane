//! Counters for machines whose atomics stop short of what the code needs.
//!
//! Two different gaps, one shape.
//!
//! * `core::sync::atomic::AtomicU64` does not exist on rv32imac, thumbv7m or any other 32-bit core
//!   whose ISA stops at 32-bit exclusive access. Code that keeps a 64-bit count — nanoseconds,
//!   ticks, spins — needs something with the same shape there.
//! * On a core with no atomic instructions at all (rv32i), `AtomicU32` and friends still *exist* —
//!   a naturally aligned word is loaded and stored in one instruction anyway — but every
//!   read-modify-write is gone: no `fetch_add`, no `swap`, no `compare_exchange`. A counter
//!   incremented from a handler needs something with the same shape there too.
//!
//! These types are that shape on a uniprocessor: an [`UnsafeCell`] every access to which
//! masks interrupts, which is exclusion because [`UniProcessor`] says so. Each offers only
//! the operations an atomic offers and nothing that returns a reference, so code written
//! against `AtomicU64` or `AtomicU32` compiles against it unchanged, and an image picks
//! one or the other with a type alias on `target_has_atomic`.
//!
//! The `Ordering` arguments are accepted and ignored: with interrupts masked on the only
//! CPU there is no weaker ordering to choose.

use core::cell::UnsafeCell;
use core::marker::PhantomData;
use core::sync::atomic::Ordering;

use crate::UniProcessor;
use crate::irq::IrqGuard;

/// Define one masked stand-in for an atomic integer.
///
/// A macro because the four widths differ only in their value type: writing them out
/// would be four copies of the same `Sync` argument, which is the thing worth reviewing
/// once rather than four times.
macro_rules! irq_cell {
    ($name:ident, $ty:ty, $doc:literal) => {
        #[doc = $doc]
        /// See the module documentation.
        pub struct $name<A: UniProcessor> {
            value: UnsafeCell<$ty>,
            _arch: PhantomData<fn() -> A>,
        }

        // SAFETY: every access goes through `with`, which masks interrupts for its whole
        // duration and hands out no reference that outlives it. On a uniprocessor — the
        // bound — that excludes every other execution context that could touch the cell.
        unsafe impl<A: UniProcessor> Sync for $name<A> {}

        impl<A: UniProcessor> $name<A> {
            pub const fn new(v: $ty) -> Self {
                $name {
                    value: UnsafeCell::new(v),
                    _arch: PhantomData,
                }
            }

            fn with<R>(&self, f: impl FnOnce(&mut $ty) -> R) -> R {
                let _masked = IrqGuard::<A>::mask();
                // SAFETY: interrupts are masked until `_masked` drops, after `f` returns,
                // and the `&mut` does not escape `f`. By the `Sync` argument nothing else
                // can reach the cell meanwhile.
                f(unsafe { &mut *self.value.get() })
            }

            pub fn load(&self, _: Ordering) -> $ty {
                self.with(|v| *v)
            }

            pub fn store(&self, new: $ty, _: Ordering) {
                self.with(|v| *v = new);
            }

            pub fn swap(&self, new: $ty, _: Ordering) -> $ty {
                self.with(|v| core::mem::replace(v, new))
            }
        }
    };
}

/// The arithmetic an integer counter needs, for the types that have it.
macro_rules! irq_cell_arith {
    ($name:ident, $ty:ty) => {
        impl<A: UniProcessor> $name<A> {
            /// Wrapping, like `fetch_add` on the atomic of the same width.
            pub fn fetch_add(&self, add: $ty, _: Ordering) -> $ty {
                self.with(|v| {
                    let old = *v;
                    *v = old.wrapping_add(add);
                    old
                })
            }

            /// Wrapping, like `fetch_sub` on the atomic of the same width.
            pub fn fetch_sub(&self, sub: $ty, _: Ordering) -> $ty {
                self.with(|v| {
                    let old = *v;
                    *v = old.wrapping_sub(sub);
                    old
                })
            }

            pub fn fetch_or(&self, bits: $ty, _: Ordering) -> $ty {
                self.with(|v| {
                    let old = *v;
                    *v = old | bits;
                    old
                })
            }
        }
    };
}

irq_cell!(IrqU64, u64, "A `u64` read and written with interrupts masked.");
irq_cell!(IrqU32, u32, "A `u32` read and written with interrupts masked.");
irq_cell!(IrqUsize, usize, "A `usize` read and written with interrupts masked.");
irq_cell!(IrqBool, bool, "A `bool` read and written with interrupts masked.");

irq_cell_arith!(IrqU64, u64);
irq_cell_arith!(IrqU32, u32);
irq_cell_arith!(IrqUsize, usize);

impl<A: UniProcessor> IrqBool<A> {
    /// Like `AtomicBool::fetch_or`: the flag is set, and what it was is returned.
    pub fn fetch_or(&self, set: bool, _: Ordering) -> bool {
        self.with(|v| {
            let old = *v;
            *v = old | set;
            old
        })
    }
}

#[cfg(test)]
mod tests {
    use hal::mock::MockTiny;

    use super::*;
    use crate::testing::{interrupts_enabled, serial};

    #[test]
    fn behaves_like_an_atomic() {
        let _s = serial();
        static V: IrqU64<MockTiny> = IrqU64::new(u64::MAX - 1);
        assert_eq!(V.fetch_add(3, Ordering::Relaxed), u64::MAX - 1);
        assert_eq!(V.load(Ordering::Relaxed), 1, "wraps, as fetch_add does");
        V.store(1 << 40, Ordering::Relaxed);
        assert_eq!(V.swap(7, Ordering::Relaxed), 1 << 40);
        assert_eq!(V.load(Ordering::Relaxed), 7);
    }

    #[test]
    fn the_narrower_widths_behave_the_same() {
        let _s = serial();
        static W: IrqU32<MockTiny> = IrqU32::new(0);
        assert_eq!(W.fetch_add(5, Ordering::Relaxed), 0);
        assert_eq!(W.fetch_sub(2, Ordering::Relaxed), 5);
        assert_eq!(W.fetch_or(0x10, Ordering::Relaxed), 3);
        assert_eq!(W.load(Ordering::Relaxed), 0x13);

        static N: IrqUsize<MockTiny> = IrqUsize::new(usize::MAX);
        assert_eq!(N.fetch_add(1, Ordering::Relaxed), usize::MAX, "wraps");
        assert_eq!(N.load(Ordering::Relaxed), 0);

        static B: IrqBool<MockTiny> = IrqBool::new(false);
        assert!(!B.swap(true, Ordering::Relaxed));
        assert!(B.load(Ordering::Relaxed));
        assert!(B.fetch_or(false, Ordering::Relaxed), "already set, and stays set");
        assert!(B.load(Ordering::Relaxed));
    }

    #[test]
    fn masks_for_the_access_and_restores_after() {
        let _s = serial();
        let v = IrqU64::<MockTiny>::new(0);
        assert!(interrupts_enabled::<MockTiny>());
        let seen = v.with(|_| interrupts_enabled::<MockTiny>());
        assert!(!seen, "the cell was reached with interrupts enabled");
        assert!(interrupts_enabled::<MockTiny>(), "and they are back");
    }
}

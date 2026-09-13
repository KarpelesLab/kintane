//! A 64-bit counter for machines without 64-bit atomics.
//!
//! `core::sync::atomic::AtomicU64` does not exist on rv32imac, thumbv7m or any other
//! 32-bit core whose ISA stops at 32-bit exclusive access. Code that keeps a 64-bit
//! count — nanoseconds, ticks, spins — needs something with the same shape there.
//!
//! [`IrqU64`] is that shape on a uniprocessor: an [`UnsafeCell`] every access to which
//! masks interrupts, which is exclusion because [`UniProcessor`] says so. It offers only
//! the operations an atomic offers and nothing that returns a reference, so code written
//! against `AtomicU64` compiles against it unchanged, and an image picks one or the other
//! with a type alias on `target_has_atomic = "64"`.
//!
//! The `Ordering` arguments are accepted and ignored: with interrupts masked on the only
//! CPU there is no weaker ordering to choose.

use core::cell::UnsafeCell;
use core::marker::PhantomData;
use core::sync::atomic::Ordering;

use crate::UniProcessor;
use crate::irq::IrqGuard;

/// A `u64` read and written with interrupts masked. See the module documentation.
pub struct IrqU64<A: UniProcessor> {
    value: UnsafeCell<u64>,
    _arch: PhantomData<fn() -> A>,
}

// SAFETY: every access goes through `with`, which masks interrupts for its whole
// duration and hands out no reference that outlives it. On a uniprocessor — the bound —
// that excludes every other execution context that could touch the cell.
unsafe impl<A: UniProcessor> Sync for IrqU64<A> {}

impl<A: UniProcessor> IrqU64<A> {
    pub const fn new(v: u64) -> Self {
        IrqU64 {
            value: UnsafeCell::new(v),
            _arch: PhantomData,
        }
    }

    fn with<R>(&self, f: impl FnOnce(&mut u64) -> R) -> R {
        let _masked = IrqGuard::<A>::mask();
        // SAFETY: interrupts are masked until `_masked` drops, after `f` returns, and the
        // `&mut` does not escape `f`. By the `Sync` argument nothing else can reach the
        // cell meanwhile.
        f(unsafe { &mut *self.value.get() })
    }

    pub fn load(&self, _: Ordering) -> u64 {
        self.with(|v| *v)
    }

    pub fn store(&self, new: u64, _: Ordering) {
        self.with(|v| *v = new);
    }

    /// Wrapping, like `AtomicU64::fetch_add`.
    pub fn fetch_add(&self, add: u64, _: Ordering) -> u64 {
        self.with(|v| {
            let old = *v;
            *v = old.wrapping_add(add);
            old
        })
    }

    pub fn swap(&self, new: u64, _: Ordering) -> u64 {
        self.with(|v| core::mem::replace(v, new))
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
    fn masks_for_the_access_and_restores_after() {
        let _s = serial();
        let v = IrqU64::<MockTiny>::new(0);
        assert!(interrupts_enabled::<MockTiny>());
        let seen = v.with(|_| interrupts_enabled::<MockTiny>());
        assert!(!seen, "the cell was reached with interrupts enabled");
        assert!(interrupts_enabled::<MockTiny>(), "and they are back");
    }
}

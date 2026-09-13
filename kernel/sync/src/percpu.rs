//! Per-CPU data.
//!
//! A variable with one instance per CPU, where code reaches the instance belonging to the
//! CPU it is running on. The two things that make that hard are both answered by a type
//! here rather than by a rule in a comment.
//!
//! # Sized by the machine
//!
//! [`PerCpu::new`] is for an architecture with [`HasSmp`], and it refuses at build time a
//! storage with fewer slots than that architecture can bring up CPUs, so a CPU never finds
//! itself without a slot. [`PerCpu::uniprocessor`] is for an architecture that asserts
//! [`UniProcessor`], and it has exactly one slot, which is all a plain `static` would be.
//! One of the two bounds is required to build one, and a uniprocessor build pays for no
//! slot it cannot use.
//!
//! # Pinned while used
//!
//! "Which CPU am I on" is only true until the next preemption. Code that reads the answer,
//! is preempted, is resumed on another CPU and then uses the slot it picked is using
//! another CPU's variable. So a slot is reached only through a [`Pinned`], which masks
//! interrupts **before** it reads the CPU index and restores them when dropped, and every
//! reference into the storage borrows from it. The borrow checker then enforces that no
//! reference to a CPU's slot outlives the window in which that CPU cannot be left.
//!
//! Masking stops preemption and interrupt handlers. It does not stop the holder from
//! blocking. **A thread must not sleep or yield while it holds a `Pinned`**, the same rule
//! as for a held spinlock (discipline rule 2 in the crate docs): a scheduler that moves
//! threads between CPUs would move the `Pinned` with it. `Pinned` is `!Send`, which stops
//! it being handed to another thread, but it cannot stop the thread it lives in from
//! moving.
//!
//! # Why every slot is `Sync`
//!
//! A slot is shared state that happens to have one expected user, and the storage makes
//! nothing `unsafe` depend on that expectation. `T: Sync` is required throughout, so a
//! port whose CPU index is wrong (two CPUs reporting the same number) produces two CPUs
//! updating one counter, a logic error the checks at bring-up look for, and never
//! undefined behaviour. Counters are atomics. State that genuinely needs exclusive access
//! brings its own exclusion, as lock-order checking's per-CPU stacks do.

use core::marker::PhantomData;

use hal::{Arch, HasSmp, UniProcessor};

/// One `T` per CPU.
pub struct PerCpu<T, const N: usize> {
    slots: [T; N],
}

impl<T: Sync, const N: usize> PerCpu<T, N> {
    /// Storage for an SMP architecture `A`: `slots[i]` belongs to CPU `i`.
    ///
    /// Fails to build when `N` is less than [`HasSmp::MAX_CPUS`], since a CPU the port can
    /// bring up would then have nowhere to keep its instance.
    pub const fn new<A: HasSmp>(slots: [T; N]) -> Self {
        const {
            assert!(N >= A::MAX_CPUS, "per-CPU storage smaller than the architecture's CPU count");
        }
        PerCpu { slots }
    }

    /// Storage with `N` slots and no architecture to size it against.
    ///
    /// For state that must exist under every lock type on every architecture, where the
    /// only bound available is [`Arch`], and so the only size available is the
    /// configuration's. A CPU at or past `N` finds no slot and [`PerCpu::get`] says so.
    // Used by lock-order checking in kernel images; a host build keeps its held stacks per
    // host thread instead, and has no other user.
    #[allow(dead_code)]
    pub(crate) const fn sized(slots: [T; N]) -> Self {
        PerCpu { slots }
    }

    /// The running CPU's instance, for as long as `pin` holds it on that CPU.
    ///
    /// `None` only when the CPU's index has no slot, which storage built with
    /// [`PerCpu::new`] or [`PerCpu::uniprocessor`] for the same architecture rules out.
    pub fn get<'p, A: Arch>(&'p self, pin: &'p Pinned<A>) -> Option<&'p T> {
        self.slots.get(pin.cpu())
    }

    /// Run `f` on the running CPU's instance, pinned for the duration.
    pub fn with<A: Arch, R>(&self, f: impl FnOnce(&T) -> R) -> Option<R> {
        let pin = Pinned::<A>::new();
        self.get(&pin).map(f)
    }

    /// CPU `cpu`'s instance, from any CPU. For reading what every CPU recorded.
    pub fn slot(&self, cpu: usize) -> Option<&T> {
        self.slots.get(cpu)
    }

    /// Every CPU's instance, in CPU order.
    pub fn iter(&self) -> core::slice::Iter<'_, T> {
        self.slots.iter()
    }

    pub const fn len(&self) -> usize {
        N
    }

    pub const fn is_empty(&self) -> bool {
        N == 0
    }
}

impl<T: Sync> PerCpu<T, 1> {
    /// Storage for a uniprocessor `A`: one slot, the only CPU's.
    pub const fn uniprocessor<A: UniProcessor>(slot: T) -> Self {
        PerCpu { slots: [slot] }
    }
}

/// Proof that the holder stays on one CPU: interrupts are masked on it until this drops.
///
/// Nest freely. Each restores exactly the state it found, like
/// [`IrqGuard`](crate::IrqGuard).
pub struct Pinned<A: Arch> {
    irq: A::IrqState,
    cpu: usize,
    /// The saved interrupt state belongs to this CPU. Restoring it anywhere else would be
    /// wrong, so this cannot be sent to another thread.
    _not_send: PhantomData<*const ()>,
}

impl<A: Arch> Pinned<A> {
    /// Mask interrupts on this CPU, then read which CPU it is.
    ///
    /// In that order. Read first, and a preemption between the read and the mask resumes
    /// the thread on another CPU holding the first one's number.
    pub fn new() -> Pinned<A> {
        let irq = A::irq_save();
        Pinned {
            irq,
            cpu: A::cpu_index(),
            _not_send: PhantomData,
        }
    }

    /// The CPU this pin holds.
    pub fn cpu(&self) -> usize {
        self.cpu
    }
}

impl<A: Arch> Default for Pinned<A> {
    fn default() -> Self {
        Self::new()
    }
}

impl<A: Arch> Drop for Pinned<A> {
    fn drop(&mut self) {
        // SAFETY: `irq` came from `irq_save` in `new`, on this CPU, since `Pinned` is
        // `!Send` and cannot have left the thread that saved it. It is restored once,
        // here.
        unsafe { A::irq_restore(self.irq) };
    }
}

#[cfg(test)]
mod tests {
    use core::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;
    use std::thread;

    use hal::mock::{MOCK_CPUS, MockFull, MockTiny, set_cpu};

    use super::*;
    use crate::testing::{interrupts_enabled, serial};

    const ZERO: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn each_cpu_reaches_its_own_slot() {
        // Serialised, and one CPU at a time: a pin saves and restores the mock's interrupt
        // flag, which is one static for the whole test binary. Two threads pinning at once
        // can restore each other's saved state and leave it masked for the next test.
        let _serial = serial();
        let counters: Arc<PerCpu<AtomicU64, MOCK_CPUS>> =
            Arc::new(PerCpu::new::<MockFull>([ZERO; MOCK_CPUS]));
        for cpu in 0..MOCK_CPUS {
            let counters = Arc::clone(&counters);
            thread::spawn(move || {
                set_cpu(cpu);
                // A different count per CPU, so a slot shared by two CPUs cannot come out
                // right by adding to the same total.
                for _ in 0..(cpu + 1) * 100 {
                    let pin = Pinned::<MockFull>::new();
                    assert_eq!(pin.cpu(), cpu);
                    counters
                        .get(&pin)
                        .expect("every mock CPU has a slot")
                        .fetch_add(1, Ordering::Relaxed);
                }
            })
            .join()
            .unwrap();
        }
        for cpu in 0..MOCK_CPUS {
            let n = counters.slot(cpu).unwrap().load(Ordering::Relaxed);
            assert_eq!(n, (cpu as u64 + 1) * 100, "CPU {cpu}'s count");
        }
    }

    #[test]
    fn a_cpu_past_the_storage_has_no_slot() {
        let _serial = serial();
        let counters = PerCpu::new::<MockFull>([ZERO; MOCK_CPUS]);
        set_cpu(MOCK_CPUS);
        let got = counters.with::<MockFull, _>(|c| c.fetch_add(1, Ordering::Relaxed));
        set_cpu(0);
        assert_eq!(got, None);
        assert!(counters.iter().all(|c| c.load(Ordering::Relaxed) == 0));
    }

    #[test]
    fn storage_sized_by_configuration_misses_past_its_end() {
        let _serial = serial();
        let slots = PerCpu::sized([ZERO; 2]);
        set_cpu(1);
        assert_eq!(slots.with::<MockFull, _>(|c| c.fetch_add(1, Ordering::Relaxed)), Some(0));
        set_cpu(2);
        assert_eq!(slots.with::<MockFull, _>(|c| c.fetch_add(1, Ordering::Relaxed)), None);
        set_cpu(0);
        assert_eq!(slots.slot(1).unwrap().load(Ordering::Relaxed), 1);
    }

    #[test]
    fn a_uniprocessor_has_one_slot_and_uses_it() {
        let _serial = serial();
        let counter = PerCpu::uniprocessor::<MockTiny>(ZERO);
        assert_eq!(counter.len(), 1);
        counter.with::<MockTiny, _>(|c| c.fetch_add(3, Ordering::Relaxed));
        assert_eq!(counter.slot(0).unwrap().load(Ordering::Relaxed), 3);
    }

    #[test]
    fn a_pin_masks_interrupts_until_it_drops_and_nests() {
        let _serial = serial();
        assert!(interrupts_enabled::<MockFull>());
        {
            let outer = Pinned::<MockFull>::new();
            assert!(!interrupts_enabled::<MockFull>(), "pinned means masked");
            {
                let _inner = Pinned::<MockFull>::new();
                assert!(!interrupts_enabled::<MockFull>());
            }
            assert!(!interrupts_enabled::<MockFull>(), "the inner pin restored the outer's mask");
            drop(outer);
        }
        assert!(interrupts_enabled::<MockFull>(), "the outer pin restored what it found");
    }

    #[test]
    fn with_pins_for_the_call() {
        let _serial = serial();
        let slots = PerCpu::new::<MockFull>([ZERO; MOCK_CPUS]);
        let masked = slots.with::<MockFull, _>(|_| !interrupts_enabled::<MockFull>());
        assert_eq!(masked, Some(true));
        assert!(interrupts_enabled::<MockFull>());
    }
}

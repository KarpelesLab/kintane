//! Epoch-based reclamation, for data that is read far more often than it changes.
//!
//! A reader of a shared structure wants to follow a pointer without taking a lock, and a
//! writer wants to unlink a node and free it. The difficulty is only the free: a reader
//! that loaded the pointer just before the unlink is still using the node. This module
//! answers "when is nobody using it any more" without the readers writing anything
//! shared, which is what makes read-mostly data cheap to read on many CPUs.
//!
//! # The protocol
//!
//! There is one global **epoch**, a counter. Each CPU is a **participant** with one state
//! word: the epoch it last observed and whether it is **active**, meaning inside a
//! [`Guard`].
//!
//! - **Pin.** [`Collector::pin`] marks the running CPU active at the current global epoch. Every
//!   pointer a reader loads is valid for as long as its guard lives.
//! - **Retire.** A writer that has unlinked a node hands it to [`Collector::retire`], which records
//!   it in the running CPU's **limbo bag** stamped with the global epoch at that moment. The node
//!   is not freed yet.
//! - **Advance.** The global epoch moves from `g` to `g + 1` only when every active participant has
//!   observed `g`. An inactive participant never holds it back.
//! - **Reclaim.** A node retired at epoch `e` is reclaimed once the global epoch has reached `e +
//!   2`.
//!
//! Why two epochs are enough, stated once so it can be checked. Let a reader's state store
//! become visible at time `t`, recording epoch `p`. Any node the reader can reach was still
//! linked after `t`, so it was retired after `t`, stamped with some `e ≥ global(t) ≥ p`.
//! Reclaiming it needs two advances after its retirement, both after `t`, while the reader
//! is active. The first moves `e → e + 1` and so needs the reader's epoch to equal `e`; the
//! second moves `e + 1 → e + 2` and needs it to equal `e + 1`. The reader's epoch is one
//! number, so at most one of those advances can happen before the guard drops. A node is
//! therefore never reclaimed while a guard that could have reached it is alive.
//!
//! The argument needs the reader's store and the advancer's load to be ordered with
//! respect to each other, which is `SeqCst` on both: the classic store-then-load
//! handshake. Every other access is local to its CPU or made under a lock.
//!
//! # What a guard costs
//!
//! Pinning masks interrupts ([`Pinned`]) and writes one word; unpinning writes it back. A
//! guard is the only way to reach a CPU's participant, so the CPU cannot change underneath
//! it, and a thread must not sleep or yield while it holds one, the same rule as for a
//! spinlock. Guards nest: only the outermost changes the state word.
//!
//! # Memory is bounded, so a stall has to be reported
//!
//! There is no allocator beneath this module. Each CPU's bag has a fixed capacity, `BAG`.
//! A participant that stays pinned stops the epoch, and with it every reclamation, on every
//! CPU. That is the price of the protocol, not a bug in it, but it must not turn into a
//! silent leak or an unbounded queue. So:
//!
//! - an advance that fails records which CPU held it back and at which epoch;
//! - after [`STALL_ATTEMPTS`] consecutive failures caused by the same CPU at the same epoch,
//!   [`Collector::stall`] reports it;
//! - a retirement that finds its bag full, even after trying to advance and reclaim, is refused. It
//!   returns [`RetireError`], naming the stalled CPU if there is one, and the caller still owns the
//!   node.
//!
//! # One CPU, and machines without compare-and-swap
//!
//! Nothing here needs CAS. The state words are only loaded and stored, which every target
//! can do. Advancing is serialised by a lock from a [`LockFamily`], and bags are protected
//! by locks of the same family. On a uniprocessor built with [`Collector::uniprocessor`],
//! there is one participant and one bag. The only thing that can hold the epoch back is the
//! CPU's own guard, so reclamation happens at the second collection after the last unpin.
//! That is the whole protocol at the cost of two stores per guard, which is cheap enough
//! not to warrant a second implementation to get right.
//!
//! # What the tests cannot prove
//!
//! The host tests run the protocol on real threads, each playing a mock CPU, including a
//! reader holding a node across a concurrent unlink and several readers racing a writer.
//! They show that a mistake which reclaims a node early is caught quickly. They do not
//! enumerate interleavings; there is no model checker in this tree. They cannot observe
//! weak memory ordering either, since the host is TSO. The safety argument above, and the
//! `SeqCst` it depends on, are reviewed rather than tested.

use core::marker::PhantomData;
use core::sync::atomic::{AtomicPtr, AtomicUsize, Ordering};

use hal::{Arch, HasSmp, UniProcessor};

use crate::family::LockFamily;
use crate::lockdep::LockClass;
use crate::percpu::{PerCpu, Pinned};

#[cfg(test)]
mod tests;

/// Class of the lock that serialises advancing the epoch.
pub static EPOCH_ADVANCE: LockClass = LockClass::new("sync.epoch.advance");
/// Class of every limbo bag's lock. Never held with another bag, or with the advance lock.
pub static EPOCH_BAG: LockClass = LockClass::new("sync.epoch.bag");

/// Consecutive advances held back by one CPU at one epoch before it counts as stalled.
pub const STALL_ATTEMPTS: u32 = 64;

/// The low bit of a state word: the participant is inside a guard.
const ACTIVE: usize = 1;
/// Epochs are counted modulo this; the state word keeps one bit for [`ACTIVE`].
const EPOCH_MASK: usize = usize::MAX >> 1;

/// Whether a node retired at `retired` may be reclaimed at global epoch `global`.
///
/// Computed modulo the epoch width. Wrapping can only make a distance of two or more look
/// like zero or one, which delays a reclamation. It cannot make a distance under two look
/// like two, which would reclaim early.
const fn reclaimable(retired: usize, global: usize) -> bool {
    global.wrapping_sub(retired) & EPOCH_MASK >= 2
}

/// A retired node: where it is and how to reclaim it.
#[derive(Clone, Copy)]
struct Deferred {
    epoch: usize,
    ptr: *mut (),
    reclaim: unsafe fn(*mut ()),
}

// SAFETY: a `Deferred` is the only remaining owner of a node nothing can reach any more,
// and `Collector::retire`'s contract requires that `reclaim` may run on any CPU. Moving
// it between CPUs' bags therefore moves nothing that is still shared.
unsafe impl Send for Deferred {}

/// One CPU's limbo list.
struct Bag<const N: usize> {
    items: [Option<Deferred>; N],
    len: usize,
    /// Every node ever retired into, and reclaimed from, this bag.
    retired: u64,
    reclaimed: u64,
}

impl<const N: usize> Bag<N> {
    const fn new() -> Self {
        Bag {
            items: [None; N],
            len: 0,
            retired: 0,
            reclaimed: 0,
        }
    }

    fn push(&mut self, d: Deferred) -> bool {
        let Some(slot) = self.items.get_mut(self.len) else {
            return false;
        };
        *slot = Some(d);
        self.len += 1;
        self.retired += 1;
        true
    }

    /// Remove one node that `global` makes reclaimable, if there is one.
    fn take_ready(&mut self, global: usize) -> Option<Deferred> {
        let live = self.items.get(..self.len)?;
        let i = live
            .iter()
            .position(|d| d.is_some_and(|d| reclaimable(d.epoch, global)))?;
        let last = self.len - 1;
        self.items.swap(i, last);
        self.len = last;
        self.reclaimed += 1;
        self.items.get_mut(last)?.take()
    }
}

/// One CPU's part in the protocol.
struct Participant<L: LockFamily, const BAG: usize> {
    /// `epoch << 1 | ACTIVE`. Written by this CPU, read by advancers.
    state: AtomicUsize,
    /// Guards nested on this CPU. Only this CPU touches it, with interrupts masked.
    depth: AtomicUsize,
    bag: L::Lock<Bag<BAG>>,
}

impl<L: LockFamily, const BAG: usize> Participant<L, BAG> {
    fn new() -> Self {
        Participant {
            state: AtomicUsize::new(0),
            depth: AtomicUsize::new(0),
            bag: L::new(Bag::new(), &EPOCH_BAG),
        }
    }
}

/// What the last failed advance found.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct Blocked {
    cpu: usize,
    epoch: usize,
    attempts: u32,
}

/// A participant that has held the epoch back for [`STALL_ATTEMPTS`] advances or more.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Stall {
    /// The CPU whose guard is holding the epoch back.
    pub cpu: usize,
    /// The epoch that CPU is pinned at.
    pub pinned_at: usize,
    /// The global epoch it is holding.
    pub global: usize,
    /// Consecutive advances it has held back.
    pub attempts: u32,
}

/// Why [`Collector::retire`] refused a node. The caller still owns it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RetireError {
    /// The running CPU's bag is full, and the epoch cannot advance because this CPU is
    /// holding it back.
    Stalled(Stall),
    /// The running CPU's bag is full, and nothing it could reclaim yet made room. Every node
    /// in it is younger than two epochs: retirement is outpacing advancement.
    Full,
    /// The running CPU has no participant slot. See [`Collector::sized`].
    NoSlot,
    /// The guard was pinned on a different collector.
    ForeignGuard,
}

/// Counts, summed over every CPU.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Stats {
    pub epoch: usize,
    pub retired: u64,
    pub reclaimed: u64,
    /// Retired and not yet reclaimed.
    pub pending: u64,
}

/// An epoch-based reclamation domain: one global epoch, one participant per CPU.
///
/// `L` protects the bags and serialises advancing. `CPUS` is the number of participant slots
/// and `BAG` the capacity of each CPU's limbo bag.
pub struct Collector<A: Arch, L: LockFamily, const CPUS: usize, const BAG: usize> {
    global: AtomicUsize,
    advance: L::Lock<Option<Blocked>>,
    participants: PerCpu<Participant<L, BAG>, CPUS>,
    _arch: PhantomData<fn() -> A>,
}

impl<A: HasSmp, L: LockFamily, const CPUS: usize, const BAG: usize> Collector<A, L, CPUS, BAG> {
    /// A collector for an SMP architecture: a participant for every CPU `A` can start.
    /// Fails to build if `CPUS` is less than [`HasSmp::MAX_CPUS`].
    pub fn new() -> Self {
        Self::from_participants(PerCpu::new::<A>(core::array::from_fn(|_| Participant::new())))
    }
}

impl<A: UniProcessor, L: LockFamily, const BAG: usize> Collector<A, L, 1, BAG> {
    /// A collector for a uniprocessor: one participant.
    pub fn uniprocessor() -> Self {
        Self::from_participants(PerCpu::uniprocessor::<A>(Participant::new()))
    }
}

impl<A: Arch, L: LockFamily, const CPUS: usize, const BAG: usize> Collector<A, L, CPUS, BAG> {
    /// A collector with `CPUS` participant slots and no architecture bound to size it by,
    /// for code that must build on every architecture with the configuration's CPU count.
    ///
    /// A CPU whose index has no slot cannot pin: [`Collector::pin`] returns `None` there,
    /// rather than sharing another CPU's participant.
    pub fn sized() -> Self {
        Self::from_participants(PerCpu::sized(core::array::from_fn(|_| Participant::new())))
    }

    fn from_participants(participants: PerCpu<Participant<L, BAG>, CPUS>) -> Self {
        Collector {
            global: AtomicUsize::new(0),
            advance: L::new(None, &EPOCH_ADVANCE),
            participants,
            _arch: PhantomData,
        }
    }

    /// Enter a read-side critical section on the running CPU.
    ///
    /// `None` only for a CPU with no participant slot. Every pointer loaded through the
    /// returned guard stays valid until it drops.
    pub fn pin(&self) -> Option<Guard<'_, A, L, CPUS, BAG>> {
        let pin = Pinned::<A>::new();
        let cpu = pin.cpu();
        let p = self.participants.slot(cpu)?;
        let depth = p.depth.load(Ordering::Relaxed);
        if depth == 0 {
            let epoch = self.global.load(Ordering::SeqCst);
            // SeqCst: this store and an advancer's load of it are the handshake the module
            // documentation's argument rests on.
            p.state.store((epoch << 1) | ACTIVE, Ordering::SeqCst);
        }
        // Relaxed: only this CPU reads or writes `depth`, with interrupts masked.
        p.depth.store(depth.saturating_add(1), Ordering::Relaxed);
        Some(Guard {
            collector: self,
            cpu,
            _pin: pin,
        })
    }

    /// The current global epoch.
    pub fn epoch(&self) -> usize {
        self.global.load(Ordering::SeqCst)
    }

    /// Move the global epoch forward by one if every active participant has observed it.
    ///
    /// `Err` names the CPU that held it back.
    pub fn try_advance(&self) -> Result<usize, (usize, usize)> {
        L::with(&self.advance, |blocked| {
            let global = self.global.load(Ordering::SeqCst);
            for (cpu, p) in self.participants.iter().enumerate() {
                let state = p.state.load(Ordering::SeqCst);
                let pinned_at = state >> 1;
                if state & ACTIVE != 0 && pinned_at != global {
                    *blocked = Some(match *blocked {
                        Some(b) if b.cpu == cpu && b.epoch == pinned_at => Blocked {
                            attempts: b.attempts.saturating_add(1),
                            ..b
                        },
                        _ => Blocked {
                            cpu,
                            epoch: pinned_at,
                            attempts: 1,
                        },
                    });
                    return Err((cpu, pinned_at));
                }
            }
            let next = global.wrapping_add(1) & EPOCH_MASK;
            // SeqCst: the other half of the handshake with `pin`.
            self.global.store(next, Ordering::SeqCst);
            *blocked = None;
            Ok(next)
        })
    }

    /// The participant holding the epoch back, once it has done so for
    /// [`STALL_ATTEMPTS`] consecutive advances.
    pub fn stall(&self) -> Option<Stall> {
        let global = self.epoch();
        L::with(&self.advance, |blocked| {
            blocked
                .filter(|b| b.attempts >= STALL_ATTEMPTS)
                .map(|b| Stall {
                    cpu: b.cpu,
                    pinned_at: b.epoch,
                    global,
                    attempts: b.attempts,
                })
        })
    }

    /// Hand a node, already unlinked from everything a reader could reach, to the
    /// collector. It is reclaimed with `reclaim(ptr)` once no guard that could have reached
    /// it is alive.
    ///
    /// If the running CPU's bag is full, this first tries to advance and to reclaim from
    /// that bag. If there is still no room, the node is refused and the caller keeps it.
    ///
    /// # Safety
    /// - `ptr` must be unreachable for any guard pinned from now on, and must not be retired twice.
    /// - `reclaim(ptr)` must be sound to call exactly once, on any CPU, from the context of a later
    ///   `collect` or `flush`, including with interrupts masked.
    pub unsafe fn retire(
        &self,
        guard: &Guard<'_, A, L, CPUS, BAG>,
        ptr: *mut (),
        reclaim: unsafe fn(*mut ()),
    ) -> Result<(), RetireError> {
        let p = self.participant(guard)?;
        // Two rounds of advance-and-reclaim at most: a node retired in the current epoch
        // needs two advances before it is ready.
        for round in 0..3 {
            let pushed = L::with(&p.bag, |bag| {
                bag.push(Deferred {
                    epoch: self.epoch(),
                    ptr,
                    reclaim,
                })
            });
            if pushed {
                return Ok(());
            }
            if round == 2 {
                break;
            }
            let _ = self.try_advance();
            self.reclaim_from(p);
        }
        Err(self.stall().map_or(RetireError::Full, RetireError::Stalled))
    }

    /// Try to advance, then reclaim whatever the running CPU's bag holds that is ready.
    /// Returns how many nodes were reclaimed.
    pub fn collect(&self, guard: &Guard<'_, A, L, CPUS, BAG>) -> usize {
        let _ = self.try_advance();
        self.participant(guard).map_or(0, |p| self.reclaim_from(p))
    }

    /// Advance as far as the participants allow, up to twice, and reclaim every ready node
    /// on every CPU. For quiescent points and teardown.
    ///
    /// Must not be called while the running CPU holds a guard: that guard would hold the
    /// epoch back and be reported as a stall.
    pub fn flush(&self) -> Result<usize, (usize, usize)> {
        let mut result = Ok(());
        for _ in 0..2 {
            if let Err(e) = self.try_advance() {
                result = Err(e);
                break;
            }
        }
        let reclaimed = self.participants.iter().map(|p| self.reclaim_from(p)).sum();
        result.map(|()| reclaimed)
    }

    /// Counts over every CPU.
    pub fn stats(&self) -> Stats {
        let mut s = Stats {
            epoch: self.epoch(),
            ..Stats::default()
        };
        for p in self.participants.iter() {
            L::with(&p.bag, |bag| {
                s.retired += bag.retired;
                s.reclaimed += bag.reclaimed;
            });
        }
        s.pending = s.retired - s.reclaimed;
        s
    }

    fn participant(
        &self,
        guard: &Guard<'_, A, L, CPUS, BAG>,
    ) -> Result<&Participant<L, BAG>, RetireError> {
        if !core::ptr::eq(guard.collector, self) {
            return Err(RetireError::ForeignGuard);
        }
        self.participants.slot(guard.cpu).ok_or(RetireError::NoSlot)
    }

    /// Reclaim every ready node in `p`'s bag, one at a time, each outside the bag's lock so
    /// that a `reclaim` function may itself retire or collect.
    fn reclaim_from(&self, p: &Participant<L, BAG>) -> usize {
        let mut n = 0;
        loop {
            let global = self.epoch();
            let Some(d) = L::with(&p.bag, |bag| bag.take_ready(global)) else {
                return n;
            };
            // SAFETY: `retire`'s contract: `d.ptr` is unreachable for every guard pinned
            // after its retirement, and `reclaimable` holds, so by the module's argument no
            // guard that could have reached it is still alive. It left the bag above, so
            // this is the one call.
            unsafe { (d.reclaim)(d.ptr) };
            n += 1;
        }
    }
}

impl<A: HasSmp, L: LockFamily, const CPUS: usize, const BAG: usize> Default
    for Collector<A, L, CPUS, BAG>
{
    fn default() -> Self {
        Self::new()
    }
}

/// A read-side critical section on one CPU. See [`Collector::pin`].
///
/// `!Send` through its [`Pinned`]: it belongs to the CPU that pinned.
pub struct Guard<'c, A: Arch, L: LockFamily, const CPUS: usize, const BAG: usize> {
    collector: &'c Collector<A, L, CPUS, BAG>,
    cpu: usize,
    _pin: Pinned<A>,
}

impl<A: Arch, L: LockFamily, const CPUS: usize, const BAG: usize> Guard<'_, A, L, CPUS, BAG> {
    /// The CPU this guard is pinned on.
    pub fn cpu(&self) -> usize {
        self.cpu
    }
}

impl<A: Arch, L: LockFamily, const CPUS: usize, const BAG: usize> Drop
    for Guard<'_, A, L, CPUS, BAG>
{
    fn drop(&mut self) {
        // The slot exists: `pin` returned this guard only after finding it.
        let Some(p) = self.collector.participants.slot(self.cpu) else {
            return;
        };
        let depth = p.depth.load(Ordering::Relaxed);
        if depth == 1 {
            let state = p.state.load(Ordering::Relaxed);
            // SeqCst: an advancer must see the participant leave.
            p.state.store(state & !ACTIVE, Ordering::SeqCst);
        }
        p.depth.store(depth.saturating_sub(1), Ordering::Relaxed);
        // `_pin` drops after this, restoring interrupts.
    }
}

/// A pointer that readers load under a [`Guard`] and a writer replaces, retiring what it
/// replaced. The shape RCU calls `rcu_dereference` / `rcu_assign_pointer`.
///
/// Tied to one collector: a guard from another is refused.
///
/// **Writers must be serialised by the caller**, with a lock of their own. Readers need
/// nothing. That is the usual rule for this pattern, and it is why no compare-and-swap is
/// needed.
pub struct EpochPtr<'c, T, A: Arch, L: LockFamily, const CPUS: usize, const BAG: usize> {
    ptr: AtomicPtr<T>,
    collector: &'c Collector<A, L, CPUS, BAG>,
    /// `AtomicPtr` is `Sync` whatever it points at. Readers on several CPUs share the
    /// target through `load`, so the pointer may only be shared if the target may be.
    _target: PhantomData<&'c T>,
}

impl<'c, T, A: Arch, L: LockFamily, const CPUS: usize, const BAG: usize>
    EpochPtr<'c, T, A, L, CPUS, BAG>
{
    /// A pointer holding `ptr`, which may be null.
    ///
    /// # Safety
    /// A non-null `ptr` must stay valid until this pointer stops naming it and it has been
    /// retired to `collector` (see [`EpochPtr::replace`]), or until this is dropped with no
    /// guard alive.
    pub unsafe fn new(ptr: *mut T, collector: &'c Collector<A, L, CPUS, BAG>) -> Self {
        EpochPtr {
            ptr: AtomicPtr::new(ptr),
            collector,
            _target: PhantomData,
        }
    }

    /// The current target, valid for as long as `guard` lives. `None` if null, or if `guard`
    /// belongs to another collector.
    pub fn load<'g>(&self, guard: &'g Guard<'_, A, L, CPUS, BAG>) -> Option<&'g T> {
        if !core::ptr::eq(guard.collector, self.collector) {
            return None;
        }
        // SeqCst: a reader must see a pointer the writer stored before the node it replaced
        // is retired, and the retirement is ordered after that store.
        let p = self.ptr.load(Ordering::SeqCst);
        // SAFETY: by `new`'s and `replace`'s contracts, a pointer stored here is valid until
        // it is replaced and retired to this collector. `guard` is this collector's and was
        // pinned before this load, so the module's argument keeps the target alive until
        // `guard` drops, which the returned lifetime cannot outlive.
        unsafe { p.as_ref() }
    }

    /// Point readers at `new`, and retire the node they were reading.
    ///
    /// If the retirement is refused, the pointer is left unchanged, and the error comes back
    /// with `new` still the caller's. That is checked before anything is stored, so a
    /// refusal changes nothing a reader can see.
    ///
    /// # Safety
    /// - The caller serialises writers of this pointer.
    /// - `new` is null, or valid until it is itself replaced and retired.
    /// - `reclaim` meets [`Collector::retire`]'s contract for the node being replaced.
    pub unsafe fn replace(
        &self,
        new: *mut T,
        reclaim: unsafe fn(*mut ()),
        guard: &Guard<'_, A, L, CPUS, BAG>,
    ) -> Result<(), RetireError> {
        let p = self.collector.participant(guard)?;
        // Make room first, so a refusal happens before anything is unlinked.
        if !self.collector.has_room(p) {
            let _ = self.collector.try_advance();
            self.collector.reclaim_from(p);
            if !self.collector.has_room(p) {
                let _ = self.collector.try_advance();
                self.collector.reclaim_from(p);
            }
            if !self.collector.has_room(p) {
                return Err(self
                    .collector
                    .stall()
                    .map_or(RetireError::Full, RetireError::Stalled));
            }
        }
        let old = self.ptr.load(Ordering::SeqCst);
        self.ptr.store(new, Ordering::SeqCst);
        if old.is_null() {
            return Ok(());
        }
        // SAFETY: `old` was just unlinked, and guards pinned from now on load `new`. Writers
        // are serialised, so nothing else retires it. `reclaim` is the caller's promise. The
        // room checked above is still there: only this CPU adds to its own bag, and it has
        // been pinned throughout.
        unsafe { self.collector.retire(guard, old.cast(), reclaim) }
    }
}

impl<A: Arch, L: LockFamily, const CPUS: usize, const BAG: usize> Collector<A, L, CPUS, BAG> {
    fn has_room(&self, p: &Participant<L, BAG>) -> bool {
        L::with(&p.bag, |bag| bag.len < BAG)
    }
}

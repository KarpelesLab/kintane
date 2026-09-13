//! The kernel object model.
//!
//! Every kernel-managed thing a program can hold — a process, a channel endpoint, a
//! memory region, a device handle — is an object with an identity, a type, and a
//! reference count. A program never names an object directly; it names a *handle*,
//! which pairs an object with the rights the holder has over it.
//!
//! Three pieces, each with one job:
//!
//! * [`rights`] — what a handle permits, and the rule that rights only ever narrow.
//! * [`handle`] — the per-process table, and the generation counters that stop a closed handle from
//!   reaching a slot's next occupant.
//! * [`store`] — objects found by identity and kept alive while referenced: the step from a
//!   handle's entry to the object it names.
//! * [`Refcount`] — a reference count embedded in an object, for objects that live outside a store.
//!
//! This layer still does not own object *bytes*. A store holds references to objects whose
//! memory belongs to someone else, and tells that owner when to free them. Where the bytes
//! live is a decision for each kind of object.

#![cfg_attr(not(test), no_std)]
#![deny(unsafe_code)]

pub mod handle;
pub mod rights;
pub mod store;

#[cfg(target_has_atomic = "32")]
use core::sync::atomic::AtomicU32;
#[cfg(target_has_atomic = "64")]
use core::sync::atomic::AtomicU64;
#[cfg(any(target_has_atomic = "32", target_has_atomic = "64"))]
use core::sync::atomic::Ordering;

pub use handle::{Handle, HandleTable, TransferError};
pub use rights::Rights;
pub use store::{Locator, ObjRef, ObjectStore, StoreError};
use sync::{LockClass, LockFamily};

/// A kernel object's identity.
///
/// Distinct from a handle: an identity is global and stable, a handle is per-process
/// and revocable. Two processes holding the same object hold different handles to
/// one `ObjectId`.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct ObjectId(u64);

impl ObjectId {
    pub const fn from_raw(v: u64) -> ObjectId {
        ObjectId(v)
    }
    pub const fn raw(self) -> u64 {
        self.0
    }
}

/// Anything that hands out object identities.
///
/// Code that creates objects takes this rather than [`ObjectIds`], so it does not inherit
/// the allocator's requirements. [`ObjectIds`] needs a 64-bit atomic counter, which rv32imac
/// and thumbv7m do not have, and rv32i has no compare-and-swap at all. [`LockedIds`] is the
/// same counter behind a lock, for those machines.
///
/// Every implementation must never return the same identity twice.
pub trait IdSource {
    fn next(&self) -> ObjectId;
}

/// The lock-order class of every [`LockedIds`].
pub static IDS_LOCK: LockClass = LockClass::new("kobject.ids");

/// Hands out object identities, like [`ObjectIds`], from a counter behind a lock of family
/// `L`. For machines without 64-bit atomics; it works on every machine, at the cost of a
/// lock per identity.
pub struct LockedIds<L: LockFamily> {
    next: L::Lock<u64>,
}

impl<L: LockFamily> LockedIds<L> {
    pub fn new() -> Self {
        // Zero is never issued, as for `ObjectIds`.
        LockedIds {
            next: L::new(1, &IDS_LOCK),
        }
    }
}

impl<L: LockFamily> Default for LockedIds<L> {
    fn default() -> Self {
        Self::new()
    }
}

impl<L: LockFamily> IdSource for LockedIds<L> {
    fn next(&self) -> ObjectId {
        L::with(&self.next, |n| {
            let id = *n;
            // Wrapping, like `ObjectIds`: 2^64 identities outlast the hardware.
            *n = n.wrapping_add(1);
            ObjectId(id)
        })
    }
}

/// Hands out object identities.
///
/// Monotonic and never reused. Recycling identities would reintroduce, at the object
/// layer, exactly the confusion the handle generations exist to prevent — and unlike
/// a handle slot, an identity may be held by another machine by the time it is
/// reused. 2^64 identities at a billion per second is longer than the hardware will
/// last.
///
/// Absent on machines without 64-bit atomics; see [`IdSource`].
#[cfg(target_has_atomic = "64")]
pub struct ObjectIds(AtomicU64);

#[cfg(target_has_atomic = "64")]
impl Default for ObjectIds {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(target_has_atomic = "64")]
impl ObjectIds {
    pub const fn new() -> Self {
        // Zero is never issued, so a zeroed field is never a valid identity.
        ObjectIds(AtomicU64::new(1))
    }

    pub fn next(&self) -> ObjectId {
        ObjectId(self.0.fetch_add(1, Ordering::Relaxed))
    }
}

#[cfg(target_has_atomic = "64")]
impl IdSource for ObjectIds {
    fn next(&self) -> ObjectId {
        ObjectIds::next(self)
    }
}

/// What kind of thing an object is.
///
/// Checked at the handle boundary, so an operation can never be applied to the wrong
/// kind of object three layers in. Non-exhaustive: the set grows with the ABI, and
/// code matching on it must say what it does with kinds it does not know.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum ObjectType {
    Process,
    Thread,
    Channel,
    MemoryRegion,
    Mapping,
    Event,
    Timer,
    Interrupt,
    DeviceResource,
    Completion,
    Job,
}

impl ObjectType {
    pub const fn name(self) -> &'static str {
        match self {
            ObjectType::Process => "process",
            ObjectType::Thread => "thread",
            ObjectType::Channel => "channel",
            ObjectType::MemoryRegion => "memory-region",
            ObjectType::Mapping => "mapping",
            ObjectType::Event => "event",
            ObjectType::Timer => "timer",
            ObjectType::Interrupt => "interrupt",
            ObjectType::DeviceResource => "device-resource",
            ObjectType::Completion => "completion",
            ObjectType::Job => "job",
        }
    }
}

/// An object's reference count.
///
/// Embedded in each object rather than held beside it, so a reference cannot outlive
/// the count that describes it.
///
/// The orderings are the standard ones for this pattern and are worth stating,
/// because this is the class of mistake QEMU cannot find — it does not model weak
/// memory ordering, so a wrong ordering here passes every test we can run and fails
/// on real ARM silicon (see `docs/testing.md#what-qemu-will-not-catch`):
///
/// * `acquire` is `Relaxed`: the caller already holds a reference, so the object is provably alive
///   and no ordering with its contents is implied.
/// * `release` is `Release`, so every write made through the dropped reference happens-before the
///   count reaching zero.
/// * The last releaser issues an `Acquire` fence before destroying, pairing with every other
///   releaser's `Release` so their writes are visible to the destructor.
///
/// Absent on machines without 32-bit compare-and-swap, where a count lives under the
/// object's lock instead.
#[cfg(target_has_atomic = "32")]
pub struct Refcount(AtomicU32);

/// Why a reference could not be taken.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RefError {
    /// The object is being destroyed; its count already reached zero.
    Dead,
    /// The count would exceed what the counter can represent. Returned rather than
    /// wrapped: a wrapped refcount frees a live object.
    TooManyRefs,
}

#[cfg(target_has_atomic = "32")]
impl Refcount {
    /// A new object, held by its creator.
    pub const fn one() -> Refcount {
        Refcount(AtomicU32::new(1))
    }

    pub fn count(&self) -> u32 {
        self.0.load(Ordering::Relaxed)
    }

    pub fn is_dead(&self) -> bool {
        self.count() == 0
    }

    /// Take a reference, given that one is already held.
    pub fn acquire(&self) -> Result<(), RefError> {
        let mut cur = self.0.load(Ordering::Relaxed);
        loop {
            if cur == 0 {
                return Err(RefError::Dead);
            }
            if cur == u32::MAX {
                return Err(RefError::TooManyRefs);
            }
            match self
                .0
                .compare_exchange_weak(cur, cur + 1, Ordering::Relaxed, Ordering::Relaxed)
            {
                Ok(_) => return Ok(()),
                Err(actual) => cur = actual,
            }
        }
    }

    /// Drop a reference. Returns true if this was the last one and the caller is now
    /// responsible for destroying the object.
    ///
    /// Exactly one caller ever sees `true` for a given object.
    pub fn release(&self) -> bool {
        let previous = self.0.fetch_sub(1, Ordering::Release);
        debug_assert!(previous != 0, "released a reference that was not held");
        if previous != 1 {
            return false;
        }
        // Pair with every other releaser's Release so their writes are visible to
        // whatever runs next.
        core::sync::atomic::fence(Ordering::Acquire);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identities_are_unique_monotonic_and_never_zero() {
        let ids = ObjectIds::new();
        let a = ids.next();
        let b = ids.next();
        assert_ne!(a, b);
        assert!(b > a);
        assert_ne!(a.raw(), 0, "zero must never be a valid identity");
    }

    #[test]
    fn the_last_release_is_reported_exactly_once() {
        let rc = Refcount::one();
        rc.acquire().unwrap();
        rc.acquire().unwrap();
        assert_eq!(rc.count(), 3);
        assert!(!rc.release());
        assert!(!rc.release());
        assert!(rc.release(), "the last release owns destruction");
        assert!(rc.is_dead());
    }

    #[test]
    fn a_dead_object_cannot_be_resurrected() {
        let rc = Refcount::one();
        assert!(rc.release());
        assert_eq!(rc.acquire(), Err(RefError::Dead));
        assert_eq!(rc.count(), 0);
    }

    #[test]
    fn saturating_the_count_is_an_error_not_a_wrap() {
        // A wrapped refcount frees a live object, which is strictly worse than
        // refusing to take another reference.
        let rc = Refcount(AtomicU32::new(u32::MAX));
        assert_eq!(rc.acquire(), Err(RefError::TooManyRefs));
        assert_eq!(rc.count(), u32::MAX);
    }

    #[test]
    fn object_types_all_name_themselves() {
        for t in [
            ObjectType::Process,
            ObjectType::Thread,
            ObjectType::Channel,
            ObjectType::MemoryRegion,
            ObjectType::Job,
        ] {
            assert!(!t.name().is_empty());
        }
    }

    #[test]
    fn concurrent_acquire_and_release_balance() {
        extern crate std;
        use std::sync::Arc;
        // Not a proof of the orderings — only real hardware can be that — but it does
        // catch an outright wrong count under contention.
        let rc = Arc::new(Refcount::one());
        let mut handles = std::vec::Vec::new();
        for _ in 0..8 {
            let rc = Arc::clone(&rc);
            handles.push(std::thread::spawn(move || {
                for _ in 0..1000 {
                    rc.acquire().unwrap();
                    assert!(!rc.release());
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(rc.count(), 1, "every acquire was matched by a release");
        assert!(rc.release());
    }
}

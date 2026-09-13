//! Host tests for the object store, against both mock profiles.
//!
//! `destroy` is a plain `fn`, so the destroyed identities are recorded in a static, and every
//! test that reads it holds `SERIAL`.

extern crate std;

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard};
use std::vec::Vec;

use hal::mock::{MockFull, MockTiny};
use sync::{Irq, Spin};

use super::*;
use crate::{IdSource, LockedIds, ObjectIds};

static SERIAL: Mutex<()> = Mutex::new(());
static DESTROYED: Mutex<Vec<u64>> = Mutex::new(Vec::new());

fn serial() -> MutexGuard<'static, ()> {
    let g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    DESTROYED.lock().unwrap_or_else(|e| e.into_inner()).clear();
    g
}

fn destroyed() -> Vec<u64> {
    DESTROYED.lock().unwrap_or_else(|e| e.into_inner()).clone()
}

struct Obj {
    value: AtomicU64,
}

fn record(id: ObjectId, obj: &Obj) {
    // Poison it, as a real owner would free it: a later read through a stale reference
    // would show.
    obj.value.store(u64::MAX, Ordering::SeqCst);
    DESTROYED
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .push(id.raw());
}

fn objs(n: usize) -> Vec<Obj> {
    (0..n)
        .map(|i| Obj {
            value: AtomicU64::new(i as u64),
        })
        .collect()
}

fn lookup_type_and_deref<L: LockFamily>() {
    let ids = ObjectIds::new();
    let o = objs(2);
    let store: ObjectStore<'_, Obj, L, 4> = ObjectStore::new(record);
    let a = ids.next();
    let b = ids.next();
    store.insert(a, ObjectType::Event, &o[0]).unwrap();
    store.insert(b, ObjectType::Timer, &o[1]).unwrap();
    assert_eq!(store.len(), 2);

    let r = store.get(b).unwrap();
    assert_eq!(r.id(), b);
    assert_eq!(r.kind(), ObjectType::Timer);
    assert_eq!(r.value.load(Ordering::SeqCst), 1);
    assert_eq!(store.references(b), Some(2), "the store's and ours");
    drop(r);
    assert_eq!(store.references(b), Some(1));
    assert_eq!(store.get(ids.next()).err(), Some(StoreError::NotFound));
    assert_eq!(store.insert(a, ObjectType::Event, &o[0]).err(), Some(StoreError::Duplicate));
}

#[test]
fn lookup_type_and_deref_full() {
    let _s = serial();
    lookup_type_and_deref::<Spin<MockFull>>();
}

#[test]
fn lookup_type_and_deref_tiny() {
    let _s = serial();
    lookup_type_and_deref::<Irq<MockTiny>>();
}

fn retirement_waits_for_the_last_holder<L: LockFamily>() {
    let ids = ObjectIds::new();
    let o = objs(1);
    let store: ObjectStore<'_, Obj, L, 2> = ObjectStore::new(record);
    let a = ids.next();
    store.insert(a, ObjectType::Event, &o[0]).unwrap();

    let held = store.get(a).unwrap();
    let second = held.try_clone().unwrap();
    store.retire(a).unwrap();
    assert_eq!(store.get(a).err(), Some(StoreError::Retiring), "nothing new finds it");
    assert_eq!(store.retire(a), Err(StoreError::Retiring), "and it retires once");
    assert!(destroyed().is_empty(), "destroyed under a live reference");
    assert_eq!(held.value.load(Ordering::SeqCst), 0, "still intact for its holders");

    drop(held);
    assert!(destroyed().is_empty());
    drop(second);
    assert_eq!(destroyed(), [a.raw()], "destroyed exactly once, by the last drop");
    assert_eq!(store.len(), 0);
    assert_eq!(store.get(a).err(), Some(StoreError::NotFound));
}

#[test]
fn retirement_waits_for_the_last_holder_full() {
    let _s = serial();
    retirement_waits_for_the_last_holder::<Spin<MockFull>>();
}

#[test]
fn retirement_waits_for_the_last_holder_tiny() {
    let _s = serial();
    retirement_waits_for_the_last_holder::<Irq<MockTiny>>();
}

#[test]
fn retiring_an_unreferenced_object_destroys_it_now() {
    let _s = serial();
    let ids = ObjectIds::new();
    let o = objs(1);
    let store: ObjectStore<'_, Obj, Spin<MockFull>, 2> = ObjectStore::new(record);
    let a = ids.next();
    store.insert(a, ObjectType::Event, &o[0]).unwrap();
    store.retire(a).unwrap();
    assert_eq!(destroyed(), [a.raw()]);
}

#[test]
fn a_stale_locator_does_not_reach_the_slots_next_occupant() {
    let _s = serial();
    let ids = ObjectIds::new();
    let o = objs(2);
    let store: ObjectStore<'_, Obj, Spin<MockFull>, 1> = ObjectStore::new(record);
    let a = ids.next();
    let at_a = store.insert(a, ObjectType::Event, &o[0]).unwrap();
    assert_eq!(store.get_at(at_a, a).unwrap().value.load(Ordering::SeqCst), 0);
    store.retire(a).unwrap();

    let b = ids.next();
    let at_b = store.insert(b, ObjectType::Event, &o[1]).unwrap();
    assert_ne!(at_a, at_b, "the reused slot has moved to a new generation");
    assert_eq!(store.get_at(at_a, a).err(), Some(StoreError::NotFound));
    assert_eq!(store.get_at(at_b, a).err(), Some(StoreError::NotFound), "wrong identity");
    assert_eq!(store.get_at(at_b, b).unwrap().id(), b);
}

#[test]
fn a_slot_whose_generation_runs_out_is_never_reused() {
    let _s = serial();
    let ids = ObjectIds::new();
    let o = objs(2);
    let store: ObjectStore<'_, Obj, Spin<MockFull>, 1> = ObjectStore::new(record);
    let a = ids.next();
    store.insert(a, ObjectType::Event, &o[0]).unwrap();
    store.set_generation(a, MAX_GENERATION - 1);
    store.retire(a).unwrap();
    assert_eq!(
        store.insert(ids.next(), ObjectType::Event, &o[1]).err(),
        Some(StoreError::Full),
        "the one slot wore out rather than wrap"
    );
}

#[test]
fn a_full_store_refuses() {
    let _s = serial();
    let ids = ObjectIds::new();
    let o = objs(3);
    let store: ObjectStore<'_, Obj, Spin<MockFull>, 2> = ObjectStore::new(record);
    store.insert(ids.next(), ObjectType::Event, &o[0]).unwrap();
    store.insert(ids.next(), ObjectType::Event, &o[1]).unwrap();
    assert_eq!(store.insert(ids.next(), ObjectType::Event, &o[2]).err(), Some(StoreError::Full));
}

#[test]
fn a_handle_resolves_to_its_object_with_type_and_rights_checked() {
    let _s = serial();
    let ids = ObjectIds::new();
    let o = objs(1);
    let store: ObjectStore<'_, Obj, Spin<MockFull>, 4> = ObjectStore::new(record);
    let mut table = HandleTable::<4>::new();
    let a = ids.next();
    store.insert(a, ObjectType::Event, &o[0]).unwrap();
    let h = table.insert(a, ObjectType::Event, Rights::READ).unwrap();

    let r = store
        .resolve(&table, h, ObjectType::Event, Rights::READ)
        .unwrap();
    assert_eq!(r.id(), a);
    drop(r);
    assert!(matches!(
        store.resolve(&table, h, ObjectType::Event, Rights::WRITE),
        Err(StoreError::Handle(handle::Error::AccessDenied { .. }))
    ));
    assert!(matches!(
        store.resolve(&table, h, ObjectType::Timer, Rights::READ),
        Err(StoreError::Handle(handle::Error::WrongType { .. }))
    ));

    // A handle whose entry claims a type the store disagrees with is refused too.
    let lying = table.insert(a, ObjectType::Timer, Rights::READ).unwrap();
    assert_eq!(
        store
            .resolve(&table, lying, ObjectType::Timer, Rights::READ)
            .err(),
        Some(StoreError::WrongType {
            expected: ObjectType::Timer,
            found: ObjectType::Event
        })
    );

    store.retire(a).unwrap();
    assert_eq!(
        store
            .resolve(&table, h, ObjectType::Event, Rights::READ)
            .err(),
        Some(StoreError::NotFound),
        "destroyed at retirement, since nothing held it"
    );
    table.close(h).unwrap();
    assert!(matches!(
        store.resolve(&table, h, ObjectType::Event, Rights::READ),
        Err(StoreError::Handle(handle::Error::BadHandle))
    ));
}

#[test]
fn concurrent_lookups_and_drops_balance() {
    let _s = serial();
    let ids = ObjectIds::new();
    let o = objs(1);
    let store: ObjectStore<'_, Obj, Spin<MockFull>, 2> = ObjectStore::new(record);
    let a = ids.next();
    store.insert(a, ObjectType::Event, &o[0]).unwrap();
    std::thread::scope(|s| {
        for cpu in 0..4 {
            let store = &store;
            s.spawn(move || {
                hal::mock::set_cpu(cpu);
                for _ in 0..2000 {
                    let r = store.get(a).unwrap();
                    assert_eq!(r.value.load(Ordering::SeqCst), 0);
                }
            });
        }
    });
    assert_eq!(store.references(a), Some(1), "every lookup's reference was given back");
    store.retire(a).unwrap();
    assert_eq!(destroyed(), [a.raw()]);
}

#[test]
fn locked_ids_are_unique_monotonic_and_never_zero() {
    let _s = serial();
    let ids: LockedIds<Irq<MockTiny>> = LockedIds::new();
    let a = ids.next();
    let b = ids.next();
    assert_ne!(a.raw(), 0);
    assert!(b > a);
    let full: LockedIds<Spin<MockFull>> = LockedIds::new();
    let mut seen: Vec<u64> = (0..100).map(|_| full.next().raw()).collect();
    seen.dedup();
    assert_eq!(seen.len(), 100);
}

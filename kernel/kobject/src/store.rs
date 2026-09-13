//! The object store: kernel objects found by identity, alive while referenced.
//!
//! A [`HandleTable`] maps a handle to an [`Entry`]: an identity, a type, rights. It stops
//! there on purpose, and something has to take the identity the rest of the way to the
//! object. That is this module, and it is where "how long does an object live" gets its
//! answer.
//!
//! # The model
//!
//! An [`ObjectStore`] holds up to `N` objects of one Rust type. The objects themselves live
//! wherever their owner put them: in an arena, in a leaked heap block, in a static. The
//! store holds a shared reference to each and its lifecycle, and it calls the owner's
//! `destroy` function when the object's last reference is gone. That keeps the store free
//! of allocation and of `unsafe`, and it lets one store serve objects whose memory is
//! managed in different ways.
//!
//! Each object has a reference count, kept under the store's lock:
//!
//! - **The store's own reference**, taken by [`ObjectStore::insert`] and given up by
//!   [`ObjectStore::retire`].
//! - **One per [`ObjRef`]**, taken by [`ObjectStore::get`], [`ObjectStore::get_at`] or
//!   [`ObjectStore::resolve`], and given up when the `ObjRef` drops.
//!
//! **Retirement** is what "delete" means here. A retired object is found by nothing new:
//! `get` reports it as [`StoreError::Retiring`]. It stays alive for whoever already holds an
//! `ObjRef`, and it is destroyed when the last of those drops. So a lookup that succeeded is
//! never invalidated from under its holder, and a lookup that starts after retirement never
//! succeeds.
//!
//! # Generations
//!
//! Identities are never reused ([`crate::IdSource`]), so a stale identity can never find a
//! new object. Slots are reused, though, and a [`Locator`] (slot and generation, for O(1)
//! lookup) could name a slot's next occupant. So a slot's generation advances every time it
//! is vacated, a `Locator` must match it, and a slot whose generation would wrap is retired
//! for good. That is the handle table's rule, applied to slots.
//!
//! # Handle to object
//!
//! [`ObjectStore::resolve`] is the path a system call takes: a handle, the type the call
//! needs and the rights it requires, checked by the handle table in one place, then the
//! identity found here and its type checked again against what the store recorded. A handle
//! naming an object that has since been retired resolves to `Retiring`.
//!
//! # Cost
//!
//! Lookup by identity scans the slots, O(`N`). Lookup by `Locator` is O(1). Every lookup and
//! every drop of an `ObjRef` takes the store's lock once, briefly. A store that has to serve
//! a hot read path lock-free would put its table behind `sync::epoch` instead. None needs to
//! yet.

use core::fmt;
use core::ops::Deref;

use sync::{LockClass, LockFamily};

use crate::handle::{self, Handle, HandleTable};
use crate::rights::Rights;
use crate::{ObjectId, ObjectType};

/// The lock-order class of every store's lock.
pub static STORE_LOCK: LockClass = LockClass::new("kobject.store");

/// A slot whose generation reaches this is retired rather than reused.
const MAX_GENERATION: u32 = u32::MAX;

/// Where an object sits: O(1) lookup, valid until the slot is vacated.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Locator {
    index: u32,
    generation: u32,
}

/// Why a store operation failed. Nothing changed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum StoreError {
    /// No live object has this identity, or the locator's slot has moved on.
    NotFound,
    /// The object is retired: found by nothing new, destroyed once its last holder lets go.
    Retiring,
    /// The object is not of the type the caller needs.
    WrongType {
        expected: ObjectType,
        found: ObjectType,
    },
    /// The handle was refused by its table: stale, of the wrong type, or lacking rights.
    Handle(handle::Error),
    /// The reference count is at its maximum.
    TooManyRefs,
    /// Every slot is occupied or retired.
    Full,
    /// An object with this identity is already in the store.
    Duplicate,
}

enum State<'o, T> {
    Free,
    Live(&'o T),
    Retiring(&'o T),
    /// The generation ran out; never reused.
    Worn,
}

impl<T> Clone for State<'_, T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T> Copy for State<'_, T> {}

struct Slot<'o, T> {
    generation: u32,
    id: ObjectId,
    kind: ObjectType,
    refs: u32,
    state: State<'o, T>,
}

impl<T> Clone for Slot<'_, T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T> Copy for Slot<'_, T> {}

struct Table<'o, T, const N: usize> {
    slots: [Slot<'o, T>; N],
    live: usize,
}

impl<'o, T, const N: usize> Table<'o, T, N> {
    fn find(&self, id: ObjectId) -> Option<usize> {
        self.slots
            .iter()
            .position(|s| s.id == id && matches!(s.state, State::Live(_) | State::Retiring(_)))
    }

    /// Drop one reference from slot `index`. Returns the object to destroy if that was the
    /// last one.
    fn release(&mut self, index: usize) -> Option<(ObjectId, &'o T)> {
        let slot = self.slots.get_mut(index)?;
        slot.refs = slot.refs.checked_sub(1)?;
        if slot.refs != 0 {
            return None;
        }
        let State::Retiring(object) = slot.state else {
            // A live object always holds the store's reference, so its count cannot reach
            // zero. Leave it be rather than destroy something still findable.
            debug_assert!(false, "a live object's count reached zero");
            return None;
        };
        let id = slot.id;
        slot.generation = slot.generation.wrapping_add(1);
        slot.state = if slot.generation >= MAX_GENERATION {
            State::Worn
        } else {
            State::Free
        };
        self.live -= 1;
        Some((id, object))
    }
}

/// Up to `N` objects of type `T`, protected by lock family `L`. See the module
/// documentation.
pub struct ObjectStore<'o, T: Sync, L: LockFamily, const N: usize> {
    table: L::Lock<Table<'o, T, N>>,
    destroy: fn(ObjectId, &'o T),
}

impl<'o, T: Sync, L: LockFamily, const N: usize> ObjectStore<'o, T, L, N> {
    /// An empty store that calls `destroy` for each object whose last reference is gone.
    ///
    /// `destroy` runs with no store lock held, on whichever CPU dropped the last reference.
    pub fn new(destroy: fn(ObjectId, &'o T)) -> Self {
        let empty = Slot {
            generation: 0,
            id: ObjectId(0),
            kind: ObjectType::Event,
            refs: 0,
            state: State::Free,
        };
        ObjectStore {
            table: L::new(
                Table {
                    slots: [empty; N],
                    live: 0,
                },
                &STORE_LOCK,
            ),
            destroy,
        }
    }

    /// Add `object`, of type `kind`, under identity `id`, held by the store.
    pub fn insert(
        &self,
        id: ObjectId,
        kind: ObjectType,
        object: &'o T,
    ) -> Result<Locator, StoreError> {
        L::with(&self.table, |t| {
            if t.find(id).is_some() {
                return Err(StoreError::Duplicate);
            }
            let index = t
                .slots
                .iter()
                .position(|s| matches!(s.state, State::Free))
                .ok_or(StoreError::Full)?;
            let slot = t.slots.get_mut(index).ok_or(StoreError::Full)?;
            *slot = Slot {
                generation: slot.generation,
                id,
                kind,
                refs: 1,
                state: State::Live(object),
            };
            t.live += 1;
            Ok(Locator {
                index: index as u32,
                generation: slot.generation,
            })
        })
    }

    /// Find a live object by identity and take a reference to it.
    pub fn get(&self, id: ObjectId) -> Result<ObjRef<'_, 'o, T, L, N>, StoreError> {
        let taken = L::with(&self.table, |t| {
            let index = t.find(id).ok_or(StoreError::NotFound)?;
            Self::acquire(t, index)
        });
        taken.map(|a| self.wrap(a))
    }

    /// Find the object at `at`, which must still be `id`, and take a reference to it.
    pub fn get_at(&self, at: Locator, id: ObjectId) -> Result<ObjRef<'_, 'o, T, L, N>, StoreError> {
        let taken = L::with(&self.table, |t| {
            let index = at.index as usize;
            let slot = t.slots.get(index).ok_or(StoreError::NotFound)?;
            if slot.generation != at.generation || slot.id != id {
                return Err(StoreError::NotFound);
            }
            Self::acquire(t, index)
        });
        taken.map(|a| self.wrap(a))
    }

    /// Resolve a handle to the object it names: `handle` must be live in `table`, name an
    /// object of type `kind`, and carry `required`.
    pub fn resolve<const M: usize>(
        &self,
        table: &HandleTable<M>,
        handle: Handle,
        kind: ObjectType,
        required: Rights,
    ) -> Result<ObjRef<'_, 'o, T, L, N>, StoreError> {
        let entry = table
            .get_checked(handle, kind, required)
            .map_err(StoreError::Handle)?;
        let r = self.get(entry.object)?;
        if r.kind() != kind {
            return Err(StoreError::WrongType {
                expected: kind,
                found: r.kind(),
            });
        }
        Ok(r)
    }

    /// Give up the store's reference to `id`. Nothing new finds it; it is destroyed when
    /// the last outstanding [`ObjRef`] drops, or now if there is none.
    pub fn retire(&self, id: ObjectId) -> Result<(), StoreError> {
        let destroyed = L::with(&self.table, |t| {
            let index = t.find(id).ok_or(StoreError::NotFound)?;
            let slot = t.slots.get_mut(index).ok_or(StoreError::NotFound)?;
            let State::Live(object) = slot.state else {
                return Err(StoreError::Retiring);
            };
            slot.state = State::Retiring(object);
            Ok(t.release(index))
        })?;
        if let Some((id, object)) = destroyed {
            (self.destroy)(id, object);
        }
        Ok(())
    }

    /// Objects in the store, live or retiring.
    pub fn len(&self) -> usize {
        L::with(&self.table, |t| t.live)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// References outstanding on `id`, the store's own included. For accounting.
    pub fn references(&self, id: ObjectId) -> Option<u32> {
        L::with(&self.table, |t| t.find(id).and_then(|i| t.slots.get(i)).map(|s| s.refs))
    }

    /// Take a reference to the live object in slot `index`.
    fn acquire(t: &mut Table<'o, T, N>, index: usize) -> Result<Acquired<'o, T>, StoreError> {
        let slot = t.slots.get_mut(index).ok_or(StoreError::NotFound)?;
        let object = match slot.state {
            State::Live(object) => object,
            State::Retiring(_) => return Err(StoreError::Retiring),
            State::Free | State::Worn => return Err(StoreError::NotFound),
        };
        slot.refs = slot.refs.checked_add(1).ok_or(StoreError::TooManyRefs)?;
        Ok(Acquired {
            index,
            id: slot.id,
            kind: slot.kind,
            object,
        })
    }

    fn wrap(&self, a: Acquired<'o, T>) -> ObjRef<'_, 'o, T, L, N> {
        ObjRef {
            store: self,
            index: a.index,
            id: a.id,
            kind: a.kind,
            object: a.object,
        }
    }

    fn release(&self, index: usize) {
        if let Some((id, object)) = L::with(&self.table, |t| t.release(index)) {
            (self.destroy)(id, object);
        }
    }

    #[cfg(test)]
    fn set_generation(&self, id: ObjectId, generation: u32) {
        L::with(&self.table, |t| {
            if let Some(slot) = t.find(id).and_then(|i| t.slots.get_mut(i)) {
                slot.generation = generation;
            }
        });
    }
}

/// A reference counted in, not yet wrapped in its [`ObjRef`].
struct Acquired<'o, T> {
    index: usize,
    id: ObjectId,
    kind: ObjectType,
    object: &'o T,
}

/// A counted reference to an object in a store. The object stays alive, and keeps its
/// identity, until this drops.
pub struct ObjRef<'s, 'o, T: Sync, L: LockFamily, const N: usize> {
    store: &'s ObjectStore<'o, T, L, N>,
    index: usize,
    id: ObjectId,
    kind: ObjectType,
    object: &'o T,
}

impl<T: Sync, L: LockFamily, const N: usize> ObjRef<'_, '_, T, L, N> {
    pub fn id(&self) -> ObjectId {
        self.id
    }

    pub fn kind(&self) -> ObjectType {
        self.kind
    }

    /// Another reference to the same object. Fails only at the count's maximum.
    ///
    /// Works on a retiring object too: whoever holds a reference may share it, even though
    /// nothing new may find the object.
    pub fn try_clone(&self) -> Result<Self, StoreError> {
        L::with(&self.store.table, |t| {
            let slot = t.slots.get_mut(self.index).ok_or(StoreError::NotFound)?;
            slot.refs = slot.refs.checked_add(1).ok_or(StoreError::TooManyRefs)?;
            Ok(())
        })?;
        Ok(ObjRef {
            store: self.store,
            index: self.index,
            id: self.id,
            kind: self.kind,
            object: self.object,
        })
    }
}

impl<T: Sync, L: LockFamily, const N: usize> Deref for ObjRef<'_, '_, T, L, N> {
    type Target = T;

    fn deref(&self) -> &T {
        self.object
    }
}

impl<T: Sync, L: LockFamily, const N: usize> Drop for ObjRef<'_, '_, T, L, N> {
    fn drop(&mut self) {
        self.store.release(self.index);
    }
}

impl<T: Sync, L: LockFamily, const N: usize> fmt::Debug for ObjRef<'_, '_, T, L, N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ObjRef")
            .field("id", &self.id)
            .field("kind", &self.kind)
            .finish()
    }
}

#[cfg(test)]
mod tests;

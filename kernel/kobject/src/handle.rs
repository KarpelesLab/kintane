//! Handle tables: the per-process mapping from an integer a program holds to an
//! object and the rights it has over it.
//!
//! The bug this module exists to prevent is **use-after-close through slot reuse**.
//! A table that hands out bare indices will, sooner or later, close handle 7, open a
//! different object into slot 7, and then honour a stale copy of the old handle 7 —
//! silently granting one program authority over another's object. It is the
//! capability equivalent of a use-after-free and it fails open.
//!
//! So a handle is not an index. It is an index *plus a generation*, and the
//! generation of a slot changes every time the slot is reused. A stale handle names
//! a generation the slot no longer has and is rejected.
//!
//! Generations are finite, so a slot could in principle wrap around to a generation
//! some ancient handle still names. Rather than make that vanishingly unlikely and
//! hope, a slot whose generation would wrap is **retired** and never reused. The
//! cost is one table entry after 2^20 open/close cycles; the benefit is that the ABA
//! case does not exist rather than being improbable.

use core::fmt;

use crate::rights::Rights;
use crate::{ObjectId, ObjectType};

/// Bits of the handle value used for the slot index.
const INDEX_BITS: u32 = 12;
const INDEX_MASK: u32 = (1 << INDEX_BITS) - 1;
/// The rest is the generation.
const MAX_GENERATION: u32 = (1 << (32 - INDEX_BITS)) - 1;

/// The largest table this encoding can address.
pub const MAX_SLOTS: usize = 1 << INDEX_BITS;

/// What a program holds. Opaque: the split into index and generation is ours.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Handle(u32);

impl Handle {
    /// The value crossing the ABI boundary.
    pub const fn raw(self) -> u32 {
        self.0
    }

    /// Reconstruct from a value a program passed back. Always validated against the
    /// table before it means anything.
    pub const fn from_raw(v: u32) -> Handle {
        Handle(v)
    }

    const fn new(index: usize, generation: u32) -> Handle {
        Handle(((generation & !INDEX_MASK) | (index as u32 & INDEX_MASK)) as u32)
    }

    const fn index(self) -> usize {
        (self.0 & INDEX_MASK) as usize
    }

    const fn generation(self) -> u32 {
        self.0 & !INDEX_MASK
    }
}

impl fmt::Debug for Handle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Handle({:#010x})", self.0)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Error {
    /// No such handle, or one whose generation no longer matches: it was closed, and
    /// the slot may since have been reused for something else entirely.
    BadHandle,
    /// The handle names an object of a different type than the operation requires.
    WrongType {
        expected: ObjectType,
        found: ObjectType,
    },
    /// The handle is valid but does not carry the required right.
    AccessDenied { required: Rights, held: Rights },
    /// Every slot is occupied or retired.
    TableFull,
}

/// What a live handle names.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Entry {
    pub object: ObjectId,
    pub kind: ObjectType,
    pub rights: Rights,
}

#[derive(Clone, Copy)]
struct Slot {
    /// Always a multiple of the index stride; the low bits belong to the index.
    generation: u32,
    entry: Option<Entry>,
    /// A slot whose generation reached the maximum is never reused.
    retired: bool,
}

/// A process's handle table.
///
/// Fixed capacity: there is no heap at this layer, and a per-process bound on
/// handles is something a kernel wants anyway. `N` must not exceed [`MAX_SLOTS`].
pub struct HandleTable<const N: usize> {
    slots: [Slot; N],
    live: usize,
}

impl<const N: usize> Default for HandleTable<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> HandleTable<N> {
    pub const fn new() -> Self {
        assert!(N <= MAX_SLOTS, "handle table larger than the index encoding");
        HandleTable {
            slots: [Slot {
                // Generation starts at one stride, so a zeroed handle value is never
                // valid — an uninitialised variable must not name slot 0.
                generation: 1 << INDEX_BITS,
                entry: None,
                retired: false,
            }; N],
            live: 0,
        }
    }

    pub fn len(&self) -> usize {
        self.live
    }

    pub fn is_empty(&self) -> bool {
        self.live == 0
    }

    /// Install an object, returning the handle that names it.
    pub fn insert(
        &mut self,
        object: ObjectId,
        kind: ObjectType,
        rights: Rights,
    ) -> Result<Handle, Error> {
        let index = self
            .slots
            .iter()
            .position(|s| s.entry.is_none() && !s.retired)
            .ok_or(Error::TableFull)?;

        let slot = &mut self.slots[index];
        slot.entry = Some(Entry {
            object,
            kind,
            rights,
        });
        self.live += 1;
        Ok(Handle::new(index, slot.generation))
    }

    /// Look up a handle, checking that it is live and of the expected generation.
    pub fn get(&self, h: Handle) -> Result<Entry, Error> {
        let index = h.index();
        let slot = self.slots.get(index).ok_or(Error::BadHandle)?;
        if slot.generation != h.generation() {
            return Err(Error::BadHandle);
        }
        slot.entry.ok_or(Error::BadHandle)
    }

    /// Look up a handle and require both a type and a set of rights.
    ///
    /// Doing all three checks in one place is deliberate: a caller that fetches an
    /// entry and then checks rights itself is a caller that will one day forget.
    pub fn get_checked(
        &self,
        h: Handle,
        kind: ObjectType,
        required: Rights,
    ) -> Result<Entry, Error> {
        let entry = self.get(h)?;
        if entry.kind != kind {
            return Err(Error::WrongType {
                expected: kind,
                found: entry.kind,
            });
        }
        if !entry.rights.contains(required) {
            return Err(Error::AccessDenied {
                required,
                held: entry.rights,
            });
        }
        Ok(entry)
    }

    /// Close a handle. The slot's generation advances, so every outstanding copy of
    /// this handle becomes invalid immediately.
    pub fn close(&mut self, h: Handle) -> Result<Entry, Error> {
        let index = h.index();
        let slot = self.slots.get_mut(index).ok_or(Error::BadHandle)?;
        if slot.generation != h.generation() {
            return Err(Error::BadHandle);
        }
        let entry = slot.entry.take().ok_or(Error::BadHandle)?;
        self.live -= 1;

        // Advance the generation, or retire the slot rather than let it wrap.
        let next = (slot.generation >> INDEX_BITS).wrapping_add(1);
        if next >= MAX_GENERATION {
            slot.retired = true;
        } else {
            slot.generation = next << INDEX_BITS;
        }
        Ok(entry)
    }

    /// Duplicate a handle, narrowing its rights.
    ///
    /// Requires `DUPLICATE` on the original, and the result carries at most what the
    /// original held — `mask` can only take rights away.
    pub fn duplicate(&mut self, h: Handle, mask: Rights) -> Result<Handle, Error> {
        let entry = self.get(h)?;
        if !entry.rights.contains(Rights::DUPLICATE) {
            return Err(Error::AccessDenied {
                required: Rights::DUPLICATE,
                held: entry.rights,
            });
        }
        self.insert(entry.object, entry.kind, entry.rights.narrow(mask))
    }

    /// Remove a handle in order to send it elsewhere.
    ///
    /// Requires `TRANSFER`. The handle is closed here before the entry is handed
    /// back, so it cannot exist in two tables at once.
    pub fn transfer_out(&mut self, h: Handle) -> Result<Entry, Error> {
        let entry = self.get(h)?;
        if !entry.rights.contains(Rights::TRANSFER) {
            return Err(Error::AccessDenied {
                required: Rights::TRANSFER,
                held: entry.rights,
            });
        }
        self.close(h)
    }

    /// Every live entry, for accounting and for tearing a process down.
    pub fn entries(&self) -> impl Iterator<Item = Entry> + '_ {
        self.slots.iter().filter_map(|s| s.entry)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table() -> HandleTable<8> {
        HandleTable::new()
    }

    fn obj(n: u64) -> ObjectId {
        ObjectId::from_raw(n)
    }

    #[test]
    fn a_handle_names_what_was_inserted() {
        let mut t = table();
        let h = t.insert(obj(1), ObjectType::Channel, Rights::READ).unwrap();
        let e = t.get(h).unwrap();
        assert_eq!(e.object, obj(1));
        assert_eq!(e.kind, ObjectType::Channel);
        assert_eq!(e.rights, Rights::READ);
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn a_closed_handle_is_rejected() {
        let mut t = table();
        let h = t.insert(obj(1), ObjectType::Channel, Rights::READ).unwrap();
        t.close(h).unwrap();
        assert_eq!(t.get(h), Err(Error::BadHandle));
        assert_eq!(t.close(h), Err(Error::BadHandle), "double close");
        assert!(t.is_empty());
    }

    #[test]
    fn a_stale_handle_cannot_reach_the_slots_new_occupant() {
        // The bug this module exists to prevent. Without generations, `stale` and
        // `fresh` would be the same integer and the first would reach the second's
        // object — one program given authority over another's.
        let mut t = table();
        let stale = t.insert(obj(1), ObjectType::Channel, Rights::ALL).unwrap();
        t.close(stale).unwrap();
        let fresh = t.insert(obj(2), ObjectType::Process, Rights::ALL).unwrap();

        assert_eq!(stale.raw() & INDEX_MASK, fresh.raw() & INDEX_MASK, "same slot");
        assert_ne!(stale, fresh, "but not the same handle");
        assert_eq!(t.get(stale), Err(Error::BadHandle));
        assert_eq!(t.get(fresh).unwrap().object, obj(2));
    }

    #[test]
    fn a_zero_handle_is_never_valid() {
        // An uninitialised variable must not name slot 0.
        let mut t = table();
        let _ = t.insert(obj(1), ObjectType::Channel, Rights::ALL).unwrap();
        assert_eq!(t.get(Handle::from_raw(0)), Err(Error::BadHandle));
    }

    #[test]
    fn an_out_of_range_handle_is_rejected_not_panicking() {
        let t = table();
        // Index beyond the table's capacity, which indexing would have panicked on.
        assert_eq!(t.get(Handle::from_raw(0xFFFF_FFFF)), Err(Error::BadHandle));
    }

    #[test]
    fn duplicate_requires_the_right_and_can_only_narrow() {
        let mut t = table();
        let rw = Rights::READ | Rights::WRITE | Rights::DUPLICATE;
        let h = t.insert(obj(1), ObjectType::Channel, rw).unwrap();

        // Asking for more than held yields only what was held.
        let d = t.duplicate(h, Rights::ALL).unwrap();
        assert_eq!(t.get(d).unwrap().rights, rw);

        // Asking for less yields less.
        let d2 = t.duplicate(h, Rights::READ).unwrap();
        assert_eq!(t.get(d2).unwrap().rights, Rights::READ);

        // A handle without DUPLICATE cannot be duplicated — including the one we
        // just made by narrowing it away.
        assert!(matches!(t.duplicate(d2, Rights::READ), Err(Error::AccessDenied { .. })));
    }

    #[test]
    fn narrowing_away_duplicate_is_permanent() {
        // A program handed a narrowed handle must not be able to recover the
        // authority that was taken from it.
        let mut t = table();
        let h = t.insert(obj(1), ObjectType::Channel, Rights::ALL).unwrap();
        let given = t.duplicate(h, Rights::READ | Rights::DUPLICATE).unwrap();
        let onward = t.duplicate(given, Rights::ALL).unwrap();
        let r = t.get(onward).unwrap().rights;
        assert!(!r.contains(Rights::WRITE), "{r:?} must not regain WRITE");
        assert!(!r.contains(Rights::DESTROY));
    }

    #[test]
    fn transfer_requires_the_right_and_removes_the_handle() {
        let mut t = table();
        let no_transfer = t.insert(obj(1), ObjectType::Channel, Rights::READ).unwrap();
        assert!(matches!(t.transfer_out(no_transfer), Err(Error::AccessDenied { .. })));

        let h = t
            .insert(obj(2), ObjectType::Channel, Rights::READ | Rights::TRANSFER)
            .unwrap();
        let e = t.transfer_out(h).unwrap();
        assert_eq!(e.object, obj(2));
        // Gone from this table: a transferred handle cannot be in two at once.
        assert_eq!(t.get(h), Err(Error::BadHandle));
    }

    #[test]
    fn type_and_rights_are_checked_together() {
        let mut t = table();
        let h = t.insert(obj(1), ObjectType::Channel, Rights::READ).unwrap();

        assert!(matches!(
            t.get_checked(h, ObjectType::Process, Rights::READ),
            Err(Error::WrongType { .. })
        ));
        assert!(matches!(
            t.get_checked(h, ObjectType::Channel, Rights::WRITE),
            Err(Error::AccessDenied { .. })
        ));
        assert!(t.get_checked(h, ObjectType::Channel, Rights::READ).is_ok());
    }

    #[test]
    fn a_full_table_reports_rather_than_overwrites() {
        let mut t = table();
        for i in 0..8 {
            t.insert(obj(i), ObjectType::Channel, Rights::READ).unwrap();
        }
        assert_eq!(t.insert(obj(99), ObjectType::Channel, Rights::READ), Err(Error::TableFull));
        assert_eq!(t.len(), 8);
    }

    #[test]
    fn a_slot_retires_rather_than_wrapping_its_generation() {
        // Generations are finite. Wrapping would let an ancient handle match a slot
        // again, so the slot is retired instead. One entry is lost; the ABA case
        // ceases to exist.
        let mut t: HandleTable<1> = HandleTable::new();
        let mut last = None;
        for _ in 0..MAX_GENERATION {
            match t.insert(obj(1), ObjectType::Channel, Rights::READ) {
                Ok(h) => {
                    last = Some(h);
                    t.close(h).unwrap();
                }
                Err(Error::TableFull) => break,
                Err(e) => panic!("unexpected {e:?}"),
            }
        }
        assert_eq!(
            t.insert(obj(1), ObjectType::Channel, Rights::READ),
            Err(Error::TableFull),
            "the slot must retire rather than wrap"
        );
        // And the last handle it ever issued stays invalid.
        if let Some(h) = last {
            assert_eq!(t.get(h), Err(Error::BadHandle));
        }
    }

    #[test]
    fn a_process_with_no_handles_can_reach_nothing() {
        // The property the capability model rests on, stated as a test.
        let t = table();
        assert!(t.is_empty());
        assert_eq!(t.entries().count(), 0);
        for raw in [0u32, 1, 42, 0x1000, u32::MAX] {
            assert_eq!(t.get(Handle::from_raw(raw)), Err(Error::BadHandle));
        }
    }
}

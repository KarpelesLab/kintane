//! How many mappings share each anonymous frame.
//!
//! Copy-on-write turns on one question: when a write faults on a read-only page, is
//! anybody else mapping its frame? If not, the page is made writable where it is. If
//! so, it is copied. Answering that needs a count per frame.
//!
//! Only frames with **more than one** mapping are recorded. A frame of an anonymous
//! region that is mapped and absent from the table has exactly one mapping, which is
//! the common case and costs no storage. So the table is sized by how much memory is
//! shared at once, not by how much exists, and the caller provides it. Sharing more than
//! fits is refused before anything changes ([`VmError::SharesFull`]).
//!
//! Lookup is a linear scan. That is the right first implementation for a table this
//! small and the wrong one for a fork-heavy userspace, which wants a per-frame array
//! alongside the frame allocator's bitmap. The interface does not change.

use core::marker::PhantomData;
use core::ptr::NonNull;

use hal::PhysAddr;

use super::VmError;

/// One recorded frame. `frame == 0` is an empty slot: physical zero is never an
/// anonymous page, because frame allocators reserve it.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct ShareSlot {
    frame: u64,
    /// Mappings beyond the first. At least 1 while the slot is in use.
    extra: u32,
}

impl ShareSlot {
    pub const EMPTY: ShareSlot = ShareSlot { frame: 0, extra: 0 };
}

/// Whether a mapping that was just dropped was the frame's last.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Remaining {
    /// Nothing else maps the frame, and its owner should free it.
    Last,
    /// Something still maps it.
    Shared,
}

/// Share counts over caller-provided slots.
///
/// Usually one `Vm`'s own ([`Shares::new`]). Two address spaces that map the same frames —
/// a process and the child `fork` made of it — must count them in one store, so that the
/// side that writes first sees the other still maps the page; each then holds a view of that
/// store ([`Shares::shared`]).
pub struct Shares<'s> {
    slots: NonNull<[ShareSlot]>,
    _store: PhantomData<&'s mut [ShareSlot]>,
}

// SAFETY: a `Shares` is the exclusive borrow `new` took, which is `Send` and `Sync` like the
// slice it came from, or a view `shared` made under a contract that serialises every use of
// the store, from whichever thread makes it.
unsafe impl Send for Shares<'_> {}
// SAFETY: as above.
unsafe impl Sync for Shares<'_> {}

impl<'s> Shares<'s> {
    /// Use `slots` as the table. Existing contents are discarded.
    pub fn new(slots: &'s mut [ShareSlot]) -> Self {
        slots.fill(ShareSlot::EMPTY);
        Shares {
            slots: NonNull::from(slots),
            _store: PhantomData,
        }
    }

    /// A view of `store`, which other views may share, keeping what it holds.
    ///
    /// # Safety
    /// `store` is valid for reads and writes for `'s`, and no two views of it are used at
    /// once. Each call on a view borrows the store only until it returns, so serialising the
    /// calls is enough; the kernel does it with the lock every `Vm` operation is made under.
    pub unsafe fn shared(store: NonNull<[ShareSlot]>) -> Self {
        Shares {
            slots: store,
            _store: PhantomData,
        }
    }

    fn slots(&self) -> &[ShareSlot] {
        // SAFETY: valid for `'s` by `new`'s borrow or `shared`'s contract, and no other view
        // is in use while this call runs.
        unsafe { self.slots.as_ref() }
    }

    fn slots_mut(&mut self) -> &mut [ShareSlot] {
        // SAFETY: as in `slots`.
        unsafe { self.slots.as_mut() }
    }

    /// Mappings of `frame`, assuming it is mapped at all.
    pub fn count(&self, frame: PhysAddr) -> u32 {
        self.slot(frame).map_or(1, |s| s.extra.saturating_add(1))
    }

    /// Slots not in use.
    pub fn free_slots(&self) -> usize {
        self.slots().iter().filter(|s| s.frame == 0).count()
    }

    /// Whether `frame` has a slot, meaning more than one mapping.
    pub fn is_shared(&self, frame: PhysAddr) -> bool {
        self.slot(frame).is_some()
    }

    /// The frames that are shared, with their mapping counts.
    pub fn iter(&self) -> impl Iterator<Item = (PhysAddr, u32)> + '_ {
        self.slots()
            .iter()
            .filter(|s| s.frame != 0)
            .map(|s| (PhysAddr::new(s.frame), s.extra.saturating_add(1)))
    }

    /// Record one more mapping of `frame`.
    pub fn share(&mut self, frame: PhysAddr) -> Result<(), VmError> {
        if frame.raw() == 0 {
            return Err(VmError::Mismatch);
        }
        if let Some(i) = self.index(frame) {
            let s = &mut self.slots_mut()[i];
            s.extra = s.extra.checked_add(1).ok_or(VmError::Overflow)?;
            return Ok(());
        }
        let slot = self
            .slots_mut()
            .iter_mut()
            .find(|s| s.frame == 0)
            .ok_or(VmError::SharesFull)?;
        *slot = ShareSlot {
            frame: frame.raw(),
            extra: 1,
        };
        Ok(())
    }

    /// Record that one mapping of `frame` is gone.
    pub fn unshare(&mut self, frame: PhysAddr) -> Remaining {
        let Some(i) = self.index(frame) else {
            return Remaining::Last;
        };
        let s = &mut self.slots_mut()[i];
        s.extra -= 1;
        if s.extra == 0 {
            *s = ShareSlot::EMPTY;
        }
        Remaining::Shared
    }

    fn index(&self, frame: PhysAddr) -> Option<usize> {
        if frame.raw() == 0 {
            return None;
        }
        self.slots().iter().position(|s| s.frame == frame.raw())
    }

    fn slot(&self, frame: PhysAddr) -> Option<ShareSlot> {
        self.index(frame).map(|i| self.slots()[i])
    }
}

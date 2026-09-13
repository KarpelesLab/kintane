//! Write-once storage for what boot discovers and the rest of the machine's life reads.
//!
//! A driver bound at boot has to live somewhere `'static` — the interrupt path holds a
//! `&'static dyn IrqChip` — and its addresses are not known until the tree is read, so
//! a plain `static` cannot hold it. `static mut` is forbidden by
//! `docs/coding-standards.md`, and a `OnceLock`-style cell needs compare-and-swap, which
//! `kbuild portability` insists the device model does without. What is left is the
//! pattern `arch/aarch64/src/irq.rs` already used for its controller slot, given one
//! name: written once, before any reader can exist, and read-only after.

#![allow(unsafe_code)]

use core::cell::UnsafeCell;

/// A value set once during single-threaded boot and read thereafter.
pub struct BootCell<T>(UnsafeCell<Option<T>>);

// SAFETY: every write happens through `set`, whose contract is that it runs during
// single-threaded boot, and which never writes a cell that is already full — so no
// reference handed out by `get` ever observes a write. `T: Sync` is required because
// those references may be used from any context once boot is over.
unsafe impl<T: Sync> Sync for BootCell<T> {}

impl<T> BootCell<T> {
    pub const fn new() -> Self {
        BootCell(UnsafeCell::new(None))
    }

    /// Store `value` if the cell is empty, returning a reference to what the cell holds.
    ///
    /// `Err` hands `value` back when the cell was already set; the stored value is left
    /// alone, so a reference an earlier [`Self::get`] returned stays valid.
    ///
    /// # Safety
    /// Must run during single-threaded boot — one CPU, interrupts masked — so that nothing
    /// can call [`Self::get`] concurrently. Nothing else is required: while the cell is
    /// empty no reference to its contents exists, and once it is full this never writes.
    pub unsafe fn set(&self, value: T) -> Result<&T, T> {
        // SAFETY: the caller guarantees no concurrent reader. Sequentially, a reference
        // into the cell can only exist if it is `Some`, and then the branch below does not
        // write; if it is `None` there is nothing to alias, so the unique borrow is sound.
        let slot = unsafe { &mut *self.0.get() };
        if slot.is_some() {
            return Err(value);
        }
        Ok(slot.insert(value))
    }

    /// The value, once set.
    pub fn get(&self) -> Option<&T> {
        // SAFETY: by `set`'s contract the only write happened before any reader, so a
        // shared reference cannot race it, and nothing writes again.
        unsafe { (*self.0.get()).as_ref() }
    }
}

impl<T> Default for BootCell<T> {
    fn default() -> Self {
        Self::new()
    }
}

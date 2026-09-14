//! Register access through a claimed window.
//!
//! The one module of the device model that holds `unsafe`, and the promise it rests
//! on is made once, where a claim becomes registers: that the window is mapped, as
//! device memory, at the address the driver will use. Every access after that is
//! checked against the window, so a driver whose offset arithmetic is wrong reads
//! all-ones and writes nothing — what an absent device does on most buses — instead of
//! writing into whatever device happens to be mapped next to it.

#![allow(unsafe_code)]

use core::ptr::{
    read_volatile, with_exposed_provenance, with_exposed_provenance_mut, write_volatile,
};

use crate::resource::{Mmio, MmioClaim};

/// A window of 32-bit device registers a driver may read and write.
#[derive(Debug)]
pub struct Registers {
    base: usize,
    len: usize,
}

impl Registers {
    /// Registers for a claimed window.
    ///
    /// `None` when the window does not fit this machine's address space — a region above
    /// 4 GiB on a 32-bit kernel, which the tree can describe and the CPU cannot reach.
    ///
    /// # Safety
    /// `[mmio.phys(), mmio.phys() + mmio.len())` must be mapped at the same virtual
    /// address, as device memory that neither caches nor reorders accesses, for as long
    /// as the returned value is used. On aarch64 that is both the boot identity map and
    /// the kernel's own space, which maps every claimed window; it is the caller who knows
    /// which of those is live.
    pub unsafe fn new(mmio: &Mmio) -> Option<Registers> {
        Some(Registers {
            base: usize::try_from(mmio.phys()).ok()?,
            len: usize::try_from(mmio.len()).ok()?,
        })
    }

    /// Registers for a window the ledger records, reached by someone other than the driver
    /// holding its handle: the platform programming an MSI-X table in a window the driver
    /// claimed.
    ///
    /// The same translation as [`Self::new`], kept beside it so that where a claimed window
    /// is mapped is decided in one place. `None` on the same terms.
    ///
    /// # Safety
    /// As [`Self::new`], for `[claim.phys, claim.phys + claim.len)`; and the caller must be
    /// the only code touching the registers it uses in that window, which the driver that
    /// claimed it has agreed to by leaving them to the platform.
    pub unsafe fn for_claim(claim: &MmioClaim) -> Option<Registers> {
        Some(Registers {
            base: usize::try_from(claim.phys).ok()?,
            len: usize::try_from(claim.len).ok()?,
        })
    }

    /// Registers over memory that is not a claimed window: a test's buffer.
    ///
    /// # Safety
    /// `[base, base + len)` must be valid for volatile reads and writes of `u32` at every
    /// multiple of four, for as long as the returned value is used.
    pub unsafe fn from_raw(base: usize, len: usize) -> Registers {
        Registers { base, len }
    }

    /// The first byte of the window, as the driver addresses it.
    pub fn base(&self) -> usize {
        self.base
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The address of the register at `offset`, if a whole aligned word fits there.
    fn at(&self, offset: usize) -> Option<usize> {
        let end = offset.checked_add(4)?;
        (offset % 4 == 0 && end <= self.len)
            .then(|| self.base.checked_add(offset))
            .flatten()
    }

    /// Read the register at `offset`. Out of the window, all-ones.
    pub fn read32(&self, offset: usize) -> u32 {
        let Some(addr) = self.at(offset) else {
            debug_assert!(
                false,
                "register read at {offset:#x} outside a {:#x}-byte window",
                self.len
            );
            return u32::MAX;
        };
        // SAFETY: `at` checked that a whole, aligned word lies inside the window, and the
        // constructor's contract is that the window is mapped for volatile `u32` access.
        // Volatile, because a device distinguishes reads the compiler would merge.
        unsafe { read_volatile(with_exposed_provenance::<u32>(addr)) }
    }

    /// Write the register at `offset`. Out of the window, nothing.
    pub fn write32(&self, offset: usize, value: u32) {
        let Some(addr) = self.at(offset) else {
            debug_assert!(
                false,
                "register write at {offset:#x} outside a {:#x}-byte window",
                self.len
            );
            return;
        };
        // SAFETY: as `read32`; the write is inside the claimed window.
        unsafe { write_volatile(with_exposed_provenance_mut::<u32>(addr), value) }
    }
}

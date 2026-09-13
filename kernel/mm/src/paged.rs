//! The page table walker, written once for every architecture.
//!
//! The architecture supplies geometry and entry encoding (see `hal::paging`); this
//! module supplies everything above: descending the tree, allocating intermediate
//! tables, choosing a page size, tearing a range down, and reclaiming tables that
//! have become empty. None of that differs between x86-64, PAE and AArch64 once the
//! entry format is abstracted, and three copies of a tree walk would be three places
//! for the same off-by-one to hide.
//!
//! # Reaching a table
//!
//! Every operation needs to read and write tables, which live in physical memory, so
//! every operation needs a [`DirectMap`]. It is held in the [`AddressSpace`] rather
//! than reached through a global: there is exactly one direct map in a kernel today,
//! but making that an ambient assumption is how a second one becomes impossible to
//! introduce later.
//!
//! # What this does not do yet
//!
//! Splitting a huge page into smaller ones. A walk that needs to descend through a
//! leaf returns [`MapError::WouldSplit`] rather than silently doing something
//! surprising. Splitting is straightforward to add and needs a TLB-shootdown story to
//! be correct on SMP, which is Phase 3.

// This module is the one place in `mm` that needs `unsafe`, and the crate's
// `deny(unsafe_code)` is overridden here rather than removed, as
// docs/coding-standards.md requires — with the justification:
//
// A page table is a data structure the *hardware* also reads and writes. Reaching one
// means forming a pointer from a physical address through the direct map, and every
// access is volatile because the CPU's page-table walker is a second writer we cannot
// see. There is no safe abstraction underneath this: this module is the abstraction,
// and everything above it — `AddressSpace::map`, `unmap`, `translate`, `protect` — is
// safe. The unsafe surface is four functions (`entry_ptr`, `read`, `write`,
// `activate`) and two calls to `flush_tlb`.
#![allow(unsafe_code)]

use crate::DirectMap;
use core::marker::PhantomData;
use hal::paging::{level_index, level_size, HasPageTables, MapError, PageFlags, PageTableEntry};
use hal::PhysAddr;

/// Where intermediate page tables come from.
///
/// A trait rather than a concrete allocator because the bootstrap, the running
/// kernel, and the tests want different sources — and because an address space that
/// held a borrow of the frame allocator could not be built while the frame allocator
/// was borrowed to build it.
pub trait FrameSource {
    /// A zeroed frame. Zeroed is part of the contract: an absent entry is all-zero on
    /// every architecture we support, so a zeroed frame is a valid empty table.
    fn alloc_zeroed(&mut self) -> Result<PhysAddr, MapError>;

    /// Return a frame. Failure is not reportable and not fatal; a leaked frame is
    /// better than a teardown that cannot complete.
    fn free(&mut self, frame: PhysAddr);
}

/// The largest number of levels any supported architecture uses. Used only to size a
/// stack array during teardown, so being generous costs nothing.
const MAX_LEVELS: usize = 8;

/// A set of page tables.
pub struct AddressSpace<A: HasPageTables> {
    root: PhysAddr,
    direct: DirectMap,
    _arch: PhantomData<fn() -> A>,
}

impl<A: HasPageTables> AddressSpace<A> {
    /// Build an empty address space, allocating its root table.
    pub fn new(direct: DirectMap, frames: &mut impl FrameSource) -> Result<Self, MapError> {
        let root = frames.alloc_zeroed()?;
        Ok(AddressSpace {
            root,
            direct,
            _arch: PhantomData,
        })
    }

    /// Adopt tables that already exist.
    ///
    /// # Safety
    /// `root` must name a correctly formed table for `A`, reachable through
    /// `direct`, and must not be concurrently modified.
    pub unsafe fn from_root(root: PhysAddr, direct: DirectMap) -> Self {
        AddressSpace {
            root,
            direct,
            _arch: PhantomData,
        }
    }

    pub fn root(&self) -> PhysAddr {
        self.root
    }

    /// Make these tables the active ones.
    ///
    /// # Safety
    /// They must map the currently executing code, the stack in use, and any device
    /// the kernel is about to touch. Installing tables that do not is immediate and
    /// unrecoverable.
    pub unsafe fn activate(&self) {
        // SAFETY: delegated to the caller's obligation, restated above.
        unsafe {
            A::set_root(self.root);
            A::flush_tlb(None);
        }
    }

    // ---- entry access -------------------------------------------------------

    fn entry_ptr(&self, table: PhysAddr, index: usize) -> Result<*mut A::Entry, MapError> {
        let size = core::mem::size_of::<A::Entry>();
        let byte = index
            .checked_mul(size)
            .ok_or(MapError::BadPhysAddr)?;
        let phys = table
            .checked_add(byte as u64)
            .map_err(|_| MapError::BadPhysAddr)?;
        let virt = self
            .direct
            .to_virt(phys)
            .map_err(|_| MapError::BadPhysAddr)?;
        // SAFETY: `to_virt` succeeded, so `phys` lies inside the direct map's window
        // and the corresponding virtual address is mapped. Alignment holds because a
        // table is frame-aligned and entries are a power-of-two size.
        Ok(unsafe { virt.as_ptr::<A::Entry>() })
    }

    fn read(&self, table: PhysAddr, index: usize) -> Result<A::Entry, MapError> {
        let p = self.entry_ptr(table, index)?;
        // SAFETY: `entry_ptr` validated the address is inside the direct map. Reads
        // are volatile because another CPU's page-table walker may write here.
        Ok(unsafe { core::ptr::read_volatile(p) })
    }

    fn write(&mut self, table: PhysAddr, index: usize, e: A::Entry) -> Result<(), MapError> {
        let p = self.entry_ptr(table, index)?;
        // SAFETY: as for `read`. Volatile so the write is not elided or reordered by
        // the compiler relative to the TLB maintenance that follows it.
        unsafe { core::ptr::write_volatile(p, e) };
        Ok(())
    }

    fn is_table_empty(&self, table: PhysAddr, level: u8) -> Result<bool, MapError> {
        let n = 1usize << A::index_bits(level);
        for i in 0..n {
            if self.read(table, i)?.is_present() {
                return Ok(false);
            }
        }
        Ok(true)
    }

    // ---- mapping ------------------------------------------------------------

    /// The largest level whose page size divides both addresses and fits in `left`.
    ///
    /// Using huge pages where they fit is not only faster; it is what keeps the
    /// number of intermediate tables bounded when mapping a gigabyte of direct map.
    fn best_level(&self, virt: usize, phys: PhysAddr, left: usize) -> u8 {
        let mut level = 0u8;
        let mut l = 1u8;
        while l < A::LEVELS {
            if !A::leaf_allowed(l) {
                break;
            }
            let size = level_size::<A>(l);
            if size > left || virt % size != 0 || phys.raw() % (size as u64) != 0 {
                break;
            }
            level = l;
            l += 1;
        }
        level
    }

    /// Map `len` bytes at `virt` to `phys`.
    ///
    /// Both addresses and the length must be page-aligned. Overlapping an existing
    /// mapping is [`MapError::AlreadyMapped`] rather than a silent replacement: an
    /// accidental overlap is a bug, and the caller that means it can unmap first.
    pub fn map(
        &mut self,
        virt: usize,
        phys: PhysAddr,
        len: usize,
        flags: PageFlags,
        frames: &mut impl FrameSource,
    ) -> Result<(), MapError> {
        let page = A::PAGE_SIZE;
        if virt % page != 0 || len % page != 0 || phys.raw() % (page as u64) != 0 {
            return Err(MapError::Misaligned);
        }
        if len == 0 {
            return Ok(());
        }

        let mut off = 0usize;
        while off < len {
            let v = virt.checked_add(off).ok_or(MapError::NotCanonical)?;
            if !A::is_canonical(v) {
                return Err(MapError::NotCanonical);
            }
            let p = phys
                .checked_add(off as u64)
                .map_err(|_| MapError::BadPhysAddr)?;
            let level = self.best_level(v, p, len - off);
            self.map_one(v, p, level, flags, frames)?;
            off += level_size::<A>(level);
        }
        Ok(())
    }

    fn map_one(
        &mut self,
        virt: usize,
        phys: PhysAddr,
        level: u8,
        flags: PageFlags,
        frames: &mut impl FrameSource,
    ) -> Result<(), MapError> {
        let mut table = self.root;
        let mut l = A::LEVELS - 1;
        while l > level {
            let idx = level_index::<A>(virt, l);
            let e = self.read(table, idx)?;
            table = if !e.is_present() {
                let new = frames.alloc_zeroed()?;
                self.write(table, idx, A::Entry::table(new, l))?;
                new
            } else if e.is_leaf(l) {
                // A huge page already covers this address. Replacing it would unmap
                // more than the caller asked about.
                return Err(MapError::WouldSplit);
            } else {
                e.address()
            };
            l -= 1;
        }

        let idx = level_index::<A>(virt, level);
        if self.read(table, idx)?.is_present() {
            return Err(MapError::AlreadyMapped);
        }
        // `PageTableEntry::leaf` has no error channel, so an address too wide for the
        // architecture's entry encoding would be silently truncated into a mapping
        // pointing somewhere else entirely. Checked once here rather than in each
        // port, where three implementations would be three chances to mask instead of
        // report.
        if phys.truncate(A::PHYS_ADDR_BITS).1 {
            return Err(MapError::BadPhysAddr);
        }
        self.write(table, idx, A::Entry::leaf(phys, flags, level))?;
        Ok(())
    }

    /// The physical address and permissions `virt` resolves to, if anything.
    ///
    /// Returns the address of the byte, not of the page: a translation that lost the
    /// offset would be correct for every test that used page-aligned addresses and
    /// wrong in production.
    pub fn translate(&self, virt: usize) -> Option<(PhysAddr, PageFlags)> {
        if !A::is_canonical(virt) {
            return None;
        }
        let mut table = self.root;
        let mut l = A::LEVELS - 1;
        loop {
            let idx = level_index::<A>(virt, l);
            let e = self.read(table, idx).ok()?;
            if !e.is_present() {
                return None;
            }
            if e.is_leaf(l) {
                let size = level_size::<A>(l) as u64;
                let offset = (virt as u64) & (size - 1);
                return Some((e.address().checked_add(offset).ok()?, e.flags(l)));
            }
            if l == 0 {
                // Present, at the leaf level, but not marked a leaf: a malformed
                // table rather than an absent mapping.
                return None;
            }
            table = e.address();
            l -= 1;
        }
    }

    /// Remove `len` bytes of mapping at `virt`, reclaiming tables left empty.
    pub fn unmap(
        &mut self,
        virt: usize,
        len: usize,
        frames: &mut impl FrameSource,
    ) -> Result<(), MapError> {
        let page = A::PAGE_SIZE;
        if virt % page != 0 || len % page != 0 {
            return Err(MapError::Misaligned);
        }

        let mut off = 0usize;
        while off < len {
            let v = virt.checked_add(off).ok_or(MapError::NotCanonical)?;
            let covered = self.unmap_one(v, len - off, frames)?;
            off += covered;
        }
        Ok(())
    }

    /// Unmaps whatever covers `virt`, returning how many bytes that was.
    fn unmap_one(
        &mut self,
        virt: usize,
        left: usize,
        frames: &mut impl FrameSource,
    ) -> Result<usize, MapError> {
        // Record the tables on the way down so empties can be reclaimed on the way
        // back up. A fixed array: the depth is the architecture's level count.
        let mut chain = [(PhysAddr::ZERO, 0usize); MAX_LEVELS];
        let mut depth = 0usize;

        let mut table = self.root;
        let mut l = A::LEVELS - 1;
        let level = loop {
            let idx = level_index::<A>(virt, l);
            let e = self.read(table, idx)?;
            if !e.is_present() {
                return Err(MapError::NotMapped);
            }
            if e.is_leaf(l) {
                break l;
            }
            if l == 0 {
                return Err(MapError::NotMapped);
            }
            chain[depth] = (table, idx);
            depth += 1;
            table = e.address();
            l -= 1;
        };

        let size = level_size::<A>(level);
        if size > left {
            // The caller asked to unmap part of a huge page.
            return Err(MapError::WouldSplit);
        }

        let idx = level_index::<A>(virt, level);
        self.write(table, idx, A::Entry::empty())?;
        // SAFETY: the entry is gone from the table; any cached translation for it is
        // now stale and must not be used.
        unsafe { A::flush_tlb(Some(virt)) };

        // Walk back up, freeing tables that have become empty. A table that still
        // holds anything stops the unwind — everything above it is still in use.
        let mut child = table;
        let mut child_level = level;
        while depth > 0 {
            if !self.is_table_empty(child, child_level)? {
                break;
            }
            depth -= 1;
            let (parent, parent_idx) = chain[depth];
            self.write(parent, parent_idx, A::Entry::empty())?;
            frames.free(child);
            child = parent;
            child_level += 1;
        }

        Ok(size)
    }

    /// Change the permissions on an existing mapping, leaving the frames alone.
    pub fn protect(
        &mut self,
        virt: usize,
        len: usize,
        flags: PageFlags,
    ) -> Result<(), MapError> {
        let page = A::PAGE_SIZE;
        if virt % page != 0 || len % page != 0 {
            return Err(MapError::Misaligned);
        }

        let mut off = 0usize;
        while off < len {
            let v = virt.checked_add(off).ok_or(MapError::NotCanonical)?;
            let (table, idx, level) = self.find_leaf(v)?;
            let size = level_size::<A>(level);
            if size > len - off {
                return Err(MapError::WouldSplit);
            }
            let e = self.read(table, idx)?;
            self.write(table, idx, A::Entry::leaf(e.address(), flags, level))?;
            // SAFETY: the permissions changed; a cached translation carries the old
            // ones and must be discarded.
            unsafe { A::flush_tlb(Some(v)) };
            off += size;
        }
        Ok(())
    }

    fn find_leaf(&self, virt: usize) -> Result<(PhysAddr, usize, u8), MapError> {
        let mut table = self.root;
        let mut l = A::LEVELS - 1;
        loop {
            let idx = level_index::<A>(virt, l);
            let e = self.read(table, idx)?;
            if !e.is_present() {
                return Err(MapError::NotMapped);
            }
            if e.is_leaf(l) {
                return Ok((table, idx, l));
            }
            if l == 0 {
                return Err(MapError::NotMapped);
            }
            table = e.address();
            l -= 1;
        }
    }
}

#[cfg(test)]
mod tests;

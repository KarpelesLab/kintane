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
//! # Huge pages
//!
//! `map`, `unmap` and `protect` never split a huge page implicitly. A walk that would
//! have to descend through one returns [`MapError::WouldSplit`] instead of doing
//! something surprising. Splitting is an explicit operation (`split_leaf`), used by
//! [`crate::vm`] where a copy-on-write share or a partial protect needs it. It
//! invalidates one address, which is correct on one CPU; on SMP it needs a shootdown,
//! which is Phase 3.

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

use core::marker::PhantomData;

use hal::PhysAddr;
use hal::paging::{
    HasPageTables, MapError, PageFlags, PageTableEntry, level_entries, level_index, level_size,
};

use crate::DirectMap;

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

    /// A frame whose contents are unspecified.
    ///
    /// For a caller about to overwrite the whole frame anyway: a copy-on-write copy, or
    /// a demand page that [`crate::vm`] zeroes itself. Defaults to [`Self::alloc_zeroed`],
    /// so a source with no cheaper answer need not provide one.
    fn alloc(&mut self) -> Result<PhysAddr, MapError> {
        self.alloc_zeroed()
    }

    /// `frames` physically contiguous frames, the first on a multiple of `align` bytes,
    /// contents unspecified. Each frame is later returned on its own with [`Self::free`].
    ///
    /// What a huge page needs: a 2 MiB leaf names one physical address, so the frames
    /// behind it must be adjacent and the first must sit on a 2 MiB boundary. The
    /// default refuses, and a caller that wanted a huge page maps small ones instead.
    fn alloc_block(&mut self, frames: usize, align: usize) -> Result<PhysAddr, MapError> {
        let _ = (frames, align);
        Err(MapError::OutOfFrames)
    }
}

/// What a walk to an address found.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Probe<E> {
    /// A leaf maps the address.
    Leaf {
        /// The table holding the leaf.
        table: PhysAddr,
        /// The leaf's index in `table`.
        index: usize,
        /// The level the leaf is at; it maps `level_size(level)` bytes.
        level: u8,
        /// The entry as read.
        entry: E,
    },
    /// Nothing maps the address. The absent entry was found at `level`, so nothing is
    /// mapped anywhere in the `level_size(level)` bytes around it either.
    Hole {
        /// Level of the absent entry.
        level: u8,
    },
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

    /// Copy every top-level entry from `other`'s root into this one's, so the two address
    /// spaces share every table `other` reaches from its root. For a process root that
    /// must share the kernel's mappings: the kernel lives under the low top-level entries
    /// and a process adds its own under a higher one, which `map` fills in on top of the
    /// zero this leaves there.
    ///
    /// # Safety
    /// `other` must be a live root reachable through this space's direct map, and the
    /// tables it names must outlive every use of this space.
    pub unsafe fn mirror_top_level(&mut self, other: PhysAddr) -> Result<(), MapError> {
        let n = level_entries::<A>(A::LEVELS - 1);
        for i in 0..n {
            let e = self.read(other, i)?;
            self.write(self.root, i, e)?;
        }
        Ok(())
    }

    /// The direct map these tables are reached through.
    pub fn direct(&self) -> DirectMap {
        self.direct
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
        let byte = index.checked_mul(size).ok_or(MapError::BadPhysAddr)?;
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
            // Masks rather than `%`: every size here is a power of two, and a `u64 %`
            // on a 32-bit target is a call to `__umoddi3` rather than an instruction.
            // It linked on x86_64 and failed on i686, where `size` varies per level and
            // so cannot be folded into a shift by the compiler.
            let mask = size - 1;
            if size > left || virt & mask != 0 || phys.raw() & (mask as u64) != 0 {
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
        let mask = page - 1;
        if virt & mask != 0 || len & mask != 0 || phys.raw() & (mask as u64) != 0 {
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
            self.map_at_level(v, p, level, flags, frames)?;
            off += level_size::<A>(level);
        }
        Ok(())
    }

    /// Map one leaf of `level_size(level)` bytes at `virt`, which must be aligned to it.
    pub(crate) fn map_at_level(
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
                if A::root_load_caches(l) {
                    // SAFETY: the new entry is written. The CPU holds a copy of this
                    // level taken when the root was loaded, and only a full flush
                    // reloads it; without this the mapping below exists in the table
                    // and not in the machine.
                    unsafe { A::flush_tlb(None) };
                }
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
            if A::root_load_caches(child_level + 1) {
                // SAFETY: the entry is cleared. The CPU's copy of it, taken at root load,
                // still names the table about to be freed, and the invalidation of the
                // leaf above did not touch that copy.
                unsafe { A::flush_tlb(None) };
            }
            frames.free(child);
            child = parent;
            child_level += 1;
        }

        Ok(size)
    }

    /// Change the permissions on an existing mapping, leaving the frames alone.
    pub fn protect(&mut self, virt: usize, len: usize, flags: PageFlags) -> Result<(), MapError> {
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

    /// Walk to `virt` and say what maps it, or at which level nothing does.
    pub(crate) fn probe(&self, virt: usize) -> Result<Probe<A::Entry>, MapError> {
        if !A::is_canonical(virt) {
            return Err(MapError::NotCanonical);
        }
        let mut table = self.root;
        let mut l = A::LEVELS - 1;
        loop {
            let index = level_index::<A>(virt, l);
            let entry = self.read(table, index)?;
            if !entry.is_present() {
                return Ok(Probe::Hole { level: l });
            }
            if entry.is_leaf(l) {
                return Ok(Probe::Leaf {
                    table,
                    index,
                    level: l,
                    entry,
                });
            }
            if l == 0 {
                // Present at the leaf level but not a leaf: a malformed table.
                return Err(MapError::NotMapped);
            }
            table = entry.address();
            l -= 1;
        }
    }

    /// Free the tables on the path to `virt` that hold nothing, deepest first.
    ///
    /// For after a mapping that failed part-way: `map` allocates intermediate tables on
    /// the way down, and if the leaf itself then cannot be placed they are left empty. They
    /// are harmless, but they are frames nothing will ever return, and the next teardown
    /// only reclaims tables it empties itself. The root is never freed.
    pub(crate) fn prune(&mut self, virt: usize, frames: &mut impl FrameSource) {
        let mut chain = [(PhysAddr::ZERO, 0usize); MAX_LEVELS];
        let mut depth = 0usize;
        let mut table = self.root;
        let mut l = A::LEVELS - 1;
        while l > 0 {
            let idx = level_index::<A>(virt, l);
            let Ok(e) = self.read(table, idx) else {
                return;
            };
            if !e.is_present() || e.is_leaf(l) {
                break;
            }
            chain[depth] = (table, idx);
            depth += 1;
            table = e.address();
            l -= 1;
        }
        let mut freed = false;
        while depth > 0 {
            if self.is_table_empty(table, l) != Ok(true) {
                break;
            }
            depth -= 1;
            let (parent, idx) = chain[depth];
            if self.write(parent, idx, A::Entry::empty()).is_err() {
                break;
            }
            frames.free(table);
            freed = true;
            table = parent;
            l += 1;
        }
        if freed {
            // SAFETY: the entries are written. No leaf was below them, but a CPU may cache
            // intermediate entries (paging-structure caches on x86, the PDPT on PAE), and
            // one naming a freed frame must not survive that frame's reuse.
            unsafe { A::flush_tlb(None) };
        }
    }

    /// Replace the leaf at `(table, index)`, which maps `virt`, and invalidate it.
    ///
    /// The frame, the permissions or both may change. Every replacement is followed by
    /// an invalidation, including one that only adds permission. Leaving that one stale
    /// is harmless on x86, which refaults and finds the new entry, but which changes may
    /// skip the flush is an architecture's question and this layer does not answer it.
    pub(crate) fn replace_leaf(
        &mut self,
        (table, index): (PhysAddr, usize),
        virt: usize,
        phys: PhysAddr,
        flags: PageFlags,
        level: u8,
    ) -> Result<(), MapError> {
        if phys.truncate(A::PHYS_ADDR_BITS).1 {
            return Err(MapError::BadPhysAddr);
        }
        self.write(table, index, A::Entry::leaf(phys, flags, level))?;
        // SAFETY: the entry is written, so any cached translation of `virt` names the old
        // frame or the old permissions. A stale writable one is how a shared frame gets
        // written through a mapping that was made read-only to protect it.
        unsafe { A::flush_tlb(Some(virt)) };
        Ok(())
    }

    /// Turn the huge leaf covering `virt` into a table of leaves one level down, mapping
    /// the same frames with the same permissions.
    ///
    /// Nothing observable changes: every address translates to the same byte before and
    /// after, which is what makes this safe to do at any time. Does nothing if `virt` is
    /// already mapped at the smallest size, and is [`MapError::NotMapped`] if nothing maps
    /// it. On any error the tables are as they were.
    pub(crate) fn split_leaf(
        &mut self,
        virt: usize,
        frames: &mut impl FrameSource,
    ) -> Result<(), MapError> {
        let (table, index, level, entry) = match self.probe(virt)? {
            Probe::Hole { .. } => return Err(MapError::NotMapped),
            Probe::Leaf { level: 0, .. } => return Ok(()),
            Probe::Leaf {
                table,
                index,
                level,
                entry,
            } => (table, index, level, entry),
        };
        let sub = level - 1;
        if !A::leaf_allowed(sub) {
            return Err(MapError::WouldSplit);
        }
        let flags = entry.flags(level);
        let base = entry.address();
        let size = level_size::<A>(sub) as u64;
        let new = frames.alloc_zeroed()?;
        // Filled completely before it is linked in, so the hardware never walks a
        // half-built table.
        for i in 0..level_entries::<A>(sub) {
            let phys = (i as u64)
                .checked_mul(size)
                .and_then(|o| base.checked_add(o).ok());
            let written = match phys {
                Some(p) => self.write(new, i, A::Entry::leaf(p, flags, sub)),
                None => Err(MapError::BadPhysAddr),
            };
            if let Err(e) = written {
                frames.free(new);
                return Err(e);
            }
        }
        self.write(table, index, A::Entry::table(new, level))?;
        let block = virt & !(level_size::<A>(level) - 1);
        // SAFETY: the table is linked in. Invalidating any address inside a huge page
        // drops the huge translation on both x86 (`invlpg`) and AArch64
        // (`tlbi vaae1is`), so one flush covers the block.
        unsafe { A::flush_tlb(Some(block)) };
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

//! Virtual memory above the page tables: regions, demand paging, copy-on-write.
//!
//! [`crate::paged`] knows how to change a table. This module decides *what* a table
//! should say, and it decides it lazily. Reserving a region maps nothing. A page appears
//! the first time something touches it, when the architecture reports a page fault and
//! [`Vm::fault`] resolves it. Sharing a region copy-on-write copies nothing either: both
//! sides map the same frames read-only, and a write fault copies the one page written.
//!
//! # What a VM object is here
//!
//! A region's [`Backing`] says where its memory comes from: zeroed anonymous memory, or
//! a fixed physical range. It does *not* keep a list of the pages it has materialised.
//! The page tables are that list. For anonymous memory in one address space, or shared
//! copy-on-write between a few, that is complete: a frame is owned by the leaves that
//! map it, and [`Shares`] counts them when there is more than one.
//!
//! The model stops being enough when a page must exist without a mapping, which means
//! swapping it out, backing it with a file, or keeping it alive while no address space
//! maps it. Those need an object with its own page list, with regions mapping windows of
//! it. They arrive with the first thing that needs them. The fault resolver's shape
//! (find the region, ask the backing for a frame, map it) does not change.
//!
//! # Invariants
//!
//! [`Vm::audit`] checks all of these, and every operation here keeps them even when it
//! fails part-way:
//!
//! 1. Every leaf lies inside one region and grants no more than the region permits.
//! 2. A physical region's leaves map exactly the frames at the region's offsets.
//! 3. **No writable leaf maps a shared frame.** This is the one that matters: break it and a write
//!    through one mapping appears in another that was promised a private copy.
//! 4. A shared frame's count equals the number of leaves mapping it.
//! 5. A huge leaf never maps a shared frame. Sharing splits huge leaves first, so counts are always
//!    per base page.
//!
//! # Failure
//!
//! Out of memory is an error ([`VmError::OutOfMemory`]), never a panic. A fault that
//! cannot get a frame leaves the tables as they were, and the caller decides whether
//! that is fatal. A copy-on-write share that runs out part-way undoes what it did.
//!
//! # The TLB
//!
//! Every leaf that is replaced is invalidated, whatever changed. The flush that matters
//! most is the one [`Vm::cow_share`] issues when it makes a writable page read-only. A
//! CPU that still caches the writable translation keeps writing straight into the frame
//! both sides now share, and nothing faults to say so. The other direction, read-only to
//! writable, is forgiving on x86: a stale entry only refaults, and the resolver finds the
//! page already writable and reports [`Resolved::Spurious`]. A missing flush there hides
//! as a doubled fault count rather than as corruption.

// Anonymous pages are zeroed and copied through the direct map, which means forming a
// pointer from a physical address. That is the whole unsafe surface: `zero` and `copy`
// below, each checking the direct map covers every byte first.
#![allow(unsafe_code)]

pub mod region;
pub mod shares;

use hal::PhysAddr;
use hal::fault::{Access, PageFault};
use hal::paging::{HasPageTables, MapError, PageFlags, PageTableEntry, level_size};
pub use region::{Backing, Region, Regions};
pub use shares::{Remaining, ShareSlot, Shares};

use crate::DirectMap;
use crate::paged::{AddressSpace, FrameSource, Probe};

/// Why a virtual memory operation did not succeed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum VmError {
    /// No region contains the address.
    NoRegion,
    /// A region contains the address and does not permit this access.
    Protection,
    /// A frame was needed and none was available. Nothing was changed.
    OutOfMemory,
    /// Sharing needs more share-count slots than are free. Nothing was changed.
    SharesFull,
    /// The region map is full.
    RegionsFull,
    /// A new region overlaps an existing one.
    Overlap,
    /// An address, length or physical base is not page-aligned.
    Misaligned,
    /// A zero-length region or range.
    Empty,
    /// Address arithmetic overflowed, or an address is not canonical.
    Overflow,
    /// The destination of a share already has pages mapped.
    NotEmpty,
    /// The tables and the regions disagree, or the request does not fit the regions:
    /// sharing between regions of different sizes, protecting across a region boundary.
    Mismatch,
    /// The walker failed for a reason other than running out of frames.
    Map(MapError),
}

impl From<MapError> for VmError {
    fn from(e: MapError) -> Self {
        match e {
            MapError::OutOfFrames => VmError::OutOfMemory,
            MapError::NotCanonical => VmError::Overflow,
            MapError::Misaligned => VmError::Misaligned,
            other => VmError::Map(other),
        }
    }
}

/// How a fault was resolved.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Resolved {
    /// A fresh zeroed page, or a zeroed huge block, was mapped.
    Zeroed {
        /// Whether a huge leaf was used.
        huge: bool,
    },
    /// A page of a physical range was mapped.
    Physical {
        /// Whether a huge leaf was used.
        huge: bool,
    },
    /// A write to a shared page copied it into a private frame.
    Copied,
    /// A write to a read-only page that nothing else maps made it writable in place.
    Reused,
    /// The tables already permitted the access. A stale translation was flushed.
    Spurious,
}

/// What [`Vm::audit`] found, when it found nothing wrong.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Audit {
    /// Base-page leaves in anonymous regions.
    pub pages: usize,
    /// Huge leaves in anonymous regions.
    pub huge: usize,
    /// Distinct anonymous frames mapped: what the address space holds from the frame
    /// allocator, not counting page tables.
    pub frames_held: usize,
    /// Frames mapped more than once.
    pub shared: usize,
}

/// An invariant [`Vm::audit`] found broken, and where.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AuditError {
    /// A leaf extends past the region it starts in.
    CrossesRegion(usize),
    /// A leaf grants a permission its region does not.
    ExceedsRegion(usize),
    /// A physical region's leaf maps the wrong frame.
    WrongFrame(usize),
    /// A writable leaf maps a shared frame.
    WritableShared(usize),
    /// A huge leaf maps a shared frame.
    HugeShared(usize),
    /// A frame's recorded count differs from the leaves that map it.
    CountWrong(PhysAddr),
    /// The walk itself failed.
    Walk(MapError),
}

/// One leaf, as found by a walk.
#[derive(Clone, Copy)]
struct Leaf {
    /// First address the leaf maps.
    base: usize,
    /// Bytes it maps.
    size: usize,
    level: u8,
    frame: PhysAddr,
    flags: PageFlags,
    slot: (PhysAddr, usize),
}

impl Leaf {
    /// The first address after the leaf. Saturating: a leaf ending at the top of the
    /// address space ends every walk, since a walk's bound is at most `usize::MAX`.
    fn next(&self) -> usize {
        self.base.saturating_add(self.size)
    }
}

/// An address space with regions, faulting pages in on demand.
pub struct Vm<'s, A: HasPageTables, const N: usize> {
    space: AddressSpace<A>,
    regions: Regions<A, N>,
    shares: Shares<'s>,
}

impl<'s, A: HasPageTables, const N: usize> Vm<'s, A, N> {
    /// Manage `space`, which may already hold mappings outside any region: those are
    /// never touched.
    pub fn new(space: AddressSpace<A>, shares: Shares<'s>) -> Self {
        Vm {
            space,
            regions: Regions::new(),
            shares,
        }
    }

    pub fn space(&self) -> &AddressSpace<A> {
        &self.space
    }

    pub fn regions(&self) -> &Regions<A, N> {
        &self.regions
    }

    pub fn shares(&self) -> &Shares<'s> {
        &self.shares
    }

    /// Add a region. Nothing is mapped until it is touched, and nothing already mapped
    /// inside it may exist.
    pub fn reserve(&mut self, region: Region) -> Result<(), VmError> {
        if region.len == 0 {
            return Err(VmError::Empty);
        }
        let end = region.end().ok_or(VmError::Overflow)?;
        if !A::is_canonical(region.start) || !A::is_canonical(end - 1) {
            return Err(VmError::Overflow);
        }
        if region.start & (A::PAGE_SIZE - 1) != 0 || region.len & (A::PAGE_SIZE - 1) != 0 {
            return Err(VmError::Misaligned);
        }
        // Checked before inserting, so a refused region leaves the map unchanged. A
        // region over existing mappings would adopt leaves nobody allocated for it, and
        // releasing it would free them.
        if self.next_leaf(region.start, end)?.is_some() {
            return Err(VmError::NotEmpty);
        }
        self.regions.insert(region)
    }

    /// Resolve a page fault.
    ///
    /// On success the faulting access will succeed when retried. On error nothing was
    /// changed: [`VmError::NoRegion`] and [`VmError::Protection`] are faults the kernel
    /// did not promise to handle, and [`VmError::OutOfMemory`] is one it could not.
    pub fn fault(
        &mut self,
        fault: PageFault,
        frames: &mut impl FrameSource,
    ) -> Result<Resolved, VmError> {
        let (_, region) = self.regions.find(fault.addr).ok_or(VmError::NoRegion)?;
        let needed = match fault.access {
            Access::Read => PageFlags::READ,
            Access::Write => PageFlags::WRITE,
            Access::Execute => PageFlags::EXECUTE,
        };
        if !region.flags.contains(needed) {
            return Err(VmError::Protection);
        }
        let page = fault.addr & !(A::PAGE_SIZE - 1);
        match self.space.probe(page)? {
            Probe::Hole { level } => self.populate(page, level, region, frames),
            Probe::Leaf { level, entry, .. } => {
                let have = entry.flags(level);
                let permitted = match fault.access {
                    Access::Read => true,
                    Access::Write => have.contains(PageFlags::WRITE),
                    Access::Execute => {
                        have.contains(PageFlags::EXECUTE) || !A::can_forbid_execute()
                    }
                };
                if permitted {
                    // Whatever the CPU faulted on is not what the table says now. A full
                    // flush rather than one address, because on PAE the stale state can
                    // be a cached top-level entry that `invlpg` does not reload.
                    //
                    // SAFETY: no table was written; this only discards cached state.
                    unsafe { A::flush_tlb(None) };
                    return Ok(Resolved::Spurious);
                }
                if fault.access != Access::Write || region.backing != Backing::Anonymous {
                    return Err(VmError::Mismatch);
                }
                self.write_to_read_only(page, region, frames)
            }
        }
    }

    /// Map whatever belongs at `page`, which nothing maps. `hole` is the level at which
    /// the walk found nothing.
    fn populate(
        &mut self,
        page: usize,
        hole: u8,
        region: Region,
        frames: &mut impl FrameSource,
    ) -> Result<Resolved, VmError> {
        if let Some(r) = self.populate_huge(page, hole, region, frames)? {
            return Ok(r);
        }
        match region.backing {
            Backing::Physical { .. } => {
                let phys = region.phys_at(page).ok_or(VmError::Overflow)?;
                self.map_or_prune(page, phys, 0, region.flags, frames)?;
                Ok(Resolved::Physical { huge: false })
            }
            Backing::Anonymous => {
                let frame = frames.alloc()?;
                let mapped = zero(self.space.direct(), frame, A::PAGE_SIZE)
                    .and_then(|()| self.map_or_prune(page, frame, 0, region.flags, frames));
                if let Err(e) = mapped {
                    frames.free(frame);
                    return Err(e);
                }
                Ok(Resolved::Zeroed { huge: false })
            }
        }
    }

    /// Map one leaf, and on failure give back any tables the attempt left empty, so a
    /// failed fault leaves no trace in the frame accounting.
    fn map_or_prune(
        &mut self,
        virt: usize,
        phys: PhysAddr,
        level: u8,
        flags: PageFlags,
        frames: &mut impl FrameSource,
    ) -> Result<(), VmError> {
        self.space
            .map_at_level(virt, phys, level, flags, frames)
            .map_err(|e| {
                self.space.prune(virt, frames);
                VmError::from(e)
            })
    }

    /// Map a huge leaf around `page` if the region wants one, the whole block is inside
    /// it and unmapped, and memory for it can be found. `None` means use base pages.
    fn populate_huge(
        &mut self,
        page: usize,
        hole: u8,
        region: Region,
        frames: &mut impl FrameSource,
    ) -> Result<Option<Resolved>, VmError> {
        const LEVEL: u8 = 1;
        if !region.huge || hole < LEVEL || A::LEVELS <= LEVEL || !A::leaf_allowed(LEVEL) {
            return Ok(None);
        }
        let size = level_size::<A>(LEVEL);
        let block = page & !(size - 1);
        let inside = block >= region.start
            && block
                .checked_add(size)
                .zip(region.end())
                .is_some_and(|(e, re)| e <= re);
        if !inside {
            return Ok(None);
        }
        match region.backing {
            Backing::Physical { .. } => {
                let phys = region.phys_at(block).ok_or(VmError::Overflow)?;
                if phys.raw() & (size as u64 - 1) != 0 {
                    return Ok(None);
                }
                self.map_or_prune(block, phys, LEVEL, region.flags, frames)?;
                Ok(Some(Resolved::Physical { huge: true }))
            }
            Backing::Anonymous => {
                let count = size / A::PAGE_SIZE;
                // No contiguous block is not an error: base pages still work.
                let Ok(base) = frames.alloc_block(count, size) else {
                    return Ok(None);
                };
                let mapped = zero(self.space.direct(), base, size)
                    .and_then(|()| self.map_or_prune(block, base, LEVEL, region.flags, frames));
                if let Err(e) = mapped {
                    free_block::<A>(frames, base, count);
                    return Err(e);
                }
                Ok(Some(Resolved::Zeroed { huge: true }))
            }
        }
    }

    /// A write to a read-only anonymous page in a writable region: copy it if it is
    /// shared, make it writable in place if not.
    fn write_to_read_only(
        &mut self,
        page: usize,
        region: Region,
        frames: &mut impl FrameSource,
    ) -> Result<Resolved, VmError> {
        let leaf = self.leaf_at(page)?.ok_or(VmError::Mismatch)?;
        if leaf.level > 0 {
            // A huge leaf is never shared (invariant 5), so making it writable is safe and
            // copies nothing. Still checked, because trusting an invariant in the one
            // place that would silently break it is how the invariant stops holding.
            if self.any_shared(leaf.frame, leaf.size) {
                return Err(VmError::Mismatch);
            }
            self.space
                .replace_leaf(leaf.slot, leaf.base, leaf.frame, region.flags, leaf.level)?;
            return Ok(Resolved::Reused);
        }
        if !self.shares.is_shared(leaf.frame) {
            self.space
                .replace_leaf(leaf.slot, page, leaf.frame, region.flags, 0)?;
            return Ok(Resolved::Reused);
        }
        let copy = frames.alloc()?;
        let direct = self.space.direct();
        let replaced = copy_page(direct, leaf.frame, copy, A::PAGE_SIZE).and_then(|()| {
            self.space
                .replace_leaf(leaf.slot, page, copy, region.flags, 0)
                .map_err(VmError::from)
        });
        if let Err(e) = replaced {
            frames.free(copy);
            return Err(e);
        }
        // The old frame is still mapped by at least one other leaf, so this never frees.
        self.shares.unshare(leaf.frame);
        Ok(Resolved::Copied)
    }

    /// Share the pages of the anonymous region at `src` with the empty anonymous region
    /// at `dst`, copy-on-write. Both must be the same length.
    ///
    /// Afterwards both regions read the same frames, and both map them read-only. The
    /// first write on either side copies the page written and leaves the other alone.
    /// Huge leaves in `src` are split first, which is invisible. All or nothing: on any
    /// error the sharing done so far is undone, though huge leaves already split stay
    /// split.
    pub fn cow_share(
        &mut self,
        src: usize,
        dst: usize,
        frames: &mut impl FrameSource,
    ) -> Result<(), VmError> {
        let (_, s) = self.regions.exact(src).ok_or(VmError::NoRegion)?;
        let (_, d) = self.regions.exact(dst).ok_or(VmError::NoRegion)?;
        if s.backing != Backing::Anonymous || d.backing != Backing::Anonymous || s.len != d.len {
            return Err(VmError::Mismatch);
        }
        let s_end = s.end().ok_or(VmError::Overflow)?;
        let d_end = d.end().ok_or(VmError::Overflow)?;
        if self.next_leaf(d.start, d_end)?.is_some() {
            return Err(VmError::NotEmpty);
        }

        // Base pages only, so that counts are per page (invariant 5).
        let mut v = s.start;
        while let Some(leaf) = self.next_leaf(v, s_end)? {
            if leaf.level > 0 {
                self.space.split_leaf(leaf.base, frames)?;
                continue;
            }
            v = leaf.next();
        }

        // Refused before anything is shared, rather than discovered half-way.
        let mut needed = 0usize;
        let mut v = s.start;
        while let Some(leaf) = self.next_leaf(v, s_end)? {
            if !self.shares.is_shared(leaf.frame) {
                needed += 1;
            }
            v = leaf.next();
        }
        if needed > self.shares.free_slots() {
            return Err(VmError::SharesFull);
        }

        let ro = d.flags.without(PageFlags::WRITE);
        let mut v = s.start;
        while let Some(leaf) = self.next_leaf(v, s_end)? {
            let at = d.start + (leaf.base - s.start);
            if let Err(e) = self.map_or_prune(at, leaf.frame, 0, ro, frames) {
                // The page that failed was not mapped; the ones before it are undone.
                self.unshare_prefix(s, d, leaf.base, frames);
                return Err(e);
            }
            if let Err(e) = self.shares.share(leaf.frame) {
                // Unreachable after the count above, and handled anyway: an unrecorded
                // second mapping is exactly invariant 4 broken.
                let _ = self.space.unmap(at, A::PAGE_SIZE, frames);
                self.unshare_prefix(s, d, leaf.base, frames);
                return Err(e);
            }
            if leaf.flags.contains(PageFlags::WRITE) {
                let made_ro = self.space.replace_leaf(
                    leaf.slot,
                    leaf.base,
                    leaf.frame,
                    leaf.flags.without(PageFlags::WRITE),
                    0,
                );
                if let Err(e) = made_ro {
                    self.unshare_prefix(s, d, leaf.base + leaf.size, frames);
                    return Err(e.into());
                }
            }
            v = leaf.next();
        }
        Ok(())
    }

    /// Share every page of this address space with `child`, an empty `Vm`, copy-on-write:
    /// what `fork` does.
    ///
    /// Every region is reserved in `child` at the same address with the same permissions,
    /// every mapped page is mapped there to the same frame, read-only, and every writable
    /// page here is made read-only too. The first write on either side copies the page
    /// written, exactly as after [`Self::cow_share`].
    ///
    /// The two spaces must count shares in one store ([`Shares::shared`]): a frame mapped
    /// in both is one frame with two mappings, and the side that writes first must see that
    /// the other still maps it. Nothing here can check that, so a caller that gives them two
    /// stores gets a write that lands in both.
    ///
    /// Only anonymous regions are shared; a physical one is refused before anything changes
    /// ([`VmError::Mismatch`]). On any other error `child` holds what was shared so far, and
    /// releasing its regions puts every count back; the pages made read-only here become
    /// writable again on their next write, which finds them unshared.
    pub fn fork_into<const M: usize>(
        &mut self,
        child: &mut Vm<'_, A, M>,
        frames: &mut impl FrameSource,
    ) -> Result<(), VmError> {
        if child.regions.iter().next().is_some() {
            return Err(VmError::NotEmpty);
        }
        if self.regions.iter().any(|r| r.backing != Backing::Anonymous) {
            return Err(VmError::Mismatch);
        }
        let mut count = 0usize;
        for r in self.regions.iter() {
            let end = r.end().ok_or(VmError::Overflow)?;
            // Base pages only, so that counts are per page (invariant 5).
            let mut v = r.start;
            while let Some(leaf) = self.next_leaf(v, end)? {
                if leaf.level > 0 {
                    self.space.split_leaf(leaf.base, frames)?;
                    continue;
                }
                if !self.shares.is_shared(leaf.frame) {
                    count += 1;
                }
                v = leaf.next();
            }
        }
        // Refused before anything is shared, rather than discovered half-way.
        if count > self.shares.free_slots() {
            return Err(VmError::SharesFull);
        }
        let mut i = 0;
        loop {
            let Some(r) = self.regions.iter().nth(i) else {
                break;
            };
            i += 1;
            child.reserve(r)?;
            let end = r.end().ok_or(VmError::Overflow)?;
            let mut v = r.start;
            while let Some(leaf) = self.next_leaf(v, end)? {
                let ro = leaf.flags.without(PageFlags::WRITE);
                child.map_or_prune(leaf.base, leaf.frame, 0, ro, frames)?;
                if let Err(e) = self.shares.share(leaf.frame) {
                    // Unreachable after the count above, and handled anyway: an unrecorded
                    // second mapping is invariant 4 broken, in two spaces at once.
                    let _ = child.space.unmap(leaf.base, A::PAGE_SIZE, frames);
                    return Err(e);
                }
                if leaf.flags.contains(PageFlags::WRITE) {
                    self.space
                        .replace_leaf(leaf.slot, leaf.base, leaf.frame, ro, 0)?;
                }
                v = leaf.next();
            }
        }
        Ok(())
    }

    /// Undo [`Self::cow_share`] for the source pages below `upto`.
    fn unshare_prefix(&mut self, s: Region, d: Region, upto: usize, frames: &mut impl FrameSource) {
        let d_upto = d.start + (upto - s.start);
        let mut v = d.start;
        while let Ok(Some(leaf)) = self.next_leaf(v, d_upto) {
            if self.space.unmap(leaf.base, leaf.size, frames).is_err() {
                return;
            }
            let _ = self.shares.unshare(leaf.frame);
            let src_page = s.start + (leaf.base - d.start);
            if s.flags.contains(PageFlags::WRITE)
                && !self.shares.is_shared(leaf.frame)
                && let Ok(Some(back)) = self.leaf_at(src_page)
            {
                let _ = self.space.replace_leaf(
                    back.slot,
                    back.base,
                    back.frame,
                    back.flags.union(PageFlags::WRITE),
                    0,
                );
            }
            v = leaf.next();
        }
    }

    /// Change what `[start, start + len)` permits. The range must lie inside one region,
    /// which is split around it; huge leaves across its edges are split too.
    ///
    /// Granting write to anonymous pages that are shared does not make them writable:
    /// they stay read-only until a write fault copies them.
    pub fn protect(
        &mut self,
        start: usize,
        len: usize,
        flags: PageFlags,
        frames: &mut impl FrameSource,
    ) -> Result<(), VmError> {
        if len == 0 {
            return Err(VmError::Empty);
        }
        if start & (A::PAGE_SIZE - 1) != 0 || len & (A::PAGE_SIZE - 1) != 0 {
            return Err(VmError::Misaligned);
        }
        let end = start.checked_add(len).ok_or(VmError::Overflow)?;
        let (_, r) = self.regions.find(start).ok_or(VmError::NoRegion)?;
        let r_end = r.end().ok_or(VmError::Overflow)?;
        if end > r_end {
            return Err(VmError::Mismatch);
        }
        let splits = usize::from(start != r.start) + usize::from(end != r_end);
        if self.regions.room() < splits {
            return Err(VmError::RegionsFull);
        }

        // Leaves must not cross the new region edges. Splitting changes nothing anyone
        // can observe, so an error part-way leaves a consistent space.
        for edge in [start, end] {
            if edge == r.start || edge == r_end {
                continue;
            }
            // Repeated, because a 1 GiB leaf splits into 2 MiB ones that may still cross.
            while let Some(leaf) = self.leaf_at(edge)?
                && leaf.base != edge
            {
                self.space.split_leaf(edge, frames)?;
            }
        }
        self.regions.split_at(start)?;
        self.regions.split_at(end)?;

        let mut v = start;
        while let Some(leaf) = self.next_leaf(v, end)? {
            let mut granted = flags;
            if r.backing == Backing::Anonymous
                && leaf.level == 0
                && self.shares.is_shared(leaf.frame)
            {
                granted = granted.without(PageFlags::WRITE);
            }
            self.space
                .replace_leaf(leaf.slot, leaf.base, leaf.frame, granted, leaf.level)?;
            v = leaf.next();
        }
        let (i, _) = self.regions.exact(start).ok_or(VmError::Mismatch)?;
        self.regions.set_flags(i, flags)
    }

    /// Remove the region starting at `start`, unmapping everything in it and returning
    /// its anonymous frames that nothing else maps.
    pub fn release(
        &mut self,
        start: usize,
        frames: &mut impl FrameSource,
    ) -> Result<Region, VmError> {
        let (_, r) = self.regions.exact(start).ok_or(VmError::NoRegion)?;
        let end = r.end().ok_or(VmError::Overflow)?;
        let mut v = r.start;
        while let Some(leaf) = self.next_leaf(v, end)? {
            // Unmapped, and so invalidated, before the frame can be handed to anyone else.
            self.space.unmap(leaf.base, leaf.size, frames)?;
            if r.backing == Backing::Anonymous {
                if leaf.level == 0 {
                    if self.shares.unshare(leaf.frame) == Remaining::Last {
                        frames.free(leaf.frame);
                    }
                } else {
                    free_block::<A>(frames, leaf.frame, leaf.size / A::PAGE_SIZE);
                }
            }
            v = leaf.next();
        }
        let (i, _) = self.regions.exact(start).ok_or(VmError::Mismatch)?;
        self.regions.remove(i).ok_or(VmError::Mismatch)
    }

    /// Check every invariant in the module comment against the live tables.
    ///
    /// Quadratic in the number of mapped pages, because invariant 4 is checked by
    /// counting. A test and bring-up tool, not something to call on every fault.
    pub fn audit(&self) -> Result<Audit, AuditError> {
        let mut audit = Audit::default();
        let execute_matters = A::can_forbid_execute();
        for r in self.regions.iter() {
            let end = r.end().ok_or(AuditError::Walk(MapError::NotCanonical))?;
            let mut v = r.start;
            while let Some(leaf) = self.next_leaf(v, end).map_err(walk)? {
                if leaf.base < r.start || leaf.base.checked_add(leaf.size).is_none_or(|e| e > end) {
                    return Err(AuditError::CrossesRegion(leaf.base));
                }
                let mut excess = leaf.flags.without(r.flags);
                if !execute_matters {
                    excess = excess.without(PageFlags::EXECUTE);
                }
                if excess.intersects(PageFlags::WRITE | PageFlags::EXECUTE | PageFlags::USER) {
                    return Err(AuditError::ExceedsRegion(leaf.base));
                }
                match r.backing {
                    Backing::Physical { .. } => {
                        if r.phys_at(leaf.base) != Some(leaf.frame) {
                            return Err(AuditError::WrongFrame(leaf.base));
                        }
                    }
                    Backing::Anonymous if leaf.level > 0 => {
                        if self.any_shared(leaf.frame, leaf.size) {
                            return Err(AuditError::HugeShared(leaf.base));
                        }
                        audit.huge += 1;
                        audit.frames_held += leaf.size / A::PAGE_SIZE;
                    }
                    Backing::Anonymous => {
                        let shared = self.shares.is_shared(leaf.frame);
                        if shared && leaf.flags.contains(PageFlags::WRITE) {
                            return Err(AuditError::WritableShared(leaf.base));
                        }
                        if self.mappings_of(leaf.frame)? != self.shares.count(leaf.frame) {
                            return Err(AuditError::CountWrong(leaf.frame));
                        }
                        audit.pages += 1;
                        if !shared {
                            audit.frames_held += 1;
                        }
                    }
                }
                v = leaf.next();
            }
        }
        // A recorded share that no leaf maps any more is a count nobody will decrement.
        for (frame, n) in self.shares.iter() {
            if self.mappings_of(frame)? != n {
                return Err(AuditError::CountWrong(frame));
            }
            audit.shared += 1;
            audit.frames_held += 1;
        }
        Ok(audit)
    }

    /// Base-page leaves in anonymous regions that map `frame`.
    fn mappings_of(&self, frame: PhysAddr) -> Result<u32, AuditError> {
        let mut n = 0u32;
        for r in self.regions.iter() {
            if r.backing != Backing::Anonymous {
                continue;
            }
            let end = r.end().ok_or(AuditError::Walk(MapError::NotCanonical))?;
            let mut v = r.start;
            while let Some(leaf) = self.next_leaf(v, end).map_err(walk)? {
                if leaf.level == 0 && leaf.frame == frame {
                    n = n.saturating_add(1);
                }
                v = leaf.next();
            }
        }
        Ok(n)
    }

    /// Whether any frame in `[base, base + size)` is shared.
    fn any_shared(&self, base: PhysAddr, size: usize) -> bool {
        self.shares
            .iter()
            .any(|(frame, _)| frame.raw() >= base.raw() && frame.raw() - base.raw() < size as u64)
    }

    /// The leaf mapping `addr`, if any.
    fn leaf_at(&self, addr: usize) -> Result<Option<Leaf>, VmError> {
        match self.space.probe(addr)? {
            Probe::Hole { .. } => Ok(None),
            Probe::Leaf {
                table,
                index,
                level,
                entry,
            } => {
                let size = level_size::<A>(level);
                Ok(Some(Leaf {
                    base: addr & !(size - 1),
                    size,
                    level,
                    frame: entry.address(),
                    flags: entry.flags(level),
                    slot: (table, index),
                }))
            }
        }
    }

    /// The first leaf mapping anything in `[from, end)`, skipping unmapped subtrees
    /// whole rather than probing every page of them.
    fn next_leaf(&self, from: usize, end: usize) -> Result<Option<Leaf>, VmError> {
        let mut v = from;
        while v < end {
            match self.space.probe(v)? {
                Probe::Leaf { .. } => return self.leaf_at(v),
                Probe::Hole { level } => {
                    let size = level_size::<A>(level);
                    match (v & !(size - 1)).checked_add(size) {
                        Some(next) => v = next,
                        None => return Ok(None),
                    }
                }
            }
        }
        Ok(None)
    }
}

fn walk(e: VmError) -> AuditError {
    match e {
        VmError::Map(m) => AuditError::Walk(m),
        _ => AuditError::Walk(MapError::NotMapped),
    }
}

/// Return `count` frames starting at `base`, one at a time.
fn free_block<A: HasPageTables>(frames: &mut impl FrameSource, base: PhysAddr, count: usize) {
    for i in 0..count {
        if let Ok(f) = base.checked_add((i * A::PAGE_SIZE) as u64) {
            frames.free(f);
        }
    }
}

/// A pointer to `len` bytes of physical memory at `phys`, if the direct map covers all
/// of them.
fn window(direct: DirectMap, phys: PhysAddr, len: usize) -> Result<*mut u8, VmError> {
    let last = phys
        .checked_add(len.saturating_sub(1) as u64)
        .map_err(|_| VmError::Overflow)?;
    if !direct.covers_phys(last) {
        return Err(VmError::Map(MapError::BadPhysAddr));
    }
    direct
        .ptr_to_phys(phys)
        .map(|p| p.as_ptr())
        .map_err(|_| VmError::Map(MapError::BadPhysAddr))
}

/// Zero `len` bytes of physical memory.
///
/// A demand page is zeroed here, not trusted to arrive zeroed. It is the one place a
/// missed zero hands one owner's data to another, and [`FrameSource::alloc`] makes no
/// promise about contents.
fn zero(direct: DirectMap, phys: PhysAddr, len: usize) -> Result<(), VmError> {
    let p = window(direct, phys, len)?;
    // SAFETY: `window` checked both the first and the last byte are inside the direct
    // map. The frames were just allocated by the caller, so nothing else reads or
    // writes them, and no leaf maps them yet.
    unsafe { core::ptr::write_bytes(p, 0, len) };
    Ok(())
}

/// Copy `len` bytes from one physical page to another.
fn copy_page(direct: DirectMap, from: PhysAddr, to: PhysAddr, len: usize) -> Result<(), VmError> {
    let src = window(direct, from, len)?;
    let dst = window(direct, to, len)?;
    // SAFETY: both ranges were checked inside the direct map. `to` was just allocated, so
    // it is not `from` and the two do not overlap. The source is shared read-only: every
    // mapping of it is read-only, so nothing writes it during the copy on one CPU.
    unsafe { core::ptr::copy_nonoverlapping(src, dst, len) };
    Ok(())
}

#[cfg(test)]
mod tests;

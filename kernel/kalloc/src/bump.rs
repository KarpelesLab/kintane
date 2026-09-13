//! The bootstrap heap: an arena with a cursor.
//!
//! # Why a bump allocator first
//!
//! Something has to be running before anything else can allocate, and that something
//! cannot itself need a heap. A bump allocator is two integers and an addition. Its
//! correctness argument fits in a paragraph, which matters because it is the code
//! running at the point in boot where there is no console worth the name and no way
//! to attach a debugger. `docs/architecture.md` puts "kalloc: kernel heap online"
//! immediately after the frame allocator and immediately before the device
//! framework; this is what comes online there.
//!
//! It is also the substrate the [size-class allocator](crate::slab) is built on: a
//! slab block is an ordinary bump allocation. One path from frames to heap memory,
//! one number for the heap's footprint.
//!
//! # What it does not do, and why that is the right trade
//!
//! **It does not reuse freed memory**, except in the immediate last-in-first-out
//! case: freeing the most recent allocation rolls the cursor back, so the
//! allocate-try-fail-free pattern does not leak, and so does a scope that allocates
//! a scratch buffer and drops it. Anything else is poisoned, counted, and abandoned.
//!
//! A free list would fix that, and a free list is what the slab above is for. Making
//! the bump allocator good at general-purpose freeing would mean duplicating the
//! slab's job in the one allocator that must stay obviously correct. The honest
//! division is: small objects go to the slab, which reuses properly; large and rare
//! objects — page tables, per-CPU areas, the slab's own blocks — come from here and
//! live as long as the kernel does.
//!
//! **It does not return frames.** Each region records its physical start and frame
//! count, so shrinking is implementable, but nothing asks for it and an unused
//! release path is an untested release path.
//!
//! # Growing
//!
//! The arena is not one range but up to [`MAX_REGIONS`] of them, because a frame
//! source under pressure may not have a long enough run. Growing takes a fresh
//! contiguous run and **abandons the tail of the current one**: the cursor cannot
//! step from one region to the next, since they are not adjacent. That tail is at
//! most as large as the request that failed, and it is counted in
//! [`BumpStats::wasted`] rather than quietly forgotten.

// Re-enabled for two calls into `crate::poison`, each on a block this allocator has
// just proved it owns. Every other line here is checked arithmetic on `KernAddr`.
#![allow(unsafe_code)]

use core::alloc::Layout;
use core::marker::PhantomData;
use core::ptr::NonNull;

use hal::{Arch, KernAddr, PhysAddr};
use mm::{AllocError, Frame, FrameRange};

use crate::context::AllocContext;
use mm::directmap::DirectMap;
use crate::frames::FrameSource;
use crate::{check_layout, narrow, poison, widen};

/// How many separate frame runs one arena may be built from.
///
/// Fixed, because the list of them has to live somewhere and the heap is the thing
/// that would otherwise hold it. Sixteen is enough for a kernel that grows its heap
/// by a run at a time and never shrinks; running out is [`AllocError::Exhausted`],
/// not corruption, and the fix when it ever matters is a region header inside each
/// region rather than a larger constant.
pub const MAX_REGIONS: usize = 16;

/// How much arena a growth tries to take, whatever was asked for.
///
/// Growing by exactly what the failing request needed is the obvious policy and it
/// is a bad one: each growth abandons the tail of the previous region and spends one
/// of [`MAX_REGIONS`] descriptors, so a heap grown a frame at a time runs out of
/// *descriptors* with most of the machine's memory still free. Sixteen kibibytes is
/// a few frames on a server and sixty-four on a target with 256-byte pages, which is
/// the right way round: the number of regions stays bounded in both.
///
/// It is a preference, not a floor. A frame source that cannot spare this much is
/// asked again for exactly what the request needed, so a nearly-full machine still
/// makes progress instead of failing while it has the memory.
const MIN_GROW_BYTES: usize = 16 * 1024;

/// One contiguous run of frames the arena was built from.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct Region {
    virt: KernAddr,
    bytes: usize,
    /// Kept so that a future `shrink` can hand the frames back, and so that a region
    /// can be identified in a dump by the physical memory it came from.
    phys: PhysAddr,
    frames: usize,
}

impl Region {
    const EMPTY: Region = Region {
        virt: KernAddr::ZERO,
        bytes: 0,
        phys: PhysAddr::ZERO,
        frames: 0,
    };

    fn contains(&self, addr: KernAddr, len: usize) -> bool {
        let Ok(off) = addr.diff(self.virt) else {
            return false;
        };
        match off.checked_add(len) {
            Some(end) => end <= self.bytes,
            None => false,
        }
    }
}

/// A snapshot of one arena's accounting.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct BumpStats {
    /// Bytes of frames the arena holds, across every region.
    pub arena_bytes: usize,
    /// Bytes currently handed out and not yet freed.
    pub in_use: usize,
    /// The largest `in_use` ever reached. What a heap size is chosen from.
    pub high_water: usize,
    /// Bytes lost to alignment padding and to abandoned region tails. The gap
    /// between `arena_bytes` and what could ever be handed out.
    pub wasted: usize,
    /// Bytes of the current region that the cursor has not reached.
    pub headroom: usize,
    /// Frames taken from the frame source.
    pub frames_held: usize,
    /// Regions in use, of [`MAX_REGIONS`].
    pub regions: usize,
    /// Live allocations.
    pub live: usize,
    /// Allocations served since construction.
    pub allocations: u64,
    /// Frees accepted since construction.
    pub frees: u64,
    /// Frees that rolled the cursor back and genuinely recovered the memory.
    pub reclaimed: u64,
}

/// An arena over frames, with a cursor.
///
/// Not internally synchronised; see the crate documentation.
pub struct Bump<A: Arch> {
    map: DirectMap,
    /// Next byte the cursor will hand out.
    cursor: KernAddr,
    /// One past the last byte of the current region. `cursor == end` means the
    /// region is spent, which is also the state a freshly constructed arena is in.
    end: KernAddr,
    regions: [Region; MAX_REGIONS],
    region_count: usize,
    /// The most recent allocation, for last-in-first-out reclaim. Cleared whenever
    /// it is consumed, so the rollback happens at most once per allocation.
    last: Option<(KernAddr, usize)>,
    arena_bytes: usize,
    frames_held: usize,
    in_use: usize,
    high_water: usize,
    wasted: usize,
    live: usize,
    allocations: u64,
    frees: u64,
    reclaimed: u64,
    _arch: PhantomData<fn() -> A>,
}

impl<A: Arch> Bump<A> {
    /// An empty arena over `map`.
    ///
    /// It holds no memory and every allocation fails with [`AllocError::Exhausted`]
    /// until it is given some, either by [`Self::grow`] or by [`Self::add_frames`].
    /// Starting empty rather than taking frames at construction keeps the constructor
    /// infallible and leaves the decision of how much heap to start with where it
    /// belongs, with the bootstrap.
    pub fn new(map: DirectMap) -> Self {
        Bump {
            map,
            cursor: KernAddr::ZERO,
            end: KernAddr::ZERO,
            regions: [Region::EMPTY; MAX_REGIONS],
            region_count: 0,
            last: None,
            arena_bytes: 0,
            frames_held: 0,
            in_use: 0,
            high_water: 0,
            wasted: 0,
            live: 0,
            allocations: 0,
            frees: 0,
            reclaimed: 0,
            _arch: PhantomData,
        }
    }

    /// The physical-to-virtual window this arena hands out pointers through.
    pub fn direct_map(&self) -> DirectMap {
        self.map
    }

    /// Current accounting.
    pub fn stats(&self) -> BumpStats {
        BumpStats {
            arena_bytes: self.arena_bytes,
            in_use: self.in_use,
            high_water: self.high_water,
            wasted: self.wasted,
            headroom: self.end.diff(self.cursor).unwrap_or(0),
            frames_held: self.frames_held,
            regions: self.region_count,
            live: self.live,
            allocations: self.allocations,
            frees: self.frees,
            reclaimed: self.reclaimed,
        }
    }

    /// Serve an allocation from memory the arena already holds.
    ///
    /// Never takes frames from anywhere; an arena with no headroom fails. This is
    /// [`Self::try_alloc_in`] with [`crate::NoFrames`], and it is the signature the
    /// rest of the kernel will use once the bootstrap has sized the heap.
    ///
    /// # Errors
    /// [`AllocError::EmptyRequest`] or [`AllocError::Misaligned`] for a layout no
    /// allocator could serve, [`AllocError::Overflow`] if the request would leave the
    /// address space, and [`AllocError::Exhausted`] when the arena has no room.
    pub fn try_alloc(
        &mut self,
        layout: Layout,
        ctx: AllocContext,
    ) -> Result<NonNull<u8>, AllocError> {
        self.try_alloc_in(layout, ctx, &mut crate::NoFrames)
    }

    /// Serve an allocation, taking more frames if the arena has no room.
    ///
    /// One retry, not a loop: [`Self::grow`] asks for enough frames to satisfy this
    /// request outright, so if the second attempt fails the first one was not going
    /// to succeed either, and a loop would only turn an out-of-memory condition into
    /// a hang.
    ///
    /// # Errors
    /// As [`Self::try_alloc`], plus whatever `src` returns — notably
    /// [`AllocError::Fragmented`] when the machine has frames but no adjacent run
    /// long enough, which a caller may be able to work around and
    /// [`AllocError::Exhausted`] which it cannot.
    pub fn try_alloc_in(
        &mut self,
        layout: Layout,
        ctx: AllocContext,
        src: &mut impl FrameSource<A>,
    ) -> Result<NonNull<u8>, AllocError> {
        let (size, align) = check_layout(layout)?;
        let start = match self.carve(size, align) {
            Ok(s) => s,
            Err(AllocError::Exhausted) => {
                // Worst case the new region starts just past an alignment boundary,
                // so ask for the object plus a full alignment of slack.
                let want = size.checked_add(align).ok_or(AllocError::Overflow)?;
                self.grow(src, want)?;
                self.carve(size, align)?
            }
            Err(e) => return Err(e),
        };
        let ptr = self.map.ptr_at(start)?;

        self.in_use = self.in_use.saturating_add(size);
        self.high_water = self.high_water.max(self.in_use);
        self.live = self.live.saturating_add(1);
        self.allocations = self.allocations.saturating_add(1);
        self.last = Some((start, size));

        if ctx.wants_zero() {
            // SAFETY: `start .. start + size` was just carved out of the current
            // region and has not been returned to any caller, so this allocator holds
            // exclusive ownership of it and no reference into it exists. The pointer
            // came from `ptr_at`, which proved the range is inside the direct-mapped
            // window.
            unsafe { poison::fill_zero(ptr, size) };
        }
        Ok(ptr)
    }

    /// Give a block back.
    ///
    /// The memory is poisoned and the accounting updated. It is reused only if it was
    /// the most recent allocation, in which case the cursor rolls back to it; see the
    /// module documentation for why that is the whole reuse story here.
    ///
    /// # Errors
    /// [`AllocError::Unmanaged`] if the block is not wholly inside one of this
    /// arena's regions, which catches a pointer from a different allocator and a
    /// length that runs off the end of a region.
    ///
    /// # Safety
    /// `ptr` must have come from this arena, with this `layout`, and must not have
    /// been freed already. The range check above is a diagnostic and not the
    /// contract: an address inside the arena is not proof that the *caller* owned it,
    /// and freeing a block twice after it has been reissued will poison memory that
    /// now belongs to somebody else.
    pub unsafe fn dealloc(
        &mut self,
        ptr: NonNull<u8>,
        layout: Layout,
        _ctx: AllocContext,
    ) -> Result<(), AllocError> {
        let (size, _align) = check_layout(layout)?;
        let addr = KernAddr::new(ptr.addr().get());
        if !self.owns(addr, size) {
            return Err(AllocError::Unmanaged);
        }

        // SAFETY: the caller guarantees the block is theirs and dead; the check above
        // guarantees `addr .. addr + size` lies inside a region this arena owns, so
        // the pointer is valid for writes of `size` bytes.
        unsafe { poison::fill_freed(ptr, size) };

        self.in_use = self.in_use.saturating_sub(size);
        self.live = self.live.saturating_sub(1);
        self.frees = self.frees.saturating_add(1);

        if self.last == Some((addr, size)) {
            self.cursor = addr;
            self.last = None;
            self.reclaimed = self.reclaimed.saturating_add(1);
        }
        Ok(())
    }

    /// Take at least `min_bytes` more of arena from `src`, and report the frames
    /// taken.
    ///
    /// The new region becomes the one the cursor runs over; the tail of the previous
    /// one is abandoned. Exposed rather than left internal so a bootstrap can size
    /// the heap up front, which is preferable to growing it for the first time from
    /// inside whatever code happened to allocate first.
    ///
    /// # Errors
    /// [`AllocError::EmptyRequest`] for `min_bytes == 0`, [`AllocError::Exhausted`]
    /// if the region table is full or `src` has nothing left, and whatever else `src`
    /// returns. Nothing is taken from `src` unless it can be recorded.
    pub fn grow(
        &mut self,
        src: &mut impl FrameSource<A>,
        min_bytes: usize,
    ) -> Result<usize, AllocError> {
        if min_bytes == 0 {
            return Err(AllocError::EmptyRequest);
        }
        // Checked before taking anything: a run taken and then not recorded is a run
        // leaked, and the frame source has no way to notice.
        if self.region_count >= MAX_REGIONS {
            return Err(AllocError::Exhausted);
        }
        let page = Frame::<A>::SIZE;
        if page == 0 {
            return Err(AllocError::Overflow);
        }
        let need = min_bytes.div_ceil(page).max(1);
        let want = need.max(MIN_GROW_BYTES.div_ceil(page));
        let range = match src.take(want) {
            Ok(r) => r,
            // The machine cannot spare the comfortable amount. Ask for exactly what
            // this request needs rather than failing while the memory is there.
            Err(_) if want > need => src.take(need)?,
            Err(e) => return Err(e),
        };
        let taken = range.count();
        self.add_frames(range)?;
        Ok(taken)
    }

    /// Add a run of frames the caller already owns to the arena.
    ///
    /// The other half of [`Self::grow`], for a bootstrap that carved memory out
    /// before the frame allocator existed and wants to donate it, or for a caller
    /// that took the frames itself because it needed them at a particular address.
    ///
    /// The arena takes ownership: these frames are never returned.
    ///
    /// # Errors
    /// [`AllocError::Exhausted`] if the region table is full, [`AllocError::Unmanaged`]
    /// if the run is not inside the direct map, and [`AllocError::Overflow`] if it
    /// does not fit in the kernel's address space. A run outside the direct map is a
    /// bootstrap configuration error rather than a runtime condition: the frames are
    /// not added, and they are not given back either, because this type has no way
    /// to.
    pub fn add_frames(&mut self, range: FrameRange<A>) -> Result<(), AllocError> {
        if self.region_count >= MAX_REGIONS {
            return Err(AllocError::Exhausted);
        }
        let phys = range.start().start();
        let bytes = narrow(range.len_bytes()?)?;
        if bytes == 0 {
            return Err(AllocError::EmptyRequest);
        }

        // Both ends, so a run that starts inside the window and leaves it is refused
        // here rather than discovered by an allocation near the top of it.
        let virt = self.map.to_virt(phys)?;
        let last_byte = phys.checked_add(widen(bytes).saturating_sub(1))?;
        self.map.to_virt(last_byte)?;
        let region_end = virt.checked_add(bytes)?;

        let slot = self
            .regions
            .get_mut(self.region_count)
            .ok_or(AllocError::Exhausted)?;
        *slot = Region {
            virt,
            bytes,
            phys,
            frames: range.count(),
        };
        self.region_count = self.region_count.saturating_add(1);

        // The cursor cannot step from one region to the next, so whatever is left of
        // the old one is lost. Counted, not hidden.
        let tail = self.end.diff(self.cursor).unwrap_or(0);
        self.wasted = self.wasted.saturating_add(tail);

        self.cursor = virt;
        self.end = region_end;
        // A rollback target in the region we just left would roll the cursor into the
        // wrong region entirely.
        self.last = None;
        self.arena_bytes = self.arena_bytes.saturating_add(bytes);
        self.frames_held = self.frames_held.saturating_add(range.count());
        Ok(())
    }

    /// Whether this arena handed out the block at `addr`.
    ///
    /// True for any address inside a region, allocated or not: the arena does not
    /// track individual blocks, so this answers "could this have come from here",
    /// which is the most a bump allocator can say.
    pub fn owns(&self, addr: KernAddr, len: usize) -> bool {
        self.regions
            .iter()
            .take(self.region_count)
            .any(|r| r.contains(addr, len))
    }

    /// Where a pointer into this arena is in physical memory.
    ///
    /// What a DMA-capable driver needs, and the reason the direct map is a window
    /// with an inverse rather than a one-way conversion.
    ///
    /// # Errors
    /// [`AllocError::Unmanaged`] if the address is outside the arena or outside the
    /// direct map.
    pub fn phys_of(&self, ptr: NonNull<u8>) -> Result<PhysAddr, AllocError> {
        let addr = KernAddr::new(ptr.addr().get());
        if !self.owns(addr, 1) {
            return Err(AllocError::Unmanaged);
        }
        self.map.to_phys(addr)
    }

    // --- internals ----------------------------------------------------------

    /// Move the cursor past `size` bytes aligned to `align`, and report where the
    /// block starts. Touches no statistics, so a failed attempt followed by a
    /// successful one counts once.
    fn carve(&mut self, size: usize, align: usize) -> Result<KernAddr, AllocError> {
        let start = self.cursor.align_up(align)?;
        let next = start.checked_add(size)?;
        if next > self.end {
            return Err(AllocError::Exhausted);
        }
        // Alignment padding is unreachable for the same reason an abandoned tail is:
        // nothing records where it went.
        let slack = start.diff(self.cursor).unwrap_or(0);
        self.wasted = self.wasted.saturating_add(slack);
        self.cursor = next;
        Ok(start)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::AllocFlags;
    use crate::hostmem::HostMemory;
    use crate::poison;
    use hal::mock::{MockFull, MockTiny};

    /// 128 KiB: 32 frames on `MockFull` and 512 on `MockTiny`, which is enough for
    /// every scenario here and small enough to allocate per test.
    const ARENA: usize = 128 * 1024;

    #[track_caller]
    fn expect<T>(r: Result<T, AllocError>) -> T {
        match r {
            Ok(v) => v,
            Err(e) => panic!("unexpected {e:?}"),
        }
    }

    #[track_caller]
    fn layout(size: usize, align: usize) -> Layout {
        match Layout::from_size_align(size, align) {
            Ok(l) => l,
            Err(e) => panic!("bad test layout: {e:?}"),
        }
    }

    fn addr_of(p: NonNull<u8>) -> usize {
        p.addr().get()
    }

    // --- the basics ---------------------------------------------------------

    fn an_empty_arena_serves_nothing<A: Arch>() {
        let mem = HostMemory::new(ARENA);
        let mut b = Bump::<A>::new(mem.direct_map());
        assert_eq!(b.stats().arena_bytes, 0);
        assert_eq!(
            b.try_alloc(layout(8, 8), AllocContext::ATOMIC).err(),
            Some(AllocError::Exhausted),
            "an arena with no frames must fail, not reach for memory it has not got"
        );
    }

    #[test]
    fn an_empty_arena_serves_nothing_full() {
        an_empty_arena_serves_nothing::<MockFull>();
    }

    #[test]
    fn an_empty_arena_serves_nothing_tiny() {
        an_empty_arena_serves_nothing::<MockTiny>();
    }

    fn allocation_is_aligned_and_does_not_overlap<A: Arch>() {
        let mem = HostMemory::new(ARENA);
        let mut src = mem.frames::<A>();
        let mut b = Bump::<A>::new(mem.direct_map());

        // Alignments spanning both sides of MockTiny's 256-byte page, so an arena
        // whose alignment came from the page size rather than from the request fails
        // on one of them.
        let mut blocks: Vec<(usize, usize)> = Vec::new();
        for align in [1usize, 2, 4, 8, 16, 64, 512, 4096] {
            for size in [1usize, 3, 17, 64] {
                let p = expect(b.try_alloc_in(layout(size, align), AllocContext::ATOMIC, &mut src));
                let a = addr_of(p);
                assert_eq!(a % align, 0, "size {size} align {align} gave {a:#x}");
                for (other, olen) in &blocks {
                    let disjoint = a.saturating_add(size) <= *other || *other + *olen <= a;
                    assert!(disjoint, "{a:#x}+{size} overlaps {other:#x}+{olen}");
                }
                blocks.push((a, size));
            }
        }
        assert_eq!(b.stats().live, blocks.len());
    }

    #[test]
    fn allocation_is_aligned_and_does_not_overlap_full() {
        allocation_is_aligned_and_does_not_overlap::<MockFull>();
    }

    #[test]
    fn allocation_is_aligned_and_does_not_overlap_tiny() {
        allocation_is_aligned_and_does_not_overlap::<MockTiny>();
    }

    fn the_pointer_points_at_the_memory_it_claims_to<A: Arch>() {
        // The point of the direct map: a returned pointer must address the physical
        // frame the arena took, at the offset the arena says. Written through the
        // pointer, read back through the buffer.
        let mem = HostMemory::new(ARENA);
        let mut src = mem.frames::<A>();
        let mut b = Bump::<A>::new(mem.direct_map());
        let p = expect(b.try_alloc_in(layout(4, 4), AllocContext::ATOMIC, &mut src));

        #[allow(unsafe_code)]
        // SAFETY: `p` is a live allocation of four bytes from `b`, which is backed by
        // `mem`. Nothing else holds a reference to those bytes, and `mem` outlives
        // this statement.
        unsafe {
            p.as_ptr().write_bytes(0xC7, 4);
        }
        assert_eq!(mem.bytes_at(addr_of(p), 4), Some(&[0xC7u8; 4][..]));

        // And the inverse conversion agrees about where it is.
        let phys = expect(b.phys_of(p));
        assert_eq!(expect(b.direct_map().to_virt(phys)).raw(), addr_of(p));
    }

    #[test]
    fn the_pointer_points_at_the_memory_it_claims_to_full() {
        the_pointer_points_at_the_memory_it_claims_to::<MockFull>();
    }

    #[test]
    fn the_pointer_points_at_the_memory_it_claims_to_tiny() {
        the_pointer_points_at_the_memory_it_claims_to::<MockTiny>();
    }

    // --- bad layouts --------------------------------------------------------

    fn absurd_layouts_are_refused_rather_than_wrapping<A: Arch>() {
        let mem = HostMemory::new(ARENA);
        let mut src = mem.frames::<A>();
        let mut b = Bump::<A>::new(mem.direct_map());
        expect(b.grow(&mut src, 4096));
        // One ordinary allocation first, so that the cursor is not sitting on an
        // enormous alignment boundary by accident of where the host put the buffer —
        // which would make the alignment case below pass or fail at random.
        let _ = expect(b.try_alloc(layout(1, 1), AllocContext::ATOMIC));
        let before = b.stats();

        assert_eq!(
            b.try_alloc(layout(0, 8), AllocContext::ATOMIC).err(),
            Some(AllocError::EmptyRequest),
            "a zero-sized block cannot be freed and must not be handed out"
        );
        // A layout that is legal but larger than the machine. The arena must report
        // exhaustion rather than wrapping its cursor into a plausible address.
        assert_eq!(
            b.try_alloc_in(layout(usize::MAX / 4, 1), AllocContext::ATOMIC, &mut src)
                .err(),
            Some(AllocError::Exhausted)
        );
        // An alignment far beyond anything the arena holds, likewise.
        assert_eq!(
            b.try_alloc_in(layout(8, 1 << 20), AllocContext::ATOMIC, &mut src)
                .err(),
            Some(AllocError::Exhausted)
        );
        assert_eq!(
            b.stats().allocations,
            before.allocations,
            "a refused request must not be counted as served"
        );
        assert_eq!(b.stats().in_use, before.in_use);
    }

    #[test]
    fn absurd_layouts_are_refused_rather_than_wrapping_full() {
        absurd_layouts_are_refused_rather_than_wrapping::<MockFull>();
    }

    #[test]
    fn absurd_layouts_are_refused_rather_than_wrapping_tiny() {
        absurd_layouts_are_refused_rather_than_wrapping::<MockTiny>();
    }

    // --- exhaustion ---------------------------------------------------------

    fn exhaustion_is_an_error_forever<A: Arch>() {
        let mem = HostMemory::new(ARENA);
        let mut src = mem.frames::<A>();
        src.limit_to(2);
        let mut b = Bump::<A>::new(mem.direct_map());

        let page = Frame::<A>::SIZE;
        // Fill the arena with page-sized blocks until it can take no more.
        let mut served = 0;
        while b
            .try_alloc_in(layout(page, 1), AllocContext::ATOMIC, &mut src)
            .is_ok()
        {
            served += 1;
            assert!(served < 1000, "the arena must run out");
        }
        assert!(served > 0, "it must serve something first");

        // Repeatedly, and without panicking: the kernel may not abort because memory
        // ran out, and may not abort on the fifth attempt either.
        for _ in 0..5 {
            assert_eq!(
                b.try_alloc_in(layout(page, 1), AllocContext::ATOMIC, &mut src)
                    .err(),
                Some(AllocError::Exhausted)
            );
        }
        // Something small still fails too, once the frames are gone.
        assert_eq!(
            b.try_alloc_in(layout(1, 1), AllocContext::ATOMIC, &mut src)
                .err(),
            Some(AllocError::Exhausted)
        );
    }

    #[test]
    fn exhaustion_is_an_error_forever_full() {
        exhaustion_is_an_error_forever::<MockFull>();
    }

    #[test]
    fn exhaustion_is_an_error_forever_tiny() {
        exhaustion_is_an_error_forever::<MockTiny>();
    }

    // --- freeing ------------------------------------------------------------

    fn freeing_poisons_and_accounts<A: Arch>() {
        let mem = HostMemory::new(ARENA);
        let mut src = mem.frames::<A>();
        let mut b = Bump::<A>::new(mem.direct_map());

        let keep = expect(b.try_alloc_in(layout(32, 8), AllocContext::ATOMIC, &mut src));
        let gone = expect(b.try_alloc_in(layout(32, 8), AllocContext::ATOMIC, &mut src));
        #[allow(unsafe_code)]
        // SAFETY: `keep` is live, 32 bytes, and nothing else refers to it.
        unsafe {
            keep.as_ptr().write_bytes(0x11, 32);
        }
        assert_eq!(b.stats().in_use, 64);

        // SAFETY: `gone` came from this arena with this layout and is freed once.
        #[allow(unsafe_code)]
        let r = unsafe { b.dealloc(gone, layout(32, 8), AllocContext::ATOMIC) };
        assert_eq!(r, Ok(()));

        let freed = match mem.bytes_at(addr_of(gone), 32) {
            Some(s) => s,
            None => panic!("the block must be inside the backing buffer"),
        };
        if poison::ENABLED {
            assert!(
                freed.iter().all(|b| *b == poison::FREED),
                "freed memory must be poisoned in a debug build: {freed:?}"
            );
        } else {
            assert!(
                freed.iter().all(|b| *b != poison::FREED),
                "a release build must not spend time poisoning"
            );
        }

        // The neighbour is untouched: poisoning must not run off the end of a block.
        assert_eq!(mem.bytes_at(addr_of(keep), 32), Some(&[0x11u8; 32][..]));

        let s = b.stats();
        assert_eq!(s.in_use, 32);
        assert_eq!(s.live, 1);
        assert_eq!(s.frees, 1);
    }

    #[test]
    fn freeing_poisons_and_accounts_full() {
        freeing_poisons_and_accounts::<MockFull>();
    }

    #[test]
    fn freeing_poisons_and_accounts_tiny() {
        freeing_poisons_and_accounts::<MockTiny>();
    }

    fn the_most_recent_block_is_reused<A: Arch>() {
        // The allocate-try-fail-free pattern must not leak, and a scratch buffer in a
        // loop must not consume the arena.
        let mem = HostMemory::new(ARENA);
        let mut src = mem.frames::<A>();
        let mut b = Bump::<A>::new(mem.direct_map());

        let first = expect(b.try_alloc_in(layout(48, 16), AllocContext::ATOMIC, &mut src));
        for _ in 0..64 {
            #[allow(unsafe_code)]
            // SAFETY: the pointer from the previous iteration, freed exactly once
            // with the layout it was allocated with.
            let r = unsafe { b.dealloc(first, layout(48, 16), AllocContext::ATOMIC) };
            assert_eq!(r, Ok(()));
            let again = expect(b.try_alloc_in(layout(48, 16), AllocContext::ATOMIC, &mut src));
            assert_eq!(
                addr_of(again),
                addr_of(first),
                "freeing the newest block must roll the cursor back to it"
            );
        }
        let s = b.stats();
        assert_eq!(s.in_use, 48, "the loop must not have grown the live set");
        assert_eq!(s.reclaimed, 64);
        assert_eq!(
            s.regions, 1,
            "nor reached for memory after the first allocation"
        );
    }

    #[test]
    fn the_most_recent_block_is_reused_full() {
        the_most_recent_block_is_reused::<MockFull>();
    }

    #[test]
    fn the_most_recent_block_is_reused_tiny() {
        the_most_recent_block_is_reused::<MockTiny>();
    }

    fn an_older_block_is_not_reused_and_says_so<A: Arch>() {
        // The honest limitation, asserted so that it is a decision rather than a
        // surprise: freeing anything but the newest block does not recover it.
        let mem = HostMemory::new(ARENA);
        let mut src = mem.frames::<A>();
        let mut b = Bump::<A>::new(mem.direct_map());

        let old = expect(b.try_alloc_in(layout(32, 8), AllocContext::ATOMIC, &mut src));
        let _new = expect(b.try_alloc_in(layout(32, 8), AllocContext::ATOMIC, &mut src));
        #[allow(unsafe_code)]
        // SAFETY: `old` came from this arena with this layout and is freed once.
        let r = unsafe { b.dealloc(old, layout(32, 8), AllocContext::ATOMIC) };
        assert_eq!(r, Ok(()));

        let next = expect(b.try_alloc_in(layout(32, 8), AllocContext::ATOMIC, &mut src));
        assert_ne!(addr_of(next), addr_of(old));
        assert_eq!(b.stats().reclaimed, 0);
    }

    #[test]
    fn an_older_block_is_not_reused_and_says_so_full() {
        an_older_block_is_not_reused_and_says_so::<MockFull>();
    }

    #[test]
    fn an_older_block_is_not_reused_and_says_so_tiny() {
        an_older_block_is_not_reused_and_says_so::<MockTiny>();
    }

    fn a_foreign_pointer_is_refused<A: Arch>() {
        let mem = HostMemory::new(ARENA);
        let other = HostMemory::new(4096);
        let mut src = mem.frames::<A>();
        let mut b = Bump::<A>::new(mem.direct_map());
        expect(b.grow(&mut src, 4096));

        // A pointer into an entirely different region of host memory.
        let foreign = expect(other.direct_map().ptr_at(
            expect(other.direct_map().to_virt(PhysAddr::new(64))),
        ));
        #[allow(unsafe_code)]
        // SAFETY: the call is expected to reject the pointer without writing to it,
        // which is the property under test; `foreign` is live memory either way.
        let r = unsafe { b.dealloc(foreign, layout(8, 8), AllocContext::ATOMIC) };
        assert_eq!(r, Err(AllocError::Unmanaged));
        assert_eq!(b.stats().frees, 0);
        assert_eq!(
            other.byte_at(foreign.addr().get()),
            Some(0x5A),
            "a rejected free must not have poisoned anything"
        );
    }

    #[test]
    fn a_foreign_pointer_is_refused_full() {
        a_foreign_pointer_is_refused::<MockFull>();
    }

    #[test]
    fn a_foreign_pointer_is_refused_tiny() {
        a_foreign_pointer_is_refused::<MockTiny>();
    }

    // --- zeroing ------------------------------------------------------------

    fn zeroing_is_honoured<A: Arch>() {
        let mem = HostMemory::new(ARENA);
        let mut src = mem.frames::<A>();
        let mut b = Bump::<A>::new(mem.direct_map());
        let ctx = AllocContext::ATOMIC.with(AllocFlags::ZERO);

        let dirty = expect(b.try_alloc_in(layout(64, 8), AllocContext::ATOMIC, &mut src));
        assert_eq!(
            mem.byte_at(addr_of(dirty)),
            Some(0x5A),
            "without the flag the block keeps whatever was there"
        );

        let clean = expect(b.try_alloc_in(layout(64, 8), ctx, &mut src));
        assert_eq!(mem.bytes_at(addr_of(clean), 64), Some(&[0u8; 64][..]));
        // Exactly 64 bytes: zeroing must not run past the block.
        assert_eq!(mem.byte_at(addr_of(clean).saturating_add(64)), Some(0x5A));
    }

    #[test]
    fn zeroing_is_honoured_full() {
        zeroing_is_honoured::<MockFull>();
    }

    #[test]
    fn zeroing_is_honoured_tiny() {
        zeroing_is_honoured::<MockTiny>();
    }

    // --- growth -------------------------------------------------------------

    fn growth_takes_whole_frames_and_counts_them<A: Arch>() {
        let mem = HostMemory::new(ARENA);
        let mut src = mem.frames::<A>();
        let mut b = Bump::<A>::new(mem.direct_map());

        let page = Frame::<A>::SIZE;
        let taken = expect(b.grow(&mut src, page.saturating_add(1)));
        let s = b.stats();
        assert_eq!(s.frames_held, taken);
        assert_eq!(
            s.arena_bytes,
            page.saturating_mul(taken),
            "an arena is always a whole number of frames"
        );
        assert!(
            taken >= 2,
            "a byte past a page costs a whole second frame at least"
        );
        assert_eq!(s.regions, 1, "one growth is one region");
        assert_eq!(s.headroom, s.arena_bytes);

        assert_eq!(b.grow(&mut src, 0).err(), Some(AllocError::EmptyRequest));
    }

    fn growth_settles_for_less_when_the_machine_has_less<A: Arch>() {
        // The fallback in `grow`: it prefers a comfortable region, but a machine that
        // cannot spare one must still make progress rather than fail with the memory
        // sitting there.
        let mem = HostMemory::new(ARENA);
        let mut src = mem.frames::<A>();
        src.limit_to(2);
        let mut b = Bump::<A>::new(mem.direct_map());

        let taken = expect(b.grow(&mut src, Frame::<A>::SIZE));
        assert_eq!(taken, 1, "exactly what the request needed, and no more");
        assert_eq!(src.remaining(), 1);
        assert!(b.try_alloc(layout(8, 8), AllocContext::ATOMIC).is_ok());
    }

    #[test]
    fn growth_settles_for_less_when_the_machine_has_less_full() {
        growth_settles_for_less_when_the_machine_has_less::<MockFull>();
    }

    #[test]
    fn growth_settles_for_less_when_the_machine_has_less_tiny() {
        growth_settles_for_less_when_the_machine_has_less::<MockTiny>();
    }

    #[test]
    fn growth_takes_whole_frames_and_counts_them_full() {
        growth_takes_whole_frames_and_counts_them::<MockFull>();
    }

    #[test]
    fn growth_takes_whole_frames_and_counts_them_tiny() {
        growth_takes_whole_frames_and_counts_them::<MockTiny>();
    }

    fn growing_abandons_the_tail_and_counts_it<A: Arch>() {
        let mem = HostMemory::new(ARENA);
        let mut src = mem.frames::<A>();
        let mut b = Bump::<A>::new(mem.direct_map());
        let page = Frame::<A>::SIZE;

        expect(b.grow(&mut src, page));
        // Half a page first, so the region cannot be consumed exactly, then fill it
        // until less than a page is left. That leftover is the tail.
        let _ = expect(b.try_alloc(layout(page / 2, 1), AllocContext::ATOMIC));
        while b.stats().headroom >= page {
            let _ = expect(b.try_alloc(layout(page, 1), AllocContext::ATOMIC));
        }
        let tail = b.stats().headroom;
        assert!(tail > 0, "the region must not divide exactly");

        let _ = expect(b.try_alloc_in(layout(page, 1), AllocContext::ATOMIC, &mut src));
        let s = b.stats();
        assert_eq!(s.regions, 2);
        assert!(
            s.wasted >= tail,
            "the abandoned tail must be counted: wasted {} tail {tail}",
            s.wasted
        );
    }

    #[test]
    fn growing_abandons_the_tail_and_counts_it_full() {
        growing_abandons_the_tail_and_counts_it::<MockFull>();
    }

    #[test]
    fn growing_abandons_the_tail_and_counts_it_tiny() {
        growing_abandons_the_tail_and_counts_it::<MockTiny>();
    }

    fn the_region_table_is_finite_and_fails_cleanly<A: Arch>() {
        let mem = HostMemory::new(ARENA);
        let mut src = mem.frames::<A>();
        let mut b = Bump::<A>::new(mem.direct_map());

        // A frame at a time, through `add_frames`, so the region table fills before
        // the machine's memory does whatever the growth policy happens to prefer.
        for _ in 0..MAX_REGIONS {
            let run = expect(FrameSource::<A>::take(&mut src, 1));
            expect(b.add_frames(run));
        }
        assert_eq!(b.stats().regions, MAX_REGIONS);

        let run = expect(FrameSource::<A>::take(&mut src, 1));
        assert_eq!(b.add_frames(run).err(), Some(AllocError::Exhausted));

        let before = src.handed_out();
        assert_eq!(b.grow(&mut src, 1).err(), Some(AllocError::Exhausted));
        assert_eq!(
            src.handed_out(),
            before,
            "a growth that cannot be recorded must not take frames it then leaks"
        );
        // The current region still works.
        assert!(b.try_alloc(layout(8, 8), AllocContext::ATOMIC).is_ok());
    }

    #[test]
    fn the_region_table_is_finite_and_fails_cleanly_full() {
        the_region_table_is_finite_and_fails_cleanly::<MockFull>();
    }

    #[test]
    fn the_region_table_is_finite_and_fails_cleanly_tiny() {
        the_region_table_is_finite_and_fails_cleanly::<MockTiny>();
    }

    fn frames_outside_the_direct_map_are_refused<A: Arch>() {
        // The failure the DirectMap exists to catch: memory the machine has and the
        // kernel cannot reach through this window.
        let mem = HostMemory::new(ARENA);
        let mut b = Bump::<A>::new(mem.direct_map());
        let far = expect(Frame::<A>::from_number(widen(ARENA / Frame::<A>::SIZE)));
        let range = expect(FrameRange::new(far, 1));
        assert_eq!(b.add_frames(range).err(), Some(AllocError::Unmanaged));
        assert_eq!(b.stats().regions, 0);
    }

    #[test]
    fn frames_outside_the_direct_map_are_refused_full() {
        frames_outside_the_direct_map_are_refused::<MockFull>();
    }

    #[test]
    fn frames_outside_the_direct_map_are_refused_tiny() {
        frames_outside_the_direct_map_are_refused::<MockTiny>();
    }

    // --- the point of the two mocks -----------------------------------------

    #[test]
    fn the_same_request_costs_different_frames_per_page_size() {
        // One request, two architectures. If this ever reports the same frame count
        // for both, something has stopped asking the architecture how big a page is.
        let mem = HostMemory::new(ARENA);
        let mut full_src = mem.frames::<MockFull>();
        let mut tiny_src = mem.frames::<MockTiny>();
        let mut full = Bump::<MockFull>::new(mem.direct_map());
        let mut tiny = Bump::<MockTiny>::new(mem.direct_map());

        expect(full.grow(&mut full_src, 32 * 1024));
        expect(tiny.grow(&mut tiny_src, 32 * 1024));
        assert_eq!(full.stats().frames_held, 8);
        assert_eq!(tiny.stats().frames_held, 128);
        assert_ne!(full.stats().frames_held, tiny.stats().frames_held);
        // Same memory either way, counted in different units.
        assert_eq!(full.stats().arena_bytes, tiny.stats().arena_bytes);
    }
}

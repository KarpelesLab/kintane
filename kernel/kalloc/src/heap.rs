//! The kernel heap: the thing callers actually hold.
//!
//! Three allocators and a routing rule. Small objects go to the [`Slab`], which reuses
//! memory properly. Larger ones go to the [`Buddy`] allocator when the heap has been
//! given a run of pages for it, which also reuses memory, and to the [`Bump`], which
//! does not, otherwise. The rule is [`slab::class_for`]: if a size class covers the
//! request's size *and* its alignment, the slab serves it.
//!
//! # Large blocks: buddy first, arena behind it
//!
//! A request past the largest size class, aligned to at most a page, is served from
//! the buddy allocator as a block of whole pages ([`Heap::attach_pages`]). If that
//! allocator has no block large enough, the request falls back to the arena, which can
//! grow from the frame source. So a buddy that is full, fragmented or absent means large
//! allocations stop being *reused*, not that they stop *succeeding*. An alignment larger
//! than a page always goes to the arena. A buddy block is only as aligned as its order,
//! measured from wherever the run happens to start, and doing better would mean
//! over-allocating to find an aligned sub-block, which the arena already does.
//!
//! # Fault injection
//!
//! The heap carries an [`Injector`], consulted at the entry and at each point where it
//! obtains memory. See [`crate::inject`]. In a build without injection every
//! consultation is a constant `false`.
//!
//! # Why the routing is by size and not by caller
//!
//! Because the caller does not know. A collection growing a buffer crosses the
//! boundary between "a slab object" and "a whole arena allocation" on some resize
//! nobody chose, and asking it to pick an allocator would mean asking it to know
//! which resize that was. Size classes are the standard answer and they are the
//! answer here.
//!
//! # Growth, and where frames come from
//!
//! [`Heap::try_alloc`] never touches physical memory: it serves from what the heap
//! already holds, or fails. [`Heap::try_alloc_in`] takes a [`FrameSource`] — in a
//! kernel image, `mm::FrameAllocator` behind its lock — and may take frames to
//! satisfy the request. Both exist because both are needed: an allocation in a
//! context that must not take the frame allocator's lock uses the first, and normal
//! process-context allocation uses the second.
//!
//! The lock order is in the signature. A caller holding the heap passes the frame
//! allocator *in*, so the heap never reaches for it, and "heap before frames" is
//! something the type system reminds you of rather than something documented in a
//! comment nobody reads.
//!
//! # When the slab cannot grow
//!
//! It has a fixed number of block descriptors ([`slab::MAX_BLOCKS`]). Past that, a
//! small allocation is served from the arena instead, at its class's size and
//! alignment. The heap degrades to the bootstrap allocator rather than failing, and
//! `dealloc` copes because it tries the slab first and falls back to the arena when
//! the slab does not recognise the pointer. That fallback is a real code path with a
//! test, not a hope.

// Re-enabled to forward `dealloc`, and to zero and poison buddy blocks. The buddy
// allocator deals in page indices and never touches memory, so turning one of its
// blocks into bytes happens here: two calls into `crate::poison`, each on a block the
// buddy has just handed out or has just accepted back.
#![allow(unsafe_code)]

use core::alloc::Layout;
use core::ptr::NonNull;

use hal::{Arch, KernAddr, PhysAddr};
use mm::directmap::DirectMap;
use mm::{AllocError, Frame, FrameRange};

use crate::buddy::{self, Buddy, BuddyStats};
use crate::bump::{Bump, BumpStats};
use crate::context::AllocContext;
use crate::frames::{FrameSource, NoFrames};
use crate::inject::{Injector, Site};
use crate::poison;
use crate::slab::{self, Slab, SlabStats};

/// A snapshot of the whole heap.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct HeapStats {
    /// The arena underneath, including the memory the slab's blocks occupy.
    pub bump: BumpStats,
    /// The size classes above it.
    pub slab: SlabStats,
    /// The buddy allocator for large blocks. All zero when no pages are attached.
    pub pages: BuddyStats,
    /// Bytes of physical memory the heap holds: the arena plus the attached pages.
    pub bytes_reserved: usize,
    /// Bytes the heap believes are live, slab objects rounded up to their class and
    /// buddy blocks rounded up to whole blocks.
    pub bytes_in_use: usize,
    /// Allocations served since construction.
    pub allocations: u64,
    /// Frees accepted since construction.
    pub frees: u64,
    /// Requests that returned an error. A kernel where this is non-zero and nothing
    /// went wrong is a kernel that is handling allocation failure, which is the
    /// point.
    pub failures: u64,
    /// Requests that asked for something not honoured yet — DMA addressability, a
    /// NUMA node, permission to sleep — and were served anyway.
    ///
    /// See [`crate::context`]. This number is how "the kernel has started relying on
    /// a constraint we do not implement" becomes visible before it becomes a bug.
    pub constrained: u64,
    /// Small allocations routed to the arena because the slab had no room for
    /// another block. Non-zero means [`slab::MAX_BLOCKS`] is too small for this
    /// workload, and that those allocations are not being reused.
    pub slab_overflow: u64,
    /// Large allocations routed to the arena because the buddy allocator could not
    /// serve them. Non-zero means those allocations are not being reused.
    pub pages_overflow: u64,
    /// Failures injected on purpose, across every injector this heap has had. An
    /// injected failure that reached the caller is also in `failures`. One the heap
    /// recovered from by falling back is not.
    pub injected: u64,
}

/// Why [`Heap::detach_pages`] refused.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Detach {
    /// No pages were attached.
    NotAttached,
    /// Blocks are still allocated. The run cannot go back to the frame allocator while
    /// anyone holds a pointer into it.
    InUse {
        /// Blocks still allocated.
        live_blocks: usize,
    },
}

/// The kernel heap.
///
/// Not internally synchronised; see the crate documentation. One of these exists per
/// kernel, behind whichever lock the configuration selected.
pub struct Heap<A: Arch> {
    map: DirectMap,
    bump: Bump<A>,
    slab: Slab,
    /// The large-block allocator, once a run of pages has been attached. Its store is
    /// `'static` because the heap lives as long as the kernel does, and so must the
    /// records of memory it has handed out.
    pages: Option<Buddy<'static, A>>,
    inject: Injector,
    /// Trips from injectors this heap has since replaced.
    injected_before: u64,
    allocations: u64,
    frees: u64,
    failures: u64,
    constrained: u64,
    slab_overflow: u64,
    pages_overflow: u64,
}

impl<A: Arch> Heap<A> {
    /// An empty heap reachable through `map`.
    ///
    /// Holds no memory: every allocation fails with [`AllocError::Exhausted`] until
    /// it is given some by [`Self::grow`], or until an allocation goes through
    /// [`Self::try_alloc_in`] with a frame source that has frames.
    ///
    /// `map` is the assumption this whole unit is built on; see
    /// [`mm::directmap`]. Today the bootstrap passes
    /// [`DirectMap::identity`](crate::DirectMap::identity).
    pub fn new(map: DirectMap) -> Self {
        Heap {
            map,
            bump: Bump::new(map),
            slab: Slab::new(),
            pages: None,
            inject: Injector::OFF,
            injected_before: 0,
            allocations: 0,
            frees: 0,
            failures: 0,
            constrained: 0,
            slab_overflow: 0,
            pages_overflow: 0,
        }
    }

    /// Give the heap a run of frames to serve large blocks from, reusably.
    ///
    /// `store` holds the buddy allocator's per-page records and must be at least
    /// [`buddy::store_bytes`] for the run. The heap keeps the frames until
    /// [`Self::detach_pages`] succeeds.
    ///
    /// # Errors
    /// [`AllocError::Unmanaged`] if any of the run is outside the direct map, since a
    /// block there could not be turned into a pointer. [`AllocError::Exhausted`] if a
    /// run is already attached, because the heap has one buddy allocator. Otherwise
    /// whatever [`Buddy::new`] reports. On an error nothing was attached.
    pub fn attach_pages(
        &mut self,
        run: FrameRange<A>,
        store: &'static mut [u8],
    ) -> Result<(), AllocError> {
        if self.pages.is_some() {
            return Err(AllocError::Exhausted);
        }
        let first = run.start().start();
        let last = first.checked_add(run.len_bytes()?.saturating_sub(1))?;
        self.map.to_virt(first)?;
        self.map.to_virt(last)?;
        self.pages = Some(Buddy::new(run, store)?);
        Ok(())
    }

    /// Take the attached run back, with its store, so the frames can be returned to the
    /// frame allocator.
    ///
    /// # Errors
    /// [`Detach::InUse`] while any block is allocated, and [`Detach::NotAttached`].
    /// On an error the heap is unchanged.
    pub fn detach_pages(&mut self) -> Result<(FrameRange<A>, &'static mut [u8]), Detach> {
        match self.pages.as_ref().map(|b| b.stats().live_blocks) {
            None => return Err(Detach::NotAttached),
            Some(n) if n > 0 => return Err(Detach::InUse { live_blocks: n }),
            Some(_) => {}
        }
        self.pages
            .take()
            .map(Buddy::into_parts)
            .ok_or(Detach::NotAttached)
    }

    /// Replace the fault-injection policy. The previous injector's trips stay counted
    /// in [`HeapStats::injected`].
    pub fn set_injector(&mut self, inject: Injector) {
        self.injected_before = self.injected_before.saturating_add(self.inject.trips());
        self.inject = inject;
    }

    /// The current fault-injection policy and its counts.
    pub fn injector(&self) -> &Injector {
        &self.inject
    }

    /// The window this heap's pointers live in.
    pub fn direct_map(&self) -> DirectMap {
        self.map
    }

    /// Serve an allocation from memory the heap already holds.
    ///
    /// The signature `docs/architecture.md` names. Never takes frames, so it is
    /// usable where the frame allocator's lock may not be taken.
    ///
    /// # Errors
    /// [`AllocError::EmptyRequest`] for a zero-sized layout,
    /// [`AllocError::Misaligned`] for an impossible one, [`AllocError::Overflow`] if
    /// it would leave the address space, and [`AllocError::Exhausted`] when the heap
    /// has no room. Never a panic: `docs/architecture.md` is explicit that allocation
    /// failure is a `Result` callers handle.
    pub fn try_alloc(
        &mut self,
        layout: Layout,
        ctx: AllocContext,
    ) -> Result<NonNull<u8>, AllocError> {
        self.try_alloc_in(layout, ctx, &mut NoFrames)
    }

    /// Serve an allocation, taking frames from `src` if the heap has no room.
    ///
    /// # Errors
    /// As [`Self::try_alloc`], plus whatever `src` reports — notably
    /// [`AllocError::Fragmented`], which tells a caller that smaller requests might
    /// still succeed where [`AllocError::Exhausted`] tells it they will not.
    pub fn try_alloc_in(
        &mut self,
        layout: Layout,
        ctx: AllocContext,
        src: &mut impl FrameSource<A>,
    ) -> Result<NonNull<u8>, AllocError> {
        // Before anything is touched, so a bad layout costs no state. Counted by
        // hand rather than with `?`, because a refusal the heap made up front is
        // still a refusal, and a `failures` count that silently omitted the layout
        // errors would be the one number nobody could reconcile.
        if let Err(e) = crate::validate(layout) {
            self.failures = self.failures.saturating_add(1);
            return Err(e);
        }
        if ctx.is_best_effort() {
            self.constrained = self.constrained.saturating_add(1);
        }
        // Before any allocator is asked, so an injected refusal costs no state, as a
        // real refusal made up front would not.
        if self.inject.trip(Site::ENTRY) {
            self.failures = self.failures.saturating_add(1);
            return Err(AllocError::Exhausted);
        }

        let result = match slab::class_for(layout) {
            Some(class) => self.alloc_small(class, ctx, src),
            None => self.alloc_large(layout, ctx, src),
        };
        match result {
            Ok(p) => {
                self.allocations = self.allocations.saturating_add(1);
                Ok(p)
            }
            Err(e) => {
                self.failures = self.failures.saturating_add(1);
                Err(e)
            }
        }
    }

    /// Give a block back.
    ///
    /// The slab is asked first. If it does not recognise the pointer it says
    /// [`AllocError::Unmanaged`] and the arena is asked instead — which is how a
    /// small object that was served from the arena, because the slab was full, finds
    /// its way home. Any other answer from the slab is final: an object it owns and
    /// refuses to free is a bug in the caller, not a reason to try somewhere else.
    ///
    /// # Errors
    /// [`AllocError::Unmanaged`] for a pointer neither allocator recognises,
    /// [`AllocError::Misaligned`] for an interior pointer or a layout that does not
    /// match the allocation, and [`AllocError::NotAllocated`] for a double free the
    /// slab can prove.
    ///
    /// # Safety
    /// `ptr` must have come from this heap, allocated with a layout of the same size
    /// class and alignment as `layout`, and must not have been freed since. See the
    /// crate documentation for why this cannot be made safe.
    pub unsafe fn dealloc(
        &mut self,
        ptr: NonNull<u8>,
        layout: Layout,
        ctx: AllocContext,
    ) -> Result<(), AllocError> {
        crate::validate(layout)?;

        // The layout the arena would have used. A small object in the arena was put
        // there by `alloc_small`'s fallback, at its class's size and alignment rather than
        // the caller's. Freeing it with the caller's layout under-counted the arena by the
        // difference on every such free, and missed its last-in-first-out reclaim. The
        // fault-injection sweep found that; the overflow test before it used 16-byte
        // objects, for which the class and the size are the same number.
        let mut arena_layout = layout;

        if let Some(class) = slab::class_for(layout) {
            // SAFETY: forwarded unchanged. The caller's obligation — this pointer,
            // from this heap, with this layout, not already freed — is exactly what
            // `Slab::dealloc` asks for, and the class is derived from that layout.
            match unsafe { self.slab.dealloc(ptr, class, ctx) } {
                Ok(()) => {
                    self.frees = self.frees.saturating_add(1);
                    return Ok(());
                }
                // Not one of the slab's objects. It may still be the arena's.
                Err(AllocError::Unmanaged) => {
                    arena_layout =
                        Layout::from_size_align(class, class).map_err(|_| AllocError::Overflow)?;
                }
                Err(e) => return Err(e),
            }
        } else if let Some((frame, phys)) = self.page_of(ptr) {
            // SAFETY: forwarded unchanged; the caller's contract is `free_pages`'s.
            unsafe { self.free_pages(ptr, frame, phys, layout) }?;
            self.frees = self.frees.saturating_add(1);
            return Ok(());
        } else if self.slab.owns(ptr) {
            // A pointer inside a slab block, freed with a layout too large for any
            // size class: the caller's layout is wrong. The arena owns that block's
            // memory and would accept the free and poison it, destroying whatever
            // live objects share the block. Refusing is the only safe answer.
            return Err(AllocError::Misaligned);
        }

        // SAFETY: forwarded, as above. For a small object the layout is the one the
        // arena allocated it with, which is what `Bump::dealloc` requires.
        let r = unsafe { self.bump.dealloc(ptr, arena_layout, ctx) };
        if r.is_ok() {
            self.frees = self.frees.saturating_add(1);
        }
        r
    }

    /// Take at least `min_bytes` more memory from `src`.
    ///
    /// What a bootstrap calls to size the heap before anything allocates, which is
    /// better than discovering the heap's first growth from inside whatever code
    /// happened to allocate first.
    ///
    /// # Errors
    /// As [`Bump::grow`].
    pub fn grow(
        &mut self,
        src: &mut impl FrameSource<A>,
        min_bytes: usize,
    ) -> Result<usize, AllocError> {
        self.bump
            .grow(&mut Injected::new(src, &mut self.inject), min_bytes)
    }

    /// Where a pointer from this heap is in physical memory.
    ///
    /// What a driver setting up a DMA descriptor needs. The slab is asked first for
    /// the same reason as in [`Self::dealloc`].
    ///
    /// # Errors
    /// [`AllocError::Unmanaged`] if the pointer did not come from this heap.
    pub fn phys_of(&self, ptr: NonNull<u8>) -> Result<PhysAddr, AllocError> {
        match self.slab.phys_of(ptr) {
            Ok(p) => Ok(p),
            Err(AllocError::Unmanaged) => match self.page_of(ptr) {
                Some((_, phys)) => Ok(phys),
                None => self.bump.phys_of(ptr),
            },
            Err(e) => Err(e),
        }
    }

    /// Current accounting.
    pub fn stats(&self) -> HeapStats {
        let bump = self.bump.stats();
        let slab = self.slab.stats();
        let pages = self.pages.as_ref().map(Buddy::stats).unwrap_or_default();
        let page_bytes = |n: usize| n.saturating_mul(pages.page_size);
        HeapStats {
            bytes_reserved: bump.arena_bytes.saturating_add(page_bytes(pages.pages)),
            // The arena's `in_use` counts each slab block as one live allocation, so
            // adding the two would count the blocks twice. What is actually live is
            // the arena minus the blocks, plus the objects inside them, plus the
            // allocated buddy blocks.
            bytes_in_use: bump
                .in_use
                .saturating_sub(slab.bytes_reserved)
                .saturating_add(slab.bytes_in_use)
                .saturating_add(page_bytes(pages.pages.saturating_sub(pages.free_pages))),
            allocations: self.allocations,
            frees: self.frees,
            failures: self.failures,
            constrained: self.constrained,
            slab_overflow: self.slab_overflow,
            pages_overflow: self.pages_overflow,
            injected: self.injected_before.saturating_add(self.inject.trips()),
            bump,
            slab,
            pages,
        }
    }

    // --- internals ----------------------------------------------------------

    /// Serve an object of `class`, adding a block to the slab if it needs one.
    fn alloc_small(
        &mut self,
        class: usize,
        ctx: AllocContext,
        src: &mut impl FrameSource<A>,
    ) -> Result<NonNull<u8>, AllocError> {
        match self.slab.try_take(class, self.map, ctx) {
            Ok(p) => return Ok(p),
            // Every block of this class is full; a new one might fix that.
            Err(AllocError::Exhausted) => {}
            Err(e) => return Err(e),
        }

        if self.slab.has_room() {
            let block = slab::block_layout(class)?;
            // A block is raw storage: zeroing it here would zero objects the caller
            // never asked to be zeroed, and the objects that did ask are zeroed
            // individually as they are handed out.
            let got = if self.inject.trip(Site::SLAB_BLOCK) {
                Err(AllocError::Exhausted)
            } else {
                let mut src = Injected::new(src, &mut self.inject);
                self.bump
                    .try_alloc_in(block, AllocContext::ATOMIC, &mut src)
            };
            if let Ok(ptr) = got {
                self.slab
                    .add_block(class, KernAddr::new(ptr.addr().get()), self.map)?;
                return self.slab.try_take(class, self.map, ctx);
            }
            // The arena could not spare a whole block. It may still be able to spare
            // one object, so fall through rather than failing here.
        } else {
            self.slab_overflow = self.slab_overflow.saturating_add(1);
        }

        // Degrade to the arena, at the class's size and alignment so the block is
        // indistinguishable from a slab object to everything except the slab.
        let direct = Layout::from_size_align(class, class).map_err(|_| AllocError::Overflow)?;
        self.bump
            .try_alloc_in(direct, ctx, &mut Injected::new(src, &mut self.inject))
    }

    /// Serve a request too large for any size class: a buddy block if pages are
    /// attached and one fits, the arena otherwise.
    fn alloc_large(
        &mut self,
        layout: Layout,
        ctx: AllocContext,
        src: &mut impl FrameSource<A>,
    ) -> Result<NonNull<u8>, AllocError> {
        if layout.align() <= A::PAGE_SIZE {
            if let Some(pages) = self.pages.as_mut() {
                let got = if self.inject.trip(Site::PAGES) {
                    Err(AllocError::Exhausted)
                } else {
                    pages.alloc_pages(layout.size().div_ceil(A::PAGE_SIZE))
                };
                match got {
                    Ok(range) => return self.hand_out_pages(range, layout, ctx),
                    // Full, fragmented, or larger than the largest order. The arena may
                    // still manage it.
                    Err(AllocError::Exhausted | AllocError::Fragmented) => {
                        self.pages_overflow = self.pages_overflow.saturating_add(1);
                    }
                    Err(e) => return Err(e),
                }
            }
        }
        self.bump
            .try_alloc_in(layout, ctx, &mut Injected::new(src, &mut self.inject))
    }

    /// Turn a block the buddy allocator has just handed out into a pointer.
    fn hand_out_pages(
        &mut self,
        range: FrameRange<A>,
        layout: Layout,
        ctx: AllocContext,
    ) -> Result<NonNull<u8>, AllocError> {
        let ptr = match self.map.ptr_to_phys(range.start().start()) {
            Ok(p) => p,
            Err(e) => {
                // `attach_pages` checked the whole run against the map, so this cannot
                // happen. It is handled anyway: a block that cannot be reached goes back
                // to the buddy, rather than staying allocated with no pointer to free.
                if let Some(pages) = self.pages.as_mut() {
                    let _ = pages.free(range);
                }
                return Err(e);
            }
        };
        if ctx.wants_zero() {
            // SAFETY: the buddy allocator has just marked this block allocated and it has
            // not been returned to anyone, so nothing else references it. It lies inside
            // the run `attach_pages` checked against the direct map, and the request's
            // size is no larger than the block.
            unsafe { poison::fill_zero(ptr, layout.size()) };
        }
        Ok(ptr)
    }

    /// The frame containing `ptr` and the pointer's physical address, if the pointer is
    /// inside the attached run.
    fn page_of(&self, ptr: NonNull<u8>) -> Option<(Frame<A>, PhysAddr)> {
        let pages = self.pages.as_ref()?;
        let phys = self.map.to_phys(KernAddr::new(ptr.addr().get())).ok()?;
        let frame = Frame::<A>::containing(phys);
        pages.owns(frame).then_some((frame, phys))
    }

    /// Give a buddy block back, then poison it.
    ///
    /// # Safety
    /// As [`Self::dealloc`]: `ptr` is a live block from the attached pages, freed with
    /// the layout it was allocated with.
    unsafe fn free_pages(
        &mut self,
        ptr: NonNull<u8>,
        frame: Frame<A>,
        phys: PhysAddr,
        layout: Layout,
    ) -> Result<(), AllocError> {
        // A block starts on a page boundary, so anything else is an interior pointer.
        // A wrong size is a wrong order, which `Buddy::free` refuses. Both are refused
        // before anything changes.
        if phys != frame.start() {
            return Err(AllocError::Misaligned);
        }
        let order =
            buddy::order_for(layout.size().div_ceil(A::PAGE_SIZE)).ok_or(AllocError::Misaligned)?;
        let range = FrameRange::new(frame, 1usize << order)?;
        self.pages
            .as_mut()
            .ok_or(AllocError::Unmanaged)?
            .free(range)?;
        // SAFETY: the buddy allocator accepted the free, so this was an allocated block of
        // exactly `range`, and by the caller's contract it is now dead. The run is inside
        // the direct map, so the pointer is valid for the whole block. Poisoned after the
        // free rather than before, so a refused free poisons nothing.
        unsafe { poison::fill_freed(ptr, range.count().saturating_mul(A::PAGE_SIZE)) };
        Ok(())
    }
}

/// A frame source that consults the heap's injector before every take.
struct Injected<'a, S> {
    src: &'a mut S,
    inject: &'a mut Injector,
}

impl<'a, S> Injected<'a, S> {
    fn new(src: &'a mut S, inject: &'a mut Injector) -> Self {
        Injected { src, inject }
    }
}

impl<A: Arch, S: FrameSource<A>> FrameSource<A> for Injected<'_, S> {
    fn take(&mut self, frames: usize) -> Result<FrameRange<A>, AllocError> {
        if self.inject.trip(Site::FRAMES) {
            return Err(AllocError::Exhausted);
        }
        self.src.take(frames)
    }
}

#[cfg(test)]
mod tests {
    use hal::mock::{MockFull, MockTiny};

    use super::*;
    use crate::context::{AllocFlags, NumaNode};
    use crate::hostmem::{HostFrames, HostMemory};
    use crate::poison;

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

    struct Fixture<A: Arch> {
        mem: HostMemory,
        src: HostFrames<A>,
        heap: Heap<A>,
    }

    impl<A: Arch> Fixture<A> {
        fn new() -> Self {
            let mem = HostMemory::new(ARENA);
            let heap = Heap::<A>::new(mem.direct_map());
            let src = mem.frames::<A>();
            Fixture { mem, src, heap }
        }

        fn alloc(&mut self, size: usize, align: usize) -> Result<NonNull<u8>, AllocError> {
            self.heap
                .try_alloc_in(layout(size, align), AllocContext::ATOMIC, &mut self.src)
        }

        fn free(&mut self, p: NonNull<u8>, size: usize, align: usize) -> Result<(), AllocError> {
            #[allow(unsafe_code)]
            // SAFETY: every call in these tests passes a pointer this heap returned,
            // with the layout it was allocated with, exactly once.
            unsafe {
                self.heap
                    .dealloc(p, layout(size, align), AllocContext::ATOMIC)
            }
        }
    }

    // --- routing ------------------------------------------------------------

    fn small_objects_go_to_the_slab_and_large_ones_to_the_arena<A: Arch>() {
        let mut f = Fixture::<A>::new();

        let small = expect(f.alloc(24, 8));
        assert_eq!(f.heap.stats().slab.objects_in_use, 1);
        assert_eq!(
            f.heap
                .stats()
                .slab
                .classes
                .iter()
                .find(|c| c.size == 32)
                .map(|c| c.in_use),
            Some(1),
            "24 bytes belongs to the 32 class"
        );

        let large = expect(f.alloc(4000, 8));
        assert_eq!(
            f.heap.stats().slab.objects_in_use,
            1,
            "4000 bytes is past the largest class and must not touch the slab"
        );
        assert_ne!(addr_of(small), addr_of(large));

        expect(f.free(small, 24, 8));
        expect(f.free(large, 4000, 8));
        assert_eq!(f.heap.stats().slab.objects_in_use, 0);
        assert_eq!(f.heap.stats().frees, 2);
    }

    #[test]
    fn small_objects_go_to_the_slab_and_large_ones_to_the_arena_full() {
        small_objects_go_to_the_slab_and_large_ones_to_the_arena::<MockFull>();
    }

    #[test]
    fn small_objects_go_to_the_slab_and_large_ones_to_the_arena_tiny() {
        small_objects_go_to_the_slab_and_large_ones_to_the_arena::<MockTiny>();
    }

    // --- alignment ----------------------------------------------------------

    fn alignment_is_honoured_across_both_allocators<A: Arch>() {
        let mut f = Fixture::<A>::new();
        // Alignments on both sides of MockTiny's 256-byte page, and sizes on both
        // sides of the largest size class, so every route is exercised.
        for align in [1usize, 8, 64, 256, 1024, 4096] {
            for size in [1usize, 31, 100, 1024, 3000] {
                let p = match f.alloc(size, align) {
                    Ok(p) => p,
                    // Running out is a legitimate answer for the larger combinations
                    // on the smaller arena; being misaligned is not.
                    Err(AllocError::Exhausted) => continue,
                    Err(e) => panic!("size {size} align {align}: unexpected {e:?}"),
                };
                assert_eq!(
                    addr_of(p) % align,
                    0,
                    "size {size} align {align} gave {:#x}",
                    addr_of(p)
                );
                expect(f.free(p, size, align));
            }
        }
    }

    #[test]
    fn alignment_is_honoured_across_both_allocators_full() {
        alignment_is_honoured_across_both_allocators::<MockFull>();
    }

    #[test]
    fn alignment_is_honoured_across_both_allocators_tiny() {
        alignment_is_honoured_across_both_allocators::<MockTiny>();
    }

    // --- bad layouts --------------------------------------------------------

    fn a_zero_sized_or_absurd_layout_is_rejected<A: Arch>() {
        let mut f = Fixture::<A>::new();

        assert_eq!(f.alloc(0, 1).err(), Some(AllocError::EmptyRequest));
        assert_eq!(f.alloc(0, 4096).err(), Some(AllocError::EmptyRequest));
        // Legal as a `Layout`, far larger than any machine. The heap must report
        // exhaustion rather than wrapping an address.
        assert_eq!(f.alloc(usize::MAX / 4, 1).err(), Some(AllocError::Exhausted));
        // A legal but preposterous alignment.
        assert_eq!(f.alloc(8, 1 << 24).err(), Some(AllocError::Exhausted));

        let s = f.heap.stats();
        assert_eq!(s.allocations, 0);
        assert_eq!(s.failures, 4, "every refusal is counted");
        assert_eq!(s.bytes_in_use, 0);

        // And a rejected free of a pointer from nowhere.
        let other = HostMemory::new(4096);
        let foreign = expect(
            other
                .direct_map()
                .ptr_at(expect(other.direct_map().to_virt(PhysAddr::new(256)))),
        );
        assert_eq!(f.free(foreign, 16, 8).err(), Some(AllocError::Unmanaged));
        assert_eq!(
            other.byte_at(foreign.addr().get()),
            Some(0x5A),
            "a rejected free must not have poisoned anything"
        );
    }

    #[test]
    fn a_zero_sized_or_absurd_layout_is_rejected_full() {
        a_zero_sized_or_absurd_layout_is_rejected::<MockFull>();
    }

    #[test]
    fn a_zero_sized_or_absurd_layout_is_rejected_tiny() {
        a_zero_sized_or_absurd_layout_is_rejected::<MockTiny>();
    }

    // --- exhaustion ---------------------------------------------------------

    fn exhaustion_is_an_error_and_stays_one<A: Arch>() {
        let mut f = Fixture::<A>::new();
        // A deliberately small machine: four frames and nothing more.
        f.src.limit_to(4);

        let mut held: Vec<NonNull<u8>> = Vec::new();
        loop {
            match f.alloc(128, 8) {
                Ok(p) => held.push(p),
                Err(AllocError::Exhausted) => break,
                Err(e) => panic!("unexpected {e:?}"),
            }
            assert!(held.len() < 100_000, "the heap must run out");
        }
        assert!(!held.is_empty(), "it must serve something first");

        // Repeatedly, without panicking, and for a large request too.
        for _ in 0..5 {
            assert_eq!(f.alloc(128, 8).err(), Some(AllocError::Exhausted));
            assert_eq!(f.alloc(4000, 8).err(), Some(AllocError::Exhausted));
        }

        // Freeing one makes exactly one more available: the heap recovers rather
        // than staying wedged.
        let p = match held.pop() {
            Some(p) => p,
            None => panic!("held at least one"),
        };
        expect(f.free(p, 128, 8));
        let again = expect(f.alloc(128, 8));
        assert_eq!(addr_of(again), addr_of(p));
    }

    #[test]
    fn exhaustion_is_an_error_and_stays_one_full() {
        exhaustion_is_an_error_and_stays_one::<MockFull>();
    }

    #[test]
    fn exhaustion_is_an_error_and_stays_one_tiny() {
        exhaustion_is_an_error_and_stays_one::<MockTiny>();
    }

    // --- reuse and poisoning ------------------------------------------------

    fn free_and_reuse_returns_the_same_memory_poisoned_in_between<A: Arch>() {
        let mut f = Fixture::<A>::new();
        let p = expect(f.alloc(64, 16));
        #[allow(unsafe_code)]
        // SAFETY: `p` is a live 64-byte allocation from this heap.
        unsafe {
            p.as_ptr().write_bytes(0x77, 64);
        }
        expect(f.free(p, 64, 16));

        let bytes = match f.mem.bytes_at(addr_of(p), 64) {
            Some(b) => b,
            None => panic!("the block must be inside the backing buffer"),
        };
        if poison::ENABLED {
            assert!(
                bytes.iter().all(|b| *b == poison::FREED),
                "DEBUG_BUILD must poison freed memory: {bytes:?}"
            );
        } else {
            assert_eq!(bytes, &[0x77u8; 64][..], "a release build leaves it alone");
        }

        let again = expect(f.alloc(64, 16));
        assert_eq!(addr_of(again), addr_of(p), "freed memory must come back");
    }

    #[test]
    fn free_and_reuse_returns_the_same_memory_poisoned_in_between_full() {
        free_and_reuse_returns_the_same_memory_poisoned_in_between::<MockFull>();
    }

    #[test]
    fn free_and_reuse_returns_the_same_memory_poisoned_in_between_tiny() {
        free_and_reuse_returns_the_same_memory_poisoned_in_between::<MockTiny>();
    }

    fn a_churning_workload_does_not_consume_the_heap<A: Arch>() {
        // The property the whole slab exists for.
        let mut f = Fixture::<A>::new();
        let mut live: Vec<NonNull<u8>> = Vec::new();
        for i in 0..2000usize {
            let p = expect(f.alloc(48, 8));
            live.push(p);
            if i % 3 == 0 {
                if let Some(q) = live.pop() {
                    expect(f.free(q, 48, 8));
                }
            }
            if live.len() > 32 {
                if let Some(q) = live.first().copied() {
                    live.remove(0);
                    expect(f.free(q, 48, 8));
                }
            }
        }
        let s = f.heap.stats();
        assert_eq!(s.allocations, 2000);
        assert!(
            s.bytes_reserved <= ARENA,
            "reserved {} bytes for a workload with at most 33 live objects",
            s.bytes_reserved
        );
        assert!(s.slab.blocks <= 4, "{} blocks is too many", s.slab.blocks);
        assert_eq!(s.slab.objects_in_use, live.len());
    }

    #[test]
    fn a_churning_workload_does_not_consume_the_heap_full() {
        a_churning_workload_does_not_consume_the_heap::<MockFull>();
    }

    #[test]
    fn a_churning_workload_does_not_consume_the_heap_tiny() {
        a_churning_workload_does_not_consume_the_heap::<MockTiny>();
    }

    fn a_double_free_is_reported_rather_than_corrupting<A: Arch>() {
        let mut f = Fixture::<A>::new();
        let p = expect(f.alloc(64, 8));
        expect(f.free(p, 64, 8));
        assert_eq!(
            f.free(p, 64, 8).err(),
            Some(AllocError::NotAllocated),
            "the slab's bitmap can prove this one"
        );
        assert_eq!(f.heap.stats().slab.double_frees, 1);
        assert_eq!(f.heap.stats().frees, 1);
    }

    fn a_slab_object_freed_with_the_wrong_layout_is_refused<A: Arch>() {
        // The dangerous mistake: a layout too large for any size class routes to the
        // arena, which owns the slab's blocks and would poison a live object's
        // neighbours. The heap has to notice.
        let mut f = Fixture::<A>::new();
        let small = expect(f.alloc(32, 8));
        let neighbour = expect(f.alloc(32, 8));
        #[allow(unsafe_code)]
        // SAFETY: a live 32-byte allocation from this heap.
        unsafe {
            neighbour.as_ptr().write_bytes(0x5E, 32);
        }

        assert_eq!(
            f.free(small, 4000, 8).err(),
            Some(AllocError::Misaligned),
            "a slab object may not be freed as though it came from the arena"
        );
        assert_eq!(
            f.mem.bytes_at(addr_of(neighbour), 32),
            Some(&[0x5Eu8; 32][..]),
            "and nothing in its block may have been poisoned"
        );
        assert_eq!(f.heap.stats().slab.objects_in_use, 2);
        // With the right layout it works.
        expect(f.free(small, 32, 8));
    }

    #[test]
    fn a_slab_object_freed_with_the_wrong_layout_is_refused_full() {
        a_slab_object_freed_with_the_wrong_layout_is_refused::<MockFull>();
    }

    #[test]
    fn a_slab_object_freed_with_the_wrong_layout_is_refused_tiny() {
        a_slab_object_freed_with_the_wrong_layout_is_refused::<MockTiny>();
    }

    #[test]
    fn a_double_free_is_reported_rather_than_corrupting_full() {
        a_double_free_is_reported_rather_than_corrupting::<MockFull>();
    }

    #[test]
    fn a_double_free_is_reported_rather_than_corrupting_tiny() {
        a_double_free_is_reported_rather_than_corrupting::<MockTiny>();
    }

    // --- context ------------------------------------------------------------

    fn zeroing_is_honoured_and_the_rest_is_counted<A: Arch>() {
        let mut f = Fixture::<A>::new();

        let ctx = AllocContext::KERNEL_ZEROED;
        let p = expect(f.heap.try_alloc_in(layout(96, 8), ctx, &mut f.src));
        assert_eq!(f.mem.bytes_at(addr_of(p), 96), Some(&[0u8; 96][..]));

        // MAY_SLEEP is advisory, so that request is best-effort and counted.
        assert_eq!(f.heap.stats().constrained, 1);

        let dma = AllocContext::ATOMIC
            .with(AllocFlags::DMA32)
            .on_node(NumaNode::new(1));
        let q = expect(f.heap.try_alloc_in(layout(96, 8), dma, &mut f.src));
        assert_eq!(
            f.heap.stats().constrained,
            2,
            "a DMA or NUMA request must be visible, since neither is honoured yet"
        );
        // Served all the same: refusing would mean no driver could be written until
        // the zone allocator exists.
        assert_ne!(addr_of(q), addr_of(p));

        // And a plain request is not counted.
        let _ = expect(f.alloc(96, 8));
        assert_eq!(f.heap.stats().constrained, 2);
    }

    #[test]
    fn zeroing_is_honoured_and_the_rest_is_counted_full() {
        zeroing_is_honoured_and_the_rest_is_counted::<MockFull>();
    }

    #[test]
    fn zeroing_is_honoured_and_the_rest_is_counted_tiny() {
        zeroing_is_honoured_and_the_rest_is_counted::<MockTiny>();
    }

    // --- growth policy ------------------------------------------------------

    fn try_alloc_never_takes_frames<A: Arch>() {
        // The contract that makes it usable where the frame allocator's lock may not
        // be taken.
        let mut f = Fixture::<A>::new();
        assert_eq!(
            f.heap.try_alloc(layout(16, 8), AllocContext::ATOMIC).err(),
            Some(AllocError::Exhausted)
        );
        assert_eq!(f.src.handed_out(), 0, "it must not have reached for frames");

        // Sized up front, it then serves without touching the frame source again.
        expect(f.heap.grow(&mut f.src, 8192));
        let taken = f.src.handed_out();
        assert!(taken > 0);
        for _ in 0..16 {
            assert!(
                f.heap
                    .try_alloc(layout(16, 8), AllocContext::ATOMIC)
                    .is_ok()
            );
        }
        assert_eq!(f.src.handed_out(), taken);
    }

    #[test]
    fn try_alloc_never_takes_frames_full() {
        try_alloc_never_takes_frames::<MockFull>();
    }

    #[test]
    fn try_alloc_never_takes_frames_tiny() {
        try_alloc_never_takes_frames::<MockTiny>();
    }

    fn the_slab_overflows_into_the_arena_and_frees_still_work<A: Arch>() {
        // The degradation path: past MAX_BLOCKS descriptors, small objects come from
        // the arena, and `dealloc` has to find them there.
        let mut f = Fixture::<A>::new();
        let mut held: Vec<NonNull<u8>> = Vec::new();
        // 16-byte objects, 64 per block, so filling the descriptor table needs
        // MAX_BLOCKS * 64 of them.
        let want = slab::MAX_BLOCKS.saturating_mul(slab::objects_per_block(16));
        for _ in 0..want {
            match f.alloc(16, 8) {
                Ok(p) => held.push(p),
                Err(AllocError::Exhausted) => break,
                Err(e) => panic!("unexpected {e:?}"),
            }
        }
        // One more forces either a new block or the fallback.
        let extra = f.alloc(16, 8);

        if f.heap.stats().slab.blocks == slab::MAX_BLOCKS {
            let p = match extra {
                Ok(p) => p,
                Err(e) => panic!("the arena must serve what the slab cannot: {e:?}"),
            };
            assert!(f.heap.stats().slab_overflow > 0);
            // And it can be freed, through the fallback in `dealloc`.
            expect(f.free(p, 16, 8));
        }

        // Everything that was handed out can be given back, wherever it came from.
        for p in held {
            expect(f.free(p, 16, 8));
        }
        assert_eq!(f.heap.stats().slab.objects_in_use, 0);
    }

    #[test]
    fn the_slab_overflows_into_the_arena_and_frees_still_work_full() {
        the_slab_overflows_into_the_arena_and_frees_still_work::<MockFull>();
    }

    #[test]
    fn the_slab_overflows_into_the_arena_and_frees_still_work_tiny() {
        the_slab_overflows_into_the_arena_and_frees_still_work::<MockTiny>();
    }

    // --- physical addresses -------------------------------------------------

    fn a_pointer_can_be_turned_back_into_a_physical_address<A: Arch>() {
        let mut f = Fixture::<A>::new();
        let small = expect(f.alloc(32, 8));
        let large = expect(f.alloc(2048, 8));
        for p in [small, large] {
            let phys = expect(f.heap.phys_of(p));
            assert_eq!(
                expect(f.heap.direct_map().to_virt(phys)).raw(),
                addr_of(p),
                "the physical address must round-trip back to the pointer"
            );
        }
        let other = HostMemory::new(4096);
        let foreign = expect(
            other
                .direct_map()
                .ptr_at(expect(other.direct_map().to_virt(PhysAddr::new(64)))),
        );
        assert_eq!(f.heap.phys_of(foreign).err(), Some(AllocError::Unmanaged));
    }

    #[test]
    fn a_pointer_can_be_turned_back_into_a_physical_address_full() {
        a_pointer_can_be_turned_back_into_a_physical_address::<MockFull>();
    }

    #[test]
    fn a_pointer_can_be_turned_back_into_a_physical_address_tiny() {
        a_pointer_can_be_turned_back_into_a_physical_address::<MockTiny>();
    }

    // --- the point of the two mocks -----------------------------------------

    #[test]
    fn the_same_workload_costs_different_frames_per_page_size() {
        let full_mem = HostMemory::new(ARENA);
        let tiny_mem = HostMemory::new(ARENA);
        let mut full_src = full_mem.frames::<MockFull>();
        let mut tiny_src = tiny_mem.frames::<MockTiny>();
        let mut full = Heap::<MockFull>::new(full_mem.direct_map());
        let mut tiny = Heap::<MockTiny>::new(tiny_mem.direct_map());

        for _ in 0..50 {
            assert!(
                full.try_alloc_in(layout(40, 8), AllocContext::ATOMIC, &mut full_src)
                    .is_ok()
            );
            assert!(
                tiny.try_alloc_in(layout(40, 8), AllocContext::ATOMIC, &mut tiny_src)
                    .is_ok()
            );
        }
        // The same objects, the same classes, the same bytes live...
        assert_eq!(full.stats().slab.objects_in_use, tiny.stats().slab.objects_in_use);
        assert_eq!(full.stats().bytes_in_use, tiny.stats().bytes_in_use);
        // ...and a different number of frames underneath, because a page is a
        // different size. If this ever stops holding, something has hardcoded 4096.
        assert_ne!(full.stats().bump.frames_held, tiny.stats().bump.frames_held);
        // Each arena is a whole number of its own frames, which is the only thing
        // the page size is allowed to decide here.
        for (s, page) in [
            (full.stats(), MockFull::PAGE_SIZE),
            (tiny.stats(), MockTiny::PAGE_SIZE),
        ] {
            assert_eq!(s.bytes_reserved, s.bump.frames_held * page);
            assert!(s.bytes_reserved >= s.bytes_in_use);
        }
    }

    // --- large blocks through the buddy allocator ---------------------------

    /// A heap over a larger buffer, with `pages` frames of it attached as buddy pages.
    fn with_pages<A: Arch>(pages: usize) -> Fixture<A> {
        let mem = HostMemory::new(1024 * 1024);
        let mut heap = Heap::<A>::new(mem.direct_map());
        let mut src = mem.frames::<A>();
        let run = expect(FrameSource::<A>::take(&mut src, pages));
        // Leaked: the heap wants a store that lives as long as it does, and a test's
        // few kilobytes are not worth a lifetime parameter on every heap.
        let store = Box::leak(vec![0u8; expect(buddy::store_bytes(pages))].into_boxed_slice());
        expect(heap.attach_pages(run, store));
        Fixture { mem, src, heap }
    }

    /// A size past the largest slab class that needs `pages` pages of `A`.
    fn large<A: Arch>(pages: usize) -> usize {
        let min = slab::CLASS_SIZES[slab::CLASS_COUNT - 1] + 1;
        (A::PAGE_SIZE * pages).max(min)
    }

    fn large_blocks_are_reused_not_consumed<A: Arch>() {
        let mut f = with_pages::<A>(64);
        let size = large::<A>(3);
        let first = expect(f.alloc(size, 8));
        assert_eq!(addr_of(first) % A::PAGE_SIZE, 0, "a buddy block starts on a page");
        assert_eq!(f.heap.stats().pages.live_blocks, 1);
        expect(f.free(first, size, 8));

        let arena_before = f.heap.stats().bump.arena_bytes;
        for _ in 0..500 {
            let p = expect(f.alloc(size, 8));
            assert_eq!(addr_of(p), addr_of(first), "the same block comes back every time");
            expect(f.free(p, size, 8));
        }
        let s = f.heap.stats();
        assert_eq!(s.bump.arena_bytes, arena_before, "the arena must not have grown at all");
        assert_eq!(s.pages.free_pages, 64);
        assert_eq!(s.pages_overflow, 0);
        assert_eq!(s.bytes_in_use, 0);
    }

    #[test]
    fn large_blocks_are_reused_not_consumed_full() {
        large_blocks_are_reused_not_consumed::<MockFull>();
    }

    #[test]
    fn large_blocks_are_reused_not_consumed_tiny() {
        large_blocks_are_reused_not_consumed::<MockTiny>();
    }

    fn a_buddy_block_is_zeroed_poisoned_and_checked_on_free<A: Arch>() {
        let mut f = with_pages::<A>(16);
        let size = large::<A>(2);
        let p = expect(f.heap.try_alloc_in(
            layout(size, 8),
            AllocContext::KERNEL_ZEROED,
            &mut f.src,
        ));
        assert!(
            f.mem
                .bytes_at(addr_of(p), size)
                .is_some_and(|b| b.iter().all(|x| *x == 0)),
            "ZERO must be honoured on the buddy route too"
        );
        let phys = expect(f.heap.phys_of(p));
        assert_eq!(expect(f.heap.direct_map().to_virt(phys)).raw(), addr_of(p));

        // An interior pointer, a wrong size, and then the real free and a double free.
        let interior = expect(
            f.heap
                .direct_map()
                .ptr_at(KernAddr::new(addr_of(p) + A::PAGE_SIZE)),
        );
        assert_eq!(f.free(interior, size, 8).err(), Some(AllocError::Misaligned));
        assert_eq!(
            f.free(p, large::<A>(9), 8).err(),
            Some(AllocError::Misaligned),
            "a layout of a different order is not this block"
        );
        assert_eq!(f.heap.stats().pages.live_blocks, 1, "refused frees change nothing");
        expect(f.free(p, size, 8));
        assert_eq!(f.free(p, size, 8).err(), Some(AllocError::NotAllocated));

        let block =
            f.heap.stats().pages.page_size * size.div_ceil(A::PAGE_SIZE).next_power_of_two();
        let bytes = f.mem.bytes_at(addr_of(p), block);
        if poison::ENABLED {
            assert!(bytes.is_some_and(|b| b.iter().all(|x| *x == poison::FREED)));
        }
        assert_eq!(f.heap.stats().frees, 1);
    }

    #[test]
    fn a_buddy_block_is_zeroed_poisoned_and_checked_on_free_full() {
        a_buddy_block_is_zeroed_poisoned_and_checked_on_free::<MockFull>();
    }

    #[test]
    fn a_buddy_block_is_zeroed_poisoned_and_checked_on_free_tiny() {
        a_buddy_block_is_zeroed_poisoned_and_checked_on_free::<MockTiny>();
    }

    fn a_full_buddy_falls_back_to_the_arena_and_detaches_when_empty<A: Arch>() {
        let size = large::<A>(2);
        // Room for exactly four blocks of this size, whatever the page size makes it.
        let block = size.div_ceil(A::PAGE_SIZE).next_power_of_two();
        let mut f = with_pages::<A>(4 * block);
        let mut held = Vec::new();
        for _ in 0..4 {
            held.push(expect(f.alloc(size, 8)));
        }
        assert_eq!(f.heap.stats().pages.free_pages, 0);
        // The fifth cannot come from the pages, and must still succeed.
        let spill = expect(f.alloc(size, 8));
        assert_eq!(f.heap.stats().pages_overflow, 1);
        assert!(f.heap.stats().bump.frames_held > 0, "served by the arena");
        // An alignment past a page goes to the arena even with pages free.
        let big_align = expect(f.alloc(size, A::PAGE_SIZE * 2));
        assert_eq!(addr_of(big_align) % (A::PAGE_SIZE * 2), 0);

        assert_eq!(
            f.heap.detach_pages().err(),
            Some(Detach::InUse { live_blocks: 4 }),
            "the run cannot be given back while blocks are out"
        );
        for p in held {
            expect(f.free(p, size, 8));
        }
        expect(f.free(spill, size, 8));
        expect(f.free(big_align, size, A::PAGE_SIZE * 2));

        let (run, _store) = match f.heap.detach_pages() {
            Ok(parts) => parts,
            Err(e) => panic!("unexpected {e:?}"),
        };
        assert_eq!(run.count(), 4 * block);
        assert_eq!(f.heap.detach_pages().err(), Some(Detach::NotAttached));
        assert_eq!(f.heap.stats().pages, BuddyStats::default());
    }

    #[test]
    fn a_full_buddy_falls_back_to_the_arena_and_detaches_when_empty_full() {
        a_full_buddy_falls_back_to_the_arena_and_detaches_when_empty::<MockFull>();
    }

    #[test]
    fn a_full_buddy_falls_back_to_the_arena_and_detaches_when_empty_tiny() {
        a_full_buddy_falls_back_to_the_arena_and_detaches_when_empty::<MockTiny>();
    }

    #[test]
    fn a_second_run_or_one_outside_the_map_is_refused() {
        let mut f = with_pages::<MockFull>(4);
        let run = expect(FrameSource::<MockFull>::take(&mut f.src, 4));
        let store = Box::leak(vec![0u8; 64].into_boxed_slice());
        assert_eq!(f.heap.attach_pages(run, store).err(), Some(AllocError::Exhausted));

        let mem = HostMemory::new(8192);
        let mut lone = Heap::<MockFull>::new(mem.direct_map());
        let outside = expect(FrameRange::new(expect(Frame::from_number(1000)), 2));
        let store = Box::leak(vec![0u8; 64].into_boxed_slice());
        assert_eq!(lone.attach_pages(outside, store).err(), Some(AllocError::Unmanaged));
    }

    // --- fault injection ----------------------------------------------------

    /// One allocation the workload made and still holds.
    struct Live {
        ptr: NonNull<u8>,
        size: usize,
        align: usize,
        fill: u8,
    }

    /// A fixed mix of small, large and over-aligned allocations with frees interleaved,
    /// run against whatever injector the heap has. Returns what it still holds and how
    /// many requests failed.
    ///
    /// Every block is filled with its own byte, and every held block is checked against
    /// that byte at the end. A failure path that handed out overlapping memory, or
    /// wrote into a live block, shows up as a wrong byte.
    fn workload<A: Arch>(f: &mut Fixture<A>) -> (Vec<Live>, u64) {
        let shapes = [
            (24usize, 8usize),
            (200, 16),
            (1000, 8),
            (large::<A>(1), 8),
            (large::<A>(5), 8),
            (48, 8),
            (large::<A>(2), A::PAGE_SIZE * 2),
            (512, 512),
        ];
        let mut live: Vec<Live> = Vec::new();
        let mut failed = 0u64;
        for i in 0..96usize {
            let (size, align) = shapes[i % shapes.len()];
            match f.alloc(size, align) {
                Ok(ptr) => {
                    let fill = u8::try_from(i % 250).unwrap_or(0) + 1;
                    #[allow(unsafe_code)]
                    // SAFETY: a live allocation of `size` bytes from this heap.
                    unsafe {
                        ptr.as_ptr().write_bytes(fill, size);
                    }
                    live.push(Live {
                        ptr,
                        size,
                        align,
                        fill,
                    });
                }
                // Injected or real, the two a heap may report for a valid layout.
                Err(AllocError::Exhausted | AllocError::Fragmented) => failed += 1,
                Err(e) => panic!("request {i}: unexpected {e:?}"),
            }
            if i % 3 == 2 && !live.is_empty() {
                let victim = live.remove((i / 3) % live.len());
                expect(f.free(victim.ptr, victim.size, victim.align));
            }
        }
        (live, failed)
    }

    /// Check the workload's blocks, free them all, and prove the heap is back where it
    /// started: nothing leaked, nothing counted twice.
    #[track_caller]
    fn settle<A: Arch>(f: &mut Fixture<A>, live: Vec<Live>, failed: u64, what: &str) {
        for l in &live {
            assert!(
                f.mem
                    .bytes_at(addr_of(l.ptr), l.size)
                    .is_some_and(|b| b.iter().all(|x| *x == l.fill)),
                "{what}: a live block was overwritten"
            );
        }
        for l in live {
            expect(f.free(l.ptr, l.size, l.align));
        }
        let s = f.heap.stats();
        assert_eq!(s.bytes_in_use, 0, "{what}: bytes still in use");
        assert_eq!(s.allocations, s.frees, "{what}: allocations and frees disagree");
        assert_eq!(s.failures, failed, "{what}: every failure the caller saw is counted");
        assert_eq!(s.slab.objects_in_use, 0, "{what}");
        assert_eq!(s.pages.live_blocks, 0, "{what}");
        assert_eq!(s.pages.free_pages, s.pages.pages, "{what}: pages not all returned");
        assert_eq!(
            s.bump.live, s.slab.blocks,
            "{what}: the only arena allocations left must be slab blocks"
        );
        assert_eq!(s.bump.in_use, s.slab.bytes_reserved, "{what}");
    }

    /// For each site, fail the first call there, then the second, and so on, until the
    /// workload makes fewer calls at that site than the index. Each run is checked for
    /// leaks and corruption. The first index must trip, so a site the workload never
    /// reaches fails the test instead of passing vacuously.
    fn every_single_injected_failure_is_survived<A: Arch>() {
        for site in [Site::ENTRY, Site::SLAB_BLOCK, Site::PAGES, Site::FRAMES] {
            let mut n = 0u64;
            loop {
                let mut f = with_pages::<A>(32);
                f.heap.set_injector(Injector::fail_nth(site, n));
                let (live, failed) = workload(&mut f);
                let tripped = f.heap.injector().trips();
                assert!(n > 0 || tripped == 1, "{site:?}: the workload never reaches this site");
                settle(&mut f, live, failed, &format!("{site:?} call {n}"));
                assert_eq!(f.heap.stats().injected, tripped);
                if tripped == 0 {
                    break;
                }
                n += 1;
                assert!(n < 1000, "{site:?}: the workload must make finitely many calls");
            }
        }
    }

    #[test]
    fn every_single_injected_failure_is_survived_full() {
        every_single_injected_failure_is_survived::<MockFull>();
    }

    #[test]
    fn every_single_injected_failure_is_survived_tiny() {
        every_single_injected_failure_is_survived::<MockTiny>();
    }

    fn persistent_and_random_failure_is_survived<A: Arch>() {
        // Running out part way through, at each site, and at all of them at once.
        for site in [
            Site::ENTRY,
            Site::SLAB_BLOCK,
            Site::PAGES,
            Site::FRAMES,
            Site::ALL,
        ] {
            for from in [0u64, 3, 17] {
                let mut f = with_pages::<A>(32);
                f.heap.set_injector(Injector::fail_from(site, from));
                let (live, failed) = workload(&mut f);
                settle(&mut f, live, failed, &format!("{site:?} from {from}"));
            }
        }
        for seed in 1..=40u64 {
            let mut f = with_pages::<A>(32);
            f.heap.set_injector(Injector::random(Site::ALL, seed, 4));
            let (live, failed) = workload(&mut f);
            assert!(f.heap.injector().trips() > 0, "seed {seed}");
            settle(&mut f, live, failed, &format!("seed {seed}"));
        }
    }

    #[test]
    fn persistent_and_random_failure_is_survived_full() {
        persistent_and_random_failure_is_survived::<MockFull>();
    }

    #[test]
    fn persistent_and_random_failure_is_survived_tiny() {
        persistent_and_random_failure_is_survived::<MockTiny>();
    }

    fn injection_that_is_recovered_from_is_not_a_caller_failure<A: Arch>() {
        // A failed buddy block with room in the arena, and a failed slab block with room
        // for one object: the heap falls back, the caller sees success, and only
        // `injected` records that anything happened.
        let mut f = with_pages::<A>(32);
        f.heap.set_injector(Injector::fail_nth(Site::PAGES, 0));
        let size = large::<A>(1);
        let p = expect(f.alloc(size, 8));
        let s = f.heap.stats();
        assert_eq!((s.injected, s.failures, s.pages_overflow), (1, 0, 1));
        expect(f.free(p, size, 8));

        f.heap.set_injector(Injector::fail_nth(Site::SLAB_BLOCK, 0));
        let q = expect(f.alloc(40, 8));
        let s = f.heap.stats();
        assert_eq!((s.injected, s.failures), (2, 0), "the earlier trip stays counted");
        assert_eq!(s.slab.objects_in_use, 0, "the object came from the arena instead");
        expect(f.free(q, 40, 8));

        // Growth refused outright: nothing is taken from the frame source.
        let mut g = Fixture::<A>::new();
        g.heap.set_injector(Injector::fail_from(Site::FRAMES, 0));
        assert_eq!(g.heap.grow(&mut g.src, 8192).err(), Some(AllocError::Exhausted));
        assert_eq!(g.src.handed_out(), 0);
    }

    #[test]
    fn injection_that_is_recovered_from_is_not_a_caller_failure_full() {
        injection_that_is_recovered_from_is_not_a_caller_failure::<MockFull>();
    }

    #[test]
    fn injection_that_is_recovered_from_is_not_a_caller_failure_tiny() {
        injection_that_is_recovered_from_is_not_a_caller_failure::<MockTiny>();
    }
}

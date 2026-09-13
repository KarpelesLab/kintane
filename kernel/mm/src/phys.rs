//! The physical frame allocator.
//!
//! # Why a bitmap
//!
//! The obvious alternative, an intrusive free list, stores each free frame's `next`
//! pointer *inside the free frame*. That is elegant and O(1), and it is unavailable
//! to us: writing into a free frame means dereferencing a physical address, and at
//! the point this allocator comes up the kernel has no physical-to-virtual mapping
//! to do that through. On a no-MMU target there is nothing to map, but on an MMU
//! target the direct map does not exist yet — and the frame allocator is one of the
//! things needed to build it. An allocator that requires a direct map cannot
//! bootstrap one.
//!
//! A buddy allocator was the other candidate; `docs/architecture.md` names it as the
//! eventual `mm::paged` allocator. It is not what belongs here first. Its order
//! arrays need dynamic storage, its split/merge logic is where the subtle bugs live,
//! and none of that buys anything until there is a caller that allocates large
//! aligned blocks under pressure. A correct bitmap is a better foundation than a
//! nearly-correct buddy, and the interface below does not change when the internals
//! are replaced.
//!
//! # Where the bits live
//!
//! There is no heap, so the caller supplies the backing store: a `&mut [u8]` carved
//! out of usable memory by whatever bootstraps the kernel, sized with
//! [`bitmap_bytes`] before construction. That caller then tells the allocator about
//! the memory it took, with [`FrameAllocator::reserve`], so the bitmap cannot be
//! handed out as a frame.
//!
//! The store is borrowed for `'store` rather than fixed at `'static`. The kernel
//! always passes `'static`, but tying the type to it would mean host tests could only
//! run against leaked memory, and a subsystem that is awkward to test is one that
//! will not be tested. Nothing else about the design changes.
//!
//! # Two bitmaps, not one
//!
//! The store holds two equal-sized bit arrays over the same frame span:
//!
//! - `pool` — this frame is real, usable memory the allocator may hand out.
//! - `taken` — this pool frame is currently allocated.
//!
//! One array would be cheaper, but it cannot tell "free" from "never existed". A
//! memory map is full of holes — firmware reservations, the kernel image, the gap
//! between two usable regions — and with a single array a `free_frame` of an address
//! in a hole would silently add non-memory to the free pool. That is a corruption
//! that surfaces hours later as a fault on a random device's MMIO window. With two,
//! it is [`AllocError::NotInPool`] at the call site, and a double free is
//! [`AllocError::NotAllocated`].
//!
//! The cost is 2 bits per frame of *span*, holes included: 64 KiB of bitmap per GiB
//! at a 4 KiB page, 1 MiB per GiB at MockTiny's 256-byte page. Spending a
//! sixteen-thousandth of RAM to make every frame error catchable is a trade worth
//! stating and worth taking.
//!
//! # Reserved beats usable
//!
//! Regions from a loader overlap, arrive unsorted, and disagree. The construction
//! order resolves that by hand: the pool starts empty, usable regions add only frames
//! they *wholly* contain, and then every non-usable region subtracts every frame it
//! touches at all. Rounding inwards for usable and outwards for reserved means a
//! partly-reserved frame is never allocatable, whatever order the loader listed the
//! regions in.

use core::marker::PhantomData;

use boot_protocol::{MemoryKind, MemoryRegion};
use hal::{Arch, PhysAddr};

use crate::frame::{Frame, FrameRange};
use crate::{AllocError, narrow, widen};

/// The one place this unit turns a [`MemoryKind`] into its wire value.
///
/// `MemoryRegion::kind` is a `u32` and not the enum because the boot protocol is an
/// ABI: a newer loader may describe a kind this kernel has never heard of, and that
/// must arrive intact rather than as an invalid discriminant. Anything that is not
/// exactly `Usable` is treated as reserved, which is the safe direction for both an
/// unknown kind and a corrupt one.
#[allow(clippy::as_conversions)]
const USABLE: u32 = MemoryKind::Usable as u32;

/// How many bytes of backing store [`FrameAllocator::new`] needs for this memory map.
///
/// Call this first, take the memory it asks for out of a usable region, build the
/// allocator, and then [`FrameAllocator::reserve`] what you took. Splitting it out
/// rather than having the allocator carve its own store keeps the bootstrap decision
/// — which region to steal from — with the code that knows the answer.
///
/// This is the total, both bit arrays included, so a caller never has to know that
/// there are two of them.
///
/// # Errors
/// [`AllocError::NoUsableMemory`] if the map describes no whole usable frame, and
/// [`AllocError::Overflow`] if the usable span does not fit in this target's `usize`.
pub fn bitmap_bytes<A: Arch>(map: &[MemoryRegion]) -> Result<usize, AllocError> {
    let (_, frames) = span::<A>(map)?;
    store_bytes(frames)
        .checked_mul(2)
        .ok_or(AllocError::Overflow)
}

/// A snapshot of the allocator's accounting.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct FrameStats {
    /// Frames in the usable pool. Holes and reserved memory are not counted here;
    /// this is memory the allocator could hand out, not memory the machine contains.
    pub total: usize,
    /// Frames currently available.
    pub free: usize,
    /// Frames currently handed out. Always `total - free`.
    pub used: usize,
    /// Bytes per frame, from `A::PAGE_SIZE`.
    pub frame_size: usize,
    /// Frames between the lowest and highest usable address, holes included. The
    /// gap between this and `total` is how much of the address range is not memory,
    /// and it is what the bitmap is sized from.
    pub span: usize,
}

impl FrameStats {
    /// Free memory in bytes.
    ///
    /// `u64` because a 32-bit kernel can have more physical memory than address
    /// space, which is the whole reason `PhysAddr` is 64-bit.
    pub fn free_bytes(&self) -> u64 {
        widen(self.free).saturating_mul(widen(self.frame_size))
    }

    /// Allocated memory in bytes.
    pub fn used_bytes(&self) -> u64 {
        widen(self.used).saturating_mul(widen(self.frame_size))
    }
}

/// A physical frame allocator over a caller-provided bitmap.
///
/// Not internally synchronised: see the crate documentation. One of these exists per
/// machine, behind whichever lock the configuration selected.
pub struct FrameAllocator<'store, A: Arch> {
    /// Bit set for each frame that is usable memory.
    pool: &'store mut [u8],
    /// Bit set for each pool frame currently allocated.
    taken: &'store mut [u8],
    /// Frame number that bit 0 refers to. Indexing from the lowest usable frame
    /// rather than from physical zero is what keeps the bitmap small on a machine
    /// whose RAM starts at 0x4000_0000, which is most ARM boards.
    base: u64,
    /// Bits in each map.
    span: usize,
    /// Popcount of `pool`.
    total: usize,
    /// Pool frames not currently in `taken`.
    free: usize,
    /// Byte index the next search starts at. A hint, never an invariant: a wrong
    /// value costs a wasted scan, not a wrong answer.
    hint: usize,
    _arch: PhantomData<fn() -> A>,
}

impl<'store, A: Arch> FrameAllocator<'store, A> {
    /// Build an allocator over the usable regions of `map`.
    ///
    /// `store` must be at least [`bitmap_bytes`] long; a longer one is accepted and
    /// the excess ignored, so a caller that rounded up to a frame boundary — which it
    /// must, since it took whole frames — does not have to trim.
    ///
    /// # Errors
    /// [`AllocError::NoUsableMemory`] if the map leaves no frame allocatable,
    /// [`AllocError::StorageTooSmall`] carrying the exact requirement, or
    /// [`AllocError::Overflow`] if the map describes more frames than this target can
    /// index.
    pub fn new(map: &[MemoryRegion], store: &'store mut [u8]) -> Result<Self, AllocError> {
        let (base, span) = span::<A>(map)?;
        let bytes = store_bytes(span);
        let needed = bitmap_bytes::<A>(map)?;
        if store.len() < needed {
            return Err(AllocError::StorageTooSmall { needed });
        }

        let (pool, rest) = store
            .split_at_mut_checked(bytes)
            .ok_or(AllocError::StorageTooSmall { needed })?;
        let (taken, _) = rest
            .split_at_mut_checked(bytes)
            .ok_or(AllocError::StorageTooSmall { needed })?;

        // The store is memory the machine was already using for something else; it
        // arrives holding whatever the firmware left behind.
        pool.fill(0);
        taken.fill(0);

        let limit = base.checked_add(widen(span)).ok_or(AllocError::Overflow)?;

        // Usable first, rounding inwards: a frame only half-covered by a usable
        // region is not a usable frame.
        for region in map.iter().filter(|r| r.kind == USABLE) {
            if let Some((lo, hi)) = inner_frames::<A>(region)? {
                for idx in clamp(lo, hi, base, limit)? {
                    set_bit(pool, idx);
                }
            }
        }

        // Then everything else, rounding outwards, so overlap always resolves against
        // the allocator rather than in its favour.
        for region in map.iter().filter(|r| r.kind != USABLE) {
            if let Some((lo, hi)) = outer_frames::<A>(region)? {
                for idx in clamp(lo, hi, base, limit)? {
                    clear_bit(pool, idx);
                }
            }
        }

        let total = popcount(pool)?;
        if total == 0 {
            return Err(AllocError::NoUsableMemory);
        }

        Ok(FrameAllocator {
            pool,
            taken,
            base,
            span,
            total,
            free: total,
            hint: 0,
            _arch: PhantomData,
        })
    }

    /// Current accounting.
    pub fn stats(&self) -> FrameStats {
        FrameStats {
            total: self.total,
            free: self.free,
            used: self.total.saturating_sub(self.free),
            frame_size: Frame::<A>::SIZE,
            span: self.span,
        }
    }

    /// Take one frame.
    ///
    /// The contents are whatever the previous owner or the firmware left; zeroing is
    /// the caller's decision, because the caller knows whether the frame is about to
    /// be handed to userspace (where zeroing is mandatory) or used as a page table
    /// that will be fully written anyway.
    ///
    /// # Errors
    /// [`AllocError::Exhausted`] when no frame is free. Never a panic: the kernel
    /// may not abort because memory ran out.
    pub fn alloc_frame(&mut self) -> Result<Frame<A>, AllocError> {
        let idx = self.find_free().ok_or(AllocError::Exhausted)?;
        set_bit(self.taken, idx);
        self.free = self.free.saturating_sub(1);
        self.hint = idx / 8;
        self.frame_at(idx)
    }

    /// Take `count` adjacent frames.
    ///
    /// The run is frame-aligned and nothing stronger. A caller needing a larger
    /// alignment — a 2 MiB huge page, a DMA buffer that must not cross a boundary —
    /// asks for it explicitly, and that request belongs to the allocator that
    /// replaces this one rather than being faked here by over-allocating.
    ///
    /// # Errors
    /// [`AllocError::EmptyRequest`] for `count == 0`, [`AllocError::Exhausted`] when
    /// fewer than `count` frames are free at all, and [`AllocError::Fragmented`]
    /// when enough are free but no run of them is adjacent.
    pub fn alloc_contiguous(&mut self, count: usize) -> Result<FrameRange<A>, AllocError> {
        if count == 0 {
            return Err(AllocError::EmptyRequest);
        }
        if self.free < count {
            return Err(AllocError::Exhausted);
        }

        // A linear scan over the span. At a 4 KiB page that is one bit per 4 KiB of
        // physical address range, so even a large machine is a few hundred kilobits
        // — and contiguous allocation is a rare, non-hot-path operation. When that
        // stops being true the answer is a buddy allocator, not a cleverer scan.
        let mut run = 0usize;
        for idx in 0..self.span {
            if self.is_free(idx) {
                run = run.saturating_add(1);
                if run == count {
                    let start = idx.saturating_sub(count.saturating_sub(1));
                    for i in start..=idx {
                        set_bit(self.taken, i);
                    }
                    self.free = self.free.saturating_sub(count);
                    self.hint = idx / 8;
                    return FrameRange::new(self.frame_at(start)?, count);
                }
            } else {
                run = 0;
            }
        }
        // `free >= count` was checked above, so the frames exist but are scattered.
        Err(AllocError::Fragmented)
    }

    /// Give one frame back.
    ///
    /// # Errors
    /// [`AllocError::Unmanaged`], [`AllocError::NotInPool`] or
    /// [`AllocError::NotAllocated`] — the last being a double free.
    pub fn free_frame(&mut self, frame: Frame<A>) -> Result<(), AllocError> {
        let idx = self.index_of(frame)?;
        self.check_freeable(idx)?;
        self.release(idx);
        Ok(())
    }

    /// Give a whole run back.
    ///
    /// All or nothing: every frame is validated before any bit is cleared, so a range
    /// that is partly bogus leaves the allocator exactly as it was. A half-applied
    /// free would leave the caller holding frames the allocator believes are free,
    /// which is worse than the error it was already going to get.
    ///
    /// # Errors
    /// The same set as [`Self::free_frame`], for the first frame of the run that
    /// fails. Nothing has been released when one is returned.
    pub fn free_contiguous(&mut self, range: FrameRange<A>) -> Result<(), AllocError> {
        let start = self.index_of(range.start())?;
        let end = start
            .checked_add(range.count())
            .ok_or(AllocError::Overflow)?;
        if end > self.span {
            return Err(AllocError::Unmanaged);
        }
        for idx in start..end {
            self.check_freeable(idx)?;
        }
        for idx in start..end {
            self.release(idx);
        }
        Ok(())
    }

    /// Permanently remove every frame the byte range `[start, start + len)` touches
    /// from the pool, and report how many were removed.
    ///
    /// This is how the bootstrap tells the allocator about memory it has already
    /// spent: the bitmap's own backing store, the kernel image if the loader did not
    /// mark it, a framebuffer the firmware is still scanning out of. Rounding is
    /// outwards, so a reservation of one byte costs the whole frame — which is
    /// correct, since a frame is the smallest thing that can be owned.
    ///
    /// Removal is permanent by design. Reclaiming boot-time memory later is a
    /// different operation with different safety requirements (the allocator would
    /// have to be told the memory really is RAM), and conflating the two would make
    /// the cheap, common case able to corrupt the pool.
    ///
    /// Addresses outside the managed span are ignored rather than rejected: a
    /// bootstrap reserving a range that happens to sit below the lowest usable frame
    /// has got what it asked for.
    ///
    /// # Errors
    /// [`AllocError::Overflow`] if `start + len` leaves the address space.
    pub fn reserve(&mut self, start: PhysAddr, len: u64) -> Result<usize, AllocError> {
        let Some((lo, hi)) = outer_frames_raw::<A>(start.raw(), len)? else {
            return Ok(0);
        };
        let limit = self
            .base
            .checked_add(widen(self.span))
            .ok_or(AllocError::Overflow)?;

        let mut removed = 0usize;
        for idx in clamp(lo, hi, self.base, limit)? {
            if !bit(self.pool, idx) {
                continue;
            }
            clear_bit(self.pool, idx);
            self.total = self.total.saturating_sub(1);
            // A frame that was not handed out was being counted as free; one that was
            // handed out was not. Only the former changes the free count, which keeps
            // `used == total - free` true either way.
            if !bit(self.taken, idx) {
                self.free = self.free.saturating_sub(1);
            }
            removed = removed.saturating_add(1);
        }
        Ok(removed)
    }

    /// Whether the allocator considers this frame usable memory, allocated or not.
    pub fn manages(&self, frame: Frame<A>) -> bool {
        match self.index_of(frame) {
            Ok(idx) => bit(self.pool, idx),
            Err(_) => false,
        }
    }

    /// Whether this frame is currently handed out.
    pub fn is_allocated(&self, frame: Frame<A>) -> bool {
        match self.index_of(frame) {
            Ok(idx) => bit(self.pool, idx) && bit(self.taken, idx),
            Err(_) => false,
        }
    }

    // --- internals ----------------------------------------------------------

    /// Bit index of a frame, or [`AllocError::Unmanaged`] if it is outside the span.
    fn index_of(&self, frame: Frame<A>) -> Result<usize, AllocError> {
        let n = frame.number();
        if n < self.base {
            return Err(AllocError::Unmanaged);
        }
        let idx = narrow(n.wrapping_sub(self.base))?;
        if idx >= self.span {
            return Err(AllocError::Unmanaged);
        }
        Ok(idx)
    }

    fn frame_at(&self, idx: usize) -> Result<Frame<A>, AllocError> {
        Frame::from_number(
            self.base
                .checked_add(widen(idx))
                .ok_or(AllocError::Overflow)?,
        )
    }

    fn is_free(&self, idx: usize) -> bool {
        bit(self.pool, idx) && !bit(self.taken, idx)
    }

    fn check_freeable(&self, idx: usize) -> Result<(), AllocError> {
        if !bit(self.pool, idx) {
            return Err(AllocError::NotInPool);
        }
        if !bit(self.taken, idx) {
            return Err(AllocError::NotAllocated);
        }
        Ok(())
    }

    /// Clear one allocated bit. Only called after [`Self::check_freeable`].
    fn release(&mut self, idx: usize) {
        clear_bit(self.taken, idx);
        self.free = self.free.saturating_add(1);
        self.hint = self.hint.min(idx / 8);
    }

    /// First free bit at or after the hint, wrapping once.
    ///
    /// Byte at a time: `pool & !taken` is non-zero exactly when the byte holds a
    /// free frame, so eight frames are rejected per iteration and a fully allocated
    /// machine is scanned in `span / 8` steps rather than `span`.
    fn find_free(&self) -> Option<usize> {
        let bytes = self.pool.len();
        if bytes == 0 {
            return None;
        }
        let hint = self.hint.min(bytes.saturating_sub(1));
        for i in (hint..bytes).chain(0..hint) {
            let available = *self.pool.get(i)? & !*self.taken.get(i)?;
            if available == 0 {
                continue;
            }
            let within = narrow(u64::from(available.trailing_zeros())).ok()?;
            let idx = i.checked_mul(8)?.checked_add(within)?;
            // Bits past the end of the span are never set in `pool`, so this cannot
            // point outside it; the check is here because relying on that from a
            // different function is how it stops being true.
            if idx < self.span {
                return Some(idx);
            }
        }
        None
    }
}

// --- bit array ---------------------------------------------------------------
//
// Bounds are checked rather than assumed. Every caller in this module has already
// proved its index, so the checks fold away; what they buy is that a future caller
// that has not proved it gets a wrong answer instead of a kernel panic — and in a
// bitmap, "the bit was not set" is a safe wrong answer, because the frame stays out
// of the pool.

fn bit(map: &[u8], i: usize) -> bool {
    match map.get(i / 8) {
        Some(b) => b & (1u8 << (i % 8)) != 0,
        None => false,
    }
}

fn set_bit(map: &mut [u8], i: usize) {
    if let Some(b) = map.get_mut(i / 8) {
        *b |= 1u8 << (i % 8);
    }
}

fn clear_bit(map: &mut [u8], i: usize) {
    if let Some(b) = map.get_mut(i / 8) {
        *b &= !(1u8 << (i % 8));
    }
}

fn popcount(map: &[u8]) -> Result<usize, AllocError> {
    let mut n = 0usize;
    for b in map {
        let set = narrow(u64::from(b.count_ones()))?;
        n = n.checked_add(set).ok_or(AllocError::Overflow)?;
    }
    Ok(n)
}

/// Bytes needed for one bit array of `frames` bits.
fn store_bytes(frames: usize) -> usize {
    frames.div_ceil(8)
}

// --- memory map interpretation -----------------------------------------------

/// Lowest usable frame and the number of frames up to the highest usable one.
///
/// Only usable regions define the span. Reserved memory above the last stick of RAM
/// would otherwise inflate the bitmap by the size of the MMIO aperture, which on a
/// PC is most of the address space.
fn span<A: Arch>(map: &[MemoryRegion]) -> Result<(u64, usize), AllocError> {
    let mut lo = u64::MAX;
    let mut hi = 0u64;
    let mut found = false;

    for region in map.iter().filter(|r| r.kind == USABLE) {
        let Some((first, end)) = inner_frames::<A>(region)? else {
            continue;
        };
        lo = lo.min(first);
        hi = hi.max(end);
        found = true;
    }

    if !found {
        return Err(AllocError::NoUsableMemory);
    }
    let frames = narrow(hi.checked_sub(lo).ok_or(AllocError::Overflow)?)?;
    if frames == 0 {
        return Err(AllocError::NoUsableMemory);
    }
    Ok((lo, frames))
}

/// Frames wholly inside the region, as `[first, end)` frame numbers.
///
/// A region that does not contain a whole frame yields `None` rather than an error:
/// firmware maps are full of small descriptors, and refusing to boot because one of
/// them is 512 bytes long would be absurd.
fn inner_frames<A: Arch>(region: &MemoryRegion) -> Result<Option<(u64, u64)>, AllocError> {
    let size = Frame::<A>::bytes();
    let end = region
        .start
        .checked_add(region.len)
        .ok_or(AllocError::Overflow)?;
    let first = Frame::<A>::index_of(PhysAddr::new(region.start).align_up(size)?.raw());
    let last = Frame::<A>::index_of(end);
    Ok((last > first).then_some((first, last)))
}

/// Every frame the region touches at all, as `[first, end)` frame numbers.
fn outer_frames<A: Arch>(region: &MemoryRegion) -> Result<Option<(u64, u64)>, AllocError> {
    outer_frames_raw::<A>(region.start, region.len)
}

fn outer_frames_raw<A: Arch>(start: u64, len: u64) -> Result<Option<(u64, u64)>, AllocError> {
    if len == 0 {
        return Ok(None);
    }
    let size = Frame::<A>::bytes();
    let end = start.checked_add(len).ok_or(AllocError::Overflow)?;
    let first = Frame::<A>::index_of(start);
    let last = Frame::<A>::index_of(PhysAddr::new(end).align_up(size)?.raw());
    Ok((last > first).then_some((first, last)))
}

/// The bit indices for frames `[lo, hi)` restricted to the managed span
/// `[base, limit)`.
fn clamp(lo: u64, hi: u64, base: u64, limit: u64) -> Result<core::ops::Range<usize>, AllocError> {
    let lo = lo.max(base);
    let hi = hi.min(limit);
    if hi <= lo {
        // An empty range rather than an error: a region entirely below or above the
        // usable span is a normal thing for a memory map to contain.
        return Ok(0..0);
    }
    let first = narrow(lo.wrapping_sub(base))?;
    let last = narrow(hi.wrapping_sub(base))?;
    Ok(first..last)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hal::mock::{MockFull, MockTiny};

    /// Backing store for the tests. Large enough for any span they build: the
    /// largest is 1024 frames, needing 2 x 128 bytes.
    const STORE: usize = 512;

    #[track_caller]
    fn expect<T>(r: Result<T, AllocError>) -> T {
        match r {
            Ok(v) => v,
            Err(e) => panic!("unexpected {e:?}"),
        }
    }

    /// A region expressed in frames, so one test body means the same thing at a
    /// 4096-byte page and at a 256-byte one. Every scenario below is built this way;
    /// a byte constant anywhere here would be a test that only checks one mock.
    fn region<A: Arch>(first_frame: u64, frames: u64, kind: MemoryKind) -> MemoryRegion {
        let size = Frame::<A>::bytes();
        MemoryRegion {
            start: first_frame.saturating_mul(size),
            len: frames.saturating_mul(size),
            kind: wire(kind),
            _reserved: 0,
        }
    }

    #[allow(clippy::as_conversions)]
    fn wire(kind: MemoryKind) -> u32 {
        kind as u32
    }

    /// One usable region of 64 frames starting at frame 16.
    fn simple<A: Arch>() -> [MemoryRegion; 1] {
        [region::<A>(16, 64, MemoryKind::Usable)]
    }

    fn addr<A: Arch>(frame: u64) -> PhysAddr {
        PhysAddr::new(frame.saturating_mul(Frame::<A>::bytes()))
    }

    // --- accounting ---------------------------------------------------------

    fn stats_describe_the_pool<A: Arch>() {
        let mut store = [0u8; STORE];
        let a = expect(FrameAllocator::<A>::new(&simple::<A>(), &mut store));
        let s = a.stats();
        assert_eq!(s.total, 64);
        assert_eq!(s.free, 64);
        assert_eq!(s.used, 0);
        assert_eq!(s.span, 64);
        assert_eq!(s.frame_size, A::PAGE_SIZE);
        assert_eq!(s.free_bytes(), 64 * widen(A::PAGE_SIZE));
        assert_eq!(s.used_bytes(), 0);
    }

    #[test]
    fn stats_describe_the_pool_full() {
        stats_describe_the_pool::<MockFull>();
    }

    #[test]
    fn stats_describe_the_pool_tiny() {
        stats_describe_the_pool::<MockTiny>();
    }

    fn accounting_follows_allocation<A: Arch>() {
        let mut store = [0u8; STORE];
        let mut a = expect(FrameAllocator::<A>::new(&simple::<A>(), &mut store));
        let f = expect(a.alloc_frame());
        assert_eq!(a.stats().free, 63);
        assert_eq!(a.stats().used, 1);
        assert!(a.is_allocated(f));
        assert!(a.manages(f));
        expect(a.free_frame(f));
        assert_eq!(a.stats().free, 64);
        assert_eq!(a.stats().used, 0);
        assert!(!a.is_allocated(f));
        assert!(a.manages(f));
    }

    #[test]
    fn accounting_follows_allocation_full() {
        accounting_follows_allocation::<MockFull>();
    }

    #[test]
    fn accounting_follows_allocation_tiny() {
        accounting_follows_allocation::<MockTiny>();
    }

    // --- allocation ---------------------------------------------------------

    fn allocation_is_aligned_unique_and_in_range<A: Arch>() {
        let mut store = [0u8; STORE];
        let mut a = expect(FrameAllocator::<A>::new(&simple::<A>(), &mut store));

        let mut seen = [false; 64];
        for _ in 0..64 {
            let f = expect(a.alloc_frame());
            assert!(
                f.start().is_aligned(Frame::<A>::bytes()),
                "every frame starts on a frame boundary"
            );
            let n = f.number();
            assert!((16..80).contains(&n), "frame {n} escaped the usable region");
            let slot = match seen.get_mut(usize::try_from(n - 16).unwrap_or(usize::MAX)) {
                Some(s) => s,
                None => panic!("frame {n} out of range"),
            };
            assert!(!*slot, "frame {n} was handed out twice");
            *slot = true;
        }
        assert!(seen.iter().all(|s| *s), "every usable frame was handed out");
    }

    #[test]
    fn allocation_is_aligned_unique_and_in_range_full() {
        allocation_is_aligned_unique_and_in_range::<MockFull>();
    }

    #[test]
    fn allocation_is_aligned_unique_and_in_range_tiny() {
        allocation_is_aligned_unique_and_in_range::<MockTiny>();
    }

    fn exhaustion_is_an_error_forever<A: Arch>() {
        let mut store = [0u8; STORE];
        let mut a = expect(FrameAllocator::<A>::new(&simple::<A>(), &mut store));
        for _ in 0..64 {
            expect(a.alloc_frame());
        }
        // The kernel may not abort because memory ran out, and it may not abort on
        // the fifth attempt either.
        for _ in 0..4 {
            assert_eq!(
                a.alloc_frame().map(|f| f.number()),
                Err(AllocError::Exhausted)
            );
        }
        assert_eq!(a.stats().free, 0);
        assert_eq!(a.stats().used, 64);
        assert_eq!(
            a.alloc_contiguous(1).map(|r| r.count()),
            Err(AllocError::Exhausted)
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

    fn a_freed_frame_comes_back<A: Arch>() {
        let mut store = [0u8; STORE];
        let mut a = expect(FrameAllocator::<A>::new(&simple::<A>(), &mut store));
        let mut held = [None; 64];
        for slot in held.iter_mut() {
            *slot = Some(expect(a.alloc_frame()));
        }
        let returned = match held.get(30).copied().flatten() {
            Some(f) => f,
            None => panic!("held 64 frames"),
        };
        expect(a.free_frame(returned));
        let again = expect(a.alloc_frame());
        assert_eq!(again, returned, "the only free frame must be the freed one");
    }

    #[test]
    fn a_freed_frame_comes_back_full() {
        a_freed_frame_comes_back::<MockFull>();
    }

    #[test]
    fn a_freed_frame_comes_back_tiny() {
        a_freed_frame_comes_back::<MockTiny>();
    }

    // --- bad frees ----------------------------------------------------------

    fn bad_frees_are_rejected<A: Arch>() {
        let map = [
            region::<A>(16, 16, MemoryKind::Usable),
            // A hole at frames 32..48, then more memory.
            region::<A>(48, 16, MemoryKind::Usable),
        ];
        let mut store = [0u8; STORE];
        let mut a = expect(FrameAllocator::<A>::new(&map, &mut store));
        let f = expect(a.alloc_frame());

        expect(a.free_frame(f));
        assert_eq!(
            a.free_frame(f),
            Err(AllocError::NotAllocated),
            "a double free is an error, not silent corruption"
        );

        let in_hole = Frame::<A>::containing(addr::<A>(40));
        assert_eq!(a.free_frame(in_hole), Err(AllocError::NotInPool));
        assert!(!a.manages(in_hole));

        let below = Frame::<A>::containing(addr::<A>(0));
        assert_eq!(a.free_frame(below), Err(AllocError::Unmanaged));

        let above = Frame::<A>::containing(addr::<A>(4096));
        assert_eq!(a.free_frame(above), Err(AllocError::Unmanaged));

        // None of the failures moved the accounting.
        assert_eq!(a.stats().free, 32);
        assert_eq!(a.stats().total, 32);
    }

    #[test]
    fn bad_frees_are_rejected_full() {
        bad_frees_are_rejected::<MockFull>();
    }

    #[test]
    fn bad_frees_are_rejected_tiny() {
        bad_frees_are_rejected::<MockTiny>();
    }

    // --- memory map interpretation ------------------------------------------

    fn holes_are_never_handed_out<A: Arch>() {
        let map = [
            region::<A>(16, 16, MemoryKind::Usable),
            region::<A>(48, 16, MemoryKind::Usable),
        ];
        let mut store = [0u8; STORE];
        let mut a = expect(FrameAllocator::<A>::new(&map, &mut store));
        assert_eq!(a.stats().total, 32);
        assert_eq!(
            a.stats().span,
            48,
            "the span covers the hole; the pool does not"
        );

        for _ in 0..32 {
            let n = expect(a.alloc_frame()).number();
            assert!(
                (16..32).contains(&n) || (48..64).contains(&n),
                "frame {n} came out of the hole"
            );
        }
        assert_eq!(
            a.alloc_frame().map(|f| f.number()),
            Err(AllocError::Exhausted)
        );
    }

    #[test]
    fn holes_are_never_handed_out_full() {
        holes_are_never_handed_out::<MockFull>();
    }

    #[test]
    fn holes_are_never_handed_out_tiny() {
        holes_are_never_handed_out::<MockTiny>();
    }

    fn reserved_wins_over_usable<A: Arch>() {
        // A loader that describes the kernel image as sitting inside a usable region
        // is describing a real machine, and listing the reservation second must not
        // be what makes it work.
        let map = [
            region::<A>(0, 64, MemoryKind::Usable),
            region::<A>(10, 10, MemoryKind::KernelImage),
            region::<A>(30, 2, MemoryKind::Reserved),
        ];
        let mut store = [0u8; STORE];
        let mut a = expect(FrameAllocator::<A>::new(&map, &mut store));
        assert_eq!(a.stats().total, 64 - 10 - 2);

        for _ in 0..a.stats().total {
            let n = expect(a.alloc_frame()).number();
            assert!(!(10..20).contains(&n), "frame {n} is kernel image");
            assert!(!(30..32).contains(&n), "frame {n} is firmware reserved");
        }
    }

    #[test]
    fn reserved_wins_over_usable_full() {
        reserved_wins_over_usable::<MockFull>();
    }

    #[test]
    fn reserved_wins_over_usable_tiny() {
        reserved_wins_over_usable::<MockTiny>();
    }

    fn reservation_order_does_not_matter<A: Arch>() {
        let forward = [
            region::<A>(0, 64, MemoryKind::Usable),
            region::<A>(10, 10, MemoryKind::BootData),
        ];
        let reverse = [forward[1], forward[0]];
        let mut s1 = [0u8; STORE];
        let mut s2 = [0u8; STORE];
        let a = expect(FrameAllocator::<A>::new(&forward, &mut s1));
        let b = expect(FrameAllocator::<A>::new(&reverse, &mut s2));
        assert_eq!(a.stats(), b.stats());
    }

    #[test]
    fn reservation_order_does_not_matter_full() {
        reservation_order_does_not_matter::<MockFull>();
    }

    #[test]
    fn reservation_order_does_not_matter_tiny() {
        reservation_order_does_not_matter::<MockTiny>();
    }

    fn partial_frames_at_region_edges_are_dropped<A: Arch>() {
        // 16 frames' worth of memory, shifted one byte up and shortened by two, so
        // neither the first nor the last frame is wholly inside it.
        let size = Frame::<A>::bytes();
        let map = [MemoryRegion {
            start: 16 * size + 1,
            len: 16 * size - 2,
            kind: USABLE,
            _reserved: 0,
        }];
        let mut store = [0u8; STORE];
        let a = expect(FrameAllocator::<A>::new(&map, &mut store));
        assert_eq!(a.stats().total, 14, "both partial frames are excluded");
    }

    #[test]
    fn partial_frames_at_region_edges_are_dropped_full() {
        partial_frames_at_region_edges_are_dropped::<MockFull>();
    }

    #[test]
    fn partial_frames_at_region_edges_are_dropped_tiny() {
        partial_frames_at_region_edges_are_dropped::<MockTiny>();
    }

    fn a_reservation_of_one_byte_costs_a_frame<A: Arch>() {
        let size = Frame::<A>::bytes();
        let map = [
            region::<A>(0, 8, MemoryKind::Usable),
            MemoryRegion {
                start: 4 * size + 1,
                len: 1,
                kind: wire(MemoryKind::Reserved),
                _reserved: 0,
            },
        ];
        let mut store = [0u8; STORE];
        let a = expect(FrameAllocator::<A>::new(&map, &mut store));
        assert_eq!(a.stats().total, 7);
        assert!(!a.manages(Frame::<A>::containing(addr::<A>(4))));
    }

    #[test]
    fn a_reservation_of_one_byte_costs_a_frame_full() {
        a_reservation_of_one_byte_costs_a_frame::<MockFull>();
    }

    #[test]
    fn a_reservation_of_one_byte_costs_a_frame_tiny() {
        a_reservation_of_one_byte_costs_a_frame::<MockTiny>();
    }

    fn a_map_with_no_whole_frame_is_refused<A: Arch>() {
        let mut store = [0u8; STORE];
        let sub_frame = [MemoryRegion {
            start: 1,
            len: Frame::<A>::bytes() - 2,
            kind: USABLE,
            _reserved: 0,
        }];
        assert_eq!(
            FrameAllocator::<A>::new(&sub_frame, &mut store).err(),
            Some(AllocError::NoUsableMemory)
        );
        assert_eq!(
            bitmap_bytes::<A>(&sub_frame),
            Err(AllocError::NoUsableMemory)
        );
        assert_eq!(bitmap_bytes::<A>(&[]), Err(AllocError::NoUsableMemory));

        // Usable memory that is entirely reserved is refused too: an allocator with
        // an empty pool is not a working allocator, and failing here is better than
        // failing on the first allocation.
        let all_reserved = [
            region::<A>(0, 4, MemoryKind::Usable),
            region::<A>(0, 4, MemoryKind::Bad),
        ];
        assert_eq!(
            FrameAllocator::<A>::new(&all_reserved, &mut store).err(),
            Some(AllocError::NoUsableMemory)
        );
    }

    #[test]
    fn a_map_with_no_whole_frame_is_refused_full() {
        a_map_with_no_whole_frame_is_refused::<MockFull>();
    }

    #[test]
    fn a_map_with_no_whole_frame_is_refused_tiny() {
        a_map_with_no_whole_frame_is_refused::<MockTiny>();
    }

    fn an_unknown_memory_kind_is_treated_as_reserved<A: Arch>() {
        // A newer loader describing a kind this kernel has never heard of. The safe
        // reading is "not usable"; the unsafe one is "probably fine".
        let map = [
            region::<A>(0, 16, MemoryKind::Usable),
            MemoryRegion {
                start: 8 * Frame::<A>::bytes(),
                len: 4 * Frame::<A>::bytes(),
                kind: 9999,
                _reserved: 0,
            },
        ];
        let mut store = [0u8; STORE];
        let a = expect(FrameAllocator::<A>::new(&map, &mut store));
        assert_eq!(a.stats().total, 12);
    }

    #[test]
    fn an_unknown_memory_kind_is_treated_as_reserved_full() {
        an_unknown_memory_kind_is_treated_as_reserved::<MockFull>();
    }

    #[test]
    fn an_unknown_memory_kind_is_treated_as_reserved_tiny() {
        an_unknown_memory_kind_is_treated_as_reserved::<MockTiny>();
    }

    // --- backing store ------------------------------------------------------

    fn the_store_requirement_is_exact<A: Arch>() {
        let map = simple::<A>();
        // 64 frames is 8 bytes of bits, and there are two bit arrays.
        let needed = expect(bitmap_bytes::<A>(&map));
        assert_eq!(needed, 16);

        let mut exact = [0u8; 16];
        let a = expect(FrameAllocator::<A>::new(&map, &mut exact));
        assert_eq!(a.stats().total, 64);

        let mut short = [0u8; 15];
        assert_eq!(
            FrameAllocator::<A>::new(&map, &mut short).err(),
            Some(AllocError::StorageTooSmall { needed }),
            "the error carries the requirement so a caller can retry"
        );

        // A store larger than required is accepted and the excess ignored; the
        // bootstrap took whole frames, so it always has more than it needs.
        let mut generous = [0u8; STORE];
        let b = expect(FrameAllocator::<A>::new(&map, &mut generous));
        assert_eq!(b.stats(), a.stats());
    }

    #[test]
    fn the_store_requirement_is_exact_full() {
        the_store_requirement_is_exact::<MockFull>();
    }

    #[test]
    fn the_store_requirement_is_exact_tiny() {
        the_store_requirement_is_exact::<MockTiny>();
    }

    fn a_dirty_store_is_not_trusted<A: Arch>() {
        // The bootstrap hands over memory the firmware was using. If construction
        // did not clear it, every frame in the span would look allocated or usable
        // at random.
        let mut store = [0xA5u8; STORE];
        let a = expect(FrameAllocator::<A>::new(&simple::<A>(), &mut store));
        assert_eq!(a.stats().total, 64);
        assert_eq!(a.stats().free, 64);
    }

    #[test]
    fn a_dirty_store_is_not_trusted_full() {
        a_dirty_store_is_not_trusted::<MockFull>();
    }

    #[test]
    fn a_dirty_store_is_not_trusted_tiny() {
        a_dirty_store_is_not_trusted::<MockTiny>();
    }

    // --- reserve ------------------------------------------------------------

    fn reserve_takes_frames_out_of_the_pool<A: Arch>() {
        let mut store = [0u8; STORE];
        let mut a = expect(FrameAllocator::<A>::new(&simple::<A>(), &mut store));

        // The bootstrap telling the allocator where it put the bitmap.
        let removed = expect(a.reserve(addr::<A>(16), Frame::<A>::bytes()));
        assert_eq!(removed, 1);
        assert_eq!(a.stats().total, 63);
        assert_eq!(a.stats().free, 63);
        assert_eq!(a.stats().used, 0);

        for _ in 0..63 {
            assert_ne!(expect(a.alloc_frame()).number(), 16);
        }
        assert_eq!(
            a.alloc_frame().map(|f| f.number()),
            Err(AllocError::Exhausted)
        );

        // Reserving outside the span is a no-op, not an error.
        assert_eq!(a.reserve(addr::<A>(1000), Frame::<A>::bytes()), Ok(0));
        // Reserving zero bytes touches nothing.
        assert_eq!(a.reserve(addr::<A>(20), 0), Ok(0));
    }

    #[test]
    fn reserve_takes_frames_out_of_the_pool_full() {
        reserve_takes_frames_out_of_the_pool::<MockFull>();
    }

    #[test]
    fn reserve_takes_frames_out_of_the_pool_tiny() {
        reserve_takes_frames_out_of_the_pool::<MockTiny>();
    }

    fn reserving_an_allocated_frame_keeps_the_books<A: Arch>() {
        let mut store = [0u8; STORE];
        let mut a = expect(FrameAllocator::<A>::new(&simple::<A>(), &mut store));
        let f = expect(a.alloc_frame());
        assert_eq!(a.stats().used, 1);

        let start = f.start();
        assert_eq!(expect(a.reserve(start, Frame::<A>::bytes())), 1);
        let s = a.stats();
        assert_eq!(s.total, 63);
        assert_eq!(s.free, 63);
        assert_eq!(s.used, s.total - s.free);
        assert_eq!(s.used, 0);
        // The holder now gets told the frame is no longer the allocator's to take.
        assert_eq!(a.free_frame(f), Err(AllocError::NotInPool));
        // Reserving twice removes nothing the second time.
        assert_eq!(a.reserve(start, Frame::<A>::bytes()), Ok(0));
    }

    #[test]
    fn reserving_an_allocated_frame_keeps_the_books_full() {
        reserving_an_allocated_frame_keeps_the_books::<MockFull>();
    }

    #[test]
    fn reserving_an_allocated_frame_keeps_the_books_tiny() {
        reserving_an_allocated_frame_keeps_the_books::<MockTiny>();
    }

    // --- contiguous ---------------------------------------------------------

    fn contiguous_runs_are_contiguous<A: Arch>() {
        let mut store = [0u8; STORE];
        let mut a = expect(FrameAllocator::<A>::new(&simple::<A>(), &mut store));
        let run = expect(a.alloc_contiguous(5));
        assert_eq!(run.count(), 5);
        assert_eq!(a.stats().free, 59);
        assert_eq!(expect(run.len_bytes()), 5 * Frame::<A>::bytes());

        let mut previous: Option<u64> = None;
        let mut n = 0;
        for f in run.iter() {
            assert!(a.is_allocated(f));
            if let Some(p) = previous {
                assert_eq!(f.number(), p + 1, "a run must be adjacent");
            }
            previous = Some(f.number());
            n += 1;
        }
        assert_eq!(n, 5);

        expect(a.free_contiguous(run));
        assert_eq!(a.stats().free, 64);
    }

    #[test]
    fn contiguous_runs_are_contiguous_full() {
        contiguous_runs_are_contiguous::<MockFull>();
    }

    #[test]
    fn contiguous_runs_are_contiguous_tiny() {
        contiguous_runs_are_contiguous::<MockTiny>();
    }

    fn contiguous_never_crosses_a_hole<A: Arch>() {
        // Two eight-frame regions with a hole between them. A sixteen-frame request
        // must fail rather than return a run that spans memory that is not there.
        let map = [
            region::<A>(0, 8, MemoryKind::Usable),
            region::<A>(16, 8, MemoryKind::Usable),
        ];
        let mut store = [0u8; STORE];
        let mut a = expect(FrameAllocator::<A>::new(&map, &mut store));
        assert_eq!(a.stats().free, 16);
        assert_eq!(
            a.alloc_contiguous(16).map(|r| r.count()),
            Err(AllocError::Fragmented),
            "enough frames, but not adjacent ones"
        );
        let run = expect(a.alloc_contiguous(8));
        assert_eq!(run.start().number(), 0);
    }

    #[test]
    fn contiguous_never_crosses_a_hole_full() {
        contiguous_never_crosses_a_hole::<MockFull>();
    }

    #[test]
    fn contiguous_never_crosses_a_hole_tiny() {
        contiguous_never_crosses_a_hole::<MockTiny>();
    }

    fn fragmentation_is_distinguished_from_exhaustion<A: Arch>() {
        let mut store = [0u8; STORE];
        let mut a = expect(FrameAllocator::<A>::new(&simple::<A>(), &mut store));

        let mut held = [None; 64];
        for slot in held.iter_mut() {
            *slot = Some(expect(a.alloc_frame()));
        }
        // Free every other frame: half the memory is available and no two adjacent
        // frames are.
        for (i, slot) in held.iter().enumerate() {
            if i % 2 == 0 {
                if let Some(f) = slot {
                    expect(a.free_frame(*f));
                }
            }
        }
        assert_eq!(a.stats().free, 32);
        assert_eq!(
            a.alloc_contiguous(2).map(|r| r.count()),
            Err(AllocError::Fragmented),
            "32 frames free, none adjacent"
        );
        assert_eq!(
            a.alloc_contiguous(33).map(|r| r.count()),
            Err(AllocError::Exhausted),
            "asking for more than exists is exhaustion, not fragmentation"
        );
        // Single frames still work throughout.
        assert!(a.alloc_frame().is_ok());
    }

    #[test]
    fn fragmentation_is_distinguished_from_exhaustion_full() {
        fragmentation_is_distinguished_from_exhaustion::<MockFull>();
    }

    #[test]
    fn fragmentation_is_distinguished_from_exhaustion_tiny() {
        fragmentation_is_distinguished_from_exhaustion::<MockTiny>();
    }

    fn a_run_appears_once_neighbours_are_freed<A: Arch>() {
        let mut store = [0u8; STORE];
        let mut a = expect(FrameAllocator::<A>::new(&simple::<A>(), &mut store));
        let mut held = [None; 64];
        for slot in held.iter_mut() {
            *slot = Some(expect(a.alloc_frame()));
        }
        assert_eq!(
            a.alloc_contiguous(3).map(|r| r.count()),
            Err(AllocError::Exhausted)
        );
        for i in 20..23 {
            if let Some(Some(f)) = held.get(i) {
                expect(a.free_frame(*f));
            }
        }
        let run = expect(a.alloc_contiguous(3));
        assert_eq!(run.start().number(), 36, "frames 16+20 .. 16+22");
        assert_eq!(a.stats().free, 0);
    }

    #[test]
    fn a_run_appears_once_neighbours_are_freed_full() {
        a_run_appears_once_neighbours_are_freed::<MockFull>();
    }

    #[test]
    fn a_run_appears_once_neighbours_are_freed_tiny() {
        a_run_appears_once_neighbours_are_freed::<MockTiny>();
    }

    fn zero_length_requests_are_refused<A: Arch>() {
        let mut store = [0u8; STORE];
        let mut a = expect(FrameAllocator::<A>::new(&simple::<A>(), &mut store));
        assert_eq!(
            a.alloc_contiguous(0).map(|r| r.count()),
            Err(AllocError::EmptyRequest)
        );
        assert_eq!(a.stats().free, 64);
    }

    #[test]
    fn zero_length_requests_are_refused_full() {
        zero_length_requests_are_refused::<MockFull>();
    }

    #[test]
    fn zero_length_requests_are_refused_tiny() {
        zero_length_requests_are_refused::<MockTiny>();
    }

    fn freeing_a_run_is_all_or_nothing<A: Arch>() {
        let mut store = [0u8; STORE];
        let mut a = expect(FrameAllocator::<A>::new(&simple::<A>(), &mut store));
        let run = expect(a.alloc_contiguous(4));
        // Free one frame of the run by hand, then try to free the whole run: that
        // frame is no longer allocated, so nothing at all may be released.
        let first = run.start();
        expect(a.free_frame(first));
        assert_eq!(a.stats().free, 61);
        assert_eq!(a.free_contiguous(run), Err(AllocError::NotAllocated));
        assert_eq!(a.stats().free, 61, "a rejected free changes nothing");

        // A range that runs off the end of the span is rejected before it can touch
        // anything either.
        let top = expect(Frame::<A>::from_number(78));
        let over = expect(FrameRange::new(top, 8));
        assert_eq!(a.free_contiguous(over), Err(AllocError::Unmanaged));
        assert_eq!(a.stats().free, 61);
    }

    #[test]
    fn freeing_a_run_is_all_or_nothing_full() {
        freeing_a_run_is_all_or_nothing::<MockFull>();
    }

    #[test]
    fn freeing_a_run_is_all_or_nothing_tiny() {
        freeing_a_run_is_all_or_nothing::<MockTiny>();
    }

    // --- wide physical addresses --------------------------------------------

    fn memory_above_four_gibibytes_is_reachable<A: Arch>() {
        // The i686-with-PAE shape: usable memory whose addresses do not fit in a
        // pointer. The frame numbers stay in `u64` and the bitmap is indexed from the
        // base, so the span is 64 frames however high the memory sits.
        let base_frame = 0x1_0000_0000u64 / Frame::<A>::bytes();
        let map = [region::<A>(base_frame, 64, MemoryKind::Usable)];
        let mut store = [0u8; STORE];
        let mut a = expect(FrameAllocator::<A>::new(&map, &mut store));
        assert_eq!(
            a.stats().span,
            64,
            "the bitmap covers the memory, not the gap below it"
        );
        assert_eq!(a.stats().total, 64);

        let f = expect(a.alloc_frame());
        assert!(f.start().raw() >= 0x1_0000_0000);
        assert_eq!(f.number(), base_frame);
        expect(a.free_frame(f));

        // A low address is outside the span even though its frame number is small.
        assert_eq!(
            a.free_frame(Frame::<A>::containing(PhysAddr::new(0))),
            Err(AllocError::Unmanaged)
        );
    }

    #[test]
    fn memory_above_four_gibibytes_is_reachable_full() {
        memory_above_four_gibibytes_is_reachable::<MockFull>();
    }

    #[test]
    fn memory_above_four_gibibytes_is_reachable_tiny() {
        memory_above_four_gibibytes_is_reachable::<MockTiny>();
    }

    // --- the point of the two mocks -----------------------------------------

    #[test]
    fn the_same_map_yields_different_frame_counts_per_page_size() {
        // One byte-identical memory map, read by two architectures. If this ever
        // reports the same total for both, something in the allocator has stopped
        // asking the architecture how big a page is.
        let map = [MemoryRegion {
            start: 0x10_0000,
            len: 0x10_0000,
            kind: USABLE,
            _reserved: 0,
        }];
        let mut s1 = [0u8; 1024];
        let mut s2 = [0u8; 1024];
        let full = expect(FrameAllocator::<MockFull>::new(&map, &mut s1));
        let tiny = expect(FrameAllocator::<MockTiny>::new(&map, &mut s2));
        assert_eq!(full.stats().total, 0x10_0000 / 4096);
        assert_eq!(tiny.stats().total, 0x10_0000 / 256);
        assert_ne!(full.stats().total, tiny.stats().total);
        // Same memory either way, counted in different units.
        assert_eq!(full.stats().free_bytes(), tiny.stats().free_bytes());
    }
}

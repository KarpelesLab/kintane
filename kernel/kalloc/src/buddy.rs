//! Multi-page blocks that come back: a binary buddy allocator over a run of frames.
//!
//! # What it is for
//!
//! The heap had two allocators and neither reused a large block. The [slab](crate::slab)
//! stops at 1024 bytes, and the [bump](crate::bump) reclaims only the most recent
//! allocation. So a driver that allocated and freed a 64 KiB buffer in a loop was
//! consuming the arena one buffer at a time. The buddy allocator is the missing third
//! route: blocks of 2^order pages that split when a smaller block is wanted and merge
//! again when both halves are free.
//!
//! # Why over frames, and why in `kalloc` rather than in `mm`
//!
//! It manages *page indices* inside one run of frames, and hands out [`FrameRange`]s.
//! Pointers are the heap's business, through its direct map. That keeps this module
//! like `mm::phys`: arithmetic over a caller-supplied store, no `unsafe`, testable
//! without any memory behind it.
//!
//! It is not a replacement for `mm::FrameAllocator`, which owns the whole machine's
//! frames and answers "is this frame usable RAM". A buddy system as *the* frame
//! allocator is the Linux shape, and it is a reasonable later step. It would also mean
//! rewriting the one allocator everything else already depends on in order to add a
//! heap feature. Here the heap takes one run of frames from `mm` and manages it
//! finely. `mm` still knows those frames are in use, and they go back as one run when
//! the heap lets go of them ([`crate::Heap::detach_pages`]).
//!
//! # The metadata, and why it is not inside the blocks
//!
//! The textbook buddy allocator threads its free lists through the free blocks
//! themselves. That needs a pointer read and a write into memory that is, by
//! definition, not in use, and so possibly poisoned, unmapped by a later change, or
//! being scribbled on by a use-after-free. The slab took the same decision for the
//! same reason. Here each page has a fixed-size record in a separate byte store that
//! the caller provides, as `mm::FrameAllocator`'s bitmaps do:
//!
//! ```text
//!   [next: u32][prev: u32][tag: u8]     per page, STORE_BYTES_PER_PAGE = 9
//! ```
//!
//! A block's first page carries its tag, free or allocated plus its order. Every other
//! page of the block has tag zero. The links are used only while the block is free.
//! Free-list heads are one `u32` per order, so taking a block and unlinking one are
//! O(1), and so is the buddy test at each level of a merge. The only loop is over the
//! at most [`MAX_ORDER`] + 1 orders.
//!
//! Nine bytes per page is 0.2% at a 4 KiB page and 3.5% at MockTiny's 256 bytes. Small
//! pages pay proportionally more, and a no-MMU target with 256-byte pages is not going
//! to want a buddy heap of any size worth metering.
//!
//! # Invariants, checked
//!
//! [`Buddy::check`] walks the whole structure and reports the first thing wrong:
//! a list that cycles or points out of range, a listed block whose tag disagrees, a
//! block not aligned to its own order, a free block whose free buddy was never merged,
//! a free-page count that does not add up. It is O(pages). When [`CHECKED`] is set,
//! which is in debug builds and under the host tests, every split and every merge runs
//! it afterwards and stops the machine if it fails. An allocator whose metadata is
//! inconsistent will hand the same memory to two owners next, and nothing it could
//! return would make that safe to continue from.

use core::marker::PhantomData;

use hal::Arch;
use mm::{AllocError, Frame, FrameRange};

use crate::{narrow, widen};

/// The largest block is 2^MAX_ORDER pages: 4 MiB at a 4 KiB page.
///
/// Larger requests are not this allocator's job. A run of that size is rare enough
/// to take from the frame allocator directly, and each extra order adds a list head
/// that anything fragmented will leave empty.
pub const MAX_ORDER: usize = 10;

/// Number of orders, for the shape of the per-order arrays.
pub const ORDERS: usize = MAX_ORDER + 1;

/// Bytes of store each managed page needs. See the module documentation.
pub const STORE_BYTES_PER_PAGE: usize = 9;

/// Whether every mutation re-verifies the whole structure.
///
/// On in debug builds, as `DEBUG_BUILD`'s help text promises, and always under the
/// host tests, so a broken invariant fails the test that caused it rather than a later
/// one. A `const`, not a `cfg`, for the reason `poison` gives: the checking code is
/// compiled in every configuration, so it cannot rot unseen in the one that skips it.
pub const CHECKED: bool = kconfig::DEBUG_BUILD || cfg!(test);

/// Link value meaning "no page".
const NIL: u32 = u32::MAX;
/// Tag bit: this page heads a free block.
const TAG_FREE: u8 = 0x40;
/// Tag bit: this page heads an allocated block.
const TAG_USED: u8 = 0x80;
/// Tag bits holding the order.
const TAG_ORDER: u8 = 0x1F;

/// What [`Buddy::check`] found wrong. Named rather than a bool so that a failure in a
/// kernel log says which invariant broke.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Invariant {
    /// A free list is longer than the number of pages, so it must cycle.
    ListCycles { order: usize },
    /// A free list names a page outside the run.
    LinkOutOfRange { order: usize },
    /// A block's `prev` link does not name the block before it in its list.
    BackLinkWrong { order: usize },
    /// A listed block's tag does not say "free, this order".
    ListedBlockNotFree { order: usize },
    /// A block does not start at a multiple of its own size, or runs past the end.
    BlockMisaligned { page: usize },
    /// A free block and its buddy are both free at the same order and were not merged.
    NotCoalesced { page: usize },
    /// A page inside a block carries a tag, or a page at a block boundary carries none.
    TagOutOfPlace { page: usize },
    /// The per-order block counts disagree with the lists.
    BlockCountWrong { order: usize },
    /// The free-page total disagrees with the lists or with the tags.
    FreeCountWrong,
}

impl Invariant {
    /// A short name, for a console that cannot format `Debug`.
    pub const fn name(self) -> &'static str {
        match self {
            Invariant::ListCycles { .. } => "free list cycles",
            Invariant::LinkOutOfRange { .. } => "link out of range",
            Invariant::BackLinkWrong { .. } => "back link wrong",
            Invariant::ListedBlockNotFree { .. } => "listed block not free",
            Invariant::BlockMisaligned { .. } => "block misaligned",
            Invariant::NotCoalesced { .. } => "free buddies not merged",
            Invariant::TagOutOfPlace { .. } => "tag out of place",
            Invariant::BlockCountWrong { .. } => "block count wrong",
            Invariant::FreeCountWrong => "free count wrong",
        }
    }
}

/// A snapshot of the allocator's accounting.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct BuddyStats {
    /// Pages managed.
    pub pages: usize,
    /// Pages in free blocks.
    pub free_pages: usize,
    /// Free blocks of each order.
    pub free_blocks: [usize; ORDERS],
    /// Blocks currently allocated.
    pub live_blocks: usize,
    /// Bytes per page, from the architecture.
    pub page_size: usize,
    /// Times a block was halved to serve a smaller request.
    pub splits: u64,
    /// Times two free buddies were merged.
    pub merges: u64,
}

impl BuddyStats {
    /// The order of the largest free block, or `None` if nothing is free. What a caller
    /// deciding between [`AllocError::Fragmented`] and waiting wants to know.
    pub fn largest_free_order(&self) -> Option<usize> {
        (0..ORDERS)
            .rev()
            .find(|o| self.free_blocks.get(*o).is_some_and(|n| *n > 0))
    }
}

/// A buddy allocator over one run of frames.
///
/// Not internally synchronised; see the crate documentation.
pub struct Buddy<'store, A: Arch> {
    store: &'store mut [u8],
    /// The whole run, kept to hand back from [`Self::into_parts`].
    run: FrameRange<A>,
    /// The run's first frame. Page index `i` is frame `base + i`.
    base: Frame<A>,
    pages: usize,
    heads: [u32; ORDERS],
    free_blocks: [usize; ORDERS],
    free_pages: usize,
    live_blocks: usize,
    splits: u64,
    merges: u64,
    _arch: PhantomData<fn() -> A>,
}

/// Bytes of store a run of `pages` pages needs.
///
/// # Errors
/// [`AllocError::Overflow`] if the product does not fit, or if `pages` is too many to
/// name in a `u32` link.
pub fn store_bytes(pages: usize) -> Result<usize, AllocError> {
    if widen(pages) >= u64::from(NIL) {
        return Err(AllocError::Overflow);
    }
    pages
        .checked_mul(STORE_BYTES_PER_PAGE)
        .ok_or(AllocError::Overflow)
}

/// The smallest order whose block holds `pages` pages, or `None` past [`MAX_ORDER`].
pub fn order_for(pages: usize) -> Option<usize> {
    let order = usize::try_from(pages.max(1).checked_next_power_of_two()?.trailing_zeros()).ok()?;
    (order <= MAX_ORDER).then_some(order)
}

/// Pages in a block of `order`.
const fn block_pages(order: usize) -> usize {
    1usize << order
}

impl<'store, A: Arch> Buddy<'store, A> {
    /// Manage `run`, keeping per-page records in `store`.
    ///
    /// The run need not be a power of two. It is carved greedily into the largest
    /// aligned blocks that fit, which is the same set of blocks that freeing every page
    /// of a fully allocated run would merge back into. So a fresh allocator already
    /// satisfies the "fully coalesced" invariant.
    ///
    /// # Errors
    /// [`AllocError::StorageTooSmall`] with the exact need, or
    /// [`AllocError::Overflow`] for a run too large to link.
    pub fn new(run: FrameRange<A>, store: &'store mut [u8]) -> Result<Self, AllocError> {
        let pages = run.count();
        let needed = store_bytes(pages)?;
        if store.len() < needed {
            return Err(AllocError::StorageTooSmall { needed });
        }
        let mut b = Buddy {
            store,
            run,
            base: run.start(),
            pages,
            heads: [NIL; ORDERS],
            free_blocks: [0; ORDERS],
            free_pages: 0,
            live_blocks: 0,
            splits: 0,
            merges: 0,
            _arch: PhantomData,
        };
        // The store arrives holding whatever was there, and a stray tag inside a block
        // would read as a block boundary.
        b.store.fill(0);

        let mut page = 0usize;
        while page < pages {
            let mut order = MAX_ORDER;
            while order > 0
                && (page % block_pages(order) != 0
                    || page.saturating_add(block_pages(order)) > pages)
            {
                order -= 1;
            }
            b.set_tag(page, TAG_FREE | order_bits(order));
            b.push(page, order);
            page = page.saturating_add(block_pages(order));
        }
        b.verify();
        Ok(b)
    }

    /// Give up the run and the store, for a caller returning the frames.
    ///
    /// Takes `self` whatever is allocated: it is the caller that knows whether anyone
    /// still holds a block. [`crate::Heap::detach_pages`] checks before calling this.
    pub fn into_parts(self) -> (FrameRange<A>, &'store mut [u8]) {
        (self.run, self.store)
    }

    /// The run this allocator manages.
    pub fn run(&self) -> FrameRange<A> {
        self.run
    }

    /// Whether `frame` is one of this allocator's pages.
    pub fn owns(&self, frame: Frame<A>) -> bool {
        self.index_of(frame).is_ok()
    }

    /// Current accounting.
    pub fn stats(&self) -> BuddyStats {
        BuddyStats {
            pages: self.pages,
            free_pages: self.free_pages,
            free_blocks: self.free_blocks,
            live_blocks: self.live_blocks,
            page_size: A::PAGE_SIZE,
            splits: self.splits,
            merges: self.merges,
        }
    }

    /// Take a block of at least `pages` pages.
    ///
    /// # Errors
    /// As [`Self::alloc_order`], plus [`AllocError::EmptyRequest`] for zero.
    pub fn alloc_pages(&mut self, pages: usize) -> Result<FrameRange<A>, AllocError> {
        if pages == 0 {
            return Err(AllocError::EmptyRequest);
        }
        // Past MAX_ORDER is "more than there is" to a caller, as in `crate::validate`.
        let order = order_for(pages).ok_or(AllocError::Exhausted)?;
        self.alloc_order(order)
    }

    /// Take a block of exactly 2^`order` pages.
    ///
    /// # Errors
    /// [`AllocError::Exhausted`] when fewer than that many pages are free, or for an
    /// order past [`MAX_ORDER`]. [`AllocError::Fragmented`] when enough pages are free
    /// but no block is large enough, which tells the caller that smaller requests would
    /// still succeed.
    pub fn alloc_order(&mut self, order: usize) -> Result<FrameRange<A>, AllocError> {
        if order > MAX_ORDER {
            return Err(AllocError::Exhausted);
        }
        let Some(mut have) = (order..ORDERS).find(|o| self.head(*o) != NIL) else {
            return Err(if self.free_pages >= block_pages(order) {
                AllocError::Fragmented
            } else {
                AllocError::Exhausted
            });
        };
        let page = to_index(self.head(have));
        self.unlink(page, have);

        // Halve until the block is the size asked for, freeing the upper half each time.
        while have > order {
            have -= 1;
            let buddy = page.saturating_add(block_pages(have));
            self.set_tag(buddy, TAG_FREE | order_bits(have));
            self.push(buddy, have);
            self.splits = self.splits.saturating_add(1);
        }
        self.set_tag(page, TAG_USED | order_bits(order));
        self.live_blocks = self.live_blocks.saturating_add(1);
        self.verify();
        FrameRange::new(self.frame_at(page)?, block_pages(order))
    }

    /// Give a block back, merging it with its buddy for as long as the buddy is free.
    ///
    /// The range must be exactly what an allocation returned: a block's first frame and
    /// its power-of-two length. A free is checked before anything changes, so a refused
    /// free leaves the allocator exactly as it was.
    ///
    /// # Errors
    /// [`AllocError::Unmanaged`] for a range outside the run,
    /// [`AllocError::Misaligned`] for a range that does not start a block or has the
    /// wrong length, and [`AllocError::NotAllocated`] for a block that is already free.
    /// That last one is a double free.
    pub fn free(&mut self, range: FrameRange<A>) -> Result<(), AllocError> {
        let mut page = self.index_of(range.start())?;
        let count = range.count();
        if page.checked_add(count).is_none_or(|end| end > self.pages) {
            return Err(AllocError::Unmanaged);
        }
        if !count.is_power_of_two() {
            return Err(AllocError::Misaligned);
        }
        let mut order = order_for(count).ok_or(AllocError::Misaligned)?;
        let tag = self.tag(page);
        if tag & TAG_FREE != 0 {
            return Err(AllocError::NotAllocated);
        }
        // A zero tag is the interior of some block. Whether that block is free or not
        // cannot be told without a search, and either way the caller's range is wrong.
        if tag & TAG_USED == 0 || usize::from(tag & TAG_ORDER) != order {
            return Err(AllocError::Misaligned);
        }

        self.set_tag(page, 0);
        self.live_blocks = self.live_blocks.saturating_sub(1);
        while order < MAX_ORDER {
            let buddy = page ^ block_pages(order);
            let fits = buddy
                .checked_add(block_pages(order))
                .is_some_and(|end| end <= self.pages);
            if !fits || self.tag(buddy) != TAG_FREE | order_bits(order) {
                break;
            }
            self.unlink(buddy, order);
            self.set_tag(buddy, 0);
            page = page.min(buddy);
            order += 1;
            self.merges = self.merges.saturating_add(1);
        }
        self.set_tag(page, TAG_FREE | order_bits(order));
        self.push(page, order);
        self.verify();
        Ok(())
    }

    /// Walk everything and report the first invariant that does not hold.
    ///
    /// # Errors
    /// The broken [`Invariant`].
    pub fn check(&self) -> Result<(), Invariant> {
        let mut listed_pages = 0usize;
        for order in 0..ORDERS {
            let mut count = 0usize;
            let mut prev = NIL;
            let mut at = self.head(order);
            while at != NIL {
                count = count.saturating_add(1);
                if count > self.pages {
                    return Err(Invariant::ListCycles { order });
                }
                let page = to_index(at);
                if page >= self.pages {
                    return Err(Invariant::LinkOutOfRange { order });
                }
                if self.prev(page) != prev {
                    return Err(Invariant::BackLinkWrong { order });
                }
                if self.tag(page) != TAG_FREE | order_bits(order) {
                    return Err(Invariant::ListedBlockNotFree { order });
                }
                listed_pages = listed_pages.saturating_add(block_pages(order));
                prev = at;
                at = self.next(page);
            }
            if self.free_blocks.get(order).copied() != Some(count) {
                return Err(Invariant::BlockCountWrong { order });
            }
        }
        if listed_pages != self.free_pages {
            return Err(Invariant::FreeCountWrong);
        }

        // Every page, block by block. This is what finds a free block that is not on any
        // list, and a tag inside a block, neither of which the list walk can see.
        let mut tagged_free = 0usize;
        let mut page = 0usize;
        while page < self.pages {
            let tag = self.tag(page);
            let is_free = tag & TAG_FREE != 0;
            if !is_free && tag & TAG_USED == 0 {
                return Err(Invariant::TagOutOfPlace { page });
            }
            let order = usize::from(tag & TAG_ORDER);
            let end = page.saturating_add(block_pages(order));
            if order > MAX_ORDER || page % block_pages(order) != 0 || end > self.pages {
                return Err(Invariant::BlockMisaligned { page });
            }
            if let Some(inner) = (page.saturating_add(1)..end).find(|p| self.tag(*p) != 0) {
                return Err(Invariant::TagOutOfPlace { page: inner });
            }
            if is_free {
                tagged_free = tagged_free.saturating_add(block_pages(order));
                let buddy = page ^ block_pages(order);
                if order < MAX_ORDER
                    && buddy.saturating_add(block_pages(order)) <= self.pages
                    && self.tag(buddy) == tag
                {
                    return Err(Invariant::NotCoalesced { page });
                }
            }
            page = end;
        }
        if tagged_free != self.free_pages {
            return Err(Invariant::FreeCountWrong);
        }
        Ok(())
    }

    // --- internals ----------------------------------------------------------

    /// Run [`Self::check`] when [`CHECKED`], and stop if it fails. See the module
    /// documentation for why stopping is the only answer.
    fn verify(&self) {
        if !CHECKED {
            return;
        }
        if let Err(broken) = self.check() {
            panic!("buddy allocator invariant broken: {} ({broken:?})", broken.name());
        }
    }

    fn index_of(&self, frame: Frame<A>) -> Result<usize, AllocError> {
        let off = frame
            .number()
            .checked_sub(self.base.number())
            .ok_or(AllocError::Unmanaged)?;
        let page = narrow(off).map_err(|_| AllocError::Unmanaged)?;
        if page >= self.pages {
            return Err(AllocError::Unmanaged);
        }
        Ok(page)
    }

    fn frame_at(&self, page: usize) -> Result<Frame<A>, AllocError> {
        let n = self
            .base
            .number()
            .checked_add(widen(page))
            .ok_or(AllocError::Overflow)?;
        Frame::from_number(n)
    }

    fn head(&self, order: usize) -> u32 {
        self.heads.get(order).copied().unwrap_or(NIL)
    }

    fn set_head(&mut self, order: usize, page: u32) {
        if let Some(h) = self.heads.get_mut(order) {
            *h = page;
        }
    }

    /// Put a free block at the front of its order's list and count it.
    fn push(&mut self, page: usize, order: usize) {
        let old = self.head(order);
        let me = to_link(page);
        self.set_next(page, old);
        self.set_prev(page, NIL);
        if old != NIL {
            self.set_prev(to_index(old), me);
        }
        self.set_head(order, me);
        if let Some(n) = self.free_blocks.get_mut(order) {
            *n = n.saturating_add(1);
        }
        self.free_pages = self.free_pages.saturating_add(block_pages(order));
    }

    /// Remove a free block from its order's list and uncount it.
    fn unlink(&mut self, page: usize, order: usize) {
        let next = self.next(page);
        let prev = self.prev(page);
        if prev == NIL {
            self.set_head(order, next);
        } else {
            self.set_next(to_index(prev), next);
        }
        if next != NIL {
            self.set_prev(to_index(next), prev);
        }
        if let Some(n) = self.free_blocks.get_mut(order) {
            *n = n.saturating_sub(1);
        }
        self.free_pages = self.free_pages.saturating_sub(block_pages(order));
    }

    // Record accessors. The store's length was checked against `pages` at construction,
    // so every access below is in range. They still go through `get` rather than
    // indexing: an out-of-range read returns a value `check` rejects, rather than
    // panicking inside the allocator.

    fn field(&self, page: usize, offset: usize, len: usize) -> Option<&[u8]> {
        let at = page
            .checked_mul(STORE_BYTES_PER_PAGE)?
            .checked_add(offset)?;
        self.store.get(at..at.checked_add(len)?)
    }

    fn field_mut(&mut self, page: usize, offset: usize, len: usize) -> Option<&mut [u8]> {
        let at = page
            .checked_mul(STORE_BYTES_PER_PAGE)?
            .checked_add(offset)?;
        self.store.get_mut(at..at.checked_add(len)?)
    }

    fn read_u32(&self, page: usize, offset: usize) -> u32 {
        self.field(page, offset, 4)
            .and_then(|b| <[u8; 4]>::try_from(b).ok())
            .map_or(NIL, u32::from_le_bytes)
    }

    fn write_u32(&mut self, page: usize, offset: usize, v: u32) {
        if let Some(b) = self.field_mut(page, offset, 4) {
            b.copy_from_slice(&v.to_le_bytes());
        }
    }

    fn next(&self, page: usize) -> u32 {
        self.read_u32(page, 0)
    }

    fn prev(&self, page: usize) -> u32 {
        self.read_u32(page, 4)
    }

    fn set_next(&mut self, page: usize, v: u32) {
        self.write_u32(page, 0, v);
    }

    fn set_prev(&mut self, page: usize, v: u32) {
        self.write_u32(page, 4, v);
    }

    fn tag(&self, page: usize) -> u8 {
        self.field(page, 8, 1)
            .and_then(|b| b.first().copied())
            .unwrap_or(0)
    }

    fn set_tag(&mut self, page: usize, tag: u8) {
        if let Some(b) = self.field_mut(page, 8, 1).and_then(|b| b.first_mut()) {
            *b = tag;
        }
    }
}

/// An order as tag bits. Orders fit in five bits because [`MAX_ORDER`] does.
fn order_bits(order: usize) -> u8 {
    const _: () = assert!(MAX_ORDER <= TAG_ORDER as usize);
    u8::try_from(order).map_or(TAG_ORDER, |o| o & TAG_ORDER)
}

/// A page index as a link. `store_bytes` refused runs whose indices would not fit.
fn to_link(page: usize) -> u32 {
    u32::try_from(page).unwrap_or(NIL)
}

/// A link as a page index. `u32` always fits in `usize` on the targets we build for;
/// a target where it did not would map it past the end, where `check` catches it.
fn to_index(link: u32) -> usize {
    usize::try_from(link).unwrap_or(usize::MAX)
}

#[cfg(test)]
mod tests {
    use hal::mock::{MockFull, MockTiny};

    use super::*;

    #[track_caller]
    fn expect<T>(r: Result<T, AllocError>) -> T {
        match r {
            Ok(v) => v,
            Err(e) => panic!("unexpected {e:?}"),
        }
    }

    /// A run of `pages` frames starting at frame `first`, and a store for it.
    fn run<A: Arch>(first: u64, pages: usize) -> (FrameRange<A>, Vec<u8>) {
        let range = expect(FrameRange::new(expect(Frame::from_number(first)), pages));
        (range, vec![0xAA; expect(store_bytes(pages))])
    }

    /// A tiny deterministic generator, so the churn tests are reproducible.
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
        fn below(&mut self, n: usize) -> usize {
            usize::try_from(self.next() % widen(n.max(1))).unwrap_or(0)
        }
    }

    fn a_fresh_run_is_carved_into_maximal_blocks<A: Arch>() {
        // 1024 + 512 + 4 + 1 pages: carving must find exactly those blocks.
        let (range, mut store) = run::<A>(100, 1541);
        let b = expect(Buddy::new(range, &mut store));
        let s = b.stats();
        assert_eq!(s.free_pages, 1541);
        assert_eq!(s.free_blocks[10], 1);
        assert_eq!(s.free_blocks[9], 1);
        assert_eq!(s.free_blocks[2], 1);
        assert_eq!(s.free_blocks[0], 1);
        assert_eq!(s.free_blocks.iter().sum::<usize>(), 4);
        assert_eq!(s.page_size, A::PAGE_SIZE, "the page size must come from the architecture");
        assert_eq!(b.check(), Ok(()));
    }

    #[test]
    fn a_fresh_run_is_carved_into_maximal_blocks_full() {
        a_fresh_run_is_carved_into_maximal_blocks::<MockFull>();
    }

    #[test]
    fn a_fresh_run_is_carved_into_maximal_blocks_tiny() {
        a_fresh_run_is_carved_into_maximal_blocks::<MockTiny>();
    }

    fn splitting_and_merging_are_exact_inverses<A: Arch>() {
        let (range, mut store) = run::<A>(7, 64);
        let mut b = expect(Buddy::new(range, &mut store));
        let pristine = b.stats();

        let one = expect(b.alloc_order(0));
        assert_eq!(one.count(), 1);
        assert_eq!(one.start(), range.start(), "the lowest block is split first");
        // 64 = one order-6 block. Serving one page splits it six times, leaving one free
        // block at each of orders 0..=5.
        let s = b.stats();
        assert_eq!(s.splits, 6);
        assert_eq!(s.free_pages, 63);
        for o in 0..6 {
            assert_eq!(s.free_blocks[o], 1, "order {o}");
        }
        assert_eq!(s.free_blocks[6], 0);

        expect(b.free(one));
        let s = b.stats();
        assert_eq!(s.merges, 6, "freeing the page must merge all the way back up");
        assert_eq!(s.free_blocks, pristine.free_blocks);
        assert_eq!(s.free_pages, 64);
        assert_eq!(s.live_blocks, 0);
    }

    #[test]
    fn splitting_and_merging_are_exact_inverses_full() {
        splitting_and_merging_are_exact_inverses::<MockFull>();
    }

    #[test]
    fn splitting_and_merging_are_exact_inverses_tiny() {
        splitting_and_merging_are_exact_inverses::<MockTiny>();
    }

    fn blocks_are_aligned_distinct_and_the_right_size<A: Arch>() {
        let (range, mut store) = run::<A>(32, 256);
        let mut b = expect(Buddy::new(range, &mut store));
        let mut held: Vec<FrameRange<A>> = Vec::new();
        for pages in [1usize, 3, 4, 7, 16, 2, 1, 31, 8] {
            let r = expect(b.alloc_pages(pages));
            assert!(
                r.count() >= pages && r.count() < pages * 2,
                "{pages} pages gave {}",
                r.count()
            );
            let off = r.start().number() - range.start().number();
            assert_eq!(off % widen(r.count()), 0, "a block starts at a multiple of its size");
            for h in &held {
                let (a0, a1) = (h.start().number(), h.end_exclusive());
                let (b0, b1) = (r.start().number(), r.end_exclusive());
                assert!(b1 <= a0 || a1 <= b0, "{h:?} overlaps {r:?}");
            }
            held.push(r);
        }
        for r in held {
            expect(b.free(r));
        }
        assert_eq!(b.stats().free_pages, 256);
        assert_eq!(b.stats().free_blocks[8], 1, "everything merges back into one block");
    }

    #[test]
    fn blocks_are_aligned_distinct_and_the_right_size_full() {
        blocks_are_aligned_distinct_and_the_right_size::<MockFull>();
    }

    #[test]
    fn blocks_are_aligned_distinct_and_the_right_size_tiny() {
        blocks_are_aligned_distinct_and_the_right_size::<MockTiny>();
    }

    fn exhaustion_and_fragmentation_are_told_apart<A: Arch>() {
        let (range, mut store) = run::<A>(0, 8);
        let mut b = expect(Buddy::new(range, &mut store));
        let pages: Vec<_> = (0..8).map(|_| expect(b.alloc_order(0))).collect();
        assert_eq!(b.alloc_order(0).err(), Some(AllocError::Exhausted));

        // Free every other page: four free, none adjacent to a free buddy.
        for p in pages.iter().step_by(2) {
            expect(b.free(*p));
        }
        assert_eq!(b.stats().free_pages, 4);
        assert_eq!(
            b.alloc_order(1).err(),
            Some(AllocError::Fragmented),
            "four pages free but no two of them buddies"
        );
        assert_eq!(b.alloc_order(3).err(), Some(AllocError::Exhausted));
        assert_eq!(b.alloc_order(MAX_ORDER + 1).err(), Some(AllocError::Exhausted));
        assert_eq!(b.alloc_pages(0).err(), Some(AllocError::EmptyRequest));
        assert!(b.alloc_order(0).is_ok(), "a smaller request still succeeds");
    }

    #[test]
    fn exhaustion_and_fragmentation_are_told_apart_full() {
        exhaustion_and_fragmentation_are_told_apart::<MockFull>();
    }

    #[test]
    fn exhaustion_and_fragmentation_are_told_apart_tiny() {
        exhaustion_and_fragmentation_are_told_apart::<MockTiny>();
    }

    fn a_bad_free_changes_nothing<A: Arch>() {
        let (range, mut store) = run::<A>(40, 32);
        let mut b = expect(Buddy::new(range, &mut store));
        let blk = expect(b.alloc_order(2));
        let before = b.stats();

        let frame = |n: u64| expect(Frame::<A>::from_number(n));
        let r = |n: u64, c: usize| expect(FrameRange::<A>::new(frame(n), c));
        let start = blk.start().number();

        // Wrong length, not a power of two, interior start, outside the run.
        assert_eq!(b.free(r(start, 2)).err(), Some(AllocError::Misaligned));
        assert_eq!(b.free(r(start, 3)).err(), Some(AllocError::Misaligned));
        assert_eq!(b.free(r(start + 1, 1)).err(), Some(AllocError::Misaligned));
        assert_eq!(b.free(r(39, 1)).err(), Some(AllocError::Unmanaged));
        assert_eq!(b.free(r(72, 1)).err(), Some(AllocError::Unmanaged));
        assert_eq!(b.free(r(68, 8)).err(), Some(AllocError::Unmanaged), "runs off the end");
        // A block that is free right now.
        let free_block = r(start + 4, 4);
        assert_eq!(b.free(free_block).err(), Some(AllocError::NotAllocated));
        assert_eq!(b.stats(), before, "a refused free must leave no trace");

        expect(b.free(blk));
        assert_eq!(b.free(blk).err(), Some(AllocError::NotAllocated), "a double free");
        assert_eq!(b.stats().free_pages, 32);
    }

    #[test]
    fn a_bad_free_changes_nothing_full() {
        a_bad_free_changes_nothing::<MockFull>();
    }

    #[test]
    fn a_bad_free_changes_nothing_tiny() {
        a_bad_free_changes_nothing::<MockTiny>();
    }

    fn random_churn_keeps_every_invariant<A: Arch>(seed: u64) {
        // An odd length, so the carving and the edge-of-run buddy tests are exercised.
        let (range, mut store) = run::<A>(1000, 1000);
        let mut b = expect(Buddy::new(range, &mut store));
        let mut rng = Rng(seed);
        let mut held: Vec<FrameRange<A>> = Vec::new();
        let mut owner = vec![usize::MAX; 1000];

        for step in 0..4000usize {
            if rng.below(3) != 0 {
                let pages = 1 + rng.below(40);
                match b.alloc_pages(pages) {
                    Ok(r) => {
                        // Claim every page, so any overlap with a live block is caught here.
                        for f in r.iter() {
                            let i = usize::try_from(f.number() - 1000).unwrap_or(usize::MAX);
                            assert_eq!(
                                owner[i],
                                usize::MAX,
                                "step {step}: page {i} handed out twice"
                            );
                            owner[i] = step;
                        }
                        held.push(r);
                    }
                    Err(AllocError::Exhausted | AllocError::Fragmented) => {}
                    Err(e) => panic!("unexpected {e:?}"),
                }
            } else if !held.is_empty() {
                let r = held.swap_remove(rng.below(held.len()));
                for f in r.iter() {
                    owner[usize::try_from(f.number() - 1000).unwrap_or(0)] = usize::MAX;
                }
                expect(b.free(r));
            }
            // CHECKED already runs this after every mutation. Asserted here too, so this
            // test does not silently depend on that constant.
            assert_eq!(b.check(), Ok(()), "step {step}");
            let live: usize = held.iter().map(|r| r.count()).sum();
            assert_eq!(b.stats().free_pages + live, 1000, "step {step}");
        }
        for r in held {
            expect(b.free(r));
        }
        let s = b.stats();
        assert_eq!(s.free_pages, 1000);
        // 1000 = 512 + 256 + 128 + 64 + 32 + 8: fully coalesced means exactly those.
        assert_eq!(s.free_blocks.iter().sum::<usize>(), 6);
    }

    #[test]
    fn random_churn_keeps_every_invariant_full() {
        for seed in [1, 0x9E37_79B9, 0xDEAD_BEEF_1234] {
            random_churn_keeps_every_invariant::<MockFull>(seed);
        }
    }

    #[test]
    fn random_churn_keeps_every_invariant_tiny() {
        for seed in [2, 0x1234_5678, 77] {
            random_churn_keeps_every_invariant::<MockTiny>(seed);
        }
    }

    #[test]
    fn the_store_must_be_large_enough() {
        let range = expect(FrameRange::<MockFull>::new(expect(Frame::from_number(0)), 100));
        let mut store = vec![0u8; 899];
        assert_eq!(
            Buddy::new(range, &mut store).err(),
            Some(AllocError::StorageTooSmall { needed: 900 })
        );
        assert_eq!(order_for(1), Some(0));
        assert_eq!(order_for(5), Some(3));
        assert_eq!(order_for(1024), Some(10));
        assert_eq!(order_for(1025), None);
    }

    #[test]
    fn check_names_what_is_broken() {
        // The checker is what every debug build leans on, so it has to be able to fail.
        // Each case corrupts one thing through the store directly.
        let range = expect(FrameRange::<MockFull>::new(expect(Frame::from_number(0)), 16));
        let mut store = vec![0u8; expect(store_bytes(16))];
        {
            let b = expect(Buddy::new(range, &mut store));
            assert_eq!(b.check(), Ok(()));
        }
        // A tag inside the single 16-page block.
        let mut bad = store.clone();
        bad[5 * STORE_BYTES_PER_PAGE + 8] = TAG_USED;
        let b = Buddy::<MockFull> {
            store: &mut bad,
            run: range,
            base: range.start(),
            pages: 16,
            heads: [NIL, NIL, NIL, NIL, 0, NIL, NIL, NIL, NIL, NIL, NIL],
            free_blocks: [0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0],
            free_pages: 16,
            live_blocks: 0,
            splits: 0,
            merges: 0,
            _arch: PhantomData,
        };
        assert_eq!(b.check(), Err(Invariant::TagOutOfPlace { page: 5 }));

        // A free-page count that is off by one.
        let mut copy = store.clone();
        let b = Buddy::<MockFull> {
            store: &mut copy,
            run: range,
            base: range.start(),
            pages: 16,
            heads: [NIL, NIL, NIL, NIL, 0, NIL, NIL, NIL, NIL, NIL, NIL],
            free_blocks: [0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0],
            free_pages: 15,
            live_blocks: 0,
            splits: 0,
            merges: 0,
            _arch: PhantomData,
        };
        assert_eq!(b.check(), Err(Invariant::FreeCountWrong));

        // Two free buddies of order 3 that should have been one block of order 4.
        let mut split = vec![0u8; expect(store_bytes(16))];
        split[8] = TAG_FREE | 3;
        split[8 * STORE_BYTES_PER_PAGE + 8] = TAG_FREE | 3;
        split[..4].copy_from_slice(&8u32.to_le_bytes());
        split[4..8].copy_from_slice(&NIL.to_le_bytes());
        split[8 * STORE_BYTES_PER_PAGE..8 * STORE_BYTES_PER_PAGE + 4]
            .copy_from_slice(&NIL.to_le_bytes());
        split[8 * STORE_BYTES_PER_PAGE + 4..8 * STORE_BYTES_PER_PAGE + 8]
            .copy_from_slice(&0u32.to_le_bytes());
        let b = Buddy::<MockFull> {
            store: &mut split,
            run: range,
            base: range.start(),
            pages: 16,
            heads: [NIL, NIL, NIL, 0, NIL, NIL, NIL, NIL, NIL, NIL, NIL],
            free_blocks: [0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0],
            free_pages: 16,
            live_blocks: 0,
            splits: 0,
            merges: 0,
            _arch: PhantomData,
        };
        assert_eq!(b.check(), Err(Invariant::NotCoalesced { page: 0 }));
    }
}

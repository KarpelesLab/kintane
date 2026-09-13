//! Size classes over the arena: the allocator that actually reuses memory.
//!
//! Almost everything a kernel allocates is small and short-lived — a message, a
//! directory entry, an object header — and almost all of it is one of a handful of
//! sizes. A [`Bump`](crate::Bump) cannot serve that, because it never takes anything
//! back. This is the layer that does.
//!
//! # The shape
//!
//! A **block** is one bump allocation, carved into a whole number of equal-sized
//! **objects**. Every block belongs to a size class; an allocation is rounded up to
//! the smallest class that fits it and served from any block of that class with a
//! free object. Freeing marks the object free, and the next allocation of that class
//! takes it back. Both are constant time.
//!
//! ```text
//!   class 64   block ──────────────────────────────────────────────
//!              │ obj │ obj │ obj │ obj │ obj │ obj │ ... │ obj │
//!              └──▲──┴─────┴──▲──┴─────┴─────┴─────┴─────┴─────┘
//!   used: 0b…10110                free              allocated
//! ```
//!
//! # Why a bitmap and not a free list
//!
//! The textbook slab threads its free list through the free objects themselves: each
//! free object holds the address of the next. It is O(1) and costs no metadata, and
//! it means the allocator reads and writes pointers inside the memory it hands out —
//! so a caller that overruns a buffer by one word corrupts the allocator's own
//! structure, and the crash happens in the next unrelated allocation. That is the
//! classic heap-corruption debugging session, and it is worth money to avoid.
//!
//! Here the state is a `u64` bitmap in a descriptor that lives **outside** the heap,
//! in this struct. The consequences, in order of how much they matter:
//!
//! * The allocator never reads or writes heap memory except to poison it and to zero
//!   it on request. A buffer overrun damages the caller's neighbour and nothing else,
//!   and the block's own accounting stays trustworthy enough to report it.
//! * **A double free is detected**, always, in every build: the bit is already clear.
//!   A free-list implementation would have to walk the list to know.
//! * An interior or misaligned pointer is detected, because the offset within the
//!   block must be an exact multiple of the class size.
//! * A block holds at most 64 objects, one per bit. For the small classes that is
//!   less than a page's worth, which costs a little more bookkeeping per byte of heap
//!   and buys the three properties above.
//! * The descriptors are a fixed array, so there are at most [`MAX_BLOCKS`] blocks.
//!   That is the real limit this design imposes, and it is the one to lift first —
//!   with a descriptor allocated from the heap itself, once there is a heap to
//!   allocate it from, which is precisely the bootstrap ordering problem this whole
//!   unit exists to solve. Until then, running out is
//!   [`AllocError::Exhausted`](mm::AllocError::Exhausted) and the
//!   [`Heap`](crate::Heap) falls back to serving the object from the arena.
//!
//! # Classes
//!
//! Powers of two from 16 to 1024 bytes. Powers of two because the class size is also
//! the alignment the class guarantees, which is what lets an over-aligned request be
//! served by rounding *the class* up rather than by padding each object. Sixteen at
//! the bottom because below that the per-object bookkeeping outweighs the object;
//! 1024 at the top because past that the waste from rounding up to a class starts to
//! matter more than the reuse, and the arena serves those directly.
//!
//! None of those numbers is a page size, and none of them may become one: a class
//! table derived from `A::PAGE_SIZE` would give a `MockTiny` build classes four times
//! smaller than a `MockFull` build for no reason anybody chose.

// Re-enabled for two calls into `crate::poison`, each on an object whose bit this
// allocator has just checked. Nothing else here touches heap memory.
#![allow(unsafe_code)]

use core::alloc::Layout;
use core::ptr::NonNull;

use hal::{KernAddr, PhysAddr};
use mm::AllocError;

use crate::context::AllocContext;
use mm::directmap::DirectMap;
use crate::poison;

/// The size classes, ascending. Each is also the alignment that class guarantees.
pub const CLASS_SIZES: [usize; 7] = [16, 32, 64, 128, 256, 512, 1024];

/// How many size classes there are, for the shape of [`SlabStats::classes`].
pub const CLASS_COUNT: usize = CLASS_SIZES.len();

/// The most blocks the slab can describe. See the module documentation.
pub const MAX_BLOCKS: usize = 64;

/// One bit of bitmap per object, in a `u64`.
const MAX_OBJECTS: usize = 64;

/// Fewer objects than this per block and the block is mostly overhead; the class is
/// given more room instead.
const MIN_OBJECTS: usize = 4;

/// The block size the object count is chosen to land near.
///
/// A tuning constant and deliberately *not* `A::PAGE_SIZE`: a block is an arena
/// allocation, not a frame, so nothing here needs to know how big a page is. Tying
/// it to the page size would make a 256-byte-page target allocate sixteen-times
/// smaller blocks than a 4096-byte-page one as a side effect rather than as a
/// decision.
const TARGET_BLOCK_BYTES: usize = 4096;

/// The size class that would serve `layout`, or `None` if no class is large enough.
///
/// The class must cover both the size **and** the alignment: an object of 16 bytes
/// that must be 64-aligned is served from the 64 class, because that is the class
/// whose objects are 64-aligned. Padding a 16-byte object inside a 16-byte class
/// would be the alternative, and it would mean the class size and the guaranteed
/// alignment stop being the same number, which is the property that makes every
/// offset calculation here trivial.
pub fn class_for(layout: Layout) -> Option<usize> {
    if layout.size() == 0 {
        return None;
    }
    let need = layout.size().max(layout.align());
    CLASS_SIZES.iter().copied().find(|c| *c >= need)
}

/// How many objects a block of `class` holds.
pub fn objects_per_block(class: usize) -> usize {
    if class == 0 {
        return 0;
    }
    (TARGET_BLOCK_BYTES / class).clamp(MIN_OBJECTS, MAX_OBJECTS)
}

/// The arena allocation a block of `class` is.
///
/// # Errors
/// [`AllocError::Overflow`] if the block would not be a representable layout, which
/// cannot happen for the classes in [`CLASS_SIZES`] but is checked rather than
/// argued.
pub fn block_layout(class: usize) -> Result<Layout, AllocError> {
    let bytes = class
        .checked_mul(objects_per_block(class))
        .ok_or(AllocError::Overflow)?;
    Layout::from_size_align(bytes, class).map_err(|_| AllocError::Overflow)
}

/// The bit that stands for object `idx`.
///
/// Zero for an index no `u64` has a bit for, which cannot happen — every block holds
/// at most [`MAX_OBJECTS`] objects — and which fails safe if it ever does: a zero
/// mask reads as "not allocated", so a free is refused rather than clearing somebody
/// else's bit.
fn bit(idx: usize) -> u64 {
    u32::try_from(idx)
        .ok()
        .and_then(|i| 1u64.checked_shl(i))
        .unwrap_or(0)
}

/// One carved-up arena allocation.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct Block {
    virt: KernAddr,
    /// Recorded at construction so a DMA-capable caller can be told where its object
    /// is without a second conversion, and so a block can be identified in a dump.
    phys: PhysAddr,
    /// Object size in bytes. Zero for an unused descriptor.
    class: usize,
    objects: usize,
    /// Bit `i` set means object `i` is handed out.
    used: u64,
}

impl Block {
    const EMPTY: Block = Block {
        virt: KernAddr::ZERO,
        phys: PhysAddr::ZERO,
        class: 0,
        objects: 0,
        used: 0,
    };

    /// Bits that correspond to objects that exist.
    fn mask(&self) -> u64 {
        if self.objects >= MAX_OBJECTS {
            u64::MAX
        } else {
            // `objects < 64`, so the bit exists and the subtraction cannot underflow.
            bit(self.objects).wrapping_sub(1)
        }
    }

    fn bytes(&self) -> usize {
        self.class.saturating_mul(self.objects)
    }

    fn in_use(&self) -> usize {
        // `count_ones` of a `u64` is at most 64, which fits every `usize`.
        usize::try_from(self.used.count_ones()).unwrap_or(MAX_OBJECTS)
    }

    /// The index of the object containing `addr`, if it is one of this block's.
    ///
    /// `Err(Misaligned)` rather than `Ok(None)` for an address that is inside the
    /// block but not on an object boundary: that is a pointer into the middle of
    /// somebody's object, and it is a different mistake from a pointer to a
    /// different block entirely.
    fn index_of(&self, addr: KernAddr) -> Result<Option<usize>, AllocError> {
        let Ok(off) = addr.diff(self.virt) else {
            return Ok(None);
        };
        if off >= self.bytes() {
            return Ok(None);
        }
        if self.class == 0 || off % self.class != 0 {
            return Err(AllocError::Misaligned);
        }
        Ok(Some(off / self.class))
    }
}

/// Per-class accounting.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct ClassStats {
    /// Object size in bytes.
    pub size: usize,
    /// Blocks currently held by this class.
    pub blocks: usize,
    /// Objects across those blocks.
    pub objects: usize,
    /// Of which handed out.
    pub in_use: usize,
}

/// A snapshot of the size-class allocator.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SlabStats {
    /// Blocks held, of [`MAX_BLOCKS`].
    pub blocks: usize,
    /// Objects across every block.
    pub objects: usize,
    /// Objects currently handed out.
    pub objects_in_use: usize,
    /// Bytes of arena the blocks occupy.
    pub bytes_reserved: usize,
    /// Bytes those handed-out objects account for, rounded up to the class. The gap
    /// between this and what callers asked for is internal fragmentation, and it is
    /// the price of size classes.
    pub bytes_in_use: usize,
    /// Objects served since construction.
    pub allocations: u64,
    /// Objects freed since construction.
    pub frees: u64,
    /// Frees refused because the object was already free. A double free the
    /// allocator could prove, rather than one it merely survived.
    pub double_frees: u64,
    /// One entry per size class.
    pub classes: [ClassStats; CLASS_COUNT],
}

/// The size-class allocator.
///
/// Holds no memory of its own: blocks are handed to it by whoever owns the arena,
/// which is [`Heap`](crate::Heap). Keeping it that way means this type is a pure
/// data structure — no lifetimes, no architecture parameter, no frame source — and
/// can be reasoned about, and tested, without any of them.
pub struct Slab {
    blocks: [Block; MAX_BLOCKS],
    count: usize,
    allocations: u64,
    frees: u64,
    double_frees: u64,
}

impl Default for Slab {
    fn default() -> Self {
        Self::new()
    }
}

impl Slab {
    /// An allocator with no blocks. Every request fails until it is given one.
    pub const fn new() -> Self {
        Slab {
            blocks: [Block::EMPTY; MAX_BLOCKS],
            count: 0,
            allocations: 0,
            frees: 0,
            double_frees: 0,
        }
    }

    /// Whether another block could be recorded.
    ///
    /// Asked *before* carving a block out of the arena, so that a full descriptor
    /// table costs nothing rather than an abandoned block.
    pub fn has_room(&self) -> bool {
        self.count < MAX_BLOCKS
    }

    /// Take an object of `class`.
    ///
    /// # Errors
    /// [`AllocError::Exhausted`] if no block of that class has a free object — the
    /// caller's cue to hand over another block. [`AllocError::Unmanaged`] if the
    /// block's memory has left the direct map, which would mean the map changed under
    /// the allocator.
    pub fn try_take(
        &mut self,
        class: usize,
        map: DirectMap,
        ctx: AllocContext,
    ) -> Result<NonNull<u8>, AllocError> {
        for block in self.blocks.iter_mut().take(self.count) {
            if block.class != class {
                continue;
            }
            let free = !block.used & block.mask();
            if free == 0 {
                continue;
            }
            let idx = usize::try_from(free.trailing_zeros()).map_err(|_| AllocError::Overflow)?;
            let off = idx.checked_mul(class).ok_or(AllocError::Overflow)?;
            let addr = block.virt.checked_add(off)?;
            let ptr = map.ptr_at(addr)?;

            // Only now, once nothing else can fail: a bit set for an object whose
            // pointer could not be formed would be an object leaked forever.
            block.used |= bit(idx);
            self.allocations = self.allocations.saturating_add(1);

            if ctx.wants_zero() {
                // SAFETY: object `idx` of this block was free a line ago and is now
                // marked allocated, so this allocator owns it exclusively and no
                // reference into it exists. `ptr_at` proved the address is inside the
                // direct-mapped window, and `off + class <= block.bytes()` because
                // `idx < objects`, so the whole object is inside the block.
                unsafe { poison::fill_zero(ptr, class) };
            }
            return Ok(ptr);
        }
        Err(AllocError::Exhausted)
    }

    /// Record a block of `class` carved out of the arena at `virt`.
    ///
    /// The caller must have allocated exactly [`block_layout`] for this class and
    /// must not use that memory for anything else afterwards; the slab takes it over.
    ///
    /// # Errors
    /// [`AllocError::Exhausted`] if the descriptor table is full,
    /// [`AllocError::EmptyRequest`] for a class with no objects, and
    /// [`AllocError::Unmanaged`] if the block is not inside the direct map.
    pub fn add_block(
        &mut self,
        class: usize,
        virt: KernAddr,
        map: DirectMap,
    ) -> Result<(), AllocError> {
        if !self.has_room() {
            return Err(AllocError::Exhausted);
        }
        let objects = objects_per_block(class);
        if class == 0 || objects == 0 {
            return Err(AllocError::EmptyRequest);
        }
        let bytes = class.checked_mul(objects).ok_or(AllocError::Overflow)?;
        // Both ends, so a descriptor can never describe memory the map does not
        // cover; every later offset calculation relies on that.
        let phys = map.to_phys(virt)?;
        let last = virt.checked_add(bytes.saturating_sub(1))?;
        map.to_phys(last)?;

        let slot = self
            .blocks
            .get_mut(self.count)
            .ok_or(AllocError::Exhausted)?;
        *slot = Block {
            virt,
            phys,
            class,
            objects,
            used: 0,
        };
        self.count = self.count.saturating_add(1);
        Ok(())
    }

    /// Give an object back.
    ///
    /// # Errors
    /// [`AllocError::Unmanaged`] if the pointer is in none of this allocator's
    /// blocks — which is how the [`Heap`](crate::Heap) learns to try the arena
    /// instead. [`AllocError::Misaligned`] if it points into the middle of an object,
    /// or if `class` is not the class the object actually belongs to.
    /// [`AllocError::NotAllocated`] for a double free.
    ///
    /// # Safety
    /// `ptr` must have come from this allocator with a layout whose class is `class`,
    /// and must not have been freed already. The checks above catch the cases they
    /// can; they do not make the call safe, because an object that was freed and then
    /// reissued looks exactly like a live one.
    pub unsafe fn dealloc(
        &mut self,
        ptr: NonNull<u8>,
        class: usize,
        _ctx: AllocContext,
    ) -> Result<(), AllocError> {
        let addr = KernAddr::new(ptr.addr().get());
        for block in self.blocks.iter_mut().take(self.count) {
            let Some(idx) = block.index_of(addr)? else {
                continue;
            };
            // The block owns this address; from here on every exit is an answer about
            // *this* object rather than a reason to keep searching.
            if block.class != class {
                // The layout handed to `dealloc` disagrees with the one the object
                // was allocated with. Refusing is the only safe answer: clearing a
                // bit computed from the wrong class would free somebody else's
                // object.
                return Err(AllocError::Misaligned);
            }
            let mine = bit(idx);
            if mine == 0 || block.used & mine == 0 {
                self.double_frees = self.double_frees.saturating_add(1);
                return Err(AllocError::NotAllocated);
            }
            block.used &= !mine;
            self.frees = self.frees.saturating_add(1);

            // SAFETY: the bit was set, so this allocator had handed the object out
            // and the caller is returning it; it is now marked free and cannot be
            // reissued until this function returns. The object lies wholly inside a
            // block whose extent was proved to be inside the direct map when the
            // block was recorded, so the pointer is valid for `class` bytes.
            unsafe { poison::fill_freed(ptr, class) };
            return Ok(());
        }
        Err(AllocError::Unmanaged)
    }

    /// Whether this address is inside one of the slab's blocks, on an object
    /// boundary or not.
    ///
    /// The question [`Heap`](crate::Heap) has to ask before letting the arena free
    /// something: a slab object handed to `dealloc` with a layout too large for any
    /// size class would otherwise be routed to the arena, which owns the block's
    /// memory and would happily poison a live object.
    pub fn owns(&self, ptr: NonNull<u8>) -> bool {
        self.offset_in_block(ptr).is_some()
    }

    /// Where an object is in physical memory, for a DMA-capable caller.
    ///
    /// # Errors
    /// [`AllocError::Unmanaged`] if the pointer is in none of this allocator's blocks.
    pub fn phys_of(&self, ptr: NonNull<u8>) -> Result<PhysAddr, AllocError> {
        let (block, off) = self.offset_in_block(ptr).ok_or(AllocError::Unmanaged)?;
        Ok(block.phys.checked_add(crate::widen(off))?)
    }

    /// The block containing `ptr` and the byte offset into it.
    ///
    /// Blocks are separate arena allocations and therefore disjoint, so the first
    /// match is the only one.
    fn offset_in_block(&self, ptr: NonNull<u8>) -> Option<(&Block, usize)> {
        let addr = KernAddr::new(ptr.addr().get());
        self.blocks.iter().take(self.count).find_map(|b| {
            let off = addr.diff(b.virt).ok()?;
            (off < b.bytes()).then_some((b, off))
        })
    }

    /// Current accounting.
    pub fn stats(&self) -> SlabStats {
        let mut classes = [ClassStats::default(); CLASS_COUNT];
        for (slot, size) in classes.iter_mut().zip(CLASS_SIZES) {
            slot.size = size;
        }

        let mut objects = 0usize;
        let mut objects_in_use = 0usize;
        let mut bytes_reserved = 0usize;
        let mut bytes_in_use = 0usize;

        for block in self.blocks.iter().take(self.count) {
            let used = block.in_use();
            objects = objects.saturating_add(block.objects);
            objects_in_use = objects_in_use.saturating_add(used);
            bytes_reserved = bytes_reserved.saturating_add(block.bytes());
            bytes_in_use = bytes_in_use.saturating_add(used.saturating_mul(block.class));

            if let Some(slot) = CLASS_SIZES
                .iter()
                .position(|c| *c == block.class)
                .and_then(|i| classes.get_mut(i))
            {
                slot.blocks = slot.blocks.saturating_add(1);
                slot.objects = slot.objects.saturating_add(block.objects);
                slot.in_use = slot.in_use.saturating_add(used);
            }
        }

        SlabStats {
            blocks: self.count,
            objects,
            objects_in_use,
            bytes_reserved,
            bytes_in_use,
            allocations: self.allocations,
            frees: self.frees,
            double_frees: self.double_frees,
            classes,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::AllocFlags;
    use crate::hostmem::{HostFrames, HostMemory};
    use crate::{Bump, poison};
    use hal::Arch;
    use hal::mock::{MockFull, MockTiny};

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

    /// An arena and a slab sharing one direct map, which is how [`crate::Heap`] wires
    /// them together. The frame source is held rather than made per call, because one
    /// made per call would restart at frame zero and hand out the same memory twice.
    struct Fixture<A: Arch> {
        mem: HostMemory,
        src: HostFrames<A>,
        bump: Bump<A>,
        slab: Slab,
    }

    impl<A: Arch> Fixture<A> {
        fn new() -> Self {
            let mem = HostMemory::new(ARENA);
            let bump = Bump::<A>::new(mem.direct_map());
            let src = mem.frames::<A>();
            Fixture {
                mem,
                src,
                bump,
                slab: Slab::new(),
            }
        }

        /// Give the arena `bytes` of memory to work with.
        fn reserve(&mut self, bytes: usize) {
            expect(self.bump.grow(&mut self.src, bytes));
        }

        /// Carve one more block of `class` out of the arena and give it to the slab.
        ///
        /// From the arena the tests already reserved, never by growing: the point is
        /// to exercise the slab's limits, and an arena that grows on demand would
        /// hide which limit was reached.
        fn add_block(&mut self, class: usize) -> Result<(), AllocError> {
            let bl = block_layout(class)?;
            let ptr = self.bump.try_alloc(bl, AllocContext::ATOMIC)?;
            self.slab
                .add_block(class, KernAddr::new(ptr.addr().get()), self.mem.direct_map())
        }
    }

    fn addr_of(p: NonNull<u8>) -> usize {
        p.addr().get()
    }

    // --- class selection ----------------------------------------------------

    #[test]
    fn a_request_picks_the_smallest_class_that_fits() {
        assert_eq!(class_for(layout(1, 1)), Some(16));
        assert_eq!(class_for(layout(16, 1)), Some(16));
        assert_eq!(class_for(layout(17, 1)), Some(32));
        assert_eq!(class_for(layout(1024, 1)), Some(1024));
        assert_eq!(class_for(layout(1025, 1)), None, "too big for the slab");
        assert_eq!(class_for(layout(0, 8)), None, "nothing to serve");
    }

    #[test]
    fn alignment_widens_the_class_rather_than_padding_the_object() {
        // A small object that must be strongly aligned comes from the class whose
        // objects have that alignment.
        assert_eq!(class_for(layout(16, 64)), Some(64));
        assert_eq!(class_for(layout(8, 256)), Some(256));
        assert_eq!(
            class_for(layout(8, 2048)),
            None,
            "an alignment past the largest class belongs to the arena"
        );
    }

    #[test]
    fn every_class_holds_a_sensible_number_of_objects() {
        for class in CLASS_SIZES {
            let n = objects_per_block(class);
            assert!((MIN_OBJECTS..=MAX_OBJECTS).contains(&n), "class {class}: {n}");
            let l = expect(block_layout(class));
            assert_eq!(l.size(), class * n);
            assert_eq!(l.align(), class, "a block is aligned like its objects");
        }
        // The classes are what makes the bitmap sound: one bit per object.
        assert!(CLASS_SIZES.iter().all(|c| objects_per_block(*c) <= 64));
    }

    #[test]
    fn the_class_table_does_not_depend_on_the_page_size() {
        // A class table derived from A::PAGE_SIZE would give MockTiny different
        // classes from MockFull for no reason anybody chose.
        assert_ne!(MockFull::PAGE_SIZE, MockTiny::PAGE_SIZE);
        assert_eq!(CLASS_SIZES[0], 16);
        assert!(!CLASS_SIZES.contains(&MockTiny::PAGE_SIZE) || CLASS_SIZES.contains(&256));
    }

    // --- allocation ---------------------------------------------------------

    fn objects_are_aligned_distinct_and_inside_their_block<A: Arch>() {
        let mut f = Fixture::<A>::new();
        f.reserve(64 * 1024);

        for class in CLASS_SIZES {
            expect(f.add_block(class));
            let n = objects_per_block(class);
            let mut seen: Vec<usize> = Vec::new();
            for _ in 0..n {
                let p = expect(f.slab.try_take(class, f.mem.direct_map(), AllocContext::ATOMIC));
                let a = addr_of(p);
                assert_eq!(a % class, 0, "class {class} gave {a:#x}");
                assert!(!seen.contains(&a), "class {class} handed out {a:#x} twice");
                seen.push(a);
            }
            // The block is now full and says so rather than overrunning.
            assert_eq!(
                f.slab
                    .try_take(class, f.mem.direct_map(), AllocContext::ATOMIC)
                    .err(),
                Some(AllocError::Exhausted),
                "class {class} must run out after {n} objects"
            );
        }
    }

    #[test]
    fn objects_are_aligned_distinct_and_inside_their_block_full() {
        objects_are_aligned_distinct_and_inside_their_block::<MockFull>();
    }

    #[test]
    fn objects_are_aligned_distinct_and_inside_their_block_tiny() {
        objects_are_aligned_distinct_and_inside_their_block::<MockTiny>();
    }

    fn an_empty_slab_asks_for_a_block_rather_than_panicking<A: Arch>() {
        let mut f = Fixture::<A>::new();
        assert_eq!(
            f.slab
                .try_take(16, f.mem.direct_map(), AllocContext::ATOMIC)
                .err(),
            Some(AllocError::Exhausted)
        );
        assert_eq!(f.slab.stats().blocks, 0);
    }

    #[test]
    fn an_empty_slab_asks_for_a_block_rather_than_panicking_full() {
        an_empty_slab_asks_for_a_block_rather_than_panicking::<MockFull>();
    }

    #[test]
    fn an_empty_slab_asks_for_a_block_rather_than_panicking_tiny() {
        an_empty_slab_asks_for_a_block_rather_than_panicking::<MockTiny>();
    }

    // --- reuse --------------------------------------------------------------

    fn a_freed_object_comes_straight_back<A: Arch>() {
        let mut f = Fixture::<A>::new();
        f.reserve(32 * 1024);
        expect(f.add_block(64));

        let n = objects_per_block(64);
        let mut held = Vec::new();
        for _ in 0..n {
            held.push(expect(f.slab.try_take(
                64,
                f.mem.direct_map(),
                AllocContext::ATOMIC,
            )));
        }
        assert_eq!(f.slab.stats().objects_in_use, n);

        // Free one in the middle: the bitmap has to find it again, not just the tail.
        let returned = match held.get(n / 2) {
            Some(p) => *p,
            None => panic!("held {n} objects"),
        };
        #[allow(unsafe_code)]
        // SAFETY: `returned` came from this slab at class 64 and is freed once.
        let r = unsafe { f.slab.dealloc(returned, 64, AllocContext::ATOMIC) };
        assert_eq!(r, Ok(()));
        assert_eq!(f.slab.stats().objects_in_use, n - 1);

        let again = expect(f.slab.try_take(64, f.mem.direct_map(), AllocContext::ATOMIC));
        assert_eq!(
            addr_of(again),
            addr_of(returned),
            "the only free object must be the freed one"
        );
        assert_eq!(f.slab.stats().objects_in_use, n);
    }

    #[test]
    fn a_freed_object_comes_straight_back_full() {
        a_freed_object_comes_straight_back::<MockFull>();
    }

    #[test]
    fn a_freed_object_comes_straight_back_tiny() {
        a_freed_object_comes_straight_back::<MockTiny>();
    }

    fn allocation_and_free_can_run_indefinitely<A: Arch>() {
        // The property a bump allocator does not have: a steady-state workload must
        // not consume the arena.
        let mut f = Fixture::<A>::new();
        f.reserve(16 * 1024);
        expect(f.add_block(128));
        let reserved = f.bump.stats().in_use;

        for _ in 0..1000 {
            let p = expect(f.slab.try_take(128, f.mem.direct_map(), AllocContext::ATOMIC));
            #[allow(unsafe_code)]
            // SAFETY: allocated on the previous line at class 128, freed once.
            let r = unsafe { f.slab.dealloc(p, 128, AllocContext::ATOMIC) };
            assert_eq!(r, Ok(()));
        }
        assert_eq!(f.slab.stats().objects_in_use, 0);
        assert_eq!(f.slab.stats().blocks, 1);
        assert_eq!(
            f.bump.stats().in_use,
            reserved,
            "a thousand allocate-free pairs must not have grown the arena"
        );
    }

    #[test]
    fn allocation_and_free_can_run_indefinitely_full() {
        allocation_and_free_can_run_indefinitely::<MockFull>();
    }

    #[test]
    fn allocation_and_free_can_run_indefinitely_tiny() {
        allocation_and_free_can_run_indefinitely::<MockTiny>();
    }

    // --- poisoning ----------------------------------------------------------

    fn freeing_poisons_exactly_the_object<A: Arch>() {
        let mut f = Fixture::<A>::new();
        f.reserve(16 * 1024);
        expect(f.add_block(64));

        let before = expect(f.slab.try_take(64, f.mem.direct_map(), AllocContext::ATOMIC));
        let target = expect(f.slab.try_take(64, f.mem.direct_map(), AllocContext::ATOMIC));
        let after = expect(f.slab.try_take(64, f.mem.direct_map(), AllocContext::ATOMIC));
        for p in [before, after] {
            #[allow(unsafe_code)]
            // SAFETY: a live 64-byte object from this slab, not otherwise referenced.
            unsafe {
                p.as_ptr().write_bytes(0x42, 64);
            }
        }

        #[allow(unsafe_code)]
        // SAFETY: `target` came from this slab at class 64 and is freed once.
        let r = unsafe { f.slab.dealloc(target, 64, AllocContext::ATOMIC) };
        assert_eq!(r, Ok(()));

        let bytes = match f.mem.bytes_at(addr_of(target), 64) {
            Some(b) => b,
            None => panic!("the object must be inside the backing buffer"),
        };
        if poison::ENABLED {
            assert!(
                bytes.iter().all(|b| *b == poison::FREED),
                "the whole object must be poisoned: {bytes:?}"
            );
        } else {
            assert!(bytes.iter().all(|b| *b != poison::FREED));
        }
        // Neighbours on both sides are untouched, so the fill did not run over.
        for p in [before, after] {
            assert_eq!(f.mem.bytes_at(addr_of(p), 64), Some(&[0x42u8; 64][..]));
        }
    }

    #[test]
    fn freeing_poisons_exactly_the_object_full() {
        freeing_poisons_exactly_the_object::<MockFull>();
    }

    #[test]
    fn freeing_poisons_exactly_the_object_tiny() {
        freeing_poisons_exactly_the_object::<MockTiny>();
    }

    fn zeroing_clears_a_reused_object<A: Arch>() {
        // The interesting case: an object that has been used, freed and poisoned,
        // and is then handed to a caller that asked for zeroes.
        let mut f = Fixture::<A>::new();
        f.reserve(16 * 1024);
        expect(f.add_block(32));
        let ctx = AllocContext::ATOMIC.with(AllocFlags::ZERO);

        let p = expect(f.slab.try_take(32, f.mem.direct_map(), AllocContext::ATOMIC));
        #[allow(unsafe_code)]
        // SAFETY: a live 32-byte object from this slab, not otherwise referenced.
        unsafe {
            p.as_ptr().write_bytes(0x99, 32);
        }
        #[allow(unsafe_code)]
        // SAFETY: allocated above at class 32, freed once.
        let r = unsafe { f.slab.dealloc(p, 32, AllocContext::ATOMIC) };
        assert_eq!(r, Ok(()));

        let again = expect(f.slab.try_take(32, f.mem.direct_map(), ctx));
        assert_eq!(addr_of(again), addr_of(p));
        assert_eq!(f.mem.bytes_at(addr_of(again), 32), Some(&[0u8; 32][..]));
    }

    #[test]
    fn zeroing_clears_a_reused_object_full() {
        zeroing_clears_a_reused_object::<MockFull>();
    }

    #[test]
    fn zeroing_clears_a_reused_object_tiny() {
        zeroing_clears_a_reused_object::<MockTiny>();
    }

    // --- bad frees ----------------------------------------------------------

    fn bad_frees_are_rejected_without_touching_anything<A: Arch>() {
        let mut f = Fixture::<A>::new();
        f.reserve(16 * 1024);
        expect(f.add_block(64));
        let p = expect(f.slab.try_take(64, f.mem.direct_map(), AllocContext::ATOMIC));

        #[allow(unsafe_code)]
        // SAFETY: a live 64-byte object from this slab, freed once here.
        let first = unsafe { f.slab.dealloc(p, 64, AllocContext::ATOMIC) };
        assert_eq!(first, Ok(()));

        // A double free the allocator can prove, because the bit is already clear.
        #[allow(unsafe_code)]
        // SAFETY: the call is expected to reject the pointer; the object is inside
        // memory this test owns either way.
        let second = unsafe { f.slab.dealloc(p, 64, AllocContext::ATOMIC) };
        assert_eq!(second, Err(AllocError::NotAllocated));
        assert_eq!(f.slab.stats().double_frees, 1);
        assert_eq!(f.slab.stats().frees, 1, "the second free is not counted");

        // A pointer into the middle of an object.
        let interior = match NonNull::new(p.as_ptr().wrapping_add(8)) {
            Some(q) => q,
            None => panic!("an interior address is never null"),
        };
        #[allow(unsafe_code)]
        // SAFETY: expected to be rejected on the offset check, before any write.
        let r = unsafe { f.slab.dealloc(interior, 64, AllocContext::ATOMIC) };
        assert_eq!(r, Err(AllocError::Misaligned));

        // The right object, the wrong class. Clearing a bit computed from the wrong
        // class would free a different object.
        let q = expect(f.slab.try_take(64, f.mem.direct_map(), AllocContext::ATOMIC));
        #[allow(unsafe_code)]
        // SAFETY: expected to be rejected on the class check, before any write.
        let r = unsafe { f.slab.dealloc(q, 32, AllocContext::ATOMIC) };
        assert_eq!(r, Err(AllocError::Misaligned));
        assert_eq!(f.slab.stats().objects_in_use, 1, "q is still allocated");

        // A pointer from somewhere else entirely.
        let other = HostMemory::new(4096);
        let foreign = expect(
            other
                .direct_map()
                .ptr_at(expect(other.direct_map().to_virt(PhysAddr::new(128)))),
        );
        #[allow(unsafe_code)]
        // SAFETY: expected to be rejected as unmanaged, before any write.
        let r = unsafe { f.slab.dealloc(foreign, 64, AllocContext::ATOMIC) };
        assert_eq!(r, Err(AllocError::Unmanaged));
        assert_eq!(
            other.byte_at(foreign.addr().get()),
            Some(0x5A),
            "a rejected free must not have poisoned anything"
        );
    }

    #[test]
    fn bad_frees_are_rejected_without_touching_anything_full() {
        bad_frees_are_rejected_without_touching_anything::<MockFull>();
    }

    #[test]
    fn bad_frees_are_rejected_without_touching_anything_tiny() {
        bad_frees_are_rejected_without_touching_anything::<MockTiny>();
    }

    // --- limits -------------------------------------------------------------

    fn the_descriptor_table_is_finite_and_says_so<A: Arch>() {
        let mut f = Fixture::<A>::new();
        f.reserve(ARENA);
        let mut added = 0;
        // 16-byte blocks are the cheapest, so this reaches the descriptor limit
        // rather than the arena limit.
        while f.slab.has_room() && f.add_block(16).is_ok() {
            added += 1;
            if added > MAX_BLOCKS {
                break;
            }
        }
        assert_eq!(added, MAX_BLOCKS, "the arena must outlast the table");
        assert!(!f.slab.has_room());
        assert_eq!(
            f.slab
                .add_block(16, KernAddr::new(f.mem.direct_map().virt_base().raw()), f.mem.direct_map())
                .err(),
            Some(AllocError::Exhausted)
        );
    }

    #[test]
    fn the_descriptor_table_is_finite_and_says_so_full() {
        the_descriptor_table_is_finite_and_says_so::<MockFull>();
    }

    #[test]
    fn the_descriptor_table_is_finite_and_says_so_tiny() {
        the_descriptor_table_is_finite_and_says_so::<MockTiny>();
    }

    fn a_block_outside_the_direct_map_is_refused<A: Arch>() {
        let mem = HostMemory::new(ARENA);
        let mut slab = Slab::new();
        let map = mem.direct_map();
        // One byte past the end of the window.
        let past = match map.virt_base().checked_add(ARENA) {
            Ok(a) => a,
            Err(e) => panic!("unexpected {e:?}"),
        };
        assert_eq!(slab.add_block(16, past, map).err(), Some(AllocError::Unmanaged));
        // And a block that starts inside and ends outside.
        let straddling = match map.virt_base().checked_add(ARENA - 16) {
            Ok(a) => a,
            Err(e) => panic!("unexpected {e:?}"),
        };
        assert_eq!(
            slab.add_block(16, straddling, map).err(),
            Some(AllocError::Unmanaged),
            "a block must be wholly inside the window, not merely start inside it"
        );
        assert_eq!(slab.stats().blocks, 0);
    }

    #[test]
    fn a_block_outside_the_direct_map_is_refused_full() {
        a_block_outside_the_direct_map_is_refused::<MockFull>();
    }

    #[test]
    fn a_block_outside_the_direct_map_is_refused_tiny() {
        a_block_outside_the_direct_map_is_refused::<MockTiny>();
    }

    // --- accounting ---------------------------------------------------------

    fn stats_describe_the_classes<A: Arch>() {
        let mut f = Fixture::<A>::new();
        f.reserve(32 * 1024);
        expect(f.add_block(32));
        expect(f.add_block(256));

        let _a = expect(f.slab.try_take(32, f.mem.direct_map(), AllocContext::ATOMIC));
        let _b = expect(f.slab.try_take(256, f.mem.direct_map(), AllocContext::ATOMIC));
        let _c = expect(f.slab.try_take(256, f.mem.direct_map(), AllocContext::ATOMIC));

        let s = f.slab.stats();
        assert_eq!(s.blocks, 2);
        assert_eq!(s.objects_in_use, 3);
        assert_eq!(s.bytes_in_use, 32 + 256 + 256);
        assert_eq!(
            s.bytes_reserved,
            32 * objects_per_block(32) + 256 * objects_per_block(256)
        );
        assert_eq!(s.allocations, 3);

        for c in s.classes {
            match c.size {
                32 => assert_eq!((c.blocks, c.in_use), (1, 1)),
                256 => assert_eq!((c.blocks, c.in_use), (1, 2)),
                _ => assert_eq!((c.blocks, c.objects, c.in_use), (0, 0, 0)),
            }
        }
    }

    #[test]
    fn stats_describe_the_classes_full() {
        stats_describe_the_classes::<MockFull>();
    }

    #[test]
    fn stats_describe_the_classes_tiny() {
        stats_describe_the_classes::<MockTiny>();
    }
}

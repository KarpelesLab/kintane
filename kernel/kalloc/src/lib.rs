//! The kernel heap. Every allocation is fallible.
//!
//! `docs/decisions.md` D6 says the `alloc` crate is not linked, because its
//! collections abort when an allocation fails and a kernel may not abort because a
//! buffer could not be grown. So this unit provides the allocator that `alloc` would
//! have provided, with one difference that shapes every signature below: **there is
//! no infallible path.** [`heap::Heap::try_alloc`] returns a `Result`, and so does
//! everything it is built out of.
//!
//! # The layers
//!
//! ```text
//!   Heap            routes by size, keeps the totals, consults the Injector
//!    ├─ Slab        size classes 16..1024, free-list reuse, O(1) alloc and free
//!    ├─ Buddy       whole-page blocks 2^0..2^10 pages, split and merged; optional
//!    └─ Bump        an arena over contiguous frames; the bootstrap heap, and the
//!         │         fallback for anything the other two cannot serve
//!         └─ FrameSource   ── mm::FrameAllocator, in a kernel image
//! ```
//!
//! The buddy allocator sits beside the arena rather than on it. It is handed one run of
//! frames ([`heap::Heap::attach_pages`]) and gives that run back whole when nothing in
//! it is allocated. See [`buddy`] for why it manages a run and not the machine.
//!
//! The slab sits *on top of* the bump rather than beside it: a slab block is an
//! ordinary bump allocation. That means there is exactly one place that turns frames
//! into heap memory, and one number — [`bump::BumpStats::arena_bytes`] — that is the
//! heap's whole footprint.
//!
//! # The physical-to-virtual question, which is the interesting one
//!
//! A frame allocator hands out [`hal::PhysAddr`]. A heap hands out pointers, which
//! are virtual. Something has to bridge that, and today there is no page-table code
//! to do it with: the kernel runs on an identity map the loader set up, so physical
//! and virtual happen to be equal in low memory.
//!
//! Writing `phys.to_usize()? as *mut u8` would work today and would be wrong the
//! morning the kernel moves to the high half — and it would be wrong *silently*,
//! because nothing in the type system records the assumption. So the assumption is a
//! value instead: [`directmap::DirectMap`], a window `[phys_base, phys_base + len)`
//! that the caller asserts is mapped at `virt_base`, handed to the heap at
//! construction. Today the bootstrap passes [`directmap::DirectMap::identity`] and
//! the offset is zero. When the direct map moves, one construction site changes and
//! nothing else does. See that module for what it does and does not promise.
//!
//! # Errors
//!
//! This unit reuses [`mm::AllocError`] rather than defining its own. Two types both
//! called `AllocError` in the same memory stack would mean a `From` impl at every
//! boundary and a coin flip at every `use` site, and `docs/architecture.md` writes
//! the heap's signature as `Result<Box<T>, AllocError>` — singular. The frame-shaped
//! variants read naturally here:
//!
//! | Variant | What it means for the heap |
//! |---|---|
//! | `EmptyRequest` | a zero-sized layout; there is nothing to hand back that could be freed |
//! | `Exhausted` | no arena space, and the frame source had nothing (or was [`frames::NoFrames`]) |
//! | `Fragmented` | the frame source had frames but no adjacent run long enough |
//! | `Misaligned` | a layout whose alignment is not a power of two, or a `dealloc` layout that does not match the allocation |
//! | `Overflow` | address arithmetic left the representable range — including a physical address that does not fit this target's pointer |
//! | `Unmanaged` | a pointer this allocator never handed out |
//! | `NotAllocated` | a double free, where the allocator can prove it |
//! | `NotInPool` / `StorageTooSmall` / `NoUsableMemory` | not produced here; they belong to frame-allocator construction |
//!
//! # Concurrency
//!
//! Like `mm`, every type here is a plain `&mut self` data structure with no interior
//! locking. `kernel/sync` picks the lock by architecture capability and hardcoding
//! either choice here would defeat that. The lock order, for when there is more than
//! one lock to order: **heap before frame allocator.** The heap calls into a
//! [`frames::FrameSource`] while holding its own state; nothing calls back the other
//! way.
//!
//! # `unsafe`
//!
//! Denied at the crate root and re-enabled module by module, each saying why at the
//! top of its own file. [`directmap`] forms a pointer from an integer, in one
//! expression; [`poison`] writes bytes; [`bump`] and [`slab`] call into [`poison`]
//! for blocks they have just proved they own; [`heap`] forwards a `dealloc`, and zeroes
//! or poisons a buddy block the buddy allocator has just handed out or taken back.
//! Every `unsafe` block has a `// SAFETY:` comment and every `unsafe fn` has a
//! `# Safety` section stating the caller's obligation. [`buddy`], [`context`],
//! [`frames`] and [`inject`] have none at all.
//!
//! `dealloc` is `unsafe` and that is deliberate. It cannot be made safe: safe code
//! could free a pointer twice, and between the two calls the block may have been
//! handed to another owner, so no amount of internal bookkeeping distinguishes the
//! second free from a legitimate one. The slab and the bump both validate what they
//! can — an unknown pointer is `Unmanaged`, an interior pointer is `Misaligned`, and
//! a slab object that is already free is `NotAllocated` — but validation is a
//! diagnostic, not the contract. The safe deliverable is the owning wrapper (`Box`,
//! `Vec`) that calls `dealloc` from its own `Drop`, and that is the next unit, not
//! this one.
//!
//! # What this unit does not do yet
//!
//! Stated plainly so nobody has to discover it:
//!
//! * **The arena never returns frames to the frame allocator.** A slab block whose objects are all
//!   free stays a slab block; a bump region stays a bump region. The bookkeeping to do it exists
//!   ([`bump::Bump`] records each region's physical start and frame count) but no caller wants it
//!   yet. The buddy allocator's run is the exception: [`heap::Heap::detach_pages`] gives it back
//!   once it is empty.
//! * **There is one buddy run per heap**, fixed at attach time. Growing it would mean a second run
//!   and a lookup by address, which is worth doing when a workload needs it.
//! * **The bump reuses memory only in the immediate LIFO case.** See [`bump`].
//! * **`realloc` does not exist.** A growable collection allocates, copies and frees.
//! * **Most [`context::AllocFlags`] are advisory.** See [`context`] for the table of which, and why
//!   each one is in the type before it is honoured.
//! * **The slab holds at most [`slab::MAX_BLOCKS`] blocks**, because its metadata is an array
//!   inside the allocator rather than a header inside each block. That is a deliberate trade: it
//!   keeps the slab free of `unsafe` reads and writes into heap memory. Past the limit, small
//!   objects fall back to the bump.

// `no_std` except under the host test harness, which needs `std` to link `libtest`.
#![cfg_attr(not(test), no_std)]
// Re-enabled, with justification, in `directmap`, `poison`, `bump` and `slab`. See
// the crate documentation above and docs/coding-standards.md.
#![deny(unsafe_code)]

use core::alloc::Layout;

pub mod buddy;
pub mod bump;
pub mod context;

pub mod frames;
pub mod heap;
pub mod inject;
pub mod poison;
pub mod slab;

pub use buddy::{Buddy, BuddyStats};
pub use bump::{Bump, BumpStats};
pub use context::{AllocContext, AllocFlags, NumaNode};
pub use frames::{FrameSource, NoFrames};
pub use heap::{Detach, Heap, HeapStats};
pub use inject::{Injector, Site};
pub use mm::AllocError;
pub use mm::directmap::DirectMap;
pub use slab::{ClassStats, Slab, SlabStats};

/// Reject a layout no allocator here could honour, before any state is touched.
///
/// [`Layout`] already guarantees a power-of-two alignment and a size that does not
/// overflow when rounded up to it, so this adds exactly two rules of our own:
///
/// * **A zero-sized request is an error**, not a dangling pointer. `alloc`'s answer is to hand back
///   `align` as a pointer, which is fine when the caller is a Rust collection that knows never to
///   dereference it and is a trap when the caller is a driver that does. There is nothing to free,
///   so there is nothing to return.
/// * **A size that cannot be rounded up to its own alignment is an error**, which is `Layout`'s
///   rule restated in our terms so the failure is `Overflow` here rather than a wrap inside the
///   bump's cursor arithmetic.
///
/// Everything else — an alignment larger than a page, a size larger than the machine
/// — is rejected later by whichever allocator could not satisfy it, and reported as
/// [`AllocError::Exhausted`], because "absurd" and "more than is left" are the same
/// answer to the caller.
///
/// # Errors
/// [`AllocError::EmptyRequest`], [`AllocError::Misaligned`] or
/// [`AllocError::Overflow`].
pub fn validate(layout: Layout) -> Result<(), AllocError> {
    check_layout(layout).map(|_| ())
}

/// [`validate`], returning the size and alignment the caller was going to ask for.
pub(crate) fn check_layout(layout: Layout) -> Result<(usize, usize), AllocError> {
    let size = layout.size();
    let align = layout.align();
    if size == 0 {
        return Err(AllocError::EmptyRequest);
    }
    // `Layout` upholds this already. Checked anyway: the alignment feeds a
    // `mask = align - 1` in three places, and every one of them is wrong for a
    // non-power-of-two, so the invariant is worth one comparison rather than three
    // comments saying it holds.
    if !align.is_power_of_two() {
        return Err(AllocError::Misaligned);
    }
    size.checked_add(align.saturating_sub(1))
        .ok_or(AllocError::Overflow)?;
    Ok((size, align))
}

/// Widen a `usize` to the `u64` physical sizes and addresses are expressed in.
///
/// The same function, and the same argument for it, as `mm::widen`: one `as` to
/// audit rather than one per call site, with the "no target has a `usize` wider than
/// 64 bits" assumption turned into a build failure if it ever stops holding.
#[allow(clippy::as_conversions)]
pub(crate) const fn widen(v: usize) -> u64 {
    const _: () = assert!(core::mem::size_of::<usize>() <= core::mem::size_of::<u64>());
    v as u64
}

/// Narrow a `u64` to a `usize`, which genuinely fails on a 32-bit target.
///
/// This is not defensive programming. A frame above 4 GiB on an i686-with-PAE kernel
/// has a physical address that does not fit in a pointer, so it cannot be reached
/// through any direct map that target could have — and the correct response is an
/// error at the conversion rather than a truncated address that points at somebody
/// else's memory.
pub(crate) fn narrow(v: u64) -> Result<usize, AllocError> {
    usize::try_from(v).map_err(|_| AllocError::Overflow)
}

// Host memory standing in for physical frames. Test scaffolding only; not compiled
// into a kernel image. Declared last so the cfg-in-body lint's test exemption, which
// runs to the end of the enclosing block, cannot mask anything above it.
#[cfg(test)]
mod hostmem;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_zero_sized_request_is_an_error_not_a_dangling_pointer() {
        let l = match Layout::from_size_align(0, 8) {
            Ok(l) => l,
            Err(e) => panic!("unexpected {e:?}"),
        };
        assert_eq!(validate(l), Err(AllocError::EmptyRequest));
    }

    #[test]
    fn an_ordinary_layout_is_accepted() {
        let l = match Layout::from_size_align(24, 8) {
            Ok(l) => l,
            Err(e) => panic!("unexpected {e:?}"),
        };
        assert_eq!(validate(l), Ok(()));
    }

    #[test]
    fn narrowing_reports_loss_rather_than_truncating() {
        // The i686-with-PAE shape, on whichever host is running the tests.
        if core::mem::size_of::<usize>() == 4 {
            assert_eq!(narrow(0x1_0000_0000), Err(AllocError::Overflow));
        } else {
            assert_eq!(narrow(0x1_0000_0000), Ok(0x1_0000_0000));
        }
        assert_eq!(narrow(u64::MAX).is_err(), core::mem::size_of::<usize>() < 8);
    }
}

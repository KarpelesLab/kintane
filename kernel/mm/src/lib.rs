//! Physical memory management.
//!
//! This is the first subsystem written against the claim in `docs/portability.md`:
//! one implementation, generic over `A: Arch`, with the page size, the physical
//! address width and the machine word arriving through the trait rather than through
//! a `#ifdef`. Nothing in here names an architecture, and the host tests instantiate
//! it twice — `MockFull` at a 4096-byte page and `MockTiny` at 256 — so a hardcoded
//! 4096 anywhere is a test failure rather than a bug discovered on a Cortex-M.
//!
//! # What this layer is and is not
//!
//! [`phys::FrameAllocator`] owns exactly one question: *which physical frames are in
//! use*. It does not map anything, does not know whether the machine translates
//! addresses, and therefore carries no [`hal::HasMmu`] bound — a no-MMU target needs
//! a frame allocator just as much as a server does, it simply hands the frames to a
//! region allocator instead of to a page table. That is why this sits in `mm` rather
//! than in `mm::paged`.
//!
//! It deliberately never dereferences a physical address. The kernel has no
//! physical-to-virtual mapping this early, and inventing one here would be the first
//! step towards an allocator that only works on targets with a direct map.
//!
//! # Failure
//!
//! Every operation that can fail returns [`AllocError`]. `docs/architecture.md` is
//! explicit that allocation failure is not a panic, and this unit takes the stronger
//! position that *nothing* here panics: there is no `unwrap`, no indexing, no
//! unchecked address arithmetic, and no `unsafe` (`deny(unsafe_code)` below). An
//! allocator that aborts when the memory map is strange is an allocator that aborts
//! during early boot on the one machine you cannot debug.
//!
//! # Concurrency
//!
//! The allocator is a plain `&mut self` data structure with no interior locking.
//! Serialisation belongs to `kernel/sync`, whose lock type is itself selected by
//! architecture capability (`HasCas` or interrupt masking), and hardcoding either
//! choice here would defeat that selection. Callers hold the lock; this type holds
//! the bits.

// `no_std` except under the host test harness, which needs `std` to link `libtest`.
// This matches `hal` and `boot_protocol`; the kernel build never sets `test`.
#![cfg_attr(not(test), no_std)]
// No module here has needed `unsafe` yet. The backing store arrives as a safe
// `&mut [u8]` and every access goes through `get`/`get_mut`, so the whole unit is
// checkable by the compiler. A module that later needs raw access (a direct map,
// say) overrides this with written justification, per docs/coding-standards.md.
#![deny(unsafe_code)]

pub mod directmap;
pub mod frame;
pub mod paged;
pub mod phys;

pub use directmap::DirectMap;

pub use frame::{Frame, FrameIter, FrameRange};
pub use phys::{FrameAllocator, FrameStats, bitmap_bytes};

use hal::AddrOverflow;

/// Why an allocation, a free, or the construction of an allocator did not succeed.
///
/// The distinction between [`Self::Exhausted`] and [`Self::Fragmented`] is load
/// bearing rather than decorative: a caller that cannot get a contiguous run may
/// still make progress with several smaller ones, but a caller that is out of frames
/// entirely must shed work. Collapsing both into one variant hides that choice.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum AllocError {
    /// Not enough free frames exist to satisfy the request.
    Exhausted,
    /// Enough frames are free, but not enough *adjacent* ones.
    Fragmented,
    /// A request for zero frames. Returning an empty range instead would hand the
    /// caller something it cannot free and cannot use.
    EmptyRequest,
    /// The backing store handed to the allocator is smaller than the memory map
    /// requires. `needed` is the exact byte count, so a caller that guessed can
    /// retry rather than having to re-derive it.
    StorageTooSmall {
        /// Bytes the allocator needs for this memory map.
        needed: usize,
    },
    /// The memory map describes no whole usable frame at all.
    NoUsableMemory,
    /// Address arithmetic left the representable range, or a frame index did not fit
    /// in `usize` on this target. The second case is real: a 32-bit kernel can be
    /// handed a map describing more frames than it can index.
    Overflow,
    /// The address lies outside the span this allocator was built over.
    Unmanaged,
    /// The frame lies inside the managed span but was never part of the usable pool
    /// — firmware-reserved memory, a hole between regions, or the kernel image.
    NotInPool,
    /// The frame is already free. A double free.
    NotAllocated,
    /// The address is not on a frame boundary.
    Misaligned,
}

impl From<AddrOverflow> for AllocError {
    fn from(_: AddrOverflow) -> Self {
        AllocError::Overflow
    }
}

/// Widen a `usize` to the `u64` that physical addresses are always expressed in.
///
/// This is the only `as` conversion in the unit, and it is here rather than at its
/// call sites so there is one thing to audit. The assertion is evaluated at compile
/// time, which turns "no target has a `usize` wider than 64 bits" from an assumption
/// into a build failure if it ever stops being true.
#[allow(clippy::as_conversions)]
pub(crate) const fn widen(v: usize) -> u64 {
    const _: () = assert!(core::mem::size_of::<usize>() <= core::mem::size_of::<u64>());
    v as u64
}

/// Narrow a `u64` to a `usize`, which genuinely fails on a 32-bit target.
///
/// The failing case is not hypothetical: `PhysAddr` is 64-bit on i686 precisely
/// because PAE puts 36 bits of physical address behind a 32-bit pointer, so a frame
/// index derived from a high address can exceed what `usize` can hold.
pub(crate) fn narrow(v: u64) -> Result<usize, AllocError> {
    usize::try_from(v).map_err(|_| AllocError::Overflow)
}

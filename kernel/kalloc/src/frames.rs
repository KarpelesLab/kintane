//! Where the heap's memory comes from.
//!
//! The heap needs one thing from physical memory management: a run of adjacent
//! frames, on request, or an error. That is a narrower interface than
//! `mm::FrameAllocator`, and naming it has three consequences worth the trait:
//!
//! * The heap does not need to know how a frame allocator is *built*. Construction takes a boot
//!   memory map and a caller-supplied bitmap, neither of which is any of the heap's business, and
//!   depending on the type would drag `boot_protocol` into this unit's dependency list for no
//!   reason.
//! * The heap does not hold a frame allocator. It borrows one for the duration of a call that might
//!   need to grow. `mm`'s allocator is a `&mut self` structure behind whatever lock `kernel/sync`
//!   selected, and `mm::paged` needs it for page tables too, so a heap that owned it would be a
//!   heap that had taken the machine's frames hostage. Passing it per call also states the lock
//!   order in the signature: heap first, frames second.
//! * The host tests get to hand the heap frames that correspond to real memory on the machine
//!   running the tests. That is not a convenience — it is what lets the allocator's *pointers* be
//!   exercised, poison be read back, and alignment be checked against an address rather than
//!   against arithmetic.

use hal::Arch;
use mm::{AllocError, FrameAllocator, FrameRange};

/// A supply of contiguous physical frames.
///
/// Contiguous rather than one-at-a-time because a heap region has to be a single
/// range of addresses: a bump allocator walking a cursor cannot step over a hole,
/// and neither can an object that spans two frames.
pub trait FrameSource<A: Arch> {
    /// Take `frames` adjacent frames.
    ///
    /// # Errors
    /// [`AllocError::EmptyRequest`] for zero, [`AllocError::Exhausted`] when there is
    /// not that much memory left at all, and [`AllocError::Fragmented`] when there is
    /// but no run of it is adjacent. A caller that can make progress with less should
    /// treat the third differently from the second.
    fn take(&mut self, frames: usize) -> Result<FrameRange<A>, AllocError>;
}

impl<A: Arch> FrameSource<A> for FrameAllocator<'_, A> {
    fn take(&mut self, frames: usize) -> Result<FrameRange<A>, AllocError> {
        self.alloc_contiguous(frames)
    }
}

/// A frame source with no frames.
///
/// Not a placeholder: it is how "allocate, but do not grow the heap" is expressed.
/// The alternative would be a second copy of every allocation path differing only in
/// whether it may call [`FrameSource::take`], and two copies of an allocator's fast
/// path is two places for it to be wrong.
///
/// It is also what a caller uses when growth is not permitted for a reason of its
/// own — an interrupt handler that may not take the frame allocator's lock, say.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoFrames;

impl<A: Arch> FrameSource<A> for NoFrames {
    fn take(&mut self, _frames: usize) -> Result<FrameRange<A>, AllocError> {
        Err(AllocError::Exhausted)
    }
}

#[cfg(test)]
mod tests {
    use hal::mock::{MockFull, MockTiny};

    use super::*;

    fn a_source_with_nothing_in_it_is_exhausted<A: Arch>() {
        let mut src = NoFrames;
        assert_eq!(
            FrameSource::<A>::take(&mut src, 1).map(|r| r.count()),
            Err(AllocError::Exhausted)
        );
        assert_eq!(
            FrameSource::<A>::take(&mut src, 0).map(|r| r.count()),
            Err(AllocError::Exhausted)
        );
    }

    #[test]
    fn a_source_with_nothing_in_it_is_exhausted_full() {
        a_source_with_nothing_in_it_is_exhausted::<MockFull>();
    }

    #[test]
    fn a_source_with_nothing_in_it_is_exhausted_tiny() {
        a_source_with_nothing_in_it_is_exhausted::<MockTiny>();
    }
}

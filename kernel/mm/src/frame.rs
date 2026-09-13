//! The unit of physical allocation.
//!
//! A [`Frame`] is a page-sized, page-aligned block of physical memory. It is a
//! distinct type from [`PhysAddr`] on purpose: an address may point anywhere, a frame
//! names a whole block the allocator can hand out and take back. Passing an
//! arbitrary address where a frame is expected is the bug this removes.
//!
//! The frame size is `A::PAGE_SIZE` and appears nowhere else. Everything that needs
//! it — index arithmetic, alignment, the size of a range in bytes — goes through
//! [`Frame::SIZE`], which is what makes the same code correct at 4096 bytes and at
//! 256.

use core::cmp::Ordering;
use core::fmt;
use core::hash::{Hash, Hasher};
use core::marker::PhantomData;

use hal::{Arch, PhysAddr};

use crate::{AllocError, widen};

/// One physical page frame.
///
/// Copy and cheap: this is a number, not a handle, and holding one implies nothing
/// about ownership. The allocator's bitmap is the only record of who has what.
pub struct Frame<A: Arch> {
    start: PhysAddr,
    // `fn() -> A` rather than `A` so that `Frame` is unconditionally `Copy`, `Send`
    // and `Sync` regardless of what the architecture marker type happens to be. The
    // parameter is a tag, not something we store.
    _arch: PhantomData<fn() -> A>,
}

impl<A: Arch> Frame<A> {
    /// Bytes in one frame on this architecture.
    pub const SIZE: usize = A::PAGE_SIZE;

    /// Monomorphisation-time proof that the architecture's page size can actually be
    /// used as an alignment.
    ///
    /// `align_down` and the index arithmetic below are only correct for a non-zero
    /// power of two, and `is_power_of_two` is false for zero. An architecture that
    /// declared `PAGE_SIZE = 3000` fails to build the moment it reaches this code,
    /// rather than silently mis-aligning every frame — which is the same bargain the
    /// capability traits make, applied to a constant.
    const SIZE_IS_USABLE: () = assert!(A::PAGE_SIZE.is_power_of_two());

    /// The frame size as the `u64` that physical arithmetic is done in.
    pub(crate) const fn bytes() -> u64 {
        widen(A::PAGE_SIZE)
    }

    /// Frame number containing byte address `addr`.
    ///
    /// Every division by the page size in this unit goes through here. The divisor
    /// is a non-zero power of two by [`Self::SIZE_IS_USABLE`], proved at
    /// monomorphisation time, so the division cannot trap — but that proof lives in
    /// a constant the lint cannot see, which is why it is asserted in one place
    /// rather than argued at four call sites.
    #[allow(clippy::arithmetic_side_effects)]
    pub(crate) fn index_of(addr: u64) -> u64 {
        #[allow(clippy::let_unit_value)]
        let () = Self::SIZE_IS_USABLE;
        addr / Self::bytes()
    }

    /// The single constructor, so the compile-time check above has exactly one place
    /// to be forced from.
    fn at(start: PhysAddr) -> Self {
        #[allow(clippy::let_unit_value)]
        let () = Self::SIZE_IS_USABLE;
        Frame {
            start,
            _arch: PhantomData,
        }
    }

    /// The frame containing `addr`, rounding down.
    pub fn containing(addr: PhysAddr) -> Self {
        Self::at(addr.align_down(Self::bytes()))
    }

    /// The frame starting exactly at `addr`.
    ///
    /// Fallible rather than rounding, because a caller that hands over an unaligned
    /// address has a different bug from one that means "the frame around here", and
    /// quietly rounding turns the first into the second.
    ///
    /// # Errors
    /// [`AllocError::Misaligned`] if `addr` is not on a frame boundary.
    pub fn from_start(addr: PhysAddr) -> Result<Self, AllocError> {
        if addr.is_aligned(Self::bytes()) {
            Ok(Self::at(addr))
        } else {
            Err(AllocError::Misaligned)
        }
    }

    /// The frame with index `n`, counting from physical zero.
    ///
    /// # Errors
    /// [`AllocError::Overflow`] if the frame's byte address exceeds 64 bits.
    pub fn from_number(n: u64) -> Result<Self, AllocError> {
        let start = n.checked_mul(Self::bytes()).ok_or(AllocError::Overflow)?;
        Ok(Self::at(PhysAddr::new(start)))
    }

    /// Index of this frame, counting from physical zero.
    ///
    /// Stays `u64` on every target. A 32-bit kernel with PAE has frame numbers that
    /// do not fit in a pointer, and narrowing here would lose the high frames on
    /// exactly the machine that has them.
    pub fn number(self) -> u64 {
        Self::index_of(self.start.raw())
    }

    /// First byte of the frame.
    pub fn start(self) -> PhysAddr {
        self.start
    }

    /// One past the last byte of the frame.
    ///
    /// # Errors
    /// [`AllocError::Overflow`] for the last frame of the address space.
    pub fn end(self) -> Result<PhysAddr, AllocError> {
        Ok(self.start.checked_add(Self::bytes())?)
    }

    /// The next frame upwards.
    ///
    /// # Errors
    /// [`AllocError::Overflow`] for the last frame of the address space.
    pub fn next(self) -> Result<Self, AllocError> {
        Self::from_number(self.number().checked_add(1).ok_or(AllocError::Overflow)?)
    }
}

// Written out rather than derived: `derive` would add an `A: Copy` bound and friends,
// which would then propagate into every signature mentioning a `Frame`. The data is
// one `PhysAddr` and a tag, so none of these need anything of `A`.

impl<A: Arch> Clone for Frame<A> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<A: Arch> Copy for Frame<A> {}

impl<A: Arch> PartialEq for Frame<A> {
    fn eq(&self, other: &Self) -> bool {
        self.start == other.start
    }
}

impl<A: Arch> Eq for Frame<A> {}

impl<A: Arch> PartialOrd for Frame<A> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<A: Arch> Ord for Frame<A> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.start.cmp(&other.start)
    }
}

impl<A: Arch> Hash for Frame<A> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.start.hash(state);
    }
}

impl<A: Arch> fmt::Debug for Frame<A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The architecture name is worth the characters: a frame printed during a
        // host test says which profile produced it.
        write!(f, "Frame<{}>({})", A::NAME, self.start)
    }
}

/// A run of adjacent frames, as returned by a contiguous allocation.
///
/// Kept as a start-and-count rather than a collection because there is no heap to
/// hold a collection in, and because a contiguous run is exactly the shape a DMA
/// buffer or a page-table level wants.
pub struct FrameRange<A: Arch> {
    start: Frame<A>,
    count: usize,
}

impl<A: Arch> FrameRange<A> {
    /// A range of `count` frames beginning at `start`.
    ///
    /// Rejects an empty range for the same reason [`AllocError::EmptyRequest`]
    /// exists, and rejects one whose end would not be representable, so that
    /// [`Self::end_exclusive`] cannot fail later.
    ///
    /// # Errors
    /// [`AllocError::EmptyRequest`] for `count == 0`, [`AllocError::Overflow`] if the
    /// run would run off the end of the address space.
    pub fn new(start: Frame<A>, count: usize) -> Result<Self, AllocError> {
        if count == 0 {
            return Err(AllocError::EmptyRequest);
        }
        start
            .number()
            .checked_add(widen(count))
            .ok_or(AllocError::Overflow)?;
        Ok(FrameRange { start, count })
    }

    /// First frame of the run.
    pub fn start(&self) -> Frame<A> {
        self.start
    }

    /// How many frames the run covers. Never zero.
    pub fn count(&self) -> usize {
        self.count
    }

    /// Index one past the last frame. Checked at construction, so infallible here.
    pub fn end_exclusive(&self) -> u64 {
        self.start.number().saturating_add(widen(self.count))
    }

    /// Size of the run in bytes.
    ///
    /// `u64` rather than `usize`: a 32-bit kernel can legitimately own a run larger
    /// than its own address space, because these are physical frames it has not
    /// mapped.
    ///
    /// # Errors
    /// [`AllocError::Overflow`] if the run is longer than the address space.
    pub fn len_bytes(&self) -> Result<u64, AllocError> {
        widen(self.count)
            .checked_mul(Frame::<A>::bytes())
            .ok_or(AllocError::Overflow)
    }

    /// Whether `frame` falls inside the run.
    pub fn contains(&self, frame: Frame<A>) -> bool {
        let n = frame.number();
        n >= self.start.number() && n < self.end_exclusive()
    }

    /// The frames of the run, in ascending order.
    pub fn iter(&self) -> FrameIter<A> {
        FrameIter {
            next: self.start.number(),
            remaining: self.count,
            _arch: PhantomData,
        }
    }
}

impl<A: Arch> Clone for FrameRange<A> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<A: Arch> Copy for FrameRange<A> {}

impl<A: Arch> PartialEq for FrameRange<A> {
    fn eq(&self, other: &Self) -> bool {
        self.start == other.start && self.count == other.count
    }
}

impl<A: Arch> Eq for FrameRange<A> {}

impl<A: Arch> fmt::Debug for FrameRange<A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "FrameRange<{}>({}, {} frames)",
            A::NAME,
            self.start.start(),
            self.count
        )
    }
}

impl<A: Arch> IntoIterator for FrameRange<A> {
    type Item = Frame<A>;
    type IntoIter = FrameIter<A>;

    fn into_iter(self) -> FrameIter<A> {
        self.iter()
    }
}

impl<A: Arch> IntoIterator for &FrameRange<A> {
    type Item = Frame<A>;
    type IntoIter = FrameIter<A>;

    fn into_iter(self) -> FrameIter<A> {
        self.iter()
    }
}

/// Iterator over the frames of a [`FrameRange`].
pub struct FrameIter<A: Arch> {
    next: u64,
    remaining: usize,
    _arch: PhantomData<fn() -> A>,
}

impl<A: Arch> Iterator for FrameIter<A> {
    type Item = Frame<A>;

    fn next(&mut self) -> Option<Frame<A>> {
        if self.remaining == 0 {
            return None;
        }
        // Both of these were proved representable when the range was constructed;
        // the fallible forms are used anyway so that a future caller who builds an
        // iterator some other way gets a short iteration rather than a panic.
        let frame = Frame::from_number(self.next).ok()?;
        self.next = self.next.checked_add(1)?;
        self.remaining = self.remaining.saturating_sub(1);
        Some(frame)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}

impl<A: Arch> ExactSizeIterator for FrameIter<A> {}

#[cfg(test)]
mod tests {
    use super::*;
    use hal::mock::{MockFull, MockTiny};

    /// Everything below is written in units of frames rather than bytes, which is
    /// what lets one body of assertions hold for a 4096-byte page and a 256-byte one.
    fn addr_of<A: Arch>(frame_index: u64) -> PhysAddr {
        PhysAddr::new(frame_index.saturating_mul(Frame::<A>::bytes()))
    }

    /// Unwrap a result the test has already established must be `Ok`, reporting the
    /// error rather than a bare "called unwrap on an Err".
    #[track_caller]
    fn expect<T>(r: Result<T, AllocError>) -> T {
        match r {
            Ok(v) => v,
            Err(e) => panic!("unexpected {e:?}"),
        }
    }

    fn frame_size_comes_from_the_arch<A: Arch>() {
        assert_eq!(Frame::<A>::SIZE, A::PAGE_SIZE);
        assert_eq!(Frame::<A>::bytes(), widen(A::PAGE_SIZE));
    }

    #[test]
    fn frame_size_full() {
        frame_size_comes_from_the_arch::<MockFull>();
    }

    #[test]
    fn frame_size_tiny() {
        frame_size_comes_from_the_arch::<MockTiny>();
    }

    #[test]
    fn the_two_profiles_really_do_differ() {
        // If this ever stops holding, every "same logic on both mocks" test below
        // has quietly become a single test run twice.
        assert_ne!(Frame::<MockFull>::SIZE, Frame::<MockTiny>::SIZE);
    }

    fn containing_rounds_down<A: Arch>() {
        let base = addr_of::<A>(7);
        let inside = expect(base.checked_add(1).map_err(AllocError::from));
        assert_eq!(Frame::<A>::containing(base).start(), base);
        assert_eq!(Frame::<A>::containing(inside).start(), base);
        assert_eq!(Frame::<A>::containing(inside).number(), 7);
    }

    #[test]
    fn containing_rounds_down_full() {
        containing_rounds_down::<MockFull>();
    }

    #[test]
    fn containing_rounds_down_tiny() {
        containing_rounds_down::<MockTiny>();
    }

    fn from_start_refuses_to_round<A: Arch>() {
        let base = addr_of::<A>(7);
        assert_eq!(Frame::<A>::from_start(base).map(|f| f.number()), Ok(7));
        let unaligned = expect(base.checked_add(1).map_err(AllocError::from));
        assert_eq!(
            Frame::<A>::from_start(unaligned),
            Err(AllocError::Misaligned)
        );
    }

    #[test]
    fn from_start_refuses_to_round_full() {
        from_start_refuses_to_round::<MockFull>();
    }

    #[test]
    fn from_start_refuses_to_round_tiny() {
        from_start_refuses_to_round::<MockTiny>();
    }

    fn number_and_address_round_trip<A: Arch>() {
        for n in [0u64, 1, 63, 1024, 0x10_0000] {
            let f = expect(Frame::<A>::from_number(n));
            assert_eq!(f.number(), n);
            assert!(f.start().is_aligned(Frame::<A>::bytes()));
            assert_eq!(
                f.end().map(|e| e.raw()),
                Ok(f.start().raw() + Frame::<A>::bytes())
            );
            assert_eq!(f.next().map(|x| x.number()), Ok(n + 1));
        }
    }

    #[test]
    fn number_and_address_round_trip_full() {
        number_and_address_round_trip::<MockFull>();
    }

    #[test]
    fn number_and_address_round_trip_tiny() {
        number_and_address_round_trip::<MockTiny>();
    }

    fn frame_numbers_overflow_rather_than_wrap<A: Arch>() {
        // A frame index whose byte address would exceed 64 bits must be rejected,
        // not truncated into a valid-looking low frame.
        assert_eq!(Frame::<A>::from_number(u64::MAX), Err(AllocError::Overflow));
    }

    #[test]
    fn frame_numbers_overflow_rather_than_wrap_full() {
        frame_numbers_overflow_rather_than_wrap::<MockFull>();
    }

    #[test]
    fn frame_numbers_overflow_rather_than_wrap_tiny() {
        frame_numbers_overflow_rather_than_wrap::<MockTiny>();
    }

    fn ranges_iterate_and_contain<A: Arch>() {
        let start = expect(Frame::<A>::from_number(10));
        let range = expect(FrameRange::new(start, 4));
        assert_eq!(range.count(), 4);
        assert_eq!(range.end_exclusive(), 14);
        assert_eq!(range.len_bytes(), Ok(4 * Frame::<A>::bytes()));

        let seen: [u64; 4] = {
            let mut buf = [0u64; 4];
            let mut n = 0;
            for f in range.iter() {
                if let Some(slot) = buf.get_mut(n) {
                    *slot = f.number();
                }
                n += 1;
            }
            assert_eq!(n, 4, "iterator must yield exactly `count` frames");
            buf
        };
        assert_eq!(seen, [10, 11, 12, 13]);

        assert!(range.contains(start));
        assert!(!range.contains(Frame::<A>::containing(addr_of::<A>(14))));
        assert!(!range.contains(Frame::<A>::containing(addr_of::<A>(9))));
    }

    #[test]
    fn ranges_iterate_and_contain_full() {
        ranges_iterate_and_contain::<MockFull>();
    }

    #[test]
    fn ranges_iterate_and_contain_tiny() {
        ranges_iterate_and_contain::<MockTiny>();
    }

    fn empty_ranges_are_rejected<A: Arch>() {
        let start = expect(Frame::<A>::from_number(1));
        assert_eq!(
            FrameRange::new(start, 0).map(|r| r.count()),
            Err(AllocError::EmptyRequest)
        );
    }

    #[test]
    fn empty_ranges_are_rejected_full() {
        empty_ranges_are_rejected::<MockFull>();
    }

    #[test]
    fn empty_ranges_are_rejected_tiny() {
        empty_ranges_are_rejected::<MockTiny>();
    }

    #[test]
    fn frames_above_the_pointer_range_are_addressable() {
        // 0xF_FFFF_F000 is the top of an i686-with-PAE physical address space: a
        // 36-bit address behind a 32-bit pointer. The frame number is a `u64`
        // throughout, so this works on a 32-bit host as well as a 64-bit one.
        let high = PhysAddr::new(0xF_FFFF_F000);
        let f = Frame::<MockFull>::containing(high);
        assert_eq!(f.start(), high);
        assert_eq!(f.number(), 0xF_FFFF_F000 / 4096);
        assert!(f.number() > u64::from(u32::MAX) / 4096);
    }
}

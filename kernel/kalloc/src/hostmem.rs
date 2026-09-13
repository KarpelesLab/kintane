//! Host memory standing in for physical frames. Tests only.
//!
//! The allocators in this unit hand out pointers, and a test that only checks the
//! arithmetic behind those pointers has not checked the thing most likely to be
//! wrong. So the tests give the heap a [`DirectMap`] whose window points at a real
//! buffer on the machine running them: "physical" address `n` is byte `n` of that
//! buffer. Then a returned pointer is a pointer to memory the test also owns, and
//! alignment, poisoning and non-overlap can be checked by *reading the bytes back*
//! rather than by re-deriving them.
//!
//! That is also what makes the direct map itself testable. `DirectMap::identity` is
//! what the kernel passes today, but a test using it would be testing `virt == phys`
//! and nothing else. Here the offset is whatever the host allocator happened to
//! return, so every test in this unit runs against a *non-zero* direct-map offset —
//! which is the configuration the kernel will move to, and the one a hardcoded cast
//! would break on.

use core::marker::PhantomData;

use hal::{Arch, KernAddr, PhysAddr};
use mm::directmap::DirectMap;
use mm::{AllocError, Frame, FrameRange};

use crate::frames::FrameSource;
use crate::widen;

/// Alignment of the stand-in memory: the largest page size any mock uses, so that
/// "physical" frame boundaries line up with real alignment boundaries for both.
const ALIGN: usize = 4096;

/// A buffer on the host that the heap is told is physical memory.
pub struct HostMemory {
    buf: Vec<u8>,
    /// Address of the first aligned byte, with provenance exposed so that the
    /// pointer the allocator forms from it is usable.
    base: usize,
    /// Address of `buf[0]`, for turning an address back into an index.
    origin: usize,
    len: usize,
}

impl HostMemory {
    /// `len` bytes of aligned memory, filled with a value that is neither zero nor
    /// the poison byte, so a test can tell "untouched" from "zeroed" from "freed".
    pub fn new(len: usize) -> Self {
        let mut buf = vec![0x5Au8; len.saturating_add(ALIGN)];
        let raw = buf.as_mut_ptr();
        // Exposed on purpose: the allocator reaches this memory by casting an
        // integer address back to a pointer (`hal::KernAddr::as_ptr`), which is the
        // exposed-provenance idiom. Taking only `.addr()` here would make every such
        // pointer dangle under a strict-provenance interpretation.
        let origin = raw.expose_provenance();
        let base = origin
            .checked_add(ALIGN.saturating_sub(1))
            .map(|v| v & !ALIGN.saturating_sub(1))
            .unwrap_or(origin);
        HostMemory {
            buf,
            base,
            origin,
            len,
        }
    }

    /// A direct map placing "physical" zero at the start of this buffer.
    ///
    /// The offset is the host address, so it is large, non-zero, and different on
    /// every run — exactly the properties an identity map does not have.
    pub fn direct_map(&self) -> DirectMap {
        match DirectMap::new(PhysAddr::ZERO, KernAddr::new(self.base), widen(self.len)) {
            Ok(m) => m,
            Err(e) => panic!("host memory is not a usable window: {e:?}"),
        }
    }

    /// A frame source over this buffer, for an architecture's page size.
    pub fn frames<A: Arch>(&self) -> HostFrames<A> {
        HostFrames {
            next: 0,
            limit: widen(self.len / Frame::<A>::SIZE),
            handed_out: 0,
            _arch: PhantomData,
        }
    }

    /// The byte at kernel-virtual address `addr`, read through the buffer rather
    /// than through the allocator's pointer, so that a test proving the allocator
    /// wrote something does not depend on the allocator to read it.
    pub fn byte_at(&self, addr: usize) -> Option<u8> {
        let idx = addr.checked_sub(self.origin)?;
        self.buf.get(idx).copied()
    }

    /// The bytes of the block at `addr`, or `None` if any of it is out of range.
    pub fn bytes_at(&self, addr: usize, len: usize) -> Option<&[u8]> {
        let start = addr.checked_sub(self.origin)?;
        let end = start.checked_add(len)?;
        self.buf.get(start..end)
    }
}

/// A [`FrameSource`] that hands out the frames of a [`HostMemory`] in order.
///
/// Deliberately simple — a cursor, no reuse — because this is scaffolding, not a
/// second allocator to get wrong. What it does model faithfully is the two error
/// cases the heap has to cope with: running out, and being asked for a run longer
/// than what is left.
pub struct HostFrames<A: Arch> {
    next: u64,
    limit: u64,
    handed_out: usize,
    _arch: PhantomData<fn() -> A>,
}

impl<A: Arch> HostFrames<A> {
    /// How many frames this source has given away.
    pub fn handed_out(&self) -> usize {
        self.handed_out
    }

    /// How many frames are left.
    pub fn remaining(&self) -> u64 {
        self.limit.saturating_sub(self.next)
    }

    /// Pretend only `frames` of the buffer exist, so exhaustion arrives early enough
    /// to be tested without allocating megabytes.
    pub fn limit_to(&mut self, frames: u64) {
        self.limit = self.limit.min(self.next.saturating_add(frames));
    }
}

impl<A: Arch> FrameSource<A> for HostFrames<A> {
    fn take(&mut self, frames: usize) -> Result<FrameRange<A>, AllocError> {
        if frames == 0 {
            return Err(AllocError::EmptyRequest);
        }
        let end = self
            .next
            .checked_add(widen(frames))
            .ok_or(AllocError::Overflow)?;
        if end > self.limit {
            return Err(AllocError::Exhausted);
        }
        let range = FrameRange::new(Frame::<A>::from_number(self.next)?, frames)?;
        self.next = end;
        self.handed_out = self.handed_out.saturating_add(frames);
        Ok(range)
    }
}

#[cfg(test)]
mod tests {
    use hal::mock::{MockFull, MockTiny};

    use super::*;

    fn the_window_covers_the_buffer<A: Arch>() {
        let mem = HostMemory::new(64 * 1024);
        let map = mem.direct_map();
        assert_eq!(map.len(), 64 * 1024);
        assert_ne!(
            map.virt_base(),
            KernAddr::ZERO,
            "the tests must run against a non-zero direct-map offset"
        );
        // The first frame is reachable and its bytes are readable through the buffer.
        let virt = match map.to_virt(PhysAddr::ZERO) {
            Ok(v) => v,
            Err(e) => panic!("unexpected {e:?}"),
        };
        assert_eq!(mem.byte_at(virt.raw()), Some(0x5A));
        assert!(map.ptr_at(virt).is_ok());
        // And the page size really did come from the architecture.
        let mut frames = mem.frames::<A>();
        let r = match FrameSource::<A>::take(&mut frames, 1) {
            Ok(r) => r,
            Err(e) => panic!("unexpected {e:?}"),
        };
        assert_eq!(r.len_bytes(), Ok(widen(A::PAGE_SIZE)));
    }

    #[test]
    fn the_window_covers_the_buffer_full() {
        the_window_covers_the_buffer::<MockFull>();
    }

    #[test]
    fn the_window_covers_the_buffer_tiny() {
        the_window_covers_the_buffer::<MockTiny>();
    }

    fn the_source_runs_out<A: Arch>() {
        let mem = HostMemory::new(64 * 1024);
        let mut frames = mem.frames::<A>();
        frames.limit_to(4);
        assert!(FrameSource::<A>::take(&mut frames, 4).is_ok());
        assert_eq!(
            FrameSource::<A>::take(&mut frames, 1).map(|r| r.count()),
            Err(AllocError::Exhausted)
        );
        assert_eq!(frames.handed_out(), 4);
    }

    #[test]
    fn the_source_runs_out_full() {
        the_source_runs_out::<MockFull>();
    }

    #[test]
    fn the_source_runs_out_tiny() {
        the_source_runs_out::<MockTiny>();
    }
}

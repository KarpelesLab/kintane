//! The region map: which virtual ranges exist, what backs them, and what they permit.
//!
//! # Fixed capacity
//!
//! The map is an array of `N` slots, sorted by start address, and running out is an
//! error ([`VmError::RegionsFull`]). An allocator-backed tree was the alternative, and
//! two things rule it out here rather than merely argue against it:
//!
//! * **Layering.** `kalloc` depends on `mm`, so `mm` cannot allocate from `kalloc`.
//! * **The fault path.** Regions are split by `protect` and consulted on every page fault. A region
//!   map that allocated would allocate from inside a fault handler, possibly a fault taken on the
//!   heap itself.
//!
//! Lookup is a binary search, and insertion and splitting shift the tail of the array.
//! That is linear in `N`. An address space with thousands of regions needs a tree built
//! over caller-provided nodes, and that is a change to this module only.

use core::marker::PhantomData;

use hal::paging::PageFlags;
use hal::{Arch, PhysAddr};

use super::VmError;

/// What provides the memory behind a region.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Backing {
    /// Zeroed memory, materialised a page at a time on first touch.
    ///
    /// The pages belong to the address space, and the page tables are where they are
    /// recorded; see [`crate::vm`] for why that is the right model today and what
    /// changes it.
    Anonymous,
    /// A fixed physical range: device registers, or memory some other owner manages.
    ///
    /// The region's first byte maps to `base`, and every page after it to the matching
    /// offset. The frames are never allocated or freed by the address space.
    Physical {
        /// Physical address of the region's first byte.
        base: PhysAddr,
    },
}

/// One virtual range of an address space.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Region {
    /// First address. Page-aligned.
    pub start: usize,
    /// Length in bytes. Page-aligned and non-zero.
    pub len: usize,
    /// What the region permits. Every mapping inside it grants at most this; an
    /// anonymous page shared copy-on-write grants less until it is written.
    pub flags: PageFlags,
    /// What backs it.
    pub backing: Backing,
    /// Whether faults may map a huge page where one fits entirely inside the region.
    pub huge: bool,
}

impl Region {
    /// One past the last address, or `None` if that overflows.
    pub fn end(&self) -> Option<usize> {
        self.start.checked_add(self.len)
    }

    /// Whether `addr` is inside the region.
    pub fn contains(&self, addr: usize) -> bool {
        addr >= self.start && addr - self.start < self.len
    }

    /// The physical address `addr` maps to, for a physically backed region.
    pub fn phys_at(&self, addr: usize) -> Option<PhysAddr> {
        match self.backing {
            Backing::Physical { base } if self.contains(addr) => {
                base.checked_add((addr - self.start) as u64).ok()
            }
            _ => None,
        }
    }

    /// The part from `at` onwards. `at` must be inside the region.
    fn tail(&self, at: usize) -> Result<Region, VmError> {
        let off = at - self.start;
        let backing = match self.backing {
            Backing::Anonymous => Backing::Anonymous,
            Backing::Physical { base } => Backing::Physical {
                base: base
                    .checked_add(off as u64)
                    .map_err(|_| VmError::Overflow)?,
            },
        };
        Ok(Region {
            start: at,
            len: self.len - off,
            backing,
            ..*self
        })
    }
}

/// A sorted, non-overlapping set of at most `N` regions.
pub struct Regions<A: Arch, const N: usize> {
    slots: [Option<Region>; N],
    len: usize,
    _arch: PhantomData<fn() -> A>,
}

impl<A: Arch, const N: usize> Default for Regions<A, N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<A: Arch, const N: usize> Regions<A, N> {
    pub const fn new() -> Self {
        Regions {
            slots: [None; N],
            len: 0,
            _arch: PhantomData,
        }
    }

    /// Number of regions.
    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Slots still unused.
    pub fn room(&self) -> usize {
        N - self.len
    }

    /// The regions, in address order.
    pub fn iter(&self) -> impl Iterator<Item = Region> + '_ {
        self.slots[..self.len].iter().filter_map(|r| *r)
    }

    /// The region at position `i` in address order.
    pub fn get(&self, i: usize) -> Option<Region> {
        self.slots
            .get(i)
            .copied()
            .flatten()
            .filter(|_| i < self.len)
    }

    /// Add a region. It must be page-aligned, non-empty, and overlap nothing.
    pub fn insert(&mut self, region: Region) -> Result<(), VmError> {
        let mask = A::PAGE_SIZE - 1;
        if region.len == 0 {
            return Err(VmError::Empty);
        }
        if region.start & mask != 0 || region.len & mask != 0 {
            return Err(VmError::Misaligned);
        }
        if let Backing::Physical { base } = region.backing
            && base.raw() & (mask as u64) != 0
        {
            return Err(VmError::Misaligned);
        }
        let end = region.end().ok_or(VmError::Overflow)?;
        let at = self.first_ending_after(region.start);
        if let Some(next) = self.get(at)
            && next.start < end
        {
            return Err(VmError::Overlap);
        }
        if self.len == N {
            return Err(VmError::RegionsFull);
        }
        self.slots.copy_within(at..self.len, at + 1);
        self.slots[at] = Some(region);
        self.len += 1;
        Ok(())
    }

    /// The position of the region containing `addr`, and the region.
    pub fn find(&self, addr: usize) -> Option<(usize, Region)> {
        let at = self.first_ending_after(addr);
        self.get(at).filter(|r| r.contains(addr)).map(|r| (at, r))
    }

    /// The position of the region starting exactly at `start`, and the region.
    pub fn exact(&self, start: usize) -> Option<(usize, Region)> {
        self.find(start).filter(|(_, r)| r.start == start)
    }

    /// Remove the region at position `i`.
    pub fn remove(&mut self, i: usize) -> Option<Region> {
        let r = self.get(i)?;
        self.slots.copy_within(i + 1..self.len, i);
        self.len -= 1;
        self.slots[self.len] = None;
        Some(r)
    }

    /// Change the permissions recorded for the region at position `i`.
    pub fn set_flags(&mut self, i: usize, flags: PageFlags) -> Result<(), VmError> {
        match self.slots.get_mut(i) {
            Some(Some(r)) if i < self.len => {
                r.flags = flags;
                Ok(())
            }
            _ => Err(VmError::NoRegion),
        }
    }

    /// Split the region containing `at` so that a region starts exactly at `at`.
    ///
    /// Does nothing if one already does, or if no region contains `at`. `at` must be
    /// page-aligned. Both halves keep the permissions and the backing, offset for the
    /// second half of a physical range.
    pub fn split_at(&mut self, at: usize) -> Result<(), VmError> {
        if at & (A::PAGE_SIZE - 1) != 0 {
            return Err(VmError::Misaligned);
        }
        let Some((i, r)) = self.find(at) else {
            return Ok(());
        };
        if r.start == at {
            return Ok(());
        }
        if self.len == N {
            return Err(VmError::RegionsFull);
        }
        let tail = r.tail(at)?;
        self.slots.copy_within(i + 1..self.len, i + 2);
        self.slots[i] = Some(Region {
            len: at - r.start,
            ..r
        });
        self.slots[i + 1] = Some(tail);
        self.len += 1;
        Ok(())
    }

    /// Index of the first region whose end is after `addr`: the only one that can
    /// contain it, and where a region starting at `addr` would be inserted.
    fn first_ending_after(&self, addr: usize) -> usize {
        let (mut lo, mut hi) = (0usize, self.len);
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            let ends_after = self
                .get(mid)
                .and_then(|r| r.end())
                .is_none_or(|end| end > addr);
            if ends_after {
                hi = mid;
            } else {
                lo = mid + 1;
            }
        }
        lo
    }
}

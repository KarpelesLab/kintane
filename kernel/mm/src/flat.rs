//! `mm::flat`: physical memory as ranges, with no translation.
//!
//! On a machine without an MMU there are no pages to map, so the natural unit of
//! allocation is not a frame but a range: a driver wants 3 KiB of DMA buffer aligned to
//! 64, a thread wants 28 KiB of stack, and neither cares about page boundaries that no
//! hardware enforces. [`Regions`] hands those out, first fit, from a sorted list of free
//! ranges built from the memory map.
//!
//! It coexists with [`crate::FrameAllocator`] rather than replacing it. The heap in
//! `kalloc` is built on frames, and frames are still a fine unit for it — a 4 KiB frame
//! is a 4 KiB range. What the flat model adds is the allocation a no-MMU kernel needs and
//! a paged one never does: contiguous physical memory of an arbitrary size at an
//! arbitrary alignment, which on a paged kernel is what virtual memory exists to avoid.
//!
//! # Representation
//!
//! A fixed-capacity array of free ranges `[start, end)`, sorted, never overlapping and
//! never touching: adjacent ranges are merged on every insertion, so the list is always
//! the shortest description of the free memory. Fixed capacity because the allocator
//! runs before any other, and because a no-MMU machine with 64 KiB of RAM cannot spend
//! it on a node per range. Running out of capacity is an error, reported before anything
//! changes, never a silently dropped range.
//!
//! Physical addresses are `u64` here as everywhere in `mm`; this model runs on 32-bit
//! cores, where a range above 4 GiB cannot exist, but the map it reads is shared with
//! targets where it can.

use boot_protocol::{MemoryKind, MemoryRegion};

/// Why a [`Regions`] operation did not succeed. Nothing changes when one fails.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FlatError {
    /// A zero-length range or allocation.
    Empty,
    /// The alignment is not a power of two.
    BadAlign,
    /// Address arithmetic left the `u64` range.
    Overflow,
    /// The range overlaps memory that is already free: a double free, or a map that
    /// describes the same memory twice.
    Overlap,
    /// No free range can hold the request.
    NoFit,
    /// The operation needs more ranges than the list can hold.
    Full,
}

/// Free physical memory as at most `N` ranges. See the module documentation.
pub struct Regions<const N: usize> {
    /// `[start, end)`, sorted by `start`; only the first `len` are meaningful.
    free: [(u64, u64); N],
    len: usize,
}

impl<const N: usize> Default for Regions<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> Regions<N> {
    pub const fn new() -> Self {
        Regions {
            free: [(0, 0); N],
            len: 0,
        }
    }

    /// Every usable region of `map`, less every other region of it.
    ///
    /// Non-usable regions are subtracted rather than trusted to lie outside the usable
    /// ones. A device tree's first entry is the tree itself, which sits inside RAM, and
    /// firmware maps overlap in practice.
    pub fn from_map(map: &[MemoryRegion]) -> Result<Self, FlatError> {
        let mut r = Self::new();
        let usable = |m: &&MemoryRegion| m.kind == MemoryKind::Usable as u32;
        for m in map.iter().filter(usable) {
            r.add(m.start, m.len)?;
        }
        for m in map.iter().filter(|m| !usable(m)) {
            if m.len > 0 {
                r.reserve(m.start, m.len)?;
            }
        }
        Ok(r)
    }

    /// The free ranges, in address order.
    pub fn ranges(&self) -> &[(u64, u64)] {
        &self.free[..self.len]
    }

    /// Bytes free in total.
    pub fn free_bytes(&self) -> u64 {
        self.ranges().iter().map(|(s, e)| e - s).sum()
    }

    /// The longest single free range, in bytes: the largest request that can succeed at
    /// alignment 1.
    pub fn largest(&self) -> u64 {
        self.ranges().iter().map(|(s, e)| e - s).max().unwrap_or(0)
    }

    /// Hand `[start, start + len)` to the allocator. It must not overlap anything free.
    pub fn add(&mut self, start: u64, len: u64) -> Result<(), FlatError> {
        let end = range_end(start, len)?;
        self.insert(start, end)
    }

    /// Give back an allocation. The same as [`Self::add`], which is the point: a free
    /// that overlaps free memory is a double free and is refused.
    ///
    /// A free can also fail with [`FlatError::Full`]: an allocation carved from the middle
    /// of a range leaves free memory on both sides, and returning it without a neighbour
    /// to merge with needs an entry of its own. The list therefore has to be sized for the
    /// number of ranges in the map plus the most allocations alive at once. That is a real
    /// constraint of fixed capacity, stated rather than hidden: nothing is lost on the
    /// error, and the caller still holds the range.
    pub fn free(&mut self, start: u64, len: u64) -> Result<(), FlatError> {
        self.add(start, len)
    }

    /// Take `[start, start + len)` out of the free memory, whatever part of it is free.
    /// Returns how many bytes were actually removed. Memory that was not free is
    /// ignored, so reserving the kernel image, which the map may or may not already
    /// exclude, needs no special case.
    pub fn reserve(&mut self, start: u64, len: u64) -> Result<u64, FlatError> {
        let end = range_end(start, len)?;
        // A reservation strictly inside one range splits it in two: one more entry.
        let splits = self.ranges().iter().any(|&(s, e)| s < start && end < e);
        if splits && self.len == N {
            return Err(FlatError::Full);
        }
        let mut removed = 0;
        let mut i = 0;
        while i < self.len {
            let (s, e) = self.free[i];
            if e <= start || end <= s {
                i += 1;
                continue;
            }
            removed += e.min(end) - s.max(start);
            match (s < start, end < e) {
                (true, true) => {
                    self.free[i] = (s, start);
                    self.insert_at(i + 1, (end, e));
                    i += 2;
                }
                (true, false) => {
                    self.free[i].1 = start;
                    i += 1;
                }
                (false, true) => {
                    self.free[i].0 = end;
                    i += 1;
                }
                (false, false) => self.remove_at(i),
            }
        }
        Ok(removed)
    }

    /// `len` bytes at an address that is a multiple of `align`, from the lowest free
    /// range that can hold them.
    ///
    /// The alignment gap and the tail stay free. When both are non-empty the range
    /// splits in two, which needs a spare entry; if the list is full the allocation
    /// tries the next range rather than failing, since a range whose start is already
    /// aligned splits into one.
    pub fn alloc(&mut self, len: u64, align: u64) -> Result<u64, FlatError> {
        if len == 0 {
            return Err(FlatError::Empty);
        }
        if !align.is_power_of_two() {
            return Err(FlatError::BadAlign);
        }
        let mut full = false;
        for i in 0..self.len {
            let (s, e) = self.free[i];
            let Some(at) = s.checked_next_multiple_of(align) else {
                continue;
            };
            let Some(end) = at.checked_add(len) else {
                continue;
            };
            if end > e {
                continue;
            }
            let (gap, tail) = (at > s, end < e);
            if gap && tail && self.len == N {
                full = true;
                continue;
            }
            match (gap, tail) {
                (true, true) => {
                    self.free[i] = (s, at);
                    self.insert_at(i + 1, (end, e));
                }
                (true, false) => self.free[i].1 = at,
                (false, true) => self.free[i].0 = end,
                (false, false) => self.remove_at(i),
            }
            return Ok(at);
        }
        Err(if full {
            FlatError::Full
        } else {
            FlatError::NoFit
        })
    }

    /// Whether the list is well-formed: sorted, non-empty ranges that neither overlap
    /// nor touch. Every operation preserves it; this is for tests and bring-up checks.
    pub fn check(&self) -> bool {
        let r = self.ranges();
        r.iter().all(|(s, e)| s < e) && r.windows(2).all(|w| w[0].1 < w[1].0)
    }

    /// Insert `[start, end)`, merging with neighbours it touches.
    fn insert(&mut self, start: u64, end: u64) -> Result<(), FlatError> {
        // `i` is the first range ending at or after `start`. If it ends exactly there it
        // touches from below, and the next one is the only candidate above; otherwise `i`
        // itself is. Nothing earlier can be involved, and the list's own ranges do not
        // touch, so one comparison settles overlap.
        let i = self.ranges().partition_point(|&(_, e)| e < start);
        let below = i < self.len && self.free[i].1 == start;
        let at_i = if below { i + 1 } else { i };
        if at_i < self.len && self.free[at_i].0 < end {
            return Err(FlatError::Overlap);
        }
        let above = at_i < self.len && self.free[at_i].0 == end;
        match (below, above) {
            (true, true) => {
                self.free[i].1 = self.free[at_i].1;
                self.remove_at(at_i);
            }
            (true, false) => self.free[i].1 = end,
            (false, true) => self.free[at_i].0 = start,
            (false, false) => {
                if self.len == N {
                    return Err(FlatError::Full);
                }
                self.insert_at(i, (start, end));
            }
        }
        Ok(())
    }

    /// Shift `[i, len)` up one and put `v` at `i`. The caller has checked capacity.
    fn insert_at(&mut self, i: usize, v: (u64, u64)) {
        self.free.copy_within(i..self.len, i + 1);
        self.free[i] = v;
        self.len += 1;
    }

    fn remove_at(&mut self, i: usize) {
        self.free.copy_within(i + 1..self.len, i);
        self.len -= 1;
    }
}

fn range_end(start: u64, len: u64) -> Result<u64, FlatError> {
    if len == 0 {
        return Err(FlatError::Empty);
    }
    start.checked_add(len).ok_or(FlatError::Overflow)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn region(start: u64, len: u64, kind: MemoryKind) -> MemoryRegion {
        MemoryRegion {
            start,
            len,
            kind: kind as u32,
            _reserved: 0,
        }
    }

    #[test]
    fn adding_merges_touching_ranges_and_refuses_overlap() {
        let mut r = Regions::<4>::new();
        r.add(0x1000, 0x1000).unwrap();
        r.add(0x3000, 0x1000).unwrap();
        r.add(0x2000, 0x1000).unwrap();
        assert_eq!(r.ranges(), [(0x1000, 0x4000)], "three touching ranges are one");
        assert_eq!(r.add(0x3fff, 2), Err(FlatError::Overlap));
        assert_eq!(r.add(0x0800, 0x1000), Err(FlatError::Overlap));
        assert_eq!(r.add(0x1800, 0x10), Err(FlatError::Overlap), "strictly inside");
        assert_eq!(r.add(0x0, 0x5000), Err(FlatError::Overlap), "covering it");
        assert_eq!(r.ranges(), [(0x1000, 0x4000)], "and a refusal changes nothing");
        assert!(r.check());
    }

    #[test]
    fn reserving_splits_trims_and_ignores_what_is_not_free() {
        let mut r = Regions::<4>::new();
        r.add(0x1000, 0x9000).unwrap();
        assert_eq!(r.reserve(0x4000, 0x1000), Ok(0x1000));
        assert_eq!(r.ranges(), [(0x1000, 0x4000), (0x5000, 0xa000)]);
        assert_eq!(r.reserve(0x0, 0x1800), Ok(0x800), "only the free part counts");
        assert_eq!(r.reserve(0x3000, 0x3000), Ok(0x2000), "across a hole");
        assert_eq!(r.ranges(), [(0x1800, 0x3000), (0x6000, 0xa000)]);
        assert_eq!(r.reserve(0x20000, 0x10), Ok(0), "nowhere near");
        assert!(r.check());
    }

    #[test]
    fn a_split_the_list_cannot_hold_is_refused_before_anything_changes() {
        let mut r = Regions::<2>::new();
        r.add(0x1000, 0x1000).unwrap();
        r.add(0x4000, 0x1000).unwrap();
        assert_eq!(r.reserve(0x1400, 0x10), Err(FlatError::Full));
        assert_eq!(r.ranges(), [(0x1000, 0x2000), (0x4000, 0x5000)]);
    }

    #[test]
    fn allocation_is_first_fit_aligned_and_keeps_the_gap_free() {
        let mut r = Regions::<4>::new();
        r.add(0x1001, 0x0fff).unwrap(); // [0x1001, 0x2000)
        r.add(0x8000, 0x8000).unwrap();
        // 0x1001 aligned to 0x100 is 0x1100; 0x800 bytes fit below 0x2000.
        assert_eq!(r.alloc(0x800, 0x100), Ok(0x1100));
        assert_eq!(r.ranges(), [(0x1001, 0x1100), (0x1900, 0x2000), (0x8000, 0x10000)]);
        // Too big for the first two ranges.
        assert_eq!(r.alloc(0x1000, 0x1000), Ok(0x8000));
        assert_eq!(r.alloc(0x100_0000, 1), Err(FlatError::NoFit));
        assert_eq!(r.alloc(0, 1), Err(FlatError::Empty));
        assert_eq!(r.alloc(1, 3), Err(FlatError::BadAlign));
        assert!(r.check());
    }

    #[test]
    fn a_full_list_still_serves_an_allocation_that_needs_no_split() {
        let mut r = Regions::<2>::new();
        r.add(0x1001, 0x2000).unwrap();
        r.add(0x8000, 0x2000).unwrap();
        // In the first range 0x100 bytes at 0x2000 would leave free memory on both sides,
        // which needs a third entry. The second range starts aligned.
        assert_eq!(r.alloc(0x100, 0x1000), Ok(0x8000));
        assert_eq!(r.ranges(), [(0x1001, 0x3001), (0x8100, 0xa000)]);

        let mut one = Regions::<1>::new();
        one.add(0x1001, 0x2000).unwrap();
        assert_eq!(one.alloc(0x100, 0x1000), Err(FlatError::Full), "not NoFit: it fits");
        assert_eq!(one.ranges(), [(0x1001, 0x3001)]);
    }

    #[test]
    fn freeing_coalesces_back_to_one_range_and_refuses_a_double_free() {
        let mut r = Regions::<8>::new();
        r.add(0x10000, 0x10000).unwrap();
        let before = r.free_bytes();
        let a = r.alloc(0x1000, 0x1000).unwrap();
        let b = r.alloc(0x2345, 8).unwrap();
        let c = r.alloc(0x100, 0x400).unwrap();
        assert!(r.check());
        r.free(b, 0x2345).unwrap();
        assert_eq!(r.free(b, 0x2345), Err(FlatError::Overlap), "double free");
        assert_eq!(r.free(b + 8, 8), Err(FlatError::Overlap), "part of a free range");
        r.free(a, 0x1000).unwrap();
        r.free(c, 0x100).unwrap();
        assert_eq!(r.ranges(), [(0x10000, 0x20000)]);
        assert_eq!(r.free_bytes(), before);
    }

    #[test]
    fn the_memory_map_minus_what_is_not_usable() {
        let map = [
            // A device tree inside RAM, as `info-fdt` reports it: first, as boot data.
            region(0x87e0_0000, 0x1_0000, MemoryKind::BootData),
            region(0x8000_0000, 0x0800_0000, MemoryKind::Usable),
        ];
        let r = Regions::<4>::from_map(&map).unwrap();
        assert_eq!(r.ranges(), [(0x8000_0000, 0x87e0_0000), (0x87e1_0000, 0x8800_0000)]);
        assert_eq!(r.free_bytes(), 0x0800_0000 - 0x1_0000);
    }

    #[test]
    fn ranges_at_the_top_of_the_address_space_do_not_wrap() {
        let mut r = Regions::<2>::new();
        assert_eq!(r.add(u64::MAX - 4, 8), Err(FlatError::Overflow));
        r.add(u64::MAX - 0x1000, 0x1000).unwrap();
        assert_eq!(r.alloc(0x100, 1 << 63), Err(FlatError::NoFit));
    }

    /// Many allocations and frees in a scrambled order: the list stays well-formed and
    /// comes back to exactly where it started.
    #[test]
    fn a_long_mixed_sequence_returns_to_the_start() {
        let mut r = Regions::<64>::new();
        r.add(0x4000_0000, 0x100_0000).unwrap();
        r.reserve(0x4040_0000, 0x1234).unwrap();
        let start: Vec<(u64, u64)> = r.ranges().to_vec();
        let mut held = Vec::new();
        let mut seed = 0x2545_f491_4f6c_dd1du64;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for round in 0..2000 {
            // Capped: every live allocation can cost one free-list entry (see `free`).
            if (next() % 3 != 0 || held.is_empty()) && held.len() < 48 {
                let len = 1 + next() % 0x3000;
                let align = 1 << (next() % 13);
                if let Ok(at) = r.alloc(len, align) {
                    assert_eq!(at % align, 0);
                    held.push((at, len));
                }
            } else {
                let i = (next() as usize) % held.len();
                let (at, len) = held.swap_remove(i);
                r.free(at, len).unwrap();
            }
            assert!(r.check(), "ill-formed after round {round}");
        }
        for (at, len) in held {
            r.free(at, len).unwrap();
        }
        assert_eq!(r.ranges(), start);
    }
}

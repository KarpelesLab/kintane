//! Host tests for the shared page table walker.
//!
//! "Physical memory" is a host allocation, and the direct map points at it with a
//! **non-zero** virtual base — so a walker bug that assumed `virt == phys` would show
//! up here rather than surviving until a high-half kernel exists.
//!
//! These run against `MockFull`, whose table format resembles no real architecture on
//! purpose: the point is to test the tree walk, not x86's bit assignments. An
//! architecture's own encoding is verified by its in-kernel `paging_selftest`.

extern crate std;

use super::*;
use hal::mock::{MockFull, TLB_FLUSHES};
use hal::{Arch, KernAddr};
use std::alloc::{alloc_zeroed, dealloc, Layout};
use std::vec::Vec;

const PAGE: usize = MockFull::PAGE_SIZE;
const TWO_MIB: usize = 2 * 1024 * 1024;

/// A pretend physical address space backed by a host allocation.
struct Mem {
    buf: *mut u8,
    layout: Layout,
    len: u64,
    /// Next never-used frame. Starts at one page so that physical zero is never a
    /// real frame — it is the sentinel an absent entry decodes to, and a test that
    /// let a genuine frame live there could not tell the two apart.
    next: u64,
    freed: Vec<PhysAddr>,
    allocs: usize,
    frees: usize,
}

impl Mem {
    fn new(frames: usize) -> Mem {
        let len = frames * PAGE;
        let layout = Layout::from_size_align(len, PAGE).unwrap();
        // SAFETY: a non-zero layout; the pointer is checked below.
        let buf = unsafe { alloc_zeroed(layout) };
        assert!(!buf.is_null(), "test allocation failed");
        Mem {
            buf,
            layout,
            len: len as u64,
            next: PAGE as u64,
            freed: Vec::new(),
            allocs: 0,
            frees: 0,
        }
    }

    fn direct(&self) -> DirectMap {
        DirectMap::new(
            PhysAddr::new(0),
            KernAddr::new(self.buf as usize),
            self.len,
        )
        .expect("direct map")
    }
}

impl Drop for Mem {
    fn drop(&mut self) {
        // SAFETY: `buf` came from `alloc_zeroed` with exactly this layout.
        unsafe { dealloc(self.buf, self.layout) };
    }
}

impl FrameSource for Mem {
    fn alloc_zeroed(&mut self) -> Result<PhysAddr, MapError> {
        self.allocs += 1;
        if let Some(f) = self.freed.pop() {
            let off = f.raw() as usize;
            // SAFETY: `f` came from this allocator, so it lies inside the buffer.
            unsafe { core::ptr::write_bytes(self.buf.add(off), 0, PAGE) };
            return Ok(f);
        }
        if self.next + PAGE as u64 > self.len {
            return Err(MapError::OutOfFrames);
        }
        let f = PhysAddr::new(self.next);
        self.next += PAGE as u64;
        Ok(f)
    }

    fn free(&mut self, frame: PhysAddr) {
        self.frees += 1;
        self.freed.push(frame);
    }
}

fn setup(frames: usize) -> (Mem, AddressSpace<MockFull>) {
    let mut mem = Mem::new(frames);
    let dm = mem.direct();
    let space = AddressSpace::<MockFull>::new(dm, &mut mem).expect("root table");
    mem.allocs = 0; // the root is not interesting to the counts below
    (mem, space)
}

/// A canonical low-half virtual address.
const V: usize = 0x0000_1234_5678_9000 & !(PAGE - 1);

#[test]
fn a_mapping_can_be_translated_back() {
    let (mut mem, mut space) = setup(64);
    let p = PhysAddr::new(0x9_0000);
    space
        .map(V, p, PAGE, PageFlags::KERNEL_DATA, &mut mem)
        .unwrap();
    let (got, flags) = space.translate(V).unwrap();
    assert_eq!(got, p);
    assert!(flags.contains(PageFlags::WRITE));
    assert!(!flags.contains(PageFlags::EXECUTE));
}

#[test]
fn translation_keeps_the_byte_offset() {
    // A translate that lost the offset would be right for every page-aligned test and
    // wrong for every real access.
    let (mut mem, mut space) = setup(64);
    let p = PhysAddr::new(0x9_0000);
    space
        .map(V, p, PAGE, PageFlags::KERNEL_DATA, &mut mem)
        .unwrap();
    let (got, _) = space.translate(V + 0x123).unwrap();
    assert_eq!(got, PhysAddr::new(0x9_0123));
}

#[test]
fn nothing_is_mapped_until_it_is() {
    let (_mem, space) = setup(64);
    assert_eq!(space.translate(V), None);
    assert_eq!(space.translate(0), None);
}

#[test]
fn misaligned_requests_are_refused() {
    let (mut mem, mut space) = setup(64);
    let p = PhysAddr::new(0x9_0000);
    let f = PageFlags::KERNEL_DATA;
    assert_eq!(
        space.map(V + 1, p, PAGE, f, &mut mem),
        Err(MapError::Misaligned)
    );
    assert_eq!(
        space.map(V, p, PAGE - 1, f, &mut mem),
        Err(MapError::Misaligned)
    );
    assert_eq!(
        space.map(V, PhysAddr::new(0x9_0001), PAGE, f, &mut mem),
        Err(MapError::Misaligned)
    );
}

#[test]
fn a_non_canonical_address_is_refused() {
    // MockFull mimics x86-64 here on purpose: an address in the middle of the range
    // is not representable, and constructing one silently is a bug worth catching at
    // the mapping call rather than at the access.
    let (mut mem, mut space) = setup(64);
    let bad = 0x0001_0000_0000_0000usize;
    assert!(!MockFull::is_canonical(bad));
    assert_eq!(
        space.map(bad, PhysAddr::new(0x9_0000), PAGE, PageFlags::KERNEL_DATA, &mut mem),
        Err(MapError::NotCanonical)
    );
    assert_eq!(space.translate(bad), None);
}

#[test]
fn mapping_over_an_existing_mapping_is_refused() {
    // An accidental overlap is a bug; a caller that means it can unmap first.
    let (mut mem, mut space) = setup(64);
    let f = PageFlags::KERNEL_DATA;
    space.map(V, PhysAddr::new(0x9_0000), PAGE, f, &mut mem).unwrap();
    assert_eq!(
        space.map(V, PhysAddr::new(0xA_0000), PAGE, f, &mut mem),
        Err(MapError::AlreadyMapped)
    );
    // ...and the original survives.
    assert_eq!(space.translate(V).unwrap().0, PhysAddr::new(0x9_0000));
}

#[test]
fn unmapping_removes_the_translation_and_flushes() {
    let (mut mem, mut space) = setup(64);
    space
        .map(V, PhysAddr::new(0x9_0000), PAGE, PageFlags::KERNEL_DATA, &mut mem)
        .unwrap();
    let before = TLB_FLUSHES.load(core::sync::atomic::Ordering::SeqCst);
    space.unmap(V, PAGE, &mut mem).unwrap();
    assert_eq!(space.translate(V), None);
    assert!(
        TLB_FLUSHES.load(core::sync::atomic::Ordering::SeqCst) > before,
        "a stale translation that is never invalidated works until it does not"
    );
}

#[test]
fn unmapping_reclaims_the_tables_it_emptied() {
    let (mut mem, mut space) = setup(64);
    space
        .map(V, PhysAddr::new(0x9_0000), PAGE, PageFlags::KERNEL_DATA, &mut mem)
        .unwrap();
    let allocated = mem.allocs;
    assert!(allocated >= 3, "a fresh 4-level walk needs intermediate tables");
    space.unmap(V, PAGE, &mut mem).unwrap();
    assert_eq!(
        mem.frees, allocated,
        "every table allocated for this mapping should have come back"
    );
}

#[test]
fn a_table_still_in_use_is_not_reclaimed() {
    // Two mappings in the same leaf table: unmapping one must not free the table the
    // other still lives in.
    let (mut mem, mut space) = setup(64);
    let f = PageFlags::KERNEL_DATA;
    space.map(V, PhysAddr::new(0x9_0000), PAGE, f, &mut mem).unwrap();
    space
        .map(V + PAGE, PhysAddr::new(0xA_0000), PAGE, f, &mut mem)
        .unwrap();
    space.unmap(V, PAGE, &mut mem).unwrap();
    assert_eq!(mem.frees, 0, "the leaf table is still occupied");
    assert_eq!(space.translate(V + PAGE).unwrap().0, PhysAddr::new(0xA_0000));
}

#[test]
fn unmapping_something_absent_is_an_error() {
    let (mut mem, mut space) = setup(64);
    assert_eq!(space.unmap(V, PAGE, &mut mem), Err(MapError::NotMapped));
}

#[test]
fn an_aligned_large_range_uses_a_huge_page() {
    // Not only faster: it is what keeps the table count bounded when mapping a
    // gigabyte of direct map.
    let (mut mem, mut space) = setup(4096);
    let v = TWO_MIB * 4;
    space
        .map(v, PhysAddr::new(TWO_MIB as u64), TWO_MIB, PageFlags::KERNEL_DATA, &mut mem)
        .unwrap();
    assert_eq!(
        mem.allocs, 2,
        "a 2 MiB leaf needs only the two tables above it, not 512 leaf entries"
    );
    // The whole range translates, including the far end.
    assert_eq!(space.translate(v).unwrap().0, PhysAddr::new(TWO_MIB as u64));
    let (end, _) = space.translate(v + TWO_MIB - 1).unwrap();
    assert_eq!(end, PhysAddr::new((TWO_MIB + TWO_MIB - 1) as u64));
}

#[test]
fn a_misaligned_large_range_falls_back_to_small_pages() {
    let (mut mem, mut space) = setup(4096);
    // Offset by one page, so no 2 MiB leaf is possible at the start.
    let v = TWO_MIB * 4 + PAGE;
    space
        .map(v, PhysAddr::new(PAGE as u64), TWO_MIB, PageFlags::KERNEL_DATA, &mut mem)
        .unwrap();
    assert!(
        mem.allocs > 2,
        "small pages need leaf tables the huge-page case does not"
    );
    assert_eq!(space.translate(v).unwrap().0, PhysAddr::new(PAGE as u64));
}

#[test]
fn descending_through_a_huge_page_is_refused_rather_than_guessed() {
    let (mut mem, mut space) = setup(4096);
    let v = TWO_MIB * 4;
    let f = PageFlags::KERNEL_DATA;
    space
        .map(v, PhysAddr::new(TWO_MIB as u64), TWO_MIB, f, &mut mem)
        .unwrap();
    // Mapping a 4 KiB page inside it would have to split the huge page.
    assert_eq!(
        space.map(v + PAGE, PhysAddr::new(0x9_0000), PAGE, f, &mut mem),
        Err(MapError::WouldSplit)
    );
    // And unmapping part of it likewise.
    assert_eq!(space.unmap(v, PAGE, &mut mem), Err(MapError::WouldSplit));
}

#[test]
fn protect_changes_permissions_and_keeps_the_frame() {
    let (mut mem, mut space) = setup(64);
    let p = PhysAddr::new(0x9_0000);
    space.map(V, p, PAGE, PageFlags::KERNEL_DATA, &mut mem).unwrap();
    assert!(space.translate(V).unwrap().1.contains(PageFlags::WRITE));

    space.protect(V, PAGE, PageFlags::KERNEL_RODATA).unwrap();
    let (got, flags) = space.translate(V).unwrap();
    assert_eq!(got, p, "protect must not move the frame");
    assert!(!flags.contains(PageFlags::WRITE));
    assert!(!flags.contains(PageFlags::EXECUTE));
}

#[test]
fn protecting_something_absent_is_an_error() {
    let (_mem, mut space) = setup(64);
    assert_eq!(
        space.protect(V, PAGE, PageFlags::KERNEL_RODATA),
        Err(MapError::NotMapped)
    );
}

#[test]
fn running_out_of_frames_is_an_error_not_a_panic() {
    // Four frames is not enough for a fresh deep walk plus a root.
    let mut mem = Mem::new(4);
    let dm = mem.direct();
    let mut space = AddressSpace::<MockFull>::new(dm, &mut mem).unwrap();
    let mut last = Ok(());
    let mut v = V;
    for _ in 0..64 {
        last = space.map(v, PhysAddr::new(0x9_0000), PAGE, PageFlags::KERNEL_DATA, &mut mem);
        if last.is_err() {
            break;
        }
        // Step by a whole level-1 span so each mapping needs fresh tables.
        v += TWO_MIB;
    }
    assert_eq!(last, Err(MapError::OutOfFrames));
}

#[test]
fn a_physical_address_beyond_the_pointer_width_round_trips() {
    // The i686-with-PAE case, exercised on the host: PhysAddr is u64 everywhere, and
    // a mapping must be able to name a frame a usize could not hold on that target.
    let (mut mem, mut space) = setup(64);
    let high = PhysAddr::new(0xF_FFFF_F000);
    space
        .map(V, high, PAGE, PageFlags::KERNEL_DATA, &mut mem)
        .unwrap();
    assert_eq!(space.translate(V).unwrap().0, high);
}

#[test]
fn mapping_several_pages_covers_all_of_them() {
    let (mut mem, mut space) = setup(64);
    let n = 5;
    space
        .map(
            V,
            PhysAddr::new(0x9_0000),
            PAGE * n,
            PageFlags::KERNEL_DATA,
            &mut mem,
        )
        .unwrap();
    for i in 0..n {
        assert_eq!(
            space.translate(V + i * PAGE).unwrap().0,
            PhysAddr::new(0x9_0000 + (i * PAGE) as u64),
            "page {i}"
        );
    }
    assert_eq!(space.translate(V + n * PAGE), None, "and no further");
}

#[test]
fn a_zero_length_mapping_does_nothing() {
    let (mut mem, mut space) = setup(64);
    space
        .map(V, PhysAddr::new(0x9_0000), 0, PageFlags::KERNEL_DATA, &mut mem)
        .unwrap();
    assert_eq!(mem.allocs, 0);
    assert_eq!(space.translate(V), None);
}

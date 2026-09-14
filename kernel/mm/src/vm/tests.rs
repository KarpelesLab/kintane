//! Host tests for regions, demand paging and copy-on-write.
//!
//! The page-table half runs against `MockFull` only, because `MockTiny` has no MMU and
//! so cannot instantiate a `Vm` at all (that absence is the portability claim working).
//! The region map and the share counts do not need page tables and run against both.
//!
//! Memory access is simulated: [`Cpu::access`] consults the tables the way hardware
//! would, raises a fault to the `Vm` when they refuse, and retries. So a test that
//! writes through a mapping exercises the same resolve-and-retry loop the kernel's
//! exception path does, and a resolver that returned success without fixing anything
//! shows up as a fault loop rather than a pass.

extern crate std;

use std::alloc::{Layout, alloc_zeroed, dealloc};
use std::collections::BTreeSet;
use std::vec::Vec;

use hal::fault::{Access, PageFault};
use hal::mock::{MockFull, MockTiny, TLB_FLUSHES};
use hal::paging::{MapError, PageFlags};
use hal::{Arch, KernAddr, PhysAddr};

use super::*;
use crate::DirectMap;
use crate::paged::{AddressSpace, FrameSource};

const PAGE: usize = MockFull::PAGE_SIZE;
const TWO_MIB: usize = 2 * 1024 * 1024;
const RW: PageFlags = PageFlags::KERNEL_DATA;

/// A pretend physical memory, with fault injection and contiguous blocks.
struct Mem {
    buf: *mut u8,
    layout: Layout,
    len: u64,
    next: u64,
    freed: Vec<u64>,
    live: BTreeSet<u64>,
    /// Allocation attempts so far, of any kind.
    attempts: usize,
    /// Fail the attempt with this index (0-based), and only that one.
    fail_at: Option<usize>,
    /// Whether `alloc_block` can succeed.
    blocks: bool,
}

impl Mem {
    fn new(frames: usize) -> Mem {
        let len = frames * PAGE;
        let layout = Layout::from_size_align(len, PAGE).unwrap();
        // SAFETY: a non-zero layout; checked below.
        let buf = unsafe { alloc_zeroed(layout) };
        assert!(!buf.is_null());
        Mem {
            buf,
            layout,
            len: len as u64,
            // Physical zero is never a frame: it is the empty-slot sentinel.
            next: PAGE as u64,
            freed: Vec::new(),
            live: BTreeSet::new(),
            attempts: 0,
            fail_at: None,
            blocks: true,
        }
    }

    fn direct(&self) -> DirectMap {
        DirectMap::new(PhysAddr::new(0), KernAddr::new(self.buf as usize), self.len).unwrap()
    }

    fn byte(&self, phys: PhysAddr) -> *mut u8 {
        assert!(phys.raw() < self.len);
        // SAFETY: checked inside the buffer.
        unsafe { self.buf.add(phys.raw() as usize) }
    }

    fn injected(&mut self) -> bool {
        let n = self.attempts;
        self.attempts += 1;
        self.fail_at == Some(n)
    }

    fn take(&mut self) -> Result<u64, MapError> {
        let f = match self.freed.pop() {
            Some(f) => f,
            None => {
                if self.next + PAGE as u64 > self.len {
                    return Err(MapError::OutOfFrames);
                }
                let f = self.next;
                self.next += PAGE as u64;
                f
            }
        };
        assert!(self.live.insert(f), "frame {f:#x} handed out twice");
        Ok(f)
    }
}

impl Drop for Mem {
    fn drop(&mut self) {
        // SAFETY: allocated with exactly this layout.
        unsafe { dealloc(self.buf, self.layout) };
    }
}

impl FrameSource for Mem {
    fn alloc_zeroed(&mut self) -> Result<PhysAddr, MapError> {
        if self.injected() {
            return Err(MapError::OutOfFrames);
        }
        let f = self.take()?;
        // SAFETY: a whole frame inside the buffer.
        unsafe { core::ptr::write_bytes(self.buf.add(f as usize), 0, PAGE) };
        Ok(PhysAddr::new(f))
    }

    /// Deliberately dirty, so a demand page that was not zeroed is visible.
    fn alloc(&mut self) -> Result<PhysAddr, MapError> {
        if self.injected() {
            return Err(MapError::OutOfFrames);
        }
        let f = self.take()?;
        // SAFETY: a whole frame inside the buffer.
        unsafe { core::ptr::write_bytes(self.buf.add(f as usize), 0xEE, PAGE) };
        Ok(PhysAddr::new(f))
    }

    fn alloc_block(&mut self, frames: usize, align: usize) -> Result<PhysAddr, MapError> {
        if self.injected() || !self.blocks {
            return Err(MapError::OutOfFrames);
        }
        let align = align as u64;
        let start = self.next.div_ceil(align) * align;
        let end = start + (frames * PAGE) as u64;
        if end > self.len {
            return Err(MapError::OutOfFrames);
        }
        // The frames skipped to reach the boundary stay usable.
        let mut skipped = self.next;
        while skipped < start {
            self.freed.push(skipped);
            skipped += PAGE as u64;
        }
        for f in (start..end).step_by(PAGE) {
            assert!(self.live.insert(f));
            // SAFETY: inside the buffer.
            unsafe { core::ptr::write_bytes(self.buf.add(f as usize), 0xEE, PAGE) };
        }
        self.next = end;
        Ok(PhysAddr::new(start))
    }

    fn free(&mut self, frame: PhysAddr) {
        assert!(self.live.remove(&frame.raw()), "free of {frame:?}, which is not allocated");
        self.freed.push(frame.raw());
    }
}

/// Stores for share counts; each test takes its own.
fn slots(n: usize) -> Vec<ShareSlot> {
    std::vec![ShareSlot::EMPTY; n]
}

struct Cpu;

impl Cpu {
    /// Read or write one byte at `addr` the way an MMU would: consult the tables, fault
    /// to the `Vm` if they refuse, retry.
    fn access<const N: usize>(
        vm: &mut Vm<'_, MockFull, N>,
        mem: &mut Mem,
        addr: usize,
        access: Access,
        value: u8,
    ) -> Result<u8, VmError> {
        for _ in 0..3 {
            if let Some((phys, flags)) = vm.space().translate(addr) {
                let permitted = match access {
                    Access::Read => true,
                    Access::Write => flags.contains(PageFlags::WRITE),
                    Access::Execute => flags.contains(PageFlags::EXECUTE),
                };
                if permitted {
                    let p = mem.byte(phys);
                    // SAFETY: inside the buffer, checked by `byte`.
                    unsafe {
                        if access == Access::Write {
                            *p = value;
                        }
                        return Ok(*p);
                    }
                }
            }
            vm.fault(PageFault { addr, access }, mem)?;
        }
        panic!("the access at {addr:#x} faulted three times: the resolver changed nothing");
    }

    fn read<const N: usize>(vm: &mut Vm<'_, MockFull, N>, mem: &mut Mem, addr: usize) -> u8 {
        Cpu::access(vm, mem, addr, Access::Read, 0).expect("read")
    }

    fn write<const N: usize>(vm: &mut Vm<'_, MockFull, N>, mem: &mut Mem, addr: usize, v: u8) {
        Cpu::access(vm, mem, addr, Access::Write, v).expect("write");
    }
}

/// A canonical low-half base, 2 MiB aligned, with room for several huge blocks.
const BASE: usize = 0x0000_1000_0000_0000;

/// Where shares land: two pages below a 2 MiB boundary, so a destination of more than
/// two pages needs a second leaf table part-way through, and an allocation can fail
/// after some pages are already shared.
const DST: usize = BASE + TWO_MIB * 4 - 2 * PAGE;

fn anon(start: usize, pages: usize) -> Region {
    Region {
        start,
        len: pages * PAGE,
        flags: RW,
        backing: Backing::Anonymous,
        huge: false,
    }
}

/// A `Vm` over fresh memory, and the frame count after its root table: the baseline
/// a full teardown must return to.
fn setup(frames: usize, store: &mut [ShareSlot]) -> (Mem, Vm<'_, MockFull, 16>, usize) {
    let mut mem = Mem::new(frames);
    let space = AddressSpace::<MockFull>::new(mem.direct(), &mut mem).unwrap();
    let baseline = mem.live.len();
    (mem, Vm::new(space, Shares::new(store)), baseline)
}

// ---- the region map, on both page sizes -------------------------------------

fn region_map_basics<A: Arch>() {
    let p = A::PAGE_SIZE;
    let mut r = Regions::<A, 4>::new();
    let reg = |start: usize, pages: usize| Region {
        start,
        len: pages * p,
        flags: RW,
        backing: Backing::Anonymous,
        huge: false,
    };
    r.insert(reg(10 * p, 4)).unwrap();
    r.insert(reg(2 * p, 2)).unwrap();
    assert_eq!(r.insert(reg(3 * p, 2)), Err(VmError::Overlap), "overlaps the tail of [2,4)");
    assert_eq!(r.insert(reg(13 * p, 1)), Err(VmError::Overlap), "inside [10,14)");
    assert_eq!(r.insert(reg(p + 1, 1)), Err(VmError::Misaligned));
    assert_eq!(r.insert(reg(20 * p, 0)), Err(VmError::Empty));
    r.insert(reg(4 * p, 6)).unwrap(); // exactly fills [4,10): adjacent is not overlapping
    assert_eq!(r.find(9 * p).map(|(_, x)| x.start), Some(4 * p));
    assert_eq!(r.find(14 * p), None, "one past the end is outside");
    assert_eq!(r.find(p), None);
    let starts: Vec<usize> = r.iter().map(|x| x.start).collect();
    assert_eq!(starts, std::vec![2 * p, 4 * p, 10 * p], "kept sorted");

    r.split_at(12 * p).unwrap();
    assert_eq!(r.len(), 4);
    assert_eq!(r.exact(12 * p).map(|(_, x)| x.len), Some(2 * p));
    assert_eq!(r.exact(10 * p).map(|(_, x)| x.len), Some(2 * p));
    assert_eq!(r.split_at(6 * p), Err(VmError::RegionsFull), "no slot for the second half");
    assert_eq!(r.split_at(4 * p), Ok(()), "already a boundary: nothing to do");

    let (i, _) = r.exact(2 * p).unwrap();
    r.remove(i).unwrap();
    assert_eq!(r.find(2 * p), None);
    assert_eq!(r.len(), 3);
}

#[test]
fn region_map_full() {
    region_map_basics::<MockFull>();
}

#[test]
fn region_map_tiny() {
    region_map_basics::<MockTiny>();
}

fn a_split_physical_range_keeps_its_offsets<A: Arch>() {
    let p = A::PAGE_SIZE;
    let mut r = Regions::<A, 4>::new();
    let base = PhysAddr::new(64 * p as u64);
    r.insert(Region {
        start: 8 * p,
        len: 8 * p,
        flags: RW,
        backing: Backing::Physical { base },
        huge: false,
    })
    .unwrap();
    r.split_at(11 * p).unwrap();
    let (_, tail) = r.exact(11 * p).unwrap();
    assert_eq!(tail.phys_at(11 * p), Some(PhysAddr::new(67 * p as u64)));
    assert_eq!(tail.phys_at(15 * p + 3), Some(PhysAddr::new(71 * p as u64 + 3)));
}

#[test]
fn a_split_physical_range_keeps_its_offsets_full() {
    a_split_physical_range_keeps_its_offsets::<MockFull>();
}

#[test]
fn a_split_physical_range_keeps_its_offsets_tiny() {
    a_split_physical_range_keeps_its_offsets::<MockTiny>();
}

#[test]
fn a_physical_base_off_a_page_boundary_is_refused_on_either_page_size() {
    for p in [MockFull::PAGE_SIZE, MockTiny::PAGE_SIZE] {
        let reg = Region {
            start: 0,
            len: p,
            flags: RW,
            backing: Backing::Physical {
                base: PhysAddr::new(p as u64 / 2),
            },
            huge: false,
        };
        if p == MockTiny::PAGE_SIZE {
            assert_eq!(Regions::<MockTiny, 1>::new().insert(reg), Err(VmError::Misaligned));
        } else {
            assert_eq!(Regions::<MockFull, 1>::new().insert(reg), Err(VmError::Misaligned));
        }
    }
}

// ---- share counts -------------------------------------------------------------

#[test]
fn share_counts_start_at_one_and_free_on_the_last() {
    let mut store = slots(2);
    let mut s = Shares::new(&mut store);
    let a = PhysAddr::new(0x1000);
    let b = PhysAddr::new(0x2000);
    assert_eq!(s.count(a), 1, "a mapped frame with no slot has one mapping");
    s.share(a).unwrap();
    s.share(a).unwrap();
    assert_eq!(s.count(a), 3);
    assert_eq!(s.free_slots(), 1, "a second share of the same frame takes no new slot");
    s.share(b).unwrap();
    assert_eq!(s.share(PhysAddr::new(0x3000)), Err(VmError::SharesFull));
    assert_eq!(s.unshare(a), Remaining::Shared);
    assert_eq!(s.unshare(a), Remaining::Shared);
    assert!(!s.is_shared(a), "back to one mapping: the slot is released");
    assert_eq!(s.unshare(a), Remaining::Last, "and dropping that one frees the frame");
    assert_eq!(s.free_slots(), 1);
}

// ---- demand paging --------------------------------------------------------------

#[test]
fn reserving_maps_nothing_and_touching_maps_one_page() {
    let mut store = slots(4);
    let (mut mem, mut vm, baseline) = setup(256, &mut store);
    vm.reserve(anon(BASE, 16)).unwrap();
    assert_eq!(mem.live.len(), baseline, "a reservation takes no frames");
    assert_eq!(vm.space().translate(BASE + 3 * PAGE), None);

    assert_eq!(Cpu::read(&mut vm, &mut mem, BASE + 3 * PAGE + 7), 0);
    let audit = vm.audit().unwrap();
    assert_eq!(audit.pages, 1);
    assert_eq!(audit.frames_held, 1);
    assert_eq!(vm.space().translate(BASE + 2 * PAGE), None, "only the page touched");
}

#[test]
fn a_demand_page_is_zeroed_even_from_a_dirty_source() {
    let mut store = slots(4);
    let (mut mem, mut vm, _) = setup(256, &mut store);
    vm.reserve(anon(BASE, 4)).unwrap();
    // `Mem::alloc` fills every frame with 0xEE; the resolver must not trust it.
    for off in [0, 1, PAGE - 1] {
        assert_eq!(Cpu::read(&mut vm, &mut mem, BASE + PAGE + off), 0, "offset {off}");
    }
}

#[test]
fn frames_are_consumed_one_per_page_touched() {
    let mut store = slots(4);
    let (mut mem, mut vm, _) = setup(256, &mut store);
    vm.reserve(anon(BASE, 8)).unwrap();
    for i in 0..8 {
        Cpu::write(&mut vm, &mut mem, BASE + i * PAGE, i as u8);
        assert_eq!(vm.audit().unwrap().frames_held, i + 1);
    }
    for i in 0..8 {
        assert_eq!(Cpu::read(&mut vm, &mut mem, BASE + i * PAGE), i as u8);
    }
}

#[test]
fn faults_outside_a_region_or_its_permissions_are_refused() {
    let mut store = slots(4);
    let (mut mem, mut vm, baseline) = setup(256, &mut store);
    vm.reserve(Region {
        flags: PageFlags::KERNEL_RODATA,
        ..anon(BASE, 4)
    })
    .unwrap();
    let f = |addr, access| PageFault { addr, access };
    assert_eq!(vm.fault(f(BASE + 4 * PAGE, Access::Read), &mut mem), Err(VmError::NoRegion));
    assert_eq!(vm.fault(f(BASE, Access::Write), &mut mem), Err(VmError::Protection));
    assert_eq!(vm.fault(f(BASE, Access::Execute), &mut mem), Err(VmError::Protection));
    assert_eq!(mem.live.len(), baseline, "a refused fault allocates nothing");
    assert_eq!(Cpu::read(&mut vm, &mut mem, BASE), 0, "reading is what the region permits");
}

#[test]
fn a_fault_on_a_page_already_permitted_is_spurious_and_flushes() {
    let mut store = slots(4);
    let (mut mem, mut vm, _) = setup(256, &mut store);
    vm.reserve(anon(BASE, 1)).unwrap();
    Cpu::write(&mut vm, &mut mem, BASE, 1);
    let before = TLB_FLUSHES.load(core::sync::atomic::Ordering::SeqCst);
    let r = vm.fault(
        PageFault {
            addr: BASE,
            access: Access::Write,
        },
        &mut mem,
    );
    assert_eq!(r, Ok(Resolved::Spurious));
    assert!(TLB_FLUSHES.load(core::sync::atomic::Ordering::SeqCst) > before);
    assert_eq!(vm.audit().unwrap().frames_held, 1, "nothing was remapped");
}

#[test]
fn a_region_over_existing_mappings_is_refused() {
    let mut mem = Mem::new(256);
    let mut space = AddressSpace::<MockFull>::new(mem.direct(), &mut mem).unwrap();
    space
        .map(BASE + PAGE, PhysAddr::new(0x10000), PAGE, RW, &mut mem)
        .unwrap();
    let mut store = slots(1);
    let mut vm: Vm<'_, MockFull, 4> = Vm::new(space, Shares::new(&mut store));
    assert_eq!(vm.reserve(anon(BASE, 4)), Err(VmError::NotEmpty));
    assert!(vm.regions().is_empty());
    vm.reserve(anon(BASE + 2 * PAGE, 2)).unwrap();
}

#[test]
fn a_physical_region_maps_its_offsets_and_allocates_no_data_frames() {
    let mut store = slots(1);
    let (mut mem, mut vm, _) = setup(256, &mut store);
    let base = PhysAddr::new(0x40000);
    vm.reserve(Region {
        backing: Backing::Physical { base },
        ..anon(BASE, 8)
    })
    .unwrap();
    // SAFETY: inside the buffer.
    unsafe { *mem.byte(PhysAddr::new(0x40000 + 5 * PAGE as u64 + 9)) = 0x77 };
    let tables_before = mem.live.len();
    assert_eq!(Cpu::read(&mut vm, &mut mem, BASE + 5 * PAGE + 9), 0x77);
    assert_eq!(
        vm.space().translate(BASE + 5 * PAGE).map(|t| t.0),
        Some(PhysAddr::new(0x40000 + 5 * PAGE as u64))
    );
    // Three new tables below the root, and not one frame for the page itself.
    assert_eq!(mem.live.len(), tables_before + 3);
    assert_eq!(vm.audit().unwrap().frames_held, 0);
}

// ---- copy-on-write ---------------------------------------------------------------

/// Two regions of `pages`, the first written with a pattern and shared into the second.
fn shared_pair(vm: &mut Vm<'_, MockFull, 16>, mem: &mut Mem, pages: usize) -> (usize, usize) {
    let (src, dst) = (BASE, DST);
    vm.reserve(anon(src, pages)).unwrap();
    vm.reserve(anon(dst, pages)).unwrap();
    for i in 0..pages {
        Cpu::write(vm, mem, src + i * PAGE + 1, 0x10 + i as u8);
    }
    vm.cow_share(src, dst, mem).unwrap();
    (src, dst)
}

#[test]
fn a_shared_region_reads_the_same_bytes_and_copies_nothing() {
    let mut store = slots(8);
    let (mut mem, mut vm, _) = setup(256, &mut store);
    let frames_before_share = {
        vm.reserve(anon(BASE, 4)).unwrap();
        for i in 0..4 {
            Cpu::write(&mut vm, &mut mem, BASE + i * PAGE, 0x10 + i as u8);
        }
        vm.audit().unwrap().frames_held
    };
    vm.reserve(anon(DST, 4)).unwrap();
    vm.cow_share(BASE, DST, &mut mem).unwrap();
    let a = vm.audit().unwrap();
    assert_eq!(a.frames_held, frames_before_share, "sharing copies no page");
    assert_eq!(a.shared, 4);
    for i in 0..4 {
        assert_eq!(Cpu::read(&mut vm, &mut mem, DST + i * PAGE), 0x10 + i as u8);
    }
    for side in [BASE, DST] {
        let (_, flags) = vm.space().translate(side).unwrap();
        assert!(!flags.contains(PageFlags::WRITE), "both sides are read-only after a share");
    }
}

#[test]
fn a_write_to_one_side_copies_that_page_and_leaves_the_other_alone() {
    let mut store = slots(8);
    let (mut mem, mut vm, _) = setup(256, &mut store);
    let (src, dst) = shared_pair(&mut vm, &mut mem, 4);

    Cpu::write(&mut vm, &mut mem, src + PAGE + 1, 0xAA);
    assert_eq!(Cpu::read(&mut vm, &mut mem, src + PAGE + 1), 0xAA);
    assert_eq!(
        Cpu::read(&mut vm, &mut mem, dst + PAGE + 1),
        0x11,
        "the other side kept its copy"
    );
    assert_ne!(
        vm.space().translate(src + PAGE).unwrap().0,
        vm.space().translate(dst + PAGE).unwrap().0
    );
    let a = vm.audit().unwrap();
    assert_eq!(a.shared, 3);
    assert_eq!(a.frames_held, 5);

    // The other side of the page just split is now the only mapping of its frame, so a
    // write reuses it rather than copying again.
    let before = mem.live.len();
    let r = vm.fault(
        PageFault {
            addr: dst + PAGE,
            access: Access::Write,
        },
        &mut mem,
    );
    assert_eq!(r, Ok(Resolved::Reused));
    assert_eq!(mem.live.len(), before);

    Cpu::write(&mut vm, &mut mem, dst + 2 * PAGE + 1, 0xBB);
    assert_eq!(Cpu::read(&mut vm, &mut mem, src + 2 * PAGE + 1), 0x12);
    vm.audit().unwrap();
}

#[test]
fn sharing_invalidates_every_page_it_makes_read_only() {
    let mut store = slots(8);
    let (mut mem, mut vm, _) = setup(256, &mut store);
    vm.reserve(anon(BASE, 4)).unwrap();
    vm.reserve(anon(DST, 4)).unwrap();
    for i in 0..4 {
        Cpu::write(&mut vm, &mut mem, BASE + i * PAGE, 1);
    }
    let before = TLB_FLUSHES.load(core::sync::atomic::Ordering::SeqCst);
    vm.cow_share(BASE, DST, &mut mem).unwrap();
    // Other tests flush concurrently, so this can only say "at least".
    assert!(TLB_FLUSHES.load(core::sync::atomic::Ordering::SeqCst) >= before + 4);
}

#[test]
fn sharing_more_than_the_share_table_holds_is_refused_untouched() {
    let mut store = slots(3);
    let (mut mem, mut vm, _) = setup(256, &mut store);
    vm.reserve(anon(BASE, 4)).unwrap();
    vm.reserve(anon(DST, 4)).unwrap();
    for i in 0..4 {
        Cpu::write(&mut vm, &mut mem, BASE + i * PAGE, 1);
    }
    let before = vm.audit().unwrap();
    assert_eq!(vm.cow_share(BASE, DST, &mut mem), Err(VmError::SharesFull));
    assert_eq!(vm.audit().unwrap(), before);
    assert!(
        vm.space()
            .translate(BASE)
            .unwrap()
            .1
            .contains(PageFlags::WRITE)
    );
    assert_eq!(vm.space().translate(DST), None);
}

#[test]
fn sharing_into_a_region_that_has_pages_is_refused() {
    let mut store = slots(8);
    let (mut mem, mut vm, _) = setup(256, &mut store);
    vm.reserve(anon(BASE, 2)).unwrap();
    vm.reserve(anon(DST, 2)).unwrap();
    Cpu::write(&mut vm, &mut mem, DST, 1);
    assert_eq!(vm.cow_share(BASE, DST, &mut mem), Err(VmError::NotEmpty));
    vm.reserve(anon(BASE + TWO_MIB * 8, 3)).unwrap();
    assert_eq!(vm.cow_share(BASE, BASE + TWO_MIB * 8, &mut mem), Err(VmError::Mismatch));
}

// ---- failure part-way ---------------------------------------------------------------

/// Run `op` with the k-th allocation failing, for every k until it succeeds, checking
/// after each failure that the tables still satisfy every invariant and that releasing
/// everything returns the frames to where they started.
fn under_injection(
    pages: usize,
    op: impl Fn(&mut Vm<'_, MockFull, 16>, &mut Mem) -> Result<(), VmError>,
) {
    let mut k = 0;
    loop {
        let mut store = slots(64);
        let (mut mem, mut vm, baseline) = setup(4096, &mut store);
        vm.reserve(anon(BASE, pages)).unwrap();
        vm.reserve(anon(DST, pages)).unwrap();
        mem.attempts = 0;
        mem.fail_at = Some(k);
        let result = op(&mut vm, &mut mem);
        mem.fail_at = None;
        if let Err(e) = result {
            assert_eq!(e, VmError::OutOfMemory, "injected failure {k} surfaced as {e:?}");
        }
        vm.audit()
            .unwrap_or_else(|e| panic!("after failure {k}: invariant broken: {e:?}"));
        vm.release(BASE, &mut mem).unwrap();
        vm.release(DST, &mut mem).unwrap();
        assert!(vm.shares().iter().next().is_none(), "after failure {k}: counts left behind");
        assert_eq!(mem.live.len(), baseline, "after failure {k}: frames leaked");
        if result.is_ok() {
            assert!(k > 0, "the operation must allocate at least once");
            return;
        }
        k += 1;
    }
}

#[test]
fn a_failed_demand_fault_leaves_nothing_behind() {
    under_injection(8, |vm, mem| {
        for i in 0..8 {
            Cpu::access(vm, mem, BASE + i * PAGE, Access::Write, 3)?;
        }
        Ok(())
    });
}

#[test]
fn a_failed_share_is_undone_and_leaves_nothing_behind() {
    under_injection(6, |vm, mem| {
        // Pages written without injection first would not test the share; the setup
        // allocations count too, so every k lands somewhere in touch-then-share.
        for i in 0..6 {
            Cpu::access(vm, mem, BASE + i * PAGE, Access::Write, 3)?;
        }
        vm.cow_share(BASE, DST, mem)?;
        let src_writable = vm
            .space()
            .translate(BASE)
            .is_some_and(|t| t.1.contains(PageFlags::WRITE));
        assert!(!src_writable, "a completed share leaves the source read-only");
        Cpu::access(vm, mem, DST + PAGE, Access::Write, 9)?;
        Ok(())
    });
}

#[test]
fn a_share_that_fails_part_way_restores_the_source_permissions() {
    // The share's only allocations are the destination's leaf tables: one for the two
    // pages below the 2 MiB boundary, one for the two above. Failing the second fails
    // after two source pages were already made read-only, and they must come back.
    let mut store = slots(8);
    let (mut mem, mut vm, _) = setup(256, &mut store);
    vm.reserve(anon(BASE, 4)).unwrap();
    vm.reserve(anon(DST, 4)).unwrap();
    for i in 0..4 {
        Cpu::write(&mut vm, &mut mem, BASE + i * PAGE, 1);
    }
    let before = vm.audit().unwrap();
    mem.attempts = 0;
    mem.fail_at = Some(1);
    assert_eq!(vm.cow_share(BASE, DST, &mut mem), Err(VmError::OutOfMemory));
    assert_eq!(mem.attempts, 2, "failed at the second table, not before it");
    assert_eq!(vm.audit().unwrap(), before);
    for i in 0..4 {
        assert!(
            vm.space()
                .translate(BASE + i * PAGE)
                .unwrap()
                .1
                .contains(PageFlags::WRITE)
        );
    }
}

// ---- huge pages -------------------------------------------------------------------

fn huge_region(start: usize, blocks: usize) -> Region {
    Region {
        len: blocks * TWO_MIB,
        huge: true,
        ..anon(start, 0)
    }
}

#[test]
fn a_huge_region_faults_in_a_whole_zeroed_block() {
    let mut store = slots(1);
    let (mut mem, mut vm, baseline) = setup(2048, &mut store);
    vm.reserve(huge_region(BASE, 2)).unwrap();
    let r = vm.fault(
        PageFault {
            addr: BASE + TWO_MIB + 12345,
            access: Access::Write,
        },
        &mut mem,
    );
    assert_eq!(r, Ok(Resolved::Zeroed { huge: true }));
    let a = vm.audit().unwrap();
    assert_eq!((a.huge, a.pages, a.frames_held), (1, 0, 512));
    assert_eq!(
        Cpu::read(&mut vm, &mut mem, BASE + TWO_MIB + TWO_MIB - 1),
        0,
        "zeroed to the end"
    );
    let (p0, _) = vm.space().translate(BASE + TWO_MIB).unwrap();
    let (p1, _) = vm.space().translate(BASE + TWO_MIB + 3 * PAGE + 5).unwrap();
    assert_eq!(p1.raw() - p0.raw(), 3 * PAGE as u64 + 5, "one contiguous block");
    assert_eq!(vm.space().translate(BASE), None, "the other block is untouched");
    vm.release(BASE, &mut mem).unwrap();
    assert_eq!(mem.live.len(), baseline);
}

#[test]
fn a_huge_fault_that_cannot_map_its_block_gives_the_block_back() {
    let fault = PageFault {
        addr: BASE + 5,
        access: Access::Write,
    };
    // Attempt 0 is the block. Failing it falls back to base pages, which succeeds.
    let mut store = slots(1);
    let (mut mem, mut vm, baseline) = setup(2048, &mut store);
    vm.reserve(huge_region(BASE, 1)).unwrap();
    mem.attempts = 0;
    mem.fail_at = Some(0);
    assert_eq!(vm.fault(fault, &mut mem), Ok(Resolved::Zeroed { huge: false }));
    vm.release(BASE, &mut mem).unwrap();
    assert_eq!(mem.live.len(), baseline);

    // Attempts 1 and 2 are the tables the block's leaf needs. Failing either fails the
    // fault, and the 512 frames already taken must all come back.
    for k in [1, 2] {
        let mut store = slots(1);
        let (mut mem, mut vm, baseline) = setup(2048, &mut store);
        vm.reserve(huge_region(BASE, 1)).unwrap();
        mem.attempts = 0;
        mem.fail_at = Some(k);
        assert_eq!(vm.fault(fault, &mut mem), Err(VmError::OutOfMemory), "failure {k}");
        assert_eq!(mem.live.len(), baseline, "failure {k}: the block or a table leaked");
        vm.audit().unwrap();
    }
}

#[test]
fn without_a_contiguous_block_a_huge_region_uses_base_pages() {
    let mut store = slots(1);
    let (mut mem, mut vm, _) = setup(1024, &mut store);
    mem.blocks = false;
    vm.reserve(huge_region(BASE, 1)).unwrap();
    let r = vm.fault(
        PageFault {
            addr: BASE,
            access: Access::Read,
        },
        &mut mem,
    );
    assert_eq!(r, Ok(Resolved::Zeroed { huge: false }));
    assert_eq!(vm.audit().unwrap().frames_held, 1);
}

#[test]
fn a_block_not_wholly_inside_the_region_is_not_mapped_huge() {
    let mut store = slots(1);
    let (mut mem, mut vm, _) = setup(2048, &mut store);
    vm.reserve(Region {
        len: TWO_MIB,
        huge: true,
        ..anon(BASE + PAGE, 0)
    })
    .unwrap();
    let r = vm.fault(
        PageFault {
            addr: BASE + TWO_MIB,
            access: Access::Read,
        },
        &mut mem,
    );
    assert_eq!(r, Ok(Resolved::Zeroed { huge: false }), "the block starts before the region");
}

#[test]
fn a_huge_physical_range_maps_one_leaf() {
    let mut store = slots(1);
    let (mut mem, mut vm, _) = setup(64, &mut store);
    vm.reserve(Region {
        backing: Backing::Physical {
            base: PhysAddr::new(0x4000_0000),
        },
        ..huge_region(BASE, 1)
    })
    .unwrap();
    let r = vm.fault(
        PageFault {
            addr: BASE + 77 * PAGE,
            access: Access::Read,
        },
        &mut mem,
    );
    assert_eq!(r, Ok(Resolved::Physical { huge: true }));
    assert_eq!(
        vm.space().translate(BASE + 77 * PAGE + 1).map(|t| t.0),
        Some(PhysAddr::new(0x4000_0000 + 77 * PAGE as u64 + 1))
    );
}

#[test]
fn sharing_a_huge_leaf_splits_it_and_copies_only_the_page_written() {
    let mut store = slots(1024);
    let (mut mem, mut vm, baseline) = setup(4096, &mut store);
    let (src, dst) = (BASE, BASE + TWO_MIB * 4);
    vm.reserve(huge_region(src, 1)).unwrap();
    vm.reserve(huge_region(dst, 1)).unwrap();
    for i in [0, 100, 511] {
        Cpu::write(&mut vm, &mut mem, src + i * PAGE + 2, i as u8 ^ 0x5A);
    }
    assert_eq!(vm.audit().unwrap().huge, 1);
    vm.cow_share(src, dst, &mut mem).unwrap();
    let a = vm.audit().unwrap();
    assert_eq!((a.huge, a.pages, a.shared, a.frames_held), (0, 1024, 512, 512));

    Cpu::write(&mut vm, &mut mem, dst + 100 * PAGE + 2, 0xFF);
    assert_eq!(Cpu::read(&mut vm, &mut mem, src + 100 * PAGE + 2), 100u8 ^ 0x5A);
    assert_eq!(Cpu::read(&mut vm, &mut mem, dst + 511 * PAGE + 2), 511usize as u8 ^ 0x5A);
    assert_eq!(vm.audit().unwrap().frames_held, 513);

    vm.release(src, &mut mem).unwrap();
    assert_eq!(Cpu::read(&mut vm, &mut mem, dst + 2), 0x5A, "the survivor keeps the data");
    vm.release(dst, &mut mem).unwrap();
    assert_eq!(mem.live.len(), baseline);
}

#[test]
fn protecting_part_of_a_huge_leaf_splits_it_and_keeps_its_contents() {
    let mut store = slots(1);
    let (mut mem, mut vm, _) = setup(2048, &mut store);
    vm.reserve(huge_region(BASE, 1)).unwrap();
    for i in [9, 10, 11] {
        Cpu::write(&mut vm, &mut mem, BASE + i * PAGE, i as u8);
    }
    vm.protect(BASE + 10 * PAGE, PAGE, PageFlags::KERNEL_RODATA, &mut mem)
        .unwrap();
    assert_eq!(vm.regions().len(), 3);
    let a = vm.audit().unwrap();
    assert_eq!((a.huge, a.pages, a.frames_held), (0, 512, 512));
    for i in [9, 10, 11] {
        assert_eq!(Cpu::read(&mut vm, &mut mem, BASE + i * PAGE), i as u8);
    }
    assert_eq!(
        Cpu::access(&mut vm, &mut mem, BASE + 10 * PAGE, Access::Write, 1),
        Err(VmError::Protection)
    );
    Cpu::write(&mut vm, &mut mem, BASE + 11 * PAGE, 0x42);
    Cpu::write(&mut vm, &mut mem, BASE + 9 * PAGE, 0x42);
}

#[test]
fn protecting_an_unshared_range_writable_again_makes_its_pages_writable() {
    let mut store = slots(1);
    let (mut mem, mut vm, _) = setup(256, &mut store);
    vm.reserve(anon(BASE, 4)).unwrap();
    Cpu::write(&mut vm, &mut mem, BASE + PAGE, 1);
    vm.protect(BASE, 4 * PAGE, PageFlags::KERNEL_RODATA, &mut mem)
        .unwrap();
    assert!(
        !vm.space()
            .translate(BASE + PAGE)
            .unwrap()
            .1
            .contains(PageFlags::WRITE)
    );
    vm.protect(BASE, 4 * PAGE, RW, &mut mem).unwrap();
    assert!(
        vm.space()
            .translate(BASE + PAGE)
            .unwrap()
            .1
            .contains(PageFlags::WRITE)
    );
    assert_eq!(vm.regions().len(), 1, "the whole region: nothing to split");
}

#[test]
fn granting_write_does_not_make_a_shared_page_writable() {
    let mut store = slots(8);
    let (mut mem, mut vm, _) = setup(256, &mut store);
    let (src, dst) = shared_pair(&mut vm, &mut mem, 2);
    vm.protect(src, 2 * PAGE, RW, &mut mem).unwrap();
    assert!(
        !vm.space()
            .translate(src)
            .unwrap()
            .1
            .contains(PageFlags::WRITE),
        "still shared, so still read-only"
    );
    vm.audit().unwrap();
    Cpu::write(&mut vm, &mut mem, src + 1, 0xCC);
    assert_eq!(Cpu::read(&mut vm, &mut mem, dst + 1), 0x10);
}

#[test]
fn protecting_across_a_region_boundary_is_refused() {
    let mut store = slots(1);
    let (mut mem, mut vm, _) = setup(256, &mut store);
    vm.reserve(anon(BASE, 2)).unwrap();
    vm.reserve(anon(BASE + 2 * PAGE, 2)).unwrap();
    assert_eq!(vm.protect(BASE + PAGE, 2 * PAGE, RW, &mut mem), Err(VmError::Mismatch));
}

#[test]
fn releasing_everything_returns_every_frame_and_table() {
    let mut store = slots(16);
    let (mut mem, mut vm, baseline) = setup(2048, &mut store);
    let (src, dst) = shared_pair(&mut vm, &mut mem, 8);
    Cpu::write(&mut vm, &mut mem, dst + 3 * PAGE, 1);
    vm.reserve(huge_region(BASE + TWO_MIB * 8, 1)).unwrap();
    Cpu::write(&mut vm, &mut mem, BASE + TWO_MIB * 8, 1);
    vm.release(src, &mut mem).unwrap();
    vm.audit().unwrap();
    vm.release(dst, &mut mem).unwrap();
    vm.release(BASE + TWO_MIB * 8, &mut mem).unwrap();
    assert!(vm.regions().is_empty());
    assert_eq!(mem.live.len(), baseline);
}

// ---- fork: sharing a whole space with another -----------------------------------

#[test]
fn a_fork_shares_every_page_and_a_write_on_either_side_stays_on_that_side() {
    let mut store = slots(16);
    let counts = core::ptr::NonNull::from(&mut store[..]);
    let mut mem = Mem::new(64);
    let space = AddressSpace::<MockFull>::new(mem.direct(), &mut mem).unwrap();
    // SAFETY: `store` outlives both views, and the test uses one `Vm` at a time.
    let mut parent: Vm<'_, MockFull, 4> = Vm::new(space, unsafe { Shares::shared(counts) });
    parent.reserve(anon(BASE, 3)).unwrap();
    Cpu::write(&mut parent, &mut mem, BASE, 1);
    Cpu::write(&mut parent, &mut mem, BASE + PAGE, 2);

    let space = AddressSpace::<MockFull>::new(mem.direct(), &mut mem).unwrap();
    // SAFETY: as above.
    let mut child: Vm<'_, MockFull, 4> = Vm::new(space, unsafe { Shares::shared(counts) });
    parent.fork_into(&mut child, &mut mem).unwrap();
    assert_eq!(child.regions().iter().count(), 1, "the region is reserved in the child");
    assert_eq!(parent.shares().iter().count(), 2, "both mapped pages are shared");
    assert_eq!(Cpu::read(&mut child, &mut mem, BASE), 1);
    assert_eq!(Cpu::read(&mut child, &mut mem, BASE + PAGE), 2);

    // The child writes one page: its copy changes and the parent's does not.
    Cpu::write(&mut child, &mut mem, BASE, 9);
    assert_eq!(Cpu::read(&mut parent, &mut mem, BASE), 1);
    assert_eq!(Cpu::read(&mut child, &mut mem, BASE), 9);
    // The parent writes the other: the child still reads what was there at the fork.
    Cpu::write(&mut parent, &mut mem, BASE + PAGE, 7);
    assert_eq!(Cpu::read(&mut child, &mut mem, BASE + PAGE), 2);
    assert_eq!(Cpu::read(&mut parent, &mut mem, BASE + PAGE), 7);
    assert_eq!(parent.shares().iter().count(), 0, "every shared page has been written");

    child.release(BASE, &mut mem).unwrap();
    parent.release(BASE, &mut mem).unwrap();
}

#[test]
fn a_fork_into_a_space_that_has_regions_is_refused() {
    let mut store = slots(16);
    let counts = core::ptr::NonNull::from(&mut store[..]);
    let mut mem = Mem::new(32);
    let space = AddressSpace::<MockFull>::new(mem.direct(), &mut mem).unwrap();
    // SAFETY: as in the test above.
    let mut parent: Vm<'_, MockFull, 4> = Vm::new(space, unsafe { Shares::shared(counts) });
    parent.reserve(anon(BASE, 1)).unwrap();
    let space = AddressSpace::<MockFull>::new(mem.direct(), &mut mem).unwrap();
    // SAFETY: as above.
    let mut child: Vm<'_, MockFull, 4> = Vm::new(space, unsafe { Shares::shared(counts) });
    child.reserve(anon(BASE, 1)).unwrap();
    assert_eq!(parent.fork_into(&mut child, &mut mem), Err(VmError::NotEmpty));
}

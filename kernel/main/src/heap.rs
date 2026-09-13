//! Bringing the kernel heap up on the machine's frames.
//!
//! Every allocator the heap is built from is exercised once on real memory: a small
//! object from the slab, whose block the arena takes from the frame allocator, and a
//! multi-page block from the buddy allocator over a run of frames. Each is written and
//! read back, then freed, and the buddy run is returned.
//!
//! This heap does not outlive the function. The one that does is `kheap`, installed
//! right after it, over frames of its own. What is kept from this one is the arena's
//! frames, which the arena never returns; the banner line says how many.

use core::alloc::Layout;
use core::cell::SyncUnsafeCell;

use arch::Cpu;
use boot_protocol::{MemoryKind, MemoryRegion};
use hal::{Arch, EarlyConsole, KernAddr, PhysAddr};
use kalloc::{AllocContext, Heap, buddy};
use mm::DirectMap;
use mm::phys::FrameAllocator;

use crate::{Check, DIRECT_MAP_MAX, write_usize};

/// Pages in the buddy run.
const PAGES: usize = 64;

const STORE_BYTES: usize = PAGES * buddy::STORE_BYTES_PER_PAGE;

/// SAFETY INVARIANT: used only by `bring_up`, which runs once, on one CPU, before any
/// other task exists.
static STORE: SyncUnsafeCell<[u8; STORE_BYTES]> = SyncUnsafeCell::new([0; STORE_BYTES]);

/// Build a heap, allocate through each of its routes, and report.
pub fn bring_up(
    c: &dyn EarlyConsole,
    frames: &mut FrameAllocator<'_, Cpu>,
    map: &[MemoryRegion],
) -> Check {
    c.write_str("\n  heap       ");
    // The window `kernel_space` builds its direct map over: lowest to highest usable
    // byte, capped the same way, at the same virtual addresses. The first version covered
    // only the buddy run, and the arena's frames, which come from above it, were refused
    // as outside the map.
    let usable = || map.iter().filter(|r| r.kind == MemoryKind::Usable as u32);
    let lo = usable().map(|r| r.start).min().unwrap_or(0);
    let hi = usable()
        .map(|r| r.start.saturating_add(r.len))
        .max()
        .unwrap_or(lo);
    let len = hi.saturating_sub(lo).min(DIRECT_MAP_MAX);
    let window = usize::try_from(lo)
        .ok()
        .and_then(|v| DirectMap::new(PhysAddr::new(lo), KernAddr::new(v), len).ok());
    let Some(window) = window else {
        c.write_str("no direct map over usable memory");
        return Check::Failed;
    };
    let Ok(run) = frames.alloc_contiguous(PAGES) else {
        c.write_str("no run of frames for the buddy allocator");
        return Check::Failed;
    };

    // SAFETY: the only use of STORE, from the single-threaded boot path; see its invariant.
    let store: &'static mut [u8] = unsafe { &mut *STORE.get() };
    let mut heap = Heap::<Cpu>::new(window);
    if heap.attach_pages(run, store).is_err() {
        let _ = frames.free_contiguous(run);
        c.write_str("buddy allocator rejected the run");
        return Check::Failed;
    }

    let small = round_trip(&mut heap, frames, 48, 0x5A);
    let large = round_trip(&mut heap, frames, Cpu::PAGE_SIZE * 3, 0xA5);
    let s = heap.stats();
    let balanced = s.bytes_in_use == 0 && s.pages.free_pages == PAGES && s.pages.merges > 0;
    let returned = match heap.detach_pages() {
        Ok((run, _)) => frames.free_contiguous(run).is_ok(),
        Err(_) => false,
    };

    write_usize(c, PAGES);
    c.write_str("-page buddy, ");
    write_usize(c, s.bump.frames_held);
    c.write_str(" arena frames");
    let ok = small && large && balanced && returned;
    c.write_str(if ok { " ok" } else { " FAILED" });
    Check::from_ok(ok)
}

/// Allocate `size` bytes, fill them, read them back, free them.
fn round_trip(
    heap: &mut Heap<Cpu>,
    frames: &mut FrameAllocator<'_, Cpu>,
    size: usize,
    fill: u8,
) -> bool {
    let Ok(layout) = Layout::from_size_align(size, 8) else {
        return false;
    };
    let Ok(p) = heap.try_alloc_in(layout, AllocContext::KERNEL_ZEROED, frames) else {
        return false;
    };
    // SAFETY: a live, zeroed allocation of `size` bytes over identity-mapped RAM that
    // nothing else uses, read and written only here and freed before returning.
    let intact = unsafe {
        let bytes = core::slice::from_raw_parts_mut(p.as_ptr(), size);
        let zeroed = bytes.iter().all(|b| *b == 0);
        bytes.fill(fill);
        zeroed && bytes.iter().all(|b| *b == fill)
    };
    // SAFETY: `p` came from this heap with `layout` and is freed exactly once.
    let freed = unsafe { heap.dealloc(p, layout, AllocContext::KERNEL_ZEROED) }.is_ok();
    intact && freed
}

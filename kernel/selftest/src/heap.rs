//! The heap over the machine's real frames: allocate until nothing is left, give it all
//! back, and check that every book balances.
//!
//! The host tests prove the same properties against host memory standing in for
//! physical frames. What they cannot prove is that a real run from the real frame
//! allocator is reachable through the direct map the kernel will use, and that its
//! blocks hold what is written to them on the real machine. That needs actual reads and
//! writes, and it is where a wrong page size or an off-by-one in the direct map shows up
//! as corruption rather than as arithmetic.

use core::alloc::Layout;
use core::cell::SyncUnsafeCell;
use core::ptr::NonNull;

use hal::Arch;
use kalloc::{AllocContext, AllocError, Heap, buddy};
use mm::DirectMap;
use mm::phys::FrameAllocator;

use crate::Report;

/// Pages handed to the heap: one maximal block of order 8, so a full merge is a single,
/// checkable block.
const PAGES: usize = 256;

const STORE_BYTES: usize = PAGES * buddy::STORE_BYTES_PER_PAGE;

/// SAFETY INVARIANT: used only by `exhaust_and_return`, which runs once on the boot CPU
/// before any other execution context exists.
static STORE: SyncUnsafeCell<[u8; STORE_BYTES]> = SyncUnsafeCell::new([0; STORE_BYTES]);

/// Every block handed out: address, size, fill byte. Static, because 256 of them on a
/// 16 KiB boot stack beside a heap would be a stack overflow waiting for a larger build.
///
/// SAFETY INVARIANT: as for `STORE`.
static HELD: SyncUnsafeCell<[(usize, usize, u8); PAGES]> = SyncUnsafeCell::new([(0, 0, 0); PAGES]);

/// Build a heap over a run of the machine's frames, exhaust it, free everything, and
/// return the run.
pub fn exhaust_and_return<A: Arch>(r: &mut Report, frames: &mut FrameAllocator<'_, A>) {
    let before = frames.stats().free;
    let Ok(run) = frames.alloc_contiguous(PAGES) else {
        r.skip("heap over real frames", "no run of 256 free frames");
        return;
    };
    // Identity, as the rest of the boot path is today: the run is low memory, which every
    // port maps one-to-one until the kernel's own address space is activated.
    let end = run
        .len_bytes()
        .ok()
        .and_then(|len| run.start().start().raw().checked_add(len));
    let Some(map) = end.and_then(|end| DirectMap::identity(end).ok()) else {
        let _ = frames.free_contiguous(run);
        r.skip("heap over real frames", "run is not reachable through an identity map");
        return;
    };

    // SAFETY: the single user of STORE and HELD, called once on the single-threaded boot
    // path; see the invariants on the statics. No other reference to either exists.
    let (store, held): (&'static mut [u8], &mut [(usize, usize, u8); PAGES]) =
        unsafe { (&mut *STORE.get(), &mut *HELD.get()) };

    let mut heap = Heap::<A>::new(map);
    let attached = heap.attach_pages(run, store).is_ok();
    r.check("heap takes a run of real frames", attached);
    if !attached {
        let _ = frames.free_contiguous(run);
        return;
    }

    // Past the largest slab class, so every request goes to the buddy allocator.
    let pages = |n: usize| (A::PAGE_SIZE * n).max(1025);
    let mut count = 0usize;
    let mut unexpected = false;
    // Mixed orders first, which fragments the run, then single pages until those run
    // out too. `try_alloc` takes no frames, so the arena behind the buddy is empty and a
    // full buddy is a refusal rather than a quiet fallback.
    for sizes in [&[3usize, 8, 2, 1][..], &[1][..]] {
        let mut i = 0usize;
        loop {
            let size = pages(sizes[i % sizes.len()]);
            let Ok(layout) = Layout::from_size_align(size, 8) else {
                unexpected = true;
                break;
            };
            match heap.try_alloc(layout, AllocContext::ATOMIC) {
                Ok(p) if count < PAGES => {
                    let fill = u8::try_from(count % 250).unwrap_or(0) + 1;
                    // SAFETY: a live allocation of `size` bytes, just handed out by the
                    // heap over identity-mapped RAM that nothing else uses.
                    unsafe { p.as_ptr().write_bytes(fill, size) };
                    // Exposed, because the checks below turn the address back into a pointer.
                    held[count] = (p.as_ptr().expose_provenance(), size, fill);
                    count += 1;
                }
                Ok(_) => {
                    unexpected = true;
                    break;
                }
                Err(AllocError::Exhausted | AllocError::Fragmented) => break,
                Err(_) => {
                    unexpected = true;
                    break;
                }
            }
            i += 1;
        }
    }
    let s = heap.stats();
    r.check(
        "heap allocates until every page is in use",
        !unexpected && count > 0 && s.pages.free_pages == 0,
    );
    let refused = Layout::from_size_align(pages(1), 8)
        .map(|l| heap.try_alloc(l, AllocContext::ATOMIC).err() == Some(AllocError::Exhausted))
        .unwrap_or(false);
    r.check("heap refuses once exhausted", refused);

    let mut intact = true;
    for &(addr, size, fill) in held.iter().take(count) {
        // SAFETY: a live block of `size` bytes from the heap, written above and not freed.
        let bytes = unsafe {
            core::slice::from_raw_parts(core::ptr::with_exposed_provenance::<u8>(addr), size)
        };
        if bytes.iter().any(|b| *b != fill) {
            intact = false;
        }
    }
    r.check("heap blocks keep their contents on real memory", intact);

    // Odd entries first, then even, so merges happen out of allocation order.
    let mut freed = true;
    for parity in [1usize, 0] {
        for (i, &(addr, size, _)) in held.iter().take(count).enumerate() {
            if i % 2 != parity {
                continue;
            }
            let ptr = NonNull::new(core::ptr::with_exposed_provenance_mut::<u8>(addr));
            let ok = match (ptr, Layout::from_size_align(size, 8)) {
                // SAFETY: each entry is a live block from this heap, freed once, with the
                // layout it was allocated with.
                (Some(p), Ok(l)) => unsafe { heap.dealloc(p, l, AllocContext::ATOMIC) }.is_ok(),
                _ => false,
            };
            freed &= ok;
        }
    }
    r.check("heap frees every block", freed);

    let s = heap.stats();
    r.check(
        "heap merges back into one block",
        s.pages.free_pages == PAGES && s.pages.free_blocks[8] == 1 && s.pages.merges > 0,
    );
    r.check(
        "heap accounting returns to zero",
        s.bytes_in_use == 0 && s.allocations == s.frees && s.pages.live_blocks == 0,
    );

    let returned = match heap.detach_pages() {
        Ok((run, _store)) => frames.free_contiguous(run).is_ok(),
        Err(_) => false,
    };
    r.check(
        "frame accounting returns to baseline",
        returned && frames.stats().free == before,
    );
}

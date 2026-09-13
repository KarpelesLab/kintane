//! Kernel heap churn under seeded fault injection.
//!
//! Two threads at the lowest workload level allocate, fill, check and free through the
//! kernel heap and through `KBox`, keeping a few blocks alive across iterations and so
//! across preemptions. Sizes cover every slab class and multi-page blocks, which the heap
//! serves from its buddy allocator. The heap fails a seeded fraction of requests on
//! purpose, and every refusal must reach the workload as an `Err` it counts.
//!
//! # Which sites fail
//!
//! The request as a whole, a new slab block, and frames for the arena. Not the buddy
//! allocator's pages. A refused page block is served from the arena instead, and the
//! arena reclaims only in last-in-first-out order (`kalloc::bump`), so a soak that
//! refused page blocks at random would run the arena out of memory by design and measure
//! that, not whether anything is wrong. The slab-block fallback abandons arena memory the
//! same way, but a slab stops needing new blocks once its classes are warm, so it trips
//! rarely and only early.
//!
//! # The books
//!
//! At a checkpoint both threads have freed everything they held. The heap's bytes in use
//! must then be what they were before the run started, and the number of failures the
//! heap counted since then must equal the refusals the two threads counted, so no
//! failure was reported that nobody saw, and none was seen that the heap does not know
//! it made.

use core::alloc::Layout;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicU64, Ordering};

use kalloc::{AllocContext, Injector, Site};

use super::{PAGE, Parked, Rng, Workload, checkpoint, fail, park_requested, progress};
use crate::kheap::{self, KBox};
use crate::preempt::begin;

/// Blocks each thread keeps alive across iterations.
const KEEP: usize = 8;

/// One request in this many fails, at the sites named in the module comment.
const FAIL_ONE_IN: u64 = 32;

/// The heap's statistics when the run started.
static BASE_IN_USE: AtomicU64 = AtomicU64::new(0);
static BASE_FAILURES: AtomicU64 = AtomicU64::new(0);

/// Refusals each thread saw and handled.
static REFUSED: [AtomicU64; 2] = [const { AtomicU64::new(0) }; 2];

/// Install the injector and take the baseline.
pub fn setup() -> Result<(), &'static str> {
    let stats = kheap::stats().ok_or("no kernel heap")?;
    BASE_IN_USE.store(stats.bytes_in_use as u64, Ordering::Relaxed);
    BASE_FAILURES.store(stats.failures, Ordering::Relaxed);
    let sites = Site::ENTRY.union(Site::SLAB_BLOCK).union(Site::FRAMES);
    let seed = super::Rng::new(0x4845_4150).next();
    if !kheap::set_injector(Injector::random(sites, seed, FAIL_ONE_IN)) {
        return Err("could not install the heap's fault injector");
    }
    Ok(())
}

/// Refusals seen, both threads together.
pub fn refused() -> u64 {
    REFUSED[0].load(Ordering::Relaxed) + REFUSED[1].load(Ordering::Relaxed)
}

/// The books; see the module comment. Called with both threads parked.
pub fn audit() -> Result<(), &'static str> {
    let stats = kheap::stats().ok_or("no kernel heap")?;
    if stats.bytes_in_use as u64 != BASE_IN_USE.load(Ordering::Relaxed) {
        return Err("bytes in use are not back at the baseline with nothing held (a leak)");
    }
    if stats.failures - BASE_FAILURES.load(Ordering::Relaxed) != refused() {
        return Err("the heap's failure count and the refusals workloads handled disagree");
    }
    if stats.slab.double_frees != 0 {
        return Err("the slab refused a double free");
    }
    if kalloc::inject::ENABLED && stats.injected == 0 {
        return Err("fault injection is built in and armed, but has never failed anything");
    }
    Ok(())
}

/// A block a thread holds, with what it wrote into it.
#[derive(Clone, Copy)]
struct Held {
    ptr: NonNull<u8>,
    layout: Layout,
    tag: u8,
}

impl Held {
    fn fill(&self) {
        // SAFETY: a live allocation of `layout.size()` bytes that only the holding thread
        // reaches, and no reference to it exists while this one does.
        let bytes =
            unsafe { core::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.layout.size()) };
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = self.tag.wrapping_add(i as u8);
        }
    }

    fn intact(&self) -> bool {
        // SAFETY: as in `fill`, read-only.
        let bytes = unsafe { core::slice::from_raw_parts(self.ptr.as_ptr(), self.layout.size()) };
        bytes
            .iter()
            .enumerate()
            .all(|(i, b)| *b == self.tag.wrapping_add(i as u8))
    }
}

/// Check and free `held`.
fn release(w: Workload, held: Held) {
    if !held.intact() {
        fail(w, "a block did not keep its contents");
    }
    // SAFETY: allocated by this thread with this layout, and freed once, here.
    if unsafe { kheap::dealloc(held.ptr, held.layout, AllocContext::KERNEL) }.is_err() {
        fail(w, "the heap refused to free a block it handed out");
    }
}

fn size(rng: &mut Rng) -> usize {
    match rng.below(10) {
        // Multi-page: served by the heap's buddy allocator.
        0 => PAGE * (1 + rng.below(4) as usize),
        // Every slab class, and sizes between them.
        _ => 1 + rng.below(1024) as usize,
    }
}

pub extern "C" fn worker(which: usize) -> ! {
    begin();
    let w = if which == 0 {
        Workload::HeapA
    } else {
        Workload::HeapB
    };
    let mut rng = Rng::new(0x100 + which as u64);
    let mut kept: [Option<Held>; KEEP] = [None; KEEP];
    loop {
        if park_requested() {
            for held in kept.iter_mut().filter_map(Option::take) {
                release(w, held);
            }
            checkpoint(w, Parked::Empty);
        }

        let slot = rng.below(KEEP as u64) as usize;
        if let Some(old) = kept[slot].take() {
            release(w, old);
        }
        let Ok(layout) = Layout::from_size_align(size(&mut rng), 8) else {
            fail(w, "a layout the workload chose is invalid");
            continue;
        };
        match kheap::try_alloc(layout, AllocContext::KERNEL) {
            Ok(ptr) => {
                let held = Held {
                    ptr,
                    layout,
                    tag: rng.next() as u8,
                };
                held.fill();
                kept[slot] = Some(held);
            }
            Err(kheap::Error::Alloc(_)) => {
                REFUSED[which].fetch_add(1, Ordering::Relaxed);
            }
            Err(_) => fail(w, "the heap refused for a reason other than memory"),
        }

        let value = rng.next();
        match KBox::try_new([value; 4], AllocContext::KERNEL) {
            Ok(b) => {
                if b.iter().any(|&v| v != value) {
                    fail(w, "a KBox did not hold its value");
                }
            }
            Err((_, kheap::Error::Alloc(_))) => {
                REFUSED[which].fetch_add(1, Ordering::Relaxed);
            }
            Err(_) => fail(w, "KBox refused for a reason other than memory"),
        }
        progress(w);
    }
}

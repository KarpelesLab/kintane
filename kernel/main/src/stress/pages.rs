//! Buddy page churn on a pool of its own.
//!
//! One thread allocates blocks of random order from a buddy allocator over a run of
//! frames taken at boot, fills each through the direct map, and checks and frees them
//! in random order, so blocks split and merge continuously. The heap's own buddy
//! allocator is exercised by the heap workload, but only through the heap; this one is
//! checked directly. At a checkpoint the thread has freed everything, so the allocator
//! must hold every page free and satisfy every invariant `Buddy::check` knows.

use core::cell::SyncUnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use arch::Cpu;
use boot_protocol::{MemoryKind, MemoryRegion};
use hal::{KernAddr, PhysAddr};
use kalloc::{Buddy, buddy};
use mm::DirectMap;
use mm::frame::FrameRange;
use mm::phys::FrameAllocator;
use sync::SpinLock;
use sync::lockdep::LockClass;

use super::{PAGE, Parked, Rng, Workload, after_ms, checkpoint, fail, park_requested, progress};
use crate::DIRECT_MAP_MAX;
use crate::preempt::{begin, sleep_until};

/// Pages in the pool.
const PAGES: usize = 256;
/// Blocks held at once.
const KEEP: usize = 8;
/// The largest order asked for: 8 pages.
const MAX_ORDER: usize = 3;

const STORE_BYTES: usize = PAGES * buddy::STORE_BYTES_PER_PAGE;

/// SAFETY INVARIANT: borrowed once, by the first [`reserve`] (see `RESERVED`), into the
/// buddy allocator that lives in `POOL` from then on.
static STORE: SyncUnsafeCell<[u8; STORE_BYTES]> = SyncUnsafeCell::new([0; STORE_BYTES]);

static CLASS: LockClass = LockClass::new("stress.pages");

struct Pool {
    buddy: Buddy<'static, Cpu>,
    direct: DirectMap,
}

static POOL: SpinLock<Option<Pool>, Cpu> = SpinLock::with_class(None, &CLASS);
static RESERVED: AtomicBool = AtomicBool::new(false);
static REGION: [AtomicU64; 2] = [const { AtomicU64::new(0) }; 2];

/// Take the pool's run from the boot allocator. Returns its size in pages.
pub fn reserve(frames: &mut FrameAllocator<'_, Cpu>, map: &[MemoryRegion]) -> Option<usize> {
    if RESERVED.swap(true, Ordering::Relaxed) {
        return None;
    }
    let run = frames.alloc_contiguous(PAGES).ok()?;
    let start = run.start().start().raw();
    let len = (PAGES * PAGE) as u64;
    // The same direct map the kernel space built, as the kernel heap computes it.
    let usable = || map.iter().filter(|r| r.kind == MemoryKind::Usable as u32);
    let lo = usable().map(|r| r.start).min().unwrap_or(0);
    let hi = usable()
        .map(|r| r.start.saturating_add(r.len))
        .max()
        .unwrap_or(lo);
    let direct = usize::try_from(lo)
        .ok()
        .and_then(|v| {
            DirectMap::new(PhysAddr::new(lo), KernAddr::new(v), (hi - lo).min(DIRECT_MAP_MAX)).ok()
        })
        .filter(|d| {
            d.covers_phys(PhysAddr::new(start)) && d.covers_phys(PhysAddr::new(start + len - 1))
        });
    let Some(direct) = direct else {
        let _ = frames.free_contiguous(run);
        return None;
    };
    // SAFETY: the one borrow of the store; `RESERVED` guarantees this runs once.
    let store = unsafe { &mut *STORE.get() };
    let buddy = Buddy::new(run, store).ok()?;
    *POOL.lock_irqsave() = Some(Pool { buddy, direct });
    REGION[0].store(start, Ordering::Relaxed);
    REGION[1].store(len, Ordering::Relaxed);
    Some(PAGES)
}

/// The pool's physical run, `(start, len)`.
pub fn region() -> (u64, u64) {
    (REGION[0].load(Ordering::Relaxed), REGION[1].load(Ordering::Relaxed))
}

pub fn setup() -> Result<(), &'static str> {
    match POOL.lock_irqsave().as_ref() {
        Some(p) if p.buddy.stats().free_pages == PAGES => Ok(()),
        Some(_) => Err("the page pool is not all free"),
        None => Err("no page pool"),
    }
}

/// Every page free and every invariant intact. Called with the thread parked.
pub fn audit() -> Result<(), &'static str> {
    let pool = POOL.lock_irqsave();
    let Some(p) = pool.as_ref() else {
        return Err("no page pool");
    };
    if p.buddy.check().is_err() {
        return Err("an invariant does not hold");
    }
    let stats = p.buddy.stats();
    if stats.live_blocks != 0 || stats.free_pages != PAGES {
        return Err("pages are missing with nothing held (a leak)");
    }
    Ok(())
}

/// A block the thread holds: where, how many pages, and the byte it was filled from.
#[derive(Clone, Copy)]
struct Held {
    range: FrameRange<Cpu>,
    tag: u8,
}

/// The block's bytes through the direct map.
fn bytes(direct: DirectMap, range: FrameRange<Cpu>) -> Option<&'static mut [u8]> {
    let p = direct.ptr_to_phys(range.start().start()).ok()?;
    // SAFETY: the block was allocated from the pool, whose whole run `reserve` checked
    // the direct map covers, and only the thread that holds it touches it.
    Some(unsafe { core::slice::from_raw_parts_mut(p.as_ptr(), range.count() * PAGE) })
}

fn fill(w: Workload, direct: DirectMap, held: Held) {
    match bytes(direct, held.range) {
        Some(b) => {
            for (i, x) in b.iter_mut().enumerate() {
                *x = held.tag.wrapping_add((i / 7) as u8);
            }
        }
        None => fail(w, "a block is outside the direct map"),
    }
}

fn free(w: Workload, direct: DirectMap, held: Held) {
    let intact = bytes(direct, held.range).is_some_and(|b| {
        b.iter()
            .enumerate()
            .all(|(i, x)| *x == held.tag.wrapping_add((i / 7) as u8))
    });
    if !intact {
        fail(w, "a block did not keep its contents");
    }
    let freed = POOL
        .lock_irqsave()
        .as_mut()
        .is_some_and(|p| p.buddy.free(held.range).is_ok());
    if !freed {
        fail(w, "the buddy allocator refused to free a block it handed out");
    }
}

pub extern "C" fn worker(_: usize) -> ! {
    begin();
    let w = Workload::Pages;
    let mut rng = Rng::new(0x300);
    let mut kept: [Option<Held>; KEEP] = [None; KEEP];
    let Some(direct) = POOL.lock_irqsave().as_ref().map(|p| p.direct) else {
        fail(w, "no page pool");
        loop {
            sleep_until(after_ms(1000));
        }
    };
    loop {
        if park_requested() {
            for held in kept.iter_mut().filter_map(Option::take) {
                free(w, direct, held);
            }
            checkpoint(w, Parked::Empty);
        }
        for _ in 0..KEEP {
            let slot = rng.below(KEEP as u64) as usize;
            if let Some(old) = kept[slot].take() {
                free(w, direct, old);
                continue;
            }
            let order = rng.below(MAX_ORDER as u64 + 1) as usize;
            let got = POOL
                .lock_irqsave()
                .as_mut()
                .map(|p| p.buddy.alloc_order(order));
            match got {
                Some(Ok(range)) => {
                    let held = Held {
                        range,
                        tag: rng.next() as u8,
                    };
                    fill(w, direct, held);
                    kept[slot] = Some(held);
                }
                // At most KEEP blocks of eight pages are held out of PAGES, so the pool
                // never runs out; a refusal is a fragmentation or accounting bug.
                Some(Err(_)) => fail(w, "the buddy allocator refused with pages to spare"),
                None => fail(w, "no page pool"),
            }
        }
        progress(w);
        sleep_until(after_ms(1));
    }
}

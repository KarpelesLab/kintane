//! Demand paging, copy-on-write sharing and huge pages on a kernel `Vm`, for hours.
//!
//! The boot check in `demand` proves each property once. This does the same operations
//! continuously, from a thread that is preempted in the middle of them, against a frame
//! pool of its own. Each cycle reserves two small regions, faults one in by touching it,
//! shares it copy-on-write into the other, writes both sides and checks nothing crossed
//! over, and every fourth cycle also faults in a huge page. Then it releases everything.
//!
//! The `Vm` and its frames sit behind one lock. The page fault hook takes it; the worker
//! takes it to reserve, share and release, and never touches demand memory while
//! holding it, so a fault never finds the lock held by the thread that faulted. On one
//! CPU the lock masks interrupts, so no other thread can hold it either.
//!
//! The thread alternates where it stops for the auditor. Stopped with its regions mapped
//! and shared, `Vm::audit` checks every leaf against the regions and the share counts.
//! Stopped with everything released, the pool must be exactly as full as it started, page
//! tables included.

use core::cell::SyncUnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use arch::Cpu;
use boot_protocol::{MemoryKind, MemoryRegion};
use hal::HasPageTables;
use hal::fault::PageFault;
use hal::paging::{PageFlags, level_size};
use mm::DirectMap;
use mm::paged::AddressSpace;
use mm::phys::{FrameAllocator, bitmap_bytes};
use mm::vm::{Backing, Region, Resolved, ShareSlot, Shares, Vm};
use sync::SpinLock;
use sync::lockdep::LockClass;

use super::{PAGE, Parked, Workload, after_ms, checkpoint, fail, park_requested, progress};
use crate::demand::{self, KernelFrames};
use crate::preempt::{begin, sleep_until};

/// Frames in the pool. A huge page needs a 2 MiB block, which the frame source finds by
/// over-allocating one alignment's worth, so the pool holds room for two.
const FRAMES: usize = 2048;
/// Regions at once: two small and one huge.
const REGIONS: usize = 4;
/// Pages in each small region.
const SMALL: usize = 8;
/// Every cycle of this many faults in a huge page as well.
const HUGE_EVERY: u64 = 4;

const FRAME_STORE_BYTES: usize = FRAMES / 2;

/// SAFETY INVARIANT: borrowed once, by the first [`reserve`] (see `RESERVED`).
static FRAME_STORE: SyncUnsafeCell<[u8; FRAME_STORE_BYTES]> =
    SyncUnsafeCell::new([0; FRAME_STORE_BYTES]);
/// SAFETY INVARIANT: as `FRAME_STORE`. One slot per page that can be shared at once.
static SHARE_STORE: SyncUnsafeCell<[ShareSlot; SMALL]> =
    SyncUnsafeCell::new([ShareSlot::EMPTY; SMALL]);

static CLASS: LockClass = LockClass::new("stress.vm");

struct Pool {
    vm: Vm<'static, Cpu, REGIONS>,
    frames: FrameAllocator<'static, Cpu>,
    direct: DirectMap,
    /// Free frames with nothing mapped.
    full: usize,
    /// The first address of the window the regions live in.
    base: usize,
}

// SAFETY: the address space's tables and the frames are reached through the kernel's
// direct map, which every thread sees at the same addresses, and nothing reaches the pool
// except through the lock around it.
unsafe impl Send for Pool {}

static POOL: SpinLock<Option<Pool>, Cpu> = SpinLock::with_class(None, &CLASS);
static RESERVED: AtomicBool = AtomicBool::new(false);
static REGION: [AtomicU64; 2] = [const { AtomicU64::new(0) }; 2];

static FAULTS: AtomicU64 = AtomicU64::new(0);
static COPIES: AtomicU64 = AtomicU64::new(0);
static HUGE: AtomicU64 = AtomicU64::new(0);
static SPURIOUS_AT: AtomicUsize = AtomicUsize::new(usize::MAX);

pub fn faults() -> u64 {
    FAULTS.load(Ordering::Relaxed)
}

pub fn copies() -> u64 {
    COPIES.load(Ordering::Relaxed)
}

pub fn huge() -> u64 {
    HUGE.load(Ordering::Relaxed)
}

/// Take the pool's frames from the boot allocator and build the `Vm` over the live
/// kernel address space. Returns the pool's size in frames.
pub fn reserve(frames: &mut FrameAllocator<'_, Cpu>, direct: DirectMap) -> Option<usize> {
    if RESERVED.swap(true, Ordering::Relaxed) {
        return None;
    }
    let base = demand::window(direct)?;
    let run = frames.alloc_contiguous(FRAMES).ok()?;
    let start = run.start().start().raw();
    let len = (FRAMES * PAGE) as u64;
    let own_map = [MemoryRegion {
        start,
        len,
        kind: MemoryKind::Usable as u32,
        _reserved: 0,
    }];
    let reachable = direct.covers_phys(hal::PhysAddr::new(start))
        && direct.covers_phys(hal::PhysAddr::new(start + len - 1));
    if !reachable || bitmap_bytes::<Cpu>(&own_map).map_or(true, |n| n > FRAME_STORE_BYTES) {
        let _ = frames.free_contiguous(run);
        return None;
    }
    // SAFETY: the one borrow of each store; `RESERVED` guarantees this runs once.
    let (frame_store, share_store) = unsafe { (&mut *FRAME_STORE.get(), &mut *SHARE_STORE.get()) };
    let pool_frames = FrameAllocator::<Cpu>::new(&own_map, frame_store).ok()?;
    // SAFETY: the root is the kernel space `kernel_space` built through `direct` and
    // installed, so every table in it is reachable through `direct`. The `Vm` edits only
    // leaves inside its own regions, in a window nothing else maps, and it is used only
    // under `POOL`'s lock.
    let space = unsafe { AddressSpace::<Cpu>::from_root(<Cpu as HasPageTables>::root(), direct) };
    let full = pool_frames.stats().free;
    *POOL.lock_irqsave() = Some(Pool {
        vm: Vm::new(space, Shares::new(share_store)),
        frames: pool_frames,
        direct,
        full,
        base,
    });
    REGION[0].store(start, Ordering::Relaxed);
    REGION[1].store(len, Ordering::Relaxed);
    Some(FRAMES)
}

/// The pool's physical run, `(start, len)`.
pub fn region() -> (u64, u64) {
    (REGION[0].load(Ordering::Relaxed), REGION[1].load(Ordering::Relaxed))
}

/// Route page faults to the pool's `Vm`.
pub fn setup() -> Result<(), &'static str> {
    if POOL.lock_irqsave().is_none() {
        return Err("no vm pool");
    }
    arch::fault::set_page_fault_hook(Some(on_page_fault));
    Ok(())
}

fn on_page_fault(fault: PageFault) -> bool {
    let mut pool = POOL.lock_irqsave();
    let Some(p) = pool.as_mut() else {
        return false;
    };
    let mut frames = KernelFrames {
        alloc: &mut p.frames,
        direct: p.direct,
    };
    match p.vm.fault(fault, &mut frames) {
        // Retried once. A second spurious fault at the same address means the flush did
        // not help, and resolving it again would loop with no output.
        Ok(Resolved::Spurious) => SPURIOUS_AT.swap(fault.addr, Ordering::Relaxed) != fault.addr,
        Ok(r) => {
            SPURIOUS_AT.store(usize::MAX, Ordering::Relaxed);
            FAULTS.fetch_add(1, Ordering::Relaxed);
            match r {
                Resolved::Copied => COPIES.fetch_add(1, Ordering::Relaxed),
                Resolved::Zeroed { huge: true } => HUGE.fetch_add(1, Ordering::Relaxed),
                _ => 0,
            };
            true
        }
        Err(_) => false,
    }
}

/// `Vm::audit` always; a full pool when the thread stopped with nothing mapped.
pub fn audit(parked: Parked) -> Result<(), &'static str> {
    let pool = POOL.lock_irqsave();
    let Some(p) = pool.as_ref() else {
        return Err("no vm pool");
    };
    if p.vm.audit().is_err() {
        return Err("Vm::audit found a leaf that disagrees with its region or share count");
    }
    if parked == Parked::Empty {
        if !p.vm.regions().is_empty() {
            return Err("regions remain with the worker holding nothing");
        }
        if p.frames.stats().free != p.full {
            return Err("frames are missing from the pool with nothing mapped (a leak)");
        }
    }
    Ok(())
}

fn peek(addr: usize) -> u8 {
    // SAFETY: only called on addresses inside a region reserved in the live kernel space,
    // whose first touch faults and is resolved to a mapped page before the read completes.
    unsafe { (addr as *const u8).read_volatile() }
}

fn poke(addr: usize, v: u8) {
    // SAFETY: as for `peek`, in a region that permits writing.
    unsafe { (addr as *mut u8).write_volatile(v) }
}

fn small(start: usize) -> Region {
    Region {
        start,
        len: SMALL * PAGE,
        flags: PageFlags::KERNEL_DATA,
        backing: Backing::Anonymous,
        huge: false,
    }
}

/// Run `f` on the pool under its lock. `None` if there is no pool.
fn with<R>(
    f: impl FnOnce(&mut Vm<'static, Cpu, REGIONS>, &mut KernelFrames<'_>) -> R,
) -> Option<R> {
    let mut pool = POOL.lock_irqsave();
    let p = pool.as_mut()?;
    let mut frames = KernelFrames {
        alloc: &mut p.frames,
        direct: p.direct,
    };
    Some(f(&mut p.vm, &mut frames))
}

/// One cycle. Returns where it offered to stop, for alternating.
fn cycle(w: Workload, base: usize, n: u64, stop_holding: bool) -> bool {
    let (a, b) = (base, base + 2 * SMALL * PAGE);
    let hsize = level_size::<Cpu>(1);
    let h = base + 32 * hsize;
    let tag = n as u8;

    if with(|vm, _| vm.reserve(small(a)).and_then(|()| vm.reserve(small(b)))) != Some(Ok(())) {
        fail(w, "reserving the small regions was refused");
        return false;
    }
    for i in 0..SMALL {
        let at = a + i * PAGE;
        if peek(at) != 0 || peek(at + PAGE - 1) != 0 {
            fail(w, "a demand page was not zeroed");
        }
        poke(at, tag.wrapping_add(i as u8));
        poke(at + PAGE - 1, !tag.wrapping_add(i as u8));
    }
    if with(|vm, frames| vm.cow_share(a, b, frames)) != Some(Ok(())) {
        fail(w, "sharing was refused");
    }
    for i in 0..SMALL {
        let at = b + i * PAGE;
        if peek(at) != tag.wrapping_add(i as u8)
            || peek(at + PAGE - 1) != !tag.wrapping_add(i as u8)
        {
            fail(w, "the shared side does not read the source's bytes");
        }
    }
    let (i, j) = ((n as usize) % SMALL, (n as usize + 3) % SMALL);
    poke(a + i * PAGE, 0xA0);
    poke(b + j * PAGE, 0xB0);
    if peek(a + i * PAGE) != 0xA0 || peek(b + j * PAGE) != 0xB0 {
        fail(w, "a write to a shared page did not stick");
    }
    if i != j
        && (peek(b + i * PAGE) != tag.wrapping_add(i as u8)
            || peek(a + j * PAGE) != tag.wrapping_add(j as u8))
    {
        fail(w, "a write to one side of a share showed on the other");
    }

    let stopped = stop_holding && park_requested();
    if stopped {
        checkpoint(w, Parked::Holding);
    }

    if n % HUGE_EVERY == 0 {
        let region = Region {
            start: h,
            len: hsize,
            huge: true,
            ..small(h)
        };
        if with(|vm, _| vm.reserve(region)) != Some(Ok(())) {
            fail(w, "reserving the huge region was refused");
        } else {
            let huges = HUGE.load(Ordering::Relaxed);
            if peek(h + 0x1234) != 0 {
                fail(w, "a huge demand page was not zeroed");
            }
            poke(h + hsize - 1, tag);
            if peek(h + hsize - 1) != tag {
                fail(w, "a huge page did not keep a byte");
            }
            if HUGE.load(Ordering::Relaxed) == huges {
                fail(w, "a huge region was faulted in without a huge leaf");
            }
            if with(|vm, frames| vm.release(h, frames).is_ok()) != Some(true) {
                fail(w, "releasing the huge region was refused");
            }
        }
    }

    let released =
        with(|vm, frames| vm.release(a, frames).is_ok() && vm.release(b, frames).is_ok());
    if released != Some(true) {
        fail(w, "releasing the small regions was refused");
    }
    stopped
}

pub extern "C" fn worker(_: usize) -> ! {
    begin();
    let w = Workload::Vm;
    let base = POOL.lock_irqsave().as_ref().map_or(0, |p| p.base);
    let mut stop_holding = true;
    let mut n = 0u64;
    loop {
        if cycle(w, base, n, stop_holding) {
            stop_holding = false;
        } else if park_requested() {
            checkpoint(w, Parked::Empty);
            stop_holding = true;
        }
        n = n.wrapping_add(1);
        progress(w);
        sleep_until(after_ms(1));
    }
}

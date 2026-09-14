//! The kernel heap that outlives boot, and [`KBox`], the owning pointer into it.
//!
//! # Where its memory comes from
//!
//! A fixed run of frames, taken from the machine's frame allocator once at boot and
//! managed from then on by a second frame allocator that knows only that run. The heap's
//! arena grows from the second allocator, and its buddy allocator sits on part of the
//! run. So everything the heap ever holds is inside one known range, and [`region`]
//! names it. That is what lets the in-kernel suite, which builds its own frame pool from
//! the loader's map, be told to keep out. Before this the boot heap was dropped before
//! the suite ran, and its frames could be reused safely. A heap that lives cannot share
//! frames with a test that writes patterns over them.
//!
//! # Locking
//!
//! One lock, of the kernel's lock family, around the heap and its frame allocator
//! together. Growing the heap takes frames, so the two are always used together and one
//! lock cannot be taken in the wrong order against the other. The family masks
//! interrupts while it holds the lock. On one CPU the timer interrupt therefore never
//! finds the lock held by the thread it interrupted, and an allocation from interrupt
//! context cannot deadlock against one from a thread.
//!
//! # Interrupt context
//!
//! What interrupt context must not do is sleep. [`AllocContext::KERNEL`] says the caller
//! may, so a request that carries `MAY_SLEEP` from inside an interrupt handler is
//! refused with [`Error::MaySleepInInterrupt`]. Nothing sleeps in the allocator yet, but
//! the call site is still wrong, and once reclaim can wait it becomes a deadlock. An
//! allocation from interrupt context never grows the heap either. It is served from
//! memory the heap already holds or refused, so a handler's worst case is bounded.
//! [`irq_enter`] and [`irq_exit`] mark the handler's extent; the kernel's timer hook
//! calls them.
//!
//! # Why not `#[global_allocator]`
//!
//! `GlobalAlloc` reports failure as a null pointer, and the `alloc` crate's everyday API
//! (`Box::new`, `Vec::push`) turns that null into a call to `handle_alloc_error`, which
//! does not return. `docs/architecture.md` requires allocation failure to be a `Result`
//! the caller handles. A global allocator would make the infallible form the easy one
//! and failure a panic. `GlobalAlloc` also has no way to pass an [`AllocContext`], which
//! is the interrupt-context rule above. And `alloc` is not built: kbuild compiles
//! `core` from source and nothing else. [`KBox::try_new`] is fallible and takes a
//! context, and a collection type can be written against [`try_alloc`] the same way.

use core::alloc::Layout;
use core::cell::SyncUnsafeCell;
use core::marker::PhantomData;
use core::ops::{Deref, DerefMut};
use core::ptr::NonNull;
use core::sync::atomic::Ordering;

use arch::Cpu;
use boot_protocol::{MemoryKind, MemoryRegion};
use hal::{EarlyConsole, KernAddr, PhysAddr};
use kalloc::{AllocContext, AllocError, Heap, HeapStats, NoFrames, buddy};
use mm::DirectMap;
use mm::phys::{FrameAllocator, bitmap_bytes};
use sync::LockFamily;
use sync::lockdep::LockClass;

use crate::{AtomicBool, AtomicU32, AtomicU64, Check, DIRECT_MAP_MAX, Locks, write_usize};

/// Frames the heap owns for the life of the kernel.
const PAGES: usize = 512;
/// Of those, frames handed to the buddy allocator for multi-page blocks. The rest feed
/// the arena.
const BUDDY_PAGES: usize = 128;

/// Bitmap store for the heap's own frame allocator. Two bits per frame, rounded up
/// generously; `install` checks the real requirement against it.
const FRAME_STORE_BYTES: usize = 512;
const BUDDY_STORE_BYTES: usize = BUDDY_PAGES * buddy::STORE_BYTES_PER_PAGE;

/// SAFETY INVARIANT: borrowed once, by the first `install` (see `INSTALLING`). The
/// borrow then lives inside `HEAP` for the rest of the kernel's life.
static FRAME_STORE: SyncUnsafeCell<[u8; FRAME_STORE_BYTES]> =
    SyncUnsafeCell::new([0; FRAME_STORE_BYTES]);
/// SAFETY INVARIANT: as `FRAME_STORE`.
static BUDDY_STORE: SyncUnsafeCell<[u8; BUDDY_STORE_BYTES]> =
    SyncUnsafeCell::new([0; BUDDY_STORE_BYTES]);

static HEAP_CLASS: LockClass = LockClass::new("kernel.heap");

struct KernelHeap {
    frames: FrameAllocator<'static, Cpu>,
    heap: Heap<Cpu>,
}

// SAFETY: the heap's raw pointers name memory in the kernel's direct map, which every
// thread and CPU sees at the same addresses, and nothing reaches the heap except
// through the lock around it. Moving it between threads moves ownership of that memory
// and nothing thread-local.
unsafe impl Send for KernelHeap {}

type Lock<T> = <Locks as LockFamily>::Lock<T>;

/// The heap, empty until [`install`] fills it in place.
///
/// Constructed in its static by a `const` initialiser, which is why this names
/// `SpinLock::with_class` rather than `LockFamily::new` (not `const`), and why it is
/// not a `Once` holding a lock. `Heap` is several KiB, most of it the slab's block
/// table. The first version built it in a helper and moved it through an `Option`, a
/// closure and `Once::call_once` into the static. Each move kept another copy on the
/// 16 KiB boot stack, and the in-kernel test image overflowed into the guard page, which
/// reported it. Now nothing larger than a pointer moves: `install` writes the heap into
/// this static under its lock. If `Locks` ever names another family, this line stops
/// compiling, rather than quietly building a second kind of lock.
static HEAP: Lock<Option<KernelHeap>> = Lock::<Option<KernelHeap>>::with_class(None, &HEAP_CLASS);

/// Set once [`install`] has put a heap in `HEAP`. Checked before taking the lock, so a
/// request before then does not take it for nothing.
static READY: AtomicBool = AtomicBool::new(false);

/// Set by the first [`install`], the only one that may borrow the stores.
static INSTALLING: AtomicBool = AtomicBool::new(false);

/// The physical run the heap owns, `[start, start + len)`. Zero until installed.
static REGION_START: AtomicU64 = AtomicU64::new(0);
static REGION_LEN: AtomicU64 = AtomicU64::new(0);

/// Interrupt handlers each CPU is inside. See [`irq_enter`].
///
/// Per CPU: a thread on one CPU is not in interrupt context because another CPU is
/// taking a timer interrupt, and one shared count refused its sleeping allocations as if
/// it were.
static IRQ_DEPTH: [AtomicU32; crate::mp::CPUS] = [const { AtomicU32::new(0) }; crate::mp::CPUS];

/// This CPU's depth counter, read with interrupts masked so the CPU cannot change
/// between reading its index and using the counter.
fn with_depth<R>(f: impl FnOnce(&AtomicU32) -> R) -> R {
    let irq = <Cpu as hal::Arch>::irq_save();
    let cpu = <Cpu as hal::Arch>::cpu_index();
    // A CPU past the table's run queues never runs a thread; the last slot stands in.
    let r = f(&IRQ_DEPTH[cpu.min(crate::mp::CPUS - 1)]);
    // SAFETY: pairs with the `irq_save` above.
    unsafe { <Cpu as hal::Arch>::irq_restore(irq) };
    r
}

/// Why the kernel heap refused.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Error {
    /// The heap is not installed.
    NotReady,
    /// A request that may sleep, from interrupt context.
    MaySleepInInterrupt,
    /// The heap itself refused.
    Alloc(AllocError),
}

/// Take the heap's run from `frames` and install the heap. Runs once; later calls fail.
pub fn install(
    c: &dyn EarlyConsole,
    frames: &mut FrameAllocator<'_, Cpu>,
    map: &[MemoryRegion],
) -> Check {
    c.write_str("\n  kheap      ");
    if INSTALLING.swap(true, Ordering::Relaxed) {
        c.write_str("already installed");
        return Check::Failed;
    }
    let Ok(run) = frames.alloc_contiguous(PAGES) else {
        c.write_str("no run of frames");
        return Check::Failed;
    };
    let start = run.start().start().raw();
    let len = (PAGES * <Cpu as hal::Arch>::PAGE_SIZE) as u64;

    // The heap reaches its memory through the same direct map the kernel space built:
    // lowest to highest usable byte, capped, at the same virtual addresses.
    let usable = || map.iter().filter(|r| r.kind == MemoryKind::Usable as u32);
    let lo = usable().map(|r| r.start).min().unwrap_or(0);
    let hi = usable()
        .map(|r| r.start.saturating_add(r.len))
        .max()
        .unwrap_or(lo);
    let window = usize::try_from(lo).ok().and_then(|v| {
        DirectMap::new(PhysAddr::new(lo), KernAddr::new(v), (hi - lo).min(DIRECT_MAP_MAX)).ok()
    });
    let Some(window) = window.filter(|w| {
        w.covers_phys(PhysAddr::new(start)) && w.covers_phys(PhysAddr::new(start + len - 1))
    }) else {
        let _ = frames.free_contiguous(run);
        c.write_str("run outside the direct map");
        return Check::Failed;
    };

    let own_map = [MemoryRegion {
        start,
        len,
        kind: MemoryKind::Usable as u32,
        _reserved: 0,
    }];
    if bitmap_bytes::<Cpu>(&own_map).map_or(true, |n| n > FRAME_STORE_BYTES) {
        let _ = frames.free_contiguous(run);
        c.write_str("frame bitmap store too small");
        return Check::Failed;
    }

    // SAFETY: the one borrow of each store; `INSTALLING` guarantees this line runs at
    // most once. See the stores' invariants.
    let (frame_store, buddy_store) = unsafe { (&mut *FRAME_STORE.get(), &mut *BUDDY_STORE.get()) };
    if !Locks::with(&HEAP, |slot| build(slot, window, &own_map, frame_store, buddy_store)) {
        // The run is not returned: the heap's frame allocator may already have handed
        // part of it to the buddy allocator, and the stores are spent. This is a boot
        // failure, and the verdict says so.
        c.write_str("could not build the heap over its run");
        return Check::Failed;
    }
    READY.store(true, Ordering::Release);
    REGION_START.store(start, Ordering::Release);
    REGION_LEN.store(len, Ordering::Release);

    write_usize(c, PAGES);
    c.write_str(" pages at ");
    crate::write_hex(c, start);
    c.write_str(", ");
    write_usize(c, BUDDY_PAGES);
    c.write_str(" of them buddy");
    let ok = round_trip();
    c.write_str(if ok { " ok" } else { " FAILED" });
    Check::from_ok(ok)
}

/// Build the heap over its own frames into `slot`. `false` if the run cannot hold one,
/// in which case `slot` is left empty and every request is refused.
fn build(
    slot: &mut Option<KernelHeap>,
    window: DirectMap,
    own_map: &[MemoryRegion],
    frame_store: &'static mut [u8],
    buddy_store: &'static mut [u8],
) -> bool {
    let Ok(frames) = FrameAllocator::<Cpu>::new(own_map, frame_store) else {
        return false;
    };
    // Written straight into the static, then attached to in place. See `HEAP` for why
    // the heap is never built on the stack and moved.
    let k = slot.insert(KernelHeap {
        frames,
        heap: Heap::new(window),
    });
    let attached = match k.frames.alloc_contiguous(BUDDY_PAGES) {
        Ok(run) => k.heap.attach_pages(run, buddy_store).is_ok(),
        Err(_) => false,
    };
    if !attached {
        *slot = None;
    }
    attached
}

/// Allocate, fill, check and free one small and one multi-page block.
fn round_trip() -> bool {
    [48usize, <Cpu as hal::Arch>::PAGE_SIZE * 3]
        .iter()
        .enumerate()
        .all(|(i, &size)| {
            let Ok(layout) = Layout::from_size_align(size, 8) else {
                return false;
            };
            let Ok(p) = try_alloc(layout, AllocContext::KERNEL_ZEROED) else {
                return false;
            };
            let fill = 0x5A ^ i as u8;
            // SAFETY: a live, zeroed allocation of `size` bytes, used only here and freed
            // below.
            let intact = unsafe {
                let bytes = core::slice::from_raw_parts_mut(p.as_ptr(), size);
                let zeroed = bytes.iter().all(|b| *b == 0);
                bytes.fill(fill);
                zeroed && bytes.iter().all(|b| *b == fill)
            };
            // SAFETY: `p` came from `try_alloc` with `layout` and is freed once.
            intact && unsafe { dealloc(p, layout, AllocContext::KERNEL_ZEROED) }.is_ok()
        })
}

/// The physical run the heap owns, as `(start, len)`. `(0, 0)` before [`install`].
pub fn region() -> (u64, u64) {
    (REGION_START.load(Ordering::Acquire), REGION_LEN.load(Ordering::Acquire))
}

/// Mark the start of an interrupt handler that may allocate.
///
/// Paired with [`irq_exit`], and the pair must not span a thread switch: a handler that
/// switches threads calls `irq_exit` before it does, because the thread it resumes is
/// not in interrupt context.
pub fn irq_enter() {
    with_depth(|d| d.fetch_add(1, Ordering::Relaxed));
}

/// Mark the end of what [`irq_enter`] started.
pub fn irq_exit() {
    with_depth(|d| d.fetch_sub(1, Ordering::Relaxed));
}

/// Whether the caller is inside an interrupt handler that called [`irq_enter`], on the
/// CPU it runs on.
pub fn in_interrupt() -> bool {
    with_depth(|d| d.load(Ordering::Relaxed) != 0)
}

/// Allocate from the kernel heap.
///
/// # Errors
/// [`Error::NotReady`] before [`install`], [`Error::MaySleepInInterrupt`] for a request
/// that may sleep made from interrupt context, and the heap's own refusals.
pub fn try_alloc(layout: Layout, ctx: AllocContext) -> Result<NonNull<u8>, Error> {
    let irq = in_interrupt();
    if irq && ctx.may_sleep() {
        return Err(Error::MaySleepInInterrupt);
    }
    with_heap(|k| {
        if irq {
            k.heap.try_alloc_in(layout, ctx, &mut NoFrames)
        } else {
            k.heap.try_alloc_in(layout, ctx, &mut k.frames)
        }
        .map_err(Error::Alloc)
    })
}

/// Run `f` on the installed heap, under its lock.
fn with_heap<R>(f: impl FnOnce(&mut KernelHeap) -> Result<R, Error>) -> Result<R, Error> {
    if !READY.load(Ordering::Acquire) {
        return Err(Error::NotReady);
    }
    Locks::with(&HEAP, |slot| slot.as_mut().map_or(Err(Error::NotReady), f))
}

/// Give a block back to the kernel heap.
///
/// # Errors
/// As [`Heap::dealloc`], and [`Error::NotReady`].
///
/// # Safety
/// `ptr` must have come from [`try_alloc`] with `layout`, and must not have been freed.
pub unsafe fn dealloc(ptr: NonNull<u8>, layout: Layout, ctx: AllocContext) -> Result<(), Error> {
    // SAFETY: forwarded; the caller's contract is `Heap::dealloc`'s.
    with_heap(|k| unsafe { k.heap.dealloc(ptr, layout, ctx) }.map_err(Error::Alloc))
}

/// The heap's accounting, or `None` before [`install`].
pub fn stats() -> Option<HeapStats> {
    with_heap(|k| Ok(k.heap.stats())).ok()
}

/// Replace the heap's fault-injection policy. `false` before [`install`]. A policy only
/// fails anything in a build with `KALLOC_FAULT_INJECT`; see `kalloc::inject`.
#[cfg_attr(
    not(CONFIG_MM_PAGED),
    expect(
        dead_code,
        reason = "used only by the stress run, which needs MM_PAGED"
    )
)]
pub fn set_injector(inject: kalloc::Injector) -> bool {
    with_heap(|k| {
        k.heap.set_injector(inject);
        Ok(())
    })
    .is_ok()
}

/// An owned `T` in the kernel heap.
///
/// The kernel's `Box`: construction is fallible and says what context it is in, and
/// dropping it frees the memory. Zero-sized `T` is refused, as the heap refuses empty
/// requests.
pub struct KBox<T> {
    ptr: NonNull<T>,
    ctx: AllocContext,
    _owns: PhantomData<T>,
}

// SAFETY: a `KBox<T>` owns its `T` exactly as a `T` would, and the heap it frees into
// is reachable from any thread.
unsafe impl<T: Send> Send for KBox<T> {}
// SAFETY: shared access to a `KBox<T>` is shared access to the `T`.
unsafe impl<T: Sync> Sync for KBox<T> {}

impl<T> KBox<T> {
    /// Move `value` into the kernel heap. On failure the value comes back with the
    /// reason, so nothing is lost.
    pub fn try_new(value: T, ctx: AllocContext) -> Result<KBox<T>, (T, Error)> {
        let layout = Layout::new::<T>();
        match try_alloc(layout, ctx) {
            Ok(p) => {
                let ptr = p.cast::<T>();
                // SAFETY: a fresh allocation of `T`'s layout, so it is valid for a write
                // of one `T`, and aligned for it.
                unsafe { ptr.as_ptr().write(value) };
                Ok(KBox {
                    ptr,
                    ctx,
                    _owns: PhantomData,
                })
            }
            Err(e) => Err((value, e)),
        }
    }
}

impl<T> Deref for KBox<T> {
    type Target = T;
    fn deref(&self) -> &T {
        // SAFETY: initialised by `try_new` and owned by this box.
        unsafe { self.ptr.as_ref() }
    }
}

impl<T> DerefMut for KBox<T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: as `deref`, and `&mut self` makes the access unique.
        unsafe { self.ptr.as_mut() }
    }
}

impl<T> Drop for KBox<T> {
    fn drop(&mut self) {
        // SAFETY: the box holds an initialised `T` that nothing else owns, and it is
        // dropped once, here.
        unsafe { self.ptr.as_ptr().drop_in_place() };
        // A refusal here is a heap bug, and there is no caller to report it to. The heap
        // counts it in its statistics, which the checks read.
        // SAFETY: allocated by `try_new` with this layout and not yet freed.
        let _ = unsafe { dealloc(self.ptr.cast(), Layout::new::<T>(), self.ctx) };
    }
}

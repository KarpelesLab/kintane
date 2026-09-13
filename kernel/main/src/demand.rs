//! Demand paging on the live kernel address space, checked at boot.
//!
//! `mm::vm` is tested on the host against a simulated MMU. This runs it against the real
//! one. Regions are reserved in a window of kernel address space nothing maps, the page
//! fault hook is registered, and then the check simply *touches* the memory. Every page
//! that appears does so because the CPU faulted, the architecture's exception path
//! offered the fault to [`on_page_fault`], and the resolver changed the live tables.
//!
//! What it demonstrates, each as an observation rather than a claim:
//!
//! 1. **Frames on touch.** Reserving takes no frames. Each first touch takes exactly one, and a
//!    second touch takes none and raises no fault.
//! 2. **Zeroing.** Before touching, a batch of frames is filled with a pattern and freed, so the
//!    demand pages land on dirty frames. Every byte read must be zero, and the check fails if no
//!    demand page was a dirtied frame, since then zeroing was not observed.
//! 3. **Copy-on-write.** A region with data is shared into a second. Writing one side must fault,
//!    copy, and leave the other side's byte unchanged. The source pages were written just before
//!    the share, so the CPU holds writable translations for them. A share that forgot to invalidate
//!    is caught here: the next write lands in the shared frame without faulting.
//! 4. **A huge page.** One touch in a huge region maps a 2 MiB leaf over one contiguous block.
//! 5. **Teardown.** Releasing everything returns the frame allocator to the count it had before the
//!    check began, page tables included.
//!
//! The regions do not outlive the check. A kernel address space that faults pages in for
//! the life of the machine needs a lock around the `Vm` and a place for it to live, and
//! that arrives with the long-lived kernel heap.

use core::cell::SyncUnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicUsize, Ordering};

use arch::Cpu;
use hal::fault::PageFault;
use hal::paging::{MapError, PageFlags, level_size};
use hal::{Arch, EarlyConsole, HasPageTables, PhysAddr};
use mm::DirectMap;
use mm::frame::Frame;
use mm::paged::{AddressSpace, FrameSource};
use mm::phys::FrameAllocator;
use mm::vm::{Backing, Region, Resolved, ShareSlot, Shares, Vm};

use crate::{Check, Live, write_hex, write_usize};

/// Regions the check uses at once.
const REGIONS: usize = 4;
/// Pages in each small region.
const PAGES: usize = 8;
/// Pages given a pattern before sharing. Every touched page is shared, patterned or not.
const SHARED: usize = 4;
/// Frames dirtied before the first touch.
const DIRTY: usize = 24;

/// SAFETY INVARIANT: borrowed only by the `Vm` in [`CONTEXT`], while [`check`] runs.
/// One slot per page of the shared region, which is exactly what sharing it needs.
static SHARE_STORE: SyncUnsafeCell<[ShareSlot; PAGES]> =
    SyncUnsafeCell::new([ShareSlot::EMPTY; PAGES]);

/// What the fault hook needs besides the frames: the address space and its direct map.
struct Context {
    vm: Vm<'static, Cpu, REGIONS>,
    direct: DirectMap,
}

/// The boot frame allocator, lifetime erased, while [`CONTEXT`] is `Some`. Valid for
/// exactly that long: it is set and cleared inside [`check`], whose caller holds the
/// allocator throughout and does not use it while `check` runs.
static FRAMES: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

/// SAFETY INVARIANT: `Some` only while [`check`] runs, on the one boot CPU with interrupts
/// masked. It is reached from two places: [`edit`], which sets [`EDITING`] for as long as
/// it holds a reference, and [`on_page_fault`], which runs only from a fault taken while
/// `check` touches demand memory. `check` never touches demand memory while editing, and a
/// fault that arrives while [`EDITING`] is set is refused rather than resolved, so the two
/// never hold a reference at the same time.
static CONTEXT: SyncUnsafeCell<Option<Context>> = SyncUnsafeCell::new(None);

/// Set while [`edit`] holds a reference into [`CONTEXT`].
static EDITING: AtomicBool = AtomicBool::new(false);

/// Faults resolved by mapping something, since the hook was registered.
static RESOLVED: AtomicUsize = AtomicUsize::new(0);
/// Of those, copy-on-write copies.
static COPIED: AtomicUsize = AtomicUsize::new(0);
/// Of those, huge leaves.
static HUGE: AtomicUsize = AtomicUsize::new(0);
/// The address of the last spurious fault, or `usize::MAX`.
static SPURIOUS_AT: AtomicUsize = AtomicUsize::new(usize::MAX);
/// Spurious faults, in total.
///
/// The check requires none. A spurious fault means the CPU faulted on a translation the
/// tables had already fixed, and the resolver's full flush then makes the retry succeed.
/// That rescue is right for a running kernel and wrong for a check: it turns every
/// missing invalidation of the forgiving kind into one extra fault and a pass. On PAE
/// that was the missing PDPT reload, which worked, one fault late, on every new
/// top-level entry.
static SPURIOUS: AtomicUsize = AtomicUsize::new(0);

/// The page fault hook: resolve against the check's `Vm`, or decline.
fn on_page_fault(fault: PageFault) -> bool {
    if EDITING.load(Ordering::Relaxed) {
        // A fault while the `Vm` is being edited is a fault inside the resolver's own
        // data. Resolving it would alias the `&mut` the editor holds.
        return false;
    }
    // SAFETY: see the invariant on `CONTEXT`. `EDITING` is clear, so no other reference
    // into it is live, and this function returns before `check` runs again.
    let Some(ctx) = (unsafe { &mut *CONTEXT.get() }).as_mut() else {
        return false;
    };
    // SAFETY: `frames` points at the allocator `check` was given, which outlives the
    // context, and nothing else uses the allocator while a fault is being handled.
    let alloc = unsafe {
        &mut *FRAMES
            .load(Ordering::Relaxed)
            .cast::<FrameAllocator<'static, Cpu>>()
    };
    let mut frames = KernelFrames {
        alloc,
        direct: ctx.direct,
    };
    match ctx.vm.fault(fault, &mut frames) {
        // A spurious fault is retried once. Twice in a row at the same address means the
        // flush did not help, and returning `true` again would loop for ever with no
        // output; reporting it as fatal is the useful answer.
        Ok(Resolved::Spurious) => {
            SPURIOUS.fetch_add(1, Ordering::Relaxed);
            SPURIOUS_AT.swap(fault.addr, Ordering::Relaxed) != fault.addr
        }
        Ok(r) => {
            SPURIOUS_AT.store(usize::MAX, Ordering::Relaxed);
            RESOLVED.fetch_add(1, Ordering::Relaxed);
            match r {
                Resolved::Copied => COPIED.fetch_add(1, Ordering::Relaxed),
                Resolved::Zeroed { huge: true } => HUGE.fetch_add(1, Ordering::Relaxed),
                _ => 0,
            };
            true
        }
        Err(_) => false,
    }
}

/// Run `f` with the `Vm` and a frame source, with faults refused for the duration.
fn edit<R>(
    f: impl FnOnce(&mut Vm<'static, Cpu, REGIONS>, &mut KernelFrames<'_>) -> R,
) -> Option<R> {
    EDITING.store(true, Ordering::Relaxed);
    // SAFETY: see the invariant on `CONTEXT`; `EDITING` is set until this returns.
    let result = (unsafe { &mut *CONTEXT.get() }).as_mut().map(|ctx| {
        // SAFETY: as in `on_page_fault`.
        let alloc = unsafe {
            &mut *FRAMES
                .load(Ordering::Relaxed)
                .cast::<FrameAllocator<'static, Cpu>>()
        };
        let mut frames = KernelFrames {
            alloc,
            direct: ctx.direct,
        };
        f(&mut ctx.vm, &mut frames)
    });
    EDITING.store(false, Ordering::Relaxed);
    result
}

/// Free frames in the allocator right now.
fn free_frames() -> usize {
    edit(|_, frames| frames.alloc.stats().free).unwrap_or(0)
}

/// Frames for the `Vm`, from the boot frame allocator.
struct KernelFrames<'a> {
    alloc: &'a mut FrameAllocator<'static, Cpu>,
    direct: DirectMap,
}

impl KernelFrames<'_> {
    /// Whether the direct map covers `frames` whole frames from `start`, the condition
    /// for a frame to be zeroed or copied at all.
    fn reachable(&self, start: PhysAddr, frames: usize) -> bool {
        let last = (frames * Cpu::PAGE_SIZE - 1) as u64;
        self.direct.covers_phys(start)
            && start
                .checked_add(last)
                .is_ok_and(|l| self.direct.covers_phys(l))
    }

    fn give_back(&mut self, start: u64, frames: usize) {
        for i in 0..frames {
            if let Ok(f) =
                Frame::<Cpu>::from_start(PhysAddr::new(start + (i * Cpu::PAGE_SIZE) as u64))
            {
                let _ = self.alloc.free_frame(f);
            }
        }
    }
}

impl FrameSource for KernelFrames<'_> {
    fn alloc_zeroed(&mut self) -> Result<PhysAddr, MapError> {
        let frame = self.alloc()?;
        let Ok(p) = self.direct.ptr_to_phys(frame) else {
            self.free(frame);
            return Err(MapError::BadPhysAddr);
        };
        // SAFETY: just allocated, so nothing else owns it, and `alloc` checked the direct
        // map covers the whole frame.
        unsafe { core::ptr::write_bytes(p.as_ptr(), 0, Cpu::PAGE_SIZE) };
        Ok(frame)
    }

    /// Whatever the frame's last owner left in it. `mm::vm` zeroes demand pages itself.
    fn alloc(&mut self) -> Result<PhysAddr, MapError> {
        let frame = self
            .alloc
            .alloc_frame()
            .map_err(|_| MapError::OutOfFrames)?;
        if !self.reachable(frame.start(), 1) {
            let _ = self.alloc.free_frame(frame);
            return Err(MapError::BadPhysAddr);
        }
        Ok(frame.start())
    }

    /// Over-allocates by one alignment's worth and returns the slack at both ends. The
    /// frame allocator offers contiguous runs but no alignment, and a huge leaf needs
    /// both.
    fn alloc_block(&mut self, frames: usize, align: usize) -> Result<PhysAddr, MapError> {
        let pad = align / Cpu::PAGE_SIZE - 1;
        let run = self
            .alloc
            .alloc_contiguous(frames + pad)
            .map_err(|_| MapError::OutOfFrames)?;
        let start = run.start().start().raw();
        let aligned = start.div_ceil(align as u64) * align as u64;
        let head = ((aligned - start) / Cpu::PAGE_SIZE as u64) as usize;
        self.give_back(start, head);
        self.give_back(aligned + (frames * Cpu::PAGE_SIZE) as u64, pad - head);
        if !self.reachable(PhysAddr::new(aligned), frames) {
            self.give_back(aligned, frames);
            return Err(MapError::BadPhysAddr);
        }
        Ok(PhysAddr::new(aligned))
    }

    fn free(&mut self, frame: PhysAddr) {
        if let Ok(f) = Frame::<Cpu>::from_start(frame) {
            let _ = self.alloc.free_frame(f);
        }
    }
}

/// Read one byte of kernel memory.
fn peek(addr: usize) -> u8 {
    // SAFETY: only called on addresses inside a region reserved in the live space, whose
    // first touch faults and is resolved to a mapped page before the read completes.
    unsafe { (addr as *const u8).read_volatile() }
}

/// Write one byte of kernel memory.
fn poke(addr: usize, v: u8) {
    // SAFETY: as for `peek`, in a region that permits writing.
    unsafe { (addr as *mut u8).write_volatile(v) }
}

/// The first 1 GiB boundary above everything the kernel space maps: the direct map, the
/// image and every device window. Nothing is mapped there, which `reserve` confirms.
fn window(direct: DirectMap) -> Option<usize> {
    let (_, img_end) = arch::image_range();
    let mut top = direct.virt_base().raw() as u64 + direct.len();
    top = top.max(img_end);
    for w in platform::device_windows().unwrap_or(&[]) {
        top = top.max(w.phys + w.len);
    }
    const GIB: u64 = 1 << 30;
    usize::try_from(top.div_ceil(GIB) * GIB).ok()
}

/// Run the check. `frames` is the boot frame allocator; `live` is what `kernel_space`
/// installed.
pub fn check(c: &dyn EarlyConsole, frames: &mut FrameAllocator<'static, Cpu>, live: Live) -> Check {
    c.write_str("\n  demand     ");
    let Some(direct) = live.direct else {
        c.write_str("skipped: no kernel address space is live");
        return Check::Skipped;
    };
    let Some(base) = window(direct) else {
        c.write_str("no free window below the top of the address space");
        return Check::Failed;
    };
    let before = frames.stats().free;

    // SAFETY: the root is the table `kernel_space` built through `direct` and installed,
    // so every table in it is reachable through `direct`. Nothing else edits it while the
    // check runs: the enforcement probes are finished, and nothing else is running.
    let space = unsafe { AddressSpace::<Cpu>::from_root(<Cpu as HasPageTables>::root(), direct) };
    // SAFETY: the only use of SHARE_STORE; see its invariant.
    let shares = Shares::new(unsafe { &mut *SHARE_STORE.get() });
    FRAMES.store((frames as *mut FrameAllocator<'static, Cpu>).cast(), Ordering::Relaxed);
    // SAFETY: nothing else reaches CONTEXT yet: the hook is registered below.
    unsafe {
        *CONTEXT.get() = Some(Context {
            vm: Vm::new(space, shares),
            direct,
        });
    }
    arch::fault::set_page_fault_hook(Some(on_page_fault));

    c.write_str("window ");
    write_hex(c, base as u64);
    let ok = demonstrate(c, base, before);

    arch::fault::set_page_fault_hook(None);
    // SAFETY: the hook is gone, so nothing else reaches CONTEXT.
    unsafe { *CONTEXT.get() = None };
    FRAMES.store(core::ptr::null_mut(), Ordering::Relaxed);
    c.write_str(if ok { " ok" } else { " FAILED" });
    Check::from_ok(ok)
}

fn demonstrate(c: &dyn EarlyConsole, base: usize, before: usize) -> bool {
    let page = Cpu::PAGE_SIZE;
    let huge = level_size::<Cpu>(1);
    let small = |start| Region {
        start,
        len: PAGES * page,
        flags: PageFlags::KERNEL_DATA,
        backing: Backing::Anonymous,
        huge: false,
    };
    let (a, b, h) = (base, base + 64 * huge, base + 128 * huge);
    let reserved = edit(|vm, _| {
        vm.reserve(small(a))
            .and_then(|()| vm.reserve(small(b)))
            .and_then(|()| {
                vm.reserve(Region {
                    start: h,
                    len: huge,
                    huge: true,
                    ..small(h)
                })
            })
    });
    if reserved != Some(Ok(())) {
        c.write_str(": window refused (already mapped?)");
        return false;
    }
    let ok = frames_zeroing_cow_huge(c, a, b, h, before);
    let released = edit(|vm, frames| {
        [a, b, h].iter().all(|r| vm.release(*r, frames).is_ok()) && vm.regions().is_empty()
    });
    let after = free_frames();
    c.write_str(", ");
    write_usize(c, before.saturating_sub(after));
    c.write_str(" frames left");
    ok && released == Some(true) && after == before
}

fn frames_zeroing_cow_huge(
    c: &dyn EarlyConsole,
    a: usize,
    b: usize,
    h: usize,
    before: usize,
) -> bool {
    let page = Cpu::PAGE_SIZE;

    if free_frames() != before {
        c.write_str(": reserving took frames");
        return false;
    }

    // Dirty a batch of frames and free them, so the lowest-first frame allocator hands
    // them straight back to the demand pages below.
    let mut dirty = [0u64; DIRTY];
    let dirtied = edit(|_, frames| {
        let mut n = 0;
        for slot in dirty.iter_mut() {
            let Ok(f) = frames.alloc() else { break };
            if let Ok(p) = frames.direct.ptr_to_phys(f) {
                // SAFETY: just allocated and reachable through the direct map.
                unsafe { core::ptr::write_bytes(p.as_ptr(), 0xA5, page) };
            }
            *slot = f.raw();
            n += 1;
        }
        for f in &dirty[..n] {
            frames.free(PhysAddr::new(*f));
        }
        n
    })
    .unwrap_or(0);

    // 1 and 2: frames on touch, zeroed.
    let mut zeroed = true;
    let mut on_touch = true;
    let mut recycled = 0usize;
    for i in 0..PAGES {
        let resolved = RESOLVED.load(Ordering::Relaxed);
        let free = free_frames();
        let addr = a + i * page;
        zeroed &= peek(addr) == 0 && peek(addr + page / 2) == 0 && peek(addr + page - 1) == 0;
        let faults = RESOLVED.load(Ordering::Relaxed) - resolved;
        // The first touch may also build the tables above the page; after that, one frame.
        let taken = free - free_frames();
        on_touch &= faults == 1 && (i == 0 || taken == 1);
        let again = RESOLVED.load(Ordering::Relaxed);
        let _ = peek(addr + 1);
        on_touch &= RESOLVED.load(Ordering::Relaxed) == again;
        let frame = edit(|vm, _| vm.space().translate(addr).map(|t| t.0.raw()))
            .flatten()
            .unwrap_or(0);
        recycled += usize::from(dirty[..dirtied].contains(&frame));
    }
    c.write_str(", ");
    write_usize(c, PAGES);
    c.write_str(" pages on touch");
    if !on_touch {
        c.write_str(" (FRAME OR FAULT COUNT WRONG)");
    }
    c.write_str(", ");
    write_usize(c, recycled);
    c.write_str(" on dirty frames");
    if !zeroed {
        c.write_str(" NOT ZEROED");
    } else if recycled == 0 {
        c.write_str(" (zeroing not observed)");
    }

    // 3: copy-on-write. Writing first leaves writable translations in the TLB.
    for i in 0..SHARED {
        poke(a + i * page, 0x30 + i as u8);
    }
    let shared = edit(|vm, frames| vm.cow_share(a, b, frames)) == Some(Ok(()));
    let copies = COPIED.load(Ordering::Relaxed);
    let mut cow = shared;
    cow &= (0..SHARED).all(|i| peek(b + i * page) == 0x30 + i as u8);
    poke(a + page, 0xC1);
    cow &= peek(a + page) == 0xC1 && peek(b + page) == 0x31;
    poke(b + 2 * page, 0xB2);
    cow &= peek(b + 2 * page) == 0xB2 && peek(a + 2 * page) == 0x32;
    let copied = COPIED.load(Ordering::Relaxed) - copies;
    let audit = edit(|vm, _| vm.audit());
    let audited = matches!(audit, Some(Ok(x)) if x.shared == PAGES - 2);
    c.write_str(", cow ");
    write_usize(c, copied);
    c.write_str(" copies");
    if !shared {
        c.write_str(" (SHARE REFUSED)");
    } else if !cow {
        c.write_str(" (A WRITE CROSSED OVER)");
    } else if !audited {
        c.write_str(" (AUDIT FAILED)");
    }
    cow &= copied == 2 && audited;

    // 4: a huge page.
    let huge_size = level_size::<Cpu>(1);
    let huges = HUGE.load(Ordering::Relaxed);
    let mut huge = peek(h + 0x1234) == 0;
    poke(h + huge_size - 1, 0x77);
    huge &= peek(h + huge_size - 1) == 0x77 && HUGE.load(Ordering::Relaxed) - huges == 1;
    let contiguous = edit(|vm, _| {
        let at = |off| vm.space().translate(h + off).map(|t| t.0.raw());
        matches!((at(0), at(3 * page + 5)), (Some(x), Some(y)) if y - x == (3 * page + 5) as u64)
    });
    huge &= contiguous == Some(true);
    c.write_str(if huge {
        ", 2 MiB leaf"
    } else {
        ", NO HUGE LEAF"
    });

    let spurious = SPURIOUS.load(Ordering::Relaxed);
    if spurious != 0 {
        c.write_str(", ");
        write_usize(c, spurious);
        c.write_str(" SPURIOUS FAULTS");
    }

    zeroed && recycled > 0 && on_touch && cow && huge && spurious == 0
}

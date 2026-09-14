//! TLB shootdown on a multiprocessor, and the boot check that it happens.
//!
//! The port invalidates the calling CPU's cache in `flush_tlb` and then calls
//! [`shoot`], which extends the invalidation to every other online CPU before the
//! caller relies on it: before a freed frame is reused, before a downgraded page is
//! trusted to be read-only. `mm::tlb::Shootdown` keeps the books. This module sends the
//! IPIs, serialises the requests, waits for the answers, and checks them.
//!
//! # Waiting without deadlock
//!
//! The initiator waits with interrupts masked, because it can be a page fault handler or
//! code holding a lock taken with interrupts masked. Two things keep that from hanging:
//!
//! * **Initiators are serialised by [`SERIAL`], taken with `try_lock` in a loop that answers any
//!   request addressed to the waiting CPU.** Two CPUs starting a shootdown at once therefore cannot
//!   each wait for the other's answer.
//! * **No lock held across a shootdown may be waited for with interrupts masked, unless the wait
//!   answers requests itself.** A CPU spinning masked for a lock the initiator holds can never take
//!   the IPI, so a lock whose holder may shoot down must be waited for with a spin that calls
//!   [`service_here`] (`SpinLock::lock_irqsave_with`, or the process locks' own loop). [`SERIAL`]
//!   is waited for that way here, and so are each process's lock and the frame lock in `userproc`.
//!   The stress run's kernel `Vm` lock is taken with a plain masked spin, and is safe only because
//!   one thread and its own page faults use that `Vm` and the audit takes it once that thread has
//!   parked. That rule is written in `docs/memory-model.md`.
//!
//! A wait that goes on far longer than a TCG-emulated IPI should take is counted as a
//! stall and continues. It does not give up: a shootdown that returned without every
//! answer would be the silent corruption it exists to prevent, and a hang is at least
//! visible to the stress run's watchdog.
//!
//! # The check
//!
//! With the secondaries up and the scheduler not yet running, on the boot CPU:
//!
//! 1. Map a page at an address nothing else uses to frame F1, holding `0xA1`.
//! 2. Have every secondary read it through an IPI, so each caches the translation.
//! 3. Unmap it, then reuse F1 for something else by filling it with `0xC3`. Map a second frame F2,
//!    holding `0xB2`, at the same address.
//! 4. Have every secondary read the address again. `0xB2` is right. `0xC3` is a stale translation
//!    read through a frame that belongs to someone else now.
//! 5. Every shootdown during the check must have been answered by exactly the online CPUs other
//!    than the one that asked.
//!
//! Step 4 is observable under QEMU only because a port's local flush is local: TCG keeps
//! a software TLB per CPU and empties it only for the CPU the guest's invalidate ran on.
//! Step 5 does not depend on the emulator at all.

use core::alloc::Layout;
use core::sync::atomic::{AtomicUsize, Ordering};

use arch::Cpu;
use hal::paging::{HasPageTables, MapError, PageFlags};
use hal::{Arch, EarlyConsole, HasIpi, Ipi, KernAddr, PhysAddr};
use kalloc::AllocContext;
use mm::DirectMap;
use mm::paged::{AddressSpace, FrameSource};
use mm::tlb::{Mask, Shootdown, bit};
use sync::SpinLock;
use sync::lockdep::LockClass;

use crate::{AtomicU64, Check, Live, kheap, mp, write_usize};

static STATE: Shootdown = Shootdown::new();

static SERIAL_CLASS: LockClass = LockClass::new("tlb.shootdown");

/// Held by the initiator for the length of one request.
static SERIAL: SpinLock<(), Cpu> = SpinLock::with_class((), &SERIAL_CLASS);

/// Requests whose answers were not exactly the online CPUs other than the initiator.
static MISMATCHES: AtomicUsize = AtomicUsize::new(0);

/// Waits that took far longer than an IPI should.
static STALLS: AtomicUsize = AtomicUsize::new(0);

/// The longest any request waited for its answers, and the total over every request, in
/// nanoseconds of the kernel's clock: under TCG that is mostly what emulated IPIs cost.
static WORST_NS: AtomicU64 = AtomicU64::new(0);
static TOTAL_NS: AtomicU64 = AtomicU64::new(0);

/// Spins of the wait loop before a wait counts as stalled: seconds under TCG.
const STALL_SPINS: usize = 1 << 26;

/// Start extending every local invalidation to the other CPUs. Idempotent.
pub fn install() {
    Cpu::set_tlb_flush_handler(Some(on_ipi));
    Cpu::set_tlb_shootdown(Some(shoot));
}

/// Shootdowns requested, flushes answered, mismatches found, and stalls, since boot.
pub fn stats() -> (usize, usize, usize) {
    (
        STATE.requests(),
        STATE.flushes(),
        MISMATCHES.load(Ordering::Relaxed) + STALLS.load(Ordering::Relaxed),
    )
}

/// The mean and the worst wait for a request's answers since boot, in microseconds.
pub fn latency_us() -> (u64, u64) {
    let total = TOTAL_NS.load(Ordering::Relaxed);
    let mean = total.checked_div(STATE.requests() as u64).unwrap_or(0);
    (mean / 1000, WORST_NS.load(Ordering::Relaxed) / 1000)
}

/// Every online CPU but `me`.
fn others(me: usize) -> Mask {
    let mut mask = 0;
    for cpu in 0..mp::CPUS {
        if cpu != me && Cpu::cpu_online(cpu) {
            mask |= bit(cpu).unwrap_or(0);
        }
    }
    mask
}

/// This CPU's half of the protocol: answer the request if it is addressed here.
fn service(me: usize) {
    STATE.service(me, |addr| {
        // SAFETY: invalidating cached translations has no effect on memory; the initiator
        // wrote the tables before it published the request.
        unsafe { Cpu::flush_tlb_local(addr) };
    });
}

/// The [`Ipi::TlbFlush`] handler.
fn on_ipi() {
    service(Cpu::cpu_index());
}

/// Answer any request addressed to this CPU, from a thread rather than the IPI handler.
///
/// For a CPU spinning with interrupts masked on a lock another CPU holds: if that CPU is
/// waiting for this one's answer to a shootdown, the spin must answer it, or the two wait
/// for each other. `shoot`'s own wait for the serial lock does exactly this.
#[cfg_attr(
    not(CONFIG_USERSPACE),
    expect(
        dead_code,
        reason = "used only by the process locks, which need USERSPACE"
    )
)]
pub fn service_here() {
    service(Cpu::cpu_index());
}

/// Extend an invalidation the caller already made locally to every other online CPU,
/// and return once each has made it. The port's `flush_tlb` calls this.
fn shoot(addr: Option<usize>) {
    let irq = Cpu::irq_save();
    let me = Cpu::cpu_index();
    let targets = others(me);
    if targets == 0 {
        // SAFETY: pairs with the `irq_save` above.
        unsafe { Cpu::irq_restore(irq) };
        return;
    }

    let serial = loop {
        if let Some(guard) = SERIAL.try_lock() {
            break guard;
        }
        // Another CPU is initiating, and its request may be waiting for this one.
        service(me);
        core::hint::spin_loop();
    };

    if !STATE.publish(addr, targets) {
        // Unreachable while `SERIAL` serialises requests: the previous one finished.
        MISMATCHES.fetch_add(1, Ordering::Relaxed);
    }
    let asked = crate::timekeeping::now();
    for cpu in 0..mp::CPUS {
        if targets & bit(cpu).unwrap_or(0) != 0 {
            Cpu::send_ipi(cpu, Ipi::TlbFlush);
        }
    }
    let mut spins = 0usize;
    while STATE.outstanding() != 0 {
        spins += 1;
        if spins == STALL_SPINS {
            STALLS.fetch_add(1, Ordering::Relaxed);
        }
        core::hint::spin_loop();
    }
    let waited = crate::timekeeping::now()
        .saturating_duration_since(asked)
        .as_nanos();
    TOTAL_NS.fetch_add(waited, Ordering::Relaxed);
    WORST_NS.fetch_max(waited, Ordering::Relaxed);
    // The books, against the online set computed again rather than the mask sent: a
    // targeting mistake above would otherwise agree with itself.
    let expected = others(me);
    if STATE.finish().is_err() || expected != targets {
        MISMATCHES.fetch_add(1, Ordering::Relaxed);
    }
    drop(serial);
    // SAFETY: pairs with the `irq_save` above.
    unsafe { Cpu::irq_restore(irq) };
}

/// Page-table frames for the check, from the kernel heap.
struct HeapFrames {
    direct: DirectMap,
}

const PAGE: Layout = match Layout::from_size_align(Cpu::PAGE_SIZE, Cpu::PAGE_SIZE) {
    Ok(l) => l,
    Err(_) => panic!("the page size is a power of two"),
};

impl HeapFrames {
    /// A heap page, as a physical frame, with every byte `fill`.
    fn page(&self, fill: u8) -> Result<PhysAddr, MapError> {
        let ptr =
            kheap::try_alloc(PAGE, AllocContext::KERNEL).map_err(|_| MapError::OutOfFrames)?;
        // SAFETY: just allocated, page-sized, owned here.
        unsafe { core::ptr::write_bytes(ptr.as_ptr(), fill, Cpu::PAGE_SIZE) };
        match self.direct.to_phys(KernAddr::new(ptr.as_ptr() as usize)) {
            Ok(p) => Ok(p),
            Err(_) => {
                // SAFETY: allocated above with `PAGE`, returned once.
                let _ = unsafe { kheap::dealloc(ptr, PAGE, AllocContext::KERNEL) };
                Err(MapError::BadPhysAddr)
            }
        }
    }

    fn fill(&self, frame: PhysAddr, value: u8) {
        if let Ok(p) = self.direct.ptr_to_phys(frame) {
            // SAFETY: a heap page this check allocated and still owns.
            unsafe { core::ptr::write_bytes(p.as_ptr(), value, Cpu::PAGE_SIZE) };
        }
    }
}

impl FrameSource for HeapFrames {
    fn alloc_zeroed(&mut self) -> Result<PhysAddr, MapError> {
        self.page(0)
    }

    fn free(&mut self, frame: PhysAddr) {
        if let Ok(p) = self.direct.ptr_to_phys(frame) {
            // SAFETY: every frame this source hands out is a `PAGE` heap allocation.
            let _ = unsafe { kheap::dealloc(p, PAGE, AllocContext::KERNEL) };
        }
    }
}

/// Runs on a secondary: the byte at `va`.
fn read(va: u64) -> u64 {
    // SAFETY: the check calls this only while `va` is mapped readable in the kernel space
    // every CPU runs on.
    u64::from(unsafe { (va as usize as *const u8).read_volatile() })
}

/// How far into the free window the check's page sits: clear of what the stress run's
/// `Vm` uses at the window's start.
const OFFSET: usize = 768 * 1024 * 1024;

/// Run the check. See the module docs.
pub fn check(c: &dyn EarlyConsole, live: Live) -> Check {
    let secondaries = others(0);
    if secondaries == 0 {
        c.write_str("skipped: no secondary CPU is online");
        return Check::Skipped;
    }
    let Some(direct) = live.direct else {
        c.write_str("skipped: no kernel address space is live");
        return Check::Skipped;
    };
    let Some(va) = crate::demand::window(direct).and_then(|w| w.checked_add(OFFSET)) else {
        c.write_str("no free window");
        return Check::Failed;
    };
    install();
    let (requests, _, bad) = stats();

    let mut frames = HeapFrames { direct };
    // SAFETY: the root is the live kernel space, whose tables `direct` reaches. The check
    // edits only the leaf at `va`, in a window nothing maps, and prunes what it added.
    let mut space =
        unsafe { AddressSpace::<Cpu>::from_root(<Cpu as HasPageTables>::root(), direct) };

    let (Ok(f1), Ok(f2)) = (frames.page(0xA1), frames.page(0xB2)) else {
        c.write_str("no heap pages");
        return Check::Failed;
    };
    let mapped = space.map(va, f1, Cpu::PAGE_SIZE, PageFlags::KERNEL_DATA, &mut frames);
    if mapped.is_err() {
        frames.free(f1);
        frames.free(f2);
        c.write_str("could not map the page");
        return Check::Failed;
    }
    let cpus = |mask: Mask| (0..mp::CPUS).filter(move |&cpu| mask & bit(cpu).unwrap_or(0) != 0);

    let mut cached = 0;
    for cpu in cpus(secondaries) {
        cached += usize::from(Cpu::call_on(cpu, read, va as u64) == Some(0xA1));
    }

    // Unmap (a shootdown), reuse F1, map F2 where F1 was.
    let unmapped = space.unmap(va, Cpu::PAGE_SIZE, &mut frames).is_ok();
    frames.fill(f1, 0xC3);
    let remapped = unmapped
        && space
            .map(va, f2, Cpu::PAGE_SIZE, PageFlags::KERNEL_DATA, &mut frames)
            .is_ok();

    let (mut fresh, mut stale, mut lost) = (0, 0, 0);
    if remapped {
        for cpu in cpus(secondaries) {
            match Cpu::call_on(cpu, read, va as u64) {
                Some(0xB2) => fresh += 1,
                Some(0xC3) => stale += 1,
                _ => lost += 1,
            }
        }
        let _ = space.unmap(va, Cpu::PAGE_SIZE, &mut frames);
    }
    frames.free(f1);
    frames.free(f2);

    let (requests_after, _, bad_after) = stats();
    let shot = requests_after - requests;
    let n = secondaries.count_ones() as usize;

    write_usize(c, n);
    c.write_str(" secondaries cached it (");
    write_usize(c, cached);
    c.write_str("); after the unmap and reuse, ");
    write_usize(c, fresh);
    c.write_str(" read the new frame");
    if stale != 0 {
        c.write_str(", ");
        write_usize(c, stale);
        c.write_str(" READ THE REUSED FRAME THROUGH A STALE TRANSLATION");
    }
    if lost != 0 || !remapped {
        c.write_str(", ");
        write_usize(c, lost);
        c.write_str(" DID NOT ANSWER OR THE REMAP FAILED");
    }
    c.write_str("; ");
    write_usize(c, shot);
    c.write_str(" shootdowns");
    if bad_after != bad {
        c.write_str(", ");
        write_usize(c, bad_after - bad);
        c.write_str(" ANSWERED BY THE WRONG CPUS OR STALLED");
    }
    let ok = cached == n && fresh == n && stale == 0 && lost == 0 && shot >= 2 && bad_after == bad;
    c.write_str(if ok { " ok" } else { " FAILED" });
    Check::from_ok(ok)
}

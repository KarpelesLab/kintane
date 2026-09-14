//! Driver isolation: the same driver body, in the kernel and in a domain.
//!
//! Phase 5's promise is that a driver's source does not change between running in the
//! kernel and running confined. This check is that promise, executed: `virtio_probe`'s
//! `identify` — one function, compiled once per side from one crate — reads the same
//! physical register window twice in a boot.
//!
//! * **In the kernel**, over the window the kernel address space maps, at the privilege every
//!   driver has today.
//! * **In a domain**: an unprivileged process whose address space contains its program, its stack,
//!   a page it shares with the kernel, and that one device window. Nothing else. It runs the driver
//!   body in ring 3 / EL0 and writes what it read to the shared page.
//!
//! Both reports must agree, register for register. The registers are a device's answer —
//! magic, version, device and vendor identifiers the kernel did not tell the domain — so a
//! domain cannot agree by inventing values. They do not say *which* window was read: every
//! unoccupied `virtio,mmio` slot answers the same four values, and the first falsification
//! of this check granted the neighbouring empty slot and passed. So a domain that succeeded
//! also has its grant audited: its window's address must translate, in its own page tables,
//! to exactly the physical window the platform recorded.
//!
//! # What the boundary is made of
//!
//! The window is *mapped into the domain*, so a register access inside it is the same load
//! the kernel executes, not a call into the kernel. That is the design's central bet and it
//! is what `docs/isolation.md` measures: isolation is free per access and costs at the
//! edges, where the grant is established and where the domain reports.
//!
//! The MMU grants whole pages and a device window may be smaller than one: the slot here is
//! 0x200 bytes. So the domain is given the page that holds the window, and the driver's own
//! window is bounded to the device's length by the proxy. What stops a driver reaching the
//! rest of *that* page is the proxy; what stops it reaching anything beyond the page is the
//! MMU, and the MMU is what [`MODE_ROGUE`] tests, by reading the page after the grant.
//!
//! # What this does not show
//!
//! The subject device does no DMA, so nothing here demonstrates confining a device that
//! writes memory on a driver's behalf. Without an IOMMU there is nothing to demonstrate:
//! a domain granted a DMA-capable device can program it to read or write any physical
//! address, isolation or not. `docs/isolation.md` says so plainly, and that is Phase 5's
//! IOMMU work rather than this prototype's.

use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use arch::Cpu;
use hal::{Arch, EarlyConsole, HasUserMode, KernAddr, PhysAddr};
use hwproxy::{Direct, NO_DMA, NoIrq, Parts};
use mm::paged::FrameSource;
use mm::vm::{Backing, Region};
use sched::ThreadId;
use time::Duration;
use virtio_probe::{MEASURE_READS, REPORT_BYTES, Report};

use crate::preempt::{self, sleep_until};
use crate::{Check, timekeeping, userproc, write_usize};

/// Guarded stack slots this check claims, for `preempt`'s build-time count. One, reused by
/// every domain it runs, because a stack slot is never given back.
pub const STACKS: usize = 1;

/// The process slot the domain runs in. `userproc::MAX_PROCS` is four and the process check
/// uses three; this is the fourth, and it runs after that check has torn its own down.
const SLOT: usize = 3;

/// The domain program's modes; mirrors `user/hwdomain`.
const MODE_REPORT: usize = 0;
const MODE_MEASURE: usize = 1;
const MODE_ROGUE: usize = 2;

/// Exit codes; `SUCCESS`, `NOT_STOPPED` and `NOT_VIRTIO` mirror `user/hwdomain`.
const SUCCESS: u64 = 0x2a;
const NOT_STOPPED: u64 = 0x5202;
/// The domain's probe found no virtio device in its window, and refused to report.
const NOT_VIRTIO: u64 = 0x5205;
/// What the kernel records for a process it killed.
const KILLED: u64 = u64::MAX;
/// What this check records for a domain whose program could not be filled in.
const NOT_LOADED: u64 = 0x10ad;

/// Where the granted window and the shared page go in the domain's address space: well
/// inside the user half, above anything the program's own segments reach, and clear of the
/// addresses `user/init` uses so a reader comparing the two is not misled.
fn window_va() -> usize {
    <Cpu as HasUserMode>::USER_START + 0x6000_0000
}
fn shared_va() -> usize {
    window_va() + 0x10_0000
}

/// The frame the domain writes its report to, and the kernel reads through the direct map.
static SHARED: AtomicU64 = AtomicU64::new(0);
/// What the domain's thread enters user mode with, read by [`domain_entry`].
static ENTRY: AtomicUsize = AtomicUsize::new(0);
static ARGS: [AtomicUsize; 4] = [const { AtomicUsize::new(0) }; 4];
static STACK_TOP: AtomicUsize = AtomicUsize::new(0);
/// The scheduler stack slot domain threads run on, once claimed; `usize::MAX` before.
static STACK: AtomicUsize = AtomicUsize::new(usize::MAX);

/// How long to wait for a domain's thread to end.
const DRAIN: Duration = Duration::from_nanos(2_000_000_000);

/// Run the prototype and report. On the boot thread, with the scheduler running, after the
/// process check has given its slots back.
pub fn check(c: &dyn EarlyConsole) -> Check {
    let Some((phys, len)) = platform::isolation_window() else {
        c.write_str("skipped: this machine has no device window to grant");
        return Check::Skipped;
    };
    let Some(program) = program() else {
        c.write_str("the embedded domain program does not load");
        return Check::Failed;
    };

    // The kernel's own run, over the window its address space maps.
    let Some(kernel_report) = in_kernel(phys, len) else {
        c.write_str("the kernel could not reach the granted window");
        return Check::Failed;
    };
    let kernel_ns = measure_in_kernel(phys, len);

    let baseline = free_frames();

    // The domain's run, over the same physical window mapped into an address space that
    // holds nothing else.
    let (domain_report, domain_code, timing) = match run_domain(&program, phys, len) {
        Ok(r) => r,
        Err(why) => {
            c.write_str("the domain FAILED: ");
            c.write_str(why);
            return Check::Failed;
        }
    };

    // The rogue run: a domain that reaches past its grant must be killed for it.
    let rogue_code = match run(&program, phys, len, MODE_ROGUE) {
        Ok((_, code)) => code,
        Err(why) => {
            c.write_str("the rogue domain FAILED: ");
            c.write_str(why);
            return Check::Failed;
        }
    };
    let leaked = baseline.saturating_sub(free_frames());

    report(
        c,
        kernel_report,
        domain_report,
        domain_code,
        rogue_code,
        kernel_ns,
        timing,
        leaked,
    );

    let agreed = domain_report == Some(kernel_report);
    let reported = domain_code == SUCCESS;
    let contained = rogue_code == KILLED;
    Check::from_ok(agreed && reported && contained && leaked == 0)
}

/// The driver body, run by the kernel over the granted window.
fn in_kernel(phys: u64, len: u64) -> Option<Report> {
    virtio_probe::identify(&kernel_hw(phys, len)?).ok()
}

/// Time [`MEASURE_READS`] identifications in the kernel, in nanoseconds for the whole loop.
///
/// The same loop the domain runs, from the same crate, so the two numbers differ only in
/// where the code was executing.
fn measure_in_kernel(phys: u64, len: u64) -> u64 {
    let Some(hw) = kernel_hw(phys, len) else {
        return 0;
    };
    let start = timekeeping::now();
    let _ = virtio_probe::identify_repeatedly(&hw, MEASURE_READS);
    timekeeping::now()
        .saturating_duration_since(start)
        .as_nanos()
}

/// The kernel's view of the granted window.
///
/// Identity, not through the direct map: `space::map_devices` maps every window the
/// platform recorded at its own physical address, as device memory, because the direct map
/// describes RAM and a device window is not RAM. The domain's mapping of the same registers
/// is at an address the kernel chose for it instead, which is the difference between the
/// two runs and the reason both are worth making.
fn kernel_hw(phys: u64, len: u64) -> Option<Parts<Direct, hwproxy::Buffer, NoIrq>> {
    let base = usize::try_from(phys).ok()?;
    let len = usize::try_from(len).ok()?;
    // SAFETY: the kernel address space maps this window identity as device memory; it is
    // one of `platform::device_windows`, which is what that space is built from.
    // Identification registers are read-only, so this run and the domain's do not disturb
    // each other.
    Some(Parts {
        regs: unsafe { Direct::new(base, len) },
        dma: NO_DMA,
        irq: NoIrq,
    })
}

/// What a domain's runs cost, in nanoseconds.
#[derive(Clone, Copy)]
struct Timing {
    /// One whole run that identifies the device once: building the address space, copying
    /// the program in, spawning and entering it, the identification, and tearing it down.
    fixed: u64,
    /// One identification inside the domain: the difference between the fastest run of
    /// [`MEASURE_READS`] and the fastest run of one, divided by the reads that differ. It
    /// still carries the jitter of whole runs, so it is reported as measured and argued in
    /// `docs/isolation.md` rather than trusted on its own.
    per_read: u64,
}

/// Whole runs of each kind the timing takes the fastest of.
///
/// A domain run builds and tears down an address space, and scheduling and emulation add
/// milliseconds of jitter to that. The fastest of a few runs is the one least disturbed, so
/// it is the one that says what the work itself costs.
const TIMED_RUNS: usize = 3;

/// The reporting runs: runs that identify the device once, and runs that identify it
/// [`MEASURE_READS`] times. Every one is timed and every one must exit with `SUCCESS` — a
/// timed run that failed early would otherwise be the fastest and be believed. Returns the
/// report from a single-read run, its exit code, and the timing the fastest of each implies.
fn run_domain(
    program: &elf::Program,
    phys: u64,
    len: u64,
) -> Result<(Option<Report>, u64, Timing), &'static str> {
    let mut report = None;
    let mut code = 0;
    let mut once = u64::MAX;
    let mut many = u64::MAX;
    for _ in 0..TIMED_RUNS {
        let start = timekeeping::now();
        (report, code) = run(program, phys, len, MODE_REPORT)?;
        once = once.min(ns_since(start));

        let start = timekeeping::now();
        let (_, measured) = run(program, phys, len, MODE_MEASURE)?;
        many = many.min(ns_since(start));
        if measured == NOT_VIRTIO {
            return Err("the domain's probe refused its window: it holds no virtio device");
        }
        if measured != SUCCESS {
            return Err("a timed domain run did not identify the device");
        }
    }
    let per_read = many.saturating_sub(once) / u64::from(MEASURE_READS - 1);
    Ok((
        report,
        code,
        Timing {
            fixed: once,
            per_read,
        },
    ))
}

fn ns_since(start: time::Instant) -> u64 {
    timekeeping::now()
        .saturating_duration_since(start)
        .as_nanos()
}

/// Build a domain, run it in `mode`, and wait for it to end.
///
/// Returns the report it left on the shared page, if it wrote a whole one, and its exit
/// code; or which step failed.
fn run(
    program: &elf::Program,
    phys: u64,
    len: u64,
    mode: usize,
) -> Result<(Option<Report>, u64), &'static str> {
    let root = match build_domain(program, phys, len, mode) {
        Ok(root) => root,
        Err(why) => {
            teardown();
            return Err(why);
        }
    };
    ENTRY.store(program.entry as usize, Ordering::Relaxed);
    let Some(stack) = stack() else {
        teardown();
        return Err("no guarded stack for the domain's thread");
    };
    let Some(id) = spawn(stack, root) else {
        teardown();
        return Err("the domain's thread could not be spawned");
    };
    if !wait_exit(id) {
        // Its thread is still running in the domain's address space, so that space cannot
        // be torn down under it. Reported, and left.
        return Err("the domain did not end");
    }
    let code = userproc::slot(SLOT).and_then(|p| p.exit);
    let _ = preempt::reap(id);
    let report = read_report();
    // A domain that succeeded read *a* window with the right registers; audit that it was
    // the one granted. Only after success, when the page is certain to have been faulted
    // in, and so that a domain whose probe refused its window is reported as that refusal.
    let audit = if code == Some(SUCCESS) {
        granted_window_is(phys)
    } else {
        Ok(())
    };
    teardown();
    audit?;
    code.map(|code| (report, code))
        .ok_or("the domain ended with no exit code")
}

/// Whether the domain in [`SLOT`] maps its window address to exactly `phys`.
///
/// Walks the domain's own page tables rather than the region it was built from: what
/// matters is what its MMU would do, and a grant bookkept right but mapped wrong must fail
/// here.
fn granted_window_is(phys: u64) -> Result<(), &'static str> {
    let window = ARGS[1].load(Ordering::Relaxed);
    let p = userproc::slot(SLOT).ok_or("the domain's slot is empty before its teardown")?;
    match p.vm.space().translate(window) {
        Some((mapped, _)) if mapped.raw() == phys => Ok(()),
        Some(_) => Err("the domain's window maps a page other than the one the platform recorded"),
        None => Err("the domain's window is not mapped after a run that read it"),
    }
}

/// The stack slot domain threads run on: claimed the first time, reused after, because the
/// previous domain's thread has always been reaped before the next is spawned.
fn stack() -> Option<usize> {
    let have = STACK.load(Ordering::Relaxed);
    if have != usize::MAX {
        return Some(have);
    }
    let claimed = preempt::claim_stacks(&["driver domain"])?;
    STACK.store(claimed, Ordering::Relaxed);
    Some(claimed)
}

/// Build the domain: a process with the granted window and a shared page, and nothing else
/// beyond its own program and stack.
fn build_domain(
    program: &elf::Program,
    phys: u64,
    len: u64,
    mode: usize,
) -> Result<PhysAddr, &'static str> {
    let root =
        userproc::build(SLOT, program).ok_or("the domain's address space could not be built")?;
    let shared = userproc::with_frames(|f| f.alloc_zeroed().ok())
        .flatten()
        .ok_or("no frame for the page the domain reports on")?;
    SHARED.store(shared.raw(), Ordering::Relaxed);
    let p = userproc::slot(SLOT).ok_or("the domain's slot is empty after building it")?;

    // The MMU grants pages; the device's window is 0x200 bytes. Map the page that holds it,
    // and tell the domain where inside that page the window starts and how long the device's
    // own window is, so the driver is bounded to the device and the MMU to the page.
    let page = Cpu::PAGE_SIZE as u64;
    let offset = phys & (page - 1);
    let base = phys - offset;
    let mapped = (offset + len).next_multiple_of(page);
    let (Ok(offset), Ok(mapped), Ok(len)) =
        (usize::try_from(offset), usize::try_from(mapped), usize::try_from(len))
    else {
        return Err("the granted window is not addressable");
    };
    // The grant itself: the device's registers, at a virtual address the kernel chose, in
    // an address space with nothing else in it. This is the only way the domain can reach
    // any device at all — there is no call that maps a physical address.
    p.vm.reserve(Region {
        start: window_va(),
        len: mapped,
        flags: userproc::user_device(),
        backing: Backing::Physical {
            base: PhysAddr::new(base),
        },
        huge: false,
    })
    .map_err(|_| "the granted window could not be mapped into the domain")?;
    p.vm.reserve(Region {
        start: shared_va(),
        len: Cpu::PAGE_SIZE,
        flags: userproc::user_rw(),
        backing: Backing::Physical { base: shared },
        huge: false,
    })
    .map_err(|_| "the report page could not be mapped into the domain")?;

    for (arg, value) in ARGS
        .iter()
        .zip([mode, window_va() + offset, len, shared_va()])
    {
        arg.store(value, Ordering::Relaxed);
    }
    Ok(root)
}

/// The domain thread's kernel entry: fill the program in, then drop to user mode.
///
/// The same shape as `crate::procs`' entry, and for the same reason: the copy runs on the
/// domain's own thread, so it is made against the address space the switch loaded.
extern "C" fn domain_entry(_: usize) -> ! {
    preempt::begin();
    let filled = program().and_then(|p| userproc::install_program(&p));
    if filled.is_none() {
        if let Some(p) = userproc::current() {
            p.exit = Some(NOT_LOADED);
        }
        preempt::exit_thread()
    }
    let args = ARGS.each_ref().map(|a| a.load(Ordering::Relaxed));
    let top = STACK_TOP.load(Ordering::Relaxed);
    let _ = Cpu::irq_save();
    // SAFETY: `spawn` bound this thread to `top` and its process's root before any CPU
    // could switch to it, the program is filled in, and its stack is mapped; masked.
    unsafe {
        Cpu::enter_user(
            ENTRY.load(Ordering::Relaxed),
            userproc::user_stack_pointer(),
            args,
            KernAddr::new(top),
        )
    }
}

fn spawn(stack: usize, root: PhysAddr) -> Option<ThreadId> {
    preempt::spawn_prepared(stack, domain_entry, 0, 4, |ctx, top| {
        STACK_TOP.store(top.raw(), Ordering::Relaxed);
        <Cpu as HasUserMode>::bind(ctx, top, root);
    })
}

/// The report the domain left on the shared page, if it wrote a whole one.
fn read_report() -> Option<Report> {
    let frame = PhysAddr::new(SHARED.load(Ordering::Relaxed));
    if frame.raw() == 0 {
        return None;
    }
    let ptr = userproc::direct_ptr(frame)?;
    let mut bytes = [0u8; REPORT_BYTES];
    for (i, b) in bytes.iter_mut().enumerate() {
        // SAFETY: the frame is the domain's shared page, mapped in the direct map and not
        // freed until `teardown`. The domain has exited, so nothing writes it now; the read
        // is volatile because the writer was another address space.
        *b = unsafe { ptr.add(i).read_volatile() };
    }
    Report::decode(&bytes)
}

/// Give the domain's slot and its shared frame back.
fn teardown() {
    userproc::teardown(SLOT);
    let frame = SHARED.swap(0, Ordering::Relaxed);
    if frame != 0 {
        userproc::with_frames(|f| f.free(PhysAddr::new(frame)));
    }
}

fn free_frames() -> usize {
    userproc::with_frames(|f| f.alloc.stats().free).unwrap_or(0)
}

/// The embedded domain program.
fn program() -> Option<elf::Program<'static>> {
    elf::Program::parse(
        DOMAIN_ELF,
        <Cpu as HasUserMode>::ELF_MACHINE,
        (<Cpu as HasUserMode>::USER_START as u64, <Cpu as HasUserMode>::USER_END as u64),
        Cpu::PAGE_SIZE as u64,
    )
    .ok()
}

/// The domain program, linked for this target and embedded by kbuild; see
/// `user/hwdomain`.
static DOMAIN_ELF: &[u8] = include_bytes!(env!("KINTANE_USER_HWDOMAIN"));

/// Wait up to [`DRAIN`] for `id` to exit.
fn wait_exit(id: ThreadId) -> bool {
    let give_up = timekeeping::now().saturating_add(DRAIN);
    while preempt::alive(id) {
        if timekeeping::now() >= give_up {
            return false;
        }
        sleep_until(timekeeping::now().saturating_add(Duration::from_nanos(5_000_000)));
    }
    true
}

#[allow(clippy::too_many_arguments)]
fn report(
    c: &dyn EarlyConsole,
    kernel: Report,
    domain: Option<Report>,
    code: u64,
    rogue: u64,
    kernel_ns: u64,
    timing: Timing,
    leaked: usize,
) {
    c.write_str("kernel read device ");
    write_usize(c, kernel.device_id as usize);
    c.write_str(", vendor ");
    write_usize(c, kernel.vendor_id as usize);
    match domain {
        Some(d) if d == kernel => c.write_str("; the domain read the same"),
        Some(_) => c.write_str("; THE DOMAIN READ SOMETHING ELSE"),
        None => c.write_str("; THE DOMAIN REPORTED NOTHING"),
    }
    if code != SUCCESS {
        c.write_str(", exit ");
        write_usize(c, code as usize);
    }
    c.write_str(match rogue {
        KILLED => "; past its grant: killed",
        NOT_STOPPED => "; PAST ITS GRANT: NOT STOPPED",
        _ => "; THE ROGUE DOMAIN DID NOT END AS EXPECTED",
    });
    c.write_str("; an identification ");
    write_usize(c, (kernel_ns / MEASURE_READS as u64) as usize);
    c.write_str(" ns in the kernel, ");
    write_usize(c, timing.per_read as usize);
    c.write_str(" ns in the domain; a domain's start, run and teardown ");
    write_usize(c, (timing.fixed / 1_000) as usize);
    c.write_str(" us");
    if leaked == 0 {
        c.write_str("; 0 frames left");
    } else {
        c.write_str("; ");
        write_usize(c, leaked);
        c.write_str(" FRAMES LEAKED");
    }
}

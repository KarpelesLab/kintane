//! The stress run: every subsystem at once, for as long as asked, audited every second.
//!
//! Built with `STRESS_TEST`. After bring-up, [`crate::persist`] hands the CPU to the
//! scheduler and boot becomes the auditor. Seven workload threads run at mixed
//! priorities:
//!
//! | workload | priority | does |
//! |---|---|---|
//! | sleep | 8 | sleeps to random deadlines and checks it woke neither early nor very late |
//! | pages | 6 | buddy page churn on a pool of its own, filling and checking every block |
//! | vm | 5 | demand paging, copy-on-write sharing and huge pages on a kernel `Vm` |
//! | heap A, heap B | 4 | kernel heap churn under seeded fault injection, never yielding |
//! | ping, pong | 4 | a channel round trip that moves a handle there and back |
//!
//! Fixed priority starves whatever sits below a thread that never blocks, so every
//! workload above the lowest level blocks on each iteration, and the busy ones share the
//! lowest level and take turns by the slice.
//!
//! # The audit
//!
//! Every [`AUDIT_EVERY`] of guest time the auditor asks every workload to stop at its
//! next checkpoint. A checkpoint is a point where the workload holds nothing another
//! check could miscount: the heap threads have freed their blocks, the page thread its
//! pages, the channel threads have no message in flight. The vm thread stops either with
//! its regions still mapped and shared, which is what `Vm::audit` is worth running on,
//! or with everything released, which is when its frame pool must be full again. A
//! workload that does not reach a checkpoint within [`PARK_WITHIN`] fails the audit, and
//! so does one that made no progress since the last audit. With every workload stopped,
//! the auditor checks:
//!
//! - **heap**: bytes in use are back at the baseline, and every failure the heap reports is one a
//!   workload saw and handled;
//! - **channel**: each side holds exactly the handles it should, and nothing is queued;
//! - **vm**: `Vm::audit`, and a full frame pool when nothing is mapped;
//! - **pages**: the buddy allocator's invariants, and every page free;
//! - **threads**: `Threads::check`, and nothing the scheduler recorded as broken;
//! - **locks**: no lock-order violation, in a build that checks.
//!
//! Then it lets them go and prints a heartbeat. `kbuild stress` watches for that line: a
//! run that stops printing it has hung, whatever the reason. A failed audit exits the
//! emulator with a failure at once. After `STRESS_SECONDS` the last audit is the final
//! one, and a pass exits with success.

mod block;
mod fs;
mod heap;
mod ipc;
mod net;
mod pages;
mod sleep;
mod vm;

use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicU8, AtomicU64, AtomicUsize, Ordering};

use arch::Cpu;
use boot_protocol::MemoryRegion;
use hal::{Arch, EarlyConsole};
use mm::phys::FrameAllocator;
use time::{Duration, Instant};

use crate::preempt::{self, sleep_until};
use crate::{Check, Live, finish, mp, timekeeping, write_usize};

/// How often the auditor stops everything and checks.
const AUDIT_EVERY: Duration = Duration::from_nanos(1_000_000_000);

/// How long a workload has to reach a checkpoint once asked. The slowest is the sleeper,
/// whose longest sleep is 50 ms; the rest reach one within an iteration.
const PARK_WITHIN: Duration = Duration::from_nanos(3_000_000_000);

/// While parked, a workload sleeps this long between looks at the request.
const PARKED_NAP: Duration = Duration::from_nanos(1_000_000);

/// The workloads, as indices into the per-workload tables.
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(usize)]
pub enum Workload {
    HeapA,
    HeapB,
    Ping,
    Pong,
    Sleep,
    Vm,
    Pages,
    /// Present only on a machine with the test disk.
    Block,
    /// A second block thread, so the disk has requests outstanding together: one thread
    /// cannot overlap with itself, and the driver's concurrency would go unexercised.
    BlockB,
    /// Present only when the filesystem check mounted the test disk's volume.
    Fs,
    /// Present only when the net check completed its round trips with kbuild.
    Net,
}

const WORKLOADS: usize = 11;

const NAMES: [&str; WORKLOADS] = [
    "heap A", "heap B", "ping", "pong", "sleep", "vm", "pages", "block", "block B", "fs", "net",
];

/// Guarded stacks the run claims beyond the ones the scheduler's own check left behind.
/// `preempt` asserts at compile time that `KERNEL_THREAD_SLOTS` covers both.
pub const EXTRA_STACKS: usize = if kconfig::STRESS_TEST {
    // The four named workloads; the three disk workloads (two block, one filesystem) when the
    // disk is attached; the network workload when a card is; and, when there is userspace,
    // the user process the auditor drives and the second thread of the waiting process it
    // drives after it.
    EXTRA_NAMES.len()
        + 3 * kconfig::QEMU_BLOCK_TEST as usize
        + kconfig::QEMU_NET_TEST as usize
        + 2 * kconfig::USERSPACE as usize
} else {
    0
};

/// The workloads that need a stack of their own, in the order they claim them.
const EXTRA_NAMES: [&str; 4] = ["heap B", "sleep", "vm", "pages"];

/// Where a parked workload stopped.
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Parked {
    /// Not parked.
    Running = 0,
    /// Stopped holding whatever it holds mid-iteration.
    Holding = 1,
    /// Stopped holding nothing.
    Empty = 2,
}

/// Set by the auditor to ask every workload to stop at its next checkpoint.
static PARK: AtomicBool = AtomicBool::new(false);

static PARKED: [AtomicU8; WORKLOADS] = [const { AtomicU8::new(Parked::Running as u8) }; WORKLOADS];

/// Iterations each workload completed.
static PROGRESS: [AtomicU64; WORKLOADS] = [const { AtomicU64::new(0) }; WORKLOADS];

/// The first thing each workload found wrong, as a `&'static str`'s pointer and length.
/// Null while nothing has.
static FAILURE: [(AtomicPtr<u8>, AtomicUsize); WORKLOADS] =
    [const { (AtomicPtr::new(core::ptr::null_mut()), AtomicUsize::new(0)) }; WORKLOADS];

/// Record that `w` found something wrong. The first report per workload is kept; the
/// auditor fails the run on its next audit.
pub fn fail(w: Workload, what: &'static str) {
    let (ptr, len) = &FAILURE[w as usize];
    if ptr
        .compare_exchange(
            core::ptr::null_mut(),
            what.as_ptr().cast_mut(),
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .is_ok()
    {
        len.store(what.len(), Ordering::Release);
    }
}

fn failure(w: usize) -> Option<&'static str> {
    let (ptr, len) = &FAILURE[w];
    let p = ptr.load(Ordering::Acquire);
    if p.is_null() {
        return None;
    }
    // SAFETY: `fail` stored the pointer and length of a `&'static str`, the pointer
    // first and the length right after; a zero length read in between is a valid empty
    // string, and a torn read is otherwise impossible because each is set once.
    let bytes = unsafe { core::slice::from_raw_parts(p.cast_const(), len.load(Ordering::Acquire)) };
    core::str::from_utf8(bytes).ok()
}

/// Iterations completed on each CPU, all workloads together.
static ON_CPU: [AtomicU64; mp::CPUS] = [const { AtomicU64::new(0) }; mp::CPUS];

/// For each workload, the CPUs it completed an iteration on since the last audit, as bits.
static SEEN_ON: [AtomicU64; WORKLOADS] = [const { AtomicU64::new(0) }; WORKLOADS];

/// Count one completed iteration of `w`, and where it ran.
pub fn progress(w: Workload) {
    PROGRESS[w as usize].fetch_add(1, Ordering::Relaxed);
    // Masked for the read only: which CPU completed the iteration, not which one the
    // thread is on by the time the counters are written.
    let irq = Cpu::irq_save();
    let cpu = Cpu::cpu_index().min(mp::CPUS - 1);
    // SAFETY: pairs with the `irq_save` above.
    unsafe { Cpu::irq_restore(irq) };
    ON_CPU[cpu].fetch_add(1, Ordering::Relaxed);
    SEEN_ON[w as usize].fetch_or(1 << cpu, Ordering::AcqRel);
}

/// Whether the auditor is asking workloads to stop.
pub fn park_requested() -> bool {
    PARK.load(Ordering::Acquire)
}

/// A checkpoint: if the auditor asked, stop here, reporting where, until it is done.
///
/// The store that reports the stop is `Release`, and the auditor's load of it is
/// `Acquire`. So when the auditor sees a workload parked, it also sees everything that
/// workload wrote before parking, on whichever CPU it ran: the handle tables, the frame
/// pools, the progress counters. See `docs/memory-model.md`.
pub fn checkpoint(w: Workload, state: Parked) {
    if !park_requested() {
        return;
    }
    PARKED[w as usize].store(state as u8, Ordering::Release);
    while park_requested() {
        sleep_until(timekeeping::now().saturating_add(PARKED_NAP));
    }
    PARKED[w as usize].store(Parked::Running as u8, Ordering::Release);
}

/// Where `w` is parked.
pub fn parked(w: Workload) -> Parked {
    match PARKED[w as usize].load(Ordering::Acquire) {
        1 => Parked::Holding,
        2 => Parked::Empty,
        _ => Parked::Running,
    }
}

/// A seeded xorshift generator. Each workload has its own, from `STRESS_SEED`.
pub struct Rng(u64);

impl Rng {
    pub fn new(stream: u64) -> Rng {
        let seed = (kconfig::STRESS_SEED as u64)
            .wrapping_mul(0x9E37_79B9_7F4A_7C15)
            .wrapping_add(stream.wrapping_mul(0xBF58_476D_1CE4_E5B9));
        Rng(if seed == 0 { 1 } else { seed })
    }

    pub fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    /// A value in `0..n`, or 0 for an empty range.
    pub fn below(&mut self, n: u64) -> u64 {
        if n == 0 { 0 } else { self.next() % n }
    }
}

/// Take the stress run's frame pools from the boot allocator. Nothing, and `Passed`,
/// without `STRESS_TEST`.
pub fn reserve(
    c: &dyn EarlyConsole,
    frames: &mut FrameAllocator<'_, Cpu>,
    map: &[MemoryRegion],
    live: Live,
) -> Check {
    if !kconfig::STRESS_TEST {
        return Check::Passed;
    }
    c.write_str("\n  stress     ");
    let Some(direct) = live.direct else {
        c.write_str("no kernel address space to page in");
        return Check::Failed;
    };
    let Some(pages) = pages::reserve(frames, map) else {
        c.write_str("no run of frames for the page pool");
        return Check::Failed;
    };
    let Some(vm_pool) = vm::reserve(frames, direct) else {
        c.write_str("no run of frames for the vm pool");
        return Check::Failed;
    };
    write_usize(c, pages);
    c.write_str(" pages for buddy churn, ");
    write_usize(c, vm_pool);
    c.write_str(" frames for demand paging ok");
    Check::Passed
}

/// The physical runs [`reserve`] took, for the in-kernel suite to keep out of. One run
/// covering both pools, `(0, 0)` when there are none.
pub fn region() -> (u64, u64) {
    let (a, b) = (pages::region(), vm::region());
    match (a.1, b.1) {
        (0, _) => b,
        (_, 0) => a,
        _ => {
            let lo = a.0.min(b.0);
            let hi = (a.0 + a.1).max(b.0 + b.1);
            (lo, hi - lo)
        }
    }
}

/// Whether every workload has parked.
fn all_parked() -> bool {
    PARKED
        .iter()
        .all(|p| p.load(Ordering::Acquire) != Parked::Running as u8)
}

/// End the run with a failure, saying why.
fn audit_failed(c: &dyn EarlyConsole, seconds: u64, what: &str, detail: &str) -> ! {
    c.write_str("\nstress AUDIT FAILED at ");
    write_usize(c, seconds as usize);
    c.write_str(" s: ");
    c.write_str(what);
    if !detail.is_empty() {
        c.write_str(": ");
        c.write_str(detail);
    }
    c.write_str("\n");
    finish(false)
}

/// The auditor, on the boot thread. Never returns: it ends the run.
pub fn run(c: &dyn EarlyConsole) -> ! {
    c.write_str("stress: ");
    write_usize(c, kconfig::STRESS_SECONDS);
    c.write_str(" s, seed ");
    write_usize(c, kconfig::STRESS_SEED);
    c.write_str("\n");

    if let Err(what) = start() {
        audit_failed(c, 0, "could not start", what);
    }

    let start = timekeeping::now();
    let end = start.saturating_add(Duration::from_nanos(
        (kconfig::STRESS_SECONDS as u64).saturating_mul(1_000_000_000),
    ));
    let mut last = [0u64; WORKLOADS];
    let mut next = start;
    let mut audits = 0u64;
    loop {
        next = next.saturating_add(AUDIT_EVERY);
        // Between audits, while every workload runs: create a user process, move its
        // thread across the CPUs, destroy it, and require every frame back. A failure ends
        // the run like any other audit.
        if let Err(what) = crate::model::process_stress_cycle(audits) {
            let seconds = timekeeping::now()
                .saturating_duration_since(start)
                .as_nanos()
                / 1_000_000_000;
            audit_failed(c, seconds, "user process", what);
        }
        // Then a process whose two threads, pinned to two CPUs, block on each other: a lost
        // wake-up is a receive that times out, and fails the run.
        if let Err(what) = crate::model::wait_stress_cycle(audits) {
            let seconds = timekeeping::now()
                .saturating_duration_since(start)
                .as_nanos()
                / 1_000_000_000;
            audit_failed(c, seconds, "waiting process", what);
        }
        sleep_until(next.min(end));
        let now = timekeeping::now();
        let seconds = now.saturating_duration_since(start).as_nanos() / 1_000_000_000;

        PARK.store(true, Ordering::Release);
        let deadline = now.saturating_add(PARK_WITHIN);
        while !all_parked() && timekeeping::now() < deadline {
            sleep_until(timekeeping::now().saturating_add(PARKED_NAP));
        }
        if let Some(w) = (0..WORKLOADS).find(|&w| PARKED[w].load(Ordering::Acquire) == 0) {
            audit_failed(c, seconds, "a workload did not reach a checkpoint", NAMES[w]);
        }
        audit(c, seconds, &mut last);
        audits += 1;
        PARK.store(false, Ordering::Release);

        heartbeat(c, seconds, audits);
        if now >= end {
            // Observed, not assumed: two block threads were running the whole time, and
            // a driver whose requests never actually overlapped proved nothing about the
            // concurrency it claims.
            if block::present() && block::peak_in_flight() < 2 {
                audit_failed(
                    c,
                    seconds,
                    "block",
                    "the disk never had two requests outstanding at once",
                );
            }
            c.write_str("stress passed: ");
            write_usize(c, audits as usize);
            c.write_str(" audits over ");
            write_usize(c, seconds as usize);
            c.write_str(" s\n");
            finish(true);
        }
    }
}

/// Set every workload up and spawn its thread.
fn start() -> Result<(), &'static str> {
    heap::setup()?;
    ipc::setup()?;
    pages::setup()?;
    vm::setup()?;
    block::setup()?;
    fs::setup()?;
    net::setup()?;

    // Idle keeps the first of the scheduler's stacks. The other three the boot checks
    // used are free again; four more come from the port's array.
    let extra = preempt::claim_stacks(&EXTRA_NAMES).ok_or("not enough guarded thread stacks")?;
    // After the workloads' own, so their slot numbers are what they were: the stack the
    // user process the auditor drives runs on, in an image with userspace.
    crate::model::process_stress_setup()?;
    crate::model::wait_stress_setup()?;
    // Every workload but the three that need the disk and the one that needs the network,
    // which are spawned below only if those exist.
    let plan: [(extern "C" fn(usize) -> !, usize, u8, usize); WORKLOADS - 4] = [
        (heap::worker, 0, 4, 1),
        (heap::worker, 1, 4, extra),
        (ipc::ping, 0, 4, 2),
        (ipc::pong, 0, 4, 3),
        (sleep::worker, 0, 8, extra + 1),
        (vm::worker, 0, 5, extra + 2),
        (pages::worker, 0, 6, extra + 3),
    ];
    let irq = Cpu::irq_save();
    let spawned = plan
        .iter()
        .all(|&(entry, arg, level, stack)| preempt::spawn(stack, entry, arg, level).is_some());
    // SAFETY: pairs with the `irq_save` above.
    unsafe { Cpu::irq_restore(irq) };
    if !spawned {
        return Err("a workload thread was refused");
    }

    // The disk workloads need the disk, and a stack only when they run: a machine without
    // the disk has neither, and their slots read as parked holding nothing, so the auditor
    // neither waits for them nor asks them for progress.
    if block::present() {
        // Two threads, each on its own half of the scratch area, so their requests overlap
        // at the device without either overwriting what the other reads back.
        spawn_disk_workload("block", block::worker, 0)?;
        spawn_disk_workload("block B", block::worker, 1)?;
    } else {
        PARKED[Workload::Block as usize].store(Parked::Empty as u8, Ordering::Release);
        PARKED[Workload::BlockB as usize].store(Parked::Empty as u8, Ordering::Release);
    }
    // The filesystem workload reads the volume the filesystem check mounted, which exists
    // only where the disk does, and the same reasoning about its slot applies.
    if fs::present() {
        spawn_disk_workload("fs", fs::worker, 0)?;
    } else {
        PARKED[Workload::Fs as usize].store(Parked::Empty as u8, Ordering::Release);
    }
    // The network workload needs the card and kbuild's address, which the net check leaves
    // only where it passed; its slot is treated the same way. It claims a stack as the disk
    // workloads do.
    if net::present() {
        spawn_disk_workload("net", net::worker, 0)?;
    } else {
        PARKED[Workload::Net as usize].store(Parked::Empty as u8, Ordering::Release);
    }
    Ok(())
}

/// Claim a guarded stack for a workload that needs the disk, and spawn its thread on it,
/// passing `arg`.
fn spawn_disk_workload(
    name: &'static str,
    entry: extern "C" fn(usize) -> !,
    arg: usize,
) -> Result<(), &'static str> {
    let stack = preempt::claim_stacks(&[name]).ok_or("not enough guarded thread stacks")?;
    let irq = Cpu::irq_save();
    let spawned = preempt::spawn(stack, entry, arg, 5).is_some();
    // SAFETY: pairs with the `irq_save` above.
    unsafe { Cpu::irq_restore(irq) };
    if spawned {
        Ok(())
    } else {
        Err("a disk workload's thread was refused")
    }
}

/// Check everything, with every workload parked. Ends the run on the first failure.
fn audit(c: &dyn EarlyConsole, seconds: u64, last: &mut [u64; WORKLOADS]) {
    for (w, name) in NAMES.iter().enumerate() {
        if let Some(what) = failure(w) {
            c.write_str("\nstress: ");
            c.write_str(name);
            audit_failed(c, seconds, "a workload found something wrong", what);
        }
        let now = PROGRESS[w].load(Ordering::Acquire);
        let is_block = w == Workload::Block as usize || w == Workload::BlockB as usize;
        let absent = (is_block && !block::present())
            || (w == Workload::Fs as usize && !fs::present())
            || (w == Workload::Net as usize && !net::present());
        if absent {
            continue;
        }
        if now == last[w] {
            audit_failed(c, seconds, "a workload made no progress since the last audit", name);
        }
        last[w] = now;
    }
    if let Err(what) = heap::audit() {
        audit_failed(c, seconds, "kernel heap", what);
    }
    if let Err(what) = ipc::audit() {
        audit_failed(c, seconds, "channel", what);
    }
    if let Err(what) = vm::audit(parked(Workload::Vm)) {
        audit_failed(c, seconds, "vm", what);
    }
    if let Err(what) = pages::audit() {
        audit_failed(c, seconds, "buddy pages", what);
    }
    if let Err(what) = block::audit() {
        audit_failed(c, seconds, "block", what);
    }
    if let Err(what) = fs::audit() {
        audit_failed(c, seconds, "filesystem", what);
    }
    if let Err(what) = net::audit() {
        audit_failed(c, seconds, "network", what);
    }
    if !preempt::table_ok() {
        audit_failed(c, seconds, "thread table", "an invariant does not hold");
    }
    if preempt::broken() != 0 {
        preempt::report_broken(c);
        audit_failed(c, seconds, "scheduler", "something went wrong in a switch");
    }
    if sync::lockdep::ENABLED {
        let report = sync::lockdep::report::<Cpu>();
        if report.count != 0 {
            crate::lockcheck::verdict(c);
            audit_failed(c, seconds, "lock order", "a violation was recorded");
        }
    }
    let seen = SEEN_ON.each_ref().map(|s| s.swap(0, Ordering::AcqRel));
    if preempt::stats().cpus > 1 {
        // The two heap threads never block, so only balancing moves them off the CPU that
        // spawned them. On one CPU for a whole audit interval between them means nothing
        // moved them apart.
        let busy = seen[Workload::HeapA as usize] | seen[Workload::HeapB as usize];
        if busy.count_ones() < 2 {
            audit_failed(
                c,
                seconds,
                "scheduler",
                "both never-blocking heap workloads ran on one CPU for a whole interval",
            );
        }
    }
    if mp::shootdown_stats().2 != 0 {
        audit_failed(
            c,
            seconds,
            "tlb shootdown",
            "a shootdown was answered by the wrong CPUs, or stalled",
        );
    }
}

fn heartbeat(c: &dyn EarlyConsole, seconds: u64, audits: u64) {
    let p = |w: Workload| PROGRESS[w as usize].load(Ordering::Relaxed) as usize;
    c.write_str("stress heartbeat ");
    write_usize(c, seconds as usize);
    c.write_str("/");
    write_usize(c, kconfig::STRESS_SECONDS);
    c.write_str(" s: heap ");
    write_usize(c, p(Workload::HeapA) + p(Workload::HeapB));
    c.write_str(" (refused ");
    write_usize(c, heap::refused() as usize);
    c.write_str("), ipc ");
    write_usize(c, p(Workload::Ping));
    c.write_str(", sleeps ");
    write_usize(c, p(Workload::Sleep));
    c.write_str(" (latest +");
    write_usize(c, (sleep::worst_late().as_nanos() / 1_000) as usize);
    c.write_str(" us), vm ");
    write_usize(c, p(Workload::Vm));
    c.write_str(" (faults ");
    write_usize(c, vm::faults() as usize);
    c.write_str(", copies ");
    write_usize(c, vm::copies() as usize);
    c.write_str(", huge ");
    write_usize(c, vm::huge() as usize);
    c.write_str("), pages ");
    write_usize(c, p(Workload::Pages));
    if block::present() {
        c.write_str(", block ");
        write_usize(c, p(Workload::Block));
        c.write_str("+");
        write_usize(c, p(Workload::BlockB));
        c.write_str(" (requests ");
        write_usize(c, block::requests() as usize);
        c.write_str(", peak in flight ");
        write_usize(c, block::peak_in_flight());
        let (by_interrupt, polled) = block::completions();
        c.write_str(", by interrupt ");
        write_usize(c, by_interrupt as usize);
        c.write_str(", polled ");
        write_usize(c, polled as usize);
        c.write_str(")");
    }
    if fs::present() {
        let (hits, misses, drops) = fs::cache_counters();
        c.write_str(", fs ");
        write_usize(c, p(Workload::Fs));
        c.write_str(" (opens ");
        write_usize(c, fs::opens() as usize);
        c.write_str(", checked ");
        write_usize(c, (fs::checked_bytes() / 1024) as usize);
        c.write_str(" KiB, cache ");
        write_usize(c, hits as usize);
        c.write_str("/");
        write_usize(c, misses as usize);
        c.write_str(" hit/miss, ");
        write_usize(c, drops as usize);
        c.write_str(" drops)");
    }
    if net::present() {
        let (pings, rounds, retries) = net::counts();
        c.write_str(", net ");
        write_usize(c, p(Workload::Net));
        c.write_str(" (echo replies ");
        write_usize(c, pings as usize);
        c.write_str(", udp round trips ");
        write_usize(c, rounds as usize);
        c.write_str(", retries ");
        write_usize(c, retries as usize);
        c.write_str(")");
    }
    if mp::CPUS > 1 {
        let s = preempt::stats();
        let (shootdowns, _, _) = mp::shootdown_stats();
        c.write_str(", cpus ");
        write_usize(c, s.cpus);
        c.write_str(" [");
        for (cpu, n) in ON_CPU.iter().enumerate().take(s.cpus.max(1)) {
            if cpu != 0 {
                c.write_str(" ");
            }
            write_usize(c, n.load(Ordering::Relaxed) as usize);
        }
        c.write_str("] migrations ");
        write_usize(c, s.migrations as usize);
        c.write_str(" (pulls ");
        write_usize(c, s.pulls as usize);
        c.write_str("), ipis ");
        write_usize(c, s.reschedules as usize + s.timer_kicks as usize);
        c.write_str(" (idle kicks ");
        write_usize(c, s.idle_kicks as usize);
        c.write_str(")");
        c.write_str(", shootdowns ");
        write_usize(c, shootdowns);
    }
    let processes = crate::model::process_stress_cycles();
    if processes != 0 {
        c.write_str(", processes ");
        write_usize(c, processes as usize);
        // How long the slowest cycle waited to see its thread served on the CPU it pinned
        // it to. A scheduling delay, reported because the wait that bounds it would
        // otherwise be a number nobody checks: at eight CPUs it outgrew the fixed window
        // this replaced.
        c.write_str(" (served after max ");
        write_usize(c, crate::model::process_stress_serve_worst_us() as usize);
        // And the most slices any of its waits was charged before it succeeded, against the
        // bounds that fail one: the margin the progress check really has.
        let (ran, passed) = crate::model::process_stress_slices_worst();
        c.write_str(" us, slices ran max ");
        write_usize(c, ran as usize);
        c.write_str(", passed over max ");
        write_usize(c, passed as usize);
        c.write_str(")");
    }
    crate::model::wait_stress_heartbeat(c);
    c.write_str(", audits ");
    write_usize(c, audits as usize);
    c.write_str(" ok\n");
}

/// `now` plus `ms` milliseconds.
pub fn after_ms(ms: u64) -> Instant {
    timekeeping::now().saturating_add(Duration::from_nanos(ms.saturating_mul(1_000_000)))
}

/// The architecture's page size, for workloads sizing blocks in pages.
pub const PAGE: usize = <Cpu as Arch>::PAGE_SIZE;

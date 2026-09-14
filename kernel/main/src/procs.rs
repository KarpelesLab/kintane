//! Several processes at once, on the kernel's own scheduler.
//!
//! [`crate::userproc`] runs one process at a time, by hand, before the scheduler exists.
//! This runs processes the way a kernel does: as threads on the same run queues as every
//! kernel thread, preempted by the same timer, and — on an SMP kernel — moved between CPUs.
//! What it proves is that a thread's address space is a property of the thread and not of
//! the CPU: the context switch loads it wherever the thread lands, and a process can only
//! ever see its own memory.
//!
//! # What runs
//!
//! Two *workers* and a *victim*, built from the same embedded `init` program:
//!
//! * Each worker is given the same private address and a signature of its own. It writes the
//!   signature there, then loops reading it back and publishing what it saw, a pass counter, and
//!   whether it has been told to stop, on a page it shares with the kernel. The kernel reads that
//!   page through its direct map while the worker runs, so it can watch progress without stopping
//!   anything.
//! * The victim writes to kernel memory and must be killed for it, while the workers go on.
//!
//! # What must hold
//!
//! * **Concurrency.** Both workers make progress within the same window of boot's sleep, so they
//!   share the CPUs rather than running one after the other.
//! * **Isolation.** Every pass of each worker reads back its *own* signature from the address both
//!   of them wrote to. Were the two threads sharing one address space — a switch that did not load
//!   the space, say — one would read the other's.
//! * **Kill.** The victim ends with the kernel's kill code, and both workers make progress after it
//!   is gone.
//! * **Migration** is not checked here, because it cannot happen here. This runs inside the
//!   boot-time scheduler check, and a secondary CPU joins the scheduler only when bring-up hands
//!   every CPU over (`preempt::resume`), after the boot verdict. Until then placement treats every
//!   CPU but the boot CPU as offline, and a thread restricted to one of them could never run again.
//!   The stress run, which runs on every CPU, is where a process thread migrates; see
//!   [`stress_cycle`].
//! * **Reclamation.** Every frame the three processes took, from a pool of this check's own, is
//!   back when they are torn down.

#![allow(unsafe_code)]

use core::cell::SyncUnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use arch::Cpu;
use boot_protocol::{MemoryKind, MemoryRegion};
use elf::Program;
use hal::{Arch, EarlyConsole, HasUserMode, KernAddr, PhysAddr};
use mm::DirectMap;
use mm::paged::FrameSource;
use mm::phys::{FrameAllocator, bitmap_bytes};
use mm::vm::{Backing, Region};
use sched::ThreadId;
use time::Duration;

use crate::preempt::{self, sleep_until};
use crate::{Check, timekeeping, userproc, write_hex, write_usize};

/// Frames the processes are built from. Each takes about a dozen — its page tables, the
/// program's segments, the pages of stack it touches, a shared and a private page — so a
/// few hundred is room for three with slack, and small enough to take from any preset.
const POOL_FRAMES: usize = 512;
const FRAME_STORE_BYTES: usize = POOL_FRAMES / 2;

/// `init`'s worker and fault modes, in the register the kernel passes them.
const MODE_WORKER: usize = 3;
const MODE_FAULT: usize = 2;
/// `init`'s exit code when a worker was stopped with its memory intact.
const WORKER_SUCCESS: u64 = 0x2a;
/// What the kernel records as the exit code of a process it killed.
const KILLED: u64 = u64::MAX;

/// Words of the page a worker shares with the kernel; mirrors `user/init`.
const W_PASSES: usize = 0;
const W_STOP: usize = 1;
const W_SEEN: usize = 2;

/// Process slots and the scheduler stack slots their threads run on. The stack slots are
/// the ones `shared`'s phases use and give back before this runs.
const WORKERS: [usize; 2] = [0, 1];
const VICTIM: usize = 2;
const STACK_OF: [usize; 3] = [1, 2, 3];
/// Priority of the process threads: below boot, so boot's wake-ups preempt them.
const PRIORITY: u8 = 4;

/// Signatures the workers write to their private page. Distinct, and unlike anything a
/// zeroed or reused page holds.
const SIGNATURE: [u64; 2] = [0x5157_0000_0000_a11a, 0x5157_0000_0000_b22b];

/// How long boot watches between samples.
const WINDOW: Duration = Duration::from_nanos(150_000_000);
/// The longest boot waits for a stopped or killed process's thread to end.
const DRAIN: Duration = Duration::from_nanos(1_000_000_000);

// ---- the pool --------------------------------------------------------------------------

/// SAFETY INVARIANT: borrowed once, by the first [`reserve`] (see `RESERVED`).
static FRAME_STORE: SyncUnsafeCell<[u8; FRAME_STORE_BYTES]> =
    SyncUnsafeCell::new([0; FRAME_STORE_BYTES]);
/// The pool's allocator. SAFETY INVARIANT: written once by [`reserve`] at boot, before any
/// process exists; after that reached only through `userproc::with_frames`, under its lock.
static POOL: SyncUnsafeCell<Option<FrameAllocator<'static, Cpu>>> = SyncUnsafeCell::new(None);
static RESERVED: AtomicBool = AtomicBool::new(false);
static REGION: [AtomicU64; 2] = [const { AtomicU64::new(0) }; 2];

/// Take this check's frames from the boot allocator. Called by boot during `memory()`,
/// while that allocator is alive; the processes are built long after it has gone.
pub fn reserve(frames: &mut FrameAllocator<'_, Cpu>, direct: DirectMap) -> bool {
    if RESERVED.swap(true, Ordering::Relaxed) {
        return false;
    }
    let Ok(run) = frames.alloc_contiguous(POOL_FRAMES) else {
        return false;
    };
    let start = run.start().start().raw();
    let len = (POOL_FRAMES * Cpu::PAGE_SIZE) as u64;
    let own_map = [MemoryRegion {
        start,
        len,
        kind: MemoryKind::Usable as u32,
        _reserved: 0,
    }];
    let reachable = direct.covers_phys(PhysAddr::new(start))
        && direct.covers_phys(PhysAddr::new(start + len - 1));
    if !reachable || bitmap_bytes::<Cpu>(&own_map).map_or(true, |n| n > FRAME_STORE_BYTES) {
        let _ = frames.free_contiguous(run);
        return false;
    }
    // SAFETY: the one borrow of the store; `RESERVED` guarantees this runs once.
    let store = unsafe { &mut *FRAME_STORE.get() };
    let Ok(pool) = FrameAllocator::<Cpu>::new(&own_map, store) else {
        return false;
    };
    // SAFETY: see `POOL`; once, at boot, before any process.
    unsafe { *POOL.get() = Some(pool) };
    REGION[0].store(start, Ordering::Relaxed);
    REGION[1].store(len, Ordering::Relaxed);
    true
}

/// The pool's physical run, `(start, len)`, for the in-kernel suite to keep out of.
pub fn region() -> (u64, u64) {
    (REGION[0].load(Ordering::Relaxed), REGION[1].load(Ordering::Relaxed))
}

fn free_frames() -> usize {
    userproc::with_frames(|f| f.alloc.stats().free).unwrap_or(0)
}

// ---- starting a process thread ----------------------------------------------------------

/// What each process thread enters user mode with, by process slot: the program entry,
/// the four argument registers, and the kernel stack its traps land on.
static ENTRY: AtomicUsize = AtomicUsize::new(0);
static ARGS: [[AtomicUsize; 4]; 3] = [const { [const { AtomicUsize::new(0) }; 4] }; 3];
static STACK_TOP: [AtomicUsize; 3] = [const { AtomicUsize::new(0) }; 3];
/// The physical frame each worker shares with the kernel.
static SHARED: [AtomicU64; 2] = [const { AtomicU64::new(0) }; 2];

/// The exit code recorded for a process whose thread could not fill its program in.
const NOT_LOADED: u64 = 0x10ad;

/// A process thread's kernel entry: fill its program in, then enter user mode.
///
/// The program is copied here, on the process's own thread, not by whoever built the
/// process. The switch into this thread loaded the process's address space, and every
/// later switch back to it loads it again, so the copy can be preempted — or the thread
/// moved to another CPU — part-way through and still lands in the right space. That is the
/// property this file exists to check, used rather than worked around. Copying from the
/// builder's thread instead means loading the process's space on the builder's CPU with
/// interrupts masked for the whole copy: tens of milliseconds under emulation, on what may
/// be the CPU that keeps time, which the stress run measured as sleeps waking 65 ms late.
extern "C" fn user_entry(slot: usize) -> ! {
    preempt::begin();
    let filled = userproc::program().and_then(|p| userproc::install_program(&p));
    if filled.is_none() {
        if let Some(p) = userproc::current() {
            p.exit = Some(NOT_LOADED);
        }
        preempt::exit_thread()
    }
    let args = ARGS[slot].each_ref().map(|a| a.load(Ordering::Relaxed));
    let top = STACK_TOP[slot].load(Ordering::Relaxed);
    // `enter_user` wants interrupts masked until its `iretq`/`eret` unmasks them.
    let _ = Cpu::irq_save();
    // SAFETY: `spawn_prepared` bound this thread to `top` and its process's root before
    // any CPU could switch to it, so this thread runs on that root wherever it is; the
    // program's segments were filled in above and the stack is mapped; masked.
    unsafe {
        Cpu::enter_user(
            ENTRY.load(Ordering::Relaxed),
            userproc::user_stack_pointer(),
            args,
            KernAddr::new(top),
        )
    }
}

/// Build the process in `slot` and return its root. Its program is filled in by its own
/// thread; see [`user_entry`].
fn build(slot: usize, program: &Program) -> Option<PhysAddr> {
    userproc::build(slot, program)
}

/// Build worker `w`: a process with a page shared with the kernel and a private page.
fn build_worker(w: usize, program: &Program) -> Option<PhysAddr> {
    let slot = WORKERS[w];
    let root = build(slot, program)?;
    let shared = userproc::with_frames(|f| f.alloc_zeroed().ok())??;
    SHARED[w].store(shared.raw(), Ordering::Relaxed);
    let p = userproc::slot(slot)?;
    p.vm.reserve(Region {
        start: shared_va(),
        len: Cpu::PAGE_SIZE,
        flags: userproc::user_rw(),
        backing: Backing::Physical { base: shared },
        huge: false,
    })
    .ok()?;
    p.vm.reserve(userproc::anon(private_va(), Cpu::PAGE_SIZE))
        .ok()?;
    for (arg, value) in ARGS[slot].iter().zip([
        MODE_WORKER,
        shared_va(),
        private_va(),
        SIGNATURE[w] as usize,
    ]) {
        arg.store(value, Ordering::Relaxed);
    }
    Some(root)
}

/// Where the shared and private pages go: well inside the user half, above anything the
/// program's segments or its `vm_map` area reach, and away from the address `init` keeps
/// unmapped.
fn shared_va() -> usize {
    <Cpu as HasUserMode>::USER_START + 0x4000_0000
}
fn private_va() -> usize {
    shared_va() + 2 * Cpu::PAGE_SIZE
}

/// Spawn the thread for process `slot`, bound to its root before it can run, on the stack
/// slot the boot check uses for it.
fn spawn(slot: usize, root: PhysAddr) -> Option<ThreadId> {
    spawn_on(slot, root, STACK_OF[slot])
}

/// As [`spawn`], on scheduler stack slot `stack`.
fn spawn_on(slot: usize, root: PhysAddr, stack: usize) -> Option<ThreadId> {
    preempt::spawn_prepared(stack, user_entry, slot, PRIORITY, |ctx, top| {
        STACK_TOP[slot].store(top.raw(), Ordering::Relaxed);
        <Cpu as HasUserMode>::bind(ctx, top, root);
    })
}

// ---- watching ----------------------------------------------------------------------------

/// Word `word` of worker `w`'s shared page, read through the direct map.
fn shared_word(w: usize, word: usize) -> u64 {
    let frame = PhysAddr::new(SHARED[w].load(Ordering::Relaxed));
    let Some(ptr) = userproc::direct_ptr(frame) else {
        return 0;
    };
    // SAFETY: the frame is the worker's shared page, mapped in the direct map and alive
    // until teardown. The worker writes it from another CPU; a volatile read through a raw
    // pointer takes no reference to memory someone else is writing.
    unsafe { ptr.cast::<u64>().add(word).read_volatile() }
}

fn set_stop(w: usize) {
    let frame = PhysAddr::new(SHARED[w].load(Ordering::Relaxed));
    if let Some(ptr) = userproc::direct_ptr(frame) {
        // SAFETY: as `shared_word`; the worker only reads this word.
        unsafe { ptr.cast::<u64>().add(W_STOP).write_volatile(1) };
    }
}

fn passes(w: usize) -> u64 {
    shared_word(w, W_PASSES)
}

/// Sleep boot for `d`, letting everything else run.
fn nap(d: Duration) {
    sleep_until(timekeeping::now().saturating_add(d));
}

/// Wait up to [`DRAIN`] for `id` to exit.
fn wait_exit(id: ThreadId) -> bool {
    let give_up = timekeeping::now().saturating_add(DRAIN);
    while preempt::alive(id) {
        if timekeeping::now() >= give_up {
            return false;
        }
        nap(Duration::from_nanos(10_000_000));
    }
    true
}

// ---- the check ------------------------------------------------------------------------

/// Run the processes and grade them. On the boot thread, with the scheduler running.
pub fn check(c: &dyn EarlyConsole) -> Check {
    c.write_str("\n  processes  ");
    // SAFETY: see `POOL`; written at boot, and nothing else holds a reference to it now.
    let Some(pool) = (unsafe { (*POOL.get()).as_mut() }) else {
        c.write_str("skipped: no frames were reserved for processes");
        return Check::Skipped;
    };
    let Some(program) = userproc::program() else {
        c.write_str("the embedded init program does not load");
        return Check::Failed;
    };
    userproc::set_frames(pool);
    let baseline = free_frames();

    let roots = [build_worker(0, &program), build_worker(1, &program)];
    let [Some(root_a), Some(root_b)] = roots else {
        c.write_str("could not build the workers");
        teardown_all();
        return Check::Failed;
    };
    ENTRY.store(program.entry as usize, Ordering::Relaxed);
    let (Some(a), Some(b)) = (spawn(WORKERS[0], root_a), spawn(WORKERS[1], root_b)) else {
        c.write_str("could not start the workers");
        teardown_all();
        return Check::Failed;
    };

    // Concurrency: both make progress within one window.
    nap(WINDOW);
    let (a0, b0) = (passes(0), passes(1));
    nap(WINDOW);
    let (a1, b1) = (passes(0), passes(1));
    let together = a1 > a0 && b1 > b0;

    // Kill: a victim that writes kernel memory, while both workers run.
    let victim = build(VICTIM, &program).and_then(|root| {
        for (arg, value) in
            ARGS[VICTIM]
                .iter()
                .zip([MODE_FAULT, userproc::kernel_root().raw() as usize, 0, 0])
        {
            arg.store(value, Ordering::Relaxed);
        }
        spawn(VICTIM, root)
    });
    let victim_gone = victim.is_some_and(wait_exit);
    let victim_code = userproc::slot(VICTIM).and_then(|p| p.exit);
    let (a2, b2) = (passes(0), passes(1));
    nap(WINDOW);
    let (a3, b3) = (passes(0), passes(1));
    let survived = a3 > a2 && b3 > b2;
    let killed = victim_gone && victim_code == Some(KILLED);

    // Migration: pin a worker to one CPU, then another, and see the kernel serve it on each.
    // Isolation: every pass read back its own signature, and still does.
    let isolated = (0..2).all(|w| shared_word(w, W_SEEN) == SIGNATURE[w]);

    // Stop the workers and collect them.
    set_stop(0);
    set_stop(1);
    let stopped = wait_exit(a) & wait_exit(b);
    let codes = WORKERS.map(|s| userproc::slot(s).and_then(|p| p.exit));
    let exits_ok = codes == [Some(WORKER_SUCCESS); 2];

    for id in [Some(a), Some(b), victim].into_iter().flatten() {
        let _ = preempt::reap(id);
    }
    teardown_all();
    let leaked = baseline.saturating_sub(free_frames());

    report(c, a1, b1, isolated, killed, survived, leaked, codes);
    Check::from_ok(together && isolated && killed && survived && stopped && exits_ok && leaked == 0)
}

/// Tear down every process slot this check uses and give back the shared frames.
fn teardown_all() {
    for slot in [WORKERS[0], WORKERS[1], VICTIM] {
        userproc::teardown(slot);
    }
    for shared in &SHARED {
        let frame = shared.swap(0, Ordering::Relaxed);
        if frame != 0 {
            userproc::with_frames(|f| f.free(PhysAddr::new(frame)));
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn report(
    c: &dyn EarlyConsole,
    a: u64,
    b: u64,
    isolated: bool,
    killed: bool,
    survived: bool,
    leaked: usize,
    codes: [Option<u64>; 2],
) {
    c.write_str("2 workers, ");
    write_usize(c, a as usize);
    c.write_str(" and ");
    write_usize(c, b as usize);
    c.write_str(" passes together");
    c.write_str(if isolated {
        "; each read its own signature"
    } else {
        "; A WORKER READ ANOTHER'S MEMORY"
    });
    c.write_str(if killed {
        "; victim killed"
    } else {
        "; VICTIM NOT KILLED"
    });
    c.write_str(if survived {
        ", workers kept running"
    } else {
        ", WORKERS STOPPED WITH IT"
    });
    if codes != [Some(WORKER_SUCCESS); 2] {
        c.write_str("; WORKER EXITS ");
        for code in codes {
            match code {
                Some(v) => write_hex(c, v),
                None => c.write_str("(none)"),
            }
            c.write_str(" ");
        }
    }
    c.write_str("; ");
    write_usize(c, leaked);
    c.write_str(if leaked == 0 {
        " frames left ok"
    } else {
        " FRAMES LEAKED"
    });
}

// ---- the stress run -------------------------------------------------------------------
//
// The boot check runs before any secondary CPU schedules, so it cannot move a process
// thread between CPUs. The stress run's auditor can: every CPU has joined by then. Once per
// audit interval, while every other workload runs, it builds a worker process, pins its
// thread to one CPU and then the next, requires the kernel to have served the process on
// each with its signature still reading back, stops it, tears it down, and requires every
// frame back in the pool. A thread whose address space did not follow it to the new CPU
// would read another space's memory there, or fault; one whose kernel stack did not follow
// it would take its next trap on the wrong stack.

/// The guarded stack the stress run's process thread runs on, claimed by [`stress_setup`].
static STRESS_STACK: AtomicUsize = AtomicUsize::new(usize::MAX);
/// Processes the stress run has created and destroyed.
static CYCLES: AtomicU64 = AtomicU64::new(0);

// A stress cycle judges its process by what the scheduler gave it, not by how long it
// waited. It used to give the process a fixed 80 ms of guest time on one CPU, and on a
// loaded host that window measured the host: under an emulator the guest's clock follows
// the host's, so a vCPU the host did not run still had its window run out, and the fixed-rate
// sleepers above the process took a larger share of what the vCPU did execute. The 20 s run
// on `x86_64-qemu` failed that way three times, each passing when rerun alone.

/// Slices a cycle's process thread may run, as the timer interrupt counts them
/// ([`preempt::slices`]), while making no progress. Its loop publishes a pass every few
/// instructions, so one slice is plenty in principle — but a slice is charged to whatever the
/// interrupt finds running, and a thread re-pinned to another CPU is charged for the interval
/// it spends being moved, queued and trapped there, without a pass to show for it.
///
/// Sixteen was below what a healthy run needs. A passing two-hour soak on `x86_64-qemu-smp`
/// at eight CPUs reported twenty slices for a wait that succeeded, and another failed at
/// 159 s with this bound on a host carrying two soaks. A 60-second run at eight CPUs on a
/// host at load 14 needed thirteen. A hundred and twenty-eight is over six times the worst
/// figure a healthy run has shown, and still a second and a third of CPU time without a pass
/// from a loop that publishes one every few instructions.
const RAN_SLICES: u64 = 128;

/// Slices it may be passed over for — ready on its CPU while a thread no more urgent runs
/// there — for each slice it ran, while making no progress. Round robin passes it over once
/// for each of the four busy workloads that share its level; sixty-four to one is a queue
/// that does not reach it. Per slice run, because a thread taking its turns among peers
/// reaches sixty-four passes at about the moment it reaches [`RAN_SLICES`]: counted alone,
/// a process that ran without advancing was reported as passed over.
const PASSED_SLICES: u64 = 64;

/// The longest a cycle waits when neither count reaches its bound, which only a thread that
/// neither runs nor is passed over can do: one that is blocked, queued on a CPU taking no
/// interrupts, or ready behind more urgent threads. Fixed priority allows that last, and
/// only its length tells a busy moment from starvation, so this one bound is still guest
/// time. It is sixty-two of the old windows, and a sixth of the thirty seconds kbuild allows
/// between heartbeats.
const STARVE_WAIT: Duration = Duration::from_nanos(5_000_000_000);

/// How often a wait looks.
const POLL: Duration = Duration::from_nanos(5_000_000);

/// How a wait by [`await_slices`] ended.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Waited {
    Done,
    /// It ran [`RAN_SLICES`] without making progress.
    Ran,
    /// It was passed over for [`PASSED_SLICES`] per slice it ran, without making progress.
    PassedOver,
    /// [`STARVE_WAIT`] passed with neither, carrying what it was given meanwhile: both zero
    /// means no interrupt on that CPU ever saw this thread, so nothing ran there at all.
    Starved {
        ran: u64,
        passed: u64,
    },
    /// The table has no such thread.
    Lost,
}

/// Wait until `done`, judging thread `id` meanwhile by the slices it is charged. `moving`
/// says whether it is making progress, which suspends that judgement: a thread that is
/// advancing, but has not yet done what is waited for, has only [`STARVE_WAIT`] to meet.
pub(crate) fn await_slices(
    id: ThreadId,
    mut done: impl FnMut() -> bool,
    mut moving: impl FnMut() -> bool,
) -> Waited {
    let Some(start) = preempt::slices(id) else {
        return Waited::Lost;
    };
    let give_up = timekeeping::now().saturating_add(STARVE_WAIT);
    loop {
        if done() {
            if let Some(now) = preempt::slices(id) {
                RAN_WORST.fetch_max(now.ran.wrapping_sub(start.ran), Ordering::Relaxed);
                PASSED_WORST.fetch_max(now.passed.wrapping_sub(start.passed), Ordering::Relaxed);
            }
            return Waited::Done;
        }
        // The counts before `moving`, so a count that reached its bound was reached with
        // no progress made up to the moment it was read.
        let Some(now) = preempt::slices(id) else {
            return Waited::Lost;
        };
        if !moving() {
            let ran = now.ran.wrapping_sub(start.ran);
            if ran >= RAN_SLICES {
                return Waited::Ran;
            }
            let passed = now.passed.wrapping_sub(start.passed);
            if passed >= PASSED_SLICES.saturating_mul(ran + 1) {
                return Waited::PassedOver;
            }
        }
        if timekeeping::now() >= give_up {
            return Waited::Starved {
                ran: now.ran.wrapping_sub(start.ran),
                passed: now.passed.wrapping_sub(start.passed),
            };
        }
        nap(POLL);
    }
}

/// The longest any cycle waited for its thread on the CPU it pinned it to.
static SERVE_WORST_NS: AtomicU64 = AtomicU64::new(0);

/// Waits that ran out with the thread charged nothing at all: no interrupt on its CPU saw
/// it, so the host was not running that CPU. Counted rather than failed, and reported in the
/// stress heartbeat.
static STARVED_ELSEWHERE: AtomicU64 = AtomicU64::new(0);

/// That count, for the stress heartbeat.
pub fn stress_starved_elsewhere() -> u64 {
    STARVED_ELSEWHERE.load(Ordering::Relaxed)
}

/// The most slices any wait by [`await_slices`] ran, and was passed over for, before it
/// succeeded: how close a passing run came to [`RAN_SLICES`] and [`PASSED_SLICES`].
static RAN_WORST: AtomicU64 = AtomicU64::new(0);
static PASSED_WORST: AtomicU64 = AtomicU64::new(0);

/// Those two counts, for the stress heartbeat.
pub fn stress_slices_worst() -> (u64, u64) {
    (RAN_WORST.load(Ordering::Relaxed), PASSED_WORST.load(Ordering::Relaxed))
}

/// That wait in microseconds, for the stress heartbeat.
pub fn stress_serve_worst_us() -> u64 {
    SERVE_WORST_NS.load(Ordering::Relaxed) / 1_000
}

/// Claim the stack the stress run's process thread runs on. Called once by the stress
/// run's setup, with interrupts masked.
pub fn stress_setup() -> Result<(), &'static str> {
    // SAFETY: see `POOL`; only its presence is read.
    if unsafe { (*POOL.get()).is_none() } {
        return Err("no frames were reserved for processes");
    }
    let stack =
        preempt::claim_stacks(&["process"]).ok_or("no guarded stack for a process thread")?;
    STRESS_STACK.store(stack, Ordering::Relaxed);
    Ok(())
}

pub fn stress_cycles() -> u64 {
    CYCLES.load(Ordering::Relaxed)
}

/// The stack [`stress_setup`] claimed, or `usize::MAX`. Free between cycles, which is when
/// `crate::waits`' stress cycle borrows it.
pub fn stress_stack() -> usize {
    STRESS_STACK.load(Ordering::Relaxed)
}

/// Point process frame operations at this module's pool. `false` if no pool was reserved.
/// For another stress cycle that builds processes, on the auditor's thread between cycles.
pub fn use_pool() -> bool {
    // SAFETY: see `POOL`; the auditor is the only thread building processes.
    match unsafe { (*POOL.get()).as_mut() } {
        Some(pool) => {
            userproc::set_frames(pool);
            true
        }
        None => false,
    }
}

/// Create, move and destroy one process; see the section comment. On the auditor's thread,
/// between audits. `round` picks which CPUs this cycle moves the thread between.
pub fn stress_cycle(round: u64) -> Result<(), &'static str> {
    let stack = STRESS_STACK.load(Ordering::Relaxed);
    if stack == usize::MAX {
        return Err("the process stack was never claimed");
    }
    // SAFETY: see `POOL`; the auditor is the only thread building processes.
    let pool = unsafe { (*POOL.get()).as_mut() }.ok_or("no frames were reserved for processes")?;
    let program = userproc::program().ok_or("the embedded init program does not load")?;
    userproc::set_frames(pool);
    let baseline = free_frames();

    let Some(root) = build_worker(0, &program) else {
        teardown_all();
        return Err("could not build a process");
    };
    ENTRY.store(program.entry as usize, Ordering::Relaxed);
    let Some(id) = spawn_on(WORKERS[0], root, stack) else {
        teardown_all();
        return Err("the process thread was refused");
    };
    let exercised = exercise(id, round);

    // Unpinned before it is told to stop, on every path. `exercise` pins the thread to one
    // CPU at a time and only unpins when it succeeds, so a failure part of the way through
    // used to leave the thread pinned: ready on a CPU busy with equal-priority workloads,
    // where the balancer may not move it, and never reading the stop word. The wait below
    // then failed, and its message hid the failure that really happened.
    let _ = preempt::set_affinity(id, u64::MAX);
    set_stop(0);
    let before = passes(0);
    if await_slices(id, || !preempt::alive(id), || false) != Waited::Done {
        // Its tables cannot be freed while it may still run on them. The run is failing
        // anyway; leaving the process is the only safe thing to do.
        //
        // What `exercise` found comes first: a thread that failed there is usually why it
        // is still here, and its message says what actually went wrong.
        exercised?;
        // Otherwise, which way it failed is the whole diagnosis, and a `&'static str`
        // cannot carry numbers, so the cases are separate messages: a thread still making
        // passes never saw the stop word, one that is ready and made none was never
        // scheduled, and a refused exit shows up in the scheduler's own record.
        let moving = passes(0) > before;
        return Err(match preempt::where_is(id) {
            _ if preempt::broken() != 0 => "a process did not stop: the scheduler refused it",
            Some((thread::State::Running, _)) if moving => {
                "a process did not stop: still running, and never read the stop word"
            }
            Some((thread::State::Running, _)) => "a process did not stop: running but stuck",
            Some((thread::State::Ready, _)) if moving => {
                "a process did not stop: ready, and ran without reading the stop word"
            }
            Some((thread::State::Ready, _)) => "a process did not stop: ready, never scheduled",
            Some((thread::State::Blocked, _)) => "a process did not stop: blocked",
            Some((thread::State::Exited, _)) => "a process did not stop: exited after the wait",
            None => "a process did not stop: the table lost its thread",
        });
    }
    let code = userproc::slot(WORKERS[0]).and_then(|p| p.exit);
    let _ = preempt::reap(id);
    teardown_all();
    CYCLES.fetch_add(1, Ordering::Relaxed);

    exercised?;
    if code != Some(WORKER_SUCCESS) {
        return Err("a process did not exit cleanly");
    }
    if free_frames() != baseline {
        return Err("a destroyed process did not give back every frame");
    }
    Ok(())
}

/// Move process thread `id` between two of the scheduling CPUs and check it on each.
fn exercise(id: ThreadId, round: u64) -> Result<(), &'static str> {
    let cpus = preempt::stats().cpus.max(1);
    if cpus < 2 {
        let before = passes(0);
        let moved = || passes(0) > before;
        match await_slices(id, moved, moved) {
            Waited::Done => {}
            Waited::Ran => return Err("a process ran its slices and made no progress"),
            Waited::PassedOver => {
                return Err("a process was passed over for its slices and made no progress");
            }
            Waited::Lost => return Err("a process made no progress: the table lost its thread"),
            // Neither count moved, and nothing at all was charged: no interrupt on this CPU
            // saw the thread, so nothing ran here. The host, not the scheduler.
            Waited::Starved { ran, passed } if ran == 0 && passed == 0 => {
                STARVED_ELSEWHERE.fetch_add(1, Ordering::Relaxed);
            }
            // Neither count reached its bound, so the state is the diagnosis.
            Waited::Starved { .. } => {
                return Err(match preempt::where_is(id) {
                    Some((thread::State::Running, _)) => {
                        "a process made no progress: running, and never charged a slice"
                    }
                    Some((thread::State::Ready, _)) => {
                        "a process made no progress: ready, behind more urgent threads"
                    }
                    Some((thread::State::Blocked, _)) => "a process made no progress: blocked",
                    Some((thread::State::Exited, _)) => "a process made no progress: it had exited",
                    None => "a process made no progress: the table lost its thread",
                });
            }
        }
    } else {
        let first = (round as usize) % cpus;
        for cpu in [first, (first + 1) % cpus] {
            if !preempt::set_affinity(id, 1 << cpu) {
                return Err("a process thread could not be moved");
            }
            userproc::clear_cpus(WORKERS[0]);
            let before = passes(0);
            // Waited for, not sampled once. How long a pinned thread takes to be served on
            // its new CPU is a scheduling delay, not a constant: it shares that CPU with
            // workloads of its own priority and only traps every so many passes. Two fixed
            // 80 ms windows used to stand in for that, which was enough to hide what went
            // wrong at eight CPUs behind "never served" — the real fault was a yield that
            // moved the thread without interrupting the CPU it moved to (`plan_yield`), so
            // an idle CPU slept through its arrival. With that fixed the worst wait any
            // cycle has taken is about 13 ms, reported in the heartbeat, so this bound is
            // measured rather than guessed.
            //
            // The wait is now judged in slices (see `RAN_SLICES`): a thread that ran or was
            // passed over for its share without moving fails at once, and only one that did
            // neither waits out `STARVE_WAIT`.
            let start = timekeeping::now();
            let served = || userproc::cpus(WORKERS[0]) & (1 << cpu) != 0;
            let waited = await_slices(id, || served() && passes(0) > before, || passes(0) > before);
            match waited {
                Waited::Done => {}
                Waited::Ran => {
                    return Err("a process ran its slices after it moved and made no progress");
                }
                Waited::PassedOver => {
                    return Err(
                        "never served: passed over for its slices on the CPU it was pinned to",
                    );
                }
                Waited::Lost => return Err("never served: the table lost its thread"),
                Waited::Starved { ran, passed } if ran == 0 && passed == 0 => {
                    // Not one timer interrupt on that CPU found this thread, ready or
                    // running, in five seconds: nothing ran there, which is the host and not
                    // the scheduler. Counted and reported rather than failed.
                    STARVED_ELSEWHERE.fetch_add(1, Ordering::Relaxed);
                }
                Waited::Starved { .. } => {
                    if served() {
                        return Err("a process stopped making progress after it moved");
                    }
                    // Where it is says which half failed: a thread the table never moved to
                    // the CPU it was pinned to is a placement bug, while one sitting there
                    // unserved is a scheduling or trap-rate problem. A `&'static str`
                    // carries no numbers, so the cases are separate messages.
                    let here = preempt::where_is(id).map(|(s, on)| (s, on == Some(cpu)));
                    return Err(match here {
                        Some((thread::State::Running, true)) => {
                            "never served: running on the CPU it was pinned to, but never trapped"
                        }
                        Some((thread::State::Running, false)) => {
                            "never served: still running on a CPU its affinity excludes"
                        }
                        Some((thread::State::Ready, true)) => {
                            "never served: ready on the right CPU, never scheduled"
                        }
                        Some((thread::State::Ready, false)) => {
                            "never served: ready on a CPU its affinity excludes"
                        }
                        Some((thread::State::Blocked, _)) => "never served: blocked",
                        Some((thread::State::Exited, _)) => "never served: it had exited",
                        None => "never served: the table lost its thread",
                    });
                }
            }
            let waited = timekeeping::now().saturating_duration_since(start);
            SERVE_WORST_NS.fetch_max(waited.as_nanos(), Ordering::Relaxed);
        }
        let _ = preempt::set_affinity(id, u64::MAX);
    }
    if shared_word(0, W_SEEN) != SIGNATURE[0] {
        return Err("a process read memory that was not its own");
    }
    Ok(())
}

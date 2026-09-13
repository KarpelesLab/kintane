//! Preemptive kernel threads on the real machine, and the check that preemption happens.
//!
//! Four threads join the boot thread in one table, under a fixed-priority policy:
//!
//! | thread | priority | does |
//! |---|---|---|
//! | boot | 10 | spawns the rest, sleeps until the demo ends, then judges it |
//! | high | 8 | runs once, sleeps five ticks, records when it woke, exits |
//! | worker A, B | 4 | count in a busy loop that **never yields**, until tick 25 |
//! | idle | 0 | waits for an interrupt whenever nothing else can run |
//!
//! # How preemption works
//!
//! The timer interrupt calls [`on_tick`] after acknowledging the tick. It wakes every
//! sleeper whose deadline has passed and then calls `Threads::yield_now` on behalf of
//! whatever thread it interrupted. That is the whole mechanism. A woken thread of higher
//! priority takes the CPU at once, and a peer at the same level takes its turn. The
//! switch happens inside the interrupt handler, so each suspended thread's interrupt
//! frame stays on its own stack, and the thread resumes by returning through that
//! handler. Why that is sound, including EOI ordering and the interrupt mask across the
//! switch, is written down in each port's `tick` module, where it has to stay true.
//!
//! Every access to the table is made with interrupts masked. The tick hook runs masked
//! because it is an interrupt handler, and thread code masks explicitly. On one CPU that
//! is mutual exclusion, and no reference into the table is held across a switch (see
//! the `thread` crate).
//!
//! # What the check proves, and how it fails instead of hanging
//!
//! * **Round robin under preemption.** The first worker to finish records the other's count.
//!   Neither worker yields, so a non-zero count can only mean the timer took the CPU away from the
//!   first worker while it was still busy.
//! * **Priority.** `high` is spawned *after* the workers, so if its priority did not matter, the
//!   queue order would put it behind them. It must run before either has counted anything. When the
//!   tick wakes it, it must run on that same tick while both workers are still busy, which again
//!   only preemption can arrange.
//! * **Ticks keep arriving across switches.** Each worker records its longest stretch of spins
//!   during which the tick counter did not move. It must stay within eight ticks' worth, measured
//!   against a spin rate calibrated just before the threads start. This is what an EOI sent *after*
//!   the switch breaks: the preempting thread would get no tick of its own, yet the round-robin and
//!   priority evidence could still look right, because the thread it preempted eventually resumes
//!   and acknowledges.
//! * **Idle.** The idle thread must have waited and been woken, and no more often than ticks
//!   elapsed. The tick is the only enabled interrupt, so an idle loop that spun instead of halting
//!   would count far more wake-ups than that.
//!
//! No wait depends on the scheduler behaving. The workers stop at tick 25 or after 50
//! ticks' worth of calibrated spins, whichever comes first. The spin cap is what keeps a
//! thread that cannot receive ticks, because it never unmasked or its tick was never
//! acknowledged, from spinning forever. Everything after the workers waits for a tick,
//! and idle unmasks and waits for exactly that. With preemption disabled, the first
//! worker keeps the CPU until tick 25, the rest run in queue order, and idle's own yield
//! hands the CPU back to boot once the boot thread's wake-up tick has passed. The check
//! completes and reports FAILED. The timer itself is proved, with its EOI, by the
//! interrupt selftest that runs earlier; this check does not run when that failed, and
//! calibration fails rather than waits if no tick arrives.

use core::cell::{SyncUnsafeCell, UnsafeCell};
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use arch::Cpu;
use hal::{Arch, EarlyConsole, KernAddr};
use sched::{Priority, ThreadId};
use thread::Threads;

use crate::{Check, write_usize};

/// Boot, idle, high, two workers, and one spare slot.
const SLOTS: usize = 6;

/// Scheduler tick rate. Slow enough that a TCG-emulated tick does not dominate the CPU,
/// fast enough that the whole check takes about a third of a second.
const HZ: u32 = 100;

/// Tick schedule, counted from the tick the check starts on.
const HIGH_WAKES_AT: u64 = 5;
const WORKERS_STOP_AT: u64 = 25;
const BOOT_WAKES_AT: u64 = 30;

/// `high` must be running within this many ticks of its wake-up tick. It is woken and
/// switched to by the same interrupt, so 0 is expected; 1 tolerates a tick landing
/// between the wake and the record.
const MAX_WAKE_LATENCY: u64 = 1;

/// Ticks the spin rate is calibrated over, starting on a tick edge.
const CALIBRATION_TICKS: u64 = 2;
/// Absolute bound on each calibration loop. Reached only if the timer is not ticking,
/// which the interrupt selftest has already ruled out; it exists so that is reported.
const CALIBRATION_CAP: u64 = 1 << 32;
/// A worker stops after this many ticks' worth of spins even if the tick never reaches
/// `WORKERS_STOP_AT`. Twice the whole window, so with ticks arriving it is never the
/// reason a worker stops.
const SPIN_CAP_TICKS: u64 = 2 * WORKERS_STOP_AT;
/// The longest a worker may spin, in ticks' worth, without seeing the tick counter move.
/// About one is expected, since a worker that is preempted sees the counter moved when
/// it resumes. Under QEMU it reads as up to two, because calibration measured the loop
/// 25–35% slower than the workers then ran it. Eight leaves room for that and for
/// jitter, and is still far below the fifty a thread that receives no ticks spins before
/// its cap stops it.
const MAX_TICKLESS_TICKS: u64 = 8;

const BOOT_PRIORITY: u8 = 10;
const HIGH_PRIORITY: u8 = 8;
const WORKER_PRIORITY: u8 = 4;

/// Stack size for each spawned thread. Deep enough for an interrupt frame, the handler's
/// Rust frames and the scheduler on top of a thread's own frames.
const STACK_BYTES: usize = 16 * 1024;

/// A thread stack in `.bss`. `align(16)` and a multiple-of-16 size put the top on the
/// strictest alignment any port asks for, although `init` does not rely on it.
///
/// No guard page. Stacks with guard pages need the kernel address space to be live,
/// which is separate work; until then these are like the #DF stack and the context
/// switch selftest's stack.
#[repr(C, align(16))]
struct Stack(UnsafeCell<[u8; STACK_BYTES]>);

// SAFETY: never read or written from Rust, only its address is taken. Each stack is
// handed to exactly one thread by `demonstrate`, which runs once (`STARTED`).
unsafe impl Sync for Stack {}

static STACKS: [Stack; 4] = [const { Stack(UnsafeCell::new([0; STACK_BYTES])) }; 4];

/// The scheduler state: the thread table and who is sleeping until when.
struct Sched {
    threads: Threads<Cpu, SLOTS>,
    sleepers: [Option<(ThreadId, u64)>; SLOTS],
}

/// SAFETY INVARIANT: written once by `demonstrate` before the tick starts, and from then
/// on accessed only with interrupts masked, on one CPU, through short-lived references
/// that never span a switch. `Threads` holds a thread's `Context`, which cannot be
/// constructed in a `const`, hence `MaybeUninit`.
static SCHED: SyncUnsafeCell<MaybeUninit<Sched>> = SyncUnsafeCell::new(MaybeUninit::uninit());

/// Set by the first run. A second would re-`init` stacks a suspended thread still owns.
static STARTED: AtomicBool = AtomicBool::new(false);

/// The tick the check started on.
static START: AtomicU64 = AtomicU64::new(0);

// Evidence, written by the threads and read by boot once they have finished.
static COUNT: [AtomicU64; 2] = [const { AtomicU64::new(0) }; 2];
/// The other worker's count, as each worker saw it when it finished.
static SAW_OTHER: [AtomicU64; 2] = [const { AtomicU64::new(0) }; 2];
static DONE: [AtomicBool; 2] = [const { AtomicBool::new(false) }; 2];
/// Each worker's longest run of spins without the tick counter moving.
static LONGEST_TICKLESS: [AtomicU64; 2] = [const { AtomicU64::new(0) }; 2];
/// The workers' loop's spins per tick, calibrated by boot before the threads start.
static SPINS_PER_TICK: AtomicU64 = AtomicU64::new(0);
/// Both workers' counts added together, when `high` first ran. `u64::MAX` until it does.
static HIGH_FIRST_SAW: AtomicU64 = AtomicU64::new(u64::MAX);
/// The tick `high` resumed on after sleeping. `u64::MAX` until it does.
static HIGH_WOKE_AT: AtomicU64 = AtomicU64::new(u64::MAX);
/// Whether both workers were still busy when `high` resumed.
static HIGH_PREEMPTED_WORKERS: AtomicBool = AtomicBool::new(false);
static IDLE_WAKES: AtomicU64 = AtomicU64::new(0);
/// Times a thread was suspended by the tick and later resumed.
static PREEMPTIONS: AtomicU64 = AtomicU64::new(0);

/// Things that went wrong where nothing could report them, as a bitmask of `BROKE_*`.
static BROKEN: AtomicU32 = AtomicU32::new(0);
const BROKE_INVARIANT: u32 = 1 << 0;
const BROKE_WAKE: u32 = 1 << 1;
const BROKE_YIELD: u32 = 1 << 2;
const BROKE_SLEEP: u32 = 1 << 3;
const BROKE_EXIT: u32 = 1 << 4;

fn broke(what: u32) {
    BROKEN.fetch_or(what, Ordering::Relaxed);
}

fn sched() -> *mut Sched {
    SCHED.get().cast::<Sched>()
}

fn threads() -> *mut Threads<Cpu, SLOTS> {
    // SAFETY: a field projection through the raw pointer, forming no reference. `SCHED`
    // is initialised before any caller runs (see its invariant).
    unsafe { &raw mut (*sched()).threads }
}

/// The timer interrupt's hook: wake whoever is due, then preempt.
fn on_tick() {
    let now = arch::tick::ticks();
    {
        // SAFETY: interrupt context, so interrupts are masked, and by `SCHED`'s invariant
        // no other reference to it is live. This one ends with the block, before the
        // switch below.
        let s = unsafe { &mut *sched() };
        for slot in s.sleepers.iter_mut() {
            if let Some((id, at)) = *slot
                && at <= now
            {
                *slot = None;
                if s.threads.wake(id).is_err() {
                    broke(BROKE_WAKE);
                }
            }
        }
        if s.threads.check().is_err() {
            broke(BROKE_INVARIANT);
        }
    }

    // SAFETY: masked, no reference into the table is live, and every thread's stack is a
    // static in `STACKS` (or the boot stack), so `yield_now`'s contract holds.
    if unsafe { Threads::yield_now(threads()) }.is_err() {
        broke(BROKE_YIELD);
    }
    // Only a thread that was switched away and later switched back sees the clock move
    // inside one call.
    if arch::tick::ticks() != now {
        PREEMPTIONS.fetch_add(1, Ordering::Relaxed);
    }
}

/// Block the calling thread until the tick numbered `at`.
fn sleep_until(at: u64) {
    let irq = Cpu::irq_save();
    {
        // SAFETY: masked; the reference ends with the block, before `block` switches.
        let s = unsafe { &mut *sched() };
        let me = s.threads.current();
        match s.sleepers.iter_mut().find(|slot| slot.is_none()) {
            Some(slot) => *slot = Some((me, at)),
            None => broke(BROKE_SLEEP),
        }
    }
    // SAFETY: as in `on_tick`.
    if unsafe { Threads::block(threads()) }.is_err() {
        broke(BROKE_SLEEP);
    }
    // SAFETY: pairs with the `irq_save` above, on this thread.
    unsafe { Cpu::irq_restore(irq) };
}

/// End the calling thread.
fn exit_thread() -> ! {
    let _ = Cpu::irq_save();
    // SAFETY: as in `on_tick`.
    let _ = unsafe { Threads::exit(threads()) };
    // Only reached if the exit was refused, which with an idle thread cannot happen.
    // Recorded and left for the tick to preempt, rather than halted, so the check still
    // finishes and reports it.
    broke(BROKE_EXIT);
    loop {
        // SAFETY: interrupts are masked here, which is what this wants; the timer has a
        // handler.
        unsafe { arch::tick::wait_for_interrupt() };
        let _ = Cpu::irq_save();
    }
}

/// The first thing every thread but idle does.
///
/// A new thread is entered through a switch, and switches happen with interrupts masked,
/// so it starts masked. Nothing in `init` or the trampoline changes that. A thread that
/// never enabled them would never be preempted, and would pass for one that could not
/// be.
fn begin() {
    // SAFETY: the vector table is installed and the only enabled line is the timer,
    // whose handler is `on_tick`. A thread's entry is not inside any masked region.
    unsafe { arch::tick::enable_interrupts() };
}

/// What one busy loop observed.
struct Spun {
    spins: u64,
    /// The longest run of consecutive spins during which the tick counter did not move.
    longest_tickless: u64,
}

/// Count on `counter` until tick `until` or `cap` spins, whichever comes first.
///
/// Calibration and the workers share this one function, and it is never inlined, so the
/// rate calibration measures is the rate of the code the workers run.
#[inline(never)]
fn spin(counter: &AtomicU64, until: u64, cap: u64) -> Spun {
    let mut last = arch::tick::ticks();
    let (mut spins, mut run, mut longest) = (0, 0, 0);
    while spins < cap {
        let now = arch::tick::ticks();
        if now >= until {
            break;
        }
        if now == last {
            run += 1;
            longest = longest.max(run);
        } else {
            last = now;
            run = 0;
        }
        counter.fetch_add(1, Ordering::Relaxed);
        spins += 1;
    }
    Spun {
        spins,
        longest_tickless: longest,
    }
}

/// Spins of [`spin`]'s loop per tick, or 0 if the timer did not tick.
///
/// Measured on the boot thread with interrupts briefly enabled and no hook installed.
fn calibrate() -> u64 {
    static SCRATCH: AtomicU64 = AtomicU64::new(0);
    // SAFETY: the vector table is installed and the only enabled line is the timer,
    // with no hook registered yet. The caller holds interrupts masked and gets them back
    // masked from the `irq_save` below, which is the state it saved.
    unsafe { arch::tick::enable_interrupts() };
    let t0 = arch::tick::ticks();
    // Start on a tick edge, so the measured span is whole ticks.
    let _ = spin(&SCRATCH, t0 + 1, CALIBRATION_CAP);
    let end = t0 + 1 + CALIBRATION_TICKS;
    let spun = spin(&SCRATCH, end, CALIBRATION_CAP);
    let reached = arch::tick::ticks() >= end;
    let _ = Cpu::irq_save();
    if reached {
        spun.spins / CALIBRATION_TICKS
    } else {
        0
    }
}

extern "C" fn worker(which: usize) -> ! {
    begin();
    let stop = START.load(Ordering::Relaxed) + WORKERS_STOP_AT;
    let cap = SPINS_PER_TICK.load(Ordering::Relaxed) * SPIN_CAP_TICKS;
    // Never yields. Getting past this loop in turn with the other worker is only
    // possible if the timer takes the CPU away.
    let spun = spin(&COUNT[which], stop, cap);
    LONGEST_TICKLESS[which].store(spun.longest_tickless, Ordering::Relaxed);
    SAW_OTHER[which].store(COUNT[1 - which].load(Ordering::Relaxed), Ordering::Relaxed);
    DONE[which].store(true, Ordering::Relaxed);
    exit_thread()
}

extern "C" fn high(_: usize) -> ! {
    begin();
    let counted = COUNT[0].load(Ordering::Relaxed) + COUNT[1].load(Ordering::Relaxed);
    HIGH_FIRST_SAW.store(counted, Ordering::Relaxed);

    sleep_until(START.load(Ordering::Relaxed) + HIGH_WAKES_AT);

    HIGH_WOKE_AT.store(arch::tick::ticks(), Ordering::Relaxed);
    let busy = !DONE[0].load(Ordering::Relaxed) && !DONE[1].load(Ordering::Relaxed);
    HIGH_PREEMPTED_WORKERS.store(busy, Ordering::Relaxed);
    exit_thread()
}

/// Runs whenever nothing else can: offer the CPU, and otherwise halt until an interrupt.
///
/// Idle stays masked except while it waits, so checking for work and halting cannot be
/// split by the interrupt that brings the work.
extern "C" fn idle(_: usize) -> ! {
    loop {
        // SAFETY: masked (a new thread starts masked, and the loop re-masks), as in
        // `on_tick` otherwise.
        if unsafe { Threads::yield_now(threads()) }.is_err() {
            broke(BROKE_YIELD);
        }
        // SAFETY: masked on entry, as `wait_for_interrupt` requires; the timer has a
        // handler.
        unsafe { arch::tick::wait_for_interrupt() };
        IDLE_WAKES.fetch_add(1, Ordering::Relaxed);
        let _ = Cpu::irq_save();
    }
}

fn priority(level: u8) -> Priority {
    // Every constant above is below `sched::LEVELS`; this is not reachable with them.
    Priority::new(level).unwrap_or(Priority::IDLE)
}

/// Run the threads and judge the result. Called once, from `kmain`, with interrupts
/// masked, after the interrupt and context switch selftests have passed.
pub fn demonstrate(c: &dyn EarlyConsole) -> Check {
    if STARTED.swap(true, Ordering::Relaxed) {
        c.write_str("already run");
        return Check::Failed;
    }
    let irq = Cpu::irq_save();

    // SAFETY: the only write to `SCHED`, before the tick starts and before any other
    // thread exists (see its invariant).
    unsafe {
        SCHED.get().write(MaybeUninit::new(Sched {
            threads: Threads::new(priority(BOOT_PRIORITY)),
            sleepers: [None; SLOTS],
        }));
    }

    // Workers before `high`, so that `high` running first is the priority's doing and not
    // the queue order's.
    let plan: [(extern "C" fn(usize) -> !, usize, u8); 4] = [
        (idle, 0, Priority::IDLE.level()),
        (worker, 0, WORKER_PRIORITY),
        (worker, 1, WORKER_PRIORITY),
        (high, 0, HIGH_PRIORITY),
    ];
    for ((entry, arg, level), stack) in plan.into_iter().zip(&STACKS) {
        let top = KernAddr::new(stack.0.get() as usize + STACK_BYTES);
        // SAFETY: masked and single-threaded, so this reference to the table is the only
        // one. `top` is the end of a static 16 KiB stack used by nothing else, mapped
        // read-write, and `STARTED` guarantees no earlier thread is suspended on it.
        let spawned = unsafe { (*threads()).spawn(entry, arg, priority(level), top, STACK_BYTES) };
        if spawned.is_err() {
            c.write_str("spawn refused");
            // SAFETY: pairs with the `irq_save` above.
            unsafe { Cpu::irq_restore(irq) };
            return Check::Failed;
        }
    }

    // SAFETY: masked, and nothing else programs the timer while the check runs.
    let hz = unsafe { arch::tick::start(HZ) };
    let per_tick = if hz == 0 { 0 } else { calibrate() };
    if per_tick == 0 {
        arch::tick::stop();
        c.write_str(if hz == 0 {
            "no timer to preempt with"
        } else {
            "timer did not tick during calibration"
        });
        // SAFETY: pairs with the `irq_save` above.
        unsafe { Cpu::irq_restore(irq) };
        return Check::Failed;
    }
    SPINS_PER_TICK.store(per_tick, Ordering::Relaxed);

    arch::tick::set_hook(Some(on_tick));
    let start = arch::tick::ticks();
    START.store(start, Ordering::Relaxed);

    // The boot thread's part: nothing, until the rest are done.
    sleep_until(start + BOOT_WAKES_AT);

    arch::tick::stop();
    arch::tick::set_hook(None);
    let elapsed = arch::tick::ticks() - start;

    // Every thread but idle has exited by now; give their slots back and let the table
    // check itself in its final state.
    let table_ok = {
        // SAFETY: masked, the tick is stopped, and this is the only reference.
        let t = unsafe { &mut *threads() };
        let reaped = (2..=4).all(|id| t.reap(ThreadId::new(id)).is_ok());
        reaped && t.check().is_ok()
    };
    // SAFETY: pairs with the `irq_save` above.
    unsafe { Cpu::irq_restore(irq) };

    report(c, hz, elapsed, table_ok)
}

fn report(c: &dyn EarlyConsole, hz: u32, elapsed: u64, table_ok: bool) -> Check {
    let load = |a: &AtomicU64| a.load(Ordering::Relaxed);
    let start = START.load(Ordering::Relaxed);
    let counts = [load(&COUNT[0]), load(&COUNT[1])];
    let saw = [load(&SAW_OTHER[0]), load(&SAW_OTHER[1])];
    let broken = BROKEN.load(Ordering::Relaxed);

    let round_robin = saw[0] > 0 && saw[1] > 0;
    let high_first = load(&HIGH_FIRST_SAW) == 0;
    let woke_at = load(&HIGH_WOKE_AT);
    let wake_tick = start + HIGH_WAKES_AT;
    let latency = woke_at.saturating_sub(wake_tick);
    let prompt = woke_at != u64::MAX
        && latency <= MAX_WAKE_LATENCY
        && HIGH_PREEMPTED_WORKERS.load(Ordering::Relaxed);
    let idled = load(&IDLE_WAKES) > 0 && load(&IDLE_WAKES) <= elapsed;
    let per_tick = load(&SPINS_PER_TICK);
    let tickless = [load(&LONGEST_TICKLESS[0]), load(&LONGEST_TICKLESS[1])];
    let ticks_kept_coming = tickless.iter().all(|&t| t <= per_tick * MAX_TICKLESS_TICKS);

    write_usize(c, SLOTS - 1);
    c.write_str(" threads at ");
    write_usize(c, hz as usize);
    c.write_str(" Hz for ");
    write_usize(c, elapsed as usize);
    c.write_str(" ticks: ");
    write_usize(c, load(&PREEMPTIONS) as usize);
    c.write_str(" preemptions, idle woke ");
    write_usize(c, load(&IDLE_WAKES) as usize);
    c.write_str(" times");
    if !idled {
        c.write_str(" BUT DID NOT HALT UNTIL AN INTERRUPT");
    }

    c.write_str("\n             round robin: ");
    write_usize(c, counts[0] as usize);
    c.write_str(" and ");
    write_usize(c, counts[1] as usize);
    c.write_str(" spins, never yielding; ");
    c.write_str(if round_robin {
        "each saw the other run"
    } else {
        "NOT INTERLEAVED"
    });

    c.write_str("\n             priority:    ");
    c.write_str(if high_first {
        "high ran first, "
    } else {
        "HIGH DID NOT RUN FIRST, "
    });
    if woke_at == u64::MAX {
        c.write_str("NEVER WOKE");
    } else {
        c.write_str("woke ");
        write_usize(c, latency as usize);
        c.write_str(" ticks late ");
        c.write_str(if HIGH_PREEMPTED_WORKERS.load(Ordering::Relaxed) {
            "over busy workers"
        } else {
            "AFTER THE WORKERS FINISHED"
        });
    }

    c.write_str("\n             ticks:       longest without one ");
    write_usize(c, tickless[0].div_ceil(per_tick) as usize);
    c.write_str(" and ");
    write_usize(c, tickless[1].div_ceil(per_tick) as usize);
    c.write_str(" ticks' worth of spins (");
    write_usize(c, per_tick as usize);
    c.write_str(" per tick, limit ");
    write_usize(c, MAX_TICKLESS_TICKS as usize);
    c.write_str(")");
    if !ticks_kept_coming {
        c.write_str(" A THREAD STOPPED RECEIVING TICKS");
    }

    if !table_ok {
        c.write_str("\n             thread table INCONSISTENT after the run");
    }
    if broken != 0 {
        c.write_str("\n             BROKEN:");
        for (bit, name) in ["invariant", "wake", "yield", "sleep", "exit"]
            .iter()
            .enumerate()
        {
            if broken & (1 << bit) != 0 {
                c.write_str(" ");
                c.write_str(name);
            }
        }
    }

    Check::from_ok(
        round_robin
            && high_first
            && prompt
            && ticks_kept_coming
            && idled
            && table_ok
            && broken == 0,
    )
}

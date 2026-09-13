//! Preemptive kernel threads on the real machine, and the check that preemption happens.
//!
//! Four threads join the boot thread in one table, under a fixed-priority policy:
//!
//! | thread | priority | does |
//! |---|---|---|
//! | boot | 10 | spawns the rest, sleeps, stops the workers, sleeps, then judges it |
//! | high | 8 | runs once, sleeps 50 ms, records when it woke, exits |
//! | worker A, B | 4 | count in a busy loop that **never yields**, until boot stops them |
//! | idle | 0 | waits for an interrupt whenever nothing else can run |
//!
//! Then the same threads run the checks of the kernel's shared state in `shared`.
//!
//! # How preemption works
//!
//! There is no periodic tick. The timer interrupt is a one-shot, which [`on_tick`] arms
//! again each time it runs (see `timekeeping`). It wakes every sleeper whose timer
//! expired, arms the next interrupt, and then calls `Threads::yield_now` on behalf of
//! whatever thread it interrupted. That is the whole mechanism. A woken thread of higher
//! priority takes the CPU at once, and a peer at the same level takes its turn. The
//! switch happens inside the interrupt handler, so each suspended thread's interrupt
//! frame stays on its own stack, and the thread resumes by returning through that
//! handler. Why that is sound, including EOI ordering and the interrupt mask across the
//! switch, is written down in each port's `tick` module, where it has to stay true.
//!
//! The next interrupt is the earliest timer, or the end of a [`SLICE`] if a thread is
//! waiting for the CPU (`Threads::contended`). A thread about to block cannot know who
//! runs next, so it arms a slice. The idle thread arms only for the earliest timer
//! before it halts. That is where tickless pays: an idle CPU is not woken to find it has
//! nothing to do.
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
//!   queue order would put it behind them. It must run before either has counted anything. When its
//!   timer wakes it, it must run within [`MAX_WAKE_LATENCY`] of the deadline while both workers are
//!   still busy, which again only preemption can arrange.
//! * **Interrupts keep arriving across switches.** Each worker records its longest stretch of spins
//!   during which the interrupt counter did not move. It must stay within eight slices' worth,
//!   measured against a spin rate calibrated just before the threads start. This is what an EOI
//!   sent *after* the switch breaks: the preempting thread would get no interrupt of its own, yet
//!   the round-robin and priority evidence could still look right, because the thread it preempted
//!   eventually resumes and acknowledges.
//! * **Idle.** The idle thread must have waited, and no more often than interrupts arrived, plus
//!   the wait still in progress. The timer is the only enabled interrupt, so an idle loop that spun
//!   instead of halting would count far more waits than that.
//!
//! No wait depends on the scheduler behaving. The workers stop when boot tells them or
//! after 50 slices' worth of calibrated spins, whichever comes first. The spin cap is
//! what keeps a thread that cannot receive interrupts, because it never unmasked or its
//! interrupt was never acknowledged, from spinning forever. Everything after the workers
//! waits for a timer, and idle unmasks and waits for exactly that. With preemption
//! disabled, the first worker keeps the CPU until its cap, the rest run in queue order,
//! and the check completes and reports FAILED. The timer itself is proved, with its EOI,
//! by the interrupt selftest that runs earlier; this check does not run when that
//! failed, and calibration fails rather than waits if no interrupt arrives.

use core::cell::SyncUnsafeCell;
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};

use arch::Cpu;
use hal::{Arch, EarlyConsole, KernAddr};
use sched::{Priority, ThreadId};
use thread::Threads;
use time::{Duration, Instant};

use crate::{Check, kheap, shared, timekeeping, write_usize};

/// Boot, idle, high, two workers, and one spare slot.
pub const SLOTS: usize = 6;

/// How long a thread runs before a waiting peer gets the CPU. Long enough that a
/// TCG-emulated interrupt does not dominate the CPU, short enough that the check takes
/// about a third of a second.
pub const SLICE: Duration = Duration::from_nanos(10_000_000);

/// Schedule, measured from the instant the check starts.
const HIGH_WAKES_AFTER: Duration = Duration::from_nanos(50_000_000);
const WORKERS_STOP_AFTER: Duration = Duration::from_nanos(250_000_000);
const BOOT_WAKES_AFTER: Duration = Duration::from_nanos(300_000_000);

/// `high` must be running within this long of its deadline. Its timer interrupt wakes it
/// and switches to it, so microseconds are expected; two slices tolerate an emulator that
/// delivers the interrupt late.
const MAX_WAKE_LATENCY: Duration = Duration::from_nanos(2 * SLICE.as_nanos());

/// Interrupts the spin rate is calibrated over, starting on an interrupt edge.
const CALIBRATION_TICKS: u64 = 2;
/// Absolute bound on each calibration loop. Reached only if the timer is not ticking,
/// which the interrupt selftest has already ruled out; it exists so that is reported.
const CALIBRATION_CAP: u64 = 1 << 32;
/// A worker stops after this many slices' worth of spins even if boot never stops it.
/// Twice the whole window, so with interrupts arriving it is never the reason a worker
/// stops.
const SPIN_CAP_TICKS: u64 = 2 * WORKERS_STOP_AFTER.as_nanos() / SLICE.as_nanos();
/// The longest a worker may spin, in slices' worth, without seeing the interrupt counter
/// move. About one is expected, since a worker that is preempted sees the counter moved
/// when it resumes. Under QEMU it reads as up to two, because calibration measured the
/// loop 25–35% slower than the workers then ran it. Eight leaves room for that and for
/// jitter, and is still far below the fifty a thread that receives no interrupts spins
/// before its cap stops it.
const MAX_TICKLESS_TICKS: u64 = 8;

const BOOT_PRIORITY: u8 = 10;
const HIGH_PRIORITY: u8 = 8;
const WORKER_PRIORITY: u8 = 4;

/// The guarded stacks the scheduler's threads run on, `(top, size)`, claimed from the
/// port's thread-stack array once, by `demonstrate`. A slot is reused by `spawn` after
/// its previous thread is reaped, so a guard-page report names the slot's first owner
/// rather than whichever later check is running on it.
///
/// Written only by boot with interrupts masked, before any thread is spawned on the slot.
static STACKS: [(AtomicUsize, AtomicUsize); THREAD_STACKS] =
    [const { (AtomicUsize::new(0), AtomicUsize::new(0)) }; THREAD_STACKS];

/// How many guarded slots the scheduler holds. The port reserves eight; test modes that
/// overflow a thread stack claim theirs after these.
const THREAD_STACKS: usize = 4;

/// The scheduler state: the thread table.
struct Sched {
    threads: Threads<Cpu, SLOTS>,
}

/// SAFETY INVARIANT: written once by `demonstrate` before the timer starts, and from then
/// on accessed only with interrupts masked, on one CPU, through short-lived references
/// that never span a switch. `Threads` holds a thread's `Context`, which cannot be
/// constructed in a `const`, hence `MaybeUninit`.
static SCHED: SyncUnsafeCell<MaybeUninit<Sched>> = SyncUnsafeCell::new(MaybeUninit::uninit());

/// Set by the first run. A second would re-`init` stacks a suspended thread still owns.
static STARTED: AtomicBool = AtomicBool::new(false);

/// The instant the check started, in nanoseconds.
static START: AtomicU64 = AtomicU64::new(0);

// Evidence, written by the threads and read by boot once they have finished.
static COUNT: [AtomicU64; 2] = [const { AtomicU64::new(0) }; 2];
/// The other worker's count, as each worker saw it when it finished.
static SAW_OTHER: [AtomicU64; 2] = [const { AtomicU64::new(0) }; 2];
static DONE: [AtomicBool; 2] = [const { AtomicBool::new(false) }; 2];
/// Set by boot when the workers' time is up.
static STOP_WORKERS: AtomicBool = AtomicBool::new(false);
/// Each worker's longest run of spins without the interrupt counter moving.
static LONGEST_TICKLESS: [AtomicU64; 2] = [const { AtomicU64::new(0) }; 2];
/// The workers' loop's spins per slice, calibrated by boot before the threads start.
static SPINS_PER_TICK: AtomicU64 = AtomicU64::new(0);
/// Both workers' counts added together, when `high` first ran. `u64::MAX` until it does.
static HIGH_FIRST_SAW: AtomicU64 = AtomicU64::new(u64::MAX);
/// The instant `high` resumed at after sleeping, in nanoseconds. `u64::MAX` until it does.
static HIGH_WOKE_AT: AtomicU64 = AtomicU64::new(u64::MAX);
/// Whether both workers were still busy when `high` resumed.
static HIGH_PREEMPTED_WORKERS: AtomicBool = AtomicBool::new(false);
/// Times idle halted to wait for an interrupt.
static IDLE_WAITS: AtomicU64 = AtomicU64::new(0);
/// Times a thread was suspended by the timer interrupt and later resumed.
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

/// The timer interrupt's hook: wake whoever is due, arm the next interrupt, then
/// preempt.
fn on_tick() {
    let interrupts = arch::tick::ticks();
    // Interrupt context until the switch: the thread a switch resumes is not in it.
    kheap::irq_enter();
    let now = timekeeping::now();
    let contended = {
        // SAFETY: interrupt context, so interrupts are masked, and by `SCHED`'s invariant
        // no other reference to it is live. This one ends with the block, before the
        // switch below. The timer lock is taken and released inside it; the table is not
        // a lock, so there is no order between them to get wrong.
        let s = unsafe { &mut *sched() };
        let woke = timekeeping::with_timers(|q| {
            let mut all = true;
            while let Some(expired) = q.pop_expired(now) {
                all &= s.threads.wake(expired.payload).is_ok();
            }
            all
        });
        if woke != Some(true) {
            broke(BROKE_WAKE);
        }
        if s.threads.check().is_err() {
            broke(BROKE_INVARIANT);
        }
        s.threads.contended()
    };
    shared::from_interrupt();
    // SAFETY: interrupt context, so masked.
    unsafe { timekeeping::program(contended.then_some(SLICE)) };
    kheap::irq_exit();

    // SAFETY: masked, no reference into the table is live, and every thread's stack is a
    // static in `STACKS` (or the boot stack), so `yield_now`'s contract holds.
    if unsafe { Threads::yield_now(threads()) }.is_err() {
        broke(BROKE_YIELD);
    }
    // Only a thread that was switched away and later switched back sees the counter move
    // inside one call.
    if arch::tick::ticks() != interrupts {
        PREEMPTIONS.fetch_add(1, Ordering::Relaxed);
    }
}

/// Block the calling thread until `deadline`, on the kernel's timer queue. Returns at
/// once if the deadline has passed.
pub fn sleep_until(deadline: Instant) {
    let irq = Cpu::irq_save();
    if deadline <= timekeeping::now() {
        // SAFETY: pairs with the `irq_save` above, on this thread.
        unsafe { Cpu::irq_restore(irq) };
        return;
    }
    // SAFETY: masked; the reference ends with the statement, before `block` switches.
    let me = unsafe { (*threads()).current() };
    // Armed with interrupts masked, and they stay masked until the thread has blocked, so
    // its timer cannot expire and try to wake a thread that is still running.
    match timekeeping::with_timers(|q| q.arm_oneshot(deadline, me)) {
        Some(Ok(_)) => {
            // Whoever runs next may have a peer waiting, and this thread cannot see who
            // that is, so a slice is armed; idle re-arms for the deadline alone.
            // SAFETY: masked.
            unsafe { timekeeping::program(Some(SLICE)) };
            // SAFETY: as in `on_tick`.
            if unsafe { Threads::block(threads()) }.is_err() {
                broke(BROKE_SLEEP);
            }
        }
        _ => broke(BROKE_SLEEP),
    }
    // SAFETY: pairs with the `irq_save` above, on this thread.
    unsafe { Cpu::irq_restore(irq) };
}

/// End the calling thread.
pub fn exit_thread() -> ! {
    let _ = Cpu::irq_save();
    // SAFETY: as in `on_tick`.
    let _ = unsafe { Threads::exit(threads()) };
    // Only reached if the exit was refused, which with an idle thread cannot happen.
    // Recorded and left for the timer to preempt, rather than halted, so the check still
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
pub fn begin() {
    // SAFETY: the vector table is installed and the only enabled line is the timer,
    // whose handler is `on_tick`. A thread's entry is not inside any masked region.
    unsafe { arch::tick::enable_interrupts() };
}

/// Spawn a thread on guarded stack slot `stack`. Called by boot, with interrupts masked,
/// only for a slot whose previous thread has been reaped.
pub fn spawn(
    stack: usize,
    entry: extern "C" fn(usize) -> !,
    arg: usize,
    level: u8,
) -> Option<ThreadId> {
    let (top, size) = STACKS.get(stack)?;
    let (top, size) = (top.load(Ordering::Relaxed), size.load(Ordering::Relaxed));
    if top == 0 {
        return None;
    }
    // SAFETY: masked and on boot's thread, so this reference to the table is the only one.
    // `top` and `size` describe a guarded slot claimed by `demonstrate` for the scheduler
    // alone, mapped read-write. The caller guarantees no live thread uses it: either it was
    // never handed out, or its thread exited and was reaped.
    unsafe { (*threads()).spawn(entry, arg, priority(level), KernAddr::new(top), size) }.ok()
}

/// Free an exited thread's slot. `false` if it has not exited.
pub fn reap(id: ThreadId) -> bool {
    let irq = Cpu::irq_save();
    // SAFETY: masked, and the reference ends with the statement.
    let ok = unsafe { (*threads()).reap(id) }.is_ok();
    // SAFETY: pairs with the `irq_save` above.
    unsafe { Cpu::irq_restore(irq) };
    ok
}

/// What one busy loop observed.
struct Spun {
    spins: u64,
    /// The longest run of consecutive spins during which the interrupt counter did not
    /// move.
    longest_tickless: u64,
}

/// Count on `counter` until interrupt number `until`, `stop` is set, or `cap` spins.
///
/// Calibration and the workers share this one function, and it is never inlined, so the
/// rate calibration measures is the rate of the code the workers run.
#[inline(never)]
fn spin(counter: &AtomicU64, until: u64, stop: &AtomicBool, cap: u64) -> Spun {
    let mut last = arch::tick::ticks();
    let (mut spins, mut run, mut longest) = (0, 0, 0);
    while spins < cap {
        let now = arch::tick::ticks();
        if now >= until || stop.load(Ordering::Relaxed) {
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

/// Calibration's hook: interrupt again a slice from now.
fn rearm_slice() {
    // SAFETY: interrupt context, so masked.
    unsafe { timekeeping::program(Some(SLICE)) };
}

/// Spins of [`spin`]'s loop per slice, or 0 if the timer did not interrupt.
///
/// Measured on the boot thread with interrupts briefly enabled and a hook that only
/// re-arms the slice.
fn calibrate() -> u64 {
    static SCRATCH: AtomicU64 = AtomicU64::new(0);
    static NEVER: AtomicBool = AtomicBool::new(false);
    arch::tick::set_hook(Some(rearm_slice));
    // SAFETY: masked, which the caller guarantees.
    unsafe { timekeeping::program(Some(SLICE)) };
    // SAFETY: the vector table is installed and the only enabled line is the timer,
    // whose hook only re-arms it. The caller holds interrupts masked and gets them back
    // masked from the `irq_save` below, which is the state it saved.
    unsafe { arch::tick::enable_interrupts() };
    let t0 = arch::tick::ticks();
    // Start on an interrupt edge, so the measured span is whole slices.
    let _ = spin(&SCRATCH, t0 + 1, &NEVER, CALIBRATION_CAP);
    let end = t0 + 1 + CALIBRATION_TICKS;
    let spun = spin(&SCRATCH, end, &NEVER, CALIBRATION_CAP);
    let reached = arch::tick::ticks() >= end;
    let _ = Cpu::irq_save();
    arch::tick::set_hook(None);
    if reached {
        spun.spins / CALIBRATION_TICKS
    } else {
        0
    }
}

extern "C" fn worker(which: usize) -> ! {
    begin();
    let cap = SPINS_PER_TICK.load(Ordering::Relaxed) * SPIN_CAP_TICKS;
    // Never yields. Getting past this loop in turn with the other worker is only
    // possible if the timer takes the CPU away.
    let spun = spin(&COUNT[which], u64::MAX, &STOP_WORKERS, cap);
    LONGEST_TICKLESS[which].store(spun.longest_tickless, Ordering::Relaxed);
    SAW_OTHER[which].store(COUNT[1 - which].load(Ordering::Relaxed), Ordering::Relaxed);
    DONE[which].store(true, Ordering::Relaxed);
    exit_thread()
}

extern "C" fn high(_: usize) -> ! {
    begin();
    let counted = COUNT[0].load(Ordering::Relaxed) + COUNT[1].load(Ordering::Relaxed);
    HIGH_FIRST_SAW.store(counted, Ordering::Relaxed);

    sleep_until(start().saturating_add(HIGH_WAKES_AFTER));

    HIGH_WOKE_AT.store(timekeeping::now().as_nanos(), Ordering::Relaxed);
    let busy = !DONE[0].load(Ordering::Relaxed) && !DONE[1].load(Ordering::Relaxed);
    HIGH_PREEMPTED_WORKERS.store(busy, Ordering::Relaxed);
    exit_thread()
}

/// Runs whenever nothing else can: offer the CPU, and otherwise halt until an interrupt.
///
/// Idle stays masked except while it waits, so checking for work, arming the timer and
/// halting cannot be split by the interrupt that brings the work.
extern "C" fn idle(_: usize) -> ! {
    loop {
        // SAFETY: masked (a new thread starts masked, and the loop re-masks), as in
        // `on_tick` otherwise.
        if unsafe { Threads::yield_now(threads()) }.is_err() {
            broke(BROKE_YIELD);
        }
        // Nothing else is ready, or the yield would have run it: wake only for a timer.
        // SAFETY: masked.
        unsafe { timekeeping::program(None) };
        // Counted before the wait, not after: the interrupt that ends it usually switches
        // to the thread it woke from inside the handler, so the wait returns only when
        // idle next runs.
        IDLE_WAITS.fetch_add(1, Ordering::Relaxed);
        // SAFETY: masked on entry, as `wait_for_interrupt` requires; the timer has a
        // handler.
        unsafe { arch::tick::wait_for_interrupt() };
        let _ = Cpu::irq_save();
    }
}

fn priority(level: u8) -> Priority {
    // Every constant above is below `sched::LEVELS`; this is not reachable with them.
    Priority::new(level).unwrap_or(Priority::IDLE)
}

fn start() -> Instant {
    Instant::from_nanos(START.load(Ordering::Relaxed))
}

/// Run the threads and judge the result. Called once, from `kmain`, with interrupts
/// masked, after the interrupt and context switch selftests have passed.
pub fn demonstrate(c: &dyn EarlyConsole) -> Check {
    if STARTED.swap(true, Ordering::Relaxed) {
        c.write_str("already run");
        return Check::Failed;
    }
    let irq = Cpu::irq_save();

    // SAFETY: masked, and nothing else programs the timer from here on.
    if let Err(e) = unsafe { timekeeping::init() } {
        c.write_str(match e {
            timekeeping::Error::NoClock => "no clock to schedule by",
            timekeeping::Error::BadRate => "clock rate not convertible",
            timekeeping::Error::NoTimer => "no one-shot timer to preempt with",
        });
        // SAFETY: pairs with the `irq_save` above.
        unsafe { Cpu::irq_restore(irq) };
        return Check::Failed;
    }

    // SAFETY: the only write to `SCHED`, before the timer starts and before any other
    // thread exists (see its invariant).
    unsafe {
        SCHED.get().write(MaybeUninit::new(Sched {
            threads: Threads::new(priority(BOOT_PRIORITY)),
        }));
    }

    // Workers before `high`, so that `high` running first is the priority's doing and not
    // the queue order's.
    //
    // Each stack comes from the port's guarded thread-stack array, so a thread that
    // overflows faults on its own guard page and the report names it, instead of quietly
    // corrupting the stack of whichever thread's slot is below.
    let plan: [(extern "C" fn(usize) -> !, usize, u8, &'static str); 4] = [
        (idle, 0, Priority::IDLE.level(), "idle"),
        (worker, 0, WORKER_PRIORITY, "worker A"),
        (worker, 1, WORKER_PRIORITY, "worker B"),
        (high, 0, HIGH_PRIORITY, "high"),
    ];
    for (i, &(_, _, _, name)) in plan.iter().enumerate() {
        let Some((_, top, size)) = arch::kspace::claim_thread_stack(name) else {
            c.write_str("no guarded thread stack left");
            // SAFETY: pairs with the `irq_save` above.
            unsafe { Cpu::irq_restore(irq) };
            return Check::Failed;
        };
        STACKS[i].0.store(top.raw(), Ordering::Relaxed);
        STACKS[i].1.store(size, Ordering::Relaxed);
    }
    let mut ids = [ThreadId::new(0); 4];
    for (i, (entry, arg, level, _)) in plan.into_iter().enumerate() {
        match spawn(i, entry, arg, level) {
            Some(id) => ids[i] = id,
            None => {
                c.write_str("spawn refused");
                // SAFETY: pairs with the `irq_save` above.
                unsafe { Cpu::irq_restore(irq) };
                return Check::Failed;
            }
        }
    }

    let per_tick = calibrate();
    if per_tick == 0 {
        arch::tick::stop();
        c.write_str("timer did not interrupt during calibration");
        // SAFETY: pairs with the `irq_save` above.
        unsafe { Cpu::irq_restore(irq) };
        return Check::Failed;
    }
    SPINS_PER_TICK.store(per_tick, Ordering::Relaxed);

    arch::tick::set_hook(Some(on_tick));
    let interrupts = arch::tick::ticks();
    let start = timekeeping::now();
    START.store(start.as_nanos(), Ordering::Relaxed);

    // The boot thread's part: nothing, until the workers' time is up, then nothing
    // again until the rest are done.
    sleep_until(start.saturating_add(WORKERS_STOP_AFTER));
    STOP_WORKERS.store(true, Ordering::Relaxed);
    sleep_until(start.saturating_add(BOOT_WAKES_AFTER));
    let interrupts = arch::tick::ticks() - interrupts;
    let elapsed = timekeeping::now().saturating_duration_since(start);

    // Every thread but idle has exited by now; give their slots back and let the table
    // check itself in its final state.
    let reaped = ids[1..].iter().all(|&id| reap(id));
    let table_ok = {
        let irq = Cpu::irq_save();
        // SAFETY: masked, and this is the only reference.
        let ok = unsafe { (*threads()).check() }.is_ok();
        // SAFETY: pairs with the `irq_save` above.
        unsafe { Cpu::irq_restore(irq) };
        reaped && ok
    };

    let preempted = report(c, interrupts, elapsed, table_ok);

    // The shared-state checks run on the same scheduler, with idle still in place and
    // the stacks the threads above gave back.
    let shared = shared::run(c);

    arch::tick::stop();
    arch::tick::set_hook(None);
    // SAFETY: pairs with the `irq_save` above.
    unsafe { Cpu::irq_restore(irq) };

    preempted.and(shared)
}

fn report(c: &dyn EarlyConsole, interrupts: u64, elapsed: Duration, table_ok: bool) -> Check {
    let load = |a: &AtomicU64| a.load(Ordering::Relaxed);
    let counts = [load(&COUNT[0]), load(&COUNT[1])];
    let saw = [load(&SAW_OTHER[0]), load(&SAW_OTHER[1])];
    let broken = BROKEN.load(Ordering::Relaxed);

    let round_robin = saw[0] > 0 && saw[1] > 0;
    let high_first = load(&HIGH_FIRST_SAW) == 0;
    let woke_at = load(&HIGH_WOKE_AT);
    let wake_deadline = start().saturating_add(HIGH_WAKES_AFTER).as_nanos();
    let latency = woke_at.saturating_sub(wake_deadline);
    let prompt = woke_at != u64::MAX
        && latency <= MAX_WAKE_LATENCY.as_nanos()
        && HIGH_PREEMPTED_WORKERS.load(Ordering::Relaxed);
    // Every wait but the one still in progress ended with an interrupt.
    let idled = load(&IDLE_WAITS) > 0 && load(&IDLE_WAITS) <= interrupts + 1;
    let per_tick = load(&SPINS_PER_TICK);
    let tickless = [load(&LONGEST_TICKLESS[0]), load(&LONGEST_TICKLESS[1])];
    let ticks_kept_coming = tickless.iter().all(|&t| t <= per_tick * MAX_TICKLESS_TICKS);
    // The workers contend for the whole of their window, so a slice must have been armed
    // on every interrupt in it. Half the slices it holds is the floor. The other
    // evidence cannot see a missing slice on x86: the PIT cannot arm further than 55 ms,
    // so the workers still alternate every fifth slice, within the tickless limit. Only
    // the count of interrupts shows that nothing asked for the slice.
    let min_interrupts = WORKERS_STOP_AFTER.as_nanos() / SLICE.as_nanos() / 2;
    let sliced = interrupts >= min_interrupts;

    write_usize(c, SLOTS - 1);
    c.write_str(" threads, ");
    write_usize(c, (SLICE.as_nanos() / 1_000_000) as usize);
    c.write_str(" ms slices: ");
    write_usize(c, interrupts as usize);
    c.write_str(" interrupts in ");
    write_usize(c, (elapsed.as_nanos() / 1_000_000) as usize);
    c.write_str(" ms, ");
    write_usize(c, load(&PREEMPTIONS) as usize);
    c.write_str(" preemptions, idle waited ");
    write_usize(c, load(&IDLE_WAITS) as usize);
    c.write_str(" times");
    if !idled {
        c.write_str(" BUT DID NOT HALT UNTIL AN INTERRUPT");
    }
    if !sliced {
        c.write_str(", TOO FEW FOR SLICES (at least ");
        write_usize(c, min_interrupts as usize);
        c.write_str(")");
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
        write_usize(c, (latency / 1_000) as usize);
        c.write_str(" us late ");
        if latency > MAX_WAKE_LATENCY.as_nanos() {
            c.write_str("(TOO LATE) ");
        }
        c.write_str(if HIGH_PREEMPTED_WORKERS.load(Ordering::Relaxed) {
            "over busy workers"
        } else {
            "AFTER THE WORKERS FINISHED"
        });
    }

    c.write_str("\n             interrupts:  longest without one ");
    write_usize(c, tickless[0].div_ceil(per_tick) as usize);
    c.write_str(" and ");
    write_usize(c, tickless[1].div_ceil(per_tick) as usize);
    c.write_str(" slices' worth of spins (");
    write_usize(c, per_tick as usize);
    c.write_str(" per slice, limit ");
    write_usize(c, MAX_TICKLESS_TICKS as usize);
    c.write_str(")");
    if !ticks_kept_coming {
        c.write_str(" A THREAD STOPPED RECEIVING INTERRUPTS");
    }

    if !table_ok {
        c.write_str("\n             thread table INCONSISTENT after the run");
    }
    report_broken(c);

    Check::from_ok(
        round_robin
            && high_first
            && prompt
            && ticks_kept_coming
            && sliced
            && idled
            && table_ok
            && broken == 0,
    )
}

/// Whether anything went wrong where it could not be reported. Printed when it did.
pub fn report_broken(c: &dyn EarlyConsole) -> bool {
    let broken = BROKEN.load(Ordering::Relaxed);
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
    broken == 0
}

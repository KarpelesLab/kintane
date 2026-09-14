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
//! expired, arms the next interrupt, and then calls `Threads::yield_on` on behalf of
//! whatever thread it interrupted. That is the whole mechanism. A woken thread of higher
//! priority takes the CPU at once, and a peer at the same level takes its turn. The
//! switch happens inside the interrupt handler, so each suspended thread's interrupt
//! frame stays on its own stack, and the thread resumes by returning through that
//! handler. Why that is sound, including EOI ordering and the interrupt mask across the
//! switch, is written down in each port's `tick` module, where it has to stay true.
//!
//! The next interrupt is the earliest timer, or the end of a [`SLICE`] if a thread is
//! waiting for the CPU (`Threads::contended_on`). A thread about to block cannot know who
//! runs next, so it arms a slice. The idle thread arms only for the earliest timer
//! before it halts. That is where tickless pays: an idle CPU is not woken to find it has
//! nothing to do.
//!
//! # One CPU, then every CPU
//!
//! The check here runs on the boot CPU alone, before any other CPU is started. After
//! bring-up, [`resume`] gives the scheduler every CPU (see `persist`), and from then on
//! the thread table has a run queue per CPU (`mp::CPUS` of them; one on a kernel built
//! without `SMP`, where `mp` is a stub and none of the following costs anything):
//!
//! * **Joining.** Each secondary leaves its bring-up loop in [`join`], where whatever runs on it
//!   becomes that CPU's idle thread.
//! * **The lock.** Every access to the table is made with interrupts masked and the scheduler lock
//!   held (`mp::lock`). The lock is held *across* a context switch: taken by the thread that
//!   switches away, released by the thread the switch resumes, or by [`thread_start`] for a thread
//!   running for the first time. Released earlier, another CPU could resume the leaving thread
//!   while its registers were still being saved.
//! * **Waking.** The CPU whose timer found a sleeper due wakes it where `sched::balance` places it,
//!   and interrupts that CPU with a reschedule IPI when the thread would run or share a slice
//!   there. Without the IPI a tickless CPU would notice at its next timer interrupt, which can be
//!   seconds away.
//! * **Sleeping.** A thread arms its timer with the lock already held and blocks before releasing
//!   it. So another CPU's timer interrupt cannot find the timer due and try to wake a thread that
//!   is still running.
//! * **Balancing.** Every timer interrupt, and every pass of an idle loop, lets the CPU pull a
//!   ready thread from the busiest other CPU when balancing is due. New threads start on the CPU
//!   that spawned them, so it is balancing that spreads work.
//! * **Timers.** Every CPU arms its timer for the earliest timer in the kernel's one queue, and
//!   whichever CPU takes that interrupt first wakes the sleeper. The honest cost: every idle CPU
//!   wakes for every expiry, until timers are kept per CPU.
//!
//! No reference into the table is held across a switch (see the `thread` crate).
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
use core::sync::atomic::Ordering;

use arch::Cpu;
use hal::{Arch, EarlyConsole, KernAddr};
use sched::balance::CpuSet;
use sched::{Priority, ThreadId};
use thread::Threads;
use time::{Duration, Instant, TimerId};

use crate::{
    AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Check, kheap, mp, shared, timekeeping,
    write_usize,
};

/// Room in the thread table: boot and idle, plus every slot of the port's guarded
/// stack array, plus one idle thread per other CPU, so a thread table slot is never what
/// refuses a spawn.
pub const SLOTS: usize = 2 + MAX_STACKS + mp::CPUS;

/// The threads this module's own check runs: boot, idle, high and two workers.
const DEMO_THREADS: usize = 5;

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

/// The guarded stacks the scheduler's threads run on, `(top, size)`. `demonstrate` claims
/// the first [`THREAD_STACKS`] from the port's thread-stack array, and [`claim_stacks`]
/// more after it. A slot is reused by `spawn` after its previous thread is reaped, so a
/// guard-page report names the slot's first owner rather than whichever later check is
/// running on it.
///
/// Written only by boot with interrupts masked, before any thread is spawned on the slot.
static STACKS: [(AtomicUsize, AtomicUsize); MAX_STACKS] =
    [const { (AtomicUsize::new(0), AtomicUsize::new(0)) }; MAX_STACKS];

/// What the thread on each stack slot runs, `(entry, argument)`, read by [`thread_start`].
/// Written by [`spawn`] under the scheduler lock, before the thread can run.
static STARTS: [(AtomicUsize, AtomicUsize); MAX_STACKS] =
    [const { (AtomicUsize::new(0), AtomicUsize::new(0)) }; MAX_STACKS];

/// Slots of `STACKS` claimed so far.
static CLAIMED: AtomicUsize = AtomicUsize::new(0);

/// How many guarded slots the scheduler's own check holds. Test modes that overflow a
/// thread stack claim theirs after these.
const THREAD_STACKS: usize = 4;

/// Guarded slots the scheduler may hand to kernel threads.
///
/// The port's array holds this many plus one per secondary CPU, which that CPU comes up on
/// and keeps as its idle thread (`codegen::stacks`). So this number is the one the
/// scheduler's own callers share, and it does not shrink as CPUs are added.
pub const MAX_STACKS: usize = kconfig::KERNEL_THREAD_SLOTS;

/// A build whose checks need more stacks than it configured would fail at run time, in the
/// middle of a check, with "no guarded thread stack left". The threads are known here, so
/// it fails to compile instead. `stress::WORKLOADS` reuses the four `THREAD_STACKS` slots
/// the scheduler's check leaves behind and claims `stress::EXTRA_STACKS` more, the
/// driver-isolation check claims `isolation::STACKS` for its domains on every boot, and with
/// userspace the standing file server (`fileserver`) keeps one for as long as the machine runs.
const _: () = assert!(
    MAX_STACKS
        >= THREAD_STACKS
            + crate::stress::EXTRA_STACKS
            + crate::isolation::STACKS
            + kconfig::USERSPACE as usize,
    "KERNEL_THREAD_SLOTS is below what this build's kernel threads need"
);

/// The scheduler state: the thread table, with a run queue per CPU.
struct Sched {
    threads: Threads<Cpu, SLOTS, { mp::CPUS }>,
}

/// SAFETY INVARIANT: written once by `demonstrate` before the timer starts, and from then
/// on accessed only with interrupts masked and the scheduler lock held, through
/// short-lived references that never span a switch. `Threads` holds a thread's `Context`,
/// which cannot be constructed in a `const`, hence `MaybeUninit`.
static SCHED: SyncUnsafeCell<MaybeUninit<Sched>> = SyncUnsafeCell::new(MaybeUninit::uninit());

/// Set by the first run. A second would re-`init` stacks a suspended thread still owns.
static STARTED: AtomicBool = AtomicBool::new(false);

/// Set once `demonstrate` has built the table and spawned idle, so [`resume`] has a
/// scheduler to resume.
static SCHEDULER_BUILT: AtomicBool = AtomicBool::new(false);

/// Which CPUs have a thread in the table running on them: CPU 0 once the table is built,
/// a secondary once [`join`] has adopted it. A timer interrupt or reschedule IPI on a CPU
/// that has not joined does nothing.
static JOINED: [AtomicBool; mp::CPUS] = [const { AtomicBool::new(false) }; mp::CPUS];

/// Reschedule IPIs sent for wake-ups placed on another CPU.
static RESCHEDULES: AtomicU64 = AtomicU64::new(0);
/// Threads pulled by balancing.
static PULLS: AtomicU64 = AtomicU64::new(0);
/// Reschedule IPIs sent to the boot CPU because a timer armed elsewhere was due before it
/// would next wake.
static KICKS: AtomicU64 = AtomicU64::new(0);
/// Reschedule IPIs sent to an idle CPU because this one had a thread waiting.
static IDLE_KICKS: AtomicU64 = AtomicU64::new(0);

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
/// Times the boot CPU's idle thread halted to wait for an interrupt.
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
const BROKE_JOIN: u32 = 1 << 5;

fn broke(what: u32) {
    BROKEN.fetch_or(what, Ordering::Relaxed);
}

fn sched() -> *mut Sched {
    SCHED.get().cast::<Sched>()
}

fn threads() -> *mut Threads<Cpu, SLOTS, { mp::CPUS }> {
    // SAFETY: a field projection through the raw pointer, forming no reference. `SCHED`
    // is initialised before any caller runs (see its invariant).
    unsafe { &raw mut (*sched()).threads }
}

/// Run `f` on the table, masked, with the scheduler lock held, and nothing switching.
fn with_table<R>(f: impl FnOnce(&mut Threads<Cpu, SLOTS, { mp::CPUS }>) -> R) -> R {
    let irq = Cpu::irq_save();
    mp::lock();
    // SAFETY: masked and locked, so by `SCHED`'s invariant this is the only reference; it
    // ends with the call, and `f` cannot switch through a `&mut`.
    let r = f(unsafe { &mut *threads() });
    // SAFETY: taken above, on this CPU, by this thread.
    unsafe { mp::unlock() };
    // SAFETY: pairs with the `irq_save` above.
    unsafe { Cpu::irq_restore(irq) };
    r
}

fn joined(cpu: usize) -> bool {
    JOINED.get(cpu).is_some_and(|j| j.load(Ordering::Acquire))
}

/// Send a reschedule IPI to every CPU in `mask`.
fn send_reschedules(mask: u64) {
    for cpu in CpuSet::from_raw(mask).iter() {
        if mp::reschedule(cpu) {
            RESCHEDULES.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Interrupt every other CPU the scheduler runs on with a reschedule IPI.
///
/// For a process that has ended while another of its threads may be running user code
/// elsewhere: an interrupt is the one thing that reaches a thread that makes no system call,
/// and `userproc` ends it on the way back to user mode.
#[cfg_attr(
    not(CONFIG_USERSPACE),
    expect(
        dead_code,
        reason = "used only to end user threads, which need USERSPACE"
    )
)]
pub fn interrupt_other_cpus() {
    let here = Cpu::cpu_index();
    let others = (0..mp::CPUS.min(64))
        .filter(|&cpu| cpu != here && joined(cpu))
        .fold(0u64, |mask, cpu| mask | 1 << cpu);
    send_reschedules(others);
}

/// Give CPU `cpu`, the caller's, to a ready thread there that should run, if one should.
///
/// # Safety
/// Masked, on `cpu`, with no reference into the table live and the scheduler lock not held.
unsafe fn reschedule_here(cpu: usize) {
    mp::lock();
    // SAFETY: masked and locked; every thread runs on a stack in `STACKS`, a CPU's boot
    // stack or the boot stack, so `yield_on`'s contract holds. The lock is released below
    // by this thread when it next runs, or by `thread_start`.
    // A thread whose affinity no longer allows this CPU is re-queued on another, which
    // must be told: an idle CPU is asleep, and nothing else announces this placement.
    // The IPI goes out under the scheduler lock, so the target spins in its handler until
    // this CPU's switch releases it, which is the next thing that happens.
    if unsafe {
        Threads::yield_on_with(threads(), cpu, |to| {
            let _ = mp::reschedule(to);
        })
    }
    .is_err()
    {
        broke(BROKE_YIELD);
    }
    // SAFETY: held on this CPU: taken above, or by the thread whose switch resumed this one.
    unsafe { mp::unlock() };
}

/// The timer interrupt's and reschedule IPI's hook, on whichever CPU took it: wake whoever
/// is due, balance, arm the next interrupt, then preempt.
fn on_tick() {
    let cpu = Cpu::cpu_index();
    if !joined(cpu) {
        return;
    }
    let interrupts = arch::tick::ticks();
    // Interrupt context until the switch: the thread a switch resumes is not in it.
    kheap::irq_enter();
    let now = timekeeping::now();
    let mut wakes_elsewhere = 0u64;
    mp::lock();
    let contended = {
        // SAFETY: interrupt context, so masked, and locked, so by `SCHED`'s invariant no
        // other reference to it is live. This one ends with the block, before the lock
        // is released. The timer lock nests inside the scheduler lock here, and never the
        // other way round.
        let s = unsafe { &mut *sched() };
        let woke = timekeeping::with_timers(|q| {
            let mut all = true;
            while let Some(expired) = q.pop_expired(now) {
                // The sleeper's timer is gone now; an early wake must not try to cancel it.
                let _ = forget_timer(expired.payload);
                match s.threads.wake_on(expired.payload) {
                    Ok(w) if w.cpu != cpu && w.reschedule => wakes_elsewhere |= 1 << w.cpu,
                    Ok(_) => {}
                    Err(_) => all = false,
                }
            }
            all
        });
        if woke != Some(true) {
            broke(BROKE_WAKE);
        }
        if s.threads.balance(cpu).is_some() {
            PULLS.fetch_add(1, Ordering::Relaxed);
        }
        if s.threads.check().is_err() {
            broke(BROKE_INVARIANT);
        }
        // Idle balancing needs the idle CPU awake to pull. A secondary with nothing to do
        // sleeps until interrupted, so a CPU with threads waiting wakes one.
        let loads = s.threads.loads();
        if loads[cpu].queued > 0
            && let Some(idle) =
                (0..mp::CPUS).find(|&o| o != cpu && loads[o].online && loads[o].idle())
        {
            wakes_elsewhere |= 1 << idle;
            IDLE_KICKS.fetch_add(1, Ordering::Relaxed);
        }
        s.threads.contended_on(cpu)
    };
    // SAFETY: taken above, on this CPU.
    unsafe { mp::unlock() };
    send_reschedules(wakes_elsewhere);
    shared::from_interrupt();
    // SAFETY: interrupt context, so masked.
    unsafe { timekeeping::program(contended.then_some(SLICE)) };
    kheap::irq_exit();

    // SAFETY: interrupt context, so masked, on `cpu`, with nothing held.
    unsafe { reschedule_here(cpu) };
    // Only a thread that was switched away and later switched back sees the counter move
    // inside one call. The counter is the boot CPU's.
    if arch::tick::ticks() != interrupts {
        PREEMPTIONS.fetch_add(1, Ordering::Relaxed);
    }
}

/// Block the calling thread until `deadline`, on the kernel's timer queue. Returns at
/// once if the deadline has passed.
pub fn sleep_until(deadline: Instant) {
    // A flag nothing ever sets: a sleep is a wait whose only way out is its deadline.
    static NEVER: AtomicBool = AtomicBool::new(false);
    let _ = block_until(Some(deadline), &NEVER);
}

/// The timer each thread blocked with a deadline is waiting on, so that a wake arriving
/// first can disarm it.
///
/// Without this an early wake would leave the timer armed, and when it later expired it
/// would wake whatever the thread was doing by then: a stale timer ending an unrelated wait
/// early. A thread holds at most one entry, so one per table slot is enough.
///
/// SAFETY INVARIANT: read and written only with interrupts masked and the scheduler lock
/// held (on a uniprocessor kernel the mask alone is that lock).
static SLEEP_TIMERS: SyncUnsafeCell<[Option<(ThreadId, TimerId)>; SLOTS]> =
    SyncUnsafeCell::new([None; SLOTS]);

/// Record that `id` is blocked on `timer`. Masked, with the scheduler lock held.
fn remember_timer(id: ThreadId, timer: TimerId) {
    // SAFETY: see `SLEEP_TIMERS`; the caller holds the scheduler lock, masked.
    let timers = unsafe { &mut *SLEEP_TIMERS.get() };
    if let Some(free) = timers.iter_mut().find(|t| t.is_none()) {
        *free = Some((id, timer));
    }
}

/// Forget the timer `id` was blocked on, returning it. Masked, with the scheduler lock held.
fn forget_timer(id: ThreadId) -> Option<TimerId> {
    // SAFETY: see `SLEEP_TIMERS`; the caller holds the scheduler lock, masked.
    let timers = unsafe { &mut *SLEEP_TIMERS.get() };
    let held = timers
        .iter_mut()
        .find(|t| t.is_some_and(|(t, _)| t == id))?;
    held.take().map(|(_, timer)| timer)
}

/// Block the calling thread until `woken` is set or `deadline` passes, whichever comes
/// first, and return whether `woken` was set. `None` waits for `woken` alone.
///
/// This is the primitive every wait is built on ([`crate::wait`]), and its contract with
/// [`wake_blocked`] is what makes a wake impossible to lose. The flag is read with the
/// scheduler lock held, and a waker sets the flag *before* it takes that lock to wake the
/// thread. So a wake either lands before this check, which then sees the flag and does not
/// block, or after the thread has blocked, where [`wake_blocked`] finds it.
pub fn block_until(deadline: Option<Instant>, woken: &AtomicBool) -> bool {
    let irq = Cpu::irq_save();
    let cpu = Cpu::cpu_index();
    // The lock before the timer: another CPU's timer interrupt wakes sleepers under this
    // lock, so it cannot find this timer due while this thread is still running.
    mp::lock();
    let already =
        woken.load(Ordering::Acquire) || deadline.is_some_and(|d| d <= timekeeping::now());
    // SAFETY: masked and locked; the reference ends with the statement, before `block_on`
    // switches.
    let me = unsafe { (*threads()).current_on(cpu) };
    let armed = match (already, me, deadline) {
        (true, _, _) => false,
        (false, None, _) => {
            broke(BROKE_SLEEP);
            false
        }
        (false, Some(_), None) => true,
        (false, Some(me), Some(deadline)) => {
            let timer = timekeeping::with_timers(|q| {
                q.arm_oneshot(deadline, me)
                    .map(|timer| (timer, timekeeping::sleep_needs_kick(deadline)))
            });
            match timer {
                Some(Ok((timer, kick))) => {
                    remember_timer(me, timer);
                    // The boot CPU keeps time; if it will not wake by this deadline, tell it
                    // to re-arm (see `timekeeping::program`).
                    if kick && mp::reschedule(0) {
                        KICKS.fetch_add(1, Ordering::Relaxed);
                    }
                    true
                }
                _ => {
                    broke(BROKE_SLEEP);
                    false
                }
            }
        }
    };
    if armed {
        // Whoever runs next may have a peer waiting, and this thread cannot see who that
        // is, so a slice is armed; idle re-arms for the deadline alone.
        // SAFETY: masked.
        unsafe { timekeeping::program(Some(SLICE)) };
        // SAFETY: masked and locked, no reference live; see `reschedule_here`.
        if unsafe { Threads::block_on(threads(), cpu) }.is_err() {
            broke(BROKE_SLEEP);
        }
    }
    // SAFETY: held on the CPU this thread now runs on, by the thread whose switch resumed
    // it (or by this thread, if nothing switched). See the module docs.
    unsafe { mp::unlock() };
    // SAFETY: pairs with the `irq_save` above, on this thread.
    unsafe { Cpu::irq_restore(irq) };
    woken.load(Ordering::Acquire)
}

/// Wake `id` if it is blocked in [`block_until`], disarming the timer it was waiting on.
/// Returns whether it was woken. A thread that is not blocked is left alone, which is the
/// case a wake racing a thread on its way to blocking relies on (see [`block_until`]).
#[cfg_attr(
    not(CONFIG_USERSPACE),
    expect(dead_code, reason = "used only by wait queues, which need USERSPACE")
)]
pub fn wake_blocked(id: ThreadId) -> bool {
    let irq = Cpu::irq_save();
    let here = Cpu::cpu_index();
    mp::lock();
    let placed = {
        // SAFETY: masked and locked, so by `SCHED`'s invariant this is the only reference;
        // it ends with the block, before the lock is released.
        let s = unsafe { &mut *sched() };
        match s.threads.state(id) {
            Some(thread::State::Blocked) => {
                // The timer lock nests inside the scheduler lock, as in `on_tick`.
                if let Some(timer) = forget_timer(id) {
                    let _ = timekeeping::with_timers(|q| q.cancel(timer));
                }
                s.threads.wake_on(id).ok()
            }
            _ => None,
        }
    };
    // SAFETY: taken above, on this CPU; nothing switched.
    unsafe { mp::unlock() };
    if let Some(w) = placed
        && w.cpu != here
        && w.reschedule
        && mp::reschedule(w.cpu)
    {
        RESCHEDULES.fetch_add(1, Ordering::Relaxed);
    }
    // SAFETY: pairs with the `irq_save` above.
    unsafe { Cpu::irq_restore(irq) };
    placed.is_some()
}

/// The thread running on this CPU, if the scheduler has one here.
#[cfg_attr(
    not(CONFIG_USERSPACE),
    expect(dead_code, reason = "used only by wait queues, which need USERSPACE")
)]
pub fn current_thread() -> Option<ThreadId> {
    with_table(|t| t.current_on(Cpu::cpu_index()))
}

/// End the calling thread.
pub fn exit_thread() -> ! {
    let _ = Cpu::irq_save();
    let cpu = Cpu::cpu_index();
    mp::lock();
    // SAFETY: as in `reschedule_here`; on success the lock is released by the thread
    // this switches to, and this thread never runs again.
    let _ = unsafe { Threads::exit_on(threads(), cpu) };
    // Only reached if the exit was refused, which with an idle thread cannot happen.
    // Recorded and left for the timer to preempt, rather than halted, so the check still
    // finishes and reports it.
    // SAFETY: taken above; nothing switched.
    unsafe { mp::unlock() };
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

/// Where every spawned thread starts: end the critical section the switch that started it
/// began, then run what [`spawn`] recorded for its stack slot.
extern "C" fn thread_start(stack: usize) -> ! {
    // SAFETY: a new thread is entered only by a switch made with the scheduler lock held,
    // on the CPU it now runs on, and it is this thread's to release.
    unsafe { mp::unlock() };
    let (entry, arg) = &STARTS[stack.min(MAX_STACKS - 1)];
    let (entry, arg) = (entry.load(Ordering::Acquire), arg.load(Ordering::Acquire));
    // SAFETY: written by `spawn`, before the thread was queued, with an
    // `extern "C" fn(usize) -> !` cast to an address; function and data addresses are the
    // same size on every port.
    let entry = unsafe { core::mem::transmute::<usize, extern "C" fn(usize) -> !>(entry) };
    entry(arg)
}

/// Spawn a thread on guarded stack slot `stack`, queued on the calling CPU and allowed on
/// every CPU. Called only for a slot whose previous thread has been reaped.
pub fn spawn(
    stack: usize,
    entry: extern "C" fn(usize) -> !,
    arg: usize,
    level: u8,
) -> Option<ThreadId> {
    spawn_with(stack, entry, arg, level, None)
}

/// As [`spawn`], or pinned to CPU `idle_on` as that CPU's idle thread.
fn spawn_with(
    stack: usize,
    entry: extern "C" fn(usize) -> !,
    arg: usize,
    level: u8,
    idle_on: Option<usize>,
) -> Option<ThreadId> {
    let (top, size) = STACKS.get(stack)?;
    let (top, size) = (top.load(Ordering::Relaxed), size.load(Ordering::Relaxed));
    if top == 0 {
        return None;
    }
    with_table(|t| {
        STARTS[stack].0.store(entry as usize, Ordering::Release);
        STARTS[stack].1.store(arg, Ordering::Release);
        let here = Cpu::cpu_index();
        let (affinity, cpu, idle) = match idle_on {
            Some(cpu) => (CpuSet::single(cpu), cpu, true),
            None => (CpuSet::all(mp::CPUS), here, false),
        };
        // SAFETY: `top` and `size` describe a guarded slot claimed for the scheduler alone,
        // mapped read-write. The caller guarantees no live thread uses it: either it was
        // never handed out, or its thread exited and was reaped.
        unsafe {
            t.spawn_on(
                thread_start,
                stack,
                priority(level),
                KernAddr::new(top),
                size,
                affinity,
                cpu,
                idle,
            )
        }
        .ok()
    })
}

/// As [`spawn`], with `prepare` run on the new thread's saved context before the thread
/// can be picked up, and given the top of the stack it will run on.
///
/// A user thread needs its kernel stack and its address space recorded in its context
/// (`hal::HasUserMode::bind`) *before* any CPU switches to it: the switch is what loads
/// them. Spawning and preparing are therefore one critical section under the scheduler
/// lock, not two calls with a window between them in which another CPU could take the
/// thread and enter it with no address space of its own.
///
/// Takes a closure rather than the binding itself so that nothing here needs the user-mode
/// capability: this file is compiled for ports that have no userspace at all.
#[cfg_attr(
    not(CONFIG_USERSPACE),
    expect(
        dead_code,
        reason = "used only to start user threads, which need USERSPACE"
    )
)]
pub fn spawn_prepared(
    stack: usize,
    entry: extern "C" fn(usize) -> !,
    arg: usize,
    level: u8,
    prepare: impl FnOnce(&mut <Cpu as hal::HasContextSwitch>::Context, KernAddr),
) -> Option<ThreadId> {
    let (top, size) = STACKS.get(stack)?;
    let (top, size) = (top.load(Ordering::Relaxed), size.load(Ordering::Relaxed));
    if top == 0 {
        return None;
    }
    with_table(|t| {
        STARTS[stack].0.store(entry as usize, Ordering::Release);
        STARTS[stack].1.store(arg, Ordering::Release);
        let here = Cpu::cpu_index();
        // SAFETY: as in `spawn_with`: a guarded slot claimed for the scheduler alone,
        // whose previous thread the caller guarantees has been reaped.
        let id = unsafe {
            t.spawn_on(
                thread_start,
                stack,
                priority(level),
                KernAddr::new(top),
                size,
                CpuSet::all(mp::CPUS),
                here,
                false,
            )
        }
        .ok()?;
        // The thread is queued but not running, so its saved context is the one a switch
        // into it will load, and `context_mut` refuses anything else.
        prepare(t.context_mut(id).ok()?, KernAddr::new(top));
        Some(id)
    })
}

/// Free an exited thread's slot. `false` if it has not exited.
pub fn reap(id: ThreadId) -> bool {
    with_table(|t| t.reap(id).is_ok())
}

/// Restrict `id` to the CPUs in `mask`, moving it if it is queued somewhere else.
#[cfg_attr(
    not(CONFIG_USERSPACE),
    expect(
        dead_code,
        reason = "used only by the process checks, which need USERSPACE"
    )
)]
pub fn set_affinity(id: ThreadId, mask: u64) -> bool {
    let placed = with_table(|t| {
        t.set_affinity(id, CpuSet::from_raw(mask))
            .ok()
            .map(|()| t.cpu_of(id))
    });
    let Some(on) = placed else {
        return false;
    };
    // The table moves a thread but interrupts nobody. A thread queued on an idle CPU would
    // wait for that CPU's next timer interrupt, which on a tickless secondary can be seconds
    // away, and a running thread would keep a CPU it may no longer use until it next
    // yields. So interrupt the CPU it is on now: it reschedules, and picks the thread up or
    // hands it on. Nothing happens if there was nothing to do.
    if let Some(cpu) = on.filter(|&cpu| cpu != Cpu::cpu_index()) {
        mp::reschedule(cpu);
    }
    true
}

/// Whether `id` still exists in the table and has not exited.
#[cfg_attr(
    not(CONFIG_USERSPACE),
    expect(
        dead_code,
        reason = "used only by the process checks, which need USERSPACE"
    )
)]
pub fn alive(id: ThreadId) -> bool {
    with_table(|t| !matches!(t.state(id), None | Some(thread::State::Exited)))
}

/// Where `id` is and what it is doing, for a check that waited for it in vain: its state
/// and the CPU it is queued on or running on. `None` when the table has never heard of it.
#[cfg_attr(
    not(CONFIG_USERSPACE),
    expect(
        dead_code,
        reason = "used only by the process checks, which need USERSPACE"
    )
)]
pub fn where_is(id: ThreadId) -> Option<(thread::State, Option<usize>)> {
    with_table(|t| t.state(id).map(|s| (s, t.cpu_of(id))))
}

/// Whether the scheduler is running, so a thread that ends must go through
/// [`exit_thread`] rather than any table of its own.
#[cfg_attr(
    not(CONFIG_MM_PAGED),
    expect(
        dead_code,
        reason = "asked only by user threads ending and by the volume's lease, which need MM_PAGED"
    )
)]
pub fn scheduled() -> bool {
    SCHEDULER_BUILT.load(Ordering::Relaxed)
}

/// Claim guarded stack slots for threads named `names`, after those already claimed.
///
/// Returns the index of the first, for [`spawn`]. `None`, having claimed nothing, if
/// the scheduler's array or the port's has too few slots left. Called by boot with
/// interrupts masked.
pub fn claim_stacks(names: &[&'static str]) -> Option<usize> {
    let first = CLAIMED.load(Ordering::Relaxed);
    if first + names.len() > MAX_STACKS {
        return None;
    }
    let mut claimed = [(0usize, 0usize); MAX_STACKS];
    for (i, &name) in names.iter().enumerate() {
        // A port that runs out part of the way leaves the slots it did hand out
        // unused. They cannot be given back, and nothing spawns on them.
        let (_, top, size) = arch::kspace::claim_thread_stack(name)?;
        claimed[i] = (top.raw(), size);
    }
    for (i, &(top, size)) in claimed[..names.len()].iter().enumerate() {
        STACKS[first + i].0.store(top, Ordering::Relaxed);
        STACKS[first + i].1.store(size, Ordering::Relaxed);
    }
    CLAIMED.store(first + names.len(), Ordering::Relaxed);
    Some(first)
}

/// Give the CPU to a ready thread of the same or higher priority, if there is one.
#[cfg_attr(
    not(CONFIG_MM_PAGED),
    expect(
        dead_code,
        reason = "used only by the stress run, which needs MM_PAGED"
    )
)]
pub fn yield_now() {
    let irq = Cpu::irq_save();
    // SAFETY: masked, on the CPU just read, nothing held.
    unsafe { reschedule_here(Cpu::cpu_index()) };
    // SAFETY: pairs with the `irq_save` above, on this thread.
    unsafe { Cpu::irq_restore(irq) };
}

/// Whether the thread table's invariants hold right now.
pub fn table_ok() -> bool {
    with_table(|t| t.check().is_ok())
}

/// What the scheduler has done across CPUs since the table was built.
#[derive(Clone, Copy, Debug, Default)]
#[cfg_attr(
    not(CONFIG_MM_PAGED),
    expect(
        dead_code,
        reason = "read only by the stress run, which needs MM_PAGED"
    )
)]
pub struct Stats {
    /// Threads moved between CPUs, by wake placement, balancing or affinity.
    pub migrations: u64,
    /// Of those, threads pulled by balancing.
    pub pulls: u64,
    /// Reschedule IPIs sent: for wake-ups placed on another CPU, and to wake idle CPUs.
    pub reschedules: u64,
    /// Of those, to wake an idle CPU while a thread waited elsewhere.
    pub idle_kicks: u64,
    /// Reschedule IPIs sent to the boot CPU to re-arm for an earlier timer.
    pub timer_kicks: u64,
    /// CPUs that have joined the scheduler.
    pub cpus: usize,
}

#[cfg_attr(
    not(CONFIG_MM_PAGED),
    expect(
        dead_code,
        reason = "used only by the stress run, which needs MM_PAGED"
    )
)]
pub fn stats() -> Stats {
    Stats {
        migrations: with_table(|t| t.migrations()),
        pulls: PULLS.load(Ordering::Relaxed),
        reschedules: RESCHEDULES.load(Ordering::Relaxed),
        idle_kicks: IDLE_KICKS.load(Ordering::Relaxed),
        timer_kicks: KICKS.load(Ordering::Relaxed),
        cpus: (0..mp::CPUS).filter(|&cpu| joined(cpu)).count(),
    }
}

/// Put the scheduler's hook back on the timer interrupt, after a check that removed it.
pub fn restore_tick_hook() {
    arch::tick::set_hook(Some(on_tick));
}

/// What went wrong where nothing could report it, as the `BROKE_*` bits. Zero is good.
#[cfg_attr(
    not(CONFIG_MM_PAGED),
    expect(
        dead_code,
        reason = "used only by the stress run, which needs MM_PAGED"
    )
)]
pub fn broken() -> u32 {
    BROKEN.load(Ordering::Relaxed)
}

/// Hand the CPU to the scheduler for good, from the boot thread, and every other CPU with
/// it.
///
/// `demonstrate` runs the scheduler for the boot checks and then stops the timer,
/// because what follows it in `kmain` — the in-kernel suite, the test modes that end the
/// run from a fault handler, a deliberate crash — assumes one thread with interrupts
/// masked. Once those are done, this starts the one-shot timer again with the scheduler's
/// hook, releases the secondaries into [`join`], and unmasks. The thread table is still
/// the one the checks used, with idle in it, so from here boot is one thread among others
/// and returns to its caller as one.
///
/// `false`, having changed nothing, if the scheduler was never built, which only
/// happens when the boot checks failed.
pub fn resume() -> bool {
    if !SCHEDULER_BUILT.load(Ordering::Relaxed) {
        return false;
    }
    let _ = Cpu::irq_save();
    // SAFETY: masked, and nothing else programs the timer: the boot checks that did have
    // finished. This re-enables the line `demonstrate` disabled when it stopped the tick.
    if unsafe { arch::tick::start_oneshot() } == 0 {
        return false;
    }
    arch::tick::set_hook(Some(on_tick));
    // SAFETY: masked, as `program` requires.
    unsafe { timekeeping::program(Some(SLICE)) };
    // SAFETY: once, from the boot CPU, with the table built; `join` is the scheduler's.
    unsafe { mp::release(join) };
    begin();
    true
}

/// Where a released secondary enters the scheduler: what runs on it becomes its idle
/// thread. Masked on entry, and idle stays masked except while it waits.
fn join(cpu: usize) -> ! {
    let adopted = cpu < mp::CPUS
        && with_table(|t| {
            t.adopt(cpu, Priority::IDLE, CpuSet::single(cpu), true)
                .is_ok()
        });
    if !adopted {
        // A CPU past the table's run queues, or one the table refused: it stays out, and
        // says so where the stress audit will see it.
        broke(BROKE_JOIN);
        Cpu::halt()
    }
    // `Release`: a timer interrupt or IPI on this CPU loads it with `Acquire`.
    JOINED[cpu].store(true, Ordering::Release);
    idle_loop(cpu)
}

/// Offer CPU `cpu` to any thread, pulling one from elsewhere first if balancing is due,
/// and otherwise halt until an interrupt.
///
/// Masked except while it waits, so checking for work, arming the timer and halting
/// cannot be split by the interrupt that brings the work.
fn idle_loop(cpu: usize) -> ! {
    loop {
        mp::lock();
        // SAFETY: masked and locked; the reference ends with the statement.
        if unsafe { (*threads()).balance(cpu) }.is_some() {
            PULLS.fetch_add(1, Ordering::Relaxed);
        }
        // SAFETY: masked (a new thread starts masked, and the loop re-masks), locked, and
        // nothing referenced; see `reschedule_here`.
        // As in `reschedule_here`: an affinity change can send the yielding thread to
        // another CPU, which has to be told.
        if unsafe {
            Threads::yield_on_with(threads(), cpu, |to| {
                let _ = mp::reschedule(to);
            })
        }
        .is_err()
        {
            broke(BROKE_YIELD);
        }
        // SAFETY: held on this CPU, by this thread or the thread whose switch resumed it.
        unsafe { mp::unlock() };
        // Nothing else is ready, or the yield would have run it: wake only for a timer,
        // or for an IPI that brings a thread.
        // SAFETY: masked.
        unsafe { timekeeping::program(None) };
        // Counted before the wait, not after: the interrupt that ends it usually switches
        // to the thread it woke from inside the handler, so the wait returns only when
        // idle next runs. The boot check reads the boot CPU's.
        if cpu == 0 {
            IDLE_WAITS.fetch_add(1, Ordering::Relaxed);
        }
        // SAFETY: masked on entry, as `wait_for_interrupt` requires; the timer and the IPIs
        // have handlers.
        unsafe { arch::tick::wait_for_interrupt() };
        let _ = Cpu::irq_save();
    }
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

/// The boot CPU's idle thread. See [`idle_loop`].
extern "C" fn idle(_: usize) -> ! {
    idle_loop(0)
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
    // thread exists (see its invariant). `Sched` is its one field, so initialising the
    // table in place initialises the whole `Sched`. In place, not by value: the table
    // grows with stack slots and CPUs, and building it on the boot stack first overflowed
    // that stack into its guard page on an eight-CPU aarch64 stress build.
    unsafe {
        let sched = SCHED.get().cast::<Sched>();
        Threads::init_in_place(core::ptr::addr_of_mut!((*sched).threads), priority(BOOT_PRIORITY));
    }
    JOINED[0].store(true, Ordering::Release);

    // Workers before `high`, so that `high` running first is the priority's doing and not
    // the queue order's.
    //
    // Each stack comes from the port's guarded thread-stack array, so a thread that
    // overflows faults on its own guard page and the report names it, instead of quietly
    // corrupting the stack of whichever thread's slot is below.
    let plan: [(extern "C" fn(usize) -> !, usize, u8, &'static str); THREAD_STACKS] = [
        (idle, 0, Priority::IDLE.level(), "idle"),
        (worker, 0, WORKER_PRIORITY, "worker A"),
        (worker, 1, WORKER_PRIORITY, "worker B"),
        (high, 0, HIGH_PRIORITY, "high"),
    ];
    let names = plan.map(|(_, _, _, name)| name);
    if claim_stacks(&names) != Some(0) {
        c.write_str("no guarded thread stack left");
        // SAFETY: pairs with the `irq_save` above.
        unsafe { Cpu::irq_restore(irq) };
        return Check::Failed;
    }
    let mut ids = [ThreadId::new(0); 4];
    for (i, (entry, arg, level, _)) in plan.into_iter().enumerate() {
        // Idle belongs to the boot CPU; the others start there and may move.
        let idle_on = (i == 0).then_some(0);
        match spawn_with(i, entry, arg, level, idle_on) {
            Some(id) => ids[i] = id,
            None => {
                c.write_str("spawn refused");
                // SAFETY: pairs with the `irq_save` above.
                unsafe { Cpu::irq_restore(irq) };
                return Check::Failed;
            }
        }
    }
    SCHEDULER_BUILT.store(true, Ordering::Relaxed);

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
    let consistent = reaped && table_ok();

    let preempted = report(c, interrupts, elapsed, consistent);

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

    write_usize(c, DEMO_THREADS);
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
        for (bit, name) in ["invariant", "wake", "yield", "sleep", "exit", "join"]
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

//! A stall point inside a wait, so the window before registering can be aimed at.
//!
//! [`crate::wait::WaitQueue::wait_once`] looks at its condition, registers the thread, looks
//! again, and only then blocks. The second look is what closes the window between the first
//! look and registering: a waker that changed the condition in there found nobody registered,
//! so its wake reached no one, and only that look sees what it did.
//!
//! The tenth round built the waits over sets on exactly that guarantee, and then found it
//! could not test it. Its `readiness` check delivered eighteen wakes of eighteen with the
//! second look **deleted**, because a wake asked for over a channel arrives milliseconds
//! later, by which time the waiting thread is long blocked. The window is sub-microsecond,
//! and no thread outside the wait can aim at it.
//!
//! So the kernel opens it on request. With `WAIT_RACE_TEST`, one thread arms itself, enters a
//! wait whose condition is false, and parks in the window; the boot thread makes the condition
//! true and wakes the queue while it is parked; then it lets the waiter go on to register. A
//! kernel that looks again sees what the waker did and never blocks at all. A kernel that does
//! not, blocks — and nothing will wake it, because the wake it needed has already happened.
//!
//! **What the check reads is therefore not "was it woken" but "did it block".** Both kernels
//! end up with the condition true, because the deadline expires and the wait looks once more on
//! its way out. Only the block count tells them apart, and it is the count this check requires
//! to be zero.
//!
//! # What it costs a kernel that does not want it
//!
//! Nothing. Without the symbol, `waitrace_off.rs` takes this module's place: [`stall`] is an
//! empty inline function, so there is no branch on the wait path and no symbol in the image.
//!
//! # What else this hook reaches
//!
//! The window belongs to the wait, not to any one thing waited on, so anything whose readiness
//! another CPU can change while a thread is in there can be raced from here. Two are checked:
//!
//! * a plain [`crate::wait::WaitQueue`] with a condition of its own — the primitive itself;
//! * the set path ([`crate::readiness`]) with a real event object, where the racer signals the
//!   event and calls `readiness::wake`, which is the path a program's `poll` takes.
//!
//! Left for later, reachable the same way: a channel closed against a lookup that holds it, a
//! timer expiring against the arming of the queue it delivers to, and a socket whose peer
//! closes while a wait is in the window.

use core::sync::atomic::Ordering;

use hal::EarlyConsole;
use kobject::handle::Entry;
use kobject::{ObjectType, Rights};
use sched::ThreadId;
use time::{Duration, Instant};

use crate::objects::{self, Object};
use crate::preempt::sleep_until;
use crate::wait::WaitQueue;
use crate::{
    AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Check, preempt, readiness, timekeeping,
    write_usize,
};

/// The scheduler stack slot the waiting thread runs on. The checks before this one have
/// reaped the threads that held it.
const STACK: usize = 1;
/// Below boot, so the boot thread's own wake-ups come first.
const PRIORITY: u8 = 4;

/// How long the waiter gives its wait before giving up, and how long either side waits for
/// the other at each step. The wait's own deadline is what a kernel that blocks here runs out,
/// so it is short enough that a failing check is prompt and long enough that a busy host does
/// not end it early.
const WAIT_FOR: Duration = Duration::from_nanos(2_000_000_000);
const PATIENCE: Duration = Duration::from_nanos(5_000_000_000);
const POLL: Duration = Duration::from_nanos(200_000);

/// The cases, in the order the waiter runs them.
const CASES: usize = 2;
/// A plain wait queue: the primitive itself.
const CASE_QUEUE: usize = 0;
/// The set path, with a real event object and `readiness::wake`.
const CASE_SET: usize = 1;

/// No thread is armed.
const NOBODY: u32 = u32::MAX;

/// The thread that stalls at the next window it reaches, or [`NOBODY`]. One thread at a time,
/// and one stall each time it is armed: [`stall`] disarms before it parks.
static ARMED: AtomicU32 = AtomicU32::new(NOBODY);
/// The case the waiter is armed for, as `case + 1`, and zero between cases. Read by
/// [`stall`] so its arrival names a case.
static CASE: AtomicUsize = AtomicUsize::new(0);
/// The case whose waiter is parked in the window, as `case + 1`, or zero.
///
/// A plain flag was not enough, and the first run of this check proved it: the boot thread
/// saw the *previous* case's arrival, made its thing ready, and released before the waiter had
/// even entered the next wait, which then found it ready at its first look and never parked.
/// Both cases still reported "ok, 0 blocks" — a pass with nothing raced. Naming the case is
/// what makes an arrival belong to the wait it came from.
static ARRIVED: AtomicUsize = AtomicUsize::new(0);
/// The case whose waiter the racer has finished with, as `case + 1`, or zero.
static RELEASE: AtomicUsize = AtomicUsize::new(0);
/// Stalls actually taken, so a check whose hook never fired says so rather than passing.
static STALLS: AtomicU64 = AtomicU64::new(0);

/// The condition of [`CASE_QUEUE`], and the queue whose waiters the racer wakes.
static QUEUE: WaitQueue = WaitQueue::new();
static FLAG: AtomicBool = AtomicBool::new(false);

/// The event object of [`CASE_SET`], as its raw identity, and the handle rights the waiter
/// asks readiness with.
static EVENT: AtomicU64 = AtomicU64::new(0);

/// Per case: whether the wait ended with its condition true, how many times it blocked, and
/// how long it took in microseconds.
static ENDED_READY: [AtomicBool; CASES] = [const { AtomicBool::new(false) }; CASES];
static BLOCKED: [AtomicU64; CASES] = [const { AtomicU64::new(0) }; CASES];
static TOOK_US: [AtomicU64; CASES] = [const { AtomicU64::new(0) }; CASES];
/// How far the waiter got, so a thread that died part of the way through is not read as a pass.
static DONE: AtomicUsize = AtomicUsize::new(0);

/// Park here if this thread armed itself, until the racer has had its turn.
///
/// Called by [`crate::wait::WaitQueue::wait_once`] between the look that precedes registering
/// and the registration itself. Disarms before parking, so the sleep below — and anything else
/// that waits while this thread is parked — does not stall again.
pub fn stall() {
    let Some(me) = preempt::current_thread() else {
        return;
    };
    if ARMED.load(Ordering::Acquire) != me.raw() {
        return;
    }
    ARMED.store(NOBODY, Ordering::Release);
    STALLS.fetch_add(1, Ordering::Relaxed);
    let mine = CASE.load(Ordering::Acquire);
    ARRIVED.store(mine, Ordering::Release);
    // Parked, and not registered on any queue: the racer's wake is the one that must be
    // remembered by the look that follows this, not delivered to a thread waiting here.
    let give_up = timekeeping::now().saturating_add(PATIENCE);
    while RELEASE.load(Ordering::Acquire) != mine && timekeeping::now() < give_up {
        sleep_until(timekeeping::now().saturating_add(POLL));
    }
}

/// Arm this thread for the next window it reaches, for `case`, and clear what the last one
/// left behind.
fn arm(me: ThreadId, case: usize) {
    ARRIVED.store(0, Ordering::Release);
    RELEASE.store(0, Ordering::Release);
    CASE.store(case + 1, Ordering::Release);
    ARMED.store(me.raw(), Ordering::Release);
}

/// The waiting thread: it arms itself, waits for something that is not ready, and is raced.
extern "C" fn waiter(_: usize) -> ! {
    preempt::begin();
    let Some(me) = preempt::current_thread() else {
        preempt::exit_thread()
    };

    // A plain queue, whose condition is a flag the racer sets.
    run_case(CASE_QUEUE, me, || {
        let deadline = timekeeping::now().saturating_add(WAIT_FOR);
        QUEUE
            .wait_until(Some(deadline), || FLAG.load(Ordering::Acquire).then_some(()))
            .is_ok()
    });

    // The set path: the same window, reached through the queue a program's `poll` registers
    // on, with readiness read from a real object.
    run_case(CASE_SET, me, || {
        let entry = Entry {
            object: kobject::ObjectId::from_raw(EVENT.load(Ordering::Acquire)),
            kind: ObjectType::Event,
            rights: Rights::ALL,
        };
        let deadline = timekeeping::now().saturating_add(WAIT_FOR);
        readiness::queue()
            .wait_until(Some(deadline), || (readiness::of(entry) != 0).then_some(()))
            .is_ok()
    });

    preempt::exit_thread()
}

/// Arm, run one wait, and record what it did.
fn run_case(case: usize, me: ThreadId, wait: impl FnOnce() -> bool) {
    let blocks_before = crate::wait::stats().blocks;
    let started = timekeeping::now();
    arm(me, case);
    let ready = wait();
    let blocked = crate::wait::stats().blocks.saturating_sub(blocks_before);
    ENDED_READY[case].store(ready, Ordering::Release);
    BLOCKED[case].store(blocked, Ordering::Release);
    TOOK_US[case].store(elapsed_us(started), Ordering::Release);
    DONE.store(case + 1, Ordering::Release);
}

fn elapsed_us(since: Instant) -> u64 {
    timekeeping::now()
        .as_nanos()
        .saturating_sub(since.as_nanos())
        / 1_000
}

/// Wait for the waiter to park in the window, make the thing it waits for ready, wake the
/// queue, and let it go. Returns whether it ever arrived.
fn race(case: usize, make_ready: impl FnOnce()) -> bool {
    let mine = case + 1;
    let give_up = timekeeping::now().saturating_add(PATIENCE);
    while ARRIVED.load(Ordering::Acquire) != mine && timekeeping::now() < give_up {
        sleep_until(timekeeping::now().saturating_add(POLL));
    }
    if ARRIVED.load(Ordering::Acquire) != mine {
        // Let it go anyway, so a waiter parked for some other reason is not left there.
        RELEASE.store(mine, Ordering::Release);
        return false;
    }
    // In the window: the waiter has looked once for *this* case and has not registered.
    make_ready();
    RELEASE.store(mine, Ordering::Release);
    true
}

/// Run the check. On the boot thread, with the scheduler running.
pub fn check(c: &dyn EarlyConsole) -> Check {
    c.write_str("\n  waitrace   ");
    objects::init();
    let objects_before = objects::live();
    FLAG.store(false, Ordering::Release);
    STALLS.store(0, Ordering::Relaxed);
    DONE.store(0, Ordering::Release);
    ARRIVED.store(0, Ordering::Release);
    RELEASE.store(0, Ordering::Release);

    let Some(event) = objects::create(Object::Event { signalled: false }) else {
        c.write_str("no object for an event");
        return Check::Failed;
    };
    EVENT.store(event.raw(), Ordering::Release);

    let Some(id) = preempt::spawn(STACK, waiter, 0, PRIORITY) else {
        objects::retire(event);
        c.write_str("no stack for the waiting thread");
        return Check::Failed;
    };

    // Case one: a flag and a plain queue.
    let arrived_queue = race(CASE_QUEUE, || {
        FLAG.store(true, Ordering::Release);
        QUEUE.wake_all();
    });
    // Case two: a real event, and the wake a program's `poll` is woken by.
    let arrived_set = race(CASE_SET, || {
        objects::signal_event(event);
        readiness::wake();
    });

    let give_up = timekeeping::now().saturating_add(PATIENCE);
    while preempt::alive(id) && timekeeping::now() < give_up {
        sleep_until(timekeeping::now().saturating_add(POLL));
    }
    let ended = !preempt::alive(id) && preempt::reap(id);
    objects::retire(event);
    let leaked = objects::live().saturating_sub(objects_before);

    report(
        c,
        Outcome {
            arrived: [arrived_queue, arrived_set],
            ended,
            leaked,
        },
    )
}

/// What the run found, beside the per-case statics.
struct Outcome {
    arrived: [bool; CASES],
    ended: bool,
    leaked: usize,
}

const NAMES: [&str; CASES] = ["a queue", "a set"];

fn report(c: &dyn EarlyConsole, out: Outcome) -> Check {
    let mut ok = out.ended && out.leaked == 0 && DONE.load(Ordering::Acquire) == CASES;
    if DONE.load(Ordering::Acquire) != CASES {
        c.write_str("THE WAITER DID NOT FINISH ITS CASES");
    } else {
        c.write_str("a wake in the window before registering was not lost");
    }
    for case in 0..CASES {
        let blocked = BLOCKED[case].load(Ordering::Acquire);
        let ready = ENDED_READY[case].load(Ordering::Acquire);
        c.write_str("; ");
        c.write_str(NAMES[case]);
        if !out.arrived[case] {
            c.write_str(": THE WAITER NEVER REACHED THE WINDOW");
            ok = false;
            continue;
        }
        if !ready {
            c.write_str(": THE WAIT ENDED WITH ITS CONDITION FALSE");
            ok = false;
        }
        // The whole point: with the look that follows registering, the wake made in the
        // window is seen there and the thread never blocks at all. Without it, it blocks and
        // waits out its deadline, and only this count says so.
        if blocked != 0 {
            c.write_str(": IT BLOCKED, so the wake in the window was lost; ");
            write_usize(c, blocked as usize);
            c.write_str(" blocks");
            ok = false;
        } else {
            c.write_str(" ok in ");
            write_usize(c, TOOK_US[case].load(Ordering::Acquire) as usize);
            c.write_str(" us, 0 blocks");
        }
    }
    c.write_str("; ");
    write_usize(c, STALLS.load(Ordering::Relaxed) as usize);
    c.write_str(" stalls taken");
    if STALLS.load(Ordering::Relaxed) as usize != CASES {
        c.write_str(", NOT ONE PER CASE");
        ok = false;
    }
    if !out.ended {
        c.write_str("; THE WAITING THREAD NEVER ENDED");
    }
    c.write_str("; ");
    write_usize(c, out.leaked);
    c.write_str(if out.leaked == 0 {
        " objects left ok"
    } else {
        " OBJECTS LEAKED"
    });
    Check::from_ok(ok)
}

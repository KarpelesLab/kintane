//! Waiting properly: blocking system calls, events, timers, two threads in one process, and
//! a file read through a service over a channel.
//!
//! Until this, a program that waited spun: a non-blocking call, a yield, and the same call
//! again. [`crate::wait`] gives the kernel wait queues, and this is the check that a program
//! gets real waits out of them — and that the objects built on them do what they say.
//!
//! # What runs
//!
//! The kernel builds `init` in its waits mode and gives it three handles: the console, a
//! handle to its own process (so it can start a thread in itself), and, when the test disk's
//! volume is mounted, a connection to the kernel's file server (`crate::fileserver`), which
//! this check starts and which runs from then on. `init` then, in order:
//!
//! 1. polls an empty completion queue and is told `ShouldWait` at once, then waits on it with a
//!    timeout and must be told `TimedOut` no earlier than the timeout and not long after. A
//!    `process_wait` for its own process, which cannot end while it waits, must run out the same
//!    way, and arming a queue with a timeout is refused;
//! 2. arms a one-shot timer on the queue and waits for its completion, then a periodic one for
//!    three expirations, cancels it, and sees nothing more arrive;
//! 3. starts a second thread in its own process, which writes to a page the first mapped and
//!    signals an event: the event wakes the first thread, which reads the write back through the
//!    same address. The second thread then blocks receiving on a channel until the first sends, and
//!    answers;
//! 4. moves an event handle across a channel with only `WAIT` kept, and sees the receiver able to
//!    wait on it and refused a signal, and the sender's handle gone. A send naming a handle it does
//!    not hold moves nothing;
//! 5. opens `/HELLO.TXT` through the file server, reads it in pieces, closes it, prints it, and
//!    compares it with what the disk holds.
//!
//! # What must hold
//!
//! * `init` exits with [`WAITS_SUCCESS`]; a failure names its step.
//! * Threads really blocked, were really woken, and a wait really timed out: [`wait::stats`] counts
//!   each, and a kernel whose "waits" were all answered without blocking fails here even if the
//!   program saw the right answers.
//! * On a machine with the test disk, the server answered requests, and let go of the connection
//!   once `init` had gone. Without one, that step is reported skipped.
//! * Every thread ended, and every object and frame is back.
//!
//! A wake from another CPU cannot be shown here: secondary CPUs join the scheduler only after
//! the boot verdict. The stress run shows it ([`stress_cycle`]).

#![allow(unsafe_code)]

use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use hal::EarlyConsole;
use time::Duration;

use crate::preempt::{self, sleep_until};
use crate::{Check, objects, spawn, timekeeping, userproc, wait, write_hex, write_usize};

/// `init`'s modes, and its codes when each behaved. Mirrors `user/init/src/main.rs`.
const MODE_WAITS: usize = 5;
const WAITS_SUCCESS: u64 = 0x6b;
const MODE_PAIR: usize = 6;
const MODE_PAIR_PEER: usize = 7;
const PAIR_SUCCESS: u64 = 0x6c;

/// The process slot, and the scheduler stack slots its threads run on. `spawn` has torn its
/// processes down and reaped its threads by the time this runs.
const SLOT: usize = 0;
const STACKS: [usize; 3] = [1, 2, 3];

/// The longest the check gives `init` for everything.
const PATIENCE: Duration = Duration::from_nanos(10_000_000_000);
/// How often the check looks for threads that have ended.
const POLL: Duration = Duration::from_nanos(5_000_000);

/// What one run of `init` came to.
struct Outcome {
    /// Whether `init`'s thread was started at all.
    started: bool,
    code: Option<u64>,
    /// Requests the file server answered while `init` ran, or `None` with no volume to serve.
    served: Option<usize>,
    /// Why `init` could not be given a connection, if it could not.
    service_failed: Option<&'static str>,
}

/// Run the check. On the boot thread, with the scheduler running.
pub fn check(c: &dyn EarlyConsole) -> Check {
    c.write_str("\n  waits      ");
    objects::init();
    if userproc::with_frames(|f| f.alloc.stats().free).is_none() {
        c.write_str("skipped: no frames for processes");
        return Check::Skipped;
    }
    let Some(program) = userproc::program() else {
        c.write_str("the init program does not load");
        return Check::Failed;
    };
    spawn::use_stacks(&STACKS);
    let frames_before = free_frames();
    let objects_before = objects::live();
    let before = wait::stats();

    let outcome = run(&program);

    let ended = spawn::end_threads();
    if ended {
        userproc::teardown(SLOT);
    }
    // The server lets go of `init`'s connection when it sees it close, on its own thread.
    let settled = crate::fileserver::settle();
    let after = wait::stats();
    let blocks = after.blocks - before.blocks;
    let wakes = after.wakes - before.wakes;
    let timeouts = after.timeouts - before.timeouts;
    let frames = frames_before.saturating_sub(free_frames());
    let leaked = objects::live().saturating_sub(objects_before);

    match outcome.code {
        Some(WAITS_SUCCESS) => c.write_str("init waited, timed out, woke and read a file"),
        Some(code) => {
            c.write_str("init exited ");
            write_hex(c, code);
            c.write_str(", WRONG");
        }
        None if !outcome.started => c.write_str("init NEVER STARTED"),
        None => c.write_str("init NEVER EXITED"),
    }
    c.write_str("; ");
    write_usize(c, blocks as usize);
    c.write_str(" blocks, ");
    write_usize(c, wakes as usize);
    c.write_str(" wakes, ");
    write_usize(c, timeouts as usize);
    c.write_str(" timeouts");
    let service_ok = match (outcome.served, outcome.service_failed) {
        (_, Some(why)) => {
            c.write_str("; FILE SERVER FAILED: ");
            c.write_str(why);
            false
        }
        (Some(n), None) => {
            c.write_str("; file server answered ");
            write_usize(c, n);
            if !settled {
                c.write_str(", NEVER LET GO OF THE CONNECTION");
            }
            n > 0 && settled
        }
        (None, None) if crate::fs::mounted() => {
            // A volume to serve, and a server never asked: `init` was never started.
            c.write_str("; file server NEVER USED");
            false
        }
        (None, None) => {
            // Only a machine with no disk attached may skip it; one that attached a disk and
            // did not mount it has already failed the filesystem check, and fails here too.
            c.write_str("; file service skipped: no volume");
            !kconfig::QEMU_BLOCK_TEST
        }
    };
    if !ended {
        c.write_str("; A THREAD NEVER ENDED, its process left in place");
    }
    c.write_str("; ");
    write_usize(c, leaked);
    c.write_str(if leaked == 0 {
        " objects left"
    } else {
        " OBJECTS LEAKED"
    });
    c.write_str(", ");
    write_usize(c, frames);
    c.write_str(if frames == 0 {
        " frames left ok"
    } else {
        " FRAMES LEAKED"
    });
    let counted = blocks > 0 && wakes > 0 && timeouts > 0;
    if !counted {
        c.write_str("; NOTHING REALLY BLOCKED, WOKE, OR TIMED OUT");
    }
    Check::from_ok(
        outcome.code == Some(WAITS_SUCCESS)
            && counted
            && service_ok
            && ended
            && leaked == 0
            && frames == 0,
    )
}

/// Build `init`, hand it its three handles, start it, serve it, and wait for every thread
/// of it to end.
fn run(program: &elf::Program) -> Outcome {
    let mut out = Outcome {
        started: false,
        code: None,
        served: None,
        service_failed: None,
    };
    if userproc::build(SLOT, program).is_none() {
        return out;
    }
    let Some(p) = userproc::slot(SLOT) else {
        return out;
    };
    p.image = Some(userproc::program_image());
    let Some(console) = p.console_handle() else {
        return out;
    };
    let Some(me) = userproc::process_handle(SLOT) else {
        return out;
    };
    let files = if !crate::fs::mounted() {
        None
    } else if !crate::fileserver::start() {
        out.service_failed = Some("the file server did not start");
        None
    } else {
        let connection = crate::fileserver::connect(SLOT);
        if connection.is_none() {
            out.service_failed = Some("the file server refused a connection");
        }
        connection
    };
    let served_before = crate::fileserver::served();
    let args = [
        MODE_WAITS,
        console.raw() as usize,
        me.raw() as usize,
        files.map_or(0, |h| h.raw() as usize),
    ];
    let Some(main) = userproc::start(SLOT, 0, args) else {
        return out;
    };
    out.started = true;
    let give_up = timekeeping::now().saturating_add(PATIENCE);
    while (preempt::alive(main) || userproc::threads_live(SLOT) != 0)
        && timekeeping::now() < give_up
    {
        sleep_until(timekeeping::now().saturating_add(POLL));
    }
    if files.is_some() {
        out.served = Some((crate::fileserver::served() - served_before) as usize);
    }
    if !preempt::alive(main) && userproc::threads_live(SLOT) == 0 {
        // Every thread has ended, so nothing else borrows the process.
        out.code = userproc::slot(SLOT).and_then(|p| p.exit);
    }
    out
}

fn free_frames() -> usize {
    userproc::with_frames(|f| f.alloc.stats().free).unwrap_or(0)
}

// ---- the stress run ---------------------------------------------------------------------
//
// Once per audit interval, while every other workload runs, the auditor builds a process
// with two threads and pins them to two different CPUs. They pass a counter back and forth
// over a channel, each blocking in `channel_recv` for the other's message, and now and then
// one makes the other wait longer with a timed wait of its own. Every receive has a timeout
// far longer than any exchange takes, so a wake-up that was lost is a receive that times out,
// and the program exits with a code saying so. The auditor requires the process's success
// code, every frame back, and — with two CPUs or more — that some wake crossed CPUs.

/// The second guarded stack a waiting process's threads run on, claimed by [`stress_setup`];
/// the first is the one the process cycle's thread runs on, free again by then.
static STRESS_STACK: AtomicUsize = AtomicUsize::new(usize::MAX);
/// Waiting processes the stress run has created and destroyed.
static PAIRS: AtomicU64 = AtomicU64::new(0);

/// How long a cycle gives its process.
const PAIR_PATIENCE: Duration = Duration::from_nanos(5_000_000_000);

/// Claim the second stack. Once, from the stress run's setup, after the process cycle's.
pub fn stress_setup() -> Result<(), &'static str> {
    let stack = preempt::claim_stacks(&["process peer"])
        .ok_or("no guarded stack for a second process thread")?;
    STRESS_STACK.store(stack, Ordering::Relaxed);
    Ok(())
}

pub fn stress_cycles() -> u64 {
    PAIRS.load(Ordering::Relaxed)
}

/// The second stack, for the stress run's other two-threaded processes (`crate::sibling`'s,
/// and the Linux personality's pair), each of which runs after this one's cycle has reaped
/// its threads.
pub fn stress_stack() -> usize {
    STRESS_STACK.load(Ordering::Relaxed)
}

/// Build, run and destroy one two-threaded waiting process; see the section comment. On the
/// auditor's thread, after the process cycle.
pub fn stress_cycle(round: u64) -> Result<(), &'static str> {
    let second = STRESS_STACK.load(Ordering::Relaxed);
    let first = crate::procs::stress_stack();
    if first == usize::MAX || second == usize::MAX {
        return Err("the waiting process's stacks were never claimed");
    }
    if !crate::procs::use_pool() {
        return Err("no frames were reserved for processes");
    }
    let program = userproc::program().ok_or("the init program does not load")?;
    spawn::use_stacks(&[first, second]);
    let frames_before = free_frames();
    let objects_before = objects::live();
    let before = wait::stats();

    let result = pair(&program, round);

    if !spawn::end_threads() {
        // Its tables cannot be freed while a thread may still run on them. The run is
        // failing anyway; leaving the process is the only safe thing to do.
        result?;
        return Err("a thread of a waiting process did not end");
    }
    userproc::teardown(SLOT);
    PAIRS.fetch_add(1, Ordering::Relaxed);
    result?;
    let after = wait::stats();
    if after.blocks == before.blocks {
        return Err("a waiting process never blocked");
    }
    if preempt::stats().cpus >= 2 && after.cross_cpu_wakes == before.cross_cpu_wakes {
        return Err("threads pinned to two CPUs never woke each other across them");
    }
    if free_frames() != frames_before {
        return Err("a waiting process did not give back every frame");
    }
    if objects::live() != objects_before {
        return Err("a waiting process left objects behind");
    }
    Ok(())
}

fn pair(program: &elf::Program, round: u64) -> Result<(), &'static str> {
    userproc::build(SLOT, program).ok_or("could not build a waiting process")?;
    let p = userproc::slot(SLOT).ok_or("the waiting process's slot is empty")?;
    p.image = Some(userproc::program_image());
    let (a, b) = userproc::channel_pair(SLOT).ok_or("no channel for the waiting process")?;
    let main = userproc::start(SLOT, 0, [MODE_PAIR, a.raw() as usize, 0, 0])
        .ok_or("the waiting process's thread was refused")?;
    // The peer enters the same program at its entry point, in a mode of its own; it waits
    // for the first thread to have installed the program.
    let peer = userproc::start(SLOT, 0, [MODE_PAIR_PEER, b.raw() as usize, 0, 0])
        .ok_or("the waiting process's second thread was refused")?;
    let cpus = preempt::stats().cpus.max(1);
    if cpus >= 2 {
        let first = (round as usize) % cpus;
        let _ = preempt::set_affinity(main, 1 << first);
        let _ = preempt::set_affinity(peer, 1 << ((first + 1) % cpus));
    }
    let give_up = timekeeping::now().saturating_add(PAIR_PATIENCE);
    while (preempt::alive(main) || preempt::alive(peer)) && timekeeping::now() < give_up {
        sleep_until(timekeeping::now().saturating_add(POLL));
    }
    // Unpinned whatever happened, so a thread that is still there can reach its end.
    let _ = preempt::set_affinity(main, u64::MAX);
    let _ = preempt::set_affinity(peer, u64::MAX);
    if preempt::alive(main) || preempt::alive(peer) {
        return Err("a waiting process did not finish: a wake-up was lost");
    }
    match userproc::slot(SLOT).and_then(|p| p.exit) {
        Some(PAIR_SUCCESS) => Ok(()),
        Some(0x603 | 0x613) => Err("a waiting process's receive timed out: a wake-up was lost"),
        _ => Err("a waiting process exited with a failure"),
    }
}

//! Stopping a thread that never asks: a process ends while another of its threads spins in
//! user mode.
//!
//! A thread of an ending process ends at its next system call, or at once if it is waiting.
//! A thread that does neither — a loop in user code — was out of reach: nothing it did brought
//! it into the kernel, so its process could not be torn down while it ran, and whoever started
//! it could only report a thread that never ended.
//!
//! It is reached by interrupt now. An exit sends a reschedule IPI to every other CPU, and
//! every scheduler interrupt that arrived in user mode asks, on its way back, whether the
//! thread's process has ended; if it has, the thread ends there (`userproc`'s
//! `on_user_interrupt`). On the exiting thread's own CPU the spinner had been preempted for the
//! exiting thread to run at all, and it meets the same question when it is resumed.
//!
//! # What runs
//!
//! `init`, as two threads of one process that the kernel starts with a handle to one event.
//! The spinner signals the event and then spins for ever without a system call. The main
//! thread waits for the signal, gives the spinner time to be deep in its loop, and exits. With
//! two CPUs or more the two are pinned apart, so the exit on one must reach a thread running
//! on the other; at boot only the boot CPU schedules, so there the spinner is reached through
//! the timer that preempted it.
//!
//! # What must hold
//!
//! * The main thread exits with [`SPIN_SUCCESS`].
//! * Both threads end within [`PATIENCE`]. A kernel that cannot stop the spinner fails here, by the
//!   clock, rather than hanging.
//! * The spinner was ended from an interrupt: `userproc::interrupt_kills` moved.
//! * Every object and frame is back once the process is torn down.

use core::sync::atomic::{AtomicU64, Ordering};

use hal::EarlyConsole;
use kobject::{ObjectType, Rights};
use time::Duration;

use crate::objects::{self, Object};
use crate::preempt::{self, sleep_until};
use crate::{Check, spawn, timekeeping, userproc, write_hex, write_usize};

/// `init`'s two modes here, and its code when the main thread behaved. Mirrors
/// `user/init/src/main.rs`.
const MODE_SPIN: usize = 8;
const MODE_SPINNER: usize = 9;
const SPIN_SUCCESS: u64 = 0x6d;

/// The process slot, and the scheduler stack slots its threads run on at boot. `waits` has
/// torn its process down and reaped its threads by the time this runs.
const SLOT: usize = 0;
const STACKS: [usize; 3] = [1, 2, 3];

/// The longest both threads get to end, from their start.
const PATIENCE: Duration = Duration::from_nanos(5_000_000_000);
/// How often the check looks.
const POLL: Duration = Duration::from_nanos(5_000_000);

/// Spinning processes the stress run has stopped and destroyed.
static CYCLES: AtomicU64 = AtomicU64::new(0);

/// What one run came to: the process's exit code, if every thread ended, and whether they
/// all did within [`PATIENCE`].
struct Outcome {
    code: Option<u64>,
    stopped: bool,
}

/// Run the check. On the boot thread, with the scheduler running.
pub fn check(c: &dyn EarlyConsole) -> Check {
    c.write_str("\n  sibling    ");
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
    let kills_before = userproc::interrupt_kills();

    let outcome = run(&program, 0);

    let ended = spawn::end_threads();
    if ended {
        userproc::teardown(SLOT);
    }
    let kills = userproc::interrupt_kills() - kills_before;
    let frames = frames_before.saturating_sub(free_frames());
    let leaked = objects::live().saturating_sub(objects_before);

    let (code, stopped) = match outcome {
        Ok(Outcome { code, stopped }) => (code, stopped),
        Err(why) => {
            c.write_str(why);
            c.write_str("; ");
            (None, false)
        }
    };
    match (code, stopped) {
        (Some(SPIN_SUCCESS), true) => {
            c.write_str("a process ended under a thread spinning in user mode, and it stopped")
        }
        (Some(other), true) => {
            c.write_str("the main thread exited ");
            write_hex(c, other);
            c.write_str(", WRONG");
        }
        _ => c.write_str("THE SPINNING THREAD WAS NEVER STOPPED"),
    }
    c.write_str("; ");
    write_usize(c, kills as usize);
    c.write_str(" stopped from an interrupt");
    if kills == 0 {
        c.write_str(", NONE");
    }
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
    Check::from_ok(
        code == Some(SPIN_SUCCESS) && stopped && ended && kills > 0 && leaked == 0 && frames == 0,
    )
}

/// Build the process, start both threads — pinned apart when there are CPUs to pin them to —
/// and wait for both to end.
fn run(program: &elf::Program, round: u64) -> Result<Outcome, &'static str> {
    userproc::build(SLOT, program).ok_or("the process could not be built")?;
    let p = userproc::slot(SLOT).ok_or("the process's slot is empty")?;
    p.image = Some(userproc::program_image());
    let event =
        objects::create(Object::Event { signalled: false }).ok_or("no object for the event")?;
    let Some(started) = p.grant(event, ObjectType::Event, Rights::ALL) else {
        objects::retire(event);
        return Err("the event's handle was refused");
    };
    let arg = started.raw() as usize;
    let main =
        userproc::start(SLOT, 0, [MODE_SPIN, arg, 0, 0]).ok_or("the main thread was refused")?;
    // The spinner enters the same program in a mode of its own, once the first thread has
    // installed it.
    let spinner = userproc::start(SLOT, 0, [MODE_SPINNER, arg, 0, 0])
        .ok_or("the spinning thread was refused")?;
    let cpus = preempt::stats().cpus.max(1);
    if cpus >= 2 {
        let first = (round as usize) % cpus;
        let _ = preempt::set_affinity(main, 1 << first);
        let _ = preempt::set_affinity(spinner, 1 << ((first + 1) % cpus));
    }
    let give_up = timekeeping::now().saturating_add(PATIENCE);
    while (preempt::alive(main) || preempt::alive(spinner)) && timekeeping::now() < give_up {
        sleep_until(timekeeping::now().saturating_add(POLL));
    }
    let stopped = !preempt::alive(main) && !preempt::alive(spinner);
    // Unpinned whatever happened, so a thread that is still starting can reach its end.
    let _ = preempt::set_affinity(main, u64::MAX);
    let _ = preempt::set_affinity(spinner, u64::MAX);
    let code = if stopped {
        // Every thread has ended, so nothing else borrows the process.
        userproc::slot(SLOT).and_then(|p| p.exit)
    } else {
        None
    };
    Ok(Outcome { code, stopped })
}

fn free_frames() -> usize {
    userproc::with_frames(|f| f.alloc.stats().free).unwrap_or(0)
}

// ---- the stress run ---------------------------------------------------------------------
//
// Every other audit interval, after the waiting process, the auditor runs the same two threads
// on the same two stacks, pinned to two different CPUs whenever there are two, so each cycle's
// exit has to reach a thread spinning on another CPU. A cycle requires the success code, both
// threads gone, the spinner stopped from an interrupt, and every frame and object back.

pub fn stress_cycles() -> u64 {
    CYCLES.load(Ordering::Relaxed)
}

/// Build, run and destroy one spinning process; see the section comment. On the auditor's
/// thread, after the waiting process's cycle.
pub fn stress_cycle(round: u64) -> Result<(), &'static str> {
    if round % 2 == 0 {
        return Ok(());
    }
    let stacks = [crate::procs::stress_stack(), crate::waits::stress_stack()];
    if stacks.contains(&usize::MAX) {
        return Err("the spinning process's stacks were never claimed");
    }
    if !crate::procs::use_pool() {
        return Err("no frames were reserved for processes");
    }
    let program = userproc::program().ok_or("the init program does not load")?;
    spawn::use_stacks(&stacks);
    let frames_before = free_frames();
    let objects_before = objects::live();
    let kills_before = userproc::interrupt_kills();

    let result = run(&program, round);

    if !spawn::end_threads() {
        // Its tables cannot be freed while a thread may still run on them.
        result?;
        return Err("a spinning thread was never stopped: its process's exit did not reach it");
    }
    userproc::teardown(SLOT);
    CYCLES.fetch_add(1, Ordering::Relaxed);
    let Outcome { code, stopped } = result?;
    if !stopped {
        return Err("a spinning thread outlived its process's patience");
    }
    if code != Some(SPIN_SUCCESS) {
        return Err("a spinning process's main thread exited with a failure");
    }
    if userproc::interrupt_kills() == kills_before {
        return Err("a spinning thread ended, but not by an interrupt");
    }
    if free_frames() != frames_before {
        return Err("a spinning process did not give back every frame");
    }
    if objects::live() != objects_before {
        return Err("a spinning process left objects behind");
    }
    Ok(())
}

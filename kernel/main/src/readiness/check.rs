//! The check: one process waiting on a channel, an event and a timer at once.
//!
//! `init` in its poll mode ([`MODE_POLL`]) holds three objects — a channel whose other end this
//! check holds, an event this check signals, and a completion queue its own timer delivers to —
//! and waits on all three with one call. Over that channel it asks for one of them to be made
//! ready after a delay it names, and this check answers.
//!
//! # Why the delays grow
//!
//! The sixteen rounds at the end ask for the event a little later each time. A wait looks at its
//! set, registers on the queue, looks again, and only then blocks, so a wake can land at three
//! different stages, and the dangerous one is between the two looks: a kernel that registered and
//! then slept without looking again would lose exactly those wakes. Growing the delay across
//! rounds puts a wake at each stage in turn rather than hoping one lands there.
//!
//! A lost wake is a round that never ends, so the program's patience is far longer than a round
//! takes and it exits with the round's number rather than hanging the boot.
//!
//! # What must hold
//!
//! * `init` exits with [`POLL_SUCCESS`]; a failure names the step or the round.
//! * Every request this check received was answered, and there was at least one.
//! * Threads really blocked and were really woken: `wait::stats` and [`super::stats`] both move,
//!   so a kernel whose "waits" all found something at their first look fails here.
//! * Every thread ended, and every object and frame is back.

use hal::EarlyConsole;
use kobject::{ObjectType, Rights};
use time::Duration;

use crate::objects::{self, Object};
use crate::{Check, preempt, spawn, timekeeping, userproc, write_hex, write_usize};

/// `init`'s mode, and the code it exits with when every step behaved. Mirrors
/// `user/init/src/main.rs`.
const MODE_POLL: usize = 12;
const POLL_SUCCESS: u64 = 0x70;

/// What the program asks for, and the bytes it asks in: a kind, then a little-endian `u32` of
/// microseconds. Mirrors `ASK_EVENT`, `ASK_CHANNEL` and the message `ask` builds.
const ASK_EVENT: u8 = b'E';
const ASK_CHANNEL: u8 = b'C';
const ASK_BYTES: usize = 5;

/// The process slot and the stack slots its thread runs on. The checks before this one have torn
/// their processes down and reaped their threads.
const SLOT: usize = 0;
const STACKS: [usize; 3] = [1, 2, 3];

/// The longest the program gets for everything, and how often this check looks at it.
const PATIENCE: Duration = Duration::from_nanos(20_000_000_000);
const POLL: Duration = Duration::from_nanos(2_000_000);

/// How one run went.
struct Run {
    started: bool,
    code: Option<u64>,
    /// Requests the program made, and the ones this check answered.
    asked: usize,
    served: usize,
    /// How long the program ran, in milliseconds.
    took_ms: usize,
}

/// Run the check. On the boot thread, with the scheduler running.
pub fn check(c: &dyn EarlyConsole) -> Check {
    c.write_str("\n  readiness  ");
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
    let waits_before = crate::wait::stats();
    let before = super::stats();

    let run = run(&program);

    let ended = spawn::end_threads();
    if ended {
        userproc::teardown(SLOT);
    }
    let blocks = crate::wait::stats().blocks - waits_before.blocks;
    let after = super::stats();
    let woken = after.woken - before.woken;
    let looks = after.looks - before.looks;
    let frames = frames_before.saturating_sub(free_frames());
    let leaked = objects::live().saturating_sub(objects_before);

    match run.code {
        Some(POLL_SUCCESS) => {
            c.write_str("init waited on a channel, an event and a timer at once");
        }
        Some(code) => {
            c.write_str("init exited ");
            write_hex(c, code);
            c.write_str(", WRONG");
        }
        None if !run.started => c.write_str("init NEVER STARTED"),
        None => c.write_str("init NEVER EXITED: a wake was lost"),
    }
    c.write_str("; ");
    write_usize(c, run.served);
    c.write_str(" of ");
    write_usize(c, run.asked);
    c.write_str(" wakes delivered in ");
    write_usize(c, run.took_ms);
    c.write_str(" ms, ");
    write_usize(c, blocks as usize);
    c.write_str(" blocks, ");
    write_usize(c, woken as usize);
    c.write_str(" woken, ");
    write_usize(c, looks as usize);
    c.write_str(" looks");
    let served_all = run.asked > 0 && run.asked == run.served;
    if !served_all {
        c.write_str(", A REQUEST WAS NEVER ANSWERED");
    }
    // A wait that never blocked, or that was never woken, is not the thing being checked.
    let really_waited = blocks > 0 && woken > 0;
    if !really_waited {
        c.write_str(", NOTHING REALLY BLOCKED OR WAS WOKEN");
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
        run.code == Some(POLL_SUCCESS)
            && served_all
            && really_waited
            && ended
            && leaked == 0
            && frames == 0,
    )
}

/// Build `init` in its poll mode, hand it the console, a channel to this check and an event, and
/// answer what it asks for while it runs.
fn run(program: &elf::Program) -> Run {
    let mut out = Run {
        started: false,
        code: None,
        asked: 0,
        served: 0,
        took_ms: 0,
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
    let Some((theirs, mut ours)) = userproc::kernel_channel(SLOT) else {
        return out;
    };
    let Some(event) = objects::create(Object::Event { signalled: false }) else {
        return out;
    };
    let granted =
        userproc::slot(SLOT).and_then(|p| p.grant(event, ObjectType::Event, Rights::ALL));
    let Some(event_handle) = granted else {
        objects::retire(event);
        return out;
    };
    let args = [
        MODE_POLL,
        console.raw() as usize,
        theirs.raw() as usize,
        event_handle.raw() as usize,
    ];
    let Some(main) = userproc::start(SLOT, 0, args) else {
        objects::retire(event);
        return out;
    };
    out.started = true;
    // One request is outstanding at a time: the program asks, waits, and only asks again once
    // it has been answered.
    let mut due: Option<(u8, u64)> = None;
    let started = timekeeping::now();
    let give_up = started.saturating_add(PATIENCE);
    while (preempt::alive(main) || userproc::threads_live(SLOT) != 0)
        && timekeeping::now() < give_up
    {
        if due.is_none() {
            let mut message = [0u8; ASK_BYTES];
            if let Ok(ASK_BYTES) = ours.try_recv(&mut message) {
                let mut micros = [0u8; 4];
                micros.copy_from_slice(&message[1..]);
                let at = timekeeping::now()
                    .as_nanos()
                    .saturating_add(u64::from(u32::from_le_bytes(micros)).saturating_mul(1_000));
                due = Some((message[0], at));
                out.asked += 1;
            }
        }
        if let Some((what, at)) = due
            && timekeeping::now().as_nanos() >= at
        {
            match what {
                ASK_EVENT => {
                    objects::signal_event(event);
                }
                ASK_CHANNEL => {
                    let _ = ours.send(b"ready");
                }
                // A request this check does not know is left unanswered, and the program's
                // wait runs out and says so.
                _ => {}
            }
            out.served += 1;
            due = None;
        }
        preempt::sleep_until(timekeeping::now().saturating_add(POLL));
    }
    out.took_ms = (timekeeping::now().as_nanos().saturating_sub(started.as_nanos()) / 1_000_000)
        as usize;
    if !preempt::alive(main) && userproc::threads_live(SLOT) == 0 {
        // Every thread has ended, so nothing else borrows the process.
        out.code = userproc::slot(SLOT).and_then(|p| p.exit);
    }
    // This check's own reference to the event; the program's handle goes with its table.
    objects::retire(event);
    out
}

fn free_frames() -> usize {
    userproc::with_frames(|f| f.alloc.stats().free).unwrap_or(0)
}

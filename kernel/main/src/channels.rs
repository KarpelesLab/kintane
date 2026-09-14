//! Channel lifetime: a channel lives for as long as anything names it — a lookup in flight
//! included — and is destroyed when the last name goes.
//!
//! # The race this is for
//!
//! A system call on a channel finds it by an endpoint's identity and then uses it: sends on
//! it, receives from it, waits on it. Between the finding and the use, another thread may
//! close the channel's last handle, or tear down the process that made it. If closing frees
//! the channel then, the call goes on using storage that is no longer its channel — and once
//! another channel has been made in that storage, it sends into, or receives from, a channel
//! belonging to someone else.
//!
//! # What runs
//!
//! Two threads, with the interleaving forced rather than hoped for. A process is built with
//! one channel. A second kernel thread looks the channel up by its first endpoint's identity
//! and keeps what it found, and says so. The boot thread then closes the channel the way it
//! is closed for real — it tears the process down, and every handle to either endpoint goes
//! with it — and makes as many new channels as there is room for, so that any storage the
//! closed channel gave back is holding another channel by now. Only then does the lookup
//! thread use what it found.
//!
//! # What must hold
//!
//! * **The lookup still names its own channel.** It asks the channel it holds whether the endpoint
//!   it looked up is one of its two; a channel freed under it and reused says no.
//! * **The last reference destroys it.** Once the lookup thread lets go, every object the check
//!   made is gone: the channel outlived its handles only for as long as the lookup held it.

use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};

use hal::EarlyConsole;
use kobject::ObjectId;
use time::Duration;

use crate::preempt::{self, sleep_until};
use crate::{Check, objects, timekeeping, userproc, write_usize};

/// The process slot the check builds in: free between `spawn` and `waits`.
const SLOT: usize = 1;
/// The scheduler stack slot the lookup thread runs on, which `spawn`'s threads have left.
const STACK: usize = 1;
/// Below boot, so boot's own wake-ups come first.
const PRIORITY: u8 = 4;

/// How long either thread waits for the other at each step.
const PATIENCE: Duration = Duration::from_nanos(3_000_000_000);
const POLL: Duration = Duration::from_nanos(1_000_000);

/// The endpoint the lookup thread looks up, as its raw identity.
static ENDPOINT: AtomicU64 = AtomicU64::new(0);
/// Set by the lookup thread once it holds what it found.
static LOOKED: AtomicBool = AtomicBool::new(false);
/// Set by the boot thread once the channel is closed and its storage reused.
static CLOSED: AtomicBool = AtomicBool::new(false);
/// What the lookup thread found when it used its lookup: one of the `SAW_` values.
static SAW: AtomicU8 = AtomicU8::new(SAW_NOTHING_YET);

const SAW_NOTHING_YET: u8 = 0;
/// The channel it holds still has the endpoint it looked up.
const SAW_SAME: u8 = 1;
/// The channel it holds has two other endpoints: freed under the lookup, and reused.
const SAW_REUSED: u8 = 2;
/// The lookup found no channel at all.
const SAW_MISSING: u8 = 3;
/// It was never told the channel had closed.
const SAW_NEVER_CLOSED: u8 = 4;

/// Look the channel up, hold what was found across the close, then use it.
extern "C" fn lookup(_: usize) -> ! {
    preempt::begin();
    let endpoint = ObjectId::from_raw(ENDPOINT.load(Ordering::Acquire));
    let found = userproc::channel_of(endpoint);
    LOOKED.store(true, Ordering::Release);
    let give_up = timekeeping::now().saturating_add(PATIENCE);
    while !CLOSED.load(Ordering::Acquire) && timekeeping::now() < give_up {
        sleep_until(timekeeping::now().saturating_add(POLL));
    }
    let saw = if !CLOSED.load(Ordering::Acquire) {
        SAW_NEVER_CLOSED
    } else {
        match found.as_deref() {
            Some(chan) if chan.side_of(endpoint).is_some() => SAW_SAME,
            Some(_) => SAW_REUSED,
            None => SAW_MISSING,
        }
    };
    // The lookup ends here, and with it the last thing naming the channel.
    drop(found);
    SAW.store(saw, Ordering::Release);
    preempt::exit_thread()
}

/// Run the check. On the boot thread, with the scheduler running.
pub fn check(c: &dyn EarlyConsole) -> Check {
    c.write_str("\n  channels   ");
    objects::init();
    if userproc::with_frames(|f| f.alloc.stats().free).is_none() {
        c.write_str("skipped: no frames for processes");
        return Check::Skipped;
    }
    let Some(program) = userproc::program() else {
        c.write_str("the init program does not load");
        return Check::Failed;
    };
    let objects_before = objects::live();
    LOOKED.store(false, Ordering::Release);
    CLOSED.store(false, Ordering::Release);
    SAW.store(SAW_NOTHING_YET, Ordering::Release);

    let (made, ended) = race(&program);

    let leaked = objects::live().saturating_sub(objects_before);
    let saw = SAW.load(Ordering::Acquire);
    match saw {
        SAW_SAME => c.write_str("a lookup held across its channel's close still named it"),
        SAW_REUSED => c.write_str("A CHANNEL WAS FREED UNDER A LOOKUP AND REUSED"),
        SAW_MISSING => c.write_str("the lookup FOUND NO CHANNEL"),
        SAW_NEVER_CLOSED => c.write_str("the channel was NEVER CLOSED"),
        _ => c.write_str("the lookup NEVER FINISHED"),
    }
    c.write_str("; ");
    write_usize(c, made);
    c.write_str(" channels made in its place");
    if !ended {
        c.write_str("; THE LOOKUP THREAD NEVER ENDED");
    }
    c.write_str("; ");
    write_usize(c, leaked);
    c.write_str(if leaked == 0 {
        " objects left ok"
    } else {
        " OBJECTS LEFT after the last reference"
    });
    Check::from_ok(saw == SAW_SAME && ended && made > 0 && leaked == 0)
}

/// Build, look up, close, reuse, and let the lookup finish. Returns how many channels were
/// made after the close and whether the lookup thread ended.
fn race(program: &elf::Program) -> (usize, bool) {
    if userproc::build(SLOT, program).is_none() {
        return (0, false);
    }
    let Some(endpoint) =
        userproc::channel_pair(SLOT).and_then(|(a, _)| userproc::endpoint_object(SLOT, a))
    else {
        userproc::teardown(SLOT);
        return (0, false);
    };
    ENDPOINT.store(endpoint.raw(), Ordering::Release);
    let Some(id) = preempt::spawn(STACK, lookup, 0, PRIORITY) else {
        userproc::teardown(SLOT);
        return (0, false);
    };
    let give_up = timekeeping::now().saturating_add(PATIENCE);
    while !LOOKED.load(Ordering::Acquire) && timekeeping::now() < give_up {
        sleep_until(timekeeping::now().saturating_add(POLL));
    }
    // Close: the process that made the channel, and every handle to both its endpoints, go.
    userproc::teardown(SLOT);
    // Reuse: as many channels as there is room for, in a process of their own.
    let mut made = 0;
    if userproc::build(SLOT, program).is_some() {
        while userproc::channel_pair(SLOT).is_some() {
            made += 1;
        }
    }
    CLOSED.store(true, Ordering::Release);
    let give_up = timekeeping::now().saturating_add(PATIENCE);
    while preempt::alive(id) && timekeeping::now() < give_up {
        sleep_until(timekeeping::now().saturating_add(POLL));
    }
    let ended = !preempt::alive(id) && preempt::reap(id);
    userproc::teardown(SLOT);
    (made, ended)
}

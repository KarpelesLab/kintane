//! Waiting on several things at once: one wait, a set of objects, and whichever is ready first.
//!
//! Every wait before this one named a single object — a channel's message, an event's signal, a
//! socket's bytes — and a program that had two things to wait for had to choose one and be deaf
//! to the other. That is the wall a ported program hits first: a server with two connections, a
//! client with a timeout, anything that reads from one place while watching another.
//!
//! # One queue, woken by every change
//!
//! A thread can register on one wait queue at a time ([`crate::wait`]), so a wait over a set
//! cannot be a wait on each member's queue. Instead every change that could make *anything*
//! ready wakes [`POLL`] as well as the queue it already woke:
//!
//! * `crate::objects` — a channel's message, an event's signal, a completion posted, a process
//!   ended, an object destroyed;
//! * `crate::sockets` — the card's interrupt after it has run the stack, a shutdown, a close;
//! * the Linux personality's pipes — bytes written, room made, an end closed.
//!
//! Each of those already wakes something; [`wake`] is called beside it, from the same place,
//! after the change. A wake nobody is waiting for costs one lock and one loop over eight empty
//! slots.
//!
//! # Why a wake cannot be lost
//!
//! [`crate::wait::WaitQueue::wait_once`] checks the condition, registers the thread, checks
//! again, and only then blocks, and every waker changes state before it wakes. The second check
//! is what closes the gap: readiness that arrived while the first check was running is seen by
//! the second, and readiness that arrives after it finds the thread registered. A waiter over a
//! set inherits that exactly, because its condition is "any member is ready" — one closure that
//! looks at every member, run at both checks. What it must not do is look once, sleep on a
//! deadline, and hope; nothing here does.
//!
//! # What readiness means
//!
//! [`READ`], [`WRITE`], [`ERROR`] and [`CLOSED`], from `abi::ready`. Readiness is a *promise
//! about the next call*: `READ` means a receive would not have to wait, `CLOSED` that the other
//! end is gone and a receive would report the end rather than wait. It is computed without
//! taking anything: a socket's bytes stay queued, a channel's message stays in the channel, an
//! event stays signalled. A program that is told a thing is ready and then takes it is the only
//! one that consumes it, which is what makes this safe to share between threads that are all
//! watching the same object.
//!
//! Nothing here is edge-triggered. A member that stays ready is reported ready every time, which
//! is what `poll` and `select` mean by level-triggered and what the Linux personality needs.
//!
//! # The timer that nothing wakes
//!
//! Two deadlines can end a wait besides the caller's own timeout. A socket in the set means the
//! network's next TCP timer may change readiness with no frame arriving, so the wait looks again
//! then ([`crate::sockets::next_look`]). A timer object in the set delivers a completion when it
//! falls due, so the wait looks again then too. Both are *floors on looking*, never on
//! answering: a look that finds nothing ready waits again.

mod check;

pub use check::check;

use core::sync::atomic::Ordering;

use kobject::ObjectType;
use kobject::handle::Entry;

use crate::objects::{self, Object};
use crate::wait::WaitQueue;
use crate::{AtomicU64, timekeeping};

/// The one queue a wait over a set registers on.
static POLL: WaitQueue = WaitQueue::new();

/// Waiting threads a change made runnable, and waits that ended at a look rather than a wake.
static WOKEN: AtomicU64 = AtomicU64::new(0);
static LOOKS: AtomicU64 = AtomicU64::new(0);

/// Readiness a program may ask about, and hear about. `ERROR` and `CLOSED` are reported
/// whether or not they were asked for: a set whose member has failed must not wait for it.
pub use abi::ready::{CLOSED, ERROR, READ, WRITE};

/// Objects one wait may name. Eight is what a queue holds waiters, and what a program's own
/// handle table is sized for; a larger set belongs to a program that should hold fewer things.
pub const MAX_SET: usize = 8;

/// Bytes one entry of a set takes in the array a program passes: the handle, then the interest.
pub const ENTRY_BYTES: usize = 8;

/// One member of a set, as the call resolved it: the table entry its handle named, and what
/// the caller asked to hear about.
#[derive(Clone, Copy)]
pub struct Watch {
    pub entry: Entry,
    pub interest: u32,
}

impl Watch {
    /// A member of no set: what the unused tail of a fixed-size set holds.
    pub const NOTHING: Watch = Watch {
        entry: Entry {
            object: kobject::ObjectId::from_raw(0),
            kind: ObjectType::Process,
            rights: kobject::Rights::empty(),
        },
        interest: 0,
    };

    pub fn is_socket(&self) -> bool {
        self.entry.kind == ObjectType::Socket
    }

    /// What this member is ready for, narrowed to what was asked about. `ERROR` and `CLOSED`
    /// come back whether or not they were asked for: a set with a dead member must not wait.
    pub fn ready(&self) -> u32 {
        of(self.entry) & (self.interest | ERROR | CLOSED)
    }
}

/// The queue a wait over a set registers on.
pub fn queue() -> &'static WaitQueue {
    &POLL
}

/// Something that could have made a member of some set ready has happened. Called after the
/// change, beside the wake of whatever queue already had one.
pub fn wake() {
    let woke = POLL.wake_all();
    WOKEN.fetch_add(woke as u64, Ordering::Relaxed);
}

/// What the waits over sets have done since boot.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Stats {
    /// Blocked waiters a change made runnable.
    pub woken: u64,
    /// Times a wait looked at its set: once before blocking, once after registering, and once
    /// per wake or deadline after that.
    pub looks: u64,
}

pub fn stats() -> Stats {
    Stats {
        woken: WOKEN.load(Ordering::Relaxed),
        looks: LOOKS.load(Ordering::Relaxed),
    }
}

/// The readiness of the object `entry` names, narrowed to the rights the handle carries: a
/// handle without `READ` is never reported readable, as a receive on it would be refused.
///
/// Takes nothing and consumes nothing; see the module documentation.
pub fn of(entry: Entry) -> u32 {
    LOOKS.fetch_add(1, Ordering::Relaxed);
    let raw = match entry.kind {
        ObjectType::Socket => socket_ready(entry),
        _ => object_ready(entry),
    };
    let mut allowed = ERROR | CLOSED;
    if entry.rights.contains(kobject::Rights::READ) {
        allowed |= READ;
    }
    if entry.rights.contains(kobject::Rights::WRITE) {
        allowed |= WRITE;
    }
    // A process is waited on, not read: its end is its readiness, and `WAIT` is what names it.
    if entry.kind == ObjectType::Process && entry.rights.contains(kobject::Rights::WAIT) {
        allowed |= READ;
    }
    raw & allowed
}

/// The readiness of everything but a socket, from the object itself.
fn object_ready(entry: Entry) -> u32 {
    if entry.kind == ObjectType::Channel {
        return endpoint_ready(entry);
    }
    if entry.kind == ObjectType::Completion {
        // A timer's expiration reaches its queue when the queue is looked at, not from the
        // timer interrupt (see `objects::deliver_due_timers`), so a wait that only read the
        // queue's length would sleep through every timer it was watching for.
        let _ = objects::deliver_due_timers(entry.object, timekeeping::now().as_nanos());
    }
    objects::with(entry.object, |o| match o {
        Object::Completion { len, .. } => {
            if *len > 0 {
                READ
            } else {
                0
            }
        }
        Object::Event { signalled } => {
            if *signalled {
                READ
            } else {
                0
            }
        }
        Object::Process { exited, .. } => {
            if *exited {
                READ | CLOSED
            } else {
                0
            }
        }
        // A timer is not waited on itself: its completion queue is what a program watches.
        Object::Timer { .. } => 0,
        Object::Free => ERROR,
        _ => 0,
    })
    .unwrap_or(ERROR)
}

/// A channel endpoint's readiness: a queued message, room to send, and whether the peer is
/// gone. Asked of the channel rather than of the cell, because the queue lives there.
fn endpoint_ready(entry: Entry) -> u32 {
    let Some(chan) = objects::channel(entry.object) else {
        // The channel is gone: the handle names an endpoint of nothing, which a receive
        // answers at once rather than waiting on.
        return ERROR | CLOSED;
    };
    let Some(status) = chan.status_of(entry.object) else {
        return ERROR | CLOSED;
    };
    let mut bits = 0;
    if status.queued > 0 {
        bits |= READ;
    }
    if status.writable {
        bits |= WRITE;
    }
    if status.peer_closed {
        // Nothing more will arrive; what is queued is still readable until it is taken.
        bits |= CLOSED | READ;
    }
    bits
}

/// A socket's readiness, from the connection's state: bytes waiting or a listener with a
/// connection to take, room to send, the peer's close, and a connection that failed.
fn socket_ready(entry: Entry) -> u32 {
    let id = entry.object;
    if let Ok((listener, _)) = crate::sockets::listener(id) {
        return if crate::sockets::pending(listener) {
            READ
        } else {
            0
        };
    }
    let Ok(conn) = crate::sockets::connection(id) else {
        // Neither connected nor listening: nothing will happen to it until the program acts.
        return 0;
    };
    crate::sockets::readiness(conn)
}

/// When a wait over `set` must look again even if nothing wakes it, in kernel-clock
/// nanoseconds: the network's next TCP timer where a socket is watched, and a timer object's
/// deadline where its completion queue is.
pub fn next_look(has_socket: bool, queues: impl Iterator<Item = kobject::ObjectId>) -> Option<u64> {
    let now = timekeeping::now().as_nanos();
    let mut soonest = if has_socket {
        crate::sockets::next_look()
    } else {
        None
    };
    for queue in queues {
        if let Some(due) = objects::next_timer_for(queue) {
            soonest = Some(soonest.map_or(due, |s: u64| s.min(due)));
        }
    }
    soonest.map(|due| due.max(now))
}

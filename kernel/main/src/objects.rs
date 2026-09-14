//! The object namespace: what a handle names, and how long it lives.
//!
//! Until now a handle named a channel endpoint or the console, and the kernel built
//! processes itself. A program that is to *create* anything needs the other half: objects
//! it can name, hold, pass on, and be refused. This is that half, and it is where the
//! ABI's promise — a process has no authority except through handles it holds — stops
//! being a property of three hardcoded handles and becomes a property of the system.
//!
//! # Where an object lives
//!
//! [`kobject::store::ObjectStore`] holds a shared reference to each object and its
//! lifecycle; the object's memory belongs to whoever made it. There is no allocator here
//! yet, so the objects live in one static arena of [`Cell`]s, each a lock around an
//! [`Object`]. A cell is claimed by [`claim`] and released when the store destroys it.
//!
//! The store is the kernel's, not a process's: **objects are global, handles are
//! per-process**. That is what makes [`crate::userproc`]'s `process_transfer` a move of a
//! handle rather than a copy of an object — the same identity appears in another table,
//! and the object itself never moves.
//!
//! # The one locking rule
//!
//! A cell's lock is never held while taking another cell's. Posting a process's exit to a
//! completion queue reads the waiter under the process's lock, drops it, and only then
//! locks the queue. Every cell shares one lock class, so nesting two would be a lock-order
//! violation and `DEBUG_LOCKDEP` would say so — which is how this rule is enforced rather
//! than merely stated.

#![allow(unsafe_code)]

use core::cell::SyncUnsafeCell;

use arch::Cpu;
use kobject::handle::{Handle, HandleTable};
use kobject::store::{ObjectStore, StoreError};
use kobject::{ObjectId, ObjectIds, ObjectType, Rights};
use sched::ThreadId;
use sync::SpinLock;
use sync::lockdep::LockClass;

use crate::Locks;
use crate::wait::WaitQueue;

/// Objects that can exist at once, across every process. A spawn sequence uses six — an
/// image, a process, a thread, a completion queue and two channel endpoints — so this is
/// room for several at a time without an allocator.
pub const MAX_OBJECTS: usize = 32;

/// Completions a queue holds before it is full. A program that never polls is a program
/// whose queue fills; `Full` says so rather than dropping the oldest, because a lost
/// completion is a wait that never ends.
const QUEUE_DEPTH: usize = 8;

/// What an object is. The variants are the kinds a program can make today; each carries
/// only what the kernel must remember about it.
pub enum Object {
    /// The cell is unused.
    Free,
    /// A program image: bytes the kernel holds, from which processes are built.
    Image { bytes: &'static [u8] },
    /// A process, by the slot it occupies in [`crate::userproc`].
    Process {
        slot: usize,
        exited: bool,
        code: u64,
        /// Where to post this process's exit, and under what key. One waiter.
        waiter: Option<(ObjectId, u64)>,
    },
    /// A thread of a process.
    Thread {
        #[expect(
            dead_code,
            reason = "no call acts on a thread through its handle yet; every thread a program starts is reaped through `spawn`'s own record"
        )]
        id: ThreadId,
    },
    /// Anonymous memory, not yet mapped anywhere.
    Region { len: usize },
    /// Where finished asynchronous operations report.
    Completion {
        ring: [(u64, u64); QUEUE_DEPTH],
        head: usize,
        len: usize,
    },
    /// A latch: signalled by one thread, consumed by the thread that waits on it.
    Event { signalled: bool },
    /// A timer delivering to a completion queue. `deadline` is nanoseconds of the kernel
    /// clock, or [`DISARMED`].
    Timer {
        queue: ObjectId,
        key: u64,
        deadline: u64,
        /// Zero for a one-shot timer.
        period: u64,
        /// Expirations delivered so far.
        fires: u64,
    },
}

impl Object {
    /// An empty completion queue.
    pub fn new_completion() -> Object {
        Object::Completion {
            ring: [(0, 0); QUEUE_DEPTH],
            head: 0,
            len: 0,
        }
    }

    /// The type a handle to this object carries, which is what a system call checks before
    /// it looks any further.
    fn kind(&self) -> Option<ObjectType> {
        Some(match self {
            Object::Free => return None,
            Object::Image { .. } | Object::Region { .. } => ObjectType::MemoryRegion,
            Object::Process { .. } => ObjectType::Process,
            Object::Thread { .. } => ObjectType::Thread,
            Object::Completion { .. } => ObjectType::Completion,
            Object::Event { .. } => ObjectType::Event,
            Object::Timer { .. } => ObjectType::Timer,
        })
    }
}

/// One object's storage: a lock around it, so two CPUs can hold references to the same
/// object and still change it one at a time.
pub struct Cell {
    state: SpinLock<Object, Cpu>,
}

impl Cell {
    /// This cell's position in [`CELLS`], which is also its wait queue's in [`WAITS`].
    fn index(&self) -> usize {
        (self as *const Cell as usize).wrapping_sub(CELLS.as_ptr() as usize)
            / core::mem::size_of::<Cell>()
    }

    const fn new() -> Cell {
        Cell {
            state: SpinLock::with_class(Object::Free, &CELL_CLASS),
        }
    }

    /// Run `f` on this object's state.
    pub fn with<R>(&self, f: impl FnOnce(&mut Object) -> R) -> R {
        let mut guard = self.state.lock_irqsave();
        f(&mut guard)
    }
}

/// Every cell shares this class: nesting two cell locks is a lock-order violation, which
/// is exactly the rule this module keeps. See the module documentation.
static CELL_CLASS: LockClass = LockClass::new("objects.cell");

/// The arena. A cell is `Free` until [`claim`] fills it and again once the store destroys
/// it, so a cell is reused only after its object is gone.
static CELLS: [Cell; MAX_OBJECTS] = [const { Cell::new() }; MAX_OBJECTS];

/// The store, and the identities it hands out.
///
/// SAFETY INVARIANT: written once by [`init`], before any process exists, and read-only
/// after. A `LockFamily` lock cannot be built in a `const` initialiser, which is why this
/// is a cell rather than a plain static.
static STORE: SyncUnsafeCell<Option<ObjectStore<'static, Cell, Locks, MAX_OBJECTS>>> =
    SyncUnsafeCell::new(None);
static IDS: ObjectIds = ObjectIds::new();

/// Give a destroyed object's cell back. Called by the store when the last reference to an
/// object is gone, with no store lock held.
fn destroy(_id: ObjectId, cell: &'static Cell) {
    cell.with(|o| *o = Object::Free);
    // A thread waiting on the object checks again and finds it gone, rather than waiting
    // for a wake the object can no longer send.
    if let Some(waiters) = WAITS.get(cell.index()) {
        waiters.wake_all();
    }
}

/// The store, once [`init`] has made it.
fn store() -> Option<&'static ObjectStore<'static, Cell, Locks, MAX_OBJECTS>> {
    // SAFETY: see `STORE`: written once before any user thread runs, read-only after.
    unsafe { (*STORE.get()).as_ref() }
}

/// Make the store. Once, at boot, before any process exists.
pub fn init() {
    if store().is_some() {
        return;
    }
    // SAFETY: see `STORE`; boot is the only thread that reaches this, once.
    unsafe { *STORE.get() = Some(ObjectStore::new(destroy)) };
}

/// Objects alive right now, the store's own reference included. The accounting a check
/// compares against its baseline: an object left behind is a handle nobody closed or a
/// process nobody tore down.
pub fn live() -> usize {
    store().map_or(0, |s| s.len())
}

/// Put `object` in a free cell and register it under a fresh identity.
///
/// Returns the identity, which is what a handle table entry holds. The object is alive
/// until [`retire`] and every handle to it is gone.
pub fn create(object: Object) -> Option<ObjectId> {
    let store = store()?;
    let kind = object.kind()?;
    let id = IDS.next();
    let mut object = Some(object);
    for cell in CELLS.iter() {
        let claimed = cell.with(|o| {
            if matches!(o, Object::Free) {
                // `take` rather than a clone: an object exists in exactly one cell.
                if let Some(value) = object.take() {
                    *o = value;
                    return true;
                }
            }
            false
        });
        if !claimed {
            continue;
        }
        match store.insert(id, kind, cell) {
            Ok(_) => return Some(id),
            Err(_) => {
                // The store is full, so nothing can find this cell. Give it back rather
                // than leave an object alive that no identity names.
                cell.with(|o| *o = Object::Free);
                return None;
            }
        }
    }
    None
}

/// Run `f` on the object `id` names, if it is live.
pub fn with<R>(id: ObjectId, f: impl FnOnce(&mut Object) -> R) -> Option<R> {
    let reference = store()?.get(id).ok()?;
    Some(reference.with(f))
}

/// Run `f` on the object `handle` names in `table`, checking its type and rights first.
///
/// This is the path a system call takes, and the only one: the handle table decides
/// whether the caller may name the object at all, and the store decides whether the object
/// is still there.
pub fn with_handle<R, const N: usize>(
    table: &HandleTable<N>,
    handle: Handle,
    kind: ObjectType,
    required: Rights,
    f: impl FnOnce(&mut Object) -> R,
) -> Result<R, StoreError> {
    let reference = store()
        .ok_or(StoreError::NotFound)?
        .resolve(table, handle, kind, required)?;
    Ok(reference.with(f))
}

/// Give up the store's reference to `id`: nothing new finds it, and it is destroyed once
/// every outstanding reference is gone.
pub fn retire(id: ObjectId) {
    if let Some(store) = store() {
        let _ = store.retire(id);
    }
}

/// Post `(key, value)` to the completion queue `queue` names. `Full` if the queue is.
pub fn post(queue: ObjectId, key: u64, value: u64) -> Result<(), ()> {
    let posted = with(queue, |o| match o {
        Object::Completion { ring, head, len } => {
            if *len >= QUEUE_DEPTH {
                return Err(());
            }
            let at = (*head + *len) % QUEUE_DEPTH;
            ring[at] = (key, value);
            *len += 1;
            Ok(())
        }
        _ => Err(()),
    })
    .unwrap_or(Err(()));
    // After the queue's lock is released: a waker takes no cell lock while waking.
    if posted.is_ok()
        && let Some(waiters) = waiters(queue)
    {
        waiters.wake_all();
    }
    posted
}

/// Take the oldest completion from `queue`, or `None` if it is empty.
pub fn take(object: &mut Object) -> Option<(u64, u64)> {
    match object {
        Object::Completion { ring, head, len } if *len > 0 => {
            let entry = ring[*head];
            *head = (*head + 1) % QUEUE_DEPTH;
            *len -= 1;
            Some(entry)
        }
        _ => None,
    }
}

/// Record that the process in `slot` ended with `code`, and post it to whoever asked.
///
/// Called from the exit path, on the exiting thread. The waiter is read and cleared under
/// the process's own lock, which is then dropped before the queue's is taken: see the
/// module documentation.
pub fn on_process_exit(slot: usize, code: u64) {
    let mut post_to = None;
    for cell in CELLS.iter() {
        let found = cell.with(|o| match o {
            Object::Process {
                slot: s,
                exited,
                code: stored,
                waiter,
            } if *s == slot && !*exited => {
                *exited = true;
                *stored = code;
                post_to = waiter.take();
                true
            }
            _ => false,
        });
        if found {
            break;
        }
    }
    if let Some((queue, key)) = post_to {
        let _ = post(queue, key, code);
    }
}

// ---- waiting on objects -------------------------------------------------------------------

/// One wait queue per cell, beside it. A queue belongs to whatever object occupies its cell;
/// a waiter on an object that is destroyed and whose cell is reused may be woken spuriously,
/// which a waiter tolerates by checking again.
static WAITS: [WaitQueue; MAX_OBJECTS] = [const { WaitQueue::new() }; MAX_OBJECTS];

/// The identities every object is issued from, store object or channel endpoint alike.
///
/// One source for both, and not one per process: a channel is found by its endpoints'
/// identities in a kernel-wide table, so two processes' channels must never share one.
pub fn ids() -> &'static ObjectIds {
    &IDS
}

/// Wake every thread waiting on any object. For a process ending while some of its threads
/// wait: each checks again, finds its process ending, and ends too.
pub fn wake_all_waiters() {
    for waiters in &WAITS {
        waiters.wake_all();
    }
}

/// The wait queue of the object `id` names, while it is live.
pub fn waiters(id: ObjectId) -> Option<&'static WaitQueue> {
    let reference = store()?.get(id).ok()?;
    WAITS.get(reference.index())
}

/// Signal the event `id` names and wake whoever waits on it. `false` if it is not an event.
pub fn signal_event(id: ObjectId) -> bool {
    let signalled = with(id, |o| match o {
        Object::Event { signalled } => {
            *signalled = true;
            true
        }
        _ => false,
    })
    .unwrap_or(false);
    if signalled && let Some(waiters) = waiters(id) {
        waiters.wake_all();
    }
    signalled
}

/// Consume the event `id`'s signal. `Some(true)` if it was signalled, `Some(false)` if not,
/// `None` if `id` is no longer a live event.
pub fn consume_event(id: ObjectId) -> Option<bool> {
    with(id, |o| match o {
        Object::Event { signalled } => Some(core::mem::replace(signalled, false)),
        _ => None,
    })?
}

// ---- timers -------------------------------------------------------------------------------

/// A timer's deadline when it is not armed.
pub const DISARMED: u64 = u64::MAX;

static DELIVERY_CLASS: LockClass = LockClass::new("objects.delivery");

/// Serialises every change to a timer's schedule and every delivery, so one expiration is
/// posted once however many threads wait on its queue. Taken before any cell lock, and cell
/// locks are taken inside it one at a time, never two at once.
static DELIVERY: SpinLock<(), Cpu> = SpinLock::with_class((), &DELIVERY_CLASS);

/// Arm (`deadline` in kernel-clock nanoseconds) or disarm ([`DISARMED`]) the timer `id`.
/// Wakes its queue's waiters, whose deadline may now be sooner. `false` if `id` is not a timer.
pub fn set_timer(id: ObjectId, deadline: u64, period: u64) -> bool {
    let queue = {
        let _serial = DELIVERY.lock_irqsave();
        with(id, |o| match o {
            Object::Timer {
                queue,
                deadline: d,
                period: p,
                ..
            } => {
                *d = deadline;
                *p = period;
                Some(*queue)
            }
            _ => None,
        })
        .flatten()
    };
    match queue {
        Some(queue) => {
            if let Some(waiters) = waiters(queue) {
                waiters.wake_all();
            }
            true
        }
        None => false,
    }
}

/// Deliver every timer on `queue` whose deadline is at or before `now`, and return the
/// earliest deadline still armed on it.
///
/// Delivery happens when the queue is looked at — by a wait, which [`crate::userproc`]
/// makes end at the earliest armed deadline, or by a poll — not from the timer interrupt.
/// A thread blocked on the queue is therefore woken at the deadline, which is when the
/// completion can be seen, and nothing posts to a completion queue in interrupt context.
///
/// Each delivery's value is how many expirations it reports: one for a one-shot timer, and
/// every period that elapsed for a periodic one. A full queue leaves the timer due, so its
/// expirations are delivered once there is room rather than lost.
pub fn deliver_due_timers(queue: ObjectId, now: u64) -> Option<u64> {
    let _serial = DELIVERY.lock_irqsave();
    let mut earliest: Option<u64> = None;
    let mut note = |d: u64| earliest = Some(earliest.map_or(d, |e| e.min(d)));
    for cell in CELLS.iter() {
        let due = cell.with(|o| match o {
            Object::Timer {
                queue: q,
                key,
                deadline,
                period,
                ..
            } if *q == queue && *deadline != DISARMED => {
                if *deadline > now {
                    Some(Err(*deadline))
                } else if *period == 0 {
                    Some(Ok((*key, 1)))
                } else {
                    Some(Ok((*key, (now - *deadline) / *period + 1)))
                }
            }
            _ => None,
        });
        match due {
            Some(Ok((key, expirations))) => {
                if post(queue, key, expirations).is_err() {
                    continue;
                }
                let next = cell.with(|o| match o {
                    Object::Timer {
                        deadline,
                        period,
                        fires,
                        ..
                    } => {
                        *fires += expirations;
                        if *period == 0 {
                            *deadline = DISARMED;
                        } else {
                            *deadline = deadline.saturating_add(expirations * *period);
                        }
                        (*deadline != DISARMED).then_some(*deadline)
                    }
                    _ => None,
                });
                if let Some(next) = next {
                    note(next);
                }
            }
            Some(Err(deadline)) => note(deadline),
            None => {}
        }
    }
    earliest
}

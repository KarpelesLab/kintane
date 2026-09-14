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
use core::ops::Deref;
use core::sync::atomic::{AtomicPtr, Ordering};

use arch::Cpu;
use kobject::handle::{Entry, Handle, HandleTable};
use kobject::store::{ObjRef, ObjectStore, StoreError};
use kobject::{ObjectId, ObjectIds, ObjectType, Rights};
use sched::ThreadId;
use sync::SpinLock;
use sync::lockdep::LockClass;

use crate::wait::WaitQueue;
use crate::{AtomicBool, AtomicUsize, Locks};

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
    /// One endpoint of the channel in [`CHANNELS`] slot `channel`. See "Channels" below.
    Endpoint { channel: usize },
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
    /// A TCP socket. `port` is the local port `socket_bind` gave it, zero until then; `conn`
    /// is the network stack's name for its connection or listener, once it has one (a
    /// `net::Conn`'s raw word). See [`crate::sockets`].
    Socket {
        port: u16,
        conn: Option<u64>,
        listening: bool,
    },
    /// A datagram socket. `port` is the local port it was bound to or given, zero until it has
    /// one; `peer` is the address a connected one sends to and takes datagrams from, as an
    /// `abi::socket` address word. It holds no connection, because UDP has none: what it holds
    /// is its port, which [`crate::sockets`] gives back when the object is destroyed.
    Datagram { port: u16, peer: Option<u64> },
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
            Object::Endpoint { .. } => ObjectType::Channel,
            Object::Timer { .. } => ObjectType::Timer,
            Object::Socket { .. } | Object::Datagram { .. } => ObjectType::Socket,
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
    crate::readiness::wake();
    let (endpoint_of, connection, datagram_port) = cell.with(|o| {
        let taken = match o {
            Object::Endpoint { channel } => (Some(*channel), None, 0),
            Object::Socket { conn, .. } => (None, conn.take(), 0),
            Object::Datagram { port, .. } => (None, None, *port),
            _ => (None, None, 0),
        };
        *o = Object::Free;
        taken
    });
    // A socket's connection is closed in order once nothing names it, after the cell's lock
    // is released: the network stack's lock is never taken inside a cell's.
    if let Some(conn) = connection {
        crate::sockets::release(conn);
    }
    // A datagram socket holds a port rather than a connection, and it is free for the next
    // socket once nothing names this one.
    if datagram_port != 0 {
        crate::sockets::release_port(datagram_port);
    }
    // A thread waiting on the object checks again and finds it gone, rather than waiting
    // for a wake the object can no longer send.
    if let Some(waiters) = WAITS.get(cell.index()) {
        waiters.wake_all();
    }
    // After the cell's lock is released: freeing a channel wakes its queue.
    if let Some(channel) = endpoint_of {
        endpoint_gone(channel);
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
    create_as(IDS.next(), object)
}

/// [`create`], under an identity already issued from [`ids`]: a channel's endpoints get
/// theirs from `ipc::Channel::new`.
fn create_as(id: ObjectId, object: Object) -> Option<ObjectId> {
    let store = store()?;
    let kind = object.kind()?;
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
    crate::readiness::wake();
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
    crate::readiness::wake();
    let mut post_to = None;
    let mut waiting = None;
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
            waiting = WAITS.get(cell.index());
            break;
        }
    }
    if let Some((queue, key)) = post_to {
        let _ = post(queue, key, code);
    }
    // After the post, so a thread woken from `process_wait` finds a queued exit there too.
    if let Some(waiters) = waiting {
        waiters.wake_all();
    }
}

/// The exit code of the process `id` names: `Some(None)` while it runs, `None` if `id` is not
/// a live process.
pub fn exit_code(id: ObjectId) -> Option<Option<u64>> {
    with(id, |o| match o {
        Object::Process { exited, code, .. } => Some(exited.then_some(*code)),
        _ => None,
    })?
}

// ---- channels -----------------------------------------------------------------------------
//
// A channel's two endpoints are objects in the store like any other: found by identity,
// retired when they close, destroyed when nothing references them. The channel itself — its
// two inboxes — lives in a slot of `CHANNELS` for as long as either endpoint object exists,
// and a lookup ([`channel`]) holds a counted reference to the endpoint it looked up. So a
// channel whose last handle closes while another thread still uses what it looked up is not
// freed under that thread: it is freed when that thread lets go.
//
// An endpoint is retired when its channel says it has closed — its last handle closed, or the
// last message carrying it thrown away — not when one of several references to it goes. Every
// path that gives an endpoint reference back goes through [`release`] or [`close_endpoint`],
// so the channel's count and the store's cannot disagree.

/// A channel: four messages each way, each of at most 64 bytes and two handles.
pub type Chan = ipc::Channel<Locks, 4, 64, 2>;

/// Channels that can exist at once.
pub const MAX_CHANNELS: usize = 8;

/// One channel's storage.
struct ChannelSlot {
    /// SAFETY INVARIANT: written by [`new_channel`] while it holds `claimed` and before any
    /// endpoint object names this slot; taken by [`endpoint_gone`] once `ends` reaches zero,
    /// when none does. In between it is only read — through a [`ChanRef`], which holds an
    /// endpoint object alive — and changed only under `Chan`'s own lock.
    chan: SyncUnsafeCell<Option<Chan>>,
    claimed: AtomicBool,
    /// Endpoint objects of this channel the store has not destroyed.
    ends: AtomicUsize,
    /// Threads waiting to receive on either end: one queue for both, since a wake that finds
    /// nothing for its end costs only a second look. Woken by every send, by an end closing,
    /// and by the channel being freed.
    waits: WaitQueue,
    /// A second queue every wake of `waits` also wakes, or null: for a thread that waits on
    /// many channels at once in a queue of its own (`crate::fileserver`). Only `'static`
    /// queues are stored here.
    relay: AtomicPtr<WaitQueue>,
}

impl ChannelSlot {
    /// Wake this channel's waiters, and its relay's.
    fn wake(&self) {
        crate::readiness::wake();
        self.waits.wake_all();
        // SAFETY: see `relay`: null, or a `'static` queue.
        if let Some(relay) = unsafe { self.relay.load(Ordering::Acquire).as_ref() } {
            relay.wake_all();
        }
    }
}

static CHANNELS: [ChannelSlot; MAX_CHANNELS] = [const {
    ChannelSlot {
        chan: SyncUnsafeCell::new(None),
        claimed: AtomicBool::new(false),
        ends: AtomicUsize::new(0),
        waits: WaitQueue::new(),
        relay: AtomicPtr::new(core::ptr::null_mut()),
    }
}; MAX_CHANNELS];

/// A channel, held through one of its endpoints: it is not freed while this lives.
pub struct ChanRef {
    _endpoint: ObjRef<'static, 'static, Cell, Locks, MAX_OBJECTS>,
    slot: &'static ChannelSlot,
    chan: &'static Chan,
}

impl ChanRef {
    /// The queue threads waiting to receive on this channel wait in.
    pub fn waiters(&self) -> &'static WaitQueue {
        &self.slot.waits
    }

    /// From now until the channel is freed, wake `queue` too whenever this channel's waiters
    /// are woken.
    pub fn relay_to(&self, queue: &'static WaitQueue) {
        self.slot
            .relay
            .store(core::ptr::from_ref(queue).cast_mut(), Ordering::Release);
    }

    /// Wake this channel's waiters, and its relay's.
    pub fn wake(&self) {
        self.slot.wake();
    }
}

impl Deref for ChanRef {
    type Target = Chan;

    fn deref(&self) -> &Chan {
        self.chan
    }
}

/// Make a channel. Returns one entry per endpoint, each that endpoint's only reference, to be
/// installed in a handle table or given back with [`release`]. `None` if no channel slot or
/// no object is free.
pub fn new_channel() -> Option<[Entry; 2]> {
    let (index, slot) = CHANNELS.iter().enumerate().find(|(_, s)| {
        s.claimed
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    })?;
    let (chan, entries) = Chan::new(&IDS, ipc::ENDPOINT_RIGHTS);
    // SAFETY: see `ChannelSlot::chan`: claimed above, and no endpoint object names it yet.
    unsafe { *slot.chan.get() = Some(chan) };
    slot.ends.store(0, Ordering::Release);
    let mut first = None;
    for entry in entries {
        // Counted before the object exists, so its destruction always has a count to take.
        slot.ends.fetch_add(1, Ordering::AcqRel);
        if create_as(entry.object, Object::Endpoint { channel: index }).is_none() {
            // This endpoint never existed. The other, if it did, is retired, and its
            // destruction frees the slot; otherwise nothing names the slot and it is freed now.
            endpoint_gone(index);
            if let Some(made) = first {
                retire(made);
            }
            return None;
        }
        first.get_or_insert(entry.object);
    }
    Some(entries)
}

/// The channel `endpoint` is an end of, held for as long as the result lives. `None` if
/// `endpoint` names no live endpoint.
pub fn channel(endpoint: ObjectId) -> Option<ChanRef> {
    let reference = store()?.get(endpoint).ok()?;
    let index = reference.with(|o| match o {
        Object::Endpoint { channel } => Some(*channel),
        _ => None,
    })?;
    let slot = CHANNELS.get(index)?;
    // SAFETY: see `ChannelSlot::chan`: `reference` holds an endpoint object of this slot's
    // channel alive, so the slot was filled before it and is not emptied while it lives.
    let chan = unsafe { (*slot.chan.get()).as_ref() }?;
    Some(ChanRef {
        _endpoint: reference,
        slot,
        chan,
    })
}

/// One endpoint object of the channel in slot `index` has been destroyed; free the channel
/// with the last.
fn endpoint_gone(index: usize) {
    let Some(slot) = CHANNELS.get(index) else {
        return;
    };
    if slot.ends.fetch_sub(1, Ordering::AcqRel) != 1 {
        return;
    }
    // SAFETY: see `ChannelSlot::chan`: no endpoint object of this channel exists, so no
    // `ChanRef` to it does either.
    drop(unsafe { (*slot.chan.get()).take() });
    // A thread still waiting on it looks again and finds it gone.
    slot.wake();
    slot.relay.store(core::ptr::null_mut(), Ordering::Release);
    slot.claimed.store(false, Ordering::Release);
}

/// Give back a reference to the object `entry` names that no handle table holds any more: a
/// handle closed, a table torn down, a handle in a message nobody will receive. An endpoint
/// goes back through its channel, so its peer sees it close, and is retired once the channel
/// says it has closed; anything else is retired.
pub fn release(entry: Entry) {
    if entry.kind == ObjectType::Channel
        && let Some(chan) = channel(entry.object)
    {
        // Handles queued for an end that closes come back here, one at a time.
        let _ = chan.release(entry, release);
        after_release(&chan, entry.object);
        return;
    }
    retire(entry.object);
}

/// Close handle `h`, an endpoint of `chan`, in `table`, as [`release`] gives one back.
pub fn close_endpoint<const N: usize>(
    chan: &ChanRef,
    table: &mut HandleTable<N>,
    h: Handle,
) -> Result<(), ipc::Error> {
    let object = table.get(h).map_err(ipc::Error::Endpoint)?.object;
    chan.close(table, h, release)?;
    after_release(chan, object);
    Ok(())
}

/// A reference to `endpoint` went back to `chan`: retire the endpoint if that closed it, and
/// wake the channel's waiters either way.
fn after_release(chan: &ChanRef, endpoint: ObjectId) {
    if chan
        .side_of(endpoint)
        .is_some_and(|side| !chan.is_open(side))
    {
        retire(endpoint);
    }
    chan.wake();
}

/// Wake whoever waits on the channel `endpoint` is an end of.
pub fn wake_channel(endpoint: ObjectId) {
    if let Some(chan) = channel(endpoint) {
        chan.wake();
    }
}

/// Wake every thread waiting on any channel.
pub fn wake_all_channel_waiters() {
    for slot in &CHANNELS {
        slot.wake();
    }
}

// ---- waiting on objects -------------------------------------------------------------------

/// One wait queue per cell, beside it. A queue belongs to whatever object occupies its cell;
/// a waiter on an object that is destroyed and whose cell is reused may be woken spuriously,
/// which a waiter tolerates by checking again.
static WAITS: [WaitQueue; MAX_OBJECTS] = [const { WaitQueue::new() }; MAX_OBJECTS];

/// Wake every thread waiting on any object. For a process ending while some of its threads
/// wait: each checks again, finds its process ending, and ends too.
pub fn wake_all_waiters() {
    crate::readiness::wake();
    for waiters in &WAITS {
        waiters.wake_all();
    }
    // A socket call waits on the network's one queue rather than its object's, and with nothing
    // arriving and no TCP timer pending nothing else would wake it.
    crate::sockets::waits().wake_all();
}

/// The wait queue of the object `id` names, while it is live.
pub fn waiters(id: ObjectId) -> Option<&'static WaitQueue> {
    let reference = store()?.get(id).ok()?;
    WAITS.get(reference.index())
}

/// Signal the event `id` names and wake whoever waits on it. `false` if it is not an event.
pub fn signal_event(id: ObjectId) -> bool {
    crate::readiness::wake();
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
/// When the soonest armed timer delivering to `queue` falls due, in kernel-clock nanoseconds.
///
/// Delivers nothing and changes nothing: a wait over a set of objects asks this to know when it
/// must look again, since a timer's completion appears without anything waking a queue
/// (`crate::readiness`).
pub fn next_timer_for(queue: ObjectId) -> Option<u64> {
    let mut earliest: Option<u64> = None;
    for cell in CELLS.iter() {
        let due = cell.with(|o| match o {
            Object::Timer {
                queue: q, deadline, ..
            } if *q == queue && *deadline != DISARMED => Some(*deadline),
            _ => None,
        });
        if let Some(due) = due {
            earliest = Some(earliest.map_or(due, |e: u64| e.min(due)));
        }
    }
    earliest
}

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

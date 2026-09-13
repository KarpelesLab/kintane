//! Channel ping-pong that moves a handle there and back.
//!
//! Two threads, each with a handle table of its own, hold the two ends of one channel.
//! `ping` owns an event object. Each round trip it sends a sequence number with the
//! event's handle transferred, so its own table loses the handle. `pong` receives both,
//! checks the number is the next one and the handle arrived as an event, and sends the
//! same bytes back with the handle transferred again. `ping` checks the reply names the
//! same object it sent. Neither thread blocks on the channel: an empty or full endpoint
//! is a yield, which at the lowest workload level passes the CPU along the level.
//!
//! # Checkpoints
//!
//! `ping` stops only between round trips, with the event back in its table. `pong` stops
//! only once `ping` has, and only with nothing queued for it, so no message is ever in
//! flight while both are stopped, and the auditor's checks are exact: two handles in
//! `ping`'s table, one in `pong`'s, nothing queued at either end.
//!
//! # Handle slot retirement
//!
//! Every receive installs a handle and every send takes one out, and a slot whose
//! generation would wrap is retired for good (`kobject::handle`). Slots are reused
//! lowest first, so a table retires one slot per million round trips through it. The
//! tables here are sized so that a day of the fastest ping-pong QEMU runs does not
//! retire them all; a table that did would fail the run with a refused receive, which
//! is what that limit looks like in a long-lived process.

use core::cell::SyncUnsafeCell;
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use ipc::{Channel, ENDPOINT_RIGHTS, Error, Transfer};
use kobject::handle::{Handle, HandleTable};
use kobject::{ObjectId, ObjectIds, ObjectType, Rights};

use super::{Parked, Workload, checkpoint, fail, park_requested, parked, progress};
use crate::Locks;
use crate::preempt::{begin, yield_now};

/// Slots per table. See the module comment.
const SLOTS: usize = 256;

type Chan = Channel<Locks, 2, 8, 1>;

/// SAFETY INVARIANT: written once by [`setup`], on the boot thread before either thread
/// exists, and only shared (`&Chan`) from then on.
static CHANNEL: SyncUnsafeCell<MaybeUninit<Chan>> = SyncUnsafeCell::new(MaybeUninit::uninit());
static READY: AtomicBool = AtomicBool::new(false);

/// SAFETY INVARIANT: `TABLES[0]` is reached only by [`setup`] before the threads exist,
/// then only by `ping`; `TABLES[1]` likewise by `pong`, and by [`audit`] only while
/// both threads are parked, when neither touches its table.
static TABLES: [SyncUnsafeCell<HandleTable<SLOTS>>; 2] =
    [const { SyncUnsafeCell::new(HandleTable::new()) }; 2];

/// Each side's endpoint handle, and `ping`'s event handle as it currently is.
static ENDPOINT: [AtomicU32; 2] = [const { AtomicU32::new(0) }; 2];
static EVENT: AtomicU32 = AtomicU32::new(0);

static IDS: ObjectIds = ObjectIds::new();
/// The event object's identity, low half and high half.
static EVENT_ID: [AtomicU32; 2] = [const { AtomicU32::new(0) }; 2];

fn channel() -> &'static Chan {
    // SAFETY: see `CHANNEL`; `READY` is set only after it was written, and the threads
    // that call this are spawned after that.
    unsafe { (*CHANNEL.get()).assume_init_ref() }
}

fn event_id() -> ObjectId {
    let lo = u64::from(EVENT_ID[0].load(Ordering::Relaxed));
    let hi = u64::from(EVENT_ID[1].load(Ordering::Relaxed));
    ObjectId::from_raw(lo | hi << 32)
}

/// Create the channel and the event, and install them.
pub fn setup() -> Result<(), &'static str> {
    if READY.swap(true, Ordering::Relaxed) {
        return Err("channel already set up");
    }
    let (ch, [a, b]) = Chan::new(&IDS, ENDPOINT_RIGHTS);
    // SAFETY: see `CHANNEL`: the only write, before any reader exists.
    unsafe { (*CHANNEL.get()).write(ch) };
    // SAFETY: see `TABLES`: no thread exists yet.
    let (ta, tb) = unsafe { (&mut *TABLES[0].get(), &mut *TABLES[1].get()) };
    let ha = ta
        .insert(a.object, a.kind, a.rights)
        .map_err(|_| "endpoint A")?;
    let hb = tb
        .insert(b.object, b.kind, b.rights)
        .map_err(|_| "endpoint B")?;
    let event = IDS.next();
    let he = ta
        .insert(event, ObjectType::Event, Rights::READ.union(Rights::TRANSFER))
        .map_err(|_| "event")?;
    ENDPOINT[0].store(ha.raw(), Ordering::Relaxed);
    ENDPOINT[1].store(hb.raw(), Ordering::Relaxed);
    EVENT.store(he.raw(), Ordering::Relaxed);
    EVENT_ID[0].store(event.raw() as u32, Ordering::Relaxed);
    EVENT_ID[1].store((event.raw() >> 32) as u32, Ordering::Relaxed);
    Ok(())
}

/// The exact state with both threads parked; see the module comment.
pub fn audit() -> Result<(), &'static str> {
    // SAFETY: see `TABLES`: both threads are parked and not using them.
    let (ta, tb) = unsafe { (&*TABLES[0].get(), &*TABLES[1].get()) };
    if ta.len() != 2 {
        return Err("ping's table does not hold exactly its endpoint and the event");
    }
    if tb.len() != 1 {
        return Err("pong's table does not hold exactly its endpoint");
    }
    let ea = Handle::from_raw(ENDPOINT[0].load(Ordering::Relaxed));
    let eb = Handle::from_raw(ENDPOINT[1].load(Ordering::Relaxed));
    let queued = |t, e| channel().status(t, e).map(|s| s.queued);
    if queued(ta, ea) != Ok(0) || queued(tb, eb) != Ok(0) {
        return Err("a message is queued with both sides stopped");
    }
    let held = ta.get(Handle::from_raw(EVENT.load(Ordering::Relaxed)));
    if held.map(|e| e.object) != Ok(event_id()) {
        return Err("ping's event handle does not name the event");
    }
    Ok(())
}

pub extern "C" fn ping(_: usize) -> ! {
    begin();
    let w = Workload::Ping;
    // SAFETY: see `TABLES`: this thread owns table 0.
    let table = unsafe { &mut *TABLES[0].get() };
    let endpoint = Handle::from_raw(ENDPOINT[0].load(Ordering::Relaxed));
    let mut sequence = 0u64;
    loop {
        if park_requested() {
            checkpoint(w, Parked::Holding);
        }
        let event = Handle::from_raw(EVENT.load(Ordering::Relaxed));
        loop {
            match channel().send(
                table,
                endpoint,
                &sequence.to_le_bytes(),
                &[Transfer::whole(event)],
            ) {
                Ok(()) => break,
                Err(Error::Full) => yield_now(),
                Err(_) => {
                    fail(w, "a send was refused");
                    yield_now();
                }
            }
        }
        let mut bytes = [0u8; 8];
        let mut handles = [Handle::from_raw(0); 1];
        let back = loop {
            match channel().receive(table, endpoint, &mut bytes, &mut handles) {
                Ok(r) => break r,
                Err(Error::Empty) => yield_now(),
                Err(_) => {
                    fail(w, "a receive was refused");
                    yield_now();
                }
            }
        };
        if back.bytes != 8 || u64::from_le_bytes(bytes) != sequence {
            fail(w, "the reply did not carry the number sent");
        }
        if back.handles != 1 || table.get(handles[0]).map(|e| e.object) != Ok(event_id()) {
            fail(w, "the reply did not bring the event back");
        }
        EVENT.store(handles[0].raw(), Ordering::Relaxed);
        sequence = sequence.wrapping_add(1);
        progress(w);
    }
}

pub extern "C" fn pong(_: usize) -> ! {
    begin();
    let w = Workload::Pong;
    // SAFETY: see `TABLES`: this thread owns table 1.
    let table = unsafe { &mut *TABLES[1].get() };
    let endpoint = Handle::from_raw(ENDPOINT[1].load(Ordering::Relaxed));
    let mut expected = 0u64;
    loop {
        if park_requested() && parked(Workload::Ping) != Parked::Running {
            match channel().status(table, endpoint) {
                Ok(s) if s.queued == 0 => checkpoint(w, Parked::Empty),
                Ok(_) => {}
                Err(_) => fail(w, "status was refused"),
            }
        }
        let mut bytes = [0u8; 8];
        let mut handles = [Handle::from_raw(0); 1];
        let got = match channel().receive(table, endpoint, &mut bytes, &mut handles) {
            Ok(r) => r,
            Err(Error::Empty) => {
                yield_now();
                continue;
            }
            Err(_) => {
                fail(w, "a receive was refused");
                yield_now();
                continue;
            }
        };
        if got.bytes != 8 || u64::from_le_bytes(bytes) != expected {
            fail(w, "a message arrived out of sequence");
        }
        match table.get(handles[0]) {
            Ok(e) if got.handles == 1 && e.object == event_id() && e.kind == ObjectType::Event => {}
            _ => fail(w, "the event handle did not arrive"),
        }
        loop {
            match channel().send(table, endpoint, &bytes, &[Transfer::whole(handles[0])]) {
                Ok(()) => break,
                Err(Error::Full) => yield_now(),
                Err(_) => {
                    fail(w, "a reply was refused");
                    yield_now();
                }
            }
        }
        expected = expected.wrapping_add(1);
        progress(w);
    }
}

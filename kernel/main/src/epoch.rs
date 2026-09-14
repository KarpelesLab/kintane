//! Epoch-based reclamation on the real machine.
//!
//! `sync::epoch` is host-tested on threads playing CPUs. This checks the two claims that
//! matter on hardware.
//!
//! **Deferral**, on every port. A reader pinned on the boot CPU holds a node while a writer on
//! the same CPU unlinks it and collects repeatedly. The node must stay intact until the reader
//! unpins, and be reclaimed by the next flush.
//!
//! **Concurrency**, where secondary CPUs are online. Each secondary runs a reader that
//! repeatedly pins, loads the published node, reads its stamp twice with a pause between, and
//! unpins, until told to stop. Meanwhile the boot CPU replaces the node thousands of times,
//! retiring each one. Reclaiming a node poisons it and returns it to a small pool, and the
//! writer reuses pool nodes with new stamps. So a node reclaimed early shows up in a reader as
//! a torn read: the poison, or a stamp that changed under it. Every retired node must
//! eventually be reclaimed.
//!
//! The readers run inside the secondaries' function-call IPI, because nothing else runs code
//! on a secondary yet: there is no SMP scheduler. `arch::smp::call` waits up to a second for
//! its answer and the readers run far longer. So each call is expected to end *without* an
//! answer, with the reader still running, which is what lets the readers overlap each other
//! and the writer. That costs a second per secondary at boot. When secondaries have threads,
//! this becomes one reader thread per CPU.

use core::cell::SyncUnsafeCell;
use core::mem::MaybeUninit;
use core::sync::atomic::Ordering;

use arch::Cpu;
use hal::EarlyConsole;
use sync::epoch::{Collector, EpochPtr, RetireError};

use crate::{AtomicBool, AtomicU64, AtomicUsize, Check, Locks, write_usize};

/// Retirements a CPU's bag holds before it must reclaim.
///
/// Two per participant rather than a fixed eight, because an epoch turns only when every
/// pinned CPU has observed it: the more readers, the longer each retirement waits. That is
/// the sizing half of the eight-CPU fix, and the smaller half. A bag of any size fills when
/// a host deschedules the readers for long enough, so what makes the check correct is
/// [`publish`] waiting for room instead of failing on the first refusal.
///
/// Not larger, because the collector is built on the 16 KiB boot stack before it is moved
/// into its static, and at opt-level 1 that is a copy, not a construction in place. Four
/// per participant at eight CPUs made it 6.7 KiB, and aarch64's boot stack overflowed into
/// its guard page. Never below the eight it always was, so a uniprocessor build and any
/// with `NR_CPUS` up to four keep exactly the collector they had.
const BAG: usize = if 2 * SLOTS > 8 { 2 * SLOTS } else { 8 };
/// Nodes the writer cycles through: more than a bag's worth, so the writer is refused for
/// want of room in the bag — the case [`publish`] waits out — rather than for want of a
/// node, which would be the same shortage wearing a different message.
const POOL: usize = 2 * BAG;
/// Replacements the boot CPU makes while the readers run.
const WRITES: usize = 4000;
/// The most CPUs checked, including the boot CPU.
const CPUS: usize = 8;
/// Iterations after which a reader stops even if never told to, so a lost stop flag ends in a
/// failed check rather than a hung secondary.
const READER_BUDGET: u64 = 50_000_000;
/// Spins the boot CPU waits for the readers to stop before calling it a failure.
const STOP_PATIENCE: u64 = 400_000_000;
/// Spins a reader waits between its two reads of a node: the window in which a node
/// reclaimed too early would be seen changing.
const READ_PAUSE: usize = 4096;
/// A stamp no published node carries.
const POISON: u64 = u64::MAX;

/// Participant slots: one per configured CPU. `NR_CPUS` is zero without `SMP`, and a build
/// without `SMP` still has its boot CPU.
const SLOTS: usize = if kconfig::NR_CPUS > 1 {
    kconfig::NR_CPUS
} else {
    1
};

type Epochs = Collector<Cpu, Locks, SLOTS, BAG>;
type Head = EpochPtr<'static, Node, Cpu, Locks, SLOTS, BAG>;

struct Node {
    stamp: AtomicU64,
    free: AtomicBool,
}

static NODES: [Node; POOL] = [const {
    Node {
        stamp: AtomicU64::new(0),
        free: AtomicBool::new(true),
    }
}; POOL];

static COLLECTOR: SyncUnsafeCell<MaybeUninit<Epochs>> = SyncUnsafeCell::new(MaybeUninit::uninit());
static HEAD: SyncUnsafeCell<MaybeUninit<Head>> = SyncUnsafeCell::new(MaybeUninit::uninit());
/// Set once both statics above are written, and never cleared.
static READY: AtomicBool = AtomicBool::new(false);

static RECLAIMED: AtomicUsize = AtomicUsize::new(0);
static STOP: AtomicBool = AtomicBool::new(false);
static TORN: AtomicUsize = AtomicUsize::new(0);
static STARTED: [AtomicBool; CPUS] = [const { AtomicBool::new(false) }; CPUS];
static STOPPED: [AtomicBool; CPUS] = [const { AtomicBool::new(false) }; CPUS];
static READS: [AtomicUsize; CPUS] = [const { AtomicUsize::new(0) }; CPUS];

fn statics() -> Option<(&'static Epochs, &'static Head)> {
    if !READY.load(Ordering::Acquire) {
        return None;
    }
    // SAFETY: `READY` is set only after `init` has written both, and they are never written
    // again, so these are shared references to initialised, immutable-from-here statics.
    unsafe { Some(((*COLLECTOR.get()).assume_init_ref(), (*HEAD.get()).assume_init_ref())) }
}

/// Build the collector and the published pointer, once, on the boot CPU with nothing else
/// running.
fn init() -> Option<(&'static Epochs, &'static Head)> {
    if READY.load(Ordering::Acquire) {
        return statics();
    }
    let first = take_node(1)?;
    // SAFETY: once, on the boot CPU before any secondary runs code that reads either static
    // (`READY` is still false), so this is the only access.
    unsafe {
        let collector = (*COLLECTOR.get()).write(Collector::sized());
        let collector: &'static Epochs = &*(collector as *const Epochs);
        // SAFETY (for `EpochPtr::new`): pool nodes are statics, valid for ever. `first`
        // is taken from the pool and becomes free again only through `reclaim`, after it
        // has been replaced and retired to `collector`.
        (*HEAD.get()).write(EpochPtr::new(first, collector));
    }
    READY.store(true, Ordering::Release);
    statics()
}

/// A free pool node, stamped, or `None` if every node is published or waiting in a bag.
/// Only the boot CPU takes nodes, and only the boot CPU reclaims them.
fn take_node(stamp: u64) -> Option<*mut Node> {
    let node = NODES.iter().find(|n| n.free.load(Ordering::Relaxed))?;
    node.free.store(false, Ordering::Relaxed);
    node.stamp.store(stamp, Ordering::Release);
    Some(core::ptr::from_ref(node).cast_mut())
}

/// The reclaim function: poison the node and give it back to the pool.
///
/// # Safety
/// `p` points at a pool node that was retired and is now unreachable.
unsafe fn reclaim(p: *mut ()) {
    // SAFETY: pool nodes are statics; the caller's contract makes this one ours.
    let node = unsafe { &*(p as *const Node) };
    node.stamp.store(POISON, Ordering::Release);
    node.free.store(true, Ordering::Relaxed);
    RECLAIMED.fetch_add(1, Ordering::Relaxed);
}

/// Give an unpublished node back to the pool, without poisoning or counting it: it was
/// taken for a retirement that the bag had no room for, and was never linked.
fn give_back(p: *mut Node) {
    // SAFETY: pool nodes are statics, and `p` came from `take_node` on this CPU.
    unsafe { &*p }.free.store(true, Ordering::Relaxed);
}

/// What one attempt to publish came to.
enum Attempt {
    Published,
    /// The running CPU's bag had no room, and nothing was unlinked. `Some` names a CPU the
    /// collector has watched hold the epoch back for `sync::epoch::STALL_ATTEMPTS` advances.
    Wait(Option<usize>),
}

/// Replace the published node with a fresh one stamped `stamp`, retiring the old one.
///
/// A full bag is not a fault: a writer that outruns reclamation has to wait. Under a loaded
/// host, with eight emulated CPUs on fewer real ones, the readers this check runs are
/// descheduled long enough for that to happen. So the node goes back to the pool and the
/// caller decides whether to wait.
fn publish_once(c: &Epochs, head: &Head, stamp: u64) -> Result<Attempt, &'static str> {
    let guard = c.pin().ok_or("the boot CPU has no participant")?;
    let mut new = take_node(stamp);
    for _ in 0..4 {
        if new.is_some() {
            break;
        }
        c.collect(&guard);
        new = take_node(stamp);
    }
    let new = new.ok_or("THE NODE POOL RAN DRY: reclamation is not keeping up")?;
    // SAFETY: the boot CPU is the only writer. `new` is a pool node, valid for ever, and
    // `reclaim` returns a retired node to the pool, which is sound on any CPU.
    let refused = match unsafe { head.replace(new, reclaim, &guard) } {
        Ok(()) => None,
        Err(RetireError::Stalled(s)) => Some(Some(s.cpu)),
        Err(_) => Some(None),
    };
    if let Some(named) = refused {
        give_back(new);
        return Ok(Attempt::Wait(named));
    }
    c.collect(&guard);
    Ok(Attempt::Published)
}

/// The CPU [`publish`] found stalled, for the report. `usize::MAX` until one is.
static STALLED_CPU: AtomicUsize = AtomicUsize::new(usize::MAX);

/// How long a CPU the collector names may go without finishing a single read before it is
/// called stalled. A reader descheduled by the host is back well within this; one that has
/// stopped unpinning never is.
const STALL_TIMEOUT: time::Duration = time::Duration::from_nanos(2_000_000_000);

/// How long [`publish`] waits for room in all, whatever it is waiting on. A reader that
/// keeps finishing reads while never actually releasing its pin looks alive to the
/// progress test, and this is what still ends that wait.
const WAIT_TIMEOUT: time::Duration = time::Duration::from_nanos(20_000_000_000);

/// Attempts [`publish`] makes before giving up however it is judged. The clock reads zero
/// if timekeeping never started, as when a failed bring-up skipped the preemption check, and
/// a wait bounded only by the clock would then never end.
const RETIRE_PATIENCE: usize = 1 << 20;

/// Replace the published node, waiting for room if reclamation is behind.
///
/// Each attempt pins and unpins. The writer's own pin holds the epoch back as much as any
/// reader's, so waiting while pinned would be waiting for something this CPU prevents.
///
/// The collector's stall report counts advances a CPU held back, not time, so a writer
/// retrying this fast turns a reader the host has merely descheduled into a "stall" within
/// a few milliseconds. That is still the right question, asked with the wrong unit. So a
/// named CPU is judged by its own progress instead: every read a reader finishes unpins and
/// counts in `READS`. A CPU that finishes no read for [`STALL_TIMEOUT`] has stopped
/// unpinning, and fails the check by name. One that is merely slow keeps counting, and the
/// writer keeps waiting.
fn publish(c: &Epochs, head: &Head, stamp: u64) -> Result<(), &'static str> {
    // The CPU last named, its read count, and when it was first seen at that count.
    let mut suspect: Option<(usize, usize, time::Instant)> = None;
    let started = crate::timekeeping::now();
    for _ in 0..=RETIRE_PATIENCE {
        match publish_once(c, head, stamp)? {
            Attempt::Published => return Ok(()),
            Attempt::Wait(None) => suspect = None,
            Attempt::Wait(Some(cpu)) => {
                let reads = READS.get(cpu).map_or(0, |r| r.load(Ordering::Acquire));
                let now = crate::timekeeping::now();
                match suspect {
                    Some((named, before, since)) if named == cpu && reads == before => {
                        if now.saturating_duration_since(since) >= STALL_TIMEOUT {
                            STALLED_CPU.store(cpu, Ordering::Relaxed);
                            return Err("A PARTICIPANT STALLED THE EPOCH");
                        }
                    }
                    _ => suspect = Some((cpu, reads, now)),
                }
            }
        }
        if crate::timekeeping::now().saturating_duration_since(started) >= WAIT_TIMEOUT {
            break;
        }
        // Unpinned, so the readers can reach the epoch this CPU is waiting on. A counted
        // loop rather than `spin_loop`, for the reason `reader` gives.
        for i in 0..READ_PAUSE {
            core::hint::black_box(i);
        }
    }
    Err("RECLAMATION NEVER CAUGHT UP: a limbo bag stayed full")
}

/// Run the check.
pub fn check(c: &dyn EarlyConsole) -> Check {
    let Some((collector, head)) = init() else {
        c.write_str("no pool node to publish");
        return Check::Failed;
    };
    if !deferral(c, collector, head) {
        return Check::Failed;
    }
    let secondaries: usize = (1..CPUS)
        .filter(|&cpu| platform::secondary_online(cpu))
        .count();
    if secondaries == 0 {
        c.write_str("; no other CPU online");
        return Check::Passed;
    }
    Check::from_ok(concurrent(c, collector, head))
}

/// A pinned reader on this CPU keeps its node through an unlink and every collection.
fn deferral(c: &dyn EarlyConsole, collector: &Epochs, head: &Head) -> bool {
    let before = RECLAIMED.load(Ordering::Relaxed);
    let Some(reader) = collector.pin() else {
        c.write_str("the boot CPU has no participant");
        return false;
    };
    let Some(held) = head.load(&reader) else {
        c.write_str("nothing published");
        return false;
    };
    let stamp = held.stamp.load(Ordering::Acquire);
    if let Err(why) = publish(collector, head, 2) {
        c.write_str(why);
        return false;
    }
    for _ in 0..8 {
        let _ = collector.try_advance();
    }
    let kept =
        held.stamp.load(Ordering::Acquire) == stamp && RECLAIMED.load(Ordering::Relaxed) == before;
    drop(reader);
    let flushed = (0..3).any(|_| {
        let _ = collector.flush();
        RECLAIMED.load(Ordering::Relaxed) == before + 1
    });
    if !kept {
        c.write_str("A PINNED READER'S NODE WAS RECLAIMED");
        return false;
    }
    if !flushed {
        c.write_str("THE UNPINNED NODE WAS NEVER RECLAIMED");
        return false;
    }
    c.write_str("deferral ok");
    true
}

/// One secondary's reader. Runs in its function-call IPI until `STOP`.
fn reader(cpu: u64) -> u64 {
    let cpu = cpu as usize;
    let (Some(started), Some(stopped), Some(reads)) =
        (STARTED.get(cpu), STOPPED.get(cpu), READS.get(cpu))
    else {
        return 0;
    };
    let Some((collector, head)) = statics() else {
        stopped.store(true, Ordering::Release);
        return 0;
    };
    started.store(true, Ordering::Release);
    let mut budget = READER_BUDGET;
    while !STOP.load(Ordering::Acquire) && budget > 0 {
        budget -= 1;
        let Some(guard) = collector.pin() else {
            break;
        };
        if let Some(node) = head.load(&guard) {
            let first = node.stamp.load(Ordering::Acquire);
            // A plain counted loop, not `spin_loop`: QEMU's x86 emulation ends the translated
            // block at every `pause`, so 4096 of them took milliseconds. The window stayed
            // wide, but a reader then re-pinned so rarely that the writer's bag filled before
            // the epoch could advance, and the check failed on timing it never meant to test.
            for i in 0..READ_PAUSE {
                core::hint::black_box(i);
            }
            let again = node.stamp.load(Ordering::Acquire);
            if first == POISON || first != again {
                TORN.fetch_add(1, Ordering::Relaxed);
            }
        }
        drop(guard);
        // One writer per slot: this CPU.
        reads.store(reads.load(Ordering::Relaxed) + 1, Ordering::Release);
    }
    stopped.store(true, Ordering::Release);
    0
}

fn concurrent(c: &dyn EarlyConsole, collector: &Epochs, head: &Head) -> bool {
    let cpus = || (1..CPUS).filter(|&cpu| platform::secondary_online(cpu));
    for cpu in cpus() {
        // Expected to time out with the reader still running; an answer means it stopped.
        if platform::call_on_secondary(cpu, reader, cpu as u64).is_some() {
            c.write_str("; A READER RETURNED BEFORE THE WRITER STARTED");
            return false;
        }
        if !STARTED.get(cpu).is_some_and(|s| s.load(Ordering::Acquire)) {
            c.write_str("; A READER NEVER STARTED");
            return false;
        }
    }

    let reads_before: [usize; CPUS] = core::array::from_fn(|i| READS[i].load(Ordering::Acquire));
    let retired_before = collector.stats().retired;
    let mut failure = None;
    for i in 0..WRITES {
        if let Err(why) = publish(collector, head, 3 + i as u64) {
            failure = Some(why);
            break;
        }
    }
    let overlapped = cpus().all(|cpu| READS[cpu].load(Ordering::Acquire) > reads_before[cpu]);
    STOP.store(true, Ordering::Release);

    let mut patience = STOP_PATIENCE;
    while cpus().any(|cpu| !STOPPED[cpu].load(Ordering::Acquire)) && patience > 0 {
        patience -= 1;
        core::hint::spin_loop();
    }
    let all_stopped = cpus().all(|cpu| STOPPED[cpu].load(Ordering::Acquire));
    for _ in 0..4 {
        if collector.stats().pending == 0 {
            break;
        }
        let _ = collector.flush();
    }
    let s = collector.stats();
    let retired = s.retired - retired_before;
    let torn = TORN.load(Ordering::Relaxed);
    let reads: usize = cpus().map(|cpu| READS[cpu].load(Ordering::Acquire)).sum();

    c.write_str("; ");
    write_usize(c, cpus().count());
    c.write_str(" readers, ");
    write_usize(c, WRITES);
    c.write_str(" replacements, ");
    write_usize(c, reads);
    c.write_str(" reads, ");
    write_usize(c, s.reclaimed as usize);
    c.write_str("/");
    write_usize(c, s.retired as usize);
    c.write_str(" reclaimed");

    let ok = if let Some(why) = failure {
        c.write_str(", ");
        c.write_str(why);
        let stalled = STALLED_CPU.load(Ordering::Relaxed);
        if stalled != usize::MAX {
            c.write_str(" on CPU ");
            write_usize(c, stalled);
        }
        false
    } else if torn != 0 {
        c.write_str(", ");
        write_usize(c, torn);
        c.write_str(" READS SAW A RECLAIMED NODE");
        false
    } else if !all_stopped {
        c.write_str(", A READER DID NOT STOP");
        false
    } else if !overlapped {
        c.write_str(", A READER DID NOT RUN DURING THE WRITES");
        false
    } else if s.pending != 0 || retired != WRITES as u64 {
        c.write_str(", RECLAMATION FELL SHORT");
        false
    } else {
        true
    };
    c.write_str(if ok { " ok" } else { "" });
    ok
}

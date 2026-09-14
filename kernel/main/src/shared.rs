//! Checks of the state the whole kernel shares, made from threads that preempt each
//! other: the timer queue, the kernel heap, tickless idle, and lock-order checking.
//!
//! They run on the scheduler `preempt` has already proved, after its own check, with its
//! idle thread still in place. Each phase spawns its threads on stacks the earlier
//! threads gave back, sleeps boot until they should be done, and reaps them. A phase
//! that goes wrong reports FAILED rather than waiting: every wait is a sleep with a
//! deadline, and every busy loop has a cap.
//!
//! * **Sleep.** Three threads sleep to deadlines armed in an order that is not their deadline
//!   order. They must wake in deadline order, never before their deadline, and within [`MAX_LATE`]
//!   after it.
//! * **Heap.** Three threads of equal priority, which never yield, allocate, fill, check and free
//!   through the kernel heap while the timer preempts them, and keep a few blocks alive across
//!   preemptions. Every block must still hold its pattern when it is freed, every thread must see
//!   the others make progress, and the heap's live bytes must return to where they started.
//!   Meanwhile the timer interrupt allocates too. An atomic request must succeed, and one that may
//!   sleep must be refused.
//! * **Tickless.** With only idle left, boot sleeps [`IDLE_FOR`]. The timer interrupts that takes
//!   are counted. The bound is how many one-shot armings the hardware needs to reach that far, plus
//!   two, and it must also be below the number a periodic slice would have taken.
//! * **ABBA** (with `LOCKDEP_ABBA_TEST` only). Two threads take two locks in opposite orders, one
//!   after the other, so nothing deadlocks. The inversion is reported through lock-order checking,
//!   and `lockcheck` turns the report into the verdict.

use core::alloc::Layout;
use core::ptr::NonNull;
use core::sync::atomic::Ordering;

use hal::{Arch, EarlyConsole};
use kalloc::AllocContext;
use sched::ThreadId;
use time::{Duration, Instant};

use crate::kheap::{self, KBox};
use crate::preempt::{self, SLICE, begin, exit_thread, sleep_until};
use crate::{AtomicBool, AtomicU32, AtomicU64, Check, lockcheck, timekeeping, write_usize};

/// Latest a sleeper may wake after its deadline. Its own timer interrupt wakes it, so
/// microseconds are expected; three slices tolerate an emulator delivering it late.
const MAX_LATE: Duration = Duration::from_nanos(3 * SLICE.as_nanos());

/// The sleepers' deadlines, from the start of the phase, in the order they are armed.
const SLEEP_AFTER_MS: [u64; 3] = [60, 20, 40];
const SLEEP_PRIORITY: u8 = 6;

/// How long the heap threads run, and how long boot then waits for them to finish.
const HEAP_FOR: Duration = Duration::from_nanos(200_000_000);
const HEAP_DRAIN: Duration = Duration::from_nanos(60_000_000);
const HEAP_PRIORITY: u8 = 4;
/// Iterations after which a heap thread stops even if boot never stops it.
const HEAP_CAP: u64 = 1_000_000;
/// Blocks each heap thread keeps alive across iterations, and so across preemptions.
const KEEP: usize = 6;

/// How long boot idles alone in the tickless phase.
const IDLE_FOR: Duration = Duration::from_nanos(500_000_000);

// ---- sleep ------------------------------------------------------------------------------

static PHASE_START: AtomicU64 = AtomicU64::new(0);
static WAKE_SEQ: AtomicU32 = AtomicU32::new(0);
/// Each sleeper's rank in wake order. `u32::MAX` until it wakes.
static WAKE_RANK: [AtomicU32; 3] = [const { AtomicU32::new(u32::MAX) }; 3];
static WOKE_AT: [AtomicU64; 3] = [const { AtomicU64::new(0) }; 3];

fn phase_start() -> Instant {
    Instant::from_nanos(PHASE_START.load(Ordering::Relaxed))
}

fn sleep_deadline(which: usize) -> Instant {
    let ms = SLEEP_AFTER_MS[which];
    phase_start().saturating_add(Duration::from_nanos(ms * 1_000_000))
}

extern "C" fn sleeper(which: usize) -> ! {
    begin();
    sleep_until(sleep_deadline(which));
    WOKE_AT[which].store(timekeeping::now().as_nanos(), Ordering::Relaxed);
    WAKE_RANK[which].store(WAKE_SEQ.fetch_add(1, Ordering::Relaxed), Ordering::Relaxed);
    exit_thread()
}

fn sleep_phase(c: &dyn EarlyConsole) -> Check {
    c.write_str("\n  sleep      ");
    let start = timekeeping::now();
    PHASE_START.store(start.as_nanos(), Ordering::Relaxed);
    let Some(ids) = spawn_all([sleeper, sleeper, sleeper], [0, 1, 2], SLEEP_PRIORITY) else {
        c.write_str("spawn refused");
        return Check::Failed;
    };
    sleep_until(start.saturating_add(Duration::from_nanos(100_000_000)));
    let reaped = ids.iter().all(|&id| preempt::reap(id));

    // Deadline order is the order of the armed offsets, sorted.
    let mut by_deadline = [0usize, 1, 2];
    by_deadline.sort_unstable_by_key(|&i| SLEEP_AFTER_MS[i]);
    let mut ok = reaped;
    for (rank, &i) in by_deadline.iter().enumerate() {
        let deadline = sleep_deadline(i).as_nanos();
        let woke = WOKE_AT[i].load(Ordering::Relaxed);
        let in_order = WAKE_RANK[i].load(Ordering::Relaxed) == rank as u32;
        let early = woke < deadline;
        let late = woke.saturating_sub(deadline);
        if rank > 0 {
            c.write_str(", ");
        }
        write_usize(c, SLEEP_AFTER_MS[i] as usize);
        c.write_str(" ms +");
        write_usize(c, (late / 1_000) as usize);
        c.write_str(" us");
        if early {
            c.write_str(" EARLY");
        }
        if late > MAX_LATE.as_nanos() {
            c.write_str(" TOO LATE");
        }
        if !in_order {
            c.write_str(" OUT OF ORDER");
        }
        ok &= in_order && !early && late <= MAX_LATE.as_nanos();
    }
    if !reaped {
        c.write_str(", a sleeper did not exit");
    }
    c.write_str(if ok {
        "; in deadline order ok"
    } else {
        " FAILED"
    });
    Check::from_ok(ok)
}

// ---- heap -------------------------------------------------------------------------------

static STOP_HEAP: AtomicBool = AtomicBool::new(false);
static HEAP_ITERATIONS: [AtomicU64; 3] = [const { AtomicU64::new(0) }; 3];
/// The other threads' iterations, added together, as each thread saw them when it stopped.
static HEAP_SAW_OTHERS: [AtomicU64; 3] = [const { AtomicU64::new(0) }; 3];
static HEAP_DONE: [AtomicBool; 3] = [const { AtomicBool::new(false) }; 3];
static HEAP_CORRUPT: AtomicU32 = AtomicU32::new(0);
static HEAP_REFUSED: AtomicU32 = AtomicU32::new(0);

/// While set, the timer interrupt allocates as well.
static PROBE_FROM_INTERRUPT: AtomicBool = AtomicBool::new(false);
static IRQ_ATOMIC_OK: AtomicU32 = AtomicU32::new(0);
static IRQ_SLEEP_REFUSED: AtomicU32 = AtomicU32::new(0);
static IRQ_WRONG: AtomicU32 = AtomicU32::new(0);

/// Sizes cycled through: slab classes, an arena-sized object, and a multi-page block.
fn heap_size(i: u64) -> usize {
    match i % 5 {
        0 => 24,
        1 => 100,
        2 => 700,
        3 => 3000,
        _ => <arch::Cpu as Arch>::PAGE_SIZE * 2,
    }
}

fn pattern(thread: usize, iteration: u64, offset: usize) -> u8 {
    (thread as u8)
        .wrapping_mul(61)
        .wrapping_add(iteration as u8)
        .wrapping_add(offset as u8)
}

/// A block a heap thread holds, with what it wrote into it.
#[derive(Clone, Copy)]
struct Held {
    ptr: NonNull<u8>,
    layout: Layout,
    iteration: u64,
}

fn fill(held: Held, thread: usize) {
    // SAFETY: a live allocation of `layout.size()` bytes that only this thread holds.
    let bytes = unsafe { core::slice::from_raw_parts_mut(held.ptr.as_ptr(), held.layout.size()) };
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = pattern(thread, held.iteration, i);
    }
}

fn intact(held: Held, thread: usize) -> bool {
    // SAFETY: as in `fill`.
    let bytes = unsafe { core::slice::from_raw_parts(held.ptr.as_ptr(), held.layout.size()) };
    bytes
        .iter()
        .enumerate()
        .all(|(i, b)| *b == pattern(thread, held.iteration, i))
}

extern "C" fn heap_thread(which: usize) -> ! {
    begin();
    let mut kept: [Option<Held>; KEEP] = [None; KEEP];
    let mut i = 0u64;
    while !STOP_HEAP.load(Ordering::Relaxed) && i < HEAP_CAP {
        let slot = (i as usize) % KEEP;
        // Free what this slot held, checking it first. It was written iterations ago,
        // with other threads allocating in between.
        if let Some(old) = kept[slot].take() {
            if !intact(old, which) {
                HEAP_CORRUPT.fetch_add(1, Ordering::Relaxed);
            }
            // SAFETY: allocated below with this layout, freed once.
            if unsafe { kheap::dealloc(old.ptr, old.layout, AllocContext::KERNEL) }.is_err() {
                HEAP_CORRUPT.fetch_add(1, Ordering::Relaxed);
            }
        }
        let Ok(layout) = Layout::from_size_align(heap_size(i), 8) else {
            break;
        };
        match kheap::try_alloc(layout, AllocContext::KERNEL) {
            Ok(ptr) => {
                let held = Held {
                    ptr,
                    layout,
                    iteration: i,
                };
                fill(held, which);
                kept[slot] = Some(held);
            }
            Err(_) => {
                HEAP_REFUSED.fetch_add(1, Ordering::Relaxed);
            }
        }
        // And a typed value through `KBox`, dropped at the end of the iteration.
        match KBox::try_new([i ^ which as u64; 4], AllocContext::KERNEL) {
            Ok(b) => {
                if b.iter().any(|&v| v != i ^ which as u64) {
                    HEAP_CORRUPT.fetch_add(1, Ordering::Relaxed);
                }
            }
            Err(_) => {
                HEAP_REFUSED.fetch_add(1, Ordering::Relaxed);
            }
        }
        i += 1;
        HEAP_ITERATIONS[which].store(i, Ordering::Relaxed);
    }
    for old in kept.iter_mut().filter_map(Option::take) {
        if !intact(old, which) {
            HEAP_CORRUPT.fetch_add(1, Ordering::Relaxed);
        }
        // SAFETY: allocated above with this layout, freed once.
        if unsafe { kheap::dealloc(old.ptr, old.layout, AllocContext::KERNEL) }.is_err() {
            HEAP_CORRUPT.fetch_add(1, Ordering::Relaxed);
        }
    }
    let others = (0..3)
        .filter(|&t| t != which)
        .map(|t| HEAP_ITERATIONS[t].load(Ordering::Relaxed))
        .min()
        .unwrap_or(0);
    HEAP_SAW_OTHERS[which].store(others, Ordering::Relaxed);
    HEAP_DONE[which].store(true, Ordering::Relaxed);
    exit_thread()
}

/// Called by the timer hook, in interrupt context, on every interrupt.
pub fn from_interrupt() {
    if !PROBE_FROM_INTERRUPT.load(Ordering::Relaxed) {
        return;
    }
    let Ok(layout) = Layout::from_size_align(32, 8) else {
        return;
    };
    match kheap::try_alloc(layout, AllocContext::ATOMIC) {
        Ok(p) => {
            // SAFETY: allocated just above with `layout`, freed once.
            let freed = unsafe { kheap::dealloc(p, layout, AllocContext::ATOMIC) }.is_ok();
            let counter = if freed { &IRQ_ATOMIC_OK } else { &IRQ_WRONG };
            counter.fetch_add(1, Ordering::Relaxed);
        }
        // The heap may be momentarily full; that is a refusal, not a wrong answer.
        Err(kheap::Error::Alloc(_)) => {}
        Err(_) => {
            IRQ_WRONG.fetch_add(1, Ordering::Relaxed);
        }
    }
    match kheap::try_alloc(layout, AllocContext::KERNEL) {
        Err(kheap::Error::MaySleepInInterrupt) => {
            IRQ_SLEEP_REFUSED.fetch_add(1, Ordering::Relaxed);
        }
        Ok(p) => {
            IRQ_WRONG.fetch_add(1, Ordering::Relaxed);
            // SAFETY: allocated just above with `layout`, freed once.
            let _ = unsafe { kheap::dealloc(p, layout, AllocContext::KERNEL) };
        }
        Err(_) => {
            IRQ_WRONG.fetch_add(1, Ordering::Relaxed);
        }
    }
}

fn heap_phase(c: &dyn EarlyConsole) -> Check {
    c.write_str("\n  kheap mt   ");
    let Some(before) = kheap::stats() else {
        c.write_str("no kernel heap");
        return Check::Failed;
    };
    let start = timekeeping::now();
    PROBE_FROM_INTERRUPT.store(true, Ordering::Relaxed);
    let Some(ids) = spawn_all([heap_thread, heap_thread, heap_thread], [0, 1, 2], HEAP_PRIORITY)
    else {
        PROBE_FROM_INTERRUPT.store(false, Ordering::Relaxed);
        c.write_str("spawn refused");
        return Check::Failed;
    };
    sleep_until(start.saturating_add(HEAP_FOR));
    STOP_HEAP.store(true, Ordering::Relaxed);
    sleep_until(start.saturating_add(HEAP_FOR).saturating_add(HEAP_DRAIN));
    PROBE_FROM_INTERRUPT.store(false, Ordering::Relaxed);
    let reaped = ids.iter().all(|&id| preempt::reap(id));
    let after = kheap::stats().unwrap_or(before);

    let load = |a: &AtomicU64| a.load(Ordering::Relaxed);
    let iterations = [
        load(&HEAP_ITERATIONS[0]),
        load(&HEAP_ITERATIONS[1]),
        load(&HEAP_ITERATIONS[2]),
    ];
    let done = HEAP_DONE.iter().all(|d| d.load(Ordering::Relaxed));
    let interleaved = HEAP_SAW_OTHERS
        .iter()
        .all(|s| s.load(Ordering::Relaxed) > 0);
    let corrupt = HEAP_CORRUPT.load(Ordering::Relaxed);
    let refused = HEAP_REFUSED.load(Ordering::Relaxed);
    let balanced = after.bytes_in_use == before.bytes_in_use;
    let irq_ok = IRQ_ATOMIC_OK.load(Ordering::Relaxed);
    let irq_refused = IRQ_SLEEP_REFUSED.load(Ordering::Relaxed);
    let irq_wrong = IRQ_WRONG.load(Ordering::Relaxed);

    c.write_str("3 threads, ");
    for (n, it) in iterations.iter().enumerate() {
        if n > 0 {
            c.write_str("/");
        }
        write_usize(c, *it as usize);
    }
    c.write_str(" iterations, ");
    write_usize(c, corrupt as usize);
    c.write_str(" corrupt, ");
    write_usize(c, refused as usize);
    c.write_str(" refused, in use ");
    write_usize(c, before.bytes_in_use);
    c.write_str(" -> ");
    write_usize(c, after.bytes_in_use);
    c.write_str(" bytes");
    c.write_str("\n             from the timer interrupt: ");
    write_usize(c, irq_ok as usize);
    c.write_str(" atomic served, ");
    write_usize(c, irq_refused as usize);
    c.write_str(" may-sleep refused, ");
    write_usize(c, irq_wrong as usize);
    c.write_str(" wrong");
    if !done || !reaped {
        c.write_str(", A THREAD DID NOT FINISH");
    }
    if !interleaved {
        c.write_str(", NOT INTERLEAVED");
    }
    if !balanced {
        c.write_str(", LEAKED");
    }
    let ok = done
        && reaped
        && interleaved
        && corrupt == 0
        && refused == 0
        && balanced
        && iterations.iter().all(|&i| i > 0)
        && irq_ok > 0
        && irq_refused > 0
        && irq_wrong == 0;
    c.write_str(if ok { " ok" } else { " FAILED" });
    Check::from_ok(ok)
}

// ---- tickless ---------------------------------------------------------------------------

fn tickless_phase(c: &dyn EarlyConsole) -> Check {
    c.write_str("\n  tickless   ");
    let reach = timekeeping::max_oneshot();
    if reach == 0 {
        c.write_str("no one-shot timer");
        return Check::Failed;
    }
    let interrupts = arch::tick::ticks();
    let start = timekeeping::now();
    sleep_until(start.saturating_add(IDLE_FOR));
    let taken = arch::tick::ticks() - interrupts;
    let slept = timekeeping::now().saturating_duration_since(start);

    // One arming per `reach` of the idle period, one for the slice boot's own sleep arms
    // before idle replaces it, and one of slack for an arming that lands just short.
    let bound = IDLE_FOR.as_nanos().div_ceil(reach) + 2;
    let periodic = IDLE_FOR.as_nanos() / SLICE.as_nanos();
    write_usize(c, taken as usize);
    c.write_str(" interrupts idling ");
    write_usize(c, (slept.as_nanos() / 1_000_000) as usize);
    c.write_str(" ms (one arming reaches ");
    write_usize(c, (reach / 1_000_000) as usize);
    c.write_str(" ms: limit ");
    write_usize(c, bound as usize);
    c.write_str("; a ");
    write_usize(c, (SLICE.as_nanos() / 1_000_000) as usize);
    c.write_str(" ms tick would take ");
    write_usize(c, periodic as usize);
    c.write_str(")");
    let ok = taken >= 1 && taken <= bound && taken < periodic && slept >= IDLE_FOR;
    let full_reach = full_reach_is_not_early(c, reach);
    c.write_str(if ok && full_reach { " ok" } else { " FAILED" });
    Check::from_ok(ok && full_reach)
}

/// How long [`full_reach_is_not_early`] takes interrupts before it starts counting.
const DRAIN: Duration = Duration::from_nanos(2_000_000);

/// How long [`full_reach_is_not_early`] waits for an interrupt that must not come.
const REACH_WATCH: Duration = Duration::from_nanos(20_000_000);

/// Arm the timer as far as one arming reaches, and require no interrupt for
/// [`REACH_WATCH`].
///
/// The idle phase above never arms more than [`IDLE_FOR`], so it cannot see a limit that
/// the hardware does not honour. The Arm generic timer's value register is signed, and
/// arming its full unsigned range put the deadline in the past: the interrupt fired at
/// once, the handler re-armed the same, and the CPU did nothing else. The stress run found
/// that after minutes; this finds it at boot.
fn full_reach_is_not_early(c: &dyn EarlyConsole, reach: u64) -> bool {
    let irq = <arch::Cpu as Arch>::irq_save();
    // No hook while watching. The scheduler's hook would re-arm the same full reach from
    // the early interrupt, which fires at once again: the failure this looks for would be
    // a hang instead of a report. Without a hook the handler stops the timer.
    arch::tick::set_hook(None);
    // SAFETY: masked, as `arm_ns` requires. The timer is in one-shot mode, since
    // `timekeeping::init` succeeded or `reach` would be zero.
    unsafe { arch::tick::arm_ns(reach) };
    // Take any interrupt an earlier arming already raised before counting. A local APIC
    // latches a timer interrupt that fires while the CPU is masked, and rearming does not
    // withdraw it, so without this the watch counted a stale slice's tick as the new arming
    // firing early: once in fifteen x86_64 SMP boots. An arming that really fires at once
    // fires again after the second arming below, and is still caught.
    //
    // SAFETY: as for the watch below; with no hook the handler only counts.
    unsafe { arch::tick::enable_interrupts() };
    let drain = timekeeping::now();
    while timekeeping::now().saturating_duration_since(drain) < DRAIN {
        core::hint::spin_loop();
    }
    let _ = <arch::Cpu as Arch>::irq_save();
    // SAFETY: masked again, as `arm_ns` requires.
    unsafe { arch::tick::arm_ns(reach) };
    let interrupts = arch::tick::ticks();
    let start = timekeeping::now();
    // Unmasked explicitly, not restored: boot runs these phases masked, and a restore
    // would keep the interrupt this is watching for from ever being taken. The first
    // version did exactly that and passed with the bug in place.
    //
    // SAFETY: the vector table is installed and the timer's handler is the scheduler's
    // hook. Boot is the highest-priority thread and nothing else is ready but idle, so
    // only the timer can take the CPU from this loop, and the `irq_restore` below puts
    // back the state saved above.
    unsafe { arch::tick::enable_interrupts() };
    while timekeeping::now().saturating_duration_since(start) < REACH_WATCH
        && arch::tick::ticks() == interrupts
    {
        core::hint::spin_loop();
    }
    let _ = <arch::Cpu as Arch>::irq_save();
    preempt::restore_tick_hook();
    // SAFETY: masked, as `program` requires; the watch above left the timer armed far away
    // or stopped, and the scheduler needs its own deadline back.
    unsafe { timekeeping::program(Some(SLICE)) };
    // SAFETY: pairs with the first `irq_save`, on this thread.
    unsafe { <arch::Cpu as Arch>::irq_restore(irq) };
    let early = arch::tick::ticks() != interrupts;
    if early {
        c.write_str(", AN ARMING AT FULL REACH FIRED AT ONCE");
    }
    !early
}

// ---- driver ---------------------------------------------------------------------------

/// Spawn three threads on stacks 1 to 3, whose previous threads must have been reaped.
fn spawn_all(
    entries: [extern "C" fn(usize) -> !; 3],
    args: [usize; 3],
    level: u8,
) -> Option<[ThreadId; 3]> {
    let irq = <arch::Cpu as Arch>::irq_save();
    let mut ids = [ThreadId::new(0); 3];
    let mut ok = true;
    for (i, id) in ids.iter_mut().enumerate() {
        match preempt::spawn(i + 1, entries[i], args[i], level) {
            Some(spawned) => *id = spawned,
            None => ok = false,
        }
    }
    // SAFETY: pairs with the `irq_save` above.
    unsafe { <arch::Cpu as Arch>::irq_restore(irq) };
    ok.then_some(ids)
}

/// Run every phase, on the boot thread, with the scheduler running and interrupts
/// masked (boot's state inside `preempt::demonstrate`).
pub fn run(c: &dyn EarlyConsole) -> Check {
    let sleep = sleep_phase(c);
    let heap = heap_phase(c);
    // Before tickless, which needs everything but idle gone, and after the phases whose
    // stack slots its process threads reuse.
    let processes = crate::model::processes_check(c);
    // After `processes`, whose process slots and stack slots it reuses once that phase has
    // torn its own down.
    let spawn = crate::model::spawn_check(c);
    // After `spawn`, whose threads have been reaped from the stack slot this one's lookup
    // thread runs on.
    let channels = crate::model::channels_check(c);
    // After `spawn`, whose process slot and stack slots it reuses once that phase has
    // reaped its threads.
    let waits = crate::model::waits_check(c);
    // After `waits`, whose process slot and stack slots it reuses once that phase has reaped
    // its threads.
    let sibling = crate::model::sibling_check(c);
    // After `sibling`, whose process slot and stack slots it reuses; and after `waits` has
    // finished, so the file server is serving a second process, not the check that started it.
    let files = crate::model::files_check(c);
    // After `files`, whose process slot and stack slots it reuses once that check has torn its
    // process down: the server writes the disk for one connection and refuses another.
    let files_write = crate::model::files_write_check(c);
    // After `files write`, which left the volume written: a program asks the server what each
    // volume is, and the kernel holds what it was told against its own walk.
    let files_statfs = crate::model::files_statfs_check(c);
    // After `files`, which has torn its process down by now, and reusing its process slot:
    // the Linux program with the scheduler, forking and starting a thread.
    let linux = crate::model::linux_check(c);
    // After `linux`, which has torn its processes down by now, reusing the same process slot;
    // and long after the net check, which learned kbuild's TCP port.
    // After `linux`, whose process slot and stacks it reuses: one process waiting on a
    // channel, an event and a timer at once.
    let readiness = crate::model::readiness_check(c);
    // After `readiness`, which has ended its threads: this races a wake into the window
    // that check could not reach. Passes silently without WAIT_RACE_TEST.
    let waitrace = crate::waitrace::check(c);
    let sockets = crate::model::sockets_check(c);
    // After `sockets`, which has torn its process down by now, reusing the same process slot:
    // the Linux program as a TCP client, and as a server kbuild connects to.
    let linux_net = crate::model::linux_sockets_check(c);
    // After `linux net`, which has torn its processes down by now: this borrows the process
    // check's frame pool and reuses its process slot and stack. Before tickless, which
    // wants everything but idle gone.
    c.write_str("\n  isolation  ");
    let isolation = crate::isolation::check(c);
    // After `isolation`, whose process slot and stack slot it reuses: on x86_64 that check is
    // skipped, so the slots are free either way. This is the disk served from a domain.
    c.write_str("\n  blk domain ");
    let blk_domain = crate::blockdomain::check(c);
    let tickless = tickless_phase(c);
    let abba = if kconfig::LOCKDEP_ABBA_TEST {
        lockcheck::abba(c)
    } else {
        Check::Passed
    };
    let unbroken = preempt::report_broken(c);
    sleep
        .and(heap)
        .and(processes)
        .and(spawn)
        .and(channels)
        .and(waits)
        .and(sibling)
        .and(files)
        .and(files_write)
        .and(files_statfs)
        .and(linux)
        .and(readiness)
        .and(waitrace)
        .and(sockets)
        .and(linux_net)
        .and(isolation)
        .and(blk_domain)
        .and(tickless)
        .and(abba)
        .and(Check::from_ok(unbroken))
}

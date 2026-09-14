//! Wait queues: how a thread waits for something another thread, or another CPU, will do.
//!
//! Until this, every wait in userspace was a loop: try, yield, try again. That spends a
//! slice per attempt, and on a tickless kernel it also hides how long a wait really took.
//! A wait queue makes a waiting thread *blocked*: off every run queue until the thing it
//! waits for happens or its deadline passes.
//!
//! # The shape of a wait
//!
//! A waiter owns a condition — "this channel has a message", "this event is signalled" —
//! that it checks with a closure, and a queue that whoever changes the condition wakes:
//!
//! ```text
//! queue.wait_until(deadline, || channel.try_receive())   // the waiter
//! channel.send(...); queue.wake_all();                    // the waker, in that order
//! ```
//!
//! [`WaitQueue::wait_once`] checks the condition, registers the thread, checks it again, and
//! only then blocks. The second check is what closes the gap between the first check and
//! registering: a waker that changed the condition in between is seen by it. A waker that
//! changes the condition after the second check finds the thread registered and sets its
//! flag before waking it, and [`crate::preempt::block_until`] reads that flag under the
//! scheduler lock before it blocks. So there is no order of events in which a wake is lost,
//! and no order in which a thread blocks with its condition already true.
//!
//! # The API, for the facilities built on it
//!
//! * [`WaitQueue::new`] is `const`: a queue lives in a static beside what it guards.
//! * [`WaitQueue::wait_until`] waits for `ready` to return `Some`, up to a deadline, and returns
//!   [`TimedOut`] otherwise. `ready` runs on the waiting thread with no lock of this queue held, so
//!   it may take the locks the condition needs.
//! * [`WaitQueue::wait_once`] blocks at most once and returns whatever `ready` says after, so a
//!   caller whose deadline can change while it waits (a completion queue a timer may be armed on)
//!   can recompute it.
//! * [`WaitQueue::wake_all`] wakes every registered thread. Call it *after* changing the condition.
//!   A spurious wake is harmless: a woken waiter checks again.
//!
//! # Rules
//!
//! * The scheduler lock is taken inside a queue's lock (by [`WaitQueue::wake_all`]), so nothing may
//!   take a queue's lock while holding the scheduler lock. A waker may hold other locks: a
//!   process's, when it ends the process, or the timer delivery lock, when it posts an expiration.
//! * Only a thread on the kernel's scheduler can block. Before the scheduler runs, a wait checks
//!   once and reports [`TimedOut`] rather than hang a machine that has nothing else to run.
//! * A queue holds [`WAITERS`] threads. One more polls its condition every millisecond instead of
//!   blocking, and is counted, so an undersized queue shows up in [`stats`] rather than as a hang.

use core::sync::atomic::Ordering;

use arch::Cpu;
use hal::Arch;
use sched::ThreadId;
use sync::SpinLock;
use sync::lockdep::LockClass;
use time::{Duration, Instant};

use crate::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, preempt, timekeeping};

/// Threads one queue can hold blocked at once.
pub const WAITERS: usize = 8;

/// A waiter slot holding no thread.
const FREE: u32 = u32::MAX;

/// How often a waiter that found no room in its queue looks at its condition.
const OVERFLOW_POLL: Duration = Duration::from_nanos(1_000_000);

/// One registered thread.
struct Waiter {
    /// The thread's identity, or [`FREE`].
    thread: AtomicU32,
    /// Set by the waker before it wakes the thread; read by `block_until` under the scheduler
    /// lock. See the module documentation.
    woken: AtomicBool,
    /// The CPU the thread was on when it registered, so a wake from another CPU is counted.
    cpu: AtomicUsize,
}

/// Threads waiting for one condition.
pub struct WaitQueue {
    /// Serialises registration against waking. Held only for those, never while blocked.
    lock: SpinLock<(), Cpu>,
    waiters: [Waiter; WAITERS],
    /// Slots in use. Read without the lock by [`WaitQueue::has_waiters`], so a waker on a hot
    /// path can skip a queue nobody is waiting in.
    registered: AtomicUsize,
}

/// Every wait queue shares this class: taking two queues' locks at once is a lock-order
/// violation, and nothing here does.
static CLASS: LockClass = LockClass::new("wait.queue");

/// A wait ran out before its condition held.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TimedOut;

static BLOCKS: AtomicU64 = AtomicU64::new(0);
static WAKES: AtomicU64 = AtomicU64::new(0);
static CROSS_CPU_WAKES: AtomicU64 = AtomicU64::new(0);
static TIMEOUTS: AtomicU64 = AtomicU64::new(0);
static OVERFLOWS: AtomicU64 = AtomicU64::new(0);

/// What every wait queue has done since boot.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Stats {
    /// Times a thread blocked.
    pub blocks: u64,
    /// Blocked threads a waker made runnable.
    pub wakes: u64,
    /// Of those, the ones woken from a CPU other than the one the thread blocked on.
    pub cross_cpu_wakes: u64,
    /// Blocks that ended at their deadline rather than by a wake.
    pub timeouts: u64,
    /// Waits that found their queue full and polled instead.
    pub overflows: u64,
}

pub fn stats() -> Stats {
    Stats {
        blocks: BLOCKS.load(Ordering::Relaxed),
        wakes: WAKES.load(Ordering::Relaxed),
        cross_cpu_wakes: CROSS_CPU_WAKES.load(Ordering::Relaxed),
        timeouts: TIMEOUTS.load(Ordering::Relaxed),
        overflows: OVERFLOWS.load(Ordering::Relaxed),
    }
}

impl Default for WaitQueue {
    fn default() -> Self {
        Self::new()
    }
}

impl WaitQueue {
    pub const fn new() -> WaitQueue {
        WaitQueue {
            lock: SpinLock::with_class((), &CLASS),
            waiters: [const {
                Waiter {
                    thread: AtomicU32::new(FREE),
                    woken: AtomicBool::new(false),
                    cpu: AtomicUsize::new(0),
                }
            }; WAITERS],
            registered: AtomicUsize::new(0),
        }
    }

    /// Whether any thread is registered here. A waker that changes something many times a
    /// second — a channel's send, a completion posted, a pipe written — asks this before doing
    /// the work of a wake, and an empty queue costs it one relaxed load.
    ///
    /// Racy by nature, and safe for it: a thread registering after this is read has not yet
    /// made its second check of the condition, which is the check that sees a change made
    /// before it. See the module documentation.
    pub fn has_waiters(&self) -> bool {
        self.registered.load(Ordering::Relaxed) != 0
    }

    /// Register `me`, returning its slot, or `None` if the queue is full.
    fn register(&self, me: ThreadId) -> Option<usize> {
        let _guard = self.lock.lock_irqsave();
        let slot = self
            .waiters
            .iter()
            .position(|w| w.thread.load(Ordering::Relaxed) == FREE)?;
        let w = &self.waiters[slot];
        w.woken.store(false, Ordering::Release);
        w.cpu.store(Cpu::cpu_index(), Ordering::Relaxed);
        w.thread.store(me.raw(), Ordering::Release);
        self.registered.fetch_add(1, Ordering::Release);
        Some(slot)
    }

    /// Give a slot back.
    fn release(&self, slot: usize) {
        let _guard = self.lock.lock_irqsave();
        self.waiters[slot].thread.store(FREE, Ordering::Release);
        self.registered.fetch_sub(1, Ordering::Release);
    }

    /// Check `ready`, and if it has nothing yet, block once — until a wake or `deadline` —
    /// and check it again. Returns what the last check found.
    pub fn wait_once<R>(
        &self,
        deadline: Option<Instant>,
        mut ready: impl FnMut() -> Option<R>,
    ) -> Option<R> {
        if let Some(r) = ready() {
            return Some(r);
        }
        if !preempt::scheduled() {
            return None;
        }
        let me = preempt::current_thread()?;
        // The window this opens is what `crate::waitrace` parks in: everything a waker
        // does from here until the look below finds nobody registered, and is seen only
        // by that look. Nothing without WAIT_RACE_TEST; see `waitrace_off.rs`.
        crate::waitrace::stall();
        let Some(slot) = self.register(me) else {
            // No room to block in. Poll rather than wait for a wake nobody can deliver.
            OVERFLOWS.fetch_add(1, Ordering::Relaxed);
            let soon = timekeeping::now().saturating_add(OVERFLOW_POLL);
            preempt::sleep_until(deadline.map_or(soon, |d| d.min(soon)));
            return ready();
        };
        // Registered, so a waker from here on sets this slot's flag. Check again: a waker
        // between the first check and registering changed the condition without finding us.
        if let Some(r) = ready() {
            self.release(slot);
            return Some(r);
        }
        BLOCKS.fetch_add(1, Ordering::Relaxed);
        let woken = preempt::block_until(deadline, &self.waiters[slot].woken);
        self.release(slot);
        if !woken {
            TIMEOUTS.fetch_add(1, Ordering::Relaxed);
        }
        ready()
    }

    /// Wait until `ready` returns `Some`, or until `deadline` (`None`: for as long as it
    /// takes). A wake that finds the condition still false waits again.
    pub fn wait_until<R>(
        &self,
        deadline: Option<Instant>,
        mut ready: impl FnMut() -> Option<R>,
    ) -> Result<R, TimedOut> {
        loop {
            if let Some(r) = self.wait_once(deadline, &mut ready) {
                return Ok(r);
            }
            if !preempt::scheduled() || deadline.is_some_and(|d| timekeeping::now() >= d) {
                return Err(TimedOut);
            }
        }
    }

    /// Wake every thread waiting here. Returns how many were blocked and are now runnable.
    /// Call after changing what the waiters are waiting for.
    pub fn wake_all(&self) -> usize {
        let here = Cpu::cpu_index();
        let _guard = self.lock.lock_irqsave();
        let mut woke = 0;
        for w in &self.waiters {
            let raw = w.thread.load(Ordering::Acquire);
            if raw == FREE {
                continue;
            }
            // The flag first, then the wake: see `preempt::block_until`.
            w.woken.store(true, Ordering::Release);
            if preempt::wake_blocked(ThreadId::new(raw)) {
                woke += 1;
                WAKES.fetch_add(1, Ordering::Relaxed);
                if w.cpu.load(Ordering::Relaxed) != here {
                    CROSS_CPU_WAKES.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
        woke
    }
}

/// The deadline `timeout_ns` from now, as the ABI spells a timeout: `u64::MAX` is no deadline.
pub fn deadline_after(timeout_ns: u64) -> Option<Instant> {
    (timeout_ns != u64::MAX)
        .then(|| timekeeping::now().saturating_add(Duration::from_nanos(timeout_ns)))
}

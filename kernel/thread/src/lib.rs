//! Kernel threads: scheduling policy bound to the architecture's context switch.
//!
//! `sched` decides who runs next and knows nothing about machines. `hal`'s
//! `HasContextSwitch` swaps two threads and knows nothing about policy. This crate is
//! the small, careful piece in between, and almost all of its care goes into one set of
//! invariants — because every scheduler bug worth fearing is one of them breaking:
//!
//! 1. **Every CPU that has joined runs exactly one thread**, the one [`Threads::current_on`] names,
//!    and no thread is `Running` without being some CPU's current thread.
//! 2. **A `Running` thread is never in a run queue.** If it were, it could be picked to run while
//!    already running — two CPUs, or one CPU twice, on one stack.
//! 3. **A `Blocked` or `Exited` thread is never in a run queue**, so nothing can resume a thread
//!    that is waiting, or one whose stack has been given back.
//! 4. **A `Ready` thread is in exactly one run queue: the queue of the CPU it names, and a CPU its
//!    affinity allows.**
//! 5. **A switch is never made from a thread to itself.** The contract forbids aliasing `from` and
//!    `to`, and a self-switch would save a context and immediately restore a half-written one.
//!
//! [`Threads::check`] asserts all five, and every test calls it after every operation.
//!
//! # Why the switching operations take a raw pointer
//!
//! [`Threads::yield_now`], [`Threads::block`] and [`Threads::exit`] take `*mut Self`, not
//! `&mut self`. The first draft took `&mut self`, and that was fine against the mock,
//! whose switch returns at once. It stopped being fine when preemption made it real.
//! A thread that switches away is suspended *inside* the call, still holding its
//! `&mut self`. The thread that resumes then makes its own call on the same table and
//! creates a second `&mut` while the first is still live. Two live exclusive references
//! to one table break Rust's aliasing rules, and the optimiser relies on those rules.
//! Masking interrupts changes nothing here, because the rule concerns references, not
//! concurrency.
//!
//! So each operation is split in two. The bookkeeping runs under a `&mut self` that ends
//! before anything switches and yields a private `Switch` naming two slots. The switch
//! is then made through pointers projected from the raw table pointer, so no reference
//! is live across it, and a resumed thread reads nothing through the table it held.
//!
//! # One CPU or many
//!
//! `CPUS` is the number of run queues, one per CPU, and it defaults to one. With one, this
//! is the Phase 2 scheduler, and every `_on` operation is the plain one on CPU 0. With
//! more, each CPU picks only from its own queue, and threads move between queues in three
//! ways, all decided by `sched::balance`: a woken thread is placed on a CPU
//! ([`Threads::wake_on`]), a CPU pulls a waiting thread from a busier one
//! ([`Threads::balance`]), and a yielding thread whose affinity no longer includes its CPU
//! is queued on one it allows.
//!
//! The table has no lock of its own. Its owner provides the exclusion, and on a
//! multiprocessor that exclusion must span the context switch: taken by the thread that
//! switches away, released by the thread the switch resumes. Released any earlier, another
//! CPU could pick the thread that is leaving while its registers are still being saved,
//! and resume a half-written context. That is also why the table can hand a ready thread
//! to any CPU the moment it is queued: by the time the lock is free, its context is
//! complete. The cost is that every context switch on every CPU is serialised. That is a
//! few hundred instructions on eight CPUs, and splitting the lock per run queue later
//! changes no decision made here.

#![cfg_attr(not(test), no_std)]
#![deny(unsafe_code)]

use hal::{HasContextSwitch, KernAddr, ThreadEntry};
use sched::balance::{self, CpuLoad, CpuSet};
use sched::{Priority, RunQueue, ThreadId};

/// Where a thread is in its life.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum State {
    /// Queued and waiting for a CPU.
    Ready,
    /// On a CPU now.
    Running,
    /// Waiting for something; not queued, and not runnable until woken.
    Blocked,
    /// Finished. Its slot is not reused until the thread is reaped.
    Exited,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Error {
    /// Every slot holds a thread.
    TableFull,
    /// The run queue could not accept the thread.
    QueueFull,
    /// No thread with this id exists.
    NoSuchThread,
    /// The thread is not in the state the operation requires.
    WrongState(State),
    /// Blocking or exiting would leave nothing to run. On a real machine an idle thread
    /// prevents this; reporting it rather than switching to nothing keeps the failure
    /// diagnosable instead of a jump to an empty context.
    NothingRunnable,
    /// The stack given to `spawn` is too small or misaligned for this architecture.
    BadStack,
    /// The scheduler picked the thread that is already running, which is only possible
    /// if a running thread was somehow queued. The table is corrupt; nothing was
    /// switched.
    InvariantBroken,
    /// A CPU number past the table's run queues, or one the operation needs joined that
    /// is not, or one already running a thread.
    BadCpu,
    /// An affinity that allows no CPU the table has, or one the requested CPU is not in.
    BadAffinity,
}

#[derive(Clone, Copy)]
struct Meta {
    id: ThreadId,
    priority: Priority,
    state: State,
    /// The CPU whose queue holds it while `Ready`, that runs it while `Running`, and that
    /// last ran it otherwise.
    cpu: usize,
    /// The CPUs it may run on.
    affinity: CpuSet,
    /// A CPU's idle thread: not counted as load, never migrated.
    idle: bool,
}

/// Where a woken thread was queued, and whether that CPU needs a reschedule IPI to notice
/// promptly.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Woken {
    pub cpu: usize,
    /// The thread would run at once or share a slice there. When `cpu` is not the caller's
    /// CPU, the caller should interrupt it.
    pub reschedule: bool,
}

/// The thread table.
///
/// Contexts live in their own array rather than beside the metadata, so the context
/// switch can take two raw pointers into one array without first creating a reference
/// to either element — two references into the same array, one of them mutable, is
/// exactly the aliasing the switch's contract forbids.
pub struct Threads<A: HasContextSwitch, const N: usize, const CPUS: usize = 1> {
    meta: [Option<Meta>; N],
    contexts: [A::Context; N],
    runq: [RunQueue<N>; CPUS],
    /// The slot each CPU runs, or `None` for a CPU that has not joined.
    current: [Option<usize>; CPUS],
    next_id: u32,
    migrations: u64,
}

/// A switch the table has recorded and not yet made: the slot to save into, and the slot
/// to resume.
///
/// Private and consumed only by `Threads::perform`. Once the bookkeeping has run, the
/// table already names `to` as running, so a switch planned and never made would leave
/// the table describing a thread that is not on the CPU.
#[must_use]
struct Switch {
    from: usize,
    to: usize,
}

impl<A: HasContextSwitch, const N: usize, const CPUS: usize> Threads<A, N, CPUS> {
    /// A table holding the thread that is running right now, on CPU 0.
    ///
    /// That thread's context is left empty: it is filled in by the first switch away
    /// from it, which is the only way to capture a running thread's state honestly. The
    /// other CPUs join later, through [`Threads::adopt`].
    pub fn new(boot_priority: Priority) -> Self {
        assert!(N > 0, "a thread table must hold at least the running thread");
        assert!(CPUS > 0 && CPUS <= 64, "a thread table has between 1 and 64 run queues");
        let mut meta = [None; N];
        meta[0] = Some(Meta {
            id: ThreadId::new(0),
            priority: boot_priority,
            state: State::Running,
            cpu: 0,
            affinity: CpuSet::all(CPUS),
            idle: false,
        });
        let mut current = [None; CPUS];
        current[0] = Some(0);
        Threads {
            meta,
            contexts: core::array::from_fn(|_| A::Context::default()),
            runq: core::array::from_fn(|_| RunQueue::new()),
            current,
            next_id: 1,
            migrations: 0,
        }
    }

    /// The thread on CPU 0.
    pub fn current(&self) -> ThreadId {
        self.current_on(0).unwrap_or(ThreadId::new(0))
    }

    /// The thread on CPU `cpu`, or `None` if that CPU has not joined.
    pub fn current_on(&self, cpu: usize) -> Option<ThreadId> {
        let slot = (*self.current.get(cpu)?)?;
        self.meta[slot].map(|m| m.id)
    }

    pub fn state(&self, id: ThreadId) -> Option<State> {
        self.index_of(id)
            .and_then(|i| self.meta[i])
            .map(|m| m.state)
    }

    /// The CPU a thread is queued on, runs on, or last ran on.
    pub fn cpu_of(&self, id: ThreadId) -> Option<usize> {
        self.index_of(id).and_then(|i| self.meta[i]).map(|m| m.cpu)
    }

    /// Threads ready on every CPU.
    pub fn runnable(&self) -> usize {
        self.runq.iter().map(RunQueue::len).sum()
    }

    /// Threads moved from one CPU to another since the table was made, by placement,
    /// balancing or affinity.
    pub fn migrations(&self) -> u64 {
        self.migrations
    }

    /// Whether a yield on CPU 0 now would switch. See [`Threads::contended_on`].
    pub fn contended(&self) -> bool {
        self.contended_on(0)
    }

    /// Whether a yield on CPU `cpu` now would switch: some thread ready there has at
    /// least the running thread's priority.
    ///
    /// What a tickless scheduler asks before it arms a time slice. A thread alone at the
    /// top priority needs no slice, because nothing is waiting for its CPU, and arming
    /// one anyway turns tickless back into periodic.
    pub fn contended_on(&self, cpu: usize) -> bool {
        let Some(cur) = self.running_meta(cpu) else {
            return false;
        };
        self.runq[cpu]
            .peek()
            .and_then(|(id, _)| self.index_of(id))
            .and_then(|i| self.meta[i])
            .is_some_and(|next| next.priority >= cur.priority)
    }

    fn running_meta(&self, cpu: usize) -> Option<Meta> {
        let slot = (*self.current.get(cpu)?)?;
        self.meta[slot]
    }

    fn index_of(&self, id: ThreadId) -> Option<usize> {
        self.meta.iter().position(|m| m.is_some_and(|m| m.id == id))
    }

    fn slot_of_id(&self, id: ThreadId) -> Result<usize, Error> {
        self.index_of(id).ok_or(Error::NoSuchThread)
    }

    /// Every CPU as `sched::balance` sees it.
    pub fn loads(&self) -> [CpuLoad; CPUS] {
        core::array::from_fn(|cpu| {
            let running = self.running_meta(cpu);
            let queued = self.runq[cpu]
                .iter()
                .filter(|&(id, _)| {
                    self.index_of(id)
                        .and_then(|i| self.meta[i])
                        .is_some_and(|m| !m.idle)
                })
                .count();
            CpuLoad {
                online: running.is_some(),
                running: running.filter(|m| !m.idle).map(|m| m.priority),
                queued,
            }
        })
    }

    /// Make whatever runs on CPU `cpu` right now a thread of this table, as `new` does for
    /// CPU 0. `idle` marks it as that CPU's idle thread, which balancing never moves and
    /// load never counts; an idle thread's affinity must be that CPU alone.
    pub fn adopt(
        &mut self,
        cpu: usize,
        priority: Priority,
        affinity: CpuSet,
        idle: bool,
    ) -> Result<ThreadId, Error> {
        if cpu >= CPUS || self.current[cpu].is_some() {
            return Err(Error::BadCpu);
        }
        if !affinity.contains(cpu) || (idle && affinity != CpuSet::single(cpu)) {
            return Err(Error::BadAffinity);
        }
        let slot = self
            .meta
            .iter()
            .position(|m| m.is_none())
            .ok_or(Error::TableFull)?;
        let id = ThreadId::new(self.next_id);
        self.next_id = self.next_id.wrapping_add(1);
        self.contexts[slot] = A::Context::default();
        self.meta[slot] = Some(Meta {
            id,
            priority,
            state: State::Running,
            cpu,
            affinity,
            idle,
        });
        self.current[cpu] = Some(slot);
        Ok(id)
    }

    /// Create a thread that will begin at `entry(arg)` on the stack `[top - size, top)`,
    /// and queue it on CPU 0, allowed everywhere.
    ///
    /// The size is required, not just the top, because it is the only way to check the
    /// stack is big enough. An earlier draft took the top alone and "checked" it by
    /// comparing an address against a byte count, which is not a check of anything.
    ///
    /// # Safety
    /// The region must satisfy [`HasContextSwitch::init`]'s contract: mapped, writable,
    /// owned by this thread alone for as long as it can run.
    #[allow(unsafe_code)]
    pub unsafe fn spawn(
        &mut self,
        entry: ThreadEntry,
        arg: usize,
        priority: Priority,
        stack_top: KernAddr,
        stack_size: usize,
    ) -> Result<ThreadId, Error> {
        // SAFETY: forwarded; the caller's contract.
        unsafe {
            self.spawn_on(entry, arg, priority, stack_top, stack_size, CpuSet::all(CPUS), 0, false)
        }
    }

    /// Create a thread as [`Threads::spawn`] does, allowed on `affinity`, queued on `cpu`.
    /// `idle` as for [`Threads::adopt`].
    ///
    /// # Safety
    /// As [`Threads::spawn`].
    #[allow(unsafe_code, clippy::too_many_arguments)]
    pub unsafe fn spawn_on(
        &mut self,
        entry: ThreadEntry,
        arg: usize,
        priority: Priority,
        stack_top: KernAddr,
        stack_size: usize,
        affinity: CpuSet,
        cpu: usize,
        idle: bool,
    ) -> Result<ThreadId, Error> {
        if cpu >= CPUS {
            return Err(Error::BadCpu);
        }
        if !affinity.contains(cpu) || (idle && affinity != CpuSet::single(cpu)) {
            return Err(Error::BadAffinity);
        }
        // Measure what is left once the top is rounded down to the required alignment:
        // that rounding can cost up to `STACK_ALIGN - 1` bytes of the region.
        let aligned = hal::context::aligned_stack_top::<A>(stack_top);
        let lost = stack_top.raw() - aligned.raw();
        if stack_size < lost || stack_size - lost < A::MIN_STACK {
            return Err(Error::BadStack);
        }
        let slot = self
            .meta
            .iter()
            .position(|m| m.is_none())
            .ok_or(Error::TableFull)?;

        let id = ThreadId::new(self.next_id);
        // SAFETY: the caller guarantees the stack satisfies `init`'s contract, and this
        // slot's context is not in use — the slot was empty.
        unsafe { A::init(&mut self.contexts[slot], stack_top, entry, arg) };

        self.runq[cpu]
            .enqueue(id, priority)
            .map_err(|_| Error::QueueFull)?;
        self.meta[slot] = Some(Meta {
            id,
            priority,
            state: State::Ready,
            cpu,
            affinity,
            idle,
        });
        self.next_id = self.next_id.wrapping_add(1);
        Ok(id)
    }

    /// Change the CPUs a thread may run on.
    ///
    /// A ready thread queued on a CPU it no longer allows is moved at once. A running
    /// thread keeps its CPU until it next yields, blocks or is preempted, and is queued
    /// on a CPU it allows then. Neither move interrupts the CPU it lands on, which picks
    /// the thread up at its next scheduling point. Idle threads cannot be moved.
    pub fn set_affinity(&mut self, id: ThreadId, affinity: CpuSet) -> Result<(), Error> {
        let slot = self.slot_of_id(id)?;
        let m = self.meta[slot].ok_or(Error::NoSuchThread)?;
        let usable = affinity.intersect(CpuSet::all(CPUS));
        if usable.is_empty() || m.idle {
            return Err(Error::BadAffinity);
        }
        if let Some(meta) = self.meta[slot].as_mut() {
            meta.affinity = usable;
        }
        if m.state == State::Ready && !usable.contains(m.cpu) {
            let to = self
                .place(usable, m.cpu, m.priority)
                .ok_or(Error::BadAffinity)?;
            self.move_queued(slot, m.cpu, to)?;
        }
        Ok(())
    }

    /// Give up CPU 0 to another thread. See [`Threads::yield_on`].
    ///
    /// # Safety
    /// See [`Threads::perform`]'s contract, which every switching operation shares.
    #[allow(unsafe_code)]
    pub unsafe fn yield_now(table: *mut Self) -> Result<(), Error> {
        // SAFETY: forwarded.
        unsafe { Self::yield_on(table, 0) }
    }

    /// Give up CPU `cpu`, which must be the caller's, to a thread of equal or higher
    /// priority ready there, if one is.
    ///
    /// Returns without switching when nothing else is runnable — yielding to yourself is
    /// not a switch, and must not become one (invariant 5).
    ///
    /// This is also the whole of preemption. A timer interrupt that calls it switches
    /// exactly when a voluntary yield would: to a peer at the same level, which is round
    /// robin, or to a higher level that something has just woken.
    ///
    /// # Safety
    /// See [`Threads::perform`]'s contract, which every switching operation shares.
    #[allow(unsafe_code)]
    pub unsafe fn yield_on(table: *mut Self, cpu: usize) -> Result<(), Error> {
        // SAFETY: the caller guarantees `table` is valid and unaliased by any live
        // reference; this `&mut` ends at the end of the statement.
        if let Some(sw) = unsafe { (*table).plan_yield(cpu) }? {
            // SAFETY: `sw` was just planned on this table, and the caller's contract is
            // `perform`'s.
            unsafe { Self::perform(table, sw) };
        }
        Ok(())
    }

    fn plan_yield(&mut self, cpu: usize) -> Result<Option<Switch>, Error> {
        let cur_slot = (*self.current.get(cpu).ok_or(Error::BadCpu)?).ok_or(Error::BadCpu)?;
        let cur = self.meta[cur_slot].ok_or(Error::NoSuchThread)?;
        let allowed_here = cur.affinity.contains(cpu);
        let Some((next_id, _)) = self.runq[cpu].peek() else {
            return Ok(None);
        };
        // Fixed priority: a lower-priority thread does not get the CPU merely because the
        // current one offered it. A thread this CPU may no longer run gives it up anyway.
        let next_prio = self
            .index_of(next_id)
            .and_then(|i| self.meta[i])
            .map(|m| m.priority)
            .ok_or(Error::NoSuchThread)?;
        if next_prio < cur.priority && allowed_here {
            return Ok(None);
        }

        let to = if allowed_here {
            cpu
        } else {
            self.place(cur.affinity, cpu, cur.priority)
                .ok_or(Error::BadAffinity)?
        };
        self.runq[to]
            .enqueue(cur.id, cur.priority)
            .map_err(|_| Error::QueueFull)?;
        if to != cpu {
            self.migrations += 1;
        }
        if let Some(m) = self.meta[cur_slot].as_mut() {
            m.state = State::Ready;
            m.cpu = to;
        }
        self.plan_next(cpu).map(Some)
    }

    /// Take the current thread off CPU 0 until something wakes it.
    ///
    /// # Safety
    /// See [`Threads::perform`].
    #[allow(unsafe_code)]
    pub unsafe fn block(table: *mut Self) -> Result<(), Error> {
        // SAFETY: forwarded.
        unsafe { Self::block_on(table, 0) }
    }

    /// Take the current thread off CPU `cpu`, the caller's, until something wakes it.
    ///
    /// # Safety
    /// See [`Threads::perform`].
    #[allow(unsafe_code)]
    pub unsafe fn block_on(table: *mut Self, cpu: usize) -> Result<(), Error> {
        // SAFETY: as in `yield_on`.
        let sw = unsafe { (*table).plan_leave(cpu, State::Blocked) }?;
        // SAFETY: as in `yield_on`.
        unsafe { Self::perform(table, sw) };
        Ok(())
    }

    fn plan_leave(&mut self, cpu: usize, state: State) -> Result<Switch, Error> {
        let cur = (*self.current.get(cpu).ok_or(Error::BadCpu)?).ok_or(Error::BadCpu)?;
        if self.runq[cpu].is_empty() {
            return Err(Error::NothingRunnable);
        }
        self.set_state(cur, state);
        self.plan_next(cpu)
    }

    /// Make a blocked thread runnable again, on CPU 0's reckoning. See
    /// [`Threads::wake_on`].
    pub fn wake(&mut self, id: ThreadId) -> Result<(), Error> {
        self.wake_on(id).map(|_| ())
    }

    /// Make a blocked thread runnable again, and queue it where `sched::balance` places
    /// it. Returns where that is, and whether that CPU needs a reschedule IPI.
    pub fn wake_on(&mut self, id: ThreadId) -> Result<Woken, Error> {
        let slot = self.slot_of_id(id)?;
        let m = self.meta[slot].ok_or(Error::NoSuchThread)?;
        if m.state != State::Blocked {
            return Err(Error::WrongState(m.state));
        }
        let loads = self.loads();
        let cpu = if m.idle {
            m.cpu
        } else {
            balance::place_wake(&loads, m.affinity, m.cpu, m.priority).ok_or(Error::BadAffinity)?
        };
        self.runq[cpu]
            .enqueue(id, m.priority)
            .map_err(|_| Error::QueueFull)?;
        if cpu != m.cpu {
            self.migrations += 1;
        }
        if let Some(meta) = self.meta[slot].as_mut() {
            meta.state = State::Ready;
            meta.cpu = cpu;
        }
        Ok(Woken {
            cpu,
            reschedule: balance::needs_reschedule(&loads[cpu], m.priority),
        })
    }

    /// Let CPU `cpu` pull one ready thread from the busiest other CPU, if balancing is
    /// due (see `sched::balance`). Returns the thread moved and the CPU it came from.
    ///
    /// Takes the highest-priority thread there that `cpu` may run and that is not an idle
    /// thread. Running threads are never moved.
    pub fn balance(&mut self, cpu: usize) -> Option<(ThreadId, usize)> {
        if cpu >= CPUS || self.current[cpu].is_none() {
            return None;
        }
        let loads = self.loads();
        let from = balance::pull_source(&loads, cpu)?;
        let (id, slot) = self.runq[from].iter().find_map(|(id, _)| {
            let slot = self.index_of(id)?;
            let m = self.meta[slot]?;
            (!m.idle && m.affinity.contains(cpu)).then_some((id, slot))
        })?;
        self.move_queued(slot, from, cpu).ok()?;
        Some((id, from))
    }

    fn place(&self, affinity: CpuSet, last: usize, priority: Priority) -> Option<usize> {
        balance::place_wake(&self.loads(), affinity, last, priority)
    }

    /// Move a queued thread from one CPU's queue to another's.
    fn move_queued(&mut self, slot: usize, from: usize, to: usize) -> Result<(), Error> {
        let m = self.meta[slot].ok_or(Error::NoSuchThread)?;
        if from == to {
            return Ok(());
        }
        self.runq[to]
            .enqueue(m.id, m.priority)
            .map_err(|_| Error::QueueFull)?;
        if self.runq[from].remove(m.id).is_err() {
            // Not where the table said: undo, and report the corruption.
            let _ = self.runq[to].remove(m.id);
            return Err(Error::InvariantBroken);
        }
        if let Some(meta) = self.meta[slot].as_mut() {
            meta.cpu = to;
        }
        self.migrations += 1;
        Ok(())
    }

    /// End the current thread on CPU 0 and run another. See [`Threads::exit_on`].
    ///
    /// # Safety
    /// See [`Threads::perform`].
    #[allow(unsafe_code)]
    pub unsafe fn exit(table: *mut Self) -> Result<(), Error> {
        // SAFETY: forwarded.
        unsafe { Self::exit_on(table, 0) }
    }

    /// End the current thread on CPU `cpu`, the caller's, and run another.
    ///
    /// On a real machine a successful exit never returns: nothing switches back to an
    /// exited thread. It is not typed `-> !` here only so the bookkeeping can be tested
    /// against a mock context switch, which does return.
    ///
    /// # Safety
    /// See [`Threads::perform`].
    #[allow(unsafe_code)]
    pub unsafe fn exit_on(table: *mut Self, cpu: usize) -> Result<(), Error> {
        // SAFETY: as in `yield_on`.
        let sw = unsafe { (*table).plan_leave(cpu, State::Exited) }?;
        // SAFETY: as in `yield_on`.
        unsafe { Self::perform(table, sw) };
        Ok(())
    }

    /// The saved context of a thread that is not running, for architecture state beyond
    /// the registers [`HasContextSwitch::init`] prepares: `hal::HasUserMode::bind` records
    /// a user thread's kernel stack and address space here, before it first runs.
    ///
    /// Refused for the running thread, whose context is not saved and would be overwritten
    /// by the next switch away from it.
    pub fn context_mut(&mut self, id: ThreadId) -> Result<&mut A::Context, Error> {
        let slot = self.slot_of_id(id)?;
        match self.meta[slot].map(|m| m.state) {
            Some(State::Running) => Err(Error::WrongState(State::Running)),
            Some(_) => Ok(&mut self.contexts[slot]),
            None => Err(Error::NoSuchThread),
        }
    }

    /// Free an exited thread's slot so it can be reused.
    ///
    /// Separate from `exit` because a thread cannot free the stack it is standing on;
    /// something else has to, after it has stopped running.
    pub fn reap(&mut self, id: ThreadId) -> Result<(), Error> {
        let slot = self.slot_of_id(id)?;
        match self.meta[slot].map(|m| m.state) {
            Some(State::Exited) => {
                self.meta[slot] = None;
                self.contexts[slot] = A::Context::default();
                Ok(())
            }
            Some(s) => Err(Error::WrongState(s)),
            None => Err(Error::NoSuchThread),
        }
    }

    fn set_state(&mut self, slot: usize, state: State) {
        if let Some(m) = self.meta[slot].as_mut() {
            m.state = state;
        }
    }

    /// Pick the next thread for CPU `cpu`, mark it running there, and say which switch
    /// that requires.
    fn plan_next(&mut self, cpu: usize) -> Result<Switch, Error> {
        let prev = self.current[cpu].ok_or(Error::BadCpu)?;
        let (next_id, _) = self.runq[cpu].pick_next().ok_or(Error::NothingRunnable)?;
        let next = self.slot_of_id(next_id)?;

        if let Some(m) = self.meta[next].as_mut() {
            m.state = State::Running;
            m.cpu = cpu;
        }
        self.current[cpu] = Some(next);

        if prev == next {
            // Unreachable while invariant 2 holds. `yield_on` only re-queues the current
            // thread behind a peer of equal or higher priority, and `block_on` and
            // `exit_on` never re-queue it at all — so `pick_next` cannot return it.
            //
            // It is kept as a tripwire rather than removed, and it fails rather than
            // quietly returning `Ok`. Falsifying the tests showed that deleting this guard
            // changed nothing, which is what you would expect of unreachable code — and
            // also exactly what you would see if it silently absorbed a corrupted table.
            // A running thread found in the queue means something upstream is broken, and
            // a self-switch would save a context and immediately restore a half-written
            // one. So it refuses, and says so.
            return Err(Error::InvariantBroken);
        }
        Ok(Switch {
            from: prev,
            to: next,
        })
    }

    /// Make a switch the bookkeeping has already recorded.
    ///
    /// # Safety
    /// The contract every switching operation shares:
    ///
    /// * `table` is valid for reads and writes, and no reference into the table is live while this
    ///   runs. The table is still in use by whichever thread resumes.
    /// * Interrupts are masked, as [`HasContextSwitch::switch`] requires. That makes this callable
    ///   from a timer interrupt, which already runs masked.
    /// * Every context in the table belongs to a thread whose stack is still valid, which `spawn`'s
    ///   contract provides.
    /// * The `cpu` given to the operation is the CPU the caller runs on.
    /// * On a multiprocessor, the exclusion the owner provides is held from before the bookkeeping
    ///   until the resumed thread releases it (see the module documentation).
    #[allow(unsafe_code)]
    unsafe fn perform(table: *mut Self, sw: Switch) {
        // A projection through the raw pointer, not `(*table).contexts`, which would
        // create a reference to the array. `from` and `to` are derived from the table
        // pointer itself, so no borrow that later ends can invalidate them.
        // SAFETY: the caller guarantees `table` is valid, so the field place is too.
        let base = unsafe { (&raw mut (*table).contexts).cast::<A::Context>() };
        // SAFETY: `from` and `to` are distinct indices below `N` (`plan_next` refuses a
        // self-switch), so the two pointers are in bounds and do not alias. `to` was
        // queued, so its context was prepared by `init` or saved by an earlier switch,
        // and it is not running. The caller masks interrupts.
        unsafe {
            let from = base.add(sw.from);
            let to = base.add(sw.to).cast_const();
            A::switch(from, to);
        }
    }

    /// Verify the table's invariants. `Ok` means all hold; `Err` names the first broken.
    pub fn check(&self) -> Result<(), &'static str> {
        let joined = self.current.iter().filter(|c| c.is_some()).count();
        let running = self
            .meta
            .iter()
            .filter(|m| m.is_some_and(|m| m.state == State::Running))
            .count();
        if running != joined {
            return Err("invariant 1: running threads do not match the CPUs that joined");
        }
        for (cpu, slot) in self.current.iter().enumerate() {
            let Some(slot) = *slot else { continue };
            if !self.meta[slot].is_some_and(|m| m.state == State::Running && m.cpu == cpu) {
                return Err("invariant 1: a CPU's current thread is not running there");
            }
            if self.current[cpu + 1..].contains(&Some(slot)) {
                return Err("invariant 1: one thread is current on two CPUs");
            }
        }
        for m in self.meta.iter().flatten() {
            let queues = self.runq.iter().filter(|q| q.contains(m.id)).count();
            match m.state {
                State::Running if queues != 0 => {
                    return Err("invariant 2: running thread is queued");
                }
                State::Blocked | State::Exited if queues != 0 => {
                    return Err("invariant 3: blocked or exited thread is queued");
                }
                State::Ready if queues != 1 || !self.runq[m.cpu].contains(m.id) => {
                    return Err("invariant 4: ready thread is not in exactly its CPU's queue");
                }
                State::Ready if !m.affinity.contains(m.cpu) => {
                    return Err("invariant 4: ready thread is queued on a CPU it may not use");
                }
                _ => {}
            }
        }
        Ok(())
    }
}

// The tests call `spawn`, which is `unsafe` because the stack region is the caller's
// promise. Against the mock that promise is trivially kept: its `init` touches no memory.
#[cfg(test)]
#[allow(unsafe_code)]
mod tests {
    use core::sync::atomic::Ordering;

    use hal::mock::{MockFull, SWITCHES, last_switch};

    use super::*;

    extern "C" fn never(_arg: usize) -> ! {
        panic!("the mock context switch never runs a thread's entry point");
    }

    /// The mock's switch recorder (`SWITCHES`, `last_switch`) is one set of statics for
    /// the whole test binary, and the harness runs tests in parallel, so two tests
    /// switching at once see each other's switches. Every test holds this for its whole
    /// body. A test that panics poisons the lock; the others still run.
    fn serial() -> std::sync::MutexGuard<'static, ()> {
        static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());
        SERIAL.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn p(n: u8) -> Priority {
        Priority::new(n).unwrap()
    }

    // The switching operations take a raw pointer (see the module comment). Against the
    // mock the switch returns at once, and the `&mut` each helper receives is the only
    // reference to the table for the duration of the call, so the contract holds.
    fn yield_now<const N: usize>(t: &mut Threads<MockFull, N>) -> Result<(), Error> {
        // SAFETY: see above.
        unsafe { Threads::yield_now(t) }
    }

    fn block<const N: usize>(t: &mut Threads<MockFull, N>) -> Result<(), Error> {
        // SAFETY: see above.
        unsafe { Threads::block(t) }
    }

    fn exit<const N: usize>(t: &mut Threads<MockFull, N>) -> Result<(), Error> {
        // SAFETY: see above.
        unsafe { Threads::exit(t) }
    }

    const STACK: KernAddr = KernAddr::new(0x10_0000);

    /// Spawn with the argument doubling as the mock context's tag, so `last_switch`
    /// reports which thread was resumed.
    const SIZE: usize = 4096;

    fn spawn(t: &mut Threads<MockFull, 8>, tag: usize, prio: u8) -> ThreadId {
        // SAFETY: the mock `init` records the argument and touches no memory.
        unsafe { t.spawn(never, tag, p(prio), STACK, SIZE) }.unwrap()
    }

    #[test]
    fn a_new_table_holds_only_the_running_thread() {
        let _serial = serial();
        let t: Threads<MockFull, 8> = Threads::new(p(5));
        assert_eq!(t.current(), ThreadId::new(0));
        assert_eq!(t.state(ThreadId::new(0)), Some(State::Running));
        assert_eq!(t.runnable(), 0);
        t.check().unwrap();
    }

    #[test]
    fn spawned_threads_are_ready_and_queued_not_running() {
        let _serial = serial();
        let mut t: Threads<MockFull, 8> = Threads::new(p(5));
        let a = spawn(&mut t, 11, 5);
        assert_eq!(t.state(a), Some(State::Ready));
        assert_eq!(t.current(), ThreadId::new(0), "spawning does not switch");
        t.check().unwrap();
    }

    #[test]
    fn yielding_hands_the_cpu_to_a_ready_peer_and_requeues_itself() {
        let _serial = serial();
        let mut t: Threads<MockFull, 8> = Threads::new(p(5));
        let a = spawn(&mut t, 11, 5);
        let before = SWITCHES.load(Ordering::SeqCst);
        yield_now(&mut t).unwrap();
        assert_eq!(t.current(), a);
        assert_eq!(t.state(ThreadId::new(0)), Some(State::Ready));
        assert_eq!(last_switch().1, 11, "the resumed context belongs to thread a");
        assert!(SWITCHES.load(Ordering::SeqCst) > before);
        t.check().unwrap();
    }

    #[test]
    fn contended_means_a_yield_would_switch() {
        let _serial = serial();
        let mut t: Threads<MockFull, 8> = Threads::new(p(5));
        assert!(!t.contended(), "nothing else exists");
        spawn(&mut t, 11, 4);
        assert!(!t.contended(), "a lower priority does not contend");
        // Judged by the table, not the mock's switch counter: that counter is shared by
        // every test in the binary, and the harness runs them in parallel.
        yield_now(&mut t).unwrap();
        assert_eq!(t.current(), ThreadId::new(0), "and a yield agrees");
        spawn(&mut t, 12, 5);
        assert!(t.contended(), "a peer at the same level contends");
        let high = spawn(&mut t, 13, 6);
        assert!(t.contended(), "so does a higher level");
        yield_now(&mut t).unwrap();
        assert_eq!(t.current(), high, "and a yield switches, to the highest");
        assert!(!t.contended(), "everything still ready is below it");
    }

    #[test]
    fn yielding_with_nothing_else_ready_does_not_switch() {
        let _serial = serial();
        // Invariant 4: a thread must never be switched to itself.
        let mut t: Threads<MockFull, 8> = Threads::new(p(5));
        let before = SWITCHES.load(Ordering::SeqCst);
        yield_now(&mut t).unwrap();
        assert_eq!(t.current(), ThreadId::new(0));
        assert_eq!(SWITCHES.load(Ordering::SeqCst), before, "no switch happened");
        t.check().unwrap();
    }

    #[test]
    fn a_lower_priority_thread_does_not_get_a_yielded_cpu() {
        let _serial = serial();
        let mut t: Threads<MockFull, 8> = Threads::new(p(9));
        spawn(&mut t, 11, 2);
        yield_now(&mut t).unwrap();
        assert_eq!(t.current(), ThreadId::new(0), "fixed priority: the high thread keeps it");
        t.check().unwrap();
    }

    #[test]
    fn repeated_yields_round_robin_through_equal_peers() {
        let _serial = serial();
        let mut t: Threads<MockFull, 8> = Threads::new(p(5));
        let a = spawn(&mut t, 11, 5);
        let b = spawn(&mut t, 12, 5);
        let boot = ThreadId::new(0);
        let mut order = [ThreadId::new(99); 6];
        for slot in order.iter_mut() {
            yield_now(&mut t).unwrap();
            *slot = t.current();
            t.check().unwrap();
        }
        assert_eq!(order, [a, b, boot, a, b, boot]);
    }

    #[test]
    fn a_blocked_thread_leaves_the_queue_and_is_not_resumed_until_woken() {
        let _serial = serial();
        let mut t: Threads<MockFull, 8> = Threads::new(p(5));
        let a = spawn(&mut t, 11, 5);
        block(&mut t).unwrap();
        assert_eq!(t.current(), a);
        assert_eq!(t.state(ThreadId::new(0)), Some(State::Blocked));
        t.check().unwrap();

        // Yielding cannot bring a blocked thread back.
        yield_now(&mut t).unwrap();
        assert_eq!(t.current(), a);
        t.check().unwrap();

        t.wake(ThreadId::new(0)).unwrap();
        assert_eq!(t.state(ThreadId::new(0)), Some(State::Ready));
        yield_now(&mut t).unwrap();
        assert_eq!(t.current(), ThreadId::new(0));
        t.check().unwrap();
    }

    #[test]
    fn blocking_the_only_runnable_thread_is_refused() {
        let _serial = serial();
        // Switching to nothing would resume an empty context. On a machine the idle
        // thread prevents this; here it must be an error, not a jump.
        let mut t: Threads<MockFull, 8> = Threads::new(p(5));
        assert_eq!(block(&mut t), Err(Error::NothingRunnable));
        assert_eq!(t.state(ThreadId::new(0)), Some(State::Running), "nothing changed");
        t.check().unwrap();
    }

    #[test]
    fn waking_a_thread_that_is_not_blocked_is_an_error() {
        let _serial = serial();
        let mut t: Threads<MockFull, 8> = Threads::new(p(5));
        let a = spawn(&mut t, 11, 5);
        assert_eq!(t.wake(a), Err(Error::WrongState(State::Ready)));
        assert_eq!(t.wake(ThreadId::new(0)), Err(Error::WrongState(State::Running)));
        // Waking twice would queue a thread twice; the run queue would refuse, but the
        // state check refuses first, which is the clearer error.
        t.check().unwrap();
    }

    #[test]
    fn an_exited_thread_is_never_resumed_and_can_be_reaped() {
        let _serial = serial();
        let mut t: Threads<MockFull, 8> = Threads::new(p(5));
        let a = spawn(&mut t, 11, 5);
        yield_now(&mut t).unwrap(); // now running a
        exit(&mut t).unwrap();
        assert_eq!(t.current(), ThreadId::new(0));
        assert_eq!(t.state(a), Some(State::Exited));
        t.check().unwrap();

        for _ in 0..5 {
            yield_now(&mut t).unwrap();
            assert_ne!(t.current(), a, "an exited thread must never run again");
        }

        t.reap(a).unwrap();
        assert_eq!(t.state(a), None);
        t.check().unwrap();
    }

    #[test]
    fn a_running_or_ready_thread_cannot_be_reaped() {
        let _serial = serial();
        // Reaping frees the stack. Doing it to a thread that can still run is a
        // use-after-free of its stack.
        let mut t: Threads<MockFull, 8> = Threads::new(p(5));
        let a = spawn(&mut t, 11, 5);
        assert_eq!(t.reap(a), Err(Error::WrongState(State::Ready)));
        assert_eq!(t.reap(ThreadId::new(0)), Err(Error::WrongState(State::Running)));
    }

    #[test]
    fn a_stack_too_small_for_the_architecture_is_refused() {
        let _serial = serial();
        let mut t: Threads<MockFull, 8> = Threads::new(p(5));
        // SAFETY: rejected before init runs, and the mock touches no memory anyway.
        let small = unsafe { t.spawn(never, 1, p(5), STACK, MockFull::MIN_STACK - 1) };
        assert_eq!(small, Err(Error::BadStack));
        // A misaligned top loses bytes to rounding, which must count against the size.
        let top = KernAddr::new(0x10_0007);
        let rounded = unsafe { t.spawn(never, 1, p(5), top, MockFull::MIN_STACK) };
        assert_eq!(rounded, Err(Error::BadStack), "alignment ate part of the stack");
        assert!(unsafe { t.spawn(never, 1, p(5), STACK, MockFull::MIN_STACK) }.is_ok());
        t.check().unwrap();
    }

    #[test]
    fn a_corrupted_queue_trips_the_self_switch_guard_instead_of_switching() {
        let _serial = serial();
        // The guard is unreachable while invariant 2 holds, so the only way to test it is
        // to break invariant 2 deliberately: put the running thread into the run queue.
        let mut t: Threads<MockFull, 8> = Threads::new(p(5));
        let boot = ThreadId::new(0);
        t.runq[0].enqueue(boot, p(5)).unwrap();
        assert!(t.check().is_err(), "the table is now corrupt, and check says so");

        let before = SWITCHES.load(Ordering::SeqCst);
        // `block` picks the head of the queue, which is the running thread itself.
        assert_eq!(block(&mut t), Err(Error::InvariantBroken));
        assert_eq!(SWITCHES.load(Ordering::SeqCst), before, "no self-switch was attempted");
    }

    #[test]
    fn only_a_thread_that_is_not_running_exposes_its_context() {
        let _serial = serial();
        let mut t: Threads<MockFull, 8> = Threads::new(p(5));
        let a = spawn(&mut t, 11, 4);
        assert_eq!(t.context_mut(a).map(|c| c.tag), Ok(11), "a ready thread's context");
        assert_eq!(
            t.context_mut(ThreadId::new(0)).map(|_| ()),
            Err(Error::WrongState(State::Running)),
            "the running thread's context is not saved, so it must not be edited"
        );
        assert_eq!(t.context_mut(ThreadId::new(99)).map(|_| ()), Err(Error::NoSuchThread));
        t.check().unwrap();
    }

    #[test]
    fn a_full_table_refuses_new_threads() {
        let _serial = serial();
        let mut t: Threads<MockFull, 2> = Threads::new(p(5));
        // SAFETY: mock init touches no memory.
        unsafe { t.spawn(never, 1, p(5), STACK, SIZE) }.unwrap();
        assert_eq!(unsafe { t.spawn(never, 2, p(5), STACK, SIZE) }, Err(Error::TableFull));
        t.check().unwrap();
    }

    #[test]
    fn reaped_slots_are_reused_and_ids_are_not() {
        let _serial = serial();
        // A reused *id* would let a stale reference to a dead thread name a new one —
        // the same class of bug kobject's handle generations prevent.
        let mut t: Threads<MockFull, 2> = Threads::new(p(5));
        let a = unsafe { t.spawn(never, 1, p(5), STACK, SIZE) }.unwrap();
        yield_now(&mut t).unwrap();
        exit(&mut t).unwrap();
        t.reap(a).unwrap();
        let b = unsafe { t.spawn(never, 2, p(5), STACK, SIZE) }.unwrap();
        assert_ne!(a, b, "the slot is reused, the identity is not");
        t.check().unwrap();
    }

    // ---- several CPUs ------------------------------------------------------------------

    type Smp = Threads<MockFull, 16, 4>;

    fn smp_spawn(t: &mut Smp, tag: usize, prio: u8, affinity: CpuSet, cpu: usize) -> ThreadId {
        // SAFETY: the mock `init` records the argument and touches no memory.
        unsafe { t.spawn_on(never, tag, p(prio), STACK, SIZE, affinity, cpu, false) }.unwrap()
    }

    /// A table with every CPU joined: CPU 0 runs boot at `boot`, CPUs 1-3 their idle
    /// threads, and CPU 0 has an idle thread queued too.
    fn smp_table(boot: u8) -> Smp {
        let mut t = Smp::new(p(boot));
        for cpu in 1..4 {
            t.adopt(cpu, Priority::IDLE, CpuSet::single(cpu), true)
                .unwrap();
        }
        // SAFETY: mock init touches no memory.
        unsafe { t.spawn_on(never, 100, Priority::IDLE, STACK, SIZE, CpuSet::single(0), 0, true) }
            .unwrap();
        t.check().unwrap();
        t
    }

    fn yield_on(t: &mut Smp, cpu: usize) -> Result<(), Error> {
        // SAFETY: as for `yield_now`.
        unsafe { Threads::yield_on(t, cpu) }
    }

    fn block_on(t: &mut Smp, cpu: usize) -> Result<(), Error> {
        // SAFETY: as for `yield_now`.
        unsafe { Threads::block_on(t, cpu) }
    }

    #[test]
    fn cpus_join_by_adoption_and_only_once() {
        let _serial = serial();
        let mut t = Smp::new(p(5));
        assert_eq!(t.current_on(1), None, "not joined yet");
        let idle = t.adopt(1, Priority::IDLE, CpuSet::single(1), true).unwrap();
        assert_eq!(t.current_on(1), Some(idle));
        assert_eq!(t.cpu_of(idle), Some(1));
        assert_eq!(t.adopt(1, Priority::IDLE, CpuSet::single(1), true), Err(Error::BadCpu));
        assert_eq!(t.adopt(4, Priority::IDLE, CpuSet::single(4), true), Err(Error::BadCpu));
        assert_eq!(
            t.adopt(2, Priority::IDLE, CpuSet::all(4), true),
            Err(Error::BadAffinity),
            "an idle thread belongs to one CPU"
        );
        t.check().unwrap();
    }

    #[test]
    fn each_cpu_picks_only_from_its_own_queue() {
        let _serial = serial();
        let mut t = smp_table(5);
        let a = smp_spawn(&mut t, 11, 4, CpuSet::all(4), 2);
        yield_on(&mut t, 1).unwrap();
        assert_ne!(t.current_on(1), Some(a), "queued on 2, not 1");
        yield_on(&mut t, 2).unwrap();
        assert_eq!(t.current_on(2), Some(a));
        assert_eq!(t.cpu_of(a), Some(2));
        t.check().unwrap();
    }

    #[test]
    fn a_woken_thread_is_placed_on_an_idle_cpu_and_asks_for_it() {
        let _serial = serial();
        let mut t = smp_table(5);
        // `a` runs on CPU 2 and blocks there; CPU 2 is idle afterwards.
        let a = smp_spawn(&mut t, 11, 6, CpuSet::all(4), 2);
        yield_on(&mut t, 2).unwrap();
        block_on(&mut t, 2).unwrap();
        // Something busy lands on CPU 2 meanwhile, so its last CPU is no longer idle.
        let b = smp_spawn(&mut t, 12, 3, CpuSet::all(4), 2);
        yield_on(&mut t, 2).unwrap();
        assert_eq!(t.current_on(2), Some(b));

        let woken = t.wake_on(a).unwrap();
        assert_eq!(woken.cpu, 1, "the lowest idle CPU beats a busy last CPU");
        assert!(woken.reschedule, "an idle CPU must be told");
        assert_eq!(t.cpu_of(a), Some(1));
        assert_eq!(t.migrations(), 1);
        t.check().unwrap();
    }

    #[test]
    fn a_thread_below_what_its_cpu_runs_does_not_ask_for_a_reschedule() {
        let _serial = serial();
        let mut t = smp_table(9);
        // Every CPU busy at 8 or above, so the woken thread at 2 cannot run anywhere now.
        for cpu in 1..4 {
            smp_spawn(&mut t, 20 + cpu, 8, CpuSet::single(cpu), cpu);
            yield_on(&mut t, cpu).unwrap();
        }
        let low = smp_spawn(&mut t, 30, 2, CpuSet::all(4), 0);
        yield_on(&mut t, 0).unwrap(); // boot at 9 keeps CPU 0: nothing to do
        // Put `low` on CPU 3, running it there, then block it.
        t.set_affinity(low, CpuSet::single(3)).unwrap();
        assert_eq!(t.cpu_of(low), Some(3), "a queued thread moves with its affinity");
        t.check().unwrap();
        t.set_affinity(low, CpuSet::all(4)).unwrap();
        let before = t.state(low);
        assert_eq!(before, Some(State::Ready));
        // Waking needs it blocked: model it blocking on CPU 3 by taking it out directly.
        t.runq[3].remove(low).unwrap();
        t.set_state(t.index_of(low).unwrap(), State::Blocked);
        t.check().unwrap();
        let woken = t.wake_on(low).unwrap();
        assert!(!woken.reschedule, "a thread at 2 does not disturb a CPU running 8");
        t.check().unwrap();
    }

    #[test]
    fn affinity_is_respected_by_placement_yield_and_balance() {
        let _serial = serial();
        let mut t = smp_table(5);
        let pinned = smp_spawn(&mut t, 11, 4, CpuSet::single(3), 3);
        assert_eq!(
            unsafe { t.spawn_on(never, 1, p(4), STACK, SIZE, CpuSet::single(3), 2, false) },
            Err(Error::BadAffinity),
            "queued on a CPU its affinity excludes"
        );
        // Load CPU 3 up; nobody may pull `pinned` away.
        for i in 0..3 {
            smp_spawn(&mut t, 40 + i, 4, CpuSet::all(4), 3);
        }
        for cpu in 0..3 {
            while t.balance(cpu).is_some() {}
        }
        assert_eq!(t.cpu_of(pinned), Some(3));
        t.check().unwrap();

        // A running thread whose affinity changes leaves at its next yield.
        yield_on(&mut t, 3).unwrap();
        let running = t.current_on(3).unwrap();
        t.set_affinity(running, CpuSet::single(1)).unwrap();
        yield_on(&mut t, 3).unwrap();
        assert_ne!(t.current_on(3), Some(running));
        assert_eq!(t.cpu_of(running), Some(1));
        assert_eq!(t.set_affinity(running, CpuSet::EMPTY), Err(Error::BadAffinity));
        t.check().unwrap();
    }

    #[test]
    fn idle_cpus_pull_waiting_threads_until_the_load_is_even() {
        let _serial = serial();
        let mut t = smp_table(4);
        // Seven threads at boot's level, all queued on CPU 0.
        for i in 0..7 {
            smp_spawn(&mut t, 50 + i, 4, CpuSet::all(4), 0);
        }
        let mut moved = 0;
        for _ in 0..8 {
            for cpu in 1..4 {
                if t.balance(cpu).is_some() {
                    moved += 1;
                    // The pulled thread starts running where it landed.
                    yield_on(&mut t, cpu).unwrap();
                }
            }
            t.check().unwrap();
        }
        let loads = t.loads();
        let (lo, hi) = (
            loads.iter().map(CpuLoad::load).min().unwrap(),
            loads.iter().map(CpuLoad::load).max().unwrap(),
        );
        assert!(hi - lo <= 1, "loads {:?}", loads.map(|l| l.load()));
        assert_eq!(t.migrations(), moved);
        assert!(t.balance(2).is_none(), "balanced: nothing more to pull");
    }

    #[test]
    fn idle_threads_are_neither_load_nor_migrated() {
        let _serial = serial();
        let mut t = smp_table(5);
        let loads = t.loads();
        assert!(loads[1].idle() && loads[2].idle() && loads[3].idle());
        assert_eq!(loads[0].load(), 1, "boot runs; CPU 0's queued idle is not counted");
        assert!(t.balance(1).is_none(), "CPU 0's idle thread stays on CPU 0");
        let idle1 = t.current_on(1).unwrap();
        assert_eq!(t.set_affinity(idle1, CpuSet::all(4)), Err(Error::BadAffinity));
    }

    #[test]
    fn a_long_random_smp_workload_keeps_every_invariant() {
        let _serial = serial();
        let mut t = smp_table(5);
        let mut seed: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut rng = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        let mut spawned: [Option<ThreadId>; 32] = [None; 32];
        let mut n = 0;
        for step in 0..20_000 {
            let r = rng();
            let cpu = (r >> 40) as usize % 4;
            let _ = match r % 8 {
                0 => {
                    let affinity = CpuSet::from_raw((r >> 20) & 0xf);
                    let at = affinity.first().unwrap_or(0);
                    // SAFETY: mock init touches no memory.
                    let res = unsafe {
                        t.spawn_on(
                            never,
                            step,
                            p((r >> 8) as u8 % 8),
                            STACK,
                            SIZE,
                            affinity,
                            at,
                            false,
                        )
                    };
                    if let Ok(id) = res {
                        spawned[n % 32] = Some(id);
                        n += 1;
                    }
                    res.map(|_| ())
                }
                1 => yield_on(&mut t, cpu),
                2 => block_on(&mut t, cpu),
                3 => match spawned[(r >> 16) as usize % 32] {
                    Some(id) => t.wake_on(id).map(|_| ()),
                    None => Ok(()),
                },
                // SAFETY: as for `yield_now`.
                4 => unsafe { Threads::exit_on(&mut t, cpu) },
                5 => match spawned[(r >> 24) as usize % 32] {
                    Some(id) => t.reap(id),
                    None => Ok(()),
                },
                6 => {
                    t.balance(cpu);
                    Ok(())
                }
                _ => match spawned[(r >> 28) as usize % 32] {
                    Some(id) => t.set_affinity(id, CpuSet::from_raw((r >> 32) & 0xf)),
                    None => Ok(()),
                },
            };
            if let Err(msg) = t.check() {
                panic!("step {step}: {msg}");
            }
        }
    }

    #[test]
    fn a_long_random_workload_keeps_every_invariant() {
        let _serial = serial();
        // Individual tests exercise individual transitions; this checks the invariants
        // survive thousands of arbitrary ones interleaved.
        let mut t: Threads<MockFull, 8> = Threads::new(p(5));
        let mut seed: u64 = 0xD1B5_4A32_D192_ED03;
        let mut rng = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        let mut spawned: [Option<ThreadId>; 32] = [None; 32];
        let mut n = 0;

        for step in 0..10_000 {
            let r = rng();
            let result = match r % 6 {
                0 => {
                    let prio = (r >> 8) % 8;
                    // SAFETY: mock init touches no memory.
                    let res = unsafe { t.spawn(never, step, p(prio as u8), STACK, SIZE) };
                    if let Ok(id) = res {
                        spawned[n % 32] = Some(id);
                        n += 1;
                    }
                    res.map(|_| ())
                }
                1 => yield_now(&mut t),
                2 => block(&mut t),
                3 => match spawned[(r >> 16) as usize % 32] {
                    Some(id) => t.wake(id),
                    None => Ok(()),
                },
                4 => exit(&mut t),
                _ => match spawned[(r >> 24) as usize % 32] {
                    Some(id) => t.reap(id),
                    None => Ok(()),
                },
            };
            // Errors are expected and fine; a broken invariant is not.
            let _ = result;
            if let Err(msg) = t.check() {
                panic!("step {step}: {msg}");
            }
        }
    }
}

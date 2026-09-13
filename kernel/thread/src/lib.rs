//! Kernel threads: scheduling policy bound to the architecture's context switch.
//!
//! `sched` decides who runs next and knows nothing about machines. `hal`'s
//! `HasContextSwitch` swaps two threads and knows nothing about policy. This crate is
//! the small, careful piece in between, and almost all of its care goes into one set of
//! invariants — because every scheduler bug worth fearing is one of them breaking:
//!
//! 1. **Exactly one thread is `Running`**, and it is the one [`Threads::current`] names.
//! 2. **A `Running` thread is never in the run queue.** If it were, it could be picked to run while
//!    already running — two threads on one stack.
//! 3. **A `Blocked` or `Exited` thread is never in the run queue**, so nothing can resume a thread
//!    that is waiting, or one whose stack has been given back.
//! 4. **A switch is never made from a thread to itself.** The contract forbids aliasing `from` and
//!    `to`, and a self-switch would save a context and immediately restore a half-written one.
//!
//! [`Threads::check`] asserts all four, and every test calls it after every operation.
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
//! # Single CPU, interrupts masked
//!
//! This is the Phase 2 scheduler: one CPU, and the caller masks interrupts around every
//! operation. Both assumptions are stated at the only place they could be violated — the
//! context switch — rather than being encoded as locks that would suggest an SMP safety
//! this code does not have. The SMP scheduler is a separate piece of work, with per-CPU
//! run queues, and it does not grow out of this one by adding a mutex.

#![cfg_attr(not(test), no_std)]
#![deny(unsafe_code)]

use hal::{HasContextSwitch, KernAddr, ThreadEntry};
use sched::{Priority, RunQueue, ThreadId};

/// Where a thread is in its life.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum State {
    /// Queued and waiting for the CPU.
    Ready,
    /// On the CPU now. Exactly one thread is in this state.
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
}

#[derive(Clone, Copy)]
struct Meta {
    id: ThreadId,
    priority: Priority,
    state: State,
}

/// The thread table.
///
/// Contexts live in their own array rather than beside the metadata, so the context
/// switch can take two raw pointers into one array without first creating a reference
/// to either element — two references into the same array, one of them mutable, is
/// exactly the aliasing the switch's contract forbids.
pub struct Threads<A: HasContextSwitch, const N: usize> {
    meta: [Option<Meta>; N],
    contexts: [A::Context; N],
    runq: RunQueue<N>,
    current: usize,
    next_id: u32,
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

impl<A: HasContextSwitch, const N: usize> Threads<A, N> {
    /// A table holding the thread that is running right now.
    ///
    /// That thread's context is left empty: it is filled in by the first switch away
    /// from it, which is the only way to capture a running thread's state honestly.
    pub fn new(boot_priority: Priority) -> Self {
        assert!(N > 0, "a thread table must hold at least the running thread");
        let mut meta = [None; N];
        meta[0] = Some(Meta {
            id: ThreadId::new(0),
            priority: boot_priority,
            state: State::Running,
        });
        Threads {
            meta,
            contexts: core::array::from_fn(|_| A::Context::default()),
            runq: RunQueue::new(),
            current: 0,
            next_id: 1,
        }
    }

    /// The thread on the CPU.
    pub fn current(&self) -> ThreadId {
        self.meta[self.current]
            .map(|m| m.id)
            .unwrap_or(ThreadId::new(0))
    }

    pub fn state(&self, id: ThreadId) -> Option<State> {
        self.index_of(id)
            .and_then(|i| self.meta[i])
            .map(|m| m.state)
    }

    pub fn runnable(&self) -> usize {
        self.runq.len()
    }

    /// Whether a yield now would switch: some ready thread has at least the running
    /// thread's priority.
    ///
    /// What a tickless scheduler asks before it arms a time slice. A thread alone at the
    /// top priority needs no slice, because nothing is waiting for its CPU, and arming
    /// one anyway turns tickless back into periodic.
    pub fn contended(&self) -> bool {
        let Some(cur) = self.meta[self.current] else {
            return false;
        };
        self.runq
            .peek()
            .and_then(|(id, _)| self.index_of(id))
            .and_then(|i| self.meta[i])
            .is_some_and(|next| next.priority >= cur.priority)
    }

    fn index_of(&self, id: ThreadId) -> Option<usize> {
        self.meta.iter().position(|m| m.is_some_and(|m| m.id == id))
    }

    fn slot_of_id(&self, id: ThreadId) -> Result<usize, Error> {
        self.index_of(id).ok_or(Error::NoSuchThread)
    }

    /// Create a thread that will begin at `entry(arg)` on the stack `[top - size, top)`,
    /// and queue it.
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

        self.runq
            .enqueue(id, priority)
            .map_err(|_| Error::QueueFull)?;
        self.meta[slot] = Some(Meta {
            id,
            priority,
            state: State::Ready,
        });
        self.next_id = self.next_id.wrapping_add(1);
        Ok(id)
    }

    /// Give up the CPU to another thread of equal or higher priority, if one is ready.
    ///
    /// Returns without switching when nothing else is runnable — yielding to yourself is
    /// not a switch, and must not become one (invariant 4).
    ///
    /// This is also the whole of preemption. A timer interrupt that calls it switches
    /// exactly when a voluntary yield would: to a peer at the same level, which is round
    /// robin, or to a higher level that something has just woken.
    ///
    /// # Safety
    /// See [`Threads::perform`]'s contract, which every switching operation shares.
    #[allow(unsafe_code)]
    pub unsafe fn yield_now(table: *mut Self) -> Result<(), Error> {
        // SAFETY: the caller guarantees `table` is valid and unaliased by any live
        // reference; this `&mut` ends at the end of the statement.
        if let Some(sw) = unsafe { (*table).plan_yield() }? {
            // SAFETY: `sw` was just planned on this table, and the caller's contract is
            // `perform`'s.
            unsafe { Self::perform(table, sw) };
        }
        Ok(())
    }

    fn plan_yield(&mut self) -> Result<Option<Switch>, Error> {
        let cur = self.meta[self.current].ok_or(Error::NoSuchThread)?;
        let Some((next_id, _)) = self.runq.peek() else {
            return Ok(None);
        };
        // Fixed priority: a lower-priority thread does not get the CPU merely because the
        // current one offered it.
        let next_prio = self
            .index_of(next_id)
            .and_then(|i| self.meta[i])
            .map(|m| m.priority)
            .ok_or(Error::NoSuchThread)?;
        if next_prio < cur.priority {
            return Ok(None);
        }

        self.set_state(self.current, State::Ready);
        self.runq
            .enqueue(cur.id, cur.priority)
            .map_err(|_| Error::QueueFull)?;
        self.plan_next().map(Some)
    }

    /// Take the current thread off the CPU until something wakes it.
    ///
    /// # Safety
    /// See [`Threads::perform`].
    #[allow(unsafe_code)]
    pub unsafe fn block(table: *mut Self) -> Result<(), Error> {
        // SAFETY: as in `yield_now`.
        let sw = unsafe { (*table).plan_block() }?;
        // SAFETY: as in `yield_now`.
        unsafe { Self::perform(table, sw) };
        Ok(())
    }

    fn plan_block(&mut self) -> Result<Switch, Error> {
        if self.runq.is_empty() {
            return Err(Error::NothingRunnable);
        }
        self.set_state(self.current, State::Blocked);
        self.plan_next()
    }

    /// Make a blocked thread runnable again.
    pub fn wake(&mut self, id: ThreadId) -> Result<(), Error> {
        let slot = self.slot_of_id(id)?;
        let m = self.meta[slot].ok_or(Error::NoSuchThread)?;
        if m.state != State::Blocked {
            return Err(Error::WrongState(m.state));
        }
        self.runq
            .enqueue(id, m.priority)
            .map_err(|_| Error::QueueFull)?;
        self.set_state(slot, State::Ready);
        Ok(())
    }

    /// End the current thread and run another.
    ///
    /// On a real machine a successful exit never returns: nothing switches back to an
    /// exited thread. It is not typed `-> !` here only so the bookkeeping can be tested
    /// against a mock context switch, which does return.
    ///
    /// # Safety
    /// See [`Threads::perform`].
    #[allow(unsafe_code)]
    pub unsafe fn exit(table: *mut Self) -> Result<(), Error> {
        // SAFETY: as in `yield_now`.
        let sw = unsafe { (*table).plan_exit() }?;
        // SAFETY: as in `yield_now`.
        unsafe { Self::perform(table, sw) };
        Ok(())
    }

    fn plan_exit(&mut self) -> Result<Switch, Error> {
        if self.runq.is_empty() {
            return Err(Error::NothingRunnable);
        }
        self.set_state(self.current, State::Exited);
        self.plan_next()
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

    /// Pick the next thread, mark it running, and say which switch that requires.
    fn plan_next(&mut self) -> Result<Switch, Error> {
        let (next_id, _) = self.runq.pick_next().ok_or(Error::NothingRunnable)?;
        let next = self.slot_of_id(next_id)?;
        let prev = self.current;

        self.set_state(next, State::Running);
        self.current = next;

        if prev == next {
            // Unreachable while invariant 2 holds. `yield_now` only re-queues the current
            // thread behind a peer of equal or higher priority, and `block` and `exit`
            // never re-queue it at all — so `pick_next` cannot return it.
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
        let running: usize = self
            .meta
            .iter()
            .filter(|m| m.is_some_and(|m| m.state == State::Running))
            .count();
        if running != 1 {
            return Err("invariant 1: not exactly one running thread");
        }
        if !self.meta[self.current].is_some_and(|m| m.state == State::Running) {
            return Err("invariant 1: `current` does not name the running thread");
        }
        for m in self.meta.iter().flatten() {
            let queued = self.runq.contains(m.id);
            match m.state {
                State::Running if queued => return Err("invariant 2: running thread is queued"),
                State::Blocked | State::Exited if queued => {
                    return Err("invariant 3: blocked or exited thread is queued");
                }
                State::Ready if !queued => return Err("ready thread is not queued"),
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
        let t: Threads<MockFull, 8> = Threads::new(p(5));
        assert_eq!(t.current(), ThreadId::new(0));
        assert_eq!(t.state(ThreadId::new(0)), Some(State::Running));
        assert_eq!(t.runnable(), 0);
        t.check().unwrap();
    }

    #[test]
    fn spawned_threads_are_ready_and_queued_not_running() {
        let mut t: Threads<MockFull, 8> = Threads::new(p(5));
        let a = spawn(&mut t, 11, 5);
        assert_eq!(t.state(a), Some(State::Ready));
        assert_eq!(t.current(), ThreadId::new(0), "spawning does not switch");
        t.check().unwrap();
    }

    #[test]
    fn yielding_hands_the_cpu_to_a_ready_peer_and_requeues_itself() {
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
        let mut t: Threads<MockFull, 8> = Threads::new(p(5));
        assert!(!t.contended(), "nothing else exists");
        spawn(&mut t, 11, 4);
        assert!(!t.contended(), "a lower priority does not contend");
        let before = SWITCHES.load(Ordering::SeqCst);
        yield_now(&mut t).unwrap();
        assert_eq!(SWITCHES.load(Ordering::SeqCst), before, "and a yield agrees");
        spawn(&mut t, 12, 5);
        assert!(t.contended(), "a peer at the same level contends");
        spawn(&mut t, 13, 6);
        assert!(t.contended(), "so does a higher level");
        yield_now(&mut t).unwrap();
        assert_eq!(last_switch().1, 13, "and a yield switches, to the highest");
        assert!(!t.contended(), "everything still ready is below it");
    }

    #[test]
    fn yielding_with_nothing_else_ready_does_not_switch() {
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
        let mut t: Threads<MockFull, 8> = Threads::new(p(9));
        spawn(&mut t, 11, 2);
        yield_now(&mut t).unwrap();
        assert_eq!(t.current(), ThreadId::new(0), "fixed priority: the high thread keeps it");
        t.check().unwrap();
    }

    #[test]
    fn repeated_yields_round_robin_through_equal_peers() {
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
        // Switching to nothing would resume an empty context. On a machine the idle
        // thread prevents this; here it must be an error, not a jump.
        let mut t: Threads<MockFull, 8> = Threads::new(p(5));
        assert_eq!(block(&mut t), Err(Error::NothingRunnable));
        assert_eq!(t.state(ThreadId::new(0)), Some(State::Running), "nothing changed");
        t.check().unwrap();
    }

    #[test]
    fn waking_a_thread_that_is_not_blocked_is_an_error() {
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
        // Reaping frees the stack. Doing it to a thread that can still run is a
        // use-after-free of its stack.
        let mut t: Threads<MockFull, 8> = Threads::new(p(5));
        let a = spawn(&mut t, 11, 5);
        assert_eq!(t.reap(a), Err(Error::WrongState(State::Ready)));
        assert_eq!(t.reap(ThreadId::new(0)), Err(Error::WrongState(State::Running)));
    }

    #[test]
    fn a_stack_too_small_for_the_architecture_is_refused() {
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
        // The guard is unreachable while invariant 2 holds, so the only way to test it is
        // to break invariant 2 deliberately: put the running thread into the run queue.
        let mut t: Threads<MockFull, 8> = Threads::new(p(5));
        let boot = ThreadId::new(0);
        t.runq.enqueue(boot, p(5)).unwrap();
        assert!(t.check().is_err(), "the table is now corrupt, and check says so");

        let before = SWITCHES.load(Ordering::SeqCst);
        // `block` picks the head of the queue, which is the running thread itself.
        assert_eq!(block(&mut t), Err(Error::InvariantBroken));
        assert_eq!(SWITCHES.load(Ordering::SeqCst), before, "no self-switch was attempted");
    }

    #[test]
    fn a_full_table_refuses_new_threads() {
        let mut t: Threads<MockFull, 2> = Threads::new(p(5));
        // SAFETY: mock init touches no memory.
        unsafe { t.spawn(never, 1, p(5), STACK, SIZE) }.unwrap();
        assert_eq!(unsafe { t.spawn(never, 2, p(5), STACK, SIZE) }, Err(Error::TableFull));
        t.check().unwrap();
    }

    #[test]
    fn reaped_slots_are_reused_and_ids_are_not() {
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

    #[test]
    fn a_long_random_workload_keeps_every_invariant() {
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

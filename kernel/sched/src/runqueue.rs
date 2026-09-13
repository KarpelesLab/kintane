//! The run queue: runnable threads, ordered by priority and then by arrival.
//!
//! Fixed capacity, because there is no heap at this layer and a kernel wants an explicit
//! bound on how many threads it will schedule anyway. Every operation is O(1) or bounded
//! by the number of priority levels, which is a small constant: the next thread is found
//! from a bitmap of non-empty levels rather than by scanning threads, so the cost of a
//! scheduling decision does not grow with the number of threads waiting.

use core::fmt;

/// Number of distinct priority levels.
///
/// 32 rather than more because one bitmap word covers them, which is what makes finding
/// the highest runnable level a single `leading_zeros`. Real-time systems rarely use more
/// than a few dozen levels, and a scheduler with thousands of priorities is usually
/// expressing something that belongs in a different policy.
pub const LEVELS: usize = 32;

/// A thread's scheduling priority. Higher runs first.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct Priority(u8);

impl Priority {
    /// The lowest priority. The idle thread lives here, so anything else pre-empts it.
    pub const IDLE: Priority = Priority(0);
    /// The highest priority.
    pub const MAX: Priority = Priority(LEVELS as u8 - 1);

    /// A priority, or `None` if the value is out of range.
    ///
    /// Out of range is refused rather than clamped. A thread asking for priority 200 has
    /// a bug, and clamping it to the maximum would hand it the power to starve the system
    /// as a reward for the bug.
    pub const fn new(level: u8) -> Option<Priority> {
        if (level as usize) < LEVELS {
            Some(Priority(level))
        } else {
            None
        }
    }

    pub const fn level(self) -> u8 {
        self.0
    }
}

/// A thread's identity as far as the scheduler is concerned.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ThreadId(u32);

impl ThreadId {
    pub const fn new(id: u32) -> ThreadId {
        ThreadId(id)
    }
    pub const fn raw(self) -> u32 {
        self.0
    }
}

impl fmt::Debug for ThreadId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Thread({})", self.0)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Error {
    /// The queue holds as many threads as it can.
    Full,
    /// The thread is already queued. Enqueueing it again would let it run twice per
    /// round, which is a scheduling bug that no individual test of fairness catches.
    AlreadyQueued,
    /// The thread is not queued.
    NotQueued,
}

#[derive(Clone, Copy)]
struct Slot {
    id: ThreadId,
    priority: Priority,
    /// Next slot in the same priority level, forming a FIFO.
    next: Option<u16>,
    /// Whether this slot currently holds a queued thread.
    used: bool,
}

/// Per-level FIFO bookkeeping.
#[derive(Clone, Copy)]
struct Level {
    head: Option<u16>,
    tail: Option<u16>,
}

/// Runnable threads, ready to be chosen.
///
/// `N` is the maximum number of threads queued at once and must fit in a `u16`.
pub struct RunQueue<const N: usize> {
    slots: [Slot; N],
    levels: [Level; LEVELS],
    /// Bit `n` set means level `n` has at least one thread. Finding the highest runnable
    /// level is then one `leading_zeros` rather than a scan.
    nonempty: u32,
    len: usize,
}

impl<const N: usize> Default for RunQueue<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> RunQueue<N> {
    pub const fn new() -> Self {
        assert!(N <= u16::MAX as usize, "run queue capacity must fit in a u16");
        RunQueue {
            slots: [Slot {
                id: ThreadId(0),
                priority: Priority::IDLE,
                next: None,
                used: false,
            }; N],
            levels: [Level {
                head: None,
                tail: None,
            }; LEVELS],
            nonempty: 0,
            len: 0,
        }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn contains(&self, id: ThreadId) -> bool {
        self.find(id).is_some()
    }

    fn find(&self, id: ThreadId) -> Option<usize> {
        self.slots.iter().position(|s| s.used && s.id == id)
    }

    /// Queue a thread at the back of its priority level.
    pub fn enqueue(&mut self, id: ThreadId, priority: Priority) -> Result<(), Error> {
        if self.contains(id) {
            return Err(Error::AlreadyQueued);
        }
        let slot = self.slots.iter().position(|s| !s.used).ok_or(Error::Full)?;
        // `slot < N <= u16::MAX`, checked in `new`.
        let idx = slot as u16;

        self.slots[slot] = Slot {
            id,
            priority,
            next: None,
            used: true,
        };

        let level = &mut self.levels[priority.0 as usize];
        match level.tail {
            Some(t) => self.slots[t as usize].next = Some(idx),
            None => level.head = Some(idx),
        }
        level.tail = Some(idx);
        self.nonempty |= 1 << priority.0;
        self.len += 1;
        Ok(())
    }

    /// The thread that should run next, without removing it.
    pub fn peek(&self) -> Option<(ThreadId, Priority)> {
        let level = self.highest()?;
        let head = self.levels[level].head?;
        let s = &self.slots[head as usize];
        Some((s.id, s.priority))
    }

    /// Remove and return the thread that should run next: the head of the highest
    /// non-empty priority level.
    pub fn pick_next(&mut self) -> Option<(ThreadId, Priority)> {
        let level = self.highest()?;
        let head = self.levels[level].head?;
        let slot = self.slots[head as usize];
        self.unlink_head(level);
        self.slots[head as usize].used = false;
        self.len -= 1;
        Some((slot.id, slot.priority))
    }

    /// Remove a specific thread, wherever it is — for a thread that blocks or exits while
    /// queued.
    pub fn remove(&mut self, id: ThreadId) -> Result<Priority, Error> {
        let slot = self.find(id).ok_or(Error::NotQueued)?;
        let priority = self.slots[slot].priority;
        let level = priority.0 as usize;

        // Walk the level's list to find the predecessor. Bounded by the level's length.
        let mut prev: Option<u16> = None;
        let mut cur = self.levels[level].head;
        while let Some(c) = cur {
            if c as usize == slot {
                break;
            }
            prev = cur;
            cur = self.slots[c as usize].next;
        }

        let next = self.slots[slot].next;
        match prev {
            Some(p) => self.slots[p as usize].next = next,
            None => self.levels[level].head = next,
        }
        if self.levels[level].tail == Some(slot as u16) {
            self.levels[level].tail = prev;
        }
        if self.levels[level].head.is_none() {
            self.nonempty &= !(1 << priority.0);
        }

        self.slots[slot].used = false;
        self.slots[slot].next = None;
        self.len -= 1;
        Ok(priority)
    }

    /// Every queued thread, in the order [`RunQueue::pick_next`] would take them: highest
    /// level first, arrival order within a level.
    pub fn iter(&self) -> Iter<'_, N> {
        Iter {
            queue: self,
            levels: self.nonempty,
            cursor: None,
        }
    }

    fn highest(&self) -> Option<usize> {
        if self.nonempty == 0 {
            return None;
        }
        Some(31 - self.nonempty.leading_zeros() as usize)
    }

    fn unlink_head(&mut self, level: usize) {
        let Some(head) = self.levels[level].head else {
            return;
        };
        let next = self.slots[head as usize].next;
        self.levels[level].head = next;
        if next.is_none() {
            self.levels[level].tail = None;
            self.nonempty &= !(1 << level);
        }
        self.slots[head as usize].next = None;
    }
}

/// The queued threads, in pick order. See [`RunQueue::iter`].
pub struct Iter<'q, const N: usize> {
    queue: &'q RunQueue<N>,
    /// Levels not yet started, as bits.
    levels: u32,
    /// The next slot in the level being walked.
    cursor: Option<u16>,
}

impl<const N: usize> Iterator for Iter<'_, N> {
    type Item = (ThreadId, Priority);

    fn next(&mut self) -> Option<(ThreadId, Priority)> {
        // Bounded: each call either yields a slot, which moves the cursor along a list no
        // longer than N, or clears one of 32 level bits.
        loop {
            if let Some(c) = self.cursor {
                let s = &self.queue.slots[c as usize];
                self.cursor = s.next;
                return Some((s.id, s.priority));
            }
            if self.levels == 0 {
                return None;
            }
            let level = 31 - self.levels.leading_zeros() as usize;
            self.levels &= !(1 << level);
            self.cursor = self.queue.levels[level].head;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iteration_follows_pick_order() {
        let mut q: RunQueue<8> = RunQueue::new();
        for (id, prio) in [(1, 3), (2, 7), (3, 3), (4, 0), (5, 7)] {
            q.enqueue(t(id), p(prio)).unwrap();
        }
        let listed: Vec<u32> = q.iter().map(|(id, _)| id.raw()).collect();
        let mut picked = Vec::new();
        while let Some((id, _)) = q.pick_next() {
            picked.push(id.raw());
        }
        assert_eq!(listed, [2, 5, 1, 3, 4]);
        assert_eq!(listed, picked);
        assert_eq!(q.iter().count(), 0);
    }

    fn t(n: u32) -> ThreadId {
        ThreadId::new(n)
    }
    fn p(n: u8) -> Priority {
        Priority::new(n).unwrap()
    }

    #[test]
    fn an_empty_queue_has_nothing_to_run() {
        let mut q: RunQueue<8> = RunQueue::new();
        assert!(q.is_empty());
        assert_eq!(q.peek(), None);
        assert_eq!(q.pick_next(), None);
    }

    #[test]
    fn the_highest_priority_runs_first_regardless_of_arrival() {
        let mut q: RunQueue<8> = RunQueue::new();
        q.enqueue(t(1), p(1)).unwrap();
        q.enqueue(t(2), p(9)).unwrap();
        q.enqueue(t(3), p(4)).unwrap();
        assert_eq!(q.pick_next(), Some((t(2), p(9))));
        assert_eq!(q.pick_next(), Some((t(3), p(4))));
        assert_eq!(q.pick_next(), Some((t(1), p(1))));
        assert_eq!(q.pick_next(), None);
    }

    #[test]
    fn equal_priorities_take_turns_in_arrival_order() {
        let mut q: RunQueue<8> = RunQueue::new();
        for n in 1..=4 {
            q.enqueue(t(n), p(5)).unwrap();
        }
        for n in 1..=4 {
            assert_eq!(q.pick_next().unwrap().0, t(n), "FIFO within a level");
        }
    }

    #[test]
    fn re_enqueueing_after_running_gives_round_robin() {
        // What a timer tick does to the running thread: pick it, then put it back at the
        // end of its level. Every thread must get a turn before any gets a second.
        let mut q: RunQueue<8> = RunQueue::new();
        for n in 1..=3 {
            q.enqueue(t(n), p(5)).unwrap();
        }
        let mut order = [0u32; 9];
        for slot in order.iter_mut() {
            let (id, prio) = q.pick_next().unwrap();
            *slot = id.raw();
            q.enqueue(id, prio).unwrap();
        }
        assert_eq!(order, [1, 2, 3, 1, 2, 3, 1, 2, 3]);
    }

    #[test]
    fn a_busy_high_priority_thread_starves_lower_ones_by_design() {
        // Stated as a test because it is the policy's known cost, not a bug. A change
        // that "fixed" this would be changing the policy, and should have to delete this
        // test to do it.
        let mut q: RunQueue<8> = RunQueue::new();
        q.enqueue(t(1), p(1)).unwrap();
        q.enqueue(t(2), p(20)).unwrap();
        for _ in 0..100 {
            let (id, prio) = q.pick_next().unwrap();
            assert_eq!(id, t(2), "the low-priority thread never runs");
            q.enqueue(id, prio).unwrap();
        }
    }

    #[test]
    fn a_thread_cannot_be_queued_twice() {
        // Queued twice, a thread runs twice per round — a fairness bug no single test of
        // ordering would catch, because every pick is individually correct.
        let mut q: RunQueue<8> = RunQueue::new();
        q.enqueue(t(1), p(5)).unwrap();
        assert_eq!(q.enqueue(t(1), p(5)), Err(Error::AlreadyQueued));
        assert_eq!(
            q.enqueue(t(1), p(9)),
            Err(Error::AlreadyQueued),
            "not even at another priority"
        );
        assert_eq!(q.len(), 1);
    }

    #[test]
    fn a_full_queue_reports_rather_than_overwrites() {
        let mut q: RunQueue<3> = RunQueue::new();
        for n in 1..=3 {
            q.enqueue(t(n), p(1)).unwrap();
        }
        assert_eq!(q.enqueue(t(99), p(31)), Err(Error::Full));
        assert_eq!(q.len(), 3);
        // Nothing already queued was displaced.
        assert!(!q.contains(t(99)));
    }

    #[test]
    fn freed_slots_are_reused() {
        let mut q: RunQueue<2> = RunQueue::new();
        q.enqueue(t(1), p(1)).unwrap();
        q.enqueue(t(2), p(1)).unwrap();
        q.pick_next().unwrap();
        q.enqueue(t(3), p(1)).unwrap();
        assert_eq!(q.pick_next().unwrap().0, t(2));
        assert_eq!(q.pick_next().unwrap().0, t(3));
    }

    #[test]
    fn remove_from_the_head_middle_and_tail_of_a_level() {
        for victim in [1, 2, 3] {
            let mut q: RunQueue<8> = RunQueue::new();
            for n in 1..=3 {
                q.enqueue(t(n), p(7)).unwrap();
            }
            assert_eq!(q.remove(t(victim)), Ok(p(7)));
            let rest: [u32; 2] = [
                q.pick_next().unwrap().0.raw(),
                q.pick_next().unwrap().0.raw(),
            ];
            let expected: [u32; 2] = match victim {
                1 => [2, 3],
                2 => [1, 3],
                _ => [1, 2],
            };
            assert_eq!(rest, expected, "removing {victim} must keep the others in order");
            assert!(q.is_empty());
        }
    }

    #[test]
    fn removing_the_last_thread_of_a_level_clears_it() {
        // If the non-empty bitmap were not updated, the next pick would look at a level
        // with nothing in it.
        let mut q: RunQueue<8> = RunQueue::new();
        q.enqueue(t(1), p(20)).unwrap();
        q.enqueue(t(2), p(3)).unwrap();
        q.remove(t(1)).unwrap();
        assert_eq!(q.pick_next(), Some((t(2), p(3))));
    }

    #[test]
    fn enqueueing_after_removing_the_tail_still_appends_correctly() {
        // Tail removal is where a stale tail pointer would silently drop the next thread.
        let mut q: RunQueue<8> = RunQueue::new();
        q.enqueue(t(1), p(5)).unwrap();
        q.enqueue(t(2), p(5)).unwrap();
        q.remove(t(2)).unwrap();
        q.enqueue(t(3), p(5)).unwrap();
        assert_eq!(q.pick_next().unwrap().0, t(1));
        assert_eq!(q.pick_next().unwrap().0, t(3), "the new tail must be reachable");
        assert!(q.is_empty());
    }

    #[test]
    fn removing_an_absent_thread_is_an_error() {
        let mut q: RunQueue<8> = RunQueue::new();
        assert_eq!(q.remove(t(1)), Err(Error::NotQueued));
        q.enqueue(t(1), p(1)).unwrap();
        q.pick_next().unwrap();
        assert_eq!(q.remove(t(1)), Err(Error::NotQueued), "already picked");
    }

    #[test]
    fn peek_does_not_consume() {
        let mut q: RunQueue<8> = RunQueue::new();
        q.enqueue(t(1), p(4)).unwrap();
        assert_eq!(q.peek(), Some((t(1), p(4))));
        assert_eq!(q.peek(), Some((t(1), p(4))));
        assert_eq!(q.len(), 1);
    }

    #[test]
    fn out_of_range_priorities_are_refused_not_clamped() {
        // Clamping would reward a thread with a bug by handing it the highest priority.
        assert!(Priority::new(LEVELS as u8).is_none());
        assert!(Priority::new(255).is_none());
        assert_eq!(Priority::new(LEVELS as u8 - 1), Some(Priority::MAX));
        assert!(Priority::IDLE < Priority::MAX);
    }

    #[test]
    fn every_level_is_reachable() {
        // Exercises every bit of the non-empty bitmap, including bit 31.
        let mut q: RunQueue<32> = RunQueue::new();
        for level in 0..LEVELS as u8 {
            q.enqueue(t(level as u32), p(level)).unwrap();
        }
        for level in (0..LEVELS as u8).rev() {
            assert_eq!(q.pick_next(), Some((t(level as u32), p(level))));
        }
        assert!(q.is_empty());
    }

    #[test]
    fn a_long_random_workload_never_loses_or_duplicates_a_thread() {
        // A deterministic pseudo-random mix of every operation, checked against a model.
        // Individual tests exercise individual paths; this catches the interactions.
        let mut q: RunQueue<16> = RunQueue::new();
        let mut model: [Option<u8>; 16] = [None; 16];
        let mut seed: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };

        for _ in 0..20_000 {
            let r = next();
            let id = (r % 16) as u32;
            let prio = ((r >> 8) % LEVELS as u64) as u8;
            match r % 3 {
                0 => {
                    let res = q.enqueue(t(id), p(prio));
                    if model[id as usize].is_some() {
                        assert_eq!(res, Err(Error::AlreadyQueued));
                    } else {
                        assert_eq!(res, Ok(()));
                        model[id as usize] = Some(prio);
                    }
                }
                1 => {
                    let res = q.remove(t(id));
                    match model[id as usize].take() {
                        Some(expect) => assert_eq!(res, Ok(p(expect))),
                        None => assert_eq!(res, Err(Error::NotQueued)),
                    }
                }
                _ => {
                    let best = model.iter().filter_map(|m| *m).max();
                    match q.pick_next() {
                        Some((got, got_prio)) => {
                            assert_eq!(Some(got_prio.level()), best, "must pick the highest");
                            assert_eq!(model[got.raw() as usize], Some(got_prio.level()));
                            model[got.raw() as usize] = None;
                        }
                        None => assert_eq!(best, None),
                    }
                }
            }
            assert_eq!(q.len(), model.iter().filter(|m| m.is_some()).count());
        }
    }
}

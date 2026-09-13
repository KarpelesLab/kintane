//! Timers: things that should happen at an instant, kept in deadline order.
//!
//! # Shape
//!
//! A binary min-heap over a fixed array of slots. Arming, cancelling and expiring are
//! O(log n); finding the next deadline is O(1). O(1) matters most, because a tickless
//! kernel asks for the next deadline every time it goes idle.
//!
//! Fixed capacity, chosen by the owner, with no allocation. A timer queue is used from
//! interrupt context, where allocation is not available, and a full queue is reported
//! as an error.
//!
//! # Handles
//!
//! Arming returns a [`TimerId`]: a slot index plus a serial number, drawn from a
//! counter that never repeats for the life of the queue. A slot is reused as soon as
//! its timer fires or is cancelled. Without the serial, a caller cancelling a one-shot
//! that had already fired would cancel whichever unrelated timer took the slot next.
//! That bug is silent, and it bites hardest where timers churn fastest. The serial is
//! 64 bits, so it runs out after 2^64 arms, which no machine will reach. The queue
//! still refuses to arm rather than wrap, as `kobject`'s handle table does.
//!
//! Equal deadlines expire in the order they were armed, because the serial is the
//! tie-break. A periodic timer keeps its serial when it re-arms, so among timers due at
//! the same instant it keeps the place it was first given.
//!
//! # Periodic timers do not drift
//!
//! A periodic timer's next deadline is its previous *deadline* plus the period, not the
//! time it happened to be serviced plus the period. The second form adds every
//! servicing delay to all later deadlines, and a 10 ms tick serviced 50 µs late each
//! time is then 0.5% slow for ever. When servicing is so late that whole periods were
//! missed, the timer skips them and reports how many, rather than firing a burst to
//! catch up. That calculation divides, and only runs when periods were missed.
//!
//! # Locking
//!
//! None here. Every mutating operation takes `&mut self`. The owner of the kernel's
//! queue decides how it is shared, just as [`crate::Clock`] leaves it to its owner.

use crate::instant::{Duration, Instant};

/// A reference to an armed timer. Stale once it fires (one-shot) or is cancelled.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct TimerId {
    index: u32,
    serial: u64,
}

/// Why a timer operation was refused.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Error {
    /// Every slot holds an armed timer.
    Full,
    /// The handle does not name an armed timer: it fired, was cancelled, or never
    /// belonged to this queue.
    Stale,
    /// A periodic timer with a zero period would expire endlessly at one instant.
    ZeroPeriod,
    /// The queue has issued every serial number it can. Unreachable in practice.
    Exhausted,
}

/// A timer that has come due.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Expired<T> {
    pub id: TimerId,
    pub payload: T,
    /// The deadline that was due. Not the time it was serviced.
    pub deadline: Instant,
    /// For a periodic timer, whole periods skipped because servicing was late. Zero for
    /// a timer serviced on time and for one-shots.
    pub missed: u64,
    /// For a periodic timer, when it will fire next. `None` for a one-shot, and for a
    /// periodic timer whose next deadline would pass [`Instant::MAX`], which is then
    /// disarmed and its handle made stale.
    pub next: Option<Instant>,
}

#[derive(Clone, Copy)]
struct Armed<T> {
    deadline: Instant,
    period: Option<Duration>,
    serial: u64,
    payload: T,
    /// Where this slot's entry sits in `heap`.
    heap_pos: u32,
}

/// A fixed-capacity queue of up to `N` armed timers, each carrying a `T`.
pub struct TimerQueue<T: Copy, const N: usize> {
    slots: [Option<Armed<T>>; N],
    /// Slot indices, as a binary min-heap ordered by `(deadline, serial)`.
    heap: [u32; N],
    len: usize,
    next_serial: u64,
}

impl<T: Copy, const N: usize> Default for TimerQueue<T, N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Copy, const N: usize> TimerQueue<T, N> {
    pub fn new() -> Self {
        assert!(N <= u32::MAX as usize, "a timer queue indexes slots with u32");
        TimerQueue {
            slots: [None; N],
            heap: [0; N],
            len: 0,
            next_serial: 0,
        }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub const fn capacity(&self) -> usize {
        N
    }

    /// Fire once at `deadline`. A deadline already past fires on the next expiry pass.
    pub fn arm_oneshot(&mut self, deadline: Instant, payload: T) -> Result<TimerId, Error> {
        self.insert(deadline, None, payload)
    }

    /// Fire at `first`, then every `period` after it, measured from deadlines rather
    /// than from when each expiry was serviced.
    pub fn arm_periodic(
        &mut self,
        first: Instant,
        period: Duration,
        payload: T,
    ) -> Result<TimerId, Error> {
        if period.is_zero() {
            return Err(Error::ZeroPeriod);
        }
        self.insert(first, Some(period), payload)
    }

    /// Disarm a timer, returning its payload.
    pub fn cancel(&mut self, id: TimerId) -> Result<T, Error> {
        let armed = self.lookup(id)?;
        self.remove_at(armed.heap_pos as usize);
        self.slots[id.index as usize] = None;
        Ok(armed.payload)
    }

    /// When `id` is next due.
    pub fn deadline(&self, id: TimerId) -> Result<Instant, Error> {
        self.lookup(id).map(|a| a.deadline)
    }

    /// The earliest armed deadline, which is what a tickless kernel programs the
    /// hardware timer for.
    pub fn next_deadline(&self) -> Option<Instant> {
        (self.len > 0).then(|| self.at(0).deadline)
    }

    /// How long the CPU may stay idle at `now`: until the next deadline, and never
    /// longer than `limit`. The limit is typically [`crate::Clock::max_idle`], which
    /// applies even with no timer armed. Zero if a timer is already due.
    pub fn idle_budget(&self, now: Instant, limit: Duration) -> Duration {
        match self.next_deadline() {
            Some(d) => d.saturating_duration_since(now).min(limit),
            None => limit,
        }
    }

    /// Take the earliest timer due at or before `now`, if any.
    ///
    /// Called in a loop until it returns `None`. A periodic timer is re-armed before it
    /// is returned, and is not returned twice in one pass, because its next deadline is
    /// after `now`.
    pub fn pop_expired(&mut self, now: Instant) -> Option<Expired<T>> {
        if self.len == 0 || self.at(0).deadline > now {
            return None;
        }
        let index = self.heap[0];
        let armed = self.slots[index as usize]?;
        let id = TimerId {
            index,
            serial: armed.serial,
        };

        let Some(period) = armed.period else {
            self.remove_at(0);
            self.slots[index as usize] = None;
            return Some(Expired {
                id,
                payload: armed.payload,
                deadline: armed.deadline,
                missed: 0,
                next: None,
            });
        };

        let (next, missed) = next_period(armed.deadline, period, now);
        match next {
            Some(next) => {
                // The deadline only moves later, so the entry sinks from the root.
                if let Some(a) = self.slots[index as usize].as_mut() {
                    a.deadline = next;
                }
                self.sift_down(0);
            }
            None => {
                self.remove_at(0);
                self.slots[index as usize] = None;
            }
        }
        Some(Expired {
            id,
            payload: armed.payload,
            deadline: armed.deadline,
            missed,
            next,
        })
    }

    fn lookup(&self, id: TimerId) -> Result<Armed<T>, Error> {
        match self.slots.get(id.index as usize).copied().flatten() {
            Some(a) if a.serial == id.serial => Ok(a),
            _ => Err(Error::Stale),
        }
    }

    fn insert(
        &mut self,
        deadline: Instant,
        period: Option<Duration>,
        payload: T,
    ) -> Result<TimerId, Error> {
        if self.next_serial == u64::MAX {
            return Err(Error::Exhausted);
        }
        let index = self
            .slots
            .iter()
            .position(Option::is_none)
            .ok_or(Error::Full)?;
        let serial = self.next_serial;
        self.next_serial += 1;

        let pos = self.len;
        self.slots[index] = Some(Armed {
            deadline,
            period,
            serial,
            payload,
            heap_pos: pos as u32,
        });
        self.heap[pos] = index as u32;
        self.len += 1;
        self.sift_up(pos);
        Ok(TimerId {
            index: index as u32,
            serial,
        })
    }

    /// The armed timer at heap position `pos`. Every heap entry names an occupied slot,
    /// which `check` asserts in the tests.
    fn at(&self, pos: usize) -> &Armed<T> {
        match &self.slots[self.heap[pos] as usize] {
            Some(a) => a,
            None => unreachable!("heap entry names an empty slot"),
        }
    }

    fn key(&self, pos: usize) -> (Instant, u64) {
        let a = self.at(pos);
        (a.deadline, a.serial)
    }

    fn place(&mut self, pos: usize, index: u32) {
        self.heap[pos] = index;
        if let Some(a) = self.slots[index as usize].as_mut() {
            a.heap_pos = pos as u32;
        }
    }

    fn swap(&mut self, a: usize, b: usize) {
        let (ia, ib) = (self.heap[a], self.heap[b]);
        self.place(a, ib);
        self.place(b, ia);
    }

    fn sift_up(&mut self, mut pos: usize) {
        while pos > 0 {
            let parent = (pos - 1) / 2;
            if self.key(pos) >= self.key(parent) {
                break;
            }
            self.swap(pos, parent);
            pos = parent;
        }
    }

    fn sift_down(&mut self, mut pos: usize) {
        loop {
            let (l, r) = (2 * pos + 1, 2 * pos + 2);
            let mut least = pos;
            if l < self.len && self.key(l) < self.key(least) {
                least = l;
            }
            if r < self.len && self.key(r) < self.key(least) {
                least = r;
            }
            if least == pos {
                break;
            }
            self.swap(pos, least);
            pos = least;
        }
    }

    /// Remove the heap entry at `pos`, leaving its slot for the caller to clear.
    fn remove_at(&mut self, pos: usize) {
        let last = self.len - 1;
        if pos != last {
            self.swap(pos, last);
        }
        self.len -= 1;
        if pos < self.len {
            // The entry moved into `pos` came from the bottom and may belong above or
            // below it; only one of these moves it.
            self.sift_up(pos);
            self.sift_down(pos);
        }
    }

    /// Assert every structural invariant. For tests; O(n).
    #[cfg(test)]
    fn check(&self) {
        let occupied = self.slots.iter().filter(|s| s.is_some()).count();
        assert_eq!(occupied, self.len, "every armed slot is in the heap exactly once");
        for pos in 0..self.len {
            let a = self.at(pos);
            assert_eq!(a.heap_pos as usize, pos, "slot and heap agree on position");
            if pos > 0 {
                assert!(self.key((pos - 1) / 2) <= self.key(pos), "heap order at {pos}");
            }
        }
    }

    #[cfg(test)]
    fn set_next_serial(&mut self, serial: u64) {
        self.next_serial = serial;
    }
}

/// A periodic timer's next deadline after `deadline` fired at `now`, and how many
/// periods were skipped. `None` if the next deadline is past the end of time.
fn next_period(deadline: Instant, period: Duration, now: Instant) -> (Option<Instant>, u64) {
    let next = deadline.checked_add(period);
    match next {
        // Serviced within its period: the common case, with no division.
        Some(n) if n > now => (Some(n), 0),
        None => (None, 0),
        Some(_) => {
            let late = now.saturating_duration_since(deadline).as_nanos();
            let missed = late / period.as_nanos();
            let step = missed.checked_add(1).and_then(|k| period.checked_mul(k));
            (step.and_then(|s| deadline.checked_add(s)), missed)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(ns: u64) -> Instant {
        Instant::from_nanos(ns)
    }

    fn ns(n: u64) -> Duration {
        Duration::from_nanos(n)
    }

    fn drain<T: Copy, const N: usize>(q: &mut TimerQueue<T, N>, now: Instant) -> Vec<Expired<T>> {
        let mut out = Vec::new();
        while let Some(e) = q.pop_expired(now) {
            q.check();
            out.push(e);
        }
        out
    }

    #[test]
    fn timers_expire_in_deadline_order() {
        let mut q: TimerQueue<u32, 8> = TimerQueue::new();
        for (d, p) in [(50, 5), (10, 1), (40, 4), (20, 2), (30, 3)] {
            q.arm_oneshot(at(d), p).unwrap();
            q.check();
        }
        assert_eq!(q.next_deadline(), Some(at(10)));
        assert!(q.pop_expired(at(9)).is_none(), "nothing is due before its deadline");
        let got: Vec<u32> = drain(&mut q, at(35)).iter().map(|e| e.payload).collect();
        assert_eq!(got, [1, 2, 3]);
        assert_eq!(q.next_deadline(), Some(at(40)));
        let got: Vec<u32> = drain(&mut q, at(1_000)).iter().map(|e| e.payload).collect();
        assert_eq!(got, [4, 5]);
        assert!(q.is_empty());
        assert_eq!(q.next_deadline(), None);
    }

    #[test]
    fn equal_deadlines_expire_in_arming_order() {
        let mut q: TimerQueue<u32, 16> = TimerQueue::new();
        for p in 0..16 {
            q.arm_oneshot(at(100), p).unwrap();
        }
        let got: Vec<u32> = drain(&mut q, at(100)).iter().map(|e| e.payload).collect();
        assert_eq!(got, (0..16).collect::<Vec<_>>());
    }

    #[test]
    fn a_stale_handle_cannot_cancel_the_slots_next_occupant() {
        let mut q: TimerQueue<&str, 1> = TimerQueue::new();
        let old = q.arm_oneshot(at(10), "old").unwrap();
        assert_eq!(drain(&mut q, at(10)).len(), 1);

        // The only slot is reused.
        let new = q.arm_oneshot(at(20), "new").unwrap();
        assert_eq!(old.index, new.index, "the test needs the slot to be reused");
        assert_eq!(q.cancel(old), Err(Error::Stale));
        assert_eq!(q.deadline(new), Ok(at(20)), "the new timer is untouched");

        assert_eq!(q.cancel(new), Ok("new"));
        assert_eq!(q.cancel(new), Err(Error::Stale), "cancelling twice is refused");
        q.check();
    }

    #[test]
    fn cancel_removes_from_anywhere_in_the_heap() {
        let mut q: TimerQueue<u64, 32> = TimerQueue::new();
        let ids: Vec<TimerId> = (0..32)
            .map(|i| q.arm_oneshot(at((i * 37) % 101), i).unwrap())
            .collect();
        for (i, id) in ids.iter().enumerate().filter(|(i, _)| i % 3 == 0) {
            assert_eq!(q.cancel(*id), Ok(i as u64));
            q.check();
        }
        let got = drain(&mut q, Instant::MAX);
        assert_eq!(got.len(), 32 - 11);
        assert!(got.windows(2).all(|w| w[0].deadline <= w[1].deadline));
        assert!(got.iter().all(|e| e.payload % 3 != 0));
    }

    #[test]
    fn a_full_queue_reports_rather_than_overwrites() {
        let mut q: TimerQueue<u8, 2> = TimerQueue::new();
        q.arm_oneshot(at(1), 1).unwrap();
        q.arm_oneshot(at(2), 2).unwrap();
        assert_eq!(q.arm_oneshot(at(0), 3), Err(Error::Full));
        assert_eq!(q.len(), 2);
        assert_eq!(q.next_deadline(), Some(at(1)));
    }

    #[test]
    fn periodic_deadlines_come_from_deadlines_not_from_service_times() {
        let mut q: TimerQueue<(), 4> = TimerQueue::new();
        let id = q.arm_periodic(at(1_000), ns(1_000), ()).unwrap();
        // Serviced 300 ns late every time. Deadlines stay on the 1000 ns grid.
        for k in 1..=100 {
            let due = at(k * 1_000);
            let e = q.pop_expired(due.saturating_add(ns(300))).unwrap();
            q.check();
            assert_eq!(e.deadline, due);
            assert_eq!(e.missed, 0);
            assert_eq!(e.next, Some(at((k + 1) * 1_000)));
            assert!(q.pop_expired(due.saturating_add(ns(300))).is_none(), "once per pass");
        }
        assert_eq!(q.deadline(id), Ok(at(101_000)), "no drift after 100 late services");
    }

    #[test]
    fn a_late_periodic_timer_skips_missed_periods_and_says_so() {
        let mut q: TimerQueue<(), 4> = TimerQueue::new();
        q.arm_periodic(at(1_000), ns(1_000), ()).unwrap();
        // Serviced at 5500: deadlines 2000..=5000 passed unserviced.
        let e = q.pop_expired(at(5_500)).unwrap();
        assert_eq!((e.deadline, e.missed, e.next), (at(1_000), 4, Some(at(6_000))));
        assert!(q.pop_expired(at(5_500)).is_none(), "no burst to catch up");

        // Exactly on a later deadline: that deadline is due now, not skipped.
        let e = q.pop_expired(at(8_000)).unwrap();
        assert_eq!((e.deadline, e.missed, e.next), (at(6_000), 2, Some(at(9_000))));
    }

    #[test]
    fn a_periodic_timer_at_the_end_of_time_disarms() {
        let mut q: TimerQueue<(), 1> = TimerQueue::new();
        let id = q.arm_periodic(at(u64::MAX - 5), ns(10), ()).unwrap();
        let e = q.pop_expired(Instant::MAX).unwrap();
        assert_eq!(e.next, None);
        assert_eq!(q.cancel(id), Err(Error::Stale));
        assert!(q.is_empty());
        q.check();
    }

    #[test]
    fn a_zero_period_is_refused() {
        let mut q: TimerQueue<(), 1> = TimerQueue::new();
        assert_eq!(q.arm_periodic(at(0), Duration::ZERO, ()), Err(Error::ZeroPeriod));
        assert!(q.is_empty());
    }

    #[test]
    fn serials_refuse_rather_than_wrap() {
        let mut q: TimerQueue<(), 2> = TimerQueue::new();
        q.set_next_serial(u64::MAX - 1);
        let last = q.arm_oneshot(at(1), ()).unwrap();
        assert_eq!(q.arm_oneshot(at(2), ()), Err(Error::Exhausted));
        assert_eq!(q.cancel(last), Ok(()));
        assert_eq!(q.arm_oneshot(at(3), ()), Err(Error::Exhausted));
    }

    #[test]
    fn idle_budget_is_bounded_by_the_next_deadline_and_the_limit() {
        let mut q: TimerQueue<(), 2> = TimerQueue::new();
        let limit = ns(1_000);
        assert_eq!(q.idle_budget(at(0), limit), limit, "no timers: the clock's limit");
        q.arm_oneshot(at(300), ()).unwrap();
        assert_eq!(q.idle_budget(at(100), limit), ns(200));
        assert_eq!(q.idle_budget(at(100), ns(50)), ns(50));
        assert_eq!(q.idle_budget(at(400), limit), Duration::ZERO, "already due");
    }

    /// Random operations against a plainly correct reference: a list sorted on demand.
    #[test]
    fn agrees_with_a_reference_model_under_random_operations() {
        const N: usize = 24;
        let mut q: TimerQueue<u64, N> = TimerQueue::new();
        // (id, deadline, period, payload)
        let mut model: Vec<(TimerId, Instant, Option<Duration>, u64)> = Vec::new();
        let mut stale: Vec<TimerId> = Vec::new();
        let mut now = 0u64;
        let mut rng = 0x9E37_79B9_7F4A_7C15u64;
        let mut next = || {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            rng
        };

        for step in 0..20_000u64 {
            match next() % 6 {
                0 | 1 => {
                    let d = at(now + next() % 500);
                    match q.arm_oneshot(d, step) {
                        Ok(id) => model.push((id, d, None, step)),
                        Err(e) => assert_eq!((e, model.len()), (Error::Full, N)),
                    }
                }
                2 => {
                    let d = at(now + next() % 500);
                    let p = ns(1 + next() % 200);
                    match q.arm_periodic(d, p, step) {
                        Ok(id) => model.push((id, d, Some(p), step)),
                        Err(e) => assert_eq!((e, model.len()), (Error::Full, N)),
                    }
                }
                3 if !model.is_empty() => {
                    let i = (next() % model.len() as u64) as usize;
                    let (id, _, _, payload) = model.remove(i);
                    assert_eq!(q.cancel(id), Ok(payload));
                    stale.push(id);
                }
                4 if !stale.is_empty() => {
                    let id = stale[(next() % stale.len() as u64) as usize];
                    assert_eq!(q.cancel(id), Err(Error::Stale));
                }
                _ => {
                    now += next() % 300;
                    let t = at(now);
                    while let Some(e) = q.pop_expired(t) {
                        // The model's earliest by (deadline, serial) must be what came out.
                        let i = (0..model.len())
                            .min_by_key(|&i| (model[i].1, model[i].0.serial))
                            .unwrap();
                        let (id, deadline, period, payload) = model[i];
                        assert!(deadline <= t);
                        assert_eq!((e.id, e.deadline, e.payload), (id, deadline, payload));
                        match period {
                            None => {
                                model.remove(i);
                                stale.push(id);
                            }
                            Some(p) => {
                                let (n, missed) = next_period(deadline, p, t);
                                assert_eq!((e.next, e.missed), (n, missed));
                                model[i].1 = n.unwrap();
                            }
                        }
                    }
                }
            }
            q.check();
            assert_eq!(q.len(), model.len());
            let earliest = model.iter().map(|m| m.1).min();
            assert_eq!(q.next_deadline(), earliest);
        }
    }
}

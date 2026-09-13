//! Where threads run on a multiprocessor: wake placement and load balancing.
//!
//! Every CPU has its own run queue, and these functions decide which queue a thread
//! joins. They are decisions only. They see each CPU as a [`CpuLoad`] snapshot and
//! return a CPU number. The thread table applies them under its lock, and the image
//! sends the reschedule IPI that makes a decision take effect. Keeping them pure is what
//! lets the policy be tested on a laptop with eight imaginary CPUs, instead of only in an
//! emulator where a wrong placement looks like a slow run.
//!
//! # The policy
//!
//! A woken thread goes, in order of preference:
//!
//! 1. **Back where it last ran, if that CPU is idle.** Its caches are likely still warm there, and
//!    nothing is disturbed.
//! 2. **To any idle CPU it may use**, the lowest-numbered one. An idle CPU is the only place a
//!    thread runs at once without taking the CPU from another thread.
//! 3. **Back where it last ran, if it outranks what runs there.** It preempts, which is what its
//!    priority is for.
//! 4. **To the least-loaded CPU it may use**, preferring its last CPU among equals.
//!
//! Balancing moves queued threads, never running ones. A CPU pulls one thread from the
//! busiest other CPU when it is idle and that CPU has a thread waiting, or when that CPU
//! carries at least two more threads than it does. The margin of two is what stops a
//! thread bouncing: with one, two CPUs whose loads differ by one would trade the same
//! thread on every balance.
//!
//! Load is the number of threads a CPU is running or holding ready, not counting its idle
//! thread. It is not weighted by priority. Fixed priority already decides who runs on a
//! CPU; balancing only has to see that a thread is waiting where a CPU could run it.

use crate::Priority;

/// A set of logical CPUs, one bit each. Bounds the scheduler at 64 CPUs.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct CpuSet(u64);

impl CpuSet {
    /// No CPU. A thread with this affinity can run nowhere, which the thread table
    /// refuses.
    pub const EMPTY: CpuSet = CpuSet(0);

    /// CPUs `0..cpus`.
    pub const fn all(cpus: usize) -> CpuSet {
        if cpus >= 64 {
            CpuSet(u64::MAX)
        } else {
            CpuSet((1u64 << cpus) - 1)
        }
    }

    /// Only `cpu`. Empty for a CPU number past the set's width.
    pub const fn single(cpu: usize) -> CpuSet {
        if cpu < 64 {
            CpuSet(1 << cpu)
        } else {
            CpuSet::EMPTY
        }
    }

    pub const fn from_raw(bits: u64) -> CpuSet {
        CpuSet(bits)
    }

    pub const fn raw(self) -> u64 {
        self.0
    }

    pub const fn contains(self, cpu: usize) -> bool {
        cpu < 64 && self.0 & (1 << cpu) != 0
    }

    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    pub const fn intersect(self, other: CpuSet) -> CpuSet {
        CpuSet(self.0 & other.0)
    }

    /// The lowest-numbered CPU in the set.
    pub const fn first(self) -> Option<usize> {
        if self.0 == 0 {
            None
        } else {
            Some(self.0.trailing_zeros() as usize)
        }
    }

    pub const fn len(self) -> usize {
        self.0.count_ones() as usize
    }

    /// The CPUs in the set, lowest first.
    pub fn iter(self) -> impl Iterator<Item = usize> {
        (0..64).filter(move |&cpu| self.contains(cpu))
    }
}

/// One CPU, as placement and balancing see it.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct CpuLoad {
    /// Whether the CPU has joined the scheduler. An offline CPU takes no thread.
    pub online: bool,
    /// The priority of the thread it runs, or `None` while it runs its idle thread.
    pub running: Option<Priority>,
    /// Threads ready in its queue, its idle thread not counted.
    pub queued: usize,
}

impl CpuLoad {
    /// Threads this CPU is running or holding ready, its idle thread not counted.
    pub const fn load(&self) -> usize {
        self.queued + if self.running.is_some() { 1 } else { 0 }
    }

    /// Running its idle thread with nothing else ready.
    pub const fn idle(&self) -> bool {
        self.running.is_none() && self.queued == 0
    }
}

/// The CPU a thread of priority `priority`, allowed on `allowed`, that last ran on
/// `last`, should be queued on when it becomes ready. `None` when no CPU it may use is
/// online.
pub fn place_wake(
    cpus: &[CpuLoad],
    allowed: CpuSet,
    last: usize,
    priority: Priority,
) -> Option<usize> {
    let usable = |cpu: usize| allowed.contains(cpu) && cpus.get(cpu).is_some_and(|c| c.online);
    let mut candidates = (0..cpus.len()).filter(|&cpu| usable(cpu));
    let first = candidates.next()?;

    if usable(last) && cpus[last].idle() {
        return Some(last);
    }
    if let Some(idle) = (0..cpus.len()).find(|&cpu| usable(cpu) && cpus[cpu].idle()) {
        return Some(idle);
    }
    if usable(last) && cpus[last].running.is_none_or(|r| priority > r) {
        return Some(last);
    }
    let mut best = first;
    for cpu in core::iter::once(first).chain(candidates) {
        let (load, best_load) = (cpus[cpu].load(), cpus[best].load());
        if load < best_load || (load == best_load && cpu == last) {
            best = cpu;
        }
    }
    Some(best)
}

/// Whether a thread of `priority` queued on a CPU that looks like `target` needs that CPU
/// interrupted to be seen: the CPU is idle, or the thread would preempt or share a slice
/// with what it runs. A thread below what the CPU runs waits for it to block, and an
/// interrupt would change nothing.
///
/// Only meaningful when the target is another CPU. The caller's own CPU re-evaluates on
/// its way out of the scheduler.
pub fn needs_reschedule(target: &CpuLoad, priority: Priority) -> bool {
    target.running.is_none_or(|r| priority >= r)
}

/// The CPU that CPU `this` should pull a queued thread from, if balancing is due.
///
/// Due when `this` is idle and some other CPU has a thread waiting, or when the busiest
/// other CPU carries at least two more threads than `this`. Ties between busiest CPUs go
/// to the lowest-numbered, so two balancing CPUs agree on a source.
pub fn pull_source(cpus: &[CpuLoad], this: usize) -> Option<usize> {
    let here = cpus.get(this).filter(|c| c.online)?;
    let mut busiest: Option<usize> = None;
    for (cpu, c) in cpus.iter().enumerate() {
        if cpu == this || !c.online || c.queued == 0 {
            continue;
        }
        if busiest.is_none_or(|b| c.load() > cpus[b].load()) {
            busiest = Some(cpu);
        }
    }
    let source = busiest?;
    let due = here.idle() || cpus[source].load() >= here.load() + 2;
    due.then_some(source)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(n: u8) -> Priority {
        Priority::new(n).unwrap()
    }

    const IDLE: CpuLoad = CpuLoad {
        online: true,
        running: None,
        queued: 0,
    };

    fn busy(prio: u8, queued: usize) -> CpuLoad {
        CpuLoad {
            online: true,
            running: Some(p(prio)),
            queued,
        }
    }

    const OFF: CpuLoad = CpuLoad {
        online: false,
        running: None,
        queued: 0,
    };

    #[test]
    fn cpu_sets_hold_what_they_say() {
        assert_eq!(CpuSet::all(4).raw(), 0b1111);
        assert_eq!(CpuSet::all(64).raw(), u64::MAX);
        assert!(CpuSet::single(3).contains(3) && !CpuSet::single(3).contains(2));
        assert!(CpuSet::single(64).is_empty(), "past the width is nothing, not bit 0");
        assert!(!CpuSet::all(8).contains(64));
        assert_eq!(CpuSet::from_raw(0b1010).first(), Some(1));
        assert_eq!(CpuSet::from_raw(0b1010).iter().collect::<Vec<_>>(), [1, 3]);
        assert_eq!(CpuSet::all(3).intersect(CpuSet::single(2)).len(), 1);
        assert_eq!(CpuSet::EMPTY.first(), None);
    }

    #[test]
    fn a_thread_goes_back_to_its_idle_last_cpu() {
        let cpus = [IDLE, busy(4, 0), IDLE, IDLE];
        assert_eq!(place_wake(&cpus, CpuSet::all(4), 2, p(5)), Some(2));
    }

    #[test]
    fn a_busy_last_cpu_loses_to_an_idle_one() {
        let cpus = [busy(9, 0), busy(4, 1), IDLE, IDLE];
        assert_eq!(place_wake(&cpus, CpuSet::all(4), 1, p(5)), Some(2), "lowest idle");
    }

    #[test]
    fn with_nothing_idle_a_thread_that_outranks_its_last_cpu_preempts_there() {
        let cpus = [busy(9, 0), busy(4, 2), busy(3, 0)];
        assert_eq!(place_wake(&cpus, CpuSet::all(3), 1, p(5)), Some(1));
    }

    #[test]
    fn otherwise_the_least_loaded_cpu_wins_and_last_breaks_ties() {
        let cpus = [busy(9, 2), busy(9, 0), busy(9, 0)];
        assert_eq!(place_wake(&cpus, CpuSet::all(3), 0, p(5)), Some(1));
        assert_eq!(place_wake(&cpus, CpuSet::all(3), 2, p(5)), Some(2), "tie: last");
    }

    #[test]
    fn affinity_is_never_overruled() {
        let cpus = [IDLE, IDLE, busy(9, 3), busy(9, 5)];
        let only_busy = CpuSet::from_raw(0b1100);
        assert_eq!(place_wake(&cpus, only_busy, 0, p(5)), Some(2));
        assert_eq!(place_wake(&cpus, CpuSet::single(3), 0, p(5)), Some(3));
        assert_eq!(place_wake(&cpus, CpuSet::EMPTY, 0, p(5)), None);
    }

    #[test]
    fn offline_cpus_take_nothing() {
        let cpus = [busy(9, 4), OFF, OFF];
        assert_eq!(place_wake(&cpus, CpuSet::all(3), 1, p(5)), Some(0));
        assert_eq!(place_wake(&cpus, CpuSet::from_raw(0b110), 1, p(5)), None);
        assert_eq!(place_wake(&cpus, CpuSet::all(3), 7, p(5)), Some(0), "last out of range");
    }

    #[test]
    fn a_reschedule_is_needed_only_where_the_thread_would_run_soon() {
        assert!(needs_reschedule(&IDLE, p(0)));
        assert!(needs_reschedule(&busy(4, 0), p(5)), "preempts");
        assert!(needs_reschedule(&busy(4, 0), p(4)), "shares a slice");
        assert!(!needs_reschedule(&busy(6, 0), p(4)), "waits for it to block");
    }

    #[test]
    fn an_idle_cpu_pulls_any_waiting_thread() {
        let cpus = [busy(4, 1), IDLE];
        assert_eq!(pull_source(&cpus, 1), Some(0));
    }

    #[test]
    fn a_busy_cpu_pulls_only_across_a_margin_of_two() {
        assert_eq!(pull_source(&[busy(4, 1), busy(4, 0)], 1), None, "2 against 1");
        assert_eq!(pull_source(&[busy(4, 2), busy(4, 0)], 1), Some(0), "3 against 1");
        assert_eq!(pull_source(&[busy(4, 2), busy(4, 1)], 1), None, "3 against 2");
    }

    #[test]
    fn the_busiest_source_wins_and_ties_go_low() {
        let cpus = [busy(4, 1), IDLE, busy(4, 3), busy(4, 3)];
        assert_eq!(pull_source(&cpus, 1), Some(2));
    }

    #[test]
    fn nothing_is_pulled_from_a_cpu_with_no_queue_or_by_an_offline_cpu() {
        assert_eq!(pull_source(&[busy(4, 0), IDLE], 1), None, "running, nothing waiting");
        assert_eq!(pull_source(&[busy(4, 5), OFF], 1), None);
        assert_eq!(pull_source(&[OFF, IDLE], 1), None);
        assert_eq!(pull_source(&[busy(4, 5)], 0), None, "no other CPU");
    }

    #[test]
    fn balancing_converges_instead_of_bouncing() {
        // Apply the policy to two CPUs repeatedly, moving one queued thread per pull. With
        // an odd number of threads, a margin of one would move a thread back and forth for
        // ever.
        let mut cpus = [busy(4, 4), IDLE];
        let mut late_moves = 0;
        for round in 0..16 {
            for this in 0..2 {
                if let Some(src) = pull_source(&cpus, this) {
                    cpus[src].queued -= 1;
                    match cpus[this].running {
                        None => cpus[this].running = Some(p(4)),
                        Some(_) => cpus[this].queued += 1,
                    }
                    if round >= 8 {
                        late_moves += 1;
                    }
                }
            }
        }
        assert_eq!(cpus[0].load() + cpus[1].load(), 5);
        assert!(cpus[0].load().abs_diff(cpus[1].load()) <= 1);
        assert_eq!(late_moves, 0, "still moving threads after it balanced");
    }
}

//! TLB shootdown: making every other CPU forget a translation before anyone relies on
//! it being gone.
//!
//! Changing a page table entry changes what the *tables* say. Each CPU keeps its own
//! cache of what they said, and a flush on one CPU empties only that CPU's cache. On a
//! multiprocessor, a leaf that is removed or downgraded is still usable through every
//! other CPU's cached copy until that CPU flushes too. A frame freed after a local flush
//! and handed to someone else is then written by a thread on another CPU through a
//! translation that no longer exists, and nothing faults to say so.
//!
//! [`Shootdown`] is the bookkeeping for asking the other CPUs and knowing they did.
//! Sending the interrupts, and serialising requests, is the kernel's. This type only
//! decides what counts as done, and it is the part a mistake would hide in, so it is
//! tested on its own.
//!
//! # The protocol
//!
//! One request is outstanding at a time. The initiator holds whatever lock serialises
//! requests, and:
//!
//! 1. [`Shootdown::publish`] stores the address, then the set of CPUs that must answer.
//! 2. It interrupts each of them, and flushes its own cache itself.
//! 3. Each target, in [`Shootdown::service`], sees its bit, reads the address, flushes, and only
//!    then clears its bit and records its answer. Clearing before flushing would let the initiator
//!    free a frame the target can still reach.
//! 4. The initiator waits until no bit remains ([`Shootdown::outstanding`]), then asks
//!    [`Shootdown::finish`] whether the CPUs that answered are exactly the CPUs it asked.
//!
//! A CPU waiting to become the initiator must keep servicing requests addressed to it.
//! Otherwise two CPUs that start a shootdown at once, with interrupts masked, each wait
//! for the other for ever.
//!
//! # Memory ordering
//!
//! The address is stored before the pending set, both with `Release`, and a target loads
//! the pending set, then the address, with `Acquire`. So a target that sees its bit has
//! also seen the address that bit is about. The target's clear is a compare-and-swap-based
//! `fetch_and`, which synchronises with the initiator's `Acquire` load of the pending set:
//! when the initiator sees zero, every flush has happened. See `docs/memory-model.md`.

use core::sync::atomic::{AtomicUsize, Ordering};

/// The address value that means "every translation".
const ALL: usize = usize::MAX;

/// A CPU set as a word: bit `n` is CPU `n`. A CPU numbered past the word's width cannot
/// take part, which [`Shootdown::publish`] refuses rather than truncates.
pub type Mask = usize;

/// The widest CPU number a mask can hold, plus one.
pub const MASK_BITS: usize = usize::BITS as usize;

/// One outstanding shootdown at a time, and what answered it.
pub struct Shootdown {
    /// The page to invalidate, or [`ALL`].
    addr: AtomicUsize,
    /// CPUs that have not flushed for the current request yet.
    pending: AtomicUsize,
    /// CPUs that flushed for the current request.
    answered: AtomicUsize,
    /// CPUs the current request was addressed to.
    asked: AtomicUsize,
    /// Requests published since boot.
    requests: AtomicUsize,
    /// Flushes targets performed for a request.
    flushes: AtomicUsize,
}

/// A finished request whose answers did not match its targets.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Mismatch {
    pub asked: Mask,
    pub answered: Mask,
}

impl Default for Shootdown {
    fn default() -> Self {
        Self::new()
    }
}

impl Shootdown {
    pub const fn new() -> Shootdown {
        Shootdown {
            addr: AtomicUsize::new(0),
            pending: AtomicUsize::new(0),
            answered: AtomicUsize::new(0),
            asked: AtomicUsize::new(0),
            requests: AtomicUsize::new(0),
            flushes: AtomicUsize::new(0),
        }
    }

    /// Begin a request to invalidate `addr` (`None` for everything) on the CPUs in
    /// `targets`.
    ///
    /// The caller must hold the lock that serialises requests, and the previous request
    /// must have finished: no bit may be outstanding. Returns `false`, publishing
    /// nothing, if one is.
    pub fn publish(&self, addr: Option<usize>, targets: Mask) -> bool {
        if self.pending.load(Ordering::Acquire) != 0 {
            return false;
        }
        self.answered.store(0, Ordering::Release);
        self.asked.store(targets, Ordering::Release);
        // Address first: a target that sees its pending bit must already see what it is
        // for (see the module docs).
        self.addr.store(addr.unwrap_or(ALL), Ordering::Release);
        self.requests.fetch_add(1, Ordering::Relaxed);
        self.pending.store(targets, Ordering::Release);
        true
    }

    /// On CPU `cpu`: if the current request is waiting for this CPU, run `flush` with its
    /// address and answer it. Returns whether it did.
    ///
    /// Safe to call at any time, from interrupt context or from a wait loop, any number
    /// of times: a CPU answers each request once.
    pub fn service(&self, cpu: usize, flush: impl FnOnce(Option<usize>)) -> bool {
        let Some(bit) = bit(cpu) else {
            return false;
        };
        if self.pending.load(Ordering::Acquire) & bit == 0 {
            return false;
        }
        let addr = self.addr.load(Ordering::Acquire);
        flush((addr != ALL).then_some(addr));
        // After the flush, never before: a cleared bit is the initiator's licence to reuse
        // the frame.
        self.answered.fetch_or(bit, Ordering::AcqRel);
        self.flushes.fetch_add(1, Ordering::Relaxed);
        self.pending.fetch_and(!bit, Ordering::AcqRel);
        true
    }

    /// CPUs that have not answered the current request.
    pub fn outstanding(&self) -> Mask {
        self.pending.load(Ordering::Acquire)
    }

    /// Once nothing is outstanding: `Ok` if the CPUs that answered are exactly those that
    /// were asked. `Err` otherwise, including when called early.
    pub fn finish(&self) -> Result<(), Mismatch> {
        let asked = self.asked.load(Ordering::Acquire);
        let answered = self.answered.load(Ordering::Acquire);
        if self.outstanding() == 0 && asked == answered {
            Ok(())
        } else {
            Err(Mismatch { asked, answered })
        }
    }

    /// Requests published since boot.
    pub fn requests(&self) -> usize {
        self.requests.load(Ordering::Relaxed)
    }

    /// Flushes performed by targets since boot.
    pub fn flushes(&self) -> usize {
        self.flushes.load(Ordering::Relaxed)
    }
}

/// The mask bit for `cpu`, or `None` past the word.
pub const fn bit(cpu: usize) -> Option<Mask> {
    if cpu < MASK_BITS {
        Some(1 << cpu)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;

    use super::*;

    #[test]
    fn a_target_flushes_the_published_address_once() {
        let s = Shootdown::new();
        assert!(s.publish(Some(0x4000), 0b110));
        let mut seen = Vec::new();
        assert!(!s.service(0, |a| seen.push((0, a))), "CPU 0 was not asked");
        assert!(s.service(1, |a| seen.push((1, a))));
        assert!(!s.service(1, |a| seen.push((1, a))), "answered already");
        assert_eq!(s.outstanding(), 0b100);
        assert!(s.finish().is_err(), "CPU 2 has not answered");
        assert!(s.service(2, |a| seen.push((2, a))));
        assert_eq!(seen, [(1, Some(0x4000)), (2, Some(0x4000))]);
        assert_eq!(s.finish(), Ok(()));
        assert_eq!((s.requests(), s.flushes()), (1, 2));
    }

    #[test]
    fn everything_is_none_and_a_new_request_waits_for_the_old_one() {
        let s = Shootdown::new();
        assert!(s.publish(None, 0b10));
        assert!(!s.publish(Some(0x1000), 0b10), "one request at a time");
        let mut got = Some(7);
        s.service(1, |a| got = a);
        assert_eq!(got, None, "a full flush");
        assert!(s.publish(Some(0x1000), 0b10));
        s.service(1, |a| got = a);
        assert_eq!(got, Some(0x1000));
    }

    #[test]
    fn an_answer_from_a_cpu_that_was_not_asked_is_a_mismatch() {
        // The bookkeeping must catch a target set that differs from the answers, not just
        // count bits: a request addressed to CPUs 1 and 2, answered by 1 and 3, has two
        // answers and is still wrong.
        let s = Shootdown::new();
        assert!(s.publish(Some(0), 0b0110));
        s.service(1, |_| {});
        s.answered.fetch_or(0b1000, Ordering::AcqRel);
        s.pending.fetch_and(!0b0100, Ordering::AcqRel);
        assert_eq!(
            s.finish(),
            Err(Mismatch {
                asked: 0b0110,
                answered: 0b1010
            })
        );
    }

    #[test]
    fn a_target_answers_only_after_its_flush_ran() {
        let s = Shootdown::new();
        assert!(s.publish(Some(0x2000), 0b10));
        s.service(1, |_| {
            assert_eq!(s.outstanding(), 0b10, "still outstanding while flushing");
        });
        assert_eq!(s.outstanding(), 0);
    }

    #[test]
    fn cpus_past_the_word_are_refused() {
        let s = Shootdown::new();
        assert!(s.publish(None, 1));
        assert!(!s.service(MASK_BITS, |_| panic!("no such bit")));
        assert_eq!(bit(MASK_BITS), None);
    }

    #[test]
    fn targets_on_other_threads_all_answer_every_request() {
        // Host threads standing in for CPUs, servicing in a loop as an IPI handler would,
        // while the initiator publishes and waits, many times over.
        const CPUS: usize = 4;
        let s = Arc::new(Shootdown::new());
        let stop = Arc::new(AtomicBool::new(false));
        let flushed: Arc<[AtomicUsize; CPUS]> = Arc::new([const { AtomicUsize::new(0) }; CPUS]);
        let targets: Vec<_> = (1..CPUS)
            .map(|cpu| {
                let (s, stop, flushed) = (s.clone(), stop.clone(), flushed.clone());
                std::thread::spawn(move || {
                    while !stop.load(Ordering::Relaxed) {
                        if !s.service(cpu, |_| {
                            flushed[cpu].fetch_add(1, Ordering::Relaxed);
                        }) {
                            std::thread::yield_now();
                        }
                    }
                })
            })
            .collect();
        for round in 0..2000 {
            assert!(s.publish(Some(round << 12), 0b1110));
            while s.outstanding() != 0 {
                std::thread::yield_now();
            }
            assert_eq!(s.finish(), Ok(()), "round {round}");
        }
        stop.store(true, Ordering::Relaxed);
        for t in targets {
            t.join().unwrap();
        }
        for cpu in 1..CPUS {
            assert_eq!(flushed[cpu].load(Ordering::Relaxed), 2000);
        }
    }
}

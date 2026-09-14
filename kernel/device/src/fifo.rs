//! A byte queue between an interrupt handler and the code that reads what arrived.
//!
//! A receiving driver has one producer — the handler, on whichever CPU the line is
//! routed to — and one consumer, a thread that asks for bytes. That is the one
//! concurrency shape a lock-free queue is worth writing for, and the one this is: a ring
//! whose producer only advances the head and whose consumer only advances the tail.
//!
//! # The rules it relies on
//!
//! * **One producer.** Every line this kernel enables is delivered to one CPU, so one handler runs
//!   at a time. Two CPUs taking the same line would need a lock instead, and that is a property of
//!   how the line is routed, not of this queue: [`Fifo::push`] documents it rather than assuming it
//!   silently.
//! * **One consumer.** Two readers would each take bytes the other expected.
//! * A full queue **drops the newest byte and counts it**. A console that blocks its own interrupt
//!   handler until someone reads is a worse failure than a lost keystroke, and a silent loss is
//!   worse than either.
//!
//! Absent on a machine with no atomics: a driver there polls.

#![cfg(all(target_has_atomic = "8", target_has_atomic = "32"))]

use core::sync::atomic::{AtomicU8, AtomicU32, Ordering};

/// A single-producer, single-consumer byte ring of `N` bytes. `N` must be a power of two.
pub struct Fifo<const N: usize> {
    bytes: [AtomicU8; N],
    /// Where the producer writes next; only the producer advances it.
    head: AtomicU32,
    /// Where the consumer reads next; only the consumer advances it.
    tail: AtomicU32,
    /// Pushes refused for want of room; for a handler, bytes it had to throw away.
    dropped: AtomicU32,
}

impl<const N: usize> Default for Fifo<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> Fifo<N> {
    /// A `const` so a driver's queue can be a `static` with no boot-time step.
    pub const fn new() -> Self {
        const { assert!(N.is_power_of_two(), "a Fifo's size must be a power of two") };
        Fifo {
            bytes: [const { AtomicU8::new(0) }; N],
            head: AtomicU32::new(0),
            tail: AtomicU32::new(0),
            dropped: AtomicU32::new(0),
        }
    }

    fn index(at: u32) -> usize {
        (at as usize) & (N - 1)
    }

    /// Add `byte`. `false` when the queue was full, in which case the byte is dropped and
    /// counted by [`Self::dropped`].
    ///
    /// Producer side: call it from one context only — the handler for one line.
    pub fn push(&self, byte: u8) -> bool {
        let head = self.head.load(Ordering::Relaxed);
        // Acquire: everything the consumer read is finished before its slot is reused.
        let tail = self.tail.load(Ordering::Acquire);
        if head.wrapping_sub(tail) as usize >= N {
            self.dropped.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        if let Some(slot) = self.bytes.get(Self::index(head)) {
            slot.store(byte, Ordering::Relaxed);
        }
        // Release: the byte is stored before the consumer can see the slot as filled.
        self.head.store(head.wrapping_add(1), Ordering::Release);
        true
    }

    /// Take the oldest byte, if any. Consumer side: call it from one context only.
    pub fn pop(&self) -> Option<u8> {
        let tail = self.tail.load(Ordering::Relaxed);
        // Acquire: pairs with the producer's release, so the byte is visible.
        if tail == self.head.load(Ordering::Acquire) {
            return None;
        }
        let byte = self.bytes.get(Self::index(tail))?.load(Ordering::Relaxed);
        // Release: the read is finished before the producer may reuse the slot.
        self.tail.store(tail.wrapping_add(1), Ordering::Release);
        Some(byte)
    }

    /// How many bytes are waiting.
    pub fn len(&self) -> usize {
        let head = self.head.load(Ordering::Acquire);
        let tail = self.tail.load(Ordering::Acquire);
        head.wrapping_sub(tail) as usize
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// How many pushes were refused for want of room. A handler that throws the byte
    /// away, which is what a receiving driver does, has lost exactly this many.
    pub fn dropped(&self) -> u32 {
        self.dropped.load(Ordering::Acquire)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_come_back_in_order() {
        let f: Fifo<4> = Fifo::new();
        assert!(f.is_empty());
        assert_eq!(f.pop(), None);
        for b in b"abc" {
            assert!(f.push(*b));
        }
        assert_eq!(f.len(), 3);
        assert_eq!(f.pop(), Some(b'a'));
        assert_eq!(f.pop(), Some(b'b'));
        assert_eq!(f.pop(), Some(b'c'));
        assert_eq!(f.pop(), None);
        assert_eq!(f.dropped(), 0);
    }

    #[test]
    fn a_full_queue_drops_the_newest_and_counts_it() {
        let f: Fifo<4> = Fifo::new();
        for b in b"1234" {
            assert!(f.push(*b));
        }
        assert!(!f.push(b'5'), "the fifth byte has nowhere to go");
        assert_eq!(f.dropped(), 1);
        // The oldest four survived: a drop does not corrupt what is already queued.
        assert_eq!(f.pop(), Some(b'1'));
        assert!(f.push(b'5'), "one slot freed, one byte accepted");
        for want in [b'2', b'3', b'4', b'5'] {
            assert_eq!(f.pop(), Some(want));
        }
        assert_eq!(f.dropped(), 1);
    }

    #[test]
    fn indices_wrap_without_losing_order() {
        let f: Fifo<2> = Fifo::new();
        // Far more than fits, pushed and popped one at a time, so head and tail run well
        // past the ring's size and wrap.
        for i in 0..1000u32 {
            assert!(f.push(i as u8));
            assert_eq!(f.pop(), Some(i as u8));
        }
        assert!(f.is_empty());
        assert_eq!(f.dropped(), 0);
    }

    #[test]
    fn a_producer_and_a_consumer_in_two_threads_lose_nothing() {
        use std::sync::Arc;

        let f: Arc<Fifo<8>> = Arc::new(Fifo::new());
        let producer = {
            let f = Arc::clone(&f);
            std::thread::spawn(move || {
                let (mut sent, mut refused) = (0u32, 0u32);
                while sent < 10_000 {
                    if f.push((sent & 0xff) as u8) {
                        sent += 1;
                    } else {
                        refused += 1;
                    }
                }
                refused
            })
        };
        let mut got = 0u32;
        while got < 10_000 {
            if let Some(b) = f.pop() {
                assert_eq!(b, (got & 0xff) as u8, "byte {got} arrived out of order");
                got += 1;
            }
        }
        let refused = producer.join().unwrap();
        // Every refusal is counted, and a refused byte is one the producer still held:
        // nothing that was accepted was lost, which the ordering above just checked.
        assert_eq!(f.dropped(), refused, "every refusal is counted exactly once");
        assert!(f.is_empty());
    }
}

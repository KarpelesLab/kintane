//! Putting a fragmented IPv4 datagram back together.
//!
//! A sender whose datagram will not fit the next link splits it into fragments, each an IPv4
//! packet carrying part of the payload and saying where that part belongs (RFC 791 §3.2). This
//! stack never sends one — everything it sends is marked don't-fragment and fits one frame —
//! but it is sent them, and a datagram whose fragments are dropped is a datagram that never
//! arrived.
//!
//! # Bounded, with hostile senders in mind
//!
//! [`SETS`] datagrams are put together at once, each up to [`MAX`] bytes, tracked as at most
//! [`PIECES`] runs of bytes that have arrived. Nothing is allocated: the memory is these sets,
//! and it is the same whether one fragment arrives or a thousand.
//!
//! Three rules keep a sender from turning that memory into a denial of service:
//!
//! * a set that is not complete within [`TIMEOUT_NS`] is given up;
//! * a datagram that arrives when every set is taken displaces the set closest to being given
//!   up, so a sender that opens sets and never finishes them loses its own first;
//! * a fragment that would reach past [`MAX`], or that would need more than [`PIECES`] runs to
//!   describe, gives up its whole set rather than growing anything.
//!
//! Fragments may overlap and may arrive in any order. A later fragment's bytes overwrite an
//! earlier one's where they overlap, and the runs they cover are merged; the datagram is
//! complete when one run covers everything from its first byte to the length that the fragment
//! without "more fragments" set announced.

use crate::wire::{Fragment, Ipv4Addr};

/// Datagrams held part-finished at once.
pub const SETS: usize = 2;
/// The largest datagram that can be put back together.
pub const MAX: usize = 2048;
/// Runs of arrived bytes one set describes. A datagram in order needs one; out of order, one
/// per hole.
pub const PIECES: usize = 6;
/// How long a set waits for the fragments it is missing (RFC 1122 §3.3.2 asks for at least
/// 60 s; a check that has to watch a set expire cannot wait that long, and the guest and its
/// peer are a virtual machine apart).
pub const TIMEOUT_NS: u64 = 2_000_000_000;

/// Which datagram a fragment belongs to: RFC 791's four fields.
#[derive(Clone, Copy, PartialEq, Eq)]
struct Key {
    src: Ipv4Addr,
    dst: Ipv4Addr,
    id: u16,
    protocol: u8,
}

struct Set {
    key: Option<Key>,
    /// Byte ranges of the datagram that have arrived, merged as they meet.
    pieces: [Option<(u16, u16)>; PIECES],
    /// The whole length, known once the last fragment has arrived.
    total: Option<u16>,
    /// When this set is given up.
    deadline: u64,
    data: [u8; MAX],
}

impl Set {
    const EMPTY: Set = Set {
        key: None,
        pieces: [None; PIECES],
        total: None,
        deadline: 0,
        data: [0; MAX],
    };

    /// Take `bytes` at `at` into the datagram. `false` when the set cannot describe the
    /// result, and must be given up.
    fn add(&mut self, at: u16, bytes: &[u8]) -> bool {
        let Some(end) = usize::from(at).checked_add(bytes.len()) else {
            return false;
        };
        if end > MAX {
            return false;
        }
        self.data[usize::from(at)..end].copy_from_slice(bytes);
        // Merged with every run it touches, so a datagram arriving in order costs one run.
        let (mut start, mut stop) = (at, end as u16);
        for slot in self.pieces.iter_mut() {
            let Some((s, e)) = *slot else { continue };
            if s <= stop && start <= e {
                start = start.min(s);
                stop = stop.max(e);
                *slot = None;
            }
        }
        match self.pieces.iter_mut().find(|p| p.is_none()) {
            Some(slot) => {
                *slot = Some((start, stop));
                true
            }
            None => false,
        }
    }

    /// The whole datagram's length, once one run covers all of it.
    fn complete(&self) -> Option<u16> {
        let total = self.total?;
        self.pieces
            .iter()
            .flatten()
            .any(|&(start, stop)| start == 0 && stop >= total)
            .then_some(total)
    }
}

/// A datagram put back together: whose it is, and its bytes.
pub struct Done<'a> {
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub protocol: u8,
    pub payload: &'a [u8],
}

/// What taking a fragment did.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Took {
    /// Held, waiting for the rest of its datagram.
    Held,
    /// This set is complete: [`Reassembler::datagram`] has it, and [`Reassembler::release`]
    /// gives the set back.
    Complete(usize),
    /// Nothing is held: the fragment was refused, and its set given up if it had one.
    Dropped,
}

pub struct Reassembler {
    sets: [Set; SETS],
}

impl Default for Reassembler {
    fn default() -> Self {
        Self::new()
    }
}

impl Reassembler {
    pub const fn new() -> Reassembler {
        Reassembler {
            sets: [Set::EMPTY, Set::EMPTY],
        }
    }

    /// Sets holding part of a datagram right now.
    pub fn in_use(&self) -> usize {
        self.sets.iter().filter(|s| s.key.is_some()).count()
    }

    /// Give up every set whose time is up. Returns how many were given up, for a counter.
    pub fn expire(&mut self, now: u64) -> usize {
        let mut gone = 0;
        for set in self.sets.iter_mut() {
            if set.key.is_some() && now >= set.deadline {
                set.key = None;
                gone += 1;
            }
        }
        gone
    }

    /// A free set, or the one closest to being given up.
    fn set_for(&mut self, key: Key, now: u64) -> Option<usize> {
        if let Some(i) = self.sets.iter().position(|s| s.key == Some(key)) {
            return Some(i);
        }
        let free = self.sets.iter().position(|s| s.key.is_none());
        let i = match free {
            Some(i) => i,
            None => self
                .sets
                .iter()
                .enumerate()
                .min_by_key(|(_, s)| s.deadline)
                .map(|(i, _)| i)?,
        };
        let set = &mut self.sets[i];
        set.key = Some(key);
        set.pieces = [None; PIECES];
        set.total = None;
        set.deadline = now.saturating_add(TIMEOUT_NS);
        Some(i)
    }

    /// Take one fragment of a datagram from `src` to `dst`.
    pub fn take(
        &mut self,
        src: Ipv4Addr,
        dst: Ipv4Addr,
        protocol: u8,
        fragment: &Fragment,
        payload: &[u8],
        now: u64,
    ) -> Took {
        let Ok(at) = u16::try_from(fragment.offset) else {
            return Took::Dropped;
        };
        let key = Key {
            src,
            dst,
            id: fragment.id,
            protocol,
        };
        let Some(i) = self.set_for(key, now) else {
            return Took::Dropped;
        };
        let set = &mut self.sets[i];
        if !fragment.more {
            match u16::try_from(usize::from(at) + payload.len()) {
                Ok(total) => set.total = Some(total),
                Err(_) => {
                    set.key = None;
                    return Took::Dropped;
                }
            }
        }
        if !set.add(at, payload) {
            // More holes than the set can describe, or past what it can hold: the sender gets
            // nothing rather than the stack growing something.
            set.key = None;
            return Took::Dropped;
        }
        match set.complete() {
            Some(_) => Took::Complete(i),
            None => Took::Held,
        }
    }

    /// The datagram set `i` holds, once [`Reassembler::take`] has said it is complete.
    pub fn datagram(&self, i: usize) -> Option<Done<'_>> {
        let set = self.sets.get(i)?;
        let key = set.key?;
        let total = set.complete()?;
        Some(Done {
            src: key.src,
            dst: key.dst,
            protocol: key.protocol,
            payload: set.data.get(..usize::from(total))?,
        })
    }

    /// Give set `i` back, whether or not it was complete.
    pub fn release(&mut self, i: usize) {
        if let Some(set) = self.sets.get_mut(i) {
            set.key = None;
        }
    }
}

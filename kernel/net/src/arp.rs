//! The ARP cache: which hardware address answers for which IPv4 address, for how long.
//!
//! Fixed size, with no allocation. An entry lives for [`TTL_NS`] after it was last
//! confirmed; a lookup never returns an expired one, so a neighbour that changed its
//! address is asked again rather than trusted for ever. When every slot is live, the one
//! closest to expiring is replaced, which is the least recently confirmed.

use crate::wire::{Ipv4Addr, Mac};

/// Entries the cache holds. One gateway and a handful of neighbours is all one interface
/// on one subnet talks to.
pub const ENTRIES: usize = 8;

/// How long an entry is believed after it was last confirmed.
pub const TTL_NS: u64 = 60_000_000_000;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct Entry {
    ip: Ipv4Addr,
    mac: Mac,
    /// The instant, in the owner's nanoseconds, after which this entry is not used.
    expires: u64,
}

pub struct Cache {
    entries: [Option<Entry>; ENTRIES],
    ttl: u64,
}

impl Default for Cache {
    fn default() -> Self {
        Self::new()
    }
}

impl Cache {
    pub const fn new() -> Cache {
        Cache::with_ttl(TTL_NS)
    }

    /// A cache whose entries live `ttl` nanoseconds, for tests of expiry.
    pub const fn with_ttl(ttl: u64) -> Cache {
        Cache {
            entries: [None; ENTRIES],
            ttl,
        }
    }

    /// The hardware address for `ip`, if an entry is live at `now`.
    pub fn lookup(&self, ip: Ipv4Addr, now: u64) -> Option<Mac> {
        self.entries
            .iter()
            .flatten()
            .find(|e| e.ip == ip && e.expires > now)
            .map(|e| e.mac)
    }

    /// Record that `ip` is at `mac` as of `now`.
    pub fn insert(&mut self, ip: Ipv4Addr, mac: Mac, now: u64) {
        let entry = Entry {
            ip,
            mac,
            expires: now.saturating_add(self.ttl),
        };
        // The same address again refreshes its entry rather than taking a second slot,
        // which would let a stale mapping be found first.
        if let Some(slot) = self
            .entries
            .iter_mut()
            .find(|e| e.is_some_and(|e| e.ip == ip))
        {
            *slot = Some(entry);
            return;
        }
        let victim = match self
            .entries
            .iter()
            .position(|e| e.is_none_or(|e| e.expires <= now))
        {
            Some(i) => i,
            None => self
                .entries
                .iter()
                .enumerate()
                .min_by_key(|(_, e)| e.map_or(0, |e| e.expires))
                .map_or(0, |(i, _)| i),
        };
        self.entries[victim] = Some(entry);
    }

    /// Drop whatever is known about `ip`, live or not.
    pub fn forget(&mut self, ip: Ipv4Addr) {
        for slot in self.entries.iter_mut() {
            if slot.is_some_and(|e| e.ip == ip) {
                *slot = None;
            }
        }
    }

    /// Entries live at `now`.
    pub fn live(&self, now: u64) -> usize {
        self.entries
            .iter()
            .flatten()
            .filter(|e| e.expires > now)
            .count()
    }
}

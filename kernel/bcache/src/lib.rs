//! A cache of blocks, between a filesystem and a device.
//!
//! A filesystem reads a byte range; a device moves whole blocks. Without something in
//! between, walking a FAT chain would read the same sector of the table once per cluster,
//! and reading one byte would read five hundred and twelve. This is that something: a
//! fixed number of slots, each holding one block, replaced least-recently-used.
//!
//! # Write-through, and why
//!
//! A write goes to the device first and updates the cached copy only if the device took
//! it. So the cache is never the only place a byte lives, nothing has to be flushed before
//! a power cut, and [`flush`](Cache::flush) is the device's own flush rather than a
//! write-back pass. The cost is that every write is a device write: a write-back cache
//! would be faster and would need a policy for ordering, a dirty list, and a story about
//! what a crash loses. None of that is worth inventing before something writes enough to
//! measure — the on-disk filesystem above this is read-only today.
//!
//! # No allocation
//!
//! Slots and their bytes come from the caller, as everywhere else in this kernel's
//! storage stack. The kernel mounts its first filesystem during bring-up, before there is
//! a heap to allocate from, and the same cache is used by a thread that must not sleep.

#![cfg_attr(not(test), no_std)]
#![deny(unsafe_code)]

#[cfg(test)]
mod tests;

use block::{BlockDevice, Error};

/// One slot's bookkeeping. The bytes live in the caller's buffer, at the slot's index.
///
/// Public because [`Cache::new`] takes an array of them: a caller that does not want
/// [`Storage`]'s fixed shape — a cache over memory a device handed back, say — declares
/// the array itself, and every field of it is this module's business.
#[derive(Clone, Copy)]
pub struct Slot {
    lba: u64,
    valid: bool,
    /// When this slot was last used, on [`Cache::tick`]'s counter. The oldest valid slot
    /// is the one replaced.
    used_at: u64,
}

impl Slot {
    /// A slot holding nothing.
    pub const EMPTY: Slot = Slot {
        lba: 0,
        valid: false,
        used_at: 0,
    };
}

/// What the cache has done, for a caller that wants to prove it is working and that
/// nothing has gone missing.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Stats {
    /// Block lookups served from a slot.
    pub hits: u64,
    /// Block lookups that had to read the device.
    pub misses: u64,
    /// Valid slots replaced to make room.
    pub evictions: u64,
    /// Blocks read from the device.
    pub device_reads: u64,
    /// Blocks written to the device.
    pub device_writes: u64,
}

/// A cache of `slots.len()` blocks.
pub struct Cache<'s> {
    slots: &'s mut [Slot],
    data: &'s mut [u8],
    block_size: usize,
    stats: Stats,
    clock: u64,
}

/// Storage for a cache of `N` blocks of `BS` bytes, so a caller can put one in a static
/// without computing the two lengths by hand and getting them out of step.
pub struct Storage<const N: usize, const BS: usize> {
    slots: [Slot; N],
    data: [[u8; BS]; N],
}

impl<const N: usize, const BS: usize> Default for Storage<N, BS> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize, const BS: usize> Storage<N, BS> {
    pub const fn new() -> Self {
        Storage {
            slots: [Slot::EMPTY; N],
            data: [[0; BS]; N],
        }
    }

    /// A cache over this storage. `None` if `BS` is not a usable block size, which is the
    /// same check [`Cache::new`] makes.
    pub fn cache(&mut self) -> Option<Cache<'_>> {
        // `[[u8; BS]; N]` is contiguous, so its bytes are the N blocks back to back.
        let data = self.data.as_flattened_mut();
        Cache::new(&mut self.slots, data, BS)
    }
}

impl<'s> Cache<'s> {
    /// A cache over `slots` and `data`, which must hold exactly one block per slot.
    pub fn new(slots: &'s mut [Slot], data: &'s mut [u8], block_size: usize) -> Option<Cache<'s>> {
        if slots.is_empty() || !block_size.is_power_of_two() {
            return None;
        }
        if data.len() != slots.len().checked_mul(block_size)? {
            return None;
        }
        for s in slots.iter_mut() {
            *s = Slot::EMPTY;
        }
        Some(Cache {
            slots,
            data,
            block_size,
            stats: Stats::default(),
            clock: 0,
        })
    }

    pub fn block_size(&self) -> usize {
        self.block_size
    }

    pub fn slots(&self) -> usize {
        self.slots.len()
    }

    pub fn stats(&self) -> Stats {
        self.stats
    }

    fn tick(&mut self) -> u64 {
        self.clock += 1;
        self.clock
    }

    fn bytes_of(&self, slot: usize) -> &[u8] {
        &self.data[slot * self.block_size..(slot + 1) * self.block_size]
    }

    /// The slot holding `lba`, reading the device into a free or replaced slot if it is
    /// not cached.
    fn slot_for(&mut self, dev: &dyn BlockDevice, lba: u64) -> Result<usize, Error> {
        if let Some(i) = self.slots.iter().position(|s| s.valid && s.lba == lba) {
            self.stats.hits += 1;
            let now = self.tick();
            self.slots[i].used_at = now;
            return Ok(i);
        }
        self.stats.misses += 1;
        let victim = self.victim();
        if self.slots[victim].valid {
            self.stats.evictions += 1;
        }
        // The slot is invalidated before the read, so a device error cannot leave it
        // holding one block's bookkeeping and another block's bytes.
        self.slots[victim].valid = false;
        let bs = self.block_size;
        let into = &mut self.data[victim * bs..(victim + 1) * bs];
        dev.read_blocks(lba, into)?;
        self.stats.device_reads += 1;
        let now = self.tick();
        self.slots[victim] = Slot {
            lba,
            valid: true,
            used_at: now,
        };
        Ok(victim)
    }

    /// A free slot, or the least recently used one.
    fn victim(&self) -> usize {
        if let Some(i) = self.slots.iter().position(|s| !s.valid) {
            return i;
        }
        let mut oldest = 0;
        for (i, s) in self.slots.iter().enumerate() {
            if s.used_at < self.slots[oldest].used_at {
                oldest = i;
            }
        }
        oldest
    }

    /// Read `into` from byte `offset` of the device, through the cache.
    ///
    /// A read that crosses blocks is several lookups, which is what makes a filesystem's
    /// small reads cheap: the second byte of a sector is a hit.
    pub fn read_at(
        &mut self,
        dev: &dyn BlockDevice,
        offset: u64,
        into: &mut [u8],
    ) -> Result<(), Error> {
        let bs = self.block_size as u64;
        let mut done = 0usize;
        while done < into.len() {
            let pos = offset
                .checked_add(done as u64)
                .ok_or(Error::Device("a read offset past the end of the address space"))?;
            let lba = pos / bs;
            let within = (pos % bs) as usize;
            let take = (self.block_size - within).min(into.len() - done);
            let slot = self.slot_for(dev, lba)?;
            let from = &self.bytes_of(slot)[within..within + take];
            into[done..done + take].copy_from_slice(from);
            done += take;
        }
        Ok(())
    }

    /// Read whole blocks, through the cache.
    pub fn read_blocks(
        &mut self,
        dev: &dyn BlockDevice,
        lba: u64,
        into: &mut [u8],
    ) -> Result<(), Error> {
        if into.len() % self.block_size != 0 {
            return Err(Error::Misaligned {
                bytes: into.len(),
                block_size: self.block_size,
            });
        }
        self.read_at(dev, lba * self.block_size as u64, into)
    }

    /// Write one block, through to the device.
    ///
    /// The device takes it first. Only then is the cached copy updated, so a slot can
    /// never hold bytes the device refused — the stale read a write-through cache exists
    /// to make impossible.
    pub fn write_block(
        &mut self,
        dev: &dyn BlockDevice,
        lba: u64,
        from: &[u8],
    ) -> Result<(), Error> {
        if from.len() != self.block_size {
            return Err(Error::Misaligned {
                bytes: from.len(),
                block_size: self.block_size,
            });
        }
        dev.write_blocks(lba, from)?;
        self.stats.device_writes += 1;
        let slot = match self.slots.iter().position(|s| s.valid && s.lba == lba) {
            Some(i) => i,
            None => {
                let victim = self.victim();
                if self.slots[victim].valid {
                    self.stats.evictions += 1;
                }
                victim
            }
        };
        let bs = self.block_size;
        self.data[slot * bs..(slot + 1) * bs].copy_from_slice(from);
        let now = self.tick();
        self.slots[slot] = Slot {
            lba,
            valid: true,
            used_at: now,
        };
        Ok(())
    }

    /// Forget a block, so the next read of it reaches the device. For a caller that wrote
    /// behind the cache's back — the block check does, to prove the cache is really being
    /// asked rather than guessing.
    pub fn invalidate(&mut self, lba: u64) {
        for s in self.slots.iter_mut() {
            if s.valid && s.lba == lba {
                s.valid = false;
            }
        }
    }

    /// Forget everything.
    pub fn invalidate_all(&mut self) {
        for s in self.slots.iter_mut() {
            s.valid = false;
        }
    }

    /// Make the device's writes durable. Nothing is held here to write back.
    pub fn flush(&mut self, dev: &dyn BlockDevice) -> Result<(), Error> {
        dev.flush()
    }

    /// Everything the cache claims about itself, checked.
    ///
    /// A caller runs this at a quiet point: the counters must add up, and no two slots may
    /// hold the same block, which is the corruption a lookup that misses a valid slot
    /// would cause — two copies of one block, one of them stale.
    pub fn check(&self) -> Result<(), &'static str> {
        if self.data.len() != self.slots.len() * self.block_size {
            return Err("the cache's bytes are not one block per slot");
        }
        if self.stats.device_reads != self.stats.misses {
            return Err("a miss did not read the device, or a read was not a miss");
        }
        if self.stats.evictions > self.stats.misses + self.stats.device_writes {
            return Err("more slots were replaced than there were lookups to replace them");
        }
        for (i, a) in self.slots.iter().enumerate() {
            if !a.valid {
                continue;
            }
            if self.slots[..i].iter().any(|b| b.valid && b.lba == a.lba) {
                return Err("two slots hold the same block");
            }
        }
        Ok(())
    }
}

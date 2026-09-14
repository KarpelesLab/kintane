//! A cache of blocks, between a filesystem and a device.
//!
//! A filesystem reads a byte range; a device moves whole blocks. Without something in
//! between, walking a FAT chain would read the same sector of the table once per cluster,
//! and reading one byte would read five hundred and twelve. This is that something: a
//! fixed number of slots, each holding one block, replaced least-recently-used.
//!
//! # Two ways to write
//!
//! * [`write_block`](Cache::write_block) writes through: the device takes the block first, and the
//!   cached copy changes only if it did. The block check uses it to prove a write reaches the
//!   device, and nothing is left to flush.
//! * [`write_at`](Cache::write_at) writes back: the bytes change in a slot, which is marked dirty,
//!   and reach the device later — when the slot is needed for another block, when a later write
//!   must follow it, or at [`sync`](Cache::sync). A filesystem that writes a file a few bytes at a
//!   time does not pay a device write for each.
//!
//! # Order, which is what makes write-back safe
//!
//! A filesystem that survives a crash does so by the order its blocks reach the disk: a
//! file's data before the table that claims its clusters, the table before the directory
//! entry that names them. A write-back cache that wrote its dirty blocks in any order would
//! undo that. So every dirty slot carries the **generation** it was dirtied in, and
//! [`barrier`](Cache::barrier) starts a new one. The rules:
//!
//! 1. Dirty blocks reach the device in ascending generation. A slot of generation `g` is written
//!    only once no dirty slot of an earlier generation remains.
//! 2. A slot dirty from an earlier generation is written out — with everything before it — before a
//!    later write changes it. Otherwise its bytes would carry the later change to the device at the
//!    earlier position, ahead of blocks that must precede that change.
//! 3. Evicting a dirty slot is writing it out, under rule 1.
//!
//! So the device sees a sequence of writes whose generations never decrease, and a
//! filesystem that puts a barrier between two steps knows the first step's blocks are all on
//! the device before any of the second's. Within one generation the order is unspecified,
//! which is why a step is chosen so that any subset of its blocks leaves the volume
//! consistent.
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
#[cfg(test)]
mod writeback_tests;

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
    /// When this slot was last used, on [`Cache::tick`]'s counter. The oldest clean slot
    /// is the one replaced.
    used_at: u64,
    /// The slot's bytes differ from the device's, and must reach it.
    dirty: bool,
    /// The generation the slot was dirtied in; meaningful only while `dirty`.
    generation: u64,
}

impl Slot {
    /// A slot holding nothing.
    pub const EMPTY: Slot = Slot {
        lba: 0,
        valid: false,
        used_at: 0,
        dirty: false,
        generation: 0,
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
    /// Slots taken for a block a write covers whole, which need no read.
    pub claims: u64,
    /// Valid slots replaced to make room.
    pub evictions: u64,
    /// Blocks read from the device.
    pub device_reads: u64,
    /// Blocks written to the device, through or back.
    pub device_writes: u64,
    /// Of those, dirty blocks written back.
    pub write_backs: u64,
    /// Dirty blocks written back because their slot was needed for another block.
    pub pressure_writes: u64,
}

/// A cache of `slots.len()` blocks.
pub struct Cache<'s> {
    slots: &'s mut [Slot],
    data: &'s mut [u8],
    block_size: usize,
    stats: Stats,
    clock: u64,
    /// The generation a dirtying write is stamped with now.
    generation: u64,
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
            generation: 1,
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

    /// Slots holding bytes the device does not have yet.
    pub fn dirty(&self) -> usize {
        self.slots.iter().filter(|s| s.valid && s.dirty).count()
    }

    fn tick(&mut self) -> u64 {
        self.clock += 1;
        self.clock
    }

    fn bytes_of(&self, slot: usize) -> &[u8] {
        &self.data[slot * self.block_size..(slot + 1) * self.block_size]
    }

    /// End a step: every block dirtied from here on reaches the device after every block
    /// dirtied before. See the module documentation.
    pub fn barrier(&mut self) {
        // A barrier with nothing dirty since the last one orders nothing, so the counter
        // does not move and a caller may put barriers wherever a step might end.
        if self
            .slots
            .iter()
            .any(|s| s.valid && s.dirty && s.generation == self.generation)
        {
            self.generation += 1;
        }
    }

    /// Write every dirty slot of generation `upto` or earlier to the device, oldest
    /// generation first. A device error leaves the slot that failed, and every later one,
    /// dirty.
    fn write_out(&mut self, dev: &dyn BlockDevice, upto: u64) -> Result<(), Error> {
        loop {
            // The dirty slot of the lowest generation, lowest block first within it, so the
            // order is deterministic as well as correct.
            let mut next: Option<usize> = None;
            for (i, s) in self.slots.iter().enumerate() {
                if !(s.valid && s.dirty && s.generation <= upto) {
                    continue;
                }
                let better = match next {
                    None => true,
                    Some(j) => {
                        let o = &self.slots[j];
                        (s.generation, s.lba) < (o.generation, o.lba)
                    }
                };
                if better {
                    next = Some(i);
                }
            }
            let Some(i) = next else {
                return Ok(());
            };
            let bs = self.block_size;
            dev.write_blocks(self.slots[i].lba, &self.data[i * bs..(i + 1) * bs])?;
            self.stats.device_writes += 1;
            self.stats.write_backs += 1;
            self.slots[i].dirty = false;
        }
    }

    /// A slot to put a new block in: a free one, or the least recently used clean one, or —
    /// when every slot is dirty — the oldest dirty one, written out first with everything it
    /// must follow.
    fn victim(&mut self, dev: &dyn BlockDevice) -> Result<usize, Error> {
        if let Some(i) = self.slots.iter().position(|s| !s.valid) {
            return Ok(i);
        }
        let mut oldest: Option<usize> = None;
        for (i, s) in self.slots.iter().enumerate() {
            if s.dirty {
                continue;
            }
            if oldest.is_none_or(|o| s.used_at < self.slots[o].used_at) {
                oldest = Some(i);
            }
        }
        if let Some(i) = oldest {
            return Ok(i);
        }
        // Every slot is dirty. Writing out the oldest generation frees at least one slot.
        let lowest = self
            .slots
            .iter()
            .map(|s| s.generation)
            .min()
            .unwrap_or(self.generation);
        let before = self.stats.write_backs;
        self.write_out(dev, lowest)?;
        self.stats.pressure_writes += self.stats.write_backs - before;
        self.slots
            .iter()
            .position(|s| !s.dirty)
            .ok_or(Error::Device("a write-out left every slot dirty"))
    }

    /// Take a slot for `lba`, evicting as needed, and count the eviction.
    fn take(&mut self, dev: &dyn BlockDevice) -> Result<usize, Error> {
        let victim = self.victim(dev)?;
        if self.slots[victim].valid {
            self.stats.evictions += 1;
        }
        // The slot is invalidated before anything is read into it, so a device error cannot
        // leave it holding one block's bookkeeping and another block's bytes.
        self.slots[victim].valid = false;
        Ok(victim)
    }

    fn cached(&self, lba: u64) -> Option<usize> {
        self.slots.iter().position(|s| s.valid && s.lba == lba)
    }

    /// The slot holding `lba`, reading the device into a free or replaced slot if it is
    /// not cached.
    fn slot_for(&mut self, dev: &dyn BlockDevice, lba: u64) -> Result<usize, Error> {
        if let Some(i) = self.cached(lba) {
            self.stats.hits += 1;
            let now = self.tick();
            self.slots[i].used_at = now;
            return Ok(i);
        }
        self.stats.misses += 1;
        let victim = self.take(dev)?;
        let bs = self.block_size;
        let into = &mut self.data[victim * bs..(victim + 1) * bs];
        dev.read_blocks(lba, into)?;
        self.stats.device_reads += 1;
        let now = self.tick();
        self.slots[victim] = Slot {
            lba,
            valid: true,
            used_at: now,
            dirty: false,
            generation: 0,
        };
        Ok(victim)
    }

    /// Read `into` from byte `offset` of the device, through the cache.
    ///
    /// A read that crosses blocks is several lookups, which is what makes a filesystem's
    /// small reads cheap: the second byte of a sector is a hit. A dirty block reads as its
    /// newest bytes.
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

    /// Write `from` at byte `offset` of the device, back: into slots marked dirty in the
    /// current generation, which reach the device later. See the module documentation for
    /// when, and in what order.
    ///
    /// A block the write covers whole is taken without reading it; a block it covers in
    /// part is read first, so the rest of the block keeps its bytes.
    pub fn write_at(
        &mut self,
        dev: &dyn BlockDevice,
        offset: u64,
        from: &[u8],
    ) -> Result<(), Error> {
        let bs = self.block_size as u64;
        let mut done = 0usize;
        while done < from.len() {
            let pos = offset
                .checked_add(done as u64)
                .ok_or(Error::Device("a write offset past the end of the address space"))?;
            let lba = pos / bs;
            let within = (pos % bs) as usize;
            let take = (self.block_size - within).min(from.len() - done);
            let slot = match self.cached(lba) {
                Some(i) => {
                    self.stats.hits += 1;
                    i
                }
                None if take == self.block_size => {
                    self.stats.claims += 1;
                    let victim = self.take(dev)?;
                    self.slots[victim] = Slot {
                        lba,
                        valid: true,
                        used_at: 0,
                        dirty: false,
                        generation: 0,
                    };
                    victim
                }
                None => self.slot_for(dev, lba)?,
            };
            // Rule 2: bytes from an earlier generation reach the device before this change.
            let s = self.slots[slot];
            if s.dirty && s.generation < self.generation {
                self.write_out(dev, s.generation)?;
            }
            let bs_us = self.block_size;
            let at = slot * bs_us + within;
            self.data[at..at + take].copy_from_slice(&from[done..done + take]);
            let now = self.tick();
            let generation = self.generation;
            let s = &mut self.slots[slot];
            s.used_at = now;
            s.dirty = true;
            s.generation = generation;
            done += take;
        }
        Ok(())
    }

    /// Write one block, through to the device.
    ///
    /// Everything dirty is written back first, so a block written through never overtakes
    /// one an earlier step left in the cache. The device takes it next. Only then is the
    /// cached copy updated, so a slot can never hold bytes the device refused — the stale
    /// read a write-through cache exists to make impossible.
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
        self.write_out(dev, u64::MAX)?;
        dev.write_blocks(lba, from)?;
        self.stats.device_writes += 1;
        let slot = match self.cached(lba) {
            Some(i) => i,
            None => self.take(dev)?,
        };
        let bs = self.block_size;
        self.data[slot * bs..(slot + 1) * bs].copy_from_slice(from);
        let now = self.tick();
        self.slots[slot] = Slot {
            lba,
            valid: true,
            used_at: now,
            dirty: false,
            generation: 0,
        };
        Ok(())
    }

    /// Forget a block, so the next read of it reaches the device. For a caller that wrote
    /// behind the cache's back — the block check does, to prove the cache is really being
    /// asked rather than guessing. A dirty block is not forgotten: its bytes exist nowhere
    /// else yet.
    pub fn invalidate(&mut self, lba: u64) {
        for s in self.slots.iter_mut() {
            if s.valid && s.lba == lba && !s.dirty {
                s.valid = false;
            }
        }
    }

    /// Forget every clean block. Dirty ones are kept, for the same reason as in
    /// [`invalidate`](Self::invalidate).
    pub fn invalidate_all(&mut self) {
        for s in self.slots.iter_mut() {
            if !s.dirty {
                s.valid = false;
            }
        }
    }

    /// Write every dirty block back, in order, and make the device's writes durable.
    pub fn sync(&mut self, dev: &dyn BlockDevice) -> Result<(), Error> {
        self.write_out(dev, u64::MAX)?;
        self.barrier();
        dev.flush()
    }

    /// The same as [`sync`](Self::sync): nothing written through is held here, and
    /// everything written back is written by it.
    pub fn flush(&mut self, dev: &dyn BlockDevice) -> Result<(), Error> {
        self.sync(dev)
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
        if self.stats.evictions > self.stats.misses + self.stats.claims + self.stats.device_writes {
            return Err("more slots were replaced than there were lookups to replace them");
        }
        if self.stats.write_backs > self.stats.device_writes
            || self.stats.pressure_writes > self.stats.write_backs
        {
            return Err("more blocks were written back than were written");
        }
        for (i, a) in self.slots.iter().enumerate() {
            if a.dirty && !a.valid {
                return Err("a slot is dirty and holds no block");
            }
            if a.dirty && a.generation > self.generation {
                return Err("a slot is dirty from a generation that has not begun");
            }
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

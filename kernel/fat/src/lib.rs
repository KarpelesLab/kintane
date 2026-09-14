//! FAT16, read and written.
//!
//! The first filesystem the kernel reads from a disk it did not write, and now writes to.
//! FAT rather than a format of our own for one reason: it is already in this tree twice.
//! kbuild writes a FAT16 volume for the EFI system partition and for the test disk, and
//! `kinboot-efi` reads one to find the kernel. A third format would be a third thing to get
//! right, with no third reader to check it against — and kbuild's reader is exactly what
//! checks, after a run, that what the kernel wrote is a volume.
//!
//! # What is implemented, and what is refused
//!
//! * **FAT16 only.** The cluster count decides the type, as the specification says — not the
//!   `FAT16` string in the boot sector, which is advisory and which real formatters get wrong. A
//!   volume outside FAT16's cluster range is refused by name rather than read as if the table were
//!   12 or 32 bits wide. FAT32 would need a root directory that is a chain, the FSInfo sector and
//!   28-bit table entries: none of it shares much with this, so it is not here.
//! * **8.3 names.** Long-name entries are skipped, so a file with one is reachable by its short
//!   name. A name created or renamed here must be a valid 8.3 name, and is stored in upper case;
//!   anything else is [`vfs::Error::BadPath`] rather than a name silently shortened.
//! * **Every field is checked before it is used.** A cluster number outside the table, a chain
//!   longer than the volume has clusters, a directory entry past the end of its region: each is
//!   [`vfs::Error::Corrupt`] with the field named. The bytes come from a disk, and a disk is not
//!   trusted.
//!
//! # Writing, and what a crash can leave
//!
//! Writes go through [`bcache::Cache::write_at`], which holds blocks back and writes them in
//! the order [`bcache::Cache::barrier`] sets. Every operation is a sequence of steps with a
//! barrier after each, chosen so that the volume is consistent after any prefix of the
//! steps, and after any subset of the blocks of the step in progress:
//!
//! 1. **Data**, into clusters the table still calls free. A crash leaves free clusters with bytes
//!    in them, which nothing reads.
//! 2. **The new clusters' own table entries**, each pointing at the next and the last at the end of
//!    the chain. A crash leaves allocated clusters nothing names: lost clusters, the one kind of
//!    damage a crash is allowed to cause.
//! 3. **The link** from the file's old last cluster to the first new one. The chain is now longer
//!    than the size its entry records, which is allowed: the size says what to read.
//! 4. **The directory entry**: its first cluster, for a file that had none, and its size. One
//!    32-byte entry is inside one sector, so it changes as a whole.
//!
//! Steps 2 and 3 run for the first table copy, then for the second, so a crash leaves the
//! copies different by at most one step, the first ahead: recoverable by taking the first.
//! Freeing runs the other way — the entry first (a smaller size, or the entry deleted), then
//! the new end of the chain, then the freed clusters — so an entry never names a free
//! cluster and a chain never runs through one. A rename that replaces a file deletes the
//! target's entry, then renames, then frees.
//!
//! What this does not give: a write that overwrites bytes inside a file is not atomic, so a
//! crash may leave some of it; a file extended and not yet synced may lose the extension.
//! What it does give: no cross-linked chain, no entry into a free cluster, and table copies
//! that differ only in a recoverable way, after a crash at any point.
//!
//! # Where the bytes come from
//!
//! Every read and write goes through [`bcache::Cache`], so walking a chain reads the table's
//! sector once rather than once per cluster. The volume may sit anywhere on the device:
//! `start` is its first block, which is what lets the test disk carry a pattern region, a
//! volume and a scratch area on one device with one driver.

#![cfg_attr(not(test), no_std)]
#![deny(unsafe_code)]

#[cfg(test)]
mod tests;
#[cfg(test)]
mod write_tests;

use bcache::Cache;
use block::BlockDevice;
use vfs::{Entry, Error, FileSystem, Kind, NodeId, Stat};

/// Bytes of one directory entry.
const ENTRY: usize = 32;
/// The attribute byte's bits this driver acts on.
const ATTR_READ_ONLY: u8 = 0x01;
const ATTR_VOLUME_ID: u8 = 0x08;
const ATTR_DIRECTORY: u8 = 0x10;
const ATTR_ARCHIVE: u8 = 0x20;
/// A long-name entry: every attribute bit below the directory bit set at once.
const ATTR_LONG_NAME: u8 = 0x0F;
/// The first byte of an entry that has never been used; nothing follows it.
const ENTRY_FREE: u8 = 0x00;
/// The first byte of a deleted entry, which is skipped.
const ENTRY_DELETED: u8 = 0xE5;
/// Cluster values at or above this end a chain.
const CHAIN_END: u16 = 0xFFF8;
/// What this driver writes to end a chain.
const END_OF_CHAIN: u16 = 0xFFFF;
/// A cluster marked bad, which no chain may run through.
const BAD_CLUSTER: u16 = 0xFFF7;
/// FAT16 is defined by its cluster count, not by any string in the volume.
const MIN_CLUSTERS: u32 = 4085;
const MAX_CLUSTERS: u32 = 65525;
/// The longest name this reader reports: eight, a dot, three.
const NAME_BYTES: usize = 12;
/// 1980-01-01 as a FAT date, the epoch kbuild's writer stamps too: this kernel keeps no
/// wall-clock time a directory entry could record.
const FAT_EPOCH_DATE: u16 = (1 << 5) | 1;
/// Clusters one allocation step claims. Bounds the table changes held on the stack and the
/// work a crash can find half done.
const STEP: usize = 32;
/// Directories a consistency walk descends through before it calls the volume corrupt. A
/// directory whose chain names an ancestor would otherwise recurse for ever.
const MAX_DEPTH: usize = 16;
/// Characters an 8.3 name may hold besides letters and digits.
const NAME_PUNCTUATION: &[u8] = b"_-!#$%&'()@^{}~";

fn u16_at(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}

fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

/// What [`Fat16::check_consistency`] found on a volume it did not call corrupt.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Consistency {
    pub files: u32,
    pub dirs: u32,
    /// Clusters some file or directory's chain claims.
    pub claimed: u32,
    /// Clusters the table allocates that no chain claims: what a crash may leave.
    pub lost: u32,
    /// Table entries on which the copies disagree.
    pub fats_differ: u32,
}

/// A mounted FAT16 volume.
///
/// Owns its cache: the cache is only ever reached through the filesystem, and a filesystem
/// that borrowed one would make every caller thread two lifetimes through its own types
/// for no benefit.
pub struct Fat16<'s, 'd> {
    dev: &'d dyn BlockDevice,
    cache: Cache<'s>,
    sector: usize,
    cluster_sectors: u64,
    /// Absolute block of the first file allocation table. Every other position the driver
    /// needs is absolute too, computed once at mount from the volume's own start, so
    /// nothing below has to remember to add it.
    fat_start: u64,
    /// Copies of the table, and sectors in each.
    fats: u64,
    fat_sectors: u64,
    /// Absolute block of the root directory's own region.
    root_start: u64,
    root_entries: usize,
    /// Absolute block the data region starts at, where cluster 2 lives.
    data_start: u64,
    clusters: u32,
    /// Where the next search for a free cluster starts.
    free_hint: u32,
}

impl<'s, 'd> Fat16<'s, 'd> {
    /// Read the volume starting at block `start` of `dev` and check its geometry.
    ///
    /// The cache's block size must be the device's, since everything below is counted in
    /// the volume's own sectors and the two must be the same unit.
    pub fn mount(
        dev: &'d dyn BlockDevice,
        mut cache: Cache<'s>,
        start: u64,
    ) -> Result<Fat16<'s, 'd>, Error> {
        let geometry = dev.geometry();
        if cache.block_size() != geometry.block_size {
            return Err(Error::Corrupt("the cache's block size is not the device's"));
        }
        let sector = geometry.block_size;
        if sector < 64 {
            return Err(Error::Corrupt("a block too small to hold a boot sector"));
        }
        let mut boot = [0u8; 512];
        let boot = &mut boot[..sector.min(512)];
        cache
            .read_blocks(dev, start, boot)
            .map_err(|_| Error::Device("the volume's first block could not be read"))?;

        if u16_at(boot, 510) != 0xAA55 {
            return Err(Error::Corrupt("no boot-sector signature"));
        }
        let bytes_per_sector = u16_at(boot, 11) as usize;
        if bytes_per_sector != sector {
            return Err(Error::Corrupt("the volume's sector size is not the device's"));
        }
        let cluster_sectors = u64::from(boot[13]);
        if cluster_sectors == 0 || !cluster_sectors.is_power_of_two() || cluster_sectors > 128 {
            return Err(Error::Corrupt("sectors per cluster"));
        }
        let reserved = u64::from(u16_at(boot, 14));
        if reserved == 0 {
            return Err(Error::Corrupt("reserved sectors"));
        }
        let fats = u64::from(boot[16]);
        if fats == 0 || fats > 4 {
            return Err(Error::Corrupt("file allocation table count"));
        }
        let root_entries = u16_at(boot, 17) as usize;
        if root_entries == 0 || (root_entries * ENTRY) % sector != 0 {
            return Err(Error::Corrupt("root directory entries"));
        }
        let fat_sectors = u64::from(u16_at(boot, 22));
        if fat_sectors == 0 {
            return Err(Error::Corrupt("sectors per file allocation table"));
        }
        let total = match u16_at(boot, 19) {
            0 => u64::from(u32_at(boot, 32)),
            small => u64::from(small),
        };
        let root_sectors = (root_entries * ENTRY / sector) as u64;
        let overhead = reserved + fats * fat_sectors + root_sectors;
        if total <= overhead {
            return Err(Error::Corrupt("a volume with no room for data"));
        }
        // The volume must be on the device, or a read past its end would be answered by
        // whatever follows rather than refused.
        if start.saturating_add(total) > geometry.capacity {
            return Err(Error::Corrupt("a volume that runs past the end of the device"));
        }
        let clusters = u32::try_from((total - overhead) / cluster_sectors)
            .map_err(|_| Error::Corrupt("cluster count"))?;
        if !(MIN_CLUSTERS..MAX_CLUSTERS).contains(&clusters) {
            // The specification decides the width of a table entry by this count alone.
            return Err(Error::Corrupt("not FAT16: the cluster count is another type's"));
        }
        // Every entry of the table must be inside it, or a chain could read the root
        // directory as if it were table entries.
        if u64::from(clusters + 2) * 2 > fat_sectors * sector as u64 {
            return Err(Error::Corrupt("a table too small for its own clusters"));
        }

        Ok(Fat16 {
            dev,
            cache,
            sector,
            cluster_sectors,
            fat_start: start + reserved,
            fats,
            fat_sectors,
            root_start: start + reserved + fats * fat_sectors,
            root_entries,
            data_start: start + overhead,
            clusters,
            free_hint: 2,
        })
    }

    /// What the cache has done, for a caller proving the volume is being read through it.
    pub fn cache_stats(&self) -> bcache::Stats {
        self.cache.stats()
    }

    /// The cache's own books.
    pub fn check_cache(&self) -> Result<(), &'static str> {
        self.cache.check()
    }

    /// Blocks written to the cache and not yet to the device.
    pub fn dirty_blocks(&self) -> usize {
        self.cache.dirty()
    }

    /// Forget every clean cached block: what a caller does after writing behind the
    /// filesystem's back, and what the boot check uses to prove a read really reached the
    /// device. Blocks not yet written are kept.
    pub fn invalidate_cache(&mut self) {
        self.cache.invalidate_all();
    }

    /// Clusters on the volume, for a caller sizing the bitmap
    /// [`check_consistency`](Self::check_consistency) needs.
    pub fn clusters(&self) -> u32 {
        self.clusters
    }

    fn bytes_per_cluster(&self) -> u64 {
        self.cluster_sectors * self.sector as u64
    }

    fn read_at_device(&mut self, offset: u64, into: &mut [u8]) -> Result<(), Error> {
        self.cache
            .read_at(self.dev, offset, into)
            .map_err(|_| Error::Device("a read of the volume failed"))
    }

    fn write_at_device(&mut self, offset: u64, from: &[u8]) -> Result<(), Error> {
        self.cache
            .write_at(self.dev, offset, from)
            .map_err(|_| Error::Device("a write of the volume failed"))
    }

    /// End a step of an operation; see the module documentation.
    fn step(&mut self) {
        self.cache.barrier();
    }

    fn in_volume(&self, cluster: u32) -> bool {
        cluster >= 2 && cluster < self.clusters + 2
    }

    /// Table copy `copy`'s entry for `cluster`, unchecked beyond its position.
    fn table_entry(&mut self, copy: u64, cluster: u32) -> Result<u16, Error> {
        let at = (self.fat_start + copy * self.fat_sectors) * self.sector as u64
            + u64::from(cluster) * 2;
        let mut bytes = [0u8; 2];
        self.read_at_device(at, &mut bytes)?;
        Ok(u16::from_le_bytes(bytes))
    }

    /// Write `changes` to every table copy, the first copy's as one step and each later
    /// copy's as the next.
    fn table_step(&mut self, changes: &[(u32, u16)]) -> Result<(), Error> {
        for copy in 0..self.fats {
            for &(cluster, value) in changes {
                if !self.in_volume(cluster) {
                    return Err(Error::Corrupt("a table change outside the volume"));
                }
                let at = (self.fat_start + copy * self.fat_sectors) * self.sector as u64
                    + u64::from(cluster) * 2;
                self.write_at_device(at, &value.to_le_bytes())?;
            }
            self.step();
        }
        Ok(())
    }

    /// The entry after `cluster` in its chain, or `None` at the end.
    fn next_cluster(&mut self, cluster: u32) -> Result<Option<u32>, Error> {
        if !self.in_volume(cluster) {
            return Err(Error::Corrupt("a cluster number outside the volume"));
        }
        let next = self.table_entry(0, cluster)?;
        if next >= CHAIN_END {
            return Ok(None);
        }
        let next = u32::from(next);
        if !self.in_volume(next) {
            return Err(Error::Corrupt("a chain entry outside the volume"));
        }
        Ok(Some(next))
    }

    /// Walk `skip` clusters along the chain from `first`.
    ///
    /// Bounded by the volume's cluster count: a chain that loops would otherwise walk for
    /// ever, and a corrupt table is exactly where a loop comes from.
    fn nth_cluster(&mut self, first: u32, skip: u64) -> Result<Option<u32>, Error> {
        if skip > u64::from(self.clusters) {
            return Err(Error::Corrupt("a chain longer than the volume"));
        }
        let mut cluster = first;
        for _ in 0..skip {
            match self.next_cluster(cluster)? {
                Some(next) => cluster = next,
                None => return Ok(None),
            }
        }
        Ok(Some(cluster))
    }

    /// Clusters in the chain from `first`, and the last of them.
    fn chain_end(&mut self, first: u32) -> Result<(u64, u32), Error> {
        let mut count = 1u64;
        let mut cluster = first;
        while let Some(next) = self.next_cluster(cluster)? {
            count += 1;
            if count > u64::from(self.clusters) {
                return Err(Error::Corrupt("a chain longer than the volume"));
            }
            cluster = next;
        }
        Ok((count, cluster))
    }

    fn cluster_offset(&self, cluster: u32) -> u64 {
        (self.data_start + u64::from(cluster - 2) * self.cluster_sectors) * self.sector as u64
    }

    /// Fill `out` with free clusters, searching from the hint and wrapping once. Returns how
    /// many were found; none is claimed until the caller writes the table.
    fn free_clusters(&mut self, out: &mut [u32]) -> Result<usize, Error> {
        let total = self.clusters;
        let start = if self.in_volume(self.free_hint) {
            self.free_hint
        } else {
            2
        };
        let mut found = 0;
        for i in 0..total {
            if found == out.len() {
                break;
            }
            let cluster = 2 + (start - 2 + i) % total;
            if self.table_entry(0, cluster)? == 0 {
                out[found] = cluster;
                found += 1;
            }
        }
        Ok(found)
    }

    /// Whether at least `want` clusters are free.
    fn have_free(&mut self, want: u64) -> Result<bool, Error> {
        if want == 0 {
            return Ok(true);
        }
        if want > u64::from(self.clusters) {
            return Ok(false);
        }
        let mut seen = 0u64;
        for cluster in 2..self.clusters + 2 {
            if self.table_entry(0, cluster)? == 0 {
                seen += 1;
                if seen == want {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }

    /// Where the `index`th raw entry of a directory lives on the device, or `None` past
    /// the end of the directory.
    ///
    /// The root has a region of its own, of a fixed number of entries. Every other
    /// directory is a chain of clusters like a file's.
    fn entry_offset(&mut self, dir: Dir, index: usize) -> Result<Option<u64>, Error> {
        match dir {
            Dir::Root => {
                if index >= self.root_entries {
                    return Ok(None);
                }
                Ok(Some(self.root_start * self.sector as u64 + (index * ENTRY) as u64))
            }
            Dir::Cluster(first) => {
                let per_cluster = self.bytes_per_cluster() / ENTRY as u64;
                if per_cluster == 0 {
                    return Err(Error::Corrupt("a cluster too small for an entry"));
                }
                let skip = index as u64 / per_cluster;
                let within = index as u64 % per_cluster;
                match self.nth_cluster(first, skip)? {
                    Some(cluster) => Ok(Some(self.cluster_offset(cluster) + within * ENTRY as u64)),
                    None => Ok(None),
                }
            }
        }
    }

    /// The raw bytes of the `index`th entry of `dir`.
    fn raw_entry(&mut self, dir: Dir, index: usize) -> Result<Option<(u64, [u8; ENTRY])>, Error> {
        let Some(offset) = self.entry_offset(dir, index)? else {
            return Ok(None);
        };
        let mut bytes = [0u8; ENTRY];
        self.read_at_device(offset, &mut bytes)?;
        Ok(Some((offset, bytes)))
    }

    /// The `n`th entry of `dir` that names something, with the ones a reader skips —
    /// free, deleted, the volume label, long names — passed over.
    ///
    /// `Ok(None)` at the end of the directory, which is the first never-used entry or the
    /// end of its region.
    fn nth_named(&mut self, dir: Dir, n: usize) -> Result<Option<(u64, [u8; ENTRY])>, Error> {
        let mut seen = 0usize;
        let mut index = 0usize;
        loop {
            let Some((offset, bytes)) = self.raw_entry(dir, index)? else {
                return Ok(None);
            };
            index += 1;
            if !names_something(&bytes)? {
                if bytes[0] == ENTRY_FREE {
                    return Ok(None);
                }
                continue;
            }
            if seen == n {
                return Ok(Some((offset, bytes)));
            }
            seen += 1;
        }
    }

    /// The entry in `dir` whose name matches `name`.
    fn find_entry(&mut self, dir: Dir, name: &[u8]) -> Result<Option<(u64, [u8; ENTRY])>, Error> {
        let mut n = 0usize;
        while let Some((offset, bytes)) = self.nth_named(dir, n)? {
            if name_matches(&bytes, name) {
                return Ok(Some((offset, bytes)));
            }
            n += 1;
        }
        Ok(None)
    }

    /// A directory's identity as this driver walks it.
    fn dir_of(&mut self, node: NodeId) -> Result<Dir, Error> {
        if node == ROOT {
            return Ok(Dir::Root);
        }
        let bytes = self.entry_bytes(node)?;
        self.dir_of_entry(&bytes)
    }

    fn dir_of_entry(&mut self, bytes: &[u8; ENTRY]) -> Result<Dir, Error> {
        if bytes[11] & ATTR_DIRECTORY == 0 {
            return Err(Error::NotADirectory);
        }
        match first_cluster(bytes) {
            // A directory with no chain has no entries: `.` and `..` are entries like any
            // other, so a real one always has at least one cluster.
            0 => Err(Error::Corrupt("a directory with no clusters")),
            c if !self.in_volume(c) => {
                Err(Error::Corrupt("a directory starting outside the volume"))
            }
            c => Ok(Dir::Cluster(c)),
        }
    }

    /// The 32 bytes of the directory entry a node names.
    fn entry_bytes(&mut self, node: NodeId) -> Result<[u8; ENTRY], Error> {
        let offset = node.checked_sub(1).ok_or(Error::NotFound)?;
        if offset % ENTRY as u64 != 0 {
            return Err(Error::NotFound);
        }
        let mut bytes = [0u8; ENTRY];
        self.read_at_device(offset, &mut bytes)?;
        if bytes[0] == ENTRY_FREE || bytes[0] == ENTRY_DELETED {
            return Err(Error::NotFound);
        }
        Ok(bytes)
    }

    /// The node for a file, checked writable.
    fn writable_file(&mut self, node: NodeId) -> Result<[u8; ENTRY], Error> {
        if node == ROOT {
            return Err(Error::IsADirectory);
        }
        let bytes = self.entry_bytes(node)?;
        if entry_kind(&bytes) != Kind::File {
            return Err(Error::IsADirectory);
        }
        if bytes[11] & ATTR_READ_ONLY != 0 {
            return Err(Error::ReadOnly);
        }
        Ok(bytes)
    }

    // ---- writing ------------------------------------------------------------------------

    /// Write `from` at `offset` of the file whose entry is at `node`, which already holds at
    /// least `offset` bytes: the steps the module documentation lists.
    fn write_span(&mut self, node: NodeId, offset: u64, from: &[u8]) -> Result<(), Error> {
        let mut entry = self.writable_file(node)?;
        let len = u64::from(u32_at(&entry, 28));
        let end = offset + from.len() as u64;
        let per = self.bytes_per_cluster();
        let first = first_cluster(&entry);
        let (have, mut tail) = match first {
            0 => (0, None),
            f => {
                let (count, last) = self.chain_end(f)?;
                (count, Some(last))
            }
        };
        let need = end.div_ceil(per);
        if need > have && !self.have_free(need - have)? {
            return Err(Error::Full);
        }

        // Bytes that land in clusters the file already has: in place, one step.
        let inside = end.min(have * per);
        if offset < inside {
            let mut pos = offset;
            while pos < inside {
                let index = pos / per;
                let cluster = self
                    .nth_cluster(first, index)?
                    .ok_or(Error::Corrupt("a chain shorter than it was a moment ago"))?;
                let within = pos % per;
                let take = (per - within).min(inside - pos) as usize;
                let at = (pos - offset) as usize;
                self.write_at_device(self.cluster_offset(cluster) + within, &from[at..at + take])?;
                pos += take as u64;
            }
            self.step();
        }

        // Clusters the file does not have yet, a step's worth at a time.
        let mut placed = have;
        let mut new_first = None;
        while placed < need {
            let want = ((need - placed) as usize).min(STEP);
            let mut fresh = [0u32; STEP];
            if self.free_clusters(&mut fresh[..want])? != want {
                return Err(Error::Full);
            }
            // Data first, into clusters the table still calls free.
            for (i, &cluster) in fresh[..want].iter().enumerate() {
                let start = (placed + i as u64) * per;
                let lo = start.max(offset);
                let hi = (start + per).min(end);
                if lo < hi {
                    let at = (lo - offset) as usize;
                    let bytes = &from[at..at + (hi - lo) as usize];
                    self.write_at_device(self.cluster_offset(cluster) + (lo - start), bytes)?;
                }
            }
            self.step();
            // The new clusters' own entries, then the link to them.
            let mut chain = [(0u32, 0u16); STEP];
            for i in 0..want {
                let value = if i + 1 < want {
                    fresh[i + 1] as u16
                } else {
                    END_OF_CHAIN
                };
                chain[i] = (fresh[i], value);
            }
            self.table_step(&chain[..want])?;
            match tail {
                Some(last) => self.table_step(&[(last, fresh[0] as u16)])?,
                None => new_first = Some(fresh[0]),
            }
            tail = Some(fresh[want - 1]);
            self.free_hint = fresh[want - 1] + 1;
            placed += want as u64;
        }

        // The entry last: its first cluster if it had none, and its size.
        if end > len || new_first.is_some() {
            if let Some(f) = new_first {
                entry[26..28].copy_from_slice(&(f as u16).to_le_bytes());
            }
            entry[28..32].copy_from_slice(&(end.max(len) as u32).to_le_bytes());
            self.write_at_device(node - 1, &entry)?;
            self.step();
        }
        Ok(())
    }

    /// Grow the file at `node` from `from` bytes to `to`, with zeros.
    fn zero_fill(&mut self, node: NodeId, from: u64, to: u64) -> Result<(), Error> {
        const ZEROS: [u8; 512] = [0; 512];
        let mut pos = from;
        while pos < to {
            let take = (to - pos).min(ZEROS.len() as u64) as usize;
            self.write_span(node, pos, &ZEROS[..take])?;
            pos += take as u64;
        }
        Ok(())
    }

    /// Free the chain from `start`, having first ended the chain at `new_end` if there is
    /// one: the end is written as a step of its own, so a chain never runs into a freed
    /// cluster.
    fn free_chain(&mut self, start: u32, new_end: Option<u32>) -> Result<(), Error> {
        if let Some(last) = new_end {
            self.table_step(&[(last, END_OF_CHAIN)])?;
        }
        let mut next = Some(start);
        let mut freed = 0u64;
        while let Some(first) = next {
            let mut batch = [(0u32, 0u16); STEP];
            let mut n = 0;
            let mut cluster = Some(first);
            while let Some(c) = cluster {
                if n == STEP {
                    break;
                }
                // Read the next link before anything is written, so the walk never follows a
                // freed entry.
                cluster = self.next_cluster(c)?;
                batch[n] = (c, 0);
                n += 1;
                freed += 1;
                if freed > u64::from(self.clusters) {
                    return Err(Error::Corrupt("a chain longer than the volume"));
                }
                self.free_hint = self.free_hint.min(c);
            }
            self.table_step(&batch[..n])?;
            next = cluster;
        }
        Ok(())
    }

    /// An entry of `dir` free to hold a new name, growing a subdirectory by a cluster when it
    /// has none. The root's region is fixed, and full is [`Error::Full`].
    fn free_entry(&mut self, dir: Dir) -> Result<u64, Error> {
        let mut index = 0usize;
        loop {
            match self.raw_entry(dir, index)? {
                Some((offset, bytes)) if bytes[0] == ENTRY_FREE || bytes[0] == ENTRY_DELETED => {
                    return Ok(offset);
                }
                Some(_) => index += 1,
                None => break,
            }
        }
        let Dir::Cluster(first) = dir else {
            return Err(Error::Full);
        };
        let (_, last) = self.chain_end(first)?;
        let mut fresh = [0u32; 1];
        if self.free_clusters(&mut fresh)? != 1 {
            return Err(Error::Full);
        }
        let cluster = fresh[0];
        self.zero_cluster(cluster)?;
        self.step();
        self.table_step(&[(cluster, END_OF_CHAIN)])?;
        self.table_step(&[(last, cluster as u16)])?;
        self.free_hint = cluster + 1;
        Ok(self.cluster_offset(cluster))
    }

    fn zero_cluster(&mut self, cluster: u32) -> Result<(), Error> {
        const ZEROS: [u8; 512] = [0; 512];
        let at = self.cluster_offset(cluster);
        let per = self.bytes_per_cluster();
        let mut done = 0u64;
        while done < per {
            let take = (per - done).min(ZEROS.len() as u64) as usize;
            self.write_at_device(at + done, &ZEROS[..take])?;
            done += take as u64;
        }
        Ok(())
    }

    /// Whether a directory names nothing but `.` and `..`.
    fn is_empty_dir(&mut self, entry: &[u8; ENTRY]) -> Result<bool, Error> {
        let dir = self.dir_of_entry(entry)?;
        Ok(self.nth_named(dir, 0)?.is_none())
    }

    // ---- consistency ----------------------------------------------------------------------

    /// Walk every directory and chain on the volume and check what a crash must never leave:
    /// no chain through a free or bad cluster, no cluster claimed twice (a cross-link or a
    /// loop), no file whose chain is shorter than its size, no directory without clusters.
    ///
    /// `seen` is a bitmap of at least [`clusters`](Self::clusters) + 2 bits the caller lends,
    /// so the check allocates nothing and runs in the kernel as well as on a host. What a
    /// crash may leave — lost clusters, table copies that differ — is counted, not refused:
    /// the caller decides whether a clean volume must have none.
    pub fn check_consistency(&mut self, seen: &mut [u8]) -> Result<Consistency, Error> {
        let bits = self.clusters as usize + 2;
        let seen = seen
            .get_mut(..bits.div_ceil(8))
            .ok_or(Error::Corrupt("a bitmap too small for the volume"))?;
        seen.fill(0);
        let mut report = Consistency::default();
        self.walk(Dir::Root, 0, seen, &mut report)?;
        for cluster in 2..self.clusters + 2 {
            let first = self.table_entry(0, cluster)?;
            let claimed = seen[cluster as usize / 8] & (1 << (cluster % 8)) != 0;
            if first != 0 && first != BAD_CLUSTER && !claimed {
                report.lost += 1;
            }
            for copy in 1..self.fats {
                if self.table_entry(copy, cluster)? != first {
                    report.fats_differ += 1;
                    break;
                }
            }
        }
        Ok(report)
    }

    fn walk(
        &mut self,
        dir: Dir,
        depth: usize,
        seen: &mut [u8],
        report: &mut Consistency,
    ) -> Result<(), Error> {
        if depth > MAX_DEPTH {
            return Err(Error::Corrupt("directories nested deeper than a walk will follow"));
        }
        let mut index = 0usize;
        while let Some((_, bytes)) = self.raw_entry(dir, index)? {
            index += 1;
            if !names_something(&bytes)? {
                if bytes[0] == ENTRY_FREE {
                    break;
                }
                continue;
            }
            let first = first_cluster(&bytes);
            match entry_kind(&bytes) {
                Kind::File => {
                    report.files += 1;
                    let size = u64::from(u32_at(&bytes, 28));
                    if first == 0 {
                        if size != 0 {
                            return Err(Error::Corrupt("a file with bytes but no clusters"));
                        }
                        continue;
                    }
                    let claimed = self.claim_chain(first, seen, report)?;
                    if claimed < size.div_ceil(self.bytes_per_cluster()) {
                        return Err(Error::Corrupt("a chain shorter than the file it holds"));
                    }
                }
                Kind::Dir => {
                    report.dirs += 1;
                    let Dir::Cluster(start) = self.dir_of_entry(&bytes)? else {
                        return Err(Error::Corrupt("a directory entry naming the root"));
                    };
                    self.claim_chain(start, seen, report)?;
                    self.walk(Dir::Cluster(start), depth + 1, seen, report)?;
                }
            }
        }
        Ok(())
    }

    /// Mark every cluster of the chain from `first` claimed. Returns its length.
    fn claim_chain(
        &mut self,
        first: u32,
        seen: &mut [u8],
        report: &mut Consistency,
    ) -> Result<u64, Error> {
        let mut cluster = first;
        let mut count = 0u64;
        loop {
            if !self.in_volume(cluster) {
                return Err(Error::Corrupt("a chain entry outside the volume"));
            }
            let value = self.table_entry(0, cluster)?;
            if value == 0 {
                return Err(Error::Corrupt("a chain through a free cluster"));
            }
            if value == BAD_CLUSTER {
                return Err(Error::Corrupt("a chain through a bad cluster"));
            }
            let bit = 1u8 << (cluster % 8);
            let byte = &mut seen[cluster as usize / 8];
            if *byte & bit != 0 {
                return Err(Error::Corrupt("a cluster claimed twice: a cross-link or a loop"));
            }
            *byte |= bit;
            count += 1;
            report.claimed += 1;
            if value >= CHAIN_END {
                return Ok(count);
            }
            cluster = u32::from(value);
        }
    }
}

/// The root, which has no directory entry of its own.
const ROOT: NodeId = 0;

/// How a directory is reached.
#[derive(Clone, Copy)]
enum Dir {
    Root,
    /// The first cluster of its chain.
    Cluster(u32),
}

/// Whether an entry names a file or directory a reader reports: not free, not deleted, not
/// the label, not a long-name piece, and not `.` or `..`.
///
/// `.` and `..` are entries on disk like any other. Skipping them keeps a directory's
/// indices dense, so a caller walking 0, 1, 2 sees every child once, and `lookup` cannot reach
/// a directory through its own name. A name of nothing but spaces is not a name either.
fn names_something(bytes: &[u8; ENTRY]) -> Result<bool, Error> {
    if bytes[0] == ENTRY_FREE || bytes[0] == ENTRY_DELETED {
        return Ok(false);
    }
    let attr = bytes[11];
    if attr & ATTR_LONG_NAME == ATTR_LONG_NAME || attr & ATTR_VOLUME_ID != 0 {
        return Ok(false);
    }
    let (name, len) = entry_name(bytes);
    Ok(!(len == 0 || &name[..len] == b"." || &name[..len] == b".."))
}

fn first_cluster(entry: &[u8; ENTRY]) -> u32 {
    // FAT16 keeps the low half only; the high half is zero on a FAT16 volume, and a
    // formatter that left something there would be describing a FAT32 cluster.
    u32::from(u16_at(entry, 26))
}

fn entry_kind(entry: &[u8; ENTRY]) -> Kind {
    if entry[11] & ATTR_DIRECTORY != 0 {
        Kind::Dir
    } else {
        Kind::File
    }
}

/// The name in an entry, as `NAME.EXT` without the padding spaces.
fn entry_name(entry: &[u8; ENTRY]) -> ([u8; NAME_BYTES], usize) {
    let mut out = [0u8; NAME_BYTES];
    let mut len = 0;
    for &c in &entry[0..8] {
        if c == b' ' {
            break;
        }
        out[len] = c;
        len += 1;
    }
    if entry[8] != b' ' {
        out[len] = b'.';
        len += 1;
        for &c in &entry[8..11] {
            if c == b' ' {
                break;
            }
            out[len] = c;
            len += 1;
        }
    }
    (out, len)
}

/// Whether a caller's name matches an entry's, ignoring case as FAT does.
fn name_matches(entry: &[u8; ENTRY], want: &[u8]) -> bool {
    let (name, len) = entry_name(entry);
    if len != want.len() {
        return false;
    }
    name[..len]
        .iter()
        .zip(want)
        .all(|(a, b)| a.eq_ignore_ascii_case(b))
}

/// `name` as the eleven bytes an entry stores, or [`Error::BadPath`] for anything that is not
/// a valid 8.3 name. Stored in upper case, which is how FAT keeps a short name.
pub fn short_name(name: &[u8]) -> Result<[u8; 11], Error> {
    let (base, ext) = match name.iter().position(|&b| b == b'.') {
        Some(dot) => (&name[..dot], &name[dot + 1..]),
        None => (name, &[][..]),
    };
    let dotted_but_empty = name.contains(&b'.') && ext.is_empty();
    if base.is_empty() || base.len() > 8 || ext.len() > 3 || dotted_but_empty {
        return Err(Error::BadPath);
    }
    let mut out = [b' '; 11];
    for (i, &c) in base.iter().enumerate() {
        out[i] = name_byte(c)?;
    }
    for (i, &c) in ext.iter().enumerate() {
        out[8 + i] = name_byte(c)?;
    }
    Ok(out)
}

fn name_byte(c: u8) -> Result<u8, Error> {
    if c.is_ascii_alphanumeric() || NAME_PUNCTUATION.contains(&c) {
        Ok(c.to_ascii_uppercase())
    } else {
        Err(Error::BadPath)
    }
}

/// A fresh directory entry.
fn new_entry(name: [u8; 11], attr: u8, cluster: u32, size: u32) -> [u8; ENTRY] {
    let mut e = [0u8; ENTRY];
    e[..11].copy_from_slice(&name);
    e[11] = attr;
    for at in [16, 18, 24] {
        e[at..at + 2].copy_from_slice(&FAT_EPOCH_DATE.to_le_bytes());
    }
    e[26..28].copy_from_slice(&(cluster as u16).to_le_bytes());
    e[28..32].copy_from_slice(&size.to_le_bytes());
    e
}

impl FileSystem for Fat16<'_, '_> {
    fn root(&self) -> NodeId {
        ROOT
    }

    fn lookup(&mut self, dir: NodeId, name: &[u8]) -> Result<NodeId, Error> {
        let dir = self.dir_of(dir)?;
        match self.find_entry(dir, name)? {
            Some((offset, _)) => Ok(offset + 1),
            None => Err(Error::NotFound),
        }
    }

    fn stat(&mut self, node: NodeId) -> Result<Stat, Error> {
        if node == ROOT {
            return Ok(Stat {
                kind: Kind::Dir,
                len: 0,
            });
        }
        let bytes = self.entry_bytes(node)?;
        let kind = entry_kind(&bytes);
        Ok(Stat {
            kind,
            len: match kind {
                Kind::File => u64::from(u32_at(&bytes, 28)),
                Kind::Dir => 0,
            },
        })
    }

    fn read_at(&mut self, node: NodeId, offset: u64, into: &mut [u8]) -> Result<usize, Error> {
        if node == ROOT {
            return Err(Error::IsADirectory);
        }
        let bytes = self.entry_bytes(node)?;
        if entry_kind(&bytes) != Kind::File {
            return Err(Error::IsADirectory);
        }
        let len = u64::from(u32_at(&bytes, 28));
        if offset >= len {
            return Ok(0);
        }
        let first = first_cluster(&bytes);
        if first == 0 {
            // An empty file has no chain. A non-empty one that claims none is corrupt.
            return Err(Error::Corrupt("a file with bytes but no clusters"));
        }
        let per_cluster = self.bytes_per_cluster();
        let want = (len - offset).min(into.len() as u64) as usize;
        let mut done = 0usize;
        while done < want {
            let pos = offset + done as u64;
            let Some(cluster) = self.nth_cluster(first, pos / per_cluster)? else {
                // The chain ended before the size in the directory entry said it would.
                return Err(Error::Corrupt("a chain shorter than the file it holds"));
            };
            let within = pos % per_cluster;
            let take = ((per_cluster - within) as usize).min(want - done);
            let at = self.cluster_offset(cluster) + within;
            self.read_at_device(at, &mut into[done..done + take])?;
            done += take;
        }
        Ok(done)
    }

    fn write_at(&mut self, node: NodeId, offset: u64, from: &[u8]) -> Result<usize, Error> {
        let entry = self.writable_file(node)?;
        if from.is_empty() {
            return Ok(0);
        }
        let end = offset
            .checked_add(from.len() as u64)
            .filter(|&e| e <= u64::from(u32::MAX))
            .ok_or(Error::Full)?;
        let _ = end;
        let len = u64::from(u32_at(&entry, 28));
        if offset > len {
            self.zero_fill(node, len, offset)?;
        }
        self.write_span(node, offset, from)?;
        Ok(from.len())
    }

    fn create(&mut self, dir: NodeId, name: &[u8], kind: Kind) -> Result<NodeId, Error> {
        let short = short_name(name)?;
        let parent = self.dir_of(dir)?;
        if self.find_entry(parent, name)?.is_some() {
            return Err(Error::Exists);
        }
        let slot = self.free_entry(parent)?;
        let entry = match kind {
            Kind::File => new_entry(short, ATTR_ARCHIVE, 0, 0),
            Kind::Dir => {
                let mut fresh = [0u32; 1];
                if self.free_clusters(&mut fresh)? != 1 {
                    return Err(Error::Full);
                }
                let cluster = fresh[0];
                // The directory's own cluster, with `.` and `..`, while the table still calls
                // it free; then the table; then the entry naming it.
                self.zero_cluster(cluster)?;
                let dot = new_entry(*b".          ", ATTR_DIRECTORY, cluster, 0);
                let up = match parent {
                    Dir::Root => 0,
                    Dir::Cluster(c) => c,
                };
                let dotdot = new_entry(*b"..         ", ATTR_DIRECTORY, up, 0);
                let at = self.cluster_offset(cluster);
                self.write_at_device(at, &dot)?;
                self.write_at_device(at + ENTRY as u64, &dotdot)?;
                self.step();
                self.table_step(&[(cluster, END_OF_CHAIN)])?;
                self.free_hint = cluster + 1;
                new_entry(short, ATTR_DIRECTORY, cluster, 0)
            }
        };
        self.write_at_device(slot, &entry)?;
        self.step();
        Ok(slot + 1)
    }

    fn truncate(&mut self, node: NodeId, len: u64) -> Result<(), Error> {
        let mut entry = self.writable_file(node)?;
        if len > u64::from(u32::MAX) {
            return Err(Error::Full);
        }
        let old = u64::from(u32_at(&entry, 28));
        if len >= old {
            return self.zero_fill(node, old, len);
        }
        let first = first_cluster(&entry);
        let keep = len.div_ceil(self.bytes_per_cluster());
        // The entry first, so it never names a cluster about to be freed.
        entry[28..32].copy_from_slice(&(len as u32).to_le_bytes());
        if keep == 0 {
            entry[26..28].copy_from_slice(&0u16.to_le_bytes());
        }
        self.write_at_device(node - 1, &entry)?;
        self.step();
        if first == 0 {
            return Ok(());
        }
        if keep == 0 {
            return self.free_chain(first, None);
        }
        let last = self
            .nth_cluster(first, keep - 1)?
            .ok_or(Error::Corrupt("a chain shorter than the file it holds"))?;
        match self.next_cluster(last)? {
            Some(rest) => self.free_chain(rest, Some(last)),
            None => Ok(()),
        }
    }

    fn unlink(&mut self, dir: NodeId, name: &[u8]) -> Result<(), Error> {
        let parent = self.dir_of(dir)?;
        let (offset, entry) = self.find_entry(parent, name)?.ok_or(Error::NotFound)?;
        if entry_kind(&entry) == Kind::Dir && !self.is_empty_dir(&entry)? {
            return Err(Error::NotEmpty);
        }
        // The entry first: once it is gone, its chain is lost clusters until it is freed.
        self.write_at_device(offset, &[ENTRY_DELETED])?;
        self.step();
        match first_cluster(&entry) {
            0 => Ok(()),
            first => self.free_chain(first, None),
        }
    }

    fn rename(&mut self, dir: NodeId, from: &[u8], to: &[u8]) -> Result<(), Error> {
        let short = short_name(to)?;
        let parent = self.dir_of(dir)?;
        let (offset, source) = self.find_entry(parent, from)?.ok_or(Error::NotFound)?;
        let mut replaced = None;
        if let Some((target_at, target)) = self.find_entry(parent, to)? {
            if target_at != offset {
                match (entry_kind(&source), entry_kind(&target)) {
                    (Kind::File, Kind::Dir) => return Err(Error::IsADirectory),
                    (Kind::Dir, Kind::File) => return Err(Error::NotADirectory),
                    (Kind::Dir, Kind::Dir) if !self.is_empty_dir(&target)? => {
                        return Err(Error::NotEmpty);
                    }
                    _ => {}
                }
                // The target's entry goes first: two entries never share a name, and its
                // chain is lost clusters until it is freed below.
                self.write_at_device(target_at, &[ENTRY_DELETED])?;
                self.step();
                replaced = Some(first_cluster(&target));
            }
        }
        self.write_at_device(offset, &short)?;
        self.step();
        match replaced {
            Some(first) if first != 0 => self.free_chain(first, None),
            _ => Ok(()),
        }
    }

    fn sync(&mut self) -> Result<(), Error> {
        self.cache
            .sync(self.dev)
            .map_err(|_| Error::Device("writing the volume back failed"))
    }

    fn readdir(&mut self, dir: NodeId, index: usize) -> Result<Option<Entry>, Error> {
        let dir = self.dir_of(dir)?;
        let Some((offset, bytes)) = self.nth_named(dir, index)? else {
            return Ok(None);
        };
        let (name, len) = entry_name(&bytes);
        Entry::new(&name[..len], offset + 1, entry_kind(&bytes)).map(Some)
    }
}

/// Whether an entry is marked read-only, which a write through this driver refuses.
pub fn is_read_only(entry: &[u8; ENTRY]) -> bool {
    entry[11] & ATTR_READ_ONLY != 0
}

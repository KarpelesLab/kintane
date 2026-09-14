//! FAT16 and FAT32, read and written.
//!
//! The first filesystem the kernel reads from a disk it did not write, and now writes to.
//! FAT rather than a format of our own for one reason: it is already in this tree twice.
//! kbuild writes FAT volumes for the EFI system partition and for the test disk, and
//! `kinboot-efi` reads one to find the kernel. A third format would be a third thing to get
//! right, with no third reader to check it against — and kbuild's reader is exactly what
//! checks, after a run, that what the kernel wrote is a volume.
//!
//! # What is implemented, and what is refused
//!
//! * **FAT16 and FAT32.** The cluster count decides which, as the specification says — not the
//!   `FAT16` or `FAT32` string in the boot sector, which is advisory and which real formatters get
//!   wrong. A volume whose count falls in FAT12's range is refused by name rather than read as if
//!   its table were 12 bits wide. The two formats differ in three places and nowhere else: a table
//!   entry is 16 or 28 bits, the root is a fixed region or a cluster chain, and FAT32 keeps a free
//!   count in an FSInfo sector ([`Format`]).
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
//! FAT32's FSInfo sector is a hint the specification allows to be stale, and this driver does
//! not let it be: the free count is kept as the table changes and written at
//! [`sync`](FileSystem::sync), and [`check_consistency`](Fat::check_consistency) reports both
//! what the sector says and what the table holds, so a caller can require the two to agree.
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
//! `start` is its first block, which is what lets the test disk carry a pattern region, two
//! volumes and a scratch area on one device with one driver.

#![cfg_attr(not(test), no_std)]
#![deny(unsafe_code)]

#[cfg(test)]
mod fat32_tests;
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
/// The cluster counts that decide a volume's format, as the specification defines them.
const MIN_CLUSTERS: u32 = 4085;
const FAT32_CLUSTERS: u32 = 65525;
/// The most clusters FAT32 addresses: the entry is 28 bits, and the top values end a chain.
const MAX_CLUSTERS: u32 = 0x0FFF_FFF5;
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
/// FSInfo's two signatures and the sector's trailing one, and where each sits.
const FSINFO_LEAD: u32 = 0x4161_5252;
const FSINFO_STRUCT: u32 = 0x6141_7272;
const FSINFO_TRAIL: u32 = 0xAA55_0000;
const FSINFO_FREE_AT: usize = 488;
const FSINFO_NEXT_AT: usize = 492;
/// What FSInfo holds when it knows neither count.
const FSINFO_UNKNOWN: u32 = 0xFFFF_FFFF;

fn u16_at(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}

fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

/// Which of the two formats a volume is, and everything that follows from it.
///
/// The cluster count alone decides this at mount; nothing below asks the boot sector's
/// advisory string.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Format {
    Fat16,
    Fat32,
}

impl Format {
    /// Bytes one table entry takes.
    fn entry_bytes(self) -> u64 {
        match self {
            Format::Fat16 => 2,
            Format::Fat32 => 4,
        }
    }

    /// The bits of an entry that are the cluster number. FAT32 keeps the top four for
    /// itself, and a driver that writes them would be writing to a field that is not its.
    fn mask(self) -> u32 {
        match self {
            Format::Fat16 => 0xFFFF,
            Format::Fat32 => 0x0FFF_FFFF,
        }
    }

    /// Values at or above this end a chain.
    fn chain_end(self) -> u32 {
        match self {
            Format::Fat16 => 0xFFF8,
            Format::Fat32 => 0x0FFF_FFF8,
        }
    }

    /// What this driver writes to end a chain.
    fn end_of_chain(self) -> u32 {
        match self {
            Format::Fat16 => 0xFFFF,
            Format::Fat32 => 0x0FFF_FFFF,
        }
    }

    /// A cluster marked bad, which no chain may run through.
    fn bad(self) -> u32 {
        match self {
            Format::Fat16 => 0xFFF7,
            Format::Fat32 => 0x0FFF_FFF7,
        }
    }
}

/// What [`Fat::check_consistency`] found on a volume it did not call corrupt.
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
    /// Clusters the table calls free, counted during the walk.
    pub free: u32,
    /// What FAT32's FSInfo sector says is free, if there is one and it claims to know.
    /// A caller that has just synced may require this to be `Some(free)`.
    pub fsinfo_free: Option<u32>,
}

/// What a volume is, as [`Fat::statfs`] reports it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct StatFs {
    pub format: Format,
    /// Bytes in one cluster: the unit everything below a file's size is allocated in.
    pub cluster_bytes: u64,
    /// Clusters the volume has, and how many of them are free.
    pub clusters: u32,
    pub free: u32,
}

/// A mounted FAT volume.
///
/// Owns its cache: the cache is only ever reached through the filesystem, and a filesystem
/// that borrowed one would make every caller thread two lifetimes through its own types
/// for no benefit.
pub struct Fat<'s, 'd> {
    dev: &'d dyn BlockDevice,
    cache: Cache<'s>,
    format: Format,
    sector: usize,
    cluster_sectors: u64,
    /// Absolute block of the first file allocation table. Every other position the driver
    /// needs is absolute too, computed once at mount from the volume's own start, so
    /// nothing below has to remember to add it.
    fat_start: u64,
    /// Copies of the table, and sectors in each.
    fats: u64,
    fat_sectors: u64,
    /// Where the root lives: a region of its own on FAT16, a chain like any other on FAT32.
    root: Root,
    /// Absolute block the data region starts at, where cluster 2 lives.
    data_start: u64,
    clusters: u32,
    /// Where the next search for a free cluster starts.
    free_hint: u32,
    /// Clusters the table calls free, counted at mount and kept as the table changes.
    free_count: u32,
    /// FAT32's FSInfo sector, absolute, and whether what it holds is behind
    /// [`free_count`](Self::free_count).
    fsinfo: Option<u64>,
    fsinfo_stale: bool,
}

/// Where a volume's root directory is.
#[derive(Clone, Copy)]
enum Root {
    /// FAT16: a region of `entries` entries at an absolute block of its own.
    Region { start: u64, entries: usize },
    /// FAT32: the first cluster of a chain, which grows like any directory's.
    Cluster(u32),
}

impl<'s, 'd> Fat<'s, 'd> {
    /// Read the volume starting at block `start` of `dev` and check its geometry.
    ///
    /// The cache's block size must be the device's, since everything below is counted in
    /// the volume's own sectors and the two must be the same unit.
    pub fn mount(
        dev: &'d dyn BlockDevice,
        mut cache: Cache<'s>,
        start: u64,
    ) -> Result<Fat<'s, 'd>, Error> {
        let geometry = dev.geometry();
        if cache.block_size() != geometry.block_size {
            return Err(Error::Corrupt("the cache's block size is not the device's"));
        }
        let sector = geometry.block_size;
        if sector < 512 {
            return Err(Error::Corrupt("a block too small to hold a boot sector"));
        }
        let mut boot = [0u8; 512];
        cache
            .read_blocks(dev, start, &mut boot)
            .map_err(|_| Error::Device("the volume's first block could not be read"))?;

        if u16_at(&boot, 510) != 0xAA55 {
            return Err(Error::Corrupt("no boot-sector signature"));
        }
        let bytes_per_sector = u16_at(&boot, 11) as usize;
        if bytes_per_sector != sector {
            return Err(Error::Corrupt("the volume's sector size is not the device's"));
        }
        let cluster_sectors = u64::from(boot[13]);
        if cluster_sectors == 0 || !cluster_sectors.is_power_of_two() || cluster_sectors > 128 {
            return Err(Error::Corrupt("sectors per cluster"));
        }
        let reserved = u64::from(u16_at(&boot, 14));
        if reserved == 0 {
            return Err(Error::Corrupt("reserved sectors"));
        }
        let fats = u64::from(boot[16]);
        if fats == 0 || fats > 4 {
            return Err(Error::Corrupt("file allocation table count"));
        }
        let root_entries = u16_at(&boot, 17) as usize;
        // A table of zero 16-bit sectors means the 32-bit field holds the size, which is
        // what a FAT32 volume looks like before its cluster count is known.
        let fat_sectors = match u64::from(u16_at(&boot, 22)) {
            0 => u64::from(u32_at(&boot, 36)),
            small => small,
        };
        if fat_sectors == 0 {
            return Err(Error::Corrupt("sectors per file allocation table"));
        }
        let total = match u16_at(&boot, 19) {
            0 => u64::from(u32_at(&boot, 32)),
            small => u64::from(small),
        };
        if (root_entries * ENTRY) % sector != 0 {
            return Err(Error::Corrupt("root directory entries"));
        }
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
        // The specification decides the width of a table entry by this count alone.
        if clusters < MIN_CLUSTERS {
            return Err(Error::Corrupt(
                "not a FAT volume this reads: the cluster count is FAT12's",
            ));
        }
        if clusters > MAX_CLUSTERS {
            return Err(Error::Corrupt("more clusters than a table entry can name"));
        }
        let format = if clusters < FAT32_CLUSTERS {
            Format::Fat16
        } else {
            Format::Fat32
        };
        // Every entry of the table must be inside it, or a chain could read the root
        // directory, or the data region, as if it were table entries.
        if u64::from(clusters + 2) * format.entry_bytes() > fat_sectors * sector as u64 {
            return Err(Error::Corrupt("a table too small for its own clusters"));
        }

        let data_start = start + overhead;
        let root = match format {
            Format::Fat16 => {
                if root_entries == 0 {
                    return Err(Error::Corrupt("a FAT16 volume with no root directory"));
                }
                Root::Region {
                    start: start + reserved + fats * fat_sectors,
                    entries: root_entries,
                }
            }
            Format::Fat32 => {
                if root_entries != 0 {
                    return Err(Error::Corrupt("a FAT32 volume with a fixed root directory"));
                }
                let first = u32_at(&boot, 44) & Format::Fat32.mask();
                if first < 2 || first >= clusters + 2 {
                    return Err(Error::Corrupt("a root directory outside the volume"));
                }
                Root::Cluster(first)
            }
        };
        // FSInfo's sector number is the boot sector's, and the sector must be inside the
        // reserved region: one outside it would be a table sector or a file's.
        let fsinfo = match format {
            Format::Fat16 => None,
            Format::Fat32 => {
                let at = u64::from(u16_at(&boot, 48));
                if at == 0 || at >= reserved {
                    return Err(Error::Corrupt("an FSInfo sector outside the reserved region"));
                }
                Some(start + at)
            }
        };

        let mut fat = Fat {
            dev,
            cache,
            format,
            sector,
            cluster_sectors,
            fat_start: start + reserved,
            fats,
            fat_sectors,
            root,
            data_start,
            clusters,
            free_hint: 2,
            free_count: 0,
            fsinfo,
            fsinfo_stale: false,
        };
        // The free count is this driver's own, counted from the table rather than taken
        // from a hint a crash may have left behind. FSInfo's value is only ever compared
        // with it, by the consistency walk.
        fat.free_count = fat.count_free()?;
        fat.check_fsinfo()?;
        // A count a crash left behind is not this driver's, and the next sync replaces it.
        fat.fsinfo_stale = fat.fsinfo_free()? != Some(fat.free_count);
        Ok(fat)
    }

    /// The FSInfo sector's signatures, checked at mount so a volume whose reserved region
    /// holds something else is refused rather than written over at the first sync.
    fn check_fsinfo(&mut self) -> Result<(), Error> {
        let Some(at) = self.fsinfo else {
            return Ok(());
        };
        let mut bytes = [0u8; 512];
        self.read_at_device(at * self.sector as u64, &mut bytes)?;
        if u32_at(&bytes, 0) != FSINFO_LEAD
            || u32_at(&bytes, 484) != FSINFO_STRUCT
            || u32_at(&bytes, 508) != FSINFO_TRAIL
        {
            return Err(Error::Corrupt("an FSInfo sector without its signatures"));
        }
        Ok(())
    }

    /// What the FSInfo sector says is free, if it says.
    fn fsinfo_free(&mut self) -> Result<Option<u32>, Error> {
        let Some(at) = self.fsinfo else {
            return Ok(None);
        };
        let mut bytes = [0u8; 4];
        self.read_at_device(at * self.sector as u64 + FSINFO_FREE_AT as u64, &mut bytes)?;
        let free = u32::from_le_bytes(bytes);
        Ok((free != FSINFO_UNKNOWN).then_some(free))
    }

    /// Write the free count and the search hint to FSInfo. A step of its own at
    /// [`sync`](FileSystem::sync): the sector is a hint, so nothing else waits for it, but a
    /// volume this driver synced has one that agrees with its table.
    fn write_fsinfo(&mut self) -> Result<(), Error> {
        let Some(at) = self.fsinfo else {
            return Ok(());
        };
        if !self.fsinfo_stale {
            return Ok(());
        }
        let base = at * self.sector as u64;
        self.write_at_device(base + FSINFO_FREE_AT as u64, &self.free_count.to_le_bytes())?;
        self.write_at_device(base + FSINFO_NEXT_AT as u64, &self.free_hint.to_le_bytes())?;
        self.step();
        self.fsinfo_stale = false;
        Ok(())
    }

    /// Clusters the table calls free, counted from the table itself.
    fn count_free(&mut self) -> Result<u32, Error> {
        let mut free = 0;
        for cluster in 2..self.clusters + 2 {
            if self.table_entry(0, cluster)? == 0 {
                free += 1;
            }
        }
        Ok(free)
    }

    /// Which format the volume is.
    pub fn format(&self) -> Format {
        self.format
    }

    /// What the volume is and how much of it is free.
    pub fn statfs(&self) -> StatFs {
        StatFs {
            format: self.format,
            cluster_bytes: self.bytes_per_cluster(),
            clusters: self.clusters,
            free: self.free_count,
        }
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

    /// Where table copy `copy`'s entry for `cluster` sits on the device.
    fn table_at(&self, copy: u64, cluster: u32) -> u64 {
        (self.fat_start + copy * self.fat_sectors) * self.sector as u64
            + u64::from(cluster) * self.format.entry_bytes()
    }

    /// Table copy `copy`'s entry for `cluster`, unchecked beyond its position.
    fn table_entry(&mut self, copy: u64, cluster: u32) -> Result<u32, Error> {
        let at = self.table_at(copy, cluster);
        match self.format {
            Format::Fat16 => {
                let mut bytes = [0u8; 2];
                self.read_at_device(at, &mut bytes)?;
                Ok(u32::from(u16::from_le_bytes(bytes)))
            }
            Format::Fat32 => {
                let mut bytes = [0u8; 4];
                self.read_at_device(at, &mut bytes)?;
                Ok(u32::from_le_bytes(bytes) & Format::Fat32.mask())
            }
        }
    }

    /// Write `changes` to every table copy, the first copy's as one step and each later
    /// copy's as the next.
    ///
    /// The free count follows the first copy: an entry that goes from free to taken, or
    /// back, is the only thing that changes it, and this is the only place entries change.
    fn table_step(&mut self, changes: &[(u32, u32)]) -> Result<(), Error> {
        for copy in 0..self.fats {
            for &(cluster, value) in changes {
                if !self.in_volume(cluster) {
                    return Err(Error::Corrupt("a table change outside the volume"));
                }
                if value & !self.format.mask() != 0 {
                    return Err(Error::Corrupt("a table value wider than an entry"));
                }
                let was = self.table_entry(copy, cluster)?;
                if copy == 0 {
                    match (was == 0, value == 0) {
                        (false, true) => {
                            self.free_count += 1;
                            self.fsinfo_stale = true;
                        }
                        (true, false) => {
                            self.free_count = self.free_count.saturating_sub(1);
                            self.fsinfo_stale = true;
                        }
                        _ => {}
                    }
                }
                let at = self.table_at(copy, cluster);
                match self.format {
                    Format::Fat16 => self.write_at_device(at, &(value as u16).to_le_bytes())?,
                    Format::Fat32 => {
                        // The top four bits are not this driver's: a volume's own flags live
                        // there, and a write that cleared them would be writing another
                        // field.
                        let mut whole = [0u8; 4];
                        self.read_at_device(at, &mut whole)?;
                        let kept = u32::from_le_bytes(whole) & !Format::Fat32.mask();
                        self.write_at_device(at, &(kept | value).to_le_bytes())?;
                    }
                }
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
        if next >= self.format.chain_end() {
            return Ok(None);
        }
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
        Ok(want <= u64::from(self.free_count))
    }

    /// Where the `index`th raw entry of a directory lives on the device, or `None` past
    /// the end of the directory.
    ///
    /// FAT16's root has a region of its own, of a fixed number of entries. Every other
    /// directory, FAT32's root included, is a chain of clusters like a file's.
    fn entry_offset(&mut self, dir: Dir, index: usize) -> Result<Option<u64>, Error> {
        match self.resolve(dir) {
            Place::Region { start, entries } => {
                if index >= entries {
                    return Ok(None);
                }
                Ok(Some(start * self.sector as u64 + (index * ENTRY) as u64))
            }
            Place::Cluster(first) => {
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

    /// Where a directory's entries are, with the root resolved to whichever shape this
    /// volume's format gives it.
    fn resolve(&self, dir: Dir) -> Place {
        match dir {
            Dir::Root => match self.root {
                Root::Region { start, entries } => Place::Region { start, entries },
                Root::Cluster(first) => Place::Cluster(first),
            },
            Dir::Cluster(first) => Place::Cluster(first),
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
        match self.first_cluster(bytes) {
            // A directory with no chain has no entries: `.` and `..` are entries like any
            // other, so a real one always has at least one cluster. `..` one below the root
            // names cluster 0, and never reaches here: a reader skips it, so nothing looks
            // a directory up through it.
            0 => Err(Error::Corrupt("a directory with no clusters")),
            c if !self.in_volume(c) => {
                Err(Error::Corrupt("a directory starting outside the volume"))
            }
            c => Ok(Dir::Cluster(c)),
        }
    }

    /// The first cluster an entry names.
    ///
    /// FAT16 keeps the low half only, and the high half is zero on such a volume: a
    /// formatter that left something there would be describing a FAT32 cluster, so it is
    /// ignored rather than believed.
    fn first_cluster(&self, entry: &[u8; ENTRY]) -> u32 {
        let low = u32::from(u16_at(entry, 26));
        match self.format {
            Format::Fat16 => low,
            Format::Fat32 => (u32::from(u16_at(entry, 20)) << 16) | low,
        }
    }

    /// Put `cluster` in `entry`, in whichever halves this format keeps it.
    fn set_first_cluster(&self, entry: &mut [u8; ENTRY], cluster: u32) {
        entry[26..28].copy_from_slice(&(cluster as u16).to_le_bytes());
        if self.format == Format::Fat32 {
            entry[20..22].copy_from_slice(&((cluster >> 16) as u16).to_le_bytes());
        }
    }

    /// A fresh directory entry, with its first cluster where this format keeps it.
    fn new_entry(&self, name: [u8; 11], attr: u8, cluster: u32, size: u32) -> [u8; ENTRY] {
        let mut e = [0u8; ENTRY];
        e[..11].copy_from_slice(&name);
        e[11] = attr;
        for at in [16, 18, 24] {
            e[at..at + 2].copy_from_slice(&FAT_EPOCH_DATE.to_le_bytes());
        }
        self.set_first_cluster(&mut e, cluster);
        e[28..32].copy_from_slice(&size.to_le_bytes());
        e
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
        let first = self.first_cluster(&entry);
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
        let end_of_chain = self.format.end_of_chain();
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
            let mut chain = [(0u32, 0u32); STEP];
            for i in 0..want {
                let value = if i + 1 < want {
                    fresh[i + 1]
                } else {
                    end_of_chain
                };
                chain[i] = (fresh[i], value);
            }
            self.table_step(&chain[..want])?;
            match tail {
                Some(last) => self.table_step(&[(last, fresh[0])])?,
                None => new_first = Some(fresh[0]),
            }
            tail = Some(fresh[want - 1]);
            self.free_hint = fresh[want - 1] + 1;
            placed += want as u64;
        }

        // The entry last: its first cluster if it had none, and its size.
        if end > len || new_first.is_some() {
            if let Some(f) = new_first {
                self.set_first_cluster(&mut entry, f);
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
            let end_of_chain = self.format.end_of_chain();
            self.table_step(&[(last, end_of_chain)])?;
        }
        let mut next = Some(start);
        let mut freed = 0u64;
        while let Some(first) = next {
            let mut batch = [(0u32, 0u32); STEP];
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

    /// An entry of `dir` free to hold a new name, growing the directory by a cluster when
    /// every entry is taken. FAT16's root region is fixed, and full is [`Error::Full`];
    /// FAT32's root is a chain and grows like any other directory.
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
        let Place::Cluster(first) = self.resolve(dir) else {
            return Err(Error::Full);
        };
        let (_, last) = self.chain_end(first)?;
        let mut fresh = [0u32; 1];
        if self.free_clusters(&mut fresh)? != 1 {
            return Err(Error::Full);
        }
        let cluster = fresh[0];
        let end_of_chain = self.format.end_of_chain();
        self.zero_cluster(cluster)?;
        self.step();
        self.table_step(&[(cluster, end_of_chain)])?;
        self.table_step(&[(last, cluster)])?;
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
    /// crash may leave — lost clusters, table copies that differ, an FSInfo count behind the
    /// table — is counted, not refused: the caller decides whether a clean volume must have
    /// none.
    pub fn check_consistency(&mut self, seen: &mut [u8]) -> Result<Consistency, Error> {
        let bits = self.clusters as usize + 2;
        let seen = seen
            .get_mut(..bits.div_ceil(8))
            .ok_or(Error::Corrupt("a bitmap too small for the volume"))?;
        seen.fill(0);
        let mut report = Consistency::default();
        // FAT32's root is a chain, and its clusters are claimed like any other directory's.
        if let Root::Cluster(first) = self.root {
            self.claim_chain(first, seen, &mut report)?;
        }
        self.walk(Dir::Root, 0, seen, &mut report)?;
        for cluster in 2..self.clusters + 2 {
            let first = self.table_entry(0, cluster)?;
            let claimed = seen[cluster as usize / 8] & (1 << (cluster % 8)) != 0;
            if first == 0 {
                report.free += 1;
            } else if first != self.format.bad() && !claimed {
                report.lost += 1;
            }
            for copy in 1..self.fats {
                if self.table_entry(copy, cluster)? != first {
                    report.fats_differ += 1;
                    break;
                }
            }
        }
        report.fsinfo_free = self.fsinfo_free()?;
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
            let first = self.first_cluster(&bytes);
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
            if value == self.format.bad() {
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
            if value >= self.format.chain_end() {
                return Ok(count);
            }
            cluster = value;
        }
    }
}

/// The root, which has no directory entry of its own.
const ROOT: NodeId = 0;

/// How a directory is reached, as a caller names it.
#[derive(Clone, Copy)]
enum Dir {
    Root,
    /// The first cluster of its chain.
    Cluster(u32),
}

/// Where a directory's entries are, once the root is resolved for this volume's format.
#[derive(Clone, Copy)]
enum Place {
    /// A region of `entries` entries at an absolute block: FAT16's root, and nothing else.
    Region { start: u64, entries: usize },
    /// The first cluster of a chain.
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

impl FileSystem for Fat<'_, '_> {
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
        let first = self.first_cluster(&bytes);
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
        offset
            .checked_add(from.len() as u64)
            .filter(|&e| e <= u64::from(u32::MAX))
            .ok_or(Error::Full)?;
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
            Kind::File => self.new_entry(short, ATTR_ARCHIVE, 0, 0),
            Kind::Dir => {
                let mut fresh = [0u32; 1];
                if self.free_clusters(&mut fresh)? != 1 {
                    return Err(Error::Full);
                }
                let cluster = fresh[0];
                // The directory's own cluster, with `.` and `..`, while the table still calls
                // it free; then the table; then the entry naming it.
                self.zero_cluster(cluster)?;
                let dot = self.new_entry(*b".          ", ATTR_DIRECTORY, cluster, 0);
                // `..` names the root as cluster 0 on both formats, whatever cluster FAT32's
                // root actually starts at: that is what every other reader writes there.
                let up = match parent {
                    Dir::Root => 0,
                    Dir::Cluster(c) => c,
                };
                let dotdot = self.new_entry(*b"..         ", ATTR_DIRECTORY, up, 0);
                let at = self.cluster_offset(cluster);
                self.write_at_device(at, &dot)?;
                self.write_at_device(at + ENTRY as u64, &dotdot)?;
                self.step();
                let end_of_chain = self.format.end_of_chain();
                self.table_step(&[(cluster, end_of_chain)])?;
                self.free_hint = cluster + 1;
                self.new_entry(short, ATTR_DIRECTORY, cluster, 0)
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
        let first = self.first_cluster(&entry);
        let keep = len.div_ceil(self.bytes_per_cluster());
        // The entry first, so it never names a cluster about to be freed.
        entry[28..32].copy_from_slice(&(len as u32).to_le_bytes());
        if keep == 0 {
            self.set_first_cluster(&mut entry, 0);
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
        match self.first_cluster(&entry) {
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
                replaced = Some(self.first_cluster(&target));
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
        // FSInfo before the flush, so a volume that synced has a free count that agrees
        // with its table rather than the hint a crash left.
        self.write_fsinfo()?;
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

//! FAT16, read-only.
//!
//! The first filesystem the kernel reads from a disk it did not write. FAT rather than a
//! format of our own for one reason: it is already in this tree twice. kbuild writes a
//! FAT16 volume for the EFI system partition, and `kinboot-efi` reads one to find the
//! kernel. A third format would be a third thing to get right, with no third reader to
//! check it against.
//!
//! # What is implemented, and what is refused
//!
//! * **FAT16 only.** The cluster count decides the type, as the specification says — not the
//!   `FAT16` string in the boot sector, which is advisory and which real formatters get wrong. A
//!   volume outside FAT16's cluster range is refused by name rather than read as if the table were
//!   12 or 32 bits wide.
//! * **8.3 names.** Long-name entries are skipped, so a file with one is reachable by its short
//!   name. kbuild writes only short names.
//! * **Read-only.** Writing is [`vfs::Error::ReadOnly`]. What a writable FAT needs — a free-cluster
//!   search, two tables kept in step, a directory entry rewritten on every size change — is worth
//!   doing when something writes files, not before.
//! * **Every field is checked before it is used.** A cluster number outside the table, a chain
//!   longer than the volume has clusters, a directory entry past the end of its region: each is
//!   [`vfs::Error::Corrupt`] with the field named. The bytes come from a disk, and a disk is not
//!   trusted.
//!
//! # Where the bytes come from
//!
//! Every read goes through [`bcache::Cache`], so walking a chain reads the table's sector
//! once rather than once per cluster. The volume may sit anywhere on the device: `start`
//! is its first block, which is what lets the test disk carry a pattern region, a volume
//! and a scratch area on one device with one driver.

#![cfg_attr(not(test), no_std)]
#![deny(unsafe_code)]

#[cfg(test)]
mod tests;

use bcache::Cache;
use block::BlockDevice;
use vfs::{Entry, Error, FileSystem, Kind, NodeId, Stat};

/// Bytes of one directory entry.
const ENTRY: usize = 32;
/// The attribute byte's bits this reader acts on.
const ATTR_READ_ONLY: u8 = 0x01;
const ATTR_VOLUME_ID: u8 = 0x08;
const ATTR_DIRECTORY: u8 = 0x10;
/// A long-name entry: every attribute bit below the directory bit set at once.
const ATTR_LONG_NAME: u8 = 0x0F;
/// The first byte of an entry that has never been used; nothing follows it.
const ENTRY_FREE: u8 = 0x00;
/// The first byte of a deleted entry, which is skipped.
const ENTRY_DELETED: u8 = 0xE5;
/// Cluster values at or above this end a chain.
const CHAIN_END: u16 = 0xFFF8;
/// FAT16 is defined by its cluster count, not by any string in the volume.
const MIN_CLUSTERS: u32 = 4085;
const MAX_CLUSTERS: u32 = 65525;
/// The longest name this reader reports: eight, a dot, three.
const NAME_BYTES: usize = 12;

fn u16_at(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}

fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
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
    /// Absolute block of the first file allocation table. Every other position the reader
    /// needs is absolute too, computed once at mount from the volume's own start, so
    /// nothing below has to remember to add it.
    fat_start: u64,
    /// Absolute block of the root directory's own region.
    root_start: u64,
    root_entries: usize,
    /// Absolute block the data region starts at, where cluster 2 lives.
    data_start: u64,
    clusters: u32,
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
            root_start: start + reserved + fats * fat_sectors,
            root_entries,
            data_start: start + overhead,
            clusters,
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

    /// Forget every cached block: what a caller does after writing behind the filesystem's
    /// back, and what the boot check uses to prove a read really reached the device.
    pub fn invalidate_cache(&mut self) {
        self.cache.invalidate_all();
    }

    fn bytes_per_cluster(&self) -> u64 {
        self.cluster_sectors * self.sector as u64
    }

    fn read_at_device(&mut self, offset: u64, into: &mut [u8]) -> Result<(), Error> {
        self.cache
            .read_at(self.dev, offset, into)
            .map_err(|_| Error::Device("a read of the volume failed"))
    }

    /// The entry after `cluster` in its chain, or `None` at the end.
    fn next_cluster(&mut self, cluster: u32) -> Result<Option<u32>, Error> {
        if cluster < 2 || cluster >= self.clusters + 2 {
            return Err(Error::Corrupt("a cluster number outside the volume"));
        }
        let at = self.fat_start * self.sector as u64 + u64::from(cluster) * 2;
        let mut bytes = [0u8; 2];
        self.read_at_device(at, &mut bytes)?;
        let next = u16::from_le_bytes(bytes);
        if next >= CHAIN_END {
            return Ok(None);
        }
        let next = u32::from(next);
        if next < 2 || next >= self.clusters + 2 {
            return Err(Error::Corrupt("a chain entry outside the volume"));
        }
        Ok(Some(next))
    }

    /// Walk `skip` clusters along the chain from `first`.
    ///
    /// Bounded by the volume's cluster count: a chain that loops would otherwise walk for
    /// ever, and a corrupt table is exactly where a loop comes from.
    fn nth_cluster(&mut self, first: u32, skip: u64) -> Result<Option<u32>, Error> {
        let mut cluster = first;
        for _ in 0..skip {
            match self.next_cluster(cluster)? {
                Some(next) => cluster = next,
                None => return Ok(None),
            }
        }
        Ok(Some(cluster))
    }

    fn cluster_offset(&self, cluster: u32) -> u64 {
        (self.data_start + u64::from(cluster - 2) * self.cluster_sectors) * self.sector as u64
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
            match bytes[0] {
                ENTRY_FREE => return Ok(None),
                ENTRY_DELETED => continue,
                _ => {}
            }
            let attr = bytes[11];
            if attr & ATTR_LONG_NAME == ATTR_LONG_NAME || attr & ATTR_VOLUME_ID != 0 {
                continue;
            }
            // `.` and `..` are entries on disk like any other. Skipping them here rather
            // than in `readdir` keeps the indices dense: a caller walking 0, 1, 2 sees
            // every child once, and `lookup` cannot reach a directory through its own
            // name. A name of nothing but spaces is not a name, and belongs to a volume
            // whose entries are not what they claim; it is skipped for the same reason.
            let (name, len) = entry_name(&bytes);
            if len == 0 || &name[..len] == b"." || &name[..len] == b".." {
                continue;
            }
            if seen == n {
                return Ok(Some((offset, bytes)));
            }
            seen += 1;
        }
    }

    /// A directory's identity as this reader walks it.
    fn dir_of(&mut self, node: NodeId) -> Result<Dir, Error> {
        if node == ROOT {
            return Ok(Dir::Root);
        }
        let bytes = self.entry_bytes(node)?;
        if bytes[11] & ATTR_DIRECTORY == 0 {
            return Err(Error::NotADirectory);
        }
        match first_cluster(&bytes) {
            // A directory with no chain has no entries: `.` and `..` are entries like any
            // other, so a real one always has at least one cluster.
            0 => Err(Error::Corrupt("a directory with no clusters")),
            c if c < 2 || c >= self.clusters + 2 => {
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

impl FileSystem for Fat16<'_, '_> {
    fn root(&self) -> NodeId {
        ROOT
    }

    fn lookup(&mut self, dir: NodeId, name: &[u8]) -> Result<NodeId, Error> {
        let dir = self.dir_of(dir)?;
        let mut n = 0usize;
        while let Some((offset, bytes)) = self.nth_named(dir, n)? {
            if name_matches(&bytes, name) {
                return Ok(offset + 1);
            }
            n += 1;
        }
        Err(Error::NotFound)
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

    fn readdir(&mut self, dir: NodeId, index: usize) -> Result<Option<Entry>, Error> {
        let dir = self.dir_of(dir)?;
        let Some((offset, bytes)) = self.nth_named(dir, index)? else {
            return Ok(None);
        };
        let (name, len) = entry_name(&bytes);
        Entry::new(&name[..len], offset + 1, entry_kind(&bytes)).map(Some)
    }
}

/// Whether an entry is marked read-only. Nothing here writes, so this is reported rather
/// than enforced; a writable FAT would refuse a write to one.
pub fn is_read_only(entry: &[u8; ENTRY]) -> bool {
    entry[11] & ATTR_READ_ONLY != 0
}

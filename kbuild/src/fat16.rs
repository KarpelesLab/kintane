//! FAT16 volumes, written from scratch.
//!
//! Two images in the tree carry one: the EFI system partition, which firmware reads, and
//! the test disk, whose volume the kernel's own FAT reader mounts. They differ only in
//! shape — size, cluster size, what sits before them on the disk — so the writer is one
//! function over [`Params`] rather than two copies that drift apart.
//!
//! Producing a volume usually means `mkfs.fat` and `mtools`, which are not part of the
//! pinned toolchain and would make a release depend on whatever versions the build machine
//! has. The subset needed is small:
//!
//! - FAT16 only, with the cluster count inside FAT16's range at both ends, since that count and
//!   nothing else is what makes a volume FAT16;
//! - 8.3 names only, and no long-name entries;
//! - files and directories written once and never modified.
//!
//! Every volume is **reproducible**. Timestamps are the FAT epoch (1980-01-01, the earliest
//! it can represent), the volume serial number is a parameter rather than a clock, and
//! directory entries are written in name order, so the same inputs give the same bytes on
//! any machine.

use std::collections::BTreeMap;

pub const SECTOR: usize = 512;
const ENTRY: usize = 32;

const ATTR_VOLUME_ID: u8 = 0x08;
const ATTR_DIRECTORY: u8 = 0x10;
const ATTR_ARCHIVE: u8 = 0x20;
/// 1980-01-01, as a FAT date: day 1, month 1, year 0 of the FAT epoch.
const FAT_EPOCH_DATE: u16 = (1 << 5) | 1;
const END_OF_CHAIN: u16 = 0xFFFF;

/// One file to place on a volume, by a `/`-separated path of 8.3 names.
pub struct File<'a> {
    pub path: &'a str,
    pub data: &'a [u8],
}

/// A volume's shape.
pub struct Params {
    /// Sectors in the whole volume.
    pub sectors: u32,
    pub sectors_per_cluster: u8,
    pub reserved_sectors: u16,
    pub fats: u8,
    pub root_entries: u16,
    /// Sectors before the volume on its disk, recorded in the boot sector. A partition's
    /// start on a partitioned disk; where the volume sits on an unpartitioned one.
    pub hidden_sectors: u32,
    /// The eleven-byte volume label, written in the boot sector and as the root's first
    /// entry.
    pub label: [u8; 11],
    pub volume_id: u32,
    /// What the volume is, for the error when the files do not fit.
    pub what: &'static str,
}

#[derive(Default)]
struct Dir<'a> {
    dirs: BTreeMap<[u8; 11], Dir<'a>>,
    files: BTreeMap<[u8; 11], &'a [u8]>,
    /// First cluster, assigned during layout. Unused for the root, which lives in its
    /// own fixed region.
    cluster: u16,
}

impl Dir<'_> {
    /// Entries this directory holds, `.` and `..` included for a subdirectory.
    fn entries(&self, is_root: bool) -> usize {
        self.dirs.len() + self.files.len() + if is_root { 1 } else { 2 }
    }
}

/// An 8.3 name as the 11 bytes a directory entry stores.
pub fn short_name(component: &str) -> Result<[u8; 11], String> {
    let bad = || {
        format!(
            "`{component}` is not an 8.3 name: at most 8 characters, an optional extension of \
             at most 3, letters, digits, `_` and `-` only"
        )
    };
    let (base, ext) = component.split_once('.').unwrap_or((component, ""));
    if base.is_empty() || base.len() > 8 || ext.len() > 3 || ext.contains('.') {
        return Err(bad());
    }
    let mut name = [b' '; 11];
    for (i, c) in base.bytes().enumerate() {
        if !(c.is_ascii_alphanumeric() || c == b'_' || c == b'-') {
            return Err(bad());
        }
        name[i] = c.to_ascii_uppercase();
    }
    for (i, c) in ext.bytes().enumerate() {
        if !(c.is_ascii_alphanumeric() || c == b'_' || c == b'-') {
            return Err(bad());
        }
        name[8 + i] = c.to_ascii_uppercase();
    }
    Ok(name)
}

/// Where a volume's regions fall, for a caller that must know without re-deriving it.
pub struct Layout {
    pub fat_sectors: u16,
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "read by esp.rs's check that the table is the smallest one"
        )
    )]
    pub root_sectors: u32,
    /// The sector cluster 2 starts at, counted from the volume's first sector.
    pub data_start: u32,
    pub clusters: u32,
}

/// The layout a volume of shape `p` has.
pub fn layout(p: &Params) -> Result<Layout, String> {
    let root_sectors = (u32::from(p.root_entries) * ENTRY as u32).div_ceil(SECTOR as u32);
    // The FAT's size depends on the cluster count, which depends on the FAT's size: take
    // the smallest FAT that covers the clusters left over after it.
    let mut fat_sectors = 1u16;
    loop {
        let data_start = u32::from(p.reserved_sectors)
            + u32::from(p.fats) * u32::from(fat_sectors)
            + root_sectors;
        let clusters = p.sectors.saturating_sub(data_start) / u32::from(p.sectors_per_cluster);
        if u32::from(fat_sectors) * SECTOR as u32 / 2 >= clusters + 2 {
            // The type of a FAT volume is its cluster count and nothing else. A shape that
            // lands outside FAT16's range would be read as FAT12 or FAT32 by every reader,
            // including the kernel's, so it is refused here rather than written.
            if !(4085..65525).contains(&clusters) {
                return Err(format!(
                    "{}: {clusters} clusters is not FAT16 (4085 to 65524)",
                    p.what
                ));
            }
            return Ok(Layout {
                fat_sectors,
                root_sectors,
                data_start,
                clusters,
            });
        }
        fat_sectors = fat_sectors
            .checked_add(1)
            .ok_or_else(|| format!("{}: no FAT size covers this volume", p.what))?;
    }
}

struct Writer<'p> {
    part: Vec<u8>,
    fat: Vec<u16>,
    next: u16,
    geo: Layout,
    p: &'p Params,
}

impl Writer<'_> {
    fn cluster_bytes(&self) -> usize {
        SECTOR * self.p.sectors_per_cluster as usize
    }

    /// Claim a chain of clusters for `bytes`, returning its first cluster, or 0 for an
    /// empty file, which FAT represents with no chain at all.
    fn chain(&mut self, bytes: usize) -> Result<u16, String> {
        let n = bytes.div_ceil(self.cluster_bytes());
        if n == 0 {
            return Ok(0);
        }
        let first = self.next;
        let last = u32::from(first) + n as u32 - 1;
        if last >= self.geo.clusters + 2 {
            return Err(format!(
                "{} is full: {} KiB of FAT16 cannot hold these files",
                self.p.what,
                self.p.sectors as usize * SECTOR >> 10
            ));
        }
        for c in u32::from(first)..last {
            self.fat[c as usize] = (c + 1) as u16;
        }
        self.fat[last as usize] = END_OF_CHAIN;
        self.next = (last + 1) as u16;
        Ok(first)
    }

    fn cluster_offset(&self, cluster: u16) -> usize {
        (self.geo.data_start as usize
            + (usize::from(cluster) - 2) * self.p.sectors_per_cluster as usize)
            * SECTOR
    }

    /// Assign clusters: each directory's own, then its children's.
    fn layout(&mut self, dir: &mut Dir<'_>, is_root: bool) -> Result<(), String> {
        if !is_root {
            dir.cluster = self.chain(dir.entries(false) * ENTRY)?;
        }
        for sub in dir.dirs.values_mut() {
            self.layout(sub, false)?;
        }
        Ok(())
    }

    fn write_dir(&mut self, dir: &Dir<'_>, is_root: bool, parent: u16) -> Result<(), String> {
        let mut entries: Vec<[u8; ENTRY]> = Vec::new();
        if is_root {
            entries.push(entry(self.p.label, ATTR_VOLUME_ID, 0, 0));
        } else {
            entries.push(entry(*b".          ", ATTR_DIRECTORY, dir.cluster, 0));
            entries.push(entry(*b"..         ", ATTR_DIRECTORY, parent, 0));
        }
        for (name, sub) in &dir.dirs {
            entries.push(entry(*name, ATTR_DIRECTORY, sub.cluster, 0));
        }
        for (name, data) in &dir.files {
            let size = u32::try_from(data.len()).map_err(|_| "a file larger than 4 GiB")?;
            let first = self.chain(data.len())?;
            if first != 0 {
                let at = self.cluster_offset(first);
                self.part[at..at + data.len()].copy_from_slice(data);
            }
            entries.push(entry(*name, ATTR_ARCHIVE, first, size));
        }

        let at = if is_root {
            if entries.len() > usize::from(self.p.root_entries) {
                return Err(format!("too many entries in the root directory of {}", self.p.what));
            }
            (usize::from(self.p.reserved_sectors)
                + usize::from(self.p.fats) * usize::from(self.geo.fat_sectors))
                * SECTOR
        } else {
            self.cluster_offset(dir.cluster)
        };
        for (i, e) in entries.iter().enumerate() {
            self.part[at + i * ENTRY..at + (i + 1) * ENTRY].copy_from_slice(e);
        }

        // A subdirectory's `..` names the root as cluster 0, whatever the root's position.
        let me = if is_root { 0 } else { dir.cluster };
        for sub in dir.dirs.values() {
            self.write_dir(sub, false, me)?;
        }
        Ok(())
    }
}

fn entry(name: [u8; 11], attr: u8, cluster: u16, size: u32) -> [u8; ENTRY] {
    let mut e = [0u8; ENTRY];
    e[..11].copy_from_slice(&name);
    e[11] = attr;
    // Creation, access and modification dates all the FAT epoch; times zero.
    e[16..18].copy_from_slice(&FAT_EPOCH_DATE.to_le_bytes());
    e[18..20].copy_from_slice(&FAT_EPOCH_DATE.to_le_bytes());
    e[24..26].copy_from_slice(&FAT_EPOCH_DATE.to_le_bytes());
    e[26..28].copy_from_slice(&cluster.to_le_bytes());
    e[28..32].copy_from_slice(&size.to_le_bytes());
    e
}

/// A FAT16 volume of `p`'s shape holding `files`.
pub fn volume(files: &[File<'_>], p: &Params) -> Result<Vec<u8>, String> {
    let mut root = Dir::default();
    for f in files {
        let mut dir = &mut root;
        let mut parts = f.path.split('/').peekable();
        while let Some(component) = parts.next() {
            let name = short_name(component)?;
            if parts.peek().is_none() {
                if dir.dirs.contains_key(&name) || dir.files.insert(name, f.data).is_some() {
                    return Err(format!("`{}` is on {} twice", f.path, p.what));
                }
            } else {
                if dir.files.contains_key(&name) {
                    return Err(format!(
                        "`{component}` in `{}` is a file, not a directory",
                        f.path
                    ));
                }
                dir = dir.dirs.entry(name).or_default();
            }
        }
    }

    let geo = layout(p)?;
    let mut w = Writer {
        part: vec![0u8; p.sectors as usize * SECTOR],
        fat: vec![0u16; (geo.clusters + 2) as usize],
        next: 2,
        geo,
        p,
    };
    w.fat[0] = 0xFFF8;
    w.fat[1] = END_OF_CHAIN;
    w.layout(&mut root, true)?;
    w.write_dir(&root, true, 0)?;

    boot_sector(&mut w.part[..SECTOR], &w.geo, p);
    let fat_bytes: Vec<u8> = w.fat.iter().flat_map(|c| c.to_le_bytes()).collect();
    for i in 0..usize::from(p.fats) {
        let at = (usize::from(p.reserved_sectors) + i * usize::from(w.geo.fat_sectors)) * SECTOR;
        w.part[at..at + fat_bytes.len()].copy_from_slice(&fat_bytes);
    }
    Ok(w.part)
}

fn boot_sector(s: &mut [u8], geo: &Layout, p: &Params) {
    s[0..3].copy_from_slice(&[0xEB, 0x3C, 0x90]);
    s[3..11].copy_from_slice(b"KINTANE ");
    s[11..13].copy_from_slice(&(SECTOR as u16).to_le_bytes());
    s[13] = p.sectors_per_cluster;
    s[14..16].copy_from_slice(&p.reserved_sectors.to_le_bytes());
    s[16] = p.fats;
    s[17..19].copy_from_slice(&p.root_entries.to_le_bytes());
    // The total always goes in the 32-bit field and the 16-bit one is zero. The
    // specification allows either for a volume that fits in 16 bits; one rule for every
    // volume keeps the ESP's bytes what they were when this writer served only it.
    s[19..21].copy_from_slice(&0u16.to_le_bytes());
    s[21] = 0xF8;
    s[22..24].copy_from_slice(&geo.fat_sectors.to_le_bytes());
    s[24..26].copy_from_slice(&63u16.to_le_bytes());
    s[26..28].copy_from_slice(&255u16.to_le_bytes());
    s[28..32].copy_from_slice(&p.hidden_sectors.to_le_bytes());
    s[32..36].copy_from_slice(&p.sectors.to_le_bytes());
    s[36] = 0x80;
    s[38] = 0x29;
    s[39..43].copy_from_slice(&p.volume_id.to_le_bytes());
    s[43..54].copy_from_slice(&p.label);
    s[54..62].copy_from_slice(b"FAT16   ");
    s[510..512].copy_from_slice(&[0x55, 0xAA]);
}

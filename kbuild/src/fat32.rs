//! FAT32 volumes, written from scratch and read back.
//!
//! A module of its own rather than a branch inside [`crate::fat16`], for two reasons. The
//! ESP's bytes are pinned byte for byte by a test, and the surest way not to change them is
//! not to touch the writer that makes them. And the reader below must share no code with the
//! writer it checks — the same rule `fat16.rs` follows — so a second format means a second
//! pair, not one pair with a flag.
//!
//! What is written is the subset the test disk needs, and no more:
//!
//! - FAT32 only, with the cluster count above the boundary the specification draws, since that
//!   count and nothing else is what makes a volume FAT32;
//! - 8.3 names, no long-name entries;
//! - files and directories written once and never modified, so every chain is contiguous.
//!
//! Every volume is reproducible: the FAT epoch for timestamps, the serial number a parameter,
//! and entries in name order.
//!
//! The three places FAT32 differs from FAT16 are all here: a table entry is four bytes of
//! which twenty-eight are the cluster number, the root is a chain like any other directory's
//! rather than a fixed region, and an FSInfo sector carries the free count.

use std::collections::BTreeMap;

pub use crate::fat16::File;

pub const SECTOR: usize = 512;
const ENTRY: usize = 32;

const ATTR_VOLUME_ID: u8 = 0x08;
const ATTR_DIRECTORY: u8 = 0x10;
const ATTR_ARCHIVE: u8 = 0x20;
const ATTR_LONG_NAME: u8 = 0x0F;
/// 1980-01-01, as a FAT date.
const FAT_EPOCH_DATE: u16 = (1 << 5) | 1;
/// What ends a chain, and what a reader treats as an end.
const END: u32 = 0x0FFF_FFFF;
const CHAIN_END: u32 = 0x0FFF_FFF8;
const BAD_CLUSTER: u32 = 0x0FFF_FFF7;
/// The bits of an entry that are the cluster number; the top four are the volume's.
const MASK: u32 = 0x0FFF_FFFF;
/// The fewest clusters a FAT32 volume may have, by the specification's own boundary.
pub const MIN_CLUSTERS: u32 = 65_525;
/// Where FSInfo sits, counted from the volume's first sector, and its signatures.
const FSINFO_SECTOR: usize = 1;
const FSINFO_LEAD: u32 = 0x4161_5252;
const FSINFO_STRUCT: u32 = 0x6141_7272;
const FSINFO_TRAIL: u32 = 0xAA55_0000;
/// The root's first cluster, which this writer always places first.
const ROOT_CLUSTER: u32 = 2;
const ENTRY_FREE: u8 = 0x00;
const ENTRY_DELETED: u8 = 0xE5;
const MAX_DEPTH: usize = 16;

/// A volume's shape.
pub struct Params {
    /// Sectors in the whole volume.
    pub sectors: u32,
    pub sectors_per_cluster: u8,
    /// FAT32 keeps its FSInfo and a backup boot sector in the reserved region, so this is
    /// more than one.
    pub reserved_sectors: u16,
    pub fats: u8,
    /// Sectors before the volume on its disk, recorded in the boot sector.
    pub hidden_sectors: u32,
    pub label: [u8; 11],
    pub volume_id: u32,
    /// What the volume is, for the error when the files do not fit.
    pub what: &'static str,
}

/// Where a volume's regions fall.
pub struct Layout {
    pub fat_sectors: u32,
    /// The sector cluster 2 starts at, counted from the volume's first sector.
    pub data_start: u32,
    pub clusters: u32,
}

/// The layout a volume of shape `p` has.
pub fn layout(p: &Params) -> Result<Layout, String> {
    if p.reserved_sectors < 2 {
        return Err(format!("{}: FAT32 needs a reserved region for its FSInfo sector", p.what));
    }
    // The table's size depends on the cluster count, which depends on the table's size: take
    // the smallest table that covers the clusters left over after it.
    let mut fat_sectors = 1u32;
    loop {
        let data_start = u32::from(p.reserved_sectors) + u32::from(p.fats) * fat_sectors;
        let clusters = p.sectors.saturating_sub(data_start) / u32::from(p.sectors_per_cluster);
        if fat_sectors * SECTOR as u32 / 4 >= clusters + 2 {
            // The format is the cluster count and nothing else: a volume below the boundary
            // would be read as FAT16 by every reader, including the kernel's.
            if clusters < MIN_CLUSTERS {
                return Err(format!(
                    "{}: {clusters} clusters is not FAT32 (at least {MIN_CLUSTERS})",
                    p.what
                ));
            }
            return Ok(Layout {
                fat_sectors,
                data_start,
                clusters,
            });
        }
        fat_sectors = fat_sectors
            .checked_add(1)
            .ok_or_else(|| format!("{}: no table size covers this volume", p.what))?;
    }
}

#[derive(Default)]
struct Dir<'a> {
    dirs: BTreeMap<[u8; 11], Dir<'a>>,
    files: BTreeMap<[u8; 11], &'a [u8]>,
    /// First cluster, assigned during layout.
    cluster: u32,
}

impl Dir<'_> {
    /// Entries this directory holds: the label for the root, `.` and `..` for any other.
    fn entries(&self, is_root: bool) -> usize {
        self.dirs.len() + self.files.len() + if is_root { 1 } else { 2 }
    }
}

struct Writer<'p> {
    part: Vec<u8>,
    fat: Vec<u32>,
    next: u32,
    geo: Layout,
    p: &'p Params,
}

impl Writer<'_> {
    fn cluster_bytes(&self) -> usize {
        SECTOR * self.p.sectors_per_cluster as usize
    }

    /// Claim a contiguous chain for `bytes`, returning its first cluster, or 0 for an empty
    /// file, which FAT represents with no chain at all.
    fn chain(&mut self, bytes: usize) -> Result<u32, String> {
        let n = bytes.div_ceil(self.cluster_bytes());
        if n == 0 {
            return Ok(0);
        }
        let first = self.next;
        let last = first + n as u32 - 1;
        if last >= self.geo.clusters + 2 {
            return Err(format!(
                "{} is full: {} KiB of FAT32 cannot hold these files",
                self.p.what,
                self.p.sectors as usize * SECTOR >> 10
            ));
        }
        for c in first..last {
            self.fat[c as usize] = c + 1;
        }
        self.fat[last as usize] = END;
        self.next = last + 1;
        Ok(first)
    }

    fn cluster_offset(&self, cluster: u32) -> usize {
        (self.geo.data_start as usize
            + (cluster as usize - 2) * self.p.sectors_per_cluster as usize)
            * SECTOR
    }

    /// Assign clusters: this directory's own chain, then its children's. The root goes first,
    /// so it starts at [`ROOT_CLUSTER`], which the boot sector names.
    fn assign(&mut self, dir: &mut Dir<'_>, is_root: bool) -> Result<(), String> {
        dir.cluster = self.chain(dir.entries(is_root) * ENTRY)?;
        for sub in dir.dirs.values_mut() {
            self.assign(sub, false)?;
        }
        Ok(())
    }

    fn write_dir(&mut self, dir: &Dir<'_>, is_root: bool, parent: u32) -> Result<(), String> {
        let mut entries: Vec<[u8; ENTRY]> = Vec::new();
        if is_root {
            entries.push(entry(self.p.label, ATTR_VOLUME_ID, 0, 0));
        } else {
            entries.push(entry(*b".          ", ATTR_DIRECTORY, dir.cluster, 0));
            // A directory one below the root names it as cluster 0, whatever cluster the
            // root actually starts at: that is what every reader expects there.
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

        // The chain is contiguous, so the entries are one run of bytes.
        let at = self.cluster_offset(dir.cluster);
        for (i, e) in entries.iter().enumerate() {
            self.part[at + i * ENTRY..at + (i + 1) * ENTRY].copy_from_slice(e);
        }

        let me = if is_root { 0 } else { dir.cluster };
        for sub in dir.dirs.values() {
            self.write_dir(sub, false, me)?;
        }
        Ok(())
    }
}

/// One directory entry. The first cluster lives in two halves, which is FAT32's own shape.
fn entry(name: [u8; 11], attr: u8, cluster: u32, size: u32) -> [u8; ENTRY] {
    let mut e = [0u8; ENTRY];
    e[..11].copy_from_slice(&name);
    e[11] = attr;
    e[16..18].copy_from_slice(&FAT_EPOCH_DATE.to_le_bytes());
    e[18..20].copy_from_slice(&FAT_EPOCH_DATE.to_le_bytes());
    e[20..22].copy_from_slice(&((cluster >> 16) as u16).to_le_bytes());
    e[24..26].copy_from_slice(&FAT_EPOCH_DATE.to_le_bytes());
    e[26..28].copy_from_slice(&(cluster as u16).to_le_bytes());
    e[28..32].copy_from_slice(&size.to_le_bytes());
    e
}

/// A FAT32 volume of `p`'s shape holding `files`.
pub fn volume(files: &[File<'_>], p: &Params) -> Result<Vec<u8>, String> {
    let mut root = Dir::default();
    for f in files {
        let mut dir = &mut root;
        let mut parts = f.path.split('/').peekable();
        while let Some(component) = parts.next() {
            let name = crate::fat16::short_name(component)?;
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
        fat: vec![0u32; (geo.clusters + 2) as usize],
        next: ROOT_CLUSTER,
        geo,
        p,
    };
    w.fat[0] = 0x0FFF_FFF8;
    w.fat[1] = END;
    w.assign(&mut root, true)?;
    if root.cluster != ROOT_CLUSTER {
        return Err(format!("{}: the root did not land on cluster 2", p.what));
    }
    w.write_dir(&root, true, 0)?;

    let used = w.next - ROOT_CLUSTER;
    boot_sector(&mut w.part[..SECTOR], &w.geo, p);
    fsinfo(
        &mut w.part[FSINFO_SECTOR * SECTOR..(FSINFO_SECTOR + 1) * SECTOR],
        w.geo.clusters - used,
        w.next,
    );
    let fat_bytes: Vec<u8> = w.fat.iter().flat_map(|c| c.to_le_bytes()).collect();
    for i in 0..usize::from(p.fats) {
        let at = (usize::from(p.reserved_sectors) + i * w.geo.fat_sectors as usize) * SECTOR;
        w.part[at..at + fat_bytes.len()].copy_from_slice(&fat_bytes);
    }
    Ok(w.part)
}

fn boot_sector(s: &mut [u8], geo: &Layout, p: &Params) {
    s[0..3].copy_from_slice(&[0xEB, 0x58, 0x90]);
    s[3..11].copy_from_slice(b"KINTANE ");
    s[11..13].copy_from_slice(&(SECTOR as u16).to_le_bytes());
    s[13] = p.sectors_per_cluster;
    s[14..16].copy_from_slice(&p.reserved_sectors.to_le_bytes());
    s[16] = p.fats;
    // A FAT32 volume has no fixed root region and no 16-bit table size: both fields are zero
    // and the 32-bit ones carry the truth.
    s[17..19].copy_from_slice(&0u16.to_le_bytes());
    s[19..21].copy_from_slice(&0u16.to_le_bytes());
    s[21] = 0xF8;
    s[22..24].copy_from_slice(&0u16.to_le_bytes());
    s[24..26].copy_from_slice(&63u16.to_le_bytes());
    s[26..28].copy_from_slice(&255u16.to_le_bytes());
    s[28..32].copy_from_slice(&p.hidden_sectors.to_le_bytes());
    s[32..36].copy_from_slice(&p.sectors.to_le_bytes());
    s[36..40].copy_from_slice(&geo.fat_sectors.to_le_bytes());
    s[40..42].copy_from_slice(&0u16.to_le_bytes());
    s[42..44].copy_from_slice(&0u16.to_le_bytes());
    s[44..48].copy_from_slice(&ROOT_CLUSTER.to_le_bytes());
    s[48..50].copy_from_slice(&(FSINFO_SECTOR as u16).to_le_bytes());
    s[50..52].copy_from_slice(&6u16.to_le_bytes());
    // FAT32's extended fields sit further along than FAT16's, which is the one place a
    // reader that guessed the format from a string would go wrong.
    s[64] = 0x80;
    s[66] = 0x29;
    s[67..71].copy_from_slice(&p.volume_id.to_le_bytes());
    s[71..82].copy_from_slice(&p.label);
    s[82..90].copy_from_slice(b"FAT32   ");
    s[510..512].copy_from_slice(&[0x55, 0xAA]);
}

fn fsinfo(s: &mut [u8], free: u32, next_free: u32) {
    s[0..4].copy_from_slice(&FSINFO_LEAD.to_le_bytes());
    s[484..488].copy_from_slice(&FSINFO_STRUCT.to_le_bytes());
    s[488..492].copy_from_slice(&free.to_le_bytes());
    s[492..496].copy_from_slice(&next_free.to_le_bytes());
    s[508..512].copy_from_slice(&FSINFO_TRAIL.to_le_bytes());
}

// ---- reading a volume back -------------------------------------------------------------------
//
// The kernel writes this volume after kbuild has, and kbuild reads it back after the guest
// exits. Deliberately not the kernel's driver and not the writer above: a reader that shares
// code with a writer cannot tell that writer is wrong.

/// What [`Volume::check`] found on a volume it did not call corrupt.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Report {
    pub files: u32,
    pub dirs: u32,
    pub claimed: u32,
    /// Clusters the table allocates that no chain claims: what a crash may leave.
    pub lost: u32,
    pub fats_differ: u32,
    /// Clusters the table calls free, counted by the walk.
    pub free: u32,
    /// What the FSInfo sector says is free, when it claims to know.
    pub fsinfo_free: Option<u32>,
}

/// A FAT32 volume's bytes, with its geometry read from its boot sector.
pub struct Volume<'a> {
    bytes: &'a [u8],
    cluster_sectors: usize,
    fat_start: usize,
    fats: usize,
    fat_sectors: usize,
    data_start: usize,
    clusters: u32,
    root: u32,
    fsinfo: usize,
}

struct Named {
    name: String,
    dir: bool,
    first: u32,
    size: u32,
}

fn le16(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}

fn le32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

impl<'a> Volume<'a> {
    /// Read the boot sector at the start of `bytes` and check the geometry fits.
    pub fn open(bytes: &'a [u8]) -> Result<Volume<'a>, String> {
        if bytes.len() < SECTOR || le16(bytes, 510) != 0xAA55 {
            return Err("no boot sector at the start of the volume".into());
        }
        if usize::from(le16(bytes, 11)) != SECTOR {
            return Err("the volume's sectors are not 512 bytes".into());
        }
        let cluster_sectors = usize::from(bytes[13]);
        let reserved = usize::from(le16(bytes, 14));
        let fats = usize::from(bytes[16]);
        let fat_sectors = le32(bytes, 36) as usize;
        let total = le32(bytes, 32) as usize;
        if cluster_sectors == 0 || reserved < 2 || fats == 0 || fat_sectors == 0 {
            return Err("a boot sector with a zero field".into());
        }
        if le16(bytes, 17) != 0 {
            return Err("a FAT32 volume with a fixed root directory".into());
        }
        let data_start = (reserved + fats * fat_sectors) * SECTOR;
        if total * SECTOR > bytes.len() || data_start >= total * SECTOR {
            return Err("a volume larger than its image, or with no data region".into());
        }
        let clusters = ((total * SECTOR - data_start) / SECTOR / cluster_sectors) as u32;
        if clusters < MIN_CLUSTERS {
            return Err(format!("{clusters} clusters is not FAT32"));
        }
        if (clusters as usize + 2) * 4 > fat_sectors * SECTOR {
            return Err("a table too small for its clusters".into());
        }
        let root = le32(bytes, 44) & MASK;
        if root < 2 || root >= clusters + 2 {
            return Err(format!("a root directory at cluster {root}, outside the volume"));
        }
        let fsinfo = usize::from(le16(bytes, 48));
        if fsinfo == 0 || fsinfo >= reserved {
            return Err("an FSInfo sector outside the reserved region".into());
        }
        Ok(Volume {
            bytes,
            cluster_sectors,
            fat_start: reserved * SECTOR,
            fats,
            fat_sectors,
            data_start,
            clusters,
            root,
            fsinfo: fsinfo * SECTOR,
        })
    }

    fn cluster_size(&self) -> usize {
        self.cluster_sectors * SECTOR
    }

    fn table(&self, copy: usize, cluster: u32) -> u32 {
        le32(
            self.bytes,
            self.fat_start + copy * self.fat_sectors * SECTOR + cluster as usize * 4,
        ) & MASK
    }

    fn in_volume(&self, cluster: u32) -> bool {
        (2..self.clusters + 2).contains(&cluster)
    }

    /// The chain from `first`, refusing a cluster outside the volume, a free or bad one, and
    /// a loop.
    fn chain(&self, first: u32) -> Result<Vec<u32>, String> {
        let mut out = Vec::new();
        let mut cluster = first;
        loop {
            if !self.in_volume(cluster) {
                return Err(format!("a chain entry outside the volume: {cluster}"));
            }
            let value = self.table(0, cluster);
            if value == 0 {
                return Err(format!("a chain through free cluster {cluster}"));
            }
            if value == BAD_CLUSTER {
                return Err(format!("a chain through bad cluster {cluster}"));
            }
            out.push(cluster);
            if out.len() > self.clusters as usize {
                return Err("a chain that loops".into());
            }
            if value >= CHAIN_END {
                return Ok(out);
            }
            cluster = value;
        }
    }

    fn cluster_bytes(&self, cluster: u32) -> &[u8] {
        let at = self.data_start + (cluster as usize - 2) * self.cluster_size();
        &self.bytes[at..at + self.cluster_size()]
    }

    /// The named entries of the directory whose chain starts at `first`; the root's when
    /// `None`, which on FAT32 is a chain like any other.
    fn entries(&self, first: Option<u32>) -> Result<Vec<Named>, String> {
        let start = first.unwrap_or(self.root);
        let raw: Vec<u8> = self
            .chain(start)?
            .into_iter()
            .flat_map(|c| self.cluster_bytes(c).to_vec())
            .collect();
        let mut out = Vec::new();
        for e in raw.chunks_exact(ENTRY) {
            if e[0] == ENTRY_FREE {
                break;
            }
            if e[0] == ENTRY_DELETED
                || e[11] & ATTR_LONG_NAME == ATTR_LONG_NAME
                || e[11] & ATTR_VOLUME_ID != 0
            {
                continue;
            }
            let base = String::from_utf8_lossy(&e[..8]).trim_end().to_string();
            let ext = String::from_utf8_lossy(&e[8..11]).trim_end().to_string();
            if base.is_empty() || base == "." || base == ".." {
                continue;
            }
            let name = if ext.is_empty() {
                base
            } else {
                format!("{base}.{ext}")
            };
            out.push(Named {
                name,
                dir: e[11] & ATTR_DIRECTORY != 0,
                first: (u32::from(le16(e, 20)) << 16) | u32::from(le16(e, 26)),
                size: le32(e, 28),
            });
        }
        Ok(out)
    }

    /// Walk every directory and chain, refusing what a crash must never leave. What a crash
    /// may leave — lost clusters, tables apart, an FSInfo count behind the table — is counted.
    pub fn check(&self) -> Result<Report, String> {
        let mut seen = vec![false; self.clusters as usize + 2];
        let mut report = Report::default();
        // The root's own chain is claimed like any directory's, which is what FAT16 has no
        // need of and what a walk that forgot would report as lost.
        for c in self.chain(self.root)? {
            seen[c as usize] = true;
            report.claimed += 1;
        }
        self.walk(None, "", 0, &mut seen, &mut report)?;
        for cluster in 2..self.clusters + 2 {
            let first = self.table(0, cluster);
            if first == 0 {
                report.free += 1;
            } else if first != BAD_CLUSTER && !seen[cluster as usize] {
                report.lost += 1;
            }
            if (1..self.fats).any(|copy| self.table(copy, cluster) != first) {
                report.fats_differ += 1;
            }
        }
        let free = le32(self.bytes, self.fsinfo + 488);
        report.fsinfo_free = (free != 0xFFFF_FFFF).then_some(free);
        if le32(self.bytes, self.fsinfo) != FSINFO_LEAD
            || le32(self.bytes, self.fsinfo + 484) != FSINFO_STRUCT
            || le32(self.bytes, self.fsinfo + 508) != FSINFO_TRAIL
        {
            return Err("an FSInfo sector without its signatures".into());
        }
        Ok(report)
    }

    fn walk(
        &self,
        dir: Option<u32>,
        path: &str,
        depth: usize,
        seen: &mut [bool],
        report: &mut Report,
    ) -> Result<(), String> {
        if depth > MAX_DEPTH {
            return Err(format!("{path}: directories nested too deep"));
        }
        for e in self.entries(dir)? {
            let here = format!("{path}/{}", e.name);
            if e.dir {
                report.dirs += 1;
                if e.first == 0 {
                    return Err(format!("{here}: a directory with no clusters"));
                }
            } else {
                report.files += 1;
                if e.first == 0 {
                    if e.size != 0 {
                        return Err(format!("{here}: {} bytes and no clusters", e.size));
                    }
                    continue;
                }
            }
            let chain = self.chain(e.first).map_err(|m| format!("{here}: {m}"))?;
            for &c in &chain {
                if std::mem::replace(&mut seen[c as usize], true) {
                    return Err(format!("{here}: cluster {c} is claimed twice"));
                }
            }
            report.claimed += chain.len() as u32;
            if !e.dir && chain.len() < (e.size as usize).div_ceil(self.cluster_size()) {
                return Err(format!(
                    "{here}: {} clusters hold a {}-byte file",
                    chain.len(),
                    e.size
                ));
            }
            if e.dir {
                self.walk(Some(e.first), &here, depth + 1, seen, report)?;
            }
        }
        Ok(())
    }

    /// The entry `path` names, comparing names as FAT does: without regard to case.
    fn find(&self, path: &str) -> Result<Option<Named>, String> {
        let mut dir = None;
        let mut parts = path.split('/').filter(|p| !p.is_empty()).peekable();
        while let Some(part) = parts.next() {
            let Some(e) = self
                .entries(dir)?
                .into_iter()
                .find(|e| e.name.eq_ignore_ascii_case(part))
            else {
                return Ok(None);
            };
            if parts.peek().is_none() {
                return Ok(Some(e));
            }
            if !e.dir {
                return Ok(None);
            }
            dir = Some(e.first);
        }
        Ok(None)
    }

    /// Whether `path` names anything.
    pub fn exists(&self, path: &str) -> Result<bool, String> {
        self.find(path).map(|e| e.is_some())
    }

    /// The bytes of the file `path` names, `None` if nothing is there.
    pub fn read(&self, path: &str) -> Result<Option<Vec<u8>>, String> {
        let Some(e) = self.find(path)? else {
            return Ok(None);
        };
        if e.dir {
            return Err(format!("{path} is a directory"));
        }
        if e.first == 0 {
            return Ok(Some(Vec::new()));
        }
        let mut data: Vec<u8> = self
            .chain(e.first)?
            .into_iter()
            .flat_map(|c| self.cluster_bytes(c).to_vec())
            .collect();
        if data.len() < e.size as usize {
            return Err(format!("{path}: a chain shorter than the file"));
        }
        data.truncate(e.size as usize);
        Ok(Some(data))
    }

    /// The files directly in the directory `path` names, by name, `None` if there is none.
    ///
    /// What the crash test reads: after a cut the directory may not have reached the disk at
    /// all, which is `None` rather than an error.
    pub fn files_in(&self, path: &str) -> Result<Option<Vec<(String, Vec<u8>)>>, String> {
        let Some(dir) = self.find(path)? else {
            return Ok(None);
        };
        if !dir.dir {
            return Err(format!("{path} is not a directory"));
        }
        let mut out = Vec::new();
        for e in self.entries(Some(dir.first))? {
            if !e.dir {
                let data = self
                    .read(&format!("{path}/{}", e.name))?
                    .unwrap_or_default();
                out.push((e.name, data));
            }
        }
        Ok(Some(out))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The smallest volume that is FAT32 by its cluster count: about 34 MiB.
    fn params() -> Params {
        Params {
            sectors: 66_600,
            sectors_per_cluster: 1,
            reserved_sectors: 32,
            fats: 2,
            hidden_sectors: 0,
            label: *b"KTFAT32    ",
            volume_id: 0x4654_3332,
            what: "a test volume",
        }
    }

    #[test]
    fn a_written_volume_reads_back_and_checks_clean() {
        let big: Vec<u8> = (0..5000u32).map(|i| (i * 7) as u8).collect();
        let files = [
            File {
                path: "A.TXT",
                data: b"hello",
            },
            File {
                path: "DIR/BIG.BIN",
                data: &big,
            },
            File {
                path: "DIR/EMPTY",
                data: b"",
            },
        ];
        let v = volume(&files, &params()).unwrap();
        let vol = Volume::open(&v).unwrap();
        let r = vol.check().unwrap();
        assert_eq!((r.files, r.dirs, r.lost, r.fats_differ), (3, 1, 0, 0));
        assert_eq!(vol.read("/a.txt").unwrap().unwrap(), b"hello");
        assert_eq!(vol.read("/DIR/BIG.BIN").unwrap().unwrap(), big);
        assert_eq!(vol.read("/DIR/EMPTY").unwrap().unwrap(), b"");
        assert!(vol.exists("/DIR").unwrap());
        // The root, the directory, the big file's ten clusters and the small one's.
        assert_eq!(r.claimed, 1 + 1 + 10 + 1);
        assert_eq!(r.claimed + r.free, vol.clusters, "every cluster is claimed or free");
    }

    #[test]
    fn the_boot_sector_says_fat32_where_fat32_says_it() {
        let v = volume(&[], &params()).unwrap();
        assert_eq!(le16(&v, 17), 0, "no fixed root region");
        assert_eq!(le16(&v, 22), 0, "no 16-bit table size");
        assert_ne!(le32(&v, 36), 0, "a 32-bit table size");
        assert_eq!(le32(&v, 44), ROOT_CLUSTER, "the root's first cluster");
        assert_eq!(&v[82..90], b"FAT32   ", "FAT32's type string, where FAT32 keeps it");
        assert_eq!(&v[510..512], &[0x55, 0xAA]);
    }

    #[test]
    fn fsinfo_holds_the_count_the_walk_finds() {
        let v = volume(
            &[File {
                path: "A.BIN",
                data: &[7u8; 3000],
            }],
            &params(),
        )
        .unwrap();
        let vol = Volume::open(&v).unwrap();
        let r = vol.check().unwrap();
        assert_eq!(r.fsinfo_free, Some(r.free), "FSInfo agrees with the table");
        assert_eq!(r.claimed + r.free, vol.clusters, "every cluster is claimed or free");
    }

    #[test]
    fn a_volume_below_the_boundary_is_refused_rather_than_written_as_fat16() {
        let small = Params {
            sectors: 20_000,
            ..params()
        };
        let err = volume(&[], &small).unwrap_err();
        assert!(err.contains("is not FAT32"), "{err}");
    }

    #[test]
    fn a_cross_link_and_a_short_chain_are_refused() {
        let files = [
            File {
                path: "A.BIN",
                data: &[1u8; 1500],
            },
            File {
                path: "B.BIN",
                data: &[2u8; 1500],
            },
        ];
        let good = volume(&files, &params()).unwrap();
        let vol = Volume::open(&good).unwrap();
        // The root holds the label, then A.BIN, then B.BIN.
        let root_at = vol.data_start;
        let (a, b) = (root_at + ENTRY, root_at + 2 * ENTRY);
        let a_first = u32::from(le16(&good, a + 26));

        let mut crossed = good.clone();
        crossed[b + 26..b + 28].copy_from_slice(&(a_first as u16).to_le_bytes());
        assert!(
            Volume::open(&crossed)
                .unwrap()
                .check()
                .unwrap_err()
                .contains("claimed twice")
        );

        let mut short = good.clone();
        short[a + 28..a + 32].copy_from_slice(&9000u32.to_le_bytes());
        assert!(
            Volume::open(&short)
                .unwrap()
                .check()
                .unwrap_err()
                .contains("clusters hold")
        );
    }
}

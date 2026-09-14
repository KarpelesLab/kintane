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

// ---- reading a volume back -------------------------------------------------------------------
//
// The kernel writes the test disk's volume now, and kbuild reads what it wrote after the guest
// exits. Deliberately not the kernel's driver: a reader that shares no code with the writer is
// what can tell the writer is wrong. It reads the specification's fields directly and trusts
// none of them.

const ENTRY_FREE: u8 = 0x00;
const ENTRY_DELETED: u8 = 0xE5;
const ATTR_LONG_NAME: u8 = 0x0F;
const CHAIN_END: u16 = 0xFFF8;
const BAD_CLUSTER: u16 = 0xFFF7;
/// Directories a walk descends through before it calls the volume corrupt.
const MAX_DEPTH: usize = 16;

/// What [`Volume::check`] found on a volume it did not call corrupt.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Report {
    pub files: u32,
    pub dirs: u32,
    /// Clusters some chain claims.
    pub claimed: u32,
    /// Clusters the first table allocates that no chain claims: what a crash may leave.
    pub lost: u32,
    /// Table entries on which the copies disagree.
    pub fats_differ: u32,
}

/// A FAT16 volume's bytes, with its geometry read from its boot sector.
pub struct Volume<'a> {
    bytes: &'a [u8],
    cluster_sectors: usize,
    fat_start: usize,
    fats: usize,
    fat_sectors: usize,
    root_start: usize,
    root_entries: usize,
    data_start: usize,
    clusters: u32,
}

/// One named entry of a directory.
struct Named {
    name: String,
    dir: bool,
    first: u16,
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
        let root_entries = usize::from(le16(bytes, 17));
        let fat_sectors = usize::from(le16(bytes, 22));
        let total = match le16(bytes, 19) {
            0 => le32(bytes, 32) as usize,
            n => usize::from(n),
        };
        if cluster_sectors == 0 || reserved == 0 || fats == 0 || fat_sectors == 0 {
            return Err("a boot sector with a zero field".into());
        }
        let root_start = (reserved + fats * fat_sectors) * SECTOR;
        let data_start = root_start + (root_entries * ENTRY).div_ceil(SECTOR) * SECTOR;
        if total * SECTOR > bytes.len() || data_start >= total * SECTOR {
            return Err("a volume larger than its image, or with no data region".into());
        }
        let clusters = ((total * SECTOR - data_start) / SECTOR / cluster_sectors) as u32;
        if !(4085..65525).contains(&clusters) {
            return Err(format!("{clusters} clusters is not FAT16"));
        }
        if (clusters as usize + 2) * 2 > fat_sectors * SECTOR {
            return Err("a table too small for its clusters".into());
        }
        Ok(Volume {
            bytes,
            cluster_sectors,
            fat_start: reserved * SECTOR,
            fats,
            fat_sectors,
            root_start,
            root_entries,
            data_start,
            clusters,
        })
    }

    fn cluster_size(&self) -> usize {
        self.cluster_sectors * SECTOR
    }

    fn table(&self, copy: usize, cluster: u32) -> u16 {
        le16(
            self.bytes,
            self.fat_start + copy * self.fat_sectors * SECTOR + cluster as usize * 2,
        )
    }

    fn in_volume(&self, cluster: u32) -> bool {
        (2..self.clusters + 2).contains(&cluster)
    }

    /// The chain from `first` by the first table, refusing a cluster outside the volume, a
    /// free or bad one, and a loop.
    fn chain(&self, first: u16) -> Result<Vec<u32>, String> {
        let mut out = Vec::new();
        let mut cluster = u32::from(first);
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
            cluster = u32::from(value);
        }
    }

    fn cluster_bytes(&self, cluster: u32) -> &[u8] {
        let at = self.data_start + (cluster as usize - 2) * self.cluster_size();
        &self.bytes[at..at + self.cluster_size()]
    }

    /// The named entries of the root (`None`) or of the directory starting at `first`.
    fn entries(&self, first: Option<u16>) -> Result<Vec<Named>, String> {
        let raw: Vec<u8> = match first {
            None => {
                self.bytes[self.root_start..self.root_start + self.root_entries * ENTRY].to_vec()
            }
            Some(first) => self
                .chain(first)?
                .into_iter()
                .flat_map(|c| self.cluster_bytes(c).to_vec())
                .collect(),
        };
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
                first: le16(e, 26),
                size: le32(e, 28),
            });
        }
        Ok(out)
    }

    /// Walk every directory and chain, refusing what a crash must never leave: a chain through
    /// a free cluster, a cluster claimed twice, a file whose chain is shorter than its size, a
    /// directory without clusters. What a crash may leave is counted.
    pub fn check(&self) -> Result<Report, String> {
        let mut seen = vec![false; self.clusters as usize + 2];
        let mut report = Report::default();
        self.walk(None, "", 0, &mut seen, &mut report)?;
        for cluster in 2..self.clusters + 2 {
            let first = self.table(0, cluster);
            if first != 0 && first != BAD_CLUSTER && !seen[cluster as usize] {
                report.lost += 1;
            }
            if (1..self.fats).any(|copy| self.table(copy, cluster) != first) {
                report.fats_differ += 1;
            }
        }
        Ok(report)
    }

    fn walk(
        &self,
        dir: Option<u16>,
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
    pub fn files_in(&self, path: &str) -> Result<Option<Vec<(String, Vec<u8>)>>, String> {
        let Some(dir) = self.find(path)? else {
            return Ok(None);
        };
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
mod read_back_tests {
    use super::*;

    fn params() -> Params {
        Params {
            sectors: 8192,
            sectors_per_cluster: 1,
            reserved_sectors: 1,
            fats: 2,
            root_entries: 64,
            hidden_sectors: 0,
            label: *b"TEST       ",
            volume_id: 1,
            what: "a test volume",
        }
    }

    #[test]
    fn a_written_volume_reads_back_and_checks_clean() {
        let big: Vec<u8> = (0..5000u32).map(|i| i as u8).collect();
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
        assert!(vol.read("/DIR/NOPE").unwrap().is_none());
        assert!(vol.exists("/DIR").unwrap());
        assert_eq!(vol.files_in("/DIR").unwrap().unwrap().len(), 2);
    }

    #[test]
    fn cross_links_free_chains_and_short_chains_are_refused() {
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
        let geo = layout(&params()).unwrap();
        let fat = SECTOR;
        let root = (1 + 2 * usize::from(geo.fat_sectors)) * SECTOR;
        // The root's first entry is the label; A is the second, B the third.
        let (a, b) = (root + ENTRY, root + 2 * ENTRY);
        let a_first = le16(&good, a + 26);

        let mut crossed = good.clone();
        crossed[b + 26..b + 28].copy_from_slice(&a_first.to_le_bytes());
        assert!(
            Volume::open(&crossed)
                .unwrap()
                .check()
                .unwrap_err()
                .contains("claimed twice")
        );

        let mut freed = good.clone();
        let at = fat + usize::from(a_first) * 2;
        freed[at..at + 2].copy_from_slice(&0u16.to_le_bytes());
        assert!(
            Volume::open(&freed)
                .unwrap()
                .check()
                .unwrap_err()
                .contains("free cluster")
        );

        let mut short = good.clone();
        short[a + 28..a + 32].copy_from_slice(&5000u32.to_le_bytes());
        assert!(
            Volume::open(&short)
                .unwrap()
                .check()
                .unwrap_err()
                .contains("clusters hold")
        );

        let mut lost = good.clone();
        let spare = fat + 4000 * 2;
        lost[spare..spare + 2].copy_from_slice(&0xFFFFu16.to_le_bytes());
        let r = Volume::open(&lost).unwrap().check().unwrap();
        assert_eq!((r.lost, r.fats_differ), (1, 1), "a lost cluster, in the first table only");
    }
}

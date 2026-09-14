//! FAT16 volumes, and operations on them: the driver reads a disk it did not write, and
//! writes to it.
//!
//! Two kinds of input, told apart by the first byte.
//!
//! * **An image** (odd first byte): the rest is a volume, zero-padded to [`TOTAL`] sectors. The
//!   driver mounts it, walks it, reads what it lists, then creates, writes, truncates and removes a
//!   file. Whatever the bytes, nothing may panic, and a volume that passed the consistency walk
//!   before the writes must pass it after them.
//! * **An operation script** (even first byte): a fresh empty volume, and a sequence of operations
//!   decoded four bytes at a time — create, write, truncate, unlink, rename, sync, a directory made
//!   and removed. After every one the volume must walk clean, with nothing lost and its two tables
//!   the same, and every file must hold exactly what a model of it says. Then every prefix of the
//!   blocks the cache wrote — every point a power cut could have stopped the device — is replayed
//!   on the empty volume, mounted afresh, and must walk clean too.
//!
//! Seeded from `corpus/fat/`: a script that exercises every operation, so the valid shapes stay
//! reachable however far mutation wanders.

use alloc::vec;
use alloc::vec::Vec;
use core::cell::RefCell;

use bcache::{Cache, Slot};
use block::{BlockDevice, Error as BlockError, Geometry};
use fat::{Consistency, Fat};
use vfs::{Error, FileSystem, Kind};

use crate::{Mutator, Rng};

const SECTOR: usize = 512;
/// One sector per cluster: FAT16 by its cluster count, and small enough to copy per cut.
const TOTAL: usize = 4200;
const ROOT_ENTRIES: usize = 32;
const RESERVED: usize = 1;
const FATS: usize = 2;
/// Operations one script runs, at most.
const MAX_OPS: usize = 48;
/// Cut points replayed per script, at most, evenly spread over its writes.
const MAX_CUTS: usize = 48;
/// The files a script names, in the root.
const NAMES: [&[u8]; 4] = [b"A.BIN", b"B.BIN", b"C.BIN", b"D.BIN"];

/// A seed, a script built from scratch, or the start of an image, then usually corrupted.
pub fn generate(rng: &mut Rng, seeds: &[Vec<u8>]) -> Vec<u8> {
    let mut bytes = match rng.below(3) {
        0 if !seeds.is_empty() => rng.pick(seeds).clone(),
        1 => {
            let mut image = vec![1u8];
            // The boot sector, both tables, the root and the first clusters of a volume with
            // something on it, so a mutation lands in structure rather than in zeros.
            let volume = populated();
            image.extend_from_slice(&volume[..64 * SECTOR]);
            image
        }
        _ => {
            let ops = 1 + rng.below(MAX_OPS);
            let mut script = vec![0u8];
            script.extend((0..ops * 4).map(|_| rng.next_u32() as u8));
            script
        }
    };
    if !rng.one_in(8) {
        Mutator::mutate(rng, &mut bytes);
    }
    bytes
}

/// Whether the input got past the first check: every script does, and an image that mounts.
pub fn accepts(input: &[u8]) -> bool {
    match input.split_first() {
        Some((mode, rest)) if mode & 1 == 1 => {
            let disk = Disk::new(padded(rest));
            with_volume(&disk, 8, |_| ()).is_some()
        }
        Some(_) => true,
        None => false,
    }
}

pub fn run(input: &[u8]) {
    match input.split_first() {
        Some((mode, rest)) if mode & 1 == 1 => image(rest),
        Some((_, rest)) => script(rest),
        None => {}
    }
}

/// A disk in memory that records every block written to it.
struct Disk {
    data: RefCell<Vec<u8>>,
    log: RefCell<Vec<(u64, Vec<u8>)>>,
}

impl Disk {
    fn new(image: Vec<u8>) -> Disk {
        Disk {
            data: RefCell::new(image),
            log: RefCell::new(Vec::new()),
        }
    }
}

impl BlockDevice for Disk {
    fn geometry(&self) -> Geometry {
        Geometry::new(SECTOR, (self.data.borrow().len() / SECTOR) as u64)
            .expect("the fuzzer's disks are always whole sectors")
    }

    fn max_transfer_blocks(&self) -> u64 {
        16
    }

    fn read_blocks(&self, lba: u64, into: &mut [u8]) -> Result<(), BlockError> {
        self.geometry().range(lba, into.len())?;
        let at = lba as usize * SECTOR;
        into.copy_from_slice(&self.data.borrow()[at..at + into.len()]);
        Ok(())
    }

    fn write_blocks(&self, lba: u64, from: &[u8]) -> Result<(), BlockError> {
        self.geometry().range(lba, from.len())?;
        let at = lba as usize * SECTOR;
        self.data.borrow_mut()[at..at + from.len()].copy_from_slice(from);
        self.log.borrow_mut().push((lba, from.to_vec()));
        Ok(())
    }

    fn flush(&self) -> Result<(), BlockError> {
        Ok(())
    }
}

fn fat_sectors() -> usize {
    let root = ROOT_ENTRIES * 32 / SECTOR;
    let mut fat = 1;
    while fat * SECTOR / 2 < TOTAL - RESERVED - FATS * fat - root + 2 {
        fat += 1;
    }
    fat
}

/// An empty volume.
fn format() -> Vec<u8> {
    let mut v = vec![0u8; TOTAL * SECTOR];
    let fat = fat_sectors();
    v[0..3].copy_from_slice(&[0xEB, 0x3C, 0x90]);
    v[11..13].copy_from_slice(&(SECTOR as u16).to_le_bytes());
    v[13] = 1;
    v[14..16].copy_from_slice(&(RESERVED as u16).to_le_bytes());
    v[16] = FATS as u8;
    v[17..19].copy_from_slice(&(ROOT_ENTRIES as u16).to_le_bytes());
    v[19..21].copy_from_slice(&(TOTAL as u16).to_le_bytes());
    v[21] = 0xF8;
    v[22..24].copy_from_slice(&(fat as u16).to_le_bytes());
    v[510..512].copy_from_slice(&[0x55, 0xAA]);
    for copy in 0..FATS {
        let at = (RESERVED + copy * fat) * SECTOR;
        v[at..at + 4].copy_from_slice(&[0xF8, 0xFF, 0xFF, 0xFF]);
    }
    v
}

/// An empty volume with a directory and a few files written into it by the driver.
fn populated() -> Vec<u8> {
    let disk = Disk::new(format());
    let _ = with_volume(&disk, 16, |fat| {
        let root = fat.root();
        if let Ok(dir) = fat.create(root, b"DIR", Kind::Dir) {
            for (i, name) in NAMES.iter().enumerate() {
                if let Ok(node) = fat.create(dir, name, Kind::File) {
                    let _ = fat.write_at(node, 0, &vec![i as u8 + 1; 700 * (i + 1)]);
                }
            }
        }
        let _ = fat.sync();
    });
    disk.data.into_inner()
}

fn padded(bytes: &[u8]) -> Vec<u8> {
    let mut v = vec![0u8; TOTAL * SECTOR];
    let n = bytes.len().min(v.len());
    v[..n].copy_from_slice(&bytes[..n]);
    v
}

/// Mount the volume `disk` holds through a cache of `slots` blocks and run `f` on it. `None`
/// if it does not mount.
fn with_volume<R>(disk: &Disk, slots: usize, f: impl FnOnce(&mut Fat<'_, '_>) -> R) -> Option<R> {
    let mut slot_array = vec![Slot::EMPTY; slots];
    let mut data = vec![0u8; slots * SECTOR];
    let cache = Cache::new(&mut slot_array, &mut data, SECTOR)?;
    let mut fat = Fat::mount(disk, cache, 0).ok()?;
    Some(f(&mut fat))
}

fn walk(fat: &mut Fat<'_, '_>) -> Result<Consistency, Error> {
    let mut seen = vec![0u8; (fat.clusters() as usize + 2).div_ceil(8)];
    fat.check_consistency(&mut seen)
}

/// Mount, walk, read and write an image made of whatever bytes arrived.
fn image(bytes: &[u8]) {
    let disk = Disk::new(padded(bytes));
    let _ = with_volume(&disk, 8, |fat| {
        let before = walk(fat);
        let root = fat.root();
        let mut buf = [0u8; 256];
        for i in 0..16 {
            match fat.readdir(root, i) {
                Ok(Some(entry)) => {
                    let _ = fat.read_at(entry.node, 0, &mut buf);
                }
                _ => break,
            }
        }
        let made = fat.create(root, b"FUZZ.BIN", Kind::File);
        let wrote = made.and_then(|node| {
            fat.write_at(node, 0, &[0xAB; 1500])?;
            fat.truncate(node, 100)?;
            fat.write_at(node, 3000, b"past the end")?;
            Ok(node)
        });
        let removed = fat.unlink(root, b"FUZZ.BIN");
        let _ = fat.sync();
        // Writes that succeeded on a volume that walked clean leave it walking clean.
        if before.is_ok() && wrote.is_ok() && removed.is_ok() {
            if let Err(e) = walk(fat) {
                panic!(
                    "a consistent volume became inconsistent after writes that succeeded: {e:?}"
                );
            }
        }
    });
}

/// What the model says one file holds, and the driver's node for it.
type Model = [Option<Vec<u8>>; NAMES.len()];

/// Run a script on an empty volume, checking after every operation, then replay its writes
/// cut at every point.
fn script(ops: &[u8]) {
    let base = format();
    let disk = Disk::new(base.clone());
    let mut model: Model = [const { None }; NAMES.len()];
    let mounted = with_volume(&disk, 5, |fat| {
        let root = fat.root();
        let mut dir = false;
        for op in ops.chunks(4).take(MAX_OPS) {
            let mut b = [0u8; 4];
            b[..op.len()].copy_from_slice(op);
            let k = usize::from(b[1]) % NAMES.len();
            apply(fat, root, &mut model, &mut dir, b, k);
            check(fat, root, &model, b);
        }
        if let Err(e) = fat.sync() {
            panic!("the final sync failed: {e:?}");
        }
    });
    if mounted.is_none() {
        panic!("a freshly formatted volume did not mount");
    }

    // Every point a power cut could stop the device, evenly sampled.
    let log = disk.log.borrow().clone();
    let step = (log.len() / MAX_CUTS).max(1);
    for cut in (0..=log.len()).step_by(step) {
        let mut image = base.clone();
        for (lba, bytes) in &log[..cut] {
            let at = *lba as usize * SECTOR;
            image[at..at + bytes.len()].copy_from_slice(bytes);
        }
        let crashed = Disk::new(image);
        let walked = with_volume(&crashed, 8, walk);
        match walked {
            Some(Ok(_)) => {}
            Some(Err(e)) => {
                panic!("after {cut} of {} writes the volume is inconsistent: {e:?}", log.len())
            }
            None => panic!("after {cut} of {} writes the volume does not mount", log.len()),
        }
    }
}

/// One operation, `b` its four bytes and `k` the file it names, checked against the model.
fn apply(
    fat: &mut Fat<'_, '_>,
    root: u64,
    model: &mut Model,
    dir: &mut bool,
    b: [u8; 4],
    k: usize,
) {
    let name = NAMES[k];
    let wide = usize::from(u16::from_le_bytes([b[2], b[3]]));
    match b[0] % 7 {
        0 => match (&model[k], fat.create(root, name, Kind::File)) {
            (None, Ok(_)) => model[k] = Some(Vec::new()),
            (Some(_), Err(Error::Exists)) => {}
            (m, r) => panic!("create {name:?} with the model {}: {r:?}", m.is_some()),
        },
        1 => {
            let offset = wide % 3000;
            let len = usize::from(b[0]) * 7 % 1500 + 1;
            let data: Vec<u8> = (0..len).map(|i| (i as u8) ^ b[1] ^ b[2]).collect();
            match (&mut model[k], fat.lookup(root, name)) {
                (Some(content), Ok(node)) => match fat.write_at(node, offset as u64, &data) {
                    Ok(n) if n == len => {
                        if content.len() < offset + len {
                            content.resize(offset + len, 0);
                        }
                        content[offset..offset + len].copy_from_slice(&data);
                    }
                    r => panic!("write {len} bytes at {offset} of {name:?}: {r:?}"),
                },
                (None, Err(Error::NotFound)) => {}
                (m, r) => panic!("look up {name:?} with the model {}: {r:?}", m.is_some()),
            }
        }
        2 => {
            let len = wide % 4000;
            if let (Some(content), Ok(node)) = (&mut model[k], fat.lookup(root, name)) {
                match fat.truncate(node, len as u64) {
                    Ok(()) => content.resize(len, 0),
                    r => panic!("truncate {name:?} to {len}: {r:?}"),
                }
            }
        }
        3 => match (model[k].is_some(), fat.unlink(root, name)) {
            (true, Ok(())) => model[k] = None,
            (false, Err(Error::NotFound)) => {}
            (m, r) => panic!("unlink {name:?} with the model {m}: {r:?}"),
        },
        4 => {
            let j = usize::from(b[2]) % NAMES.len();
            match (model[k].is_some(), fat.rename(root, name, root, NAMES[j])) {
                (true, Ok(())) if j != k => model[j] = model[k].take(),
                (true, Ok(())) => {}
                (false, Err(Error::NotFound)) => {}
                (m, r) => panic!("rename {name:?} to {:?} with the model {m}: {r:?}", NAMES[j]),
            }
        }
        5 => {
            if let Err(e) = fat.sync() {
                panic!("sync: {e:?}");
            }
        }
        _ => {
            if *dir {
                match fat.unlink(root, b"DIR") {
                    Ok(()) => *dir = false,
                    r => panic!("remove the empty directory: {r:?}"),
                }
            } else {
                match fat.create(root, b"DIR", Kind::Dir) {
                    Ok(_) => *dir = true,
                    r => panic!("make the directory: {r:?}"),
                }
            }
        }
    }
}

/// The volume walks clean with nothing lost, and every file holds what the model says.
fn check(fat: &mut Fat<'_, '_>, root: u64, model: &Model, op: [u8; 4]) {
    match walk(fat) {
        Ok(c) if c.lost == 0 && c.fats_differ == 0 => {}
        r => panic!("after operation {op:?} the volume walks {r:?}"),
    }
    let mut buf = vec![0u8; 8000];
    for (k, expected) in model.iter().enumerate() {
        match (expected, fat.lookup(root, NAMES[k])) {
            (Some(content), Ok(node)) => {
                let n = fat.read_at(node, 0, &mut buf).unwrap_or(usize::MAX);
                if n != content.len() || buf[..n] != content[..] {
                    panic!("after operation {op:?} {:?} does not hold what was written", NAMES[k]);
                }
            }
            (None, Err(Error::NotFound)) => {}
            (m, r) => panic!(
                "after operation {op:?} {:?} with the model {}: {r:?}",
                NAMES[k],
                m.is_some()
            ),
        }
    }
}

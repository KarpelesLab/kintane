//! Filesystem traffic against the test disk's volume, alongside everything else.
//!
//! One thread opens a random file through a namespace, reads a random range, checks it
//! against what kbuild wrote, and closes it; now and then it lists the root, and now and
//! then it drops the whole cache so the next reads go back to the disk. The volume's cache
//! holds fewer blocks than `/BIG.BIN` has clusters, so this is a cache under pressure, and
//! the disk it reads is the same one the block workload is writing at the same time.
//!
//! It writes too: a scratch file in `/SUB` grows by appends, is read back against the bytes it
//! was written with, is cut short, and is removed and made again. Every iteration that writes
//! syncs before it gives the volume back, so between iterations nothing is waiting in the
//! cache.
//!
//! At a checkpoint it holds nothing: every handle it opened is closed, so opens and closes
//! must balance, the cache's books must hold with no block left unwritten, and the volume
//! must pass the consistency walk with no cluster lost and its two tables the same.
//!
//! Present only when the filesystem check mounted the volume. On a machine without it, the
//! workload is not spawned and the auditor does not ask it for progress.

use core::sync::atomic::{AtomicU64, Ordering};

use block::testdisk;
use time::Duration;
use vfs::{Error, OpenFlags, Vfs, Whence};

use super::{Parked, Rng, Workload, after_ms, checkpoint, fail, park_requested, progress};
use crate::preempt::{begin, sleep_until};
use crate::timekeeping;

/// How long the auditor waits for the file server to give the volume back.
const LEASE_PATIENCE: Duration = Duration::from_nanos(1_000_000_000);

/// Handles opened and closed, for the audit.
static OPENED: AtomicU64 = AtomicU64::new(0);
static CLOSED: AtomicU64 = AtomicU64::new(0);
/// File bytes read and checked, and times the cache was dropped, for the heartbeat.
static CHECKED_BYTES: AtomicU64 = AtomicU64::new(0);
static DROPS: AtomicU64 = AtomicU64::new(0);
/// The cache's counters, copied by the audit while the workload is parked, so the heartbeat
/// can print them without touching the volume while it runs.
static HITS: AtomicU64 = AtomicU64::new(0);
static MISSES: AtomicU64 = AtomicU64::new(0);

/// Every this many iterations the whole cache is dropped.
const DROP_EVERY: u64 = 64;

/// The file the workload writes, the seed of its bytes, and the size past which it is cut
/// short rather than grown.
const SCRATCH: &str = "/SUB/STRESS.TMP";
const SCRATCH_SEED: u8 = 0x53;
const SCRATCH_MAX: u64 = 24_000;

/// Whether the machine has the volume this workload reads.
pub fn present() -> bool {
    crate::fs::mounted()
}

pub fn opens() -> u64 {
    OPENED.load(Ordering::Relaxed)
}

pub fn checked_bytes() -> u64 {
    CHECKED_BYTES.load(Ordering::Relaxed)
}

pub fn cache_counters() -> (u64, u64, u64) {
    (
        HITS.load(Ordering::Relaxed),
        MISSES.load(Ordering::Relaxed),
        DROPS.load(Ordering::Relaxed),
    )
}

/// Ready to run: a mounted volume whose cache's books hold.
pub fn setup() -> Result<(), &'static str> {
    if !present() {
        return Ok(());
    }
    // No workload thread exists yet; the file server may be answering a request, and the lease
    // waits for it.
    let Some(fat) = crate::fs::lease(None) else {
        return Ok(());
    };
    fat.check_cache()
        .map_err(|_| "the volume's cache is inconsistent before the run")
}

/// Every handle closed, the cache's books balanced with nothing unwritten, and the volume
/// consistent. Called with the thread parked.
pub fn audit() -> Result<(), &'static str> {
    if !present() {
        return Ok(());
    }
    if OPENED.load(Ordering::Acquire) != CLOSED.load(Ordering::Acquire) {
        return Err("a handle is still open with the workload parked (a leak)");
    }
    // The workload thread is parked at a checkpoint, between iterations, so it holds no lease;
    // the file server may hold one for the request it is answering.
    let deadline = timekeeping::now().saturating_add(LEASE_PATIENCE);
    let Some(mut fat) = crate::fs::lease(Some(deadline)) else {
        return Err("the volume stayed leased for a second with the workload parked");
    };
    fat.check_cache()?;
    if fat.dirty_blocks() != 0 {
        return Err("blocks written to the volume's cache never reached the disk");
    }
    match crate::fs::consistency(&mut fat) {
        Ok(c) if c.lost == 0 && c.fats_differ == 0 => {}
        Ok(_) => {
            return Err("the volume lost a cluster, or its tables differ, with every write synced");
        }
        Err(_) => return Err("the volume failed the consistency walk"),
    }
    let s = fat.cache_stats();
    HITS.store(s.hits, Ordering::Relaxed);
    MISSES.store(s.misses, Ordering::Relaxed);
    Ok(())
}

pub extern "C" fn worker(_: usize) -> ! {
    begin();
    let w = Workload::Fs;
    let mut rng = Rng::new(0xF5F5);
    if !present() {
        fail(w, "spawned without a volume");
        loop {
            sleep_until(after_ms(1000));
        }
    }
    let mut buf = [0u8; 512];
    let mut small = [0u8; 64];
    let mut iterations = 0u64;
    loop {
        if park_requested() {
            // Between iterations every handle is closed, every write synced and the volume
            // given back, so there is nothing to hold.
            checkpoint(w, Parked::Empty);
        }

        {
            // The volume for this iteration only: the file server takes its turns in between.
            let Some(mut fat) = crate::fs::lease(None) else {
                fail(w, "the volume could not be leased");
                sleep_until(after_ms(1000));
                continue;
            };
            {
                let mut ns = Vfs::<1, 2>::new();
                if ns.mount("/", &mut *fat).is_err() {
                    fail(w, "the volume could not be mounted in a namespace");
                } else {
                    match rng.below(6) {
                        0 | 1 => read_big(w, &mut ns, &mut rng, &mut buf),
                        2 => read_small(w, &mut ns, &mut rng, &mut small),
                        3 => list_root(w, &mut ns),
                        4 => write_scratch(w, &mut ns, &mut rng, &mut buf),
                        _ => check_scratch(w, &mut ns, &mut buf),
                    }
                    if ns.open_count() != 0 {
                        fail(w, "a handle was left open at the end of an iteration");
                    }
                    if ns.sync().is_err() {
                        fail(w, "syncing the volume failed");
                    }
                }
            }
            iterations += 1;
            if iterations % DROP_EVERY == 0 {
                fat.invalidate_cache();
                DROPS.fetch_add(1, Ordering::Relaxed);
            }
        }
        progress(w);
        sleep_until(after_ms(1));
    }
}

/// A random range of `/BIG.BIN`, checked byte for byte.
fn read_big(w: Workload, ns: &mut Vfs<'_, 1, 2>, rng: &mut Rng, buf: &mut [u8; 512]) {
    let fd = match ns.open_with("/BIG.BIN", OpenFlags::READ) {
        Ok(fd) => fd,
        Err(_) => return fail(w, "opening /BIG.BIN failed"),
    };
    OPENED.fetch_add(1, Ordering::Relaxed);
    let offset = rng.below(testdisk::BIG_LEN as u64) as usize;
    let want = (1 + rng.below(buf.len() as u64) as usize).min(testdisk::BIG_LEN - offset);
    let read = ns
        .seek(fd, Whence::Start, offset as i64)
        .and_then(|_| ns.read(fd, &mut buf[..want]));
    match read {
        Ok(n) if n == want => {
            let wrong = buf[..n]
                .iter()
                .enumerate()
                .any(|(i, &b)| b != testdisk::big_byte(offset + i));
            if wrong {
                fail(w, "/BIG.BIN read back something kbuild did not write");
            } else {
                CHECKED_BYTES.fetch_add(n as u64, Ordering::Relaxed);
            }
        }
        Ok(_) => fail(w, "a read inside /BIG.BIN came back short"),
        Err(_) => fail(w, "a read of /BIG.BIN failed"),
    }
    if ns.close(fd).is_ok() {
        CLOSED.fetch_add(1, Ordering::Relaxed);
    } else {
        fail(w, "closing /BIG.BIN failed");
    }
}

/// One of the small files, whole.
fn read_small(w: Workload, ns: &mut Vfs<'_, 1, 2>, rng: &mut Rng, small: &mut [u8; 64]) {
    let (path, want): (&str, &[u8]) = if rng.below(2) == 0 {
        ("/HELLO.TXT", testdisk::HELLO)
    } else {
        ("/SUB/NESTED.TXT", testdisk::NESTED)
    };
    // `read_all` opens and closes inside the namespace, so it is counted as both.
    OPENED.fetch_add(1, Ordering::Relaxed);
    let result = ns.read_all(path, small);
    CLOSED.fetch_add(1, Ordering::Relaxed);
    match result {
        Ok(n) if &small[..n] == want => {
            CHECKED_BYTES.fetch_add(n as u64, Ordering::Relaxed);
        }
        Ok(_) => fail(w, "a small file read back something kbuild did not write"),
        Err(Error::Corrupt(_)) => fail(w, "a small file came back corrupt"),
        Err(_) => fail(w, "reading a small file failed"),
    }
}

/// The root lists a stable number of names: the scratch file lives in `/SUB`, so writing never
/// changes it.
fn list_root(w: Workload, ns: &mut Vfs<'_, 1, 2>) {
    let want = if kconfig::USERSPACE { 4 } else { 3 };
    let mut count = 0usize;
    loop {
        match ns.readdir("/", count) {
            Ok(Some(_)) => count += 1,
            Ok(None) => break,
            Err(_) => return fail(w, "listing / failed"),
        }
    }
    if count != want {
        fail(w, "the root listed a different number of names");
    }
}

/// Grow the scratch file by an append of its own bytes; or, once it is large, cut it short;
/// and now and then remove it, so the next append makes it again.
fn write_scratch(w: Workload, ns: &mut Vfs<'_, 1, 2>, rng: &mut Rng, buf: &mut [u8; 512]) {
    if rng.below(16) == 0 {
        match ns.unlink(SCRATCH) {
            Ok(()) | Err(Error::NotFound) => {}
            Err(_) => fail(w, "removing the scratch file failed"),
        }
        return;
    }
    let flags = OpenFlags {
        write: true,
        create: true,
        append: true,
        ..OpenFlags::READ
    };
    let fd = match ns.open_with(SCRATCH, flags) {
        Ok(fd) => fd,
        Err(_) => return fail(w, "opening the scratch file to write failed"),
    };
    OPENED.fetch_add(1, Ordering::Relaxed);
    let wrote = ns.fstat(fd).and_then(|stat| {
        if stat.len >= SCRATCH_MAX {
            return ns.truncate(fd, rng.below(stat.len));
        }
        let len = 1 + rng.below(buf.len() as u64) as usize;
        for (i, b) in buf[..len].iter_mut().enumerate() {
            *b = testdisk::out_byte(SCRATCH_SEED, stat.len as usize + i);
        }
        ns.write(fd, &buf[..len]).map(|_| ())
    });
    if wrote.is_err() {
        fail(w, "writing the scratch file failed");
    }
    if ns.close(fd).is_ok() {
        CLOSED.fetch_add(1, Ordering::Relaxed);
    } else {
        fail(w, "closing the scratch file failed");
    }
}

/// The scratch file holds exactly the bytes it was written with, however it was grown, cut
/// short and made again.
fn check_scratch(w: Workload, ns: &mut Vfs<'_, 1, 2>, buf: &mut [u8; 512]) {
    let fd = match ns.open_with(SCRATCH, OpenFlags::READ) {
        Ok(fd) => fd,
        Err(Error::NotFound) => return,
        Err(_) => return fail(w, "opening the scratch file to read failed"),
    };
    OPENED.fetch_add(1, Ordering::Relaxed);
    let mut offset = 0usize;
    loop {
        match ns.read(fd, buf) {
            Ok(0) => break,
            Ok(n) => {
                let wrong = buf[..n]
                    .iter()
                    .enumerate()
                    .any(|(i, &b)| b != testdisk::out_byte(SCRATCH_SEED, offset + i));
                if wrong {
                    fail(w, "the scratch file read back something it was not written with");
                    break;
                }
                offset += n;
                CHECKED_BYTES.fetch_add(n as u64, Ordering::Relaxed);
            }
            Err(_) => {
                fail(w, "reading the scratch file failed");
                break;
            }
        }
    }
    if ns.close(fd).is_ok() {
        CLOSED.fetch_add(1, Ordering::Relaxed);
    } else {
        fail(w, "closing the scratch file failed");
    }
}

//! The filesystem check: the namespace, the block cache and the FAT reader, over the disk
//! the block check brought up.
//!
//! What the check proves, on the real device and on the volume kbuild actually wrote —
//! which the host tests cannot, since their volumes come from a builder of their own:
//!
//! * the volume mounts from where the disk format says it starts, and its geometry is FAT16;
//! * the root lists exactly the names kbuild placed there, `.`, `..` and the label hidden;
//! * `/HELLO.TXT`, `/SUB/NESTED.TXT` and the 196-cluster `/BIG.BIN` read back byte for byte, the
//!   last through a chain walk;
//! * reading at or past a file's end gives nothing, and a buffer too small for a file is refused
//!   rather than filled with a truncated copy;
//! * a block written through a cache is what the next read of it sees, from the cache and from the
//!   device;
//! * the cache's books balance, and every handle opened was closed;
//! * with userspace, `/KINTANE/INIT.ELF` loads from the volume and runs to the exit code a program
//!   that saw everything behave returns. From then on the kernel's later process checks run that
//!   program rather than the copy embedded in the image.
//!
//! The mounted volume outlives the check: a [`lease`] is how the file server and the stress run
//! reach it.

use core::cell::{SyncUnsafeCell, UnsafeCell};
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicBool, Ordering};

use arch::Cpu;
use bcache::Storage;
use block::BlockDevice;
use block::testdisk::{self, SECTOR};
use fat::Fat;
use hal::{EarlyConsole, PhysAddr};
use mm::phys::FrameAllocator;
use time::{Duration, Instant};
use vfs::{Error, Kind, OpenFlags, Vfs, Whence};

use crate::{Check, Live, preempt, timekeeping, write_usize};

/// Blocks the volume's cache holds. Fewer than `/BIG.BIN` has clusters, so reading it
/// replaces slots and the check sees a cache under pressure rather than one that holds
/// everything.
const CACHE_SLOTS: usize = 32;

/// Pages for the program read from the disk. The embedded `init` is a little over 110 KiB;
/// this is room for it with slack, taken from the boot allocator and kept.
const PROGRAM_PAGES: usize = 64;

/// The scratch sector the write-through check writes: the last one, which the block
/// workload's runs reach least often.
const PROBE_LBA: u64 = testdisk::SCRATCH_START + testdisk::SCRATCH_SECTORS - 1;

/// The volume's cache.
///
/// SAFETY INVARIANT: borrowed once, by [`check`], which hands the cache to the volume it
/// mounts; nothing reaches the storage except through that volume afterwards.
static CACHE: SyncUnsafeCell<Storage<CACHE_SLOTS, SECTOR>> = SyncUnsafeCell::new(Storage::new());

/// A small cache of its own for the write-through check, so that check can prove what it
/// claims without touching the volume's.
///
/// SAFETY INVARIANT: borrowed only by [`write_through`], which runs once on the boot path.
static PROBE: SyncUnsafeCell<Storage<4, SECTOR>> = SyncUnsafeCell::new(Storage::new());

/// A chunk of `/BIG.BIN` at a time, off the 16 KiB boot stack.
///
/// SAFETY INVARIANT: borrowed only by [`contents`], on the boot path.
static CHUNK: SyncUnsafeCell<[u8; 4096]> = SyncUnsafeCell::new([0; 4096]);

/// The mounted volume, kept for the file server and the stress run.
///
/// Not a `SyncUnsafeCell`: a volume holds a `&dyn BlockDevice`, which is not `Sync`, so the
/// compiler cannot vouch for sharing it and the invariant below is what does.
struct Volume(UnsafeCell<Option<Fat<'static, 'static>>>);

// SAFETY: written once, by `check`, before `MOUNTED` is set. After that it is reached through
// `volume`, on the boot path before any other thread can use the volume, or through a `Lease`,
// which one thread holds at a time: the file server for one request, the stress run's
// filesystem workload for one iteration, its auditor for one audit. So no two borrows are ever
// live at once, and the device it holds is itself shared-safe (its driver locks).
unsafe impl Sync for Volume {}

static VOLUME: Volume = Volume(UnsafeCell::new(None));
static MOUNTED: AtomicBool = AtomicBool::new(false);

/// Whether the check mounted the volume. Reads nothing but a flag, so any thread may ask
/// without borrowing the volume.
pub fn mounted() -> bool {
    MOUNTED.load(Ordering::Acquire)
}

/// The mounted volume, once the check has mounted it.
///
/// # Safety
/// The caller is on the boot path, before the file server or the stress run has started: no
/// other thread may use the volume. Everything after takes a [`lease`]. See [`Volume`]'s
/// invariant.
#[cfg_attr(
    not(CONFIG_ABI_LINUX),
    expect(
        dead_code,
        reason = "the Linux personality's check is the one boot-path user left"
    )
)]
pub unsafe fn volume() -> Option<&'static mut Fat<'static, 'static>> {
    if !MOUNTED.load(Ordering::Acquire) {
        return None;
    }
    // SAFETY: `MOUNTED` is set only after the one write; the caller upholds exclusivity.
    unsafe { (*VOLUME.0.get()).as_mut() }
}

/// Whether a [`Lease`] on the volume is held.
static LEASED: AtomicBool = AtomicBool::new(false);

/// How often a thread waiting for the volume looks again.
const LEASE_POLL: Duration = Duration::from_nanos(1_000_000);

/// Bits for [`consistency`]: one per cluster of the test disk's volume, with room to spare.
const BITMAP_BYTES: usize = 2048;

/// SAFETY INVARIANT: borrowed only by [`consistency`], while [`BITMAP_BUSY`] is held.
static BITMAP: SyncUnsafeCell<[u8; BITMAP_BYTES]> = SyncUnsafeCell::new([0; BITMAP_BYTES]);
static BITMAP_BUSY: AtomicBool = AtomicBool::new(false);

/// Walk `volume` for what a crash must never leave — see `fat::Fat::check_consistency` — with
/// a bitmap of this module's, so no caller needs a kilobyte of stack for one.
/// [`Error::Device`] if another thread is walking at the same moment.
pub fn consistency(volume: &mut Fat<'_, '_>) -> Result<fat::Consistency, Error> {
    if BITMAP_BUSY
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return Err(Error::Device("another consistency walk holds the bitmap"));
    }
    // SAFETY: see `BITMAP`: the claim is this thread's.
    let result = volume.check_consistency(unsafe { &mut *BITMAP.get() });
    BITMAP_BUSY.store(false, Ordering::Release);
    result
}

/// The volume, held by one thread until this is dropped.
///
/// Every user of the volume once other threads can run takes one: the file server for each
/// request, the stress run's filesystem workload for each iteration, its auditor for each
/// audit. They take turns without knowing about each other, and none holds the volume while it
/// waits for anything else.
pub struct Lease {
    volume: &'static mut Fat<'static, 'static>,
}

impl Deref for Lease {
    type Target = Fat<'static, 'static>;

    fn deref(&self) -> &Self::Target {
        self.volume
    }
}

impl DerefMut for Lease {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.volume
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        LEASED.store(false, Ordering::Release);
    }
}

/// Take the volume, waiting for whoever holds it until `deadline` (`None`: for as long as it
/// takes). `None` if no volume is mounted, or if the deadline passed first. A thread waits by
/// sleeping, so one that is not on the scheduler is told `None` at once if the volume is held.
pub fn lease(deadline: Option<Instant>) -> Option<Lease> {
    if !mounted() {
        return None;
    }
    loop {
        if LEASED
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            // SAFETY: see `Volume`: the lease is this thread's, so this is the only borrow.
            return match unsafe { (*VOLUME.0.get()).as_mut() } {
                Some(volume) => Some(Lease { volume }),
                None => {
                    LEASED.store(false, Ordering::Release);
                    None
                }
            };
        }
        let now = timekeeping::now();
        if !preempt::scheduled() || deadline.is_some_and(|d| now >= d) {
            return None;
        }
        preempt::sleep_until(now.saturating_add(LEASE_POLL));
    }
}

/// What an error names, for a console with no formatter.
pub(crate) fn describe(e: Error) -> &'static str {
    match e {
        Error::NotFound => "not found",
        Error::NotADirectory => "not a directory",
        Error::IsADirectory => "a directory",
        Error::BadPath => "a bad path",
        Error::NoSuchMount => "no such mount",
        Error::MountFull => "the mount table is full",
        Error::TooManyOpen => "too many open files",
        Error::BadHandle => "a bad handle",
        Error::OutOfRange => "out of range",
        Error::ReadOnly => "read-only",
        Error::Full => "full",
        Error::Exists => "it already exists",
        Error::NotEmpty => "a directory that is not empty",
        Error::CrossDevice => "a rename between filesystems",
        Error::Corrupt(what) | Error::Device(what) => what,
    }
}

fn failed(c: &dyn EarlyConsole, doing: &str, e: Error) -> bool {
    c.write_str("; ");
    c.write_str(doing);
    c.write_str(" FAILED: ");
    c.write_str(describe(e));
    false
}

/// Mount the volume and check it.
pub fn check(c: &dyn EarlyConsole, frames: &mut FrameAllocator<'static, Cpu>, live: Live) -> Check {
    c.write_str("\n  fs         ");
    let Some(disk) = crate::block::disk() else {
        if kconfig::QEMU_BLOCK_TEST {
            c.write_str("NO DISK, though the run attached one");
            return Check::Failed;
        }
        c.write_str("skipped: no block device");
        return Check::Skipped;
    };

    // SAFETY: the one borrow of `CACHE`; see its invariant.
    let storage = unsafe { &mut *CACHE.get() };
    let Some(cache) = storage.cache() else {
        c.write_str("the cache's storage is not whole blocks");
        return Check::Failed;
    };
    let mut fat = match Fat::mount(disk, cache, testdisk::FS_START) {
        Ok(f) => f,
        Err(e) => {
            failed(c, "mounting the volume", e);
            return Check::Failed;
        }
    };
    c.write_str("FAT16 at sector ");
    write_usize(c, testdisk::FS_START as usize);

    let mut ok = true;
    {
        let mut ns = Vfs::<1, 4>::new();
        if let Err(e) = ns.mount("/", &mut fat) {
            failed(c, "mounting at /", e);
            return Check::Failed;
        }
        ok &= names(c, &mut ns);
        ok &= contents(c, &mut ns);
        ok &= load_program(c, &mut ns, frames, live);
        if ns.open_count() != 0 {
            c.write_str("; A HANDLE WAS LEFT OPEN");
            ok = false;
        }
    }
    ok &= cache_books(c, &fat);
    ok &= write_through(c, disk);
    ok &= volume_size(c, &mut fat);
    if kconfig::FS_CRASH_TEST {
        crash_writes(c, fat);
    }

    // SAFETY: the one write to `VOLUME`, before `MOUNTED` makes it reachable.
    unsafe { *VOLUME.0.get() = Some(fat) };
    MOUNTED.store(true, Ordering::Release);
    if ok {
        c.write_str(" ok");
        Check::Passed
    } else {
        Check::Failed
    }
}

/// The root lists exactly what kbuild placed there.
fn names(c: &dyn EarlyConsole, ns: &mut Vfs<'_, 1, 4>) -> bool {
    let want: &[&[u8]] = if kconfig::USERSPACE {
        &[b"BIG.BIN", b"HELLO.TXT", b"KINTANE", b"SUB"]
    } else {
        &[b"BIG.BIN", b"HELLO.TXT", b"SUB"]
    };
    let mut seen = 0usize;
    let mut index = 0usize;
    loop {
        let entry = match ns.readdir("/", index) {
            Ok(Some(e)) => e,
            Ok(None) => break,
            Err(e) => return failed(c, "listing /", e),
        };
        index += 1;
        let Some(at) = want.iter().position(|w| *w == entry.name()) else {
            c.write_str("; AN ENTRY KBUILD DID NOT WRITE: ");
            c.write_bytes(entry.name());
            return false;
        };
        if seen & (1 << at) != 0 {
            c.write_str("; LISTED TWICE: ");
            c.write_bytes(entry.name());
            return false;
        }
        seen |= 1 << at;
    }
    if seen != (1 << want.len()) - 1 {
        c.write_str("; THE ROOT IS MISSING AN ENTRY KBUILD WROTE");
        return false;
    }
    c.write_str("; / lists ");
    write_usize(c, want.len());
    true
}

/// Every file reads back, and reads at the end give nothing.
fn contents(c: &dyn EarlyConsole, ns: &mut Vfs<'_, 1, 4>) -> bool {
    let mut small = [0u8; 64];
    match ns.read_all("/HELLO.TXT", &mut small) {
        Ok(n) if &small[..n] == testdisk::HELLO => {}
        Ok(_) => {
            c.write_str("; /HELLO.TXT DOES NOT HOLD WHAT KBUILD WROTE");
            return false;
        }
        Err(e) => return failed(c, "reading /HELLO.TXT", e),
    }
    match ns.read_all("/sub/nested.txt", &mut small) {
        Ok(n) if &small[..n] == testdisk::NESTED => {}
        Ok(_) => {
            c.write_str("; /SUB/NESTED.TXT DOES NOT HOLD WHAT KBUILD WROTE");
            return false;
        }
        Err(e) => return failed(c, "reading /sub/nested.txt", e),
    }

    // `/BIG.BIN`, a chunk at a time, every byte against the function kbuild wrote it with.
    let fd = match ns.open("/BIG.BIN") {
        Ok(fd) => fd,
        Err(e) => return failed(c, "opening /BIG.BIN", e),
    };
    // SAFETY: the one borrow of `CHUNK`; see its invariant.
    let chunk = unsafe { &mut *CHUNK.get() };
    let mut offset = 0usize;
    loop {
        let n = match ns.read(fd, chunk) {
            Ok(n) => n,
            Err(e) => {
                let _ = ns.close(fd);
                return failed(c, "reading /BIG.BIN", e);
            }
        };
        if n == 0 {
            break;
        }
        if let Some(at) = chunk[..n]
            .iter()
            .enumerate()
            .position(|(i, &b)| b != testdisk::big_byte(offset + i))
        {
            let _ = ns.close(fd);
            c.write_str("; /BIG.BIN DIFFERS AT BYTE ");
            write_usize(c, offset + at);
            return false;
        }
        offset += n;
    }
    if offset != testdisk::BIG_LEN {
        let _ = ns.close(fd);
        c.write_str("; /BIG.BIN IS THE WRONG LENGTH: ");
        write_usize(c, offset);
        return false;
    }

    // At and past the end there is nothing to read, and asking must not wrap or fault.
    let past = ns
        .seek(fd, Whence::Start, testdisk::BIG_LEN as i64 + 4096)
        .and_then(|_| ns.read(fd, &mut small));
    let closed = ns.close(fd);
    match past {
        Ok(0) => {}
        Ok(_) => {
            c.write_str("; A READ PAST THE END OF /BIG.BIN RETURNED BYTES");
            return false;
        }
        Err(e) => return failed(c, "reading past the end of /BIG.BIN", e),
    }
    if let Err(e) = closed {
        return failed(c, "closing /BIG.BIN", e);
    }
    // A buffer smaller than the file is refused rather than filled with part of it.
    match ns.read_all("/BIG.BIN", &mut small) {
        Err(Error::OutOfRange) => {}
        Ok(_) => {
            c.write_str("; /BIG.BIN WAS READ INTO A BUFFER TOO SMALL FOR IT");
            return false;
        }
        Err(e) => return failed(c, "refusing a short buffer", e),
    }
    if ns.stat("/SUB").map(|s| s.kind) != Ok(Kind::Dir) {
        c.write_str("; /SUB IS NOT A DIRECTORY");
        return false;
    }
    c.write_str("; files read back, ");
    write_usize(c, testdisk::BIG_LEN / 1000);
    c.write_str(" KB through a chain");
    true
}

/// Load the program from the disk and run it.
fn load_program(
    c: &dyn EarlyConsole,
    ns: &mut Vfs<'_, 1, 4>,
    frames: &mut FrameAllocator<'static, Cpu>,
    live: Live,
) -> bool {
    if !kconfig::USERSPACE {
        // Without userspace kbuild places no program, and there is nothing to run one.
        return match ns.stat(testdisk::PROGRAM_PATH) {
            Err(Error::NotFound) => true,
            _ => {
                c.write_str("; A PROGRAM IS ON A DISK FOR A KERNEL WITHOUT USERSPACE");
                false
            }
        };
    }
    let Some(direct) = live.direct else {
        c.write_str("; no kernel address space to load a program into");
        return false;
    };
    let Ok(run) = frames.alloc_contiguous(PROGRAM_PAGES) else {
        c.write_str("; no run of frames for the program");
        return false;
    };
    let phys = run.start().start().raw();
    let len = PROGRAM_PAGES * <Cpu as hal::Arch>::PAGE_SIZE;
    let Ok(virt) = direct.to_virt(PhysAddr::new(phys)) else {
        let _ = frames.free_contiguous(run);
        c.write_str("; the program's frames are outside the direct map");
        return false;
    };
    if !direct.covers_phys(PhysAddr::new(phys + len as u64 - 1)) {
        let _ = frames.free_contiguous(run);
        c.write_str("; the program's frames run past the direct map");
        return false;
    }
    // SAFETY: the run was just taken from the frame allocator, so nothing else refers to it,
    // and the direct map maps `[phys, phys + len)` at `virt` writable. It is never freed: the
    // program read into it stays the one later process checks run.
    let buf: &'static mut [u8] =
        unsafe { core::slice::from_raw_parts_mut(virt.raw() as *mut u8, len) };

    let n = match ns.read_all(testdisk::PROGRAM_PATH, buf) {
        Ok(n) => n,
        Err(e) => return failed(c, "reading the program from the disk", e),
    };
    let bytes: &'static [u8] = &buf[..n];
    c.write_str("; ");
    c.write_str(testdisk::PROGRAM_PATH);
    c.write_str(" (");
    write_usize(c, n);
    // The program writes to the console itself, a line of its own. Ending this line first,
    // and indenting what follows, keeps its words from splitting the check's report.
    c.write_str(" bytes):\n             ");
    let outcome = run_program(c, frames, bytes);
    c.write_str("             ");
    match outcome {
        Some((_, true)) => {
            c.write_str("ran from the disk");
            set_disk_program(bytes);
            true
        }
        Some((code, false)) => {
            c.write_str("EXITED WRONG: ");
            crate::write_hex(c, code);
            false
        }
        None => {
            c.write_str("DID NOT LOAD OR RUN");
            false
        }
    }
}

#[cfg(CONFIG_USERSPACE)]
fn run_program(
    c: &dyn EarlyConsole,
    frames: &mut FrameAllocator<'static, Cpu>,
    bytes: &'static [u8],
) -> Option<(u64, bool)> {
    crate::userproc::run_disk_program(c, frames, bytes)
}

#[cfg(not(CONFIG_USERSPACE))]
fn run_program(
    _c: &dyn EarlyConsole,
    _frames: &mut FrameAllocator<'static, Cpu>,
    _bytes: &'static [u8],
) -> Option<(u64, bool)> {
    None
}

#[cfg(CONFIG_USERSPACE)]
fn set_disk_program(bytes: &'static [u8]) {
    crate::userproc::set_disk_program(bytes);
}

#[cfg(not(CONFIG_USERSPACE))]
fn set_disk_program(_bytes: &'static [u8]) {}

/// The volume was read through its cache, and the cache's books balance.
fn cache_books(c: &dyn EarlyConsole, fat: &Fat<'_, '_>) -> bool {
    if let Err(what) = fat.check_cache() {
        c.write_str("; THE CACHE'S BOOKS ARE WRONG: ");
        c.write_str(what);
        return false;
    }
    let s = fat.cache_stats();
    // Reading `/BIG.BIN` reads the table's sectors again for every cluster; a cache that
    // was never hit is not caching, and one that never missed never read the disk.
    if s.hits == 0 || s.misses == 0 || s.evictions == 0 {
        c.write_str("; THE CACHE WAS NOT EXERCISED");
        return false;
    }
    c.write_str("; cache ");
    write_usize(c, s.hits as usize);
    c.write_str(" hits, ");
    write_usize(c, s.misses as usize);
    c.write_str(" misses");
    true
}

/// What the volume says it is, against what the walk counts.
///
/// The driver keeps its free count as the table changes rather than counting on demand, so
/// this is the check that the two never drift: the walk counts free clusters from the table
/// itself, and `statfs` reports the number the driver has been keeping.
fn volume_size(c: &dyn EarlyConsole, fat: &mut Fat<'static, 'static>) -> bool {
    use vfs::FileSystem;
    let size = match fat.statfs() {
        Ok(s) => s,
        Err(e) => return failed(c, "asking the volume its size", e),
    };
    let walk = match consistency(fat) {
        Ok(k) => k,
        Err(e) => return failed(c, "walking the volume", e),
    };
    if size.block_size == 0 || size.blocks == 0 || size.free > size.blocks {
        c.write_str("; THE VOLUME'S SIZE MAKES NO SENSE");
        return false;
    }
    if size.free != u64::from(walk.free) {
        c.write_str("; THE VOLUME'S FREE COUNT IS NOT WHAT THE WALK COUNTED");
        return false;
    }
    c.write_str("; ");
    write_usize(c, size.free as usize);
    c.write_str(" of ");
    write_usize(c, size.blocks as usize);
    c.write_str(" clusters free");
    true
}

/// A block written through a cache is what the next read sees.
fn write_through(c: &dyn EarlyConsole, disk: &dyn BlockDevice) -> bool {
    // SAFETY: the one borrow of `PROBE`; see its invariant.
    let storage = unsafe { &mut *PROBE.get() };
    let Some(mut cache) = storage.cache() else {
        c.write_str("; the probe cache's storage is not whole blocks");
        return false;
    };
    let mut before = [0u8; SECTOR];
    if cache.read_blocks(disk, PROBE_LBA, &mut before).is_err() {
        c.write_str("; reading the probe sector FAILED");
        return false;
    }
    // Something the sector does not hold, so a stale copy cannot pass for the new one.
    let mut new = [0u8; SECTOR];
    for (i, b) in new.iter_mut().enumerate() {
        *b = before[i] ^ 0x5A ^ (i as u8);
    }
    if cache.write_block(disk, PROBE_LBA, &new).is_err() {
        c.write_str("; writing the probe sector FAILED");
        return false;
    }
    let mut after = [0u8; SECTOR];
    if cache.read_blocks(disk, PROBE_LBA, &mut after).is_err() || after != new {
        c.write_str("; A WRITE THROUGH THE CACHE READ BACK STALE FROM THE CACHE");
        return false;
    }
    // And from the device: forget the slot, so the read must go below.
    cache.invalidate(PROBE_LBA);
    after.fill(0);
    if cache.read_blocks(disk, PROBE_LBA, &mut after).is_err() || after != new {
        c.write_str("; A WRITE THROUGH THE CACHE DID NOT REACH THE DEVICE");
        return false;
    }
    if let Err(what) = cache.check() {
        c.write_str("; THE PROBE CACHE'S BOOKS ARE WRONG: ");
        c.write_str(what);
        return false;
    }
    c.write_str("; a write through the cache read back fresh");
    true
}

// ---- the crash test's workload -----------------------------------------------------------

/// The directory `FS_CRASH_TEST`'s workload writes, its files, and the seed of every byte it
/// writes there; mirrored in `kbuild/src/diskcheck.rs`, which checks them after each cut.
const CRASH_DIR: &str = "/CRASH";
const CRASH_FILES: [&str; 6] = [
    "/CRASH/F0.BIN",
    "/CRASH/F1.BIN",
    "/CRASH/F2.BIN",
    "/CRASH/F3.BIN",
    "/CRASH/F4.BIN",
    "/CRASH/F5.BIN",
];
const CRASH_SEED: u8 = 0x41;

/// `FS_CRASH_TEST`: write the volume for ever, for `kbuild crashtest` to cut off at a random
/// point. Every byte of every file below [`CRASH_DIR`] is `out_byte(CRASH_SEED, offset)`,
/// whichever file it was written through and however it was renamed since, so after any cut a
/// byte below a file's size that is anything else was never written there. Never returns.
fn crash_writes(c: &dyn EarlyConsole, mut fat: Fat<'static, 'static>) -> ! {
    let mut ns = Vfs::<1, 1>::new();
    if ns.mount("/", &mut fat).is_err() {
        c.write_str("\nfscrash: THE VOLUME DID NOT MOUNT\n");
        halt();
    }
    let _ = ns.mkdir(CRASH_DIR);
    let _ = ns.sync();
    c.write_str("\nfscrash: writing\n");
    // Where the cut lands decides what it catches; the operations it catches vary too.
    let mut rng = 0x2545_f491_4f6c_dd1d
        ^ timekeeping::now()
            .saturating_duration_since(Instant::from_nanos(0))
            .as_nanos() as u64;
    let mut ops = 0usize;
    loop {
        let r = xorshift(&mut rng);
        let pick = |bits: u64| CRASH_FILES[(bits % CRASH_FILES.len() as u64) as usize];
        let file = pick(r);
        let result = match (r >> 8) % 10 {
            0..=3 => crash_append(&mut ns, file, 1 + (r >> 16) % 3000),
            4 | 5 => crash_overwrite(&mut ns, file, r >> 20),
            6 => crash_truncate(&mut ns, file, r >> 24),
            7 => ns.unlink(file),
            8 => match pick(r >> 32) {
                to if to == file => Ok(()),
                to => ns.rename(file, to),
            },
            _ => ns.mkdir("/CRASH/D").or_else(|_| ns.unlink("/CRASH/D")),
        };
        // A missing file, a full volume: the workload's own business. A corrupt volume is not.
        if let Err(Error::Corrupt(what)) = result {
            c.write_str("fscrash: THE VOLUME IS CORRUPT: ");
            c.write_str(what);
            c.write_str("\n");
            halt();
        }
        if (r >> 40) % 8 == 0 {
            let _ = ns.sync();
        }
        ops += 1;
        if ops % 32 == 0 {
            c.write_str("fscrash: ");
            write_usize(c, ops);
            c.write_str(" ops\n");
        }
    }
}

fn halt() -> ! {
    loop {
        core::hint::spin_loop();
    }
}

fn xorshift(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}

/// Write `len` of the crash workload's bytes at `start` of the open file `fd`, whose position is
/// already there.
fn crash_fill(ns: &mut Vfs<'_, 1, 1>, fd: vfs::Fd, start: u64, len: u64) -> Result<(), Error> {
    let mut chunk = [0u8; 512];
    let mut done = 0u64;
    while done < len {
        let n = (len - done).min(chunk.len() as u64) as usize;
        for (i, b) in chunk[..n].iter_mut().enumerate() {
            *b = testdisk::out_byte(CRASH_SEED, (start + done) as usize + i);
        }
        ns.write(fd, &chunk[..n])?;
        done += n as u64;
    }
    Ok(())
}

/// Run `f` on `path` opened as `flags` say, closing it whatever `f` did.
fn crash_with(
    ns: &mut Vfs<'_, 1, 1>,
    path: &str,
    flags: OpenFlags,
    f: impl FnOnce(&mut Vfs<'_, 1, 1>, vfs::Fd, u64) -> Result<(), Error>,
) -> Result<(), Error> {
    let fd = ns.open_with(path, flags)?;
    let result = match ns.fstat(fd) {
        Ok(stat) => f(ns, fd, stat.len),
        Err(e) => Err(e),
    };
    let _ = ns.close(fd);
    result
}

fn crash_append(ns: &mut Vfs<'_, 1, 1>, path: &str, len: u64) -> Result<(), Error> {
    let flags = OpenFlags {
        write: true,
        create: true,
        append: true,
        ..OpenFlags::READ
    };
    crash_with(ns, path, flags, |ns, fd, size| crash_fill(ns, fd, size, len))
}

fn crash_overwrite(ns: &mut Vfs<'_, 1, 1>, path: &str, r: u64) -> Result<(), Error> {
    crash_with(ns, path, OpenFlags::READ_WRITE, |ns, fd, size| {
        if size == 0 {
            return Ok(());
        }
        let at = r % size;
        let len = (1 + (r >> 12) % 700).min(size - at);
        ns.seek(fd, Whence::Start, at as i64)?;
        crash_fill(ns, fd, at, len)
    })
}

fn crash_truncate(ns: &mut Vfs<'_, 1, 1>, path: &str, r: u64) -> Result<(), Error> {
    crash_with(ns, path, OpenFlags::READ_WRITE, |ns, fd, size| ns.truncate(fd, r % (size + 1)))
}

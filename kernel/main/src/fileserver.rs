//! The file server: a kernel thread, started once at boot and never stopped, that answers
//! `lib/vfsproto` for any process holding a channel to it.
//!
//! # A connection
//!
//! A process reaches the server through a channel of its own, which the kernel makes with
//! [`connect`] or [`connect_writable`]: one end goes into the process's table, the other to the
//! server, which adopts it. Each connection has its own open files, so a client that closes a
//! file, or ends with files still open, touches nobody else's. When the client's end closes —
//! its handle closed, or its process torn down — the server is told `PeerClosed`, forgets that
//! connection's files and closes its own end, and the channel is freed.
//!
//! # Writing is a right of the connection
//!
//! Whether a connection may change the volume is decided when the kernel makes it, not by
//! anything the client says: a request that would write — an open that creates, truncates or
//! asks for writing, a write, a truncate, an unlink, a mkdir, a rename — on a read-only
//! connection is answered `ReadOnly` before the volume is touched. Within a writable
//! connection, a file opened without the write flag is still read-only.
//!
//! # One thread, many channels
//!
//! The server blocks on a wait queue of its own, its doorbell, and every channel it has adopted
//! rings it: a send or an end closing wakes the doorbell as well as the channel's own queue
//! (`objects::ChanRef::relay_to`). A new connection rings it too. Woken, the server adopts what
//! is pending and takes one request at a time from the connections in turn, so a client that
//! sends without pause cannot starve the others. It blocks with no deadline: an idle server takes
//! no timer interrupts, which the tickless check depends on.
//!
//! # The volume
//!
//! The server holds the volume only while it answers one request, through a
//! [`crate::fs::lease`], so it and the stress run's filesystem workload share the volume a
//! request or an iteration at a time. So it keeps nothing of the volume's open between
//! requests: an open file here is a path, an offset and the flags it was opened with, and each
//! read or write opens the path in a namespace of its own, seeks, does its work and closes. That
//! costs a directory walk per request, and buys a server that never holds the volume while it
//! waits for a client. Writes reach the disk when the volume's cache must write them, and at the
//! latest when the file that made them is closed or the client asks for a `sync`.
//!
//! # What the `files` check proves
//!
//! After `waits` has read `/HELLO.TXT` through the server and torn its process down, a second
//! process — `init` in its files mode — is given a connection and reads the same file. The check
//! requires that process's success code, the same server thread still running, one new
//! connection and at least two since boot, requests answered, and every object and frame back
//! once the server has let go of the connection.
//!
//! # What the `files write` check proves
//!
//! Then `init` in its write mode is given two connections, one writable and one not. Through the
//! first it creates, writes, reads back, truncates, renames and removes files and a directory,
//! and leaves [`testdisk::NATIVE_OUT_PATH`]; through the second every write is refused. The
//! check requires its success code, and then reads the volume itself: the file it left holds
//! exactly what it wrote, the names it removed are gone, nothing is waiting in the cache, and the
//! consistency walk finds no lost cluster and the two tables the same. kbuild reads the file
//! again from the disk image after the guest exits.

use core::cell::SyncUnsafeCell;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use arch::Cpu;
use block::testdisk;
use hal::{Arch, EarlyConsole};
use kobject::handle::Handle;
use sched::ThreadId;
use sync::SpinLock;
use sync::lockdep::LockClass;
use time::Duration;
use vfs::{OpenFlags, Vfs, Whence};
use vfsproto::{Request, Status};

use crate::preempt::{self, sleep_until};
use crate::wait::WaitQueue;
use crate::{Check, objects, spawn, timekeeping, userproc, write_hex, write_usize};

/// Connections the server holds at once.
const CONNECTIONS: usize = 4;
/// Files one connection holds open at once.
const FILES: usize = 4;
/// Above process threads, so an answer is not queued behind the client that asked for it; below
/// boot.
const PRIORITY: u8 = 6;

/// `init`'s files and write modes, and their codes when every step behaved. Mirrors
/// `user/init/src/main.rs`.
const MODE_FILES: usize = 10;
const FILES_SUCCESS: u64 = 0x6e;
const MODE_WRITE: usize = 11;
const WRITE_SUCCESS: u64 = 0x6f;
/// The names `init`'s write mode makes and removes again.
const REMOVED: [&str; 3] = ["/KINTANE/NWTMP.TXT", "/KINTANE/NWREN.TXT", "/KINTANE/NWDIR"];

/// The process slot and the scheduler stack slots the checks use: `sibling` has torn its
/// process down and reaped its threads by the time they run.
const SLOT: usize = 0;
const STACKS: [usize; 3] = [1, 2, 3];

/// How long a check gives its process, and the server to let go of a connection.
const PATIENCE: Duration = Duration::from_nanos(5_000_000_000);
const POLL: Duration = Duration::from_nanos(5_000_000);

/// The server's thread, as its raw identity, or `u64::MAX` before it is started.
static THREAD: AtomicU64 = AtomicU64::new(u64::MAX);
/// Connections adopted since boot, connections held now, and requests answered since boot.
static CONNECTED: AtomicU64 = AtomicU64::new(0);
static OPEN: AtomicUsize = AtomicUsize::new(0);
static SERVED: AtomicU64 = AtomicU64::new(0);

/// What wakes the server. See the module documentation.
static DOORBELL: WaitQueue = WaitQueue::new();

static PENDING_CLASS: LockClass = LockClass::new("fileserver.pending");

/// Connections made by [`connect`] that the server has not adopted yet, and whether each may
/// write. Taken for a moment by either side, never while a channel's lock or a cell's is held.
static PENDING: SpinLock<[Option<(userproc::KernelEnd, bool)>; CONNECTIONS], Cpu> =
    SpinLock::with_class([const { None }; CONNECTIONS], &PENDING_CLASS);

/// A file one connection has open: its path, how far into it the connection has read or
/// written, and the protocol flags it was opened with.
#[derive(Clone, Copy)]
struct OpenFile {
    path: [u8; vfsproto::PAYLOAD],
    len: usize,
    offset: u64,
    flags: u8,
}

impl OpenFile {
    fn writable(&self) -> bool {
        self.flags & vfsproto::flags::WRITE != 0
    }
}

struct Connection {
    end: userproc::KernelEnd,
    writable: bool,
    files: [Option<OpenFile>; FILES],
}

/// What woke the server.
enum Work {
    /// A connection was adopted.
    Adopted,
    /// Connection `conn` sent a request of `len` bytes.
    Request { conn: usize, len: usize },
    /// Connection `conn`'s client has gone.
    Gone(usize),
}

/// Start the server, if it is not running and there is a volume to serve. Returns whether it
/// runs. On the boot thread, with the scheduler running; the first call claims its stack.
pub fn start() -> bool {
    if THREAD.load(Ordering::Acquire) != u64::MAX {
        return running().is_some();
    }
    if !crate::fs::mounted() {
        return false;
    }
    let irq = Cpu::irq_save();
    let spawned = preempt::claim_stacks(&["file server"])
        .and_then(|stack| preempt::spawn(stack, serve, 0, PRIORITY));
    // SAFETY: pairs with the `irq_save` above.
    unsafe { Cpu::irq_restore(irq) };
    match spawned {
        Some(id) => {
            THREAD.store(u64::from(id.raw()), Ordering::Release);
            true
        }
        None => false,
    }
}

/// The server's thread, while it runs.
pub fn running() -> Option<ThreadId> {
    let raw = THREAD.load(Ordering::Acquire);
    let id = ThreadId::new(u32::try_from(raw).ok()?);
    preempt::alive(id).then_some(id)
}

/// Give process `slot` a read-only connection to the server. Returns the handle its program
/// uses. Before any thread of the process runs; `None` if the server is not running or holds as
/// many connections as it can.
pub fn connect(slot: usize) -> Option<Handle> {
    connect_with(slot, false)
}

/// Give process `slot` a connection to the server that may change the volume.
pub fn connect_writable(slot: usize) -> Option<Handle> {
    connect_with(slot, true)
}

fn connect_with(slot: usize, writable: bool) -> Option<Handle> {
    running()?;
    let (given, end) = userproc::kernel_channel(slot)?;
    let refused = {
        let mut pending = PENDING.lock_irqsave();
        match pending.iter_mut().find(|p| p.is_none()) {
            Some(free) => {
                *free = Some((end, writable));
                None
            }
            None => Some(end),
        }
    };
    if refused.is_some() {
        // Dropped outside the lock: closing the kernel's end wakes its channel.
        drop(refused);
        return None;
    }
    DOORBELL.wake_all();
    Some(given)
}

/// Requests answered since boot.
pub fn served() -> u64 {
    SERVED.load(Ordering::Relaxed)
}

/// Connections adopted since boot.
pub fn connections() -> u64 {
    CONNECTED.load(Ordering::Relaxed)
}

/// Wait up to [`PATIENCE`] for the server to hold no connection, pending or adopted: a client
/// that has gone is let go of asynchronously, and a check counting objects must wait for that.
/// Returns whether it did.
pub fn settle() -> bool {
    let give_up = timekeeping::now().saturating_add(PATIENCE);
    loop {
        let idle =
            OPEN.load(Ordering::Acquire) == 0 && PENDING.lock_irqsave().iter().all(Option::is_none);
        if idle {
            return true;
        }
        if timekeeping::now() >= give_up {
            return false;
        }
        sleep_until(timekeeping::now().saturating_add(POLL));
    }
}

/// The server's thread.
extern "C" fn serve(_: usize) -> ! {
    preempt::begin();
    let mut conns: [Option<Connection>; CONNECTIONS] = [const { None }; CONNECTIONS];
    let mut request = [0u8; vfsproto::MESSAGE];
    let mut next = 0;
    loop {
        let work = DOORBELL.wait_until(None, || find_work(&mut conns, &mut request, &mut next));
        match work {
            Ok(Work::Request { conn, len }) => {
                let Some(c) = conns.get_mut(conn).and_then(Option::as_mut) else {
                    continue;
                };
                let reply = answer(c.writable, &mut c.files, request.get(..len).unwrap_or(&[]));
                SERVED.fetch_add(1, Ordering::Relaxed);
                if c.end.send(reply.as_bytes()).is_err() {
                    // A client that cannot be answered — gone, or not reading its answers — is
                    // let go of rather than left to back up.
                    let_go(&mut conns, conn);
                }
            }
            Ok(Work::Gone(conn)) => let_go(&mut conns, conn),
            Ok(Work::Adopted) | Err(_) => {}
        }
    }
}

/// Adopt a pending connection, or take one request from the next connection that has one.
/// `None` if there is nothing to do.
fn find_work(
    conns: &mut [Option<Connection>; CONNECTIONS],
    request: &mut [u8; vfsproto::MESSAGE],
    next: &mut usize,
) -> Option<Work> {
    if let Some(free) = conns.iter().position(Option::is_none) {
        let adopted = PENDING.lock_irqsave().iter_mut().find_map(Option::take);
        if let Some((end, writable)) = adopted {
            // From here every send on it rings the doorbell. A request that arrived before is
            // found below, the next time round.
            end.relay_to(&DOORBELL);
            conns[free] = Some(Connection {
                end,
                writable,
                files: [None; FILES],
            });
            OPEN.fetch_add(1, Ordering::AcqRel);
            CONNECTED.fetch_add(1, Ordering::Relaxed);
            return Some(Work::Adopted);
        }
    }
    for k in 0..CONNECTIONS {
        let i = (*next + k) % CONNECTIONS;
        let Some(conn) = conns[i].as_mut() else {
            continue;
        };
        match conn.end.try_recv(request) {
            Ok(len) => {
                *next = (i + 1) % CONNECTIONS;
                return Some(Work::Request { conn: i, len });
            }
            Err(abi::Error::ShouldWait) => {}
            Err(_) => return Some(Work::Gone(i)),
        }
    }
    None
}

/// Forget connection `conn`, closing the server's end.
fn let_go(conns: &mut [Option<Connection>; CONNECTIONS], conn: usize) {
    if conns.get_mut(conn).and_then(Option::take).is_some() {
        OPEN.fetch_sub(1, Ordering::AcqRel);
    }
}

/// The status a failed operation is answered with.
fn status_of(e: vfs::Error) -> Status {
    use vfs::Error as E;
    match e {
        E::NotFound | E::NoSuchMount => Status::NotFound,
        E::NotADirectory | E::IsADirectory => Status::WrongKind,
        E::BadPath => Status::BadName,
        E::TooManyOpen => Status::Full,
        E::BadHandle => Status::BadFile,
        E::ReadOnly => Status::ReadOnly,
        E::Full | E::MountFull => Status::NoSpace,
        E::Exists => Status::Exists,
        E::NotEmpty => Status::NotEmpty,
        E::OutOfRange | E::Corrupt(_) | E::Device(_) => Status::Io,
    }
}

/// How a file opened with protocol flags `flags` is opened again for one request: never
/// creating or truncating, which its first open did.
fn reopen_flags(flags: u8) -> OpenFlags {
    OpenFlags {
        write: flags & vfsproto::flags::WRITE != 0,
        append: flags & vfsproto::flags::APPEND != 0,
        ..OpenFlags::READ
    }
}

/// One reply to one request, on a connection that may write if `writable` says so.
fn answer(
    writable: bool,
    files: &mut [Option<OpenFile>; FILES],
    request: &[u8],
) -> vfsproto::Message {
    let Some(request) = vfsproto::parse_request(request) else {
        return vfsproto::status(Status::BadRequest, 0);
    };
    if request.writes() && !writable {
        return vfsproto::status(Status::ReadOnly, 0);
    }
    match request {
        Request::Open { path, flags } => {
            let Some(free) = files.iter().position(Option::is_none) else {
                return vfsproto::status(Status::Full, 0);
            };
            let mut stored = [0u8; vfsproto::PAYLOAD];
            let Some(into) = stored.get_mut(..path.len()) else {
                return vfsproto::status(Status::NotFound, 0);
            };
            into.copy_from_slice(path);
            let open = OpenFile {
                path: stored,
                len: path.len(),
                offset: 0,
                flags,
            };
            use vfsproto::flags as f;
            let first = OpenFlags {
                write: flags & f::WRITE != 0,
                create: flags & f::CREATE != 0,
                exclusive: flags & f::EXCLUSIVE != 0,
                truncate: flags & f::TRUNCATE != 0,
                append: flags & f::APPEND != 0,
            };
            match with_file(&open, first, |_, _| Ok(())) {
                Ok(()) => {
                    files[free] = Some(open);
                    vfsproto::status(Status::Ok, free as u8)
                }
                Err(e) => vfsproto::status(status_of(e), 0),
            }
        }
        Request::Read { file, max } => {
            let Some(Some(open)) = files.get_mut(usize::from(file)) else {
                return vfsproto::status(Status::BadFile, file);
            };
            let mut data = [0u8; vfsproto::PAYLOAD];
            // The request's own size is a program's word, so it is bounded here, not trusted.
            let want = usize::from(max).min(vfsproto::PAYLOAD);
            let offset = open.offset;
            let read = with_file(open, reopen_flags(open.flags), |ns, fd| {
                ns.seek(fd, Whence::Start, offset as i64)?;
                ns.read(fd, &mut data[..want])
            });
            match read {
                Ok(n) => {
                    open.offset += n as u64;
                    vfsproto::reply(Status::Ok, file, &data[..n])
                        .unwrap_or(vfsproto::status(Status::Io, file))
                }
                Err(e) => vfsproto::status(status_of(e), file),
            }
        }
        Request::Write { file, data } => {
            let Some(Some(open)) = files.get_mut(usize::from(file)) else {
                return vfsproto::status(Status::BadFile, file);
            };
            if !open.writable() {
                return vfsproto::status(Status::ReadOnly, file);
            }
            let offset = open.offset;
            let wrote = with_file(open, reopen_flags(open.flags), |ns, fd| {
                ns.seek(fd, Whence::Start, offset as i64)?;
                let n = ns.write(fd, data)?;
                // An appending file's writes land at its end, wherever the offset was.
                Ok((n, ns.tell(fd)?))
            });
            match wrote {
                Ok((n, now)) => {
                    open.offset = now;
                    vfsproto::written(file, n as u8)
                }
                Err(e) => vfsproto::status(status_of(e), file),
            }
        }
        Request::Seek { file, offset } => match files.get_mut(usize::from(file)) {
            Some(Some(open)) => {
                open.offset = offset;
                vfsproto::status(Status::Ok, file)
            }
            _ => vfsproto::status(Status::BadFile, file),
        },
        Request::Truncate { file, len } => {
            let Some(Some(open)) = files.get_mut(usize::from(file)) else {
                return vfsproto::status(Status::BadFile, file);
            };
            if !open.writable() {
                return vfsproto::status(Status::ReadOnly, file);
            }
            match with_file(open, reopen_flags(open.flags), |ns, fd| ns.truncate(fd, len)) {
                Ok(()) => vfsproto::status(Status::Ok, file),
                Err(e) => vfsproto::status(status_of(e), file),
            }
        }
        Request::Unlink { path } => done(with_path(path, |ns, p| ns.unlink(p))),
        Request::Mkdir { path } => done(with_path(path, |ns, p| ns.mkdir(p))),
        Request::Rename { from, to } => {
            let to = core::str::from_utf8(to).map_err(|_| vfs::Error::BadPath);
            done(to.and_then(|to| with_path(from, |ns, from| ns.rename(from, to))))
        }
        Request::Sync => done(with_ns(|ns| ns.sync())),
        Request::Close { file } => {
            match files.get_mut(usize::from(file)).and_then(Option::take) {
                // What a writer wrote reaches the disk by the time its close is answered.
                Some(open) if open.writable() => done(with_ns(|ns| ns.sync())),
                Some(_) => vfsproto::status(Status::Ok, file),
                None => vfsproto::status(Status::BadFile, file),
            }
        }
    }
}

/// A reply to an operation on no file.
fn done(result: Result<(), vfs::Error>) -> vfsproto::Message {
    match result {
        Ok(()) => vfsproto::status(Status::Ok, 0),
        Err(e) => vfsproto::status(status_of(e), 0),
    }
}

/// Lease the volume, mount it in a namespace of its own, run `f` on it, and give it back.
fn with_ns<R>(
    f: impl FnOnce(&mut Vfs<'_, 1, 1>) -> Result<R, vfs::Error>,
) -> Result<R, vfs::Error> {
    let mut volume = crate::fs::lease(None).ok_or(vfs::Error::NoSuchMount)?;
    let mut ns = Vfs::<1, 1>::new();
    ns.mount("/", &mut *volume)?;
    let result = f(&mut ns);
    let _ = ns.unmount("/");
    result
}

/// [`with_ns`], for a path a program sent.
fn with_path<R>(
    path: &[u8],
    f: impl FnOnce(&mut Vfs<'_, 1, 1>, &str) -> Result<R, vfs::Error>,
) -> Result<R, vfs::Error> {
    let path = core::str::from_utf8(path).map_err(|_| vfs::Error::BadPath)?;
    with_ns(|ns| f(ns, path))
}

/// Open `open`'s path as `flags` say in a namespace of its own, run `f` on the file, and give
/// everything back.
fn with_file<R>(
    open: &OpenFile,
    flags: OpenFlags,
    f: impl FnOnce(&mut Vfs<'_, 1, 1>, vfs::Fd) -> Result<R, vfs::Error>,
) -> Result<R, vfs::Error> {
    let path = open.path.get(..open.len).ok_or(vfs::Error::BadPath)?;
    with_path(path, |ns, path| {
        let fd = ns.open_with(path, flags)?;
        let r = f(ns, fd);
        let _ = ns.close(fd);
        r
    })
}

// ---- the checks --------------------------------------------------------------------------

/// Whether a check may run, and what it prints when it may not.
fn ready(c: &dyn EarlyConsole) -> Result<ThreadId, Check> {
    if !crate::fs::mounted() {
        // Only a machine with no disk attached may skip it; one that attached a disk and did
        // not mount it has already failed the filesystem check, and fails here too.
        c.write_str("skipped: no volume");
        return Err(if kconfig::QEMU_BLOCK_TEST {
            Check::Failed
        } else {
            Check::Skipped
        });
    }
    let Some(server) = running() else {
        c.write_str("the file server is NOT RUNNING");
        return Err(Check::Failed);
    };
    objects::init();
    if userproc::with_frames(|f| f.alloc.stats().free).is_none() {
        c.write_str("skipped: no frames for processes");
        return Err(Check::Skipped);
    }
    Ok(server)
}

/// What a check's process left behind once it has ended and been torn down.
struct Aftermath {
    ended: bool,
    settled: bool,
    same: bool,
    frames: usize,
    leaked: usize,
}

/// Run `init` in `mode` in the check's slot, with `handles` beside its console, and tear it
/// down. Its exit code, and what it left behind.
fn run_checked(
    program: &elf::Program,
    server: ThreadId,
    mode: usize,
    connections: impl FnOnce() -> Option<[Handle; 2]>,
) -> (Option<u64>, Aftermath) {
    spawn::use_stacks(&STACKS);
    let frames_before = free_frames();
    let objects_before = objects::live();

    let code = run(program, mode, connections);

    let ended = spawn::end_threads();
    if ended {
        userproc::teardown(SLOT);
    }
    let settled = settle();
    let after = Aftermath {
        ended,
        settled,
        same: running() == Some(server),
        frames: frames_before.saturating_sub(free_frames()),
        leaked: objects::live().saturating_sub(objects_before),
    };
    (code, after)
}

/// Report what a check's process left behind. Whether all of it was clean.
fn report(c: &dyn EarlyConsole, a: &Aftermath) -> bool {
    c.write_str(if a.same {
        "the same server thread"
    } else {
        "NOT THE SAME SERVER THREAD"
    });
    if !a.settled {
        c.write_str("; THE SERVER NEVER LET GO OF THE CONNECTION");
    }
    if !a.ended {
        c.write_str("; A THREAD NEVER ENDED, its process left in place");
    }
    c.write_str("; ");
    write_usize(c, a.leaked);
    c.write_str(if a.leaked == 0 {
        " objects left"
    } else {
        " OBJECTS LEAKED"
    });
    c.write_str(", ");
    write_usize(c, a.frames);
    c.write_str(if a.frames == 0 {
        " frames left"
    } else {
        " FRAMES LEAKED"
    });
    a.same && a.settled && a.ended && a.leaked == 0 && a.frames == 0
}

/// Run the `files` check. On the boot thread, with the scheduler running, after `sibling`.
pub fn check(c: &dyn EarlyConsole) -> Check {
    c.write_str("\n  files      ");
    let server = match ready(c) {
        Ok(server) => server,
        Err(check) => return check,
    };
    let Some(program) = userproc::program() else {
        c.write_str("the init program does not load");
        return Check::Failed;
    };
    let served_before = served();
    let connected_before = connections();
    let (code, after) = run_checked(&program, server, MODE_FILES, || {
        let files = connect(SLOT)?;
        Some([files, Handle::from_raw(0)])
    });
    let answered = served() - served_before;
    let connected = connections() - connected_before;

    match code {
        Some(FILES_SUCCESS) => {
            c.write_str("a second process read /HELLO.TXT through the server after waits ended")
        }
        Some(other) => {
            c.write_str("init exited ");
            write_hex(c, other);
            c.write_str(", WRONG");
        }
        None => c.write_str("init NEVER EXITED"),
    }
    c.write_str("; ");
    write_usize(c, connections() as usize);
    c.write_str(" connections since boot, ");
    write_usize(c, answered as usize);
    c.write_str(" requests answered; ");
    let clean = report(c, &after);
    if clean {
        c.write_str(" ok");
    }
    Check::from_ok(
        code == Some(FILES_SUCCESS)
            && connected == 1
            && connections() >= 2
            && answered > 0
            && clean,
    )
}

/// `/KINTANE/NATIVE.OUT` read back, off the boot stack.
///
/// SAFETY INVARIANT: borrowed only by [`write_check`], on the boot thread.
static READ_BACK: SyncUnsafeCell<[u8; testdisk::NATIVE_OUT_LEN + 1]> =
    SyncUnsafeCell::new([0; testdisk::NATIVE_OUT_LEN + 1]);

/// Run the `files write` check. On the boot thread, with the scheduler running, after `files`.
pub fn write_check(c: &dyn EarlyConsole) -> Check {
    c.write_str("\n  files write ");
    let server = match ready(c) {
        Ok(server) => server,
        Err(check) => return check,
    };
    let Some(program) = userproc::program() else {
        c.write_str("the init program does not load");
        return Check::Failed;
    };
    let connected_before = connections();
    let (code, after) = run_checked(&program, server, MODE_WRITE, || {
        Some([connect_writable(SLOT)?, connect(SLOT)?])
    });
    let connected = connections() - connected_before;
    let code_ok = code == Some(WRITE_SUCCESS);
    match code {
        Some(WRITE_SUCCESS) => c.write_str(
            "created, wrote, read back, truncated, renamed and removed through a writable \
             connection; refused through a read-only one",
        ),
        Some(other) => {
            c.write_str("init exited ");
            write_hex(c, other);
            c.write_str(", WRONG");
        }
        None => c.write_str("init NEVER EXITED"),
    }
    c.write_str("; ");
    let volume_ok = code_ok && volume_after(c);
    c.write_str("; ");
    let clean = report(c, &after);
    if volume_ok && clean && connected == 2 {
        c.write_str(" ok");
    }
    Check::from_ok(code_ok && volume_ok && clean && connected == 2)
}

/// Read the volume after `init` wrote it: what it left, what it removed, the cache and the
/// consistency walk. Whether all of it was right.
fn volume_after(c: &dyn EarlyConsole) -> bool {
    let Some(mut volume) = crate::fs::lease(Some(timekeeping::now().saturating_add(PATIENCE)))
    else {
        c.write_str("THE VOLUME COULD NOT BE LEASED");
        return false;
    };
    let dirty = volume.dirty_blocks();
    let mut ok = true;
    {
        let mut ns = Vfs::<1, 1>::new();
        if ns.mount("/", &mut *volume).is_err() {
            c.write_str("THE VOLUME COULD NOT BE MOUNTED");
            return false;
        }
        // SAFETY: the one borrow of `READ_BACK`; see its invariant.
        let buf = unsafe { &mut *READ_BACK.get() };
        match ns.read_all(testdisk::NATIVE_OUT_PATH, buf) {
            Ok(n)
                if n == testdisk::NATIVE_OUT_LEN
                    && buf[..n]
                        .iter()
                        .enumerate()
                        .all(|(i, &b)| b == testdisk::out_byte(testdisk::NATIVE_OUT_SEED, i)) =>
            {
                c.write_str(testdisk::NATIVE_OUT_PATH);
                c.write_str(" read back");
            }
            Ok(_) => {
                c.write_str(testdisk::NATIVE_OUT_PATH);
                c.write_str(" HOLDS SOMETHING ELSE");
                ok = false;
            }
            Err(_) => {
                c.write_str(testdisk::NATIVE_OUT_PATH);
                c.write_str(" WAS NOT WRITTEN");
                ok = false;
            }
        }
        if REMOVED
            .iter()
            .any(|p| ns.stat(p) != Err(vfs::Error::NotFound))
        {
            c.write_str(", A REMOVED NAME IS STILL THERE");
            ok = false;
        }
        let _ = ns.unmount("/");
    }
    if dirty != 0 {
        c.write_str(", ");
        write_usize(c, dirty);
        c.write_str(" BLOCKS NEVER WRITTEN after the sync");
        ok = false;
    }
    match crate::fs::consistency(&mut volume) {
        Ok(k) if k.lost == 0 && k.fats_differ == 0 => {
            c.write_str(", the volume consistent: ");
            write_usize(c, k.files as usize);
            c.write_str(" files, ");
            write_usize(c, k.dirs as usize);
            c.write_str(" directories, no lost cluster, the tables the same");
        }
        Ok(k) => {
            c.write_str(", THE VOLUME LOST ");
            write_usize(c, k.lost as usize);
            c.write_str(" CLUSTERS and its tables differ in ");
            write_usize(c, k.fats_differ as usize);
            ok = false;
        }
        Err(e) => {
            c.write_str(", THE VOLUME IS INCONSISTENT: ");
            c.write_str(crate::fs::describe(e));
            ok = false;
        }
    }
    ok
}

/// Build `init` in `mode` with a console and the connections `connections` makes, and wait for
/// it to end.
fn run(
    program: &elf::Program,
    mode: usize,
    connections: impl FnOnce() -> Option<[Handle; 2]>,
) -> Option<u64> {
    userproc::build(SLOT, program)?;
    let p = userproc::slot(SLOT)?;
    p.image = Some(userproc::program_image());
    let console = p.console_handle()?;
    let [first, second] = connections()?;
    let main = userproc::start(
        SLOT,
        0,
        [
            mode,
            console.raw() as usize,
            first.raw() as usize,
            second.raw() as usize,
        ],
    )?;
    let give_up = timekeeping::now().saturating_add(PATIENCE);
    while (preempt::alive(main) || userproc::threads_live(SLOT) != 0)
        && timekeeping::now() < give_up
    {
        sleep_until(timekeeping::now().saturating_add(POLL));
    }
    if preempt::alive(main) || userproc::threads_live(SLOT) != 0 {
        return None;
    }
    // Every thread has ended, so nothing else borrows the process.
    userproc::slot(SLOT).and_then(|p| p.exit)
}

fn free_frames() -> usize {
    userproc::with_frames(|f| f.alloc.stats().free).unwrap_or(0)
}

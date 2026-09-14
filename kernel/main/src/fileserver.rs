//! The file server: a kernel thread, started once at boot and never stopped, that answers
//! `lib/vfsproto` for any process holding a channel to it.
//!
//! # A connection
//!
//! A process reaches the server through a channel of its own, which the kernel makes with
//! [`connect`]: one end goes into the process's table, the other to the server, which adopts
//! it. Each connection has its own open files, so a client that closes a file, or ends with
//! files still open, touches nobody else's. When the client's end closes — its handle closed,
//! or its process torn down — the server is told `PeerClosed`, forgets that connection's files
//! and closes its own end, and the channel is freed.
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
//! requests: an open file here is a path and an offset, and each read opens the path in a
//! namespace of its own, seeks, reads and closes. That costs a directory walk per read, and buys
//! a server that never holds the volume while it waits for a client.
//!
//! # What the `files` check proves
//!
//! After `waits` has read `/HELLO.TXT` through the server and torn its process down, a second
//! process — `init` in its files mode — is given a connection and reads the same file. The check
//! requires that process's success code, the same server thread still running, one new
//! connection and at least two since boot, requests answered, and every object and frame back
//! once the server has let go of the connection.

use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use arch::Cpu;
use hal::{Arch, EarlyConsole};
use kobject::handle::Handle;
use sched::ThreadId;
use sync::SpinLock;
use sync::lockdep::LockClass;
use time::Duration;
use vfs::{Vfs, Whence};
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

/// `init`'s files mode, and its code when it read the file. Mirrors `user/init/src/main.rs`.
const MODE_FILES: usize = 10;
const FILES_SUCCESS: u64 = 0x6e;

/// The process slot and the scheduler stack slots the `files` check uses: `sibling` has torn
/// its process down and reaped its threads by the time it runs.
const SLOT: usize = 0;
const STACKS: [usize; 3] = [1, 2, 3];

/// How long the check gives its process, and the server to let go of a connection.
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

/// Connections made by [`connect`] that the server has not adopted yet. Taken for a moment by
/// either side, never while a channel's lock or a cell's is held.
static PENDING: SpinLock<[Option<userproc::KernelEnd>; CONNECTIONS], Cpu> =
    SpinLock::with_class([const { None }; CONNECTIONS], &PENDING_CLASS);

/// A file one connection has open: its path, and how far into it the connection has read.
#[derive(Clone, Copy)]
struct OpenFile {
    path: [u8; vfsproto::PAYLOAD],
    len: usize,
    offset: u64,
}

struct Connection {
    end: userproc::KernelEnd,
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

/// Give process `slot` a connection to the server. Returns the handle its program uses. Before
/// any thread of the process runs; `None` if the server is not running or holds as many
/// connections as it can.
pub fn connect(slot: usize) -> Option<Handle> {
    running()?;
    let (given, end) = userproc::kernel_channel(slot)?;
    let refused = {
        let mut pending = PENDING.lock_irqsave();
        match pending.iter_mut().find(|p| p.is_none()) {
            Some(free) => {
                *free = Some(end);
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
                let reply = answer(&mut c.files, request.get(..len).unwrap_or(&[]));
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
        if let Some(end) = adopted {
            // From here every send on it rings the doorbell. A request that arrived before is
            // found below, the next time round.
            end.relay_to(&DOORBELL);
            conns[free] = Some(Connection {
                end,
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

/// One reply to one request.
fn answer(files: &mut [Option<OpenFile>; FILES], request: &[u8]) -> vfsproto::Message {
    match vfsproto::parse_request(request) {
        None => vfsproto::status(Status::BadRequest, 0),
        Some(Request::Open { path }) => {
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
            };
            match with_file(&open, |_, _| Ok(())) {
                Ok(()) => {
                    files[free] = Some(open);
                    vfsproto::status(Status::Ok, free as u8)
                }
                Err(vfs::Error::NotFound | vfs::Error::BadPath) => {
                    vfsproto::status(Status::NotFound, 0)
                }
                Err(_) => vfsproto::status(Status::Io, 0),
            }
        }
        Some(Request::Read { file, max }) => {
            let Some(Some(open)) = files.get_mut(usize::from(file)) else {
                return vfsproto::status(Status::BadFile, file);
            };
            let mut data = [0u8; vfsproto::PAYLOAD];
            // The request's own size is a program's word, so it is bounded here, not trusted.
            let want = usize::from(max).min(vfsproto::PAYLOAD);
            let offset = open.offset;
            let read = with_file(open, |ns, fd| {
                ns.seek(fd, Whence::Start, offset as i64)?;
                ns.read(fd, &mut data[..want])
            });
            match read {
                Ok(n) => {
                    open.offset += n as u64;
                    vfsproto::reply(Status::Ok, file, &data[..n])
                        .unwrap_or(vfsproto::status(Status::Io, file))
                }
                Err(_) => vfsproto::status(Status::Io, file),
            }
        }
        Some(Request::Close { file }) => {
            match files.get_mut(usize::from(file)).and_then(Option::take) {
                Some(_) => vfsproto::status(Status::Ok, file),
                None => vfsproto::status(Status::BadFile, file),
            }
        }
    }
}

/// Lease the volume, mount it in a namespace of its own, open `open`'s path, run `f` on the
/// file, and give everything back.
fn with_file<R>(
    open: &OpenFile,
    f: impl FnOnce(&mut Vfs<'_, 1, 1>, vfs::Fd) -> Result<R, vfs::Error>,
) -> Result<R, vfs::Error> {
    let path = open
        .path
        .get(..open.len)
        .and_then(|p| core::str::from_utf8(p).ok())
        .ok_or(vfs::Error::BadPath)?;
    let mut volume = crate::fs::lease(None).ok_or(vfs::Error::NoSuchMount)?;
    let mut ns = Vfs::<1, 1>::new();
    ns.mount("/", &mut *volume)?;
    let result = ns.open(path).and_then(|fd| {
        let r = f(&mut ns, fd);
        let _ = ns.close(fd);
        r
    });
    let _ = ns.unmount("/");
    result
}

// ---- the check ---------------------------------------------------------------------------

/// Run the `files` check. On the boot thread, with the scheduler running, after `sibling`.
pub fn check(c: &dyn EarlyConsole) -> Check {
    c.write_str("\n  files      ");
    if !crate::fs::mounted() {
        // Only a machine with no disk attached may skip it; one that attached a disk and did
        // not mount it has already failed the filesystem check, and fails here too.
        c.write_str("skipped: no volume");
        return if kconfig::QEMU_BLOCK_TEST {
            Check::Failed
        } else {
            Check::Skipped
        };
    }
    let Some(server) = running() else {
        c.write_str("the file server is NOT RUNNING");
        return Check::Failed;
    };
    objects::init();
    if userproc::with_frames(|f| f.alloc.stats().free).is_none() {
        c.write_str("skipped: no frames for processes");
        return Check::Skipped;
    }
    let Some(program) = userproc::program() else {
        c.write_str("the init program does not load");
        return Check::Failed;
    };
    spawn::use_stacks(&STACKS);
    let frames_before = free_frames();
    let objects_before = objects::live();
    let served_before = served();
    let connected_before = connections();

    let code = run(&program);

    let ended = spawn::end_threads();
    if ended {
        userproc::teardown(SLOT);
    }
    let settled = settle();
    let answered = served() - served_before;
    let connected = connections() - connected_before;
    let same = running() == Some(server);
    let frames = frames_before.saturating_sub(free_frames());
    let leaked = objects::live().saturating_sub(objects_before);

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
    c.write_str(if same {
        "the same server thread"
    } else {
        "NOT THE SAME SERVER THREAD"
    });
    c.write_str(", ");
    write_usize(c, connections() as usize);
    c.write_str(" connections since boot, ");
    write_usize(c, answered as usize);
    c.write_str(" requests answered");
    if !settled {
        c.write_str("; THE SERVER NEVER LET GO OF THE CONNECTION");
    }
    if !ended {
        c.write_str("; A THREAD NEVER ENDED, its process left in place");
    }
    c.write_str("; ");
    write_usize(c, leaked);
    c.write_str(if leaked == 0 {
        " objects left"
    } else {
        " OBJECTS LEAKED"
    });
    c.write_str(", ");
    write_usize(c, frames);
    c.write_str(if frames == 0 {
        " frames left ok"
    } else {
        " FRAMES LEAKED"
    });
    Check::from_ok(
        code == Some(FILES_SUCCESS)
            && same
            && connected == 1
            && connections() >= 2
            && answered > 0
            && settled
            && ended
            && leaked == 0
            && frames == 0,
    )
}

/// Build `init` in its files mode with a console and a connection, and wait for it to end.
fn run(program: &elf::Program) -> Option<u64> {
    userproc::build(SLOT, program)?;
    let p = userproc::slot(SLOT)?;
    p.image = Some(userproc::program_image());
    let console = p.console_handle()?;
    let files = connect(SLOT)?;
    let main =
        userproc::start(SLOT, 0, [MODE_FILES, console.raw() as usize, files.raw() as usize, 0])?;
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

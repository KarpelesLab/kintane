//! A program creating a program: the check that userspace can build a process.
//!
//! Everything before this built processes in the kernel. `init` and its workers exist
//! because [`crate::userproc`] and [`crate::procs`] assembled them — which proves the
//! machinery works, and proves nothing about whether a *program* can use it. The ABI says
//! a process has no authority except through handles it holds; until a program can turn
//! handles into a running process, that sentence describes an interface nobody has.
//!
//! # What runs
//!
//! The kernel builds one process, `init` in its spawn mode, and gives it two handles: the
//! debug console, and a memory region holding the bytes of a second program, `user/child`.
//! Everything after that is `init`'s doing, through system calls:
//!
//! 1. create a channel, keeping one endpoint;
//! 2. create a process from the image;
//! 3. move the other endpoint into it, which names it in *that* process's table;
//! 4. create a completion queue and ask for the child's exit on it;
//! 5. start a thread in the child, passing it the endpoint's value there;
//! 6. exchange a message with it, then wait for its exit code.
//!
//! The child has nothing but the endpoint it was given. It says hello, waits for the
//! reply, and exits with a code of its own. `init` checks that code and exits with one the
//! kernel checks — so the kernel grades a sequence it did not perform.
//!
//! # What must hold
//!
//! * **Construction.** `init` exits with [`SPAWN_SUCCESS`]. Any step that failed gives a code
//!   naming it instead.
//! * **The child really ran.** Its message arrived and its exit code is the child's own, which
//!   `init` reports and this check requires.
//! * **Accounting.** Every object and every frame is back when both processes are gone. An object
//!   outliving its last handle is a leak the store's count reports.
//!
//! # Starting a thread in a process
//!
//! This module also starts every thread a program asks for, and every thread the kernel starts
//! in a process built this way ([`start_thread`]). Each runs on one of a few scheduler stack
//! slots the running check hands over ([`use_stacks`]), and enters user mode from a record of
//! its own: where, on which user stack, with which arguments. A process's first thread installs
//! its program on the way; a later one finds it installed, and waits if the first is still
//! copying it.

#![allow(unsafe_code)]

use core::cell::SyncUnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use arch::Cpu;
use hal::{Arch, EarlyConsole, HasUserMode, KernAddr, PhysAddr};
use kobject::{ObjectType, Rights};
use sched::ThreadId;
use time::Duration;

use crate::objects::{self, Object};
use crate::preempt::{self, sleep_until};
use crate::{Check, timekeeping, userproc, write_hex, write_usize};

/// The second program, embedded like `init`. The kernel never loads it: it hands `init` a
/// handle to these bytes, and `init` builds the process.
static CHILD_ELF: &[u8] = include_bytes!(env!("KINTANE_USER_USERCHILD"));

/// `init`'s spawn mode, in the register the kernel passes it, and the code it returns when
/// every step behaved. Mirrors `user/init/src/main.rs`.
const MODE_SPAWN: usize = 4;
const SPAWN_SUCCESS: u64 = 0x5a;

/// The process slot `init` runs in. `procs` has torn its own down by the time this runs.
const PARENT: usize = 0;

/// The scheduler stack slots this check's threads run on: `init`'s, its child's, and one to
/// spare. The boot check and `procs` have reaped the threads that held these, and
/// `preempt::spawn` requires exactly that.
const STACKS: [usize; 3] = [1, 2, 3];

/// Priority of process threads: below boot, so boot's wake-ups preempt them.
const PRIORITY: u8 = 4;

/// The longest this check waits for `init` to finish the whole sequence, and the longest a
/// thread waits for its process's program to be installed.
const PATIENCE: Duration = Duration::from_nanos(3_000_000_000);
/// How often it looks.
const POLL: Duration = Duration::from_nanos(5_000_000);

// ---- starting threads in processes ------------------------------------------------------

/// Threads of processes that can exist at once: as many as the stack slots a check hands
/// over, at most.
pub const POOL: usize = 3;

/// A pool entry no thread holds.
const FREE: u64 = u64::MAX;
/// A pool entry being claimed, between choosing it and the spawn that fills it.
const CLAIMING: u64 = u64::MAX - 1;

/// How a thread enters its process, worked out by `userproc` under the process's lock.
pub struct Start {
    pub slot: usize,
    pub root: PhysAddr,
    pub entry: usize,
    pub user_sp: usize,
    /// Whether this is the process's first thread, which installs its program.
    pub install: bool,
    pub args: [usize; 4],
}

/// The scheduler stack slot each pool entry runs on, or `usize::MAX`.
static STACK: [AtomicUsize; POOL] = [const { AtomicUsize::new(usize::MAX) }; POOL];
/// The thread on each pool entry, [`FREE`], or [`CLAIMING`]. An entry is free again only
/// once its thread has been reaped: `preempt::spawn_prepared` reuses the stack.
static THREAD: [AtomicU64; POOL] = [const { AtomicU64::new(FREE) }; POOL];
/// Each entry's [`Start`], read by [`user_entry`] on the new thread.
static SLOT: [AtomicUsize; POOL] = [const { AtomicUsize::new(0) }; POOL];
static ENTRY: [AtomicUsize; POOL] = [const { AtomicUsize::new(0) }; POOL];
static USER_SP: [AtomicUsize; POOL] = [const { AtomicUsize::new(0) }; POOL];
static INSTALL: [AtomicBool; POOL] = [const { AtomicBool::new(false) }; POOL];
static ARGS: [[AtomicUsize; 4]; POOL] = [const { [const { AtomicUsize::new(0) }; 4] }; POOL];
/// The kernel stack each entry's traps land on.
static TOP: [AtomicUsize; POOL] = [const { AtomicUsize::new(0) }; POOL];
/// For a thread [`start_resumed`] started — a Linux `fork`'s child, or a `clone`'s thread —
/// the registers it resumes user code with and its thread pointer. `None` for a thread that
/// enters its program at an entry point.
///
/// SAFETY INVARIANT: written by the starter while its pool entry is claimed and before the
/// thread exists, and taken by that thread in [`user_entry`]; nothing else reaches an entry.
type Resume = (<Cpu as HasUserMode>::UserRegisters, usize);
static RESUME: [SyncUnsafeCell<Option<Resume>>; POOL] = [const { SyncUnsafeCell::new(None) }; POOL];

/// Hand this module the scheduler stack slots process threads run on, for the check now
/// running. Every thread started on the previous ones must have ended: see [`end_threads`].
pub fn use_stacks(stacks: &[usize]) {
    for (i, cell) in STACK.iter().enumerate() {
        cell.store(stacks.get(i).copied().unwrap_or(usize::MAX), Ordering::Relaxed);
    }
}

/// A process thread's kernel entry: install the program if this is the first thread, then
/// enter user mode.
///
/// The program is copied here, on the process's own thread, for the reason
/// [`crate::procs`] gives: the switch into this thread loaded this process's address
/// space, so the copy lands in the right space and may be preempted freely.
extern "C" fn user_entry(index: usize) -> ! {
    preempt::begin();
    // SAFETY: see `RESUME`; this is the thread the entry was written for.
    if let Some((regs, tls)) = unsafe { (*RESUME[index].get()).take() } {
        let top = TOP[index].load(Ordering::Relaxed);
        let _ = Cpu::irq_save();
        // SAFETY: bound to `top` and its process's root before any CPU could switch to it;
        // its memory is already there, shared from a parent or its own; masked, so the thread
        // pointer is set on the CPU that resumes it.
        unsafe {
            Cpu::set_tls(tls);
            Cpu::resume_user(&regs, KernAddr::new(top))
        }
    }
    let slot = SLOT[index].load(Ordering::Relaxed);
    let ready = if INSTALL[index].load(Ordering::Relaxed) {
        userproc::install_image(slot).is_some()
    } else {
        installed_soon(slot)
    };
    if !ready {
        userproc::abandon(slot, NOT_LOADED)
    }
    let args = ARGS[index].each_ref().map(|a| a.load(Ordering::Relaxed));
    let top = TOP[index].load(Ordering::Relaxed);
    // `enter_user` wants interrupts masked until its `iretq`/`eret` unmasks them.
    let _ = Cpu::irq_save();
    // SAFETY: `spawn_prepared` bound this thread to `top` and its process's root before any
    // CPU could switch to it; the program is installed, and the stack `USER_SP` points into
    // is reserved in the process; masked.
    unsafe {
        Cpu::enter_user(
            ENTRY[index].load(Ordering::Relaxed),
            USER_SP[index].load(Ordering::Relaxed),
            args,
            KernAddr::new(top),
        )
    }
}

/// Wait for process `slot`'s first thread to install its program. A thread started straight
/// after the first can otherwise run ahead of the copy, into memory that is still zero.
fn installed_soon(slot: usize) -> bool {
    let give_up = timekeeping::now().saturating_add(PATIENCE);
    while !userproc::installed(slot) {
        if timekeeping::now() >= give_up {
            return false;
        }
        sleep_until(timekeeping::now().saturating_add(Duration::from_nanos(1_000_000)));
    }
    true
}

/// The exit code recorded for a process whose thread could not install its program.
const NOT_LOADED: u64 = 0x10ad;

/// Start the thread `start` describes, on a free pool entry. This is what `thread_create`
/// reaches, and what the kernel uses to start a thread in a process it built.
pub fn start_thread(start: Start) -> Option<ThreadId> {
    start_on_pool(start, None)
}

/// Start a thread in process `slot`, whose space is `root`, that resumes user code with
/// `regs` and thread pointer `tls` rather than entering at an entry point: a Linux `fork`'s
/// child, or a `clone`'s new thread. The process's memory must already be in place.
#[cfg_attr(
    not(CONFIG_ABI_LINUX),
    expect(dead_code, reason = "used only by the Linux personality")
)]
pub fn start_resumed(
    slot: usize,
    root: PhysAddr,
    regs: <Cpu as HasUserMode>::UserRegisters,
    tls: usize,
) -> Option<ThreadId> {
    let start = Start {
        slot,
        root,
        entry: hal::user::UserRegisters::pc(&regs),
        user_sp: 0,
        install: false,
        args: [0; 4],
    };
    start_on_pool(start, Some((regs, tls)))
}

fn start_on_pool(start: Start, resume: Option<Resume>) -> Option<ThreadId> {
    let index = (0..POOL).find(|&i| {
        STACK[i].load(Ordering::Relaxed) != usize::MAX
            && THREAD[i]
                .compare_exchange(FREE, CLAIMING, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
    })?;
    // SAFETY: see `RESUME`; the entry is claimed and its thread does not exist yet.
    unsafe { *RESUME[index].get() = resume };
    SLOT[index].store(start.slot, Ordering::Relaxed);
    ENTRY[index].store(start.entry, Ordering::Relaxed);
    USER_SP[index].store(start.user_sp, Ordering::Relaxed);
    INSTALL[index].store(start.install, Ordering::Relaxed);
    for (cell, value) in ARGS[index].iter().zip(start.args) {
        cell.store(value, Ordering::Relaxed);
    }
    let stack = STACK[index].load(Ordering::Relaxed);
    let spawned = preempt::spawn_prepared(stack, user_entry, index, PRIORITY, |ctx, top| {
        TOP[index].store(top.raw(), Ordering::Relaxed);
        userproc::bind(start.slot, ctx, top, start.root);
    });
    match spawned {
        Some(id) => {
            THREAD[index].store(u64::from(id.raw()), Ordering::Release);
            Some(id)
        }
        None => {
            THREAD[index].store(FREE, Ordering::Release);
            None
        }
    }
}

/// Wait for every thread this module started to end, and reap it. Returns whether they all
/// did. A thread that did not is left where it is, and so must its process be: its tables
/// cannot be freed while it may still run on them.
pub fn end_threads() -> bool {
    let mut all = true;
    for thread in &THREAD {
        let raw = thread.load(Ordering::Acquire);
        if raw >= CLAIMING {
            continue;
        }
        let id = ThreadId::new(raw as u32);
        if wait_exit(id) && preempt::reap(id) {
            thread.store(FREE, Ordering::Release);
        } else {
            all = false;
        }
    }
    all
}

// ---- the check ---------------------------------------------------------------------------

/// Run the check. On the boot thread, with the scheduler running.
pub fn check(c: &dyn EarlyConsole) -> Check {
    c.write_str("\n  spawn      ");
    objects::init();
    if userproc::with_frames(|f| f.alloc.stats().free).is_none() {
        c.write_str("skipped: no frames for processes");
        return Check::Skipped;
    }
    let Some(program) = userproc::program() else {
        c.write_str("the embedded init program does not load");
        return Check::Failed;
    };
    use_stacks(&STACKS);
    let frames_before = free_frames();
    let objects_before = objects::live();

    let outcome = run(c, &program);

    let ended = end_threads();
    if ended {
        for slot in 0..userproc::MAX_PROCS {
            userproc::teardown(slot);
        }
    }
    let leaked_frames = frames_before.saturating_sub(free_frames());
    let leaked_objects = objects::live().saturating_sub(objects_before);
    report(c, outcome, ended, leaked_frames, leaked_objects);
    Check::from_ok(
        outcome == Some(SPAWN_SUCCESS) && ended && leaked_frames == 0 && leaked_objects == 0,
    )
}

/// Build `init`, give it the two handles the sequence starts from, and wait for its exit.
fn run(c: &dyn EarlyConsole, program: &elf::Program) -> Option<u64> {
    userproc::build(PARENT, program)?;
    let parent = userproc::slot(PARENT)?;
    parent.image = Some(userproc::init_elf());

    // The image of the program `init` will create, as an object it holds a handle to. This
    // is the authority to make a process out of those bytes, and `init` has it only because
    // the kernel chose to give it.
    let image = objects::create(Object::Image { bytes: CHILD_ELF })?;
    let image_handle = parent.grant(image, ObjectType::MemoryRegion, Rights::READ)?;
    let console = parent.console_handle()?;

    let args = [
        MODE_SPAWN,
        usize::try_from(image_handle.raw()).ok()?,
        usize::try_from(console.raw()).ok()?,
        0,
    ];
    let id = userproc::start(PARENT, 0, args)?;

    if !wait_exit(id) {
        c.write_str("init did not finish: ");
        return None;
    }
    userproc::slot(PARENT).and_then(|p| p.exit)
}

/// Wait up to [`PATIENCE`] for `id` to exit.
fn wait_exit(id: ThreadId) -> bool {
    let give_up = timekeeping::now().saturating_add(PATIENCE);
    while preempt::alive(id) {
        if timekeeping::now() >= give_up {
            return false;
        }
        sleep_until(timekeeping::now().saturating_add(POLL));
    }
    true
}

fn free_frames() -> usize {
    userproc::with_frames(|f| f.alloc.stats().free).unwrap_or(0)
}

fn report(c: &dyn EarlyConsole, outcome: Option<u64>, ended: bool, frames: usize, objects: usize) {
    match outcome {
        Some(SPAWN_SUCCESS) => {
            c.write_str("init created a process, gave it a channel, and waited for it")
        }
        Some(code) => {
            c.write_str("init exited ");
            write_hex(c, code);
            c.write_str(", WRONG");
        }
        None => c.write_str("init never exited"),
    }
    if !ended {
        c.write_str("; A THREAD NEVER ENDED, its process left in place");
    }
    c.write_str("; ");
    write_usize(c, objects);
    c.write_str(if objects == 0 {
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
}

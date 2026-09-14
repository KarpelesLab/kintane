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

#![allow(unsafe_code)]

use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

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

/// The process slots this check uses: `init`, and the child it creates. `procs` has torn
/// its own down by the time this runs.
const PARENT: usize = 0;

/// The scheduler stack slots the two threads run on. The boot check and `procs` have reaped
/// the threads that held these, and `preempt::spawn` requires exactly that.
const PARENT_STACK: usize = 1;
const CHILD_STACK: usize = 2;

/// Priority of both threads: below boot, so boot's wake-ups preempt them.
const PRIORITY: u8 = 4;

/// The longest this check waits for `init` to finish the whole sequence.
const PATIENCE: Duration = Duration::from_nanos(3_000_000_000);
/// How often it looks.
const POLL: Duration = Duration::from_nanos(5_000_000);

/// What each process's thread enters user mode with, by slot: entry, arguments, and the
/// kernel stack its traps land on.
static ENTRY: [AtomicUsize; userproc::MAX_PROCS] =
    [const { AtomicUsize::new(0) }; userproc::MAX_PROCS];
static ARGS: [[AtomicUsize; 4]; userproc::MAX_PROCS] =
    [const { [const { AtomicUsize::new(0) }; 4] }; userproc::MAX_PROCS];
static STACK_TOP: [AtomicUsize; userproc::MAX_PROCS] =
    [const { AtomicUsize::new(0) }; userproc::MAX_PROCS];
/// Which scheduler stack slot each process's thread took, so a second thread for a slot
/// reuses it rather than claiming another.
static STACK_OF: [AtomicUsize; userproc::MAX_PROCS] =
    [const { AtomicUsize::new(usize::MAX) }; userproc::MAX_PROCS];
/// The threads started here, to reap.
static THREADS: [AtomicU64; userproc::MAX_PROCS] =
    [const { AtomicU64::new(u64::MAX) }; userproc::MAX_PROCS];

/// A process thread's kernel entry: install its program, then enter user mode.
///
/// The program is copied here, on the process's own thread, for the reason
/// [`crate::procs`] gives: the switch into this thread loaded this process's address
/// space, so the copy lands in the right space and may be preempted freely.
extern "C" fn user_entry(slot: usize) -> ! {
    preempt::begin();
    let filled = userproc::slot(slot)
        .and_then(|p| p.image)
        .and_then(userproc::parse)
        .and_then(|program| userproc::install_program(&program));
    if filled.is_none() {
        if let Some(p) = userproc::slot(slot) {
            userproc::record_exit(p, NOT_LOADED);
        }
        preempt::exit_thread()
    }
    let args = ARGS[slot].each_ref().map(|a| a.load(Ordering::Relaxed));
    let top = STACK_TOP[slot].load(Ordering::Relaxed);
    // `enter_user` wants interrupts masked until its `iretq`/`eret` unmasks them.
    let _ = Cpu::irq_save();
    // SAFETY: `spawn_prepared` bound this thread to `top` and its process's root before any
    // CPU could switch to it; the program is installed and the stack is mapped; masked.
    unsafe {
        Cpu::enter_user(
            ENTRY[slot].load(Ordering::Relaxed),
            userproc::user_stack_pointer(),
            args,
            KernAddr::new(top),
        )
    }
}

/// The exit code recorded for a process whose thread could not install its program.
const NOT_LOADED: u64 = 0x10ad;

/// Start a thread in process `slot`, at `entry` or its program's entry point, with `arg` in
/// its first argument register. This is what `thread_create` reaches.
pub fn start_thread(slot: usize, entry: usize, arg: usize) -> Option<ThreadId> {
    let p = userproc::slot(slot)?;
    let root = p.vm.space().root();
    let program_entry = p.image.and_then(userproc::parse)?.entry as usize;
    // One thread per process, which is what `userproc::current`'s soundness rests on.
    if THREADS[slot].load(Ordering::Relaxed) != u64::MAX {
        return None;
    }
    ENTRY[slot].store(if entry == 0 { program_entry } else { entry }, Ordering::Relaxed);
    for (cell, value) in ARGS[slot].iter().zip([arg, 0, 0, 0]) {
        cell.store(value, Ordering::Relaxed);
    }
    let stack = match STACK_OF[slot].load(Ordering::Relaxed) {
        usize::MAX => CHILD_STACK,
        held => held,
    };
    STACK_OF[slot].store(stack, Ordering::Relaxed);
    let id = spawn_on(slot, root, stack)?;
    THREADS[slot].store(u64::from(id.raw()), Ordering::Relaxed);
    Some(id)
}

/// Spawn `slot`'s thread on scheduler stack `stack`, bound to its address space before any
/// CPU can pick it up.
fn spawn_on(slot: usize, root: PhysAddr, stack: usize) -> Option<ThreadId> {
    preempt::spawn_prepared(stack, user_entry, slot, PRIORITY, |ctx, top| {
        STACK_TOP[slot].store(top.raw(), Ordering::Relaxed);
        <Cpu as HasUserMode>::bind(ctx, top, root);
    })
}

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
    let frames_before = free_frames();
    let objects_before = objects::live();

    let outcome = run(c, &program);

    teardown();
    let leaked_frames = frames_before.saturating_sub(free_frames());
    let leaked_objects = objects::live().saturating_sub(objects_before);
    report(c, outcome, leaked_frames, leaked_objects);
    Check::from_ok(outcome == Some(SPAWN_SUCCESS) && leaked_frames == 0 && leaked_objects == 0)
}

/// Build `init`, give it the two handles the sequence starts from, and wait for its exit.
fn run(c: &dyn EarlyConsole, program: &elf::Program) -> Option<u64> {
    let root = userproc::build(PARENT, program)?;
    let parent = userproc::slot(PARENT)?;
    parent.image = Some(userproc::init_elf());

    // The image of the program `init` will create, as an object it holds a handle to. This
    // is the authority to make a process out of those bytes, and `init` has it only because
    // the kernel chose to give it.
    let image = objects::create(Object::Image { bytes: CHILD_ELF })?;
    let image_handle = parent.grant(image, ObjectType::MemoryRegion, Rights::READ)?;
    let console = parent.console_handle()?;

    for (cell, value) in ARGS[PARENT].iter().zip([
        MODE_SPAWN,
        usize::try_from(image_handle.raw()).ok()?,
        usize::try_from(console.raw()).ok()?,
        0,
    ]) {
        cell.store(value, Ordering::Relaxed);
    }
    ENTRY[PARENT].store(program.entry as usize, Ordering::Relaxed);
    STACK_OF[PARENT].store(PARENT_STACK, Ordering::Relaxed);
    let id = spawn_on(PARENT, root, PARENT_STACK)?;
    THREADS[PARENT].store(u64::from(id.raw()), Ordering::Relaxed);

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

/// Reap both threads and tear both processes down, whatever state they reached.
fn teardown() {
    // Threads a program created, as the objects record them. The kernel's own record
    // covers the two this check knows about; this covers any other a program made, which
    // would otherwise stay in the scheduler's table after its process is gone.
    let mut ids = [ThreadId::new(0); objects::MAX_OBJECTS];
    let found = objects::thread_ids(&mut ids);
    for id in ids.iter().take(found) {
        if !preempt::alive(*id) {
            let _ = preempt::reap(*id);
        }
    }
    for slot in 0..userproc::MAX_PROCS {
        let raw = THREADS[slot].swap(u64::MAX, Ordering::Relaxed);
        if raw != u64::MAX {
            let id = ThreadId::new(raw as u32);
            let _ = wait_exit(id);
            let _ = preempt::reap(id);
        }
        STACK_OF[slot].store(usize::MAX, Ordering::Relaxed);
        userproc::teardown(slot);
    }
}

fn report(c: &dyn EarlyConsole, outcome: Option<u64>, frames: usize, objects: usize) {
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

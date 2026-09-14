//! The first native userspace program, run and checked at boot.
//!
//! This is to userspace what `demand` is to demand paging: `lib/abi`, `kernel/elf` and the
//! `hal::HasUserMode` port are exercised on the host as far as they can be, and this runs
//! them for real. It loads the embedded `init` program into a process, enters ring 3, and
//! grades the process by the exit code it comes back with — so a kernel that answered a
//! system call wrong is caught by the program that received the wrong answer, not by the
//! kernel checking its own work.
//!
//! It also owns what every process shares, whoever runs it: the table of processes, the
//! system-call handler and the fault hook. [`crate::procs`] runs processes on the scheduler
//! through the same table.
//!
//! # What a process is here
//!
//! A [`Process`] is an address space ([`mm::vm::Vm`] over its own page tables, sharing the
//! kernel half), a handle table, and at most one channel it made for itself, in one slot
//! of a small fixed table. It has exactly one thread. A system call or a fault finds its
//! process by the address space loaded on the CPU that took it ([`current`]). The context
//! switch loads a thread's space wherever the thread runs, so that answer follows a thread
//! that migrates.
//!
//! # The boot-time slice, without the scheduler
//!
//! This check runs three processes in sequence, before the scheduler exists. Each user
//! program is a kernel thread whose entry ([`trampoline`]) enters ring 3. The boot thread
//! switches to it through [`thread::Threads`] directly, with no timer and no preemption,
//! and every system call the program makes returns on that same thread's kernel stack.
//! `process_exit`, `thread_exit` and a fatal fault all end the thread, which switches back
//! to the boot thread, and the check reads the exit code. Once the scheduler runs, the same
//! calls end the thread through it instead.
//!
//! # The address space, restored
//!
//! Filling a process in loads its page tables on the boot CPU, masked, so the copy faults
//! pages in against the right space. The kernel root is put back before the check returns,
//! so the later in-kernel suite finds the kernel's own tables exactly as it left them.

#![allow(unsafe_code)]

use core::cell::SyncUnsafeCell;
use core::sync::atomic::{AtomicPtr, Ordering};

use abi::{Error, Handle as AbiHandle, UserPtr};
use arch::Cpu;
use elf::Program;
use hal::fault::PageFault;
use hal::user::{UserHooks, UserTrap};
use hal::{Arch, EarlyConsole, HasPageTables, HasUserMode, KernAddr, PhysAddr, UserAddr};
use kobject::handle::{Handle, HandleTable};
use kobject::{ObjectId, ObjectIds, ObjectType, Rights};
use mm::DirectMap;
use mm::paged::{AddressSpace, FrameSource};
use mm::phys::FrameAllocator;
use mm::vm::{Backing, Region, ShareSlot, Shares, Vm};

use crate::demand::KernelFrames;
use crate::{Check, Live, Locks, write_hex, write_usize};

/// The embedded program. `kbuild` links `user/init` for this target and sets the variable
/// to its path; see the `user` unit kind in `kbuild/src/build.rs`.
static INIT_ELF: &[u8] = include_bytes!(env!("KINTANE_USER_USERINIT"));

/// `init`'s exit code when its main mode saw everything behave. Mirrors `SUCCESS` in
/// `user/init/src/main.rs`; the two are one contract.
const INIT_SUCCESS: u64 = 0x2a;
/// `init`'s modes, in the register the kernel passes them.
const MODE_MAIN: usize = 0;
const MODE_FORGE: usize = 1;
const MODE_FAULT: usize = 2;

/// Handle slots, and regions, a process holds. A static program has a handful of segments;
/// sixteen leaves room for the stack and the channel endpoints.
const N: usize = 16;
const REGIONS: usize = 20;

/// The user stack: below the top of the user half, its own guard of unmapped space above.
const USER_STACK_PAGES: usize = 16;

/// A process's channel, for `channel_create`. One per process is all `init` asks for.
type Chan = ipc::Channel<Locks, 4, 64, 2>;

/// Everything one process is.
pub(crate) struct Process {
    table: HandleTable<N>,
    pub(crate) vm: Vm<'static, Cpu, REGIONS>,
    ids: ObjectIds,
    /// The next free user address `vm_map` hands out, bumped upward.
    next_map: usize,
    channel: Option<Chan>,
    /// The console object's identity, so a handle to it can be recognised.
    console: ObjectId,
    pub(crate) exit: Option<u64>,
    /// The physical root of its address space: what [`current`] recognises it by, and what
    /// the context switch loads for its thread.
    pub(crate) root: PhysAddr,
    /// Which slot of [`PROCS`] this is, for the per-slot records kept outside it.
    slot: usize,
}

/// How many processes can exist at once. The sequential slice needs one; the scheduled
/// check ([`crate::procs`]) runs two workers and a third that is killed while they run.
pub(crate) const MAX_PROCS: usize = 4;

/// Every process, by slot.
///
/// SAFETY INVARIANT: a slot is `Some` only between [`build`] and [`teardown`], and is
/// reached in exactly two ways. [`current`] finds the slot whose address space is the one
/// loaded on this CPU, from the system-call handler and the fault hook, both of which run
/// with interrupts masked (`SFMASK` clears IF on a `syscall`; a fault handler runs
/// masked); and boot reaches a slot by index while that process's thread is not running.
/// **Each process has exactly one thread**, so only one CPU can ever be running in a given
/// slot, and the mutable borrow each path takes is unique. Two *different* processes on
/// two CPUs borrow two different slots.
static PROCS: [SyncUnsafeCell<Option<Process>>; MAX_PROCS] =
    [const { SyncUnsafeCell::new(None) }; MAX_PROCS];
/// SAFETY INVARIANT: the boot frame allocator, valid while a process exists. Reached only
/// through [`with_frames`], which holds [`FRAME_LOCK`], because two processes can fault on
/// two CPUs at once and the allocator is one shared structure.
static FRAMES: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());
/// Exclusion for [`FRAMES`]. Held for one frame operation or one `Vm` call and never
/// across a context switch, so it orders below the scheduler's lock and above nothing.
static FRAME_CLASS: sync::lockdep::LockClass = sync::lockdep::LockClass::new("userproc.frames");
static FRAME_LOCK: sync::SpinLock<(), Cpu> = sync::SpinLock::with_class((), &FRAME_CLASS);
/// The share-count slots each process's `Vm` borrows: one store per slot, since two
/// processes can exist at once.
static SHARE_STORE: [SyncUnsafeCell<[ShareSlot; N]>; MAX_PROCS] =
    [const { SyncUnsafeCell::new([ShareSlot::EMPTY; N]) }; MAX_PROCS];
/// The kernel direct map, set by [`check`] and used to reach frames. Its raw parts, since
/// `DirectMap` is `Copy` but has no `const` default; stored as an `Option`.
static DIRECT: SyncUnsafeCell<Option<DirectMap>> = SyncUnsafeCell::new(None);

fn direct() -> DirectMap {
    // SAFETY: set once by `check` before any process runs, read-only after.
    unsafe { (*DIRECT.get()).expect("direct map set before use") }
}

/// The kernel's own address space, recorded by [`check`]. What a thread with no process
/// runs on, and what every process's root mirrors its upper half from.
static KERNEL_ROOT: AtomicU64 = AtomicU64::new(0);

pub(crate) fn kernel_root() -> PhysAddr {
    PhysAddr::new(KERNEL_ROOT.load(Ordering::Relaxed))
}

/// One bit per CPU each process slot has been served a system call on. Kept outside
/// [`Process`] so boot can read it while the process's thread runs and writes it: a thread
/// that migrates shows up here, and nowhere else the kernel can see it.
static CPUS_SEEN: [AtomicU64; MAX_PROCS] = [const { AtomicU64::new(0) }; MAX_PROCS];

/// The CPUs slot `slot`'s process has been served on since the last [`clear_cpus`].
pub(crate) fn cpus(slot: usize) -> u64 {
    CPUS_SEEN.get(slot).map_or(0, |c| c.load(Ordering::Relaxed))
}

pub(crate) fn clear_cpus(slot: usize) {
    if let Some(c) = CPUS_SEEN.get(slot) {
        c.store(0, Ordering::Relaxed);
    }
}

/// A frame's first byte through the kernel's direct map.
pub(crate) fn direct_ptr(frame: PhysAddr) -> Option<*mut u8> {
    direct().ptr_to_phys(frame).ok().map(|p| p.as_ptr())
}

/// The process whose address space is loaded on this CPU: the one a system call or a fault
/// arriving here belongs to, by construction rather than by bookkeeping. A switch to a
/// user thread loads that thread's space, so this cannot go stale when a thread migrates —
/// and a kernel that failed to load the space would be found serving the wrong process,
/// which is what the isolation checks in [`crate::procs`] measure.
pub(crate) fn current() -> Option<&'static mut Process> {
    let root = <Cpu as HasPageTables>::root();
    slots().find(|p| p.root == root)
}

/// Every live process. Boot only: a running thread reaches its own process through
/// [`current`].
fn slots() -> impl Iterator<Item = &'static mut Process> {
    // SAFETY: see `PROCS`.
    PROCS.iter().filter_map(|p| unsafe { (*p.get()).as_mut() })
}

/// The process in slot `i`, for boot to build, inspect and tear down.
pub(crate) fn slot(i: usize) -> Option<&'static mut Process> {
    // SAFETY: see `PROCS`; the caller is boot, and the slot's thread is not running.
    PROCS.get(i).and_then(|p| unsafe { (*p.get()).as_mut() })
}

/// Run `f` with the frame allocator, under [`FRAME_LOCK`].
pub(crate) fn with_frames<R>(f: impl FnOnce(&mut KernelFrames<'static>) -> R) -> Option<R> {
    let ptr = FRAMES.load(Ordering::Relaxed);
    if ptr.is_null() {
        return None;
    }
    let _guard = FRAME_LOCK.lock_irqsave();
    // SAFETY: see `FRAMES`: the pointer is the boot allocator, live while any process is,
    // and the lock makes this borrow the only one. The direct map is the kernel's, which
    // every process's space maps identically.
    let alloc = unsafe { &mut *ptr.cast::<FrameAllocator<'static, Cpu>>() };
    let mut frames = KernelFrames {
        alloc,
        direct: direct(),
    };
    Some(f(&mut frames))
}

// ---- the fault hook and system-call handler -------------------------------------------

/// Resolve a user page fault, or a fault in a user copy, against the process `Vm`.
fn on_user_fault(fault: PageFault) -> bool {
    let Some(p) = current() else { return false };
    with_frames(|f| p.vm.fault(fault, f).is_ok()).unwrap_or(false)
}

/// End the running user thread, recording why. Switches back to the boot thread and does
/// not return.
fn on_kill(trap: UserTrap) -> ! {
    if let Some(p) = current() {
        // A fault before the program set an exit code is the process being killed. If it
        // had already exited, keep that.
        if p.exit.is_none() {
            p.exit = Some(KILLED);
        }
    }
    let _ = trap;
    end_thread()
}

/// End the running user thread, whichever scheduler it belongs to: the one the boot-time
/// slice drives by hand, or the kernel's own once it is running. Never returns.
fn end_thread() -> ! {
    if crate::preempt::scheduled() {
        crate::preempt::exit_thread()
    }
    // SAFETY: on the user thread, masked; `THREADS` is the table it belongs to and this
    // reference ends before the switch inside `exit`.
    let _ = unsafe { thread::Threads::exit(threads()) };
    // `exit` switches away and never comes back to an ended thread. If it somehow returned,
    // there is nothing safe to do but stop.
    Cpu::halt()
}

/// Recorded as the exit code when the kernel kills a process rather than the program
/// choosing its own code.
const KILLED: u64 = 0xffff_ffff_ffff_ffff;

/// Run one system call.
fn on_syscall(frame: &mut <Cpu as HasUserMode>::SyscallFrame) {
    use hal::user::SyscallFrame;
    let (status, value) = abi::encode(dispatch(frame.number(), frame.args()));
    frame.set_result(status, value);
}

/// Decode and perform system call `nr`. A process with no current state fails everything.
fn dispatch(nr: u64, args: [u64; 6]) -> Result<u64, Error> {
    let p = current().ok_or(Error::Unsupported)?;
    // Where the call was served. The only record of a user thread having run on a CPU, and
    // what makes a migration observable.
    CPUS_SEEN[p.slot].fetch_or(1 << (Cpu::cpu_index() & 63), Ordering::Relaxed);
    abi::dispatch(&mut Syscalls { p }, nr, args)
}

/// The kernel's implementation of the native ABI, over one process.
struct Syscalls<'a> {
    p: &'a mut Process,
}

impl abi::Handler for Syscalls<'_> {
    fn process_exit(&mut self, code: u64) -> Result<u64, Error> {
        self.thread_exit(code)
    }

    fn thread_exit(&mut self, code: u64) -> Result<u64, Error> {
        self.p.exit = Some(code);
        end_thread()
    }

    fn thread_yield(&mut self) -> Result<u64, Error> {
        // Under the scheduler, give up the rest of the slice; in the boot-time slice there
        // is nothing else to run, and the call returns.
        if crate::preempt::scheduled() {
            crate::preempt::yield_now();
        }
        Ok(0)
    }

    fn debug_write(
        &mut self,
        console: AbiHandle,
        bytes: UserPtr,
        len: usize,
    ) -> Result<u64, Error> {
        let entry = self
            .p
            .table
            .get_checked(handle(console), ObjectType::DeviceResource, Rights::WRITE)
            .map_err(handle_error)?;
        if entry.object != self.p.console {
            return Err(Error::WrongType);
        }
        if len > 256 {
            return Err(Error::TooLarge);
        }
        let mut buf = [0u8; 256];
        // SAFETY: the process address space is loaded; `copy_from_user` checks the range and
        // faults pages in, and refuses an address it cannot map without faulting the kernel.
        unsafe { Cpu::copy_from_user(&mut buf[..len], user(bytes)) }.map_err(|_| Error::Fault)?;
        arch::EARLY.write_bytes(&buf[..len]);
        Ok(len as u64)
    }

    fn vm_map(&mut self, len: usize) -> Result<u64, Error> {
        let page = Cpu::PAGE_SIZE;
        let pages = len.div_ceil(page).max(1);
        let bytes = pages * page;
        let start = self.p.next_map;
        let end = start.checked_add(bytes).ok_or(Error::InvalidArgument)?;
        if end > <Cpu as HasUserMode>::USER_END {
            return Err(Error::NoMemory);
        }
        self.p
            .vm
            .reserve(Region {
                start,
                len: bytes,
                flags: user_rw(),
                backing: Backing::Anonymous,
                huge: false,
            })
            .map_err(|_| Error::NoMemory)?;
        self.p.next_map = end + page; // a page of gap between mappings
        Ok(start as u64)
    }

    fn channel_create(&mut self, out: UserPtr) -> Result<u64, Error> {
        if self.p.channel.is_some() {
            return Err(Error::Full);
        }
        let (ch, [a, b]) = Chan::new(&self.p.ids, ipc::ENDPOINT_RIGHTS);
        let ha = self
            .p
            .table
            .insert(a.object, a.kind, a.rights)
            .map_err(handle_error)?;
        let hb = self
            .p
            .table
            .insert(b.object, b.kind, b.rights)
            .map_err(handle_error)?;
        self.p.channel = Some(ch);
        let mut pair = [0u8; 8];
        pair[0..4].copy_from_slice(&ha.raw().to_le_bytes());
        pair[4..8].copy_from_slice(&hb.raw().to_le_bytes());
        // SAFETY: process space loaded; `copy_to_user` checks and faults in the page.
        unsafe { Cpu::copy_to_user(user(out), &pair) }.map_err(|_| Error::Fault)?;
        Ok(0)
    }

    fn channel_write(
        &mut self,
        channel: AbiHandle,
        bytes: UserPtr,
        len: usize,
    ) -> Result<u64, Error> {
        if len > 64 {
            return Err(Error::TooLarge);
        }
        let mut buf = [0u8; 64];
        // SAFETY: as `debug_write`.
        unsafe { Cpu::copy_from_user(&mut buf[..len], user(bytes)) }.map_err(|_| Error::Fault)?;
        let ch = self.p.channel.as_ref().ok_or(Error::BadHandle)?;
        ch.send(&mut self.p.table, handle(channel), &buf[..len], &[])
            .map_err(channel_error)?;
        Ok(0)
    }

    fn channel_read(&mut self, channel: AbiHandle, buf: UserPtr, cap: usize) -> Result<u64, Error> {
        let ch = self.p.channel.as_ref().ok_or(Error::BadHandle)?;
        let mut bytes = [0u8; 64];
        let mut handles = [Handle::from_raw(0); 2];
        let cap = cap.min(bytes.len());
        let got = ch
            .receive(&mut self.p.table, handle(channel), &mut bytes[..cap], &mut handles)
            .map_err(channel_error)?;
        // SAFETY: as `channel_create`.
        unsafe { Cpu::copy_to_user(user(buf), &bytes[..got.bytes]) }.map_err(|_| Error::Fault)?;
        Ok(got.bytes as u64)
    }

    fn handle_close(&mut self, h: AbiHandle) -> Result<u64, Error> {
        self.p
            .table
            .close(handle(h))
            .map(|_| 0)
            .map_err(handle_error)
    }
}

// ---- the check ------------------------------------------------------------------------

/// Build, run and grade the three `init` processes. `frames` is the boot allocator; `live`
/// is the kernel address space. Restores the kernel root before returning.
pub fn check(c: &dyn EarlyConsole, frames: &mut FrameAllocator<'static, Cpu>, live: Live) -> Check {
    c.write_str("\n  userspace  ");
    let Some(direct) = live.direct else {
        c.write_str("skipped: no kernel address space");
        return Check::Skipped;
    };
    let program = match Program::parse(
        INIT_ELF,
        <Cpu as HasUserMode>::ELF_MACHINE,
        (<Cpu as HasUserMode>::USER_START as u64, <Cpu as HasUserMode>::USER_END as u64),
        Cpu::PAGE_SIZE as u64,
    ) {
        Ok(p) => p,
        Err(_) => {
            c.write_str("the embedded init program does not load");
            return Check::Failed;
        }
    };

    // SAFETY: set once here before any process runs.
    unsafe { *DIRECT.get() = Some(direct) };
    let kernel_root = <Cpu as HasPageTables>::root();
    KERNEL_ROOT.store(kernel_root.raw(), Ordering::Relaxed);
    set_frames(frames);
    // SAFETY: nothing else reaches CURRENT; installed before any user thread runs.
    unsafe {
        Cpu::install(
            UserHooks {
                syscall: on_syscall,
                fault: on_user_fault,
                kill: on_kill,
            },
            kernel_root,
        );
    }
    let before = frames.stats().free;

    let main = run(c, &program, kernel_root, MODE_MAIN, 0);
    let forge = run(c, &program, kernel_root, MODE_FORGE, 0);
    // The fault mode is handed the kernel root's address as its target: memory it must not
    // reach, and touching it must end the process rather than the kernel.
    let fault = run(c, &program, kernel_root, MODE_FAULT, kernel_root.raw() as usize);

    FRAMES.store(core::ptr::null_mut(), Ordering::Relaxed);
    let after = frames.stats().free;
    let leaked = before.saturating_sub(after);

    let main_ok = main == Some(INIT_SUCCESS);
    let forge_ok = forge == Some(FORGE_REFUSALS);
    let fault_ok = fault == Some(KILLED);
    report(c, "main", main, main_ok);
    report(c, "forge", forge, forge_ok);
    report(c, "fault", fault, fault_ok);
    if leaked != 0 {
        c.write_str(", ");
        write_usize(c, leaked);
        c.write_str(" FRAMES LEAKED");
    }
    Check::from_ok(main_ok && forge_ok && fault_ok && leaked == 0)
}

/// The number of forged-handle attempts `init`'s forge mode makes, each of which must be
/// refused; mirrors the array in `user/init/src/main.rs`.
const FORGE_REFUSALS: u64 = 6;

fn report(c: &dyn EarlyConsole, name: &str, code: Option<u64>, ok: bool) {
    c.write_str(name);
    c.write_str(" ");
    match code {
        Some(v) => write_hex(c, v),
        None => c.write_str("(no exit)"),
    }
    c.write_str(if ok { " ok, " } else { " WRONG, " });
}

/// Build a process for `program` in `mode`, run it to exit, tear it down, and return its
/// exit code. `None` if the thread never ended.
fn run(
    c: &dyn EarlyConsole,
    program: &Program,
    kernel_root: PhysAddr,
    mode: usize,
    fault_target: usize,
) -> Option<u64> {
    let root = build(0, program)?;
    // SAFETY: `root` maps the kernel half (mirrored) plus this process's regions; the running
    // code and stack live in the kernel half, identical across roots.
    unsafe { Cpu::set_root(root) };

    let arg1 = if mode == MODE_FAULT { fault_target } else { 0 };
    let ready = install_program(program).is_some() && install_handles(mode).is_some();
    let exit = if ready {
        drive(program.entry as usize, mode, arg1)
    } else {
        c.write_str("(setup failed) ");
        None
    };

    // SAFETY: `kernel_root` is the live kernel root; the running code and stack are mapped in
    // it identically.
    unsafe { Cpu::set_root(kernel_root) };
    teardown(0);
    exit
}

/// Build an empty process in `slot`: its own address space with the kernel half mirrored,
/// `program`'s segments and a stack reserved, and its handle table. Returns its root.
///
/// The process is not loaded and nothing runs in it yet; the caller loads the space (or
/// binds a thread to it) and fills the segments in with [`install_program`].
pub(crate) fn build(slot: usize, program: &Program) -> Option<PhysAddr> {
    if slot >= MAX_PROCS || self::slot(slot).is_some() {
        return None;
    }
    let direct = direct();
    let kernel_root = kernel_root();
    let mut space = with_frames(|f| AddressSpace::<Cpu>::new(direct, f).ok())??;
    // SAFETY: `kernel_root` is the live kernel root, reachable through `direct`, and its
    // tables outlive this process.
    unsafe { space.mirror_top_level(kernel_root).ok()? };
    // SAFETY: one store per slot, borrowed while that slot is `Some`, and this slot is
    // `None` (checked above), so no other borrow of this store is live.
    let shares = Shares::new(unsafe { &mut *SHARE_STORE[slot].get() });
    let mut vm = Vm::new(space, shares);

    // Every segment as a writable region, filled once the space is loaded, then tightened.
    for seg in program.segments() {
        let seg = seg.ok()?;
        if seg.mem_size == 0 {
            continue;
        }
        let (lo, hi) = seg.pages(Cpu::PAGE_SIZE as u64);
        vm.reserve(anon(lo as usize, (hi - lo) as usize)).ok()?;
    }
    let stack_top = <Cpu as HasUserMode>::USER_END - Cpu::PAGE_SIZE;
    let stack_bottom = stack_top - USER_STACK_PAGES * Cpu::PAGE_SIZE;
    vm.reserve(anon(stack_bottom, USER_STACK_PAGES * Cpu::PAGE_SIZE))
        .ok()?;
    let root = vm.space().root();

    // SAFETY: see `PROCS`; the slot is `None` and no thread exists for it yet.
    unsafe {
        *PROCS[slot].get() = Some(Process {
            table: HandleTable::new(),
            vm,
            ids: ObjectIds::new(),
            next_map: first_map_addr(program),
            channel: None,
            console: ObjectId::from_raw(0),
            exit: None,
            root,
            slot,
        });
    }
    Some(root)
}

/// The user stack pointer a process starts on: the top of its stack region, with room for
/// the ABI's alignment and the initial frame.
pub(crate) fn user_stack_pointer() -> usize {
    <Cpu as HasUserMode>::USER_END - Cpu::PAGE_SIZE - 16
}

/// Point every process's frame operations at `frames`: the boot allocator for the slice
/// `check` runs, a pool of its own for the scheduled check, which outlives `memory()`.
///
/// # Safety invariant
/// `frames` must outlive every process built while it is installed.
pub(crate) fn set_frames(frames: &mut FrameAllocator<'static, Cpu>) {
    let _guard = FRAME_LOCK.lock_irqsave();
    FRAMES.store((frames as *mut FrameAllocator<'static, Cpu>).cast(), Ordering::Relaxed);
}

/// The embedded `init` program, parsed against this port's user half.
pub(crate) fn program() -> Option<Program<'static>> {
    Program::parse(
        INIT_ELF,
        <Cpu as HasUserMode>::ELF_MACHINE,
        (<Cpu as HasUserMode>::USER_START as u64, <Cpu as HasUserMode>::USER_END as u64),
        Cpu::PAGE_SIZE as u64,
    )
    .ok()
}

/// Copy each segment into user memory and set its final permissions.
///
/// The process's address space must be loaded for the whole copy. Either the caller is
/// the process's own thread, whose space every switch into it reloads, so it may be
/// preempted freely; or the caller loaded the space itself and keeps interrupts masked
/// until it puts the kernel's back, as the boot-time slice does.
pub(crate) fn install_program(program: &Program) -> Option<()> {
    for seg in program.segments() {
        let seg = seg.ok()?;
        if seg.mem_size == 0 || seg.file.is_empty() {
            continue;
        }
        // SAFETY: the process space is loaded; the region is mapped writable and
        // `copy_to_user` faults its pages in.
        unsafe { Cpu::copy_to_user(UserAddr::new(seg.vaddr as usize), seg.file) }.ok()?;
    }
    let p = current()?;
    with_frames(|f| {
        for seg in program.segments() {
            let seg = seg.ok()?;
            if seg.mem_size == 0 || seg.access.write {
                continue;
            }
            let (lo, hi) = seg.pages(Cpu::PAGE_SIZE as u64);
            p.vm.protect(lo as usize, (hi - lo) as usize, user_flags(&seg.access), f)
                .ok()?;
        }
        Some(())
    })?
}

/// Install the handles `mode` starts with, and record the argument handle values the
/// trampoline passes the program. Forge and fault modes get nothing.
fn install_handles(mode: usize) -> Option<()> {
    ARG_HANDLES[0].store(0, Ordering::Relaxed);
    ARG_HANDLES[1].store(0, Ordering::Relaxed);
    if mode != MODE_MAIN {
        return Some(());
    }
    let p = current()?;
    let console = p.ids.next();
    p.console = console;
    // A console handle with WRITE, and one with only READ: the same object, narrower rights.
    let write = p
        .table
        .insert(console, ObjectType::DeviceResource, Rights::WRITE)
        .ok()?;
    let read = p
        .table
        .insert(console, ObjectType::DeviceResource, Rights::READ)
        .ok()?;
    ARG_HANDLES[0].store(u64::from(write.raw()), Ordering::Relaxed);
    ARG_HANDLES[1].store(u64::from(read.raw()), Ordering::Relaxed);
    Some(())
}

/// Spawn the user thread and switch to it; return the exit code the handlers recorded.
fn drive(entry: usize, mode: usize, arg1: usize) -> Option<u64> {
    let irq = Cpu::irq_save();
    // SAFETY: written once here before the thread is spawned; boot is the only thread.
    unsafe {
        THREADS
            .get()
            .write(core::mem::MaybeUninit::new(thread::Threads::new(sched::Priority::IDLE)));
    }
    ENTRY.store(entry, Ordering::Relaxed);
    MODE.store(mode, Ordering::Relaxed);
    FAULT_ARG.store(arg1, Ordering::Relaxed);
    let (top, size) = user_thread_stack();
    // SAFETY: masked, boot the only thread; `top`/`size` are the user thread's kernel stack,
    // mapped read-write.
    let spawned = unsafe {
        (*threads()).spawn(
            trampoline,
            0,
            sched::Priority::new(5).unwrap_or(sched::Priority::IDLE),
            KernAddr::new(top),
            size,
        )
    };
    let id = spawned.ok()?;
    // Bind the thread to its kernel stack and its process's address space. The switch into
    // it loads that space and the switch back to boot loads the kernel's, so the space a
    // thread runs on is the thread's own property rather than whatever the last `set_root`
    // left loaded.
    let root = current()?.vm.space().root();
    // SAFETY: masked, boot the only thread, and the thread is spawned but not running, so
    // its saved context is not the one a switch is about to overwrite.
    unsafe { Cpu::bind((*threads()).context_mut(id).ok()?, KernAddr::new(top), root) };
    // Switch to the user thread; it runs until it exits, which switches back here.
    // SAFETY: masked; no reference into the table is live across the switch; boot runs on
    // its own stack.
    let _ = unsafe { thread::Threads::yield_now(threads()) };
    // SAFETY: masked; the user thread has exited.
    let _ = unsafe { (*threads()).reap(id) };
    // SAFETY: pairs with the irq_save above.
    unsafe { Cpu::irq_restore(irq) };
    // By slot, not through `current`: the switch back to boot loaded the kernel's space,
    // because boot is a kernel thread, so no process's space is loaded here any more.
    slot(0).and_then(|p| p.exit)
}

/// The user thread's kernel entry: drop to ring 3 with the program's arguments.
extern "C" fn trampoline(_: usize) -> ! {
    let entry = ENTRY.load(Ordering::Relaxed);
    let mode = MODE.load(Ordering::Relaxed);
    // 16 bytes below the top: room for the ABI's stack alignment and the initial frame.
    let stack = <Cpu as HasUserMode>::USER_END - Cpu::PAGE_SIZE - 16;
    let (top, _) = user_thread_stack();
    let arg1 = if mode == MODE_FAULT {
        FAULT_ARG.load(Ordering::Relaxed)
    } else {
        ARG_HANDLES[0].load(Ordering::Relaxed) as usize
    };
    let arg2 = ARG_HANDLES[1].load(Ordering::Relaxed) as usize;
    // SAFETY: on the user thread; the process root is loaded, `entry`/`stack` are in its
    // mapped user half, and `top` is this thread's kernel stack for traps to land on.
    unsafe { Cpu::enter_user(entry, stack, [mode, arg1, arg2, 0], KernAddr::new(top)) }
}

/// Release the regions of the process in `slot` and free its root, then clear the slot.
///
/// The caller runs on the kernel's address space, not the process's: a process's tables
/// are freed here, and no CPU may be running on them. The process's thread has exited and
/// been reaped, and the switch away from it loaded the kernel root on its CPU.
pub(crate) fn teardown(slot: usize) {
    let Some(p) = self::slot(slot) else { return };
    with_frames(|f| {
        // Collect region starts first: `release` mutates the map as it goes.
        let mut starts = [0usize; REGIONS];
        let mut n = 0;
        for r in p.vm.regions().iter() {
            if let Some(s) = starts.get_mut(n) {
                *s = r.start;
                n += 1;
            }
        }
        for &s in &starts[..n] {
            let _ = p.vm.release(s, f);
        }
        // The root frame goes back too. `release` prunes the user page tables it empties,
        // and the kernel-half tables are shared with every other space and never freed.
        f.free(p.vm.space().root());
    });
    // SAFETY: see `PROCS`; the thread has exited and been reaped, so nothing else holds
    // this slot.
    unsafe { *PROCS[slot].get() = None };
}

// ---- thread plumbing ------------------------------------------------------------------

use core::sync::atomic::{AtomicU64, AtomicUsize};

/// The user thread's table: boot plus one user thread.
static THREADS: SyncUnsafeCell<core::mem::MaybeUninit<thread::Threads<Cpu, 2>>> =
    SyncUnsafeCell::new(core::mem::MaybeUninit::uninit());
static ENTRY: AtomicUsize = AtomicUsize::new(0);
static MODE: AtomicUsize = AtomicUsize::new(0);
static FAULT_ARG: AtomicUsize = AtomicUsize::new(0);
/// The two argument handle values a MAIN process is given, or zero.
static ARG_HANDLES: [AtomicU64; 2] = [const { AtomicU64::new(0) }; 2];

fn threads() -> *mut thread::Threads<Cpu, 2> {
    THREADS.get().cast()
}

/// The user thread's kernel stack. One user thread runs at a time; it never overflows a
/// page in this check, so no guard page here — the guarded array belongs to the scheduler.
const USER_KSTACK_BYTES: usize = 16 * 1024;
#[repr(C, align(16))]
struct KStack(core::cell::UnsafeCell<[u8; USER_KSTACK_BYTES]>);
// SAFETY: only its address is taken, and one user thread uses it at a time.
unsafe impl Sync for KStack {}
static USER_KSTACK: KStack = KStack(core::cell::UnsafeCell::new([0; USER_KSTACK_BYTES]));

fn user_thread_stack() -> (usize, usize) {
    (USER_KSTACK.0.get() as usize + USER_KSTACK_BYTES, USER_KSTACK_BYTES)
}

// ---- small helpers --------------------------------------------------------------------

pub(crate) fn anon(start: usize, len: usize) -> Region {
    Region {
        start,
        len,
        flags: user_rw(),
        backing: Backing::Anonymous,
        huge: false,
    }
}

/// The first address `vm_map` hands out: a page above the highest segment.
fn first_map_addr(program: &Program) -> usize {
    let mut top = <Cpu as HasUserMode>::USER_START + 0x10_0000;
    for seg in program.segments().flatten() {
        let (_, hi) = seg.pages(Cpu::PAGE_SIZE as u64);
        top = top.max(hi as usize + Cpu::PAGE_SIZE);
    }
    top
}

fn user(p: UserPtr) -> UserAddr {
    UserAddr::new(p.0 as usize)
}

fn handle(h: AbiHandle) -> Handle {
    Handle::from_raw(h.0)
}

fn user_flags(a: &elf::Access) -> hal::PageFlags {
    let mut f = hal::PageFlags::USER | hal::PageFlags::READ;
    if a.write {
        f = f | hal::PageFlags::WRITE;
    }
    if a.execute {
        f = f | hal::PageFlags::EXECUTE;
    }
    f
}

pub(crate) fn user_rw() -> hal::PageFlags {
    hal::PageFlags::USER | hal::PageFlags::READ | hal::PageFlags::WRITE
}

fn handle_error(e: kobject::handle::Error) -> Error {
    use kobject::handle::Error as H;
    match e {
        H::BadHandle => Error::BadHandle,
        H::WrongType { .. } => Error::WrongType,
        H::AccessDenied { .. } => Error::AccessDenied,
        H::TableFull => Error::Full,
    }
}

fn channel_error(e: ipc::Error) -> Error {
    match e {
        ipc::Error::Empty => Error::ShouldWait,
        ipc::Error::Full => Error::Full,
        ipc::Error::PeerClosed | ipc::Error::Closed => Error::PeerClosed,
        ipc::Error::BufferTooSmall { .. } | ipc::Error::TooLarge { .. } => Error::TooLarge,
        _ => Error::BadHandle,
    }
}

//! The first native userspace program, run and checked at boot.
//!
//! This is to userspace what `demand` is to demand paging: `lib/abi`, `kernel/elf` and the
//! `hal::HasUserMode` port are exercised on the host as far as they can be, and this runs
//! them for real. It loads the embedded `init` program into a process, enters ring 3, and
//! grades the process by the exit code it comes back with — so a kernel that answered a
//! system call wrong is caught by the program that received the wrong answer, not by the
//! kernel checking its own work.
//!
//! # What a process is here
//!
//! A [`Process`] is an address space ([`mm::vm::Vm`] over its own page tables, sharing the
//! kernel half), a handle table, and at most one channel it made for itself. One runs at a
//! time: the whole check is three processes in sequence, each built, run to exit, and torn
//! down before the next. That is enough to demonstrate the properties this round is about,
//! and it keeps the machinery a single global rather than a process table, which the
//! object store will bring.
//!
//! # How it runs without the scheduler
//!
//! The user program is a kernel thread whose entry ([`trampoline`]) enters ring 3. The
//! boot thread switches to it through [`thread::Threads`] directly — no timer, no
//! preemption — and every system call the program makes returns on that same thread's
//! kernel stack. `process_exit`, `thread_exit` and a fatal fault all end the thread, which
//! switches back to the boot thread, and the check reads the exit code. Nothing here blocks,
//! so one thread is enough; a program that waited on another thread would need the
//! scheduler, which is why `init`'s channel-to-a-kernel-thread step is left for when the
//! process runs under the real scheduler.
//!
//! # The address space, restored
//!
//! Building the process loads its page tables (its `Vm` faults pages in against the CPU it
//! is copied into), so the check runs on the process root. It saves the kernel root first
//! and restores it before returning, so the later in-kernel suite finds the kernel's own
//! tables, exactly as it left them.

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
struct Process {
    table: HandleTable<N>,
    vm: Vm<'static, Cpu, REGIONS>,
    ids: ObjectIds,
    /// The next free user address `vm_map` hands out, bumped upward.
    next_map: usize,
    channel: Option<Chan>,
    /// The console object's identity, so a handle to it can be recognised.
    console: ObjectId,
    exit: Option<u64>,
}

/// SAFETY INVARIANT: `Some` only while [`run`] drives one process, on the boot CPU, reached
/// only from the system-call handler and the fault hook — both of which run with interrupts
/// masked (`SFMASK` clears IF on a `syscall`; a fault handler runs masked) — and from `run`
/// itself while the user thread is not running. No two of those overlap, so the single
/// mutable borrow each takes is unique.
static CURRENT: SyncUnsafeCell<Option<Process>> = SyncUnsafeCell::new(None);
/// SAFETY INVARIANT: the boot frame allocator, valid while [`run`] holds it. `run` does not
/// use it while the process runs, and clears this before returning.
static FRAMES: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());
/// The share-count slots the process `Vm` borrows.
static SHARE_STORE: SyncUnsafeCell<[ShareSlot; N]> = SyncUnsafeCell::new([ShareSlot::EMPTY; N]);
/// The kernel direct map, set by [`check`] and used to reach frames. Its raw parts, since
/// `DirectMap` is `Copy` but has no `const` default; stored as an `Option`.
static DIRECT: SyncUnsafeCell<Option<DirectMap>> = SyncUnsafeCell::new(None);

fn direct() -> DirectMap {
    // SAFETY: set once by `check` before any process runs, read-only after.
    unsafe { (*DIRECT.get()).expect("direct map set before use") }
}

fn current() -> Option<&'static mut Process> {
    // SAFETY: see `CURRENT`.
    unsafe { (*CURRENT.get()).as_mut() }
}

fn frames() -> KernelFrames<'static> {
    // SAFETY: see `FRAMES`; the direct map is the process's, which is the kernel's direct
    // map (the halves are shared).
    let alloc = unsafe {
        &mut *FRAMES
            .load(Ordering::Relaxed)
            .cast::<FrameAllocator<'static, Cpu>>()
    };
    KernelFrames {
        alloc,
        direct: direct(),
    }
}

// ---- the fault hook and system-call handler -------------------------------------------

/// Resolve a user page fault, or a fault in a user copy, against the process `Vm`.
fn on_user_fault(fault: PageFault) -> bool {
    let Some(p) = current() else { return false };
    let mut f = frames();
    p.vm.fault(fault, &mut f).is_ok()
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
    // SAFETY: on the user thread, masked; `THREADS` is the table it belongs to and this
    // reference ends before the switch inside `exit`.
    let _ = unsafe { thread::Threads::exit(threads()) };
    // `exit` switches away and never comes back to a killed thread. If it somehow returned,
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
        // SAFETY: on the user thread, masked; the reference ends before the switch.
        let _ = unsafe { thread::Threads::exit(threads()) };
        Cpu::halt()
    }

    fn thread_yield(&mut self) -> Result<u64, Error> {
        // Nothing else to run in this single-thread slice; a yield is a no-op that returns.
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
    FRAMES.store((frames as *mut FrameAllocator<'static, Cpu>).cast(), Ordering::Relaxed);
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

    let main = run(c, &program, direct, kernel_root, MODE_MAIN, 0);
    let forge = run(c, &program, direct, kernel_root, MODE_FORGE, 0);
    // The fault mode is handed the kernel root's address as its target: memory it must not
    // reach, and touching it must end the process rather than the kernel.
    let fault = run(c, &program, direct, kernel_root, MODE_FAULT, kernel_root.raw() as usize);

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
    direct: DirectMap,
    kernel_root: PhysAddr,
    mode: usize,
    fault_target: usize,
) -> Option<u64> {
    let mut f = KernelFrames::at(direct);
    let mut space = AddressSpace::<Cpu>::new(direct, &mut f).ok()?;
    // SAFETY: `kernel_root` is the live kernel root, reachable through `direct`, and its
    // tables outlive this process.
    unsafe { space.mirror_top_level(kernel_root).ok()? };
    // SAFETY: the share store is borrowed only here, and a process is torn down before the
    // next is built, so no two borrows are live.
    let shares = Shares::new(unsafe { &mut *SHARE_STORE.get() });
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

    // SAFETY: CURRENT is None here; this is the one writer, before the user thread runs.
    unsafe {
        *CURRENT.get() = Some(Process {
            table: HandleTable::new(),
            vm,
            ids: ObjectIds::new(),
            next_map: first_map_addr(program),
            channel: None,
            console: ObjectId::from_raw(0),
            exit: None,
        });
    }
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
    teardown();
    exit
}

/// Copy each segment into user memory and set its final permissions.
fn install_program(program: &Program) -> Option<()> {
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
    let mut f = frames();
    for seg in program.segments() {
        let seg = seg.ok()?;
        if seg.mem_size == 0 || seg.access.write {
            continue;
        }
        let (lo, hi) = seg.pages(Cpu::PAGE_SIZE as u64);
        p.vm.protect(lo as usize, (hi - lo) as usize, user_flags(&seg.access), &mut f)
            .ok()?;
    }
    Some(())
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
    // Switch to the user thread; it runs until it exits, which switches back here.
    // SAFETY: masked; no reference into the table is live across the switch; boot runs on
    // its own stack.
    let _ = unsafe { thread::Threads::yield_now(threads()) };
    // SAFETY: masked; the user thread has exited.
    let _ = unsafe { (*threads()).reap(id) };
    // SAFETY: pairs with the irq_save above.
    unsafe { Cpu::irq_restore(irq) };
    current().and_then(|p| p.exit)
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

/// Release a process's regions and free its root, then clear it.
fn teardown() {
    let Some(p) = current() else { return };
    let mut f = frames();
    // Collect region starts first: `release` mutates the map as it goes.
    let mut starts = [0usize; REGIONS];
    let mut n = 0;
    for r in p.vm.regions().iter() {
        if let Some(slot) = starts.get_mut(n) {
            *slot = r.start;
            n += 1;
        }
    }
    for &s in &starts[..n] {
        let _ = p.vm.release(s, &mut f);
    }
    // The root frame goes back. The user page tables above it that `release`'s unmap did not
    // empty, and the kernel-half tables (shared, and never to be freed), stay — full
    // per-process teardown arrives with the object store. This check keeps nothing
    // long-lived, so what it frees is what it took.
    f.free(p.vm.space().root());
    // SAFETY: the user thread has exited and been reaped; nothing else holds this.
    unsafe { *CURRENT.get() = None };
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

impl KernelFrames<'static> {
    fn at(direct: DirectMap) -> Self {
        // SAFETY: see `FRAMES`.
        let alloc = unsafe {
            &mut *FRAMES
                .load(Ordering::Relaxed)
                .cast::<FrameAllocator<'static, Cpu>>()
        };
        KernelFrames { alloc, direct }
    }
}

fn anon(start: usize, len: usize) -> Region {
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

fn user_rw() -> hal::PageFlags {
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

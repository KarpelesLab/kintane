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
//! kernel half) and a handle table, in one slot of a small fixed table. A system call or a
//! fault finds its process by the address space loaded on the CPU that took it
//! ([`current_slot`]). The context switch loads a thread's space wherever the thread runs, so
//! that answer follows a thread that migrates.
//!
//! # Threads, and the process lock
//!
//! A process may have several threads, each started by `thread_create` with a user stack of
//! its own, and two of them may be in the kernel on two CPUs at once. So a system call does
//! not simply borrow its process: it takes the process's lock ([`lock`]), and releases it
//! before anything that blocks or yields, taking it again when it next needs the process.
//! A fault taken while the lock is held — a user copy faulting a page in — finds the lock
//! already held by its own CPU and uses it rather than waiting for itself.
//!
//! A process ends when one thread calls `process_exit` or is killed, and its other threads
//! end at their next system call, or at once if they are waiting: the exit wakes every wait,
//! and a waiter whose process is ending ends. Whoever asked for the exit is told when the
//! last thread has gone ([`finish_thread`]), not when the first one leaves, because a
//! process whose threads are still running is not over.
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
use core::ptr::NonNull;
use core::sync::atomic::{AtomicPtr, Ordering};

use abi::{Error, Handle as AbiHandle, UserPtr};
use arch::Cpu;
use elf::Program;
use hal::fault::PageFault;
use hal::user::{UserHooks, UserTrap};
use hal::{Arch, EarlyConsole, HasPageTables, HasUserMode, KernAddr, PhysAddr, UserAddr};
use kobject::handle::{Entry, Handle, HandleTable};
use kobject::{ObjectId, ObjectIds, ObjectType, Rights};
use mm::DirectMap;
use mm::paged::{AddressSpace, FrameSource};
use mm::phys::FrameAllocator;
use mm::vm::{Backing, Region, ShareSlot, Shares, Vm};
use sched::ThreadId;
use time::Instant;

use crate::demand::KernelFrames;
use crate::objects::{self, Object};
use crate::wait::{self, WaitQueue};
use crate::{Check, Live, mp, preempt, sockets, timekeeping, write_hex, write_usize};

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

/// A program names rights by `abi::rights`' bits, and the kernel checks them as
/// `kobject::Rights`. They are one numbering, and a build where they are not fails here.
const _: () = assert!(
    abi::rights::READ == Rights::READ.bits()
        && abi::rights::WRITE == Rights::WRITE.bits()
        && abi::rights::EXECUTE == Rights::EXECUTE.bits()
        && abi::rights::DUPLICATE == Rights::DUPLICATE.bits()
        && abi::rights::TRANSFER == Rights::TRANSFER.bits()
        && abi::rights::WAIT == Rights::WAIT.bits()
        && abi::rights::SIGNAL == Rights::SIGNAL.bits()
        && abi::rights::MAP == Rights::MAP.bits()
        && abi::rights::DESTROY == Rights::DESTROY.bits()
        && abi::rights::INSPECT == Rights::INSPECT.bits()
        && abi::rights::ALL == Rights::ALL.bits(),
    "lib/abi's rights disagree with kobject::Rights"
);

/// The channel the endpoint `object` belongs to, in whichever table holds a handle to it,
/// held for as long as the result lives.
///
/// Not a field of [`Process`], which is where channels began: an endpoint given to another
/// process with `process_transfer` names its channel there too. A channel is the kernel's,
/// like every other object, and lives in the object store ([`objects::channel`]). The
/// reference this returns is counted there, so a channel closed by another thread while a
/// call still uses it is freed when the call lets go, not under it.
pub(crate) fn channel_of(object: ObjectId) -> Option<objects::ChanRef> {
    objects::channel(object)
}

/// The wait queue of the channel the endpoint `object` belongs to.
fn channel_queue(object: ObjectId) -> Option<&'static WaitQueue> {
    channel_of(object).map(|chan| chan.waiters())
}

/// Wake whoever waits on the channel the endpoint `object` belongs to.
fn wake_channel(object: ObjectId) {
    objects::wake_channel(object);
}

fn wake_all_channel_waiters() {
    objects::wake_all_channel_waiters();
}

/// Install both endpoints of a new channel in `table`, or give both back.
fn install_pair<const M: usize>(
    table: &mut HandleTable<M>,
    [a, b]: [Entry; 2],
) -> Result<(Handle, Handle), kobject::handle::Error> {
    let ha = match table.insert(a.object, a.kind, a.rights) {
        Ok(h) => h,
        Err(e) => {
            objects::release(a);
            objects::release(b);
            return Err(e);
        }
    };
    match table.insert(b.object, b.kind, b.rights) {
        Ok(hb) => Ok((ha, hb)),
        Err(e) => {
            if let Some(chan) = channel_of(a.object) {
                let _ = objects::close_endpoint(&chan, table, ha);
            }
            objects::release(b);
            Err(e)
        }
    }
}

/// Everything one process is.
pub(crate) struct Process {
    table: HandleTable<N>,
    pub(crate) vm: Vm<'static, Cpu, REGIONS>,
    ids: ObjectIds,
    /// The next free user address `vm_map` hands out, bumped upward.
    next_map: usize,
    /// The program this process was built from, for its own thread to install. `None` for
    /// a process the kernel filled in itself.
    pub(crate) image: Option<&'static [u8]>,
    /// The console object's identity, so a handle to it can be recognised.
    console: ObjectId,
    pub(crate) exit: Option<u64>,
    /// The physical root of its address space: what [`current`] recognises it by, and what
    /// the context switch loads for its thread.
    pub(crate) root: PhysAddr,
    /// Which slot of [`PROCS`] this is, for the per-slot records kept outside it.
    pub(crate) slot: usize,
    /// Whether a thread has been started in it: the first installs the program, and
    /// every later one is given a stack of its own.
    started: bool,
    /// User stacks given to threads after the first, each reserved once.
    stacks: usize,
    /// The system call ABI it speaks, decided once from its program at [`build`].
    pub(crate) personality: Personality,
    /// Its system call table, chosen with `personality`. [`on_syscall`] calls through it and
    /// never looks at the personality, so a second ABI costs the native one an indirect call
    /// and nothing else.
    syscalls: SyscallTable,
}

/// Which system call ABI a process speaks.
///
/// Decided at load by [`personality_of`], from the program alone: a program cannot choose a
/// personality once it runs, and a process never changes one.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Personality {
    /// KinTane's own ABI, `lib/abi`: a status and a value in two registers, handles for
    /// everything.
    Native,
    /// Linux's x86_64 ABI, answered by [`crate::personality`].
    Linux,
}

/// A process's system call table: one call, given the calling process's slot and the frame
/// to read the arguments from and to write the result into, in that ABI's own convention.
///
/// The slot, not the process: a table takes the process's lock itself, so that the native
/// one can let go of it around a call that blocks ([`Syscalls::wait_for`]).
pub(crate) type SyscallTable = fn(usize, &mut <Cpu as HasUserMode>::SyscallFrame);

/// The personality `program` runs under, or `None` for a program the kernel refuses.
///
/// A program carrying the KinTane ABI note ([`elf::NOTE_KINTANE`]) is native; every native
/// program's link script writes one. A program without it is Linux's if its `EI_OSABI` is
/// System V or Linux, which is what Linux's own toolchains write, and if this kernel has
/// the Linux personality. Anything else — a note-less program for another system, or a
/// Linux one on a kernel without the personality — is refused at load rather than run
/// under an ABI it was not built for.
pub(crate) fn personality_of(program: &Program) -> Option<Personality> {
    if program.has_note(elf::NOTE_KINTANE, elf::NT_KINTANE_ABI) {
        return Some(Personality::Native);
    }
    match program.os_abi() {
        elf::ELFOSABI_SYSV | elf::ELFOSABI_LINUX if crate::personality::ENABLED => {
            Some(Personality::Linux)
        }
        _ => None,
    }
}

/// The table a process of `personality` calls through.
fn table_for(personality: Personality) -> SyscallTable {
    match personality {
        Personality::Native => native_syscalls,
        Personality::Linux => linux_syscalls,
    }
}

/// How many processes can exist at once. The sequential slice needs one; the scheduled
/// check ([`crate::procs`]) runs two workers and a third that is killed while they run.
pub(crate) const MAX_PROCS: usize = 4;

/// Every process, by slot.
///
/// SAFETY INVARIANT: a slot is `Some` only between [`build`] and [`teardown`], and is
/// borrowed in one of two ways:
///
/// * **Under its lock** ([`lock`]), by anything a running process can reach: the system-call
///   handler, the fault hook, and a thread installing its program. The lock is held by one CPU at a
///   time with interrupts masked, and a CPU that already holds it reuses it only from a fault
///   inside a system call, while the call holds no borrow of the process. So the borrow is unique
///   however many threads the process has.
/// * **By index, from boot or a check**, while no thread of that process runs: before its first
///   thread starts, or after its last has ended ([`slot`], [`current`]).
static PROCS: [SyncUnsafeCell<Option<Process>>; MAX_PROCS] =
    [const { SyncUnsafeCell::new(None) }; MAX_PROCS];

/// Each slot's address-space root, or zero: what [`current_slot`] matches the loaded root
/// against, without touching [`PROCS`].
static ROOTS: [crate::AtomicU64; MAX_PROCS] = [const { crate::AtomicU64::new(0) }; MAX_PROCS];
/// Whether each slot is claimed, from the start of [`build`] to the end of [`teardown`].
static USED: [crate::AtomicBool; MAX_PROCS] = [const { crate::AtomicBool::new(false) }; MAX_PROCS];
/// The CPU holding each process's lock, plus one; zero when nobody does.
static OWNER: [crate::AtomicUsize; MAX_PROCS] = [const { crate::AtomicUsize::new(0) }; MAX_PROCS];
/// Threads each process has that have not ended; see [`bind`] and [`leave`].
static LIVE: [crate::AtomicUsize; MAX_PROCS] = [const { crate::AtomicUsize::new(0) }; MAX_PROCS];
/// Set once a process is ending, so its other threads end too.
static EXITING: [crate::AtomicBool; MAX_PROCS] =
    [const { crate::AtomicBool::new(false) }; MAX_PROCS];
/// Set once a process's first thread has installed its program, which a thread started
/// after it waits for.
static INSTALLED: [crate::AtomicBool; MAX_PROCS] =
    [const { crate::AtomicBool::new(false) }; MAX_PROCS];

/// A process's lock, held; released when dropped.
struct Held {
    slot: usize,
    process: *mut Process,
    /// Taken by a fault inside a system call that already held it: dropping this one leaves
    /// the lock with the call.
    reentrant: bool,
    irq: <Cpu as Arch>::IrqState,
}

impl Held {
    fn process(&mut self) -> &mut Process {
        // SAFETY: see `PROCS`: the lock is held by this CPU, masked, and the slot was `Some`
        // when it was taken; a slot is emptied only by `teardown`, after every thread ended.
        unsafe { &mut *self.process }
    }
}

impl Drop for Held {
    fn drop(&mut self) {
        if !self.reentrant {
            OWNER[self.slot].store(0, Ordering::Release);
        }
        // SAFETY: pairs with the `irq_save` in `try_lock`, on this CPU.
        unsafe { Cpu::irq_restore(self.irq) };
    }
}

enum Attempt {
    Held(Held),
    /// Another CPU holds it.
    Busy,
    /// No process in that slot.
    Empty,
}

/// Take process `slot`'s lock if nobody else holds it. Masks interrupts while held.
fn try_lock(slot: usize) -> Attempt {
    let Some(owner) = OWNER.get(slot) else {
        return Attempt::Empty;
    };
    let irq = Cpu::irq_save();
    let me = Cpu::cpu_index() + 1;
    let reentrant = match owner.compare_exchange(0, me, Ordering::AcqRel, Ordering::Acquire) {
        Ok(_) => false,
        Err(holder) if holder == me => true,
        Err(_) => {
            // SAFETY: pairs with the `irq_save` above.
            unsafe { Cpu::irq_restore(irq) };
            return Attempt::Busy;
        }
    };
    // SAFETY: see `PROCS`; the lock is held, so this is the only borrow, and it is turned
    // into a raw pointer at once.
    let process = unsafe { (*PROCS[slot].get()).as_mut() }.map(|p| p as *mut Process);
    let held = Held {
        slot,
        process: process.unwrap_or(core::ptr::null_mut()),
        reentrant,
        irq,
    };
    match process {
        Some(_) => Attempt::Held(held),
        None => Attempt::Empty,
    }
}

/// Take process `slot`'s lock, waiting for it. `None` if there is no such process.
///
/// The wait answers TLB shootdowns: the holder may be changing the process's mappings and
/// waiting, masked, for every CPU to flush — this one included.
fn lock(slot: usize) -> Option<Held> {
    loop {
        match try_lock(slot) {
            Attempt::Held(held) => return Some(held),
            Attempt::Empty => return None,
            Attempt::Busy => {
                mp::answer_shootdowns();
                core::hint::spin_loop();
            }
        }
    }
}
/// SAFETY INVARIANT: the boot frame allocator, valid while a process exists. Reached only
/// through [`with_frames`], which holds [`FRAME_LOCK`], because two processes can fault on
/// two CPUs at once and the allocator is one shared structure.
static FRAMES: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());
/// Exclusion for [`FRAMES`]. Held for one frame operation or one `Vm` call and never
/// across a context switch, so it orders below the scheduler's lock and above nothing.
///
/// Its holder may shoot down TLBs: a `Vm` call that unmaps or write-protects a page waits,
/// with interrupts masked, for every other CPU to flush. So a CPU waiting for this lock
/// answers shootdowns while it spins (see `shootdown`), which is why it is taken only through
/// [`with_frames`] and [`set_frames`] and never with a plain `lock_irqsave`: a thread faulting
/// on another CPU spins for it masked, and a spin that did not answer would never let the
/// holder finish.
static FRAME_CLASS: sync::lockdep::LockClass = sync::lockdep::LockClass::new("userproc.frames");
static FRAME_LOCK: sync::SpinLock<(), Cpu> = sync::SpinLock::with_class((), &FRAME_CLASS);
/// The share-count slots each process's `Vm` borrows: one store per slot, since two
/// processes can exist at once.
static SHARE_STORE: [SyncUnsafeCell<[ShareSlot; N]>; MAX_PROCS] =
    [const { SyncUnsafeCell::new([ShareSlot::EMPTY; N]) }; MAX_PROCS];
/// Every Linux process's share counts, in one store.
///
/// A process and the child `fork` made of it map the same frames, and whichever writes one
/// first must see that the other still maps it; so both count in here, rather than each in
/// its slot's [`SHARE_STORE`]. Sized for the pages of a few small static programs shared at
/// once; a `fork` that would need more fails with nothing shared.
///
/// SAFETY INVARIANT: reached only through the [`Shares`] views [`shares_for`] makes, and a
/// `Vm` touches its shares only in operations made under [`FRAME_LOCK`] ([`with_frames`]).
const LINUX_SHARED: usize = 128;
static LINUX_SHARES: SyncUnsafeCell<[ShareSlot; LINUX_SHARED]> =
    SyncUnsafeCell::new([ShareSlot::EMPTY; LINUX_SHARED]);

/// The share counts a process in `slot` of `personality` is built with.
fn shares_for(slot: usize, personality: Personality) -> Shares<'static> {
    match personality {
        // SAFETY: one store per slot, borrowed while that slot is `Some`, and the caller
        // builds into a slot that is `None`, so no other borrow of this store is live.
        Personality::Native => Shares::new(unsafe { &mut *SHARE_STORE[slot].get() }),
        Personality::Linux => {
            let store = core::ptr::slice_from_raw_parts_mut(
                LINUX_SHARES.get().cast::<ShareSlot>(),
                LINUX_SHARED,
            );
            // SAFETY: a static, valid for ever, and serialised by `FRAME_LOCK`; see
            // `LINUX_SHARES`.
            unsafe { Shares::shared(NonNull::new(store).expect("a static is never null")) }
        }
    }
}

/// The kernel direct map, set by [`check`] and used to reach frames. Its raw parts, since
/// `DirectMap` is `Copy` but has no `const` default; stored as an `Option`.
static DIRECT: SyncUnsafeCell<Option<DirectMap>> = SyncUnsafeCell::new(None);

fn direct() -> DirectMap {
    // SAFETY: set once by `check` before any process runs, read-only after.
    unsafe { (*DIRECT.get()).expect("direct map set before use") }
}

/// Device memory, mapped into a process: readable and writable by user code, and neither
/// cached nor speculated into. What a granted register window is mapped with.
#[cfg_attr(
    not(any(CONFIG_DRIVER_ISOLATION, CONFIG_BLOCK_DOMAIN)),
    expect(
        dead_code,
        reason = "used only by the driver-isolation and block-domain checks, which grant a window"
    )
)]
pub(crate) fn user_device() -> hal::PageFlags {
    user_rw() | hal::PageFlags::DEVICE
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
fn current_slot() -> Option<usize> {
    let root = <Cpu as HasPageTables>::root().raw();
    ROOTS.iter().position(|r| {
        let r = r.load(Ordering::Acquire);
        r != 0 && r == root
    })
}

/// The process [`current_slot`] names, borrowed without its lock: for a kernel thread of a
/// process no other thread of which is running, as [`slot`] is. Everything a running process
/// can reach takes the lock instead; see [`PROCS`].
pub(crate) fn current() -> Option<&'static mut Process> {
    current_slot().and_then(slot)
}

impl Process {
    /// Give this process a handle to `object`, of type `kind`, carrying `rights`.
    ///
    /// The one way in from outside: the handle table stays private, because a table that
    /// anything may insert into is a table whose contents prove nothing about who granted
    /// what. Boot uses this to hand a process the authority it starts with.
    pub(crate) fn grant(
        &mut self,
        object: ObjectId,
        kind: ObjectType,
        rights: Rights,
    ) -> Option<Handle> {
        self.table.insert(object, kind, rights).ok()
    }

    /// A handle to the debug console with `WRITE`, made on demand.
    ///
    /// The console is the one object a process cannot create for itself: it is authority
    /// over the machine's output, and a program holds it only because something handed it
    /// over. Boot does that for the processes it starts.
    pub(crate) fn console_handle(&mut self) -> Option<Handle> {
        if self.console == ObjectId::from_raw(0) {
            self.console = self.ids.next();
        }
        self.table
            .insert(self.console, ObjectType::DeviceResource, Rights::WRITE)
            .ok()
    }

    /// Whether `h` is a handle to this process's console carrying `WRITE`: the check a
    /// descriptor that views the console makes, the same one the native `debug_write` makes.
    #[cfg_attr(
        not(CONFIG_ABI_LINUX),
        expect(
            dead_code,
            reason = "only the Linux personality's descriptors view handles"
        )
    )]
    pub(crate) fn may_write_console(&self, h: Handle) -> bool {
        self.table
            .get_checked(h, ObjectType::DeviceResource, Rights::WRITE)
            .is_ok_and(|entry| entry.object == self.console)
    }

    /// Close handle `h`, retiring what it named. `false` if it named nothing.
    #[cfg_attr(
        not(CONFIG_ABI_LINUX),
        expect(
            dead_code,
            reason = "only the Linux personality's descriptors view handles"
        )
    )]
    pub(crate) fn close_handle(&mut self, h: Handle) -> bool {
        match self.table.close(h) {
            Ok(entry) => {
                objects::release(entry);
                true
            }
            Err(_) => false,
        }
    }

    /// Reserve `bytes` of anonymous memory with `flags` at the next free user address, a page
    /// of unmapped gap above it. Its address, or why not.
    pub(crate) fn reserve_next(
        &mut self,
        bytes: usize,
        flags: hal::PageFlags,
    ) -> Result<usize, Error> {
        let start = self.next_map;
        let end = start.checked_add(bytes).ok_or(Error::InvalidArgument)?;
        if end > <Cpu as HasUserMode>::USER_END {
            return Err(Error::NoMemory);
        }
        self.vm
            .reserve(Region {
                start,
                len: bytes,
                flags,
                backing: Backing::Anonymous,
                huge: false,
            })
            .map_err(|_| Error::NoMemory)?;
        self.next_map = end + Cpu::PAGE_SIZE;
        Ok(start)
    }

    /// Release the region that starts at `start` and is exactly `len` bytes, frames and all.
    /// `false` if no region is exactly that: part of a region is never released.
    #[cfg_attr(
        not(CONFIG_ABI_LINUX),
        expect(
            dead_code,
            reason = "only the Linux personality's munmap releases by range"
        )
    )]
    pub(crate) fn release_exact(&mut self, start: usize, len: usize) -> bool {
        if !self
            .vm
            .regions()
            .iter()
            .any(|r| r.start == start && r.len == len)
        {
            return false;
        }
        with_frames(|f| self.vm.release(start, f).is_ok()).unwrap_or(false)
    }
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
    let _guard = FRAME_LOCK.lock_irqsave_with(mp::answer_shootdowns);
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
    let Some(mut held) = current_slot().and_then(lock) else {
        return false;
    };
    let p = held.process();
    with_frames(|f| p.vm.fault(fault, f).is_ok()).unwrap_or(false)
}

/// End the running user thread, and the process it belongs to, recording why. Does not
/// return.
fn on_kill(trap: UserTrap) -> ! {
    let _ = trap;
    let Some(slot) = current_slot() else {
        end_thread()
    };
    let (last, exit) = match lock(slot) {
        Some(mut held) => {
            let p = held.process();
            // A fault before the program set an exit code is the process being killed. If
            // it had already exited, `record_exit` keeps that.
            record_exit(p, KILLED);
            (leave(slot), p.exit)
        }
        None => (leave(slot), Some(KILLED)),
    };
    finish_thread(slot, last, exit)
}

/// The way back to user code from an interrupt that arrived while it ran. A thread whose
/// process has ended in the meantime ends here instead of returning.
///
/// A thread spinning in user mode makes no system call and waits on nothing, so this is the
/// one place it can be stopped: at the next timer interrupt on its CPU, at the reschedule IPI
/// [`record_exit`] sends to every other CPU, or, on the exiting thread's own CPU, when the
/// scheduler resumes it inside the interrupt that preempted it. See `crate::sibling`.
fn on_user_interrupt() {
    let Some(slot) = current_slot() else {
        return;
    };
    if !EXITING[slot].load(Ordering::Acquire) {
        return;
    }
    INTERRUPT_KILLS.fetch_add(1, Ordering::Relaxed);
    let (last, exit) = match lock(slot) {
        Some(mut held) => (leave(slot), held.process().exit),
        None => (leave(slot), Some(KILLED)),
    };
    finish_thread(slot, last, exit)
}

/// Threads [`on_user_interrupt`] has ended since boot.
static INTERRUPT_KILLS: AtomicU64 = AtomicU64::new(0);

pub(crate) fn interrupt_kills() -> u64 {
    INTERRUPT_KILLS.load(Ordering::Relaxed)
}

/// Count one thread of process `slot` as ended, and say whether it was the last.
///
/// A process whose threads were never counted — the boot-time slice starts its one thread
/// without [`bind`] — has its only thread end as its last.
fn leave(slot: usize) -> bool {
    LIVE.get(slot).is_none_or(|live| {
        live.try_update(Ordering::AcqRel, Ordering::Acquire, |n| n.checked_sub(1))
            .map_or(true, |before| before == 1)
    })
}

/// End the running thread of process `slot`, telling whoever waits for the process if it
/// was the last. Called with no process lock held. Never returns.
fn finish_thread(slot: usize, last: bool, exit: Option<u64>) -> ! {
    if last {
        crate::objects::on_process_exit(slot, exit.unwrap_or(KILLED));
        // A Linux parent waiting in `wait4` learns of it here, once no thread is left.
        crate::personality::process_ended(slot, exit.unwrap_or(KILLED));
    }
    end_thread()
}

/// End the running user thread, whichever scheduler it belongs to: the one the boot-time
/// slice drives by hand, or the kernel's own once it is running. Never returns.
pub(crate) fn end_thread() -> ! {
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

/// Record that a process is ending, with `code` unless it already had one, and wake its
/// other threads so they end too.
///
/// Every path that ends a process goes through here — the program's own exit, its last
/// thread ending, and the kernel killing it — so no thread of it is left waiting on
/// something that will never come. Whoever asked to be told of the exit is told by
/// [`finish_thread`], once the last thread has gone.
fn record_exit(p: &mut Process, code: u64) {
    if p.exit.is_none() {
        p.exit = Some(code);
    }
    EXITING[p.slot].store(true, Ordering::Release);
    // Its other threads may be waiting on anything. Each wakes, finds its process ending,
    // and ends at the call it was waiting in. Other processes' waiters wake for nothing and
    // wait again.
    objects::wake_all_waiters();
    wake_all_channel_waiters();
    // A thread of it running user code on another CPU neither calls nor waits; an interrupt
    // is what reaches it ([`on_user_interrupt`]).
    if threads_live(p.slot) > 1 {
        preempt::interrupt_other_cpus();
    }
    // And the Linux personality's own queues: pipes, futexes, `wait4`.
    crate::personality::wake_all_waiters();
}

/// End the running process with `code`, from its own system call. Never returns.
#[cfg_attr(
    not(CONFIG_ABI_LINUX),
    expect(dead_code, reason = "the native ABI's exits go through its handler")
)]
pub(crate) fn exit_current(p: &mut Process, code: u64) -> ! {
    let slot = p.slot;
    record_exit(p, code);
    let exit = p.exit;
    let last = leave(slot);
    // The call ending here holds the process's lock ([`linux_syscalls`]) and never returns to
    // drop it, so it is let go of now, as the native exits do.
    if let Some(owner) = OWNER.get(slot) {
        let _ =
            owner.compare_exchange(Cpu::cpu_index() + 1, 0, Ordering::AcqRel, Ordering::Acquire);
    }
    finish_thread(slot, last, exit)
}

/// Recorded as the exit code when the kernel kills a process rather than the program
/// choosing its own code.
pub(crate) const KILLED: u64 = 0xffff_ffff_ffff_ffff;

/// Fail the call in `frame` the native way: the only ABI a call with no process can have.
fn unsupported(frame: &mut <Cpu as HasUserMode>::SyscallFrame) {
    use hal::user::SyscallFrame;
    let (status, value) = abi::encode(Err(Error::Unsupported));
    frame.set_result(status, value);
}

/// Run one system call, through the calling process's own table.
fn on_syscall(frame: &mut <Cpu as HasUserMode>::SyscallFrame) {
    let Some(slot) = current_slot() else {
        unsupported(frame);
        return;
    };
    // Where the call was served. The only record of a user thread having run on a CPU, and
    // what makes a migration observable.
    CPUS_SEEN[slot].fetch_or(1 << (Cpu::cpu_index() & 63), Ordering::Relaxed);
    // The table is read under the lock and called without it: each table takes the lock
    // itself, for as long as it needs it.
    let Some(table) = lock(slot).map(|mut held| held.process().syscalls) else {
        unsupported(frame);
        return;
    };
    table(slot, frame)
}

/// The native table: decode and perform the call in `frame` by `lib/abi`'s numbers.
fn native_syscalls(slot: usize, frame: &mut <Cpu as HasUserMode>::SyscallFrame) {
    use hal::user::SyscallFrame;
    let Some(held) = lock(slot) else {
        unsupported(frame);
        return;
    };
    let mut calls = Syscalls {
        slot,
        held: Some(held),
    };
    // A thread whose process another thread has ended ends at its next call...
    calls.end_if_exiting();
    let result = abi::dispatch(&mut calls, frame.number(), frame.args());
    // ...or on its way out of the one it was in, which the ending woke.
    calls.end_if_exiting();
    drop(calls);
    let (status, value) = abi::encode(result);
    frame.set_result(status, value);
}

/// The Linux table: [`crate::personality::syscalls`]. It takes the process's lock itself, a
/// piece of a call at a time ([`with_locked`]), so that a call that blocks — a pipe, a futex,
/// `wait4` — waits through [`crate::wait`] holding nothing, as the native calls do.
fn linux_syscalls(slot: usize, frame: &mut <Cpu as HasUserMode>::SyscallFrame) {
    crate::personality::syscalls(slot, frame)
}

// ---- what the Linux personality asks of a process ---------------------------------------

/// Run `f` on process `slot` under its lock. `None` if there is no such process.
#[cfg_attr(
    not(CONFIG_ABI_LINUX),
    expect(dead_code, reason = "used only by the Linux personality")
)]
pub(crate) fn with_locked<R>(slot: usize, f: impl FnOnce(&mut Process) -> R) -> Option<R> {
    let mut held = lock(slot)?;
    Some(f(held.process()))
}

/// Whether process `slot` is ending, so a thread of it must end at the call it is in.
#[cfg_attr(
    not(CONFIG_ABI_LINUX),
    expect(dead_code, reason = "used only by the Linux personality")
)]
pub(crate) fn exiting(slot: usize) -> bool {
    EXITING.get(slot).is_some_and(|e| e.load(Ordering::Acquire))
}

/// End the calling thread if its process is ending. Called holding no process lock.
#[cfg_attr(
    not(CONFIG_ABI_LINUX),
    expect(dead_code, reason = "used only by the Linux personality")
)]
pub(crate) fn end_if_exiting(slot: usize) {
    if !exiting(slot) {
        return;
    }
    let last = leave(slot);
    let exit = lock(slot).and_then(|mut held| held.process().exit);
    finish_thread(slot, last, exit)
}

/// End the calling thread of process `slot` alone, as Linux's `exit` does; the process
/// ends with `code` if it was the last. Called holding no process lock. Never returns.
#[cfg_attr(
    not(CONFIG_ABI_LINUX),
    expect(dead_code, reason = "used only by the Linux personality")
)]
pub(crate) fn exit_thread_current(slot: usize, code: u64) -> ! {
    let ended = lock(slot).map(|mut held| {
        // Counted under the lock, as the native `thread_exit` counts it.
        let last = leave(slot);
        let p = held.process();
        if last {
            record_exit(p, code);
        }
        (last, p.exit)
    });
    let (last, exit) = match ended {
        Some(ended) => ended,
        None => (leave(slot), Some(code)),
    };
    finish_thread(slot, last, exit)
}

/// Build a Linux process for `program` in `slot` and start its first thread, from a kernel
/// thread with the scheduler running: install its segments, let `start` lay out what it
/// starts with and return its stack pointer, and enter it there. What a check or the stress
/// run starts a Linux program with; [`run_linux`] is the boot-time slice's.
#[cfg_attr(
    not(CONFIG_ABI_LINUX),
    expect(dead_code, reason = "used only by the Linux personality")
)]
pub(crate) fn start_linux(
    slot: usize,
    program: &Program,
    start: impl FnOnce(&mut Process, &Program) -> Option<usize>,
) -> Option<ThreadId> {
    let begun = crate::spawn::start_thread(prepare_linux(slot, program, start)?);
    if begun.is_none() {
        teardown(slot);
    }
    begun
}

/// [`start_linux`] without starting the thread: build the process, install it, lay out its
/// start, and return how its first thread enters it, for `spawn::start_thread`. `None` has
/// torn down whatever it built.
#[cfg_attr(
    not(CONFIG_ABI_LINUX),
    expect(dead_code, reason = "used only by the Linux personality")
)]
pub(crate) fn prepare_linux(
    slot: usize,
    program: &Program,
    start: impl FnOnce(&mut Process, &Program) -> Option<usize>,
) -> Option<crate::spawn::Start> {
    let root = build_as(slot, program, Personality::Linux)?;
    // Masked from loading the space to putting the kernel's back: a switch in between would
    // load this kernel thread's own space, the kernel's, under the copy.
    let irq = Cpu::irq_save();
    // SAFETY: `root` mirrors the kernel half, where the running code and stack live.
    unsafe { Cpu::set_root(root) };
    let sp = install_program(program).and_then(|()| start(self::slot(slot)?, program));
    // SAFETY: as above.
    unsafe { Cpu::set_root(kernel_root()) };
    // SAFETY: pairs with the `irq_save` above.
    unsafe { Cpu::irq_restore(irq) };
    let prepared = sp.and_then(|user_sp| {
        let mut held = lock(slot)?;
        held.process().started = true;
        Some(crate::spawn::Start {
            slot,
            root,
            entry: program.entry as usize,
            user_sp,
            install: false,
            args: [0; 4],
        })
    });
    if prepared.is_none() {
        teardown(slot);
    }
    prepared
}

/// Make a copy-on-write child of Linux process `parent` in a free slot, as `fork` does: its
/// address space shares every page with the parent's, and it has no thread and no handles
/// yet. Returns the child's slot and root. Called holding no process lock.
#[cfg_attr(
    not(CONFIG_ABI_LINUX),
    expect(dead_code, reason = "used only by the Linux personality")
)]
pub(crate) fn fork_linux(parent: usize) -> Option<(usize, PhysAddr)> {
    let child = (0..MAX_PROCS).find(|&i| !USED[i].swap(true, Ordering::AcqRel))?;
    let built = fork_claimed(parent, child);
    if built.is_none() {
        USED[child].store(false, Ordering::Release);
    }
    built.map(|root| (child, root))
}

/// [`fork_linux`], into a slot it has claimed.
fn fork_claimed(parent: usize, child: usize) -> Option<PhysAddr> {
    if self::slot(child).is_some() {
        return None;
    }
    let direct = direct();
    let mut space = with_frames(|f| AddressSpace::<Cpu>::new(direct, f).ok())??;
    // SAFETY: as in `build_claimed`.
    unsafe { space.mirror_top_level(kernel_root()).ok()? };
    let mut vm = Vm::new(space, shares_for(child, Personality::Linux));
    let mut held = lock(parent)?;
    let p = held.process();
    if p.personality != Personality::Linux {
        return None;
    }
    let shared = with_frames(|f| p.vm.fork_into(&mut vm, f).is_ok()).unwrap_or(false);
    let root = vm.space().root();
    // In place even if the share failed part-way, so that teardown releases what was shared
    // and every count goes back.
    // SAFETY: see `PROCS`; the slot is `None` and no thread exists for it.
    unsafe {
        *PROCS[child].get() = Some(Process {
            table: HandleTable::new(),
            vm,
            ids: ObjectIds::new(),
            next_map: p.next_map,
            image: None,
            console: ObjectId::from_raw(0),
            exit: None,
            root,
            slot: child,
            started: true,
            stacks: p.stacks,
            personality: Personality::Linux,
            syscalls: table_for(Personality::Linux),
        });
    }
    drop(held);
    LIVE[child].store(0, Ordering::Release);
    EXITING[child].store(false, Ordering::Release);
    INSTALLED[child].store(true, Ordering::Release);
    ROOTS[child].store(root.raw(), Ordering::Release);
    if !shared {
        teardown(child);
        return None;
    }
    Some(root)
}

/// Replace Linux process `slot`'s memory with `program`, as `execve` does: every region
/// released, the program's segments and a stack reserved, and the segments installed. On
/// the process's own thread, its only one, holding no process lock. `None` leaves the
/// process with no memory to return to, which the caller must end.
#[cfg_attr(
    not(CONFIG_ABI_LINUX),
    expect(dead_code, reason = "used only by the Linux personality")
)]
pub(crate) fn exec_linux(slot: usize, program: &Program) -> Option<()> {
    {
        let mut held = lock(slot)?;
        let p = held.process();
        with_frames(|f| {
            let mut starts = [0usize; REGIONS];
            let mut n = 0;
            for r in p.vm.regions().iter() {
                if let Some(s) = starts.get_mut(n) {
                    *s = r.start;
                    n += 1;
                }
            }
            starts[..n].iter().all(|&s| p.vm.release(s, f).is_ok())
        })
        .filter(|&released| released)?;
        for seg in program.segments() {
            let seg = seg.ok()?;
            if seg.mem_size == 0 {
                continue;
            }
            let (lo, hi) = seg.pages(Cpu::PAGE_SIZE as u64);
            p.vm.reserve(anon(lo as usize, (hi - lo) as usize)).ok()?;
        }
        let stack_bottom = user_stack_top() - USER_STACK_PAGES * Cpu::PAGE_SIZE;
        p.vm.reserve(anon(stack_bottom, USER_STACK_PAGES * Cpu::PAGE_SIZE))
            .ok()?;
        p.next_map = first_map_addr(program);
        p.stacks = 0;
        p.image = None;
    }
    install_program(program)
}

/// The kernel's implementation of the native ABI, over one process.
struct Syscalls {
    slot: usize,
    /// The process's lock, while held. Released around anything that blocks or yields, and
    /// taken again by [`Syscalls::p`] when the call next needs the process.
    held: Option<Held>,
}

impl abi::Handler for Syscalls {
    fn process_exit(&mut self, code: u64) -> Result<u64, Error> {
        let slot = self.slot;
        let p = self.p();
        record_exit(p, code);
        let exit = p.exit;
        let last = leave(slot);
        self.unlock();
        finish_thread(slot, last, exit)
    }

    fn thread_exit(&mut self, code: u64) -> Result<u64, Error> {
        let slot = self.slot;
        // Counted under the process's lock, so two threads ending at once cannot each take
        // the other for the last. The last thread's code is the process's.
        let last = leave(slot);
        let p = self.p();
        if last {
            record_exit(p, code);
        }
        let exit = p.exit;
        self.unlock();
        finish_thread(slot, last, exit)
    }

    fn thread_yield(&mut self) -> Result<u64, Error> {
        // Under the scheduler, give up the rest of the slice; in the boot-time slice there
        // is nothing else to run, and the call returns. Never while holding the process.
        self.unlock();
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
            .p()
            .table
            .get_checked(handle(console), ObjectType::DeviceResource, Rights::WRITE)
            .map_err(handle_error)?;
        if entry.object != self.p().console {
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
        self.p()
            .reserve_next(pages * page, user_rw())
            .map(|start| start as u64)
    }

    fn channel_create(&mut self, out: UserPtr) -> Result<u64, Error> {
        let ends = objects::new_channel().ok_or(Error::Full)?;
        let (ha, hb) = install_pair(&mut self.p().table, ends).map_err(handle_error)?;
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
        let entry = self.p().table.get(handle(channel)).map_err(handle_error)?;
        let ch = channel_of(entry.object).ok_or(Error::BadHandle)?;
        ch.send(&mut self.p().table, handle(channel), &buf[..len], &[])
            .map_err(channel_error)?;
        wake_channel(entry.object);
        Ok(0)
    }

    fn channel_read(&mut self, channel: AbiHandle, buf: UserPtr, cap: usize) -> Result<u64, Error> {
        let entry = self.p().table.get(handle(channel)).map_err(handle_error)?;
        let ch = channel_of(entry.object).ok_or(Error::BadHandle)?;
        let mut bytes = [0u8; 64];
        let mut handles = [Handle::from_raw(0); 2];
        let cap = cap.min(bytes.len());
        let got = ch
            .receive(&mut self.p().table, handle(channel), &mut bytes[..cap], &mut handles)
            .map_err(channel_error)?;
        // SAFETY: as `channel_create`.
        unsafe { Cpu::copy_to_user(user(buf), &bytes[..got.bytes]) }.map_err(|_| Error::Fault)?;
        Ok(got.bytes as u64)
    }

    fn handle_close(&mut self, h: AbiHandle) -> Result<u64, Error> {
        let entry = self.p().table.get(handle(h)).map_err(handle_error)?;
        if let Some(ch) = channel_of(entry.object) {
            // Through the channel, so that its peer sees this end close: a thread waiting to
            // receive there is told `PeerClosed` rather than waiting for a message that
            // cannot come. Handles still queued for this end are given back with it.
            objects::close_endpoint(&ch, &mut self.p().table, handle(h)).map_err(channel_error)?;
            return Ok(0);
        }
        let entry = self.p().table.close(handle(h)).map_err(handle_error)?;
        // The handle was this process's only name for the object. Retiring here is what
        // brings the object count back to its baseline once a program has cleaned up.
        objects::retire(entry.object);
        Ok(0)
    }

    fn process_create(&mut self, image: AbiHandle) -> Result<u64, Error> {
        let bytes = objects::with_handle(
            &self.p().table,
            handle(image),
            ObjectType::MemoryRegion,
            Rights::READ,
            |o| match o {
                Object::Image { bytes } => Some(*bytes),
                _ => None,
            },
        )
        .map_err(store_error)?
        .ok_or(Error::WrongType)?;
        let program = parse(bytes).ok_or(Error::InvalidArgument)?;
        // The child's thread enters its program the native way, so only a native program.
        if personality_of(&program) != Some(Personality::Native) {
            return Err(Error::InvalidArgument);
        }
        let slot = free_slot().ok_or(Error::Full)?;
        build(slot, &program).ok_or(Error::NoMemory)?;
        // The child's own thread installs the program; remember what from.
        if let Some(child) = self::slot(slot) {
            child.image = Some(bytes);
        }
        let id = objects::create(Object::Process {
            slot,
            exited: false,
            code: 0,
            waiter: None,
        })
        .ok_or(Error::Full)?;
        match self.p().table.insert(id, ObjectType::Process, Rights::ALL) {
            Ok(h) => Ok(u64::from(h.raw())),
            Err(e) => {
                // Nothing could name the process, so nothing could ever tear it down.
                objects::retire(id);
                teardown(slot);
                Err(handle_error(e))
            }
        }
    }

    fn process_transfer(&mut self, process: AbiHandle, h: AbiHandle) -> Result<u64, Error> {
        let slot = self.target_slot(process)?;
        // Moving a handle into the table it is already in would put it there twice, under
        // two values.
        if slot == self.slot {
            return Err(Error::InvalidArgument);
        }
        self.with_other(slot, |mine, child| {
            let entry = mine.table.transfer_out(handle(h)).map_err(handle_error)?;
            match child.table.insert(entry.object, entry.kind, entry.rights) {
                Ok(new) => Ok(u64::from(new.raw())),
                Err(e) => {
                    // Give it back rather than destroy authority the caller still owns.
                    let _ = mine.table.insert(entry.object, entry.kind, entry.rights);
                    Err(handle_error(e))
                }
            }
        })?
    }

    fn thread_create(&mut self, process: AbiHandle, entry: u64, arg: u64) -> Result<u64, Error> {
        let slot = self.target_slot(process)?;
        let args = [arg as usize, 0, 0, 0];
        let start = if slot == self.slot {
            prepare_thread(self.p(), entry, args)
        } else {
            self.with_other(slot, |_, target| prepare_thread(target, entry, args))?
        }?;
        let id = crate::spawn::start_thread(start).ok_or(Error::NoMemory)?;
        let object = objects::create(Object::Thread { id }).ok_or(Error::Full)?;
        self.p()
            .table
            .insert(object, ObjectType::Thread, Rights::ALL)
            .map(|h| u64::from(h.raw()))
            .map_err(handle_error)
    }

    fn process_wait(
        &mut self,
        process: AbiHandle,
        completion: AbiHandle,
        key: u64,
        timeout_ns: u64,
    ) -> Result<u64, Error> {
        if completion.0 == 0 {
            // Wait for the process itself, on its object's queue, which its exit wakes.
            let id = self
                .p()
                .table
                .get_checked(handle(process), ObjectType::Process, Rights::WAIT)
                .map_err(handle_error)?
                .object;
            let waiters = objects::waiters(id).ok_or(Error::BadHandle)?;
            return self.wait_for(
                waiters,
                timeout_ns,
                || None,
                move |_| match objects::exit_code(id) {
                    Some(Some(code)) => Ok(Some(code)),
                    Some(None) => Ok(None),
                    None => Err(Error::BadHandle),
                },
            );
        }
        // Arming a queue waits for nothing, so a timeout on it is a caller's mistake.
        if timeout_ns != 0 {
            return Err(Error::InvalidArgument);
        }
        let queue = self
            .p()
            .table
            .get_checked(handle(completion), ObjectType::Completion, Rights::WRITE)
            .map_err(handle_error)?
            .object;
        // Arm, or answer now: a process that has already ended must not leave its waiter
        // waiting for something that has been and gone.
        let ended = objects::with_handle(
            &self.p().table,
            handle(process),
            ObjectType::Process,
            Rights::WAIT,
            |o| match o {
                Object::Process {
                    exited,
                    code,
                    waiter,
                    ..
                } => {
                    if *exited {
                        Ok(Some(*code))
                    } else if waiter.is_some() {
                        Err(Error::Full)
                    } else {
                        *waiter = Some((queue, key));
                        Ok(None)
                    }
                }
                _ => Err(Error::WrongType),
            },
        )
        .map_err(store_error)??;
        if let Some(code) = ended {
            objects::post(queue, key, code).map_err(|_| Error::Full)?;
        }
        Ok(0)
    }

    fn completion_create(&mut self) -> Result<u64, Error> {
        let id = objects::create(Object::new_completion()).ok_or(Error::Full)?;
        self.p()
            .table
            .insert(id, ObjectType::Completion, Rights::ALL)
            .map(|h| u64::from(h.raw()))
            .map_err(handle_error)
    }

    fn completion_poll(&mut self, completion: AbiHandle, out: UserPtr) -> Result<u64, Error> {
        let queue = self
            .p()
            .table
            .get_checked(handle(completion), ObjectType::Completion, Rights::READ)
            .map_err(handle_error)?
            .object;
        // Timers deliver when their queue is looked at; see `objects::deliver_due_timers`.
        let _ = objects::deliver_due_timers(queue, timekeeping::now().as_nanos());
        let taken = objects::with_handle(
            &self.p().table,
            handle(completion),
            ObjectType::Completion,
            Rights::READ,
            objects::take,
        )
        .map_err(store_error)?;
        let (key, value) = taken.ok_or(Error::ShouldWait)?;
        let mut bytes = [0u8; 16];
        bytes[..8].copy_from_slice(&key.to_le_bytes());
        bytes[8..].copy_from_slice(&value.to_le_bytes());
        // SAFETY: the process address space is loaded; `copy_to_user` checks the range and
        // faults the page in, and refuses an address it cannot map.
        unsafe { Cpu::copy_to_user(user(out), &bytes) }.map_err(|_| Error::Fault)?;
        Ok(1)
    }

    fn vm_region_create(&mut self, len: usize) -> Result<u64, Error> {
        let page = Cpu::PAGE_SIZE;
        let bytes = len.div_ceil(page).max(1) * page;
        let id = objects::create(Object::Region { len: bytes }).ok_or(Error::Full)?;
        self.p()
            .table
            .insert(id, ObjectType::MemoryRegion, Rights::ALL)
            .map(|h| u64::from(h.raw()))
            .map_err(handle_error)
    }

    fn vm_map_in(&mut self, process: AbiHandle, region: AbiHandle) -> Result<u64, Error> {
        let len = objects::with_handle(
            &self.p().table,
            handle(region),
            ObjectType::MemoryRegion,
            Rights::MAP,
            |o| match o {
                Object::Region { len } => Some(*len),
                // An image is memory the kernel owns; mapping one into a process is not
                // something this kernel offers.
                _ => None,
            },
        )
        .map_err(store_error)?
        .ok_or(Error::WrongType)?;
        let slot = self.target_slot(process)?;
        let mapped = if slot == self.slot {
            self.p().reserve_next(len, user_rw())
        } else {
            self.with_other(slot, |_, target| target.reserve_next(len, user_rw()))?
        };
        mapped.map(|start| start as u64)
    }

    fn channel_send(
        &mut self,
        channel: AbiHandle,
        bytes: UserPtr,
        len: usize,
        handles: UserPtr,
        count: usize,
    ) -> Result<u64, Error> {
        if len > 64 || count > 2 {
            return Err(Error::TooLarge);
        }
        let mut buf = [0u8; 64];
        // SAFETY: as `debug_write`.
        unsafe { Cpu::copy_from_user(&mut buf[..len], user(bytes)) }.map_err(|_| Error::Fault)?;
        let mut raw = [0u8; 16];
        if count > 0 {
            // SAFETY: as above.
            unsafe { Cpu::copy_from_user(&mut raw[..count * 8], user(handles)) }
                .map_err(|_| Error::Fault)?;
        }
        let word = |at: usize| u32::from_le_bytes([raw[at], raw[at + 1], raw[at + 2], raw[at + 3]]);
        let mut transfers = [ipc::Transfer::whole(Handle::from_raw(0)); 2];
        for (i, t) in transfers.iter_mut().enumerate().take(count) {
            // The mask only ever narrows: `ipc` gives the receiver what the sender held,
            // intersected with it.
            *t = ipc::Transfer::narrowed(
                Handle::from_raw(word(8 * i)),
                Rights::from_bits_truncate(word(8 * i + 4)),
            );
        }
        let entry = self.p().table.get(handle(channel)).map_err(handle_error)?;
        let ch = channel_of(entry.object).ok_or(Error::BadHandle)?;
        ch.send(&mut self.p().table, handle(channel), &buf[..len], &transfers[..count])
            .map_err(channel_error)?;
        wake_channel(entry.object);
        Ok(0)
    }

    fn channel_recv(
        &mut self,
        channel: AbiHandle,
        buf: UserPtr,
        cap: usize,
        handles: UserPtr,
        hcap: usize,
        timeout_ns: u64,
    ) -> Result<u64, Error> {
        let cap = cap.min(64);
        let hcap = hcap.min(2);
        let entry = self.p().table.get(handle(channel)).map_err(handle_error)?;
        let queue = channel_queue(entry.object).ok_or(Error::BadHandle)?;
        // Both buffers are written before anything is received, so their pages are present:
        // a message taken off the queue and then refused its copy would be lost, and the
        // handles it carried with it.
        // SAFETY: as `channel_create`.
        unsafe { Cpu::copy_to_user(user(buf), &[0u8; 64][..cap]) }.map_err(|_| Error::Fault)?;
        if hcap > 0 {
            // SAFETY: as above.
            unsafe { Cpu::copy_to_user(user(handles), &[0u8; 8][..hcap * 4]) }
                .map_err(|_| Error::Fault)?;
        }
        let (object, endpoint) = (entry.object, handle(channel));
        self.wait_for(
            queue,
            timeout_ns,
            || None,
            move |p| {
                let ch = channel_of(object).ok_or(Error::PeerClosed)?;
                let mut bytes = [0u8; 64];
                let mut got_handles = [Handle::from_raw(0); 2];
                let got = match ch.receive(
                    &mut p.table,
                    endpoint,
                    &mut bytes[..cap],
                    &mut got_handles[..hcap],
                ) {
                    Ok(got) => got,
                    Err(ipc::Error::Empty) => return Ok(None),
                    Err(e) => return Err(channel_error(e)),
                };
                let mut raw = [0u8; 8];
                for (i, h) in got_handles.iter().take(got.handles).enumerate() {
                    raw[4 * i..4 * i + 4].copy_from_slice(&h.raw().to_le_bytes());
                }
                // SAFETY: as `channel_create`; both ranges were written above.
                unsafe { Cpu::copy_to_user(user(buf), &bytes[..got.bytes]) }
                    .map_err(|_| Error::Fault)?;
                if got.handles > 0 {
                    // SAFETY: as above.
                    unsafe { Cpu::copy_to_user(user(handles), &raw[..4 * got.handles]) }
                        .map_err(|_| Error::Fault)?;
                }
                Ok(Some(got.bytes as u64 | (got.handles as u64) << 32))
            },
        )
    }

    fn completion_wait(
        &mut self,
        completion: AbiHandle,
        out: UserPtr,
        timeout_ns: u64,
    ) -> Result<u64, Error> {
        let queue = self
            .p()
            .table
            .get_checked(handle(completion), ObjectType::Completion, Rights::READ)
            .map_err(handle_error)?
            .object;
        let waiters = objects::waiters(queue).ok_or(Error::BadHandle)?;
        // SAFETY: as `completion_poll`; written first for the reason `channel_recv` gives.
        unsafe { Cpu::copy_to_user(user(out), &[0u8; 16]) }.map_err(|_| Error::Fault)?;
        let now = || timekeeping::now().as_nanos();
        self.wait_for(
            waiters,
            timeout_ns,
            // A timer on this queue ends the wait when it is due, which is when its
            // completion can be delivered.
            move || objects::deliver_due_timers(queue, now()),
            move |_| {
                let _ = objects::deliver_due_timers(queue, now());
                let (key, value) = match objects::with(queue, objects::take) {
                    None => return Err(Error::BadHandle),
                    Some(None) => return Ok(None),
                    Some(Some(entry)) => entry,
                };
                let mut bytes = [0u8; 16];
                bytes[..8].copy_from_slice(&key.to_le_bytes());
                bytes[8..].copy_from_slice(&value.to_le_bytes());
                // SAFETY: as above.
                unsafe { Cpu::copy_to_user(user(out), &bytes) }.map_err(|_| Error::Fault)?;
                Ok(Some(1))
            },
        )
    }

    fn event_create(&mut self) -> Result<u64, Error> {
        let id = objects::create(Object::Event { signalled: false }).ok_or(Error::Full)?;
        self.insert_new(id, ObjectType::Event)
    }

    fn event_signal(&mut self, event: AbiHandle) -> Result<u64, Error> {
        let id = self
            .p()
            .table
            .get_checked(handle(event), ObjectType::Event, Rights::SIGNAL)
            .map_err(handle_error)?
            .object;
        if objects::signal_event(id) {
            Ok(0)
        } else {
            Err(Error::BadHandle)
        }
    }

    fn event_wait(&mut self, event: AbiHandle, timeout_ns: u64) -> Result<u64, Error> {
        let id = self
            .p()
            .table
            .get_checked(handle(event), ObjectType::Event, Rights::WAIT)
            .map_err(handle_error)?
            .object;
        let waiters = objects::waiters(id).ok_or(Error::BadHandle)?;
        self.wait_for(
            waiters,
            timeout_ns,
            || None,
            move |_| match objects::consume_event(id) {
                Some(true) => Ok(Some(0)),
                Some(false) => Ok(None),
                None => Err(Error::BadHandle),
            },
        )
    }

    fn timer_create(&mut self, completion: AbiHandle, key: u64) -> Result<u64, Error> {
        let queue = self
            .p()
            .table
            .get_checked(handle(completion), ObjectType::Completion, Rights::WRITE)
            .map_err(handle_error)?
            .object;
        let id = objects::create(Object::Timer {
            queue,
            key,
            deadline: objects::DISARMED,
            period: 0,
            fires: 0,
        })
        .ok_or(Error::Full)?;
        self.insert_new(id, ObjectType::Timer)
    }

    fn timer_set(&mut self, timer: AbiHandle, delay_ns: u64, period_ns: u64) -> Result<u64, Error> {
        let id = self
            .p()
            .table
            .get_checked(handle(timer), ObjectType::Timer, Rights::WRITE)
            .map_err(handle_error)?
            .object;
        // `DISARMED` is the one deadline a timer cannot be armed for; a delay that would
        // reach it waits one nanosecond less, which is to say for ever.
        let deadline = timekeeping::now()
            .as_nanos()
            .saturating_add(delay_ns)
            .min(objects::DISARMED - 1);
        if objects::set_timer(id, deadline, period_ns) {
            Ok(0)
        } else {
            Err(Error::BadHandle)
        }
    }

    fn timer_cancel(&mut self, timer: AbiHandle) -> Result<u64, Error> {
        let id = self
            .p()
            .table
            .get_checked(handle(timer), ObjectType::Timer, Rights::WRITE)
            .map_err(handle_error)?
            .object;
        if objects::set_timer(id, objects::DISARMED, 0) {
            Ok(0)
        } else {
            Err(Error::BadHandle)
        }
    }

    fn clock_now(&mut self) -> Result<u64, Error> {
        Ok(timekeeping::now().as_nanos())
    }

    // ---- sockets: see `crate::sockets` -------------------------------------------------------

    fn socket_create(&mut self, kind: u64) -> Result<u64, Error> {
        if kind != abi::socket::STREAM {
            return Err(Error::InvalidArgument);
        }
        if !sockets::available() {
            return Err(Error::Unsupported);
        }
        let socket = Object::Socket {
            port: 0,
            conn: None,
            listening: false,
        };
        let id = objects::create(socket).ok_or(Error::Full)?;
        self.insert_new(id, ObjectType::Socket)
    }

    fn socket_bind(&mut self, socket: AbiHandle, address: u64) -> Result<u64, Error> {
        let id = self.socket(socket, Rights::WRITE)?;
        sockets::bind(id, address)
    }

    fn socket_connect(
        &mut self,
        socket: AbiHandle,
        address: u64,
        timeout_ns: u64,
    ) -> Result<u64, Error> {
        let id = self.socket(socket, Rights::WRITE)?;
        let conn = sockets::connect(id, address)?;
        self.wait_for(sockets::waits(), timeout_ns, sockets::next_look, move |_| {
            sockets::connected(conn)
        })
    }

    fn socket_listen(&mut self, socket: AbiHandle, backlog: u64) -> Result<u64, Error> {
        // Advisory, as the table says: the stack's own backlog applies.
        let _ = backlog;
        let id = self.socket(socket, Rights::WRITE)?;
        sockets::listen(id)
    }

    fn socket_accept(&mut self, socket: AbiHandle, timeout_ns: u64) -> Result<u64, Error> {
        let id = self.socket(socket, Rights::READ)?;
        let (listener, port) = sockets::listener(id)?;
        self.wait_for(sockets::waits(), timeout_ns, sockets::next_look, move |p| {
            let Some(accepted) = sockets::accept(listener, port)? else {
                return Ok(None);
            };
            match p.table.insert(accepted, ObjectType::Socket, Rights::ALL) {
                Ok(h) => Ok(Some(u64::from(h.raw()))),
                Err(e) => {
                    // Nothing names it, so nothing could ever close it.
                    objects::retire(accepted);
                    Err(handle_error(e))
                }
            }
        })
    }

    fn socket_send(
        &mut self,
        socket: AbiHandle,
        bytes: UserPtr,
        len: usize,
        timeout_ns: u64,
    ) -> Result<u64, Error> {
        let conn = self.connection(socket, Rights::WRITE)?;
        let len = len.min(sockets::CHUNK);
        let mut buf = [0u8; sockets::CHUNK];
        // SAFETY: as `channel_write`: the process's space is loaded, and the copy checks the
        // range and faults pages in.
        unsafe { Cpu::copy_from_user(&mut buf[..len], user(bytes)) }.map_err(|_| Error::Fault)?;
        self.wait_for(sockets::waits(), timeout_ns, sockets::next_look, move |_| {
            sockets::send(conn, &buf[..len])
        })
    }

    fn socket_recv(
        &mut self,
        socket: AbiHandle,
        buf: UserPtr,
        cap: usize,
        timeout_ns: u64,
    ) -> Result<u64, Error> {
        let conn = self.connection(socket, Rights::READ)?;
        let cap = cap.min(sockets::CHUNK);
        if cap == 0 {
            return Ok(0);
        }
        // Written before anything is received, so its pages are present: bytes taken from the
        // connection and then refused their copy would be lost, as `channel_recv` says.
        // SAFETY: as `channel_recv`.
        unsafe { Cpu::copy_to_user(user(buf), &[0u8; sockets::CHUNK][..cap]) }
            .map_err(|_| Error::Fault)?;
        self.wait_for(sockets::waits(), timeout_ns, sockets::next_look, move |_| {
            let mut bytes = [0u8; sockets::CHUNK];
            let Some(n) = sockets::recv(conn, &mut bytes[..cap])? else {
                return Ok(None);
            };
            // SAFETY: as `channel_recv`; the range was written above.
            unsafe { Cpu::copy_to_user(user(buf), &bytes[..n]) }.map_err(|_| Error::Fault)?;
            Ok(Some(n as u64))
        })
    }

    fn socket_shutdown(&mut self, socket: AbiHandle, timeout_ns: u64) -> Result<u64, Error> {
        let conn = self.connection(socket, Rights::WRITE)?;
        sockets::shutdown(conn)?;
        self.wait_for(sockets::waits(), timeout_ns, sockets::next_look, move |_| {
            sockets::shut(conn)
        })
    }
}

impl Syscalls {
    /// The socket `socket` names, checked for `rights`.
    fn socket(&mut self, socket: AbiHandle, rights: Rights) -> Result<ObjectId, Error> {
        Ok(self
            .p()
            .table
            .get_checked(handle(socket), ObjectType::Socket, rights)
            .map_err(handle_error)?
            .object)
    }

    /// The connection of the connected socket `socket` names, checked for `rights`.
    fn connection(&mut self, socket: AbiHandle, rights: Rights) -> Result<net::Conn, Error> {
        let id = self.socket(socket, rights)?;
        sockets::connection(id)
    }
}

impl Syscalls {
    /// The caller's process, taking its lock again if the call let go of it.
    fn p(&mut self) -> &mut Process {
        let slot = self.slot;
        self.held
            .get_or_insert_with(|| lock(slot).expect("a process outlives its threads"))
            .process()
    }

    /// Let go of the caller's process. [`Syscalls::p`] takes it again.
    fn unlock(&mut self) {
        self.held = None;
    }

    /// Give the caller a handle with every right to the new object `id`, or retire it.
    fn insert_new(&mut self, id: ObjectId, kind: ObjectType) -> Result<u64, Error> {
        match self.p().table.insert(id, kind, Rights::ALL) {
            Ok(h) => Ok(u64::from(h.raw())),
            Err(e) => {
                // Nothing names it, so nothing could ever close it.
                objects::retire(id);
                Err(handle_error(e))
            }
        }
    }

    /// End the calling thread if its process is ending. See the module documentation.
    fn end_if_exiting(&mut self) {
        if !EXITING[self.slot].load(Ordering::Acquire) {
            return;
        }
        let slot = self.slot;
        let last = leave(slot);
        let exit = self.p().exit;
        self.unlock();
        finish_thread(slot, last, exit)
    }

    /// Run `f` on the caller's process and the process in `slot`, a different one, holding
    /// both locks.
    ///
    /// Two locks are taken in slot order, whoever asks first: a caller in a higher slot that
    /// finds the other lock taken lets go of its own and tries again, so two processes acting
    /// on each other at once cannot each hold one lock and wait for the other.
    fn with_other<R>(
        &mut self,
        slot: usize,
        f: impl FnOnce(&mut Process, &mut Process) -> R,
    ) -> Result<R, Error> {
        if slot == self.slot {
            return Err(Error::InvalidArgument);
        }
        loop {
            let _ = self.p();
            match try_lock(slot) {
                Attempt::Held(mut other) => {
                    let mine: *mut Process = self.p();
                    // SAFETY: two different slots, both locked by this CPU, so these are
                    // borrows of two different processes, and each is unique; see `PROCS`.
                    return Ok(f(unsafe { &mut *mine }, other.process()));
                }
                Attempt::Empty => return Err(Error::BadHandle),
                Attempt::Busy => {
                    if self.slot > slot {
                        self.unlock();
                    }
                    mp::answer_shootdowns();
                    core::hint::spin_loop();
                }
            }
        }
    }

    /// Wait on `queue` until `attempt` produces a result, up to `timeout_ns`, as the ABI
    /// defines a timeout; see `lib/abi/src/table.rs`.
    ///
    /// `attempt` runs with the process's lock held and the process's space loaded. It must
    /// not fault: whatever it copies to the program was written once already, before the wait.
    /// `next_deadline` names an instant, in kernel-clock nanoseconds, at which the wait must
    /// look again even if nothing wakes it — a timer on the queue falling due.
    fn wait_for<R>(
        &mut self,
        queue: &'static WaitQueue,
        timeout_ns: u64,
        mut next_deadline: impl FnMut() -> Option<u64>,
        mut attempt: impl FnMut(&mut Process) -> Result<Option<R>, Error>,
    ) -> Result<R, Error> {
        if let Some(r) = attempt(self.p())? {
            return Ok(r);
        }
        if timeout_ns == 0 {
            return Err(Error::ShouldWait);
        }
        let until = wait::deadline_after(timeout_ns);
        let slot = self.slot;
        // Never blocked holding the process: its other threads need it, and so does the
        // thread that ends it.
        self.unlock();
        loop {
            let soonest = match (until, next_deadline().map(Instant::from_nanos)) {
                (Some(until), Some(due)) => Some(until.min(due)),
                (until, due) => until.or(due),
            };
            let got = queue.wait_once(soonest, || {
                if EXITING[slot].load(Ordering::Acquire) {
                    return Some(Err(Error::PeerClosed));
                }
                let Some(mut held) = lock(slot) else {
                    return Some(Err(Error::BadHandle));
                };
                attempt(held.process()).transpose()
            });
            if let Some(result) = got {
                return result;
            }
            if !preempt::scheduled() || until.is_some_and(|u| timekeeping::now() >= u) {
                return Err(Error::TimedOut);
            }
        }
    }

    /// The process slot `process` names: live, and writable by the caller.
    fn target_slot(&mut self, process: AbiHandle) -> Result<usize, Error> {
        objects::with_handle(
            &self.p().table,
            handle(process),
            ObjectType::Process,
            Rights::WRITE,
            |o| match o {
                Object::Process { slot, exited, .. } if !*exited => Some(*slot),
                _ => None,
            },
        )
        .map_err(store_error)?
        .ok_or(Error::InvalidArgument)
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
    // A last line of defence, not the check: `model::kernel_space` fails the boot on these
    // same tables before any process exists, and with device windows mapped above the user
    // half nothing the kernel maps can land here. Kept because the cost of it being wrong
    // is every process sharing pages.
    if !user_half_clear(direct, <Cpu as HasPageTables>::root()) {
        c.write_str(
            "REFUSED: the kernel maps something in the user half, which every process would share",
        );
        return Check::Failed;
    }
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

    // Before any process runs: a channel is made of store objects, and `main` makes one.
    objects::init();
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
                interrupted: on_user_interrupt,
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
        drive(program.entry as usize, mode, arg1, user_stack_pointer())
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

/// Whether the kernel's own tables leave the user half empty.
///
/// A process root mirrors every top-level entry of the kernel's, and fills its user half in
/// on top of the zero it expects there. If the kernel maps anything in that half — a device
/// window firmware placed there, as happened while windows were mapped at their physical
/// address, before the device window — the
/// entry is not zero: every process then builds its pages into one shared table, and two
/// processes see each other's memory. That is refused, rather than a process built on it.
pub(crate) fn user_half_clear(direct: DirectMap, kernel_root: PhysAddr) -> bool {
    // SAFETY: the live kernel root, reachable through `direct`; this only reads its entries.
    let kernel = unsafe { AddressSpace::<Cpu>::from_root(kernel_root, direct) };
    matches!(
        kernel.top_level_mapped(<Cpu as HasUserMode>::USER_START, <Cpu as HasUserMode>::USER_END,),
        Ok(false)
    )
}

/// Build an empty process in `slot`: its own address space with the kernel half mirrored,
/// `program`'s segments and a stack reserved, and its handle table. Returns its root.
///
/// The process is not loaded and nothing runs in it yet; the caller loads the space (or
/// binds a thread to it) and fills the segments in with [`install_program`].
///
/// `program` must be native ([`personality_of`]): everything that builds a process this way
/// enters it by the native convention. [`run_linux`] builds a Linux one.
pub(crate) fn build(slot: usize, program: &Program) -> Option<PhysAddr> {
    build_as(slot, program, Personality::Native)
}

/// [`build`], for a program that must be tagged `personality`. `None` if it is not.
fn build_as(slot: usize, program: &Program, personality: Personality) -> Option<PhysAddr> {
    if personality_of(program) != Some(personality) {
        return None;
    }
    if slot >= MAX_PROCS || USED[slot].swap(true, Ordering::AcqRel) {
        return None;
    }
    let built = build_claimed(slot, program, personality);
    if built.is_none() {
        USED[slot].store(false, Ordering::Release);
    }
    built
}

/// [`build_as`], in a slot it has claimed.
fn build_claimed(slot: usize, program: &Program, personality: Personality) -> Option<PhysAddr> {
    if self::slot(slot).is_some() {
        return None;
    }
    let direct = direct();
    let kernel_root = kernel_root();
    if !user_half_clear(direct, kernel_root) {
        return None;
    }
    let mut space = with_frames(|f| AddressSpace::<Cpu>::new(direct, f).ok())??;
    // SAFETY: `kernel_root` is the live kernel root, reachable through `direct`, and its
    // tables outlive this process.
    unsafe { space.mirror_top_level(kernel_root).ok()? };
    let mut vm = Vm::new(space, shares_for(slot, personality));

    // Every segment as a writable region, filled once the space is loaded, then tightened.
    for seg in program.segments() {
        let seg = seg.ok()?;
        if seg.mem_size == 0 {
            continue;
        }
        let (lo, hi) = seg.pages(Cpu::PAGE_SIZE as u64);
        vm.reserve(anon(lo as usize, (hi - lo) as usize)).ok()?;
    }
    let stack_top = user_stack_top();
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
            image: None,
            console: ObjectId::from_raw(0),
            exit: None,
            root,
            slot,
            started: false,
            stacks: 0,
            personality,
            syscalls: table_for(personality),
        });
    }
    LIVE[slot].store(0, Ordering::Release);
    EXITING[slot].store(false, Ordering::Release);
    INSTALLED[slot].store(false, Ordering::Release);
    ROOTS[slot].store(root.raw(), Ordering::Release);
    Some(root)
}

/// The top of a process's stack region: one past the highest byte its stack may use, with an
/// unmapped page above.
pub(crate) fn user_stack_top() -> usize {
    <Cpu as HasUserMode>::USER_END - Cpu::PAGE_SIZE
}

/// The user stack pointer a native process starts on: the top of its stack region, with
/// room for the ABI's alignment and the initial frame.
pub(crate) fn user_stack_pointer() -> usize {
    user_stack_top() - 16
}

/// Pages of stack each thread after a process's first is given.
const THREAD_STACK_PAGES: usize = 4;
/// Threads after the first a process may start in its life. Each one's stack is reserved
/// when it starts and stays until the process is torn down, so this bounds threads started,
/// not threads at once.
const MAX_EXTRA_THREADS: usize = 3;

/// The top of the `k`th extra thread's stack: below the first thread's, each with a page of
/// unmapped space beneath it so an overflow faults rather than running into the next.
fn thread_stack_top(k: usize) -> usize {
    let first_bottom =
        <Cpu as HasUserMode>::USER_END - Cpu::PAGE_SIZE - USER_STACK_PAGES * Cpu::PAGE_SIZE;
    first_bottom - Cpu::PAGE_SIZE - k * (THREAD_STACK_PAGES + 1) * Cpu::PAGE_SIZE
}

/// Work out how a new thread of `p` starts, reserving its stack if it is not the first: at
/// `entry`, or the program's entry point for zero, with `args` in its argument registers.
fn prepare_thread(
    p: &mut Process,
    entry: u64,
    args: [usize; 4],
) -> Result<crate::spawn::Start, Error> {
    let user = <Cpu as HasUserMode>::USER_START as u64..<Cpu as HasUserMode>::USER_END as u64;
    let entry = if entry == 0 {
        p.image.and_then(parse).ok_or(Error::InvalidArgument)?.entry
    } else if user.contains(&entry) {
        entry
    } else {
        return Err(Error::InvalidArgument);
    };
    let (user_sp, install) = if !p.started {
        (user_stack_pointer(), true)
    } else {
        if p.stacks >= MAX_EXTRA_THREADS {
            return Err(Error::Full);
        }
        let top = thread_stack_top(p.stacks);
        let len = THREAD_STACK_PAGES * Cpu::PAGE_SIZE;
        p.vm.reserve(anon(top - len, len))
            .map_err(|_| Error::NoMemory)?;
        p.stacks += 1;
        (top - 16, false)
    };
    p.started = true;
    Ok(crate::spawn::Start {
        slot: p.slot,
        root: p.root,
        entry: entry as usize,
        user_sp,
        install,
        args,
    })
}

/// Start a thread in process `slot` from the kernel, as `thread_create` would: at `entry`
/// (zero for the program's entry point), with `args`. The first thread of a process installs
/// its program; see [`crate::spawn`].
pub(crate) fn start(slot: usize, entry: u64, args: [usize; 4]) -> Option<ThreadId> {
    let start = {
        let mut held = lock(slot)?;
        prepare_thread(held.process(), entry, args).ok()?
    };
    crate::spawn::start_thread(start)
}

/// Bind a new thread of process `slot` to its kernel stack and address space, and count
/// it. What `preempt::spawn_prepared`'s preparation does for a thread [`crate::spawn`] starts.
pub(crate) fn bind(
    slot: usize,
    ctx: &mut <Cpu as hal::HasContextSwitch>::Context,
    top: KernAddr,
    root: PhysAddr,
) {
    if let Some(live) = LIVE.get(slot) {
        live.fetch_add(1, Ordering::AcqRel);
    }
    <Cpu as HasUserMode>::bind(ctx, top, root);
}

/// Threads of process `slot` that have not ended.
pub(crate) fn threads_live(slot: usize) -> usize {
    LIVE.get(slot).map_or(0, |l| l.load(Ordering::Acquire))
}

/// Whether process `slot`'s first thread has installed its program.
pub(crate) fn installed(slot: usize) -> bool {
    INSTALLED
        .get(slot)
        .is_some_and(|i| i.load(Ordering::Acquire))
}

/// Install process `slot`'s program from its image, on the process's first thread.
pub(crate) fn install_image(slot: usize) -> Option<()> {
    let image = lock(slot)?.process().image?;
    install_program(&parse(image)?)
}

/// End the running thread of process `slot` before it reached user mode, ending the process
/// with `code`. Never returns.
pub(crate) fn abandon(slot: usize, code: u64) -> ! {
    let (last, exit) = match lock(slot) {
        Some(mut held) => {
            let p = held.process();
            record_exit(p, code);
            (leave(slot), p.exit)
        }
        None => (leave(slot), Some(code)),
    };
    finish_thread(slot, last, exit)
}

/// Give process `slot` a handle with every right to itself, so a program can start threads
/// in its own process. Before any thread of it runs.
pub(crate) fn process_handle(slot: usize) -> Option<Handle> {
    let id = objects::create(Object::Process {
        slot,
        exited: false,
        code: 0,
        waiter: None,
    })?;
    match self::slot(slot).and_then(|p| p.grant(id, ObjectType::Process, Rights::ALL)) {
        Some(h) => Some(h),
        None => {
            objects::retire(id);
            None
        }
    }
}

/// Make a channel with both endpoints in process `slot`'s table. Before any thread of it
/// runs.
pub(crate) fn channel_pair(slot: usize) -> Option<(Handle, Handle)> {
    let p = self::slot(slot)?;
    install_pair(&mut p.table, objects::new_channel()?).ok()
}

/// The object handle `h` names in process `slot`'s table. Before any thread of it runs, or
/// after the last has ended.
pub(crate) fn endpoint_object(slot: usize, h: Handle) -> Option<ObjectId> {
    self::slot(slot)?
        .table
        .get(h)
        .ok()
        .map(|entry| entry.object)
}

/// One end of a channel the kernel holds itself, for a service a program talks to: the
/// other end is in the program's table, and this one in a small table of the kernel's own.
/// `crate::fileserver` holds one per connection.
pub(crate) struct KernelEnd {
    table: HandleTable<2>,
    handle: Handle,
    object: ObjectId,
}

/// Make a channel between process `slot` and the kernel. Returns the program's handle and
/// the kernel's end. Before any thread of the process runs. The kernel's end closes when it
/// is dropped, the program's when its handle is closed or the process torn down, and the
/// channel is freed once both have.
pub(crate) fn kernel_channel(slot: usize) -> Option<(Handle, KernelEnd)> {
    let p = self::slot(slot)?;
    let [theirs, ours] = objects::new_channel()?;
    let mut table = HandleTable::new();
    let Ok(handle) = table.insert(ours.object, ours.kind, ours.rights) else {
        objects::release(theirs);
        objects::release(ours);
        return None;
    };
    // From here the kernel's end closes itself if the program's cannot be installed.
    let end = KernelEnd {
        table,
        handle,
        object: ours.object,
    };
    match p.table.insert(theirs.object, theirs.kind, theirs.rights) {
        Ok(given) => Some((given, end)),
        Err(_) => {
            objects::release(theirs);
            None
        }
    }
}

impl Drop for KernelEnd {
    /// Close the kernel's end, so the program's sees `PeerClosed`.
    fn drop(&mut self) {
        if let Some(chan) = channel_of(self.object) {
            let _ = objects::close_endpoint(&chan, &mut self.table, self.handle);
        }
    }
}

impl KernelEnd {
    /// Receive one message into `buf` if one is queued: `ShouldWait` if none is, `PeerClosed`
    /// once the program's end has closed and everything it sent has been received.
    pub(crate) fn try_recv(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        let ch = channel_of(self.object).ok_or(Error::PeerClosed)?;
        let mut handles = [Handle::from_raw(0); 2];
        ch.receive(&mut self.table, self.handle, buf, &mut handles)
            .map(|got| got.bytes)
            .map_err(channel_error)
    }

    /// Receive one message into `buf`, waiting until `deadline` for it: `TimedOut` if none
    /// came. On a kernel thread. `crate::blockdomain` serves its domain this way.
    #[cfg_attr(not(CONFIG_BLOCK_DOMAIN), allow(dead_code))]
    pub(crate) fn recv(
        &mut self,
        buf: &mut [u8],
        deadline: Option<Instant>,
    ) -> Result<usize, Error> {
        let queue = channel_queue(self.object).ok_or(Error::PeerClosed)?;
        queue
            .wait_until(deadline, || match self.try_recv(buf) {
                Err(Error::ShouldWait) => None,
                got => Some(got),
            })
            .unwrap_or(Err(Error::TimedOut))
    }

    /// Wake `queue` whenever this channel's waiters are woken: for a kernel thread that waits
    /// on several channels in one queue of its own.
    pub(crate) fn relay_to(&self, queue: &'static WaitQueue) {
        if let Some(chan) = channel_of(self.object) {
            chan.relay_to(queue);
        }
    }

    /// Send `bytes` to the program, waking it if it waits.
    pub(crate) fn send(&mut self, bytes: &[u8]) -> Result<(), Error> {
        let ch = channel_of(self.object).ok_or(Error::PeerClosed)?;
        ch.send(&mut self.table, self.handle, bytes, &[])
            .map_err(channel_error)?;
        wake_channel(self.object);
        Ok(())
    }
}

/// Point every process's frame operations at `frames`: the boot allocator for the slice
/// `check` runs, a pool of its own for the scheduled check, which outlives `memory()`.
///
/// # Safety invariant
/// `frames` must outlive every process built while it is installed.
pub(crate) fn set_frames(frames: &mut FrameAllocator<'static, Cpu>) {
    let _guard = FRAME_LOCK.lock_irqsave_with(mp::answer_shootdowns);
    FRAMES.store((frames as *mut FrameAllocator<'static, Cpu>).cast(), Ordering::Relaxed);
}

/// The `init` program, parsed against this port's user half: the one read from a disk if
/// the filesystem check loaded one, and the copy embedded in the image otherwise.
pub(crate) fn program() -> Option<Program<'static>> {
    parse(program_bytes())
}

/// A program read from a disk, which [`program`] prefers to the embedded one. Its length
/// is stored before its pointer, so a reader that sees the pointer sees the length too.
static DISK_PROGRAM: AtomicPtr<u8> = AtomicPtr::new(core::ptr::null_mut());
static DISK_PROGRAM_LEN: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

/// Make `bytes` the program later processes run. Called once, by the filesystem check,
/// after the program has already run from those bytes and exited as it should — so a
/// program that does not load never replaces one that does.
pub(crate) fn set_disk_program(bytes: &'static [u8]) {
    DISK_PROGRAM_LEN.store(bytes.len(), Ordering::Release);
    DISK_PROGRAM.store(bytes.as_ptr().cast_mut(), Ordering::Release);
}

fn program_bytes() -> &'static [u8] {
    let ptr = DISK_PROGRAM.load(Ordering::Acquire);
    if ptr.is_null() {
        return INIT_ELF;
    }
    let len = DISK_PROGRAM_LEN.load(Ordering::Acquire);
    // SAFETY: `set_disk_program` stored a `'static` slice's length before its pointer, and
    // nothing stores either again.
    unsafe { core::slice::from_raw_parts(ptr, len) }
}

/// Run a program the kernel read from somewhere other than its own image, once, in the
/// mode that exercises every system call, and return its exit code and whether that code is
/// the one a program that saw everything behave returns.
///
/// `None` if the program does not parse, or if [`check`] never installed the user-mode
/// hooks this needs — which it does only once the embedded program has loaded.
pub(crate) fn run_disk_program(
    c: &dyn EarlyConsole,
    frames: &mut FrameAllocator<'static, Cpu>,
    bytes: &'static [u8],
) -> Option<(u64, bool)> {
    if KERNEL_ROOT.load(Ordering::Relaxed) == 0 {
        return None;
    }
    let program = parse(bytes)?;
    set_frames(frames);
    let exit = run(c, &program, kernel_root(), MODE_MAIN, 0);
    FRAMES.store(core::ptr::null_mut(), Ordering::Relaxed);
    exit.map(|code| (code, code == INIT_SUCCESS))
}

/// Run `program` as a Linux process in slot 0, to exit, and return its exit code.
///
/// The way [`run`] runs `init`, but for a program tagged `linux`: build it, install its
/// segments, and let `start` lay out what a Linux program starts with — its descriptors and
/// its start-up stack — returning the stack pointer to enter it on. Every argument register
/// is zero at entry, as Linux leaves them. `None` if the program is not a Linux one, if it
/// never started or never exited, or if [`check`] never installed the user-mode hooks.
#[cfg_attr(
    not(CONFIG_ABI_LINUX),
    expect(dead_code, reason = "used only by the Linux personality's check")
)]
pub(crate) fn run_linux(
    frames: &mut FrameAllocator<'static, Cpu>,
    program: &Program,
    start: impl FnOnce(&mut Process, &Program) -> Option<usize>,
) -> Option<u64> {
    if KERNEL_ROOT.load(Ordering::Relaxed) == 0 {
        return None;
    }
    set_frames(frames);
    let exit = build_as(0, program, Personality::Linux).and_then(|root| {
        // SAFETY: as in `run`: `root` mirrors the kernel half, where the running code and
        // stack live.
        unsafe { Cpu::set_root(root) };
        let stack = install_program(program).and_then(|()| start(current()?, program));
        for arg in &ARG_HANDLES {
            arg.store(0, Ordering::Relaxed);
        }
        let exit = stack.and_then(|sp| drive(program.entry as usize, MODE_MAIN, 0, sp));
        // SAFETY: as in `run`.
        unsafe { Cpu::set_root(kernel_root()) };
        teardown(0);
        exit
    });
    FRAMES.store(core::ptr::null_mut(), Ordering::Relaxed);
    exit
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
    let slot = current_slot()?;
    let mut held = lock(slot)?;
    let p = held.process();
    let protected = with_frames(|f| {
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
    })?;
    drop(held);
    if protected.is_some() {
        INSTALLED[slot].store(true, Ordering::Release);
    }
    protected
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

/// Spawn the user thread and switch to it, to enter `entry` on user stack pointer `stack`;
/// return the exit code the handlers recorded.
fn drive(entry: usize, mode: usize, arg1: usize, stack: usize) -> Option<u64> {
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
    STACK.store(stack, Ordering::Relaxed);
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
    let stack = STACK.load(Ordering::Relaxed);
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
    // First, so nothing matches a root about to be freed.
    ROOTS[slot].store(0, Ordering::Release);
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
    // Objects only this process's table named go with it: a table that is gone can close
    // nothing, and an object nothing can name is a leak the accounting reports. An endpoint
    // goes back through its channel, so the far end sees it close, wherever that end is.
    for entry in p.table.entries() {
        crate::objects::release(entry);
    }
    // What only a Linux process has: its descriptors and its thread pointer.
    if p.personality == Personality::Linux {
        crate::personality::release(slot);
    }
    // SAFETY: see `PROCS`; the threads have exited and been reaped, so nothing else holds
    // this slot.
    unsafe { *PROCS[slot].get() = None };
    LIVE[slot].store(0, Ordering::Release);
    USED[slot].store(false, Ordering::Release);
}

// ---- thread plumbing ------------------------------------------------------------------

use core::sync::atomic::{AtomicU64, AtomicUsize};

/// The user thread's table: boot plus one user thread.
static THREADS: SyncUnsafeCell<core::mem::MaybeUninit<thread::Threads<Cpu, 2>>> =
    SyncUnsafeCell::new(core::mem::MaybeUninit::uninit());
static ENTRY: AtomicUsize = AtomicUsize::new(0);
static MODE: AtomicUsize = AtomicUsize::new(0);
static FAULT_ARG: AtomicUsize = AtomicUsize::new(0);
/// The user stack pointer the thread [`drive`] spawns enters on.
static STACK: AtomicUsize = AtomicUsize::new(0);
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

/// A free process slot, or `None` when as many processes exist as this kernel allows.
fn free_slot() -> Option<usize> {
    // The claim flags, not the slots: another CPU may be building or tearing one down.
    (0..MAX_PROCS).find(|&i| !USED[i].load(Ordering::Acquire))
}

/// The bytes [`program`] parses, for a process built from them to name as its image.
pub(crate) fn program_image() -> &'static [u8] {
    program_bytes()
}

/// Parse `bytes` as a program for this port's user half.
pub(crate) fn parse(bytes: &'static [u8]) -> Option<Program<'static>> {
    Program::parse(
        bytes,
        <Cpu as HasUserMode>::ELF_MACHINE,
        (<Cpu as HasUserMode>::USER_START as u64, <Cpu as HasUserMode>::USER_END as u64),
        Cpu::PAGE_SIZE as u64,
    )
    .ok()
}

/// The embedded `init` program's bytes, for a process built to run it.
pub(crate) fn init_elf() -> &'static [u8] {
    INIT_ELF
}

fn store_error(e: kobject::StoreError) -> Error {
    use kobject::StoreError as S;
    match e {
        S::Handle(h) => handle_error(h),
        S::WrongType { .. } => Error::WrongType,
        S::NotFound | S::Retiring => Error::BadHandle,
        S::Full | S::TooManyRefs | S::Duplicate => Error::Full,
    }
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
        ipc::Error::Endpoint(e) | ipc::Error::Transfer { error: e, .. } => handle_error(e),
        _ => Error::BadHandle,
    }
}

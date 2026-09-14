//! The Linux personality: Linux system calls, answered on KinTane's objects.
//!
//! A process whose program carries no KinTane ABI note is tagged `linux` at load
//! ([`userproc::personality_of`]), and its system call table is [`syscalls`]: Linux's numbers
//! for this architecture and its argument registers, a value or a negated errno in the one
//! return register, and every other register as the program left it. The half of this that
//! needs no process — the tables of names, the errno mapping, the start-up stack, `struct
//! stat` and `struct utsname` — is `kernel/linux`, and host-tested there.
//!
//! # Locks, and waiting
//!
//! A call takes its process's lock only for the pieces that touch the process
//! ([`userproc::with_locked`]): its descriptor table, its mappings. Anything that waits — a
//! pipe with nothing in it, a futex, `wait4`, the filesystem namespace another thread is
//! using — waits on a [`crate::wait`] queue holding nothing, so another thread of the process
//! can make the call that ends the wait. A process that ends wakes every queue here
//! ([`wake_all_waiters`]), and a thread woken into an ending process ends at the call it was
//! in.
//!
//! # Descriptors
//!
//! A Linux process's descriptors are a view, not a second kind of authority. Standard output
//! and standard error are console handles in the process's own handle table: a write through
//! either is checked against its handle exactly as the native `debug_write` is, and closing
//! the descriptor closes the handle. A file opened with `openat` is an open file in the
//! filesystem namespace the process was started with. Standard input reads as end of file:
//! the kernel has no console input to give it. A pipe end names one of a few kernel pipes,
//! whose readers and writers block on the pipe's queue.
//!
//! A socket descriptor names a socket object in the object store, counted across processes as
//! a pipe's ends are; `read` and `write` on one are `recv` and `send`. Linux's socket calls, and
//! what they refuse, are in [`socket`].
//!
//! # Processes and threads
//!
//! `fork`, and `clone` without `CLONE_THREAD`, make a child whose address space shares every
//! page with its parent copy-on-write ([`userproc::fork_linux`]) and whose one thread resumes
//! with the parent's registers and thread pointer. `clone` with `CLONE_THREAD` starts a thread
//! in the same process on the stack the caller gave it. Both use the scheduler's pool of
//! process threads ([`spawn::start_resumed`]). `execve` reads a program whole from the
//! namespace and replaces the calling process's memory with it. `wait4` reports a child once
//! its last thread has gone, and its parent is sent `SIGCHLD`.
//!
//! # Signals
//!
//! Dispositions, masks and delivery are [`signals`]. This file calls into it at the few places
//! signals touch a call: on the way out of every call, which is where a signal is delivered; in
//! the waits of a pipe, a futex and `wait4`, which a signal interrupts; in `clone`, `fork`,
//! `execve` and a thread's exit, which carry or reset signal state; and when a process ends,
//! for its parent's `SIGCHLD`.
//!
//! # What is checked at boot
//!
//! [`check`] reads `/KINTANE/LINUX.ELF` from the test disk — `user/linux-hello`, a static
//! program that knows nothing of KinTane — and runs it unmodified in the boot-time slice,
//! grading it by what it wrote, by its exit code and by the unimplemented call it made. It
//! keeps the program. [`scheduled_check`] runs it again with the scheduler, in the mode that
//! uses pipes, `fork`, `execve`, `wait4`, a thread and a futex, and requires that a pipe read
//! and a futex wait really blocked, and then in the mode that exercises signals
//! ([`signals::check`]). [`sockets_check`] runs it as a TCP client of kbuild's service and as
//! a server kbuild connects to. The stress run starts two of it at once on one CPU, each
//! checking its own thread pointer across a hundred yields ([`stress_cycle`]).

#![allow(unsafe_code)]

use core::cell::SyncUnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicU32, AtomicU64, AtomicUsize, Ordering};

use arch::Cpu;
use block::testdisk;
use elf::Program;
use hal::user::{SyscallFrame, UserRegisters};
use hal::{Arch, EarlyConsole, HasUserMode, PhysAddr, UserAddr};
use kobject::handle::Handle;
use linux::{Abi, Call, Failure, FileKind};
use mm::phys::FrameAllocator;
use sched::ThreadId;
use sync::SpinLock;
use sync::lockdep::LockClass;
use time::Duration;
use vfs::{Kind, Vfs};

use crate::userproc::{self, MAX_PROCS, Personality, Process};
use crate::wait::WaitQueue;
use crate::{Check, Live, preempt, spawn, timekeeping, write_hex, write_usize};

mod signals;
mod socket;

/// This kernel has the Linux personality, so [`userproc::personality_of`] tags programs
/// with no KinTane note `linux` rather than refusing them.
pub(crate) const ENABLED: bool = true;

/// Whether an unimplemented call kills the process (LINUX_ENOSYS_FATAL) rather than failing
/// with `ENOSYS`.
const ENOSYS_FATAL: bool = kconfig::LINUX_ENOSYS_FATAL;

/// The Linux ABI of this port's programs. A port the personality has no table for does not
/// build with `ABI_LINUX`, which the configuration already forbids.
const ABI: Abi = match Abi::for_machine(<Cpu as HasUserMode>::ELF_MACHINE) {
    Some(abi) => abi,
    None => panic!("ABI_LINUX on a port with no Linux system call table"),
};

/// Descriptors a process can hold at once.
const MAX_FDS: usize = 16;
/// The most one `read` or `write` moves. Linux allows a short count; a program loops.
const MAX_IO: usize = 4096;
/// The longest path `openat` or `execve` reads, NUL included.
const PATH_MAX: usize = 128;
/// The break's reservation, in pages: `brk` moves within it and never past it.
const BRK_PAGES: usize = 64;

/// A descriptor: what one Linux file descriptor number names.
#[derive(Clone, Copy)]
enum Descriptor {
    Closed,
    /// Standard input: nothing feeds it, so it reads as end of file.
    Stdin,
    /// The console, through a handle in the process's own table.
    Console(Handle),
    /// An open file in the namespace, with what `fstat` reports of it that the namespace does
    /// not, and what it was opened for.
    File {
        fd: vfs::Fd,
        kind: FileKind,
        ino: u64,
        readable: bool,
        writable: bool,
    },
    /// The read end of pipe `n`.
    PipeRead(usize),
    /// The write end of pipe `n`.
    PipeWrite(usize),
    /// Socket `n` of [`socket`]'s table.
    Socket(usize),
}

/// What a Linux process has that a native one does not.
#[derive(Clone, Copy)]
struct State {
    fds: [Descriptor; MAX_FDS],
    /// Descriptors closed by `execve`, one bit each.
    cloexec: u32,
    /// Descriptors whose reads and writes never block, one bit each.
    nonblock: u32,
    /// The break: `[brk_base, brk)` is the heap the program asked for, inside the
    /// reservation `[brk_base, brk_end)`.
    brk_base: usize,
    brk: usize,
    brk_end: usize,
}

impl State {
    /// Linux's rule for a new descriptor: the lowest free number.
    fn lowest_free(&self) -> Result<usize, Failure> {
        self.fds
            .iter()
            .position(|d| matches!(d, Descriptor::Closed))
            .ok_or(Failure::TooManyOpen)
    }

    fn place(&mut self, d: Descriptor, flags: u64) -> Result<usize, Failure> {
        let i = self.lowest_free()?;
        self.fds[i] = d;
        let bit = 1u32 << i;
        self.cloexec &= !bit;
        self.nonblock &= !bit;
        if flags & linux::O_CLOEXEC != 0 {
            self.cloexec |= bit;
        }
        if flags & linux::O_NONBLOCK != 0 {
            self.nonblock |= bit;
        }
        Ok(i)
    }
}

/// Each process slot's Linux state.
///
/// SAFETY INVARIANT: a slot is written by [`start`] or [`fork`] before any thread of that
/// process exists, reached from its threads only under the process's lock
/// ([`userproc::with_locked`]), and cleared by [`release`] from teardown once every thread has
/// ended. So each borrow is the only one.
static STATES: [SyncUnsafeCell<Option<State>>; MAX_PROCS] =
    [const { SyncUnsafeCell::new(None) }; MAX_PROCS];

/// Run `f` on process `slot` and its Linux state, under the process's lock.
fn locked<R>(
    slot: usize,
    f: impl FnOnce(&mut Process, &mut State) -> Result<R, Failure>,
) -> Result<R, Failure> {
    userproc::with_locked(slot, |p| {
        let cell = STATES.get(p.slot).ok_or(Failure::BadDescriptor)?;
        // SAFETY: see `STATES`; the lock is held.
        let s = unsafe { (*cell.get()).as_mut() }.ok_or(Failure::BadDescriptor)?;
        f(p, s)
    })
    .unwrap_or(Err(Failure::BadDescriptor))
}

// ---- the namespace ----------------------------------------------------------------------

/// The namespace Linux processes open files in.
type Namespace = Vfs<'static, 1, 4>;

/// The namespace, while a check runs Linux processes in it; null otherwise.
///
/// SAFETY INVARIANT: set by a check to a namespace it owns and cleared before that namespace
/// is dropped, with no Linux process of the check still running. Used only through
/// [`with_ns`], which one thread holds at a time.
static NS: AtomicPtr<Namespace> = AtomicPtr::new(core::ptr::null_mut());
/// Held by the thread using the namespace. A file read may wait for the disk, so this is a
/// claim a thread waits for on [`NS_WAIT`], not a spin lock.
static NS_BUSY: AtomicBool = AtomicBool::new(false);
static NS_WAIT: WaitQueue = WaitQueue::new();

/// Run `f` on the namespace, waiting for any other thread using it.
fn with_ns<R>(f: impl FnOnce(&mut Namespace) -> Result<R, Failure>) -> Result<R, Failure> {
    NS_WAIT
        .wait_until(None, || {
            NS_BUSY
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
                .then_some(())
        })
        .map_err(|_| Failure::Io)?;
    let ptr = NS.load(Ordering::Relaxed);
    // SAFETY: see `NS`; the claim is held.
    let result = unsafe { ptr.as_mut() }.ok_or(Failure::Io).and_then(f);
    NS_BUSY.store(false, Ordering::Release);
    NS_WAIT.wake_all();
    result
}

// ---- the table ------------------------------------------------------------------------

/// The Linux system call table: what a process tagged `linux` calls through.
pub(crate) fn syscalls(slot: usize, frame: &mut <Cpu as HasUserMode>::SyscallFrame) {
    // A thread whose process another thread has ended ends at its next call...
    userproc::end_if_exiting(slot);
    // What the call was made with: a call a signal interrupts runs again from these.
    let entry = Cpu::registers(frame).to_words();
    let number = frame.number();
    let result = match linux::decode(ABI, number) {
        Some(call) => dispatch(slot, frame, call),
        None => unimplemented(slot, number),
    };
    // ...or on its way out of the one it was in, which the ending woke.
    userproc::end_if_exiting(slot);
    if result == Err(Failure::BrokenPipe) {
        signals::raise_self(slot, linux::signal::SIGPIPE);
    }
    frame.set_return(linux::ret(result));
    // The way out of a call is where a signal is delivered: the one place the kernel returns
    // to a Linux thread with its registers at hand.
    signals::deliver(slot, frame, &entry, result);
}

fn dispatch(
    slot: usize,
    frame: &mut <Cpu as HasUserMode>::SyscallFrame,
    call: Call,
) -> Result<u64, Failure> {
    let a = frame.args();
    let [a0, a1, a2, a3, a4, a5] = a;
    match call {
        Call::Read => read(slot, a0, a1, a2),
        Call::Write => write(slot, a0, a1, a2),
        Call::Close => close(slot, a0),
        Call::Fstat => fstat(slot, a0, a1),
        Call::Mmap => mmap(slot, a1, a2, a3),
        Call::Munmap => munmap(slot, a0, a1),
        Call::Brk => brk(slot, a0),
        Call::Pipe => pipe(slot, a0, 0),
        Call::Pipe2 => pipe(slot, a0, a1),
        Call::SchedYield => {
            if preempt::scheduled() {
                preempt::yield_now();
            }
            Ok(0)
        }
        Call::Getpid => Ok(pid(slot)),
        Call::Gettid => Ok(tid(slot)),
        Call::SetTidAddress => set_tid_address(slot, a0),
        Call::Clone => clone(slot, frame, ABI.clone_args(a)),
        Call::Fork => fork(slot, frame),
        Call::Execve => execve(slot, frame, a0, a1, a2),
        Call::Exit => exit_thread(slot, a0),
        Call::ExitGroup => exit_group(slot, a0 & 0xff),
        Call::Wait4 => wait4(slot, a0, a1, a2),
        Call::Uname => uname(a0),
        Call::ArchPrctl => arch_prctl(a0, a1),
        Call::Futex => futex(slot, a0, a1, a2, a3),
        Call::Openat => openat(slot, a0, a1, a2),
        Call::RtSigaction => signals::sigaction(slot, a0, a1, a2, a3),
        Call::RtSigprocmask => signals::procmask(slot, a0, a1, a2, a3),
        Call::RtSigreturn => signals::sigreturn(slot, frame),
        Call::RtSigpending => signals::pending(slot, a0, a1),
        Call::Sigaltstack => signals::altstack(a0, a1),
        Call::Kill => signals::kill(slot, a0, a1),
        Call::Tgkill => signals::tgkill(slot, a0, a1, a2),
        Call::Socket => socket::socket(slot, a0, a1, a2),
        Call::Connect => socket::connect(slot, a0, a1, a2),
        Call::Accept => socket::accept4(slot, a0, a1, a2, 0),
        Call::Accept4 => socket::accept4(slot, a0, a1, a2, a3),
        Call::Bind => socket::bind(slot, a0, a1, a2),
        Call::Listen => socket::listen(slot, a0, a1),
        Call::Sendto => socket::sendto(slot, a0, a1, a2, a3),
        Call::Recvfrom => socket::recvfrom(slot, a0, a1, a2, a3, a5),
        Call::Shutdown => socket::shutdown(slot, a0, a1),
        Call::Getsockname => socket::name(slot, a0, a1, a2, false),
        Call::Getpeername => socket::name(slot, a0, a1, a2, true),
        Call::Setsockopt => socket::setsockopt(slot, a0, a1, a2, a3, a4),
        Call::Getsockopt => socket::getsockopt(slot, a0, a1, a2, a3, a4),
        Call::Open => openat(slot, linux::AT_FDCWD as u64, a0, a1),
        Call::Lseek => lseek(slot, a0, a1, a2),
        Call::Ftruncate => ftruncate(slot, a0, a1),
        Call::Fsync => fsync(slot, a0),
        Call::Unlink => unlinkat(slot, linux::AT_FDCWD as u64, a0, 0),
        Call::Unlinkat => unlinkat(slot, a0, a1, a2),
        Call::Mkdir => mkdirat(slot, linux::AT_FDCWD as u64, a0),
        Call::Mkdirat => mkdirat(slot, a0, a1),
        Call::Rename => renameat(slot, linux::AT_FDCWD as u64, a0, linux::AT_FDCWD as u64, a1),
        Call::Renameat => renameat(slot, a0, a1, a2, a3),
    }
}

/// Log a call the personality does not implement, by the name Linux gives it, and fail it
/// with `ENOSYS` — or end the process, under LINUX_ENOSYS_FATAL.
fn unimplemented(slot: usize, number: u64) -> Result<u64, Failure> {
    let e = &arch::EARLY;
    e.write_str("linux: ");
    e.write_str(linux::name(ABI.table(), number).unwrap_or("an unknown call"));
    e.write_str(" (");
    write_usize(e, number as usize);
    e.write_str(") is not implemented");
    UNIMPLEMENTED.store(number.wrapping_add(1), Ordering::Relaxed);
    if ENOSYS_FATAL {
        e.write_str(", and LINUX_ENOSYS_FATAL ends the process\n");
        exit_group(slot, userproc::KILLED)
    }
    e.write_str("\n");
    Err(Failure::NotImplemented)
}

/// The exit code a process a trap ends is recorded with: a Linux process by the signal the
/// trap raised, which is `SIGSEGV` unless a fault said otherwise and nothing handled it; a
/// native process as killed.
pub(crate) fn killed_by(slot: usize, personality: Personality) -> u64 {
    match personality {
        Personality::Linux => signals::fault_exit_code(slot)
            .unwrap_or(linux::signal::exit_code(linux::signal::SIGSEGV)),
        Personality::Native => userproc::KILLED,
    }
}

/// Deliver a signal to the thread of `slot` an interrupt took out of user mode, with the
/// registers it was taken with. `true` when `regs` is now a handler's and the port must return
/// to it. This is what runs a handler for a thread that makes no system call at all.
///
/// On the way back to user code, so the interrupted context was the program's: it cannot have
/// held any lock this takes.
pub(crate) fn deliver_on_interrupt(
    slot: usize,
    regs: &mut [u64; hal::user::REGISTER_WORDS],
) -> bool {
    signals::deliver_interrupted(slot, regs)
}

/// Hand `trap` to the process of `slot` as the signal it raises: `true` when it has a handler
/// and `regs` is now that handler's, `false` when the port must end the thread as before.
///
/// The signal a trap raises is the port's own vector or exception class read through this
/// build's ABI, and `si_addr` is the address that faulted for a page fault, or the instruction
/// for everything else, as Linux reports them.
pub(crate) fn trap_signal(
    slot: usize,
    trap: hal::user::UserTrap,
    regs: &mut [u64; hal::user::REGISTER_WORDS],
) -> bool {
    use linux::signal::{SIGBUS, SIGFPE, SIGILL, SIGSEGV};
    let (signo, addr) = match trap {
        // A page the process may not touch, or one no mapping covers. Linux tells the two
        // apart with `si_code`; this kernel does not, and reports the address either way.
        hal::user::UserTrap::Page { fault, .. } => (SIGSEGV, fault.addr as u64),
        hal::user::UserTrap::BadReturn { pc } => (SIGSEGV, pc as u64),
        hal::user::UserTrap::Exception { code, pc } => {
            let signo = match ABI {
                // x86_64 vectors: #DE, #UD, #GP and #AC are the ones a program raises.
                linux::Abi::X86_64 => match code {
                    0 => SIGFPE,
                    6 => SIGILL,
                    17 => SIGBUS,
                    _ => SIGSEGV,
                },
                // aarch64 exception classes: an unknown reason is an undefined instruction,
                // 0x18 a system register it may not touch, 0x2c a floating-point exception,
                // and 0x0e an illegal execution state.
                linux::Abi::Aarch64 => match code {
                    0x00 | 0x0e | 0x18 => SIGILL,
                    0x2c => SIGFPE,
                    0x22 => SIGBUS,
                    _ => SIGSEGV,
                },
            };
            (signo, pc as u64)
        }
    };
    signals::on_fault(slot, signo, addr, regs)
}

fn pid(slot: usize) -> u64 {
    // Linux's pid 0 is no process; slots count from it.
    slot as u64 + 1
}

/// The descriptor `fd` names, or `EBADF`.
fn descriptor(s: &State, fd: u64) -> Result<Descriptor, Failure> {
    let d = usize::try_from(fd)
        .ok()
        .and_then(|i| s.fds.get(i))
        .ok_or(Failure::BadDescriptor)?;
    match d {
        Descriptor::Closed => Err(Failure::BadDescriptor),
        d => Ok(*d),
    }
}

/// The descriptor `fd` names and whether it never blocks.
fn descriptor_of(slot: usize, fd: u64) -> Result<(Descriptor, bool), Failure> {
    locked(slot, |_, s| {
        let d = descriptor(s, fd)?;
        Ok((d, s.nonblock & (1 << fd) != 0))
    })
}

/// The user address `offset` bytes past `base`.
fn user_at(base: u64, offset: usize) -> Result<UserAddr, Failure> {
    usize::try_from(base)
        .ok()
        .and_then(|b| b.checked_add(offset))
        .map(UserAddr::new)
        .ok_or(Failure::Fault)
}

fn to_user(at: u64, bytes: &[u8]) -> Result<(), Failure> {
    // SAFETY: the calling process's space is loaded, as on every system call; `copy_to_user`
    // checks the range and faults its pages in.
    unsafe { Cpu::copy_to_user(user_at(at, 0)?, bytes) }.map_err(|_| Failure::Fault)
}

fn from_user(at: u64, into: &mut [u8]) -> Result<(), Failure> {
    // SAFETY: as in `to_user`.
    unsafe { Cpu::copy_from_user(into, user_at(at, 0)?) }.map_err(|_| Failure::Fault)
}

fn read(slot: usize, fd: u64, buf: u64, count: u64) -> Result<u64, Failure> {
    let (d, nonblock) = descriptor_of(slot, fd)?;
    let count = usize::try_from(count).unwrap_or(MAX_IO).min(MAX_IO);
    match d {
        Descriptor::Stdin => Ok(0),
        Descriptor::File {
            fd, readable: true, ..
        } => read_file(fd, buf, count),
        Descriptor::PipeRead(pipe) => read_pipe(slot, pipe, buf, count, nonblock),
        Descriptor::Socket(i) => socket::recv(slot, i, nonblock, buf, count),
        _ => Err(Failure::BadDescriptor),
    }
}

fn read_file(fd: vfs::Fd, buf: u64, count: usize) -> Result<u64, Failure> {
    with_ns(|ns| {
        let mut chunk = [0u8; 256];
        let mut done = 0;
        while done < count {
            let want = (count - done).min(chunk.len());
            let got = ns.read(fd, &mut chunk[..want]).map_err(failure)?;
            // SAFETY: as in `to_user`.
            unsafe { Cpu::copy_to_user(user_at(buf, done)?, &chunk[..got]) }
                .map_err(|_| Failure::Fault)?;
            done += got;
            if got < want {
                break;
            }
        }
        Ok(done as u64)
    })
}

fn write(slot: usize, fd: u64, buf: u64, count: u64) -> Result<u64, Failure> {
    let (d, nonblock) = descriptor_of(slot, fd)?;
    let count = usize::try_from(count).unwrap_or(MAX_IO).min(MAX_IO);
    match d {
        Descriptor::Console(handle) => write_console(slot, handle, buf, count),
        Descriptor::PipeWrite(pipe) => write_pipe(slot, pipe, buf, count, nonblock),
        Descriptor::Socket(i) => socket::send(slot, i, nonblock, buf, count),
        Descriptor::File {
            fd, writable: true, ..
        } => write_file(fd, buf, count),
        // Standard input is not open for writing, and neither is a file opened to read.
        _ => Err(Failure::BadDescriptor),
    }
}

fn write_console(slot: usize, handle: Handle, buf: u64, count: usize) -> Result<u64, Failure> {
    if !locked(slot, |p, _| Ok(p.may_write_console(handle)))? {
        return Err(Failure::BadDescriptor);
    }
    let mut chunk = [0u8; 256];
    let mut done = 0;
    while done < count {
        let n = (count - done).min(chunk.len());
        // SAFETY: as in `to_user`.
        unsafe { Cpu::copy_from_user(&mut chunk[..n], user_at(buf, done)?) }
            .map_err(|_| Failure::Fault)?;
        arch::EARLY.write_bytes(&chunk[..n]);
        capture(&chunk[..n]);
        done += n;
    }
    Ok(done as u64)
}

fn close(slot: usize, fd: u64) -> Result<u64, Failure> {
    let d = locked(slot, |p, s| {
        let d = descriptor(s, fd)?;
        // `descriptor` accepted `fd`, so it indexes the table.
        s.fds[fd as usize] = Descriptor::Closed;
        if let Descriptor::Console(handle) = d {
            p.close_handle(handle);
        }
        Ok(d)
    })?;
    match d {
        Descriptor::File { fd, .. } => with_ns(|ns| ns.close(fd).map_err(failure))?,
        Descriptor::PipeRead(pipe) => drop_end(pipe, End::Read),
        Descriptor::PipeWrite(pipe) => drop_end(pipe, End::Write),
        Descriptor::Socket(i) => socket::drop_ref(i),
        Descriptor::Console(_) | Descriptor::Stdin | Descriptor::Closed => {}
    }
    Ok(0)
}

fn fstat(slot: usize, fd: u64, out: u64) -> Result<u64, Failure> {
    let (d, _) = descriptor_of(slot, fd)?;
    let (kind, len, ino) = match d {
        // The size now, not at open: the process may have written since.
        Descriptor::File { fd, kind, ino, .. } => {
            (kind, with_ns(|ns| ns.fstat(fd).map_err(failure))?.len, ino)
        }
        Descriptor::PipeRead(pipe) | Descriptor::PipeWrite(pipe) => {
            (FileKind::Fifo, 0, PIPE_INODES + pipe as u64)
        }
        Descriptor::Socket(i) => (FileKind::Socket, 0, SOCKET_INODES + i as u64),
        _ => (FileKind::CharDevice, 0, fd + 1),
    };
    let bytes = linux::stat_bytes(ABI, kind, len, ino);
    to_user(out, &bytes[..ABI.stat_len()])?;
    Ok(0)
}

fn openat(slot: usize, dirfd: u64, path: u64, flags: u64) -> Result<u64, Failure> {
    use linux::{O_ACCMODE, O_APPEND, O_CREAT, O_EXCL, O_RDONLY, O_RDWR, O_TRUNC, O_WRONLY};
    let mut name = [0u8; PATH_MAX + 1];
    let n = absolute_path(slot, dirfd, path, &mut name)?;
    let path = path_str(&name, n)?;
    let (readable, writable) = match flags & O_ACCMODE {
        O_RDONLY => (true, false),
        O_WRONLY => (false, true),
        O_RDWR => (true, true),
        _ => return Err(Failure::InvalidArgument),
    };
    let how = vfs::OpenFlags {
        write: writable,
        create: flags & O_CREAT != 0,
        exclusive: flags & O_CREAT != 0 && flags & O_EXCL != 0,
        truncate: writable && flags & O_TRUNC != 0,
        append: writable && flags & O_APPEND != 0,
    };
    let (fd, stat) = with_ns(|ns| {
        if flags & ABI.o_directory() != 0 && ns.stat(path).map_err(failure)?.kind != Kind::Dir {
            return Err(Failure::NotADirectory);
        }
        let fd = ns.open_with(path, how).map_err(failure)?;
        match ns.fstat(fd) {
            Ok(stat) => Ok((fd, stat)),
            Err(e) => {
                let _ = ns.close(fd);
                Err(failure(e))
            }
        }
    })?;
    let file = Descriptor::File {
        fd,
        kind: match stat.kind {
            Kind::File => FileKind::Regular,
            Kind::Dir => FileKind::Directory,
        },
        ino: inode(path),
        readable,
        writable,
    };
    let placed = locked(slot, |_, s| s.place(file, flags));
    if placed.is_err() {
        let _ = with_ns(|ns| ns.close(fd).map_err(failure));
    }
    placed.map(|i| i as u64)
}

/// Read the NUL-terminated path at user address `path` into `name`, made absolute: the
/// working directory is the root, and a path relative to a descriptor is refused, since no
/// descriptor here is a directory. Returns its length in `name`.
fn absolute_path(
    slot: usize,
    dirfd: u64,
    path: u64,
    name: &mut [u8; PATH_MAX + 1],
) -> Result<usize, Failure> {
    // Read one byte in, so a relative path can be made absolute in place.
    let n = copy_path(path, &mut name[1..])?;
    if n == 0 {
        return Err(Failure::NotFound);
    }
    if name[1] == b'/' {
        name.copy_within(1..=n, 0);
        return Ok(n);
    }
    if dirfd as i64 != linux::AT_FDCWD {
        locked(slot, |_, s| descriptor(s, dirfd))?;
        return Err(Failure::NotADirectory);
    }
    name[0] = b'/';
    Ok(n + 1)
}

/// A path read by [`absolute_path`], as the namespace takes one. A name the volume cannot
/// hold is a name it does not have.
fn path_str(name: &[u8], len: usize) -> Result<&str, Failure> {
    core::str::from_utf8(&name[..len]).map_err(|_| Failure::NotFound)
}

/// The file a descriptor names, or the failure Linux gives a call that needs one.
fn file_of(slot: usize, fd: u64, otherwise: Failure) -> Result<(vfs::Fd, bool), Failure> {
    match descriptor_of(slot, fd)?.0 {
        Descriptor::File { fd, writable, .. } => Ok((fd, writable)),
        _ => Err(otherwise),
    }
}

fn write_file(fd: vfs::Fd, buf: u64, count: usize) -> Result<u64, Failure> {
    with_ns(|ns| {
        let mut chunk = [0u8; 256];
        let mut done = 0;
        while done < count {
            let n = (count - done).min(chunk.len());
            // SAFETY: as in `to_user`.
            unsafe { Cpu::copy_from_user(&mut chunk[..n], user_at(buf, done)?) }
                .map_err(|_| Failure::Fault)?;
            match ns.write(fd, &chunk[..n]) {
                Ok(wrote) => {
                    done += wrote;
                    if wrote < n {
                        break;
                    }
                }
                // What was written stays written, and a short count says so, as Linux does.
                Err(_) if done > 0 => break,
                Err(e) => return Err(failure(e)),
            }
        }
        Ok(done as u64)
    })
}

fn lseek(slot: usize, fd: u64, offset: u64, whence: u64) -> Result<u64, Failure> {
    let (fd, _) = file_of(slot, fd, Failure::IllegalSeek)?;
    let whence = match whence {
        linux::SEEK_SET => vfs::Whence::Start,
        linux::SEEK_CUR => vfs::Whence::Current,
        linux::SEEK_END => vfs::Whence::End,
        _ => return Err(Failure::InvalidArgument),
    };
    with_ns(|ns| {
        ns.seek(fd, whence, offset as i64)
            .map_err(|_| Failure::InvalidArgument)
    })
}

fn ftruncate(slot: usize, fd: u64, len: u64) -> Result<u64, Failure> {
    let (fd, writable) = file_of(slot, fd, Failure::InvalidArgument)?;
    // Linux's answer to a descriptor not open for writing.
    if !writable || (len as i64) < 0 {
        return Err(Failure::InvalidArgument);
    }
    with_ns(|ns| ns.truncate(fd, len).map_err(failure))?;
    Ok(0)
}

fn fsync(slot: usize, fd: u64) -> Result<u64, Failure> {
    let (fd, _) = file_of(slot, fd, Failure::InvalidArgument)?;
    with_ns(|ns| ns.fsync(fd).map_err(failure))?;
    Ok(0)
}

fn unlinkat(slot: usize, dirfd: u64, path: u64, flags: u64) -> Result<u64, Failure> {
    if flags & !linux::AT_REMOVEDIR != 0 {
        return Err(Failure::InvalidArgument);
    }
    let mut name = [0u8; PATH_MAX + 1];
    let n = absolute_path(slot, dirfd, path, &mut name)?;
    let path = path_str(&name, n)?;
    with_ns(|ns| {
        let kind = ns.stat(path).map_err(failure)?.kind;
        match (kind, flags & linux::AT_REMOVEDIR != 0) {
            (Kind::Dir, false) => Err(Failure::IsADirectory),
            (Kind::File, true) => Err(Failure::NotADirectory),
            _ => ns.unlink(path).map_err(failure),
        }
    })?;
    Ok(0)
}

fn mkdirat(slot: usize, dirfd: u64, path: u64) -> Result<u64, Failure> {
    let mut name = [0u8; PATH_MAX + 1];
    let n = absolute_path(slot, dirfd, path, &mut name)?;
    let path = path_str(&name, n)?;
    with_ns(|ns| ns.mkdir(path).map_err(failure))?;
    Ok(0)
}

fn renameat(slot: usize, from_dir: u64, from: u64, to_dir: u64, to: u64) -> Result<u64, Failure> {
    let mut old = [0u8; PATH_MAX + 1];
    let n = absolute_path(slot, from_dir, from, &mut old)?;
    let old = path_str(&old, n)?;
    let mut new = [0u8; PATH_MAX + 1];
    let n = absolute_path(slot, to_dir, to, &mut new)?;
    let new = path_str(&new, n)?;
    // The namespace renames only within a directory. Across two, Linux's answer for a
    // rename the filesystem cannot do is `EXDEV`, which a program handles by copying.
    fn parent(p: &str) -> Option<&str> {
        let p = p.trim_end_matches('/');
        p.rfind('/').map(|cut| &p[..cut])
    }
    match (parent(old), parent(new)) {
        (Some(a), Some(b)) if a.eq_ignore_ascii_case(b) => {}
        _ => return Err(Failure::CrossDevice),
    }
    with_ns(|ns| ns.rename(old, new).map_err(failure))?;
    Ok(0)
}

/// Copy a NUL-terminated string from user address `at` into `into`, a page at a time so a
/// string that ends just before unmapped memory reads. Its length without the NUL.
fn copy_path(at: u64, into: &mut [u8]) -> Result<usize, Failure> {
    let page = Cpu::PAGE_SIZE;
    let mut done = 0;
    while done < into.len() {
        let addr = user_at(at, done)?;
        let n = (page - addr.raw() % page).min(into.len() - done);
        // SAFETY: as in `to_user`.
        unsafe { Cpu::copy_from_user(&mut into[done..done + n], addr) }
            .map_err(|_| Failure::Fault)?;
        if let Some(nul) = into[done..done + n].iter().position(|&b| b == 0) {
            return Ok(done + nul);
        }
        done += n;
    }
    Err(Failure::NameTooLong)
}

/// An inode number for `path`: stable for a path, which is all `st_ino` promises a program
/// that compares two. FNV-1a.
fn inode(path: &str) -> u64 {
    path.bytes()
        .fold(0xcbf2_9ce4_8422_2325, |h, b| (h ^ u64::from(b)).wrapping_mul(0x0100_0000_01b3))
}

/// Anonymous private mappings, anywhere the kernel chooses.
fn mmap(slot: usize, len: u64, prot: u64, flags: u64) -> Result<u64, Failure> {
    use linux::{MAP_ANONYMOUS, MAP_FIXED, MAP_PRIVATE, PROT_EXEC, PROT_READ, PROT_WRITE};
    // A file mapping, a shared one, or one at a fixed address is not what this offers; the
    // address, when not fixed, is a hint Linux may ignore too.
    if flags & MAP_ANONYMOUS == 0 || flags & MAP_PRIVATE == 0 || flags & MAP_FIXED != 0 {
        return Err(Failure::InvalidArgument);
    }
    // W^X: an executable mapping is never granted. PROT_NONE, a reservation, is not offered.
    if prot & PROT_EXEC != 0 {
        return Err(Failure::AccessDenied);
    }
    if prot & (PROT_READ | PROT_WRITE) == 0 {
        return Err(Failure::InvalidArgument);
    }
    let page = Cpu::PAGE_SIZE;
    let bytes = usize::try_from(len)
        .ok()
        .filter(|&l| l != 0)
        .and_then(|l| l.checked_next_multiple_of(page))
        .ok_or(Failure::InvalidArgument)?;
    let mut flags = hal::PageFlags::USER | hal::PageFlags::READ;
    if prot & PROT_WRITE != 0 {
        flags = flags | hal::PageFlags::WRITE;
    }
    locked(slot, |p, _| {
        p.reserve_next(bytes, flags)
            .map(|start| start as u64)
            .map_err(|_| Failure::NoMemory)
    })
}

/// Unmap exactly a mapping `mmap` made; part of one is refused.
fn munmap(slot: usize, addr: u64, len: u64) -> Result<u64, Failure> {
    let page = Cpu::PAGE_SIZE;
    let start = usize::try_from(addr).map_err(|_| Failure::InvalidArgument)?;
    let bytes = usize::try_from(len)
        .ok()
        .and_then(|l| l.checked_next_multiple_of(page))
        .ok_or(Failure::InvalidArgument)?;
    if start % page != 0 || !locked(slot, |p, _| Ok(p.release_exact(start, bytes)))? {
        return Err(Failure::InvalidArgument);
    }
    Ok(0)
}

/// Move the break within its reservation. Linux's convention: the answer is the break as it
/// now is, which is the old one when the request cannot be met.
fn brk(slot: usize, addr: u64) -> Result<u64, Failure> {
    locked(slot, |_, s| {
        if let Ok(want) = usize::try_from(addr)
            && (s.brk_base..=s.brk_end).contains(&want)
        {
            s.brk = want;
        }
        Ok(s.brk as u64)
    })
}

fn uname(out: u64) -> Result<u64, Failure> {
    to_user(out, &linux::utsname(ABI.machine()))?;
    Ok(0)
}

fn arch_prctl(code: u64, addr: u64) -> Result<u64, Failure> {
    if code != linux::ARCH_SET_FS {
        return Err(Failure::InvalidArgument);
    }
    let addr = usize::try_from(addr)
        .ok()
        .filter(|&a| a < <Cpu as HasUserMode>::USER_END)
        .ok_or(Failure::InvalidArgument)?;
    // SAFETY: from the calling thread's own system call, on the CPU it runs on; the value is
    // part of the thread's saved context from here on (`hal::HasUserMode::set_tls`).
    unsafe { Cpu::set_tls(addr) };
    Ok(0)
}

fn failure(e: vfs::Error) -> Failure {
    use vfs::Error as E;
    match e {
        E::NotFound | E::NoSuchMount => Failure::NotFound,
        E::NotADirectory => Failure::NotADirectory,
        E::IsADirectory => Failure::IsADirectory,
        E::BadPath => Failure::NameTooLong,
        E::TooManyOpen => Failure::TooManyOpen,
        E::BadHandle => Failure::BadDescriptor,
        E::OutOfRange => Failure::InvalidArgument,
        E::ReadOnly => Failure::ReadOnly,
        E::Full | E::MountFull => Failure::NoSpace,
        E::Exists => Failure::Exists,
        E::NotEmpty => Failure::NotEmpty,
        E::Corrupt(_) | E::Device(_) => Failure::Io,
    }
}

// ---- pipes ------------------------------------------------------------------------------

/// Pipes that can exist at once, and the bytes each holds.
const PIPES: usize = 4;
const PIPE_BYTES: usize = 512;
/// `st_ino` of pipe 0; the others follow it.
const PIPE_INODES: u64 = 0x7069_7065_0000;
/// `st_ino` of socket 0; the others follow it.
const SOCKET_INODES: u64 = 0x736f_636b_0000;

struct Pipe {
    used: bool,
    buf: [u8; PIPE_BYTES],
    /// Where the oldest byte is, and how many there are.
    head: usize,
    len: usize,
    /// Descriptors naming each end, in every process: a `fork` counts its copies.
    readers: u32,
    writers: u32,
}

impl Pipe {
    const EMPTY: Pipe = Pipe {
        used: false,
        buf: [0; PIPE_BYTES],
        head: 0,
        len: 0,
        readers: 0,
        writers: 0,
    };

    fn take(&mut self, into: &mut [u8]) -> usize {
        let n = self.len.min(into.len());
        for (i, b) in into[..n].iter_mut().enumerate() {
            *b = self.buf[(self.head + i) % PIPE_BYTES];
        }
        self.head = (self.head + n) % PIPE_BYTES;
        self.len -= n;
        n
    }

    fn put(&mut self, from: &[u8]) -> usize {
        let n = (PIPE_BYTES - self.len).min(from.len());
        for (i, &b) in from[..n].iter().enumerate() {
            self.buf[(self.head + self.len + i) % PIPE_BYTES] = b;
        }
        self.len += n;
        n
    }
}

static PIPE_CLASS: LockClass = LockClass::new("linux.pipes");
/// Every pipe. Held only to look at or change one, never while copying to or from a program
/// or waiting, and nothing is taken inside it.
static PIPE_TABLE: SpinLock<[Pipe; PIPES], Cpu> =
    SpinLock::with_class([Pipe::EMPTY; PIPES], &PIPE_CLASS);
/// Each pipe's readers and writers, waiting for bytes or for room. Woken by every change.
static PIPE_WAITS: [WaitQueue; PIPES] = [const { WaitQueue::new() }; PIPES];
/// Reads that found their pipe empty and blocked until a writer woke them.
static PIPE_BLOCKED_READS: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, PartialEq, Eq)]
enum End {
    Read,
    Write,
}

/// Count one more descriptor naming `pipe`'s `end`, for a `fork`'s copy.
fn add_end(pipe: usize, end: End) {
    let mut pipes = PIPE_TABLE.lock_irqsave();
    let p = &mut pipes[pipe];
    match end {
        End::Read => p.readers += 1,
        End::Write => p.writers += 1,
    }
}

/// Count one descriptor naming `pipe`'s `end` gone, freeing the pipe with its last, and wake
/// whoever waits on it: a reader sees end of file once no writer is left, a writer `EPIPE`
/// once no reader is.
fn drop_end(pipe: usize, end: End) {
    {
        let mut pipes = PIPE_TABLE.lock_irqsave();
        let p = &mut pipes[pipe];
        match end {
            End::Read => p.readers = p.readers.saturating_sub(1),
            End::Write => p.writers = p.writers.saturating_sub(1),
        }
        if p.readers == 0 && p.writers == 0 {
            *p = Pipe::EMPTY;
        }
    }
    PIPE_WAITS[pipe].wake_all();
}

fn pipe(slot: usize, out: u64, flags: u64) -> Result<u64, Failure> {
    if flags & !(linux::O_CLOEXEC | linux::O_NONBLOCK) != 0 {
        return Err(Failure::InvalidArgument);
    }
    // Written first, so the answer cannot fault after the descriptors exist.
    to_user(out, &[0u8; 8])?;
    let pipe = {
        let mut pipes = PIPE_TABLE.lock_irqsave();
        let i = pipes
            .iter()
            .position(|p| !p.used)
            .ok_or(Failure::TooManyOpen)?;
        pipes[i] = Pipe {
            used: true,
            readers: 1,
            writers: 1,
            ..Pipe::EMPTY
        };
        i
    };
    let placed = locked(slot, |_, s| {
        let r = s.place(Descriptor::PipeRead(pipe), flags)?;
        match s.place(Descriptor::PipeWrite(pipe), flags) {
            Ok(w) => Ok((r, w)),
            Err(e) => {
                s.fds[r] = Descriptor::Closed;
                Err(e)
            }
        }
    });
    let (r, w) = match placed {
        Ok(ends) => ends,
        Err(e) => {
            drop_end(pipe, End::Read);
            drop_end(pipe, End::Write);
            return Err(e);
        }
    };
    let mut fds = [0u8; 8];
    fds[..4].copy_from_slice(&(r as u32).to_le_bytes());
    fds[4..].copy_from_slice(&(w as u32).to_le_bytes());
    to_user(out, &fds)?;
    Ok(0)
}

fn read_pipe(
    slot: usize,
    pipe: usize,
    buf: u64,
    count: usize,
    nonblock: bool,
) -> Result<u64, Failure> {
    let count = count.min(PIPE_BYTES);
    if count == 0 {
        return Ok(0);
    }
    // Written first, so its pages are present: bytes taken from the pipe and then refused
    // their copy would be lost.
    to_user(buf, &[0u8; PIPE_BYTES][..count])?;
    let mut chunk = [0u8; PIPE_BYTES];
    let mut looks = 0u32;
    let got = PIPE_WAITS[pipe].wait_until(None, || {
        looks += 1;
        if userproc::exiting(slot) {
            return Some(Err(Failure::Io));
        }
        let taken = {
            let mut pipes = PIPE_TABLE.lock_irqsave();
            let p = &mut pipes[pipe];
            if p.len > 0 {
                Some(Ok(p.take(&mut chunk[..count])))
            } else if p.writers == 0 {
                Some(Ok(0))
            } else if nonblock {
                Some(Err(Failure::TryAgain))
            } else {
                None
            }
        };
        // Nothing to read, and a signal to act on: the read ends, outside the pipe's lock.
        taken.or_else(|| signals::interrupting(slot).then_some(Err(Failure::Interrupted)))
    });
    // Before the scheduler runs nothing can write, so a wait that cannot block reports it.
    let n = got.map_err(|_| Failure::TryAgain)?;
    if n == Err(Failure::Interrupted) && looks >= 3 {
        signals::blocked_call_interrupted();
    }
    let n = n?;
    // A first look, a second after registering, and a third after the block: a read that
    // needed three waited for a writer.
    if looks >= 3 && n > 0 {
        PIPE_BLOCKED_READS.fetch_add(1, Ordering::Relaxed);
    }
    // A writer may be waiting for the room this made.
    PIPE_WAITS[pipe].wake_all();
    to_user(buf, &chunk[..n])?;
    Ok(n as u64)
}

fn write_pipe(
    slot: usize,
    pipe: usize,
    buf: u64,
    count: usize,
    nonblock: bool,
) -> Result<u64, Failure> {
    let count = count.min(PIPE_BYTES);
    let mut chunk = [0u8; PIPE_BYTES];
    from_user(buf, &mut chunk[..count])?;
    let mut done = 0;
    while done < count {
        let put = PIPE_WAITS[pipe].wait_until(None, || {
            if userproc::exiting(slot) {
                return Some(Err(Failure::Io));
            }
            let put = {
                let mut pipes = PIPE_TABLE.lock_irqsave();
                let p = &mut pipes[pipe];
                if p.readers == 0 {
                    Some(Err(Failure::BrokenPipe))
                } else if p.len < PIPE_BYTES {
                    Some(Ok(p.put(&chunk[done..count])))
                } else if nonblock {
                    Some(Err(Failure::TryAgain))
                } else {
                    None
                }
            };
            put.or_else(|| signals::interrupting(slot).then_some(Err(Failure::Interrupted)))
        });
        match put {
            Ok(Ok(n)) => done += n,
            // Linux's rule: what was written is the answer, and the error waits for the next
            // call.
            Ok(Err(e)) if done == 0 => return Err(e),
            Err(_) if done == 0 => return Err(Failure::TryAgain),
            Ok(Err(_)) | Err(_) => break,
        }
        PIPE_WAITS[pipe].wake_all();
    }
    Ok(done as u64)
}

// ---- threads ----------------------------------------------------------------------------

/// Threads of Linux processes the personality knows by thread id.
const THREADS: usize = 8;
const NO_THREAD: u32 = u32::MAX;

/// One thread's Linux identity: its tid, and the `clear_child_tid` address it zeroes and
/// wakes when it exits. A thread with no record is its process's first, whose tid is the pid.
struct ThreadRecord {
    thread: AtomicU32,
    slot: AtomicUsize,
    tid: AtomicU64,
    clear_tid: AtomicU64,
}

static RECORDS: [ThreadRecord; THREADS] = [const {
    ThreadRecord {
        thread: AtomicU32::new(NO_THREAD),
        slot: AtomicUsize::new(0),
        tid: AtomicU64::new(0),
        clear_tid: AtomicU64::new(0),
    }
}; THREADS];
/// The next tid a `clone` hands out. Above every pid, so no thread's tid is a process's.
static NEXT_TID: AtomicU64 = AtomicU64::new(MAX_PROCS as u64 + 1);

fn record_of(thread: ThreadId) -> Option<&'static ThreadRecord> {
    RECORDS
        .iter()
        .find(|r| r.thread.load(Ordering::Acquire) == thread.raw())
}

fn new_record(thread: ThreadId, slot: usize, tid: u64) -> Option<&'static ThreadRecord> {
    let r = RECORDS.iter().find(|r| {
        r.thread
            .compare_exchange(NO_THREAD, thread.raw(), Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    })?;
    r.slot.store(slot, Ordering::Release);
    r.tid.store(tid, Ordering::Release);
    r.clear_tid.store(0, Ordering::Release);
    Some(r)
}

/// The calling thread's record, made for it if it is its process's first.
fn my_record(slot: usize) -> Option<&'static ThreadRecord> {
    let me = preempt::current_thread()?;
    record_of(me).or_else(|| new_record(me, slot, pid(slot)))
}

fn tid(slot: usize) -> u64 {
    preempt::current_thread()
        .and_then(record_of)
        .map_or(pid(slot), |r| r.tid.load(Ordering::Acquire))
}

fn set_tid_address(slot: usize, addr: u64) -> Result<u64, Failure> {
    if let Some(r) = my_record(slot) {
        r.clear_tid.store(addr, Ordering::Release);
    }
    Ok(tid(slot))
}

/// End the calling thread alone. A thread started with `CLONE_CHILD_CLEARTID`, or that set
/// its address since, zeroes it and wakes a futex waiting there first: how a thread library
/// joins a thread.
fn exit_thread(slot: usize, code: u64) -> ! {
    signals::thread_ended(slot);
    if let Some(me) = preempt::current_thread()
        && let Some(r) = record_of(me)
    {
        let clear = r.clear_tid.load(Ordering::Acquire);
        if clear != 0 && to_user(clear, &0u32.to_le_bytes()).is_ok() {
            futex_wake(slot, clear, u32::MAX);
        }
        r.thread.store(NO_THREAD, Ordering::Release);
    }
    userproc::exit_thread_current(slot, code & 0xff)
}

/// End the calling process with `code`, every thread of it.
fn exit_group(slot: usize, code: u64) -> ! {
    userproc::with_locked(slot, |p| -> () { userproc::exit_current(p, code) });
    userproc::end_thread()
}

fn clone(
    slot: usize,
    frame: &<Cpu as HasUserMode>::SyscallFrame,
    [flags, stack, parent_tid, child_tid, tls]: [u64; 5],
) -> Result<u64, Failure> {
    use linux::clone as c;
    if flags & c::THREAD == 0 {
        // A fork by another name, which is how an aarch64 C library forks: the exit signal in
        // the low byte and nothing else.
        if flags & !c::CSIGNAL != 0 || stack != 0 {
            return Err(Failure::InvalidArgument);
        }
        return fork(slot, frame);
    }
    let needed = c::VM | c::SIGHAND;
    if flags & !(c::THREAD_FLAGS | c::CSIGNAL) != 0 || flags & needed != needed || stack == 0 {
        return Err(Failure::InvalidArgument);
    }
    let tls = if flags & c::SETTLS != 0 {
        usize::try_from(tls)
            .ok()
            .filter(|&t| t < <Cpu as HasUserMode>::USER_END)
            .ok_or(Failure::InvalidArgument)?
    } else {
        // SAFETY: from the calling thread's own system call.
        unsafe { Cpu::tls() }
    };
    let stack = usize::try_from(stack).map_err(|_| Failure::InvalidArgument)?;
    let root = userproc::with_locked(slot, |p| p.root).ok_or(Failure::BadDescriptor)?;
    let tid = NEXT_TID.fetch_add(1, Ordering::Relaxed);
    let tid_bytes = (tid as u32).to_le_bytes();
    if flags & c::PARENT_SETTID != 0 {
        to_user(parent_tid, &tid_bytes)?;
    }
    // One address space, so the child's address is written now, before it runs.
    if flags & c::CHILD_SETTID != 0 {
        to_user(child_tid, &tid_bytes)?;
    }
    let mut regs = Cpu::registers(frame);
    regs.set_return(0);
    regs.set_stack(stack);
    // Masked from starting the thread to recording its tid, so that on this CPU it cannot
    // run and ask for its tid before it has one.
    let irq = Cpu::irq_save();
    let started = spawn::start_resumed(slot, root, regs, tls);
    let recorded = started.and_then(|id| new_record(id, slot, tid));
    if let Some(r) = recorded
        && flags & c::CHILD_CLEARTID != 0
    {
        r.clear_tid.store(child_tid, Ordering::Release);
    }
    if let Some(id) = started {
        signals::cloned(slot, id, tid);
    }
    // SAFETY: pairs with the `irq_save` above.
    unsafe { Cpu::irq_restore(irq) };
    started.map(|_| tid).ok_or(Failure::TryAgain)
}

// ---- futexes ----------------------------------------------------------------------------

/// Wait queues futexes hash to. A wake wakes every waiter in its bucket, and each looks
/// again: a futex waiter must expect to be woken for nothing, and Linux's are too.
const FUTEX_BUCKETS: usize = 8;

static FUTEX_CLASS: LockClass = LockClass::new("linux.futex");
/// Each bucket's count of wakes. A waiter checks the futex's value and reads this under the
/// lock, and a waker counts under it before waking, so a wake between the check and the
/// block is seen as a changed count rather than lost. A fault may be taken under it, in the
/// second read of a futex word another thread has just unmapped; nothing that holds a lock a
/// fault takes ever takes this one.
static FUTEX_SEQ: SpinLock<[u64; FUTEX_BUCKETS], Cpu> =
    SpinLock::with_class([0; FUTEX_BUCKETS], &FUTEX_CLASS);
static FUTEX_WAITS: [WaitQueue; FUTEX_BUCKETS] = [const { WaitQueue::new() }; FUTEX_BUCKETS];
/// Futex waits that blocked, and waiters futex wakes made runnable.
static FUTEX_BLOCKS: AtomicU64 = AtomicU64::new(0);
static FUTEX_WAKES: AtomicU64 = AtomicU64::new(0);

/// The bucket of the futex at `addr` in process `slot`'s address space.
fn bucket(slot: usize, addr: u64) -> usize {
    let root = userproc::with_locked(slot, |p| p.root.raw()).unwrap_or(0);
    let h = (root ^ addr.rotate_left(20)).wrapping_mul(0x9e37_79b9_7f4a_7c15);
    (h >> 61) as usize % FUTEX_BUCKETS
}

fn futex(slot: usize, addr: u64, op: u64, val: u64, timeout: u64) -> Result<u64, Failure> {
    match op & !(linux::FUTEX_PRIVATE_FLAG | linux::FUTEX_CLOCK_REALTIME) {
        linux::FUTEX_WAIT => futex_wait(slot, addr, val as u32, timeout),
        linux::FUTEX_WAKE => Ok(futex_wake(slot, addr, val as u32) as u64),
        _ => Err(Failure::NotImplemented),
    }
}

fn futex_wait(slot: usize, addr: u64, val: u32, timeout: u64) -> Result<u64, Failure> {
    let deadline = if timeout == 0 {
        None
    } else {
        let mut ts = [0u8; 16];
        from_user(timeout, &mut ts)?;
        let secs = u64::from_le_bytes(ts[..8].try_into().unwrap_or([0; 8]));
        let nanos = u64::from_le_bytes(ts[8..].try_into().unwrap_or([0; 8]));
        crate::wait::deadline_after(secs.saturating_mul(1_000_000_000).saturating_add(nanos))
    };
    let mut word = [0u8; 4];
    // Faulted in before the lock.
    from_user(addr, &mut word)?;
    let b = bucket(slot, addr);
    let seen = {
        let seq = FUTEX_SEQ.lock_irqsave();
        from_user(addr, &mut word)?;
        if u32::from_le_bytes(word) != val {
            return Err(Failure::TryAgain);
        }
        seq[b]
    };
    let mut looks = 0u32;
    let woken = FUTEX_WAITS[b].wait_until(deadline, || {
        looks += 1;
        if userproc::exiting(slot) || FUTEX_SEQ.lock_irqsave()[b] != seen {
            return Some(Ok(0));
        }
        signals::interrupting(slot).then_some(Err(Failure::Interrupted))
    });
    if looks >= 3 {
        FUTEX_BLOCKS.fetch_add(1, Ordering::Relaxed);
        if woken == Ok(Err(Failure::Interrupted)) {
            signals::blocked_call_interrupted();
        }
    }
    woken.map_err(|_| Failure::TimedOut)?
}

/// Wake the waiters on the futex at `addr`. Returns how many were woken, at most `n`.
fn futex_wake(slot: usize, addr: u64, n: u32) -> usize {
    let b = bucket(slot, addr);
    {
        let mut seq = FUTEX_SEQ.lock_irqsave();
        seq[b] = seq[b].wrapping_add(1);
    }
    let woke = FUTEX_WAITS[b].wake_all();
    FUTEX_WAKES.fetch_add(woke as u64, Ordering::Relaxed);
    woke.min(n as usize)
}

// ---- fork, execve, wait4 ----------------------------------------------------------------

/// Each process slot's parent's slot plus one, zero for none: set by `fork`, cleared when
/// the parent reaps the child or either is torn down.
static PARENT: [AtomicUsize; MAX_PROCS] = [const { AtomicUsize::new(0) }; MAX_PROCS];
/// Each slot's `wait4` status once its last thread has gone, with [`ENDED`] set; zero before.
static STATUS: [AtomicU64; MAX_PROCS] = [const { AtomicU64::new(0) }; MAX_PROCS];
const ENDED: u64 = 1 << 32;
/// Parents waiting in `wait4`, woken by every child that ends.
static CHILD_WAIT: WaitQueue = WaitQueue::new();

/// Record that process `slot`'s last thread has gone, for a parent's `wait4`, and close its
/// descriptors, as Linux does at exit rather than when the parent reaps it: a pipe's reader
/// sees end of file once the last writer's process has ended. Called for every process that
/// ends, from its last thread, with no process lock held.
pub(crate) fn process_ended(slot: usize, code: u64) {
    let Some(status) = STATUS.get(slot) else {
        return;
    };
    let fds = userproc::with_locked(slot, |p| {
        let cell = STATES.get(p.slot)?;
        // SAFETY: see `STATES`; the lock is held, and the process's last thread is the caller.
        let s = unsafe { (*cell.get()).as_mut() }?;
        let fds = s.fds;
        s.fds = [Descriptor::Closed; MAX_FDS];
        Some(fds)
    })
    .flatten();
    close_all(fds.unwrap_or([Descriptor::Closed; MAX_FDS]));
    let reported = if code == userproc::KILLED {
        linux::KILLED_STATUS
    } else if let Some(signo) = linux::signal::exit_signal(code) {
        linux::signal::status(signo)
    } else {
        linux::exited_status(code)
    };
    status.store(u64::from(reported) | ENDED, Ordering::Release);
    signals::child_ended(slot);
    CHILD_WAIT.wake_all();
}

fn fork(slot: usize, frame: &<Cpu as HasUserMode>::SyscallFrame) -> Result<u64, Failure> {
    let mut regs = Cpu::registers(frame);
    regs.set_return(0);
    // SAFETY: from the calling thread's own system call.
    let tls = unsafe { Cpu::tls() };
    let (child, root) = userproc::fork_linux(slot).ok_or(Failure::TryAgain)?;
    let started = inherit(slot, child).and_then(|()| {
        signals::forked(slot, child);
        STATUS[child].store(0, Ordering::Release);
        PARENT[child].store(slot + 1, Ordering::Release);
        spawn::start_resumed(child, root, regs, tls).ok_or(Failure::TryAgain)
    });
    match started {
        Ok(_) => Ok(pid(child)),
        Err(e) => {
            PARENT[child].store(0, Ordering::Release);
            userproc::teardown(child);
            Err(e)
        }
    }
}

/// Give the child `fork` made in `child` its parent's descriptors: a console handle of its
/// own for each console descriptor, and one more count on each pipe end. Open files are not
/// inherited, since the namespace has no way to share one open file between two descriptors;
/// the child's copies are closed.
fn inherit(parent: usize, child: usize) -> Result<(), Failure> {
    let mut s = locked(parent, |_, s| Ok(*s))?;
    let c = userproc::slot(child).ok_or(Failure::TryAgain)?;
    for d in &mut s.fds {
        *d = match *d {
            Descriptor::Console(_) => {
                Descriptor::Console(c.console_handle().ok_or(Failure::TooManyOpen)?)
            }
            Descriptor::File { .. } => Descriptor::Closed,
            Descriptor::PipeRead(pipe) => {
                add_end(pipe, End::Read);
                Descriptor::PipeRead(pipe)
            }
            Descriptor::PipeWrite(pipe) => {
                add_end(pipe, End::Write);
                Descriptor::PipeWrite(pipe)
            }
            Descriptor::Socket(i) => {
                socket::add_ref(i);
                Descriptor::Socket(i)
            }
            other => other,
        };
    }
    // SAFETY: see `STATES`; the child has no thread yet.
    unsafe { *STATES[child].get() = Some(s) };
    Ok(())
}

/// Arguments and environment strings `execve` passes on, and the bytes they may take.
const EXEC_ARGS: usize = 8;
const EXEC_STRINGS: usize = 384;
/// Pages a program `execve` reads may take. aarch64's linker aligns segments to 64 KiB, so a
/// small static program there is several times its x86_64 size.
const EXEC_PAGES: usize = 32;

/// Strings copied from a program's `argv` or `envp`, before its memory is replaced.
struct Strings {
    bytes: [u8; EXEC_STRINGS],
    used: usize,
    spans: [(usize, usize); EXEC_ARGS],
    count: usize,
}

impl Strings {
    const fn new() -> Strings {
        Strings {
            bytes: [0; EXEC_STRINGS],
            used: 0,
            spans: [(0, 0); EXEC_ARGS],
            count: 0,
        }
    }

    /// Copy the null-terminated array of string pointers at `at`.
    fn read(&mut self, at: u64) -> Result<(), Failure> {
        if at == 0 {
            return Ok(());
        }
        for i in 0..=EXEC_ARGS {
            let mut word = [0u8; 8];
            // SAFETY: as in `to_user`.
            unsafe { Cpu::copy_from_user(&mut word, user_at(at, i * 8)?) }
                .map_err(|_| Failure::Fault)?;
            let ptr = u64::from_le_bytes(word);
            if ptr == 0 {
                return Ok(());
            }
            if self.count == EXEC_ARGS {
                break;
            }
            let n = copy_path(ptr, &mut self.bytes[self.used..])
                .map_err(|_| Failure::InvalidArgument)?;
            self.spans[self.count] = (self.used, n);
            self.used += n + 1;
            self.count += 1;
        }
        Err(Failure::InvalidArgument)
    }

    fn list(&self) -> [&[u8]; EXEC_ARGS] {
        let mut list: [&[u8]; EXEC_ARGS] = [&[]; EXEC_ARGS];
        for (l, &(at, n)) in list.iter_mut().zip(&self.spans[..self.count]) {
            *l = &self.bytes[at..at + n];
        }
        list
    }
}

fn execve(
    slot: usize,
    frame: &mut <Cpu as HasUserMode>::SyscallFrame,
    path: u64,
    argv: u64,
    envp: u64,
) -> Result<u64, Failure> {
    // Linux ends every other thread; this refuses rather than do that without signals.
    if userproc::threads_live(slot) > 1 {
        return Err(Failure::TryAgain);
    }
    let mut name = [0u8; PATH_MAX];
    let n = copy_path(path, &mut name)?;
    if name.first() != Some(&b'/') {
        return Err(Failure::NotFound);
    }
    let path = core::str::from_utf8(&name[..n]).map_err(|_| Failure::NotFound)?;
    let mut args = Strings::new();
    args.read(argv)?;
    let mut env = Strings::new();
    env.read(envp)?;

    let run = userproc::with_frames(|f| f.alloc.alloc_contiguous(EXEC_PAGES).ok())
        .flatten()
        .ok_or(Failure::NoMemory)?;
    let base = userproc::direct_ptr(PhysAddr::new(run.start().start().raw()));
    let result = base.ok_or(Failure::NoMemory).and_then(|base| {
        // SAFETY: the run was just taken from the allocator, so nothing else refers to it, and
        // the direct map reaches every byte of it; it is freed below, after its last use.
        let image = unsafe { core::slice::from_raw_parts_mut(base, EXEC_PAGES * Cpu::PAGE_SIZE) };
        exec_image(slot, frame, path, image, &args, &env)
    });
    userproc::with_frames(|f| {
        let _ = f.alloc.free_contiguous(run);
    });
    result
}

/// The part of `execve` that needs the program's bytes, read into `image`.
fn exec_image(
    slot: usize,
    frame: &mut <Cpu as HasUserMode>::SyscallFrame,
    path: &str,
    image: &mut [u8],
    args: &Strings,
    env: &Strings,
) -> Result<u64, Failure> {
    let len = with_ns(|ns| ns.read_all(path, image).map_err(failure))?;
    let program = Program::parse(
        &image[..len],
        <Cpu as HasUserMode>::ELF_MACHINE,
        (<Cpu as HasUserMode>::USER_START as u64, <Cpu as HasUserMode>::USER_END as u64),
        Cpu::PAGE_SIZE as u64,
    )
    .map_err(|_| Failure::NotExecutable)?;
    if userproc::personality_of(&program) != Some(Personality::Linux) {
        return Err(Failure::NotExecutable);
    }
    // Descriptors marked close-on-exec go now.
    let closing = locked(slot, |_, s| Ok(s.cloexec))?;
    for fd in (0..MAX_FDS).filter(|&fd| closing & (1 << fd) != 0) {
        let _ = close(slot, fd as u64);
    }
    // Past here the old program is gone: a failure ends the process, as Linux's does.
    let argv = args.list();
    let envp = env.list();
    let started = userproc::exec_linux(slot, &program).and_then(|()| {
        userproc::with_locked(slot, |p| {
            let (sp, brk_base) = lay_out(p, &program, &argv[..args.count], &envp[..env.count])?;
            let cell = STATES.get(slot)?;
            // SAFETY: see `STATES`; the lock is held.
            let s = unsafe { (*cell.get()).as_mut() }?;
            s.brk_base = brk_base;
            s.brk = brk_base;
            s.brk_end = brk_base + BRK_PAGES * Cpu::PAGE_SIZE;
            s.cloexec = 0;
            Some(sp)
        })
        .flatten()
    });
    let Some(sp) = started else {
        exit_group(slot, userproc::KILLED)
    };
    // SAFETY: from the calling thread's own system call; a new program starts with none.
    unsafe { Cpu::set_tls(0) };
    signals::executed(slot);
    let regs = <Cpu as HasUserMode>::UserRegisters::start(program.entry as usize, sp);
    Cpu::set_registers(frame, &regs);
    Ok(0)
}

fn wait4(slot: usize, pid_arg: u64, status: u64, options: u64) -> Result<u64, Failure> {
    let want = pid_arg as i64;
    // A process group, the caller's or another: there are none.
    if want == 0 || want < -1 {
        return Err(Failure::InvalidArgument);
    }
    if status != 0 {
        to_user(status, &[0u8; 4])?;
    }
    let me = slot + 1;
    let find = || -> Option<Result<(usize, u32), Failure>> {
        let mut any = false;
        for child in 0..MAX_PROCS {
            if PARENT[child].load(Ordering::Acquire) != me || (want > 0 && want != child as i64 + 1)
            {
                continue;
            }
            any = true;
            let s = STATUS[child].load(Ordering::Acquire);
            // Claimed, so a second waiter cannot report the same child.
            if s & ENDED != 0
                && PARENT[child]
                    .compare_exchange(me, 0, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
            {
                return Some(Ok((child, s as u32)));
            }
        }
        (!any).then_some(Err(Failure::NoChild))
    };
    let found = if options & linux::WNOHANG != 0 {
        match find() {
            Some(found) => found,
            None => return Ok(0),
        }
    } else {
        CHILD_WAIT
            .wait_until(None, || {
                if userproc::exiting(slot) {
                    return Some(Err(Failure::Io));
                }
                // A child to report first, then a signal to act on.
                find().or_else(|| signals::interrupting(slot).then_some(Err(Failure::Interrupted)))
            })
            .map_err(|_| Failure::TryAgain)?
    };
    let (child, code) = found?;
    if status != 0 {
        to_user(status, &code.to_le_bytes())?;
    }
    Ok(pid(child))
}

/// Wake every thread waiting on any of the personality's queues. Called when a process
/// starts to end, so a thread of it waiting here ends; the others look again and wait on.
pub(crate) fn wake_all_waiters() {
    for queue in PIPE_WAITS.iter().chain(&FUTEX_WAITS) {
        queue.wake_all();
    }
    CHILD_WAIT.wake_all();
    NS_WAIT.wake_all();
    crate::sockets::waits().wake_all();
}

/// Release what a Linux process in `slot` holds beyond its handles and memory: its open
/// files, its pipe ends, its threads' records, and its place in the family. Called from
/// teardown, once every thread of it has ended.
pub(crate) fn release(slot: usize) {
    signals::release(slot);
    for r in &RECORDS {
        if r.slot.load(Ordering::Acquire) == slot {
            r.thread.store(NO_THREAD, Ordering::Release);
        }
    }
    PARENT[slot].store(0, Ordering::Release);
    STATUS[slot].store(0, Ordering::Release);
    // Its children have no parent left to wait for them.
    for parent in &PARENT {
        let _ = parent.compare_exchange(slot + 1, 0, Ordering::AcqRel, Ordering::Acquire);
    }
    let Some(cell) = STATES.get(slot) else { return };
    // SAFETY: see `STATES`; every thread of the process has ended.
    let Some(s) = (unsafe { (*cell.get()).take() }) else {
        return;
    };
    close_all(s.fds);
}

/// Close what `fds` name beyond the process's own handles: files, pipe ends and sockets.
fn close_all(fds: [Descriptor; MAX_FDS]) {
    for d in fds {
        match d {
            Descriptor::File { fd, .. } => {
                let _ = with_ns(|ns| ns.close(fd).map_err(failure));
            }
            Descriptor::PipeRead(pipe) => drop_end(pipe, End::Read),
            Descriptor::PipeWrite(pipe) => drop_end(pipe, End::Write),
            Descriptor::Socket(i) => socket::drop_ref(i),
            Descriptor::Console(_) | Descriptor::Stdin | Descriptor::Closed => {}
        }
    }
}

// ---- start-up -------------------------------------------------------------------------

const ENVP: [&[u8]; 1] = [b"HOME=/"];
/// `argv` for each of the program's modes; mirrors `user/linux-hello/src/main.rs`.
const HELLO_ARGV: [&[u8]; 1] = [b"hello"];
const RICH_ARGV: [&[u8]; 2] = [b"hello", b"rich"];
const TLS_ARGV: [&[u8]; 2] = [b"hello", b"tls"];
const FILES_ARGV: [&[u8]; 2] = [b"hello", b"files"];

/// Reserve a new program's break and lay out its start-up stack, in process `p`, whose space
/// is loaded. Its stack pointer and the start of its break.
fn lay_out(
    p: &mut Process,
    program: &Program,
    argv: &[&[u8]],
    envp: &[&[u8]],
) -> Option<(usize, usize)> {
    let page = Cpu::PAGE_SIZE;
    let brk_base = p.reserve_next(BRK_PAGES * page, userproc::user_rw()).ok()?;
    let auxv = [
        (linux::AT_PHDR, program.phdr_vaddr().unwrap_or(0)),
        (linux::AT_PHENT, 56),
        (linux::AT_PHNUM, program.phnum() as u64),
        (linux::AT_PAGESZ, page as u64),
        (linux::AT_ENTRY, program.entry),
        (linux::AT_UID, 0),
        (linux::AT_EUID, 0),
        (linux::AT_GID, 0),
        (linux::AT_EGID, 0),
        (linux::AT_SECURE, 0),
    ];
    let info = linux::StartInfo {
        argv,
        envp,
        auxv: &auxv,
        random: random_bytes(p.root.raw() ^ program.entry),
    };
    let top = userproc::user_stack_top();
    let mut stack = [0u8; 1024];
    let sp = linux::initial_stack(&mut stack, top as u64, &info).ok()?;
    // SAFETY: the process's space is loaded; the stack region is mapped writable below
    // `top`, and `copy_to_user` faults its pages in.
    unsafe { Cpu::copy_to_user(UserAddr::new(top - stack.len()), &stack) }.ok()?;
    Some((usize::try_from(sp).ok()?, brk_base))
}

/// What a Linux program started with `argv` starts with, for [`userproc::run_linux`] or
/// [`userproc::start_linux`] to lay out once its segments are installed: descriptors 0 to 2,
/// its break, and its start-up stack. Returns the stack pointer.
fn start_with(
    argv: &'static [&'static [u8]],
) -> impl FnOnce(&mut Process, &Program) -> Option<usize> {
    move |p, program| {
        let stdout = p.console_handle()?;
        let stderr = p.console_handle()?;
        let (sp, brk_base) = lay_out(p, program, argv, &ENVP)?;
        let mut fds = [Descriptor::Closed; MAX_FDS];
        fds[0] = Descriptor::Stdin;
        fds[1] = Descriptor::Console(stdout);
        fds[2] = Descriptor::Console(stderr);
        PARENT[p.slot].store(0, Ordering::Release);
        STATUS[p.slot].store(0, Ordering::Release);
        // SAFETY: see `STATES`; the process's thread does not exist yet.
        unsafe {
            *STATES[p.slot].get() = Some(State {
                fds,
                cloexec: 0,
                nonblock: 0,
                brk_base,
                brk: brk_base,
                brk_end: brk_base + BRK_PAGES * Cpu::PAGE_SIZE,
            });
        }
        Some(sp)
    }
}

/// Sixteen bytes for `AT_RANDOM`, from a SplitMix64 stream over `seed`.
///
/// Not secret: the program cannot see the seed, but whoever knows the kernel can predict it.
/// A C library seeds its stack protector from these bytes, so this is a weakness until the
/// kernel has an entropy source to draw on.
fn random_bytes(seed: u64) -> [u8; 16] {
    let mut x = seed;
    let mut out = [0u8; 16];
    for chunk in out.chunks_mut(8) {
        x = x.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = x;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        chunk.copy_from_slice(&(z ^ (z >> 31)).to_le_bytes());
    }
    out
}

// ---- the boot-time check --------------------------------------------------------------

/// Pages read the program into. Kept, once it loads, for the scheduled check and the stress
/// run, which cannot read the volume themselves.
const PROGRAM_PAGES: usize = 64;
/// The program's exit codes when every step of a mode behaved; mirror `SUCCESS`,
/// `RICH_SUCCESS` and `TLS_SUCCESS` in `user/linux-hello/src/main.rs`.
const HELLO_SUCCESS: u64 = 42;
const RICH_SUCCESS: u64 = 43;
const TLS_SUCCESS: u64 = 44;
const FILES_SUCCESS: u64 = 50;

/// What the files mode left, read back.
///
/// SAFETY INVARIANT: borrowed only by [`run_hello`], once, on the boot path.
static OUT_BUF: SyncUnsafeCell<[u8; testdisk::LINUX_OUT_LEN + 1]> =
    SyncUnsafeCell::new([0; testdisk::LINUX_OUT_LEN + 1]);
/// What it writes to standard output.
const HELLO_OUTPUT: &[u8] = b"hello from linux\n";
/// The call it makes that the personality does not implement.
const HELLO_UNIMPLEMENTED: &str = "getrandom";

/// The program's bytes, kept by [`check`]; null until then. Written once, before anything
/// reads it.
static KEPT: AtomicPtr<u8> = AtomicPtr::new(core::ptr::null_mut());
static KEPT_LEN: AtomicUsize = AtomicUsize::new(0);

fn kept_program() -> Option<Program<'static>> {
    let ptr = KEPT.load(Ordering::Acquire);
    if ptr.is_null() {
        return None;
    }
    // SAFETY: `check` stored the length first and then the pointer of frames it never frees,
    // holding a program that loaded.
    let bytes = unsafe { core::slice::from_raw_parts(ptr, KEPT_LEN.load(Ordering::Acquire)) };
    userproc::parse(bytes)
}

/// What the Linux processes wrote to their consoles, for the boot check to read after its
/// process ends.
static CAPTURE_CLASS: LockClass = LockClass::new("linux.capture");
static CAPTURED: SpinLock<([u8; 64], usize), Cpu> =
    SpinLock::with_class(([0; 64], 0), &CAPTURE_CLASS);
/// The last unimplemented call a Linux process made, plus one; zero for none.
static UNIMPLEMENTED: AtomicU64 = AtomicU64::new(0);

fn capture(bytes: &[u8]) {
    let mut c = CAPTURED.lock_irqsave();
    let (buf, len) = &mut *c;
    let n = bytes.len().min(buf.len() - *len);
    buf[*len..*len + n].copy_from_slice(&bytes[..n]);
    *len += n;
}

/// Run the static Linux program from the test disk, unmodified, and grade it; then run
/// `init` to show native processes are unaffected. `frames` is the boot allocator.
pub fn check(c: &dyn EarlyConsole, frames: &mut FrameAllocator<'static, Cpu>, live: Live) -> Check {
    c.write_str("\n  linux      ");
    let Some(direct) = live.direct else {
        c.write_str("skipped: no kernel address space");
        return Check::Skipped;
    };
    // SAFETY: boot, before the stress run that is the volume's other user exists; the
    // namespace borrowing it is unmounted and dropped before this returns.
    let Some(volume) = (unsafe { crate::fs::volume() }) else {
        c.write_str("skipped: no volume is mounted");
        return Check::Skipped;
    };
    let before = frames.stats().free;
    let Ok(run) = frames.alloc_contiguous(PROGRAM_PAGES) else {
        c.write_str("NO RUN OF FRAMES for the program");
        return Check::Failed;
    };
    let phys = run.start().start().raw();
    let len = PROGRAM_PAGES * Cpu::PAGE_SIZE;
    let virt = match direct.to_virt(PhysAddr::new(phys)) {
        Ok(v) if direct.covers_phys(PhysAddr::new(phys + len as u64 - 1)) => v,
        _ => {
            let _ = frames.free_contiguous(run);
            c.write_str("THE PROGRAM'S FRAMES are outside the direct map");
            return Check::Failed;
        }
    };
    // SAFETY: the run was just taken from the allocator, so nothing else refers to it, and
    // the direct map maps it writable at `virt`. `'static` because a program is parsed as
    // one, and because the run is kept for the life of the machine once the program loads.
    let buf: &'static mut [u8] =
        unsafe { core::slice::from_raw_parts_mut(virt.raw() as *mut u8, len) };

    let mut ns: Namespace = Vfs::new();
    let (ok, kept) = match ns.mount("/", volume) {
        Ok(()) => run_hello(c, frames, &mut ns, buf),
        Err(_) => {
            c.write_str("MOUNTING THE VOLUME FAILED");
            (false, false)
        }
    };
    let open = ns.open_count();
    let _ = ns.unmount("/");
    drop(ns);
    // The volume after the program wrote it, walked from its tables: nothing lost, the tables
    // the same, nothing waiting in the cache.
    // SAFETY: boot, as above; the namespace that borrowed the volume is gone.
    let consistent = match unsafe { crate::fs::volume() } {
        Some(v) => {
            v.dirty_blocks() == 0
                && matches!(crate::fs::consistency(v), Ok(k) if k.lost == 0 && k.fats_differ == 0)
        }
        None => false,
    };
    c.write_str(if consistent {
        ", the volume consistent"
    } else {
        ", THE VOLUME IS NOT CONSISTENT"
    });
    let held = if kept {
        PROGRAM_PAGES
    } else {
        let _ = frames.free_contiguous(run);
        0
    };
    let leaked = before.saturating_sub(frames.stats().free) - held;
    if open != 0 {
        c.write_str(", ");
        write_usize(c, open);
        c.write_str(" FILES LEFT OPEN");
    }
    if leaked != 0 {
        c.write_str(", ");
        write_usize(c, leaked);
        c.write_str(" FRAMES LEAKED");
    }
    Check::from_ok(ok && open == 0 && leaked == 0 && consistent)
}

/// Run the program in its hello mode and grade it. Returns whether it passed and whether the
/// program was kept.
fn run_hello(
    c: &dyn EarlyConsole,
    frames: &mut FrameAllocator<'static, Cpu>,
    ns: &mut Namespace,
    buf: &'static mut [u8],
) -> (bool, bool) {
    let path = testdisk::LINUX_PROGRAM_PATH;
    let Ok(n) = ns.read_all(path, &mut *buf) else {
        c.write_str(path);
        c.write_str(" COULD NOT BE READ from the disk");
        return (false, false);
    };
    let buf: &'static [u8] = buf;
    let Some(program) = userproc::parse(&buf[..n]) else {
        c.write_str(path);
        c.write_str(" DOES NOT LOAD");
        return (false, false);
    };
    c.write_str(path);
    if userproc::personality_of(&program) != Some(Personality::Linux) {
        c.write_str(" IS NOT TAGGED linux");
        return (false, false);
    }
    c.write_str(" (");
    write_usize(c, n);
    // The program writes a line of its own; end this one first, as the fs check does.
    c.write_str(" bytes, tagged linux):\n             ");

    *CAPTURED.lock_irqsave() = ([0; 64], 0);
    UNIMPLEMENTED.store(0, Ordering::Relaxed);
    NS.store(core::ptr::from_mut(ns).cast(), Ordering::Relaxed);
    let exit = userproc::run_linux(frames, &program, start_with(&HELLO_ARGV));
    NS.store(core::ptr::null_mut(), Ordering::Relaxed);

    c.write_str("             exit ");
    let expected = if ENOSYS_FATAL {
        userproc::KILLED
    } else {
        HELLO_SUCCESS
    };
    let exit_ok = exit == Some(expected);
    match exit {
        Some(code) => write_hex(c, code),
        None => c.write_str("(none)"),
    }
    c.write_str(if exit_ok { " ok" } else { " WRONG" });
    let output_ok = {
        let captured = CAPTURED.lock_irqsave();
        &captured.0[..captured.1] == HELLO_OUTPUT
    };
    c.write_str(if output_ok {
        ", output ok"
    } else {
        ", OUTPUT WRONG"
    });
    let logged = UNIMPLEMENTED
        .load(Ordering::Relaxed)
        .checked_sub(1)
        .and_then(|number| linux::name(ABI.table(), number));
    let logged_ok = logged == Some(HELLO_UNIMPLEMENTED);
    c.write_str(if logged_ok {
        ", getrandom logged as unimplemented"
    } else {
        ", THE UNIMPLEMENTED CALL WAS NOT LOGGED"
    });

    c.write_str("; init after it:\n             ");
    let native = userproc::run_disk_program(c, frames, userproc::init_elf());
    let native_ok = matches!(native, Some((_, true)));
    c.write_str(if native_ok {
        "             native init unaffected"
    } else {
        "             NATIVE INIT BROKEN"
    });

    // The same program writing the disk: files, a directory, a rename, removals, and a file
    // left for kbuild to read after the guest exits.
    NS.store(core::ptr::from_mut(ns).cast(), Ordering::Relaxed);
    let files = userproc::run_linux(frames, &program, start_with(&FILES_ARGV));
    NS.store(core::ptr::null_mut(), Ordering::Relaxed);
    c.write_str("; files mode exit ");
    match files {
        Some(code) => write_hex(c, code),
        None => c.write_str("(none)"),
    }
    // SAFETY: the one borrow of `OUT_BUF`; see its invariant.
    let out = unsafe { &mut *OUT_BUF.get() };
    let written = matches!(
        ns.read_all(testdisk::LINUX_OUT_PATH, out),
        Ok(n) if n == testdisk::LINUX_OUT_LEN
            && out[..n]
                .iter()
                .enumerate()
                .all(|(i, &b)| b == testdisk::out_byte(testdisk::LINUX_OUT_SEED, i))
    );
    let files_ok = files == Some(FILES_SUCCESS) && written;
    c.write_str(match (files == Some(FILES_SUCCESS), written) {
        (true, true) => " ok, /KINTANE/LINUX.OUT read back",
        (true, false) => ", /KINTANE/LINUX.OUT IS NOT WHAT IT WROTE",
        _ => " WRONG",
    });
    // Kept for the checks that run the program with the scheduler, which is only worth
    // doing with a program that passed here.
    let pass = exit_ok && output_ok && logged_ok && native_ok && files_ok;
    if pass {
        KEPT_LEN.store(n, Ordering::Release);
        KEPT.store(buf.as_ptr().cast_mut(), Ordering::Release);
    }
    (pass, pass)
}

// ---- the scheduled check --------------------------------------------------------------

/// The process slot the scheduled check starts the program in, and the scheduler stack
/// slots its threads run on: the program, its thread and its child. `waits` has torn its
/// process down and reaped its threads by the time this runs.
const SLOT: usize = 0;
const STACKS: [usize; 3] = [1, 2, 3];
/// The longest the scheduled check gives the program.
const PATIENCE: Duration = Duration::from_nanos(10_000_000_000);
const POLL: Duration = Duration::from_nanos(5_000_000);

/// How one run of the kept program with the scheduler went.
struct Run {
    started: bool,
    /// Its exit code, or `None` if it had not exited when [`PATIENCE`] ran out.
    code: Option<u64>,
    /// Whether every thread it started ended, so its processes could be torn down.
    ended: bool,
    /// Files left open in its namespace.
    open: usize,
    /// Frames of the process pool not given back.
    frames: usize,
}

/// Run the kept program in the mode `argv` names, with the scheduler and the volume's
/// namespace, until it and every process it made have exited or [`PATIENCE`] runs out, and tear
/// them down. On the boot thread. `Err` is the verdict, and what to say, when it cannot run.
fn run_mode(argv: &'static [&'static [u8]]) -> Result<Run, (Check, &'static str)> {
    let Some(program) = kept_program() else {
        return Err((Check::Skipped, "skipped: the linux check kept no program"));
    };
    if userproc::with_frames(|f| f.alloc.stats().free).is_none() {
        return Err((Check::Skipped, "skipped: no frames for processes"));
    }
    // SAFETY: as in `check`: the stress run has not started, and nothing else on the boot
    // path holds the volume now.
    let Some(volume) = (unsafe { crate::fs::volume() }) else {
        return Err((Check::Skipped, "skipped: no volume is mounted"));
    };
    let mut ns: Namespace = Vfs::new();
    if ns.mount("/", volume).is_err() {
        return Err((Check::Failed, "MOUNTING THE VOLUME FAILED"));
    }
    spawn::use_stacks(&STACKS);
    let frames_before = free_frames();
    NS.store(core::ptr::from_mut(&mut ns).cast(), Ordering::Relaxed);

    let started = userproc::start_linux(SLOT, &program, start_with(argv));
    let give_up = timekeeping::now().saturating_add(PATIENCE);
    let running = || {
        started.is_some_and(preempt::alive)
            || (0..MAX_PROCS).any(|slot| userproc::threads_live(slot) != 0)
    };
    while running() && timekeeping::now() < give_up {
        preempt::sleep_until(timekeeping::now().saturating_add(POLL));
    }
    let code = if running() {
        None
    } else {
        userproc::slot(SLOT).and_then(|p| p.exit)
    };
    let ended = spawn::end_threads();
    if ended {
        for slot in 0..MAX_PROCS {
            userproc::teardown(slot);
        }
    }
    NS.store(core::ptr::null_mut(), Ordering::Relaxed);
    let open = ns.open_count();
    let _ = ns.unmount("/");
    drop(ns);
    Ok(Run {
        started: started.is_some(),
        code,
        ended,
        open,
        frames: frames_before.saturating_sub(free_frames()),
    })
}

/// Report what a run left behind. Whether it left nothing.
fn report_run(c: &dyn EarlyConsole, run: &Run) -> bool {
    if !run.ended {
        c.write_str("; A THREAD NEVER ENDED, its processes left in place");
    }
    if run.open != 0 {
        c.write_str("; ");
        write_usize(c, run.open);
        c.write_str(" FILES LEFT OPEN");
    }
    c.write_str("; ");
    write_usize(c, run.frames);
    c.write_str(if run.frames == 0 {
        " frames left ok"
    } else {
        " FRAMES LEAKED"
    });
    run.ended && run.open == 0 && run.frames == 0
}

/// Run the program again with the scheduler, in its mode that forks, pipes, execs, waits and
/// starts a thread that shares a futex-guarded counter, and grade it; then in its signals mode.
/// On the boot thread.
pub fn scheduled_check(c: &dyn EarlyConsole) -> Check {
    c.write_str("\n  linux mt   ");
    let reads_before = PIPE_BLOCKED_READS.load(Ordering::Relaxed);
    let blocks_before = FUTEX_BLOCKS.load(Ordering::Relaxed);
    let wakes_before = FUTEX_WAKES.load(Ordering::Relaxed);
    let run = match run_mode(&RICH_ARGV) {
        Ok(run) => run,
        Err((check, why)) => {
            c.write_str(why);
            return check;
        }
    };
    let reads = PIPE_BLOCKED_READS.load(Ordering::Relaxed) - reads_before;
    let blocks = FUTEX_BLOCKS.load(Ordering::Relaxed) - blocks_before;
    let wakes = FUTEX_WAKES.load(Ordering::Relaxed) - wakes_before;
    match (run.started, run.code) {
        (false, _) => c.write_str("the program NEVER STARTED"),
        (true, None) => c.write_str("the program NEVER EXITED"),
        (true, Some(RICH_SUCCESS)) => {
            c.write_str("pipe, fork, execve, wait4, a thread and a futex ok")
        }
        (true, Some(code)) => {
            c.write_str("the program exited ");
            write_hex(c, code);
            c.write_str(", WRONG");
        }
    }
    c.write_str("; ");
    write_usize(c, reads as usize);
    c.write_str(" pipe reads blocked, ");
    write_usize(c, blocks as usize);
    c.write_str(" futex waits blocked, ");
    write_usize(c, wakes as usize);
    c.write_str(" woken");
    let blocked = reads > 0 && blocks > 0 && wakes > 0;
    if !blocked {
        c.write_str("; NOTHING REALLY BLOCKED");
    }
    let clean = report_run(c, &run);
    let rich = Check::from_ok(run.code == Some(RICH_SUCCESS) && blocked && clean);
    if !run.ended {
        // Its processes are still in the slots the signals run would use.
        c.write_str("\n  linux sig  NOT RUN: the run before it left its processes in place");
        return Check::Failed;
    }
    rich.and(signals::check(c)).and(signals::faults_check(c))
}

fn free_frames() -> usize {
    userproc::with_frames(|f| f.alloc.stats().free).unwrap_or(0)
}

/// Run the program in its socket modes with the scheduler, a client of kbuild's TCP service and
/// a server kbuild connects to, and grade them. On the boot thread.
pub fn sockets_check(c: &dyn EarlyConsole) -> Check {
    socket::check(c)
}

// ---- the stress run ---------------------------------------------------------------------
//
// Once per audit interval the auditor starts the program twice in its thread-pointer mode,
// pins both processes to one CPU, and waits for both. Each sets a thread pointer of its own
// and checks it after each of a hundred yields, which on one CPU switch to the other process
// or to a workload. A thread pointer that did not travel with its thread is read by the wrong
// process, which exits with a code saying so. Which CPU moves with the round, so on a
// multiprocessor every CPU takes a turn.
//
// A hundred, not thousands: a yield on a CPU a busy workload shares can hand that workload a
// whole slice, and two thousand of them took longer than the patience below on aarch64.
//
// And only every fourth audit interval. On one CPU a pair still costs the workloads a good
// part of a second, and run every interval it cut a 20 s run on `aarch64-virt` from 20 audits
// to 12; the thread pointer on one CPU is what the boot check already proves.

/// Pairs of Linux processes the stress run has run to completion.
static PAIRS: AtomicU64 = AtomicU64::new(0);
const PAIR_PATIENCE: Duration = Duration::from_nanos(10_000_000_000);
/// Audit intervals per pair.
const PAIR_EVERY: u64 = 4;

pub fn stress_cycles() -> u64 {
    PAIRS.load(Ordering::Relaxed)
}

/// Run this audit interval's Linux processes: a churning pair or a thread-pointer pair, each
/// in its turn. On the auditor's thread, after the waiting process.
pub fn stress_cycle(round: u64) -> Result<(), &'static str> {
    churn_cycle(round)?;
    pair_cycle(round)
}

/// Run one pair; see the section comment.
fn pair_cycle(round: u64) -> Result<(), &'static str> {
    if round % PAIR_EVERY != 0 {
        return Ok(());
    }
    let pair = round / PAIR_EVERY;
    let Some(program) = kept_program() else {
        // No disk, so no program: the boot check said so, and there is nothing to run.
        return Ok(());
    };
    let (first, second) = (crate::procs::stress_stack(), crate::waits::stress_stack());
    if first == usize::MAX || second == usize::MAX {
        return Err("the Linux processes' stacks were never claimed");
    }
    if !crate::procs::use_pool() {
        return Err("no frames were reserved for processes");
    }
    spawn::use_stacks(&[first, second]);
    let frames_before = free_frames();
    let cpu = (pair as usize) % preempt::stats().cpus.max(1);

    let [a, b] = [0, 1].map(|slot| userproc::start_linux(slot, &program, start_with(&TLS_ARGV)));
    for id in [a, b].into_iter().flatten() {
        preempt::set_affinity(id, 1 << cpu);
    }
    let give_up = timekeeping::now().saturating_add(PAIR_PATIENCE);
    while [a, b].into_iter().flatten().any(preempt::alive) && timekeeping::now() < give_up {
        preempt::sleep_until(timekeeping::now().saturating_add(POLL));
    }
    if !spawn::end_threads() {
        // Its tables cannot be freed while a thread may still run on them.
        return Err("a Linux process's thread did not end");
    }
    let codes = [0, 1].map(|slot| userproc::slot(slot).and_then(|p| p.exit));
    userproc::teardown(0);
    userproc::teardown(1);
    if a.is_none() || b.is_none() {
        return Err("a Linux process did not start");
    }
    if codes != [Some(TLS_SUCCESS); 2] {
        return Err("a Linux process read a thread pointer that was not its own");
    }
    if free_frames() != frames_before {
        return Err("a Linux process's frames did not all come back");
    }
    PAIRS.fetch_add(1, Ordering::Relaxed);
    Ok(())
}

// ---- the stress run: mappings churned on two CPUs at once -------------------------------
//
// Halfway between pairs, the auditor starts the program in its churn mode pinned to one CPU,
// lets it begin, and only then builds and starts a second pinned to the next CPU. Each maps
// anonymous pages, faults every one in by writing it, and unmaps them, two hundred times over.
// Every fault takes the frame lock, and every unmap shoots down the other CPUs' translations
// while holding it; so does installing the second program while the first faults. A CPU that
// waits for the frame lock without answering the shootdown its holder is waiting for stops
// them both, and then every CPU that needs either; see `userproc::with_frames`.

/// Churning pairs the stress run has run to completion.
static CHURNS: AtomicU64 = AtomicU64::new(0);
const CHURN_ARGV: [&[u8]; 2] = [b"hello", b"churn"];
/// Mirrors `CHURN_SUCCESS` in `user/linux-hello/src/main.rs`.
const CHURN_SUCCESS: u64 = 46;
/// How long the first churning process runs alone before the second is built and installed:
/// long enough for it to be faulting on its CPU when the install shoots down.
const CHURN_HEAD_START: Duration = Duration::from_nanos(20_000_000);

pub fn churn_cycles() -> u64 {
    CHURNS.load(Ordering::Relaxed)
}

/// Run one churning pair; see the section comment.
fn churn_cycle(round: u64) -> Result<(), &'static str> {
    let cpus = preempt::stats().cpus;
    if round % PAIR_EVERY != PAIR_EVERY / 2 || cpus < 2 {
        return Ok(());
    }
    let Some(program) = kept_program() else {
        return Ok(());
    };
    let (first, second) = (crate::procs::stress_stack(), crate::waits::stress_stack());
    if first == usize::MAX || second == usize::MAX {
        return Err("the churning processes' stacks were never claimed");
    }
    if !crate::procs::use_pool() {
        return Err("no frames were reserved for processes");
    }
    spawn::use_stacks(&[first, second]);
    let frames_before = free_frames();
    let cpu = (round / PAIR_EVERY) as usize % cpus;
    let start_on = |slot: usize, cpu: usize| {
        let id = userproc::start_linux(slot, &program, start_with(&CHURN_ARGV))?;
        preempt::set_affinity(id, 1 << cpu);
        Some(id)
    };
    let a = start_on(0, cpu);
    preempt::sleep_until(timekeeping::now().saturating_add(CHURN_HEAD_START));
    let b = start_on(1, (cpu + 1) % cpus);
    let give_up = timekeeping::now().saturating_add(PAIR_PATIENCE);
    while [a, b].into_iter().flatten().any(preempt::alive) && timekeeping::now() < give_up {
        preempt::sleep_until(timekeeping::now().saturating_add(POLL));
    }
    if !spawn::end_threads() {
        return Err("a churning process's thread did not end");
    }
    let codes = [0, 1].map(|slot| userproc::slot(slot).and_then(|p| p.exit));
    userproc::teardown(0);
    userproc::teardown(1);
    if a.is_none() || b.is_none() {
        return Err("a churning process did not start");
    }
    if codes != [Some(CHURN_SUCCESS); 2] {
        return Err("a churning process could not map, fault in or unmap its pages");
    }
    if free_frames() != frames_before {
        return Err("a churning process's frames did not all come back");
    }
    CHURNS.fetch_add(1, Ordering::Relaxed);
    Ok(())
}

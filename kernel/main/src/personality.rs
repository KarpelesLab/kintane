//! The Linux personality: Linux system calls, answered on KinTane's objects.
//!
//! A process whose program carries no KinTane ABI note is tagged `linux` at load
//! ([`userproc::personality_of`]), and its system call table is [`syscalls`]: Linux's x86_64
//! numbers and argument registers, a value or a negated errno in `rax`, and every other
//! register as the program left it. The half of this that needs no process — the table of
//! names, the errno mapping, the start-up stack, `struct stat` and `struct utsname` — is
//! `kernel/linux`, and host-tested there.
//!
//! # Descriptors
//!
//! A Linux process's descriptors are a view, not a second kind of authority. Standard output
//! and standard error are console handles in the process's own handle table: a write through
//! either is checked against its handle exactly as the native `debug_write` is, and closing
//! the descriptor closes the handle. A file opened with `openat` is an open file in the
//! filesystem namespace the process was started with. Standard input reads as end of file,
//! because nothing feeds it yet.
//!
//! Every operation on a descriptor answers at once, with a value or a [`Failure`]. A
//! descriptor that can have nothing to give yet — a pipe, a socket, a console with input —
//! needs the native ABI's blocking calls and wait queues. It parks its thread on that
//! mechanism at the point where `read` answers today, rather than on one of this file's
//! own; [`Descriptor`] gains the variant, and the table does not change shape.
//!
//! # What is checked at boot
//!
//! [`check`] reads `/KINTANE/LINUX.ELF` from the test disk — `user/linux-hello`, a static
//! program that knows nothing of KinTane — and runs it unmodified. It grades it by what it
//! wrote to standard output, by the exit code it chose (which names the first step that
//! went wrong), and by the unimplemented call the kernel logged by name. Then `init` runs
//! again on the same kernel, to show a native process is unaffected.

#![allow(unsafe_code)]

use core::cell::SyncUnsafeCell;
use core::sync::atomic::{AtomicPtr, AtomicU64, AtomicUsize, Ordering};

use arch::Cpu;
use block::testdisk;
use elf::Program;
use hal::user::SyscallFrame;
use hal::{Arch, EarlyConsole, HasUserMode, PhysAddr, UserAddr};
use kobject::handle::Handle;
use linux::{Failure, FileKind, nr};
use mm::phys::FrameAllocator;
use vfs::{Kind, Vfs};

use crate::userproc::{self, MAX_PROCS, Personality, Process};
use crate::{Check, Live, write_hex, write_usize};

/// This kernel has the Linux personality, so [`userproc::personality_of`] tags programs
/// with no KinTane note `linux` rather than refusing them.
pub(crate) const ENABLED: bool = true;

/// Whether an unimplemented call kills the process (LINUX_ENOSYS_FATAL) rather than failing
/// with `ENOSYS`.
const ENOSYS_FATAL: bool = kconfig::LINUX_ENOSYS_FATAL;

/// Descriptors a process can hold at once.
const MAX_FDS: usize = 16;
/// The most one `read` or `write` moves. Linux allows a short count; a program loops.
const MAX_IO: usize = 4096;
/// The longest path `openat` reads, NUL included.
const PATH_MAX: usize = 128;
/// The break's reservation, in pages: `brk` moves within it and never past it.
const BRK_PAGES: usize = 64;
/// `uname`'s machine.
const MACHINE: &str = "x86_64";

/// A descriptor: what one Linux file descriptor number names.
#[derive(Clone, Copy)]
enum Descriptor {
    Closed,
    /// Standard input: nothing feeds it, so it reads as end of file.
    Stdin,
    /// The console, through a handle in the process's own table.
    Console(Handle),
    /// An open file in the namespace, with what `fstat` reports of it.
    File {
        fd: vfs::Fd,
        kind: FileKind,
        len: u64,
        ino: u64,
    },
}

/// What a Linux process has that a native one does not.
struct State {
    fds: [Descriptor; MAX_FDS],
    /// The break: `[brk_base, brk)` is the heap the program asked for, inside the
    /// reservation `[brk_base, brk_end)`.
    brk_base: usize,
    brk: usize,
    brk_end: usize,
    /// The thread pointer the program set, or zero.
    tls: usize,
}

/// Each process slot's Linux state.
///
/// SAFETY INVARIANT: the same as `userproc::PROCS`, whose slots these follow. A slot is
/// written by [`start`] before the process's one thread exists, reached from that thread's
/// own system calls while it runs, and cleared by [`release`] from teardown once the thread
/// has been reaped. One thread per process, so each borrow is the only one.
static STATES: [SyncUnsafeCell<Option<State>>; MAX_PROCS] =
    [const { SyncUnsafeCell::new(None) }; MAX_PROCS];

/// The namespace Linux processes open files in.
type Namespace = Vfs<'static, 1, 4>;

/// The namespace, while [`check`] runs a Linux process in it; null otherwise.
///
/// SAFETY INVARIANT: set by the check to a namespace it owns and cleared before that
/// namespace is dropped, and used only by the one Linux process the check runs — from its
/// own thread's system calls, and from its teardown on the boot thread once it has ended.
static NS: AtomicPtr<Namespace> = AtomicPtr::new(core::ptr::null_mut());

fn ns() -> Result<&'static mut Namespace, Failure> {
    let ptr = NS.load(Ordering::Relaxed);
    // SAFETY: see `NS`.
    unsafe { ptr.as_mut() }.ok_or(Failure::Io)
}

fn state(p: &Process) -> Result<&'static mut State, Failure> {
    let cell = STATES.get(p.slot).ok_or(Failure::BadDescriptor)?;
    // SAFETY: see `STATES`; this is the process's own thread.
    unsafe { (*cell.get()).as_mut() }.ok_or(Failure::BadDescriptor)
}

// ---- the table ------------------------------------------------------------------------

/// The Linux system call table: what a process tagged `linux` calls through.
pub(crate) fn syscalls(p: &mut Process, frame: &mut <Cpu as HasUserMode>::SyscallFrame) {
    let [a0, a1, a2, a3, _, _] = frame.args();
    let number = frame.number();
    let result = match number {
        nr::READ => read(p, a0, a1, a2),
        nr::WRITE => write(p, a0, a1, a2),
        nr::CLOSE => close(p, a0),
        nr::FSTAT => fstat(p, a0, a1),
        nr::MMAP => mmap(p, a1, a2, a3),
        nr::MUNMAP => munmap(p, a0, a1),
        nr::BRK => brk(p, a0),
        // One thread per process, so its thread id is its process id.
        nr::GETPID | nr::GETTID | nr::SET_TID_ADDRESS => Ok(pid(p)),
        nr::EXIT | nr::EXIT_GROUP => userproc::exit_current(p, a0 & 0xff),
        nr::UNAME => uname(a0),
        nr::ARCH_PRCTL => arch_prctl(p, a0, a1),
        nr::OPENAT => openat(p, a0, a1, a2),
        _ => unimplemented(p, number),
    };
    frame.set_return(linux::ret(result));
}

/// Log a call the personality does not implement, by the name Linux gives it, and fail it
/// with `ENOSYS` — or end the process, under LINUX_ENOSYS_FATAL.
fn unimplemented(p: &mut Process, number: u64) -> Result<u64, Failure> {
    let e = &arch::EARLY;
    e.write_str("linux: ");
    e.write_str(linux::name(linux::TABLE_X86_64, number).unwrap_or("an unknown call"));
    e.write_str(" (");
    write_usize(e, number as usize);
    e.write_str(") is not implemented");
    UNIMPLEMENTED.store(number.wrapping_add(1), Ordering::Relaxed);
    if ENOSYS_FATAL {
        e.write_str(", and LINUX_ENOSYS_FATAL ends the process\n");
        userproc::exit_current(p, userproc::KILLED)
    }
    e.write_str("\n");
    Err(Failure::NotImplemented)
}

fn pid(p: &Process) -> u64 {
    // Linux's pid 0 is no process; slots count from it.
    p.slot as u64 + 1
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

/// The user address `offset` bytes past `base`.
fn user_at(base: u64, offset: usize) -> Result<UserAddr, Failure> {
    usize::try_from(base)
        .ok()
        .and_then(|b| b.checked_add(offset))
        .map(UserAddr::new)
        .ok_or(Failure::Fault)
}

fn read(p: &mut Process, fd: u64, buf: u64, count: u64) -> Result<u64, Failure> {
    let s = state(p)?;
    let Descriptor::File { fd, .. } = descriptor(s, fd)? else {
        return match descriptor(s, fd)? {
            Descriptor::Stdin => Ok(0),
            _ => Err(Failure::BadDescriptor),
        };
    };
    let ns = ns()?;
    let count = usize::try_from(count).unwrap_or(MAX_IO).min(MAX_IO);
    let mut chunk = [0u8; 256];
    let mut done = 0;
    while done < count {
        let want = (count - done).min(chunk.len());
        let got = ns.read(fd, &mut chunk[..want]).map_err(failure)?;
        // SAFETY: the process's space is loaded, as on every system call; `copy_to_user`
        // checks the range and faults its pages in.
        unsafe { Cpu::copy_to_user(user_at(buf, done)?, &chunk[..got]) }
            .map_err(|_| Failure::Fault)?;
        done += got;
        if got < want {
            break;
        }
    }
    Ok(done as u64)
}

fn write(p: &mut Process, fd: u64, buf: u64, count: u64) -> Result<u64, Failure> {
    let s = state(p)?;
    let Descriptor::Console(handle) = descriptor(s, fd)? else {
        // Standard input is not open for writing, and every file is open read-only.
        return Err(Failure::BadDescriptor);
    };
    if !p.may_write_console(handle) {
        return Err(Failure::BadDescriptor);
    }
    let count = usize::try_from(count).unwrap_or(MAX_IO).min(MAX_IO);
    let mut chunk = [0u8; 256];
    let mut done = 0;
    while done < count {
        let n = (count - done).min(chunk.len());
        // SAFETY: as in `read`.
        unsafe { Cpu::copy_from_user(&mut chunk[..n], user_at(buf, done)?) }
            .map_err(|_| Failure::Fault)?;
        arch::EARLY.write_bytes(&chunk[..n]);
        capture(&chunk[..n]);
        done += n;
    }
    Ok(done as u64)
}

fn close(p: &mut Process, fd: u64) -> Result<u64, Failure> {
    let s = state(p)?;
    match descriptor(s, fd)? {
        Descriptor::Console(handle) => {
            p.close_handle(handle);
        }
        Descriptor::File { fd, .. } => ns()?.close(fd).map_err(failure)?,
        Descriptor::Stdin | Descriptor::Closed => {}
    }
    // `descriptor` accepted `fd`, so it indexes the table.
    s.fds[fd as usize] = Descriptor::Closed;
    Ok(0)
}

fn fstat(p: &mut Process, fd: u64, out: u64) -> Result<u64, Failure> {
    let s = state(p)?;
    let (kind, len, ino) = match descriptor(s, fd)? {
        Descriptor::File { kind, len, ino, .. } => (kind, len, ino),
        _ => (FileKind::CharDevice, 0, fd + 1),
    };
    // SAFETY: as in `read`.
    unsafe { Cpu::copy_to_user(user_at(out, 0)?, &linux::stat_bytes(kind, len, ino)) }
        .map_err(|_| Failure::Fault)?;
    Ok(0)
}

fn openat(p: &mut Process, dirfd: u64, path: u64, flags: u64) -> Result<u64, Failure> {
    let s = state(p)?;
    // Read the path one byte in, so a relative one can be made absolute in place: the
    // working directory is the root.
    let mut name = [0u8; PATH_MAX + 1];
    let n = copy_path(path, &mut name[1..])?;
    let path = match name.get(1) {
        Some(b'/') => &name[1..=n],
        _ if n == 0 => return Err(Failure::NotFound),
        _ if dirfd as i64 != linux::AT_FDCWD => {
            // Relative to a descriptor: none of them is a directory.
            descriptor(s, dirfd)?;
            return Err(Failure::NotADirectory);
        }
        _ => {
            name[0] = b'/';
            &name[..=n]
        }
    };
    if flags & linux::O_ACCMODE != linux::O_RDONLY {
        return Err(Failure::ReadOnly);
    }
    // A name the volume cannot hold is a name it does not have.
    let path = core::str::from_utf8(path).map_err(|_| Failure::NotFound)?;
    let ns = ns()?;
    let stat = ns.stat(path).map_err(failure)?;
    if flags & linux::O_DIRECTORY != 0 && stat.kind != Kind::Dir {
        return Err(Failure::NotADirectory);
    }
    // Linux's rule: the lowest free number.
    let index = s
        .fds
        .iter()
        .position(|d| matches!(d, Descriptor::Closed))
        .ok_or(Failure::TooManyOpen)?;
    let fd = ns.open(path).map_err(failure)?;
    s.fds[index] = Descriptor::File {
        fd,
        kind: match stat.kind {
            Kind::File => FileKind::Regular,
            Kind::Dir => FileKind::Directory,
        },
        len: stat.len,
        ino: inode(path),
    };
    Ok(index as u64)
}

/// Copy a NUL-terminated string from user address `at` into `into`, a page at a time so a
/// string that ends just before unmapped memory reads. Its length without the NUL.
fn copy_path(at: u64, into: &mut [u8]) -> Result<usize, Failure> {
    let page = Cpu::PAGE_SIZE;
    let mut done = 0;
    while done < into.len() {
        let addr = user_at(at, done)?;
        let n = (page - addr.raw() % page).min(into.len() - done);
        // SAFETY: as in `read`.
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
fn mmap(p: &mut Process, len: u64, prot: u64, flags: u64) -> Result<u64, Failure> {
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
    p.reserve_next(bytes, flags)
        .map(|start| start as u64)
        .map_err(|_| Failure::NoMemory)
}

/// Unmap exactly a mapping `mmap` made; part of one is refused.
fn munmap(p: &mut Process, addr: u64, len: u64) -> Result<u64, Failure> {
    let page = Cpu::PAGE_SIZE;
    let start = usize::try_from(addr).map_err(|_| Failure::InvalidArgument)?;
    let bytes = usize::try_from(len)
        .ok()
        .and_then(|l| l.checked_next_multiple_of(page))
        .ok_or(Failure::InvalidArgument)?;
    if start % page != 0 || !p.release_exact(start, bytes) {
        return Err(Failure::InvalidArgument);
    }
    Ok(0)
}

/// Move the break within its reservation. Linux's convention: the answer is the break as it
/// now is, which is the old one when the request cannot be met.
fn brk(p: &mut Process, addr: u64) -> Result<u64, Failure> {
    let s = state(p)?;
    if let Ok(want) = usize::try_from(addr)
        && (s.brk_base..=s.brk_end).contains(&want)
    {
        s.brk = want;
    }
    Ok(s.brk as u64)
}

fn uname(out: u64) -> Result<u64, Failure> {
    // SAFETY: as in `read`.
    unsafe { Cpu::copy_to_user(user_at(out, 0)?, &linux::utsname(MACHINE)) }
        .map_err(|_| Failure::Fault)?;
    Ok(0)
}

fn arch_prctl(p: &mut Process, code: u64, addr: u64) -> Result<u64, Failure> {
    if code != linux::ARCH_SET_FS {
        return Err(Failure::InvalidArgument);
    }
    let s = state(p)?;
    let addr = usize::try_from(addr)
        .ok()
        .filter(|&a| a < <Cpu as HasUserMode>::USER_END)
        .ok_or(Failure::InvalidArgument)?;
    // SAFETY: from the process's own system call, on the CPU it runs on; the kernel does
    // not read `FS`.
    unsafe { Cpu::set_tls(addr) };
    s.tls = addr;
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
        E::Corrupt(_) | E::Device(_) => Failure::Io,
    }
}

/// Release what a Linux process in `slot` holds beyond its handles and memory: its open
/// files, and the thread pointer it set. Called from teardown, on the kernel's space.
pub(crate) fn release(slot: usize) {
    let Some(cell) = STATES.get(slot) else { return };
    // SAFETY: see `STATES`; the process's thread has been reaped.
    let Some(s) = (unsafe { (*cell.get()).take() }) else {
        return;
    };
    for d in s.fds {
        if let (Descriptor::File { fd, .. }, Ok(ns)) = (d, ns()) {
            let _ = ns.close(fd);
        }
    }
    if s.tls != 0 {
        // SAFETY: on the boot CPU, the one the process ran on; the thread pointer is not
        // part of a thread's saved context yet, so it is reset here rather than left for the
        // next program to find.
        unsafe { Cpu::set_tls(0) };
    }
}

// ---- start-up -------------------------------------------------------------------------

const ARGV: [&[u8]; 1] = [b"hello"];
const ENVP: [&[u8]; 1] = [b"HOME=/"];

/// Lay out what a Linux program starts with, in the process `run_linux` built and loaded:
/// descriptors 0 to 2, the break's reservation, and the start-up stack. The stack pointer.
fn start(p: &mut Process, program: &Program) -> Option<usize> {
    let page = Cpu::PAGE_SIZE;
    let stdout = p.console_handle()?;
    let stderr = p.console_handle()?;
    let brk_bytes = BRK_PAGES * page;
    let brk_base = p.reserve_next(brk_bytes, userproc::user_rw()).ok()?;

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
        argv: &ARGV,
        envp: &ENVP,
        auxv: &auxv,
        random: random_bytes(p.root.raw() ^ program.entry),
    };
    let top = userproc::user_stack_top();
    let mut stack = [0u8; 1024];
    let sp = linux::initial_stack(&mut stack, top as u64, &info).ok()?;
    // SAFETY: `run_linux` loaded the process's space; the stack region is mapped writable
    // below `top`, and `copy_to_user` faults its pages in.
    unsafe { Cpu::copy_to_user(UserAddr::new(top - stack.len()), &stack) }.ok()?;

    let mut fds = [Descriptor::Closed; MAX_FDS];
    fds[0] = Descriptor::Stdin;
    fds[1] = Descriptor::Console(stdout);
    fds[2] = Descriptor::Console(stderr);
    // SAFETY: see `STATES`; the process's thread does not exist yet.
    unsafe {
        *STATES[p.slot].get() = Some(State {
            fds,
            brk_base,
            brk: brk_base,
            brk_end: brk_base + brk_bytes,
            tls: 0,
        });
    }
    usize::try_from(sp).ok()
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

// ---- the check ------------------------------------------------------------------------

/// Pages read the program into.
const PROGRAM_PAGES: usize = 64;
/// `linux-hello`'s exit code when every step behaved; mirrors `SUCCESS` in
/// `user/linux-hello/src/main.rs`.
const HELLO_SUCCESS: u64 = 42;
/// What it writes to standard output.
const HELLO_OUTPUT: &[u8] = b"hello from linux\n";
/// The call it makes that the personality does not implement.
const HELLO_UNIMPLEMENTED: &str = "getrandom";

/// What the Linux processes wrote to their consoles, for the check to read after they end.
///
/// SAFETY INVARIANT: written only from a Linux process's `write`, and the check runs one at
/// a time; read by the check once that process has ended.
static CAPTURED: SyncUnsafeCell<[u8; 64]> = SyncUnsafeCell::new([0; 64]);
static CAPTURED_LEN: AtomicUsize = AtomicUsize::new(0);
/// The last unimplemented call a Linux process made, plus one; zero for none.
static UNIMPLEMENTED: AtomicU64 = AtomicU64::new(0);

fn capture(bytes: &[u8]) {
    let at = CAPTURED_LEN.load(Ordering::Relaxed);
    // SAFETY: see `CAPTURED`.
    let buf = unsafe { &mut *CAPTURED.get() };
    let n = bytes.len().min(buf.len() - at);
    buf[at..at + n].copy_from_slice(&bytes[..n]);
    CAPTURED_LEN.store(at + n, Ordering::Relaxed);
}

fn captured() -> &'static [u8] {
    // SAFETY: see `CAPTURED`; the writer has ended.
    let buf = unsafe { &*CAPTURED.get() };
    &buf[..CAPTURED_LEN.load(Ordering::Relaxed)]
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
    // one; nothing built from it outlives the process, which ends before the run is freed.
    let buf: &'static mut [u8] =
        unsafe { core::slice::from_raw_parts_mut(virt.raw() as *mut u8, len) };

    let mut ns: Namespace = Vfs::new();
    let ok = match ns.mount("/", volume) {
        Ok(()) => run_hello(c, frames, &mut ns, buf),
        Err(_) => {
            c.write_str("MOUNTING THE VOLUME FAILED");
            false
        }
    };
    let open = ns.open_count();
    let _ = ns.unmount("/");
    drop(ns);
    let _ = frames.free_contiguous(run);
    let leaked = before.saturating_sub(frames.stats().free);
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
    Check::from_ok(ok && open == 0 && leaked == 0)
}

fn run_hello(
    c: &dyn EarlyConsole,
    frames: &mut FrameAllocator<'static, Cpu>,
    ns: &mut Namespace,
    buf: &'static mut [u8],
) -> bool {
    let path = testdisk::LINUX_PROGRAM_PATH;
    let Ok(n) = ns.read_all(path, &mut *buf) else {
        c.write_str(path);
        c.write_str(" COULD NOT BE READ from the disk");
        return false;
    };
    let buf: &'static [u8] = buf;
    let Some(program) = userproc::parse(&buf[..n]) else {
        c.write_str(path);
        c.write_str(" DOES NOT LOAD");
        return false;
    };
    c.write_str(path);
    if userproc::personality_of(&program) != Some(Personality::Linux) {
        c.write_str(" IS NOT TAGGED linux");
        return false;
    }
    c.write_str(" (");
    write_usize(c, n);
    // The program writes a line of its own; end this one first, as the fs check does.
    c.write_str(" bytes, tagged linux):\n             ");

    CAPTURED_LEN.store(0, Ordering::Relaxed);
    UNIMPLEMENTED.store(0, Ordering::Relaxed);
    NS.store(core::ptr::from_mut(ns).cast(), Ordering::Relaxed);
    let exit = userproc::run_linux(frames, &program, start);
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
    let output_ok = captured() == HELLO_OUTPUT;
    c.write_str(if output_ok {
        ", output ok"
    } else {
        ", OUTPUT WRONG"
    });
    let logged = UNIMPLEMENTED
        .load(Ordering::Relaxed)
        .checked_sub(1)
        .and_then(|number| linux::name(linux::TABLE_X86_64, number));
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
    exit_ok && output_ok && logged_ok && native_ok
}

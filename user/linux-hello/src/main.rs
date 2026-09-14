//! `linux-hello`: a static Linux program, and the test of the Linux personality.
//!
//! Everything here is Linux's, not KinTane's: the system calls are made by Linux's numbers
//! for the architecture it is built for, through `syscall` on x86_64 and `svc #0` on aarch64,
//! and return a value or a negated errno; the entry reads Linux's start-up stack; and nothing
//! links the native ABI crate. The same source builds for both architectures, the numbers
//! and the few instructions that differ in a module per architecture.
//!
//! What it does is chosen by `argv[1]`, and each mode exits with its success code or with
//! the number of the first step that was wrong, so the kernel's check learns *where* the
//! personality failed:
//!
//! * no argument: [`hello`], one process and no scheduler needed;
//! * `rich`: [`rich`], a pipe, `fork`, `execve`, `wait4`, and a thread sharing a futex-guarded
//!   counter;
//! * `child`: what `rich`'s child `execve`s into, which writes to the pipe it inherited;
//! * `tls`: [`tls`], a thread pointer checked across a hundred yields, run two at a time;
//! * `churn`: [`churn`], anonymous pages mapped, faulted in and unmapped, over and over, run two at
//!   a time on two CPUs.
//! * `signals`: [`signals`], handlers, masks, `EINTR`, `SIGCHLD`, `SIGPIPE` and default actions.
//! * `tcp <port>`: [`tcp`], a TCP client of kbuild's service on `<port>`, blocking and not;
//! * `serve`: [`serve`], a TCP server kbuild connects to through a port QEMU forwards.
//! * `poll`: [`poll_mode`], two connections kbuild makes into the guest, served in the order they
//!   arrive through `ppoll`, `select` and `epoll`;
//! * `files`: [`files`], writing the test disk: create, write, append, truncate, directories,
//!   rename and remove, and a file left for kbuild to read after the guest exits.
//! * `faults`: [`faults`], a handler run for a thread that only spins, and handlers for the faults
//!   a program raises itself.
//! * `rtsig`: [`rtsig`], real-time signals queued three deep and delivered in order, and a full
//!   queue refused.
//!
//! No step decides whether the kernel is right: the program reports what it saw.

#![no_std]
#![no_main]

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

#[cfg(target_arch = "x86_64")]
#[path = "x86_64.rs"]
mod sys;

#[cfg(target_arch = "aarch64")]
#[path = "aarch64.rs"]
mod sys;

const AT_FDCWD: u64 = -100i64 as u64;
const PROT_RW: u64 = 1 | 2;
const MAP_PRIVATE_ANONYMOUS: u64 = 0x02 | 0x20;
const AT_PAGESZ: u64 = 6;
const AT_ENTRY: u64 = 9;
const AT_RANDOM: u64 = 25;
const FUTEX_WAIT: u64 = 0;
const FUTEX_WAKE: u64 = 1;

const ENOENT: i64 = 2;
const EBADF: i64 = 9;
const ECHILD: i64 = 10;
const ENOSYS: i64 = 38;

/// The exit codes when every step of a mode behaved; `kernel/main/src/personality.rs`
/// mirrors the first three.
const SUCCESS: u64 = 42;
const RICH_SUCCESS: u64 = 43;
const TLS_SUCCESS: u64 = 44;
const CHILD_SUCCESS: u64 = 45;
const CHURN_SUCCESS: u64 = 46;
const FILES_SUCCESS: u64 = 50;

/// What the program says on standard output.
const HELLO: &[u8] = b"hello from linux\n";
/// `/HELLO.TXT` on the test disk; mirrors `kernel/block/src/testdisk.rs`.
const DISK_HELLO: &[u8] = b"hello from the KinTane test disk\n";
/// Where this program is on the test disk; mirrors `LINUX_PROGRAM_PATH` there.
const SELF: &[u8] = b"/KINTANE/LINUX.ELF\0";
/// What the `child` mode writes to the pipe.
const CHILD_MESSAGE: &[u8] = b"from the child, after execve\n";

const PAGE: u64 = 4096;

unsafe extern "C" {
    fn _start();
}

fn exit(code: u64) -> ! {
    sys::call(sys::EXIT_GROUP, [code, 0, 0, 0, 0, 0]);
    loop {
        core::hint::spin_loop();
    }
}

/// End with `step` unless `ok`.
fn expect(ok: bool, step: u64) {
    if !ok {
        exit(step);
    }
}

fn call1(nr: u64, a: u64) -> i64 {
    sys::call(nr, [a, 0, 0, 0, 0, 0])
}

fn yield_now() {
    sys::call(sys::SCHED_YIELD, [0; 6]);
}

fn map(len: u64) -> i64 {
    sys::call(sys::MMAP, [0, len, PROT_RW, MAP_PRIVATE_ANONYMOUS, -1i64 as u64, 0])
}

/// The byte string a C string pointer names, up to 64 bytes.
///
/// # Safety
/// `p` points at readable memory holding a NUL within 64 bytes.
unsafe fn cstr<'a>(p: *const u8) -> &'a [u8] {
    let mut n = 0;
    // SAFETY: the caller's promise.
    while n < 64 && unsafe { *p.add(n) } != 0 {
        n += 1;
    }
    // SAFETY: the `n` bytes just read.
    unsafe { core::slice::from_raw_parts(p, n) }
}

/// What the start-up stack said.
struct Start {
    argc: u64,
    argv0: &'static [u8],
    mode: &'static [u8],
    /// `argv[2]`: the mode's argument, if it takes one.
    arg: &'static [u8],
    pagesz: u64,
    entry: u64,
    random: u64,
}

extern "C" fn start(sp: *const u64) -> ! {
    // SAFETY: `sp` is where Linux's start-up stack begins; every read below follows its
    // layout: argc, argv pointers and a null, envp pointers and a null, auxv pairs to
    // AT_NULL.
    let s = unsafe {
        let argc = *sp;
        let argv = sp.add(1);
        let arg = |i: u64| {
            if i < argc && *argv.add(i as usize) != 0 {
                cstr(*argv.add(i as usize) as *const u8)
            } else {
                &[]
            }
        };
        let mut at = argv.add(argc as usize + 1);
        while *at != 0 {
            at = at.add(1);
        }
        at = at.add(1);
        let (mut pagesz, mut entry, mut random) = (0, 0, 0);
        while *at != 0 {
            match *at {
                AT_PAGESZ => pagesz = *at.add(1),
                AT_ENTRY => entry = *at.add(1),
                AT_RANDOM => random = *at.add(1),
                _ => {}
            }
            at = at.add(2);
        }
        Start {
            argc,
            argv0: arg(0),
            mode: arg(1),
            arg: arg(2),
            pagesz,
            entry,
            random,
        }
    };
    match s.mode {
        b"rich" => rich(),
        b"child" => child(),
        b"tls" => tls(),
        b"churn" => churn(),
        b"signals" => signals(),
        b"tcp" => tcp(s.arg),
        b"serve" => serve(),
        b"udp" => udp(s.arg),
        b"files" => files(),
        b"faults" => faults(),
        b"rtsig" => rtsig(),
        b"poll" => poll_mode(),
        b"peek" => peek_mode(s.arg),
        _ => hello(&s),
    }
}

// ---- hello: one process ------------------------------------------------------------------

fn hello(s: &Start) -> ! {
    // 10: argc and argv[0].
    expect(s.argc >= 1 && s.argv0 == b"hello", 10);
    // 11–13: the auxiliary vector.
    expect(s.pagesz == PAGE, 11);
    expect(s.entry == _start as *const () as u64, 12);
    expect(s.random != 0, 13);

    // 14: standard output.
    expect(
        sys::call(sys::WRITE, [1, HELLO.as_ptr() as u64, HELLO.len() as u64, 0, 0, 0])
            == HELLO.len() as i64,
        14,
    );

    // 15: a process id.
    expect(sys::call(sys::GETPID, [0; 6]) > 0, 15);

    // 16: uname says Linux, and whose. Every slice below is taken with `get`: indexing by a
    // range instantiates `core`'s panicking path, whose formatting code is built for the
    // kernel's code model and cannot be linked in the user half (see `lib/rt`).
    let mut uts = [0u8; 390];
    expect(call1(sys::UNAME, uts.as_mut_ptr() as u64) == 0, 16);
    expect(uts.get(0..6) == Some(b"Linux\0".as_slice()), 16);
    let release = uts.get(130..195).unwrap_or(&[]);
    expect(
        (0..release.len()).any(|i| release.get(i..i + 7) == Some(b"kintane".as_slice())),
        16,
    );

    // 17–18: the break moves, and the memory it gives is there.
    let b0 = call1(sys::BRK, 0);
    expect(b0 > 0, 17);
    let b1 = call1(sys::BRK, b0 as u64 + 2 * PAGE);
    expect(b1 == b0 + 2 * PAGE as i64, 17);
    // SAFETY: `[b0, b1)` is the break the kernel just granted.
    unsafe {
        let heap = b0 as *mut u8;
        for i in 0..(2 * PAGE as usize) {
            *heap.add(i) = i as u8;
        }
        for i in 0..(2 * PAGE as usize) {
            expect(*heap.add(i) == i as u8, 18);
        }
    }

    // 19–20: an anonymous mapping, used and unmapped.
    let m = map(2 * PAGE);
    expect(m > 0, 19);
    // SAFETY: `[m, m + 2 pages)` is the mapping just made.
    unsafe {
        let p = m as *mut u64;
        *p = 0x6c69_6e75_78;
        *p.add(1) = !0x6c69_6e75_78;
        expect(*p == 0x6c69_6e75_78 && *p.add(1) == !0x6c69_6e75_78, 19);
    }
    expect(sys::call(sys::MUNMAP, [m as u64, 2 * PAGE, 0, 0, 0, 0]) == 0, 20);

    // 21–22: the thread pointer. A TLS block's first word is its own address, which is what
    // a read through the thread pointer must then find.
    let tls = map(PAGE);
    expect(tls > 0, 21);
    // SAFETY: the page just mapped.
    unsafe { *(tls as *mut u64) = tls as u64 };
    expect(sys::set_tls(tls as u64), 21);
    expect(sys::tls_word() == tls as u64, 22);

    // 23–26: a file on the disk, through openat, fstat, read and close.
    let fd = sys::call(sys::OPENAT, [AT_FDCWD, b"/HELLO.TXT\0".as_ptr() as u64, 0, 0, 0, 0]);
    expect(fd >= 3, 23);
    let mut st = [0u8; 144];
    expect(sys::call(sys::FSTAT, [fd as u64, st.as_mut_ptr() as u64, 0, 0, 0, 0]) == 0, 24);
    // `st_size` is at the same offset in both architectures' `struct stat`.
    let size = st
        .get(48..56)
        .and_then(|s| <[u8; 8]>::try_from(s).ok())
        .map(u64::from_le_bytes);
    expect(size == Some(DISK_HELLO.len() as u64), 24);
    let mut buf = [0u8; 64];
    let n = sys::call(
        sys::READ,
        [
            fd as u64,
            buf.as_mut_ptr() as u64,
            buf.len() as u64,
            0,
            0,
            0,
        ],
    );
    expect(n == DISK_HELLO.len() as i64, 25);
    expect(buf.get(..DISK_HELLO.len()) == Some(DISK_HELLO), 25);
    expect(call1(sys::CLOSE, fd as u64) == 0, 26);

    // 27: a path that names nothing is ENOENT.
    let none = sys::call(sys::OPENAT, [AT_FDCWD, b"/NOPE.TXT\0".as_ptr() as u64, 0, 0, 0, 0]);
    expect(none == -ENOENT, 27);

    // 28: a descriptor that names nothing is EBADF.
    expect(sys::call(sys::READ, [99, buf.as_mut_ptr() as u64, 1, 0, 0, 0]) == -EBADF, 28);

    // 29: a call the personality does not implement is ENOSYS, and the kernel says which.
    let mut rnd = [0u8; 16];
    expect(
        sys::call(sys::GETRANDOM, [rnd.as_mut_ptr() as u64, 16, 0, 0, 0, 0]) == -ENOSYS,
        29,
    );

    exit(SUCCESS)
}

// ---- rich: processes, pipes and threads --------------------------------------------------

/// Marks each thread writes at the start of its own TLS block and reads back through its
/// thread pointer.
const PARENT_MARK: u64 = 0x7061_7265_6e74_0001;
const CHILD_MARK: u64 = 0x6368_696c_6400_0002;
const THREAD_MARK: u64 = 0x7468_7265_6164_0003;
const TLS_MARK: u64 = 0x746c_7300_0000_0000;

/// A page the parent never writes after the fork, and the child does before its `execve`.
const COW_ORIGINAL: u64 = 0x636f_775f_6f72_6967;
const COW_CHILD: u64 = 0x636f_775f_6368_6c64;
static COW_PROBE: AtomicU64 = AtomicU64::new(COW_ORIGINAL);

/// The counter both threads bump, the futex-based lock that guards it, and how often each
/// bumps it. Each bump yields while holding the lock, so the other thread finds it held and
/// waits on the futex.
static COUNTER: AtomicU64 = AtomicU64::new(0);
static LOCK: AtomicU32 = AtomicU32::new(0);
const ROUNDS: u64 = 40;
/// Yields a thread spends after its work, so the one that waits for it is already waiting.
const LINGER: u64 = 50;
/// The thread's tid, written by the kernel before the thread runs and zeroed when it exits.
static THREAD_TID: AtomicU32 = AtomicU32::new(u32::MAX);
/// What the thread found: `THREAD_OK`, or the step it failed at.
static THREAD_RESULT: AtomicU64 = AtomicU64::new(0);
const THREAD_OK: u64 = 1;

/// Take the lock: 0 is free, 1 held, 2 held with a waiter (Drepper's futex mutex).
fn lock() {
    if LOCK
        .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
    {
        return;
    }
    while LOCK.swap(2, Ordering::AcqRel) != 0 {
        sys::call(sys::FUTEX, [LOCK.as_ptr() as u64, FUTEX_WAIT, 2, 0, 0, 0]);
    }
}

fn unlock() {
    if LOCK.swap(0, Ordering::AcqRel) == 2 {
        sys::call(sys::FUTEX, [LOCK.as_ptr() as u64, FUTEX_WAKE, 1, 0, 0, 0]);
    }
}

/// Map a TLS block, mark it, point this thread at it, and check the mark reads back.
fn own_tls(mark: u64, step: u64) -> u64 {
    let block = map(PAGE);
    expect(block > 0, step);
    // SAFETY: the page just mapped.
    unsafe { *(block as *mut u64) = mark };
    expect(sys::set_tls(block as u64), step);
    expect(sys::tls_word() == mark, step);
    block as u64
}

fn rich() -> ! {
    // 50–51: a pipe, at the lowest free descriptors, which the `child` mode relies on.
    let mut fds = [0u32; 2];
    expect(call1(sys::PIPE2, fds.as_mut_ptr() as u64) == 0, 50);
    let [rfd, wfd] = fds.map(u64::from);
    expect(rfd == 3 && wfd == 4, 51);

    // 52: a thread pointer of this process's own.
    own_tls(PARENT_MARK, 52);

    // 53: fork.
    let child = sys::fork();
    expect(child >= 0, 53);
    if child == 0 {
        forked(rfd);
    }

    // 54: the write end closed here, so the child's is the last.
    expect(call1(sys::CLOSE, wfd) == 0, 54);
    // 55: the pipe is empty until the child, after its `execve`, writes. The read waits.
    let mut buf = [0u8; 64];
    let n = sys::call(sys::READ, [rfd, buf.as_mut_ptr() as u64, buf.len() as u64, 0, 0, 0]);
    expect(n == CHILD_MESSAGE.len() as i64, 55);
    expect(buf.get(..CHILD_MESSAGE.len()) == Some(CHILD_MESSAGE), 55);
    // 56: this thread's pointer is its own after that wait.
    expect(sys::tls_word() == PARENT_MARK, 56);
    // 57–58: wait4 reports the child, and the code it exited with. A child that failed says
    // which step, and that is passed on.
    let mut status = 0u32;
    let reaped = sys::call(sys::WAIT4, [child as u64, &raw mut status as u64, 0, 0, 0, 0]);
    expect(reaped == child, 57);
    let code = u64::from(status >> 8);
    expect(status == (CHILD_SUCCESS << 8) as u32, if code >= 70 { code } else { 58 });
    // 59: the child's write to the page they shared never reached this copy.
    expect(COW_PROBE.load(Ordering::Relaxed) == COW_ORIGINAL, 59);
    // 60: end of file, with no writer left anywhere.
    expect(sys::call(sys::READ, [rfd, buf.as_mut_ptr() as u64, 1, 0, 0, 0]) == 0, 60);
    // 61: no child is left to wait for.
    let none = sys::call(sys::WAIT4, [-1i64 as u64, &raw mut status as u64, 0, 0, 0, 0]);
    expect(none == -ECHILD, 61);

    // 62–63: a thread, on a stack of its own, with a thread pointer of its own.
    let stack = map(4 * PAGE);
    expect(stack > 0, 62);
    let block = map(PAGE);
    expect(block > 0, 62);
    // SAFETY: the page just mapped.
    unsafe { *(block as *mut u64) = THREAD_MARK };
    let mut parent_tid = 0u32;
    let tid = sys::clone_thread(
        (stack as u64) + 4 * PAGE,
        &raw mut parent_tid,
        THREAD_TID.as_ptr(),
        block as u64,
        thread,
    );
    expect(tid > 0, 62);
    expect(u64::from(parent_tid) == tid as u64, 63);
    // 64: both threads bump the counter under the lock.
    bump(64);
    // 65: this thread's pointer is its own throughout.
    expect(sys::tls_word() == PARENT_MARK, 65);
    // 66: join: wait on the tid word until the kernel zeroes it as the thread exits.
    loop {
        let t = THREAD_TID.load(Ordering::Acquire);
        if t == 0 {
            break;
        }
        let r = sys::call(
            sys::FUTEX,
            [
                THREAD_TID.as_ptr() as u64,
                FUTEX_WAIT,
                u64::from(t),
                0,
                0,
                0,
            ],
        );
        expect(r == 0 || r == -11, 66);
    }
    // 67: no bump was lost.
    expect(COUNTER.load(Ordering::Relaxed) == 2 * ROUNDS, 67);
    // 68: what the thread found.
    let found = THREAD_RESULT.load(Ordering::Relaxed);
    expect(found == THREAD_OK, if found >= 69 { found } else { 68 });
    exit(RICH_SUCCESS)
}

/// Bump the counter `ROUNDS` times under the lock, yielding while holding it.
fn bump(step: u64) {
    for _ in 0..ROUNDS {
        lock();
        let v = COUNTER.load(Ordering::Relaxed);
        yield_now();
        COUNTER.store(v + 1, Ordering::Relaxed);
        unlock();
        yield_now();
    }
    expect(COUNTER.load(Ordering::Relaxed) >= ROUNDS, step);
}

/// The thread `rich` starts. It cannot exit the process on a failure without taking the
/// test down with a code that names nothing, so it records the step instead.
extern "C" fn thread() -> u64 {
    let mut result = THREAD_OK;
    // 69: its thread pointer is the one `clone` gave it.
    if sys::tls_word() != THREAD_MARK {
        result = 69;
    }
    // 70: its tid is not the process's.
    if sys::call(sys::GETTID, [0; 6]) == sys::call(sys::GETPID, [0; 6]) {
        result = 70;
    }
    for _ in 0..ROUNDS {
        lock();
        let v = COUNTER.load(Ordering::Relaxed);
        yield_now();
        COUNTER.store(v + 1, Ordering::Relaxed);
        unlock();
        // 71: still its own pointer, after switches to and from the other thread.
        if sys::tls_word() != THREAD_MARK {
            result = 71;
        }
    }
    for _ in 0..LINGER {
        yield_now();
    }
    THREAD_RESULT.store(result, Ordering::Relaxed);
    0
}

/// The child `rich` forks, before its `execve`. Its failures are its exit code, which the
/// parent passes on.
fn forked(rfd: u64) -> ! {
    // 72–73: the page is still the parent's value, and a write here changes this copy.
    expect(COW_PROBE.load(Ordering::Relaxed) == COW_ORIGINAL, 72);
    COW_PROBE.store(COW_CHILD, Ordering::Relaxed);
    expect(COW_PROBE.load(Ordering::Relaxed) == COW_CHILD, 73);
    // 74: a thread pointer of its own, which stays its own while the parent runs, blocked on
    // the pipe this child has not yet written.
    own_tls(CHILD_MARK, 74);
    for _ in 0..LINGER {
        yield_now();
        expect(sys::tls_word() == CHILD_MARK, 74);
    }
    expect(call1(sys::CLOSE, rfd) == 0, 75);
    // 76: become the `child` mode of this same program, read afresh from the disk.
    let argv: [*const u8; 3] = [b"hello\0".as_ptr(), b"child\0".as_ptr(), core::ptr::null()];
    let envp: [*const u8; 2] = [b"HOME=/\0".as_ptr(), core::ptr::null()];
    sys::call(
        sys::EXECVE,
        [
            SELF.as_ptr() as u64,
            argv.as_ptr() as u64,
            envp.as_ptr() as u64,
            0,
            0,
            0,
        ],
    );
    exit(76)
}

/// What `forked` `execve`s into: a new program image, with the descriptors it inherited.
fn child() -> ! {
    // 77: the pipe's write end is still descriptor 4, and the parent is waiting on it.
    let n = sys::call(
        sys::WRITE,
        [
            4,
            CHILD_MESSAGE.as_ptr() as u64,
            CHILD_MESSAGE.len() as u64,
            0,
            0,
            0,
        ],
    );
    expect(n == CHILD_MESSAGE.len() as i64, 77);
    // 78: memory from before the `execve` is gone: this is the program's own first value.
    expect(COW_PROBE.load(Ordering::Relaxed) == COW_ORIGINAL, 78);
    exit(CHILD_SUCCESS)
}

// ---- tls: a thread pointer across switches -----------------------------------------------

/// Yields `tls` checks its thread pointer across. Few enough that a CPU shared with busy
/// stress workloads, each yield of which may cost a slice, still finishes in seconds.
const TLS_ROUNDS: u64 = 100;

fn tls() -> ! {
    // 90: a pointer and a mark of this process's own, told apart from another's by the pid.
    let pid = sys::call(sys::GETPID, [0; 6]) as u64;
    let mark = TLS_MARK | pid;
    own_tls(mark, 90);
    // 91: the same after every yield, however many other threads ran on this CPU between.
    for _ in 0..TLS_ROUNDS {
        yield_now();
        expect(sys::tls_word() == mark, 91);
    }
    exit(TLS_SUCCESS)
}

// ---- churn: page faults and unmaps, while another CPU does the same ----------------------

/// Times `churn` maps, faults in and unmaps its pages.
const CHURN_ROUNDS: u64 = 200;
/// Pages in each mapping.
const CHURN_PAGES: u64 = 8;

fn churn() -> ! {
    for round in 0..CHURN_ROUNDS {
        // 95: a fresh anonymous mapping, with nothing in it yet.
        let at = map(CHURN_PAGES * PAGE);
        expect(at > 0, 95);
        // 96: every page faulted in by a write, and reading back what was written.
        for i in 0..CHURN_PAGES {
            let page = (at as u64 + i * PAGE) as *mut u64;
            // SAFETY: a page of the mapping just made, readable and writable.
            unsafe { page.write(round << 8 | i) };
            // SAFETY: as above.
            expect(unsafe { page.read() } == round << 8 | i, 96);
        }
        // 97: unmapped again, which takes the page from every other CPU's cache too.
        let unmapped = sys::call(sys::MUNMAP, [at as u64, CHURN_PAGES * PAGE, 0, 0, 0, 0]);
        expect(unmapped == 0, 97);
    }
    exit(CHURN_SUCCESS)
}

// ---- signals: handlers, masks, EINTR, SIGCHLD, SIGPIPE and default actions -----------------

const SIGNALS_SUCCESS: u64 = 47;
const SIGKILL: u64 = 9;
const SIGUSR1: u64 = 10;
const SIGUSR2: u64 = 12;
const SIGPIPE: u64 = 13;
const SIGTERM: u64 = 15;
const SIGCHLD: u64 = 17;
const SIGSTOP: u64 = 19;
const SIG_DFL: u64 = 0;
const SIG_IGN: u64 = 1;
const SIG_BLOCK: u64 = 0;
const SIG_UNBLOCK: u64 = 1;
const SA_SIGINFO: u64 = 4;
const SA_RESTORER: u64 = 0x0400_0000;
const SA_RESTART: u64 = 0x1000_0000;
const EINTR: i64 = 4;
const EINVAL: i64 = 22;
const EPIPE: i64 = 32;

/// Times the handler that zeroes the callee-saved registers ran; `sys`'s assembly counts them.
pub static CLOBBER_HITS: AtomicU64 = AtomicU64::new(0);
static USR2_HITS: AtomicU64 = AtomicU64::new(0);
static USR2_SIGNO: AtomicU64 = AtomicU64::new(0);
static INTR_HITS: AtomicU64 = AtomicU64::new(0);
static CHLD_HITS: AtomicU64 = AtomicU64::new(0);
/// The pipe the interrupted thread reads, that it is about to, what its read answered, and its
/// tid word, which the kernel zeroes as it exits.
static INTR_FD: AtomicU64 = AtomicU64::new(0);
static INTR_READY: AtomicU64 = AtomicU64::new(0);
static INTR_RESULT: AtomicU64 = AtomicU64::new(0);
static INTR_TID: AtomicU32 = AtomicU32::new(u32::MAX);

fn bit(sig: u64) -> u64 {
    1 << (sig - 1)
}

/// Install `handler` for `sig`, returning through `sys::restorer`.
fn sigaction(sig: u64, handler: u64, flags: u64) -> i64 {
    let act = [handler, flags | SA_RESTORER, sys::restorer(), 0u64];
    sys::call(sys::RT_SIGACTION, [sig, act.as_ptr() as u64, 0, 8, 0, 0])
}

fn sigprocmask(how: u64, set: u64) -> i64 {
    sys::call(sys::RT_SIGPROCMASK, [how, &raw const set as u64, 0, 8, 0, 0])
}

fn pipe(step: u64) -> [u64; 2] {
    let mut fds = [0u32; 2];
    expect(call1(sys::PIPE2, fds.as_mut_ptr() as u64) == 0, step);
    fds.map(u64::from)
}

fn wait_child(child: i64, step: u64) -> u32 {
    let mut status = 0u32;
    let reaped = sys::call(sys::WAIT4, [child as u64, &raw mut status as u64, 0, 0, 0, 0]);
    expect(reaped == child, step);
    status
}

/// Wait on a tid word until the kernel zeroes it as its thread exits.
fn join(word: &AtomicU32, step: u64) {
    loop {
        let t = word.load(Ordering::Acquire);
        if t == 0 {
            return;
        }
        let r = sys::call(sys::FUTEX, [word.as_ptr() as u64, FUTEX_WAIT, u64::from(t), 0, 0, 0]);
        expect(r == 0 || r == -11 || r == -EINTR, step);
    }
}

extern "C" fn on_usr2(_sig: i32, info: *const i32, _uc: *const u8) {
    USR2_HITS.fetch_add(1, Ordering::Relaxed);
    // SAFETY: the kernel passes the `siginfo` it pushed, whose first field is the signal.
    USR2_SIGNO.store(unsafe { *info } as u64, Ordering::Relaxed);
}

extern "C" fn on_intr(_sig: i32) {
    INTR_HITS.fetch_add(1, Ordering::Relaxed);
}

extern "C" fn on_chld(_sig: i32) {
    CHLD_HITS.fetch_add(1, Ordering::Relaxed);
}

/// The thread [`signals`] interrupts: it reads an empty pipe no one writes.
extern "C" fn intr_thread() -> u64 {
    let mut b = [0u8; 1];
    INTR_READY.store(1, Ordering::Release);
    let fd = INTR_FD.load(Ordering::Relaxed);
    let n = sys::call(sys::READ, [fd, b.as_mut_ptr() as u64, 1, 0, 0, 0]);
    INTR_RESULT.store(n as u64, Ordering::Relaxed);
    0
}

fn signals() -> ! {
    let pid = sys::call(sys::GETPID, [0; 6]) as u64;
    let usr2 = on_usr2 as *const () as u64;

    // 110: SIGKILL and SIGSTOP take no disposition.
    expect(sigaction(SIGKILL, usr2, 0) == -EINVAL, 110);
    expect(sigaction(SIGSTOP, usr2, 0) == -EINVAL, 110);

    // 111–113: a signal a process sends itself runs its handler on the way out of `kill`. The
    // handler zeroes every callee-saved register, and `rt_sigreturn` gives each back.
    expect(sigaction(SIGUSR1, sys::clobber_handler(), 0) == 0, 111);
    let intact = sys::raise_marked(pid, SIGUSR1);
    expect(CLOBBER_HITS.load(Ordering::Relaxed) == 1, 112);
    expect(intact, 113);

    // 114–118: a blocked signal stays pending, runs once unblocked, and its siginfo names it.
    expect(sigaction(SIGUSR2, usr2, SA_SIGINFO) == 0, 114);
    expect(sigprocmask(SIG_BLOCK, bit(SIGUSR2)) == 0, 114);
    expect(sys::call(sys::KILL, [pid, SIGUSR2, 0, 0, 0, 0]) == 0, 114);
    expect(USR2_HITS.load(Ordering::Relaxed) == 0, 115);
    let mut pending = 0u64;
    let asked = sys::call(sys::RT_SIGPENDING, [&raw mut pending as u64, 8, 0, 0, 0, 0]);
    expect(asked == 0 && pending & bit(SIGUSR2) != 0, 116);
    expect(sigprocmask(SIG_UNBLOCK, bit(SIGUSR2)) == 0, 117);
    expect(USR2_HITS.load(Ordering::Relaxed) == 1, 117);
    expect(USR2_SIGNO.load(Ordering::Relaxed) == SIGUSR2, 118);

    // 119: SIGPIPE ignored, a write no one can read is EPIPE.
    expect(sigaction(SIGPIPE, SIG_IGN, 0) == 0, 119);
    let [r, w] = pipe(119);
    expect(call1(sys::CLOSE, r) == 0, 119);
    expect(sys::call(sys::WRITE, [w, b"x".as_ptr() as u64, 1, 0, 0, 0]) == -EPIPE, 119);
    expect(call1(sys::CLOSE, w) == 0, 119);
    expect(sigaction(SIGPIPE, SIG_DFL, 0) == 0, 119);

    // 120–124: a thread blocked reading an empty pipe is signalled by this one; its handler
    // runs, and its read answers EINTR.
    expect(sigaction(SIGUSR1, on_intr as *const () as u64, 0) == 0, 120);
    let [r, w] = pipe(120);
    INTR_FD.store(r, Ordering::Relaxed);
    let stack = map(4 * PAGE);
    let block = map(PAGE);
    expect(stack > 0 && block > 0, 121);
    let mut parent_tid = 0u32;
    let tid = sys::clone_thread(
        (stack as u64) + 4 * PAGE,
        &raw mut parent_tid,
        INTR_TID.as_ptr(),
        block as u64,
        intr_thread,
    );
    expect(tid > 0, 121);
    while INTR_READY.load(Ordering::Acquire) == 0 {
        yield_now();
    }
    // Long enough that its read has blocked.
    for _ in 0..LINGER {
        yield_now();
    }
    expect(sys::call(sys::TGKILL, [pid, tid as u64, SIGUSR1, 0, 0, 0]) == 0, 122);
    join(&INTR_TID, 123);
    expect(INTR_RESULT.load(Ordering::Relaxed) == -EINTR as u64, 123);
    expect(INTR_HITS.load(Ordering::Relaxed) == 1, 124);
    expect(call1(sys::CLOSE, r) == 0 && call1(sys::CLOSE, w) == 0, 124);

    // 125–127: a child writing to a pipe no one reads is ended by SIGPIPE's default action; its
    // end sends this process SIGCHLD, and wait4 still reaps it and says which signal.
    expect(sigaction(SIGCHLD, on_chld as *const () as u64, SA_RESTART) == 0, 125);
    let [r, w] = pipe(125);
    expect(call1(sys::CLOSE, r) == 0, 125);
    let child = sys::fork();
    expect(child >= 0, 125);
    if child == 0 {
        sys::call(sys::WRITE, [w, b"x".as_ptr() as u64, 1, 0, 0, 0]);
        exit(125)
    }
    let status = wait_child(child, 125);
    expect(status == SIGPIPE as u32, if status == 125 << 8 { 125 } else { 126 });
    expect(CHLD_HITS.load(Ordering::Relaxed) == 1, 127);
    expect(call1(sys::CLOSE, w) == 0, 127);
    expect(sigaction(SIGCHLD, SIG_DFL, 0) == 0, 127);

    // 128–130: SIGTERM's default action ends a child blocked in a read.
    let [r, w] = pipe(128);
    let child = sys::fork();
    expect(child >= 0, 128);
    if child == 0 {
        call1(sys::CLOSE, w);
        let mut b = [0u8; 1];
        sys::call(sys::READ, [r, b.as_mut_ptr() as u64, 1, 0, 0, 0]);
        exit(128)
    }
    expect(call1(sys::CLOSE, r) == 0, 128);
    for _ in 0..LINGER {
        yield_now();
    }
    expect(sys::call(sys::KILL, [child as u64, SIGTERM, 0, 0, 0, 0]) == 0, 128);
    let status = wait_child(child, 129);
    expect(status == SIGTERM as u32, 130);
    expect(call1(sys::CLOSE, w) == 0, 130);

    // 131–132: SIGKILL cannot be caught, and ends a child that tried.
    let child = sys::fork();
    expect(child >= 0, 131);
    if child == 0 {
        expect(sigaction(SIGKILL, usr2, 0) == -EINVAL, 131);
        loop {
            yield_now();
        }
    }
    for _ in 0..LINGER {
        yield_now();
    }
    expect(sys::call(sys::KILL, [child as u64, SIGKILL, 0, 0, 0, 0]) == 0, 132);
    let status = wait_child(child, 132);
    expect(status == SIGKILL as u32, if status == 131 << 8 { 131 } else { 132 });
    exit(SIGNALS_SUCCESS)
}

// ---- rtsig: real-time signals, queued ------------------------------------------------------

/// Exits with this when every step behaved; `kernel/main/src/personality/signals.rs` mirrors it.
const RTSIG_SUCCESS: u64 = 56;
/// Two real-time numbers. Real-time signals are 32 to 64 as the kernel numbers them, and
/// unlike the rest they queue: three sent are three delivered, in the order they were sent.
const SIGRT_A: u64 = 34;
const SIGRT_B: u64 = 35;
const SI_QUEUE: i32 = -1;
/// What the kernel queues per process. One more than this must be refused, not dropped.
const RT_DEPTH: usize = 8;

/// What each delivery was: the signal in the high word, its value in the low one.
static RT_SEEN: [AtomicU64; RT_DEPTH] = [const { AtomicU64::new(0) }; RT_DEPTH];
static RT_HITS: AtomicU64 = AtomicU64::new(0);
/// The `si_code` of the first delivery, which must say a queued signal.
static RT_CODE: AtomicU64 = AtomicU64::new(0);

/// A `siginfo` for `rt_sigqueueinfo`: the signal, `SI_QUEUE`, this process's pid, and the value.
fn queued_info(sig: u64, pid: u64, value: u64) -> [u8; 128] {
    let mut info = [0u8; 128];
    info[0..4].copy_from_slice(&(sig as u32).to_le_bytes());
    info[8..12].copy_from_slice(&SI_QUEUE.to_le_bytes());
    info[16..20].copy_from_slice(&(pid as u32).to_le_bytes());
    info[24..32].copy_from_slice(&value.to_le_bytes());
    info
}

fn rt_queue(pid: u64, sig: u64, value: u64) -> i64 {
    let info = queued_info(sig, pid, value);
    sys::call(sys::RT_SIGQUEUEINFO, [pid, sig, info.as_ptr() as u64, 0, 0, 0])
}

extern "C" fn on_rt(sig: i32, info: *const u8, _uc: *const u8) {
    let n = RT_HITS.fetch_add(1, Ordering::Relaxed) as usize;
    // SAFETY: the kernel pushed a `siginfo` whose `si_code` is at 8 and whose `si_value`, for a
    // queued signal, is at 24.
    let (code, value) = unsafe {
        (
            core::ptr::read_unaligned(info.add(8) as *const i32),
            core::ptr::read_unaligned(info.add(24) as *const u64),
        )
    };
    if n == 0 {
        RT_CODE.store(code as i64 as u64, Ordering::Relaxed);
    }
    if let Some(slot) = RT_SEEN.get(n) {
        slot.store(((sig as u64) << 32) | (value & 0xffff_ffff), Ordering::Relaxed);
    }
}

fn rtsig() -> ! {
    let pid = sys::call(sys::GETPID, [0; 6]) as u64;
    let handler = on_rt as *const () as u64;

    // 250: a real-time signal takes a handler like any other.
    expect(sigaction(SIGRT_A, handler, SA_SIGINFO) == 0, 240);
    expect(sigaction(SIGRT_B, handler, SA_SIGINFO) == 0, 240);

    // 251-253: with both blocked, three of one number and one of the other are queued. Nothing
    // runs yet, so what arrives later is what the queue kept, in the order it kept it.
    expect(sigprocmask(SIG_BLOCK, bit(SIGRT_A) | bit(SIGRT_B)) == 0, 241);
    for value in 1..=3u64 {
        expect(rt_queue(pid, SIGRT_A, value) == 0, 242);
    }
    expect(rt_queue(pid, SIGRT_B, 9) == 0, 243);
    expect(RT_HITS.load(Ordering::Relaxed) == 0, 243);

    // 254: both numbers are pending while they are blocked.
    let mut pending = 0u64;
    let asked = sys::call(sys::RT_SIGPENDING, [&raw mut pending as u64, 8, 0, 0, 0, 0]);
    expect(asked == 0 && pending & bit(SIGRT_A) != 0 && pending & bit(SIGRT_B) != 0, 244);

    // 255: the queue fills, and one more is refused rather than dropped on the floor.
    let mut queued = 4;
    while queued < RT_DEPTH {
        expect(rt_queue(pid, SIGRT_B, 100 + queued as u64) == 0, 245);
        queued += 1;
    }
    expect(rt_queue(pid, SIGRT_B, 200) == -EAGAIN, 245);

    // 256-259: unblocked, every one queued is delivered — the lower number first, and within a
    // number in the order it was queued.
    expect(sigprocmask(SIG_UNBLOCK, bit(SIGRT_A) | bit(SIGRT_B)) == 0, 246);
    expect(RT_HITS.load(Ordering::Relaxed) == RT_DEPTH as u64, 247);
    for (i, expected) in [
        (SIGRT_A, 1u64),
        (SIGRT_A, 2),
        (SIGRT_A, 3),
        (SIGRT_B, 9),
        (SIGRT_B, 104),
        (SIGRT_B, 105),
        (SIGRT_B, 106),
        (SIGRT_B, 107),
    ]
    .iter()
    .enumerate()
    {
        let seen = RT_SEEN[i].load(Ordering::Relaxed);
        expect(seen == ((expected.0 << 32) | expected.1), 248);
    }
    expect(RT_CODE.load(Ordering::Relaxed) == SI_QUEUE as i64 as u64, 249);
    exit(RTSIG_SUCCESS)
}

// ---- faults: a handler from an interrupt, and handlers for a program's own faults ---------

/// Exits with this when every step behaved; `kernel/main/src/personality/signals.rs` mirrors it.
const FAULTS_SUCCESS: u64 = 54;
const SIGSEGV: u64 = 11;

static SPIN_HITS: AtomicU64 = AtomicU64::new(0);
static SPIN_READY: AtomicU64 = AtomicU64::new(0);
static SPIN_TID: AtomicU32 = AtomicU32::new(u32::MAX);
static SEGV_HITS: AtomicU64 = AtomicU64::new(0);
static SEGV_ADDR: AtomicU64 = AtomicU64::new(0);
static ARITH_HITS: AtomicU64 = AtomicU64::new(0);

extern "C" fn on_spin(_sig: i32) {
    SPIN_HITS.fetch_add(1, Ordering::Relaxed);
}

/// The thread [`faults`] signals: it spins in user mode and makes no system call at all, so
/// nothing but an interrupt can deliver to it.
extern "C" fn spinner() -> u64 {
    SPIN_READY.store(1, Ordering::Release);
    while SPIN_HITS.load(Ordering::Relaxed) == 0 {
        core::hint::spin_loop();
    }
    0
}

/// `SIGSEGV`: `si_addr` names the address that faulted. Returning would run the store again,
/// so the handler steps over it through the saved program counter, as [`on_arith`] does — and
/// that the thread comes back at all is what proves the frame holds the context the fault was
/// taken with.
extern "C" fn on_segv(_sig: i32, info: *const u64, uc: *mut u8) {
    SEGV_HITS.fetch_add(1, Ordering::Relaxed);
    // SAFETY: the `siginfo` the kernel pushed; `si_addr` is its third word.
    let addr = unsafe { *info.add(2) };
    SEGV_ADDR.store(addr, Ordering::Relaxed);
    // SAFETY: as in `on_arith`: the `ucontext`'s saved program counter.
    unsafe { uc.add(sys::UC_PC).cast::<u64>().write(sys::after_store()) };
}

/// The architecture's arithmetic trap. Returning would run the instruction again, so the
/// handler steps over it by pointing the saved program counter past it — which is also what
/// proves the frame's program counter is where the kernel says it is.
extern "C" fn on_arith(_sig: i32, _info: *const u64, uc: *mut u8) {
    ARITH_HITS.fetch_add(1, Ordering::Relaxed);
    // SAFETY: `uc` is the `ucontext` the kernel pushed, whose `sigcontext` keeps the program
    // counter at this architecture's fixed offset.
    unsafe { uc.add(sys::UC_PC).cast::<u64>().write(sys::after_arith()) };
}

fn faults() -> ! {
    let pid = sys::call(sys::GETPID, [0; 6]) as u64;

    // 210–212: a thread that only spins runs its handler. Its signal cannot wait for a system
    // call, because it makes none: the timer interrupt that finds it is the delivery.
    expect(sigaction(SIGUSR1, on_spin as *const () as u64, 0) == 0, 210);
    let stack = map(4 * PAGE);
    let block = map(PAGE);
    expect(stack > 0 && block > 0, 210);
    let mut parent_tid = 0u32;
    let tid = sys::clone_thread(
        (stack as u64) + 4 * PAGE,
        &raw mut parent_tid,
        SPIN_TID.as_ptr(),
        block as u64,
        spinner,
    );
    expect(tid > 0, 211);
    while SPIN_READY.load(Ordering::Acquire) == 0 {
        yield_now();
    }
    for _ in 0..LINGER {
        yield_now();
    }
    expect(sys::call(sys::TGKILL, [pid, tid as u64, SIGUSR1, 0, 0, 0]) == 0, 211);
    join(&SPIN_TID, 212);
    expect(SPIN_HITS.load(Ordering::Relaxed) == 1, 212);

    // 213–216: a store to an address with no mapping raises SIGSEGV; `si_addr` names exactly
    // the address, and the handler steps over the store so the thread carries on.
    let spare = map(PAGE);
    expect(spare > 0, 213);
    let gone = spare as u64;
    expect(sys::call(sys::MUNMAP, [gone, PAGE, 0, 0, 0, 0]) == 0, 213);
    expect(sigaction(SIGSEGV, on_segv as *const () as u64, SA_SIGINFO) == 0, 214);
    // The store faults; the handler sends the thread to the instruction after it.
    sys::bad_store(gone);
    expect(SEGV_HITS.load(Ordering::Relaxed) == 1, 215);
    expect(SEGV_ADDR.load(Ordering::Relaxed) == gone, 216);

    // 217–218: the architecture's arithmetic trap — a division by zero on x86_64, an
    // undefined instruction on aarch64 — raises its signal, and the handler steps over it.
    expect(sigaction(sys::ARITH_SIG, on_arith as *const () as u64, SA_SIGINFO) == 0, 217);
    sys::raise_arith();
    expect(ARITH_HITS.load(Ordering::Relaxed) == 1, 218);

    // 219: both dispositions go back to the default, which is also the last proof that the
    // process is still its own after three handlers.
    expect(sigaction(SIGSEGV, SIG_DFL, 0) == 0, 219);
    expect(sigaction(sys::ARITH_SIG, SIG_DFL, 0) == 0, 219);
    exit(FAULTS_SUCCESS)
}

// ---- tcp and serve: sockets ---------------------------------------------------------------

const TCP_SUCCESS: u64 = 48;
const SERVE_SUCCESS: u64 = 49;

const AF_INET: u64 = 2;
const AF_INET6: u64 = 10;
const SOCK_STREAM: u64 = 1;
const SOCK_NONBLOCK: u64 = 0o4000;
const SOCK_CLOEXEC: u64 = 0o2000000;
const SOL_SOCKET: u64 = 1;
const SO_REUSEADDR: u64 = 2;
const SO_TYPE: u64 = 3;
const SO_ERROR: u64 = 4;
const IPPROTO_TCP: u64 = 6;
const TCP_NODELAY: u64 = 1;
const MSG_DONTWAIT: u64 = 0x40;
const MSG_NOSIGNAL: u64 = 0x4000;
const SHUT_RD: u64 = 0;

const EAGAIN: i64 = 11;
const ENOTSOCK: i64 = 88;
const EOPNOTSUPP: i64 = 95;
const EAFNOSUPPORT: i64 = 97;
const EISCONN: i64 = 106;
const ENOTCONN: i64 = 107;
const EALREADY: i64 = 114;
const EINPROGRESS: i64 = 115;

/// QEMU's gateway, through which kbuild is reached, and the machine's own address; mirror
/// `GATEWAY` and `CONFIG` in `kernel/main/src/net.rs`.
const GATEWAY: [u8; 4] = [10, 0, 2, 2];
const OURS: [u8; 4] = [10, 0, 2, 15];
/// The port `serve` listens on, which kbuild forwards a loopback port to; mirrors
/// `INBOUND_PORT` in `kernel/main/src/personality/socket.rs`.
const INBOUND_PORT: u16 = 7777;
/// kbuild's protocols: `kbuild/src/qemu.rs`.
const REQUEST: &[u8] = b"kintane-tcp-request peer-closes linux\n";
const REPLY: &[u8] = b"kintane-tcp-reply peer-closes linux\n";
const NB_REQUEST: &[u8] = b"kintane-tcp-request peer-closes linux-nonblocking\n";
const NB_REPLY: &[u8] = b"kintane-tcp-reply peer-closes linux-nonblocking\n";
const INBOUND: &[u8] = b"kintane-tcp-inbound ";
const INBOUND_REPLY: &[u8] = b"kintane-tcp-inbound-reply ";
const INBOUND_VERIFIED: &[u8] = b"kintane-tcp-inbound-verified ";

/// Tries a non-blocking `connect` gets to see its connection established, and a non-blocking
/// read to see its reply arrive.
const CONNECT_TRIES: u32 = 2_000_000;

/// The port `serve`'s second thread listens on, which nobody connects to; its listener; and the
/// thread's tid word and whether it has started.
const IDLE_PORT: u16 = 7778;
static IDLE_LISTENER: AtomicU64 = AtomicU64::new(0);
static IDLE_TID: AtomicU32 = AtomicU32::new(u32::MAX);
static IDLE_STARTED: AtomicU32 = AtomicU32::new(0);

/// `ip`:`port` as a `struct sockaddr_in`.
fn sockaddr(ip: [u8; 4], port: u16) -> [u8; 16] {
    let p = port.to_be_bytes();
    let mut a = [0u8; 16];
    for (to, from) in a
        .iter_mut()
        .zip([AF_INET as u8, 0, p[0], p[1], ip[0], ip[1], ip[2], ip[3]])
    {
        *to = from;
    }
    a
}

fn socket(kind: u64) -> i64 {
    sys::call(sys::SOCKET, [AF_INET, kind, 0, 0, 0, 0])
}

fn connect(fd: u64, ip: [u8; 4], port: u16) -> i64 {
    let a = sockaddr(ip, port);
    sys::call(sys::CONNECT, [fd, a.as_ptr() as u64, a.len() as u64, 0, 0, 0])
}

fn set_opt(fd: u64, level: u64, option: u64, value: u32) -> i64 {
    sys::call(sys::SETSOCKOPT, [fd, level, option, &raw const value as u64, 4, 0])
}

fn get_opt(fd: u64, level: u64, option: u64) -> Option<u32> {
    let mut value = 0u32;
    let mut len = 4u32;
    let r = sys::call(
        sys::GETSOCKOPT,
        [
            fd,
            level,
            option,
            &raw mut value as u64,
            &raw mut len as u64,
            0,
        ],
    );
    (r == 0 && len == 4).then_some(value)
}

/// `getsockname` or `getpeername`, as an address and a port.
fn name(nr: u64, fd: u64) -> Option<([u8; 4], u16)> {
    let mut a = [0u8; 16];
    let mut len = a.len() as u32;
    let r = sys::call(nr, [fd, a.as_mut_ptr() as u64, &raw mut len as u64, 0, 0, 0]);
    (r == 0 && len == 16 && a[0] == AF_INET as u8)
        .then_some(([a[4], a[5], a[6], a[7]], u16::from_be_bytes([a[2], a[3]])))
}

/// A port in decimal, or 0.
fn decimal(digits: &[u8]) -> u16 {
    let mut n: u32 = 0;
    for &d in digits {
        if !d.is_ascii_digit() || n > u32::from(u16::MAX) {
            return 0;
        }
        n = n * 10 + u32::from(d - b'0');
    }
    u16::try_from(n).unwrap_or(0)
}

// ---- udp: datagram sockets -----------------------------------------------------------------

const UDP_SUCCESS: u64 = 52;

const SOCK_DGRAM: u64 = 2;
const IPPROTO_UDP: u64 = 17;
const SO_BROADCAST: u64 = 6;
const SO_RCVTIMEO: u64 = 20;
const MSG_TRUNC: u64 = 0x20;
const EMSGSIZE: i64 = 90;
const ENOPROTOOPT: i64 = 92;
const EPROTONOSUPPORT: i64 = 93;

/// kbuild's datagram protocol, in `kbuild/src/qemu.rs`. The tag is this program's, so a reply
/// to it is not one to `user/udp-client`'s request.
const UDP_REQUEST: &[u8] = b"kintane-udp-request linux";
const UDP_REPLY: &[u8] = b"kintane-udp-reply linux";
/// The largest datagram the kernel carries; one byte more is `EMSGSIZE`. Mirrors
/// `sockets::MAX_DATAGRAM`.
const MAX_DATAGRAM: usize = 256;

/// Send `bytes` on `fd`, to `to` or to whatever it connected to.
fn send_to(fd: u64, bytes: &[u8], to: Option<([u8; 4], u16)>, flags: u64) -> i64 {
    let (at, len) = match to {
        Some((ip, port)) => (sockaddr(ip, port), 16u64),
        None => ([0u8; 16], 0),
    };
    let address = if len == 0 { 0 } else { at.as_ptr() as u64 };
    sys::call(
        sys::SENDTO,
        [
            fd,
            bytes.as_ptr() as u64,
            bytes.len() as u64,
            flags,
            address,
            len,
        ],
    )
}

/// Take a datagram on `fd`, and where it came from.
fn recv_from(fd: u64, buf: &mut [u8], flags: u64) -> (i64, Option<([u8; 4], u16)>) {
    let mut a = [0u8; 16];
    let mut len = a.len() as u32;
    let n = sys::call(
        sys::RECVFROM,
        [
            fd,
            buf.as_mut_ptr() as u64,
            buf.len() as u64,
            flags,
            a.as_mut_ptr() as u64,
            &raw mut len as u64,
        ],
    );
    let from = (len == 16 && a[0] == AF_INET as u8)
        .then_some(([a[4], a[5], a[6], a[7]], u16::from_be_bytes([a[2], a[3]])));
    (n, from)
}

/// A `struct msghdr` naming one buffer, and `to` when it names an address.
fn msghdr(address: &[u8; 16], to: bool, vector: &[u8; 16]) -> [u8; 56] {
    let mut h = [0u8; 56];
    let name = if to { address.as_ptr() as u64 } else { 0 };
    let name_len: u64 = if to { 16 } else { 0 };
    h[0..8].copy_from_slice(&name.to_le_bytes());
    h[8..16].copy_from_slice(&name_len.to_le_bytes());
    h[16..24].copy_from_slice(&(vector.as_ptr() as u64).to_le_bytes());
    h[24..32].copy_from_slice(&1u64.to_le_bytes());
    h
}

/// A `struct msghdr` naming `count` buffers at `iov`, and `to` when it names an address.
fn msghdr_n(address: &[u8; 16], to: bool, iov: u64, count: u64) -> [u8; 56] {
    let mut h = [0u8; 56];
    let name = if to { address.as_ptr() as u64 } else { 0 };
    let name_len: u64 = if to { 16 } else { 0 };
    h[0..8].copy_from_slice(&name.to_le_bytes());
    h[8..16].copy_from_slice(&name_len.to_le_bytes());
    h[16..24].copy_from_slice(&iov.to_le_bytes());
    h[24..32].copy_from_slice(&count.to_le_bytes());
    h
}

/// A `struct iovec` over `bytes`.
fn iovec(base: u64, len: u64) -> [u8; 16] {
    let mut v = [0u8; 16];
    v[0..8].copy_from_slice(&base.to_le_bytes());
    v[8..16].copy_from_slice(&len.to_le_bytes());
    v
}

/// How long a receive waits before `EAGAIN`, as a `struct timeval`.
fn set_timeout(fd: u64, option: u64, micros: u64) -> i64 {
    let mut tv = [0u8; 16];
    tv[0..8].copy_from_slice(&(micros / 1_000_000).to_le_bytes());
    tv[8..16].copy_from_slice(&(micros % 1_000_000).to_le_bytes());
    sys::call(sys::SETSOCKOPT, [fd, SOL_SOCKET, option, tv.as_ptr() as u64, 16, 0])
}

/// The two ports the kernel passes as `<service>,<quiet>`.
fn two_ports(arg: &[u8]) -> (u16, u16) {
    let mut at = 0;
    while at < arg.len() && arg.get(at) != Some(&b',') {
        at += 1;
    }
    let service = decimal(arg.get(..at).unwrap_or(&[]));
    let quiet = decimal(arg.get(at + 1..).unwrap_or(&[]));
    (service, quiet)
}

// ---- peek: looking without taking, and messages of several buffers ------------------------

const PEEK_SUCCESS: u64 = 59;
const MSG_PEEK: u64 = 0x2;
const MSG_WAITALL: u64 = 0x100;

/// Buffers one `sendmsg` or `recvmsg` may name, which the personality bounds.
const MAX_IOV: usize = 4;

/// `peek <service>,<tcp>`: what `MSG_PEEK` leaves behind, what `MSG_WAITALL` waits for, and
/// messages spread over several buffers.
fn peek_mode(ports: &[u8]) -> ! {
    let (service, tcp_port) = two_ports(ports);
    // 220: the ports the kernel passed, and a datagram socket connected to kbuild's service.
    expect(service != 0 && tcp_port != 0, 220);
    let fd = socket(SOCK_DGRAM | SOCK_CLOEXEC);
    expect(fd >= 3, 220);
    let fd = fd as u64;
    expect(connect(fd, GATEWAY, service) == 0, 220);
    expect(set_timeout(fd, SO_RCVTIMEO, 2_000_000) == 0, 220);

    // 221: a peeked datagram stays. Two peeks answer the same bytes, and the receive after
    //      them answers those bytes again.
    expect(send_to(fd, UDP_REQUEST, None, 0) == UDP_REQUEST.len() as i64, 221);
    let mut first = [0u8; 64];
    let (a, _) = recv_from(fd, &mut first, MSG_PEEK);
    expect(a == UDP_REPLY.len() as i64, 221);
    expect(first.get(..a as usize) == Some(UDP_REPLY), 221);
    let mut second = [0u8; 64];
    let (b, _) = recv_from(fd, &mut second, MSG_PEEK);
    expect(b == a && second.get(..b as usize) == Some(UDP_REPLY), 221);
    let mut taken = [0u8; 64];
    let (c, _) = recv_from(fd, &mut taken, 0);
    expect(c == a && taken.get(..c as usize) == Some(UDP_REPLY), 222);

    // 223: and it was one datagram, not several: nothing is left to take.
    let mut empty = [0u8; 64];
    expect(recv_from(fd, &mut empty, 0).0 == -EAGAIN, 223);

    // 224: peeking into a short buffer answers what fits, and with MSG_TRUNC what the datagram
    //      had; the datagram is still there afterwards, because neither took it.
    expect(send_to(fd, UDP_REQUEST, None, 0) == UDP_REQUEST.len() as i64, 224);
    let mut small = [0u8; 4];
    let (fit, _) = recv_from(fd, &mut small, MSG_PEEK);
    expect(fit == small.len() as i64, 224);
    let (whole, _) = recv_from(fd, &mut small, MSG_PEEK | MSG_TRUNC);
    expect(whole == UDP_REPLY.len() as i64, 224);
    let (after, _) = recv_from(fd, &mut first, 0);
    expect(after == UDP_REPLY.len() as i64, 224);

    // 225: one datagram gathered from two buffers, and the reply scattered into two.
    let (head, tail) = UDP_REQUEST.split_at(8);
    let out = [
        iovec(head.as_ptr() as u64, head.len() as u64),
        iovec(tail.as_ptr() as u64, tail.len() as u64),
    ];
    let address = [0u8; 16];
    let header = msghdr_n(&address, false, out.as_ptr() as u64, 2);
    expect(
        sys::call(sys::SENDMSG, [fd, header.as_ptr() as u64, 0, 0, 0, 0])
            == UDP_REQUEST.len() as i64,
        225,
    );
    let mut part1 = [0u8; 6];
    let mut part2 = [0u8; 64];
    let back = [
        iovec(part1.as_mut_ptr() as u64, part1.len() as u64),
        iovec(part2.as_mut_ptr() as u64, part2.len() as u64),
    ];
    let mut in_header = msghdr_n(&address, false, back.as_ptr() as u64, 2);
    let n = sys::call(sys::RECVMSG, [fd, in_header.as_mut_ptr() as u64, 0, 0, 0, 0]);
    expect(n == UDP_REPLY.len() as i64, 225);
    // 226: the reply really is spread over both, in order, not crammed into the first.
    expect(part1.as_slice() == UDP_REPLY.get(..6).unwrap_or(&[]), 226);
    let rest = UDP_REPLY.len() - part1.len();
    expect(part2.get(..rest) == UDP_REPLY.get(part1.len()..), 226);

    // 227: more buffers than the personality carries is refused, not half sent.
    let many = [iovec(first.as_ptr() as u64, 1); MAX_IOV + 1];
    let too_many = msghdr_n(&address, false, many.as_ptr() as u64, many.len() as u64);
    expect(
        sys::call(sys::SENDMSG, [fd, too_many.as_ptr() as u64, 0, 0, 0, 0]) == -EOPNOTSUPP,
        227,
    );
    expect(call1(sys::CLOSE, fd) == 0, 227);

    // 228: a stream peek leaves the bytes in the ring, and MSG_WAITALL waits for the whole
    //      reply rather than the first segment of it.
    let s = socket(SOCK_STREAM | SOCK_CLOEXEC);
    expect(s >= 3, 228);
    let s = s as u64;
    expect(connect(s, GATEWAY, tcp_port) == 0, 228);
    expect(set_timeout(s, SO_RCVTIMEO, 4_000_000) == 0, 228);
    let len = REQUEST.len() as u64;
    expect(
        sys::call(sys::SENDTO, [s, REQUEST.as_ptr() as u64, len, 0, 0, 0]) == len as i64,
        228,
    );
    let mut peeked = [0u8; 64];
    let want = REPLY.len();
    let (got, _) = recv_from(s, &mut peeked[..want], MSG_PEEK | MSG_WAITALL);
    expect(got == want as i64, 228);
    expect(peeked.get(..want) == Some(REPLY), 228);
    // 229: and the receive after it reads those same bytes, because the peek took none.
    let mut read_back = [0u8; 64];
    let (again, _) = recv_from(s, &mut read_back[..want], MSG_WAITALL);
    expect(again == want as i64, 229);
    expect(read_back.get(..want) == Some(REPLY), 229);
    expect(call1(sys::CLOSE, s) == 0, 229);
    exit(PEEK_SUCCESS)
}

fn udp(ports: &[u8]) -> ! {
    let (service, quiet) = two_ports(ports);
    // 170: the ports the kernel passed, and a datagram socket of the type asked for.
    expect(service != 0 && quiet != 0, 170);
    let fd = socket(SOCK_DGRAM | SOCK_CLOEXEC);
    expect(fd >= 3, 170);
    let fd = fd as u64;
    expect(get_opt(fd, SOL_SOCKET, SO_TYPE) == Some(SOCK_DGRAM as u32), 170);
    // UDP named outright is the same socket as protocol 0; another protocol is not.
    let named = sys::call(sys::SOCKET, [AF_INET, SOCK_DGRAM, IPPROTO_UDP, 0, 0, 0]);
    expect(named >= 3, 170);
    expect(call1(sys::CLOSE, named as u64) == 0, 170);
    expect(
        sys::call(sys::SOCKET, [AF_INET, SOCK_DGRAM, IPPROTO_TCP, 0, 0, 0]) == -EPROTONOSUPPORT,
        170,
    );

    // 171: with nowhere to send and no address given, there is nothing to do but refuse.
    expect(send_to(fd, UDP_REQUEST, None, 0) == -ENOTCONN, 171);

    // 172: a request to kbuild's service, and the reply, which names where it came from.
    let mut buf = [0u8; 128];
    expect(
        send_to(fd, UDP_REQUEST, Some((GATEWAY, service)), 0) == UDP_REQUEST.len() as i64,
        172,
    );
    let (n, from) = recv_from(fd, &mut buf, 0);
    expect(n == UDP_REPLY.len() as i64, 172);
    expect(buf.get(..n as usize) == Some(UDP_REPLY), 172);
    expect(from == Some((GATEWAY, service)), 172);

    // 173: into four bytes, what is answered is what fit; with MSG_TRUNC, what the datagram had.
    let mut small = [0u8; 4];
    expect(
        send_to(fd, UDP_REQUEST, Some((GATEWAY, service)), 0) == UDP_REQUEST.len() as i64,
        173,
    );
    let (fit, _) = recv_from(fd, &mut small, 0);
    expect(fit == small.len() as i64, 173);
    expect(
        send_to(fd, UDP_REQUEST, Some((GATEWAY, service)), 0) == UDP_REQUEST.len() as i64,
        173,
    );
    let (whole, _) = recv_from(fd, &mut small, MSG_TRUNC);
    expect(whole == UDP_REPLY.len() as i64, 173);

    // 174: a datagram past what the stack carries is EMSGSIZE, not a short send.
    let big = [b'x'; MAX_DATAGRAM + 1];
    expect(send_to(fd, &big, Some((GATEWAY, service)), 0) == -EMSGSIZE, 174);

    // 175: a receive with nothing to take waits its timeout and then answers EAGAIN.
    expect(set_timeout(fd, SO_RCVTIMEO, 200_000) == 0, 175);
    let (waited, _) = recv_from(fd, &mut buf, 0);
    expect(waited == -EAGAIN, 175);

    // 176: broadcasting is not offered, and a program that asks is told so.
    expect(set_opt(fd, SOL_SOCKET, SO_BROADCAST, 1) == -ENOPROTOOPT, 176);

    // 177: nothing connects to a datagram socket, and it has no half to shut.
    expect(sys::call(sys::LISTEN, [fd, 1, 0, 0, 0, 0]) == -EOPNOTSUPP, 177);
    expect(sys::call(sys::SHUTDOWN, [fd, SHUT_RD, 0, 0, 0, 0]) == -EOPNOTSUPP, 177);
    expect(call1(sys::CLOSE, fd) == 0, 177);

    // 178: a connected datagram socket sends and receives without naming an address, and both
    //      names agree with what it connected to.
    let c = socket(SOCK_DGRAM);
    expect(c >= 3, 178);
    let c = c as u64;
    expect(connect(c, GATEWAY, service) == 0, 178);
    expect(name(sys::GETPEERNAME, c) == Some((GATEWAY, service)), 178);
    expect(matches!(name(sys::GETSOCKNAME, c), Some((OURS, p)) if p != 0), 178);
    expect(send_to(c, UDP_REQUEST, None, 0) == UDP_REQUEST.len() as i64, 178);
    let (n, _) = recv_from(c, &mut buf, 0);
    expect(buf.get(..n.max(0) as usize) == Some(UDP_REPLY), 178);

    // 179: the same round trip through sendmsg and recvmsg, one buffer each.
    let address = sockaddr(GATEWAY, service);
    let out = iovec(UDP_REQUEST.as_ptr() as u64, UDP_REQUEST.len() as u64);
    let header = msghdr(&address, false, &out);
    expect(
        sys::call(sys::SENDMSG, [c, header.as_ptr() as u64, 0, 0, 0, 0])
            == UDP_REQUEST.len() as i64,
        179,
    );
    let mut got = [0u8; 128];
    let back = iovec(got.as_mut_ptr() as u64, got.len() as u64);
    let mut in_header = msghdr(&address, true, &back);
    let n = sys::call(sys::RECVMSG, [c, in_header.as_mut_ptr() as u64, 0, 0, 0, 0]);
    expect(n == UDP_REPLY.len() as i64, 179);
    expect(got.get(..n.max(0) as usize) == Some(UDP_REPLY), 179);

    // 180: connected to the port nobody listens on, a reply from the service is not this
    //      socket's to take: it waits its timeout and answers EAGAIN.
    let elsewhere = socket(SOCK_DGRAM);
    expect(elsewhere >= 3, 180);
    let elsewhere = elsewhere as u64;
    expect(connect(elsewhere, GATEWAY, quiet) == 0, 180);
    expect(set_timeout(elsewhere, SO_RCVTIMEO, 500_000) == 0, 180);
    expect(
        send_to(elsewhere, UDP_REQUEST, Some((GATEWAY, service)), 0) == UDP_REQUEST.len() as i64,
        180,
    );
    let (refused, _) = recv_from(elsewhere, &mut buf, 0);
    expect(refused == -EAGAIN, 180);
    expect(call1(sys::CLOSE, elsewhere) == 0, 180);
    expect(call1(sys::CLOSE, c) == 0, 180);
    exit(UDP_SUCCESS)
}

/// Write all of `bytes` to `fd`.
fn write_all(fd: u64, bytes: &[u8]) -> bool {
    let mut done = 0;
    while let Some(rest) = bytes.get(done..) {
        if rest.is_empty() {
            return true;
        }
        let n = sys::call(sys::WRITE, [fd, rest.as_ptr() as u64, rest.len() as u64, 0, 0, 0]);
        if n <= 0 {
            return false;
        }
        done += n as usize;
    }
    false
}

/// Read one line from `fd` into `line`, a byte at a time so nothing after it is taken. Its
/// length, newline included; short at the end of the stream or an error.
fn read_line(fd: u64, line: &mut [u8]) -> usize {
    let mut n = 0;
    while let Some(byte) = line.get_mut(n) {
        if sys::call(sys::READ, [fd, byte as *mut u8 as u64, 1, 0, 0, 0]) != 1 {
            break;
        }
        n += 1;
        if *byte == b'\n' {
            break;
        }
    }
    n
}

/// `a` then `b` into `buf`. The length written.
fn concat(buf: &mut [u8], a: &[u8], b: &[u8]) -> usize {
    let mut n = 0;
    for (to, &from) in buf.iter_mut().zip(a.iter().chain(b)) {
        *to = from;
        n += 1;
    }
    n
}

fn tcp(port_arg: &[u8]) -> ! {
    // 110: kbuild's port, as the kernel passed it.
    let port = decimal(port_arg);
    expect(port != 0, 110);
    // 111: only IPv4: another family is EAFNOSUPPORT.
    expect(
        sys::call(sys::SOCKET, [AF_INET6, SOCK_STREAM, 0, 0, 0, 0]) == -EAFNOSUPPORT,
        111,
    );
    // 112: a socket, with an option a client sets, of the type asked for.
    let fd = socket(SOCK_STREAM | SOCK_CLOEXEC);
    expect(fd >= 3, 112);
    let fd = fd as u64;
    expect(set_opt(fd, IPPROTO_TCP, TCP_NODELAY, 1) == 0, 112);
    expect(get_opt(fd, SOL_SOCKET, SO_TYPE) == Some(SOCK_STREAM as u32), 112);
    // 113: a descriptor that is not a socket is ENOTSOCK.
    expect(connect(1, GATEWAY, port) == -ENOTSOCK, 113);
    // 114: sending before connecting is ENOTCONN.
    let len = REQUEST.len() as u64;
    expect(
        sys::call(sys::SENDTO, [fd, REQUEST.as_ptr() as u64, len, 0, 0, 0]) == -ENOTCONN,
        114,
    );
    // 115: connect, waiting for the handshake.
    expect(connect(fd, GATEWAY, port) == 0, 115);
    // 116: connecting a connected socket is EISCONN.
    expect(connect(fd, GATEWAY, port) == -EISCONN, 116);
    // 117: the names at both ends.
    expect(name(sys::GETPEERNAME, fd) == Some((GATEWAY, port)), 117);
    expect(matches!(name(sys::GETSOCKNAME, fd), Some((OURS, p)) if p != 0), 117);
    // 118: kbuild says nothing before a request, so a receive that must not wait is EAGAIN.
    let mut buf = [0u8; 128];
    let cap = buf.len() as u64;
    expect(
        sys::call(sys::RECVFROM, [fd, buf.as_mut_ptr() as u64, cap, MSG_DONTWAIT, 0, 0]) == -EAGAIN,
        118,
    );
    // 119: the request, with a flag a server sets.
    expect(
        sys::call(sys::SENDTO, [fd, REQUEST.as_ptr() as u64, len, MSG_NOSIGNAL, 0, 0])
            == len as i64,
        119,
    );
    // 120: the reply, through `read`, to the end of the stream: kbuild closes once it replied.
    let mut got = 0;
    loop {
        let Some(room) = buf.get_mut(got..) else {
            exit(120)
        };
        expect(!room.is_empty(), 120);
        let n = sys::call(sys::READ, [fd, room.as_mut_ptr() as u64, room.len() as u64, 0, 0, 0]);
        if n == 0 {
            break;
        }
        expect(n > 0, 120);
        got += n as usize;
    }
    expect(buf.get(..got) == Some(REPLY), 120);
    // 121: the receiving half alone cannot be shut down; the socket closes.
    expect(sys::call(sys::SHUTDOWN, [fd, SHUT_RD, 0, 0, 0, 0]) == -EOPNOTSUPP, 121);
    expect(call1(sys::CLOSE, fd) == 0, 121);

    // 122: a non-blocking socket's connect starts the handshake and returns at once.
    let nb = socket(SOCK_STREAM | SOCK_NONBLOCK);
    expect(nb >= 3, 122);
    let nb = nb as u64;
    expect(connect(nb, GATEWAY, port) == -EINPROGRESS, 122);
    // 123: again, EALREADY until the connection is established, then EISCONN.
    let mut established = false;
    for _ in 0..CONNECT_TRIES {
        let r = connect(nb, GATEWAY, port);
        if r == -EISCONN {
            established = true;
            break;
        }
        expect(r == -EALREADY, 123);
        yield_now();
    }
    expect(established, 123);
    // 124: no error pending, and nothing to read, which is EAGAIN rather than a wait.
    expect(get_opt(nb, SOL_SOCKET, SO_ERROR) == Some(0), 124);
    expect(sys::call(sys::READ, [nb, buf.as_mut_ptr() as u64, 8, 0, 0, 0]) == -EAGAIN, 124);
    // 125: a whole exchange without waiting: EAGAIN until the reply comes, then to kbuild's
    // close. kbuild closing first leaves no connection in TIME-WAIT, whose timer would wake
    // every waiter on the network, behind for `serve`'s second thread.
    expect(write_all(nb, NB_REQUEST), 125);
    let mut got = 0;
    let mut tries = 0;
    loop {
        let Some(room) = buf.get_mut(got..) else {
            exit(125)
        };
        expect(!room.is_empty() && tries < CONNECT_TRIES, 125);
        tries += 1;
        let n = sys::call(sys::READ, [nb, room.as_mut_ptr() as u64, room.len() as u64, 0, 0, 0]);
        if n == -EAGAIN {
            yield_now();
            continue;
        }
        if n == 0 {
            break;
        }
        expect(n > 0, 125);
        got += n as usize;
    }
    expect(buf.get(..got) == Some(NB_REPLY), 125);
    expect(call1(sys::CLOSE, nb) == 0, 126);
    exit(TCP_SUCCESS)
}

/// `serve`'s second thread: it waits in `accept` on a listener nobody connects to, and so must
/// be ended by its process's end, since nothing else will end the wait.
extern "C" fn idle_acceptor() -> u64 {
    IDLE_STARTED.store(1, Ordering::Release);
    let l = IDLE_LISTENER.load(Ordering::Acquire);
    sys::call(sys::ACCEPT4, [l, 0, 0, 0, 0, 0]);
    // 142: the wait ended while the process lived.
    exit(142)
}

fn serve() -> ! {
    // 141: a second thread, waiting in `accept` on port 7778, where nobody connects. When the
    // process ends below, no TCP timer is pending anywhere (every connection before this one was
    // closed by kbuild first), so only the process's end can end that wait, and the kernel's
    // check requires every thread of the process to have ended.
    let idle = socket(SOCK_STREAM);
    expect(idle >= 3, 141);
    let idle = idle as u64;
    let idle_at = sockaddr([0; 4], IDLE_PORT);
    expect(
        sys::call(sys::BIND, [idle, idle_at.as_ptr() as u64, idle_at.len() as u64, 0, 0, 0]) == 0
            && sys::call(sys::LISTEN, [idle, 1, 0, 0, 0, 0]) == 0,
        141,
    );
    IDLE_LISTENER.store(idle, Ordering::Release);
    let stack = map(4 * PAGE);
    let block = map(PAGE);
    expect(stack > 0 && block > 0, 141);
    let mut parent_tid = 0u32;
    let tid = sys::clone_thread(
        (stack as u64) + 4 * PAGE,
        &raw mut parent_tid,
        IDLE_TID.as_ptr(),
        block as u64,
        idle_acceptor,
    );
    expect(tid > 0, 141);
    while IDLE_STARTED.load(Ordering::Acquire) == 0 {
        yield_now();
    }

    // 130: a listener, on any of this machine's addresses, at the port kbuild forwards to.
    let l = socket(SOCK_STREAM);
    expect(l >= 3, 130);
    let l = l as u64;
    expect(set_opt(l, SOL_SOCKET, SO_REUSEADDR, 1) == 0, 130);
    let any = sockaddr([0; 4], INBOUND_PORT);
    expect(
        sys::call(sys::BIND, [l, any.as_ptr() as u64, any.len() as u64, 0, 0, 0]) == 0,
        131,
    );
    expect(sys::call(sys::LISTEN, [l, 1, 0, 0, 0, 0]) == 0, 132);
    expect(name(sys::GETSOCKNAME, l) == Some(([0; 4], INBOUND_PORT)), 133);
    // 134: accept, waiting for kbuild, which the kernel's check tells once this listens.
    let mut peer = [0u8; 16];
    let mut len = peer.len() as u32;
    let c = sys::call(
        sys::ACCEPT4,
        [
            l,
            peer.as_mut_ptr() as u64,
            &raw mut len as u64,
            SOCK_CLOEXEC,
            0,
            0,
        ],
    );
    expect(c >= 3, 134);
    let c = c as u64;
    // 135: the connection came in through QEMU's gateway.
    expect(
        len == 16 && peer[0] == AF_INET as u8 && peer.get(4..8) == Some(&GATEWAY[..]),
        135,
    );
    // 136: kbuild's request, and the tag it carries.
    let mut line = [0u8; 64];
    let n = read_line(c, &mut line);
    let Some(tag) = line.get(..n).and_then(|l| l.strip_prefix(INBOUND)) else {
        exit(136)
    };
    let mut tag_buf = [0u8; 32];
    let tag_len = concat(&mut tag_buf, tag, b"");
    let tag = tag_buf.get(..tag_len).unwrap_or(&[]);
    // 137: the reply.
    let mut reply = [0u8; 64];
    let r = concat(&mut reply, INBOUND_REPLY, tag);
    expect(write_all(c, reply.get(..r).unwrap_or(&[])), 137);
    // 138: kbuild checked the reply, and says so.
    let n = read_line(c, &mut line);
    let mut verified = [0u8; 64];
    let v = concat(&mut verified, INBOUND_VERIFIED, tag);
    expect(line.get(..n) == verified.get(..v), 138);
    // 139: then kbuild closes its end.
    expect(sys::call(sys::READ, [c, line.as_mut_ptr() as u64, 1, 0, 0, 0]) == 0, 139);
    // 140: both sockets close.
    expect(call1(sys::CLOSE, c) == 0, 140);
    expect(call1(sys::CLOSE, l) == 0, 140);
    // The second thread is still waiting in `accept`: the process's end has to end it.
    exit(SERVE_SUCCESS)
}

// ---- poll: waiting on several descriptors at once -------------------------------------------

const POLL_SUCCESS: u64 = 51;

/// `poll` events, as Linux numbers them.
const POLLIN: u16 = 0x001;
const POLLERR: u16 = 0x008;
const POLLHUP: u16 = 0x010;
const EPOLLIN: u32 = 0x001;
/// Edge-triggered, which this kernel refuses rather than pretending to offer.
const EPOLLET: u32 = 1 << 31;
const EPOLL_CTL_ADD: u64 = 1;

/// The port `poll_mode` listens on: the same one `serve` uses, which kbuild forwards to.
const POLL_PORT: u16 = INBOUND_PORT;
/// How long the wait that must run out is given.
const POLL_TIMEOUT_NS: u64 = 50_000_000;
/// Connections kbuild makes into this listener, one per number the kernel's check announces.
const POLL_CONNECTIONS: usize = 2;
/// Connections this mode holds at once, so an empty one QEMU made can be let go of and another
/// accepted in its place.
const POLL_SLOTS: usize = 4;
/// Empty connections tolerated before this is a failure rather than QEMU's port forward.
const POLL_EMPTY_MAX: usize = 8;

/// One `struct pollfd`, as the kernel reads it.
fn pollfd(buf: &mut [u8], at: usize, fd: u64, events: u16) {
    let fd = (fd as u32).to_le_bytes();
    let events = events.to_le_bytes();
    for (i, b) in fd.into_iter().chain(events).chain([0, 0]).enumerate() {
        if let Some(slot) = buf.get_mut(at * 8 + i) {
            *slot = b;
        }
    }
}

/// What an entry of a `pollfd` array was answered with.
fn revents(buf: &[u8], at: usize) -> u16 {
    let (lo, hi) = (buf.get(at * 8 + 6), buf.get(at * 8 + 7));
    match (lo, hi) {
        (Some(lo), Some(hi)) => u16::from_le_bytes([*lo, *hi]),
        _ => 0,
    }
}

/// Name `fd` in a `select` bitmap: least significant bit of the first byte is descriptor 0.
fn fd_set_bit(set: &mut [u8; 8], fd: u64) {
    if let Some(byte) = set.get_mut((fd / 8) as usize) {
        *byte |= 1 << (fd % 8);
    }
}

/// `pselect6`, and where the architecture has it `select`: wait for `fd` to be readable, with a
/// timeout. Both answer zero when nothing is ready, which is what this asks of them.
fn select_idle(fd: u64, timeout_ns: u64) -> (i64, Option<i64>) {
    let mut read = [0u8; 8];
    fd_set_bit(&mut read, fd);
    let nfds = fd + 1;
    // `pselect6` takes a `timespec` and a pointer to (mask, size), which is null here.
    let spec = [
        (timeout_ns / 1_000_000_000) as i64,
        (timeout_ns % 1_000_000_000) as i64,
    ];
    let mut copy = read;
    let p = sys::call(
        sys::PSELECT6,
        [
            nfds,
            copy.as_mut_ptr() as u64,
            0,
            0,
            spec.as_ptr() as u64,
            0,
        ],
    );
    // `select` takes a `timeval`: seconds and microseconds.
    let plain = sys::SELECT.map(|nr| {
        let tv = [
            (timeout_ns / 1_000_000_000) as i64,
            ((timeout_ns % 1_000_000_000) / 1_000) as i64,
        ];
        let mut copy = read;
        sys::call(nr, [nfds, copy.as_mut_ptr() as u64, 0, 0, tv.as_ptr() as u64, 0])
    });
    (p, plain)
}

/// `ppoll`: the form both architectures have. `timeout_ns` of `None` waits as long as it takes.
fn ppoll(fds: &mut [u8], n: usize, timeout_ns: Option<u64>) -> i64 {
    let spec = match timeout_ns {
        Some(ns) => [(ns / 1_000_000_000) as i64, (ns % 1_000_000_000) as i64],
        None => [0, 0],
    };
    let at = match timeout_ns {
        Some(_) => spec.as_ptr() as u64,
        None => 0,
    };
    sys::call(sys::PPOLL, [fds.as_mut_ptr() as u64, n as u64, at, 0, 8, 0])
}

/// Serve one connection kbuild made: read its request, reply, and read its verdict.
fn poll_serve(c: u64, step: u64) -> bool {
    let mut line = [0u8; 64];
    let n = read_line(c, &mut line);
    if n == 0 {
        return false;
    }
    let Some(tag) = line.get(..n).and_then(|l| l.strip_prefix(INBOUND)) else {
        exit(step)
    };
    let mut tag_buf = [0u8; 32];
    let tag_len = concat(&mut tag_buf, tag, b"");
    let tag = tag_buf.get(..tag_len).unwrap_or(&[]);
    let mut reply = [0u8; 64];
    let r = concat(&mut reply, INBOUND_REPLY, tag);
    expect(write_all(c, reply.get(..r).unwrap_or(&[])), step);
    let n = read_line(c, &mut line);
    let mut verified = [0u8; 64];
    let v = concat(&mut verified, INBOUND_VERIFIED, tag);
    expect(line.get(..n) == verified.get(..v), step + 1);
    true
}

/// Wait on a listener and its connections at once, serving whichever is ready, and then on
/// nothing that will ever be ready, which must run out. The kernel's check tells kbuild about
/// this listener twice, with a different number each time, so two connections come in.
fn poll_mode() -> ! {
    // 150: a listener at the port kbuild forwards to.
    let l = socket(SOCK_STREAM);
    expect(l >= 3, 150);
    let l = l as u64;
    expect(set_opt(l, SOL_SOCKET, SO_REUSEADDR, 1) == 0, 150);
    let any = sockaddr([0; 4], POLL_PORT);
    expect(
        sys::call(sys::BIND, [l, any.as_ptr() as u64, any.len() as u64, 0, 0, 0]) == 0
            && sys::call(sys::LISTEN, [l, 2, 0, 0, 0, 0]) == 0,
        151,
    );

    // 152-155: the listener and whatever has been accepted, all in one wait. Each pass serves
    // whichever is ready: a connection to accept, or a request to answer.
    let mut conns = [0u64; POLL_SLOTS];
    let mut done = [false; POLL_SLOTS];
    let mut accepted = 0;
    let mut served = 0;
    let mut empty = 0;
    while served < POLL_CONNECTIONS {
        let mut fds = [0u8; 8 * (POLL_SLOTS + 1)];
        pollfd(&mut fds, 0, l, POLLIN);
        let mut watched = 1;
        let mut i = 0;
        while i < accepted {
            if let Some(&c) = conns.get(i) {
                pollfd(&mut fds, watched, c, POLLIN);
                watched += 1;
            }
            i += 1;
        }
        let ready = ppoll(&mut fds, watched, None);
        expect(ready >= 1, 152);
        // The listener first: a connection waiting is one to accept.
        if revents(&fds, 0) & POLLIN != 0 && accepted < POLL_SLOTS {
            let c = sys::call(sys::ACCEPT4, [l, 0, 0, SOCK_CLOEXEC, 0, 0]);
            expect(c >= 3, 153);
            if let Some(slot) = conns.get_mut(accepted) {
                *slot = c as u64;
            }
            accepted += 1;
        }
        // Then every connection the wait says has a request, in the order they arrived.
        let mut i = 0;
        while i < accepted {
            let ready = revents(&fds, 1 + i) & (POLLIN | POLLHUP | POLLERR) != 0;
            let fresh = done.get(i) == Some(&false);
            if ready
                && fresh
                && let Some(&c) = conns.get(i)
            {
                if poll_serve(c, 154) {
                    served += 1;
                } else {
                    // Nothing on it: QEMU's port forward accepted before kbuild was there.
                    expect(call1(sys::CLOSE, c) == 0, 155);
                    empty += 1;
                    expect(empty <= POLL_EMPTY_MAX, 155);
                    if let Some(slot) = conns.get_mut(i) {
                        *slot = 0;
                    }
                }
                if let Some(slot) = done.get_mut(i) {
                    *slot = true;
                }
            }
            i += 1;
        }
    }
    expect(served == POLL_CONNECTIONS, 156);

    // 157: a wait for something that will not happen runs out, and not before its timeout.
    let mut idle = [0u8; 8];
    pollfd(&mut idle, 0, l, POLLIN);
    // How long it took is not measured here: this personality has no `clock_gettime`, so the
    // program cannot read a clock. That a timeout runs out on time, and not before, is what the
    // native check measures (`kernel/main/src/readiness/check.rs`).
    let ran_out = ppoll(&mut idle, 1, Some(POLL_TIMEOUT_NS));
    expect(ran_out == 0, 157);

    // 158: `pselect6`, and `select` where the architecture has it, over the same idle listener.
    let (pselect, select) = select_idle(l, POLL_TIMEOUT_NS);
    expect(pselect == 0, 158);
    expect(select.is_none_or(|n| n == 0), 158);

    // 159: `poll` itself, where the architecture has it: the listener is not ready either.
    if let Some(nr) = sys::POLL {
        let mut fds = [0u8; 8];
        pollfd(&mut fds, 0, l, POLLIN);
        expect(sys::call(nr, [fds.as_mut_ptr() as u64, 1, 0, 0, 0, 0]) == 0, 159);
    }

    // 160-163: `epoll`, over the two connections kbuild is closing, which must come back as
    // readable or hung up; and the flags this kernel refuses.
    let ep = sys::call(sys::EPOLL_CREATE1, [0, 0, 0, 0, 0, 0]);
    expect(ep >= 3, 160);
    let ep = ep as u64;
    let mut event = [0u8; 16];
    for (i, b) in EPOLLIN.to_le_bytes().into_iter().enumerate() {
        if let Some(slot) = event.get_mut(i) {
            *slot = b;
        }
    }
    let mut i = 0;
    while i < accepted {
        if let Some(&c) = conns.get(i)
            && c != 0
        {
            for (k, b) in (c as u64).to_le_bytes().into_iter().enumerate() {
                if let Some(slot) = event.get_mut(sys::EPOLL_DATA_AT + k) {
                    *slot = b;
                }
            }
            expect(
                sys::call(sys::EPOLL_CTL, [ep, EPOLL_CTL_ADD, c, event.as_ptr() as u64, 0, 0]) == 0,
                161,
            );
        }
        i += 1;
    }
    // 162: an edge-triggered interest is refused, rather than quietly made level-triggered.
    let mut edge = event;
    for (i, b) in (EPOLLIN | EPOLLET).to_le_bytes().into_iter().enumerate() {
        if let Some(slot) = edge.get_mut(i) {
            *slot = b;
        }
    }
    expect(
        sys::call(sys::EPOLL_CTL, [ep, EPOLL_CTL_ADD, l, edge.as_ptr() as u64, 0, 0]) == -EINVAL,
        162,
    );
    // 163: the connections kbuild closed are ready, and `epoll` says which.
    let mut out = [0u8; 16 * POLL_CONNECTIONS];
    // What `epoll_wait` writes per entry differs between the two ABIs; the buffer holds either.
    expect(sys::EPOLL_EVENT_BYTES <= 16, 163);
    let got = sys::call(
        sys::EPOLL_PWAIT,
        [
            ep,
            out.as_mut_ptr() as u64,
            POLL_CONNECTIONS as u64,
            5_000,
            0,
            0,
        ],
    );
    expect(got >= 1, 163);

    // 164: everything closes.
    let mut i = 0;
    while i < accepted {
        if let Some(&c) = conns.get(i)
            && c != 0
        {
            expect(call1(sys::CLOSE, c) == 0, 164);
        }
        i += 1;
    }
    expect(call1(sys::CLOSE, ep) == 0 && call1(sys::CLOSE, l) == 0, 164);
    exit(POLL_SUCCESS)
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    exit(101)
}

// ---- files: writing the test disk --------------------------------------------------------

const O_WRONLY: u64 = 1;
const O_RDWR: u64 = 2;
const O_CREAT: u64 = 0o100;
const O_EXCL: u64 = 0o200;
const O_TRUNC: u64 = 0o1000;
const O_APPEND: u64 = 0o2000;
const SEEK_SET: u64 = 0;
const SEEK_END: u64 = 2;
const AT_REMOVEDIR: u64 = 0x200;
const EEXIST: i64 = 17;
const EISDIR: i64 = 21;
const ENAMETOOLONG: i64 = 36;

const TEMP: &[u8] = b"/KINTANE/LXTMP.TXT\0";
const RENAMED: &[u8] = b"/KINTANE/LXREN.TXT\0";
const DIR: &[u8] = b"/KINTANE/LXDIR\0";
const INTO_DIR: &[u8] = b"/KINTANE/LXDIR/X.TXT\0";
/// A name with two dots, which no short directory entry can hold: the volume keeps it in long
/// entries and gives it back as it was written.
const LONG_NAME: &[u8] = b"/KINTANE/NOT.AN.83\0";
/// A component longer than the namespace holds, which is refused whatever it is made of.
const BAD_NAME: &[u8] =
    b"/KINTANE/a-name-far-longer-than-any-directory-entry-holds-however-long-its-name-may-be.txt\0";
/// What this mode leaves on the disk for kbuild to read after the guest exits; mirrors
/// `LINUX_OUT_PATH`, `LINUX_OUT_LEN` and `out_byte` in `kernel/block/src/testdisk.rs`.
const OUT: &[u8] = b"/KINTANE/LINUX.OUT\0";
const OUT_LEN: usize = 2000;
const OUT_SEED: u8 = 0x4c;

fn out_byte(seed: u8, i: usize) -> u8 {
    let x = (i as u32).wrapping_mul(2_654_435_761) ^ u32::from(seed).wrapping_mul(0x9E37_79B9);
    (x >> 23) as u8 ^ seed
}

fn openat(path: &[u8], flags: u64) -> i64 {
    sys::call(sys::OPENAT, [AT_FDCWD, path.as_ptr() as u64, flags, 0o644, 0, 0])
}

/// Write all of `bytes`, in pieces that start and end anywhere.
fn write_pieces(fd: u64, bytes: &[u8]) -> bool {
    let mut done = 0;
    while done < bytes.len() {
        let take = (bytes.len() - done).min(700);
        let n = sys::call(sys::WRITE, [fd, bytes[done..].as_ptr() as u64, take as u64, 0, 0, 0]);
        if n <= 0 {
            return false;
        }
        done += n as usize;
    }
    true
}

fn read_exact(fd: u64, into: &mut [u8]) -> bool {
    let mut done = 0;
    while done < into.len() {
        let n = sys::call(
            sys::READ,
            [
                fd,
                into[done..].as_mut_ptr() as u64,
                (into.len() - done) as u64,
                0,
                0,
                0,
            ],
        );
        if n <= 0 {
            return false;
        }
        done += n as usize;
    }
    true
}

/// `st_size`, which both architectures' `struct stat` keep at byte 48.
fn size_of_fd(fd: u64) -> i64 {
    let mut stat = [0u8; 144];
    if sys::call(sys::FSTAT, [fd, stat.as_mut_ptr() as u64, 0, 0, 0, 0]) != 0 {
        return -1;
    }
    i64::from_le_bytes([
        stat[48], stat[49], stat[50], stat[51], stat[52], stat[53], stat[54], stat[55],
    ])
}

/// Create, write, read back, append, truncate, make a directory, rename and remove, through
/// Linux's calls on the test disk; then leave [`OUT`] for kbuild. Exits [`FILES_SUCCESS`] or
/// the step that was wrong, from 80.
fn files() -> ! {
    let mut data = [0u8; 3000];
    for (i, b) in data.iter_mut().enumerate() {
        *b = out_byte(0x11, i);
    }
    // 80–82: create exclusively, write, and a second exclusive create is refused.
    let fd = openat(TEMP, O_WRONLY | O_CREAT | O_EXCL);
    expect(fd >= 0, 80);
    let fd = fd as u64;
    expect(write_pieces(fd, &data), 81);
    expect(openat(TEMP, O_WRONLY | O_CREAT | O_EXCL) == -EEXIST, 82);
    expect(call1(sys::CLOSE, fd) == 0, 83);

    // 84–86: read back, a write on a read-only descriptor, and the size seen from the end.
    let fd = openat(TEMP, 0);
    expect(fd >= 0, 84);
    let fd = fd as u64;
    let mut back = [0u8; 3000];
    expect(read_exact(fd, &mut back) && back == data, 84);
    expect(sys::call(sys::WRITE, [fd, data.as_ptr() as u64, 1, 0, 0, 0]) == -EBADF, 85);
    expect(sys::call(sys::LSEEK, [fd, 0, SEEK_END, 0, 0, 0]) == 3000, 86);
    expect(call1(sys::CLOSE, fd) == 0, 86);

    // 87: appending writes at the end, and fstat sees the new size.
    let fd = openat(TEMP, O_WRONLY | O_APPEND);
    expect(fd >= 0, 87);
    let fd = fd as u64;
    expect(write_pieces(fd, b"tail") && size_of_fd(fd) == 3004, 87);
    expect(call1(sys::CLOSE, fd) == 0, 87);

    // 88: ftruncate shortens, and what is left reads back.
    let fd = openat(TEMP, O_RDWR);
    expect(fd >= 0, 88);
    let fd = fd as u64;
    expect(sys::call(sys::FTRUNCATE, [fd, 100, 0, 0, 0, 0]) == 0, 88);
    expect(size_of_fd(fd) == 100, 88);
    expect(sys::call(sys::LSEEK, [fd, 0, SEEK_SET, 0, 0, 0]) == 0, 88);
    let mut short = [0u8; 100];
    expect(read_exact(fd, &mut short) && short[..] == data[..100], 88);
    expect(call1(sys::CLOSE, fd) == 0, 88);

    // 89: O_TRUNC empties.
    let fd = openat(TEMP, O_WRONLY | O_TRUNC);
    expect(fd >= 0 && size_of_fd(fd as u64) == 0, 89);
    expect(call1(sys::CLOSE, fd as u64) == 0, 89);

    // 90: a directory, and making it twice is refused.
    let mkdir =
        |path: &[u8]| sys::call(sys::MKDIRAT, [AT_FDCWD, path.as_ptr() as u64, 0o755, 0, 0, 0]);
    expect(mkdir(DIR) == 0 && mkdir(DIR) == -EEXIST, 90);

    // 91–92: a rename within a directory, and one into another directory of the same
    // filesystem, which moves the name rather than refusing it. It moves back out, so the
    // steps below find the directory empty and the file where they left it.
    let rename = |from: &[u8], to: &[u8]| {
        sys::call(
            sys::RENAMEAT,
            [
                AT_FDCWD,
                from.as_ptr() as u64,
                AT_FDCWD,
                to.as_ptr() as u64,
                0,
                0,
            ],
        )
    };
    expect(rename(TEMP, RENAMED) == 0, 91);
    expect(openat(TEMP, 0) == -ENOENT, 91);
    expect(rename(RENAMED, INTO_DIR) == 0, 92);
    expect(openat(RENAMED, 0) == -ENOENT, 92);
    let moved = openat(INTO_DIR, 0);
    expect(moved >= 0, 92);
    expect(call1(sys::CLOSE, moved as u64) == 0, 92);
    expect(rename(INTO_DIR, RENAMED) == 0, 92);

    // 93–94: a directory is removed only as one; a file is removed and gone.
    let unlink = |path: &[u8], flags: u64| {
        sys::call(sys::UNLINKAT, [AT_FDCWD, path.as_ptr() as u64, flags, 0, 0, 0])
    };
    expect(unlink(DIR, 0) == -EISDIR, 93);
    expect(unlink(DIR, AT_REMOVEDIR) == 0, 93);
    expect(unlink(RENAMED, 0) == 0 && openat(RENAMED, 0) == -ENOENT, 94);

    // 94: a name no short directory entry can hold is kept in long entries, and comes back by
    // the name it was made with. Before step 95, so that step's `fsync` makes this create and
    // this removal durable as well.
    let made = openat(LONG_NAME, O_WRONLY | O_CREAT);
    expect(made >= 0, 94);
    expect(call1(sys::CLOSE, made as u64) == 0, 94);
    let again = openat(LONG_NAME, 0);
    expect(again >= 0, 94);
    expect(call1(sys::CLOSE, again as u64) == 0, 94);
    expect(unlink(LONG_NAME, 0) == 0, 94);

    // 95: what kbuild reads after the guest exits, through `open` where the architecture has
    // one, made durable with `fsync`.
    let flags = O_WRONLY | O_CREAT | O_TRUNC;
    let fd = match sys::OPEN {
        Some(nr) => sys::call(nr, [OUT.as_ptr() as u64, flags, 0o644, 0, 0, 0]),
        None => openat(OUT, flags),
    };
    expect(fd >= 0, 95);
    let fd = fd as u64;
    let mut out = [0u8; OUT_LEN];
    for (i, b) in out.iter_mut().enumerate() {
        *b = out_byte(OUT_SEED, i);
    }
    expect(write_pieces(fd, &out), 95);
    expect(call1(sys::FSYNC, fd) == 0, 95);
    expect(call1(sys::CLOSE, fd) == 0, 95);

    // 96: a name longer than the namespace holds is refused, not shortened. It creates
    // nothing, so nothing is left unwritten after step 95 made everything durable.
    expect(openat(BAD_NAME, O_WRONLY | O_CREAT) == -ENAMETOOLONG, 96);
    exit(FILES_SUCCESS)
}

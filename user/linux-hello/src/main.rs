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
//! * `tcp <port>`: [`tcp`], a TCP client of kbuild's service on `<port>`, blocking and not;
//! * `serve`: [`serve`], a TCP server kbuild connects to through a port QEMU forwards.
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
        b"tcp" => tcp(s.arg),
        b"serve" => serve(),
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

// ---- tcp and serve: sockets ---------------------------------------------------------------

const TCP_SUCCESS: u64 = 46;
const SERVE_SUCCESS: u64 = 47;

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
const INBOUND: &[u8] = b"kintane-tcp-inbound ";
const INBOUND_REPLY: &[u8] = b"kintane-tcp-inbound-reply ";
const INBOUND_VERIFIED: &[u8] = b"kintane-tcp-inbound-verified ";

/// Tries a non-blocking `connect` gets to see its connection established.
const CONNECT_TRIES: u32 = 2_000_000;

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
fn join(buf: &mut [u8], a: &[u8], b: &[u8]) -> usize {
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
    expect(call1(sys::CLOSE, nb) == 0, 125);
    exit(TCP_SUCCESS)
}

fn serve() -> ! {
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
    let tag_len = join(&mut tag_buf, tag, b"");
    let tag = tag_buf.get(..tag_len).unwrap_or(&[]);
    // 137: the reply.
    let mut reply = [0u8; 64];
    let r = join(&mut reply, INBOUND_REPLY, tag);
    expect(write_all(c, reply.get(..r).unwrap_or(&[])), 137);
    // 138: kbuild checked the reply, and says so.
    let n = read_line(c, &mut line);
    let mut verified = [0u8; 64];
    let v = join(&mut verified, INBOUND_VERIFIED, tag);
    expect(line.get(..n) == verified.get(..v), 138);
    // 139: then kbuild closes its end.
    expect(sys::call(sys::READ, [c, line.as_mut_ptr() as u64, 1, 0, 0, 0]) == 0, 139);
    // 140: both sockets close.
    expect(call1(sys::CLOSE, c) == 0, 140);
    expect(call1(sys::CLOSE, l) == 0, 140);
    exit(SERVE_SUCCESS)
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    exit(101)
}

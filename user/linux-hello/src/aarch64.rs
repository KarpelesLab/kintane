//! What differs on aarch64: Linux's generic numbers, `svc #0`, the entry, the thread pointer
//! in `TPIDR_EL0`, and the `clone` trampoline. aarch64 has no `fork` and no `arch_prctl`: a
//! C library forks with `clone(SIGCHLD)` and sets its thread pointer itself, at EL0.

use core::arch::{asm, global_asm};

pub const READ: u64 = 63;
pub const WRITE: u64 = 64;
pub const CLOSE: u64 = 57;
pub const FSTAT: u64 = 80;
pub const MMAP: u64 = 222;
pub const MUNMAP: u64 = 215;
pub const BRK: u64 = 214;
pub const SCHED_YIELD: u64 = 124;
pub const GETPID: u64 = 172;
pub const CLONE: u64 = 220;
pub const EXECVE: u64 = 221;
pub const WAIT4: u64 = 260;
pub const UNAME: u64 = 160;
pub const GETTID: u64 = 178;
pub const FUTEX: u64 = 98;
pub const EXIT_GROUP: u64 = 94;
pub const OPENAT: u64 = 56;
pub const LSEEK: u64 = 62;
pub const FSYNC: u64 = 82;
pub const FTRUNCATE: u64 = 46;
pub const MKDIRAT: u64 = 34;
pub const UNLINKAT: u64 = 35;
pub const RENAMEAT: u64 = 38;
/// aarch64 has no `open`: a C library opens with `openat`.
pub const OPEN: Option<u64> = None;
pub const PIPE2: u64 = 59;
pub const GETRANDOM: u64 = 278;
pub const RT_SIGACTION: u64 = 134;
pub const RT_SIGPROCMASK: u64 = 135;
pub const RT_SIGPENDING: u64 = 136;
pub const RT_SIGQUEUEINFO: u64 = 138;
pub const KILL: u64 = 129;
pub const TGKILL: u64 = 131;
pub const SOCKET: u64 = 198;
pub const BIND: u64 = 200;
pub const LISTEN: u64 = 201;
pub const CONNECT: u64 = 203;
pub const GETSOCKNAME: u64 = 204;
pub const GETPEERNAME: u64 = 205;
pub const SENDTO: u64 = 206;
pub const SENDMSG: u64 = 211;
pub const RECVMSG: u64 = 212;
pub const RECVFROM: u64 = 207;
pub const SETSOCKOPT: u64 = 208;
pub const GETSOCKOPT: u64 = 209;
pub const SHUTDOWN: u64 = 210;
pub const ACCEPT4: u64 = 242;
/// arm64 has no plain `poll` or `select`: only the forms that take a signal mask.
pub const POLL: Option<u64> = None;
pub const SELECT: Option<u64> = None;
pub const PPOLL: u64 = 73;
pub const PSELECT6: u64 = 72;
pub const EPOLL_CREATE1: u64 = 20;
pub const EPOLL_CTL: u64 = 21;
pub const EPOLL_PWAIT: u64 = 22;
/// `struct epoll_event` is aligned here: the data word sits at eight.
pub const EPOLL_EVENT_BYTES: usize = 16;
pub const EPOLL_DATA_AT: usize = 8;

const SIGCHLD: u64 = 17;

// The entry: `sp` points at `argc`, as Linux leaves it, already 16-byte aligned. Pass it to
// Rust.
global_asm!(
    ".pushsection .text._start, \"ax\"",
    ".globl _start",
    ".type _start, %function",
    "_start:",
    "    mov x0, sp",
    "    mov x29, xzr",
    "    mov x30, xzr",
    "    bl {start}",
    "    brk #0",
    ".popsection",
    start = sym crate::start,
);

/// A Linux system call.
pub fn call(nr: u64, a: [u64; 6]) -> i64 {
    let ret: i64;
    // SAFETY: `svc #0` is always a valid instruction; the kernel preserves every register but
    // `x0`, which carries the result.
    unsafe {
        asm!(
            "svc #0",
            in("x8") nr,
            inlateout("x0") a[0] => ret,
            in("x1") a[1],
            in("x2") a[2],
            in("x3") a[3],
            in("x4") a[4],
            in("x5") a[5],
            options(nostack),
        );
    }
    ret
}

/// Point this thread's thread pointer at `addr`: a register EL0 writes itself.
pub fn set_tls(addr: u64) -> bool {
    // SAFETY: `TPIDR_EL0` is EL0's own register.
    unsafe { asm!("msr tpidr_el0, {v}", v = in(reg) addr, options(nostack)) };
    true
}

/// The first word of this thread's TLS block, read through the thread pointer.
pub fn tls_word() -> u64 {
    let v: u64;
    // SAFETY: the thread pointer names a mapped block; every caller set it first.
    unsafe {
        asm!(
            "mrs {t}, tpidr_el0",
            "ldr {v}, [{t}]",
            t = out(reg) _,
            v = out(reg) v,
            options(nostack),
        )
    };
    v
}

/// `fork`, as an aarch64 C library makes it.
pub fn fork() -> i64 {
    call(CLONE, [SIGCHLD, 0, 0, 0, 0, 0])
}

// `clone` for a thread: the child returns from the call on the stack it was given, calls `f`
// from here and exits with its result. `f` travels in x19, which the kernel gives the child
// as the parent had it.
global_asm!(
    ".pushsection .text.linux_clone, \"ax\"",
    ".globl linux_clone",
    "linux_clone:",
    // x0 flags, x1 stack, x2 parent_tid, x3 child_tid, x4 tls, x5 f; aarch64's `clone` takes
    // the thread pointer before the child's tid.
    "    stp x19, x30, [sp, #-16]!",
    "    mov x19, x5",
    "    mov x6, x3",
    "    mov x3, x4",
    "    mov x4, x6",
    "    mov x8, #220",
    "    svc #0",
    "    cbnz x0, 2f",
    "    mov x29, xzr",
    "    mov x30, xzr",
    "    blr x19",
    "    mov x8, #93",
    "    svc #0",
    "    brk #1",
    "2:",
    "    ldp x19, x30, [sp], #16",
    "    ret",
    ".popsection",
);

unsafe extern "C" {
    fn linux_clone(
        flags: u64,
        stack: u64,
        parent_tid: *mut u32,
        child_tid: *mut u32,
        tls: u64,
        f: extern "C" fn() -> u64,
    ) -> i64;
}

// Signals, as on x86_64: the restorer makes `rt_sigreturn`; the clobbering handler zeroes
// x19–x29 and returns through x30, which the kernel pointed at the restorer; and
// `linux_raise_marked` marks x19–x30, sends the signal with `kill` (x0 pid, x1 signal) and
// answers 1 in x0 if every mark is back.
global_asm!(
    ".pushsection .text.linux_signals, \"ax\"",
    ".globl linux_restorer",
    "linux_restorer:",
    "    mov x8, #139",
    "    svc #0",
    "    brk #2",
    ".globl linux_clobber",
    "linux_clobber:",
    "    adrp x9, {hits}",
    "    add x9, x9, :lo12:{hits}",
    "    ldr x10, [x9]",
    "    add x10, x10, #1",
    "    str x10, [x9]",
    "    mov x19, xzr",
    "    mov x20, xzr",
    "    mov x21, xzr",
    "    mov x22, xzr",
    "    mov x23, xzr",
    "    mov x24, xzr",
    "    mov x25, xzr",
    "    mov x26, xzr",
    "    mov x27, xzr",
    "    mov x28, xzr",
    "    mov x29, xzr",
    "    ret",
    ".globl linux_raise_marked",
    "linux_raise_marked:",
    "    stp x19, x20, [sp, #-96]!",
    "    stp x21, x22, [sp, #16]",
    "    stp x23, x24, [sp, #32]",
    "    stp x25, x26, [sp, #48]",
    "    stp x27, x28, [sp, #64]",
    "    stp x29, x30, [sp, #80]",
    "    ldr x19, =0x5349474e414c0013",
    "    ldr x20, =0x5349474e414c0014",
    "    ldr x21, =0x5349474e414c0015",
    "    ldr x22, =0x5349474e414c0016",
    "    ldr x23, =0x5349474e414c0017",
    "    ldr x24, =0x5349474e414c0018",
    "    ldr x25, =0x5349474e414c0019",
    "    ldr x26, =0x5349474e414c001a",
    "    ldr x27, =0x5349474e414c001b",
    "    ldr x28, =0x5349474e414c001c",
    "    ldr x29, =0x5349474e414c001d",
    "    ldr x30, =0x5349474e414c001e",
    "    mov x8, #129",
    "    svc #0",
    "    mov x0, xzr",
    "    ldr x9, =0x5349474e414c0013",
    "    cmp x19, x9",
    "    b.ne 2f",
    "    ldr x9, =0x5349474e414c0014",
    "    cmp x20, x9",
    "    b.ne 2f",
    "    ldr x9, =0x5349474e414c0015",
    "    cmp x21, x9",
    "    b.ne 2f",
    "    ldr x9, =0x5349474e414c0016",
    "    cmp x22, x9",
    "    b.ne 2f",
    "    ldr x9, =0x5349474e414c0017",
    "    cmp x23, x9",
    "    b.ne 2f",
    "    ldr x9, =0x5349474e414c0018",
    "    cmp x24, x9",
    "    b.ne 2f",
    "    ldr x9, =0x5349474e414c0019",
    "    cmp x25, x9",
    "    b.ne 2f",
    "    ldr x9, =0x5349474e414c001a",
    "    cmp x26, x9",
    "    b.ne 2f",
    "    ldr x9, =0x5349474e414c001b",
    "    cmp x27, x9",
    "    b.ne 2f",
    "    ldr x9, =0x5349474e414c001c",
    "    cmp x28, x9",
    "    b.ne 2f",
    "    ldr x9, =0x5349474e414c001d",
    "    cmp x29, x9",
    "    b.ne 2f",
    "    ldr x9, =0x5349474e414c001e",
    "    cmp x30, x9",
    "    b.ne 2f",
    "    mov x0, #1",
    "2:",
    "    ldp x29, x30, [sp, #80]",
    "    ldp x27, x28, [sp, #64]",
    "    ldp x25, x26, [sp, #48]",
    "    ldp x23, x24, [sp, #32]",
    "    ldp x21, x22, [sp, #16]",
    "    ldp x19, x20, [sp], #96",
    "    ret",
    "    .ltorg",
    ".popsection",
    hits = sym crate::CLOBBER_HITS,
);

unsafe extern "C" {
    fn linux_restorer();
    fn linux_clobber();
    fn linux_raise_marked(pid: u64, sig: u64) -> u64;
}

// The arithmetic trap, as far as aarch64 has one: `sdiv` by zero answers zero and raises
// nothing, so the trap a program can raise here is an undefined instruction, which the kernel
// reports as `SIGILL`. As on x86_64, the label after it is where the handler sends the thread.
global_asm!(
    ".pushsection .text.linux_arith, \"ax\"",
    ".globl linux_raise_arith",
    "linux_raise_arith:",
    "    udf #0",
    ".globl linux_after_arith",
    "linux_after_arith:",
    "    ret",
    ".popsection",
);

// A store to whatever address it is given, with the instruction after it labelled, as on
// x86_64: the handler steps over the store rather than guessing its length.
global_asm!(
    ".pushsection .text.linux_bad_store, \"ax\"",
    ".globl linux_bad_store",
    "linux_bad_store:",
    "    mov x1, #1",
    "    str x1, [x0]",
    ".globl linux_after_store",
    "linux_after_store:",
    "    ret",
    ".popsection",
);

unsafe extern "C" {
    fn linux_raise_arith();
    fn linux_after_arith();
    fn linux_bad_store(addr: u64);
    fn linux_after_store();
}

/// Store to `addr`, which the caller has made sure has no mapping.
pub fn bad_store(addr: u64) {
    // SAFETY: the store faults, and the handler this mode installs points the saved program
    // counter at the `ret` after it.
    unsafe { linux_bad_store(addr) };
}

/// The instruction after the store.
pub fn after_store() -> u64 {
    linux_after_store as *const () as u64
}

/// The signal the trap this architecture can raise reports as.
pub const ARITH_SIG: u64 = 4; // SIGILL

/// Where the program counter sits in a `ucontext`: its `sigcontext` starts 176 bytes in, and
/// `pc` follows the reserved word, the 31 registers and `sp`. Mirrors `kernel/linux`'s `a64`
/// layout, where the frame puts `pc` at 568 with the `ucontext` at 128.
pub const UC_PC: usize = 176 + 8 + 31 * 8 + 8;

/// Raise the trap, and come back through the handler's redirect.
pub fn raise_arith() {
    // SAFETY: the instruction traps, and the handler this mode installs points the saved
    // program counter at the `ret` after it.
    unsafe { linux_raise_arith() };
}

/// The instruction after the one that traps.
pub fn after_arith() -> u64 {
    linux_after_arith as *const () as u64
}

/// The restorer every handler is installed with.
pub fn restorer() -> u64 {
    linux_restorer as *const () as u64
}

/// A handler that zeroes every callee-saved register before it returns.
pub fn clobber_handler() -> u64 {
    linux_clobber as *const () as u64
}

/// Send `sig` to process `pid` with every callee-saved register marked, and say whether every
/// mark survived the handler.
pub fn raise_marked(pid: u64, sig: u64) -> bool {
    // SAFETY: the function saves and restores every register it marks, and makes one system call.
    unsafe { linux_raise_marked(pid, sig) == 1 }
}

/// The flags a thread library's `clone` passes for a thread.
const THREAD_FLAGS: u64 =
    0x100 | 0x200 | 0x400 | 0x800 | 0x10000 | 0x40000 | 0x80000 | 0x100000 | 0x200000 | 0x1000000;

/// Start a thread running `f` on the stack whose top is `stack`, with thread pointer `tls`.
pub fn clone_thread(
    stack: u64,
    parent_tid: *mut u32,
    child_tid: *mut u32,
    tls: u64,
    f: extern "C" fn() -> u64,
) -> i64 {
    // SAFETY: as on x86_64: a mapped, aligned stack of the thread's own, and tid addresses
    // that outlive it.
    unsafe { linux_clone(THREAD_FLAGS, stack, parent_tid, child_tid, tls, f) }
}

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
pub const PIPE2: u64 = 59;
pub const GETRANDOM: u64 = 278;

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

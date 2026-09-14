//! What differs on x86_64: Linux's numbers, `syscall`, the entry, the thread pointer in `FS`,
//! and the `clone` trampoline.

use core::arch::{asm, global_asm};

pub const READ: u64 = 0;
pub const WRITE: u64 = 1;
pub const CLOSE: u64 = 3;
pub const FSTAT: u64 = 5;
pub const MMAP: u64 = 9;
pub const MUNMAP: u64 = 11;
pub const BRK: u64 = 12;
pub const SCHED_YIELD: u64 = 24;
pub const GETPID: u64 = 39;
pub const FORK: u64 = 57;
pub const EXECVE: u64 = 59;
pub const WAIT4: u64 = 61;
pub const UNAME: u64 = 63;
pub const ARCH_PRCTL: u64 = 158;
pub const GETTID: u64 = 186;
pub const FUTEX: u64 = 202;
pub const EXIT_GROUP: u64 = 231;
pub const OPENAT: u64 = 257;
pub const PIPE2: u64 = 293;
pub const GETRANDOM: u64 = 318;
pub const SOCKET: u64 = 41;
pub const CONNECT: u64 = 42;
pub const SENDTO: u64 = 44;
pub const RECVFROM: u64 = 45;
pub const SHUTDOWN: u64 = 48;
pub const BIND: u64 = 49;
pub const LISTEN: u64 = 50;
pub const GETSOCKNAME: u64 = 51;
pub const GETPEERNAME: u64 = 52;
pub const SETSOCKOPT: u64 = 54;
pub const GETSOCKOPT: u64 = 55;
pub const ACCEPT4: u64 = 288;

const ARCH_SET_FS: u64 = 0x1002;

// The entry: `rsp` points at `argc`, as Linux leaves it. Pass that to Rust, on a stack
// aligned the way a call expects.
global_asm!(
    ".pushsection .text._start, \"ax\"",
    ".globl _start",
    ".type _start, @function",
    "_start:",
    "    mov rdi, rsp",
    "    and rsp, -16",
    "    call {start}",
    "    ud2",
    ".popsection",
    start = sym crate::start,
);

/// A Linux system call.
pub fn call(nr: u64, a: [u64; 6]) -> i64 {
    let ret: i64;
    // SAFETY: `syscall` is always a valid instruction; the kernel preserves every register
    // but `rax`, which carries the result, and the `rcx`/`r11` pair `syscall` overwrites.
    unsafe {
        asm!(
            "syscall",
            inlateout("rax") nr as i64 => ret,
            in("rdi") a[0],
            in("rsi") a[1],
            in("rdx") a[2],
            in("r10") a[3],
            in("r8") a[4],
            in("r9") a[5],
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    ret
}

/// Point this thread's thread pointer at `addr`.
pub fn set_tls(addr: u64) -> bool {
    call(ARCH_PRCTL, [ARCH_SET_FS, addr, 0, 0, 0, 0]) == 0
}

/// The first word of this thread's TLS block, read through the thread pointer.
pub fn tls_word() -> u64 {
    let v: u64;
    // SAFETY: the thread pointer names a mapped block; every caller set it first.
    unsafe { asm!("mov {v}, qword ptr fs:[0]", v = out(reg) v, options(nostack)) };
    v
}

/// `fork`, which x86_64 has as a call of its own.
pub fn fork() -> i64 {
    call(FORK, [0; 6])
}

// `clone` for a thread: the child returns from the call on the stack it was given, with no
// frame to return into, so it calls `f` from here and exits with its result. `f` travels in
// r12, which the kernel gives the child as the parent had it.
global_asm!(
    ".pushsection .text.linux_clone, \"ax\"",
    ".globl linux_clone",
    "linux_clone:",
    // rdi flags, rsi stack, rdx parent_tid, rcx child_tid, r8 tls, r9 f
    "    push r12",
    "    mov r12, r9",
    "    mov r10, rcx",
    "    mov eax, 56",
    "    syscall",
    "    test rax, rax",
    "    jnz 2f",
    "    xor ebp, ebp",
    "    call r12",
    "    mov rdi, rax",
    "    mov eax, 60",
    "    syscall",
    "    ud2",
    "2:",
    "    pop r12",
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
    // SAFETY: `stack` is the top of a mapped stack no one else uses, 16-byte aligned, and
    // both tid addresses are this program's statics or locals, alive until the thread ends.
    unsafe { linux_clone(THREAD_FLAGS, stack, parent_tid, child_tid, tls, f) }
}

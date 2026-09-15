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
pub const LSEEK: u64 = 8;
pub const FSYNC: u64 = 74;
pub const FTRUNCATE: u64 = 77;
pub const MKDIRAT: u64 = 258;
pub const UNLINKAT: u64 = 263;
pub const RENAMEAT: u64 = 264;
pub const STATFS: u64 = 137;
pub const FSTATFS: u64 = 138;
pub const GETDENTS64: u64 = 217;
/// `open`, which x86_64 keeps beside `openat`.
pub const OPEN: Option<u64> = Some(2);
pub const PIPE2: u64 = 293;
pub const GETRANDOM: u64 = 318;
pub const RT_SIGACTION: u64 = 13;
pub const RT_SIGPROCMASK: u64 = 14;
pub const RT_SIGPENDING: u64 = 127;
pub const RT_SIGQUEUEINFO: u64 = 129;
pub const KILL: u64 = 62;
pub const TGKILL: u64 = 234;
pub const SOCKET: u64 = 41;
pub const CONNECT: u64 = 42;
pub const SENDTO: u64 = 44;
pub const SENDMSG: u64 = 46;
pub const RECVMSG: u64 = 47;
pub const RECVFROM: u64 = 45;
pub const SHUTDOWN: u64 = 48;
pub const BIND: u64 = 49;
pub const LISTEN: u64 = 50;
pub const GETSOCKNAME: u64 = 51;
pub const GETPEERNAME: u64 = 52;
pub const SETSOCKOPT: u64 = 54;
pub const GETSOCKOPT: u64 = 55;
pub const ACCEPT4: u64 = 288;
pub const POLL: Option<u64> = Some(7);
pub const SELECT: Option<u64> = Some(23);
pub const PPOLL: u64 = 271;
pub const PSELECT6: u64 = 270;
pub const EPOLL_CREATE1: u64 = 291;
pub const EPOLL_CTL: u64 = 233;
pub const EPOLL_PWAIT: u64 = 281;
/// `struct epoll_event` is packed here: four bytes of events, then the data word.
pub const EPOLL_EVENT_BYTES: usize = 12;
pub const EPOLL_DATA_AT: usize = 4;

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

// Signals. `linux_restorer` is what every handler returns into: `rt_sigreturn`. The clobbering
// handler zeroes every callee-saved register and returns; `linux_raise_marked` loads each with a
// mark, sends the signal to its own process with `kill` (rdi pid, rsi signal), and answers 1 in
// rax if every mark is back once the call has returned through the handler.
global_asm!(
    ".pushsection .text.linux_signals, \"ax\"",
    ".globl linux_restorer",
    "linux_restorer:",
    "    mov eax, 15",
    "    syscall",
    "    ud2",
    ".globl linux_clobber",
    "linux_clobber:",
    "    lea rax, [rip + {hits}]",
    "    inc qword ptr [rax]",
    "    xor ebx, ebx",
    "    xor ebp, ebp",
    "    xor r12d, r12d",
    "    xor r13d, r13d",
    "    xor r14d, r14d",
    "    xor r15d, r15d",
    "    ret",
    ".globl linux_raise_marked",
    "linux_raise_marked:",
    "    push rbx",
    "    push rbp",
    "    push r12",
    "    push r13",
    "    push r14",
    "    push r15",
    "    movabs rbx, 0x5349474e414c0001",
    "    movabs rbp, 0x5349474e414c0002",
    "    movabs r12, 0x5349474e414c0003",
    "    movabs r13, 0x5349474e414c0004",
    "    movabs r14, 0x5349474e414c0005",
    "    movabs r15, 0x5349474e414c0006",
    "    mov eax, 62",
    "    syscall",
    "    xor eax, eax",
    "    movabs rcx, 0x5349474e414c0001",
    "    cmp rbx, rcx",
    "    jne 2f",
    "    movabs rcx, 0x5349474e414c0002",
    "    cmp rbp, rcx",
    "    jne 2f",
    "    movabs rcx, 0x5349474e414c0003",
    "    cmp r12, rcx",
    "    jne 2f",
    "    movabs rcx, 0x5349474e414c0004",
    "    cmp r13, rcx",
    "    jne 2f",
    "    movabs rcx, 0x5349474e414c0005",
    "    cmp r14, rcx",
    "    jne 2f",
    "    movabs rcx, 0x5349474e414c0006",
    "    cmp r15, rcx",
    "    jne 2f",
    "    mov eax, 1",
    "2:",
    "    pop r15",
    "    pop r14",
    "    pop r13",
    "    pop r12",
    "    pop rbp",
    "    pop rbx",
    "    ret",
    ".popsection",
    hits = sym crate::CLOBBER_HITS,
);

unsafe extern "C" {
    fn linux_restorer();
    fn linux_clobber();
    fn linux_raise_marked(pid: u64, sig: u64) -> u64;
}

// The arithmetic trap: `div` by zero is #DE, which the kernel reports as `SIGFPE`. The label
// after it is where the handler sends the thread, since returning to the `div` would raise it
// again for as long as the kernel let it.
global_asm!(
    ".pushsection .text.linux_arith, \"ax\"",
    ".globl linux_raise_arith",
    "linux_raise_arith:",
    "    xor edx, edx",
    "    mov eax, 1",
    "    xor ecx, ecx",
    "    div ecx",
    ".globl linux_after_arith",
    "linux_after_arith:",
    "    ret",
    ".popsection",
);

// A store to whatever address it is given, with the instruction after it labelled: the length
// of a store is the architecture's business, so the handler that steps over one needs the
// assembler to say where it ends rather than guessing.
global_asm!(
    ".pushsection .text.linux_bad_store, \"ax\"",
    ".globl linux_bad_store",
    "linux_bad_store:",
    "    mov qword ptr [rdi], 1",
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

/// The signal an arithmetic trap raises here.
pub const ARITH_SIG: u64 = 8; // SIGFPE

/// Where the program counter sits in a `ucontext`: its `sigcontext` starts 40 bytes in, and
/// `rip` is the sixteenth of the registers there. Mirrors `kernel/linux`'s `x86` layout.
pub const UC_PC: usize = 40 + 16 * 8;

/// Where `sigcontext` keeps the pointer to the saved floating-point state: after `cr2`, the
/// twenty-fourth word. Mirrors `kernel/linux`'s `x86::FPSTATE`.
pub const UC_FPSTATE_PTR: usize = 40 + 23 * 8;

/// Where the first XMM register sits in the `FXSAVE` image the pointer names, from the SDM's
/// layout.
const FX_XMM0: usize = 160;

// Floating point across a handler. `linux_fp_marked` puts a known double in xmm0-xmm7, sends
// the signal to its own process (rdi pid, rsi signal), and answers 1 in rax if every one came
// back. The handler in between does floating-point work of its own, so a kernel that did not
// save and restore this state would be caught by the compare rather than by luck.
//
// The marks are doubles with exact binary representations — small integers scaled by powers of
// two — so a value that survives a save and restore compares bit-for-bit, and the comparison is
// integer, on the bits, not a floating-point compare that a NaN could pass or fail oddly.
global_asm!(
    ".pushsection .text.linux_fp, \"ax\"",
    ".globl linux_fp_marked",
    "linux_fp_marked:",
    "    sub rsp, 128",
    // The eight marks: 1.5, 2.5, ... 8.5, built as integers and moved in.
    "    mov rax, 0x3ff8000000000000", // 1.5
    "    movq xmm0, rax",
    "    mov rax, 0x4004000000000000", // 2.5
    "    movq xmm1, rax",
    "    mov rax, 0x400c000000000000", // 3.5
    "    movq xmm2, rax",
    "    mov rax, 0x4012000000000000", // 4.5
    "    movq xmm3, rax",
    "    mov rax, 0x4016000000000000", // 5.5
    "    movq xmm4, rax",
    "    mov rax, 0x401a000000000000", // 6.5
    "    movq xmm5, rax",
    "    mov rax, 0x401e000000000000", // 7.5
    "    movq xmm6, rax",
    "    mov rax, 0x4021000000000000", // 8.5
    "    movq xmm7, rax",
    // kill(pid, sig). rdi and rsi already hold them.
    "    mov eax, 62",
    "    syscall",
    // Every register back, or zero.
    "    xor eax, eax",
    "    mov rcx, 0x3ff8000000000000",
    "    movq rdx, xmm0",
    "    cmp rdx, rcx",
    "    jne 2f",
    "    mov rcx, 0x4004000000000000",
    "    movq rdx, xmm1",
    "    cmp rdx, rcx",
    "    jne 2f",
    "    mov rcx, 0x400c000000000000",
    "    movq rdx, xmm2",
    "    cmp rdx, rcx",
    "    jne 2f",
    "    mov rcx, 0x4012000000000000",
    "    movq rdx, xmm3",
    "    cmp rdx, rcx",
    "    jne 2f",
    "    mov rcx, 0x4016000000000000",
    "    movq rdx, xmm4",
    "    cmp rdx, rcx",
    "    jne 2f",
    "    mov rcx, 0x401a000000000000",
    "    movq rdx, xmm5",
    "    cmp rdx, rcx",
    "    jne 2f",
    "    mov rcx, 0x401e000000000000",
    "    movq rdx, xmm6",
    "    cmp rdx, rcx",
    "    jne 2f",
    "    mov rcx, 0x4021000000000000",
    "    movq rdx, xmm7",
    "    cmp rdx, rcx",
    "    jne 2f",
    "    mov eax, 1",
    "2:",
    "    add rsp, 128",
    "    ret",
    // Put `bits` in xmm0, send the signal, and answer what xmm0 holds afterwards. One routine
    // rather than a set and a separate read: xmm0 is caller-saved, so between two calls the
    // compiler may use it for anything it likes, and the check would be of the compiler rather
    // than of the kernel.
    ".globl linux_fp_across",
    "linux_fp_across:",
    "    movq xmm0, rdx",
    "    mov eax, 62",
    "    syscall",
    "    movq rax, xmm0",
    "    ret",
    ".popsection",
);

unsafe extern "C" {
    fn linux_fp_marked(pid: u64, sig: u64) -> u64;
    fn linux_fp_across(pid: u64, sig: u64, bits: u64) -> u64;
}

/// Send `sig` to `pid` with eight floating-point registers marked, and say whether every mark
/// survived the handler.
pub fn fp_marked(pid: u64, sig: u64) -> bool {
    // SAFETY: the routine touches only volatile registers and its own red-zone allocation, and
    // makes one system call.
    unsafe { linux_fp_marked(pid, sig) == 1 }
}

/// Put `bits` in the first floating-point argument register, send `sig` to `pid`, and answer
/// what that register holds once the handler has returned.
pub fn fp_across_signal(pid: u64, sig: u64, bits: u64) -> u64 {
    // SAFETY: the routine writes one volatile register and makes one system call.
    unsafe { linux_fp_across(pid, sig, bits) }
}

/// The saved floating-point state in a `ucontext`, which `sigcontext`'s pointer names.
///
/// # Safety
/// `uc` is the `ucontext` the kernel pushed for a handler of this process, whose pointer the
/// kernel wrote and nothing has changed yet.
unsafe fn saved_fp(uc: *mut u8) -> *mut u8 {
    unsafe { uc.add(UC_FPSTATE_PTR).cast::<u64>().read() as *mut u8 }
}

/// Write `bits` over the saved first floating-point register, so the interrupted code resumes
/// with what the handler chose rather than with what it had.
///
/// # Safety
/// As [`saved_fp`].
pub unsafe fn set_saved_fp_first(uc: *mut u8, bits: u64) {
    unsafe { saved_fp(uc).add(FX_XMM0).cast::<u64>().write(bits) }
}

/// Make the frame's floating-point state malformed: a pointer of the program's own choosing,
/// which `rt_sigreturn` must refuse rather than follow.
///
/// # Safety
/// `uc` is the `ucontext` the kernel pushed for a handler of this process.
pub unsafe fn corrupt_saved_fp(uc: *mut u8) {
    unsafe { uc.add(UC_FPSTATE_PTR).cast::<u64>().write(0x4000_0000) }
}

/// Divide by zero, and come back through the handler's redirect.
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
    // SAFETY: `stack` is the top of a mapped stack no one else uses, 16-byte aligned, and
    // both tid addresses are this program's statics or locals, alive until the thread ends.
    unsafe { linux_clone(THREAD_FLAGS, stack, parent_tid, child_tid, tls, f) }
}

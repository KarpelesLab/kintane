//! Signals, as far as they are data: the numbers and what each does by default, `struct
//! sigaction`, and the frame a handler runs on.
//!
//! The kernel's half — who has which disposition, which thread has what pending, and when a
//! signal is delivered — is `kernel/main/src/personality/signals.rs`. This half is what can be
//! written without a process, and host-tested and fuzzed as a pure function of bytes:
//!
//! * **The frame.** [`build`] lays out what Linux pushes on a thread's stack before it enters a
//!   handler: x86_64's `rt_sigframe` (the return address, a `ucontext` with its `sigcontext`, and a
//!   `siginfo`), or aarch64's (a `siginfo`, a `ucontext` whose `sigcontext` ends in 4 KiB of
//!   reserved space, and a frame record above it). It returns the registers the handler starts
//!   with.
//! * **The way back.** [`restore`] reads the frame `rt_sigreturn` finds and returns the registers
//!   and the mask it holds. The frame is the program's to write, so it is untrusted: a return
//!   address outside the user half, or on aarch64 a processor state that is not EL0 with only the
//!   condition flags its own, is refused, and the flags x86_64 lets a program hold are the only
//!   ones kept. What a frame cannot carry at all — a segment, a privilege level — is never read
//!   from it.
//!
//! # Registers as words
//!
//! A context is `[u64; REGISTER_WORDS]` in the order a port's `hal::user::UserRegisters` gives
//! them: `rax, rbx, rcx, rdx, rsi, rdi, rbp, r8`–`r15, rip, rflags, rsp` on x86_64, and
//! `x0`–`x30, sp, pc, pstate` on aarch64. This crate depends on nothing, so the order is written
//! down twice; `kernel/main` asserts the word count agrees, and the boot check that a handler
//! returns with every callee-saved register intact is what proves the order does.
//!
//! # Floating-point state, and how much of it is trusted
//!
//! The frame carries it: x86_64's `fpstate` pointer names a 512-byte `FXSAVE` area at the end of
//! the frame, and aarch64's reserved space opens with a `fpsimd_context` record — Linux's magic
//! and size, `fpsr` and `fpcr`, then the 32 V registers — terminated by a null record. A handler
//! is the program's own code and may use those registers, so the interrupted code's values have
//! to be somewhere.
//!
//! This crate only *places* those bytes. It depends on nothing and has no architecture to ask,
//! so the personality fills them from `hal::HasFpu::save_live` and hands them back to
//! `load_live`; [`FPU_AT`] and [`FPU_BYTES`] say where and how many, and `kernel/main` asserts
//! the size against the port's own at compile time.
//!
//! **What [`restore`] will accept is narrower than what a program can write.** That field is the
//! one a program would use to aim the kernel at memory of its choosing, so it is checked rather
//! than followed: on x86_64 the only pointer accepted is the one naming the area inside that very
//! frame — which is why `restore` needs the frame's address, since the saved `rsp` is the
//! interrupted stack pointer and nothing in the bytes says where they came from — and on aarch64
//! the record must carry exactly Linux's magic and size. Null is not "no state claimed" but a
//! malformed frame, because every frame this kernel writes carries the state.

#[cfg(test)]
mod tests;

use crate::Abi;

/// Signals are numbered from 1 to this, the same on both architectures.
pub const NSIG: u64 = 64;

pub const SIGHUP: u64 = 1;
pub const SIGINT: u64 = 2;
pub const SIGQUIT: u64 = 3;
pub const SIGILL: u64 = 4;
pub const SIGTRAP: u64 = 5;
pub const SIGABRT: u64 = 6;
pub const SIGBUS: u64 = 7;
pub const SIGFPE: u64 = 8;
pub const SIGKILL: u64 = 9;
pub const SIGUSR1: u64 = 10;
pub const SIGSEGV: u64 = 11;
pub const SIGUSR2: u64 = 12;
pub const SIGPIPE: u64 = 13;
pub const SIGALRM: u64 = 14;
pub const SIGTERM: u64 = 15;
pub const SIGCHLD: u64 = 17;
pub const SIGCONT: u64 = 18;
pub const SIGSTOP: u64 = 19;
pub const SIGTSTP: u64 = 20;
pub const SIGTTIN: u64 = 21;
pub const SIGTTOU: u64 = 22;
pub const SIGURG: u64 = 23;
pub const SIGXCPU: u64 = 24;
pub const SIGXFSZ: u64 = 25;
pub const SIGWINCH: u64 = 28;
pub const SIGSYS: u64 = 31;

/// `sig`'s bit in a signal set, or zero for a number that is no signal.
pub const fn bit(sig: u64) -> u64 {
    if sig == 0 || sig > NSIG {
        0
    } else {
        1 << (sig - 1)
    }
}

/// The two signals no mask blocks and no handler catches.
pub const UNBLOCKABLE: u64 = bit(SIGKILL) | bit(SIGSTOP);

/// Whether `sig` is one a fault raises on the thread that faulted, rather than one a process
/// sends. Its `siginfo` carries the address that faulted in place of a sender's pid, and it
/// cannot be held off: the instruction that raised it runs again as soon as the thread does.
pub const fn from_fault(sig: u64) -> bool {
    matches!(sig, SIGSEGV | SIGBUS | SIGFPE | SIGILL | SIGTRAP)
}

/// What a signal does when its disposition is the default.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Default {
    /// End the process.
    Terminate,
    /// End the process, where Linux would also write a core file. None is written.
    Core,
    /// Nothing.
    Ignore,
    /// Stop the process until `SIGCONT`.
    Stop,
}

/// `sig`'s default action, by Linux's `signal(7)`. Real-time signals, 32 to 64, terminate.
pub const fn default_action(sig: u64) -> Default {
    match sig {
        SIGQUIT | SIGILL | SIGTRAP | SIGABRT | SIGBUS | SIGFPE | SIGSEGV | SIGXCPU | SIGXFSZ
        | SIGSYS => Default::Core,
        SIGCHLD | SIGCONT | SIGURG | SIGWINCH => Default::Ignore,
        SIGSTOP | SIGTSTP | SIGTTIN | SIGTTOU => Default::Stop,
        _ => Default::Terminate,
    }
}

/// `sa_handler`'s two values that are not handlers.
pub const SIG_DFL: u64 = 0;
pub const SIG_IGN: u64 = 1;

/// `sa_flags`, the same on both architectures.
pub mod flags {
    pub const SA_NOCLDSTOP: u64 = 0x1;
    pub const SA_NOCLDWAIT: u64 = 0x2;
    pub const SA_SIGINFO: u64 = 0x4;
    pub const SA_RESTORER: u64 = 0x0400_0000;
    pub const SA_ONSTACK: u64 = 0x0800_0000;
    pub const SA_RESTART: u64 = 0x1000_0000;
    pub const SA_NODEFER: u64 = 0x4000_0000;
    pub const SA_RESETHAND: u64 = 0x8000_0000;
}

/// `rt_sigprocmask`'s `how`.
pub const SIG_BLOCK: u64 = 0;
pub const SIG_UNBLOCK: u64 = 1;
pub const SIG_SETMASK: u64 = 2;

/// The only `sigsetsize` the calls accept: the kernel's `sigset_t` is one 64-bit word.
pub const SIGSET_BYTES: u64 = 8;

/// `stack_t`'s "no alternate stack".
pub const SS_DISABLE: i32 = 2;
/// Bytes of a `stack_t`.
pub const STACK_T_BYTES: usize = 24;

/// `siginfo`'s `si_code` for a signal `kill` sent, one `tgkill` sent, and one the kernel raised.
pub const SI_USER: i32 = 0;
/// `si_code` for a signal `rt_sigqueueinfo` queued, which carries a value.
pub const SI_QUEUE: i32 = -1;
pub const SI_TKILL: i32 = -6;
pub const SI_KERNEL: i32 = 0x80;

/// One `struct sigaction`, as the kernel's calls read it on both architectures: the handler,
/// the flags, the restorer, the mask.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Action {
    pub handler: u64,
    pub flags: u64,
    pub restorer: u64,
    pub mask: u64,
}

/// Bytes of a `struct sigaction`.
pub const ACTION_BYTES: usize = 32;

impl Action {
    /// The disposition every signal starts with.
    pub const DEFAULT: Action = Action {
        handler: SIG_DFL,
        flags: 0,
        restorer: 0,
        mask: 0,
    };

    pub fn from_bytes(b: &[u8; ACTION_BYTES]) -> Action {
        let word = |i: usize| u64::from_le_bytes(array8(b, i * 8));
        Action {
            handler: word(0),
            flags: word(1),
            restorer: word(2),
            mask: word(3),
        }
    }

    pub fn to_bytes(&self) -> [u8; ACTION_BYTES] {
        let mut b = [0u8; ACTION_BYTES];
        for (i, w) in [self.handler, self.flags, self.restorer, self.mask]
            .into_iter()
            .enumerate()
        {
            b[i * 8..i * 8 + 8].copy_from_slice(&w.to_le_bytes());
        }
        b
    }
}

/// What delivering a signal does, given its disposition.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Effect {
    /// Discard it.
    Ignore,
    /// End the process, reporting the signal.
    Terminate,
    /// Run the handler.
    Handle,
}

/// The effect of `sig` under `action`. `SIGKILL` and `SIGSTOP` never take a disposition, and a
/// stop, which this kernel does not implement, is ignored.
pub const fn effect(sig: u64, action: &Action) -> Effect {
    if sig == SIGKILL {
        return Effect::Terminate;
    }
    let default = match default_action(sig) {
        Default::Terminate | Default::Core => Effect::Terminate,
        Default::Ignore | Default::Stop => Effect::Ignore,
    };
    if sig == SIGSTOP {
        return default;
    }
    match action.handler {
        SIG_DFL => default,
        SIG_IGN => Effect::Ignore,
        _ => Effect::Handle,
    }
}

/// The exit code a process ended by `sig` is recorded with: tagged, so it cannot be mistaken
/// for a code a program chose, whose low byte is all `wait4` reports, nor for the kernel's
/// "killed" of all ones.
pub const fn exit_code(sig: u64) -> u64 {
    SIGNALLED | (sig & 0x7f)
}

const SIGNALLED: u64 = 0x5349_474e_0000_0000;

/// The signal an exit code [`exit_code`] made names, or `None` for any other code.
pub const fn exit_signal(code: u64) -> Option<u64> {
    if code & !0x7f == SIGNALLED {
        Some(code & 0x7f)
    } else {
        None
    }
}

/// The status `wait4` reports for a child `sig` ended: the signal in the low 7 bits. No core
/// file is written, so the core bit is never set.
pub const fn status(sig: u64) -> u32 {
    (sig & 0x7f) as u32
}

// ---- the frame --------------------------------------------------------------------------

/// Where a frame carries saved floating-point state: x86_64's `fpstate` pointer, and the first
/// record in aarch64's reserved space. [`restore`] reads both, and refuses a frame whose
/// pointer, magic or size is not the one this kernel writes.
pub const FPSTATE_AT: usize = x86::FPSTATE;
pub const RECORD_AT: usize = a64::RECORD;

/// Where the saved registers themselves begin, as an offset into the frame: behind x86_64's
/// pointer, and past the `fpsimd_context` header on aarch64. The personality fills these bytes
/// from `hal::HasFpu::save_live` and hands them back to `load_live`; this crate only places
/// them, because it depends on nothing and has no architecture to ask.
pub const FPU_AT: [usize; 2] = [x86::FPSTATE_AREA, a64::RECORD + a64::RECORD_HEADER];

/// Bytes of floating-point state each port's frame carries. The personality asserts these
/// against `hal::HasFpu::FPU_BYTES` at compile time, so the layout here and the image the port
/// actually saves cannot drift apart.
pub const FPU_BYTES: [usize; 2] = [x86::FPSTATE_BYTES, a64::FPSIMD_BYTES];

/// What a well-formed `fpsimd_context` header holds on aarch64: Linux's magic, and the size
/// covering the header and the state together. Public because the fuzz target checks an
/// accepted frame against them, which it cannot do with the layout module private.
pub const FPSIMD_MAGIC: u32 = a64::FPSIMD_MAGIC;
pub const FPSIMD_SIZE: usize = a64::FPSIMD_SIZE;

/// Words of a context; see the module documentation for the order.
pub const REGISTER_WORDS: usize = 34;

const _: () = {
    // [`FPU_AT`] and [`FPU_BYTES`] are indexed by `abi as usize`. `Abi` names its variants in
    // this order and nothing pins the discriminants, so a reordering would hand each port the
    // other's offsets — a frame that still builds, still restores, and is wrong.
    assert!(Abi::X86_64 as usize == 0);
    assert!(Abi::Aarch64 as usize == 1);
};

/// The most bytes [`Built::head`] holds: aarch64's frame up to and including its
/// `fpsimd_context` record and the null record that terminates it, which is the longer of the
/// two ports' heads.
pub const HEAD_BYTES: usize = a64::RECORD + a64::RECORD_HEADER + a64::FPSIMD_BYTES + 8;

const _: () = {
    // Both heads fit, and x86_64's whole frame does: `build` writes into `[u8; HEAD_BYTES]`.
    assert!(HEAD_BYTES >= x86::FRAME);
    assert!(HEAD_BYTES == 1128);
    // The x86_64 area is 16-aligned in user memory. A frame starts at `at ≡ 8 (mod 16)`, so an
    // area at an offset ≡ 8 (mod 16) lands on a multiple of 16 — which is what `FXRSTOR`
    // requires of a program that restores the frame itself.
    assert!((x86::FPSTATE_AREA + 8) % 16 == 0);
    assert!(x86::FPSTATE_AREA + x86::FPSTATE_BYTES == x86::FRAME);
    // aarch64's record is `fpsimd_context`: an 8-byte header then the state, and the size the
    // header declares covers both.
    assert!(a64::RECORD_HEADER + a64::FPSIMD_BYTES == a64::FPSIMD_SIZE);
    assert!(a64::FPSIMD_SIZE == 0x210);
    // The record and its terminator stay inside the 4 KiB of reserved space.
    assert!(a64::RECORD + a64::FPSIMD_SIZE + 8 <= a64::FRAME);
};

/// What delivering one signal to a handler needs besides the context.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Delivery {
    pub sig: u64,
    pub action: Action,
    /// The mask the thread had, which `rt_sigreturn` restores.
    pub old_mask: u64,
    /// `si_code`, and the sender's pid for a signal a process sent.
    pub code: i32,
    pub pid: u32,
    /// For a signal a fault raised, the address that faulted: `siginfo`'s `si_addr`, which
    /// shares its bytes with `si_pid`. `None` for every other signal, which leaves those
    /// bytes to the sender's pid.
    pub addr: Option<u64>,
    /// `si_value`, the word `rt_sigqueueinfo` carries, for a delivery whose `code` is
    /// [`SI_QUEUE`]. Zero for every other, which writes no value at all.
    pub value: u64,
}

/// A frame laid out for a thread's stack.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Built {
    /// Where the frame starts: the handler's stack pointer.
    pub at: u64,
    /// The frame's first bytes, written at `at`.
    pub head: [u8; HEAD_BYTES],
    pub head_len: usize,
    /// Zero bytes that follow the head: aarch64's reserved space.
    pub zeros: usize,
    /// aarch64's frame record, and where it goes: the interrupted `x29` and `x30`, which the
    /// handler's `x29` points at so a debugger can walk through the frame.
    pub record: Option<(u64, [u8; 16])>,
    /// The registers the handler starts with.
    pub regs: [u64; REGISTER_WORDS],
}

/// Why a frame could not be built or read.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BadFrame {
    /// The stack does not have room below it in the user half.
    NoRoom,
    /// The frame names a return address outside the user half.
    BadReturn,
    /// aarch64: a processor state other than EL0 with condition flags.
    BadState,
    /// aarch64: a stack pointer that is not 16-byte aligned, which no frame this built has.
    Misaligned,
    /// Fewer bytes than the frame.
    Short,
    /// The frame carries saved floating-point state: x86_64's `fpstate` pointer is not null, or
    /// aarch64's reserved space holds a record. Nothing here can restore those registers, and a
    /// frame accepted with them unread would tell a program otherwise.
    FpState,
}

/// The x86_64 layout: `rt_sigframe` is the return address, a `ucontext` and a `siginfo`.
mod x86 {
    /// The whole frame: everything up to the floating-point area, then the area itself.
    pub const FRAME: usize = FPSTATE_AREA + FPSTATE_BYTES;
    pub const UC: usize = 8;
    pub const MCONTEXT: usize = UC + 40;
    /// `uc_sigmask`, after the 256-byte `sigcontext`.
    pub const SIGMASK: usize = MCONTEXT + 256;
    /// `sigcontext`'s `fpstate` pointer, after `cr2`. [`super::build`] points it at
    /// [`FPSTATE_AREA`] inside this same frame, and [`super::restore`] accepts that one value
    /// and nothing else: the area is the kernel's to place, so a frame naming anywhere else is
    /// a program asking this kernel to read memory of its choosing.
    pub const FPSTATE: usize = MCONTEXT + 23 * 8;
    /// Where the `FXSAVE` image sits, just past the rest of the frame. Linux puts its
    /// `_fpstate` above the frame too; what matters here is that it is at a fixed offset, so
    /// the pointer can be checked rather than followed.
    pub const FPSTATE_AREA: usize = 440;
    /// An `FXSAVE` image: x87, MMX and SSE, which is all a program built for
    /// `targets/x86_64-kintane-hf.json` can name. Mirrors `X86_64::FPU_BYTES`.
    pub const FPSTATE_BYTES: usize = 512;
    pub const INFO: usize = SIGMASK + 8;
    /// `sigcontext`'s first eighteen words, as indices into the port's register order.
    pub const ORDER: [usize; 18] = [7, 8, 9, 10, 11, 12, 13, 14, 5, 4, 6, 1, 3, 0, 2, 17, 15, 16];
    pub const RSP: usize = 17;
    pub const RIP: usize = 15;
    pub const RFLAGS: usize = 16;
    pub const RAX: usize = 0;
    pub const RDI: usize = 5;
    pub const RSI: usize = 4;
    pub const RDX: usize = 3;
    /// The red zone a function may use below its stack pointer, which a frame skips.
    pub const RED_ZONE: u64 = 128;
    /// Flags a program may hold, and the ones every return to it carries: the same policy as
    /// `arch/x86_64/src/user.rs`.
    pub const USER_FLAGS: u64 = 0xcd5;
    pub const START_FLAGS: u64 = 0x202;
    /// The direction flag, which a handler starts with clear.
    pub const DF: u64 = 0x400;
    /// `sigcontext`'s segment word: `cs`, `gs`, `fs`, `ss`, for the program to read. Never read
    /// back.
    pub const SEGMENTS: u64 = (0x2b << 48) | 0x33;
}

/// The aarch64 layout: `rt_sigframe` is a `siginfo` and a `ucontext`, with a frame record above.
mod a64 {
    pub const INFO: usize = 0;
    pub const UC: usize = 128;
    pub const SIGMASK: usize = UC + 40;
    /// `uc_mcontext`, after `__unused` pads `uc_sigmask` to glibc's 1024 bits and the
    /// `sigcontext`'s 16-byte alignment rounds it up.
    pub const MCONTEXT: usize = UC + 176;
    pub const REGS: usize = MCONTEXT + 8;
    pub const SP: usize = REGS + 31 * 8;
    pub const PC: usize = SP + 8;
    pub const PSTATE: usize = PC + 8;
    /// The reserved space, 4 KiB aligned to 16.
    pub const RESERVED: usize = MCONTEXT + 288;
    /// The first record in it: a magic and a size, then the state. [`super::build`] writes a
    /// `fpsimd_context` here and a terminating null record above it, and [`super::restore`]
    /// requires exactly that — Linux's own magic and Linux's own size, or the frame is refused.
    pub const RECORD: usize = RESERVED;
    /// `struct _aarch64_ctx`: a magic word and a size word.
    pub const RECORD_HEADER: usize = 8;
    /// `fpsimd_context`'s magic, which is Linux's: "FPSB" little-endian.
    pub const FPSIMD_MAGIC: u32 = 0x4650_5342;
    /// The state behind the header: `fpsr` and `fpcr` as 32-bit fields, then the 32 V
    /// registers. Mirrors `Aarch64::FPU_BYTES`.
    pub const FPSIMD_BYTES: usize = 8 + 32 * 16;
    /// What the header's size field declares: the header and the state together, which is what
    /// Linux writes and what a program walking the records steps over.
    pub const FPSIMD_SIZE: usize = RECORD_HEADER + FPSIMD_BYTES;
    pub const FRAME: usize = RESERVED + 4096;
    pub const X29: usize = 29;
    pub const X30: usize = 30;
    pub const W_SP: usize = 31;
    pub const W_PC: usize = 32;
    pub const W_PSTATE: usize = 33;
    /// The condition flags, the only part of `PSTATE` a program holds.
    pub const USER_PSTATE: u64 = 0xf000_0000;
}

impl Abi {
    /// Bytes of the system call instruction, which a restarted call returns to.
    pub const fn syscall_len(self) -> u64 {
        match self {
            Abi::X86_64 => 2,
            Abi::Aarch64 => 4,
        }
    }

    /// The word a context keeps its program counter in.
    pub const fn pc_word(self) -> usize {
        match self {
            Abi::X86_64 => x86::RIP,
            Abi::Aarch64 => a64::W_PC,
        }
    }

    /// The word a context keeps its stack pointer in.
    pub const fn sp_word(self) -> usize {
        match self {
            Abi::X86_64 => x86::RSP,
            Abi::Aarch64 => a64::W_SP,
        }
    }

    /// Bytes of the frame [`restore`] reads.
    ///
    /// Both now reach past the registers to the saved floating-point state: x86_64's whole
    /// frame including the `FXSAVE` area at its end, and aarch64's up to and including the null
    /// record that terminates the `fpsimd_context`. This length, [`HEAD_BYTES`], the copy
    /// `build` asks for and the copy `rt_sigreturn` makes all move together — a frame written
    /// longer than it is read back would hand a program registers the kernel never looks at.
    pub const fn restore_len(self) -> usize {
        match self {
            Abi::X86_64 => x86::FRAME,
            Abi::Aarch64 => a64::RECORD + a64::FPSIMD_SIZE + 8,
        }
    }

    /// Where this port's frame keeps the saved floating-point state, as an offset into it, and
    /// how many bytes of it there are. The personality fills them before the frame is written
    /// and hands them back to the port after [`restore`] accepts one.
    pub const fn fpu_at(self) -> usize {
        FPU_AT[self as usize]
    }

    pub const fn fpu_bytes(self) -> usize {
        FPU_BYTES[self as usize]
    }

    /// Where `rt_sigreturn` finds the frame, given the stack pointer it was called with: x86_64's
    /// handler has returned into the restorer, popping the return address, and aarch64's
    /// returns with the stack pointer the frame gave it.
    pub fn frame_at(self, sp: u64) -> Result<u64, BadFrame> {
        match self {
            Abi::X86_64 => sp.checked_sub(8).ok_or(BadFrame::NoRoom),
            Abi::Aarch64 if sp % 16 != 0 => Err(BadFrame::Misaligned),
            Abi::Aarch64 => Ok(sp),
        }
    }
}

fn array8(b: &[u8], at: usize) -> [u8; 8] {
    let mut w = [0u8; 8];
    w.copy_from_slice(&b[at..at + 8]);
    w
}

fn put(b: &mut [u8], at: usize, v: u64) {
    b[at..at + 8].copy_from_slice(&v.to_le_bytes());
}

fn put32(b: &mut [u8], at: usize, v: u32) {
    b[at..at + 4].copy_from_slice(&v.to_le_bytes());
}

/// `siginfo` for `d`, at `at`.
///
/// The union after `si_signo`, `si_errno` and `si_code` is what the signal decides: a fault
/// puts the address that raised it in `_sigfault.si_addr`, and everything else the sender's
/// pid in `_kill.si_pid`. Both start at the same offset, which is why one field carries both.
fn info(b: &mut [u8], at: usize, d: &Delivery) {
    put32(b, at, d.sig as u32);
    put32(b, at + 8, d.code as u32);
    match d.addr {
        Some(addr) => put(b, at + 16, addr),
        None => put32(b, at + 16, d.pid),
    }
    // A queued signal's value follows the sender's pid and uid, which is where `sigqueue`'s
    // `si_value` lives in the same union.
    if d.code == SI_QUEUE {
        put(b, at + 24, d.value);
    }
}

/// Lay out the frame delivering `d` to a thread whose registers are `ctx`, below its stack, in
/// a user half of `[user_start, user_end)`.
pub fn build(
    abi: Abi,
    ctx: &[u64; REGISTER_WORDS],
    d: &Delivery,
    user_start: u64,
    user_end: u64,
) -> Result<Built, BadFrame> {
    let mut head = [0u8; HEAD_BYTES];
    let mut regs = *ctx;
    let fits = |at: u64, len: u64| {
        at >= user_start && at.checked_add(len).is_some_and(|end| end <= user_end)
    };
    match abi {
        Abi::X86_64 => {
            let below = ctx[x86::RSP]
                .checked_sub(x86::RED_ZONE + x86::FRAME as u64)
                .ok_or(BadFrame::NoRoom)?;
            // Aligned so the handler finds its stack as a call leaves it: 8 below a multiple of 16.
            let at = (below & !15).checked_sub(8).ok_or(BadFrame::NoRoom)?;
            if !fits(at, x86::FRAME as u64) {
                return Err(BadFrame::NoRoom);
            }
            put(&mut head, 0, d.action.restorer);
            // uc_flags and uc_link are zero; uc_stack says there is no alternate stack.
            put32(&mut head, x86::UC + 24, SS_DISABLE as u32);
            for (i, &w) in x86::ORDER.iter().enumerate() {
                put(&mut head, x86::MCONTEXT + i * 8, ctx[w]);
            }
            put(&mut head, x86::MCONTEXT + 18 * 8, x86::SEGMENTS);
            // err and trapno are zero; oldmask is the mask, as Linux fills it.
            put(&mut head, x86::MCONTEXT + 21 * 8, d.old_mask);
            put(&mut head, x86::SIGMASK, d.old_mask);
            info(&mut head, x86::INFO, d);
            regs[x86::RIP] = d.action.handler;
            regs[x86::RSP] = at;
            regs[x86::RDI] = d.sig;
            regs[x86::RSI] = at + x86::INFO as u64;
            regs[x86::RDX] = at + x86::UC as u64;
            regs[x86::RAX] = 0;
            regs[x86::RFLAGS] = (ctx[x86::RFLAGS] & x86::USER_FLAGS & !x86::DF) | x86::START_FLAGS;
            // The floating-point area is part of this frame, so the pointer is the one address
            // it can be. `restore` accepts that value and no other: a program may write
            // anything here, and following a pointer of its choosing would be reading memory it
            // named. The bytes behind it are the personality's to fill; see `Abi::fpu_at`.
            put(&mut head, x86::FPSTATE, at + x86::FPSTATE_AREA as u64);
            Ok(Built {
                at,
                head,
                head_len: x86::FRAME,
                zeros: 0,
                record: None,
                regs,
            })
        }
        Abi::Aarch64 => {
            let record_at = ctx[a64::W_SP].checked_sub(16).ok_or(BadFrame::NoRoom)? & !15;
            let at = record_at
                .checked_sub(a64::FRAME as u64)
                .ok_or(BadFrame::NoRoom)?;
            if !fits(at, a64::FRAME as u64 + 16) {
                return Err(BadFrame::NoRoom);
            }
            info(&mut head, a64::INFO, d);
            put32(&mut head, a64::UC + 24, SS_DISABLE as u32);
            put(&mut head, a64::SIGMASK, d.old_mask);
            for i in 0..31 {
                put(&mut head, a64::REGS + i * 8, ctx[i]);
            }
            put(&mut head, a64::SP, ctx[a64::W_SP]);
            put(&mut head, a64::PC, ctx[a64::W_PC]);
            put(&mut head, a64::PSTATE, ctx[a64::W_PSTATE] & a64::USER_PSTATE);
            let mut record = [0u8; 16];
            put(&mut record, 0, ctx[a64::X29]);
            put(&mut record, 8, ctx[a64::X30]);
            regs[a64::W_PC] = d.action.handler;
            regs[a64::W_SP] = at;
            regs[0] = d.sig;
            regs[1] = at + a64::INFO as u64;
            regs[2] = at + a64::UC as u64;
            regs[a64::X29] = record_at;
            regs[a64::X30] = d.action.restorer;
            regs[a64::W_PSTATE] = ctx[a64::W_PSTATE] & a64::USER_PSTATE;
            // `fpsimd_context` at the head of the reserved space, then the null record that
            // terminates the chain. The size the header declares is the header and the state
            // together, which is what a program walking these records steps over. The state
            // itself is the personality's to fill; see `Abi::fpu_at`.
            put32(&mut head, a64::RECORD, a64::FPSIMD_MAGIC);
            put32(&mut head, a64::RECORD + 4, a64::FPSIMD_SIZE as u32);
            let after = a64::RECORD + a64::FPSIMD_SIZE;
            // The terminating record is a zero magic and a zero size, which `head` already
            // holds; naming it here is what makes the length below mean what it says.
            let head_len = after + 8;
            Ok(Built {
                at,
                head,
                head_len,
                zeros: a64::FRAME - head_len,
                record: Some((record_at, record)),
                regs,
            })
        }
    }
}

/// What a frame `rt_sigreturn` read holds.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Restored {
    pub regs: [u64; REGISTER_WORDS],
    /// The mask to restore, without the two signals no mask blocks.
    pub mask: u64,
}

/// Read the frame in `bytes`, [`Abi::restore_len`] of them from the address [`Abi::frame_at`]
/// gave, for a user half of `[user_start, user_end)`. Registers the frame does not hold are
/// zero.
///
/// `at` is where those bytes came from, which the caller knows and the bytes do not say. It is
/// needed because x86_64's `sigcontext` carries a *pointer* to the saved floating-point state,
/// and the only pointer this kernel accepts is the one naming the area inside this very frame.
/// The saved `rsp` in the frame is the interrupted stack pointer, not the frame's address, so
/// there is nothing in the bytes to check the pointer against.
pub fn restore(
    abi: Abi,
    bytes: &[u8],
    at: u64,
    user_start: u64,
    user_end: u64,
) -> Result<Restored, BadFrame> {
    if bytes.len() < abi.restore_len() {
        return Err(BadFrame::Short);
    }
    let word = |at: usize| u64::from_le_bytes(array8(bytes, at));
    let mut regs = [0u64; REGISTER_WORDS];
    let mask = match abi {
        Abi::X86_64 => {
            for (i, &w) in x86::ORDER.iter().enumerate() {
                regs[w] = word(x86::MCONTEXT + i * 8);
            }
            regs[x86::RFLAGS] = (regs[x86::RFLAGS] & x86::USER_FLAGS) | x86::START_FLAGS;
            // The pointer must name the area inside this very frame. `restore` is given the
            // frame's bytes and not its address, so the check is on the offset the pointer
            // implies: `at` is the frame's start and the area sits `FPSTATE_AREA` into it, so
            // a well-formed pointer is exactly that far above the `rsp` the frame restores.
            // Anything else — null, a byte past, an address elsewhere in the program — is a
            // program asking this kernel to read memory of its choosing, and is refused.
            if word(x86::FPSTATE) != at.wrapping_add(x86::FPSTATE_AREA as u64) {
                return Err(BadFrame::FpState);
            }
            word(x86::SIGMASK)
        }
        Abi::Aarch64 => {
            for (i, r) in regs.iter_mut().take(31).enumerate() {
                *r = word(a64::REGS + i * 8);
            }
            regs[a64::W_SP] = word(a64::SP);
            regs[a64::W_PC] = word(a64::PC);
            let pstate = word(a64::PSTATE);
            if pstate & !a64::USER_PSTATE != 0 {
                return Err(BadFrame::BadState);
            }
            regs[a64::W_PSTATE] = pstate;
            // The record must be the `fpsimd_context` this kernel writes: Linux's magic and
            // Linux's size, in the first record of the reserved space. A program may write any
            // bytes here, and a record claiming a different size is one asking the kernel to
            // walk a chain of its length rather than this one's.
            let magic = word(a64::RECORD) as u32;
            let size = (word(a64::RECORD) >> 32) as u32;
            if magic != a64::FPSIMD_MAGIC || size != a64::FPSIMD_SIZE as u32 {
                return Err(BadFrame::FpState);
            }
            word(a64::SIGMASK)
        }
    };
    let pc = regs[abi.pc_word()];
    if !(user_start..user_end).contains(&pc) {
        return Err(BadFrame::BadReturn);
    }
    Ok(Restored {
        regs,
        mask: mask & !UNBLOCKABLE,
    })
}

/// Whether a context is one a return to user mode may carry: its program counter in the user
/// half, and its flags or processor state a program's own. What [`restore`] guarantees of
/// every frame it accepts, and what the fuzz target asserts.
pub fn is_user_context(
    abi: Abi,
    regs: &[u64; REGISTER_WORDS],
    user_start: u64,
    user_end: u64,
) -> bool {
    let pc_ok = (user_start..user_end).contains(&regs[abi.pc_word()]);
    let state_ok = match abi {
        Abi::X86_64 => {
            let f = regs[x86::RFLAGS];
            f & !(x86::USER_FLAGS | x86::START_FLAGS) == 0
                && f & x86::START_FLAGS == x86::START_FLAGS
        }
        Abi::Aarch64 => regs[a64::W_PSTATE] & !a64::USER_PSTATE == 0,
    };
    pc_ok && state_ok
}

//! The AArch64 exception vector table and the common entry/exit path.
//!
//! # The shape the architecture dictates
//!
//! `VBAR_EL1` points at a table of sixteen entries, each exactly 128 bytes, and the
//! table itself must be 2 KiB aligned. The sixteen are four groups of four — sync,
//! IRQ, FIQ, SError — one group per origin:
//!
//! | offset | origin |
//! |---|---|
//! | 0x000 | current EL, `SP_EL0` selected |
//! | 0x200 | current EL, `SP_ELx` selected |
//! | 0x400 | lower EL, AArch64 |
//! | 0x600 | lower EL, AArch32 |
//!
//! This kernel runs at EL1h — EL1 with `SP_EL1` — so every exception it takes today
//! lands in the 0x200 group. The other twelve are filled in anyway: an unexpected
//! exception that lands on an unfilled entry executes whatever happens to be there,
//! which is the worst possible failure mode. All sixteen therefore reach the same
//! reporting path, carrying an index that says which one fired.
//!
//! # Why there is a common path
//!
//! 128 bytes is 32 instructions, which is not enough room to save the general-purpose
//! registers, call into Rust, restore, and `eret`. Each entry therefore does the
//! minimum — open a frame, stash `x0`, load the vector index into `x0` — and branches
//! to [`__exc_common`], which does the rest once.
//!
//! # What is saved
//!
//! All of `x0`–`x30`, plus `ELR_EL1` and `SPSR_EL1` because `eret` consumes them and a
//! nested exception would otherwise destroy the outer return address, plus `ESR_EL1`
//! and `FAR_EL1` because they are the only description of *why* a synchronous
//! exception happened and they are not preserved either.
//!
//! Nothing floating-point is saved. The image is built softfloat with `-neon`, so it
//! has no FP state to lose; that changes with the context switch in Phase 2.
//!
//! Reference: Arm Architecture Reference Manual for A-profile, DDI 0487, D1.10
//! ("Exception entry") and D17.2.144 (`VBAR_EL1`).

use hal::EarlyConsole;

use crate::serial::EARLY;

core::arch::global_asm!(
    r#"
// One vector entry: open the frame, save x0 so there is a scratch register, put the
// vector index where the common path expects it, and go. Four instructions, padded to
// the 128 bytes the architecture requires.
.macro VECTOR index
    sub     sp, sp, #0x120
    str     x0, [sp, #0x00]
    mov     x0, #\index
    b       __exc_common
    .balign 0x80
.endm

// The synchronous entry for the stack the kernel runs on, which is the one entry that can
// be reached *because* that stack overflowed. The test is too long for a vector slot, so
// the slot only branches to it; see `__sync_spx_entry` below.
.macro VECTOR_SYNC_SPX index
    b       __sync_spx_entry
    .balign 0x80
.endm

// Branch to 9f if the address in x0 is in a guard page: the boot stack's, or the bottom
// page of any slot in the thread-stack array. Touches no memory. Clobbers x0 and x1.
.macro GUARD_TEST
    bic     x0, x0, #0xfff
    adrp    x1, __stack_guard_start
    cmp     x0, x1
    b.eq    9f
    adrp    x1, __thread_stacks_end
    cmp     x0, x1
    b.hs    1f
    adrp    x1, __thread_stacks_start
    subs    x0, x0, x1
    b.lo    1f
    and     x0, x0, #{slot_mask}
    cmp     x0, #{guard}
    b.lo    9f
1:
.endm

.section .text.vectors, "ax"
.balign 0x800
.globl __exception_vectors
__exception_vectors:
    VECTOR 0            // current EL, SP_EL0: synchronous
    VECTOR 1            // current EL, SP_EL0: IRQ
    VECTOR 2            // current EL, SP_EL0: FIQ
    VECTOR 3            // current EL, SP_EL0: SError
    VECTOR_SYNC_SPX 4   // current EL, SP_ELx: synchronous
    VECTOR 5            // current EL, SP_ELx: IRQ
    VECTOR 6            // current EL, SP_ELx: FIQ
    VECTOR 7            // current EL, SP_ELx: SError
    VECTOR 8            // lower EL, AArch64: synchronous
    VECTOR 9            // lower EL, AArch64: IRQ
    VECTOR 10           // lower EL, AArch64: FIQ
    VECTOR 11           // lower EL, AArch64: SError
    VECTOR 12           // lower EL, AArch32: synchronous
    VECTOR 13           // lower EL, AArch32: IRQ
    VECTOR 14           // lower EL, AArch32: FIQ
    VECTOR 15           // lower EL, AArch32: SError

// Before opening a frame, check, touching no memory, whether the frame would touch a guard
// page. If it would, the store faults, the next exception opens its frame 0x120 lower,
// beneath the guard, and succeeds there: on top of `.bss` below the boot stack, or on top
// of the stack of the thread whose slot is below. So it goes to the overflow path in
// `kspace.rs` instead, which runs on a stack of its own.
//
// Two addresses are tested. The frame's bottom, `sp - 0x120`, catches a frame that would
// open inside a guard. `sp - 1` catches a stack pointer that is already in one, whose
// frame would open below it. A guard page is larger than a frame, so between them nothing
// the frame writes can be in a guard page unnoticed.
//
// Two registers are scratch. `SP_EL0` is one: this entry is taken only at EL1 on `SP_EL1`,
// and the process stack pointer it banks is already in the frame of the trap from EL0 that
// brought the kernel here, which restores it on the way back. `TPIDRRO_EL0` is the other,
// zeroed again before anything returns, so a program reading it never sees a kernel value.
// `TPIDR_EL0` is not: it is a thread's own, which its program sets at EL0 and the context
// switch carries (`context.rs`).
__sync_spx_entry:
    msr     tpidrro_el0, x0
    msr     sp_el0, x1
    sub     x0, sp, #0x120
    GUARD_TEST
    sub     x0, sp, #1
    GUARD_TEST
    mrs     x1, sp_el0
    mrs     x0, tpidrro_el0
    msr     tpidrro_el0, xzr
    sub     sp, sp, #0x120
    str     x0, [sp, #0x00]
    mov     x0, #4
    b       __exc_common
9:
    mrs     x1, sp_el0
    mrs     x0, tpidrro_el0
    msr     tpidrro_el0, xzr
    b       __kspace_stack_overflow

// x0 holds the vector index; the frame is open and x0's original value is in it.
// The offsets below are the layout of `TrapFrame` and the two must change together.
__exc_common:
    str     x1, [sp, #0x08]
    stp     x2, x3, [sp, #0x10]
    stp     x4, x5, [sp, #0x20]
    stp     x6, x7, [sp, #0x30]
    stp     x8, x9, [sp, #0x40]
    stp     x10, x11, [sp, #0x50]
    stp     x12, x13, [sp, #0x60]
    stp     x14, x15, [sp, #0x70]
    stp     x16, x17, [sp, #0x80]
    stp     x18, x19, [sp, #0x90]
    stp     x20, x21, [sp, #0xa0]
    stp     x22, x23, [sp, #0xb0]
    stp     x24, x25, [sp, #0xc0]
    stp     x26, x27, [sp, #0xd0]
    stp     x28, x29, [sp, #0xe0]
    mrs     x1, elr_el1
    stp     x30, x1, [sp, #0xf0]
    mrs     x1, spsr_el1
    mrs     x2, esr_el1
    stp     x1, x2, [sp, #0x100]
    mrs     x1, far_el1
    str     x1, [sp, #0x110]
    // SP_EL0 is a process's stack pointer, and banked rather than saved by the CPU on an
    // exception. A handler that switches threads — a timer tick from EL0 — can return to
    // EL0 in another process, which sets SP_EL0 to its own, so each frame keeps the value
    // its own `eret` must restore.
    mrs     x1, sp_el0
    str     x1, [sp, #0x118]

    // (index, &mut TrapFrame) — the AAPCS64 argument registers, in order.
    mov     x1, sp
    bl      aarch64_exception

    // SPSR and ELR are restored from the frame rather than left alone, so that a
    // handler may legitimately redirect the return and so that a nested exception
    // cannot silently corrupt the outer one's return state.
    ldr     x1, [sp, #0x118]
    msr     sp_el0, x1
    ldp     x1, x2, [sp, #0x100]
    msr     spsr_el1, x1
    ldp     x30, x1, [sp, #0xf0]
    msr     elr_el1, x1
    ldp     x28, x29, [sp, #0xe0]
    ldp     x26, x27, [sp, #0xd0]
    ldp     x24, x25, [sp, #0xc0]
    ldp     x22, x23, [sp, #0xb0]
    ldp     x20, x21, [sp, #0xa0]
    ldp     x18, x19, [sp, #0x90]
    ldp     x16, x17, [sp, #0x80]
    ldp     x14, x15, [sp, #0x70]
    ldp     x12, x13, [sp, #0x60]
    ldp     x10, x11, [sp, #0x50]
    ldp     x8, x9, [sp, #0x40]
    ldp     x6, x7, [sp, #0x30]
    ldp     x4, x5, [sp, #0x20]
    ldp     x2, x3, [sp, #0x10]
    ldp     x0, x1, [sp, #0x00]
    add     sp, sp, #0x120
    eret
"#,
    slot_mask = const crate::THREAD_STACK_SLOT - 1,
    guard = const <crate::Aarch64 as hal::Arch>::PAGE_SIZE,
);

/// Register state saved by `__exc_common`, in the order it writes it.
///
/// `repr(C)` and the offsets in the assembly above are one definition split across two
/// languages; changing either without the other is silent memory corruption.
#[repr(C)]
pub(crate) struct TrapFrame {
    /// `x0` through `x30`, indexed by register number.
    pub(crate) x: [u64; 31],
    /// Address the exception will return to.
    pub(crate) elr: u64,
    /// Processor state to restore on return.
    pub(crate) spsr: u64,
    /// Syndrome — the reason for a synchronous exception.
    esr: u64,
    /// Faulting address, when the syndrome says there is one.
    far: u64,
    /// The interrupted context's `SP_EL0`, restored on return. It is also what keeps the
    /// frame a multiple of 16, which SP must always be.
    pub(crate) sp_el0: u64,
}

/// Vector index for "current EL with `SP_ELx`, IRQ" — the only entry a working kernel
/// reaches during normal operation.
const VEC_CURRENT_SPX_IRQ: u64 = 5;

/// Vector index for "current EL with `SP_ELx`, synchronous": where a kernel page fault
/// arrives.
const VEC_CURRENT_SPX_SYNC: u64 = 4;

/// Vector index for "lower EL, AArch64, IRQ": an interrupt taken while a process runs.
const VEC_LOWER_A64_IRQ: u64 = 9;

/// Handle a synchronous exception from a lower EL (a system call or fault from EL0).
/// Returns `true` if it took it. The two definitions keep the `cfg` at item level.
///
/// # Safety
/// `frame` is the live exception frame.
#[cfg(CONFIG_USERSPACE)]
unsafe fn try_user_sync(index: u64, frame: *mut TrapFrame) -> bool {
    // Vector 8 is "lower EL, AArch64, synchronous".
    if index != 8 {
        return false;
    }
    // SAFETY: forwarded; `frame` is live.
    let (esr, far) = unsafe { ((*frame).esr, (*frame).far) };
    unsafe { crate::user::on_lower_sync(esr, far, frame) };
    true
}

/// No userspace port: nothing from a lower EL to take.
///
/// # Safety
/// None; matches the userspace form's signature.
#[cfg(not(CONFIG_USERSPACE))]
unsafe fn try_user_sync(_index: u64, _frame: *mut TrapFrame) -> bool {
    false
}

/// The last thing an IRQ taken from EL0 does before it returns: the kernel may end the thread
/// there instead (`hal::user::UserHooks::interrupted`). The two definitions keep the `cfg` at
/// item level.
#[cfg(CONFIG_USERSPACE)]
fn returning_to_user() {
    crate::user::interrupted();
}

/// No userspace port: nothing at EL0 to return to.
#[cfg(not(CONFIG_USERSPACE))]
fn returning_to_user() {}

/// Install the vector table in `VBAR_EL1`.
///
/// # Safety
/// Must be called with interrupts masked, on a CPU running at EL1, before anything
/// enables an interrupt source. Installing it twice is harmless; installing it late is
/// not, because every exception before this point is unrecoverable.
pub unsafe fn install_vectors() {
    // SAFETY: `__exception_vectors` is a 2 KiB-aligned, 16-entry table defined in the
    // assembly above and linked into `.text`, which is exactly what VBAR_EL1 requires.
    // The kernel is identity-mapped, so the link-time address is both the virtual
    // address VBAR_EL1 takes and the physical address behind it — and this is called
    // once before the MMU is enabled and again after, with the same answer either
    // way. `isb` is what makes the new table visible to exceptions taken by
    // instructions after this point rather than at some later context-synchronising
    // event. Writing VBAR_EL1 is permitted at EL1 and has no other effect.
    unsafe {
        core::arch::asm!(
            "adrp {t}, __exception_vectors",
            "add  {t}, {t}, :lo12:__exception_vectors",
            "msr  vbar_el1, {t}",
            "isb",
            t = out(reg) _,
            options(nomem, nostack, preserves_flags)
        );
    }
}

/// The one Rust entry point for every exception this kernel takes.
///
/// Called from `__exc_common` with the vector index and the saved state. Returning
/// from it resumes the interrupted context.
#[unsafe(no_mangle)]
extern "C" fn aarch64_exception(index: u64, frame: *mut TrapFrame) {
    // An interrupt is the same interrupt whether it arrived while the kernel ran or while
    // a process did. From EL0 it lands on the running thread's kernel stack, exactly as
    // one from EL1 does, so a timer tick that switches threads here resumes the process
    // later through this same frame. Before processes ran under the scheduler nothing at
    // EL0 was ever interrupted, and index 9 was reported as unhandled.
    if index == VEC_CURRENT_SPX_IRQ || index == VEC_LOWER_A64_IRQ {
        crate::irq::dispatch();
        if index == VEC_LOWER_A64_IRQ {
            returning_to_user();
        }
        return;
    }

    // A synchronous exception from a lower EL (index 8) is a system call or a fault from a
    // user process, handled without ever reaching the fatal path — which would halt the
    // kernel for a program's mistake. `try_user_sync` is a no-op without a userspace port.
    // SAFETY: `frame` is the live exception frame.
    if unsafe { try_user_sync(index, frame) } {
        return;
    }

    // Everything else is unexpected in Phase 0. Say precisely what happened — the
    // vector that fired and the syndrome — and stop, because continuing from an
    // exception nobody has written a handler for is guesswork.
    //
    // SAFETY: `frame` points at the stack frame `__exc_common` just filled in, which
    // is live for the whole call and is not aliased by anything else.
    let (esr, elr, far, spsr) =
        unsafe { ((*frame).esr, (*frame).elr, (*frame).far, (*frame).spsr) };

    // A page fault the kernel resolves returns to the faulting instruction; `fault.rs`
    // decides which aborts are offered.
    if index == VEC_CURRENT_SPX_SYNC && crate::fault::route(esr, far) {
        return;
    }

    let c = &EARLY;
    c.write_str("\n\nunhandled exception: vector ");
    write_dec(c, index);
    c.write_str("\n  esr  ");
    write_hex(c, esr);
    c.write_str("\n  elr  ");
    write_hex(c, elr);
    c.write_str("\n  far  ");
    write_hex(c, far);
    c.write_str("\n  spsr ");
    write_hex(c, spsr);
    c.write_str("\n");
    crate::backtrace::print(c, Some(elr as usize), crate::backtrace::EXCEPTION_FRAMES);
    crate::kspace::after_fault_report(c, esr, far, frame as u64);

    <crate::Aarch64 as hal::Arch>::halt()
}

/// Write `v` in decimal. Shared with the context switch selftest.
pub(crate) fn write_dec(c: &dyn EarlyConsole, mut v: u64) {
    if v == 0 {
        c.write_bytes(b"0");
        return;
    }
    let mut buf = [0u8; 20];
    let mut i = buf.len();
    while v > 0 {
        i -= 1;
        buf[i] = b'0' + (v % 10) as u8;
        v /= 10;
    }
    c.write_bytes(&buf[i..]);
}

/// Write `v` as sixteen hex digits. Shared with the context switch's fatal path.
pub(crate) fn write_hex(c: &dyn EarlyConsole, v: u64) {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut buf = [0u8; 18];
    buf[0] = b'0';
    buf[1] = b'x';
    for i in 0..16 {
        buf[2 + i] = DIGITS[((v >> (60 - i * 4)) & 0xf) as usize];
    }
    c.write_bytes(&buf);
}

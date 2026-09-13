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
// be reached *because* that stack overflowed. Before opening a frame it checks, touching
// no memory, whether the frame would land in the boot stack's guard page. If it would,
// the store below faults, the next exception opens its frame 0x120 lower, beneath the
// guard, and succeeds there — on top of `.bss`. So it goes to the overflow path in
// `kspace.rs` instead, which runs on a stack of its own. The two EL0 thread-pointer
// registers are scratch: nothing runs at EL0, so nothing reads them.
.macro VECTOR_SYNC_SPX index
    msr     tpidrro_el0, x0
    msr     tpidr_el0, x1
    sub     x0, sp, #0x120
    and     x0, x0, #0xfffffffffffff000
    adrp    x1, __stack_guard_start
    cmp     x0, x1
    mrs     x1, tpidr_el0
    mrs     x0, tpidrro_el0
    b.eq    __kspace_stack_overflow
    sub     sp, sp, #0x120
    str     x0, [sp, #0x00]
    mov     x0, #\index
    b       __exc_common
    .balign 0x80
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

    // (index, &mut TrapFrame) — the AAPCS64 argument registers, in order.
    mov     x1, sp
    bl      aarch64_exception

    // SPSR and ELR are restored from the frame rather than left alone, so that a
    // handler may legitimately redirect the return and so that a nested exception
    // cannot silently corrupt the outer one's return state.
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
"#
);

/// Register state saved by `__exc_common`, in the order it writes it.
///
/// `repr(C)` and the offsets in the assembly above are one definition split across two
/// languages; changing either without the other is silent memory corruption.
#[repr(C)]
struct TrapFrame {
    /// `x0` through `x30`, indexed by register number.
    x: [u64; 31],
    /// Address the exception will return to.
    elr: u64,
    /// Processor state to restore on return.
    spsr: u64,
    /// Syndrome — the reason for a synchronous exception.
    esr: u64,
    /// Faulting address, when the syndrome says there is one.
    far: u64,
    /// Keeps the frame a multiple of 16, which SP must always be.
    _pad: u64,
}

/// Vector index for "current EL with `SP_ELx`, IRQ" — the only entry a working kernel
/// reaches during normal operation.
const VEC_CURRENT_SPX_IRQ: u64 = 5;

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
    if index == VEC_CURRENT_SPX_IRQ {
        crate::irq::dispatch();
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

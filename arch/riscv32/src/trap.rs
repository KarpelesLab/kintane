//! Machine-mode traps: the entry in `mtvec`, the one Rust handler, and the timer
//! interrupt's accounting.
//!
//! `mtvec` is in direct mode, so every trap — interrupt or exception — arrives at
//! `__trap_entry`, which saves every general register and the four trap CSRs on the
//! current stack and calls [`riscv32_trap`] with a pointer to them.
//!
//! **The frame, not the CSRs, carries `mepc` and `mstatus` back out.** Those two are
//! per-hart registers, not per-thread ones. The timer interrupt's hook may switch to
//! another thread, whose own next trap overwrites both, so the path that eventually
//! returns from this trap restores them from the frame it saved on its own stack
//! before `mret`. That is the same fact aarch64 keeps with `ELR_EL1` and `SPSR_EL1`.
//!
//! Entry clears `mstatus.MIE`, and nothing here sets it, so traps do not nest. The
//! saved `mstatus` has `MPIE` holding the interrupted code's `MIE`, and `mret` puts it
//! back, so a preempted thread resumes with interrupts as it had them.

use core::cell::UnsafeCell;

use hal::{Arch, EarlyConsole};

use crate::Riscv32;

core::arch::global_asm!(
    r#"
.section .text.trap, "ax"
// mtvec's two low bits are its mode; a direct-mode target must be 4-byte aligned, and
// with compressed instructions the default alignment is only 2.
.balign 4
.globl __trap_entry
__trap_entry:
    addi    sp, sp, -144
    sw      x1, 4(sp)
    sw      x3, 12(sp)
    sw      x4, 16(sp)
    sw      x5, 20(sp)
    sw      x6, 24(sp)
    sw      x7, 28(sp)
    sw      x8, 32(sp)
    sw      x9, 36(sp)
    sw      x10, 40(sp)
    sw      x11, 44(sp)
    sw      x12, 48(sp)
    sw      x13, 52(sp)
    sw      x14, 56(sp)
    sw      x15, 60(sp)
    sw      x16, 64(sp)
    sw      x17, 68(sp)
    sw      x18, 72(sp)
    sw      x19, 76(sp)
    sw      x20, 80(sp)
    sw      x21, 84(sp)
    sw      x22, 88(sp)
    sw      x23, 92(sp)
    sw      x24, 96(sp)
    sw      x25, 100(sp)
    sw      x26, 104(sp)
    sw      x27, 108(sp)
    sw      x28, 112(sp)
    sw      x29, 116(sp)
    sw      x30, 120(sp)
    sw      x31, 124(sp)
    // The interrupted stack pointer, as it was before this frame.
    addi    t0, sp, 144
    sw      t0, 8(sp)
    csrr    t0, mepc
    sw      t0, 128(sp)
    csrr    t0, mstatus
    sw      t0, 132(sp)
    csrr    t0, mcause
    sw      t0, 136(sp)
    csrr    t0, mtval
    sw      t0, 140(sp)

    // s0 still holds the interrupted code's frame pointer, so the handler's frame
    // record links to it and a backtrace from inside the handler reaches the code
    // that was running.
    mv      a0, sp
    call    riscv32_trap

    lw      t0, 128(sp)
    csrw    mepc, t0
    lw      t0, 132(sp)
    csrw    mstatus, t0
    lw      x1, 4(sp)
    lw      x3, 12(sp)
    lw      x4, 16(sp)
    lw      x5, 20(sp)
    lw      x6, 24(sp)
    lw      x7, 28(sp)
    lw      x8, 32(sp)
    lw      x9, 36(sp)
    lw      x10, 40(sp)
    lw      x11, 44(sp)
    lw      x12, 48(sp)
    lw      x13, 52(sp)
    lw      x14, 56(sp)
    lw      x15, 60(sp)
    lw      x16, 64(sp)
    lw      x17, 68(sp)
    lw      x18, 72(sp)
    lw      x19, 76(sp)
    lw      x20, 80(sp)
    lw      x21, 84(sp)
    lw      x22, 88(sp)
    lw      x23, 92(sp)
    lw      x24, 96(sp)
    lw      x25, 100(sp)
    lw      x26, 104(sp)
    lw      x27, 108(sp)
    lw      x28, 112(sp)
    lw      x29, 116(sp)
    lw      x30, 120(sp)
    lw      x31, 124(sp)
    addi    sp, sp, 144
    mret
"#
);

/// Register state saved by `__trap_entry`, in the order it writes it.
///
/// `repr(C)` and the offsets in the assembly are one definition in two languages.
#[repr(C)]
struct TrapFrame {
    /// `x0` through `x31`, indexed by register number. `x0` is not saved and reads zero;
    /// `x2` is the stack pointer the trap interrupted.
    x: [u32; 32],
    mepc: u32,
    mstatus: u32,
    mcause: u32,
    mtval: u32,
}

const _: () = assert!(core::mem::size_of::<TrapFrame>() == 144);

/// `mcause`'s top bit: set for an interrupt, clear for an exception.
const INTERRUPT: u32 = 1 << 31;
/// Machine timer interrupt.
const MACHINE_TIMER: u32 = 7;

/// Install `__trap_entry` in `mtvec`, and say whether the hart kept it.
///
/// `_start` has already done this; doing it again costs nothing and lets the interrupt
/// selftest confirm the register holds what it should.
pub fn install() -> bool {
    unsafe extern "C" {
        fn __trap_entry();
    }
    let want = __trap_entry as *const () as usize;
    let got: usize;
    // SAFETY: `mtvec` is writable in M-mode and the address is a 4-byte-aligned trap
    // entry, so direct mode (low bits zero) is what is written. Reading it back has no
    // side effects.
    unsafe {
        core::arch::asm!(
            "csrw mtvec, {w}",
            "csrr {g}, mtvec",
            w = in(reg) want,
            g = out(reg) got,
            options(nomem, nostack)
        );
    }
    got == want
}

/// The one Rust entry point for every trap.
#[unsafe(no_mangle)]
extern "C" fn riscv32_trap(frame: *mut TrapFrame) {
    // SAFETY: `frame` is the block `__trap_entry` just filled on this stack, live for the
    // whole call and aliased by nothing.
    let (mcause, mepc, mtval) = unsafe { ((*frame).mcause, (*frame).mepc, (*frame).mtval) };

    if mcause == INTERRUPT | MACHINE_TIMER {
        // SAFETY: trap context, so interrupts are masked. Disarming first is this port's
        // EOI: the interrupt is level-sensitive, and a hook that switches threads must not
        // leave it asserted for the next thread, which would take it again at once.
        unsafe { crate::clint::disarm() };
        TIMER_TICKS.increment();
        crate::tick::run_hook();
        return;
    }

    let c = &crate::EARLY;
    c.write_str("\n\nunhandled trap: mcause ");
    write_hex(c, u64::from(mcause));
    c.write_str(" (");
    c.write_str(describe(mcause));
    c.write_str(")\n  mepc  ");
    write_hex(c, u64::from(mepc));
    c.write_str("\n  mtval ");
    write_hex(c, u64::from(mtval));
    c.write_str("\n");
    crate::backtrace::print(c, Some(mepc as usize), crate::backtrace::EXCEPTION_FRAMES);
    crate::stop_after_fault()
}

fn describe(mcause: u32) -> &'static str {
    if mcause & INTERRUPT != 0 {
        return "an interrupt nothing enabled";
    }
    match mcause {
        0 => "instruction address misaligned",
        1 => "instruction access fault",
        2 => "illegal instruction",
        3 => "breakpoint",
        4 => "load address misaligned",
        5 => "load access fault",
        6 => "store address misaligned",
        7 => "store access fault",
        11 => "environment call from M-mode",
        _ => "reserved",
    }
}

/// Timer interrupts taken since boot.
pub static TIMER_TICKS: Counter = Counter(UnsafeCell::new(0));

/// A 64-bit count kept without 64-bit atomics, which rv32imac does not have.
///
/// Written only from the timer interrupt, where interrupts are masked, and read with
/// them masked. On one hart that is exclusion; `Riscv32` asserts `UniProcessor`, and this
/// type is one of the reasons it has to be true.
pub struct Counter(UnsafeCell<u64>);

// SAFETY: see the type's documentation. Every access is made with interrupts masked, on
// the only hart that runs the kernel.
unsafe impl Sync for Counter {}

impl Counter {
    /// Add one. Called only with interrupts masked.
    fn increment(&self) {
        // SAFETY: interrupts are masked (trap context), so no reader runs between the
        // read and the write.
        unsafe { *self.0.get() = (*self.0.get()).wrapping_add(1) };
    }

    /// The current count.
    pub fn get(&self) -> u64 {
        let irq = Riscv32::irq_save();
        // SAFETY: masked, so the interrupt cannot write while this reads both halves.
        let v = unsafe { *self.0.get() };
        // SAFETY: pairs with the `irq_save` above.
        unsafe { Riscv32::irq_restore(irq) };
        v
    }
}

/// Write `v` in decimal.
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

/// Write `v` as sixteen hex digits, like every other port's reports.
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

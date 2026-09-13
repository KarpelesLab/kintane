//! Early boot: the ELF entry point and the jump to `kmain`.
//!
//! QEMU's `virt` machine with `-bios none` has no firmware. Its reset vector loads the
//! hart ID into `a0` and the device tree's address into `a1`, then jumps to the image
//! at the base of RAM. Every hart starts there at once, in M-mode, with the MMU —
//! which this core does not have anyway — out of the picture and interrupts disabled.
//! What has to happen before Rust can run:
//!
//! 1. **Park every hart but hart 0.** They would otherwise race through `.bss` zeroing and share
//!    one stack. Hart IDs are not guaranteed dense or zero-based on real boards, but on `virt` they
//!    are, and SMP is not configured for this port.
//! 2. **Point `mtvec` at the trap entry.** Nothing before it can report an exception, and a stray
//!    one would otherwise jump to address zero.
//! 3. **Zero `.bss`, take the boot stack.** The stack sits above a page nothing uses, in its own
//!    section; see `link.ld` for why that page is not a guard here.
//!
//! `kmain` takes the boot argument as a `u64`. Under the ilp32 calling convention a
//! 64-bit argument is passed as two register halves, low in `a0` and high in `a1`,
//! so the device tree address goes in `a0` and zero in `a1`.

core::arch::global_asm!(
    r#"
.section .text.boot, "ax"
.globl _start
_start:
    // Nothing can interrupt yet, and nothing should.
    csrw    mie, zero
    csrci   mstatus, 0x8

    bnez    a0, .Lpark

    // Callee-saved, and nothing below calls anything until kmain.
    mv      s1, a1

    la      t0, __trap_entry
    csrw    mtvec, t0

    la      t0, __bss_start
    la      t1, __bss_end
.Lzero_bss:
    bgeu    t0, t1, .Lbss_done
    sw      zero, 0(t0)
    addi    t0, t0, 4
    j       .Lzero_bss
.Lbss_done:

    la      sp, __stack_top

    // End the frame-pointer chain here: kmain's own record saves this zero, and the
    // unwinder stops on it.
    li      s0, 0
    li      ra, 0

    mv      a0, s1
    li      a1, 0
    call    kmain

    // kmain diverges; reaching this is a kernel bug.
.Lhang:
    csrci   mstatus, 0x8
    wfi
    j       .Lhang

// Harts other than 0. `mie` is zero, so `wfi` never returns on an interrupt, and a
// spurious wake-up goes straight back to sleep.
.Lpark:
    wfi
    j       .Lpark

// The boot stack, in its own section above a page nothing else uses (see link.ld).
.section .stack, "aw", @nobits
.balign 4096
.globl __stack_bottom
.globl __stack_top
__stack_bottom:
    .skip 16384
__stack_top:
"#
);

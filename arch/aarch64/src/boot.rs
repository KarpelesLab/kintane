//! Early boot: the ELF entry point, the exception-level descent, and the jump to
//! `kmain`.
//!
//! Far less has to happen here than on x86. AArch64 starts in a 64-bit mode with a
//! flat address space and the MMU off, so there is no mode switch to engineer and the
//! page tables can be built in Rust once there is a stack — which is what
//! `paging::aarch64_mmu_init` does, called from the bottom of this file. What is left
//! in assembly is the handful of things that genuinely cannot be expressed in Rust:
//!
//! 1. **Park any other CPU that arrives here.** A loader that releases every CPU at the ELF entry
//!    would otherwise have them all race through `.bss` zeroing and share one stack. QEMU `virt`
//!    does not: its secondaries stay off until PSCI `CPU_ON`, which starts them at
//!    `__secondary_entry` instead (see `smp`). A CPU parked here spins in `wfe` and is never
//!    started.
//! 2. **Descend to EL1 if we came up at EL2.** QEMU's `virt` machine starts the kernel at EL1
//!    unless it was given `virtualization=on`, in which case the same image lands at EL2 instead.
//!    That is a machine-configuration detail, not an architecture one, so the code handles both
//!    rather than asserting one.
//! 3. **Zero `.bss`, then take a stack.** Nothing before the stack switch needs a stack — the
//!    descent to EL1 goes through system registers and `eret`, and the zeroing loop uses registers
//!    only. The translation tables live in `.bss`, so the zeroing is what makes every descriptor
//!    start out invalid. The stack itself is not in `.bss`: it sits above a guard page in its own
//!    `.stack` section (see `link.ld`), and is therefore neither zeroed nor adjacent to anything an
//!    overflow could quietly corrupt.
//!
//! Register state on entry is whatever QEMU left. Its ELF path is documented as
//! "assume that raw images are Linux kernels and ELF images are not", so unlike the
//! Linux boot protocol there is no device-tree pointer in `x0` — QEMU parks the DTB
//! at the base of RAM instead. `x0` is still carried through to `kmain` unchanged,
//! because that is where a pointer will arrive from every other loader, and a value
//! the banner prints is a value somebody notices when it becomes wrong.
//!
//! Entry at EL3 is not handled. It would mean a board booting its own kernel as
//! secure firmware, which is a different port with a different linker script, not a
//! variation of this one.

core::arch::global_asm!(
    r#"
.section .text.boot, "ax"
.globl _start
_start:
    // Mask debug, SError, IRQ and FIQ for all of early boot. There is no vector
    // table installed yet, so any exception taken here would be unrecoverable and
    // silent.
    msr     daifset, #0xf

    // Carry whatever the loader left in x0 through to kmain.
    mov     x19, x0

    // No per-CPU block yet. TPIDR_EL1's reset value is UNKNOWN, and `cpu_index` reads a
    // block through it; zero is the one value it answers without reading.
    msr     tpidr_el1, xzr

    // Aff2:Aff1:Aff0 of zero identifies the boot CPU on every machine we target.
    // The rest have nothing to do until SMP bring-up exists.
    mrs     x0, mpidr_el1
    and     x0, x0, #0xffffff
    cbz     x0, .Lprimary
.Lpark:
    wfe
    b       .Lpark

.Lprimary:
    mrs     x0, CurrentEL
    lsr     x0, x0, #2
    cmp     x0, #2
    b.ne    .Lat_el1

    // --- EL2: hand the machine to EL1 and never come back -------------------

    // HCR_EL2.RW: the lower exception level is AArch64, not AArch32.
    mov     x0, #(1 << 31)
    msr     hcr_el2, x0

    // Let EL1 read the counter and program the timer, with no virtual offset, so
    // the two exception levels agree on what time it is.
    mrs     x0, cnthctl_el2
    orr     x0, x0, #3
    msr     cnthctl_el2, x0
    msr     cntvoff_el2, xzr

    // SCTLR_EL1 to its architectural reset shape: MMU off, caches off, all the RES1
    // bits set. EL1's copy is not reset by entering EL2, so it must be written
    // before the eret or EL1 starts with whatever was left there.
    mov     x0, #0x0800
    movk    x0, #0x30d0, lsl #16
    msr     sctlr_el1, x0

    // Return into EL1h — EL1 using SP_EL1 — with the same four exceptions masked
    // that were masked on entry. SPSR bits: D,A,I,F set, M[4:0] = 0b00101.
    mov     x0, #0x3c5
    msr     spsr_el2, x0
    adr     x0, .Lat_el1
    msr     elr_el2, x0
    eret

.Lat_el1:
    // CPACR_EL1.FPEN = 0b11: do not trap FP or Advanced SIMD at EL1 or EL0.
    // The kernel is built softfloat and should never issue one, but a trap with no
    // vector table is an unreadable hang, whereas an FP instruction that simply
    // executes is a bug somebody can find later.
    mov     x0, #(3 << 20)
    msr     cpacr_el1, x0
    isb

    // Zero .bss. The linker aligns __bss_end to 16, so storing 8 bytes at a time
    // and stopping on >= never overruns and never leaves a tail behind.
    adrp    x0, __bss_start
    add     x0, x0, :lo12:__bss_start
    adrp    x1, __bss_end
    add     x1, x1, :lo12:__bss_end
.Lzero_bss:
    cmp     x0, x1
    b.hs    .Lbss_done
    str     xzr, [x0], #8
    b       .Lzero_bss
.Lbss_done:

    // SP must be 16-byte aligned on aarch64 whenever it is used as a base address,
    // which __stack_top is — the linker puts the stack on a page boundary. Its contents
    // are whatever the loader left; a stack slot is written before it is read.
    adrp    x0, __stack_top
    add     x0, x0, :lo12:__stack_top
    mov     sp, x0

    // Terminate the frame and return-address chains so an unwinder or a debugger
    // stops here instead of walking into whatever the loader left behind.
    mov     x29, xzr
    mov     x30, xzr

    // Build the identity map and turn the MMU on, in Rust, before anything else runs.
    // It needs the stack, which is why it cannot come earlier, and it comes before
    // kmain so that no part of the kernel proper ever runs untranslated. x19 survives
    // the call because it is callee-saved under AAPCS64.
    bl      aarch64_mmu_init

    mov     x0, x19
    bl      kmain

    // kmain is diverging; reaching this is a bug in the kernel, not a normal exit.
.Lhang:
    msr     daifset, #0xf
    wfi
    b       .Lhang

// The boot stack, in a section of its own so that link.ld can put a guard page
// directly beneath it. Were it left in .bss it would sit wherever the linker chose,
// with the translation tables — also .bss — as likely as not immediately below, and an
// overflow would rewrite the page tables instead of faulting. `nobits`, so the 16 KiB
// costs nothing in the image; `.balign 4096` so the bottom of the stack is the page
// boundary the guard ends on.
.section .stack, "aw", @nobits
.balign 4096
// Global, not because anything links against them, but because link.ld's ASSERTs do:
// a linker-script expression can only name a global symbol, and those assertions are
// what stops the guard page and the stack drifting into each other unnoticed.
.globl __stack_bottom
.globl __stack_top
__stack_bottom:
    .skip 16384
__stack_top:
"#
);

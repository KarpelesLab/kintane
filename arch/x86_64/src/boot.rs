//! Early boot: multiboot entry, the switch to long mode, and the jump to `kmain`.
//!
//! A multiboot loader hands control over in 32-bit protected mode with paging off, so
//! everything up to the far jump is necessarily assembly. The sequence is fixed by the
//! architecture and has to be done in this order:
//!
//! 1. Take a stack and stash the multiboot info pointer, which arrives in `ebx`.
//! 2. Build page tables. Long mode requires paging to be enabled *before* it can be entered, so
//!    there is no way to defer this to Rust. We identity-map the first 1 GiB with 2 MiB pages:
//!    three tables, one loop, and enough to reach `kmain`.
//! 3. Enable PAE (`CR4.PAE`), set `EFER.LME`, load `CR3`, then enable paging (`CR0.PG`). Setting
//!    LME only arms long mode; it activates when paging comes on.
//! 4. Load a GDT with a 64-bit code segment and far-jump to reload `CS`. Until that jump the CPU is
//!    in 32-bit compatibility mode.
//!
//! The GDT below is the bootstrap one and stops being the live table early: `gdt.rs`
//! replaces it during interrupt bring-up with a table that also describes a TSS, so
//! that #DF can be given a stack of its own. It keeps the code descriptor at the same
//! index with the same bits, which is what lets the replacement happen without a
//! second far jump — so the two definitions must stay in step, and `gdt.rs` says so
//! at its copy.
//!
//! The boot stack is not defined here. `link.ld` owns it, because the stack's position
//! is the whole point: it is the first thing in the writable region, with a guard page
//! immediately below it that belongs to no section and that the address space builder
//! leaves unmapped. The page tables this file builds are now *above* the stack rather
//! than directly below it, which is where an overflow used to land — see the layout
//! comment in `link.ld` and the experiment recorded in `gdt.rs`. All this file needs is
//! `__stack_top`, which the linker script defines.
//!
//! Written in AT&T syntax because `ljmp $sel, $off` is unambiguous there; LLVM's Intel
//! far-jump syntax is fiddly enough to be worth avoiding in code that cannot be
//! unit-tested.
//!
//! Phase 1 replaces the identity map with a high-half mapping, which also changes the
//! code model in the target specification.

core::arch::global_asm!(
    r#"
.section .multiboot_header, "a"
.align 8
    .long 0x1BADB002
    .long 0x00000000
    .long -(0x1BADB002 + 0x00000000)

.section .text.boot, "ax"
.code32
.globl _start
_start:
    cli
    movl $__stack_top, %esp
    movl %ebx, multiboot_info

    movl $pml4, %edi
    movl $2048, %ecx
    xorl %eax, %eax
    rep stosl

    xorl %ecx, %ecx
.Lfill_pd:
    movl $0x200000, %eax
    mull %ecx
    orl $0x83, %eax
    movl %eax, pd(,%ecx,8)
    movl $0, pd+4(,%ecx,8)
    incl %ecx
    cmpl $512, %ecx
    jne .Lfill_pd

    movl $pd, %eax
    orl $0x03, %eax
    movl %eax, pdpt

    movl $pdpt, %eax
    orl $0x03, %eax
    movl %eax, pml4

    movl $pml4, %eax
    movl %eax, %cr3

    movl %cr4, %eax
    orl $(1 << 5), %eax
    movl %eax, %cr4

    movl $0xC0000080, %ecx
    rdmsr
    orl $(1 << 8), %eax
    wrmsr

    movl %cr0, %eax
    orl $(1 << 31), %eax
    orl $(1 << 0), %eax
    movl %eax, %cr0

    lgdt gdt64_pointer
    ljmp $0x08, $long_mode_start

.code64
long_mode_start:
    xorl %eax, %eax
    movw %ax, %ss
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %fs
    movw %ax, %gs

    movq $__stack_top, %rsp
    xorq %rbp, %rbp

    movl multiboot_info, %edi
    call kmain

.Lhang:
    cli
    hlt
    jmp .Lhang

.section .rodata
.align 8
gdt64:
    .quad 0
    .quad (1 << 43) | (1 << 44) | (1 << 47) | (1 << 53)
gdt64_pointer:
    .word . - gdt64 - 1
    .quad gdt64

.section .bss
.align 4096
pml4:
    .skip 4096
pdpt:
    .skip 4096
pd:
    .skip 4096
multiboot_info:
    .skip 8

/* The boot stack. A section of its own, not part of .bss, because link.ld places it
 * first in the writable region with a guard page below it — see the layout comment
 * there. 16 KiB, a whole number of pages so that the guard page below is a whole page
 * too; the linker owns `__stack_bottom` and `__stack_top`. */
.section .stack, "aw", @nobits
.align 4096
    .skip 16384
"#,
    options(att_syntax)
);

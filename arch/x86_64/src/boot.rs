//! Early boot: multiboot entry, the switch to long mode, and the jump to `kmain`.
//!
//! A multiboot loader hands control over in 32-bit protected mode with paging off, so
//! everything up to the far jump is necessarily assembly. The sequence is fixed by the
//! architecture and has to be done in this order:
//!
//! 1. Take a stack and stash the multiboot info pointer, which arrives in `ebx`.
//! 2. Build page tables. Long mode requires paging to be enabled *before* it can be entered, so
//!    there is no way to defer this to Rust. We identity-map the first 4 GiB with 2 MiB pages: a
//!    PML4, a PDPT and four page directories filled by one loop. One gigabyte reaches `kmain`; four
//!    also reach the PC's MMIO hole below 4 GiB, where device discovery reads the PCI Express
//!    configuration window and the APICs before the kernel's own address space exists
//!    (`kernel/platform/acpi`, [`crate::pc::BOOT_IDENTITY_END`]).
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
//!
//! Both entries point `GS` at CPU 0's block (`smp.rs`) before any Rust runs, because
//! [`crate::smp::cpu_index`] reads the CPU's number through `GS` and lock-order checking
//! asks for it inside the first lock taken. A secondary does the same in its own entry,
//! with its own block. The bootstrap page tables are also named `__boot_pml4` for a
//! secondary's trampoline, which enters long mode on them before switching to the
//! kernel's.
//!
//! # The second way in: `kinboot_entry`
//!
//! A UEFI loader cannot call `_start`. The firmware runs in long mode and has no 32-bit
//! code segment to hand over on, so `kinboot-efi` enters at `kinboot_entry` instead,
//! already in 64-bit mode, with the boot protocol's structure in `rdi`. The loader finds
//! that address in the `KinTane` ELF note below, not in `e_entry`, which stays `_start`
//! for multiboot. `boot_protocol::image` describes the note and the entry contract.
//!
//! What the 64-bit path does is what the 32-bit path does minus the mode switch, and
//! for the same reason: nothing the loader set up is ours to keep. The firmware's page
//! tables live in boot-services memory, which the memory map hands to the frame
//! allocator as usable, and its GDT and stack are in the same position. So the entry
//! takes the kernel's own stack, builds the same identity map in the same `.bss`
//! tables, loads the same bootstrap GDT and reloads `CS` with a far return. From
//! `kmain`'s point of view the two paths are indistinguishable except for what
//! `boot_arg` points at, which is what the configuration's `bootinfo` provider reads.
//!
//! Two things the loader guarantees make that safe: the image and the structure are
//! identity-mapped by the firmware's tables while the kernel's are built, and both lie
//! below 1 GiB, well inside the kernel's bootstrap map.

// The boot tables alias their identity map at `hal::paging::DEVICE_WINDOW_BASE` through PML4
// entry 2 (`pml4+16` below), so drivers that start during discovery reach registers where
// the kernel's own space later maps them. Another base needs another entry.
const _: () = assert!(
    hal::paging::DEVICE_WINDOW_BASE == 2 << 39,
    "x86_64's boot tables alias the device window through PML4 entry 2"
);

core::arch::global_asm!(
    r#"
.section .multiboot_header, "a"
.align 8
    .long 0x1BADB002
    .long 0x00000000
    .long -(0x1BADB002 + 0x00000000)

/* The boot protocol entry note; see boot_protocol::image. `.quad kinboot_entry` is
 * the physical address, which is also the link address in this identity-linked image. */
.section .note.kintane, "a", @note
.align 4
    .long 8
    .long 16
    .long 1
    .ascii "KinTane\0"
    .quad kinboot_entry
    .long 1
    .long 0

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
    cmpl $2048, %ecx
    jne .Lfill_pd

    movl $pd, %eax
    orl $0x03, %eax
    movl %eax, pdpt
    addl $4096, %eax
    movl %eax, pdpt+8
    addl $4096, %eax
    movl %eax, pdpt+16
    addl $4096, %eax
    movl %eax, pdpt+24

    movl $pdpt, %eax
    orl $0x03, %eax
    movl %eax, pml4
    /* The device window: the same 4 GiB again at DEVICE_WINDOW_BASE (1 TiB, PML4 entry 2),
     * where every driver reaches its registers. */
    movl %eax, pml4+16

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

    /* GS base: CPU 0's block. After the selector loads above, which may clear it. */
    movl $0xC0000101, %ecx
    leaq __cpu_blocks(%rip), %rax
    movq %rax, %rdx
    shrq $32, %rdx
    wrmsr

    movl multiboot_info, %edi
    call kmain

.Lhang:
    cli
    hlt
    jmp .Lhang

/* Entered by a KinTane loader in long mode: rdi = boot information, interrupts off. */
.globl kinboot_entry
kinboot_entry:
    cli
    cld
    movq %rdi, %rbx
    movq $__stack_top, %rsp

    movl $pml4, %edi
    movl $2048, %ecx
    xorl %eax, %eax
    rep stosl

    xorl %ecx, %ecx
.Lfill_pd64:
    movq %rcx, %rax
    shlq $21, %rax
    orq $0x83, %rax
    movq %rax, pd(,%rcx,8)
    incl %ecx
    cmpl $2048, %ecx
    jne .Lfill_pd64

    movq $pd, %rax
    orq $0x03, %rax
    movq %rax, pdpt
    addq $4096, %rax
    movq %rax, pdpt+8
    addq $4096, %rax
    movq %rax, pdpt+16
    addq $4096, %rax
    movq %rax, pdpt+24
    movq $pdpt, %rax
    orq $0x03, %rax
    movq %rax, pml4
    /* The device window, as on the multiboot path. */
    movq %rax, pml4+16

    movq $pml4, %rax
    movq %rax, %cr3

    lgdt gdt64_pointer
    /* A far return is the only way to load CS in long mode without a far pointer in
     * memory: push the selector and the target, and return to them. */
    pushq $0x08
    leaq .Lkinboot_cs(%rip), %rax
    pushq %rax
    lretq
.Lkinboot_cs:
    xorl %eax, %eax
    movw %ax, %ss
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %fs
    movw %ax, %gs

    movl $0xC0000101, %ecx
    leaq __cpu_blocks(%rip), %rax
    movq %rax, %rdx
    shrq $32, %rdx
    wrmsr

    movq %rbx, %rdi
    xorq %rbp, %rbp
    call kmain
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
.globl __boot_pml4
__boot_pml4:
pml4:
    .skip 4096
pdpt:
    .skip 4096
/* Four page directories, one per gigabyte of the identity map. */
pd:
    .skip 16384
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

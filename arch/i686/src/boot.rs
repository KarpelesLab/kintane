//! Early boot: multiboot entry, PAE paging, and the jump to `kmain`.
//!
//! A multiboot loader hands control over in 32-bit protected mode with paging off,
//! which on this target is already the mode the kernel runs in. There is no long-mode
//! switch and no far jump to a 64-bit code segment — the whole reason this port is
//! shorter than `arch/x86_64` is that the loader has done the mode transition for us.
//!
//! What is left still has to be assembly, and still has a fixed order:
//!
//! 1. Take our own GDT. Multiboot guarantees flat segments on entry but explicitly does *not*
//!    guarantee the loader's GDT stays in memory the kernel may not reuse, so we load one we own
//!    and far-jump to reload `CS` before anything else.
//! 2. Take a stack and stash the multiboot info pointer, which arrives in `ebx`.
//! 3. Build PAE page tables and identity-map the low 4 GiB with 2 MiB pages.
//! 4. Enable PAE (`CR4.PAE`), load `CR3`, then enable paging (`CR0.PG`).
//!
//! ## Why PAE and not 32-bit paging
//!
//! Classic 2-level 32-bit paging would boot this kernel in fewer instructions. PAE is
//! chosen deliberately: it is the only mode in which a physical address on this target
//! is 36 bits wide behind a 32-bit pointer, and that asymmetry is the entire reason
//! i686 is a tier-1 target (`docs/targets.md#i686`). A port that used 32-bit paging
//! would let `PhysAddr == usize` stay true here and the target would stop earning its
//! place. `PHYS_ADDR_BITS` is 36 because of the mode selected here, not the other way
//! around.
//!
//! Note the PDPT entry format, which is the one trap in PAE that long mode does not
//! have: in 32-bit PAE paging a PDPTE has only the present bit and the two cache
//! bits. Bits 1 and 2 — R/W and U/S, which long-mode PDPTEs do have and which
//! `arch/x86_64/src/boot.rs` therefore sets — are *reserved* here, and setting them
//! faults on the `mov %eax, %cr0` that enables paging. The entries below carry `0x01`
//! and nothing else.
//!
//! ## Where the boot stack and the early tables live
//!
//! Both are `.bss`, and until recently both were in the *same* `.bss`, with the four
//! page directories ending exactly where the stack began. A stack that grew one page
//! too far therefore overwrote the live translation tables — quietly, because a table
//! stays valid until the corrupted entry is next walked, so the fault landed somewhere
//! unrelated and much later.
//!
//! They are now in sections of their own, `.bss.boot_tables` and `.stack`, and
//! `link.ld` puts the tables at the bottom of `.bss`, the stack at the top of the
//! image, and an unmapped guard page between them. That page is how this port *detects*
//! an overflow. Reporting one is the double-fault task's job (`tss.rs`): a 32-bit gate
//! descriptor has no IST field, so `#DF` is a task gate, which switches to a stack of its
//! own without pushing anything on the one that overflowed.
//!
//! The guard is not enforced by the map this file builds, which uses 2 MiB leaves and
//! cannot express a 4 KiB hole; it becomes real when the kernel installs the address
//! space it builds for itself from `image_sections()`.
//!
//! ## Why SSE is enabled here and not on x86_64
//!
//! `arch/x86_64` never touches `CR0.EM` or `CR4.OSFXSR` because its target
//! specification builds the whole kernel with `-mmx,-sse,+soft-float`, so no SSE
//! instruction is ever emitted. That is not available on i686: `+soft-float` is
//! rejected as incompatible with an ABI that returns floats in x87 registers, and
//! disabling `sse` fails to build `core`. `targets/i686-kintane.json` therefore
//! leaves SSE on, and LLVM uses it for ordinary work that has nothing to do with
//! floating point — `xorps %xmm0, %xmm0` / `movaps %xmm0, (%esp)` to zero a stack
//! buffer is what it emits for the banner's digit buffer.
//!
//! So the instructions are in the image whether the kernel means to use FP or not,
//! and the CPU has to be told they are legal: with `CR4.OSFXSR` clear they raise
//! `#UD`. Untreated, that is a triple fault before the first line of output, because
//! there is no IDT yet and the BIOS IVT is still installed. "The kernel must not use
//! floating point" remains the policy for *kernel-authored* code and for context
//! switching; it is not a statement about what the compiler emits.
//!
//! Written in AT&T syntax to match `arch/x86_64/src/boot.rs`; `ljmp $sel, $off` is
//! unambiguous there and fiddly in LLVM's Intel far-jump syntax.
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

    // ebx holds the multiboot info pointer. Park it in a register that survives the
    // segment reload, since the store below must happen on a data segment we own.
    movl %ebx, %esi

    lgdt gdt32_pointer
    ljmp $0x08, $.Lsegments

.Lsegments:
    movw $0x10, %ax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %fs
    movw %ax, %gs
    movw %ax, %ss
    movl $__stack_top, %esp
    xorl %ebp, %ebp

    movl %esi, multiboot_info

    // A PAE PDPT is four 8-byte entries. It gets a whole page so that CR3's
    // alignment requirement is satisfied by construction, and the page is zeroed
    // because only the first four entries are written below.
    movl $pdpt, %edi
    movl $1024, %ecx
    xorl %eax, %eax
    rep stosl

    // Identity-map the low 4 GiB with 2 MiB pages: 2048 page directory entries
    // across four contiguous page directories. Every entry is written, so this does
    // not depend on .bss having been zeroed by the loader.
    //
    // The high dword of each entry is the top 4 bits of the 36-bit physical address.
    // It is zero here only because everything we map lives below 4 GiB; the field
    // exists, which is the difference that matters.
    xorl %ecx, %ecx
.Lfill_pd:
    movl %ecx, %eax
    shll $21, %eax              // entry n covers physical n * 2 MiB
    orl $0x83, %eax             // present | writable | page size (2 MiB leaf)
    movl %eax, pd(,%ecx,8)
    movl $0, pd+4(,%ecx,8)
    incl %ecx
    cmpl $2048, %ecx
    jne .Lfill_pd

    // PDPT[0..4] -> the four page directories. Present bit only: see the module
    // comment on reserved bits in 32-bit PAE PDPT entries.
    movl $pd, %eax
    orl $0x01, %eax
    movl %eax, pdpt
    movl $0, pdpt+4
    addl $4096, %eax
    movl %eax, pdpt+8
    movl $0, pdpt+12
    addl $4096, %eax
    movl %eax, pdpt+16
    movl $0, pdpt+20
    addl $4096, %eax
    movl %eax, pdpt+24
    movl $0, pdpt+28

    // CR3 must be loaded before paging is enabled: turning on CR0.PG with CR4.PAE
    // set is the moment the CPU caches the four PDPT entries into its registers.
    movl $pdpt, %eax
    movl %eax, %cr3

    movl %cr4, %eax
    orl $(1 << 5), %eax         // CR4.PAE
    orl $(1 << 9), %eax         // CR4.OSFXSR: SSE state is ours to save
    orl $(1 << 10), %eax        // CR4.OSXMMEXCPT: SIMD exceptions as #XF, not #UD
    movl %eax, %cr4

    // CR0.PE is already set — the loader handed us protected mode. Paging is the bit
    // we came for; the other two are what makes SSE legal to execute, which on this
    // target is not optional — see the module comment.
    movl %cr0, %eax
    andl $0xFFFFFFFB, %eax      // clear CR0.EM: no x87 emulation trap
    orl $(1 << 1), %eax         // CR0.MP
    orl $(1 << 31), %eax        // CR0.PG
    movl %eax, %cr0
    jmp .Lpaging_on             // serialize: no fetch across the mode change

.Lpaging_on:
    // EFER.NXE and CR0.WP, before anything above this point in the kernel builds a
    // mapping and expects it to be enforced. Both are properties of the CPU rather
    // than of any one mapping, and `paging::i686_early_mmu_init` documents why here is
    // the right moment. No arguments, no return value, and esp is still 16-byte
    // aligned afterwards.
    call i686_early_mmu_init

    // cdecl: arguments on the stack, caller-cleaned. Eight bytes are pushed rather
    // than four so the call is correct whether `kmain` takes a 32-bit or a 64-bit
    // multiboot pointer — the low dword is the value either way on a little-endian
    // target, and the callee never returns for the caller to clean up after.
    // The extra 8 bytes keep esp 16-byte aligned at the call, as the i386 System V
    // ABI requires.
    subl $8, %esp
    pushl $0
    pushl multiboot_info
    call kmain

.Lhang:
    cli
    hlt
    jmp .Lhang

.section .rodata
.align 8
gdt32:
    .quad 0
    .quad 0x00CF9A000000FFFF    // code: base 0, limit 4 GiB, ring 0, 32-bit
    .quad 0x00CF92000000FFFF    // data: base 0, limit 4 GiB, ring 0, writable
gdt32_pointer:
    .word . - gdt32 - 1
    .long gdt32

// The early translation tables, in a section of their own so `link.ld` can place them
// at the *bottom* of .bss. They used to sit at its top, immediately below the boot
// stack, which made the live page directories the first thing a stack overflow
// overwrote — silently, since the tables stay valid until the overwritten entry is
// walked. What is below the stack now is a guard page; what is below that is ordinary
// Rust statics.
.section .bss.boot_tables, "aw", @nobits
.align 4096
pdpt:
    .skip 4096
pd:
    .skip 16384
multiboot_info:
    .skip 4

// The boot stack is not reserved here. `link.ld` reserves CONFIG_BOOT_STACK_KIB of it in a
// section of its own, page-aligned, with __stack_guard_start / __stack_guard_end for the
// page beneath; nothing else may be placed there, and the address space the kernel builds
// for itself leaves it unmapped.
"#,
    options(att_syntax)
);

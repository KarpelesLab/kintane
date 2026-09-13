//! Stage 2 entry, the BIOS call thunk, and the jump to the kernel.
//!
//! # Entry
//!
//! Stage 1 jumps here in real mode with the boot drive in `DL`. The only work done in
//! real mode is loading a GDT and entering 32-bit protected mode. Collecting the memory
//! map, enabling A20 and reading the kernel all happen from Rust, through the thunk.
//!
//! That corrects the plan `docs/bootloader.md` first described, in which real-mode code
//! collected everything before the switch, "because after the switch there is no BIOS".
//! Only the kernel's *load address* is out of real mode's reach, and it is the one thing
//! a loader cannot avoid: INT 13h reads into a `segment:offset` buffer below 1 MiB, and
//! the kernel loads at 1 MiB. So the loader needs a way back into the BIOS whatever
//! else it does. With that in place, doing the E820 loop in assembly as well would just
//! put logic where it cannot be tested.
//!
//! # The thunk
//!
//! `bios_int(vector)` calls a real-mode interrupt with the registers in `bios_regs`, and
//! writes the registers and flags the BIOS returned back into it. It:
//!
//! 1. far-jumps to a 16-bit code segment, still in protected mode;
//! 2. clears `CR0.PE` and far-jumps again to `0000:xxxx`, which is real mode;
//! 3. takes the real-mode stack below `0x7C00`, loads the registers and executes `int` with
//!    interrupts enabled, because disk services may wait on an IRQ;
//! 4. saves what the BIOS returned, then sets `CR0.PE`, far-jumps back into the 32-bit segment and
//!    restores the protected-mode stack.
//!
//! Real-mode code addresses its data through `CS`, which is zero there, so it can load
//! `DS` and `ES` with the caller's values and still read and write `bios_regs`. The code
//! and the data it touches are in `.stage2.real`, which the link script places inside
//! stage 2's 32 KiB, well below the 64 KiB that 16-bit offsets can reach. An offset that
//! did not fit would be a link-time relocation error.
//!
//! The interrupt vector is patched into the `int` instruction's operand before the
//! switch. The loader runs with no memory protection, and a patched opcode needs no
//! dispatch table.
//!
//! The IDT register keeps the real-mode IVT (base 0, limit 0x3FF) throughout: the loader
//! never loads an IDT, so the BIOS finds its vectors, and protected-mode code runs with
//! interrupts disabled. A CPU exception in protected mode is a triple fault. That is
//! acceptable in a loader whose every input is checked before use, and it is documented.

core::arch::global_asm!(
    r#"
.section .stage2.head, "awx"
.code16
.globl stage2_start
stage2_start:
    jmp .Lreal_entry

// The disk header. Its offset and layout are fixed by boot/kinboot-bios/src/disk.rs,
// and kbuild fills the zeros in.
.org 8
.globl disk_header
disk_header:
    .ascii "KBS2"
    .word 2
    .word 32
    .long 0, 0, 0, 0, 0, 0

.Lreal_entry:
    cli
    xorw %ax, %ax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %ss
    movw $0x7C00, %sp
    movb %dl, boot_drive

    lgdtl gdt_pointer
    movl %cr0, %eax
    orl $1, %eax
    movl %eax, %cr0
    ljmpl $0x08, $.Lprotected

.section .stage2.real, "awx"
.code32
.Lprotected:
    movw $0x10, %ax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %fs
    movw %ax, %gs
    movw %ax, %ss
    movl $loader_stack_top, %esp
    xorl %ebp, %ebp

    // Zero .bss. Nothing before this line may live there.
    movl $__bss_start, %edi
    movl $__bss_end, %ecx
    subl %edi, %ecx
    xorl %eax, %eax
    cld
    rep stosb

    movzbl boot_drive, %eax
    pushl %eax
    call kinboot_main
.Lstop:
    cli
    hlt
    jmp .Lstop

// void bios_int(u32 vector)
.globl bios_int
bios_int:
    pushl %ebp
    pushl %ebx
    pushl %esi
    pushl %edi
    movl 20(%esp), %eax
    movb %al, .Lvector
    movl %esp, .Lsaved_esp
    ljmp $0x18, $.Lprotected16

.code16
.Lprotected16:
    movl %cr0, %eax
    andl $0xFFFFFFFE, %eax
    movl %eax, %cr0
    ljmp $0x0000, $.Lreal

.Lreal:
    xorw %ax, %ax
    movw %ax, %ss
    movw $0x7C00, %sp
    movl %cs:bios_regs + 4, %ebx
    movl %cs:bios_regs + 8, %ecx
    movl %cs:bios_regs + 12, %edx
    movl %cs:bios_regs + 16, %esi
    movl %cs:bios_regs + 20, %edi
    movl %cs:bios_regs + 24, %ebp
    movw %cs:bios_regs + 30, %es
    movw %cs:bios_regs + 28, %ds
    movl %cs:bios_regs + 0, %eax
    sti
    .byte 0xCD
.Lvector:
    .byte 0
    cli
    movl %eax, %cs:bios_regs + 0
    movl %ebx, %cs:bios_regs + 4
    movl %ecx, %cs:bios_regs + 8
    movl %edx, %cs:bios_regs + 12
    movl %esi, %cs:bios_regs + 16
    movl %edi, %cs:bios_regs + 20
    movl %ebp, %cs:bios_regs + 24
    movw %ds, %cs:bios_regs + 28
    movw %es, %cs:bios_regs + 30
    pushfl
    popl %cs:bios_regs + 32

    lgdtl %cs:gdt_pointer
    movl %cr0, %eax
    orl $1, %eax
    movl %eax, %cr0
    ljmpl $0x08, $.Lback

.code32
.Lback:
    movw $0x10, %ax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %fs
    movw %ax, %gs
    movw %ax, %ss
    movl .Lsaved_esp, %esp
    popl %edi
    popl %esi
    popl %ebx
    popl %ebp
    ret

// noreturn enter_kernel(u32 entry, u32 info, u32 magic)
//
// The 32-bit entry's machine state (boot_protocol::image): EAX = the magic naming the
// structure, EBX = the structure, flat 32-bit code and data segments, protected mode,
// paging off, interrupts off. All of that except the two registers is already true here.
.globl enter_kernel
enter_kernel:
    movl 4(%esp), %ecx
    movl 8(%esp), %ebx
    movl 12(%esp), %eax
    jmp *%ecx

// noreturn chain_boot(u32 drive, u32 si)
//
// Enter a boot record at 0000:7C00 the way a BIOS or an MBR would: real mode, DL = the
// boot drive, DS:SI = its partition entry, a stack below 0x7C00, interrupts enabled. The
// record and the MBR copy are already in place. The two values ride through the mode
// switch in EDX and ESI, which nothing on the way touches.
.globl chain_boot
chain_boot:
    cli
    movl 4(%esp), %edx
    movl 8(%esp), %esi
    ljmp $0x18, $.Lchain16

.code16
.Lchain16:
    movl %cr0, %eax
    andl $0xFFFFFFFE, %eax
    movl %eax, %cr0
    ljmp $0x0000, $.Lchain_real

.Lchain_real:
    xorw %ax, %ax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %ss
    movw $0x7C00, %sp
    sti
    ljmp $0x0000, $0x7C00

.code32

.Lsaved_esp:
    .long 0

.globl boot_drive
boot_drive:
    .byte 0

// eax, ebx, ecx, edx, esi, edi, ebp (4 bytes each), ds, es (2 each), eflags (4).
// loader/bios.rs mirrors this layout and asserts its size.
.globl bios_regs
bios_regs:
    .space 36, 0

gdt:
    .quad 0
    // 0x08: 32-bit code, base 0, limit 4 GiB.
    .word 0xFFFF, 0x0000
    .byte 0x00, 0x9A, 0xCF, 0x00
    // 0x10: 32-bit data, base 0, limit 4 GiB.
    .word 0xFFFF, 0x0000
    .byte 0x00, 0x92, 0xCF, 0x00
    // 0x18: 16-bit code, base 0, limit 64 KiB: the step between protected and real mode.
    .word 0xFFFF, 0x0000
    .byte 0x00, 0x9A, 0x00, 0x00
gdt_end:

gdt_pointer:
    .word gdt_end - gdt - 1
    .long gdt

.section .bss
.align 16
    .space 16384
loader_stack_top:
"#,
    options(att_syntax)
);

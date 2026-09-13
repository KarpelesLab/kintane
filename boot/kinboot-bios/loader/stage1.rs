//! Stage 1: the master boot record.
//!
//! The BIOS loads sector 0 at `0x7C00` and jumps to it in 16-bit real mode, with the
//! boot drive in `DL` and nothing else guaranteed: not the segment registers, not the
//! stack, not even whether `CS:IP` is `0000:7C00` or `07C0:0000`. This sector does one
//! thing, load stage 2, in the 424 bytes before its table:
//!
//! 1. Normalise `CS`, zero the data segments, and take a stack below `0x7C00`.
//! 2. Ask INT 13h whether extensions are present (`AH=41h`). If so, read all of stage 2 with one
//!    extended read (`AH=42h`).
//! 3. Otherwise read it the old way, one sector at a time with `AH=02h`, converting LBA to
//!    cylinder/head/sector with the geometry `AH=08h` reports. That is the path for machines whose
//!    BIOS predates LBA, and for floppies.
//! 4. Check stage 2's magic, then jump to it with the boot drive still in `DL`.
//!
//! On failure it prints `kinboot-bios: stage 1 error` and a letter to the screen and to
//! COM1, then calls INT 18h. INT 18h is the BIOS's "this device did not boot" entry: a
//! real machine moves on to its next boot device, and QEMU run with
//! `-boot reboot-timeout=0 -no-reboot` exits, so the test harness sees the failure at
//! once instead of waiting out its timeout.
//!
//! - `r`: a disk read failed.
//! - `g`: no LBA, and the CHS geometry was unusable.
//! - `m`: what was read is not stage 2.
//!
//! Where stage 2 lives comes from the table at offset 424, written by `kbuild`. The
//! table's position is asserted with `.org`, so code that grows into it fails to
//! assemble. That is the hard 440-byte limit from `docs/bootloader.md`, enforced by the
//! assembler rather than by review.
//!
//! AT&T syntax, like the kernel's boot code. `global_asm!` with `.code16` goes through
//! LLVM's integrated assembler, so no external assembler is involved.

core::arch::global_asm!(
    r#"
.section .stage1, "awx"
.code16
.globl stage1_start
stage1_start:
    cli
    xorw %ax, %ax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %ss
    movw $0x7C00, %sp
    // Some BIOSes enter at 07C0:0000. Every address below assumes CS = 0.
    ljmp $0x0000, $.Lnormalised
.Lnormalised:
    sti
    cld
    movb %dl, .Ldrive

    movb $0x41, %ah
    movw $0x55AA, %bx
    int $0x13
    jc .Lchs
    cmpw $0xAA55, %bx
    jne .Lchs
    // CX bit 0: the extended read/write functions (the "fixed disk access" subset).
    testb $1, %cl
    jz .Lchs

    movw .Lstage2_sectors, %ax
    movw %ax, .Ldap_count
    movl .Lstage2_lba, %eax
    movl %eax, .Ldap_lba
    movb .Ldrive, %dl
    movw $.Ldap, %si
    movb $0x42, %ah
    int $0x13
    jc .Lread_error
    jmp .Lloaded

.Lchs:
    movb .Ldrive, %dl
    movb $0x08, %ah
    xorw %di, %di
    int $0x13
    jc .Lgeometry_error
    // AH=08h may point ES:DI at a floppy parameter table; the reads below use ES.
    xorw %ax, %ax
    movw %ax, %es
    // Sectors per track are the low six bits of CL; the top two belong to the cylinder.
    andw $0x3F, %cx
    jz .Lgeometry_error
    movw %cx, .Lspt
    movzbw %dh, %ax
    incw %ax
    movw %ax, .Lheads

    movw .Lstage2_lba, %ax
    movw .Lstage2_sectors, %cx
    movw $0x7E00, %bx
.Lchs_next:
    pushw %cx
    pushw %ax
    xorw %dx, %dx
    divw .Lspt
    movw %dx, %cx
    // Sector numbers start at 1.
    incw %cx
    xorw %dx, %dx
    divw .Lheads
    movb %dl, %dh
    movb %al, %ch
    shlb $6, %ah
    orb %ah, %cl
    movb .Ldrive, %dl
    movw $0x0201, %ax
    int $0x13
    popw %ax
    popw %cx
    jc .Lread_error
    incw %ax
    addw $512, %bx
    loop .Lchs_next

.Lloaded:
    // "KBS2" at stage 2's header offset.
    cmpl $0x3253424B, 0x7E08
    jne .Lmagic_error
    movb .Ldrive, %dl
    ljmp $0x0000, $0x7E00

.Lread_error:
    movb $'r', %al
    jmp .Lfail
.Lgeometry_error:
    movb $'g', %al
    jmp .Lfail
.Lmagic_error:
    movb $'m', %al
.Lfail:
    pushw %ax
    movw $.Lmessage, %si
.Lprint:
    lodsb
    testb %al, %al
    jz .Lprinted
    call .Lputc
    jmp .Lprint
.Lprinted:
    popw %ax
    call .Lputc
    int $0x18
    cli
.Lhalt:
    hlt
    jmp .Lhalt

// One character to the screen through the BIOS, and to COM1 directly. The UART may be
// unprogrammed on a real machine, which costs a garbled character, not correctness.
.Lputc:
    pushw %ax
    movb $0x0E, %ah
    movw $0x0007, %bx
    int $0x10
    popw %ax
    movw $0x3F8, %dx
    outb %al, %dx
    ret

.Lmessage:
    .asciz "\r\nkinboot-bios: stage 1 error "
.Ldrive:
    .byte 0
.Lspt:
    .word 0
.Lheads:
    .word 0
// The INT 13h extended read packet: size, reserved, count, buffer offset:segment, LBA.
.Ldap:
    .byte 0x10, 0
.Ldap_count:
    .word 0
    .word 0x7E00, 0x0000
.Ldap_lba:
    .long 0, 0

// The table kbuild fills in. See boot/kinboot-bios/src/disk.rs.
.org 424
    .ascii "KBS1"
.Lstage2_lba:
    .long 0
.Lstage2_sectors:
    .word 0

// 440: disk signature. 446: partition table. Both written by kbuild.
.org 510
    .byte 0x55, 0xAA
"#,
    options(att_syntax)
);

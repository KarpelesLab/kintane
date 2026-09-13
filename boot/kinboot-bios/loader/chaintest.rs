//! The chainload test payload: a partition boot record that checks how it was entered.
//!
//! Not part of the loader. `kbuild` builds it only for `CHAIN_TEST` and writes it as
//! partition 2's first sector, and the test entry in the boot list chainloads that
//! partition. The record then checks exactly what a chainloaded boot record may rely on:
//!
//! - `DL` is the drive the loader was started from;
//! - `DS:SI` points at this partition's entry in a copy of the partition table, whose start LBA is
//!   the sector this record was read from.
//!
//! Both expected values are in a table `kbuild` fills in. It reports on COM1 and exits QEMU
//! through `isa-debug-exit`: `0x10` (exit 33, the harness's pass) if both checks hold,
//! `0x11` (exit 35, a failure) if either does not. A wrong `DL` or a wrong `SI` therefore
//! fails the run at once, instead of hanging it until the timeout.

#![no_std]
#![no_main]

core::arch::global_asm!(
    r#"
.section .chaintest, "awx"
.code16
.globl chaintest_start
chaintest_start:
    cli
    // Keep what the loader handed over before anything else uses the registers.
    movw %si, %bp
    movb %dl, %bh
    xorw %ax, %ax
    movw %ax, %ds
    movw %ax, %ss
    movw $0x7C00, %sp
    cld

    movw $.Lhello, %si
    call .Lputs

    cmpb .Ldrive, %bh
    jne .Lbad_drive
    // SS is zero, so (%bp) addresses the physical byte SI named.
    movl 8(%bp), %eax
    cmpl .Llba, %eax
    jne .Lbad_entry

    movw $.Lpass, %si
    call .Lputs
    movb $0x10, %al
    jmp .Lexit

.Lbad_drive:
    movw $.Ldrive_message, %si
    call .Lputs
    movb $0x11, %al
    jmp .Lexit
.Lbad_entry:
    movw $.Lentry_message, %si
    call .Lputs
    movb $0x11, %al

.Lexit:
    movw $0xF4, %dx
    outb %al, %dx
.Lhalt:
    cli
    hlt
    jmp .Lhalt

.Lputs:
    lodsb
    testb %al, %al
    jz .Ldone
    movw $0x3F8, %dx
    outb %al, %dx
    jmp .Lputs
.Ldone:
    ret

.Lhello:
    .asciz "\r\nchain test: boot record entered\r\n"
.Lpass:
    .asciz "chain test: DL and DS:SI are as a chainloaded record expects\r\n"
.Ldrive_message:
    .asciz "chain test: FAILED, DL is not the boot drive\r\n"
.Lentry_message:
    .asciz "chain test: FAILED, DS:SI is not this partition's entry\r\n"

// The table kbuild fills in: "KBCT", the expected drive, the expected start LBA.
.org 0x1A0
    .ascii "KBCT"
.Ldrive:
    .byte 0
.Llba:
    .long 0

.org 510
    .byte 0x55, 0xAA
"#,
    options(att_syntax)
);

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}

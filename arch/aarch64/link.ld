/* aarch64 kernel image layout for QEMU's `virt` machine.
 *
 * RAM on `virt` begins at 0x40000000 and 0x40080000 is the conventional place to put
 * a kernel there: it is the address the Linux arm64 boot protocol's "text offset" of
 * 0x80000 lands on, and every loader for the board already expects an image to start
 * somewhere at or above it. The half megabyte it leaves below is where QEMU puts the
 * device tree when it has one to hand over, which is why the gap is worth keeping even
 * though nothing reads the DTB yet.
 *
 * There is no header to place first here, unlike multiboot on x86: QEMU loads an ELF
 * and jumps to its entry point, so `.text.boot` leads only so that `_start` sits at a
 * predictable address for a debugger.
 *
 * Like x86_64 this is a Phase 0 identity layout: the image is linked at the physical
 * address it is loaded at and runs with the MMU off. Moving the kernel to the high
 * half is Phase 1 work.
 */

ENTRY(_start)

SECTIONS {
    . = 0x40080000;

    .text : ALIGN(4K) {
        KEEP(*(.text.boot))
        *(.text .text.*)
    }

    .rodata : ALIGN(4K) {
        *(.rodata .rodata.*)
    }

    .data : ALIGN(4K) {
        *(.data .data.*)
        /* A static, non-PIE aarch64 link should need no GOT at all, but LLD will
         * still synthesise one for a stray absolute reference. Naming it keeps it
         * inside a loaded segment rather than orphaned at an arbitrary address. */
        *(.got .got.plt)
    }

    .bss : ALIGN(4K) {
        __bss_start = .;
        *(.bss .bss.*)
        *(COMMON)
        /* The zeroing loop in boot.rs stores 8 bytes at a time and stops on `>=`,
         * so the end must be a multiple of 8 or the last word is skipped. */
        . = ALIGN(16);
        __bss_end = .;
    }

    __kernel_end = .;

    /DISCARD/ : {
        *(.eh_frame)
        *(.note .note.*)
        *(.comment)
    }
}

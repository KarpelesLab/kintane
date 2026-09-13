/* i686 kernel image layout.
 *
 * Linked at 1 MiB, the lowest address a multiboot loader will place a kernel above
 * the legacy low-memory region. The multiboot header must land in the first 8 KiB of
 * the file, which placing it first guarantees.
 *
 * Unlike x86_64 this image is ELF32 natively, so nothing is repackaged after linking:
 * CONFIG_IMAGE_FORMAT is plain "elf" and the linked file is what QEMU boots.
 *
 * Deliberately a low-half identity-mapped layout for Phase 0. i686 is the target
 * where the high half is genuinely scarce — a 32-bit kernel has at most 1 GiB of
 * kernel virtual address space in the conventional 3/1 split — so the Phase 1 move
 * to a high-half layout will have to pick that split here rather than inherit one.
 */

ENTRY(_start)

SECTIONS {
    . = 1M;

    .boot : ALIGN(8) {
        KEEP(*(.multiboot_header))
    }

    .text : ALIGN(4K) {
        KEEP(*(.text.boot))
        *(.text .text.*)
    }

    .rodata : ALIGN(4K) {
        *(.rodata .rodata.*)
    }

    .data : ALIGN(4K) {
        *(.data .data.*)
    }

    .bss : ALIGN(4K) {
        __bss_start = .;
        *(.bss .bss.*)
        *(COMMON)
        __bss_end = .;
    }

    __kernel_end = .;

    /DISCARD/ : {
        *(.eh_frame)
        *(.note .note.*)
        *(.comment)
    }
}

/* x86_64 kernel image layout.
 *
 * Linked at 1 MiB, the lowest address a multiboot loader will place a kernel above
 * the legacy low-memory region. The multiboot header must land in the first 8 KiB of
 * the file, which placing it first guarantees.
 *
 * This is deliberately a low-half identity-mapped layout for Phase 0. Moving the
 * kernel to the high half is Phase 1 work, and it changes the code model in
 * targets/x86_64-kintane.json from "small" to "kernel".
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

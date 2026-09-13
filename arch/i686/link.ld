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
 *
 * ## Why every boundary is page-aligned at both ends
 *
 * The permissions in `hal::ImageSections` are per page, and a page can only carry one
 * set of them. A boundary in the middle of a page forces that page to hold the union
 * of what its two halves need — a `.text`/`.rodata` split sharing a page means either
 * the constants are executable or the instructions are not, and a `.rodata`/`.data`
 * split sharing a page means the constants are writable. Each section therefore pads
 * itself to a page at its end, so the next one starts on a fresh page and the split
 * the symbols describe is the split the MMU can actually enforce.
 *
 * The multiboot header sits at the head of `.text` rather than in a section of its
 * own. It is twelve bytes; giving it a page would cost a page, and giving it an
 * unaligned section of its own would cost the alignment of everything after it. It is
 * read by the loader before the kernel runs and by nothing afterwards, so mapping it
 * read + execute along with the instructions it precedes grants nothing.
 *
 * ## The stack guard page
 *
 * `__stack_guard_start .. __stack_guard_end` is a page-sized hole between the end of
 * `.bss` and the start of `.stack`. No output section covers it, so nothing can be
 * placed there by accident, and the address-space builder leaves it unmapped: the
 * first push past the bottom of the boot stack then faults instead of quietly
 * overwriting whatever the linker happened to put below.
 *
 * This matters more here than on x86_64. A 32-bit gate descriptor has no IST field
 * (see `src/idt.rs`), so this port cannot give #DF a private stack — detecting the
 * overflow before it becomes a #DF is the only option the hardware leaves.
 *
 * `.stack` is a section of its own for the same reason: while the boot stack lived at
 * the end of the general `.bss`, the sixteen kilobytes directly beneath it were the
 * early PAE page directories, and an overflow walked into the live translation tables.
 * Those now sit at the *bottom* of `.bss`, as far from the stack as the image allows.
 */

ENTRY(_start)

SECTIONS {
    . = 1M;
    __kernel_start = .;

    .text : ALIGN(4K) {
        __text_start = .;
        KEEP(*(.multiboot_header))
        KEEP(*(.text.boot))
        *(.text .text.*)
        . = ALIGN(4K);
        __text_end = .;
    }

    .rodata : ALIGN(4K) {
        __rodata_start = .;
        *(.rodata .rodata.*)
        . = ALIGN(4K);
        __rodata_end = .;
    }

    /* `.data`, `.bss`, the guard hole and `.stack` are one writable run: the data
     * range reported by `image_sections()` spans all four, and the guard is punched
     * back out of it. `__data_start` is assigned outside the section description
     * because `.data` is empty in this image today and an empty output section is
     * dropped, taking any symbol defined inside it along. */
    . = ALIGN(4K);
    __data_start = .;

    .data : ALIGN(4K) {
        *(.data .data.*)
        . = ALIGN(4K);
    }

    .bss : ALIGN(4K) {
        __bss_start = .;
        /* The early PAE tables first, so the far end of `.bss` — the end nearest the
         * stack — is ordinary Rust statics rather than the live page tables. */
        *(.bss.boot_tables)
        *(.bss .bss.*)
        *(COMMON)
        . = ALIGN(4K);
        __bss_end = .;
    }

    /* The guard. One page, covered by no section, left unmapped. */
    . = ALIGN(4K);
    __stack_guard_start = .;
    . = . + 4K;
    __stack_guard_end = .;

    .stack : ALIGN(4K) {
        __stack_bottom = .;
        KEEP(*(.stack))
        . = ALIGN(4K);
        __stack_top = .;
    }

    __data_end = .;
    __kernel_end = .;

    /DISCARD/ : {
        *(.eh_frame)
        *(.note .note.*)
        *(.comment)
    }
}

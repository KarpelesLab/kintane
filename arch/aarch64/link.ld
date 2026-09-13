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
 * address it is loaded at. Moving the kernel to the high half is Phase 1 work.
 *
 * # Why every boundary is page-aligned
 *
 * The three ranges below are handed to the address-space builder through
 * `hal::ImageSections`, which maps `.text` read+execute, `.rodata` read-only and
 * `.data`+`.bss` read+write+no-execute. A permission boundary is a property of a page,
 * not of a byte: if `.text` ended halfway through a page the page holding both its tail
 * and `.rodata`'s head would have to be mapped with the union of the two — writable and
 * executable at once is exactly what the split exists to prevent. So each section is
 * aligned at its start *and* padded to a page at its end, and the symbols marking them
 * are therefore page-aligned on both sides by construction.
 *
 * # The stack guard
 *
 * `.stack_guard` is a page of nothing between `.bss` and the boot stack, reserved so
 * that the builder can leave it unmapped. Without it a stack overflow runs quietly off
 * the bottom of the stack into whatever the linker placed below — here that would be
 * the translation tables, which are in `.bss` — and the machine is gone before any
 * handler can say so. With it, the overflowing store takes a translation fault at a
 * known address, which the exception path can report.
 *
 * It is deliberately its own output section rather than padding inside `.bss`: a hole
 * that shows up in `llvm-objdump -h` is a hole somebody can check, and nothing can
 * drift into it. It is also outside `[__bss_start, __bss_end)`, so even the boot
 * zeroing loop never touches it.
 */

ENTRY(_start)

/* One 4 KiB page — the granule this port configures in TCR_EL1.TG0. Every boundary
 * below is a multiple of it. */
PAGE_SIZE = 4K;

SECTIONS {
    . = 0x40080000;
    __kernel_start = .;

    .text : ALIGN(PAGE_SIZE) {
        __text_start = .;
        KEEP(*(.text.boot))
        *(.text .text.*)
        . = ALIGN(PAGE_SIZE);
        __text_end = .;
    }

    .rodata : ALIGN(PAGE_SIZE) {
        __rodata_start = .;
        *(.rodata .rodata.*)
        . = ALIGN(PAGE_SIZE);
        __rodata_end = .;
    }

    /* `.data`, `.bss` and the boot stack are one permission region — read, write, never
     * execute — so `__data_start` opens here and `__data_end` closes past the stack. */
    .data : ALIGN(PAGE_SIZE) {
        __data_start = .;
        *(.data .data.*)
        /* A static, non-PIE aarch64 link should need no GOT at all, but LLD will
         * still synthesise one for a stray absolute reference. Naming it keeps it
         * inside a loaded segment rather than orphaned at an arbitrary address. */
        *(.got .got.plt)
    }

    .bss : ALIGN(PAGE_SIZE) {
        __bss_start = .;
        *(.bss .bss.*)
        *(COMMON)
        /* The zeroing loop in boot.rs stores 8 bytes at a time and stops on `>=`, so
         * the end must be a multiple of 8 or the last word is skipped. Rounding to a
         * whole page satisfies that and also puts the guard page immediately above,
         * with no byte of `.bss` sharing a page with it. */
        . = ALIGN(PAGE_SIZE);
        __bss_end = .;
    }

    .stack_guard (NOLOAD) : ALIGN(PAGE_SIZE) {
        __stack_guard_start = .;
        . += PAGE_SIZE;
        __stack_guard_end = .;
    }

    /* The boot stack, grown downward from `__stack_top` towards the guard page. It is
     * `nobits` like `.bss` but lives outside it, so it is not zeroed at boot; nothing
     * reads a stack slot it has not written. */
    .stack : ALIGN(PAGE_SIZE) {
        *(.stack)
        . = ALIGN(PAGE_SIZE);
    }

    __data_end = .;
    __kernel_end = .;

    /DISCARD/ : {
        *(.eh_frame)
        *(.note .note.*)
        *(.comment)
    }
}

/* The layout above is load-bearing for W^X and for the guard page, and a silent
 * regression — an added section landing between two of these, an alignment lost in a
 * refactor — would show up as permissions quietly merging rather than as a link error.
 * These assertions make it a link error. */
ASSERT(__text_start % PAGE_SIZE == 0, "__text_start is not page-aligned")
ASSERT(__text_end % PAGE_SIZE == 0, "__text_end is not page-aligned")
ASSERT(__rodata_start % PAGE_SIZE == 0, "__rodata_start is not page-aligned")
ASSERT(__rodata_end % PAGE_SIZE == 0, "__rodata_end is not page-aligned")
ASSERT(__data_start % PAGE_SIZE == 0, "__data_start is not page-aligned")
ASSERT(__data_end % PAGE_SIZE == 0, "__data_end is not page-aligned")
ASSERT(__text_end <= __rodata_start, ".text and .rodata overlap")
ASSERT(__rodata_end <= __data_start, ".rodata and .data overlap")
ASSERT(__stack_guard_end - __stack_guard_start == PAGE_SIZE, "the stack guard is not one page")
ASSERT(__bss_end <= __stack_guard_start, ".bss runs into the stack guard")
ASSERT(__stack_guard_end <= __stack_top, "the stack guard overlaps the stack")
ASSERT(__stack_top - __stack_bottom >= 4 * PAGE_SIZE, "the boot stack shrank")

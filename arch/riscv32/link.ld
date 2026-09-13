/* riscv32 kernel image layout for QEMU's `virt` machine, run with `-bios none`.
 *
 * RAM on `virt` begins at 0x80000000. With no firmware, QEMU's reset vector at 0x1000
 * jumps straight there in M-mode with the hart ID in a0 and the device tree's address
 * in a1, so the image is linked at the base of RAM and `_start` must come first.
 * QEMU places the device tree near the top of RAM, out of the image's way.
 *
 * There is no MMU, so nothing here is a permission boundary the hardware enforces.
 * The layout is the other ports' anyway — page-aligned `.text`, `.rodata` and `.data`,
 * a page below the boot stack, a run of thread-stack slots — because `hal::ImageSections`
 * describes it and the unwinder confines its walks by it. The "guard" pages are memory
 * nothing uses and nothing protects: an overflow here is not caught. PMP could make
 * them faults, and does not yet; see `src/kspace.rs`.
 */

OUTPUT_ARCH(riscv)
ENTRY(_start)

PAGE_SIZE = 4K;

/* See `.thread_stacks` below. */
THREAD_STACK_SLOT = 32K;
THREAD_STACK_SLOTS = 8;

SECTIONS {
    . = 0x80000000;
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
        /* The build ID kbuild stamps after linking; see lib/buildid. */
        KEEP(*(.kintane_build_id))
        *(.rodata .rodata.*)
        *(.srodata .srodata.*)
        . = ALIGN(PAGE_SIZE);
        __rodata_end = .;
    }

    .data : ALIGN(PAGE_SIZE) {
        __data_start = .;
        *(.data .data.*)
        *(.sdata .sdata.*)
        *(.got .got.plt)
    }

    .bss : ALIGN(PAGE_SIZE) {
        __bss_start = .;
        *(.sbss .sbss.*)
        *(.bss .bss.*)
        *(COMMON)
        /* The zeroing loop stores a word at a time and stops on `>=`. */
        . = ALIGN(PAGE_SIZE);
        __bss_end = .;
    }

    .stack_guard (NOLOAD) : ALIGN(PAGE_SIZE) {
        __stack_guard_start = .;
        . += PAGE_SIZE;
        __stack_guard_end = .;
    }

    .stack : ALIGN(PAGE_SIZE) {
        *(.stack)
        . = ALIGN(PAGE_SIZE);
    }

    .thread_stacks (NOLOAD) : ALIGN(4K) {
        __thread_stacks_start = .;
        . += THREAD_STACK_SLOTS * THREAD_STACK_SLOT;
        __thread_stacks_end = .;
    }

    __data_end = .;
    __kernel_end = .;

    /DISCARD/ : {
        *(.eh_frame)
        *(.note .note.*)
        *(.comment)
        *(.riscv.attributes)
    }
}

ASSERT(_start == 0x80000000, "_start is not the first instruction of the image")
ASSERT(__text_end <= __rodata_start, ".text and .rodata overlap")
ASSERT(__rodata_end <= __data_start, ".rodata and .data overlap")
ASSERT(__bss_end <= __stack_guard_start, ".bss runs into the stack guard")
ASSERT(__stack_guard_end <= __stack_top, "the stack guard overlaps the stack")
ASSERT(__stack_top - __stack_bottom >= 4 * PAGE_SIZE, "the boot stack shrank")
ASSERT(THREAD_STACK_SLOT == 32K, "THREAD_STACK_SLOT disagrees with src/lib.rs")
ASSERT((__thread_stacks_end - __thread_stacks_start) % THREAD_STACK_SLOT == 0, "thread stacks are not whole slots")

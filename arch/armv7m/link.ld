/* armv7m kernel image layout for QEMU's `mps2-an385` machine, executing in place.
 *
 * At reset an ARMv7-M core reads its initial main stack pointer from address 0 and
 * its reset vector from address 4: the vector table must be at the base of the code
 * memory, and there is no loader to put it anywhere else. So this is an XIP image in
 * the classic Cortex-M shape:
 *
 *   FLASH  .vectors, .text, .rodata, and the initial contents of .data, which are
 *          loaded here (their LMA) and copied to RAM by the reset handler.
 *   RAM    .data (its VMA), .bss, the handler stack, a guard page, the boot stack, and
 *          the thread-stack slots.
 *
 * "Flash" is the AN385's ZBT SSRAM1, which QEMU models as RAM; config/boards/ says why
 * this port treats it as read-only anyway. The MPU enforces it once it is on.
 *
 * Execution runs on two stacks, as Cortex-M software usually does. Handlers run on
 * the main stack (MSP), which the vector table's first word points at. Threads,
 * including boot from the moment the reset handler switches, run on the process
 * stack (PSP). An overflow of a thread's stack therefore faults while the handler that
 * reports it still has a stack of its own.
 */

MEMORY {
    FLASH (rx) : ORIGIN = 0x00000000, LENGTH = 4M
    RAM (rwx)  : ORIGIN = 0x20000000, LENGTH = 4M
}

ENTRY(__reset)

PAGE_SIZE = 4K;

/* The configuration's numbers, which is how a board too small for the defaults shrinks
 * what the image reserves: CONFIG_BOOT_STACK_KIB and CONFIG_HANDLER_STACK_KIB below.
 * `src/lib.rs` reads the same symbols through kconfig, and the assertions at the end of
 * this file check the two agree. */
INCLUDE sizes.ld

/* THREAD_STACK_SLOT and THREAD_STACK_SLOTS: the thread-stack array's geometry, derived by
 * kbuild from THREAD_STACK_KIB, KERNEL_THREAD_SLOTS and NR_CPUS (`codegen::stacks`). A
 * slot's guard is a quarter of it, because an MPU region covers two slots and its
 * subregions are eighths of the region. See `.thread_stacks` below. */
INCLUDE stacks.ld
THREAD_STACK_GUARD = THREAD_STACK_SLOT / 4;

SECTIONS {
    __kernel_start = ORIGIN(FLASH);

    .text ORIGIN(FLASH) : {
        __text_start = .;
        KEEP(*(.vectors))
        *(.text .text.*)
        . = ALIGN(4);
        __text_end = .;
    } > FLASH

    /* Word-aligned, not page-aligned. This core has no pages: the MPU's flash region is
     * the whole of flash and its RAM region the whole of RAM, so a section boundary
     * rounded to 4 KiB protects nothing and costs up to a page of flash per section —
     * 5 KiB of a 64 KiB image. The guard below the boot stack does stay page-aligned,
     * because it is an MPU region of its own. */
    .rodata : ALIGN(4) {
        __rodata_start = .;
        /* The build ID kbuild stamps after linking; see lib/buildid. */
        KEEP(*(.kintane_build_id))
        *(.rodata .rodata.*)
        . = ALIGN(4);
        __rodata_end = .;
    } > FLASH

    .data : ALIGN(4) {
        __data_start = .;
        *(.data .data.*)
        /* The copy loop moves a word at a time and stops on `>=`. */
        . = ALIGN(4);
        __data_init_end = .;
    } > RAM AT > FLASH
    __data_load = LOADADDR(.data);

    .bss (NOLOAD) : ALIGN(4) {
        __bss_start = .;
        *(.bss .bss.*)
        *(COMMON)
        . = ALIGN(4);
        __bss_end = .;
    } > RAM

    /* The main stack: exceptions and interrupts only. Below it is .bss, so an overflow
     * of this one is not caught; handlers here are small and do not nest deeply. */
    .handler_stack (NOLOAD) : ALIGN(8) {
        __handler_stack_bottom = .;
        . += CONFIG_HANDLER_STACK_KIB * 1K;
        __handler_stack_top = .;
    } > RAM

    /* A page no region of the MPU lets anything read or write, below the boot stack.
     * MPU region bases must be multiples of the region's size. */
    .stack_guard (NOLOAD) : ALIGN(PAGE_SIZE) {
        __stack_guard_start = .;
        . += PAGE_SIZE;
        __stack_guard_end = .;
    } > RAM

    .stack (NOLOAD) : {
        __stack_bottom = .;
        . += CONFIG_BOOT_STACK_KIB * 1K;
        __stack_top = .;
    } > RAM

    /* Kernel thread stacks: THREAD_STACK_SLOTS slots of THREAD_STACK_SLOT bytes, each
     * with THREAD_STACK_GUARD bytes at its bottom that the MPU forbids. The array starts
     * on a 64 KiB boundary because each MPU region covers two slots, 64 KiB, with the
     * two guards as its enabled subregions — eight regions would not stretch to one
     * per slot. That is also why a guard is a quarter of a slot rather than a page: a
     * subregion is an eighth of its region. */
    .thread_stacks (NOLOAD) : ALIGN(2 * THREAD_STACK_SLOT) {
        __thread_stacks_start = .;
        . += THREAD_STACK_SLOTS * THREAD_STACK_SLOT;
        __thread_stacks_end = .;
    } > RAM

    __data_end = .;
    __kernel_end = .;

    /DISCARD/ : {
        *(.ARM.exidx .ARM.exidx.*)
        *(.ARM.extab .ARM.extab.*)
        *(.ARM.attributes)
        *(.eh_frame)
        *(.note .note.*)
        *(.comment)
    }
}

ASSERT(__reset != 0, "no reset handler")
ASSERT(__text_start == 0, "the vector table is not at address 0")
ASSERT(__text_end <= __rodata_start, ".text and .rodata overlap")
ASSERT(__data_load >= __rodata_end, ".data's load copy overlaps .rodata")
ASSERT(__bss_end <= __handler_stack_bottom, ".bss runs into the handler stack")
ASSERT(__stack_guard_end <= __stack_bottom, "the stack guard overlaps the stack")
ASSERT(__thread_stacks_start % (2 * THREAD_STACK_SLOT) == 0, "thread stacks do not start on an MPU region boundary")
ASSERT(THREAD_STACK_SLOT >= 1K, "a thread stack slot must be at least 1 KiB")
ASSERT(THREAD_STACK_GUARD * 4 == THREAD_STACK_SLOT, "a guard is a quarter of its slot")
ASSERT(THREAD_STACK_SLOTS % 2 == 0, "an MPU region covers two thread-stack slots")

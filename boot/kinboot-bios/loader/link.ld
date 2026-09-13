/*
 * kinboot-bios memory layout.
 *
 * The BIOS loads sector 0 at 0x7C00. Stage 1 loads stage 2 immediately after it, at
 * 0x7E00, from LBA 1. So the flat binary `llvm-objcopy -O binary` makes of this file is
 * exactly the first sectors of the disk: 512 bytes of stage 1, then stage 2.
 *
 *   0x00000 - 0x004FF   IVT and BIOS data area
 *   0x00500 - 0x07BFF   real-mode stack, growing down from 0x7C00
 *   0x07C00 - 0x07DFF   stage 1
 *   0x07E00 - ...       stage 2 code and data; at most 32 KiB, so below 0xFE00
 *   ...     - 0x1FFFF   stage 2 .bss: its protected-mode stack and handover buffers
 *   0x20000 - 0x2FFFF   disk bounce buffer (fixed; see loader/main.rs)
 *
 * Every limit below that can be checked at link time is checked here, so a loader that
 * outgrows its layout fails to link instead of failing to boot.
 */

ENTRY(stage1_start)

SECTIONS
{
    . = 0x7C00;
    .stage1 : {
        KEEP(*(.stage1))
    }
    ASSERT(SIZEOF(.stage1) == 512, "stage 1 must be exactly one sector")

    . = 0x7E00;
    __stage2_start = .;
    .stage2 : {
        /* The jump and the disk header first: the header's offset is part of the disk
         * layout (boot/kinboot-bios/src/disk.rs). */
        KEEP(*(.stage2.head))
        /* Code and data used in real mode, addressed with 16-bit offsets. */
        KEEP(*(.stage2.real))
        *(.text .text.*)
        *(.rodata .rodata.*)
        *(.data .data.*)
    }
    __stage2_end = .;
    ASSERT(__stage2_end - __stage2_start <= 64 * 512,
           "stage 2 exceeds its 32 KiB budget (docs/bootloader.md)")

    .bss (NOLOAD) : {
        __bss_start = .;
        *(.bss .bss.*)
        *(COMMON)
        __bss_end = .;
    }
    ASSERT(__bss_end <= 0x20000, "stage 2 memory would overlap the bounce buffer")

    /DISCARD/ : {
        *(.eh_frame .eh_frame_hdr)
        *(.comment)
        *(.note .note.*)
    }
}

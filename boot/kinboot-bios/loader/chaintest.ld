/*
 * The chainload test payload: one boot record sector, entered at 0x7C00.
 * See chaintest.rs. The flat binary of this is exactly the sector kbuild writes.
 */

ENTRY(chaintest_start)

SECTIONS
{
    . = 0x7C00;
    .chaintest : {
        KEEP(*(.chaintest))
    }
    ASSERT(SIZEOF(.chaintest) == 512, "the chain test record must be exactly one sector")

    /DISCARD/ : {
        *(.text .text.* .rodata .rodata.* .data .data.* .bss .bss.*)
        *(.eh_frame .eh_frame_hdr)
        *(.comment)
        *(.note .note.*)
    }
}

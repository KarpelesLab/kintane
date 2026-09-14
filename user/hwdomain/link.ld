/* The domain program's layout, the same shape as `user/init/link.ld`: text, read-only
 * data and writable data, each in its own page-aligned segment with the permissions the
 * loader maps it with, so the loader's W^X rule is met by construction.
 *
 * Linked at the same address as `init`. Two programs may share a link address because each
 * runs in its own address space; nothing maps both at once.
 *
 * The granted register window and the channel are *not* here. They are placed by the
 * kernel, at addresses it passes in argument registers, because a domain must not be able
 * to decide for itself what hardware it can reach. */
ENTRY(_start)

PHDRS
{
    text   PT_LOAD FLAGS(5);   /* R X */
    rodata PT_LOAD FLAGS(4);   /* R   */
    data   PT_LOAD FLAGS(6);   /* R W */
}

SECTIONS
{
    . = 0x8000010000;

    .text : ALIGN(4K) {
        *(.text._start)
        *(.text .text.*)
    } :text

    . = ALIGN(4K);
    .rodata : {
        *(.rodata .rodata.*)
    } :rodata

    . = ALIGN(4K);
    .data : {
        *(.data .data.*)
        *(.got .got.*)
    } :data
    .bss : {
        *(.bss .bss.*)
        *(COMMON)
    } :data

    /DISCARD/ : {
        *(.eh_frame .eh_frame_hdr)
        *(.comment)
        *(.note .note.*)
    }
}

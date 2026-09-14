/* The block domain program's layout, the same shape as `user/init/link.ld`: text, read-only
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
    rodata PT_LOAD FLAGS(4);
    note   PT_NOTE FLAGS(4);   /* R   */
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
    /* The KinTane ABI note: what tells the loader this is a native program. Without it a
     * program is taken for a Linux one (see docs/userspace-abi.md). Written as data here
     * rather than by the program, so no program can forget it: owner "KinTane", type 0x4b54,
     * and the native ABI version, 1. */
    .note.kintane : {
        LONG(8) LONG(4) LONG(0x4b54)
        BYTE(0x4b) BYTE(0x69) BYTE(0x6e) BYTE(0x54) BYTE(0x61) BYTE(0x6e) BYTE(0x65) BYTE(0x00)
        LONG(1)
    } :rodata :note
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

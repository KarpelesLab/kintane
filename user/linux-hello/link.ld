/* A static Linux program's layout: text, read-only data and writable data, each in its own
 * page-aligned segment, so the loader's W^X rule is met by construction.
 *
 * Linked at 0x80_0040_0000, in the user half, 4 MiB above its start. Unlike the native
 * programs' script this one keeps no KinTane ABI note: its notes are discarded, and a
 * program without the note is what the loader tags `linux`. */
ENTRY(_start)

PHDRS
{
    text   PT_LOAD FLAGS(5);   /* R X */
    rodata PT_LOAD FLAGS(4);   /* R   */
    data   PT_LOAD FLAGS(6);   /* R W */
}

SECTIONS
{
    . = 0x8000400000;

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

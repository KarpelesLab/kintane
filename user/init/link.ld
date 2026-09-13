/* A user program's layout: text, read-only data and writable data, each in its own
 * page-aligned segment with the permissions the loader will map it with.
 *
 * Linked at 0x80_0001_0000: 64 KiB into the user half, which begins at 512 GiB, the
 * first address past the one top-level page-table entry the kernel keeps for itself on
 * both x86_64 and aarch64. The page at the bottom of the user half stays unmapped.
 *
 * PHDRS are explicit so that the loader's W^X rule is met by construction: no segment
 * here is both writable and executable, and a section the linker would otherwise place
 * in a mixed segment has nowhere to go but the three below. */
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

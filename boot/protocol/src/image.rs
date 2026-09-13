//! The kernel image as a loader sees it: what to copy where, and where to jump.
//!
//! # The entry note
//!
//! A kernel image may be entered in more than one way. The x86_64 image is a multiboot
//! kernel whose ELF entry point is 32-bit protected-mode code, because that is what a
//! multiboot loader calls. A UEFI loader hands over in long mode, and jumping to 32-bit
//! code from there does not work. So the image names its protocol entry separately, in an
//! ELF note:
//!
//! ```text
//! PT_NOTE   namesz = 8, descsz = 16, type = NOTE_ENTRY (1)
//!           name   "KinTane\0"
//!           desc   entry: u64 (physical address), protocol: u32 = VERSION, _reserved: u32
//! ```
//!
//! A note rather than a magic number to scan for, like the multiboot header: the program
//! headers say exactly where it is, there is nothing to guess, and `llvm-objcopy
//! --strip-all` keeps it because it is allocated. The ELF `e_entry` stays whatever the
//! image's other boot path needs.
//!
//! # What the entry expects
//!
//! Stated here because every loader for the architecture must provide it:
//!
//! - **x86, 32-bit protected mode** (i686 and x86_64 alike): the ELF entry point, which is the
//!   image's Multiboot entry; paging off; flat 4 GiB code and data segments; interrupts disabled;
//!   `EAX` = [`crate::ENTRY32_MAGIC`]; `EBX` = the boot information's physical address, below 4
//!   GiB. That is Multiboot 1's machine state with a different magic, on purpose: the kernel's
//!   32-bit entry is already written for exactly that state, and the magic tells a reader which
//!   structure `EBX` points at. `kinboot-bios` enters this way.
//! - **x86_64:** long mode; interrupts disabled; direction flag clear; the loaded segments and the
//!   boot information identity-mapped; the boot information's physical address in `rdi`. The kernel
//!   takes its own stack, page tables and GDT before it touches anything else, so the loader's are
//!   only borrowed for a handful of instructions.
//!
//! # Untrusted input
//!
//! The image comes off a disk. Every offset and size is checked against the file and
//! against overflow before it is used, and a segment whose file bytes are longer than its
//! memory size is rejected rather than truncated.

use crate::VERSION;

/// Owner name of KinTane's ELF notes, NUL-terminated as the ELF specification requires.
pub const NOTE_NAME: &[u8; 8] = b"KinTane\0";
/// Note type carrying the protocol entry point.
pub const NOTE_ENTRY: u32 = 1;

const PT_LOAD: u32 = 1;
const PT_NOTE: u32 = 4;
const ELFCLASS64: u8 = 2;
const EHDR_SIZE: usize = 64;
const PHDR_SIZE: usize = 56;

/// Why an image cannot be loaded.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ImageError {
    /// Not an ELF file, or not the 64-bit little-endian kind a loader of this version
    /// understands.
    NotElf64,
    /// The file ends before a header or segment it describes.
    Truncated,
    /// A size or address that overflows, or a segment with more file bytes than memory.
    BadSegment,
    /// No loadable segment at all.
    NoSegments,
    /// No KinTane entry note: this image was not built to be entered by the protocol.
    NoEntryNote,
    /// The entry note was written for a newer protocol than this loader speaks.
    UnsupportedProtocol(u32),
    /// The entry point is outside every loadable segment.
    EntryOutsideImage,
}

fn u16_at(b: &[u8], at: usize) -> Result<u16, ImageError> {
    b.get(at..at + 2)
        .and_then(|s| s.try_into().ok())
        .map(u16::from_le_bytes)
        .ok_or(ImageError::Truncated)
}

fn u32_at(b: &[u8], at: usize) -> Result<u32, ImageError> {
    b.get(at..at + 4)
        .and_then(|s| s.try_into().ok())
        .map(u32::from_le_bytes)
        .ok_or(ImageError::Truncated)
}

fn u64_at(b: &[u8], at: usize) -> Result<u64, ImageError> {
    b.get(at..at + 8)
        .and_then(|s| s.try_into().ok())
        .map(u64::from_le_bytes)
        .ok_or(ImageError::Truncated)
}

/// One loadable segment: copy `file` to `phys`, then zero up to `mem_size`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Segment<'a> {
    pub phys: u64,
    pub mem_size: u64,
    pub file: &'a [u8],
}

/// A validated kernel image.
#[derive(Clone, Copy)]
pub struct Image<'a> {
    bytes: &'a [u8],
    phoff: usize,
    phnum: usize,
    /// Physical entry point from the KinTane note.
    pub entry: u64,
    /// Lowest physical address any segment occupies.
    pub phys_start: u64,
    /// One past the highest physical address any segment occupies.
    pub phys_end: u64,
}

impl<'a> Image<'a> {
    /// Validate an ELF64 kernel image and find its protocol entry.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, ImageError> {
        let ident = bytes.get(..EHDR_SIZE).ok_or(ImageError::NotElf64)?;
        // Little-endian only: every architecture this version of the protocol serves is.
        if &ident[0..4] != b"\x7fELF" || ident[4] != ELFCLASS64 || ident[5] != 1 {
            return Err(ImageError::NotElf64);
        }
        let phoff = usize::try_from(u64_at(bytes, 32)?).map_err(|_| ImageError::Truncated)?;
        let phentsize = usize::from(u16_at(bytes, 54)?);
        let phnum = usize::from(u16_at(bytes, 56)?);
        if phentsize != PHDR_SIZE {
            return Err(ImageError::NotElf64);
        }
        let table_end = phnum
            .checked_mul(PHDR_SIZE)
            .and_then(|n| n.checked_add(phoff))
            .ok_or(ImageError::Truncated)?;
        if table_end > bytes.len() {
            return Err(ImageError::Truncated);
        }

        let mut image = Image {
            bytes,
            phoff,
            phnum,
            entry: 0,
            phys_start: u64::MAX,
            phys_end: 0,
        };
        let mut entry = None;
        for i in 0..phnum {
            let ph = phoff + i * PHDR_SIZE;
            match u32_at(bytes, ph)? {
                PT_LOAD => {
                    let seg = image.segment_at(ph)?;
                    let end = seg
                        .phys
                        .checked_add(seg.mem_size)
                        .ok_or(ImageError::BadSegment)?;
                    if seg.mem_size > 0 {
                        image.phys_start = image.phys_start.min(seg.phys);
                        image.phys_end = image.phys_end.max(end);
                    }
                }
                PT_NOTE => {
                    if let Some(e) = entry_from_notes(file_range(bytes, ph)?)? {
                        entry = Some(e);
                    }
                }
                _ => {}
            }
        }
        if image.phys_end == 0 {
            return Err(ImageError::NoSegments);
        }
        image.entry = entry.ok_or(ImageError::NoEntryNote)?;
        let inside = image.segments().any(|s| {
            s.map(|s| s.phys <= image.entry && image.entry < s.phys + s.mem_size)
                .unwrap_or(false)
        });
        if !inside {
            return Err(ImageError::EntryOutsideImage);
        }
        Ok(image)
    }

    fn segment_at(&self, ph: usize) -> Result<Segment<'a>, ImageError> {
        let file = file_range(self.bytes, ph)?;
        let phys = u64_at(self.bytes, ph + 24)?;
        let mem_size = u64_at(self.bytes, ph + 40)?;
        if file.len() as u64 > mem_size {
            return Err(ImageError::BadSegment);
        }
        phys.checked_add(mem_size).ok_or(ImageError::BadSegment)?;
        Ok(Segment {
            phys,
            mem_size,
            file,
        })
    }

    /// The loadable segments, in program header order.
    pub fn segments(&self) -> impl Iterator<Item = Result<Segment<'a>, ImageError>> + '_ {
        (0..self.phnum).filter_map(move |i| {
            let ph = self.phoff + i * PHDR_SIZE;
            match u32_at(self.bytes, ph) {
                Ok(PT_LOAD) => Some(self.segment_at(ph)),
                Ok(_) => None,
                Err(e) => Some(Err(e)),
            }
        })
    }
}

/// The bytes a program header's `p_offset`/`p_filesz` describe.
fn file_range(bytes: &[u8], ph: usize) -> Result<&[u8], ImageError> {
    let off = usize::try_from(u64_at(bytes, ph + 8)?).map_err(|_| ImageError::Truncated)?;
    let len = usize::try_from(u64_at(bytes, ph + 32)?).map_err(|_| ImageError::Truncated)?;
    let end = off.checked_add(len).ok_or(ImageError::Truncated)?;
    bytes.get(off..end).ok_or(ImageError::Truncated)
}

/// Walk one PT_NOTE segment for the KinTane entry note.
fn entry_from_notes(mut notes: &[u8]) -> Result<Option<u64>, ImageError> {
    while notes.len() >= 12 {
        let namesz = u32_at(notes, 0)? as usize;
        let descsz = u32_at(notes, 4)? as usize;
        let kind = u32_at(notes, 8)?;
        // Name and descriptor are each padded to four bytes in ELF64 notes as written by
        // every toolchain in practice, which is what lld emits.
        let pad4 = |n: usize| {
            n.checked_add(3)
                .map(|v| v & !3)
                .ok_or(ImageError::Truncated)
        };
        let name_end = 12usize
            .checked_add(pad4(namesz)?)
            .ok_or(ImageError::Truncated)?;
        let desc_end = name_end
            .checked_add(pad4(descsz)?)
            .ok_or(ImageError::Truncated)?;
        let name = notes.get(12..12 + namesz).ok_or(ImageError::Truncated)?;
        let desc = notes
            .get(name_end..name_end + descsz)
            .ok_or(ImageError::Truncated)?;
        if name == NOTE_NAME && kind == NOTE_ENTRY {
            if descsz < 16 {
                return Err(ImageError::Truncated);
            }
            let protocol = u32_at(desc, 8)?;
            if protocol > u32::from(VERSION) {
                return Err(ImageError::UnsupportedProtocol(protocol));
            }
            return Ok(Some(u64_at(desc, 0)?));
        }
        notes = notes.get(desc_end..).unwrap_or(&[]);
    }
    Ok(None)
}

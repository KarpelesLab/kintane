//! Static ELF64 executables, as the kernel loads them into a new process.
//!
//! This is the program loader's view of a file, not a general ELF library: it answers
//! "what goes where, with which permissions, and where does it start", and it refuses
//! every file for which the answer would be unsafe to act on. The bytes come from
//! whoever built the program, so nothing in them is trusted.
//!
//! # What is refused, and why each rule exists
//!
//! * Anything but a little-endian, 64-bit, `ET_EXEC` file for the expected machine. A
//!   position-independent executable (`ET_DYN`) needs relocation, which this loader does not do
//!   yet; accepting one and mapping it at its link address would run it with every absolute address
//!   wrong.
//! * A loadable segment that is both writable and executable. The kernel keeps W^X for itself, and
//!   a loader that mapped user pages W+X on request would make the rule a suggestion.
//! * A segment outside the address range the caller gives, which is the user half. Without this
//!   check a file could ask for a mapping on top of the kernel.
//! * Two segments that share a page. Each segment becomes a region with its own permissions, and a
//!   page cannot have two.
//! * More file bytes than memory bytes, sizes that overflow, and offsets past the end of the file.
//! * An entry point that is not inside an executable segment.
//!
//! A `PT_LOAD` segment's permissions are its `p_flags`, and only those. Sections are not
//! consulted: the loader maps segments, and a file whose program headers disagree with
//! its section headers gets what the program headers say.

#![cfg_attr(not(test), no_std)]
#![deny(unsafe_code)]

#[cfg(test)]
mod tests;

/// `e_machine` for x86_64.
pub const EM_X86_64: u16 = 62;
/// `e_machine` for aarch64.
pub const EM_AARCH64: u16 = 183;

const ET_EXEC: u16 = 2;
const PT_LOAD: u32 = 1;
const PF_X: u32 = 1;
const PF_W: u32 = 2;
const PF_R: u32 = 4;
const EHDR_SIZE: usize = 64;
const PHDR_SIZE: usize = 56;

/// The most loadable segments a program may have. A static program has three or four;
/// the bound keeps the overlap check's cost fixed.
pub const MAX_SEGMENTS: usize = 16;

/// Why a file is not a program this loader will run.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Error {
    /// Not a little-endian ELF64 file.
    NotElf64,
    /// An ELF file, but not a static executable (`ET_EXEC`).
    NotExecutable,
    /// Built for another machine.
    WrongMachine(u16),
    /// A header or segment runs past the end of the file.
    Truncated,
    /// A size or address overflows, or a segment has more file bytes than memory.
    BadSegment,
    /// A segment is both writable and executable.
    WritableAndExecutable,
    /// A segment lies outside the address range the program may occupy.
    OutsideRange,
    /// Two segments share a page.
    Overlap,
    /// More than [`MAX_SEGMENTS`] loadable segments.
    TooManySegments,
    /// No loadable segment with any memory.
    NoSegments,
    /// The entry point is not inside an executable segment.
    EntryNotExecutable,
}

/// A segment's permissions.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Access {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
}

/// One loadable segment: `file` goes at `vaddr`, and the rest up to `mem_size` is zero.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Segment<'a> {
    pub vaddr: u64,
    pub mem_size: u64,
    pub file: &'a [u8],
    pub access: Access,
}

impl Segment<'_> {
    /// The pages the segment touches, `[start, end)`, for pages of `page` bytes.
    pub fn pages(&self, page: u64) -> (u64, u64) {
        let start = self.vaddr & !(page - 1);
        // Cannot overflow: `parse` checked `vaddr + mem_size` against the range's end,
        // which the caller gave page-aligned below the top of the address space.
        let end = (self.vaddr + self.mem_size).div_ceil(page) * page;
        (start, end)
    }
}

/// A validated program.
#[derive(Clone, Copy)]
pub struct Program<'a> {
    bytes: &'a [u8],
    phoff: usize,
    phnum: usize,
    pub entry: u64,
}

fn u16_at(b: &[u8], at: usize) -> Result<u16, Error> {
    b.get(at..at + 2)
        .and_then(|s| s.try_into().ok())
        .map(u16::from_le_bytes)
        .ok_or(Error::Truncated)
}

fn u32_at(b: &[u8], at: usize) -> Result<u32, Error> {
    b.get(at..at + 4)
        .and_then(|s| s.try_into().ok())
        .map(u32::from_le_bytes)
        .ok_or(Error::Truncated)
}

fn u64_at(b: &[u8], at: usize) -> Result<u64, Error> {
    b.get(at..at + 8)
        .and_then(|s| s.try_into().ok())
        .map(u64::from_le_bytes)
        .ok_or(Error::Truncated)
}

impl<'a> Program<'a> {
    /// Validate `bytes` as a static executable for `machine` whose every segment lies in
    /// `[range.0, range.1)`, with pages of `page` bytes (a power of two).
    pub fn parse(
        bytes: &'a [u8],
        machine: u16,
        range: (u64, u64),
        page: u64,
    ) -> Result<Self, Error> {
        let ident = bytes.get(..EHDR_SIZE).ok_or(Error::NotElf64)?;
        if &ident[0..4] != b"\x7fELF" || ident[4] != 2 || ident[5] != 1 {
            return Err(Error::NotElf64);
        }
        if u16_at(bytes, 16)? != ET_EXEC {
            return Err(Error::NotExecutable);
        }
        let found = u16_at(bytes, 18)?;
        if found != machine {
            return Err(Error::WrongMachine(found));
        }
        let entry = u64_at(bytes, 24)?;
        let phoff = usize::try_from(u64_at(bytes, 32)?).map_err(|_| Error::Truncated)?;
        if usize::from(u16_at(bytes, 54)?) != PHDR_SIZE {
            return Err(Error::NotElf64);
        }
        let phnum = usize::from(u16_at(bytes, 56)?);
        let end = phnum
            .checked_mul(PHDR_SIZE)
            .and_then(|n| n.checked_add(phoff))
            .ok_or(Error::Truncated)?;
        if end > bytes.len() {
            return Err(Error::Truncated);
        }

        let program = Program {
            bytes,
            phoff,
            phnum,
            entry,
        };
        let mut pages = [(0u64, 0u64); MAX_SEGMENTS];
        let mut n = 0usize;
        let mut entry_ok = false;
        for seg in program.segments() {
            let seg = seg?;
            if seg.mem_size == 0 {
                continue;
            }
            let top = seg
                .vaddr
                .checked_add(seg.mem_size)
                .ok_or(Error::BadSegment)?;
            if seg.vaddr < range.0 || top > range.1 {
                return Err(Error::OutsideRange);
            }
            let (lo, hi) = seg.pages(page);
            if pages[..n].iter().any(|&(a, b)| lo < b && a < hi) {
                return Err(Error::Overlap);
            }
            let slot = pages.get_mut(n).ok_or(Error::TooManySegments)?;
            *slot = (lo, hi);
            n += 1;
            entry_ok |= seg.access.execute && seg.vaddr <= entry && entry < top;
        }
        if n == 0 {
            return Err(Error::NoSegments);
        }
        if !entry_ok {
            return Err(Error::EntryNotExecutable);
        }
        Ok(program)
    }

    /// The loadable segments, in program header order, each already checked by `parse`
    /// except for being in range, which `parse` checks on the non-empty ones.
    pub fn segments(&self) -> impl Iterator<Item = Result<Segment<'a>, Error>> + '_ {
        (0..self.phnum).filter_map(move |i| {
            let ph = self.phoff + i * PHDR_SIZE;
            match u32_at(self.bytes, ph) {
                Ok(PT_LOAD) => Some(self.segment_at(ph)),
                Ok(_) => None,
                Err(e) => Some(Err(e)),
            }
        })
    }

    fn segment_at(&self, ph: usize) -> Result<Segment<'a>, Error> {
        let flags = u32_at(self.bytes, ph + 4)?;
        let off = usize::try_from(u64_at(self.bytes, ph + 8)?).map_err(|_| Error::Truncated)?;
        let vaddr = u64_at(self.bytes, ph + 16)?;
        let filesz = usize::try_from(u64_at(self.bytes, ph + 32)?).map_err(|_| Error::Truncated)?;
        let mem_size = u64_at(self.bytes, ph + 40)?;
        let file_end = off.checked_add(filesz).ok_or(Error::Truncated)?;
        let file = self.bytes.get(off..file_end).ok_or(Error::Truncated)?;
        if file.len() as u64 > mem_size {
            return Err(Error::BadSegment);
        }
        let access = Access {
            read: flags & PF_R != 0,
            write: flags & PF_W != 0,
            execute: flags & PF_X != 0,
        };
        if access.write && access.execute {
            return Err(Error::WritableAndExecutable);
        }
        Ok(Segment {
            vaddr,
            mem_size,
            file,
            access,
        })
    }
}

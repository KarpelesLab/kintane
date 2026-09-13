//! The tag stream: reading it in the kernel, writing it in a loader.
//!
//! # Layout
//!
//! ```text
//! BootInfo header   16 bytes  magic, version, header_size, tags_size
//! tag               8 bytes   kind: u32, size: u32 (header + payload, padding excluded)
//!   payload         size - 8 bytes
//!   padding         to the next multiple of 8, zero
//! ...
//! End tag           kind 0, size 8
//! ```
//!
//! `tags_size` counts every tag, its padding, and the End tag. All integers are in the
//! machine's own byte order: a loader and the kernel it starts always share one.
//!
//! Tags start `header_size` bytes after the header's first byte, not
//! `size_of::<BootInfo>()`, so a newer loader's longer header is stepped over by an
//! older kernel. That is the compatibility rule the protocol exists for, and
//! [`parse`] follows it rather than assuming the layout it was written against.
//!
//! # Payloads
//!
//! | kind | payload |
//! |---|---|
//! | `MemoryMap` | `entry_size: u32`, `_reserved: u32`, then entries of `entry_size` bytes, each beginning with a [`MemoryRegion`] |
//! | `CommandLine` | UTF-8 bytes, not NUL-terminated; at most [`MAX_COMMAND_LINE`] bytes |
//! | `AcpiRsdp` | `address: u64`, physical |
//! | `KernelRange` | `start: u64`, `len: u64`, physical |
//! | `Firmware` | `kind: u32` ([`Firmware`]), `_reserved: u32` |
//!
//! `entry_size` is explicit so a later protocol version can grow a region entry
//! without breaking an older kernel, which reads the prefix it knows.
//!
//! Every read here is bounds-checked against the slice. The kernel builds that slice
//! from an address a loader handed it, and nothing in this module believes a length
//! until it has been compared against the bytes that are actually there.

use crate::{BootInfo, Error, Firmware, MAGIC, MemoryRegion, TagKind, VERSION};

/// Size of the `BootInfo` header this version writes.
pub const HEADER_SIZE: usize = core::mem::size_of::<BootInfo>();
/// Size of a tag's own header.
pub const TAG_HEADER_SIZE: usize = 8;
/// Size of a [`MemoryRegion`] as this version writes it.
pub const REGION_SIZE: usize = core::mem::size_of::<MemoryRegion>();

/// The longest command line a loader writes and a kernel accepts. A line claiming more is
/// malformed rather than truncated: a kernel that silently dropped the end of its
/// arguments would boot a configuration nobody asked for.
pub const MAX_COMMAND_LINE: usize = 1024;

/// Tags are padded to this alignment, so every tag header can be read as aligned data.
const TAG_ALIGN: usize = 8;

fn align_up(n: usize) -> Option<usize> {
    n.checked_add(TAG_ALIGN - 1).map(|v| v & !(TAG_ALIGN - 1))
}

fn read_u16(b: &[u8], at: usize) -> Option<u16> {
    b.get(at..at + 2)?.try_into().ok().map(u16::from_ne_bytes)
}

fn read_u32(b: &[u8], at: usize) -> Option<u32> {
    b.get(at..at + 4)?.try_into().ok().map(u32::from_ne_bytes)
}

fn read_u64(b: &[u8], at: usize) -> Option<u64> {
    b.get(at..at + 8)?.try_into().ok().map(u64::from_ne_bytes)
}

/// Read and validate the fixed header at the start of `bytes`.
///
/// Separate from [`parse`] because the kernel has only an address to begin with: it
/// reads the header to learn how long the whole structure claims to be, bounds that
/// claim, and only then makes a slice of that length.
pub fn header(bytes: &[u8]) -> Result<BootInfo, Error> {
    let magic = read_u64(bytes, 0).ok_or(Error::Truncated)?;
    let info = BootInfo {
        magic,
        version: read_u16(bytes, 8).ok_or(Error::Truncated)?,
        header_size: read_u16(bytes, 10).ok_or(Error::Truncated)?,
        tags_size: read_u32(bytes, 12).ok_or(Error::Truncated)?,
    };
    info.validate()?;
    Ok(info)
}

impl BootInfo {
    /// Bytes from the start of the header to the end of the End tag.
    pub fn total_size(&self) -> usize {
        usize::from(self.header_size).saturating_add(self.tags_size as usize)
    }
}

/// A validated boot information structure and its tags.
#[derive(Clone, Copy)]
pub struct Parsed<'a> {
    pub header: BootInfo,
    /// The tag stream, exactly `tags_size` bytes.
    tags: &'a [u8],
    /// Offset of `tags` from the start of the structure, for error reporting.
    base: usize,
}

/// Validate `bytes` as a boot information structure.
///
/// `bytes` may be longer than the structure; it must not be shorter.
pub fn parse(bytes: &[u8]) -> Result<Parsed<'_>, Error> {
    let header = header(bytes)?;
    let base = usize::from(header.header_size);
    let end = base
        .checked_add(header.tags_size as usize)
        .ok_or(Error::Truncated)?;
    let tags = bytes.get(base..end).ok_or(Error::Truncated)?;
    Ok(Parsed { header, tags, base })
}

/// One tag, its payload sliced to the size the tag declares.
#[derive(Clone, Copy, Debug)]
pub struct TagRef<'a> {
    pub kind: u32,
    pub payload: &'a [u8],
    /// Offset of the tag header from the start of the structure.
    pub offset: usize,
}

/// Walks the tag stream up to the End tag.
///
/// Ends after reporting the first malformed tag: once one size is wrong, every
/// following offset is a guess.
pub struct Tags<'a> {
    data: &'a [u8],
    base: usize,
    at: usize,
    done: bool,
}

impl<'a> Iterator for Tags<'a> {
    type Item = Result<TagRef<'a>, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        let offset = self.base + self.at;
        let malformed = |done: &mut bool| {
            *done = true;
            Some(Err(Error::Malformed { offset }))
        };
        let (Some(kind), Some(size)) =
            (read_u32(self.data, self.at), read_u32(self.data, self.at + 4))
        else {
            // Ran out of bytes without meeting End: the stream is not terminated.
            return malformed(&mut self.done);
        };
        let size = size as usize;
        if size < TAG_HEADER_SIZE {
            return malformed(&mut self.done);
        }
        let Some(payload) = self
            .at
            .checked_add(size)
            .and_then(|end| self.data.get(self.at + TAG_HEADER_SIZE..end))
        else {
            return malformed(&mut self.done);
        };
        if kind == TagKind::End as u32 {
            self.done = true;
            return None;
        }
        // A padded size past the end is fine only if nothing follows; the missing End
        // tag is then reported on the next call.
        self.at = align_up(self.at + size).unwrap_or(usize::MAX);
        Some(Ok(TagRef {
            kind,
            payload,
            offset,
        }))
    }
}

impl<'a> Parsed<'a> {
    pub fn tags(&self) -> Tags<'a> {
        Tags {
            data: self.tags,
            base: self.base,
            at: 0,
            done: false,
        }
    }

    /// The first tag of `kind`, if the loader supplied one.
    pub fn find(&self, kind: TagKind) -> Result<Option<TagRef<'a>>, Error> {
        for tag in self.tags() {
            let tag = tag?;
            if tag.kind == kind as u32 {
                return Ok(Some(tag));
            }
        }
        Ok(None)
    }

    /// The memory map, if present.
    pub fn memory_map(&self) -> Result<Option<Regions<'a>>, Error> {
        let Some(tag) = self.find(TagKind::MemoryMap)? else {
            return Ok(None);
        };
        let bad = Error::Malformed { offset: tag.offset };
        let entry_size = read_u32(tag.payload, 0).ok_or(bad)? as usize;
        if entry_size < REGION_SIZE {
            return Err(bad);
        }
        let entries = tag.payload.get(8..).ok_or(bad)?;
        if entries.len() % entry_size != 0 {
            return Err(bad);
        }
        Ok(Some(Regions {
            entries,
            entry_size,
        }))
    }

    /// The physical address of the ACPI RSDP, if the firmware has one.
    pub fn acpi_rsdp(&self) -> Result<Option<u64>, Error> {
        self.u64_tag(TagKind::AcpiRsdp)
    }

    /// The kernel command line, if the loader passed one.
    ///
    /// Any bytes are returned as they are, UTF-8 or not: the kernel's argument parser
    /// decides what it will accept, and a loader that wrote garbage should be reported as
    /// such by the code that knows what an argument looks like. Only the length is
    /// judged here.
    pub fn command_line(&self) -> Result<Option<&'a [u8]>, Error> {
        let Some(tag) = self.find(TagKind::CommandLine)? else {
            return Ok(None);
        };
        if tag.payload.len() > MAX_COMMAND_LINE {
            return Err(Error::Malformed { offset: tag.offset });
        }
        Ok(Some(tag.payload))
    }

    /// Which kind of firmware or loader produced this structure.
    pub fn firmware(&self) -> Result<Option<u32>, Error> {
        Ok(self
            .find(TagKind::Firmware)?
            .and_then(|t| read_u32(t.payload, 0)))
    }

    /// The physical range the loader placed the kernel image in, `(start, len)`.
    pub fn kernel_range(&self) -> Result<Option<(u64, u64)>, Error> {
        let Some(tag) = self.find(TagKind::KernelRange)? else {
            return Ok(None);
        };
        let bad = Error::Malformed { offset: tag.offset };
        Ok(Some((
            read_u64(tag.payload, 0).ok_or(bad)?,
            read_u64(tag.payload, 8).ok_or(bad)?,
        )))
    }

    fn u64_tag(&self, kind: TagKind) -> Result<Option<u64>, Error> {
        let Some(tag) = self.find(kind)? else {
            return Ok(None);
        };
        read_u64(tag.payload, 0)
            .map(Some)
            .ok_or(Error::Malformed { offset: tag.offset })
    }
}

/// The entries of a memory map tag.
#[derive(Clone, Copy)]
pub struct Regions<'a> {
    entries: &'a [u8],
    entry_size: usize,
}

impl Regions<'_> {
    pub fn len(&self) -> usize {
        self.entries.len() / self.entry_size
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Iterator for Regions<'_> {
    type Item = MemoryRegion;

    fn next(&mut self) -> Option<MemoryRegion> {
        let (entry, rest) = self.entries.split_at_checked(self.entry_size)?;
        self.entries = rest;
        Some(MemoryRegion {
            start: read_u64(entry, 0)?,
            len: read_u64(entry, 8)?,
            kind: read_u32(entry, 16)?,
            _reserved: read_u32(entry, 20)?,
        })
    }
}

/// Writes a boot information structure into a buffer the loader owns.
///
/// Tags are appended in call order and the header is written by [`Builder::finish`].
/// Nothing here allocates: a loader running after `ExitBootServices` has no allocator,
/// and that is exactly when the memory map tag must be written.
pub struct Builder<'a> {
    buf: &'a mut [u8],
    at: usize,
}

impl<'a> Builder<'a> {
    /// Start a structure at the beginning of `buf`.
    pub fn new(buf: &'a mut [u8]) -> Result<Self, Error> {
        if buf.len() < HEADER_SIZE {
            return Err(Error::NoRoom);
        }
        buf[..HEADER_SIZE].fill(0);
        Ok(Builder {
            buf,
            at: HEADER_SIZE,
        })
    }

    /// Reserve a tag with `payload_len` bytes of payload and return the payload for
    /// the caller to fill. The padding is zeroed here.
    fn reserve(&mut self, kind: TagKind, payload_len: usize) -> Result<&mut [u8], Error> {
        let size = TAG_HEADER_SIZE
            .checked_add(payload_len)
            .ok_or(Error::NoRoom)?;
        let size32 = u32::try_from(size).map_err(|_| Error::NoRoom)?;
        let padded = align_up(size).ok_or(Error::NoRoom)?;
        let end = self.at.checked_add(padded).ok_or(Error::NoRoom)?;
        // Leave room for the End tag, so `finish` cannot fail for lack of space.
        if end
            .checked_add(TAG_HEADER_SIZE)
            .is_none_or(|e| e > self.buf.len())
        {
            return Err(Error::NoRoom);
        }
        let tag = &mut self.buf[self.at..end];
        tag.fill(0);
        tag[0..4].copy_from_slice(&(kind as u32).to_ne_bytes());
        tag[4..8].copy_from_slice(&size32.to_ne_bytes());
        let start = self.at + TAG_HEADER_SIZE;
        self.at = end;
        Ok(&mut self.buf[start..start + payload_len])
    }

    /// Append a tag whose payload is `payload`.
    pub fn tag(&mut self, kind: TagKind, payload: &[u8]) -> Result<(), Error> {
        self.reserve(kind, payload.len())?.copy_from_slice(payload);
        Ok(())
    }

    pub fn acpi_rsdp(&mut self, address: u64) -> Result<(), Error> {
        self.tag(TagKind::AcpiRsdp, &address.to_ne_bytes())
    }

    /// Append the kernel command line. Longer than [`MAX_COMMAND_LINE`] is refused, for
    /// the reason the reader refuses it.
    pub fn command_line(&mut self, line: &[u8]) -> Result<(), Error> {
        if line.len() > MAX_COMMAND_LINE {
            return Err(Error::NoRoom);
        }
        self.tag(TagKind::CommandLine, line)
    }

    pub fn firmware(&mut self, firmware: Firmware) -> Result<(), Error> {
        let mut p = [0u8; 8];
        p[..4].copy_from_slice(&(firmware as u32).to_ne_bytes());
        self.tag(TagKind::Firmware, &p)
    }

    pub fn kernel_range(&mut self, start: u64, len: u64) -> Result<(), Error> {
        let mut p = [0u8; 16];
        p[..8].copy_from_slice(&start.to_ne_bytes());
        p[8..].copy_from_slice(&len.to_ne_bytes());
        self.tag(TagKind::KernelRange, &p)
    }

    /// Append a memory map tag with room for `capacity` regions, and return a writer
    /// for it.
    ///
    /// The tag is sized for the capacity up front and shrunk to what was written when
    /// the writer is closed, because a loader translating a firmware map does not know
    /// how many regions will survive coalescing until it has done it — and by then it
    /// can no longer ask the firmware for memory.
    pub fn memory_map(&mut self, capacity: usize) -> Result<MapWriter<'_, 'a>, Error> {
        let bytes = capacity
            .checked_mul(REGION_SIZE)
            .and_then(|b| b.checked_add(8))
            .ok_or(Error::NoRoom)?;
        let tag_at = self.at;
        let payload = self.reserve(TagKind::MemoryMap, bytes)?;
        payload[..4].copy_from_slice(&(REGION_SIZE as u32).to_ne_bytes());
        Ok(MapWriter {
            builder: self,
            tag_at,
            capacity,
            len: 0,
        })
    }

    /// Write the End tag and the header, returning the structure's total size.
    pub fn finish(mut self) -> usize {
        let end = self.at + TAG_HEADER_SIZE;
        self.buf[self.at..self.at + 4].copy_from_slice(&(TagKind::End as u32).to_ne_bytes());
        self.buf[self.at + 4..end].copy_from_slice(&(TAG_HEADER_SIZE as u32).to_ne_bytes());
        self.at = end;
        let tags_size = (end - HEADER_SIZE) as u32;
        let h = &mut self.buf[..HEADER_SIZE];
        h[0..8].copy_from_slice(&MAGIC.to_ne_bytes());
        h[8..10].copy_from_slice(&VERSION.to_ne_bytes());
        h[10..12].copy_from_slice(&(HEADER_SIZE as u16).to_ne_bytes());
        h[12..16].copy_from_slice(&tags_size.to_ne_bytes());
        end
    }
}

/// Fills a memory map tag, keeping it sorted by address and merging neighbours.
///
/// Firmware maps are long and fragmented: OVMF reports dozens of adjacent descriptors
/// that differ only in which firmware driver owned them, and every one of them
/// translates to "usable". Handing the kernel that list as-is would spend most of a
/// fixed-size region buffer on boundaries that mean nothing once the firmware is gone.
/// So [`MapWriter::push`] merges a region into an equal-kind neighbour it touches.
///
/// It merges only regions that are exactly adjacent, never ones that overlap. An
/// overlapping map is a firmware bug, and the kernel is better placed to report it than
/// a loader is to guess which claim was true.
pub struct MapWriter<'b, 'a> {
    builder: &'b mut Builder<'a>,
    /// Offset of the tag header in the builder's buffer.
    tag_at: usize,
    capacity: usize,
    len: usize,
}

impl MapWriter<'_, '_> {
    fn entry_at(&self, i: usize) -> usize {
        self.tag_at + TAG_HEADER_SIZE + 8 + i * REGION_SIZE
    }

    fn get(&self, i: usize) -> MemoryRegion {
        let at = self.entry_at(i);
        let b = &self.builder.buf[at..at + REGION_SIZE];
        MemoryRegion {
            start: read_u64(b, 0).unwrap_or(0),
            len: read_u64(b, 8).unwrap_or(0),
            kind: read_u32(b, 16).unwrap_or(0),
            _reserved: 0,
        }
    }

    fn set(&mut self, i: usize, r: MemoryRegion) {
        let at = self.entry_at(i);
        let b = &mut self.builder.buf[at..at + REGION_SIZE];
        b[0..8].copy_from_slice(&r.start.to_ne_bytes());
        b[8..16].copy_from_slice(&r.len.to_ne_bytes());
        b[16..20].copy_from_slice(&r.kind.to_ne_bytes());
        b[20..24].copy_from_slice(&0u32.to_ne_bytes());
    }

    /// Regions written so far.
    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Add a region, in address order, merged with any equal-kind region it touches.
    /// Empty regions are dropped.
    pub fn push(&mut self, r: MemoryRegion) -> Result<(), Error> {
        if r.len == 0 {
            return Ok(());
        }
        let r_end = r
            .start
            .checked_add(r.len)
            .ok_or(Error::Malformed { offset: 0 })?;
        // Insertion point: the first entry starting after `r`.
        let mut i = 0;
        while i < self.len && self.get(i).start <= r.start {
            i += 1;
        }
        let touches_prev = i > 0 && {
            let p = self.get(i - 1);
            p.kind == r.kind && p.start + p.len == r.start
        };
        let touches_next = i < self.len && {
            let n = self.get(i);
            n.kind == r.kind && r_end == n.start
        };
        match (touches_prev, touches_next) {
            (true, true) => {
                let (p, n) = (self.get(i - 1), self.get(i));
                self.set(
                    i - 1,
                    MemoryRegion {
                        len: p.len + r.len + n.len,
                        ..p
                    },
                );
                for j in i..self.len - 1 {
                    let next = self.get(j + 1);
                    self.set(j, next);
                }
                self.len -= 1;
            }
            (true, false) => {
                let p = self.get(i - 1);
                self.set(
                    i - 1,
                    MemoryRegion {
                        len: p.len + r.len,
                        ..p
                    },
                );
            }
            (false, true) => {
                let n = self.get(i);
                self.set(
                    i,
                    MemoryRegion {
                        start: r.start,
                        len: r.len + n.len,
                        ..n
                    },
                );
            }
            (false, false) => {
                if self.len == self.capacity {
                    return Err(Error::NoRoom);
                }
                let mut j = self.len;
                while j > i {
                    let prev = self.get(j - 1);
                    self.set(j, prev);
                    j -= 1;
                }
                self.set(i, MemoryRegion { _reserved: 0, ..r });
                self.len += 1;
            }
        }
        Ok(())
    }

    /// Shrink the tag to the regions written, releasing the unused capacity.
    pub fn close(self) {
        let payload = 8 + self.len * REGION_SIZE;
        let size = TAG_HEADER_SIZE + payload;
        let at = self.tag_at;
        let buf = &mut self.builder.buf;
        buf[at + 4..at + 8].copy_from_slice(&(size as u32).to_ne_bytes());
        let end = align_up(at + size).unwrap_or(self.builder.at);
        buf[at + size..end].fill(0);
        self.builder.at = end;
    }
}

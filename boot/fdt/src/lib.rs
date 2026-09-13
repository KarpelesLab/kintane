//! Flattened device tree (DTB) parsing.
//!
//! A device tree is how most non-PC machines describe themselves: where RAM is, what
//! firmware has reserved, which devices sit at which addresses. On aarch64 it is the
//! only memory map there is. The format is the Devicetree Specification, v0.4,
//! chapter 5 ("Flattened Devicetree (DTB) Format"); section numbers below refer to
//! that document.
//!
//! # Untrusted input
//!
//! Like `boot/multiboot`, this treats what it is handed as **untrusted input**. A
//! device tree is a large structure written by firmware — or by a bootloader editing
//! firmware's copy in place — and a malformed one must be a diagnosable error naming
//! a byte offset, never a fault. Concretely:
//!
//! - The parser works on a `&[u8]` and contains no `unsafe` at all. Turning a pointer into that
//!   slice is the caller's job and the caller's contract. A bounds mistake in here is therefore an
//!   error value or a wrong answer, never a wild read.
//! - Every header offset and size is range-checked against `totalsize` with checked arithmetic
//!   before anything is read through it, so a `u32` that wraps is caught.
//! - Every walk is bounded. The structure walk advances at least four bytes per token and never
//!   past the end of the structure block; the reservation walk advances sixteen and never past
//!   `totalsize`; nesting is capped at [`MAX_DEPTH`].
//! - Every property name is resolved through the strings block with its offset checked and its
//!   terminator found inside the block.
//! - [`Fdt::new`] validates the *whole* structure once, so a tree that is accepted is well-formed
//!   throughout, not merely well-formed in the part the first caller read.
//!
//! # Cell counts
//!
//! A `reg` property is a list of `(address, size)` pairs whose widths, in 32-bit
//! cells, are set by the *parent* node's `#address-cells` and `#size-cells` (§2.3.5).
//! QEMU's `virt` machine uses two and two, and a parser that assumes that is right on
//! QEMU and wrong on a Raspberry Pi 3, whose root uses one and one. Nothing here assumes
//! it: cells are tracked per nesting level, absent properties take the specification's
//! defaults of two and one, and a count too large for a `u64` is an error.
//!
//! # What becomes a memory region
//!
//! - `reg` of each child of the root with `device_type = "memory"` (§3.4) is
//!   [`MemoryKind::Usable`], unless its `status` says it is not available.
//! - `reg` of each child of `/reserved-memory` (§3.5) is [`MemoryKind::Reserved`] — whatever its
//!   `status` says, because a reservation wrongly honoured costs a few frames and one wrongly
//!   ignored hands firmware's memory to the allocator.
//! - Each entry of the memory reservation block (§5.3) is [`MemoryKind::Reserved`].
//!
//! Every ambiguity is resolved in the direction that keeps memory *out* of the pool: a
//! node without `device_type = "memory"` is not RAM whatever it is called, and a
//! disabled memory node is not RAM either.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

use boot_protocol::{MemoryKind, MemoryRegion};

/// The first four bytes of every device tree blob, big-endian (§5.2).
pub const MAGIC: u32 = 0xd00d_feed;

/// Size of the version-17 header, which is every field this parser reads.
pub const HEADER_LEN: usize = 40;

/// The structure version this parser implements (§5.2).
///
/// Trees older than this lack `size_dt_struct`, without which the structure block has
/// no bound other than `totalsize`; they are refused rather than walked on a guess.
/// Newer trees are accepted when they declare themselves backwards compatible with it.
pub const VERSION: u32 = 17;

/// The deepest nesting accepted, counting the root as depth 1.
///
/// Real trees are shallow: QEMU's `virt` reaches 4, and large SoC trees rarely pass 8.
/// The cap exists so that nesting can be tracked in a fixed array rather than
/// recursion or a heap, and a tree that exceeds it is far more likely to be corrupt
/// than to be describing hardware.
pub const MAX_DEPTH: usize = 32;

/// The widest `#address-cells` or `#size-cells` this parser will interpret.
///
/// Values wider than 64 bits are still accepted when their high cells are zero, which
/// is how a three-cell PCI-style address holding a CPU address looks; four covers
/// that with room to spare. A count above this is reported, not truncated.
pub const MAX_CELLS: u32 = 4;

/// §2.3.5: "If missing, a client program should assume a default value of 2 for
/// #address-cells, and a value of 1 for #size-cells."
const DEFAULT_ADDRESS_CELLS: u32 = 2;
const DEFAULT_SIZE_CELLS: u32 = 1;

// Structure block tokens (§5.4.1).
const FDT_BEGIN_NODE: u32 = 0x1;
const FDT_END_NODE: u32 = 0x2;
const FDT_PROP: u32 = 0x3;
const FDT_NOP: u32 = 0x4;
const FDT_END: u32 = 0x9;

// Header field offsets (§5.2).
const FIELD_MAGIC: usize = 0;
const FIELD_TOTALSIZE: usize = 4;
const FIELD_OFF_STRUCT: usize = 8;
const FIELD_OFF_STRINGS: usize = 12;
const FIELD_OFF_RSVMAP: usize = 16;
const FIELD_VERSION: usize = 20;
const FIELD_LAST_COMP: usize = 24;
const FIELD_BOOT_CPUID: usize = 28;
const FIELD_SIZE_STRINGS: usize = 32;
const FIELD_SIZE_STRUCT: usize = 36;

/// One memory reservation block entry: two `u64`s.
const RESERVATION_LEN: usize = 16;
/// The same, as the header's integer type.
const RESERVATION_LEN_U32: u32 = 16;

/// Which of the three blocks a header field describes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Block {
    /// The memory reservation block (§5.3).
    MemoryReservation,
    /// The structure block (§5.4).
    Structure,
    /// The strings block (§5.5).
    Strings,
}

/// Why a tree was rejected.
///
/// Every variant about a place in the blob carries the byte offset, from the start of
/// the blob, of the header field or token at fault — enough to find it in a hex dump.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Error {
    /// The buffer ends before the header does, or before `totalsize` bytes.
    Truncated {
        /// Bytes the header says are needed.
        needed: usize,
        /// Bytes actually supplied.
        available: usize,
    },
    /// The first four bytes are not [`MAGIC`]: this is not a device tree.
    BadMagic(u32),
    /// A structure version this parser cannot read.
    UnsupportedVersion {
        /// The tree's `version`.
        version: u32,
        /// The tree's `last_comp_version`.
        last_compatible: u32,
    },
    /// `totalsize` is smaller than the header it is part of.
    BadTotalSize(u32),
    /// A block's offset or size in the header puts it inside the header or past
    /// `totalsize`.
    BlockOutOfBounds {
        /// Which block.
        block: Block,
        /// The offset the header claimed.
        offset: u32,
        /// The size the header claimed, or the minimum one if it has no size field.
        size: u32,
    },
    /// The reservation block runs off the end of the blob without its terminating
    /// all-zero entry.
    UnterminatedReservations {
        /// Offset of the entry that did not fit.
        offset: usize,
    },
    /// A token, or the payload it declares, runs past the end of the structure block.
    TruncatedStructure {
        /// Offset of the token.
        offset: usize,
    },
    /// A token value the format does not define.
    UnknownToken {
        /// Offset of the token.
        offset: usize,
        /// The value found.
        token: u32,
    },
    /// A node name with no terminating NUL inside the structure block.
    UnterminatedNodeName {
        /// Offset of the `FDT_BEGIN_NODE` token.
        offset: usize,
    },
    /// A property's name offset points outside the strings block.
    NameOffsetOutOfRange {
        /// Offset of the `FDT_PROP` token.
        offset: usize,
        /// The `nameoff` it carried.
        name_offset: u32,
    },
    /// A property's name starts inside the strings block but is not terminated there.
    UnterminatedPropertyName {
        /// Offset of the `FDT_PROP` token.
        offset: usize,
        /// The `nameoff` it carried.
        name_offset: u32,
    },
    /// Nesting deeper than [`MAX_DEPTH`].
    NestingTooDeep {
        /// Offset of the `FDT_BEGIN_NODE` that went too deep.
        offset: usize,
    },
    /// An `FDT_END_NODE` with no node open.
    UnbalancedEndNode {
        /// Offset of the token.
        offset: usize,
    },
    /// A property before the root node opened or after it closed.
    PropertyOutsideNode {
        /// Offset of the `FDT_PROP` token.
        offset: usize,
    },
    /// A property after a subnode of the same node. §5.4.2 requires properties to
    /// precede subnodes, and cell counts are only well-defined if they do: a child's
    /// `reg` is read using properties of its parent that must already have been seen.
    PropertyAfterSubnode {
        /// Offset of the `FDT_PROP` token.
        offset: usize,
    },
    /// A second node at the top level. A tree has exactly one root.
    MultipleRoots {
        /// Offset of the second root's `FDT_BEGIN_NODE`.
        offset: usize,
    },
    /// `FDT_END` before any node.
    NoRootNode {
        /// Offset of the `FDT_END` token.
        offset: usize,
    },
    /// `FDT_END` while nodes are still open.
    EndInsideNode {
        /// Offset of the `FDT_END` token.
        offset: usize,
        /// How many nodes were open.
        depth: usize,
    },
    /// The structure block ends without an `FDT_END` token.
    MissingEnd {
        /// Offset of the end of the structure block.
        offset: usize,
    },
    /// An `#address-cells` or `#size-cells` property that is not exactly one cell,
    /// found while interpreting a `reg` that depends on it.
    BadCellsProperty {
        /// Offset of the malformed cell-count property.
        offset: usize,
    },
    /// Cell counts that cannot describe a region: wider than [`MAX_CELLS`], or zero
    /// cells in total.
    UnsupportedCells {
        /// Offset of the `reg` property being interpreted.
        offset: usize,
        /// The parent's `#address-cells`.
        address_cells: u32,
        /// The parent's `#size-cells`.
        size_cells: u32,
    },
    /// A `reg` whose length is not a whole number of `(address, size)` entries.
    RegLength {
        /// Offset of the `reg` property.
        offset: usize,
        /// Its length in bytes.
        len: usize,
        /// The entry size in bytes the cell counts imply.
        entry: usize,
    },
    /// A multi-cell value whose high cells are not zero, so it does not fit in 64 bits.
    ValueTooWide {
        /// Offset of the property.
        offset: usize,
    },
    /// A region whose end is past the top of the 64-bit address space.
    RegionOverflow {
        /// Offset of the property or reservation entry.
        offset: usize,
    },
    /// More regions than the output buffer holds.
    TooManyRegions {
        /// The buffer's length.
        capacity: usize,
    },
    /// The tree describes no usable memory at all.
    NoMemory,
}

impl Error {
    /// The byte offset in the blob this error is about.
    ///
    /// Zero for the two errors that are not about a place — [`Error::TooManyRegions`]
    /// and [`Error::NoMemory`] — and for [`Error::BadMagic`], which is about offset
    /// zero.
    pub fn offset(&self) -> usize {
        match *self {
            Error::Truncated { available, .. } => available,
            Error::BadMagic(_) => FIELD_MAGIC,
            Error::UnsupportedVersion { .. } => FIELD_VERSION,
            Error::BadTotalSize(_) => FIELD_TOTALSIZE,
            Error::BlockOutOfBounds { block, .. } => match block {
                Block::MemoryReservation => FIELD_OFF_RSVMAP,
                Block::Structure => FIELD_OFF_STRUCT,
                Block::Strings => FIELD_OFF_STRINGS,
            },
            Error::UnterminatedReservations { offset }
            | Error::TruncatedStructure { offset }
            | Error::UnknownToken { offset, .. }
            | Error::UnterminatedNodeName { offset }
            | Error::NameOffsetOutOfRange { offset, .. }
            | Error::UnterminatedPropertyName { offset, .. }
            | Error::NestingTooDeep { offset }
            | Error::UnbalancedEndNode { offset }
            | Error::PropertyOutsideNode { offset }
            | Error::PropertyAfterSubnode { offset }
            | Error::MultipleRoots { offset }
            | Error::NoRootNode { offset }
            | Error::EndInsideNode { offset, .. }
            | Error::MissingEnd { offset }
            | Error::BadCellsProperty { offset }
            | Error::UnsupportedCells { offset, .. }
            | Error::RegLength { offset, .. }
            | Error::ValueTooWide { offset }
            | Error::RegionOverflow { offset } => offset,
            Error::TooManyRegions { .. } | Error::NoMemory => 0,
        }
    }
}

/// The version-17 header, decoded but not yet checked against a buffer (§5.2).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Header {
    /// `totalsize`: bytes in the whole blob, header and padding included.
    pub total_size: u32,
    /// `off_dt_struct`.
    pub struct_offset: u32,
    /// `off_dt_strings`.
    pub strings_offset: u32,
    /// `off_mem_rsvmap`.
    pub reservations_offset: u32,
    /// `version`.
    pub version: u32,
    /// `last_comp_version`.
    pub last_compatible_version: u32,
    /// `boot_cpuid_phys`: the physical ID of the CPU that booted.
    pub boot_cpuid_phys: u32,
    /// `size_dt_strings`.
    pub strings_size: u32,
    /// `size_dt_struct`.
    pub struct_size: u32,
}

impl Header {
    /// Decode and sanity-check a header from the first [`HEADER_LEN`] bytes of `bytes`.
    ///
    /// This is split out from [`Fdt::new`] for a caller holding a pointer rather than a
    /// slice: it reads the header, learns `total_size` from it, and only then knows how
    /// long a slice to build. Nothing here is checked against a buffer beyond the
    /// header itself; [`Fdt::new`] does that.
    ///
    /// # Errors
    /// [`Error::BadMagic`], [`Error::Truncated`] if `bytes` is shorter than the
    /// header, [`Error::UnsupportedVersion`], or [`Error::BadTotalSize`].
    pub fn parse(bytes: &[u8]) -> Result<Header, Error> {
        // Magic first, when there are four bytes to check: "this is not a device
        // tree" is the more useful answer for a short buffer of something else.
        if let Some(magic) = be32(bytes, FIELD_MAGIC) {
            if magic != MAGIC {
                return Err(Error::BadMagic(magic));
            }
        }
        let truncated = Error::Truncated {
            needed: HEADER_LEN,
            available: bytes.len(),
        };
        if bytes.len() < HEADER_LEN {
            return Err(truncated);
        }
        let field = |at| be32(bytes, at).ok_or(truncated);

        let header = Header {
            total_size: field(FIELD_TOTALSIZE)?,
            struct_offset: field(FIELD_OFF_STRUCT)?,
            strings_offset: field(FIELD_OFF_STRINGS)?,
            reservations_offset: field(FIELD_OFF_RSVMAP)?,
            version: field(FIELD_VERSION)?,
            last_compatible_version: field(FIELD_LAST_COMP)?,
            boot_cpuid_phys: field(FIELD_BOOT_CPUID)?,
            strings_size: field(FIELD_SIZE_STRINGS)?,
            struct_size: field(FIELD_SIZE_STRUCT)?,
        };

        if header.version < VERSION || header.last_compatible_version > VERSION {
            return Err(Error::UnsupportedVersion {
                version: header.version,
                last_compatible: header.last_compatible_version,
            });
        }
        match to_usize(header.total_size) {
            Some(total) if total >= HEADER_LEN => Ok(header),
            _ => Err(Error::BadTotalSize(header.total_size)),
        }
    }
}

/// A validated device tree blob.
///
/// Holding one is proof that the header is consistent, every block lies inside
/// `totalsize`, the reservation block is terminated, and the structure block is
/// well-formed from the root's `FDT_BEGIN_NODE` to `FDT_END`.
#[derive(Clone, Copy, Debug)]
pub struct Fdt<'a> {
    /// Exactly `totalsize` bytes.
    blob: &'a [u8],
    header: Header,
    /// `[start, end)` of the structure block, in blob offsets.
    structure: (usize, usize),
    /// `[start, end)` of the strings block, in blob offsets.
    strings: (usize, usize),
    /// Start of the memory reservation block.
    reservations: usize,
}

impl<'a> Fdt<'a> {
    /// Validate a device tree blob.
    ///
    /// `bytes` may be longer than the tree; only `totalsize` bytes are used.
    ///
    /// # Errors
    /// Any of the header errors from [`Header::parse`], [`Error::Truncated`] if `bytes`
    /// is shorter than `totalsize`, [`Error::BlockOutOfBounds`], and every structural
    /// error the reservation and structure walks can report.
    pub fn new(bytes: &'a [u8]) -> Result<Fdt<'a>, Error> {
        let header = Header::parse(bytes)?;
        let total = to_usize(header.total_size).ok_or(Error::BadTotalSize(header.total_size))?;
        let blob = bytes.get(..total).ok_or(Error::Truncated {
            needed: total,
            available: bytes.len(),
        })?;

        let structure = block(total, header.struct_offset, header.struct_size, Block::Structure)?;
        let strings = block(total, header.strings_offset, header.strings_size, Block::Strings)?;
        // The reservation block has no size field. The least it can be is its
        // terminator; the walk below checks every entry beyond that.
        let (reservations, _) = block(
            total,
            header.reservations_offset,
            RESERVATION_LEN_U32,
            Block::MemoryReservation,
        )?;

        let fdt = Fdt {
            blob,
            header,
            structure,
            strings,
            reservations,
        };

        // Walk both variable-length blocks to the end now, so that every later use of
        // an accepted tree walks a structure already known to be sound.
        for entry in fdt.reservations() {
            entry?;
        }
        for token in fdt.tokens() {
            token?;
        }
        Ok(fdt)
    }

    /// The decoded header.
    pub fn header(&self) -> &Header {
        &self.header
    }

    /// The blob, exactly `totalsize` bytes long.
    pub fn as_bytes(&self) -> &'a [u8] {
        self.blob
    }

    /// The memory reservation block's entries, terminator excluded (§5.3).
    pub fn reservations(&self) -> Reservations<'a> {
        Reservations {
            blob: self.blob,
            pos: self.reservations,
            done: false,
        }
    }

    /// The structure block as a stream of tokens, `FDT_NOP` skipped (§5.4).
    pub fn tokens(&self) -> Tokens<'a> {
        Tokens {
            blob: self.blob,
            pos: self.structure.0,
            end: self.structure.1,
            strings: self.blob.get(self.strings.0..self.strings.1).unwrap_or(&[]),
            depth: 0,
            has_child: 0,
            root_seen: false,
            done: false,
        }
    }

    /// Write the memory map this tree describes into `out`, returning how many regions
    /// were written.
    ///
    /// Reservation block entries come first, then `/memory` and `/reserved-memory`
    /// regions in tree order. Zero-length regions describe nothing and are omitted.
    /// Regions may overlap — a reservation inside RAM always does — and are not
    /// merged: resolving overlap is the frame allocator's job, and it resolves it
    /// against itself.
    ///
    /// # Errors
    /// [`Error::TooManyRegions`] if `out` is too short, [`Error::NoMemory`] if the tree
    /// describes no usable memory, or an error about the `reg` or cell-count property
    /// that could not be interpreted.
    pub fn memory_map(&self, out: &mut [MemoryRegion]) -> Result<usize, Error> {
        let mut sink = Sink {
            out,
            n: 0,
            usable: 0,
        };

        for entry in self.reservations() {
            let r = entry?;
            sink.push(r.address, r.size, MemoryKind::Reserved)?;
        }

        // Cell counts declared by the open node at each depth: `cells[d - 1]` for the
        // node at depth `d`. A node's `reg` is read with its parent's entry.
        let mut cells = [Cells::DEFAULT; MAX_DEPTH];
        // The open child of the root, and the open grandchild. Only those two levels
        // can hold what this function looks for.
        let mut top = Node::EMPTY;
        let mut child = Node::EMPTY;

        for token in self.tokens() {
            match token? {
                Token::BeginNode { name, depth, .. } => {
                    if let Some(c) = depth.checked_sub(1).and_then(|i| cells.get_mut(i)) {
                        *c = Cells::DEFAULT;
                    }
                    match depth {
                        2 => {
                            top = Node {
                                reserved_container: name == b"reserved-memory",
                                ..Node::EMPTY
                            }
                        }
                        3 => child = Node::EMPTY,
                        _ => {}
                    }
                }
                Token::Property {
                    name,
                    value,
                    depth,
                    offset,
                } => {
                    if let Some(c) = depth.checked_sub(1).and_then(|i| cells.get_mut(i)) {
                        c.record(name, value, offset);
                    }
                    let node = match depth {
                        2 => Some(&mut top),
                        3 if top.reserved_container => Some(&mut child),
                        _ => None,
                    };
                    if let Some(node) = node {
                        node.record(name, value, offset);
                    }
                }
                Token::EndNode { depth, .. } => match depth {
                    // A child of the root: RAM if it says it is, and says it is on.
                    2 if top.memory && top.available => {
                        if let (Some((reg, offset)), Some(parent)) = (top.reg, cells.first()) {
                            emit(reg, offset, *parent, MemoryKind::Usable, &mut sink)?;
                        }
                    }
                    // A child of /reserved-memory, read with /reserved-memory's cells.
                    3 if top.reserved_container => {
                        if let (Some((reg, offset)), Some(parent)) = (child.reg, cells.get(1)) {
                            emit(reg, offset, *parent, MemoryKind::Reserved, &mut sink)?;
                        }
                    }
                    _ => {}
                },
            }
        }

        if sink.usable == 0 {
            return Err(Error::NoMemory);
        }
        Ok(sink.n)
    }
}

/// One memory reservation block entry.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Reservation {
    /// First reserved physical address.
    pub address: u64,
    /// Bytes reserved.
    pub size: u64,
}

/// Iterator over the memory reservation block.
///
/// Bounded by construction: every entry is read through a checked slice of the blob,
/// which is exactly `totalsize` long, and the position advances sixteen bytes per
/// entry. An entry that does not fit ends the walk with an error, after which the
/// iterator yields nothing.
pub struct Reservations<'a> {
    blob: &'a [u8],
    pos: usize,
    done: bool,
}

impl Iterator for Reservations<'_> {
    type Item = Result<Reservation, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        let offset = self.pos;
        let entry = self
            .pos
            .checked_add(8)
            .and_then(|size_at| Some((be64(self.blob, offset)?, be64(self.blob, size_at)?)));
        let Some((address, size)) = entry else {
            self.done = true;
            return Some(Err(Error::UnterminatedReservations { offset }));
        };
        if address == 0 && size == 0 {
            self.done = true;
            return None;
        }
        match self.pos.checked_add(RESERVATION_LEN) {
            Some(next) => self.pos = next,
            None => self.done = true,
        }
        if address.checked_add(size).is_none() {
            self.done = true;
            return Some(Err(Error::RegionOverflow { offset }));
        }
        Some(Ok(Reservation { address, size }))
    }
}

/// One structure block token.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Token<'a> {
    /// A node opened. The root is at depth 1 and its name is empty.
    BeginNode {
        /// The node name, unit address included, without its NUL.
        name: &'a [u8],
        /// Depth of the node just opened.
        depth: usize,
        /// Offset of the token.
        offset: usize,
    },
    /// A node closed.
    EndNode {
        /// Depth of the node just closed.
        depth: usize,
        /// Offset of the token.
        offset: usize,
    },
    /// A property of the node open at `depth`.
    Property {
        /// The name, resolved through the strings block, without its NUL.
        name: &'a [u8],
        /// The raw value.
        value: &'a [u8],
        /// Depth of the node the property belongs to.
        depth: usize,
        /// Offset of the token.
        offset: usize,
    },
}

/// Iterator over the structure block.
///
/// Bounded by construction: every token either ends the walk or advances the position
/// by at least four bytes, and no read is taken past the end of the structure block,
/// so a block of `n` bytes yields at most `n / 4` tokens. After an error or `FDT_END`
/// the iterator yields nothing.
pub struct Tokens<'a> {
    blob: &'a [u8],
    pos: usize,
    /// End of the structure block. No read crosses it.
    end: usize,
    strings: &'a [u8],
    depth: usize,
    /// Bit `d - 1` is set once the open node at depth `d` has had a subnode.
    has_child: u64,
    root_seen: bool,
    done: bool,
}

impl<'a> Iterator for Tokens<'a> {
    type Item = Result<Token<'a>, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        match self.step() {
            Ok(Some(t)) => Some(Ok(t)),
            Ok(None) => {
                self.done = true;
                None
            }
            Err(e) => {
                self.done = true;
                Some(Err(e))
            }
        }
    }
}

impl<'a> Tokens<'a> {
    /// A big-endian `u32` at `at`, only if all four bytes are inside the structure
    /// block.
    fn cell(&self, at: usize) -> Option<u32> {
        if at.checked_add(4)? > self.end {
            return None;
        }
        be32(self.blob, at)
    }

    /// The bit in `has_child` for the node open at `depth`, if `depth` is a real one.
    fn child_bit(depth: usize) -> Option<u64> {
        let shift = u32::try_from(depth.checked_sub(1)?).ok()?;
        1u64.checked_shl(shift)
    }

    fn step(&mut self) -> Result<Option<Token<'a>>, Error> {
        // Bounded: each pass either returns or advances `pos` by four, and `cell`
        // refuses to read past `end`.
        loop {
            let offset = self.pos;
            if offset >= self.end {
                return Err(Error::MissingEnd { offset: self.end });
            }
            let truncated = Error::TruncatedStructure { offset };
            let token = self.cell(offset).ok_or(truncated)?;
            let after = offset.checked_add(4).ok_or(truncated)?;

            match token {
                FDT_NOP => {
                    self.pos = after;
                }
                FDT_BEGIN_NODE => {
                    let rest = self.blob.get(after..self.end).ok_or(truncated)?;
                    let len = rest
                        .iter()
                        .position(|&b| b == 0)
                        .ok_or(Error::UnterminatedNodeName { offset })?;
                    let name = rest.get(..len).ok_or(truncated)?;
                    let next = after
                        .checked_add(len)
                        .and_then(|v| v.checked_add(1))
                        .and_then(align4)
                        .ok_or(truncated)?;
                    if next > self.end {
                        return Err(truncated);
                    }

                    if self.depth == 0 && self.root_seen {
                        return Err(Error::MultipleRoots { offset });
                    }
                    if self.depth >= MAX_DEPTH {
                        return Err(Error::NestingTooDeep { offset });
                    }
                    if let Some(bit) = Self::child_bit(self.depth) {
                        self.has_child |= bit;
                    }
                    self.depth = self.depth.checked_add(1).ok_or(truncated)?;
                    if let Some(bit) = Self::child_bit(self.depth) {
                        self.has_child &= !bit;
                    }
                    self.root_seen = true;
                    self.pos = next;
                    return Ok(Some(Token::BeginNode {
                        name,
                        depth: self.depth,
                        offset,
                    }));
                }
                FDT_END_NODE => {
                    let depth = self.depth;
                    self.depth = depth
                        .checked_sub(1)
                        .ok_or(Error::UnbalancedEndNode { offset })?;
                    self.pos = after;
                    return Ok(Some(Token::EndNode { depth, offset }));
                }
                FDT_PROP => {
                    let len = self.cell(after).ok_or(truncated)?;
                    let name_at = after.checked_add(4).ok_or(truncated)?;
                    let name_offset = self.cell(name_at).ok_or(truncated)?;
                    let value_start = name_at.checked_add(4).ok_or(truncated)?;
                    let value_end = to_usize(len)
                        .and_then(|l| value_start.checked_add(l))
                        .ok_or(truncated)?;
                    let next = align4(value_end).ok_or(truncated)?;
                    if value_end > self.end || next > self.end {
                        return Err(truncated);
                    }
                    let value = self.blob.get(value_start..value_end).ok_or(truncated)?;

                    if self.depth == 0 {
                        return Err(Error::PropertyOutsideNode { offset });
                    }
                    if Self::child_bit(self.depth).is_some_and(|bit| self.has_child & bit != 0) {
                        return Err(Error::PropertyAfterSubnode { offset });
                    }
                    let name = self.string(name_offset, offset)?;
                    self.pos = next;
                    return Ok(Some(Token::Property {
                        name,
                        value,
                        depth: self.depth,
                        offset,
                    }));
                }
                FDT_END => {
                    if !self.root_seen {
                        return Err(Error::NoRootNode { offset });
                    }
                    if self.depth != 0 {
                        return Err(Error::EndInsideNode {
                            offset,
                            depth: self.depth,
                        });
                    }
                    self.pos = after;
                    return Ok(None);
                }
                other => {
                    return Err(Error::UnknownToken {
                        offset,
                        token: other,
                    });
                }
            }
        }
    }

    /// Resolve a property name through the strings block.
    fn string(&self, name_offset: u32, offset: usize) -> Result<&'a [u8], Error> {
        let rest = to_usize(name_offset)
            .and_then(|start| self.strings.get(start..))
            .filter(|rest| !rest.is_empty())
            .ok_or(Error::NameOffsetOutOfRange {
                offset,
                name_offset,
            })?;
        let len = rest
            .iter()
            .position(|&b| b == 0)
            .ok_or(Error::UnterminatedPropertyName {
                offset,
                name_offset,
            })?;
        rest.get(..len).ok_or(Error::UnterminatedPropertyName {
            offset,
            name_offset,
        })
    }
}

// --- memory map interpretation ---------------------------------------------------

/// Cell counts declared by one node.
#[derive(Clone, Copy)]
struct Cells {
    address: u32,
    size: u32,
    /// Offset of a cell-count property that was not exactly one cell. Recorded rather
    /// than reported on sight: a malformed count on a node nobody reads a `reg` under
    /// is not a reason to refuse the machine's memory map.
    malformed: Option<usize>,
}

impl Cells {
    const DEFAULT: Cells = Cells {
        address: DEFAULT_ADDRESS_CELLS,
        size: DEFAULT_SIZE_CELLS,
        malformed: None,
    };

    fn record(&mut self, name: &[u8], value: &[u8], offset: usize) {
        let slot = match name {
            b"#address-cells" => &mut self.address,
            b"#size-cells" => &mut self.size,
            _ => return,
        };
        match value {
            [a, b, c, d] => *slot = u32::from_be_bytes([*a, *b, *c, *d]),
            _ => self.malformed = Some(offset),
        }
    }
}

/// What has been seen so far of one open node that might describe memory.
#[derive(Clone, Copy)]
struct Node<'a> {
    /// `device_type = "memory"`.
    memory: bool,
    /// `status` absent, `"okay"` or `"ok"`.
    available: bool,
    /// This is `/reserved-memory`.
    reserved_container: bool,
    /// The `reg` value and the offset of its token.
    reg: Option<(&'a [u8], usize)>,
}

impl<'a> Node<'a> {
    const EMPTY: Node<'static> = Node {
        memory: false,
        available: true,
        reserved_container: false,
        reg: None,
    };

    fn record(&mut self, name: &[u8], value: &'a [u8], offset: usize) {
        match name {
            b"device_type" => self.memory = string_value(value) == Some(&b"memory"[..]),
            b"status" => {
                self.available = matches!(string_value(value), Some(b"okay") | Some(b"ok"))
            }
            b"reg" => self.reg = Some((value, offset)),
            _ => {}
        }
    }
}

/// A property value holding one string: the bytes before its single terminating NUL.
fn string_value(value: &[u8]) -> Option<&[u8]> {
    let s = value.strip_suffix(&[0])?;
    (!s.contains(&0)).then_some(s)
}

/// Where regions are written, and how many of them are usable.
struct Sink<'o> {
    out: &'o mut [MemoryRegion],
    n: usize,
    usable: usize,
}

impl Sink<'_> {
    fn push(&mut self, start: u64, len: u64, kind: MemoryKind) -> Result<(), Error> {
        if len == 0 {
            return Ok(());
        }
        let capacity = self.out.len();
        let slot = self
            .out
            .get_mut(self.n)
            .ok_or(Error::TooManyRegions { capacity })?;
        *slot = MemoryRegion {
            start,
            len,
            kind: wire(kind),
            _reserved: 0,
        };
        // Cannot saturate: `n` indexed a slot, so it is below `out.len()`.
        self.n = self.n.saturating_add(1);
        if kind == MemoryKind::Usable {
            self.usable = self.usable.saturating_add(1);
        }
        Ok(())
    }
}

/// Interpret one `reg` property with its parent's cell counts, pushing each entry.
fn emit(
    reg: &[u8],
    offset: usize,
    cells: Cells,
    kind: MemoryKind,
    sink: &mut Sink<'_>,
) -> Result<(), Error> {
    if let Some(bad) = cells.malformed {
        return Err(Error::BadCellsProperty { offset: bad });
    }
    let unsupported = Error::UnsupportedCells {
        offset,
        address_cells: cells.address,
        size_cells: cells.size,
    };
    if cells.address > MAX_CELLS || cells.size > MAX_CELLS {
        return Err(unsupported);
    }
    // Both counts are at most MAX_CELLS, so none of this can overflow; checked anyway
    // so that raising MAX_CELLS cannot quietly make it overflow.
    let address_bytes = cells
        .address
        .checked_mul(4)
        .and_then(to_usize)
        .ok_or(unsupported)?;
    let size_bytes = cells
        .size
        .checked_mul(4)
        .and_then(to_usize)
        .ok_or(unsupported)?;
    let entry = address_bytes.checked_add(size_bytes).ok_or(unsupported)?;
    if entry == 0 {
        // Zero-width entries would make the loop below take no steps per entry, and a
        // `reg` of any length would "contain" infinitely many of them.
        return Err(unsupported);
    }
    if reg.len() % entry != 0 {
        return Err(Error::RegLength {
            offset,
            len: reg.len(),
            entry,
        });
    }

    for pair in reg.chunks_exact(entry) {
        let (address, size) = pair
            .split_at_checked(address_bytes)
            .ok_or(Error::RegLength {
                offset,
                len: reg.len(),
                entry,
            })?;
        let start = cells_value(address, offset)?;
        let len = cells_value(size, offset)?;
        if start.checked_add(len).is_none() {
            return Err(Error::RegionOverflow { offset });
        }
        sink.push(start, len, kind)?;
    }
    Ok(())
}

/// A big-endian multi-cell value as a `u64`, refusing one whose high cells are set.
fn cells_value(bytes: &[u8], offset: usize) -> Result<u64, Error> {
    let mut value = 0u64;
    for cell in bytes.chunks_exact(4) {
        let [a, b, c, d] = cell else {
            return Err(Error::ValueTooWide { offset });
        };
        if value >> 32 != 0 {
            return Err(Error::ValueTooWide { offset });
        }
        value = (value << 32) | u64::from(u32::from_be_bytes([*a, *b, *c, *d]));
    }
    Ok(value)
}

/// The one place this unit turns a [`MemoryKind`] into its wire value. The boot
/// protocol carries it as a `u32` so that an unknown kind survives intact.
#[allow(clippy::as_conversions)]
fn wire(kind: MemoryKind) -> u32 {
    kind as u32
}

// --- byte helpers ----------------------------------------------------------------

/// A header block's `[start, end)`, checked to lie after the header and within
/// `totalsize`.
fn block(total: usize, offset: u32, size: u32, which: Block) -> Result<(usize, usize), Error> {
    let err = Error::BlockOutOfBounds {
        block: which,
        offset,
        size,
    };
    let start = to_usize(offset).ok_or(err)?;
    let end = to_usize(size)
        .and_then(|s| start.checked_add(s))
        .ok_or(err)?;
    if start < HEADER_LEN || end > total {
        return Err(err);
    }
    Ok((start, end))
}

fn be32(bytes: &[u8], at: usize) -> Option<u32> {
    let b = bytes.get(at..at.checked_add(4)?)?;
    Some(u32::from_be_bytes(b.try_into().ok()?))
}

fn be64(bytes: &[u8], at: usize) -> Option<u64> {
    let b = bytes.get(at..at.checked_add(8)?)?;
    Some(u64::from_be_bytes(b.try_into().ok()?))
}

fn to_usize(v: u32) -> Option<usize> {
    usize::try_from(v).ok()
}

fn align4(v: usize) -> Option<usize> {
    Some(v.checked_add(3)? & !3)
}

#[cfg(test)]
mod tests;

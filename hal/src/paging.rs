//! The page table contract.
//!
//! Three architectures, three table formats, and one walker. The formats genuinely
//! differ — x86-64 has four uniform 9-bit levels, i686 with PAE has two 9-bit levels
//! under a 2-bit one, and AArch64 encodes permissions as access-permission bits
//! rather than as a write flag plus a no-execute flag. What they share is the
//! *shape*: a radix tree, indexed by slices of the virtual address, whose leaves name
//! frames.
//!
//! So this module splits the problem where the difference actually lies. The
//! architecture supplies **geometry** (how many levels, how many bits each consumes)
//! and **entry encoding** (how to read and write one word of table). Everything
//! above — walking, allocating intermediate tables, splitting a huge page, tearing a
//! range down — is written once in `mm::paged` and is the same code on every target.
//!
//! The alternative, a `map`/`unmap` pair implemented per architecture, was rejected:
//! it is three copies of the same tree walk, and a tree walk is precisely where the
//! subtle bugs live.
//!
//! # Level numbering
//!
//! **Level 0 is the leaf table**, and numbers increase toward the root. So on x86-64
//! level 0 is the PT, level 3 the PML4; with PAE, level 0 is the PT and level 2 the
//! PDPT. Counting from the leaf rather than the root means "a leaf entry at level 0"
//! means the same thing everywhere, and a three-level format is a four-level one with
//! the top removed rather than with everything renumbered.

use crate::PhysAddr;
use core::fmt;

/// What a mapping permits, in architecture-neutral terms.
///
/// The architecture translates these into its own encoding, which is not a
/// straightforward renaming: x86 spells "not writable" as the absence of a bit and
/// "not executable" as the presence of one, while AArch64 uses a two-bit
/// access-permission field plus separate privileged and unprivileged execute-never
/// bits. Keeping the neutral form free of either spelling is what stops one
/// architecture's habits leaking into the shared walker.
#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub struct PageFlags(u16);

macro_rules! flags {
    ($($name:ident = $bit:expr, $doc:literal;)*) => {
        impl PageFlags {
            $(#[doc = $doc] pub const $name: PageFlags = PageFlags(1 << $bit);)*
            fn names(self) -> impl Iterator<Item = &'static str> {
                const T: &[(u16, &str)] = &[$((1 << $bit, stringify!($name))),*];
                T.iter().filter(move |(b, _)| self.0 & b != 0).map(|(_, n)| *n)
            }
        }
    };
}

flags! {
    READ = 0, "The mapping may be read. Absent on every architecture we target as a \
               separate bit — a present entry is readable — but kept explicit so that \
               a target with read-disable can express it.";
    WRITE = 1, "The mapping may be written.";
    EXECUTE = 2, "Instructions may be fetched from the mapping.";
    USER = 3, "Unprivileged code may access the mapping.";
    GLOBAL = 4, "The translation survives an address-space switch.";
    DEVICE = 5, "Device memory: uncached, and not speculatively accessed or reordered.";
    NO_CACHE = 6, "Normal memory, caching disabled.";
}

impl PageFlags {
    pub const fn empty() -> PageFlags {
        PageFlags(0)
    }
    pub const fn bits(self) -> u16 {
        self.0
    }
    pub const fn contains(self, other: PageFlags) -> bool {
        self.0 & other.0 == other.0
    }
    pub const fn union(self, other: PageFlags) -> PageFlags {
        PageFlags(self.0 | other.0)
    }
    pub const fn without(self, other: PageFlags) -> PageFlags {
        PageFlags(self.0 & !other.0)
    }

    /// Kernel code: readable and executable, never writable.
    pub const KERNEL_TEXT: PageFlags = PageFlags(1 | (1 << 2));
    /// Kernel read-only data: readable only. Not executable — the distinction is the
    /// whole reason `.rodata` is a separate section.
    pub const KERNEL_RODATA: PageFlags = PageFlags(1);
    /// Kernel data and stacks: readable and writable, never executable.
    pub const KERNEL_DATA: PageFlags = PageFlags(1 | (1 << 1));
}

impl core::ops::BitOr for PageFlags {
    type Output = PageFlags;
    fn bitor(self, rhs: PageFlags) -> PageFlags {
        self.union(rhs)
    }
}

impl fmt::Debug for PageFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0 == 0 {
            return f.write_str("PageFlags(none)");
        }
        f.write_str("PageFlags(")?;
        let mut first = true;
        for n in self.names() {
            if !first {
                f.write_str("|")?;
            }
            f.write_str(n)?;
            first = false;
        }
        f.write_str(")")
    }
}

/// One word of a page table.
///
/// Deliberately `Copy` and free of lifetimes: an entry is a value read out of a
/// table, reasoned about, and written back. Holding a reference into a live page
/// table across a walk is how aliasing bugs start.
pub trait PageTableEntry: Copy + Sized + Send + Sync + 'static {
    /// An absent entry. Must be all-zero on every architecture we support, because
    /// freshly allocated tables are zeroed frames.
    fn empty() -> Self;

    /// Whether this entry maps anything at all.
    fn is_present(self) -> bool;

    /// Whether this entry maps a frame directly, rather than naming a next-level
    /// table.
    ///
    /// Takes the level because the encoding is level-dependent: on x86 bit 7 means
    /// "huge page" at an intermediate level and means PAT at the leaf, so the same
    /// bit pattern answers differently depending on where it was found.
    fn is_leaf(self, level: u8) -> bool;

    /// The physical address this entry names — a frame if it is a leaf, the next
    /// table if it is not.
    fn address(self) -> PhysAddr;

    /// The permissions this entry grants, in neutral terms.
    fn flags(self, level: u8) -> PageFlags;

    /// An entry naming the next-level table at `table`.
    ///
    /// Intermediate entries are deliberately permissive on architectures where
    /// permissions intersect down the tree: restricting here would silently cap every
    /// leaf beneath, and the leaf is where the intent is expressed.
    fn table(table: PhysAddr) -> Self;

    /// An entry mapping `frame` with `flags` at `level`.
    fn leaf(frame: PhysAddr, flags: PageFlags, level: u8) -> Self;
}

/// Why a mapping operation could not be completed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MapError {
    /// The virtual address is not one this architecture can represent — on x86-64,
    /// a non-canonical address.
    NotCanonical,
    /// Address or length is not a multiple of the page size.
    Misaligned,
    /// Something is already mapped there.
    AlreadyMapped,
    /// Nothing is mapped there.
    NotMapped,
    /// A frame was needed for an intermediate table and none was available.
    OutOfFrames,
    /// The walk reached a huge page where it needed to descend, and splitting was
    /// not permitted.
    WouldSplit,
    /// The physical address does not fit this architecture's entry encoding.
    BadPhysAddr,
}

/// An architecture with page tables.
///
/// Extends [`crate::HasMmu`] with everything the shared walker needs. Kept separate
/// from `HasMmu` so that a target which has an MMU the kernel does not drive — an
/// early bring-up, or a hypervisor guest using someone else's tables — can still
/// advertise the capability.
pub trait HasPageTables: crate::HasMmu {
    /// One word of a table on this architecture.
    type Entry: PageTableEntry;

    /// Virtual address bits consumed by the index at `level`.
    ///
    /// Not a constant, because it is not uniform: with PAE the top level is indexed
    /// by two bits and the rest by nine. A format whose levels are uniform returns
    /// the same number for every level and costs nothing.
    fn index_bits(level: u8) -> u8;

    /// Whether a leaf entry is permitted at `level`. Level 0 is always true; higher
    /// levels are the huge-page sizes, and not every level supports one.
    fn leaf_allowed(level: u8) -> bool;

    /// Whether `addr` is a virtual address this architecture can represent.
    ///
    /// x86-64 requires the unused high bits to replicate bit 47 — a "non-canonical"
    /// address faults rather than wrapping, and constructing one silently is a bug
    /// worth catching at the mapping call rather than at the access.
    fn is_canonical(addr: usize) -> bool;

    /// Install `root` as the active translation table.
    ///
    /// # Safety
    /// `root` must name a correctly formed table for this architecture that maps,
    /// at minimum, the code currently executing and the stack in use. Installing a
    /// table that does not is an immediate and unrecoverable fault.
    unsafe fn set_root(root: PhysAddr);

    /// The active translation table.
    fn root() -> PhysAddr;

    /// Invalidate cached translations for one address, or for all of them.
    ///
    /// # Safety
    /// Callers must ensure the corresponding table writes are visible to the page
    /// table walker first — on architectures with a separate walker this needs a
    /// barrier the caller is responsible for.
    unsafe fn flush_tlb(addr: Option<usize>);
}

/// Bytes mapped by one entry at `level`, for an architecture's geometry.
///
/// Free function rather than a trait method: it is the same arithmetic everywhere
/// once `index_bits` is known, and every architecture deriving it independently is
/// three chances to get a shift wrong.
pub fn level_size<A: HasPageTables>(level: u8) -> usize {
    let mut shift = A::PAGE_SIZE.trailing_zeros() as u8;
    for l in 0..level {
        shift += A::index_bits(l);
    }
    1usize << shift
}

/// The index into the table at `level` for virtual address `addr`.
pub fn level_index<A: HasPageTables>(addr: usize, level: u8) -> usize {
    let size = level_size::<A>(level);
    let bits = A::index_bits(level) as u32;
    (addr / size) & ((1usize << bits) - 1)
}

/// Number of entries in a table at `level`.
pub fn level_entries<A: HasPageTables>(level: u8) -> usize {
    1usize << A::index_bits(level)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flag_sets_are_what_they_say() {
        assert!(PageFlags::KERNEL_TEXT.contains(PageFlags::EXECUTE));
        assert!(!PageFlags::KERNEL_TEXT.contains(PageFlags::WRITE));
        assert!(PageFlags::KERNEL_DATA.contains(PageFlags::WRITE));
        assert!(
            !PageFlags::KERNEL_DATA.contains(PageFlags::EXECUTE),
            "writable and executable at once is the thing these sets exist to prevent"
        );
        assert!(!PageFlags::KERNEL_RODATA.contains(PageFlags::WRITE));
        assert!(!PageFlags::KERNEL_RODATA.contains(PageFlags::EXECUTE));
    }

    #[test]
    fn without_removes_and_union_adds() {
        let f = PageFlags::KERNEL_DATA | PageFlags::USER;
        assert!(f.contains(PageFlags::USER));
        assert!(!f.without(PageFlags::USER).contains(PageFlags::USER));
        assert!(f.without(PageFlags::USER).contains(PageFlags::WRITE));
    }

    #[test]
    fn debug_names_the_bits() {
        extern crate std;
        let s = std::format!("{:?}", PageFlags::KERNEL_TEXT);
        assert!(s.contains("READ") && s.contains("EXECUTE"), "{s}");
        assert_eq!(std::format!("{:?}", PageFlags::empty()), "PageFlags(none)");
    }
}

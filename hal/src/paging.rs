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

use core::fmt;

use crate::PhysAddr;

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
    /// Reconstruct from raw bits, dropping any this build does not define — the same
    /// discipline as `kobject::Rights`: authority we cannot reason about is discarded
    /// rather than carried.
    pub const fn from_bits_truncate(bits: u16) -> PageFlags {
        PageFlags(bits & 0x7F)
    }
    /// Whether **every** bit of `other` is present.
    pub const fn contains(self, other: PageFlags) -> bool {
        self.0 & other.0 == other.0
    }

    /// Whether **any** bit of `other` is present.
    ///
    /// The one to reach for when asking "is anything here that should not be". Using
    /// `contains` for that reads the same and means the opposite: a probe denying
    /// `WRITE | EXECUTE` passes on a page that is merely executable, because it does
    /// not hold *both*.
    pub const fn intersects(self, other: PageFlags) -> bool {
        self.0 & other.0 != 0
    }
    pub const fn union(self, other: PageFlags) -> PageFlags {
        PageFlags(self.0 | other.0)
    }
    pub const fn without(self, other: PageFlags) -> PageFlags {
        PageFlags(self.0 & !other.0)
    }

    /// Every flag, for tests that need a full mask.
    #[doc(hidden)]
    pub const ALL_TEST: PageFlags = PageFlags(0x7F);

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
    ///
    /// Takes the level because one architecture needs it, and that architecture is
    /// the reason this parameter exists. A 32-bit PAE PDPT entry has **only** the
    /// present bit and the two cache bits — bits 1 and 2 are reserved, and setting
    /// them faults on the write to CR3 — while the page directory entry one level
    /// down needs exactly those bits set or every leaf beneath it is read-only and
    /// supervisor-only. There is no single encoding that is correct at both levels,
    /// so there cannot be a single answer without the level.
    fn table(table: PhysAddr, level: u8) -> Self;

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

/// Where the kernel image's parts live in physical memory.
///
/// Needed because a linker script knows things no amount of runtime probing can
/// recover: which bytes are instructions, which are constants, and which are
/// writable. Without that split there is no W^X — the whole image has to be mapped
/// readable, writable and executable, which is what every port does at boot today.
///
/// Ranges are `[start, end)` and need not be page-aligned; the consumer rounds
/// outward for writability and inward for execute, so a section boundary inside a
/// page never grants more than both neighbours should have.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ImageSections {
    /// Instructions. Mapped read + execute, never writable.
    pub text: (u64, u64),
    /// Constants. Mapped read-only and non-executable — which is the entire reason
    /// `.rodata` is a section of its own.
    pub rodata: (u64, u64),
    /// Initialised and zeroed data, including the stacks. Read + write, never
    /// executable.
    pub data: (u64, u64),
    /// A page below the boot stack that must be left **unmapped**.
    ///
    /// An IST or a separate fault stack lets the kernel report a stack overflow; it
    /// does not let it *detect* one. Without a guard page an overflow walks quietly
    /// into whatever the linker placed below the stack — on x86_64 that was the live
    /// page tables — and the machine is gone before any handler runs. This is the
    /// half that turns a silent death into a diagnosable fault.
    ///
    /// `(0, 0)` means the port has not carved one out yet.
    pub stack_guard: (u64, u64),
    /// Kernel thread stacks, each above a guard page of its own. Inside `data`, with
    /// every guard page punched back out of it the way `stack_guard` is.
    ///
    /// [`StackArray::NONE`] means the port has not laid any out.
    pub thread_stacks: StackArray,
}

/// A run of equal-sized kernel thread stacks, each with an unmapped guard page below it.
///
/// The boot stack's guard page protects one stack. A kernel thread's stack overflowing
/// into the next thread's stack does not fault and does not report; it corrupts a
/// suspended thread, which fails later and somewhere else. So each stack gets a slot of
/// its own: a guard page at the bottom, then the stack.
///
/// ```text
///   start                                                          end
///   | guard | stack 0      | guard | stack 1      | ... | guard | stack n-1 |
///   |<-------- slot ------->|
/// ```
///
/// The slot size is a power of two. That is not tidiness: aarch64's exception entry has to
/// decide whether an exception frame would land in *some* guard page before it may touch
/// the stack, in a handful of instructions and two scratch registers, and a mask is the
/// only test that fits.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct StackArray {
    /// First byte of the first slot.
    pub start: u64,
    /// One past the last byte of the last slot.
    pub end: u64,
    /// Bytes per slot, guard included. A power of two, or the array is treated as empty.
    pub slot: u64,
    /// Bytes of guard at the bottom of each slot. Less than `slot`.
    pub guard: u64,
}

impl StackArray {
    /// No thread stacks laid out.
    pub const NONE: StackArray = StackArray {
        start: 0,
        end: 0,
        slot: 0,
        guard: 0,
    };

    /// Whether the geometry describes at least one usable stack.
    pub const fn is_valid(&self) -> bool {
        self.slot.is_power_of_two() && self.guard < self.slot && self.end > self.start
    }

    /// How many whole slots fit.
    pub const fn count(&self) -> usize {
        if !self.is_valid() {
            return 0;
        }
        // A shift, not a division: `slot` is a power of two, and u64 division on a
        // 32-bit target is a runtime-library call.
        ((self.end - self.start) >> self.slot.trailing_zeros()) as usize
    }

    /// `[start, end)` of slot `i`, guard included.
    const fn slot_range(&self, i: usize) -> Option<(u64, u64)> {
        if i >= self.count() {
            return None;
        }
        let lo = self.start + ((i as u64) << self.slot.trailing_zeros());
        Some((lo, lo + self.slot))
    }

    /// The guard page of slot `i`, as `[start, end)`.
    pub const fn guard_range(&self, i: usize) -> Option<(u64, u64)> {
        match self.slot_range(i) {
            Some((lo, _)) => Some((lo, lo + self.guard)),
            None => None,
        }
    }

    /// The usable stack of slot `i`, as `[bottom, top)`.
    pub const fn stack_range(&self, i: usize) -> Option<(u64, u64)> {
        match self.slot_range(i) {
            Some((lo, hi)) => Some((lo + self.guard, hi)),
            None => None,
        }
    }

    /// The slot `addr` falls in, guard or stack.
    pub const fn slot_of(&self, addr: u64) -> Option<usize> {
        if addr < self.start || !self.is_valid() {
            return None;
        }
        let i = ((addr - self.start) >> self.slot.trailing_zeros()) as usize;
        if i < self.count() { Some(i) } else { None }
    }

    /// The slot whose guard page `addr` is in. `None` for an address on a stack, or
    /// outside the array.
    pub const fn guard_hit(&self, addr: u64) -> Option<usize> {
        match self.slot_of(addr) {
            Some(i) if (addr - self.start) & (self.slot - 1) < self.guard => Some(i),
            _ => None,
        }
    }
}

impl ImageSections {
    /// A single read-write-execute blob, for a port that has not split its image yet.
    ///
    /// Deliberately not the default anyone should keep: it maps instructions writable
    /// and data executable. It exists so the address-space builder can be written and
    /// tested before every port has section symbols, and so that a port that has not
    /// done the work says so in its own type rather than silently looking finished.
    pub const fn unsplit(start: u64, end: u64) -> ImageSections {
        ImageSections {
            text: (start, end),
            rodata: (0, 0),
            data: (0, 0),
            stack_guard: (0, 0),
            thread_stacks: StackArray::NONE,
        }
    }

    /// Whether this port actually distinguishes its sections.
    pub const fn is_split(&self) -> bool {
        self.rodata.1 > self.rodata.0 && self.data.1 > self.data.0
    }

    /// Whether this port has a guard page below its stack.
    pub const fn has_stack_guard(&self) -> bool {
        self.stack_guard.1 > self.stack_guard.0
    }
}

/// A range of device memory the kernel reaches after it installs its own tables.
///
/// The address space the kernel builds for itself maps RAM and the image, because those
/// are what a memory map and a linker script describe. It knows nothing about devices,
/// and a device left out of it is not an error anyone sees at build time. It becomes a
/// fault on the first register access after the switch, which on a port whose console
/// is MMIO is a fault with nowhere to print. So each port states its windows, and the
/// builder maps them.
///
/// Mapped at the same virtual address as the physical one while the kernel is
/// identity-mapped, and never executable.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct DeviceWindow {
    /// First byte of the window. Need not be page-aligned; the builder rounds outward.
    pub phys: u64,
    /// Length in bytes.
    pub len: u64,
    /// What lives there, for the report when mapping it fails.
    pub what: &'static str,
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

    /// Whether a mapping can currently be made non-executable.
    ///
    /// Not a constant, because on x86 it is not: execute-disable needs a CPU feature
    /// probed at run time *and* a control bit that has to be set before it is honoured.
    /// The i686 target's default QEMU CPU has no NX at all, so on that machine every
    /// mapping is executable whatever the page table says.
    ///
    /// Callers that verify W^X need this to tell "the kernel asked for the wrong
    /// permissions" from "the hardware cannot express the right ones". Treating the
    /// second as the first produces a failure nobody can fix; treating the first as the
    /// second hides a real bug. So the answer has to come from the architecture.
    fn can_forbid_execute() -> bool;

    /// Whether the CPU copies entries of the table at `level` when the root is loaded,
    /// rather than walking them through the TLB.
    ///
    /// When it does, filling an absent entry at that level is invisible until the root
    /// is reloaded: `flush_tlb(Some(addr))` does not re-read it, and a fault on the new
    /// mapping looks spurious to a handler that only flushes one address, so it faults
    /// again for ever. 32-bit PAE is the case: the four PDPT entries are loaded into
    /// internal registers with CR3. Everywhere else a not-present-to-present change
    /// needs no invalidation at all, which is the default.
    fn root_load_caches(level: u8) -> bool {
        let _ = level;
        false
    }

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
    fn contains_and_intersects_are_not_the_same_question() {
        // This distinction was a live bug: a W^X check denying WRITE|EXECUTE used
        // `contains`, so it passed on a page that was executable-but-not-writable —
        // which is exactly the case it existed to catch. `contains` asks "all of
        // these", `intersects` asks "any of these".
        let rx = PageFlags::READ | PageFlags::EXECUTE;
        let forbidden = PageFlags::WRITE | PageFlags::EXECUTE;

        assert!(!rx.contains(forbidden), "rx lacks WRITE, so not all of them");
        assert!(rx.intersects(forbidden), "but it does have EXECUTE");

        // The read-only page the check should accept.
        let ro = PageFlags::READ;
        assert!(!ro.intersects(forbidden));
        assert!(!PageFlags::empty().intersects(PageFlags::ALL_TEST));
    }

    #[test]
    fn without_removes_and_union_adds() {
        let f = PageFlags::KERNEL_DATA | PageFlags::USER;
        assert!(f.contains(PageFlags::USER));
        assert!(!f.without(PageFlags::USER).contains(PageFlags::USER));
        assert!(f.without(PageFlags::USER).contains(PageFlags::WRITE));
    }

    /// Three 32 KiB slots, 4 KiB of guard each, starting at 0x10_0000.
    const STACKS: StackArray = StackArray {
        start: 0x10_0000,
        end: 0x10_0000 + 3 * 0x8000,
        slot: 0x8000,
        guard: 0x1000,
    };

    #[test]
    fn stack_array_geometry() {
        assert_eq!(STACKS.count(), 3);
        assert_eq!(STACKS.guard_range(0), Some((0x10_0000, 0x10_1000)));
        assert_eq!(STACKS.stack_range(0), Some((0x10_1000, 0x10_8000)));
        assert_eq!(STACKS.guard_range(2), Some((0x11_0000, 0x11_1000)));
        assert_eq!(STACKS.stack_range(2), Some((0x11_1000, 0x11_8000)));
        assert_eq!(STACKS.stack_range(3), None);
        assert_eq!(StackArray::NONE.count(), 0);
        assert_eq!(StackArray::NONE.guard_hit(0), None);
    }

    #[test]
    fn a_guard_hit_names_its_slot_and_a_stack_address_is_not_one() {
        // The first and last byte of each guard, and the bytes either side of it.
        assert_eq!(STACKS.guard_hit(0x10_0000), Some(0));
        assert_eq!(STACKS.guard_hit(0x10_0fff), Some(0));
        assert_eq!(STACKS.guard_hit(0x10_1000), None, "bottom byte of stack 0");
        assert_eq!(STACKS.guard_hit(0x10_7fff), None, "top byte of stack 0");
        assert_eq!(STACKS.guard_hit(0x10_8000), Some(1));
        assert_eq!(STACKS.guard_hit(0x11_0fff), Some(2));
        // Outside the array on both sides.
        assert_eq!(STACKS.guard_hit(0x0f_ffff), None);
        assert_eq!(STACKS.guard_hit(0x11_8000), None);
        assert_eq!(STACKS.slot_of(0x11_7fff), Some(2));
        assert_eq!(STACKS.slot_of(0x11_8000), None);
    }

    #[test]
    fn a_slot_that_is_not_a_power_of_two_describes_nothing() {
        // The exception-entry test on aarch64 is a mask, so a geometry it cannot test
        // must not be treated as one that works.
        let odd = StackArray {
            slot: 0x5000,
            ..STACKS
        };
        assert_eq!(odd.count(), 0);
        assert_eq!(odd.guard_hit(0x10_0000), None);
        let all_guard = StackArray {
            guard: 0x8000,
            ..STACKS
        };
        assert_eq!(all_guard.count(), 0);
    }

    #[test]
    fn debug_names_the_bits() {
        extern crate std;
        let s = std::format!("{:?}", PageFlags::KERNEL_TEXT);
        assert!(s.contains("READ") && s.contains("EXECUTE"), "{s}");
        assert_eq!(std::format!("{:?}", PageFlags::empty()), "PageFlags(none)");
    }
}

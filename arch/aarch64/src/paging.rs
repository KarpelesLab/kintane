//! AArch64 translation tables: the descriptor format, the boot identity map, and the
//! switch that turns the MMU on.
//!
//! # Level numbering, which is inverted from Arm's
//!
//! `hal::paging` numbers levels from the leaf: **level 0 is the table whose entries
//! map 4 KiB pages**, and the number grows toward the root. Arm numbers them the other
//! way — its level 0 is the root and its level 3 holds the pages. Every level number
//! crossing the `hal` boundary is therefore the opposite of the one in DDI 0487, and
//! the translation is:
//!
//! | `hal` level | Arm level | one entry maps | leaf descriptor |
//! |---|---|---|---|
//! | 0 | L3 | 4 KiB | page, `0b11` |
//! | 1 | L2 | 2 MiB | block, `0b01` |
//! | 2 | L1 | 1 GiB | block, `0b01` |
//! | 3 | L0 | 512 GiB | none — table only |
//!
//! This is worth stating loudly because getting it backwards is silent: a level-1
//! block descriptor written where a level-2 one belongs is a well-formed entry that
//! maps the wrong 512 pages, and nothing faults until something reads the wrong
//! memory. The mapping above is the only place the two conventions meet; below this
//! line every `level` is a `hal` level.
//!
//! # The descriptor format
//!
//! A descriptor is one 64-bit word. Bits `[1:0]` say what it is, and — this is the
//! collision that forces [`hal::PageTableEntry::is_leaf`] to take a level — the same
//! `0b11` means "points at the next table" at Arm levels 0–2 and "maps a page" at Arm
//! level 3. `0b01` is a block, valid only at Arm L1 and L2. Anything with bit 0 clear
//! is invalid.
//!
//! Permissions are not a write bit and a no-execute bit. `AP[2:1]` in bits `[7:6]` is a
//! two-bit *access permission* selecting one of RW/RO crossed with EL1-only/EL1+EL0,
//! and execution has two separate bits: `PXN` (53) for EL1 and `UXN` (54) for EL0.
//! Translating the neutral [`PageFlags`] into that is where the interesting part of
//! this file is, and the direction that matters is the hardening one: a mapping
//! reachable from EL0 is never executable at EL1, and a kernel mapping is never
//! executable at EL0, regardless of what the caller asked for.
//!
//! `AF` (bit 10) must be set on every leaf we write. Hardware does not manage it for
//! us unless `FEAT_HAFDBS` is both present and enabled, so a leaf without it takes an
//! Access Flag fault on its first touch — the single most common way an otherwise
//! correct AArch64 map turns into an immediate exception.
//!
//! # Memory attributes
//!
//! `AttrIndx[4:2]` selects one of eight byte-sized entries in `MAIR_EL1` rather than
//! encoding the memory type inline. [`MAIR`] defines them; index 0 is
//! Device-nGnRnE, which is what every MMIO mapping gets. This is not a performance
//! knob: mapping the PL011 or the GIC as Normal memory lets the CPU cache, merge and
//! reorder accesses that the device distinguishes, and the failure is intermittent.
//!
//! # What the boot map covers
//!
//! Two regions, both identity, so that enabling the MMU does not move anything:
//!
//! - `0x0000_0000..0x4000_0000` as one 1 GiB Device-nGnRnE block. That is where
//!   QEMU `virt` puts the PL011, the GIC distributor and redistributors, and the
//!   flash — everything the kernel reaches by MMIO.
//! - `0x4000_0000..0x8000_0000` as 512 × 2 MiB Normal write-back blocks. RAM begins
//!   at `0x4000_0000` on `virt` and the image is linked at `0x4008_0000`.
//!
//! The second is deliberately larger than the RAM QEMU is usually given, so that
//! changing `-m` does not unmap the kernel. Mapping unbacked addresses as Normal
//! memory is a real hazard on hardware that speculates into them, and the fix is the
//! same one the frame allocator is waiting for: build this range from the memory map
//! instead of from a constant, once there is a device-tree parser to read it from.
//!
//! # Why the image is not left inside a 2 MiB block
//!
//! `link.ld` splits the image into `.text`, `.rodata` and a data region, page-aligned
//! at every boundary, and reserves a guard page under the boot stack; `image_sections`
//! reports them. All of that is expressed in units of 4 KiB — and a 2 MiB block cannot
//! express any of it. One block covers the whole image here, so leaving the boot map as
//! 512 blocks would mean the finest permission this port can state over its own
//! instructions is "these two megabytes", which is the union of text, rodata, data,
//! stack and guard: read, write and execute, everywhere.
//!
//! So [`aarch64_mmu_init`] walks back over the blocks the image occupies and replaces
//! each with a table of 512 4 KiB pages naming the same frames with the same
//! permissions. The boot map is unchanged in what it *permits* — it still grants RWX
//! over the image, because applying W^X is the address-space builder's job and it needs
//! a console to report a mistake, which does not exist yet. What changes is that the
//! refinement is now *possible*: the builder can rewrite a leaf per page instead of
//! failing with [`MapError::WouldSplit`] on a block it is not allowed to break apart.
//!
//! [`selftest`] checks this rather than assuming it — it walks the live tables and
//! reports the level at which the image's first and last pages are mapped.
//!
//! Reference: Arm Architecture Reference Manual for A-profile, DDI 0487, D8.3
//! ("Translation table descriptor formats"), D8.4 ("Memory access control"),
//! D19.2.107 (`MAIR_EL1`), D19.2.145 (`TCR_EL1`), D19.2.120 (`SCTLR_EL1`).

use crate::Aarch64;
use core::cell::UnsafeCell;
use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{AtomicUsize, Ordering};
use hal::paging::{level_index, HasPageTables, MapError, PageFlags, PageTableEntry};
use hal::{Arch, EarlyConsole, HasMmu, PhysAddr};

// --- descriptor bits ------------------------------------------------------------

/// Bit 0: the descriptor describes something. Clear means a translation fault.
const VALID: u64 = 1 << 0;
/// Bit 1: "table or page" rather than "block". Its meaning depends on the level,
/// which is the whole reason [`PageTableEntry::is_leaf`] is given one.
const TABLE_OR_PAGE: u64 = 1 << 1;
/// `AttrIndx[4:2]`: which `MAIR_EL1` byte describes this mapping's memory type.
const ATTR_INDX_SHIFT: u32 = 2;
/// `AP[1]` (bit 6): the mapping is reachable from EL0.
const AP_EL0: u64 = 1 << 6;
/// `AP[2]` (bit 7): the mapping is read-only. Note the polarity — this is a
/// *restriction*, unlike x86's writable bit.
const AP_RO: u64 = 1 << 7;
/// `SH[9:8] = 0b11`: inner shareable, which is what Normal memory needs for the
/// broadcast TLB and cache maintenance the rest of this file relies on.
const SH_INNER: u64 = 0b11 << 8;
/// Bit 10, the Access Flag. Mandatory on every leaf; see the module comment.
const AF: u64 = 1 << 10;
/// Bit 11, not-global: the translation is tagged with the current ASID.
const NG: u64 = 1 << 11;
/// Bit 53: privileged execute-never — EL1 may not fetch instructions from here.
const PXN: u64 = 1 << 53;
/// Bit 54: unprivileged execute-never — EL0 may not fetch instructions from here.
const UXN: u64 = 1 << 54;
/// Bit 59 of a *table* descriptor: PXN for everything beneath it.
const PXN_TABLE: u64 = 1 << 59;
/// Bit 60 of a *table* descriptor: UXN for everything beneath it.
const UXN_TABLE: u64 = 1 << 60;
/// `APTable[0]` (bit 61): no EL0 access below this table, whatever the leaves say.
const AP_TABLE_NO_EL0: u64 = 1 << 61;
/// `APTable[1]` (bit 62): no write access below this table.
const AP_TABLE_NO_WRITE: u64 = 1 << 62;
/// Output address, bits `[47:12]`. 52-bit output needs `FEAT_LPA` and a different
/// encoding; `Arch::PHYS_ADDR_BITS` says 48 for the same reason.
const ADDR_MASK: u64 = 0x0000_ffff_ffff_f000;

// --- MAIR_EL1 -------------------------------------------------------------------

/// `MAIR_EL1` index for Device-nGnRnE: non-gathering, non-reordering, no early write
/// acknowledgement. The strictest device type there is, and the right default for
/// registers whose behaviour depends on exactly which accesses reach them.
const ATTR_DEVICE_NGNRNE: u64 = 0;
/// Index for Normal memory, inner and outer write-back, read- and write-allocate.
const ATTR_NORMAL_WB: u64 = 1;
/// Index for Normal non-cacheable — memory shared with a non-coherent master.
const ATTR_NORMAL_NC: u64 = 2;
/// Index for Device-nGnRE: gathering still forbidden, but early acknowledgement
/// allowed. Nothing selects it yet; it is defined so that a driver that wants it does
/// not have to re-lay out `MAIR_EL1`.
const ATTR_DEVICE_NGNRE: u64 = 3;

/// The `MAIR_EL1` value the four indices above describe, one byte each.
const MAIR: u64 = 0x00 | (0xff << 8) | (0x44 << 16) | (0x04 << 24);

// --- Entry ----------------------------------------------------------------------

/// One VMSAv8-64 stage-1 translation table descriptor.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Entry(u64);

impl Entry {
    /// The raw descriptor word, for debugging and for the table writes in this module.
    pub const fn bits(self) -> u64 {
        self.0
    }
}

impl PageTableEntry for Entry {
    fn empty() -> Self {
        Entry(0)
    }

    fn is_present(self) -> bool {
        self.0 & VALID != 0
    }

    fn is_leaf(self, level: u8) -> bool {
        if !self.is_present() {
            return false;
        }
        if level == 0 {
            // Arm L3: `0b11` is a page. `0b01` at this level is not a block, it is
            // reserved and faults.
            return self.0 & TABLE_OR_PAGE != 0;
        }
        // Arm L1 and L2: `0b01` is a block, `0b11` points at the next table. At Arm
        // L0 (our level 3) there is no block at a 4 KiB granule, so a descriptor with
        // bit 1 clear is malformed rather than a leaf; reporting "not a leaf" is the
        // answer that keeps the walker's shape, and nothing in this port writes one.
        self.0 & TABLE_OR_PAGE == 0 && Aarch64::leaf_allowed(level)
    }

    fn address(self) -> PhysAddr {
        PhysAddr::new(self.0 & ADDR_MASK)
    }

    fn flags(self, level: u8) -> PageFlags {
        if !self.is_present() {
            return PageFlags::empty();
        }
        if !self.is_leaf(level) {
            return self.table_flags();
        }

        // A present leaf is readable; AArch64 has no read-disable.
        let mut f = PageFlags::READ;
        if self.0 & AP_RO == 0 {
            f = f.union(PageFlags::WRITE);
        }
        // Execution is read from whichever execute-never bit applies to the exception
        // level this mapping is *for*, which is the same rule `leaf` encodes with.
        if self.0 & AP_EL0 != 0 {
            f = f.union(PageFlags::USER);
            if self.0 & UXN == 0 {
                f = f.union(PageFlags::EXECUTE);
            }
        } else if self.0 & PXN == 0 {
            f = f.union(PageFlags::EXECUTE);
        }
        if self.0 & NG == 0 {
            f = f.union(PageFlags::GLOBAL);
        }
        match (self.0 >> ATTR_INDX_SHIFT) & 0b111 {
            ATTR_DEVICE_NGNRNE | ATTR_DEVICE_NGNRE => f = f.union(PageFlags::DEVICE),
            ATTR_NORMAL_NC => f = f.union(PageFlags::NO_CACHE),
            _ => {}
        }
        f
    }

    fn table(table: PhysAddr, _level: u8) -> Self {
        debug_assert!(table.is_aligned(<Aarch64 as Arch>::PAGE_SIZE as u64));
        // All four of NSTable, APTable, UXNTable and PXNTable left clear: permissions
        // on AArch64 intersect down the tree, so restricting here would cap every leaf
        // beneath and the leaf is where the intent lives.
        Entry((table.raw() & ADDR_MASK) | VALID | TABLE_OR_PAGE)
    }

    fn leaf(frame: PhysAddr, flags: PageFlags, level: u8) -> Self {
        let mut v = (frame.raw() & ADDR_MASK) | VALID | AF;
        // Arm L3 spells a leaf `0b11`; the block descriptors above it spell it `0b01`.
        if level == 0 {
            v |= TABLE_OR_PAGE;
        }

        let attr = if flags.contains(PageFlags::DEVICE) {
            ATTR_DEVICE_NGNRNE
        } else if flags.contains(PageFlags::NO_CACHE) {
            ATTR_NORMAL_NC
        } else {
            ATTR_NORMAL_WB
        };
        v |= attr << ATTR_INDX_SHIFT;
        // Shareability is ignored for Device memory and must be inner shareable for
        // Normal memory if TLB and cache maintenance from another CPU is to reach it.
        if !flags.contains(PageFlags::DEVICE) {
            v |= SH_INNER;
        }

        if flags.contains(PageFlags::USER) {
            v |= AP_EL0;
        }
        if !flags.contains(PageFlags::WRITE) {
            v |= AP_RO;
        }

        // Two execute-never bits, and the one that is *not* asked about is always set:
        // EL1 must not execute user memory, and EL0 must not execute kernel memory.
        // Both directions are privilege escalations that cost nothing to close here.
        if flags.contains(PageFlags::USER) {
            v |= PXN;
            if !flags.contains(PageFlags::EXECUTE) {
                v |= UXN;
            }
        } else {
            v |= UXN;
            if !flags.contains(PageFlags::EXECUTE) {
                v |= PXN;
            }
        }

        if !flags.contains(PageFlags::GLOBAL) {
            v |= NG;
        }
        Entry(v)
    }
}

impl Entry {
    /// What a *table* descriptor permits beneath it.
    ///
    /// Separate from the leaf decode because the bits are different ones: a table
    /// descriptor carries restrictions (`APTable`, `UXNTable`, `PXNTable`) rather than
    /// grants, so the neutral answer is "everything, minus whatever is restricted".
    fn table_flags(self) -> PageFlags {
        let mut f = PageFlags::READ;
        if self.0 & AP_TABLE_NO_WRITE == 0 {
            f = f.union(PageFlags::WRITE);
        }
        let user = self.0 & AP_TABLE_NO_EL0 == 0;
        if user {
            f = f.union(PageFlags::USER);
            if self.0 & UXN_TABLE == 0 {
                f = f.union(PageFlags::EXECUTE);
            }
        } else if self.0 & PXN_TABLE == 0 {
            f = f.union(PageFlags::EXECUTE);
        }
        f
    }
}

// --- HasPageTables --------------------------------------------------------------

impl HasPageTables for Aarch64 {
    type Entry = Entry;

    fn index_bits(_level: u8) -> u8 {
        // Uniform at a 4 KiB granule: 48 bits of virtual address are 12 of offset and
        // four indices of nine. The 16 KiB and 64 KiB granules are not uniform, and
        // are also not configured here.
        9
    }

    fn leaf_allowed(level: u8) -> bool {
        // Arm L3 pages, Arm L2 2 MiB blocks, Arm L1 1 GiB blocks. Arm L0 has no block
        // descriptor at this granule.
        level <= 2
    }

    fn is_canonical(addr: usize) -> bool {
        // 48-bit addresses split at the top: all-zero selects TTBR0 and all-one
        // selects TTBR1. Anything between is a translation fault rather than a wrap,
        // exactly as on x86-64, and is worth catching at the mapping call.
        let top = addr >> 47;
        top == 0 || top == 0x1_ffff
    }

    unsafe fn set_root(root: PhysAddr) {
        // SAFETY: the caller guarantees `root` names a table that maps the running
        // code and stack. `dsb ishst` publishes the table's contents to the walker
        // before it can be reached; the `isb` after the `msr` is what makes the new
        // root apply to subsequent instructions rather than at some later
        // context-synchronising event; the `tlbi` then drops translations cached from
        // the outgoing table, which would otherwise shadow the new one.
        unsafe {
            core::arch::asm!(
                "dsb ishst",
                "msr ttbr0_el1, {r}",
                "isb",
                "tlbi vmalle1is",
                "dsb ish",
                "isb",
                r = in(reg) root.raw(),
                options(nostack, preserves_flags)
            );
        }
    }

    fn root() -> PhysAddr {
        let ttbr: u64;
        // SAFETY: reading TTBR0_EL1 is permitted at EL1 and has no side effects.
        unsafe {
            core::arch::asm!(
                "mrs {}, ttbr0_el1",
                out(reg) ttbr,
                options(nomem, nostack, preserves_flags)
            );
        }
        // BADDR is bits [47:1]; bit 0 is CnP and bits [63:48] are the ASID, neither of
        // which is part of the address.
        PhysAddr::new(ttbr & 0x0000_ffff_ffff_fffe)
    }

    unsafe fn flush_tlb(addr: Option<usize>) {
        // The barriers here are not decoration, unlike x86's `invlpg`. `tlbi` is
        // issued to the memory system and completes asynchronously: without the
        // leading `dsb ishst` the walker may still be looking at the old descriptor
        // when the invalidate is broadcast, and without the trailing `dsb ish; isb`
        // the very next instruction may still use a translation the invalidate was
        // supposed to remove. Both windows are small, which is what makes them
        // vicious.
        match addr {
            Some(va) => {
                // VAAE1IS: by address, all ASIDs, inner shareable. The operand is the
                // virtual address shifted right by 12, not the address itself.
                //
                // SAFETY: the caller is responsible for the table writes this
                // publishes. `tlbi` is architecturally permitted at EL1 and affects
                // only cached translations.
                unsafe {
                    core::arch::asm!(
                        "dsb ishst",
                        "tlbi vaae1is, {v}",
                        "dsb ish",
                        "isb",
                        v = in(reg) (va as u64) >> 12,
                        options(nostack, preserves_flags)
                    );
                }
            }
            None => {
                // SAFETY: as above. VMALLE1IS drops every stage-1 EL1&0 translation on
                // every CPU in the inner shareable domain, which is always safe and
                // merely expensive.
                unsafe {
                    core::arch::asm!(
                        "dsb ishst",
                        "tlbi vmalle1is",
                        "dsb ish",
                        "isb",
                        options(nostack, preserves_flags)
                    );
                }
            }
        }
    }
}

// --- static table storage -------------------------------------------------------

/// One 4 KiB page: 512 descriptors, or 4 KiB of anything else.
///
/// The alignment is the architectural requirement for a translation table at this
/// granule, and it is also what makes a `Page`'s address usable as a frame address.
#[repr(C, align(4096))]
struct Page(UnsafeCell<[u64; 512]>);

// SAFETY: the invariant is that every write to a `Page` in this module happens either
// before the MMU is enabled, on the one CPU that is running, or from `selftest`, which
// `kmain` calls once on that same CPU before any other execution context exists. No
// two writers can therefore exist at once. A `Page` is never handed out as a `&mut`;
// all access goes through raw pointers derived from the `UnsafeCell`, so no two
// references to the same descriptor are ever live. When SMP arrives the tables move
// behind the frame allocator and a lock, and this impl goes away with them.
unsafe impl Sync for Page {}

/// A zeroed page, which is also an all-invalid table.
const EMPTY: Page = Page(UnsafeCell::new([0; 512]));

/// Index of the root table — Arm L0, our level 3.
const T_ROOT: usize = 0;
/// Index of the table covering the low 512 GiB — Arm L1, our level 2.
const T_LOW: usize = 1;
/// Index of the table of 2 MiB blocks covering the first GiB of RAM — our level 1.
const T_RAM: usize = 2;
/// First table available to [`map_page`] for intermediate levels. Everything below is
/// part of the boot map and must not be handed out.
const T_SCRATCH: usize = 3;
/// Four spare tables: enough for the two independent branches the selftest maps. Each
/// branch diverges at a level-2 entry and so needs a fresh level-1 table and a fresh
/// level-0 table beneath it.
const TABLES_LEN: usize = T_SCRATCH + 4;

/// Every translation table this port owns.
///
/// Statically allocated because the tables must exist before there is an allocator: the
/// frame allocator needs a memory map, and on this machine the memory map needs a
/// device-tree parser, neither of which can run before the MMU does.
static TABLES: [Page; TABLES_LEN] = [EMPTY; TABLES_LEN];

/// How many 2 MiB blocks of the boot map are broken down into 4 KiB pages so that the
/// image's section boundaries and its stack guard page can be expressed at all.
///
/// Four blocks is 8 MiB, against an image of some eighty kilobytes; the margin is for
/// an instrumented build, not for a plan. An image that outgrows it is not a boot
/// failure — the blocks past the fourth simply stay 2 MiB and stay RWX — but it is a
/// silent loss of the split, which is why [`selftest`] checks the last page of the
/// image rather than trusting this number.
const IMAGE_TABLES_LEN: usize = 4;

/// Level-0 tables refining the blocks the kernel image lives in. Separate from
/// [`TABLES`] because they belong to the boot map and must never be handed to
/// [`alloc_table`], which is the pool [`map_page`] draws from.
static IMAGE_TABLES: [Page; IMAGE_TABLES_LEN] = [EMPTY; IMAGE_TABLES_LEN];

/// The frame [`selftest`] aliases. Its contents mean nothing; that two virtual
/// addresses reach the same bytes is the entire point.
static ALIAS_FRAME: Page = EMPTY;

/// Next unused entry of [`TABLES`].
static NEXT_TABLE: AtomicUsize = AtomicUsize::new(T_SCRATCH);

/// The address of a page. With the kernel identity-mapped this is both its virtual and
/// its physical address.
fn page_addr(p: &Page) -> u64 {
    p.0.get() as usize as u64
}

/// Take an unused table from the static pool, or `None` when there are none left.
fn alloc_table() -> Option<&'static Page> {
    let i = NEXT_TABLE.fetch_add(1, Ordering::Relaxed);
    TABLES.get(i)
}

/// The pointer through which the kernel reaches physical address `pa`.
///
/// Correct only while the kernel is identity-mapped, which it is for all of Phase 1.
/// This is the single assumption in this module that moving to the high half has to
/// revisit, and it is deliberately one function rather than a scattering of casts.
fn phys_to_ptr(pa: PhysAddr) -> *mut u64 {
    pa.raw() as usize as *mut u64
}

/// Read descriptor `index` from the table at `table`.
///
/// # Safety
/// `table` must point at a live 512-entry table and `index` must be below 512.
unsafe fn read_entry(table: *mut u64, index: usize) -> Entry {
    // SAFETY: the caller guarantees the table and the bound, so the offset is inside
    // the same allocation. Volatile because the page table walker is another observer
    // of these words and the compiler must not invent or elide accesses to them.
    Entry(unsafe { read_volatile(table.add(index)) })
}

/// Write descriptor `index` of the table at `table`.
///
/// # Safety
/// `table` must point at a live 512-entry table, `index` must be below 512, and no
/// translation that the CPU may currently be using may be invalidated by the write
/// without a following [`Aarch64::flush_tlb`].
unsafe fn write_entry(table: *mut u64, index: usize, e: Entry) {
    // SAFETY: as for `read_entry`; the caller owns the ordering obligation.
    unsafe { write_volatile(table.add(index), e.bits()) };
}

// --- a self-contained walker ----------------------------------------------------

/// Map one 4 KiB page, allocating intermediate tables from the static pool.
///
/// This duplicates what `mm::paged` does generically, and does so deliberately: `arch`
/// may not depend on a `core` unit, so the code that brings the MMU up cannot call the
/// shared walker that will later run on top of it. It is kept to the one case it needs
/// — a single page, into a table that does not already map it.
///
/// # Safety
/// The MMU must be on with the boot identity map installed, so that `phys_to_ptr`
/// holds, and no other CPU may be walking the tables being edited.
unsafe fn map_page(va: usize, pa: PhysAddr, flags: PageFlags) -> Result<(), MapError> {
    if !Aarch64::is_canonical(va) {
        return Err(MapError::NotCanonical);
    }
    let page = <Aarch64 as Arch>::PAGE_SIZE;
    if va % page != 0 || !pa.is_aligned(page as u64) {
        return Err(MapError::Misaligned);
    }
    if pa.raw() & !ADDR_MASK != 0 {
        return Err(MapError::BadPhysAddr);
    }

    let mut table = phys_to_ptr(Aarch64::root());
    let mut level = <Aarch64 as HasMmu>::LEVELS - 1;
    loop {
        let index = level_index::<Aarch64>(va, level);
        // SAFETY: `table` came from the root register or from a table descriptor this
        // module wrote, and `level_index` masks to `index_bits`, so the index is below
        // 512.
        let e = unsafe { read_entry(table, index) };

        if level == 0 {
            if e.is_present() {
                return Err(MapError::AlreadyMapped);
            }
            // SAFETY: same table and bound as the read above. Nothing was mapped here,
            // so no live translation is being changed and the caller's `flush_tlb`
            // covers the walker's own negative caching.
            unsafe { write_entry(table, index, Entry::leaf(pa, flags, 0)) };
            return Ok(());
        }

        let next = if !e.is_present() {
            let fresh = alloc_table().ok_or(MapError::OutOfFrames)?;
            let addr = PhysAddr::new(page_addr(fresh));
            // SAFETY: as above; the table is statically allocated, zeroed, and not yet
            // referenced by anything.
            unsafe { write_entry(table, index, Entry::table(addr, level)) };
            addr
        } else if e.is_leaf(level) {
            // Splitting a block is the shared walker's job, not this one's.
            return Err(MapError::WouldSplit);
        } else {
            e.address()
        };

        table = phys_to_ptr(next);
        level -= 1;
    }
}

/// The level of the leaf that maps `va` in the live tables, or `None` if nothing does.
///
/// `translate` answers *whether* an address is mapped, by asking the hardware; this
/// answers *how coarsely*, which the hardware will not tell you — `PAR_EL1` reports a
/// physical address whether it came from a 4 KiB page or a 1 GiB block. The granularity
/// is the thing a permission split depends on, so it is worth being able to see.
///
/// Read-only: it follows table descriptors this module wrote and never edits one.
fn leaf_level(va: usize) -> Option<u8> {
    let mut table = phys_to_ptr(Aarch64::root());
    let mut level = <Aarch64 as HasMmu>::LEVELS - 1;
    loop {
        let index = level_index::<Aarch64>(va, level);
        // SAFETY: `table` is the root register's value on the first pass and the
        // address out of a table descriptor thereafter, so it names a live 512-entry
        // table; `level_index` masks to `index_bits`, so `index` is below 512.
        let e = unsafe { read_entry(table, index) };
        if !e.is_present() {
            return None;
        }
        if e.is_leaf(level) {
            return Some(level);
        }
        if level == 0 {
            // A level-0 descriptor that is present and not a leaf is malformed; nothing
            // in this port writes one, and reporting "unmapped" beats descending into
            // whatever address it holds.
            return None;
        }
        table = phys_to_ptr(e.address());
        level -= 1;
    }
}

// --- bringing the MMU up --------------------------------------------------------

/// `SCTLR_EL1.M`, `.C` and `.I`: translation, the data cache and the instruction cache.
const SCTLR_ENABLE: u64 = (1 << 0) | (1 << 2) | (1 << 12);

/// Build the boot identity map and turn the MMU on.
///
/// Called from `_start` rather than from `kmain`, so that the whole kernel — including
/// the early console's first write — runs translated. That is also why it cannot
/// report anything: there is no console yet. A mistake here shows up as an exception
/// through the vector table this function installs first, or, if the map does not
/// cover the instruction after `SCTLR_EL1.M` is set, as a machine that stops dead.
///
/// # Safety
/// Called exactly once, from `_start`, at EL1, with interrupts masked, `.bss` zeroed
/// and a stack established.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn aarch64_mmu_init() {
    // Before anything else, so that a fault from the code below is reported rather
    // than fetched from whatever `VBAR_EL1` happened to contain. `interrupt_selftest`
    // installs the same table again later, which the documented contract permits.
    //
    // SAFETY: this is the first thing to run after the stack is established, at EL1
    // with all four DAIF bits masked, and no interrupt source has been enabled.
    unsafe { crate::exception::install_vectors() };

    let root = phys_to_ptr(PhysAddr::new(page_addr(&TABLES[T_ROOT])));
    let low = PhysAddr::new(page_addr(&TABLES[T_LOW]));
    let ram = PhysAddr::new(page_addr(&TABLES[T_RAM]));

    // Everything below is global: these translations belong to the kernel and must
    // survive an address-space switch rather than being tagged with an ASID.
    let device = PageFlags::KERNEL_DATA | PageFlags::DEVICE | PageFlags::GLOBAL;
    let normal = PageFlags::KERNEL_DATA | PageFlags::EXECUTE | PageFlags::GLOBAL;

    // SAFETY: `root`, `low` and `ram` are distinct statically allocated, 4 KiB aligned,
    // zeroed tables; the indices are constants below 512; the MMU is off so nothing is
    // walking them; and this runs on the only CPU that is out of its parking loop.
    unsafe {
        // The low 512 GiB of the address space hangs off entry 0 of the root.
        write_entry(root, 0, Entry::table(low, 3));
        // One 1 GiB Device block covering every MMIO window on this machine.
        write_entry(phys_to_ptr(low), 0, Entry::leaf(PhysAddr::new(0), device, 2));
        // RAM gets 2 MiB blocks rather than a second 1 GiB block, because the
        // permission split the image needs later is a refinement of these.
        write_entry(phys_to_ptr(low), 1, Entry::table(ram, 2));
    }

    let ram_ptr = phys_to_ptr(ram);
    for i in 0..512u64 {
        let pa = PhysAddr::new(RAM_BASE + i * BLOCK);
        // SAFETY: as above — `ram` is a zeroed static table, `i` is below 512, and
        // each block address is 2 MiB aligned by construction.
        unsafe { write_entry(ram_ptr, i as usize, Entry::leaf(pa, normal, 1)) };
    }

    // Now break the blocks the image sits in down into 4 KiB pages, mapping exactly
    // the same frames with exactly the same permissions. Nothing about the map's
    // meaning changes; what changes is that a later pass can say something different
    // about one page of it. See the module comment.
    for (n, table) in image_blocks().zip(IMAGE_TABLES.iter()) {
        let leaves = phys_to_ptr(PhysAddr::new(page_addr(table)));
        let base = RAM_BASE + n * BLOCK;
        for j in 0..512u64 {
            let pa = PhysAddr::new(base + j * <Aarch64 as Arch>::PAGE_SIZE as u64);
            // SAFETY: `table` is a distinct zeroed static page not reachable from any
            // other descriptor yet, `j` is below 512, and the address is 4 KiB aligned
            // by construction. The MMU is still off, so nothing is walking this.
            unsafe { write_entry(leaves, j as usize, Entry::leaf(pa, normal, 0)) };
        }
        let addr = PhysAddr::new(page_addr(table));
        // SAFETY: as above. The block entry being overwritten described the same 2 MiB
        // the table just filled describes, so no translation changes; the MMU is off,
        // so there is nothing cached to invalidate.
        unsafe { write_entry(ram_ptr, n as usize, Entry::table(addr, 1)) };
    }

    // SAFETY: the tables above are complete and describe the code, stack, static data
    // and MMIO this CPU is using, all at their current addresses, so the instruction
    // after the enable is fetchable and the stack stays where it is. The sequence is
    // the architecturally required one: publish the tables with `dsb`, program the
    // three registers, synchronise, drop everything cached from before the switch,
    // then set `SCTLR_EL1.M` and synchronise again so the next fetch is translated.
    //
    // `.C` is set in the same write. The caches held nothing before this point: with
    // the MMU off, data accesses at EL1 are Device-nGnRnE and go straight to memory.
    // That is an assumption about the loader, not a proof — a boot protocol that
    // hands over with dirty lines in the cache needs an invalidate by set/way here,
    // which is why the Linux arm64 boot protocol requires the loader to have cleaned
    // them and why this port states the same requirement.
    unsafe {
        core::arch::asm!(
            "dsb ishst",
            "msr mair_el1, {mair}",
            "msr tcr_el1, {tcr}",
            "msr ttbr0_el1, {ttbr}",
            "isb",
            "tlbi vmalle1",
            "ic iallu",
            "dsb nsh",
            "isb",
            "mrs {tmp}, sctlr_el1",
            "orr {tmp}, {tmp}, {bits}",
            "msr sctlr_el1, {tmp}",
            "isb",
            mair = in(reg) MAIR,
            tcr = in(reg) tcr_el1(),
            ttbr = in(reg) page_addr(&TABLES[T_ROOT]),
            bits = in(reg) SCTLR_ENABLE,
            tmp = out(reg) _,
            options(nostack, preserves_flags)
        );
    }
}

/// Physical address of the first byte of RAM on QEMU's `virt` machine.
///
/// Hardcoded for the same reason the PL011's address is, and with the same remedy: the
/// device tree says where RAM is, and nothing can read it yet.
const RAM_BASE: u64 = 0x4000_0000;

/// Bytes one level-1 leaf maps — 2 MiB, the block size the RAM table is built from.
const BLOCK: u64 = 2 * 1024 * 1024;

/// Indices into the level-1 RAM table of the blocks the kernel image occupies.
///
/// Computed from the image's own extent rather than assumed to be one block, so that an
/// image which eventually straddles a 2 MiB boundary gets both halves refined instead
/// of half a split. Clamped to the table's 512 entries; a range whose start is past its
/// end is empty and refines nothing, which is the right answer for an image linked
/// outside RAM.
fn image_blocks() -> core::ops::Range<u64> {
    let (start, end) = crate::image_range();
    let first = start.saturating_sub(RAM_BASE) / BLOCK;
    let last = end.saturating_sub(RAM_BASE).div_ceil(BLOCK).min(512);
    first..last
}

/// The `TCR_EL1` value for a 48-bit TTBR0 address space at a 4 KiB granule.
fn tcr_el1() -> u64 {
    /// 64 − 48: a 48-bit TTBR0 region, which starts translation at Arm L0 and gives
    /// the four levels `HasMmu::LEVELS` advertises.
    const T0SZ: u64 = 16;
    /// Table walks for TTBR0 are cacheable, write-back, read-write-allocate, inner and
    /// outer. Walking uncached would work and would be dramatically slower.
    const IRGN0_WBWA: u64 = 0b01 << 8;
    const ORGN0_WBWA: u64 = 0b01 << 10;
    /// Walks are inner shareable, matching the Normal memory the tables live in.
    const SH0_INNER: u64 = 0b11 << 12;
    /// `TG0 = 0b00`: a 4 KiB granule for TTBR0.
    const TG0_4K: u64 = 0b00 << 14;
    /// TTBR1 is sized but disabled: the kernel is in the low half today, and leaving
    /// walks enabled for a region with no table means a stray high address walks
    /// whatever `TTBR1_EL1` happens to hold instead of faulting cleanly.
    const T1SZ: u64 = 16 << 16;
    const EPD1: u64 = 1 << 23;
    /// `TG1 = 0b10` is 4 KiB — the TTBR1 granule field is encoded differently from
    /// TTBR0's, which is a genuine trap in the architecture and not a typo here.
    const TG1_4K: u64 = 0b10 << 30;

    T0SZ | IRGN0_WBWA | ORGN0_WBWA | SH0_INNER | TG0_4K | T1SZ | EPD1 | TG1_4K | (ips() << 32)
}

/// `TCR_EL1.IPS`: the intermediate physical address size, which must come from the
/// implementation rather than from a constant.
///
/// Capped at the 48-bit encoding because the descriptor format above puts the output
/// address in bits `[47:12]`; claiming 52 bits would promise an encoding this port
/// does not write.
fn ips() -> u64 {
    let mmfr0: u64;
    // SAFETY: ID_AA64MMFR0_EL1 is a read-only identification register, readable at EL1
    // with no side effects.
    unsafe {
        core::arch::asm!(
            "mrs {}, id_aa64mmfr0_el1",
            out(reg) mmfr0,
            options(nomem, nostack, preserves_flags)
        );
    }
    let parange = mmfr0 & 0xf;
    if parange > 5 { 5 } else { parange }
}

/// `SCTLR_EL1`, read back so that the selftest can say whether translation is actually
/// on rather than assuming it.
fn sctlr_el1() -> u64 {
    let v: u64;
    // SAFETY: reading SCTLR_EL1 is permitted at EL1 and has no side effects.
    unsafe {
        core::arch::asm!(
            "mrs {}, sctlr_el1",
            out(reg) v,
            options(nomem, nostack, preserves_flags)
        );
    }
    v
}

/// Ask the hardware to translate `va` as a privileged read, and report what it said.
///
/// `AT S1E1R` runs the address through the same translation the CPU would use, and
/// `PAR_EL1` reports either the resulting physical address or a fault. It is the one
/// answer in this file that does not depend on any of the code in this file being
/// right.
fn translate(va: usize) -> Option<PhysAddr> {
    let par: u64;
    // SAFETY: `AT S1E1R` is permitted at EL1. It performs a translation table walk and
    // writes PAR_EL1; it never accesses the memory it translates and cannot fault, so
    // an unmapped address is reported in PAR_EL1.F rather than taken as an exception.
    // The `isb` is required between the `at` and the `mrs` for the result to be
    // visible.
    unsafe {
        core::arch::asm!(
            "at s1e1r, {v}",
            "isb",
            "mrs {p}, par_el1",
            v = in(reg) va as u64,
            p = out(reg) par,
            options(nostack, preserves_flags)
        );
    }
    if par & 1 != 0 {
        return None;
    }
    Some(PhysAddr::new((par & ADDR_MASK) | (va as u64 & 0xfff)))
}

// --- the selftest ---------------------------------------------------------------

/// First virtual address of the alias pair: 256 GiB.
///
/// Chosen far above any physical address this machine has. With the MMU off, or with
/// translation that did not actually happen, an access here would reach an unassigned
/// physical address and take an external abort — so the fact that the write below
/// completes at all is already evidence.
const VA_A: usize = 0x0000_0040_0000_0000;
/// Second virtual address of the pair: 320 GiB. It takes a different level-2 entry
/// from [`VA_A`], so below the shared top of the tree the two walks have no table in
/// common — which is what makes reaching the same frame through both mean something.
const VA_B: usize = 0x0000_0050_0000_0000;

/// Prove that translation is real, and report what was actually observed.
///
/// The demonstration is an alias: one physical frame mapped at two unrelated virtual
/// addresses, written through one and read back through the other. That is impossible
/// without translation — the two addresses differ, so with the MMU off they would name
/// different memory, and in fact would name no memory at all on this machine.
pub fn selftest(c: &dyn EarlyConsole) -> bool {
    if sctlr_el1() & 1 == 0 {
        c.write_str("MMU off");
        return false;
    }
    c.write_str("MMU on");

    if !encoding_round_trips() {
        c.write_str(", encoding does not round-trip");
        return false;
    }

    // The image must be mapped one 4 KiB page at a time, or `image_sections`' section
    // boundaries and its guard page describe something the tables cannot express. Both
    // ends are checked because the refinement is per 2 MiB block and an image that grew
    // past the tables reserved for it would lose only its tail.
    let (img_start, img_end) = crate::image_range();
    match (
        leaf_level(img_start as usize),
        leaf_level(img_end.saturating_sub(1) as usize),
    ) {
        (Some(0), Some(0)) => c.write_str(", image mapped at 4 KiB"),
        _ => {
            c.write_str(", image not mapped at 4 KiB");
            return false;
        }
    }

    let frame = PhysAddr::new(page_addr(&ALIAS_FRAME));
    let flags = PageFlags::KERNEL_DATA | PageFlags::GLOBAL;
    for va in [VA_A, VA_B] {
        // SAFETY: the MMU is on with the boot identity map installed, this is the only
        // CPU out of its parking loop, and `kmain` calls this once, so nothing else is
        // walking or editing the tables.
        if let Err(e) = unsafe { map_page(va, frame, flags) } {
            c.write_str(", map failed: ");
            c.write_str(map_error(e));
            return false;
        }
    }
    // SAFETY: the writes above added translations where there were none. The
    // architecture permits a walker to have cached the absence, so the invalidate is
    // not optional; `flush_tlb` carries the barriers that make the new descriptors
    // visible to it first.
    unsafe { Aarch64::flush_tlb(None) };

    // Ask the hardware what it thinks, before trusting any pointer. This distinguishes
    // "the tables are right" from "the access happened to work".
    match (translate(VA_A), translate(VA_B)) {
        (Some(a), Some(b)) if a == frame && b == frame => {}
        _ => {
            c.write_str(", AT disagrees");
            return false;
        }
    }

    let a = VA_A as *mut u64;
    let b = VA_B as *mut u64;
    let direct = ALIAS_FRAME.0.get().cast::<u64>();

    // Write through one virtual address, observe through the other. Distinct patterns
    // per direction so that a stale or zeroed read cannot pass.
    const PATTERN_A: u64 = 0x4b69_6e54_616e_6531;
    const PATTERN_B: u64 = 0xa5a5_5a5a_dead_beef;

    // SAFETY: `a` and `b` are mapped, 8-byte aligned, Normal write-back memory backing
    // `ALIAS_FRAME`, which is a live static of 4 KiB. Volatile so that the compiler
    // cannot fold the store into the load through the other pointer — it has no reason
    // to believe the three pointers alias, and that reasoning is exactly what is being
    // tested.
    unsafe { write_volatile(a, PATTERN_A) };
    // SAFETY: as above, reading the word just written through the other mapping.
    if unsafe { read_volatile(b) } != PATTERN_A {
        c.write_str(", alias not observed");
        return false;
    }

    // And the other way, into a different word, checked against the identity mapping
    // of the same frame — which pins the alias to this particular physical page rather
    // than merely to some shared page.
    // SAFETY: word 1 of the same live 4 KiB frame, reached through the second alias.
    unsafe { write_volatile(b.add(1), PATTERN_B) };
    // SAFETY: word 1 of `ALIAS_FRAME` itself, through its identity mapping.
    if unsafe { read_volatile(direct.add(1)) } != PATTERN_B {
        c.write_str(", frame not the one mapped");
        return false;
    }

    c.write_str(", ");
    write_hex(c, VA_A as u64);
    c.write_str(" and ");
    write_hex(c, VA_B as u64);
    c.write_str(" alias phys ");
    write_hex(c, frame.raw());
    true
}

/// Check that the descriptor encoding survives a round trip through [`Entry`].
///
/// This runs on the machine rather than in a host test because `arch` is only ever
/// compiled for its own target — there is nowhere else to run it. It is worth running:
/// the shared walker reads permissions back out of entries it did not write, and the
/// AP/PXN/UXN translation is the part of this file most likely to be subtly wrong in a
/// way that a two-flag boot map never exercises.
fn encoding_round_trips() -> bool {
    /// One flag set per interesting corner: the three kernel sets, the two memory
    /// types, the global bit, and both user cases — where the execute flag is read
    /// back out of a *different* hardware bit than in the kernel cases.
    const CASES: [PageFlags; 8] = [
        PageFlags::KERNEL_TEXT,
        PageFlags::KERNEL_RODATA,
        PageFlags::KERNEL_DATA,
        PageFlags::KERNEL_DATA.union(PageFlags::GLOBAL),
        PageFlags::KERNEL_DATA.union(PageFlags::DEVICE),
        PageFlags::KERNEL_DATA.union(PageFlags::NO_CACHE),
        PageFlags::KERNEL_TEXT.union(PageFlags::USER),
        PageFlags::KERNEL_DATA.union(PageFlags::USER),
    ];

    let frame = PhysAddr::new(0x4321_0000);
    for f in CASES {
        for level in 0..=2u8 {
            let e = Entry::leaf(frame, f, level);
            if !e.is_present() || !e.is_leaf(level) || e.address() != frame {
                return false;
            }
            // Without AF the first access to this mapping would fault, and nothing
            // else in this file would notice.
            if e.bits() & AF == 0 {
                return false;
            }
            if e.flags(level) != f {
                return false;
            }
        }
    }

    // A table descriptor is not a leaf at any level where it can appear, and it is
    // permissive, because AArch64 intersects permissions down the tree.
    for level in 1..=3u8 {
        let t = Entry::table(frame, level);
        if !t.is_present() || t.is_leaf(level) || t.address() != frame {
            return false;
        }
    }

    // Built at a non-leaf level, which is where a table descriptor belongs.
    let t = Entry::table(frame, 2);
    let permissive = PageFlags::KERNEL_DATA | PageFlags::EXECUTE | PageFlags::USER;
    if t.flags(2) != permissive {
        return false;
    }

    // The same bit pattern at the leaf level is a page, not a table. This is the
    // collision `is_leaf` takes a level to resolve, and it is the assertion that would
    // catch the level numbering being inverted.
    if !t.is_leaf(0) {
        return false;
    }

    !Entry::empty().is_present()
        && Aarch64::is_canonical(0)
        && Aarch64::is_canonical(usize::MAX)
        && !Aarch64::is_canonical(1 << 47)
}

/// A short name for a mapping failure, for the one line the banner has room for.
fn map_error(e: MapError) -> &'static str {
    match e {
        MapError::NotCanonical => "not canonical",
        MapError::Misaligned => "misaligned",
        MapError::AlreadyMapped => "already mapped",
        MapError::NotMapped => "not mapped",
        MapError::OutOfFrames => "out of tables",
        MapError::WouldSplit => "would split a block",
        MapError::BadPhysAddr => "bad physical address",
    }
}

/// Hexadecimal without leading zeros. The one in `exception` pads to 16 digits, which
/// is right for a register dump and wrong for three addresses on one banner line.
fn write_hex(c: &dyn EarlyConsole, v: u64) {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut buf = [0u8; 18];
    buf[0] = b'0';
    buf[1] = b'x';
    let mut n = 2;
    let mut seen = false;
    for i in 0..16 {
        let d = ((v >> (60 - i * 4)) & 0xf) as usize;
        seen |= d != 0;
        if seen {
            buf[n] = DIGITS[d];
            n += 1;
        }
    }
    if !seen {
        buf[n] = b'0';
        n += 1;
    }
    c.write_bytes(&buf[..n]);
}

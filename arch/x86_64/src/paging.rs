//! x86-64 page tables: the entry encoding, the geometry, and the bring-up proof.
//!
//! ## What this file owns
//!
//! The two halves of `hal::paging`'s contract for this architecture — [`Entry`], one
//! word of a table, and the [`hal::HasPageTables`] impl that states the geometry and
//! drives CR3 and the TLB. The tree walk that uses them belongs to `kernel/mm`, and
//! deliberately does not live here: an `arch` unit may not depend on a `core` unit, so
//! everything below that looks like a walker ([`map`], [`leaf_of`]) is the small,
//! self-contained one this module needs for its own bring-up and nothing more. That
//! restriction is useful rather than annoying — it means [`selftest`] proves the entry
//! encoding on its own, without the shared walker being correct.
//!
//! ## Level numbering
//!
//! `hal::paging` counts from the leaf: level 0 is the PT, 1 the PD, 2 the PDPT and 3
//! the PML4. Intel counts the other way and calls them PML4E/PDPTE/PDE/PTE. Every
//! number in this file is the `hal` one; the Intel name is given where a manual
//! reference is cited.
//!
//! ## Two bits that are not what they look like
//!
//! * **Bit 7** is PS ("this entry maps a huge page") at levels 1 and 2, and PAT at
//!   level 0, where there is nothing to be huge. Reading it without knowing the level
//!   turns a 4 KiB page with a non-default memory type into a 2 MiB page, which is why
//!   [`hal::PageTableEntry::is_leaf`] and `flags` take a level. It is reserved at
//!   level 3 and must be zero there.
//! * **Bit 63** is NX, and it is *reserved* unless `EFER.NXE` is set. Setting a
//!   reserved bit is not ignored: the next walk that reaches the entry raises #PF with
//!   the RSVD bit set in the error code, from an entry that looks perfectly valid.
//!   [`init`] enables NXE when CPUID says the CPU has NX, and [`Entry::leaf`] refuses
//!   to emit bit 63 until that has happened — so the failure mode of forgetting to
//!   call `init` is a mapping that is executable when it should not be, which is
//!   reported, rather than a reserved-bit fault, which is not.
//!
//! ## And one bit that is not in the tables at all
//!
//! **`CR0.WP`**. With it clear — which is how the CPU comes out of `boot.rs`, and how
//! this kernel ran until the selftest below was written — a supervisor-mode write to a
//! page whose R/W bit is clear *succeeds silently*. Clearing R/W is then not a
//! protection but a note to oneself, and every `.rodata` mapping a kernel makes is
//! decorative. This was not a theory: the read-only check reported `NO FAULT` on its
//! first run, which is exactly what an unenforced permission looks like and exactly
//! what a selftest that only checked for the absence of a crash would have called a
//! pass. [`init`] sets WP and reports it, and the check now observes the fault.
//!
//! ## Identity mapping, and what replaces it
//!
//! [`Table`] is a bare pointer because the kernel still runs on an identity map, so a
//! table's physical address and the address we write it through are the same number.
//! That is true for exactly as long as Phase 0 lasts; `mm::DirectMap` is what the type
//! turns into when the kernel moves to the high half.
//!
//! Reference: Intel SDM Vol. 3A, §4.5 (4-level paging), tables 4-14..4-19 for the
//! entry formats, §4.7 for the page-fault error code, and §4.1.4 for the `EFER.NXE`
//! interaction. CPUID leaf 0x8000_0001 is SDM Vol. 2A, `CPUID`, and AMD APM Vol. 3
//! appendix E.

use crate::serial::{write_dec, write_hex};
use crate::{X86_64, interrupt};
use core::arch::asm;
use core::arch::x86_64::__cpuid;
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU8, AtomicU32, AtomicU64, AtomicUsize, Ordering, compiler_fence};
use hal::paging::{HasPageTables, MapError, PageFlags, PageTableEntry, level_index, level_size};
use hal::{Arch, EarlyConsole, HasMmu, PhysAddr};

// This module is compiled only for x86-64, where `usize` is exactly the width of a
// physical address register. Every `usize`/`u64` conversion below is therefore
// lossless in both directions; this turns that from an assumption into a build
// failure if the module is ever pulled into a narrower target.
const _: () = assert!(core::mem::size_of::<usize>() == 8);

/// Bits 12..=51 of an entry: the physical address it names.
///
/// The architecture permits up to 52 physical address bits with 4-level paging; a CPU
/// with fewer treats the excess as reserved, so an address that does not fit is
/// rejected at the point of construction rather than discovered as a fault.
const ADDR_MASK: u64 = 0x000f_ffff_ffff_f000;

/// Bit 0, P: the entry maps something.
const PRESENT: u64 = 1 << 0;
/// Bit 1, R/W: writes are permitted through this entry and everything below it.
const WRITABLE: u64 = 1 << 1;
/// Bit 2, U/S: unprivileged code may use this entry and everything below it.
const USER: u64 = 1 << 2;
/// Bit 3, PWT: write-through rather than write-back caching.
const WRITE_THROUGH: u64 = 1 << 3;
/// Bit 4, PCD: caching disabled.
const CACHE_DISABLE: u64 = 1 << 4;
/// Bit 5, A: the CPU has used this entry in a translation. Written by hardware.
const ACCESSED: u64 = 1 << 5;
/// Bit 6, D: the page has been written. Written by hardware, leaf entries only.
const DIRTY: u64 = 1 << 6;
/// Bit 7. PS at levels 1 and 2, PAT at level 0, reserved at level 3 — see the module
/// comment.
const PAGE_SIZE_BIT: u64 = 1 << 7;
/// Bit 8, G: the translation survives a CR3 reload. Ignored unless `CR4.PGE` is set,
/// which this kernel does not yet set.
const GLOBAL: u64 = 1 << 8;
/// Bit 63, XD/NX: instruction fetches from this entry's range fault. Reserved unless
/// `EFER.NXE` is set.
const NO_EXECUTE: u64 = 1 << 63;

/// One word of an x86-64 page table, at any of the four levels.
///
/// The four levels share one encoding, which is why a single type serves all of them
/// and why the two level-dependent bits have to be asked about with a level in hand.
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct Entry(u64);

impl Entry {
    /// The raw word, for diagnostics and for the tests that check the encoding.
    pub const fn bits(self) -> u64 {
        self.0
    }

    /// Whether the CPU has used this entry in a translation since it was last cleared.
    ///
    /// Hardware sets this bit; nothing in software does. It is the input to any
    /// eventual page-replacement policy, and reading it is the only way to tell a
    /// mapping that is merely present from one that is being used.
    pub const fn accessed(self) -> bool {
        self.0 & ACCESSED != 0
    }

    /// Whether the page this leaf entry maps has been written since the bit was last
    /// cleared. Meaningless on a non-leaf entry, where hardware never sets it.
    pub const fn dirty(self) -> bool {
        self.0 & DIRTY != 0
    }
}

impl PageTableEntry for Entry {
    fn empty() -> Self {
        Entry(0)
    }

    fn is_present(self) -> bool {
        self.0 & PRESENT != 0
    }

    fn is_leaf(self, level: u8) -> bool {
        if !self.is_present() {
            return false;
        }
        match level {
            // A present PTE always maps a frame. Bit 7 here is PAT and is deliberately
            // not consulted: reading it as PS is the bug this signature exists to make
            // impossible.
            0 => true,
            // PD and PDPT: PS selects a 2 MiB or 1 GiB leaf.
            1 | 2 => self.0 & PAGE_SIZE_BIT != 0,
            // PML4, and anything above it. Bit 7 is reserved; there is no 512 GiB page.
            _ => false,
        }
    }

    fn address(self) -> PhysAddr {
        // The same field at every level. In a huge leaf the low bits of the field are
        // architecturally zero, so masking yields the frame base either way.
        PhysAddr::new(self.0 & ADDR_MASK)
    }

    fn flags(self, level: u8) -> PageFlags {
        if !self.is_present() {
            return PageFlags::empty();
        }
        // A present entry is readable; x86 has no read-disable.
        let mut f = PageFlags::READ;
        if self.0 & WRITABLE != 0 {
            f = f.union(PageFlags::WRITE);
        }
        if self.0 & USER != 0 {
            f = f.union(PageFlags::USER);
        }
        // NX is the presence of a bit and execute is its absence, which is the
        // inversion the neutral form exists to hide. Note that bit 63 reads as zero on
        // a CPU where NXE is off, so an entry is reported executable exactly when the
        // hardware will treat it as executable.
        if self.0 & NO_EXECUTE == 0 {
            f = f.union(PageFlags::EXECUTE);
        }
        if self.is_leaf(level) {
            // G and the cache-control bits describe a mapping. On an intermediate
            // entry PWT/PCD describe how the CPU caches the *table* below, which is
            // not a permission and would be a lie to report as one.
            if self.0 & GLOBAL != 0 {
                f = f.union(PageFlags::GLOBAL);
            }
            match (self.0 & CACHE_DISABLE != 0, self.0 & WRITE_THROUGH != 0) {
                (true, true) => f = f.union(PageFlags::DEVICE),
                (true, false) => f = f.union(PageFlags::NO_CACHE),
                _ => {}
            }
        }
        f
    }

    fn table(table: PhysAddr) -> Self {
        // Permissive on purpose, and on x86 that is not merely a convention: the
        // effective permission of a translation is the AND of every level, so clearing
        // R/W or U/S here would cap every leaf beneath this entry and the leaf's own
        // flags would silently stop meaning what they say. NX is left clear for the
        // same reason. The leaf is where intent is expressed.
        Entry((table.raw() & ADDR_MASK) | PRESENT | WRITABLE | USER)
    }

    fn leaf(frame: PhysAddr, flags: PageFlags, level: u8) -> Self {
        let mut e = (frame.raw() & ADDR_MASK) | PRESENT;
        if level > 0 {
            e |= PAGE_SIZE_BIT;
        }
        if flags.contains(PageFlags::WRITE) {
            e |= WRITABLE;
        }
        if flags.contains(PageFlags::USER) {
            e |= USER;
        }
        if flags.contains(PageFlags::GLOBAL) {
            e |= GLOBAL;
        }
        if flags.contains(PageFlags::DEVICE) {
            e |= CACHE_DISABLE | WRITE_THROUGH;
        } else if flags.contains(PageFlags::NO_CACHE) {
            e |= CACHE_DISABLE;
        }
        // Bit 63 is reserved unless EFER.NXE is set, and a reserved bit is a fault
        // rather than an ignored one. Emitting it is therefore conditional on the CPU
        // actually being in a state that accepts it; `selftest` reports when it is
        // not, so a mapping that came out executable against intent is visible rather
        // than silent.
        if !flags.contains(PageFlags::EXECUTE) && features().nx {
            e |= NO_EXECUTE;
        }
        Entry(e)
    }
}

impl HasPageTables for X86_64 {
    type Entry = Entry;

    fn index_bits(_level: u8) -> u8 {
        // Uniform at every level: 4 levels x 9 bits + a 12-bit offset is the 48-bit
        // virtual address space. PAE's ragged top level is the i686 port's problem.
        9
    }

    fn leaf_allowed(level: u8) -> bool {
        match level {
            0 => true,
            // 2 MiB pages have existed since PSE-36 and are architecturally mandatory
            // in long mode.
            1 => true,
            // 1 GiB pages are not. Asked of the CPU rather than assumed — see
            // `probe`.
            2 => features().gib_pages,
            _ => false,
        }
    }

    fn is_canonical(addr: usize) -> bool {
        // Bits 63..=47 must all equal bit 47: seventeen bits, all zero or all one.
        // Anything else is non-canonical and faults on use rather than wrapping, so it
        // is worth rejecting where the address is constructed.
        let high = addr >> 47;
        high == 0 || high == (1 << 17) - 1
    }

    unsafe fn set_root(root: PhysAddr) {
        // The low twelve bits of CR3 are PWT/PCD (and PCID, if CR4.PCIDE is set, which
        // it is not) rather than part of the address, so they are cleared rather than
        // inherited.
        let value = root.raw() & ADDR_MASK;
        // SAFETY: the caller guarantees `root` names a well-formed table that maps the
        // running code and stack; that is the whole contract of this function and
        // there is nothing this side can check. Writing CR3 also flushes every
        // non-global TLB entry, so no separate invalidation is needed. Not `nomem`:
        // this changes what every subsequent memory access means.
        unsafe { asm!("mov cr3, {}", in(reg) value, options(nostack, preserves_flags)) };
    }

    fn root() -> PhysAddr {
        let cr3: u64;
        // SAFETY: reading a control register has no side effects and is permitted at
        // CPL 0, the only privilege level this kernel runs at.
        unsafe { asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack, preserves_flags)) };
        PhysAddr::new(cr3 & ADDR_MASK)
    }

    unsafe fn flush_tlb(addr: Option<usize>) {
        match addr {
            Some(a) => {
                // SAFETY: `invlpg` drops any cached translation for one address and
                // has no other effect; an address with no cached translation is a
                // no-op rather than a fault. Not `nomem`, because the point of the
                // instruction is that memory accesses after it mean something
                // different from those before.
                unsafe { asm!("invlpg [{}]", in(reg) a, options(nostack, preserves_flags)) };
            }
            None => {
                // Reloading CR3 with its own value flushes everything that is not
                // global. Global entries would need CR4.PGE toggled; this kernel never
                // sets PGE, so there are none.
                let cr3 = X86_64::root().raw();
                // SAFETY: writing back the value just read leaves the active table
                // unchanged, so the mapping the current instruction stream depends on
                // cannot go away underneath it.
                unsafe { asm!("mov cr3, {}", in(reg) cr3, options(nostack, preserves_flags)) };
            }
        }
    }
}

// ---------------------------------------------------------------------------
// CPU features, and the EFER.NXE question
// ---------------------------------------------------------------------------

/// The `IA32_EFER` model-specific register.
const EFER: u32 = 0xc000_0080;
/// `EFER.NXE`, bit 11: makes bit 63 of a page table entry mean NX instead of reserved.
const EFER_NXE: u64 = 1 << 11;
/// `CR0.WP`, bit 16: makes the R/W bit apply to supervisor-mode writes too.
const CR0_WP: u64 = 1 << 16;

/// Probed state, packed into one atomic so a reader gets a consistent answer.
static FEATURES: AtomicU8 = AtomicU8::new(0);
/// [`init`] has run and the other bits are meaningful.
const F_READY: u8 = 1 << 0;
/// CPUID reports 1 GiB leaf entries.
const F_GIB: u8 = 1 << 1;
/// CPUID reports NX *and* `EFER.NXE` read back set.
const F_NX: u8 = 1 << 2;
/// `CR0.WP` read back set, so a clear R/W bit binds the kernel as well as userspace.
const F_WP: u8 = 1 << 3;

/// What this CPU can do, as probed once by [`init`].
///
/// Every field defaults to `false` before `init` runs, and every default is the
/// conservative answer: no 1 GiB pages, no NX bit. A caller that forgot to initialise
/// gets a correct if unambitious mapping rather than a reserved-bit fault.
#[derive(Clone, Copy)]
pub struct Features {
    /// Leaf entries at level 2 (1 GiB pages) are supported: CPUID leaf 0x8000_0001,
    /// EDX bit 26.
    pub gib_pages: bool,
    /// Bit 63 may be emitted: the CPU has NX (EDX bit 20) and `EFER.NXE` is set.
    pub nx: bool,
    /// `CR0.WP` is set, so a read-only mapping is read-only to the kernel too. Without
    /// it, clearing R/W protects nothing above ring 3.
    pub wp: bool,
    /// Whether [`init`] has run. When false the others are defaults, not answers.
    pub ready: bool,
}

/// What [`init`] found, or the conservative defaults if it has not run.
pub fn features() -> Features {
    let f = FEATURES.load(Ordering::Relaxed);
    Features {
        gib_pages: f & F_GIB != 0,
        nx: f & F_NX != 0,
        wp: f & F_WP != 0,
        ready: f & F_READY != 0,
    }
}

/// Probe the paging-related CPU features and enable `EFER.NXE` and `CR0.WP`.
///
/// Idempotent, and safe to call before anything else in this module: nothing here
/// changes a translation, only what the bits in one already mean. Both side effects
/// are preconditions rather than policies — with NXE off a kernel cannot mark anything
/// non-executable, and with WP off it cannot mark anything read-only. Enabling WP is
/// safe here and only here: every mapping in existence at this point, in the boot table
/// and in the one this module is about to build, is writable, so no write that
/// succeeded a moment ago starts faulting.
pub fn init() {
    if features().ready {
        return;
    }

    // Leaf 0x8000_0000 reports the highest extended leaf the CPU implements, and is
    // read first because querying a leaf above that returns the highest *basic* leaf's
    // data on some CPUs rather than zeroes — reading feature bits out of unrelated data
    // is exactly how a kernel concludes it has a feature it does not.
    let max_extended = __cpuid(0x8000_0000).eax;

    let mut bits = F_READY;
    if max_extended >= 0x8000_0001 {
        let edx = __cpuid(0x8000_0001).edx;
        if edx & (1 << 26) != 0 {
            bits |= F_GIB;
        }
        if edx & (1 << 20) != 0 {
            // SAFETY: EFER exists on every CPU that reached long mode — `boot.rs` has
            // already written it to set LME — and NXE is a defined bit of it. Setting
            // NXE changes only the interpretation of bit 63 in entries, and no entry
            // in the currently installed tables sets it, so no live translation
            // changes meaning.
            unsafe { write_msr(EFER, read_msr(EFER) | EFER_NXE) };
            // Read back rather than assume. A hypervisor that declines the write, or a
            // CPU whose NX is disabled in firmware, leaves the bit clear — and then
            // every NX we emit is a reserved-bit fault.
            // SAFETY: as above.
            if unsafe { read_msr(EFER) } & EFER_NXE != 0 {
                bits |= F_NX;
            }
        }
    }

    // SAFETY: setting WP makes the R/W bit bind CPL 0 as well. Every page currently
    // mapped — the boot identity map and everything this module maps — is writable, so
    // no store that was legal before this instruction becomes a fault after it. Nothing
    // else in CR0 is touched: the value is read, one bit is set, and it is written back.
    unsafe { write_cr0(read_cr0() | CR0_WP) };
    // Read back for the same reason as EFER: if the bit did not stick, every read-only
    // mapping this kernel makes is advisory, and that has to be visible rather than
    // assumed.
    if read_cr0() & CR0_WP != 0 {
        bits |= F_WP;
    }

    FEATURES.store(bits, Ordering::Relaxed);
}

/// CR0, which holds the mode bits paging depends on.
fn read_cr0() -> u64 {
    let v: u64;
    // SAFETY: reading a control register has no side effects and is permitted at CPL 0.
    unsafe { asm!("mov {}, cr0", out(reg) v, options(nomem, nostack, preserves_flags)) };
    v
}

/// Write CR0.
///
/// # Safety
/// CR0 holds PG, PE, WP and the cache-control bits; changing any of them changes the
/// meaning of code that is already running. Callers must read, modify and write back
/// rather than composing a value, and must know that every mapping in use tolerates the
/// new setting.
unsafe fn write_cr0(value: u64) {
    // SAFETY: the caller guarantees the value is a legal successor to the current one.
    // Not `nomem`: this changes how subsequent memory accesses are checked.
    unsafe { asm!("mov cr0, {}", in(reg) value, options(nostack, preserves_flags)) };
}

/// Read a model-specific register.
///
/// # Safety
/// `msr` must be implemented by this CPU. `rdmsr` on an unimplemented register raises
/// #GP, which this early in boot is a fault inside the code that exists to make faults
/// reportable.
unsafe fn read_msr(msr: u32) -> u64 {
    let lo: u32;
    let hi: u32;
    // SAFETY: `rdmsr` reads the register named by ECX into EDX:EAX and touches nothing
    // else; the caller guarantees the register exists.
    unsafe {
        asm!(
            "rdmsr",
            in("ecx") msr,
            out("eax") lo,
            out("edx") hi,
            options(nomem, nostack, preserves_flags),
        );
    }
    (u64::from(hi) << 32) | u64::from(lo)
}

/// Write a model-specific register.
///
/// # Safety
/// `msr` must be implemented by this CPU and `value` must be a legal value for it: a
/// reserved bit set in an MSR is #GP, and some MSRs change the meaning of code that is
/// already executing. The caller owns what the register does.
unsafe fn write_msr(msr: u32, value: u64) {
    let lo = value & 0xffff_ffff;
    let hi = value >> 32;
    // SAFETY: `wrmsr` writes EDX:EAX to the register named by ECX; the caller
    // guarantees both the register and the value.
    unsafe {
        asm!(
            "wrmsr",
            in("ecx") msr,
            in("eax") lo,
            in("edx") hi,
            options(nostack, preserves_flags),
        );
    }
}

// ---------------------------------------------------------------------------
// Tables: a page arena and the small walk this module needs for itself
// ---------------------------------------------------------------------------

/// Entries in one table, at every level on this architecture.
const ENTRIES: usize = 512;

/// Frames reserved for the tables this module builds.
///
/// Eight are needed for what [`selftest`] maps — a PML4, a PDPT, a PD and its 2 MiB
/// leaves for the identity map, a second PD, and four PTs — and the rest is slack so
/// that adding a mapping does not silently fall off the end. This arena exists because
/// an `arch` unit cannot reach `mm::FrameAllocator`; it is not a general allocator and
/// never frees.
const ARENA_FRAMES: usize = 12;

/// Backing store for [`alloc_table`].
///
/// `UnsafeCell` rather than a plain array for the reason `gdt.rs` records at its stack:
/// an immutable all-zero static is `.rodata`, and page tables the CPU walks and this
/// module writes are neither immutable nor read-only.
#[repr(C, align(4096))]
struct Arena(UnsafeCell<[[u64; ENTRIES]; ARENA_FRAMES]>);

// SAFETY: the invariant is single-writer. `alloc_table` hands out each frame exactly
// once, through an atomic bump, and the only writers afterwards are this module's own
// table writes and the CPU's A/D bit updates — which the entry accessors treat as
// volatile for precisely that reason. No two callers can obtain the same frame.
unsafe impl Sync for Arena {}

static ARENA: Arena = Arena(UnsafeCell::new([[0; ENTRIES]; ARENA_FRAMES]));

/// Index of the next unhanded-out frame in [`ARENA`].
static ARENA_NEXT: AtomicUsize = AtomicUsize::new(0);

/// A pointer to one 512-entry page table.
///
/// Deliberately not a reference: the CPU's page-table walker reads these words
/// concurrently with us and writes the A and D bits into them, so a `&mut [Entry]`
/// held across a walk would be an aliasing claim the hardware does not honour.
#[derive(Clone, Copy)]
struct Table(*mut Entry);

impl Table {
    /// The table at physical address `p`.
    ///
    /// Correct only while the kernel runs identity-mapped, which is the whole of Phase
    /// 0. `mm::DirectMap` is what this becomes when it stops being true.
    #[allow(clippy::as_conversions)]
    fn from_phys(p: PhysAddr) -> Table {
        Table(p.raw() as usize as *mut Entry)
    }

    /// The physical address of this table, by the same identity-map equality.
    #[allow(clippy::as_conversions)]
    fn phys(self) -> PhysAddr {
        PhysAddr::new(self.0 as usize as u64)
    }

    /// Read one entry. Out-of-range indices read as absent rather than panicking;
    /// every caller derives its index from [`level_index`], which masks to nine bits.
    fn get(self, index: usize) -> Entry {
        if index >= ENTRIES {
            return Entry::empty();
        }
        // SAFETY: the bound above keeps the offset inside the single 4 KiB frame this
        // table occupies, and every `Table` in this module names a frame handed out by
        // `alloc_table` or reached from one by following a present entry.
        let slot = unsafe { self.0.add(index) };
        // SAFETY: volatile because the CPU writes the A and D bits of these words
        // without the compiler's knowledge, so a cached read would be stale.
        unsafe { slot.read_volatile() }
    }

    /// Write one entry. Out-of-range indices are dropped, for the same reason.
    fn set(self, index: usize, entry: Entry) {
        if index >= ENTRIES {
            return;
        }
        // SAFETY: as `get`.
        let slot = unsafe { self.0.add(index) };
        // SAFETY: volatile so the write is not sunk or reordered past the `invlpg` or
        // CR3 load that publishes it to the walker.
        unsafe { slot.write_volatile(entry) };
    }
}

/// Hand out one zeroed frame from the arena.
///
/// Zeroed explicitly rather than trusting the loader to have cleared `.bss`: the
/// assembly in `boot.rs` does not trust it either, and a page table with one stale
/// non-zero word is a mapping nobody wrote.
fn alloc_table() -> Option<Table> {
    let index = ARENA_NEXT.fetch_add(1, Ordering::Relaxed);
    if index >= ARENA_FRAMES {
        return None;
    }
    let base = ARENA.0.get().cast::<[u64; ENTRIES]>();
    // SAFETY: `index` is below `ARENA_FRAMES`, so this stays inside the static.
    let frame = unsafe { base.add(index) };
    // SAFETY: `frame` names one whole 4 KiB element of the arena, handed out exactly
    // once by the bump above, so nothing else holds a pointer into it.
    unsafe { core::ptr::write_bytes(frame.cast::<u8>(), 0, 4096) };
    Some(Table(frame.cast::<Entry>()))
}

/// Map `va` to `frame` with `flags`, with the leaf placed at `leaf_level`.
///
/// The whole walk this module needs: descend from the root allocating intermediate
/// tables, then write one leaf. It splits nothing, unmaps nothing and frees nothing —
/// that is `mm::paged`'s job, and duplicating it here would be the second copy of the
/// tree walk that `hal::paging` exists to prevent.
fn map(
    root: Table,
    va: usize,
    frame: PhysAddr,
    flags: PageFlags,
    leaf_level: u8,
) -> Result<(), MapError> {
    if !X86_64::is_canonical(va) {
        return Err(MapError::NotCanonical);
    }
    if !X86_64::leaf_allowed(leaf_level) {
        return Err(MapError::WouldSplit);
    }
    if frame.raw() & !ADDR_MASK != 0 {
        return Err(MapError::BadPhysAddr);
    }
    // A leaf above level 0 has more of the address field architecturally reserved, so
    // an under-aligned frame is not a smaller mapping — it is reserved bits set, which
    // faults on the first walk.
    let size = level_size::<X86_64>(leaf_level);
    #[allow(clippy::as_conversions)]
    let size64 = size as u64;
    if !frame.is_aligned(size64) || va & size.saturating_sub(1) != 0 {
        return Err(MapError::Misaligned);
    }

    let mut table = root;
    let mut level = <X86_64 as HasMmu>::LEVELS.saturating_sub(1);
    while level > leaf_level {
        let index = level_index::<X86_64>(va, level);
        let entry = table.get(index);
        table = if entry.is_present() {
            if entry.is_leaf(level) {
                // A huge page is already here. Splitting it is a policy decision the
                // caller has to make, so it is reported rather than taken.
                return Err(MapError::WouldSplit);
            }
            Table::from_phys(entry.address())
        } else {
            let fresh = alloc_table().ok_or(MapError::OutOfFrames)?;
            table.set(index, Entry::table(fresh.phys()));
            fresh
        };
        level = level.saturating_sub(1);
    }

    let index = level_index::<X86_64>(va, leaf_level);
    if table.get(index).is_present() {
        return Err(MapError::AlreadyMapped);
    }
    table.set(index, Entry::leaf(frame, flags, leaf_level));
    Ok(())
}

/// The leaf entry translating `va` under `root`, and the table and index it lives in.
///
/// Returns `None` when the walk hits an absent entry before reaching a leaf. Used by
/// the fault trap to edit the entry it just faulted on, which is the smallest possible
/// version of what a demand-paging fault handler does.
fn leaf_of(root: PhysAddr, va: usize) -> Option<(Table, usize)> {
    let mut table = Table::from_phys(root);
    let mut level = <X86_64 as HasMmu>::LEVELS.saturating_sub(1);
    loop {
        let index = level_index::<X86_64>(va, level);
        let entry = table.get(index);
        if !entry.is_present() {
            return None;
        }
        if entry.is_leaf(level) {
            return Some((table, index));
        }
        if level == 0 {
            return None;
        }
        table = Table::from_phys(entry.address());
        level = level.saturating_sub(1);
    }
}

// ---------------------------------------------------------------------------
// The expected-fault trap
// ---------------------------------------------------------------------------

/// A single-shot expectation that the next #PF will land on a known page.
///
/// The problem this solves is that a page fault the kernel *asked for* and one it did
/// not look identical at the handler: both are vector 14 with a CR2 and an error code,
/// and `exception::fatal` halts. Without a way to tell them apart, a selftest that
/// proves a mapping is read-only proves it by killing the machine.
///
/// Single-shot and armed with an exact page, so the window in which a fault is
/// non-fatal is one instruction wide and covers one address. Disarming happens *before*
/// the fixup is attempted, so a fault we then fail to resolve falls through to the
/// fatal reporter on its second occurrence instead of looping forever — which is the
/// difference between a bug that prints a diagnosis and one that hangs QEMU.
///
/// This is deliberately the shape demand paging will need in Phase 1: consult
/// something that knows about the address, resolve it, return and let the instruction
/// re-execute. The `exception` module's comment already describes that shape; this is
/// its first, very small, instance.
struct FaultTrap {
    /// Page the next #PF is expected on, or 0 for "nothing is expected".
    page: AtomicUsize,
    /// Bits to set in the faulting leaf entry so the retry succeeds.
    set: AtomicU64,
    /// Bits to clear in it.
    clear: AtomicU64,
    /// Error code the trapped fault pushed.
    code: AtomicU64,
    /// Faults trapped since boot.
    hits: AtomicU32,
}

static TRAP: FaultTrap = FaultTrap {
    page: AtomicUsize::new(0),
    set: AtomicU64::new(0),
    clear: AtomicU64::new(0),
    code: AtomicU64::new(0),
    hits: AtomicU32::new(0),
};

/// Page containing `va`.
const fn page_of(va: usize) -> usize {
    va & !0xfff
}

/// Expect one #PF on the page containing `va`, and resolve it by setting `set` and
/// clearing `clear` in the leaf entry that faulted.
///
/// Arming is not a promise that a fault will happen; [`disarm`] reports whether one
/// did, which is what makes "the write was refused" an observation rather than an
/// inference from survival.
fn arm(va: usize, set: u64, clear: u64) {
    TRAP.set.store(set, Ordering::Relaxed);
    TRAP.clear.store(clear, Ordering::Relaxed);
    TRAP.code.store(0, Ordering::Relaxed);
    // Published last: until this store the handler ignores everything above. The low
    // bit is a marker, not part of the address, so that page zero can be armed and
    // "nothing armed" stays representable as plain zero.
    TRAP.page.store(page_of(va) | 1, Ordering::SeqCst);
    // The access this guards is a volatile one, and nothing in the memory model forbids
    // the compiler from hoisting it above an atomic store. One instruction of ordering
    // is cheap next to a fault that would be fatal instead of trapped.
    compiler_fence(Ordering::SeqCst);
}

/// Stop expecting a fault, and report the error code of the one that was trapped.
///
/// `None` means no fault was trapped, which for a check that expected one is a
/// failure: the access it guarded went through when it should not have.
fn disarm() -> Option<u64> {
    compiler_fence(Ordering::SeqCst);
    let armed = TRAP.page.swap(0, Ordering::SeqCst);
    let code = TRAP.code.load(Ordering::Relaxed);
    // The handler clears `page` when it fires, so a non-zero value here means it never
    // did.
    if armed == 0 { Some(code) } else { None }
}

/// Consider a page fault against the standing expectation.
///
/// Returns `true` when the fault was expected and has been resolved, in which case the
/// handler returns and the faulting instruction re-executes. Everything else — an
/// unexpected address, an unexpected fault while nothing is armed, or an armed fault
/// whose entry cannot be found — returns `false` and reaches the fatal reporter.
pub(crate) fn on_page_fault(cr2: u64, code: u64) -> bool {
    let armed = TRAP.page.load(Ordering::Acquire);
    if armed == 0 {
        return false;
    }
    // Disarm first, unconditionally. If anything below fails to make the retry
    // succeed, the second fault is fatal and reports itself, rather than becoming an
    // endless loop with no output.
    TRAP.page.store(0, Ordering::Release);

    #[allow(clippy::as_conversions)]
    let faulting = page_of(cr2 as usize);
    if faulting != (armed & !1) {
        return false;
    }

    let Some((table, index)) = leaf_of(X86_64::root(), faulting) else {
        return false;
    };
    let entry = table.get(index);
    let set = TRAP.set.load(Ordering::Relaxed);
    let clear = TRAP.clear.load(Ordering::Relaxed);
    table.set(index, Entry((entry.bits() | set) & !clear));

    // SAFETY: the entry write above is a volatile store that has already retired from
    // the compiler's point of view, which is what this call requires: x86's page-table
    // walker is coherent with the store buffer, so no barrier beyond that is needed
    // before invalidating.
    unsafe { X86_64::flush_tlb(Some(faulting)) };

    TRAP.code.store(code, Ordering::Relaxed);
    TRAP.hits.fetch_add(1, Ordering::Relaxed);
    true
}

// ---------------------------------------------------------------------------
// The selftest
// ---------------------------------------------------------------------------

/// Bytes identity-mapped by the table [`selftest`] builds.
///
/// One gibibyte, with 2 MiB leaves — the same span and the same page size as the
/// assembly map in `boot.rs`, because the moment CR3 changes, the code executing, the
/// stack under it and the arena holding the tables themselves must all still be where
/// they were. Building a new table that *contains* the old map is the only way to
/// replace it while running on it.
const IDENTITY_BYTES: usize = 1024 * 1024 * 1024;

/// Bytes one level-1 leaf maps.
const TWO_MIB: usize = 2 * 1024 * 1024;

/// Virtual addresses for the test mappings, all above the identity map so that
/// reaching them at all is proof that the new table is the live one — none of them
/// translates under the table `boot.rs` built.
const VA_RW: usize = 0x4000_0000;
/// A second mapping of the same frame, in a different level-1 table.
const VA_ALIAS: usize = 0x4020_0000;
/// A read-only mapping of the same frame.
const VA_RO: usize = 0x4040_0000;
/// A non-executable mapping of the same frame.
const VA_NX: usize = 0x4060_0000;
/// A single level-2 leaf mapping the whole first gibibyte of physical memory. Present
/// only when CPUID says 1 GiB pages exist.
const VA_GIB: usize = 0x8000_0000;

/// Offset in the test frame of the word the aliasing check writes.
const ALIAS_OFFSET: usize = 0;
/// Offset of the word the read-only check writes.
const RO_OFFSET: usize = 0x100;
/// Offset of the `ret` the no-execute check calls.
const CODE_OFFSET: usize = 0x800;

/// `ret`, the entire body of the function the no-execute check calls.
const RET: u8 = 0xc3;

/// A value with no chance of being what was already there.
const ALIAS_MAGIC: u64 = 0x4b69_6e54_616e_6531;
/// Likewise, for the read-only check.
const RO_MAGIC: u32 = 0x5057_6f6b;

/// One frame, mapped at four virtual addresses with four different permissions.
///
/// A single frame rather than four is the point: if a write through one address is
/// visible through another, the two addresses demonstrably translate to the same
/// physical memory, and that is a property no amount of not-crashing can fake.
#[repr(C, align(4096))]
struct TestFrame(UnsafeCell<[u8; 4096]>);

// SAFETY: written only from `selftest`, which runs once during boot on the only CPU
// that exists, and read back through mappings that same function installs. Nothing
// else in the kernel knows this static's name.
unsafe impl Sync for TestFrame {}

static TEST_FRAME: TestFrame = TestFrame(UnsafeCell::new([0; 4096]));

/// Bring kernel-managed page tables up and prove they work.
///
/// Four independent demonstrations, each reported separately and each an observation
/// rather than an inference:
///
/// 1. **alias** — a write through one virtual address is read back through a second
///    one that maps the same frame, and through the frame's own identity address.
///    Neither test address exists under the boot tables, so this also proves CR3 now
///    names ours.
/// 2. **1G** — the same value is read back through a level-2 leaf, which exercises the
///    PS bit at a level where it means something. Skipped with a report when CPUID
///    says the CPU has no 1 GiB pages, which is the one thing `leaf_allowed` must not
///    assume.
/// 3. **ro** — a write through a read-only mapping raises #PF with a write-protection
///    error code, and the trap handler's fixup makes the retry succeed. The fault is
///    counted, so "no fault happened" is a failure and not a pass.
/// 4. **nx** — a call into a non-executable mapping raises #PF with the
///    instruction-fetch bit set. This one is the direct evidence that `EFER.NXE` took
///    effect, and it is skipped with a report, not silently, when NX is unavailable.
///
/// Returns true only if every check that ran observed what it was looking for.
pub fn selftest(c: &dyn EarlyConsole) -> bool {
    // Everything below must be uninterruptible: CR3 changes under us otherwise, and
    // the fault trap is a single global armed for one instruction.
    let _masked = X86_64::irq_save();

    // The interrupt path first, and not for tidiness. Until `idt::load` has run the
    // IDTR is whatever the loader left — a zero limit under QEMU — so the #PF this
    // test deliberately provokes would be a triple fault and a silent reset. `init`
    // is idempotent and leaves every line masked, so `interrupt_selftest` calling it
    // again later is a no-op.
    interrupt::init();

    init();
    let f = features();

    c.write_str("4x9 bits, 1G pages ");
    c.write_str(if f.gib_pages { "yes" } else { "no" });
    c.write_str(", NX ");
    c.write_str(if f.nx {
        "on (EFER.NXE)"
    } else {
        "UNAVAILABLE, not emitted"
    });
    c.write_str(", WP ");
    c.write_str(if f.wp { "on (CR0.WP)" } else { "OFF" });

    let old_root = X86_64::root();
    let Some(root) = build_tables(c) else {
        return false;
    };

    c.write_str("\n             cr3    ");
    write_hex(c, old_root.raw(), 16);
    c.write_str(" -> ");
    write_hex(c, root.phys().raw(), 16);

    // SAFETY: `root` identity-maps the low gibibyte with the same permissions the boot
    // table gave it, which covers the kernel image, the stack, this arena and the test
    // frame; the serial port is I/O-space and needs no mapping. `build_tables` returned
    // Some only after every one of those mappings was written. The test addresses all
    // sit above the identity map and are additions to it, not replacements.
    unsafe { X86_64::set_root(root.phys()) };

    let installed = X86_64::root() == root.phys();
    if !installed {
        c.write_str("\n             cr3    READ BACK WRONG");
        return false;
    }

    let alias_ok = check_alias(c);
    let huge_ok = check_huge(c, f.gib_pages);
    let ro_ok = check_read_only(c, f.wp);
    let nx_ok = check_no_execute(c, f.nx);

    alias_ok && huge_ok && ro_ok && nx_ok
}

/// Build a table that reproduces the boot identity map and adds the test mappings.
fn build_tables(c: &dyn EarlyConsole) -> Option<Table> {
    let Some(root) = alloc_table() else {
        c.write_str("\n             arena  empty");
        return None;
    };

    // Read, write and execute, which is what the assembly map already grants. Narrowing
    // it — execute only on `.text`, no-execute everywhere else — is a real use for the
    // NX bit this file just enabled, and it belongs with the high-half move in Phase 1:
    // doing it here would mean deciding section boundaries from an arch unit that
    // cannot see the linker script's symbols for anything but the image's ends.
    let kernel = PageFlags::KERNEL_DATA | PageFlags::EXECUTE;

    let mut offset = 0usize;
    while offset < IDENTITY_BYTES {
        #[allow(clippy::as_conversions)]
        let frame = PhysAddr::new(offset as u64);
        if let Err(e) = map(root, offset, frame, kernel, 1) {
            c.write_str("\n             ident  failed at ");
            write_hex(c, frame.raw(), 16);
            report_map_error(c, e);
            return None;
        }
        offset = offset.saturating_add(TWO_MIB);
    }

    // One 1 GiB leaf over the same physical gibibyte, when the CPU has them. The point
    // is to exercise a level-2 leaf rather than to report that CPUID mentioned one: the
    // PS bit at level 2 and the alignment rules that come with it are encoding this
    // module is responsible for, and `check_huge` reads back through it.
    if features().gib_pages {
        if let Err(e) = map(root, VA_GIB, PhysAddr::new(0), PageFlags::KERNEL_DATA, 2) {
            c.write_str("\n             huge   failed");
            report_map_error(c, e);
            return None;
        }
    }

    // The frame is in `.bss`, inside the span just identity-mapped, so its physical
    // address is the address we already hold it at.
    let frame = test_frame_phys();

    // The body of the function the no-execute check calls, written through the identity
    // map while the page is still plain data. x86's instruction cache is coherent with
    // stores, so no explicit synchronisation is needed before executing it.
    let bytes = TEST_FRAME.0.get().cast::<u8>();
    // SAFETY: the static is 4096 bytes and `CODE_OFFSET` is well inside it.
    let slot = unsafe { bytes.add(CODE_OFFSET) };
    // SAFETY: volatile so the store is not elided as dead — nothing in Rust's model
    // ever reads this byte, and the only thing that executes it is the CPU.
    unsafe { slot.write_volatile(RET) };

    let mappings = [
        (VA_RW, PageFlags::KERNEL_DATA),
        (VA_ALIAS, PageFlags::KERNEL_DATA),
        (VA_RO, PageFlags::KERNEL_RODATA),
        // Readable and writable but not executable: the check needs to reach the page
        // as data afterwards, and withholding EXECUTE is what sets bit 63.
        (VA_NX, PageFlags::KERNEL_DATA),
    ];
    for (va, flags) in mappings {
        if let Err(e) = map(root, va, frame, flags, 0) {
            c.write_str("\n             map    failed at ");
            write_hex(c, va_bits(va), 16);
            report_map_error(c, e);
            return None;
        }
    }

    Some(root)
}

/// The physical address of the test frame.
///
/// It lives in `.bss`, inside the identity-mapped low gibibyte, so the address the
/// linker gave it is also its physical address. That equality is the Phase 0 identity
/// map and nothing more; it is the assumption `mm::DirectMap` removes.
#[allow(clippy::as_conversions)]
fn test_frame_phys() -> PhysAddr {
    PhysAddr::new(TEST_FRAME.0.get() as usize as u64)
}

/// Widen a virtual address for the console, which speaks in `u64`.
#[allow(clippy::as_conversions)]
const fn va_bits(va: usize) -> u64 {
    va as u64
}

/// Name a mapping failure, so a build that fails says which of seven things went wrong.
fn report_map_error(c: &dyn EarlyConsole, e: MapError) {
    c.write_str(match e {
        MapError::NotCanonical => " (non-canonical)",
        MapError::Misaligned => " (misaligned)",
        MapError::AlreadyMapped => " (already mapped)",
        MapError::NotMapped => " (not mapped)",
        MapError::OutOfFrames => " (arena exhausted)",
        MapError::WouldSplit => " (would split)",
        MapError::BadPhysAddr => " (bad physical address)",
    });
}

/// Write through one mapping, read back through another, and through the frame itself.
fn check_alias(c: &dyn EarlyConsole) -> bool {
    #[allow(clippy::as_conversions)]
    let write_at = (VA_RW + ALIAS_OFFSET) as *mut u64;
    #[allow(clippy::as_conversions)]
    let read_at = (VA_ALIAS + ALIAS_OFFSET) as *mut u64;

    // SAFETY: both addresses were mapped read-write to `TEST_FRAME` by `build_tables`
    // and the table containing them is installed, so both are live, aligned (the
    // mappings are page-aligned and the offset is zero) and eight bytes inside a 4 KiB
    // frame. Volatile because the whole point is that these two accesses reach the same
    // memory through different addresses, which the compiler has no way to know.
    unsafe { write_at.write_volatile(ALIAS_MAGIC) };
    // SAFETY: as above.
    let through_alias = unsafe { read_at.read_volatile() };
    // SAFETY: the same frame, through the identity map it has always had.
    let through_frame = unsafe { TEST_FRAME.0.get().cast::<u64>().read_volatile() };

    c.write_str("\n             alias  ");
    if through_alias != ALIAS_MAGIC || through_frame != ALIAS_MAGIC {
        c.write_str("MISMATCH: wrote ");
        write_hex(c, ALIAS_MAGIC, 16);
        c.write_str(", alias ");
        write_hex(c, through_alias, 16);
        c.write_str(", frame ");
        write_hex(c, through_frame, 16);
        return false;
    }
    write_hex(c, ALIAS_MAGIC, 16);
    c.write_str(" via ");
    write_hex(c, va_bits(VA_RW), 8);
    c.write_str(" seen via ");
    write_hex(c, va_bits(VA_ALIAS), 8);
    c.write_str(" and the frame");
    true
}

/// Read the test frame back through a 1 GiB leaf, when the CPU has them.
///
/// Runs after [`check_alias`], so the value it is looking for is one this test put
/// there through an unrelated mapping. That is what makes it evidence that a level-2
/// leaf with PS set translates, rather than evidence that some memory somewhere reads
/// back.
fn check_huge(c: &dyn EarlyConsole, gib: bool) -> bool {
    c.write_str("\n             1G     ");
    if !gib {
        c.write_str("skipped: CPUID 0x80000001 EDX[26] clear, level 2 refuses leaves");
        // Not a failure: `leaf_allowed` declining a size the CPU does not have is the
        // behaviour asked for, and asserting otherwise would fail on every older CPU.
        return true;
    }

    let phys = test_frame_phys().raw();
    #[allow(clippy::as_conversions)]
    let through_huge = VA_GIB
        .saturating_add(phys as usize)
        .saturating_add(ALIAS_OFFSET);
    #[allow(clippy::as_conversions)]
    let read_at = through_huge as *const u64;
    // SAFETY: `VA_GIB` is one level-2 leaf covering physical 0..1 GiB, and `phys` is
    // the address of a static inside that range, so this address is mapped and
    // eight-byte aligned. Volatile because the aliasing is the point and the compiler
    // cannot see it.
    let seen = unsafe { read_at.read_volatile() };

    if seen != ALIAS_MAGIC {
        c.write_str("MISMATCH: ");
        write_hex(c, seen, 16);
        c.write_str(" at ");
        write_hex(c, va_bits(through_huge), 16);
        return false;
    }
    write_hex(c, ALIAS_MAGIC, 16);
    c.write_str(" read at ");
    write_hex(c, va_bits(through_huge), 16);
    c.write_str(" through one PS leaf at level 2");
    true
}

/// Write through a read-only mapping and require the hardware to refuse it.
///
/// The trap handler resolves the fault by setting R/W and invalidating, so the retried
/// instruction succeeds — which means this check also demonstrates that a page table
/// edit plus `invlpg` takes effect on an already-translated address, and that the
/// instruction really did re-execute rather than being skipped.
fn check_read_only(c: &dyn EarlyConsole, wp: bool) -> bool {
    if !wp {
        // Deliberately not attempted. Without WP the store below would succeed, and a
        // check that cannot fail for the right reason is worse than no check.
        c.write_str(
            "\n             ro     NOT CHECKED: CR0.WP is clear, so R/W binds \
             nothing at CPL 0",
        );
        return false;
    }

    #[allow(clippy::as_conversions)]
    let write_at = (VA_RO + RO_OFFSET) as *mut u32;
    #[allow(clippy::as_conversions)]
    let read_at = (VA_RW + RO_OFFSET) as *mut u32;

    arm(VA_RO, WRITABLE, 0);
    // SAFETY: mapped to `TEST_FRAME` by `build_tables`, four-byte aligned inside the
    // frame. This store is *expected* to fault: the trap armed immediately above makes
    // the #PF handler set R/W on the entry and return, and the instruction then
    // re-executes and completes. Volatile so it is neither elided nor merged with the
    // read below, which would defeat the retry it is here to observe.
    unsafe { write_at.write_volatile(RO_MAGIC) };
    let trapped = disarm();

    c.write_str("\n             ro     ");
    let Some(code) = trapped else {
        c.write_str("NO FAULT: the write through a read-only mapping was allowed");
        return false;
    };

    // P | W/R: present page, write access, supervisor mode.
    const EXPECTED: u64 = 0b011;
    // SAFETY: a live read-write mapping of the same frame; four-byte aligned.
    let landed = unsafe { read_at.read_volatile() };
    let ok = code == EXPECTED && landed == RO_MAGIC;

    if !ok {
        c.write_str("WRONG: err ");
        write_hex(c, code, 2);
        c.write_str(" (wanted ");
        write_hex(c, EXPECTED, 2);
        c.write_str("), retry stored ");
        write_hex(c, u64::from(landed), 8);
        return false;
    }
    c.write_str("#PF err ");
    write_hex(c, code, 2);
    c.write_str(" at ");
    write_hex(c, va_bits(VA_RO), 8);
    c.write_str(", R/W set, retry stored ");
    write_hex(c, u64::from(landed), 8);
    true
}

/// Call into a non-executable mapping and require the fetch to fault.
///
/// This is the only check here that observes `EFER.NXE` rather than reporting it: bit
/// 63 is reserved with NXE clear, so if the bit had been emitted without the MSR being
/// set, the fault would carry the reserved-bit flag instead of the fetch flag and this
/// would say so.
fn check_no_execute(c: &dyn EarlyConsole, nx: bool) -> bool {
    c.write_str("\n             nx     ");
    if !nx {
        c.write_str("skipped: no NX on this CPU, nothing was marked non-executable");
        // Not a failure. The encoding refused to emit a bit the hardware would have
        // faulted on, which is the correct behaviour, and saying so is the whole
        // requirement.
        return true;
    }

    let target = VA_NX.saturating_add(CODE_OFFSET);
    // A transmute, which `docs/coding-standards.md` says needs review, and this is the
    // review: there is no validated conversion from an address to a function, because
    // nothing about an address can be validated into one. What makes it sound here is
    // that this module wrote the byte at `target` itself — a single `ret` — through the
    // identity map a few lines of control flow ago, and mapped that page executable
    // apart from the NX bit the trap below clears.
    // SAFETY: `usize` and `extern "C" fn()` are both eight bytes on this target, and
    // `target` names a live mapping whose contents are an ABI-conformant function body:
    // it returns immediately, touches no register it must preserve, and leaves the
    // stack as it found it. The first instruction fetch from it is expected to fault;
    // the armed trap clears NX on the entry and returns, and the fetch re-executes.
    let f: extern "C" fn() = unsafe { core::mem::transmute::<usize, extern "C" fn()>(target) };
    arm(VA_NX, 0, NO_EXECUTE);
    f();
    let trapped = disarm();

    let Some(code) = trapped else {
        c.write_str("NO FAULT: a fetch from a non-executable mapping was allowed");
        return false;
    };

    // P | I/D: present page, instruction fetch, supervisor mode. Bit 3 (RSVD) clear is
    // the part that matters — set, it would mean NX was emitted into an entry the CPU
    // considers reserved, which is exactly the bug `init` exists to prevent.
    const EXPECTED: u64 = 0b1_0001;
    if code != EXPECTED {
        c.write_str("WRONG: err ");
        write_hex(c, code, 2);
        c.write_str(" (wanted ");
        write_hex(c, EXPECTED, 2);
        c.write_str(code_note(code));
        return false;
    }
    c.write_str("#PF err ");
    write_hex(c, code, 2);
    c.write_str(" on fetch at ");
    write_hex(c, va_bits(target), 8);
    c.write_str(", NX cleared, call returned (");
    write_dec(c, u64::from(TRAP.hits.load(Ordering::Relaxed)));
    c.write_str(" traps total)");
    true
}

/// A word about an unexpected #PF error code, where one is worth saying.
fn code_note(code: u64) -> &'static str {
    if code & 0b1000 != 0 {
        ") - RSVD set: a reserved bit is set in an entry, which is what NX becomes \
         when EFER.NXE is not"
    } else {
        ")"
    }
}

//! Page tables in the 32-bit PAE format.
//!
//! Three levels, and — unlike every other target in tier 1 — they are not uniform.
//! The page directory pointer table has **four** entries, the page directory and the
//! page table have 512 each. In the `hal::paging` numbering, where level 0 is the
//! leaf and numbers grow toward the root:
//!
//! ```text
//!   level 2   PDPT   4 entries      2 index bits    1 GiB per entry
//!   level 1   PD     512 entries    9 index bits    2 MiB per entry (PS leaf, or PT)
//!   level 0   PT     512 entries    9 index bits    4 KiB per entry
//! ```
//!
//! Two bits plus nine plus nine plus a twelve-bit page offset is thirty-two, which is
//! the whole address space — so `is_canonical` is trivially true here and there is no
//! sign-extended hole in the middle of the range.
//!
//! An entry is **64 bits wide even though a pointer is 32**. That is the entire point
//! of PAE and the reason `PhysAddr` is `u64` project-wide: the address field is bits
//! 12..=35, so a frame can live above 4 GiB where no `usize` on this machine can name
//! it. [`Entry::address`] therefore returns a `PhysAddr` that genuinely fails
//! `to_usize()`, and [`selftest`] proves it does.
//!
//! # The PDPT entry is not a page directory entry
//!
//! This is the trap `boot.rs` documents and the reason the encoders below take a
//! level. In 32-bit PAE a PDPTE has the present bit, PWT and PCD, and **nothing
//! else**: bits 1 and 2 — R/W and U/S, which long mode does have and which
//! `arch/x86_64` therefore sets — are *reserved*, and `mov %eax, %cr3` with either of
//! them set raises #GP. Intel SDM Vol. 3A, §4.4.1, table 4-8.
//!
//! ## Where the contract did not stretch
//!
//! [`hal::PageTableEntry::is_leaf`], `flags` and `leaf` all take a level, and
//! [`hal::HasPageTables::index_bits`] is a function rather than a constant — all of
//! which PAE needs and all of which work. **`PageTableEntry::table` does not take a
//! level**, and PAE is the format where that matters: the correct encoding for a
//! level-2 entry is `P` alone and for a level-1 entry is `P | R/W | U/S`, and no
//! single answer is right at both. The trait impl here returns the level-1 encoding,
//! because a page directory entry without R/W would make every 4 KiB leaf beneath it
//! read-only; [`Entry::table_at`] is the level-aware form, and it is what this port's
//! own code uses. A shared walker that writes `Entry::table(..)` into a PDPT slot on
//! this target produces a root that faults the moment it is installed. The fix is one
//! parameter: `fn table(table: PhysAddr, level: u8) -> Self`.
//!
//! # NX
//!
//! Bit 63 is execute-disable, and PAE is the only 32-bit paging mode that has it — but
//! it is architecturally reserved until `EFER.NXE` is set, and setting a reserved bit
//! is a page fault rather than a no-op. [`enable_nx`] therefore asks CPUID first and
//! only writes the MSR when leaf `0x8000_0001` advertises the feature; when it does
//! not, [`Entry::leaf`] refuses to emit bit 63 at all and reports every mapping as
//! executable, which is the truth about the hardware rather than a wish. QEMU's
//! default `qemu32` CPU does not advertise NX, so the CI run takes the second path.
//!
//! # Entry stores are not atomic here
//!
//! An entry is eight bytes and a store is four. A 64-bit write to a *live* table can
//! therefore be observed torn by the page table walker. [`store_entry`] writes the low
//! dword to zero first, so the intermediate state a walker could see is "not present"
//! rather than "present, half-updated address". This costs nothing on a table that is
//! not yet installed and is necessary on one that is.
//!
//! Reference: Intel SDM Vol. 3A, §4.4 (PAE paging), tables 4-7 through 4-12.

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, Ordering};

use hal::paging::{HasPageTables, PageFlags, PageTableEntry, level_index, level_size};
use hal::{Arch, EarlyConsole, HasMmu, PhysAddr};

use crate::I686;
use crate::serial::write_dec;

/// Physical address field of a 4 KiB entry: bits 12..=35, the 36 bits PAE gives us.
const ADDR_4K: u64 = 0x0000_000F_FFFF_F000;
/// Physical address field of a 2 MiB leaf: bits 21..=35.
const ADDR_2M: u64 = 0x0000_000F_FFE0_0000;

const PRESENT: u64 = 1 << 0;
const WRITABLE: u64 = 1 << 1;
const USER: u64 = 1 << 2;
const WRITE_THROUGH: u64 = 1 << 3;
const CACHE_DISABLE: u64 = 1 << 4;
/// Page size. Bit 7 means "2 MiB leaf" in a page directory entry and means PAT in a
/// page table entry, which is why reading it needs to know the level.
const PAGE_SIZE_BIT: u64 = 1 << 7;
const GLOBAL: u64 = 1 << 8;
/// Execute-disable. Reserved, and faulting, unless `EFER.NXE` is set.
const NO_EXECUTE: u64 = 1 << 63;

/// The level of the page directory pointer table, in `hal::paging` numbering.
const PDPT_LEVEL: u8 = 2;

/// Whether bit 63 may be written into an entry, decided once by [`enable_nx`].
///
/// A static rather than a parameter because [`hal::PageTableEntry::leaf`] is a free
/// constructor with no place to carry the answer, and the answer is a property of the
/// CPU rather than of the mapping. Written once during early initialisation, read
/// everywhere after; `Relaxed` is sufficient because the write happens before any
/// other execution context exists.
static NXE: AtomicBool = AtomicBool::new(false);

/// One word of a PAE page table: 64 bits, on a machine whose pointers are 32.
///
/// A value, not a location: the tables themselves are arrays of `u64`, and this type
/// is the *interpretation* of one of those words. Entries are read out, reasoned
/// about and written back, never held as a reference into a live table — which is the
/// discipline `hal::PageTableEntry` asks for, and the reason it is `Copy`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Entry(u64);

impl Entry {
    /// The raw 64-bit word, as it is stored in the table.
    pub const fn bits(self) -> u64 {
        self.0
    }

    /// Interpret a raw 64-bit word read out of a table.
    pub const fn from_bits(v: u64) -> Entry {
        Entry(v)
    }

    /// An entry naming the next-level table at `table`, encoded for `level`.
    ///
    /// The level-aware form of [`PageTableEntry::table`], which this port needs and
    /// the trait cannot express. At level 2 the result carries the present bit alone:
    /// R/W and U/S are reserved in a 32-bit PAE PDPTE and setting them faults on the
    /// `mov` to CR3. Below that the entry is deliberately permissive — R/W and U/S
    /// both set — because x86 intersects permissions down the tree and restricting
    /// here would silently cap every leaf beneath, where the intent actually lives.
    ///
    /// A level with no table below it (0, or anything past the root) yields an absent
    /// entry rather than a plausible-looking wrong one.
    pub fn table_at(table: PhysAddr, level: u8) -> Entry {
        let addr = table.raw() & ADDR_4K;
        match level {
            PDPT_LEVEL => Entry(addr | PRESENT),
            1 => Entry(addr | PRESENT | WRITABLE | USER),
            _ => Entry(0),
        }
    }

    /// The cache bits for `flags`, shared by both leaf sizes.
    ///
    /// x86 spells uncached as PCD and strongly-uncached as PCD plus PWT. Device
    /// memory gets both: the ordering guarantees a device needs are what PWT buys
    /// here, and a driver that gets write-back memory for an MMIO window finds out
    /// much later and much less pleasantly.
    const fn cache_bits(flags: PageFlags) -> u64 {
        if flags.contains(PageFlags::DEVICE) {
            CACHE_DISABLE | WRITE_THROUGH
        } else if flags.contains(PageFlags::NO_CACHE) {
            CACHE_DISABLE
        } else {
            0
        }
    }
}

impl PageTableEntry for Entry {
    fn empty() -> Entry {
        Entry(0)
    }

    fn is_present(self) -> bool {
        self.0 & PRESENT != 0
    }

    fn is_leaf(self, level: u8) -> bool {
        match level {
            // Every present page table entry maps a frame; bit 7 there is PAT.
            0 => self.is_present(),
            // Bit 7 in a page directory entry selects a 2 MiB leaf.
            1 => self.is_present() && self.0 & PAGE_SIZE_BIT != 0,
            // PDPTE.PS does not exist outside long mode: there are no 1 GiB pages in
            // PAE, so a present PDPTE always names a page directory.
            _ => false,
        }
    }

    fn address(self) -> PhysAddr {
        // The 4 KiB mask is correct for a 2 MiB leaf too: bits 12..20 are zero there
        // by construction, because `leaf` aligns the frame before encoding it.
        PhysAddr::new(self.0 & ADDR_4K)
    }

    fn flags(self, level: u8) -> PageFlags {
        if !self.is_present() {
            return PageFlags::empty();
        }

        // A PDPTE has no permission bits at all — the three the format would spend on
        // them are reserved — so it constrains nothing about the subtree beneath it.
        // Reporting "read-only, supervisor-only" because the bits read as zero would
        // be a lie about the hardware, and a walker that intersects permissions down
        // the tree would act on it.
        if level >= PDPT_LEVEL {
            return PageFlags::READ | PageFlags::WRITE | PageFlags::EXECUTE | PageFlags::USER;
        }

        let mut f = PageFlags::READ;
        if self.0 & WRITABLE != 0 {
            f = f | PageFlags::WRITE;
        }
        if self.0 & USER != 0 {
            f = f | PageFlags::USER;
        }
        // Bit 63 reads as zero on a CPU without NX and on every entry we built while
        // NXE was clear, so "no bit" means executable in both cases.
        if self.0 & NO_EXECUTE == 0 {
            f = f | PageFlags::EXECUTE;
        }
        if self.is_leaf(level) && self.0 & GLOBAL != 0 {
            f = f | PageFlags::GLOBAL;
        }
        if self.0 & CACHE_DISABLE != 0 {
            // PCD alone is uncached; PCD with PWT is the strongly-ordered form a
            // device window needs, which is how `leaf` encodes DEVICE.
            let cache = if self.0 & WRITE_THROUGH != 0 {
                PageFlags::DEVICE
            } else {
                PageFlags::NO_CACHE
            };
            f = f | cache;
        }
        f
    }
    /// A PDPT entry (level 2) carries the present bit and the cache bits and nothing
    /// else — bits 1 and 2 are reserved there and setting them faults on the write to
    /// CR3 — while a page directory entry (level 1) needs R/W and U/S set or every
    /// leaf beneath it is capped read-only and supervisor-only.
    ///
    /// This port is why `table` takes a level at all. Before it did, the only
    /// possible implementation returned the level-1 encoding unconditionally, and a
    /// shared walker writing that into a PDPT slot produced a root that #GPs the
    /// instant it is installed.
    fn table(table: PhysAddr, level: u8) -> Entry {
        Entry::table_at(table, level)
    }

    fn leaf(frame: PhysAddr, flags: PageFlags, level: u8) -> Entry {
        let (addr, size_bit) = match level {
            0 => (frame.raw() & ADDR_4K, 0),
            1 => (frame.raw() & ADDR_2M, PAGE_SIZE_BIT),
            // `leaf_allowed` says no leaf lives here. There is no error channel on
            // this constructor, so an absent entry is the answer: a mapping that is
            // visibly missing beats one that is present and wrong.
            _ => return Entry(0),
        };

        let mut bits = addr | PRESENT | size_bit | Entry::cache_bits(flags);
        if flags.contains(PageFlags::WRITE) {
            bits |= WRITABLE;
        }
        if flags.contains(PageFlags::USER) {
            bits |= USER;
        }
        if flags.contains(PageFlags::GLOBAL) {
            bits |= GLOBAL;
        }
        // READ is not encoded: a present entry is readable on x86, and there is no
        // read-disable bit to spend on it.
        if !flags.contains(PageFlags::EXECUTE) && NXE.load(Ordering::Relaxed) {
            bits |= NO_EXECUTE;
        }
        Entry(bits)
    }
}

impl HasPageTables for I686 {
    fn can_forbid_execute() -> bool {
        // False on QEMU's default 32-bit CPU, which has no NX: the i686-qemu preset can
        // enforce the no-write half of W^X and not the no-execute half.
        nx_enabled()
    }

    fn root_load_caches(level: u8) -> bool {
        // The PDPT, level 2. Its four entries are loaded into the CPU with CR3 and not
        // walked again (SDM Vol. 3A, 4.4.1), so a new page directory under it is not
        // seen until CR3 is reloaded.
        level == 2
    }

    type Entry = Entry;

    fn index_bits(level: u8) -> u8 {
        match level {
            0 | 1 => 9,
            PDPT_LEVEL => 2,
            // Past the root. Zero rather than a plausible number, so that arithmetic
            // built on it produces something obviously wrong rather than subtly so.
            _ => 0,
        }
    }

    fn leaf_allowed(level: u8) -> bool {
        // 4 KiB in the page table, 2 MiB in the page directory. PDPTE.PS is a
        // long-mode field; in PAE it is reserved, so there is no 1 GiB page to allow.
        level <= 1
    }

    fn is_canonical(_addr: usize) -> bool {
        // 2 + 9 + 9 index bits plus a 12-bit offset is exactly 32, so every value a
        // `usize` can hold on this target is a translatable address. There is no
        // sign-extended hole the way x86-64 has one between 0x0000_7fff_ffff_ffff and
        // 0xffff_8000_0000_0000, because the tree covers the whole space. Always
        // true, and stated rather than assumed so that nobody has to rediscover why.
        true
    }

    unsafe fn set_root(root: PhysAddr) {
        // # Safety (in addition to the trait's contract)
        // In PAE, CR3 holds the *PDPT's* physical address in bits 31..=5 — so the
        // root must be below 4 GiB and 32-byte aligned, even though a leaf frame need
        // not be. The hardware ignores the low five bits; a root above 4 GiB cannot
        // be expressed at all, and rather than install a truncated address (which
        // would point at the wrong page and fault on the next instruction fetch) this
        // leaves the current table in place. `root()` reports what actually took.
        let Ok(base) = u32::try_from(root.raw()) else {
            return;
        };
        // The double-fault task loads CR3 from its TSS, so it has to name these tables
        // before they are live, or a double fault would switch to tables nobody runs on.
        crate::tss::follow_root(base);
        // SAFETY: the caller guarantees `base` names a well formed PDPT that maps the
        // running code and stack. Loading CR3 flushes every non-global TLB entry and,
        // in PAE specifically, re-reads the four PDPTEs into the CPU's internal
        // registers — which is why it is also the only way to make a PDPT edit take
        // effect. Not `nomem`: this changes what every subsequent memory access
        // means, and the compiler must not move accesses across it.
        unsafe {
            core::arch::asm!("mov cr3, {}", in(reg) base, options(nostack, preserves_flags));
        }
    }

    fn root() -> PhysAddr {
        // Bits 4..=0 are ignored by the hardware and are not part of the address.
        PhysAddr::new(u64::from(read_cr3() & 0xFFFF_FFE0))
    }

    unsafe fn flush_tlb(addr: Option<usize>) {
        match addr {
            Some(a) => {
                // SAFETY: `invlpg` invalidates the translation for one linear address
                // and has no other effect; it is legal at ring 0 on every i686. The
                // caller owns the ordering contract. Note what this does *not* do:
                // the four PDPTEs the CPU cached at CR3-load time are not re-read, so
                // an edit to the PDPT needs `flush_tlb(None)` and nothing less.
                unsafe {
                    core::arch::asm!("invlpg [{}]", in(reg) a, options(nostack, preserves_flags));
                }
            }
            None => {
                let cr3 = read_cr3();
                // SAFETY: rewriting CR3 with the value it already holds flushes every
                // non-global entry and re-reads the PDPTEs. The table it names is the
                // one currently in use, so the address space does not change.
                unsafe {
                    core::arch::asm!("mov cr3, {}", in(reg) cr3, options(nostack, preserves_flags));
                }
            }
        }
    }
}

/// CR3 as the CPU holds it, address bits and all.
pub(crate) fn read_cr3() -> u32 {
    let v: u32;
    // SAFETY: reading a control register at ring 0 has no side effects.
    unsafe {
        core::arch::asm!("mov {}, cr3", out(reg) v, options(nomem, nostack, preserves_flags));
    }
    v
}
/// Set `CR0.WP`, and report whether it took.
///
/// With WP clear, a supervisor write to a page whose R/W bit is 0 **succeeds
/// silently**. Every read-only mapping the kernel makes for itself — `.rodata`, a
/// guard page, a W^X split — is then decorative, and the first symptom is not a fault
/// but the absence of one. The x86-64 port shipped with this bit clear and its
/// read-only check printed "NO FAULT" the first time it ran; this port had the same
/// hole and no check to notice, which is the more interesting half of the story.
///
/// Safe to call at exactly this point: everything currently mapped is writable, so
/// turning the bit on cannot fault anything already in flight.
///
/// Read back rather than assumed, for the same reason as NXE.
pub fn enable_write_protect() -> bool {
    // SAFETY: CR0 is readable and writable at CPL 0, which is where the kernel runs.
    // Setting WP changes only whether supervisor writes honour the R/W bit; it does
    // not alter any mapping.
    unsafe {
        let mut cr0: u32;
        core::arch::asm!("mov {}, cr0", out(reg) cr0, options(nomem, nostack, preserves_flags));
        cr0 |= 1 << 16;
        core::arch::asm!("mov cr0, {}", in(reg) cr0, options(nomem, nostack, preserves_flags));
        let check: u32;
        core::arch::asm!("mov {}, cr0", out(reg) check, options(nomem, nostack, preserves_flags));
        check & (1 << 16) != 0
    }
}

/// Turn on the two CPU features every later permission decision depends on.
///
/// Called from `_start`, immediately after paging comes up and before `kmain`, because
/// both answers have to be settled *before* anything builds a mapping it expects to be
/// enforced. `EFER.NXE` decides whether [`Entry::leaf`] may emit bit 63 at all, and
/// `CR0.WP` decides whether a clear R/W bit binds supervisor code; a page table built
/// while either is still off is decorative, and the symptom is the absence of a fault
/// rather than the presence of one. They used to be enabled inside [`selftest`], which
/// runs well after the kernel has built the address space it means to protect.
///
/// Safe at this point specifically: every page the early map covers is writable and
/// executable, so neither bit can fault anything already in flight. Both calls are
/// idempotent, so [`selftest`] still calls them and still reports what took.
///
/// `extern "C"` with a fixed symbol name because its only caller is the assembly in
/// `boot.rs`; nothing in the kernel above `arch` names it.
#[unsafe(no_mangle)]
pub extern "C" fn i686_early_mmu_init() {
    enable_nx();
    enable_write_protect();
}

/// Whether `CR0.WP` is set, so a clear R/W bit binds the kernel too.
pub fn write_protect_enabled() -> bool {
    // SAFETY: reading CR0 at CPL 0 has no side effects.
    unsafe {
        let cr0: u32;
        core::arch::asm!("mov {}, cr0", out(reg) cr0, options(nomem, nostack, preserves_flags));
        cr0 & (1 << 16) != 0
    }
}

/// Turn on `EFER.NXE` if the CPU has it, and report whether bit 63 is now usable.
///
/// Asks CPUID before touching the MSR on purpose. `EFER` is an AMD64 extension that a
/// genuine i686 need not implement at all, and `rdmsr` on a nonexistent MSR is #GP —
/// which, on the path this runs from, is a #GP with no IDT installed and therefore a
/// triple fault. Leaf `0x8000_0001` EDX bit 20 is the architectural "NX exists, and so
/// does the EFER that gates it" answer.
///
/// Idempotent: a second call re-reads the MSR and reaches the same conclusion.
pub fn enable_nx() -> bool {
    // Leaf 0x80000000 is defined on every CPU that has extended leaves at all, and
    // returns the largest *basic* leaf on those that do not — a small number, which
    // fails the comparison below rather than being mistaken for support. `__cpuid` is
    // safe on this target: the instruction exists unconditionally on i686 and has no
    // effect beyond its four output registers.
    let max_ext = core::arch::x86::__cpuid(0x8000_0000).eax;
    if max_ext < 0x8000_0001 {
        return false;
    }
    let features = core::arch::x86::__cpuid(0x8000_0001).edx;
    if features & (1 << 20) == 0 {
        return false;
    }

    // MSR 0xC0000080, EFER. Bit 11 is NXE.
    let (lo, hi) = read_efer();
    write_efer(lo | (1 << 11), hi);
    // Read back rather than assume. A hypervisor that advertises NX and silently
    // masks the write would otherwise leave us emitting a reserved bit into every
    // non-executable mapping, and the first symptom would be a page fault on kernel
    // data.
    let live = read_efer().0 & (1 << 11) != 0;
    NXE.store(live, Ordering::Relaxed);
    live
}

/// Whether entries built from here on may carry the execute-disable bit.
pub fn nx_enabled() -> bool {
    NXE.load(Ordering::Relaxed)
}

/// EFER, as a low/high dword pair.
fn read_efer() -> (u32, u32) {
    let (lo, hi): (u32, u32);
    // SAFETY: reached only after CPUID confirmed the NX feature, which implies the
    // extended feature MSR exists. `rdmsr` reads; it changes nothing.
    unsafe {
        core::arch::asm!(
            "rdmsr",
            in("ecx") 0xC000_0080u32,
            out("eax") lo,
            out("edx") hi,
            options(nomem, nostack, preserves_flags)
        );
    }
    (lo, hi)
}

/// Write EFER. Only ever called with a value read back from [`read_efer`] plus NXE.
fn write_efer(lo: u32, hi: u32) {
    // SAFETY: reached only after CPUID confirmed the MSR exists, and the value
    // written is the one just read with a single defined bit added — no other field,
    // in particular not LME or SCE, is disturbed.
    unsafe {
        core::arch::asm!(
            "wrmsr",
            in("ecx") 0xC000_0080u32,
            in("eax") lo,
            in("edx") hi,
            options(nostack, preserves_flags)
        );
    }
}

/// Store `entry` into a table slot without ever publishing a torn one.
///
/// An entry is 64 bits and this machine stores 32 at a time. On a table the CPU is
/// already walking, the window between the two halves is real: a walker that catches
/// the new low dword with the old high dword sees a present entry naming a frame that
/// was never mapped. Clearing the present bit first makes the only visible
/// intermediate state "absent", which a walker handles correctly.
///
/// # Safety
/// `slot` must be a live, 8-byte-aligned page table slot the caller owns, reachable
/// through the current mapping.
unsafe fn store_entry(slot: *mut u64, entry: Entry) {
    let lo = slot.cast::<u32>();
    // SAFETY: `slot` is an aligned 8-byte object by the caller's contract, so its
    // second dword is in bounds. Little-endian: the low dword, holding the present
    // bit, is first.
    let hi = unsafe { lo.add(1) };
    // SAFETY: as above; volatile because the page table walker is a second observer
    // the compiler does not model, and the order of these three stores is the whole
    // point of this function.
    unsafe {
        lo.write_volatile(0);
        hi.write_volatile((entry.bits() >> 32) as u32);
        lo.write_volatile(entry.bits() as u32);
    }
}

/// Read a table slot back as an entry.
///
/// # Safety
/// `slot` must be a live, 8-byte-aligned page table slot reachable through the
/// current mapping.
unsafe fn load_entry(slot: *const u64) -> Entry {
    // SAFETY: the caller guarantees the slot is live and aligned. Volatile so the
    // read is not folded away against the store that preceded it — which would turn
    // the round-trip check below into a tautology about a register.
    Entry::from_bits(unsafe { slot.read_volatile() })
}

// ---------------------------------------------------------------------------
// The self test
// ---------------------------------------------------------------------------

/// The tables the selftest builds, and the memory it maps through them.
///
/// One allocation so that the whole set is contiguous and page aligned by
/// construction: every field is a multiple of 4096 bytes and the struct is
/// 4096-aligned, so each table starts on its own page without any per-field
/// attribute. There is no frame allocator in `arch` — `kernel/mm` owns that and an
/// `arch` unit may not depend on a `core` unit — so the tables are statically
/// reserved rather than allocated. Twenty-eight kilobytes of `.bss`, once.
#[repr(C, align(4096))]
struct Tables {
    /// The root. Four entries are read by the CPU; the page exists so that CR3's
    /// 32-byte alignment requirement holds by construction and with room to spare.
    pdpt: [u64; 512],
    /// Four page directories, identity-mapping the low 4 GiB with 2 MiB leaves —
    /// the same map `boot.rs` builds in assembly, rebuilt here through the contract.
    pd: [[u64; 512]; 4],
    /// One page table, backing the 2 MiB window the aliasing test needs.
    pt: [u64; 512],
    /// Two frames of scratch memory, mapped and written through the new tables.
    scratch: [u32; 2048],
}

/// The tables as a static with interior mutability.
///
/// `static mut` is forbidden (`docs/coding-standards.md`), and these must be writable
/// while they are built and then live at a fixed physical address for as long as the
/// CPU walks them. Same shape as `idt.rs`, for the same reason.
struct TablesCell(UnsafeCell<Tables>);

// SAFETY: single-writer-then-installed. `selftest` is the only writer, runs once
// during early boot on the one CPU that exists, with interrupts masked, and nothing
// else in the image knows this static exists. After installation the CPU reads it and
// the kernel does not write it.
unsafe impl Sync for TablesCell {}

static TABLES: TablesCell = TablesCell(UnsafeCell::new(Tables {
    pdpt: [0; 512],
    pd: [[0; 512]; 4],
    pt: [0; 512],
    scratch: [0; 2048],
}));

/// The 2 MiB of linear address space the test maps by hand.
///
/// The last 2 MiB below 4 GiB. Deliberately not somewhere in the low half: under the
/// identity map that is live when the test starts, this window translates to the PCI
/// hole rather than to RAM, so a read that succeeds there cannot be the identity map
/// answering by accident.
const WINDOW: usize = 0xFFE0_0000;
/// First alias of the test frame.
const ALIAS_A: usize = WINDOW;
/// Second alias of the same frame, one page along and a separate page table entry.
const ALIAS_B: usize = WINDOW + 4096;
/// Where the wide-physical entry is parked: mapped by the same page table, never
/// walked, because nothing reads this address.
const WIDE_SLOT: usize = 3;
/// Page table slot used by the above-4-GiB probe.
const HIGH_SLOT: usize = 4;
/// The linear address that probe is reached through.
const HIGH_ALIAS: usize = WINDOW + HIGH_SLOT * 4096;

/// A 36-bit physical address that does not fit in a `usize` on this target.
///
/// Just under 1 TiB. Every bit above 32 is significant, so an encoder that stored the
/// entry as a 32-bit word, or a decoder that read one, loses it visibly.
const WIDE_PHYS: u64 = 0x0000_000F_1234_5000;

/// Bring up kernel-built page tables and prove they translate.
///
/// Returns `true` only for things observed. The interesting part is the aliasing
/// check: one frame is mapped at two linear addresses two pages apart, a value is
/// written through the first and read back through the second, and both are compared
/// against the frame's identity-mapped address. Nothing about that can succeed by
/// accident — the identity map alone would have `ALIAS_A` land in the PCI hole.
///
/// Runs before the IDT is loaded, which sets the standard of care: a fault here is a
/// triple fault with no diagnostic, so the new tables identity-map everything the old
/// ones did before CR3 is touched, and the only mapping that changes is a 2 MiB window
/// no code or data lives in.
pub fn selftest(c: &dyn EarlyConsole) -> bool {
    // Both were already settled by `i686_early_mmu_init` on the way out of `_start`;
    // both are idempotent, and asking again is how this line reports what the CPU
    // actually agreed to rather than what was requested of it. Without WP a read-only
    // mapping does not bind the kernel at all, so every protection the kernel makes
    // for itself would report success while enforcing nothing.
    let nx = enable_nx();
    let wp = enable_write_protect();

    let geometry_ok = check_geometry(c, nx);
    c.write_str(if wp { ", WP on" } else { ", WP UNAVAILABLE" });
    let root = build();

    // SAFETY: `build` has just written a complete PAE hierarchy whose four PDPTEs
    // carry the present bit alone, whose page directories identity-map the low 4 GiB
    // with 2 MiB leaves — covering the running code at 1 MiB, the boot stack, this
    // static, and the multiboot info block — and whose one page table covers a window
    // nothing lives in. The root is in `.bss` inside the kernel image, so it is below
    // 4 GiB and page aligned, which is more than CR3 asks for.
    unsafe { I686::set_root(root) };

    let installed = I686::root() == root;
    c.write_str("\n             root   ");
    write_phys(c, I686::root());
    c.write_str(" in CR3, ");
    write_dec(c, 1 << u32::from(I686::index_bits(PDPT_LEVEL)));
    c.write_str(" PDPTEs");
    if !installed {
        c.write_str(" (NOT the table we built)");
        return false;
    }

    let alias_ok = check_alias(c);
    let flush_ok = check_flush(c);
    let wide_ok = check_wide_phys(c);
    let high_ok = check_above_4gib(c);

    geometry_ok && alias_ok && flush_ok && wide_ok && high_ok
}

/// Report the geometry and check it against the shared helpers in `hal::paging`.
///
/// Worth checking rather than only printing: `level_size` and `level_index` are the
/// arithmetic the shared walker runs, and PAE is the format where a uniform-levels
/// assumption in either of them would show up. If 1 GiB per PDPTE and 2 MiB per PDE
/// do not fall out of `index_bits`, the contract is not describing this machine.
fn check_geometry(c: &dyn EarlyConsole, nx: bool) -> bool {
    c.write_str("PAE ");
    write_dec(c, u32::from(I686::index_bits(2)));
    c.write_str("+");
    write_dec(c, u32::from(I686::index_bits(1)));
    c.write_str("+");
    write_dec(c, u32::from(I686::index_bits(0)));
    c.write_str("+12 bits, NX ");
    c.write_str(if nx { "on" } else { "unavailable" });

    let sizes_ok = level_size::<I686>(0) == I686::PAGE_SIZE
        && level_size::<I686>(1) == 2 * 1024 * 1024
        && level_size::<I686>(2) == 1024 * 1024 * 1024
        && I686::leaf_allowed(0)
        && I686::leaf_allowed(1)
        && !I686::leaf_allowed(2)
        && I686::is_canonical(usize::MAX)
        && <I686 as HasMmu>::LEVELS == 3;
    if !sizes_ok {
        c.write_str(" (geometry disagrees with hal::paging)");
    }
    sizes_ok
}

/// Build the hierarchy and return the physical address of its root.
///
/// Rebuilds the identity map rather than reusing `boot.rs`'s: the point is to exercise
/// the entry encoders, and a map built through [`Entry::leaf`] that keeps the machine
/// running is a stronger statement than one inherited from assembly.
fn build() -> PhysAddr {
    let t = TABLES.0.get();
    // SAFETY: the single writer, per the invariant on `TablesCell`. Raw pointers
    // throughout rather than a `&mut Tables`, so that no reference to the whole
    // structure exists while the CPU may be reading part of it.
    let pdpt = unsafe { (&raw mut (*t).pdpt).cast::<u64>() };
    // SAFETY: as above.
    let pd = unsafe { (&raw mut (*t).pd).cast::<u64>() };
    // SAFETY: as above.
    let pt = unsafe { (&raw mut (*t).pt).cast::<u64>() };

    // Identity-map the low 4 GiB with 2 MiB leaves: 2048 entries across the four
    // directories, which are contiguous, so one linear walk covers all of them.
    // Writable and executable, because the running kernel's text, data and stack are
    // all inside it and this is not the moment to start enforcing W^X.
    let flags = PageFlags::READ | PageFlags::WRITE | PageFlags::EXECUTE;
    let mut i = 0usize;
    while i < 2048 {
        let phys = PhysAddr::new((i as u64) << 21);
        // SAFETY: `i` is below 2048 and `pd` points at `[[u64; 512]; 4]`, which is
        // exactly 2048 entries laid out contiguously.
        unsafe { store_entry(pd.add(i), Entry::leaf(phys, flags, 1)) };
        i += 1;
    }

    // Four PDPT entries, one per directory. `table_at` at level 2 emits the present
    // bit alone; anything else here faults on the `mov` to CR3 below.
    let mut k = 0usize;
    while k < 4 {
        // SAFETY: `k` is below 4 and each directory is 512 entries of 8 bytes.
        let dir = unsafe { pd.add(k * 512) };
        // SAFETY: `k` is below 4, well inside the 512-entry PDPT page.
        unsafe { store_entry(pdpt.add(k), Entry::table_at(phys_of(dir), PDPT_LEVEL)) };
        k += 1;
    }

    // Replace the 2 MiB leaf covering WINDOW with a pointer to the page table. The
    // indices come from the shared helpers, not from hand arithmetic, so that a
    // mistake in the contract's index maths shows up as a triple fault in the one
    // place that is looking for it rather than silently in the walker later.
    let top = level_index::<I686>(WINDOW, 2);
    let mid = level_index::<I686>(WINDOW, 1);
    // SAFETY: `top` is below 4 and `mid` below 512 by construction of `level_index`
    // with 2 and 9 index bits, so the product is inside the 2048-entry array. PDPT
    // entry `top` points at directory `top`, which is what makes this the right slot.
    unsafe { store_entry(pd.add(top * 512 + mid), Entry::table_at(phys_of(pt), 1)) };

    // The page table itself: absent everywhere except the two aliases.
    let mut j = 0usize;
    while j < 512 {
        // SAFETY: `j` is below the table's 512 entries.
        unsafe { store_entry(pt.add(j), Entry::empty()) };
        j += 1;
    }
    let frame0 = scratch_phys(0);
    // SAFETY: entries 0 and 1 are inside the page table.
    unsafe {
        store_entry(pt, Entry::leaf(frame0, PageFlags::KERNEL_DATA, 0));
        store_entry(pt.add(1), Entry::leaf(frame0, PageFlags::KERNEL_DATA, 0));
    }

    phys_of(pdpt)
}

/// Write through one alias and read through the other, both ways.
fn check_alias(c: &dyn EarlyConsole) -> bool {
    const FIRST: u32 = 0x5AA5_1234;
    const SECOND: u32 = 0xDEAD_BEEF;

    let a = ALIAS_A as *mut u32;
    let b = ALIAS_B as *mut u32;

    // SAFETY: both linear addresses are mapped by the page table just installed, to
    // the first scratch frame, writable. Volatile because the whole question is
    // whether two addresses the compiler believes are unrelated reach the same
    // memory — a non-volatile round trip would be answered from a register.
    let (via_b, via_ident, via_a) = unsafe {
        a.write_volatile(FIRST);
        let via_b = b.read_volatile();
        let via_ident = scratch_ptr(0).read_volatile();
        b.write_volatile(SECOND);
        (via_b, via_ident, a.read_volatile())
    };

    let ok = via_b == FIRST && via_ident == FIRST && via_a == SECOND;
    c.write_str("\n             alias  ");
    write_hex32(c, ALIAS_A);
    c.write_str(" and ");
    write_hex32(c, ALIAS_B);
    c.write_str(" -> ");
    write_phys(c, scratch_phys(0));
    if ok {
        c.write_str(", both directions");
    } else {
        c.write_str(", NOT aliased (");
        write_hex32(c, via_b as usize);
        c.write_str("/");
        write_hex32(c, via_ident as usize);
        c.write_str("/");
        write_hex32(c, via_a as usize);
        c.write_str(")");
    }
    ok
}

/// Re-point one alias at a different frame and prove `invlpg` published the change.
///
/// The previous check left a live, cached translation for `ALIAS_B`. Overwriting the
/// entry without flushing would leave the stale one in the TLB and the read below
/// would return the old frame's contents — so this tests the flush, not just the
/// store. The two frames hold distinct values written through the identity map, so
/// neither answer can be mistaken for the other.
fn check_flush(c: &dyn EarlyConsole) -> bool {
    const MARK: u32 = 0x0FF1_CE55;

    // SAFETY: the second scratch frame is identity-mapped (it is inside the kernel
    // image, which the new tables map with 2 MiB leaves) and owned by this module.
    unsafe { scratch_ptr(1024).write_volatile(MARK) };

    let t = TABLES.0.get();
    // SAFETY: single writer, as above.
    let pt = unsafe { (&raw mut (*t).pt).cast::<u64>() };
    // SAFETY: entry 1 is inside the page table, which is live but is not being walked
    // by anything else — this is a uniprocessor with interrupts masked.
    unsafe {
        store_entry(pt.add(1), Entry::leaf(scratch_phys(1024), PageFlags::KERNEL_DATA, 0));
    }
    // SAFETY: the store above is complete and this CPU is the only observer, so the
    // ordering the trait asks the caller to guarantee is satisfied by program order.
    unsafe { I686::flush_tlb(Some(ALIAS_B)) };

    // SAFETY: `ALIAS_B` is mapped, now to the second scratch frame.
    let seen = unsafe { (ALIAS_B as *const u32).read_volatile() };
    let ok = seen == MARK;

    c.write_str("\n             invlpg ");
    write_hex32(c, ALIAS_B);
    c.write_str(" -> ");
    write_phys(c, scratch_phys(1024));
    if ok {
        c.write_str(", new frame visible");
    } else {
        c.write_str(", stale (read ");
        write_hex32(c, seen as usize);
        c.write_str(")");
    }
    ok
}

/// Round-trip a 36-bit physical address through a live page table entry.
///
/// This is the check this target exists for. `WIDE_PHYS` needs every one of its 36
/// bits, so it survives only if the entry really is a 64-bit word and the address
/// field really is bits 12..=35 — an encoder that took a `usize` would have truncated
/// it at the call, and `PhysAddr::to_usize` refusing it is the same fact stated by the
/// type system.
///
/// What this does **not** do is translate through it. QEMU's `pc` machine is started
/// with 128 MiB, so there is no frame above 4 GiB to map and nothing to read back
/// through such a mapping; the entry is written into the live page table at a slot
/// nothing reads, decoded back out of table memory, and then removed. On a machine
/// with memory up there the same entry is what `Entry::leaf` would produce for it.
fn check_wide_phys(c: &dyn EarlyConsole) -> bool {
    let wide = PhysAddr::new(WIDE_PHYS);
    let entry = <Entry as PageTableEntry>::leaf(wide, PageFlags::KERNEL_DATA, 0);

    let t = TABLES.0.get();
    // SAFETY: single writer, per the invariant on `TablesCell`.
    let pt = unsafe { (&raw mut (*t).pt).cast::<u64>() };
    // SAFETY: `WIDE_SLOT` is inside the 512-entry page table, and no linear address
    // it would translate is read by anything, so the CPU never walks it.
    let read_back = unsafe {
        store_entry(pt.add(WIDE_SLOT), entry);
        let back = load_entry(pt.add(WIDE_SLOT).cast_const());
        // Put it back the way it was found: a present entry naming memory that is not
        // there is not something to leave lying in a live table.
        store_entry(pt.add(WIDE_SLOT), Entry::empty());
        back
    };
    // SAFETY: the entry above is gone; nothing may keep a cached translation for it.
    unsafe { I686::flush_tlb(Some(WINDOW + WIDE_SLOT * 4096)) };

    let ok = read_back.address() == wide
        && read_back.is_present()
        && read_back.is_leaf(0)
        && read_back.bits() >> 32 != 0
        && wide.to_usize().is_err()
        && read_back.flags(0).contains(PageFlags::WRITE);

    c.write_str("\n             36-bit ");
    write_phys(c, read_back.address());
    if ok {
        c.write_str(" round-trips through a live PTE, and no usize holds it");
    } else {
        c.write_str(" is NOT what went in (");
        write_phys(c, wide);
        c.write_str(")");
    }
    ok
}

/// Prove that bit 32 of a physical address reaches the MMU, not just the encoder.
///
/// [`check_wide_phys`] shows the *software* keeps 36 bits. This shows the hardware
/// does, and it works on a machine with only 128 MiB of RAM, which is the situation
/// CI is actually in.
///
/// The trick is to pick a probe address whose low 32 bits name a frame we own and can
/// recognise: exactly 4 GiB above the first scratch frame. That frame is filled with a
/// known value first. Then the probe address is mapped and read:
///
/// * reading the known value back means bit 32 was dropped somewhere between `PhysAddr` and the
///   page table walker, and the mapping landed on the low frame — which is precisely the
///   `usize`-as-physical-address bug, caught in the act;
/// * reading anything else means the translation went 4 GiB up, where this machine has no RAM and
///   an unclaimed read returns all-ones.
///
/// If the machine *does* have memory up there, the second write below round-trips and
/// the probe becomes a genuine above-4-GiB mapping rather than a negative result. The
/// verdict says which of the two happened rather than blurring them: with `-m 128M`
/// the honest answer is "no RAM up there, but truncation is ruled out", and with
/// `-m 5G` it is "written and read back".
fn check_above_4gib(c: &dyn EarlyConsole) -> bool {
    const DECOY: u32 = 0xC0DE_F00D;
    const PROBE: u32 = 0x2468_ACE0;

    let low = scratch_phys(0);
    let Ok(high) = low.checked_add(1u64 << 32) else {
        c.write_str("\n             >4GiB  scratch frame is too high to offset");
        return false;
    };

    // SAFETY: the first scratch frame is identity-mapped and owned by this module.
    unsafe { scratch_ptr(0).write_volatile(DECOY) };

    let t = TABLES.0.get();
    // SAFETY: single writer, per the invariant on `TablesCell`.
    let pt = unsafe { (&raw mut (*t).pt).cast::<u64>() };
    // SAFETY: `HIGH_SLOT` is inside the 512-entry page table.
    unsafe { store_entry(pt.add(HIGH_SLOT), Entry::leaf(high, PageFlags::KERNEL_DATA, 0)) };
    // SAFETY: the store is complete and this CPU is the only observer.
    unsafe { I686::flush_tlb(Some(HIGH_ALIAS)) };

    // SAFETY: `HIGH_ALIAS` is now mapped. The physical address behind it is either
    // RAM or unclaimed; an unclaimed *read* on a PC is a master abort that returns
    // all-ones, not a fault, and the MMU is satisfied either way because 36 bits is
    // what PAE entries are architecturally allowed to carry.
    let seen = unsafe { (HIGH_ALIAS as *const u32).read_volatile() };
    let truncated = seen == DECOY;

    // Only if the probe demonstrably did not land on our low frame is it worth asking
    // whether real memory is up there — and only then is the write below going
    // somewhere that is not a frame we are using for something else. The word is put
    // back as it was found: on a machine that does have this memory it is an ordinary
    // free frame the allocator will hand to somebody, and a selftest has no business
    // leaving a mark in it.
    // SAFETY: as above for the read; the writes go to the same mapped page.
    let backed = !truncated
        && unsafe {
            (HIGH_ALIAS as *mut u32).write_volatile(PROBE);
            let ok = (HIGH_ALIAS as *const u32).read_volatile() == PROBE
                && scratch_ptr(0).read_volatile() == DECOY;
            (HIGH_ALIAS as *mut u32).write_volatile(seen);
            ok
        };

    // SAFETY: `HIGH_SLOT` is inside the page table; the probe mapping has served its
    // purpose and a live entry naming possibly-absent memory is not worth keeping.
    unsafe { store_entry(pt.add(HIGH_SLOT), Entry::empty()) };
    // SAFETY: the entry is gone, so no cached translation for it may survive.
    unsafe { I686::flush_tlb(Some(HIGH_ALIAS)) };

    c.write_str("\n             >4GiB  ");
    write_phys(c, high);
    if truncated {
        c.write_str(" TRUNCATED to ");
        write_phys(c, low);
    } else if backed {
        c.write_str(" written and read back: real memory above 4 GiB");
    } else {
        c.write_str(" reaches the MMU intact (no RAM there to read)");
    }
    !truncated
}

/// The physical address of something in the kernel image.
///
/// Valid because the low 4 GiB is identity-mapped, both by the table `boot.rs` builds
/// and by the one this module installs, so a linear address inside the image is its
/// own physical address. Phase 1 moves the kernel to the high half and this becomes a
/// subtraction against the image's load offset — which is precisely why it is one
/// function and not a cast repeated at six call sites.
fn phys_of<T>(p: *const T) -> PhysAddr {
    PhysAddr::new(p as usize as u64)
}

/// A pointer into the scratch area, `offset` 32-bit words along.
fn scratch_ptr(offset: usize) -> *mut u32 {
    let t = TABLES.0.get();
    // SAFETY: the scratch field is 2048 words and callers pass 0 or 1024, both in
    // bounds. Taken as a raw pointer so no reference to the whole `Tables` exists.
    unsafe { (&raw mut (*t).scratch).cast::<u32>().add(offset) }
}

/// The physical address of the scratch frame `offset` words in.
fn scratch_phys(offset: usize) -> PhysAddr {
    phys_of(scratch_ptr(offset).cast_const())
}

const HEX: &[u8; 16] = b"0123456789abcdef";

/// Write a physical address as nine hex digits — the full 36 bits, always.
///
/// `serial::write_hex` takes a `u32`, which is the right width for everything else
/// this port prints and exactly the wrong one here: truncating the address that this
/// whole module exists to keep wide would be a comic failure.
fn write_phys(c: &dyn EarlyConsole, p: PhysAddr) {
    let v = p.raw();
    let mut buf = [0u8; 11];
    buf[0] = b'0';
    buf[1] = b'x';
    for i in 0..9 {
        let shift = (8 - i) * 4;
        buf[2 + i] = HEX[((v >> shift) & 0xf) as usize];
    }
    c.write_bytes(&buf);
}

/// Write a linear address as eight hex digits.
fn write_hex32(c: &dyn EarlyConsole, v: usize) {
    let mut buf = [0u8; 10];
    buf[0] = b'0';
    buf[1] = b'x';
    for i in 0..8 {
        let shift = (7 - i) * 4;
        buf[2 + i] = HEX[((v >> shift) & 0xf) as usize];
    }
    c.write_bytes(&buf);
}

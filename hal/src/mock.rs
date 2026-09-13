//! Mock architectures for host-side testing.
//!
//! These exist so that a subsystem can be tested on a laptop in a second rather than
//! in an emulator in a minute — and, more importantly, so that the *same* test runs
//! against several hardware profiles. A scheduler tested only against a machine with
//! an MMU, SMP and atomics has not been tested against half the targets we claim.
//!
//! The rule this supports, from `docs/testing.md`: **a subsystem that cannot be
//! tested against `MockArch` has a design problem.**

use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use crate::paging::{HasPageTables, PageFlags, PageTableEntry};
use crate::*;

/// A full-featured machine: MMU, SMP, atomics, coherent DMA, floating point.
/// Models the x86_64 and aarch64 end of the range.
pub struct MockFull;

/// A minimal machine: memory protection regions but no translation, one CPU, and no
/// compare-and-swap. Models the ARMv6-M / rv32i end of the range.
///
/// Code that compiles against `MockFull` but not `MockTiny` is code that has silently
/// acquired a hardware requirement, which is exactly what we want to find out early.
pub struct MockTiny;

static FULL_IRQ: AtomicBool = AtomicBool::new(true);
static TINY_IRQ: AtomicBool = AtomicBool::new(true);

/// Counts barriers issued, so a test can assert that ordering was requested where the
/// memory model requires it. QEMU cannot check this and neither can a laptop; the
/// most we can do on the host is verify the call was made.
pub static BARRIERS: AtomicU64 = AtomicU64::new(0);

impl Arch for MockFull {
    const NAME: &'static str = "mock-full";
    const PAGE_SIZE: usize = 4096;
    const PHYS_ADDR_BITS: u8 = 52;
    const ENDIAN: Endian = Endian::Little;
    const UNALIGNED_ACCESS: bool = true;

    type IrqState = bool;

    fn irq_save() -> bool {
        FULL_IRQ.swap(false, Ordering::SeqCst)
    }

    unsafe fn irq_restore(state: bool) {
        FULL_IRQ.store(state, Ordering::SeqCst);
    }

    fn memory_barrier() {
        BARRIERS.fetch_add(1, Ordering::SeqCst);
    }

    fn halt() -> ! {
        panic!("MockFull::halt() — a host test asked the machine to stop");
    }
}

impl HasMmu for MockFull {
    const LEVELS: u8 = 4;
    const HUGE_PAGE_SIZES: &'static [usize] = &[2 * 1024 * 1024, 1024 * 1024 * 1024];
}

impl HasSmp for MockFull {
    fn cpu_id() -> u32 {
        0
    }
}

impl HasCas for MockFull {}
impl HasCoherentDma for MockFull {}

impl HasFpu for MockFull {
    type FpuState = ();
}

impl Arch for MockTiny {
    const NAME: &'static str = "mock-tiny";
    // A smaller page than the full mock, so anything that hardcoded 4096 shows up.
    const PAGE_SIZE: usize = 256;
    const PHYS_ADDR_BITS: u8 = 32;
    const ENDIAN: Endian = Endian::Little;
    // Deliberately false: unaligned access faults on this profile.
    const UNALIGNED_ACCESS: bool = false;

    type IrqState = bool;

    fn irq_save() -> bool {
        TINY_IRQ.swap(false, Ordering::SeqCst)
    }

    unsafe fn irq_restore(state: bool) {
        TINY_IRQ.store(state, Ordering::SeqCst);
    }

    fn memory_barrier() {
        BARRIERS.fetch_add(1, Ordering::SeqCst);
    }

    fn halt() -> ! {
        panic!("MockTiny::halt() — a host test asked the machine to stop");
    }
}

impl HasMpu for MockTiny {
    const REGIONS: usize = 8;
}

// SAFETY: `MockTiny` models an ARMv6-M-class part: one CPU, no `HasSmp` below, and
// an interrupt flag with no second processor behind it. Masking interrupts on it is
// therefore genuine mutual exclusion.
unsafe impl UniProcessor for MockTiny {}

// Note what MockTiny does NOT implement: HasMmu, HasSmp, HasCas, HasCoherentDma,
// HasFpu. Any subsystem generic over those simply cannot be instantiated with it,
// which is the compile-time half of the portability claim.

// ---- page tables ------------------------------------------------------------
//
// A software table format, deliberately resembling no real architecture. The point
// is to test the *walker* — the tree descent, table allocation, huge-page splitting
// and teardown that `mm::paged` does once for every target — without also testing
// x86's bit assignments. A mock that copied a real format would make a walker bug and
// an encoding bug look the same.

/// A mock page table entry.
///
/// bit 0 present, bit 1 leaf, bits 2..=8 the neutral `PageFlags`, address from bit 12.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct MockEntry(u64);

const M_PRESENT: u64 = 1 << 0;
const M_LEAF: u64 = 1 << 1;
const M_FLAG_SHIFT: u32 = 2;
const M_FLAG_MASK: u64 = 0x7F << M_FLAG_SHIFT;
const M_ADDR_MASK: u64 = !0xFFF;

impl PageTableEntry for MockEntry {
    fn empty() -> Self {
        MockEntry(0)
    }
    fn is_present(self) -> bool {
        self.0 & M_PRESENT != 0
    }
    fn is_leaf(self, _level: u8) -> bool {
        self.is_present() && self.0 & M_LEAF != 0
    }
    fn address(self) -> PhysAddr {
        PhysAddr::new(self.0 & M_ADDR_MASK)
    }
    fn flags(self, _level: u8) -> PageFlags {
        PageFlags::from_bits_truncate(((self.0 & M_FLAG_MASK) >> M_FLAG_SHIFT) as u16)
    }
    fn table(table: PhysAddr, _level: u8) -> Self {
        MockEntry((table.raw() & M_ADDR_MASK) | M_PRESENT)
    }
    fn leaf(frame: PhysAddr, flags: PageFlags, _level: u8) -> Self {
        MockEntry(
            (frame.raw() & M_ADDR_MASK)
                | M_PRESENT
                | M_LEAF
                | ((flags.bits() as u64) << M_FLAG_SHIFT),
        )
    }
}

static MOCK_ROOT: AtomicU64 = AtomicU64::new(0);

/// Counts TLB invalidations, so a test can assert the walker issued one. Forgetting
/// to flush is a bug that works perfectly until the stale translation is used.
pub static TLB_FLUSHES: AtomicUsize = AtomicUsize::new(0);
/// Counts full-address-space invalidations specifically.
pub static TLB_FLUSHES_ALL: AtomicUsize = AtomicUsize::new(0);

impl HasPageTables for MockFull {
    fn can_forbid_execute() -> bool {
        true
    }

    type Entry = MockEntry;

    fn index_bits(_level: u8) -> u8 {
        9
    }

    fn leaf_allowed(level: u8) -> bool {
        // 4 KiB, 2 MiB and 1 GiB, matching MockFull::HUGE_PAGE_SIZES.
        level <= 2
    }

    fn is_canonical(addr: usize) -> bool {
        // Mimics x86-64 deliberately: the walker must cope with an architecture that
        // rejects addresses in the middle of the range, and a mock that accepted
        // everything would never exercise that path.
        let sign = (addr >> 47) & 1;
        let high = addr >> 48;
        if sign == 1 { high == 0xFFFF } else { high == 0 }
    }

    unsafe fn set_root(root: PhysAddr) {
        MOCK_ROOT.store(root.raw(), Ordering::SeqCst);
    }

    fn root() -> PhysAddr {
        PhysAddr::new(MOCK_ROOT.load(Ordering::SeqCst))
    }

    unsafe fn flush_tlb(addr: Option<usize>) {
        TLB_FLUSHES.fetch_add(1, Ordering::SeqCst);
        if addr.is_none() {
            TLB_FLUSHES_ALL.fetch_add(1, Ordering::SeqCst);
        }
    }
}

// Note what is absent: no `impl HasPageTables for MockTiny`. It has no MMU, so a
// subsystem generic over page tables cannot be instantiated with it at all.

/// An interrupt controller that records what was asked of it.
pub struct MockIrqChip {
    enabled: AtomicU64,
    pub eois: AtomicU64,
}

impl Default for MockIrqChip {
    fn default() -> Self {
        Self::new()
    }
}

impl MockIrqChip {
    pub const fn new() -> Self {
        MockIrqChip {
            enabled: AtomicU64::new(0),
            eois: AtomicU64::new(0),
        }
    }

    pub fn is_enabled(&self, irq: IrqNumber) -> bool {
        irq.0 < 64 && self.enabled.load(Ordering::SeqCst) & (1 << irq.0) != 0
    }
}

impl IrqChip for MockIrqChip {
    unsafe fn init(&self) {
        self.enabled.store(0, Ordering::SeqCst);
    }

    fn enable(&self, irq: IrqNumber) {
        if irq.0 < 64 {
            self.enabled.fetch_or(1 << irq.0, Ordering::SeqCst);
        }
    }

    fn disable(&self, irq: IrqNumber) {
        if irq.0 < 64 {
            self.enabled.fetch_and(!(1 << irq.0), Ordering::SeqCst);
        }
    }

    fn claim(&self) -> Option<IrqNumber> {
        let bits = self.enabled.load(Ordering::SeqCst);
        (bits != 0).then(|| IrqNumber(bits.trailing_zeros()))
    }

    fn eoi(&self, _irq: IrqNumber) {
        self.eois.fetch_add(1, Ordering::SeqCst);
    }

    fn name(&self) -> &'static str {
        "mock-irqchip"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_two_profiles_differ_where_it_matters() {
        assert_ne!(MockFull::PAGE_SIZE, MockTiny::PAGE_SIZE);
        assert!(MockFull::UNALIGNED_ACCESS);
        assert!(!MockTiny::UNALIGNED_ACCESS);
    }

    #[test]
    fn irq_state_round_trips() {
        let saved = MockFull::irq_save();
        // SAFETY: paired with the save immediately above, on this thread.
        unsafe { MockFull::irq_restore(saved) };
        assert!(MockFull::irq_save());
        unsafe { MockFull::irq_restore(true) };
    }

    #[test]
    fn irqchip_tracks_enable_and_eoi() {
        let chip = MockIrqChip::new();
        // SAFETY: first initialisation of a local mock.
        unsafe { chip.init() };
        assert_eq!(chip.claim(), None);
        chip.enable(IrqNumber(3));
        assert!(chip.is_enabled(IrqNumber(3)));
        assert_eq!(chip.claim(), Some(IrqNumber(3)));
        chip.eoi(IrqNumber(3));
        assert_eq!(chip.eois.load(Ordering::SeqCst), 1);
        chip.disable(IrqNumber(3));
        assert_eq!(chip.claim(), None);
    }
}

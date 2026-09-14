//! The driver against the modelled unit: bring-up, mapping, translation, attach, and the
//! fault log.

use crate::harness::{FRCD_HIGH, IOTLB_CMD, MockFrames, MockMem, MockRegs};
use crate::{ADDR_MASK, Error, PAGE_SIZE, Perm, PhysMem, Regs, Unit, reg};

/// A unit over the modelled hardware, with `frames` frames to spend.
fn unit(frames: u64) -> (Unit<MockRegs, MockMem>, MockFrames) {
    let mut pool = MockFrames::new(frames);
    let unit = Unit::new(MockRegs::new(), MockMem::default(), &mut pool).expect("bring-up");
    (unit, pool)
}

#[test]
fn bring_up_reads_the_address_width_and_refuses_a_narrow_unit() {
    let (unit, _) = unit(64);
    assert_eq!(unit.max_address_width(), 48);
    assert!(!unit.enabled(), "translation is off until enable()");

    let mut pool = MockFrames::new(64);
    assert_eq!(
        Unit::new(MockRegs::narrow(), MockMem::default(), &mut pool).err(),
        Some(Error::AddressWidth)
    );
}

#[test]
fn enable_latches_the_root_table_and_turns_translation_on() {
    let (mut unit, _pool) = unit(64);
    unit.enable().unwrap();
    assert!(unit.enabled());
    // Both the root-pointer-set and translation-enable status bits are up.
    let gsts = unit.regs_for_test().read32(reg::GSTS);
    assert_ne!(gsts & reg::gsts::RTPS, 0, "root pointer latched");
    assert_ne!(gsts & reg::gsts::TES, 0, "translation enabled");
    unit.disable().unwrap();
    assert!(!unit.enabled());
}

#[test]
fn a_mapped_page_translates_and_an_unmapped_one_faults() {
    let (mut unit, mut pool) = unit(64);
    let domain = unit.new_domain(1, &mut pool).unwrap();
    let mem = unit.mem();

    // A grant of one writable page at an IOVA equal to its physical address.
    let phys = 0x4444_0000;
    domain
        .map(phys, phys, PAGE_SIZE, Perm::ReadWrite, mem, &mut pool)
        .unwrap();
    assert_eq!(domain.translate(phys, mem), Some((phys, true)));
    assert_eq!(
        domain.translate(phys + 0x123, mem),
        Some((phys + 0x123, true)),
        "the page offset is carried through"
    );
    // One page further is outside the grant: it faults.
    assert_eq!(domain.translate(phys + PAGE_SIZE, mem), None);
}

#[test]
fn a_read_only_grant_is_not_writable() {
    let (mut unit, mut pool) = unit(64);
    let domain = unit.new_domain(1, &mut pool).unwrap();
    let mem = unit.mem();
    let phys = 0x5000_0000;
    domain
        .map(phys, phys, PAGE_SIZE, Perm::Read, mem, &mut pool)
        .unwrap();
    assert_eq!(domain.translate(phys, mem), Some((phys, false)), "readable, not writable");
}

#[test]
fn a_domain_remaps_an_iova_to_a_different_physical_page() {
    let (mut unit, mut pool) = unit(64);
    let domain = unit.new_domain(2, &mut pool).unwrap();
    let mem = unit.mem();
    // A device address that is *not* its physical target: the point of translation.
    let iova = 0x1000;
    let phys = 0x9999_0000;
    domain
        .map(iova, phys, PAGE_SIZE, Perm::ReadWrite, mem, &mut pool)
        .unwrap();
    assert_eq!(domain.translate(iova, mem), Some((phys, true)));
    assert_eq!(domain.translate(phys, mem), None, "the physical address itself is not mapped");
}

#[test]
fn unmapping_makes_an_address_fault_again() {
    let (mut unit, mut pool) = unit(64);
    let domain = unit.new_domain(1, &mut pool).unwrap();
    let mem = unit.mem();
    let phys = 0x4444_0000;
    domain
        .map(phys, phys, 4 * PAGE_SIZE, Perm::ReadWrite, mem, &mut pool)
        .unwrap();
    assert!(domain.translate(phys + 2 * PAGE_SIZE, mem).is_some());
    domain.unmap(phys + 2 * PAGE_SIZE, PAGE_SIZE, mem).unwrap();
    assert_eq!(domain.translate(phys + 2 * PAGE_SIZE, mem), None, "unmapped");
    assert!(domain.translate(phys, mem).is_some(), "its neighbours are untouched");
    assert!(domain.translate(phys + 3 * PAGE_SIZE, mem).is_some());
}

#[test]
fn a_two_megabyte_aligned_range_uses_superpages_and_costs_few_frames() {
    let (mut unit, mut pool) = unit(64);
    let domain = unit.new_domain(1, &mut pool).unwrap();
    let mem = unit.mem();
    let before = pool.given.len();
    // 128 MiB, identity, all 2 MiB-aligned.
    let len = 128 * 1024 * 1024;
    domain
        .map(0, 0, len, Perm::ReadWrite, mem, &mut pool)
        .unwrap();
    let frames = pool.given.len() - before;
    // The domain's top table already existed; the map adds a PDPT and one PD, whose 64 entries
    // are 2 MiB superpage leaves. Two frames for 128 MiB — 4 KiB leaves would be dozens.
    assert_eq!(frames, 2, "2 MiB superpages, not 4 KiB leaves");
    // The leaf really is a superpage, and it translates.
    assert_eq!(domain.translate(0x20_0000 + 0x40, mem), Some((0x20_0000 + 0x40, true)));
    assert_eq!(domain.translate(len - PAGE_SIZE, mem), Some((len - PAGE_SIZE, true)));
    assert_eq!(domain.translate(len, mem), None, "one page past the range faults");
}

#[test]
fn a_misaligned_map_is_refused() {
    let (mut unit, mut pool) = unit(64);
    let domain = unit.new_domain(1, &mut pool).unwrap();
    let mem = unit.mem();
    assert_eq!(
        domain.map(0x800, 0x800, PAGE_SIZE, Perm::Read, mem, &mut pool),
        Err(Error::Misaligned)
    );
    assert_eq!(domain.map(0, 0, 0x800, Perm::Read, mem, &mut pool), Err(Error::Misaligned));
}

#[test]
fn running_out_of_frames_is_an_error_not_a_panic() {
    // Two frames: the root table and one domain table. Nothing left for a page table below it.
    let mut pool = MockFrames::new(2);
    let mut unit = Unit::new(MockRegs::new(), MockMem::default(), &mut pool).unwrap();
    let domain = unit.new_domain(1, &mut pool).unwrap();
    let mem = unit.mem();
    assert_eq!(domain.map(0, 0, PAGE_SIZE, Perm::Read, mem, &mut pool), Err(Error::NoFrames));
}

#[test]
fn attach_builds_the_root_and_context_entries_for_a_device() {
    let (mut unit, mut pool) = unit(64);
    let domain = unit.new_domain(7, &mut pool).unwrap();
    // A device at 03:00.0 — its source id is 0x0300.
    let source = 0x0300;
    unit.attach(source, &domain, &mut pool).unwrap();

    // Walk the root and context tables the way the hardware would, and check they name the
    // domain's page table and its id.
    let mem = unit.mem();
    let root_entry = unit.root_for_test() + 3 * 16;
    let root_low = mem.read64(root_entry);
    assert_ne!(root_low & 1, 0, "the bus's root entry is present");
    let context = root_low & ADDR_MASK;
    let ctx_low = mem.read64(context); // dev.fn 0 -> entry 0
    let ctx_high = mem.read64(context + 8);
    assert_ne!(ctx_low & 1, 0, "the device's context entry is present");
    assert_eq!(ctx_low & ADDR_MASK, domain.root(), "it points at the domain's table");
    assert_eq!((ctx_high >> 8) & 0xffff, 7, "it carries the domain id");
}

#[test]
fn two_devices_on_one_bus_share_a_context_table() {
    let (mut unit, mut pool) = unit(64);
    let a = unit.new_domain(1, &mut pool).unwrap();
    let b = unit.new_domain(2, &mut pool).unwrap();
    // 03:00.0 and 03:01.0: the same bus, different context entries.
    unit.attach(0x0300, &a, &mut pool).unwrap();
    let before = pool.given.len();
    unit.attach(0x0308, &b, &mut pool).unwrap();
    assert_eq!(pool.given.len(), before, "the second device reuses the bus's context table");

    let mem = unit.mem();
    let context = mem.read64(unit.root_for_test() + 3 * 16) & ADDR_MASK;
    assert_eq!(mem.read64(context) & ADDR_MASK, a.root(), "dev 0 -> domain a");
    // 03:01.0 is devfn 0x08, so its context entry is 0x08 sixteen-byte entries in.
    assert_eq!(mem.read64(context + 0x08 * 16) & ADDR_MASK, b.root(), "dev 1 -> domain b");
}

#[test]
fn the_fault_log_reports_the_address_and_device_and_then_is_empty() {
    let (mut unit, _pool) = unit(64);
    assert_eq!(unit.take_fault(), None, "nothing has faulted");

    // Plant what the hardware records when device 0x0300 writes an unmapped 0xdead_0000.
    unit.regs_for_test()
        .plant_fault(0xdead_0000, 0x0300, 5, true);
    let fault = unit.take_fault().expect("a fault was recorded");
    assert_eq!(fault.address, 0xdead_0000);
    assert_eq!(fault.source_id, 0x0300);
    assert_eq!(fault.reason, 5);
    assert!(fault.write);
    // Reading it clears it: the record and the status bit are gone.
    assert_eq!(unit.take_fault(), None, "the log is empty after the fault is taken");
    assert_eq!(unit.regs_for_test().read64(FRCD_HIGH) & (1 << 63), 0, "F bit cleared");
    assert_eq!(unit.regs_for_test().read32(reg::FSTS) & reg::fsts::PPF, 0, "PPF cleared");
}

#[test]
fn invalidation_clears_the_command_bits() {
    let (mut unit, _pool) = unit(64);
    unit.invalidate_context().unwrap();
    unit.invalidate_iotlb().unwrap();
    // The command bits are one-shot: the hardware clears them when it is done, and the driver
    // waits for that. Left set, `enable` would have timed out; it did not.
    assert_eq!(unit.regs_for_test().read64(reg::CCMD) & (1 << 63), 0);
    assert_eq!(unit.regs_for_test().read64(IOTLB_CMD) & (1 << 63), 0);
}

#[test]
fn a_superpage_can_be_unmapped_and_split_regions_still_translate() {
    let (mut unit, mut pool) = unit(64);
    let domain = unit.new_domain(1, &mut pool).unwrap();
    let mem = unit.mem();
    let two_mib = 2 * 1024 * 1024;
    domain
        .map(0, 0, 3 * two_mib, Perm::ReadWrite, mem, &mut pool)
        .unwrap();
    assert!(domain.translate(two_mib, mem).is_some());
    domain.unmap(two_mib, two_mib, mem).unwrap();
    assert_eq!(domain.translate(two_mib, mem), None, "the middle superpage is gone");
    assert!(domain.translate(0, mem).is_some(), "the first is not");
    assert!(domain.translate(2 * two_mib, mem).is_some(), "the third is not");
}

/// A helper for the tests to reach the internals the hardware would.
impl<R: Regs, M: PhysMem> Unit<R, M> {
    fn regs_for_test(&self) -> &R {
        &self.regs
    }

    fn root_for_test(&self) -> u64 {
        self.root
    }
}

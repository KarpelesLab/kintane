//! Host tests, against tables QEMU's firmware built and against deliberately broken ones.
//!
//! # Fixtures
//!
//! `testdata/*.bin` are the complete ACPI table sets of three QEMU machines, captured by
//! `testdata/capture.sh`. That script boots the machine with no kernel at all. Once the
//! firmware has published its tables and is looking for something to boot, it saves all
//! of guest memory through the QEMU monitor (`pmemsave`). `testdata/extract.py` then
//! finds the RSDP and writes it and every table it reaches. Each record is a
//! little-endian `u64` physical address, a `u32` length and the bytes.
//!
//! - `q35.bin`: `-machine q35 -smp 2` under SeaBIOS, with the root port and test device the x86
//!   presets add. An ACPI 1.0 RSDP and an RSDT, with MCFG.
//! - `pc.bin`: `-machine pc -smp 2` under SeaBIOS, with the PCI bridge and test device. An RSDT, no
//!   MCFG, and a 116-byte ACPI 1.0 FADT.
//! - `q35-ovmf.bin`: the q35 machine under OVMF. A revision 2 RSDP, whose XSDT is the root.
//! - `q35-iommu.bin`: the q35 machine with `-device intel-iommu,intremap=on`. As `q35.bin`, plus a
//!   DMAR the others do not have.

use super::*;

const Q35: &[u8] = include_bytes!("testdata/q35.bin");
const PC: &[u8] = include_bytes!("testdata/pc.bin");
const Q35_OVMF: &[u8] = include_bytes!("testdata/q35-ovmf.bin");
/// `-machine q35,kernel-irqchip=split -device intel-iommu,intremap=on`, otherwise as
/// `q35.bin`. Publishes a DMAR the others do not.
const Q35_IOMMU: &[u8] = include_bytes!("testdata/q35-iommu.bin");

/// Physical memory that holds only the records of a fixture, or regions built by a test.
#[derive(Clone)]
struct Memory {
    regions: Vec<(u64, Vec<u8>)>,
}

impl Memory {
    fn fixture(bytes: &[u8]) -> Memory {
        let mut regions = Vec::new();
        let mut at = 0;
        while at < bytes.len() {
            let address = u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap());
            let len = u32::from_le_bytes(bytes[at + 8..at + 12].try_into().unwrap()) as usize;
            regions.push((address, bytes[at + 12..at + 12 + len].to_vec()));
            at += 12 + len;
        }
        Memory { regions }
    }

    /// The region starting exactly at `address`.
    fn region_mut(&mut self, address: u64) -> &mut Vec<u8> {
        &mut self
            .regions
            .iter_mut()
            .find(|(a, _)| *a == address)
            .expect("no region there")
            .1
    }

    fn rsdp_address(&self) -> u64 {
        self.regions[0].0
    }

    fn tables(&self) -> Tables<'_, Memory> {
        let rsdp = Rsdp::read(self, self.rsdp_address()).unwrap();
        Tables::new(self, rsdp).unwrap()
    }

    fn table(&self, signature: &[u8; 4]) -> Sdt<'_> {
        self.tables().find(signature).unwrap().unwrap()
    }
}

impl PhysMemory for Memory {
    fn bytes(&self, address: u64, len: usize) -> Option<&[u8]> {
        self.regions.iter().find_map(|(base, data)| {
            let off = usize::try_from(address.checked_sub(*base)?).ok()?;
            data.get(off..off.checked_add(len)?)
        })
    }
}

/// Make a table's checksum right again after a test edited it.
fn fix_checksum(table: &mut [u8]) {
    table[9] = 0;
    table[9] = 0u8.wrapping_sub(checksum(table));
}

fn signatures(mem: &Memory) -> Vec<[u8; 4]> {
    mem.tables()
        .tables()
        .map(|t| t.unwrap().signature())
        .collect()
}

#[test]
fn q35_under_seabios_publishes_an_rsdt_with_madt_and_mcfg() {
    let mem = Memory::fixture(Q35);
    let tables = mem.tables();
    let rsdp = tables.rsdp();
    assert_eq!(rsdp.revision, 0);
    assert_eq!(rsdp.xsdt, None);
    assert_eq!(&tables.root().signature(), b"RSDT");
    assert_eq!(signatures(&mem), [*b"FACP", *b"APIC", *b"HPET", *b"MCFG", *b"WAET"]);
}

#[test]
fn pc_under_seabios_has_no_mcfg() {
    let mem = Memory::fixture(PC);
    assert_eq!(signatures(&mem), [*b"FACP", *b"APIC", *b"HPET", *b"WAET"]);
    assert_eq!(mem.tables().find(b"MCFG").unwrap().map(|t| t.address()), None);
}

#[test]
fn ovmf_publishes_a_revision_2_rsdp_and_the_xsdt_is_the_root() {
    let mem = Memory::fixture(Q35_OVMF);
    let tables = mem.tables();
    assert_eq!(tables.rsdp().revision, 2);
    assert!(tables.rsdp().xsdt.is_some());
    assert_eq!(&tables.root().signature(), b"XSDT");
    assert!(signatures(&mem).contains(b"MCFG"));
    assert!(signatures(&mem).contains(b"APIC"));
}

#[test]
fn the_madt_lists_both_processors_and_the_ioapic() {
    for fixture in [Q35, PC, Q35_OVMF] {
        let mem = Memory::fixture(fixture);
        let madt = Madt::parse(mem.table(b"APIC")).unwrap();
        let entries: Vec<MadtEntry> = madt.entries().map(Result::unwrap).collect();
        let cpus: Vec<(u8, bool)> = entries
            .iter()
            .filter_map(|e| match *e {
                MadtEntry::LocalApic { apic_id, flags, .. } => Some((apic_id, flags.enabled())),
                _ => None,
            })
            .collect();
        assert_eq!(cpus, [(0, true), (1, true)], "-smp 2");
        let ioapics: Vec<MadtEntry> = entries
            .iter()
            .copied()
            .filter(|e| matches!(e, MadtEntry::IoApic { .. }))
            .collect();
        assert_eq!(
            ioapics,
            [MadtEntry::IoApic {
                id: 0,
                address: 0xfec0_0000,
                gsi_base: 0
            }]
        );
        assert_eq!(madt.local_apic_address().unwrap(), 0xfee0_0000);
        assert_ne!(madt.flags() & madt::PCAT_COMPAT, 0, "QEMU has 8259s");
        // The PIT's IRQ 0 arrives on GSI 2 on every PC chipset QEMU models.
        assert!(entries.contains(&MadtEntry::SourceOverride {
            bus: 0,
            source: 0,
            gsi: 2,
            flags: 0
        }));
    }
}

#[test]
fn the_q35_mcfg_is_one_segment_of_256_buses() {
    for fixture in [Q35, Q35_OVMF] {
        let mem = Memory::fixture(fixture);
        let mcfg = Mcfg::parse(mem.table(b"MCFG")).unwrap();
        let segments: Vec<EcamSegment> = mcfg.segments().map(Result::unwrap).collect();
        assert_eq!(segments.len(), 1);
        let s = segments[0];
        assert_eq!((s.segment, s.start_bus, s.end_bus), (0, 0, 255));
        assert_eq!(s.len(), 256 << 20);
        assert_eq!(s.function_address(0, 0, 0), Some(s.base));
        assert_eq!(s.function_address(1, 2, 3), Some(s.base + (1 << 20) + (2 << 15) + (3 << 12)));
        assert_eq!(s.function_address(0, 32, 0), None);
        assert_eq!(s.function_address(0, 0, 8), None);
    }
}

#[test]
fn the_fadt_names_the_pm_timer() {
    let q35 = Memory::fixture(Q35);
    let fadt = Fadt::parse(q35.table(b"FACP")).unwrap();
    let (timer, _) = fadt.pm_timer().unwrap();
    assert_eq!(timer.space, AddressSpace::SystemIo);
    assert_eq!(timer.address, 0x608, "PMBASE 0x600, timer at +8");
    assert_ne!(fadt.dsdt(), 0);

    let pc = Memory::fixture(PC);
    let fadt = Fadt::parse(pc.table(b"FACP")).unwrap();
    assert_eq!(pc.table(b"FACP").bytes().len(), 116);
    let (timer, _) = fadt.pm_timer().unwrap();
    // QEMU gives its PIIX4 the same PMBASE as ICH9, so the timer port matches q35's.
    assert_eq!(timer.address, 0x608);
    assert_eq!(fadt.reset(), None, "an ACPI 1.0 FADT has no reset register");
    // The DSDT it names is one of the fixture's records, and is itself a valid table.
    assert_eq!(&pc.tables().read(fadt.dsdt()).unwrap().signature(), b"DSDT");
}

#[test]
fn a_bios_scan_finds_the_rsdp_on_a_16_byte_boundary_past_a_false_signature() {
    let real = Memory::fixture(Q35);
    let rsdp = real.regions[0].1.clone();
    let mut area = vec![0u8; 0x2_0000];
    // A signature with a wrong checksum first, as a copy of the string in firmware code
    // would be, then the real structure.
    area[0x100..0x108].copy_from_slice(b"RSD PTR ");
    area[0x200..0x200 + rsdp.len()].copy_from_slice(&rsdp);
    let mem = Memory {
        regions: vec![(0xe_0000, area.clone())],
    };
    assert_eq!(Rsdp::find_bios(&mem).unwrap().address, 0xe_0200);

    // Off the boundary it is not where the specification says to look.
    let mut shifted = vec![0u8; 0x2_0000];
    shifted[0x204..0x204 + rsdp.len()].copy_from_slice(&rsdp);
    let mem = Memory {
        regions: vec![(0xe_0000, shifted)],
    };
    assert_eq!(Rsdp::find_bios(&mem), Err(Error::NoRsdp));
}

#[test]
fn a_bios_scan_looks_in_the_ebda_first() {
    let real = Memory::fixture(Q35);
    let rsdp = real.regions[0].1.clone();
    let mut low = vec![0u8; 0x10_0000];
    // EBDA segment 0x9fc0: base 0x9fc00.
    low[0x40e..0x410].copy_from_slice(&0x9fc0u16.to_le_bytes());
    low[0x9fc10..0x9fc10 + rsdp.len()].copy_from_slice(&rsdp);
    low[0xe0000..0xe0000 + rsdp.len()].copy_from_slice(&rsdp);
    let mem = Memory {
        regions: vec![(0, low)],
    };
    assert_eq!(Rsdp::find_bios(&mem).unwrap().address, 0x9fc10);
}

#[test]
fn every_single_byte_change_to_any_table_is_caught_by_its_checksum() {
    for fixture in [Q35, PC, Q35_OVMF] {
        let mem = Memory::fixture(fixture);
        // The RSDP, and every table with a standard header. The FACS has neither a
        // checksum nor a header, and is not a record this walks.
        for (address, bytes) in &mem.regions {
            let is_rsdp = bytes.starts_with(b"RSD PTR ");
            if bytes.starts_with(b"FACS") {
                continue;
            }
            // The whole RSDP is covered only by the extended checksum; revision 0 has 20
            // bytes, and that is all it has.
            for i in 0..bytes.len() {
                for flip in [0x01u8, 0x80, 0xff] {
                    let mut edited = bytes.clone();
                    edited[i] ^= flip;
                    let rejected = if is_rsdp {
                        Rsdp::parse(*address, &edited).is_err()
                    } else {
                        Sdt::from_bytes(*address, &edited).is_err()
                    };
                    assert!(rejected, "a change at byte {i} of {address:#x} was accepted");
                }
            }
        }
    }
}

#[test]
fn a_truncated_table_is_an_error_never_a_panic() {
    for fixture in [Q35, PC, Q35_OVMF] {
        let mem = Memory::fixture(fixture);
        for (address, bytes) in &mem.regions {
            for len in 0..bytes.len() {
                let _ = Rsdp::parse(*address, &bytes[..len]);
                assert!(Sdt::from_bytes(*address, &bytes[..len]).is_err());
            }
        }
    }
}

#[test]
fn a_length_that_runs_past_readable_memory_is_unreadable() {
    let mut mem = Memory::fixture(Q35);
    let madt = mem.table(b"APIC").address();
    let table = mem.region_mut(madt);
    table[4..8].copy_from_slice(&4096u32.to_le_bytes());
    assert_eq!(
        Sdt::read(&mem, madt).unwrap_err(),
        Error::Unreadable {
            address: madt,
            len: 4096
        }
    );
    let table = mem.region_mut(madt);
    table[4..8].copy_from_slice(&20u32.to_le_bytes());
    assert!(matches!(Sdt::read(&mem, madt), Err(Error::BadLength { len: 20, .. })));
}

#[test]
fn a_broken_table_before_the_one_wanted_is_reported() {
    let mut mem = Memory::fixture(Q35);
    let fadt = mem.table(b"FACP").address();
    mem.region_mut(fadt)[20] ^= 1;
    assert!(matches!(
        mem.tables().find(b"MCFG"),
        Err(Error::BadChecksum {
            signature: [b'F', b'A', b'C', b'P'],
            ..
        })
    ));
}

#[test]
fn a_broken_xsdt_is_an_error_even_with_a_good_rsdt() {
    let mut mem = Memory::fixture(Q35_OVMF);
    let rsdp = Rsdp::read(&mem, mem.rsdp_address()).unwrap();
    let xsdt = rsdp.xsdt.unwrap();
    mem.region_mut(xsdt)[40] ^= 1;
    assert!(matches!(Tables::new(&mem, rsdp), Err(Error::BadChecksum { .. })));
    // The RSDT is still fine, and would have been a quiet fallback.
    assert!(Sdt::read(&mem, u64::from(rsdp.rsdt)).is_ok());
}

#[test]
fn a_revision_2_rsdp_must_carry_a_good_extended_checksum() {
    let mem = Memory::fixture(Q35_OVMF);
    let mut rsdp = mem.regions[0].1.clone();
    assert!(Rsdp::parse(0, &rsdp).is_ok());
    // Byte 33 is outside the ACPI 1.0 checksum's reach.
    rsdp[33] ^= 1;
    assert!(Rsdp::parse(0, &rsdp[..20]).is_err(), "revision 2 needs the extension");
    assert!(matches!(Rsdp::parse(0, &rsdp), Err(Error::BadChecksum { .. })));
}

#[test]
fn root_tables_with_too_many_entries_are_refused() {
    let mut rsdt = vec![0u8; HEADER_LEN + 4 * (MAX_TABLES + 1)];
    rsdt[..4].copy_from_slice(b"RSDT");
    let len = rsdt.len() as u32;
    rsdt[4..8].copy_from_slice(&len.to_le_bytes());
    fix_checksum(&mut rsdt);
    let mut rsdp = Memory::fixture(Q35).regions[0].1.clone();
    rsdp[16..20].copy_from_slice(&0x1000u32.to_le_bytes());
    rsdp[8] = 0;
    rsdp[8] = 0u8.wrapping_sub(checksum(&rsdp[..20]));
    let mem = Memory {
        regions: vec![(0x1000, rsdt), (0x10, rsdp)],
    };
    let parsed = Rsdp::read(&mem, 0x10).unwrap();
    assert_eq!(
        Tables::new(&mem, parsed).err(),
        Some(Error::TooManyTables {
            count: MAX_TABLES + 1
        })
    );
}

/// A MADT with the q35 fixture's header and the given entry bytes.
fn madt_with(entries: &[u8]) -> Vec<u8> {
    let mem = Memory::fixture(Q35);
    let mut t = mem.table(b"APIC").bytes()[..44].to_vec();
    t.extend_from_slice(entries);
    let len = t.len() as u32;
    t[4..8].copy_from_slice(&len.to_le_bytes());
    fix_checksum(&mut t);
    t
}

fn walk(table: &[u8]) -> Vec<Result<MadtEntry, Error>> {
    let sdt = Sdt::from_bytes(0x1000, table).unwrap();
    Madt::parse(sdt).unwrap().entries().collect()
}

#[test]
fn a_zero_length_madt_entry_ends_the_walk_with_an_error() {
    let t = madt_with(&[0, 0, 0, 0, 0, 0, 0, 0]);
    assert_eq!(
        walk(&t),
        [Err(Error::Malformed {
            signature: *b"APIC",
            offset: 44
        })]
    );
}

#[test]
fn a_madt_entry_shorter_than_its_type_or_past_the_end_is_malformed() {
    // A local APIC entry needs eight bytes.
    let short = madt_with(&[0, 6, 0, 0, 1, 0]);
    assert!(matches!(walk(&short)[..], [Err(Error::Malformed { .. })]));
    // Declares twelve bytes, has eight.
    let past = madt_with(&[1, 12, 0, 0, 0, 0, 0xc0, 0xfe]);
    assert!(matches!(walk(&past)[..], [Err(Error::Malformed { .. })]));
}

#[test]
fn an_unknown_madt_entry_is_skipped_and_the_walk_continues() {
    let t = madt_with(&[0x7f, 4, 0xaa, 0xbb, 0, 8, 3, 7, 1, 0, 0, 0]);
    assert_eq!(
        walk(&t),
        [
            Ok(MadtEntry::Other { kind: 0x7f, len: 4 }),
            Ok(MadtEntry::LocalApic {
                processor_uid: 3,
                apic_id: 7,
                flags: ProcessorFlags(1)
            })
        ]
    );
}

#[test]
fn a_local_apic_address_override_wins_over_the_header() {
    let mut entry = vec![5, 12, 0, 0];
    entry.extend_from_slice(&0x1_2345_6000u64.to_le_bytes());
    let t = madt_with(&entry);
    let madt = Madt::parse(Sdt::from_bytes(0, &t).unwrap()).unwrap();
    assert_eq!(madt.header_local_apic_address(), 0xfee0_0000);
    assert_eq!(madt.local_apic_address().unwrap(), 0x1_2345_6000);
}

#[test]
fn processor_flags_distinguish_enabled_from_online_capable() {
    assert!(ProcessorFlags(1).enabled());
    assert!(!ProcessorFlags(2).enabled());
    assert!(ProcessorFlags(2).online_capable());
    assert!(!ProcessorFlags(0).enabled() && !ProcessorFlags(0).online_capable());
}

#[test]
fn an_mcfg_with_an_inverted_bus_range_or_a_partial_entry_is_refused() {
    let mem = Memory::fixture(Q35);
    let mut t = mem.table(b"MCFG").bytes().to_vec();
    t[44 + 10] = 5;
    t[44 + 11] = 4;
    fix_checksum(&mut t);
    let mcfg = Mcfg::parse(Sdt::from_bytes(0, &t).unwrap()).unwrap();
    assert!(matches!(mcfg.segments().next(), Some(Err(Error::Malformed { offset: 44, .. }))));

    let mut partial = mem.table(b"MCFG").bytes().to_vec();
    partial.truncate(partial.len() - 1);
    let len = partial.len() as u32;
    partial[4..8].copy_from_slice(&len.to_le_bytes());
    fix_checksum(&mut partial);
    assert!(matches!(
        Mcfg::parse(Sdt::from_bytes(0, &partial).unwrap()),
        Err(Error::BadLength { .. })
    ));
}

#[test]
fn asking_for_the_wrong_kind_of_table_is_an_error() {
    let mem = Memory::fixture(Q35);
    assert!(matches!(Madt::parse(mem.table(b"MCFG")), Err(Error::WrongSignature { .. })));
    assert!(matches!(Fadt::parse(mem.table(b"APIC")), Err(Error::WrongSignature { .. })));
}

#[test]
fn the_iommu_machine_publishes_a_dmar_the_others_do_not() {
    for fixture in [Q35, PC, Q35_OVMF] {
        assert!(
            Memory::fixture(fixture)
                .tables()
                .find(b"DMAR")
                .unwrap()
                .is_none(),
            "a machine with no intel-iommu has no DMAR"
        );
    }
    let mem = Memory::fixture(Q35_IOMMU);
    let dmar = Dmar::parse(mem.table(b"DMAR")).unwrap();
    // QEMU's intel-iommu defaults to a 48-bit address width and turns interrupt remapping
    // on when it is asked for with intremap=on.
    assert_eq!(dmar.host_address_width(), 48);
    assert_ne!(dmar.flags() & dmar::INTR_REMAP, 0, "intremap=on");
}

#[test]
fn the_dmar_names_one_remapping_unit_at_qemus_register_base() {
    let mem = Memory::fixture(Q35_IOMMU);
    let dmar = Dmar::parse(mem.table(b"DMAR")).unwrap();
    let units: Vec<Drhd> = dmar.units().map(Result::unwrap).collect();
    assert_eq!(units.len(), 1, "QEMU presents a single remapping unit");
    // The register base QEMU's intel-iommu always uses.
    assert_eq!(units[0].register_base, 0xfed9_0000);
    assert_eq!(units[0].segment, 0);
    // Every remapping structure that is not a DRHD comes back as `Other`, not an error, so
    // a kind this parser does not know does not hide the unit.
    assert!(dmar.structures().all(|s| s.is_ok()));
}

#[test]
fn a_dmar_structure_with_a_bad_length_ends_the_walk_with_an_error() {
    let mut bytes = Memory::fixture(Q35_IOMMU).table(b"DMAR").bytes().to_vec();
    // The first remapping structure's length word, zeroed: a structure that cannot advance
    // the walk. STRUCTURES_OFFSET is 48, its length is the u16 at 50.
    bytes[50] = 0;
    bytes[51] = 0;
    fix_checksum(&mut bytes);
    let sdt = Sdt::from_bytes(0x2000, &bytes).unwrap();
    let dmar = Dmar::parse(sdt).unwrap();
    assert!(
        matches!(dmar.units().next(), Some(Err(Error::Malformed { .. }))),
        "a zero-length structure is malformed, not skipped"
    );
}

/// A hand-built DMAR: a 48-byte header (with a host address width byte and flags) followed
/// by `structures`, with the length and checksum made right.
fn dmar_with(haw: u8, flags: u8, structures: &[u8]) -> Vec<u8> {
    let mut t = vec![0u8; 48];
    t[0..4].copy_from_slice(b"DMAR");
    t[36] = haw;
    t[37] = flags;
    t.extend_from_slice(structures);
    let len = t.len() as u32;
    t[4..8].copy_from_slice(&len.to_le_bytes());
    fix_checksum(&mut t);
    t
}

#[test]
fn an_unknown_dmar_structure_is_skipped_and_later_units_are_still_found() {
    // An RMRR (type 1) of 24 bytes, then a DRHD (type 0) of 16 bytes at base 0xabc000.
    let mut structures = vec![1, 0, 24, 0];
    structures.extend(core::iter::repeat_n(0u8, 20));
    let mut drhd = vec![0, 0, 16, 0, dmar::INCLUDE_PCI_ALL, 0, 0, 0];
    drhd.extend_from_slice(&0x00ab_c000u64.to_le_bytes());
    structures.extend_from_slice(&drhd);

    let bytes = dmar_with(0x26, dmar::INTR_REMAP, &structures);
    let sdt = Sdt::from_bytes(0x3000, &bytes).unwrap();
    let dmar = Dmar::parse(sdt).unwrap();
    assert_eq!(dmar.host_address_width(), 39, "0x26 + 1");
    assert!(matches!(
        dmar.structures().next(),
        Some(Ok(Remapping::Other {
            kind: 1,
            length: 24
        }))
    ));
    let units: Vec<Drhd> = dmar.units().map(Result::unwrap).collect();
    assert_eq!(units.len(), 1);
    assert_eq!(units[0].register_base, 0x00ab_c000);
    assert!(units[0].includes_all(), "INCLUDE_PCI_ALL was set");
}

/// A small deterministic generator, so a fuzz failure is reproducible by its seed.
struct XorShift(u64);

impl XorShift {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

#[test]
fn fuzzed_tables_with_valid_checksums_never_panic_or_loop() {
    let mut rng = XorShift(0x6b69_6e74_616e_6531);
    for fixture in [Q35, PC, Q35_OVMF, Q35_IOMMU] {
        let mem = Memory::fixture(fixture);
        for signature in [b"APIC", b"MCFG", b"FACP", b"DMAR"] {
            let Some(original) = mem.tables().find(signature).unwrap() else {
                continue;
            };
            let original = original.bytes().to_vec();
            for _ in 0..2000 {
                let mut t = original.clone();
                // Mutate a few bytes anywhere past the checksum, sometimes the length too,
                // and sometimes cut the table short.
                for _ in 0..1 + rng.next() % 4 {
                    let i = 10 + (rng.next() as usize % (t.len() - 10));
                    t[i] = rng.next() as u8;
                }
                if rng.next() % 4 == 0 {
                    let keep = HEADER_LEN + rng.next() as usize % (t.len() - HEADER_LEN + 1);
                    t.truncate(keep);
                }
                let len = t.len() as u32;
                t[4..8].copy_from_slice(&len.to_le_bytes());
                fix_checksum(&mut t);
                let sdt = Sdt::from_bytes(0x1000, &t).unwrap();
                if let Ok(madt) = Madt::parse(sdt) {
                    let n = madt.entries().count();
                    assert!(n <= t.len() / 2, "each entry is at least two bytes");
                    let _ = madt.local_apic_address();
                }
                if let Ok(mcfg) = Mcfg::parse(sdt) {
                    for s in mcfg.segments().flatten() {
                        let _ = s.function_address(s.end_bus, 31, 7);
                    }
                }
                if let Ok(fadt) = Fadt::parse(sdt) {
                    let _ = (fadt.pm_timer(), fadt.reset(), fadt.dsdt());
                }
                if let Ok(dmar) = Dmar::parse(sdt) {
                    let n = dmar.structures().count();
                    assert!(n <= t.len() / 4, "each structure is at least four bytes");
                    for unit in dmar.units() {
                        let _ = unit.map(|u| (u.register_base, u.includes_all()));
                    }
                }
            }
        }
    }
}

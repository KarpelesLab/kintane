use crate::image::{Image, ImageError, NOTE_ENTRY, NOTE_NAME};
use crate::tags::{self, Builder, HEADER_SIZE, REGION_SIZE};
use crate::uefi::{self, memory_type};
use crate::{Error, Firmware, MAGIC, MemoryKind, MemoryRegion, TagKind, VERSION};

fn region(start: u64, len: u64, kind: MemoryKind) -> MemoryRegion {
    MemoryRegion {
        start,
        len,
        kind: kind as u32,
        _reserved: 0,
    }
}

fn build(f: impl FnOnce(&mut Builder<'_>)) -> Vec<u8> {
    let mut buf = vec![0u8; 4096];
    let mut b = Builder::new(&mut buf).unwrap();
    f(&mut b);
    let n = b.finish();
    buf.truncate(n);
    buf
}

fn regions(bytes: &[u8]) -> Vec<MemoryRegion> {
    tags::parse(bytes)
        .unwrap()
        .memory_map()
        .unwrap()
        .unwrap()
        .collect()
}

#[test]
fn a_built_structure_parses_back() {
    let bytes = build(|b| {
        b.firmware(Firmware::Uefi).unwrap();
        b.acpi_rsdp(0xE_0000).unwrap();
        b.kernel_range(0x10_0000, 0x4_0000).unwrap();
        let mut m = b.memory_map(8).unwrap();
        m.push(region(0x10_0000, 0x10_0000, MemoryKind::Usable))
            .unwrap();
        m.push(region(0, 0x1000, MemoryKind::Reserved)).unwrap();
        m.close();
        b.tag(TagKind::CommandLine, b"safe").unwrap();
    });

    let p = tags::parse(&bytes).unwrap();
    assert_eq!(p.header.magic, MAGIC);
    assert_eq!(p.header.version, VERSION);
    assert_eq!(p.header.total_size(), bytes.len());
    assert_eq!(p.firmware().unwrap(), Some(Firmware::Uefi as u32));
    assert_eq!(p.acpi_rsdp().unwrap(), Some(0xE_0000));
    assert_eq!(p.kernel_range().unwrap(), Some((0x10_0000, 0x4_0000)));
    assert_eq!(p.find(TagKind::CommandLine).unwrap().unwrap().payload, b"safe");
    assert_eq!(
        regions(&bytes),
        [
            region(0, 0x1000, MemoryKind::Reserved),
            region(0x10_0000, 0x10_0000, MemoryKind::Usable)
        ],
        "sorted by address"
    );
    assert!(p.find(TagKind::DeviceTree).unwrap().is_none());
}

#[test]
fn every_tag_is_eight_byte_aligned_and_padding_is_zero() {
    let bytes = build(|b| {
        b.tag(TagKind::CommandLine, b"abc").unwrap();
        b.tag(TagKind::CommandLine, b"defghijkl").unwrap();
        b.firmware(Firmware::Bios).unwrap();
    });
    let p = tags::parse(&bytes).unwrap();
    let offsets: Vec<usize> = p.tags().map(|t| t.unwrap().offset).collect();
    assert_eq!(offsets, [16, 32, 56]);
    // "abc" occupies 8..11 of the first tag; bytes 11..16 are padding.
    assert_eq!(&bytes[16 + 11..32], &[0; 5]);
    assert_eq!(bytes.len() % 8, 0);
}

#[test]
fn adjacent_regions_of_one_kind_merge_whatever_order_they_arrive_in() {
    let bytes = build(|b| {
        let mut m = b.memory_map(8).unwrap();
        // Three pieces of one usable run, pushed out of order, plus a reserved hole
        // that touches it but must not merge.
        m.push(region(0x3000, 0x1000, MemoryKind::Usable)).unwrap();
        m.push(region(0x1000, 0x1000, MemoryKind::Usable)).unwrap();
        m.push(region(0x5000, 0x1000, MemoryKind::Reserved))
            .unwrap();
        m.push(region(0x2000, 0x1000, MemoryKind::Usable)).unwrap();
        m.push(region(0x4000, 0x1000, MemoryKind::Usable)).unwrap();
        assert_eq!(m.len(), 2);
        m.close();
    });
    assert_eq!(
        regions(&bytes),
        [
            region(0x1000, 0x4000, MemoryKind::Usable),
            region(0x5000, 0x1000, MemoryKind::Reserved)
        ]
    );
}

#[test]
fn a_gap_or_a_different_kind_keeps_regions_apart() {
    let bytes = build(|b| {
        let mut m = b.memory_map(8).unwrap();
        m.push(region(0x1000, 0x1000, MemoryKind::Usable)).unwrap();
        m.push(region(0x3000, 0x1000, MemoryKind::Usable)).unwrap();
        m.push(region(0x2000, 0x1000, MemoryKind::BootData))
            .unwrap();
        m.push(region(0x9000, 0, MemoryKind::Usable)).unwrap();
        m.close();
    });
    assert_eq!(regions(&bytes).len(), 3, "empty regions are dropped, kinds kept apart");
}

#[test]
fn a_full_map_refuses_rather_than_dropping_a_region() {
    let mut buf = vec![0u8; 4096];
    let mut b = Builder::new(&mut buf).unwrap();
    let mut m = b.memory_map(2).unwrap();
    m.push(region(0x1000, 0x1000, MemoryKind::Usable)).unwrap();
    m.push(region(0x3000, 0x1000, MemoryKind::Usable)).unwrap();
    assert_eq!(m.push(region(0x5000, 0x1000, MemoryKind::Usable)), Err(Error::NoRoom));
    // Merging needs no room, so a full map still accepts a touching region.
    m.push(region(0x2000, 0x1000, MemoryKind::Usable)).unwrap();
    assert_eq!(m.len(), 1);
}

#[test]
fn closing_a_map_returns_its_unused_capacity() {
    let mut buf = vec![0u8; 4096];
    let mut b = Builder::new(&mut buf).unwrap();
    let mut m = b.memory_map(100).unwrap();
    m.push(region(0x1000, 0x1000, MemoryKind::Usable)).unwrap();
    m.close();
    let n = b.finish();
    // Header, map tag (8 + 8 + one region), End tag.
    assert_eq!(n, HEADER_SIZE + 8 + 8 + REGION_SIZE + 8);
}

#[test]
fn a_buffer_too_small_is_reported_not_overrun() {
    let mut buf = [0u8; 40];
    let mut b = Builder::new(&mut buf).unwrap();
    assert_eq!(b.tag(TagKind::CommandLine, &[1; 32]), Err(Error::NoRoom));
    // A small tag still fits, with room kept for End.
    b.tag(TagKind::CommandLine, b"ok").unwrap();
    assert_eq!(b.finish(), 40);
    assert!(matches!(Builder::new(&mut [0u8; 8]), Err(Error::NoRoom)));
}

#[test]
fn a_newer_loaders_longer_header_is_stepped_over() {
    let bytes = build(|b| b.firmware(Firmware::Uefi).unwrap());
    // Insert 8 bytes of "future header" after the 16 we know and say so.
    let mut newer = bytes[..HEADER_SIZE].to_vec();
    newer.extend_from_slice(&[0xAA; 8]);
    newer.extend_from_slice(&bytes[HEADER_SIZE..]);
    newer[10..12].copy_from_slice(&24u16.to_ne_bytes());
    let p = tags::parse(&newer).unwrap();
    assert_eq!(p.firmware().unwrap(), Some(Firmware::Uefi as u32));
}

#[test]
fn unknown_tags_are_skipped() {
    let bytes = build(|b| {
        b.tag(TagKind::EntropySeed, &[7; 13]).unwrap();
        b.firmware(Firmware::Uefi).unwrap();
    });
    let mut raw = bytes.clone();
    // Relabel the first tag as a kind no version defines.
    raw[16..20].copy_from_slice(&0xDEADu32.to_ne_bytes());
    let p = tags::parse(&raw).unwrap();
    assert_eq!(p.firmware().unwrap(), Some(Firmware::Uefi as u32));
}

#[test]
fn a_corrupt_header_is_named() {
    let bytes = build(|_| {});
    let mut bad = bytes.clone();
    bad[0] ^= 1;
    assert!(matches!(tags::parse(&bad), Err(Error::BadMagic)));

    let mut newer = bytes.clone();
    newer[8..10].copy_from_slice(&(VERSION + 1).to_ne_bytes());
    assert!(matches!(tags::parse(&newer), Err(Error::UnsupportedVersion(_))));

    assert!(matches!(tags::parse(&bytes[..bytes.len() - 1]), Err(Error::Truncated)));
    assert!(matches!(tags::parse(&bytes[..10]), Err(Error::Truncated)));
}

#[test]
fn a_tag_whose_size_runs_past_the_end_is_malformed() {
    let bytes = build(|b| b.tag(TagKind::CommandLine, b"hello").unwrap());
    let mut raw = bytes.clone();
    raw[20..24].copy_from_slice(&4096u32.to_ne_bytes());
    let p = tags::parse(&raw).unwrap();
    assert_eq!(p.find(TagKind::Firmware).err(), Some(Error::Malformed { offset: 16 }));

    let mut tiny = bytes.clone();
    tiny[20..24].copy_from_slice(&4u32.to_ne_bytes());
    let p = tags::parse(&tiny).unwrap();
    assert_eq!(p.find(TagKind::Firmware).err(), Some(Error::Malformed { offset: 16 }));
}

#[test]
fn a_stream_without_an_end_tag_is_malformed() {
    let bytes = build(|b| b.firmware(Firmware::Uefi).unwrap());
    // Drop the End tag and shrink tags_size to match.
    let mut raw = bytes[..bytes.len() - 8].to_vec();
    let size = (raw.len() - HEADER_SIZE) as u32;
    raw[12..16].copy_from_slice(&size.to_ne_bytes());
    let p = tags::parse(&raw).unwrap();
    assert!(matches!(p.find(TagKind::DeviceTree), Err(Error::Malformed { .. })));
}

#[test]
fn a_memory_map_with_a_ragged_entry_is_malformed() {
    let bytes = build(|b| {
        let mut m = b.memory_map(2).unwrap();
        m.push(region(0x1000, 0x1000, MemoryKind::Usable)).unwrap();
        m.close();
    });
    let mut raw = bytes.clone();
    // Claim 32-byte entries over a 24-byte payload.
    raw[24..28].copy_from_slice(&32u32.to_ne_bytes());
    assert!(matches!(tags::parse(&raw).unwrap().memory_map(), Err(Error::Malformed { .. })));
    let mut short = bytes.clone();
    short[24..28].copy_from_slice(&16u32.to_ne_bytes());
    assert!(matches!(
        tags::parse(&short).unwrap().memory_map(),
        Err(Error::Malformed { .. })
    ));
}

#[test]
fn a_larger_region_entry_is_read_by_its_prefix() {
    // A future version with 32-byte entries: this version reads the first 24 bytes.
    let mut payload = Vec::new();
    payload.extend_from_slice(&32u32.to_ne_bytes());
    payload.extend_from_slice(&0u32.to_ne_bytes());
    for (start, len) in [(0x1000u64, 0x2000u64), (0x8000, 0x1000)] {
        payload.extend_from_slice(&start.to_ne_bytes());
        payload.extend_from_slice(&len.to_ne_bytes());
        payload.extend_from_slice(&(MemoryKind::Usable as u32).to_ne_bytes());
        payload.extend_from_slice(&[0; 4]);
        payload.extend_from_slice(&[0xEE; 8]);
    }
    let bytes = build(|b| b.tag(TagKind::MemoryMap, &payload).unwrap());
    assert_eq!(
        regions(&bytes),
        [
            region(0x1000, 0x2000, MemoryKind::Usable),
            region(0x8000, 0x1000, MemoryKind::Usable)
        ]
    );
}

// ---- images --------------------------------------------------------------------------

struct Seg {
    kind: u32,
    phys: u64,
    data: Vec<u8>,
    mem: u64,
}

/// A minimal ELF64 with the given program headers, data laid out after the table.
fn elf(segs: &[Seg]) -> Vec<u8> {
    let phoff = 64usize;
    let mut out = vec![0u8; phoff + segs.len() * 56];
    out[..4].copy_from_slice(b"\x7fELF");
    out[4] = 2;
    out[5] = 1;
    out[32..40].copy_from_slice(&(phoff as u64).to_le_bytes());
    out[54..56].copy_from_slice(&56u16.to_le_bytes());
    out[56..58].copy_from_slice(&(segs.len() as u16).to_le_bytes());
    for (i, s) in segs.iter().enumerate() {
        let ph = phoff + i * 56;
        let off = out.len() as u64;
        out[ph..ph + 4].copy_from_slice(&s.kind.to_le_bytes());
        out[ph + 8..ph + 16].copy_from_slice(&off.to_le_bytes());
        out[ph + 24..ph + 32].copy_from_slice(&s.phys.to_le_bytes());
        out[ph + 32..ph + 40].copy_from_slice(&(s.data.len() as u64).to_le_bytes());
        out[ph + 40..ph + 48].copy_from_slice(&s.mem.to_le_bytes());
        out.extend_from_slice(&s.data);
    }
    out
}

fn entry_note(entry: u64, protocol: u32) -> Vec<u8> {
    let mut n = Vec::new();
    n.extend_from_slice(&8u32.to_le_bytes());
    n.extend_from_slice(&16u32.to_le_bytes());
    n.extend_from_slice(&NOTE_ENTRY.to_le_bytes());
    n.extend_from_slice(NOTE_NAME);
    n.extend_from_slice(&entry.to_le_bytes());
    n.extend_from_slice(&protocol.to_le_bytes());
    n.extend_from_slice(&0u32.to_le_bytes());
    n
}

fn other_note() -> Vec<u8> {
    // A GNU build-id note, as a linker might add, to be skipped.
    let mut n = Vec::new();
    n.extend_from_slice(&4u32.to_le_bytes());
    n.extend_from_slice(&3u32.to_le_bytes());
    n.extend_from_slice(&3u32.to_le_bytes());
    n.extend_from_slice(b"GNU\0");
    n.extend_from_slice(&[1, 2, 3, 0]);
    n
}

fn kernel(entry: u64, protocol: u32) -> Vec<u8> {
    let mut notes = other_note();
    notes.extend(entry_note(entry, protocol));
    elf(&[
        Seg {
            kind: 1,
            phys: 0x10_0000,
            data: vec![0x90; 100],
            mem: 0x1000,
        },
        Seg {
            kind: 4,
            phys: 0,
            data: notes,
            mem: 0,
        },
        Seg {
            kind: 1,
            phys: 0x20_0000,
            data: vec![],
            mem: 0x3000,
        },
    ])
}

#[test]
fn an_image_yields_its_segments_extent_and_entry() {
    let bytes = kernel(0x10_0010, u32::from(VERSION));
    let img = Image::parse(&bytes).unwrap();
    assert_eq!(img.entry, 0x10_0010);
    assert_eq!((img.phys_start, img.phys_end), (0x10_0000, 0x20_3000));
    let segs: Vec<_> = img.segments().map(Result::unwrap).collect();
    assert_eq!(segs.len(), 2);
    assert_eq!(segs[0].file.len(), 100);
    assert_eq!(segs[1].mem_size, 0x3000);
}

#[test]
fn an_image_without_the_note_is_refused_by_name() {
    let bytes = elf(&[Seg {
        kind: 1,
        phys: 0x10_0000,
        data: vec![1; 8],
        mem: 8,
    }]);
    assert_eq!(Image::parse(&bytes).err(), Some(ImageError::NoEntryNote));
}

#[test]
fn an_entry_outside_the_image_or_from_a_newer_protocol_is_refused() {
    assert_eq!(
        Image::parse(&kernel(0x30_0000, u32::from(VERSION))).err(),
        Some(ImageError::EntryOutsideImage)
    );
    assert_eq!(
        Image::parse(&kernel(0x10_0010, u32::from(VERSION) + 1)).err(),
        Some(ImageError::UnsupportedProtocol(u32::from(VERSION) + 1))
    );
}

#[test]
fn malformed_images_are_errors_not_panics() {
    let good = kernel(0x10_0010, u32::from(VERSION));
    assert_eq!(Image::parse(&good[..40]).err(), Some(ImageError::NotElf64));
    let mut not_elf = good.clone();
    not_elf[4] = 1;
    assert_eq!(Image::parse(&not_elf).err(), Some(ImageError::NotElf64));

    // Truncate at every length: each is an error, none panics.
    for n in 0..good.len() {
        assert!(Image::parse(&good[..n]).is_err(), "prefix of {n} bytes");
    }

    // More file bytes than memory.
    let fat = elf(&[Seg {
        kind: 1,
        phys: 0x1000,
        data: vec![0; 16],
        mem: 8,
    }]);
    assert_eq!(Image::parse(&fat).err(), Some(ImageError::BadSegment));

    // A segment that wraps the address space.
    let wrap = elf(&[Seg {
        kind: 1,
        phys: u64::MAX - 4,
        data: vec![],
        mem: 16,
    }]);
    assert_eq!(Image::parse(&wrap).err(), Some(ImageError::BadSegment));

    // A program header count that runs past the file.
    let mut many = good.clone();
    many[56..58].copy_from_slice(&0xFFFFu16.to_le_bytes());
    assert_eq!(Image::parse(&many).err(), Some(ImageError::Truncated));
}

// ---- UEFI translation ----------------------------------------------------------------

#[test]
fn uefi_types_translate_to_what_the_kernel_may_do_with_them() {
    use memory_type::*;
    let usable = MemoryKind::Usable as u32;
    for t in [
        LOADER_CODE,
        LOADER_DATA,
        BOOT_SERVICES_CODE,
        BOOT_SERVICES_DATA,
        CONVENTIONAL,
    ] {
        assert_eq!(uefi::kind_of(t), usable, "type {t} is free after ExitBootServices");
    }
    for t in [
        RESERVED,
        RUNTIME_SERVICES_CODE,
        RUNTIME_SERVICES_DATA,
        MMIO,
        MMIO_PORT_SPACE,
    ] {
        assert_eq!(uefi::kind_of(t), MemoryKind::Reserved as u32, "type {t} outlives boot");
    }
    assert_eq!(uefi::kind_of(ACPI_RECLAIM), MemoryKind::AcpiReclaimable as u32);
    assert_eq!(uefi::kind_of(ACPI_NVS), MemoryKind::AcpiNvs as u32);
    assert_eq!(uefi::kind_of(UNUSABLE), MemoryKind::Bad as u32);
    assert_eq!(uefi::kind_of(KINTANE_KERNEL), MemoryKind::KernelImage as u32);
    assert_eq!(uefi::kind_of(KINTANE_BOOT_DATA), MemoryKind::BootData as u32);
    // Another OS loader's type, and one from a future specification.
    assert_eq!(uefi::kind_of(0x8000_0000), MemoryKind::Reserved as u32);
    assert_eq!(uefi::kind_of(15), MemoryKind::Reserved as u32);
}

#[test]
fn uefi_descriptors_become_byte_regions() {
    assert_eq!(
        uefi::region(memory_type::CONVENTIONAL, 0x10_0000, 3),
        Some(region(0x10_0000, 0x3000, MemoryKind::Usable))
    );
    assert_eq!(uefi::region(memory_type::CONVENTIONAL, u64::MAX - 0x1000, 2), None);
    assert_eq!(uefi::region(memory_type::CONVENTIONAL, 0, u64::MAX), None);
}

#[test]
fn a_command_line_round_trips_and_its_absence_is_not_an_empty_line() {
    let with = build(|b| b.command_line(b"mode=safe kintane.canary=x").unwrap());
    let p = tags::parse(&with).unwrap();
    assert_eq!(p.command_line().unwrap(), Some(&b"mode=safe kintane.canary=x"[..]));

    let without = build(|b| b.firmware(Firmware::Bios).unwrap());
    assert_eq!(tags::parse(&without).unwrap().command_line().unwrap(), None);

    let empty = build(|b| b.command_line(b"").unwrap());
    assert_eq!(tags::parse(&empty).unwrap().command_line().unwrap(), Some(&b""[..]));
}

#[test]
fn an_overlong_command_line_is_refused_by_both_sides() {
    let long = vec![b'x'; tags::MAX_COMMAND_LINE + 1];
    let mut buf = vec![0u8; 4096];
    let mut b = Builder::new(&mut buf).unwrap();
    assert_eq!(b.command_line(&long), Err(Error::NoRoom));
    assert!(b.command_line(&long[..tags::MAX_COMMAND_LINE]).is_ok());

    // A loader that bypasses the builder is still caught by the reader.
    let bytes = build(|b| b.tag(TagKind::CommandLine, &long).unwrap());
    assert!(matches!(
        tags::parse(&bytes).unwrap().command_line(),
        Err(Error::Malformed { .. })
    ));
}

#[test]
fn a_uefi_runtime_tag_round_trips_and_a_short_one_is_malformed() {
    let r = uefi::Runtime {
        call_root: 0x3F00_0000,
        call_stack_top: 0x3F01_6000,
        get_variable: 0x3FE1_2340,
        set_variable: 0x3FE1_5670,
        reset_system: 0x3FE1_89A0,
        attempt: 4,
        failures_before_safe: 3,
    };
    let bytes = build(|b| b.uefi_runtime(&r).unwrap());
    assert_eq!(tags::parse(&bytes).unwrap().uefi_runtime().unwrap(), Some(r));

    let without = build(|b| b.firmware(Firmware::Uefi).unwrap());
    assert_eq!(tags::parse(&without).unwrap().uefi_runtime().unwrap(), None);

    // Cut short, it is malformed rather than a runtime whose entry points read as zero.
    let short = build(|b| b.tag(TagKind::UefiRuntime, &[0u8; 40]).unwrap());
    assert!(matches!(
        tags::parse(&short).unwrap().uefi_runtime(),
        Err(Error::Malformed { .. })
    ));
}

#[test]
fn the_boot_counter_is_named_in_terminated_ucs2_and_its_call_space_is_reserved() {
    let name = uefi::boot_counter::NAME;
    assert_eq!(name.last(), Some(&0));
    let text: String = name[..name.len() - 1]
        .iter()
        .map(|&u| char::from(u8::try_from(u).unwrap()))
        .collect();
    assert_eq!(text, "KinTaneBootAttempts");
    assert_eq!(uefi::kind_of(memory_type::KINTANE_FIRMWARE_CALL), MemoryKind::Reserved as u32);
}

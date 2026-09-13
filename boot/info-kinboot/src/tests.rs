use boot_protocol::tags::Builder;
use boot_protocol::{Firmware, MemoryKind, MemoryRegion};

use super::*;

const EMPTY: MemoryRegion = MemoryRegion {
    start: 0,
    len: 0,
    kind: 0,
    _reserved: 0,
};

fn usable(start: u64, len: u64) -> MemoryRegion {
    MemoryRegion {
        start,
        len,
        kind: MemoryKind::Usable as u32,
        _reserved: 0,
    }
}

/// A structure as the loader writes it: `n` separate usable regions.
fn handover(n: u64) -> Vec<u8> {
    let mut buf = vec![0u8; 8192];
    let mut b = Builder::new(&mut buf).unwrap();
    b.firmware(Firmware::Uefi).unwrap();
    let mut m = b.memory_map(64).unwrap();
    for i in 0..n {
        m.push(usable(0x10_0000 * (i + 1), 0x8_0000)).unwrap();
    }
    m.close();
    let len = b.finish();
    buf.truncate(len);
    buf
}

#[test]
fn the_structure_itself_comes_first_then_the_loaders_map() {
    let bytes = handover(3);
    let mut out = [EMPTY; 8];
    let n = regions_from(0x7F_0000, &bytes, &mut out).unwrap();
    assert_eq!(n, 4);
    assert_eq!(out[0].start, 0x7F_0000);
    assert_eq!(out[0].len, bytes.len() as u64);
    assert_eq!(out[0].kind, MemoryKind::BootData as u32);
    assert_eq!(
        out[1..4],
        [
            usable(0x10_0000, 0x8_0000),
            usable(0x20_0000, 0x8_0000),
            usable(0x30_0000, 0x8_0000)
        ]
    );
}

#[test]
fn a_map_larger_than_the_buffer_is_reported_with_the_callers_capacity() {
    let bytes = handover(5);
    let mut out = [EMPTY; 5];
    assert_eq!(
        regions_from(0x1000, &bytes, &mut out),
        Err(Error::TooManyRegions { capacity: 5 })
    );
    let mut exact = [EMPTY; 6];
    assert_eq!(regions_from(0x1000, &bytes, &mut exact), Ok(6));
}

#[test]
fn no_structure_no_map_and_a_corrupt_map_are_distinct_errors() {
    let mut out = [EMPTY; 8];
    assert_eq!(regions_from(0, &[0u8; 64], &mut out), Err(Error::NoLoader));

    let mut buf = vec![0u8; 256];
    let mut b = Builder::new(&mut buf).unwrap();
    b.firmware(Firmware::Uefi).unwrap();
    let len = b.finish();
    assert_eq!(regions_from(0, &buf[..len], &mut out), Err(Error::NoMemoryMap));

    let mut bad = handover(2);
    // The map tag follows the 16-byte firmware tag: corrupt its entry size.
    bad[32 + 8..32 + 12].copy_from_slice(&7u32.to_ne_bytes());
    assert!(matches!(regions_from(0, &bad, &mut out), Err(Error::Malformed { .. })));
}

#[test]
fn a_zero_pointer_reads_nothing() {
    let mut out = [EMPTY; 4];
    // SAFETY: zero is rejected before anything is dereferenced.
    assert_eq!(unsafe { memory_regions(0, &mut out) }, Err(Error::NoLoader));
}

#[test]
fn the_unsafe_entry_reads_a_real_address() {
    let bytes = handover(2);
    let mut out = [EMPTY; 8];
    let addr = bytes.as_ptr().expose_provenance() as u64;
    // SAFETY: `addr` is a live Vec holding a whole structure.
    let n = unsafe { memory_regions(addr, &mut out) }.unwrap();
    assert_eq!(n, 3);
    assert_eq!(out[0].start, addr);
}

#[test]
fn an_absurd_declared_size_is_not_believed() {
    let mut bytes = handover(1);
    bytes[12..16].copy_from_slice(&(64 * 1024 * 1024u32).to_ne_bytes());
    let mut out = [EMPTY; 8];
    let addr = bytes.as_ptr().expose_provenance() as u64;
    // SAFETY: only the 16-byte header is read before the size is rejected.
    assert_eq!(unsafe { memory_regions(addr, &mut out) }, Err(Error::Malformed { offset: 0 }));
}

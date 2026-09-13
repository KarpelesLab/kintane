use std::vec::Vec;

use super::*;

const PAGE: u64 = 4096;
const RANGE: (u64, u64) = (0x80_0000_0000, 0x100_0000_0000);
const BASE: u64 = 0x80_0001_0000;

/// One program header: `(flags, vaddr, file bytes, memory size)`.
type Ph = (u32, u64, Vec<u8>, u64);

/// A minimal ELF64 executable with the given program headers, files laid out after the
/// headers in order.
fn build(machine: u16, e_type: u16, entry: u64, phs: &[Ph]) -> Vec<u8> {
    let mut out = vec![0u8; EHDR_SIZE + phs.len() * PHDR_SIZE];
    out[0..4].copy_from_slice(b"\x7fELF");
    out[4] = 2;
    out[5] = 1;
    out[16..18].copy_from_slice(&e_type.to_le_bytes());
    out[18..20].copy_from_slice(&machine.to_le_bytes());
    out[24..32].copy_from_slice(&entry.to_le_bytes());
    out[32..40].copy_from_slice(&(EHDR_SIZE as u64).to_le_bytes());
    out[54..56].copy_from_slice(&(PHDR_SIZE as u16).to_le_bytes());
    out[56..58].copy_from_slice(&(phs.len() as u16).to_le_bytes());
    for (i, (flags, vaddr, file, mem)) in phs.iter().enumerate() {
        let ph = EHDR_SIZE + i * PHDR_SIZE;
        let off = out.len() as u64;
        out[ph..ph + 4].copy_from_slice(&PT_LOAD.to_le_bytes());
        out[ph + 4..ph + 8].copy_from_slice(&flags.to_le_bytes());
        out[ph + 8..ph + 16].copy_from_slice(&off.to_le_bytes());
        out[ph + 16..ph + 24].copy_from_slice(&vaddr.to_le_bytes());
        out[ph + 32..ph + 40].copy_from_slice(&(file.len() as u64).to_le_bytes());
        out[ph + 40..ph + 48].copy_from_slice(&mem.to_le_bytes());
        out.extend_from_slice(file);
    }
    out
}

fn text(vaddr: u64) -> Ph {
    (PF_R | PF_X, vaddr, vec![0xc3; 16], 16)
}

fn parse(bytes: &[u8]) -> Result<Program<'_>, Error> {
    Program::parse(bytes, EM_X86_64, RANGE, PAGE)
}

#[test]
fn a_well_formed_program_parses_and_lists_its_segments() {
    let data: Ph = (PF_R | PF_W, BASE + 0x1000, vec![1, 2, 3], 0x2000);
    let bytes = build(EM_X86_64, ET_EXEC, BASE + 4, &[text(BASE), data]);
    let p = parse(&bytes).unwrap();
    assert_eq!(p.entry, BASE + 4);
    let segs: Vec<_> = p.segments().map(Result::unwrap).collect();
    assert_eq!(segs.len(), 2);
    assert!(segs[0].access.execute && !segs[0].access.write);
    assert_eq!(segs[1].file, &[1, 2, 3]);
    assert_eq!(segs[1].mem_size, 0x2000);
    assert_eq!(segs[1].pages(PAGE), (BASE + 0x1000, BASE + 0x3000));
}

#[test]
fn writable_and_executable_is_refused() {
    let wx: Ph = (PF_R | PF_W | PF_X, BASE, vec![0xc3], 1);
    let bytes = build(EM_X86_64, ET_EXEC, BASE, &[wx]);
    assert_eq!(parse(&bytes).err(), Some(Error::WritableAndExecutable));
}

#[test]
fn a_segment_outside_the_user_range_is_refused() {
    // On top of the kernel, low in the address space.
    let bytes = build(EM_X86_64, ET_EXEC, 0x10_0000, &[text(0x10_0000)]);
    assert_eq!(parse(&bytes).err(), Some(Error::OutsideRange));
    // Starting inside, running past the end.
    let long: Ph = (PF_R | PF_X, RANGE.1 - 8, vec![0xc3], 16);
    let bytes = build(EM_X86_64, ET_EXEC, RANGE.1 - 8, &[long]);
    assert_eq!(parse(&bytes).err(), Some(Error::OutsideRange));
    // Wrapping round the top of the address space.
    let wrap: Ph = (PF_R | PF_X, u64::MAX - 4, vec![], 16);
    let bytes = build(EM_X86_64, ET_EXEC, u64::MAX - 4, &[wrap]);
    assert_eq!(parse(&bytes).err(), Some(Error::BadSegment));
}

#[test]
fn two_segments_in_one_page_are_refused() {
    let data: Ph = (PF_R | PF_W, BASE + 0x800, vec![1], 1);
    let bytes = build(EM_X86_64, ET_EXEC, BASE, &[text(BASE), data]);
    assert_eq!(parse(&bytes).err(), Some(Error::Overlap));
}

#[test]
fn the_entry_must_be_in_an_executable_segment() {
    let data: Ph = (PF_R | PF_W, BASE + 0x1000, vec![1], 1);
    let bytes = build(EM_X86_64, ET_EXEC, BASE + 0x1000, &[text(BASE), data]);
    assert_eq!(parse(&bytes).err(), Some(Error::EntryNotExecutable));
    let bytes = build(EM_X86_64, ET_EXEC, BASE + 16, &[text(BASE)]);
    assert_eq!(parse(&bytes).err(), Some(Error::EntryNotExecutable), "one past the end");
}

#[test]
fn wrong_kind_of_file_is_refused() {
    let good = build(EM_X86_64, ET_EXEC, BASE, &[text(BASE)]);
    assert!(parse(&good).is_ok());
    assert_eq!(
        parse(&build(EM_AARCH64, ET_EXEC, BASE, &[text(BASE)])).err(),
        Some(Error::WrongMachine(EM_AARCH64))
    );
    assert_eq!(
        parse(&build(EM_X86_64, 3, BASE, &[text(BASE)])).err(),
        Some(Error::NotExecutable),
        "a PIE is not loaded as if it were not one"
    );
    let mut not_elf = good.clone();
    not_elf[0] = 0;
    assert_eq!(parse(&not_elf).err(), Some(Error::NotElf64));
    assert_eq!(parse(&[]).err(), Some(Error::NotElf64));
}

#[test]
fn more_file_than_memory_and_truncation_are_errors() {
    let fat: Ph = (PF_R | PF_X, BASE, vec![0xc3; 32], 16);
    assert_eq!(parse(&build(EM_X86_64, ET_EXEC, BASE, &[fat])).err(), Some(Error::BadSegment));
    let good = build(EM_X86_64, ET_EXEC, BASE, &[text(BASE)]);
    for len in 0..good.len() {
        assert!(parse(&good[..len]).is_err(), "truncated to {len} still parsed");
    }
}

#[test]
fn no_loadable_memory_is_an_error() {
    let empty: Ph = (PF_R | PF_X, BASE, vec![], 0);
    assert_eq!(parse(&build(EM_X86_64, ET_EXEC, BASE, &[empty])).err(), Some(Error::NoSegments));
}

#[test]
fn too_many_segments_is_an_error_not_a_truncated_list() {
    let phs: Vec<Ph> = (0..=MAX_SEGMENTS as u64)
        .map(|i| (PF_R, BASE + 0x1000 * (i + 1), vec![], 1))
        .chain([text(BASE)])
        .collect();
    assert_eq!(
        parse(&build(EM_X86_64, ET_EXEC, BASE, &phs)).err(),
        Some(Error::TooManySegments)
    );
}

#[test]
fn garbage_never_panics() {
    let good =
        build(EM_X86_64, ET_EXEC, BASE, &[text(BASE), (PF_R, BASE + 0x1000, vec![7; 40], 64)]);
    let mut state = 0x9e37_79b9_7f4a_7c15u64;
    for _ in 0..20_000 {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let mut bytes = good.clone();
        let at = (state as usize) % bytes.len();
        bytes[at] = (state >> 32) as u8;
        let _ = parse(&bytes).map(|p| p.segments().count());
    }
}

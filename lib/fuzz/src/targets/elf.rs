//! Static ELF executables: what the kernel loads a userspace program from.
//!
//! Built rather than seeded. An ELF64 executable's header is fixed-size and its program
//! headers are a flat array, so a generator can produce a structurally valid one in a few
//! dozen lines — and one it built is more useful than a mutated real binary, because it can
//! put the interesting values *in the fields that matter* rather than hoping a random word
//! lands there.
//!
//! # Valid first, then one mistake
//!
//! The generator builds a program `Program::parse` accepts — segments on distinct pages
//! inside the user range, an entry point inside the first, executable one — and then, a
//! third of the time, makes exactly one mistake a validator exists to catch: a segment
//! below or above the range, one that wraps, two sharing a page, an entry outside every
//! executable segment, a header field that disagrees with the table.
//!
//! The first version built "plausible but not always sane" programs, with most of the
//! segment addresses deliberately wrong. Its campaign accepted **none** of 5000 inputs:
//! besides those choices, it wrote `e_phentsize` and `e_phnum` two bytes late, so the
//! parser read the header size (64) where it wanted the entry size (56) and refused every
//! file at the first check. The fuzzer had been testing one `return Err`. The acceptance
//! rate `kbuild fuzz` now prints, and the host test that requires it, are what found that.
//!
//! The parser is given the same bounds the kernel gives it — a user address range and a
//! page size — because "inside the range" is half of what it checks.

use alloc::vec;
use alloc::vec::Vec;

use elf::{EM_AARCH64, EM_X86_64, Program};

use crate::{Mutator, Rng};

const EHDR_SIZE: usize = 64;
const PHDR_SIZE: usize = 56;
const PT_LOAD: u32 = 1;
const ET_EXEC: u16 = 2;
const PF_X: u32 = 1;
const PF_W: u32 = 2;
const PF_R: u32 = 4;

/// The user range and page size the kernel parses against.
const RANGE: (u64, u64) = (0x1000, 0x0000_8000_0000_0000);
const PAGE: u64 = 4096;

pub fn generate(rng: &mut Rng, _seeds: &[Vec<u8>]) -> Vec<u8> {
    let mut bytes = build(rng);
    // Half the time the bytes are corrupted as well; the other half, the structural mistake
    // (or none) is the whole story, so the paths behind the header stay reachable.
    if rng.one_in(2) {
        Mutator::mutate(rng, &mut bytes);
    }
    bytes
}

struct Segment {
    kind: u32,
    flags: u32,
    vaddr: u64,
    file: Vec<u8>,
    mem_size: u64,
}

fn build(rng: &mut Rng) -> Vec<u8> {
    // A valid program: segments on strictly increasing pages, the first executable.
    let count = 1 + rng.below(4);
    let mut segments: Vec<Segment> = Vec::new();
    let mut next_page = RANGE.0 + (1 + rng.below(16) as u64) * PAGE;
    for i in 0..count {
        let file_len = rng.interesting_len(64);
        let file: Vec<u8> = (0..file_len).map(|_| rng.next_u32() as u8).collect();
        let mem_size = (file_len as u64).max(1) + (rng.below(3) as u64) * PAGE;
        let flags = if i == 0 {
            PF_R | PF_X
        } else {
            *rng.pick(&[PF_R, PF_R | PF_W, PF_R | PF_X])
        };
        let vaddr = next_page;
        // The next segment starts on a page after this one's last, so no two share a page.
        next_page = (vaddr + mem_size).div_ceil(PAGE) * PAGE + (rng.below(4) as u64) * PAGE;
        segments.push(Segment {
            kind: PT_LOAD,
            flags,
            vaddr,
            file,
            mem_size,
        });
    }
    let first = &segments[0];
    let mut entry = first.vaddr + rng.below(first.mem_size as usize) as u64;
    let mut machine = if rng.one_in(2) { EM_X86_64 } else { EM_AARCH64 };
    let mut file_kind = ET_EXEC;
    let mut phentsize = PHDR_SIZE as u16;
    let mut phnum: Option<u16> = None;

    // A third of the time, exactly one mistake: each is a rule `Program::parse` enforces,
    // or a record it must step over rather than refuse.
    if rng.one_in(3) {
        let s = rng.below(segments.len());
        match rng.below(12) {
            0 => segments[s].vaddr = RANGE.0 - 1,
            1 => segments[s].vaddr = RANGE.1 - PAGE / 2,
            2 => segments[s].vaddr = u64::MAX - PAGE,
            3 => {
                if segments.len() > 1 {
                    let shared = segments[0].vaddr + 8;
                    let last = segments.len() - 1;
                    segments[last].vaddr = shared;
                }
            }
            // Empty, which is skipped rather than refused.
            4 => segments[s].mem_size = 0,
            5 => entry = RANGE.1 + PAGE,
            6 => {
                for seg in &mut segments {
                    seg.flags &= !PF_X;
                }
            }
            // Not a loadable segment, which is skipped.
            7 => segments[s].kind = rng.next_u32(),
            8 => machine = 0x3e21,
            9 => file_kind = 3,
            10 => phentsize = 32,
            _ => phnum = Some(rng.next_u32() as u16),
        }
    }

    // The bytes: header, program headers, then each segment's file contents.
    let headers = EHDR_SIZE + segments.len() * PHDR_SIZE;
    let mut phdrs: Vec<u8> = Vec::new();
    let mut body: Vec<u8> = Vec::new();
    for seg in &segments {
        let offset = (headers + body.len()) as u64;
        body.extend_from_slice(&seg.file);
        let mut ph = [0u8; PHDR_SIZE];
        ph[0..4].copy_from_slice(&seg.kind.to_le_bytes());
        ph[4..8].copy_from_slice(&seg.flags.to_le_bytes());
        ph[8..16].copy_from_slice(&offset.to_le_bytes());
        ph[16..24].copy_from_slice(&seg.vaddr.to_le_bytes());
        ph[24..32].copy_from_slice(&seg.vaddr.to_le_bytes());
        ph[32..40].copy_from_slice(&(seg.file.len() as u64).to_le_bytes());
        ph[40..48].copy_from_slice(&seg.mem_size.to_le_bytes());
        ph[48..56].copy_from_slice(&PAGE.to_le_bytes());
        phdrs.extend_from_slice(&ph);
    }

    let mut out = vec![0u8; EHDR_SIZE];
    out[0..4].copy_from_slice(b"\x7fELF");
    out[4] = 2; // ELFCLASS64
    out[5] = 1; // ELFDATA2LSB
    out[6] = 1; // EV_CURRENT
    out[16..18].copy_from_slice(&file_kind.to_le_bytes());
    out[18..20].copy_from_slice(&machine.to_le_bytes());
    out[20..24].copy_from_slice(&1u32.to_le_bytes());
    out[24..32].copy_from_slice(&entry.to_le_bytes());
    out[32..40].copy_from_slice(&(EHDR_SIZE as u64).to_le_bytes());
    // e_ehsize, e_phentsize, e_phnum: ELF64 puts them at 52, 54 and 56.
    out[52..54].copy_from_slice(&(EHDR_SIZE as u16).to_le_bytes());
    out[54..56].copy_from_slice(&phentsize.to_le_bytes());
    let count = phnum.unwrap_or(segments.len() as u16);
    out[56..58].copy_from_slice(&count.to_le_bytes());

    out.extend_from_slice(&phdrs);
    out.extend_from_slice(&body);
    out
}

/// Past the first check: a header, program headers and segments that validate for either
/// machine the kernel loads programs for.
pub fn accepts(input: &[u8]) -> bool {
    [EM_X86_64, EM_AARCH64]
        .into_iter()
        .any(|machine| Program::parse(input, machine, RANGE, PAGE).is_ok())
}

pub fn run(input: &[u8]) {
    for machine in [EM_X86_64, EM_AARCH64] {
        let Ok(program) = Program::parse(input, machine, RANGE, PAGE) else {
            continue;
        };
        let _ = program.entry;
        for segment in program.segments() {
            let Ok(s) = segment else { break };
            // What a loader does with each: bound its pages and read its bytes.
            let _ = s.pages(PAGE);
            let _ = s.file.len();
            let _ = s.mem_size.checked_sub(s.file.len() as u64);
            let _ = (s.access.read, s.access.write, s.access.execute);
        }
    }
}

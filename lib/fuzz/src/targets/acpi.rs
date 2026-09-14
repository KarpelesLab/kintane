//! ACPI tables: what firmware describes a PC with.
//!
//! Seeded, for the reason device trees are: a table set is an RSDP pointing at an XSDT
//! pointing at tables, each with its own length and a checksum over all of it. A generator
//! building that from nothing would be a second implementation of the firmware.
//!
//! # The seeds are records, not memory
//!
//! Each seed is what `boot/acpi/src/testdata/extract.py` writes from a QEMU memory dump: a
//! sequence of records, each a little-endian `u64` physical address, a `u32` length and
//! that many bytes, with the RSDP first. The first version of this target treated a seed as
//! flat memory starting at address zero and scanned it for an RSDP. There is none at any of
//! those offsets, so its campaign accepted **none** of 5000 inputs and tested only the
//! scan's failure; the acceptance rate `kbuild fuzz` prints is what showed it.
//!
//! So the input is parsed back into records, and [`Records`] answers `PhysMemory` reads
//! from whichever record holds the address, as the parser's own tests do.
//!
//! # Mutation inside the records, and checksums repaired half the time
//!
//! A mutation is applied to a record's *bytes* — a table — and only occasionally to the
//! record's address or length, which would otherwise move tables out from under the
//! pointers to them on nearly every input. A mutated table almost always fails its
//! checksum, which a parser checks first, so half the time the checksum of what was
//! corrupted is repaired. That is what gets the mutation past the gate and into the walks
//! over entries, segments and addresses; the gate itself is covered by the parser's tests.

use alloc::vec::Vec;

use acpi::{Fadt, Madt, Mcfg, PhysMemory, Rsdp, Tables};

use crate::{Mutator, Rng};

/// More records than any seed has: QEMU's `pc` has eight tables and the RSDP.
const MAX_RECORDS: usize = 64;
/// The record header: an address and a length.
const RECORD_HEADER: usize = 12;

/// The input's records, borrowed.
struct Records<'a> {
    regions: Vec<(u64, &'a [u8])>,
}

impl<'a> Records<'a> {
    /// Parse as many whole records as the input holds. A record whose length runs past the
    /// end stops the walk, as a truncated capture would.
    fn parse(input: &'a [u8]) -> Records<'a> {
        let mut regions = Vec::new();
        let mut at = 0usize;
        while regions.len() < MAX_RECORDS && at + RECORD_HEADER <= input.len() {
            let address = u64::from_le_bytes(input[at..at + 8].try_into().unwrap_or([0; 8]));
            let len =
                u32::from_le_bytes(input[at + 8..at + 12].try_into().unwrap_or([0; 4])) as usize;
            let start = at + RECORD_HEADER;
            let Some(bytes) = start.checked_add(len).and_then(|end| input.get(start..end)) else {
                break;
            };
            regions.push((address, bytes));
            at = start + len;
        }
        Records { regions }
    }

    /// Where the capture put the RSDP.
    fn rsdp_address(&self) -> Option<u64> {
        self.regions.first().map(|(a, _)| *a)
    }
}

impl PhysMemory for Records<'_> {
    fn bytes(&self, address: u64, len: usize) -> Option<&[u8]> {
        self.regions.iter().find_map(|(base, bytes)| {
            let offset = usize::try_from(address.checked_sub(*base)?).ok()?;
            bytes.get(offset..offset.checked_add(len)?)
        })
    }
}

/// Owned records, for mutating and writing back.
fn split(seed: &[u8]) -> Vec<(u64, Vec<u8>)> {
    Records::parse(seed)
        .regions
        .into_iter()
        .map(|(a, b)| (a, b.to_vec()))
        .collect()
}

fn join(records: &[(u64, Vec<u8>)]) -> Vec<u8> {
    let mut out = Vec::new();
    for (address, bytes) in records {
        out.extend_from_slice(&address.to_le_bytes());
        out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
        out.extend_from_slice(bytes);
    }
    out
}

/// Set the checksum byte at `checksum_at` so the first `len` bytes sum to zero.
fn fix_checksum(bytes: &mut [u8], checksum_at: usize, len: usize) {
    let len = len.min(bytes.len());
    if checksum_at >= len {
        return;
    }
    bytes[checksum_at] = 0;
    let sum = bytes[..len].iter().fold(0u8, |a, &b| a.wrapping_add(b));
    bytes[checksum_at] = sum.wrapping_neg();
}

pub fn generate(rng: &mut Rng, seeds: &[Vec<u8>]) -> Vec<u8> {
    if seeds.is_empty() {
        return Vec::new();
    }
    let mut records = split(rng.pick(seeds));
    if records.is_empty() {
        return rng.pick(seeds).clone();
    }

    let i = rng.below(records.len());
    if rng.one_in(10) {
        // Occasionally the record itself: a table that moved, or one shorter than the
        // pointers to it assume.
        if rng.one_in(2) {
            records[i].0 = records[i].0.wrapping_add(u64::from(rng.interesting_u32()));
        } else {
            let keep = rng.below(records[i].1.len() + 1);
            records[i].1.truncate(keep);
        }
    } else {
        Mutator::mutate(rng, &mut records[i].1);
    }

    if rng.one_in(2) {
        let bytes = &mut records[i].1;
        if i == 0 {
            // The RSDP: a checksum over the first 20 bytes, and on revision 2 an extended
            // one over all 36.
            fix_checksum(bytes, 8, 20);
            if bytes.len() >= 36 && bytes.get(15).is_some_and(|&rev| rev >= 2) {
                fix_checksum(bytes, 32, 36);
            }
        } else if bytes.len() >= 36 {
            // A table: its own declared length, and a checksum over that many bytes.
            let declared = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]) as usize;
            fix_checksum(bytes, 9, declared);
        }
    }
    join(&records)
}

/// Past the first check: the RSDP the capture recorded, and the root table it points at.
pub fn accepts(input: &[u8]) -> bool {
    let mem = Records::parse(input);
    let Some(address) = mem.rsdp_address() else {
        return false;
    };
    Rsdp::read(&mem, address).is_ok_and(|rsdp| Tables::new(&mem, rsdp).is_ok())
}

pub fn run(input: &[u8]) {
    let mem = Records::parse(input);

    // The BIOS scan, which walks whatever of its area the records happen to cover.
    let _ = Rsdp::find_bios(&mem);

    let Some(address) = mem.rsdp_address() else {
        return;
    };
    let Ok(rsdp) = Rsdp::read(&mem, address) else {
        return;
    };
    let Ok(tables) = Tables::new(&mem, rsdp) else {
        return;
    };

    for address in tables.addresses() {
        let _ = tables.read(address);
    }

    for signature in [b"APIC", b"MCFG", b"FACP", b"DSDT"] {
        let Ok(Some(sdt)) = tables.find(signature) else {
            continue;
        };
        let _ = (sdt.address(), sdt.revision(), sdt.bytes().len());

        if let Ok(madt) = Madt::parse(sdt) {
            let _ = madt.header_local_apic_address();
            let _ = madt.flags();
            let _ = madt.local_apic_address();
            for entry in madt.entries() {
                if entry.is_err() {
                    break;
                }
            }
        }
        if let Ok(mcfg) = Mcfg::parse(sdt) {
            for segment in mcfg.segments() {
                let Ok(s) = segment else { break };
                let _ = s.len();
                // The address arithmetic a driver does with a segment, at its edges.
                let _ = s.function_address(s.start_bus, 0, 0);
                let _ = s.function_address(s.end_bus, 31, 7);
            }
        }
        if let Ok(fadt) = Fadt::parse(sdt) {
            let _ = (fadt.flags(), fadt.sci_interrupt(), fadt.dsdt());
            let _ = fadt.pm_timer();
            let _ = fadt.reset();
        }
    }
}

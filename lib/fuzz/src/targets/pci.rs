//! PCI configuration space: what a device answers when the kernel enumerates it.
//!
//! Untrusted in a way the file formats are not. There is no file here: the input is the
//! *devices' answers*, and a hostile or broken device answers however it likes. A bridge
//! can claim a secondary bus that loops back to its own, every function can claim to be a
//! multifunction bridge, and a BAR can report a size that is not a power of two.
//!
//! # Buses laid out on purpose
//!
//! The generator builds a machine: a host bridge and a PCI-to-PCI bridge on bus 0, devices
//! behind the bridge on its secondary bus, and sometimes a second bridge, a bridge whose
//! secondary bus loops back to one already walked, one outside the enumerated range, or a
//! multifunction device. Then, half the time, it corrupts the bytes.
//!
//! The first version filled configuration space word by word at random. Enumeration never
//! once found a bridge with a device behind it: a bridge needs a header type, a secondary
//! bus in range and a device answering on that bus to line up by chance, and they did not.
//! That was found by breaking `enumerate` on purpose — recording an impossible parent for
//! every function behind a bridge — and running 20,000 inputs without one failure. The
//! recursion into child buses, and the parent-ordering invariant this target checks, had
//! never run.
//!
//! # Sparse records, not a register file
//!
//! An input is a list of 8-byte records, `bus, device, function, slot` and a little-endian
//! value; a slot below 64 is a header word, and 64 to 69 are the six BAR size masks. A read
//! is answered by the last record for that register, and a register with none reads as
//! all-ones, which is an empty slot.
//!
//! The second version laid the same machines out as a dense register file: every slot of
//! five buses, whether anything was there or not. That is some 360 KiB per input, nearly
//! all of it the all-ones of empty slots, so mutations landed in padding, and shrinking a
//! failure would have spawned a worker for tens of thousands of candidates. Records make an
//! input a few kilobytes of registers that matter.
//!
//! # BARs that size like hardware
//!
//! Sizing a BAR writes all-ones and reads back what the device kept: the size, as a mask.
//! [`Fake`] answers that write from the BAR's mask record rather than with the all-ones it
//! was given, so sizing and `verify_restored` run their real arithmetic.
//!
//! What is checked is that enumeration ends, stays inside the caller's storage, and comes
//! back with every function's parent an earlier entry — the invariant `enumerate`
//! documents, and the one a loop in the bus graph would break.

use alloc::vec::Vec;
use core::cell::RefCell;

use device::pci::{Address, ConfigSpace, Function, enumerate, verify_restored};

use crate::{Mutator, Rng};

/// Functions the enumeration may report. Small, so filling it is reachable: more functions
/// than the caller's storage holds is a path with an error of its own.
const MAX_FUNCTIONS: usize = 24;

/// The last bus enumerated. A bridge pointing above it is recorded and not followed.
const LAST_BUS: u8 = 4;

/// Bytes per record: bus, device, function, slot, then a `u32`.
const RECORD: usize = 8;

/// The most records an input is read for. Far more than any generated machine has; a
/// longer input's tail is ignored rather than making every read slower.
const MAX_RECORDS: usize = 4096;

/// The slot of BAR `i`'s size mask, after the header's 64 words.
const MASK_SLOT: u8 = 64;

// Register offsets, as `device::pci` reads them.
const ID: u16 = 0x00;
const CLASS: u16 = 0x08;
const HEADER: u16 = 0x0c;
const BAR0: u16 = 0x10;
const BUS_NUMBERS: u16 = 0x18;
const INTERRUPT: u16 = 0x3c;

/// A machine that answers from the fuzzer's records.
struct Fake {
    /// `(bus, device, function, slot, value)`, in input order; the last for a register wins.
    records: Vec<(u8, u8, u8, u8, u32)>,
    written: RefCell<Vec<(Address, u16, u32)>>,
}

impl Fake {
    fn parse(input: &[u8]) -> Fake {
        let records = input
            .chunks_exact(RECORD)
            .take(MAX_RECORDS)
            .map(|r| (r[0], r[1], r[2], r[3], u32::from_le_bytes([r[4], r[5], r[6], r[7]])))
            .collect();
        Fake {
            records,
            written: RefCell::new(Vec::new()),
        }
    }

    /// The input's value for a slot, or all-ones for one it does not describe.
    fn slot(&self, at: Address, slot: u8) -> u32 {
        self.records
            .iter()
            .rev()
            .find(|r| r.0 == at.bus && r.1 == at.device && r.2 == at.function && r.3 == slot)
            .map_or(0xffff_ffff, |r| r.4)
    }
}

impl ConfigSpace for Fake {
    fn read(&self, at: Address, offset: u16) -> u32 {
        let written = self
            .written
            .borrow()
            .iter()
            .rev()
            .find(|(a, o, _)| *a == at && *o == offset)
            .map(|(_, _, v)| *v);
        let is_bar = (BAR0..BAR0 + 24).contains(&offset);
        match written {
            // The sizing probe: a BAR keeps only the bits its size allows.
            Some(0xffff_ffff) if is_bar => {
                let bar = ((offset - BAR0) / 4) as u8;
                let original = self.slot(at, (offset / 4) as u8);
                let mask = self.slot(at, MASK_SLOT + bar);
                // The low bits say memory or I/O, and are read-only.
                let kept = if original & 1 == 1 { 0x3 } else { 0xf };
                (mask & !kept) | (original & kept)
            }
            Some(v) => v,
            None => self.slot(at, (offset / 4) as u8),
        }
    }

    fn write(&self, at: Address, offset: u16, value: u32) {
        self.written.borrow_mut().push((at, offset, value));
    }
}

/// The input being built, as records.
struct Space {
    bytes: Vec<u8>,
}

impl Space {
    fn record(&mut self, at: Address, slot: u8, value: u32) {
        self.bytes
            .extend_from_slice(&[at.bus, at.device, at.function, slot]);
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn set(&mut self, at: Address, offset: u16, value: u32) {
        self.record(at, (offset / 4) as u8, value);
    }

    /// A type-0 endpoint with plausible BARs, and sometimes an implausible one.
    fn endpoint(&mut self, rng: &mut Rng, at: Address, multifunction: bool) {
        let vendor = *rng.pick(&[0x1af4u32, 0x8086, 0x1b36, 0x10de]);
        let device = rng.next_u32() & 0xffff;
        self.set(at, ID, vendor | (device << 16));
        let class = *rng.pick(&[0x0100_0000u32, 0x0200_0000, 0x0300_0000, 0x0c03_3000]);
        self.set(at, CLASS, class | (rng.next_u32() & 0xff));
        self.set(at, HEADER, if multifunction { 0x0080_0000 } else { 0 });
        for bar in 0..6u8 {
            let (value, mask) = match rng.below(4) {
                // 32-bit memory, a power-of-two size.
                0 => (0xfe00_0000u32, !((1u32 << (12 + rng.below(12))) - 1)),
                // I/O ports.
                1 => (0x0000_c001, !((1u32 << (2 + rng.below(6))) - 1)),
                // A size that is not a power of two, which hardware must not report.
                2 => (0xfd00_0000, rng.next_u32() | 0xf),
                _ => (0, 0),
            };
            self.set(at, BAR0 + 4 * u16::from(bar), value);
            self.record(at, MASK_SLOT + bar, mask);
        }
        self.set(at, INTERRUPT, ((1 + rng.below(4) as u32) << 8) | 11);
    }

    /// A type-1 bridge to buses `secondary..=subordinate`.
    fn bridge(&mut self, at: Address, secondary: u8, subordinate: u8) {
        self.set(at, ID, 0x8086 | (0x244e << 16));
        self.set(at, CLASS, 0x0604_0000);
        self.set(at, HEADER, 0x0001_0000);
        let buses =
            u32::from(at.bus) | (u32::from(secondary) << 8) | (u32::from(subordinate) << 16);
        self.set(at, BUS_NUMBERS, buses);
    }
}

pub fn generate(rng: &mut Rng, _seeds: &[Vec<u8>]) -> Vec<u8> {
    let mut space = Space { bytes: Vec::new() };

    // Bus 0: a host bridge, which sizing leaves alone.
    let host = Address::new(0, 0, 0);
    space.set(host, ID, 0x8086 | (0x29c0 << 16));
    space.set(host, CLASS, 0x0600_0000);
    space.set(host, HEADER, 0);

    // A bridge on bus 0, to a secondary bus that usually exists and is in range.
    let secondary = match rng.below(8) {
        // Back to bus 0, which enumeration has already walked.
        0 => 0,
        // Beyond the enumerated range: recorded, not followed.
        1 => LAST_BUS + 1 + rng.below(8) as u8,
        _ => 1 + rng.below(usize::from(LAST_BUS)) as u8,
    };
    let bridge_dev = 1 + rng.below(8) as u8;
    space.bridge(Address::new(0, bridge_dev, 0), secondary, secondary.max(LAST_BUS));

    // Endpoints beside it on bus 0, at higher device numbers, so a child's parent is not
    // always the entry immediately before the children.
    for _ in 0..rng.below(4) {
        let dev = 10 + rng.below(20) as u8;
        space.endpoint(rng, Address::new(0, dev, 0), false);
    }

    // Devices behind the bridge.
    if secondary != 0 && secondary <= LAST_BUS {
        for _ in 0..1 + rng.below(3) {
            let dev = rng.below(32) as u8;
            let multifunction = rng.one_in(4);
            space.endpoint(rng, Address::new(secondary, dev, 0), multifunction);
            if multifunction {
                for f in 1..1 + rng.below(7) as u8 {
                    space.endpoint(rng, Address::new(secondary, dev, f), false);
                }
            }
        }
        // Sometimes a second bridge behind the first: to a new bus, to itself, or back to
        // bus 0, which enumeration must visit at most once whatever bridges claim.
        if rng.one_in(3) {
            let next = match rng.below(3) {
                0 => secondary,
                1 => 0,
                _ => (secondary % LAST_BUS) + 1,
            };
            let dev = 20 + rng.below(8) as u8;
            space.bridge(Address::new(secondary, dev, 0), next, LAST_BUS);
            if next != 0 && next != secondary && next <= LAST_BUS {
                let at = Address::new(next, rng.below(32) as u8, 0);
                space.endpoint(rng, at, false);
            }
        }
    }

    let mut bytes = space.bytes;
    if rng.one_in(2) {
        Mutator::mutate(rng, &mut bytes);
    }
    bytes
}

pub fn run(input: &[u8]) {
    let cfg = Fake::parse(input);
    let mut out = [Function::EMPTY; MAX_FUNCTIONS];
    let Ok(n) = enumerate(&cfg, 0, LAST_BUS, &mut out) else {
        return;
    };

    for (i, f) in out.iter().take(n).enumerate() {
        // Every function's parent must be an earlier entry: that is what makes the list
        // walkable, and a bus graph that looped would break it.
        if let Some(parent) = f.parent {
            assert!(
                usize::from(parent) < i,
                "function {i} at {:?} names parent {parent}, which is not earlier",
                f.address
            );
        }
        let _ = f.name();
        let _ = f.compatible();
        let _ = f.is_host_bridge();
        let _ = f.original_bars();
        for b in 0..6 {
            let _ = f.memory_bar(b);
        }
    }

    // Sizing must leave the BARs as it found them. The fake records every write, so a BAR
    // not written back shows here.
    let _ = verify_restored(&cfg, &out[..n]);
}

//! AML: the DSDT and SSDT bytecode a PC's firmware describes its devices in.
//!
//! Seeded with the DSDTs QEMU's q35 and pc machines publish, taken from the captures in
//! `boot/acpi/src/testdata`. A seed is one whole table, header included. A generator
//! building AML from nothing would be a second compiler.
//!
//! # Mutation in the body, the checksum always repaired
//!
//! A mutation lands after the header. The length and checksum are then rewritten every
//! time: the checksum is the table parser's gate, which the `acpi` target already covers.
//! This target is about what happens after that gate: loading the namespace, and running
//! what it declares.
//!
//! # What a run exercises
//!
//! `run` does what the kernel does with a table. It loads the table, selects APIC mode, and
//! routes the pins of a function on the root bus, of the LPC bridge, and of a function
//! behind a bridge. Then it evaluates every method with integer arguments. Each evaluation
//! has a small step budget, and the host answers every field read with changing values, so
//! loops that wait on a register end. Errors are expected; a panic or a hang is the bug.

use alloc::vec;
use alloc::vec::Vec;

use acpi::Sdt;
use acpi::aml::{Host, Interpreter, Node, Object, Space, Storage};

use crate::{Mutator, Rng};

/// A table header's length.
const HEADER: usize = 36;
/// Steps per evaluation. QEMU's routing takes under two thousand.
const STEPS: u32 = 5_000;

/// Field reads answer with a value that changes on every access; writes are absorbed.
struct Answers(u64);

impl Host for Answers {
    fn read(&mut self, _: Space, address: u64, _: u8) -> Option<u64> {
        self.0 = self.0.rotate_left(7) ^ address;
        Some(self.0)
    }

    fn write(&mut self, _: Space, _: u64, _: u8, value: u64) -> Option<()> {
        self.0 ^= value;
        Some(())
    }
}

/// Set the header's length to the table's and repair its checksum.
fn repair(table: &mut [u8]) {
    if table.len() < HEADER {
        return;
    }
    let len = table.len() as u32;
    table[4..8].copy_from_slice(&len.to_le_bytes());
    table[9] = 0;
    let sum = table.iter().fold(0u8, |a, &b| a.wrapping_add(b));
    table[9] = sum.wrapping_neg();
}

pub fn generate(rng: &mut Rng, seeds: &[Vec<u8>]) -> Vec<u8> {
    if seeds.is_empty() {
        return Vec::new();
    }
    let mut table = rng.pick(seeds).clone();
    if table.len() <= HEADER {
        return table;
    }
    let mut body = table.split_off(HEADER);
    Mutator::mutate(rng, &mut body);
    table.extend_from_slice(&body);
    repair(&mut table);
    table
}

/// Storage for one interpreter, as large as the kernel's.
struct Owned {
    nodes: Vec<Node>,
    cells: Vec<Object>,
    bytes: Vec<u8>,
}

impl Owned {
    fn new() -> Owned {
        Owned {
            nodes: vec![Node::EMPTY; 1024],
            cells: vec![Object::Uninitialized; 1024],
            bytes: vec![0; 4096],
        }
    }

    fn storage(&mut self) -> Storage<'_> {
        Storage {
            nodes: &mut self.nodes,
            cells: &mut self.cells,
            bytes: &mut self.bytes,
        }
    }
}

/// Past the table's checksum and into a namespace that loaded.
pub fn accepts(input: &[u8]) -> bool {
    let Ok(sdt) = Sdt::from_bytes(0, input) else {
        return false;
    };
    let mut owned = Owned::new();
    let Ok(mut aml) = Interpreter::new(owned.storage(), Answers(0)) else {
        return false;
    };
    aml.load(sdt).is_ok()
}

pub fn run(input: &[u8]) {
    let Ok(sdt) = Sdt::from_bytes(0, input) else {
        return;
    };
    let mut owned = Owned::new();
    let Ok(mut aml) = Interpreter::new(owned.storage(), Answers(0x9e37_79b9_7f4a_7c15)) else {
        return;
    };
    aml.set_budget(STEPS);
    if aml.load(sdt).is_err() {
        return;
    }
    let _ = aml.select_apic_mode();
    let paths: [&[(u8, u8)]; 3] = [&[(3, 0)], &[(0x1f, 0)], &[(4, 0), (2, 0)]];
    for path in paths {
        for pin in 1..=4 {
            let _ = aml.route_pin(0, path, pin);
        }
    }
    let methods: Vec<_> = aml
        .all_nodes()
        .filter_map(|node| aml.method_args(node).map(|args| (node, args)))
        .collect();
    for (node, args) in methods {
        let args = vec![Object::Integer(1); args];
        let _ = aml.evaluate(node, &args);
    }
}

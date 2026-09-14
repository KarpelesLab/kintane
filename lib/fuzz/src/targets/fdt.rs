//! Device trees: what firmware hands every port that has no ACPI.
//!
//! Seeded rather than built. A device tree is a header of eleven big-endian offsets, a
//! reservation block, a token stream and a string table, all referring to each other by
//! offset; a generator that produced valid ones from nothing would be a second
//! implementation of the writer, and its bugs would look like parser bugs. The seeds are
//! the real blobs QEMU passes `virt`, plus the small hand-written tree the device model's
//! own tests use.
//!
//! The mutations that matter here are big-endian words: every length and offset in the
//! header is one, and flipping a bit inside `totalsize` usually just makes it absurd,
//! where replacing it with another plausible offset reaches the block walks.
//!
//! Both layers are driven: `fdt::Fdt`, which validates the blob, and
//! `device::DeviceTree::build`, which walks it into nodes. The second is where a tree that
//! passed validation can still be hostile — a depth that never closes, a `ranges` that
//! lies, a phandle pointing at itself.

use alloc::vec::Vec;

use boot_protocol::MemoryRegion;
use device::tree::{DeviceTree, Node};
use fdt::Fdt;

use crate::{Mutator, Rng};

/// A tree's nodes need somewhere to live; the kernel gives the builder a fixed array and
/// so does this. Larger than any seed needs, so running out is not the common path — but
/// a mutated tree can still fill it, which is a case worth reaching.
const MAX_NODES: usize = 96;

pub fn generate(rng: &mut Rng, seeds: &[Vec<u8>]) -> Vec<u8> {
    if seeds.is_empty() {
        return Vec::new();
    }
    let mut bytes = rng.pick(seeds).clone();
    // Always mutate: an unmutated seed is the parsers' own fixture, already covered by
    // their tests, and spending iterations re-parsing it proves nothing new.
    Mutator::mutate(rng, &mut bytes);
    bytes
}

pub fn run(input: &[u8]) {
    // The header alone, as the kernel reads it before it has a length to slice by.
    let _ = fdt::Header::parse(input);

    let Ok(tree) = Fdt::new(input) else {
        return;
    };

    let mut map = [MemoryRegion {
        start: 0,
        len: 0,
        kind: 0,
        _reserved: 0,
    }; 16];
    let _ = tree.memory_map(&mut map);
    let _ = tree.bootargs();
    let _ = tree.reservations().count();
    // The token walk, which is what every higher layer iterates.
    for token in tree.tokens() {
        if token.is_err() {
            break;
        }
    }

    // The device model's view: nodes, their addresses, and the relationships between them.
    let mut storage = [Node::EMPTY; MAX_NODES];
    let Ok(model) = DeviceTree::build(&tree, &mut storage) else {
        return;
    };
    let _ = model.stdout();
    for id in model.ids() {
        let node = model.node(id);
        let _ = node.name().len();
        let _ = node.compatible().count();
        let _ = node.is_interrupt_controller();
        let _ = node.is_available();
        let _ = node.clock_frequency();
        if let Some(phandle) = node.phandle() {
            let _ = model.by_phandle(phandle);
        }
        let _ = model.children(id).count();
        // The interpreting accessors, which is where a tree that passed validation can
        // still lie: cells that disagree, `ranges` that do not translate, a `reg` whose
        // entries are not whole.
        let _ = model.mmio_count(id);
        for index in 0..3 {
            let _ = model.mmio(id, index);
            let _ = model.ports(id, index);
            let _ = model.interrupt(id, index);
            let _ = model.clock(id, index);
        }
        let _ = model.interrupt_count(id);
        let _ = model.interrupt_parent(id);
        let _ = model.reg_address(id, 0);
    }
}

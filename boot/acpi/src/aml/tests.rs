//! Host tests: the DSDTs QEMU's q35 and pc machines really publish, from the captures in
//! `testdata/`, and small tables built here to reach what those do not.

use std::collections::HashMap;
use std::vec::Vec;

use super::*;
use crate::Sdt;

const Q35: &[u8] = include_bytes!("../testdata/q35.bin");
const PC: &[u8] = include_bytes!("../testdata/pc.bin");

/// The DSDT record of a capture.
fn dsdt(capture: &'static [u8]) -> Sdt<'static> {
    let mut at = 0;
    while at + 12 <= capture.len() {
        let address = u64::from_le_bytes(capture[at..at + 8].try_into().unwrap());
        let len = u32::from_le_bytes(capture[at + 8..at + 12].try_into().unwrap()) as usize;
        let bytes = &capture[at + 12..at + 12 + len];
        if bytes.starts_with(b"DSDT") {
            return Sdt::from_bytes(address, bytes).unwrap();
        }
        at += 12 + len;
    }
    panic!("no DSDT in the capture");
}

/// Configuration space and ports as a map, with every access recorded. What was never
/// written reads as zero.
#[derive(Default)]
struct Machine {
    values: HashMap<(Space, u64), u64>,
    reads: Vec<(Space, u64, u8)>,
    writes: Vec<(Space, u64, u8, u64)>,
}

impl Host for Machine {
    fn read(&mut self, space: Space, address: u64, bits: u8) -> Option<u64> {
        self.reads.push((space, address, bits));
        Some(self.values.get(&(space, address)).copied().unwrap_or(0))
    }

    fn write(&mut self, space: Space, address: u64, bits: u8, value: u64) -> Option<()> {
        self.writes.push((space, address, bits, value));
        self.values.insert((space, address), value);
        Some(())
    }
}

struct Owned {
    nodes: Vec<Node>,
    cells: Vec<Object>,
    bytes: Vec<u8>,
}

impl Owned {
    fn new() -> Owned {
        Owned {
            nodes: vec![Node::EMPTY; 1024],
            cells: vec![Object::Uninitialized; 2048],
            bytes: vec![0; 8192],
        }
    }

    fn interpreter(&mut self, machine: Machine) -> Interpreter<'static, '_, Machine> {
        let storage = Storage {
            nodes: &mut self.nodes,
            cells: &mut self.cells,
            bytes: &mut self.bytes,
        };
        Interpreter::new(storage, machine).unwrap()
    }
}

fn pci(bus: u8, device: u8, function: u8) -> Space {
    Space::PciConfig {
        bus,
        device,
        function,
    }
}

/// An SSDT of `revision` holding `body`, with its checksum.
fn table(revision: u8, body: &[u8]) -> Sdt<'static> {
    let mut t = vec![0u8; 36];
    t[..4].copy_from_slice(b"SSDT");
    t.extend_from_slice(body);
    let len = t.len() as u32;
    t[4..8].copy_from_slice(&len.to_le_bytes());
    t[8] = revision;
    let sum = t.iter().fold(0u8, |a, &b| a.wrapping_add(b));
    t[9] = sum.wrapping_neg();
    Sdt::from_bytes(0, Box::leak(t.into_boxed_slice())).unwrap()
}

/// `op`, a PkgLength covering `contents`, and `contents`.
fn with_length(op: &[u8], contents: &[u8]) -> Vec<u8> {
    let mut out = op.to_vec();
    let total = contents.len() + 1;
    if total < 0x40 {
        out.push(total as u8);
    } else {
        let total = contents.len() + 2;
        assert!(total < 0x1000);
        out.push(0x40 | (total & 0x0f) as u8);
        out.push((total >> 4) as u8);
    }
    out.extend_from_slice(contents);
    out
}

fn method(name: &[u8; 4], args: u8, body: &[u8]) -> Vec<u8> {
    let mut contents = name.to_vec();
    contents.push(args);
    contents.extend_from_slice(body);
    with_length(&[0x14], &contents)
}

fn run(revision: u8, body: &[u8], name: &str) -> Result<Object, Error> {
    let mut owned = Owned::new();
    let mut aml = owned.interpreter(Machine::default());
    aml.load(table(revision, body))?;
    let node = aml.find(name).ok_or(Error::NotFound)?;
    aml.evaluate(node, &[])
}

#[test]
fn both_dsdts_load_into_a_namespace_with_a_routing_table() {
    for (capture, what) in [(Q35, "q35"), (PC, "pc")] {
        let mut owned = Owned::new();
        let mut aml = owned.interpreter(Machine::default());
        aml.load(dsdt(capture))
            .unwrap_or_else(|e| panic!("{what}: {e:?}"));
        assert!(aml.find("\\_SB.PCI0._PRT").is_some(), "{what}");
        assert!(aml.node_count() > 100, "{what}: {} nodes", aml.node_count());
    }
}

#[test]
fn q35_routes_every_slot_through_its_gsi_link_in_apic_mode() {
    let mut owned = Owned::new();
    let mut aml = owned.interpreter(Machine::default());
    aml.load(dsdt(Q35)).unwrap();
    assert_eq!(aml.select_apic_mode(), Ok(true));
    let bridge = aml.find("\\_SB.PCI0").unwrap();
    for slot in 1..0x18u8 {
        for pin in 1..=4u8 {
            let route = aml.route_pin(0, &[(slot, 0)], pin).unwrap();
            // QEMU's table: slot s, pin p goes to GSIE + (s + p) % 4, and GSIE is GSI 20.
            let index = (slot + pin - 1) % 4;
            assert_eq!(route.gsi, 0x14 + u32::from(index), "slot {slot} pin {pin}");
            assert!(route.level && !route.active_low, "slot {slot} pin {pin}");
            assert_eq!(route.bridge, bridge);
            let link = route.link.expect("a GSI link device");
            assert_eq!(aml.name(link), [b'G', b'S', b'I', b'E' + index]);
        }
    }
    // The disk the x86_64 presets attach lands at 00:03.0: INTA# is GSI 23.
    assert_eq!(aml.route_pin(0, &[(3, 0)], 1).unwrap().gsi, 23);
    // Nothing had to be read from the machine to get there.
    assert!(aml.host().reads.is_empty());
}

#[test]
fn q35_before_pic_mode_routes_through_a_pirq_register_instead() {
    let mut owned = Owned::new();
    let mut machine = Machine::default();
    for offset in 0x60..0x70 {
        machine.values.insert((pci(0, 0x1f, 0), offset), 0x0b);
    }
    let mut aml = owned.interpreter(machine);
    aml.load(dsdt(Q35)).unwrap();
    let route = aml.route_pin(0, &[(3, 0)], 1).unwrap();
    assert_eq!(route.gsi, 11);
    assert_eq!(aml.name(route.link.unwrap()), *b"LNKH");
    let reads = &aml.host().reads;
    assert!(!reads.is_empty());
    assert!(
        reads
            .iter()
            .all(|&(space, offset, bits)| space == pci(0, 0x1f, 0)
                && (0x60..0x70).contains(&offset)
                && bits == 8),
        "{reads:x?}"
    );
}

#[test]
fn pc_routes_through_the_piix_link_register() {
    let mut owned = Owned::new();
    let mut machine = Machine::default();
    // PIRQC#, which LNKC reads through PRQ2.
    machine.values.insert((pci(0, 1, 0), 0x62), 11);
    let mut aml = owned.interpreter(machine);
    aml.load(dsdt(PC)).unwrap();
    // No `_PIC` on pc: its table is the same either way.
    assert_eq!(aml.select_apic_mode(), Ok(false));
    let route = aml.route_pin(0, &[(3, 0)], 1).unwrap();
    assert_eq!(route.gsi, 11);
    assert!(route.level && !route.active_low);
    assert_eq!(aml.name(route.link.unwrap()), *b"LNKC");
    assert!(aml.host().reads.contains(&(pci(0, 1, 0), 0x62, 8)));
    assert!(aml.host().writes.is_empty());
}

#[test]
fn a_link_with_no_interrupt_is_given_its_first_possible_one() {
    let mut owned = Owned::new();
    let mut machine = Machine::default();
    // Bit 7: routing disabled, as a PIIX PIRQ register resets.
    machine.values.insert((pci(0, 1, 0), 0x62), 0x80);
    let mut aml = owned.interpreter(machine);
    aml.load(dsdt(PC)).unwrap();
    let route = aml.route_pin(0, &[(3, 0)], 1).unwrap();
    // LNKC's `_PRS` lists 5, 10 and 11.
    assert_eq!(route.gsi, 5);
    assert_eq!(aml.host().writes, [(pci(0, 1, 0), 0x62, 8, 5)]);
}

#[test]
fn a_function_behind_a_bridge_with_no_prt_is_swizzled_onto_the_bridge() {
    let mut owned = Owned::new();
    let mut aml = owned.interpreter(Machine::default());
    aml.load(dsdt(PC)).unwrap();
    for device in 0..8u8 {
        for pin in 1..=4u8 {
            let behind = aml.route_pin(0, &[(4, 0), (device, 0)], pin).unwrap();
            let bridge_pin = (pin - 1 + device) % 4 + 1;
            let direct = aml.route_pin(0, &[(4, 0)], bridge_pin).unwrap();
            assert_eq!(behind, direct, "device {device} pin {pin}");
        }
    }
}

#[test]
fn a_pin_that_does_not_exist_has_no_route() {
    let mut owned = Owned::new();
    let mut aml = owned.interpreter(Machine::default());
    aml.load(dsdt(Q35)).unwrap();
    assert_eq!(aml.route_pin(0, &[(3, 0)], 0), Err(Error::NoRoute));
    assert_eq!(aml.route_pin(0, &[(3, 0)], 5), Err(Error::NoRoute));
    assert_eq!(aml.route_pin(0, &[], 1), Err(Error::NoRoute));
    assert_eq!(aml.route_pin(0, &[(0x20, 0)], 1), Err(Error::NoRoute));
    assert_eq!(aml.route_pin(7, &[(3, 0)], 1), Err(Error::NoRoute));
}

#[test]
fn an_unknown_opcode_is_an_error_naming_it() {
    let body = method(b"TEST", 0, &[0xa4, 0xfe]);
    let got = run(2, &body, "\\TEST");
    assert!(matches!(got, Err(Error::UnknownOpcode { opcode: 0xfe, .. })), "{got:?}");
}

#[test]
fn a_loop_that_never_ends_runs_out_of_budget() {
    // While (One) {}
    let body = method(b"LOOP", 0, &[0xa2, 0x02, 0x01]);
    assert_eq!(run(2, &body, "\\LOOP"), Err(Error::Budget));
}

#[test]
fn unbounded_recursion_is_too_deep() {
    let body = method(b"RECU", 0, b"\xa4RECU");
    assert_eq!(run(2, &body, "\\RECU"), Err(Error::TooDeep));
}

#[test]
fn integers_are_32_bits_in_a_revision_1_table() {
    let body = method(b"ONES", 0, &[0xa4, 0xff]);
    assert_eq!(run(1, &body, "\\ONES"), Ok(Object::Integer(0xffff_ffff)));
    assert_eq!(run(2, &body, "\\ONES"), Ok(Object::Integer(u64::MAX)));
    // Add (Ones, One): wraps at the table's width.
    let body = method(b"WRAP", 0, &[0xa4, 0x72, 0xff, 0x01, 0x00]);
    assert_eq!(run(1, &body, "\\WRAP"), Ok(Object::Integer(0)));
}

#[test]
fn storing_into_a_package_literal_copies_it_first() {
    // Name (PKG, Package (2) {1, 2})
    let mut body = vec![0x08];
    body.extend_from_slice(b"PKG_");
    body.extend(with_length(&[0x12], &[0x02, 0x01, 0x0a, 0x02]));
    // Method (SETP) { Store (7, Index (PKG, 1)); Return (DerefOf (Index (PKG, 1))) }
    let mut m = vec![0x70, 0x0a, 0x07, 0x88];
    m.extend_from_slice(b"PKG_");
    m.extend_from_slice(&[0x01, 0x00, 0xa4, 0x83, 0x88]);
    m.extend_from_slice(b"PKG_");
    m.extend_from_slice(&[0x01, 0x00]);
    body.extend(method(b"SETP", 0, &m));
    let mut owned = Owned::new();
    let mut aml = owned.interpreter(Machine::default());
    aml.load(table(2, &body)).unwrap();
    let setp = aml.find("\\SETP").unwrap();
    assert_eq!(aml.evaluate(setp, &[]), Ok(Object::Integer(7)));
    let pkg = aml.find("\\PKG").unwrap();
    let pkg = aml.evaluate(pkg, &[]).unwrap();
    assert_eq!(aml.element(pkg, 0), Ok(Object::Integer(1)));
    assert_eq!(aml.element(pkg, 1), Ok(Object::Integer(7)));
}

#[test]
fn a_table_that_fails_to_load_adds_nothing() {
    let mut body = vec![0x08];
    body.extend_from_slice(b"GOOD\x01");
    body.push(0xfe);
    let mut owned = Owned::new();
    let mut aml = owned.interpreter(Machine::default());
    let before = aml.node_count();
    assert!(matches!(aml.load(table(2, &body)), Err(Error::UnknownOpcode { .. })));
    assert_eq!(aml.node_count(), before);
    assert!(aml.find("\\GOOD").is_none());
}

#[test]
fn running_out_of_nodes_is_an_error() {
    let mut nodes = vec![Node::EMPTY; 32];
    let mut cells = vec![Object::Uninitialized; 16];
    let mut bytes = vec![0; 16];
    let storage = Storage {
        nodes: &mut nodes,
        cells: &mut cells,
        bytes: &mut bytes,
    };
    let mut aml = Interpreter::new(storage, Machine::default()).unwrap();
    assert_eq!(aml.load(dsdt(Q35)), Err(Error::NoNodes));
}

#[test]
fn every_method_of_both_dsdts_runs_to_a_result_or_an_error() {
    for capture in [Q35, PC] {
        let mut owned = Owned::new();
        let mut aml = owned.interpreter(Machine::default());
        aml.load(dsdt(capture)).unwrap();
        let methods: Vec<_> = aml
            .all_nodes()
            .filter_map(|n| aml.method_args(n).map(|a| (n, a)))
            .collect();
        let mut ok = 0;
        for (node, args) in &methods {
            let args = vec![Object::Integer(1); *args];
            if aml.evaluate(*node, &args).is_ok() {
                ok += 1;
            }
        }
        assert!(ok * 2 > methods.len(), "{ok} of {} methods ran", methods.len());
    }
}

#[test]
fn mutated_dsdts_never_panic() {
    for capture in [Q35, PC] {
        let original = dsdt(capture).bytes();
        for at in (36..original.len()).step_by(7) {
            for value in [0x00, 0xff, original[at] ^ 0x5a, 0x14, 0x5b] {
                let mut t = original.to_vec();
                t[at] = value;
                t[9] = 0;
                let sum = t.iter().fold(0u8, |a, &b| a.wrapping_add(b));
                t[9] = sum.wrapping_neg();
                let sdt = Sdt::from_bytes(0, Box::leak(t.into_boxed_slice())).unwrap();
                let mut owned = Owned::new();
                let mut aml = owned.interpreter(Machine::default());
                if aml.load(sdt).is_ok() {
                    let _ = aml.select_apic_mode();
                    let _ = aml.route_pin(0, &[(3, 0)], 1);
                }
            }
        }
    }
}

#[test]
fn small_and_extended_interrupt_descriptors_decode() {
    // IRQ (Level, ActiveLow, Shared) {5, 9}, then an extended descriptor {0x10, 0x11}.
    let template = [
        0x23, 0x20, 0x02, 0x18, 0x89, 0x0a, 0x00, 0x0d, 0x02, 0x10, 0, 0, 0, 0x11, 0, 0, 0, 0x79,
        0x00,
    ];
    let irq = |n, level, low, shared| Interrupt {
        number: n,
        level,
        active_low: low,
        shared,
    };
    assert_eq!(nth_interrupt(&template, 0), Ok(Some(irq(5, true, true, true))));
    assert_eq!(nth_interrupt(&template, 1), Ok(Some(irq(9, true, true, true))));
    assert_eq!(nth_interrupt(&template, 2), Ok(Some(irq(0x10, true, true, true))));
    assert_eq!(nth_interrupt(&template, 3), Ok(Some(irq(0x11, true, true, true))));
    assert_eq!(nth_interrupt(&template, 4), Ok(None));
    // A two-byte IRQ descriptor is edge-triggered and active high.
    assert_eq!(
        nth_interrupt(&[0x22, 0x10, 0x00, 0x79, 0x00], 0),
        Ok(Some(irq(4, false, false, false)))
    );
    // Truncated, or with no end tag.
    // Interrupt 0 is found before the cut; interrupt 2 is past it.
    assert_eq!(nth_interrupt(&template[..6], 0), Ok(Some(irq(5, true, true, true))));
    assert_eq!(nth_interrupt(&template[..6], 2), Err(Error::BadResource));
    assert_eq!(nth_interrupt(&[0x22, 0x10, 0x00], 1), Err(Error::BadResource));
    let chosen = irq(23, true, false, true);
    assert_eq!(nth_interrupt(&interrupt_template(chosen), 0), Ok(Some(chosen)));
}

#[test]
fn eisa_ids_encode_as_asl_does() {
    // QEMU's q35 host bridge: `Name (_HID, EisaId ("PNP0A08"))` is DWordConst 0x080AD041.
    assert_eq!(eisa_id(b"PNP0A08"), 0x080a_d041);
    assert_eq!(eisa_id(b"PNP0A03"), 0x030a_d041);
}

//! Host tests for PCI enumeration and for nodes that do not come from a device tree.
//!
//! The bus is a model: configuration space as an array per function, with BARs that
//! behave like hardware. Only the address bits a BAR implements take a write, and the
//! type bits never do. The model also records what enumeration must not do: size a BAR
//! while the device decodes, touch a host bridge's decoding, or write status bits.

use std::cell::RefCell;

use super::driver::{self, best_match};
use super::pci::{self, Address, Bar, BusRange, ConfigSpace, Disturbed, Function};
use super::table::{Described, Kind};
use super::tree::{Builder, Error, Origin};
use super::*;

/// One BAR as the model builds it.
#[derive(Clone, Copy)]
enum Spec {
    Mem32 {
        base: u32,
        size: u32,
        prefetch: bool,
    },
    Mem64 {
        base: u64,
        size: u64,
        prefetch: bool,
    },
    /// A 16-bit I/O decoder.
    Io { base: u16, size: u16 },
}

struct Fake {
    at: Address,
    config: [u32; 64],
    /// Which bits of each BAR register take a write.
    writable: [u32; 6],
    /// A BAR was written with all ones while memory or I/O decoding was on.
    sized_while_decoding: bool,
    command_writes: usize,
}

#[derive(Default)]
struct Model {
    functions: RefCell<Vec<Fake>>,
}

const HOST: [u8; 3] = [0x06, 0x00, 0x00];
const ETHERNET: [u8; 3] = [0x02, 0x00, 0x00];
const BRIDGE: [u8; 3] = [0x06, 0x04, 0x00];

impl Model {
    fn add(&self, at: Address, id: (u16, u16), class: [u8; 3], header_type: u8, bars: &[Spec]) {
        let mut f = Fake {
            at,
            config: [0; 64],
            writable: [0; 6],
            sized_while_decoding: false,
            command_writes: 0,
        };
        f.config[0] = u32::from(id.0) | (u32::from(id.1) << 16);
        // Memory and I/O decoding on, as firmware leaves an assigned device, and a status
        // bit set so that a write carrying status would show.
        f.config[1] = 0x0010_0003;
        f.config[2] = (u32::from(class[0]) << 24)
            | (u32::from(class[1]) << 16)
            | (u32::from(class[2]) << 8)
            | 0x01;
        f.config[3] = u32::from(header_type) << 16;
        f.config[11] = 0x1100_1af4;
        f.config[15] = 0x0000_010b;
        let mut i = 0;
        for spec in bars {
            match *spec {
                Spec::Mem32 {
                    base,
                    size,
                    prefetch,
                } => {
                    f.config[4 + i] = base | if prefetch { 0x8 } else { 0 };
                    f.writable[i] = !(size - 1) & !0xf;
                    i += 1;
                }
                Spec::Mem64 {
                    base,
                    size,
                    prefetch,
                } => {
                    let mask = !(size - 1);
                    f.config[4 + i] = base as u32 | 0x4 | if prefetch { 0x8 } else { 0 };
                    f.config[5 + i] = (base >> 32) as u32;
                    f.writable[i] = mask as u32 & !0xf;
                    f.writable[i + 1] = (mask >> 32) as u32;
                    i += 2;
                }
                Spec::Io { base, size } => {
                    f.config[4 + i] = u32::from(base) | 0x1;
                    f.writable[i] = u32::from(!(size - 1)) & !0x3;
                    i += 1;
                }
            }
        }
        self.functions.borrow_mut().push(f);
    }

    fn endpoint(&self, at: Address, id: (u16, u16), class: [u8; 3], bars: &[Spec]) {
        self.add(at, id, class, 0, bars);
    }

    fn bridge(&self, at: Address, secondary: u8, subordinate: u8) {
        self.add(at, (0x1b36, 0x000c), BRIDGE, 1, &[]);
        let mut fns = self.functions.borrow_mut();
        let f = fns.last_mut().unwrap();
        f.config[6] =
            u32::from(at.bus) | (u32::from(secondary) << 8) | (u32::from(subordinate) << 16);
    }

    /// Give the last-added function a capability list: `(id, offset, payload)` each, chained
    /// in the order given. The status bit that says a list exists is set with it.
    fn capabilities(&self, caps: &[(u8, u16, u32)]) {
        let mut fns = self.functions.borrow_mut();
        let f = fns.last_mut().unwrap();
        f.config[1] |= 0x0010_0000;
        f.config[0x34 / 4] = u32::from(caps.first().map_or(0, |c| c.1));
        for (i, &(id, offset, payload)) in caps.iter().enumerate() {
            let next = caps.get(i + 1).map_or(0, |c| c.1);
            f.config[usize::from(offset) / 4] =
                u32::from(id) | (u32::from(next) << 8) | (payload << 16);
        }
    }

    /// Give the last-added function capabilities with whole structures behind them:
    /// `(id, offset, words)`, chained in order. `words[0]`'s low half is overwritten with
    /// the id and the next pointer, which is the layout the hardware has.
    fn capability_words(&self, caps: &[(u8, u16, [u32; 6])]) {
        let mut fns = self.functions.borrow_mut();
        let f = fns.last_mut().unwrap();
        f.config[1] |= 0x0010_0000;
        f.config[0x34 / 4] = u32::from(caps.first().map_or(0, |c| c.1));
        for (i, &(id, offset, words)) in caps.iter().enumerate() {
            let next = caps.get(i + 1).map_or(0, |c| c.1);
            let base = usize::from(offset) / 4;
            for (w, value) in words.iter().enumerate() {
                if base + w < f.config.len() {
                    f.config[base + w] = *value;
                }
            }
            f.config[base] =
                (f.config[base] & 0xffff_0000) | u32::from(id) | (u32::from(next) << 8);
        }
    }

    /// Write a capability pointer and clear the status bit that says the list exists, which
    /// `add` sets as firmware leaves a real function.
    fn raw_capability_pointer(&self, offset: u16) {
        let mut fns = self.functions.borrow_mut();
        let f = fns.last_mut().unwrap();
        f.config[1] &= !0x0010_0000;
        f.config[0x34 / 4] = u32::from(offset);
        f.config[usize::from(offset) / 4] = 0x09;
    }

    /// Point the last-added function's capability list at itself, which a broken device does.
    fn looping_capability(&self, offset: u16) {
        let mut fns = self.functions.borrow_mut();
        let f = fns.last_mut().unwrap();
        f.config[1] |= 0x0010_0000;
        f.config[0x34 / 4] = u32::from(offset);
        f.config[usize::from(offset) / 4] = 0x09 | (u32::from(offset) << 8);
    }

    /// Mark function 0 of `bus:device` as multi-function.
    fn multifunction(&self, bus: u8, device: u8) {
        let mut fns = self.functions.borrow_mut();
        let f = fns
            .iter_mut()
            .find(|f| f.at == Address::new(bus, device, 0))
            .unwrap();
        f.config[3] |= 0x80 << 16;
    }

    fn with<R>(&self, at: Address, f: impl FnOnce(&Fake) -> R) -> R {
        f(self.functions.borrow().iter().find(|x| x.at == at).unwrap())
    }
}

impl ConfigSpace for Model {
    fn read(&self, at: Address, offset: u16) -> u32 {
        assert_eq!(offset % 4, 0, "reads are 32 bits at aligned offsets");
        self.functions
            .borrow()
            .iter()
            .find(|f| f.at == at)
            .map_or(0xffff_ffff, |f| f.config[usize::from(offset / 4)])
    }

    fn write(&self, at: Address, offset: u16, value: u32) {
        let mut fns = self.functions.borrow_mut();
        let Some(f) = fns.iter_mut().find(|f| f.at == at) else {
            return;
        };
        let index = usize::from(offset / 4);
        match offset {
            0x04 => {
                f.command_writes += 1;
                assert_eq!(value >> 16, 0, "a write to COMMAND carried STATUS bits");
                f.config[1] = (f.config[1] & 0xffff_0000) | value;
            }
            0x10..=0x24 => {
                let bar = index - 4;
                let header_bars = if (f.config[3] >> 16) & 0x7f == 1 {
                    2
                } else {
                    6
                };
                if bar >= header_bars {
                    return;
                }
                if value == 0xffff_ffff && f.config[1] & 0x3 != 0 {
                    f.sized_while_decoding = true;
                }
                let writable = f.writable[bar];
                f.config[index] = (f.config[index] & !writable) | (value & writable);
            }
            _ => f.config[index] = value,
        }
    }
}

fn enumerate(m: &Model) -> Vec<Function> {
    let mut out = vec![Function::EMPTY; 64];
    let n = pci::enumerate(m, 0, 255, &mut out).unwrap();
    out.truncate(n);
    out
}

fn find(fns: &[Function], at: Address) -> &Function {
    fns.iter()
        .find(|f| f.address == at)
        .unwrap_or_else(|| panic!("{at:?} not enumerated"))
}

/// A small machine: a host bridge, a NIC with three kinds of BAR, a multi-function device
/// with a hole at function 1, and a bridge with a device behind it.
fn machine() -> Model {
    let m = Model::default();
    m.endpoint(Address::new(0, 0, 0), (0x8086, 0x29c0), HOST, &[]);
    m.endpoint(
        Address::new(0, 2, 0),
        (0x8086, 0x100e),
        ETHERNET,
        &[
            Spec::Mem32 {
                base: 0xfebc_0000,
                size: 0x2_0000,
                prefetch: false,
            },
            Spec::Io {
                base: 0xc000,
                size: 0x40,
            },
            Spec::Mem64 {
                base: 0x8_0000_0000,
                size: 0x2_0000_0000,
                prefetch: true,
            },
        ],
    );
    m.endpoint(Address::new(0, 3, 0), (0x1af4, 0x1000), ETHERNET, &[]);
    m.endpoint(Address::new(0, 3, 2), (0x1af4, 0x1001), ETHERNET, &[]);
    m.multifunction(0, 3);
    m.bridge(Address::new(0, 4, 0), 1, 1);
    m.endpoint(
        Address::new(1, 0, 0),
        (0x1b36, 0x0005),
        [0x00, 0xff, 0x00],
        &[
            Spec::Io {
                base: 0xd000,
                size: 0x100,
            },
            Spec::Mem32 {
                base: 0xfea0_0000,
                size: 0x1000,
                prefetch: false,
            },
        ],
    );
    m
}

#[test]
fn every_function_is_found_including_behind_the_bridge() {
    let m = machine();
    let fns = enumerate(&m);
    let addresses: Vec<Address> = fns.iter().map(|f| f.address).collect();
    assert_eq!(
        addresses,
        [
            Address::new(0, 0, 0),
            Address::new(0, 2, 0),
            Address::new(0, 3, 0),
            Address::new(0, 3, 2),
            Address::new(0, 4, 0),
            Address::new(1, 0, 0),
        ]
    );
    let bridge = fns.iter().position(|f| f.address == Address::new(0, 4, 0));
    assert_eq!(
        find(&fns, Address::new(0, 4, 0)).bridge,
        Some(BusRange {
            secondary: 1,
            subordinate: 1
        })
    );
    let behind = find(&fns, Address::new(1, 0, 0));
    assert_eq!(behind.parent.map(usize::from), bridge, "its parent is the bridge");
    assert_eq!(find(&fns, Address::new(0, 2, 0)).parent, None);
}

#[test]
fn a_single_function_device_is_not_probed_past_function_0() {
    let m = machine();
    // Present in configuration space, but function 0 does not say multi-function, so
    // hardware that aliases function 0 onto every function number is not listed eight
    // times.
    m.endpoint(Address::new(0, 2, 1), (0x8086, 0xdead), ETHERNET, &[]);
    let fns = enumerate(&m);
    assert!(!fns.iter().any(|f| f.address == Address::new(0, 2, 1)));
}

#[test]
fn identity_and_compatible_strings() {
    let fns = enumerate(&machine());
    let nic = find(&fns, Address::new(0, 2, 0));
    assert_eq!((nic.vendor, nic.device), (0x8086, 0x100e));
    assert_eq!((nic.class, nic.subclass, nic.prog_if, nic.revision), (2, 0, 0, 1));
    assert_eq!((nic.subsystem_vendor, nic.subsystem), (0x1af4, 0x1100));
    assert_eq!((nic.interrupt_pin, nic.interrupt_line), (1, 11));
    assert_eq!(nic.name(), b"00:02.0");
    assert_eq!(nic.compatible(), b"pci8086,100e\0pciclass,020000\0pciclass,0200\0");
    assert!(find(&fns, Address::new(0, 0, 0)).is_host_bridge());
    assert_eq!(find(&fns, Address::new(0, 4, 0)).subsystem_vendor, 0, "bridges have none");
}

#[test]
fn bars_are_sized_exactly() {
    let fns = enumerate(&machine());
    let nic = find(&fns, Address::new(0, 2, 0));
    assert_eq!(
        nic.bars,
        [
            Bar::Memory {
                base: 0xfebc_0000,
                size: 0x2_0000,
                prefetchable: false,
                wide: false
            },
            Bar::Io {
                base: 0xc000,
                size: 0x40
            },
            Bar::Memory {
                base: 0x8_0000_0000,
                size: 0x2_0000_0000,
                prefetchable: true,
                wide: true
            },
            Bar::None,
            Bar::None,
            Bar::None,
        ]
    );
    let testdev = find(&fns, Address::new(1, 0, 0));
    assert_eq!(
        testdev.bars[..2],
        [
            Bar::Io {
                base: 0xd000,
                size: 0x100
            },
            Bar::Memory {
                base: 0xfea0_0000,
                size: 0x1000,
                prefetchable: false,
                wide: false
            }
        ]
    );
    assert_eq!(nic.memory_bar(0), Some((0xfebc_0000, 0x2_0000)));
    assert_eq!(nic.memory_bar(1), Some((0x8_0000_0000, 0x2_0000_0000)));
    assert_eq!(nic.memory_bar(2), None);
}

#[test]
fn sizing_restores_every_bar_and_the_decode_bits() {
    let m = machine();
    let fns = enumerate(&m);
    assert_eq!(pci::verify_restored(&m, &fns), Ok(()));
    for f in &fns {
        m.with(f.address, |fake| {
            // Deliberately so for a host bridge; see below.
            if !f.is_host_bridge() {
                assert!(!fake.sized_while_decoding, "{:?} sized while decoding", f.address);
            }
            assert_eq!(fake.config[1] & 0x3, 0x3, "{:?} decoding left off", f.address);
        });
    }
    // A host bridge's decoding is never switched off.
    m.with(Address::new(0, 0, 0), |host| assert_eq!(host.command_writes, 0));
    m.with(Address::new(0, 2, 0), |nic| assert_eq!(nic.command_writes, 2));
}

#[test]
fn a_bar_left_disturbed_is_caught() {
    let m = machine();
    let fns = enumerate(&m);
    m.write(Address::new(1, 0, 0), 0x14, 0xffff_ffff);
    assert_eq!(
        pci::verify_restored(&m, &fns),
        Err(Disturbed::Bar {
            at: Address::new(1, 0, 0),
            index: 1,
            was: 0xfea0_0000,
            now: 0xffff_f000
        })
    );
    m.write(Address::new(1, 0, 0), 0x14, 0xfea0_0000);
    m.write(Address::new(0, 3, 2), 0x04, 0);
    assert!(matches!(pci::verify_restored(&m, &fns), Err(Disturbed::Command { .. })));
}

#[test]
fn a_bridge_outside_the_segment_is_not_followed() {
    let m = machine();
    let mut out = vec![Function::EMPTY; 64];
    // Buses 0 to 0 only: the bridge to bus 1 is listed, what is behind it is not.
    let n = pci::enumerate(&m, 0, 0, &mut out).unwrap();
    assert_eq!(n, 5);
    assert!(out[..n].iter().all(|f| f.address.bus == 0));
}

#[test]
fn misprogrammed_bridges_cannot_loop_the_walk() {
    let m = machine();
    // A second bridge to bus 1, and one on bus 1 pointing back at bus 0.
    m.bridge(Address::new(0, 5, 0), 1, 1);
    m.bridge(Address::new(1, 1, 0), 0, 0);
    let fns = enumerate(&m);
    let on_bus_1 = fns.iter().filter(|f| f.address.bus == 1).count();
    assert_eq!(on_bus_1, 2, "bus 1 walked once");
    let on_bus_0 = fns.iter().filter(|f| f.address.bus == 0).count();
    assert_eq!(on_bus_0, 6, "bus 0 walked once");
}

#[test]
fn running_out_of_storage_is_an_error_not_a_partial_bus() {
    let m = machine();
    let mut out = vec![Function::EMPTY; 3];
    assert_eq!(
        pci::enumerate(&m, 0, 255, &mut out),
        Err(pci::Error::TooManyFunctions { capacity: 3 })
    );
}

#[test]
fn an_empty_bus_has_no_functions() {
    let m = Model::default();
    let mut out = vec![Function::EMPTY; 4];
    assert_eq!(pci::enumerate(&m, 0, 255, &mut out), Ok(0));
}

// --- nodes from enumeration --------------------------------------------------------

struct Nic;

impl Driver for Nic {
    fn name(&self) -> &'static str {
        "nic"
    }
    fn compatible(&self) -> &'static [&'static str] {
        &["pciclass,0200"]
    }
    fn probe(&self, p: &mut Probe<'_, '_, '_, '_>) -> Result<(), ProbeError> {
        p.claim_mmio(0, "nic registers")?;
        Ok(())
    }
    fn start(&self, _: &Bound) -> Result<(), &'static str> {
        Ok(())
    }
}

struct E1000;

impl Driver for E1000 {
    fn name(&self) -> &'static str {
        "e1000"
    }
    fn compatible(&self) -> &'static [&'static str] {
        &["pci8086,100e"]
    }
    fn probe(&self, p: &mut Probe<'_, '_, '_, '_>) -> Result<(), ProbeError> {
        p.claim_mmio(0, "e1000 registers")?;
        Ok(())
    }
    fn start(&self, _: &Bound) -> Result<(), &'static str> {
        Ok(())
    }
}

struct Ecam;

impl Driver for Ecam {
    fn name(&self) -> &'static str {
        "ecam"
    }
    fn compatible(&self) -> &'static [&'static str] {
        &["pci-host-ecam-generic"]
    }
    fn probe(&self, p: &mut Probe<'_, '_, '_, '_>) -> Result<(), ProbeError> {
        p.claim_mmio(0, "configuration space")?;
        Ok(())
    }
    fn start(&self, _: &Bound) -> Result<(), &'static str> {
        Ok(())
    }
}

#[test]
fn functions_become_nodes_under_their_bridges_and_bind_by_compatible() {
    let m = machine();
    let fns = enumerate(&m);
    let host = Described::new(
        Kind::EcamConfigSpace {
            segment: 0,
            start_bus: 0,
            end_bus: 255,
        },
        format_args!("pci@{:x}", 0xb000_0000u64),
        &[(0xb000_0000, 0x1000_0000)],
    )
    .unwrap();

    let mut storage = vec![Node::EMPTY; 16];
    let mut b = Builder::new(&mut storage).unwrap();
    let host_id = b
        .add(NodeId::ROOT, host.name(), host.compatible(), Origin::Table(&host))
        .unwrap();
    let mut ids = Vec::new();
    for f in &fns {
        let parent = f.parent.map_or(host_id, |p| ids[usize::from(p)]);
        ids.push(
            b.add(parent, f.name(), f.compatible(), Origin::Pci(f))
                .unwrap(),
        );
    }
    let tree = b.finish();
    assert_eq!(tree.len(), 1 + 1 + fns.len());

    // The device behind the bridge is the bridge node's child, found by path.
    let behind = tree.find(b"/pci@b0000000/00:04.0/01:00.0").unwrap();
    assert!(matches!(tree.node(behind).origin(), Origin::Pci(f) if f.device == 0x0005));
    assert_eq!(tree.mmio_count(behind), 1, "the I/O BAR is not a window");
    assert_eq!(tree.mmio(behind, 0), Ok((0xfea0_0000, 0x1000)));
    // Its interrupt is the line firmware programmed: pin INTA#, routed to 11. Whether that
    // line means anything is the platform's decision, not the model's.
    let spec = tree.interrupt(behind, 0).unwrap();
    assert_eq!(spec.cells(), &[11]);
    assert_eq!(
        tree.interrupt(behind, 1),
        Err(Error::NoSuchEntry {
            node: behind,
            index: 1
        }),
        "a function has one interrupt pin"
    );
    assert_eq!(tree.stdout(), None, "no device tree, no chosen console");

    // The most specific string wins: the e1000 driver takes the e1000, the class driver the
    // other two NICs.
    let drivers: [&dyn Driver; 3] = [&Nic, &E1000, &Ecam];
    let nic = tree.find(b"/pci@b0000000/00:02.0").unwrap();
    assert_eq!(best_match(&tree, nic, &drivers), Some((1, 0)));
    let virtio = tree.find(b"/pci@b0000000/00:03.2").unwrap();
    assert_eq!(best_match(&tree, virtio, &drivers), Some((0, 2)));
    assert_eq!(best_match(&tree, behind, &drivers), None);

    // Claims go through the same ledger, and the ECAM window cannot be claimed twice.
    let (mut mmio, mut irqs) = (vec![None; 8], vec![None; 4]);
    let mut res = Resources::new(&mut mmio, &mut irqs);
    let host_node = tree.find(b"/pci@b0000000").unwrap();
    let bound = driver::probe(&Ecam, &tree, host_node, &mut res).unwrap();
    assert!(matches!(
        driver::probe(&Ecam, &tree, host_node, &mut res),
        Err(ProbeError::Claim(ClaimError::Overlaps { .. }))
    ));
    driver::probe(&E1000, &tree, nic, &mut res).unwrap();
    let claimed: Vec<(u64, u64)> = res.mmio_claims().map(|c| (c.phys, c.len)).collect();
    assert_eq!(claimed, [(0xb000_0000, 0x1000_0000), (0xfebc_0000, 0x2_0000)]);
    driver::remove(&Ecam, bound, &mut res);
    assert_eq!(res.mmio_claims().count(), 1);
}

#[test]
fn a_function_with_no_assigned_bar_has_no_window_to_claim() {
    let m = Model::default();
    m.endpoint(
        Address::new(0, 1, 0),
        (0x8086, 0x100e),
        ETHERNET,
        &[Spec::Mem32 {
            base: 0,
            size: 0x1000,
            prefetch: false,
        }],
    );
    let fns = enumerate(&m);
    let mut storage = vec![Node::EMPTY; 4];
    let mut b = Builder::new(&mut storage).unwrap();
    let id = b
        .add(NodeId::ROOT, fns[0].name(), fns[0].compatible(), Origin::Pci(&fns[0]))
        .unwrap();
    let tree = b.finish();
    assert_eq!(tree.mmio_count(id), 0);
    assert!(tree.mmio(id, 0).is_err());
    let (mut mmio, mut irqs) = (vec![None; 2], vec![None; 2]);
    let mut res = Resources::new(&mut mmio, &mut irqs);
    assert!(matches!(
        driver::probe(&E1000, &tree, id, &mut res),
        Err(ProbeError::Tree(Error::NoSuchEntry { .. }))
    ));
}

#[test]
fn the_builder_refuses_unknown_parents_and_full_storage() {
    let mut storage = vec![Node::EMPTY; 2];
    let mut b = Builder::new(&mut storage).unwrap();
    let group = Described::new(Kind::Group, format_args!("cpus"), &[]).unwrap();
    assert_eq!(
        b.add(NodeId::ROOT, b"x", b"", Origin::Table(&group))
            .map(|_| ()),
        Ok(())
    );
    assert!(matches!(
        b.add(NodeId::ROOT, b"y", b"", Origin::Table(&group)),
        Err(Error::TooManyNodes { capacity: 2 })
    ));
    let mut storage = vec![Node::EMPTY; 4];
    let mut b = Builder::new(&mut storage).unwrap();
    let unknown = b
        .add(NodeId::ROOT, b"a", b"", Origin::Table(&group))
        .unwrap();
    let mut other = vec![Node::EMPTY; 8];
    let mut far = Builder::new(&mut other).unwrap();
    for _ in 0..3 {
        far.add(NodeId::ROOT, b"z", b"", Origin::Table(&group))
            .unwrap();
    }
    let far_id = far
        .add(NodeId::ROOT, b"z", b"", Origin::Table(&group))
        .unwrap();
    assert!(far_id > unknown);
    assert_eq!(
        b.add(far_id, b"b", b"", Origin::Table(&group)),
        Err(Error::UnknownParent { parent: far_id })
    );
}

#[test]
fn a_pci_node_has_an_interrupt_only_when_firmware_routed_its_pin() {
    let m = Model::default();
    m.endpoint(Address::new(0, 0, 0), (0x8086, 0x29c0), HOST, &[]);
    // `add` gives every function pin INTA# routed to line 11. Three variations on it.
    m.endpoint(Address::new(0, 1, 0), (0x1af4, 0x1042), ETHERNET, &[]);
    m.endpoint(Address::new(0, 2, 0), (0x1af4, 0x1042), ETHERNET, &[]);
    m.endpoint(Address::new(0, 3, 0), (0x1af4, 0x1042), ETHERNET, &[]);
    {
        let mut fns = m.functions.borrow_mut();
        // No interrupt pin at all: the function raises nothing.
        fns[2].config[15] = 0x0000_000b;
        // A pin, but firmware left the line unassigned.
        fns[3].config[15] = 0x0000_01ff;
    }
    let fns = enumerate(&m);
    let mut storage = vec![Node::EMPTY; 16];
    let mut b = Builder::new(&mut storage).unwrap();
    let ids: Vec<NodeId> = fns
        .iter()
        .map(|f| {
            b.add(NodeId::ROOT, f.name(), f.compatible(), Origin::Pci(f))
                .unwrap()
        })
        .collect();
    let tree = b.finish();
    let routed = ids[1];
    assert_eq!(tree.interrupt(routed, 0).unwrap().cells(), &[11]);
    for &id in &ids[2..] {
        assert_eq!(
            tree.interrupt(id, 0),
            Err(Error::NoSuchEntry { node: id, index: 0 }),
            "no pin, or a line firmware did not assign, is no interrupt"
        );
    }
}

#[test]
fn a_capability_list_is_walked_in_order() {
    let m = Model::default();
    m.endpoint(Address::new(0, 5, 0), (0x1af4, 0x1042), ETHERNET, &[]);
    // A virtio device's vendor capabilities, with a PCI Express and an MSI-X capability
    // among them that a reader must walk past rather than stop at.
    m.capabilities(&[
        (0x09, 0x40, 0),
        (0x10, 0x50, 0),
        (0x09, 0x60, 0),
        (0x11, 0x70, 0),
    ]);
    let mut caps = [pci::Capability::EMPTY; 8];
    let n = pci::capabilities(&m, Address::new(0, 5, 0), &mut caps);
    assert_eq!(n, 4);
    let ids: Vec<(u8, u16)> = caps[..n].iter().map(|c| (c.id, c.offset)).collect();
    assert_eq!(ids, vec![(0x09, 0x40), (0x10, 0x50), (0x09, 0x60), (0x11, 0x70)]);
}

#[test]
fn enumeration_records_a_capability_structure_for_the_driver_to_read() {
    // The property the driver rests on: a driver is handed the `Function`, never the bus,
    // so a capability's own words have to survive enumeration. virtio's vendor capability
    // carries the BAR, offset and length of one structure in words the driver reads back.
    let m = Model::default();
    m.endpoint(Address::new(0, 4, 0), (0x1af4, 0x1042), ETHERNET, &[]);
    m.capability_words(&[(
        0x09,
        0x40,
        // cap_len 0x14 and cfg_type 1 in the first word's upper half, then BAR 4, then
        // the offset and length of the common configuration structure.
        [0x0114_0000, 0x0000_0004, 0x0000_3000, 0x0000_1000, 0, 0],
    )]);
    let fns = enumerate(&m);
    let f = find(&fns, Address::new(0, 4, 0));
    let caps = f.capabilities();
    assert_eq!(caps.len(), 1);
    assert_eq!(caps[0].id, 0x09);
    assert_eq!(caps[0].byte(3), 1, "cfg_type");
    assert_eq!(caps[0].byte(4), 4, "the BAR the structure is in");
    assert_eq!(caps[0].word(2), 0x3000, "its offset into that BAR");
    assert_eq!(caps[0].word(3), 0x1000, "its length");
}

#[test]
fn a_function_without_the_status_bit_is_not_read_for_capabilities() {
    // The pointer holds a plausible offset, but the status bit says there is no list.
    // Following it anyway would invent capabilities out of whatever 0x34 happens to hold.
    let m = Model::default();
    m.endpoint(Address::new(0, 6, 0), (0x1af4, 0x1042), ETHERNET, &[]);
    m.raw_capability_pointer(0x40);
    let mut caps = [pci::Capability::EMPTY; 8];
    assert_eq!(pci::capabilities(&m, Address::new(0, 6, 0), &mut caps), 0);
}

#[test]
fn a_looping_capability_list_is_read_once_rather_than_for_ever() {
    let m = Model::default();
    m.endpoint(Address::new(0, 7, 0), (0x1af4, 0x1042), ETHERNET, &[]);
    m.looping_capability(0x40);
    let mut caps = [pci::Capability::EMPTY; 64];
    // It terminates, at the walk's own bound rather than by filling the caller's slice.
    let n = pci::capabilities(&m, Address::new(0, 7, 0), &mut caps);
    assert_eq!(n, 48);
    assert!(caps[..n].iter().all(|c| c.offset == 0x40));
}

#[test]
fn capabilities_stop_when_the_callers_slice_fills() {
    let m = Model::default();
    m.endpoint(Address::new(0, 8, 0), (0x1af4, 0x1042), ETHERNET, &[]);
    m.capabilities(&[(0x09, 0x40, 0), (0x09, 0x50, 0), (0x09, 0x60, 0)]);
    let mut caps = [pci::Capability::EMPTY; 2];
    assert_eq!(pci::capabilities(&m, Address::new(0, 8, 0), &mut caps), 2);
    assert_eq!(caps[1].offset, 0x50);
}

#[test]
fn a_capability_pointer_inside_the_header_is_refused() {
    // 0x20 is a BAR, not a capability: following it would read a base address as a
    // capability ID and chain onwards from whatever that happened to be.
    let m = Model::default();
    m.endpoint(Address::new(0, 9, 0), (0x1af4, 0x1042), ETHERNET, &[]);
    m.capabilities(&[(0x09, 0x20, 0)]);
    let mut caps = [pci::Capability::EMPTY; 8];
    assert_eq!(pci::capabilities(&m, Address::new(0, 9, 0), &mut caps), 0);
}

#[test]
fn described_devices_carry_their_windows_and_a_compatible_per_kind() {
    let ioapic = Described::new(
        Kind::IoInterruptController { id: 0, gsi_base: 0 },
        format_args!("io-apic@{:x}", 0xfec0_0000u32),
        &[(0xfec0_0000, 0x1000)],
    )
    .unwrap();
    assert_eq!(ioapic.name(), b"io-apic@fec00000");
    assert_eq!(ioapic.compatible(), b"acpi,io-apic\0");
    assert_eq!(ioapic.windows(), &[(0xfec0_0000, 0x1000)]);
    // Too many windows, or a name too long for the record, is refused rather than cut.
    assert!(Described::new(Kind::Group, format_args!("x"), &[(0, 1); 3]).is_none());
    assert!(Described::new(Kind::Group, format_args!("{:>40}", "long"), &[]).is_none());
}

// --- message-signalled vectors ------------------------------------------------------

/// Claims one message-signalled vector, and nothing else.
struct Vectors(u16);

impl Driver for Vectors {
    fn name(&self) -> &'static str {
        "vectors"
    }
    fn compatible(&self) -> &'static [&'static str] {
        &["pci1af4,1042"]
    }
    fn probe(&self, p: &mut Probe<'_, '_, '_, '_>) -> Result<(), ProbeError> {
        p.claim_msi(self.0)?;
        Ok(())
    }
    fn start(&self, _: &Bound) -> Result<(), &'static str> {
        Ok(())
    }
}

/// One virtio-like function at 00:05.0 with a memory BAR and the capabilities given.
fn function_with(caps: &[(u8, u16, [u32; 6])]) -> Vec<Function> {
    let m = Model::default();
    m.endpoint(
        Address::new(0, 5, 0),
        (0x1af4, 0x1042),
        ETHERNET,
        &[Spec::Mem32 {
            base: 0xfeb0_0000,
            size: 0x1000,
            prefetch: false,
        }],
    );
    if !caps.is_empty() {
        m.capability_words(caps);
    }
    enumerate(&m)
}

/// MSI-X with a table of `entries` in BAR 0.
fn msix_cap(entries: u32) -> (u8, u16, [u32; 6]) {
    (msi::CAP_MSIX, 0x40, [(entries - 1) << 16, 0, 0x800, 0, 0, 0])
}

#[test]
fn a_vector_is_claimed_only_where_the_platform_delivers_messages() {
    let fns = function_with(&[msix_cap(2)]);
    let mut storage = vec![Node::EMPTY; 4];
    let mut b = Builder::new(&mut storage).unwrap();
    let id = b
        .add(NodeId::ROOT, fns[0].name(), fns[0].compatible(), Origin::Pci(&fns[0]))
        .unwrap();
    let tree = b.finish();

    let (mut mmio, mut irqs) = (vec![None; 2], vec![None; 4]);
    let mut res = Resources::new(&mut mmio, &mut irqs);
    assert_eq!(
        driver::probe(&Vectors(0), &tree, id, &mut res).err(),
        Some(ProbeError::Declined("this platform delivers no message-signalled interrupts"))
    );
    assert_eq!(res.irq_claims().count(), 0);
}

#[test]
fn msix_vectors_are_claimed_up_to_the_table_size_and_once_each() {
    let fns = function_with(&[msix_cap(2)]);
    let mut storage = vec![Node::EMPTY; 4];
    let mut b = Builder::new(&mut storage).unwrap();
    let id = b
        .add(NodeId::ROOT, fns[0].name(), fns[0].compatible(), Origin::Pci(&fns[0]))
        .unwrap();
    let tree = b.finish();

    let (mut mmio, mut irqs) = (vec![None; 2], vec![None; 4]);
    let mut res = Resources::new(&mut mmio, &mut irqs).with_msi(true);
    driver::probe(&Vectors(0), &tree, id, &mut res).unwrap();
    driver::probe(&Vectors(1), &tree, id, &mut res).unwrap();
    let claimed: Vec<(NodeId, Vec<u32>)> = res
        .irq_claims()
        .map(|c| (c.spec.controller, c.spec.cells().to_vec()))
        .collect();
    assert_eq!(
        claimed,
        [(id, vec![msi::VECTOR_TAG]), (id, vec![msi::VECTOR_TAG | 1])],
        "each vector names the function itself, tagged, so no line can collide with it"
    );
    assert!(matches!(
        driver::probe(&Vectors(2), &tree, id, &mut res),
        Err(ProbeError::Tree(Error::NoSuchEntry { index: 2, .. }))
    ));
    assert!(matches!(
        driver::probe(&Vectors(0), &tree, id, &mut res),
        Err(ProbeError::Claim(ClaimError::IrqTaken { holder })) if holder == id
    ));
}

#[test]
fn msi_without_msix_is_one_vector_and_a_function_with_neither_has_none() {
    let fns = function_with(&[(msi::CAP_MSI, 0x50, [0; 6])]);
    let mut storage = vec![Node::EMPTY; 4];
    let mut b = Builder::new(&mut storage).unwrap();
    let id = b
        .add(NodeId::ROOT, fns[0].name(), fns[0].compatible(), Origin::Pci(&fns[0]))
        .unwrap();
    let tree = b.finish();
    let (mut mmio, mut irqs) = (vec![None; 2], vec![None; 4]);
    let mut res = Resources::new(&mut mmio, &mut irqs).with_msi(true);
    driver::probe(&Vectors(0), &tree, id, &mut res).unwrap();
    assert!(matches!(
        driver::probe(&Vectors(1), &tree, id, &mut res),
        Err(ProbeError::Tree(Error::NoSuchEntry { index: 1, .. }))
    ));

    let fns = function_with(&[]);
    let mut storage = vec![Node::EMPTY; 4];
    let mut b = Builder::new(&mut storage).unwrap();
    let id = b
        .add(NodeId::ROOT, fns[0].name(), fns[0].compatible(), Origin::Pci(&fns[0]))
        .unwrap();
    let tree = b.finish();
    let (mut mmio, mut irqs) = (vec![None; 2], vec![None; 4]);
    let mut res = Resources::new(&mut mmio, &mut irqs).with_msi(true);
    assert!(matches!(
        driver::probe(&Vectors(0), &tree, id, &mut res),
        Err(ProbeError::Tree(Error::NoSuchEntry { index: 0, .. }))
    ));
}

#[test]
fn a_function_reports_its_msix_table_through_enumeration() {
    // Firmware left MSI-X enabled with the function masked; the record says so, and the
    // table and pending bits are where the capability put them.
    let fns = function_with(&[(
        msi::CAP_MSIX,
        0x40,
        [(1 << 31) | (1 << 30) | (3 << 16), 0x2000, 0x3000, 0, 0, 0],
    )]);
    let cap = msi::msix(&fns[0]).unwrap();
    assert_eq!(cap.table_size, 4);
    assert_eq!((cap.table_bar, cap.table_offset), (0, 0x2000));
    assert_eq!((cap.pba_bar, cap.pba_offset), (0, 0x3000));
    assert!(cap.enabled && cap.function_masked);
    assert_eq!(msi::msi(&fns[0]), None);
}

/// A machine whose firmware assigned nothing: every BAR reads zero, which is what QEMU's
/// `virt` presents when it is booted with `-kernel` and no firmware runs at all.
fn unassigned() -> Model {
    let m = Model::default();
    m.add(Address::new(0, 0, 0), (0x1b36, 0x0008), HOST, 0, &[]);
    m.endpoint(
        Address::new(0, 1, 0),
        (0x1af4, 0x1042),
        ETHERNET,
        &[
            Spec::Mem32 {
                base: 0,
                size: 0x1000,
                prefetch: false,
            },
            Spec::Mem64 {
                base: 0,
                size: 0x4000,
                prefetch: false,
            },
        ],
    );
    m
}

#[test]
fn an_unassigned_bar_is_placed_and_reads_back() {
    let m = unassigned();
    let mut fns = enumerate(&m);
    let at = Address::new(0, 1, 0);
    // Before: the registers are implemented, sized, and decode nowhere.
    assert!(matches!(
        find(&fns, at).bars[0],
        Bar::Memory {
            base: 0,
            size: 0x1000,
            ..
        }
    ));
    let placed = pci::assign_memory_bars(&m, &mut fns, 0x1000_0000, 0x10_0000).unwrap();
    assert_eq!(placed, 2, "both memory registers are placed");

    let f = find(&fns, at);
    let (b0, b1) = (f.bars[0], f.bars[1]);
    let base0 = match b0 {
        Bar::Memory { base, .. } => base,
        _ => panic!("bar 0 is memory"),
    };
    let base1 = match b1 {
        Bar::Memory {
            base, size, wide, ..
        } => {
            assert!(wide && size == 0x4000);
            base
        }
        _ => panic!("bar 1 is a 64-bit memory register"),
    };
    assert_ne!(base0, 0);
    assert_ne!(base1, 0);
    // Natural alignment: the decoder ignores the low bits of the address it is given, so a
    // register placed off its own size would answer somewhere else.
    assert_eq!(base0 % 0x1000, 0);
    assert_eq!(base1 % 0x4000, 0);
    // They do not overlap.
    assert!(base0 + 0x1000 <= base1 || base1 + 0x4000 <= base0);
    // And the hardware holds what the record claims, which is the point of assigning.
    assert_eq!(m.read(at, 0x10) & !0xf, base0 as u32);
    assert_eq!(m.read(at, 0x14) & !0xf, base1 as u32 & !0xf);
    assert_eq!(m.read(at, 0x18), (base1 >> 32) as u32);
    // The record of what the registers held is updated with them, so a restore check run
    // afterwards compares against what is really there.
    assert_eq!(pci::verify_restored(&m, &fns), Ok(()));
}

#[test]
fn a_bar_firmware_already_assigned_is_left_alone() {
    // The repair is for the machine nobody assigned. One that was assigned keeps what it
    // was given, because moving a decoder under a driver would be worse than doing nothing.
    let m = Model::default();
    m.add(Address::new(0, 0, 0), (0x1b36, 0x0008), HOST, 0, &[]);
    m.endpoint(
        Address::new(0, 1, 0),
        (0x1af4, 0x1042),
        ETHERNET,
        &[Spec::Mem32 {
            base: 0xc000_0000,
            size: 0x1000,
            prefetch: false,
        }],
    );
    let mut fns = enumerate(&m);
    let placed = pci::assign_memory_bars(&m, &mut fns, 0x1000_0000, 0x10_0000).unwrap();
    assert_eq!(placed, 0, "nothing was unassigned, so nothing moved");
    assert!(matches!(
        find(&fns, Address::new(0, 1, 0)).bars[0],
        Bar::Memory {
            base: 0xc000_0000,
            ..
        }
    ));
}

#[test]
fn a_host_bridges_own_registers_are_not_placed() {
    // As in sizing: a bridge's BARs are not device registers to hand out, and disturbing
    // its decoding can take the path to everything behind it with it.
    let m = Model::default();
    m.add(
        Address::new(0, 0, 0),
        (0x1b36, 0x0008),
        HOST,
        0,
        &[Spec::Mem32 {
            base: 0,
            size: 0x1000,
            prefetch: false,
        }],
    );
    let mut fns = enumerate(&m);
    assert_eq!(pci::assign_memory_bars(&m, &mut fns, 0x1000_0000, 0x10_0000), Ok(0));
    assert_eq!(m.read(Address::new(0, 0, 0), 0x10) & !0xf, 0);
}

#[test]
fn an_arena_too_small_says_which_register_did_not_fit() {
    let m = unassigned();
    let mut fns = enumerate(&m);
    // Room for the 4 KiB register and not for the 16 KiB one behind it.
    let err = pci::assign_memory_bars(&m, &mut fns, 0x1000_0000, 0x2000).unwrap_err();
    assert!(
        matches!(
            err,
            pci::Unplaced::NoRoom { at, index: 1, need: 0x4000, .. } if at == Address::new(0, 1, 0)
        ),
        "{err:?}"
    );
}

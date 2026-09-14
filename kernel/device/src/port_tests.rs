//! Host tests for I/O port claims and the devices a platform declares.
//!
//! The PC's serial port is the case these exist for: no table lists it, the platform
//! declares it, it lives in the port space rather than in memory, and its interrupt is a
//! line number rather than cells for a controller to interpret.

use super::driver::{self, best_match};
use super::tree::Error;
use super::*;

/// A driver that takes a port range and its interrupt, like the PC's serial port.
struct PortDriver;

impl Driver for PortDriver {
    fn name(&self) -> &'static str {
        "ports"
    }

    fn compatible(&self) -> &'static [&'static str] {
        &["ns16550a"]
    }

    fn probe(&self, p: &mut Probe<'_, '_, '_, '_>) -> Result<(), ProbeError> {
        p.claim_ports(0, "test UART")?;
        p.claim_irq(0)?;
        Ok(())
    }

    fn start(&self, _bound: &Bound) -> Result<(), &'static str> {
        Ok(())
    }
}

/// A record the platform declares: ports and one interrupt line, no window.
fn declared(name: core::fmt::Arguments<'_>, base: u16, len: u16, irq: u32) -> Described {
    Described::new(table::Kind::LegacyUart, name, &[])
        .unwrap()
        .with_ports(Some((base, len)), Some(irq))
}

#[test]
fn a_declared_device_carries_its_ports_and_its_line() {
    let com1 = declared(format_args!("serial@3f8"), 0x3f8, 8, 4);
    let mut nodes = vec![Node::EMPTY; 4];
    let mut b = Builder::new(&mut nodes).unwrap();
    let id = b
        .add(NodeId::ROOT, com1.name(), com1.compatible(), Origin::Table(&com1))
        .unwrap();
    let tree = b.finish();

    assert_eq!(tree.ports(id, 0), Ok((0x3f8, 8)));
    assert!(matches!(tree.ports(id, 1), Err(Error::NoSuchEntry { .. })), "one range only");
    // A declared device's interrupt is the line itself, not cells to interpret.
    let spec = tree.interrupt(id, 0).unwrap();
    assert_eq!(spec.cells(), &[4]);
    assert_eq!(spec.controller, NodeId::ROOT);
    assert!(matches!(tree.interrupt(id, 1), Err(Error::NoSuchEntry { .. })));
    // It has no memory window, and asking for one says so rather than inventing one.
    assert!(matches!(tree.mmio(id, 0), Err(Error::NoSuchEntry { .. })));
    assert_eq!(best_match(&tree, id, &[&PortDriver]), Some((0, 0)));
}

#[test]
fn port_ranges_are_claimed_exclusively() {
    let com1 = declared(format_args!("serial@3f8"), 0x3f8, 8, 4);
    let overlapping = declared(format_args!("serial@3fc"), 0x3fc, 8, 3);
    let com2 = declared(format_args!("serial@2f8"), 0x2f8, 8, 3);
    let mut nodes = vec![Node::EMPTY; 8];
    let mut b = Builder::new(&mut nodes).unwrap();
    let mut ids = Vec::new();
    for d in [&com1, &overlapping, &com2] {
        ids.push(
            b.add(NodeId::ROOT, d.name(), d.compatible(), Origin::Table(d))
                .unwrap(),
        );
    }
    let tree = b.finish();

    let (mut mmio, mut irqs, mut ports) = (vec![None; 4], vec![None; 4], vec![None; 4]);
    let mut res = Resources::new(&mut mmio, &mut irqs).with_ports(&mut ports);

    let first = driver::probe(&PortDriver, &tree, ids[0], &mut res).unwrap();
    assert_eq!(res.port_claims().count(), 1);

    // 0x3fc..0x404 runs into 0x3f8..0x400, and the refusal names who holds it.
    match driver::probe(&PortDriver, &tree, ids[1], &mut res) {
        Err(ProbeError::Claim(ClaimError::Overlaps { holder, phys, len })) => {
            assert_eq!((holder, phys, len), (ids[0], 0x3f8, 8));
        }
        other => panic!("overlapping ports were not refused: {other:?}"),
    }
    // The failed probe left nothing behind, not even the interrupt it claimed first.
    assert_eq!(res.port_claims().count(), 1);
    assert_eq!(res.irq_claims().count(), 1);

    // A range that does not overlap is granted.
    let second = driver::probe(&PortDriver, &tree, ids[2], &mut res).unwrap();
    assert_eq!(res.port_claims().count(), 2);

    driver::remove(&PortDriver, first, &mut res);
    assert_eq!(res.port_claims().count(), 1, "removal released exactly its own range");
    driver::remove(&PortDriver, second, &mut res);
    assert_eq!(res.port_claims().count(), 0);
}

#[test]
fn a_machine_with_no_port_space_grants_no_ports() {
    let com1 = declared(format_args!("serial@3f8"), 0x3f8, 8, 4);
    let mut nodes = vec![Node::EMPTY; 4];
    let mut b = Builder::new(&mut nodes).unwrap();
    let id = b
        .add(NodeId::ROOT, com1.name(), com1.compatible(), Origin::Table(&com1))
        .unwrap();
    let tree = b.finish();

    // `Resources::new` without `with_ports`: an aarch64 or riscv32 platform.
    let (mut mmio, mut irqs) = (vec![None; 4], vec![None; 4]);
    let mut res = Resources::new(&mut mmio, &mut irqs);
    assert_eq!(
        driver::probe(&PortDriver, &tree, id, &mut res),
        Err(ProbeError::Claim(ClaimError::NoRoom))
    );
    assert_eq!(res.irq_claims().count(), 0, "the failed probe kept nothing");
}

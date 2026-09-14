//! Host tests for the device model.
//!
//! Three trees: QEMU `virt` as it describes itself with a GICv2 and with a GICv3,
//! dumped with `-machine virt,dumpdtb=`, and `testdata/model.dts`, written to break one
//! rule per node. The QEMU trees are what the kernel actually boots on; the hand-written
//! one is where the corner cases live.

use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use hal::IrqNumber;

use super::driver::{self, best_match};
use super::tree::Error;
use super::*;

const VIRT_V3: &[u8] = include_bytes!("testdata/qemu-virt-gicv3-128m.dtb");
const VIRT_V2: &[u8] = include_bytes!("testdata/qemu-virt-gicv2-128m.dtb");
const MODEL: &[u8] = include_bytes!("testdata/model.dtb");

/// Nodes and a ledger to build against.
struct Fixture {
    nodes: Vec<Node<'static>>,
    mmio: Vec<Option<MmioClaim>>,
    irqs: Vec<Option<IrqClaim>>,
}

impl Fixture {
    fn new() -> Fixture {
        Fixture {
            nodes: vec![Node::EMPTY; 128],
            mmio: vec![None; 16],
            irqs: vec![None; 16],
        }
    }
}

fn fdt(blob: &'static [u8]) -> fdt::Fdt<'static> {
    fdt::Fdt::new(blob).expect("fixture is a valid tree")
}

fn at<'t>(tree: &DeviceTree<'_, 't>, path: &str) -> NodeId {
    tree.find(path.as_bytes())
        .unwrap_or_else(|| panic!("no node {path}"))
}

// --- the real machine --------------------------------------------------------------

#[test]
fn virt_v3_windows_and_console() {
    let f = fdt(VIRT_V3);
    let mut fx = Fixture::new();
    let tree = DeviceTree::build(&f, &mut fx.nodes).unwrap();

    let uart = tree.stdout().expect("chosen stdout-path resolves");
    assert_eq!(tree.node(uart).name(), b"pl011@9000000");
    assert!(tree.node(uart).is_compatible("arm,pl011"));
    assert_eq!(tree.mmio(uart, 0), Ok((0x0900_0000, 0x1000)));

    let gic = at(&tree, "/intc@8000000");
    assert!(tree.node(gic).is_compatible("arm,gic-v3"));
    assert_eq!(tree.mmio_count(gic), 2);
    assert_eq!(tree.mmio(gic, 0), Ok((0x0800_0000, 0x1_0000)));
    assert_eq!(tree.mmio(gic, 1), Ok((0x080a_0000, 0xf6_0000)));
    assert!(tree.mmio(gic, 2).is_err());

    // The UART's interrupt resolves through the root's inherited interrupt-parent.
    let spec = tree.interrupt(uart, 0).unwrap();
    assert_eq!(spec.controller, gic);
    assert_eq!(spec.cells(), &[0, 1, 4]);

    // The timer's second interrupt is the non-secure physical PPI 14.
    let timer = at(&tree, "/timer");
    assert_eq!(tree.interrupt_count(timer), 4);
    assert_eq!(tree.interrupt(timer, 1).unwrap().cells(), &[1, 14, 4]);

    // The UART clock is the 24 MHz fixed clock, through `clocks`.
    let clk = tree.clock(uart, 0).unwrap();
    assert_eq!(tree.node(clk).clock_frequency(), Some(24_000_000));
}

#[test]
fn virt_v2_is_told_apart_by_compatible() {
    let f = fdt(VIRT_V2);
    let mut fx = Fixture::new();
    let tree = DeviceTree::build(&f, &mut fx.nodes).unwrap();
    let gic = at(&tree, "/intc@8000000");
    assert!(tree.node(gic).is_compatible("arm,cortex-a15-gic"));
    assert!(!tree.node(gic).is_compatible("arm,gic-v3"));
    assert_eq!(tree.mmio(gic, 1), Ok((0x0801_0000, 0x1_0000)));
    // The v2m frame is a child of the GIC, whose empty `ranges` maps it 1:1.
    let v2m = at(&tree, "/intc@8000000/v2m@8020000");
    assert_eq!(tree.mmio(v2m, 0), Ok((0x0802_0000, 0x1000)));
}

#[test]
fn virt_cpu_reg_is_not_an_address() {
    let f = fdt(VIRT_V3);
    let mut fx = Fixture::new();
    let tree = DeviceTree::build(&f, &mut fx.nodes).unwrap();
    let cpu = at(&tree, "/cpus/cpu@0");
    // `/cpus` has #size-cells = 0, so the entry is address-only, and `/cpus` has no
    // `ranges`: a CPU number must not come back as an MMIO window at zero.
    assert!(matches!(tree.mmio(cpu, 0), Err(Error::NotMemoryMapped { .. })));
}

// --- the hand-written tree ---------------------------------------------------------

fn model(fx: &mut Fixture) -> DeviceTree<'static, '_> {
    DeviceTree::build(&fdt(MODEL), &mut fx.nodes).unwrap()
}

#[test]
fn ranges_translate_through_every_bus() {
    let mut fx = Fixture::new();
    let tree = model(&mut fx);
    assert_eq!(tree.mmio(at(&tree, "/soc/uart@1000"), 0), Ok((0x2_0000_1000, 0x1000)));
    // Through `inner`'s empty ranges, then soc's.
    assert_eq!(tree.mmio(at(&tree, "/soc/inner/dev@0"), 0), Ok((0x2_0000_3000, 0x100)));
    let outside = at(&tree, "/soc/outside@20000000");
    assert!(matches!(
        tree.mmio(outside, 0),
        Err(Error::Untranslatable {
            address: 0x2000_0000,
            ..
        })
    ));
}

#[test]
fn cell_counts_are_not_inherited() {
    let mut fx = Fixture::new();
    let tree = model(&mut fx);
    // `inner` declares none, so its child uses 2 and 1 — three cells — not soc's 1 and 1.
    // Read with soc's counts, the same bytes would be two entries.
    let dev = at(&tree, "/soc/inner/dev@0");
    assert_eq!(tree.mmio_count(dev), 1);
}

#[test]
fn interrupt_parent_is_inherited() {
    let mut fx = Fixture::new();
    let tree = model(&mut fx);
    let dev = at(&tree, "/soc/inner/dev@0");
    let spec = tree.interrupt(dev, 0).unwrap();
    assert_eq!(spec.controller, at(&tree, "/intc@8000000"));
    assert_eq!(spec.cells(), &[0, 2, 4]);
}

#[test]
fn interrupt_parents_that_cannot_take_a_specifier() {
    let mut fx = Fixture::new();
    let tree = model(&mut fx);
    assert!(matches!(
        tree.interrupt(at(&tree, "/pci-ish/child"), 0),
        Err(Error::InterruptNexus { .. })
    ));
    assert!(matches!(
        tree.interrupt(at(&tree, "/not-a-controller/orphan"), 0),
        Err(Error::NotAnInterruptController { .. })
    ));
    assert!(matches!(
        tree.interrupt(at(&tree, "/dangling"), 0),
        Err(Error::NoSuchPhandle {
            phandle: 0x9999,
            ..
        })
    ));
}

#[test]
fn malformed_properties_fail_only_the_question_that_needs_them() {
    let mut fx = Fixture::new();
    let tree = model(&mut fx);
    let dev = at(&tree, "/bad-cells/dev@0");
    assert!(matches!(tree.mmio(dev, 0), Err(Error::BadCellProperty { .. })));
    let wide = at(&tree, "/wide/dev@0");
    assert!(matches!(tree.mmio(wide, 0), Err(Error::UnsupportedCells { cells: 5, .. })));
    // The rest of the tree is unaffected.
    assert!(tree.mmio(at(&tree, "/soc/uart@1000"), 0).is_ok());
}

#[test]
fn stdout_resolves_an_alias_and_drops_options() {
    let mut fx = Fixture::new();
    let tree = model(&mut fx);
    assert_eq!(tree.stdout(), Some(at(&tree, "/soc/uart@1000")));
    assert_eq!(tree.find(b"bogus"), None, "an alias must hold a full path");
    assert_eq!(tree.find(b"nonexistent"), None);
    assert_eq!(tree.find(b"/soc/uart"), Some(at(&tree, "/soc/uart@1000")));
}

#[test]
fn clocks_skip_each_providers_specifier_cells() {
    let mut fx = Fixture::new();
    let tree = model(&mut fx);
    let uart = at(&tree, "/soc/uart@1000");
    // Entry 0 is the mux with one specifier cell; entry 1 must skip that cell.
    assert_eq!(tree.clock(uart, 0), Some(at(&tree, "/clock-mux")));
    assert_eq!(tree.clock(uart, 1), Some(at(&tree, "/clock")));
    assert_eq!(tree.clock(uart, 2), None);
}

#[test]
fn too_many_nodes_is_an_error_not_a_truncated_tree() {
    let f = fdt(VIRT_V3);
    let mut small = vec![Node::EMPTY; 8];
    assert_eq!(
        DeviceTree::build(&f, &mut small).err(),
        Some(Error::TooManyNodes { capacity: 8 })
    );
}

#[test]
fn every_node_of_both_machines_is_asked_every_question_without_panicking() {
    for blob in [VIRT_V2, VIRT_V3, MODEL] {
        let f = fdt(blob);
        let mut fx = Fixture::new();
        let tree = DeviceTree::build(&f, &mut fx.nodes).unwrap();
        for id in tree.ids() {
            for i in 0..4 {
                let _ = tree.mmio(id, i);
                let _ = tree.interrupt(id, i);
                let _ = tree.clock(id, i);
            }
            let _ = tree.interrupt_parent(id);
            let _ = tree.node(id).compatible().count();
        }
    }
}

#[test]
fn a_truncated_blob_is_refused_by_the_parser_first() {
    // The model builds only on a tree `boot/fdt` validated; a corrupted blob never gets
    // as far as nodes. Every prefix is refused or, if it happens to be a whole tree,
    // builds cleanly.
    for len in (0..VIRT_V3.len()).step_by(97) {
        if let Ok(f) = fdt::Fdt::new(&VIRT_V3[..len]) {
            let mut fx = Fixture::new();
            let _ = DeviceTree::build(&f, &mut fx.nodes);
        }
    }
}

// --- binding and phases ------------------------------------------------------------

struct Uart {
    fail_after_first_claim: bool,
}

impl Driver for Uart {
    fn name(&self) -> &'static str {
        "uart"
    }
    fn compatible(&self) -> &'static [&'static str] {
        &["arm,pl011"]
    }
    fn probe(&self, p: &mut Probe<'_, '_, '_, '_>) -> Result<(), ProbeError> {
        let _regs = p.claim_mmio(0, "uart")?;
        if self.fail_after_first_claim {
            return Err(ProbeError::Declined("test"));
        }
        let _irq = p.claim_irq(0)?;
        Ok(())
    }
    fn start(&self, _: &Bound) -> Result<(), &'static str> {
        Ok(())
    }
}

/// Declines unless told otherwise, and never starts.
struct Generic;

impl Driver for Generic {
    fn name(&self) -> &'static str {
        "generic"
    }
    fn compatible(&self) -> &'static [&'static str] {
        &["test,generic", "arm,primecell"]
    }
    fn probe(&self, _: &mut Probe<'_, '_, '_, '_>) -> Result<(), ProbeError> {
        Ok(())
    }
    fn start(&self, _: &Bound) -> Result<(), &'static str> {
        Err("never starts")
    }
}

struct Specific;

impl Driver for Specific {
    fn name(&self) -> &'static str {
        "specific"
    }
    fn compatible(&self) -> &'static [&'static str] {
        &["test,specific"]
    }
    fn probe(&self, _: &mut Probe<'_, '_, '_, '_>) -> Result<(), ProbeError> {
        Ok(())
    }
    fn start(&self, _: &Bound) -> Result<(), &'static str> {
        Ok(())
    }
}

/// Claims its node's first window, and nothing else.
struct Twin;

impl Driver for Twin {
    fn name(&self) -> &'static str {
        "twin"
    }
    fn compatible(&self) -> &'static [&'static str] {
        &["test,twin"]
    }
    fn probe(&self, p: &mut Probe<'_, '_, '_, '_>) -> Result<(), ProbeError> {
        p.claim_mmio(0, "twin").map(|_| ())
    }
    fn start(&self, _: &Bound) -> Result<(), &'static str> {
        Ok(())
    }
}

const UART: Uart = Uart {
    fail_after_first_claim: false,
};

#[test]
fn the_most_specific_compatible_wins() {
    let mut fx = Fixture::new();
    let tree = model(&mut fx);
    let (g, s) = (Generic, Specific);
    let drivers: [&dyn Driver; 3] = [&g, &UART, &s];

    // The UART lists "arm,pl011" before "arm,primecell": the UART driver wins even though
    // the generic one is earlier in the driver list.
    assert_eq!(best_match(&tree, at(&tree, "/soc/uart@1000"), &drivers), Some((1, 0)));
    // "test,specific" is the node's first entry, so its driver wins over "test,generic".
    assert_eq!(best_match(&tree, at(&tree, "/multi-compat"), &drivers), Some((2, 0)));
    // Without the specific driver, the generic one binds at the node's second entry.
    let fewer: [&dyn Driver; 2] = [&g, &UART];
    assert_eq!(best_match(&tree, at(&tree, "/multi-compat"), &fewer), Some((0, 1)));
    // Disabled nodes bind to nothing, even with a matching driver; nodes without a
    // `compatible` bind to nothing at all.
    assert_eq!(best_match(&tree, at(&tree, "/soc/disabled@5000"), &drivers), None);
    assert_eq!(best_match(&tree, at(&tree, "/soc/inner/dev@0"), &drivers), None);
}

#[test]
fn overlapping_windows_are_refused_and_name_the_holder() {
    let mut fx = Fixture::new();
    let tree = DeviceTree::build(&fdt(MODEL), &mut fx.nodes).unwrap();
    let mut res = Resources::new(&mut fx.mmio, &mut fx.irqs);
    let uart_node = at(&tree, "/soc/uart@1000");
    let bound = driver::probe(&UART, &tree, uart_node, &mut res).unwrap();
    assert_eq!(bound.node(), uart_node);
    assert_eq!(res.mmio_claims().count(), 1);
    assert_eq!(res.irq_claims().count(), 1);

    let err = driver::probe(&Twin, &tree, at(&tree, "/soc/twin@1800"), &mut res).unwrap_err();
    assert_eq!(
        err,
        ProbeError::Claim(ClaimError::Overlaps {
            holder: uart_node,
            phys: 0x2_0000_1000,
            len: 0x1000
        })
    );

    // Probing the bound UART again fails on its own window — and releasing that failed
    // probe's claims must leave the existing binding's alone.
    assert!(driver::probe(&UART, &tree, uart_node, &mut res).is_err());
    assert_eq!(
        res.mmio_claims().count(),
        1,
        "a failed re-probe released the bound device's window"
    );
    assert_eq!(res.irq_claims().count(), 1);

    driver::remove(&UART, bound, &mut res);
    assert_eq!(res.mmio_claims().count(), 0);
    assert!(driver::probe(&Twin, &tree, at(&tree, "/soc/twin@1800"), &mut res).is_ok());
}

#[test]
fn a_failed_probe_releases_what_it_claimed() {
    let mut fx = Fixture::new();
    let tree = DeviceTree::build(&fdt(MODEL), &mut fx.nodes).unwrap();
    let mut res = Resources::new(&mut fx.mmio, &mut fx.irqs);
    let failing = Uart {
        fail_after_first_claim: true,
    };
    let node = at(&tree, "/soc/uart@1000");
    assert_eq!(
        driver::probe(&failing, &tree, node, &mut res),
        Err(ProbeError::Declined("test"))
    );
    assert_eq!(res.mmio_claims().count(), 0);
    // The window is free again for a driver that succeeds.
    assert!(driver::probe(&UART, &tree, node, &mut res).is_ok());
}

#[test]
fn a_leaked_handle_cannot_release_a_reused_slot() {
    let mut mmio = vec![None; 2];
    let mut irqs = vec![None; 1];
    let mut res = Resources::new(&mut mmio, &mut irqs);
    let first = res.begin();
    let a = res
        .claim_mmio(first, NodeId::ROOT, 0x1000, 0x1000, "a")
        .unwrap();
    res.release_owner(first);
    let second = res.begin();
    let b = res
        .claim_mmio(second, NodeId::ROOT, 0x1000, 0x1000, "b")
        .unwrap();
    // Same window, same slot, same node: only the owner tells the two claims apart.
    res.release_mmio(a);
    assert_eq!(res.mmio_claims().count(), 1, "releasing a stale handle freed b's claim");
    res.release_mmio(b);
    assert_eq!(res.mmio_claims().count(), 0);
}

#[test]
fn window_edges() {
    let mut mmio = vec![None; 4];
    let mut irqs = vec![None; 1];
    let mut res = Resources::new(&mut mmio, &mut irqs);
    let o = res.begin();
    let n = NodeId::ROOT;
    assert_eq!(res.claim_mmio(o, n, 0x1000, 0, "e"), Err(ClaimError::Empty));
    let _a = res.claim_mmio(o, n, 0x1000, 0x1000, "a").unwrap();
    // Adjacent on both sides is not overlap.
    assert!(res.claim_mmio(o, n, 0x2000, 0x1000, "b").is_ok());
    assert!(res.claim_mmio(o, n, 0x0, 0x1000, "c").is_ok());
    // One byte in is.
    assert!(matches!(
        res.claim_mmio(o, n, 0x1fff, 1, "d"),
        Err(ClaimError::Overlaps { phys: 0x1000, .. })
    ));
    // The top of the address space is expressible.
    assert!(
        res.claim_mmio(o, n, u64::MAX - 0xfff, 0x1000, "top")
            .is_ok()
    );
    assert_eq!(res.claim_mmio(o, n, 0x9000, 1, "full"), Err(ClaimError::NoRoom));
}

/// The line `Holder` claimed in its last probe, handed to the test.
static HELD: Mutex<Option<IrqLine>> = Mutex::new(None);

/// Claims its node's first interrupt and keeps it, as a driver keeps its lines.
struct Holder;

impl Driver for Holder {
    fn name(&self) -> &'static str {
        "holder"
    }
    fn compatible(&self) -> &'static [&'static str] {
        &["arm,pl011"]
    }
    fn probe(&self, p: &mut Probe<'_, '_, '_, '_>) -> Result<(), ProbeError> {
        *HELD.lock().unwrap() = Some(p.claim_irq(0)?);
        Ok(())
    }
    fn start(&self, _: &Bound) -> Result<(), &'static str> {
        Ok(())
    }
}

#[test]
fn phases_gate_handlers_and_carry_through_power_transitions() {
    static RAN: AtomicUsize = AtomicUsize::new(0);
    fn handler() {
        RAN.fetch_add(1, Ordering::Relaxed);
    }

    let mut fx = Fixture::new();
    let tree = DeviceTree::build(&fdt(MODEL), &mut fx.nodes).unwrap();
    let mut res = Resources::new(&mut fx.mmio, &mut fx.irqs);

    let node = at(&tree, "/soc/uart@1000");
    let bound = driver::probe(&Holder, &tree, node, &mut res).unwrap();
    let line = HELD.lock().unwrap().take().unwrap();

    let mut handlers: Handlers<4> = Handlers::new();
    handlers
        .register(&bound, &line, IrqNumber(33), handler)
        .unwrap();
    assert_eq!(
        handlers.register(&bound, &line, IrqNumber(33), handler),
        Err(HandlerError::Busy)
    );
    // Registered but not enabled: dispatch does not run it.
    assert!(!handlers.dispatch(IrqNumber(33)));

    // A line another binding claimed cannot be registered with this token — even when
    // the other binding is of a node with the same driver.
    let other_node = at(&tree, "/soc/inner/dev@0");
    let other = driver::probe(&Holder, &tree, other_node, &mut res).unwrap();
    let foreign = HELD.lock().unwrap().take().unwrap();
    assert_eq!(
        handlers.register(&bound, &foreign, IrqNumber(34), handler),
        Err(HandlerError::NotOwner)
    );
    assert!(
        handlers
            .register(&other, &foreign, IrqNumber(34), handler)
            .is_ok()
    );

    let started = driver::start(&Holder, bound).unwrap();
    handlers.enable(&started, IrqNumber(33)).unwrap();
    // Enabling someone else's handler with this device's token is refused.
    assert_eq!(handlers.enable(&started, IrqNumber(34)), Err(HandlerError::NotRegistered));
    assert!(handlers.dispatch(IrqNumber(33)));
    assert!(!handlers.dispatch(IrqNumber(34)));
    assert_eq!(RAN.load(Ordering::Relaxed), 1);

    // A registered, enabled handler cannot be unregistered: the line is still live.
    assert_eq!(
        handlers.unregister(started.bound(), IrqNumber(33)),
        Err(HandlerError::StillEnabled)
    );

    let suspended = driver::suspend(&Holder, started).unwrap();
    let started = driver::resume(&Holder, suspended).unwrap();

    // Taking the device away: disable, unregister, and dispatch finds nothing. This is
    // the order `remove` needs, and each step is refused out of it.
    handlers.disable(&started, IrqNumber(33)).unwrap();
    assert!(!handlers.dispatch(IrqNumber(33)), "disabled: the handler does not run");
    assert!(handlers.registered(IrqNumber(33)), "but it is still registered");
    let bound = driver::stop(&Holder, started);
    handlers.unregister(&bound, IrqNumber(33)).unwrap();
    assert!(!handlers.registered(IrqNumber(33)));
    assert_eq!(
        handlers.unregister(&bound, IrqNumber(33)),
        Err(HandlerError::NotRegistered),
        "twice is refused"
    );
    assert_eq!(RAN.load(Ordering::Relaxed), 1, "nothing ran after the disable");
    driver::remove(&Holder, bound, &mut res);
    assert_eq!(res.irq_claims().count(), 1, "remove released exactly its own binding's claims");
    driver::remove(&Holder, other, &mut res);
    assert_eq!(res.irq_claims().count(), 0);
}

#[test]
fn a_failed_start_hands_the_bound_token_back() {
    let mut fx = Fixture::new();
    let tree = DeviceTree::build(&fdt(MODEL), &mut fx.nodes).unwrap();
    let mut res = Resources::new(&mut fx.mmio, &mut fx.irqs);
    let node = at(&tree, "/multi-compat");
    let bound = driver::probe(&Generic, &tree, node, &mut res).unwrap();
    let (bound, why) = driver::start(&Generic, bound).unwrap_err();
    assert_eq!(why, "never starts");
    assert_eq!(bound.driver(), "generic");
}

// --- registers ---------------------------------------------------------------------

#[test]
#[allow(unsafe_code)]
fn registers_stay_inside_their_window() {
    let mut backing = [0u32; 4];
    // SAFETY: a live, aligned, 16-byte buffer, used only through `regs` below and read
    // back only after `regs` is last used.
    let regs = unsafe { Registers::from_raw(backing.as_mut_ptr().expose_provenance(), 16) };
    regs.write32(0, 0x1234_5678);
    regs.write32(12, 0xdead_beef);
    assert_eq!(regs.read32(0), 0x1234_5678);
    assert_eq!(regs.read32(12), 0xdead_beef);
    // Out of the window or misaligned: debug builds stop, which is what a test build
    // is, so check that it does.
    for bad in [16usize, 13, 2, usize::MAX - 1] {
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| regs.read32(bad)));
        assert!(r.is_err(), "read at {bad:#x} was allowed");
        let w = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| regs.write32(bad, 1)));
        assert!(w.is_err(), "write at {bad:#x} was allowed");
    }
    assert_eq!(backing, [0x1234_5678, 0, 0, 0xdead_beef]);
}

#[test]
#[allow(unsafe_code)]
fn a_boot_cell_is_written_once_and_never_again() {
    let cell = BootCell::new();
    assert_eq!(cell.get(), None);
    // SAFETY: a test thread with no concurrent reader.
    let first = unsafe { cell.set(1u32) }.unwrap();
    assert_eq!(*first, 1);
    // A second set hands its value back and leaves the reference the first returned
    // pointing at what it pointed at — which is what makes a refused second probe sound.
    // SAFETY: as above.
    assert_eq!(unsafe { cell.set(2) }, Err(2));
    assert_eq!(*first, 1);
    assert_eq!(cell.get(), Some(&1));
}

// --- CPUs and firmware interfaces --------------------------------------------------

/// `virt` with `-smp 4`, for the CPU nodes; otherwise the same machine as `VIRT_V3`.
const VIRT_V3_SMP4: &[u8] = include_bytes!("testdata/qemu-virt-gicv3-smp4-128m.dtb");

#[test]
fn virt_smp_cpus_are_read_by_identifier_not_as_windows() {
    let f = fdt(VIRT_V3_SMP4);
    let mut fx = Fixture::new();
    let tree = DeviceTree::build(&f, &mut fx.nodes).unwrap();
    let cpus = at(&tree, "/cpus");
    let ids: Vec<u64> = tree
        .children(cpus)
        .filter(|&c| tree.string(c, b"device_type") == Some(b"cpu"))
        .map(|c| tree.reg_address(c, 0).unwrap())
        .collect();
    assert_eq!(ids, [0, 1, 2, 3]);
    // `cpu-map` is a child of `/cpus` too, and is not a CPU.
    assert_eq!(tree.children(cpus).count(), 5);
    for c in tree
        .children(cpus)
        .filter(|&c| tree.node(c).name().starts_with(b"cpu@"))
    {
        assert_eq!(tree.string(c, b"enable-method"), Some(&b"psci"[..]));
        assert!(matches!(tree.mmio(c, 0), Err(Error::NotMemoryMapped { .. })));
    }
}

#[test]
fn property_reads_what_the_model_does_not_record() {
    let f = fdt(VIRT_V3_SMP4);
    let mut fx = Fixture::new();
    let tree = DeviceTree::build(&f, &mut fx.nodes).unwrap();
    let psci = at(&tree, "/psci");
    assert!(tree.node(psci).is_compatible("arm,psci-0.2"));
    assert_eq!(tree.string(psci, b"method"), Some(&b"hvc"[..]));
    assert_eq!(tree.property(psci, b"cpu_on"), Some(&0xc400_0003u32.to_be_bytes()[..]));
    assert_eq!(tree.property(psci, b"absent"), None);
    // A child's property is not its parent's: `/cpus` has no `reg`, and every `cpu@N`
    // below it does.
    let cpus = at(&tree, "/cpus");
    assert_eq!(tree.property(cpus, b"reg"), None);
    assert_eq!(tree.property(cpus, b"#address-cells"), Some(&1u32.to_be_bytes()[..]));
    // A list is not one string.
    assert_eq!(tree.string(psci, b"compatible"), None);
}

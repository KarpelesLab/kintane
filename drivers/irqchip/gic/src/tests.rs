//! Host tests: specifier translation, binding against QEMU's own trees, and the GICv2
//! register sequence over plain memory.

use device::driver::{self, best_match};
use device::{DeviceTree, Driver, IrqClaim, MmioClaim, Node, Registers, Resources};
use hal::{IrqChip, IrqNumber};

use super::spec::Error;
use super::*;

const VIRT_V3: &[u8] =
    include_bytes!("../../../../kernel/device/src/testdata/qemu-virt-gicv3-128m.dtb");
const VIRT_V2: &[u8] =
    include_bytes!("../../../../kernel/device/src/testdata/qemu-virt-gicv2-128m.dtb");

#[test]
fn specifiers_are_offset_by_type() {
    // The virt timer's non-secure physical PPI, and the UART's SPI.
    assert_eq!(translate(&[1, 14, 4]), Ok(IrqNumber(30)));
    assert_eq!(translate(&[0, 1, 4]), Ok(IrqNumber(33)));
    assert_eq!(translate(&[1, 0, 4]), Ok(IrqNumber(16)));
    assert_eq!(translate(&[0, 987, 4]), Ok(IrqNumber(1019)));
    // A zero partition cell is no partition.
    assert_eq!(translate(&[1, 14, 4, 0]), Ok(IrqNumber(30)));
}

#[test]
fn specifiers_that_name_nothing() {
    assert_eq!(translate(&[1, 14]), Err(Error::TooShort));
    assert_eq!(translate(&[2, 0, 4]), Err(Error::UnknownType(2)));
    assert_eq!(
        translate(&[1, 16, 4]),
        Err(Error::OutOfRange {
            kind: 1,
            number: 16
        })
    );
    assert_eq!(
        translate(&[0, 988, 4]),
        Err(Error::OutOfRange {
            kind: 0,
            number: 988
        })
    );
    assert_eq!(translate(&[1, 14, 4, 0x55]), Err(Error::Partitioned));
}

/// Every GIC driver this host can compile: both on aarch64, where the GICv3 CPU
/// interface's system registers exist, and GICv2 alone elsewhere.
#[cfg(target_arch = "aarch64")]
fn drivers() -> Vec<&'static dyn Driver> {
    vec![&v2::DRIVER, &v3::DRIVER]
}

#[cfg(not(target_arch = "aarch64"))]
fn drivers() -> Vec<&'static dyn Driver> {
    vec![&v2::DRIVER]
}

#[test]
fn each_virt_tree_binds_exactly_the_right_driver() {
    for (blob, want) in [(VIRT_V2, "GICv2"), (VIRT_V3, "GICv3")] {
        let f = device::Fdt::new(blob).unwrap();
        let mut nodes = vec![Node::EMPTY; 128];
        let tree = DeviceTree::build(&f, &mut nodes).unwrap();
        let drivers = drivers();
        let bound: Vec<&str> = tree
            .ids()
            .filter_map(|id| best_match(&tree, id, &drivers))
            .map(|(d, _)| drivers[d].name())
            .collect();
        if cfg!(target_arch = "aarch64") || want == "GICv2" {
            assert_eq!(bound, [want], "tree for {want}");
        } else {
            assert!(bound.is_empty(), "no GICv3 driver off aarch64");
        }
    }
}

#[test]
fn the_timer_ppi_the_tree_names_is_the_one_the_arch_uses() {
    let f = device::Fdt::new(VIRT_V3).unwrap();
    let mut nodes = vec![Node::EMPTY; 128];
    let tree = DeviceTree::build(&f, &mut nodes).unwrap();
    let timer = tree.find(b"/timer").unwrap();
    // Entry 1 is the EL1 non-secure physical timer, which is what arch/aarch64 arms.
    let spec = tree.interrupt(timer, 1).unwrap();
    assert_eq!(translate(spec.cells()), Ok(IrqNumber(30)));
}

#[test]
fn v2_claims_its_two_windows_from_reg() {
    let f = device::Fdt::new(VIRT_V2).unwrap();
    let mut nodes = vec![Node::EMPTY; 128];
    let tree = DeviceTree::build(&f, &mut nodes).unwrap();
    let mut mmio: Vec<Option<MmioClaim>> = vec![None; 8];
    let mut irqs: Vec<Option<IrqClaim>> = vec![None; 8];
    let mut res = Resources::new(&mut mmio, &mut irqs);
    let gic = tree.find(b"/intc@8000000").unwrap();
    // The driver statics are process-wide, and this is the only test that probes the v2
    // driver, so the first probe here is the first probe anywhere.
    let bound = driver::probe(&v2::DRIVER, &tree, gic, &mut res).unwrap();
    let windows: Vec<(u64, u64, &str)> =
        res.mmio_claims().map(|c| (c.phys, c.len, c.what)).collect();
    assert_eq!(
        windows,
        [
            (0x0800_0000, 0x1_0000, "GIC distributor"),
            (0x0801_0000, 0x1_0000, "GICv2 CPU interface")
        ]
    );
    // A second GICv2 is refused, and its failed probe leaves the first one's claims.
    assert!(driver::probe(&v2::DRIVER, &tree, gic, &mut res).is_err());
    assert_eq!(res.mmio_claims().count(), 2);
    let _ = bound;
}

/// Plain memory standing in for a register window. Every access, the driver's and the
/// test's, goes through one raw pointer, so the test's own reads and writes cannot
/// invalidate the pointer the driver was given.
struct Window {
    ptr: *mut u32,
    _buf: Box<[u32]>,
}

#[allow(unsafe_code)]
impl Window {
    fn new(bytes: usize) -> Window {
        let mut buf = vec![0u32; bytes / 4].into_boxed_slice();
        Window {
            ptr: buf.as_mut_ptr(),
            _buf: buf,
        }
    }
    fn get(&self, offset: usize) -> u32 {
        // SAFETY: tests only name offsets inside the buffer.
        unsafe { self.ptr.add(offset / 4).read() }
    }
    fn set(&self, offset: usize, v: u32) {
        // SAFETY: as `get`.
        unsafe { self.ptr.add(offset / 4).write(v) }
    }
    fn registers(&self) -> Registers {
        // SAFETY: the buffer lives as long as `self`, which outlives every use in a test.
        unsafe { Registers::from_raw(self.ptr.expose_provenance(), self._buf.len() * 4) }
    }
}

#[test]
#[allow(unsafe_code)]
fn v2_init_programs_the_distributor_and_cpu_interface() {
    let dist = Window::new(0x1000);
    let cpu = Window::new(0x100);
    // 96 interrupt lines: ITLinesNumber = 2.
    dist.set(GICD_TYPER, 2);
    let chip = v2::over(dist.registers(), cpu.registers());
    // SAFETY: plain memory; nothing can be delivered.
    unsafe { chip.init() };
    chip.enable(IrqNumber(33));
    chip.disable(IrqNumber(64));
    cpu.set(0x0C, 1023);
    assert_eq!(chip.claim(), None, "1023 is the spurious ID");
    cpu.set(0x0C, (3 << 10) | 30);
    assert_eq!(chip.claim(), Some(IrqNumber(30)), "the SGI source CPU field is not the ID");
    chip.eoi(IrqNumber(30));

    assert_eq!(dist.get(GICD_CTLR), 1, "distributor enabled last");
    // Three words of 96 lines cleared...
    for w in 0..3 {
        assert_eq!(dist.get(GICD_ICPENDR + w * 4), 0xffff_ffff);
    }
    // ...and no fourth, which would be past what TYPER reported.
    assert_eq!(dist.get(GICD_ICPENDR + 12), 0);
    assert_eq!(dist.get(GICD_IPRIORITYR + 92), DEFAULT_PRIORITY_WORD);
    assert_eq!(dist.get(GICD_IPRIORITYR + 96), 0);
    assert_eq!(dist.get(GICD_ISENABLER + 4), 1 << 1, "ID 33 is bit 1 of word 1");
    assert_eq!(dist.get(GICD_ICENABLER + 8), 1, "ID 64 is bit 0 of word 2");
    assert_eq!(cpu.get(0x04), 0xff, "priority mask open");
    assert_eq!(cpu.get(0x00), 1, "CPU interface enabled");
    assert_eq!(cpu.get(0x10), 30, "EOI names the claimed ID");
}

#[test]
#[allow(unsafe_code)]
fn v2_sgis_keep_their_sender_until_eoi() {
    let dist = Window::new(0x1000);
    let cpu = Window::new(0x100);
    let chip = v2::over(dist.registers(), cpu.registers());
    // SGI 1 from CPU interface 2.
    cpu.set(0x0C, (2 << 10) | 1);
    let claimed = chip.claim().unwrap();
    assert_eq!(claimed, IrqNumber((2 << 10) | 1), "the sender is part of the claim");
    assert_eq!(chip.id(claimed), IrqNumber(1), "and not part of which interrupt it is");
    chip.eoi(claimed);
    assert_eq!(cpu.get(0x10), (2 << 10) | 1, "EOIR takes IAR's value back, sender included");
}

#[test]
#[allow(unsafe_code)]
fn v2_ipis_route_by_the_interface_bit_each_cpu_reads() {
    let dist = Window::new(0x1000);
    let cpu = Window::new(0x100);
    let chip = v2::over(dist.registers(), cpu.registers());
    // What CPU interface 3 reads from its banked ITARGETSR0.
    dist.set(0x800, 0x0808_0808);
    // SAFETY: plain memory.
    let token = unsafe { chip.init_cpu() };
    assert_eq!(token, Some(0x08));
    assert_eq!(cpu.get(0x00), 1, "the banked CPU interface is enabled");
    assert_eq!(dist.get(GICD_IPRIORITYR + 28), DEFAULT_PRIORITY_WORD, "banked PPI priorities");
    chip.send_ipi(IrqNumber(1), 0x08);
    assert_eq!(dist.get(0xF00), (0x08 << 16) | 1, "GICD_SGIR: target list, then the ID");

    // A uniprocessor GICv2 reads its targets as zero and has nowhere to send an IPI.
    dist.set(0x800, 0);
    // SAFETY: plain memory.
    assert_eq!(unsafe { chip.init_cpu() }, None);
}

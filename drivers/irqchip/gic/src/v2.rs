//! GICv2: a memory-mapped distributor plus a memory-mapped per-CPU interface.

#![allow(unsafe_code)]

use device::{BootCell, Bound, Driver, Mmio, Probe, ProbeError, Registers};
use hal::{IrqChip, IrqNumber};

use crate::{
    DEFAULT_PRIORITY_WORD, FIRST_SPECIAL_IRQ, GICD_CTLR, GICD_ICENABLER, GICD_ICPENDR,
    GICD_IPRIORITYR, GICD_ISENABLER, interrupt_lines, word,
};

// CPU interface registers.
const GICC_CTLR: usize = 0x00;
const GICC_PMR: usize = 0x04;
const GICC_BPR: usize = 0x08;
const GICC_IAR: usize = 0x0C;
const GICC_EOIR: usize = 0x10;

/// The `compatible` strings driven with the GICv2 programming model.
///
/// `arm,cortex-a15-gic` is what QEMU's `virt` says; `arm,gic-400` is the standalone IP
/// most GICv2 boards use. The Cortex-A9 and A7 integrated GICs are the same model.
pub const COMPATIBLE: &[&str] = &[
    "arm,gic-400",
    "arm,cortex-a15-gic",
    "arm,cortex-a9-gic",
    "arm,cortex-a7-gic",
];

/// A GICv2, once its windows are known.
pub struct Gicv2 {
    gicd: Registers,
    gicc: Registers,
}

/// The driver. One instance per image; one controller per machine.
pub struct Gicv2Driver;

pub static DRIVER: Gicv2Driver = Gicv2Driver;

/// The windows probe claimed, kept for start.
static CLAIMS: BootCell<[Mmio; 2]> = BootCell::new();
/// The controller start brought up, for the interrupt path to hold.
static CHIP: BootCell<Gicv2> = BootCell::new();

/// The started controller, if this driver started one.
pub fn chip() -> Option<&'static dyn IrqChip> {
    CHIP.get().map(|c| c as &'static dyn IrqChip)
}

impl Driver for Gicv2Driver {
    fn name(&self) -> &'static str {
        "GICv2"
    }

    fn compatible(&self) -> &'static [&'static str] {
        COMPATIBLE
    }

    fn probe(&self, p: &mut Probe<'_, '_, '_, '_>) -> Result<(), ProbeError> {
        let gicd = p.claim_mmio(0, "GIC distributor")?;
        let gicc = p.claim_mmio(1, "GICv2 CPU interface")?;
        // SAFETY: probe runs during single-threaded boot, which is `BootCell::set`'s
        // whole contract.
        unsafe { CLAIMS.set([gicd, gicc]) }
            .map(|_| ())
            .map_err(|_| ProbeError::Declined("a GICv2 is already bound"))
    }

    fn start(&self, _bound: &Bound) -> Result<(), &'static str> {
        let [gicd, gicc] = CLAIMS.get().ok_or("started without a probe")?;
        // SAFETY: both windows were claimed by probe, and every claimed window is mapped
        // at its physical address: by the boot identity map until the kernel's own space
        // is installed, and by that space, which maps every claim, afterwards.
        let chip = unsafe {
            Gicv2 {
                gicd: Registers::new(gicd).ok_or("distributor above the address space")?,
                gicc: Registers::new(gicc).ok_or("CPU interface above the address space")?,
            }
        };
        // SAFETY: single-threaded boot, per `Driver::start`'s contract.
        let chip = unsafe { CHIP.set(chip) }.map_err(|_| "a GICv2 is already started")?;
        // SAFETY: `CHIP` was empty, so this is the first and only initialisation of this
        // controller; `Driver::start` runs with interrupts masked at the CPU.
        unsafe { chip.init() };
        Ok(())
    }
}

impl IrqChip for Gicv2 {
    unsafe fn init(&self) {
        // The bring-up sequence of IHI 0048B §4.3, in the order the specification
        // requires: the distributor must be disabled while its per-interrupt state is
        // rewritten, because an interrupt forwarded midway through would be delivered
        // under half-applied configuration. Loop bounds come from the controller's own
        // TYPER rather than from an assumption about the board.
        self.gicd.write32(GICD_CTLR, 0);

        let lines = interrupt_lines(&self.gicd);

        // Whatever firmware left enabled or pending is not ours. These registers are
        // write-1-to-act, so a full word is "all of them" and not a read-modify-write.
        for i in (0..lines).step_by(32) {
            self.gicd.write32(GICD_ICENABLER + word(i), 0xffff_ffff);
            self.gicd.write32(GICD_ICPENDR + word(i), 0xffff_ffff);
        }

        // Give everything a priority that passes the mask programmed below. The reset
        // value is IMPLEMENTATION DEFINED, so leaving it alone risks a source that is
        // enabled but can never preempt the mask.
        for i in (0..lines).step_by(4) {
            self.gicd
                .write32(GICD_IPRIORITYR + i as usize, DEFAULT_PRIORITY_WORD);
        }

        // QEMU's `virt` builds its GICv2 without the Security Extensions, so there is one
        // security state, `GICD_IGROUPR` is RAZ/WI, every interrupt is Group 0, and Group
        // 0 is signalled as IRQ. Bit 0 of CTLR is the single enable. A board that does
        // implement the extensions would need the group registers programmed here too.
        self.gicd.write32(GICD_CTLR, 1);

        // Lowest possible priority mask: nothing is filtered out. Only 5 bits are required
        // to be implemented, so this reads back as 0xf8 or similar; what matters is that
        // it is above DEFAULT_PRIORITY.
        self.gicc.write32(GICC_PMR, 0xff);
        // No priority grouping: the whole field is preemption priority.
        self.gicc.write32(GICC_BPR, 7);
        self.gicc.write32(GICC_CTLR, 1);
    }

    fn enable(&self, irq: IrqNumber) {
        // Write-1-to-set, so writing a single bit enables exactly that interrupt and leaves
        // the other 31 in the word alone — no read-modify-write, nothing to race.
        self.gicd
            .write32(GICD_ISENABLER + word(irq.0), 1 << (irq.0 % 32));
    }

    fn disable(&self, irq: IrqNumber) {
        self.gicd
            .write32(GICD_ICENABLER + word(irq.0), 1 << (irq.0 % 32));
    }

    fn claim(&self) -> Option<IrqNumber> {
        // Reading IAR is the acknowledge — the side effect the trait documents `claim` as
        // performing — so this is the only read of the register.
        let iar = self.gicc.read32(GICC_IAR);
        // Bits 12:10 are the source CPU for an SGI and bits 9:0 the ID. No SGIs are sent
        // yet, so the CPU field is discarded; it has to be carried back to EOIR once it
        // can be non-zero.
        let id = iar & 0x3ff;
        (id < FIRST_SPECIAL_IRQ).then_some(IrqNumber(id))
    }

    fn eoi(&self, irq: IrqNumber) {
        // Drops the running priority for the interrupt named. Writing an ID that was not
        // claimed is UNPREDICTABLE, so the trait's contract — that `irq` came from a
        // matching `claim` — is what keeps this defined.
        self.gicc.write32(GICC_EOIR, irq.0);
    }

    fn name(&self) -> &'static str {
        "GICv2"
    }
}

/// A GICv2 over test memory, so the register sequence can be checked on the host.
#[cfg(test)]
pub(crate) fn over(gicd: Registers, gicc: Registers) -> Gicv2 {
    Gicv2 { gicd, gicc }
}

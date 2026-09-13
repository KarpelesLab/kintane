//! GICv3: a memory-mapped distributor, a per-CPU redistributor, and a CPU interface
//! reached through system registers rather than MMIO.
//!
//! The only part of this unit selected by target architecture: `ICC_*_EL1` are AArch64
//! system registers, and there is no way to name them on anything else.

#![allow(unsafe_code)]

use device::{BootCell, Bound, Driver, Mmio, Probe, ProbeError, Registers};
use hal::{IrqChip, IrqNumber};

use crate::{
    DEFAULT_PRIORITY_WORD, FIRST_SPECIAL_IRQ, GICD_CTLR, GICD_ICENABLER, GICD_ICPENDR,
    GICD_IPRIORITYR, GICD_ISENABLER, interrupt_lines, word,
};

pub const COMPATIBLE: &[&str] = &["arm,gic-v3"];

/// Distributor group registers. RAZ/WI on the GICv2 `virt` builds without the Security
/// Extensions, so only this driver writes them.
const GICD_IGROUPR: usize = 0x0080;

// Redistributor, RD_base frame.
const GICR_WAKER: usize = 0x0014;
/// `GICR_WAKER.ProcessorSleep` — while set, the redistributor delivers nothing.
const GICR_WAKER_PROCESSOR_SLEEP: u32 = 1 << 1;
/// `GICR_WAKER.ChildrenAsleep` — hardware clears it once the wake has taken effect.
const GICR_WAKER_CHILDREN_ASLEEP: u32 = 1 << 2;

/// The SGI_base frame sits immediately after RD_base, 64 KiB in. It holds the per-CPU
/// configuration of SGIs and PPIs, which in GICv2 lived in banked copies of the
/// distributor's registers.
const GICR_SGI_FRAME: usize = 0x1_0000;
/// Both frames of one CPU's redistributor.
const GICR_FRAMES_LEN: usize = 0x2_0000;
const GICR_IGROUPR0: usize = 0x0080;
const GICR_ISENABLER0: usize = 0x0100;
const GICR_ICENABLER0: usize = 0x0180;
const GICR_ICPENDR0: usize = 0x0280;
const GICR_IPRIORITYR: usize = 0x0400;

/// `GICD_CTLR.ARE` with security disabled: affinity routing, which GICv3 requires.
const GICD_CTLR_ARE: u32 = 1 << 4;
const GICD_CTLR_ENABLE_GRP0: u32 = 1 << 0;
const GICD_CTLR_ENABLE_GRP1: u32 = 1 << 1;
/// `GICD_CTLR.RWP` — a register write is still propagating; poll until clear.
const GICD_CTLR_RWP: u32 = 1 << 31;

/// The first 32 IDs — SGIs and PPIs — are per-CPU and live in the redistributor, not the
/// distributor. Getting this wrong is the classic GICv3 porting bug: the write lands in a
/// valid distributor register, is ignored, and the interrupt simply never arrives.
const PPI_LIMIT: u32 = 32;

/// Polls of a propagating write before giving up. A controller that never clears the
/// bit is broken, and hanging here would look identical to hanging anywhere else.
const SPIN_LIMIT: u32 = 1_000_000;

pub struct Gicv3 {
    gicd: Registers,
    gicr: Registers,
}

pub struct Gicv3Driver;

pub static DRIVER: Gicv3Driver = Gicv3Driver;

static CLAIMS: BootCell<[Mmio; 2]> = BootCell::new();
static CHIP: BootCell<Gicv3> = BootCell::new();

/// The started controller, if this driver started one.
pub fn chip() -> Option<&'static dyn IrqChip> {
    CHIP.get().map(|c| c as &'static dyn IrqChip)
}

impl Driver for Gicv3Driver {
    fn name(&self) -> &'static str {
        "GICv3"
    }

    fn compatible(&self) -> &'static [&'static str] {
        COMPATIBLE
    }

    fn probe(&self, p: &mut Probe<'_, '_, '_, '_>) -> Result<(), ProbeError> {
        let gicd = p.claim_mmio(0, "GIC distributor")?;
        let gicr = p.claim_mmio(1, "GICv3 redistributors")?;
        if gicr.len() < GICR_FRAMES_LEN as u64 {
            return Err(ProbeError::Declined("redistributor region smaller than one CPU's frames"));
        }
        // SAFETY: probe runs during single-threaded boot.
        unsafe { CLAIMS.set([gicd, gicr]) }
            .map(|_| ())
            .map_err(|_| ProbeError::Declined("a GICv3 is already bound"))
    }

    fn start(&self, _bound: &Bound) -> Result<(), &'static str> {
        let [gicd, gicr] = CLAIMS.get().ok_or("started without a probe")?;
        // SAFETY: both windows were claimed by probe, and every claimed window is mapped
        // at its physical address, as in the v2 driver.
        let chip = unsafe {
            Gicv3 {
                gicd: Registers::new(gicd).ok_or("distributor above the address space")?,
                gicr: Registers::new(gicr).ok_or("redistributors above the address space")?,
            }
        };
        // SAFETY: single-threaded boot, per `Driver::start`'s contract.
        let chip = unsafe { CHIP.set(chip) }.map_err(|_| "a GICv3 is already started")?;
        // SAFETY: first and only initialisation, with interrupts masked at the CPU.
        unsafe { chip.init() };
        Ok(())
    }
}

impl Gicv3 {
    /// Wait for a distributor write affecting interrupt delivery to take effect.
    fn wait_rwp(&self) {
        let mut spins = 0u32;
        while self.gicd.read32(GICD_CTLR) & GICD_CTLR_RWP != 0 && spins < SPIN_LIMIT {
            spins += 1;
            core::hint::spin_loop();
        }
    }

    /// This CPU's SGI_base frame, as an offset into the redistributor window.
    fn sgi(&self, offset: usize) -> usize {
        GICR_SGI_FRAME + offset
    }
}

impl IrqChip for Gicv3 {
    unsafe fn init(&self) {
        // The bring-up sequence of IHI 0069 §12.9 and §12.11, in the order it mandates.
        // Three things make the ordering load-bearing rather than stylistic: ARE must be
        // set before the group and routing registers mean what this code assumes; the
        // redistributor must be woken before any of its per-CPU state is programmed; and
        // ICC_SRE_EL1.SRE must be set, with an `isb`, before any other ICC_* register is
        // architecturally accessible.
        self.gicd.write32(GICD_CTLR, 0);
        self.wait_rwp();

        let lines = interrupt_lines(&self.gicd);

        // SPIs only; IDs below 32 belong to the redistributor. Group 1 throughout: with
        // security disabled, Group 0 is delivered as FIQ, and this kernel takes IRQs.
        for i in (PPI_LIMIT..lines).step_by(32) {
            self.gicd.write32(GICD_ICENABLER + word(i), 0xffff_ffff);
            self.gicd.write32(GICD_ICPENDR + word(i), 0xffff_ffff);
            self.gicd.write32(GICD_IGROUPR + word(i), 0xffff_ffff);
        }
        for i in (PPI_LIMIT..lines).step_by(4) {
            self.gicd
                .write32(GICD_IPRIORITYR + i as usize, DEFAULT_PRIORITY_WORD);
        }

        self.gicd
            .write32(GICD_CTLR, GICD_CTLR_ARE | GICD_CTLR_ENABLE_GRP1 | GICD_CTLR_ENABLE_GRP0);
        self.wait_rwp();

        // Wake this CPU's redistributor. It comes out of reset asleep and forwards nothing
        // until ChildrenAsleep clears.
        let waker = self.gicr.read32(GICR_WAKER);
        self.gicr
            .write32(GICR_WAKER, waker & !GICR_WAKER_PROCESSOR_SLEEP);
        let mut spins = 0u32;
        while self.gicr.read32(GICR_WAKER) & GICR_WAKER_CHILDREN_ASLEEP != 0 && spins < SPIN_LIMIT {
            spins += 1;
            core::hint::spin_loop();
        }

        // Per-CPU SGI and PPI configuration, including the timer PPI.
        self.gicr.write32(self.sgi(GICR_ICENABLER0), 0xffff_ffff);
        self.gicr.write32(self.sgi(GICR_ICPENDR0), 0xffff_ffff);
        self.gicr.write32(self.sgi(GICR_IGROUPR0), 0xffff_ffff);
        for i in (0..32).step_by(4) {
            self.gicr
                .write32(self.sgi(GICR_IPRIORITYR + i), DEFAULT_PRIORITY_WORD);
        }

        // SAFETY: the caller guarantees interrupts are masked and that this is the only
        // initialisation. ICC_SRE_EL1.SRE selects the system-register interface over the
        // (absent) memory-mapped one; every ICC_* access after this is only
        // architecturally defined once it is set and an `isb` has retired. SRE is
        // write-once-then-RAO on an implementation with no memory-mapped interface, so
        // this is a read-modify-write rather than a plain store. This driver is only bound
        // to a node the tree calls a GICv3, which is what guarantees the CPU implements
        // these registers at all.
        unsafe {
            let mut sre: u64;
            core::arch::asm!("mrs {}, icc_sre_el1", out(reg) sre, options(nomem, nostack));
            sre |= 1;
            core::arch::asm!("msr icc_sre_el1, {}", "isb", in(reg) sre, options(nomem, nostack));

            // Priority mask wide open, no priority grouping, Group 1 enabled — the
            // system-register equivalents of the three GICC writes in the v2 driver.
            core::arch::asm!(
                "msr icc_pmr_el1, {pmr}",
                "msr icc_bpr1_el1, xzr",
                "msr icc_igrpen1_el1, {en}",
                "isb",
                pmr = in(reg) 0xffu64,
                en = in(reg) 1u64,
                options(nomem, nostack)
            );
        }
    }

    fn enable(&self, irq: IrqNumber) {
        if irq.0 < PPI_LIMIT {
            // Write-1-to-set on this CPU's redistributor, which `init` has woken.
            self.gicr.write32(self.sgi(GICR_ISENABLER0), 1 << irq.0);
        } else {
            self.gicd
                .write32(GICD_ISENABLER + word(irq.0), 1 << (irq.0 % 32));
        }
    }

    fn disable(&self, irq: IrqNumber) {
        if irq.0 < PPI_LIMIT {
            self.gicr.write32(self.sgi(GICR_ICENABLER0), 1 << irq.0);
        } else {
            self.gicd
                .write32(GICD_ICENABLER + word(irq.0), 1 << (irq.0 % 32));
        }
    }

    fn claim(&self) -> Option<IrqNumber> {
        let iar: u64;
        // SAFETY: reading ICC_IAR1_EL1 acknowledges the highest-priority pending Group 1
        // interrupt — the side effect the trait documents `claim` as having. The register
        // is accessible because `init` set ICC_SRE_EL1.SRE.
        unsafe { core::arch::asm!("mrs {}, icc_iar1_el1", out(reg) iar, options(nostack)) };
        // GICv3 widens the ID field to 24 bits to make room for LPIs.
        let id = (iar & 0xff_ffff) as u32;
        (id < FIRST_SPECIAL_IRQ).then_some(IrqNumber(id))
    }

    fn eoi(&self, irq: IrqNumber) {
        // SAFETY: ICC_EOIR1_EL1 drops the running priority for the interrupt named. With
        // ICC_CTLR_EL1.EOImode left at 0 it also deactivates it. The trait's contract —
        // that `irq` came from a matching `claim` — keeps the write defined.
        unsafe {
            core::arch::asm!("msr icc_eoir1_el1, {}", in(reg) irq.0 as u64, options(nostack));
        }
    }

    fn name(&self) -> &'static str {
        "GICv3"
    }
}

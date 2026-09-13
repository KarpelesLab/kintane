//! Arm Generic Interrupt Controller, v2 and v3, selected at run time.
//!
//! This module is the concrete case that `docs/portability.md` uses to justify the
//! whole static-architecture/dynamic-device split: one aarch64 image has to drive a
//! GICv2 on one board and a GICv3 on another. Both drivers are compiled into every
//! aarch64 image, both implement [`hal::IrqChip`], and which one runs is decided by
//! reading a register at boot. Nothing above this module knows there was a choice.
//!
//! # Telling them apart
//!
//! `GICD_PIDR2` carries the architecture revision in bits 7:4 — `0x2` for GICv2, `0x3`
//! for GICv3, `0x4` for GICv4. What it does *not* have is one address: the two
//! architectures put it in different places, because they give the distributor
//! different frame sizes.
//!
//! | | distributor frame | `GICD_PIDR2` |
//! |---|---|---|
//! | GICv2 (IHI 0048B §4.3.12) | 4 KiB | `0x0FE8` |
//! | GICv3 (IHI 0069 §12.9.21) | 64 KiB | `0xFFE8` |
//!
//! That is not a detail to paper over. Reading `0xFFE8` on a GICv2 is a read past the
//! end of the device: under QEMU it is an unassigned physical address and the load
//! takes an external abort (`ESR_EL1` = `0x96000010`), which was observed and is what
//! forced this ordering. So the probe reads the *v2* location first and only falls
//! through to the v3 one when that does not answer. `0x0FE8` is inside the GICv3 frame
//! and lies in a reserved, RES0 gap there, so the wrong-architecture read is defined
//! and returns zero rather than faulting. Linux's two drivers each read the offset for
//! their own architecture (`irq-gic.c` reads `0xFE8`, `irq-gic-v3.c` reads `0xFFE8`)
//! and rely on the device tree to say which to load; with no DTB parser yet, trying
//! them in the order that cannot fault is the equivalent.
//!
//! This is a weaker method than reading the device tree, and the difference matters on
//! real hardware rather than under QEMU:
//!
//! - PIDR2 identifies the *IP revision*, not the programming model in force. A GICv3
//!   configured with `GICD_CTLR.ARE == 0` is legitimately driven as a GICv2, and PIDR2
//!   still says 3.
//! - The distributor's address is hardcoded to `virt`'s, exactly as the PL011's is in
//!   `serial`. On any other board the probe reads whatever is at `0x08000000`.
//! - A board that puts nothing at that address at all, and does not abort the read,
//!   reads zero and is reported as having no GIC — which is right, but by luck.
//!
//! Reading the DTB `compatible` string is the correct answer and arrives with the
//! device framework in Phase 3.
//!
//! # What is deliberately not here
//!
//! No SGIs, no SPI affinity routing, no priority grouping, no LPIs or ITS. Phase 0
//! needs exactly one interrupt — the timer PPI — to prove the path is live.
//!
//! # Where this belongs
//!
//! In `drivers/irqchip/`, per `docs/architecture.md`. It cannot live there yet: that
//! is layer `device`, `arch` may not depend on `device`, and nothing else references
//! it, so a unit there would never be linked. It moves when the device framework can
//! register and find it, in Phase 3.
//!
//! References: Arm GIC Architecture Specification, GICv2 (IHI 0048B) §4.3 and §4.4;
//! GICv3/v4 (IHI 0069) §12.9 (distributor), §12.11 (redistributor), §12.3 (CPU
//! interface system registers).

use core::ptr::{read_volatile, write_volatile};
use hal::{IrqChip, IrqNumber};

/// The distributor, at the address QEMU's `virt` machine fixes it at.
///
/// Identical for both GIC versions on this machine, which is convenient but not a
/// coincidence: the distributor is the part whose placement the board defines and
/// whose identification registers are architecturally common.
pub const GICD_BASE: usize = 0x0800_0000;

/// GICv2 CPU interface on `virt`. Has no counterpart in GICv3, where the CPU
/// interface is a set of system registers rather than a memory-mapped frame.
const GICC_BASE: usize = 0x0801_0000;

/// GICv3 redistributor frames on `virt`, one pair of 64 KiB frames per CPU.
const GICR_BASE: usize = 0x080A_0000;

// --- Distributor registers, common to both architectures where used here ----------

const GICD_CTLR: usize = 0x0000;
const GICD_TYPER: usize = 0x0004;
const GICD_IGROUPR: usize = 0x0080;
const GICD_ISENABLER: usize = 0x0100;
const GICD_ICENABLER: usize = 0x0180;
const GICD_ICPENDR: usize = 0x0280;
const GICD_IPRIORITYR: usize = 0x0400;

/// Peripheral ID 2 as GICv2 places it, at the top of a 4 KiB distributor frame.
/// Reserved and RES0 at the same offset in a GICv3 distributor, which is what makes it
/// safe to read first.
const GICD_PIDR2_V2: usize = 0x0FE8;
/// Peripheral ID 2 as GICv3 places it, at the top of a 64 KiB distributor frame. Past
/// the end of a GICv2 distributor, so this read can abort — see the module comment.
const GICD_PIDR2_V3: usize = 0xFFE8;
/// Architecture revision, `GICD_PIDR2` bits 7:4.
const PIDR2_ARCH_SHIFT: u32 = 4;
const PIDR2_ARCH_MASK: u32 = 0xf;

/// Priority given to every interrupt. Any value numerically below the priority mask
/// programmed into the CPU interface will do; the middle of the range leaves room to
/// add both more and less urgent sources later without renumbering.
const DEFAULT_PRIORITY: u32 = 0x80;
/// Four interrupts share one `IPRIORITYR` word, each a byte.
const DEFAULT_PRIORITY_WORD: u32 = DEFAULT_PRIORITY * 0x0101_0101;

/// Interrupt IDs 1020..=1023 are reserved: 1023 means "no pending interrupt", the rest
/// report a claim that could not be made. None of them is a real source.
const FIRST_SPECIAL_IRQ: u32 = 1020;

/// # Safety
/// `addr` must be the address of a mapped, naturally aligned 32-bit device register,
/// and the write must be one the device tolerates in its current state.
unsafe fn write32(addr: usize, value: u32) {
    // SAFETY: the boot identity map covers the whole first GiB as Device-nGnRnE, so
    // the constant address is the device itself and the mapping neither caches nor
    // reorders the access. Volatile is what stops the *compiler* merging, reordering
    // or eliding accesses the device distinguishes — every GIC register here is one
    // where that matters.
    unsafe { write_volatile(addr as *mut u32, value) };
}

/// # Safety
/// `addr` must be the address of a mapped, naturally aligned 32-bit device register
/// whose read has no side effect the caller is not expecting. `GICC_IAR` and
/// `ICC_IAR1_EL1` do have one — they acknowledge — which is why claiming is spelled out
/// at each call site rather than hidden here.
unsafe fn read32(addr: usize) -> u32 {
    // SAFETY: as above — a mapped, naturally aligned device register.
    unsafe { read_volatile(addr as *const u32) }
}

/// Number of interrupt IDs the distributor implements, from `GICD_TYPER.ITLinesNumber`.
///
/// # Safety
/// `gicd` must be a mapped GIC distributor.
unsafe fn interrupt_lines(gicd: usize) -> u32 {
    // ITLinesNumber is `(lines / 32) - 1`, and is capped at 1020 real IDs.
    // SAFETY: reading TYPER has no side effects.
    let typer = unsafe { read32(gicd + GICD_TYPER) };
    let lines = ((typer & 0x1f) + 1) * 32;
    if lines > FIRST_SPECIAL_IRQ { FIRST_SPECIAL_IRQ } else { lines }
}

// ---------------------------------------------------------------------------------
// GICv2
// ---------------------------------------------------------------------------------

/// GICv2: a memory-mapped distributor plus a memory-mapped per-CPU interface.
pub struct Gicv2 {
    gicd: usize,
    gicc: usize,
}

// GICv2 CPU interface registers.
const GICC_CTLR: usize = 0x00;
const GICC_PMR: usize = 0x04;
const GICC_BPR: usize = 0x08;
const GICC_IAR: usize = 0x0C;
const GICC_EOIR: usize = 0x10;

impl IrqChip for Gicv2 {
    unsafe fn init(&self) {
        // SAFETY: the bring-up sequence of IHI 0048B §4.3, in the order the
        // specification requires: the distributor must be disabled while its
        // per-interrupt state is rewritten, because an interrupt forwarded midway
        // through would be delivered under half-applied configuration. Every address
        // below is a register of the distributor or CPU interface this struct names,
        // both of which the caller has guaranteed are mapped, and the loop bounds come
        // from the controller's own TYPER rather than from an assumption about the
        // board. The caller has also guaranteed interrupts are masked, so nothing can
        // be delivered between the writes.
        unsafe {
            write32(self.gicd + GICD_CTLR, 0);

            let lines = interrupt_lines(self.gicd);

            // Whatever firmware left enabled or pending is not ours. Clearing is
            // per-32-interrupt; these registers are write-1-to-act, so a full word is
            // "all of them" and not a read-modify-write.
            let mut i = 0;
            while i < lines {
                let word = (i / 32) as usize * 4;
                write32(self.gicd + GICD_ICENABLER + word, 0xffff_ffff);
                write32(self.gicd + GICD_ICPENDR + word, 0xffff_ffff);
                i += 32;
            }

            // Give everything a priority that passes the mask programmed below. The
            // reset value is IMPLEMENTATION DEFINED, so leaving it alone risks a
            // source that is enabled but can never preempt the mask.
            let mut i = 0;
            while i < lines {
                write32(self.gicd + GICD_IPRIORITYR + i as usize, DEFAULT_PRIORITY_WORD);
                i += 4;
            }

            // QEMU's `virt` builds its GICv2 without the Security Extensions, so there
            // is one security state, `GICD_IGROUPR` is RAZ/WI, every interrupt is
            // Group 0, and Group 0 is signalled as IRQ. Bit 0 of CTLR is the single
            // enable. A board that *does* implement the extensions would need the
            // group registers programmed here as well.
            write32(self.gicd + GICD_CTLR, 1);

            // Lowest possible priority mask: nothing is filtered out. Only 5 bits are
            // required to be implemented, so this reads back as 0xf8 or similar; what
            // matters is that it is above DEFAULT_PRIORITY.
            write32(self.gicc + GICC_PMR, 0xff);
            // No priority grouping: the whole field is preemption priority. Phase 0 has
            // one interrupt, so this only sets a defensible default.
            write32(self.gicc + GICC_BPR, 7);
            write32(self.gicc + GICC_CTLR, 1);
        }
    }

    fn enable(&self, irq: IrqNumber) {
        let word = (irq.0 / 32) as usize * 4;
        // SAFETY: ISENABLER is write-1-to-set, so writing a single bit enables exactly
        // that interrupt and leaves the other 31 in the word alone — no read-modify-
        // write, and therefore nothing to race against. An out-of-range ID lands in a
        // reserved word of the same 4 KiB frame, where writes are ignored.
        unsafe { write32(self.gicd + GICD_ISENABLER + word, 1 << (irq.0 % 32)) };
    }

    fn disable(&self, irq: IrqNumber) {
        let word = (irq.0 / 32) as usize * 4;
        // SAFETY: as `enable`, on the write-1-to-clear counterpart.
        unsafe { write32(self.gicd + GICD_ICENABLER + word, 1 << (irq.0 % 32)) };
    }

    fn claim(&self) -> Option<IrqNumber> {
        // SAFETY: reading IAR is the acknowledge — that side effect is the entire
        // point of the call, and the trait documents `claim` as performing it. It must
        // happen exactly once per delivered interrupt, which is why this is the only
        // read of the register.
        let iar = unsafe { read32(self.gicc + GICC_IAR) };
        // Bits 12:10 are the source CPU for an SGI and bits 9:0 the ID. Phase 0 sends
        // no SGIs, so the CPU field is discarded here; it has to be carried back to
        // EOIR once it can be non-zero.
        let id = iar & 0x3ff;
        if id >= FIRST_SPECIAL_IRQ { None } else { Some(IrqNumber(id)) }
    }

    fn eoi(&self, irq: IrqNumber) {
        // SAFETY: EOIR is write-only and its effect is to drop the running priority
        // for the interrupt named. Writing an ID that was not claimed is UNPREDICTABLE,
        // so the contract on the trait — that `irq` came from a matching `claim` — is
        // what makes this sound.
        unsafe { write32(self.gicc + GICC_EOIR, irq.0) };
    }

    fn name(&self) -> &'static str {
        "GICv2"
    }
}

// ---------------------------------------------------------------------------------
// GICv3
// ---------------------------------------------------------------------------------

/// GICv3: a memory-mapped distributor, a per-CPU redistributor, and a CPU interface
/// reached through system registers rather than MMIO.
pub struct Gicv3 {
    gicd: usize,
    gicr: usize,
}

// Redistributor, RD_base frame.
const GICR_WAKER: usize = 0x0014;
/// `GICR_WAKER.ProcessorSleep` — while set, the redistributor delivers nothing.
const GICR_WAKER_PROCESSOR_SLEEP: u32 = 1 << 1;
/// `GICR_WAKER.ChildrenAsleep` — hardware clears it once the wake has taken effect.
const GICR_WAKER_CHILDREN_ASLEEP: u32 = 1 << 2;

/// The SGI_base frame sits immediately after RD_base, 64 KiB in. It holds the
/// per-CPU configuration of SGIs and PPIs, which in GICv2 lived in banked copies of
/// the distributor's registers.
const GICR_SGI_FRAME: usize = 0x1_0000;
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

/// The first 32 IDs — SGIs and PPIs — are per-CPU and live in the redistributor, not
/// the distributor. Getting this wrong is the classic GICv3 porting bug: the write
/// lands in a valid distributor register, is ignored, and the interrupt simply never
/// arrives.
const PPI_LIMIT: u32 = 32;

impl Gicv3 {
    /// Wait for a distributor write affecting interrupt delivery to take effect.
    ///
    /// # Safety
    /// `gicd` must be a mapped GICv3 distributor.
    unsafe fn wait_rwp(gicd: usize) {
        // Bounded rather than infinite: a controller that never clears RWP is broken,
        // and hanging here would look identical to hanging anywhere else in boot.
        let mut spins = 0u32;
        // SAFETY: reading CTLR has no side effects.
        while unsafe { read32(gicd + GICD_CTLR) } & GICD_CTLR_RWP != 0 && spins < 1_000_000 {
            spins += 1;
            core::hint::spin_loop();
        }
    }

    fn sgi_base(&self) -> usize {
        self.gicr + GICR_SGI_FRAME
    }
}

impl IrqChip for Gicv3 {
    unsafe fn init(&self) {
        // SAFETY: the bring-up sequence of IHI 0069 §12.9 and §12.11, in the order it
        // mandates. Three things make the ordering load-bearing rather than stylistic:
        // ARE must be set before the group and routing registers mean what this code
        // assumes; the redistributor must be woken before any of its per-CPU state is
        // programmed; and ICC_SRE_EL1.SRE must be set, with an `isb`, before any other
        // ICC_* register is architecturally accessible. The caller has guaranteed the
        // controller is mapped, that this runs once, and that interrupts are masked.
        unsafe {
            // Distributor off while its state is rewritten, then wait for the write to
            // land — in GICv3 that is not immediate and RWP is how it is observed.
            write32(self.gicd + GICD_CTLR, 0);
            Self::wait_rwp(self.gicd);

            let lines = interrupt_lines(self.gicd);

            // SPIs only; IDs below 32 belong to the redistributor and are handled
            // below. Group 1 throughout: with security disabled, Group 0 is delivered
            // as FIQ, and this kernel takes IRQs.
            let mut i = PPI_LIMIT;
            while i < lines {
                let word = (i / 32) as usize * 4;
                write32(self.gicd + GICD_ICENABLER + word, 0xffff_ffff);
                write32(self.gicd + GICD_ICPENDR + word, 0xffff_ffff);
                write32(self.gicd + GICD_IGROUPR + word, 0xffff_ffff);
                i += 32;
            }
            let mut i = PPI_LIMIT;
            while i < lines {
                write32(self.gicd + GICD_IPRIORITYR + i as usize, DEFAULT_PRIORITY_WORD);
                i += 4;
            }

            write32(
                self.gicd + GICD_CTLR,
                GICD_CTLR_ARE | GICD_CTLR_ENABLE_GRP1 | GICD_CTLR_ENABLE_GRP0,
            );
            Self::wait_rwp(self.gicd);

            // Wake this CPU's redistributor. It comes out of reset asleep and forwards
            // nothing until ChildrenAsleep clears.
            let waker = read32(self.gicr + GICR_WAKER);
            write32(self.gicr + GICR_WAKER, waker & !GICR_WAKER_PROCESSOR_SLEEP);
            let mut spins = 0u32;
            while read32(self.gicr + GICR_WAKER) & GICR_WAKER_CHILDREN_ASLEEP != 0
                && spins < 1_000_000
            {
                spins += 1;
                core::hint::spin_loop();
            }

            // Per-CPU SGI and PPI configuration, including the timer PPI.
            let sgi = self.sgi_base();
            write32(sgi + GICR_ICENABLER0, 0xffff_ffff);
            write32(sgi + GICR_ICPENDR0, 0xffff_ffff);
            write32(sgi + GICR_IGROUPR0, 0xffff_ffff);
            let mut i = 0usize;
            while i < 32 {
                write32(sgi + GICR_IPRIORITYR + i, DEFAULT_PRIORITY_WORD);
                i += 4;
            }

            // The CPU interface. ICC_SRE_EL1.SRE selects the system-register interface
            // over the (absent) memory-mapped one; every ICC_* access after this is
            // only architecturally defined once it is set and an `isb` has retired.
            // SRE is write-once-then-RAO on an implementation with no memory-mapped
            // interface, so this is a read-modify-write rather than a plain store.
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
            // SAFETY: write-1-to-set on this CPU's redistributor, which `init` has
            // already woken. Only the named bit changes.
            unsafe { write32(self.sgi_base() + GICR_ISENABLER0, 1 << irq.0) };
        } else {
            let word = (irq.0 / 32) as usize * 4;
            // SAFETY: write-1-to-set in the distributor, as in the v2 driver.
            unsafe { write32(self.gicd + GICD_ISENABLER + word, 1 << (irq.0 % 32)) };
        }
    }

    fn disable(&self, irq: IrqNumber) {
        if irq.0 < PPI_LIMIT {
            // SAFETY: write-1-to-clear counterpart of `enable`.
            unsafe { write32(self.sgi_base() + GICR_ICENABLER0, 1 << irq.0) };
        } else {
            let word = (irq.0 / 32) as usize * 4;
            // SAFETY: as above, in the distributor.
            unsafe { write32(self.gicd + GICD_ICENABLER + word, 1 << (irq.0 % 32)) };
        }
    }

    fn claim(&self) -> Option<IrqNumber> {
        let iar: u64;
        // SAFETY: reading ICC_IAR1_EL1 acknowledges the highest-priority pending
        // Group 1 interrupt — the side effect the trait documents `claim` as having.
        // The register is accessible because `init` set ICC_SRE_EL1.SRE; this driver
        // is only ever selected when the probe found a GICv3, which is what guarantees
        // the CPU implements these registers at all.
        unsafe { core::arch::asm!("mrs {}, icc_iar1_el1", out(reg) iar, options(nostack)) };
        // GICv3 widens the ID field to 24 bits to make room for LPIs.
        let id = (iar & 0xff_ffff) as u32;
        if id >= FIRST_SPECIAL_IRQ { None } else { Some(IrqNumber(id)) }
    }

    fn eoi(&self, irq: IrqNumber) {
        // SAFETY: ICC_EOIR1_EL1 drops the running priority for the interrupt named.
        // With ICC_CTLR_EL1.EOImode left at 0 it also deactivates it, which is what
        // this kernel wants. The trait's contract — that `irq` came from a matching
        // `claim` — is what keeps the write defined.
        unsafe {
            core::arch::asm!("msr icc_eoir1_el1, {}", in(reg) irq.0 as u64, options(nostack));
        }
    }

    fn name(&self) -> &'static str {
        "GICv3"
    }
}

// ---------------------------------------------------------------------------------
// Selection
// ---------------------------------------------------------------------------------

/// The v2 driver, bound to the addresses QEMU's `virt` machine uses.
static GICV2: Gicv2 = Gicv2 { gicd: GICD_BASE, gicc: GICC_BASE };

/// The v3 driver, likewise. Both are constructed unconditionally; only one is ever
/// initialised, and which one is not known until [`detect`] has run.
static GICV3: Gicv3 = Gicv3 { gicd: GICD_BASE, gicr: GICR_BASE };

/// Identify the interrupt controller at `gicd` and return a driver for it.
///
/// The v2 location is read first and the v3 location only if it does not answer; see
/// the module comment for why that order is not interchangeable.
///
/// Returns `None` when neither location holds a revision either driver speaks, which
/// includes the all-zeroes read from an address with no device behind it.
///
/// # Safety
/// `gicd` must be an address it is safe to read a word from — either a GIC distributor
/// or at least a mapping where a stray read cannot disturb something else. The boot
/// map is an identity one, so this remains a statement about the board's memory map
/// rather than about the page tables.
pub unsafe fn detect(gicd: usize) -> Option<&'static dyn IrqChip> {
    // SAFETY: PIDR2 is a read-only identification register; reading it has no side
    // effects and depends on no prior configuration, which is exactly why it can be
    // read before knowing what is there. This offset is within the 4 KiB every GIC
    // distributor implements, so the read cannot run off the end of the device.
    let v2 = unsafe { read32(gicd + GICD_PIDR2_V2) };
    if (v2 >> PIDR2_ARCH_SHIFT) & PIDR2_ARCH_MASK == 0x2 {
        return Some(&GICV2);
    }

    // Not a GICv2, so the device is at least 64 KiB wide if it is a GIC at all, and the
    // v3 identification register is inside it.
    // SAFETY: as above.
    let v3 = unsafe { read32(gicd + GICD_PIDR2_V3) };
    match (v3 >> PIDR2_ARCH_SHIFT) & PIDR2_ARCH_MASK {
        // GICv4 adds direct injection of virtual interrupts and is otherwise a GICv3
        // as far as a physical-only driver is concerned.
        0x3 | 0x4 => Some(&GICV3),
        _ => None,
    }
}

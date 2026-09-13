//! Arm Generic Interrupt Controller, v2 and v3, bound by device tree `compatible`.
//!
//! The concrete case `docs/portability.md` uses for the static-architecture/dynamic-
//! device split: one aarch64 image drives a GICv2 on one board and a GICv3 on another.
//! Both drivers are in every image; which one binds is decided by the tree.
//!
//! # Telling them apart
//!
//! By `compatible`, which is what the tree is for. The two bindings name different
//! programming models — `arm,cortex-a15-gic` and `arm,gic-400` are driven as a GICv2,
//! `arm,gic-v3` as a GICv3 — and that is the right question to ask. The previous
//! driver, written before there was a tree to read, read `GICD_PIDR2` instead, which
//! reports the *IP revision*: a GICv3 run with affinity routing disabled is legitimately
//! programmed as a GICv2 and still says 3. It also had to read the v2 offset first and
//! fall through to the v3 one, because `0xFFE8` is past the end of a GICv2 distributor
//! and the read takes an external abort. None of that is needed when the firmware says
//! what the controller is.
//!
//! # Addresses
//!
//! From `reg`, through the device model's claims: the distributor is entry 0 for both;
//! entry 1 is the GICv2 CPU interface or the GICv3 redistributor region. Every window
//! the driver claims is mapped by the kernel address space, and nothing else is.
//!
//! # What is deliberately not here
//!
//! No SGIs, no SPI affinity routing, no priority grouping, no LPIs or ITS, and one
//! redistributor — CPU 0's, at the start of the region, which is where a uniprocessor
//! `virt` machine puts it. Finding each CPU's frame by `GICR_TYPER` affinity arrives with
//! secondary CPUs.
//!
//! References: Arm GIC Architecture Specification, GICv2 (IHI 0048B) §4.3 and §4.4;
//! GICv3/v4 (IHI 0069) §12.9 (distributor), §12.11 (redistributor), §12.3 (CPU
//! interface system registers); Linux `Documentation/devicetree/bindings/interrupt-
//! controller/arm,gic.yaml` and `arm,gic-v3.yaml`.

#![cfg_attr(not(test), no_std)]
#![deny(unsafe_code)]

pub mod spec;
pub mod v2;
#[cfg(target_arch = "aarch64")]
pub mod v3;

pub use spec::translate;

/// Priority given to every interrupt. Any value numerically below the priority mask
/// programmed into the CPU interface will do; the middle of the range leaves room to
/// add both more and less urgent sources later without renumbering.
const DEFAULT_PRIORITY: u32 = 0x80;
/// Four interrupts share one `IPRIORITYR` word, each a byte.
const DEFAULT_PRIORITY_WORD: u32 = DEFAULT_PRIORITY * 0x0101_0101;

/// Interrupt IDs 1020..=1023 are reserved: 1023 means "no pending interrupt", the rest
/// report a claim that could not be made. None of them is a real source.
const FIRST_SPECIAL_IRQ: u32 = 1020;

// Distributor registers, common to both architectures where used here.
const GICD_CTLR: usize = 0x0000;
const GICD_TYPER: usize = 0x0004;
const GICD_ISENABLER: usize = 0x0100;
const GICD_ICENABLER: usize = 0x0180;
const GICD_ICPENDR: usize = 0x0280;
const GICD_IPRIORITYR: usize = 0x0400;

/// Number of interrupt IDs the distributor implements, from `GICD_TYPER.ITLinesNumber`.
fn interrupt_lines(gicd: &device::Registers) -> u32 {
    // ITLinesNumber is `(lines / 32) - 1`, and is capped at 1020 real IDs.
    let typer = gicd.read32(GICD_TYPER);
    (((typer & 0x1f) + 1) * 32).min(FIRST_SPECIAL_IRQ)
}

/// The byte offset of the 32-bit bitmap word holding `irq` in a one-bit-per-interrupt
/// register array.
fn word(irq: u32) -> usize {
    (irq / 32) as usize * 4
}

#[cfg(test)]
mod tests;

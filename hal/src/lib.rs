//! Hardware abstraction traits — the contract, and nothing else.
//!
//! This crate contains no code and no state: only trait definitions. That is what
//! lets it compile for every target including the host, which is what makes
//! host-side testing of the upper layers possible (see `docs/testing.md`).
//!
//! `Arch` covers only what *every* target has. Anything else is a separate
//! capability trait an architecture opts into, so that code needing a capability
//! states it in its signature and simply does not exist on targets that lack it.
//! See `docs/portability.md` — this is the central idea of the project.

#![cfg_attr(not(test), no_std)]

pub mod addr;

// Mock architectures for host-side testing. Gated at the module boundary, which is
// the only place cfg is allowed, and off in every kernel image.
#[cfg(CONFIG_MOCK_ARCH)]
pub mod mock;

pub use addr::{AddrOverflow, KernAddr, PhysAddr, UserAddr};

/// Byte order of the target.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Endian {
    Little,
    Big,
}

/// What every target has, without exception.
pub trait Arch: Sized + 'static {
    const NAME: &'static str;
    const PAGE_SIZE: usize;
    const PHYS_ADDR_BITS: u8;
    const ENDIAN: Endian;
    /// Whether unaligned loads and stores are permitted by the hardware.
    const UNALIGNED_ACCESS: bool;

    /// Opaque saved interrupt-enable state.
    type IrqState: Copy;

    fn irq_save() -> Self::IrqState;

    /// # Safety
    /// `state` must have come from a matching [`Arch::irq_save`] on this CPU, and
    /// must not be restored twice.
    unsafe fn irq_restore(state: Self::IrqState);

    /// Full barrier. Stronger than most call sites need; narrower barriers arrive
    /// with the memory model in Phase 3.
    fn memory_barrier();

    /// Stop this CPU permanently.
    fn halt() -> !;
}

/// The target has a hardware MMU with page tables.
#[diagnostic::on_unimplemented(
    message = "`{Self}` has no MMU, so this code cannot exist on it",
    label = "requires address translation",
    note = "use the mm::flat interface, which is what no-MMU targets build instead"
)]
pub trait HasMmu: Arch {
    /// Number of page table levels.
    const LEVELS: u8;
    /// Page sizes larger than [`Arch::PAGE_SIZE`] that the hardware supports.
    const HUGE_PAGE_SIZES: &'static [usize];
}

/// The target has a memory protection unit but no address translation.
#[diagnostic::on_unimplemented(
    message = "`{Self}` has no MPU",
    label = "requires hardware memory protection regions"
)]
pub trait HasMpu: Arch {
    const REGIONS: usize;
}

/// The target can execute more than one hardware thread.
#[diagnostic::on_unimplemented(
    message = "`{Self}` is single-processor, so this code cannot exist on it",
    label = "requires more than one CPU",
    note = "per-CPU data and IPIs are dead weight on a uniprocessor build"
)]
pub trait HasSmp: Arch {
    fn cpu_id() -> u32;
}

/// The target has atomic compare-and-swap at machine word width.
///
/// ARMv6-M and RISC-V `rv32i` without the `A` extension do not. Code requiring
/// lock-free data structures carries this bound; everything else uses a lock whose
/// implementation is selected by this same capability.
#[diagnostic::on_unimplemented(
    message = "`{Self}` has no atomic compare-and-swap",
    label = "requires CAS",
    note = "lock-free structures are not offered on this target; use a lock"
)]
pub trait HasCas: Arch {}

/// DMA-capable devices see coherent memory; no manual cache maintenance is needed.
///
/// Absence of this is the bug class QEMU cannot find, because QEMU's memory is
/// always coherent. See `docs/testing.md#what-qemu-will-not-catch`.
pub trait HasCoherentDma: Arch {}

/// Floating-point or SIMD state that must be saved across context switches.
pub trait HasFpu: Arch {
    type FpuState: Default;
}

/// An interrupt number as the interrupt controller numbers them.
///
/// Not a global identifier: two controllers on the same machine may both have an
/// IRQ 5. Mapping a device's line to a controller is the device framework's job.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct IrqNumber(pub u32);

/// An interrupt controller.
///
/// Object-safe and dispatched through `dyn`, unlike the architecture traits above.
/// This is the deliberate seam described in `docs/portability.md`: **the architecture
/// layer is generic, the device layer is dynamic.** One aarch64 image must drive a
/// GICv2 on one board and a GICv3 on another, discovered at runtime from a device
/// tree, and that cannot be a type parameter.
///
/// Builds that cannot afford a vtable in the interrupt path pin a single provider in
/// the configuration, and kbuild emits a type alias instead.
pub trait IrqChip: Sync {
    /// Prepare the controller. Called once, before any interrupt is enabled.
    ///
    /// # Safety
    /// Must be called once per controller, with interrupts masked.
    unsafe fn init(&self);

    fn enable(&self, irq: IrqNumber);
    fn disable(&self, irq: IrqNumber);

    /// Acknowledge and return the interrupt now being serviced, if any.
    fn claim(&self) -> Option<IrqNumber>;

    /// Signal end-of-interrupt for a previously claimed interrupt.
    fn eoi(&self, irq: IrqNumber);

    /// Name for diagnostics, e.g. "GICv3".
    fn name(&self) -> &'static str;
}

/// A console usable before the device framework exists.
///
/// Object-safe on purpose: which console a machine has is a runtime question even
/// this early, and the cost of a virtual call on a panic path is irrelevant.
pub trait EarlyConsole: Sync {
    fn write_bytes(&self, bytes: &[u8]);

    fn write_str(&self, s: &str) {
        self.write_bytes(s.as_bytes());
    }
}

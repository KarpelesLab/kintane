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
pub mod clock;
pub mod context;
pub mod fault;
pub mod ipi;
pub mod paging;
pub mod timer;
pub mod user;

// Mock architectures for host-side testing. Gated at the module boundary, which is
// the only place cfg is allowed, and off in every kernel image.
#[cfg(CONFIG_MOCK_ARCH)]
pub mod mock;

pub use addr::{AddrOverflow, KernAddr, PhysAddr, UserAddr};
pub use clock::ClockSource;
pub use context::{HasContextSwitch, ThreadEntry};
pub use fault::{Access, PageFault, PageFaultHook};
pub use ipi::{HasIpi, Ipi};
pub use paging::{HasPageTables, ImageSections, MapError, PageFlags, PageTableEntry, StackArray};
pub use timer::EventTimer;
pub use user::{CopyFault, HasUserMode, SyscallFrame, UserHooks, UserTrap};

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

    /// The logical number of the CPU this code is running on: dense, 0 for the CPU the
    /// machine booted on, and below [`HasSmp::MAX_CPUS`] on a port that has it.
    ///
    /// On `Arch` rather than on [`HasSmp`] because code that must work on every machine
    /// needs to ask it: lock-order checking keeps what each CPU holds apart, and it runs
    /// under every lock type, uniprocessor ones included. A port that runs one CPU keeps
    /// this default. A port that starts a second **must** override it, and its
    /// [`HasSmp::cpu_id`] must return the same number. Nothing can make the compiler
    /// check that, so each SMP port's bring-up checks it on every CPU instead.
    ///
    /// Answers for the instant it is read. Code that uses the answer to reach per-CPU
    /// state must not migrate in between, which is what `sync::percpu::Pinned` is for.
    fn cpu_index() -> usize {
        0
    }
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
    /// The most CPUs this port can bring up. Every [`HasSmp::cpu_id`] it returns is
    /// below this, so per-CPU storage with this many slots never misses.
    const MAX_CPUS: usize;

    /// The running CPU's logical number: the same value as [`Arch::cpu_index`].
    ///
    /// Not a hardware identifier. An aarch64 MPIDR or an x86 APIC ID is sparse, and
    /// arrays are not; the port maps one to the other when it brings a CPU up.
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
///
/// The kernel itself never names a floating-point register — every port builds
/// `+soft-float`, and `arch/aarch64/src/context.rs` asserts at compile time that nothing
/// in the image can — so this state is entirely a *user* program's. That is why it is the
/// whole user-visible set rather than the ABI's callee-saved subset: the kernel is not a
/// caller that saved anything, it is a different address space borrowing the registers.
///
/// A port that implements this stores the state inside its own
/// [`HasContextSwitch::Context`](crate::HasContextSwitch::Context) and saves it in its own
/// switch. Nothing above the architecture layer names `FpuState`, so a port whose hardware
/// has no such state leaves it `()` and costs nothing.
///
/// `Default` must produce a state a restore will accept. That is not the same as zero: an
/// all-zero x86 `FXSAVE` image has `MXCSR = 0`, which unmasks every floating-point
/// exception, so the first user multiply that underflows traps. See `X86_64::FpuState`.
///
/// # The live registers, which are not the context's
///
/// [`save_live`](HasFpu::save_live) and [`load_live`](HasFpu::load_live) move the state of the
/// *running CPU*, not of a stored [`Context`](crate::HasContextSwitch::Context). A signal frame
/// needs exactly that and cannot use the switch: at delivery the interrupted thread's registers
/// are live, and at `rt_sigreturn` the bytes to put back come from the program's own stack.
///
/// A switch between the two is harmless in both directions, which is worth spelling out because
/// it is the reason this is sound at all. After `save_live` the live registers still hold the
/// interrupted values, so a switch saves and restores them as it always did. After `load_live`
/// they hold what the frame asked for, and a switch carries *those*. Neither leaves the frame's
/// copy and the thread's copy disagreeing.
///
/// Both work in bytes rather than in `Self::FpuState` because their caller holds the frame's
/// bytes inside a plain array with no alignment guarantee, while `FXSAVE` and `stp q` fault on
/// a misaligned address. A port copies through an aligned local of its own, so alignment stays
/// the architecture's business and never reaches the code that lays frames out.
pub trait HasFpu: Arch {
    type FpuState: Default;

    /// Bytes of the image the two calls below move. A caller that lays this state out in a
    /// structure of its own checks its offsets against this at compile time rather than
    /// writing the number down a second time.
    const FPU_BYTES: usize;

    /// Write the running CPU's user-visible floating-point state into `out`.
    ///
    /// # Panics
    /// If `out` is shorter than [`FPU_BYTES`](HasFpu::FPU_BYTES).
    fn save_live(out: &mut [u8]);

    /// Load `bytes` into the running CPU's user-visible floating-point registers.
    ///
    /// Every byte is a value some register may legally hold, so there is nothing here to
    /// validate: the control words this writes are masked by the port to the bits a program
    /// may set, and a program can reach the same states with its own instructions anyway.
    ///
    /// # Panics
    /// If `bytes` is shorter than [`FPU_BYTES`](HasFpu::FPU_BYTES).
    fn load_live(bytes: &[u8]);
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

    /// Prepare the part of the controller that belongs to the calling CPU, on that CPU:
    /// a GICv3 redistributor and CPU interface, a GICv2's banked registers.
    ///
    /// Returns the token [`IrqChip::send_ipi`] routes to this CPU with, which only the
    /// controller knows how to form (an affinity value on a GICv3, a CPU interface bitmask
    /// on a GICv2), or `None` when this controller cannot direct an interrupt at one CPU.
    /// It leaves alone the enables of interrupts already enabled on this CPU, so calling it
    /// on the CPU [`IrqChip::init`] already prepared is harmless.
    ///
    /// The default is a controller with no per-CPU part and no IPIs, which is every
    /// uniprocessor one.
    ///
    /// # Safety
    /// On the CPU being prepared, with its interrupts masked, after [`IrqChip::init`].
    unsafe fn init_cpu(&self) -> Option<u64> {
        None
    }

    /// Raise inter-processor interrupt `irq` on the CPU whose [`IrqChip::init_cpu`]
    /// returned `target`. Does nothing on a controller with no IPIs.
    fn send_ipi(&self, irq: IrqNumber, target: u64) {
        let _ = (irq, target);
    }

    /// The interrupt that a value [`IrqChip::claim`] returned names, without whatever the
    /// controller attached to it. A GICv2 reports an SGI's sender above the ID, and
    /// [`IrqChip::eoi`] must be given the value with the sender still in it. This is the
    /// part that says which interrupt it was.
    fn id(&self, claimed: IrqNumber) -> IrqNumber {
        claimed
    }
}

/// An architecture with exactly one hardware thread, where masking interrupts is
/// mutual exclusion.
///
/// This is the bound on `sync::IrqLock`, and it exists because `IrqLock` on a
/// multiprocessor is silent corruption rather than a slow lock.
///
/// # Why this is not simply `A: !HasSmp`
///
/// Because Rust has no negative bounds, and the ways to fake one are all worse:
///
/// - `feature(negative_bounds)` exists on nightly, and this is a nightly kernel. It is also marked
///   incomplete, it does not propagate reliably through generic code, and it is not on the
///   permitted-features list in `toolchain.toml`. Adding it there would rest a soundness argument
///   on a feature that may behave differently after the next toolchain bump, and a guarantee that
///   can quietly stop holding is worse than one that is honest about being an assertion.
/// - Two overlapping blanket impls (one over [`HasSmp`], one over this trait) are rejected by
///   coherence outright — E0119 is raised because the impls *could* overlap, not because any type
///   actually satisfies both, so this expresses nothing.
/// - Autoref specialisation can ask "does `A` implement `HasSmp`?" at run time. A run-time answer
///   to a question the whole unit exists to settle at compile time is a step backwards, and the
///   only thing it could do with the answer is halt.
///
/// # The trade this makes
///
/// What the bound does buy, and it is not nothing: the default is closed. An
/// architecture that implements only `Arch` — which is every architecture in the tree
/// today — cannot instantiate an `IrqLock` at all. Reaching one requires writing
/// `unsafe impl UniProcessor for …`, which is an explicit, `unsafe`, greppable,
/// reviewable act carrying the contract below, rather than a `#define` that nobody
/// reads. The remaining hole is an architecture that asserts this *and* implements
/// `HasSmp`; the compiler will not catch that, and no construction available to us
/// would.
///
/// # Where the impls live
///
/// Here, in `hal`, and that placement is load-bearing rather than tidy. The trait was
/// first written in `kernel/sync` beside its only user, and that turned out to make it
/// unimplementable by any real architecture: the orphan rule requires an impl for
/// `arch_armv7m`'s type to live in either that crate or the trait's, and kbuild's
/// `layer_violation` rule forbids an `arch` unit from depending on a `core` unit. The
/// only impl that could exist was for a mock. A capability claim has to live where the
/// capability traits live.
///
/// # Safety
///
/// Implementing this is a claim that **no code compiled against `Self` will ever run
/// on more than one hardware thread**, so that masking interrupts on the running CPU
/// leaves no other agent able to touch memory. Specifically:
///
/// - The architecture has one CPU, or the kernel never releases the others from reset.
/// - `Self` does not implement [`HasSmp`], and never will. Adding `HasSmp` to a type that
///   implements this trait must be accompanied by removing this impl; the compiler will not remind
///   you.
/// - No DMA-capable device writes memory that an `IrqLock` protects. Masking interrupts does not
///   stop a bus master, which is the same argument one level down.
///
/// Breaking any of these makes every `sync::IrqLock` in the image a no-op that still
/// type-checks.
#[diagnostic::on_unimplemented(
    message = "`{Self}` has not asserted that it is a uniprocessor",
    label = "masking interrupts is only mutual exclusion on a machine with one CPU",
    note = "use sync::SpinLock (requires hal::HasCas) on anything that might be SMP"
)]
pub unsafe trait UniProcessor: Arch {}

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

# Portability Without the Preprocessor

This is the document that defines KinTane. Everything else follows from it.

## The problem

A kernel that spans microcontrollers and servers has to cope with hardware that
differs in ways that are not merely quantitative:

- **Some targets have no MMU.** Virtual memory is not "disabled", it is absent. There
  is no page table to configure.
- **Some targets have no atomic compare-and-swap.** ARMv6-M and RISC-V `rv32i`
  without the `A` extension cannot implement a lock-free queue. Mutual exclusion must
  fall back to disabling interrupts.
- **Some targets have no cache coherency with DMA devices.** Buffers must be flushed
  and invalidated by hand around every transfer, or must not be, and doing the wrong
  one is silent corruption.
- **Some targets have no hardware floating point**, or have it but must not use it in
  kernel context, or must save it lazily per task.
- **Address widths differ from pointer widths.** 32-bit x86 with PAE has 36-bit
  physical addresses behind 32-bit pointers.
- **Some targets are single-core by construction.** Per-CPU data, IPIs, and memory
  barriers are dead weight.

C kernels handle this with `#ifdef CONFIG_MMU`, `#ifdef CONFIG_SMP`,
`#ifdef ARCH_HAS_DMA_COHERENT`, and arch-specific header shadowing. The cost is
well known: code paths that no one compiles rot; the set of valid configurations is
unknowable; a change that compiles on x86_64 breaks four other architectures; and the
logic of a function is interleaved with the question of which machine it is running
on.

## The approach

**Hardware capabilities are traits. Code that needs a capability is generic over it.
Code that cannot run on a machine does not compile for that machine, and the compiler
proves it.**

### The base trait

Every architecture implements `Arch`, which covers only what *every* target has.

```rust
pub trait Arch: Sized + 'static {
    const NAME: &'static str;
    const PAGE_SIZE: usize;
    const PHYS_ADDR_BITS: u8;
    const ENDIAN: Endian;
    const UNALIGNED_ACCESS: bool;

    /// Machine word. usize on most targets, but kept explicit because
    /// pointer width and register width are not always the same thing.
    type Word: Word;
    type PhysAddr: PhysAddr;

    /// Opaque saved interrupt-enable state.
    type IrqState: Copy;

    fn irq_save() -> Self::IrqState;
    /// # Safety
    /// `state` must have come from a matching `irq_save` on this CPU.
    unsafe fn irq_restore(state: Self::IrqState);

    fn memory_barrier();
    fn halt() -> !;
}
```

### Capability traits

Anything not universal is a separate trait an architecture opts into:

```rust
/// The target has a hardware MMU with page tables.
pub trait HasMmu: Arch {
    type PageTable: PageTable<Self>;
    type AddressSpace: AddressSpace<Self>;
    const LEVELS: u8;
    const HUGE_PAGE_SIZES: &'static [usize];
}

/// The target has a memory protection unit but no translation.
pub trait HasMpu: Arch {
    const REGIONS: usize;
    type Region: MpuRegion;
}

/// The target can execute more than one hardware thread.
pub trait HasSmp: Arch {
    const MAX_CPUS: usize;
    fn cpu_id() -> CpuId;
    fn send_ipi(target: CpuId, ipi: Ipi);
}

/// The target has atomic compare-and-swap at machine word width.
pub trait HasCas: Arch {}

/// DMA-capable devices see coherent memory; no manual cache maintenance.
pub trait HasCoherentDma: Arch {}

/// Floating-point / SIMD state that must be saved across context switches.
pub trait HasFpu: Arch {
    type FpuState: Default;
    unsafe fn fpu_save(into: &mut Self::FpuState);
    unsafe fn fpu_restore(from: &Self::FpuState);
}
```

A Cortex-M0+ port implements `Arch` and `HasMpu`. An x86_64 port implements `Arch`,
`HasMmu`, `HasSmp`, `HasCas`, `HasCoherentDma`, and `HasFpu`. Neither carries any
notion of the other.

### Consequences

Code states its hardware requirements in its signature:

```rust
/// Maps a range into a user address space.
/// Exists only for architectures with an MMU.
pub fn map_user_range<A: Arch + HasMmu>(
    space: &mut A::AddressSpace,
    at: UserAddr,
    phys: A::PhysAddr,
    len: usize,
    prot: Prot,
) -> Result<(), MapError> { /* ... */ }
```

On a Cortex-M build this function is not `#ifdef`-ed away. It is never instantiated,
because no type in that build satisfies `Arch + HasMmu`. There is no dead branch, no
stub, and no possibility of calling it by accident — the call site would fail to type
check.

The same mechanism removes whole classes of configuration bug:

```rust
/// A spinlock implemented with CAS.
pub struct CasLock<A: Arch + HasCas> { /* ... */ }

/// A critical section implemented by disabling interrupts.
/// Correct only when there is exactly one CPU.
pub struct IrqLock<A: Arch> { /* ... */ }
```

`IrqLock` used on an SMP machine would be a serious bug. We encode that: the SMP
kernel's lock type is `CasLock`, selected by the memory-model layer, and a
uniprocessor-only build selects `IrqLock`. The choice is made once, in one place,
against a trait bound, rather than as an `#ifdef CONFIG_SMP` inside every lock
acquisition.

## Where `cfg` is still allowed

Monomorphization cannot do everything. We do use `cfg`, under one rule:

> **`cfg` selects which modules and crates enter the build. It does not appear inside
> a function body, and it does not appear inside a type's fields.**

So this is fine — the config picks an implementation of a subsystem:

```rust
// kernel/src/mm/mod.rs
#[cfg(kintane_mm = "paged")]
mod paged;
#[cfg(kintane_mm = "paged")]
pub use paged::*;

#[cfg(kintane_mm = "flat")]
mod flat;
#[cfg(kintane_mm = "flat")]
pub use flat::*;
```

and this is not:

```rust
fn schedule(&mut self) {
    #[cfg(kintane_smp)]
    self.steal_from_other_cpus();     // forbidden
    // ...
}
```

The second form is what produces unbuildable configurations. The lint that enforces
this is described in [coding-standards.md](coding-standards.md).

`kbuild` generates the `--cfg` flags from the resolved configuration; they are never
written by hand and never come from environment probing.

## Static architecture, dynamic devices

There is a real tension here worth stating plainly.

**Architecture is static.** One kernel image targets one architecture. Making the
`Arch` implementation a compile-time type parameter costs nothing and buys full
monomorphization: an `A::PAGE_SIZE` is a constant, a page-table walk is inlined, and
the optimizer sees through all of it.

**Devices are dynamic.** A single aarch64 image must drive a GICv2 on one board and a
GICv3 on another, discovered from a device tree at runtime. That cannot be a type
parameter. Device drivers are therefore behind object-safe traits and dispatched
through `dyn`:

```rust
pub trait IrqChip: Send + Sync {
    fn enable(&self, irq: IrqNumber);
    fn disable(&self, irq: IrqNumber);
    fn eoi(&self, irq: IrqNumber);
    fn claim(&self) -> Option<IrqNumber>;
}
```

The split is deliberate: **the architecture layer is generic, the device layer is
dynamic**, and the boundary between them is the one place where a virtual call
appears in a hot path.

### Buying the indirection back on small targets

For embedded builds that cannot afford a vtable in the interrupt path, the config may
pin a subsystem to exactly one implementation. When it does, `kbuild` emits a type
alias instead of a trait object:

```rust
// generated by kbuild from CONFIG_IRQCHIP=nvic (single-provider mode)
pub type SystemIrqChip = crate::drivers::irqchip::nvic::Nvic;
```

The subsystem is written once against the trait. On a server it is reached through
`dyn IrqChip`; on a Cortex-M it is a direct, inlinable static call. No source
differences, no duplicate implementation. This is the main reason the build system is
allowed to generate Rust source at all — see
[build-system.md](build-system.md#generated-sources).

## What this costs

Honesty about the downsides, so they are not discovered later:

- **Trait bounds propagate.** A function calling `map_user_range` must itself carry
  `A: Arch + HasMmu`. Bounds accumulate up the call graph and can become noisy.
  Mitigation: group capabilities into aliases (`trait FullMmuArch: Arch + HasMmu +
  HasSmp + HasCas {}` with a blanket impl) at subsystem boundaries.
- **Compile time and code size.** Monomorphization duplicates code per instantiation.
  Since exactly one `Arch` is instantiated per image, the duplication factor is one —
  this cost is mostly theoretical for us, but it returns if we ever generify over a
  second axis.
- **Error messages.** A missing capability surfaces as an unsatisfied trait bound,
  which is less obvious than a missing `#define`. Mitigation: `#[diagnostic::on_unimplemented]`
  messages on every capability trait, e.g. *"this code requires an MMU; target
  `armv7m-none` has none — use the `mm::flat` interface instead."*
- **Some things genuinely are per-arch code.** Context switch, exception entry,
  early boot. These live in `arch/<name>/` and are `cfg`-selected at crate level.
  We are not pretending assembly is portable.

## Test of the thesis

### What has actually been demonstrated

Phase 1 put both halves of the split under test rather than leaving them as argument.

**The dynamic half.** One aarch64 kernel image — the same binary, confirmed by md5
rather than by looking at it — boots and takes timer interrupts under `gic-version=2`
and `gic-version=3`, and also under the machine default, `gic-version=max`,
`gic-version=4` with virtualization enabled, and on `cortex-a53` and `cortex-a57`.
The GIC driver is chosen at runtime from the hardware's own ID register, behind
`dyn IrqChip`. This is the case the type system genuinely cannot handle, and it works.

**The static half.** x86_64, i686 and aarch64 boot from one unmodified `kernel/main`,
with paging depth (4, 3 and 4 levels), page size and physical address width all read
from the architecture's associated constants. The frame allocator is written once,
generic over `A: Arch`, and its tests run against two mock profiles with different
page sizes.

**A cost worth recording.** The rule that adding an architecture touches nothing
outside `arch/`, `targets/` and `config/` holds — but only after a one-time change
that the rule itself did not predict. The kernel image had to stop naming a specific
architecture crate, which meant the build system had to let several units *provide*
one name and let the configuration select among them. The rule was true for the third
architecture and not for the second, and that distinction is the kind of thing a
roadmap tends to lose.

### Keeping it true

The claim is only credible if it is checked continuously. The rule:

> Every merge builds every tier-1 target. Adding a target must not require touching
> any file outside `arch/`, `drivers/`, and the configuration.

Phase 1 of the [roadmap](roadmap.md) exists specifically to prove this with a second
architecture before any significant subsystem is written, and Phase 4 proves it in
the opposite direction by scaling down to a target with no MMU and 64 KiB of RAM.

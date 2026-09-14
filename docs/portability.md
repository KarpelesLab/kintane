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

### Where a bound is not enough

The claim above, that code for a missing capability "is never instantiated", is
true, and it was once read as more than it says. Never instantiated is not the same
as never compiled. Rust type-checks a generic body where it is *defined*, against the
target's own `core`. So this does not build for an rv32i core, even though nothing
implements `HasCas` there and nothing calls `try_lock`:

```rust
pub fn try_lock<A: Arch + HasCas>(flag: &AtomicU32) -> bool {
    flag.compare_exchange(0, 1, Acquire, Relaxed).is_ok()
    // error[E0599]: no method named `compare_exchange` found
}
```

A bound can rule out a *caller*. It cannot remove a body that names something the
target does not have. The line falls here:

- **Methods of our own traits** are fine behind a bound. `A::map_page` exists on every
  target as a trait item, so a body that calls it type-checks everywhere and is only
  unusable where no `A` satisfies the bound. That covers the MMU example above and
  almost every capability.
- **Items the compiler provides only on some targets** need `cfg`. The case that
  matters today is atomics: `compare_exchange` and `fetch_add` do not exist without
  CAS, and `AtomicU64` does not exist without 64-bit atomics. Those items are gated
  with `#[cfg(target_has_atomic = "8" | "32" | "64")]`. That is the compiler's own
  knowledge of the target, so it cannot disagree with it.

This is still within the `cfg` rule below, which is why it is a correction and not a
new exception. The gate goes on a whole item: `CasGate`, `SpinLock`, `Refcount`,
`ObjectIds`. The bound stays as well, because it says the same thing to readers and
to callers. Code that merely *creates* objects takes `impl kobject::IdSource` instead
of `&ObjectIds`, so it does not inherit a 64-bit atomic from the allocator it happens
to use.

This went unnoticed through two phases because nothing could show it. The host has
every atomic, so `MockTiny` — a machine with no CAS — compiles against a `core` that
has CAS. The code `sync`, `kobject` and `ipc` had then did not build for either
no-MMU tier-1 target: rv32imac fails on `AtomicU64` alone. `kbuild portability` now
compiles every host-testable unit, with warnings denied, for `riscv32i` (no atomics),
`riscv32imac` (no 64-bit atomics) and `thumbv7m`. It fails if the gating is removed
from either of two items, which was checked by removing it.

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
The GIC driver is chosen at runtime behind `dyn IrqChip`. This is the case the type
system genuinely cannot handle, and it works.

It was first chosen from the hardware's own ID register, `GICD_PIDR2`, which reports
the IP revision rather than the programming model in force. Since the device model
landed it is chosen by the device tree's `compatible` string, as the drivers in
`drivers/irqchip/` are bound. The same image was re-run on every variant above, plus
Cortex-A53 on GICv2 and Cortex-A57 on GICv3, and passed all of them. It also fails
visibly, rather than hanging, when booted with a tree that names the wrong controller.

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

### The other extreme: riscv32

The fourth architecture was the first without an MMU: rv32imac in machine mode, which
implements `Arch`, `HasCas`, `UniProcessor` and a context switch, and nothing else. The
same `kernel/main` boots on it and runs everything that does not need translation:

- the memory map, the frame allocator and the kernel heap;
- interrupts, the context switch and preemption;
- sleep, the tickless idle and lock-order checking;
- all 35 in-kernel checks and crash decoding.

The MMU checks report Skipped. The claim was that code needing a capability simply is not
in an image without it. For the kernel's subsystems that held with no change: every one
of them already compiled for rv32imac, which `kbuild portability` had been checking since
Phase 2.

The rule about which files an architecture may touch did **not** hold, and the files are
worth listing, because each is a different kind of miss.

- **`kernel/main` assumed an MMU (the expected one).** The banner, the kernel address
  space, demand paging and three test modes named `HasMmu`, `HasPageTables` and arch
  functions no flat port has. They moved unchanged into `model_paged.rs`, and
  `model_flat.rs` answers the same calls. The choice between them is made once, at module
  level on `MM_PAGED`/`MM_FLAT`. A one-time cost, like the provider units were for the
  second architecture. Every existing preset's banner is identical before and after,
  apart from numbers.
- **`kernel/main` used `AtomicU64` (the portability check could not see it).** The image
  crate is not host-tested, so `kbuild portability` never compiled it. rv32imac has no
  64-bit atomics, so `kernel/main` now names `crate::AtomicU64`: the real one where the
  target has it, otherwise `sync::IrqU64`, a masked-interrupt counter with the same
  methods that only a `UniProcessor` can use. The hardware-independent units needed
  nothing, and the one unit that was never checked did.
- **Latent bugs in shared code.**
  - `boot/info-fdt` refused a device tree ending above `isize::MAX`, a requirement it
    read into `slice::from_raw_parts` that the function does not have. On a 64-bit port
    it could never trigger. On a 32-bit machine whose RAM starts at 2 GiB it turned every
    tree into "no loader".
  - `lib/unwind`'s frame layout had unsigned offsets, so the RISC-V record, which sits
    below the frame pointer, could not be described at all.
- **Selection and plumbing, not code.**
  - `info-fdt` and `info-none` gained `ARCH_RISCV32` in their `requires` lines.
  - `kbuild/src/qemu.rs` gained the machine.
  - CI's guard-page loops skip presets without `MM_PAGED`.

  All of that is configuration in everything but location.

The port also found a mistake that would have been easy to copy into every future one.
Its `irq_restore` was written like aarch64's, with `options(nomem)`. That tells the
optimiser the instruction touches no memory, yet unmasking lets a handler run that
writes the tick counter. The clock check's wait loop had its counter read hoisted out,
and it waited out its whole timeout for an interrupt it had already taken. The asm that
unmasks interrupts on this port no longer claims `nomem`. The aarch64 and x86 ports use
atomics for their counters and passed. They carry the same claim, and whether it can
bite them is not yet checked.

### The second small target: ARMv7-M

riscv32 left a question: were its misses the price of the first no-MMU port, or of every
port? ARMv7-M (a Cortex-M3 on `mps2-an385`, executing in place, with an MPU) was the
re-test. It passes the same list riscv32 does, plus MPU-enforced guards and W^X, and the
MMU checks report Skipped:

- the boot banner, the flat allocator, the kernel heap;
- interrupts, the context switch, preemption, sleep, tickless idle, lock order;
- all 35 in-kernel checks, and crash decoding by panic and by fault.

**`kernel/main`, `kernel/sched`, `kernel/thread`, `hal` and `lib/unwind` needed no change
at all.** The memory-model seam riscv32 paid for held. Thumb's frame record is aarch64's
at half the word size, which `unwind::Layout::frame_record(4)` already described. What
this port did touch outside `arch/`, `targets/` and `config/`:

- **A new `bootinfo` provider, and one line in another's selection.** `boot/info-board` is
  the build-time memory map (below). It is new, but `boot/info-none/kmod.toml`'s
  `requires` had to learn to step aside for it. That is the second port to edit that
  line. Providers that exclude each other by listing every other architecture make
  every new platform a change to the providers it does not use; they should be selected
  by a symbol each architecture's configuration sets instead.
- **The Arm run-time ABI, in `lib/builtins`.** LLVM calls `__aeabi_memclr4`, `__aeabi_memcpy`,
  `__aeabi_uldivmod` and, at opt-level `z`, `__aeabi_llsl` on 32-bit Arm, not the C names
  the crate provided. That is a cost of the architecture family, not of this port: an
  ARMv7-A port would link against the same new file. It also found a trap in the crate
  itself. Neither calling `memset` from `__aeabi_memclr` nor writing the loop out avoided
  a call to itself: LLVM lowered both to `__aeabi_memclr`, and the first zeroed array
  recursed until the stack ran out. The crate is now `#![no_builtins]`.
- **The symbolizer, in `kbuild/src/symbolize.rs`.** Return addresses into Thumb code carry
  the interworking bit, so "one byte before the return address" was the instruction
  after the call again. Every never-returning call in a panic's backtrace was attributed
  to the next function. The tool was wrong for every Thumb target, not this one.
- **Harness.** `kbuild/src/qemu_armv7m.rs` for the machine, and an `OPTIMIZE_FOR_SIZE`
  symbol kbuild maps to opt-level `z` for the size work.

So the rule held for kernel code and failed, again, for the parts of the build that
stand in for a toolchain's runtime and a debugger's conventions. Those are shared by
every port and had only been exercised on three instruction sets.

**Where the context-switch contract does not fit.** `HasContextSwitch::switch` is a
function call made wherever the scheduler runs, and every other port runs the
scheduler's hook inside the timer interrupt. On ARMv7-M, handler mode and the active
exception are core state that only an exception return restores. A switch made inside a
handler would resume the other thread still in handler mode, with interrupts of equal
priority blocked. The port does not change the trait. It uses PendSV to reach thread
mode: the timer's handler pends PendSV, PendSV builds a second exception frame that
returns to a trampoline, the trampoline runs the hook as a thread would, and a second
PendSV returns through the original frame. `arch/armv7m/src/preempt.rs` has the
details, including why a tick that lands during that return must not be dropped.

### Without compare-and-swap: rv32i

This chapter has claimed since Phase 1 that code needing a capability the target lacks is
absent from its image rather than stubbed. rv32i is the case the claim was written for:
the base RISC-V ISA, with no A extension and so no atomic instruction at all. The
`riscv32i-virt` preset builds the riscv32 port for it. It boots on QEMU's `rv32` hart with
the A extension switched off, and M and C with it, so an atomic, multiply, divide or
compressed instruction is illegal. That the hart refuses exactly what the image avoids was
checked, not assumed: the rv32imac image, which does use atomics, boots on the same hart
until `kheap::install` swaps an `AtomicBool`, and dies there on an illegal `amoor.w`. QEMU's
own `rv32i` model could not be used. It has no Zicsr either, and a machine-mode kernel
cannot run without CSRs: both images trap on their first instruction, `csrw mie, zero`.
The port implements `Arch`,
`UniProcessor` and a context switch, and not `HasCas`, and the kernel's lock family is
interrupt masking throughout. It passes the banner, the flat allocator and the heap,
preemption, sleep and the tickless idle, lock-order checking in its uniprocessor form,
both PMP stack-guard modes, crash decoding by panic, and the in-kernel suite with its four
atomic read-modify-write checks reported as skipped: 31 passed, 4 skipped.

**The hardware-independent units needed nothing.** `sync`, `kobject`, `ipc` and the rest
were gated on `target_has_atomic` in Phase 2, and `kbuild portability` has compiled them
for `riscv32i` ever since. Every miss was in code that check could not see:

- **`kernel/main`, again.** It named the spinlock family, a compare-and-swap `Once` and
  atomic counters directly. The capability seam riscv32 started now also chooses the lock
  family (`sync::Irq` where there is no compare-and-swap), the `Once`, and 32-bit,
  pointer-width and boolean counters, through new masked stand-ins `sync::IrqU32`,
  `IrqUsize` and `IrqBool` beside `IrqU64`. The choice is made once, at item level on
  `target_has_atomic`. The image crate is not host-tested, so `kbuild portability` now also
  builds the whole rv32i kernel image.
- **`kernel/selftest`.** Its atomics check is compiled only into test images, and the unit
  is not host-tested, so nothing had built it for such a core. It is now absent there, and
  its checks report as skipped under the names they have elsewhere.
- **The runtime library, in `lib/builtins`.** rv32i has no M extension either, so every
  `*`, `/` and `%` becomes a call: `__mulsi3`, `__muldi3`, `__udivsi3` and the rest, and
  the 64-bit shifts. The first link failed on `__muldi3`, from a multiply in the heap's
  statistics. It is the same class of debt ARMv7-M paid for the Arm run-time ABI.
- **A latent bug in `sync::IrqLock`.** No image had used interrupt masking as its kernel
  lock family before, so this code had never run under a timer. `IrqLock::lock` told
  lock-order checking it held the lock *before* it masked interrupts. A timer interrupt in
  that window ran a handler whose own acquisition of the heap lock looked like recursion,
  and the checker stops the CPU on recursion, silently. It hung the heap check in 4 boots
  of 5; with the stop turned into a panic, 4 boots of 5 panicked with that recursion.
  Masking first, as `SpinLock::lock_irqsave` already did, passed 8 boots of 8, and
  restoring only the old order hung again, in 1 boot of 5. The bug was not rv32i's: any
  uniprocessor that chose `Irq` would have hit it.

So the claim held where it had always been checked, in the hardware-independent units. It
failed only in code outside the check's reach, in one runtime library, and in one lock the
compare-and-swap ports never exercised.

### Keeping it true

The claim is only credible if it is checked continuously. The rule:

> Every merge builds every tier-1 target. Adding a target must not require touching
> any file outside `arch/`, `drivers/`, and the configuration.

Phase 1 of the [roadmap](roadmap.md) exists specifically to prove this with a second
architecture before any significant subsystem is written, and Phase 4 proves it in
the opposite direction by scaling down to a target with no MMU and 64 KiB of RAM.

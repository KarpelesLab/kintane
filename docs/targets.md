# Targets and Support Tiers

## Tier definitions

**Tier 1 — gated.** Builds and boots on every merge. A change that breaks a tier-1
target does not land. Every tier-1 target has a QEMU machine in CI from the start, and
real hardware someone can reach from Phase 7 — see
[testing.md](testing.md#the-hardware-debt) for what that ordering defers and when the
debt comes due.

**Tier 2 — built.** Compiled on every merge; booted nightly. Breakage is a bug with
an owner, not a merge blocker.

**Tier 3 — best effort.** Built when someone remembers. Contributed ports that have
not earned an owner or CI capacity. May be removed if they rot for two releases.

Promotion from tier 2 to tier 1 requires: a CI-reachable machine, a named
maintainer, and a full pass of the target test suite.

## Tier 1

The tier-1 set is chosen to stress the portability layer along every axis that
matters, not to chase popularity.

### `x86_64`

The reference target. UEFI boot, ACPI, APIC/x2APIC, SMP, IOMMU (VT-d/AMD-Vi), 4-level
and 5-level paging, huge pages. Implements every capability trait. QEMU `q35` in CI;
real hardware from Phase 7.

*Stresses:* SMP, NUMA, IOMMU-backed driver isolation, the full modern feature set.

### `aarch64`

Second architecture, and the one that proves the thesis. Device-tree and ACPI boot
paths, GICv2 and GICv3 selected at runtime, 4 KiB / 16 KiB / 64 KiB granules, PSCI
for secondary CPU bringup. QEMU `virt` in CI.

*Stresses:* a second page-table format, runtime-variable page size, runtime driver
selection for the interrupt controller, a memory model weaker than x86's.

### `i686`

32-bit x86, BIOS boot, PIC or APIC, PAE. This is the "platforms Linux dropped"
commitment made concrete — 32-bit x86 support is being actively removed from
mainstream systems, and the hardware still exists in industrial and embedded
deployments.

*Stresses:* physical addresses wider than pointers (36-bit PAE behind 32-bit
`usize`), a tiny kernel virtual address space, legacy firmware with no structured
hardware description, segmentation.

This target exists specifically to catch the `usize`-as-physical-address assumption
that creeps into any kernel written 64-bit-first. It is tier 1 for that reason.

It is also the hardest target to stand up, and the one that dictates our toolchain
policy. **There is no built-in `i686-unknown-none`**: every other tier-1 target has a
built-in bare-metal equivalent, but 32-bit x86 bare metal must be described by a
hand-written target specification — which is nightly-gated, and is therefore the
single reason we cannot build on stable
([build-system.md](build-system.md#engine-a-pinned-nightly)).

Two hazards in that specification, and their resolution — found by building it:

- `+soft-float` is rejected outright as incompatible with the i686 ABI, which returns
  floats in x87 registers. The x86_64 approach of `-mmx,-sse,+soft-float` does not
  transfer.
- Disabling SSE fails to build `core`, which contains functions requiring the `sse`
  target feature.

So the i686 specification leaves SSE enabled, and the consequence is the part worth
knowing: **SSE instructions end up in the image whether or not kernel code uses
floating point.** LLVM emits `xorps`/`movaps` to zero a stack buffer. The first i686
boot triple-faulted on exactly that, three lines into the banner, and the fault chain
is instructive — `#UD` on the SSE instruction, delivered through the BIOS IVT that is
still installed at that point, becoming `#GP` with error `0x32` (`(6 << 3) | IDT`),
then `#DF`, then reset.

The resolution is that the i686 boot path clears `CR0.EM`, sets `CR0.MP`, and sets
`CR4.OSFXSR | CR4.OSXMMEXCPT` alongside enabling PAE and paging. `arch/x86_64` needs
none of this because its specification really can disable SSE.

This is not a workaround. "The kernel must not use floating point" is a policy about
code we write and about what a context switch has to save; it is not a claim about
what the code generator emits, and the port has to make the emitted instructions
legal.

One more difference that will bite anyone copying from `arch/x86_64`: **a 32-bit PAE
PDPT entry is not a long-mode one.** It carries only the present bit and the two cache
bits — bits 1 and 2 (R/W and U/S) are reserved and must be zero. The `0x03` that
x86_64 writes into its PDPTE is correct there and faults here.

### `armv7m` — Cortex-M, no MMU

Thumb-2, MPU instead of MMU, no privilege model worth speaking of, single core,
kilobytes rather than megabytes of RAM, execute-in-place from flash. Implements
`Arch` and `HasMpu` and nothing else. QEMU `mps2-an385` (Cortex-M3) in CI; a real board
from Phase 7. Semihosting is the only result channel this target has, which is why the
test protocol standardizes on it rather than on console scraping.

*Stresses:* every assumption that virtual memory exists, the entire size budget, the
lower bound of the configuration system. If the config system cannot produce a kernel
that fits here, it is not a configuration system.

### `riscv32` — rv32imac, no MMU

The second no-MMU target, and the one that catches architecture assumptions that
`armv7m` alone would let through. Also gives us a target where the atomics extension
can be configured away, exercising the `HasCas` bound.

*Stresses:* a third ISA in the no-MMU class, optional atomics, PLIC/CLINT interrupt
model.

**As built** (the `riscv32-virt` preset, `targets/riscv32-kintane.json`):

- **Boot and traps.** rv32imac in machine mode on QEMU `virt` with `-bios none`. There is
  no firmware below the kernel, which owns `mtvec` and the CLINT directly.
- **Timer, clock and context.**
  - `mtime` is the clock source, and `mtimecmp` a one-shot timer.
  - Traps save every register plus `mepc` and `mstatus` in the frame, so the timer
    interrupt can preempt.
  - The context switch saves `ra`, `sp` and `s0`–`s11`.
- **Capabilities.** It implements `Arch`, `HasCas`, `UniProcessor` and
  `HasContextSwitch`, and nothing else.
- **What passes.**
  - The whole boot banner, the flat region allocator and the heap.
  - Preemption, sleep and the tickless idle.
  - All 35 in-kernel checks.
  - Crash decoding by panic and by fault.
- **What reports Skipped.** The MMU checks. The guard-page test modes do not exist here.

What the port found outside `arch/`:

- **64-bit atomics.** The target spec's `max-atomic-width` is 32, the truth for rv32imac.
  `kernel/main` kept 64-bit counters in `AtomicU64`, so it gained an alias that becomes
  `sync::IrqU64` on a uniprocessor without them.
- **A tree above 2 GiB.** `boot/info-fdt` refused a device tree ending above `isize::MAX`,
  which is every tree on a 32-bit machine whose RAM starts at 2 GiB.
- **Record below the frame pointer.** The RISC-V frame record sits below the frame
  pointer, which `lib/unwind` could not describe.

The addresses of the UART, the CLINT and `sifive_test`, and the timebase frequency, are
`virt`'s constants. The device tree carries the same facts, and reading them is the device
model's work, which only aarch64 has so far.

## Tier 2

Planned, in roughly this order:

- **`riscv64`** — `rv64gc`, SBI boot, Sv39/Sv48 paging, SMP. Largely covered by the
  work for `aarch64` and `riscv32`; expected to be cheap once both exist. A strong
  candidate for early tier-1 promotion.
- **`armv7a`** — 32-bit ARM with an MMU. The combination of "has MMU" and "32-bit"
  that neither `i686` nor `aarch64` covers, on very widely deployed hardware.
- **`powerpc` / `powerpc64`** — big-endian by default, which is the only way we will
  ever find the endianness bugs. Still current in networking and aerospace.

## Tier 3 and the long tail

The project's stated purpose includes platforms that mainstream kernels have
abandoned. Candidates, explicitly welcome but not scheduled:

- **m68k** — 68020+ with MMU, and 68000/ColdFire without. No CAS on the earliest
  parts.
- **SPARC (sun4m / sun4u)** — a register-window architecture, which will find every
  place we assumed a flat register file during context switch.
- **MIPS** — big and little endian, software-managed TLB. A software TLB refill path
  is a genuinely different `HasMmu` implementation and worth having.
- **SuperH**, **Alpha**, **PA-RISC**, **Itanium** — each removed from or unmaintained
  in Linux, each with working hardware in collections and in the field.

We do not promise these. We promise that the architecture makes them possible without
a fork, and that adding one touches only `arch/`, `drivers/`, and `config/`.

## Target specifications

Each target has a JSON spec under `targets/` pinned in-tree rather than relying on a
built-in rustc target, so that a rustc upgrade cannot silently change our ABI, our
relocation model, or our atomic width assumptions. `kbuild` builds `core` from source
against these specs.

Built-in targets are used as the *starting point* where one exists — `x86_64-unknown-none`,
`aarch64-unknown-none-softfloat`, `thumbv7m-none-eabi`, `riscv32imac-unknown-none-elf`,
and `riscv32i-unknown-none-elf` for the no-atomics variant — dumped with
`--print target-spec-json`, then edited and committed. `i686` has no such starting
point and is written from scratch.

The spec records, among other things:
- pointer width, data layout, endianness
- `max-atomic-width` — `0` for targets without atomics, which is how the `HasCas`
  capability is kept honest
- `features` — the exact ISA subset, never "whatever the host supports"
- `panic-strategy = "abort"`, `relocation-model`, `code-model`
- floating point ABI and whether the kernel may use FP registers at all

## Machine support versus architecture support

An architecture port makes the ISA work. A *machine* — a board, an SoC, a PC
chipset generation — additionally needs its interrupt controller, timer, console, and
boot protocol. These are drivers, described in
[architecture.md](architecture.md#device--the-device-framework), and they are
enumerated per target in `config/presets/`.

One `aarch64` image can support many machines through device-tree probing. One
`armv7m` image typically supports exactly one board, because discovery costs more
than the board is worth. Both are the same source; the difference is configuration.

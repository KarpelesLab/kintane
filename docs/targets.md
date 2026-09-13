# Targets and Support Tiers

## Tier definitions

**Tier 1 — gated.** Builds and boots on every merge. A change that breaks a tier-1
target does not land. Every tier-1 target has a QEMU machine in CI and at least one
piece of real hardware someone can reach.

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

### `armv7m` — Cortex-M, no MMU

Thumb-2, MPU instead of MMU, no privilege model worth speaking of, single core,
kilobytes rather than megabytes of RAM, execute-in-place from flash. Implements
`Arch` and `HasMpu` and nothing else. QEMU `mps2-an385` in CI, plus a real board.

*Stresses:* every assumption that virtual memory exists, the entire size budget, the
lower bound of the configuration system. If the config system cannot produce a kernel
that fits here, it is not a configuration system.

### `riscv32` — rv32imac, no MMU

The second no-MMU target, and the one that catches architecture assumptions that
`armv7m` alone would let through. Also gives us a target where the atomics extension
can be configured away, exercising the `HasCas` bound.

*Stresses:* a third ISA in the no-MMU class, optional atomics, PLIC/CLINT interrupt
model.

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

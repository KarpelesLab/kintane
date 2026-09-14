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

**As built** (the `armv7m-mps2` preset, `targets/armv7m-kintane.json`, derived from the
built-in `thumbv7m-none-eabi`):

- **Boot.** A vector table at address 0 and a reset handler that copies `.data` from its
  load address in code memory, zeroes `.bss`, and moves thread mode onto the process stack.
  Handlers keep the main stack. The memory map comes from the board description at build
  time (`boot/info-board`); nothing starts the kernel but the core's reset.
- **Console and timers.**
  - The console is the CMSDK APB UART0.
  - SysTick is the clock, running full 24-bit laps counted by its exception.
  - APB timer 0 is the scheduler's one-shot.
- **Context switch.** It saves `r4`–`r11`, `sp` and `lr`. Preemption reaches thread mode
  through PendSV before the hook runs; see
  [portability.md](portability.md#the-second-small-target-armv7-m).
- **MPU.** All eight regions:
  - code memory read-only and executable;
  - RAM and PSRAM read-write and never executable;
  - no access to the page below the boot stack;
  - no access to a guard at the bottom of each thread-stack slot, a quarter of the slot
    (8 KiB at the default 32 KiB), using subregions.

  The interrupt selftest proves each guard faults and `.rodata` refuses a write. A real
  overflow of the boot stack, run as a mutation, is reported with the guard named even
  though the core could not stack the exception.
- **Capabilities.** It implements `Arch`, `HasMpu`, `HasCas` (`LDREX`/`STREX`),
  `UniProcessor` and `HasContextSwitch`.
- **What passes.**
  - The whole boot banner, including preemption, sleep and tickless idle.
  - All 35 in-kernel checks.
  - Crash decoding by panic and by fault, and the lock-order ABBA test and safe mode.

  The MMU checks report Skipped.

**Size**, against the roadmap's 64 KiB, from `kbuild size`. Flash is `.text`, `.rodata` and
`.data`'s load copy; RAM is `.data`, `.bss`, both stacks, the boot-stack guard and the thread
stacks.

| Configuration | `.text` | `.rodata` | Flash | `.bss` | stacks + guard | RAM |
|---|---|---|---|---|---|---|
| first port: `armv7m-mps2`, before this round | 100.0 KiB | 12.0 KiB | 116.0 KiB | 41.0 KiB | 284.0 KiB | 329.0 KiB |
| `armv7m-mps2` (debug, test channel) | 99.4 KiB | 10.7 KiB | 114.1 KiB | 11.0 KiB | 284.0 KiB | 298.9 KiB |
| `armv7m-tiny` (release, opt-level `z`, test channel) | 51.3 KiB | 10.6 KiB | 65.0 KiB | 10.8 KiB | 42.0 KiB | **55.9 KiB** |
| `armv7m-tiny`, `QEMU_EXIT=n` (the product image) | 50.8 KiB | 10.6 KiB | 64.6 KiB | 10.8 KiB | 42.0 KiB | **55.9 KiB** |

**RAM fits a 64 KiB machine; flash is 0.6 KiB over.** The product image boots, reaches
`kmain`, hands the CPU to the scheduler and keeps printing its uptime. The test image
passes the whole boot banner. What moved, each by configuration and none by changing the
kernel:

- **Thread stacks.** `THREAD_STACK_SLOTS` and `THREAD_STACK_KIB` reach `link.ld` through
  kbuild's generated `sizes.ld`. `armv7m-tiny` has six 4 KiB slots, 24 KiB, where the
  first port had eight 32 KiB ones, 256 KiB. A slot's MPU guard stays a quarter of it, and
  the MPU programs one region per two slots, however many there are.
- **The bitmap store.** `FRAME_BITMAP_KIB` now goes down to 1. The board needs 2 KiB, and
  the kernel names the shortfall if a preset asks for less: 1 KiB boots to "need 2048 bytes
  of bitmap, have 1024".
- **Section padding.** `.text`, `.rodata` and `.data` are word-aligned, not page-aligned,
  since the MPU's flash and RAM regions are whole memories. Only the boot-stack guard, a
  region of its own, stays on a page.
- **The boot and handler stacks.** `BOOT_STACK_KIB` and `HANDLER_STACK_KIB`. The boot stack
  cannot go below 12 KiB with the boot checks in: at 4 KiB the guard caught an overflow in
  the interrupt selftest, and at 8 KiB one in `Threads::new`, which builds the whole thread
  table on the stack before it is stored.

What remains, in the order it would pay:

- **The boot demonstrations.** `kernel/main` is 13.6 KiB of `.text` in the product image
  (`kbuild size`'s `kintane` row), and most of it is the banner's checks — clock,
  preemption, sleep, the heap under threads — which are in every image, product or test.
  The flash overrun is 0.6 KiB, so leaving even the clock check out of a product image
  would bring flash inside 64 KiB. That needs a configuration symbol that restructures
  `kernel/main`, which other work is editing, so it was not taken this round.
- **`Threads::new` building on the stack**, which sets the boot stack's floor at 12 KiB.
  Constructing the table in place would let it drop to 8 or lower.
- **Formatting.** `core`'s formatting reached through `panic!` messages is most of the 5 KiB
  of `core`.

The addresses of the UART, timer 0, and the 25 MHz clocks are the AN385's constants, as
riscv32's are `virt`'s; `config/boards/mps2-an385.kcfg` names them.

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
- **Stack guards.** Physical Memory Protection, not unmapped pages. The port locks a
  no-access PMP region over the page below the boot stack and over the bottom page of each
  thread-stack slot (`ARCH_HAS_PMP`), and the banner reads `pmp 9 of 9 stack guards
  locked`. The two stack-guard test modes run here; the null-dereference mode, which needs
  page 0 unmapped, does not.
- **What passes.**
  - The whole boot banner, the flat region allocator and the heap.
  - Preemption, sleep and the tickless idle.
  - All 35 in-kernel checks.
  - Crash decoding by panic and by fault.
  - Both stack-guard modes. Each touches a guard from a healthy stack, because a
    machine-mode trap runs on the stack it interrupts; a real overflow is not yet
    reported, which needs an emergency stack switched in through `mscratch`.
- **What reports Skipped.** The MMU checks.

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

**The rv32i variant** (the `riscv32i-virt` preset, `targets/riscv32i-kintane.json`,
`RISCV32_NO_ATOMICS`) is the same port built for the base ISA: no A extension, so no
compare-and-swap, and no M extension, so no multiply or divide instruction. It runs on
QEMU's `rv32` hart with A, M and C switched off, where an atomic, multiply, divide or
compressed instruction is illegal. (QEMU's own `rv32i` model has no Zicsr, so no
machine-mode kernel can run on it.) It implements `Arch`,
`UniProcessor` and `HasContextSwitch`, and not `HasCas`, so the kernel's lock family is
interrupt masking throughout. It passes the banner, the heap, preemption, sleep and the
tickless idle, lock-order checking in its uniprocessor form, both PMP stack-guard modes,
and crash decoding by panic. The in-kernel suite reports its four atomic
read-modify-write checks as skipped: 31 passed, 4 skipped. What it took is in
[portability.md](portability.md#without-compare-and-swap-rv32i).

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
- `max-atomic-width` and `atomic-cas` — together, which atomics exist. A core with no atomic
  instructions still loads and stores a naturally aligned word in one instruction, so
  `riscv32i-kintane` keeps `max-atomic-width: 32` with `atomic-cas: false`, as the built-in
  `riscv32i-unknown-none-elf` does: `AtomicU32` exists, and every read-modify-write on it
  does not. That, not a width of `0`, is how the `HasCas` capability is kept honest.
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

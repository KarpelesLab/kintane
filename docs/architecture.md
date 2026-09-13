# Architecture

## Shape

KinTane is a **modular monolithic core with optional driver isolation**. The core —
memory management, scheduling, IPC, the object model, the device framework — always
runs privileged and in one address space. Drivers are written against an abstract
interface that allows them to run in one of three domains:

| Domain | Address space | Requires | Typical use |
|---|---|---|---|
| `InKernel` | kernel | nothing | no-MMU targets, timers, interrupt controllers, anything on the fault-handling path |
| `Isolated` | its own, privileged or reduced | MMU; IOMMU for DMA-capable devices | most drivers on a machine that can afford it |
| `User` | userspace process | MMU + full ABI | drivers that want to be restartable and are not latency-critical |

**The driver source is identical across all three.** The domain is chosen by
configuration and, for `Isolated` vs `InKernel`, may even be chosen per-device at
runtime. This is possible because a driver never touches raw pointers or takes
interrupts directly; it works through handles (`Mmio<T>`, `DmaBuffer`, `IrqLine`)
whose implementation is either a direct access or a proxied one.

This is the pragmatic middle of the microkernel debate. A pure microkernel cannot
serve the no-MMU targets we care about. A pure monolith throws away isolation on the
machines that could have it. The hybrid asks drivers to be written to a slightly
stricter interface, and in exchange the same driver is a trusted in-kernel component
on a Cortex-M and a restartable isolated component on a server.

### The cost, stated plainly

Isolation is not free. An isolated driver pays an address-space switch and message
marshalling per operation, which is unacceptable for a 10 GbE NIC's fast path and
irrelevant for an I²C temperature sensor. We therefore expect a permanent split:
high-throughput drivers ship `InKernel` by default, everything else `Isolated`, and
the config lets an operator move any of them. Making that trade visible is better
than pretending one answer fits all hardware.

## Layers

```
┌──────────────────────────────────────────────────────────────────┐
│  userspace                                                        │
├──────────────────────────────────────────────────────────────────┤
│  syscall / object layer      capability handles, invocation        │
│    ├─ native ABI             the real interface                    │
│    └─ linux personality      compat surface, a client of the above │
├──────────────────────────────────────────────────────────────────┤
│  subsystems                                                        │
│  ┌──────────┬──────────┬──────────┬──────────┬─────────────────┐ │
│  │ sched    │ vfs      │ net      │ block    │ ipc / channels  │ │
│  └──────────┴──────────┴──────────┴──────────┴─────────────────┘ │
├──────────────────────────────────────────────────────────────────┤
│  device framework      probing, binding, resources, power, domains │
├──────────────────────────────────────────────────────────────────┤
│  core                  mm, kalloc, sync, time, kobject, panic      │
├──────────────────────────────────────────────────────────────────┤
│  hal                   traits only: Arch, HasMmu, HasSmp, …        │
├──────────────────────────────────────────────────────────────────┤
│  arch/<name>           the single implementation of the above       │
└──────────────────────────────────────────────────────────────────┘
```

Dependencies point downward only, enforced by the crate graph in `kbuild`. A
subsystem may not name `arch::` directly; it names `hal::` traits. `kbuild` fails the
build if a crate imports something the graph does not permit.

## Core subsystems

### `hal` — hardware abstraction traits

Trait definitions and nothing else: no code, no state. This crate is the contract
described in [portability.md](portability.md). It compiles for every target,
including the host, which is what makes host-side unit testing of upper layers
possible (see [testing.md](testing.md)).

### `arch/<name>` — the one implementation

Boot entry, exception and interrupt vectors, context switch, page-table format, cache
and TLB maintenance, atomic primitives where the ISA needs help. This is where
assembly lives and where the `unsafe` budget is spent. One `arch` crate is linked per
image.

### `mm` — memory management

Two interchangeable implementations selected by config:

- **`mm::paged`** — for `HasMmu` targets. Physical frame allocator (buddy), virtual
  address space objects, demand paging, copy-on-write, huge pages where the arch
  advertises them.
- **`mm::flat`** — for no-MMU targets. Region allocator over physical memory,
  optional MPU region programming for `HasMpu` targets, no translation, no paging.

Upper layers use the `AddressSpace` trait, which both provide, and are honest about
what a flat build cannot do: `mm::flat` has no `fork`-style address space cloning,
and the process layer's config marks that feature unavailable rather than emulating
it badly.

### `kalloc` — allocation

We do **not** use the `alloc` crate. Its collections abort on allocation failure,
which a kernel may not do. `kalloc` provides fallible equivalents:

```rust
pub fn try_new<T>(value: T) -> Result<Box<T>, AllocError>;
impl<T> Vec<T> {
    pub fn try_push(&mut self, value: T) -> Result<(), AllocError>;
    pub fn try_reserve(&mut self, additional: usize) -> Result<(), AllocError>;
}
```

Every allocation in the kernel is fallible and every failure is handled. Allocation
also carries a context — GFP-like flags for *may this sleep*, *must this be DMA
addressable*, *which NUMA node* — because those questions are unavoidable and hiding
them in a global has caused real bugs elsewhere.

### `sync` — synchronization

Lock types are selected by architecture capability, not by `#ifdef`:

- `HasCas + HasSmp` → ticket or MCS spinlocks, lock-free primitives available.
- `HasCas`, no SMP → CAS-based locks, uncontended fast path, no memory barriers.
- No CAS → interrupt-masking critical sections; lock-free data structures are simply
  not offered, and code requiring them carries a `HasCas` bound.

Generic subsystems, which cannot name the machine, take a `LockFamily` type parameter
(`Spin<A>` or `Irq<A>`) and let the kernel image choose. Every lock can carry a
`LockClass`. In debug builds (`DEBUG_LOCKDEP`) the order classes are taken in is
recorded, and an inversion is reported the first time both orders have been seen,
without the deadlock having to happen. Re-taking a held lock stops the CPU. When
checking is off, a lock carries no class and pays nothing. The held-lock stack is
global until secondary CPUs exist, and becomes per-CPU with them.

Sleeping locks (mutex, rwlock, semaphore) sit above the scheduler and exist only in
builds that have one.

For reclamation of shared read-mostly data on SMP builds we plan epoch-based
reclamation rather than a full RCU. RCU's quiescent-state tracking has deep
interactions with the scheduler and idle loop that we would rather not commit to
before Phase 3.

### `kobject` — the object and reference model

Every kernel-managed thing a userspace program can hold — a process, a channel
endpoint, a memory region, a device handle — is a `KObject` with refcounting, a type
tag, and a rights mask. This is the substrate the syscall layer exposes as
capabilities; see [userspace-abi.md](userspace-abi.md).

### `device` — the device framework

- **Enumeration** from device tree (FDT), ACPI, PCI/PCIe config space, USB, or a
  static board description compiled in for targets with no discovery mechanism at
  all. All four produce the same internal device node representation.
- **Binding** matches drivers to nodes by compatible-string, PCI ID, or explicit
  board table.
- **Resources** — MMIO ranges, IRQ lines, DMA channels, clocks, regulators, GPIOs —
  are handed to the driver as typed handles, never as integers the driver
  dereferences itself. This is what makes the isolation domains possible.
- **Power and lifecycle** — suspend, resume, and driver removal are part of the
  interface from the start, not retrofitted.

### `sched` — scheduling

Pluggable policy behind a trait, with the config selecting one or more:

- A fixed-priority preemptive scheduler for real-time and embedded builds; on
  single-CPU no-MMU targets this is the whole scheduler and it is small.
- A general-purpose fair scheduler with per-CPU runqueues, load balancing, and idle
  balancing for SMP builds.

Per-CPU data is a `HasSmp`-gated abstraction; a uniprocessor build resolves
`per_cpu!(X)` to a plain static with no indirection.

## Boot flow

```
bootloader: kinboot-efi / kinboot-bios / none / a foreign loader
  └─ hands over one BootInfo, then ceases to exist  [bootloader.md]
      ↓
platform entry (arch/<name>/boot)
  └─ minimal machine setup: stack, exception vectors, early console
     └─ hal init: report memory map, CPU features, CPU count
        └─ mm early: bootstrap allocator over the memory map
           └─ mm full: frame allocator, kernel address space
              └─ kalloc: kernel heap online
                 └─ device: enumerate, bind early drivers (timer, irqchip)
                    └─ sched: create idle + init tasks, enable preemption
                       └─ secondary CPUs brought up (HasSmp builds)
                          └─ device: bind remaining drivers, start isolation domains
                             └─ hand off to init
```

Each arrow is a phase with a defined set of services already available. Drivers
declare which phase they may bind in, so a driver that needs the heap cannot be
probed before it exists. This is enforced by type — early-phase driver registration
takes a different token than late-phase — rather than by convention.

## Failure model

- **Panics in isolated drivers** kill the domain, mark the device failed, and are
  eligible for restart. The device framework is written expecting this.
- **Panics in the core** are fatal. There is no pretending otherwise; the kernel
  prints state and halts or reboots according to config.
- **Allocation failure is never a panic.** It is a `Result` that callers handle.
- **Arithmetic overflow** is checked in debug builds and wrapping in release, with
  the exception of address arithmetic, which is always checked because the failure
  mode is memory corruption.

## Directory layout

```
kintane/
├── kbuild/              the build tool (host binary, plain cargo project)
├── config/              configuration definitions and target presets
│   ├── *.kcfg
│   └── presets/
├── targets/             rustc JSON target specifications
├── boot/                the boot protocol and the loaders
│   ├── protocol/        BootInfo and its tags — a genuinely stable ABI
│   ├── efi/             kinboot-efi (PE/COFF, built-in uefi targets)
│   ├── bios/            kinboot-bios (16-bit stage 1 + i686 stage 2)
│   └── shims/           translation from U-Boot, GRUB, OpenSBI, QEMU -kernel
├── hal/                 architecture traits
├── arch/
│   ├── x86_64/
│   ├── aarch64/
│   ├── i686/
│   └── armv7m/
├── kernel/
│   ├── kalloc/
│   ├── sync/
│   ├── mm/
│   ├── kobject/
│   ├── device/
│   ├── sched/
│   ├── time/
│   ├── ipc/
│   └── main/            the linked kernel image
├── drivers/
│   ├── irqchip/
│   ├── timer/
│   ├── serial/
│   ├── block/
│   └── net/
├── lib/                 no_std support crates (fdt, collections, fmt helpers)
├── tools/               image packaging, symbol extraction, QEMU harness
└── docs/
```

`kbuild/` is the one place where cargo is used, because it is a host tool with no
unusual requirements. Everything under `hal/`, `arch/`, `kernel/`, and `drivers/` is
built by `kbuild` calling `rustc` directly.

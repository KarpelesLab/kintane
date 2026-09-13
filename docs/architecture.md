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

#### The kernel's own address space, as built today

Every `mm::paged` port runs on tables the kernel builds for itself, not on the ones its
boot code left behind. `kernel/main` builds them with the shared walker from three
inputs, verifies them, installs them, and checks them again through the live root:

- **The direct map**, over usable RAM as the memory map describes it (capped at 1 GiB so
  a 32-bit kernel can address it). This is where the frame allocator's bitmap and the
  page tables themselves live.
- **The image**, from `image_sections()`: `.text` read-execute, `.rodata` read-only,
  data and stacks read-write and never executable. A one-page hole below the boot stack
  is left unmapped. That hole is the stack guard.
- **Device windows**, from `arch::kspace::device_windows()`. Neither of the other two
  inputs describes a device. A device left out of the map is a fault on its first
  register access after the switch, and on aarch64, where the console is MMIO, that
  fault has nowhere to print. x86 needs none today, because its devices are I/O ports.

Nothing is installed unless every mapping reads back with the intended permissions, the
guard page reads back unmapped, and the loader's boot data is reachable. After the switch
each port shows that the hardware enforces the tables, not only that they are written
correctly:

| Port | Enforcement observed after the switch |
|---|---|
| x86_64 | `CR0.WP` and `EFER.NXE` read live; a write to `.rodata` takes #PF (err 0x03) and a call into `.data` takes #PF (err 0x11), both through the expected-fault trap, with the permission restored afterwards |
| i686 | `CR0.WP` read live and NX reported. No fault probe: the #PF handler has no expected-fault path yet |
| aarch64 | `SCTLR_EL1.M` read live; `AT S1E1W` reports a permission fault on `.text` and `.rodata`; `AT S1E1R` reports a translation fault on the guard page |

The frames holding the live tables are handed to anything else that builds a frame pool
from the loader's map, which does not know they are in use. The in-kernel suite is the
first such pool, and the live tables are walked again after it runs. On x86 an overwritten
entry goes unnoticed while the TLB still holds the old translation, so without that second
walk the corruption would surface much later, somewhere else.

**What a stack overflow does now.** On x86_64 an overflow of the boot stack faults on the
guard page. The #PF cannot be pushed onto the exhausted stack, so #DF is raised and runs on
its IST stack, and the report names the guard page. On aarch64 the synchronous vector
checks, before touching memory, whether its own frame would land in the guard page. If it
would, it switches to a reserved stack. Otherwise the frame would go beneath the guard and
overwrite `.bss` to print the report. On i686 a real overflow still triple-faults: a 32-bit
gate has no IST, and this port has no #DF task gate. The guard page is unmapped and a touch
of it is reported, but an overflow that exhausts the stack cannot be reported yet.
`STACK_GUARD_TEST` exercises all of this; see
[testing.md](testing.md#expected-faults-the-stack-guard-test).

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

### `time` — the monotonic clock and timers

Time is split three ways, and only one part touches hardware:

- **Counters** are devices. `hal::ClockSource` is an object-safe trait for a free-running
  counter: its value, its width, and its rate. The architecture supplies one today:
  - x86: the TSC, with its rate calibrated at boot against PIT channel 2.
  - aarch64: the generic counter through `CNTVCT_EL0`, at the rate firmware put in
    `CNTFRQ_EL0`.

  An HPET, SysTick or RTC driver would provide one the same way.
- **The clock** (`kernel/time`, `Clock`) turns counter values into nanoseconds as an
  `Instant`, a `u64` from an origin near boot. The conversion is a multiply and a
  shift, so the read path has no 64-bit division. Wraps are handled, and so are
  counters that step backwards. The clock carries its sub-nanosecond remainder, so how
  often it is read does not change what it reads. It never reads hardware itself and
  takes no locks.
- **Timers** (`kernel/time`, `TimerQueue`) are a fixed-capacity deadline heap, with
  one-shot and periodic entries and handles that go stale rather than naming a reused
  slot. Periodic deadlines advance from the previous deadline, so late servicing
  does not accumulate as drift. `next_deadline` and `idle_budget` are what a tickless
  idle needs. The budget is bounded by `Clock::max_idle`, because a counter must be
  read at least once per half-wrap.

Programming a timer interrupt for the next deadline is not in `time`. That belongs to
whoever owns the tick, which is the scheduler working with the interrupt controller.
Wall-clock time is an offset added on top of the monotonic clock, and does not exist
yet.

The boot banner's `clock` line checks the real counter on each port. It times ten
timer interrupts of known period with the clock, and fails if the two disagree by
more than a wide margin, or if the counter steps backwards.

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

#### What exists today

The fixed-priority scheduler runs on x86_64, i686 and aarch64, on one CPU. It is three
pieces, split where the knowledge actually is:

- **`kernel/sched`** is the policy: 32 priority levels, round robin within a level,
  and the highest runnable level always wins. It depends on nothing.
- **`hal::HasContextSwitch`**, implemented in each `arch/<name>/context.rs`, is the
  mechanism: save the callee-saved registers, load another thread's.
- **`kernel/thread`** binds the two into a thread table with four checked invariants.
  The operations that switch (`yield_now`, `block`, `exit`) take a raw table pointer
  and do their bookkeeping under a reference that ends *before* the switch. A thread
  is suspended in the middle of such a call, and the thread that resumes calls into the
  same table; with `&mut self` that is two live exclusive references to one object.

**Preemption is `yield_now` called from the timer interrupt.** Each port's `tick`
module runs a periodic timer (the PIT on x86, the generic timer re-armed from its own
interrupt on aarch64) and calls one registered `fn()` after acknowledging each tick.
`arch` cannot depend on the scheduler, so the scheduler registers the hook. The switch
happens inside the interrupt handler. The interrupted thread's whole trap frame stays
on its own stack, and it resumes, much later, by returning through that handler. Three
conditions make this sound, and each port's `tick` module states them:

1. **EOI before the hook.** Otherwise the 8259A's in-service bit, or the GIC's running
   priority, stays set while the thread that raised it is suspended, and the next thread
   never receives a tick. The in-kernel check below catches exactly this. With the EOI
   moved after the hook, round robin and priority *still looked correct*, because the
   preempted thread eventually resumes and acknowledges. The only symptom was a worker
   that saw no tick for fifty ticks' worth of spinning.
2. **The trap frame lives on the thread's stack.** No IST on the timer gate on x86_64.
   On aarch64, `ELR_EL1` and `SPSR_EL1` are banked per exception level, so they are
   saved into the frame, not left in the register. On i686 the `x86-interrupt` prologue
   saves the XMM registers as well, which was confirmed in the disassembly because the
   kernel runs with SSE.
3. **Interrupts are masked for every table access**, by the CPU in the handler and
   explicitly in thread code. That is the Phase 2 exclusion on one CPU. A new thread
   starts masked, because a switch always happens masked, and unmasking is its first act.

The idle thread runs at priority 0 and waits for an interrupt with a race-free
check-then-halt (`sti; hlt` on x86, `wfi` then unmask on aarch64).

Every boot proves this with a verdict-gated check (`kernel/main/src/preempt.rs`). Two
threads spin without ever yielding and must interleave. A higher-priority thread spawned
after them must run first, and must preempt them on the tick that wakes it. Every
thread must keep receiving ticks, and idle must halt. Disabling the preemption call, the
EOI ordering, the threads' unmasking, the priority, or idle's halt each makes the boot
fail within seconds instead of hanging.

Not yet: thread stacks are static `.bss` arrays with no guard page, sleeping is a tick
count, not a timer subsystem with deadlines, and nothing but the demonstration creates
threads.

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

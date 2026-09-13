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
  is left unmapped. That hole is the stack guard. So is the bottom page of every slot in
  the kernel thread-stack array (below), and so is page 0, on every port, so that a null
  pointer faults instead of reading the real-mode interrupt vector table.
- **Device windows**, from `platform::device_windows()`. Neither of the other two
  inputs describes a device. A device left out of the map is a fault on its first
  register access after the switch, and on aarch64, where the console is MMIO, that
  fault has nowhere to print. On aarch64 the windows are exactly what the drivers bound
  from the device tree claimed (see [`device`](#device--the-device-framework)); x86 needs
  none today, because its devices are I/O ports, and passes the architecture's empty list
  through.

Nothing is installed unless every mapping reads back with the intended permissions, the
guard page reads back unmapped, and the loader's boot data is reachable. After the switch
each port shows that the hardware enforces the tables, not only that they are written
correctly:

| Port | Enforcement observed after the switch |
|---|---|
| x86_64 | `CR0.WP` and `EFER.NXE` read live; a write to `.rodata` takes #PF (err 0x03) and a call into `.data` takes #PF (err 0x11), both through the expected-fault trap, with the permission restored afterwards |
| i686 | `CR0.WP` read live and NX reported. No fault probe yet. The #PF handler can now return, but only for faults the kernel's page fault hook resolves; there is no expected-fault trap |
| aarch64 | `SCTLR_EL1.M` read live; `AT S1E1W` reports a permission fault on `.text` and `.rodata`; `AT S1E1R` reports a translation fault on the guard page |

The frames holding the live tables are handed to anything else that builds a frame pool
from the loader's map, which does not know they are in use. The in-kernel suite is the
first such pool, and the live tables are walked again after it runs. On x86 an overwritten
entry goes unnoticed while the TLB still holds the old translation, so without that second
walk the corruption would surface much later, somewhere else.

**Kernel thread stacks.** Each port's `link.ld` reserves a run of 32 KiB slots after the
boot stack, and `hal::StackArray` describes them: a guard page at the bottom of each slot,
then a 28 KiB stack. Threads take their stacks from `arch::kspace::claim_thread_stack`,
which records who each slot is for, so an overflow report names the thread. Without this, a
thread that overflowed wrote into the stack of the thread whose slot was below, which
corrupts a suspended thread and fails later, somewhere else. The slot size is a power of
two for a reason: aarch64's exception entry has to decide whether a frame would land in
*some* guard page with two scratch registers and no stack, and a mask is the test that fits.

**What a stack overflow does now.** On every port, an overflow of the boot stack or of a
thread stack faults on that stack's guard page and is reported by name:

- **x86_64.** The #PF cannot be pushed onto the exhausted stack, so #DF is raised and runs on its
  IST stack.
- **i686.** A 32-bit gate has no IST, so #DF is a *task gate* (`arch/i686/src/tss.rs`): the CPU
  switches to a task with its own stack and `CR3` without pushing anything on the broken one, and
  that task reads the interrupted `EIP`, `ESP` and `EBP` out of the TSS the switch saved them into.
  A hardware task switch sets `CR0.TS`, and this target emits SSE for ordinary code, so the task's
  first instruction is `clts`; without it the report's first `movaps` raises #NM and the recursion
  that follows destroys the task's stack.
- **aarch64.** The synchronous vector checks, before touching memory, whether its own frame would
  touch the boot stack's guard page or any thread stack's. If it would, it switches to a reserved
  stack. Otherwise the frame would go beneath the guard, onto `.bss` or onto the stack of the
  thread below, to print the report.

`STACK_GUARD_TEST`, `THREAD_STACK_GUARD_TEST` and `NULL_DEREF_TEST` exercise all of this;
see [testing.md](testing.md#expected-faults-the-stack-guard-test).

#### Regions, demand paging and copy-on-write (`mm::vm`)

`mm::paged` changes tables. `mm::vm` decides what they should say, and decides it lazily.

- **Regions.** An address space has a sorted, fixed-capacity region map. Each region has a
  start, a length, the permissions it grants at most, a backing, and whether huge pages are
  allowed. The capacity is fixed for two reasons. Layering: `kalloc` depends on `mm`, so the
  map cannot allocate. And the fault path consults the map, so allocating there would mean
  allocating inside a fault handler.
- **Backing.** Anonymous regions are zeroed on first touch. Physical regions map a fixed range
  at matching offsets and never allocate or free its frames. There is no separate VM object
  with a page list yet: the page tables record which anonymous pages exist, and a small
  caller-provided table counts mappings of frames shared more than once. That covers anonymous
  memory in one space and copy-on-write between a few. Swap, file backing and pages that exist
  while unmapped need a real object, and they arrive with the first thing that needs them.
- **Faults.** `Vm::fault(addr, access)` finds the region and checks the access against it.
  Then:
  - A hole gets a zeroed frame, or a zeroed 2 MiB block when the region allows huge pages, the
    block fits inside the region, and a contiguous aligned run is available. Otherwise it gets
    a base page.
  - A write to a read-only anonymous page copies the page if its frame is shared, and makes
    it writable in place if not.
  - A leaf that already permits the access is spurious, and the TLB is flushed.
  - Everything else is an error, and nothing was changed.
- **Out of memory.** Running out during a fault returns frames and prunes any tables it
  allocated.
- **Copy-on-write sharing.** `cow_share` splits huge leaves first, so share counts are always
  per base page. It then maps every page read-only on both sides. It is all or nothing: a
  failure part-way unmaps what it mapped and restores the source's write permission.
- **`protect`.** It splits regions and huge leaves at its edges. Granting write does not make a
  shared page writable; the next write copies it.
- **Checking.** `Vm::audit` checks the invariants against the live tables. The one that matters
  most is that no writable leaf maps a shared frame.

**On the machine.** Each port decodes its page-fault syndrome into a `hal::fault::PageFault`
and offers it to a hook the kernel registers (`arch::fault::set_page_fault_hook`). On x86 that
is CR2 and the #PF error code. On aarch64 it is FAR and ESR, for same-EL translation and
permission faults only. A fault the hook declines still reaches the fatal report, so the
guard page, which no region covers, is exactly as fatal as before. The boot `demand` line
reserves regions in an unmapped 1 GiB window and simply touches them. It requires:

- a frame per first touch, and none for a second;
- zero bytes, on frames deliberately dirtied first;
- a write to either side of a share copying only that page;
- a 2 MiB leaf over one contiguous block;
- no spurious faults;
- the frame allocator back at its starting count after release.

**Where a missing TLB flush hides.** Replacing a leaf always invalidates it. The flush that
matters is the one `cow_share` issues when it makes a writable page read-only. A CPU still
holding the writable translation writes straight into the shared frame, and nothing faults to
say so. The boot check writes the source pages just before sharing so that translation is
cached. Without the flush it fails on both x86 ports. Under QEMU's TCG on aarch64 the stale
translation was not kept, so there the omission went unobserved. The forgiving direction,
read-only to writable, only refaults: the resolver reports a spurious fault and does a full
flush. For that reason the boot check requires zero spurious faults instead of tolerating
them.

32-bit PAE adds a trap. The four PDPT entries are copied into the CPU when CR3 is loaded, so a
new page directory under them is invisible to `invlpg`. `HasPageTables::root_load_caches`
lets i686 say so, and the walker then reloads CR3 after filling or clearing such an entry.
QEMU's TCG does not model that cache, so this follows the SDM and is not observable under
emulation.

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

#### The kernel heap, as it exists today

`kernel/main/src/kheap.rs` owns one `kalloc::Heap` for the life of the kernel, so any
thread can reach it. Its memory is a fixed run of 512 frames taken from the machine's
frame allocator at boot. From then on a second frame allocator manages that run and
knows nothing else. 128 of the frames are the buddy allocator's, and the arena grows
from the rest. Everything the heap holds is therefore inside one range the kernel can
name, and the in-kernel suite, which builds its own frame pool from the loader's map,
is told to keep out of it.

One lock of the kernel's lock family (`sync::Spin<Cpu>`, class `kernel.heap`) covers
the heap and its frames together. The family masks interrupts while held, so on one
CPU the timer interrupt never finds the lock held by the thread it interrupted.
Allocating from interrupt context is therefore safe, with two rules:

- A request that says it may sleep (`AllocContext::KERNEL`) is refused with
  `MaySleepInInterrupt`.
- An interrupt-context request never grows the heap.

The interrupt extent is marked explicitly by the tick hook (`kheap::irq_enter`/
`irq_exit`), and ends before the hook switches threads.

`KBox<T>` is the owning pointer. `try_new(value, ctx)` gives the value back on failure,
and dropping the box frees it. There is no `#[global_allocator]`, for three reasons:

- `GlobalAlloc` signals failure with a null pointer, which `alloc`'s everyday API turns
  into a call that does not return.
- It cannot carry an allocation context.
- `alloc` is not built.

The boot check `kheap mt` runs three non-yielding threads that allocate, fill, check and
free across preemptions while the timer interrupt allocates too. It requires no
corruption, no leak, atomic requests from the interrupt served, and may-sleep requests
from the interrupt refused.

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

The kernel's one clock and one timer queue live in `kernel/main/src/timekeeping.rs`,
each behind its own lock of the kernel's lock family (`time.clock`, `time.timers`).
The two locks are never held together. Nothing ticks. Each port's `tick` module offers
a one-shot timer (`start_oneshot`, `arm_ns`), and `timekeeping::program` arms it for
the earliest timer, or for the end of a time slice when the scheduler says a thread is
waiting for the CPU. How far one arming reaches is a fact about the hardware:

- **Arm generic timer:** a signed 32-bit count of ticks, 2.15 s at QEMU's 1 GHz. A 500 ms idle
  period takes one interrupt.
- **x86 PIT (mode 0):** 16 bits, 54.9 ms. The same idle period takes nine interrupts,
  where a 10 ms tick would take fifty. The PIT is the interim one-shot, and the local
  APIC timer, which has a 32-bit count and a divider, replaces it with the APIC driver.

The boot check `tickless` measures exactly this, and fails if an idle period takes more
interrupts than the hardware's reach requires.

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

#### What exists today

The model is `kernel/device`. It is host-tested against QEMU `virt`'s own device trees
(GICv2 and GICv3, dumped with `-machine virt,dumpdtb=`) and against a hand-written tree
that breaks one rule per node. It compiles for rv32i, rv32imac and thumbv7m.

- **Nodes.** `DeviceTree` is built from a validated `boot/fdt` blob into caller-provided
  storage, with no allocation.
  - A `reg` entry is translated to a CPU address through every ancestor's `ranges`: empty
    means identity, and a missing `ranges` means the bus is not memory-mapped. `/cpus` is
    the case where that matters.
  - `#address-cells` and `#size-cells` are **not inherited**, per the specification.
    Linux inherits them, as a legacy behaviour.
  - `interrupt-parent` **is** inherited. Interrupts resolve to their controller node and
    raw specifier cells; turning cells into a line number is the controller driver's job.
  - `stdout-path` resolves through `/aliases`, and `clocks` walks each provider's
    `#clock-cells`.
  - Not yet: `interrupt-map` nexuses (reported as an error), `interrupts-extended`, and
    ACPI and PCIe enumeration.
- **Binding.** The node's own `compatible` list decides specificity: its first entry that
  any driver knows wins. A disabled node binds nothing.
- **Resources.** An MMIO window or an interrupt is claimed through the probe token and
  comes back as a handle that is not `Copy`. Overlapping windows are refused, naming the
  holder. A failed probe releases exactly its own claims: claims are tagged per probe,
  not per node, so re-probing a bound node cannot strip the existing binding.
  `Registers` checks every access against the window.
- **Phases as types.**
  - Only a probe produces `Bound`, and only a successful start produces `Started`.
  - Registering an interrupt handler requires `Bound`, plus an `IrqLine` claimed by that
    same binding. Enabling the handler requires `Started`.
  - Suspend, resume, stop and remove move between the tokens. Their default
    implementations are trivial, but they are in the interface.
  - The handler table is not yet what the architectures dispatch through; aarch64's
    interrupt path still knows only its timer.
- **Drivers.** `drivers/irqchip/gic` holds GICv2 and GICv3, moved out of `arch/aarch64`.
  `drivers/serial/pl011` takes its window and its baud divisors from the tree.
- **Platform.** `kernel/platform/fdt` is the one unit that sees both the drivers and the
  architecture. It is layer `kernel`, because only the image may name `arch`. The PC ports
  get `kernel/platform/none`.

Boot on aarch64 departs from the diagram below in one place: devices are enumerated
**before** the kernel address space is built, because that space maps exactly the windows
the bound drivers claimed. Discovery runs on the boot identity map, which covers every
device, and ends by installing the GIC as the interrupt path's controller.

It refuses to go further, printing why, when the tree and the running kernel disagree:

- the tree's console is not where the early console writes;
- the timer interrupt the tree names is not the one the architecture arms;
- no interrupt controller bound.

In each case the kernel address space is not installed, because it would unmap the only
console that can report the failure.

Checked by booting the unmodified image on edited trees. It exits with a failure,
without hanging, when:

- the UART's `reg` is moved;
- the timer's PPI is changed;
- the GIC's `compatible` is unknown, or names the wrong version for the machine.

A mutation that claims the GICv3 redistributor but leaves it out of the mapped windows
faults on the redistributor's first register after the switch.

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
module drives a one-shot timer (PIT mode 0 on x86, the generic timer on aarch64) and
calls one registered `fn()` after acknowledging each interrupt. The hook wakes the
threads whose timers expired, arms the next interrupt, and yields. The next interrupt
is the earliest timer, or the end of a 10 ms slice if `Threads::contended` says a
ready thread would take the CPU at the next yield. A thread about to sleep arms a
slice, because it cannot see who runs next. Idle arms for the earliest timer alone
before it halts.
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

Thread stacks come from the guarded thread-stack array described under memory, so a thread
that overflows faults on its own guard page, and the report names the slot's owner.

Threads sleep with `preempt::sleep_until(Instant)`, which arms a one-shot timer on the
kernel's timer queue and blocks. The expiring timer's interrupt wakes the thread. After
the preemption check, the same scheduler runs the shared-state checks
(`kernel/main/src/shared.rs`):

- **sleep:** three sleepers wake in deadline order, never early, and at most three slices
  late.
- **kheap mt:** the heap under preemption.
- **tickless:** interrupts during an idle period are bounded by the hardware's one-shot
  reach, not the slice.
- **lockdep:** in debug builds every boot prints what lock-order checking found and fails
  on any violation. `LOCKDEP_ABBA_TEST` makes two threads take two locks in opposite
  orders, and passes only if exactly that inversion was reported.

#### The scheduler's lifetime

The scheduler runs twice, on one thread table. The boot checks run it and then stop the
timer. What `kmain` does next assumes one thread with interrupts masked:

- the in-kernel suite, which builds its own frame pool over memory the loader reported
  free;
- the test modes that end the run from a fault handler;
- a deliberate crash.

Those stay on the boot thread rather than becoming threads, because each either ends
the run or needs the machine not to change underneath it. A guard-page test has to be
the thing that faults.

Once they are done, `kmain` decides what the image does next:

- **A test image** (`QEMU_EXIT`) reports its verdict and stops, as before.
- **Any other image** calls `persist::run`, provided bring-up passed. That calls
  `preempt::resume`, which re-enables the one-shot timer with the scheduler's hook and
  unmasks. Boot is then one thread among the others, at the priority the checks gave
  it, and idle is still in the table.
  - A normal image then has boot sleep, printing `uptime N s` every ten seconds. That
    is how a boot with no result channel shows it did not just halt.
  - A `STRESS_TEST` image makes boot the stress auditor instead
    ([testing.md](testing.md#3a-stress)).

A failed bring-up never starts the scheduler: it halts, or exits with the failure.

Not yet:

- A stack is never given back to the port when its thread exits; the scheduler reuses
  the slots it claimed. The ports reserve eight: the boot checks claim four, and the
  stress run four more.
- Nothing creates threads except the checks and the stress run.
- Boot keeps its boot-check priority for good, which is above every stress workload.

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
│   ├── platform/        per-firmware glue: binds drivers, hands the arch its devices
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

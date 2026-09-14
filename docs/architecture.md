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
  fault has nowhere to print. On every port the windows are exactly what the bound
  drivers claimed (see [`device`](#device--the-device-framework)): on aarch64 from the
  device tree, and on x86 from ACPI. The PC's console, PIC and PIT are I/O ports, which
  no page table governs; its windows are the I/O APIC, the local APIC and, on q35, the
  256 MiB PCI Express configuration window.

  Every window is mapped in the **device window**: at `DEVICE_WINDOW_BASE` above its
  physical address, never at the physical address itself, and never executable. The base is
  1 TiB on x86_64 and aarch64, which is where their user half, `[512 GiB, 1 TiB)`, ends; it
  is zero, meaning identity, on i686, which has no user half and no room in 32 bits for a
  linear window over a 36-bit bus, and on the ports without an MMU. Drivers never add the
  base themselves: `hal::paging::device_virt` is the one way from a device's physical
  address to one that can be dereferenced, and `Registers::new`, the virtio transports, the
  ECAM configuration space and the aarch64 early console all go through it. The boot tables
  alias the low device memory at the same base — x86_64's PML4 entry 2 points at the boot
  PDPT's 4 GiB identity map, and aarch64's root entry 2 at a table holding the 1 GiB Device
  block — so a driver that starts during discovery, before the kernel's own space exists,
  already holds its final addresses. After the switch the live tables are checked for an
  empty user half on every boot (the `live` line), and on aarch64 the UART is probed writable
  in the window and unmapped at its physical address.

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

**Kernel thread stacks.** Each paged port's `link.ld` reserves a run of 32 KiB slots after
the boot stack, and `hal::StackArray` describes them: a guard page at the bottom of each
slot, then a 28 KiB stack. ARMv7-M sizes its run from the configuration instead
(`THREAD_STACK_SLOTS`, `THREAD_STACK_KIB`, read through kbuild's `sizes.ld`), with an MPU
guard of a quarter of each slot rather than a page, because a microcontroller cannot spend
256 KiB on stacks. Threads take their stacks from `arch::kspace::claim_thread_stack`,
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

#### The flat model, as built today (`mm::flat`)

`riscv32` is the first port without an MMU, and it runs the flat model.
`mm::flat::Regions` is a fixed-capacity, sorted list of free physical ranges. It is built
from the memory map with every non-usable region subtracted, including the device tree,
which sits inside RAM. It hands out first-fit ranges of any size at any power-of-two
alignment, and returns them with coalescing. A free that overlaps free memory is refused
as a double free. It is host-tested, including 2000 rounds of scrambled
allocations and frees that must end at exactly the starting list.

It sits beside the frame allocator, not in place of it. The heap is built on frames, and a
4 KiB frame is still a fine unit on a flat machine. What the flat model adds is contiguous
memory of arbitrary size and alignment, which a paged kernel gets from virtual memory
instead. On every flat boot, a check allocates a DMA-sized and a stack-sized range from the
real map and confirms they are aligned, inside usable RAM, outside the image and disjoint.
It then frees both and requires the list to come back byte for byte, and requires a double
free to be refused.

Two limits are worth stating:

- **A free can fail.** A free with no neighbour to merge with needs an entry of its own,
  so capacity has to cover the map's ranges plus the most allocations alive at once. A
  full list refuses the free, and nothing is lost.
- **No kernel code allocates physical ranges yet.** The allocator does not outlive the
  boot check, and no MPU or PMP regions are programmed.

`kernel/main` chooses its memory model once, at module level. `model_paged.rs` holds the
kernel address space, demand paging and the guard-page test modes; `model_flat.rs` holds
this check. `main.rs` calls `model::` and contains no `cfg` in any body. On a flat image
every MMU check reports Skipped: `pagetable`, `demand`, and the guard-page test modes,
which the configuration refuses without `MM_PAGED`. None of them reports Passed.

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
checking is off, a lock carries no class and pays nothing. The order classes are taken
in is shared by every CPU. The held-lock stack is per-CPU (`sync::percpu`), since what
one CPU holds says nothing about what another may take.

Sleeping locks (mutex, rwlock, semaphore) sit above the scheduler and exist only in
builds that have one.

#### Epoch-based reclamation (`sync::epoch`)

Shared read-mostly data is reclaimed by epochs rather than by a full RCU. RCU's
quiescent-state tracking is deeply tied to the scheduler and idle loop, and that is not a
commitment to make before the SMP scheduler exists.

- **Participants.** One global epoch, and one participant per CPU in `PerCpu` storage.
- **Readers** `pin` a guard, which masks interrupts and records "active at epoch `g`". Every
  pointer loaded through `EpochPtr::load` stays valid until the guard drops.
- **Writers** unlink a node and `retire` it into their CPU's fixed-size limbo bag, stamped
  with the current epoch. Writers of one pointer are serialised by the caller's own lock;
  readers take none.
- **Advancing.** The epoch moves from `g` to `g + 1` only when every active participant is
  at `g`.
- **Reclaiming.** A node stamped `e` is reclaimed at `e + 2`. The two-epoch argument is
  written out in the module.
- **Nothing needs compare-and-swap.** State words are only loaded and stored, and
  advancing and the bags use a `LockFamily` lock. The same code serves rv32i. A
  uniprocessor collector has one participant, and reclaims at the second collection after
  its last unpin.
- **Stalls are reported, not leaked.** A CPU that stays pinned stops every reclamation.
  - After 64 consecutive advances held back by one CPU at one epoch, `Collector::stall`
    names it.
  - A retirement that finds its bag full, even after advancing and reclaiming, is
    refused. The caller keeps the node.
- **A full bag means wait; only a stuck reader is a fault.** The boot check's writer
  (`kernel/main/src/epoch.rs`) gives a refused node back and tries again. It unpins
  between attempts, because its own pin holds the epoch back as much as any reader's.
  - `stall` counts advances, not time. A writer retrying that fast names a reader the host
    has merely descheduled within milliseconds.
  - So a named CPU is judged by its own progress. A reader finishes one read per
    pin-and-unpin, and each finished read is counted. A CPU that finishes none for two
    seconds has stopped unpinning, and fails the check by name.
  - An attempt cap bounds the wait even when the clock never started.

**Eight CPUs needed both halves of the fix.** Eight emulated CPUs contended for the host
when both SMP ports ran at once. The writer's bag then filled before seven readers had all
observed the epoch, and a check that failed on the first refusal failed about half the
time.

- **Sizing was the smaller half.** The bag grew from a fixed eight to two per participant,
  floored at eight. It is capped by the boot stack: the collector is built there before it
  moves into its static, and at four per participant aarch64's 16 KiB boot stack
  overflowed into its guard page.
- **The check's premise was the larger half.** A writer that outruns reclamation must
  wait, and the first version of the wait tripped the stall report itself. That is why a
  stall is now judged by progress.

Checked on the host with real threads playing CPUs: a reader held across a concurrent
unlink, a stalled participant, and three readers racing a writer through 20 000
replacements. Checked at boot on every port: a pinned reader keeps its node through an
unlink and repeated collections. On `aarch64-virt-smp`, three secondaries run readers
inside their function-call IPI, because nothing else runs code on a secondary yet, while
the boot CPU makes 4 000 replacements. A node reclaimed one epoch early shows up there as
thousands of torn reads. What neither can prove is every interleaving, or weak memory
ordering: the `SeqCst` handshake between pinning and advancing is reviewed, not tested.

### `kobject` — the object and reference model

Every kernel-managed thing a userspace program can hold — a process, a channel
endpoint, a memory region, a device handle — is an object with an identity, a type
tag and a reference count, named through a handle that carries a rights mask. This is the
substrate the syscall layer exposes as capabilities; see
[userspace-abi.md](userspace-abi.md).

#### What exists today

- **Handle tables** (`kobject::handle`): generation-checked handles, rights that only
  narrow, and all-or-nothing transfer.
- **Identities** from an `IdSource`, which never repeats one. `ObjectIds` is a 64-bit atomic
  counter. `LockedIds` is the same counter behind a `LockFamily` lock, for rv32imac and
  thumbv7m, which have no 64-bit atomics.
- **The object store** (`kobject::store`): the step from a handle to the object it names.
  An `ObjectStore<T, L, N>` holds references to up to `N` objects of one type whose memory
  belongs to their owner, and calls the owner's `destroy` when an object's last reference
  is gone.
  - `insert(id, kind, &object)` adds an object, held by the store.
  - `get(id)`, `get_at(locator, id)` (O(1)) and `resolve(table, handle, kind, rights)` each
    return a counted `ObjRef` that derefs to the object.
  - `retire(id)` gives up the store's reference. Nothing new finds the object, holders
    keep it alive, and the last `ObjRef` to drop destroys it.
  - A slot's generation advances each time it is vacated, and a slot that would wrap is
    never reused, so a stale `Locator` cannot reach the next occupant.
  - Everything runs under one lock per store, with no allocation and no `unsafe`.
- **The kernel's object namespace** (`kernel/main/src/objects.rs`), the first user of the
  store: the objects a program can create and name.
  - **Kinds.** A program image, a process, a thread, an anonymous memory region and a
    completion queue, each an `Object` variant carrying only what the kernel must remember.
    Images and regions are both `ObjectType::MemoryRegion`.
  - **Storage.** One static arena of `Cell`s, each a spinlock around an `Object`, behind a
    single `ObjectStore`. There is no allocator here yet. A cell is claimed on creation and
    freed by the store's `destroy`, so it is reused only after its object is gone.
  - **Objects are global, handles are per-process.** An object's identity can appear in
    several tables. `process_transfer` moves that name into another process's table while
    the object itself stays where it is.
  - **Lifetime.** Closing a handle, or tearing down the process whose table held it, retires
    the object. It is destroyed once no reference remains, and `objects::live()` is the
    count a check compares against its baseline.
  - **The locking rule.** A cell's lock is never held while another's is taken; every cell
    shares one lock class, so `DEBUG_LOCKDEP` fails the boot if one ever is. Posting an exit
    reads the waiter under the process's lock, drops it, then locks the queue. Collecting
    thread ids for reaping copies them out under the cells' locks and reaps afterwards,
    because `thread_create` takes the scheduler's lock before a cell's.
  - **Channels** are kept in their own kernel table, keyed by their endpoints' identities, so
    an endpoint moved into another process still names its channel there. They are not yet
    store objects.

### `ipc` — channels

A channel is two endpoints with bounded inboxes. Sending moves handles, all or nothing.
A channel refuses to carry its own endpoints. Cycles through two or more channels are
collected by a `ChannelSet`, which owns its channels:

- **When it runs.** On every `close` or `release` through the set, a mark and sweep counts each
  endpoint's references against its copies queued in the set.
- **Mark.** Endpoints held from outside the queues are roots, and anything queued in a reachable
  inbox is reachable.
- **Sweep.** Unreachable inboxes are taken apart. Their endpoint entries are released, which
  closes the cycle, and other objects go to the caller's sink. Rounds repeat until nothing is
  left to take apart.
- **Exclusion.** Collection takes `&mut` on the set, so no send can run under it. Sends and
  receives still go through each channel's own lock.
- **Outside a set.** Channels used on their own still leak such cycles, as before.

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
- **x86_64 local APIC timer:** a 32-bit count at divide-by-16, measured against the TSC
  when the APIC driver is installed, and about 68 s at QEMU's rate. A 500 ms idle period
  takes one interrupt, and the `tickless` bound derived from the reach tightened from twelve
  interrupts to three.
- **x86 PIT (mode 0):** 16 bits, 54.9 ms. The same idle period takes nine interrupts,
  where a 10 ms tick would take fifty. i686 still uses it, and x86_64 falls back to it on a
  machine without a MADT.

The boot check `tickless` measures exactly this, and fails if an idle period takes more
interrupts than the hardware's reach requires. It also arms the full reach and requires no interrupt for 20 ms.
Before counting, it takes any interrupt an earlier arming already raised: a local APIC
latches a timer interrupt that fires while the CPU is masked, and rearming does not withdraw
it. Before that drain, one x86_64 SMP boot in fifteen reported a stale slice's tick as the
full arming firing early. Injecting a stale tick on purpose fails the check without the
drain and passes with it, and the aarch64 signed-reach bug still fails it.

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
- **Interrupt dispatch** crosses from `arch` to a driver in one of two modes, from one
  source. `arch::irq::dispatch_with` is generic over `IrqChip`. An image with several
  controller drivers calls it through the installed `&'static dyn IrqChip`, a vtable
  call per claim, identify and acknowledge. An image the configuration left with exactly
  one (`IRQCHIP_STATIC`, today aarch64 with `GIC_V2=n`) has the platform provider
  instantiate it for the concrete driver and export it as `kintane_irq_dispatch`, which
  the vector calls by name: no indirect call on the path, and a GICv3 acknowledgement
  that compiles to one instruction. See
  [portability.md](portability.md#buying-the-indirection-back-on-small-targets).

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
  - Not yet: `interrupt-map` nexuses (reported as an error) and `interrupts-extended`.
  - Nodes from other enumerators go through `tree::Builder`. Such a node's `Origin`
    borrows the record that describes it (a `pci::Function` or a `table::Described`), and
    its name, `compatible` list and register windows are that record's. Windows are CPU
    addresses the enumerator already read, so `mmio()` skips the `ranges` walk. Binding,
    claims and parent order work exactly as for device-tree nodes. A `Described` record
    may also carry a range of I/O ports and one interrupt line: `ports()` returns the
    range, and `interrupt()` returns a specifier whose one cell is the line itself, since a
    firmware table names the line rather than cells for a controller to interpret.
- **PCI.** `device::pci` enumerates buses through a `ConfigSpace` the platform provides,
  and is host-tested against a model bus whose BARs behave like hardware.
  - Buses are walked breadth first from the segment's first, following bridges, each bus
    at most once, so misprogrammed bus numbers cannot loop the walk. Function 1 and up
    are probed only when function 0 says the device is multi-function.
  - BARs are sized with memory and I/O decoding switched off, except on host bridges, as
    Linux does. 32- and 64-bit memory BARs, prefetchable ones and 16- and 32-bit I/O BARs
    are all handled. The command register is written without its status half, whose bits
    clear when written with ones. `verify_restored` checks afterwards that every BAR and
    decode bit reads what it read before.
  - A function's `compatible` list follows the Open Firmware PCI binding, most specific
    first: `pciVVVV,DDDD`, `pciclass,CCSSPP`, `pciclass,CCSS`. A chip driver and a class
    driver bind by the same rule as a device-tree driver.
  - Capabilities are walked during enumeration and recorded on each `Function`, bounded so
    a looping list is read once. A driver is handed the node and never the bus, so what it
    reads from its own capabilities has to survive enumeration; virtio uses them to say
    where in its BARs each register structure lives.
  - Not yet: resource assignment (BARs are read as firmware left them), MSI and MSI-X, and
    segments other than 0.
  - **INTx routing, decided per port.** A function's interrupt-line register holds the line
    firmware routed its pin to, and firmware routed it *for the 8259A*. Where the 8259A is
    the controller — i686 — that is the answer, so the platform wires it
    (`PCI_LINE_TRUSTED`), and `virtio-blk` takes its completions on it. Under the I/O APIC —
    x86_64 — a PCI pin arrives on a different input altogether: on q35 a global system
    interrupt from 16 up, level-triggered and active low, named only by `_PRT` in the ACPI
    namespace, which is AML. Wiring the register there would program an input nothing
    drives, and the device would look wired and time out. So PCI devices on x86_64 are
    left polled, and the boot says so. The two ways past that are an AML interpreter for
    `_PRT`, which Phase 7 needs for ACPI anyway, or MSI-X, which delivers straight to a
    local APIC and needs no routing table at all.
- **ACPI.** `boot/acpi` parses the RSDP, RSDT/XSDT, MADT, MCFG and the FADT's PM timer
  and reset register. There is no `unsafe`: physical memory is read through a trait.
  Every table's length is capped and its checksum checked before any field is read. A
  malformed MADT entry ends the walk with an error naming its offset, and an unknown
  entry type is skipped. Host tests run against the complete table sets of q35 and pc
  under SeaBIOS and q35 under OVMF (see `boot/acpi/src/testdata/capture.sh`). They check
  that every single-byte change to any table is rejected, that every truncation is an
  error, and that fuzzed tables with valid checksums never panic.
- **Binding.** The node's own `compatible` list decides specificity: its first entry that
  any driver knows wins. A disabled node binds nothing.
- **Resources.** An MMIO window, a range of I/O ports or an interrupt is claimed through
  the probe token and comes back as a handle that is not `Copy`. Overlapping windows, and
  overlapping port ranges, are refused, naming the holder. A failed probe releases exactly
  its own claims: claims are tagged per probe, not per node, so re-probing a bound node
  cannot strip the existing binding. `Registers` checks every access against the window,
  and `Ports` every access against the range. Ports exist only on the PC: a platform that
  does not give the ledger port storage refuses every port claim.
- **Phases as types.**
  - Only a probe produces `Bound`, and only a successful start produces `Started`.
  - Registering an interrupt handler requires `Bound`, plus an `IrqLine` claimed by that
    same binding. Enabling the handler requires `Started`.
  - Suspend, resume, stop and remove move between the tokens. Their default
    implementations are trivial, but they are in the interface.
  - Unregistering a handler requires `Bound` and a handler that is already disabled, so the
    removal order — disable, stop, unregister, remove — is the only one that works.
- **Interrupt dispatch.** Device interrupts reach drivers through the device model's
  handler table, `device::Handlers`:
  - A driver says which line it wants through `Driver::interrupt()`: the `IrqLine` it
    claimed at probe and the function to run. After the driver starts, the platform
    translates the specifier with the machine's controller, registers and enables the
    handler in the table, and only then unmasks the line at the controller. A line is
    never live before its handler is.
  - `arch` is below `device` and cannot name the table, so each architecture's interrupt
    path calls a function the platform installs once at discovery
    (`arch::irq::set_device_dispatch` on aarch64, `arch::interrupt::set_device_dispatch`
    on the PCs). Everything that is neither an IPI nor the architecture's timer goes
    there: GIC SPIs on aarch64, I/O APIC lines on x86_64 (with the MADT's source overrides
    applied by the controller), 8259A lines on i686.
  - The table lives in the platform, behind a spinlock of class `platform.handlers`,
    because a device interrupt can be taken on any CPU and removing or rebinding a device
    changes the table. Dispatch copies the handler out and **runs it with the lock
    released**, so a handler may touch the table without deadlocking and a slow handler
    does not stall other CPUs' dispatch.
  - The rules a handler lives by: it runs in interrupt context on the CPU the line is
    routed to, with that CPU's interrupts masked; it must not block or allocate; and it
    may assume one instance of itself at a time only because every line is routed to one
    CPU today (all SPIs to CPU 0, all I/O APIC lines to the boot CPU). A driver whose line
    could reach two CPUs at once needs its own lock.
  - An interrupt that finds no enabled handler is counted and its line masked. A
    level-triggered source nobody quiets would otherwise be re-delivered at once and hold
    the CPU; registering a UART's handler for the wrong line found exactly that hang.
- **Drivers.** `drivers/irqchip/gic` holds GICv2 and GICv3, moved out of `arch/aarch64`.
  The serial drivers receive on interrupt, into a single-producer, single-consumer byte
  queue (`device::Fifo`) that a kernel thread reads, and transmit polled, because a console
  must be able to report a fault with nothing to wake it:
  - `drivers/serial/pl011` takes its window and baud divisors from the tree, and its
    receive interrupt (RX and receive timeout) from the node's `interrupts`.
  - `drivers/serial/uart16550` drives a 16550 through a claimed port range. Its start
    checks the part answers through the scratch register before it drives it. Its state
    is kept per binding, so a removed device can be bound again, up to four times a boot.
  - Both are transmit-only on a machine without atomics, where there is no queue to share
    with a handler; `kbuild portability` compiles them for rv32i that way.
  - The early consoles in `arch` stay, because they must work before anything is
    discovered. ARMv7-M's CMSDK UART and riscv32's 16550 are still arch-side; riscv32's
    interrupt controller is someone else's work in progress, and the dispatch seam is what
    its driver will plug into.
- **Platform.** A platform is the one unit that sees both the drivers and the
  architecture. It is layer `kernel`, because only the image may name `arch`.
  `kernel/platform/fdt` serves aarch64 and `kernel/platform/acpi` the PC ports, and
  `kernel/platform/none` is left for a port with nothing to enumerate.

On a PC, `platform/acpi` does the following, before the kernel address space exists:

1. **Finds the RSDP.** It comes from `kinboot-efi` through the boot protocol, or from a
   scan of the EBDA and the BIOS area.
2. **Records the MADT.** Processors become `cpu@N` nodes under `cpus`. The local APIC and
   each I/O APIC become nodes with their register windows.
3. **Records each MCFG segment** as a `pci-host-ecam-generic` node, the same binding the
   hardware has in a device tree.
4. **Enumerates PCI**, through ECAM on q35 or configuration mechanism #1 on pc, and puts
   every function under its host node or its bridge.
5. **Binds the interrupt controllers.** On x86_64 the local APIC and I/O APIC drivers
   (`drivers/irqchip/apic`) bind the MADT's nodes. The platform then builds the controller
   with the MADT's ISA source overrides, measures its timer against the TSC, and installs
   it in the architecture's interrupt path (`arch::interrupt::set_chip`) and tick
   (`arch::tick::set_event_timer`). On i686, placeholder drivers claim the same windows and
   drive nothing. That port keeps the 8259A and the PIT, because its interrupt path has no
   controller seam and it has no second CPU for an APIC to start. The ECAM window is claimed
   by a placeholder on both.
6. **Declares the serial port.** COM1 at ports `0x3f8`–`0x3ff` on ISA IRQ 4 is described
   only in AML, so the platform declares it as a `LegacyUart` record, compatible
   `ns16550a`. The 16550 driver binds it, and its start refuses if nothing answers there.
7. **Wires device interrupts**, after the controller is installed: it runs
   `arch::interrupt::init` first (on i686 that is what masks the 8259A, and a line
   unmasked before it would be masked again), installs the dispatch function, and wires
   each started driver's line through the table and the controller.

x86_64's boot identity map was widened from 1 GiB to 4 GiB for this, so that discovery
reaches the MMIO hole below 4 GiB. Discovery also moved ahead of the paging check, whose
tables map only the first gigabyte. On those tables, discovery read RAM aliases where the
ECAM window should be, and found 32 functions, all of vendor zero.

With `QEMU_PCI_TEST_DEVICE`, which every x86 preset sets, discovery also checks what
QEMU's machines are:

- the host bridge at `00:00.0` is the Q35 MCH when there is an MCFG, and the i440FX
  otherwise;
- the MADT lists exactly `QEMU_CPUS` enabled processors (two);
- `pci-testdev` is found behind the bridge kbuild adds, with its 4 KiB memory BAR and
  256-byte I/O BAR sized exactly.

A failure prints why and keeps the kernel address space from being installed, as on
aarch64.

Boot departs from the diagram below in one place: devices are enumerated **before** the
kernel address space is built, because that space maps exactly the windows the bound
drivers claimed. Discovery runs on the boot identity map, which covers every device. On
aarch64 it ends by installing the GIC as the interrupt path's controller.

It then wires each started driver's interrupt through the handler table, after the GIC is
installed: today that is the PL011's receive interrupt, SPI 1 (line 33).

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

### Driver isolation — the Phase 5 prototype

Phase 5 promises that the same driver source runs in the kernel or confined to a domain of
its own. The prototype makes that claim executable on aarch64, with `DRIVER_ISOLATION`, on
every boot.

**Where the shared code has to live.** A domain is an unprivileged program, and a user
program may link only `user`-layer crates. That rule is enforced by kbuild, and it is why
`abi` sits there. So everything a driver body touches in *both* modes lives at that layer
too, and `device`-layer crates cannot be the driver — at most, they can be the glue that
binds one:

- **`lib/hwproxy`** is the proxy layer the roadmap names. `Regs` is register access, `Dma` is
  memory the device addresses (kept apart from the CPU's addresses by type), and `Irq` is an
  interrupt as a count. A driver takes one `Hw` and never names a pointer or a controller.
  Its accessors refuse an out-of-bounds or misaligned access *silently*, where the device
  layer's accessors `debug_assert!`. A window may be handed to a driver the host does not
  trust, and a bad offset from one must be something it observes, never a way to panic
  the host.
- **`drivers/virtio-probe`** is the driver body: it reads a `virtio,mmio` slot's four
  identification registers. It is small on purpose, because what is under test is the
  boundary rather than the driver.
- **`user/hwdomain`** is the domain program: it links `abi`, `hwproxy` and `virtio-probe`,
  and nothing else.
- **`kernel/main/src/isolation.rs`** runs the body twice over one physical window. The first
  run is in the kernel, over the kernel's identity mapping of the window. The second is in a
  domain whose address space holds its program, its stack, one page shared with the kernel
  for the report, and that window. Both reports must agree.

**What the boundary is made of.** The window is *mapped into* the domain, so a register
access there is the same load the kernel executes, in ring 3 / EL0. The MMU is the proxy,
and isolation costs at the edges rather than per access. `platform/fdt` grants an
*unoccupied* slot, recorded during the enumeration scan it already makes. It is mapped like
any claimed window, and it keeps the disk's slot out of an unprivileged grant. A slot is
0x200 bytes and the MMU grants pages, so the domain is given the page that holds the window:

- the proxy bounds the driver to the device's own 0x200 bytes;
- the MMU bounds it to the page.

A domain that reads the page after its grant is killed, the kernel continues, and every
frame comes back.

Matching registers are not enough on their own. Every unoccupied slot answers the same
four identification values, so the check's first falsification granted the neighbouring
empty slot and passed. A domain that succeeds therefore also has its grant audited: its
window's address must translate, in the domain's own page tables, to exactly the physical
window the platform recorded.

**What the aarch64 prototype does not show.** The subject device does no DMA, and without an
IOMMU a domain granted a DMA-capable device could program it to read or write any physical
address anyway. Confining DMA is what the IOMMU below adds.

### DMA confinement — the VT-d IOMMU

An `IOMMU` build (x86_64, the `x86_64-iommu` preset) puts the disk — the one device here that
reads and writes memory on its own — behind an Intel VT-d IOMMU, so a device address that its
driver was not granted *faults in hardware* instead of reaching memory. This is what an
isolated DMA-capable driver's containment rests on, demonstrated in the kernel:

- **`boot/acpi::dmar`** reads the DMA remapping table for each hardware unit's register base — the
  one place that names it.
- **`drivers/iommu/vtd`** programs a unit: a root table, per-bus context tables, and a four-level
  second-level page table per translation [`Domain`]. It maps a grant (4 KiB leaves, or 2 MiB
  superpages where a range allows), attaches a device by its PCI source id, enables translation
  with the spec's SRTP/invalidate/TE sequence, and reads faults back from the log. The whole
  driver is plain logic over three traits — registers, a frame source, physical memory — and is
  host-tested against models of each; the `unsafe` that turns a physical address into a load is
  the kernel's, in `kernel/main/src/iommu.rs`.
- **`kernel/main/src/block.rs`** builds a domain that maps *exactly* the disk's DMA grant and
  nothing else, attaches the disk, and turns translation on before the device does any DMA. The
  block check then runs with every DMA translated, proving an in-grant DMA still works; a
  deliberate out-of-grant DMA is stopped and read back from the fault log; and the faulted
  device is reset and brought up again so it serves once more.

The driver source does not change: `virtio_blk_core` puts physical addresses in descriptors and
accepts `VIRTIO_F_ACCESS_PLATFORM`, and behind the IOMMU those addresses are the I/O virtual
addresses the grant maps identity. Measurements, the interrupt-as-a-message gap, and the
still-missing x86_64 *domain* (as opposed to in-kernel) driver are in
[isolation.md](isolation.md).

### `block` — the block layer, and the first driver with DMA

`kernel/block` is what a storage driver implements and the bookkeeping above it. It does
not allocate, cache or block:

- **`BlockDevice`:** geometry, a per-request transfer limit, `read_blocks`, `write_blocks` and
  `flush`, all `&self` and fallible.
- **`Geometry::range`:** the range and alignment check every driver needs, including the
  overflow of a request that starts near `u64::MAX`.
- **`block::read` / `block::write`:** split a transfer larger than the device takes into pieces
  that cover the buffer exactly once.
- **`Queue<N>`:** fixed-capacity request tracking with generation-checked tickets. Its counters
  balance, `issued == completed + in_flight`, which the boot check and the stress audit both
  assert. A request whose outcome is recorded but not collected is no longer in flight.

It is host-tested against a RAM disk that fails on request.

#### virtio-blk (`drivers/block/virtio-blk`)

virtio 1.x over two transports: memory-mapped, bound from the device tree on aarch64, and
PCI, bound from enumeration on the PCs. The device's protocol is written once against the
`Transport` trait, and each transport is only where its registers are. It is the first
driver that hands a device *addresses*:

- **`mem::Dma`** carries a region's physical and virtual addresses and keeps them apart. A
  descriptor takes `Dma::phys`, and the CPU dereferences `Dma::virt`. Host tests place the fake
  device's memory at a different offset from the driver's, so handing it a virtual address fails
  on a laptop rather than in an emulator.
- **No IOMMU yet.** The device can reach all of memory. With Phase 5's IOMMU, `Dma` becomes a
  grant of a range to one device, and `phys` becomes a device address. Nothing above `mem` changes.
- **Split virtqueue** (`queue::Ring`): the driver fills descriptors and the ring entry, then
  publishes `avail.idx` with a release fence before it. It reads `used.idx` with an acquire
  fence before reading the element that index names. QEMU cannot show either fence missing.
  Both are argument in the sense of [memory-model.md](memory-model.md), following virtio 1.1
  §2.6.13.
- **Enumeration is not probing.** QEMU's `virt` lists thirty-two `virtio,mmio` slots whether
  or not anything is plugged in, and only a slot's `DeviceID` register says which is occupied.
  The platform reads it during discovery, as `pci::enumerate` reads configuration space, and
  binds the driver to the slot holding a block device. The driver's probe keeps its rule of
  touching no hardware.
- **Bring-up waits for memory.** Discovery runs before the frame allocator exists, and the
  handshake ends by handing the device queue addresses. So the driver's `start` does nothing,
  and the kernel calls `VirtioBlk::bring_up` once it has a DMA region to give. An untouched
  virtio device is quiescent.
- **Completion by interrupt, and several requests at once.** Each request owns a slot: its own
  header, status byte and bounce buffer, so requests in flight cannot overwrite each other.
  A request is submitted under the device's lock and waited for *without* it, because the
  lock is what the interrupt handler takes to collect a completion; held across the wait,
  it would mask the device's interrupt and every completion would be polled. Completions
  are matched to slots by the head descriptor the used element names, since the device
  answers in whatever order it likes. Where a line is wired, the handler acknowledges the
  device and drains the ring; where none is, the waiter drains it itself, to a bounded
  limit, and a device that stops answering is `Error::Timeout`, not a hang. A request that
  timed out keeps its slot, because a late completion would write into its buffers.
  `IN_FLIGHT` is four, and a build-time assertion holds `QUEUE_SIZE` to three descriptors
  for each: a queue of eight, which this was, fits only two full chains, and nothing short
  of three requests outstanding together would show it. Waiting with the lock released
  doubled the disk's throughput under stress on aarch64 (the numbers are in
  [testing.md](testing.md#2b-block-storage)).
- **A bounce buffer.** Data is copied through a buffer inside the DMA region, so a caller's
  buffer need not be physically contiguous. That costs a copy, and bounds a request by the
  buffer, which is what `max_transfer_blocks` reports and `block::read` splits around.
- **Legacy devices are refused.** QEMU's memory-mapped transport presents the legacy
  register layout by default, so test runs pass `virtio-mmio.force-legacy=false`. A legacy
  slot is reported as one during discovery.

**The PCI transport** (`pci::Pci`). A PCI virtio device does not have its registers at a
fixed layout: vendor-specific capabilities name a BAR, an offset and a length for each of
the common, notification, interrupt-status and device-configuration structures. Those
capabilities are read from the `Function` enumeration recorded, since a driver cannot
reach configuration space, and every structure is required to sit in one BAR, because one
window is what a probe claims and the kernel maps. A capability names a BAR by its own
number while `claim_mmio` counts only memory BARs; they differ on a transitional device,
whose BAR 0 decodes I/O, and `Function::memory_bar_index` is the translation. Test runs
attach the device with `disable-legacy=on`, for the same reason the memory-mapped transport
needs `force-legacy=false`.

**A BAR in the user half, and the device window that fixed it.** OVMF puts a 64-bit BAR
near the top of the CPU's address width — at 768 GiB under TCG, which is inside x86_64's
user half, `[512 GiB, 1 TiB)`. While the kernel mapped every claimed window at its physical
address, that BAR landed in a top-level entry every process root mirrors, so all processes
built their pages into one table and two workers read each other's memory. For a round the
boot refused to build processes over such a mapping and the EFI test machine ran with
`phys-bits=36` to keep the BAR low. Device windows are now mapped in the device window above
the user half (see [the kernel's own address space](#the-kernels-own-address-space-as-built-today)),
the EFI machine runs at TCG's full 40 bits with the BAR at 768 GiB on purpose, and
`userproc::user_half_clear` stays only as a backstop behind the post-install check.

**The check** (`kernel/main/src/block.rs`, on presets with `QEMU_BLOCK_TEST`) brings the
device up on eight frames and gates the boot on the following:

- the disk's header naming the geometry the device reported;
- 32 sectors reading back kbuild's pattern through a split read;
- a scratch-area write reading back after a flush, with the sector below it untouched;
- a read past the end refused by the driver;
- the same read with the driver's check skipped refused *by the device*, and returned as
  an error;
- nothing in flight and every descriptor back on the ring after 64 more requests.

A second check, `block irq`, runs once interrupts are enabled, where the port wires the
disk's line (aarch64 and i686). It puts the driver in interrupt-driven mode, in which a
waiter never drains the ring, and requires 32 reads to return the pattern with every
completion collected by the handler and none polled. On x86_64 it is skipped, and says the
disk is polled.

The started device lives on for the stress run's two block workloads, which must be seen
outstanding together at least once in a run.

### `vfs`, `bcache` and `fat` — files

Three units above the block layer, each at the `subsystem` layer, each host-tested, and each
compiled by `kbuild portability` for the machines with no atomics:

- **`vfs`** is the namespace: a mount table, path walking, and a table of open files, over a trait
  of five operations a filesystem implements — `lookup`, `stat`, `read_at`, `write_at` and
  `readdir`, all by an opaque `NodeId`. Both tables are fixed arrays and a filesystem is borrowed
  rather than owned, so nothing allocates and the kernel mounts a volume during bring-up. A handle
  carries a generation, as an object handle does, so a closed one cannot name the file that takes
  its slot. `.` and empty components resolve; `..` does not yet. `vfs::memfs` is the in-memory
  reference filesystem the namespace's own tests run against.
- **`bcache`** caches whole blocks between a filesystem and a device: fixed slots from the caller,
  least-recently-used replacement, and **write-through**. A write goes to the device first and
  updates the cached copy only if the device took it, so the cache is never the only place a byte
  lives, nothing is lost that a flush would have saved, and `flush` is the device's own. A
  write-back cache would be faster and would need an ordering policy and a story about what a
  crash loses; neither is worth inventing before something writes enough to measure. The cache's
  books — every miss read the device exactly once, no block held by two slots — are checked by
  `Cache::check`.
- **`fat`** is FAT16, read-only. FAT rather than a format of our own because the tree already
  writes it twice — the ESP and the test disk, both through `kbuild/src/fat16.rs` — and
  `kinboot-efi` already reads it. The type is decided by the cluster count, as the specification
  says, and a volume outside FAT16's range is refused by name. Every boot-sector field, every
  cluster number and every chain step is checked before it is used, and a chain walk is bounded,
  so a corrupt volume is an error rather than a hang.

**The VFS as a service over channels**, which Phase 6a describes, is a wrapper that has not been
written: a server would decode a message into one of the namespace's calls and encode what came
back. Nothing in `vfs` knows about channels, processes or rights, so nothing there has to change
when it arrives — and the kernel can read a volume long before a channel exists.

**Where a volume lives.** The test disk (`kernel/block/src/testdisk.rs`, version 2) has three
regions: the pattern sectors the block check verifies, the scratch area tests may overwrite, and a
4 MiB FAT16 volume from `FS_START`. The scratch area sits between the other two so every sector the
block check and the block workload read is still the pattern exactly as it was. kbuild places
`/HELLO.TXT`, the 200-cluster `/BIG.BIN`, `/SUB/NESTED.TXT`, and — when the configuration links a
user program — that program at `/KINTANE/INIT.ELF`.

**Loading a program from a disk.** The boot `fs` check reads `/KINTANE/INIT.ELF` from the volume
into frames it keeps, runs it once, and only after it exits with the success code makes it the
program `userproc::program()` returns. So on a machine with the disk — aarch64 today — the
scheduled process check and the stress run's process cycles run the copy read from the disk. The
copy embedded in the image is still what the sequential userspace slice runs, because that slice
runs before the disk is brought up, and what every machine without a disk runs.

### `sched` — scheduling

Pluggable policy behind a trait, with the config selecting one or more:

- A fixed-priority preemptive scheduler for real-time and embedded builds; on
  single-CPU no-MMU targets this is the whole scheduler and it is small.
- A general-purpose fair scheduler with per-CPU runqueues, load balancing, and idle
  balancing for SMP builds.

Per-CPU data is `sync::PerCpu`, a `HasSmp`-gated abstraction; a uniprocessor build
gets one slot, which is a plain static with an index of zero. See [SMP](#smp) below.

#### What exists today

The fixed-priority scheduler runs on x86_64, i686, aarch64 and riscv32, and on every CPU
of `aarch64-virt-smp` (see [the SMP scheduler](#the-smp-scheduler)). It is three pieces,
split where the knowledge actually is:

- **`kernel/sched`** is the policy: 32 priority levels, round robin within a level,
  and the highest runnable level always wins. Its `balance` module decides, for a
  multiprocessor, which CPU's queue a thread joins. It depends on nothing.
- **`hal::HasContextSwitch`**, implemented in each `arch/<name>/context.rs`, is the
  mechanism: save the callee-saved registers, load another thread's.
- **`kernel/thread`** binds the two into a thread table with five checked invariants,
  and one run queue per CPU (one, by default). The operations that switch (`yield_on`,
  `block_on`, `exit_on`) take a raw table pointer and do their bookkeeping under a
  reference that ends *before* the switch. A thread is suspended in the middle of such
  a call, and the thread that resumes calls into the same table; with `&mut self` that
  is two live exclusive references to one object.

**Preemption is `yield_now` called from the timer interrupt.** Each port's `tick`
module drives a one-shot timer (the local APIC timer on x86_64, PIT mode 0 on i686, the
generic timer on aarch64) and
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

1. **EOI before the hook.** Otherwise the 8259A's or local APIC's in-service bit, or the GIC's running
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
   explicitly in thread code, and on a multiprocessor the scheduler lock is held too. A
   new thread starts masked, because a switch always happens masked, and unmasking is its
   first act.

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

**The array is sized by configuration, not by each linker script.** Two symbols decide it:

- `THREAD_STACK_KIB` is one slot, guard included, and must be a power of two.
- `KERNEL_THREAD_SLOTS` is how many kernel threads may hold a stack at once.

The port reserves `KERNEL_THREAD_SLOTS` plus one slot per secondary CPU, because each
secondary comes up on a stack of its own and keeps it as its idle thread. kbuild computes
that count once (`codegen::stacks`) and writes it into `stacks.ld` beside `config.rs`.
Every port's `link.ld` includes the fragment, and each arch crate reads the slot size from
`kconfig`, so the linker and the kernel cannot disagree.

A count written by hand into each script is what stopped an eight-CPU stress run from
starting its workloads. Twelve slots covered four CPUs, but the secondaries' seven took
most of them at eight. Two checks now happen at build time rather than at run time:

- `kernel/main/src/preempt.rs` asserts that `KERNEL_THREAD_SLOTS` covers the threads its
  checks and the stress run need.
- Every `link.ld` asserts that the slot size is a power of two with room above its guard.
  ARMv7-M also asserts an even count, since one MPU region covers two slots.

A uniprocessor build now reserves eight slots instead of the twelve the SMP-capable ports
had hard-coded, which is 128 KiB less RAM.

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
  `preempt::resume`, which re-enables the one-shot timer with the scheduler's hook,
  hands every started secondary to the scheduler, and unmasks. Boot is then one thread
  among the others, at the priority the checks gave it, and idle is still in the table.
  - A normal image then has boot sleep, printing `uptime N s` every ten seconds. That
    is how a boot with no result channel shows it did not just halt.
  - A `STRESS_TEST` image makes boot the stress auditor instead
    ([testing.md](testing.md#3a-stress)).

A failed bring-up never starts the scheduler: it halts, or exits with the failure.

Not yet:

- A stack is never given back to the port when its thread exits; the scheduler reuses
  the slots it claimed. i686 and riscv32 reserve eight: the boot checks claim four, and
  the stress run four more. aarch64 and x86_64 reserve twelve, and the extra four are for
  the stacks of secondary CPUs.
- Nothing creates threads except the checks and the stress run.
- Boot keeps its boot-check priority for good, which is above every stress workload.

### SMP

Phase 3 has started on aarch64 and x86_64. With `SMP=y`, the boot CPU starts every CPU
firmware lists (the device tree's `/cpus`, or the MADT's enabled processors), up to
`NR_CPUS` and the port's `HasSmp::MAX_CPUS`. Each one it starts runs an idle loop until the
scheduler is handed every CPU after bring-up, and from then on each schedules threads from
its own run queue ([the SMP scheduler](#the-smp-scheduler)). Both ports reach the scheduler
through the same `hal::HasIpi`.

**A CPU's number.** Hardware names a CPU sparsely: an MPIDR on Arm, an APIC ID on x86.
The kernel names it densely, 0 being the boot CPU, because per-CPU storage is an array.
`hal::Arch::cpu_index` answers "which CPU am I" on every port. It defaults to 0, and a
port that starts a second CPU overrides it. `HasSmp::cpu_id` returns the same number.
On aarch64 the answer is read through `TPIDR_EL1`, which each CPU points at its own
block in `arch/aarch64/src/smp.rs`. On x86_64 it is read through `GS`: `MSR_GS_BASE` holds
the address of the CPU's block in `arch/x86_64/src/smp.rs`, whose first field is the
index, and both boot entries set the boot CPU's before any Rust runs, because lock-order
checking asks for the number inside the first lock taken.

**Per-CPU data.** `sync::PerCpu<T, N>` holds one `T` per CPU. Its constructors are the
gate:

- `PerCpu::new::<A: HasSmp>` refuses at build time a storage with fewer slots than
  `A::MAX_CPUS`.
- `PerCpu::uniprocessor::<A: UniProcessor>` has one slot.

A slot is reached only through a `sync::Pinned<A>`. It masks interrupts *before* it
reads the CPU number, and the reference borrows from it, so a slot cannot be used after
a preemption that might have moved the thread. Every slot must be `Sync`, so a port that
got its CPU numbering wrong causes a logic error the bring-up check looks for, never
undefined behaviour. Lock-order checking keeps each CPU's held-lock stack in one.

**Bring-up** (`arch/aarch64/src/smp.rs`, driven by `kernel/platform/fdt/src/smp.rs`):

1. The platform reads `/cpus` (`device_type = "cpu"`, `reg` as the MPIDR) and the PSCI
   node's conduit (`hvc` or `smc`) during discovery.
2. For each CPU, `smp::start` claims a guarded thread-stack slot named after the CPU and
   captures the boot CPU's `MAIR_EL1`, `TCR_EL1`, `TTBR0_EL1` and `SCTLR_EL1`. It then
   calls PSCI `CPU_ON` with `__secondary_entry` and the CPU's block as the context.
3. The secondary descends from EL2 if firmware started it there. It takes its stack,
   sets `TPIDR_EL1`, loads the boot CPU's translation registers, enables its MMU on the
   one kernel address space, and installs its vectors.
4. It prepares its part of the interrupt controller through `IrqChip::init_cpu`. On a
   GICv3 that is its own redistributor, found by `GICR_TYPER` affinity, woken, and
   refused if it will not wake, plus the ICC system registers. On a GICv2 it is the
   banked CPU interface and SGI/PPI priorities.
5. It enables its two IPIs and its generic timer at 100 Hz, and reports in.

**Bring-up on x86_64** (`arch/x86_64/src/smp.rs`, driven by
`kernel/platform/acpi/src/smp_x86_64.rs`, with the INIT and startup IPIs sent by
`drivers/irqchip/apic`):

1. Discovery records every processor entry in the MADT (APIC ID, enabled) and installs the
   local APIC and I/O APIC.
2. For each enabled processor, `smp::prepare` claims a guarded thread-stack slot named after
   the CPU. It copies the real-mode trampoline to physical page `0x1000`, the first page
   above the never-mapped page 0, which the frame allocator never hands out. It captures
   the boot CPU's `CR4`, `CR3` and `CR0` for the entry. The driver sends INIT, waits
   10 ms, and sends up to two startup IPIs with vector 1.
3. The trampoline enters protected mode, then long mode on the bootstrap tables `boot.rs`
   built. Those identity-map 4 GiB with every page executable, where the kernel's own
   tables map low memory as data only. It sets `EFER.NXE` when the boot CPU has it, and
   jumps to `__ap_long_mode_entry` in the kernel's text. That loads the captured control
   registers, so the CPU joins the one kernel address space, points `GS` at its block, and
   takes its stack.
4. In Rust the secondary loads its own GDT and TSS, which carry its own #DF IST stack
   (8 KiB, where the boot CPU's is 16 KiB), and the shared IDT. It prepares its local APIC
   through `IrqChip::init_cpu` (x2APIC mode when CPUID has it, MMIO otherwise), starts its
   local APIC timer periodic at 100 Hz, and reports in.

**IPIs** on x86_64 are fixed-delivery interrupts on vectors `0xF0` (function call) and
`0xF1` (reschedule) and `0xF2` (TLB shootdown), addressed by APIC ID, which `init_cpu`
returned on the target.
`arch::smp::send(cpu, IPI_CALL | IPI_RESCHEDULE | IPI_TLB)` has the same names and
meaning on both ports. It raises one IPI and returns without waiting, from any CPU. The local APIC timer is vector `0xEF` and the spurious
vector `0xFF`. Device lines stay on 32..48, routed through the I/O APIC, so the per-line
entry points serve the 8259A and the I/O APIC alike.

**IPIs** on aarch64 are SGIs. SGI 0 runs a function on the target, SGI 1 is a reschedule, and
SGI 2 is a TLB shootdown. `IrqChip::send_ipi` takes the routing token the target's
`init_cpu` returned: an affinity value on a GICv3, and a CPU interface bit on a GICv2,
which routes by interface number rather than MPIDR. A GICv2 SGI is acknowledged with its
sender, so `claim` keeps it and `IrqChip::id` strips it.

**The check.** On the `aarch64-virt-smp` and `x86_64-qemu-smp` presets, the `smp` line
in the banner gates the exit status. It requires all of the following:

- firmware lists exactly `QEMU_CPUS` CPUs;
- each CPU reports its own number through both interfaces, asked on itself;
- on x86_64, each CPU's local APIC reports the APIC ID it was started for, no two alike,
  and each has its own GDT, TSS and #DF stack loaded, read back with `sgdt`;
- each secondary takes its own timer interrupts. On x86_64 the rate must also be within a
  factor of two of 100 Hz over a 200 ms TSC window, because the kernel calibrated that
  timer itself;
- a function-call IPI reaches each secondary, runs there, and a reschedule IPI comes
  back;
- each CPU's `PerCpu` counter holds its own count;
- one CPU holding a lock while another takes a second one records no ordering between
  them, which a shared held-lock stack would.

These mutations each made the aarch64 boot fail:

- two CPUs sharing a block;
- IPIs sent to the boot CPU's token;
- every CPU programming the first redistributor;
- a skipped redistributor wake;
- a single lock-order stack;
- a `-smp` smaller than the configuration.

And these the x86_64 one:

- every secondary's `GS` pointing at the boot CPU's block: `ids 0 WRONG(1) WRONG(2) WRONG(3)`,
  and every IPI lost;
- IPIs sent to the APIC ID after the target's: `ipi 0/3`;
- INIT and startup IPIs sent to the APIC ID after the intended one: a CPU never reports in,
  and the others come up under the wrong logical numbers;
- the trampoline never copied: no secondary reports in;
- every secondary loading CPU 0's GDT and TSS, which `ltr` accepts once the descriptor is
  rewritten as available: `ids 0 WRONG(1) WRONG(2) WRONG(3)`. This one passed until the
  `sgdt` read-back was added;
- the timer's rate read ten times slow: the secondaries tick 132 times in 200 ms, and the
  `tickless` check takes 39 interrupts;
- the timer's rate read ten times fast: `preempt` sees 3 interrupts in 302 ms, and the run
  hangs in the sleep phase until the harness times out;
- the source overrides ignored, with IRQ 0 routed to GSI 0 instead of 2: `IRQ0 0 of 3 ticks`
  and a failed `clock` line.

The skipped wake is only visible because `init_cpu` refuses a redistributor that stays
asleep: QEMU delivers to one anyway.

#### What a port provides: `hal::HasIpi`

The scheduler and the shootdown reach other CPUs only through `hal::HasIpi`, so a second
SMP port plugs in by implementing it:

- `cpu_online` and `send_ipi`, with `Ipi::Call`, `Ipi::Reschedule` and `Ipi::TlbFlush`;
- `call_on`, the boot-path function call;
- `set_tlb_flush_handler`, which the port runs for every `Ipi::TlbFlush`;
- `set_tlb_shootdown`, which the port's `flush_tlb` calls after invalidating locally;
- `flush_tlb_local`, the invalidation a shootdown target makes;
- `release_secondaries`, which hands every started CPU to the scheduler's entry point.
  From then on the port runs the scheduler's hook after that CPU's timer interrupts and
  reschedule IPIs, exactly as after the boot CPU's timer interrupts.

The kernel side is `kernel/main/src/mp_smp.rs`, selected by `SMP` with the paged memory
model. A kernel without them gets `mp_up.rs`, which is one run queue, no lock, no IPIs
and no shootdown, so a uniprocessor build pays for none of this.

#### Address spaces follow threads

A thread that runs user code carries its address space in its saved context, with its
kernel stack (`hal::HasUserMode::bind`). The port's context switch loads it: on x86_64 the
switch installs the kernel stack in the running CPU's `TSS.rsp0` and `syscall` stack and
loads `CR3`; on aarch64 it loads `TTBR0_EL1`. A kernel thread carries no space and runs on
the kernel's, so no kernel thread ever runs on tables a process might free. The switch
writes the root only when it changes, so a switch between kernel threads costs one register
read. The binding is made under the scheduler lock in the same critical section that
creates the thread (`preempt::spawn_prepared`), because the switch is what loads the space:
bound any later, another CPU could take the thread first and enter it on the wrong tables.

**The TLB: no ASIDs or PCIDs, and why.** A change of root invalidates. On x86_64 the `CR3`
write drops every non-global translation. On aarch64 the kernel is also mapped through
`TTBR0`, so there is no split to lean on, and `set_root` ends with `tlbi vmalle1is`. That
is correct with the fewest moving parts at the point where a process's pages can be freed
while another CPU still ran it. ASIDs and PCIDs are an optimisation with a correctness
obligation of their own: a recycled identifier must never meet translations its previous
owner left. They should be adopted once measured, not before. The cost is real, and on
aarch64 it is the first thing to replace: the flush is a broadcast, so every switch between
processes reaches every CPU's TLB.

**Interrupts from user mode.** Before processes ran on the scheduler, nothing at EL0 was
ever interrupted. On aarch64 the "lower EL, IRQ" vector now goes to the same dispatch as
the kernel's own IRQ vector. `SP_EL0`, which the CPU banks rather than saves, is kept in
each exception frame. A timer tick that switches threads returns to user mode in a
different process, and each frame must restore the stack pointer its own `eret` needs.

**Moving a thread interrupts its new CPU.** `preempt::set_affinity` sends a reschedule IPI
to the CPU the thread is on after the table moves it. Without it, a thread queued on an idle
tickless secondary waited for that CPU's next timer interrupt, up to one full arming
(2.15 s on aarch64). The stress run's process cycle found this as a process that did not
stop within its one-second drain.

That covers a thread the table moves while it is queued. A thread that is *running* when
its affinity changes keeps its CPU until it next yields, and `plan_yield` then re-queues it
where `sched::balance` places it — the one placement path that used to name its destination
to nobody. `Threads::yield_on_with` now hands that CPU back to the caller, which interrupts
it, because an idle CPU is asleep and nothing else was going to tell it. Until this, an
eight-CPU stress run left its user process ready on exactly the CPU it had been pinned to,
unscheduled for the whole second the check allows, while four CPUs sat idle. Four CPUs hid
it: with the workloads filling every run queue, the destination was never an idle CPU.

#### The SMP scheduler

After bring-up, `preempt::resume` releases every secondary into `preempt::join`, where
the code running on it becomes that CPU's idle thread in the one thread table.

- **One lock, held across the switch.** The table has a run queue per CPU and one lock,
  `sched.table` (`mp_smp.rs`). The thread that switches away takes it, and the thread
  the switch resumes releases it, or `thread_start` does for a thread's first run. Held
  any shorter, another CPU could pick the leaving thread while its registers were still
  being saved. The lock serialises every context switch in the machine. That costs a few
  hundred instructions per switch on up to eight CPUs, and splitting it per run queue
  later changes no scheduling decision, because those already live in `sched::balance`.
  The lock is a `SpinLock<()>` taken with `lock_handoff` and released with
  `unlock_handoff`, because a guard cannot be dropped on another thread's stack.
- **Placement.** A woken thread goes back to its last CPU if that CPU is idle, else to any
  idle CPU it may use, else back to its last CPU if it outranks what runs there, else to
  the least-loaded CPU it may use. The CPU that wakes it sends a reschedule IPI when the
  thread would run or share a slice where it landed. Affinity masks
  (`Threads::set_affinity`) are never overruled.
- **Balancing.** Every timer interrupt and every pass of an idle loop lets a CPU pull the
  highest-priority ready thread it may run from the busiest other CPU. A pull happens
  when this CPU is idle and the other has a thread waiting, or when the other carries at
  least two more threads. The margin of two is what stops a thread bouncing. A CPU with a
  thread waiting sends a reschedule IPI to an idle CPU, because an idle secondary sleeps
  until something interrupts it.
- **Time.** The boot CPU keeps time: only it arms its timer for the earliest sleeper, and
  it records that arming under the timer queue's lock. A secondary arms only its slice,
  or one full arming (2.15 s) when idle. A thread that sleeps on a secondary with a
  deadline before the boot CPU's arming sends the boot CPU a reschedule IPI. The design
  makes a missing IPI visible, as a wake-up seconds late. If every CPU woke for every
  expiry, the same bug would hide in milliseconds. That held for the wake-placement IPI,
  whose removal failed the stress run. It did not hold for the kick to the boot CPU: the
  stress run keeps the boot CPU too busy for its removal to matter, so that kick is
  argued and untested.
- **Sleeping.** A thread takes the scheduler lock before it arms its timer, and releases
  it only after it has blocked. A timer interrupt on another CPU wakes sleepers under that
  lock, so it cannot find the timer due while the thread is still running.

The core decisions are host-tested: `sched::balance` for placement, reschedule and pull
decisions, and convergence without bouncing; `kernel/thread` for multi-CPU yields,
wakes, affinity, balancing and 20,000 random operations with every invariant checked.

**The proof** is the stress run on `aarch64-virt-smp` ([testing](testing.md#3a-stress)).
Its heartbeat reports iterations per CPU, migrations, pulls, IPIs and shootdowns. Its
audit fails if the two never-blocking heap workloads spend a whole second on one CPU. It
also fails if any shootdown was answered by the wrong CPUs. Each of the following
mutations made the run fail:

- **No reschedule IPI for a cross-CPU wake:** a workload did not reach its checkpoint.
- **Balancing disabled:** both heap workloads on one CPU, at the first audit.
- **The scheduler lock removed:** a thread vanished, and a workload never checked in.

#### TLB shootdown

A mapping removed or downgraded on one CPU is still usable through every other CPU's
cached translation until that CPU flushes too. The port's `flush_tlb` invalidates locally
and calls `shootdown::shoot` (`kernel/main/src/shootdown.rs`):

1. The initiator masks interrupts and takes `tlb.shootdown` with `try_lock`, in a loop
   that answers any request addressed to it meanwhile, so two simultaneous initiators
   cannot each wait for the other.
2. It publishes the address and target set in `mm::tlb::Shootdown`, and sends
   `Ipi::TlbFlush` to every online CPU but itself.
3. Each target flushes, then clears its bit.
4. The initiator waits for no bits, then checks that the CPUs that answered are exactly
   the online CPUs other than itself, recomputed rather than trusted from what it sent.

On aarch64 the local flush is now `tlbi vaae1` / `vmalle1`, not the `...is` broadcast
forms. On real hardware the broadcast would be a legitimate shootdown by itself, and Linux
uses it. It is not used here, so that one protocol with acknowledgements serves every
port, including those whose TLBs have no broadcast form. It also means a shootdown that
misses a CPU cannot be quietly covered by the broadcast.

On x86_64 the local flush is `invlpg`, or a `CR3` reload for everything, and the
`Ipi::TlbFlush` is a fixed-delivery interrupt on vector `0xF2`. The protocol above is
unchanged: the port only supplies the local flush and the IPI.

**The rule that keeps the wait from deadlocking:** the initiator may wait with interrupts
masked, so no lock it holds across a shootdown may be waited for by another CPU with
interrupts masked. See [memory-model.md](memory-model.md).

**The check.** On `aarch64-virt-smp` and `x86_64-qemu-smp` the `shootdown` banner line gates
the exit status:

1. A page is mapped at a free address, and every secondary reads it through an IPI, so
   each caches the translation.
2. The page is unmapped, its frame is refilled as if reused, and a second frame is mapped
   at the same address.
3. Every secondary reads the address again, and must see the second frame.
4. Every shootdown must have been answered by exactly the right CPUs.

Skipping CPU 3 in the target set failed both halves: CPU 3 read the reused frame through
its stale translation, and the books recorded wrong answers. The stale read is observable
because QEMU's TCG keeps a software TLB per CPU and empties it only for the CPU a guest
invalidate ran on. The bookkeeping half does not depend on the emulator.

Also not yet:

- the overflow path's reporting stack is one for all CPUs, so two simultaneous stack
  overflows would share it;
- SPIs are all delivered to CPU 0;
- CPUs are never stopped or hot-unplugged;
- timers are one queue, so the boot CPU takes every expiry and wakes sleepers for every
  CPU;
- the scheduler lock is one lock for every run queue;
- a shootdown targets every online CPU, including ones that cannot have cached the
  translation, and flushes one page per request. `mm::vm` operations on many pages pay
  one round of IPIs per page.
- every device interrupt is routed to the boot CPU, and only ISA IRQs are routed through the
  I/O APIC: a PCI interrupt there needs `_PRT` or MSI-X, so x86_64's PCI devices poll;
- i686 starts no second CPU and keeps `HasSmp::MAX_CPUS = 1`;
- the I/O APIC's select-then-access registers assume one CPU programs them, which holds
  while only the boot CPU enables lines.

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
│   ├── platform/        per-firmware glue (fdt, acpi): binds drivers, hands the arch its devices
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

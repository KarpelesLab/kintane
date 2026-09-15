# Driver Isolation

Phase 5 of the [roadmap](roadmap.md) promises address-space-separated driver domains,
with the same unmodified driver source running in the kernel or isolated. The roadmap's
own risk table names what could sink that: isolation too slow to ever enable. Its
mitigation is to measure early with a prototype.

This page is that prototype: what it builds, what it proves, what it costs, and — as
plainly as the rest — what it does not prove.

Three things run under this heading:

- **The aarch64 register-driver prototype** (`DRIVER_ISOLATION`): the same driver body in the
  kernel and in an unprivileged domain, over one register window. This is the "same source, either
  way" claim, executed on every aarch64 boot. It does no DMA.
- **DMA confinement with a VT-d IOMMU** (`IOMMU`, x86_64): the disk's DMA put behind an IOMMU that
  maps exactly its grant, demonstrated **in the kernel**. This is the DMA-confinement piece the
  prototype named as missing.
- **The disk's driver in a domain** (`BLOCK_DOMAIN`, x86_64, the `x86_64-isolated` preset): the two
  halves above joined. `virtio-blk-core` — a stateful, DMA-capable driver — runs in an unprivileged
  ring-3 domain, confined by the IOMMU to exactly its grant, served the kernel's block requests over
  a channel, and given the disk's MSI-X interrupt as a message. This is Phase 5's exit criterion on
  x86_64, and the section [Running the driver in a domain (x86_64)](#running-the-driver-in-a-domain-x86_64)
  covers it, its measurements, and what it still leaves for a later fork.

## What runs

On aarch64, with `DRIVER_ISOLATION` (on by default there), every boot runs one driver body
twice over one physical register window:

- **In the kernel**, over the kernel's identity mapping of the window, at the privilege every
  driver has today.
- **In a domain**, an unprivileged process whose address space holds exactly four things: its
  program, its stack, one page it shares with the kernel for the report, and that one
  device window.

The driver body is `drivers/virtio-probe`. It reads a `virtio,mmio` slot's four
identification registers: magic, version, device id and vendor id. Both runs must report the
same four values. The vendor id reads `0x554d4551`, ASCII `QEMU` — a value from the device
that nothing told the domain, which rules out a domain that *invents* its answer.

It does not rule out a domain that read a *different* slot, and the first falsification
of this check proved it. Every unoccupied `virtio,mmio` slot answers byte-identical
identification registers, so a grant that pointed at the neighbouring empty slot produced
a report indistinguishable from the right one, and the check passed. Register values alone
cannot say which window was read. So the check also audits the grant itself: after mapping
the window into the domain, it walks the domain's own page tables and requires the
window's virtual address to translate to the page the platform recorded.

The code:

| Piece | Where | Layer |
|---|---|---|
| The proxy layer: `Regs`, `Dma`, `Irq`, `Hw` | `lib/hwproxy` | `user` |
| The driver body | `drivers/virtio-probe` | `user` |
| The domain program | `user/hwdomain` | `user` |
| The grant, the two runs, the check | `kernel/main/src/isolation.rs` | `kernel` |
| An unoccupied slot, recorded and mapped | `kernel/platform/fdt` | `kernel` |

### Why everything shared sits at the `user` layer

A domain is an unprivileged program, and kbuild lets a user program link only `user`-layer
crates. It enforces that with a test, and it is why `abi` lives there. So "the same driver
source, either way" is not a convention here but a build rule: a crate the domain links is,
by construction, a crate the kernel can link too. The corollary is just as firm: a
`device`-layer crate cannot be the driver a domain runs. At most, it can be the glue that
binds one.

## What the boundary is made of

The design's central bet is that **isolation costs at the edges, not per access**. The
kernel maps the granted window *into* the domain, so a register read in the domain is the
same load the kernel executes, in EL0 on a page the domain was given. No call crosses into
the kernel. The MMU is the proxy.

A `virtio,mmio` slot is 0x200 bytes, and the MMU grants pages, so the domain is given the
page that holds the window:

- **The proxy** bounds the driver to the device's own 0x200 bytes. `hwproxy::Direct` refuses an
  out-of-bounds or misaligned access *silently*, where the device layer's accessors
  `debug_assert!`. A window may be handed to a driver the host does not trust, and a bad
  offset from one must be something it observes, never a way to panic the host.
- **The MMU** bounds it to the page. A domain that reads the page after its grant is killed for
  it; the check proves that on every boot by running a domain that does exactly that.

`platform/fdt` grants an *unoccupied* slot. It is recorded during the enumeration scan
discovery already makes, and mapped like any claimed window. An empty slot answers the same
identification registers as an occupied one, so the driver reads real hardware either way,
and the disk's slot never ends up behind an unprivileged grant.

## What the check requires

The `isolation` line in the boot banner gates the verdict:

- **Same answer.** The domain's four registers equal the kernel's.
- **The right window.** After a domain that succeeded, its window's virtual address translates, in
  the domain's own page tables, to exactly the physical window the platform recorded. Register
  values cannot tell two empty slots apart, so this is what does.
- **A clean exit.** Every domain run that should succeed exits with success, including the timed
  ones. A timed run that failed early would otherwise be the fastest, and be believed.
- **A refusal, not a guess.** A domain whose window does not hold a virtio device refuses to
  report rather than inventing an answer.
- **Containment.** A domain that reads the page after its grant is killed, and the kernel goes
  on.
- **Nothing kept.** Every frame the domains took is back.

Each of these was falsified; see [testing.md](testing.md#2c-driver-isolation).

## What it costs

Measured on every boot, and reported in the `isolation` line. One boot's numbers, under QEMU
TCG on the `aarch64-virt` preset:

| Operation | In the kernel | In a domain |
|---|---|---|
| One identification: four MMIO register reads | 726 ns | 662 ns |
| Starting, running and tearing down a domain that identifies once | — | 6310 µs |

Across boots, the kernel's figure moved between 726 and 753 ns, and a domain's fixed cost
between 6.3 and 7.8 ms.

### How it is measured

- **In the kernel**, `virtio_probe::identify_repeatedly` runs 65 536 identifications, timed with
  the kernel clock, and the total is divided.
- **In a domain**, there is no clock to read, so the kernel times whole domain runs from outside.
  A run that identifies once measures the fixed cost. A run that identifies 65 536 times
  measures the fixed cost plus the loop. The difference, divided by the 65 535 extra
  identifications, is the per-identification cost inside the domain.
- **The fastest of three** runs of each kind is kept. A domain run builds and tears down an
  address space, and that jitters by milliseconds under emulation. An earlier version of this
  check timed one run of each with a loop of only 4096 identifications, and the jitter
  swallowed the loop entirely. It reported the domain's per-identification cost as zero. That
  was a measurement failure, not a result, and it is why the loop is long and the runs
  repeated.

### What QEMU makes meaningless, and what survives it

The absolute numbers are **emulator timings, not silicon**:

- Under TCG, every MMIO access leaves the translated code and dispatches through QEMU's device
  model. Most of the ~700 ns is that dispatch. On real hardware, one identification is four
  loads of a few nanoseconds each.
- The domain's fixed cost is dominated by copying the program into a fresh address space and
  tearing the space down. Emulated, that is milliseconds; on hardware it is far less.

What survives the emulator is the **comparison**:

- **Per access, the two modes cost the same.** Both run the same instruction over a mapped
  page, and the measurements agree within the jitter of the method. Isolation adds nothing
  per register access, because the MMU is doing the work either way.
- **The cost is in establishing a domain.** Building the address space, installing the grant,
  and starting and ending the thread is where isolation spends. That scales with how often
  domains are created and destroyed, not with how hard the driver works. It argues for
  long-lived domains, which is what driver domains are.

### What a domain costs the image

The domain program is embedded in the kernel image, which reads only its loadable
segments: 3.4 KiB of code and half a kilobyte of read-only data. Unstripped, it weighed
**2.2 MiB**, and every aarch64 image jumped from 889 KiB to 3.16 MiB, 241% of its size
budget. The size check refused all three presets.

The cause was debug info, not code. The program links `core`'s integer formatting, which
a slice copy's length-mismatch panic path reaches, and `core` is built with full debug
info. So a couple of kilobytes of code carried over two megabytes of DWARF along with it.
`user/init` links no such path and is 43 KiB of DWARF.

The program is now stripped of debug info at link (`-C strip=debuginfo`), keeping its
symbol names. The image is back inside its budget without the budget moving, which is the
point of having one: raising it to 3.3 MiB would have hidden exactly the regression it
exists to catch.

### What is not measured

The directive for this work named several operations to measure. The register-identification
cost is measured above, and the block-read and interrupt-delivery ones are now measured on
x86_64 by the driver domain (see [Running the driver in a domain](#running-the-driver-in-a-domain-x86_64)).
One remains unmeasurable, and nothing is estimated:

- **IOMMU map and unmap.** Attempted and deliberately **not published as a per-operation number**:
  over 65 536 map+unmap+invalidate iterations the total came in below the boot clock's resolution
  under QEMU TCG, so any per-op figure would round to zero and mean nothing. QEMU's `intel-iommu`
  global invalidation is a cheap flag toggle rather than the pipeline drain hardware pays, so the
  operation is exactly the kind QEMU makes meaningless — reported here as unmeasurable rather than
  reported as a false small number.

## Confining DMA with an IOMMU (x86_64)

The aarch64 prototype above named DMA confinement as the piece it could not do: without an
IOMMU, a driver that programs a DMA-capable device can point it at any physical address, and
the device's own address space is irrelevant because the device does not use it. On x86_64 with
`IOMMU` (the `x86_64-iommu` preset), that piece is built and demonstrated **in the kernel**.

### What runs

QEMU is started with `-device intel-iommu,intremap=on` behind a split irqchip, and both disks
with `iommu_platform=on`. On boot:

1. **`boot/acpi::dmar`** reads the DMA remapping table for the one hardware unit's register base —
   no other table names it — its address width, and the interrupt-remapping flag.
2. **`kernel/platform/acpi`** records that register window among the device windows the kernel maps,
   and records each block device's PCI source id **per slot**, from the very function that slot was
   bound from — as it already does for their interrupt lines. Taking the first block function
   enumeration happened to list would pair a name with whichever device came out first, and a
   source id paired with the wrong slot would confine one device to the other's grant.
3. **`drivers/iommu/vtd`** programs the unit: a root table, a per-bus context table, and a
   four-level second-level page table per translation domain. `kernel/main/src/block.rs` gives
   **each** bound disk a domain of its own and maps *exactly* that disk's DMA grant into it — at an
   I/O virtual address equal to its physical one, because the driver puts physical addresses in
   descriptors and the device treats them as device addresses (`VIRTIO_F_ACCESS_PLATFORM`) —
   attaches each disk, and turns translation on before any of them does DMA. There is one `Unit`:
   translation, the root table and the invalidation queue belong to the hardware unit, not to a
   device, and a second `Unit` over the same registers would be two drivers for one piece of
   hardware.

The driver source does not change between this and a plain boot. `virtio_blk_core` already accepts
`VIRTIO_F_ACCESS_PLATFORM` and already keeps the device's address and the CPU's apart
(`mem::Dma`); behind the IOMMU, `phys()` is an I/O virtual address the grant maps, and nothing
above the transport knows the difference. That is the payoff of having kept the two addresses
distinct in the type since before it bit.

### What the check requires

The `block` line shows the disk brought up behind the IOMMU and passes every functional check
with its DMA translated — the in-grant DMA working end to end. The `iommu` line then gates on:

- **Exact grant.** The domain maps the grant and does *not* map the canary frame beside it.
- **Out-of-grant DMA stopped and logged.** A deliberate read into the canary (a descriptor pointing
  outside the grant, which a driver never does and an isolated one must not be able to get away
  with) is stopped by the hardware. The unit's fault log names the canary's address and the disk's
  own source id, `00:02.0`, and the canary still holds its sentinel. The check compares the
  fault's source id against the one *that disk* was attached with, so a fault matched only by
  address — which another device behind the same unit could produce — is not taken for this one.
- **Restart.** The faulted device is reset and brought up again over the same grant, and serves a
  read — so the host survives a device fault and the stress run still has a disk.

Because the log is the unit's and every device behind it records there, the check drains it
before causing the fault it means to read. A second disk faults once as it is brought up behind
its own domain — stopped, as it should be — and without the drain that record, not the rogue
one, is what the check would find.

Each was falsified; see [testing.md](testing.md#2c-bis-dma-confinement-with-the-iommu).

### Flushing what the unit cached

A VT-d unit caches what it reads from its tables: context entries, translations (its IOTLB) and
interrupt remapping entries. A change to one of those tables takes effect only once the cache is
invalidated, so a mapping taken away without the flush is still reachable, and a remapping entry
changed without it still delivers where it used to. The register interface invalidates contexts
and translations only globally, and cannot invalidate an interrupt entry at all.

The kernel turns the unit's *invalidation queue* on right after translation (`drivers/iommu/vtd`,
`qi.rs`): a frame of 128-bit descriptors the unit reads from its head to its tail, each batch ended
by a wait descriptor whose status write says the unit is done. Every change the unit may have
cached is followed by its flush, waited for under a bound:

- unmapping a page in use flushes its translation, page by page (`Unit::unmap_in_use`);
- attaching a device while translating flushes its context entry and its domain;
- changing a remapping entry flushes that entry's cache (`Unit::set_irte`), and a unit without the
  queue on refuses the change rather than make half of it;
- latching a new remapping table flushes the whole entry cache.

QEMU's unit keeps a real IOTLB for its emulated devices, so a missing translation flush is visible
in a guest, and the `iommu` check shows it. The disk reads a sector into a canary page mapped into
its domain, the page is unmapped with its flush, and the rogue DMA aimed at it must then fault.
With the flush skipped, the device reaches the canary through the translation it cached, and the
boot fails. QEMU keeps no interrupt entry cache for an emulated device, so a skipped entry flush
changes nothing a guest can observe. The `remap` check requires a completed flush for each of its
six changes to the disk's entry in use, and the host tests' model of the cache shows the stale
entry itself.

| Operation | Value, under QEMU TCG |
|---|---|
| A remapping entry changed and its cache flushed, the wait included | 4.5 µs mean over 64 (`blk smp`); below the boot clock's resolution over 256 at boot (`remap`) |
| Status reads before a wait saw its completion | 1 |

QEMU processes the queue inside the exit the tail write causes, so a wait is complete by its first
read. The 4.5 µs is two traps into the emulator and its descriptor processing, not a real unit's
asynchronous queue, which drains in its own time; there the bound the driver waits under is what
matters, and only the host tests exercise it.

## Discovering an SMMUv3 (aarch64), and why confinement stops there

aarch64 has no IOMMU integration, so a driver domain on that port is confined by nothing — the
gap the prototype above names. With `SMMUV3` (the `aarch64-smmu` preset) the kernel finds the
machine's unit and reports what it could translate for. It programs nothing, and the reason it
stops there is a fact about the machine rather than a missing piece of code.

### What runs

QEMU is started with `-machine virt,iommu=smmuv3`. On boot, `kernel/platform/fdt` finds the
`arm,smmu-v3` node and reads the unit's identification registers **on the boot identity map** —
the same way the memory-mapped virtio slots are identified before any driver is bound, so no
window has to be claimed and no driver exists to claim it. Nothing is programmed.

What the unit reports under QEMU 11.0.3: 16-bit stream ids (`IDR1.SIDSIZE`), 4 KiB and 64 KiB
granules (`IDR5.GRAN4K`, `GRAN64K`), a 44-bit output address (`IDR5.OAS`), and 65 536 stream ids
mapped to it from the PCIe root complex.

### Why nothing is confined

**QEMU wires the SMMU to the PCIe root complex and to nothing else.** `iommu-map` appears on
`pcie@10000000` and on no other node, and the 32 `virtio,mmio` slots carry no `iommus` property
at all. That was established by dumping the machine's own tree (`-machine dumpdtb`) and diffing
it against the same machine without the option: `iommu=smmuv3` adds exactly one node and that
one property.

This port's disk is a `virtio-blk-device` in one of those memory-mapped slots. So there is no
device here whose DMA the unit could translate, and confining one would mean first putting the
disk on PCIe — an ECAM host bridge driver, enumeration from the tree, and message-signalled
interrupts through the ITS. That is a separate piece of work rather than a step inside this one:
`kernel/device/src/pci.rs` reaches configuration space through the windows an ACPI MCFG
describes, and the FDT platform never builds one.

The `smmu` check asserts that coverage fact rather than leaving it in this document. While no
virtio-mmio slot sits behind the unit, the next stage is known to be unreachable; if a machine
ever puts one there, the check fails and says the topology changed, instead of the claim quietly
going stale.

## Running the driver in a domain (x86_64)

With `BLOCK_DOMAIN` (the `x86_64-isolated` preset), the two halves above are joined: the disk's
stateful, DMA-capable driver runs in an unprivileged ring-3 **domain**, confined by the IOMMU.
This is Phase 5's exit criterion on x86_64.

The disk still comes up in the kernel during boot, behind the IOMMU, and the boot-time `block`
check reads it there — before the scheduler exists there are no domains to run one. Once the
scheduler is up, the `blk domain` check hands the disk to a domain and reads it *from there*
instead, then hands it back so the stress run and the filesystem find it working.

### What runs

`user/blkdomain` is an unprivileged program that links the same crates the kernel's in-kernel
host of the driver links — `virtio-blk-core`, `virtio`, `hwproxy`, `abi`, all `user`-layer — and
runs `virtio_blk_core::Engine`. It carries the KinTane ABI note in its link script, so the loader
runs it native rather than tagging it Linux. The kernel builds it a domain whose address space
holds only its program, its stack, two channels, a setup page, and three mappings:

- the device's **register window**, as device memory — a register access there is the same load the
  kernel would make, executed in ring 3;
- the device's **DMA buffer**, which is *exactly* the grant the IOMMU already confines the device to
  (`kernel/main/src/block.rs` reuses it), so the rings and bounce buffers the domain builds are
  precisely what VT-d lets the device reach;
- **data pages** shared with the kernel, that a request's bytes move through. The CPU copies them to
  and from the engine's bounce buffers, so they are never device-visible and need no IOMMU mapping.

The kernel's block layer is the domain's **client**, over a channel: `kernel/main/src/blockdomain.rs`
sends a request and reads a reply. The disk's **MSI-X interrupt** is taken by the kernel's handler,
which acknowledges it and forwards it to the domain as a message on a second channel. The domain
drains the used ring only after a message has arrived — never on its own — so every completion it
collects was announced by an interrupt the kernel delivered; a request whose interrupt never comes
times out rather than being polled into looking fine. The proxy layer's `hwproxy::Irq` is the
domain's view of this: it counts the messages.

### What the check requires

The `blk domain` line runs the same `block` checks against the test disk, served by the domain, and
gates on all of:

- the geometry is the test disk's, behind VT-d, on MSI-X;
- 32 sectors read back the pattern (a read split across several requests), a write reads back after a
  flush, and a read past the end is the *device's* own refusal returned as an error;
- every completion arrived by an interrupt message and no descriptor leaked;
- **containment of a rogue DMA:** a DMA the domain aims outside its grant is stopped by VT-d, whose
  fault log names the target address and the disk's source id, and the target is untouched;
- **containment of a faulting domain:** a domain whose driver reaches past its grant is killed by the
  MMU — not a bounds check in the driver — alone, the disk is marked failed, and a fresh domain over
  the same grant serves a read again;
- the disk is handed back to the kernel afterwards.

Each was falsified; see [testing.md](testing.md#2c-ter-the-disk-driver-in-a-domain).

### What it costs

Measured on every `x86_64-isolated` boot and reported in the `blk domain` line. One boot's numbers,
under QEMU TCG:

| Operation | Value |
|---|---|
| Block reads/writes served end to end from the domain | 73 requests, all completed |
| Completions collected, each after an interrupt message | 73 in 73 messages |
| Interrupt forward latency — kernel handler to domain receiving the message | ~42 µs mean, ~0.6 ms worst |

The forward latency is the cost this design adds over an in-kernel handler: the interrupt lands in
the kernel, is turned into a channel message, and the domain is scheduled to receive it. Under TCG
that is tens of microseconds dominated by scheduling and emulation, not the message itself; on
hardware it is far less, and it is paid once per interrupt, not per register access — the same shape
the register prototype measured. The block transfers themselves run at the same per-access cost as
in the kernel, because the domain executes the same loads and stores over the same mapped DMA buffer;
what isolation adds is the completion's trip through a channel, which is why an interrupt-driven
driver that waits on many completions is the case this measures.

### Four CPUs (`x86_64-isolated-smp`)

The handler does not send the message itself. A channel send takes the channel's lock and the
object store's, and a handler that took them could wait for another CPU holding one. So the handler
only counts the interrupt, stamps it, and wakes the *forwarder*, a kernel thread waiting on a wait
queue, which sends the cumulative count (`blockdomain::forward_interrupt`). The only locks left on
the handler's path are the wait queue's and the scheduler's, which every holder takes with
interrupts masked for a few instructions. The count the forwarder records as sent is the one its
message carried, not the counter read again after the send, so an interrupt taken while a message
is leaving is still owed one. Every run checks that each interrupt the platform dispatched on the
disk's line reached the forwarder and was sent.

`x86_64-isolated-smp` runs the boot checks as `x86_64-isolated` does, and `block cpu` moves the
disk's remapped interrupt to CPU 1 through its table entry. Once `persist` has given the scheduler
every CPU, `blk smp` runs the domain checks again with the sides apart: the kernel's block layer
pinned to CPU 0, the disk's interrupt on CPU 1, the domain pinned to CPU 2, and the domain started
after the deliberate fault pinned to CPU 3. It gates the verdict on everything `blk domain` does,
and on each domain entering user mode on its CPU and every interrupt of the run being taken on
CPU 1 and none elsewhere.

| Forward latency, kernel handler to the domain receiving | Mean | Worst |
|---|---|---|
| `x86_64-isolated`, one CPU | 127 µs | 1.1 ms |
| `x86_64-isolated-smp`, `blk domain` (the scheduler still on one CPU) | 146 µs | 1.3 ms |
| `x86_64-isolated-smp`, `blk smp` (handler, forwarder and domain apart) | 293–419 µs | 1.3–4.1 ms |

Single boots, on a host running other QEMU guests; the spread is host load, and `blk domain` on
the same image is the fair baseline. Apart, a message crosses CPUs twice: the handler's wake reaches
the forwarder by IPI, and the forwarder's send reaches the domain by another, and under TCG each IPI
is a round trip through the emulator's CPU threads. What the numbers support is the ratio, two to
three times the one-CPU path. On hardware an IPI costs microseconds.

### What it does not prove

- **The interrupt reaches the domain through the kernel.** The disk's message is steered by a
  remapping table entry the kernel owns, but remapping cannot make ring 3 an interrupt's target, so
  the kernel's handler still takes it and the forwarder sends it on.
- **The forward latency is QEMU's.** It is dominated by TCG scheduling and emulation, as the register
  prototype's fixed cost is.

## What it does not prove

- **The numbers are QEMU's.** The map/unmap cost is below the boot clock under TCG (above), and
  QEMU's IOMMU invalidation is far cheaper than silicon's. What survives the emulator is the
  *shape*: the grant is mapped once at setup, and per DMA the MMU-equivalent does the work, so the
  cost is at the edges, as with the register prototype.
- **No CPU above x2APIC ID 255.** Delivery through a remapping entry to such a CPU is shown only by
  the host tests and by the boot CPU not taking a message aimed at ID 256. QEMU can place a CPU at
  ID 256 only in a topology of at least 257 possible CPUs, and its MADT lists every one; the
  kernel's ACPI discovery describes at most 72 devices (`MAX_DESCRIBED`), so it stops before it
  installs the local APIC. Tried with `-smp 3,sockets=4,cores=128,threads=1,maxcpus=512` and a
  fourth CPU cold-plugged at socket 2: `512 in the MADT`, no local APIC, no disk.
- **One unit, the first DRHD.** The kernel programs the first remapping unit the DMAR lists, which
  is all QEMU presents. A machine with several units, each covering part of the PCI topology, would
  need each programmed and the device matched to the unit whose scope covers it.
- **The aarch64 register prototype's own limits still hold:** its driver is small and stateless, and
  its "restart" is a fresh domain rather than a recovered one. The x86_64 restart above *is* a
  recovered device — reset and brought up again over the same grant after a real fault — which is
  the stronger of the two.

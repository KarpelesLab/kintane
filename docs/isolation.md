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

QEMU is started with `-device intel-iommu,intremap=on` behind a split irqchip, and the disk
with `iommu_platform=on`. On boot:

1. **`boot/acpi::dmar`** reads the DMA remapping table for the one hardware unit's register base —
   no other table names it — its address width, and the interrupt-remapping flag.
2. **`kernel/platform/acpi`** records that register window among the device windows the kernel maps,
   and pairs it with the disk's PCI source id.
3. **`drivers/iommu/vtd`** programs the unit: a root table, a per-bus context table, and a
   four-level second-level page table for one translation domain. `kernel/main/src/block.rs` maps
   *exactly* the disk's DMA grant into that domain — at an I/O virtual address equal to its physical
   one, because the driver puts physical addresses in descriptors and the device treats them as
   device addresses (`VIRTIO_F_ACCESS_PLATFORM`) — attaches the disk, and turns translation on
   before the device does any DMA.

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
  own source id, `00:03.0`, and the canary still holds its sentinel.
- **Restart.** The faulted device is reset and brought up again over the same grant, and serves a
  read — so the host survives a device fault and the stress run still has a disk.

Each was falsified; see [testing.md](testing.md#2c-bis-dma-confinement-with-the-iommu).

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

### What it does not prove

- **The interrupt reaches the domain in software, not through VT-d interrupt remapping.** The kernel's
  handler takes the MSI and forwards it as a message. VT-d interrupt remapping (`intremap=on` is
  already enabled on the machine) would steer the device's MSI at the domain directly, and the kernel
  handler would only acknowledge; that remapping table is another fork's work
  (`drivers/iommu/vtd`), and where it slots in is marked in `blockdomain::forward_interrupt`.
- **Uniprocessor only.** The `x86_64-isolated` preset runs one CPU. Forwarding the interrupt from the
  handler relies on the uniprocessor lock discipline (every lock the forward takes is held with
  interrupts masked); an SMP variant would forward through a dedicated queue instead.
- **The forward latency is QEMU's.** It is dominated by TCG scheduling and emulation, as the register
  prototype's fixed cost is.

## What it does not prove

- **The numbers are QEMU's.** The map/unmap cost is below the boot clock under TCG (above), and
  QEMU's IOMMU invalidation is far cheaper than silicon's. What survives the emulator is the
  *shape*: the grant is mapped once at setup, and per DMA the MMU-equivalent does the work, so the
  cost is at the edges, as with the register prototype.
- **One unit, the first DRHD.** The kernel programs the first remapping unit the DMAR lists, which
  is all QEMU presents. A machine with several units, each covering part of the PCI topology, would
  need each programmed and the device matched to the unit whose scope covers it.
- **The aarch64 register prototype's own limits still hold:** its driver is small and stateless, and
  its "restart" is a fresh domain rather than a recovered one. The x86_64 restart above *is* a
  recovered device — reset and brought up again over the same grant after a real fault — which is
  the stronger of the two.

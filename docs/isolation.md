# Driver Isolation

Phase 5 of the [roadmap](roadmap.md) promises address-space-separated driver domains,
with the same unmodified driver source running in the kernel or isolated. The roadmap's
own risk table names what could sink that: isolation too slow to ever enable. Its
mitigation is to measure early with a prototype.

This page is that prototype: what it builds, what it proves, what it costs, and — as
plainly as the rest — what it does not prove.

Two things run under this heading, and they are at different stages:

- **The aarch64 register-driver prototype** (`DRIVER_ISOLATION`): the same driver body in the
  kernel and in an unprivileged domain, over one register window. This is the "same source, either
  way" claim, executed on every aarch64 boot. It does no DMA.
- **DMA confinement with a VT-d IOMMU** (`IOMMU`, x86_64): the disk's DMA put behind an IOMMU that
  maps exactly its grant, demonstrated **in the kernel**. This is the DMA-confinement piece the
  prototype named as missing. It is not yet a separate driver *domain* on x86_64 — the stateful
  driver runs in-kernel behind the IOMMU — and that remaining gap is stated plainly below.

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
cost is measured above. The DMA-related ones are only partly measurable with what runs today,
and nothing is estimated:

- **A block read end to end, in-kernel versus in a domain.** Not measured as a comparison: the
  converted block driver runs in-kernel behind the IOMMU, but there is no x86_64 *domain* running
  it, so there is no second number to compare against. The in-kernel read behind VT-d passes the
  block check (see the IOMMU section), which shows it works, not what it costs relative to a domain.
- **IOMMU map and unmap.** Attempted and deliberately **not published as a per-operation number**:
  over 65 536 map+unmap+invalidate iterations the total came in below the boot clock's resolution
  under QEMU TCG, so any per-op figure would round to zero and mean nothing. QEMU's `intel-iommu`
  global invalidation is a cheap flag toggle rather than the pipeline drain hardware pays, so the
  operation is exactly the kind QEMU makes meaningless — reported here as unmeasurable rather than
  reported as a false small number.
- **Interrupt delivery**, in-kernel versus as a message to a domain. Not measured, and not
  implemented: x86_64 has no PCI interrupt route to the disk yet (`controller::PCI_LINE_TRUSTED` is
  false; the disk is polled), and MSI-X is a separate fork's work. `hwproxy::Irq` remains defined
  and unused on this path. Interrupt remapping (`intremap=on`) is enabled on the machine so that MSI
  fork can build on it, but nothing here delivers an interrupt as a message.

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

## What it does not prove

- **The stateful driver is confined in the kernel, not in a domain, on x86_64.** The block driver
  runs in-kernel behind the IOMMU; it is not the separate unprivileged *domain* the aarch64
  register prototype is. The two halves — a driver body in a domain (aarch64, no DMA) and a
  DMA-capable driver confined by an IOMMU (x86_64, in-kernel) — are not yet joined into one
  isolated DMA-capable driver domain on x86_64. Joining them needs the domain to run
  `virtio_blk_core` in ring 3 and to receive completions, which is the interrupt-as-a-message path
  that does not exist yet (see below).
- **Interrupts do not reach a domain as messages.** x86_64 has no PCI interrupt route to the disk
  (it is polled), and MSI-X is a separate fork's work. Until then a driver domain would poll, which
  is why the domain half is not wired on x86_64 yet.
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

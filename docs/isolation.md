# Driver Isolation

Phase 5 of the [roadmap](roadmap.md) promises address-space-separated driver domains,
with the same unmodified driver source running in the kernel or isolated. The roadmap's
own risk table names what could sink that: isolation too slow to ever enable. Its
mitigation is to measure early with a prototype.

This page is that prototype: what it builds, what it proves, what it costs, and — as
plainly as the rest — what it does not prove.

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

The directive for this work named three operations to measure. One is measured here; two
are not, and neither is estimated:

- **Interrupt delivery**, in-kernel versus as a message to a domain. Not measured: the subject
  device has no interrupt wired to it, and the prototype's `Irq` is `NoIrq`. Delivering an
  interrupt to a domain needs a message path the kernel can post to from interrupt context,
  and that path does not exist yet.
- **A DMA round trip.** Not measured: the subject device does no DMA. See below for why that is
  also the case isolation cannot yet protect.

## What it does not prove

- **DMA is not confined.** Nothing here confines a device that writes memory on a driver's
  behalf. Without an IOMMU, a domain granted a DMA-capable device can program it to read or
  write *any* physical address. The domain's own address space is irrelevant to that, because
  the device does not use it.
- **What an IOMMU has to add.** Phase 5's IOMMU work has to make DMA confinement real:
  - a translation domain per device: SMMUv3 on aarch64, VT-d or AMD-Vi on x86;
  - `hwproxy::Dma::phys` becoming an I/O virtual address in that domain rather than a physical
    address;
  - a grant of DMA memory becoming a mapping in the device's domain;
  - a device naming memory outside its grant faulting in the IOMMU, instead of corrupting the
    kernel.

  The `Dma` trait already keeps the device's address and the CPU's apart, so that change is
  confined to the host's implementation of it. The driver body would not change.
- **No domain on x86_64.** A domain is granted a *mapping*, and the PCs have no memory-mapped
  device to grant today:
  - COM1 is in the port space, which cannot be mapped into an address space. A port range
    could be granted through the TSS I/O permission bitmap instead, which would be a real
    mechanism with a different shape.
  - virtio-blk reaches x86 only over PCI, and its PCI transport is separate work.
- **The driver is small on purpose.** Identification is read-only and has no state. That is
  right for testing the boundary and says nothing about the protocol a stateful isolated
  driver needs: start, stop, fault recovery mid-request, and restarting a device the domain
  left half-programmed.
- **Restart is a new domain, not a recovered one.** Every run builds a fresh domain on the same
  slot after the previous one is torn down, including after the rogue domain is killed. That
  demonstrates the host survives and can grant the window again. It does not demonstrate
  resuming a device that failed partway through real work.

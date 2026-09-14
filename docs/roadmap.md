# Roadmap

Phases are ordered by dependency, not by calendar. Each has **exit criteria** that are
demonstrable — something boots, something passes, something fits in a budget — because
"mostly done" is not a state a kernel phase can be in.

## Status

| Phase | State |
|---|---|
| 0 — Build system and first boot | **done**, including `kinboot-efi` |
| 1 — The portability spine | **done**, including `kinboot-bios` |
| 2 — Core kernel | **every item landed**; stress runs of 10 minutes pass on all three; the 24-hour run is not yet done |
| 3 — SMP and the device model | **exit criterion met**: 8 CPUs boot and stress clean on both ports; devices, interrupts and consoles through one device model from FDT and from ACPI/PCIe |
| 4 — Configurability, scaling down | riscv32 (with and without atomics), ARMv7-M at 56 KiB of RAM, `mm::flat`, modules, the full config language, random configs, size budgets. Real hardware and a thousand random configs remain |
| 5 — Driver isolation | a first prototype: one driver body in the kernel and in a domain, a rogue domain killed; no IOMMU, so no DMA confinement |
| 6 — Userspace and the Linux personality | a program creates a program through handles and construction calls; a VFS; `init` loaded from disk. The Linux personality is not started |
| 7 — Real hardware and real work | started early: disks on every tier-1 port, a read-only FAT16 filesystem, an EFI stub, image formats, reproducible releases, a last-known-good boot counter |

### The sixth round of landings

Fifteen presets now build and boot, with `x86_64-efistub` new. Six branches landed. As
before, most of the work of merging was in the seams between them, not in the conflicts.

- **A program creates a program** (Phase 6a). Images, processes, threads, memory regions
  and completion queues are kernel objects behind handles, and eight construction calls
  build a process piece by piece from handles its builder holds — still no fork. `init`,
  given only a console and an image, builds a child, hands it a channel endpoint, waits
  for it on a completion queue, and checks its exit code; the child's forged handles are
  refused, and every object and frame comes back.
- **Storage end to end.** `vfs` (a mount namespace, handles, an in-memory filesystem), a
  write-through block cache and a read-only FAT16 reader, all host-tested. The test disk
  carries a FAT16 volume, and on every port with a disk the kernel loads
  `/KINTANE/INIT.ELF` from it and runs it — userspace from storage, not from the image.
- **Disks on the PCs.** virtio over PCI on x86_64 and i686, completion by interrupt with
  several requests in flight (32 of 32 by interrupt on aarch64 and i686; x86_64 still
  polls until MSI-X or `_PRT` routing exists), and roughly double the throughput.
- **Driver isolation, a first prototype** (Phase 5). One driver body runs in the kernel
  and in an unprivileged domain over the same device window; the reports must agree, the
  domain's page tables must map only its grant, a rogue domain is killed, and every frame
  returns. A register access costs the same in both modes under emulation; starting and
  tearing down a domain costs about 6 ms, which argues for long-lived domains. No DMA
  confinement yet: that needs an IOMMU.
- **Fuzzing.** `kbuild fuzz` runs seeded, reproducible, structure-aware campaigns over nine
  targets — the device tree, ACPI, ELF, modules, boot tags, the boot menu, PCI
  configuration, virtio rings and the syscall table — with a committed corpus replayed on
  every change and a million inputs per target nightly. No kernel parser has panicked or
  hung.
- **Boot integration** (Phase 7). The kernel boots as its own UEFI application; images come
  in `elf`, `bin`, `uki` and `uimage`; `kbuild release` produces a manifest two cold builds
  reproduce; and a last-known-good counter falls back to safe mode after three failed
  boots and is cleared by a good one, proven end to end in one QEMU machine.

**A security bug the storage work exposed, guarded rather than fixed.** On x86_64 UEFI
boots, firmware placed the disk's BAR at 768 GiB, inside the user half of the address
space. The kernel maps device memory at its physical address, and every process copies
the kernel's top-level entries, so all processes built their pages into one shared table
and one read another's memory. The kernel now refuses to build a process while anything
is mapped in the user range. The real fix — mapping device memory outside the user range —
changes an assumption every driver makes, and is named here as open work.

*Fixed in the seventh round (3d0428f).* Device memory on x86_64 and aarch64 now lives in a
kernel-half window at 1 TiB above its physical address, and `hal::paging::device_virt` is
the only way to turn a device's physical address into a pointer. The machine that exposed
the bug runs unchanged, with its BAR still at 768 GiB, and passes the process, spawn and
isolation checks. Every boot now checks that the user half holds no kernel mapping, and the
refusal in `userproc.rs` stays as a backstop that can no longer trigger. i686 keeps identity
mapping: it has no user half, and no room in 32 bits for the window.

**What integration found that no branch could:**

- **The scheduler's table lived on the boot stack.** `Threads::new` returned the table by
  value, so it existed once on the 16 KiB boot stack before moving into place, and it grows
  with stack slots and CPUs. Isolation's extra slot at eight CPUs overflowed the boot stack
  into its guard page — which caught it cleanly. The table is now built in place.
- **A fuzz mock that predated eight syscalls.** The fuzzing branch's mock handler was
  written against the syscall table before the object layer grew it, so after both merged
  the fuzz unit no longer compiled. That break was exactly the compile error the target's
  documentation promised. It also reached master: the merge was pushed before its checks
  had finished, and every push since is gated on the full suite passing.
- **Two branches wrote the same helper.** The object layer and the filesystem both added
  an identical `parse` to `userproc.rs`.
- **Three disk workloads, one stack budget.** The filesystem and storage branches each
  added a stress workload that needs the disk; together with isolation's slot, a stress
  build now needs thirteen guarded stacks, and the build-time assertion counts every one.

**Findings worth keeping from the branches themselves:**

- **Three fuzz generators were testing nothing.** A first campaign of 45,000 inputs found no
  failures, and was worth almost nothing: the ELF, ACPI and menu generators produced inputs
  every parser rejected at its first check (0–5% accepted). Measuring acceptance exposed
  it; they now reach 40–80%.
- **A falsification only a host test could see.** A FAT reader that starts the root
  directory one entry late passes the boot check, because kbuild's volume — like almost
  every real one — has its label first, and skipping the label hides the offset.
- **A grant check that passed on the wrong window.** Every empty virtio slot answers
  identical identification registers, so a domain granted the neighbouring slot matched the
  kernel's read. Only walking the domain's page tables says which window it read.

**Build speed, measured.** A no-op rebuild takes 0.18 s and a one-line change to the kernel
crate about a second; a one-line change in `hal` recompiles 37 of 42 crates in 4.9 s,
against 22 s cold. The cache is content-addressed and per crate, dependents are keyed on
their dependencies' keys, crates compile one at a time, and nothing is incremental.

### The fifth round of landings

Fourteen presets now build and boot. Six branches landed, plus one integration fix.

- **Phase 3 is finished.** Both SMP ports boot eight CPUs and pass the stress run there:
  60 seconds, every audit, work on every CPU, with 300k+ TLB shootdowns and tens of
  thousands of migrations per run.
- **Device interrupts through the device model.** A bound driver's handler is registered
  before its line is unmasked, and aarch64's GIC, x86_64's I/O APIC and i686's 8259A all
  hand device lines to one table. The PL011 and a new 16550 driver receive on interrupt:
  every x86 and aarch64 boot has the harness type a string that must arrive that way, and
  the PCs unbind and rebind the driver in between with nothing left claimed.
- **Storage.** `kernel/block` gives drivers one fallible, allocation-free interface;
  `drivers/block/virtio-blk` is the first driver with DMA, host-tested against a fake
  device. Both aarch64 presets read and write a build-time pattern disk on every boot.
- **Processes on the scheduler.** A thread carries its address space, and the context
  switch loads it wherever the thread lands. Two workers run concurrently, each reading
  only its own memory at the same address, while a third is killed for touching kernel
  memory. The stress run migrates a process between CPUs every second.
- **Single-provider dispatch and the ARMv7-M RAM diet.** A build with one interrupt
  controller driver has no indirect call on the interrupt path, while the default aarch64
  image still picks GICv2 or GICv3 at run time from one binary. `armv7m-tiny` boots in
  **55.9 KiB of RAM**, down from 329 KiB; flash is 64.6 KiB, 0.6 KiB over the goal.
- **rv32i without atomics boots**, on a QEMU hart with A, M and C switched off — the case
  [portability.md](portability.md) has claimed since Phase 1. The rv32imac image dies on
  that hart at its first atomic instruction, which is how we know the hart refuses them.
  riscv32 also gained PMP stack guards.

**Three bugs that only integration could find**, each invisible to the branch that
carried the code:

- **A silent placement.** Every path that moves a thread to another CPU announces where it
  went and interrupts that CPU — except a yield from a CPU the thread's affinity no longer
  allows. An idle CPU sleeps until interrupted, so a process sat *ready on the CPU it had
  been pinned to, never scheduled*, while four CPUs idled. At four CPUs the run queues are
  never empty, so it could not appear; at eight it did. The check that found it was itself
  hiding it, reporting a stale symptom ("a process did not stop when told") instead of the
  cause.
- **A size that came from configuration, and two tables that did not.** The thread-stack
  array grew with the CPU count, but the per-port slot-name table and the address-space
  planner's limit were still the literal `16`. A stress build at eight CPUs lays out
  seventeen, so the kernel refused its own address space. The count is derived once now,
  and both tables read it.
- **`sync::IrqLock` registered with the lock-order checker before masking interrupts.** A
  timer interrupt in that window looked like recursion and halted the CPU. No image had
  used interrupt masking as its lock family until rv32i did; any uniprocessor build would
  have hit it.

**What the parallel work costs.** Two branches independently made thread-stack sizing
configuration-driven, with two generators and two symbol names; merging them was a design
decision, not a textual one. Three agents stalled waiting on their own background runs.
The integration tax is paid by whoever merges, and it is the honest price of six branches
at once.

### The fourth round of landings

Eleven presets now boot, including `x86_64-qemu-smp` and `armv7m-mps2`.

- **SMP, both ports, one scheduler.** Each CPU has its own run queue, with host-tested
  wake placement, balancing with a margin of two, and affinity masks. Cross-CPU wake-ups
  ride reschedule IPIs. Kernel mapping changes are shot down with an acknowledged IPI
  protocol that replaces aarch64's broadcast invalidate, so one protocol serves every
  port. x86_64 brings its CPUs up with INIT and startup IPIs through a real-mode
  trampoline, and runs on local APIC and I/O APIC drivers bound from the MADT; both ports
  plug into `hal::HasIpi`.
- **The first native userspace slice** (Phase 6a). `lib/abi` declares the system-call
  table once, `kernel/elf` loads static programs, and every x86_64 and aarch64 boot runs
  three processes from an embedded `init`: one that works, one that can do nothing with
  forged handles, and one that is killed for faulting while the kernel continues. On
  x86_64 the entry became per-CPU along with SMP — ring-3 segments in every GDT, `rsp0`
  installed by the context switch, `syscall` MSRs per CPU, and a `swapgs` discipline whose
  removal at any single point makes the kernel fault rather than the process.
- **Loadable modules** (Phase 4, x86_64). A module carries its kernel's build identity
  and an interface hash. Loading one built for a different configuration is refused with
  the differing symbol named; a module in use cannot be unloaded; unloading returns every
  frame. `kbuild sdk` builds an out-of-tree module byte-identical to the in-tree one.
- **The ARMv7-M port** (Phase 4). A Cortex-M3 executing in place from flash, with its
  memory map generated from a board description at build time, PendSV preemption and all
  eight MPU regions enforcing W^X and stack guards. A size-optimised release image is
  63 KiB of flash, inside the roadmap's 64 KiB. RAM is 324 KiB, mostly thread stacks, and
  is the open problem.
- **Epoch reclamation, the object store and channel cycles** (Phase 3). Readers pin, the
  epoch advances only when every pinned CPU has observed it, and memory is reclaimed two
  epochs later; a CPU that never unpins is reported instead of leaking. `kobject` gained
  an object store and a lock-backed identity source for machines without 64-bit atomics.
  Channels that hold each other in their queues are now collected.

**The ARMv7-M port re-tested the portability rule and split the verdict.** Kernel code
needed no change at all — not `kernel/main`, `sched`, `thread`, `hal` or the unwinder —
which is what riscv32's memory-model seam bought. Shared *tooling* still needed two
fixes: `lib/builtins` had none of the Arm run-time ABI (and LLVM compiled one helper into
a call to itself), and the symbolizer mishandled Thumb return addresses, where the low bit
of a return address is set.

**Phase 3's exit criterion is not met yet.** Both SMP ports boot 8 CPUs and pass every
bring-up check there, but the stress run does not:

- **Thread stacks run out.** The guarded stack slots in each `link.ld` are a fixed count
  that does not scale with CPUs, so at 8 CPUs the stress run cannot start its workloads.
- **Epoch retirement is refused at 8 CPUs.** With seven pinned readers the epoch advances
  too slowly for a fixed-size retirement bag, and the check reports the refusal rather
  than leaking, which is the designed behaviour and still a failure of the run.

Both are sizing, not design, and both are named here rather than in a commit message.

### The third round of landings

Six more branches landed. The tree now boots nine presets: the seven from before, plus
`aarch64-virt-smp` and `riscv32-virt`.

- **Phase 2's exit instrument.** After bring-up the scheduler keeps the CPU for good.
  `kbuild stress` runs seven workloads under seeded heap fault injection: heap churn,
  channel ping-pong with handle transfer, sleeps, demand paging and COW, and buddy
  pages. An auditor checks every book once a second, and a heartbeat watchdog turns a
  hang into a failure. Ten minutes pass all 600 audits on x86_64, i686 and aarch64. A
  nightly workflow runs 30 minutes each. The 24-hour run needs a self-hosted runner and
  has not been done.
- **SMP on aarch64.** `sync::PerCpu` is sized by `HasSmp::MAX_CPUS` at build time and
  reachable only through an interrupt-masking `Pinned` guard. PSCI `CPU_ON` starts every
  CPU in the device tree. Each CPU gets its own redistributor, which is found by
  affinity, or its banked GICv2 interface, plus its own timer. SGI IPIs work on both GIC
  versions, and lockdep keeps one held-lock stack per CPU. The scheduler itself is still
  single-CPU.
- **ACPI and PCIe on x86.** `boot/acpi` validates checksums before reading any field and
  is tested against real firmware tables captured from three machines. `device::pci`
  walks buses through bridges and sizes BARs without disturbing them. `platform/acpi`
  turns the MADT, MCFG and PCI functions into device nodes, the same model aarch64's
  device tree feeds.
- **Boot entries, command line, chainloading.**
  - Both loaders show a normal/safe/recovery menu, selectable by key, and hand the
    kernel a command line. `kinboot-bios` now hands over the native `BootInfo`.
  - BIOS chainloads another partition's boot record; UEFI chainloads another
    application.
  - The boot counter waits on a kernel-side writer.
- **riscv32 without an MMU** (Phase 4). rv32imac runs in M-mode with `mm::flat`. All 35
  in-kernel checks run, and the MMU-only ones honestly report Skipped.
- **kbuild** (Phase 4). The config language gains hex symbols, conditional ranges, menus
  and honest tristates. `menuconfig` is a real terminal editor. Random, allyes and allno
  configurations are generated valid by construction. Every preset has a size budget,
  enforced against committed baselines.

**The central claim met its first real counterexample.** Adding riscv32 did not stay
inside `arch/`, `targets/` and `config/`:

- `kernel/main` had to split its MMU bring-up behind a memory-model seam.
- `kernel/main` also used 64-bit atomics that the portability check never compiled,
  because the check only covers host-tested units.
- Shared code carried two latent 32-bit bugs: the device-tree reader rejected blobs above
  `isize::MAX`, and the unwinder had unsigned frame offsets.

These are one-time costs of the first no-MMU target, the same shape as Phase 1's
provider-unit cost. They are recorded rather than explained away. ARMv7-M is where the
rule gets tested again.

Other findings from this round:

- **Arm's timer compare value is signed.** `CNTP_TVAL_EL0` holds a signed 32-bit value.
  Arming it for `u32::MAX` ticks sign-extended into the past and caused an interrupt
  storm whenever the timer queue emptied. Only the long stress run found it, after
  109–406 seconds.
- **SGI pending state is per target, not per sender.** Three CPUs raising the same SGI
  at one masked CPU deliver it once.
- **Two branches invented the same configuration symbol under two names**
  (`QEMU_SMP`/`QEMU_CPUS`), and three merges needed fixes that neither side could see
  alone. Parallel work is fast. The integration tax is real and lands on whoever merges.
- **Random configurations earned their keep on the first run.** `MOCK_ARCH` was
  user-settable and broke 36 of 50 builds.

### The second round of landings

Six more branches landed in parallel. Each passed the same gates as the first round.
The tree now boots seven presets:

- `x86_64-qemu`, `i686-qemu`, `i686-large` and `aarch64-virt`;
- `i686-bios` and `x86_64-bios`, from a raw disk through SeaBIOS and `kinboot-bios`;
- `x86_64-efi`, through OVMF and `kinboot-efi`.

Every preset runs the 35 in-kernel checks and the stack-guard test.

- **Bootloaders.**
  - `kinboot-bios` is a 440-byte MBR plus a protected-mode stage 2. Stage 2 calls the
    BIOS through a thunk to enable A20 and read E820 or E801. It checks the kernel ELF
    against the memory map and a CRC-32 before handing over as a Multiboot 1 loader.
  - `kinboot-efi` loads the kernel from a FAT ESP that kbuild writes itself. It handles
    a stale map key at `ExitBootServices` by retrying, and hands over the boot
    protocol's own tags, which a new `bootinfo` provider reads.
  - Both disk images are byte-reproducible. kbuild gained per-unit targets and a
    `loader` layer.
- **`mm::paged`.** A region map with anonymous and physical backing. Faults zero pages
  on first touch and map 2 MiB blocks where a region allows. Copy-on-write shares
  pages through per-frame share counts, and every step fails cleanly when memory runs
  out. All three ports route kernel page faults through `hal::fault`.
- **Shared kernel state.** A kernel heap outlives boot behind the lock family, with
  interrupt-context rules and a fallible `KBox`. One locked clock and timer queue drive
  one-shot timer interrupts on every port, so the kernel is tickless. A 500 ms idle
  period costs one interrupt on aarch64 and nine on x86's PIT, against 50 for a tick.
  Lock-order violations fail debug boots.
- **Hardening.**
  - Kernel threads run on guard-paged stacks, and an overflow report names the thread.
  - i686 reports a real stack overflow from a `#DF` task gate.
  - Page 0 is unmapped on every port.
  - A reproducible build ID appears in every banner and backtrace, and
    `kbuild symbolize` refuses a log from another build.
- **Device model (Phase 3).**
  - `kernel/device` binds drivers to device-tree nodes, hands out typed resource
    claims that cannot overlap, and enforces probe phases as types.
  - The GIC and PL011 drivers moved to `drivers/`, and the GIC is chosen by
    `compatible` instead of `GICD_PIDR2`.
  - aarch64 maps exactly the device windows its drivers claimed.
  - One image passes on GICv2, GICv3, `max`, v4 with virtualization, and two other
    CPU models.

Findings from this round:

- **The hardware keeps no stale translations in QEMU.** Two TLB-related fixes cannot be
  observed under software emulation: reloading the PAE top-level table on i686, and
  the read-only invalidation on aarch64. They follow the architecture manuals, and
  nothing here tests them.
- **A too-coarse slice hid a missing preemption.** The PIT's 55 ms one-shot reach kept
  workers alternating even with slices removed. The check now also requires an
  interrupt count.
- **The `#DF` task gate needs `clts`.** Without it, the first SSE instruction in the
  report raised `#NM` and the report triple-faulted.
- **Discovery can hang on a hostile tree.** A device tree that moved the UART used to
  start the PL011 driver on unassigned memory. Discovery now checks the tree against
  the running console before any driver starts.
- **A host test was flaky for months unnoticed.** A `kernel/thread` test asserted on
  the mock's process-wide switch counter while the harness ran tests in parallel. It
  surfaced only when the suite ran under a second preset.

### Phase 2, so far

*(Written after the first round of landings. `mm::paged`, shared kernel state and the
smaller gaps listed below have since landed; see above.)*

Every Phase 2 item except `mm::paged` has landed on all three tier-1 architectures.
Each one gates the boot verdict or the host suite, and each check was falsified:
mutated, confirmed to fail, then restored. Today a boot runs 35 in-kernel checks on
each architecture, plus 13 host-tested units.

- **Address space.** The kernel runs on page tables it built itself. They are verified
  before they are loaded and checked against the CPU afterwards. W^X is enforced by
  the hardware and observed with real faults on x86_64 and with translation queries on
  aarch64. The boot-stack guard page is live, and `STACK_GUARD_TEST` in CI proves an
  overflow is caught.
- **Scheduling.** Fixed-priority round robin, preempted from the timer interrupt, with
  an idle thread that halts. The boot check demonstrates interleaving, priority, tick
  delivery and a halting idle thread.
- **Time.** `kernel/time` provides a monotonic clock that never divides on the hot
  path, and a fixed-capacity timer queue that supports tickless operation. The clock
  is driven by a PIT-calibrated TSC on x86 and by `CNTVCT_EL0` on aarch64.
- **Allocation.** `kalloc` has slab, buddy and arena allocators, context flags and
  poisoning. Deterministic fault injection covers every allocation site, and an
  in-kernel exhaust-and-free check runs on real frames.
- **Locking and objects.**
  - `sync` owns the one `LockFamily`, and debug builds check lock order: inversions,
    recursion and same-class nesting.
  - `kobject` handle transfer is all-or-nothing. `ipc` channels are built on it.
- **Crash reports.** Backtraces use frame pointers. The image is stripped, and a
  separate `.debug` bundle lets `kbuild symbolize` decode reports. `run` and `test`
  decode them automatically. CI crashes each architecture both ways and requires the
  decoded names.
- **Portability.** `kbuild portability` compiles every host-tested unit for riscv32i,
  riscv32imac and thumbv7m.

**The largest finding: a capability bound does not remove code.** `sync`, `kobject`
and `ipc` did not compile for either no-MMU target. On a machine without CAS, a
`compare_exchange` behind `A: HasCas` is still a compile error, and host tests could
not see it because the host has every atomic. See
[portability.md](portability.md#where-a-bound-is-not-enough).

Integration also turned up bugs that the unit-level tests could not have found:

- **Aliasing in `kernel/thread`.** Its `&mut self` switching API left a suspended
  thread holding a live exclusive reference to the table. The mock switch returns
  immediately, so host tests never saw it.
- **EOI ordering.** Sending the EOI after the tick hook instead of before it still
  passed the round-robin and priority checks. Only the tick-gap measurement caught it.
- **Page-table corruption.** The in-kernel suite's frame pool overwrote the live
  x86_64 top-level table, and the suite kept passing on cached translations. The live
  tables are now reserved from that pool and walked again after the suite.
- **Heap accounting.** In the slab-overflow path, the heap freed with the caller's
  layout instead of the size class, which under-counted the arena. Only the
  fault-injection sweep reached that path.
- **Lockdep false positives.** The first lock-order checker kept one global held-lock
  stack and reported ordinary contention as recursion.

An older finding still stands: **an IST alone does not make a stack overflow
diagnosable; a guard page does.** On x86_64 a real overflow is now reported from the
`#DF` IST stack. The `#DF` stack itself had first landed in `.rodata`, because an
immutable zeroed static is const data. That stayed harmless until real page
protections arrived.

Not done, and needed for the Phase 2 exit:

- **`mm::paged`:** virtual memory objects, demand paging, copy-on-write and huge
  pages.
- **Shared kernel state.** A global, locked heap and clock that outlive boot. Timer
  interrupts are still periodic rather than programmed from `next_deadline`, and sleep
  still counts ticks.
- **Stress.** The 24-hour stress run, and fault injection exercised across the whole
  kernel, not only `kalloc`.
- **Smaller gaps:**
  - Thread stacks have no guard pages.
  - On i686 a real overflow still triple-faults, because it needs a `#DF` task gate.
  - aarch64 device windows are hardcoded for QEMU `virt`.
  - Lockdep's first report is recorded but not printed.
  - No build ID ties a console log to its symbol bundle.
  - Page 0 is still mapped on x86.

### Phase 1, as it actually stands

Done: the `Arch` and capability trait family; x86_64, i686 and aarch64 ports, all
three booting from one unmodified `kernel/main`; distinct `PhysAddr`/`KernAddr`/
`UserAddr`; a physical frame allocator written once and generic over the
architecture; exception and interrupt entry on x86_64 and aarch64; `MockFull` and
`MockTiny` with a host test runner; the `cfg_in_body` and layering lints; and CI
building and booting every preset.

**The central claim is demonstrated rather than asserted.** One aarch64 image —
verified by md5, not by inspection — takes timer interrupts under GICv2 *and* GICv3,
selected at runtime, plus `gic-version=max`, `gic-version=4` with virtualization, and
several CPU models. That is the static-architecture/dynamic-devices split in
[portability.md](portability.md#static-architecture-dynamic-devices) working.

The exit criterion said adding an architecture must touch nothing outside `arch/`,
`targets/` and `config/`. That holds **now**, but was not free: the first additional
architecture also forced `kernel/main` to stop naming a specific one, and forced
kbuild to allow several units to *provide* a name so the configuration could pick.
Both were one-time costs, and the third architecture did land within the rule.

Landed since, as Phase 2 opened: an in-kernel test suite, `kbuild test --target`,
which boots a test image and takes the guest's exit status as the verdict — 17 checks
on x86_64 and i686, 10 on aarch64, which correctly *skips* rather than claims the
memory checks it cannot run.

Not done, and deliberately named rather than quietly folded into "done":

- ~~No page table manipulation or kernel address space.~~ Done in Phase 2: see above.
- ~~The GIC drivers are in `arch/aarch64/`~~ (moved to `drivers/irqchip/` in Phase 3) — not `drivers/irqchip/` where
  [architecture.md](architecture.md) says they belong, because `arch` may not depend
  on the `device` layer and nothing else would reference them yet. They move when the
  device framework can register and find them.
- ~~GIC detection reads `GICD_PIDR2`~~ (now the device tree's `compatible`), which reports the IP revision rather than the
  programming model — a GICv3 with `GICD_CTLR.ARE == 0` is legitimately a GICv2 and
  still reports 3. The real answer is the device tree's compatible string.

**Phase 0 closed** with `kbuild run --preset x86_64-qemu` building an x86_64 kernel
from source, booting it under QEMU, and exiting on the guest's own signal (exit 33,
which is `(0x10 << 1) | 1` from `isa-debug-exit`). Cold build 4.9s, warm 0.22s on the
content-addressed cache.

Three things the documentation had wrong until the code existed, now corrected in
place:

- QEMU's multiboot loader **refuses an ELF64 container** outright, so the image is
  repackaged to ELF32 after linking. The ELF64 survives as the debug artifact, which
  is the image/symbols split the deliverables already described — arriving a phase
  earlier than planned.
- `-no-shutdown` suppresses `isa-debug-exit` and turns every passing test into a
  timeout. It reads as a natural companion to `-no-reboot` and is not one.
- `naked_functions` was cited as a reason nightly is required and has been stable
  since 1.88. The real reasons are in
  [build-system.md](build-system.md#engine-a-pinned-nightly).

Carried into Phase 1 as known-incomplete: `compiler_builtins` is byte-at-a-time and
needs real intrinsics as the kernel grows; `HasSmp::cpu_id` returns a constant 0,
correct only while every preset sets `SMP=n`; and the image is identity-mapped at
1 MiB, so the move to the high half also flips the x86_64 code model back to
`kernel`.

The sequencing has one governing idea: **prove the portability claim before building
anything on top of it.** Phase 1 adds a second and third architecture while the
kernel is still small enough to restructure. Phase 4 scales down to a target with no
MMU and 64 KiB of RAM. If the design is wrong, those are the cheapest places to find
out.

---

## Phase 0 — Build system and first boot

*Nothing about the kernel can be evaluated until something builds and runs.*

- `kbuild` MVP: `.kcfg` parsing, constraint resolution, `.config`, generated
  `config.rs` and `--cfg` flags.
- Crate graph from `kmod.toml`, topological build, direct `rustc` invocation, content-
  addressed cache.
- Building `core` from source against in-tree target specs.
- `kbuild toolchain --verify` / `--fetch`: enforce the pin in
  [`toolchain.toml`](../toolchain.toml) before any build, and refuse to proceed on a
  `commit-hash`, `release`, or LLVM-version mismatch.
- Reproducibility from the start — path remapping, `SOURCE_DATE_EPOCH`, deterministic
  link order — because retrofitting byte-identical builds is far harder than never
  losing them.
- `x86_64` target spec, early serial console, panic handler, `kbuild run` under QEMU.
- **Boot protocol v1** — `BootInfo`, its tag encoding, and the forward/backward
  compatibility rules. Defined early because every loader and the kernel entry path
  both depend on it ([bootloader.md](bootloader.md#the-boot-protocol)).
- **Minimal `kinboot-efi`**: load the kernel from the ESP, collect the memory map,
  `ExitBootServices`, hand over `BootInfo`. Built on the built-in
  `x86_64-unknown-uefi` target, so it emits PE/COFF with no custom target spec.
- Skeleton `hal` traits — `Arch` only, no capability traits yet.
- **The QEMU test harness** ([testing.md](testing.md#the-qemu-protocol)): canonical
  machine per target, real result channels (`isa-debug-exit` / semihosting /
  `sifive_test`) rather than console scraping, two serial channels separating the human
  log from the machine one, timeouts that dump state instead of dying silently, and
  `-no-reboot` so a triple fault is a visible failure rather than a boot loop.

**Exit:** `kbuild run --preset x86_64-qemu` prints a banner and a panic backtrace over
serial, and a second invocation is a cache hit.

---

## Phase 1 — The portability spine

*The highest-risk phase. Everything after it assumes the answer.*

- The full `Arch` + capability trait family: `HasMmu`, `HasMpu`, `HasSmp`, `HasCas`,
  `HasCoherentDma`, `HasFpu`.
- `aarch64` port: QEMU `virt`, device tree, exception vectors, MMU bring-up.
- `i686` port: BIOS boot, PAE, 36-bit physical addresses behind 32-bit pointers.
- **`kinboot-bios`** — stage 1 in 440 bytes of real-mode assembly via `global_asm!`
  with `.code16`, stage 2 collecting E820/EDD/VBE in real mode before switching to
  protected mode and handing off to Rust. Early work, not Phase 7 polish: tier-1 i686
  has no other way to boot.
- Physical frame allocator, early page tables, kernel address space — written once,
  generic over `A: Arch + HasMmu`.
- `PhysAddr` / `KernAddr` / `UserAddr` as distinct types, tree-wide.
- Interrupt and exception entry, `IrqChip` trait with two implementations on aarch64
  (GICv2, GICv3) selected at runtime.
- `MockArch` family and the host test harness.
- The `cfg_in_body` and `layer_violation` lints.
- CI building and booting all three targets on every merge.

**Exit:** all three targets boot to a shell-less idle loop and pass the in-kernel test
suite. Adding `i686` after `aarch64` required changes to no file outside `arch/`,
`targets/`, and `config/` — verified by reading the diff, and recorded.

**If this fails**, the trait approach needs revision, and it is far better to learn it
here than in Phase 5.

---

## Phase 2 — Core kernel

- `kalloc`: fallible allocation, slab and buddy, allocation context flags, debug
  poisoning.
- `sync`: capability-selected lock types, lock-order checking in debug builds.
- `mm::paged`: virtual memory objects, demand paging, copy-on-write, huge pages.
- `time`: monotonic clock, timer subsystem, one-shot and periodic, tickless-capable.
- `sched`: single-CPU preemptive scheduler, task objects, context switch per arch,
  idle task.
- `kobject`: refcounting, type tags, rights masks.
- Kernel-internal channels (the IPC primitive, before any userspace exists).
- Symbolized panic backtraces against the separate symbol bundle.

**Exit:** kernel tasks run concurrently, preempt on a timer, allocate and free under
memory pressure, and survive a 24-hour stress run on all three targets. Allocation
failure is exercised by injection and handled everywhere.

---

## Phase 3 — SMP and the device model

- Per-CPU data as a `HasSmp`-gated abstraction resolving to a plain static on
  uniprocessor builds.
- Secondary CPU bringup: x86_64 (APIC/INIT-SIPI), aarch64 (PSCI).
- IPIs, TLB shootdown, memory barriers placed against a written memory model.
- SMP scheduler: per-CPU runqueues, load balancing, idle balancing.
- Epoch-based reclamation for read-mostly shared data.
- Device framework: FDT, ACPI, and PCIe enumeration into one node representation;
  driver binding; typed resource handles; probe phases as type-enforced tokens.
- Power management and driver removal in the interface from the start.
- Real console, real timer, real interrupt controller drivers per target.

**Exit:** 8-CPU QEMU boot on x86_64 and aarch64 with all CPUs scheduling; a stress run
with concurrent allocation, mapping, and teardown; devices enumerated from device tree
on aarch64 and from ACPI/PCIe on x86_64 using the same binding code.

---

## Phase 4 — Configurability, proven by scaling down

*The counterpart to Phase 1: prove the design holds at the other extreme.*

- Full config language: tristate, `choice`, `select`, ranges, `menuconfig` TUI.
- `armv7m` port: Thumb-2, MPU, NVIC, no MMU, XIP from flash.
- `riscv32` port (`rv32imac`, and an `rv32i` variant without atomics to exercise
  `HasCas` being absent).
- `mm::flat`: region allocator, optional MPU programming, no translation.
- **Build-time `BootInfo`** for targets with no bootloader: `kbuild` emits it as a
  `const` from the board description, so the kernel entry path is identical to the
  UEFI one at no runtime cost.
- Single-provider mode: config-pinned subsystems resolving to static type aliases,
  removing virtual dispatch from the interrupt path.
- Loadable modules: ELF loader, per-arch relocations, build identity and interface
  hashing, refcounted unload, `kbuild sdk`.
- Size budgets in CI with per-crate deltas.
- Randomized-configuration builds, nightly, reproducible by seed.

**Exit:** an `armv7m` image under 64 KiB boots on QEMU and on real hardware, running a
fixed-priority scheduler with in-kernel tasks. A `riscv32` image without atomics boots.
Modules load and unload on x86_64, and a module built for a different `.config` is
rejected with a message naming the difference. A thousand random configurations build.

---

## Phase 5 — Driver isolation

- Address-space-separated driver domains on `HasMmu` targets.
- IOMMU support: VT-d, AMD-Vi, SMMUv3 — DMA from an isolated driver is confined.
- The proxy layer: `Mmio<T>`, `DmaBuffer`, `IrqLine` implemented over domain crossing,
  with the same driver source running either way.
- Domain fault handling: contain, mark the device failed, tear down, restart.
- Per-domain resource accounting and quotas.
- Benchmarks quantifying the isolation cost, per driver class, published.

**Exit:** the same unmodified driver runs `InKernel` and `Isolated` on x86_64;
deliberately faulting it kills only its domain and it restarts; an isolated driver
cannot DMA outside its granted buffers, demonstrated by attempting it; the cost is
measured and documented rather than asserted.

---

## Phase 6 — Userspace, the native ABI, and the Linux personality

### 6a — Native first

The native object layer comes first because the Linux personality is built on top of
it. Building compatibility first would shape the kernel around Linux semantics and
leave the native ABI a veneer over them.

- Syscall entry per architecture; dispatch generated from `#[syscall]`.
- Handle tables, rights masks, handle transfer over channels.
- `Process`, `Thread`, `MemoryRegion`, `Mapping`, `Event`, `Timer`, `Job`.
- Explicit process construction; no `fork` in the native ABI.
- Completion-queue-based asynchronous primitives, with blocking wrappers.
- ELF loading, PIE, per-process address spaces.
- Native runtime library; first userspace programs.
- A VFS as a service over channels, and a simple in-memory filesystem.
- Syscall and parser fuzzing from the day each exists.

**6a exit:** a native userspace program starts, communicates over a channel, maps
memory, is scheduled against other processes, and exits cleanly on x86_64 and aarch64.
A process with no handles provably cannot affect anything. The native ABI is frozen
for the major version.

### 6b — The Linux personality

Same phase, immediately after, because it is what turns the kernel from demonstrable
into usable — and because every gap it exposes in the native interfaces is a gap worth
fixing while the ABI freeze is still fresh.

- Personality tag on `Process`, dispatch-table pointer in the thread control block,
  ELF-note-based tagging at load.
- Per-architecture Linux syscall tables, generated from an in-tree table.
- The fd table as a compat view over handles; ambient root namespace and `cwd`.
- `fork` / `clone` with copy-on-write; depends on `MM_PAGED`.
- POSIX signals: masks, handlers, `sigaltstack`, per-arch signal frames, restart
  semantics. Budget accordingly — this is the largest single item in the phase.
- The `Result` → `errno` mapping table, reviewed rather than accreted.
- Minimal `/proc`, `/sys`, `/dev`; `mmap` and `brk` semantics; TLS setup; vDSO.
- `-ENOSYS` with a named log line for gaps, fatal under a CI config flag.
- `ABI_LINUX` as a loadable module, exercising Phase 4's module work against something
  substantial.
- The compatibility corpus in CI, starting at static musl.

**6b exit:** an unmodified static busybox runs on x86_64 and aarch64 — shell, coreutils
applets, pipes, job control — from a corpus CI runs on every merge. Every gap found is
either implemented or recorded with its syscall name. At least one gap has been fixed
in the *native* ABI rather than papered over in the compat layer, demonstrating the
forcing function works.

---

## Phase 7 — Real hardware and real work

- Block layer, AHCI and NVMe drivers, a real on-disk filesystem.
- Network stack and at least one NIC driver; isolated-domain networking as the
  demonstration of Phase 5's value.
- USB host.
- Framebuffer and input.
- **Bring-up on real machines for every tier-1 target**; the nightly hardware rack.
  This is where the [hardware debt](testing.md#the-hardware-debt) comes due — weak
  memory ordering, cache/DMA coherency, device errata, and real firmware all arrive at
  once. Scheduled as substantial work, not a formality: a port that boots under QEMU is
  perhaps two thirds of the way to booting the machine QEMU was modelling.
- Boot integration: the EFI stub (kernel as its own PE/COFF application), Secure Boot
  and signature verification, measured boot with PCR extension and an event log,
  module signing, `uImage`/FIT and XIP packaging.
- Last-known-good escalation: boot counter in an EFI variable or reserved sector,
  automatic fallback `normal` → `safe` → previous kernel.
- Chainloading: VBR chainload on BIOS; `LoadImage`/`StartImage` on UEFI and nothing
  more, since the firmware's boot manager already does it better.
- Foreign-loader shims: U-Boot FIT, OpenSBI, GRUB/systemd-boot.
- Crash-dump format and offline decoder.
- First tagged release, with images, modules, symbol bundles, and SDK.

- Compatibility corpus extended to dynamic musl and then glibc userland, run against
  real storage and networking rather than an in-memory filesystem.

**Exit:** KinTane boots on physical hardware for all tier-1 targets, mounts a
filesystem from a real disk, serves network traffic, and survives a week-long soak —
with the soak workload driven by unmodified Linux programs, which is the point of
having the personality.

---

## After Phase 7

Candidates, in no fixed order: `riscv64` and `armv7a` promoted toward tier 1; a
big-endian target (`powerpc`) to flush out endianness assumptions; user-domain
drivers as a third isolation option; real-time scheduling guarantees and latency
measurement; hypervisor support; and the long-tail architectures in
[targets.md](targets.md#tier-3-and-the-long-tail) — which by then should be a matter
of writing an `arch/` crate and nothing else.

---

## Risks

| Risk | Where it bites | Mitigation |
|---|---|---|
| Trait bounds become unmanageable as subsystems compose | Phase 2–3 | Capability alias traits at subsystem boundaries; if it still hurts, revisit in Phase 1 while it is cheap |
| No-MMU support turns out to need parallel implementations rather than shared ones | Phase 4 | `mm::flat` is planned as a peer implementation, not an emulation; features that genuinely cannot exist are marked unavailable, not faked |
| Driver isolation is too slow to ever enable | Phase 5 | Measure early with a prototype in Phase 3; `InKernel` is always available, so the fallback is the status quo |
| `kbuild` becomes a second project competing for attention | continuous | Keep it minimal; it resolves config and calls `rustc`. Any feature that is not needed for a shipping kernel is out |
| Nightly toolchain churn breaks builds | continuous | Pinned toolchain with hashes; upgrades are deliberate, separate commits with a full-matrix build |
| QEMU-only validation hides weak-memory, cache/DMA and firmware bugs until Phase 7, when they all land at once | Phase 0–7 | Named and tracked rather than assumed away ([D12](decisions.md#d12--qemu-first-testing-with-the-gaps-named)): affected code is marked unvalidated until hardware runs it, the memory model is written before the SMP work, lock-free code is model-checked on the host, and no test may depend on emulator-specific behaviour |
| The Linux personality is a large, permanently incomplete surface; signals alone are substantial | Phase 6b | Compatibility is defined by a published corpus CI runs, never a percentage claim. Gaps are loud: `-ENOSYS` plus a named log line, fatal under CI. Scope grows corpus tier by corpus tier, starting at static musl |
| The compat path becomes the de-facto ABI and the native one gets no users | Phase 6b onward | The personality is a client of native interfaces, so it cannot outgrow them; native-first sequencing in 6a; the native runtime library and our own userland stay the primary target. Accepted as a live risk, not a solved one |
| Linux semantics leak into kernel design through the compat layer | Phase 6b onward | Each place the layer reaches past the native interfaces for performance is documented at the site with the measurement that justified it, so the exceptions stay countable |
| Scope is a full operating system built by very few people | all of it | Phases are ordered so that each produces something usable on its own; a project that stops after Phase 4 is still a working embedded kernel |

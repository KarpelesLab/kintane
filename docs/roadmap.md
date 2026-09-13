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
| 3 — SMP and the device model | in progress: aarch64 SMP, the device model from FDT and from ACPI/PCIe |
| 4 — Configurability, scaling down | in progress: riscv32 without an MMU, `mm::flat`, the full config language, random configs, size budgets |
| 5 onward | not started |

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

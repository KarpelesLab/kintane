# Roadmap

Phases are ordered by dependency, not by calendar. Each has **exit criteria** that are
demonstrable — something boots, something passes, something fits in a budget — because
"mostly done" is not a state a kernel phase can be in.

## Status

| Phase | State |
|---|---|
| 0 — Build system and first boot | **done** |
| 1 — The portability spine | **substantially done** — see below |
| 2 onward | not started |

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

Not done, and deliberately named rather than quietly folded into "done":

- **No in-kernel test suite.** `kbuild test` runs host tests only; `--target` reports
  that in-kernel tests are unimplemented. They belong with Phase 2, when there is a
  kernel worth testing from inside.
- **No page table manipulation or kernel address space.** The frame allocator exists;
  building mappings on top of it does not. Phase 2.
- **No i686 interrupt support.** That port boots and reports memory but has no IDT.
- **No TSS on x86_64**, so `#DF` has no IST: a stack overflow double-faults and then
  triple-faults while pushing the frame. Needs a GDT entry, and belongs with per-CPU
  data.
- **The GIC drivers are in `arch/aarch64/`**, not `drivers/irqchip/` where
  [architecture.md](architecture.md) says they belong, because `arch` may not depend
  on the `device` layer and nothing else would reference them yet. They move when the
  device framework can register and find them.
- **GIC detection reads `GICD_PIDR2`**, which reports the IP revision rather than the
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

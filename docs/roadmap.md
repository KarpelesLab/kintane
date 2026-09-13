# Roadmap

Phases are ordered by dependency, not by calendar. Each has **exit criteria** that are
demonstrable — something boots, something passes, something fits in a budget — because
"mostly done" is not a state a kernel phase can be in.

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
- Pinned toolchain in `toolchain.toml`.
- `x86_64` target spec, UEFI entry, early serial console, panic handler, `kbuild run`
  under QEMU.
- Skeleton `hal` traits — `Arch` only, no capability traits yet.

**Exit:** `kbuild run --preset x86_64-qemu` prints a banner and a panic backtrace over
serial, and a second invocation is a cache hit.

---

## Phase 1 — The portability spine

*The highest-risk phase. Everything after it assumes the answer.*

- The full `Arch` + capability trait family: `HasMmu`, `HasMpu`, `HasSmp`, `HasCas`,
  `HasCoherentDma`, `HasFpu`.
- `aarch64` port: QEMU `virt`, device tree, exception vectors, MMU bring-up.
- `i686` port: BIOS boot, PAE, 36-bit physical addresses behind 32-bit pointers.
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
- Bring-up on real machines for every tier-1 target; the nightly hardware rack.
- Boot integration: UEFI stub, secure boot, module signing, `uImage` and XIP
  packaging for embedded targets.
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
| The Linux personality is a large, permanently incomplete surface; signals alone are substantial | Phase 6b | Compatibility is defined by a published corpus CI runs, never a percentage claim. Gaps are loud: `-ENOSYS` plus a named log line, fatal under CI. Scope grows corpus tier by corpus tier, starting at static musl |
| The compat path becomes the de-facto ABI and the native one gets no users | Phase 6b onward | The personality is a client of native interfaces, so it cannot outgrow them; native-first sequencing in 6a; the native runtime library and our own userland stay the primary target. Accepted as a live risk, not a solved one |
| Linux semantics leak into kernel design through the compat layer | Phase 6b onward | Each place the layer reaches past the native interfaces for performance is documented at the site with the measurement that justified it, so the exceptions stay countable |
| Scope is a full operating system built by very few people | all of it | Phases are ordered so that each produces something usable on its own; a project that stops after Phase 4 is still a working embedded kernel |

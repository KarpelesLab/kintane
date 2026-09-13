# Foundational Decisions

Decisions that shape everything else, with the reasoning and the cost. When one of
these is revisited, the entry is updated rather than replaced, so the history of the
reasoning stays readable.

Status values: **accepted** · **provisional** (accepted but expected to be tested by
implementation) · **open**.

---

### D1 — Portability through traits, not the preprocessor
**Accepted.** 2026-09-13.

Hardware capabilities are expressed as Rust traits; code that needs a capability is
generic over it. `cfg` selects which crates and modules enter the build and appears
nowhere inside a function body.

*Why:* `#ifdef`-based portability produces configurations nobody compiles and code
paths nobody tests, and it interleaves what a function does with which machine it is
on. The type system can carry the same information and check it.

*Cost:* trait bounds propagate up call graphs; missing-capability errors are less
obvious than missing `#define`s; genuinely per-arch code still exists in `arch/`.

*Tested by:* Phase 1 (three architectures) and Phase 4 (scaling to 64 KiB).
See [portability.md](portability.md).

---

### D2 — Hybrid: monolithic core, optionally isolated drivers
**Accepted.** 2026-09-13.

The core is monolithic and privileged. Drivers are written against an abstract
resource interface and may run in the kernel address space, in an isolated address
space behind an IOMMU, or in userspace — chosen by configuration, from identical
source.

*Why:* a microkernel cannot serve no-MMU targets; a pure monolith discards isolation
on machines that could afford it. The hybrid lets one driver codebase serve both ends.

*Cost:* the driver interface is stricter than a monolith's, isolation costs a domain
crossing per operation, and high-throughput drivers will ship in-kernel regardless.

*Alternatives considered:* pure monolithic (simpler, but gives up fault isolation
permanently); pure microkernel (cleanest, but the no-MMU targets are half the point of
the project). See [architecture.md](architecture.md).

---

### D3 — Custom build tool, not cargo
**Accepted.** 2026-09-13.

`kbuild`, a Rust host binary, owns config resolution, the crate graph, `rustc`
invocation, linking, and packaging. Cargo is used only to build `kbuild` itself.

*Why:* cargo's feature unification cannot express `depends on` / `select` / mutually
exclusive choices; we need to build one crate twice in one image with different
settings; we are not publishing or resolving packages.

*Cost:* we maintain a build system. Mitigation: keep it minimal and refuse features
not needed to ship a kernel. Tracked as a risk in the [roadmap](roadmap.md#risks).

See [build-system.md](build-system.md).

---

### D4 — Our own userspace ABI, plus an in-kernel Linux personality
**Accepted** 2026-09-13. **Amended** 2026-09-13 — see below.

The native ABI is capability-based, handle-oriented, no `fork`, errors as values,
asynchronous primitives with synchronous wrappers.

*Why:* the Linux ABI assumes a machine model — MMU, POSIX process model, signals — we
deliberately do not require. A kernel serving no-MMU hardware cannot take it as a
foundation.

*Cost:* no existing native userland; we write one. A POSIX-ish library above the
native interface reduces porting pain.

**Amendment — the Linux personality.** The original decision also rejected Linux
syscall compatibility outright, on the grounds that partial compatibility produces
software that runs until it does not. That reasoning still holds as a warning, but it
does not outweigh what compatibility buys, so it is now a thing to manage rather than
a reason to refuse.

The kernel implements a second syscall ABI, selected per process by a personality tag
fixed at load time, so unmodified Linux binaries run transparently. It is in-kernel,
not a userspace translation layer.

*Why the change:* an existing userland from the day the syscall layer works — static
musl binaries, busybox, real test suites — instead of after we have written one. It
collapses the distance between "schedules processes" and "runs useful software", makes
Phase 7's storage and network work testable against programs not written to flatter
us, and gives the hardware a migration path.

*Why it does not undermine the native ABI:* the personality is a **client of the
native kernel interfaces, not a second path into the kernel**. Where it needs
something those interfaces cannot express, the native ABI is fixed — Linux is a
thorough specification of what a general-purpose kernel must do, and auditing our
interface against it is worth more than the compatibility itself.

*Cost:* a large and permanently incomplete surface; signals alone are substantial.
Ambient authority for processes that opt in, weakening the capability model for those
processes only. `ABI_LINUX` depends on `MM_PAGED` — `fork` needs copy-on-write — so it
does not exist on no-MMU targets, and it is tristate so a general-purpose build can
load it as a module. Managed by defining compatibility as a published corpus of
programs CI runs rather than as a percentage claim, and by making unimplemented
syscalls loud (`-ENOSYS` plus a named log line; fatal under CI).

*Risk carried:* the compat path could become the de-facto ABI, leaving the native one
with no users. Tracked in the [roadmap](roadmap.md#risks).

See [userspace-abi.md](userspace-abi.md#the-linux-personality).

---

### D5 — Tier-1 targets chosen to span the range
**Accepted.** 2026-09-13.

`x86_64`, `aarch64`, `i686`, `armv7m`, `riscv32`. Gated in CI on every merge.

*Why:* each covers an axis the others do not — SMP and IOMMU; a second page-table
format and runtime driver selection; physical addresses wider than pointers; no MMU
and a hard size budget; a third no-MMU ISA with optional atomics.

`riscv64` is tier 2 rather than tier 1 because it exercises little that `aarch64` and
`riscv32` do not, and is expected to be cheap to promote once both exist.

See [targets.md](targets.md).

---

### D6 — No `alloc` crate; all allocation is fallible
**Accepted.** 2026-09-13.

`kalloc` provides `try_*` APIs and allocation-context flags. `alloc` is not linked.

*Why:* `alloc`'s collections abort on allocation failure. A kernel may not abort
because a buffer could not be grown.

*Cost:* we reimplement collections. Bounded work, and they end up carrying kernel
concerns (DMA-addressable, may-sleep, NUMA node) that a general-purpose collection
should not.

---

### D7 — No stable module ABI; compatibility by hash
**Accepted.** 2026-09-13.

Modules record the build identity they were compiled against; the loader refuses
anything that does not match exactly.

*Why:* Rust has no stable ABI, and our layouts vary with configuration by design. A
version-string check would be a guess dressed as a guarantee.

*Cost:* modules are rebuilt for each kernel build. `kbuild sdk` makes that tractable
for third parties. See [modules.md](modules.md).

---

### D8 — Rust 1.98 baseline on a pinned nightly engine, no third-party crates
**Accepted.** 2026-09-13.

**Baseline: Rust 1.98.** The stable surface we may rely on freely; nothing older is
supported and no shims are written for it.

**Engine: an exactly pinned nightly**, recorded in [`toolchain.toml`](../toolchain.toml)
— channel, release, `commit-hash`, `commit-date`, and LLVM version, all verified by
`kbuild` before it builds anything.

*Why nightly is required rather than preferred* — verified against stable 1.98, not
assumed:

1. Custom JSON target specs are nightly-gated, and **there is no built-in
   `i686-unknown-none`**. Every other tier-1 target has a built-in bare-metal
   equivalent; 32-bit x86 does not. Tier-1 `i686` cannot exist on stable.
2. `extern "x86-interrupt"` for IDT entry points is still experimental.
3. Building `core` and `compiler_builtins` from source with our own codegen flags.

`naked_functions` was listed as a reason in the first draft of this decision and is
not one: `#[unsafe(naked)]` has been stable since 1.88. The unstable surface is
enumerated in `toolchain.toml`'s `[features]` table, and each bump re-checks whether
an entry can be dropped. The intent is for that table to empty and the engine to move
to stable.

*Why the pin is by hash:* the dated nightly manifest carries a SHA256 per component,
so pinning one manifest hash transitively pins all 997 packages — no per-component
list to drift. LLVM's version is pinned alongside rustc's because codegen differs
between LLVM releases even when the compiler does not change.

*Why no third-party crates:* everything under `hal/`, `arch/`, `kernel/`, `drivers/`,
`lib/` is written in-tree or vendored with a documented reason and license. Keeps the
`unsafe` budget and the audit surface under our control.

*Cost:* nightly churns, so bumps are deliberate, isolated commits with a full-matrix
build. We write things that exist elsewhere — the normal cost of a kernel.

---

### D9 — Epoch-based reclamation rather than RCU
**Provisional.** 2026-09-13.

For read-mostly shared data on SMP builds, until Phase 3 says otherwise.

*Why:* RCU's quiescent-state tracking interacts deeply with the scheduler and idle
loop, and committing to it before those exist would be premature.

*Revisit:* Phase 3, with a workload to measure.

---

### D10 — MIT license
**Accepted.** 2026-09-13.

The whole tree is MIT. See [LICENSE](../LICENSE).

*Why:* permissive licensing keeps the module story simple — loadable modules, derived
kernels, and vendor board-support packages may be proprietary without a derived-work
argument, which matters for a kernel aimed at embedded and industrial deployments. It
also excludes nobody: contributors whose employers restrict copyleft can participate.
MIT specifically, over Apache-2.0, for brevity and near-universal acceptance.

*Cost:* no explicit patent grant, which Apache-2.0 would provide — a real difference
if a contributor's employer holds patents reading on their contribution. No copyleft,
so improvements made downstream need not come back; we get contributions because the
project is worth contributing to, not because a license compels it.

*Consequences:* module signing ([D7](#d7--no-stable-module-abi-compatibility-by-hash))
is a security mechanism only, never a licensing one. Any vendored third-party code
must carry a compatible permissive license — [D8](#d8--pinned-nightly-toolchain-no-third-party-crates-in-the-kernel)
keeps that list near-empty, and each entry records its license alongside its
justification.

---

## Open questions

### Project governance
**Open.** Deferrable until there is more than one contributor, but the tier-1
promotion rules in [targets.md](targets.md) already assume named maintainers.

### Real-time guarantees
**Open.** The `armv7m` target invites an RTOS-shaped use case, which implies bounded
interrupt latency and a documented worst case. Whether that is a stated guarantee or a
best effort changes the locking design. Decide before Phase 4 fixes the embedded
scheduler.

### Memory model documentation
**Open.** Phase 3 places barriers "against a written memory model" — that document
does not exist yet, and writing it before the SMP work rather than after is strongly
preferable.

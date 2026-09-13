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

### D4 — Our own userspace ABI
**Accepted.** 2026-09-13.

Capability-based, handle-oriented, no `fork`, errors as values, asynchronous
primitives with synchronous wrappers. Not Linux-compatible.

*Why:* partial Linux compatibility is worse than none; the Linux ABI assumes a machine
model we deliberately do not require.

*Cost:* no existing userland; we write one. A POSIX-ish library above the native
interface reduces porting pain, and a userspace Linux compatibility layer stays
possible but is not a goal.

See [userspace-abi.md](userspace-abi.md).

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

### D8 — Pinned nightly toolchain, no third-party crates in the kernel
**Accepted.** 2026-09-13.

Exact nightly date and component hashes in `toolchain.toml`. Everything under `hal/`,
`arch/`, `kernel/`, `drivers/`, `lib/` is written in-tree or vendored with a
documented reason.

*Why:* nightly is unavoidable for custom target specs and `naked_functions`; an
unpinned nightly is not a build system. Zero external dependencies keeps the `unsafe`
budget and the audit surface under our control.

*Cost:* we write things that exist elsewhere. Accepted; it is the normal cost of a
kernel.

---

### D9 — Epoch-based reclamation rather than RCU
**Provisional.** 2026-09-13.

For read-mostly shared data on SMP builds, until Phase 3 says otherwise.

*Why:* RCU's quiescent-state tracking interacts deeply with the scheduler and idle
loop, and committing to it before those exist would be premature.

*Revisit:* Phase 3, with a workload to measure.

---

## Open questions

### License
**Open.** The choice interacts with the module story (a permissive license makes
proprietary modules straightforward; a copyleft one deliberately does not) and with
whether contributions can be accepted from people whose employers restrict copyleft.
Candidates: MPL-2.0 (file-level copyleft, module-friendly), GPL-2.0 (Linux-aligned,
maximises contribution reuse), Apache-2.0 (permissive, patent grant), or dual
licensing. Must be resolved before the first external contribution.

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

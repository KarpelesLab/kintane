# KinTane

A modular operating system kernel written in Rust, targeting the full range from
microcontrollers without an MMU to multi-socket SMP machines — with one codebase and
no conditional compilation sprinkled through the logic.

## What this is

KinTane is a from-scratch kernel with three commitments:

1. **Breadth of hardware.** Platforms Linux has dropped, or never served well, are
   first-class here: 32-bit x86, no-MMU microcontrollers, unusual interrupt
   controllers, machines without atomic compare-and-swap. So are modern 64-bit SMP
   systems. Neither is a second-class citizen.

2. **Portability through the type system, not the preprocessor.** Architecture
   differences are expressed as traits and associated constants, resolved at compile
   time. A function that maps a page is generic over an architecture that *has* an
   MMU; on a target without one, that code does not exist rather than being
   `#ifdef`-ed out. See [docs/portability.md](docs/portability.md) — this is the
   central idea of the project.

3. **Configurability as a build-time contract.** Like Linux's Kconfig, but the
   config drives which crates enter the graph and which associated types get
   monomorphized, not which lines the preprocessor keeps. See
   [docs/build-system.md](docs/build-system.md).

## What this is not

- Not a crate. It will never be published to crates.io, and cargo is not the build
  system. Builds go through `kbuild`, a purpose-built Rust tool that owns config
  resolution, the crate graph, and `rustc` invocation.
- Not a Linux clone. The native userspace ABI is our own — capability-based and
  designed for machines that may have no MMU. A per-process **Linux personality** runs
  unmodified Linux binaries on top of those native interfaces, which gives us a real
  userland for testing without making Linux the foundation. See
  [docs/userspace-abi.md](docs/userspace-abi.md).
- Not source-distributed. Deliverables are compiled kernel images, optional loadable
  modules, and separately packaged debug symbols.

## Structure

Modular monolithic core with **optional driver isolation**: the same driver source
runs in the kernel address space on a microcontroller and in its own address space,
behind an IOMMU, on a server. Where the driver runs is a configuration decision, not
a rewrite. See [docs/architecture.md](docs/architecture.md).

## Status

Pre-implementation. The repository currently contains design documentation, a
roadmap, and the pinned toolchain. Nothing boots yet.

The build engine is pinned exactly in [`toolchain.toml`](toolchain.toml): a Rust 1.98
stable baseline on a hash-pinned nightly, with the unstable surface enumerated in one
table. Nightly is required rather than preferred — 32-bit x86 bare metal has no
built-in rustc target, and hand-written target specs are nightly-gated.

Start with the [roadmap](docs/roadmap.md) for what is planned and in what order, and
[docs/decisions.md](docs/decisions.md) for the foundational choices and why they were
made.

## Documentation

| Document | Contents |
|---|---|
| [architecture.md](docs/architecture.md) | Layering, subsystems, the isolation model |
| [portability.md](docs/portability.md) | How we avoid `#ifdef`; the `Arch` trait family |
| [build-system.md](docs/build-system.md) | `kbuild`, the config language, the crate graph |
| [targets.md](docs/targets.md) | Supported platforms and support tiers |
| [bootloader.md](docs/bootloader.md) | The boot protocol, and one loader per boot mechanism |
| [modules.md](docs/modules.md) | Loadable modules and the module ABI problem |
| [userspace-abi.md](docs/userspace-abi.md) | Syscall and object model principles |
| [testing.md](docs/testing.md) | Host tests, QEMU harness, CI gates |
| [coding-standards.md](docs/coding-standards.md) | `unsafe` policy, lints, conventions |
| [roadmap.md](docs/roadmap.md) | Phases, exit criteria, sequencing |
| [decisions.md](docs/decisions.md) | Foundational decisions and their rationale |

## Name

Kin (欽) — regard, attend to. Tane (種) — seed, kind, species. A kernel that attends to
the many kinds of machine.

## License

MIT. See [LICENSE](LICENSE).

Permissive by choice: loadable modules and derived kernels may be proprietary, and
contributors whose employers restrict copyleft are not excluded. See
[D10](docs/decisions.md#d10--mit-license).

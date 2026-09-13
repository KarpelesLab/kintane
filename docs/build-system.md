# Build System

## Why not cargo

Cargo is an excellent package manager for applications and libraries. A kernel is
neither. Specifically:

- **Features are additive and unified.** Cargo will silently enable a feature because
  some other crate in the graph wanted it. A kernel configuration needs `depends on`,
  `select`, mutually exclusive `choice` groups, and the ability to say *no*
  definitively.
- **One crate, one set of cfgs.** We need to build the same driver crate twice in one
  image — once `InKernel`, once for an isolated domain with a different allocator and
  a different panic strategy.
- **`build.rs` is the wrong hook.** Config resolution is a whole-tree constraint
  problem, not a per-crate script.
- **Target JSON and `build-std` are still awkward**, and we need to build `core` from
  source for every target, with our own codegen flags.
- **We are not shipping source.** Dependency resolution, semver, and registry
  publishing are machinery we pay for and never use.

`kbuild` is a Rust host binary (built by cargo — it has no special needs) that owns
config resolution, the crate graph, `rustc` invocation, linking, and image packaging.

## The configuration system

### Config language

Declarative `.kcfg` files, Kconfig-shaped but with stricter typing. Familiar to
anyone who has configured a Linux kernel, without the historical warts.

```kcfg
config SMP
    bool "Symmetric multiprocessing"
    depends on ARCH_HAS_SMP
    default y if ARCH_HAS_SMP
    help
        Support more than one CPU. Requires an architecture that
        implements the HasSmp capability.

config NR_CPUS
    int "Maximum number of CPUs"
    depends on SMP
    range 2 4096
    default 8

choice MM_MODEL
    prompt "Memory model"
    default MM_PAGED if ARCH_HAS_MMU
    default MM_FLAT

    config MM_PAGED
        bool "Paged virtual memory"
        depends on ARCH_HAS_MMU
        select KALLOC_LARGE

    config MM_FLAT
        bool "Flat physical memory"
        help
            No address translation. Required on targets without an MMU;
            selectable on MMU targets for minimal-overhead builds.
endchoice

config DRIVER_ISOLATION
    bool "Run drivers in separate address spaces"
    depends on MM_PAGED
    default y if SMP

config IRQCHIP_SINGLE_PROVIDER
    bool "Statically bind exactly one interrupt controller"
    default y if !DEVICETREE
    help
        Removes virtual dispatch from the interrupt path. Only valid when
        the build contains exactly one irqchip driver.
```

`ARCH_HAS_*` symbols are not user-settable. They are emitted by the architecture
definition and describe what the hardware can do; everything else depends on them.
This means the config system knows that `SMP` is impossible on a Cortex-M without
anyone writing that rule down twice.

### Resolution

`kbuild config` resolves a configuration to a fixed point, reports conflicts with the
chain of constraints that caused them, and writes `.config` — a complete, explicit
record of every symbol's value. Nothing is left implicit; a `.config` plus a source
tree is a reproducible build.

```
$ kbuild config --preset x86_64-server
$ kbuild menuconfig                    # interactive TUI
$ kbuild config --set SMP=n            # re-resolves, may reject
error: cannot set SMP=n
  SMP is selected by NUMA
    NUMA is enabled by preset x86_64-server
  to disable SMP, first disable NUMA
```

### Presets

Named starting points under `config/presets/`, covering the common cases so nobody
configures a kernel from zero: `x86_64-server`, `x86_64-qemu`, `aarch64-virt`,
`i686-pc-legacy`, `armv7m-minimal`, plus a `debug-everything` preset used by CI.

## Generated sources

`kbuild` generates a small, strictly bounded set of Rust source into `build/gen/`:

1. **`config.rs`** — every config symbol as a typed constant.
   ```rust
   pub const NR_CPUS: usize = 8;
   pub const DRIVER_ISOLATION: bool = true;
   ```
   Used in preference to `--cfg` wherever the value flows into logic, because a
   `const` participates in type checking and dead-code elimination while a `cfg`
   only deletes text.

2. **`--cfg` flags** — only for crate- and module-level selection, per the rule in
   [portability.md](portability.md#where-cfg-is-still-allowed).

3. **Provider aliases** — when a subsystem is pinned to one implementation:
   ```rust
   pub type SystemIrqChip = drivers::irqchip::nvic::Nvic;
   ```
   This is the only place `kbuild` emits type definitions, and it does so from a
   fixed template.

4. **The registry tables** — driver match tables, initcall ordering, syscall dispatch.
   Built from `#[driver]` / `#[syscall]` attributes collected across the tree, so
   there is no hand-maintained list to forget to update.

Generated code is checked into neither git nor the deliverable, is always
regenerated, and is `rustfmt`-ed so that diffing two configurations is readable.

## The crate graph

Each buildable unit declares itself in a `kmod.toml`:

```toml
[unit]
name = "mm"
kind = "kernel-lib"

[deps]
hal = "*"
kalloc = "*"
sync = "*"

[config]
requires = ["MM_PAGED || MM_FLAT"]

[sources]
common = ["src/lib.rs", "src/frame.rs"]
paged  = { cfg = "MM_PAGED", files = ["src/paged/**"] }
flat   = { cfg = "MM_FLAT",  files = ["src/flat/**"] }

[layer]
# enforced: may not depend on anything above this layer
level = "core"
```

`kbuild` builds the graph, checks layering, topologically sorts, and invokes `rustc`
once per unit with explicit `--extern` paths. No transitive dependency is visible
unless declared.

### Building `core`

Every target builds `core` (and `compiler_builtins`) from the pinned toolchain's
source with our codegen flags — no prebuilt `core` from rustup, because we need
matching `panic_immediate_abort`, `-C soft-float` on targets that require it, and
consistent `-C relocation-model`.

### Caching

Content-addressed: the key is the hash of (source files, rustc version, full argument
vector, hashes of all dependency outputs). A cache hit is a hardlink. This makes
"rebuild all six tier-1 targets" cheap in CI, which is what makes the
every-target-every-merge rule in [testing.md](testing.md) affordable.

## Commands

```
kbuild config [--preset P] [--set K=V]   resolve configuration
kbuild menuconfig                         interactive configuration
kbuild build [--target T]                 build the kernel image
kbuild modules                            build loadable modules
kbuild image [--format elf|bin|uki|uimage]  package a bootable artifact
kbuild symbols                            extract the separate debug-symbol bundle
kbuild run [--machine M]                  boot the image under QEMU
kbuild test [--host|--target]             run the test suites
kbuild size [--compare REF]               size report, optionally vs a baseline
kbuild sdk                                produce a module SDK for this config
```

## Toolchain policy

- **Pinned nightly**, recorded in `toolchain.toml` with an exact date and the SHA256
  of each required component. Nightly is unavoidable — we need features like
  `naked_functions` for exception entry and custom target specs — but an unpinned
  nightly is not a build system, it is a lottery.
- **Toolchain bumps are deliberate changes** with their own commit, a note on what
  they buy, and a full-matrix build.
- **`rustc` is invoked directly.** No `cargo`, no `rustup` wrapper shims in the build
  path; `kbuild` resolves the absolute toolchain paths once and records them.
- **No third-party crates in the kernel.** Everything under `hal/`, `arch/`,
  `kernel/`, `drivers/`, and `lib/` is written here or vendored with a documented
  reason. This is a defensible position for a kernel and it keeps the audit surface
  and the `unsafe` budget under our control.

## Deliverables

A release produces:

- `kintane-<version>-<target>-<configname>.img` — the bootable image.
- `modules/` — loadable modules for that exact configuration.
- `kintane-<...>.symbols.tar.zst` — DWARF and a symbol table, stripped from the
  image and shipped separately.
- `.config` — the exact configuration, so a build can be reproduced.
- `sdk/` — optional, for building out-of-tree modules against this image; see
  [modules.md](modules.md).

Images are stripped by default. The symbol bundle is what makes a crash report from
the field decodable without shipping debug info to every device.

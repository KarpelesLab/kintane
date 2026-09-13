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
- **Building `core` from source is a cargo problem, not a rustc problem.** We need
  `core` and `compiler_builtins` compiled per target with our own codegen flags.
  Through cargo that means `-Z build-std` and its constraints; calling `rustc`
  directly makes it just another crate in the graph.
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
kbuild toolchain [--verify|--fetch]       check or install the pinned toolchain
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

Recorded in [`toolchain.toml`](../toolchain.toml) at the repository root. An unpinned
toolchain is not a build system, it is a lottery.

### Baseline: Rust 1.98

The stable release whose language and library surface we may rely on freely. Nothing
older is supported and no compatibility shims are written for it. Raising the baseline
is a deliberate change with its own commit, not a side effect of a nightly bump.

### Engine: a pinned nightly

Nightly is **required, not preferred**. Three things force it, each verified against
stable 1.98 rather than assumed:

1. **Custom JSON target specifications are nightly-gated** — stable rejects them
   outright: *"custom targets are unstable and require `-Zunstable-options`"*. This
   matters because **there is no built-in `i686-unknown-none`**. Every other tier-1
   target has a built-in bare-metal equivalent (`x86_64-unknown-none`,
   `aarch64-unknown-none-softfloat`, `thumbv7m-none-eabi`,
   `riscv32imac-unknown-none-elf`), but 32-bit x86 bare metal does not exist as a
   built-in target and must be described by hand. Our tier-1 `i686` support cannot
   exist on stable.
2. **`extern "x86-interrupt"`** for IDT entry points on x86_64 and i686 — still
   experimental.
3. **Building `core` and `compiler_builtins` from source** with our own codegen
   flags.

Notably *not* a reason any more: `naked_functions`. `#[unsafe(naked)]` and
`naked_asm!` are stable as of 1.88 and compile fine on 1.98, as does
`#[diagnostic::on_unimplemented]`, which [portability.md](portability.md#what-this-costs)
relies on for capability-trait error messages.

The unstable surface is enumerated in `toolchain.toml`'s `[features]` table and
nowhere else. Adding an entry needs a written justification and a reviewer. Every
bump re-checks whether an entry has stabilized and can be dropped — the goal is for
that table to shrink to nothing and this section to name a stable channel.

### How the pin is enforced

`kbuild` runs `rustc -vV` before anything else and compares **`commit-hash`,
`release`, and `LLVM version`** against `toolchain.toml`. A mismatch is a hard error,
not a warning. A kernel built with a different compiler is a different kernel, and
LLVM's version is part of that: codegen differs between LLVM releases even when rustc
does not change.

Component integrity comes from the dated manifest at
`static.rust-lang.org/dist/<date>/channel-rust-nightly.toml`, which carries a SHA256
for each component package it describes. **Pinning that one manifest hash transitively
pins all 997 of them**, so there is no per-component hash list to maintain and drift.
`kbuild toolchain --verify` checks it; `kbuild toolchain --fetch` installs from it.

Dated nightlies are retained upstream, but a reproducible build should not depend on
someone else's retention policy, so releases are cut against a local mirror recorded
in the same file.

### Bumping

A toolchain bump is its own commit, containing only `toolchain.toml` and whatever
minimal changes the new compiler forces, with a message stating what the bump buys,
which `[features]` entries it lets us drop, and the result of a full-matrix build.
Bumps do not ride along with feature work.

### Reproducibility

Same source plus same `.config` plus same `toolchain.toml` must produce a
byte-identical image on any machine:

- `--remap-path-prefix` for every input, so no build directory appears in the binary.
- `SOURCE_DATE_EPOCH` derived from the commit, never from the clock.
- Deterministic link order — the crate graph is topologically sorted with ties broken
  by name, never by filesystem iteration order.
- No `__DATE__`-equivalents, no hostname, no build counter anywhere in the image.
- `kbuild build` records the hash of every output. CI rebuilds each release from
  scratch on a different machine and compares; a mismatch blocks the release.

This is also what makes the build identity in [modules.md](modules.md) meaningful — a
module's compatibility check is only as trustworthy as the determinism of the build it
names.

### Invocation

**`rustc` is invoked directly.** No `cargo`, no `rustup` shims in the build path;
`kbuild` resolves absolute toolchain paths once and records them. Note that
`-Z build-std` never enters the picture — it is a *cargo* feature, and since we call
`rustc` ourselves, compiling `core` from source is simply compiling a crate.
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

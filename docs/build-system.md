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

#### The language, as implemented

`kbuild/src/kcfg` implements the following. Each rule is host-tested, and each rule
that changes a verdict has a test that fails if the rule is removed.

- **Types.** `bool`, `tristate`, `int`, `hex` and `string`. A `hex` value must be
  written with its `0x` prefix. An address a factor of sixteen away from the one the
  reader assumed is not a typo worth allowing. Hex values are unsigned 64-bit, so an
  upper-half address is not a negative number. Generated Rust gives `int` as `usize`,
  `hex` as `u64` and `tristate` as an enum, so `m` is never silently truthy.
- **Menus.** `menu "Title"` ... `endmenu` groups entries for `menuconfig`. A menu's
  `depends on` is added to everything inside it, nested menus and choices included, by
  folding it into each entry's own condition. A menu must close in the file that opened
  it.
- **Ranges.** `range LOW HIGH [if CONDITION]`, on `int` and `hex` only; any other type is
  a parse error. When several are given, the first whose condition holds applies, as in
  Kconfig, so the conditional ones go first. A value outside its range is an error,
  whether a preset asked for it or a default produced it. The error names the range that
  applied and why.
- **Choices.** Members are `bool`; exactly one usable member is on. A member with unmet
  dependencies is reported as such rather than as "another member was chosen".
- **`select` does not override `depends on`.** Selecting a symbol whose dependencies are
  unmet is an error naming the selector, the target, and the dependency that is off. In
  Kconfig it is a warning, and the result is a symbol that is on without what it needs.
  Only `bool` and `tristate` symbols can be selected, never a choice member: a choice
  already decides its member.
- **`tristate` and modules.** `m` is meaningful only while `MODULES` is `y`, which today
  means an x86-64 kernel with `MM_PAGED`; see [modules.md](modules.md#as-built).
  - Asking for `m` while `MODULES` is not `y` (preset, `--set` or `menuconfig`) is an error
    naming why. A module quietly becoming built-in code is not what was asked for.
  - With `MODULES=y`, an `m` enables exactly the units of kind `module` it gates. A library
    unit enabled by `m` is an error (it would be linked in as `y`), and so is a module unit
    whose condition is `y` (it cannot be linked in at all). A tristate that should only ever
    be a module caps itself with `depends on ... && m`, as `MODULE_TEST` does.
  - `default m`, or a `select` from an `m` symbol, is built in. The recorded reason says
    so ("it would be m (...), and MODULES is not y").
  - `depends on` limits a tristate to its condition's value: a driver on an `m` bus can
    be `m` but not `y`.
  - A `bool` whose condition is `m` may still be `y`, since it has no module form.
- **Not implemented:** `imply`, `visible if` and `comment`. This document does not use
  them, and nothing in the tree needs them.

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

#### `menuconfig`

`kbuild menuconfig [--preset P]` starts from a preset and lets a person walk the menus
and choices in declaration order and change values. The keys are:

- arrows or `hjkl` to move, enter to open a menu or change a value, space to toggle,
  `y`/`n`/`m` to set directly;
- `?` for a symbol's help, `w` for why it has its value (following a `select` back to
  whatever set its selector), `s` to save, `q` to quit.

Every change is re-resolved before it is accepted. A change the resolver refuses is not
applied, and the resolver's own explanation is shown in its place, so the editor can
never hold an invalid configuration.

Saving writes `.config` and `menuconfig.preset`. A build resolves from presets, not from
`.config`, so the preset is what to build: `kbuild build --preset ./menuconfig.preset`.
A `--preset` that contains a `/` is a file path.

Raw terminal mode comes from `stty`, not from `termios` declared by hand. The `termios`
struct's layout differs between macOS and Linux, and a hand-written definition that
nothing checks is a stack-corruption bug in a build tool. The editor itself
(`menuconfig::Session`) is plain data driven by key events, and its tests run it without
a terminal.

#### Generated configurations

Every command takes `--random [--seed N]`, `--allyes` or `--allno`. Each extends the
preset and `--set` requests into a complete configuration:

- **`--random`:** each settable symbol at random, each choice a random usable member, and
  each ranged `int` or `hex` biased towards its bounds. Without `--seed`, a seed is
  picked and printed.
- **`--allyes`:** everything on that can be on.
- **`--allno`:** everything off that can be off.

The preset's own requests are never changed, and a generated configuration is always
valid. Proposals are made one symbol at a time, and each is kept only if the whole
request set still resolves. The same preset and seed give the same configuration on any
machine, so `kbuild build --preset x86_64-qemu --random --seed 1234` reproduces a
nightly failure exactly. `kbuild randconfig-build --count K --seed S` builds `K` of
them, and `--allyes` or `--allno` there builds each preset's boundary. Either way it
reports every failure with that command; see
[testing.md](testing.md#configuration-coverage).

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

A unit's `kind` is `lib`, `bin` (the kernel image, or an image for a target of its own),
or `module`: a loadable module, built after the kernel against its configuration, into a
relocatable object the kernel loads at run time. A module links only units at `core` or
below, and nothing links a module. See [modules.md](modules.md#as-built).

### Building `core`

Every target builds `core` (and `compiler_builtins`) from the pinned toolchain's
source with our codegen flags — no prebuilt `core` from rustup, because we need
matching `panic_immediate_abort`, `-C soft-float` on targets that require it, and
consistent `-C relocation-model`.

### Images for another target

A unit may name a target of its own:

```toml
[unit]
name = "kinboot_efi"
kind = "bin"
layer = "loader"
target = "x86_64-unknown-uefi"
```

Such a unit is a separate image — today, the UEFI loader, and with `CHAIN_TEST` the UEFI
chainload test application — and it is built after the kernel in a build of its own under
`build/<kernel target>/<triple>/`: `core`,
`compiler_builtins` and the generated config compiled for that triple, then its
dependencies, then itself. Nothing compiled is shared with the kernel, which is not
waste: the kernel's `boot_protocol` rlib is for a different target and could not be
linked here. The triple is part of every cache key. The graph enforces the rest: a
`target` is only for `bin` units, nothing may depend on such a unit, and the `loader`
layer sits just above `hal`, so a loader can link the boot protocol and nothing of the
kernel's.

The target must be one built into the pinned rustc, which is the point: firmware
targets are exactly what rustc already describes, and they need no linker script.

The image format decides where each such image goes, by unit name: the `efi-esp` format
places `kinboot_efi` at `EFI/BOOT/BOOTX64.EFI` and `kinboot_efi_chaintest` at
`EFI/KINTANE/CHAIN.EFI` (`kbuild/src/build.rs`). An image that is built but that no format
has a place for is an error, not a file silently left out of the disk.

### Caching

Content-addressed: the key is the hash of (source files, rustc version, full argument
vector, hashes of all dependency outputs). A cache hit is a hardlink. This makes
"rebuild all six tier-1 targets" cheap in CI, which is what makes the
every-target-every-merge rule in [testing.md](testing.md) affordable.

## Commands

```
kbuild toolchain [--verify|--fetch]       check or install the pinned toolchain
kbuild config [--preset P] [--set K=V]   resolve configuration
kbuild config --random [--seed N]         ... extended randomly (any command takes this)
kbuild config --allyes | --allno          ... extended to a boundary (any command)
kbuild menuconfig [--preset P]            interactive configuration; saves menuconfig.preset
kbuild randconfig-build --count K --seed S  build sampled configurations, report each failure
kbuild randconfig-build --allyes|--allno  build every preset's boundary configuration
kbuild build [--target T]                 build the kernel image
kbuild modules [--preset P]               build the kernel, its modules, and the bundle
kbuild image [--format elf|bin|uki|uimage]  package a bootable artifact
kbuild symbols                            extract the separate debug-symbol bundle
kbuild symbolize [--preset P] [log]       decode a guest backtrace against the symbol bundle
kbuild run [--machine M]                  boot the image under QEMU
kbuild test [--host|--target]             run the test suites
kbuild lint                               cfg-in-body and the other rules rustc cannot express
kbuild portability                        compile host-testable units for rv32i, rv32imac, thumbv7m
kbuild stress --duration 10m              run the stress image, killing it if its heartbeat stops
kbuild size --preset P [--compare REF|FILE] [--save FILE] [--update-baseline]
                                          sections and per-crate sizes, against the preset's
                                          SIZE_BUDGET_KIB and a baseline report
kbuild sdk [--preset P]                   build, then write the module SDK to build/<target>/sdk
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
- UEFI images are linked with `/Brepro` and without a PDB. lld-link otherwise stamps the
  PE with the link time, and the PDB rustc asks for records a temporary directory it
  names at random — which reaches the PE through its debug directory. CI builds the
  `x86_64-efi` disk image twice from scratch and compares it too.
- The ESP disk image records the FAT epoch for every timestamp and a constant volume
  serial and disk signature, and writes directory entries in name order.

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
- `boot/` — the loader for that platform: a signed `kinboot-efi` PE/COFF binary, the
  `kinboot-bios` stages, or nothing at all where the kernel is its own boot image.
  Built from the same pinned toolchain under the same reproducibility rules; see
  [bootloader.md](bootloader.md).
- `modules/` — loadable modules for that exact configuration.
- `kintane-<...>.symbols.tar.zst` — DWARF and a symbol table, stripped from the
  image and shipped separately.
- `.config` — the exact configuration, so a build can be reproduced.
- `sdk/` — optional, for building out-of-tree modules against this image; see
  [modules.md](modules.md).

Images are stripped by default. The symbol bundle is what makes a crash report from
the field decodable without shipping debug info to every device.

### What a build produces today

The release packaging above is ahead of the code. What `kbuild build` writes to
`build/<target>/out/`:

- `kintane.elf` — the linked image, with symbols and DWARF. The debug artifact, and the
  file the reproducibility check hashes.
- `kintane.debug` — the symbol bundle: `llvm-objcopy --only-keep-debug` of the linked
  image. It holds the symbol table and DWARF and no code, and it is what
  `kbuild symbolize` reads. It also carries the image's build ID, in a section of its own
  (`.kintane.build-id`), because `--only-keep-debug` drops the loaded bytes the ID is in.
- `kintane.mb32.elf` (x86_64) or `kintane.img.elf` (everything else) — the bootable
  image, `--strip-all`. It has no symbol table, and CI checks that.
- `kinboot-bios.img` (x86 with `KINBOOT_BIOS=y`) — a raw MBR disk: `kinboot-bios`
  stage 1 and stage 2, the boot entries, then the bootable image above, byte for byte;
  with `CHAIN_TEST`, also the BIOS chain test record as partition 2. `kbuild run` and
  `kbuild test --target` boot this instead of passing `-kernel`. The loader itself is
  built beside it in `build/<target>/kinboot-bios/`, for its own target
  (`targets/i686-kinboot.json`) with its own `core`; see
  [bootloader.md](bootloader.md#build-integration).
- With `KINBOOT_EFI` (the `x86_64-efi` preset): `kintane.esp.img`, a 33 MiB disk image
  whose EFI system partition holds `EFI/BOOT/BOOTX64.EFI` — the loader, built to
  `build/x86_64-kintane/x86_64-unknown-uefi/kinboot_efi.efi` — `KINTANE/BOOT.CFG`, the boot
  entries, and `KINTANE/KERNEL.ELF`, the stripped ELF64. The ELF64 rather than the ELF32:
  the loader enters in long mode. With `CHAIN_TEST` it also holds `EFI/KINTANE/CHAIN.EFI`.

- With `MODULES` and at least one module unit at `m`: `modules/<name>.kmod`, one
  relocatable object per module, and `modules.kmb`, the bundle that carries them. A
  `-kernel` boot passes the bundle with `-initrd`. The modules' own builds, compiled with
  bitcode, are under `build/<target>/modules/`, one directory per configuration they were
  built against. See [modules.md](modules.md#building-one).

Both disk images carry the same boot entries, written by `kbuild/src/bootcfg.rs` from
`CMDLINE`, `BOOT_MODE`, `BOOT_MENU_TIMEOUT` and `CHAIN_TEST`. A `-kernel` boot gets the
default entry's command line through `-append` instead. The entry format belongs to
`boot/kinboot-menu`. kbuild cannot link that crate, so the writer and the parser are held
together by two files in `boot/kinboot-menu/testdata`: kbuild's tests require it to write
exactly those bytes, and the crate's tests require its parser to read them as meant.

### The build ID

After linking, kbuild stamps a build ID into the image (`kbuild/src/buildid.rs`). The ID
is the first 20 bytes of a SHA-256 over the entry point and every loadable segment, with
its own 20 bytes read as zero. So it cannot depend on itself, stamping twice changes
nothing, and two clean builds of one tree stay byte-identical. The kernel reserves the
bytes after a marker in `.rodata` (`lib/buildid`), kbuild refuses an image in which that
marker does not occur exactly once, and the stamped file replaces the linked one by rename,
so a linked image hard-linked from the cache is never edited in place. The ID is printed
by the build (`build   <id>`), in the kernel's banner (`build id   <id>`) and at the head
of every backtrace (`bt build <id>`).

The kernel never reads its own symbols. A panic or fatal exception prints raw return
addresses (`lib/unwind`), and decoding happens off the machine:

```
$ kbuild run --preset aarch64-virt --set CRASH_PANIC=y
kernel panic: /kintane/kernel/main/src/crash.rs:25
backtrace:
  bt build 641308d39e08b37ccda0c5adea0867ede7cca800
  bt 0 0x0000000040209298
  bt 1 0x0000000040202b74
  ...
symbolized backtrace (build/aarch64-kintane/out/kintane.debug)
   #0  0x0000000040209298  core::panicking::panic_fmt+0x28  /rust/lib/rustlib/src/rust/library/core/src/panicking.rs:80
   #1  0x0000000040202b74  kintane::crash::nested_panic+0x20  kernel/main/src/crash.rs:25
   #2  0x0000000040202b8c  kintane::crash::outer+0xc  kernel/main/src/crash.rs:18
   ...
```

`kbuild run` and `kbuild test --target` decode a backtrace automatically when the
guest's console contains one, and keep the console in `build/<target>/console.log`.
`kbuild symbolize` decodes that file, or any log given to it.

Decoding refuses a log whose `bt build` ID is not the bundle's. A log from another build
still decodes, into function names that look right and are not, and a warning about that
is the kind nobody reads:

```
$ kbuild symbolize --preset x86_64-qemu old-console.log
error: build ID mismatch: the log was printed by build 66efaee3…, but
  build/x86_64-kintane/out/kintane.debug is build fec3ac6a…
```

A log with no ID, from before IDs existed or cut short, is decoded with a warning that it
could not be checked.

Function names come from the pinned `llvm-nm`, which demangles v0 symbols. File and
line come from kbuild's own reader for `.debug_line`, because the `llvm-tools` component
ships neither `llvm-symbolizer` nor `llvm-addr2line`, and a symbolizer taken from the host
would be an unpinned input. That reader was checked against `llvm-objdump --line-numbers`
on every instruction of the x86_64 and i686 kernels (DWARF 4), and on a DWARF 5 sample.
Its limit is inlining. It reports the innermost line an address was compiled from, but
not the chain of inlined calls that led there, because that chain is in `.debug_info`,
which it does not read.

Nothing yet ties a log to the build that produced it. Decoding an old log against a newer
bundle gives confident, wrong names. Until the image carries a build ID that the kernel
prints and `symbolize` compares, decode against the build that produced the log.

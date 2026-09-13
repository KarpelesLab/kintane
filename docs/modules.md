# Loadable Modules

## The problem

Rust has no stable ABI. Generic code is monomorphized, struct layout is unspecified,
trait objects have unspecified vtable layout, and all of it may change between
compiler releases — or between two builds of the same kernel with different
configuration. A module compiled against one kernel and loaded into another is not
"probably fine"; it is silent memory corruption.

Linux handles the analogous C problem with `vermagic` strings and per-symbol CRCs. We
need something stricter, because our ABI surface varies with configuration far more
than a C kernel's does.

## The rule

> **A module is valid for exactly one kernel build.** Compatibility is proven by
> hash, not asserted by version number.

Every kernel image carries a **build identity**: a hash over the resolved `.config`,
the toolchain identity, the target spec, and the interface hash of every crate a
module may link against. Every module records the identity it was built against. The
loader compares them and refuses anything that does not match exactly.

This sounds restrictive. It is honest. The alternative — a stable module ABI — would
require freezing struct layouts across configurations, which would undo the
monomorphization that makes the portability approach work in the first place. We
would rather rebuild modules than ship a kernel that can be corrupted by a stale one.

## What modules are for

Given that constraint, modules still earn their place:

- **Not shipping every driver in every image.** A distribution kernel supports
  hundreds of devices; loading the four that are present keeps the image small and
  the attack surface smaller.
- **Loading after the root filesystem.** Drivers for things not needed to boot.
- **Unload and reload during development.** Iterating on a driver without a reboot.
- **Third-party and out-of-tree drivers**, built against a published SDK.
- **Restarting a failed isolated driver** with a fresh copy.

## Format

Modules are relocatable ELF objects (`ET_REL`) with KinTane-specific sections:

| Section | Contents |
|---|---|
| `.kintane.identity` | build identity hash, module name, version, license |
| `.kintane.imports` | symbols required, each with its interface hash |
| `.kintane.exports` | symbols provided |
| `.kintane.deps` | other modules required |
| `.kintane.drivers` | driver match table, merged into the device framework on load |
| `.kintane.params` | tunable parameters with types and ranges |

The interface hash per symbol is not a CRC of the signature text. It is a structural
hash of the resolved type — including the layout of every type transitively reachable
through it — computed by `kbuild` from rustc's own type information. Two symbols with
the same name and the same structural hash are genuinely interchangeable.

## Loading

1. Read `.kintane.identity`; reject on mismatch with a message naming which component
   differs (config, toolchain, target, or a specific crate interface).
2. Resolve `.kintane.deps`, loading recursively; detect cycles.
3. Allocate module memory. On `HasMmu` targets this is in a dedicated region so that
   text can be mapped read-execute and data read-write. On no-MMU targets it is a
   plain heap allocation and the protection is advisory at best.
4. Resolve imports against the kernel symbol table, checking each interface hash.
5. Apply relocations. Each architecture implements the relocation types its ELF ABI
   defines; this is the one genuinely per-arch part of the loader and it lives in
   `arch/<name>/module.rs`.
6. Flush instruction cache / invalidate as the architecture requires.
7. Run the module's init. Failure unwinds every step above.

## Unloading

Unloading is a refcount problem, and getting it wrong is a use-after-free in kernel
text. Rules:

- A module may be unloaded only when its refcount is zero and no kernel object it
  created is still alive.
- Objects a module creates hold a reference to it. A file handle to a device a module
  drives pins that module, transitively.
- Function pointers into module text — registered callbacks, timer handlers,
  interrupt handlers — must be registered through a wrapper that holds a reference.
  Registering a bare `fn` pointer from a module is prevented by the registration APIs
  taking a type that only the macro-generated module glue can construct.
- If unloading cannot be proven safe, it fails. There is no force-unload.

Modules may also be marked permanent, which is the right answer for anything on the
fault-handling or scheduling path.

## As built

What exists today is the core of the design, on x86-64: build, identity, interface, load,
relocate, protect, reference-count, unload, and the SDK. Dependencies between modules,
parameters, driver match tables, signing and loading after boot are not yet built. Where
this section and the design above differ, this section is what the code does, and the
design is corrected below it.

### A module is a unit of kind `module`

```toml
[unit]
name = "test-roundtrip"
kind = "module"
root = "src/lib.rs"
layer = "subsystem"

[deps]
units = ["module"]

[config]
requires = "MODULE_TEST"
```

A module unit is built only when its `config.requires` evaluates to `m`, which needs
`MODULES=y`. The graph refuses the two ways `m` could lie:

- a module unit whose condition is `y` has no way into the image, so it is an error;
- a library unit enabled by an `m` would be linked in as if it were `y`, so that is an
  error too.

A module may depend only on units at `core` or below. It reaches the kernel through its
interface and never through a second copy of a crate that holds kernel state. Nothing may
depend on a module.

`MODULES` depends on `ARCH_X86_64 && MM_PAGED`. `MODULE_TEST` is a tristate capped at
`m` (`depends on MODULES && QEMU_EXIT && m`), and builds the three test modules under
`modules/test`.

### Building one

`kbuild/src/modules.rs` builds each module against the finished configuration:

1. **Compile.** The module's dependencies, `core` included, are compiled with embedded
   bitcode, and the module crate is compiled as a `staticlib` with fat LTO in one codegen
   unit. Only what the module reaches survives. The round-trip module is 7 KiB, with
   `core::fmt` in it.
2. **Link.** `rust-lld -r --whole-archive` turns the archive into one `ET_REL` object.
3. **Stamp.** `llvm-objcopy` strips debug information and leftover bitcode, and adds
   `.kintane.identity`.

A module unit may ask to be built against another configuration:
`[module] config-overrides = ["DEBUG_BUILD=!"]`, where `!` means "the opposite of the
kernel's". It is a test facility, and `test-other-config` is its one user.

The static relocation model and the kernel's `small` code model mean a module's absolute
32-bit relocations must reach it. Modules are therefore loaded below 2 GiB. The loader
refuses a relocation that does not fit rather than truncating it.

### Sections

| Section | Contents |
|---|---|
| `.kintane.identity` | `KTIDENT1`, the SHA-256 of the identity text, its length, the text |
| `.kintane.imports` | one 64-byte record per interface function: name, length, interface hash |

The **identity text** is `kbuild/src/codegen.rs`'s `identity_text`. It holds the
toolchain identity, the SHA-256 of the target specification, and every configuration
symbol's value in declaration order. The kernel gets the same text and its hash as
`kconfig::MODULE_IDENTITY` and `MODULE_IDENTITY_HASH`.

The hash decides. The text only explains a refusal: `built with DEBUG_BUILD=n, kernel has
y`, or another toolchain, or another target. A hash mismatch over identical text is
reported as corruption. The per-crate interface hashes the design lists are not part of
the identity. A module links no kernel crate, so the identity has nothing of the kind to
cover.

### The interface

`kernel/module/src/abi.rs` declares, with `declare_interface!`, every `extern "C"`
function a module may call. Today there are four: `kt_log`, `kt_register_callback`,
`kt_unregister_callback` and `kt_panic`. Parameters are primitives, raw pointers and
`extern "C"` function pointers, so the signature text is the ABI.

A function's **interface hash** is FNV-1a over that text, computed by the compiler on both
sides. That is not the structural hash from rustc's type information the design called
for. It becomes necessary only if the interface admits a `#[repr(C)]` struct.

- **The kernel's side.** It builds its export table with `module::export!`, which casts each
  implementation to the declared type. An implementation that disagrees with its
  declaration does not compile.
- **The module's side.** `module::module!` defines `kt_module_init` and `kt_module_exit`, a
  panic handler that calls `kt_panic`, and the imports records.
- **The loader's check.** Every symbol a module leaves undefined must be exported, recorded,
  and recorded with the kernel's hash. Otherwise the module is refused by name:
  `kt_register_callback is not the kernel's interface`.

### Loading

`kernel/module` is host-tested and allocates nothing. Its steps:

1. check the machine;
2. check the identity;
3. check the imports;
4. lay the allocated sections out into text, read-only data and writable data;
5. copy them into memory the caller supplies;
6. apply every relocation;
7. find the entry points.

Relocation is per ELF machine, not per running architecture. It is arithmetic on bytes
(`kernel/module/src/reloc.rs`), so it lives with the loader and is tested on the host.
The design put it in `arch/<name>/module.rs`.

- **x86-64 relocations** (the ones rustc emits for modules): `R_X86_64_64`, `PC32`, `PLT32`,
  `32`, `32S` and `PC64`. The GOT-relative types are refused by name.
- **AArch64 relocations:** `ABS64`, `ABS32`, `PREL64`, `PREL32`, `CALL26`, `JUMP26`,
  `ADR_PREL_PG_HI21`, `ADD_ABS_LO12_NC` and the `LDST*_ABS_LO12_NC` family. They are
  host-tested but not used yet. An AArch64 kernel needs module text within 128 MiB of its
  exports, or veneers, before `MODULES` can include it.

On a paged kernel, `kernel/main/src/modules.rs` maps each region page by page into a window
of the live kernel space, writable. The loader writes and relocates. Then the regions are
sealed: text `R-X`, read-only data `R--`, data `RW-`. The seal is read back from the live
tables. There is a guard page between regions. Unloading unmaps every page, frees every
frame, and frees every page table the mapping needed.

### Getting modules to the kernel

There is no filesystem yet. kbuild packs every module it built into a **bundle**,
`build/<target>/out/modules.kmb`: `KTBUNDL1`, a count, a table of name, offset and
length, then the modules. The boot path passes the bundle as a **multiboot boot module**.
QEMU's `-kernel` loader takes it from `-initrd`, as GRUB takes a `module` line.

`bootinfo::module_bundle` finds it. The multiboot provider carves the bundle and the
module list out of the memory map as boot data, so no allocation lands on a module before
it is read. The first boot to try this lost the module list that way.

The kinboot loaders do not pass bundles yet. Their providers say so
(`MODULE_BUNDLES = false`), and a kernel with test modules reports the check as skipped
there instead of failing. On a multiboot boot, a missing bundle fails the boot.

### Unloading

`module::Registry` holds a reference count per loaded module:

- A callback registered through `kt_register_callback` takes a reference.
  `kt_unregister_callback` gives it back.
- `begin_unload` is refused while any reference is held. Once it starts, no new reference
  can be taken.
- A module id carries a generation, so a stale id names nothing.
- There is no force-unload.

### The boot check

With `MODULE_TEST`, every x86-64 multiboot boot gates on the `modules` line:

1. load `test-roundtrip`, which logs and registers a callback, and call the callback twice.
   The values 42 and 72 only come out of correctly relocated text, read-only data and
   data;
2. refuse to unload it while the callback holds it;
3. unregister, unload, and require the frame allocator back to its free count before the
   first load;
4. refuse `test-other-config`, naming `DEBUG_BUILD`, and `test-other-interface`, naming
   `kt_register_callback`, both before any memory is taken.

Modules do not outlive the check yet. That needs the registry and the export state under
the kernel's lock, and a lasting home for the module window.

## The design, corrected

The format section of the original design listed six sections, and the loading steps put
relocation in `arch/`. What changed, and why:

- **Two sections, not six.** `.kintane.exports`, `.kintane.deps`, `.kintane.drivers` and
  `.kintane.params` wait for what needs them: a module that exports to another module,
  dependencies, driver binding from modules, and parameters. `identity` holds no module
  name, version or licence yet; the bundle entry names the module.
- **Relocation in `kernel/module`**, keyed by `e_machine`, for the reason above.
- **Interface hashes over signature text**, for the reason above.
- **Registration is not yet glue-only.** `kt_register_callback` takes a bare function pointer
  and a module id, and the reference it takes is what pins the module. The rule above, a
  type only `module!`'s glue can construct, is still the goal: today a module could
  register a pointer into another module, or pass another module's id.
- **The identity covers configuration, toolchain and target.** It does not cover crate
  interfaces, which modules do not link.

## Modules and isolation domains

A module destined for an isolated domain is loaded into that domain's address space
rather than the kernel's, and its imports resolve against the domain's proxy stubs
rather than kernel symbols directly. The module binary is the same; the link
environment differs. See [architecture.md](architecture.md#shape).

This is also the restart mechanism: when an isolated driver faults, its domain is torn
down and the module is loaded again into a fresh one.

## The SDK

`kbuild sdk --preset P` writes `build/<target>/sdk/`, everything needed to build a module
for that one kernel build without the kernel's source:

| Entry | What it is |
|---|---|
| `IDENTITY`, `identity.section` | the build identity, as text and as the section to stamp |
| `config.rs` | the generated configuration, as a module's `kconfig` crate sees it |
| `<target>.json` | the target specification, under the name rustc knows it by |
| `lib/` | `core`, `compiler_builtins`, `kconfig` and `module`, compiled with bitcode |
| `src/module/` | the interface crate's source, for reading |
| `example/` | a module to start from |
| `build-module.sh SRC NAME OUT` | build a module |

`build-module.sh` refuses any rustc but the pinned one. It runs the rustc, `rust-lld` and
`llvm-objcopy` invocations kbuild runs, with the kernel build's own flags written in, taken
from the same code that builds in-tree modules (`Build::unit_args`). A module's sources are
remapped to `/module/<name>` wherever they are, so the result is byte for byte what kbuild
produces from the same source. The CI checks exactly that, on a copy of the round-trip
module outside the tree.

## Signing

Module signature verification is a config option, default on for builds that also
enable secure boot. The signature covers the module image including its identity
section, so a valid signature on a module for a different kernel is still rejected —
identity checking and signing are independent gates and both must pass.

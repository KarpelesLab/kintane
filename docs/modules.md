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

## Modules and isolation domains

A module destined for an isolated domain is loaded into that domain's address space
rather than the kernel's, and its imports resolve against the domain's proxy stubs
rather than kernel symbols directly. The module binary is the same; the link
environment differs. See [architecture.md](architecture.md#shape).

This is also the restart mechanism: when an isolated driver faults, its domain is torn
down and the module is loaded again into a fresh one.

## The SDK

`kbuild sdk` produces everything needed to build an out-of-tree module against one
kernel build:

- the build identity
- `hal/` and public kernel crate interfaces, as compiled `.rmeta` plus source
- generated `config.rs` and the `--cfg` set
- the pinned toolchain identity (the toolchain itself must match, not merely be
  compatible)
- target specification
- a `kbuild`-compatible manifest template

Shipping the SDK alongside a release is what makes third-party drivers possible
without shipping the whole kernel source. It is also large enough that it is an
optional deliverable, not part of the default release.

## Signing

Module signature verification is a config option, default on for builds that also
enable secure boot. The signature covers the module image including its identity
section, so a valid signature on a module for a different kernel is still rejected —
identity checking and signing are independent gates and both must pass.

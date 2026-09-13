# Testing and CI

A kernel that claims to support twelve platforms and a thousand configurations is
making a claim about things nobody runs daily. The only defence is automation, and
the only automation that works is the kind that blocks merges.

## Four levels

### 1. Host tests

Any code that does not touch hardware is compiled for the **host** target and tested
with ordinary Rust test tooling. This is possible because the kernel's upper layers
are generic over `hal` traits rather than calling into `arch` directly — so we can
supply a `MockArch`:

```rust
pub struct MockArch;

impl Arch for MockArch { /* deterministic, instrumented */ }
impl HasMmu for MockArch {
    type PageTable = SoftwarePageTable;   // a real page table walker in a HashMap
    /* ... */
}
```

Several mock architectures exist, each with a different capability set, so that the
same subsystem test runs against "has MMU + SMP + CAS" and "no MMU, no CAS" and the
differences are caught on a laptop in a second rather than on a board in an hour.

This is the single largest payoff of the trait-based portability design and it is
worth protecting: **a subsystem that cannot be tested against `MockArch` has a design
problem.** New subsystems are expected to justify it if they cannot.

Covered this way: allocators, schedulers (with a mock time source), the VFS, the
object model, device tree parsing, the module loader's relocation logic, config
resolution, data structures.

### 2. In-kernel tests

Tests that must run on the real architecture — page table manipulation, context
switch, atomics, cache maintenance, exception entry — are compiled into a test kernel
that boots under QEMU, runs, reports results over the console, and exits with a
status code.

```
$ kbuild test --target aarch64-virt
  running 218 tests in-kernel
  ...
  test mm::paged::huge_page_split ... ok
  218 passed; 0 failed; 3 skipped (require HasSmp)
```

Skipping is by trait bound, not by runtime check: a test requiring `HasSmp` is
generic over it and simply is not registered in a build that lacks it.

### 3. Boot and integration tests

Per-target, per-preset: boot the real kernel image under QEMU, reach userspace (once
there is one), run a scripted workload, check output and exit cleanly. Includes
deliberate fault injection — kill an isolated driver and confirm it restarts, exhaust
memory and confirm the fallible allocation paths are actually exercised rather than
merely present.

From Phase 6b, this level gains its most valuable input: **unmodified Linux binaries**.
The compatibility corpus — static musl programs first, busybox, later a real userland —
is run under the Linux personality on every merge. Software written without any
knowledge of this kernel is the only test workload that does not share our
assumptions, and it finds things our own tests structurally cannot. The corpus is also
the compatibility claim itself; see
[userspace-abi.md](userspace-abi.md#scoping-and-the-partial-compatibility-problem).

Gaps are made loud rather than silent: an unimplemented syscall returns `-ENOSYS` and
logs its name, and CI builds enable the config option that makes it fatal, so a
missing syscall is a named test failure instead of a program that misbehaves.

### 4. Hardware

A small rack of real machines for tier-1 targets, driven nightly: an x86_64 server,
an aarch64 board, a genuinely old 32-bit PC, and Cortex-M and RISC-V development
boards. QEMU is a model of hardware, and the places where the model is wrong are
exactly the places kernels break.

## Configuration coverage

The configuration space is too large to enumerate. We sample it deliberately:

- **All presets, every merge.** The configurations we actually ship.
- **Boundary configurations**: everything off that can be off, everything on that can
  be on. These catch the majority of "this config does not compile" bugs.
- **Randomized configurations, nightly.** `kbuild config --random --seed N` produces a
  valid configuration; build it. A failure is reported with its seed, so it is
  reproducible. This is where the unbuildable-configuration bugs that plague
  `#ifdef`-based kernels would show up — and where we find out whether the trait
  approach really removed them.
- **Pairwise coverage** over config symbols known to interact (SMP × MM model ×
  isolation × module support), once the symbol count makes exhaustive impractical.

## Merge gates

A change may not land unless:

1. Every tier-1 target builds, every preset.
2. Host tests pass.
3. In-kernel tests pass under QEMU for every tier-1 target.
4. No new `unsafe` block lacks a `// SAFETY:` comment.
5. No `cfg` appears inside a function body or struct definition
   ([the rule](portability.md#where-cfg-is-still-allowed)).
6. Layering is not violated.
7. The size report does not regress beyond the configured budget.
8. From Phase 6b: the Linux compatibility corpus passes. Programs leave the corpus
   only by explicit decision, never by being quietly removed when they break.

Gates 1 and 3 are what make the portability claim real, and they are affordable only
because of `kbuild`'s content-addressed cache.

## Size budgets

Each preset declares a maximum image size in `config/presets/`. `kbuild size
--compare <ref>` reports per-crate and per-section deltas against a baseline.

```
$ kbuild size --compare origin/main
  preset armv7m-minimal     budget 64 KiB
    .text      41,208   +312
    .rodata     6,944    +18
    .data         512     +0
    .bss       11,520     +0
    total      60,184   +330    ( 92% of budget)
```

A 300-byte regression on a Cortex-M matters and is invisible on x86_64. Tracking it
per-commit is the only way the small targets stay viable, and it is the mechanism
that keeps "supports microcontrollers" from quietly becoming false.

## Sanitizers and analysis

- **Debug builds** enable overflow checks, poison freed memory, add lock-order
  checking, and validate that sleeping functions are not called in atomic context —
  all as config options so the checks can be enabled selectively in production too.
- **Address arithmetic is always checked**, in every build, because the failure mode
  is corruption rather than a wrong number.
- **Miri** on host tests for the portions that involve `unsafe` and can run under it.
- **Fuzzing**, from Phase 6, on every parser that touches untrusted input: device
  tree, ELF loading, module loading, filesystem metadata, network packets. Syscall
  argument fuzzing from the point the ABI exists.

## Debugging

- `kbuild run --gdb` starts QEMU stopped with a GDB stub and loads the symbol bundle.
- Panics print a symbolized backtrace, resolved against the separately shipped
  symbols so that stripped production images remain debuggable.
- A crash-dump format and an offline decoder, so a report from a device in the field
  can be read with only the `.config` and the symbol bundle.

# Boot and the Bootloader

## Position

We own the boot path. Not one generic bootloader, but **a small purpose-built loader
per boot mechanism**, plus a well-defined handoff that all of them produce and the
kernel alone consumes.

The alternative — depending on GRUB — was rejected. GRUB is an operating system in its
own right: a scripting language, filesystem drivers for a dozen formats, a module
loader, and decades of accumulated quirk handling. Most of that exists to boot kernels
that are not ours, from filesystems we do not need to read, on a boot path we would
rather keep auditable. It also stops at the water's edge: GRUB has nothing to say
about a Cortex-M part, which is half of what this project is for.

What we give up is real and worth naming: GRUB's hardware quirk knowledge, its
filesystem breadth, and its familiarity. We buy back a boot path that is part of our
own build, our own reproducibility story, and our own signing chain — and one that
degrades coherently to platforms where "bootloader" is not a concept.

**We are not, however, precious about it.** Being *loaded by* someone else's
bootloader is cheap to support and disproportionately useful; see
[Being loaded by others](#being-loaded-by-others).

## The boot protocol

The loaders are plural and platform-specific. The thing they produce is singular:

```rust
#[repr(C)]
pub struct BootInfo {
    magic: u64,
    /// Protocol version. Bumped only for incompatible change.
    version: u16,
    /// Size of this header, so an older kernel can skip a newer one's additions.
    header_size: u16,
    /// Total bytes of tag data following.
    tags_size: u32,
    // followed by a sequence of tags
}

#[repr(C)]
pub struct Tag {
    kind: TagKind,
    /// Including this header. A kernel skips tags it does not recognise.
    size: u32,
    // followed by kind-specific payload
}
```

Tags carry the memory map, command line, framebuffer description, ACPI RSDP pointer,
device tree blob, boot device identity, loaded module/initrd list, entropy seed, TPM
event log, the kernel's physical and virtual load addresses, and the firmware type.

The byte-level layout — 8-byte tag alignment, `tags_size` including the End tag, the
memory map's explicit `entry_size` so a region entry can grow — is specified where it
is implemented, in `boot/protocol/src/tags.rs`, with a host-tested reader and a writer
that needs no allocator. Of the tags above, v1 as implemented writes the memory map,
the ACPI RSDP, the kernel's physical range and the firmware type.

### Entering the kernel

A loader also has to know **where to jump**, and the ELF entry point is not always the
answer. The x86_64 image is a multiboot kernel as well, and its `e_entry` is 32-bit
protected-mode code, which is what a multiboot loader calls and what a UEFI loader, in
long mode, cannot. So the image names its protocol entry separately, in an ELF note
owned by `KinTane` (type 1) that carries the entry's physical address and the protocol
version it expects. The program headers say exactly where the note is, so there is
nothing to scan for, and `--strip-all` keeps it. `boot_protocol::image` parses it and
states the machine state each architecture's entry expects.

### This is a genuinely stable ABI

Almost nothing else in this project is. [D7](decisions.md#d7--no-stable-module-abi-compatibility-by-hash)
refuses a stable module ABI and checks compatibility by hash instead. The boot
protocol is the opposite, and the difference is not inconsistency:

| | Modules | Boot protocol |
|---|---|---|
| Runs in | kernel address space, sharing monomorphized Rust types | its own world; hands over a flat `#[repr(C)]` blob and exits |
| Updated | together with the kernel | **independently** — the loader lives on the ESP or in the MBR gap and survives kernel updates and rollbacks |
| Surface | every type reachable through every exported symbol | one struct and a set of tags |

An installed loader must boot a newer kernel, and a newer loader must boot an older
kernel so that rollback works. That forces forward and backward compatibility, which
is why the protocol is tag-based with explicit sizes — the same reason device tree and
multiboot2 are. Unknown tags are skipped; missing required tags are a diagnosable
failure with a name, not a hang.

The protocol is versioned independently of the kernel and changes rarely. Each change
is reviewed against the question *"can a two-year-old loader still boot this?"*

## The loaders

### `kinboot-efi` — UEFI

A PE/COFF EFI application. Rust targets `x86_64-unknown-uefi`, `aarch64-unknown-uefi`,
and `i686-unknown-uefi` are all built in, so — unlike the kernel's i686 target — this
needs no hand-written target specification and produces PE/COFF directly from `rustc`.

Responsibilities: locate and read the kernel from the ESP via `SimpleFileSystem`,
verify its signature, query the framebuffer through GOP, collect the UEFI memory map,
extend TPM PCRs if present, perform the `ExitBootServices` handshake (including the
retry when the map key is stale — getting this wrong is the classic UEFI bug), build
`BootInfo`, and jump.

UEFI-specific behaviour, since the firmware offers things no other platform does:

- **Boot configuration in EFI variables** rather than a file, so the firmware's own
  boot manager can present our entries.
- **Secure Boot state** is queried and recorded in `BootInfo`; the kernel can refuse
  to load unsigned modules when the chain was verified, matching
  [modules.md](modules.md#signing).
- **Boot counter and last-known-good state** in a non-volatile variable — see
  [Failure handling](#failure-handling).

**The EFI stub.** As a configuration option, the kernel image itself is emitted as a
PE/COFF EFI application with the loader linked in, so firmware boots the kernel
directly with no separate file. Fewer moving parts, one signature, and it is what most
modern UEFI systems expect.

#### As built: the minimal loader

Phase 0's loader exists for x86_64 (`boot/kinboot-efi`, preset `x86_64-efi`). It
does what the Phasing section below asks of the minimal loader and nothing more: read
`\KINTANE\KERNEL.ELF` from the partition it was started from, place the segments at
their link addresses, take the ACPI RSDP from the configuration table,
`ExitBootServices` with the stale-key retry, translate the final map into protocol
regions, and jump to the note's entry with the structure in `rdi`. It is 27 KiB, a
fifth of the budget below.

Where the design above was silent or wrong, the implementation decided:

- **Memory that outlives the loader is typed, not remembered.** The kernel image and
  the boot information are allocated with memory types from the range the UEFI
  specification reserves for OS loaders, and the translation turns those into the
  protocol's `KernelImage` and `BootData`. Everything else the firmware or the loader
  used becomes usable, because after `ExitBootServices` it is.
- **Handover below 1 GiB.** The loader refuses an image above the first gigabyte and
  allocates the structure below it. The kernel's bootstrap page tables mapped exactly
  that much when this was written; they now map four, so the limit is conservative
  rather than required.
- **The map is coalesced.** OVMF reports around a hundred descriptors; merged by kind,
  the kernel receives 26. Without merging the map does not fit the kernel's region
  buffer, which the boot check turns into a failure rather than a truncated map.
- **The disk image is written by kbuild** — MBR, one `0xEF` partition, FAT16 — rather
  than by `mkfs.fat` and `mtools`, which are not part of the pinned toolchain. MBR
  rather than GPT because UEFI requires firmware to accept both and one partition
  needs nothing more.
- **Float symbols the loader never calls, resolved honestly.** lld-link demands every symbol in every
  object it reads, and `core` puts float code beside integer formatting. The loader's
  `compiler_builtins` satisfies those symbols with stubs that trap, and kbuild fails the
  build if one survives the linker's dead-code removal (`lib/builtins/src/uefi_link.rs`).

Not in the minimal loader, and following the phasing below: boot entries and modes,
GOP framebuffer, the command line from `LoadOptions`, Secure Boot and signature
verification, measured boot, the boot counter, chainloading, and the aarch64 and i686
UEFI builds. The loader carries no symbol bundle yet either: it is linked without a
PDB, because lld-link's PDB records a path rustc picks at random and would make the
image irreproducible.

### `kinboot-bios` — MBR / BIOS

The legacy PC path, required because tier-1 [`i686`](targets.md#i686) boots this way.

It exists, in `boot/kinboot-bios/`, and boots both x86 kernels under QEMU. The
`i686-bios` and `x86_64-bios` presets boot from a raw disk through SeaBIOS with no
`-kernel`, so every boot, in-kernel and stack guard test on them also tests the loader.

```text
LBA 0                MBR: stage 1 code (at most 424 bytes), stage 1 table, disk
                     signature, one partition entry, 0x55AA
LBA 1 ..             stage 2 (at most 32 KiB), with a header naming the kernel's LBA,
                     length and CRC-32
LBA 1 + stage 2      the packaged kernel image, byte for byte
```

**Stage 1** occupies the 440 bytes of MBR boot code (bytes 440–445 are the disk
signature, 446–509 the partition table, 510–511 the `0x55AA` signature — the budget is
not negotiable). It runs in 16-bit real mode and does exactly one thing: check for
INT 13h extensions, then load stage 2. It copes with the BIOS handing it the boot drive
in `DL` and entering at `07C0:0000` instead of `0000:7C00`. Without LBA it reads stage 2
one sector at a time through CHS, with the geometry `AH=08h` reports. Its last 16 bytes
of code space are a table `kbuild` fills in with stage 2's location, and the table's
position is asserted with `.org`, so code that grows into it fails to assemble.

Rust has no 16-bit x86 target, so this is assembly — but it needs **no external
assembler**. `global_asm!` with `.code16` goes through LLVM's integrated assembler in
our pinned toolchain and emits correct real-mode encodings, which keeps
[D8](decisions.md#d8--rust-198-baseline-on-a-pinned-nightly-engine-no-third-party-crates)'s
"no non-Rust build dependencies" intact. Verified: stage 1 is about 280 bytes.

**Stage 2** lives in the MBR gap, at LBA 1. A BIOS Boot Partition on GPT disks is not
supported yet. It is built for its own target, `targets/i686-kinboot.json`: an i486
with no SSE and no x87 use. The kernel's i686 target assumes a Pentium 4, and a loader
cannot fault before it has printed why.

This section first said stage 2 must collect everything in real mode, *because after
the switch there is no BIOS*. That turned out to be wrong in the way that matters.
INT 13h reads into a `segment:offset` buffer below 1 MiB, and the kernel loads at
1 MiB, so a loader cannot avoid going back to the BIOS after it has started loading.
Once it can do that, collecting the memory map in assembly first only moves logic out
of reach of tests. So stage 2 does the minimum in real mode, which is load a GDT and
enter protected mode. Everything after that is Rust, calling BIOS services through a
real-mode **thunk** (`loader/stage2.rs`). The thunk drops to real mode, performs one
`int` with the registers the caller set, and comes back. In order, stage 2:

1. **A20**: tests the line, then tries INT 15h `2401h`, the keyboard controller and
   port `0x92` in that order, testing after each.
2. **Memory map**: E820, handling 20- and 24-byte entries, the ACPI 3.0 "enabled" bit
   and the continuation value. On a BIOS without E820 it builds the map E801 implies.
3. **Kernel**: checks the header, then streams the kernel off the disk in 32 KiB chunks
   through a bounce buffer at `0x20000`. The ELF is validated from its first chunk, and
   each segment's destination is checked against the memory map before any byte is
   copied. The CRC-32 of the whole file must match the header before the jump.
4. **Handover**: jumps to the ELF entry point as a Multiboot 1 loader, with
   `EAX = 0x2BADB002` and `EBX` pointing to an information structure carrying the memory
   map, `mem_lower`/`mem_upper`, the boot drive, a command line and the loader's name.

**The handover is interim.** Both x86 kernels already accept Multiboot 1 through
`boot/info-multiboot`, because QEMU's `-kernel` uses it, so no kernel change was needed.
Switching this loader to the native `BootInfo` protocol comes once a kernel-side
`BootInfo` consumer exists; `kinboot-efi` is the first loader to produce one.

Every decision stage 2 makes is in the `kinboot-bios` crate (`boot/kinboot-bios/src/`),
which is byte-slice code with no `unsafe` and has host tests. That covers the disk
layout, E820/E801 decoding, ELF validation, the streaming copy plan and the Multiboot
structure's offsets. The disk layout file is also compiled into `kbuild`, so the writer
and the reader cannot disagree. `loader/` only does I/O.

On any failure the loader prints `kinboot-bios:` and a reason to the screen and COM1,
then calls INT 18h, the BIOS's "this device did not boot" entry. A real machine moves
on to its next boot device. Under QEMU, the harness passes `-boot reboot-timeout=0
-no-reboot`, so a failed boot ends the run within seconds instead of timing out.

**Not in the minimal loader yet:** the entry list and its `normal`/`safe`/`recovery`
modes (below), the boot counter, chainloading, EDD and VBE queries, and GPT. The
command line field in the disk header is written empty today.

**Unvalidated on hardware.** Every path above, including the ones SeaBIOS never takes,
was exercised under QEMU by forcing it:

- CHS reads in both stages, including a kernel placed past cylinder 1;
- E801 instead of E820;
- A20 masked and each enable method in turn;
- A20 that cannot be enabled, which must fail.

That is not the same as a 1998 BIOS. See
[testing.md](testing.md#what-qemu-will-not-catch).

### No bootloader — `armv7m`, `riscv32`, and friends

On a microcontroller there is nothing to boot from and nothing to choose. The kernel
image *is* the boot image: a vector table at the reset address whose first entry is the
initial stack pointer and whose second is the reset vector, executing in place from
flash.

These targets still need a `BootInfo` — and they get one **constructed at build time by
`kbuild`** from the board description and linked in as a `const`. The kernel's entry
path is identical to the UEFI one; it reads a `BootInfo` either way. On a
microcontroller that structure costs a few hundred bytes of flash and no runtime work
at all.

This is the project's thesis applied to boot: the same kernel code, the difference
pushed into configuration rather than into a parallel code path.

### Being loaded by others

Supporting foreign loaders is cheap and buys reach we should not refuse:

- **U-Boot**, via FIT/uImage, on ARM and RISC-V boards. Replacing vendor firmware on an
  SoC is a losing battle and not one worth fighting — U-Boot is already there and
  already knows the board.
- **OpenSBI** on riscv64, which is not optional on that platform anyway.
- **GRUB and systemd-boot**, via a thin entry shim that translates their handoff into
  `BootInfo`. Useful for anyone who wants us alongside an existing OS without touching
  their boot setup.
- **QEMU `-kernel`**, which skips firmware entirely and is the fastest path for CI.

Each is a translation shim producing the same `BootInfo`. None of them changes the
kernel.

## Boot options

Deliberately not a scripting language. A declarative entry list on the boot medium (or
in EFI variables), where each entry names a kernel, a **mode**, and optional extra
command line. The bootloader's job is to pick one and pass it on, not to compute
anything.

### Modes

`normal` is the configured kernel. `safe` is defined concretely, because a safe mode
nobody has enumerated is not a feature:

- single CPU — secondary processors are not brought up
- no driver isolation; every driver runs `InKernel`
- no loadable modules; built-in drivers only
- serial console plus the firmware framebuffer, nothing else
- no power management, no frequency scaling, no suspend
- verbose logging from the first line

`recovery` goes further: a minimal in-memory root and no storage writes, for fixing a
system that safe mode cannot reach.

### Failure handling

The loader increments a boot counter in persistent storage — an EFI variable on UEFI, a
reserved sector on BIOS — before jumping. The kernel clears it once initialization
reaches a defined point. Repeated failures escalate automatically: `normal` → `safe` →
the previously installed kernel.

This is a small amount of machinery that turns an unbootable machine into a machine
that boots badly, which on hardware without a serial console is the difference between
debuggable and bricked.

## Chainloading other operating systems

Scoped by what each platform actually makes easy:

- **BIOS:** load the selected partition's volume boot record to `0x7C00`, restore `DL`,
  and jump in real mode. That is the whole mechanism, it is about twenty instructions,
  and it is worth having.
- **UEFI:** the firmware already has a boot manager that does this better than we
  would. We offer `LoadImage`/`StartImage` for another EFI application and stop there.

Explicitly **out of scope**: probing disks to detect installed operating systems,
filesystem drivers for formats we do not otherwise need, and per-OS quirk handling. A
user who wants that has GRUB, and should use it — we boot fine from it.

## What the bootloader must not do

The scoping rule, stated positively, since "small" erodes without a definition:

- **No scripting language.** A declarative entry list, nothing evaluated.
- **No filesystem writes**, ever. Read-only, and only FAT (which the ESP requires
  anyway) plus our own format. Not ext4, not btrfs, not XFS.
- **No network boot** in the first implementation. UEFI firmware can HTTP-boot by
  itself, and PXE can come later if something needs it.
- **No graphical menu.** Text, on whatever console exists.
- **No device drivers** beyond what is needed to read the kernel off the boot medium.

Size budgets, tracked in CI exactly like the kernel's
([testing.md](testing.md#size-budgets)): stage 1 is hard-capped at 440 bytes, stage 2
at 32 KiB, and `kinboot-efi` at 128 KiB. The first two are enforced by the build, not a
report: stage 1's table is placed with `.org`, which fails to assemble if the code
reaches it, and the loader's link script asserts stage 2's size. Both were checked by
growing each past its limit.

## Security

The bootloader is in the trusted computing base, which is the main argument for keeping
it this small.

- **UEFI Secure Boot:** `kinboot-efi` is signed and verifies the kernel's signature
  before jumping. The verified state is recorded in `BootInfo`, so the kernel can
  require signed modules when — and only when — the chain that loaded it was itself
  verified.
- **Measured boot:** PCRs extended with the kernel hash, the command line, and the
  selected mode. The event log is passed through in `BootInfo`. Measuring the *mode*
  matters: booting into safe mode disables isolation, and an attestation that cannot
  tell the difference is not much of an attestation.
- **BIOS has no root of trust.** An MBR chain cannot be verified and we will not
  pretend otherwise. `kinboot-bios` does not offer a security guarantee, and the
  documentation says so wherever the option appears.

## Build integration

The loaders are built by `kbuild` from the same pinned toolchain under the same
reproducibility rules as the kernel ([build-system.md](build-system.md#reproducibility)),
and ship as part of the same release. `kbuild image --format` produces the bootable
artifact per platform: a GPT/ESP disk image, an MBR disk image, a raw XIP binary, or a
FIT image.

Today the MBR image is the one that exists. With `KINBOOT_BIOS=y`, `kbuild build` also
writes `build/<target>/out/kinboot-bios.img` (`kbuild/src/bios.rs`), in these steps:

1. **Build the loader.** `core` is built for the loader's own target, then the
   `kinboot-bios` crate and the loader binary.
2. **Flatten it** with `llvm-objcopy -O binary`.
3. **Check its layout.** The signature, table and header must be where the disk format
   says, and the partition table must be untouched.
4. **Write the disk.** Stage 2's header is filled in, and the image is padded to whole
   16×63 cylinders. SeaBIOS on q35 refuses to read a disk smaller than one cylinder,
   which the first `x86_64-bios` boot found.

The disk is byte-identical across cold builds; its signature is derived from its
contents, not the clock.

## Support matrix

| Target | Mechanism | Loader |
|---|---|---|
| x86_64 | UEFI | `kinboot-efi`, or the EFI stub |
| x86_64 | BIOS/CSM | `kinboot-bios` |
| aarch64 | UEFI | `kinboot-efi` |
| aarch64 | U-Boot board | loaded by U-Boot (FIT) |
| i686 | BIOS | `kinboot-bios` |
| i686 | UEFI (32-bit) | `kinboot-efi` |
| armv7m | none | kernel is the image; `BootInfo` built by `kbuild` |
| riscv32 | none | kernel is the image; `BootInfo` built by `kbuild` |
| riscv64 (tier 2) | SBI | loaded by OpenSBI |
| any | CI | QEMU `-kernel` |

## Phasing

Boot work is spread across the [roadmap](roadmap.md) rather than deferred:

- **Phase 0** — boot protocol v1, and a minimal `kinboot-efi` that gets x86_64 to a
  banner under QEMU. Done: see [As built](#as-built-the-minimal-loader).
- **Phase 1** — `kinboot-bios`, because tier-1 i686 cannot boot without it. This is the
  scheduling consequence most likely to be missed: the MBR loader is early work, not
  Phase 7 polish.
- **Phase 4** — build-time `BootInfo` for the no-MMU targets.
- **Phase 7** — Secure Boot, measured boot, last-known-good escalation, chainloading,
  and real firmware on real machines.

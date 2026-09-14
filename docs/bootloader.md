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
the command line, the ACPI RSDP, the kernel's physical range and the firmware type. Both
loaders write the command line. `kinboot-bios` has no ACPI RSDP to pass yet.

### Entering the kernel

A loader also has to know **where to jump**, and the ELF entry point is not always the
answer. The x86_64 image is a multiboot kernel as well, and its `e_entry` is 32-bit
protected-mode code, which is what a multiboot loader calls and what a UEFI loader, in
long mode, cannot. So the image names its protocol entry separately, in an ELF note
owned by `KinTane` (type 1) that carries the entry's physical address and the protocol
version it expects. The program headers say exactly where the note is, so there is
nothing to scan for, and `--strip-all` keeps it. `boot_protocol::image` parses it and
states the machine state each architecture's entry expects.

A loader running in 32-bit protected mode, which is `kinboot-bios`, uses the other entry:
the ELF entry point, which a Multiboot loader would call. That entry's machine state is
already Multiboot 1's, so the protocol reuses it. What differs is the magic in `EAX`:
`boot_protocol::ENTRY32_MAGIC` (`KINT`) instead of `0x2BADB002`. `EBX` then points at a
`BootInfo`. The kernel's entry code needed no change, because it already keeps `EBX`
and nothing else. A kernel built for a KinTane loader reads `EBX` as a `BootInfo` and
validates its magic, so a Multiboot handover to such a kernel fails its boot with a
reason instead of being misread.

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

Since then it has gained the [boot entries and menu](#as-built-entries-the-menu-and-the-command-line),
the command line tag, and [chainloading](#as-built-chainloading) through
`LoadImage`/`StartImage`. The menu and the boot entry list are `core::fmt` and a parser,
and the loader is 54 KiB now, still under half its budget.

Not yet, and following the phasing below: GOP framebuffer, a command line from
`LoadOptions` (a firmware boot entry's options are ignored; the entry list is the one
place arguments come from), Secure Boot and signature verification, measured boot, the
boot counter, and the aarch64 and i686 UEFI builds. The loader carries no symbol bundle
yet either: it is linked without a PDB, because lld-link's PDB records a path rustc
picks at random and would make the image irreproducible.

#### As built: the EFI stub

The kernel is its own UEFI application with `KINBOOT_STUB` (preset `x86_64-efistub`). The
firmware starts one file, `EFI/BOOT/BOOTX64.EFI`, and that file is the kernel with the
handover in front of it. There is no loader beside it and nothing to read off a partition.

No single link can produce that file, so it is built in three steps:

1. `boot/kinboot-stub` is linked for `x86_64-unknown-uefi`, like `kinboot-efi`, knowing
   nothing about the kernel.
2. Once the kernel is linked and stamped with its build ID, kbuild appends two sections to
   the stub's PE (`kbuild/src/pe.rs`): `.kernel`, the stripped ELF64, and `.cmdline`, the
   command line, which is where a unified kernel image carries it. The firmware loads every
   section a PE declares, so both arrive in memory with the stub.
3. kbuild writes where each landed into a descriptor the stub declares after a sixteen-byte
   marker, under the rule the build ID follows: the marker must occur exactly once.

The stub reads the descriptor, checks every range against the image size the firmware
reports, and calls the same handover `kinboot-efi` does. That handover now lives in
`boot/uefi` as `uefi::handover`. Placing the segments, finding the RSDP, `ExitBootServices`
with the stale-key retry and writing `BootInfo` are identical for both loaders, so the part
that is easy to get wrong exists once.

It deliberately has no menu, no entry list and no chainloading. A stub is the configuration
that says "boot this kernel with these arguments"; `kinboot-efi` is the one that says
"choose". A stub that fails returns to the firmware, which may have other ways to boot,
except in test builds: a stamped flag makes it reset instead, so `-no-reboot` ends the run
at once rather than after the harness's timeout.

**The first boot found a layout bug the host tests could not.** The marker was twelve
bytes, which left four bytes of padding before the descriptor's first 64-bit word. kbuild
wrote the words straight after the marker, the stub read them four bytes later, and the
first boot reported a kernel of 2.3 petabytes. The marker is sixteen bytes now, and the stub
asserts `offset_of!(Blob, words) == MARKER.len()` at compile time, so that layout fails the
build rather than the boot. kbuild's test of the stamped image could not have caught it,
because it read back the layout kbuild wrote, not the one the stub reads.

### `kinboot-bios` — MBR / BIOS

The legacy PC path, required because tier-1 [`i686`](targets.md#i686) boots this way.

It exists, in `boot/kinboot-bios/`, and boots both x86 kernels under QEMU. The
`i686-bios` and `x86_64-bios` presets boot from a raw disk through SeaBIOS with no
`-kernel`, so every boot, in-kernel and stack guard test on them also tests the loader.

```text
LBA 0                MBR: stage 1 code (at most 424 bytes), stage 1 table, disk
                     signature, partition entries, 0x55AA
LBA 1 ..             stage 2 (at most 32 KiB), with a header naming the LBA, length and
                     CRC-32 of the boot entries and of the kernel
after stage 2        the boot entries, at most 4 KiB
after the entries    the packaged kernel image, byte for byte
after the kernel     with CHAIN_TEST only: partition 2, one sector, the chain test record
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
3. **Boot entries**: reads the entry list the header names and checks its CRC-32, then
   shows the [menu](#as-built-entries-the-menu-and-the-command-line) on the screen and
   COM1, reading keys from INT 16h and from COM1, and waiting between polls with INT 15h
   `86h`, or on the BIOS clock tick where that is missing.
4. **Kernel**: checks the header, then streams the kernel off the disk in 32 KiB chunks
   through a bounce buffer at `0x20000`. The ELF is validated from its first chunk, and
   each segment's destination is checked against the memory map before any byte is
   copied. The CRC-32 of the whole file must match the header before the jump.
5. **Handover**: writes the boot protocol's structure, with the memory map translated
   from E820, the kernel's range, the firmware kind and the entry's command line, and
   enters the kernel's 32-bit entry with `EAX = ENTRY32_MAGIC` and `EBX` pointing at it.
   For a chainload entry it [boots the partition's record](#as-built-chainloading)
   instead.

**The handover used to be interim.** The first version of this loader handed over as
Multiboot 1, which both x86 kernels already accepted through `boot/info-multiboot`. Now
that `kinboot-efi` produces `BootInfo` and `boot/info-kinboot` reads it, this loader
writes the same structure through the same builder, and both `*-bios` presets use the
kinboot provider. `-kernel` boots keep the Multiboot path.

Every decision stage 2 makes is in the `kinboot-bios` crate (`boot/kinboot-bios/src/`)
or in `kinboot-menu`, which are byte-slice code with no `unsafe` and have host tests.
That covers the disk layout, E820/E801 decoding, ELF validation, the streaming copy
plan, the handover, which partition a chainload boots and what it is handed, and the
whole menu. The disk layout file is also compiled into `kbuild`, so the writer and the
reader cannot disagree. `loader/` only does I/O.

Before an entry is chosen, a failure prints `kinboot-bios:` and a reason to the screen
and COM1, then calls INT 18h, the BIOS's "this device did not boot" entry. A real machine
moves on to its next boot device. After an entry is chosen, the entry list's
`on-failure` decides: INT 18h, or a reset through port `0xCF9` with the keyboard
controller as a fallback. Under QEMU, the harness passes `-boot reboot-timeout=0
-no-reboot`, so either ends the run within seconds instead of timing out.

Stage 2 is 27.5 KiB with the menu and the entry parser. The first build of it was
34.5 KiB, over budget. The `cmdline` crate's words were `str`, and slicing a `str` links
`core`'s panic formatting and Unicode tables. Byte slices cost 7 KiB less.

**Not in this loader yet:** the boot counter (see
[Failure handling](#failure-handling)), EDD and VBE queries, and GPT.

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

**As built** (`armv7m-mps2`). The board description is a file under `config/boards/`
that declares the board and a `BOARD_MEMORY` string under `config/board.kcfg`: the
board's memory as `kind start length` entries. kbuild already emits every configuration
symbol into the generated `kconfig` crate as a constant, so no generator was needed.
`boot/info-board` is the `bootinfo` provider for any configuration with
`BOARD_DESCRIBED`:

- Its `MAP` is a `const` item that parses `BOARD_MEMORY` **in the compiler**, so a
  description with an unknown kind, a malformed number or an overflowing region stops the
  build with the reason. The parser is host-tested on its own.
- Its `command_line` composes `mode=` from `BOOT_MODE` and then `CMDLINE`: the line a
  KinTane loader's default entry would pass. So `BOOT_ARGS_CHECK` means the same thing
  here as on a loaded port.
- It returns the same `memory_regions` and `command_line` every other provider does. The
  plan above said a `BootInfo` structure; what is linked in is the provider's answer
  rather than a tag block, because `kmain` reads the provider, not the tags, on every
  port.

What it cannot do is notice a board that differs from its description. A loader's map is
measured and this one is asserted.

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

**What a mode changes today.** Most of the list above is about subsystems that do not
exist yet: secondary CPUs, driver isolation, modules, power management, storage. Each of
them must read the mode when it arrives. That is an obligation recorded here, not a
behaviour anyone can observe yet. The one item with a subject today is verbose output:
in `safe` and `recovery` mode the kernel prints the loader's memory map, region by region,
right after the command line (`kernel/main/src/bootargs.rs`). That is the first thing a
person needs to know about a machine that does not boot, and it is too long for every
boot. The banner reports the mode in every mode, as `boot mode`.

### As built: entries, the menu and the command line

Both loaders read the same entry list, and the same `boot/kinboot-menu` crate decides
what it means: a line-based file with a few settings (`timeout`, `default`,
`on-failure`) followed by entries. Each entry has a `title` and either a kernel `mode`
and `cmdline` or a chainload target. The crate's documentation is the format's
specification, and its host tests include the exact bytes `kbuild` writes. Nothing in
the file is evaluated. A file that does not parse is reported with its line number, and
the loader boots a built-in default entry, normal mode with no arguments, rather than
refusing to boot a machine over a typo.

Where the list lives: `\KINTANE\BOOT.CFG` on the ESP for `kinboot-efi`, and sectors after
stage 2, named by stage 2's header, for `kinboot-bios`. The design above mentions EFI
variables for UEFI boot configuration. A file was chosen first because the same file
serves both loaders and is written by the build. Variables remain the way to let the
firmware's own boot manager list our entries.

The menu is printed on every console the loader has: ConOut on UEFI (which OVMF mirrors
to the serial port), and the BIOS screen and COM1 on BIOS. The digit keys boot an entry
at once, up and down (or `k` and `j` on a serial line) move the mark, and Enter boots the
marked entry. Any key stops the countdown, so a person who has started choosing is not
overtaken by the timeout. A zero timeout still prints the menu and boots the default
without waiting.

The kernel command line an entry hands over is `mode=<its mode>`, then the entry's
`cmdline`. The kernel parses it with `boot/cmdline`, the grammar the loaders compose it
with, so a mode a loader offers is a mode the kernel understands. A `-kernel` boot gets
the same line from QEMU's `-append`: through the Multiboot command line on x86, and
through `/chosen/bootargs` on aarch64.

The configuration writes all of it (`config/main.kcfg`):

| Symbol | What it sets |
|---|---|
| `CMDLINE` | the `cmdline` of every entry, and the arguments after `mode=` for `-append` |
| `BOOT_MODE` | `normal`, `safe` or `recovery`: the default entry, and the `mode=` of a `-kernel` boot |
| `BOOT_MENU_TIMEOUT` | the countdown, 0 in test builds and 5 otherwise |
| `CHAIN_TEST` | adds a chainload test entry and makes it the default |
| `BOOT_ARGS_CHECK`, `BOOT_EXPECT_MODE`, `BOOT_TEST_KEYS` | test settings; see [testing.md](testing.md#boot-entries-the-command-line-and-chainloading) |

Test builds also write `on-failure reboot`. Under `-no-reboot`, a reset ends the run
within a second, and handing a failed boot back to OVMF would leave it trying its other
boot options until the harness timed out.

### Failure handling

The loader increments a boot counter in persistent storage — an EFI variable on UEFI, a
reserved sector on BIOS — before jumping. The kernel clears it once initialization
reaches a defined point. Repeated failures escalate automatically: `normal` → `safe` →
the previously installed kernel.

This is a small amount of machinery that turns an unbootable machine into a machine
that boots badly, which on hardware without a serial console is the difference between
debuggable and bricked.

#### As built: the EFI stub counts, the kernel confirms

The counter is the EFI variable `KinTaneBootAttempts`. Its name, vendor GUID and limit
are in `boot_protocol::uefi::boot_counter`, which both sides link.

- **The stub counts** (`boot/uefi/src/counter.rs`). Before anything else in the boot path
  can fail, it reads the number of attempts since the last confirmed boot, adds this one
  and writes it back. After three unconfirmed attempts in a row, the fourth starts with
  `mode=safe` in place of the built mode. The rest of the line is kept byte for byte.
- **The kernel confirms** (`kernel/lastgood/uefi`). Once `kmain`'s bring-up verdict is a
  pass, it deletes the variable with `SetVariable` and reads it back with `GetVariable`,
  requiring `EFI_NOT_FOUND`: a confirmation the firmware dropped would otherwise surface
  as safe mode a few boots later, with nothing in any log. A failed verdict leaves the
  count standing, and so does anything that stops the kernel before the verdict. A boot
  the tag says is past the limit must have arrived in safe mode, or the verdict fails.
- **How the kernel calls firmware.** Runtime code lives in memory the kernel does not map,
  and nothing the kernel maps outside its text is executable. So, while boot services are
  still up, the stub allocates a call space in memory the kernel sees as reserved:
  - six pages of page tables identity-mapping the first 4 GiB, writable and executable as
    the firmware ran on them;
  - a 64 KiB stack.

  It passes the call space and the three entry points it needs in a `UefiRuntime` tag. A
  call masks interrupts, loads that root, switches to that stack, calls, and restores
  both. The kernel's own tables never gain a page that is both writable and executable.
  `SetVirtualAddressMap` is never called, so the firmware runs at the addresses it was
  built for. The stub passes no tag if any runtime region lies above 4 GiB.
- **How it is proved.** `BOOT_COUNTER_TEST` runs on `x86_64-efistub`. It boots one QEMU
  machine without `-no-reboot`, so its variable store lives through the resets. Every
  boot before the fallback fails on purpose and resets through `ResetSystem`. The run
  passes only if:
  - attempts 1 to 3 arrive in normal mode;
  - attempt 4 arrives in safe mode;
  - that boot's confirmation reads back as gone.

  Every other `x86_64-efistub` boot confirms as well, so the runtime call also runs under
  the in-kernel, safe-mode and stack guard tests.

**Not built.**
- `kinboot-efi` and `kinboot-bios` do not count. For the first, the menu is the fallback,
  and a counter waits on a way to tell which entry a confirmed boot came from.
- Escalation stops at safe mode. There is no previously installed kernel to fall back to.
- A kernel that hangs rather than fails needs a watchdog, or a person, to reset it before
  the count moves.

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

### As built: chainloading

Both mechanisms above exist, as entry targets.

- **`chain-partition N`** (`kinboot-bios`) reads the MBR and checks its signature, takes
  partition N's entry, reads that partition's first sector, and checks its signature too.
  It then copies the MBR to `0x0600`, where classic MBRs relocate themselves, and the
  record to `0x7C00`. It drops to real mode and jumps with `DL` = the boot drive and
  `DS:SI` pointing at the partition's entry in that copy, which is what DOS-era boot
  records read to find their own partition. The decisions are `kinboot_bios::chain`; the
  jump is `chain_boot` in `loader/stage2.rs`.
- **`chain-file \PATH`** (`kinboot-efi`) reads the file from the loader's own partition
  and builds its device path: the partition's path with a file path node appended. It
  calls `LoadImage`, sets the child's `LoadOptions` to `kinboot-efi`, and calls
  `StartImage`. An application that returns to the loader is a failed boot.

Each has a test payload that `kbuild` builds only for `CHAIN_TEST`, and that exits QEMU
itself with a pass only if it was entered the way the mechanism promises. The BIOS one is
a boot record written as partition 2 (`boot/kinboot-bios/loader/chaintest.rs`). It checks
`DL` and that `DS:SI` is its own partition entry. The UEFI one is an EFI application on
the ESP (`boot/kinboot-efi-chaintest`). It checks its load options and that its
`FilePath` names its own file.

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

### As built: what is not verified, and why

Neither Secure Boot nor measured boot exists yet. This says precisely what that means, so
the design above is not read as a description of the code.

- **No signature is checked.** `kinboot-efi` and the EFI stub start whatever kernel they read
  or carry. The stub checks that its descriptor points inside its own image, which is bounds
  safety against a corrupt file, not authenticity: whoever can change the kernel can change
  the descriptor as well.
- **Secure Boot cannot be demonstrated here yet.** QEMU ships a Secure-Boot-capable OVMF
  (`edk2-x86_64-secure-code.fd`), but with the variable store that comes with it no keys are
  enrolled. The firmware is in setup mode and refuses nothing: the unsigned `kinboot-efi`
  starts under it and hands over to the kernel. Showing a refusal needs a key hierarchy
  enrolled into the variable store, and passing the check needs the image signed with
  Authenticode, a PKCS#7 signature over the PE's hash. Neither exists in the tree, and D8
  rules out taking them from a crate. They are one piece of work, not two.
- **Measured boot needs a TPM**, which QEMU provides only through `swtpm`. That is not part of
  the test environment, so no PCR is extended and no event log is passed.
- **Modules are not signed**, for the same missing primitive. A module carries a build
  identity and an interface hash, which refuse one built for another configuration. That
  guards against a mistake, not an adversary.

## Build integration

The loaders are built by `kbuild` from the same pinned toolchain under the same
reproducibility rules as the kernel ([build-system.md](build-system.md#reproducibility)),
and ship as part of the same release. `kbuild image --format` produces the bootable
artifact per platform: a GPT/ESP disk image, an MBR disk image, a raw XIP binary, or a
FIT image.

Two disk images exist today: the ESP image for `KINBOOT_EFI`, which
[build-system.md](build-system.md#what-a-build-produces-today) describes, and the MBR
image. With `KINBOOT_BIOS=y`, `kbuild build` also writes
`build/<target>/out/kinboot-bios.img` (`kbuild/src/bios.rs`), in these steps:

1. **Build the loader.** `core` is built for the loader's own target, then the
   `kinboot-bios` crate and the loader binary.
2. **Flatten it** with `llvm-objcopy -O binary`.
3. **Check its layout.** The signature, table and header must be where the disk format
   says, and the partition table must be untouched.
4. **Write the disk.** Stage 2's header is filled in with the entry list's and the
   kernel's locations and CRCs, the entries come from `kbuild/src/bootcfg.rs`, and with
   `CHAIN_TEST` the chain test record goes in as partition 2 with its expected drive and
   LBA filled in. The image is padded to whole 16×63 cylinders. SeaBIOS on q35 refuses to
   read a disk smaller than one cylinder, which the first `x86_64-bios` boot found.

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
- **Phase 7** — Secure Boot, measured boot, last-known-good escalation, and real firmware
  on real machines. Chainloading and the boot entries arrived early, with the minimal
  loaders, because they were asked for from the start.

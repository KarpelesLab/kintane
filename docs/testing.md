# Testing Protocol

A kernel that claims to support a dozen platforms and a thousand configurations is
making a claim about things nobody runs daily. The only defence is automation, and the
only automation that works is the kind that blocks merges.

**We rely fully on QEMU to begin with.** Physical hardware comes later. That is a
deliberate trade — QEMU gives us every tier-1 target on every developer's laptop and in
CI from day one, at the cost of a set of bug classes it structurally cannot find.
Those are enumerated in [What QEMU will not catch](#what-qemu-will-not-catch), and
pretending they do not exist is the one way this strategy fails.

Validated against QEMU 11.0.3; every mechanism described below was checked to exist
rather than assumed.

## Levels

### 1. Host tests

Code that does not touch hardware is compiled for the **host** target and tested with
ordinary Rust test tooling, against a mock architecture:

```rust
/// MMU, SMP, atomics, coherent DMA, floating point. A 4096-byte page.
pub struct MockFull;

/// Memory protection regions but no translation, one CPU, no compare-and-swap.
/// A 256-byte page, so anything that hardcoded 4096 shows up.
pub struct MockTiny;
```

`MockTiny` implements none of `HasMmu`, `HasSmp`, `HasCas`, `HasCoherentDma` or
`HasFpu`. **Code that compiles against one profile and not the other has silently
acquired a hardware requirement**, which is exactly what we want to find out on a
laptop in a second rather than on a board in an hour.

What the mocks cannot show is whether the code **compiles** for the machine a profile
imitates. Host tests build against the host's `core`, and the host has every atomic.
`MockTiny` therefore has no CAS as a trait, but its tests compile against a library
that has `compare_exchange`. `kbuild portability` covers that half. It compiles every
host-testable unit for built-in rustc targets that lack what the mocks only pretend to
lack: `riscv32i` has no atomics and `riscv32imac` has no 64-bit ones. See
[portability.md](portability.md#where-a-bound-is-not-enough).

The convention is that a test body is generic over `A: Arch` and instantiated once per
profile, which shows up in the output as paired `_full` / `_tiny` results. The frame
allocator's 65 tests are 33 scenarios run twice.

This is the largest payoff of the trait-based portability design and it is worth
protecting: **a subsystem that cannot be tested against `MockArch` has a design
problem.** New subsystems justify it or get restructured.

Covered here: allocators, schedulers (with a mock time source), the VFS, the object
model, device tree parsing, module relocation logic, config resolution, data
structures, and the boot protocol's tag encoding.

### 2. In-kernel tests

Tests that must run on the real architecture compile into a test image that boots
under QEMU, reports, and exits with a status code. The verdict is the exit status, so
no harness has to parse console output:

```
$ kbuild test --target --preset aarch64-virt
  selftest
    ok   irq_save/irq_restore nest and return
    ok   atomic compare_exchange fails on mismatch
    skip frame allocator over the real map (no memory map on this port)
    ...
    10 passed, 0 failed
  in-kernel tests passed (qemu exit 0)
```

**Skipped is reported distinctly from passed**, because they are different claims and
conflating them is how coverage rots silently. The aarch64 line above is an honest
statement that those checks did not run, not a green tick.

The test image is selected by a *provider pair* rather than a `cfg` in `kmain`:
`kernel/selftest` is linked when `INKERNEL_TESTS` is set and `kernel/selftest-none`
otherwise, so a production image does not contain the test code at all rather than
merely not reaching it.

What belongs here is only what a mock architecture cannot make good on — that this
machine's atomics really are atomic, that masking interrupts really masks them, that
memory the loader described can be read and written. Anything that does not need real
hardware belongs in level 1, which is faster and far easier to debug. Page table
manipulation and context switching join this level when they exist.

### Expected faults: the stack guard test

Some properties are only visible as a fault: "the guard page is unmapped" is a fact about
a table, and "an overflow is caught and reported" is a fact about the running machine.
A fault normally ends a run in a halt, and a halted guest looks the same to the harness as
a hung one. So the image itself has to know the fault was expected, and say so through the
result channel.

`STACK_GUARD_TEST` (depends on `QEMU_EXIT`) does that:

```
$ kbuild run --preset x86_64-qemu --set QEMU_EXIT=y --set STACK_GUARD_TEST=y
  ...
  overflowing the boot stack into its guard page
*** cpu exception 0x08 #DF double fault
    cr2    0x000000000010ef68
    ...
stack overflow: cr2 is in the guard page below the boot stack, reported from the #DF IST stack
expected guard page fault: observed
guest signalled success (qemu exit 33)
```

After bring-up, and only if bring-up passed, the image overflows the boot stack. The
exception path checks the faulting address against the guard page. That fault exits with
success; any other fault exits with failure immediately, so a broken guard fails fast
instead of timing out. Each port recognises the fault differently, and each difference is
stated in its `kspace.rs`:

| Port | Passes when |
|---|---|
| x86_64 | #PF or #DF with CR2 in the guard page |
| i686 | the same, with #DF reported from the double-fault task rather than an IST stack |
| aarch64 | the synchronous vector diverts a frame that would touch the guard page, or a data abort with FAR in it whose frame is *above* the guard |

Two more modes use the same machinery:

- **`THREAD_STACK_GUARD_TEST`** starts a kernel thread on a stack from the guarded
  thread-stack array and overflows it. The run passes only if the fault is on *that* stack's
  guard; a hit on the boot stack's guard, which is where an unguarded thread stack eventually
  ends up, fails.
- **`NULL_DEREF_TEST`** reads address zero and passes only if the fault is reported as a null
  dereference. Page 0 is never mapped on any port.

Each verdict was falsified, in every case by a mutation confirmed to have applied:

| Mutation | What happened |
|---|---|
| Boot guard page mapped | x86_64's recursion runs into `.rodata` and fails; aarch64 fails |
| aarch64 vector check removed | the report runs on a frame beneath the guard and fails |
| i686 #DF back on an interrupt gate (selftest told to accept it) | both i686 presets triple-fault: QEMU exits 0, a failure. With the selftest intact, the banner reports `NO task gate` and the boot fails instead |
| i686 double-fault task without `clts` | the report's first SSE instruction raises #NM, the #NM recursion runs through the task's stack, and the run triple-faults |
| Thread stack guards not cut from the data | the kernel space is refused before it is installed (`thread stack guards mapped: 8`). With that check also removed, the overflow runs down through every slot: x86_64 triple-faults, i686 and aarch64 reach the boot stack's guard and fail as "not it" |
| aarch64 vector ignores the thread-stack array | the thread overflow is reported from a frame beneath its guard and fails; the boot-stack test still passes |
| Page 0 mapped | the kernel space is refused. With the check also removed, the null read succeeds and x86_64 and i686 fail |

CI runs all three on every preset with an MMU, beside the ordinary boot. `riscv32-virt`
and `riscv32i-virt` have no page to unmap, but their harts have Physical Memory
Protection. The port locks a no-access PMP region over the page below the boot stack and
over the bottom page of each thread-stack slot, and the boot banner's `interrupts` line
reads `pmp 9 of 9 stack guards locked`. So the two stack-guard modes depend on
`MM_PAGED || ARCH_HAS_PMP`, and CI runs both on the two riscv32 presets. The
null-dereference mode needs page 0 unmapped, which only a paged kernel has, so it stays
`MM_PAGED`-only.

On riscv32 each mode *touches* a guard from a healthy stack rather than overflowing into
it. A machine-mode trap runs on the stack it interrupts, so a real overflow would take its
trap on the overflowed stack, with no separate stack to escape to. The modes therefore
prove that each region faults and is reported as the stack it guards — `stack guard: the
address is in the PMP region below the boot stack`, then `expected guard fault: observed`
— on rv32i and rv32imac alike. They do not prove a real overflow is reported, which needs
an emergency stack switched in through `mscratch`.

The falsification is the lock bit. An entry without it does not bind machine mode, the
mode the kernel runs in. With the bit dropped, the run prints `touching the boot stack's
guard region`, the read succeeds, and the guest exits with code 1. The banner still reads
`9 of 9 locked`, because its read-back checks what was written, not that machine mode is
bound by it — which is why the test mode, not the banner, is the proof.

`armv7m-mps2` has no page to unmap either, but it has an MPU, and its guards are MPU
regions: no access to the page below the boot stack, or to the bottom 8 KiB of each
thread-stack slot. The configuration refuses the three test modes there too, because
they are written against `MM_PAGED`. So its interrupt selftest proves the guards instead:
it reads the boot stack's guard and a thread stack's guard, writes `.rodata`, and requires
the first three to fault and a read of `.rodata` not to, stepping over each faulting
instruction. A genuine overflow of the boot stack was run by hand as a mutation. The core
fails to stack the exception frame, and the report still names the guard (`stack
overflow: the address is in the guard below the boot stack`), because handlers run on the
main stack and threads on the process stack.

### Boot entries, the command line and chainloading

The boot path has its own settings, and each is proven the same way: by a boot whose exit
code depends on it. See [bootloader.md](bootloader.md#as-built-entries-the-menu-and-the-command-line)
for what they are.

- **The command line arrives intact, on every preset.** Test builds set `CMDLINE` to a
  canary and `BOOT_ARGS_CHECK`. The kernel's banner fails the boot unless it received
  `mode=` `BOOT_EXPECT_MODE` followed by exactly the words of `CMDLINE`. Every boot in CI
  therefore checks the whole path from the configuration to the kernel. On `-kernel`
  presets that path is `-append`, through Multiboot on x86 and `/chosen/bootargs` on
  aarch64. On the loader presets it is the entry list, the menu and the protocol's
  command line tag. A line that is missing, cut short or in the wrong mode is exit 35.
- **Safe mode does what safe mode does.** Every preset is also booted with
  `BOOT_MODE_SAFE=y`. The check above then requires `mode=safe`, and the step requires the
  mode's effect, the verbose memory map, in the console output.
- **The menu reads a keyboard.** With a nonzero `BOOT_MENU_TIMEOUT`, `BOOT_TEST_KEYS` is
  typed on the guest's serial console once the loader prints its menu, and
  `BOOT_EXPECT_MODE` is set to the mode of the entry that key selects, not the default's:

  ```
  $ kbuild run --preset i686-bios --set BOOT_MENU_TIMEOUT=30 --set BOOT_TEST_KEYS=2 \
        --set BOOT_EXPECT_MODE=safe
  ```

  The keys are typed when the menu appears rather than when QEMU starts, because firmware
  and loader both reset the UART's receive FIFO when they program it. The first version
  typed at once, and the keystroke was lost every time.
- **Chainloading hands over what it promises.** `CHAIN_TEST` makes a test payload the
  default entry, on `i686-bios`, `x86_64-bios` and `x86_64-efi`. The payload exits QEMU
  itself: 33 if it was entered correctly, 35 if not. The BIOS payload checks `DL` and
  `DS:SI`; the UEFI one checks its load options and `FilePath`.

Each verdict was falsified by a mutation confirmed to have applied:

| Mutation | What happened |
|---|---|
| `kinboot-bios` writes no command line tag | `cmdline none passed`, exit 35 |
| `kinboot-efi` writes no command line tag | the same on `x86_64-efi` |
| `-append` dropped from x86 `-kernel` boots | the kernel gets only QEMU's image path, which it strips; `EXPECTED ...`, exit 35 |
| `-append` dropped from aarch64 | no `/chosen/bootargs`: `none passed`, exit 35 |
| The BIOS loader hands over the line one byte short | `kintane.canary=cmdline-intac`, `EXPECTED ...`, exit 35 |
| The menu ignores `default` (`BOOT_MODE_SAFE=y`) | both loaders boot normal, `EXPECTED mode=safe`, exit 35 |
| Digit keys off by one (key `2` typed) | `i686-bios` boots recovery, exit 35; a `kinboot-menu` host test fails too |
| Chainload with `DL` wrong | the record prints `FAILED, DL is not the boot drive`, exit 35 within seconds |
| Chainload with `SI` one entry off | `FAILED, DS:SI is not this partition's entry`, exit 35; a `kinboot-bios` host test fails too |
| Chain entry names an empty partition | `partition 3 is empty`, INT 18h, exit 0 (a failure) at once |
| Entry list CRC written wrong | `boot entries checksum mismatch`, exit 0 (a failure) at once |
| `kinboot-efi` sets no load options | the application prints `FAILED, not started by kinboot-efi`, exit 35 |
| Chain entry names a missing EFI file | `cannot open`, then the `on-failure reboot` reset: exit 0 (a failure) two seconds in. **Control:** with `on-failure firmware`, OVMF moves on to PXE and the run times out at 60 s, which is why test builds write `reboot` |
| Safe mode's verbose map removed | the boot still passes, as intended, since output is not a verdict, but the CI step's check for the map fails |
| Multiboot image path not stripped | the kernel sees QEMU's file name as its first word, exit 35. This proves QEMU does pass the path |
| `/chosen` not recognised | aarch64 `none passed`, exit 35; an `fdt` host test fails too |
| kbuild writes a different entry title | kbuild's pinned-fixture tests fail |
| The parser renames `chain-partition` | four `kinboot-menu` tests fail, the pinned fixture among them |

### Loadable modules

With `MODULE_TEST=m`, the default on x86-64 test builds, kbuild builds the three modules
under `modules/test` and the bundle that carries them, and a `-kernel` boot passes the
bundle as a multiboot boot module. The boot then gates on the `modules` line
([modules.md](modules.md#the-boot-check)):

```
  modules    3 in the bundle at 0x00000000001ca000
             test-roundtrip:
             [test-roundtrip: init]
             loaded at 0x0000000060000000, 9 relocations, W^X sealed; 42, 72; unload refused while referenced
             [test-roundtrip: exit]; unloaded
             0 frames left
             test-other-config: refused, built with DEBUG_BUILD=n, kernel has y
             test-other-interface: refused, kt_register_callback is not the kernel's interface ok
```

The loader's steps are host-tested in `kernel/module`:

- objects built byte by byte;
- a real module kbuild built, in `kernel/module/testdata`;
- every byte of a module corrupted three ways, and every truncation, all without a panic.

Each property the boot claims was falsified: the mutation was applied and checked, the
check failed, and the mutation was restored and compared byte for byte.

| Mutation | What caught it |
|---|---|
| `R_X86_64_32` not written | host test; the boot faulted on a null string pointer |
| unloading ignores references | host test; `UNLOAD NOT REFUSED WHILE REFERENCED` |
| identity not compared | host test; `test-other-config: LOADED, and must not have` |
| interface hashes not compared | host test; `test-other-interface: LOADED` |
| the module list not carved from the memory map | `NO MODULE BUNDLE, though this handover carries one` |
| unloading does not free frames | `3 frames left` |
| text sealed writable | `the live tables did not take the module's protections` |

The SDK is checked the same way. CI builds it, copies the round-trip module's source
outside the tree, builds it with the SDK's `build-module.sh`, and requires the result to
be byte-identical to the module kbuild built in the tree.

### 2a. The userspace slice

On x86_64 and aarch64 (`USERSPACE`, on by default) every boot runs the native userspace
check: it builds three processes from the embedded `user/init` program, enters ring 3 /
EL0, and grades each by its exit code — `main` returns `0x2a` when every step behaved,
`forge` returns the count of refused forged-handle attempts, and `fault` is *killed* at a
write to kernel memory. The program reports what it observed and the kernel compares, so
the grader is not the code under test. See
[userspace-abi.md](userspace-abi.md#as-built--the-native-vertical-slice).

Falsified (each mutation on x86_64, then restored):

| Mutation | Result |
|---|---|
| `debug_write` skips the `WRITE`-rights check | `main` fails at the console-rights step (`0x102`) |
| `enter_user` does not set `TSS.rsp0` | a demand fault from ring 3 lands on a stale stack; `main` and `forge` are killed |
| `copy_from_user` skips its validation | reading the program's bad pointer faults the *kernel*: `#PF`, halted |

The ABI table and the ELF loader are also host-tested (`lib/abi`, `kernel/elf`), the
loader against fuzzed and truncated files.

### 2b. Block storage

With `QEMU_BLOCK_TEST`, on by default on aarch64 test builds, kbuild writes
`testdisk.img` beside the image. It is 6 MiB in three regions: 4096 sectors in which every
byte is a function of its sector and offset, with a header in sector 0; a scratch area the
write checks use; and a FAT16 volume for the [files check](#2c-files). QEMU attaches it to a `virtio-blk-device` with
`snapshot=on`, so a run's writes never reach the file. The format is written twice, in
`kernel/block/src/testdisk.rs` and `kbuild/src/testdisk.rs`, and a pinned set of bytes
that both sides' tests assert keeps the two in step.

The boot gates on the `block` line ([architecture.md](architecture.md#block--the-block-layer-and-the-first-driver-with-dma)):

```
  block      12544 sectors of 512 bytes, 23 per request; 32 sectors read back the pattern;
             a write read back after a flush; a read past the end refused; the device's own
             refusal was an error; 64 more requests, 0 in flight ok
```

The driver's protocol is host-tested without QEMU:

- `test_support::FakeDevice` walks the rings from the device's side, at a different memory
  offset, and answers virtio-blk requests against a RAM disk.
- The tests cover the handshake and every refusal in it, reads, writes, splits, a device
  error, a device that never answers, and a thousand requests with no descriptor lost.

In a stress run the `block` workload writes random runs of the scratch area and reads them
back, reads the untouched part against the pattern, and flushes. At every audit the driver
must report nothing in flight and every descriptor on the ring.

### 2c. Files

On the presets with the test disk — every aarch64 preset, where `QEMU_BLOCK_TEST` defaults on — every boot runs an
`fs` check right after the block check, on the FAT16 volume kbuild writes into the disk's third
region ([architecture.md](architecture.md#vfs-bcache-and-fat--files)). The check requires:

- the volume mounts at `FS_START` and is FAT16 by its cluster count;
- `/` lists exactly the names kbuild placed there, and nothing else;
- `/HELLO.TXT`, `/SUB/NESTED.TXT` and the 196-cluster `/BIG.BIN` read back byte for byte, the
  last through a chain walk;
- a read past the end of `/BIG.BIN` returns nothing, and a buffer too small for it is refused
  rather than filled with part of it;
- a block written through a cache reads back fresh, both from the cache and from the device;
- the volume's cache was hit, missed and made to replace slots, and its books hold;
- with userspace, `/KINTANE/INIT.ELF` loads from the volume and runs to its success exit code. From
  then on the scheduled process check and the stress run's process cycles run that copy.

On `aarch64-virt` the line reads:

```
  fs         FAT16 at sector 4352; / lists 4; files read back, 100 KB through a chain; /KINTANE/INIT.ELF (113320 bytes):
             hello from userspace
             ran from the disk; cache 43746 hits, 426 misses; a write through the cache read back fresh ok
```

The stress run adds a filesystem workload on the same presets. It reads random ranges of
`/BIG.BIN`, reads the small files whole, and lists the root, all through a namespace, dropping the
whole cache every 64 iterations. The disk it reads is the one the block workload is writing at the
same time. The audit requires every handle closed and the cache's books balanced.

`vfs`, `bcache` and `fat` are host-tested (13, 10 and 17 tests). The FAT reader's tests build their
volumes with a writer of their own, independent of kbuild's.

Each property was falsified: the mutation was applied and checked, the check failed, and the file
was restored and compared byte for byte.

| Mutation | What caught it |
|---|---|
| The chain walk reads the table one entry off | 4 `fat` host tests; boot: `/BIG.BIN DIFFERS AT BYTE 512` |
| Directory entries read 31 bytes apart | 10 `fat` host tests; boot: `THE ROOT IS MISSING AN ENTRY KBUILD WROTE` |
| A write-through leaves the cached copy stale | a `bcache` host test; boot: `A WRITE THROUGH THE CACHE READ BACK STALE FROM THE CACHE` |
| A write drops its reference to the slot already holding the block | a `bcache` host test; boot: the same stale read |
| The stress workload never closes a handle, its counters still balanced | stress, at 1 s: `a handle was left open at the end of an iteration` |
| The reader starts the root directory one entry late | only the label-less `fat` host test — **the boot check still passes** |

The last row is the one worth remembering. kbuild's volume, like almost every real one, has its
label in the root's first entry, and a reader skips the label. So a reader that starts one entry
late skips the label by accident and still lists everything correctly. With that mutation every
other check passed, including the boot check on the real disk. A host test on a volume with no label
is what catches it, and it was added because the mutation showed nothing else would.

Moving kbuild's FAT writer into `kbuild/src/fat16.rs` was checked for the ESP by building the old
writer and the new one as standalone programs over the same files. The two images are
byte-identical, and a copy of the new writer with one boot-sector field changed is not, so the
comparison can see a difference.

### 3. Boot and integration tests

Per-target, per-preset: boot the real kernel image under QEMU, reach userspace (once
there is one), run a scripted workload, check output, exit cleanly. Includes deliberate
fault injection — kill an isolated driver and confirm it restarts, exhaust memory and
confirm the fallible allocation paths are exercised rather than merely present.

From Phase 6b this level gains its most valuable input: **unmodified Linux binaries**.
The compatibility corpus — static musl first, busybox, later a real userland — runs
under the Linux personality on every merge. Software written without any knowledge of
this kernel is the only workload that does not share our assumptions. The corpus is
also the compatibility claim itself; see
[userspace-abi.md](userspace-abi.md#scoping-and-the-partial-compatibility-problem).

Gaps are loud rather than silent: an unimplemented syscall returns `-ENOSYS` and logs
its name, and CI enables the option making that fatal, so a missing syscall is a named
failure instead of a program behaving oddly.

### 3a. Stress

The Phase 2 exit criterion is a kernel that survives 24 hours of concurrent work on
every tier-1 architecture, with allocation failure injected. `kbuild stress` is that
run:

```
$ kbuild stress --preset aarch64-virt --duration 10m
stress heartbeat 600/600 s: heap 19811696 (refused 1239506), ipc 104967, sleeps 22725
  (latest +31871 us), vm 210144 (faults 2153987, copies 420290, huge 52537), pages 262773,
  audits 600 ok
stress passed: 600 audits over 600 s
```

It builds the image with `STRESS_TEST`, which requires `QEMU_EXIT` and selects
`KALLOC_FAULT_INJECT`, and `STRESS_SECONDS` set from `--duration`. After a clean
bring-up the kernel hands the CPU to the scheduler for good (see
[architecture.md](architecture.md)), and boot becomes an auditor over seven workload
threads at mixed priorities (`kernel/main/src/stress.rs`):

- **heap** — kernel heap churn from two threads, with one request in 32 failed on purpose from a
  seeded injector;
- **ipc** — a channel ping-pong that moves a handle there and back on every round trip;
- **sleep** — sleeps to random deadlines, which must never wake early;
- **vm** — demand paging, copy-on-write sharing and 2 MiB pages on a kernel `Vm`;
- **pages** — buddy allocator churn on a pool of its own.

Every second of guest time the auditor stops every workload at a checkpoint, where it
holds nothing that would make the books inexact, and checks them:

- the heap's bytes in use are back at their baseline;
- the heap's failure count equals the refusals the workloads handled;
- channel handle counts are exact and nothing is queued;
- `Vm::audit` passes, and the vm frame pool is full when nothing is mapped;
- `Buddy::check` passes, with every page free;
- `Threads::check` passes, and nothing was recorded as broken;
- no lock-order violation;
- every workload made progress since the last audit.

A failed audit prints `stress AUDIT FAILED` and exits with the failure code. A workload
that cannot reach a checkpoint within three seconds is a failure too. Each audit ends
with a `stress heartbeat` line, and the last one with success.

**The heartbeat is read, the verdict is not.** A thread spinning with interrupts masked
stops the auditor with it, and a stopped guest cannot reach the exit port. So `kbuild
stress` kills a guest whose heartbeat is missing for 30 seconds, or that has not printed
its first one within 180 seconds of starting. It reports that as a hang. That is the
only place the harness looks at console output, and it looks only for the absence of a
line. A pass is still only the exit code. The run also drops QEMU's per-interrupt log,
which a day of timer interrupts would grow past any disk.

**What each check was shown to catch**, by breaking the code and watching the run fail:

| Mutation | Result |
|---|---|
| One held heap block leaked after an injected refusal | audit failed at 1 s: heap bytes not back at baseline |
| The sleep workload keeps parking but stops sleeping | "made no progress since the last audit: sleep" at 3 s |
| The page workload spins with interrupts masked | killed by the watchdog: no heartbeat for 30 s |
| Pong keeps one extra handle | "pong's table does not hold exactly its endpoint" |
| One vm pool frame leaked once | "frames are missing from the pool with nothing mapped" at the first empty checkpoint |

**Eight CPUs.** Phase 3's exit criterion is eight CPUs. The SMP presets boot four, so
every other step stays quick. CI adds a 20-second eight-CPU run of both SMP presets,
the nightly soak adds eight-CPU jobs, and a run by hand passes `--set QEMU_CPUS=8`. A
guest given more CPUs than `NR_CPUS` is refused by kbuild before it boots, rather than
started with fewer.

Sixty seconds at eight CPUs passed all 60 audits on both ports, with every CPU doing work:

| Port | Iterations per CPU | Least over most | Migrations | Shootdowns |
|---|---|---|---|---|
| x86_64 | 171,674 – 285,244 | 0.60 | 27,976 | 161,519 |
| aarch64 | 591,456 – 2,024,585 | 0.29 | 32,507 | 324,042 |

On aarch64, CPU 1 carried the least. That is observed, not explained.

Five minutes at eight CPUs, one port after the other, passed all 300 audits on both:

| Port | Heap iterations | Channel round trips | Shootdowns | Migrations | Least over most |
|---|---|---|---|---|---|
| x86_64 | 4,401,203 (276,033 refused) | 2,061,894 | 782,777 | 130,551 | 0.47 |
| aarch64 | 20,163,952 (1,261,496 refused) | 19,955,584 | 1,620,530 | 174,886 | 0.33 |

aarch64's CPU 1 again carried the least. The latest wake-up in either run was about
300 ms late, where four CPUs stay within tens of milliseconds. That fits the boot CPU
alone keeping time for eight emulated CPUs competing for fewer real ones, but it is an
observation rather than a measured cause.

Two things had stopped eight CPUs, and neither showed at four:

- **Thread stacks ran out.** Each linker script hard-coded its slot count, and at eight
  CPUs the secondaries' own stacks left the stress run too few for its workloads. The
  array is now sized from configuration ([architecture](architecture.md)). Two checks make
  asking for too little fail at build time:
  - `KERNEL_THREAD_SLOTS=4` fails to compile: "KERNEL_THREAD_SLOTS is below what this
    build's kernel threads need".
  - `THREAD_STACK_KIB=12` fails to link: "THREAD_STACK_KIB is not a power of two".
- **The epoch check failed under a loaded host.** It passed 16 of 16 runs alone. With both
  SMP ports booting eight CPUs at once, aarch64 failed "RETIREMENT REFUSED" in two of two
  rounds, because its writer outran reclamation. Now the writer waits for room, and judges
  a CPU the collector names by that CPU's own finished reads rather than by the
  collector's count of advances. The contended case then passed eight of eight.

The epoch fix was falsified in three directions, each mutation asserted and restored byte
for byte:

| Mutation | Result |
|---|---|
| A reader stuck while pinned on CPU 1 | "A PARTICIPANT STALLED THE EPOCH on CPU 1" |
| A reader that never releases its pin but keeps counting reads | "RECLAMATION NEVER CAUGHT UP" after 24 s, not a harness timeout |
| The writer fails on the first full bag again, bag still scaled | aarch64 "RETIREMENT REFUSED" in two of three contended rounds |

The last row is why the waiting, and not the larger bag, is the fix.

**Not only at eight CPUs.** Before the fix, other verification runs saw the same "RETIREMENT
REFUSED" at four CPUs, on `aarch64-virt-smp` and in both SMP stress images. They reported
it at roughly one boot in five while the host ran suites in parallel, and passing when
rerun alone. That rate is their report, not measured here.

After the fix, both SMP presets booted twenty times in a row at their default four CPUs.
Every boot shared the host with `i686-qemu` and `riscv32-virt`, so four QEMUs ran at once.
All 40 boots passed the epoch check and exited cleanly.

**What it found on its first long run.** x86_64 and i686 passed 600 audits. aarch64 went
silent after 109 audits, with no report, and the watchdog killed it. Three runs
reproduced it, at 156, 191 and 406 seconds. `info registers` on QEMU's monitor at the
hang showed a CPU that was running, but only in the interrupt path: GIC claim and EOI,
the counter read, and `arm_ns`.

The cause was `CNTP_TVAL_EL0`. It holds 32 bits, but as a **signed** value, and the port
allowed arming up to `u32::MAX` ticks. The scheduler arms the full reach whenever the
timer queue is empty and no thread is waiting, which happens for an instant while the
auditor runs. A deadline more than 2.15 s ahead sign-extended into the past, fired at
once, and was re-armed identically from the interrupt, so the CPU took timer interrupts
and nothing else.

No boot check could see it, because none armed more than half a second. The fix limits
one arming to `i32::MAX` ticks. The boot's tickless check now also arms the full reach
and requires no interrupt for 20 ms. The first version of that check restored the boot
thread's masked interrupt state, so the early interrupt could never be taken, and it
passed with the bug in place. The second takes the interrupt but kept the scheduler's
hook, which re-armed the same deadline, so the bug became a hang again. The third
unmasks explicitly and removes the hook while it watches, and it reports FAILED on the
unsigned limit.

**On several CPUs** (`aarch64-virt-smp`, `x86_64-qemu-smp`) the scheduler runs every CPU and the same
workloads spread across them. Two more checks join the audit there:

- **Spread.** The two heap workloads never block, so only balancing moves them off the CPU that
  spawned them. If both ran on a single CPU for a whole interval, the audit fails.
- **Shootdowns.** Every TLB shootdown since boot was answered by exactly the online CPUs other than
  the initiator, and none stalled.

The heartbeat adds iterations per CPU, migrations, pulls, reschedule IPIs and shootdowns:

```
stress heartbeat 30/30 s: heap 2506153 (refused 157179), ipc 2223464, sleeps 1135
  (latest +87075 us), vm 9531 (faults 97703, copies 19064, huge 2383), pages 13732,
  cpus 4 [1763522 1883534 1753371 1577052] migrations 954 (pulls 445),
  ipis 23720 (idle kicks 127), shootdowns 250201, audits 30 ok
```

| Mutation | Result |
|---|---|
| No reschedule IPI for a wake placed on another CPU | "a workload did not reach a checkpoint: ping" at 3 s |
| Balancing disabled | "both never-blocking heap workloads ran on one CPU for a whole interval" at 1 s |
| The scheduler lock removed | "a workload did not reach a checkpoint: heap B" at 1 s |

The first works because an idle secondary no longer wakes for every timer in the
kernel (see [architecture.md](architecture.md#the-smp-scheduler)). A woken thread
placed on it without an IPI waits for a full arming of its timer, seconds, instead of
milliseconds.

**Not falsified:** the reschedule IPI a secondary sends the boot CPU when it arms a timer
earlier than the boot CPU's next wake-up. Removing it still passed a 20-second run. The
stress workloads keep the boot CPU busy with slices, so it never sleeps long enough for
the missing kick to matter. The mechanism is argued in `timekeeping::program`, and nothing
here tests it.

An 8-minute run on `aarch64-virt-smp` passed all 480 audits: 40 million heap iterations,
33 million channel round trips, 151 thousand vm cycles, 16,504 migrations, 447,737
reschedule IPIs and 3.97 million shootdowns. The four CPUs completed 27.9, 27.6, 26.0 and
24.9 million workload iterations.

Every merge runs a 20-second stress smoke on each tier-1 architecture and on
`aarch64-virt-smp` and `x86_64-qemu-smp`, which keeps the image building and passing its first audits. A nightly workflow
(`.github/workflows/stress.yml`) runs 30 minutes per tier-1 preset,
and takes a duration input when dispatched by hand. The 24-hour run is that dispatch
with `24h`. GitHub-hosted runners cap a job at six hours, so it needs a self-hosted
runner; the workflow says so rather than letting the job be cancelled at hour six.

What this level does not cover yet: more than one CPU, userspace, devices beyond the
timer and the console, and fault injection outside the kernel heap. The heap injector
also leaves out the buddy-page site, because a refused page block falls back to an arena
that reclaims only in last-in-first-out order. Injecting there would exhaust the arena by
design (`kernel/main/src/stress/heap.rs`).

### 4. Hardware — deferred

Not "cancelled". See [The hardware debt](#the-hardware-debt) for what deferring it
actually costs and when it comes due.

## The QEMU protocol

### Machines

One canonical invocation per target, defined in `config/presets/` and never typed by
hand:

| Target | Emulator | Machine | Firmware | Result channel |
|---|---|---|---|---|
| x86_64 (UEFI) | `qemu-system-x86_64` | `q35` | OVMF, booting `kinboot-efi` from the image's ESP | `isa-debug-exit` |
| x86_64 (`x86_64-qemu`) | `qemu-system-x86_64` | `q35` | `-kernel` | `isa-debug-exit` |
| x86_64 (`x86_64-bios`) | `qemu-system-x86_64` | `q35`, raw disk | SeaBIOS, `kinboot-bios` | `isa-debug-exit` |
| i686 (`i686-qemu`) | `qemu-system-i386` | `pc` (i440FX) | `-kernel` | `isa-debug-exit` |
| i686 (`i686-bios`) | `qemu-system-i386` | `pc` (i440FX), raw disk | SeaBIOS, `kinboot-bios` | `isa-debug-exit` |
| aarch64 | `qemu-system-aarch64` | `virt` | AAVMF, or `-kernel` | semihosting |
| aarch64 (`aarch64-virt-smp`) | `qemu-system-aarch64` | `virt`, `-smp 4` | `-kernel`, secondaries through PSCI | semihosting |
| armv7m (`armv7m-mps2`) | `qemu-system-arm` | `mps2-an385` (Cortex-M3) | none: `-kernel`, executing in place | semihosting |
| x86_64 (`x86_64-qemu-smp`) | `qemu-system-x86_64` | `q35`, `-smp 4` | `-kernel`, secondaries through INIT and startup IPIs | `isa-debug-exit` |
| riscv32 (`riscv32-virt`) | `qemu-system-riscv32` | `virt` | `-bios none`, `-kernel` | `sifive_test` |
| riscv32 (`riscv32i-virt`) | `qemu-system-riscv32` | `virt`, `-cpu rv32` with A, M and C off | `-bios none`, `-kernel` | `sifive_test` |

The `-kernel` rows also pass `-append` with the command line the configuration's default
entry would hand over.

The UEFI row is the `x86_64-efi` preset. It needs firmware that is not part of the
pinned toolchain, so `kbuild` looks for OVMF where distributions put it: next to the
`qemu-system-x86_64` on `PATH` (QEMU's own edk2 build, as Homebrew installs it), then
Debian/Ubuntu's `ovmf`, Fedora's and Arch's `edk2-ovmf`, or `KINTANE_OVMF_CODE` and
`KINTANE_OVMF_VARS`. The variable store is copied fresh for every boot, and the disk is
attached with `snapshot=on`, so a run changes neither the firmware's state nor the
image the build produced. That preset logs guest errors and resets rather than every
interrupt, because OVMF takes thousands of them before the kernel starts.

The `x86_64-qemu` preset boots the same kernel with `-kernel` and stays the fast path
for everyday work. The two differ only in how the kernel is entered and where its
memory map comes from, and a kernel built for the loader fails its boot check if the
handover is missing — a lost `rdi` must not read as "no memory map on this port".

The `aarch64-virt-smp` preset is the `aarch64-virt` kernel with `SMP=y` and
`QEMU_CPUS=4`. `QEMU_CPUS` is both the `-smp` given to QEMU and the CPU count the kernel
requires the device tree to report. So a run that loses the option fails, instead of
passing an SMP check on one CPU. Its `smp` and `shootdown` banner lines are described in
[architecture.md](architecture.md#smp). It runs every mode the other aarch64 preset runs,
and the stress run, where the scheduler works across all four CPUs. The one-CPU preset
reports both lines as skipped: `SMP=n`, so nothing was started.

The `x86_64-qemu-smp` preset is the same for x86_64: the `x86_64-qemu` kernel with `SMP=y`
and `QEMU_CPUS=4`, whose `smp` line requires the MADT to list exactly four processors and
each started one to prove its number, its APIC ID, its own GDT and TSS, its timer's rate,
an IPI round trip, its per-CPU counter and its lock-order stack. It runs every mode
`x86_64-qemu` runs. The two-CPU x86_64 presets report the line as skipped. With a local
APIC that lacks x2APIC mode (`--set QEMU_CPU=max,-x2apic`) the same preset exercises the
driver's MMIO path; that run is not in CI.

Every x86 row also gets two CPUs (`QEMU_CPUS`) and, with `QEMU_PCI_TEST_DEVICE`, a
`pci-testdev` behind a bridge: a PCI Express root port on q35, a PCI-to-PCI bridge on pc.
Outside the SMP presets the kernel starts only one CPU, and nothing drives the test
device. They exist so that device discovery has something to be wrong about:

- the MADT must list exactly two enabled processors;
- enumeration must follow the bridge to find the device;
- its BARs must size to exactly 4 KiB of memory and 256 bytes of I/O;
- the host bridge at `00:00.0` must be the chipset the machine type implies.

Discovery also re-reads every BAR it sized and fails the boot if any reads differently.
Each of these was falsified by mutation; see the device model in
[architecture.md](architecture.md#device--the-device-framework).

Every x86_64, i686 and aarch64 test build also proves the console UART receives on
interrupt through the device model (`SERIAL_IRQ_TEST`, the `serial` banner line). The
kernel prints `serial probe 1: waiting for input`; kbuild, watching the console, types
`kintane-probe-1` on the guest's serial input (`SERIAL_PROBES` in `kbuild/src/qemu.rs`,
the same mechanism that types boot-menu keys); and the round passes only if every byte
comes back from the driver's queue, at least one receive interrupt ran, the interrupts
were dispatched through the device model's handler table, and no interrupt reached a line
with no handler. On the PCs the 16550 is then unbound — line disabled, driver stopped,
handler unregistered, ports and line given back to the ledger, which must then show
nothing held for the node — and bound again, and a second string must arrive the same
way. The PL011 is aarch64's console and its state is write-once, so aarch64 runs one
round and says so. The check waits at most 15 seconds a round, by the clock, so a broken
path fails the boot rather than timing it out.

Each property was falsified: the mutation was asserted to apply, the boot failed, and the
file was restored byte for byte.

| Mutation | Preset | What caught it |
|---|---|---|
| the line never unmasked at the controller | `x86_64-qemu` | `0 bytes in 0 receive interrupts`, both rounds; exit 35 |
| the handler registered in the table for the wrong line | `aarch64-virt` | `0 bytes … 1 unhandled`; exit 1 (before the fix below: a hang) |
| no handler ever registered | `aarch64-virt` | `0 bytes … 1 unhandled`; exit 1 |
| the architecture's interrupt path never calls the device model | `i686-qemu` | `0 dispatched through the device model, 1 unhandled`, both rounds; exit 35 |
| removal does not give the claims back | `x86_64-qemu` | `1 port ranges and 1 lines still claimed`, then the rebind's probe refused; exit 35 |
| unbinding leaves the handler registered | `i686-qemu` | `HANDLER STILL REGISTERED`, then the rebind refused a second handler for the line; exit 35 |

The second row found a real hang: the PL011's receive interrupt is level-triggered, and
with no handler to read the byte it was re-delivered the moment it was acknowledged. The
interrupt path now masks and counts a line nobody handles.

The ACPI parser's host tests read the firmware's tables from three of these machines,
captured without booting anything: `boot/acpi/src/testdata/capture.sh` starts the
machine with no kernel, lets the firmware build its tables and fail to find a boot
device, saves guest memory through the QEMU monitor, and extracts the RSDP and every
table it reaches.

QEMU also ships system emulators for `m68k`, `sparc`, `sh4`, `mips`, `alpha`, `hppa`,
and `ppc` — every architecture in the
[tier-3 long tail](targets.md#tier-3-and-the-long-tail). A contributed port can have CI
from its first commit, which is what makes the "possible without a fork" promise
credible rather than rhetorical.

### How a test reports its result

Console scraping is not a protocol. Each platform has a real mechanism for a guest to
terminate with a status, and we use it:

- **x86:** `-device isa-debug-exit,iobase=0xf4,iosize=0x04`. The kernel writes a byte
  to port `0xf4` and QEMU exits with `(value << 1) | 1`. Note the consequence: **the
  guest can never produce exit code 0.** Convention is to write `0x10` for success,
  giving exit code 33, and the harness maps it back. Anything else — including a real
  0 — is a failure, which conveniently means "QEMU exited for reasons of its own" is
  never mistaken for a pass.

  A disk boot relies on that. The `*-bios` presets add `-boot reboot-timeout=0`, so when
  the BIOS finds nothing bootable, or `kinboot-bios` gives up through INT 18h, SeaBIOS
  reboots at once and `-no-reboot` turns the reboot into exit code 0. A corrupted boot
  signature or a kernel with a bad checksum fails in seconds, with the loader's reason
  on the console, instead of waiting out the timeout.
- **ARM / AArch64:** semihosting, `-semihosting-config enable=on,target=native`, with
  `SYS_EXIT` and `ADP_Stopped_ApplicationExit`. Works identically on `armv7m`, where
  there is no other channel at all.
- **RISC-V:** the `sifive_test` MMIO finisher built into the `virt` machine (it is part
  of the machine, not a `-device`). Write `0x5555` to pass, `0x3333 | (code << 16)` to
  fail. A pass is QEMU exit status 0, the same asymmetry as semihosting: QEMU also exits
  0 for reasons of its own, and a guest that wrote `0x3333` with a code of 0 would pass.
  The harness treats a timeout as a failure; only the kernel's own `exit_emulator` writes
  the register, and it writes a code of 1 for a failure. A fatal trap on this port ends
  the run through the same channel, so a crash test finishes at once instead of timing
  out.

### Structured output

Two channels, never one:

- **Serial 0** — the human log. Whatever the kernel prints.
- **Serial 1** — the machine channel. A line protocol with a fixed prefix carrying test
  start/end, result, timing, and structured failure data.

Separating them means a test's verdict is never lost inside a burst of kernel logging,
and a kernel log line can never accidentally parse as a result. Level 1 and level 2
tests share the same line protocol, so one reporter renders both.

### Timeouts and hangs

Every test carries a wall-clock budget. On expiry the harness does not simply kill
QEMU — it first requests a state dump through the monitor, so a hang produces evidence
rather than silence:

```
-no-reboot -d int,guest_errors -D qemu.log
```

`-no-reboot` matters more than it looks: without it a triple fault reboots and the
kernel starts again, turning a crash into an infinite loop that reads as a timeout.
With it, the crash is the failure, with the fault visible in `qemu.log`.

Note the absence of `-no-shutdown`, which an earlier draft of this document
recommended alongside it. It is not a companion to `-no-reboot`: it keeps QEMU alive
across a guest shutdown, which suppresses `isa-debug-exit` and turns **every passing
test into a timeout**. It cost a debugging cycle to find, and it is the kind of flag
that looks obviously right.

### Determinism and replay

QEMU's instruction counting and record/replay make kernel races tractable, which is the
strongest single reason to be QEMU-first:

```
-icount shift=7,rr=record,rrfile=run.rr        # record
-icount shift=7,rr=replay,rrfile=run.rr        # replay, exactly
```

`-icount` decouples guest time from host time, so a test's timing does not depend on CI
load. Record/replay then makes a failing run **exactly reproducible**, including under
GDB — a scheduler race that appears once in five hundred runs can be captured and then
single-stepped as many times as needed. On real hardware that same bug is a week of
guessing.

Caveats, since this is not free: record/replay constrains which devices may be used,
does not compose with KVM, and slows execution. It is therefore on for nightly stress
runs and switched on for any test that has ever failed intermittently, not for the
whole matrix.

### Deliberate variation

QEMU lets us test configurations nobody owns hardware for, and we use that
aggressively rather than running one canonical machine:

- **`-machine virt,gic-version=2` and `gic-version=3`** on aarch64. The *same kernel
  image* must boot under both. This is the direct test of the runtime interrupt
  controller selection in [portability.md](portability.md#static-architecture-dynamic-devices) —
  the claim that architecture is static and devices are dynamic is validated here or
  nowhere.
- **`-smp 1, 2, 8, 64`** — the uniprocessor path is a real configuration, not a
  degenerate case, and 64 CPUs finds lock contention that 2 never will.
- **`-m`** from the target's minimum to generous — the frame allocator under pressure.
- **`-cpu`** varied deliberately, including old models on i686, so feature detection is
  tested rather than assumed. `-cpu max` alone would let "assume the feature exists"
  pass forever.
- **Missing devices and unusual memory maps**, to exercise the device framework's
  failure paths.

### Artifacts

Every failing run keeps: both serial logs, `qemu.log`, the exact QEMU argument vector,
the `.config`, the kernel image and its symbol bundle, a monitor state dump, and the
replay trace where one exists. A failure that cannot be investigated from CI output
alone is itself a harness bug.

### No automatic retries

A test that fails intermittently is **a bug, most likely a real race**. It is not
retried until green. It is recorded with `rr=record`, filed, and quarantined with an
owner. Auto-retry in a kernel test suite is a mechanism for converting genuine
concurrency bugs into invisible ones.

## What QEMU will not catch

The honest half of a QEMU-first strategy. These bug classes pass CI and fail on
silicon:

| Class | Why QEMU misses it | What we do instead |
|---|---|---|
| **Weak memory ordering** | TCG does not faithfully model aarch64's memory model; a missing barrier usually passes | Write the memory model down *before* the SMP work (an open question in [decisions.md](decisions.md#open-questions)); host-side model checking for lock-free code; explicit review for any barrier change |
| **Cache/DMA coherency** | QEMU's memory is coherent, so missing cache maintenance passes silently | Make cache operations explicit and typed, so omission is a compile error where possible; `HasCoherentDma` is a capability, never an assumption; debug-mode buffer poisoning |
| **Interrupt latency and timing** | `-icount` is deterministic, not realistic | The real-time guarantee question stays open until hardware exists; no latency claims are made from QEMU numbers |
| **Device errata and quirks** | QEMU models the specification; hardware deviates from it | Drivers cite the manual and revision they were written against, so the gap is at least locatable |
| **Firmware variation** | OVMF is one clean UEFI implementation; real firmware is neither | Keep `kinboot-efi` minimal and defensive; assume nothing the spec does not require |
| **Legacy BIOS reality** | SeaBIOS is not a 1998 BIOS | Acknowledged as the weakest coverage we have — see below |
| **Power management, suspend/resume** | Barely modelled | Deferred with the hardware |

Note the sharp edge in that table: **our most exotic target is the one QEMU validates
least well.** The i686 BIOS boot path exists precisely because real old machines
behave in ways modern ones do not, and SeaBIOS under QEMU is a clean, modern,
well-behaved BIOS. `kinboot-bios` will pass CI long before anyone knows whether it
boots a Pentium III.

What has been done about that under QEMU is to take, by force, every path SeaBIOS never
chooses:

- CHS reads in stage 1 and stage 2, including past cylinder 1;
- the E801 memory map instead of E820;
- A20 masked, recovered by each of the BIOS, the keyboard controller and port `0x92`
  in turn, and a masked A20 that nothing recovers, which must fail.

Each was a temporary mutation, not a test that runs in CI, and none of it substitutes
for the machine. The loader stays **unvalidated** until one boots it.

The consequence is a rule rather than a worry: code in these categories is marked
**unvalidated** in its module documentation until hardware has run it, and "CI is
green" is never cited as evidence of correctness for them.

## The hardware debt

Deferring hardware is a debt with a due date, and the roadmap names it: Phase 7 brings
up real machines for every tier-1 target. Until then we accumulate exactly the bug
classes above, and the longer we wait the more of them land at once.

Two things keep the debt serviceable:

- **Nothing in the design assumes QEMU.** No test may depend on an emulator-specific
  behaviour, and the harness abstracts "run this image and collect a result" so that a
  hardware runner drops in behind the same interface.
- **The first hardware bring-up is expected to be unpleasant**, and is scheduled as
  real work rather than a formality. A port that boots under QEMU is perhaps two thirds
  of the way to booting on the machine it models.

## Configuration coverage

The configuration space is too large to enumerate, so we sample it deliberately:

- **All presets, every merge.** The configurations we actually ship.
- **Boundary configurations** — everything off that can be off, everything on that can
  be on. Catches most "this config does not compile" bugs.
- **Randomized configurations, nightly.** `kbuild config --random --seed N` produces a
  valid configuration; build it. Failures are reported with their seed and so are
  reproducible. This is where the unbuildable-configuration bugs that plague
  `#ifdef`-based kernels would surface — and where we find out whether the trait
  approach really removed them.

### As built

- `kbuild randconfig-build --count K --seed S` builds `K` samples, one seed each
  (`S`, `S+1`, ...), each on a preset picked by its own seed.
- `--allyes` and `--allno` build every preset's boundary instead.
- A failure is printed with the command that rebuilds it, such as
  `kbuild build --preset i686-qemu --random --seed 1031`, and its log is kept under
  `build/randconfig/`.
- The generator is described in [build-system.md](build-system.md#generated-configurations).
  It never produces a configuration the resolver refuses. If one appears anyway, the
  report counts it separately as a kbuild bug, apart from configurations that resolve
  and do not build.
- The nightly workflow (`.github/workflows/nightly.yml`) runs both boundaries and 50
  random samples. Its seed comes from the run number, so every night draws a new sample.
- Random values stay within what a preset leaves free: the preset fixes the
  architecture, so a sample never asks for an architecture with no port.
- `int` and `hex` symbols are sampled only when they declare a `range`. The range is the
  only statement of which values are meant to work.

**What the first run found.** 36 of the first 50 random samples, and every `--allyes`
boundary, failed to build. None of that was a kernel bug. `MOCK_ARCH`, the switch that
compiles `hal`'s mock architectures for host tests, had a prompt, so the generator
treated it as a choice a person could make. Kernel images built with it failed in two
ways: the mocks' `extern crate std`, and a 64-bit shift in `hal/src/mock.rs` that is an
overflow on i686. The fix was to the declaration, not the kernel. `MOCK_ARCH` no longer
has a prompt, which in this language means "derived, not chosen"; `kbuild test` still
sets it. After that, all 50 samples (seed 1000) and all 14 boundary builds passed.

**What "builds" does not yet cover.** A sample is built, not booted. Several of the
symbols it varies select test modes that crash on purpose. `MM_FLAT` changes no unit on
the paged ports today, so a sample that picks it proves less than it seems to.
- **Pairwise coverage** over symbols known to interact (SMP × memory model × isolation
  × modules × `ABI_LINUX`), once exhaustive becomes impractical.

## Merge gates

A change may not land unless:

1. Every tier-1 target builds, every preset.
2. Host tests pass, and every host-testable unit compiles for the machines no port
   covers yet (`kbuild portability`).
3. In-kernel tests pass under QEMU for every tier-1 target.
4. Boot tests pass for every preset, including `gic-version` 2 and 3 on aarch64 and
   both `-smp 1` and multi-CPU where supported.
5. No new `unsafe` block lacks a `// SAFETY:` comment.
6. No `cfg` appears inside a function body or struct definition
   ([the rule](portability.md#where-cfg-is-still-allowed)).
7. Layering is not violated.
8. The size report does not regress beyond the configured budget.
9. From Phase 6b: the Linux compatibility corpus passes. Programs leave the corpus only
   by explicit decision, never by being quietly dropped when they break.

Gates 1, 3, and 4 are what make the portability claim real, and they are affordable
only because of `kbuild`'s content-addressed cache.

## Size budgets

Each preset declares a maximum image size in `config/presets/` as `SIZE_BUDGET_KIB`.
`kbuild size --preset P` builds the preset and reports every allocated section and
every crate against the budget and a baseline. It fails when the total exceeds the
budget.

```
$ kbuild size --preset x86_64-qemu --compare origin/master
  preset x86_64-qemu          budget 768 KiB
    .bss                          155,648       +0
    .rodata                        16,344      +18
    .text                         135,168     +312
    .thread_stacks                262,144       +0
    ...
    total                         591,180     +330   (75% of budget)
  crates (text + rodata + data + bss)
    arch                          118,691       +0   text 27,937, rodata 0, data 361, bss 90,393
    kintane                        83,546     +330   text 42,456, rodata 48, data 3,964, bss 37,078
    ...
```

- **What is measured:** the linked kernel ELF's allocated sections, `.bss` and the
  thread-stack array included, since that is what the machine must hold. The packaged
  image, whose size depends on the container, is not measured.
- **How crates are attributed:** each sized symbol (`llvm-nm --print-size --demangle`)
  is charged to the crate its demangled path starts in. A generic is charged to the
  crate that defines it, which is where the code to shrink lives. Assembly and
  unmangled symbols, and LLVM's anonymous constants, get rows of their own.
- **Which crates are listed:** the largest dozen, plus every crate whose size moved, so a
  regression is never hidden below the cut.
- **The baseline:** `config/size-baseline/<preset>.size`, a line-oriented report
  rewritten by `--update-baseline` and reviewed like any other diff. `--compare` takes
  another report file, or a git revision, whose committed baseline is read with
  `git show`, so comparing against `origin/master` needs no second build.
  - A baseline that drifts from reality only makes the deltas stale. The budget is the
    gate.
- **When budgets and baselines change:** whenever a change moves the kernel's size on
  purpose, in the same commit. Budgets were set with roughly 25–30% headroom over the
  size at the time.
- **CI:** every push and pull request runs `kbuild size` on every preset.
- **Falsified:** adding a 256 KiB static to `kmain` failed x86_64-qemu at 108% of its
  budget, with the growth attributed to `kintane`'s rodata.

A 300-byte regression on a Cortex-M matters and is invisible on x86_64. Tracking it
per-commit is the only way small targets stay viable, and it is what keeps "supports
microcontrollers" from quietly becoming false. The bootloader stages carry their own
budgets ([bootloader.md](bootloader.md#what-the-bootloader-must-not-do)), where stage 1
is hard-capped by the 440 bytes the MBR allows.

## Sanitizers and analysis

- **Debug builds** enable overflow checks, poison freed memory, add lock-order
  checking, and validate that sleeping functions are not called in atomic context — all
  as config options, so the checks can be enabled selectively in production too.
- **Address arithmetic is always checked**, in every build, because the failure mode is
  corruption rather than a wrong number.
- **Miri** on host tests for the `unsafe` portions that can run under it.
- **Model checking** for lock-free data structures on the host, since this is the one
  mitigation that genuinely substitutes for the weak-memory testing QEMU cannot do.
- **Fuzzing** from Phase 6 on every parser touching untrusted input: device tree, ELF,
  module loading, filesystem metadata, network packets, and the boot protocol's tags.
  Syscall argument fuzzing from the point an ABI exists.

## Debugging

- `kbuild run --gdb` starts QEMU stopped with a GDB stub and loads the symbol bundle.
- `kbuild run --replay <trace>` re-executes a recorded failure deterministically, with
  or without GDB attached.
- Panics print a symbolized backtrace resolved against the separately shipped symbols,
  so stripped production images stay debuggable. **This part exists.** A panic or a
  fatal CPU exception prints raw return addresses from a bounded frame-pointer walk
  (`lib/unwind`), and `kbuild run`, `kbuild test --target` and `kbuild symbolize`
  resolve them against `build/<target>/out/kintane.debug`. See
  [build-system.md](build-system.md#what-a-build-produces-today) for the format and the
  limits.

  The unwinder follows frame pointers on a stack that may be corrupt. It reads only
  inside the image's data, less the guard page. It stops on a null, misaligned,
  out-of-bounds or non-increasing frame pointer, and at 32 frames. Host tests drive it
  over synthetic stacks that are well formed, corrupt or looping. The live chain is
  checked on every boot (`backtrace  3 frames to null frame ok`): it must end at the null
  frame `_start` plants, with every return address inside `.text`.

  Every backtrace begins with `bt build <id>`, the image's build ID, and `kbuild symbolize`
  refuses a log whose ID is not its bundle's: decoded against another build's symbols, the
  addresses would turn into names that look right and are not. CI decodes a crash log from
  a release build against a debug build's bundle and requires the refusal.

  The `CRASH_TEST` configuration choice panics or takes an undefined instruction two
  calls deep. CI does both on all three architectures and requires the decoded report
  to name those functions. An exception report skips its own frames and prints the
  faulting instruction as `pc`. A fatal `#DF` on x86_64's IST stack has not been
  exercised. By construction its walk should stop right after `pc`, because the
  interrupted frames are on the boot stack, below the IST stack, and the walk refuses a
  frame pointer that decreases. A fault report halts rather than exiting the emulator,
  so under `kbuild run` it ends in a timeout, and the decoded backtrace is still printed.
- A crash-dump format and an offline decoder, so a report from a device in the field is
  readable with only the `.config` and the symbol bundle.

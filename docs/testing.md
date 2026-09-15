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

### The boot stack: its size and how deep the boot goes

Every boot prints a `bootstack` line and gates on it:

```
  bootstack  deepest 10688 of 16384 bytes (65%, limit 75%) ok
```

`kmain` paints the boot stack below its own frame before anything else runs, and after the
banner's checks and the in-kernel suite the line reports the lowest byte that no longer holds
the paint. More than 75% fails the boot while there is still room to act. The first boots
measured x86_64-qemu at 65% of 16 KiB, x86_64-isolated at 55% of 32 KiB, i686-qemu 55%,
aarch64-virt 48%, riscv32-virt, riscv32i-virt and armv7m-mps2 37%, and armv7m-tiny at 77% of its
12 KiB, which failed and now has 14 (66%).

An in-kernel test image goes deeper than the boot of the same preset, because the suite runs on
the boot stack too. `x86_64-iommu`'s reached 15,280 bytes, 93% of 16 KiB, and failed; the VT-d
and remapping checks are what take it there. `x86_64-qemu-smp`'s reached 72%. Both an IOMMU and
SMP now default the boot stack to 32 KiB, as `BLOCK_DOMAIN` already did, which puts those images
at 46% and 36%. The next deepest are `armv7m-tiny`'s at 70% of its 14 KiB — a 56 KiB board, so it
keeps what it has — and `x86_64-efistub`'s at 65%.

A stress image is deeper again, its setup running on the boot stack as well: `x86_64-qemu`'s
reached 77% and failed, and `i686-qemu`'s passed at 74%, one point short. `STRESS_TEST` therefore
defaults the boot stack to 32 KiB too. Each of these was found by the check itself during this
round's verification, which is the argument for having it: all three configurations were within a
kilobyte or two of the guard page, and nothing before this said so.

The size is checked twice. Each port's linker script asserts that `__stack_bottom` to
`__stack_top` is `BOOT_STACK_KIB` rounded up to a page, and kbuild refuses any linked kernel
where it is not, whatever its script says (`kbuild/src/bootstack.rs`, with host tests). The
default of 16 KiB cannot tell a port that honours the option from one that hard-codes 16 KiB,
so CI also builds every preset with `BOOT_STACK_KIB=20`.

| Mutation | What happened |
|---|---|
| aarch64's boot assembly and script back to the fixed 16 KiB, built with `BOOT_STACK_KIB=32` | kbuild refuses the image: `the kernel image reserves a 16384-byte boot stack (0x40323000..0x40327000), but BOOT_STACK_KIB asks for 32768 bytes` |
| aarch64's script reserves a fixed `16K` but keeps its assertion, built with 32 | the link fails: `the boot stack is not BOOT_STACK_KIB, rounded up to a page` |
| A 12 KiB array written on the boot stack just before the line, on `x86_64-qemu` | `deepest 14272 of 16384 bytes (87%, limit 75%) TOO DEEP`, and the boot fails |

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
- **Three failed boots fall back to safe mode, and a good boot clears the count.**
  `BOOT_COUNTER_TEST` on `x86_64-efistub` boots one machine without `-no-reboot`. Every
  boot the EFI stub did not fall back on fails on purpose and resets through
  `ResetSystem`. The run exits 33 only if all of these hold:
  - attempts 1 to 3 arrive in normal mode;
  - attempt 4 arrives in safe mode;
  - that boot's deletion of the count reads back as `EFI_NOT_FOUND`.

  CI also requires exactly three `failed on purpose` lines. See
  [bootloader.md](bootloader.md#as-built-the-efi-stub-counts-the-kernel-confirms).

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
| The kernel skips `SetVariable` when confirming | the read-back finds the count, `FAILED: the count still reads back after clearing`, exit 35 |
| The firmware call keeps the kernel's page tables (no `mov cr3`) | `#PF` inside the call; the run times out |
| The stub falls back one boot early | attempt 3 arrives in safe mode, `FAILED: not started in normal mode before the limit`, exit 35 |
| The stub never writes the count back | 40 boots in 150 s, every one attempt 1 and none in safe mode; the run times out |
| The stub counts but keeps the built mode | attempt 4 arrives in normal mode, `FAILED: past the limit, and not started in safe mode`, exit 35 |
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

**A program creating a program.** The `spawn` line (`kernel/main/src/spawn.rs`) runs on
the same presets, after the scheduled-processes check. The kernel starts one process,
`init` in its spawn mode, and hands it only a console handle and a handle to the bytes of
`user/child`. `init` is then refused two calls as the wrong kind of object and one for lack
of a right. It builds a process from the image, moves a channel endpoint into it, asks for
the child's exit on a completion queue, and starts the child's thread. While it waits for
the child's hello it also watches that queue, so a child that dies early is reported with
its own exit code folded in rather than as a parent waiting forever. The child tries six
handle values it was never given, each refused as a bad handle, then exchanges a message
and exits. The check requires `init`'s success code, and every object and frame back once
both processes are torn down:

```
  spawn      init created a process, gave it a channel, and waited for it; 0 objects left, 0 frames left ok
```

Falsified (each mutation on x86_64, applied, booted, then restored byte for byte by
`build/falsify.py`):

| Mutation | Result |
|---|---|
| `process_transfer` puts the handle back in the caller's table | the child's endpoint names nothing, its send fails, and `init` reports it: exit `0x43c02` |
| a process's exit is never posted to its waiter | `init` waits in `join` and never exits — the only honest symptom, since nothing can tell it |
| teardown retires none of the objects a process named | `4 OBJECTS LEAKED` |
| `vm_map_in` accepts `READ` where it needs `MAP` | mapping the image is not refused for lack of a right: exit `0x412` |
| the child's forged-handle step also tries its own real endpoint | a real handle is refused as the wrong type, not a bad handle, so the step is not vacuous: exit `0x43c05` |

The first version of `init` waited for the child's hello on the channel alone, and three of
these mutations showed only as a parent that never exited. Watching the completion queue
while waiting is what turned two of them into codes naming the fault.

**A channel outlives a lookup in flight.** The `channels` line
(`kernel/main/src/channels.rs`) runs after `spawn` and gates the verdict on the same presets.
It forces the race the seventh round's Phase 6a work named: two threads, one closing a channel
while the other is between finding it and using it. The kernel builds a process with one
channel. A second kernel thread looks the channel up by its first endpoint and holds what it
found. The boot thread then tears the process down, which closes both endpoints, and makes as
many new channels as there is room for, so that any storage the closed channel gave back now
holds another. Only then does the lookup thread ask the channel it holds whether its endpoint
is one of that channel's two. Every object must be gone once it lets go:

```
  channels   a lookup held across its channel's close still named it; 7 channels made in its place; 0 objects left ok
```

Seven, not eight: the closed channel still occupies its slot until the lookup lets go.

Shown failing on the code before channels became store objects — a kernel-wide table whose
slot the owner's teardown emptied — on `x86_64-qemu` and `aarch64-virt-smp`:

```
  channels   A CHANNEL WAS FREED UNDER A LOOKUP AND REUSED; 8 channels made in its place; 0 objects left ok
```

Falsified (applied, booted on `x86_64-qemu`, restored): a channel freed when its *first*
endpoint object is destroyed rather than its last gives that same line and fails the boot.

The interleaving is forced, not raced: at boot only the boot CPU schedules, so this proves
that a held lookup keeps its channel, not that two CPUs happen to collide.

**A wait for a process runs out on time.** In the `waits` line, `init` waits for its own
process with `process_wait` and no completion queue. That process cannot end while it waits,
so a zero timeout must answer `ShouldWait`, arming a queue with a timeout must be refused, and
a 30 ms wait must end in `TimedOut` no earlier than 30 ms and not long after. `spawn` joins its
child with a timeout. Falsified: a kernel that ignores the timeout fails `waits` within its
patience, as `init NEVER EXITED`, rather than hanging the boot.

**A thread spinning in user mode is stopped when its process ends.** The `sibling` line
(`kernel/main/src/sibling.rs`) runs after `waits` on the same presets. The kernel starts two
threads of `init` in one process. The second signals an event and then spins in user mode for
ever, with no system call; the first waits for the signal, waits 20 ms more, and exits. A
thread that neither calls nor waits can only be reached by interrupt. An exit sends a
reschedule IPI to every other CPU, and every scheduler interrupt that arrived in user mode
ends its thread on the way back if the thread's process has ended
(`hal::user::UserHooks::interrupted`, on x86_64 after the timer's and the reschedule IPI's
hook, on aarch64 after an IRQ from EL0). The check requires the success code, both threads
ended within 5 s, at least one thread ended from an interrupt, and every object and frame
back:

```
  sibling    a process ended under a thread spinning in user mode, and it stopped; 1 stopped from an interrupt; 0 objects left, 0 frames left ok
```

At boot only the boot CPU schedules, so there the spinner is reached when the scheduler
resumes it inside the timer interrupt that preempted it. In the stress run, every other audit
interval runs the same process with its two threads pinned to two CPUs, so the exit on one
must reach a thread spinning on the other. That cycle fails the run as `spinning sibling` if
the spinner is not stopped, if it ended other than by interrupt, or if a frame or object is
left.

Falsified (applied, booted on `x86_64-qemu`, restored): with the interrupt hook never ending
a thread, the line fails by the clock rather than hanging the boot:

```
  sibling    THE SPINNING THREAD WAS NEVER STOPPED; 0 stopped from an interrupt, NONE; A THREAD NEVER ENDED, its process left in place; 1 OBJECTS LEAKED, 14 FRAMES LEAKED
```

Over 20 s of stress on `x86_64-qemu-smp` and `aarch64-virt-smp`, ten spinning processes each
had their spinner, pinned to a CPU other than the exiting thread's, stopped from an interrupt.
One falsification did **not** fail. With the exit sending no reschedule IPI at all, the same
stress run still passed with ten spinners stopped. The stress run keeps every CPU busy, so the
spinner's CPU takes slice ticks, and the next tick stops it. The IPI is what reaches a spinner
on an otherwise idle CPU, and nothing here isolates that case yet. The stress cycle runs only
with two CPUs or more; one CPU is the boot check's case.

**The file server outlives the check that started it.** `waits` starts the kernel's standing
file server (`kernel/main/src/fileserver.rs`), and `init` reads `/HELLO.TXT` through a
connection to it. `waits` now also requires the server to have let go of that connection
before it counts objects. The `files` line runs after `sibling`, once `waits` has torn its
process down. It builds a second process, `init` in its files mode, gives it a new connection,
and requires the same file read back:

```
  files      a second process read /HELLO.TXT through the server after waits ended; the same server thread, 2 connections since boot, 7 requests answered; 0 objects left, 0 frames left ok
```

The line requires the success code, the same server thread still running, exactly one new
connection and at least two since boot, requests answered, the server's connection let go of,
and every object and frame back. Without a disk it is skipped, and only on a machine that
attached none.

Falsified (applied, booted on `x86_64-qemu`, restored): a server thread that exits once its
first connection closes serves `waits` and then fails this line as `the file server is NOT
RUNNING`.

The stress run's filesystem workload and the server share the volume through a lease, one
iteration or one request at a time. The server is idle during the stress run, so that sharing
is not exercised under load yet.

### 2b. Block storage

With `QEMU_BLOCK_TEST`, on by default on aarch64, x86_64 and i686 test builds, kbuild
writes `testdisk.img` beside the image. It is 79,144 sectors — about 39 MiB — in four regions:
4096 sectors in which every byte is a function of its sector and offset, with a header in
sector 0; a scratch area the write checks use; a FAT16 volume for the
[files check](#2e-files); and the FAT32 volume that follows it. Each run attaches a fresh
copy of it, written for real, which kbuild reads back after a passing run
([2e](#the-disk-image-after-a-run)), so the image kbuild built never changes: to a
`virtio-blk-device` in a memory-mapped
slot on aarch64, and to a modern-only `virtio-blk-pci` function on the PCs, through every boot
path they have (`-kernel`, BIOS and UEFI). The format is written twice, in
`kernel/block/src/testdisk.rs` and `kbuild/src/testdisk.rs`, and a pinned set of bytes
that both sides' tests assert keeps the two in step.

A PCI run without an IOMMU attaches a **second disk** as well, `testdisk2.img`, on its own
virtio-blk function and its own file — two `-drive`s on one image make QEMU refuse the run with
`Failed to get shared "write" lock`. It carries no volume: both volumes stay on the first disk,
so `FS_START` and `FS32_START` are unchanged. Its bytes are the same pattern with the disk's
index folded into the hash, so disk 0's image is untouched and a sector read from the wrong disk
matches nothing. The `block` line reports how many disks the boot bound, so a run that attached
two and bound one is visible there rather than only as a later check quietly skipping:

```
  block      2 disks bound; 79144 sectors of 512 bytes, 15 per request; 32 sectors read back
             the pattern; ...
```

The IOMMU presets and the memory-mapped transport still attach one, for the reasons given under
"A second disk" in [architecture.md](architecture.md).

The boot gates on the `block` line ([architecture.md](architecture.md#block--the-block-layer-and-the-first-driver-with-dma)):

```
  block      12544 sectors of 512 bytes, 23 per request; 32 sectors read back the pattern;
             a write read back after a flush; a read past the end refused; the device's own
             refusal was an error; 64 more requests, 0 in flight ok
```

After the serial check, the boot also gates on the `block irq` line, which proves the
disk's completions arrive by interrupt. The driver is put in interrupt-driven mode, where
a waiting caller never drains the ring itself, interrupts are enabled, and 32 reads must
each return the pattern with every completion collected in the handler and none polled:

```
  block irq  line 16, MSI-X; 32 requests, 32 completions in 32 interrupts, 0 polled ok
```

The interrupt differs by port:

- **x86_64** (`x86_64-qemu`, `x86_64-efi`, `x86_64-efistub`, `x86_64-qemu-smp`, `x86_64-iommu`):
  MSI-X entry 0 of QEMU's virtio-blk-pci function, delivered to the boot CPU's local APIC.
  Discovery reports `virtio-blk receives MSI-X entry 0 on line 16, vector 48`. On `x86_64-iommu`
  that entry is remapped through the IOMMU, and the `remap` line below proves it.
- **x86_64-bios**: the disk's interrupt pin. That run starts QEMU's function with `vectors=0`, so
  it has no MSI-X table, and discovery routes INTA# through the ACPI namespace's `_PRT`
  ([architecture.md](architecture.md#device--the-device-framework), "PCI interrupts"):
  `AML 276 nodes, _PIC(1), 5 pins routed; ... virtio-blk receives its pin through _PRT on GSI 22,
  level, active high, line 16`. The check reads the I/O APIC entry back and requires what the
  route asked for: the line's vector, the boot CPU, unmasked, the trigger and the polarity. It
  also requires the route QEMU's q35 gives a PCI pin: GSI 16 to 23, level-triggered, active high.

  ```
    block irq  line 16, INTx on GSI 22 level active high; 32 requests, 32 completions in 32 interrupts, 0 polled ok
  ```

  On x86_64, `block irq` fails if a test run's disk came up on anything else. A function with an
  MSI-X table must be on it, and one without must be on its routed pin. So falling back to
  polling cannot quietly turn these checks into skips.
- **i686**: the line firmware programmed into the PCI function, 11 under QEMU's `pc`, wired
  through the 8259A.
- **aarch64**: the slot's SPI.

A lost interrupt is a request that times out, which fails the check rather than hanging it.

After the secondary CPUs start, the `block cpu` line moves the disk's interrupt to CPU 1. It
repeats the reads from CPU 0 with CPU 0's interrupts masked, so only a handler running on CPU 1
can collect a completion. The platform counts which CPU each interrupt's handler ran on. Every
interrupt in the run must be on CPU 1 and none on CPU 0, and the interrupt is moved back
afterwards, pass or fail:

```
  block cpu  line 16 to CPU 1; 32 requests, 32 completions in 32 interrupts, 0 polled; taken on CPU 1: 32, on CPU 0: 0 ok
```

It runs on `x86_64-qemu-smp`. It skips where the interrupt is a line, which cannot be moved,
and where no second CPU is online. A kernel built with `SMP` whose QEMU has a second CPU that
is not online fails instead of skipping.

The driver's protocol is host-tested without QEMU:

- `virtio::fake::FakeDevice`, shared with virtio-net, walks the rings from the device's side
  at a different memory offset, and virtio-blk's `test_support::serve_block` answers
  virtio-blk requests against a RAM disk.
- The tests cover the handshake and every refusal in it, reads, writes, splits, a device
  error, a device that never answers, and a thousand requests with no descriptor lost.
- The queue's MSI-X vector is written after the reset and before the queue is enabled. A
  vector past the table fails bring-up, and an MSI-X interrupt collects completions without
  reading the status register.
- Beneath the driver, `device::msi` has its own tests:
  - capabilities decoded, including a reserved BAR refused;
  - MSI and MSI-X enabled through a configuration space that keeps read-only bits and records
    the order of writes;
  - an MSI-X table over a buffer that refuses a message to an unmasked entry and any entry past
    its end;
  - `Probe::claim_msi`, which grants a vector only where the platform delivers messages and
    only up to the table's size.

  `apic::msi` is tested for the address and data a message carries, including a destination
  above 255 being refused rather than truncated.

In a stress run two block workloads, `block` and `block B`, each write random runs of their
own half of the scratch area and read them back, read the untouched part against the
pattern, and flush. At every audit the driver must report nothing in flight and every
descriptor on the ring, and a run with a disk fails if the two were never outstanding at
once: the heartbeat's `peak in flight` must reach 2. Where the disk has an interrupt, the
run puts the driver in interrupt-driven mode throughout. Every audit fails the run if even
one completion was collected by polling, and the heartbeat reports `by interrupt` and
`polled`. On `x86_64-qemu-smp` at 8 CPUs for 60 s both block workloads ran on MSI-X:
82,177 requests, 130,271 completions by interrupt, 0 polled, 60 audits.

Letting a request wait with the lock released, rather than polling to completion under
it, roughly doubled what the disk serves under the same load. Requests in 20 s of guest
time in a stress run, all other workloads running, before (one request at a time, polled
under the lock) and after:

| Preset | Before | After | |
| --- | --- | --- | --- |
| aarch64-virt-smp, 4 CPUs, by interrupt | 27,501 (1,375/s) | 55,790 (2,790/s) | 2.0× |
| x86_64-qemu-smp, 8 CPUs, polled | 24,118 (1,206/s) | 35,917 (1,796/s) | 1.5× |

These are QEMU under TCG on one host, not a disk benchmark: they say the lock stopped
being the bottleneck, not how fast a disk is.

Falsified, each mutation confirmed applied, then restored:

| Mutation | Caught by |
| --- | --- |
| The PCI node's interrupt is its line plus one | i686: `virtio-blk receives on IRQ 12`, then `block irq` fails with a request timed out, its interrupt never arrived |
| `on_interrupt` never reads the clear-on-read ISR register | aarch64: the level-triggered line storms once interrupts are unmasked, and the boot times out at `interrupts` |
| `drain` marks the first request in flight, not the one the device named | the host test `a_completion_marks_the_request_it_names_not_the_first_one_in_flight` |
| The ring returns a chain's descriptors only when no other chain is outstanding | aarch64-virt-smp stress fails at 1 s: the ring fills and a block workload's read fails |
| A waiter drains the ring even in interrupt-driven mode | aarch64: `block irq` fails, 30 of 32 completions polled |
| Every device window mapped at its physical address as well as in the device window, on x86_64-efi with the virtio BAR at 768 GiB | the `live` line: `the kernel maps something in the USER HALF`, and the boot fails; `userspace` also refuses, as the backstop |
| The device window undone (base zero), the post-install check forced to pass and the `userproc` backstop disabled, BAR at 768 GiB | the boot fails: no `userspace` program exits, `processes` cannot build its workers and `spawn`'s init never exits. The shared table breaks process construction outright rather than reproducing the old cross-read |

**Not observable on i686:** the block-irq mutation passes there. On QEMU's `pc` the device
completes and interrupts before the waiter first looks, so the handler always wins. The
check is sound, and aarch64 proves it catches polling, but on i686 it cannot distinguish
the two.

**The machine that broke runs as it broke.** x86_64-efi used to run with `-cpu max,phys-bits=36`
so OVMF would place its 64-bit PCI window below 64 GiB. It now runs at TCG's full 40 bits on
purpose: the virtio BAR lands at `0xc020000000`, 768 GiB, inside the user half's physical range,
and every boot requires `user half clear` on the live tables with the BAR mapped in the device
window above it. aarch64's enforcement probe also checks that the UART is writable in the
window and faults with a translation fault at its physical address.

The MSI-X path on the PCs was falsified the same way, each mutation confirmed applied, then
restored. Every mutation fails a check, and every boot still completes:

| Mutation | Caught by |
| --- | --- |
| The MSI-X entry's data names the next line's vector, 49 | x86_64-qemu: discovery reports `vector 49`, and `block irq` fails on its first request, which timed out because its interrupt never arrived. The delivery is counted as unhandled |
| The MSI-X entry is left masked | x86_64-qemu: `block irq` fails, a request timed out |
| A secondary CPU's message names an APIC ID no CPU has | x86_64-qemu-smp: `block irq` passes on CPU 0, then `block cpu` fails: a request timed out and CPU 1 took 0 interrupts |
| The interrupt is routed to CPU 2 while the check counts CPU 1 | x86_64-qemu-smp: `block cpu` fails with `taken on CPU 1: 0`, although all 32 completions arrived by interrupt |
| No EOI for a message-signalled line | x86_64-qemu: `clock` fails first, with 0 timer interrupts. The local APIC's in-service bit for vector 48, left set by an MSI raised during bring-up's polled requests, holds off every lower-priority vector, the ISA timer's among them. Then `block irq` fails with a request timed out |
| The queue is given no vector | x86_64-qemu: `block irq` fails, a request timed out |
| MSI-X left disabled, as QEMU leaves it | x86_64-qemu: `block irq` fails, a request timed out |
| QEMU's function has no MSI-X table (`vectors=0`) | x86_64-qemu: discovery falls back to the line and leaves the disk polled, and `block irq` fails with `THE DISK IS NOT ON MSI-X, THOUGH QEMU'S FUNCTION HAS IT` |
| A stress run leaves the driver polling | x86_64-qemu-smp stress fails an audit: `a completion was collected by polling in a run driven by interrupts` |
| `on_interrupt` reads the ISR register under MSI-X | the host test `an_msix_interrupt_collects_completions_without_asking_the_status_register` |

**Not observable on QEMU:** the last mutation passes every boot. QEMU sets the ISR bit even
when it delivers a queue interrupt by MSI-X, which virtio 1.1 allows a device not to do. Only
the host test's device, which leaves the bit clear, shows the handler dropping completions.

The `vectors=0` row predates INTx routing. Back then, a function without MSI-X fell back to its
line and was left polled. Before the guard moved into `block irq`, the same mutation failed
discovery itself, and the boot halted until kbuild's timeout instead of reporting a check. A
function without an MSI-X table is now expected on its pin through `_PRT`, and that is what
`x86_64-bios` runs. Its falsifications, each confirmed applied and then restored:

| Mutation | Caught by |
| --- | --- |
| The route's GSI is one past the one `_PRT` gave | x86_64-bios: `block irq  line 16, INTx on GSI 23 level active high`, then the first read waits for an interrupt nothing raises, and kbuild's 60 s timeout fails the run |
| The I/O APIC entry is programmed with the opposite polarity | `THE I/O APIC ENTRY HAS THE WRONG POLARITY` |
| The link device's `_CRS` is decoded with the opposite polarity | `INTx on GSI 22 level active low: NOT THE ROUTE QEMU'S Q35 GIVES A PCI PIN`. The AML host tests fail too |
| No route is kept, so the disk polls | discovery reports `0 pins routed`, and `block irq` fails with `THE DISK HAS NO MSI-X AND IS NOT ON ITS PIN THROUGH _PRT` |

**Polarity is not observable in delivery on QEMU.** Its I/O APIC ignores the polarity bit, so
an entry with the wrong one still delivers. That is why the check compares the entry with the
route, and the route with q35's known wiring. It is also why host tests pin the AML decode
against the captured DSDTs.

### 2c. Driver isolation

On aarch64, with `DRIVER_ISOLATION` (on by default there), every boot runs Phase 5's
prototype and gates on its `isolation` line; [isolation.md](isolation.md) covers the design
and the costs. One driver body, `drivers/virtio-probe`, reads an unoccupied `virtio,mmio`
slot's identification registers twice: once in the kernel, and once inside an unprivileged
domain whose address space holds its program, its stack, a report page and that one window.

```
  isolation  kernel read device 0, vendor 1431127377; the domain read the same; past its grant: killed; an identification 732 ns in the kernel, 673 ns in the domain; a domain's start, run and teardown 6370 us; 0 frames left
```

The boot fails if any of these happens:

- the domain's registers differ from the kernel's;
- a domain that should succeed does not, including each timed run;
- a domain's window translates, in its own page tables, to any page but the one the platform
  recorded;
- a domain whose window is not a virtio device reports instead of refusing;
- a domain that reads the page after its grant is not killed;
- a frame is left behind.

Each was falsified: the mutation was asserted to apply, the boot observed, and the file
restored byte for byte.

| Mutation | Result |
|---|---|
| Grant the neighbouring empty slot | before the grant audit existed, **the check passed**; see below. With it: `the domain's window maps a page other than the one the platform recorded` |
| Grant the PL011's page instead of a slot | `the domain's probe refused its window: it holds no virtio device` |
| Do not give the report page back on teardown | `7 FRAMES LEAKED`, one per domain run |
| Grant a second page, so the read past the window lands inside the grant | `PAST ITS GRANT: NOT STOPPED` |

**The first mutation is why the grant audit exists.** Every unoccupied slot answers
byte-identical identification registers, so a domain granted the wrong empty slot read what
the kernel read, and matching registers passed it. Register values prove the domain did not
invent an answer, not which window it read; only walking its page tables says that.

The proxy layer and the driver body are also host-tested. `lib/hwproxy` checks bounds,
alignment and silent refusal across all four widths. `drivers/virtio-probe` checks register
offsets, an empty slot, non-virtio memory, a window too small to read, and the report's
wire format round trip. The falsifications above were run by hand; nothing in CI mutates
the code.

### 2c-bis. DMA confinement with the IOMMU

On x86_64 with `IOMMU` (the `x86_64-iommu` preset), the disk runs behind an Intel VT-d IOMMU:
a translation domain that maps *exactly* its DMA grant. The `iommu` line gates the boot:

```
  iommu      in-grant DMA served behind VT-d; a page the device used was unmapped and flushed; out-of-grant DMA stopped at 0x00000000002a9000 from 0x0000000000000010; restarted and served a read ok
```

The `block` line first shows the device brought up behind the IOMMU (`VT-d on, 48-bit; disk
00:03.0 mapped to its grant only`) and passes every functional check with its DMA translated —
that is the in-grant DMA working. Then the `iommu` line requires all of:

- a translation the device used is taken away: the canary is mapped into the domain, the device
  reads a sector into it and the sector arrives, and the canary is unmapped with a page-selective
  flush through the invalidation queue. QEMU's unit caches the translation, so without the flush the
  rogue DMA below would reach the canary;
- the domain maps the grant and does **not** map the canary frame beside it (map exactly the grant);
- a deliberate out-of-grant DMA (a read into the canary) is stopped, and the unit's fault log names
  the canary's address and the disk's own source id `00:03.0`;
- the canary still holds its sentinel — the blocked write never landed;
- the faulted device is reset, brought up again over the same grant, and serves a read.

| Mutation | Result |
|---|---|
| Grant one extra page, so the canary is inside the grant | `THE DOMAIN DOES NOT MAP EXACTLY THE GRANT` |
| Skip mapping the grant into the domain | the device faults reading its own ring; the block check fails |
| Drop the restart | the device is not re-stored; `restarted and served a read` never prints and the boot fails |
| `unmap_in_use` skips its flush | `THE ROGUE DMA WAS NOT STOPPED; THE CANARY WAS OVERWRITTEN`: the device used its cached translation |

`drivers/iommu/vtd` and `boot/acpi::dmar` are host-tested under every preset: the DMAR fixture
(`q35-iommu.bin`) and the register programming, page tables, attach and fault decode against
models of the hardware. The live falsifications above were run by hand.

**Interrupt remapping.** On the same preset the disk's MSI-X goes through the unit's interrupt
remapping table. QEMU runs with `intel-iommu,intremap=on,eim=on`; `eim=on` because `auto`
turns extended interrupt mode on only with an in-kernel irqchip. The `block` line reports
`interrupts remapped, 32-bit destinations`, and `block irq` runs with the disk's message naming
entry 0. The `remap` line gates the boot, and every other preset reports it skipped:

```
  remap      remappable MSI-X through entry 0; 32 requests, 32 completions in 32 interrupts, 0 polled; entry absent: blocked, fault 0x22 from 0x10; entry for another function: blocked, fault 0x26 from 0x10; entry to x2APIC ID 256: not taken by the boot CPU; 6 entry-cache flushes completed in 6 waits; 256 entry changes flushed below the boot clock's resolution (longest wait 1 status reads); restored; 32 requests, 32 completions in 32 interrupts, 0 polled ok
```

(The two fault fields are printed at 64-bit width.) The check requires the disk's MSI-X entry to
hold a remappable-format message naming entry 0, remapping to be on, and the entry to be the
disk's, for its line's vector on the boot CPU. Then, with interrupts enabled:

- every read by interrupt completes;
- with the entry absent, a read that completes by polling takes no interrupt, and the fault log
  holds an interrupt-remapping fault from the disk for entry 0. QEMU records reason 0x22, entry
  not present;
- the same with the entry present but validating another function (the disk's function 1).
  QEMU records 0x26, invalid source id;
- with the entry delivering to x2APIC ID 256, the boot CPU takes nothing. Cut to the eight bits
  a compatibility-format message holds, that ID is the boot CPU's 0;
- every one of those six changes to the entry in use was followed by an interrupt entry cache flush
  the unit completed, counted by the queue's wait descriptors;
- restored, every read by interrupt completes again.

| Mutation | Result |
|---|---|
| The disk's message names entry 1, which is absent | `block irq  line 16, MSI-X` and its first read waits for an interrupt that is blocked, so kbuild's 60 s timeout fails the run |
| "Absent" leaves the entry present | `entry absent: THE INTERRUPT WAS DELIVERED` |
| "Another function" writes the disk's own source id | `entry for another function: THE INTERRUPT WAS DELIVERED` |
| Extended destinations are cut to eight bits when encoded | `entry to x2APIC ID 256: DELIVERED TO THE BOOT CPU: THE DESTINATION WAS CUT TO EIGHT BITS`, and the `vtd` host tests fail |
| `set_irte` skips the entry cache flush | `AN ENTRY CHANGED IN USE WAS NOT FLUSHED`, and `qi::tests::changing_an_interrupt_entry_in_use_flushes_the_entry_cache` fails on the stale entry its model delivers |

**Not shown in a guest:** delivery to a CPU whose x2APIC ID is above 255, or a stale interrupt
entry. The first needs a topology of at least 257 possible CPUs, which the kernel's ACPI discovery
does not describe (isolation.md, "What it does not prove"); the check shows the 32-bit destination
is carried whole, not truncated onto CPU 0, and the `vtd` host tests show it encoded. The second
needs an entry cache, which QEMU does not keep for an emulated device; the host tests' model does.

On `x86_64-isolated-smp`, `block cpu` moves the disk's remapped interrupt to CPU 1 by rewriting its
table entry, with the entry's cache flushed, and requires all 32 completions taken there:

```
  block cpu  line 16 to CPU 1 through its remapping entry; 32 requests, 32 completions in 32 interrupts, 0 polled; taken on CPU 1: 32, on CPU 0: 0 ok
```

### 2c-ter. The disk's driver in a domain

On x86_64 with `BLOCK_DOMAIN` (the `x86_64-isolated` preset), the disk's driver runs in an
unprivileged ring-3 domain confined by VT-d, not in the kernel. Once the scheduler is up, the
`blk domain` line hands the disk to `user/blkdomain`, serves the block check from the kernel over a
channel, delivers the disk's MSI-X interrupt to the domain as a message, and gates the boot on the
whole thing; [isolation.md](isolation.md#running-the-driver-in-a-domain-x86_64) covers the design
and the costs. The same driver source, `virtio-blk-core`, is what the in-kernel `x86_64-iommu` build
runs — both are in CI.

```
  blk domain 12544 sectors of 512 bytes, 15 per request, in a domain; 32 sectors read back the pattern; a write read back after a flush; the device's own refusal was an error; 73 requests, 73 completions in 73 interrupt messages (42008 ns mean, 579930 ns worst forward); the domain's out-of-grant DMA stopped at 0x00000000004ff000 from 0x0000000000000010; a faulting domain was killed, disk marked failed; a new domain served a read; restarted and served a read; disk back in the kernel
```

The boot fails if any of these happens: the domain cannot bring the disk up; a read, write, flush or
the device's own refusal comes back wrong; a completion arrives without an interrupt message or a
descriptor leaks; the domain's out-of-grant DMA is not stopped and logged, or its target is touched;
a faulting domain is not killed; or a fresh domain does not serve a read after it.

| Mutation | Result |
|---|---|
| Grant the domain the wrong register window | `the domain could not bring the disk up` |
| Acknowledge the interrupt but do not forward it | `reading sector 0 in the domain FAILED` — every read times out with no message |
| Skip the restart's read after the faulting domain is killed | `THE NEW DOMAIN DID NOT SERVE A READ` |
| Aim the rogue DMA inside the grant (an over-broad grant) | `THE IOMMU DOMAIN DOES NOT MAP EXACTLY THE GRANT` |

Each run also requires every interrupt the platform dispatched on the disk's line while a domain
owned it to have been forwarded (`73 interrupts taken, 73 forwarded`).

The wire types between the kernel and the domain (`virtio_blk_core::domain`: `Setup`, `Request`,
`Reply`, `Facts`, `Interrupt`) are host-tested for their encode/decode round trips. The live
falsifications above were run by hand.

**On four CPUs.** `x86_64-isolated-smp` runs the same boot checks, then, once `persist` has given
the scheduler every CPU, `blk smp` runs the domain checks with the client pinned to CPU 0, the disk's
interrupt on CPU 1, the domain pinned to CPU 2 and its replacement after the fault to CPU 3. A test
image on this preset reports its verdict only after `blk smp`; a stress image runs it before the
stress run and stops if it fails.

```
  blk smp    client on CPU 0, interrupt on CPU 1; an entry change flushed in 4452 ns; 12544 sectors of 512 bytes, 15 per request, in a domain; 32 sectors read back the pattern; a write read back after a flush; the device's own refusal was an error; 73 requests, 73 completions in 73 interrupt messages (419359 ns mean, 4071097 ns worst forward); 73 interrupts taken, 73 forwarded; the domain ran on CPU 2; the domain's out-of-grant DMA stopped at 0x00000000005d9000 from 0x0000000000000010; a faulting domain was killed, disk marked failed; a new domain served a read; the new domain ran on CPU 3; restarted and served a read; disk back in the kernel; interrupts taken on CPU 1: 75, elsewhere: 0 ok
```

It fails if anything `blk domain` requires fails, if a domain did not enter user mode on the CPU it
was pinned to, or if an interrupt of the run was taken anywhere but CPU 1.

| Mutation | Result |
|---|---|
| The handler drops an interrupt taken while the forwarder sends, with the forwarder holding its send 3 ms to force the overlap | `blk domain` passes, its one scheduling CPU never overlapping them; `blk smp` fails: `reading ... FAILED`, `2 interrupts taken, 1 forwarded; AN INTERRUPT WAS TAKEN BUT NEVER FORWARDED` |

### 2d. Fuzzing

Every parser that reads bytes the kernel did not write is fuzzed on the host, and so is
system call dispatch. The harness is `lib/fuzz`, one table of targets that `kbuild fuzz`
lists, the nightly job iterates, and the smoke run replays:

| Target | What it reads | How inputs are made |
|---|---|---|
| `fdt` | device tree blobs | seeded: QEMU `virt` and the device model's tree, mutated |
| `acpi` | ACPI tables | seeded: QEMU `q35` and `pc` captures, mutated, checksums repaired half the time |
| `aml` | DSDT and SSDT bytecode, loaded and run as the kernel routes pins | seeded: QEMU `q35` and `pc` DSDTs, body mutated, checksum always repaired; `\_PIC(1)`, pin routes, and every method under a 5000-step budget |
| `elf` | static executables | built valid, then one deliberate mistake a third of the time |
| `module` | relocatable modules and their bundle | seeded: a module kbuild built, sometimes bundled |
| `fat` | FAT16 **and FAT32** volumes, and every write the driver makes to one | seeded: a script that uses every operation; an image mounted, walked, read and written, which must walk clean after writes if it did before; or an operation script run against a model of every file, walked after each operation and replayed at every cut point. A bit of the input's mode byte picks the format, so both are reachable by mutation, and two of the four names the scripts use are long ones |
| `bootproto` | the boot protocol's tag stream | built with the crate's own `Builder`, then corrupted |
| `menu` | the boot menu's entry list, and the menu it drives | built valid, then one mistake a person makes |
| `pci` | configuration space, as devices answer enumeration | a machine with bridges and buses laid out on purpose |
| `virtio-ring` | a used ring, as a hostile device writes it | a device script: heads, lengths, index jumps |
| `net` | Ethernet frames carrying ARP, IPv4, ICMP, UDP and TCP, and the stack given one with a TCP listener open, then its timers run | seeded: an ARP reply, an echo request, a datagram and a TCP SYN for the listener, with correct checksums; or built with the stack's own writers; then mutated |
| `syscall` | numbers and argument registers | drawn from `abi::TABLE`, so a new call is fuzzed without a new target |
| `dirent` | the records `getdents64` packs into a program's buffer | a name of up to 255 bytes, a buffer usually within four bytes of the record's own length, and an offset the input invents |

A target's `run` must answer every input: a value or an error, never a panic, never a
hang. The driver runs each input on a worker thread under `catch_unwind` and waits for it
with a deadline, so a panic and a loop are both failures, reported with the seed and
iteration that produced them. Out-of-bounds reads are panics in Rust, which makes them the
first rule rather than a third.

```
$ kbuild fuzz --preset x86_64-qemu --iterations 5000 --seed 3
fdt          5000 iterations, seed 3, 1.0s, 971 accepted (19.4%), no failures
acpi         5000 iterations, seed 3, 2.3s, 4018 accepted (80.4%), no failures
elf          5000 iterations, seed 3, 0.1s, 2153 accepted (43.1%), no failures
...
```

**Reproducing a failure.** The failing input is shrunk and written to
`lib/fuzz/corpus/<target>/crash-<hash>.bin`, with a note beside it naming the seed, the
iteration and the message. `kbuild fuzz --target <t> --file <path>` runs that one input.
Committing the file makes it a permanent regression test: `kbuild fuzz --smoke` replays
the whole corpus, and CI runs it on every change. A panic is shrunk; a hang is saved as
found, because every shrink attempt at a hang would wait out the whole budget.

**The `fat` target's second format, over a sparse disk.** A volume is FAT32 by its cluster count
and nothing else, and the specification's boundary is 65,525 clusters — so the smallest honest
FAT32 volume is about 34 MiB, against the FAT16 one's 2.1 MiB, and the script mode clones the base
image again at every cut point it replays, up to 48 of them. Held densely that is more memory than
the whole campaign is worth. So the target's disk is sparse: a `BTreeMap` of only the sectors
something has written, with an absent sector reading as zeros. The driver sees a full-size volume;
the fuzzer stores a few dozen kilobytes. Two seeds keep both formats reachable without relying on
a mutation to flip the mode bit — `seed-fat32-script.bin` (97 bytes) and `seed-fat32-image.bin`
(16,897 bytes, trimmed from 542 KB).

**Two ways this could have passed while testing nothing**, both closed:

- A FAT32 volume built with the wrong geometry is **FAT16 to every reader**. Nothing would have
  failed: every "FAT32" input would have quietly exercised FAT16 a second time and passed. The
  host test `the_second_format_mounts_as_fat32` asserts the volume the generator builds really
  mounts as FAT32, and falsifying it — pushing the cluster count just below the boundary — failed
  both it and `a_script_runs_on_either_format`, which is what a real geometry mistake would look
  like. This is the one failure a fuzz target cannot report about itself, since a target that
  tests the wrong thing still answers every input.
- The stress run's FAT32 half could have been skipped silently, since the boot line naming the
  second volume is printed *before* the run and so proves nothing. What settles it is the image
  afterwards ([2e](#2e-files)).

**Why structure-aware, and not coverage-guided.** Coverage guidance needs the compiler to
instrument every branch and a runtime to read the counters; kbuild drives `rustc`
directly, the kernel crates are `no_std`, and neither is available. Random bytes without
it spend their budget failing the first length check. So each generator knows the shape of
what it makes, and the driver reports how many inputs got past the parser's top-level
check. That number is the honest measure of whether a campaign tested a parser or only its
rejection of garbage, and a host test requires the built generators to beat random bytes by
a wide margin.

**What the acceptance rate found.** The first campaign ran 45,000 inputs with no failures,
and that result was worth almost nothing:

| Target | First version | Now | Why |
|---|---|---|---|
| `elf` | 0% | 43% | the generator wrote `e_phentsize` and `e_phnum` two bytes late, so every file failed the first header check |
| `acpi` | 0% | 80% | the seeds are address/length records, not flat memory; no RSDP was ever found |
| `menu` | 5% | 40% | every line was drawn from lists half made of mistakes, so nearly every file had several |

**What falsification found.** Each check was broken on purpose, confirmed to fail, and
restored byte for byte:

| Mutation | Result |
|---|---|
| a panic planted in `boot_protocol::tags::parse` | caught at iteration 9; `--smoke` then failed on the saved input, and passed once the parser was restored |
| an infinite loop planted in `Config::parse` | caught by the watchdog at iteration 0, input saved unshrunk |
| `abi::dispatch` sends an unknown number to a handler | caught at iteration 1, shrunk from 450 to 112 bytes |
| `pci::enumerate` records an impossible parent | **not caught in 20,000 inputs** by the first generator, which never built a bridge with a device behind it; caught at iteration 0 by the rewritten one, shrunk from 1336 to 320 bytes |

Two defects were the harness's own. The virtio target built the device's view of the used
ring at an address it recomputed, ignoring the alignment padding `Dma::take` adds; its
writes landed misaligned and were refused, which the first run reported as a driver
failure. And the driver waited for each worker by polling every millisecond, which put a
floor under every input: all nine targets ran at the same ~800 inputs a second, whatever
their parser cost. A channel receive with a timeout made the cheap targets about sixty
times faster.

**No parser in the kernel has panicked or hung** on any input so far. That is a statement
about the inputs these generators make, not a proof.

**CI.** Every change replays the corpus and runs 200 inputs per target from a fixed seed.
Nightly, every target runs a million inputs from a seed that changes each night, and any
failing input is uploaded so it can be committed.

**Not covered.** In-guest system call fuzzing: the host target proves dispatch refuses
unknown numbers and decodes arguments before a handler runs, but "never faults the kernel"
and "never leaks kernel memory" depend on the real copy-in and copy-out paths, which only a
fuzzing user program against a booted kernel can exercise. Filesystem metadata joins the
table when that parser exists. Network frames are the `net` target.

### 2e. Files

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
same time. It also writes: `/SUB/STRESS.TMP` grows by appends of its own bytes, is read back
against them, is cut short once it passes 24 KB, and is removed and made again, with a sync at the
end of every iteration. It writes the **second volume** too, `/FAT32/SUB32/STRESS.TMP` by the same
appends, read-backs, truncation and removal, under the same lease, so the FAT32 driver is exercised
by a workload racing the block workload rather than only by host tests. The audit requires every
handle closed, the cache's books balanced with no block left unwritten, and the volume's
consistency walk to find no lost cluster and the two tables the same — and, on the second volume,
that its FSInfo free count is what its table says, since the workload syncs and a synced volume has
no excuse for disagreeing.

That the FAT32 half runs at all is checked by the image afterwards, not by the boot line naming the
second volume, which is printed before the run and so proves nothing: the image holds four files
where kbuild wrote three, and 13 fewer free clusters.

`vfs`, `bcache` and `fat` are host-tested (20, 18 and 37 tests, the last of them against FAT32 volumes as well as FAT16). The FAT tests build their volumes
with a writer of their own, independent of kbuild's, or format them empty and fill them through
the driver itself. `vfsproto` has 8 host tests, and kbuild's own FAT reader, disk check and crash
test have theirs among kbuild's.

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

#### Writing

On the same presets with userspace, two checks write the volume and gate the boot.

- **`files write`**, right after `files`. `init` is given two connections to the file server, one
  writable and one not. Through the first it creates `/KINTANE/NWTMP.TXT` exclusively, writes
  1,200 bytes a message at a time and reads them back, truncates to 90 bytes and reads those, is
  refused a second exclusive create, makes a directory once, renames the file, removes both, is
  refused a write on a file it opened to read, and leaves `/KINTANE/NATIVE.OUT`, synced. Through the
  read-only connection a `mkdir` and an open for writing are both refused. Then the kernel reads
  the volume itself: `NATIVE.OUT` holds exactly its bytes, the names it removed are gone, nothing is
  waiting in the cache, and the consistency walk finds no lost cluster and the tables the same.
- **The `linux` check** runs `linux-hello` a third time, in its `files` mode, which does the same
  through Linux's calls: `openat` with `O_CREAT|O_EXCL`, `O_APPEND` and `O_TRUNC`, `write`,
  `lseek`, `fstat`, `ftruncate`, `mkdirat`, `renameat`, which moves a name between two directories of one filesystem,
  `unlinkat` with and without `AT_REMOVEDIR`, `fsync`, and `ENAMETOOLONG` for a name FAT cannot
  hold. On x86_64 `/KINTANE/LINUX.OUT` is made with `open`. It exits 50, or the step (80 to 96)
  that was wrong; the check requires 50, reads the file back, and walks the volume.

```
  files write init: wrote the disk through the file service; created, wrote, read back, truncated, renamed and removed through a writable connection; refused through a read-only one; /KINTANE/NATIVE.OUT read back, the volume consistent: 7 files, 2 directories, no lost cluster, the tables the same; the same server thread; 0 objects left, 0 frames left ok
```

#### Long names

The `fat` host tests cover the pieces against the format's own arithmetic — the checksum over the
short name, the one-based ordinals and the bit marking the entry that holds the end of the name,
the two bits recording whether each half of a short name was written in lower case — and the
driver against what a caller sees: a long name is written and read back, its alias is a name of
its own that never takes one something else answers to, a name the driver will not write is
refused rather than shortened, and a long name survives a rename and a move between directories.

One of them counts the directory's entries in the image rather than asking the driver, because
**every other check passes with a leaked set still on the disk**: a long set whose short entry
is gone lists as nothing, answers to no name, and holds no cluster, so the listing, the lookups
and the consistency walk are all satisfied by it. Deleting only the short entry was not caught
until the test counted entries before the name was made and after it was removed.

In a boot, `linux-hello`'s files mode makes `/KINTANE/NOT.AN.83` — a name no short entry can hold
— opens it again by the name it was made with, and removes it, before the step whose `fsync`
makes all of that durable. Before that same `fsync` it carries a long name through a whole life:
created with `openat`, renamed with `renameat` onto *another* long name, reopened by the new name,
and removed with `unlinkat`. The ordering is not incidental — anything that writes must happen
before the step that syncs, or the walk that follows finds the volume dirty and the boot fails;
steps that only ask may follow it. What must still be refused is a component longer than the
namespace holds, which creates nothing, and a name the driver will not write, which reaches the
program as `ENAMETOOLONG` rather than as a shortened name.

**A Linux program lists a long name as itself.** `getdents64` answers on both architectures
([userspace-abi.md](userspace-abi.md#as-built--static-programs-x86_64-and-aarch64)). Steps 230 to
239 of the files mode make a long name and a directory beside it, list `/KINTANE` in 128-byte
pieces, and require all of: the long name present and never the short alias it also answers to;
`LSDIR` carrying `DT_DIR` where the long name carries `DT_REG`; no entry seen twice across the
pieces and none lost between them; a buffer too small for even one record refused with `EINVAL`,
rather than the zero a caller would read as the end of the directory; and a listing rewound with
`lseek` reproducing its first batch. The steps write, so they run before the step that syncs, and
they make and remove their own names rather than looking for a name an earlier step removed.

The `dirent` fuzz target reads the packing itself, where the program's buffer length meets the
volume's name: 200,000 inputs at seed 7, 43.4% of them packing a record rather than being turned
away, no failures. It asserts that a record never reaches past the buffer it was given, that its
length leaves the next record aligned and is the `d_reclen` the header claims, that the inode, the
offset and the name come back as they went in with the name terminated, that the padding is written
rather than left as whatever the buffer held, and that a name the format cannot carry — an empty
one, or one holding a NUL — is refused outright rather than packed into something a reader would
stop early in.

| Mutation | What catches it |
|---|---|
| Deleting only the short entry, leaving the long ones | `removing_a_long_name_frees_every_entry_of_its_set`, by the entry count; nothing else |
| An alias that ignores what the directory already holds | `an_alias_never_takes_a_name_something_else_answers_to` |
| A name with a reserved character, or a trailing dot, written rather than refused | `a_name_this_driver_will_not_write_is_refused`, and the boot's step 96 |
| `fstatfs` answers for the filesystem at the root instead of the one its descriptor's file is on | the `linux` check: files mode exited **`0xc6`**, step 198, and the boot failed `rc=1`; restored, it exits `0x32` and the boot passes |
| A long name listed as the short alias it also answers to (`fat`'s `readdir` reporting the short entry) | files mode exited **`0xeb`**, step 235, and the guest exited 35 rather than 33 |
| A record that does not fit consumed anyway, so an entry is lost between two calls | files mode exited **`0xec`**, step 236, and the guest exited 35 |
| A directory carrying a regular file's `d_type` | files mode exited **`0xec`**, step 236, and the guest exited 35 |
| A Linux `statfs` answer overstating the free count by 64 clusters | **the program still exited `0x32`** — its own steps cannot catch a fabricated number — and the kernel's walk failed the boot with `THE PROGRAM WAS TOLD SOMETHING ELSE ABOUT /`, the guest exiting 35 |

#### What the volumes say they are

- **`files size`**, right after `files write`. `init` asks the file server what the filesystem
  covering `/` is, and what covers `/FAT32`, through `statfs` — a read-side request, so a
  read-only connection may ask it too, and the answer follows the path rather than the mount at
  the root. The program requires each answer to stand on its own — an allocation unit of some
  size, units to hold, no more free than there are, and room for a name longer than
  eight-and-three — and requires the two to differ, since one volume answered twice would look
  the same. It leaves both answers in `/KINTANE/STATFS.BIN`, synced.

  Then the kernel reads them back and holds them against its own walk of the same volumes. The
  allocation unit, the unit count and the longest name must match exactly. The free count may be
  ahead by at most eight clusters: the program was told before it wrote the file carrying the
  answer, so it is ahead by what that file took, and no more. And the count the driver keeps must
  be what the walk counts, which is what makes the answer worth anything — a program cannot count
  free clusters itself, so its half is that it asked and was answered coherently, and the kernel's
  half is that the answer was true.

- **The `linux` check asks the same questions through Linux's calls**, in `linux-hello`'s files
  mode: `statfs` on `/` and on `/FAT32`, each answer required to stand on its own, the two required
  to differ in their block counts since one volume answered twice would look the same, and
  `fstatfs` on an open file of the second volume required to agree with the `statfs` of its path on
  the allocation unit, the unit count and the longest name. These steps only ask, so they run after
  the step whose `fsync` makes the writing durable, leaving nothing in the cache for the walk that
  follows.

  **And the kernel holds those answers against its own walk.** The program leaves both `statfs`
  answers, and a listing of `/KINTANE` taken after its last change to that directory, in
  `/KINTANE/LINUX.DIR`, synced. The kernel then reads the file back and compares: each answer
  against `vfs::statfs` of the same path — the allocation unit, the unit count and the longest name
  exactly, the free count ahead by at most eight clusters for the same reason as `files size` — and
  the listing against the kernel's own `readdir` walk of that directory, requiring every name the
  walk finds to appear with a matching `d_type`, and requiring the two to hold the same number of
  entries, so an invented name is caught as well as a dropped one. The program's own steps prove
  only that it was answered coherently; a driver reporting the same fabricated numbers to every
  asker would pass them. This is the half that says the answers were true.

  It asks the namespace where a volume is mounted rather than naming a sector, so it is unaffected
  by which drive the FAT32 volume lives on.

```
  files size init: asked the file service what the volumes are; both volumes answered for themselves; the same server thread; 0 objects left, 0 frames left ok
```

#### The disk image after a run

The test disk is no longer attached with `snapshot=on`. Before each run kbuild copies the image it
built to `testdisk.run.img` and attaches that copy, so every boot starts from the same bytes and
the image kbuild built never changes. After a run the guest passed, kbuild reads the copy with its
own FAT reader — `kbuild/src/fat16.rs`, which shares no code with the kernel's driver — and fails
the run unless the volume walks consistent with no lost cluster and both tables the same, every name
the writing checks remove is gone, and each of `NATIVE.OUT` and `LINUX.OUT` that the console says the
kernel read back holds exactly the bytes it should. kbuild does not take the kernel's word for it:

```
  disk image: FAT16 consistent, 7 files, 2 directories, no lost cluster, the tables the same; kbuild read back /KINTANE/NATIVE.OUT and /KINTANE/LINUX.OUT
```

#### Cutting the power

`kbuild crashtest --preset x86_64-qemu --count N --seed S` builds with `FS_CRASH_TEST`. With it the
kernel, once the fs check has mounted the volume, writes it for ever instead of booting on: files in
`/CRASH` appended to, overwritten, truncated, renamed over each other and removed, a directory made
and removed, a sync now and then. Every byte of every file there is `out_byte(0x41, offset)`,
whichever file it was written through, so no rename or truncation changes what a byte must be. For
each cut kbuild starts the guest on a fresh copy of the image, waits for `fscrash: writing`, lets it
write for a random 0 to 3 seconds, and kills QEMU with `SIGKILL`: no flush and no orderly shutdown,
the image holds what QEMU had written when the signal arrived. Then kbuild's reader walks the copy.
It must find no chain through a free cluster, no cluster claimed twice, no file longer than its
chain, and no byte below a `/CRASH` file's size that the workload did not write. Lost clusters and
table copies apart are counted, since that is what the write order allows a cut to leave.

**Both volumes are cut, not only the first.** The workload writes `/FAT32/CRASH` on the second
volume as it writes `/CRASH` on the first, so a cut lands in FAT32's root cluster chain, its
28-bit entries and its FSInfo sector; a rename between the two volumes is `EXDEV`, which the
workload takes as an answer. kbuild walks the second volume after every cut too, and each cut line
now ends with its counts — `FAT32: N lost, tables differ in N, N files, N bytes` — with the
campaign summary counting a cut that damaged either volume. The FAT32 free count in **FSInfo is
not required to match** after a cut: FSInfo is written at a sync, so a cut between a table change
and the next sync leaves it stale by design. A synced volume whose FSInfo disagrees is a failure
(the stress audit requires the match); a crashed one whose FSInfo disagrees is the ordering working
([architecture.md](architecture.md#vfs-bcache-and-fat--files)).

A campaign of 4 cuts at seed 23 left 0 inconsistent volumes with the second volume visibly damaged
and tolerated: one cut left 1 lost cluster with the tables differing in 1 entry, another left 3
lost clusters. The transcript below predates the FAT32 columns.

```
$ kbuild crashtest --preset x86_64-qemu --count 30 --seed 20260914
  cut   1 after 2777 ms,  2400+ ops: consistent; 10 files, 0 lost clusters, tables differ in 0; 5 workload files, 19443 bytes checked
  ...
30 cuts, 0 inconsistent; 9 left lost clusters (at most 6), 6 left the tables apart; at least 46560 operations written
```

A cut that finds an inconsistent volume keeps its image as `testdisk.crash-<n>.img`. The host
tests make the same argument exhaustively on a smaller scale: `fat`'s
`every_point_a_crash_could_stop_the_writes_leaves_a_consistent_volume` records every block a
workload's cache writes, replays every prefix of that sequence on the empty volume, and walks each
one; it also requires that some prefix left a lost cluster and some left the tables apart, so it
cannot pass by never reaching the states the ordering exists for. The `fat` fuzz target does the
same for every operation script it runs.

The write path was falsified like the read path:

| Mutation | What caught it |
|---|---|
| The directory entry, first cluster and size, is written before the data and the table | `fat`'s crash-point host test; `kbuild crashtest`, 2 cuts of 8: `/CRASH/F5.BIN: 1 clusters hold a 1024-byte file`. A boot with no cut still passes, as it should |
| Only the first table copy is written | 7 `fat` host tests; boot: `files write`'s tables differ, and the `linux` check's `THE VOLUME IS NOT CONSISTENT` |
| The same, with both kernel checks made blind to differing tables | kbuild, after the guest exited 0: `the disk image after a clean exit lost 0 clusters, and its tables differ in 6 entries` |
| A sync writes nothing back | 7 `fat` host tests; boot: `files write`'s `2 BLOCKS NEVER WRITTEN after the sync`, and the `linux` check's `THE VOLUME IS NOT CONSISTENT` |
| The second volume's check after a cut swallows a failed walk | kbuild's `a_volume_the_walk_refuses_is_not_reported_clean`, which cross-links two table entries onto one cluster, **FAILED**; restored, 210 kbuild tests pass. Without it a cut could report a cross-linked FAT32 volume as consistent |
| The FAT32 generator builds a volume below the 65,525-cluster boundary | `the_second_format_mounts_as_fat32` and `a_script_runs_on_either_format` **FAILED**; restored, 41 host units pass. The volume would otherwise be FAT16 to every reader and every FAT32 input would have passed while testing FAT16 twice |

### 2f. The Linux personality

On the x86_64 and aarch64 presets with userspace and the test disk, where `ABI_LINUX` defaults on,
every boot runs a `linux` check right after `fs`
([userspace-abi.md](userspace-abi.md#as-built--static-programs-x86_64-and-aarch64)). It reads
`/KINTANE/LINUX.ELF` from the volume. That file is `user/linux-hello`, a static program that makes
Linux's system calls by Linux's numbers for the architecture it is built for and knows nothing of
KinTane; one source builds for both. The check runs it unmodified, with no argument, in the
boot-time slice, and requires:

- the file loads and is tagged `linux`: it has no KinTane ABI note and a System V `EI_OSABI`;
- it exits with 42. It returns 42 only if every step behaved; otherwise its exit code is the
  number of the first step that went wrong:

  | Step | What it checks |
  |---|---|
  | 10 | `argc` and `argv[0]` |
  | 11 | `AT_PAGESZ` |
  | 12 | `AT_ENTRY` |
  | 13 | `AT_RANDOM` |
  | 14 | `write(1)` |
  | 15 | `getpid` |
  | 16 | `uname` |
  | 17–18 | `brk`, and the memory behind it |
  | 19–20 | anonymous `mmap` and `munmap` |
  | 21–22 | the thread pointer, set with `arch_prctl(ARCH_SET_FS)` on x86_64 or written to `TPIDR_EL0` on aarch64, and read back through it |
  | 23–26 | `openat`, `fstat`, `read` and `close` on `/HELLO.TXT` |
  | 27 | `ENOENT` for a missing file |
  | 28 | `EBADF` for a descriptor that names nothing |
  | 29 | `ENOSYS` for `getrandom` |

- what it wrote to standard output, as the kernel captured it, is exactly `hello from linux\n`;
- the kernel logged the unimplemented call, and the number it recorded is the one the
  architecture's table names `getrandom`;
- `init` then runs natively on the same kernel, to its success code;
- no file is left open in the namespace, and no frame is leaked, apart from the program's own
  frames, which a passing check keeps for the two runs below.

With `LINUX_ENOSYS_FATAL=y` the check expects the process to be killed at `getrandom` instead, and
the log line says so.

On `x86_64-qemu` the line reads:

```
  linux      /KINTANE/LINUX.ELF (18560 bytes, tagged linux):
             hello from linux
linux: getrandom (318) is not implemented
             exit 0x000000000000002a ok, output ok, getrandom logged as unimplemented; init after it:
             hello from userspace
             native init unaffected
```

On `aarch64-virt` the program is 81064 bytes, since aarch64's linker aligns its segments to
64 KiB, and the logged call is `getrandom (278)`.

**With the scheduler.** After `waits`, a `linux mt` check starts the kept program again, as
`hello rich`, and hands it the volume's namespace. `rich` pipes, forks, `execve`s the same file in
its `child` mode, waits, and starts a thread that bumps a counter under a futex-based lock, each of
its threads with a thread pointer of its own. Its exit code is 43 when every step behaved, or the
first step that went wrong:

| Step | What it checks |
|---|---|
| 50–51 | `pipe2`, at descriptors 3 and 4 |
| 52 | a thread pointer of the parent's own |
| 53 | `fork` on x86_64, `clone(SIGCHLD)` on aarch64 |
| 54–55 | the parent closes its write end and reads: the pipe is empty until the child, after its `execve`, writes, so the read blocks, and then returns the child's line |
| 56 | the parent's thread pointer is its own after that block |
| 57–58 | `wait4` names the child and reports its exit code, 45; a child that failed passes its own step on instead |
| 59 | the page the child wrote before its `execve` still holds the parent's value |
| 60 | end of file, now that the last writer's process has ended |
| 61 | `ECHILD` with no child left |
| 62–63 | `clone` with `CLONE_THREAD`, on a mapped stack with a thread pointer of its own; `CLONE_PARENT_SETTID` writes the tid |
| 64 | both threads bump the counter 40 times each, yielding while they hold the lock, so the other waits on the futex |
| 65 | the parent's thread pointer is its own throughout |
| 66 | a join: `FUTEX_WAIT` on the tid word until the kernel zeroes it as the thread exits (`CLONE_CHILD_CLEARTID`) |
| 67 | the counter is 80: no bump was lost |
| 68–71 | what the thread found: its thread pointer is the one `clone` gave it, its tid is not the pid, and its pointer stays its own across the switches |
| 72–76 | the forked child, before its `execve`: the shared page reads the parent's value, a write changes its own copy, and its own thread pointer holds across 50 yields while the parent is blocked |
| 77–78 | the `child` mode, after it: descriptor 4 is still the pipe, and the memory is the new program's |

The check requires that exit code; that at least one pipe read blocked, at least one futex wait
blocked, and at least one waiter was woken by a futex wake, each counted by the kernel; that every
thread ended; that no file is left open; and that every frame of the process pool is back once the
parent and child are torn down. It runs on the boot CPU alone, since the secondaries join the
scheduler after the verdict, so the parent, the child and the thread share one CPU and every
switch between them is one a thread pointer must survive. On `x86_64-qemu` the line reads:

```
  linux mt   pipe, fork, execve, wait4, a thread and a futex ok; 1 pipe reads blocked, 41 futex waits blocked, 41 woken; 0 frames left ok
```

On `aarch64-virt` it read 42 futex waits blocked and 42 woken.

**Signals.** Once `linux mt` has torn its processes down, a `linux sig` check runs the program again,
as `hello signals`, on the same slot and stacks. Its exit code is 47 when every step behaved:

| Step | What it checks |
|---|---|
| 110 | `rt_sigaction` refuses a handler for `SIGKILL` and for `SIGSTOP` |
| 111–113 | a signal the process sends itself with `kill` runs its handler on the way out of that call. The handler, in assembly, zeroes every callee-saved register (`rbx`, `rbp`, `r12`–`r15`; `x19`–`x29`) and returns through the restorer, and every register marked before the `kill` holds its mark after it, `x30` too |
| 114–118 | `SIGUSR2` blocked with `rt_sigprocmask` and sent: its handler does not run, `rt_sigpending` shows it, and unblocking it runs the handler once, whose `siginfo` names the signal |
| 119 | with `SIGPIPE` ignored, a write to a pipe with no reader is `EPIPE` |
| 120–124 | a thread started with `clone` blocks reading an empty pipe; after 50 yields the first thread sends it `SIGUSR1` with `tgkill`; its handler runs on it, and its read answers `EINTR` |
| 125–127 | a child writing to a pipe with no reader is ended by `SIGPIPE`'s default action; its end sends the parent `SIGCHLD`, whose handler runs once, and `wait4` still reaps the child and reports signal 13 |
| 128–130 | a child blocked reading a pipe is ended by `SIGTERM`'s default action, reported as signal 15 |
| 131–132 | a child is refused a `SIGKILL` handler, spins yielding, and is ended by `SIGKILL`, reported as signal 9 |

The check requires that exit code, and counts from the kernel: at least four handlers run, as many
frames returned through `rt_sigreturn` as handlers run, at least one blocked call a signal ended
(the kernel counts a pipe read or futex wait that had registered and blocked before it did), and at
least three processes a signal's default action ended. It also requires every thread ended, no file
left open and every frame back. On `x86_64-qemu` and `aarch64-virt`, and on both SMP presets:

```
  linux sig  handlers, masks, EINTR, SIGCHLD, SIGPIPE and default actions ok; 4 handlers run, 4 returned, 1 blocked calls interrupted, 3 processes ended by a signal; 0 frames left ok
```

A check that forks three children and clones a thread starts five process threads, more than the
pool of three holds at once. A Linux `fork` or `clone` now reaps a pool entry whose thread has
exited before it looks for a free one; before that, the first run stopped at step 128, its second
`fork` refused. Native thread starts do not reap: a native thread that has exited stays in the
table until its check reaps it.

**Signals a system call never reaches.** A third run, `linux flt`, follows `linux sig` on the same
slot and stacks, as `hello faults`. Its exit code is 54 when every step behaved:

| Step | What it checks |
|---|---|
| 210–212 | a thread started with `clone` spins in user mode reading one word, making no system call at all; the first thread sends it `SIGUSR1` with `tgkill`, and its handler runs. Nothing but the interrupt that finds it spinning can deliver that, so this is the whole of delivery from an interrupt |
| 213–216 | a one-page mapping is unmapped and stored to. The store raises `SIGSEGV`, whose `siginfo` names *exactly* the address stored to in `si_addr`, and the handler steps over the store by writing the saved program counter in the `ucontext` — which also proves the frame's program counter is where the kernel says it is |
| 217–218 | the architecture's arithmetic trap — a division by zero on x86_64, an undefined instruction on aarch64, since `sdiv` by zero raises nothing there — reaches its handler as `SIGFPE` or `SIGILL`, and is stepped over the same way |
| 219 | both dispositions go back to the default, with the process still its own after three handlers |

The check requires that exit code and, from the kernel's own counters, at least one handler entered
from an interrupt, at least two entered from a fault, and as many frames returned through
`rt_sigreturn` as handlers entered. On `x86_64-qemu` and `aarch64-virt`:

```
  linux flt  a spinning thread took its handler, SIGSEGV was fixed from si_addr, the arithmetic trap stepped over; 1 from an interrupt, 2 from a fault, 3 of 3 returned; 0 frames left ok
```

**Signals that queue.** A fourth run, `linux rt`, follows `linux flt` on the same slot and stacks,
as `hello rtsig`. Its exit code is 56 when every step behaved, and otherwise the step that
was wrong — which is why these are numbered below 256, since a Linux exit status is the low
eight bits of the code:

| Step | What it checks |
|---|---|
| 240–241 | a real-time signal takes a handler like any other, and both numbers are blocked before anything is sent, so what arrives later is what the queue kept rather than what happened to race |
| 242–243 | three of one number are queued with values 1, 2 and 3, and one of a higher number with 9. Nothing runs while they are blocked |
| 244 | `rt_sigpending` reports both numbers |
| 245 | the queue fills to its eighth entry, and the ninth send is `EAGAIN` — refused, not dropped, which is the difference a sender can act on |
| 246–248 | unblocked, all eight arrive: the lower number's three first, each in the order queued and with its own value, then the higher number's five |
| 249 | the first delivery's `si_code` is `SI_QUEUE`, so a handler can tell a queued signal from one `kill` sent |

The check requires that exit code and, from the kernel's own counters, at least eight queued
deliveries and at least one send refused. On `x86_64-qemu` and `aarch64-virt`:

```
  linux rt   queued three deep and delivered in order, lowest number first, a full queue refused; 8 queued signals delivered, 1 refused when full; 0 frames left ok
```

**In the stress run.** Every fourth audit interval, after the waiting process, the auditor starts
the program twice as `hello tls`, on the two stacks the process and waiting-process cycles use.
It starts each process as it builds it and pins both to one CPU, a
different one each pair. Each sets its own thread pointer to a block marked with its pid and checks
it after each of 100 yields, then exits with 44. A process that reads another's mark exits 91 and
fails the audit, and so does a pair that is not over in 10 s or that leaves a frame behind. The
heartbeat counts the pairs. In 20 s runs, `x86_64-qemu`, `aarch64-virt`, and both SMP presets at 4
and at 8 CPUs each ran 5 pairs and 20 audits.

Three versions came before this one, and the stress run found something wrong with each:

- **2000 yields.** On `aarch64-virt-smp` one pair in twenty did not end within its patience. A
  yield on a CPU a busy stress workload shares can hand that workload a whole 10 ms slice, so 2000
  yields could take 20 s. The count went down, and the patience did not go up past what a pair
  should take.
- **A pair every interval.** On one CPU a pair costs the workloads a good part of a second, and a
  20 s run on `aarch64-virt` fell from 20 audits to 12, and on `x86_64-qemu` from 20 to 16.
- **Starting each process as it was built.** On 8 CPUs, both `x86_64-qemu-smp` and
  `aarch64-virt-smp` hung: the heartbeat watchdog stopped the runs after heartbeats 12 and 8. The
  first process's thread was faulting on another CPU, spinning with interrupts masked for the
  frame lock, while the auditor installed the second process, whose segment protection shoots down
  TLBs holding that lock. `shootdown.rs` forbids waiting masked for a lock held across a shootdown.
  For a round the pair built and installed both processes before starting either. In the ninth
  round the frame lock's wait was made to answer shootdowns, and the pair starts each process as
  it builds it again; see [the frame lock under shootdowns](#the-frame-lock-under-shootdowns).

#### The frame lock under shootdowns

Every process's `Vm` operations share one frame lock, and an unmap, a write-protect, a program
install, `fork` and `execve` all shoot down TLBs holding it. A thread faulting on another CPU
waits for that lock with interrupts masked, so unless its wait answers the shootdown, the two
CPUs wait for each other, and every CPU that needs either stops after them.

**The churning pair.** Every fourth audit interval, halfway between thread-pointer pairs, and
only on more than one CPU, the auditor starts the program as `hello churn`, pinned to one CPU. It
lets it run 20 ms, then builds, installs and starts a second, pinned to the next CPU, so the second
install shoots down while the first faults. Each maps eight anonymous pages, writes and reads back
every one, and unmaps them, 200 times, then exits with 46. A process that cannot map, gets back
the wrong value, or cannot unmap exits 95, 96 or 97 and fails the audit, and so does a pair that is
not over in 10 s or that leaves a frame behind. The heartbeat counts `churning pairs`.

| Lock (40 s stress runs) | `x86_64-qemu-smp` 4 CPUs | 8 CPUs | `aarch64-virt-smp` 4 CPUs | 8 CPUs |
|---|---|---|---|---|
| Plain masked spin, the pair workaround in place (base `8bfa611` plus the cycle) | watchdog after heartbeat 2 | watchdog after heartbeat 2 | watchdog after heartbeat 2 | `a churning process's thread did not end` at 18 s |
| Plain masked spin, final code (the fix reverted) | `a churning process's thread did not end` at 18 s | the same | the same | watchdog, no heartbeat in 180 s |
| Answering wait (`lock_irqsave_with`) | 41 audit lines, 10 churning pairs, 10 Linux pairs | the same | the same | the same |

Eight runs of eight hung with the plain spin, each at the first churning pair or, on
`aarch64-virt-smp` at 8 CPUs with the final code, already on the boot path; four of four passed
with the answering wait. A hang is caught by one of two bounds: the pair's 10 s patience, when the
auditor's own CPU is not one of the stuck two, and otherwise kbuild's heartbeat watchdog.

The heartbeat's shootdown count now carries the mean and worst wait for answers. Those numbers
are QEMU's and the host's, not the protocol's; see
[architecture.md](architecture.md#tlb-shootdown). In the passing runs above: mean 31 us and worst
36 ms (`x86_64-qemu-smp`, 4 CPUs), 174 us and 42 ms (8 CPUs), 26 us and 4 ms (`aarch64-virt-smp`,
4 CPUs), 114 us and 103 ms (8 CPUs). Before the fix the same runs showed means of 23–144 us over
their first two intervals, before they hung.

**Not reproduced here:** `fork` and `execve` against a fault. The stress run has no namespace
for `execve`, and a forked child keeps its process slot and its pool stack until the tree is torn
down, so a fork loop would run out of both within a few forks. They take the frame lock through
the same `with_frames`, and the churning pair exercises its wait with the two operations the
stress run can repeat: installs and unmaps.

During this branch's verification, 20 s single-CPU stress runs also failed as the round-7 notes
describe: `x86_64-qemu` with "user process: a process made no progress", and `i686-qemu` with
"a workload made no progress since the last audit: heap A", under a host load average near 9. The
base commit, `9576bb2`, failed both the same way in the same conditions, `i686-qemu` once in three
runs. `i686` does not build the personality.

`kernel/linux` is host-tested (15 tests), covering:

- every dispatched number, for both architectures, against its name in that architecture's table,
  and `decode` finding it;
- aarch64 lacking `fork`, `pipe` and `arch_prctl`, and its numbering not being x86_64's;
- `clone`'s argument order on each architecture, and `wait4`'s status encoding;
- the errno encoding and its range;
- the start-up stack, read back the way start-up code reads it, at 40 string lengths for its
  alignment;
- the `struct stat` offsets in both layouts, and `struct utsname`'s;
- signals: `SIGKILL` and `SIGSTOP` taking no disposition and every default action, `struct
  sigaction` read back, and a signal's exit code told apart from a program's and from the kernel's
  killed;
- each architecture's signal frame, at Linux's offsets, built and read back to the context it was
  built from, with the handler's registers, x86_64's red zone and alignment, and aarch64's frame
  record;
- a frame whose return address is outside the user half, whose aarch64 state is not EL0, or which
  is short, refused; x86_64 flags a program may not hold dropped; a mask blocking `SIGKILL` given
  back without it; and a stack with no room below it taking no frame.

The `sigframe` fuzz target reads random bytes, and frames `signal::build` laid out and then
corrupted, as a frame `rt_sigreturn` would find, and asserts that nothing it accepts carries a
return address outside the user half, flags or a processor state that are not a program's own, or a
mask that blocks `SIGKILL` or `SIGSTOP`. A 200,000-input campaign ran with no failures, 31% of
inputs accepted.

`kernel/mm` has 2 more, for `Vm::fork_into`: two address spaces over one share store, where a write
on either side after the fork stays on that side and the other still reads the value from before,
and a fork into a space that already has regions is refused.

`kernel/elf` has 4 more tests for the note walk: the KinTane note found, a prefix of its owner not
matching, notes truncated at every length and with an oversized name never panicking, and
`AT_PHDR`'s address.

Each property was falsified: the mutation was applied and checked, the check failed, and the file
was restored and compared byte for byte.

| Mutation | What caught it |
|---|---|
| `Failure::NotFound` mapped to `EIO` | the `linux` host test `errors_travel_as_negated_linux_numbers`; boot: `exit 0x1b WRONG`, step 27 |
| `AT_ENTRY` left out of the auxiliary vector | boot: `exit 0xc WRONG, OUTPUT WRONG`, step 12, before the program writes anything |
| A Linux process given the native table | boot: `exit 0x1 WRONG, OUTPUT WRONG`. The program's first system call reached the native table |
| A native process given the Linux table | boot: the `userspace` check logs `linux: stat (4) is not implemented` for `init`'s native calls, and the boot fails |
| The unimplemented call logged but not recorded | boot: `THE UNIMPLEMENTED CALL WAS NOT LOGGED` |
| Every program tagged native, the note test reading `true` | boot: `/KINTANE/LINUX.ELF IS NOT TAGGED linux` |
| The x86_64 context switch neither saving nor loading `FS` base | boot: `linux mt  the program exited 0xffffffffffffffff, WRONG; 1 pipe reads blocked, 0 futex waits blocked`. The parent was killed after its blocked read, with the thread part never reached, which is what follows when the child's `execve` zeroes `FS` base on the one CPU and nothing puts the parent's back |
| A pipe read that answers `EAGAIN` instead of blocking while a writer is left | boot: `linux mt  the program exited 0x0000000000000037, WRONG; 0 pipe reads blocked`, step 55 |
| `Vm::fork_into` mapping the shared pages writable in both spaces, so no write copies | boot: `linux mt  the program exited 0x000000000000003b, WRONG`, step 59: the parent read the child's write. Host: `a_fork_shares_every_page_and_a_write_on_either_side_stays_on_that_side` fails |
| A futex wake that wakes its bucket without counting the wake | boot: `linux mt  the program NEVER EXITED; 1 pipe reads blocked, 0 futex waits blocked, 1 woken; NOTHING REALLY BLOCKED; A THREAD NEVER ENDED`. The woken waiter found the count unchanged and waited again, and nothing woke it after |
| `signal::restore` giving `rbx` back as zero (x86_64) | boot: `linux sig  the program exited 0x71, WRONG; 1 handlers run, 1 returned`, step 113: a callee-saved register did not survive the handler |
| Delivery ignoring the mask (aarch64) | boot: `linux sig  the program exited 0x73, WRONG`, step 115: the blocked `SIGUSR2`'s handler ran |
| Sending a signal waking no blocked thread (x86_64) | boot: `linux sig  the program NEVER EXITED; 2 handlers run, 2 returned, 0 blocked calls interrupted; A THREAD NEVER ENDED`. The thread in its read was never woken to see the signal, and the check's patience, not a hang, ended the run |
| `rt_sigaction` taking a disposition for `SIGKILL` (aarch64) | boot: `linux sig  the program exited 0x6e, WRONG`, step 110 |
| Nothing delivered on the way out of an interrupt (x86_64) | boot: `linux flt  the program NEVER EXITED; 0 from an interrupt, 0 from a fault, 0 of 0 returned; A THREAD NEVER ENDED, its processes left in place; 15 FRAMES LEAKED`. The spinning thread never sees its signal, and the check's patience, not a hang, ends the run |
| `si_addr` a page away from the address that faulted (x86_64) | boot: `linux flt  the program exited 0x00000000000000d8, WRONG; 1 from an interrupt, 1 from a fault`, step 216: the handler was told about an address the store never touched |
| A fault handler that returns without fixing anything (x86_64) | boot: `linux flt  the program exited 0x5349474e0000000b, WRONG; 1 from an interrupt, 16 from a fault, 17 of 17 returned`. The store faults again the moment the handler returns; after 16 of them at that one instruction the kernel stops running the handler and the default action ends the process, reported as `SIGSEGV` — promptly, not as a hang |
| A queued signal delivered once instead of three times (`pop_queued` not putting the pending bit back while another entry of that number is held) | boot: `linux rt  the program exited 0x00000000000000f7, WRONG; 2 queued signals delivered, 1 refused when full; NOT WHAT THE MODE DOES`, step 247: the first of each number arrived and the rest stayed in the queue, which the kernel's own count confirms |
| Delivery ignoring the order entries went in (`pop_queued` taking the newest rather than the oldest) | boot: `linux rt  the program exited 0x00000000000000f8, WRONG; 8 queued signals delivered, 1 refused when full`, step 248: all eight arrived, so the count is right and only the order is wrong |
| A full queue dropping a send silently instead of refusing it (`queue` answering `Ok` when no slot is free) | boot: `linux rt  the program exited 0x00000000000000f5, WRONG; 0 queued signals delivered, 0 refused when full`, step 245: the ninth send was accepted, so the program never unblocked and nothing was delivered at all |
| `restore` reading past a frame that claims floating-point state instead of refusing it | host: `a_frame_that_asks_for_floating_point_state_back_is_refused` fails on both architectures; a 20,000-input `sigframe` campaign stops with `Aarch64: a frame claiming floating-point state was accepted` |
| The same, with the re-fault bound removed (`REFAULTS` raised) | boot: `linux flt  the program NEVER EXITED; 1 from an interrupt, 317451 from a fault, 317451 of 317452 returned; A THREAD NEVER ENDED, its processes left in place; 15 FRAMES LEAKED`. This is what the bound exists to stop, and what Linux itself leaves to the program |

`LINUX_ENOSYS_FATAL=y` was booted as well. The boot passes, with `exit 0xffffffffffffffff ok` and
the log line `linux: getrandom (318) is not implemented, and LINUX_ENOSYS_FATAL ends the process`.

### 2g. Network

With `QEMU_NET_TEST`, on by default on aarch64, x86_64 and i686 test builds, kbuild attaches
a virtio-net card to QEMU's user-mode network: a `virtio-net-device` in a memory-mapped slot
on aarch64, and a modern-only `virtio-net-pci` function on the PCs, at slot `0x1e` on `pc`.
The network is

```
-netdev user,id=kt_net,hostfwd=udp:127.0.0.1:<udp>-:5555
-chardev socket,id=kt_relay_out,host=127.0.0.1,port=<out>
-chardev socket,id=kt_relay_in,host=127.0.0.1,port=<in>
-object filter-redirector,id=kt_net_in,netdev=kt_net,queue=rx,indev=kt_relay_in
-object filter-redirector,id=kt_net_out,netdev=kt_net,queue=rx,outdev=kt_relay_out
-chardev socket,id=kt_down_out,host=127.0.0.1,port=<down out>
-chardev socket,id=kt_down_in,host=127.0.0.1,port=<down in>
-object filter-redirector,id=kt_net_down_out,netdev=kt_net,queue=tx,outdev=kt_down_out
-object filter-redirector,id=kt_net_down_in,netdev=kt_net,queue=tx,indev=kt_down_in
```

The two pairs are declared in opposite orders on purpose. A frame the guest sends passes the
filters last to first, so the injector is declared first and what it puts back goes on to the
network; a frame on its way to the guest passes them in declaration order, so there the
redirector is declared first and what the injector puts back goes on to the card. Declared the
other way round, the second pair swallowed every inbound frame and the boot reported that the
gateway never answered an ARP request.

where the ports are free loopback ports kbuild picks for the run. Nothing leaves the host.
QEMU's user-mode stack answers ARP and echo requests for its gateway, 10.0.2.2, itself, and
the only other party is kbuild, in three threads of `kbuild/src/qemu.rs`:

- `udp_peer` sends `kintane-udp-probe` to the forwarded port four times a second, each followed
  by `kintane-tcp-port <tcp>`, `kintane-udp-port <service>`, `kintane-udp-quiet <quiet>` and
  `kintane-udp-fragmented 1 <64 bytes>`, and answers every `kintane-udp-echo <n>` the guest
  sends back with `kintane-udp-ack <n>`. The 64 bytes are `i ^ 0x5a`, which the guest checks
  one by one once it has the datagram whole.
- `udp_service` answers `kintane-udp-request <tag>` on the loopback port `<service>` with
  `kintane-udp-reply <tag>`, to whoever sent it. The guest reaches it the way it reaches
  `tcp_service`, by addressing the gateway. `<quiet>` is a port kbuild found free and never
  bound, which is how a check can send a datagram nobody will answer.
- `tcp_service` listens on the loopback port `<tcp>`. The guest reaches it by connecting to the
  gateway's address, which QEMU's user network turns into a connection to the host's loopback
  interface. It reads `kintane-tcp-request <mode> <tag>` and writes back
  `kintane-tcp-reply <mode> <tag>`, in two writes with Nagle off, so the reply is two segments
  and `downstream` has a pair to swap. It closes first for `peer-closes`, and after the guest for
  `guest-closes`.
- `relay` sits between the card and QEMU's network, on the frames the guest sends. The two
  filters hand each to kbuild on one socket and take it back on the other before the network
  sees it. It passes every frame but one kind: the first data segment of each connection to
  `<tcp>`, which it drops the first time it sees it. That is what lets a check require a
  retransmission rather than hope for one.
- `downstream` is the same thing on the frames the network sends the guest, and it is where the
  network stops being orderly. It does three things, each of which the `net` check gates on:
  - **fragmentation**: every datagram carrying `kintane-udp-fragmented ` is split into two IPv4
    fragments, each with its own header checksum, at an eight-byte boundary. Put back together
    the datagram is the bytes that were sent, so the guest checks a pattern rather than that
    something arrived;
  - **reordering**: the first data segment of the first connection to `<tcp>` is split into two
    segments, each with its own sequence number and checksums, and the second half is sent
    first, so the guest holds it until the half in front of it arrives;
  - **duplication**: the half in front is then sent twice, so the guest must take it once.

  The last two happen once per run; fragmentation happens every time, because the guest may not
  be listening when the first one goes past. The relay never holds a frame back waiting for
  another: an earlier version held the first data segment until the next frame went by, which
  reordered a pair only when that next frame happened to be the rest of the reply. On
  `x86_64-qemu-smp` it was an acknowledgement, nothing arrived out of order, and the boot failed
  a check that was really about frame timing. Splitting one segment cannot be timed out of
  happening.

Like the serial probes, all three answer and never judge: the verdict is the exit code. The
resolver at 10.0.2.3 is not used, because it forwards to the host's, which an offline machine
lacks.

The boot gates on three lines ([architecture.md](architecture.md#net--the-network-stack-and-virtio-net)):

```
  nic        virtio-net 52:54:00:12:34:56, 8 receive buffers posted ok
  net        line 78; gateway 52:55:0a:00:02:02; 4 echo replies; udp port 5555, 3 round trips;
             4 fragments, 2 datagrams reassembled; tcp port 55824, closed by the kernel
             [syn-sent established fin-wait-1 fin-wait-2 time-wait] and by kbuild [syn-sent
             established close-wait last-ack], 2 data retransmits, 1 segments held out of order,
             1 runs joined up; 81 frames in, 22 out, 50 interrupts, 0 polled, 0 stack buffers
             held ok
  sockets    tcp-client connected, sent, read its reply to kbuild's close; 1 established,
             1 data retransmits; waits woken by the card 5, armed for a TCP timer 5, polled 0;
             udp-client: a reply from the service, a truncation reported whole, a foreign
             datagram refused, nothing on the quiet port (7 sent, 106 received, 24 with the
             inbox full, 0 for want of a buffer); closed in order, every buffer back;
             0 objects left, 0 frames left ok
  linux net  tcp client ok; server ok; udp ok (kbuild told of its listener 1 time); waits woken
             by the card 10, armed for a TCP timer 9, polled 0; closed in order, every buffer
             back; 0 objects left, 0 frames left ok
```

**Datagrams.** After its stream client, `sockets` runs `user/udp-client`, a native program over
the datagram socket calls. It sends a request to `udp_service` from a socket the kernel gives a
port to at its first send and checks the reply and where it came from; takes a second reply into
four bytes, which must report the length the datagram had rather than the four that fit;
connects a socket to `<quiet>`, sends to the service from it anyway, and requires that the
service's reply is *not* delivered, since a connected socket takes datagrams only from the
address it connected to; and finally sends to `<quiet>` itself. The Linux program's `udp` mode
does the same over Linux's calls, and adds what a wrong call earns: `EOPNOTSUPP` for `listen`
and `shutdown` on a datagram socket, `EMSGSIZE` past 256 bytes, `EAGAIN` when `SO_RCVTIMEO`
expires, `ENOPROTOOPT` for `SO_BROADCAST`, and a `sendmsg`/`recvmsg` round trip of one buffer.

**What the quiet port answers is nothing.** A datagram sent to a port nobody listens on earns a
timeout rather than `ECONNREFUSED`, and both programs still accept the timeout — but the reason
has changed. The stack now parses ICMP destination-unreachable, matches it to the port that
sent, and reports the refusal on that socket's next receive; what is missing is anyone to send
the message. A packet capture of a whole boot (`filter-dump` on the network, read back frame by
frame) shows QEMU's user-mode network sending echo replies and nothing else of ICMP: no
unreachable message for the quiet port or for any other. So the path is proven by host tests —
a refusal reaches the port that sent it, one quoting another address or port refuses nothing —
and the programs keep accepting either outcome, because on this network only one of them can
happen.

That is aarch64, where every frame arrives by interrupt. i686 reads the same on line 10,
through the 8259A, and x86_64 on `line 17, MSI-X`. On a platform that delivers
message-signalled interrupts, a card that came up on anything but MSI-X fails with `THE CARD
IS NOT ON MSI-X, THOUGH QEMU'S FUNCTION HAS IT`. Every wait is bounded by the clock: 5 s for
the gateway, 3 s for each reply, 15 s for kbuild's first probe. A broken path fails the boot
rather than timing it out.

**The fragmented datagram.** Before the TCP part, the check waits for a datagram that arrived as
two fragments and requires its 64-byte pattern to be exactly what kbuild sent, byte for byte:
`4 fragments, 2 datagrams reassembled` above is the probe's copy and the check's. A stack that
refuses fragments never sees one, and the boot fails with `THE FRAGMENTED DATAGRAM NEVER ARRIVED
WHOLE AND INTACT`.

The TCP part of `net` makes two connections to `tcp_service`, each step bounded at 10 s. The
first is closed by the kernel first and must pass through FIN-WAIT-1 to TIME-WAIT. The second
is closed by kbuild first and must pass through CLOSE-WAIT and LAST-ACK to CLOSED, and be
reaped. Each must have had a data segment retransmitted, since the relay dropped its first. The
first connection also meets `downstream`'s swapped pair, so the rounds must show at least one
segment held out of order and at least one run of held bytes joining the stream, and none given
up: a stack that dropped what arrived early would still deliver the reply, from the peer's
retransmission, which is exactly what the counters tell apart. Then the check lingers 3 s, and
*from there on* no segment may arrive twice or out of order and no reset may be exchanged: a
segment the kernel failed to acknowledge would come again, since QEMU's TCP retransmits after a
second or so. (Duplicates and reordering during the rounds are what the relay is for; after them
there is no excuse for either.) Every buffer must be back afterwards, as before.
`sockets`, on x86_64 and aarch64, runs `user/tcp-client` over the socket calls on the scheduler
([userspace-abi.md](userspace-abi.md)); i686 has no userspace, and gates on the TCP part of
`net` alone.

**What the congestion control costs, measured.** A 60-second stress run at four CPUs on
`x86_64-qemu-smp` made **204 TCP round trips with 205 data retransmits and no retried round**,
with 6,181 socket waits woken by the card and none polled. The same run shape recorded before
this work made 162 round trips with 163 retransmits (and 154/154 on `aarch64-virt-smp`). Two
caveats, and they matter more than the numbers: the guest is emulated, so TCG's cost dominates a
loopback path with no real latency or loss to control for; and the relay drops one data segment
of every connection on purpose, so retransmits track round trips by construction rather than
telling you anything about loss recovery. What the figures support is that a window, an estimate
and a queue did not cost throughput — not that TCP got faster on a network.

**Waits woken by the card.** From `sockets` on, the card's interrupt handler runs the stack and
wakes the socket calls' queue, and a waiter otherwise looks again only at the stack's next TCP
timer ([architecture.md](architecture.md#net--the-network-stack-and-virtio-net)). Both
`sockets` and `linux net` count the waits the card's handler woke, the waits armed for a TCP
timer, and the waits armed on the 2 ms fallback, and on a card with an interrupt route they
require at least one of the first and none of the last. The stress heartbeat carries the same
three counts (`network waits woken by the card …, armed for a TCP timer …, polled …`), where the
TCP workload's rounds wait the same way.

**The Linux program's socket modes** (`linux net`, after `sockets`, on x86_64 and aarch64). The
kept `/KINTANE/LINUX.ELF` runs twice more:

- as `tcp <port>`, a client of kbuild's service. Before it connects it checks that another
  family is `EAFNOSUPPORT`, a descriptor that is not a socket `ENOTSOCK`, and a send on an
  unconnected socket `ENOTCONN`. Then it connects, checks `EISCONN`, both names, and that a
  `MSG_DONTWAIT` receive is `EAGAIN` while kbuild waits for a request; sends the request, reads the
  reply through `read` to kbuild's close, and checks `SHUT_RD` is `EOPNOTSUPP`. A second,
  non-blocking socket's `connect` must be `EINPROGRESS`, then `EALREADY` until it is established
  and `EISCONN` after, with no `SO_ERROR`, and a read on it `EAGAIN`; then it makes a whole
  exchange on that socket without waiting, reading `EAGAIN` until the reply comes, to kbuild's
  close. Every connection of the mode is closed by kbuild first, so none is left in TIME-WAIT;
- as `serve`, a server. First it starts a second thread that waits in `accept` on port 7778,
  where nobody connects, and leaves it waiting when the process ends: with no TCP timer pending
  by then, only the process's end can end that wait. Then it binds `0.0.0.0:7777`, listens and
  blocks in `accept4`. kbuild's QEMU
  command line forwards a loopback port to guest port 7777 (`hostfwd=tcp:…-:7777`). Once the
  listener is up the check sends kbuild's datagram peer `kintane-tcp-listening <n>`, repeated
  every 500 ms while the program runs, and kbuild connects in once per number, sends
  `kintane-tcp-inbound <n>`, and answers the reply with `kintane-tcp-inbound-verified <n>` only if
  it is `kintane-tcp-inbound-reply <n>`, then closes. The program requires the peer's address to be
  the gateway, the verification, and the end of the stream after it. kbuild answers and does not
  judge: a wrong reply gets `kintane-tcp-inbound-wrong`, and the program fails. `<n>` is the
  scheduler clock's nanoseconds when the check runs, so each boot's differs: the boot counter
  test, which restarts one QEMU several times under the same kbuild, found that a fixed number was
  served on the first boot only, and every later boot's server waited in `accept` for good.

The check requires both exit codes, both processes' threads ended, the waits woken as above,
every connection closed in order with every stack buffer back, every Linux socket let go of, and
every object and frame back. The check tells kbuild only once something listens, because a
connection kbuild made earlier would be refused with a reset, which the `net` check's linger
forbids.

The boot counter test, which resets one QEMU several times, found a fault the single boots
could not. Every boot opened its first connections from port 49152 again, with nearly the same
initial sequence numbers, and QEMU's TCP still held those connections from the boot before. A
later boot's round was refused, and the next boot's program could not connect. Ephemeral ports
now start from the clock at the first connection.

On MSI-X the card first took no interrupts at all. Its table entry was written and unmasked,
both queues read back vector 0, and QEMU's trace showed `virtio_notify` for its queues, but
no `apic_deliver_irq` for its vector. The function was not a bus master: nothing in discovery
sets the bit, QEMU's virtio DMA does not need it, and the disk's interrupts arrived only
because SeaBIOS had made the disk a bus master to boot from it. The platform now sets the bit
before programming a function's message.

Host tests, without QEMU:

- `kernel/net`: 47 tests. 21 are against a simulated gateway, and cover RFC 1071 checksums, IPv4
  lengths, fragments and bad checksums refused and counted, and the UDP pseudo-header. For
  ARP: resolution through the gateway and its retry limit, a reply with the wrong operation
  ignored, and expiry followed by a new request. Then echo replies matched by sequence
  number, a UDP round trip, the stack answering ARP and pings addressed to it and ignoring
  frames for other hosts, a refused send holding no buffer, a full inbox counted, a flood
  handled in bounded polls, and the pool refusing a second give.
- `kernel/net`'s TCP: the other 26, against a scripted peer that spells out every segment it
  sends, so loss is a segment it never answers, duplication one it delivers twice, and
  reordering two it delivers out of turn. They cover the wire format (the checksum over the
  pseudo-header, and a bad data offset or option length refused) and a round trip closed by
  each side and by both at once. For a listener: an accepted connection and a bounded backlog.
  Loss: a lost data segment and a lost SYN sent again on the timer, with the timeout doubling,
  and go-back-N from the oldest unacknowledged byte. A duplicated segment is acknowledged and
  delivered once, an overlapping one trimmed, reordered segments repaired by retransmission,
  and a FIN ahead of missing data held back. Retries run out into a reset. Sequence checks: a
  wrong acknowledgement to a SYN, a refused connection, only an exact reset obeyed, an
  acknowledgement for unsent data ignored, and a reset for a segment that matches nothing.
  Memory: the receive window shrinking to zero and announced again, the peer's window and
  segment size respected with a shut window probed, two pool buffers per connection with the
  pool's bound, a stale connection name refused, and unread data turning a close into a reset.
  Selective acknowledgement: the options written and parsed back, the blocks naming the runs
  held past a hole nearest first, none sent to a peer that never asked, and — the sending half —
  a peer's blocks used to resend the hole and step over what it already holds, with a block
  naming data never sent discarded. The last two are what tell selective recovery from
  go-back-N, which is why they are worth spelling out: with the blocks ignored the stack resends
  every byte from the hole onwards (`bbbbccccdddd` where the fix sends `bbbb`), and with a
  block naming unsent data believed it steps over bytes the peer never had. Both mutations were
  applied, each failed its own test while leaving the other passing, and `tcp.rs` was restored
  byte for byte afterwards.

  **No boot exercises either half**, and that is a property of the peer rather than of the
  stack: QEMU's user-mode network offers no SACK-permitted, as the capture in this document's
  network section shows, so nothing in a guest can send a block to act on.
- `kbuild`: the relay drops each connection's first data segment once and passes everything
  else.
- `drivers/net/virtio-net`: 16 tests against the shared fake device on both queues, three of
  them for MSI-X: both queues on one vector with the status register left unread, a refused
  vector failing bring-up, and no vector without one. They cover
  the handshake, the address and its fallback, a legacy or block device refused, a frame
  sent behind a zero header, bad lengths refused, a full transmit queue recovering, frames
  received in order with their buffers posted again, a short completion and one naming a
  buffer never posted, interrupt-driven collection, and the stack resolving its gateway
  through the card.
- `drivers/virtio`: the virtqueue and fake-device tests that were virtio-blk's, unchanged.

Fuzzing is the `net` target ([2d](#2d-fuzzing)). 200,000 inputs from a random seed ran
clean, and 21.9% of them parsed past Ethernet to a protocol the stack speaks.

In a stress run one `net` workload pings the gateway and makes a UDP round trip with kbuild,
over and over, interrupt-driven where the card's line is wired. A lost reply is retried
twice, a third loss fails the run, and the heartbeat counts retries. At every audit the
stack's pool must be full and every receive buffer with the card or holding a frame, while
kbuild's probes keep arriving. 60 s on `aarch64-virt-smp`, four CPUs, passed all 60 audits
with 1,536 echo replies, 1,536 round trips and 2 retries, beside 255,650 disk completions by
interrupt and none polled. The 20-second runs pass on
`x86_64-qemu`, `i686-qemu`, `aarch64-virt`, both SMP presets at four CPUs and both at eight.

A `tcp` workload runs beside it, making TCP round trips with `tcp_service` through the same
card and stack. Each round connects, sends a request, reads the reply and closes: the kernel
closes first on odd rounds, and kbuild on even ones. The relay drops each connection's first
data segment, so every round retransmits. Each step waits at most 2 s. A failed round is tried
twice more and a third failure fails the run, and the heartbeat counts retries and names the
reason for the latest. At every audit no connection may hold a ring, and the pool's books must
agree with what connections hold. 60 s at four CPUs passed all 60 audits on both SMP presets,
neither retrying a round: `aarch64-virt-smp` made 154 round trips with 154 data retransmits,
and `x86_64-qemu-smp` 162 with 163.

The first 60-second runs passed too, but retried 7 rounds on `x86_64-qemu-smp` (before the
heartbeat named a reason) and 2 on `aarch64-virt-smp`. The recorded reason was `a connection
did not end where its close order leads`, and the fault was in the round's bookkeeping, not in
TCP. On a round kbuild closes first, the connection's states were read only by the wait after
the kernel's close. QEMU's acknowledgement of the FIN could arrive, and the connection be closed
and reaped, before that wait first looked, so LAST-ACK was never seen. The status is now read
under the same lock as the close.

The workload is no longer paced: it sleeps 1 ms between polls for a reply and between
rounds. For a while it slept 5 ms and 25 ms. At one millisecond each on a single CPU, it took
enough time from the user process below it that `x86_64-qemu` and `aarch64-virt` both failed
with `user process: a process made no progress`, and 2 ms and 10 ms stopped being enough once
MSI-X put the disk and the card on interrupts. What failed was the process check's fixed
80 ms window, not the process. With that check counting slices
([below](#3a-stress)), the unpaced 20-second runs passed three times on `x86_64-qemu`, twice
on `aarch64-virt` and once on `i686-qemu`, with about 2,300 round trips each where the paced
runs made 470. Beside six busy guests, both `x86_64-qemu` runs that got past bring-up passed.
The other three stopped in the boot `preempt` check, before the workload ran.

The first two such runs hung at about 40 s: in one a workload missed its checkpoint, and the
watchdog killed the other. The network workload took the stack's spinlock without masking
interrupts, so a timer interrupt could preempt the holder in the middle of a poll and move
it to another CPU, and kernel spinlocks are held with preemption off. Taken with
`lock_irqsave`, the same run passed.

Falsified, each mutation confirmed applied, then restored:

| Mutation | Preset | What caught it |
|---|---|---|
| The IPv4 header checksum written one too high | `aarch64-virt`, `x86_64-qemu` | the gateway resolved, then `AN ECHO REQUEST WAS NEVER ANSWERED`: QEMU drops a packet whose header does not verify. Seven host tests fail too |
| ARP requests sent with operation 3 | `aarch64-virt`, `i686-qemu` | **not caught at first**: both passed. QEMU asks for the guest's address before it forwards kbuild's first probe, and the stack learned the gateway from that request. The check now forgets the gateway and requires a reply to its own request, and fails with `THE GATEWAY NEVER ANSWERED AN ARP REQUEST`. Eight host tests fail too |
| The first received frame's buffer never given back to the pool | `aarch64-virt`, `x86_64-qemu` | every exchange passed, then `1 stack buffers held, A STACK BUFFER WAS NOT GIVEN BACK`. Seven host tests fail too |
| The 500th received frame's buffer never given back | `aarch64-virt-smp` stress | the boot check passed, then `stress AUDIT FAILED at 3 s: network: a stack buffer is out of its pool with nothing using it (a leak)` |
| The card's interrupt handler acknowledges but never drains the receive queue | `aarch64-virt`, `i686-qemu`, `x86_64-qemu` | `0 frames in, 28 interrupts`, then `THE GATEWAY NEVER ANSWERED AN ARP REQUEST`, on the GIC, the 8259A and MSI-X alike. The host test `in_interrupt_mode_only_the_handler_collects` fails too. Before MSI-X landed the x86_64 card was polled, and the same mutation passed there |
| The platform does not make a function a bus master before programming its message | `x86_64-qemu` | the disk still passes `block irq` on MSI-X, because SeaBIOS made it a bus master; the card takes `0 interrupts` and fails with `THE GATEWAY NEVER ANSWERED AN ARP REQUEST`. The host test `a_bus_master_keeps_the_rest_of_its_command_register` covers the register write |
| `recv` drains the receive queue even in interrupt-driven mode | host test | `in_interrupt_mode_only_the_handler_collects` fails. **Not observable under QEMU**: `aarch64-virt` and `i686-qemu` both passed with `0 polled`, because the card completes and interrupts before the waiter first looks, so the handler always collects first. The check is sound, but QEMU cannot make the waiter win |

The TCP checks, falsified the same way, each run on `x86_64-qemu`:

| Mutation | What caught it |
|---|---|
| Every data segment sent with its sequence number one too high | `NO TCP REPLY ARRIVED`: QEMU's TCP never takes the request. `sockets` fails too, the program exiting `0x7c05` when its receive runs out |
| Pure acknowledgements never sent | **only the linger**: both rounds completed, because data and FIN segments carry acknowledgements. Then `1 segments repeated or reset` and `THE PEER SENT A SEGMENT AGAIN OR A RESET WAS EXCHANGED: AN ACKNOWLEDGEMENT WENT MISSING`. `sockets` alone passed, since its program looks at nothing after its close |
| The retransmission timer runs out without going back to the oldest unacknowledged byte | the request the relay dropped is never sent again: `NO TCP REPLY ARRIVED`, and `sockets` reports `0 data retransmits, NONE, though kbuild drops the first data segment` |
| A finished connection's send ring never given back to the pool | both rounds passed, then `2 stack buffers held, A STACK BUFFER WAS NOT GIVEN BACK`; `sockets` fails with `THE CONNECTION NEVER FINISHED CLOSING, OR A BUFFER IS MISSING` |

The interrupt-woken waits and the Linux socket calls, each run on `x86_64-qemu`:

| Mutation | What caught it |
|---|---|
| The 2 ms poll back: every wait armed on the fixed interval, and the card's handler waking nobody | both programs still succeeded, and both checks failed: `sockets` with `waits woken by the card 0, armed for a TCP timer 0, polled 121, NOT WOKEN BY THE CARD'S INTERRUPT`, `linux net` with `polled 108` |
| A Linux receive that drops the last byte of what arrived | `linux net  tcp client exited 0x0000000000000078, WRONG`, step 120, the reply compared. The server passed, since it reads a byte at a time |
| `accept4` answering the listener's descriptor again instead of the connection's | `server exited 0x0000000000000088, WRONG`, step 136: the read on the listener fails. The accepted connection was never let go of, and the check reports that too: `A CONNECTION NEVER FINISHED CLOSING`, `A LINUX SOCKET WAS NEVER LET GO OF`, `1 OBJECTS LEAKED` |
| A Linux socket wait that never looks at whether its process is ending | `server NEVER EXITED, A THREAD NEVER ENDED`: `serve`'s second thread was woken (`waits woken by the card 62`) and waited again, and its process's socket, object and frames were left in place |
| A process's end waking no socket waiter | **passed**. Every frame the card collects wakes every socket waiter, and kbuild's datagram probes arrive four times a second, so the waiting thread looked again, found its process ending and ended within a quarter of a second anyway. The wake matters on a quiet network; QEMU's is never quiet |
| A non-blocking call that waits instead of answering `EAGAIN` | `tcp client NEVER EXITED, A THREAD NEVER ENDED`: its `MSG_DONTWAIT` receive at step 118 waited for a reply to a request it had not sent, past the check's 10 s patience. With its thread still holding the process slot the server `NEVER STARTED`, and the process's frames were left in place (`12 FRAMES LEAKED`) |

**Not covered.** Fragment reassembly, IPv6, DHCP, TCP congestion control, an out-of-order
queue, datagram sockets and `poll`/`select`/`epoll` do not exist. Native `listen` and
`socket_accept` are host-tested and reached at boot only through the Linux personality's
`accept4`. The 2 ms fallback for a card with no interrupt route is not run by any preset: every
QEMU machine routes the card's interrupt. The only network card driver is virtio-net, and it has
run only under QEMU.


**kbuild as the whole network** (`QEMU_NET_PEER`, the `x86_64-peer` preset). Everything above is
QEMU's user-mode network with kbuild disturbing frames in flight. That network is also what keeps
two things out of reach of a guest: it offers no SACK-permitted on a SYN and sends no ICMP
destination-unreachable, so neither selective acknowledgement nor a refused datagram can be
exercised however the frames are mutated. The alternative is to be the network:

```
-netdev dgram,id=kt_net,local.type=inet,local.host=127.0.0.1,local.port=<local>,
        remote.type=inet,remote.host=127.0.0.1,remote.port=<remote>
```

One raw Ethernet frame per datagram, both ways, with no NAT, no gateway and no filters: a
disturbance this peer wants to make, it makes by choosing what to send. It is built in stages,
because the `net` check gates on three TCP rounds and an inbound connection into the guest's own
listener — a TCP endpoint that both accepts and originates.

- **Stage one** answers ARP and counts what crosses, which proves the socket carries frames both
  ways rather than inferring it from the backend's existence. An earlier attempt hand-built a
  QEMU command line, omitted what the platform supplies, and never brought the card up, so no
  frame arriving proved nothing: the netdev is substituted inside kbuild's own machine
  construction for that reason.
- **Stage two** is the datagram half: an echo reply for each request to the gateway, the four
  datagrams that tell the guest which ports to use, an acknowledgement for each echo it returns,
  a service answering `kintane-udp-request <tag>` at the gateway's address, a port that answers
  nothing, and one datagram sent as two IPv4 fragments. Under `-netdev user` those services are
  loopback sockets QEMU forwards to, and the fragmenting is the downstream relay's; with no NAT
  there is nowhere else for them to live, so the peer sends the two fragments itself — the same
  thing seen from the other side.
- **Stage three** is a TCP endpoint that accepts, which is what the three rounds need. Where the
  user-mode network has a relay between the guest and the network to drop and swap segments, here
  there is no between: every condition the check gates on, the peer produces by choosing what to
  send.
  - **Each connection's first in-order data segment is dropped, once.** A lost segment is one
    that never arrived, so the peer answers it with silence rather than a refusal and the guest
    must notice by itself. With a one-segment request its retransmission timer does that; with
    the bulk round's four, the three behind the hole draw three duplicate acknowledgements and
    its fast retransmit sends the lost one at once — which is the only way that path is reachable
    in a guest.
  - **Segments past the hole are held, not discarded**, and each earns an acknowledgement naming
    what is still missing. Discarding them would cost a window of retransmissions where the
    protocol costs one.
  - **The reply goes out as two segments, the half in front sent second**, so the guest holds one
    out of order and joins it to the stream when the rest arrives. One segment would leave
    nothing to hold, and the check requires both the holding and the joining.
  - **A connection is forgotten only once both ends have finished.** Forgetting it when the guest
    acknowledges the peer's FIN left the guest's own FIN, which follows, arriving for a
    connection the peer no longer had — unanswered, so the guest stayed in LAST-ACK and its round
    never reached CLOSED. That is what the `peer-closes` round is there to catch.

A boot of `x86_64-peer` reports it from both ends at once, the guest's check and then the peer's
own count:

```
  net        line 17, MSI-X; gateway 52:55:0a:00:02:02; 4 echo replies; udp port 5555,
             3 round trips; 4 fragments, 2 datagrams reassembled; tcp port 61753,
             closed by the kernel [syn-sent established fin-wait-1 fin-wait-2 time-wait]
             and by kbuild [syn-sent established close-wait last-ack], ...
  linux net  tcp client ok; server ok; poll ok (two connections, 4 announcements);
             udp ok; peek ok (kbuild told of its listener 1 time); waits woken by the
             card 33, armed for a TCP timer 15, polled 0; closed in order, every buffer
             back; 0 objects left, 0 frames left ok
  net peer:  87 frames in, 1 ARP requests, 1 answered, 4 echoes answered,
             3 acknowledgements, 12 service replies, 51 rounds of announcements,
             7 connections, 7 first segments dropped, 3 duplicate acknowledgements,
             7 replies sent back to front, 3 connections opened, 3 verdicts sent
```

The peer counts the two kinds of connection separately, because they are not the same thing to
it. Seven *connections* are ones the guest opened and this end accepted, and each contributes one
first segment dropped and one reply sent back to front — the disturbances of stage three, which
are why seven connections serve fewer rounds than seven: a dropped first segment makes the guest
open the round again rather than wait. Three *connections opened* are the ones this end originated
into the guest's listener, one for each tag the guest announced, and each earns one verdict. The
drop never applies to those: losing the guest's reply on a connection this end opened would slow
the exchange with no check asking for it.

Those counts, and everything the check gates on, are the same every boot. Four figures in that
transcript are not, and should not be read as fixed: the guest's ephemeral port, its interrupt
count, and the peer's frames-in and rounds of announcements, which depend on how long the guest
takes to reach the check while the peer is announcing into it.

**`x86_64-peer` boots rc=0 and is in `scratchpad/verify.sh`'s preset list**, in both the boot loop
and the in-kernel loop. It joined at stage four, which is the endpoint that connects as well as
accepts. `linux net`'s `server`, `poll` and `peek` modes each open a listener and wait for a
connection to arrive at it, so until kbuild could *originate* one they waited for a connection
that never came and the run ended `timed out after 30s with no exit signal from the guest`.

Nothing sends unprompted, and nothing needed to. The guest announces each listener with
`kintane-tcp-listening <tag>` every 500ms for as long as it is waiting, so the announcement is
itself the prompt: the peer answers it with a SYN. A tag it has already served earns nothing, and
a tag whose SYN went unanswered earns that same SYN again, which makes a lost one recoverable on
the next announcement without a retransmit timer anywhere in the peer.

Two things about the guest's side shape how a connection is identified. `poll` announces two
different tags for one listener, so both of its connections reach guest port 7777 and the guest's
port alone cannot tell them apart; the peer keys a connection by both ports and speaks from a port
of its own, drawn from 49152 upwards. And the guest's `serve` reads the verdict line and then
reads again expecting end-of-stream, so the peer sends the verdict and the FIN in one batch.

**Nothing said above about selective acknowledgement or the quiet port changes yet**: both stay
host-tested until the peer offers SACK-permitted and sends a destination-unreachable, which is
stage five and wants a solid endpoint beneath it.

### 2h. Waiting on many things at once

Two checks, one native and one Linux, for the one mechanism: a wait over a set of things, where
whichever becomes ready first ends it.

**`readiness`** runs `init` in a poll mode holding three objects — a channel whose other end the
check holds, an event the check signals, and a completion queue its own timer delivers to — and
waits on all three with one call. Over that channel it asks the check to make one of them ready
after a delay it names, so every wake is deliberate rather than incidental:

```
  readiness  init waited on a channel, an event and a timer at once; 18 of 18 wakes delivered in
             150 ms, 20 blocks, 18 woken, 243 looks; 0 objects left, 0 frames left ok
```

In order: a wait with nothing ready runs out, and not before its timeout; a zero timeout answers
at once with nothing ready; the event, then the channel, then the timer's completion each comes
back as the member that is ready, and is consumed so it is not ready again; and then sixteen
rounds ask for the event a little later each time. Those rounds vary when the wake lands relative to the wait,
and each one must end with the event reported ready.

**What they do not cover.** A wait looks at its set, registers on the queue, looks again, and only
then blocks. The dangerous window is between the first look and registering, and these rounds do
not reach it: this check serves requests on a millisecond poll, so the wake lands after the waiting
thread is already blocked, whatever delay the round asked for. Removing the second look from
`WaitQueue::wait_once` — the check that closes that window — leaves this check passing, 18 wakes of
18. It is recorded here rather than implied away: the window is sub-microsecond and cannot be aimed
at from another thread without a hook inside the wait, and that hook does not exist. What the
rounds do prove is that a wake is delivered and acted on every time, rather than a wait expiring at
its deadline and finding the thing ready afterwards, which is what the counters distinguish.

The boot fails if the program does not exit with its success code, if a request went unanswered,
or if nothing really blocked and was woken — the counters above are what make "waited" mean
waited. A lost wake shows as a round that never ends, so the program's patience is far longer than
a round takes and the check reports it rather than hanging the boot. The difference the wake path
makes is visible in those numbers: with the set queue woken only by channels and the card, the
same run delivered 13 wakes in 60 seconds with 2 of them woken — the rest were waits expiring at
their deadline and finding the event already signalled.

**`poll`, inside `linux net`**, is the same mechanism through Linux's calls. The check announces
the guest's listener to kbuild twice under two numbers, so kbuild makes two connections into one
listener, and the program serves them in the order they arrive while watching the listener for the
next one:

```
  linux net  tcp client ok; server ok; poll ok (two connections, 4 announcements)
```

It waits with `ppoll` over the listener and its connections; serves each request and checks
kbuild's verdict; requires a wait over an idle listener to run out; repeats it through `pselect6`,
and through `select` and `poll` on the architecture that has them; adds both connections to an
`epoll` set and requires `epoll_pwait` to report them; and requires an `EPOLLET` interest to be
refused with `EINVAL`, since edge-triggered is not built. A connection that arrives carrying
nothing is QEMU's port forward accepting before kbuild is there, not a failure: it is closed and
another is waited for, up to a bound. The `linux net` verdict also requires every `epoll` set to
have been let go of, as it already requires of sockets.

Each property was falsified: the mutation applied, the boot run, the failure seen, and the file
restored.

| Mutation | Result |
|---|---|
| A socket is never reported ready (`ready_of`) | `linux net`: `poll NEVER EXITED, A THREAD NEVER ENDED`; the boot fails |
| A wait runs out at once whatever timeout it was given | `readiness`: `init exited 0x710, WRONG` — the step that requires a timeout not to fire early — with `A REQUEST WAS NEVER ANSWERED, NOTHING REALLY BLOCKED OR WAS WOKEN` |
| The second look after registering is removed from `WaitQueue::wait_once` | **`readiness` still passed**, 18 of 18 wakes delivered. The window it closes is not reached by this check; see above. |

**`peek`, inside `linux net`**, is what a receive leaves behind, and what a message of several
buffers carries. The mode runs against kbuild's datagram service and its TCP service:

```
  linux net  tcp client ok; server ok; poll ok (two connections, 4 announcements); udp ok; peek ok
```

It peeks a datagram twice and requires both to answer the same bytes, then receives and requires
those bytes again, then requires nothing to be left — one datagram arrived, and two peeks took
none of it. It peeks into a buffer shorter than the datagram, with and without `MSG_TRUNC`, and
requires the datagram to survive both. It sends one datagram gathered from two buffers and
requires the reply to arrive scattered across two more, in order, rather than crammed into the
first. It requires more buffers than the personality carries to be refused with `EOPNOTSUPP`
rather than half carried. On a stream it peeks with `MSG_WAITALL` for the whole reply, then reads
the same bytes again, because a peek moves neither the ring's head nor the inbox's slot.

A peek that finds fewer bytes than asked for waits rather than looping: it would otherwise see
the same bytes it had already seen and spin. That was a real fault in the first version of this
code, and it hung the boot at `linux net` until the wait itself was made to decide whether enough
had arrived.

| Mutation | Result |
|---|---|
| A peek takes the datagram (`datagram_peek` calling `udp_recv_from`) | `linux net`: `peek exited 0x00000000000000dd, WRONG` — step 221, where the second peek finds nothing |
| A receive fills only the first buffer it was given (`scatter`) | `linux net`: `peek exited 0x00000000000000e2, WRONG` — step 226, where the reply must be spread over both |

A step number is the exit status a failing step ends with, and a status is eight bits: a step
above 255 comes back truncated. This mode's steps are 220 to 229 for that reason — the band first
assigned, 310 to 329, would have reported step 315 as 59, which is the mode's own success code,
and graded that failure a pass.

Timing is measured on the native side only. This personality has no `clock_gettime`, so a Linux
program here cannot read a clock to say its timeout ran out on time; `readiness` is where that is
checked.

### 2i. Racing a wait, on purpose

The section above ends with a confession: the window between a wait's first look and its
registering is sub-microsecond, nothing outside the wait can aim at it, and deleting the second
look — the check that closes it — left every existing test passing, 18 wakes of 18. A guarantee
nothing can falsify is a guarantee on paper.

`WAIT_RACE_TEST` compiles a stall point into `WaitQueue::wait_once`, between the look that
precedes registering and the registration itself. A thread arms itself, enters a wait whose
condition is false, and parks there; the boot thread makes the condition true and wakes the
queue while it is parked; then it lets the waiter go on to register. Two cases run: a plain
`WaitQueue` with a condition of its own, and the set path (`readiness`) with a real event
object, where the racer signals the event and calls `readiness::wake` — the path a program's
`poll` is woken by.

```
  waitrace   a wake in the window before registering was not lost; a queue ok in 476 us,
             0 blocks; a set ok in 1677 us, 0 blocks; 2 stalls taken; 0 objects left ok
```

**What it reads is not "was it woken" but "did it block".** Both a fixed and a broken kernel end
with the condition true, because the wait's deadline expires and it looks once more on the way
out; a check that asked only "did the condition hold" would pass either. A kernel that looks
again after registering sees what the waker did in the window and never blocks at all, so the
count that separates them is the block count, and this check requires it to be zero. It also
requires one stall per case, so a run whose hook never fired says so rather than passing.

| Mutation | Result |
|---|---|
| The second look after registering is deleted from `WaitQueue::wait_once` | **the boot fails**: both cases report `IT BLOCKED, so the wake in the window was lost; 1 blocks`. This is the mutation section 2h records as uncatchable |
| The handshake does not name its case (the check's own first version) | both cases reported `ok, 0 blocks` with only **1 stall taken**: the boot thread saw the previous case's arrival, made its thing ready and released before the waiter had entered the next wait, which then found it ready at its first look. Caught by the one-stall-per-case requirement, and the reason the handshake carries a case number |

That second row was not a planned falsification — it was the first run of the check, and it is
kept here because it is the same failure this whole section exists to prevent: a test that
reports success while racing nothing.

**What it costs a kernel that does not want it.** Nothing. Without the symbol, `waitrace_off.rs`
takes the module's place: `stall` is an empty inline function, so the wait path carries neither a
branch nor a symbol, and the check passes without printing a word. The default build of every
preset is unchanged.

**The last wall-clock bound in this area went with it.** `spawn::wait_exit`, which every check
calls through `spawn::end_threads` to reap the threads it started, waited three seconds of wall
clock for a thread to exit and then reported "a thread did not end". Under an emulator that
measured the host: a soak lost a run at 141 s that way. It now judges the thread by the slices
the scheduler charged it, sharing `procs::await_slices` with the nine bounds the tenth round
converted, rather than keeping a second rule for the same question.

What that changes, stated plainly: a thread that is *running* and not exiting fails after 128
slices, which is prompt and load-proof. A thread that is not running at all — blocked, or on a
CPU the host is not scheduling — is charged nothing, so the wait falls through to
`await_slices`'s starvation floor, five seconds of guest time, where the old bound used three.
The worst case is therefore slower than it was, deliberately: five seconds of a guest that is
genuinely stuck is cheaper than a false failure on a busy host.

| Mutation | Result |
|---|---|
| `wait_exit` never sees the thread exit | **the boot fails.** Every check that reaps threads pays the starvation floor, because a thread that has already exited is charged no slices, so the run took 123 s rather than failing at one bound |

**What else the hook reaches.** The window belongs to the wait rather than to any one thing
waited on, so anything whose readiness another CPU can change while a thread is in there can be
raced from here. Two are covered. Left for later, reachable the same way: a channel closed
against a lookup that holds it, a timer expiring against the arming of the queue it delivers to,
and a socket whose peer closes while a wait is in the window.

### 2j. A program built for the hard-float target

`user/fptest` is built for `targets/<target>-hf.json` rather than the kernel's own
specification, and multiplies, adds, divides, subtracts and converts doubles — every value
through `core::hint::black_box`, so the constant folder cannot compute the answers at compile
time and ship a program with no arithmetic in it. It exits `0x77`, or with the number of the
first step that disagreed (200 to 206).

The interesting check is not the arithmetic, which a soft-float build would get right too, by
calling `__muldf3`. It is that the instructions are there at all. `kbuild` disassembles the
linked program after every build and requires floating-point arithmetic in it:

```
  float   userfp holds 8 floating-point instructions
```

A build whose flavour quietly fell back to the kernel's target — a dropped `rustc-abi` change,
a cache entry served across targets — produces a program that behaves identically and holds
none, and the build fails there rather than passing.

**Why it counts mnemonics and not registers.** The obvious check, "does a floating-point
register appear", is unsound, and its failure is instructive. On aarch64 a *soft-float* `init`
matches `\bd[0-9]+\b` **59 times** — more than the hard-float program's 38 — because objdump
prints each instruction's encoding beside it and `sub x9, x27, #1` encodes as `d1000769`. The
`d1` is a byte. On x86_64 the same check happens to work, a soft-float program having no `xmm`
at all, which is exactly the coincidence that would make a broken check look sound on the port
someone tested it on. Arithmetic mnemonics discriminate on both: zero in every soft-float
program, eight in each hard-float one.

| Mutation | Result |
|---|---|
| `rustc-abi: softfloat` restored in the hard-float specification | the build fails: `userfp` holds no floating-point arithmetic |
| x86_64 `fxrstor64` restores from the context being switched *away* from | `fpu` fails: REGISTERS DID NOT SURVIVE THE SWITCH, first lost register 0, second lost register 0 |
| aarch64 FPSIMD restore reads its base from `x0` rather than `x1` | the same, on that port |
| `-neon` removed from the kernel's own aarch64 target | the build fails on the assertion in `arch/aarch64/src/context.rs`: *NEON/FP is enabled for aarch64: d8-d15 are callee-saved and the context switch must now save them* |
| a kernel function given `asm!("fmul d0, d0, d0")` | the build fails: *instruction requires: fp-armv8*. The assertion above catches the target being changed; this catches a single file reaching for the registers anyway |

Both of those keep the save, so the `{fpu}` operand is still used and the build is still
honest; only the restore is wrong. A mutation that removed the instructions outright would
leave the operand unused, which is a compile error rather than a check that fails.

**Running it.** `kernel/main/src/fpu.rs` runs the program in a guest and grades its exit. That
is what turns the x86_64 enable bits from a reasoned claim into a tested one: until it existed
nothing had executed a floating-point instruction in a guest, and a fault on the first SSE
instruction would have gone unnoticed. It now fails the boot.

It then runs what the arithmetic cannot reach. Eight vector registers are loaded with values
derived from a seed, yielded across sixty-four times and read back, while a second thread of
the same process holds a *different* pattern in the same registers, pinned to another CPU
where there is one. The phase runs twice with the seeds swapped, so each pattern is the graded
one in turn. A thread whose registers were clobbered exits `210 + n` and the check names which
register came back wrong.

```
  fpu        arithmetic ran in a hard-float program; eight vector registers held across
             64 yields beside a thread holding others, both ways round; 0 objects left,
             0 frames left ok
```

The load, the system call and the read-back are **one `asm!` block**, and the call is issued
directly rather than through `abi`. In plain Rust the check would prove nothing: nothing
obliges the compiler to keep those values in vector registers across a call, and values spilled
to the stack and reloaded compare equal whether or not the kernel saved a single register.

Only the graded thread exits. A process carries one exit code and `record_exit` keeps the first
one recorded, so two threads racing for it would grade whichever won — which is how the first
run of this check reported a lost register that was really a killed process.

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
- **pages** — buddy allocator churn on a pool of its own;
- **net** — echo requests to the gateway and UDP round trips with kbuild, on a machine with a
  network card ([2g](#2g-network));
- **tcp** — TCP round trips with kbuild, closed from each side in turn and each with a
  retransmission, on a machine with a network card ([2g](#2g-network)).

Every second of guest time the auditor stops every workload at a checkpoint, where it
holds nothing that would make the books inexact, and checks them:

- the heap's bytes in use are back at their baseline;
- the heap's failure count equals the refusals the workloads handled;
- channel handle counts are exact and nothing is queued;
- `Vm::audit` passes, and the vm frame pool is full when nothing is mapped;
- `Buddy::check` passes, with every page free;
- the network stack's pool is full, and every receive buffer is with the card or holding a
  frame;
- no TCP connection holds a ring, and the pool's books agree with what connections hold;
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

**The user process cycle is judged in slices, not wall-clock time.** Between audits the
auditor builds a process, waits for it to make progress (on one CPU) or to be served on
each of two pinned CPUs, stops it and tears it down (`procs::stress_cycle`). On one CPU the
first wait used to be a fixed 80 ms of guest time. Under TCG the guest's clock follows the
host's, so on a loaded host that window measured the host. A vCPU the host did not run
still ran out its window, and the fixed-rate sleepers above the process took a larger share
of what the vCPU did execute. The 20-second run on `x86_64-qemu` failed three times in the
seventh round with `user process: a process made no progress`, each time passing when rerun
alone.

Every wait in the cycle is now judged by what the scheduler gave the thread, as the timer
interrupt counts it ([architecture](architecture.md)): slices it *ran*, and slices it was
*passed over* for (ready on its CPU while a thread no more urgent ran there).

- **It ran 16 slices and made no progress:** a process that runs without advancing fails,
  however long that took.
- **It was passed over for 64 slices per slice it ran, and made no progress:** a thread the
  queue does not reach fails too. Round robin passes it over once for each of the four busy
  workloads at its level. The bound was first 64 slices in total. The falsification below
  showed that a process which runs without advancing reaches that at about the same moment it
  reaches 16 slices run, and it was reported as passed over. Counting passes per slice run
  leaves a thread that runs to the first rule.
- **It did neither for 5 s:** the remaining case is a thread that is blocked, queued on a CPU
  taking no interrupts, or ready behind more urgent threads. Fixed priority allows the last
  of these, and only its length tells a busy moment from starvation, so this bound is still
  guest time. It is 62 times the old window, and a sixth of the watchdog's 30 s.

The heartbeat reports the most slices of each kind any passing wait needed. Unloaded,
`x86_64-qemu` needs at most 2 run slices and 9 passed-over slices.

**Under load.** Six other QEMU guests, each running this stress kernel on four vCPUs
(host load average 13 to 24 on 16 cores), ran beside the single-CPU 20-second run:

| Check | Runs | Failed |
|---|---|---|
| The old 80 ms window | 10 | 9: eight `a process made no progress`, one in the boot `preempt` check (below) |
| Slices | 10 | 0; at most 5 slices run and 17 passed over before progress |

With only other agents' work loading the host, the old window also failed 2 runs in 20.

**Other bounds that are still durations**, and why each stays:

- the boot `sleep` check's three slices: lateness *is* wall time, and what it checks. The
  stress run's sleeper no longer fails on lateness alone — see
  [a late wake-up](#a-late-wake-up-is-the-schedulers-only-if-it-passed-the-sleeper-over);
- `waits`' 10 s and 5 s patience and `procs::wait_exit`'s 1 s drain in the boot check:
  generous bounds on something that normally takes milliseconds;
- `PARK_WITHIN`'s 3 s and the audit's `STALL_WAIT`: these now judge only a workload the
  scheduler has barely run, which is the one case no count of its own slices can judge. See
  [the workloads' bounds](#the-workloads-are-judged-by-their-slices-too) below;
- `spawn::PATIENCE`'s 3 s, which `end_threads` waits for each of a process's threads to
  exit. It is shared with the boot checks and left alone here; it is what says `a ... process's
  thread did not end` when a pair is still running as the wait gives up;
- none in the boot `preempt` check any more; see below.

**The boot `preempt` check is judged in interrupts and slices too.** It used to require 12
interrupts in its 300 ms window and `high` awake within 20 ms of its deadline, and under the
load above it failed bring-up in 4 of 15 runs with 7 to 11 interrupts and wakes 45.7 to 56.2 ms
late. Neither number is the kernel's to answer for: a host that stalls the emulator moves the
guest's clock on without delivering the interrupts that time would have held. What the kernel
does with each interrupt is its own, so the check now requires:

- **slices:** every boot-CPU interrupt that found the workers contending armed the next no more
  than a slice away, as `timekeeping::program` reports it, with at least two such interrupts.
  That is what the interrupt count stood for: on x86 the PIT's 55 ms reach hides a missing slice
  from the tickless bound;
- **the wake-up:** the interrupt before the one that woke `high` came before its deadline, so no
  interrupt after the deadline passed `high` over, and `high` ran inside the interrupt that
  woke it, before the next. Its lateness is still printed in microseconds.

And boot no longer trusts a window. It stops the workers once their 250 ms have passed *and*
`high` has woken, and waits for every thread to finish a slice at a time, both bounded by 5 s of
guest time. The loaded runs below showed the fixed window failing a boot outright, too:
a stall at the start carried the guest clock past 250 ms before the workers had run at all, so
boot stopped them unrun (`NOT INTERLEAVED`, 0 spins) and idle waited more often than the window
counted interrupts (`DID NOT HALT`). Calibration keeps the fastest of four single slices, since
a stall only ever removes spins from one.

Old and new boots alternated beside six busy QEMU guests (the stress kernel on four vCPUs each,
restarted before every boot when one had stopped, since that kernel ends on a failed audit under
this load), booted directly under QEMU and stopped once the `preempt` block was out. The host has
16 cores; its load average, with other work on it too, was 22 to 33 throughout:

| Check | x86_64-qemu failed | aarch64-virt failed |
|---|---|---|
| old | 1 of 10: 11 interrupts, `NOT INTERLEAVED`, `DID NOT HALT` (the window) | 3 of 10: woken 37.2, 37.2 and 82.3 ms late |
| new | 0 of 10 | 0 of 10 |

Three of the new boots measured what the old check would have failed: x86_64 woken 25.8 ms late,
and once 6 interrupts in 302 ms with a 78.1 ms wake; aarch64 woken 21.9 ms late. Each ran `high`
inside the interrupt that woke it, with no interrupt after its deadline passing it over, and
armed a slice on every contended interrupt. A first attempt at this load was discarded: its
guests stopped on their own audits one by one, so the load it reported was not the load it had.

What the reworked check still catches, each mutation confirmed applied and booted on
`x86_64-qemu`:

| Mutation | Result |
|---|---|
| Preemption disabled: the tick never reschedules | `NOT INTERLEAVED`, `DID NOT HALT`, `high` `NOT IN THE INTERRUPT THAT WOKE IT`, `AFTER THE WORKERS FINISHED` |
| The tick wakes every sleeper but `high` | `NEVER WOKE`, after the 5 s bound rather than a hang |
| Idle enables interrupts and loops instead of halting | `idle waited 17543 times BUT DID NOT HALT UNTIL AN INTERRUPT` |
| A contended interrupt arms no slice | `0 of 3 contended interrupts armed a slice`; the tickless bound fails too (19 slices' worth) on this LAPIC-timed preset |
| Timers popped a slice late | `AN INTERRUPT AFTER ITS DEADLINE PASSED IT OVER` |
| `high` no more urgent than the workers | `HIGH DID NOT RUN FIRST`, `NOT IN THE INTERRUPT THAT WOKE IT` |
| The local APIC timer's EOI sent after the hook | `A THREAD STOPPED RECEIVING INTERRUPTS` (50 slices' worth), `AFTER THE WORKERS FINISHED` |

**A real bug the window hid: two threads on one stack.** Under load the old check sometimes
went on to fault. Another branch saw `thread table INCONSISTENT` and then a fault at rip 0x5,
and 3 of the 60 loaded boots of the old check above did the same (none of the 60 of the new
one, before or after the fix). The sequence:

1. The fixed window ended before a worker or `high` had exited.
2. `reap` refused that thread, which the report called an inconsistent table.
3. `shared::run` went on anyway. Its sleep phase spawns on stack slots 1 to 3, which belonged
   to the workers and `high`, and nothing checked that a slot's previous thread was gone.
4. The worker resumed on frames the sleeper had written, and returned to whatever address
   was there.

Base 8bfa611 reproduces it without any load when boot wakes the moment it stops the workers
(`BOOT_WAKES_AFTER` = `WORKERS_STOP_AFTER`): `thread table INCONSISTENT`, then `#PF` with rip
equal to cr2. The check now waits until its threads have exited, not for a flag each sets on
the way out, which a thread preempted between the two has set without being reapable. A thread
not given back fails the check as `A THREAD HAD NOT EXITED`, and the shared checks do not run
on its stack. Under all of that, `spawn` and `spawn_prepared` refuse a stack slot whose last
thread is still in the table, so no other caller can repeat it.

| Mutation, with boot reaping before its threads can exit | Result |
|---|---|
| Nothing else | `A THREAD HAD NOT EXITED`, `shared not run: a scheduler thread's stack is still in use`; no fault |
| The shared checks run anyway | `kheap mt spawn refused`, `processes could not start the workers`, and the rest fail; no fault |
| The shared checks run, and `spawn` no longer refuses a slot in use | `#PF` at rip `0x0000000000000005`: the fault the other branch saw |

**What the slice check was shown to catch**, each mutation in a 20-second run on
`x86_64-qemu` unless named:

| Mutation | Result |
|---|---|
| The process runs but never publishes a pass (`user/init` skips the write when the kernel sets a word) | `a process ran its slices and made no progress` at 3 s. With the first, total passed-over bound it read `was passed over`, which is why that bound is now per slice run |
| The process thread is never made ready (`spawn_on` skips the run queue once) | `a process was passed over for its slices and made no progress` at 0 s |
| The process pinned to a CPU that never joined, on `x86_64-qemu-smp` | `a process thread could not be moved` at 0 s: `set_affinity` refuses an offline CPU, so that thread cannot exist |
| The vm workload (priority 5) spins from its start, above the process (4) | `a process made no progress: ready, behind more urgent threads` at 10 s, from the 5 s bound |
| A priority inversion: heap A (4) holds a flag the sleeper (8) waits on, and the page workload (6) spins while it is held | `a workload did not reach a checkpoint: heap A` at 3 s. The audit's 3 s park bound caught the starvation before a process cycle's 5 s bound could. Held for only 100 heap iterations, heap A finished before the page workload woke, and the run passed |

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
  the initiator, and none stalled. The heartbeat also reports how long they waited for their
  answers, mean and worst.

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

#### The workloads are judged by their slices too

The auditor's two per-workload bounds were durations of guest time: three seconds to reach a
checkpoint once asked, and an iteration in every one-second audit interval. Under an emulator
that measures the host, for the reason above, and it is the same fault the process cycle was
cured of — left in the workloads.

Each workload's thread is remembered when it is spawned, and both bounds are now read from the
slices the timer interrupt charges it:

- **`PARK_SLICES`, 512:** a workload that runs this long without reaching a checkpoint fails,
  however long the host took over it. The bound has to clear the longest honest iteration:
  the network workload waits up to a second for a round trip and the TCP one up to two,
  polling with millisecond naps, which the scheduler charges as running. A first try at 128
  failed a healthy run at four seconds with the network workload 89 slices into an iteration.
  Five hundred is over five seconds of CPU, more than twice the longest wait any workload
  makes.
- **`PROGRESS_SLICES`, 512:** the same, for slices run without completing an iteration.
- **`PARK_WITHIN`, 3 s, and `STALL_WAIT`, 5 s:** a workload that is *not* running earns no
  slices, and only a duration tells a sleeper mid-nap, or a thread behind more urgent ones,
  from one that will never answer. These two apply only where the scheduler has charged the
  workload fewer than `RUNNING_SLICES` since the request; a workload that is running keeps its
  whole slice allowance.

The heartbeat carries how close a passing run came to each slice bound — `slices to park max`
and `without progress max` — so the margin is a number somebody can read rather than a guess.
Unloaded, a 45-second run on `x86_64-qemu-smp` at eight CPUs needed 176 slices to park; beside
a second soak, a two-hour run on the same preset needed 304 of the 512 allowed, and never
missed an iteration in an audit interval at all.

| Mutation | Result |
|---|---|
| No workload is ever asked to park | `a workload ran its slices without reaching a checkpoint: block B`, at 1 s |
| heap A runs but never records an iteration, with `STALL_WAIT` raised so only the slice bound can fire | `a workload ran its slices without progress: heap A`, at 6 s |
| The sleeper blocks for ten seconds, so it cannot answer a park request | `a workload did not reach a checkpoint: sleep`, at 1 s |
| The sleeper parks and sleeps as usual but never records an iteration | `a workload made no progress: sleep`, at 4 s |

#### A late wake-up is the scheduler's only if it passed the sleeper over

The sleep workload failed the run on any wake more than half a second after its deadline.
That is wall time, and under an emulator the guest's clock follows the host's: a vCPU the host
stops running wakes late with nothing wrong in the kernel. A two-hour soak on
`aarch64-virt-smp` at eight CPUs died this way at 453 seconds, beside a second soak, with the
host at load 19 — the run's worst lateness was 437 ms by then, against a 500 ms bound.

What the kernel answers for is what it did with the interrupts it took. The sleeper is the
most urgent workload, so an interrupt that found it ready and ran something no more urgent is
the scheduler failing to reach it. A wake-up past `MAX_LATE` is now looked into rather than
failed outright: with `LATE_PASSES` slices passed over while ready, it fails and says so; with
none, nobody ran on that CPU at all, which is the host, and it is counted and printed in the
heartbeat as `late with the CPU elsewhere`. Waking *before* a deadline still fails outright,
which is the half of the check an emulator cannot forge.

| Mutation | Result |
|---|---|
| Every wake over a millisecond late, and all of it blamed on the scheduler (`LATE_PASSES` 0) | `a sleep woke late after the scheduler passed it over while ready`, at 1 s |
| Every wake over a millisecond late, judged as built | the run **passes**: 453 late wakes, worst 733 ms, every one counted as the CPU being elsewhere and none blamed on the scheduler |

The second is the point of the change: on a host running two soaks and five other jobs, three
quarters of a second of lateness was reported and not one wake-up was the scheduler's doing.

#### A wait charged nothing at all is the host, not a starved thread

`await_slices` ends in `Starved` when neither count reached its bound, and the caller reads the
thread's state to say why. One of those states — ready on the CPU it was pinned to — was
reported as `never served: ready on the right CPU, never scheduled`. Another fork hit exactly
that on unmodified master, at eight CPUs, while this branch's soaks had the host at load 20 to
35.

`Starved` now carries what the thread was given. Both counts zero means not one timer interrupt
on that CPU saw the thread in five seconds, ready or running: nothing ran there at all, which is
the host and not the scheduler. That case is counted and printed in the heartbeat as
`none charged`. A thread that was charged something and still made no progress fails as before —
dropping the process threads' priority below every workload, so they are ready and passed over,
still fails a run at 7 s.

#### The watchdog was measuring the host too

`kbuild stress` kills a guest that stops printing its heartbeat, which is the only way to catch
a run that hangs with interrupts masked. Its allowance was thirty seconds of wall time, and the
guest prints one heartbeat per second of *its* time — so on a machine running several eight-CPU
guests at load 18, a healthy soak was killed as hung with its counters still climbing, no audit
failed, and heartbeats still arriving.

A guest that has really hung never prints again, so a longer allowance costs only how soon that
is noticed, never whether it is. It is two minutes now: four times the worst gap measured on a
loaded host, and still a short wait beside a run of hours.

#### A message that arrived late is not a wake-up that was lost

The waiting-pair program's `recv_promptly` returned `TimedOut` for two different facts: nothing
received inside `WAKE_NS`, which is a wake that never came, and a message that *did* arrive but
took longer than `LOST_NS`. Both exited 0x603 or 0x613, and the auditor called either one a lost
wake-up. A two-hour soak on `x86_64-qemu-smp` at eight CPUs died that way at 42 seconds beside a
second soak: the message arrived, a second late, because the host was not running the sender's
CPU.

A message that arrived is proof the wake was not lost. So the slow case exits 0x608 or 0x617 and
is counted as a *slow exchange*, printed in the heartbeat beside the wait counters; a receive
that saw nothing at all still exits 0x603 or 0x613 and still fails the run.

Seeing nothing inside the timeout has the same ambiguity one level down: a wake that was lost
and a sender the host never ran are indistinguishable from inside the program. So a timed-out
receive now asks once more without waiting. A message already queued was sent and merely not
collected in time, which is the slow case; an empty channel is a wake that never came. That
question is the guest's own, and needs no clock to answer.

The wait around that exchange had the same fault: the cycle gave its two threads
`PAIR_PATIENCE` to finish and called them still alive a lost wake-up, which a 30-minute soak
hit at 49 s. It is now judged like every other pair wait — `PAIR_SLICES` between the two
threads, with the duration kept only for a pair the scheduler is barely running.

| Mutation | Result |
|---|---|
| The peer never sends, so the wake really is lost | `a waiting process's receive timed out: a wake-up was lost`, at 2 s |
| The pair reports a slow exchange on a receive that did arrive | the run **passes**, with `slow exchanges 23` in the heartbeat |
| The pair never stops exchanging, so its threads cannot finish | `a waiting process did not finish: a wake-up was lost`, at 36 s — the wait's own slice bound, not its patience |
| The peer never sends, so the retry finds an empty channel | `a waiting process's receive timed out: a wake-up was lost`, at 2 s |
| `LOST_NS` cut to a millisecond | the *boot* `waits` check fails and bring-up stops; it proves nothing about the stress cycle |

#### A slow shootdown is not a broken one

The audit failed on `mismatches + stalls` together. They are not the same kind of fact. A
mismatch is the kernel's: the answers were not the online CPUs, or the books did not balance.
A stall is a wait that spun `STALL_SPINS` before its answers arrived — and that count is the
*waiting* CPU's own spins, which a host that stops running the CPU being waited for runs up
without anything here going wrong.

A two-hour soak on `aarch64-virt-smp` at eight CPUs, running beside a second soak, failed this
way at 65 seconds, with the mean answer holding at 236 µs and the worst at 92 ms; a 90-second
rerun passed with a worse worst-case wait of 219 ms. So the audit fails on mismatches alone,
and every heartbeat carries the stalled-wait count beside the mean and worst answer, where a
kernel that grows slower at this shows it. A shootdown that is never answered still fails the
run: the wait never returns, the heartbeat stops, and kbuild kills the guest.

| Mutation | Result |
|---|---|
| Every request recorded as answered by the wrong CPUs | the *boot* shootdown check catches it first: `bring-up failed; not starting the scheduler`, and the audit never runs |
| The same, but only after the boot check's first requests | `tlb shootdown: a shootdown was answered by the wrong CPUs`, at 9 s |

The first mutation is why the second exists: a check that fails at boot proves nothing about
the one in the audit, so the mutation has to let bring-up through to reach it.

### 3a-bis. The soak

`kbuild soak --duration <len>` is a stress run nobody watches. It builds and runs the stress
image exactly as `stress` does — the verdict is still the guest's exit status — and adds the
two things a long run needs.

**The trail.** Every heartbeat, the verdict, and the failed audit when there is one are written
to `build/<target>/soak-<len>.trail`, whatever the outcome, because a run that failed at the
ninth hour is exactly the one whose trail is worth reading after the scrollback is gone.

**The drift.** The trail is compared with itself: the first window of the run against the last,
where the window is a sixth of the run between ten seconds and ten minutes. A run can pass every
audit and still be leaking, and that is what a long run is for. The comparison is arithmetic on
the guest's own numbers; nothing in it decides whether the run passed.

**One test does not fit every number**, and using one was a mistake worth writing down. A
heartbeat carries three sorts of number, and the guest says which is which in the
`stress field kinds:` line it prints once — beside the code that prints the numbers, so a field
added without a kind is read as a count rather than guessed at from its name in `kbuild`.

| Kind | Compared by | Flagged when |
|---|---|---|
| A **count**, which only climbs | its rate in each window | the rate moves by more than a quarter; it stood still early and climbed late; or it goes backwards, which no count may do |
| A **level** — a high-water mark or a standing value | how much it rose within each window | it rose at least as much late as early, so nothing is bounding it |
| A **mean** | its value directly | it moves by more than a quarter |

A level's *rate* means nothing: a worst case that stopped getting worse is good news, and the
first version reported it as a rate that had collapsed to nothing. A two-hour soak that passed
7,200 audits of 7,200 marked four numbers that way — `passed over max` 3 → 7, `slices ran max`
21 → 24, `served after max`, and `answered in mean`, a mean that had not moved at all and was
reported as −100%. Four marks that mean nothing are how the one that matters hides.

The same reading found the opposite hole. A count with no early rate — zero for the whole first
window — has no ratio to compare, so the first version printed `-` and moved on: a leak that
*began* after the first window was invisible, which is exactly the leak a long run exists to
catch. It is now a finding of its own. The counts that should stay at zero for a whole run —
`none charged`, `stalled waits`, `slow exchanges` — are counts for that reason, and are reported
the moment they start.

The legend and the prose it describes are written in two places, so they can drift apart. When a
kind names a number no heartbeat carries, that is reported as a finding too, because the field it
was meant to describe is being read as a count.

**The verdict says how many findings there are**, and `none` is what a healthy run says.

#### What the gates showed

A soak gates a branch at thirty minutes per SMP preset: long enough for every bound above to
be exercised thousands of times under load, and to compare the first five minutes with the
last five. The two-hour and twenty-four-hour runs are for leaks a shorter run cannot show,
and are run on a quiet machine.

`aarch64-virt-smp` at eight CPUs, thirty minutes, on a host carrying other work at load 12 to
25 throughout: **1,800 heartbeats of 1,800, no audit failed**. Its drift, the first five
minutes against the last five, is the shape of a machine doing more work as its caches warm
and nothing else: heap +8%, channels +13%, page faults and copy-on-write +16%, pages +11%,
block +13%, filesystem +13%, datagrams +11%, TCP +3%. No counter ran away, and the retry
counts fell slightly.

What the bounds had left at the end of that run, against what would have failed it:

| Margin | Reached | Bound |
|---|---|---|
| Slices to park | 44 | 512 |
| Slices without progress | 0 | 512 |
| Late wakes blamed on the scheduler | 0 | any |
| Late wakes charged to the host | 1, worst 581 ms | reported, not fatal |
| Slow exchanges | 0 | reported, not fatal |
| Waits charged nothing at all | 0 | reported, not fatal |
| Stalled shootdown waits | 0 of 4,397,954, mean 186 µs | reported, not fatal |

`x86_64-qemu-smp` at eight CPUs, thirty minutes, on the same busy host: **1,800 heartbeats of
1,800, no audit failed**. Its drift runs the other way — heap −7%, channels −12%, faults −8%,
pages −5% — because the host grew busier as the run went on rather than because anything in
the kernel slowed. That is what the comparison is for: the direction says where the work went,
and neither run has a counter that ran away. Its margins at the end were 244 slices to park of
512, no interval without progress, and zero for every reportable count: no late wake charged to
the host (the worst was 214 ms), no slow exchange, no wait charged nothing, no stalled
shootdown wait.

The counts that are *reported rather than fatal* are the point of this round's work: on a
loaded host they stay near zero on a healthy kernel, and every one of them used to end a run.

#### What the soaks found

Seven attempts at a two-hour soak died, six of them inside the first ten minutes, on six
distinct bounds — and none on anything the kernel did wrong. They are why the bounds above
changed. Each attempt ran on the tree as it stood, so a run that died on a bound fixed later is
evidence for that fix, not against it.

| Run | Died at | On | What it was |
|---|---|---|---|
| `aarch64-virt-smp`, 8 CPUs | 65 s | `tlb shootdown: ... wrong CPUs, or stalled` | a stall is the *waiting* CPU's own spins; split from mismatches |
| `aarch64-virt-smp`, 8 CPUs | 453 s | `a sleep woke more than half a second after its deadline` | lateness the host caused; now judged by slices passed over |
| `aarch64-virt-smp`, 8 CPUs | 108 s | `linux processes: a churning process's thread did not end` | `PAIR_PATIENCE`, 10 s, over two Linux processes each faulting 1,600 pages |
| `aarch64-virt-smp`, 8 CPUs | 77 s | the same | the same, on final code: which is what settled it |
| `x86_64-qemu-smp`, 8 CPUs | 159 s | `user process: a process ran its slices after it moved and made no progress` | `RAN_SLICES`, 16, below what healthy runs measure |
| `x86_64-qemu-smp`, 8 CPUs | 42 s | `waiting process: a waiting process's receive timed out: a wake-up was lost` | a message that arrived a second late, reported as one that never came |
| `aarch64-virt-smp`, 8 CPUs | 676 s | the same | the same, and the longest any attempt ran before its fix landed |
| `aarch64-virt-smp`, 8 CPUs | 141 s | `spinning sibling: a spinning thread was never stopped: its process's exit did not reach it` | `spawn::PATIENCE` again: the spinner's CPU was not run, so no interrupt reached it |
| `aarch64-virt-smp`, 8 CPUs | 49 s | `waiting process: a waiting process did not finish: a wake-up was lost` | `waits::PAIR_PATIENCE`, 5 s, over two threads passing a counter |
| `aarch64-virt-smp`, 8 CPUs | 64 s | `killed by the heartbeat watchdog: the guest is hung` | kbuild's own 30 s allowance between heartbeats, with the guest still printing them |
| `aarch64-virt-smp`, 8 CPUs | 39 s | `waiting process's receive timed out: a wake-up was lost` | `WAKE_NS`: from inside the program, a sender the host never ran looks like a lost wake |

Each time the host was carrying two soaks and five other jobs, at load averages of 19 to 25.

**The pair waits are now judged the same way.** Two processes mapping, faulting and unmapping
1,600 pages between them take as long as the host lets them, so both cycles wait until their
threads have been given `PAIR_SLICES` between them, with `PAIR_PATIENCE` left for the one case
slices cannot judge: threads the scheduler is not running at all. Each thread is counted
against its own start, because a thread that has ended is reaped and reports no slices.

What the wait does *not* decide is the message: `end_threads` waits `spawn::PATIENCE` for each
thread afterwards, and that 3 s is what reports `a ... process's thread did not end` — and, from
the spinning-sibling cycle, `a spinning thread was never stopped`. It is the one bound of this
family still measured in wall time, and at load 28 it has failed a run at 141 s. Fixing it means
judging the thread by whether interrupts reached it: a spinner that took slices and was not
stopped is the kernel's fault, and one whose CPU was never run is the host's. That needs the
thread's id plumbed out of the cycles that call `end_threads`, which is left undone here. It is
shared with the boot checks, so it is left alone and listed above. This is also why a mutation
that makes the pair wait give up at once does not fail the run — `end_threads` still waits,
and the pair still finishes — so the bound is falsified by a pair that cannot finish rather
than by a wait that gives up early.

**The last one is the process cycle's own slice bound.** `RAN_SLICES` allowed sixteen slices
without a pass after a thread was re-pinned; a passing soak had already reported twenty for a
wait that succeeded, and a 60-second run at eight CPUs needed thirteen. It is now a hundred and
twenty-eight, derived from those measurements rather than from what looked generous.

| Mutation | Result |
|---|---|
| `passes` reports nothing at all | the *boot* process check fails first: `bring-up failed; not starting the scheduler`, and the stress cycle never runs |
| The stress cycle's own wait never sees progress, leaving the boot check intact | `user process: a process ran its slices after it moved and made no progress`, at 0 s |

The first mutation is the lesson, not the test: a check that dies during bring-up says nothing
about the bound in the stress run, so the mutation has to be scoped to the cycle's own wait.
Three of this round's mutations failed that way before they were scoped — the pass counter, the
shootdown mismatch and the receive patience each kill bring-up when changed wholesale, because
the boot checks use the same code the stress run does. A mutation that stops the guest before
the audit runs is not a falsification of the audit.

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
| x86_64 (`x86_64-efistub`) | `qemu-system-x86_64` | `q35` | OVMF, booting the kernel itself: the EFI stub | `isa-debug-exit` |
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
- **Fuzzing** of every parser that reads untrusted input, and of system call dispatch:
  see [2c. Fuzzing](#2c-fuzzing). Network frames are fuzzed (`net`); filesystem metadata
  joins the table the day that parser exists.

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

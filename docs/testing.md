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

CI runs all three on every preset, beside the ordinary boot.

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

Every merge runs a 20-second stress smoke on each tier-1 architecture, which keeps the
image building and passing its first audits. A nightly workflow
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
| armv7m | `qemu-system-arm` | `mps2-an385` (Cortex-M3) | none | semihosting |
| riscv32 | `qemu-system-riscv32` | `virt` | `-bios none` | `sifive_test` |

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
  fail.

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

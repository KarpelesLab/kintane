# Userspace ABI

Status: **the native slice is built; the Linux personality is still a sketch.** The
principles below are the commitment; the syscall numbers are not.

## As built — the native vertical slice

x86_64 and aarch64 now run unprivileged processes. Every boot on those ports (the
`USERSPACE` config symbol, on by default where the machine allows it) builds three
processes from one embedded program (`user/init`), enters ring 3 / EL0, and grades each
by the exit code it returns — so a kernel that answers a system call wrong is caught by
the program that got the wrong answer, not by the kernel checking its own work. What
exists:

- **`lib/abi`** — the ABI as one table (`lib/abi/src/table.rs`), in a `syscalls!` macro
  that generates the numbering, the kernel's `Handler` trait, the argument-decoding
  dispatcher, and the userspace bindings from a single source. There is no `#[syscall]`
  proc-macro (kbuild has no way to build one); the macro is chosen because the table is
  Rust, so a signature is type-checked identically on both sides. Errors are values: a
  status register (0 or an `Error`) and a value register, no `errno`.
- **`kernel/elf`** — a static-ELF loader that refuses a non-executable, a
  writable-and-executable segment, a segment outside the user half, two segments in one
  page, or an entry point outside code. Fuzz-tested.
- **`hal::HasUserMode`** — the per-port contract: enter user mode, take a system call
  and a fault from it, and copy across the boundary without trusting the pointer.
  Implemented for x86_64 (`arch/x86_64/src/user.rs`: the `syscall`/`sysret` fast path,
  ring-3 GDT segments in every CPU's GDT, `TSS.rsp0` per thread installed on whichever CPU
  it runs, the `swapgs` discipline for per-CPU `GS`, the `SYSRET` canonical hazard
  handled) and
  aarch64 (`arch/aarch64/src/user.rs`: `eret` to EL0t, the `svc` decode in the lower-EL
  vector, `SP_EL0` per thread).
- **The syscalls** for the slice: `process_exit`, `thread_exit`, `thread_yield`,
  `debug_write` (rights-checked), `vm_map` of anonymous memory (demand-paged),
  `channel_create`/`channel_write`/`channel_read`, and `handle_close`. Each process has
  its own address space (a `mm::vm::Vm` over its own page tables, sharing the kernel
  half) and its own handle table.

**User-pointer safety, and the choice made.** The design asks for fault-safe copies.
Rather than an exception-fixup table, `copy_from_user`/`copy_to_user` validate the range
against the user half and fault every page in through the process's own fault hook
*before* touching it, so the copy itself only ever reads present memory and cannot fault
the kernel. A page the hook maps and a recheck still finds absent, or an address the
hook will not map, is refused as `Fault`. This is sound because all user memory is
backed by the process `Vm`; a fixup table becomes worthwhile only when a copy may touch
memory no `Vm` owns.

**What the check proves, each falsified:** a program maps memory and uses it, writes to
the console, is refused a write through a console handle without `WRITE`, is refused a
copy from a bad pointer *without the kernel faulting*, and loops a message through its
own channel. A second process is given only the raw handle *values* of another's handles
and every use is refused — "a process with no handles can do nothing." A third writes to
kernel memory and is killed at the fault, the kernel continuing. Removing the rights
check, the `rsp0` switch, or the copy validation each makes the check fail.

**Processes on the scheduler.** A process thread is an ordinary scheduler thread whose
saved context carries its kernel stack and its address space (`hal::HasUserMode::bind`),
recorded under the scheduler lock before any CPU can pick the thread up
(`preempt::spawn_prepared`). The context switch loads that space wherever the thread
resumes, and the kernel's own for a kernel thread, so the space a thread runs on is the
thread's property rather than the CPU's. The kernel finds the process a system call or a
fault belongs to by the address space loaded on the CPU that took it
(`userproc::current`), which cannot go stale when a thread migrates. Two checks prove it:

- **At boot** (`kernel/main/src/procs.rs`, the `processes` banner line), on every
  x86_64 and aarch64 preset: two worker processes run together on the scheduler, each
  writing its own signature to the *same* virtual address and reading it back on every
  pass; both make progress in one window, and neither ever reads the other's signature. A
  third process writes to kernel memory, is killed, and both workers keep running after
  it. Every frame the three took comes back when they are torn down.
- **Under stress** (`kbuild stress`), once per audit interval while every other workload
  runs: a worker process is created, its thread is pinned to one CPU and then another, the
  kernel must serve its system calls on each with its signature still intact, and the
  process is destroyed with every frame returned. Migration is checked here and not at boot
  because a secondary CPU joins the scheduler only after the boot verdict.

**Programs creating programs.** Until this, every process was assembled by the kernel,
which proved the machinery and proved nothing about whether a *program* could use it. Now
the handle namespace holds objects a program can create, and a process is built by the
program that has the handles to build it with — there is still no `fork`:

- **Objects** (`kernel/main/src/objects.rs`): a program image, a process, a thread, an
  anonymous memory region, a completion queue, an event and a timer. They live in one static arena behind
  `kobject::store::ObjectStore`, which owns their identity and lifetime: an object is found
  by the identity its handles carry, retired when its last name is closed, and destroyed
  once nothing holds a reference. **Objects are the kernel's; handles are a process's.** That
  is what makes giving a handle to another process a move of a name rather than a copy of an
  object.
- **Construction calls** (numbers 9–16 in `lib/abi/src/table.rs`): `process_create` from an
  image, `process_transfer` of a handle into it, `vm_region_create` and `vm_map_in`,
  `thread_create`, and `process_wait` — which posts the exit code to a completion queue,
  read with `completion_poll`. Every step names the objects it acts on by handle, and every
  handle is checked for kind, then rights, before anything happens.
- **Channels became the kernel's too.** A channel used to be a field of the process that made
  it, which meant an endpoint handed to another process named nothing there. A channel now
  lives in a kernel table keyed by its endpoints' identities, so a transferred endpoint works
  in whichever table holds it.
- **`lib/rt`**, the native runtime: typed wrappers (`Process::create`, `give`, `start`,
  `start_at`, `join`), channel, completion, event and timer helpers. Its waiting wrappers
  (`recv`, `completion_wait`, `Event::wait`, `Process::join`) block in the kernel; the
  non-blocking forms remain as `try_recv` and `try_completion`.

**What the check proves** (`kernel/main/src/spawn.rs`, the `spawn` banner line, on every
x86_64 and aarch64 preset including both SMP ones). The kernel starts one process, `init`,
and hands it two handles: the console, and a region holding the bytes of a second program,
`user/child`. Everything after that is `init`'s doing. It is refused `process_create` on the
console and `thread_create` on the image, both as the wrong kind of object; it builds a
process from the image; it is refused mapping the image into that process, holding it
without `MAP`; it creates a channel, moves one endpoint into the child, asks for the child's
exit on a completion queue, and starts the child's thread with the endpoint's value *in the
child's table*. The child holds nothing but that endpoint. It tries six handle values it was
never given and every use is refused as a bad handle; then it says hello, waits for the
reply, and exits with a code of its own. `init` checks that code and exits with one the
kernel checks, so the kernel grades a sequence it did not perform. Both processes are then
torn down and every object and every frame must be back.

**Waiting properly.** A wait used to be a loop of a non-blocking call and a yield. The
kernel now has wait queues (`kernel/main/src/wait.rs`, described in `docs/architecture.md`),
and the calls numbered 17–26 are built on them:

- **`channel_send`** moves up to two handles with a message, each with a mask of the rights the
  receiver may keep — rights only narrow — all or nothing. **`channel_recv`** blocks for a
  message and returns its length and handle count. `channel_write` and `channel_read` remain,
  non-blocking and without handles.
- **`completion_wait`** blocks for a completion. `process_wait` still only arms a completion; the
  wait for a process is `completion_wait` on that queue, which `rt::Process::join` does.
- **Events** (`event_create`, `event_signal`, `event_wait`): a latch. Signalling needs `SIGNAL`,
  waiting needs `WAIT`, and a wait consumes the signal.
- **Timers** (`timer_create`, `timer_set`, `timer_cancel`) deliver to a completion queue, once or
  periodically, each delivery carrying how many expirations it reports. A timer is delivered when
  its queue is looked at — by `completion_wait`, which ends its wait at the timer's deadline, or
  by `completion_poll` — not from the timer interrupt, so nothing posts in interrupt context.
- **`clock_now`**, the monotonic clock in nanoseconds.

Every waiting call takes a timeout in nanoseconds: zero polls and answers `ShouldWait`,
`u64::MAX` waits for as long as it takes, and anything else ends in `TimedOut` (error 13).

**Threads.** `thread_create` starts further threads in a process, each with a four-page
user stack of its own, up to three beyond the first over the process's life. Two threads of
one process may be in the kernel on two CPUs at once, so a system call takes its process's
lock and releases it around anything that blocks. A process ends when any thread calls
`process_exit` or faults. Its other threads end at their next system call, or at once if
they are waiting, because the exit wakes every wait. Its exit is posted to `process_wait`'s
queue when the last thread has gone.

**A file service.** `lib/vfsproto` is a channel protocol (open, read, close, one 64-byte
message each). The boot check serves it from a kernel thread over `kernel/vfs` on the
mounted test volume, and `init` reads `/HELLO.TXT` through it. That is the VFS as a service a
program reaches through a channel it was handed, not a set of system calls.

**What the check proves** (`kernel/main/src/waits.rs`, the `waits` banner line, gating the
verdict on every x86_64 and aarch64 preset including both SMP ones). `init`:
- polls an empty queue and is told `ShouldWait`, and a 30 ms wait ends in `TimedOut` no earlier
  than 30 ms;
- sees a one-shot timer deliver once and on time, and a periodic one deliver until cancelled;
- starts a second thread that writes to a page the first mapped and signals an event, which wakes
  the first; that thread reads the write back at the same address;
- blocks the second thread in `channel_recv` and wakes it with a send;
- moves an event handle with `WAIT` only, and finds the receiver able to wait on it, refused a
  signal, and the sender's handle gone. A send naming a handle it does not hold moves nothing;
- reads `/HELLO.TXT` through the file service, and has a missing file refused.

The kernel also requires its own counters to show threads blocked, were woken, and timed out,
and every thread, object and frame back. A wake from another CPU cannot happen before the
verdict, because secondary CPUs join the scheduler after it. The stress run shows it instead:
once per audit interval a two-threaded process with its threads pinned to two CPUs passes a
counter back and forth, blocking for each message. A lost wake-up is a receive that times out
and fails the run, and the run requires a wake counted as crossing CPUs.

**Not yet:** no `Mapping` or `Job` objects; a thread spinning in user mode is not stopped when
another thread ends its process, only one that makes a system call or waits; the file service
runs inside the boot check, not as a standing server, and serves reads only; no ASIDs or PCIDs,
so every change of address space flushes the TLB (see `docs/architecture.md`). i686 and riscv32
have no userspace port.

## Two ABIs, one kernel

KinTane has a **native ABI** and a **Linux-compatible ABI**, selected per process by a
personality tag. They are not peers:

- The **native ABI** is the real interface. It is capability-based, handle-oriented,
  and designed for the range of machines this kernel targets — including those with no
  MMU, where most of the Linux process model cannot exist.
- The **Linux personality** is a compatibility surface implemented *on top of* the
  native kernel interfaces, so that unmodified Linux userland binaries run
  transparently.

The native ABI is primary because the Linux ABI encodes forty years of decisions about
a machine with an MMU, a POSIX process model, and signals. A kernel that exists to
serve unusual hardware cannot take that as its foundation. `errno`, ambient authority
through a global filesystem namespace, and integer file descriptors are precisely the
parts we want to do differently.

The Linux personality exists anyway, for two reasons that outweigh the purity
argument:

1. **An existing userland from day one.** Static musl binaries, busybox, real
   compilers and test suites — available the moment the syscall layer works, instead
   of after we have written a userland of our own. This collapses the gap between
   "the kernel schedules processes" and "the kernel runs useful software", and it is
   what makes Phase 7's storage and networking work testable against programs that
   were not written to flatter us.
2. **A migration path.** Hardware that nobody can run existing software on is
   hardware nobody deploys.

See [the Linux personality](#the-linux-personality) below for how the surface is
scoped and how we avoid the failure mode of partial compatibility.

## Principles

### Capabilities, not ambient authority

A process has no authority except through handles it holds. There is no global
namespace it can reach by writing a path; a path is resolved relative to a directory
handle it was given. A process with no handles can do nothing but compute and exit.

Handles are indices into a per-process table pointing at `KObject`s, each carrying a
rights mask. Rights can be narrowed when a handle is duplicated or passed, never
widened.

```
handle = 0x0000_002a
  → object: Channel #1183
  → rights: READ | WRITE            (not TRANSFER, not DUPLICATE)
```

### Explicit process creation

No `fork`. `fork` requires copy-on-write address space cloning, which `mm::flat`
cannot provide, and it implicitly inherits everything — the opposite of capability
discipline.

Instead, a process is built explicitly: create an empty process object, map segments
into it, install exactly the handles it should have, set its entry point, start it.
Verbose, auditable, and implementable on a machine with no MMU.

`fork` and `clone` exist in the Linux personality, which is why that personality
requires a paged memory model and is unavailable on no-MMU builds. The native ABI
does not gain a `fork` because the compat layer needs one.

### Errors are values

Syscalls return a discriminated result, not a sentinel plus a thread-global `errno`.
The error set is closed and enumerated per syscall, so a caller can exhaustively
match and the compiler will say when a new variant appears.

### Handles are typed

An operation on a handle of the wrong object type fails at the ABI boundary, not
three layers in. Combined with the rights mask, this means a syscall's preconditions
are checkable in the dispatcher.

### Everything is not a file

A channel is a channel; a memory region is a memory region; a device is a device.
Each object type has its own operations. The uniformity of "everything is a file" is
appealing and, in practice, `ioctl` is where it goes to die. A filesystem-like
namespace exists as a *service*, built on channels, for the things that genuinely are
hierarchical name lookups.

### Asynchronous by default, with synchronous convenience

The primitive is submit-and-complete against a completion queue. Blocking calls are a
thin library wrapper over it. Designing the blocking interface first and bolting on
async later is a mistake that is very hard to undo.

## Object types (initial set)

| Object | Purpose |
|---|---|
| `Process` | address space + handle table + threads |
| `Thread` | an execution context |
| `Channel` | bidirectional message + handle transfer |
| `MemoryRegion` | a range of physical or anonymous memory, mappable |
| `Mapping` | a region's presence in an address space |
| `Event` | signalling and waiting |
| `Timer` | deadline notification |
| `Interrupt` | a device IRQ delivered to userspace (for user-domain drivers) |
| `DeviceResource` | MMIO range / DMA capability, granted to a driver |
| `Completion` | a completion queue |
| `Job` | a resource-accounting and lifetime group of processes |

## Syscall surface

The *native* surface is deliberately small. The target is under fifty syscalls, with
functionality that would otherwise be syscalls expressed as messages to services over
channels. Anything that looks like it wants to be an `ioctl` is a channel protocol
instead. (The Linux surface is not small, and cannot be; that is its problem, not the
native ABI's.)

Syscall dispatch is generated from `#[syscall]` attributes
([build-system.md](build-system.md#generated-sources)), which keeps the numbering
table, the argument-validation code, the userspace bindings, and the documentation
generated from one source.

## The Linux personality

### The tag

Every process carries a personality, fixed at load time:

```rust
#[non_exhaustive]
pub enum Personality {
    Native,
    Linux,
}
```

The tag is cached in the thread control block as a pointer to a syscall dispatch
table, so the entry path loads a table pointer and indexes it. There is no branch on
personality in the syscall path and no cost to a native process for the compat layer
existing.

A process is tagged `Linux` when:

- its ELF header declares `ELFOSABI_LINUX`, or it declares `ELFOSABI_SYSV` and carries
  no `.note.kintane.abi` section (i.e. it was not built for us), **or**
- the creating process asked for it explicitly when constructing the process object.

Native binaries carry `.note.kintane.abi`. The fallback for unmarked SysV binaries is
a config option, defaulting to `Linux`, because in practice an unmarked binary is a
Linux binary and making that work without ceremony is the point.

### Implemented on native primitives

The governing rule:

> **The Linux personality is a client of the native kernel interfaces, not a second
> path into the kernel.**

A Linux `openat` resolves to the same VFS service call the native interface uses. A
Linux `clone` builds the same `Process` and `Thread` objects. The compat layer owns
translation — argument shapes, error numbering, structure layouts — not mechanism.

This is a deliberate forcing function. If the Linux personality needs a kernel
facility the native interfaces cannot express, that is **a gap in the native ABI**, to
be fixed there, rather than a special case bolted onto the compat layer. Linux is a
thorough specification of what a general-purpose kernel must actually do; using it to
audit our own interface is worth more than the compatibility itself.

The exception is performance. Where translation demonstrably dominates — the read and
write paths, futexes, `epoll` — the compat layer may reach further into a subsystem,
and each such case is documented where it happens with the measurement that justified
it.

### What the layer has to supply

Beyond syscall translation, a Linux process needs a machine-shaped environment:

| Area | Notes |
|---|---|
| File descriptors | An `int` → handle table, a compat view over the same `KObject`s. Rights are set wide at creation; the fd table *is* the ambient authority. |
| Ambient namespace | A root directory handle installed at creation, plus `cwd`. Path resolution starts there rather than from a passed-in handle. |
| `fork` / `clone` | Copy-on-write address space cloning. Requires `MM_PAGED`. |
| Signals | Full POSIX delivery: masks, handlers, `sigaltstack`, per-architecture signal frames, restart semantics. The largest single item, and the one most likely to be subtly wrong. |
| `errno` | Native `Result` error enums mapped to negative errno returns. The mapping is many-to-one and lossy; it is a table, reviewed, not an afterthought. |
| `/proc`, `/sys`, `/dev` | More userland depends on these than on most syscalls. Minimal but real implementations, served through the VFS. |
| `mmap`, `brk` | Linux mapping semantics, including the parts nobody likes. |
| TLS setup | `arch_prctl`, `set_thread_area`, and equivalents per architecture. |
| vDSO | Per-architecture, for `clock_gettime` and friends. Optional at first; some libcs hard-require it. |
| Syscall tables | Numbering differs per architecture. Generated per target from a table in-tree, not hand-written. |

### Scoping, and the partial-compatibility problem

The objection to Linux compatibility is real and this document previously used it to
reject the idea outright: *partial compatibility produces software that runs until it
does not, which is worse than software that does not run.* Committing to the
personality does not make that objection go away. It makes it something to manage.

The management is: **compatibility is defined by a corpus, not by a percentage.** We
do not claim a compatibility level. We publish the list of programs CI runs, and that
list is the claim.

Corpus tiers, in the order they are pursued:

1. **Static musl binaries.** No dynamic linker, no NSS, no locale machinery — a
   dramatically smaller surface, and enough for busybox, toybox, and most test
   programs. This is the early-testing target and where most of the value lands.
2. **Static glibc**, then **dynamic musl** — the dynamic linker, `mmap` of shared
   objects, TLS models.
3. **Dynamic glibc userland.** A real distribution's `/bin`. The point at which the
   personality is genuinely useful rather than merely demonstrable.
4. **Selected LTP subsets** as a conformance measure, chosen per subsystem rather than
   run wholesale for a number.

Unimplemented syscalls return `-ENOSYS` **and log the syscall name, arguments, and
process**. A config option makes them fatal instead; CI runs with it enabled, so a gap
surfaces as a test failure with a name attached rather than as a program that behaves
strangely.

### Security posture

A Linux process has ambient authority by construction — that is what the fd table and
the root namespace are. This weakens the capability model, and it does so *only for
processes that opted into it*. Native processes are unaffected: the kernel does not
acquire a global namespace because the compat layer has one, it acquires a namespace
service that Linux processes are given a handle to.

Confining Linux processes is therefore done with the native tools — give the process a
root handle pointing at a subtree, restrict the `Job` it belongs to — rather than by
reimplementing namespaces and cgroups. Whether we eventually want those too is a
question for after the corpus is running.

### Configuration

```kcfg
config ABI_LINUX
    tristate "Linux syscall compatibility"
    depends on ABI_NATIVE && MM_PAGED
    default m
    help
        Run unmodified Linux userland binaries. Processes are tagged at
        load time and dispatched to the Linux syscall table.

        Requires a paged memory model: fork(2) needs copy-on-write, which
        the flat memory model cannot provide.
```

Tristate, and `m` by default: the personality is a loadable module in a
general-purpose build, compiled in for appliance builds, and absent from embedded
ones. A kernel that runs Linux binaries and a kernel that fits in 64 KiB are the same
source tree with different configurations, which is the whole thesis applied to the
ABI layer.

## Scaling down

On a no-MMU target most of this collapses, and that is intended rather than a
degradation to apologize for:

- There is one address space. `MemoryRegion` and `Mapping` still exist but map
  identity.
- Isolation is by MPU region where available and by convention where not. A
  microcontroller build is cooperative and we say so, rather than implying a
  protection guarantee the hardware cannot make.
- Processes may be static, defined at build time, with no loader.
- The Linux personality does not exist. `ABI_LINUX` depends on `MM_PAGED`, and the
  config system enforces that rather than offering a version of it that cannot
  `fork`.
- The syscall layer may be configured away entirely: a build with no userspace is
  tasks in the kernel, which is what an RTOS is.

The same kernel source, the same subsystem interfaces, a very different machine. That
is the whole point of the project.

## Binary format and userland

- **ELF**, with position-independent executables required where the MMU allows ASLR.
- A **native runtime library** rather than a libc. A POSIX-ish compatibility library
  above it, since porting existing software is easier than not, but the native
  interface is the real one and is not constrained by POSIX semantics.
- No dynamic linker in the first implementation. Static linking is simpler, and the
  reasons dynamic linking exists — memory sharing, independent updates — deserve a
  fresh answer rather than the traditional one.

## Stability

The native ABI is unstable until Phase 6 completes. After that: syscall numbers and
structure layouts are frozen within a major version; additions are additive; removals
require a major version and a deprecation period of at least one. The `Completion`
and `Channel` protocols are versioned independently of the syscall numbering, because
they will evolve faster.

The Linux ABI's stability is not ours to set — it is Linux's, and it is famously never
broken. We inherit that: a syscall the personality implements keeps working, and
changes to our internals must not be visible to a Linux process. The compat layer is
therefore versioned by *corpus*, not by number: the published list of programs CI runs
only grows.

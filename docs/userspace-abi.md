# Userspace ABI

Status: **the native slice is built; the Linux personality runs static programs on x86_64 and
aarch64, with pipes, threads, `fork`, `execve` and `wait4`, and no signals or sockets**
([as built](#as-built--static-programs-x86_64-and-aarch64)). The principles below are the
commitment; the native syscall numbers are not.

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
  it, which meant an endpoint handed to another process named nothing there. Each endpoint is
  now an object in the store, so a transferred endpoint works in whichever table holds it. A
  channel lives while any handle, queued message or system call in progress names either
  end, and is destroyed when the last of them lets go — not when the process that made it is
  torn down while another process still holds the far end. Nothing about the channel calls
  changed.
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
- **`completion_wait`** blocks for a completion.
- **`process_wait`** has two forms. With a completion queue it arms that queue, as it always
  did, and takes no timeout. With a zero completion handle it blocks for the process itself, up
  to its timeout, and returns the exit code — `TimedOut` if the process is still running, like
  every other wait. `rt::Process::join(timeout_ns)` is that form; `rt::Process::wait_on` is
  the other.
- **Events** (`event_create`, `event_signal`, `event_wait`): a latch. Signalling needs `SIGNAL`,
  waiting needs `WAIT`, and a wait consumes the signal.
- **Timers** (`timer_create`, `timer_set`, `timer_cancel`) deliver to a completion queue, once or
  periodically, each delivery carrying how many expirations it reports. A timer is delivered when
  its queue is looked at — by `completion_wait`, which ends its wait at the timer's deadline, or
  by `completion_poll` — not from the timer interrupt, so nothing posts in interrupt context.
- **`clock_now`**, the monotonic clock in nanoseconds.

Every waiting call takes a timeout in nanoseconds: zero polls and answers `ShouldWait`,
`u64::MAX` waits for as long as it takes, and anything else ends in `TimedOut` (error 13).

**Sockets.** Calls 27–34 put the kernel's TCP (`kernel/net`, described in
`docs/architecture.md`) behind handles. A socket is a `Socket` object in the store, and an
address is one word: the IPv4 address in bits 47..16 and the port in bits 15..0
(`abi::socket::address`).

- **`socket_create(STREAM)`** makes a socket with every right, neither bound nor connected.
- **`socket_connect`** (`WRITE`) begins the handshake and waits for it: `PeerClosed` if the peer
  refused, `TimedOut` if it never answered. A socket connects from an ephemeral port.
- **`socket_bind`** and **`socket_listen`** (`WRITE`) make a listener on the bound port.
  **`socket_accept`** (`READ`) waits for a connection and returns a new socket with every right.
- **`socket_send`** (`WRITE`) queues up to 512 bytes, waiting for room for at least one.
  **`socket_recv`** (`READ`) waits for data and returns up to 512 bytes, and zero at the end of
  the stream. Either on a socket that is not connected is `InvalidArgument`.
- **`socket_shutdown`** (`WRITE`) sends a FIN after what is queued and waits for the peer to
  acknowledge everything. Closing the handle closes the connection in order without waiting,
  or resets it if data arrived that was never read.
- A socket call that waits is blocked on a wait queue, but nothing wakes that queue when a frame
  arrives: the waiter looks at the network every 2 ms until its timeout. The card's interrupt
  does not reach socket waiters yet.

`lib/rt` wraps the calls as `TcpStream` and `TcpListener`. There is no Linux socket call;
`kernel/main/src/sockets.rs` lists where `socket`, `bind`, `listen`, `accept`, `connect`,
`send`, `recv`, `shutdown` and `close` would land on these.

**What the socket check proves** (`kernel/main/src/sockets.rs`, the `sockets` banner line, on
every x86_64 and aarch64 preset with a network card). `user/tcp-client`, a native program with
the ABI note, is given the console and the address of kbuild's TCP service. It checks that a
socket that is not connected refuses to send. Then it connects through QEMU's user network,
sends a request, reads the reply until kbuild closes, and closes its socket. kbuild drops the
connection's first data segment once, so the reply arrives only because the kernel sent the
request again. The kernel requires the program's success code, a data retransmission while it
ran, the connection it let go of closed in order with every stack buffer back, and every object
and frame back.

**Threads.** `thread_create` starts further threads in a process, each with a four-page
user stack of its own, up to three beyond the first over the process's life. Two threads of
one process may be in the kernel on two CPUs at once, so a system call takes its process's
lock and releases it around anything that blocks. A process ends when any thread calls
`process_exit` or faults. Its other threads end at their next system call, or at once if
they are waiting, because the exit wakes every wait. A thread running user code, which does
neither, is ended by interrupt: the exit sends a reschedule IPI to every other CPU, and a
scheduler interrupt that arrived in user mode ends its thread on the way back if that thread's
process has ended. Nothing of the process is freed until every thread is gone. Its exit is posted to `process_wait`'s
queue when the last thread has gone.

**A file server.** `lib/vfsproto` is a channel protocol (open, read, close, one 64-byte
message each). A kernel thread, `kernel/main/src/fileserver.rs`, serves it over `kernel/vfs`
on the mounted test volume. The thread is started once at boot and never stopped. The kernel
gives a process a connection — a channel of its own, one end in the process's table — and
the server adopts the other end. Each connection has its own open files, and the server lets
go of a connection when its client's end closes. It waits on every connection through one
queue of its own, which each adopted channel also wakes. It holds the volume only for the
request it is answering, through a lease the stress run's filesystem workload takes too, so
an open file is a path and an offset rather than a handle into the volume. `init` reads
`/HELLO.TXT` through it in the `waits` check, and a second process does the same after that
check has ended. That is the VFS as a service a program reaches through a channel it was
handed, not a set of system calls. No program can yet ask for a connection itself: the kernel
hands one to the processes it starts.

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
| `Socket` | a TCP connection or listener of the kernel's network stack |

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

### As built — static programs, x86_64 and aarch64

Static Linux programs run unmodified from the filesystem on x86_64 and aarch64.
`user/linux-hello` knows nothing of KinTane. It makes system calls by Linux's numbers for the
architecture it is built for, through `syscall` or `svc #0`, reads a value or a negated errno
back from the one return register, and reads Linux's start-up stack (`argc`, `argv`, `envp`,
the auxiliary vector) at its entry. One source builds for both, with the numbers and the few
instructions that differ in a module per architecture. kbuild puts it on the test disk as
`/KINTANE/LINUX.ELF`. Every boot of a configuration with `ABI_LINUX` runs it twice: once alone
in the boot-time slice, and once with the scheduler, where it pipes, forks, `execve`s, waits
and starts a thread ([testing.md](testing.md#2f-the-linux-personality)). The stress run starts
two at a time on one CPU.

It is built in-tree with the pinned Rust toolchain, not with a C one, so it is a Linux binary
in every way the kernel can tell but is not musl or glibc output. The first corpus tier below,
static musl, has not been attempted. The program links at `0x80_0040_0000`, in the user half,
and not at Linux's customary `0x400000`: the kernel still maps itself in the lower half, and a
program with a segment there is refused at load (`OutsideRange`).

**The tag.** Every `Process` carries a `Personality` (`Native` or `Linux`), decided once at
load from the program alone, by `userproc::personality_of`:

| The program | Tagged |
|---|---|
| carries the KinTane ABI note: a `PT_NOTE` holding owner `KinTane`, type `0x4b54`, the native ABI version | `Native` |
| no note, and `EI_OSABI` is System V (0) or Linux (3) | `Linux`, if the kernel has `ABI_LINUX` |
| no note, and `EI_OSABI` is Linux or System V, on a kernel without `ABI_LINUX` | refused at load |
| no note, and any other `EI_OSABI` | refused at load |

Every native link script (`user/init/link.ld`, `user/hwdomain/link.ld`) writes the note as data,
so no native program can forget it. `kernel/elf` finds it by walking the notes in each `PT_NOTE`
segment, bounded and never panicking on a corrupt one. A process cannot ask for a personality
after it starts. A native process's `process_create` refuses a Linux image with
`InvalidArgument`, because the child's thread would enter it the native way.

**Dispatch.** The personality chooses a table, a function pointer stored on the `Process` when
it is built. The system call entry finds the process by the loaded address space, as it always
has, and calls through the pointer. Nothing on the path branches on the personality, and a
native process pays one indirect call for the Linux one existing. The Linux table sets only
the one return register (`SyscallFrame::set_return`). The native one still sets status and
value. The Linux table takes its process's lock only for the pieces of a call that touch the
process, its descriptors or its mappings, and waits on the kernel's wait queues holding nothing,
so that another thread of the process can make the call that ends the wait.

**The numbers and the tables.** `kernel/linux/syscalls_x86_64.tbl` is a subset of Linux's
`syscall_64.tbl`, in its format: 74 calls. `kernel/linux/syscalls_aarch64.tbl` is a subset of
the generic table arm64 numbers its calls by, in the format of Linux's `scripts/syscall.tbl`:
78 calls. Neither is turned into code. The calls the personality answers are `linux::Call`s,
each with its number under each `linux::Abi`; a host test pins every number to its name in
that ABI's table, and the kernel reads a table at run time only to name a call it does not
implement. The kernel picks the ABI from its port's ELF machine at compile time, and dispatches
with a `match` on the `Call`.

**Errors.** The personality's calls fail with a `linux::Failure`, and `linux::errno` is a
single exhaustive `match` from `Failure` to Linux's number, so a new failure does not compile
until someone decides what Linux calls it. Filesystem errors map onto `Failure` in one more
`match`. The mappings that are a choice rather than obvious:

| Failure | errno | Why |
|---|---|---|
| a path the volume cannot represent (`vfs::BadPath`) | `ENAMETOOLONG` | a FAT 8.3 name that does not fit is, from the program's side, a name too long |
| a name that is not UTF-8 | `ENOENT` | the volume cannot hold it, so it has no such file |
| an open for writing | `EROFS` | every file is on a read-only view |
| an executable mapping | `EACCES` | W^X is never granted, and Linux uses `EACCES` for protections the object refuses |
| a volume or mount table full | `ENOSPC` | |
| a corrupt volume or a device failure | `EIO` | |
| a futex whose value has changed, a non-blocking pipe with nothing to give, or no free process slot or thread for `fork` or `clone` | `EAGAIN` | Linux's own answer to a `fork` past its process limit |
| a write to a pipe with no reader | `EPIPE` | the writer is sent `SIGPIPE` too, whose default action ends it before it sees this |
| a blocking call a signal with a handler interrupts, without `SA_RESTART` | `EINTR` | |
| `kill` or `tgkill` naming no live Linux process or thread | `ESRCH` | |
| `execve` of a file that is not a Linux program for this machine | `ENOEXEC` | |
| a futex wait whose timeout ran out | `ETIMEDOUT` | |
| `wait4` with no child to report | `ECHILD` | |

**Descriptors.** Each Linux process has a table of 16 descriptors, a view over what the process
already holds rather than a second authority:

- 0 is standard input. It reads as end of file. The kernel has no console input path, since no
  driver reads the serial port's receive side, so there is nothing for a read to wait for.
- 1 and 2 are two console handles in the process's own handle table. A write through either is
  checked against the handle's rights exactly as the native `debug_write` is, and `close`
  closes the handle.
- `openat` opens a file in the filesystem namespace the process was started with, at the
  lowest free number.
- `pipe2` makes two ends of one of 4 kernel pipes, each holding 512 bytes. A read of an empty
  pipe blocks on the pipe's wait queue until a writer puts bytes in, or until the last write end
  closes, which is end of file. A write to a full pipe blocks until a reader makes room, and
  fails with `EPIPE` once no read end is left. `O_NONBLOCK` makes both answer `EAGAIN` instead,
  and `O_CLOEXEC` closes the end at `execve`.

The file descriptors are open files in the VFS and pipes in the personality, not kernel objects
yet. That falls short of the table below, where every descriptor is a view over a `KObject`. A
process's descriptors close when its last thread ends, as Linux closes them at exit: a pipe's
reader sees end of file once the last writer's process has ended, not once its parent reaps it.

A socket is the next variant of `Descriptor` in `kernel/main/src/personality.rs`. Its `read`
and `write` go where a pipe's do, blocking on the socket's own queue, and the table does not
change shape.

**The calls.**

| Call | As built |
|---|---|
| `read`, `write` | standard input reads end of file; the console takes writes; a file reads through the VFS; a pipe blocks as above. Up to 4096 bytes a call, 512 on a pipe, a short count as Linux allows |
| `openat` | `AT_FDCWD` or an absolute path; the working directory is `/`. Read-only (`O_ACCMODE` other than `O_RDONLY` is `EROFS`); `O_DIRECTORY`, in the architecture's own numbering, is honoured, and so is `O_CLOEXEC`; other flags are ignored. A relative path against any other descriptor is `ENOTDIR` |
| `close`, `fstat` | `fstat` reports a regular file or directory with its size, a FIFO for a pipe end, or a character device for 0–2, in the architecture's own `struct stat`; `st_ino` is a hash of the path |
| `pipe2`, `pipe` | `O_CLOEXEC` and `O_NONBLOCK`; any other flag is `EINVAL`. `pipe` is x86_64's only |
| `brk` | moves within a reservation of 64 pages made at start; the answer is the break as it now is, which is the old one when the request cannot be met |
| `mmap`, `munmap` | anonymous private mappings, readable or read-write, where the kernel chooses. File-backed, shared, `MAP_FIXED` and `PROT_NONE` are `EINVAL`, `PROT_EXEC` is `EACCES`. `munmap` releases exactly one earlier mapping; part of one is `EINVAL` |
| `arch_prctl` | x86_64 only. `ARCH_SET_FS` only, below the top of the user half; everything else is `EINVAL`. aarch64 has no such call: a program writes `TPIDR_EL0` itself |
| `uname` | `Linux`, `kintane`, `6.1.0-kintane`, `#1 KinTane`, and `x86_64` or `aarch64` |
| `getpid` | the slot number plus one |
| `gettid`, `set_tid_address` | a process's first thread's tid is its pid; a thread `clone` starts is given one above every pid. `set_tid_address` records the address the calling thread zeroes and wakes when it exits, and answers its tid |
| `sched_yield` | gives the CPU to a ready thread of the same or higher priority |
| `clone` | with `CLONE_THREAD`: a thread in the same process, on the stack given, which requires `CLONE_VM` and `CLONE_SIGHAND`. `CLONE_SETTLS`, `CLONE_PARENT_SETTID`, `CLONE_CHILD_SETTID` and `CLONE_CHILD_CLEARTID` are honoured, and `CLONE_FS`, `CLONE_FILES` and `CLONE_SYSVSEM` accepted, since the process has one of each. Without `CLONE_THREAD`: a fork, allowed only with nothing but the exit signal in the flags and no stack, which is how an aarch64 C library forks. Anything else, `CLONE_VFORK` included, is `EINVAL` |
| `fork` | x86_64 only, since aarch64 has no such call: a copy-on-write child whose one thread resumes with the parent's registers and thread pointer, returning 0; the parent is answered the child's pid |
| `execve` | an absolute path read whole from the namespace, at most 128 KiB, with up to 8 arguments and 8 environment strings. Refused with `EAGAIN` while the process has another thread. Once the old memory is released, a failure ends the process, as Linux's does. The thread pointer starts at zero, and close-on-exec descriptors close |
| `wait4` | a child by pid, or any child with -1, once its last thread has gone; `WNOHANG`. The status is the exit code's low 8 bits shifted up 8; the signal's number for a child a signal ended, a trap included, which is `SIGSEGV`; or 9, `SIGKILL`'s, for a child the kernel killed for another reason. No core bit is ever set. A process group is `EINVAL`; `rusage` is not written |
| `futex` | `FUTEX_WAIT` with an optional relative timeout, and `FUTEX_WAKE`, private or not; any other operation is `ENOSYS` |
| `exit` | ends the calling thread, and its process with it when it was the last |
| `exit_group` | ends every thread of the process; the low 8 bits of the code, as Linux reports a status |
| `rt_sigaction` | any signal but `SIGKILL` and `SIGSTOP`, which are `EINVAL`; `sigsetsize` must be 8. A handler must carry `SA_RESTORER`, since the kernel has no trampoline of its own to return through; one without is `EINVAL`. `SA_SIGINFO`, `SA_RESTART`, `SA_NODEFER` and `SA_RESETHAND` are honoured, and `SA_ONSTACK` has no effect, as with no alternate stack set. Setting a signal to be ignored discards it where it is pending |
| `rt_sigprocmask` | `SIG_BLOCK`, `SIG_UNBLOCK` and `SIG_SETMASK` on the calling thread's mask; `SIGKILL` and `SIGSTOP` are never blocked |
| `rt_sigpending` | the pending signals the calling thread blocks, its own and its process's |
| `rt_sigreturn` | resumes from the frame below the stack pointer, validated; a frame it refuses ends the process with `SIGSEGV` |
| `sigaltstack` | reports that there is no alternate stack; setting one is `ENOSYS`, and logged |
| `kill` | a signal, or 0 to ask whether the process exists, to a Linux process by pid. A process group and -1 are `EINVAL`, and so is `SIGSTOP`, since nothing here stops a process |
| `tgkill` | a signal to one thread of a process, by tid; a process's first thread, whose tid is the pid, before it has made a call, takes it as its process |

**The thread pointer** is part of a user thread's saved context on both ports. The context
switch reads `FS` base (x86_64) or `TPIDR_EL0` (aarch64) back into the thread it switches away
from and loads the one it switches to, for threads bound to a process; a switch between kernel
threads touches neither. aarch64's EL1 exception entry, which used `TPIDR_EL0` and
`TPIDRRO_EL0` as scratch, now uses `SP_EL0`, whose value the frame of the trap from EL0 already
holds, and `TPIDRRO_EL0`, zeroed before it returns.

**`fork`** builds the child's address space with `mm::vm::Vm::fork_into`. Every region is
reserved at the same address, every mapped page is mapped to the same frame read-only in both
spaces, and every Linux process counts its shares in one store, so whichever side writes a page
first copies it and the other keeps the original. The parent's pages made read-only are
invalidated as every replaced leaf is, with a shootdown on a multiprocessor. The child's thread
comes from the kernel's pool of process threads and resumes with the parent's full registers
(`hal::HasUserMode::resume_user`); x86_64's system call frame carries the callee-saved
registers for this. The child inherits console and pipe descriptors. It does not inherit open
files, because the namespace has no way to share one open file between two descriptors, so the
child's copies are closed.

**Futexes** hash an address and its address space to one of 8 buckets, each a wait queue with a
count of wakes. A waiter checks the futex's value and reads the count under one lock, and a
waker counts under that lock before it wakes, so a wake between the check and the block shows
as a changed count rather than being lost. A wake wakes the bucket, and every waiter looks
again, as a futex waiter must.

**Signals** divide as Linux divides them (`kernel/main/src/personality/signals.rs`). A process has
a disposition for each of the 64 signals and a set of signals sent to it as a whole; each thread
has a mask and a set sent to it alone. A `clone`d thread starts with its creator's mask, a `fork`ed
child with the parent's dispositions and the forking thread's mask, and `execve` resets every
handler to the default while an ignored signal stays ignored.

- **Delivery** happens on the way out of a system call, the one place the kernel returns to a
  Linux thread with its registers at hand: the lowest-numbered signal that is pending and not
  masked, the thread's own before its process's. An ignored one is discarded. One whose action
  ends the process ends it, and `wait4` reports the signal. One with a handler gets the frame
  Linux pushes, and the call returns into the handler, with its `sa_mask` and, unless
  `SA_NODEFER`, the signal itself added to the mask.
- **The frame** is `kernel/linux`'s `signal::build`: on x86_64 an `rt_sigframe`, the restorer as
  its return address, then a `ucontext` whose `sigcontext` holds every general register and a
  `siginfo`, below the 128-byte red zone and aligned as a call leaves the stack; on aarch64 a
  `siginfo` and a `ucontext` whose `sigcontext` ends in 4 KiB of reserved space, with a frame
  record above it that the handler's `x29` points at. The handler starts with the signal, the
  `siginfo` and the `ucontext` in its first three argument registers. Neither frame holds
  floating-point or SIMD state: a handler that uses those registers changes them under the code
  it interrupted.
- **`rt_sigreturn`** reads the frame back with `signal::restore`. The frame is the program's to
  write, so a return address outside the user half, or on aarch64 a processor state that is not
  EL0 with only the condition flags, is refused, and on x86_64 only the flags a program may hold
  are kept. A segment or a privilege level is never read from it. The restore then goes through
  the port's `set_registers`, which sanitises the address and the flags again.
- **A signal whose action ends the process** is acted on when it is sent, not when a thread
  next returns: the process ends as `exit_group` ends it, a thread spinning in user mode
  included. A handler, though, waits for its thread's next system call, since the interrupt path
  has no registers to build a frame from.
- **Blocking calls.** A pipe read or write, a futex wait and `wait4` look for a deliverable signal
  that is not ignored each time they wake, and sending one wakes the personality's queues. The
  call ends with `EINTR` when a handler without `SA_RESTART` runs after it. When the handler has
  `SA_RESTART`, or no handler runs after all, the call returns to its own system call instruction
  with its arguments, and runs again.
- **Generated by the kernel:** `SIGCHLD` to a parent when a child's last thread has gone, and
  `SIGPIPE` to a thread whose write found no reader. A trap ends a Linux process as `SIGSEGV`
  would, but runs no handler, since the trap hook has no registers either.

**Limits, all of them fixed sizes:** 4 process slots, and a pool of 3 process threads at once per
check, an exited thread's entry given back when the next thread starts; 8 thread records, and 16
threads with signal state; 4 pipes; 128 shared-page counts across every Linux process. A child's process slot is freed when whatever started the
process tree tears it down, not by `wait4`.

**Start-up.** `argv` is `["hello"]`, or `["hello", <mode>]` for the modes the scheduled check
and the stress run start, and `envp` is `["HOME=/"]`. The auxiliary vector carries:

- `AT_PHDR`, by Linux's rule for a static executable;
- `AT_PHENT`, `AT_PHNUM`, `AT_PAGESZ` and `AT_ENTRY`;
- zero for `AT_UID`, `AT_EUID`, `AT_GID`, `AT_EGID` and `AT_SECURE`;
- `AT_RANDOM` and `AT_EXECFN`.

`kernel/linux` lays the stack out and host-tests it by reading it back the way start-up code
does. Every argument register is zero at entry.

**Unimplemented calls** return `-ENOSYS` and log `linux: <name> (<number>) is not implemented`.
They log the name and number, but not the arguments or the process. With `LINUX_ENOSYS_FATAL`
the same line ends the process instead, recorded as killed. CI does not run with it on: there is
no corpus yet for a gap to fail.

**What it does not do yet:**

- **Signals are not complete.** Nothing stops a process: `SIGSTOP` is refused, and the default
  action of the other stop signals does nothing. There is no alternate signal stack,
  `rt_sigsuspend`, `rt_sigtimedwait` or `signalfd`. A pending signal is a bit, so a second one
  sent before the first is delivered is lost, real-time signals included. A handler for a thread
  spinning in user mode waits for its next system call, and no handler runs for a trap. The frame
  holds no floating-point state.
- **No sockets.** `socket` and the calls after it are logged as unimplemented.
- **`AT_RANDOM`'s bytes are not secret.** They are a SplitMix64 stream seeded from the
  process's page-table root and entry point. A C library seeds its stack protector from them.
- **Only the checks have a filesystem namespace.** A Linux process started any other way, the
  stress run's included, would find `openat` and `execve` failing with `EIO`.
- **`execve` does not end a process's other threads**, and refuses instead.
- **On a multiprocessor, a `fork` or an `execve` can hang against another process's page
  fault.** Both change mappings under the frame lock every process's `Vm` operations take, and
  a change that makes a page read-only or unmaps one shoots down TLBs while holding that lock.
  A thread faulting on another CPU at that moment spins for the lock with interrupts masked,
  so it never answers the shootdown. The rule in `shootdown.rs` forbids exactly this, and a
  native process installing its program breaks it the same way. The stress run hung on eight
  CPUs when it started one Linux process before installing the next, and it now installs both
  first. The general fix is a frame lock whose spin answers shootdowns, or per-process
  locking. That is in `userproc`'s object layer, not here.
- **No `dup`, `mprotect`, `/proc`, or console input.**

### The tag

Every process carries a personality, fixed at load time:

```rust
pub enum Personality {
    Native,
    Linux,
}
```

The design put the tag in the thread control block as a pointer to a syscall dispatch table.
As built, it is on the `Process`, and every thread of a process speaks its process's ABI:
a thread `clone` starts is a Linux thread because its process is a Linux one. Either way, there is no branch on personality in the
syscall path and no cost to a native process for the compat layer existing.

A process is tagged `Linux` when its ELF carries no KinTane ABI note and declares
`ELFOSABI_LINUX` or `ELFOSABI_SYSV`, as the table above has it. A creating process asking for
the tag explicitly is not built.

Native binaries carry the note. The design made the fallback for unmarked SysV binaries a
config option. As built, it follows `ABI_LINUX`: an unmarked binary is a Linux one when the
kernel has the personality and refused when it does not, because in practice an unmarked
binary is a Linux binary, and making that work without ceremony is the point.

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

As built, `ABI_LINUX` is a `bool` that depends on `USERSPACE && (ARCH_X86_64 || ARCH_AARCH64)`, defaults to `y`,
and is compiled in. `LINUX_ENOSYS_FATAL` (default `n`) turns an unimplemented call into the
process's end. Both live in `config/main.kcfg`. The design is tristate, and `m` by default: the
personality is a loadable module in a general-purpose build, compiled in for appliance builds,
and absent from embedded ones. It becomes tristate when the personality can be built as a
module. A kernel that runs Linux binaries and a kernel that fits in 64 KiB are the same
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

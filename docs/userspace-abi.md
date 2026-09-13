# Userspace ABI

Status: **design sketch.** Nothing here is implemented, and the details will move.
The principles are the commitment; the syscall numbers are not.

## Decision: our own ABI

KinTane does not implement the Linux syscall interface. The reasons:

- Linux compatibility is all-or-nothing in practice. Partial compatibility produces
  software that runs until it does not, which is worse than software that does not
  run.
- The Linux ABI encodes forty years of decisions about a machine with an MMU, a
  process model, and POSIX signals. We want to serve machines with none of those.
- `errno`, `fork`, ambient authority through the filesystem namespace, and integer
  file descriptors are exactly the parts we would most like to do differently.

The cost is real: no existing userland, so we write our own, and the ecosystem
argument is not on our side. We accept it because a kernel that exists to support
unusual hardware should not start by adopting an ABI designed around usual hardware.

A Linux compatibility layer *in userspace*, translating to native primitives, remains
possible later. It is not a goal.

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

Deliberately small. The target is under fifty syscalls, with functionality that would
otherwise be syscalls expressed as messages to services over channels. Anything that
looks like it wants to be an `ioctl` is a channel protocol instead.

Syscall dispatch is generated from `#[syscall]` attributes
([build-system.md](build-system.md#generated-sources)), which keeps the numbering
table, the argument-validation code, the userspace bindings, and the documentation
generated from one source.

## Scaling down

On a no-MMU target most of this collapses, and that is intended rather than a
degradation to apologize for:

- There is one address space. `MemoryRegion` and `Mapping` still exist but map
  identity.
- Isolation is by MPU region where available and by convention where not. A
  microcontroller build is cooperative and we say so, rather than implying a
  protection guarantee the hardware cannot make.
- Processes may be static, defined at build time, with no loader.
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

The ABI is unstable until Phase 6 completes. After that: syscall numbers and
structure layouts are frozen within a major version; additions are additive; removals
require a major version and a deprecation period of at least one. The `Completion`
and `Channel` protocols are versioned independently of the syscall numbering, because
they will evolve faster.

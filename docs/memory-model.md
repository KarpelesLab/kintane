# The Memory Model

What one CPU may assume about memory another CPU wrote, and where the kernel's code
depends on it. The roadmap asks for barriers "placed against a written memory model";
this is that model, and the list of places.

**Status: argument and review, not test.** QEMU's TCG runs guest memory as the host's,
which is x86's strongly ordered memory. It does not model the weaker ordering aarch64
permits, so every ordering below would pass under emulation with `Relaxed` in its place.
Each entry here was placed by reading the code against the rules, and checking it again
means reading again. That remains true until a model checker or real Arm hardware under
stress can say otherwise.

## The model

A CPU's write to shared memory is not visible to another CPU at a definite instant. The
store may sit in a store buffer or a cache line the reader has not synchronised with.
Rust's atomic orderings name the synchronisation points, and the kernel uses them in the
pairs its `SpinLock` already does (`kernel/sync/src/spin.rs`):

- **`Release` on a store publishes.** Everything the writing CPU wrote before it, to
  any location, becomes visible to a reader that synchronises afterwards.
- **`Acquire` on a load synchronises.** The reader sees every write published by a
  `Release` that happened before the load.
- **`AcqRel`** does both, for compare-and-swap, `fetch_or` and the like that read and
  publish in one operation.
- **`Relaxed`** promises nothing across CPUs. It is correct only when one of the
  following holds:
  - the value is touched by one CPU at a time, and a lock hands it over;
  - it is written and read on the same CPU;
  - it is a statistic, where a stale read is a stale number and nothing more.

**A lock is a publication.** The ticket lock's release is a `Release` store and its
admission an `Acquire` load. So anything written inside a critical section is visible to
the next holder, on any CPU. Most shared state below relies on that, and needs no
ordering of its own.

**Transitivity is what the handshakes rely on.** A thread that writes several values
and then makes one `Release` store has published all of them. A reader that sees that
store through an `Acquire` load sees them all. That is how a single "parked" flag makes
a whole workload's state safe to audit.

## Shared state and how it is published

### The scheduler (`kernel/main/src/preempt.rs`, `kernel/thread`)

| State | Written | Read | Published by |
|---|---|---|---|
| Thread table: metadata, run queues, `current` | under `sched.table` | under `sched.table` | the lock |
| Saved thread contexts | the switch, on the leaving thread's CPU, with the lock held | the switch that resumes the thread, on any CPU, with the lock held | the lock, which the resumed thread releases only after the save |
| `STARTS` (a new thread's entry and argument) | `spawn`, `Release`, under the lock | `thread_start`, `Acquire`, after the switch that started it | the lock and the pair |
| `JOINED` | `join`, `Release` | the timer hook, `Acquire` | the pair |
| `BROKEN`, `PULLS`, `RESCHEDULES`, `KICKS` | any CPU, `Relaxed` | reports | statistics |

**The context switch** is the one place a lock's publication carries a CPU's registers
to another CPU. CPU A's thread saves its context with the lock held. The thread A
switches to releases the lock, which is a `Release` store after the save. Later, some
CPU B admits a holder through an `Acquire` load and resumes the saved thread. B
therefore sees the whole saved context. Releasing the lock before the switch would break
this, and that is also why the lock spans the switch at all.

### Time (`kernel/main/src/timekeeping.rs`)

| State | Written | Read | Published by |
|---|---|---|---|
| Clock, timer queue | under `time.clock` / `time.timers` | under the same lock | the lock |
| `ARMED_UNTIL` (when the boot CPU's timer fires) | boot CPU's `program`, `Release`, under `time.timers` | a sleeper's `sleep_needs_kick`, `Acquire`, under `time.timers` | the lock, and the pair stated anyway |

`ARMED_UNTIL` is read in the same critical section in which the sleeper arms its timer.
The boot CPU writes it in the critical section in which it reads the earliest deadline.
Serialised by the lock, either the boot CPU's read sees the new timer, or the sleeper
sees the boot CPU's arming and sends it a reschedule IPI.

### TLB shootdown (`kernel/mm/src/tlb.rs`, `kernel/main/src/shootdown.rs`)

| State | Written | Read | Ordering |
|---|---|---|---|
| request address | initiator, `Release`, before the pending set | target, `Acquire`, after seeing its pending bit | a target that sees its bit sees the address |
| pending set | initiator `Release`; target `fetch_and` `AcqRel` | initiator, `Acquire` | the initiator sees zero only after every target's clear |
| answered set | target `fetch_or` `AcqRel` | initiator, `Acquire` | as above |

A target clears its bit **after** it flushes. The cleared bit is the initiator's licence
to reuse a frame, so clearing first would publish that licence before it was true. A host
test runs the flush callback while asserting the bit is still outstanding.

### The architecture's per-CPU blocks and hooks (`arch/aarch64/src/smp.rs`, `arch/x86_64/src/smp.rs`, `tick.rs`)

Both ports publish the same state the same way; the x86_64 names differ only in the
start-up column (APIC ID and captured control registers instead of MPIDR and translation
registers).

| State | Written | Read | Ordering |
|---|---|---|---|
| a secondary's stack, MPIDR, translation registers | boot CPU, `Release`, before `CPU_ON` | the secondary as it starts, `Acquire` | the pair |
| a secondary's state, IPI token, answers | the secondary, `Release` | the boot CPU, `Acquire` | the pair |
| the scheduler's entry for secondaries | `release`, `Release`, before the waking IPIs | the secondary's idle loop, `Acquire` | the pair |
| the shootdown hook and TLB IPI handler | `set_shootdown` / `set_tlb_handler`, `Release` | `flush_tlb` and the IPI path, `Acquire` | the pair |
| the tick hook | `set_hook`, `Release` | the interrupt path, `Acquire` | the pair |
| the interrupt controller | once, before any secondary starts | every CPU | before the reader exists |

### Everything per CPU

- **`sync::PerCpu` slots, lockdep's held-lock stacks, the kernel heap's interrupt depth.**
  Written and read on the CPU that owns them, with interrupts masked for the read of the
  CPU number. `Relaxed` is correct. A read of another CPU's slot is a statistic.

### The stress run's handshake (`kernel/main/src/stress.rs`)

The auditor inspects state that workloads on other CPUs wrote: handle tables, frame
pools, progress counters. Its only synchronisation with them is the park handshake:

- the auditor stores `PARK` with `Release`, and workloads load it with `Acquire`;
- a workload stores its `PARKED` state with `Release`, last, after its final write
  before stopping;
- the auditor loads `PARKED` with `Acquire`, and only then reads anything the workload
  wrote.

By transitivity, the auditor sees the workload's handle tables and pools exactly as the
workload left them. These were `Relaxed` on one CPU, where that was correct, and became
wrong the moment the workloads could run elsewhere.

## Rules the code keeps

1. **Shared across CPUs means a lock, or a `Release` store answered by an `Acquire`
   load.** `Relaxed` needs one of the three reasons above, and the code says which.
2. **Never let a writer's barrier come before its writes.** A target clears its shootdown
   bit after flushing. A workload marks itself parked after its last write. A thread's
   context is saved before the scheduler lock is released.
3. **No lock held across a TLB shootdown may be waited for with interrupts masked, unless
   the wait answers shootdowns itself.** The initiator may itself be masked: it can be a
   page fault handler. It waits for every other CPU to take an IPI, so a CPU spinning masked
   for a lock the initiator holds, and not answering, is a deadlock. Three locks are held
   across shootdowns and waited for masked, and each wait answers:
   `SpinLock::lock_irqsave_with` calls the shootdown service on every turn of its spin.
   - the shootdown's own serial lock (rule 4);
   - each process's lock (`userproc::lock`), an owner word whose spin answers;
   - the frame lock every process's `Vm` operations take (`userproc::with_frames`). Until
     the ninth round it was a plain masked spin, and a thread faulting on one CPU while
     another installed a program, unmapped or forked hung both; the stress run's churning
     pairs reproduce that on every SMP preset.

   The kernel `Vm` pool in the stress run is taken with a plain masked spin, and is safe
   only because that `Vm` is used by one thread and its own page faults, and the audit
   takes the lock after that thread has parked. A second user of it needs the answering
   wait, or shootdowns deferred until the lock is released.
4. **Initiators answer while they wait to initiate.** Two simultaneous shootdowns would
   otherwise each wait for the other's IPI.
5. **The scheduler lock spans the context switch**, and every path that can resume a
   thread releases it: the end of `yield_on` / `block_on` / `exit_on`, and `thread_start`.

## What would falsify this, if anything could run it

- Replacing any `Release`/`Acquire` pair above with `Relaxed`, run on a many-core Arm
  machine under the stress mode, should eventually fail an audit or corrupt a channel.
  Under QEMU it passes, which is exactly why this file exists.
- A lock-free reader added without an entry here is a review failure, whatever the tests
  say.

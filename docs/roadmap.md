# Roadmap

Phases are ordered by dependency, not by calendar. Each has **exit criteria** that are
demonstrable — something boots, something passes, something fits in a budget — because
"mostly done" is not a state a kernel phase can be in.

## Status

| Phase | State |
|---|---|
| 0 — Build system and first boot | **done**, including `kinboot-efi` |
| 1 — The portability spine | **done**, including `kinboot-bios` |
| 2 — Core kernel | **every item landed**; the stress audit is judged in slices rather than wall-clock windows, and `kbuild soak` runs it unattended; **a two-hour soak at 8 CPUs passed 7,200 audits of 7,200** while five branches shared the host, and the 24-hour run is not yet done |
| 3 — SMP and the device model | **exit criterion met**: 8 CPUs boot and stress clean on both ports; devices, interrupts and consoles through one device model from FDT and from ACPI/PCIe |
| 4 — Configurability, scaling down | riscv32 (with and without atomics), ARMv7-M at 56 KiB of RAM, `mm::flat`, modules, the full config language, random configs, size budgets. Real hardware and a thousand random configs remain |
| 5 — Driver isolation | **exit criterion met** on x86_64, and past it: the same virtio-blk core runs in the kernel and in a ring-3 domain, its interrupt delivered as a message, its DMA confined by VT-d with remapped interrupts and queued invalidation; on `x86_64-isolated-smp` the client, the interrupt and the domain each run on a different CPU; a faulting domain dies alone and restarts; the cost is measured. AMD-Vi, SMMUv3 and per-domain quotas remain |
| 6 — Userspace and the Linux personality | 6a closed, including channels as counted objects and a standing file server. 6b on x86_64 and aarch64: threads, pipes, futexes, copy-on-write `fork`, `execve`, `wait4`, signals delivered from interrupts and faults, TCP and datagram sockets, `poll`/`select`/`epoll`, and file writes. Queued real-time signals, `MSG_PEEK`, scattered and gathered messages, and floating-point state carried in a signal frame and validated on return are built too. Stopping signals too: a stop parks a process at its next system call and `SIGCONT` resumes it, reported to a parent by `wait4` with `WUNTRACED` and `WCONTINUED`. What remains unbuilt is alternate signal stacks, `rt_sigsuspend`, `rt_sigtimedwait`, `signalfd`, and `SIGCHLD` on a child's stop |
| 7 — Real hardware and real work | started early: disks with MSI-X and INTx through `_PRT`, an interrupt that belongs to its device rather than its driver, FAT16 and FAT32 written as well as read and both crash-tested and fuzzed, and directories a program can list; virtio-net with IPv4 reassembly, TCP with congestion control, out-of-order delivery and selective acknowledgement on both sides, exercised against a peer kbuild controls end to end; datagram and stream sockets over handles and through Linux calls; an EFI stub, image formats, reproducible releases, a last-known-good boot counter |

### The fourteenth round of landings

Nineteen presets build and boot. Four briefs ran; three have landed, and the round's most useful
result is a measurement that found nothing.

- **Selective acknowledgement and a refused datagram, exercised in a guest at last.** Both halves of
  selective acknowledgement have existed since round 12 and had never once run in a boot, because
  QEMU's user-mode network offers no SACK-permitted and sends no unreachable message — established by
  packet capture rather than assumed. kbuild's own peer now offers both: it acknowledges selectively,
  and refuses a datagram to a quiet port so a connected socket answers `ECONNREFUSED`. Three rounds
  of work reach a guest, and the two "host-tested only" notes come **out** of the documents rather
  than standing next to checks that now contradict them.
- **And selective retransmission turns out to save nothing at this ring size.** Seven segments, 610
  bytes, resent identically across five boots whether blocks are sent, ignored, disbelieved or never
  offered — a ratio of 1.00. That is arithmetic, not a defect: a send ring is one pool buffer, so a
  bulk round is four segments and exactly one may be dropped; a single hole yields a *full*
  acknowledgement, which NewReno already answers with one resend. The saving lives at a **partial**
  acknowledgement — two holes and five segments in flight, one more than the ring holds. Raising the
  ring is memory every port pays for, so it was left to a round willing to decide that cost
  deliberately, with the number written down rather than the conclusion.
- **A program lists a directory through the file server.** `Op::Getdents` is driven over a channel in
  a boot and the verdict gates on it, so the listing arm is no longer implemented, documented and
  unexercised. Listing runs on the **read-only** connection, since listing is read-side; the writable
  one only creates the fixtures. The kernel then walks the same directories itself and requires every
  name to be listed with matching kind **and** the record counts to agree — the two directions being a
  dropped entry and an invented one. `..` stays a refusal, now with its reason recorded: FAT's one
  scan skips it, `/FAT32/..` names another filesystem's root that `lookup` cannot express, FAT's
  on-disk `..` records cluster 0 as a sentinel, and ascending would let a read-only connection escape
  its subtree.
- **A signal frame carries floating-point state instead of refusing it.** `HasFpu` grew `save_live`
  and `load_live`, because a context switch moves state between two stored `Context`s while a frame's
  bytes belong to nobody — a distinction earlier rounds never had to make. `restore` now *validates*:
  x86_64 accepts only the pointer naming the area inside that very frame, aarch64 exactly Linux's
  magic and size, and null is malformed rather than "nothing claimed". `linux-hello` became the
  hard-float Linux program at zero image cost, which is precisely the prerequisite round 13 recorded
  as missing.
- **A bug the ports could not show, and the boot did.** aarch64 saved the vector registers before the
  control words while Linux's order is the reverse, because the paired store needs a 16-byte aligned
  address. Eight bytes of skew: a handler editing `d0` edited `v1`. x86_64 never showed it, since
  `FXSAVE`'s layout is the hardware's — and it surfaced only in the check its author called the one
  he would have been most tempted to skip.

**What the round taught about checks.** Five times this round the code under test was sound and the
thing proving it was broken: a falsification grep that also matched a test fixture; a guard using
`grep -q` with `\{` and `\(`, which a basic regular expression reads as operators, so it reported
mutations as unapplied that had applied; a restore set that omitted one file and left a mutation in
the tree; a step-code audit that examined only explicit `return` statements and silently skipped five
functions that return trailing expressions; and an isolation test whose verdict read the exit status
of a pipeline instead of the command. Every one of them **passed**. The habit that answers it is the
one the floating-point work committed: its two corpus seeds are pinned by a test asserting that the
well-formed one is accepted, the malformed one is refused, and the two differ in nothing but the size
field — so a seed that decays into a no-op fails loudly instead of replaying nothing.
- **A second drive, each disk confined to a grant of its own.** Two drives now, each with its own
  file, distinguishable by content: the disk index folds into the existing hash *before* its shift,
  so the first disk's image does not change a byte while the second shares almost no sector with it.
  That detail is the check — two identical images would have left "did this read come from the right
  disk?" satisfiable by exactly the confusion it exists to catch. The block layer carries the device
  through as per-slot arrays with an interrupt trampoline each, since the device model's table holds a
  bare function pointer that cannot say which device fired; and the IOMMU gained a domain per device
  with faults attributed by **source id**, because the fault log is shared and matching only on
  address and direction would accept another device's fault as this one's.
- **The volume is now found by reading rather than by assuming, and that was a real bug.** QEMU fills
  the virtio-mmio slots *downwards* as devices are created while enumeration walks the tree *upwards*,
  so on aarch64 slot 0 is the **second** drive: trusting the slot number mounted the wrong disk. The
  primary is chosen by reading each disk's header. `disk()` now means the volume-carrying disk, which
  is what all fifteen of its callers already meant — so none of them changed.
- **Three of that brief's four checks were written, falsified, and deliberately not landed.** They
  compile, pass, and fail in three directions when mutated; they are kept as a patch. The blocker was
  size, measured rather than estimated: one preset went over by 6,828 bytes, and the two i686 images
  reached exactly 100% of their budget and **hung at boot**. The obvious remedy was tried first and
  reported insufficient rather than abandoned quietly. Raising three budgets to carry a
  verification-only check, in a round whose brief was to defend them, is a trade worth refusing.

**The round found a hole in its own gate.** `kbuild size` returns success at *exactly* 100% of
budget, so the size check passed the two i686 presets while their boots hung — every "all nineteen
within budget" statement this round rested on a check that cannot tell "fits" from "exactly fills and
will not boot". It was found by the one brief that pushed an image hard enough to sit on the
boundary, which is the argument for briefs that defend a budget rather than raise it.

### The thirteenth round of landings

Nineteen presets build and boot, with `x86_64-peer` new. Four briefs ran; two of them stopped short
on purpose, and the stopping is where the round's value is.

- **Floating-point state survives a context switch, and a guest proves it.** Each port's own
  `Context` carries the whole user-visible set — a 512-byte `FXSAVE` image on x86_64, the vector
  registers and their control words on aarch64 — saved eagerly. `FXSAVE` rather than `XSAVE`,
  because the visible set is x87, MMX and SSE, which it covers in a fixed size needing no run-time
  negotiation, and nothing this kernel builds enables anything wider; the default image is
  deliberately not zero, since an all-zero one unmasks every SSE exception. Eager was chosen against
  a measurement, and because lazy saving fails **silently** — as a thread computing with another
  thread's numbers. A boot check now runs the hard-float program and grades it, so the x86_64 enable
  bits are tested at runtime rather than argued, and two threads hold different values in the same
  eight vector registers across sixty-four yields.
- **An ABI bug older than the round, found by that work.** Native threads were entered on a
  sixteen-byte aligned stack, where System V promises an `extern "C"` entry the eight-byte gap a
  call would have pushed. It surfaced as a fault on a **compiler-generated** aligned vector store —
  invisible to every soft-float program ever run here, and unsurvivable for the first hard-float
  one. It is a HAL constant now: eight on x86_64, zero on aarch64, which is exactly why the same
  test passed there untouched.
- **A program can list a directory.** `getdents64` answers on both architectures at Linux's own
  numbers, reporting long names as themselves rather than the short aliases FAT also answers to,
  distinguishing a directory from a file, and filling a small buffer across repeated calls without
  losing or repeating an entry — a record that does not fit is never consumed, because the cursor
  advances only once the record reaches user memory. What an offset *promises* is written down
  rather than implied: an index names a place in the directory as it is now, not a name, because no
  filesystem here has a stable per-entry cookie, so a program removing entries while listing may see
  a name twice or miss one. The cost is stated with it — finding the *n*th entry counts from the
  first.
- **A `statfs` answer is now held against the kernel's own walk**, and falsifying it showed exactly
  the gap that closes: a fabricated free count satisfied **every step the program runs on itself**
  and still exited successfully, while the kernel's walk caught it. Self-coherence proves only that
  a program was answered consistently; a driver reporting the same wrong number to every asker would
  pass.
- **kbuild is now a network peer of its own, in four verified stages.** With the user-mode network
  replaced by a socket pair carrying raw Ethernet, kbuild answers ARP to the guest's own request,
  echoes, the announcements, acknowledgements, a UDP service, a deliberately silent port and a
  fragmented datagram it builds and splits itself; then accepts TCP across three rounds — both close
  orders, and a bulk round where dropping each connection's first in-order segment makes the guest's
  **fast retransmit** reachable in a guest for the first time; and finally **originates**, opening
  the connection the guest announces, so the server, poll and peek modes pass and the preset joins
  the gate.
- **The device layer went further without the second drive landing.** A block device's interrupt
  line now belongs to that device: the driver's slot numbering is authoritative, so the platforms no
  longer keep a parallel counter that agrees until probe order and wiring order diverge, and the
  platforms' line and message-signalled-interrupt facts became arrays — because a cell whose first
  write wins was **discarding a second device's line at the moment discovery found it**.

**Two briefs stopped deliberately, and both left the next attempt strictly better off.**

- **The second drive.** Before editing anything, the fork attached a second drive and asked the
  kernel what it had bound: `bound=2`, boot green, two register windows and two interrupt tables.
  Enumeration already claims both functions, so the blocker was never discovery — it is that every
  layer above is a singleton *by shape rather than by parameter*: one disk, one grant, one
  confinement taken from the first matching device, one forwarder, one mount, one drive in the build
  tool. It stopped on a clean line with nothing half-applied.
- **`HasFpu`'s signal frame.** The frame still *refuses* a frame claiming floating-point state
  rather than carrying one. Making that honest needs a hard-float Linux program, which does not yet
  exist — only the dedicated test program opts in.

**What the round taught about landing large work.** Two earlier attempts at the network peer
concluded it could not land incrementally, because any preset carrying a partial peer fails its own
network check. That is true only of a preset the gate already runs — and the gate's list is
explicit. Held outside it, the same job produced four committed, individually verified stages, each
finding something the next one needed: that a frame count means nothing until the card actually
initialises; that with no network in between, a disturbance must be something the peer *chooses* to
send; that forgetting a connection one acknowledgement too early strands the guest in LAST-ACK; and
that a requirement in the brief — sending frames unprompted — was unnecessary, because the guest
re-announces every half second, so the announcement is the prompt and no retransmit timer is needed
anywhere.

**Still open.** Selective acknowledgement and an ICMP refusal exercised in a guest, which the peer
can now offer for the first time; the second drive, starting from the singletons above the device;
floating-point state in a signal frame, which needs a hard-float Linux program; the file server's
listing arm, implemented and documented but not yet exercised over a channel in a boot; and, as
before, real hardware, Secure Boot with a TPM, and the 24-hour soak.

### The twelfth round of landings

Eighteen presets build and boot. Six branches ran; three of them declined their headline item and
said why, which is the round's real result.

- **The soak's comparison now knows what it is comparing.** The guest names each heartbeat number's
  kind in a line printed beside the code that prints the numbers, so the two cannot be edited apart,
  and kbuild no longer guesses from a hardcoded list: a count is judged by its rate, a level by
  whether it is still climbing at the end, a mean by its value. The four marks the eleventh round's
  two-hour soak produced were every one a rate test applied to a high-water mark or a mean, and they
  are gone. Reading the comparison for those artifacts exposed the opposite hole, and a worse one: a
  count that stood at zero through the first window had no rate to compare, so it printed as a dash
  and was passed over — **a leak beginning after the first window was invisible**, which is precisely
  what a long run exists to catch. That is a finding of its own now, as is a count that goes
  backwards, and three fields silenced by being called gauges are counts that should stay at zero.
- **Selective acknowledgement has both halves.** A peer's blocks are recorded against the connection
  and clamped to what was actually sent, so recovery starts at the first byte the peer has not
  reported and a retransmission steps over the runs it holds; a block naming data this end never
  sent is discarded rather than believed, and a timeout still falls back to go-back-N. Separating
  the two took care: with or without the blocks, **the first retransmission starts at the same
  byte** — go-back-N and selective recovery agree on where a hole begins, and only its length
  differs, so that is what the tests compare.
- **An interrupt belongs to a device, not to a driver.** `Driver::interrupt` now names the bound
  device, and virtio-blk keeps an indexed slot per disk where it kept one cell and turned a second
  device away. Each slot dispatches through a trampoline of its own, because the device model's
  interrupt table holds a bare function pointer with nothing to say which device fired, and a slot
  count that outgrows its trampolines is a compile error. Every preset still completes 32 requests
  in 32 interrupts — on MSI-X, on a plain line, through a ring-3 domain, and across CPUs.
- **A user program can be built for a hard-float target**, which nothing in this kernel could do
  before: two specifications drop the ABI field that was rejecting the floating-point features, and
  a unit opts in and gets a `core` of its own in a flavour whose cache keys cannot be confused with
  the soft-float one. It is an opt-in rather than a switch for every user program, because the
  compiler emits floating-point instructions to move bytes with no float in the source, and nothing
  saves those registers across a context switch yet. That a program really was built this way is
  checked by disassembling it — a soft-float build computes identical answers — and **that check was
  wrong twice before it was right**: matching register names matched the disassembler's encoding
  bytes, so a soft-float binary scored higher than the hard-float one, and the mnemonic parser
  skipped `fadd` because that word is four hexadecimal digits.
- **FAT32 reaches the machinery that was FAT16-only**, and a Linux program can ask what filesystem
  it is on. The crash workload writes both volumes and kbuild reads both back after every cut,
  tolerating the lost clusters and one-step-apart tables the write ordering allows while still
  refusing inconsistency; the stress workload writes the second volume under the same lease; and the
  fuzz target gained the second format over a sparse disk, because a 34 MiB volume cannot be copied
  per cut point. `statfs` answers for the filesystem covering a path and `fstatfs` for the one an
  open descriptor's file is on, on both architectures. **Two vacuous passes were closed by evidence
  rather than assumption:** a volume below FAT32's cluster boundary is FAT16 to every reader, so
  without a test that the second format really is FAT32, every FAT32 input would have exercised
  FAT16 and passed — the one failure a fuzz target cannot report about itself.

**Three refusals, each with its measurement.**

- **Floating-point state in a signal frame, again — and now the reason beneath the reason.** User
  programs were compiled from the kernel's own soft-float target, so no code in the image could name
  a floating-point register at all: `a * b` in a user program became a call to `__muldf3`. Every
  check `HasFpu` would need was therefore unwritable, and the branch declined to land the
  context-switch half alone rather than ship save-and-restore code with no test that could fail. The
  hard-float target above exists because of that refusal, and makes the work falsifiable.
- **A peer that could exercise selective acknowledgement in a guest.** This host has no tap device,
  no `ip`, no `tunctl`, and QEMU's `vmnet` backends need root; the one usable backend replaces the
  user-mode network outright, so kbuild would have to answer ARP, echo, the probes, the UDP service,
  the fragmented datagram and the whole TCP service before a single block could be sent. The design
  is decided and recorded; the kernel half it would gate was built instead.
- **The second drive.** Verifying the survey found it incomplete: `platform::block_line()` alone has
  fifteen callers that each need a device index, and the platforms, the IOMMU, the driver domain and
  the filesystem each keep their own singleton besides. The device layer was made plural and left at
  a clean line, with nothing half-applied and no disk layout moved.

**What the round taught about its own instructions.** Numbers assigned in advance again produced no
collisions, and the two defects the eleventh round found in *my* assignments did not recur. But two
briefs were wrong in substance, and both were overruled with evidence: one told a branch to switch
every user program to a hard-float target, which would have had user threads clobbering each other
silently; another told a branch to require a refusal that nothing on the network can send. A fourth
stale-tool incident also went into the record — a rebuilt binary turned a passing crash campaign
with no FAT32 columns into the real result.

**Still open.** `HasFpu` itself, now falsifiable; a boot check that runs the hard-float program, so
the enable bits are tested at runtime; the second drive, starting at `platform::block_line()`; a peer
that can exercise selective acknowledgement or an ICMP refusal in a guest; `getdents`, without which
a program cannot list a long name; a kernel-side check that a program's `statfs` answers match the
kernel's walk; and, as before, real hardware, Secure Boot with a TPM, and the 24-hour soak.

### The eleventh round of landings

Eighteen presets build and boot. Five branches ran in parallel, and the round is as much about what
was refused as about what was built.

- **A race the checks can reach.** The tenth round closed the window between a wait's first
  readiness look and its registering, then found its own checks could not hit it: deleting that look
  left them passing, because a millisecond-paced test cannot aim at a sub-microsecond window.
  `WAIT_RACE_TEST` now compiles a stall point into the wait, parks a thread there, and has another
  make the condition true and wake the queue — on a plain queue and on the set path a program's
  `poll` is woken by. Deleting the second look now **fails the boot**. The check reads the block
  count rather than whether the condition held, because both a fixed and a broken kernel end with
  the condition true; a check asking the obvious question would have passed either. Its own first
  run caught itself racing nothing — the boot thread released before the waiter parked — which is
  the same failure the work exists to prevent. Without the symbol the stall is an empty inline
  function, so a default build carries neither a branch nor a symbol, and `spawn::wait_exit`, the
  last wall-clock bound in that area, now shares the slice-based rule.
- **Long names, and `statfs` reaching a program.** A name that fits eight-and-three keeps the case
  it was written in; anything longer, mixed in case, or holding a space or second dot is kept in
  long entries with a short alias that is never given out twice, and the file answers to either
  name. Only printable ASCII is written: a name the driver will not write is refused rather than
  shortened, including one ending in a dot or space, which every reader strips. Removing or moving a
  name takes away every entry of its set. `statfs` rides a new file-server operation rather than a
  system call, answers for the filesystem covering a path, and a program's answers for both volumes
  are held against the kernel's own walk. **Two of its falsifications failed to catch their
  mutations**, and both tests were strengthened until they did: a leaked long-name set lists as
  nothing, answers to no name and holds no cluster, so listings, lookups and the consistency walk
  are all satisfied by it; and three files sharing one alias are each reachable by their long names.
  A check that surveys state can be satisfied by the very thing it should catch.
- **A receive that looks without taking.** `MSG_PEEK` leaves the datagram in its slot and the
  stream's ring head where it was, and deliberately does not flush — nothing was taken, so nothing
  is acknowledged and no window reopens. `MSG_WAITALL` waits for the whole count on a stream and is
  honestly a no-op on a datagram. Messages carry up to four buffers, gathering one datagram from
  several and scattering one receive across them in order, refusing more rather than carrying half
  a message.
- **The sender's fast retransmit, proven in a guest.** A segment is now a quarter of the send ring
  rather than a whole MSS, so four are outstanding and the three behind a dropped one draw three
  duplicate acknowledgements; kbuild's relay already drops each connection's first data segment, so
  a new bulk round turns that into a gated, falsified check. The smaller segment was chosen over
  several pool buffers per ring because the latter costs about 18 KB on every port, and i686 sits at
  the edge of its budget.
- **Queued real-time signals.** A signal of 32 or above queues eight deep per process: three sent
  are three delivered, oldest first and lowest number first, each carrying its sender's value, and a
  ninth send is refused rather than dropped. Below 32 a signal still coalesces, keeping the first
  sender's value.

**Three things were refused, and each refusal is the finding.**

- **Floating-point state in a signal frame.** Saving it there would be false the moment another
  thread ran: neither port's context switch saves those registers by explicit design, aarch64
  asserts at compile time that nothing in the image can name one, and x86_64 never sets the bit that
  would let a program use SSE at all — a user SSE instruction is `SIGILL` today. So the frame now
  **refuses** one that claims such state rather than reading past it, and the honest home for the
  feature is the `HasFpu` trait that already names the work.
- **Selective acknowledgement and ICMP errors, in a guest.** Before writing either, that branch
  captured a whole boot's frames and parsed them: QEMU's user-mode network offers only MSS — never
  SACK-permitted — and sends no destination-unreachable message at all. kbuild's relay could have
  forged both, but that tests the guest against a peer that does not exist. Both are implemented and
  host-tested and **documented as unreachable in a boot**, with the capture as the evidence. The
  same measurement overruled an instruction of mine: I asked for the quiet-port check to require
  `ECONNREFUSED`, which would have failed every network boot.
- **A second drive.** Every layer that names "the disk" is a singleton — the driver's claims and
  handler, the platform's block line and MSI-X in both ACPI and FDT, the block layer's statics, the
  IOMMU's single domain source, the driver domain's one grant, and the filesystem mounting both
  volumes from one device. That is a six-crate rework before the brief's actual content begins, so
  it was left unstarted and nothing was moved half-way.

**What assigning numbers in advance taught this round.** Round ten collided because native call
numbers were left to chance, so this round every number was handed out first — and **every branch
merged without a single conflict**. But two of the assignments were themselves defective, and only
running the falsifications exposed them: one step band was unrepresentable in an eight-bit exit
status, and another truncated onto its own mode's success code, so a failure there would have been
graded a pass. Assigning was right; the assignments now need checking for truncation and
self-collision before they go out. A third lesson came free: a hard kill during a build can leave a
zero-length object hard-linked inside the build cache, so deleting the build directory does not
clear it and the failure reads like a compiler bug.

**Still open.** Selective acknowledgement's sending half, and a peer that can exercise it or the
ICMP path in a guest; a real second drive; floating-point state, which waits on `HasFpu`;
`rt_sigsuspend` and `rt_sigtimedwait`; FAT32 in the fuzz target, the crash test and the stress
workload; the Linux `statfs` calls; and, as before, real hardware, Secure Boot with a TPM, and the
24-hour soak.

### The tenth round of landings

Eighteen presets build and boot. Six branches ran in parallel.

- **A program can wait on several things at once.** One kernel queue carries every wait over a
  set of objects, woken by each change that already woke something, and readiness takes nothing:
  a channel reported readable still holds its message. The native ABI gains `object_wait_any`,
  and the Linux personality answers `poll`, `ppoll`, `select`, `pselect6` and the `epoll` family
  on both architectures, refusing edge-triggered and one-shot rather than pretending to offer
  them. A native check waits on a channel, an event and a timer at once; a Linux check serves two
  connections kbuild makes into one listener, in the order they arrive. The branch reports that
  its checks do **not** cover the window between a wait's first look and its registering:
  removing that look left them passing, because a millisecond-paced test cannot hit a
  sub-microsecond race. The code closes it; the documentation says the checks do not prove it.
- **Datagram sockets**, from the stack's inbox to Linux's calls. A datagram socket holds a port
  rather than a connection, answers `MSG_TRUNC` with the length the datagram had, refuses
  datagrams from anywhere but the address it connected to, and bounds its waits with
  `SO_RCVTIMEO`/`SO_SNDTIMEO`. kbuild answers a request on a port it announces and leaves another
  unbound, which is how a boot proves that a datagram nobody answers earns a timeout: this stack
  turns no ICMP message into a socket error, and says so.
- **The IP stack has the parts Phase 7 said it lacked.** TCP grows a congestion window in slow
  start and congestion avoidance, fast-retransmits on three duplicate acknowledgements and
  recovers the NewReno way, and computes its timeout from a round-trip estimate under Karn's
  rule. A segment that arrives early is held in the receive ring where the stream will read it,
  so a hole costs one retransmission rather than a window; IPv4 datagrams are reassembled in two
  bounded sets that a hostile sender can only starve of its own. kbuild's relay now disturbs the
  frames going *to* the guest — fragmenting, splitting, reordering and duplicating — so every
  network boot must reassemble a datagram with its pattern intact and hold a segment out of order
  before joining it to the stream. What is deliberately absent (SACK, ABC, PRR, pacing, ECN,
  Nagle, delayed ACKs, reassembly of fragmented TCP) is named in the source rather than left to
  be discovered, and the sender's fast retransmit is unreachable in a boot because the send ring
  is one frame: host tests prove that half.
- **Signals reach a thread the kernel is not already returning to.** The scheduler's interrupts
  deliver on their way back to user mode, so a thread that only spins runs its handler, and a
  fault raises its own signal — `SIGSEGV`, `SIGBUS`, `SIGFPE`, `SIGILL` — with the faulting
  address in `si_addr`, which cannot be masked away because the instruction runs again the moment
  the thread does. Getting there cost x86_64 assembly entries for seven vectors, since a signal
  frame holds every register and the `x86-interrupt` ABI hides them. A handler that fixes nothing
  is stopped after 16 re-faults rather than looping as Linux does. Floating-point state in the
  frame is a stated gap: the kernel never clobbers those registers, but a handler is the
  program's own code and does.
- **FAT32, and a second volume in the guest.** The cluster count decides the format at mount:
  FAT32's root is a chain that grows like any directory's, its entries are 28 bits wide with the
  volume's own flag bits preserved, and its FSInfo free count is the driver's own — counted at
  mount, kept as the table changes, and checked against the consistency walk on every disk boot.
  The test disk carries a second, FAT32 volume written by a kbuild module whose reader and writer
  share no code with each other or with the kernel, so a guest reads it and meets `EXDEV` when it
  renames onto it. A rename across directories deletes the old entry before writing the new one,
  because the other order would leave two names on one chain; a crash there leaves lost clusters,
  the damage the ordering already allows. Long names are not built, and 8.3 names are refused
  rather than mangled.
- **The stress audit is judged in slices, and a soak runs unattended.** Nine of its bounds were
  durations standing in for facts about the kernel, and under an emulator a duration measures the
  host: workload parking and progress, the shootdown stall, sleeper lateness, the Linux pair's
  waits, the post-move progress bound, a lost wake against a slow arrival, the waiting pair's
  patience, and a starved thread against one that never ran. Each is now judged by what the
  scheduler actually gave the thread, and each still fails when broken — the falsifications fail
  in seconds rather than at the old bound's expiry. One of them, "ready on the right CPU, never
  scheduled", was the single failure this round that reproduced on unmodified master. kbuild's
  own harness was killing healthy guests as hung, because it allowed thirty seconds of wall time
  between heartbeats a guest prints once per second of its own; that allowance is two minutes
  now, so detection is later but never weaker. `kbuild soak` runs a stress image nobody watches,
  keeps the audit trail whatever the outcome, and compares the first window against the last, so
  a counter whose rate moves is a finding even when nothing fails. Both multiprocessor presets
  passed thirty-minute gates on this code with no audit failed, on a host carrying five other
  branches' work: aarch64 drifted +3% to +16% as its caches warmed, x86_64 −5% to −12% as the
  host got busier, with 44 and 244 slices of margin against a 512-slice parking bound and every
  other reportable count at zero. **The two-hour run is pending, not done**: thirty minutes shows
  the bounds hold under load, but only the long run shows the books stay balanced over time,
  since a counter gaining a few objects per thousand audits is invisible at that scale. Ten
  attempts died before any of this landed, six of them inside ten minutes, none a kernel fault.
  `spawn::PATIENCE` is deliberately untouched and documented with a reproduction: it is shared
  with the boot checks and needs a thread's id plumbed out of the cycles that end it.

**What merging six branches taught this round:**

- **Numbers assigned in advance did not collide; numbers left to chance did.** Exit codes and
  step ranges were handed out before the round started, and every branch stayed inside them.
  Native system call numbers were not, and two branches both took 35 — `object_wait_any` and
  `socket_send_to`. Next round the native numbers get the same treatment.
- **The same sentence, edited by three branches, merges silently.** The count of rows in the
  Linux system call tables was wrong twice before the round ended, each time because git took one
  side of an identical-looking edit without reporting a conflict. It is now recomputed from the
  tables themselves after every merge rather than trusted.
- **A stale tool looks exactly like a passing test.** One branch's falsifications came back "not
  caught" twice because a failed build left the old binary in place, and another had four boots
  "pass" on stale code for the same reason. Both now check the build's own output before
  believing a run. That is the third time this project has been fooled this way.
- **Two helpers with one name is a compiler error; two modes with one exit code is not.** The
  compiler caught `join` and `write_all`; nothing but reading caught four test modes sharing exit
  codes 46 and 47 last round, which is why they were assigned in advance this time.

**Still open.** Long file names; `statfs` reaching a program; FAT32 in the fuzz target, crash test
and stress workload; selective acknowledgement and the sender's fast retransmit in a guest;
floating-point state in a signal frame; queued real-time signals; `MSG_PEEK` and scatter/gather;
ICMP errors reaching a socket; the wait-registration window a check cannot yet hit; and, as
before, the 24-hour soak, real hardware, and Secure Boot with a TPM.

### The ninth round of landings

Eighteen presets now build and boot, with `x86_64-isolated-smp` new. Six branches ran in
parallel, and all six landed.

- **The SMP deadlock the eighth round recorded is fixed.** A thread faulting on one CPU while
  another installed a program, unmapped or forked could stop both: the frame lock's wait spun
  with interrupts masked and never answered the holder's TLB shootdown. The wait now answers
  shootdowns on every spin, as the process locks already did. A churning-pair stress cycle hung
  all eight runs with the old lock on both SMP presets at 4 and 8 CPUs, and passes with the fix;
  the Linux pair's workaround is gone. Every lock held across a shootdown is now written down
  with how it is waited for.
- **Signals** (Phase 6b), on x86_64 and aarch64. Processes have dispositions and a pending set,
  threads have masks and pending sets of their own, and delivery happens on the way out of every
  system call through Linux's own signal frames. `rt_sigreturn` validates the frame the program
  hands back, and a fuzz target holds it to that. Blocked pipe, futex and `wait4` calls return
  `EINTR` or restart under `SA_RESTART`; children send `SIGCHLD`, readerless writes raise
  `SIGPIPE`, and default actions end processes with the signal `wait4` reports. Stopping,
  alternate stacks, queued real-time signals, handlers from interrupts or traps, and
  floating-point state in the frame are not built.
- **Networking serves real programs** (Phase 7). The virtio-net interrupt handler runs the stack
  and wakes socket waiters, which otherwise look again only at TCP timers: the checks require
  wakes from the card and zero polls. The Linux personality answers the IPv4 TCP socket calls on
  both architectures, blocking and non-blocking, over the kernel's socket objects. A static
  program that knows nothing of KinTane is both a client of kbuild's service and a server kbuild
  connects into through a QEMU port forward. No `poll`, `select`, `epoll`, datagram sockets or
  congestion control.
- **Driver isolation past its exit criterion** (Phase 5). On `x86_64-isolated-smp` the disk is
  served from a ring-3 domain with its client, its interrupt and the domain each on a different
  CPU; the interrupt handler hands work to a forwarder thread without taking a lock, and every
  interrupt of the run is accounted as forwarded. VT-d changes the unit may have cached are
  flushed through the invalidation queue, and every IOMMU boot proves it: a translation taken
  away while the device runs cannot be reached through QEMU's IOTLB. Delivery to a CPU with an
  x2APIC ID above 255 stays blocked, because the kernel's ACPI discovery cannot describe the 257
  or more CPUs QEMU needs for such a topology. The branch also fixed a seventh-round overrun that
  zeroed the page after every VT-d table frame.
- **KinTane writes files** (Phase 7). The block cache holds writes back and releases them in the
  order FAT16 needs, so a crash can leave lost clusters or table copies one step apart, but never
  a cross-linked chain or a directory entry pointing at free clusters. Native programs write
  through the standing file server, where writing is a right the kernel grants per connection;
  Linux programs use their own calls on both architectures. After every run kbuild reads the disk
  image back with its own FAT reader, which shares no code with the kernel, and `kbuild crashtest`
  killed QEMU 30 times mid-write without producing an inconsistent volume. FAT32, long names and
  renames across directories are not built.
- **The boot stack is the configured size on every port, and measured.** aarch64, i686 and riscv32
  reserved a fixed 16 KiB and ignored `BOOT_STACK_KIB`; all five ports now take it from `sizes.ld`
  and assert it, and kbuild refuses a linked kernel whose stack symbols disagree. Every boot paints
  the stack and reports how deep it went, failing past 75%: that found `x86_64-iommu`'s test image
  at 93% of 16 KiB, so IOMMU, SMP and stress builds join driver-domain builds at 32 KiB, while
  `armv7m-tiny` keeps 14 KiB at 66%, because there the RAM is real. The boot `preempt` check is now
  judged in interrupts, preemptions and slices rather than wall-clock windows: beside six busy
  guests the old check failed 4 of 20 runs and the new one none of 20.

**A real bug, found because branches compared notes.** Three branches reported the same thing
under load — the `preempt` check saying "thread table INCONSISTENT", once followed by a fault at
instruction address 5. It was not a timing artefact. When the check's fixed window ended before a
worker had exited, its slot was never reaped, and the checks that follow spawned on stack slots 1
to 3 regardless: two live threads shared one stack, and the older one returned into whatever the
newer had written. Nothing had ever checked that a slot's previous thread was gone. `spawn` and
`spawn_prepared` now refuse such a slot, an unreaped thread fails the check outright, and the bug
reproduces on the eighth round's last commit with no load at all.

**What merging six branches taught this round:**

- **Three branches, three helpers, one name.** `join`, `write_all` and a mode's success code each
  arrived twice in the one test program, from branches that never saw each other. Git merged the
  files without complaint and the compiler caught two of them; the third, four modes sharing exit
  codes 46 and 47, no compiler could catch. The modes are numbered 42 to 50 now, each distinct.
- **A loaded host is not a verdict, and not an excuse either.** Every branch reported failures in
  the boot `preempt` check at load averages above 20, including on ports that carry none of the
  code under test. The gate held — nothing was pushed until a quiet host agreed — and the same
  reports, taken together, are what uncovered the shared-stack bug above.
- **Size budgets moved again**, this time on aarch64: signals, Linux sockets and writable FAT16
  together took `aarch64-virt` and `aarch64-virt-gicv3` to 101% of 1536 KiB and `aarch64-virt-smp`
  to 100% of 1792 KiB. Raised to 2048 and 2304 KiB, matching what the eighth round did to x86_64.

**Still open.** `poll`/`epoll` and datagram sockets; congestion control; signals delivered from
interrupts and traps; FAT32, long names and renames across directories; VT-d queued invalidation's
recovery from a rejected descriptor; an x2APIC ID above 255 on hardware that can have one; the
guest-time bounds that remain in the stress audit; and, as before, the 24-hour soak, real hardware,
and Secure Boot with a TPM.

### The eighth round of landings

Seventeen presets now build and boot, with `x86_64-isolated` new. Six branches ran in parallel
again, and all six landed.

- **Phase 5's exit criterion is met on x86_64.** `virtio-blk-core` runs in an unprivileged ring-3
  domain, `user/blkdomain`, over a grant of the disk's register window and the DMA buffer VT-d
  already confines it to. The kernel's block layer serves it over a channel, and the disk's MSI-X
  interrupt reaches the domain as a message the kernel forwards. The same driver source runs in
  the kernel on `x86_64-iommu` and in the domain on `x86_64-isolated`, and both pass the same
  `block` checks on every boot. Every `x86_64-isolated` boot stops a rogue DMA from inside the
  domain, kills a deliberately faulting domain alone, marks the disk failed, and has a new domain
  serve reads again. The domain-versus-kernel costs are in isolation.md, with the caveat that they
  are QEMU's: an interrupt forwarded as a message took about 45 µs on average under TCG. User
  programs on x86_64 are now built position-independent, because the domain links at the user
  half's 512 GiB, beyond the small code model's reach.
- **The flaky progress check is fixed, not loosened.** The scheduler now counts, per thread, the
  slices it ran and the times it was passed over. The stress run's process cycle fails a thread
  that ran 16 slices, or was passed over 64 times per slice it ran, without progress, instead of
  one that made none in a fixed 80 ms of wall time. Beside six busy guests, the old check failed
  9 runs of 10 and the new one none of 10; a process never scheduled, one that runs and never
  advances, and a real priority inversion all still fail. The network workload's pacing, added for
  that margin, is gone.
- **The Linux personality's second slice** (Phase 6b), on x86_64 and aarch64. A thread's thread
  pointer travels with it through the context switch. Pipes block on the Phase 6a wait queues;
  `clone` for threads, futexes, copy-on-write `fork`, `wait4` and `execve` from the VFS work; and
  aarch64 has its own in-tree table. One static program that knows nothing of KinTane pipes,
  forks, execs, waits and joins a futex-synchronised thread on every Linux boot of both
  architectures, and two of it share one CPU in the stress run. Signals and Linux sockets are not
  started.
- **TCP and sockets** (Phase 7). `kernel/net` speaks TCP with every RFC 793 state, go-back-N
  retransmission on a timer, a fixed receive window and pool-bounded memory, and says plainly that
  it has no congestion control. Sockets are handle objects with rights, and their calls block on
  the Phase 6a wait queues with timeouts. kbuild relays the guest's frames and drops each
  connection's first data segment, so every network boot on x86_64, aarch64 and i686 must
  retransmit, close in both orders, and return every buffer; a native program talks TCP to kbuild
  on x86_64 and aarch64.
- **Phase 6a's leftovers are closed.** Channels are counted store objects: the race the seventh
  round named, a channel freed and reused under another process's lookup, is reproduced by a boot
  check that failed on the old code. `process_wait` takes a timeout, a thread spinning in user mode
  is stopped from an interrupt when its process ends, and the VFS service is a standing kernel
  file server that serves any process given a connection.
- **x86 interrupt routing.** A bounded AML interpreter, fuzzed and host-tested against QEMU's q35
  and pc DSDTs, evaluates `_PRT` and link devices, so a PCI function without MSI-X gets a real INTx
  route: `x86_64-bios` takes its disk's interrupts on GSI 22, level, active high. On the IOMMU
  presets the disk's MSI-X goes through a VT-d interrupt remapping table, and an interrupt from an
  absent entry or another function is blocked and logged.

**What merging six branches found this round:**

- **A stack overflow no branch had.** The driver domain passed its stress run alone, and so did
  the object-layer checks, but together they overflowed the boot stack as the domain handed the
  disk back to the kernel: kmain's frame had grown by the new checks' inlined state, and the path
  measured about 15.7 KiB of a 16 KiB stack. The root cause was older. x86_64 reserved a fixed
  16 KiB in its boot assembly and ignored `BOOT_STACK_KIB`; the linker script now reserves the
  configured size, and a driver-domain build takes 32 KiB. aarch64, i686 and riscv32 still reserve
  a fixed 16 KiB.
- **The identical-edit trap, again.** The Phase 6a leftovers and TCP each raised the stress
  stack-slot defaults by one from the same base; git merged the identical lines silently, and
  the build-time count of every thread is what makes a missed increment a compile error. The
  defaults are now 16, 17 with driver isolation and 18 with a driver domain.
- **An API one branch removed and another used.** The domain served its requests with a blocking
  channel receive that the channel rework replaced with a non-blocking one; the merge restored a
  deadline receive over the new store objects.
- **A stale tool looks like a regression.** After the interrupt-remapping merge, the remap check
  failed at "no extended interrupt mode" and the BIOS preset still reported MSI-X. Nothing in the
  kernel was wrong: the kbuild binary predated the branch's QEMU flags. kbuild is now rebuilt after
  every merge that touches it, before anything is run.
- **Warnings that no gate counted.** The flat ports had carried dead-code warnings since the
  seventh round, and this round added more. They are gone, and each stand-in now *expects* its dead
  code on a flat kernel, so one that starts being called fails the build.

**Size budgets moved again.** The Linux second slice, interrupt routing with its AML interpreter,
and TCP grew every x86_64 image by about 240 KB in one round, which took `x86_64-iommu`,
`x86_64-isolated` and `x86_64-qemu-smp` past their budgets and `x86_64-qemu` to 99%. Every x86_64
preset was raised, none lowered: 1536 to 2048 KiB, and `x86_64-qemu-smp` from 1792 to 2304 KiB.
aarch64 grew by about 215 KB and stays within its budgets, at 93%.

**Still open.** Signals and Linux sockets; a frame-lock hazard where a `fork`, `execve` or program
install on a multiprocessor can deadlock against another CPU's page fault; socket waiters woken by
the card's interrupt rather than polling; congestion control and fragment reassembly; VT-d
queued invalidation and delivery to an x2APIC ID above 255 on a real CPU; remapping every function
and the I/O APIC; the boot `preempt` check, now the wall-clock check a loaded host breaks first;
and, as before, the 24-hour soak, real hardware, and Secure Boot with a TPM.

### The seventh round of landings

Sixteen presets now build and boot, with `x86_64-iommu` new. Six branches ran in parallel;
the round's work was as much in coordinating them as in any one of them.

- **The x86_64 device-memory bug is fixed.** Device memory on x86_64 and aarch64 lives in a
  kernel-half window at 1 TiB above its physical address, and `hal::paging::device_virt` is
  the only way to turn a device's physical address into a pointer. The machine that exposed
  the bug runs unchanged, its BAR still at 768 GiB, and every boot checks that the user
  half holds no kernel mapping.
- **The Linux personality has begun** (Phase 6b). A process's personality is decided at
  load from a KinTane ABI note — no note and a System V or Linux `EI_OSABI` means Linux —
  and the syscall entry calls a per-process table without branching on it. A static
  program that knows nothing of KinTane runs unmodified from the test disk on every x86_64
  boot: it writes, reads `/HELLO.TXT`, uses `brk` and `mmap`, and exits with the code the
  kernel checks. An unimplemented call returns `-ENOSYS` and is logged by name.
- **MSI-X on x86_64.** `device::msi` claims vectors like lines and reaches the MSI-X table
  only through a claimed window. The x86_64 disk completes 32 of 32 requests by interrupt
  on every x86_64 preset, and `x86_64-qemu-smp` routes its interrupt to CPU 1 and counts
  every completion there. INTx stays the fallback; what `_PRT` would need is written down.
- **Phase 6a is closed.** A reusable wait queue on the scheduler, blocking calls with
  timeouts, handles moved over channels with rights narrowed, events, timers, processes
  with several threads, and the VFS reachable as a channel service. Over 60 s at 8 CPUs the
  stress run proves cross-CPU wakes with none lost: 4,339 on x86_64 and 6,170 on aarch64.
- **Hardware DMA confinement** (Phase 5). The ACPI DMAR is parsed, a host-tested VT-d driver
  programs per-device translation domains, and in `x86_64-iommu` the disk runs behind a
  domain that maps exactly its DMA grant. Every boot stops a deliberate out-of-grant DMA,
  logs it with the faulting address and source id, resets the device, and has it serve
  again. virtio-blk is split into a `user`-layer core over `hwproxy`, so the same source
  can build into a domain.
- **Networking** (Phase 7). virtio-net and a minimal IPv4 stack — Ethernet, ARP, IPv4,
  ICMP echo and UDP — run on aarch64, x86_64 and i686, taking every frame by interrupt:
  the GIC, the 8259A and MSI-X. Every test boot resolves QEMU's gateway from a reply to its
  own ARP request, gets echo replies with matching sequence numbers, and completes UDP
  round trips with kbuild acting as the peer, with no host network needed; every buffer
  must come back to the pool. The packet parsers are fuzz targets, and a network workload
  joins the stress audit. virtio-blk and virtio-net now share one virtio crate at the
  `user` layer over `hwproxy`, beneath virtio-blk's protocol core, with the kernel's binding
  glue a layer above. TCP, fragment reassembly and a socket API are not built.

  The branch found a bug in code that had already landed: nothing in the kernel ever set a
  PCI function's bus-master bit, and QEMU drops MSIs from a function that is not a bus
  master. The x86_64 disk had completed by MSI-X only because SeaBIOS set the bit to boot
  from it.

**Phase 5's exit criterion is still open, on three counts.** The IOMMU confines the disk,
but the disk's driver still runs in the kernel: nothing yet runs `virtio-blk-core` in a
ring-3 domain on x86_64, no interrupt reaches a domain as a message, and there is no
domain-versus-kernel cost comparison. IOMMU map, unmap and invalidate came in below the boot
clock's resolution under QEMU, and that is recorded as not measurable here rather than
published as zero.

**What coordinating six branches taught this round:**

- **Merging early beats merging well.** Three branches depended on device addresses the
  device-window fix changed, two on the syscall dispatch the Linux personality reworked,
  and two restructured virtio-blk in incompatible directions. Each agent was told as soon as
  the change it depended on landed, and merged it in its own worktree before its final
  verification. Integration happened where the knowledge was.
- **Git records no conflict for an identical change that is still wrong.** Phase 6a and
  the network work each raised the stress stack-slot defaults to the same values, which
  together are one short. The build-time assertion that counts every thread is what turns
  that into a compile error instead of a run that cannot start.
- **A shared machine is a shared process table.** One branch's `pkill -f qemu-system`
  killed a QEMU in the main checkout's verification, which reported a chainload failure
  that was not there. The gate held — nothing was pushed until the test was rerun alone and
  passed — and every agent now kills only processes it started.
- **An agent's turn budget is finite.** The IOMMU branch reached its limit mid-verification
  and had to be resumed; the work survived because its commits were already in the tree.
- **The gate held twice on failures that were not regressions,** and each time the push
  waited for an isolated rerun rather than being forced through: the killed QEMU above, and
  a stress audit described next.

**A flaky check, named as open work.** Twice this round, the 20 s stress run on
single-CPU `x86_64-qemu` stopped at its first audit with "user process: a process made no
progress", once in the Phase 6a branch and once on the IOMMU merge. Both times the same run
passed alone. The process check waits a fixed window for progress, and on one CPU, with
other QEMU instances loading the host, that window can end before the process has been
scheduled at all. That check is measuring host load, not the kernel. It needs a progress
measure in the process's own run time rather than wall time, and it is not to be loosened
until that is understood.

**Size budgets moved.** The wait queues, threads and file service took `x86_64-qemu` to 95%
of its budget before VT-d landed, so every x86_64 and aarch64 preset that this round's
growth reached was raised, none lowered: 1280 to 1536 KiB, and `aarch64-virt-smp` to
1792 KiB. Budgets exist to catch a regression, and each raise is recorded with the landing
that needed it.

### The sixth round of landings

Fifteen presets now build and boot, with `x86_64-efistub` new. Six branches landed. As
before, most of the work of merging was in the seams between them, not in the conflicts.

- **A program creates a program** (Phase 6a). Images, processes, threads, memory regions
  and completion queues are kernel objects behind handles, and eight construction calls
  build a process piece by piece from handles its builder holds — still no fork. `init`,
  given only a console and an image, builds a child, hands it a channel endpoint, waits
  for it on a completion queue, and checks its exit code; the child's forged handles are
  refused, and every object and frame comes back.
- **Storage end to end.** `vfs` (a mount namespace, handles, an in-memory filesystem), a
  write-through block cache and a read-only FAT16 reader, all host-tested. The test disk
  carries a FAT16 volume, and on every port with a disk the kernel loads
  `/KINTANE/INIT.ELF` from it and runs it — userspace from storage, not from the image.
- **Disks on the PCs.** virtio over PCI on x86_64 and i686, completion by interrupt with
  several requests in flight (32 of 32 by interrupt on aarch64 and i686; x86_64 still
  polls until MSI-X or `_PRT` routing exists), and roughly double the throughput.
- **Driver isolation, a first prototype** (Phase 5). One driver body runs in the kernel
  and in an unprivileged domain over the same device window; the reports must agree, the
  domain's page tables must map only its grant, a rogue domain is killed, and every frame
  returns. A register access costs the same in both modes under emulation; starting and
  tearing down a domain costs about 6 ms, which argues for long-lived domains. No DMA
  confinement yet: that needs an IOMMU.
- **Fuzzing.** `kbuild fuzz` runs seeded, reproducible, structure-aware campaigns over nine
  targets — the device tree, ACPI, ELF, modules, boot tags, the boot menu, PCI
  configuration, virtio rings and the syscall table — with a committed corpus replayed on
  every change and a million inputs per target nightly. No kernel parser has panicked or
  hung.
- **Boot integration** (Phase 7). The kernel boots as its own UEFI application; images come
  in `elf`, `bin`, `uki` and `uimage`; `kbuild release` produces a manifest two cold builds
  reproduce; and a last-known-good counter falls back to safe mode after three failed
  boots and is cleared by a good one, proven end to end in one QEMU machine.

**A security bug the storage work exposed, guarded rather than fixed.** On x86_64 UEFI
boots, firmware placed the disk's BAR at 768 GiB, inside the user half of the address
space. The kernel maps device memory at its physical address, and every process copies
the kernel's top-level entries, so all processes built their pages into one shared table
and one read another's memory. The kernel now refuses to build a process while anything
is mapped in the user range. The real fix — mapping device memory outside the user range —
changes an assumption every driver makes, and is named here as open work.

*Fixed in the seventh round (3d0428f).* Device memory on x86_64 and aarch64 now lives in a
kernel-half window at 1 TiB above its physical address, and `hal::paging::device_virt` is
the only way to turn a device's physical address into a pointer. The machine that exposed
the bug runs unchanged, with its BAR still at 768 GiB, and passes the process, spawn and
isolation checks. Every boot now checks that the user half holds no kernel mapping, and the
refusal in `userproc.rs` stays as a backstop that can no longer trigger. i686 keeps identity
mapping: it has no user half, and no room in 32 bits for the window.

**What integration found that no branch could:**

- **The scheduler's table lived on the boot stack.** `Threads::new` returned the table by
  value, so it existed once on the 16 KiB boot stack before moving into place, and it grows
  with stack slots and CPUs. Isolation's extra slot at eight CPUs overflowed the boot stack
  into its guard page — which caught it cleanly. The table is now built in place.
- **A fuzz mock that predated eight syscalls.** The fuzzing branch's mock handler was
  written against the syscall table before the object layer grew it, so after both merged
  the fuzz unit no longer compiled. That break was exactly the compile error the target's
  documentation promised. It also reached master: the merge was pushed before its checks
  had finished, and every push since is gated on the full suite passing.
- **Two branches wrote the same helper.** The object layer and the filesystem both added
  an identical `parse` to `userproc.rs`.
- **Three disk workloads, one stack budget.** The filesystem and storage branches each
  added a stress workload that needs the disk; together with isolation's slot, a stress
  build now needs thirteen guarded stacks, and the build-time assertion counts every one.

**Findings worth keeping from the branches themselves:**

- **Three fuzz generators were testing nothing.** A first campaign of 45,000 inputs found no
  failures, and was worth almost nothing: the ELF, ACPI and menu generators produced inputs
  every parser rejected at its first check (0–5% accepted). Measuring acceptance exposed
  it; they now reach 40–80%.
- **A falsification only a host test could see.** A FAT reader that starts the root
  directory one entry late passes the boot check, because kbuild's volume — like almost
  every real one — has its label first, and skipping the label hides the offset.
- **A grant check that passed on the wrong window.** Every empty virtio slot answers
  identical identification registers, so a domain granted the neighbouring slot matched the
  kernel's read. Only walking the domain's page tables says which window it read.

**Build speed, measured.** A no-op rebuild takes 0.18 s and a one-line change to the kernel
crate about a second; a one-line change in `hal` recompiles 37 of 42 crates in 4.9 s,
against 22 s cold. The cache is content-addressed and per crate, dependents are keyed on
their dependencies' keys, crates compile one at a time, and nothing is incremental.

### The fifth round of landings

Fourteen presets now build and boot. Six branches landed, plus one integration fix.

- **Phase 3 is finished.** Both SMP ports boot eight CPUs and pass the stress run there:
  60 seconds, every audit, work on every CPU, with 300k+ TLB shootdowns and tens of
  thousands of migrations per run.
- **Device interrupts through the device model.** A bound driver's handler is registered
  before its line is unmasked, and aarch64's GIC, x86_64's I/O APIC and i686's 8259A all
  hand device lines to one table. The PL011 and a new 16550 driver receive on interrupt:
  every x86 and aarch64 boot has the harness type a string that must arrive that way, and
  the PCs unbind and rebind the driver in between with nothing left claimed.
- **Storage.** `kernel/block` gives drivers one fallible, allocation-free interface;
  `drivers/block/virtio-blk` is the first driver with DMA, host-tested against a fake
  device. Both aarch64 presets read and write a build-time pattern disk on every boot.
- **Processes on the scheduler.** A thread carries its address space, and the context
  switch loads it wherever the thread lands. Two workers run concurrently, each reading
  only its own memory at the same address, while a third is killed for touching kernel
  memory. The stress run migrates a process between CPUs every second.
- **Single-provider dispatch and the ARMv7-M RAM diet.** A build with one interrupt
  controller driver has no indirect call on the interrupt path, while the default aarch64
  image still picks GICv2 or GICv3 at run time from one binary. `armv7m-tiny` boots in
  **55.9 KiB of RAM**, down from 329 KiB; flash is 64.6 KiB, 0.6 KiB over the goal.
- **rv32i without atomics boots**, on a QEMU hart with A, M and C switched off — the case
  [portability.md](portability.md) has claimed since Phase 1. The rv32imac image dies on
  that hart at its first atomic instruction, which is how we know the hart refuses them.
  riscv32 also gained PMP stack guards.

**Three bugs that only integration could find**, each invisible to the branch that
carried the code:

- **A silent placement.** Every path that moves a thread to another CPU announces where it
  went and interrupts that CPU — except a yield from a CPU the thread's affinity no longer
  allows. An idle CPU sleeps until interrupted, so a process sat *ready on the CPU it had
  been pinned to, never scheduled*, while four CPUs idled. At four CPUs the run queues are
  never empty, so it could not appear; at eight it did. The check that found it was itself
  hiding it, reporting a stale symptom ("a process did not stop when told") instead of the
  cause.
- **A size that came from configuration, and two tables that did not.** The thread-stack
  array grew with the CPU count, but the per-port slot-name table and the address-space
  planner's limit were still the literal `16`. A stress build at eight CPUs lays out
  seventeen, so the kernel refused its own address space. The count is derived once now,
  and both tables read it.
- **`sync::IrqLock` registered with the lock-order checker before masking interrupts.** A
  timer interrupt in that window looked like recursion and halted the CPU. No image had
  used interrupt masking as its lock family until rv32i did; any uniprocessor build would
  have hit it.

**What the parallel work costs.** Two branches independently made thread-stack sizing
configuration-driven, with two generators and two symbol names; merging them was a design
decision, not a textual one. Three agents stalled waiting on their own background runs.
The integration tax is paid by whoever merges, and it is the honest price of six branches
at once.

### The fourth round of landings

Eleven presets now boot, including `x86_64-qemu-smp` and `armv7m-mps2`.

- **SMP, both ports, one scheduler.** Each CPU has its own run queue, with host-tested
  wake placement, balancing with a margin of two, and affinity masks. Cross-CPU wake-ups
  ride reschedule IPIs. Kernel mapping changes are shot down with an acknowledged IPI
  protocol that replaces aarch64's broadcast invalidate, so one protocol serves every
  port. x86_64 brings its CPUs up with INIT and startup IPIs through a real-mode
  trampoline, and runs on local APIC and I/O APIC drivers bound from the MADT; both ports
  plug into `hal::HasIpi`.
- **The first native userspace slice** (Phase 6a). `lib/abi` declares the system-call
  table once, `kernel/elf` loads static programs, and every x86_64 and aarch64 boot runs
  three processes from an embedded `init`: one that works, one that can do nothing with
  forged handles, and one that is killed for faulting while the kernel continues. On
  x86_64 the entry became per-CPU along with SMP — ring-3 segments in every GDT, `rsp0`
  installed by the context switch, `syscall` MSRs per CPU, and a `swapgs` discipline whose
  removal at any single point makes the kernel fault rather than the process.
- **Loadable modules** (Phase 4, x86_64). A module carries its kernel's build identity
  and an interface hash. Loading one built for a different configuration is refused with
  the differing symbol named; a module in use cannot be unloaded; unloading returns every
  frame. `kbuild sdk` builds an out-of-tree module byte-identical to the in-tree one.
- **The ARMv7-M port** (Phase 4). A Cortex-M3 executing in place from flash, with its
  memory map generated from a board description at build time, PendSV preemption and all
  eight MPU regions enforcing W^X and stack guards. A size-optimised release image is
  63 KiB of flash, inside the roadmap's 64 KiB. RAM is 324 KiB, mostly thread stacks, and
  is the open problem.
- **Epoch reclamation, the object store and channel cycles** (Phase 3). Readers pin, the
  epoch advances only when every pinned CPU has observed it, and memory is reclaimed two
  epochs later; a CPU that never unpins is reported instead of leaking. `kobject` gained
  an object store and a lock-backed identity source for machines without 64-bit atomics.
  Channels that hold each other in their queues are now collected.

**The ARMv7-M port re-tested the portability rule and split the verdict.** Kernel code
needed no change at all — not `kernel/main`, `sched`, `thread`, `hal` or the unwinder —
which is what riscv32's memory-model seam bought. Shared *tooling* still needed two
fixes: `lib/builtins` had none of the Arm run-time ABI (and LLVM compiled one helper into
a call to itself), and the symbolizer mishandled Thumb return addresses, where the low bit
of a return address is set.

**Phase 3's exit criterion is not met yet.** Both SMP ports boot 8 CPUs and pass every
bring-up check there, but the stress run does not:

- **Thread stacks run out.** The guarded stack slots in each `link.ld` are a fixed count
  that does not scale with CPUs, so at 8 CPUs the stress run cannot start its workloads.
- **Epoch retirement is refused at 8 CPUs.** With seven pinned readers the epoch advances
  too slowly for a fixed-size retirement bag, and the check reports the refusal rather
  than leaking, which is the designed behaviour and still a failure of the run.

Both are sizing, not design, and both are named here rather than in a commit message.

### The third round of landings

Six more branches landed. The tree now boots nine presets: the seven from before, plus
`aarch64-virt-smp` and `riscv32-virt`.

- **Phase 2's exit instrument.** After bring-up the scheduler keeps the CPU for good.
  `kbuild stress` runs seven workloads under seeded heap fault injection: heap churn,
  channel ping-pong with handle transfer, sleeps, demand paging and COW, and buddy
  pages. An auditor checks every book once a second, and a heartbeat watchdog turns a
  hang into a failure. Ten minutes pass all 600 audits on x86_64, i686 and aarch64. A
  nightly workflow runs 30 minutes each. The 24-hour run needs a self-hosted runner and
  has not been done.
- **SMP on aarch64.** `sync::PerCpu` is sized by `HasSmp::MAX_CPUS` at build time and
  reachable only through an interrupt-masking `Pinned` guard. PSCI `CPU_ON` starts every
  CPU in the device tree. Each CPU gets its own redistributor, which is found by
  affinity, or its banked GICv2 interface, plus its own timer. SGI IPIs work on both GIC
  versions, and lockdep keeps one held-lock stack per CPU. The scheduler itself is still
  single-CPU.
- **ACPI and PCIe on x86.** `boot/acpi` validates checksums before reading any field and
  is tested against real firmware tables captured from three machines. `device::pci`
  walks buses through bridges and sizes BARs without disturbing them. `platform/acpi`
  turns the MADT, MCFG and PCI functions into device nodes, the same model aarch64's
  device tree feeds.
- **Boot entries, command line, chainloading.**
  - Both loaders show a normal/safe/recovery menu, selectable by key, and hand the
    kernel a command line. `kinboot-bios` now hands over the native `BootInfo`.
  - BIOS chainloads another partition's boot record; UEFI chainloads another
    application.
  - The boot counter waits on a kernel-side writer.
- **riscv32 without an MMU** (Phase 4). rv32imac runs in M-mode with `mm::flat`. All 35
  in-kernel checks run, and the MMU-only ones honestly report Skipped.
- **kbuild** (Phase 4). The config language gains hex symbols, conditional ranges, menus
  and honest tristates. `menuconfig` is a real terminal editor. Random, allyes and allno
  configurations are generated valid by construction. Every preset has a size budget,
  enforced against committed baselines.

**The central claim met its first real counterexample.** Adding riscv32 did not stay
inside `arch/`, `targets/` and `config/`:

- `kernel/main` had to split its MMU bring-up behind a memory-model seam.
- `kernel/main` also used 64-bit atomics that the portability check never compiled,
  because the check only covers host-tested units.
- Shared code carried two latent 32-bit bugs: the device-tree reader rejected blobs above
  `isize::MAX`, and the unwinder had unsigned frame offsets.

These are one-time costs of the first no-MMU target, the same shape as Phase 1's
provider-unit cost. They are recorded rather than explained away. ARMv7-M is where the
rule gets tested again.

Other findings from this round:

- **Arm's timer compare value is signed.** `CNTP_TVAL_EL0` holds a signed 32-bit value.
  Arming it for `u32::MAX` ticks sign-extended into the past and caused an interrupt
  storm whenever the timer queue emptied. Only the long stress run found it, after
  109–406 seconds.
- **SGI pending state is per target, not per sender.** Three CPUs raising the same SGI
  at one masked CPU deliver it once.
- **Two branches invented the same configuration symbol under two names**
  (`QEMU_SMP`/`QEMU_CPUS`), and three merges needed fixes that neither side could see
  alone. Parallel work is fast. The integration tax is real and lands on whoever merges.
- **Random configurations earned their keep on the first run.** `MOCK_ARCH` was
  user-settable and broke 36 of 50 builds.

### The second round of landings

Six more branches landed in parallel. Each passed the same gates as the first round.
The tree now boots seven presets:

- `x86_64-qemu`, `i686-qemu`, `i686-large` and `aarch64-virt`;
- `i686-bios` and `x86_64-bios`, from a raw disk through SeaBIOS and `kinboot-bios`;
- `x86_64-efi`, through OVMF and `kinboot-efi`.

Every preset runs the 35 in-kernel checks and the stack-guard test.

- **Bootloaders.**
  - `kinboot-bios` is a 440-byte MBR plus a protected-mode stage 2. Stage 2 calls the
    BIOS through a thunk to enable A20 and read E820 or E801. It checks the kernel ELF
    against the memory map and a CRC-32 before handing over as a Multiboot 1 loader.
  - `kinboot-efi` loads the kernel from a FAT ESP that kbuild writes itself. It handles
    a stale map key at `ExitBootServices` by retrying, and hands over the boot
    protocol's own tags, which a new `bootinfo` provider reads.
  - Both disk images are byte-reproducible. kbuild gained per-unit targets and a
    `loader` layer.
- **`mm::paged`.** A region map with anonymous and physical backing. Faults zero pages
  on first touch and map 2 MiB blocks where a region allows. Copy-on-write shares
  pages through per-frame share counts, and every step fails cleanly when memory runs
  out. All three ports route kernel page faults through `hal::fault`.
- **Shared kernel state.** A kernel heap outlives boot behind the lock family, with
  interrupt-context rules and a fallible `KBox`. One locked clock and timer queue drive
  one-shot timer interrupts on every port, so the kernel is tickless. A 500 ms idle
  period costs one interrupt on aarch64 and nine on x86's PIT, against 50 for a tick.
  Lock-order violations fail debug boots.
- **Hardening.**
  - Kernel threads run on guard-paged stacks, and an overflow report names the thread.
  - i686 reports a real stack overflow from a `#DF` task gate.
  - Page 0 is unmapped on every port.
  - A reproducible build ID appears in every banner and backtrace, and
    `kbuild symbolize` refuses a log from another build.
- **Device model (Phase 3).**
  - `kernel/device` binds drivers to device-tree nodes, hands out typed resource
    claims that cannot overlap, and enforces probe phases as types.
  - The GIC and PL011 drivers moved to `drivers/`, and the GIC is chosen by
    `compatible` instead of `GICD_PIDR2`.
  - aarch64 maps exactly the device windows its drivers claimed.
  - One image passes on GICv2, GICv3, `max`, v4 with virtualization, and two other
    CPU models.

Findings from this round:

- **The hardware keeps no stale translations in QEMU.** Two TLB-related fixes cannot be
  observed under software emulation: reloading the PAE top-level table on i686, and
  the read-only invalidation on aarch64. They follow the architecture manuals, and
  nothing here tests them.
- **A too-coarse slice hid a missing preemption.** The PIT's 55 ms one-shot reach kept
  workers alternating even with slices removed. The check now also requires an
  interrupt count.
- **The `#DF` task gate needs `clts`.** Without it, the first SSE instruction in the
  report raised `#NM` and the report triple-faulted.
- **Discovery can hang on a hostile tree.** A device tree that moved the UART used to
  start the PL011 driver on unassigned memory. Discovery now checks the tree against
  the running console before any driver starts.
- **A host test was flaky for months unnoticed.** A `kernel/thread` test asserted on
  the mock's process-wide switch counter while the harness ran tests in parallel. It
  surfaced only when the suite ran under a second preset.

### Phase 2, so far

*(Written after the first round of landings. `mm::paged`, shared kernel state and the
smaller gaps listed below have since landed; see above.)*

Every Phase 2 item except `mm::paged` has landed on all three tier-1 architectures.
Each one gates the boot verdict or the host suite, and each check was falsified:
mutated, confirmed to fail, then restored. Today a boot runs 35 in-kernel checks on
each architecture, plus 13 host-tested units.

- **Address space.** The kernel runs on page tables it built itself. They are verified
  before they are loaded and checked against the CPU afterwards. W^X is enforced by
  the hardware and observed with real faults on x86_64 and with translation queries on
  aarch64. The boot-stack guard page is live, and `STACK_GUARD_TEST` in CI proves an
  overflow is caught.
- **Scheduling.** Fixed-priority round robin, preempted from the timer interrupt, with
  an idle thread that halts. The boot check demonstrates interleaving, priority, tick
  delivery and a halting idle thread.
- **Time.** `kernel/time` provides a monotonic clock that never divides on the hot
  path, and a fixed-capacity timer queue that supports tickless operation. The clock
  is driven by a PIT-calibrated TSC on x86 and by `CNTVCT_EL0` on aarch64.
- **Allocation.** `kalloc` has slab, buddy and arena allocators, context flags and
  poisoning. Deterministic fault injection covers every allocation site, and an
  in-kernel exhaust-and-free check runs on real frames.
- **Locking and objects.**
  - `sync` owns the one `LockFamily`, and debug builds check lock order: inversions,
    recursion and same-class nesting.
  - `kobject` handle transfer is all-or-nothing. `ipc` channels are built on it.
- **Crash reports.** Backtraces use frame pointers. The image is stripped, and a
  separate `.debug` bundle lets `kbuild symbolize` decode reports. `run` and `test`
  decode them automatically. CI crashes each architecture both ways and requires the
  decoded names.
- **Portability.** `kbuild portability` compiles every host-tested unit for riscv32i,
  riscv32imac and thumbv7m.

**The largest finding: a capability bound does not remove code.** `sync`, `kobject`
and `ipc` did not compile for either no-MMU target. On a machine without CAS, a
`compare_exchange` behind `A: HasCas` is still a compile error, and host tests could
not see it because the host has every atomic. See
[portability.md](portability.md#where-a-bound-is-not-enough).

Integration also turned up bugs that the unit-level tests could not have found:

- **Aliasing in `kernel/thread`.** Its `&mut self` switching API left a suspended
  thread holding a live exclusive reference to the table. The mock switch returns
  immediately, so host tests never saw it.
- **EOI ordering.** Sending the EOI after the tick hook instead of before it still
  passed the round-robin and priority checks. Only the tick-gap measurement caught it.
- **Page-table corruption.** The in-kernel suite's frame pool overwrote the live
  x86_64 top-level table, and the suite kept passing on cached translations. The live
  tables are now reserved from that pool and walked again after the suite.
- **Heap accounting.** In the slab-overflow path, the heap freed with the caller's
  layout instead of the size class, which under-counted the arena. Only the
  fault-injection sweep reached that path.
- **Lockdep false positives.** The first lock-order checker kept one global held-lock
  stack and reported ordinary contention as recursion.

An older finding still stands: **an IST alone does not make a stack overflow
diagnosable; a guard page does.** On x86_64 a real overflow is now reported from the
`#DF` IST stack. The `#DF` stack itself had first landed in `.rodata`, because an
immutable zeroed static is const data. That stayed harmless until real page
protections arrived.

Not done, and needed for the Phase 2 exit:

- **`mm::paged`:** virtual memory objects, demand paging, copy-on-write and huge
  pages.
- **Shared kernel state.** A global, locked heap and clock that outlive boot. Timer
  interrupts are still periodic rather than programmed from `next_deadline`, and sleep
  still counts ticks.
- **Stress.** The 24-hour stress run, and fault injection exercised across the whole
  kernel, not only `kalloc`.
- **Smaller gaps:**
  - Thread stacks have no guard pages.
  - On i686 a real overflow still triple-faults, because it needs a `#DF` task gate.
  - aarch64 device windows are hardcoded for QEMU `virt`.
  - Lockdep's first report is recorded but not printed.
  - No build ID ties a console log to its symbol bundle.
  - Page 0 is still mapped on x86.

### Phase 1, as it actually stands

Done: the `Arch` and capability trait family; x86_64, i686 and aarch64 ports, all
three booting from one unmodified `kernel/main`; distinct `PhysAddr`/`KernAddr`/
`UserAddr`; a physical frame allocator written once and generic over the
architecture; exception and interrupt entry on x86_64 and aarch64; `MockFull` and
`MockTiny` with a host test runner; the `cfg_in_body` and layering lints; and CI
building and booting every preset.

**The central claim is demonstrated rather than asserted.** One aarch64 image —
verified by md5, not by inspection — takes timer interrupts under GICv2 *and* GICv3,
selected at runtime, plus `gic-version=max`, `gic-version=4` with virtualization, and
several CPU models. That is the static-architecture/dynamic-devices split in
[portability.md](portability.md#static-architecture-dynamic-devices) working.

The exit criterion said adding an architecture must touch nothing outside `arch/`,
`targets/` and `config/`. That holds **now**, but was not free: the first additional
architecture also forced `kernel/main` to stop naming a specific one, and forced
kbuild to allow several units to *provide* a name so the configuration could pick.
Both were one-time costs, and the third architecture did land within the rule.

Landed since, as Phase 2 opened: an in-kernel test suite, `kbuild test --target`,
which boots a test image and takes the guest's exit status as the verdict — 17 checks
on x86_64 and i686, 10 on aarch64, which correctly *skips* rather than claims the
memory checks it cannot run.

Not done, and deliberately named rather than quietly folded into "done":

- ~~No page table manipulation or kernel address space.~~ Done in Phase 2: see above.
- ~~The GIC drivers are in `arch/aarch64/`~~ (moved to `drivers/irqchip/` in Phase 3) — not `drivers/irqchip/` where
  [architecture.md](architecture.md) says they belong, because `arch` may not depend
  on the `device` layer and nothing else would reference them yet. They move when the
  device framework can register and find them.
- ~~GIC detection reads `GICD_PIDR2`~~ (now the device tree's `compatible`), which reports the IP revision rather than the
  programming model — a GICv3 with `GICD_CTLR.ARE == 0` is legitimately a GICv2 and
  still reports 3. The real answer is the device tree's compatible string.

**Phase 0 closed** with `kbuild run --preset x86_64-qemu` building an x86_64 kernel
from source, booting it under QEMU, and exiting on the guest's own signal (exit 33,
which is `(0x10 << 1) | 1` from `isa-debug-exit`). Cold build 4.9s, warm 0.22s on the
content-addressed cache.

Three things the documentation had wrong until the code existed, now corrected in
place:

- QEMU's multiboot loader **refuses an ELF64 container** outright, so the image is
  repackaged to ELF32 after linking. The ELF64 survives as the debug artifact, which
  is the image/symbols split the deliverables already described — arriving a phase
  earlier than planned.
- `-no-shutdown` suppresses `isa-debug-exit` and turns every passing test into a
  timeout. It reads as a natural companion to `-no-reboot` and is not one.
- `naked_functions` was cited as a reason nightly is required and has been stable
  since 1.88. The real reasons are in
  [build-system.md](build-system.md#engine-a-pinned-nightly).

Carried into Phase 1 as known-incomplete: `compiler_builtins` is byte-at-a-time and
needs real intrinsics as the kernel grows; `HasSmp::cpu_id` returns a constant 0,
correct only while every preset sets `SMP=n`; and the image is identity-mapped at
1 MiB, so the move to the high half also flips the x86_64 code model back to
`kernel`.

The sequencing has one governing idea: **prove the portability claim before building
anything on top of it.** Phase 1 adds a second and third architecture while the
kernel is still small enough to restructure. Phase 4 scales down to a target with no
MMU and 64 KiB of RAM. If the design is wrong, those are the cheapest places to find
out.

---

## Phase 0 — Build system and first boot

*Nothing about the kernel can be evaluated until something builds and runs.*

- `kbuild` MVP: `.kcfg` parsing, constraint resolution, `.config`, generated
  `config.rs` and `--cfg` flags.
- Crate graph from `kmod.toml`, topological build, direct `rustc` invocation, content-
  addressed cache.
- Building `core` from source against in-tree target specs.
- `kbuild toolchain --verify` / `--fetch`: enforce the pin in
  [`toolchain.toml`](../toolchain.toml) before any build, and refuse to proceed on a
  `commit-hash`, `release`, or LLVM-version mismatch.
- Reproducibility from the start — path remapping, `SOURCE_DATE_EPOCH`, deterministic
  link order — because retrofitting byte-identical builds is far harder than never
  losing them.
- `x86_64` target spec, early serial console, panic handler, `kbuild run` under QEMU.
- **Boot protocol v1** — `BootInfo`, its tag encoding, and the forward/backward
  compatibility rules. Defined early because every loader and the kernel entry path
  both depend on it ([bootloader.md](bootloader.md#the-boot-protocol)).
- **Minimal `kinboot-efi`**: load the kernel from the ESP, collect the memory map,
  `ExitBootServices`, hand over `BootInfo`. Built on the built-in
  `x86_64-unknown-uefi` target, so it emits PE/COFF with no custom target spec.
- Skeleton `hal` traits — `Arch` only, no capability traits yet.
- **The QEMU test harness** ([testing.md](testing.md#the-qemu-protocol)): canonical
  machine per target, real result channels (`isa-debug-exit` / semihosting /
  `sifive_test`) rather than console scraping, two serial channels separating the human
  log from the machine one, timeouts that dump state instead of dying silently, and
  `-no-reboot` so a triple fault is a visible failure rather than a boot loop.

**Exit:** `kbuild run --preset x86_64-qemu` prints a banner and a panic backtrace over
serial, and a second invocation is a cache hit.

---

## Phase 1 — The portability spine

*The highest-risk phase. Everything after it assumes the answer.*

- The full `Arch` + capability trait family: `HasMmu`, `HasMpu`, `HasSmp`, `HasCas`,
  `HasCoherentDma`, `HasFpu`.
- `aarch64` port: QEMU `virt`, device tree, exception vectors, MMU bring-up.
- `i686` port: BIOS boot, PAE, 36-bit physical addresses behind 32-bit pointers.
- **`kinboot-bios`** — stage 1 in 440 bytes of real-mode assembly via `global_asm!`
  with `.code16`, stage 2 collecting E820/EDD/VBE in real mode before switching to
  protected mode and handing off to Rust. Early work, not Phase 7 polish: tier-1 i686
  has no other way to boot.
- Physical frame allocator, early page tables, kernel address space — written once,
  generic over `A: Arch + HasMmu`.
- `PhysAddr` / `KernAddr` / `UserAddr` as distinct types, tree-wide.
- Interrupt and exception entry, `IrqChip` trait with two implementations on aarch64
  (GICv2, GICv3) selected at runtime.
- `MockArch` family and the host test harness.
- The `cfg_in_body` and `layer_violation` lints.
- CI building and booting all three targets on every merge.

**Exit:** all three targets boot to a shell-less idle loop and pass the in-kernel test
suite. Adding `i686` after `aarch64` required changes to no file outside `arch/`,
`targets/`, and `config/` — verified by reading the diff, and recorded.

**If this fails**, the trait approach needs revision, and it is far better to learn it
here than in Phase 5.

---

## Phase 2 — Core kernel

- `kalloc`: fallible allocation, slab and buddy, allocation context flags, debug
  poisoning.
- `sync`: capability-selected lock types, lock-order checking in debug builds.
- `mm::paged`: virtual memory objects, demand paging, copy-on-write, huge pages.
- `time`: monotonic clock, timer subsystem, one-shot and periodic, tickless-capable.
- `sched`: single-CPU preemptive scheduler, task objects, context switch per arch,
  idle task.
- `kobject`: refcounting, type tags, rights masks.
- Kernel-internal channels (the IPC primitive, before any userspace exists).
- Symbolized panic backtraces against the separate symbol bundle.

**Exit:** kernel tasks run concurrently, preempt on a timer, allocate and free under
memory pressure, and survive a 24-hour stress run on all three targets. Allocation
failure is exercised by injection and handled everywhere.

---

## Phase 3 — SMP and the device model

- Per-CPU data as a `HasSmp`-gated abstraction resolving to a plain static on
  uniprocessor builds.
- Secondary CPU bringup: x86_64 (APIC/INIT-SIPI), aarch64 (PSCI).
- IPIs, TLB shootdown, memory barriers placed against a written memory model.
- SMP scheduler: per-CPU runqueues, load balancing, idle balancing.
- Epoch-based reclamation for read-mostly shared data.
- Device framework: FDT, ACPI, and PCIe enumeration into one node representation;
  driver binding; typed resource handles; probe phases as type-enforced tokens.
- Power management and driver removal in the interface from the start.
- Real console, real timer, real interrupt controller drivers per target.

**Exit:** 8-CPU QEMU boot on x86_64 and aarch64 with all CPUs scheduling; a stress run
with concurrent allocation, mapping, and teardown; devices enumerated from device tree
on aarch64 and from ACPI/PCIe on x86_64 using the same binding code.

---

## Phase 4 — Configurability, proven by scaling down

*The counterpart to Phase 1: prove the design holds at the other extreme.*

- Full config language: tristate, `choice`, `select`, ranges, `menuconfig` TUI.
- `armv7m` port: Thumb-2, MPU, NVIC, no MMU, XIP from flash.
- `riscv32` port (`rv32imac`, and an `rv32i` variant without atomics to exercise
  `HasCas` being absent).
- `mm::flat`: region allocator, optional MPU programming, no translation.
- **Build-time `BootInfo`** for targets with no bootloader: `kbuild` emits it as a
  `const` from the board description, so the kernel entry path is identical to the
  UEFI one at no runtime cost.
- Single-provider mode: config-pinned subsystems resolving to static type aliases,
  removing virtual dispatch from the interrupt path.
- Loadable modules: ELF loader, per-arch relocations, build identity and interface
  hashing, refcounted unload, `kbuild sdk`.
- Size budgets in CI with per-crate deltas.
- Randomized-configuration builds, nightly, reproducible by seed.

**Exit:** an `armv7m` image under 64 KiB boots on QEMU and on real hardware, running a
fixed-priority scheduler with in-kernel tasks. A `riscv32` image without atomics boots.
Modules load and unload on x86_64, and a module built for a different `.config` is
rejected with a message naming the difference. A thousand random configurations build.

---

## Phase 5 — Driver isolation

- Address-space-separated driver domains on `HasMmu` targets.
- IOMMU support: VT-d, AMD-Vi, SMMUv3 — DMA from an isolated driver is confined.
- The proxy layer: `Mmio<T>`, `DmaBuffer`, `IrqLine` implemented over domain crossing,
  with the same driver source running either way.
- Domain fault handling: contain, mark the device failed, tear down, restart.
- Per-domain resource accounting and quotas.
- Benchmarks quantifying the isolation cost, per driver class, published.

**Exit:** the same unmodified driver runs `InKernel` and `Isolated` on x86_64;
deliberately faulting it kills only its domain and it restarts; an isolated driver
cannot DMA outside its granted buffers, demonstrated by attempting it; the cost is
measured and documented rather than asserted.

---

## Phase 6 — Userspace, the native ABI, and the Linux personality

### 6a — Native first

The native object layer comes first because the Linux personality is built on top of
it. Building compatibility first would shape the kernel around Linux semantics and
leave the native ABI a veneer over them.

- Syscall entry per architecture; dispatch generated from `#[syscall]`.
- Handle tables, rights masks, handle transfer over channels.
- `Process`, `Thread`, `MemoryRegion`, `Mapping`, `Event`, `Timer`, `Job`.
- Explicit process construction; no `fork` in the native ABI.
- Completion-queue-based asynchronous primitives, with blocking wrappers.
- ELF loading, PIE, per-process address spaces.
- Native runtime library; first userspace programs.
- A VFS as a service over channels, and a simple in-memory filesystem.
- Syscall and parser fuzzing from the day each exists.

**6a exit:** a native userspace program starts, communicates over a channel, maps
memory, is scheduled against other processes, and exits cleanly on x86_64 and aarch64.
A process with no handles provably cannot affect anything. The native ABI is frozen
for the major version.

### 6b — The Linux personality

Same phase, immediately after, because it is what turns the kernel from demonstrable
into usable — and because every gap it exposes in the native interfaces is a gap worth
fixing while the ABI freeze is still fresh.

- Personality tag on `Process`, dispatch-table pointer in the thread control block,
  ELF-note-based tagging at load.
- Per-architecture Linux syscall tables, generated from an in-tree table.
- The fd table as a compat view over handles; ambient root namespace and `cwd`.
- `fork` / `clone` with copy-on-write; depends on `MM_PAGED`.
- POSIX signals: masks, handlers, `sigaltstack`, per-arch signal frames, restart
  semantics. Budget accordingly — this is the largest single item in the phase.
- The `Result` → `errno` mapping table, reviewed rather than accreted.
- Minimal `/proc`, `/sys`, `/dev`; `mmap` and `brk` semantics; TLS setup; vDSO.
- `-ENOSYS` with a named log line for gaps, fatal under a CI config flag.
- `ABI_LINUX` as a loadable module, exercising Phase 4's module work against something
  substantial.
- The compatibility corpus in CI, starting at static musl.

**6b exit:** an unmodified static busybox runs on x86_64 and aarch64 — shell, coreutils
applets, pipes, job control — from a corpus CI runs on every merge. Every gap found is
either implemented or recorded with its syscall name. At least one gap has been fixed
in the *native* ABI rather than papered over in the compat layer, demonstrating the
forcing function works.

---

## Phase 7 — Real hardware and real work

- Block layer, AHCI and NVMe drivers, a real on-disk filesystem.
- Network stack and at least one NIC driver; isolated-domain networking as the
  demonstration of Phase 5's value.
- USB host.
- Framebuffer and input.
- **Bring-up on real machines for every tier-1 target**; the nightly hardware rack.
  This is where the [hardware debt](testing.md#the-hardware-debt) comes due — weak
  memory ordering, cache/DMA coherency, device errata, and real firmware all arrive at
  once. Scheduled as substantial work, not a formality: a port that boots under QEMU is
  perhaps two thirds of the way to booting the machine QEMU was modelling.
- Boot integration: the EFI stub (kernel as its own PE/COFF application), Secure Boot
  and signature verification, measured boot with PCR extension and an event log,
  module signing, `uImage`/FIT and XIP packaging.
- Last-known-good escalation: boot counter in an EFI variable or reserved sector,
  automatic fallback `normal` → `safe` → previous kernel.
- Chainloading: VBR chainload on BIOS; `LoadImage`/`StartImage` on UEFI and nothing
  more, since the firmware's boot manager already does it better.
- Foreign-loader shims: U-Boot FIT, OpenSBI, GRUB/systemd-boot.
- Crash-dump format and offline decoder.
- First tagged release, with images, modules, symbol bundles, and SDK.

- Compatibility corpus extended to dynamic musl and then glibc userland, run against
  real storage and networking rather than an in-memory filesystem.

**Exit:** KinTane boots on physical hardware for all tier-1 targets, mounts a
filesystem from a real disk, serves network traffic, and survives a week-long soak —
with the soak workload driven by unmodified Linux programs, which is the point of
having the personality.

---

## After Phase 7

Candidates, in no fixed order: `riscv64` and `armv7a` promoted toward tier 1; a
big-endian target (`powerpc`) to flush out endianness assumptions; user-domain
drivers as a third isolation option; real-time scheduling guarantees and latency
measurement; hypervisor support; and the long-tail architectures in
[targets.md](targets.md#tier-3-and-the-long-tail) — which by then should be a matter
of writing an `arch/` crate and nothing else.

---

## Risks

| Risk | Where it bites | Mitigation |
|---|---|---|
| Trait bounds become unmanageable as subsystems compose | Phase 2–3 | Capability alias traits at subsystem boundaries; if it still hurts, revisit in Phase 1 while it is cheap |
| No-MMU support turns out to need parallel implementations rather than shared ones | Phase 4 | `mm::flat` is planned as a peer implementation, not an emulation; features that genuinely cannot exist are marked unavailable, not faked |
| Driver isolation is too slow to ever enable | Phase 5 | Measure early with a prototype in Phase 3; `InKernel` is always available, so the fallback is the status quo |
| `kbuild` becomes a second project competing for attention | continuous | Keep it minimal; it resolves config and calls `rustc`. Any feature that is not needed for a shipping kernel is out |
| Nightly toolchain churn breaks builds | continuous | Pinned toolchain with hashes; upgrades are deliberate, separate commits with a full-matrix build |
| QEMU-only validation hides weak-memory, cache/DMA and firmware bugs until Phase 7, when they all land at once | Phase 0–7 | Named and tracked rather than assumed away ([D12](decisions.md#d12--qemu-first-testing-with-the-gaps-named)): affected code is marked unvalidated until hardware runs it, the memory model is written before the SMP work, lock-free code is model-checked on the host, and no test may depend on emulator-specific behaviour |
| The Linux personality is a large, permanently incomplete surface; signals alone are substantial | Phase 6b | Compatibility is defined by a published corpus CI runs, never a percentage claim. Gaps are loud: `-ENOSYS` plus a named log line, fatal under CI. Scope grows corpus tier by corpus tier, starting at static musl |
| The compat path becomes the de-facto ABI and the native one gets no users | Phase 6b onward | The personality is a client of native interfaces, so it cannot outgrow them; native-first sequencing in 6a; the native runtime library and our own userland stay the primary target. Accepted as a live risk, not a solved one |
| Linux semantics leak into kernel design through the compat layer | Phase 6b onward | Each place the layer reaches past the native interfaces for performance is documented at the site with the measurement that justified it, so the exceptions stay countable |
| Scope is a full operating system built by very few people | all of it | Phases are ordered so that each produces something usable on its own; a project that stops after Phase 4 is still a working embedded kernel |

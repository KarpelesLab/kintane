//! Secondary CPUs: starting them through PSCI, the per-CPU block each one's `TPIDR_EL1`
//! points at, inter-processor interrupts as SGIs, and each secondary's idle loop.
//!
//! This is mechanism only. Which CPUs exist, and how firmware is to be called, comes from
//! the device tree, which `arch` may not read. `kernel/platform/fdt` reads it and calls
//! [`start`] for each CPU, then checks what came up.
//!
//! # A CPU's number
//!
//! Hardware names an aarch64 CPU by its MPIDR affinity, which is sparse: a board numbers
//! clusters in Aff1 and cores in Aff0, and nothing obliges either to start at zero. The
//! kernel names it by a dense logical index, the boot CPU's being 0, because per-CPU
//! storage is an array. The index is decided here when a CPU is started, and kept in that
//! CPU's [`CpuBlock`]. `TPIDR_EL1` holds a pointer to the block, so [`cpu_index`] is two
//! instructions and a load, on any CPU, at any time, including inside an exception.
//! `TPIDR_EL1` is banked per CPU and reserved for the kernel: nothing below EL1 can write
//! it, and the exception entry's scratch registers are `TPIDR_EL0` and `TPIDRRO_EL0`.
//!
//! # Starting one
//!
//! `CPU_ON` (Arm DEN 0022, §5.6) takes the target's MPIDR, an entry point and a context
//! value, and starts the CPU at the entry point with the MMU off, at the highest exception
//! level firmware gives the kernel, and with the context in `x0`. [`start`] passes the
//! block's address as the context. `__secondary_entry` then does for the new CPU what
//! `_start` and `aarch64_mmu_init` did for the boot CPU, except build tables: it loads the
//! boot CPU's live `MAIR_EL1`, `TCR_EL1`, `TTBR0_EL1` and `SCTLR_EL1`, captured by
//! [`start`], so every CPU runs on the one kernel address space with identical
//! translation settings. The kernel is identity-mapped, so the instruction after the
//! MMU enable is the same whether or not translation is on.
//!
//! The stack is a slot in the thread-stack array, claimed under the CPU's name, so the
//! guard page under it is unmapped and an overflow reports which CPU overflowed.
//!
//! # What a secondary does
//!
//! It installs the vectors, prepares its part of the interrupt controller, starts its
//! own generic timer at [`SECONDARY_HZ`], and waits for interrupts. Until [`release`], it
//! takes timer ticks and IPIs and runs nothing else, and its ticks are counted in its
//! block and never reach the scheduler's hook. After it, the CPU is the scheduler's (see
//! below, and `docs/architecture.md`, SMP).
//!
//! # IPIs
//!
//! SGI [`IPI_CALL`] runs a function on the target and records the result, SGI
//! [`IPI_RESCHEDULE`] is counted and then reaches the scheduler's hook, and SGI
//! [`IPI_TLB`] runs the kernel's shootdown handler. One function call is outstanding per
//! target at a time. [`call`] is a boot-path facility that waits for its answer, and the
//! boot CPU is its only caller.
//!
//! # Handing the secondaries to the scheduler
//!
//! Until [`release`], a secondary's timer is its own and its ticks go no further than its
//! block. [`release`] records the function each secondary enters and wakes them. A
//! secondary leaves its bring-up loop on its next wake-up, stops its periodic timer, and
//! calls that function, which is the scheduler's and never returns. From then on its
//! timer interrupts and reschedule IPIs reach the scheduler's hook like the boot CPU's.

use core::sync::atomic::{AtomicPtr, AtomicU8, AtomicU32, AtomicU64, AtomicUsize, Ordering};

use hal::{Arch, IrqNumber};

use crate::{Aarch64, exception, irq, tick, timer};

/// The most CPUs this port starts. Eight covers every `virt` configuration CI runs and a
/// GICv2's limit, and costs one block each.
pub const MAX_CPUS: usize = 8;

/// SGI that runs a function on the target.
pub const IPI_CALL: u32 = 0;
/// SGI that asks the target to reschedule. It is counted, and once the scheduler owns the
/// CPUs, the interrupt path calls the scheduler's hook after it as after a timer tick.
pub const IPI_RESCHEDULE: u32 = 1;
/// SGI that makes the target run the kernel's shootdown handler.
pub const IPI_TLB: u32 = 2;
/// Interrupt IDs below this are SGIs.
pub(crate) const SGI_LIMIT: u32 = 16;

/// Timer interrupts per second on a secondary: enough to see ticks within a check's
/// patience, few enough to cost nothing.
pub const SECONDARY_HZ: u64 = 100;

const OFFLINE: u8 = 0;
const STARTING: u8 = 1;
const ONLINE: u8 = 2;
/// Came up but could not prepare its part of the interrupt controller.
const FAILED: u8 = 3;

/// Everything one CPU owns, reached through its `TPIDR_EL1`.
///
/// `repr(C)` because `__secondary_entry` reads `stack_top` by offset before any Rust runs,
/// and `cpu_index` reads `index`. The two offsets are asserted below.
#[repr(C)]
pub struct CpuBlock {
    /// This CPU's logical number. Constant.
    index: usize,
    /// Where the secondary entry puts its stack pointer.
    stack_top: AtomicUsize,
    /// The hardware ID `start` was given.
    mpidr: AtomicU64,
    /// What the interrupt controller's `init_cpu` returned on this CPU.
    ipi_target: AtomicU64,
    has_ipi_target: AtomicU8,
    state: AtomicU8,
    /// What `Arch::cpu_index` answered when asked on this CPU, as it came up.
    seen_index: AtomicUsize,
    /// What `HasSmp::cpu_id` answered there.
    seen_id: AtomicU32,
    /// Timer interrupts this CPU has taken, secondaries only.
    ticks: AtomicU64,
    /// Counter ticks between them; zero stops the timer.
    period: AtomicU32,
    /// The pending function call, as an address, or zero.
    call_fn: AtomicUsize,
    call_arg: AtomicU64,
    call_result: AtomicU64,
    calls_done: AtomicU64,
    reschedules: AtomicU64,
}

const _: () = assert!(core::mem::offset_of!(CpuBlock, index) == 0);
const _: () = assert!(core::mem::offset_of!(CpuBlock, stack_top) == 8);

impl CpuBlock {
    const fn new(index: usize) -> CpuBlock {
        CpuBlock {
            index,
            stack_top: AtomicUsize::new(0),
            mpidr: AtomicU64::new(0),
            ipi_target: AtomicU64::new(0),
            has_ipi_target: AtomicU8::new(0),
            state: AtomicU8::new(OFFLINE),
            seen_index: AtomicUsize::new(usize::MAX),
            seen_id: AtomicU32::new(u32::MAX),
            ticks: AtomicU64::new(0),
            period: AtomicU32::new(0),
            call_fn: AtomicUsize::new(0),
            call_arg: AtomicU64::new(0),
            call_result: AtomicU64::new(0),
            calls_done: AtomicU64::new(0),
            reschedules: AtomicU64::new(0),
        }
    }
}

static BLOCKS: [CpuBlock; MAX_CPUS] = {
    let mut blocks = [const { CpuBlock::new(0) }; MAX_CPUS];
    let mut i = 0;
    while i < MAX_CPUS {
        blocks[i] = CpuBlock::new(i);
        i += 1;
    }
    blocks
};

/// The boot CPU's translation registers, captured by [`start`] and loaded by every
/// secondary as it enables its MMU: `MAIR_EL1`, `TCR_EL1`, `TTBR0_EL1`, `SCTLR_EL1`, in
/// that order. Named for the assembly, which reads it by symbol.
#[unsafe(no_mangle)]
static __smp_boot_regs: [AtomicU64; 4] = [const { AtomicU64::new(0) }; 4];

core::arch::global_asm!(
    r#"
.section .text.smp, "ax"
.balign 4
.globl __secondary_entry
// x0 is the CpuBlock `start` passed to CPU_ON as the context. The MMU is off, every
// exception is masked, and the exception level is whatever firmware started us at.
__secondary_entry:
    msr     daifset, #0xf
    mov     x19, x0

    mrs     x1, CurrentEL
    lsr     x1, x1, #2
    cmp     x1, #2
    b.ne    1f

    // At EL2: the same descent `_start` makes, for the same reasons. See boot.rs.
    mov     x1, #(1 << 31)
    msr     hcr_el2, x1
    mrs     x1, cnthctl_el2
    orr     x1, x1, #3
    msr     cnthctl_el2, x1
    msr     cntvoff_el2, xzr
    mov     x1, #0x0800
    movk    x1, #0x30d0, lsl #16
    msr     sctlr_el1, x1
    mov     x1, #0x3c5
    msr     spsr_el2, x1
    adr     x1, 1f
    msr     elr_el2, x1
    eret

1:
    // FP and SIMD untrapped, as on the boot CPU.
    mov     x1, #(3 << 20)
    msr     cpacr_el1, x1
    isb

    // This CPU's stack and its per-CPU pointer. The stack is a thread-stack slot, which
    // the identity map already covers at this address, translated or not.
    ldr     x1, [x19, #8]
    mov     sp, x1
    msr     tpidr_el1, x19

    // Translation exactly as the boot CPU has it, in the order `aarch64_mmu_init` uses:
    // tables and attributes first, synchronise, drop anything cached, then enable.
    adrp    x1, __smp_boot_regs
    add     x1, x1, :lo12:__smp_boot_regs
    ldr     x2, [x1, #0]
    msr     mair_el1, x2
    ldr     x2, [x1, #8]
    msr     tcr_el1, x2
    ldr     x2, [x1, #16]
    msr     ttbr0_el1, x2
    isb
    tlbi    vmalle1
    ic      iallu
    dsb     nsh
    isb
    ldr     x2, [x1, #24]
    msr     sctlr_el1, x2
    isb

    mov     x29, xzr
    mov     x30, xzr
    mov     x0, x19
    bl      aarch64_secondary_main

2:
    msr     daifset, #0xf
    wfi
    b       2b
"#
);

/// Point this CPU's `TPIDR_EL1` at block 0. Called on the boot CPU before anything asks
/// [`cpu_index`]; until then it reads as zero, which [`cpu_index`] also answers as 0.
///
/// # Safety
/// On the boot CPU, once, before any secondary is started.
pub(crate) unsafe fn adopt_boot_cpu() {
    let block = &raw const BLOCKS[0];
    // SAFETY: TPIDR_EL1 is an EL1 register with no effect on execution; the pointer names a
    // static that lives forever.
    unsafe {
        core::arch::asm!(
            "msr tpidr_el1, {}",
            in(reg) block as u64,
            options(nomem, nostack, preserves_flags)
        );
    }
}

/// The running CPU's logical index. See the module docs.
pub(crate) fn cpu_index() -> usize {
    let ptr: u64;
    // SAFETY: reading TPIDR_EL1 at EL1 has no side effects.
    unsafe {
        core::arch::asm!(
            "mrs {}, tpidr_el1",
            out(reg) ptr,
            options(nomem, nostack, preserves_flags)
        );
    }
    if ptr == 0 {
        return 0;
    }
    // SAFETY: the only non-zero values ever written to TPIDR_EL1 are the addresses of
    // `BLOCKS` entries: by `adopt_boot_cpu` on the boot CPU, and by `__secondary_entry` from
    // the block `start` passed. `index` is at offset 0 and never written after
    // initialisation.
    unsafe { (*(ptr as *const CpuBlock)).index }
}

/// The boot CPU's MPIDR affinity fields, `Aff3` and `Aff2.Aff1.Aff0`, with the flag and
/// reserved bits cleared: the value a device tree's `/cpus` `reg` names it by.
pub fn this_mpidr() -> u64 {
    let mpidr: u64;
    // SAFETY: MPIDR_EL1 is readable at EL1 and reading it has no side effects.
    unsafe {
        core::arch::asm!(
            "mrs {}, mpidr_el1",
            out(reg) mpidr,
            options(nomem, nostack, preserves_flags)
        );
    }
    mpidr & 0xff_00ff_ffff
}

/// How firmware is called.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Conduit {
    /// `HVC #0`: a hypervisor implements PSCI. QEMU's `virt` without EL2 or EL3 for the
    /// guest.
    Hvc,
    /// `SMC #0`: secure firmware does. QEMU's `virt` with `virtualization=on`.
    Smc,
}

/// Why a CPU did not come online.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum StartError {
    /// Logical index 0, or past [`MAX_CPUS`].
    BadIndex,
    /// Every thread-stack slot is taken.
    NoStack,
    /// No interrupt controller is installed, so a secondary could take no interrupt.
    NoController,
    /// `CPU_ON` refused, with the PSCI status it returned.
    Firmware(i64),
    /// Started, but did not report in within a second.
    Timeout,
    /// Reported in, but its part of the interrupt controller could not be prepared.
    ControllerRefused,
}

/// PSCI 0.2 `CPU_ON`, SMC64 calling convention.
const PSCI_CPU_ON: u64 = 0xc400_0003;

/// Start the CPU whose MPIDR affinity is `mpidr` as logical CPU `cpu`, and wait for it to
/// report in. `cpu_on` is the PSCI function ID for `CPU_ON`, `name` names its stack in a
/// fault report.
///
/// # Safety
/// On the boot CPU, with the kernel address space and interrupt controller installed and
/// interrupts masked. `mpidr` must name a CPU that is off and is not the caller, and each
/// `cpu` must be used once.
pub unsafe fn start(
    cpu: usize,
    mpidr: u64,
    conduit: Conduit,
    cpu_on: Option<u64>,
    name: &'static str,
) -> Result<(), StartError> {
    let block = match BLOCKS.get(cpu) {
        Some(b) if cpu != 0 => b,
        _ => return Err(StartError::BadIndex),
    };
    if irq::chip().is_none() {
        return Err(StartError::NoController);
    }
    let (_, top, _) = crate::kspace::claim_thread_stack(name).ok_or(StartError::NoStack)?;
    capture_boot_regs();
    block.stack_top.store(top.raw(), Ordering::Release);
    block.mpidr.store(mpidr, Ordering::Release);
    block.state.store(STARTING, Ordering::Release);

    unsafe extern "C" {
        fn __secondary_entry();
    }
    let entry = __secondary_entry as *const () as usize as u64;
    let context = block as *const CpuBlock as u64;
    // SAFETY: the conduit the tree names is how this machine's firmware takes calls, and
    // CPU_ON has no effect on the caller beyond the registers SMCCC lets it clobber. The
    // entry point is identity-mapped code, and the context is a static block whose stack
    // and translation registers were published above, with `Release` stores so the new CPU
    // sees them.
    let status = unsafe { psci(conduit, cpu_on.unwrap_or(PSCI_CPU_ON), mpidr, entry, context) };
    if status != 0 {
        block.state.store(OFFLINE, Ordering::Release);
        return Err(StartError::Firmware(status));
    }

    let deadline = deadline_after(timer::frequency());
    loop {
        match block.state.load(Ordering::Acquire) {
            ONLINE => return Ok(()),
            FAILED => return Err(StartError::ControllerRefused),
            _ if timer::counter() >= deadline => return Err(StartError::Timeout),
            _ => core::hint::spin_loop(),
        }
    }
}

/// Prepare the boot CPU to take and send IPIs: its own routing token, and the two SGIs
/// enabled. Returns whether its controller can direct IPIs at all.
///
/// # Safety
/// On the boot CPU with interrupts masked, after the controller is installed.
pub unsafe fn prepare_boot_cpu() -> bool {
    let Some(chip) = irq::chip() else {
        return false;
    };
    let block = &BLOCKS[0];
    block.mpidr.store(this_mpidr(), Ordering::Release);
    block
        .seen_index
        .store(Aarch64::cpu_index(), Ordering::Release);
    block
        .seen_id
        .store(<Aarch64 as hal::HasSmp>::cpu_id(), Ordering::Release);
    // SAFETY: the caller's contract is `init_cpu`'s.
    let Some(token) = (unsafe { chip.init_cpu() }) else {
        return false;
    };
    block.ipi_target.store(token, Ordering::Release);
    block.has_ipi_target.store(1, Ordering::Release);
    chip.enable(IrqNumber(IPI_CALL));
    chip.enable(IrqNumber(IPI_RESCHEDULE));
    chip.enable(IrqNumber(IPI_TLB));
    block.state.store(ONLINE, Ordering::Release);
    true
}

/// What CPU `cpu` said its own logical index and `cpu_id` were, asked on that CPU.
pub fn seen_ids(cpu: usize) -> Option<(usize, u32)> {
    let b = BLOCKS.get(cpu)?;
    Some((b.seen_index.load(Ordering::Acquire), b.seen_id.load(Ordering::Acquire)))
}

/// Whether CPU `cpu` has reported in.
pub fn is_online(cpu: usize) -> bool {
    BLOCKS
        .get(cpu)
        .is_some_and(|b| b.state.load(Ordering::Acquire) == ONLINE)
}

/// Timer interrupts CPU `cpu` has taken. Secondaries only; the boot CPU's are the tick's.
pub fn ticks(cpu: usize) -> u64 {
    BLOCKS
        .get(cpu)
        .map_or(0, |b| b.ticks.load(Ordering::Acquire))
}

/// Reschedule IPIs CPU `cpu` has taken.
pub fn reschedules(cpu: usize) -> u64 {
    BLOCKS
        .get(cpu)
        .map_or(0, |b| b.reschedules.load(Ordering::Acquire))
}

/// Raise `ipi` on CPU `cpu`. `false` if that CPU cannot be addressed.
pub fn send(cpu: usize, ipi: u32) -> bool {
    let (Some(block), Some(chip)) = (BLOCKS.get(cpu), irq::chip()) else {
        return false;
    };
    if block.has_ipi_target.load(Ordering::Acquire) == 0 {
        return false;
    }
    chip.send_ipi(IrqNumber(ipi), block.ipi_target.load(Ordering::Acquire));
    true
}

/// Run `f(arg)` on CPU `cpu` from its IPI handler, and wait up to a second for the result.
///
/// `f` runs in interrupt context on the target, with interrupts masked: it must not
/// block, and it must not take a lock the target's interrupted code could hold.
///
/// Boot-path only: one call per target is outstanding at a time and the boot CPU is the
/// only caller, which is what lets a sequence number stand in for a queue.
pub fn call(cpu: usize, f: fn(u64) -> u64, arg: u64) -> Option<u64> {
    let block = BLOCKS.get(cpu)?;
    if block.state.load(Ordering::Acquire) != ONLINE {
        return None;
    }
    let before = block.calls_done.load(Ordering::Acquire);
    block.call_arg.store(arg, Ordering::Release);
    block.call_fn.store(f as usize, Ordering::Release);
    if !send(cpu, IPI_CALL) {
        block.call_fn.store(0, Ordering::Release);
        return None;
    }
    let deadline = deadline_after(timer::frequency());
    while block.calls_done.load(Ordering::Acquire) == before {
        if timer::counter() >= deadline {
            // Withdraw it, so a late IPI does not run a call nobody waits for.
            block.call_fn.store(0, Ordering::Release);
            return None;
        }
        core::hint::spin_loop();
    }
    Some(block.call_result.load(Ordering::Acquire))
}

/// A counter value `ticks` from now, saturating.
fn deadline_after(ticks: u64) -> u64 {
    timer::counter().saturating_add(ticks)
}

/// Copy the boot CPU's translation registers for `__secondary_entry`.
fn capture_boot_regs() {
    let (mair, tcr, ttbr, sctlr): (u64, u64, u64, u64);
    // SAFETY: reading these four EL1 registers has no side effects.
    unsafe {
        core::arch::asm!(
            "mrs {m}, mair_el1",
            "mrs {t}, tcr_el1",
            "mrs {b}, ttbr0_el1",
            "mrs {s}, sctlr_el1",
            m = out(reg) mair,
            t = out(reg) tcr,
            b = out(reg) ttbr,
            s = out(reg) sctlr,
            options(nomem, nostack, preserves_flags)
        );
    }
    for (slot, value) in __smp_boot_regs.iter().zip([mair, tcr, ttbr, sctlr]) {
        slot.store(value, Ordering::Release);
    }
}

/// Call PSCI function `function` with three arguments, returning its status.
///
/// # Safety
/// `conduit` must be how this machine's firmware is called, and the call must be one that
/// returns to the caller.
unsafe fn psci(conduit: Conduit, function: u64, a1: u64, a2: u64, a3: u64) -> i64 {
    let status: u64;
    // SAFETY: the caller's contract. SMCCC lets the callee clobber x0-x17, which
    // `clobber_abi("C")` declares, and preserves the rest.
    unsafe {
        match conduit {
            Conduit::Hvc => core::arch::asm!(
                "hvc #0",
                inout("x0") function => status,
                in("x1") a1,
                in("x2") a2,
                in("x3") a3,
                clobber_abi("C"),
                options(nostack)
            ),
            Conduit::Smc => core::arch::asm!(
                "smc #0",
                inout("x0") function => status,
                in("x1") a1,
                in("x2") a2,
                in("x3") a3,
                clobber_abi("C"),
                options(nostack)
            ),
        }
    }
    status as i64
}

/// A secondary's first Rust, on its own stack, translated, masked, with `TPIDR_EL1` set.
#[unsafe(no_mangle)]
extern "C" fn aarch64_secondary_main(block: &'static CpuBlock) -> ! {
    // SAFETY: VBAR_EL1 is banked, so this installs the table for this CPU alone, which has
    // every exception masked and no interrupt source enabled.
    unsafe { exception::install_vectors() };

    block
        .seen_index
        .store(Aarch64::cpu_index(), Ordering::Release);
    block
        .seen_id
        .store(<Aarch64 as hal::HasSmp>::cpu_id(), Ordering::Release);

    let Some(chip) = irq::chip() else {
        block.state.store(FAILED, Ordering::Release);
        Aarch64::halt()
    };
    // SAFETY: on this CPU, masked, after the boot CPU's `init`, as `start` requires.
    let Some(token) = (unsafe { chip.init_cpu() }) else {
        block.state.store(FAILED, Ordering::Release);
        Aarch64::halt()
    };
    block.ipi_target.store(token, Ordering::Release);
    block.has_ipi_target.store(1, Ordering::Release);

    chip.enable(IrqNumber(IPI_CALL));
    chip.enable(IrqNumber(IPI_RESCHEDULE));
    chip.enable(IrqNumber(IPI_TLB));
    chip.enable(IrqNumber(timer::PPI));
    let period = u32::try_from(timer::frequency() / SECONDARY_HZ).unwrap_or(u32::MAX);
    block.period.store(period, Ordering::Release);
    timer::arm(period.max(1));

    block.state.store(ONLINE, Ordering::Release);

    // Idle until released: nothing else runs here. `wait_for_interrupt` returns with IRQs
    // unmasked, having taken whatever woke it; masking again before the next look is what
    // keeps the check for work and the wait inseparable once there is work to check for.
    loop {
        // SAFETY: the vectors are installed and every source enabled above has a handler.
        unsafe { tick::wait_for_interrupt() };
        let _ = Aarch64::irq_save();
        if let Some(entry) = released_entry() {
            // The timer is the scheduler's from here: no more periodic re-arming. Stopped
            // before the entry runs, which arms it one-shot for itself.
            block.period.store(0, Ordering::Release);
            timer::stop();
            entry(block.index);
        }
    }
}

/// The scheduler's entry for secondaries, as a type-erased `fn(usize) -> !`. Null until
/// [`release`].
static SECONDARY_ENTRY: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

fn released_entry() -> Option<fn(usize) -> !> {
    let raw = SECONDARY_ENTRY.load(Ordering::Acquire);
    if raw.is_null() {
        return None;
    }
    // SAFETY: written only by `release`, with a `fn(usize) -> !` cast to a data pointer;
    // the two have the same size and representation on this target.
    Some(unsafe { core::mem::transmute::<*mut (), fn(usize) -> !>(raw) })
}

/// Whether the scheduler owns the secondaries' timers and reschedule IPIs.
pub(crate) fn released() -> bool {
    !SECONDARY_ENTRY.load(Ordering::Acquire).is_null()
}

/// Hand every online secondary to `entry`. See the module docs.
///
/// # Safety
/// Once, from the boot CPU, after the scheduler `entry` joins exists.
pub unsafe fn release(entry: fn(usize) -> !) {
    // `Release`, and before the wake-ups: a secondary woken by the IPI below loads it with
    // `Acquire`, so it sees the entry.
    SECONDARY_ENTRY.store(entry as *mut (), Ordering::Release);
    for cpu in 1..MAX_CPUS {
        if is_online(cpu) {
            let _ = send(cpu, IPI_RESCHEDULE);
        }
    }
}

/// The handler every [`IPI_TLB`] runs, as a type-erased `fn()`. Null to ignore them.
static TLB_HANDLER: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

/// Set what [`IPI_TLB`] runs.
pub fn set_tlb_handler(handler: Option<fn()>) {
    let raw = handler.map_or(core::ptr::null_mut(), |f| f as *mut ());
    TLB_HANDLER.store(raw, Ordering::Release);
}

/// The kernel's extension of a local invalidation to every CPU, as a type-erased
/// `fn(Option<usize>)`. Null keeps invalidation local.
static SHOOTDOWN: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

/// Set what [`crate::paging`]'s `flush_tlb` calls after it invalidates locally.
pub fn set_shootdown(hook: Option<fn(Option<usize>)>) {
    let raw = hook.map_or(core::ptr::null_mut(), |f| f as *mut ());
    SHOOTDOWN.store(raw, Ordering::Release);
}

/// Called by `flush_tlb` after its local invalidation.
pub(crate) fn shootdown(addr: Option<usize>) {
    let raw = SHOOTDOWN.load(Ordering::Acquire);
    if raw.is_null() {
        return;
    }
    // SAFETY: written only by `set_shootdown`, with a `fn(Option<usize>)` cast to a data
    // pointer, or null, excluded above.
    let hook = unsafe { core::mem::transmute::<*mut (), fn(Option<usize>)>(raw) };
    hook(addr);
}

/// Handle a timer interrupt if it arrived on a secondary. `None` on the boot CPU, whose
/// timer belongs to the tick. `Some(true)` when the scheduler owns this CPU and its hook
/// should run, `Some(false)` when the tick was the secondary's own.
pub(crate) fn on_secondary_tick() -> Option<bool> {
    let cpu = cpu_index();
    if cpu == 0 {
        return None;
    }
    let block = BLOCKS.get(cpu)?;
    // Level-sensitive, as on the boot CPU: re-arming is what deasserts it. Once released,
    // the period is zero and the scheduler's hook arms the next deadline.
    let period = block.period.load(Ordering::Acquire);
    match period {
        0 => timer::stop(),
        p => timer::arm(p),
    }
    block.ticks.fetch_add(1, Ordering::Release);
    Some(period == 0 && released())
}

/// Handle SGI `id` on the running CPU. Returns whether the scheduler's hook should run
/// after it: a reschedule IPI once the scheduler owns the CPUs.
pub(crate) fn on_ipi(id: u32) -> bool {
    let Some(block) = BLOCKS.get(cpu_index()) else {
        return false;
    };
    match id {
        IPI_CALL => {
            let f = block.call_fn.swap(0, Ordering::AcqRel);
            if f == 0 {
                // Withdrawn after a timeout, or a duplicate; nobody waits.
                return false;
            }
            // SAFETY: `call_fn` is written only by `call`, with a `fn(u64) -> u64` cast to
            // an address, or with zero, excluded above. Function and data addresses are
            // the same size on this target, so the cast back is the identity.
            let f = unsafe { core::mem::transmute::<usize, fn(u64) -> u64>(f) };
            let result = f(block.call_arg.load(Ordering::Acquire));
            block.call_result.store(result, Ordering::Release);
            block.calls_done.fetch_add(1, Ordering::Release);
            false
        }
        IPI_RESCHEDULE => {
            block.reschedules.fetch_add(1, Ordering::Release);
            released()
        }
        IPI_TLB => {
            let raw = TLB_HANDLER.load(Ordering::Acquire);
            if !raw.is_null() {
                // SAFETY: written only by `set_tlb_handler`, with a `fn()` cast to a data
                // pointer, or null, excluded above.
                let handler = unsafe { core::mem::transmute::<*mut (), fn()>(raw) };
                handler();
            }
            false
        }
        _ => false,
    }
}

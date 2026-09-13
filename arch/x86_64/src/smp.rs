//! Secondary CPUs: the per-CPU block each one's `GS` points at, the real-mode trampoline a
//! startup IPI enters, inter-processor interrupts, and each secondary's idle loop.
//!
//! This is mechanism only. Which CPUs exist comes from the MADT, and the INIT and startup
//! IPIs are the local APIC driver's to send, and `arch` may read neither. So
//! `kernel/platform/acpi` asks [`prepare`] to get a CPU's trampoline and stack ready, has
//! the driver send the IPIs, and then waits with [`wait_online`].
//!
//! # A CPU's number
//!
//! Hardware names an x86 CPU by its APIC ID, which is sparse. The kernel names it by a
//! dense logical index, the boot CPU's being 0, decided here when a CPU is prepared and kept
//! in that CPU's [`CpuBlock`]. The `GS` base (`MSR_GS_BASE`) holds the block's address, and
//! the index is the block's first field, so [`cpu_index`] is one load through `GS`, on any
//! CPU, at any time. The boot entries in `boot.rs` set the boot CPU's before any Rust runs.
//! Nothing in the kernel loads `GS` after that; `swapgs`, when user mode exists, will have to
//! keep this true for kernel code.
//!
//! # Starting one
//!
//! A startup IPI starts the CPU in real mode at `vector * 0x1000`, with `CS` = `vector << 8`
//! and nothing else set up. So the trampoline is copied to [`TRAMPOLINE_PAGE`], the first
//! page above the never-mapped page 0: below 1 MiB, as real mode requires; not
//! handed out by the frame allocator, which reserves the low mebibyte; and past the BIOS
//! interrupt vector table and data area, which are all in page 0. By the time the kernel
//! starts CPUs, nothing still reads the loader's data there.
//!
//! The trampoline enables protected mode, then long mode on the bootstrap page tables
//! `boot.rs` built, which identity-map the first 4 GiB with every page executable. The
//! kernel's own tables map low memory as data, never executable, and the instructions right
//! after `CR0.PG` is set run from the trampoline page. From long mode it jumps to
//! `__ap_long_mode_entry`, in the kernel's text, which loads the boot CPU's `CR4`, `CR3` and
//! `CR0` (captured by [`prepare`]) so that every CPU runs on the one kernel address space
//! with the same protections, points `GS` at its block, takes the stack slot [`prepare`]
//! claimed, and calls Rust.
//!
//! # What a secondary does
//!
//! It loads its own GDT and TSS (`gdt.rs`, which gives it its own #DF stack), the shared IDT,
//! prepares its local APIC, starts its local APIC timer at [`SECONDARY_HZ`], and waits for
//! interrupts. It takes timer ticks and IPIs and runs nothing else: the scheduler is the boot
//! CPU's alone. Its ticks are counted in its block and never reach the scheduler's hook.
//!
//! # IPIs
//!
//! [`IPI_CALL`] runs a function on the target and records the result; [`IPI_RESCHEDULE`] is
//! delivered and counted. The names match `arch/aarch64`'s, so code above `arch` that sends
//! them is the same on both. [`send`] is the primitive a TLB shootdown will build on: it
//! raises one IPI on one CPU and returns, without waiting. [`call`] is a boot-path facility
//! that waits for its answer, one call outstanding per target, from one caller.

use core::sync::atomic::{AtomicU8, AtomicU32, AtomicU64, AtomicUsize, Ordering};

use hal::{Arch, HasPageTables, IrqNumber};

use crate::paging::{self, EFER, EFER_NXE, WRITABLE};
use crate::{X86_64, clock, gdt, idt, interrupt, tick};

/// The most CPUs this port starts: what `gdt.rs` has tables for.
pub const MAX_CPUS: usize = 8;

/// IPI that runs a function on the target.
pub const IPI_CALL: u32 = 0;
/// IPI that asks the target to reschedule. Nothing reschedules on a secondary yet, so it is
/// counted, which is all a check needs to prove it arrived.
pub const IPI_RESCHEDULE: u32 = 1;

/// Timer interrupts per second on a secondary: enough to see ticks within a check's
/// patience, few enough to cost nothing.
pub const SECONDARY_HZ: u64 = 100;

/// The physical page the trampoline is copied to, and the startup IPI vector naming it.
pub const TRAMPOLINE_PAGE: u64 = 0x1000;
pub const TRAMPOLINE_VECTOR: u8 = (TRAMPOLINE_PAGE >> 12) as u8;

const OFFLINE: u8 = 0;
const STARTING: u8 = 1;
const ONLINE: u8 = 2;
/// Came up but could not prepare its local APIC or its timer.
const FAILED: u8 = 3;

/// Everything one CPU owns, reached through its `GS` base.
///
/// `repr(C)` because [`cpu_index`] reads `index` at offset 0 through `GS`, and
/// `__ap_long_mode_entry` reads `stack_top` at offset 8 before any Rust runs.
#[repr(C)]
pub struct CpuBlock {
    /// This CPU's logical number. Constant.
    index: usize,
    /// Where the secondary entry puts its stack pointer.
    stack_top: AtomicUsize,
    /// The APIC ID it was prepared for.
    apic_id: AtomicU32,
    /// What the interrupt controller's `init_cpu` returned on this CPU.
    ipi_target: AtomicU64,
    has_ipi_target: AtomicU8,
    state: AtomicU8,
    /// What `Arch::cpu_index` answered when asked on this CPU, as it came up.
    seen_index: AtomicUsize,
    /// What `HasSmp::cpu_id` answered there.
    seen_id: AtomicU32,
    /// Whether this CPU found its own GDT, TSS and #DF stack loaded, as it came up.
    own_tables: AtomicU8,
    /// Timer interrupts this CPU has taken, secondaries only.
    ticks: AtomicU64,
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
            apic_id: AtomicU32::new(u32::MAX),
            ipi_target: AtomicU64::new(0),
            has_ipi_target: AtomicU8::new(0),
            state: AtomicU8::new(OFFLINE),
            seen_index: AtomicUsize::new(usize::MAX),
            seen_id: AtomicU32::new(u32::MAX),
            own_tables: AtomicU8::new(0),
            ticks: AtomicU64::new(0),
            call_fn: AtomicUsize::new(0),
            call_arg: AtomicU64::new(0),
            call_result: AtomicU64::new(0),
            calls_done: AtomicU64::new(0),
            reschedules: AtomicU64::new(0),
        }
    }
}

/// Every CPU's block. Named for `boot.rs`, which points the boot CPU's `GS` at entry 0.
#[unsafe(no_mangle)]
static __cpu_blocks: [CpuBlock; MAX_CPUS] = {
    let mut blocks = [const { CpuBlock::new(0) }; MAX_CPUS];
    let mut i = 0;
    while i < MAX_CPUS {
        blocks[i] = CpuBlock::new(i);
        i += 1;
    }
    blocks
};

/// What `__ap_long_mode_entry` loads, captured by [`prepare`] for the CPU being started: the
/// boot CPU's `CR4`, `CR3` and `CR0`, and the address of the starting CPU's block. One CPU
/// starts at a time, which is what lets one set serve every start.
#[unsafe(no_mangle)]
static __smp_entry: [AtomicU64; 4] = [const { AtomicU64::new(0) }; 4];

core::arch::global_asm!(
    r#"
.equ TRAMPOLINE, 0x1000

/* Copied to TRAMPOLINE and entered there by a startup IPI, in real mode. Every address it
 * uses is written as TRAMPOLINE plus an offset into this section, because the bytes run
 * at the page they are copied to, not where the linker put them. */
.section .text.ap_trampoline, "ax"
.code16
.globl __ap_trampoline_start
__ap_trampoline_start:
    cli
    cld
    xorw %ax, %ax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %ss
    lgdtl (TRAMPOLINE + ap_gdt_pointer - __ap_trampoline_start)
    movl %cr0, %eax
    orl $1, %eax
    movl %eax, %cr0
    ljmpl $0x10, $(TRAMPOLINE + ap_protected - __ap_trampoline_start)

.code32
ap_protected:
    movw $0x18, %ax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %ss
    /* Long mode on the bootstrap tables: PAE, then EFER.LME (and NXE when the boot CPU has
     * it, since the kernel's tables use the NX bit), then paging. */
    movl (TRAMPOLINE + ap_boot_pml4 - __ap_trampoline_start), %eax
    movl %eax, %cr3
    movl %cr4, %eax
    orl $(1 << 5), %eax
    movl %eax, %cr4
    movl $0xC0000080, %ecx
    rdmsr
    orl $(1 << 8), %eax
    orl (TRAMPOLINE + __ap_efer_or - __ap_trampoline_start), %eax
    wrmsr
    movl %cr0, %eax
    orl $0x80000001, %eax
    movl %eax, %cr0
    ljmpl $0x08, $(TRAMPOLINE + ap_long - __ap_trampoline_start)

.code64
ap_long:
    movq (TRAMPOLINE + ap_entry - __ap_trampoline_start), %rax
    jmpq *%rax

.balign 8
/* Null; 0x08 the kernel's 64-bit code descriptor, so CS is already right for gdt.rs's
 * table; 0x10 and 0x18 flat 32-bit code and data for the protected-mode steps. */
ap_gdt:
    .quad 0
    .quad (1 << 43) | (1 << 44) | (1 << 47) | (1 << 53)
    .quad 0x00cf9a000000ffff
    .quad 0x00cf92000000ffff
ap_gdt_pointer:
    .word 4 * 8 - 1
    .long TRAMPOLINE + ap_gdt - __ap_trampoline_start
ap_boot_pml4:
    .long __boot_pml4
.globl __ap_efer_or
__ap_efer_or:
    .long 0
ap_entry:
    .quad __ap_long_mode_entry
.globl __ap_trampoline_end
__ap_trampoline_end:

/* In the kernel's text, on the bootstrap tables, in long mode. */
.section .text.smp, "ax"
.globl __ap_long_mode_entry
__ap_long_mode_entry:
    xorl %eax, %eax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %ss
    movw %ax, %fs
    movw %ax, %gs
    movq __smp_entry+0(%rip), %rax
    movq %rax, %cr4
    movq __smp_entry+8(%rip), %rax
    movq %rax, %cr3
    movq __smp_entry+16(%rip), %rax
    movq %rax, %cr0
    movq __smp_entry+24(%rip), %rbx
    movl $0xC0000101, %ecx
    movq %rbx, %rax
    movq %rbx, %rdx
    shrq $32, %rdx
    wrmsr
    movq 8(%rbx), %rsp
    xorq %rbp, %rbp
    movq %rbx, %rdi
    call x86_64_secondary_main
2:
    cli
    hlt
    jmp 2b
"#,
    options(att_syntax)
);

/// The running CPU's logical index. See the module docs.
pub(crate) fn cpu_index() -> usize {
    let index: usize;
    // SAFETY: `GS` points at a `CpuBlock` on every CPU from its entry onwards (`boot.rs`
    // for the boot CPU, `__ap_long_mode_entry` for a secondary), and `index` is its first
    // field, never written after initialisation.
    unsafe {
        core::arch::asm!(
            "mov {}, gs:[0]",
            out(reg) index,
            options(nostack, preserves_flags, readonly)
        );
    }
    index
}

/// Why a CPU did not come online.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum StartError {
    /// Logical index 0, or past [`MAX_CPUS`].
    BadIndex,
    /// Every thread-stack slot is taken.
    NoStack,
    /// The 8259A is still the controller, which cannot address a CPU.
    NoController,
    /// No local APIC timer, so a secondary could take no ticks.
    NoTimer,
    /// The trampoline page is not mapped writable in the kernel's space.
    NoTrampolinePage,
    /// The trampoline does not fit its page.
    TrampolineTooLarge,
    /// Prepared and sent, but did not report in within a second.
    Timeout,
    /// Reported in, but its local APIC or timer could not be prepared.
    ControllerRefused,
}

/// Get logical CPU `cpu`, whose APIC ID is `apic_id`, ready to be started: its stack, its
/// block, the trampoline at [`TRAMPOLINE_PAGE`], and what its entry loads. Returns the
/// startup IPI vector to send.
///
/// # Safety
/// On the boot CPU, with the kernel address space and the local APIC installed and
/// interrupts masked; the CPU must be off, and each `cpu` used once. No other CPU may be
/// between [`prepare`] and [`wait_online`] at the same time.
pub unsafe fn prepare(cpu: usize, apic_id: u32, name: &'static str) -> Result<u8, StartError> {
    let block = match __cpu_blocks.get(cpu) {
        Some(b) if cpu != 0 => b,
        _ => return Err(StartError::BadIndex),
    };
    if interrupt::legacy_pic() {
        return Err(StartError::NoController);
    }
    if tick::event_timer().is_none() {
        return Err(StartError::NoTimer);
    }
    unsafe extern "C" {
        static __ap_trampoline_start: u8;
        static __ap_trampoline_end: u8;
        static __ap_efer_or: u8;
    }
    let start = (&raw const __ap_trampoline_start) as usize;
    let end = (&raw const __ap_trampoline_end) as usize;
    let efer_at = (&raw const __ap_efer_or) as usize - start;
    let len = end - start;
    if len > X86_64::PAGE_SIZE {
        return Err(StartError::TrampolineTooLarge);
    }
    let page = TRAMPOLINE_PAGE as usize;
    let mapped = paging::live_leaf_bits(page).is_some_and(|e| e & 1 != 0 && e & WRITABLE != 0);
    if !mapped {
        return Err(StartError::NoTrampolinePage);
    }
    let (_, top, _) = crate::kspace::claim_thread_stack(name).ok_or(StartError::NoStack)?;

    // SAFETY: EFER exists on every CPU in long mode; reading it has no effect.
    let nxe = unsafe { paging::read_msr(EFER) } & EFER_NXE;
    // SAFETY: the page is mapped writable at its own address (checked above) and nothing
    // else uses it: the frame allocator reserves low memory, and page 0x1000 holds nothing
    // the kernel still reads by now. The trampoline's bytes are in the kernel's text and do
    // not overlap it. `efer_at` is inside the copy, and a `u32` there is written unaligned.
    unsafe {
        let dest = core::ptr::with_exposed_provenance_mut::<u8>(page);
        core::ptr::copy_nonoverlapping(start as *const u8, dest, len);
        dest.add(efer_at).cast::<u32>().write_unaligned(nxe as u32);
    }

    __smp_entry[0].store(read_cr4(), Ordering::Release);
    __smp_entry[1].store(X86_64::root().raw(), Ordering::Release);
    __smp_entry[2].store(paging::read_cr0(), Ordering::Release);
    __smp_entry[3].store(block as *const CpuBlock as u64, Ordering::Release);
    block.stack_top.store(top.raw(), Ordering::Release);
    block.apic_id.store(apic_id, Ordering::Release);
    block.state.store(STARTING, Ordering::Release);
    Ok(TRAMPOLINE_VECTOR)
}

/// Whether CPU `cpu` has reported in, one way or the other: online, or failed.
pub fn has_reported(cpu: usize) -> bool {
    __cpu_blocks
        .get(cpu)
        .is_some_and(|b| matches!(b.state.load(Ordering::Acquire), ONLINE | FAILED))
}

/// Wait up to a second for CPU `cpu`, which [`prepare`] readied and the startup IPIs
/// started, to report in.
pub fn wait_online(cpu: usize) -> Result<(), StartError> {
    let Some(block) = __cpu_blocks.get(cpu) else {
        return Err(StartError::BadIndex);
    };
    let deadline = Deadline::after_us(1_000_000);
    loop {
        match block.state.load(Ordering::Acquire) {
            ONLINE => return Ok(()),
            FAILED => return Err(StartError::ControllerRefused),
            _ if deadline.passed() => {
                block.state.store(OFFLINE, Ordering::Release);
                return Err(StartError::Timeout);
            }
            _ => core::hint::spin_loop(),
        }
    }
}

/// Prepare the boot CPU to take and send IPIs through its local APIC. Returns whether the
/// installed controller can address CPUs at all.
///
/// # Safety
/// On the boot CPU with interrupts masked, after the controller is installed.
pub unsafe fn prepare_boot_cpu() -> bool {
    if interrupt::legacy_pic() {
        return false;
    }
    let block = &__cpu_blocks[0];
    block
        .seen_index
        .store(X86_64::cpu_index(), Ordering::Release);
    block
        .seen_id
        .store(<X86_64 as hal::HasSmp>::cpu_id(), Ordering::Release);
    block
        .own_tables
        .store(u8::from(gdt::owns_tables(0)), Ordering::Release);
    // SAFETY: the caller's contract is `init_cpu`'s.
    let Some(token) = (unsafe { interrupt::irq_chip().init_cpu() }) else {
        return false;
    };
    block.apic_id.store(token as u32, Ordering::Release);
    block.ipi_target.store(token, Ordering::Release);
    block.has_ipi_target.store(1, Ordering::Release);
    block.state.store(ONLINE, Ordering::Release);
    true
}

/// What CPU `cpu` said its own logical index and `cpu_id` were, asked on that CPU.
pub fn seen_ids(cpu: usize) -> Option<(usize, u32)> {
    let b = __cpu_blocks.get(cpu)?;
    Some((b.seen_index.load(Ordering::Acquire), b.seen_id.load(Ordering::Acquire)))
}

/// Whether CPU `cpu` has reported in and is running.
pub fn is_online(cpu: usize) -> bool {
    __cpu_blocks
        .get(cpu)
        .is_some_and(|b| b.state.load(Ordering::Acquire) == ONLINE)
}

/// The APIC ID CPU `cpu`'s local APIC reported when it came up, if it has.
pub fn apic_id(cpu: usize) -> Option<u32> {
    let b = __cpu_blocks.get(cpu)?;
    (b.has_ipi_target.load(Ordering::Acquire) != 0)
        .then(|| b.ipi_target.load(Ordering::Acquire) as u32)
}

/// Whether CPU `cpu` found its own GDT, TSS and #DF stack loaded when it came up.
pub fn owns_tables(cpu: usize) -> bool {
    __cpu_blocks
        .get(cpu)
        .is_some_and(|b| b.own_tables.load(Ordering::Acquire) != 0)
}

/// The APIC ID CPU `cpu` was prepared for: the one the MADT gave, or the boot CPU's own.
pub fn prepared_apic_id(cpu: usize) -> Option<u32> {
    let id = __cpu_blocks.get(cpu)?.apic_id.load(Ordering::Acquire);
    (id != u32::MAX).then_some(id)
}

/// Timer interrupts CPU `cpu` has taken. Secondaries only; the boot CPU's are the tick's.
pub fn ticks(cpu: usize) -> u64 {
    __cpu_blocks
        .get(cpu)
        .map_or(0, |b| b.ticks.load(Ordering::Acquire))
}

/// Reschedule IPIs CPU `cpu` has taken.
pub fn reschedules(cpu: usize) -> u64 {
    __cpu_blocks
        .get(cpu)
        .map_or(0, |b| b.reschedules.load(Ordering::Acquire))
}

/// Raise `ipi` on CPU `cpu`, and return without waiting. `false` if that CPU cannot be
/// addressed or `ipi` is not one this port knows.
///
/// Callable from any CPU, with interrupts masked or not: it is one write to the calling
/// CPU's interrupt command register (x2APIC) or two (MMIO), and the local APIC is the
/// calling CPU's own.
pub fn send(cpu: usize, ipi: u32) -> bool {
    let Some(block) = __cpu_blocks.get(cpu) else {
        return false;
    };
    let vector = match ipi {
        IPI_CALL => interrupt::IPI_CALL_VECTOR,
        IPI_RESCHEDULE => interrupt::IPI_RESCHEDULE_VECTOR,
        _ => return false,
    };
    if block.has_ipi_target.load(Ordering::Acquire) == 0 || interrupt::legacy_pic() {
        return false;
    }
    interrupt::irq_chip()
        .send_ipi(IrqNumber(u32::from(vector)), block.ipi_target.load(Ordering::Acquire));
    true
}

/// Run `f(arg)` on CPU `cpu` from its IPI handler, and wait up to a second for the result.
///
/// `f` runs in interrupt context on the target, with interrupts masked: it must not
/// block, and it must not take a lock the target's interrupted code could hold.
///
/// Boot-path only: one call per target is outstanding at a time and one CPU is the caller,
/// which is what lets a sequence number stand in for a queue.
pub fn call(cpu: usize, f: fn(u64) -> u64, arg: u64) -> Option<u64> {
    let block = __cpu_blocks.get(cpu)?;
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
    let deadline = Deadline::after_us(1_000_000);
    while block.calls_done.load(Ordering::Acquire) == before {
        if deadline.passed() {
            // Withdraw it, so a late IPI does not run a call nobody waits for.
            block.call_fn.store(0, Ordering::Release);
            return None;
        }
        core::hint::spin_loop();
    }
    Some(block.call_result.load(Ordering::Acquire))
}

/// Busy-wait `us` microseconds on the TSC. The waits between INIT and startup IPIs.
pub fn delay_us(us: u64) {
    let deadline = Deadline::after_us(us);
    while !deadline.passed() {
        core::hint::spin_loop();
    }
}

/// A point in TSC time, or a spin budget when there is no calibrated TSC.
struct Deadline {
    at: u64,
    spins: core::cell::Cell<u64>,
    tsc: bool,
}

impl Deadline {
    /// Spins that stand in for a microsecond without a TSC: generous, since it only bounds.
    const SPINS_PER_US: u64 = 1_000;

    fn after_us(us: u64) -> Deadline {
        match clock::clock_source() {
            Some(c) => Deadline {
                at: c
                    .read()
                    .saturating_add(c.frequency_hz().saturating_mul(us) / 1_000_000),
                spins: core::cell::Cell::new(0),
                tsc: true,
            },
            None => Deadline {
                at: us.saturating_mul(Self::SPINS_PER_US),
                spins: core::cell::Cell::new(0),
                tsc: false,
            },
        }
    }

    fn passed(&self) -> bool {
        if self.tsc {
            return clock::clock_source().is_some_and(|c| c.read() >= self.at);
        }
        let n = self.spins.get() + 1;
        self.spins.set(n);
        n >= self.at
    }
}

/// CR4.
fn read_cr4() -> u64 {
    let v: u64;
    // SAFETY: reading a control register has no side effects and is permitted at CPL 0.
    unsafe {
        core::arch::asm!("mov {}, cr4", out(reg) v, options(nomem, nostack, preserves_flags))
    };
    v
}

/// A secondary's first Rust: on its own stack, on the kernel's tables, masked, with `GS` set.
#[unsafe(no_mangle)]
extern "C" fn x86_64_secondary_main(block: &'static CpuBlock) -> ! {
    // SAFETY: once, on this CPU, with interrupts masked, before anything can fault on it:
    // the start-up path is the only code this CPU has run. The IDT is the boot CPU's,
    // complete and loaded there long before any secondary is started.
    let tables = unsafe {
        let ok = gdt::init_cpu(block.index);
        idt::load();
        ok
    };

    block
        .seen_index
        .store(X86_64::cpu_index(), Ordering::Release);
    block
        .seen_id
        .store(<X86_64 as hal::HasSmp>::cpu_id(), Ordering::Release);
    block
        .own_tables
        .store(u8::from(gdt::owns_tables(block.index)), Ordering::Release);

    let chip = interrupt::irq_chip();
    // SAFETY: on this CPU, masked, after the boot CPU installed the controller.
    let token = unsafe { chip.init_cpu() };
    let timer = tick::event_timer();
    let (Some(token), Some(timer), true) = (token, timer, tables) else {
        block.state.store(FAILED, Ordering::Release);
        X86_64::halt()
    };
    block.ipi_target.store(token, Ordering::Release);
    block.has_ipi_target.store(1, Ordering::Release);

    // SAFETY: on this CPU, masked, with its local APIC just prepared.
    let period = unsafe { timer.start_periodic_ns(1_000_000_000 / SECONDARY_HZ) };
    if period.is_none() {
        block.state.store(FAILED, Ordering::Release);
        X86_64::halt()
    }

    block.state.store(ONLINE, Ordering::Release);

    // Idle: nothing else runs here. `wait_for_interrupt` returns with interrupts enabled,
    // having taken whatever woke it; masking again before the next wait is what keeps the
    // check for work and the wait inseparable once there is work to check for.
    loop {
        // SAFETY: the IDT is loaded and every source this CPU enabled has a handler.
        unsafe { tick::wait_for_interrupt() };
        let _ = X86_64::irq_save();
    }
}

/// Count a local APIC timer interrupt if it arrived on a secondary. Returns `false` on the
/// boot CPU, whose timer belongs to the tick.
pub(crate) fn on_secondary_tick() -> bool {
    let cpu = cpu_index();
    if cpu == 0 {
        return false;
    }
    let Some(block) = __cpu_blocks.get(cpu) else {
        return false;
    };
    // Periodic: the local APIC reloads the count itself.
    block.ticks.fetch_add(1, Ordering::Release);
    true
}

/// Handle IPI `ipi` on the running CPU.
pub(crate) fn on_ipi(ipi: u32) {
    let Some(block) = __cpu_blocks.get(cpu_index()) else {
        return;
    };
    match ipi {
        IPI_CALL => {
            let f = block.call_fn.swap(0, Ordering::AcqRel);
            if f == 0 {
                // Withdrawn after a timeout, or a duplicate; nobody waits.
                return;
            }
            // SAFETY: `call_fn` is written only by `call`, with a `fn(u64) -> u64` cast to
            // an address, or with zero, excluded above. Function and data addresses are the
            // same size on this target, so the cast back is the identity.
            let f = unsafe { core::mem::transmute::<usize, fn(u64) -> u64>(f) };
            let result = f(block.call_arg.load(Ordering::Acquire));
            block.call_result.store(result, Ordering::Release);
            block.calls_done.fetch_add(1, Ordering::Release);
        }
        IPI_RESCHEDULE => {
            block.reschedules.fetch_add(1, Ordering::Release);
        }
        _ => {}
    }
}

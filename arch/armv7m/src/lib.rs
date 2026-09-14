//! ARMv7-M architecture support: a Cortex-M3 on the MPS2 AN385 board, executing in place,
//! with a memory protection unit and no MMU.
//!
//! The single implementation of the `hal` traits for this target, and the second port
//! without address translation. What it implements is what the core has: [`Arch`],
//! [`HasMpu`], [`HasCas`] (`LDREX`/`STREX`), [`UniProcessor`] and a context switch. Not
//! `HasMmu`, `HasSmp` or `HasFpu`.
//!
//! Everything runs privileged, threads in thread mode on the process stack and
//! exceptions in handler mode on the main stack (`boot.rs`). The one place this core's
//! exception model does not fit the kernel's context-switch contract is described in
//! `preempt.rs`, with what the port does about it.

#![no_std]

pub mod backtrace;
mod boot;
pub mod clock;
pub mod context;
mod counter;
mod exception;
pub mod kspace;
mod mpu;
mod preempt;
pub mod scs;
pub mod serial;
pub mod tick;
pub mod timer;

pub use clock::{clock_source, spin_with_timer_interrupts};
use hal::{Arch, Endian, HasCas, HasMpu, UniProcessor};
pub use serial::EARLY;

/// The ARMv7-M architecture.
pub struct Armv7m;

/// The architecture this image is built for, under a name that does not change.
pub type Cpu = Armv7m;

impl Arch for Armv7m {
    const NAME: &'static str = "armv7m";
    /// Not a translation granule — there is none — but the unit the frame allocator and
    /// the heap count memory in, as on riscv32.
    const PAGE_SIZE: usize = 4096;
    /// No translation, so a physical address is a pointer.
    const PHYS_ADDR_BITS: u8 = 32;
    const ENDIAN: Endian = Endian::Little;
    /// Loads and stores of any alignment are defined on ARMv7-M.
    const UNALIGNED_ACCESS: bool = true;

    /// `PRIMASK` as it was: bit 0 set means interrupts were masked.
    type IrqState = u32;

    fn irq_save() -> u32 {
        let old: u32;
        // SAFETY: reads PRIMASK, then sets it. Setting it only masks; faults still run.
        unsafe {
            core::arch::asm!("mrs {}, primask", "cpsid i", out(reg) old, options(nomem, nostack));
        }
        old & 1
    }

    unsafe fn irq_restore(state: u32) {
        if state == 0 {
            // SAFETY: the caller guarantees `state` came from a matching `irq_save`, which
            // found interrupts unmasked; clearing PRIMASK restores exactly that.
            //
            // Not `nomem`: unmasking lets a pending handler run, which writes memory.
            // riscv32 found what `nomem` does here: the optimiser hoisted a read of the
            // tick counter out of a loop that polled it.
            unsafe { core::arch::asm!("cpsie i", options(nostack)) };
        }
    }

    /// Nothing to wait for: one core, and no instruction for a barrier.
    fn memory_barrier() {}

    fn halt() -> ! {
        loop {
            // SAFETY: with PRIMASK set nothing but a fault runs, and `wfi` returning is
            // what the loop is for.
            unsafe { core::arch::asm!("cpsid i", "wfi", options(nomem, nostack)) };
        }
    }
}

impl HasCas for Armv7m {}

/// The Cortex-M3's PMSAv7 MPU. Eight regions is what the core offers and what QEMU models;
/// `mpu.rs` reads `MPU_TYPE` rather than trusting this.
impl HasMpu for Armv7m {
    const REGIONS: usize = 8;
}

// SAFETY: a Cortex-M3 is one core. PRIMASK masks every exception that runs kernel code
// except the faults, which report and stop rather than touch shared state, and nothing
// on the board bus-masters kernel memory.
unsafe impl UniProcessor for Armv7m {}

// Deliberately no `HasMmu`, `HasSmp`, `HasFpu` or `HasCoherentDma`: PMSAv7 does not
// translate, the M3 is one core with no FPU, and the AN385 has no DMA device this port
// uses.

/// Semihosting's `SYS_EXIT_EXTENDED`.
#[cfg(CONFIG_QEMU_EXIT)]
const SYS_EXIT_EXTENDED: u32 = 0x20;
/// `ADP_Stopped_ApplicationExit`.
#[cfg(CONFIG_QEMU_EXIT)]
const APPLICATION_EXIT: u32 = 0x2_0026;

/// Terminate the emulator, reporting whether the run passed.
///
/// Semihosting, as on aarch64: `BKPT #0xAB` with the operation in `r0` and a parameter
/// block in `r1`. A pass is exit status 0, which QEMU also produces for its own reasons;
/// the harness treats a timeout as a failure.
#[cfg(CONFIG_QEMU_EXIT)]
pub fn exit_emulator(ok: bool) -> ! {
    let block: [u32; 2] = [APPLICATION_EXIT, if ok { 0 } else { 1 }];
    // SAFETY: under QEMU with semihosting enabled this does not return. On a board with no
    // debugger BKPT is a HardFault, which is why QEMU_EXIT must be off in anything that
    // ships.
    unsafe {
        core::arch::asm!(
            "bkpt #0xab",
            in("r0") SYS_EXIT_EXTENDED,
            in("r1") block.as_ptr(),
            options(nostack)
        );
    }
    Armv7m::halt()
}

/// Stop after a fatal exception has been reported: through the emulator's result channel
/// when there is one, so a crash ends the run at once instead of as a timeout.
#[cfg(CONFIG_QEMU_EXIT)]
pub(crate) fn stop_after_fault() -> ! {
    exit_emulator(false)
}

#[cfg(not(CONFIG_QEMU_EXIT))]
pub(crate) fn stop_after_fault() -> ! {
    Armv7m::halt()
}

/// Bring up exception handling and prove it works: the MPU enforcing, and one timer
/// interrupt taken and returned from.
pub fn interrupt_selftest(c: &dyn hal::EarlyConsole) -> bool {
    // SAFETY: kmain calls this with interrupts masked.
    unsafe { exception::configure() };
    clock::start();
    c.write_str("nvic, ");
    if !exception::selftest(c) {
        return false;
    }

    let before = tick::ticks();
    timer::set_enabled(true);
    // SAFETY: masked; the handler disarms it.
    unsafe { timer::arm(timer::ticks_for(10_000_000)) };
    // SAFETY: the vector table is installed and the only enabled interrupts are the timer
    // and SysTick, whose handlers count and return; masked again below.
    unsafe { tick::enable_interrupts() };

    // A second of SysTick: far past the 10 ms armed, and a bound if the timer is dead.
    let deadline = clock::FREQUENCY;
    let start = hal::ClockSource::read(&clock::COUNTER);
    while tick::ticks() == before
        && hal::ClockSource::read(&clock::COUNTER).wrapping_sub(start) < deadline
    {
        core::hint::spin_loop();
    }

    let _ = Armv7m::irq_save();
    tick::stop();

    if tick::ticks() == before {
        c.write_str(", timer interrupt never fired");
        return false;
    }
    c.write_str("; timer interrupt taken");
    true
}

/// The kernel image, as `[start, end)`: from the vector table at the base of code memory
/// to the end of its RAM part. It spans the hole between the two, which is no memory at
/// all, so reserving it reserves exactly the image.
pub fn image_range() -> (u64, u64) {
    unsafe extern "C" {
        static __kernel_start: u8;
        static __kernel_end: u8;
    }
    let start = (&raw const __kernel_start) as usize as u64;
    let end = (&raw const __kernel_end) as usize as u64;
    (start, end)
}

/// Bytes per kernel thread stack slot, from `THREAD_STACK_KIB`. `link.ld` reserves whole
/// slots of the same size through `stacks.ld`, which kbuild derives from the same symbol,
/// so the two cannot drift.
pub const THREAD_STACK_SLOT: u64 = kconfig::THREAD_STACK_KIB as u64 * 1024;

/// Bytes of MPU guard at the bottom of each slot: an eighth of the two-slot region that
/// covers it, which is a quarter of a slot; see `link.ld`.
pub const THREAD_STACK_GUARD: u64 = THREAD_STACK_SLOT / 4;

/// The kernel image's sections, from the symbols `link.ld` places around them.
///
/// `data` is the RAM part — `.data` at its run address through the thread stacks — which
/// is where every stack the unwinder may walk lives.
pub fn image_sections() -> hal::ImageSections {
    unsafe extern "C" {
        static __text_start: u8;
        static __text_end: u8;
        static __rodata_start: u8;
        static __rodata_end: u8;
        static __data_start: u8;
        static __data_end: u8;
        static __stack_guard_start: u8;
        static __stack_guard_end: u8;
        static __stack_bottom: u8;
        static __stack_top: u8;
        static __thread_stacks_start: u8;
        static __thread_stacks_end: u8;
    }
    fn addr(sym: *const u8) -> u64 {
        sym as usize as u64
    }
    hal::ImageSections {
        text: (addr(&raw const __text_start), addr(&raw const __text_end)),
        rodata: (addr(&raw const __rodata_start), addr(&raw const __rodata_end)),
        data: (addr(&raw const __data_start), addr(&raw const __data_end)),
        stack_guard: (addr(&raw const __stack_guard_start), addr(&raw const __stack_guard_end)),
        boot_stack: (addr(&raw const __stack_bottom), addr(&raw const __stack_top)),
        thread_stacks: hal::StackArray {
            start: addr(&raw const __thread_stacks_start),
            end: addr(&raw const __thread_stacks_end),
            slot: THREAD_STACK_SLOT,
            guard: THREAD_STACK_GUARD,
        },
    }
}

/// Start a second kernel thread, switch to it and back, and prove both directions work.
pub fn context_switch_selftest(c: &dyn hal::EarlyConsole) -> bool {
    context::selftest(c)
}

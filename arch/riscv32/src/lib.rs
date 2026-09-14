//! riscv32 architecture support: rv32imac in machine mode, with no MMU.
//!
//! The single implementation of the `hal` traits for this target, and the first port
//! without address translation. What it implements is exactly what the hardware has:
//! [`Arch`], [`HasCas`] (the A extension's LR/SC), [`UniProcessor`] and a context
//! switch. Not `HasMmu`, `HasSmp` or `HasFpu`. Code in the layers above that needs one
//! of those does not exist in this image, which is the claim this port is here to test.
//!
//! Everything runs in M-mode. There is no firmware below the kernel (`-bios none`), so
//! the kernel owns the trap vector and the timer directly.

#![no_std]

pub mod backtrace;
mod boot;
pub mod clint;
pub mod clock;
pub mod context;
pub mod kspace;
pub mod serial;
pub mod tick;
pub mod trap;

pub use clock::{clock_source, spin_with_timer_interrupts};
use hal::{Arch, Endian, HasCas, UniProcessor};
pub use serial::EARLY;

/// The riscv32 architecture.
pub struct Riscv32;

/// The architecture this image is built for, under a name that does not change.
pub type Cpu = Riscv32;

/// `mstatus.MIE`: machine-mode interrupts enabled.
const MSTATUS_MIE: usize = 1 << 3;

impl Arch for Riscv32 {
    const NAME: &'static str = "riscv32";
    /// Not a translation granule — there is no translation — but the unit the frame
    /// allocator and the heap count memory in. 4 KiB is what every other port uses, and
    /// what an Sv32 core would use if this port ever grows an MMU.
    const PAGE_SIZE: usize = 4096;
    /// No translation, so a physical address is a pointer.
    const PHYS_ADDR_BITS: u8 = 32;
    const ENDIAN: Endian = Endian::Little;
    /// Permitted by the ISA. On real cores misaligned loads may trap to firmware to be
    /// emulated, which is slow rather than wrong; M-mode here has no firmware to emulate
    /// them, so QEMU is more forgiving than a board may be.
    const UNALIGNED_ACCESS: bool = true;

    /// Whether `mstatus.MIE` was set.
    type IrqState = usize;

    fn irq_save() -> usize {
        let old: usize;
        // SAFETY: `csrrci` reads `mstatus` and clears MIE in one instruction, so the
        // state returned is the state before the mask. No other bit changes.
        unsafe {
            core::arch::asm!("csrrci {}, mstatus, 0x8", out(reg) old, options(nomem, nostack));
        }
        old & MSTATUS_MIE
    }

    unsafe fn irq_restore(state: usize) {
        if state & MSTATUS_MIE != 0 {
            // SAFETY: the caller guarantees `state` came from a matching `irq_save`, which
            // found MIE set; setting it again restores exactly that.
            //
            // Not `nomem`. Unmasking lets a pending interrupt run its handler, which
            // writes memory, and `nomem` told the optimiser otherwise: a loop polling the
            // tick counter through `irq_save`/`irq_restore` had its read of the counter
            // hoisted out, because nothing in the loop could write it, and waited out
            // its whole timeout for an interrupt it had already taken.
            unsafe { core::arch::asm!("csrsi mstatus, 0x8", options(nostack)) };
        }
    }

    /// Nothing to wait for. A barrier orders one CPU's view against another's, and this
    /// port runs the kernel on one hart; there is no instruction for it either.
    fn memory_barrier() {}

    fn halt() -> ! {
        loop {
            // SAFETY: with MIE clear and `mie` cleared, nothing can wake the hart, and
            // `wfi` returning spuriously is what the loop is for.
            unsafe {
                core::arch::asm!(
                    "csrci mstatus, 0x8",
                    "csrw mie, zero",
                    "wfi",
                    options(nomem, nostack)
                );
            }
        }
    }
}

impl HasCas for Riscv32 {}

// SAFETY: the kernel runs on hart 0 only. `_start` parks every other hart in a `wfi` loop
// with `mie` cleared before it touches any shared state, and no SMP bring-up exists for
// this port, so masking `mstatus.MIE` excludes every other execution context. There is no
// NMI in this machine model that runs kernel code, and no DMA device writes kernel memory.
unsafe impl UniProcessor for Riscv32 {}

// Deliberately no `HasMmu`, `HasSmp`, `HasFpu` or `HasCoherentDma`: rv32imac has no
// translation, this port brings up one hart, the ISA string has no F or D, and whether a
// bus master sees coherent memory is a property of a board this port has not met.

/// The `sifive_test` finisher on `virt`. A store of `0x5555` powers QEMU off with status
/// 0; `0x3333` with a code in the upper half exits with that code.
#[cfg(CONFIG_QEMU_EXIT)]
const SIFIVE_TEST: usize = 0x0010_0000;

/// Terminate the emulator, reporting whether the run passed.
///
/// Like aarch64's semihosting and unlike x86's `isa-debug-exit`, a pass is exit status
/// 0, which QEMU also produces for its own reasons. The harness compensates the same way,
/// by treating a timeout as a failure.
#[cfg(CONFIG_QEMU_EXIT)]
pub fn exit_emulator(ok: bool) -> ! {
    let code: u32 = if ok { 0x5555 } else { (1 << 16) | 0x3333 };
    // SAFETY: `test@100000` is always present on `virt`, and this store does not return
    // on QEMU. On anything else it is a store to whatever lives there, which is why
    // QEMU_EXIT must be off in anything that ships.
    unsafe { core::ptr::write_volatile(SIFIVE_TEST as *mut u32, code) };
    Riscv32::halt()
}

/// Stop after a fatal trap has been reported: through the emulator's result channel when
/// there is one, so a crash ends the run at once instead of as a timeout.
#[cfg(CONFIG_QEMU_EXIT)]
pub(crate) fn stop_after_fault() -> ! {
    exit_emulator(false)
}

#[cfg(not(CONFIG_QEMU_EXIT))]
pub(crate) fn stop_after_fault() -> ! {
    Riscv32::halt()
}

/// Bring up trap handling and prove it works: take one timer interrupt and come back.
pub fn interrupt_selftest(c: &dyn hal::EarlyConsole) -> bool {
    if !trap::install() {
        c.write_str("mtvec did not keep the trap entry");
        return false;
    }
    c.write_str("clint");

    let before = trap::TIMER_TICKS.get();
    tick::set_mie(true);
    // SAFETY: interrupts are masked (kmain's contract), so the two halves of `mtimecmp`
    // are written with nothing able to act on the intermediate value.
    unsafe { clint::set_deadline(clint::now() + clint::FREQUENCY / 100) };
    // SAFETY: `mtvec` holds the trap entry, the only enabled source is the timer, whose
    // handler disarms it, and the mask is set again below.
    unsafe { tick::enable_interrupts() };

    let deadline = clint::now() + clint::FREQUENCY;
    while trap::TIMER_TICKS.get() == before && clint::now() < deadline {
        core::hint::spin_loop();
    }

    let _ = Riscv32::irq_save();
    tick::stop();

    if trap::TIMER_TICKS.get() == before {
        c.write_str(", timer interrupt never fired");
        return false;
    }
    c.write_str(", timer interrupt taken; ");
    // The stack guards are armed here, beside the trap path that reports a fault on one:
    // a guard is only as useful as the handler that names it, which this selftest has just
    // shown takes traps. ARMv7-M probes its MPU guards from its interrupt selftest too.
    kspace::arm_guards(c)
}

/// The physical range the kernel image occupies, as `[start, end)`.
pub fn image_range() -> (u64, u64) {
    unsafe extern "C" {
        static __kernel_start: u8;
        static __kernel_end: u8;
    }
    let start = (&raw const __kernel_start) as usize as u64;
    let end = (&raw const __kernel_end) as usize as u64;
    (start, end)
}

/// Bytes per kernel thread stack slot. `link.ld` reserves whole slots and asserts it
/// agrees with this value.
pub const THREAD_STACK_SLOT: u64 = 32 * 1024;

/// The kernel image's sections, from the symbols `link.ld` places around them.
///
/// Nothing enforces these boundaries — there is no MMU — but the unwinder confines its
/// walks by them, and the layout is the other ports' so that stays true.
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
        thread_stacks: hal::StackArray {
            start: addr(&raw const __thread_stacks_start),
            end: addr(&raw const __thread_stacks_end),
            slot: THREAD_STACK_SLOT,
            guard: <Riscv32 as Arch>::PAGE_SIZE as u64,
        },
    }
}

/// Start a second kernel thread, switch to it and back, and prove both directions work.
pub fn context_switch_selftest(c: &dyn hal::EarlyConsole) -> bool {
    context::selftest(c)
}

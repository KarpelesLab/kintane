//! What the frame-pointer unwinder needs to know about riscv32.
//!
//! The RISC-V psABI points `s0` at the top of the frame — the stack pointer the function
//! was entered with — and keeps the frame record in the two words below it: the return
//! address at `s0 - 4`, the caller's `s0` at `s0 - 8`. That is below the frame pointer,
//! where every other port keeps it above, which `unwind::Layout::record_below` describes.
//! `_start` zeroes `s0` before calling `kmain`, which is where a walk ends.

use hal::EarlyConsole;

/// `[s0 - 8]` saved `s0`, `[s0 - 4]` saved `ra`.
pub const LAYOUT: unwind::Layout = unwind::Layout::record_below(4);

/// Frames a trap report adds between the interrupted code and the walk: `riscv32_trap`,
/// whose return address is in `__trap_entry`. The entry leaves `s0` alone, so the next
/// record is the interrupted function's own.
pub const EXCEPTION_FRAMES: usize = 1;

/// The frame pointer of whoever this is inlined into.
#[inline(always)]
pub fn frame_pointer() -> usize {
    let fp: usize;
    // SAFETY: copies a register; touches no memory.
    unsafe { core::arch::asm!("mv {}, s0", out(reg) fp, options(nomem, nostack)) };
    fp
}

/// Print a backtrace of the caller, leaving out `skip` of its innermost frames.
#[inline(never)]
pub fn print(c: &dyn EarlyConsole, pc: Option<usize>, skip: usize) {
    // SAFETY: there is no translation; the image's data is always readable.
    unsafe {
        unwind::print(c, LAYOUT, &crate::image_sections(), frame_pointer(), pc, skip + 1);
    }
}

/// Walk this call chain without printing, for the boot check.
#[inline(never)]
pub fn chain() -> unwind::Chain {
    // SAFETY: as for `print`.
    unsafe { unwind::chain(LAYOUT, &crate::image_sections(), frame_pointer()) }
}

/// Take an illegal-instruction trap here. For proving that a fault report's backtrace is
/// decodable.
#[inline(never)]
pub fn undefined_instruction() -> ! {
    // SAFETY: `unimp` is defined never to be a valid instruction; the trap is reported and
    // stops the machine.
    unsafe { core::arch::asm!("unimp", options(noreturn)) }
}

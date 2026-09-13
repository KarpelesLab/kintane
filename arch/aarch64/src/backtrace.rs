//! What the frame-pointer unwinder needs to know about AArch64.
//!
//! AAPCS64 makes `x29` point at a frame record: the caller's `x29`, then the link
//! register the function was entered with. `_start` zeroes both `x29` and `x30`
//! before calling into Rust, which is where a walk ends.

use hal::EarlyConsole;

/// `[x29]` saved `x29`, `[x29 + 8]` saved `x30`.
pub const LAYOUT: unwind::Layout = unwind::Layout::frame_record(8);

/// Frames an exception report adds between the interrupted code and the walk.
///
/// Just `aarch64_exception`, whose return address is in `__exc_common`. The vector
/// stub leaves `x29` alone, so the next record is the interrupted function's own.
pub const EXCEPTION_FRAMES: usize = 1;

/// The frame pointer of whoever this is inlined into.
#[inline(always)]
pub fn frame_pointer() -> usize {
    let fp: usize;
    // SAFETY: copies a register; touches no memory and no flags.
    unsafe {
        core::arch::asm!("mov {}, x29", out(reg) fp, options(nomem, nostack, preserves_flags));
    }
    fp
}

/// Print a backtrace of the caller, leaving out `skip` of its innermost frames.
///
/// Never inlined, so its own frame is always there to be left out as well.
#[inline(never)]
pub fn print(c: &dyn EarlyConsole, pc: Option<usize>, skip: usize) {
    // SAFETY: the image's data is identity-mapped read-write from boot onward.
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

/// Take an undefined-instruction exception here. For proving that a fault report's
/// backtrace is decodable.
#[inline(never)]
pub fn undefined_instruction() -> ! {
    // SAFETY: `udf` is permanently undefined, and its synchronous exception is reported
    // and halts.
    unsafe { core::arch::asm!("udf #0", options(noreturn)) }
}

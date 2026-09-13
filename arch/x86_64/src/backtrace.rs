//! What the frame-pointer unwinder needs to know about x86_64.
//!
//! With frame pointers forced, every function starts `push rbp; mov rbp, rsp`, so
//! `[rbp]` is the caller's `rbp` and `[rbp + 8]` is the return address the `call`
//! pushed. `_start` zeroes `rbp` before calling `kmain`, which is where a walk ends.

use hal::EarlyConsole;

/// `[rbp]` saved `rbp`, `[rbp + 8]` return address.
pub const LAYOUT: unwind::Layout = unwind::Layout::frame_record(8);

/// Frames an exception report adds between the interrupted code and the walk.
///
/// `fatal`, then the `x86-interrupt` handler. The handler's "return address" slot is
/// not one: above its saved `rbp` the CPU pushed either the interrupted `rip` or an
/// error code. The `rip` is printed separately as `pc`, so that slot is skipped too.
pub const EXCEPTION_FRAMES: usize = 2;

/// The frame pointer of whoever this is inlined into.
#[inline(always)]
pub fn frame_pointer() -> usize {
    let fp: usize;
    // SAFETY: copies a register; touches no memory and no flags.
    unsafe {
        core::arch::asm!("mov {}, rbp", out(reg) fp, options(nomem, nostack, preserves_flags));
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

/// Raise `#UD` here. For proving that a fault report's backtrace is decodable.
#[inline(never)]
pub fn undefined_instruction() -> ! {
    // SAFETY: `ud2` is defined to raise #UD, whose handler reports and halts.
    unsafe { core::arch::asm!("ud2", options(noreturn)) }
}

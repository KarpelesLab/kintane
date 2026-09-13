//! What the frame-pointer unwinder needs to know about ARMv7-M.
//!
//! Thumb code built with frame pointers keeps `r7` as the frame pointer, pointing at a
//! two-word record: the caller's `r7` at `[r7]`, the return address at `[r7 + 4]`. That
//! is aarch64's layout at half the word size, `unwind::Layout::frame_record(4)`. The
//! reset handler zeroes `r7` before calling `kmain`, which is where a walk ends.
//!
//! A return address read from a record has the Thumb bit set. The symbolizer looks up
//! the byte before each one, which for a Thumb return address is still inside the call.

use hal::EarlyConsole;

/// `[r7]` saved `r7`, `[r7 + 4]` saved `lr`.
pub const LAYOUT: unwind::Layout = unwind::Layout::frame_record(4);

/// The frame pointer of whoever this is inlined into.
#[inline(always)]
pub fn frame_pointer() -> usize {
    let fp: usize;
    // SAFETY: copies a register; touches no memory.
    unsafe { core::arch::asm!("mov {}, r7", out(reg) fp, options(nomem, nostack)) };
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

/// Print a backtrace starting from a frame pointer an exception saved, rather than the
/// caller's own: a fault report walks the interrupted code, not the handler.
pub(crate) fn print_from(c: &dyn EarlyConsole, fp: usize, pc: Option<usize>) {
    // SAFETY: as for `print`.
    unsafe { unwind::print(c, LAYOUT, &crate::image_sections(), fp, pc, 0) };
}

/// Walk this call chain without printing, for the boot check.
#[inline(never)]
pub fn chain() -> unwind::Chain {
    // SAFETY: as for `print`.
    unsafe { unwind::chain(LAYOUT, &crate::image_sections(), frame_pointer()) }
}

/// Take an undefined-instruction fault here. For proving that a fault report's backtrace
/// is decodable.
#[inline(never)]
pub fn undefined_instruction() -> ! {
    // SAFETY: `udf` is permanently undefined; the fault is reported and stops the machine.
    unsafe { core::arch::asm!("udf #0", options(noreturn)) }
}

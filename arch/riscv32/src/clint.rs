//! The core-local interruptor: `mtime`, `mtimecmp`, and nothing else this port uses.
//!
//! Both are 64-bit registers, and this is a 32-bit core, so each is two 32-bit halves.
//! That is the whole difficulty of this file:
//!
//! * **Reading `mtime`** can see the low half wrap between reading the two halves. It is read high,
//!   low, high, and retried until both highs agree.
//! * **Writing `mtimecmp`** in two halves passes through an intermediate value. The timer interrupt
//!   is level-sensitive — pending exactly while `mtime >= mtimecmp` — so an intermediate value in
//!   the past raises it. Writing the high half to all-ones first makes every intermediate value a
//!   deadline in the far future, and callers write with interrupts masked, so only the final value
//!   is ever acted on.
//!
//! The addresses and the tick rate are `virt`'s: `clint@2000000`, and
//! `timebase-frequency` 10 000 000 in the tree's `/cpus` node. The same device-tree
//! reading the early console is waiting for would supply both.

use core::ptr::{read_volatile, write_volatile};

/// `clint@2000000` on `virt`.
const BASE: usize = 0x0200_0000;
/// `mtimecmp` for hart 0.
const MTIMECMP: usize = BASE + 0x4000;
/// `mtime`, shared by every hart.
const MTIME: usize = BASE + 0xbff8;

/// `mtime` ticks per second on `virt`.
pub const FREQUENCY: u64 = 10_000_000;

/// # Safety
/// `addr` must be one of the register halves above.
unsafe fn read32(addr: usize) -> u32 {
    // SAFETY: the caller's contract; the CLINT is always present on `virt`, and there is
    // no translation.
    unsafe { read_volatile(addr as *const u32) }
}

/// # Safety
/// As [`read32`].
unsafe fn write32(addr: usize, v: u32) {
    // SAFETY: as for `read32`.
    unsafe { write_volatile(addr as *mut u32, v) }
}

/// The current `mtime`.
pub fn now() -> u64 {
    loop {
        // SAFETY: both halves of `mtime`; reading has no side effects.
        let (hi, lo, again) = unsafe { (read32(MTIME + 4), read32(MTIME), read32(MTIME + 4)) };
        if hi == again {
            return (u64::from(hi) << 32) | u64::from(lo);
        }
    }
}

/// Raise the timer interrupt once `mtime` reaches `deadline`.
///
/// # Safety
/// Interrupts must be masked, so no intermediate value is acted on (see the module doc).
pub unsafe fn set_deadline(deadline: u64) {
    // SAFETY: the halves of hart 0's `mtimecmp`, written high-first as the module doc
    // describes, with interrupts masked by the caller.
    unsafe {
        write32(MTIMECMP + 4, u32::MAX);
        write32(MTIMECMP, deadline as u32);
        write32(MTIMECMP + 4, (deadline >> 32) as u32);
    }
}

/// Move the deadline to the end of time, which deasserts the timer interrupt.
///
/// # Safety
/// As [`set_deadline`].
pub unsafe fn disarm() {
    // SAFETY: as for `set_deadline`; all-ones in both halves is never in the past.
    unsafe {
        write32(MTIMECMP + 4, u32::MAX);
        write32(MTIMECMP, u32::MAX);
    }
}

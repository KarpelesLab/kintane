//! How deep the boot has used the boot stack: painted at `kmain`'s entry, measured once
//! the boot checks have run.
//!
//! The boot stack is `BOOT_STACK_KIB` with a guard page below it, so running out of it
//! faults and is reported. Nearly running out is not: the eighth round found the x86_64
//! driver-domain boot at about 15.7 KiB of a 16 KiB stack only when a merge pushed it the
//! last few hundred bytes. So [`paint`] fills everything below `kmain`'s frame with a known
//! byte, and [`check`] finds the lowest byte that no longer holds it, which is as deep as
//! the stack has been. Using more than [`LIMIT_PERCENT`] of the stack fails the boot while
//! there is still room to fix it, by raising `BOOT_STACK_KIB` or by moving deep work onto a
//! thread of its own.
//!
//! A high-water mark, so a lower bound on the need: a path the boot did not take is not
//! measured, and a frame that reserved stack without writing to it is not seen.

use core::sync::atomic::Ordering;

use hal::EarlyConsole;

use crate::{AtomicBool, Check, write_usize};

/// The byte the unused stack is painted with. Not zero: much of what a frame stores is.
const PAINT: u8 = 0xb5;

/// Bytes left unpainted below the painting frame, for the frame itself and anything its
/// loop calls.
const SKIP: usize = 1024;

/// The most of the boot stack a boot may use.
pub const LIMIT_PERCENT: usize = 75;

/// Whether [`paint`] found itself on the boot stack and painted it.
static PAINTED: AtomicBool = AtomicBool::new(false);

/// Paint the boot stack below the caller's frame. `kmain`'s first act, masked, on the boot
/// stack.
#[inline(never)]
pub fn paint() {
    let (bottom, top) = arch::image_sections().boot_stack;
    let marker = 0u8;
    let here = core::hint::black_box(&raw const marker) as usize;
    let (bottom, top) = (bottom as usize, top as usize);
    if bottom == 0 || !(bottom..top).contains(&here) {
        return;
    }
    let mut at = bottom;
    while at < here.saturating_sub(SKIP) {
        // SAFETY: `[bottom, here - SKIP)` is the boot stack below this function's frame, which
        // the port maps read-write (`ImageSections::boot_stack`). Nothing lives below the
        // running frame: interrupts are masked, so no handler frame is there to overwrite.
        unsafe { (at as *mut u8).write_volatile(PAINT) };
        at += 1;
    }
    PAINTED.store(true, Ordering::Relaxed);
}

/// The deepest use of the boot stack since [`paint`], and its size, in bytes. `None` when it
/// was not painted.
pub fn used() -> Option<(usize, usize)> {
    if !PAINTED.load(Ordering::Relaxed) {
        return None;
    }
    let (bottom, top) = arch::image_sections().boot_stack;
    let (bottom, top) = (bottom as usize, top as usize);
    let mut at = bottom;
    // SAFETY: the same mapped, read-write boot stack; reading below the caller's frame.
    while at < top && unsafe { (at as *const u8).read_volatile() } == PAINT {
        at += 1;
    }
    Some((top - at, top - bottom))
}

/// The `bootstack` line: how much of the boot stack the boot used, failed past
/// [`LIMIT_PERCENT`].
pub fn check(c: &dyn EarlyConsole) -> Check {
    c.write_str("  bootstack  ");
    let Some((used, size)) = used() else {
        c.write_str("skipped: not painted, so not measured\n");
        return Check::Skipped;
    };
    let within = used * 100 <= size * LIMIT_PERCENT;
    c.write_str("deepest ");
    write_usize(c, used);
    c.write_str(" of ");
    write_usize(c, size);
    c.write_str(" bytes (");
    write_usize(c, used * 100 / size.max(1));
    c.write_str("%, limit ");
    write_usize(c, LIMIT_PERCENT);
    c.write_str("%)");
    c.write_str(if within {
        " ok\n"
    } else {
        " TOO DEEP: raise BOOT_STACK_KIB or move the work onto a thread\n"
    });
    Check::from_ok(within)
}

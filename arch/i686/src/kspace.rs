//! What this port contributes to the kernel's own address space once it is live.
//!
//! The same three questions as on x86-64: which devices the space must map (none: every
//! device this port drives is an I/O port), whether the CPU enforces the tables, and
//! what a stack overflow looks like. The answers to the last two are weaker here, for
//! reasons that are architectural and stated below rather than left to be discovered.
//!
//! ## An overflow of the boot stack cannot be reported on this port
//!
//! A recursion that reaches the guard page faults on a push. Delivering that #PF needs a
//! push onto the same stack, which faults, which raises #DF, whose delivery needs a push
//! onto the same stack again. On x86-64 the #DF gate names an IST slot and the frame goes
//! elsewhere. A 32-bit gate has no IST field. The only way out is a task gate with its own
//! TSS, which this port does not have (see `idt.rs`), so a real overflow ends in a triple
//! fault and no report.
//!
//! So [`provoke_guard_fault`] does not overflow. It stores one byte into the guard page
//! from a healthy stack. That proves the part the address space is responsible for, that
//! the page is unmapped in the tables the CPU is running on and a touch of it faults at
//! the right address. It does not prove the part this port cannot do yet.
//!
//! ## No fault probe of `.rodata`
//!
//! x86-64 makes the CPU refuse a write to `.rodata` and observes the fault. This port's
//! #PF handler has no expected-fault path to return through, so [`enforcement_selftest`]
//! reads `CR0.WP` and `EFER.NXE` back from the hardware and reports that it did no more.

use core::sync::atomic::{AtomicBool, Ordering};

use hal::EarlyConsole;
use hal::paging::DeviceWindow;

use crate::paging;

/// Device memory the kernel touches after its own tables are installed. None here.
pub fn device_windows() -> &'static [DeviceWindow] {
    &[]
}

/// Report whether the CPU is enforcing the live tables, as far as this port can tell.
///
/// `CR0.WP` is read from the register now. Without it a read-only mapping binds nothing at
/// CPL 0, so a clear bit is a failure. NX is reported but not demanded, because the
/// target's baseline CPU does not have it and the kernel space check already accounts for
/// that.
pub fn enforcement_selftest(c: &dyn EarlyConsole) -> bool {
    let wp = paging::write_protect_enabled();
    c.write_str("CR0.WP ");
    c.write_str(if wp { "on" } else { "OFF" });
    c.write_str(", NX ");
    c.write_str(if paging::nx_enabled() {
        "on"
    } else {
        "unavailable"
    });
    c.write_str(", no fault probe on this port");
    wp
}

/// Set while [`provoke_guard_fault`] is touching the guard page on purpose.
static EXPECTING: AtomicBool = AtomicBool::new(false);

/// Whether `addr` is inside the boot stack's guard page.
fn in_guard(addr: u32) -> bool {
    let (start, end) = crate::image_sections().stack_guard;
    start < end && (start..end).contains(&u64::from(addr))
}

/// Called by the exception reporter after it has printed a fatal fault.
///
/// Names a page fault on the guard page for what it is, and, while one is being provoked,
/// turns the report into the run's verdict: that fault passes, any other fails at once.
pub(crate) fn after_fault_report(c: &dyn EarlyConsole, vector: Option<u8>, cr2: u32) {
    let guard = vector == Some(14) && in_guard(cr2);
    if guard {
        c.write_str("\nstack guard: cr2 is in the guard page below the boot stack\n");
    }
    if EXPECTING.load(Ordering::Relaxed) {
        c.write_str(if guard {
            "expected guard page fault: observed\n"
        } else {
            "expected guard page fault: this fault is not it\n"
        });
        conclude(guard)
    }
}

/// Store into the guard page, and conclude the run from the fault that must follow.
///
/// A single store rather than an overflow; the module comment says why.
pub fn provoke_guard_fault() -> ! {
    let (start, _) = crate::image_sections().stack_guard;
    EXPECTING.store(true, Ordering::SeqCst);
    #[allow(clippy::as_conversions)]
    let at = start as usize as *mut u8;
    // SAFETY: expected to fault, and the fault handler does not return: it concludes the
    // run. If the store completes, the guard page was mapped, and the one byte written is
    // in a page the linker reserved for nothing; that is reported as a failure below.
    unsafe { at.write_volatile(0) };
    conclude(false)
}

/// End the run with a verdict.
#[cfg(CONFIG_QEMU_EXIT)]
fn conclude(ok: bool) -> ! {
    crate::exit_emulator(ok)
}

/// Without a result channel there is nobody to report to, so stop.
#[cfg(not(CONFIG_QEMU_EXIT))]
fn conclude(_ok: bool) -> ! {
    <crate::I686 as hal::Arch>::halt()
}

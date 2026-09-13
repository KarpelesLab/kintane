//! What this port contributes to the kernel's own address space once it is live.
//!
//! `kernel/main` builds the space from the memory map and `image_sections()`, verifies
//! it, and installs it in `TTBR0_EL1`. The per-port parts are here.
//!
//! 1. **Devices.** Not here. This is the port where leaving one out is fatal and silent — the
//!    console is a PL011, so the first write after the switch would fault, and the fault report
//!    would itself be a write to the unmapped console — which is why the windows are not a list a
//!    person keeps up to date. `kernel/platform/fdt` maps exactly what the drivers bound from the
//!    device tree claimed, and refuses to proceed if the tree's console is not the early one.
//! 2. **Enforcement.** [`enforcement_selftest`] asks the MMU rather than the tables. `AT S1E1W`
//!    runs a write translation through the live regime and reports a permission fault in `PAR_EL1`
//!    without taking one, so "the hardware refuses a write to `.rodata`" is observed directly.
//! 3. **Stack overflow.** An overflow here is harder to report than on x86-64, and the reason is in
//!    the exception entry. Every vector begins by opening its frame on the current stack. When that
//!    stack is the one that overflowed, the frame lands in the guard page, the store faults, and
//!    the new exception opens its frame 0x120 bytes further down — below the guard, in `.bss`,
//!    where it succeeds and quietly overwrites whatever lives there. So the synchronous vector
//!    checks first, without touching memory, whether its frame would land in the guard page, and if
//!    so switches to a stack reserved for reporting that. The check is in `exception.rs`; the stack
//!    and the report are here.

use core::sync::atomic::{AtomicBool, Ordering};

use hal::{Arch, EarlyConsole};

use crate::Aarch64;
use crate::exception::write_hex;

/// Ask the MMU whether it enforces the live tables, and report what it said.
///
/// Every answer comes from `AT`, which walks the translation regime the CPU is using.
/// Execute permission is the one thing `AT` cannot be asked about; PXN is part of the
/// descriptor format and needs no enable bit, which `kernel/main` has already read back
/// from the tables.
pub fn enforcement_selftest(c: &dyn EarlyConsole) -> bool {
    let s = crate::image_sections();
    let m = sctlr_el1() & 1 != 0;
    c.write_str("SCTLR_EL1.M ");
    c.write_str(if m { "on" } else { "OFF" });

    let mut ok = m;
    ok &= expect(c, ", text", s.text.0, Walk::Read, None);
    ok &= expect(c, " w", s.text.0, Walk::Write, Some(Fault::Permission));
    ok &= expect(c, ", rodata w", s.rodata.0, Walk::Write, Some(Fault::Permission));
    ok &= expect(c, ", data w", s.data.0, Walk::Write, None);
    ok &= expect(c, ", guard", s.stack_guard.0, Walk::Read, Some(Fault::Translation));
    ok &= expect(c, ", uart w", crate::serial::UART0 as u64, Walk::Write, None);
    ok
}

#[derive(Clone, Copy)]
enum Walk {
    Read,
    Write,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Fault {
    Translation,
    Permission,
    Other,
}

/// Check one `AT` answer against what was wanted and print it.
fn expect(c: &dyn EarlyConsole, label: &str, va: u64, walk: Walk, want: Option<Fault>) -> bool {
    let got = at(walk, va);
    c.write_str(label);
    c.write_str(match got {
        None => " ok",
        Some(Fault::Translation) => " unmapped",
        Some(Fault::Permission) => " refused",
        Some(Fault::Other) => " faulted",
    });
    if got == want {
        return true;
    }
    c.write_str(match want {
        None => " (WANTED ACCESS)",
        Some(Fault::Translation) => " (WANTED UNMAPPED)",
        Some(Fault::Permission) => " (WANTED REFUSED)",
        Some(Fault::Other) => " (WANTED A FAULT)",
    });
    false
}

/// Run a stage-1 EL1 translation of `va` and return the fault it reports, if any.
fn at(walk: Walk, va: u64) -> Option<Fault> {
    let par: u64;
    // SAFETY: `AT S1E1R` and `AT S1E1W` are permitted at EL1. Each walks the tables and
    // writes `PAR_EL1`; neither accesses the address, and a failing translation is
    // reported in `PAR_EL1.F` rather than taken as an exception. The `isb` is what makes
    // the result visible to the `mrs`.
    unsafe {
        match walk {
            Walk::Read => core::arch::asm!(
                "at s1e1r, {v}",
                "isb",
                "mrs {p}, par_el1",
                v = in(reg) va,
                p = out(reg) par,
                options(nostack, preserves_flags)
            ),
            Walk::Write => core::arch::asm!(
                "at s1e1w, {v}",
                "isb",
                "mrs {p}, par_el1",
                v = in(reg) va,
                p = out(reg) par,
                options(nostack, preserves_flags)
            ),
        }
    }
    if par & 1 == 0 {
        return None;
    }
    // FST, bits [6:1]: 0b0001LL is a translation fault at level LL, 0b0011LL a
    // permission fault.
    Some(match (par >> 1) & 0b11_1100 {
        0b00_0100 => Fault::Translation,
        0b00_1100 => Fault::Permission,
        _ => Fault::Other,
    })
}

/// `SCTLR_EL1`, read now.
fn sctlr_el1() -> u64 {
    let v: u64;
    // SAFETY: reading SCTLR_EL1 is permitted at EL1 and has no side effects.
    unsafe {
        core::arch::asm!("mrs {}, sctlr_el1", out(reg) v, options(nomem, nostack, preserves_flags));
    }
    v
}

// --- the guard page ---------------------------------------------------------------

core::arch::global_asm!(
    r#"
// Entered from the synchronous vector with the exception state intact and the stack
// that overflowed abandoned. Everything the report needs is in system registers.
.section .text.kspace_overflow, "ax"
.globl __kspace_stack_overflow
__kspace_stack_overflow:
    adrp    x0, __overflow_stack_top
    add     x0, x0, :lo12:__overflow_stack_top
    mov     sp, x0
    mov     x29, xzr
    mov     x30, xzr
    mrs     x0, far_el1
    mrs     x1, esr_el1
    mrs     x2, elr_el1
    bl      aarch64_stack_overflow
.Loverflow_hang:
    msr     daifset, #0xf
    wfi
    b       .Loverflow_hang

// The stack the report runs on. Used once, by a path that never returns, so it needs
// no more than the report's own frames.
.section .bss.overflow_stack, "aw", @nobits
.balign 4096
    .skip 8192
__overflow_stack_top:
"#
);

/// Set while [`provoke_guard_fault`] is overflowing the stack on purpose.
static EXPECTING: AtomicBool = AtomicBool::new(false);

/// Whether `addr` is inside the boot stack's guard page.
fn in_guard(addr: u64) -> bool {
    let (start, end) = crate::image_sections().stack_guard;
    start < end && (start..end).contains(&addr)
}

/// `ESR_EL1.EC` for a data abort taken without a change in exception level.
const EC_DATA_ABORT_SAME_EL: u64 = 0x25;

/// Called by the exception reporter after it has printed an unhandled exception.
///
/// A data abort whose `FAR_EL1` is in the guard page is a stack overflow that still had
/// room for the exception frame, and the report says so. While an overflow is being
/// provoked this is also the verdict.
///
/// `frame` is where the exception frame was opened. Below the guard page means the
/// report is running on whatever lies beneath the stack: the synchronous vector's check
/// did not divert it, and memory the kernel owns has been overwritten to print this. The
/// overflow was caught, but not cleanly, and that is not a pass.
pub(crate) fn after_fault_report(c: &dyn EarlyConsole, esr: u64, far: u64, frame: u64) {
    let guard = esr >> 26 == EC_DATA_ABORT_SAME_EL && in_guard(far);
    let beneath = frame < crate::image_sections().stack_guard.0;
    if guard {
        c.write_str("stack overflow: far is in the guard page below the boot stack\n");
    }
    if guard && beneath {
        c.write_str(
            "and this report's frame is beneath the guard: memory below it was overwritten\n",
        );
    }
    verdict(c, guard && !beneath);
}

/// The Rust half of the overflow path: report, and conclude if this was provoked.
///
/// Reached only when the synchronous vector found its own frame would land in the guard
/// page. That is the evidence, whatever the syndrome says, so it is the verdict too.
#[unsafe(no_mangle)]
extern "C" fn aarch64_stack_overflow(far: u64, esr: u64, elr: u64) -> ! {
    let c = &crate::serial::EARLY;
    c.write_str("\n\nstack overflow: the exception frame would land in the guard page");
    c.write_str("\n  esr  ");
    write_hex(c, esr);
    c.write_str("\n  elr  ");
    write_hex(c, elr);
    c.write_str("\n  far  ");
    write_hex(c, far);
    c.write_str("\nreported from the overflow stack\n");
    verdict(c, true);
    Aarch64::halt()
}

/// While a guard fault is expected, end the run: pass on the guard, fail on anything else.
fn verdict(c: &dyn EarlyConsole, guard: bool) {
    if EXPECTING.load(Ordering::Relaxed) {
        c.write_str(if guard {
            "expected guard page fault: observed\n"
        } else {
            "expected guard page fault: not observed cleanly\n"
        });
        conclude(guard)
    }
}

/// Overflow the boot stack until it reaches the guard page.
///
/// Does not return: the exception path concludes the run. If it did return, the guard
/// protected nothing, and that is the failure reported.
pub fn provoke_guard_fault() -> ! {
    EXPECTING.store(true, Ordering::SeqCst);
    let depth = descend(0);
    let _ = depth;
    conclude(false)
}

/// Recurse without end, keeping every frame alive. See the x86-64 port's copy.
#[inline(never)]
#[allow(unconditional_recursion)]
fn descend(n: u64) -> u64 {
    let frame = core::hint::black_box([n; 16]);
    descend(core::hint::black_box(n.wrapping_add(1))).wrapping_add(frame[15])
}

/// End the run with a verdict.
#[cfg(CONFIG_QEMU_EXIT)]
fn conclude(ok: bool) -> ! {
    crate::exit_emulator(ok)
}

/// Without a result channel there is nobody to report to, so stop.
#[cfg(not(CONFIG_QEMU_EXIT))]
fn conclude(_ok: bool) -> ! {
    Aarch64::halt()
}

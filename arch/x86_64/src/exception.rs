//! CPU exception entry points and the fault report.
//!
//! Failure model (`docs/architecture.md`): an exception the kernel did not ask for is
//! a violated invariant, so there is nothing to recover to. These handlers print what
//! the hardware told us — vector, error code, CR2, RIP, and the rest of the pushed
//! frame — and stop the CPU. They deliberately do not try to resume, and they
//! deliberately do not panic: `panic!` would run the kernel's panic handler, and a
//! formatter inside a fault handler is one more thing that can fault.
//!
//! Two exceptions are not fatal:
//!
//! * **#BP** is a trap, resumable by construction — the pushed RIP is the instruction *after*
//!   `int3` — so the handler counts it and returns. This is what makes the synchronous half of the
//!   selftest an observation rather than an inference.
//! * **#PF**, but only when something has declared in advance that it expects a fault at a specific
//!   page. That is the shape demand paging needs in Phase 1 — consult something that knows about
//!   the address, resolve it, return and let the instruction re-execute — and
//!   `paging::on_page_fault` is its first and very small instance, used by the paging selftest so
//!   that "this mapping is read-only" can be demonstrated rather than asserted. Every other page
//!   fault still falls through to the reporter below, which is what makes an expected fault
//!   distinguishable from a real one instead of making all of them survivable.
//!
//! Handlers allocate nothing, take no lock, and call only into the polled UART, in
//! line with the rule that the interrupt path contains nothing that can fault or
//! deadlock against itself. The fatal report also walks the frame-pointer chain for a
//! backtrace, and that walk reads only memory it has bounds-checked against the image's
//! data (`lib/unwind`), so a corrupt stack ends the backtrace instead of faulting.
//!
//! Reference: Intel SDM Vol. 3A, §6.15 (exception reference) for vector numbers,
//! error-code presence, and the meaning of the #PF error code bits.

use core::sync::atomic::{AtomicU32, Ordering};

use hal::{Arch, EarlyConsole};

use crate::idt::InterruptFrame;
use crate::serial::{EARLY, write_hex};

/// Number of #BP exceptions taken and returned from since boot.
///
/// A counter rather than a flag so a second breakpoint is distinguishable from a
/// handler that ran once and left a flag set.
pub static BREAKPOINTS: AtomicU32 = AtomicU32::new(0);

/// Vectors 0..32 that push an error code, as a bitmask indexed by vector.
///
/// The distinction matters more than it looks: the error code sits between the CPU's
/// pushed frame and RSP, so a handler with the wrong signature reads a frame shifted
/// by eight bytes and `iret`s to a garbage address.
pub const ERROR_CODE_VECTORS: u32 = (1 << 8)      // #DF
    | (1 << 10)                                    // #TS
    | (1 << 11)                                    // #NP
    | (1 << 12)                                    // #SS
    | (1 << 13)                                    // #GP
    | (1 << 14)                                    // #PF
    | (1 << 17)                                    // #AC
    | (1 << 21)                                    // #CP
    | (1 << 29)                                    // #VC
    | (1 << 30); // #SX

/// #DE, vector 0. Fatal: the faulting `div` would re-execute on return.
pub extern "x86-interrupt" fn divide_error(frame: InterruptFrame) -> ! {
    fatal(Some(0), None, &frame)
}

/// #BP, vector 3. Counted and resumed — see the module comment.
pub extern "x86-interrupt" fn breakpoint(_frame: InterruptFrame) {
    BREAKPOINTS.fetch_add(1, Ordering::Relaxed);
}

/// #UD, vector 6. Fatal: the undefined instruction would re-execute on return.
pub extern "x86-interrupt" fn invalid_opcode(frame: InterruptFrame) -> ! {
    fatal(Some(6), None, &frame)
}

/// #DF, vector 8. Fatal by architecture: `iret` from a double fault is undefined.
///
/// The error code is always zero; it is printed anyway so the report format does not
/// change shape between vectors.
///
/// This is the one handler that does not run on the stack it was entered from: its
/// gate names an IST slot, so the CPU loads RSP from the TSS before pushing anything.
/// That is what makes the report below reachable when the double fault was caused by
/// the stack itself — the case that would otherwise triple-fault. The `rsp` printed in
/// the report is therefore the *interrupted* stack pointer, and a value that is not
/// inside the kernel stack is the diagnosis.
pub extern "x86-interrupt" fn double_fault(frame: InterruptFrame, code: u64) -> ! {
    fatal(Some(8), Some(code), &frame)
}

/// #GP, vector 13. The error code is the selector at fault, or zero.
pub extern "x86-interrupt" fn general_protection(frame: InterruptFrame, code: u64) -> ! {
    fatal(Some(13), Some(code), &frame)
}

/// #PF, vector 14. CR2 holds the address that faulted; the error code says why.
///
/// The one handler that can return, and only when something has said in advance that
/// it expects a fault at that exact page — see `paging::on_page_fault`. Returning
/// re-executes the faulting instruction, so a handler that returns without having
/// changed anything is an endless loop; the trap it consults is single-shot for
/// precisely that reason, and a second fault on the same address falls through here.
///
/// Everything else still ends at [`fatal`], so an unexpected #PF is as fatal as it was
/// before this path existed.
pub extern "x86-interrupt" fn page_fault(frame: InterruptFrame, code: u64) {
    if crate::paging::on_page_fault(cr2(), code) {
        return;
    }
    fatal(Some(14), Some(code), &frame)
}

/// Any other vector below 32 that does not push an error code.
///
/// Generic over the vector so each one gets its own entry point and can name itself
/// in the report, without hand-writing thirty near-identical functions.
pub extern "x86-interrupt" fn reserved<const V: u8>(frame: InterruptFrame) -> ! {
    fatal(Some(V), None, &frame)
}

/// Any other vector below 32 that does push an error code.
pub extern "x86-interrupt" fn reserved_with_code<const V: u8>(
    frame: InterruptFrame,
    code: u64,
) -> ! {
    fatal(Some(V), Some(code), &frame)
}

/// Vectors 48..256: nothing is wired to raise them, so delivery means either stray
/// hardware or a software `int` the kernel did not intend.
pub extern "x86-interrupt" fn unexpected(frame: InterruptFrame) -> ! {
    fatal(None, None, &frame)
}

/// Print everything the hardware told us and stop this CPU.
///
/// Not `#[inline]`: one copy shared by every entry point keeps the fault path small
/// and keeps the stack it needs small, which matters when the reason we got here is
/// that something ran out of stack.
fn fatal(vector: Option<u8>, code: Option<u64>, frame: &InterruptFrame) -> ! {
    let c: &dyn EarlyConsole = &EARLY;

    c.write_str("\n\n*** cpu exception ");
    match vector {
        Some(v) => {
            write_hex(c, u64::from(v), 2);
            c.write_str(" ");
            c.write_str(name(v));
        }
        None => c.write_str("(vector >= 48; no handler claims it)"),
    }

    c.write_str("\n    error  ");
    match code {
        Some(e) => write_hex(c, e, 8),
        None => c.write_str("(none pushed)"),
    }

    c.write_str("\n    cr2    ");
    write_hex(c, cr2(), 16);
    c.write_str("\n    rip    ");
    write_hex(c, frame.rip, 16);
    c.write_str("\n    cs     ");
    write_hex(c, frame.cs, 4);
    c.write_str("\n    rflags ");
    write_hex(c, frame.rflags, 8);
    c.write_str("\n    rsp    ");
    write_hex(c, frame.rsp, 16);
    c.write_str("\n    ss     ");
    write_hex(c, frame.ss, 4);
    c.write_str("\n");
    crate::backtrace::print(c, Some(frame.rip as usize), crate::backtrace::EXCEPTION_FRAMES);
    c.write_str("\nhalted.\n");

    crate::X86_64::halt()
}

/// CR2, the linear address of the last page fault.
///
/// Read on every fault, not only on #PF: it costs one instruction, and knowing that
/// CR2 still holds an address from an *earlier* fault has more than once been the
/// clue that identified a fault inside a fault.
fn cr2() -> u64 {
    let v: u64;
    // SAFETY: reading a control register has no side effects. CR2 is readable at CPL
    // 0, which is the only privilege level this kernel runs at today.
    unsafe {
        core::arch::asm!("mov {}, cr2", out(reg) v, options(nomem, nostack, preserves_flags));
    }
    v
}

/// The architectural mnemonic for a vector below 32.
fn name(vector: u8) -> &'static str {
    match vector {
        0 => "#DE divide error",
        1 => "#DB debug",
        2 => "NMI",
        3 => "#BP breakpoint",
        4 => "#OF overflow",
        5 => "#BR bound range exceeded",
        6 => "#UD invalid opcode",
        7 => "#NM device not available",
        8 => "#DF double fault",
        9 => "coprocessor segment overrun",
        10 => "#TS invalid TSS",
        11 => "#NP segment not present",
        12 => "#SS stack-segment fault",
        13 => "#GP general protection",
        14 => "#PF page fault",
        16 => "#MF x87 floating-point error",
        17 => "#AC alignment check",
        18 => "#MC machine check",
        19 => "#XM SIMD floating-point error",
        20 => "#VE virtualisation exception",
        21 => "#CP control protection",
        28 => "#HV hypervisor injection",
        29 => "#VC VMM communication",
        30 => "#SX security exception",
        _ => "reserved",
    }
}

//! Faults, and the exception configuration every other handler depends on.
//!
//! Every vector nothing else claims — NMI, HardFault, MemManage, BusFault, UsageFault,
//! SVCall, DebugMonitor, and every external interrupt but the timer's — enters
//! `__fault_entry`, which hands the exception frame to [`armv7m_fault`]. The core has
//! already stacked `r0`–`r3`, `r12`, `lr`, the return address and `xPSR`, on the process
//! stack if thread mode was interrupted and the main stack if a handler was;
//! `EXC_RETURN` in `lr` says which.
//!
//! One fault is expected and survived: the MPU probe (`mpu.rs`), whose faulting
//! instruction the handler steps over. Everything else is reported and stops the
//! machine.

use hal::EarlyConsole;

use crate::counter::write_hex;
use crate::{kspace, mpu, scs};

core::arch::global_asm!(
    r#"
.syntax unified
.thumb

.section .text.fault, "ax"
.globl __fault_entry
.type __fault_entry, %function
.thumb_func
__fault_entry:
    // r7 is not stacked by the core and not yet touched: it is the interrupted code's
    // frame pointer, where the report's backtrace starts.
    mov     r2, r7
    mov     r1, lr
    tst     lr, #4
    ite     eq
    mrseq   r0, msp
    mrsne   r0, psp
    // Two words keep the main stack on the 8-byte boundary exception entry left it on.
    push    {{r4, lr}}
    bl      armv7m_fault
    pop     {{r4, pc}}
"#
);

/// What the core stacked on exception entry, lowest address first.
#[repr(C)]
struct ExceptionFrame {
    r: [u32; 4],
    r12: u32,
    lr: u32,
    pc: u32,
    xpsr: u32,
}

/// `CFSR.MMARVALID`: `MMFAR` holds the address of a memory-management fault.
const MMARVALID: u32 = 1 << 7;
/// `CFSR.BFARVALID`: `BFAR` holds the address of a bus fault.
const BFARVALID: u32 = 1 << 15;
/// `CFSR`'s memory-management fault bits: instruction access, data access, unstacking,
/// stacking, lazy FP.
const MMFSR_FAULTS: u32 = 0b0011_1011;
/// `CFSR` bits saying the core could not stack or unstack the frame: MemManage's
/// `MSTKERR` and `MUNSTKERR`, BusFault's `STKERR` and `UNSTKERR`. The frame pointer this
/// handler got then points at memory the core failed to write, so it is not read.
const STACKING_FAULTS: u32 = (1 << 4) | (1 << 3) | (1 << 12) | (1 << 11);
/// `HFSR.FORCED`: a configurable fault escalated to HardFault.
const HFSR_FORCED: u32 = 1 << 30;
/// `CCR.STKALIGN`: exception entry aligns the stack to 8 bytes.
const CCR: usize = 0xE000_ED14;
const CCR_STKALIGN: u32 = 1 << 9;

/// Set up what every handler relies on: faults as exceptions of their own, 8-byte stack
/// alignment on entry, the vector table at the image's base, and priorities that put
/// PendSV below everything so it only ever returns to thread mode.
///
/// # Safety
/// Interrupts must be masked.
pub unsafe fn configure() {
    unsafe extern "C" {
        static __vectors: u8;
    }
    // SAFETY: SCS registers every ARMv7-M core has; masked, per the contract. SHPR3's top
    // byte is SysTick's priority and the one below it PendSV's; the timer's line gets the
    // same priority as SysTick.
    unsafe {
        scs::write(scs::VTOR, (&raw const __vectors) as usize as u32);
        scs::write(CCR, scs::read(CCR) | CCR_STKALIGN);
        scs::write(scs::SHCSR, scs::read(scs::SHCSR) | scs::SHCSR_FAULTS_ENABLED);
        scs::write(scs::SHPR3, (0x80 << 24) | (0xFF << 16));
        core::ptr::write_volatile((scs::NVIC_IPR + crate::timer::IRQ as usize) as *mut u8, 0x80);
    }
}

/// The length of the Thumb instruction at `pc`: 32 bits if its first halfword starts
/// `0b11101`, `0b11110` or `0b11111`, otherwise 16.
fn thumb_len(pc: u32) -> u32 {
    // SAFETY: `pc` is a return address the core stacked for an instruction it fetched, so
    // the halfword there is readable code.
    let first = unsafe { core::ptr::read_volatile(pc as usize as *const u16) };
    if first >> 11 >= 0b11101 { 4 } else { 2 }
}

/// What `CFSR` says happened, most specific first. A configurable fault taken while
/// `PRIMASK` masked it arrives as a HardFault with `HFSR.FORCED`, and this is how the
/// report still names it.
fn cause(cfsr: u32) -> &'static str {
    const CAUSES: [(u32, &str); 14] = [
        (1 << 0, "MemManage: instruction access violation"),
        (1 << 1, "MemManage: data access violation"),
        (1 << 3, "MemManage: fault unstacking on exception return"),
        (1 << 4, "MemManage: fault stacking on exception entry"),
        (1 << 8, "BusFault: instruction bus error"),
        (1 << 9, "BusFault: precise data bus error"),
        (1 << 10, "BusFault: imprecise data bus error"),
        (1 << 11, "BusFault: fault unstacking on exception return"),
        (1 << 12, "BusFault: fault stacking on exception entry"),
        (1 << 16, "UsageFault: undefined instruction"),
        (1 << 17, "UsageFault: invalid state (a branch without the Thumb bit)"),
        (1 << 18, "UsageFault: invalid exception return"),
        (1 << 24, "UsageFault: unaligned access"),
        (1 << 25, "UsageFault: divide by zero"),
    ];
    CAUSES
        .iter()
        .find(|(bit, _)| cfsr & bit != 0)
        .map_or("no configurable fault status", |(_, what)| what)
}

fn name(exception: u32) -> &'static str {
    match exception {
        2 => "NMI",
        3 => "HardFault",
        4 => "MemManage",
        5 => "BusFault",
        6 => "UsageFault",
        11 => "SVCall",
        12 => "DebugMonitor",
        n if n >= 16 => "an interrupt nothing enabled",
        _ => "a reserved exception",
    }
}

/// The one Rust entry point for every fault.
#[unsafe(no_mangle)]
extern "C" fn armv7m_fault(frame: *mut ExceptionFrame, exc_return: u32, fp: usize) {
    let exception: u32;
    // SAFETY: copies IPSR, the active exception's number; touches no memory.
    unsafe { core::arch::asm!("mrs {}, ipsr", out(reg) exception, options(nomem, nostack)) };
    // SAFETY: SCS fault status registers, read without side effects.
    let (cfsr, hfsr, mmfar, bfar) = unsafe {
        (
            scs::read(scs::CFSR),
            scs::read(scs::HFSR),
            scs::read(scs::MMFAR),
            scs::read(scs::BFAR),
        )
    };
    let fault_addr = (cfsr & MMARVALID != 0).then_some(mmfar);
    let stacked = cfsr & STACKING_FAULTS == 0;
    // SAFETY: when nothing reports a stacking fault, `frame` is the block the core stacked
    // for this exception, live for the call.
    let (pc, lr, xpsr, r) = if stacked {
        unsafe { ((*frame).pc, (*frame).lr, (*frame).xpsr, (*frame).r) }
    } else {
        (0, 0, 0, [0; 4])
    };

    // A memory-management fault on a probe — directly, or escalated to HardFault because
    // the probe ran with interrupts masked — is stepped over.
    if stacked && cfsr & MMFSR_FAULTS != 0 && mpu::probe_fault(pc, fault_addr) {
        // SAFETY: as above; the frame's return address is what exception return resumes at.
        unsafe { (*frame).pc = pc + thumb_len(pc) };
        // SAFETY: CFSR and HFSR are write-one-to-clear; this acknowledges exactly what was
        // found, so the next fault starts from clean status.
        unsafe {
            scs::write(scs::CFSR, cfsr);
            scs::write(scs::HFSR, hfsr & HFSR_FORCED);
        }
        return;
    }

    // A MemManage or BusFault handler runs with the MPU on, and what it is about to read
    // for the report — the frame, the stack the backtrace walks — may be exactly what the
    // MPU refused. Nothing runs after the report, so nothing needs it back.
    // SAFETY: MPU_CTRL is always present; zero disables the MPU.
    unsafe { scs::write(scs::MPU_CTRL, 0) };

    let c = &crate::EARLY;
    c.write_str("\n\nunhandled exception ");
    write_hex(c, u64::from(exception));
    c.write_str(" (");
    c.write_str(name(exception));
    c.write_str(")");
    if !stacked {
        c.write_str("\n  the core could not stack the interrupted state; the stack pointer was ");
        write_hex(c, frame as usize as u64);
    }
    c.write_str("\n  pc     ");
    write_hex(c, u64::from(pc));
    c.write_str("\n  lr     ");
    write_hex(c, u64::from(lr));
    c.write_str("\n  xpsr   ");
    write_hex(c, u64::from(xpsr));
    c.write_str("\n  r0-r3  ");
    for (i, v) in r.iter().enumerate() {
        if i > 0 {
            c.write_str(" ");
        }
        write_hex(c, u64::from(*v));
    }
    c.write_str("\n  cause  ");
    c.write_str(cause(cfsr));
    if exception == 3 && hfsr & HFSR_FORCED != 0 {
        c.write_str(", escalated to HardFault because it was masked");
    }
    c.write_str("\n  cfsr   ");
    write_hex(c, u64::from(cfsr));
    c.write_str("  hfsr ");
    write_hex(c, u64::from(hfsr));
    c.write_str("\n  stack  ");
    c.write_str(if exc_return & 4 != 0 {
        "process"
    } else {
        "main"
    });
    if let Some(addr) = fault_addr {
        c.write_str("\n  mmfar  ");
        write_hex(c, u64::from(addr));
        kspace::describe_guard(c, u64::from(addr));
    }
    if cfsr & BFARVALID != 0 {
        c.write_str("\n  bfar   ");
        write_hex(c, u64::from(bfar));
    }
    c.write_str("\n");
    crate::backtrace::print_from(c, fp, stacked.then_some(pc as usize));
    crate::stop_after_fault()
}

/// Enable the configurable faults and the MPU, and report both.
pub(crate) fn selftest(c: &dyn EarlyConsole) -> bool {
    mpu::selftest(c)
}

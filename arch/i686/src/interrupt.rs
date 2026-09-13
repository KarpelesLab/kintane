//! Interrupt bring-up: what is wired to what, and the proof that it works.
//!
//! ## The shape of the path
//!
//! ```text
//!   device --> 8259A line 0..16 --> vector 32..48 --> irq_entry<LINE> --> dispatch
//!   CPU fault --------------------> vector 0..32  --> exception::*
//! ```
//!
//! Each IRQ line gets its own entry point, generic over the line number, so the line
//! is known from the vector the CPU dispatched rather than asked for afterwards. That
//! matters on the 8259A specifically: its "which line is in service" register is a
//! port read, and a port read in every interrupt is a cost with no benefit when the
//! vector already carries the answer. It is read only where the answer is genuinely
//! unknown — the spurious-interrupt case, below.
//!
//! ## Locking discipline
//!
//! There is none, and that is deliberate. Everything a handler touches is an atomic
//! or a port. A lock taken in an interrupt handler must be a lock that no interrupted
//! code can hold, which is a property that has to be designed rather than hoped for;
//! the lock types and the per-CPU data they need do not exist yet, so the rule here is
//! that the interrupt path allocates nothing, locks nothing, and calls nothing that
//! can fault.
//!
//! ## SSE in the interrupt path
//!
//! This target builds with SSE enabled — it has no choice; see
//! `docs/targets.md#i686` — so the question the x86-64 port never has to ask is live
//! here: what happens to XMM state when a handler runs?
//!
//! The answer is that LLVM's `x86_intrcc` convention treats *every* register as
//! callee-saved, XMM included when the subtarget has SSE, and the prologue spills
//! exactly those an individual handler disturbs. So nothing is lost across an
//! interrupt even though the handlers are ordinary Rust functions whose calls clobber
//! XMM by the SysV rules. The kernel does not have to save FPU state by hand here, and
//! `HasFpu::FpuState` staying `()` until Phase 2 is about *context switching* between
//! tasks, not about interrupt entry.
//!
//! The part that would have been a real bug is alignment. A 32-bit interrupt entry
//! pushes twelve bytes onto a stack of whatever alignment the interrupted code had, and
//! a 16-byte SSE spill to a misaligned slot is #GP — the kind of failure that happens
//! on some interrupts and not others. This was verified against the generated code
//! rather than assumed. Every `x86_intrcc` prologue in the image does, in order:
//!
//! ```text
//!     push %ebp; mov %esp, %ebp     ; frame pointer at the CPU-pushed frame
//!     push ...                      ; the GPRs this handler disturbs
//!     and  $-0x10, %esp             ; realign for anything it calls
//!     movups %xmm7, -0x28(%ebp)     ; ...XMM spilled *unaligned*, relative to ebp
//!     cld
//! ```
//!
//! So the callee gets an aligned stack (which is what lets the `movaps` LLVM uses to
//! zero a buffer inside `fatal` be legal), while the spill slots themselves — which
//! hang off the unaligned `ebp` — are written with the unaligned form. Both halves are
//! necessary and LLVM gets both right; the reason to write it down is that neither is
//! obvious from the source, and a future change to the target's feature string would
//! change the generated code silently.
//!
//! The same prologue issues `cld`, so a handler cannot inherit a set direction flag
//! from interrupted code. What is *not* handled is x87: no kernel code uses it, and
//! when userspace arrives its state becomes entry-path work rather than an assumption.
//!
//! ## What the selftest proves
//!
//! Two separate mechanisms, checked separately, neither inferred from the other:
//! a synchronous exception (`int3`, chosen because #BP is resumable and so the
//! handler returning is itself observable) and a hardware interrupt (the PIT on
//! IRQ 0). Each reports a counter the handler incremented. If the counter did not
//! move, the selftest fails — it never concludes success from the absence of a crash.

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use hal::{Arch, EarlyConsole, IrqChip, IrqNumber};

use crate::serial::{write_dec, write_hex};
use crate::{I686, exception, idt, pic, pit, tick};

/// Install plain (no error code) handlers for a list of vectors.
///
/// The compile-time assertion is the point: a handler whose signature disagrees with
/// what the CPU pushes reads the frame one stack word off and `iret`s to nowhere, and
/// that is a failure nobody wants to debug at runtime.
macro_rules! reserved_gates {
    ($($v:literal),* $(,)?) => {$(
        const _: () = assert!(
            exception::ERROR_CODE_VECTORS & (1u32 << $v) == 0,
            "vector pushes an error code; it needs the error-code handler form"
        );
        idt::set_gate($v, idt::EntryPoint::diverging(exception::reserved::<$v>));
    )*};
}

/// Install error-code-taking handlers for a list of vectors.
macro_rules! reserved_gates_with_code {
    ($($v:literal),* $(,)?) => {$(
        const _: () = assert!(
            exception::ERROR_CODE_VECTORS & (1u32 << $v) != 0,
            "vector pushes no error code; the error-code handler form would misread \
             the stack frame"
        );
        idt::set_gate($v, idt::EntryPoint::with_code(exception::reserved_with_code::<$v>));
    )*};
}

/// Install the per-line IRQ entry points at their remapped vectors.
macro_rules! irq_gates {
    ($($line:literal),* $(,)?) => {$(
        idt::set_gate(
            pic::VECTOR_BASE + $line,
            idt::EntryPoint::plain(irq_entry::<$line>),
        );
    )*};
}

/// The interrupt controller this machine uses.
///
/// A `&'static dyn` and not a concrete type: which controller a machine has is a
/// runtime question (this one, or the local APIC once that driver exists, or none of
/// the above on a machine that boots us through something else), and the cost of one
/// indirect call per interrupt is the price of not baking the answer into the image.
/// Today there is one candidate, so the static is initialised directly; when there is
/// more than one it becomes a cell written during device discovery.
static CHIP: &dyn IrqChip = &pic::PIC;

/// The machine's interrupt controller.
pub fn irq_chip() -> &'static dyn IrqChip {
    CHIP
}

/// Timer ticks observed since boot. Written only by the IRQ 0 handler.
///
/// 64 bits on a 32-bit machine, which costs a `cmpxchg8b` loop per tick rather than a
/// single `lock incl`. Deliberate: a 32-bit tick counter wraps in 49 days at 1 kHz,
/// and a clock that silently restarts is a worse bug than a handful of cycles is a
/// cost. If the tick handler ever becomes hot enough for this to matter, the answer is
/// a per-CPU 32-bit counter folded into a 64-bit one outside the interrupt path, not a
/// narrower clock.
pub static TICKS: AtomicU64 = AtomicU64::new(0);

/// Set once [`init`] has run, so a second call cannot re-enter the ICW sequence.
static READY: AtomicBool = AtomicBool::new(false);

/// The line the PIT is wired to. Fixed by the PC architecture, not discovered.
pub(crate) const TIMER_IRQ: IrqNumber = IrqNumber(0);

/// Tick rate for the selftest. Fast enough that waiting for one tick is imperceptible,
/// slow enough that it is not a meaningful share of a TCG-emulated CPU.
const TEST_HZ: u32 = 1000;

/// How many times the selftest may spin waiting for a tick before calling it a
/// failure. Bounded because a selftest that hangs reports nothing; at this rate a
/// tick is due within roughly a millisecond of wall clock, and this budget is orders
/// of magnitude more than that even under emulation.
const SPIN_LIMIT: u64 = 100_000_000;

/// How many ticks the selftest waits for. More than one, so that the end-of-interrupt
/// path is exercised rather than assumed: a controller that is never acknowledged
/// delivers exactly once and then goes quiet.
const REQUIRED_TICKS: u64 = 3;

/// Entry point for one PIC line.
///
/// Generic over the line so that each of the sixteen vectors gets its own function
/// and knows, at compile time, which device interrupted.
extern "x86-interrupt" fn irq_entry<const LINE: u8>(_frame: idt::InterruptFrame) {
    // The 8259A's two lowest-priority lines are also how it reports a request that
    // withdrew itself between INTR and the acknowledge cycle. Such an interrupt has
    // no in-service bit and must not be acknowledged, or the EOI clears the bit of
    // whatever *is* in service and that interrupt is lost.
    if LINE == 7 || LINE == 15 {
        if CHIP.claim().is_none() {
            // A spurious line 15 still went through the master's cascade, which does
            // have an in-service bit, so the master alone is acknowledged.
            if LINE == 15 {
                CHIP.eoi(IrqNumber(2));
            }
            return;
        }
    }

    let irq = IrqNumber(u32::from(LINE));
    dispatch(irq);
    CHIP.eoi(irq);
    // Last, and after the EOI: the hook may switch threads, and this line must be
    // acknowledged before the interrupted thread is suspended. See `tick`.
    if irq == TIMER_IRQ {
        tick::run_hook();
    }
}

/// Route a line to its handler.
///
/// A `match` and not a table because there is one entry. The table arrives with the
/// device framework, which is what owns the question of who registered for a line;
/// inventing the registry here would put it in the wrong layer.
fn dispatch(irq: IrqNumber) {
    if irq == TIMER_IRQ {
        TICKS.fetch_add(1, Ordering::Relaxed);
    }
}

/// Build and load the IDT, then initialise the interrupt controller.
///
/// Idempotent: a second call returns without touching the hardware. Leaves every
/// interrupt line masked and the CPU's interrupt flag as it found it — bringing the
/// machinery up and deciding to take interrupts are separate decisions.
pub fn init() {
    if READY.swap(true, Ordering::Relaxed) {
        return;
    }

    // Every gate written before the table is loaded, with interrupts masked by the
    // caller's contract: no delivery can observe a partially built table.
    // SAFETY: each entry point below is an `extern "x86-interrupt"` function whose
    // signature matches what the CPU pushes for its vector — the error-code form for
    // the vectors that push one, the plain form for the rest — which is the
    // invariant `set_gate` asks for. The two macros assert that pairing against
    // `ERROR_CODE_VECTORS` at compile time. The whole table is filled, so `load`'s
    // requirement that no reachable vector is absent holds. `CHIP.init` wants to be
    // called once with interrupts masked and nothing else touching its ports: the
    // `READY` flag above makes it once, the caller's contract makes it masked, and no
    // other code in this kernel knows those port numbers.
    unsafe {
        idt::set_gate(0, idt::EntryPoint::diverging(exception::divide_error));
        idt::set_gate(3, idt::EntryPoint::plain(exception::breakpoint));
        idt::set_gate(6, idt::EntryPoint::diverging(exception::invalid_opcode));
        idt::set_gate(8, idt::EntryPoint::with_code(exception::double_fault));
        idt::set_gate(13, idt::EntryPoint::with_code(exception::general_protection));
        idt::set_gate(14, idt::EntryPoint::with_code(exception::page_fault));

        // The rest of the architecturally defined range, so that an unexpected one
        // reports itself instead of escalating to a triple fault.
        reserved_gates!(1, 2, 4, 5, 7, 9, 15, 16, 18, 19, 20, 22, 23, 24, 25, 26, 27, 28, 31);
        reserved_gates_with_code!(10, 11, 12, 17, 21, 29, 30);

        // The sixteen PIC lines.
        irq_gates!(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);

        // Everything above the PIC's range. Nothing raises these today; a delivery
        // means something we do not model, and it says so rather than vanishing. On a
        // BIOS-booted machine that includes the firmware's own software interrupts —
        // vector 0x10, 0x13 and friends are real-mode BIOS services, and reaching one
        // from protected mode is a bug that should name itself.
        let mut v: u16 = u16::from(pic::VECTOR_BASE) + u16::from(pic::LINES);
        while v < 256 {
            idt::set_gate(v as u8, idt::EntryPoint::diverging(exception::unexpected));
            v += 1;
        }

        idt::load();

        // Only now is it safe to let the controller exist: every vector it can
        // deliver already has a handler.
        CHIP.init();
    }
}

/// Bring interrupts up and prove both halves of the path.
///
/// Returns `true` only if a synchronous exception was taken *and returned from*, and
/// a hardware interrupt was genuinely delivered. Both are read back from counters the
/// handlers incremented; neither is inferred from the other or from survival.
pub fn selftest(c: &dyn EarlyConsole) -> bool {
    // We are called from `kmain` with interrupts masked, but say so rather than
    // assume it: everything up to the deliberate `sti` below must be uninterruptible.
    let _masked = I686::irq_save();

    init();

    c.write_str("IDT 256 gates, ");
    c.write_str(CHIP.name());
    c.write_str(" on vectors ");
    write_dec(c, u32::from(pic::VECTOR_BASE));
    c.write_str("..");
    write_dec(c, u32::from(pic::VECTOR_BASE) + u32::from(pic::LINES));

    let bp_ok = check_breakpoint(c);
    let irq_ok = check_timer(c);

    bp_ok && irq_ok
}

/// Raise #BP and confirm the handler ran and execution continued past it.
fn check_breakpoint(c: &dyn EarlyConsole) -> bool {
    let before = exception::BREAKPOINTS.load(Ordering::Relaxed);
    // SAFETY: `int3` raises #BP, vector 3, whose gate was installed above and whose
    // handler increments a counter and returns. The trap pushes the address of the
    // next instruction, so `iret` resumes here. No options: the handler writes
    // memory, and the compiler must not assume otherwise.
    unsafe { core::arch::asm!("int3") };
    let after = exception::BREAKPOINTS.load(Ordering::Relaxed);

    c.write_str("\n             #BP  ");
    let ok = after == before.wrapping_add(1);
    if ok {
        c.write_str("taken and resumed");
    } else {
        c.write_str("NOT taken (counter ");
        write_dec(c, before);
        c.write_str(" -> ");
        write_dec(c, after);
        c.write_str(")");
    }
    ok
}

/// Start the PIT, unmask IRQ 0, enable interrupts, and wait for several ticks.
///
/// Several and not one on purpose. A single tick proves only that the controller
/// delivered once; the second one cannot arrive unless the first was acknowledged, so
/// waiting for more than one is what actually tests the end-of-interrupt path. Miss
/// the EOI and this hangs to the spin limit and reports one tick, which is exactly the
/// diagnosis you want.
///
/// Leaves the line masked and interrupts disabled again on the way out, so the caller
/// gets the machine back in the state it lent us.
fn check_timer(c: &dyn EarlyConsole) -> bool {
    // SAFETY: nothing else in this kernel programs the PIT, and interrupts are masked
    // here, so the command byte and the two halves of the divisor cannot be separated
    // by another access to channel 0.
    let divisor = unsafe { pit::start_periodic(TEST_HZ) };
    let before = TICKS.load(Ordering::Relaxed);

    CHIP.enable(TIMER_IRQ);

    // SAFETY: the IDT is loaded, every vector the PIC can deliver has a handler, and
    // the only unmasked line is the timer, whose handler acknowledges it. This is the
    // first point in the kernel's life at which taking an interrupt is defined.
    unsafe { core::arch::asm!("sti", options(nomem, nostack, preserves_flags)) };

    // Saturating, not wrapping: at 1 kHz the counter needs half a billion years to
    // reach u64::MAX, but a comparison that silently inverts is not worth the risk.
    let wanted = before.saturating_add(REQUIRED_TICKS);
    let mut spins: u64 = 0;
    while TICKS.load(Ordering::Relaxed) < wanted && spins < SPIN_LIMIT {
        spins += 1;
        core::hint::spin_loop();
    }

    // SAFETY: masking interrupts is always sound; it only defers delivery.
    unsafe { core::arch::asm!("cli", options(nomem, nostack, preserves_flags)) };
    CHIP.disable(TIMER_IRQ);

    let ticks = TICKS.load(Ordering::Relaxed).saturating_sub(before);

    c.write_str("\n             IRQ0 ");
    if ticks < REQUIRED_TICKS {
        write_dec64(c, ticks);
        c.write_str(" of ");
        write_dec64(c, REQUIRED_TICKS);
        c.write_str(" ticks after ");
        write_dec64(c, spins);
        c.write_str(" spins");
        return false;
    }
    write_dec64(c, ticks);
    c.write_str(" ticks at ");
    write_dec(c, TEST_HZ);
    c.write_str(" Hz (vector ");
    write_hex(c, u32::from(pic::VECTOR_BASE), 2);
    c.write_str(", divisor ");
    write_dec(c, u32::from(divisor));
    c.write_str(", ");
    write_dec64(c, spins);
    c.write_str(" spins)");
    true
}

/// Write a 64-bit count in decimal.
///
/// Separate from `serial::write_dec`, which takes the machine's native width: the
/// tick and spin counters are the only 64-bit quantities this port prints, and paying
/// for 64-bit division on every hex digit elsewhere to avoid one function would be the
/// wrong trade on a 32-bit target.
fn write_dec64(c: &dyn EarlyConsole, mut v: u64) {
    if v == 0 {
        c.write_bytes(b"0");
        return;
    }
    let mut buf = [0u8; 20];
    let mut i = buf.len();
    while v > 0 {
        i -= 1;
        buf[i] = b'0' + (v % 10) as u8;
        v /= 10;
    }
    c.write_bytes(&buf[i..]);
}

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
//! the lock types and the per-CPU data they need do not exist yet, so the rule for
//! Phase 0 is that the interrupt path allocates nothing, locks nothing, and calls
//! nothing that can fault.
//!
//! ## What the selftest proves
//!
//! Two separate mechanisms, checked separately, neither inferred from the other:
//! a synchronous exception (`int3`, chosen because #BP is resumable and so the
//! handler returning is itself observable) and a hardware interrupt (the PIT on
//! IRQ 0). Each reports a counter the handler incremented. If the counter did not
//! move, the selftest fails — it never concludes success from the absence of a crash.
//!
//! A third line reports the #DF stack, and is deliberately weaker: it reads the task
//! register and the TSS back out of the hardware, which catches a TSS that was built
//! and never loaded, but it cannot *demonstrate* the stack switch because doing so
//! means double-faulting and a double fault does not return. That demonstration was
//! done once, by hand, against a throwaway build; `gdt.rs` records what it showed and
//! what it did not.

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use hal::{Arch, EarlyConsole, IrqChip, IrqNumber};

use crate::serial::{write_dec, write_hex};
use crate::{X86_64, exception, gdt, idt, pic, pit};

/// Install plain (no error code) handlers for a list of vectors.
///
/// The compile-time assertion is the point: a handler whose signature disagrees with
/// what the CPU pushes reads the frame eight bytes off and `iret`s to nowhere, and
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
pub static TICKS: AtomicU64 = AtomicU64::new(0);

/// Set once [`init`] has run, so a second call cannot re-enter the ICW sequence.
static READY: AtomicBool = AtomicBool::new(false);

/// The line the PIT is wired to. Fixed by the PC architecture, not discovered.
const TIMER_IRQ: IrqNumber = IrqNumber(0);

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

    // The TSS first, because a gate is about to name one of its stacks. Order matters
    // only in one direction — a gate with an IST index is harmless until the vector is
    // delivered — but the CPU must have the task register loaded before anything can
    // double-fault, and "before the IDT exists" is the earliest such point.
    // SAFETY: `gdt::init` wants to run once, with interrupts masked, before any gate
    // naming an IST index can be delivered. The `READY` flag above makes it once, the
    // caller's contract makes it masked, and no vector can be delivered at all until
    // `idt::load` below.
    unsafe { gdt::init() };

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
        // #DF is the one gate that does not run on the stack it was raised from: the
        // stack is the thing most likely to have caused it. `gdt::init` has already
        // filled that slot and loaded the task register.
        idt::set_gate_on_ist(
            8,
            idt::EntryPoint::with_code(exception::double_fault),
            gdt::DF_IST_INDEX,
        );
        idt::set_gate(13, idt::EntryPoint::with_code(exception::general_protection));
        // #PF is the one vector whose handler may return: it re-executes the faulting
        // instruction after resolving the fault, and falls through to the fatal
        // reporter when it cannot. See `exception::page_fault`.
        idt::set_gate(14, idt::EntryPoint::resumable_with_code(exception::page_fault));

        // The rest of the architecturally defined range, so that an unexpected one
        // reports itself instead of escalating to a triple fault.
        reserved_gates!(1, 2, 4, 5, 7, 9, 15, 16, 18, 19, 20, 22, 23, 24, 25, 26, 27, 28, 31);
        reserved_gates_with_code!(10, 11, 12, 17, 21, 29, 30);

        // The sixteen PIC lines.
        irq_gates!(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);

        // Everything above the PIC's range. Nothing raises these today; a delivery
        // means something we do not model, and it says so rather than vanishing.
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
    let _masked = X86_64::irq_save();

    init();

    c.write_str("IDT 256 gates, ");
    c.write_str(CHIP.name());
    c.write_str(" on vectors ");
    write_dec(c, u64::from(pic::VECTOR_BASE));
    c.write_str("..");
    write_dec(c, u64::from(pic::VECTOR_BASE) + u64::from(pic::LINES));

    let bp_ok = check_breakpoint(c);
    let irq_ok = check_timer(c);
    let df_ok = report_df_stack(c);

    bp_ok && irq_ok && df_ok
}

/// Report that #DF has a stack of its own, reading the state back from the hardware.
///
/// Not a test — the only way to test it is to double-fault, and that is fatal by
/// architecture — but not an assertion either. The task register is read with `str`
/// and the stack pointer out of the TSS, so what is printed is what the CPU will
/// actually do on delivery rather than what this code asked for. The failure this
/// catches is the realistic one: a TSS built but never loaded, which looks identical
/// to a working setup right up until the double fault.
fn report_df_stack(c: &dyn EarlyConsole) -> bool {
    let tr = gdt::task_register();
    let top = gdt::df_stack_top();
    let ok = tr == gdt::TSS_SELECTOR && top != 0;

    c.write_str("\n             #DF  ");
    if !ok {
        c.write_str("NO dedicated stack (tr ");
        write_hex(c, u64::from(tr), 4);
        c.write_str(")");
        return false;
    }
    c.write_str("on IST");
    write_dec(c, u64::from(gdt::DF_IST_INDEX));
    c.write_str(", stack top ");
    write_hex(c, top, 16);
    c.write_str(" (tr ");
    write_hex(c, u64::from(tr), 4);
    c.write_str(")");
    true
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
        write_dec(c, u64::from(before));
        c.write_str(" -> ");
        write_dec(c, u64::from(after));
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
        write_dec(c, ticks);
        c.write_str(" of ");
        write_dec(c, REQUIRED_TICKS);
        c.write_str(" ticks after ");
        write_dec(c, spins);
        c.write_str(" spins");
        return false;
    }
    write_dec(c, ticks);
    c.write_str(" ticks at ");
    write_dec(c, u64::from(TEST_HZ));
    c.write_str(" Hz (vector ");
    write_hex(c, u64::from(pic::VECTOR_BASE), 2);
    c.write_str(", divisor ");
    write_dec(c, u64::from(divisor));
    c.write_str(", ");
    write_dec(c, spins);
    c.write_str(" spins)");
    true
}

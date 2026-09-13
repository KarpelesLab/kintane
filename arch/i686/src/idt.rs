//! The Interrupt Descriptor Table, in the 32-bit gate format.
//!
//! Model: one table, 256 gates, built once during early initialisation and never
//! modified afterwards. Every gate is an *interrupt* gate rather than a trap gate, so
//! the CPU clears IF on entry and a handler always runs with interrupts masked; that
//! is what lets handlers touch state the rest of the kernel touches without a lock, on
//! the uniprocessor Phase 0 build.
//!
//! Until this table is loaded the machine still has whatever the loader left in IDTR.
//! On this target that is worse than the x86-64 case: a BIOS-booted i686 still has the
//! real-mode interrupt vector table described by a protected-mode IDTR, so a fault is
//! not even a not-present gate — it is a gate built out of whatever bytes happen to
//! live at physical zero, and the resulting chain (#UD -> #GP -> #DF -> reset) is the
//! one recorded in `docs/targets.md#i686`. Loading a real table is the precondition
//! for every later bug on this port being debuggable at all.
//!
//! ## How this differs from `arch/x86_64/src/idt.rs`
//!
//! The two files describe the same idea and not the same hardware structure:
//!
//! * A gate is **8 bytes, not 16**. There is no IST field and no upper 32 bits of offset; the byte
//!   that x86-64 spends on IST is a must-be-zero byte here.
//! * The type nibble means a *32-bit* interrupt gate (`0xE` with the D bit set), and the 16-bit
//!   gate types (`0x6`/`0x7`) exist alongside it. `0x8E` happens to be the right flags byte on both
//!   targets for different reasons, which is exactly the kind of coincidence worth writing down
//!   rather than relying on silently.
//! * The `lidt` operand carries a 32-bit base, so the pseudo-descriptor is six bytes rather than
//!   ten.
//!
//! Reference: Intel SDM Vol. 3A, §6.11 (IDT descriptors) and figure 6-2 (32-bit gate
//! format).
//!
//! Not done here: no gate uses a task gate. The 32-bit architecture offers one — a
//! #DF task gate is the classic way to survive a stack overflow on i386, because the
//! task switch loads a whole new ESP from a TSS — but it needs a TSS, a GDT this port
//! owns at runtime, and hardware task switching that no other target has. The x86-64
//! equivalent (an IST stack) is the shape the kernel wants long term, so #DF on i686
//! stays on the faulting stack until per-CPU data exists and both ports can be done
//! the same way. The consequence is stated plainly: a stack overflow on i686 still
//! triple-faults.

use core::cell::UnsafeCell;
use core::mem::size_of;

/// The stack frame the CPU pushes before entering a handler.
///
/// Laid out exactly as the hardware pushes it (SDM Vol. 3A, figure 6-4, no privilege
/// change). The kernel runs only at ring 0 today, so an interrupt never switches
/// stacks and the CPU therefore pushes **no SS:ESP pair** — the three fields below are
/// the whole frame. A ring-3 entry would push two more words after `eflags`, and when
/// userspace arrives this type grows a second form rather than gaining two fields that
/// are sometimes absent.
///
/// `extern "x86-interrupt"` handlers take this by value; the ABI passes a pointer to
/// the real frame rather than copying it, which is why changing a field here would
/// change where execution resumes.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct InterruptFrame {
    /// Address of the faulting instruction, or of the one after it for traps.
    pub eip: u32,
    /// Code segment selector at the point of the interrupt.
    pub cs: u32,
    /// EFLAGS at the point of the interrupt.
    pub eflags: u32,
}

/// An entry point for a vector that pushes no error code and may return.
pub type Handler = extern "x86-interrupt" fn(InterruptFrame);
/// An entry point for a vector that pushes no error code and does not return.
pub type DivergingHandler = extern "x86-interrupt" fn(InterruptFrame) -> !;
/// An entry point for a vector that pushes an error code and does not return.
///
/// The code is 32 bits here and 64 on x86-64: the CPU pushes one stack word, and a
/// stack word is the pointer width.
pub type HandlerWithCode = extern "x86-interrupt" fn(InterruptFrame, u32) -> !;
/// An entry point for a vector that pushes an error code and may return: #PF, when the
/// kernel resolves the fault. The `x86-interrupt` ABI discards the code before `iret`.
pub type ResumableHandlerWithCode = extern "x86-interrupt" fn(InterruptFrame, u32);

/// The address of an interrupt entry point, with its ABI shape already checked.
///
/// The constructor names are the whole point: an entry point can only reach
/// [`set_gate`] through one of these, and each takes a specific function-pointer
/// type, so a handler whose signature does not match what its vector pushes is a
/// compile error rather than a wild `iret`.
#[derive(Clone, Copy)]
pub struct EntryPoint(usize);

impl EntryPoint {
    /// A handler for a vector with no error code, which returns to the interrupted
    /// code.
    pub fn plain(f: Handler) -> EntryPoint {
        EntryPoint(f as usize)
    }

    /// A handler for a vector with no error code, which never returns.
    pub fn diverging(f: DivergingHandler) -> EntryPoint {
        EntryPoint(f as usize)
    }

    /// A handler for a vector that pushes an error code.
    pub fn with_code(f: HandlerWithCode) -> EntryPoint {
        EntryPoint(f as usize)
    }

    /// A handler for a vector that pushes an error code, which may return.
    pub fn with_code_resumable(f: ResumableHandlerWithCode) -> EntryPoint {
        EntryPoint(f as usize)
    }
}

/// A 32-bit IDT gate descriptor. Eight bytes, half the size of the long-mode one.
#[derive(Clone, Copy)]
#[repr(C)]
struct Gate {
    offset_low: u16,
    selector: u16,
    /// Reserved, must be zero. This is the byte long mode repurposed as the IST index.
    zero: u8,
    /// Present, DPL, and gate type.
    flags: u8,
    offset_high: u16,
}

/// Present (bit 7), DPL 0 (bits 5..7), S = 0, 32-bit interrupt gate (type `0b1110`).
///
/// Bit 3 of the type is the D bit: clear selects the 16-bit gate the 286 had, which
/// would enter the handler in 16-bit mode and is a failure with no useful symptom.
///
/// DPL 0 means a user-mode `int $n` against these vectors raises #GP instead of
/// entering the handler. When userspace arrives, the vectors it is allowed to raise
/// deliberately (a breakpoint from a debugger, the syscall trap if we ever use one)
/// get DPL 3 individually; the default stays 0.
const PRESENT_DPL0_INTERRUPT32: u8 = 0x8E;

impl Gate {
    const EMPTY: Gate = Gate {
        offset_low: 0,
        selector: 0,
        zero: 0,
        flags: 0,
        offset_high: 0,
    };

    fn new(handler: usize, selector: u16) -> Gate {
        let addr = handler as u32;
        Gate {
            offset_low: (addr & 0xffff) as u16,
            selector,
            zero: 0,
            flags: PRESENT_DPL0_INTERRUPT32,
            offset_high: ((addr >> 16) & 0xffff) as u16,
        }
    }
}

/// The table itself. 8-byte aligned so no descriptor straddles a cache line.
#[repr(C, align(8))]
struct Idt([Gate; 256]);

/// The table as a static with interior mutability.
///
/// `static mut` is forbidden (`docs/coding-standards.md`), and the table must be
/// writable during initialisation yet live at a fixed address for as long as the CPU
/// is running, so it is an `UnsafeCell` behind a documented invariant.
struct IdtCell(UnsafeCell<Idt>);

// SAFETY: the invariant is single-writer-then-frozen. `set_gate` is the only writer,
// it is `unsafe` and documented to run once during early initialisation with
// interrupts masked and before `load`, so no handler can observe a half-written gate
// and no second CPU exists yet to race with. After `load` the table is read by the
// CPU only.
unsafe impl Sync for IdtCell {}

static IDT: IdtCell = IdtCell(UnsafeCell::new(Idt([Gate::EMPTY; 256])));

/// The operand of `lidt`: a 16-bit limit followed by a 32-bit base, unpadded.
#[repr(C, packed(2))]
struct Idtr {
    limit: u16,
    base: u32,
}

/// Install `handler` as the entry point for `vector`.
///
/// # Safety
/// `handler` must have been built with the [`EntryPoint`] constructor matching what
/// the CPU pushes for `vector`: it must take an error code if and only if the vector
/// delivers one, or the handler reads the frame four bytes off and `iret`s to a wrong
/// address. Must be called before [`load`], with interrupts masked, and from a single
/// thread of control.
pub unsafe fn set_gate(vector: u8, handler: EntryPoint) {
    // SAFETY: upholds the IdtCell invariant documented above — the caller guarantees
    // initialisation-time, interrupts-masked, single-writer use, so this `&mut` is
    // the only live reference to the table.
    let table = unsafe { &mut *IDT.0.get() };
    if let Some(slot) = table.0.get_mut(usize::from(vector)) {
        *slot = Gate::new(handler.0, code_segment());
    }
}

/// Load the table into the CPU's IDTR.
///
/// # Safety
/// Every vector the machine can deliver must already have a gate installed, or a
/// delivery lands on a not-present descriptor and becomes #GP — and if that happens
/// while handling a fault, a double fault. Call once, with interrupts masked.
pub unsafe fn load() {
    let idtr = Idtr {
        limit: (size_of::<Idt>() - 1) as u16,
        base: IDT.0.get() as u32,
    };
    // SAFETY: `lidt` reads six bytes from the operand address and copies them into
    // IDTR; `idtr` is a live, correctly shaped local for the duration of the
    // instruction, and the table it points at is a static that outlives everything.
    unsafe {
        core::arch::asm!("lidt [{}]", in(reg) &idtr, options(readonly, nostack, preserves_flags));
    }
}

/// The selector currently in CS.
///
/// Read from the CPU rather than hardcoded as 0x08 so that this keeps working if the
/// boot GDT in `boot.rs` is rearranged — a wrong selector here is a fault inside the
/// fault path, which is the least debuggable failure there is.
fn code_segment() -> u16 {
    let cs: u16;
    // SAFETY: reading a segment register has no side effects and no operands beyond
    // the destination.
    unsafe {
        core::arch::asm!("mov {0:x}, cs", out(reg) cs, options(nomem, nostack, preserves_flags));
    }
    cs
}

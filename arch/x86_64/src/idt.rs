//! The Interrupt Descriptor Table.
//!
//! Model: one table, 256 gates, built once during early initialisation and never
//! modified afterwards. Every gate is an *interrupt* gate rather than a trap gate, so
//! the CPU clears IF on entry and a handler always runs with interrupts masked; that
//! is what lets handlers touch state the rest of the kernel touches without a lock, on
//! the uniprocessor Phase 0 build.
//!
//! Until this table is loaded the CPU still has whatever descriptor register the
//! multiboot loader left, which for QEMU means a zero-limit IDT: any fault becomes a
//! triple fault and a silent machine reset with no diagnostic at all. Loading a table
//! is therefore not a feature so much as the precondition for every later bug being
//! debuggable.
//!
//! Reference: Intel SDM Vol. 3A, §6.11 (IDT descriptors) and §6.14.1 (64-bit mode
//! gate format).
//!
//! Not done here: no gate uses an IST stack, because IST slots live in a TSS and this
//! port has no GDT entry for one yet (see `boot.rs`, which builds a two-entry GDT).
//! The practical consequence is that #DF runs on the faulting stack, so a stack
//! overflow reports a double fault and then triple-faults while pushing the frame. A
//! TSS with a dedicated #DF stack belongs with the per-CPU work in Phase 2.

use core::cell::UnsafeCell;
use core::mem::size_of;

/// The stack frame the CPU pushes before entering a handler.
///
/// Laid out exactly as the hardware pushes it (SDM Vol. 3A, figure 6-8, 64-bit mode,
/// no stack switch). `extern "x86-interrupt"` handlers take this by value; the ABI
/// passes it as a pointer to the real frame rather than copying it, which is why
/// changing a field here would change where execution resumes.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct InterruptFrame {
    /// Address of the faulting instruction, or of the one after it for traps.
    pub rip: u64,
    /// Code segment selector at the point of the interrupt.
    pub cs: u64,
    /// RFLAGS at the point of the interrupt.
    pub rflags: u64,
    /// Stack pointer at the point of the interrupt.
    pub rsp: u64,
    /// Stack segment selector at the point of the interrupt.
    pub ss: u64,
}

/// An entry point for a vector that pushes no error code and may return.
pub type Handler = extern "x86-interrupt" fn(InterruptFrame);
/// An entry point for a vector that pushes no error code and does not return.
pub type DivergingHandler = extern "x86-interrupt" fn(InterruptFrame) -> !;
/// An entry point for a vector that pushes an error code and does not return.
pub type HandlerWithCode = extern "x86-interrupt" fn(InterruptFrame, u64) -> !;

/// The address of an interrupt entry point, with its ABI shape already checked.
///
/// The constructor names are the whole point: an entry point can only reach
/// [`set_gate`] through one of the three, and each takes a specific function-pointer
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
}

/// A 64-bit IDT gate descriptor.
#[derive(Clone, Copy)]
#[repr(C)]
struct Gate {
    offset_low: u16,
    selector: u16,
    /// Interrupt Stack Table index in bits 0..3, zero elsewhere. Always 0 here.
    ist: u8,
    /// Present, DPL, and gate type.
    flags: u8,
    offset_mid: u16,
    offset_high: u32,
    reserved: u32,
}

/// Present (bit 7), DPL 0 (bits 5..7), 64-bit interrupt gate (type 0xE).
///
/// DPL 0 means a user-mode `int $n` against these vectors raises #GP instead of
/// entering the handler. When userspace arrives, the vectors it is allowed to raise
/// deliberately (a breakpoint from a debugger, the syscall trap if we ever use one)
/// get DPL 3 individually; the default stays 0.
const PRESENT_DPL0_INTERRUPT: u8 = 0x8E;

impl Gate {
    const EMPTY: Gate = Gate {
        offset_low: 0,
        selector: 0,
        ist: 0,
        flags: 0,
        offset_mid: 0,
        offset_high: 0,
        reserved: 0,
    };

    fn new(handler: usize, selector: u16) -> Gate {
        let addr = handler as u64;
        Gate {
            offset_low: (addr & 0xffff) as u16,
            selector,
            ist: 0,
            flags: PRESENT_DPL0_INTERRUPT,
            offset_mid: ((addr >> 16) & 0xffff) as u16,
            offset_high: ((addr >> 32) & 0xffff_ffff) as u32,
            reserved: 0,
        }
    }
}

/// The table itself. 16-byte aligned so no descriptor straddles a cache line.
#[repr(C, align(16))]
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

/// The operand of `lidt`: a 16-bit limit followed by a 64-bit base, unpadded.
#[repr(C, packed(2))]
struct Idtr {
    limit: u16,
    base: u64,
}

/// Install `handler` as the entry point for `vector`.
///
/// # Safety
/// `handler` must have been built with the [`EntryPoint`] constructor matching what
/// the CPU pushes for `vector`: it must take an error code if and only if the vector
/// delivers one, or the handler reads the frame eight bytes off and `iret`s to a
/// wrong address. Must be called before [`load`], with interrupts masked, and from a
/// single thread of control.
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
        base: IDT.0.get() as u64,
    };
    // SAFETY: `lidt` reads ten bytes from the operand address and copies them into
    // IDTR; `idtr` is a live, correctly shaped local for the duration of the
    // instruction, and the table it points at is a static that outlives everything.
    unsafe {
        core::arch::asm!("lidt [{}]", in(reg) &idtr, options(readonly, nostack, preserves_flags));
    }
}

/// The selector currently in CS.
///
/// Read from the CPU rather than hardcoded as 0x08 so that this keeps working if the
/// boot GDT is rearranged — a wrong selector here is a fault inside the fault path,
/// which is the least debuggable failure there is.
fn code_segment() -> u16 {
    let cs: u16;
    // SAFETY: reading a segment register has no side effects and no operands beyond
    // the destination.
    unsafe {
        core::arch::asm!("mov {0:x}, cs", out(reg) cs, options(nomem, nostack, preserves_flags));
    }
    cs
}

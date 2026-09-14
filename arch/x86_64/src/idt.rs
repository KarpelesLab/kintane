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
//! One gate uses an interrupt stack table entry: #DF, through [`set_gate_on_ist`]. The
//! reasoning for that, and for the other vectors deliberately *not* given one, is in
//! `gdt.rs`, which owns the TSS the slots live in. Everything else runs on whatever
//! stack was current, which is what you want — an IST stack is a single stack, and a
//! vector that can nest on itself would overwrite its own frame.

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
/// [`set_gate`] through one of the four, and each takes a specific function-pointer
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

    /// An entry point written in assembly, which saves the interrupted general registers
    /// itself rather than letting the compiler choose where to keep them.
    ///
    /// The four constructors above buy their safety from the `x86-interrupt` ABI, which is
    /// also what makes them useless to a handler that must *read* the interrupted registers:
    /// the ABI saves them where only the compiler knows. A signal frame holds every register
    /// a thread had, so the vectors that can deliver one to user code — the scheduler's
    /// interrupts and the faults a program can raise — are entered this way instead. See
    /// `user::traps`, which writes them and owns the layout they push.
    ///
    /// # Safety
    /// `entry` must be an assembly entry point built for exactly this vector: it must pop an
    /// error code if and only if the vector pushes one, restore every register it saved, and
    /// leave the stack as the CPU left it before its `iretq`.
    pub unsafe fn raw(entry: unsafe extern "C" fn()) -> EntryPoint {
        EntryPoint(entry as usize)
    }
}

/// Every register a trap took from the code it interrupted, as [`trap_entry`] saves them.
///
/// `repr(C)` and the push order in that macro are one layout in two languages: the general
/// registers lowest, in the order the pushes leave them, then the vector and the error code
/// the entry made uniform, then the frame the CPU itself pushed.
///
/// The `x86-interrupt` handlers above cannot offer this. That ABI saves the interrupted
/// registers wherever the compiler likes, so a handler can read the return address and the
/// stack pointer but not `rbx` or `r12` — and a signal frame has to hold every one of them,
/// because the handler it runs is free to clobber the caller-saved registers the interrupted
/// code was using. Vectors that can deliver a signal are therefore entered from assembly that
/// saves the lot.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct TrapFrame {
    pub rax: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rbx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rbp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    /// The vector, which the entry pushes because the CPU does not.
    pub vector: u64,
    /// The error code the CPU pushed, or zero where the vector pushes none.
    pub error: u64,
    pub rip: u64,
    pub cs: u64,
    pub rflags: u64,
    pub rsp: u64,
    pub ss: u64,
}

impl TrapFrame {
    /// The frame the CPU pushed, for the reporting paths that take one.
    pub fn interrupt_frame(&self) -> InterruptFrame {
        InterruptFrame {
            rip: self.rip,
            cs: self.cs,
            rflags: self.rflags,
            rsp: self.rsp,
            ss: self.ss,
        }
    }
}

/// Define an assembly entry point for `vector` that saves every register into a [`TrapFrame`]
/// and calls `handler` with it.
///
/// `$error` says whether the CPU pushes an error code for this vector: where it does not, the
/// entry pushes a zero in its place, so one frame layout serves every vector. The call is made
/// on a 16-byte-aligned stack, as the C ABI requires, with the frame's address in `rdi`; `r15`
/// keeps the real stack pointer across the call, which is sound because the frame already
/// holds the interrupted `r15` and the pops read it back from there.
macro_rules! trap_entry {
    // A vector the CPU pushes no error code for: the entry pushes a zero in its place, so one
    // frame layout serves every vector.
    ($name:ident, $vector:literal, $handler:path) => {
        $crate::idt::trap_entry!(@asm $name, $vector, $handler, "push 0");
    };
    // A vector that pushes one: it is already where the frame wants it.
    (with_code $name:ident, $vector:literal, $handler:path) => {
        $crate::idt::trap_entry!(@asm $name, $vector, $handler, "");
    };
    (@asm $name:ident, $vector:literal, $handler:path, $error:literal) => {
        core::arch::global_asm!(
            concat!(".section .text, \"ax\"\n.globl ", stringify!($name), "\n", stringify!($name), ":"),
            $error,
            concat!("push ", $vector),
            "push r15", "push r14", "push r13", "push r12", "push r11", "push r10",
            "push r9", "push r8", "push rbp", "push rdi", "push rsi", "push rbx",
            "push rdx", "push rcx", "push rax",
            "mov rdi, rsp",
            "mov r15, rsp",
            "and rsp, -16",
            "call {handler}",
            "mov rsp, r15",
            "pop rax", "pop rcx", "pop rdx", "pop rbx", "pop rsi", "pop rdi", "pop rbp",
            "pop r8", "pop r9", "pop r10", "pop r11", "pop r12", "pop r13", "pop r14",
            "pop r15",
            // The vector and the error code, which `iretq` does not pop.
            "add rsp, 16",
            "iretq",
            handler = sym $handler,
        );

        unsafe extern "C" {
            pub(crate) fn $name();
        }
    };
}

pub(crate) use trap_entry;

/// A 64-bit IDT gate descriptor.
#[derive(Clone, Copy)]
#[repr(C)]
struct Gate {
    offset_low: u16,
    selector: u16,
    /// Interrupt Stack Table index in bits 0..3, zero elsewhere.
    ///
    /// Zero is not slot zero: it means "do not switch stacks", and the seven usable
    /// slots are numbered 1..8. See `gdt.rs`.
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

    fn new(handler: usize, selector: u16, ist: u8) -> Gate {
        let addr = handler as u64;
        Gate {
            offset_low: (addr & 0xffff) as u16,
            selector,
            ist: ist & 0x7,
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
    // SAFETY: the caller's contract is exactly the one `set_gate_on_ist` asks for, and
    // IST index 0 is the encoding for "no stack switch" — the behaviour every vector
    // had before the TSS existed.
    unsafe { set_gate_on_ist(vector, handler, 0) }
}

/// Install `handler` for `vector`, entered on interrupt stack table slot `ist`.
///
/// `ist` is one-based: `0` means no stack switch, `1..=7` select a pointer from the
/// TSS that the CPU loads into RSP *before* pushing anything. That ordering is the
/// whole value of the mechanism — it is what lets a handler run when the reason it was
/// entered is that the current stack cannot be pushed to.
///
/// # Safety
/// Everything [`set_gate`] requires, plus: a non-zero `ist` must name a slot that
/// `gdt::init` has filled with the top of a real, currently unused stack, and the TSS
/// must already be loaded into the task register by the time this vector can be
/// delivered. A gate naming an empty slot loads RSP with zero and the next push is a
/// fault with nowhere to report it.
pub unsafe fn set_gate_on_ist(vector: u8, handler: EntryPoint, ist: u8) {
    // SAFETY: upholds the IdtCell invariant documented above — the caller guarantees
    // initialisation-time, interrupts-masked, single-writer use, so this `&mut` is
    // the only live reference to the table.
    let table = unsafe { &mut *IDT.0.get() };
    if let Some(slot) = table.0.get_mut(usize::from(vector)) {
        *slot = Gate::new(handler.0, code_segment(), ist);
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

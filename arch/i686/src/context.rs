//! Kernel thread context switching for 32-bit x86, and the proof that it works.
//!
//! Implements `hal::context`. Read that module first: a switch is an ordinary function
//! call that returns in a different thread, so only the registers the i386 System V ABI
//! makes **callee-saved** need to survive it — `ebx`, `esi`, `edi`, `ebp` and `esp`.
//! Everything else (`eax`, `ecx`, `edx`, EFLAGS' status bits, every XMM register and the
//! x87 stack) the caller already assumed was destroyed when it made the call.
//!
//! ## The saved state lives on the suspended thread's own stack
//!
//! [`Context`] is one word: the stack pointer. [`context_switch`] pushes the four
//! callee-saved general registers onto the running thread's stack, stores `esp` in
//! `from`, loads `esp` from `to`, pops the four, and `ret`s — to the instruction after
//! whatever `call` suspended *that* thread. Nothing about the switch knows which of the
//! two threads is new: [`init`](hal::HasContextSwitch::init) fabricates exactly the
//! stack an earlier switch would have left behind, with the "return address" pointing
//! at [`thread_trampoline`] instead of into a caller.
//!
//! EFLAGS is not saved. `IF` is the scheduler's to manage (the contract has it mask
//! interrupts around the switch, so every thread is resumed with `IF` clear and
//! restores its own state on the way out of the scheduler), `DF` is clear at every
//! call boundary by the ABI, and the rest are status bits. The x87 control word and
//! the MXCSR control bits are callee-saved by the letter of the ABI and are *not*
//! saved here: no kernel code changes them, so every kernel thread holds the same
//! values. The first code that changes either one — user FPU state is the obvious
//! candidate — must bring `HasFpu::FpuState` with it.
//!
//! ## Stack alignment: what the compiler actually assumes
//!
//! The i386 System V ABI as GCC and Linux use it (psABI 1.1 onward) requires `esp` to
//! be a multiple of 16 at every `call`, so `esp + 4` is 16-aligned on entry. It is
//! tempting to assume rustc relies on that here. **It does not**, and this was checked
//! against the generated code rather than inferred:
//!
//! * LLVM takes its incoming-stack-alignment assumption from the target *triple*, not from the data
//!   layout. It assumes 16 bytes for Linux, Darwin, kFreeBSD and every 64-bit target, and the i386
//!   minimum of 4 bytes otherwise. `targets/i686-kintane.json` says `i686-unknown-none-elf`, so the
//!   kernel is compiled assuming only 4 — the `S128` in its data layout does not change that.
//! * Consequently every function in the image that wants a 16-aligned stack slot realigns in its
//!   own prologue: `push %ebp; mov %esp, %ebp; ...; and $-0x10, %esp`. In the built image, every
//!   function with an aligned SSE operand on a stack slot has that `and`, and none lacks it.
//! * The same LLVM IR compiled with the triple changed to `i686-unknown-linux-gnu` drops the `and`
//!   and writes `movdqa` to `(%esp)` straight after a `sub $0x2c, %esp` — which is correct *only*
//!   if `esp + 4` was 16-aligned on entry.
//!
//! So with today's target specification, a thread started on a stack that is only
//! 4-aligned would run correctly: LLVM's output fixes the alignment itself. That is
//! precisely why [`STACK_ALIGN`](hal::HasContextSwitch::STACK_ALIGN) is **16 and not
//! 4**. The weaker assumption is a property of one string in a JSON file; changing the
//! triple, or anything that sets LLVM's stack-alignment override, silently turns every
//! 4-aligned thread stack into a #GP on the first vector instruction, with no source
//! change anywhere in the kernel. Sixteen satisfies both compilers, satisfies
//! hand-written assembly that follows the psABI (as `boot.rs` does), and costs at most
//! twelve bytes per thread.
//!
//! It also dictates the shape of the selftest. A `movaps` into a Rust local cannot
//! detect a misaligned `init` on this target — the function's own prologue realigns
//! before the instruction runs — so the alignment probe is written in assembly, relying
//! on the psABI guarantee exactly as the Linux-triple code above does.
//!
//! ## What the selftest proves
//!
//! One `.bss` stack, one second thread, three round trips.
//!
//! * **Control flow and argument passing.** The thread counts every time it runs and records the
//!   argument `init` placed for it. The count must advance by exactly one per switch, which on
//!   rounds two and three means a context saved by a switch was resumed, not one built by `init`.
//! * **The callee-saved set.** Rounds one and two go through [`switch_with_sentinels`], which loads
//!   a distinct value into each of `ebx`, `esi`, `edi` and `ebp`, switches, and reports which ones
//!   came back different. On the other side, [`clobber_and_switch`] overwrites all four with
//!   different values before switching back. A register the switch fails to preserve therefore
//!   comes back holding the *other* thread's value and is named. Both harnesses are assembly
//!   because a Rust caller would save and restore these registers in its own prologue whenever it
//!   used them, and could mask exactly the bug under test. Round three goes through the trait's
//!   `I686::switch`, so the path the scheduler will use is exercised too — and is skipped if a
//!   register was lost, because resuming compiled Rust across such a switch crashes it before it
//!   can say why.
//! * **Alignment.** The thread's entry point, [`thread_entry`], records `esp` and then writes to a
//!   stack slot with `movaps`, which raises #GP unless `esp + 4` was 16-aligned on entry. A
//!   misaligned `init` is reported by the IDT as a #GP inside `thread_entry`; the recorded `esp` is
//!   checked afterwards against the exact address `init` should have produced.
//!
//! Every check was falsified before being believed. Dropping the restore of each of the
//! four registers from [`context_switch`] in turn is caught by the register test, which
//! names exactly that register. Moving `init`'s frame down by four bytes faults on the
//! probe's `movaps`. With the probe removed and a `movaps` into a 16-aligned Rust local
//! put in `thread_main` instead, the same misalignment runs without a fault — LLVM
//! realigned in the prologue — and only the recorded-`esp` check catches it, which is
//! the measurement above observed at run time.

use core::cell::UnsafeCell;
use core::mem::{offset_of, size_of};
use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

use hal::{Arch, EarlyConsole, HasContextSwitch, KernAddr, ThreadEntry};

use crate::I686;
use crate::serial::{EARLY, write_dec, write_hex};

/// The saved state of a suspended kernel thread: its stack pointer.
///
/// Everything else the switch preserves is on the stack this points at, in the order
/// [`context_switch`] pushes it. A `Default` context is a null stack pointer, which is
/// what the running thread saves into on its first switch away and which must never be
/// switched *to*.
#[derive(Default)]
#[repr(C)]
pub struct Context {
    /// `esp` at the moment of the switch, with `ebp`, `ebx`, `esi` and `edi` pushed
    /// beneath the return address in that order.
    esp: usize,
}

impl Context {
    /// An empty context, usable in a `static` initialiser where `Default` is not const.
    const EMPTY: Context = Context { esp: 0 };
}

// The assembly below addresses the one field as `(%eax)`; this is what makes that true.
const _: () = assert!(offset_of!(Context, esp) == 0 && size_of::<Context>() == 4);

/// The stack `init` fabricates for a new thread, lowest address first.
///
/// The first five words are exactly what [`context_switch`] leaves on a suspended
/// thread's stack — the four registers in pop order, then the return address — so the
/// switch cannot tell a new thread from a resumed one. The last two belong to
/// [`thread_trampoline`]. The pop order in `context_switch` and this layout must agree,
/// which is why both live in this file.
///
/// `entry` travels on the stack rather than in a callee-saved register on purpose: a
/// new thread then depends on the switch restoring only `esp` and the return address,
/// so a switch that loses a register still starts the thread, and the selftest can
/// name the lost register instead of jumping through it.
#[repr(C)]
struct InitialFrame {
    edi: usize,
    esi: usize,
    ebx: usize,
    /// Zero, so a frame-pointer walk from the new thread terminates here.
    ebp: usize,
    /// Where `context_switch`'s `ret` lands.
    eip: usize,
    /// Popped by the trampoline and called.
    entry: usize,
    /// `entry`'s argument, in the slot a cdecl caller would have pushed it to.
    arg: usize,
}

/// Bytes `init` uses below the aligned stack top.
///
/// Seven words plus the twelve bytes of padding above them that put the argument slot
/// on a 16-byte boundary: at the trampoline's `call`, `esp` points at the argument, and
/// the ABI wants that address to be a multiple of 16.
const INIT_FRAME: usize = size_of::<InitialFrame>() + 12;

// The argument slot is exactly 16 bytes below the aligned top. If a field is ever added
// the padding has to be recomputed, and this is what says so.
const _: () = assert!(INIT_FRAME - offset_of!(InitialFrame, arg) == 16);

impl HasContextSwitch for I686 {
    type Context = Context;

    // The frame itself, plus the up-to-fifteen bytes `aligned_stack_top` may round away.
    const MIN_STACK: usize = INIT_FRAME + (16 - 1);

    // Sixteen, not the four the compiler assumes for this triple — see the module
    // comment for the measurement and for why the stronger value is the right one.
    const STACK_ALIGN: usize = 16;

    unsafe fn init(ctx: &mut Context, stack_top: KernAddr, entry: ThreadEntry, arg: usize) {
        let top = hal::context::aligned_stack_top::<I686>(stack_top).raw();
        let esp = top - INIT_FRAME;
        let frame = InitialFrame {
            edi: 0,
            esi: 0,
            ebx: 0,
            ebp: 0,
            eip: thread_trampoline as *const () as usize,
            entry: entry as usize,
            arg,
        };
        // SAFETY: the caller guarantees `stack_top` is the top of at least `MIN_STACK`
        // mapped, writable bytes owned by this thread. `MIN_STACK` covers the alignment
        // rounding plus `INIT_FRAME`, so `esp .. esp + size_of::<InitialFrame>()` lies
        // inside the region and cannot underflow it. The region is word-aligned because
        // `top` is 16-aligned and `INIT_FRAME` is a multiple of four.
        unsafe { KernAddr::new(esp).as_ptr::<InitialFrame>().write(frame) };
        ctx.esp = esp;
    }

    unsafe fn switch(from: *mut Context, to: *const Context) {
        // SAFETY: forwarded verbatim; `context_switch` has exactly this method's
        // contract, and being an `extern "C"` call, the compiler already treats every
        // caller-saved register as clobbered across it.
        unsafe { context_switch(from, to) }
    }
}

/// The switch itself: save the callee-saved registers on this stack, swap stacks,
/// restore them from the other one, and return into the other thread.
///
/// `from` is written only after the pushes, and `to` is read only after `from` is
/// written, so the saved stack pointer always describes a complete frame.
///
/// # Safety
/// As `HasContextSwitch::switch`: interrupts masked, `from` writable and distinct from
/// `to`, `to` holding a context from `init` or an earlier switch whose stack is valid
/// and not running anywhere.
#[unsafe(naked)]
unsafe extern "C" fn context_switch(from: *mut Context, to: *const Context) {
    core::arch::naked_asm!(
        // Order is load-bearing: `InitialFrame` describes these, lowest address first,
        // so it lists them in the reverse of the order they are pushed.
        "pushl %ebp",
        "pushl %ebx",
        "pushl %esi",
        "pushl %edi",
        // Arguments are above the four pushes and the return address.
        "movl 20(%esp), %eax", // from
        "movl 24(%esp), %ecx", // to
        "movl %esp, (%eax)",
        "movl (%ecx), %esp",
        "popl %edi",
        "popl %esi",
        "popl %ebx",
        "popl %ebp",
        "ret",
        options(att_syntax)
    );
}

/// The first code a new thread runs: call `entry(arg)` exactly as a caller would.
///
/// `context_switch` returns here with `esp` pointing at the `entry` word of the
/// [`InitialFrame`]. Popping it leaves `esp` on the argument slot, which is 16-aligned;
/// the `call` pushes the return address, so `entry` starts with `esp + 4` aligned and
/// its argument at `4(%esp)` — indistinguishable from being called by compiled code.
/// `ebp` is zero.
///
/// `entry` is `-> !`, so returning is a bug; the return lands on a report rather than
/// on whatever was above the fabricated frame. The stack is still aligned at that
/// second call, because `entry`'s `ret` pops back to the argument slot.
#[unsafe(naked)]
extern "C" fn thread_trampoline() -> ! {
    core::arch::naked_asm!(
        "popl %eax",
        "call *%eax",
        "call {returned}",
        "ud2",
        returned = sym thread_returned,
        options(att_syntax)
    );
}

/// Reached only if a thread's entry point returned, which its type says it cannot.
extern "C" fn thread_returned() -> ! {
    let c: &dyn EarlyConsole = &EARLY;
    c.write_str("\n\n*** kernel thread entry point returned; there is nothing to return to\n");
    c.write_str("\nhalted.\n");
    I686::halt()
}

// ---------------------------------------------------------------------------------------
// Selftest
// ---------------------------------------------------------------------------------------

/// Size of the second thread's stack. Generous for what the thread does, which is to
/// count and switch back; it is `.bss`, so the size costs nothing in the image.
const THREAD_STACK_SIZE: usize = 16 * 1024;

/// Round trips through [`switch_with_sentinels`]. More than one, so that a context
/// saved by a switch is resumed — the first trip resumes only the frame `init` built.
const SENTINEL_ROUNDS: u32 = 2;

/// Round trips in total: the sentinel rounds, then one through `I686::switch`.
const ROUNDS: u32 = SENTINEL_ROUNDS + 1;

/// The argument handed to the second thread. Arbitrary and recognisable.
const THREAD_ARG: usize = 0x7EAD_A126;

/// Values the boot thread holds across its switch in [`switch_with_sentinels`].
const SENTINEL_EBX: u32 = 0xB0B0_0EBC;
const SENTINEL_ESI: u32 = 0x5151_0E51;
const SENTINEL_EDI: u32 = 0xD1D1_0ED1;
const SENTINEL_EBP: u32 = 0xB9B9_0EB9;

/// Values the second thread loads into the same registers before switching back.
/// Distinct from the sentinels and from each other, so a lost register is attributable.
const CLOBBER_EBX: u32 = 0xDEAD_0B1C;
const CLOBBER_ESI: u32 = 0xDEAD_051C;
const CLOBBER_EDI: u32 = 0xDEAD_0D1C;
const CLOBBER_EBP: u32 = 0xDEAD_0B9C;

/// The register names, in the bit order [`switch_with_sentinels`] reports them.
const REGISTER_NAMES: [&str; 4] = ["ebx", "esi", "edi", "ebp"];

/// The second thread's stack.
///
/// 16-byte aligned so its top is already on a boundary and `init` rounds nothing away
/// — which keeps the exact `esp` the selftest expects a simple expression.
#[repr(C, align(16))]
struct ThreadStack(UnsafeCell<[u8; THREAD_STACK_SIZE]>);

// SAFETY: the stack is touched only by the second thread and by `init`, and the
// selftest runs once, on one CPU, with interrupts masked — nothing can observe it
// concurrently.
unsafe impl Sync for ThreadStack {}

static THREAD_STACK: ThreadStack = ThreadStack(UnsafeCell::new([0; THREAD_STACK_SIZE]));

/// A context in a static, for the two threads of the selftest.
struct ContextCell(UnsafeCell<Context>);

// SAFETY: each cell is written only by `init` or by `context_switch`, and the selftest
// runs once, on one CPU, with interrupts masked; at any instant exactly one of the two
// threads is running, so no two accesses to a cell can overlap.
unsafe impl Sync for ContextCell {}

static BOOT_CONTEXT: ContextCell = ContextCell(UnsafeCell::new(Context::EMPTY));
static THREAD_CONTEXT: ContextCell = ContextCell(UnsafeCell::new(Context::EMPTY));

/// Times the second thread has been resumed. Written only by that thread.
static THREAD_RUNS: AtomicU32 = AtomicU32::new(0);

/// The argument the second thread found on entry.
static THREAD_ARG_SEEN: AtomicUsize = AtomicUsize::new(0);

/// `esp` as the second thread's entry point saw it, before it touched the stack.
static THREAD_ENTRY_ESP: AtomicUsize = AtomicUsize::new(0);

/// The second thread's entry point: probe the alignment `init` produced, then run.
///
/// `movaps` to a memory operand raises #GP unless the address is a multiple of 16.
/// Subtracting twelve from an entry `esp` whose `esp + 4` is aligned lands on a
/// multiple of 16; any other entry alignment does not. This is the instruction LLVM
/// emits under a triple that trusts the psABI, and the probe is assembly precisely
/// because under *this* triple LLVM would realign first and the probe could not fail.
///
/// `esp` is recorded before the probe so that a misalignment is visible in two ways:
/// the #GP report here, and the address check in [`selftest`] should a future edit
/// weaken the probe.
///
/// The jump rather than a call hands `thread_main` this same frame: the return address
/// into the trampoline and the argument above it, untouched.
#[unsafe(naked)]
extern "C" fn thread_entry(arg: usize) -> ! {
    core::arch::naked_asm!(
        "movl %esp, {entry_esp}",
        "subl $12, %esp",
        "pcmpeqd %xmm0, %xmm0",
        "movaps %xmm0, (%esp)",
        "addl $12, %esp",
        "jmp {main}",
        entry_esp = sym THREAD_ENTRY_ESP,
        main = sym thread_main,
        options(att_syntax)
    );
}

/// The second thread's body: record, clobber, switch back, forever.
extern "C" fn thread_main(arg: usize) -> ! {
    THREAD_ARG_SEEN.store(arg, Ordering::Relaxed);
    loop {
        THREAD_RUNS.fetch_add(1, Ordering::Relaxed);
        // SAFETY: interrupts are masked for the whole selftest. `THREAD_CONTEXT` is
        // this thread's own cell and `BOOT_CONTEXT` holds the boot thread's context,
        // saved by the switch that resumed us; the boot stack is valid and not running.
        unsafe { clobber_and_switch(THREAD_CONTEXT.0.get(), BOOT_CONTEXT.0.get()) };
    }
}

/// Switch with known values in every callee-saved register, and report which changed.
///
/// Returns a bitmask in [`REGISTER_NAMES`] order: zero means all four came back. Calls
/// [`context_switch`] directly, not through a Rust wrapper, so no compiled prologue can
/// save one of the four on the switch's behalf.
///
/// # Safety
/// As [`context_switch`].
#[unsafe(naked)]
unsafe extern "C" fn switch_with_sentinels(from: *mut Context, to: *const Context) -> u32 {
    core::arch::naked_asm!(
        // Our own caller's registers, which we are about to overwrite.
        "pushl %ebp",
        "pushl %ebx",
        "pushl %esi",
        "pushl %edi",
        "movl 20(%esp), %eax",
        "movl 24(%esp), %ecx",
        "movl ${ebx}, %ebx",
        "movl ${esi}, %esi",
        "movl ${edi}, %edi",
        "movl ${ebp}, %ebp",
        "pushl %ecx",
        "pushl %eax",
        "call {switch}",
        "addl $8, %esp",
        "xorl %eax, %eax",
        "cmpl ${ebx}, %ebx",
        "je 2f",
        "orl $1, %eax",
        "2:",
        "cmpl ${esi}, %esi",
        "je 3f",
        "orl $2, %eax",
        "3:",
        "cmpl ${edi}, %edi",
        "je 4f",
        "orl $4, %eax",
        "4:",
        "cmpl ${ebp}, %ebp",
        "je 5f",
        "orl $8, %eax",
        "5:",
        "popl %edi",
        "popl %esi",
        "popl %ebx",
        "popl %ebp",
        "ret",
        ebx = const SENTINEL_EBX,
        esi = const SENTINEL_ESI,
        edi = const SENTINEL_EDI,
        ebp = const SENTINEL_EBP,
        switch = sym context_switch,
        options(att_syntax)
    );
}

/// Overwrite every callee-saved register, then switch.
///
/// The other thread's registers must not be affected by what this thread held when it
/// was suspended. Restores its own on return, as any `extern "C"` function must.
///
/// # Safety
/// As [`context_switch`].
#[unsafe(naked)]
unsafe extern "C" fn clobber_and_switch(from: *mut Context, to: *const Context) {
    core::arch::naked_asm!(
        "pushl %ebp",
        "pushl %ebx",
        "pushl %esi",
        "pushl %edi",
        "movl 20(%esp), %eax",
        "movl 24(%esp), %ecx",
        "movl ${ebx}, %ebx",
        "movl ${esi}, %esi",
        "movl ${edi}, %edi",
        "movl ${ebp}, %ebp",
        "pushl %ecx",
        "pushl %eax",
        "call {switch}",
        "addl $8, %esp",
        "popl %edi",
        "popl %esi",
        "popl %ebx",
        "popl %ebp",
        "ret",
        ebx = const CLOBBER_EBX,
        esi = const CLOBBER_ESI,
        edi = const CLOBBER_EDI,
        ebp = const CLOBBER_EBP,
        switch = sym context_switch,
        options(att_syntax)
    );
}

/// Start a second thread on a `.bss` stack, switch to it and back [`ROUNDS`] times, and
/// report what was observed. See the module comment for what each check proves.
pub fn selftest(c: &dyn EarlyConsole) -> bool {
    // The contract: a switch happens with interrupts masked. Restored on the way out.
    let irq = I686::irq_save();

    let base = THREAD_STACK.0.get() as usize;
    let top = KernAddr::new(base + THREAD_STACK_SIZE);
    // SAFETY: `top` is the end of `THREAD_STACK`, a 16 KiB `.bss` region far larger than
    // `MIN_STACK`, mapped writable as part of the image's data range, and used by nothing
    // but the thread being created. The static lives forever.
    unsafe { I686::init(&mut *THREAD_CONTEXT.0.get(), top, thread_entry, THREAD_ARG) };

    // Rounds one and two through the sentinel harness: the first resumes the frame `init`
    // built, the second a context saved by a switch.
    let mut lost: u32 = 0;
    let mut runs_ok = true;
    let mut round = 1;
    while round <= SENTINEL_ROUNDS {
        let before = THREAD_RUNS.load(Ordering::Relaxed);
        // SAFETY: interrupts are masked above. `BOOT_CONTEXT` is this thread's own cell and
        // does not alias `THREAD_CONTEXT`, which was filled by `init` (round one) or by
        // the second thread's switch back to us, and whose stack is the static above and
        // is not running while we are.
        lost |= unsafe { switch_with_sentinels(BOOT_CONTEXT.0.get(), THREAD_CONTEXT.0.get()) };
        runs_ok &= THREAD_RUNS.load(Ordering::Relaxed) == before.wrapping_add(1);
        round += 1;
    }

    // The last round through the trait, which is the path the scheduler will take. Only
    // if nothing was lost: this caller is compiled Rust, which may hold its own state in
    // exactly the registers a broken switch fails to restore — with `ebp` gone it cannot
    // even find its arguments — so resuming it across such a switch would crash before
    // the loss could be reported.
    let mut trait_ran = false;
    if lost == 0 {
        let before = THREAD_RUNS.load(Ordering::Relaxed);
        // SAFETY: as for the rounds above; the thread's context was saved by its last
        // switch back to us.
        unsafe { I686::switch(BOOT_CONTEXT.0.get(), THREAD_CONTEXT.0.get()) };
        runs_ok &= THREAD_RUNS.load(Ordering::Relaxed) == before.wrapping_add(1);
        trait_ran = true;
    }

    // SAFETY: pairs with the `irq_save` at the top of this function, on this CPU.
    unsafe { I686::irq_restore(irq) };

    let runs = THREAD_RUNS.load(Ordering::Relaxed);
    let arg = THREAD_ARG_SEEN.load(Ordering::Relaxed);
    let entry_esp = THREAD_ENTRY_ESP.load(Ordering::Relaxed);
    // Where a real caller at an aligned call site would have left `esp` on entry: the
    // argument slot 16 below the top, and the return address below that.
    let expected_esp = hal::context::aligned_stack_top::<I686>(top).raw() - 16 - 4;

    let flow_ok = runs_ok && trait_ran && runs == ROUNDS && arg == THREAD_ARG;
    let regs_ok = lost == 0;
    let align_ok = entry_esp == expected_esp && (entry_esp + 4) % I686::STACK_ALIGN == 0;

    c.write_str("2 threads, ");
    write_dec(c, runs);
    c.write_str(" of ");
    write_dec(c, ROUNDS);
    c.write_str(" round trips");
    if arg != THREAD_ARG {
        c.write_str(", arg ");
        write_hex(c, arg as u32, 8);
        c.write_str(" != ");
        write_hex(c, THREAD_ARG as u32, 8);
    }
    if !runs_ok {
        c.write_str(" (a switch did not run the thread exactly once)");
    }
    if !trait_ran {
        c.write_str(" (trait round skipped: registers lost)");
    }

    c.write_str("\n             regs ");
    if regs_ok {
        c.write_str("ebx esi edi ebp preserved");
    } else {
        c.write_str("LOST");
        for (bit, name) in REGISTER_NAMES.iter().enumerate() {
            if lost & (1 << bit) != 0 {
                c.write_str(" ");
                c.write_str(name);
            }
        }
    }

    c.write_str("\n             esp  ");
    write_hex(c, entry_esp as u32, 8);
    c.write_str(" at entry");
    if align_ok {
        c.write_str(", +4 16-aligned, movaps ok");
    } else {
        c.write_str(", expected ");
        write_hex(c, expected_esp as u32, 8);
    }

    flow_ok && regs_ok && align_ok
}

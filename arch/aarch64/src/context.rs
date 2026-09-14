//! The context switch: [`hal::HasContextSwitch`] for AArch64, and the selftest that
//! proves it.
//!
//! # What is saved
//!
//! A switch is a function call (see `hal::context`), so only what AAPCS64 makes
//! callee-saved has to survive it: x19–x28, the frame pointer x29, the link register
//! x30 and the stack pointer. Thirteen words, in [`Context`], in that order.
//!
//! x18 is not among them. AAPCS64 calls it the platform register and leaves its role
//! to the platform; this kernel gives it none, and LLVM treats it as an ordinary
//! caller-saved temporary on `aarch64-unknown-none`, so nothing expects it to survive a
//! call. If it is ever given a role — a shadow call stack is the usual one — it becomes
//! per-thread state and joins the context.
//!
//! # d8–d15, and why they are not saved
//!
//! AAPCS64 also makes the low 64 bits of d8–d15 callee-saved. This port does not save
//! them, and that is correct for one reason only: **nothing in this image can use them.**
//!
//! `targets/aarch64-kintane.json` is `"abi": "softfloat"` with features
//! `+v8a,+strict-align,-neon`. Under the softfloat ABI rustc also takes `fp-armv8` away
//! from LLVM, so there is no FP or SIMD register the code generator is allowed to name —
//! not in the kernel, not in `core`, not in `compiler_builtins`. It is not merely that
//! the compiler chooses not to: the integrated assembler rejects `stp d8, d9, ...` in this
//! target outright with "instruction requires: fp-armv8", so even hand-written assembly
//! cannot touch them without an explicit `.arch_extension fp`. A register nothing can
//! write needs no saving.
//!
//! Linux makes the same choice for the same reason: arm64 `cpu_switch_to` saves x19–x29,
//! sp and lr and nothing else, because the kernel is built `-mgeneral-regs-only`, and the
//! few places that want NEON bracket it with `kernel_neon_begin`/`kernel_neon_end`.
//!
//! The assumption would stop being true silently — deleting `-neon` from the target
//! only produces a warning, and `+v8a` then turns NEON and FP back on — so it is
//! asserted at compile time below, on `target_feature = "neon"`, which is how rustc
//! reports both the removal of `-neon` and a move to a hard-float ABI. The day that
//! assertion fires, the fix is not to delete it: it is to add d8–d15 to [`Context`],
//! to the save and restore in `aarch64_context_switch`, and to the register test (load
//! a pattern into d8–d15 in `aarch64_switch_probe`, clobber them in
//! `aarch64_clobber_and_switch`, compare on return), all in the same change.
//!
//! Any assembly in this port that enables the FP extension locally must save and restore
//! d8–d15 itself. There is none today.
//!
//! # Starting a thread
//!
//! The switch restores callee-saved registers and returns through x30; it does not load
//! x0. So [`init`](hal::HasContextSwitch::init) builds a context whose x30 is
//! `aarch64_thread_trampoline`, with the entry point in x19 and its argument in x20 —
//! both callee-saved, so both are restored by the first switch like any other register.
//! The trampoline moves the argument into x0 and calls the entry point. `ThreadEntry`
//! diverges, so the instruction after that call is never reached by a correct thread;
//! it goes to [`aarch64_thread_returned`], which says so and stops the machine.
//!
//! # Interrupts
//!
//! DAIF is not part of the context. A switch runs with IRQs masked (the contract makes
//! that the caller's job), so a thread resumed by a switch resumes masked, and a new
//! thread starts masked; enabling interrupts is the entry point's decision.

use core::cell::UnsafeCell;
use core::mem::offset_of;
use core::sync::atomic::{AtomicU64, Ordering};

use hal::{Arch, EarlyConsole, HasContextSwitch, KernAddr, ThreadEntry};

use crate::Aarch64;
use crate::exception::{write_dec, write_hex};

// The d8–d15 decision above rests on this. If it fires, the vector registers have become
// reachable from compiled code and `Context` must grow to hold them; read the module doc.
const _: () = assert!(
    !cfg!(target_feature = "neon"),
    "NEON/FP is enabled for aarch64: d8-d15 are callee-saved and the context switch must \
     now save them (see arch/aarch64/src/context.rs)"
);

/// The callee-saved state of a suspended thread.
///
/// `repr(C)` because `aarch64_context_switch` addresses the fields by offset. The offsets
/// are asserted below, so a reordering is a compile error rather than a thread that
/// resumes with its registers shuffled.
#[repr(C)]
#[derive(Default)]
pub struct Context {
    x19: u64,
    x20: u64,
    x21: u64,
    x22: u64,
    x23: u64,
    x24: u64,
    x25: u64,
    x26: u64,
    x27: u64,
    x28: u64,
    /// x29.
    fp: u64,
    /// x30: where the switch returns to when this context is resumed.
    lr: u64,
    sp: u64,
    /// For a thread that runs user code: the kernel stack its traps land on, and the root
    /// of its address space. Both zero for a kernel-only thread, past the saved registers
    /// so the assembly offsets (which stop at `sp`, 0x60) are unchanged.
    pub(crate) user_kernel_stack: u64,
    pub(crate) user_root: u64,
}

impl Context {
    /// An empty context, usable in a `static` where `Default` is not.
    const fn empty() -> Self {
        Self {
            x19: 0,
            x20: 0,
            x21: 0,
            x22: 0,
            x23: 0,
            x24: 0,
            x25: 0,
            x26: 0,
            x27: 0,
            x28: 0,
            fp: 0,
            lr: 0,
            sp: 0,
            user_kernel_stack: 0,
            user_root: 0,
        }
    }
}

const _: () = {
    assert!(offset_of!(Context, x19) == 0x00);
    assert!(offset_of!(Context, x21) == 0x10);
    assert!(offset_of!(Context, x23) == 0x20);
    assert!(offset_of!(Context, x25) == 0x30);
    assert!(offset_of!(Context, x27) == 0x40);
    assert!(offset_of!(Context, fp) == 0x50);
    assert!(offset_of!(Context, lr) == 0x58);
    assert!(offset_of!(Context, sp) == 0x60);
};

/// Size of an AArch64 frame record: the saved x29 and x30 of the frame above.
const FRAME_RECORD: usize = 16;

core::arch::global_asm!(
    r#"
.section .text.context, "ax"

// aarch64_context_switch(from: *mut Context, to: *const Context)
//
// Save the callee-saved registers into `from`, load them from `to`, and return through
// the loaded x30. The offsets are `Context`'s, asserted in Rust. x9 is a caller-saved
// scratch register, which the caller has already given up by making a call; SP cannot be
// the operand of an stp/ldp transfer, hence the detour through it.
.globl aarch64_context_switch
aarch64_context_switch:
    stp     x19, x20, [x0, #0x00]
    stp     x21, x22, [x0, #0x10]
    stp     x23, x24, [x0, #0x20]
    stp     x25, x26, [x0, #0x30]
    stp     x27, x28, [x0, #0x40]
    stp     x29, x30, [x0, #0x50]
    mov     x9, sp
    str     x9, [x0, #0x60]

    ldp     x19, x20, [x1, #0x00]
    ldp     x21, x22, [x1, #0x10]
    ldp     x23, x24, [x1, #0x20]
    ldp     x25, x26, [x1, #0x30]
    ldp     x27, x28, [x1, #0x40]
    ldp     x29, x30, [x1, #0x50]
    ldr     x9, [x1, #0x60]
    mov     sp, x9
    ret

// The first code a new thread runs, arrived at by the `ret` above. `init` left the entry
// point in x19 and its argument in x20; x29 already points at the terminating frame
// record `init` wrote, so the entry point's own frame chains onto it.
.globl aarch64_thread_trampoline
aarch64_thread_trampoline:
    mov     x0, x20
    blr     x19
    // `ThreadEntry` diverges. Getting here is a bug in the thread; x19 is callee-saved,
    // so it still names the entry point that returned.
    mov     x0, x19
    b       aarch64_thread_returned
"#
);

unsafe extern "C" {
    fn aarch64_context_switch(from: *mut Context, to: *const Context);
    fn aarch64_thread_trampoline();
}

/// Where a thread lands if its entry point returns, which it must not.
///
/// Loud on purpose: the alternative is the trampoline falling through into whatever
/// follows it in `.text`.
#[unsafe(no_mangle)]
extern "C" fn aarch64_thread_returned(entry: u64) -> ! {
    let c = &crate::EARLY;
    c.write_str("\n\nkernel thread entry point returned: entry ");
    write_hex(c, entry);
    c.write_str("\n");
    Aarch64::halt()
}

impl HasContextSwitch for Aarch64 {
    type Context = Context;

    /// The alignment slack plus the one frame record `init` writes. That is the floor
    /// for starting a thread, not a size anything can usefully run in.
    const MIN_STACK: usize = 2 * FRAME_RECORD;

    /// AAPCS64 requires SP to be a multiple of 16 at all times, not only at calls, and
    /// the hardware enforces it on SP-relative access when SCTLR_EL1.SA is set.
    const STACK_ALIGN: usize = 16;

    unsafe fn init(ctx: &mut Context, stack_top: KernAddr, entry: ThreadEntry, arg: usize) {
        let top = hal::context::aligned_stack_top::<Self>(stack_top);
        // Cannot wrap: the caller guarantees at least MIN_STACK bytes below `stack_top`,
        // which covers the rounding and this record.
        let record = KernAddr::new(top.raw().wrapping_sub(FRAME_RECORD));
        // SAFETY: `record` lies inside the region the caller guarantees is mapped,
        // writable and owned by this thread, and is 16-aligned, which covers `[u64; 2]`.
        // A zero x29/x30 pair is the AAPCS64 end-of-chain marker, so an unwinder or a
        // debugger walking the new thread stops here.
        unsafe { record.as_ptr::<[u64; 2]>().write([0, 0]) };

        *ctx = Context {
            x19: entry as usize as u64,
            x20: arg as u64,
            fp: record.raw() as u64,
            lr: aarch64_thread_trampoline as *const () as usize as u64,
            sp: record.raw() as u64,
            ..Context::empty()
        };
    }

    #[inline]
    unsafe fn switch(from: *mut Context, to: *const Context) {
        // A thread that runs user code carries its own address space; a kernel thread
        // carries none and runs on the kernel's, so no kernel thread ever runs on tables a
        // process might free. On this port `SP_EL1` is the thread's own kernel stack, so
        // there is nothing else to install for a trap from EL0 to land on.
        // SAFETY: the caller's contract makes `to` a valid suspended context and the
        // switch masked, on the CPU `to` is about to run on; `user_root` is what `bind`
        // recorded, or zero.
        unsafe { crate::user::load_space((*to).user_root) };
        // SAFETY: the caller upholds the contract — interrupts masked, `from` writable
        // and distinct from `to`, `to` a suspended context with a live stack. The call
        // is an ordinary AAPCS64 call, so the compiler already treats every caller-saved
        // register as clobbered across it, which is what lets the switch save only the
        // callee-saved ones.
        unsafe { aarch64_context_switch(from, to) }
    }
}

// --- selftest ---------------------------------------------------------------------------

core::arch::global_asm!(
    r#"
.section .text.context_selftest, "ax"

// x<reg> = <src> + <reg>. Distinct per register, so a restore from a neighbour's slot
// shows up as a difference of one.
.macro PATTERN reg, src
    add     x\reg, \src, #\reg
.endm

// Set bit <reg> of x0 if x<reg> no longer holds x9 + <reg>.
.macro CHECK reg
    add     x10, x9, #\reg
    cmp     x\reg, x10
    cset    x11, ne
    lsl     x11, x11, #\reg
    orr     x0, x0, x11
.endm

// aarch64_switch_probe(from, to, base) -> u64
//
// Load x19–x29 with a pattern derived from `base`, switch away, and on return report
// which of them did not come back as a bitmask (bit n set = xn lost). A well-behaved
// function to its Rust caller: its own callee-saved registers are kept on its stack and
// put back. `base` goes on the stack too, since x2 does not survive the call.
.globl aarch64_switch_probe
aarch64_switch_probe:
    stp     x29, x30, [sp, #-112]!
    mov     x29, sp
    stp     x19, x20, [sp, #16]
    stp     x21, x22, [sp, #32]
    stp     x23, x24, [sp, #48]
    stp     x25, x26, [sp, #64]
    stp     x27, x28, [sp, #80]
    str     x2, [sp, #96]

    PATTERN 19, x2
    PATTERN 20, x2
    PATTERN 21, x2
    PATTERN 22, x2
    PATTERN 23, x2
    PATTERN 24, x2
    PATTERN 25, x2
    PATTERN 26, x2
    PATTERN 27, x2
    PATTERN 28, x2
    PATTERN 29, x2
    bl      aarch64_context_switch

    ldr     x9, [sp, #96]
    mov     x0, xzr
    CHECK   19
    CHECK   20
    CHECK   21
    CHECK   22
    CHECK   23
    CHECK   24
    CHECK   25
    CHECK   26
    CHECK   27
    CHECK   28
    CHECK   29

    ldp     x27, x28, [sp, #80]
    ldp     x25, x26, [sp, #64]
    ldp     x23, x24, [sp, #48]
    ldp     x21, x22, [sp, #32]
    ldp     x19, x20, [sp, #16]
    ldp     x29, x30, [sp], #112
    ret

// aarch64_clobber_and_switch(from, to)
//
// The other thread's half: overwrite x19–x29 with values the probe never uses, then
// switch. If the switch fails to put any of them back, the probe on the far side sees
// this thread's garbage instead of its own pattern. Its own registers are restored
// from its stack when it is resumed, so its Rust caller is none the wiser.
.globl aarch64_clobber_and_switch
aarch64_clobber_and_switch:
    stp     x29, x30, [sp, #-96]!
    mov     x29, sp
    stp     x19, x20, [sp, #16]
    stp     x21, x22, [sp, #32]
    stp     x23, x24, [sp, #48]
    stp     x25, x26, [sp, #64]
    stp     x27, x28, [sp, #80]

    movz    x9, #0xdead, lsl #48
    PATTERN 19, x9
    PATTERN 20, x9
    PATTERN 21, x9
    PATTERN 22, x9
    PATTERN 23, x9
    PATTERN 24, x9
    PATTERN 25, x9
    PATTERN 26, x9
    PATTERN 27, x9
    PATTERN 28, x9
    PATTERN 29, x9
    bl      aarch64_context_switch

    ldp     x27, x28, [sp, #80]
    ldp     x25, x26, [sp, #64]
    ldp     x23, x24, [sp, #48]
    ldp     x21, x22, [sp, #32]
    ldp     x19, x20, [sp, #16]
    ldp     x29, x30, [sp], #96
    ret
"#
);

unsafe extern "C" {
    fn aarch64_switch_probe(from: *mut Context, to: *const Context, base: u64) -> u64;
    fn aarch64_clobber_and_switch(from: *mut Context, to: *const Context);
}

/// How many times the selftest goes there and back. The first visit enters through the
/// trampoline; every later one resumes a context `switch` saved, which is the path a
/// scheduler actually uses and the one `init` alone cannot prove.
const ROUNDS: u64 = 3;

/// The probe's pattern base. Anything that cannot collide with the thread's `0xdead`
/// garbage, and varied per round so a value left over from the previous round fails.
const PATTERN_BASE: u64 = 0x5a17_c0de_0000_0000;

/// The argument the selftest thread must receive in x0.
const THREAD_ARG: usize = 0x7418_ea5e_0bad_f00d;

/// The selftest thread's stack. There is no frame allocator in `arch`, so it is a static
/// in `.bss`. Unlike the boot stack it has no guard page beneath it; the thread runs one
/// short loop and nothing recursive, and 16 KiB is two orders of magnitude more than it
/// uses.
const THREAD_STACK_BYTES: usize = 16 * 1024;

#[repr(C, align(16))]
struct ThreadStack(UnsafeCell<[u8; THREAD_STACK_BYTES]>);

/// A context in a `static`.
struct ContextSlot(UnsafeCell<Context>);

// SAFETY: both are touched only by `selftest` and the thread it starts, which never run
// at the same time — one is always suspended inside a switch while the other runs — on
// the one CPU that is out of its parking loop, with interrupts masked across every
// switch. No reference into either outlives the statement that makes it.
unsafe impl Sync for ThreadStack {}
// SAFETY: as for `ThreadStack`.
unsafe impl Sync for ContextSlot {}

static THREAD_STACK: ThreadStack = ThreadStack(UnsafeCell::new([0; THREAD_STACK_BYTES]));
static BOOT_CTX: ContextSlot = ContextSlot(UnsafeCell::new(Context::empty()));
static THREAD_CTX: ContextSlot = ContextSlot(UnsafeCell::new(Context::empty()));

/// Times the thread has been scheduled. Atomic so the compiler cannot conclude that a
/// call to an external symbol leaves it unchanged.
static THREAD_RUNS: AtomicU64 = AtomicU64::new(0);
/// What arrived in x0 at the thread's entry point.
static THREAD_ARG_SEEN: AtomicU64 = AtomicU64::new(0);

extern "C" fn selftest_thread(arg: usize) -> ! {
    THREAD_ARG_SEEN.store(arg as u64, Ordering::SeqCst);
    // Counted in a local, not in the static, so the count is itself evidence of
    // resumption: it lives in this thread's registers or stack, and survives from one
    // round to the next only if the switch really put this thread back where it left
    // off. A thread restarted from scratch each time would report 1 forever.
    let mut runs: u64 = 0;
    loop {
        runs += 1;
        THREAD_RUNS.store(runs, Ordering::SeqCst);
        // SAFETY: the boot thread is suspended in `aarch64_switch_probe` with its state
        // in BOOT_CTX, interrupts are masked (it masked them before switching here), and
        // THREAD_CTX is this thread's own slot, distinct from BOOT_CTX.
        unsafe { aarch64_clobber_and_switch(THREAD_CTX.0.get(), BOOT_CTX.0.get()) };
    }
}

/// Start a thread on a static stack, go there and back [`ROUNDS`] times, and check that
/// every trip actually reached the thread and that x19–x29 survived each one.
pub fn selftest(c: &dyn EarlyConsole) -> bool {
    let top = KernAddr::new(THREAD_STACK.0.get() as usize + THREAD_STACK_BYTES);
    // SAFETY: the stack is a 16 KiB static in `.bss`, mapped read-write by the boot
    // tables, used by nothing but this thread, and lives forever. The thread is not
    // running — it has either never run or is suspended in a switch — so re-initialising
    // its slot on a second call abandons it harmlessly. The `&mut` ends with the call.
    unsafe { Aarch64::init(&mut *THREAD_CTX.0.get(), top, selftest_thread, THREAD_ARG) };
    THREAD_RUNS.store(0, Ordering::SeqCst);

    for round in 0..ROUNDS {
        let daif = Aarch64::irq_save();
        // SAFETY: interrupts are masked for the duration. BOOT_CTX is this thread's slot
        // and THREAD_CTX the other's, so they do not alias; THREAD_CTX was filled by
        // `init` above or by the thread's last switch, and its stack is the static one.
        let lost = unsafe {
            aarch64_switch_probe(BOOT_CTX.0.get(), THREAD_CTX.0.get(), PATTERN_BASE + round)
        };
        // SAFETY: `daif` came from the `irq_save` just above, on this CPU.
        unsafe { Aarch64::irq_restore(daif) };

        let runs = THREAD_RUNS.load(Ordering::SeqCst);
        if runs != round + 1 {
            c.write_str("thread ran ");
            write_dec(c, runs);
            c.write_str(" times in ");
            write_dec(c, round + 1);
            c.write_str(" switches");
            return false;
        }
        if lost != 0 {
            c.write_str("round ");
            write_dec(c, round + 1);
            c.write_str(" lost");
            for reg in 19..=29 {
                if lost & (1 << reg) != 0 {
                    c.write_str(" x");
                    write_dec(c, reg);
                }
            }
            return false;
        }
    }

    if THREAD_ARG_SEEN.load(Ordering::SeqCst) != THREAD_ARG as u64 {
        c.write_str("entry argument not delivered in x0");
        return false;
    }

    c.write_str("switched ");
    write_dec(c, ROUNDS);
    c.write_str(" round trips, x19-x29 preserved");
    true
}

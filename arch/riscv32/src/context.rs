//! The context switch: [`hal::HasContextSwitch`] for riscv32, and the selftest that
//! proves it.
//!
//! # What is saved
//!
//! A switch is a function call (see `hal::context`), so only what the RISC-V calling
//! convention makes callee-saved has to survive it: `s0`–`s11`, the return address and
//! the stack pointer. Fourteen words, in [`Context`].
//!
//! `gp` and `tp` are not among them. This kernel gives neither a role: nothing defines
//! `__global_pointer$`, so the linker never relaxes an access to be `gp`-relative, and
//! there is no thread-local storage. If either is ever given one it becomes per-thread
//! state and joins the context.
//!
//! There are no floating-point registers to save, and not by choice: rv32imac has no F
//! or D extension, and the target is `ilp32`, the soft-float ABI.
//!
//! # Starting a thread
//!
//! The switch restores callee-saved registers and returns through `ra`; it does not load
//! `a0`. So `init` builds a context whose `ra` is `riscv32_thread_trampoline`, with the
//! entry point in `s1` and its argument in `s2`, and `s0` zero. The entry point's own
//! frame record saves that zero, which is where a backtrace of the thread ends.
//!
//! # Interrupts
//!
//! `mstatus.MIE` is not part of the context. A switch runs masked, so a thread resumed by
//! a switch resumes masked, and a new thread starts masked.

use core::cell::UnsafeCell;
use core::mem::offset_of;
use core::sync::atomic::{AtomicUsize, Ordering};

use hal::{Arch, EarlyConsole, HasContextSwitch, KernAddr, ThreadEntry};

use crate::Riscv32;
use crate::trap::{write_dec, write_hex};

/// The callee-saved state of a suspended thread.
///
/// `repr(C)` because `riscv32_context_switch` addresses the fields by offset, which is
/// asserted below.
#[repr(C)]
#[derive(Default)]
pub struct Context {
    ra: u32,
    sp: u32,
    /// `s0`–`s11`; `s0` is the frame pointer.
    s: [u32; 12],
}

impl Context {
    const fn empty() -> Self {
        Self {
            ra: 0,
            sp: 0,
            s: [0; 12],
        }
    }
}

const _: () = {
    assert!(offset_of!(Context, ra) == 0);
    assert!(offset_of!(Context, sp) == 4);
    assert!(offset_of!(Context, s) == 8);
    assert!(core::mem::size_of::<Context>() == 56);
};

core::arch::global_asm!(
    r#"
.section .text.context, "ax"

// riscv32_context_switch(from: *mut Context, to: *const Context)
.globl riscv32_context_switch
riscv32_context_switch:
    sw      ra, 0(a0)
    sw      sp, 4(a0)
    sw      s0, 8(a0)
    sw      s1, 12(a0)
    sw      s2, 16(a0)
    sw      s3, 20(a0)
    sw      s4, 24(a0)
    sw      s5, 28(a0)
    sw      s6, 32(a0)
    sw      s7, 36(a0)
    sw      s8, 40(a0)
    sw      s9, 44(a0)
    sw      s10, 48(a0)
    sw      s11, 52(a0)

    lw      ra, 0(a1)
    lw      sp, 4(a1)
    lw      s0, 8(a1)
    lw      s1, 12(a1)
    lw      s2, 16(a1)
    lw      s3, 20(a1)
    lw      s4, 24(a1)
    lw      s5, 28(a1)
    lw      s6, 32(a1)
    lw      s7, 36(a1)
    lw      s8, 40(a1)
    lw      s9, 44(a1)
    lw      s10, 48(a1)
    lw      s11, 52(a1)
    ret

// The first code a new thread runs, arrived at by the `ret` above.
.globl riscv32_thread_trampoline
riscv32_thread_trampoline:
    mv      a0, s2
    jalr    s1
    // `ThreadEntry` diverges; s1 still names the entry point that returned.
    mv      a0, s1
    j       riscv32_thread_returned
"#
);

unsafe extern "C" {
    fn riscv32_context_switch(from: *mut Context, to: *const Context);
    fn riscv32_thread_trampoline();
}

/// Where a thread lands if its entry point returns, which it must not.
#[unsafe(no_mangle)]
extern "C" fn riscv32_thread_returned(entry: usize) -> ! {
    let c = &crate::EARLY;
    c.write_str("\n\nkernel thread entry point returned: entry ");
    write_hex(c, entry as u64);
    c.write_str("\n");
    Riscv32::halt()
}

impl HasContextSwitch for Riscv32 {
    type Context = Context;

    /// The alignment slack and one frame. A floor for starting a thread, not a size
    /// anything useful runs in.
    const MIN_STACK: usize = 32;

    /// The psABI requires the stack pointer to be a multiple of 16 on entry to a function.
    const STACK_ALIGN: usize = 16;

    unsafe fn init(ctx: &mut Context, stack_top: KernAddr, entry: ThreadEntry, arg: usize) {
        let top = hal::context::aligned_stack_top::<Self>(stack_top);
        let mut s = [0; 12];
        s[1] = entry as usize as u32;
        s[2] = arg as u32;
        *ctx = Context {
            ra: riscv32_thread_trampoline as *const () as usize as u32,
            sp: top.raw() as u32,
            s,
        };
    }

    #[inline]
    unsafe fn switch(from: *mut Context, to: *const Context) {
        // SAFETY: the caller upholds the contract — interrupts masked, `from` writable and
        // distinct from `to`, `to` a suspended context with a live stack. It is an ordinary
        // call, so the compiler treats every caller-saved register as clobbered across it.
        unsafe { riscv32_context_switch(from, to) }
    }
}

// --- selftest ---------------------------------------------------------------------------

core::arch::global_asm!(
    r#"
.section .text.context_selftest, "ax"

// s<n> = t0 + n. Distinct per register, so a restore from a neighbour's slot shows up
// as a difference of one.
.macro PATTERN reg, n
    addi    \reg, t0, \n
.endm

// Set bit n of a0 if s<n> no longer holds t0 + n.
.macro CHECK reg, n
    addi    t1, t0, \n
    sub     t2, \reg, t1
    snez    t2, t2
    slli    t2, t2, \n
    or      a0, a0, t2
.endm

// riscv32_switch_probe(from, to, base) -> u32
//
// Load s0-s11 with a pattern derived from `base`, switch away, and on return report as
// a bitmask which of them did not come back. Its own callee-saved registers, and
// `base`, are kept on its stack.
.globl riscv32_switch_probe
riscv32_switch_probe:
    addi    sp, sp, -64
    sw      ra, 60(sp)
    sw      s0, 56(sp)
    sw      s1, 52(sp)
    sw      s2, 48(sp)
    sw      s3, 44(sp)
    sw      s4, 40(sp)
    sw      s5, 36(sp)
    sw      s6, 32(sp)
    sw      s7, 28(sp)
    sw      s8, 24(sp)
    sw      s9, 20(sp)
    sw      s10, 16(sp)
    sw      s11, 12(sp)
    sw      a2, 8(sp)

    mv      t0, a2
    PATTERN s0, 0
    PATTERN s1, 1
    PATTERN s2, 2
    PATTERN s3, 3
    PATTERN s4, 4
    PATTERN s5, 5
    PATTERN s6, 6
    PATTERN s7, 7
    PATTERN s8, 8
    PATTERN s9, 9
    PATTERN s10, 10
    PATTERN s11, 11
    call    riscv32_context_switch

    lw      t0, 8(sp)
    li      a0, 0
    CHECK   s0, 0
    CHECK   s1, 1
    CHECK   s2, 2
    CHECK   s3, 3
    CHECK   s4, 4
    CHECK   s5, 5
    CHECK   s6, 6
    CHECK   s7, 7
    CHECK   s8, 8
    CHECK   s9, 9
    CHECK   s10, 10
    CHECK   s11, 11

    lw      s11, 12(sp)
    lw      s10, 16(sp)
    lw      s9, 20(sp)
    lw      s8, 24(sp)
    lw      s7, 28(sp)
    lw      s6, 32(sp)
    lw      s5, 36(sp)
    lw      s4, 40(sp)
    lw      s3, 44(sp)
    lw      s2, 48(sp)
    lw      s1, 52(sp)
    lw      s0, 56(sp)
    lw      ra, 60(sp)
    addi    sp, sp, 64
    ret

// riscv32_clobber_and_switch(from, to)
//
// The other thread's half: overwrite s0-s11 with values the probe never uses, then
// switch. Its own registers come back from its stack when it is resumed.
.globl riscv32_clobber_and_switch
riscv32_clobber_and_switch:
    addi    sp, sp, -64
    sw      ra, 60(sp)
    sw      s0, 56(sp)
    sw      s1, 52(sp)
    sw      s2, 48(sp)
    sw      s3, 44(sp)
    sw      s4, 40(sp)
    sw      s5, 36(sp)
    sw      s6, 32(sp)
    sw      s7, 28(sp)
    sw      s8, 24(sp)
    sw      s9, 20(sp)
    sw      s10, 16(sp)
    sw      s11, 12(sp)

    li      t0, 0xdead0000
    PATTERN s0, 0
    PATTERN s1, 1
    PATTERN s2, 2
    PATTERN s3, 3
    PATTERN s4, 4
    PATTERN s5, 5
    PATTERN s6, 6
    PATTERN s7, 7
    PATTERN s8, 8
    PATTERN s9, 9
    PATTERN s10, 10
    PATTERN s11, 11
    call    riscv32_context_switch

    lw      s11, 12(sp)
    lw      s10, 16(sp)
    lw      s9, 20(sp)
    lw      s8, 24(sp)
    lw      s7, 28(sp)
    lw      s6, 32(sp)
    lw      s5, 36(sp)
    lw      s4, 40(sp)
    lw      s3, 44(sp)
    lw      s2, 48(sp)
    lw      s1, 52(sp)
    lw      s0, 56(sp)
    lw      ra, 60(sp)
    addi    sp, sp, 64
    ret
"#
);

unsafe extern "C" {
    fn riscv32_switch_probe(from: *mut Context, to: *const Context, base: u32) -> u32;
    fn riscv32_clobber_and_switch(from: *mut Context, to: *const Context);
}

/// Round trips. The first enters through the trampoline; the rest resume a saved context.
const ROUNDS: usize = 3;

/// The probe's pattern base; varied per round, and far from the thread's `0xdead0000`.
const PATTERN_BASE: u32 = 0x5a17_0000;

/// The argument the selftest thread must receive in `a0`.
const THREAD_ARG: usize = 0x0bad_f00d;

const THREAD_STACK_BYTES: usize = 16 * 1024;

#[repr(C, align(16))]
struct ThreadStack(UnsafeCell<[u8; THREAD_STACK_BYTES]>);

struct ContextSlot(UnsafeCell<Context>);

// SAFETY: touched only by `selftest` and the thread it starts, which never run at the
// same time — one is always suspended inside a switch — on the one hart, with interrupts
// masked across every switch.
unsafe impl Sync for ThreadStack {}
// SAFETY: as for `ThreadStack`.
unsafe impl Sync for ContextSlot {}

static THREAD_STACK: ThreadStack = ThreadStack(UnsafeCell::new([0; THREAD_STACK_BYTES]));
static BOOT_CTX: ContextSlot = ContextSlot(UnsafeCell::new(Context::empty()));
static THREAD_CTX: ContextSlot = ContextSlot(UnsafeCell::new(Context::empty()));

static THREAD_RUNS: AtomicUsize = AtomicUsize::new(0);
static THREAD_ARG_SEEN: AtomicUsize = AtomicUsize::new(0);

extern "C" fn selftest_thread(arg: usize) -> ! {
    THREAD_ARG_SEEN.store(arg, Ordering::SeqCst);
    // A local, so the count survives only if the switch really resumes this thread.
    let mut runs = 0;
    loop {
        runs += 1;
        THREAD_RUNS.store(runs, Ordering::SeqCst);
        // SAFETY: the boot thread is suspended in the probe with its state in BOOT_CTX,
        // interrupts are masked, and THREAD_CTX is this thread's own slot.
        unsafe { riscv32_clobber_and_switch(THREAD_CTX.0.get(), BOOT_CTX.0.get()) };
    }
}

/// Start a thread on a static stack, go there and back [`ROUNDS`] times, and check that
/// every trip reached the thread and that `s0`–`s11` survived each one.
pub fn selftest(c: &dyn EarlyConsole) -> bool {
    let top = KernAddr::new(THREAD_STACK.0.get() as usize + THREAD_STACK_BYTES);
    // SAFETY: the stack is a static used by nothing but this thread, which is not running.
    unsafe { Riscv32::init(&mut *THREAD_CTX.0.get(), top, selftest_thread, THREAD_ARG) };
    THREAD_RUNS.store(0, Ordering::SeqCst);

    for round in 0..ROUNDS {
        let irq = Riscv32::irq_save();
        // SAFETY: masked; BOOT_CTX and THREAD_CTX are distinct, and THREAD_CTX holds a
        // context `init` or the thread's last switch left.
        let lost = unsafe {
            riscv32_switch_probe(
                BOOT_CTX.0.get(),
                THREAD_CTX.0.get(),
                PATTERN_BASE + ((round as u32) << 8),
            )
        };
        // SAFETY: pairs with the `irq_save` above.
        unsafe { Riscv32::irq_restore(irq) };

        let runs = THREAD_RUNS.load(Ordering::SeqCst);
        if runs != round + 1 {
            c.write_str("thread ran ");
            write_dec(c, runs as u64);
            c.write_str(" times in ");
            write_dec(c, round as u64 + 1);
            c.write_str(" switches");
            return false;
        }
        if lost != 0 {
            c.write_str("round ");
            write_dec(c, round as u64 + 1);
            c.write_str(" lost");
            for reg in 0..12 {
                if lost & (1 << reg) != 0 {
                    c.write_str(" s");
                    write_dec(c, reg);
                }
            }
            return false;
        }
    }

    if THREAD_ARG_SEEN.load(Ordering::SeqCst) != THREAD_ARG {
        c.write_str("entry argument not delivered in a0");
        return false;
    }

    c.write_str("switched ");
    write_dec(c, ROUNDS as u64);
    c.write_str(" round trips, s0-s11 preserved");
    true
}

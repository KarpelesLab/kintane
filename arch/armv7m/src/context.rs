//! The context switch: [`hal::HasContextSwitch`] for ARMv7-M, and the selftest that
//! proves it.
//!
//! # What is saved
//!
//! A switch is a function call (see `hal::context`), so only what AAPCS makes
//! callee-saved has to survive it: `r4`–`r11`, the stack pointer and the return address.
//! Ten words, in [`Context`]. `r7` is among them and is Thumb's frame pointer.
//!
//! There is no floating-point state: the Cortex-M3 has no FPU, and the target is the
//! soft-float EABI. A Cortex-M4F port adds `d8`–`d15` here and the lazy-stacking bits
//! of `EXC_RETURN` to `preempt.rs`.
//!
//! # Where switches happen
//!
//! Only in thread mode, on the process stack, with `PRIMASK` set. The scheduler's own
//! calls are there by construction; preemption gets there through PendSV, and
//! `preempt.rs` explains why a switch inside a handler would be wrong on this core.
//! Because `SPSEL` selects the process stack in thread mode, the `mov sp` below writes
//! `PSP`.
//!
//! # Starting a thread
//!
//! The switch restores callee-saved registers and returns through `lr`; it does not
//! load `r0`. So `init` builds a context whose `lr` is `armv7m_thread_trampoline`, with
//! the entry point in `r4`, its argument in `r5`, and `r7` zero, which is where a
//! backtrace of the thread ends.

use core::cell::UnsafeCell;
use core::mem::offset_of;
use core::sync::atomic::{AtomicUsize, Ordering};

use hal::{Arch, EarlyConsole, HasContextSwitch, KernAddr, ThreadEntry};

use crate::Armv7m;
use crate::counter::{write_dec, write_hex};

/// The callee-saved state of a suspended thread.
///
/// `repr(C)` because `armv7m_context_switch` addresses the fields by offset, which is
/// asserted below.
#[repr(C)]
#[derive(Default)]
pub struct Context {
    /// `r4`–`r11`; `r7` is the frame pointer.
    r: [u32; 8],
    sp: u32,
    lr: u32,
}

impl Context {
    const fn empty() -> Self {
        Self {
            r: [0; 8],
            sp: 0,
            lr: 0,
        }
    }
}

const _: () = {
    assert!(offset_of!(Context, r) == 0);
    assert!(offset_of!(Context, sp) == 32);
    assert!(offset_of!(Context, lr) == 36);
    assert!(core::mem::size_of::<Context>() == 40);
};

core::arch::global_asm!(
    r#"
.syntax unified
.thumb

.section .text.context, "ax"

// armv7m_context_switch(from: *mut Context, to: *const Context)
.globl armv7m_context_switch
.type armv7m_context_switch, %function
.thumb_func
armv7m_context_switch:
    stmia   r0!, {{r4-r11}}
    mov     r2, sp
    str     r2, [r0], #4
    str     lr, [r0]

    ldmia   r1!, {{r4-r11}}
    ldr     r2, [r1], #4
    mov     sp, r2
    ldr     lr, [r1]
    bx      lr

// The first code a new thread runs, arrived at by the `bx lr` above.
.globl armv7m_thread_trampoline
.type armv7m_thread_trampoline, %function
.thumb_func
armv7m_thread_trampoline:
    mov     r0, r5
    blx     r4
    // `ThreadEntry` diverges; r4 still names the entry point that returned.
    mov     r0, r4
    b       armv7m_thread_returned
"#
);

unsafe extern "C" {
    fn armv7m_context_switch(from: *mut Context, to: *const Context);
    fn armv7m_thread_trampoline();
}

/// Where a thread lands if its entry point returns, which it must not.
#[unsafe(no_mangle)]
extern "C" fn armv7m_thread_returned(entry: usize) -> ! {
    let c = &crate::EARLY;
    c.write_str("\n\nkernel thread entry point returned: entry ");
    write_hex(c, entry as u64);
    c.write_str("\n");
    Armv7m::halt()
}

impl HasContextSwitch for Armv7m {
    type Context = Context;

    /// The alignment slack and one frame. A floor for starting a thread, not a size
    /// anything useful runs in.
    const MIN_STACK: usize = 32;

    /// AAPCS requires the stack pointer to be a multiple of 8 at a public interface.
    const STACK_ALIGN: usize = 8;

    unsafe fn init(ctx: &mut Context, stack_top: KernAddr, entry: ThreadEntry, arg: usize) {
        let top = hal::context::aligned_stack_top::<Self>(stack_top);
        let mut r = [0; 8];
        // r4, r5; r7 (index 3) stays zero.
        r[0] = entry as usize as u32;
        r[1] = arg as u32;
        *ctx = Context {
            r,
            sp: top.raw() as u32,
            lr: armv7m_thread_trampoline as *const () as usize as u32,
        };
    }

    #[inline]
    unsafe fn switch(from: *mut Context, to: *const Context) {
        // SAFETY: the caller upholds the contract — interrupts masked, `from` writable and
        // distinct from `to`, `to` a suspended context with a live stack. It is an ordinary
        // call, so the compiler treats every caller-saved register as clobbered across it.
        unsafe { armv7m_context_switch(from, to) }
    }
}

// --- selftest ---------------------------------------------------------------------------

core::arch::global_asm!(
    r#"
.syntax unified
.thumb

.section .text.context_selftest, "ax"

// r<n> = base + n. Distinct per register, so a restore from a neighbour's slot shows up
// as a difference of one.
.macro PATTERN reg, n
    add     \reg, r2, #\n
.endm

// Set bit n of r0 if r<n> no longer holds base + n.
.macro CHECK reg, n
    add     r3, r2, #\n
    cmp     \reg, r3
    it      ne
    orrne   r0, r0, #(1 << \n)
.endm

// armv7m_switch_probe(from, to, base) -> u32
//
// Load r4-r11 with a pattern derived from `base`, switch away, and on return report as
// a bitmask which of them did not come back. `base` and its own callee-saved registers
// are kept on its stack; ten words keep the stack on an 8-byte boundary.
.globl armv7m_switch_probe
.type armv7m_switch_probe, %function
.thumb_func
armv7m_switch_probe:
    push    {{r2, r4-r11, lr}}
    PATTERN r4, 4
    PATTERN r5, 5
    PATTERN r6, 6
    PATTERN r7, 7
    PATTERN r8, 8
    PATTERN r9, 9
    PATTERN r10, 10
    PATTERN r11, 11
    bl      armv7m_context_switch

    ldr     r2, [sp]
    movs    r0, #0
    CHECK   r4, 4
    CHECK   r5, 5
    CHECK   r6, 6
    CHECK   r7, 7
    CHECK   r8, 8
    CHECK   r9, 9
    CHECK   r10, 10
    CHECK   r11, 11
    pop     {{r2, r4-r11, pc}}

// armv7m_clobber_and_switch(from, to)
//
// The other thread's half: overwrite r4-r11 with values the probe never uses, then
// switch. Its own registers come back from its stack when it is resumed.
.globl armv7m_clobber_and_switch
.type armv7m_clobber_and_switch, %function
.thumb_func
armv7m_clobber_and_switch:
    push    {{r3, r4-r11, lr}}
    ldr     r2, =0xdead0000
    PATTERN r4, 4
    PATTERN r5, 5
    PATTERN r6, 6
    PATTERN r7, 7
    PATTERN r8, 8
    PATTERN r9, 9
    PATTERN r10, 10
    PATTERN r11, 11
    bl      armv7m_context_switch
    pop     {{r3, r4-r11, pc}}
.ltorg
"#
);

unsafe extern "C" {
    fn armv7m_switch_probe(from: *mut Context, to: *const Context, base: u32) -> u32;
    fn armv7m_clobber_and_switch(from: *mut Context, to: *const Context);
}

/// Round trips. The first enters through the trampoline; the rest resume a saved context.
const ROUNDS: usize = 3;

/// The probe's pattern base; varied per round, and far from the thread's `0xdead0000`.
const PATTERN_BASE: u32 = 0x5a17_0000;

/// The argument the selftest thread must receive in `r0`.
const THREAD_ARG: usize = 0x0bad_f00d;

const THREAD_STACK_BYTES: usize = 4 * 1024;

#[repr(C, align(8))]
struct ThreadStack(UnsafeCell<[u8; THREAD_STACK_BYTES]>);

struct ContextSlot(UnsafeCell<Context>);

// SAFETY: touched only by `selftest` and the thread it starts, which never run at the
// same time — one is always suspended inside a switch — on the one core, with interrupts
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
        unsafe { armv7m_clobber_and_switch(THREAD_CTX.0.get(), BOOT_CTX.0.get()) };
    }
}

/// Start a thread on a static stack, go there and back [`ROUNDS`] times, and check that
/// every trip reached the thread and that `r4`–`r11` survived each one.
pub fn selftest(c: &dyn EarlyConsole) -> bool {
    let top = KernAddr::new(THREAD_STACK.0.get() as usize + THREAD_STACK_BYTES);
    // SAFETY: the stack is a static used by nothing but this thread, which is not running.
    unsafe { Armv7m::init(&mut *THREAD_CTX.0.get(), top, selftest_thread, THREAD_ARG) };
    THREAD_RUNS.store(0, Ordering::SeqCst);

    for round in 0..ROUNDS {
        let irq = Armv7m::irq_save();
        // SAFETY: masked; BOOT_CTX and THREAD_CTX are distinct, and THREAD_CTX holds a
        // context `init` or the thread's last switch left.
        let lost = unsafe {
            armv7m_switch_probe(
                BOOT_CTX.0.get(),
                THREAD_CTX.0.get(),
                PATTERN_BASE + ((round as u32) << 8),
            )
        };
        // SAFETY: pairs with the `irq_save` above.
        unsafe { Armv7m::irq_restore(irq) };

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
            for reg in 4..12 {
                if lost & (1 << reg) != 0 {
                    c.write_str(" r");
                    write_dec(c, reg);
                }
            }
            return false;
        }
    }

    if THREAD_ARG_SEEN.load(Ordering::SeqCst) != THREAD_ARG {
        c.write_str("entry argument not delivered in r0");
        return false;
    }

    c.write_str("switched ");
    write_dec(c, ROUNDS as u64);
    c.write_str(" round trips, r4-r11 preserved");
    true
}

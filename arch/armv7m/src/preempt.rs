//! Preemption through PendSV, onto a context switch that is a function call.
//!
//! # Why the hook cannot run in the timer's handler
//!
//! `hal::HasContextSwitch::switch` is a function call: it saves the callee-saved
//! registers, loads another thread's, and returns into that thread wherever it last
//! called `switch`. Every other port calls the scheduler's hook from the timer's
//! interrupt handler and lets it switch there, which works because their exception
//! state travels with the interrupted thread: the saved `ELR`/`SPSR`, `mepc`/`mstatus`,
//! or the IRET frame is on that thread's stack, and "in a handler" is not a property of
//! the CPU that outlives the frame.
//!
//! On ARMv7-M it is. Handler mode, the active exception and its priority are the core's
//! state, restored only by an exception return. A switch made inside the timer's handler
//! would resume the other thread still in handler mode, with the timer's exception
//! active: a thread that yielded in thread mode would continue with interrupts of equal
//! and lower priority blocked, and a new thread would start that way. **This is where
//! the trait's assumption fails on this architecture**: that the place a switch is made
//! is a place both threads can run in.
//!
//! # What this does instead
//!
//! The standard Cortex-M answer is to switch in PendSV at the lowest priority. This port
//! uses PendSV to reach thread mode rather than to switch in handler mode, so `switch`
//! stays the function call the trait describes and every thread only ever runs in
//! thread mode:
//!
//! 1. The timer's handler acknowledges the interrupt, sets `ARMV7M_HOOK_DUE` and pends PendSV, then
//!    returns. PendSV runs when nothing of higher priority is active: after the timer's handler,
//!    never inside another handler.
//! 2. PendSV, finding the hook due, leaves the interrupted thread's exception frame where it is on
//!    that thread's stack and pushes a second frame below it, whose return address is
//!    [`armv7m_preempt_trampoline`]. Its exception return lands there in thread mode, with the
//!    stack pointer at the original frame.
//! 3. The trampoline masks interrupts and calls the hook, which may `switch` like any thread.
//!    Whenever this thread is switched back to, the hook returns here.
//! 4. The trampoline pends PendSV again and unmasks, arriving at `armv7m_resume_point`. PendSV,
//!    seeing that return address, discards the trampoline's frame and returns through the original
//!    one. The hardware restores the interrupted code exactly, including the IT state inside a
//!    Thumb `IT` block, which no hand-written return from thread mode could.
//!
//! A tick that arrives while a thread sits at the resume point is not dropped: the hook
//! is due, so PendSV preempts the resume point itself, and the resume that follows
//! unwinds both frames. That matters because the hook arms the next one-shot; a hook
//! skipped once would stop the timer for good.

use core::sync::atomic::Ordering;

use crate::tick;

core::arch::global_asm!(
    r#"
.syntax unified
.thumb

.section .text.preempt, "ax"

// PendSV. Thread mode is always on the process stack here (boot.rs), so the frame to
// work on is at PSP, and EXC_RETURN is 0xFFFFFFFD.
.globl __pendsv_entry
.type __pendsv_entry, %function
.thumb_func
__pendsv_entry:
    ldr     r3, =0xFFFFFFFD
    cmp     lr, r3
    bne     9f
    mrs     r0, psp

    ldr     r1, =ARMV7M_HOOK_DUE
    ldrb    r2, [r1]
    cbnz    r2, 5f

    // Resume: discard every trampoline frame parked at the resume point, then return
    // through the frame below them.
    ldr     r3, =armv7m_resume_point
    bic     r3, r3, #1
1:
    ldr     r1, [r0, #24]
    cmp     r1, r3
    bne     2f
    ldr     r1, [r0, #28]
    add     r0, r0, #32
    // Stacked xPSR bit 9: the core padded this frame by 4 bytes to align the stack.
    tst     r1, #0x200
    it      ne
    addne   r0, r0, #4
    b       1b
2:
    msr     psp, r0
9:
    bx      lr

5:
    // Preempt: a frame below the interrupted one, returning to the trampoline. The
    // interrupted frame starts on an 8-byte boundary (CCR.STKALIGN), so this one does
    // too, and its xPSR carries no padding bit.
    sub     r0, r0, #32
    ldr     r1, =armv7m_preempt_trampoline
    bic     r1, r1, #1
    str     r1, [r0, #24]
    ldr     r1, =0x01000000
    str     r1, [r0, #28]
    movs    r1, #0
    str     r1, [r0, #20]
    msr     psp, r0
    bx      lr

.globl armv7m_preempt_trampoline
.type armv7m_preempt_trampoline, %function
.thumb_func
armv7m_preempt_trampoline:
    cpsid   i
    bl      armv7m_run_preempt_hook
    ldr     r0, =0xE000ED04
    ldr     r1, =0x10000000
    str     r1, [r0]
    cpsie   i
.globl armv7m_resume_point
.type armv7m_resume_point, %function
.thumb_func
armv7m_resume_point:
    b       armv7m_resume_point
.ltorg
"#
);

/// The hook, from the trampoline: thread mode, interrupts masked.
#[unsafe(no_mangle)]
extern "C" fn armv7m_run_preempt_hook() {
    tick::ARMV7M_HOOK_DUE.store(false, Ordering::Release);
    tick::run_hook();
}

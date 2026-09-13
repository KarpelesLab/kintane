//! Reset: the vector table and the code the core runs first.
//!
//! An ARMv7-M core has no boot ROM contract to speak of. At reset it loads the main
//! stack pointer from the vector table's first word and jumps to its second, in thread
//! mode, privileged, on the main stack, with interrupts enabled but none configured.
//! What has to happen before Rust can run:
//!
//! 1. **Copy `.data` to RAM.** The image executes in place: `.data`'s initial contents are in flash
//!    at its load address, and the code expects them at its RAM address.
//! 2. **Zero `.bss`.**
//! 3. **Move thread mode to the process stack.** Handlers keep the main stack the vector table
//!    named, `__handler_stack_top`; boot and every later thread run on `PSP`. That split is what
//!    lets an overflow of a thread's stack be reported by a handler that still has a stack. See
//!    `link.ld`.
//! 4. **End the frame-pointer chain.** `r7` is Thumb's frame pointer; a zero there is where the
//!    unwinder stops.
//!
//! `kmain` takes a `u64`, which AAPCS passes in `r0` and `r1`. There is no loader and so
//! no argument: both are zero, and `boot/info-board` answers from the build instead.

core::arch::global_asm!(
    r#"
.syntax unified
.thumb

.section .vectors, "a"
.globl __vectors
__vectors:
    .word   __handler_stack_top
    .word   __reset
    .word   __fault_entry           // NMI
    .word   __fault_entry           // HardFault
    .word   __fault_entry           // MemManage
    .word   __fault_entry           // BusFault
    .word   __fault_entry           // UsageFault
    .word   0
    .word   0
    .word   0
    .word   0
    .word   __fault_entry           // SVCall: nothing makes supervisor calls
    .word   __fault_entry           // DebugMonitor
    .word   0
    .word   __pendsv_entry          // PendSV: deferred preemption, src/preempt.rs
    .word   armv7m_systick          // SysTick: the clock's wrap count
    // External interrupts 0-31 on the AN385. Only APB timer 0 (8) is enabled; the rest
    // report themselves as faults if they ever arrive.
    .rept 8
    .word   __fault_entry
    .endr
    .word   armv7m_timer0           // 8: CMSDK APB timer 0, the scheduler's one-shot
    .rept 23
    .word   __fault_entry
    .endr

.section .text.boot, "ax"
.globl __reset
.type __reset, %function
.thumb_func
__reset:
    cpsid   i

    ldr     r0, =__data_load
    ldr     r1, =__data_start
    ldr     r2, =__data_init_end
1:
    cmp     r1, r2
    bhs     2f
    ldr     r3, [r0], #4
    str     r3, [r1], #4
    b       1b
2:
    ldr     r1, =__bss_start
    ldr     r2, =__bss_end
    movs    r3, #0
3:
    cmp     r1, r2
    bhs     4f
    str     r3, [r1], #4
    b       3b
4:
    // Thread mode on PSP from here. CONTROL.SPSEL takes effect at once; `isb` makes sure
    // nothing already fetched runs with the old stack.
    ldr     r0, =__stack_top
    msr     psp, r0
    movs    r0, #2
    msr     control, r0
    isb

    movs    r0, #0
    mov     r7, r0
    mov     lr, r0
    movs    r1, #0
    bl      kmain

    // kmain diverges; reaching this is a kernel bug.
5:
    cpsid   i
    wfi
    b       5b
.ltorg
"#
);

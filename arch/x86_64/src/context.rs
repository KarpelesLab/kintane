//! Kernel thread context switching for x86-64, and the proof that it preserves what it
//! must.
//!
//! ## What is saved, and why nothing else is
//!
//! [`switch`](hal::HasContextSwitch::switch) is an ordinary SysV call, so by the time it
//! runs its caller has already written off every caller-saved register. What a switch
//! must carry across is exactly the **callee-saved** set of the SysV AMD64 ABI (§3.2.1,
//! figure 3.4): **rbx, rbp, r12, r13, r14, r15 and rsp**. rip is not in the list because
//! it does not need to be — it is the return address `call` already pushed onto the
//! stack rsp names, so saving rsp saves it too, and the `ret` at the end of the switch
//! is what resumes the other thread.
//!
//! Two entries in the ABI's callee-saved table are deliberately **not** saved: the x87
//! control word and the control bits of MXCSR. This kernel is built `-mmx,-sse,
//! +soft-float` (see `targets/x86_64-kintane.json`), so no kernel code ever writes
//! either, and every thread observes the values the firmware left. That stops being true
//! the moment anything loads user FPU state, which is the `HasFpu` work and a separate
//! save area — not something to smuggle into every kernel-to-kernel switch. RFLAGS is
//! not saved either: DF is required clear at every call boundary, so it is already
//! correct, and IF is masked by the switch's own contract.
//!
//! ## The one stack invariant everything rests on
//!
//! A saved context's rsp always points at a return address, and is always
//! `≡ 8 (mod 16)`: it is the rsp of a function that has just been entered, because the
//! caller aligned to 16 and `call` pushed eight bytes. [`init`](HasContextSwitch::init)
//! fabricates a context that obeys exactly the same rule, so a new thread and a resumed
//! one are indistinguishable to the `ret` that ends the switch.
//!
//! ## Starting a thread
//!
//! The `ret` of the first switch into a new thread lands on [`thread_start`], a
//! three-instruction trampoline. It exists because `entry` wants `arg` in rdi, and rdi
//! is caller-saved — the switch does not restore it, and must not start to. So `init`
//! parks `arg` in rbx and `entry` in r12, which the switch *does* restore, and the
//! trampoline moves them into place and makes a real `call`. A real call rather than a
//! jump means `entry` sees a genuine return address, which is what puts the stack at
//! `≡ 8 (mod 16)` on entry, and the return address points at a `ud2` — so an entry point
//! that returns despite its `-> !` raises #UD, which the IDT reports with the faulting
//! rip, rather than executing whatever lies above the fabricated frame.
//!
//! ## Why stack alignment is checked when nothing here would notice
//!
//! Misalignment is a deferred failure: code runs correctly until a function uses an
//! aligned vector instruction on a stack slot (`movaps`) and takes #GP. This target is
//! built without SSE, so on x86-64 that function may never exist and a wrong `init`
//! could survive indefinitely. That is a reason to get it right on principle, not a
//! licence to get it wrong — the day vector code appears in the kernel, or someone
//! calls into a C library built for the ordinary ABI, the bug is already there. The
//! selftest therefore measures rsp at a new thread's first instruction rather than
//! trusting the arithmetic.
//!
//! ## What the selftest proves
//!
//! See [`selftest`]. In short: that a new thread starts at its entry point with its
//! argument and an ABI-aligned stack; that switching away and back works repeatedly,
//! so a context filled in by `switch` is exercised and not only one fabricated by
//! `init`; and — the part a "did it come back" test cannot see — that every
//! callee-saved register survives the round trip while the other thread deliberately
//! overwrites all of them.

use core::cell::UnsafeCell;
use core::mem::offset_of;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use hal::{Arch, EarlyConsole, HasContextSwitch, KernAddr, ThreadEntry};

use crate::X86_64;
use crate::serial::{write_dec, write_hex};

/// The saved state of a suspended kernel thread: the SysV callee-saved registers.
///
/// Layout is `repr(C)` because the switch reads and writes it from assembly by
/// `offset_of!`. The field order carries no meaning beyond that.
#[repr(C)]
#[derive(Default)]
pub struct Context {
    /// Points at the return address the thread will resume at. See the module comment
    /// for its alignment invariant.
    rsp: u64,
    rbx: u64,
    rbp: u64,
    r12: u64,
    r13: u64,
    r14: u64,
    r15: u64,
    /// For a thread that runs user code: the kernel stack its traps and system calls land
    /// on, and the physical root of its address space. Both zero for a kernel-only thread,
    /// and past the seven registers `switch` saves, so the assembly's offsets are unchanged.
    /// See `hal::HasUserMode::bind` and `super::user`.
    pub(crate) user_kernel_stack: u64,
    pub(crate) user_root: u64,
}

/// Size of the return address a `call` pushes, and of the slot `init` fabricates for
/// the switch's `ret` to pop.
const WORD: usize = 8;

impl HasContextSwitch for X86_64 {
    type Context = Context;

    /// Up to 15 bytes lost aligning the top down, one word for the trampoline address
    /// the first switch's `ret` pops, and one for the return address the trampoline's
    /// `call` pushes. What `entry` itself goes on to use is the thread's own business.
    const MIN_STACK: usize = 32;

    /// SysV AMD64 §3.2.2: `(rsp + 8)` is a multiple of 16 on function entry.
    const STACK_ALIGN: usize = 16;

    unsafe fn init(ctx: &mut Context, stack_top: KernAddr, entry: ThreadEntry, arg: usize) {
        // Aligned to 16, this is what rsp would hold just *before* a `call`. The
        // trampoline makes that call after the switch's `ret` has popped the slot
        // below, so the slot goes one word under the aligned top — which leaves the
        // saved rsp at `≡ 8 (mod 16)`, the same as any context `switch` saved.
        let top = hal::context::aligned_stack_top::<X86_64>(stack_top);
        // Cannot wrap for any `stack_top` the contract allows: the region extends
        // `MIN_STACK` bytes below it, so the top is at least that far above zero.
        let slot = top.raw().wrapping_sub(WORD);

        // SAFETY: `slot` is 8 mod 16 and so aligned for a `u64`; whether it is mapped and
        // unaliased is the write's question, answered below. No reference is formed.
        let slot_ptr = unsafe { KernAddr::new(slot).as_ptr::<u64>() };
        // SAFETY: the caller guarantees `stack_top` is the top of a mapped, writable
        // region of at least `MIN_STACK` bytes owned by this thread and not in use, and
        // `slot` lies within its highest 23 bytes, so the eight bytes written are inside
        // that region and nothing else holds a reference to them.
        unsafe { slot_ptr.write(thread_start as *const () as usize as u64) };

        *ctx = Context {
            rsp: slot as u64,
            // Picked up by the trampoline; see `thread_start`.
            rbx: arg as u64,
            r12: entry as *const () as usize as u64,
            // Zero terminates a frame-pointer walk at the thread's first frame rather
            // than following whatever the stack's previous user left.
            rbp: 0,
            r13: 0,
            r14: 0,
            r15: 0,
            user_kernel_stack: 0,
            user_root: 0,
        };
    }

    unsafe fn switch(from: *mut Context, to: *const Context) {
        // SAFETY: forwarded verbatim; the caller upholds `switch_raw`'s contract, which
        // is this function's own.
        unsafe { switch_raw(from, to) }
    }
}

/// Save the callee-saved registers into `from`, load them from `to`, and return into
/// whichever thread `to` describes.
///
/// # Safety
/// As [`HasContextSwitch::switch`]: interrupts masked, `from` writable and not aliasing
/// `to`, and `to` a context filled in by `init` or by an earlier switch whose stack is
/// still valid and which is not running.
#[unsafe(naked)]
unsafe extern "C" fn switch_raw(from: *mut Context, to: *const Context) {
    core::arch::naked_asm!(
        // Save. rsp here points at our caller's return address — that is the resume
        // point, so nothing else needs recording.
        "mov [rdi + {rsp}], rsp",
        "mov [rdi + {rbx}], rbx",
        "mov [rdi + {rbp}], rbp",
        "mov [rdi + {r12}], r12",
        "mov [rdi + {r13}], r13",
        "mov [rdi + {r14}], r14",
        "mov [rdi + {r15}], r15",
        // Restore. After the rsp load we are on the other thread's stack.
        "mov rsp, [rsi + {rsp}]",
        "mov rbx, [rsi + {rbx}]",
        "mov rbp, [rsi + {rbp}]",
        "mov r12, [rsi + {r12}]",
        "mov r13, [rsi + {r13}]",
        "mov r14, [rsi + {r14}]",
        "mov r15, [rsi + {r15}]",
        // Pops the return address `to` was saved with — or, for a fresh thread, the
        // trampoline address `init` put there.
        "ret",
        rsp = const offset_of!(Context, rsp),
        rbx = const offset_of!(Context, rbx),
        rbp = const offset_of!(Context, rbp),
        r12 = const offset_of!(Context, r12),
        r13 = const offset_of!(Context, r13),
        r14 = const offset_of!(Context, r14),
        r15 = const offset_of!(Context, r15),
    );
}

/// The first code a new thread runs, reached by the `ret` of the switch into it.
///
/// On arrival rsp is the aligned top of the stack (`≡ 0 mod 16`), rbx holds `arg` and
/// r12 holds `entry`, as `init` arranged. The `call` pushes a return address, so
/// `entry` is entered at `≡ 8 (mod 16)` exactly as if it had been called from Rust.
///
/// Never called as a function; typed as one only so its address can be taken.
#[unsafe(naked)]
unsafe extern "C" fn thread_start() -> ! {
    core::arch::naked_asm!(
        "mov rdi, rbx",
        "call r12",
        // `entry` is `-> !`. If one returns anyway, fault here, where the report names
        // this address, instead of popping whatever lies above the fabricated frame.
        "ud2",
    );
}

// ---------------------------------------------------------------------------------------
// Selftest
// ---------------------------------------------------------------------------------------

/// Stack size for the selftest's second thread.
const TEST_STACK_BYTES: usize = 16 * 1024;

/// How many times the boot thread switches to the test thread and back. The first
/// switch enters a context made by `init`; every later one enters a context that
/// `switch` saved, which is the case a single round trip never reaches.
const ROUNDS: u64 = 3;

/// The argument passed to the test thread, checked on arrival.
const TEST_ARG: usize = 0x6b69_6e74_616e_6521;

/// What the boot thread holds in rbx, rbp, r12, r13, r14, r15 across each switch.
const BOOT_VALUES: [u64; 6] = [
    0x1111_1111_1111_1111,
    0x2222_2222_2222_2222,
    0x3333_3333_3333_3333,
    0x4444_4444_4444_4444,
    0x5555_5555_5555_5555,
    0x6666_6666_6666_6666,
];

/// What the test thread holds in the same registers across each switch. Every value
/// differs from its counterpart in [`BOOT_VALUES`], so loading these *is* the clobber.
const THREAD_VALUES: [u64; 6] = [
    0xaaaa_aaaa_aaaa_aaaa,
    0xbbbb_bbbb_bbbb_bbbb,
    0xcccc_cccc_cccc_cccc,
    0xdddd_dddd_dddd_dddd,
    0xeeee_eeee_eeee_eeee,
    0xffff_ffff_ffff_ffff,
];

const REGISTER_NAMES: [&str; 6] = ["rbx", "rbp", "r12", "r13", "r14", "r15"];

/// Slots in an observation: the six registers, then rsp before and after the switch.
const OBSERVED: usize = 8;

/// The test thread's stack. `align(16)` and a size that is a multiple of 16 make the
/// top already aligned, though `init` does not rely on it.
///
/// No guard page. Like the #DF stack in `gdt.rs`, this is an ordinary `.bss` object;
/// the test thread's frames are a few hundred bytes, and stacks with guard pages arrive
/// with the allocator that can place them.
#[repr(C, align(16))]
struct TestStack(UnsafeCell<[u8; TEST_STACK_BYTES]>);

// SAFETY: never accessed from Rust — only its address is taken, to hand to `init`. The
// test thread is its only user, and the test thread runs only while the boot thread is
// suspended in a switch.
unsafe impl Sync for TestStack {}

static TEST_STACK: TestStack = TestStack(UnsafeCell::new([0; TEST_STACK_BYTES]));

/// A context in a static, reached only through raw pointers.
struct ContextCell(UnsafeCell<Context>);

// SAFETY: the two cells below are touched only by the selftest, on one CPU, with
// interrupts masked. Apart from the one `&mut` handed to `init` before the test thread
// exists, they are reached only through raw pointers handed to `switch`. Exactly one of the two
// threads is running at any moment, and a switch writes `from` before it reads `to`, which are
// distinct cells.
unsafe impl Sync for ContextCell {}

static BOOT_CONTEXT: ContextCell = ContextCell(UnsafeCell::new(Context {
    rsp: 0,
    rbx: 0,
    rbp: 0,
    r12: 0,
    r13: 0,
    r14: 0,
    r15: 0,
    user_kernel_stack: 0,
    user_root: 0,
}));
static THREAD_CONTEXT: ContextCell = ContextCell(UnsafeCell::new(Context {
    rsp: 0,
    rbx: 0,
    rbp: 0,
    r12: 0,
    r13: 0,
    r14: 0,
    r15: 0,
    user_kernel_stack: 0,
    user_root: 0,
}));

/// Set by the first selftest run. A second would re-`init` a stack a suspended thread
/// is still using.
static STARTED: AtomicBool = AtomicBool::new(false);

/// rsp at the test thread's first instruction, written by [`test_entry`].
static ENTRY_RSP: AtomicU64 = AtomicU64::new(0);
/// The argument the test thread received.
static ARG_SEEN: AtomicU64 = AtomicU64::new(0);
/// Times the test thread has run up to its switch back.
static THREAD_RUNS: AtomicU64 = AtomicU64::new(0);
/// Times the test thread has been resumed and checked its own registers.
static THREAD_CHECKS: AtomicU64 = AtomicU64::new(0);
/// Registers the test thread found altered on resume, as a bitmask over
/// [`REGISTER_NAMES`], with bit 6 for rsp. Zero if everything survived.
static THREAD_MISMATCH: AtomicU64 = AtomicU64::new(0);

/// Load `values` into rbx, rbp, r12–r15, switch from `from` to `to`, and on return write
/// what those registers then hold into `observed`.
///
/// Assembly because the test is about registers Rust code will not hold still: the six
/// values must be in the registers at the instant of the switch and read back at the
/// instant it returns, with nothing in between. The function is itself a well-behaved
/// SysV callee — it saves its caller's copies of the same registers first and restores
/// them last — so it can be called from ordinary Rust.
///
/// `observed[6]` is rsp immediately before the inner call and `observed[7]` rsp
/// immediately after it returns; they must be equal.
///
/// # Safety
/// As [`HasContextSwitch::switch`] for `from` and `to`. `values` must be readable and
/// `observed` writable, and `observed` must belong to the calling thread.
#[unsafe(naked)]
unsafe extern "C" fn switch_holding(
    from: *mut Context,
    to: *const Context,
    values: *const [u64; 6],
    observed: *mut [u64; OBSERVED],
) {
    core::arch::naked_asm!(
        // rsp is 8 mod 16 on entry; six pushes keep it there, the seventh aligns it
        // for the call below.
        "push rbx",
        "push rbp",
        "push r12",
        "push r13",
        "push r14",
        "push r15",
        "push rcx",
        "mov rbx, [rdx]",
        "mov rbp, [rdx + 8]",
        "mov r12, [rdx + 16]",
        "mov r13, [rdx + 24]",
        "mov r14, [rdx + 32]",
        "mov r15, [rdx + 40]",
        "mov [rcx + 48], rsp",
        "call {switch}",
        // rcx did not survive the call — it is caller-saved, which is the point — so
        // take `observed` back from where it was pushed. Only rax is written before
        // the six registers are recorded.
        "mov rax, [rsp]",
        "mov [rax], rbx",
        "mov [rax + 8], rbp",
        "mov [rax + 16], r12",
        "mov [rax + 24], r13",
        "mov [rax + 32], r14",
        "mov [rax + 40], r15",
        "mov [rax + 56], rsp",
        "pop rcx",
        "pop r15",
        "pop r14",
        "pop r13",
        "pop r12",
        "pop rbp",
        "pop rbx",
        "ret",
        switch = sym switch_raw,
    );
}

/// The test thread's entry point: record rsp at the first instruction, then carry on in
/// Rust.
///
/// A tail jump, not a call, so [`test_thread`] is entered on exactly the stack `init`
/// arranged and with `arg` untouched in rdi.
#[unsafe(naked)]
extern "C" fn test_entry(arg: usize) -> ! {
    core::arch::naked_asm!(
        "mov [rip + {probe}], rsp",
        "jmp {body}",
        probe = sym ENTRY_RSP,
        body = sym test_thread,
    );
}

/// The test thread proper: count a run, switch back holding [`THREAD_VALUES`], and on
/// every resume check that those values survived the boot thread's switch.
extern "C" fn test_thread(arg: usize) -> ! {
    ARG_SEEN.store(arg as u64, Ordering::Relaxed);
    loop {
        THREAD_RUNS.fetch_add(1, Ordering::Relaxed);
        let mut observed = [0u64; OBSERVED];
        // SAFETY: the boot thread switched here with interrupts masked and is
        // suspended in `BOOT_CONTEXT`, which that switch just filled in and whose stack
        // is the live boot stack. The two cells are distinct. `observed` is a local of
        // this thread.
        unsafe {
            switch_holding(
                THREAD_CONTEXT.0.get(),
                BOOT_CONTEXT.0.get(),
                &THREAD_VALUES,
                &mut observed,
            )
        };
        THREAD_CHECKS.fetch_add(1, Ordering::Relaxed);
        THREAD_MISMATCH.fetch_or(mismatches(&observed, &THREAD_VALUES), Ordering::Relaxed);
    }
}

/// Registers in `observed` that differ from `expected`, as a bitmask over
/// [`REGISTER_NAMES`], with bit 6 set if rsp changed across the switch.
fn mismatches(observed: &[u64; OBSERVED], expected: &[u64; 6]) -> u64 {
    let mut mask = 0;
    for (bit, (got, want)) in observed.iter().zip(expected).enumerate() {
        if got != want {
            mask |= 1 << bit;
        }
    }
    let [.., before, after] = *observed;
    if before != after {
        mask |= 1 << 6;
    }
    mask
}

/// Start a second thread, switch to it and back [`ROUNDS`] times, and prove the
/// callee-saved registers survive.
///
/// Each round, the boot thread loads [`BOOT_VALUES`] into rbx, rbp, r12–r15 and switches
/// away; the test thread loads [`THREAD_VALUES`] into the same six — overwriting every
/// one — and switches back. The boot thread then reads the registers at the instant the
/// switch returns. A switch that forgot any of them hands back the test thread's value
/// in that register, and the report names it. The test thread performs the same check
/// in the other direction on each resume.
///
/// Returns `true` only if the new thread started with its argument on an ABI-aligned
/// stack, ran once per round, and every register check in both directions passed.
pub fn selftest(c: &dyn EarlyConsole) -> bool {
    if STARTED.swap(true, Ordering::Relaxed) {
        c.write_str("already run");
        return false;
    }

    let irq = X86_64::irq_save();

    // The one-past-the-end address of the stack object. Never dereferenced as such:
    // `init` writes below it.
    let top = KernAddr::new(TEST_STACK.0.get() as usize + TEST_STACK_BYTES);
    // SAFETY: the test thread does not exist yet and interrupts are masked, so this is
    // the only access to the cell (see `ContextCell`), and the reference ends with the
    // `init` call below.
    let thread_context = unsafe { &mut *THREAD_CONTEXT.0.get() };
    // SAFETY: `top` is the end of a 16 KiB `.bss` object, mapped read-write by the
    // kernel address space, used by nothing else (see `TestStack`), and static. The
    // `STARTED` flag guarantees no earlier thread is still suspended on it.
    unsafe { X86_64::init(thread_context, top, test_entry, TEST_ARG) };

    let mut ok = true;
    let mut boot_mismatch = 0;
    let mut first_bad = [0u64; OBSERVED];
    let mut short_rounds = 0;
    for _ in 0..ROUNDS {
        let runs_before = THREAD_RUNS.load(Ordering::Relaxed);
        let mut observed = [0u64; OBSERVED];
        // SAFETY: interrupts were masked above. `BOOT_CONTEXT` is the running thread's
        // save area and distinct from `THREAD_CONTEXT`, which holds either the `init`
        // context or the one the test thread saved when it last switched back; its
        // stack is `TEST_STACK`, which is static. The test thread is not running,
        // because only this thread is. `observed` is a local of this thread.
        unsafe {
            switch_holding(
                BOOT_CONTEXT.0.get(),
                THREAD_CONTEXT.0.get(),
                &BOOT_VALUES,
                &mut observed,
            )
        };
        if THREAD_RUNS.load(Ordering::Relaxed) != runs_before + 1 {
            short_rounds += 1;
        }
        let m = mismatches(&observed, &BOOT_VALUES);
        if m != 0 && boot_mismatch == 0 {
            first_bad = observed;
        }
        boot_mismatch |= m;
    }

    // SAFETY: pairs with the `irq_save` above, on this CPU, once.
    unsafe { X86_64::irq_restore(irq) };

    let entry_rsp = ENTRY_RSP.load(Ordering::Relaxed);
    c.write_str("entry rsp ");
    write_hex(c, entry_rsp, 16);
    // `(rsp + 8) % 16 == 0` at entry, i.e. what a real `call` from an aligned stack
    // leaves.
    let aligned =
        entry_rsp != 0 && entry_rsp.wrapping_add(WORD as u64) % (X86_64::STACK_ALIGN as u64) == 0;
    c.write_str(if aligned {
        " (aligned)"
    } else {
        " (MISALIGNED)"
    });
    ok &= aligned;

    let arg_ok = ARG_SEEN.load(Ordering::Relaxed) == TEST_ARG as u64;
    c.write_str(if arg_ok { ", arg ok" } else { ", ARG WRONG" });
    ok &= arg_ok;

    c.write_str("\n             ");
    write_dec(c, THREAD_RUNS.load(Ordering::Relaxed));
    c.write_str(" runs in ");
    write_dec(c, ROUNDS);
    c.write_str(" round trips");
    if short_rounds != 0 {
        c.write_str(", THREAD DID NOT RUN in ");
        write_dec(c, short_rounds);
        ok = false;
    }

    // The boot thread checked once per round. The test thread checked once per resume,
    // and was resumed every round but the first.
    let checks = THREAD_CHECKS.load(Ordering::Relaxed);
    let thread_mismatch = THREAD_MISMATCH.load(Ordering::Relaxed);
    c.write_str("\n             rbx rbp r12-r15 rsp ");
    c.write_str(if boot_mismatch == 0 && thread_mismatch == 0 {
        "held while the other thread overwrote them"
    } else {
        "NOT HELD"
    });
    c.write_str(" (checked ");
    write_dec(c, ROUNDS);
    c.write_str(" + ");
    write_dec(c, checks);
    c.write_str(")");
    if checks != ROUNDS - 1 {
        c.write_str(" THREAD CHECKS MISSING");
        ok = false;
    }
    if thread_mismatch != 0 {
        c.write_str("\n             in thread CLOBBERED:");
        write_names(c, thread_mismatch);
        ok = false;
    }
    if boot_mismatch != 0 {
        c.write_str("\n             in boot   CLOBBERED:");
        write_names(c, boot_mismatch);
        report_mismatch(c, &first_bad);
        ok = false;
    }

    ok
}

/// Print each register in `mask` by name.
fn write_names(c: &dyn EarlyConsole, mask: u64) {
    for (bit, name) in REGISTER_NAMES.iter().chain(&["rsp"]).enumerate() {
        if mask & (1 << bit) != 0 {
            c.write_str(" ");
            c.write_str(name);
        }
    }
}

/// Print the first bad round's wrong registers with the value found and the value
/// expected.
fn report_mismatch(c: &dyn EarlyConsole, observed: &[u64; OBSERVED]) {
    for ((name, got), want) in REGISTER_NAMES.iter().zip(observed).zip(&BOOT_VALUES) {
        if got != want {
            c.write_str("\n             ");
            c.write_str(name);
            c.write_str("=");
            write_hex(c, *got, 16);
            c.write_str(" want ");
            write_hex(c, *want, 16);
        }
    }
}

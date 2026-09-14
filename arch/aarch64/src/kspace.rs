//! What this port contributes to the kernel's own address space once it is live.
//!
//! `kernel/main` builds the space from the memory map and `image_sections()`, verifies
//! it, and installs it in `TTBR0_EL1`. The per-port parts are here.
//!
//! 1. **Devices.** Not here. This is the port where leaving one out is fatal and silent — the
//!    console is a PL011, so the first write after the switch would fault, and the fault report
//!    would itself be a write to the unmapped console — which is why the windows are not a list a
//!    person keeps up to date. `kernel/platform/fdt` maps exactly what the drivers bound from the
//!    device tree claimed, and refuses to proceed if the tree's console is not the early one.
//! 2. **Enforcement.** [`enforcement_selftest`] asks the MMU rather than the tables. `AT S1E1W`
//!    runs a write translation through the live regime and reports a permission fault in `PAR_EL1`
//!    without taking one, so "the hardware refuses a write to `.rodata`" is observed directly.
//! 3. **Stack overflow.** An overflow here is harder to report than on x86-64, and the reason is in
//!    the exception entry. Every vector begins by opening its frame on the current stack. When that
//!    stack is the one that overflowed, the frame lands in the guard page, the store faults, and
//!    the new exception opens its frame 0x120 bytes further down — below the guard, in `.bss`,
//!    where it succeeds and quietly overwrites whatever lives there. So the synchronous vector
//!    checks first, without touching memory, whether its frame would land in a guard page, and if
//!    so switches to a stack reserved for reporting that. The check is in `exception.rs`; the stack
//!    and the report are here. Kernel thread stacks come from [`claim_thread_stack`], each with a
//!    guard page the same check knows about, so an overflowing thread is reported by name instead
//!    of writing its exception frame onto the stack of the thread below it.
//! 4. **Null dereference.** Nothing is mapped at page 0, so a read through a null pointer is a
//!    translation fault, reported as a null dereference.

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU8, AtomicUsize, Ordering};

use hal::{Arch, EarlyConsole, HasContextSwitch, KernAddr};

use crate::Aarch64;
use crate::exception::write_hex;

/// Ask the MMU whether it enforces the live tables, and report what it said.
///
/// Every answer comes from `AT`, which walks the translation regime the CPU is using.
/// Execute permission is the one thing `AT` cannot be asked about; PXN is part of the
/// descriptor format and needs no enable bit, which `kernel/main` has already read back
/// from the tables.
pub fn enforcement_selftest(c: &dyn EarlyConsole) -> bool {
    let s = crate::image_sections();
    let m = sctlr_el1() & 1 != 0;
    c.write_str("SCTLR_EL1.M ");
    c.write_str(if m { "on" } else { "OFF" });

    let mut ok = m;
    ok &= expect(c, ", text", s.text.0, Walk::Read, None);
    ok &= expect(c, " w", s.text.0, Walk::Write, Some(Fault::Permission));
    ok &= expect(c, ", rodata w", s.rodata.0, Walk::Write, Some(Fault::Permission));
    ok &= expect(c, ", data w", s.data.0, Walk::Write, None);
    ok &= expect(c, ", guard", s.stack_guard.0, Walk::Read, Some(Fault::Translation));
    ok &= expect(c, ", uart w", crate::serial::UART0 as u64, Walk::Write, None);
    ok
}

#[derive(Clone, Copy)]
enum Walk {
    Read,
    Write,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Fault {
    Translation,
    Permission,
    Other,
}

/// Check one `AT` answer against what was wanted and print it.
fn expect(c: &dyn EarlyConsole, label: &str, va: u64, walk: Walk, want: Option<Fault>) -> bool {
    let got = at(walk, va);
    c.write_str(label);
    c.write_str(match got {
        None => " ok",
        Some(Fault::Translation) => " unmapped",
        Some(Fault::Permission) => " refused",
        Some(Fault::Other) => " faulted",
    });
    if got == want {
        return true;
    }
    c.write_str(match want {
        None => " (WANTED ACCESS)",
        Some(Fault::Translation) => " (WANTED UNMAPPED)",
        Some(Fault::Permission) => " (WANTED REFUSED)",
        Some(Fault::Other) => " (WANTED A FAULT)",
    });
    false
}

/// Run a stage-1 EL1 translation of `va` and return the fault it reports, if any.
fn at(walk: Walk, va: u64) -> Option<Fault> {
    let par: u64;
    // SAFETY: `AT S1E1R` and `AT S1E1W` are permitted at EL1. Each walks the tables and
    // writes `PAR_EL1`; neither accesses the address, and a failing translation is
    // reported in `PAR_EL1.F` rather than taken as an exception. The `isb` is what makes
    // the result visible to the `mrs`.
    unsafe {
        match walk {
            Walk::Read => core::arch::asm!(
                "at s1e1r, {v}",
                "isb",
                "mrs {p}, par_el1",
                v = in(reg) va,
                p = out(reg) par,
                options(nostack, preserves_flags)
            ),
            Walk::Write => core::arch::asm!(
                "at s1e1w, {v}",
                "isb",
                "mrs {p}, par_el1",
                v = in(reg) va,
                p = out(reg) par,
                options(nostack, preserves_flags)
            ),
        }
    }
    if par & 1 == 0 {
        return None;
    }
    // FST, bits [6:1]: 0b0001LL is a translation fault at level LL, 0b0011LL a
    // permission fault.
    Some(match (par >> 1) & 0b11_1100 {
        0b00_0100 => Fault::Translation,
        0b00_1100 => Fault::Permission,
        _ => Fault::Other,
    })
}

/// `SCTLR_EL1`, read now.
fn sctlr_el1() -> u64 {
    let v: u64;
    // SAFETY: reading SCTLR_EL1 is permitted at EL1 and has no side effects.
    unsafe {
        core::arch::asm!("mrs {}, sctlr_el1", out(reg) v, options(nomem, nostack, preserves_flags));
    }
    v
}

// --- the guard page ---------------------------------------------------------------

core::arch::global_asm!(
    r#"
// Entered from the synchronous vector with the exception state intact and the stack
// that overflowed abandoned. Everything the report needs is in system registers.
.section .text.kspace_overflow, "ax"
.globl __kspace_stack_overflow
__kspace_stack_overflow:
    mov     x3, sp
    adrp    x0, __overflow_stack_top
    add     x0, x0, :lo12:__overflow_stack_top
    mov     sp, x0
    mov     x29, xzr
    mov     x30, xzr
    mrs     x0, far_el1
    mrs     x1, esr_el1
    mrs     x2, elr_el1
    bl      aarch64_stack_overflow
.Loverflow_hang:
    msr     daifset, #0xf
    wfi
    b       .Loverflow_hang

// The stack the report runs on. Used once, by a path that never returns, so it needs
// no more than the report's own frames.
.section .bss.overflow_stack, "aw", @nobits
.balign 4096
    .skip 8192
__overflow_stack_top:
"#
);

/// Whether `addr` is inside the boot stack's guard page.
fn in_guard(addr: u64) -> bool {
    let (start, end) = crate::image_sections().stack_guard;
    start < end && (start..end).contains(&addr)
}

/// `ESR_EL1.EC` for a data abort taken without a change in exception level.
const EC_DATA_ABORT_SAME_EL: u64 = 0x25;

/// Called by the exception reporter after it has printed an unhandled exception.
///
/// A data abort whose `FAR_EL1` is in the guard page is a stack overflow that still had
/// room for the exception frame, and the report says so. While an overflow is being
/// provoked this is also the verdict.
///
/// `frame` is where the exception frame was opened. Below the guard page means the
/// report is running on whatever lies beneath the stack: the synchronous vector's check
/// did not divert it, and memory the kernel owns has been overwritten to print this. The
/// overflow was caught, but not cleanly, and that is not a pass.
///
/// The same holds for a thread stack's guard page, where "beneath" is the top of the slot
/// below. A data abort in page 0 is a null dereference, and the report names it.
pub(crate) fn after_fault_report(c: &dyn EarlyConsole, esr: u64, far: u64, frame: u64) {
    let abort = esr >> 26 == EC_DATA_ABORT_SAME_EL;
    let threads = crate::image_sections().thread_stacks;
    let (hit, guard_start) = if abort && in_guard(far) {
        c.write_str("stack overflow: far is in the guard page below the boot stack\n");
        (Hit::BootGuard, crate::image_sections().stack_guard.0)
    } else if let Some(slot) = threads.guard_hit(far).filter(|_| abort) {
        c.write_str("stack overflow: far is in the guard page below ");
        write_slot(c, slot);
        c.write_str("\n");
        let start = threads.guard_range(slot).map_or(0, |(g, _)| g);
        (Hit::ThreadGuard(slot), start)
    } else if abort && far < Aarch64::PAGE_SIZE as u64 {
        c.write_str("null dereference: far is in page 0, which is never mapped\n");
        (Hit::Null, 0)
    } else {
        (Hit::Nothing, 0)
    };
    // Within a page below the guard: the frame was opened on whatever the guard protects.
    let beneath = matches!(hit, Hit::BootGuard | Hit::ThreadGuard(_))
        && frame < guard_start
        && frame + 0x1000 >= guard_start;
    if beneath {
        c.write_str(
            "and this report's frame is beneath the guard: memory below it was overwritten\n",
        );
    }
    verdict(c, if beneath { Hit::Nothing } else { hit });
}

/// The Rust half of the overflow path: report, and conclude if this was provoked.
///
/// Reached only when the synchronous vector found its own frame would touch a guard page.
/// That is the evidence, whatever the syndrome says, so it is the verdict too. `sp` is the
/// stack pointer the exception arrived with, which says whose guard it was.
#[unsafe(no_mangle)]
extern "C" fn aarch64_stack_overflow(far: u64, esr: u64, elr: u64, sp: u64) -> ! {
    let c = &crate::serial::EARLY;
    let threads = crate::image_sections().thread_stacks;
    let slot = [sp.wrapping_sub(0x120), sp.wrapping_sub(1)]
        .into_iter()
        .find_map(|a| threads.guard_hit(a));
    c.write_str("\n\nstack overflow: the exception frame would land in the guard page below ");
    let hit = match slot {
        Some(slot) => {
            write_slot(c, slot);
            Hit::ThreadGuard(slot)
        }
        None => {
            c.write_str("the boot stack");
            Hit::BootGuard
        }
    };
    c.write_str("\n  sp   ");
    write_hex(c, sp);
    c.write_str("\n  esr  ");
    write_hex(c, esr);
    c.write_str("\n  elr  ");
    write_hex(c, elr);
    c.write_str("\n  far  ");
    write_hex(c, far);
    c.write_str("\nreported from the overflow stack\n");
    verdict(c, hit);
    Aarch64::halt()
}

/// Overflow the boot stack until it reaches the guard page.
///
/// Does not return: the exception path concludes the run. If it did return, the guard
/// protected nothing, and that is the failure reported.
pub fn provoke_guard_fault() -> ! {
    EXPECTING.store(EXPECT_BOOT_GUARD, Ordering::SeqCst);
    let depth = descend(0);
    let _ = depth;
    conclude(false)
}

/// Recurse without end, keeping every frame alive. See the x86-64 port's copy.
#[inline(never)]
#[allow(unconditional_recursion)]
fn descend(n: u64) -> u64 {
    let frame = core::hint::black_box([n; 16]);
    descend(core::hint::black_box(n.wrapping_add(1))).wrapping_add(frame[15])
}

// ---------------------------------------------------------------------------
// Kernel thread stacks, and what a fault report says about them
// ---------------------------------------------------------------------------

/// Slots handed out so far. A stack is never given back: nothing that exits returns its
/// stack yet, and a slot a suspended thread may still be using must not be reissued.
static CLAIMED: AtomicUsize = AtomicUsize::new(0);

/// Most slots a fault report can name the owner of. The planner in `kernel/main` refuses
/// more thread stacks than this anyway.
/// Every slot `link.ld` reserves, by the same derivation as its `stacks.ld`. It was a
/// literal, which a configuration-sized array outgrew: at eight CPUs a stress build lays
/// out seventeen slots, and the seventeenth claim was refused though the array had room.
const NAMED_SLOTS: usize = kconfig::THREAD_STACK_SLOTS;

/// Who each slot was claimed for, for the report.
struct Owners(UnsafeCell<[&'static str; NAMED_SLOTS]>);

// SAFETY: a slot's entry is written once, by `claim_thread_stack`, before the slot is
// returned and so before any thread can run on it. The fault reporter only reads, and an
// entry it reads has either been written or is still the initial `""`.
unsafe impl Sync for Owners {}

static OWNERS: Owners = Owners(UnsafeCell::new([""; NAMED_SLOTS]));

/// A kernel thread stack with an unmapped guard page below it, claimed for `owner`.
///
/// Returns `(slot, top, size)`. `None` once every slot the linker reserved is taken.
/// The stack is mapped read-write by the kernel address space, and the page below
/// `top - size` is not, so an overflow faults and the report names `owner`.
pub fn claim_thread_stack(owner: &'static str) -> Option<(usize, KernAddr, usize)> {
    let t = crate::image_sections().thread_stacks;
    let slot = CLAIMED
        .try_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
            (n < t.count().min(NAMED_SLOTS)).then_some(n + 1)
        })
        .ok()?;
    let (bottom, top) = t.stack_range(slot)?;
    // SAFETY: see `Owners`: this slot was just claimed, so nothing runs on it yet and no
    // other writer exists for its entry.
    unsafe { (*OWNERS.0.get())[slot] = owner };
    Some((slot, KernAddr::new(top as usize), (top - bottom) as usize))
}

/// The owner a slot was claimed for, or `""`.
fn owner_of(slot: usize) -> &'static str {
    // SAFETY: a read of a `&'static str` written before the slot's thread could run.
    unsafe { (*OWNERS.0.get()).get(slot).copied().unwrap_or("") }
}

/// `thread stack N (owner)`.
fn write_slot(c: &dyn EarlyConsole, slot: usize) {
    c.write_str("thread stack ");
    let digits = [b'0' + (slot / 10 % 10) as u8, b'0' + (slot % 10) as u8];
    c.write_bytes(if slot < 10 { &digits[1..] } else { &digits });
    let owner = owner_of(slot);
    if !owner.is_empty() {
        c.write_str(" (");
        c.write_str(owner);
        c.write_str(")");
    }
}

/// What a faulting address turned out to be.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Hit {
    Nothing,
    BootGuard,
    ThreadGuard(usize),
    Null,
}

/// What a provoked fault must turn out to be, while one is being provoked. One of the
/// `EXPECT_*` values below.
///
/// A plain flag is enough. It is set once, from the only running context, and read only
/// from a fault handler that context caused.
static EXPECTING: AtomicU8 = AtomicU8::new(EXPECT_NOTHING);

const EXPECT_NOTHING: u8 = 0;
const EXPECT_BOOT_GUARD: u8 = 1;
const EXPECT_THREAD_GUARD: u8 = 2;
const EXPECT_NULL: u8 = 3;

/// The run's verdict while a fault is expected: pass on the expected kind, fail on any
/// other fault, at once rather than by timeout.
fn verdict(c: &dyn EarlyConsole, hit: Hit) {
    let want = EXPECTING.load(Ordering::Relaxed);
    if want == EXPECT_NOTHING {
        return;
    }
    let (ok, what) = match want {
        EXPECT_BOOT_GUARD => (hit == Hit::BootGuard, "guard page fault"),
        EXPECT_THREAD_GUARD => (matches!(hit, Hit::ThreadGuard(_)), "thread stack guard fault"),
        _ => (hit == Hit::Null, "null dereference"),
    };
    c.write_str("expected ");
    c.write_str(what);
    c.write_str(if ok {
        ": observed\n"
    } else {
        ": this fault is not it\n"
    });
    conclude(ok)
}

/// Run a thread on a guarded stack that recurses until it reaches its guard page.
///
/// Does not return: the exception path concludes the run, and passes it only if the fault
/// is on that thread stack's guard. If the recursion ever returned, the guard protected
/// nothing, and the thread reports that as a failure.
pub fn provoke_thread_guard_fault() -> ! {
    let Some((_, top, _)) = claim_thread_stack("stack guard test") else {
        crate::serial::EARLY.write_str("no thread stack to overflow\n");
        conclude(false)
    };
    EXPECTING.store(EXPECT_THREAD_GUARD, Ordering::SeqCst);
    let mut boot = <Aarch64 as HasContextSwitch>::Context::default();
    let mut thread = <Aarch64 as HasContextSwitch>::Context::default();
    // SAFETY: `top` is the top of a stack slot claimed just now, mapped read-write and used
    // by nothing else. `boot` is a local of this function, which never returns, so it
    // outlives the switch. Nothing switches back.
    unsafe {
        <Aarch64 as HasContextSwitch>::init(&mut thread, top, overflow_thread, 0);
        <Aarch64 as HasContextSwitch>::switch(&mut boot, &thread);
    }
    conclude(false)
}

/// The thread [`provoke_thread_guard_fault`] starts.
extern "C" fn overflow_thread(_: usize) -> ! {
    let depth = descend(0);
    let _ = depth;
    conclude(false)
}

/// Read address zero, and conclude the run from the fault that must follow.
pub fn provoke_null_dereference() -> ! {
    EXPECTING.store(EXPECT_NULL, Ordering::SeqCst);
    // Through `black_box`, so the compiler cannot see a null pointer and replace the read
    // with a trap of its own choosing: the point is what the MMU does with it.
    let at = core::hint::black_box(0usize) as *const u8;
    // SAFETY: expected to fault, and the fault handler does not return: it concludes the
    // run. If the read completes, page 0 is mapped, which is the failure reported below.
    let byte = unsafe { at.read_volatile() };
    let _ = byte;
    conclude(false)
}

/// End the run with a verdict.
#[cfg(CONFIG_QEMU_EXIT)]
fn conclude(ok: bool) -> ! {
    crate::exit_emulator(ok)
}

/// Without a result channel there is nobody to report to, so stop.
#[cfg(not(CONFIG_QEMU_EXIT))]
fn conclude(_ok: bool) -> ! {
    Aarch64::halt()
}

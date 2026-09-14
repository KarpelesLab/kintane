//! What this port contributes to the kernel's own address space once it is live.
//!
//! The same questions as on x86-64: which devices the space must map (none: every device
//! this port drives is an I/O port), whether the CPU enforces the tables, what a stack
//! overflow looks like, and what a null dereference looks like. The answer to the second
//! is weaker here, for a reason stated below rather than left to be discovered.
//!
//! ## An overflow is reported from the #DF task
//!
//! A recursion that reaches a guard page faults on a push. Delivering that #PF needs a
//! push onto the same stack, which faults, which raises #DF. On x86-64 the #DF gate names
//! an IST slot and the frame goes elsewhere. A 32-bit gate has no IST field, so #DF here
//! is a *task gate* (`tss.rs`): the CPU switches to a task with its own stack without
//! pushing anything on the broken one, and that task reports. [`provoke_guard_fault`]
//! and [`provoke_thread_guard_fault`] therefore overflow for real, the same as on x86-64.
//!
//! ## No fault probe of `.rodata`
//!
//! x86-64 makes the CPU refuse a write to `.rodata` and observes the fault. This port's
//! #PF handler has no expected-fault path to return through, so [`enforcement_selftest`]
//! reads `CR0.WP` and `EFER.NXE` back from the hardware and reports that it did no more.

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU8, AtomicUsize, Ordering};

use hal::paging::DeviceWindow;
use hal::{Arch, EarlyConsole, HasContextSwitch, KernAddr};

use crate::{I686, paging};

/// Device memory the kernel touches after its own tables are installed. None here.
pub fn device_windows() -> &'static [DeviceWindow] {
    &[]
}

/// Report whether the CPU is enforcing the live tables, as far as this port can tell.
///
/// `CR0.WP` is read from the register now. Without it a read-only mapping binds nothing at
/// CPL 0, so a clear bit is a failure. NX is reported but not demanded, because the
/// target's baseline CPU does not have it and the kernel space check already accounts for
/// that.
pub fn enforcement_selftest(c: &dyn EarlyConsole) -> bool {
    let wp = paging::write_protect_enabled();
    c.write_str("CR0.WP ");
    c.write_str(if wp { "on" } else { "OFF" });
    c.write_str(", NX ");
    c.write_str(if paging::nx_enabled() {
        "on"
    } else {
        "unavailable"
    });
    c.write_str(", no fault probe on this port");
    wp
}

/// Whether `addr` is inside the boot stack's guard page.
fn in_guard(addr: u32) -> bool {
    let (start, end) = crate::image_sections().stack_guard;
    start < end && (start..end).contains(&u64::from(addr))
}

/// Called by the exception reporter after it has printed a fatal fault.
///
/// A page fault or double fault whose CR2 is in a guard page is a stack overflow, and the
/// report says whose; a page fault in page 0 is a null dereference. While a fault is being
/// provoked this is also the run's verdict: the expected fault passes, any other fails at
/// once.
///
/// `from_task` is true when the report comes from the #DF task rather than from a handler
/// on the faulting stack.
pub(crate) fn after_fault_report(
    c: &dyn EarlyConsole,
    vector: Option<u8>,
    cr2: u32,
    from_task: bool,
) {
    let overflow = matches!(vector, Some(8) | Some(14));
    let addr = u64::from(cr2);
    let hit = if overflow && in_guard(cr2) {
        Hit::BootGuard
    } else if let Some(slot) = crate::image_sections().thread_stacks.guard_hit(addr) {
        if overflow {
            Hit::ThreadGuard(slot)
        } else {
            Hit::Nothing
        }
    } else if vector == Some(14) && addr < I686::PAGE_SIZE as u64 {
        Hit::Null
    } else {
        Hit::Nothing
    };
    match hit {
        Hit::BootGuard => {
            c.write_str("\nstack overflow: cr2 is in the guard page below the boot stack")
        }
        Hit::ThreadGuard(slot) => {
            c.write_str("\nstack overflow: cr2 is in the guard page below ");
            write_slot(c, slot);
        }
        Hit::Null => c.write_str("\nnull dereference: cr2 is in page 0, which is never mapped"),
        Hit::Nothing => {}
    }
    if matches!(hit, Hit::BootGuard | Hit::ThreadGuard(_)) && from_task {
        c.write_str(", reported from the #DF task");
    }
    if hit != Hit::Nothing {
        c.write_str("\n");
    }
    verdict(c, hit);
}

/// Overflow the boot stack until it reaches the guard page.
///
/// Does not return. The recursion faults on the guard page, the #DF task reports, and the
/// exception path concludes the run. If it ever did return the guard page protected
/// nothing, and that is reported as a failure.
pub fn provoke_guard_fault() -> ! {
    EXPECTING.store(EXPECT_BOOT_GUARD, Ordering::SeqCst);
    let depth = descend(0);
    let _ = depth;
    conclude(false)
}

/// Recurse without end, keeping every frame alive. See the x86-64 port's copy.
#[inline(never)]
#[allow(unconditional_recursion)]
fn descend(n: u32) -> u32 {
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
    let mut boot = <I686 as HasContextSwitch>::Context::default();
    let mut thread = <I686 as HasContextSwitch>::Context::default();
    // SAFETY: `top` is the top of a stack slot claimed just now, mapped read-write and used
    // by nothing else. `boot` is a local of this function, which never returns, so it
    // outlives the switch. Nothing switches back.
    unsafe {
        <I686 as HasContextSwitch>::init(&mut thread, top, overflow_thread, 0);
        <I686 as HasContextSwitch>::switch(&mut boot, &thread);
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
    <crate::I686 as hal::Arch>::halt()
}

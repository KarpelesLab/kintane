//! What this port contributes to the kernel's own address space once it is live.
//!
//! `kernel/main` builds that space from the memory map and `image_sections()`, verifies
//! it, and installs it. Three things about it are per-port knowledge, and they are here:
//!
//! 1. **Which devices it must map.** None on x86-64 today: the console, the PIC and the PIT are I/O
//!    ports, which no page table governs.
//! 2. **Whether the hardware enforces it.** A table that says read-only protects nothing if
//!    `CR0.WP` is clear, and a no-execute bit means nothing without `EFER.NXE`. So
//!    [`enforcement_selftest`] reads both registers now, not the values cached at `init`, and then
//!    makes the CPU refuse a write to `.rodata` and a fetch from `.data` in the live tables.
//! 3. **What a stack overflow looks like.** The guard page is unmapped, so an overflow faults on
//!    it. [`after_fault_report`] recognises that address in a fault report and says so, and
//!    [`provoke_guard_fault`] overflows the boot stack on purpose, for the harness. Kernel thread
//!    stacks come from [`claim_thread_stack`], each with a guard page of its own, and an overflow
//!    of one is reported with the slot and the thread it was claimed for.
//! 4. **What a null dereference looks like.** Page 0 is left unmapped, so a read through a null
//!    pointer faults, and the report names it as one rather than as a fault at a small address.
//!
//! ## The #DF path is the one that gets exercised
//!
//! A recursion that reaches the guard page faults on a push. Delivering that #PF needs a
//! push onto the same exhausted stack, which faults again, so the CPU raises #DF. #DF has
//! an IST slot (`gdt.rs`), which means its frame goes onto a stack that is not the broken
//! one. CR2 still holds the guard page address from the fault that could not be
//! delivered. This is the case that used to end in an endless #PF/#DF alternation with no
//! output. The report now names the guard page from the IST stack.

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU8, AtomicUsize, Ordering};

use hal::paging::DeviceWindow;
use hal::{Arch, EarlyConsole, HasContextSwitch, KernAddr};

use crate::X86_64;
use crate::paging::{self, CR0_WP, EFER, EFER_NXE, NO_EXECUTE, WRITABLE};
use crate::serial::write_hex;

/// Device memory the kernel touches after its own tables are installed.
///
/// Empty on this port, and stated rather than assumed: every device the kernel drives
/// here is reached through `in`/`out`, and a local APIC is the first thing that will add
/// an entry.
pub fn device_windows() -> &'static [DeviceWindow] {
    &[]
}

/// Prove the live tables are enforced by the CPU and not only written down.
///
/// Four observations, each printed:
///
/// * `CR0.WP` and `EFER.NXE`, read from the registers now.
/// * A write to `.rodata` faults with a write-protection error code. The expected-fault trap in
///   `paging` makes the page writable so the retried store completes, writing back the byte that
///   was already there, and the page is then made read-only again. Without the fault the store
///   would succeed silently, which is what an unenforced permission looks like.
/// * A call into a byte of `.data` holding `ret` faults with the instruction-fetch bit, and NX is
///   put back afterwards.
///
/// Must be called once the kernel address space is live, with nothing else running.
pub fn enforcement_selftest(c: &dyn EarlyConsole) -> bool {
    let _masked = X86_64::irq_save();
    let s = crate::image_sections();

    let wp = paging::read_cr0() & CR0_WP != 0;
    // SAFETY: EFER exists on every CPU that reached long mode; reading it has no effect.
    let nxe = unsafe { paging::read_msr(EFER) } & EFER_NXE != 0;
    c.write_str("CR0.WP ");
    c.write_str(if wp { "on" } else { "OFF" });
    c.write_str(", EFER.NXE ");
    c.write_str(if nxe { "on" } else { "off" });

    let ro_ok = wp && rodata_refuses_write(c, s.rodata.0);
    if !wp {
        c.write_str(", rodata NOT CHECKED: a clear WP makes read-only advisory");
    }
    let nx_ok = if nxe {
        data_refuses_fetch(c, s.data)
    } else {
        c.write_str(", no NX on this CPU: data is executable");
        true
    };
    ro_ok && nx_ok
}

/// Store to the first page of `.rodata` and require the CPU to refuse it.
fn rodata_refuses_write(c: &dyn EarlyConsole, rodata: u64) -> bool {
    #[allow(clippy::as_conversions)]
    let at = rodata as usize as *mut u8;
    // SAFETY: the first byte of `.rodata`, which the kernel space maps readable.
    let byte = unsafe { at.read_volatile() };
    paging::arm(at as usize, WRITABLE, 0);
    // SAFETY: expected to fault. The armed trap sets R/W on this page's entry and the
    // store re-executes, writing back the value just read, so nothing changes. Volatile
    // so the store of an unchanged value is not optimised away, which would turn "the
    // write was refused" into "no write was attempted".
    unsafe { at.write_volatile(byte) };
    let trapped = paging::disarm();
    // Read-only again before anything is reported, so a failure below cannot leave the
    // hole this check opened.
    let restored = paging::edit_live_leaf(at as usize, 0, WRITABLE);
    let still_ro = paging::live_leaf_bits(at as usize).is_some_and(|e| e & WRITABLE == 0);

    c.write_str(", rodata ");
    // P | W/R, supervisor.
    const EXPECTED: u64 = 0b011;
    match trapped {
        Some(EXPECTED) if restored && still_ro => {
            c.write_str("write #PF err ");
            write_hex(c, EXPECTED, 2);
            true
        }
        Some(code) => {
            c.write_str("WRONG: err ");
            write_hex(c, code, 2);
            c.write_str(if still_ro { "" } else { ", and left writable" });
            false
        }
        None => {
            c.write_str("WRITE ALLOWED");
            false
        }
    }
}

/// A byte of `.data` holding `ret`.
///
/// Interior-mutable so that it lands in `.data` rather than `.rodata`: an immutable
/// static with this value would be placed with the constants, which are not what this
/// check is about.
struct DataByte(UnsafeCell<u8>);

// SAFETY: never written; the `UnsafeCell` is only there to decide its section. It is read
// by the CPU as an instruction, from the one CPU, with interrupts masked.
unsafe impl Sync for DataByte {}

/// `ret`.
static RET_IN_DATA: DataByte = DataByte(UnsafeCell::new(0xc3));

/// Call into `.data` and require the fetch to fault.
fn data_refuses_fetch(c: &dyn EarlyConsole, data: (u64, u64)) -> bool {
    #[allow(clippy::as_conversions)]
    let target = RET_IN_DATA.0.get() as usize;
    c.write_str(", data ");
    #[allow(clippy::as_conversions)]
    let inside = (data.0..data.1).contains(&(target as u64));
    if !inside {
        c.write_str("probe byte is not in .data");
        return false;
    }
    // SAFETY: `target` is a live byte holding `ret`, a complete function under the C ABI:
    // it touches no register it must preserve and leaves the stack as it found it. The
    // conversion is the reviewed transmute `paging::check_no_execute` also documents.
    let f: extern "C" fn() = unsafe { core::mem::transmute::<usize, extern "C" fn()>(target) };
    paging::arm(target, 0, NO_EXECUTE);
    f();
    let trapped = paging::disarm();
    let restored = paging::edit_live_leaf(target, NO_EXECUTE, 0);
    let still_nx = paging::live_leaf_bits(target).is_some_and(|e| e & NO_EXECUTE != 0);

    // P | I/D, supervisor.
    const EXPECTED: u64 = 0b1_0001;
    match trapped {
        Some(EXPECTED) if restored && still_nx => {
            c.write_str("fetch #PF err ");
            write_hex(c, EXPECTED, 2);
            true
        }
        Some(code) => {
            c.write_str("WRONG: err ");
            write_hex(c, code, 2);
            c.write_str(if still_nx {
                ""
            } else {
                ", and left executable"
            });
            false
        }
        None => {
            c.write_str("FETCH ALLOWED");
            false
        }
    }
}

// ---------------------------------------------------------------------------
// The guard page
// ---------------------------------------------------------------------------

/// Whether `addr` is inside the boot stack's guard page.
fn in_guard(addr: u64) -> bool {
    let (start, end) = crate::image_sections().stack_guard;
    start < end && (start..end).contains(&addr)
}

/// Called by the exception reporter after it has printed a fatal fault.
///
/// A page fault or double fault whose CR2 is in a guard page is a stack overflow, and
/// the report says whose, because "#PF at some address in the kernel image" is a much
/// less useful sentence. A page fault in page 0 is a null dereference. While a fault is
/// being provoked this is also the verdict: the run passes only if the fault is the one
/// expected, and anything else fails at once instead of waiting for a timeout.
pub(crate) fn after_fault_report(c: &dyn EarlyConsole, vector: Option<u8>, cr2: u64) {
    let overflow = matches!(vector, Some(8) | Some(14));
    let hit = if overflow && in_guard(cr2) {
        Hit::BootGuard
    } else if let Some(slot) = crate::image_sections().thread_stacks.guard_hit(cr2) {
        if overflow {
            Hit::ThreadGuard(slot)
        } else {
            Hit::Nothing
        }
    } else if vector == Some(14) && cr2 < X86_64::PAGE_SIZE as u64 {
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
    if matches!(hit, Hit::BootGuard | Hit::ThreadGuard(_)) && vector == Some(8) {
        c.write_str(", reported from the #DF IST stack");
    }
    if hit != Hit::Nothing {
        c.write_str("\n");
    }
    verdict(c, hit);
}

/// Overflow the boot stack until it reaches the guard page.
///
/// Does not return. With the kernel space live the recursion faults on the guard page and
/// the exception path concludes the run; see [`after_fault_report`]. If it ever did return
/// the guard page protected nothing, and that is reported as a failure.
pub fn provoke_guard_fault() -> ! {
    EXPECTING.store(EXPECT_BOOT_GUARD, Ordering::SeqCst);
    let depth = descend(0);
    let _ = depth;
    conclude(false)
}

/// Recurse without end, keeping every frame alive.
///
/// Not a tail call, because the result is combined with a local after the call returns,
/// and the local goes through `black_box` so the frame cannot be optimised down to
/// nothing. Each level costs a little over 128 bytes of stack.
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
    let mut boot = <X86_64 as HasContextSwitch>::Context::default();
    let mut thread = <X86_64 as HasContextSwitch>::Context::default();
    // SAFETY: `top` is the top of a stack slot claimed just now, mapped read-write and used
    // by nothing else. `boot` is a local of this function, which never returns, so it
    // outlives the switch. Nothing switches back.
    unsafe {
        <X86_64 as HasContextSwitch>::init(&mut thread, top, overflow_thread, 0);
        <X86_64 as HasContextSwitch>::switch(&mut boot, &thread);
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
    X86_64::halt()
}

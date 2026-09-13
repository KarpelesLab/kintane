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
//!    [`provoke_guard_fault`] overflows the boot stack on purpose, for the harness.
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
use core::sync::atomic::{AtomicBool, Ordering};

use hal::paging::DeviceWindow;
use hal::{Arch, EarlyConsole};

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

/// Set when [`provoke_guard_fault`] is overflowing the stack on purpose.
///
/// A plain flag is enough. It is set once, from the only running context, and read only
/// from a fault handler that context caused.
static EXPECTING: AtomicBool = AtomicBool::new(false);

/// Whether `addr` is inside the boot stack's guard page.
fn in_guard(addr: u64) -> bool {
    let (start, end) = crate::image_sections().stack_guard;
    start < end && (start..end).contains(&addr)
}

/// Called by the exception reporter after it has printed a fatal fault.
///
/// A page fault or double fault whose CR2 is in the guard page is a stack overflow, and
/// the report says so, because "#PF at some address in the kernel image" is a much less
/// useful sentence. While a guard fault is being provoked this is also the verdict: the
/// run passes only if the fault is that one, and anything else fails at once instead of
/// waiting for a timeout.
pub(crate) fn after_fault_report(c: &dyn EarlyConsole, vector: Option<u8>, cr2: u64) {
    let guard = matches!(vector, Some(8) | Some(14)) && in_guard(cr2);
    if guard {
        c.write_str("\nstack overflow: cr2 is in the guard page below the boot stack");
        if vector == Some(8) {
            c.write_str(", reported from the #DF IST stack");
        }
        c.write_str("\n");
    }
    if EXPECTING.load(Ordering::Relaxed) {
        c.write_str(if guard {
            "expected guard page fault: observed\n"
        } else {
            "expected guard page fault: this fault is not it\n"
        });
        conclude(guard)
    }
}

/// Overflow the boot stack until it reaches the guard page.
///
/// Does not return. With the kernel space live the recursion faults on the guard page and
/// the exception path concludes the run; see [`after_fault_report`]. If it ever did return
/// the guard page protected nothing, and that is reported as a failure.
pub fn provoke_guard_fault() -> ! {
    EXPECTING.store(true, Ordering::SeqCst);
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

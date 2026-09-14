//! What this port contributes to kernel memory layout: no address space, and stacks
//! that the MPU guards.
//!
//! There is no translation, so there is no kernel address space to build, and
//! [`device_windows`] is empty for the same reason as on riscv32. What there is instead
//! is a memory protection unit, which `mpu.rs` programs with one no-access region below
//! the boot stack and one below each thread-stack slot. So unlike riscv32, a thread that
//! overflows its stack here faults, and [`describe_guard`] lets the fault report say
//! whose stack it was.

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicUsize, Ordering};

use hal::KernAddr;
use hal::paging::DeviceWindow;

use crate::counter::write_dec;

/// Device memory to map once the kernel's own tables are live: none, since there are none.
pub fn device_windows() -> &'static [DeviceWindow] {
    &[]
}

/// Slots handed out so far. A stack is never given back.
static CLAIMED: AtomicUsize = AtomicUsize::new(0);

/// The most slots `link.ld` reserves.
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

/// A kernel thread stack from the image's thread-stack array, with an MPU-guarded region
/// below it once `mpu::enable` has run.
///
/// Returns `(slot, top, size)`, or `None` once every slot is taken.
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

/// If `addr` is in a stack guard, say which, and return true.
pub(crate) fn describe_guard(c: &dyn hal::EarlyConsole, addr: u64) -> bool {
    let s = crate::image_sections();
    if addr >= s.stack_guard.0 && addr < s.stack_guard.1 {
        c.write_str("\n  stack overflow: the address is in the guard below the boot stack");
        return true;
    }
    let t = s.thread_stacks;
    for slot in 0..t.count() {
        let Some((lo, hi)) = t.guard_range(slot) else {
            break;
        };
        if addr >= lo && addr < hi {
            c.write_str("\n  stack overflow: the address is in the guard below thread stack ");
            write_dec(c, slot as u64);
            // SAFETY: a read of a `&'static str` written before the slot's thread could run.
            let owner = unsafe { (*OWNERS.0.get()).get(slot).copied().unwrap_or("") };
            if !owner.is_empty() {
                c.write_str(" (");
                c.write_str(owner);
                c.write_str(")");
            }
            return true;
        }
    }
    false
}

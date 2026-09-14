//! The flat memory model's part of bring-up.
//!
//! Selected by `MM_FLAT`, alongside `model_paged.rs` for `MM_PAGED`; `main.rs` declares
//! one of the two as `model`, and both have the same functions. With no address
//! translation there is no kernel address space to build, nothing to page in on demand,
//! and no unmapped page for a test mode to fault on. What there is instead is the flat
//! region allocator, `mm::flat`, which this checks over the machine's real memory map.
//!
//! The checks that need an MMU report Skipped, not Passed: this image makes no claim
//! about them, and a boot log that said "ok" would be claiming one.

use arch::Cpu;
use boot_protocol::MemoryRegion;
use hal::EarlyConsole;
use mm::flat::Regions;

use crate::{Check, LOW_MEMORY, write_usize};

/// Nothing is installed: no page tables exist to reserve or re-check after the suite.
#[derive(Clone, Copy)]
pub struct Live {
    /// Always empty; present so `kmain` reserves the same list on every model.
    pub tables: (u64, u64),
}

impl Live {
    pub const NONE: Live = Live { tables: (0, 0) };

    /// Trivially true, and silent: there are no tables whose integrity could be checked.
    pub fn still_intact(self, _c: &dyn EarlyConsole) -> bool {
        true
    }
}

/// The banner's `paging` line.
pub fn write_translation(c: &dyn EarlyConsole) {
    c.write_str("none (flat memory model)");
}

/// No processes on a flat kernel, for the same reason as [`userspace_check`]. Each always
/// `Passed`, or empty.
pub fn process_reserve<F, L>(_frames: F, _live: L) -> Check {
    Check::Passed
}

pub fn process_region() -> (u64, u64) {
    (0, 0)
}

pub fn processes_check(_c: &dyn EarlyConsole) -> Check {
    Check::Passed
}

pub fn spawn_check(_c: &dyn EarlyConsole) -> Check {
    Check::Passed
}

pub fn waits_check(_c: &dyn EarlyConsole) -> Check {
    Check::Passed
}

pub fn linux_check(_c: &dyn EarlyConsole) -> Check {
    Check::Passed
}

/// No userspace on a flat kernel: USERSPACE depends on MM_PAGED. Always `Passed`.
pub fn userspace_check<F, L>(_c: &dyn EarlyConsole, _frames: F, _live: L) -> Check {
    Check::Passed
}

/// The banner's `pagetable` line.
pub fn paging_selftest(c: &dyn EarlyConsole) -> Check {
    c.write_str("skipped: no MMU, so there are no page tables");
    Check::Skipped
}

/// The banner's `modules` line.
pub fn module_check(
    c: &dyn EarlyConsole,
    _frames: &mut mm::phys::FrameAllocator<'static, Cpu>,
    _live: Live,
    _boot_arg: u64,
) -> Check {
    c.write_str("\n  modules    skipped: no MMU, so no protected module text");
    Check::Skipped
}

/// The banner's `demand` line.
pub fn demand_check(
    c: &dyn EarlyConsole,
    _frames: &mut mm::phys::FrameAllocator<'static, Cpu>,
    _live: Live,
) -> Check {
    c.write_str("\n  demand     skipped: no MMU, so nothing is paged in on demand");
    Check::Skipped
}

/// The stack-guard test modes, on a core whose Physical Memory Protection can make a
/// guard fault without an MMU.
///
/// Each touches a guard rather than overflowing into it: a machine-mode trap runs on the
/// stack it interrupts, so a real overflow would take its trap on the overflowed stack
/// with nowhere to escape to (see `arch::kspace`). The null-dereference mode needs page 0
/// unmapped, which only a paged kernel has, so the configuration refuses it here.
#[cfg(CONFIG_ARCH_HAS_PMP)]
pub fn test_modes(c: &dyn EarlyConsole, boot: Check) {
    if kconfig::STACK_GUARD_TEST {
        if boot == Check::Failed {
            crate::finish(false);
        }
        c.write_str("\n  touching the boot stack's guard region\n");
        arch::kspace::provoke_guard_fault();
    }
    if kconfig::THREAD_STACK_GUARD_TEST {
        if boot == Check::Failed {
            crate::finish(false);
        }
        c.write_str("\n  touching a kernel thread stack's guard region\n");
        arch::kspace::provoke_thread_guard_fault();
    }
}

/// No test mode here without an MMU or PMP to make a guard fault: the configuration
/// refuses them.
#[cfg(not(CONFIG_ARCH_HAS_PMP))]
pub fn test_modes(_c: &dyn EarlyConsole, _boot: Check) {}

/// Free-list entries for the check. The map's ranges, the holes the reservations cut, and
/// the two allocations below, with room to spare.
const RANGES: usize = 64;

/// A DMA-sized request at a device's alignment, and a thread-stack-sized one.
const REQUESTS: [(u64, u64); 2] = [(3 * 1024 + 7, 64), (28 * 1024, 16)];

/// The flat model's counterpart of the kernel address space: build the region allocator
/// from the memory map, less what is already in use, and prove it hands out aligned,
/// disjoint, in-bounds ranges and takes them back exactly.
///
/// The allocator is a boot check, not yet the kernel's: nothing after boot allocates
/// contiguous physical ranges, so nothing holds on to it.
pub fn kernel_space(
    c: &dyn EarlyConsole,
    _frames: &mut mm::phys::FrameAllocator<'_, Cpu>,
    map: &[MemoryRegion],
    _boot_arg: u64,
) -> (Check, Live) {
    let live = Live::NONE;
    c.write_str("\n  flat       ");

    let mut regions = match Regions::<RANGES>::from_map(map) {
        Ok(r) => r,
        Err(_) => {
            c.write_str("the memory map does not fit a region list");
            return (Check::Failed, live);
        }
    };
    let (img_start, img_end) = arch::image_range();
    let reserved = regions
        .reserve(0, LOW_MEMORY)
        .and_then(|low| Ok(low + regions.reserve(img_start, img_end - img_start)?));
    let Ok(reserved) = reserved else {
        c.write_str("cannot reserve the image");
        return (Check::Failed, live);
    };
    let baseline = Snapshot::of(regions.ranges());
    let before = regions.free_bytes();

    write_usize(c, regions.ranges().len());
    c.write_str(" ranges, ");
    write_usize(c, (before / 1024) as usize);
    c.write_str(" KiB free, ");
    write_usize(c, (reserved / 1024) as usize);
    c.write_str(" KiB reserved; ");

    let mut got = [0u64; REQUESTS.len()];
    for (slot, &(len, align)) in got.iter_mut().zip(REQUESTS.iter()) {
        let Ok(at) = regions.alloc(len, align) else {
            c.write_str("allocation refused");
            return (Check::Failed, live);
        };
        *slot = at;
    }

    // Aligned, inside RAM the map called usable and outside the image, and disjoint.
    let usable = |at: u64, len: u64| {
        map.iter().any(|r| {
            r.kind == boot_protocol::MemoryKind::Usable as u32
                && at >= r.start
                && at + len <= r.start + r.len
        })
    };
    let in_image = |at: u64, len: u64| at < img_end && img_start < at + len;
    let mut ok = true;
    for (i, (&at, &(len, align))) in got.iter().zip(REQUESTS.iter()).enumerate() {
        if at % align != 0 || !usable(at, len) || in_image(at, len) {
            ok = false;
        }
        for (&other, &(other_len, _)) in got[i + 1..].iter().zip(REQUESTS[i + 1..].iter()) {
            if at < other + other_len && other < at + len {
                ok = false;
            }
        }
    }
    let taken: u64 = REQUESTS.iter().map(|(len, _)| len).sum();
    let accounted = regions.free_bytes() == before - taken;

    for (&at, &(len, _)) in got.iter().zip(REQUESTS.iter()) {
        if regions.free(at, len).is_err() {
            ok = false;
        }
    }
    let double_free_refused = regions.free(got[0], REQUESTS[0].0).is_err();
    let restored = regions.ranges() == baseline.as_slice() && regions.check();

    write_usize(c, REQUESTS.len());
    c.write_str(" ranges allocated and freed");
    if !ok {
        c.write_str(", MISPLACED");
    }
    if !accounted {
        c.write_str(", BOOKKEEPING WRONG");
    }
    if !double_free_refused {
        c.write_str(", DOUBLE FREE ACCEPTED");
    }
    if !restored {
        c.write_str(", NOT RESTORED");
    }
    let all = ok && accounted && double_free_refused && restored;
    c.write_str(if all { " ok" } else { " FAILED" });
    (Check::from_ok(all), live)
}

/// A copy of a free list, to compare against after the frees, without an allocator to
/// put a `Vec` in.
struct Snapshot {
    ranges: [(u64, u64); RANGES],
    len: usize,
}

impl Snapshot {
    fn of(ranges: &[(u64, u64)]) -> Snapshot {
        let mut s = Snapshot {
            ranges: [(0, 0); RANGES],
            len: ranges.len().min(RANGES),
        };
        s.ranges[..s.len].copy_from_slice(&ranges[..s.len]);
        s
    }

    fn as_slice(&self) -> &[(u64, u64)] {
        &self.ranges[..self.len]
    }
}

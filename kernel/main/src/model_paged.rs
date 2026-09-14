//! The paged memory model's part of bring-up.
//!
//! Selected by `MM_PAGED`, alongside `model_flat.rs` for `MM_FLAT`; `main.rs` declares
//! one of the two as `model`. Everything here needs an MMU: building, checking and
//! installing the kernel's own address space, demand paging, and the test modes that
//! provoke a fault on an unmapped page. It was moved out of `main.rs` unchanged when the
//! first port without an MMU arrived, so what a paged image does and prints is what it
//! did before.

use arch::Cpu;
use boot_protocol::{MemoryKind, MemoryRegion};
use hal::{EarlyConsole, HasMmu, HasPageTables};

use crate::{Check, DIRECT_MAP_MAX, demand, finish, modules, space, write_hex, write_usize};

/// The translation this image runs under, for the banner's `paging` line.
pub fn write_translation(c: &dyn EarlyConsole) {
    write_usize(c, <Cpu as HasMmu>::LEVELS as usize);
    c.write_str(" levels");
}

/// The architecture's paging selftest, for the banner's `pagetable` line.
pub fn paging_selftest(c: &dyn EarlyConsole) -> Check {
    let paging_ok = arch::paging_selftest(c);
    c.write_str(if paging_ok { " ok" } else { "" });
    Check::from_ok(paging_ok)
}

/// The native userspace slice: build a process, enter ring 3, grade it by its exit code.
/// Passed when USERSPACE is off, so `memory()` calls it unconditionally. Two definitions
/// keep the `cfg` at item level.
#[cfg(CONFIG_USERSPACE)]
pub fn userspace_check(
    c: &dyn EarlyConsole,
    frames: &mut mm::phys::FrameAllocator<'static, Cpu>,
    live: Live,
) -> Check {
    crate::userproc::check(c, frames, live)
}

#[cfg(not(CONFIG_USERSPACE))]
pub fn userspace_check(
    c: &dyn EarlyConsole,
    frames: &mut mm::phys::FrameAllocator<'static, Cpu>,
    live: Live,
) -> Check {
    let _ = (c, frames, live);
    Check::Passed
}

/// Take the frames the scheduled processes are built from, while the boot allocator is
/// alive. Passed when USERSPACE is off.
#[cfg(CONFIG_USERSPACE)]
pub fn process_reserve(frames: &mut mm::phys::FrameAllocator<'static, Cpu>, live: Live) -> Check {
    match live.direct {
        Some(direct) => Check::from_ok(crate::procs::reserve(frames, direct)),
        None => Check::Skipped,
    }
}

#[cfg(not(CONFIG_USERSPACE))]
pub fn process_reserve(frames: &mut mm::phys::FrameAllocator<'static, Cpu>, live: Live) -> Check {
    let _ = (frames, live);
    Check::Passed
}

/// The physical run [`process_reserve`] took, `(0, 0)` when there is none.
#[cfg(CONFIG_USERSPACE)]
pub fn process_region() -> (u64, u64) {
    crate::procs::region()
}

#[cfg(not(CONFIG_USERSPACE))]
pub fn process_region() -> (u64, u64) {
    (0, 0)
}

/// Several processes at once on the scheduler. Passed when USERSPACE is off.
#[cfg(CONFIG_USERSPACE)]
pub fn processes_check(c: &dyn EarlyConsole) -> Check {
    crate::procs::check(c)
}

#[cfg(not(CONFIG_USERSPACE))]
pub fn processes_check(c: &dyn EarlyConsole) -> Check {
    let _ = c;
    Check::Passed
}

/// The stress run's user-process cycle: claim the stack its process thread runs on.
/// Nothing to do, and `Ok`, without USERSPACE.
#[cfg(CONFIG_USERSPACE)]
pub fn process_stress_setup() -> Result<(), &'static str> {
    crate::procs::stress_setup()
}

#[cfg(not(CONFIG_USERSPACE))]
pub fn process_stress_setup() -> Result<(), &'static str> {
    Ok(())
}

/// Create a user process, move its thread across the CPUs, and destroy it, checking its
/// memory and every frame. `Ok` without USERSPACE.
#[cfg(CONFIG_USERSPACE)]
pub fn process_stress_cycle(round: u64) -> Result<(), &'static str> {
    crate::procs::stress_cycle(round)
}

#[cfg(not(CONFIG_USERSPACE))]
pub fn process_stress_cycle(round: u64) -> Result<(), &'static str> {
    let _ = round;
    Ok(())
}

/// User processes the stress run has created and destroyed.
#[cfg(CONFIG_USERSPACE)]
pub fn process_stress_cycles() -> u64 {
    crate::procs::stress_cycles()
}

/// The longest a cycle waited for its thread on the CPU it pinned it to, in microseconds.
#[cfg(CONFIG_USERSPACE)]
pub fn process_stress_serve_worst_us() -> u64 {
    crate::procs::stress_serve_worst_us()
}

#[cfg(not(CONFIG_USERSPACE))]
pub fn process_stress_serve_worst_us() -> u64 {
    0
}

#[cfg(not(CONFIG_USERSPACE))]
pub fn process_stress_cycles() -> u64 {
    0
}

/// Demand paging over a window of the live kernel space.
pub fn demand_check(
    c: &dyn EarlyConsole,
    frames: &mut mm::phys::FrameAllocator<'static, Cpu>,
    live: Live,
) -> Check {
    demand::check(c, frames, live)
}

/// Load, call and unload the test modules, and refuse the ones built for another kernel.
pub fn module_check(
    c: &dyn EarlyConsole,
    frames: &mut mm::phys::FrameAllocator<'static, Cpu>,
    live: Live,
    boot_arg: u64,
) -> Check {
    modules::check(c, frames, live, boot_arg)
}

/// Run the test mode the configuration names, if any. Each ends the run, so this returns
/// only when none is enabled.
pub fn test_modes(c: &dyn EarlyConsole, boot: Check) {
    // A test mode that ends the run from the fault handler. Only on a machine that came
    // up cleanly: an overflow on tables that failed verification proves nothing.
    if kconfig::STACK_GUARD_TEST {
        if boot == Check::Failed {
            finish(false);
        }
        c.write_str("\n  overflowing the boot stack into its guard page\n");
        arch::kspace::provoke_guard_fault();
    }
    if kconfig::THREAD_STACK_GUARD_TEST {
        if boot == Check::Failed {
            finish(false);
        }
        c.write_str("\n  overflowing a kernel thread's stack into its guard page\n");
        arch::kspace::provoke_thread_guard_fault();
    }
    if kconfig::NULL_DEREF_TEST {
        if boot == Check::Failed {
            finish(false);
        }
        c.write_str("\n  reading through a null pointer\n");
        arch::kspace::provoke_null_dereference();
    }
}

/// The kernel address space as installed, for checks made after bring-up.
#[derive(Clone, Copy)]
pub struct Live {
    /// Frames the tables occupy, `[lo, hi)`. Empty when nothing was installed.
    pub tables: (u64, u64),
    /// The direct map the tables are reached through, when they were installed.
    pub direct: Option<mm::DirectMap>,
}

impl Live {
    pub const NONE: Live = Live {
        tables: (0, 0),
        direct: None,
    };

    /// Whether the installed tables still say what they said at bring-up. Trivially true
    /// when nothing was installed, which the bring-up verdict has already failed.
    pub fn still_intact(self, c: &dyn EarlyConsole) -> bool {
        let Some(direct) = self.direct else {
            return true;
        };
        c.write_str("  kspace     after the suite: ");
        let ok = space::check_live::<Cpu>(c, direct, arch::image_sections());
        c.write_str(if ok { " ok\n" } else { " DAMAGED\n" });
        ok
    }
}

/// Build the kernel's own address space, check it, and install it.
///
/// Returns the verdict and what was installed. Nothing is installed unless every check
/// of the built tables passed.
pub fn kernel_space(
    c: &dyn EarlyConsole,
    frames: &mut mm::phys::FrameAllocator<'_, Cpu>,
    map: &[MemoryRegion],
    boot_arg: u64,
) -> (Check, Live) {
    c.write_str("\n  kspace     ");

    // The direct map spans where RAM actually is, not `[0, top)`. An earlier version
    // assumed memory starts at physical zero, which is true on a PC and false on
    // aarch64, where RAM begins at 1 GiB: `[0, 1 GiB)` then contained no RAM at all, and
    // the first page table allocation failed with nothing to allocate from.
    let usable = || map.iter().filter(|r| r.kind == MemoryKind::Usable as u32);
    let Some(lo) = usable().map(|r| r.start).min() else {
        c.write_str("no usable memory");
        return (Check::Failed, Live::NONE);
    };
    let hi = usable().map(|r| r.start + r.len).max().unwrap_or(lo);
    let len = (hi - lo).min(DIRECT_MAP_MAX);
    if len == 0 {
        c.write_str("no usable memory");
        return (Check::Failed, Live::NONE);
    }

    let base = hal::PhysAddr::new(lo);
    let virt = match usize::try_from(lo) {
        Ok(v) => hal::KernAddr::new(v),
        Err(_) => {
            c.write_str("RAM starts above the addressable range");
            return (Check::Failed, Live::NONE);
        }
    };
    let direct = match mm::DirectMap::new(base, virt, len) {
        Ok(d) => d,
        Err(_) => {
            c.write_str("direct map rejected");
            return (Check::Failed, Live::NONE);
        }
    };

    // The loader's structure is read again after the switch, by the in-kernel suite, so
    // it has to be inside the space. Zero means there is no such pointer on this port.
    let boot_data = [boot_arg];
    let must_reach: &[u64] = if boot_arg == 0 { &[] } else { &boot_data };
    let sections = arch::image_sections();
    let Some(devices) = platform::device_windows() else {
        // Without them the switch would unmap the console on a port whose console is a
        // device, and nothing could report what happened next.
        c.write_str("no device windows (device discovery failed), not installed");
        return (Check::Failed, Live::NONE);
    };
    let Some(built) =
        space::build_and_verify::<Cpu>(c, frames, direct, sections, devices, must_reach)
    else {
        c.write_str(" FAILED, not installed");
        return (Check::Failed, Live::NONE);
    };
    c.write_str(" ok");

    c.write_str("\n  live       ");
    let root = built.space.root();
    // SAFETY: `build_and_verify` returned the space only after walking it and confirming
    // that it maps the image with its sections' permissions, the boot stack, the whole
    // direct map (which holds the frame allocator's bitmap and these tables), every
    // device window the port names, and the boot data. The code running now is in
    // `.text`, the stack is the boot stack, and interrupts are masked, so the instruction
    // after the switch is fetchable and nothing can be delivered against a stale map.
    // Nothing is ever freed from this space: it is the kernel's for the life of the
    // machine, so dropping the handle below leaks nothing that should be reclaimed.
    unsafe { built.space.activate() };
    let installed = <Cpu as HasPageTables>::root() == root;
    let live = Live {
        tables: built.tables,
        direct: Some(direct),
    };
    c.write_str(if installed {
        "root "
    } else {
        "ROOT READ BACK WRONG "
    });
    write_hex(c, root.raw());
    if !installed {
        // Nothing below means anything on tables that are not ours, and the hardware
        // probes edit whatever table is live.
        return (Check::Failed, live);
    }
    c.write_str(", ");
    let walked = space::check_live::<Cpu>(c, direct, sections);
    c.write_str("\n             ");
    let enforced = arch::kspace::enforcement_selftest(c);
    (Check::from_ok(walked && enforced), live)
}

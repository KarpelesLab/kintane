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

/// A program creating a program: `init` builds a process out of an image and talks to it.
/// Passed when USERSPACE is off.
#[cfg(CONFIG_USERSPACE)]
pub fn spawn_check(c: &dyn EarlyConsole) -> Check {
    crate::spawn::check(c)
}

#[cfg(not(CONFIG_USERSPACE))]
pub fn spawn_check(c: &dyn EarlyConsole) -> Check {
    let _ = c;
    Check::Passed
}

#[cfg(not(CONFIG_USERSPACE))]
pub fn processes_check(c: &dyn EarlyConsole) -> Check {
    let _ = c;
    Check::Passed
}

/// A channel looked up by one thread and closed by another lives until the lookup lets go.
/// Passed when USERSPACE is off.
#[cfg(CONFIG_USERSPACE)]
pub fn channels_check(c: &dyn EarlyConsole) -> Check {
    crate::channels::check(c)
}

#[cfg(not(CONFIG_USERSPACE))]
pub fn channels_check(c: &dyn EarlyConsole) -> Check {
    let _ = c;
    Check::Passed
}

/// Blocking waits, events, timers, two threads in one process, and a file read through a
/// service over a channel. Passed when USERSPACE is off.
#[cfg(CONFIG_USERSPACE)]
pub fn waits_check(c: &dyn EarlyConsole) -> Check {
    crate::waits::check(c)
}

#[cfg(not(CONFIG_USERSPACE))]
pub fn waits_check(c: &dyn EarlyConsole) -> Check {
    let _ = c;
    Check::Passed
}

/// A process ends while another of its threads spins in user mode, and that thread is stopped.
/// Passed when USERSPACE is off.
#[cfg(CONFIG_USERSPACE)]
pub fn sibling_check(c: &dyn EarlyConsole) -> Check {
    crate::sibling::check(c)
}

#[cfg(not(CONFIG_USERSPACE))]
pub fn sibling_check(c: &dyn EarlyConsole) -> Check {
    let _ = c;
    Check::Passed
}

/// The card's interrupt handler has run the stack: wake whoever waits on the network. Nothing
/// does without userspace.
#[cfg(CONFIG_USERSPACE)]
pub fn network_changed() {
    crate::sockets::wake_from_interrupt();
}

#[cfg(not(CONFIG_USERSPACE))]
pub fn network_changed() {}

/// Wait for the network to change, or for the stack's next TCP timer, as a socket call does.
/// `false`, having waited for nothing, where nothing would wake the wait.
#[cfg(CONFIG_USERSPACE)]
pub fn await_network(seen: crate::net::Seen) -> bool {
    crate::sockets::await_activity(seen)
}

#[cfg(not(CONFIG_USERSPACE))]
pub fn await_network(seen: crate::net::Seen) -> bool {
    let _ = seen;
    false
}

/// Network waits woken by the card's handler, armed for a TCP timer, and armed on a fixed
/// interval, for the heartbeat. `None` where the handler does not run the stack.
#[cfg(CONFIG_USERSPACE)]
pub fn network_wakes() -> Option<(u64, u64, u64)> {
    crate::net::by_interrupt().then(|| {
        let w = crate::sockets::wakes();
        (w.woken, w.timers, w.polls)
    })
}

#[cfg(not(CONFIG_USERSPACE))]
pub fn network_wakes() -> Option<(u64, u64, u64)> {
    None
}

/// A native program talking TCP through the socket calls. Passed when USERSPACE is off.
#[cfg(CONFIG_USERSPACE)]
pub fn sockets_check(c: &dyn EarlyConsole) -> Check {
    crate::sockets::check(c)
}

#[cfg(not(CONFIG_USERSPACE))]
pub fn sockets_check(c: &dyn EarlyConsole) -> Check {
    let _ = c;
    Check::Passed
}

/// The Linux program's socket modes: a TCP client, and a server kbuild connects to. Passed,
/// silently, without the personality.
#[cfg(CONFIG_USERSPACE)]
pub fn linux_sockets_check(c: &dyn EarlyConsole) -> Check {
    crate::personality::sockets_check(c)
}

#[cfg(not(CONFIG_USERSPACE))]
pub fn linux_sockets_check(c: &dyn EarlyConsole) -> Check {
    let _ = c;
    Check::Passed
}

/// The Linux program again, with the scheduler: pipes, `fork`, `execve`, `wait4`, a thread
/// and a futex. Passed, silently, without the personality.
#[cfg(CONFIG_USERSPACE)]
pub fn linux_check(c: &dyn EarlyConsole) -> Check {
    crate::personality::scheduled_check(c)
}

#[cfg(not(CONFIG_USERSPACE))]
pub fn linux_check(c: &dyn EarlyConsole) -> Check {
    let _ = c;
    Check::Passed
}

/// The standing file server serves a second process after the check that started it has
/// ended. Passed when USERSPACE is off.
#[cfg(CONFIG_USERSPACE)]
pub fn files_check(c: &dyn EarlyConsole) -> Check {
    crate::fileserver::check(c)
}

#[cfg(not(CONFIG_USERSPACE))]
pub fn files_check(c: &dyn EarlyConsole) -> Check {
    let _ = c;
    Check::Passed
}

/// The file server writes the disk for a process on a writable connection and refuses it on a
/// read-only one. Passed when USERSPACE is off.
#[cfg(CONFIG_USERSPACE)]
pub fn files_write_check(c: &dyn EarlyConsole) -> Check {
    crate::fileserver::write_check(c)
}

#[cfg(not(CONFIG_USERSPACE))]
pub fn files_write_check(c: &dyn EarlyConsole) -> Check {
    let _ = c;
    Check::Passed
}

/// Run a process whose second thread spins in user mode on another CPU, end it, and require
/// the spinner stopped. `Ok` without USERSPACE.
#[cfg(CONFIG_USERSPACE)]
pub fn sibling_stress_cycle(round: u64) -> Result<(), &'static str> {
    crate::sibling::stress_cycle(round)
}

#[cfg(not(CONFIG_USERSPACE))]
pub fn sibling_stress_cycle(round: u64) -> Result<(), &'static str> {
    let _ = round;
    Ok(())
}

/// Two Linux processes on one CPU, each checking its own thread pointer. `Ok` without the
/// personality.
#[cfg(CONFIG_USERSPACE)]
pub fn linux_stress_cycle(round: u64) -> Result<(), &'static str> {
    crate::personality::stress_cycle(round)
}

#[cfg(not(CONFIG_USERSPACE))]
pub fn linux_stress_cycle(round: u64) -> Result<(), &'static str> {
    let _ = round;
    Ok(())
}

/// The stress run's waiting-process cycle: claim the second stack its threads run on.
/// Nothing to do, and `Ok`, without USERSPACE.
#[cfg(CONFIG_USERSPACE)]
pub fn wait_stress_setup() -> Result<(), &'static str> {
    crate::waits::stress_setup()
}

#[cfg(not(CONFIG_USERSPACE))]
pub fn wait_stress_setup() -> Result<(), &'static str> {
    Ok(())
}

/// Run a two-threaded process whose threads wake each other across CPUs, and destroy it.
/// `Ok` without USERSPACE.
#[cfg(CONFIG_USERSPACE)]
pub fn wait_stress_cycle(round: u64) -> Result<(), &'static str> {
    crate::waits::stress_cycle(round)
}

#[cfg(not(CONFIG_USERSPACE))]
pub fn wait_stress_cycle(round: u64) -> Result<(), &'static str> {
    let _ = round;
    Ok(())
}

/// The waiting-process part of the stress heartbeat. Nothing without USERSPACE.
#[cfg(CONFIG_USERSPACE)]
pub fn wait_stress_heartbeat(c: &dyn EarlyConsole) {
    let cycles = crate::waits::stress_cycles();
    if cycles == 0 {
        return;
    }
    let s = crate::wait::stats();
    c.write_str(", waiting processes ");
    crate::write_usize(c, cycles as usize);
    c.write_str(" (blocks ");
    crate::write_usize(c, s.blocks as usize);
    c.write_str(", cross-CPU wakes ");
    crate::write_usize(c, s.cross_cpu_wakes as usize);
    c.write_str(", timeouts ");
    crate::write_usize(c, s.timeouts as usize);
    c.write_str(")");
    let siblings = crate::sibling::stress_cycles();
    if siblings > 0 {
        c.write_str(", spinning siblings stopped ");
        crate::write_usize(c, siblings as usize);
        c.write_str(" (from an interrupt ");
        crate::write_usize(c, crate::userproc::interrupt_kills() as usize);
        c.write_str(")");
    }
    let linux = crate::personality::stress_cycles();
    if linux != 0 {
        c.write_str(", linux pairs ");
        crate::write_usize(c, linux as usize);
    }
    let churns = crate::personality::churn_cycles();
    if churns != 0 {
        c.write_str(", churning pairs ");
        crate::write_usize(c, churns as usize);
    }
}

#[cfg(not(CONFIG_USERSPACE))]
pub fn wait_stress_heartbeat(c: &dyn EarlyConsole) {
    let _ = c;
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

/// The most slices any of the process cycles' waits ran and was passed over for before it
/// succeeded.
#[cfg(CONFIG_USERSPACE)]
pub fn process_stress_slices_worst() -> (u64, u64) {
    crate::procs::stress_slices_worst()
}

#[cfg(not(CONFIG_USERSPACE))]
pub fn process_stress_slices_worst() -> (u64, u64) {
    (0, 0)
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
    c.write_str(", ");
    let user_half = user_half_check(c, direct);
    c.write_str("\n             ");
    let enforced = arch::kspace::enforcement_selftest(c);
    (Check::from_ok(walked && enforced && user_half), live)
}

/// Whether the live kernel tables leave the user half empty, on a configuration with one.
///
/// A process root mirrors every top-level entry of the kernel's, so anything the kernel maps
/// in the user half is shared by every process: a page table all of them build into. Device
/// windows once landed there, mapped at a physical address firmware had put at 768 GiB.
/// They are mapped in the device window now, and this is what says so on every boot.
#[cfg(CONFIG_USERSPACE)]
fn user_half_check(c: &dyn EarlyConsole, direct: mm::DirectMap) -> bool {
    let clear = crate::userproc::user_half_clear(direct, <Cpu as HasPageTables>::root());
    c.write_str(if clear {
        "user half clear"
    } else {
        "the kernel maps something in the USER HALF"
    });
    clear
}

#[cfg(not(CONFIG_USERSPACE))]
fn user_half_check(c: &dyn EarlyConsole, direct: mm::DirectMap) -> bool {
    let _ = direct;
    c.write_str("no user half on this configuration");
    true
}

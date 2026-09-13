//! Secondary CPUs: which exist and how firmware starts them, from the tree, and the checks
//! that each one that came up is really a CPU of its own.
//!
//! `arch::smp` is the mechanism: PSCI calls, per-CPU blocks, IPIs. This module is the
//! part that needs the device tree, which `arch` may not read, and the part that needs
//! `sync`, which `arch` may not depend on. So the proof that per-CPU data, per-CPU lock
//! order and IPIs work across real CPUs lives here, one layer above both.

use core::sync::atomic::{AtomicU64, Ordering};

use arch::Cpu;
use arch::smp::{self, Conduit, StartError};
use device::{BootCell, DeviceTree};
use hal::{EarlyConsole, HasSmp};
use sync::lockdep::{self, LockClass};
use sync::{PerCpu, Pinned, SpinLock};

use crate::{write_hex, write_usize};

/// CPU nodes recorded from the tree. More than this are counted and not started.
const MAX_TREE_CPUS: usize = 32;

/// What the tree says about CPUs, recorded by [`record`] during discovery.
#[derive(Clone, Copy)]
struct Topology {
    /// Each available `cpu` node's hardware ID, and whether its `enable-method` is PSCI.
    cpus: [(u64, bool); MAX_TREE_CPUS],
    /// Every available `cpu` node, including any past `cpus`' capacity.
    count: usize,
    /// A `cpu` node whose `reg` could not be read.
    unreadable: bool,
    /// How the PSCI node says firmware is called.
    conduit: Option<Conduit>,
    /// The `CPU_ON` function ID the PSCI node gives, for the pre-0.2 binding, whose IDs
    /// were not standard. `None` for 0.2 and later, where the standard ID is mandatory.
    cpu_on: Option<u64>,
}

static TOPOLOGY: BootCell<Topology> = BootCell::new();

/// Read `/cpus` and the PSCI node.
///
/// # Safety
/// Once, on the single-threaded boot path, as `discover` is.
pub(crate) unsafe fn record(tree: &DeviceTree<'_, '_>) {
    let mut t = Topology {
        cpus: [(0, false); MAX_TREE_CPUS],
        count: 0,
        unreadable: false,
        conduit: None,
        cpu_on: None,
    };
    if let Some(cpus) = tree.find(b"/cpus") {
        // `cpu-map` and other bookkeeping nodes sit beside the CPUs; `device_type` is what
        // makes a node a CPU (Devicetree Specification §3.8).
        for c in tree.children(cpus) {
            if tree.string(c, b"device_type") != Some(b"cpu") || !tree.node(c).is_available() {
                continue;
            }
            match tree.reg_address(c, 0) {
                Ok(id) => {
                    let psci = tree.string(c, b"enable-method") == Some(b"psci");
                    if let Some(slot) = t.cpus.get_mut(t.count) {
                        *slot = (id, psci);
                    }
                    t.count += 1;
                }
                Err(_) => t.unreadable = true,
            }
        }
    }
    let modern = |id| {
        let n = tree.node(id);
        n.is_compatible("arm,psci-0.2") || n.is_compatible("arm,psci-1.0")
    };
    if let Some(psci) = tree
        .ids()
        .find(|&id| modern(id) || tree.node(id).is_compatible("arm,psci"))
    {
        t.conduit = match tree.string(psci, b"method") {
            Some(b"hvc") => Some(Conduit::Hvc),
            Some(b"smc") => Some(Conduit::Smc),
            _ => None,
        };
        if !modern(psci) {
            t.cpu_on = tree
                .property(psci, b"cpu_on")
                .and_then(|v| <[u8; 4]>::try_from(v).ok())
                .map(|b| u64::from(u32::from_be_bytes(b)));
        }
    }
    // SAFETY: the caller's contract is `BootCell::set`'s.
    let _ = unsafe { TOPOLOGY.set(t) };
}

/// Names the CPUs' stacks carry in a fault report.
const NAMES: [&str; smp::MAX_CPUS] = [
    "cpu 0", "cpu 1", "cpu 2", "cpu 3", "cpu 4", "cpu 5", "cpu 6", "cpu 7",
];

/// Start every CPU the tree lists, up to the configuration's limit, and prove each one
/// that came up is a CPU of its own. See [`crate::start_secondaries`].
///
/// # Safety
/// Once, from `kmain`, on the boot CPU with interrupts masked, after the kernel address
/// space and the interrupt controller are installed.
pub(crate) unsafe fn start_secondaries(c: &dyn EarlyConsole) -> Option<bool> {
    let Some(t) = TOPOLOGY.get() else {
        c.write_str("no CPU topology: the device tree was not read");
        return Some(false);
    };
    write_usize(c, t.count);
    c.write_str(" in the tree");

    // A run that asked QEMU for N CPUs and got another count is a harness failure, and
    // one that would otherwise pass an SMP check on a single CPU.
    let asked = kconfig::QEMU_SMP;
    let count_ok = asked == 0 || t.count == asked;
    if !count_ok {
        c.write_str(", THE RUN ASKED FOR ");
        write_usize(c, asked);
    }
    if !kconfig::SMP {
        c.write_str("; SMP=n, the others stay off");
        return if count_ok { None } else { Some(false) };
    }
    if t.unreadable {
        c.write_str("; A CPU NODE'S reg IS UNREADABLE");
        return Some(false);
    }

    let boot = smp::this_mpidr();
    let listed = t.cpus.iter().take(t.count).map(|&(id, _)| id);
    if !listed.clone().any(|id| id == boot) {
        c.write_str("; THE BOOT CPU ");
        write_hex(c, boot);
        c.write_str(" IS NOT IN IT");
        return Some(false);
    }

    // SAFETY: the caller's contract.
    if !unsafe { smp::prepare_boot_cpu() } {
        c.write_str("; the interrupt controller cannot send IPIs");
        return Some(false);
    }
    let Some(conduit) = t.conduit else {
        c.write_str("; NO PSCI CONDUIT");
        return Some(false);
    };

    let limit = kconfig::NR_CPUS.min(<Cpu as HasSmp>::MAX_CPUS);
    let mut ok = count_ok;
    let mut started = 1;
    let mut left_off = 0;
    for &(id, psci) in t.cpus.iter().take(t.count).filter(|&&(id, _)| id != boot) {
        if started >= limit {
            left_off += 1;
            continue;
        }
        if !psci {
            c.write_str("; CPU ");
            write_hex(c, id);
            c.write_str(" HAS NO PSCI enable-method");
            ok = false;
            continue;
        }
        let name = NAMES.get(started).copied().unwrap_or("cpu");
        // SAFETY: the caller's contract, `id` is a listed CPU other than this one, and
        // each logical index is used once: `started` moves on after every attempt, since a
        // CPU that timed out may still come up late on the block it was given.
        let result = unsafe { smp::start(started, id, conduit, t.cpu_on, name) };
        started += 1;
        if let Err(e) = result {
            c.write_str("; CPU ");
            write_hex(c, id);
            c.write_str(" DID NOT START: ");
            describe(c, e);
            ok = false;
        }
    }
    c.write_str("; ");
    write_usize(c, (0..started).filter(|&cpu| smp::is_online(cpu)).count());
    c.write_str(" online");
    if left_off > 0 {
        c.write_str(", ");
        write_usize(c, left_off);
        c.write_str(" past NR_CPUS left off");
    }

    ok &= ids(c, started);
    ok &= ticks(c, started);
    ok &= ipis(c, started);
    ok &= per_cpu_counters(c, started);
    ok &= lock_order_is_per_cpu(c, started);
    c.write_str(if ok { " ok" } else { " FAILED" });
    Some(ok)
}

fn describe(c: &dyn EarlyConsole, e: StartError) {
    match e {
        StartError::BadIndex => c.write_str("bad logical index"),
        StartError::NoStack => c.write_str("no thread-stack slot left"),
        StartError::NoController => c.write_str("no interrupt controller"),
        StartError::Firmware(status) => {
            c.write_str("PSCI status ");
            write_hex(c, status as u64);
        }
        StartError::Timeout => c.write_str("never reported in"),
        StartError::ControllerRefused => c.write_str("its interrupt controller refused it"),
    }
}

/// Every CPU, asked on itself, reports its own logical index through both interfaces.
///
/// The number is a pointer read from a banked register, so this is the check that each
/// CPU's `TPIDR_EL1` names its own block: two CPUs sharing a block agree on a number that
/// is right for at most one of them.
fn ids(c: &dyn EarlyConsole, cpus: usize) -> bool {
    c.write_str("; ids");
    let mut ok = true;
    for cpu in 0..cpus {
        let seen = smp::seen_ids(cpu);
        c.write_str(" ");
        match seen {
            Some((index, id)) if index == cpu && id as usize == cpu && smp::is_online(cpu) => {
                write_usize(c, cpu);
            }
            _ => {
                c.write_str("WRONG(");
                write_usize(c, cpu);
                c.write_str(")");
                ok = false;
            }
        }
    }
    ok
}

/// Timer interrupts every secondary has to have taken for its timer to count as its own.
const MIN_TICKS: u64 = 5;

/// Every secondary takes interrupts from its own generic timer.
fn ticks(c: &dyn EarlyConsole, cpus: usize) -> bool {
    let deadline = arch::timer::counter().saturating_add(arch::timer::frequency());
    let lowest = || (1..cpus).map(smp::ticks).min().unwrap_or(MIN_TICKS);
    while lowest() < MIN_TICKS && arch::timer::counter() < deadline {
        core::hint::spin_loop();
    }
    c.write_str("; ticks");
    let mut ok = true;
    for cpu in 1..cpus {
        c.write_str(" ");
        let n = smp::ticks(cpu);
        write_usize(c, n as usize);
        ok &= n >= MIN_TICKS;
    }
    if cpus == 1 {
        c.write_str(" (no secondary)");
    }
    ok
}

/// Runs on the target: says which CPU it ran on, and sends a reschedule IPI back.
fn echo(arg: u64) -> u64 {
    let _ = smp::send(0, smp::IPI_RESCHEDULE);
    ((<Cpu as hal::Arch>::cpu_index() as u64) << 32) | arg
}

/// A function-call IPI reaches each secondary, runs there, and an IPI comes back.
///
/// One secondary at a time, taking each reply before the next call. An SGI's pending state
/// is one bit per target, not per sender, so three CPUs raising the same SGI at a masked
/// CPU deliver it once. Found by doing it the other way first: three answered, one back.
fn ipis(c: &dyn EarlyConsole, cpus: usize) -> bool {
    let secondaries = cpus.saturating_sub(1);
    let mut answered = 0;
    let mut back = 0;
    for cpu in 1..cpus {
        let before = smp::reschedules(0);
        let arg = 0x1000 + cpu as u64;
        if smp::call(cpu, echo, arg) == Some(((cpu as u64) << 32) | arg) {
            answered += 1;
        }
        if take_interrupts_until(|| smp::reschedules(0) > before) {
            back += 1;
        }
    }
    c.write_str("; ipi ");
    write_usize(c, answered);
    c.write_str("/");
    write_usize(c, secondaries);
    c.write_str(" answered, ");
    write_usize(c, back);
    c.write_str(" back");
    answered == secondaries && back == secondaries
}

/// Unmask this CPU's interrupts until `done`, or for a second. Whether `done` came true.
///
/// `kmain` runs with interrupts masked, and the replies checked for are interrupts here.
fn take_interrupts_until(done: impl Fn() -> bool) -> bool {
    let deadline = arch::timer::counter().saturating_add(arch::timer::frequency());
    let irq = <Cpu as hal::Arch>::irq_save();
    // SAFETY: the vectors are installed and the only sources enabled on this CPU are the
    // two SGIs `prepare_boot_cpu` enabled, which have handlers; the tick is stopped.
    unsafe { arch::tick::enable_interrupts() };
    while !done() && arch::timer::counter() < deadline {
        core::hint::spin_loop();
    }
    // SAFETY: restores the mask `irq_save` found, which is `kmain`'s.
    unsafe { <Cpu as hal::Arch>::irq_restore(irq) };
    done()
}

/// One counter per CPU, in the storage `sync::percpu` sizes by the architecture.
static COUNTS: PerCpu<AtomicU64, { <Cpu as HasSmp>::MAX_CPUS }> =
    PerCpu::new::<Cpu>([const { AtomicU64::new(0) }; <Cpu as HasSmp>::MAX_CPUS]);

/// How many times CPU `cpu` bumps its counter: different for every CPU, so two CPUs on
/// one slot cannot come out right by adding up to the same total.
fn bumps_for(cpu: usize) -> u64 {
    100 * (cpu as u64 + 1)
}

/// Runs on the target: bump the running CPU's counter `times` times, pinned each time.
fn bump(times: u64) -> u64 {
    for _ in 0..times {
        let pin = Pinned::<Cpu>::new();
        if let Some(n) = COUNTS.get(&pin) {
            n.fetch_add(1, Ordering::Relaxed);
        }
    }
    times
}

/// Each CPU's counter holds its own count, and nobody else's.
fn per_cpu_counters(c: &dyn EarlyConsole, cpus: usize) -> bool {
    bump(bumps_for(0));
    for cpu in 1..cpus {
        let _ = smp::call(cpu, bump, bumps_for(cpu));
    }
    c.write_str("; percpu");
    let mut ok = true;
    for (cpu, slot) in COUNTS.iter().enumerate() {
        let want = if cpu < cpus { bumps_for(cpu) } else { 0 };
        let got = slot.load(Ordering::Relaxed);
        if cpu < cpus {
            c.write_str(" ");
            write_usize(c, got as usize);
        }
        ok &= got == want;
    }
    ok
}

static HELD_CLASS: LockClass = LockClass::new("smp.check.held");
static OTHER_CLASS: LockClass = LockClass::new("smp.check.other");
static HELD: SpinLock<(), Cpu> = SpinLock::with_class((), &HELD_CLASS);
static OTHER: SpinLock<(), Cpu> = SpinLock::with_class((), &OTHER_CLASS);

/// Runs on the target: take and release `OTHER`.
fn take_other(_: u64) -> u64 {
    drop(OTHER.lock());
    0
}

/// What one CPU holds is not recorded as held by another.
///
/// The boot CPU holds `HELD` while CPU 1 takes `OTHER`. The two never nest on any one CPU,
/// so no order between them exists. A held-lock stack shared between CPUs would record
/// "`OTHER` after `HELD`" all the same, and the boot CPU's legitimate `OTHER`-then-`HELD`
/// nesting that follows would then be reported as an inversion.
fn lock_order_is_per_cpu(c: &dyn EarlyConsole, cpus: usize) -> bool {
    c.write_str("; lockdep ");
    if !lockdep::ENABLED {
        c.write_str("off");
        return true;
    }
    if cpus < 2 {
        c.write_str("needs a second CPU");
        return true;
    }
    let before = lockdep::report::<Cpu>().count;
    let called = {
        let _held = HELD.lock();
        smp::call(1, take_other, 0).is_some()
    };
    {
        let _other = OTHER.lock();
        let _held = HELD.lock();
    }
    let found = lockdep::report::<Cpu>().count - before;
    let ok = called && found == 0;
    if !called {
        c.write_str("CALL LOST");
    } else if found != 0 {
        c.write_str("CROSS-CPU ORDER RECORDED");
    } else {
        c.write_str("per-cpu");
    }
    ok
}

//! Secondary CPUs on x86_64: which exist, from the MADT; starting them, with the local APIC
//! driver's INIT and startup IPIs around `arch::smp`'s trampoline; and the checks that each
//! one that came up is really a CPU of its own.
//!
//! The counterpart of `platform/fdt`'s `smp.rs`, and the same five checks, so the two ports
//! prove the same things. Two differ in how, not what. A secondary's timer is checked for its
//! rate as well as for ticking, over a window the TSC measures, because a local APIC timer is
//! calibrated by the kernel and can be wrong; the Arm generic timer's rate is firmware's. And
//! every wait is on the TSC.

use core::sync::atomic::{AtomicU64, Ordering};

use arch::Cpu;
use arch::smp::{self, StartError};
use hal::{EarlyConsole, HasSmp};
use sync::lockdep::{self, LockClass};
use sync::{PerCpu, Pinned, SpinLock};

use crate::{MADT, write_hex, write_usize};

/// Names the CPUs' stacks carry in a fault report.
const NAMES: [&str; smp::MAX_CPUS] = [
    "cpu 0", "cpu 1", "cpu 2", "cpu 3", "cpu 4", "cpu 5", "cpu 6", "cpu 7",
];

/// Start every enabled processor the MADT lists, up to the configuration's limit, and prove
/// each one that came up is a CPU of its own.
///
/// # Safety
/// As `crate::start_secondaries`.
pub(crate) unsafe fn start_secondaries(c: &dyn EarlyConsole) -> Option<bool> {
    let Some(facts) = MADT.get() else {
        c.write_str("no CPU topology: the MADT was not read");
        return Some(false);
    };
    write_usize(c, facts.cpu_count);
    c.write_str(" in the MADT");

    // A run that asked QEMU for N CPUs and got another count is a harness failure, and one
    // that would otherwise pass an SMP check on a single CPU.
    let asked = kconfig::QEMU_CPUS;
    let count_ok = asked == 0 || facts.cpu_count == asked;
    if !count_ok {
        c.write_str(", THE RUN ASKED FOR ");
        write_usize(c, asked);
    }
    if !kconfig::SMP {
        c.write_str("; SMP=n, the others stay off");
        return if count_ok { None } else { Some(false) };
    }
    let Some(chip) = apic::installed() else {
        c.write_str("; NO LOCAL APIC INSTALLED");
        return Some(false);
    };
    // SAFETY: the caller's contract.
    if !unsafe { smp::prepare_boot_cpu() } {
        c.write_str("; the interrupt controller cannot send IPIs");
        return Some(false);
    }
    let Some(boot) = smp::apic_id(0) else {
        c.write_str("; NO BOOT APIC ID");
        return Some(false);
    };
    if !facts.cpus().iter().any(|&(id, _)| id == boot) {
        c.write_str("; THE BOOT CPU ");
        write_hex(c, u64::from(boot));
        c.write_str(" IS NOT IN IT");
        return Some(false);
    }

    let limit = kconfig::NR_CPUS.min(<Cpu as HasSmp>::MAX_CPUS);
    let mut ok = count_ok;
    let mut started = 1;
    let mut left_off = 0;
    let others = facts
        .cpus()
        .iter()
        .filter(|&&(id, enabled)| id != boot && enabled);
    for &(id, _) in others {
        if started >= limit {
            left_off += 1;
            continue;
        }
        let cpu = started;
        let name = NAMES.get(cpu).copied().unwrap_or("cpu");
        // Each logical index is used once: `started` moves on after every attempt, since a
        // CPU that timed out may still come up late on the block it was given.
        started += 1;
        // SAFETY: the caller's contract, `id` is an enabled processor other than this one,
        // and this is the only CPU between `prepare` and `wait_online`.
        let vector = match unsafe { smp::prepare(cpu, id, name) } {
            Ok(v) => v,
            Err(e) => {
                report_start(c, id, e);
                ok = false;
                continue;
            }
        };
        let sent = chip.start_cpu(id, vector, &smp::delay_us, &|| smp::has_reported(cpu));
        if !sent {
            c.write_str("; CPU ");
            write_hex(c, u64::from(id));
            c.write_str(" REFUSED ITS INIT OR STARTUP IPI");
            ok = false;
            continue;
        }
        if let Err(e) = smp::wait_online(cpu) {
            report_start(c, id, e);
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

fn report_start(c: &dyn EarlyConsole, id: u32, e: StartError) {
    c.write_str("; CPU ");
    write_hex(c, u64::from(id));
    c.write_str(" DID NOT START: ");
    c.write_str(match e {
        StartError::BadIndex => "bad logical index",
        StartError::NoStack => "no thread-stack slot left",
        StartError::NoController => "no local APIC",
        StartError::NoTimer => "no local APIC timer",
        StartError::NoTrampolinePage => "the trampoline page is not mapped writable",
        StartError::TrampolineTooLarge => "the trampoline does not fit its page",
        StartError::Timeout => "never reported in",
        StartError::ControllerRefused => "its local APIC or timer refused it",
    });
}

/// Every CPU, asked on itself, reports its own logical index through both interfaces, its
/// local APIC reports the APIC ID the MADT gave the CPU the kernel meant to start, and it
/// has its own GDT, TSS and #DF stack loaded.
///
/// The number is read through `GS`, so this is the check that each CPU's `GS` names its own
/// block: two CPUs sharing a block agree on a number that is right for at most one.
fn ids(c: &dyn EarlyConsole, cpus: usize) -> bool {
    c.write_str("; ids");
    let mut ok = true;
    let mut apic_ids = [u32::MAX; smp::MAX_CPUS];
    for cpu in 0..cpus {
        let seen = smp::seen_ids(cpu);
        let apic_id = smp::apic_id(cpu);
        let distinct = apic_id.is_some_and(|a| !apic_ids[..cpu].contains(&a));
        let intended = apic_id.is_some() && apic_id == smp::prepared_apic_id(cpu);
        if let (Some(a), Some(slot)) = (apic_id, apic_ids.get_mut(cpu)) {
            *slot = a;
        }
        c.write_str(" ");
        match seen {
            Some((index, id))
                if index == cpu
                    && id as usize == cpu
                    && smp::is_online(cpu)
                    && distinct
                    && intended
                    && smp::owns_tables(cpu) =>
            {
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

/// How long the secondaries' timers are watched, in milliseconds.
const TICK_WINDOW_MS: u64 = 200;

/// Every secondary takes interrupts from its own local APIC timer, at the rate it was
/// asked for within a factor of two: a timer calibrated ten times fast or slow is not
/// rounding error.
fn ticks(c: &dyn EarlyConsole, cpus: usize) -> bool {
    let mut before = [0u64; smp::MAX_CPUS];
    for (cpu, slot) in before.iter_mut().enumerate().take(cpus) {
        *slot = smp::ticks(cpu);
    }
    smp::delay_us(TICK_WINDOW_MS * 1_000);
    let expected = smp::SECONDARY_HZ * TICK_WINDOW_MS / 1_000;
    c.write_str("; ticks");
    let mut ok = true;
    for cpu in 1..cpus {
        let n = smp::ticks(cpu).saturating_sub(before[cpu]);
        c.write_str(" ");
        write_usize(c, n as usize);
        ok &= (expected / 2..=expected * 2).contains(&n);
    }
    c.write_str(" in ");
    write_usize(c, TICK_WINDOW_MS as usize);
    c.write_str(" ms");
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
/// One secondary at a time, taking each reply before the next call, as on aarch64.
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
    let irq = <Cpu as hal::Arch>::irq_save();
    // SAFETY: the IDT is loaded and the only sources that can reach this CPU are the IPI
    // vectors, which have handlers; the tick is stopped and every device line is masked.
    unsafe { arch::tick::enable_interrupts() };
    for _ in 0..1_000 {
        if done() {
            break;
        }
        smp::delay_us(1_000);
    }
    // SAFETY: restores the mask `irq_save` found, which is `kmain`'s.
    unsafe { <Cpu as hal::Arch>::irq_restore(irq) };
    done()
}

/// One counter per CPU, in the storage `sync::percpu` sizes by the architecture.
static COUNTS: PerCpu<AtomicU64, { <Cpu as HasSmp>::MAX_CPUS }> =
    PerCpu::new::<Cpu>([const { AtomicU64::new(0) }; <Cpu as HasSmp>::MAX_CPUS]);

/// How many times CPU `cpu` bumps its counter: different for every CPU, so two CPUs on one
/// slot cannot come out right by adding up to the same total.
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

/// What one CPU holds is not recorded as held by another; see `platform/fdt`'s version,
/// which this is, for why the order below exposes a shared held-lock stack.
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

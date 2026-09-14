//! The APICs on x86_64: the drivers that bind them, and installing the controller they make
//! into the architecture's interrupt path.
//!
//! After [`install`], device lines are routed through the I/O APIC with the MADT's source
//! overrides applied, end-of-interrupt goes to the local APIC, and the scheduler's one-shot
//! tick is the local APIC timer, measured against the TSC. The architecture chose the
//! vectors; this is where they meet the driver.

use device::Driver;
use hal::EarlyConsole;

use crate::{ECAM, MadtFacts, write_usize};

/// Every driver this image carries.
pub(crate) const DRIVERS: &[&dyn Driver] = &[
    &apic::LOCAL_DRIVER,
    &apic::IO_DRIVER,
    &ECAM,
    &uart16550::DRIVER,
    &virtio_blk::DRIVER,
];

/// Build the controller from what bound and install it and its timer. Returns whether that
/// worked, or whether there was legitimately nothing to install.
///
/// A machine whose firmware has no MADT at all has no APIC to find, and keeps the 8259A.
/// One whose MADT describes APICs that cannot be installed fails the boot: running on the
/// 8259A there would pass every check that does not start a second CPU, and hide why.
///
/// # Safety
/// Once, from `discover`, with interrupts masked on the boot identity map, after the
/// drivers probed. The claimed windows are mapped there and in the kernel's own space.
pub(crate) unsafe fn install(c: &dyn EarlyConsole, facts: Option<&MadtFacts>) -> bool {
    let Some(facts) = facts else {
        c.write_str("; NO MADT RECORD");
        return false;
    };
    if facts.cpu_count == 0 {
        c.write_str("; no processors described, staying on the 8259A");
        return true;
    }
    if facts.overrides_dropped {
        c.write_str("; AN INTERRUPT SOURCE OVERRIDE DID NOT FIT");
        return false;
    }
    let vectors = apic::Vectors {
        irq_base: arch::pic::VECTOR_BASE,
        timer: arch::interrupt::TIMER_VECTOR,
        spurious: arch::interrupt::SPURIOUS_VECTOR,
    };
    // SAFETY: the caller's contract is `install`'s.
    let chip =
        match unsafe { apic::install(facts.overrides(), vectors, arch::clock_source(), true) } {
            Ok(chip) => chip,
            Err(e) => {
                c.write_str("; APIC NOT INSTALLED: ");
                c.write_str(match e {
                    apic::InstallError::NoLocalApic => "no local APIC",
                    apic::InstallError::NoIoApic => "no I/O APIC",
                    apic::InstallError::Unaddressable => "a window is unaddressable",
                    apic::InstallError::Refused => "the local APIC refused its mode",
                    apic::InstallError::Again => "installed twice",
                });
                return false;
            }
        };
    // SAFETY: once, masked, single-threaded, and `chip` is initialised: the contracts of
    // both. Its timer interrupt arrives on `TIMER_VECTOR`, which it was just given.
    unsafe {
        arch::interrupt::set_chip(chip);
        arch::tick::set_event_timer(chip);
    }
    c.write_str("; APIC ");
    c.write_str(if apic::is_x2apic(chip) {
        "x2APIC"
    } else {
        "MMIO"
    });
    c.write_str(", boot ID ");
    write_usize(c, chip.boot_id() as usize);
    c.write_str(", ");
    write_usize(c, facts.override_count);
    c.write_str(" overrides, timer ");
    if chip.rate() == 0 {
        c.write_str("UNCALIBRATED");
        return false;
    }
    write_usize(c, chip.rate() as usize);
    c.write_str("/s");
    true
}

/// Start every other enabled processor, and check each. See `smp_x86_64.rs`.
///
/// # Safety
/// As `crate::start_secondaries`.
pub(crate) unsafe fn start_secondaries(c: &dyn EarlyConsole) -> Option<bool> {
    // SAFETY: forwarded.
    unsafe { crate::smp::start_secondaries(c) }
}

/// Whether secondary CPU `cpu` came up and is running.
pub(crate) fn secondary_online(cpu: usize) -> bool {
    cpu != 0 && arch::smp::is_online(cpu)
}

/// Run `f(arg)` on secondary CPU `cpu` through its function-call IPI. Boot path only, with
/// the boot CPU the only caller: see `arch::smp::call`.
pub(crate) fn call_on_secondary(cpu: usize, f: fn(u64) -> u64, arg: u64) -> Option<u64> {
    if !secondary_online(cpu) {
        return None;
    }
    arch::smp::call(cpu, f, arg)
}

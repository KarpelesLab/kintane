//! The APICs on i686: placeholders that claim their windows and drive nothing.
//!
//! The i686 port keeps the 8259A and the PIT. Its interrupt path routes through a fixed
//! controller rather than one discovery installs, and it has no second CPU to start, which
//! is the reason x86_64 needed an APIC at all. The windows are still claimed, so the kernel
//! address space is built the same way on both PC ports.

use device::Driver;
use hal::EarlyConsole;

use crate::{ECAM, MadtFacts, Reserve};

static LOCAL_APIC: Reserve = Reserve {
    name: "local-apic",
    compatible: &["acpi,local-apic"],
    what: "local APIC",
};
static IO_APIC: Reserve = Reserve {
    name: "io-apic",
    compatible: &["acpi,io-apic"],
    what: "I/O APIC",
};

/// Whether a PCI function's interrupt-line register can be wired as its interrupt.
///
/// Yes, here. That register holds the line firmware routed the function's pin to, and it
/// routed it for the interrupt controller a PC has before any APIC is programmed: the
/// 8259A, which is the controller this port keeps. So the answer firmware wrote is the
/// answer, and no interpreter for the ACPI namespace's `_PRT` is needed to find it.
pub(crate) const PCI_LINE_TRUSTED: bool = true;

/// Whether a PCI function's message-signalled interrupts can be delivered.
///
/// No: a message is a write to a local APIC, and this port leaves the APICs alone. A
/// function keeps the line firmware routed, which on this port is trusted.
pub(crate) const MSI: bool = false;

/// No lines for message-signalled interrupts.
pub(crate) const MSI_LINES: core::ops::Range<u32> = 0..0;

/// No message reaches a CPU on this port.
pub(crate) fn msi_message(_line: u32, _cpu: usize) -> Option<(u64, u32)> {
    None
}

/// Every driver this image carries.
pub(crate) const DRIVERS: &[&dyn Driver] = &[
    &LOCAL_APIC,
    &IO_APIC,
    &ECAM,
    &uart16550::DRIVER,
    &virtio_blk::DRIVER,
];

/// Nothing to install: the 8259A stays.
///
/// # Safety
/// None required; `unsafe` so both PC ports have one signature.
pub(crate) unsafe fn install(_c: &dyn EarlyConsole, _facts: Option<&MadtFacts>) -> bool {
    true
}

/// No other CPU is started on i686. Returns `None`: nothing was checked.
///
/// # Safety
/// None required; `unsafe` so both PC ports have one signature.
pub(crate) unsafe fn start_secondaries(c: &dyn EarlyConsole) -> Option<bool> {
    c.write_str("one CPU; this port starts no others yet");
    None
}

/// No secondary CPU on i686.
pub(crate) fn secondary_online(_cpu: usize) -> bool {
    false
}

/// No secondary CPU to call on i686. Always `None`.
pub(crate) fn call_on_secondary(_cpu: usize, _f: fn(u64) -> u64, _arg: u64) -> Option<u64> {
    None
}

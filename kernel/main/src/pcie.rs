//! The boot's check of the PCI Express host bridge the platform found (only with `PCIE`).
//!
//! Two things happen here, and the split between them is the point. The bridge is *described*
//! by the device tree during discovery, and what the tree says is checked for the coherence
//! enumeration depends on: a window that exists, and one big enough to address every bus the
//! same tree claims lies behind it. A bridge whose `bus-range` outruns its `reg` would have an
//! enumerator read one bus's configuration space believing it was another's.
//!
//! Then the bus is *walked*, here rather than during discovery, because only by now does the
//! kernel's own address space map the window. Discovery runs on the boot tables, which map two
//! gigabytes; `virt` puts configuration space a quarter of a terabyte up. So the window is out
//! of reach exactly when the PC's is in reach, which is why `platform/acpi` enumerates during
//! discovery and this does not. The window is claimed by the `ecam` driver so that the address
//! space maps it at all — a window no driver claimed is in nobody's ledger.
//!
//! The walk itself lives in the platform, which owns the device model. This reports it.

use hal::EarlyConsole;

use crate::{Check, write_usize};

/// The first physical address the boot tables do not map on this port.
///
/// `arch/aarch64/src/paging.rs` builds two identity regions: a gigabyte of device memory and
/// a gigabyte of RAM. Configuration space above this is unreadable until the kernel's own
/// address space exists, which is the whole reason the walk is a later stage than discovery.
const BOOT_TABLES_END: u64 = 0x8000_0000;

/// Report the bridge, walk the buses behind it, and gate the boot on both.
///
/// Passes when a bridge was found, its window is real and big enough for the buses claimed,
/// its messages are mapped somewhere, and the walk found at least the bridge's own function
/// with every base address register put back as it was.
pub fn check(c: &dyn EarlyConsole) -> Check {
    c.write_str("\n  pcie       ");
    let Some(f) = platform::pcie() else {
        c.write_str("NO pci-host-ecam-generic NODE ON A BUILD THAT ASKED FOR ONE");
        return Check::Failed;
    };
    if f.ecam_base == 0 || f.ecam_len == 0 {
        c.write_str("THE BRIDGE'S CONFIGURATION WINDOW IS EMPTY");
        return Check::Failed;
    }
    // The window has to hold every bus the same tree claims. One bus is a megabyte of
    // configuration space, so this is arithmetic the tree can contradict, and a tree that
    // does is describing a machine no enumerator could walk.
    let (claimed, held) = (f.buses_claimed(), f.buses_the_window_holds());
    if claimed > held {
        c.write_str("bus-range CLAIMS ");
        write_usize(c, claimed as usize);
        c.write_str(" BUSES AND THE WINDOW HOLDS ");
        write_usize(c, held as usize);
        return Check::Failed;
    }
    // A bridge whose messages go nowhere could carry a device that could never interrupt.
    let Some((_, ids)) = f.msi else {
        c.write_str("NO msi-map ON THE BRIDGE, SO NOTHING BEHIND IT COULD RAISE A MESSAGE");
        return Check::Failed;
    };
    write_usize(c, claimed as usize);
    c.write_str(" buses at ");
    write_usize(c, (f.ecam_base >> 20) as usize);
    c.write_str(" MiB, a ");
    write_usize(c, (f.ecam_len >> 20) as usize);
    c.write_str(" MiB window holding ");
    write_usize(c, held as usize);
    c.write_str("; ");
    write_usize(c, ids as usize);
    c.write_str(" requester ids mapped to an MSI controller; forwards");
    for (what, window) in [
        (" io", f.io),
        (" 32-bit memory", f.mem32),
        (" 64-bit memory", f.mem64),
    ] {
        if window.is_some() {
            c.write_str(what);
        }
    }
    // Why the walk waited, stated as an observation rather than a belief: the day a machine
    // puts the window inside the boot tables, this says so and enumeration could move earlier.
    if f.ecam_base < BOOT_TABLES_END {
        c.write_str("; THE WINDOW IS INSIDE THE BOOT TABLES, so configuration space is readable");
        c.write_str(" during discovery on this machine and the walk need not have waited");
        return Check::Failed;
    }
    c.write_str("; the window is above what the boot tables map");
    let Some(scan) = platform::pcie_enumerate(c) else {
        c.write_str(", AND THE BUS BEHIND IT COULD NOT BE WALKED");
        return Check::Failed;
    };
    // A bridge presents at least its own function. Finding none means configuration space read
    // back as nothing, which is what an *absent function* returns: all ones, from the hardware.
    //
    // It is not what an unclaimed window looks like. That was measured rather than assumed:
    // removing the `ecam` driver's claim leaves the window unmapped, and reading it takes a
    // translation fault inside the walk — an unhandled exception, not a value. So this guard
    // catches a bus that answers with nothing, while a claim that never reached the address
    // space fails earlier and louder, and neither failure is silent.
    if scan.functions == 0 {
        c.write_str(", AND CONFIGURATION SPACE HELD NO FUNCTION, NOT EVEN THE BRIDGE'S OWN");
        return Check::Failed;
    }
    if scan.bridges == 0 {
        c.write_str(", AND NO HOST BRIDGE ANSWERED ON A BUS THAT HAS ONE");
        return Check::Failed;
    }
    // A bridge presents its own function whether or not anything is plugged in, so the number
    // of functions alone cannot say a device was found. What a machine presents is the
    // machine's business and is reported rather than asserted — except that a run which
    // attached one must find one, or the walk saw nothing the bridge did not present by itself.
    if kconfig::QEMU_PCIE_BLOCK && scan.endpoints == 0 {
        c.write_str(", AND NOTHING BEHIND THE BRIDGE, THOUGH THE RUN ATTACHED A FUNCTION");
        return Check::Failed;
    }
    // Sizing a register writes to it and puts it back. One left disturbed works until a driver
    // maps it, which is the kind of damage that surfaces far from its cause.
    if !scan.restored {
        c.write_str(", AND A BASE ADDRESS REGISTER DID NOT READ BACK AS ENUMERATION LEFT IT");
        return Check::Failed;
    }
    c.write_str("; walked ");
    write_usize(c, scan.functions);
    c.write_str(" functions, ");
    write_usize(c, scan.bridges);
    c.write_str(" host bridge");
    if scan.bridges != 1 {
        c.write_str("s");
    }
    c.write_str(", ");
    write_usize(c, scan.endpoints);
    c.write_str(" endpoint");
    if scan.endpoints != 1 {
        c.write_str("s");
    }
    if scan.truncated {
        c.write_str(", the buffer filled before the walk finished");
    }
    c.write_str(", every register restored");
    Check::Passed
}

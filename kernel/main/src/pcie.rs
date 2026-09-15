//! The boot's check of the PCI Express host bridge the platform found (only with `PCIE`).
//!
//! Reading is the whole of it. The bridge is described by the tree, and what the tree says
//! is checked for the coherence enumeration would depend on: a window that exists, and one
//! big enough to address every bus the same tree claims lies behind it. A bridge whose
//! `bus-range` outruns its `reg` would have an enumerator read one bus's configuration
//! space believing it was another's, and find devices that are not there.
//!
//! Nothing is enumerated, and the reason is a fact about this port rather than a missing
//! piece of code. Discovery runs on the boot tables, which map two gigabytes; `virt` puts
//! configuration space at a quarter of a terabyte. So the window is out of reach exactly
//! when the PC's is in reach, which is why `platform/acpi` enumerates during discovery and
//! this does not. The last line below reports that distance rather than assuming it, so the
//! day a machine puts the window low, the boot says the topology changed and enumeration
//! could move earlier.

use hal::EarlyConsole;

use crate::{Check, write_usize};

/// The first physical address the boot tables do not map on this port.
///
/// `arch/aarch64/src/paging.rs` builds two identity regions: a gigabyte of device memory and
/// a gigabyte of RAM. Configuration space above this is unreadable until the kernel's own
/// address space exists, which is the whole reason enumeration is a later stage.
const BOOT_TABLES_END: u64 = 0x8000_0000;

/// Report the bridge and gate the boot on the description being coherent.
///
/// Passes when a bridge was found, its window is real, and the window can address every bus
/// `bus-range` claims. Fails when a build that asked for PCIe has no bridge, or when what
/// the tree says could not be enumerated even once the window is mapped.
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
    // Why nothing is enumerated here, stated as an observation rather than a belief.
    if f.ecam_base < BOOT_TABLES_END {
        c.write_str("; THE WINDOW IS INSIDE THE BOOT TABLES, so configuration space is readable");
        c.write_str(" during discovery on this machine and enumeration need not wait");
        return Check::Failed;
    }
    c.write_str("; the window is above what the boot tables map, so nothing is enumerated yet");
    Check::Passed
}

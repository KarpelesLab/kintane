//! PCI interrupt pins as the PC platform routes them through the ACPI namespace's `_PRT`.
//!
//! What `block` asks about a disk on its pin rather than on a message: the route, the I/O
//! APIC entry read back against it, and whether the function had an MSI-X table to be on
//! instead. Only `kernel/platform/acpi` routes pins, so the device-tree ports take
//! `intx_off.rs`, where none is ever routed.

pub use platform::{PinRoute, block_has_msix, check_pin_entry, pin_route};

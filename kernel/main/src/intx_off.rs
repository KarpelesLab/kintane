//! PCI interrupt pins' place on a port whose platform routes none through `_PRT`.
//!
//! The device-tree ports wire a PCI function's interrupt from the tree, not from the ACPI
//! namespace, so no line is ever a routed pin here. The calls exist so `block` reads the same
//! on every port. See `intx.rs`.

#![cfg_attr(
    CONFIG_MM_FLAT,
    expect(
        dead_code,
        reason = "only block.rs calls pin routing's stand-ins, and a flat kernel builds block_off.rs"
    )
)]

/// A PCI pin's route, as the PC platform gives it. Never made here.
#[derive(Clone, Copy)]
pub struct PinRoute {
    pub gsi: u32,
    pub active_low: bool,
    pub level: bool,
}

/// No line is a routed pin.
pub fn pin_route(_line: u32) -> Option<PinRoute> {
    None
}

/// No I/O APIC entry to read back.
pub fn check_pin_entry(_line: u32) -> Result<PinRoute, &'static str> {
    Err("NO PCI PIN IS ROUTED ON THIS PORT")
}

/// Not recorded on this port. Only a platform that delivers messages asks, and none here does.
pub fn block_has_msix(_i: usize) -> bool {
    false
}

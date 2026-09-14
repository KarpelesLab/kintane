//! What a message-signalled interrupt says on x86: which local APIC takes it, and on which
//! vector.
//!
//! The address is `0xFEE0_0000` with the destination APIC ID in bits 19:12, and the data is
//! the vector with fixed delivery and edge trigger (Intel SDM Vol. 3A, §11.11). A PCI
//! function writes exactly these two values, so programming them is all it takes to deliver
//! its interrupt straight to one CPU — no I/O APIC entry, no routing table.
//!
//! Eight bits of destination is all this format has. A CPU whose APIC ID is above 255, which
//! x2APIC mode allows, cannot be named without interrupt remapping (an IOMMU's remapping
//! table entry, or the extended destination ID some hypervisors offer), so such a destination
//! is refused rather than truncated to some other CPU's ID.

/// The address every message to a local APIC starts from.
pub const ADDRESS_BASE: u64 = 0xfee0_0000;

/// The lowest vector a message may name: 0 to 31 are the CPU's exceptions.
pub const FIRST_VECTOR: u8 = 32;

/// The highest APIC ID the address can carry.
pub const MAX_DESTINATION: u32 = 0xff;

/// The `(address, data)` a function writes to interrupt the local APIC with ID `apic_id` on
/// `vector`. `None` when the ID does not fit the address or the vector is an exception's.
pub fn message(apic_id: u32, vector: u8) -> Option<(u64, u32)> {
    if apic_id > MAX_DESTINATION || vector < FIRST_VECTOR {
        return None;
    }
    Some((ADDRESS_BASE | (u64::from(apic_id) << 12), u32::from(vector)))
}

/// The APIC ID an address names, if it is a local APIC address at all.
pub fn destination(address: u64) -> Option<u32> {
    (address & !0x000f_f000 == ADDRESS_BASE).then(|| ((address >> 12) & 0xff) as u32)
}

/// The vector message data names, with fixed delivery and edge trigger; `None` for any other
/// delivery mode or trigger.
pub fn vector(data: u32) -> Option<u8> {
    // Bits 10:8 delivery mode, bit 15 trigger mode; both zero for fixed, edge.
    (data & !0xff == 0).then_some(data as u8)
}

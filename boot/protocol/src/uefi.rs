//! Translating a UEFI memory map into protocol regions.
//!
//! Shared by every UEFI loader — x86_64 today, aarch64 and i686 when they exist —
//! because the translation is a property of the UEFI specification, not of any one
//! architecture, and it is exactly the kind of table that is wrong in one copy and right
//! in another.
//!
//! The map describes the machine as it will be **after** `ExitBootServices`, when the
//! firmware's boot services are gone. So memory the firmware used for boot services, and
//! memory the loader itself used, is usable by the kernel — including the loader's own
//! code and stack, which the kernel abandons within a few instructions of entry. Memory
//! that must outlive the loader is allocated with the two OS-loader memory types below,
//! which the specification reserves for exactly this, and translated to the protocol's
//! `KernelImage` and `BootData` kinds.

use crate::{MemoryKind, MemoryRegion};

/// UEFI memory types, as numbered by the specification.
pub mod memory_type {
    pub const RESERVED: u32 = 0;
    pub const LOADER_CODE: u32 = 1;
    pub const LOADER_DATA: u32 = 2;
    pub const BOOT_SERVICES_CODE: u32 = 3;
    pub const BOOT_SERVICES_DATA: u32 = 4;
    pub const RUNTIME_SERVICES_CODE: u32 = 5;
    pub const RUNTIME_SERVICES_DATA: u32 = 6;
    pub const CONVENTIONAL: u32 = 7;
    pub const UNUSABLE: u32 = 8;
    pub const ACPI_RECLAIM: u32 = 9;
    pub const ACPI_NVS: u32 = 10;
    pub const MMIO: u32 = 11;
    pub const MMIO_PORT_SPACE: u32 = 12;
    pub const PAL_CODE: u32 = 13;
    pub const PERSISTENT: u32 = 14;

    /// Pages holding the kernel image. `0x8000_0000` and above is reserved by the
    /// specification for OS loaders.
    pub const KINTANE_KERNEL: u32 = 0x8000_4B00;
    /// Pages holding the boot information structure.
    pub const KINTANE_BOOT_DATA: u32 = 0x8000_4B01;
}

/// UEFI pages are always 4 KiB, whatever the architecture's own page size.
pub const PAGE_SIZE: u64 = 4096;

/// What a region of this UEFI type is to the kernel.
///
/// Unknown types — a newer specification's, or another OS loader's — are reserved. A
/// kernel that treated memory it does not understand as free would be the one
/// overwriting it.
#[allow(clippy::as_conversions)]
pub fn kind_of(uefi_type: u32) -> u32 {
    use memory_type::*;
    let kind = match uefi_type {
        LOADER_CODE | LOADER_DATA | BOOT_SERVICES_CODE | BOOT_SERVICES_DATA | CONVENTIONAL => {
            MemoryKind::Usable
        }
        ACPI_RECLAIM => MemoryKind::AcpiReclaimable,
        ACPI_NVS => MemoryKind::AcpiNvs,
        UNUSABLE => MemoryKind::Bad,
        KINTANE_KERNEL => MemoryKind::KernelImage,
        KINTANE_BOOT_DATA => MemoryKind::BootData,
        _ => MemoryKind::Reserved,
    };
    kind as u32
}

/// One firmware descriptor as a protocol region.
///
/// `None` for a descriptor whose extent overflows, which only broken firmware produces;
/// dropping it is safer than trusting either end.
pub fn region(uefi_type: u32, physical_start: u64, pages: u64) -> Option<MemoryRegion> {
    Some(MemoryRegion {
        start: physical_start,
        len: pages
            .checked_mul(PAGE_SIZE)
            .filter(|l| physical_start.checked_add(*l).is_some())?,
        kind: kind_of(uefi_type),
        _reserved: 0,
    })
}

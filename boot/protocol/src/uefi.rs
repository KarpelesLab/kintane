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
    /// Pages holding the firmware call space a loader builds for the kernel: page tables
    /// and a stack for calling runtime services after the handover ([`super::Runtime`]).
    /// Reserved to the kernel, as every type it has no other name for is.
    pub const KINTANE_FIRMWARE_CALL: u32 = 0x8000_4B02;
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

/// The last-known-good boot counter: an EFI variable a loader counts boots in, and the
/// kernel deletes once a boot has worked. See `docs/bootloader.md#failure-handling`.
///
/// Both sides of the handover name the variable, so its name and vendor are here, once,
/// rather than typed into a loader and a kernel that could disagree.
pub mod boot_counter {
    /// `KinTaneBootAttempts`, in UCS-2 and terminated, as `GetVariable` takes a name.
    pub const NAME: [u16; 20] = ucs2(b"KinTaneBootAttempts");

    /// The vendor GUID, as `EFI_GUID`'s four fields: `4b494e54-4254-4c47-9a3d-612e5c0f8417`.
    pub const VENDOR: (u32, u16, u16, [u8; 8]) =
        (0x4B49_4E54, 0x4254, 0x4C47, [0x9A, 0x3D, 0x61, 0x2E, 0x5C, 0x0F, 0x84, 0x17]);

    /// Non-volatile, and readable and writable before and after `ExitBootServices`.
    pub const ATTRIBUTES: u32 = 0x7;

    /// How many boots in a row may go unconfirmed before the next one starts in safe mode.
    /// The variable holds the attempts since the last confirmed boot, a little-endian `u32`.
    pub const FAILURES_BEFORE_SAFE: u32 = 3;

    #[allow(clippy::as_conversions)]
    const fn ucs2<const N: usize>(ascii: &[u8]) -> [u16; N] {
        assert!(ascii.len() < N, "no room for the terminator");
        let mut out = [0u16; N];
        let mut i = 0;
        while i < ascii.len() {
            out[i] = ascii[i] as u16;
            i += 1;
        }
        out
    }
}

/// What a UEFI loader hands the kernel so it can call runtime services after the handover:
/// the payload of [`TagKind::UefiRuntime`](crate::TagKind::UefiRuntime).
///
/// Passed by a loader that counts boots, which today is the EFI stub, because confirming a
/// boot is the one runtime call the kernel makes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Runtime {
    /// A page table root, for `CR3` on x86_64, identity-mapping the first 4 GiB writable and
    /// executable: the address space the firmware's runtime code ran in. The loader built
    /// it before leaving boot services, in [`memory_type::KINTANE_FIRMWARE_CALL`] pages.
    pub call_root: u64,
    /// The top of a stack inside that space, for the calls to run on.
    pub call_stack_top: u64,
    /// `GetVariable`, at the physical address it was built for: nothing called
    /// `SetVirtualAddressMap` to move it.
    pub get_variable: u64,
    /// `SetVariable`, likewise.
    pub set_variable: u64,
    /// `ResetSystem`, likewise.
    pub reset_system: u64,
    /// This boot's number since the last confirmed one, counting from 1.
    pub attempt: u32,
    /// The loader's [`boot_counter::FAILURES_BEFORE_SAFE`]. An attempt past it was started
    /// in safe mode.
    pub failures_before_safe: u32,
}

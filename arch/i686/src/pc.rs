//! What a PC leaves at fixed places for the platform to find: physical memory reachable
//! during boot, and PCI configuration mechanism #1.
//!
//! `kernel/platform/acpi` reads firmware tables and enumerates PCI before the kernel's
//! own address space exists, through the boot identity map `boot.rs` builds. These are
//! the two primitives that needs from the architecture. The same file exists, with the
//! same contents, on x86_64.
//!
//! Here the boot map already covers the four gigabytes a 32-bit pointer can name; the
//! PAE tables behind it can reach further, but a slice cannot.

use core::arch::asm;

/// The end of the boot identity map: physical memory below this is readable at its own
/// address until the kernel's address space is installed. Four gigabytes, which covers
/// RAM on the machines QEMU models, the BIOS area, ACPI tables, and the PC's fixed MMIO
/// hole, where the ECAM window, the I/O APIC and the local APIC live.
pub const BOOT_IDENTITY_END: u64 = 4 << 30;

/// `len` bytes of physical memory at `address`, through the boot identity map.
///
/// `None` for a range that is empty, starts at zero, or reaches past
/// [`BOOT_IDENTITY_END`].
///
/// # Safety
/// Only while the boot identity map is the live address space, which is until `kmain`
/// installs the kernel's own; and nothing may write the range while the slice lives.
/// Reading device memory can have side effects, so the range must be RAM or firmware
/// tables, never registers.
pub unsafe fn boot_physical(address: u64, len: usize) -> Option<&'static [u8]> {
    let end = address.checked_add(len as u64)?;
    if address == 0 || len == 0 || end > BOOT_IDENTITY_END {
        return None;
    }
    // SAFETY: non-null, inside the identity map the caller guarantees is live, and not
    // written while borrowed by the caller's contract. Bytes have no invalid values.
    Some(unsafe {
        core::slice::from_raw_parts(core::ptr::with_exposed_provenance(address as usize), len)
    })
}

const CONFIG_ADDRESS: u16 = 0xcf8;
const CONFIG_DATA: u16 = 0xcfc;
/// The enable bit of `CONFIG_ADDRESS`.
const ENABLE: u32 = 1 << 31;

/// Whether configuration mechanism #1 answers: the address register holds what is
/// written to its enable bit, which no ISA device at `0xcf8` does.
///
/// # Safety
/// Writes `0xcf8`, so nothing else may be using the configuration ports.
pub unsafe fn config_mechanism_1_present() -> bool {
    // SAFETY: the caller owns the configuration ports; the old value is put back.
    unsafe {
        let saved = inl(CONFIG_ADDRESS);
        outl(CONFIG_ADDRESS, ENABLE);
        let answered = inl(CONFIG_ADDRESS) == ENABLE;
        outl(CONFIG_ADDRESS, saved);
        answered
    }
}

/// Read the 32-bit configuration register at `offset` of `bus:device.function` through
/// the I/O ports. `offset` is rounded down to a multiple of four and limited to the
/// 256-byte PCI space, which is all this mechanism reaches.
///
/// # Safety
/// Nothing else may be using the configuration ports between the two port accesses: on
/// one CPU with interrupts masked, or under a lock once there is more than one.
pub unsafe fn config_read(bus: u8, device: u8, function: u8, offset: u8) -> u32 {
    // SAFETY: the caller serialises the ports; selecting and reading a register has no
    // side effects on standard configuration headers.
    unsafe {
        outl(CONFIG_ADDRESS, config_address(bus, device, function, offset));
        inl(CONFIG_DATA)
    }
}

/// Write the 32-bit configuration register at `offset` of `bus:device.function`.
///
/// # Safety
/// As [`config_read`], and the write's effect on the device is the caller's to know.
pub unsafe fn config_write(bus: u8, device: u8, function: u8, offset: u8, value: u32) {
    // SAFETY: the caller serialises the ports and owns the write's meaning.
    unsafe {
        outl(CONFIG_ADDRESS, config_address(bus, device, function, offset));
        outl(CONFIG_DATA, value);
    }
}

fn config_address(bus: u8, device: u8, function: u8, offset: u8) -> u32 {
    ENABLE
        | (u32::from(bus) << 16)
        | (u32::from(device & 0x1f) << 11)
        | (u32::from(function & 0x7) << 8)
        | u32::from(offset & 0xfc)
}

/// # Safety
/// Writing a port can have arbitrary effects; the caller knows the device behind it.
unsafe fn outl(port: u16, value: u32) {
    // SAFETY: `out` with the caller's port and value.
    unsafe {
        asm!("out dx, eax", in("dx") port, in("eax") value, options(nomem, nostack, preserves_flags));
    }
}

/// # Safety
/// Reading a port can have side effects on the device behind it.
unsafe fn inl(port: u16) -> u32 {
    let value: u32;
    // SAFETY: `in` with the caller's port.
    unsafe {
        asm!("in eax, dx", out("eax") value, in("dx") port, options(nomem, nostack, preserves_flags));
    }
    value
}

//! The boot protocol: what every loader hands the kernel.
//!
//! The loaders are plural and platform-specific; this structure is singular. It is
//! also one of the very few genuinely stable ABIs in this project — unlike loadable
//! modules, which are hash-locked to one kernel build, a bootloader lives on the ESP
//! or in the MBR gap and is updated *independently* of the kernel. An installed
//! loader must boot a newer kernel, and a newer loader must boot an older one so that
//! rollback works.
//!
//! That forces forward and backward compatibility, which is why this is tag-based
//! with explicit sizes rather than a fixed struct: a kernel skips tags it does not
//! know, and a loader may omit tags a kernel does not need. See
//! `docs/bootloader.md#the-boot-protocol`.

#![cfg_attr(not(test), no_std)]

pub mod image;
pub mod tags;
pub mod uefi;

#[cfg(test)]
mod tests;

pub const MAGIC: u64 = 0x4b_49_4e_54_41_4e_45_00; // "KINTANE\0"

/// What a 32-bit x86 loader leaves in `EAX` when `EBX` points at a [`BootInfo`] rather
/// than a Multiboot information structure, whose magic is `0x2BADB002`. `KINT` in ASCII.
/// See [`image`] for the rest of that entry's contract.
pub const ENTRY32_MAGIC: u32 = 0x4B49_4E54;

/// Incremented only for an incompatible change. Adding a tag is not one.
pub const VERSION: u16 = 1;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u32)]
pub enum TagKind {
    End = 0,
    MemoryMap = 1,
    CommandLine = 2,
    Framebuffer = 3,
    AcpiRsdp = 4,
    DeviceTree = 5,
    BootDevice = 6,
    Module = 7,
    EntropySeed = 8,
    KernelRange = 9,
    Firmware = 10,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct BootInfo {
    pub magic: u64,
    pub version: u16,
    /// Size of this header, so an older kernel can skip a newer one's additions.
    pub header_size: u16,
    /// Total bytes of tag data following the header.
    pub tags_size: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Tag {
    pub kind: u32,
    /// Including this header, so an unknown tag can still be stepped over.
    pub size: u32,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u32)]
pub enum MemoryKind {
    Usable = 1,
    Reserved = 2,
    AcpiReclaimable = 3,
    AcpiNvs = 4,
    Bad = 5,
    /// Holds the kernel image; usable once it has been relocated, never before.
    KernelImage = 6,
    /// Holds the boot information itself.
    BootData = 7,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemoryRegion {
    pub start: u64,
    pub len: u64,
    pub kind: u32,
    pub _reserved: u32,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u32)]
pub enum Firmware {
    Unknown = 0,
    Multiboot = 1,
    Uefi = 2,
    Bios = 3,
    DeviceTree = 4,
    /// Built at compile time by kbuild, for targets with no bootloader at all.
    Static = 5,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    BadMagic,
    /// The loader is newer than this kernel understands.
    UnsupportedVersion(u16),
    Truncated,
    /// A tag, or the stream of tags, is inconsistent at this byte offset from the start
    /// of the structure.
    Malformed {
        offset: usize,
    },
    /// A loader's buffer is too small for what it is writing.
    NoRoom,
}

impl BootInfo {
    /// Validate a structure handed over by a loader.
    ///
    /// Deliberately does not reject a *larger* header than we know about: that is a
    /// newer loader booting an older kernel, which must work.
    pub fn validate(&self) -> Result<(), Error> {
        if self.magic != MAGIC {
            return Err(Error::BadMagic);
        }
        if self.version > VERSION {
            return Err(Error::UnsupportedVersion(self.version));
        }
        if (self.header_size as usize) < core::mem::size_of::<BootInfo>() {
            return Err(Error::Truncated);
        }
        Ok(())
    }
}

//! `bootinfo` for images a KinTane loader starts.
//!
//! One of the units providing this name, alongside `boot/info-multiboot`,
//! `boot/info-fdt` and `boot/info-none`; the configuration selects one, so `kmain` calls
//! the same function whichever loader ran and contains no `cfg`.
//!
//! The other providers translate: a multiboot structure or a device tree becomes
//! protocol regions. This one has nothing to translate. `kinboot-efi` already wrote the
//! protocol's own memory map, sorted and coalesced, and all that remains is to find it,
//! bound it, and copy it out.
//!
//! The structure is still **untrusted input**. The loader is ours, but it may be a
//! different build from a different year: the protocol is the one ABI in the project
//! that is meant to be crossed by independently updated code (`docs/bootloader.md`).
//! So the header is read before any length is believed, and the length it claims is
//! capped before a slice is made of it.

#![cfg_attr(not(test), no_std)]

use boot_protocol::{MemoryKind, MemoryRegion, tags};

#[cfg(test)]
mod tests;

/// Why a memory map could not be obtained.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Error {
    /// `boot_arg` does not point at a boot information structure.
    NoLoader,
    /// The structure is valid but carries no memory map, and we will not invent one.
    NoMemoryMap,
    /// The structure is malformed at this byte offset from its start.
    Malformed { offset: usize },
    /// More regions than the caller's buffer can hold.
    TooManyRegions { capacity: usize },
}

/// How this platform learns its memory layout, for the banner.
pub const SOURCE: &str = "kinboot";

/// The largest structure believed. The x86_64 loader writes a few pages; a header
/// claiming more than this is corrupt, and is not read for megabytes on its word.
pub const MAX_BOOT_INFO_BYTES: usize = 1024 * 1024;

#[allow(clippy::as_conversions)]
const BOOT_DATA: u32 = MemoryKind::BootData as u32;

/// Fill `out` from a structure already in hand as bytes, returning how many regions
/// were written.
///
/// The first region is always the structure itself, as [`MemoryKind::BootData`]. The
/// loader allocates it with a memory type that translates to exactly that, so this is
/// usually a duplicate — but "usually" is a promise about one loader, and the frame
/// allocator must never hand out the page the in-kernel tests read the map from again.
/// A duplicate costs one slot; a missing reservation costs a corrupted map.
pub fn regions_from(address: u64, bytes: &[u8], out: &mut [MemoryRegion]) -> Result<usize, Error> {
    let parsed = tags::parse(bytes).map_err(translate)?;
    let map = parsed
        .memory_map()
        .map_err(translate)?
        .ok_or(Error::NoMemoryMap)?;

    let capacity = out.len();
    let (first, rest) = out
        .split_first_mut()
        .ok_or(Error::TooManyRegions { capacity })?;
    *first = MemoryRegion {
        start: address,
        len: parsed.header.total_size() as u64,
        kind: BOOT_DATA,
        _reserved: 0,
    };
    if map.len() > rest.len() {
        return Err(Error::TooManyRegions { capacity });
    }
    let mut n = 0;
    for (slot, region) in rest.iter_mut().zip(map) {
        *slot = region;
        n += 1;
    }
    Ok(n + 1)
}

fn translate(e: boot_protocol::Error) -> Error {
    match e {
        boot_protocol::Error::BadMagic => Error::NoLoader,
        boot_protocol::Error::Malformed { offset } => Error::Malformed { offset },
        // A version this kernel does not speak, or a header cut short: either way the
        // structure cannot be read, and the offset of the problem is its header.
        _ => Error::Malformed { offset: 0 },
    }
}

/// Fill `out` with the memory map the loader provided, returning how many regions were
/// written.
///
/// # Safety
/// `boot_arg` must be the value the platform's boot code passed to `kmain` — for a
/// KinTane loader, the physical address of the boot information structure — and that
/// address must be readable, through the current mapping, for the structure's header and
/// for the total size the header declares, up to [`MAX_BOOT_INFO_BYTES`]. A zero
/// `boot_arg` is reported as [`Error::NoLoader`] and nothing is read.
pub unsafe fn memory_regions(boot_arg: u64, out: &mut [MemoryRegion]) -> Result<usize, Error> {
    if boot_arg == 0 {
        return Err(Error::NoLoader);
    }
    let base = usize::try_from(boot_arg).map_err(|_| Error::NoLoader)?;

    // SAFETY: the caller guarantees `boot_arg` is readable for at least the header. The
    // read copies a byte array, so neither alignment nor the validity of the bits is in
    // question, and nothing here keeps a reference into loader memory.
    let head: [u8; tags::HEADER_SIZE] = unsafe {
        core::ptr::read_unaligned(core::ptr::with_exposed_provenance::<[u8; tags::HEADER_SIZE]>(
            base,
        ))
    };
    let header = tags::header(&head).map_err(translate)?;
    let total = header.total_size();
    if total > MAX_BOOT_INFO_BYTES {
        return Err(Error::Malformed { offset: 0 });
    }
    // `from_raw_parts` requires the range not to wrap and to fit in `isize`.
    if base
        .checked_add(total)
        .is_none_or(|end| end > isize::MAX.unsigned_abs())
    {
        return Err(Error::NoLoader);
    }

    // SAFETY: the header at `base` is valid, and for that case the caller guarantees
    // `total` bytes are readable; `total` was capped and the range checked not to wrap.
    // Bytes have no invalid values, and nothing writes to the structure while the slice
    // lives: it is dropped before this returns, on a single-threaded boot path.
    let bytes: &[u8] = unsafe {
        core::slice::from_raw_parts(core::ptr::with_exposed_provenance::<u8>(base), total)
    };
    regions_from(boot_arg, bytes, out)
}

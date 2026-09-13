//! `bootinfo` for platforms a multiboot loader hands over on.
//!
//! One of two units providing this name; the other is `boot/info-none`, used where
//! no loader supplies a memory map yet. The configuration selects one, so `kmain`
//! calls the same function on every target and no `cfg` appears in it.
//!
//! That is the provider pattern the build system grew for architectures, applied to
//! a second axis. It is also what `docs/bootloader.md` describes: loaders are plural
//! and platform-specific, the handover is singular.

#![cfg_attr(not(test), no_std)]

use boot_protocol::MemoryRegion;

/// Why a memory map could not be obtained.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Error {
    /// No loader of a kind we understand ran.
    NoLoader,
    /// A loader ran but supplied no memory map, and we will not invent one.
    NoMemoryMap,
    /// The loader's map was malformed at this byte offset.
    Malformed { offset: usize },
    /// More regions than the caller's buffer can hold.
    TooManyRegions { capacity: usize },
}

/// How this platform learns its memory layout, for the banner.
pub const SOURCE: &str = "multiboot";

/// Fill `out` with the memory map the loader provided, returning how many regions
/// were written.
///
/// # Safety
/// `boot_arg` must be the value the platform's boot code passed to `kmain` — for
/// multiboot, the pointer the loader left in `ebx` — and the structure it points at
/// must still be mapped.
pub unsafe fn memory_regions(boot_arg: u64, out: &mut [MemoryRegion]) -> Result<usize, Error> {
    // The magic is not available at this point: the boot code keeps only the info
    // pointer. Passing the magic through is a small change to every x86 port and is
    // worth doing when something depends on telling "no loader" from "a loader we do
    // not understand"; until then, a null pointer is the signal.
    if boot_arg == 0 {
        return Err(Error::NoLoader);
    }
    let addr = usize::try_from(boot_arg).map_err(|_| Error::NoLoader)?;

    // SAFETY: the caller guarantees `boot_arg` is the loader's info pointer and that
    // the structure is mapped. We pass the magic the loader would have left, having
    // already rejected a null pointer above.
    let handover = unsafe { multiboot::Handover::new(multiboot::BOOTLOADER_MAGIC, addr) }
        .map_err(|_| Error::NoLoader)?;

    // SAFETY: same guarantee; the map lives alongside the structure we just read.
    let iter = unsafe { handover.memory_regions() }.map_err(|_| Error::NoMemoryMap)?;

    let mut n = 0;
    for region in iter {
        let region = region.map_err(|e| match e {
            multiboot::Error::MalformedEntry { offset } => Error::Malformed { offset },
            _ => Error::NoMemoryMap,
        })?;
        if n >= out.len() {
            return Err(Error::TooManyRegions {
                capacity: out.len(),
            });
        }
        out[n] = region;
        n += 1;
    }
    Ok(n)
}

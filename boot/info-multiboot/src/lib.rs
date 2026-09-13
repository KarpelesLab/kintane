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

/// The ACPI RSDP a loader recorded. Multiboot 1 has no field for one, so always `None`,
/// and the platform finds it by scanning the BIOS areas instead.
///
/// # Safety
/// None required; `unsafe` so every `bootinfo` provider has one signature.
pub unsafe fn acpi_rsdp(_boot_arg: u64) -> Option<u64> {
    None
}

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

/// Copy the kernel command line into `out`, returning its length, or `None` when the
/// loader passed none.
///
/// Multiboot loaders put the image's own path first. GRUB writes the path it loaded the
/// kernel from, and QEMU's `-kernel` writes the file name before `-append`. So a first
/// word that is a path is dropped, recognised by its first byte: `/`, or `(` for GRUB's
/// device syntax. A line that starts with an argument is passed through whole. The rule
/// is [`strip_image_path`], which has host tests.
///
/// # Safety
/// As [`memory_regions`].
pub unsafe fn command_line(boot_arg: u64, out: &mut [u8]) -> Result<Option<usize>, Error> {
    if boot_arg == 0 {
        return Err(Error::NoLoader);
    }
    let addr = usize::try_from(boot_arg).map_err(|_| Error::NoLoader)?;
    // SAFETY: as in `memory_regions`.
    let handover = unsafe { multiboot::Handover::new(multiboot::BOOTLOADER_MAGIC, addr) }
        .map_err(|_| Error::NoLoader)?;
    // SAFETY: the caller guarantees the loader's structures are still mapped.
    let Some(line) = (unsafe { handover.cmdline() }) else {
        return Ok(None);
    };
    let line = strip_image_path(line.as_bytes());
    let slot = out
        .get_mut(..line.len())
        .ok_or(Error::Malformed { offset: 0 })?;
    slot.copy_from_slice(line);
    Ok(Some(line.len()))
}

/// `line` without a leading image path, and without the separators after it.
pub fn strip_image_path(line: &[u8]) -> &[u8] {
    match line.first() {
        Some(b'/' | b'(') => {
            let end = line.iter().position(|&b| b == b' ').unwrap_or(line.len());
            let rest = &line[end..];
            let start = rest.iter().position(|&b| b != b' ').unwrap_or(rest.len());
            &rest[start..]
        }
        _ => line,
    }
}

#[cfg(test)]
mod tests {
    use super::strip_image_path;

    #[test]
    fn the_loaders_image_path_is_dropped_and_arguments_are_kept() {
        assert_eq!(strip_image_path(b"/build/kintane.mb32.elf mode=safe x=1"), b"mode=safe x=1");
        assert_eq!(strip_image_path(b"(hd0,1)/boot/kintane  mode=normal"), b"mode=normal");
        assert_eq!(strip_image_path(b"/boot/kintane"), b"");
        assert_eq!(strip_image_path(b"mode=safe /not/a/path"), b"mode=safe /not/a/path");
        assert_eq!(strip_image_path(b""), b"");
    }
}

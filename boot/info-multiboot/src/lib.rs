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

use boot_protocol::{MemoryKind, MemoryRegion};

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

    // The loader's map describes the machine; the boot modules it placed, and the list that
    // says where they are, are in memory it calls usable. Take them out, so nothing
    // allocates over a module before it is read.
    if let Some((start, end)) = handover.module_list() {
        n = carve(out, n, start as u64, end as u64, MemoryKind::BootData)?;
    }
    let mut index = 0;
    // SAFETY: as above; the module list lives alongside the structure.
    while let Some((start, end)) = unsafe { handover.module(index) } {
        n = carve(out, n, start as u64, end as u64, MemoryKind::BootData)?;
        index += 1;
    }
    Ok(n)
}

/// Whether this handover can carry a module bundle: multiboot boot modules can, so a kernel
/// built with test modules and handed none has lost them.
pub const MODULE_BUNDLES: bool = true;

/// The boot module bundle the loader passed, as `(physical start, length)`: the first boot
/// module, when there is one.
///
/// # Safety
/// As [`memory_regions`].
pub unsafe fn module_bundle(boot_arg: u64) -> Option<(u64, u64)> {
    let addr = usize::try_from(boot_arg).ok().filter(|&a| a != 0)?;
    // SAFETY: as in `memory_regions`.
    let handover = unsafe { multiboot::Handover::new(multiboot::BOOTLOADER_MAGIC, addr) }.ok()?;
    // SAFETY: the caller guarantees the loader's structures are still mapped.
    let (start, end) = unsafe { handover.module(0) }?;
    (end > start).then_some((start as u64, (end - start) as u64))
}

/// Mark `[start, end)`, rounded out to whole pages, as `kind` within the first `n` regions
/// of `out`, splitting any region it falls inside. Returns the new count. Regions of other
/// kinds are left as they are: only memory the map calls usable is taken.
pub fn carve(
    out: &mut [MemoryRegion],
    mut n: usize,
    start: u64,
    end: u64,
    kind: MemoryKind,
) -> Result<usize, Error> {
    const PAGE: u64 = 4096;
    let start = start & !(PAGE - 1);
    let end = end.saturating_add(PAGE - 1) & !(PAGE - 1);
    if end <= start {
        return Ok(n);
    }
    let mut i = 0;
    while i < n {
        let r = out[i];
        let r_end = r.start.saturating_add(r.len);
        if r.kind != MemoryKind::Usable as u32 || end <= r.start || start >= r_end {
            i += 1;
            continue;
        }
        let (lo, hi) = (start.max(r.start), end.min(r_end));
        let pieces = [
            (r.start, lo, r.kind),
            (lo, hi, kind as u32),
            (hi, r_end, r.kind),
        ];
        let pieces: &[(u64, u64, u32)] = &pieces;
        let keep = pieces.iter().filter(|(a, b, _)| b > a).count();
        if n - 1 + keep > out.len() {
            return Err(Error::TooManyRegions {
                capacity: out.len(),
            });
        }
        out.copy_within(i + 1..n, i + keep);
        let mut at = i;
        for &(a, b, k) in pieces.iter().filter(|(a, b, _)| b > a) {
            out[at] = MemoryRegion {
                start: a,
                len: b - a,
                kind: k,
                _reserved: 0,
            };
            at += 1;
        }
        n = n - 1 + keep;
        i += keep;
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
    use super::{Error, MemoryKind, MemoryRegion, carve, strip_image_path};

    fn r(start: u64, len: u64, kind: MemoryKind) -> MemoryRegion {
        MemoryRegion {
            start,
            len,
            kind: kind as u32,
            _reserved: 0,
        }
    }

    #[test]
    fn a_boot_module_is_carved_out_of_usable_memory_in_whole_pages() {
        let mut out = [r(0, 0, MemoryKind::Reserved); 8];
        out[0] = r(0, 0x9f000, MemoryKind::Usable);
        out[1] = r(0xf0000, 0x10000, MemoryKind::Reserved);
        out[2] = r(0x100000, 0x7f00000, MemoryKind::Usable);
        let n = carve(&mut out, 3, 0x20_1234, 0x20_5001, MemoryKind::BootData).unwrap();
        assert_eq!(
            out[..n],
            [
                r(0, 0x9f000, MemoryKind::Usable),
                r(0xf0000, 0x10000, MemoryKind::Reserved),
                r(0x100000, 0x101000, MemoryKind::Usable),
                r(0x201000, 0x5000, MemoryKind::BootData),
                r(0x206000, 0x7dfa000, MemoryKind::Usable),
            ]
        );
        // At a region's start, nothing is split off before it; inside a reserved region,
        // nothing changes.
        let n2 = carve(&mut out, n, 0, 0x1000, MemoryKind::BootData).unwrap();
        assert_eq!(out[0], r(0, 0x1000, MemoryKind::BootData));
        assert_eq!(out[1], r(0x1000, 0x9e000, MemoryKind::Usable));
        assert_eq!(n2, n + 1);
        assert_eq!(carve(&mut out, n2, 0xf1000, 0xf2000, MemoryKind::BootData), Ok(n2));
        assert_eq!(
            carve(&mut out[..n2], n2, 0x300000, 0x301000, MemoryKind::BootData),
            Err(Error::TooManyRegions { capacity: n2 })
        );
    }

    #[test]
    fn the_loaders_image_path_is_dropped_and_arguments_are_kept() {
        assert_eq!(strip_image_path(b"/build/kintane.mb32.elf mode=safe x=1"), b"mode=safe x=1");
        assert_eq!(strip_image_path(b"(hd0,1)/boot/kintane  mode=normal"), b"mode=normal");
        assert_eq!(strip_image_path(b"/boot/kintane"), b"");
        assert_eq!(strip_image_path(b"mode=safe /not/a/path"), b"mode=safe /not/a/path");
        assert_eq!(strip_image_path(b""), b"");
    }
}

//! `bootinfo` for platforms that describe themselves with a flattened device tree.
//!
//! One of the units providing this name, alongside `boot/info-multiboot` and
//! `boot/info-none`; the configuration selects one, so `kmain` calls the same function
//! on every target and contains no `cfg`. The parsing is `boot/fdt`'s, which works on
//! a byte slice and holds no `unsafe`. What lives here is the part that cannot be
//! safe: deciding where the tree is and turning that address into a slice.
//!
//! # Finding the tree
//!
//! A loader that follows the Linux arm64 boot protocol — U-Boot, a UEFI stub, QEMU
//! booting a raw `Image` — passes the tree's physical address in `x0`, which the boot
//! code carries through to `kmain` as `boot_arg`. That is a handover, and when
//! `boot_arg` is non-zero it is the only place looked.
//!
//! QEMU's `virt` machine booting an ELF passes nothing: `hw/arm/boot.c` assumes "raw
//! images are linux kernels, and ELF images are not", leaves `x0` zero, and instead
//! *tries* to place the tree at the base of RAM, `0x4000_0000`, if it fits below the
//! image. So when `boot_arg` is zero this probes that address for the magic. A probe is
//! a guess, not a handover: the banner prints `boot_arg` on the line above the memory
//! map, and [`SOURCE`] says that zero means probed, so the two together say which
//! happened.
//!
//! **The probe does not find a tree with the image linked at `0x4008_0000`.** QEMU
//! builds the `virt` tree in a 1 MiB buffer and loads it only where all of that fits:
//! `arm_load_dtb` returns without loading anything when the tree would cross the
//! image's lowest address, and 512 KiB is not 1 MiB. Nothing is reported, and the base
//! of RAM stays zeroed — which this reads as [`Error::NoLoader`], the truth. The tree
//! appears there once the image starts at `0x4010_0000` or above, or when QEMU is given
//! a compacted tree with `-dtb`, which it loads with only modest padding.

#![cfg_attr(not(test), no_std)]

use boot_protocol::{MemoryKind, MemoryRegion};

/// Why a memory map could not be obtained.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Error {
    /// No device tree where one was looked for: `boot_arg` did not point at one, or it
    /// was zero and the base of RAM holds none.
    NoLoader,
    /// A device tree was found but describes no usable memory, and we will not invent
    /// any.
    NoMemoryMap,
    /// The device tree was malformed at this byte offset from its start.
    Malformed {
        /// Byte offset into the tree.
        offset: usize,
    },
    /// More regions than the caller's buffer can hold.
    TooManyRegions {
        /// The caller's buffer length.
        capacity: usize,
    },
}

/// How this platform learns its memory layout, for the banner.
///
/// A constant, printed before the lookup runs, so it cannot say which path was taken.
/// It says how to tell instead: the banner's `boot arg` line is `x0`.
pub const SOURCE: &str = "device tree at x0, or probed at 0x40000000 if x0 is 0";

/// Where QEMU's `virt` machine parks the tree when it does not pass a pointer: the base
/// of RAM, `VIRT_MEM` in `hw/arm/virt.c`.
const PROBE_ADDRESS: u64 = 0x4000_0000;

/// The largest tree accepted. Linux's arm64 port refuses anything larger
/// (`MAX_FDT_SIZE`), so no firmware that boots Linux produces one; and a `totalsize` in
/// a probed header is not believed far enough to read gigabytes on its word.
const MAX_TREE_BYTES: usize = 2 * 1024 * 1024;

/// The byte offset of `totalsize` in the header, for reporting a tree that is too big.
const TOTALSIZE_OFFSET: usize = 4;

#[allow(clippy::as_conversions)]
const BOOT_DATA: u32 = MemoryKind::BootData as u32;

/// Fill `out` with the memory map the device tree describes, returning how many regions
/// were written.
///
/// The first region is always the tree itself, as [`MemoryKind::BootData`]: nothing in
/// a device tree says where the device tree is, and the device framework will want to
/// read it after the frame allocator has started handing memory out.
///
/// # Safety
/// `boot_arg` must be the value the platform's boot code passed to `kmain` — for
/// aarch64, what the loader left in `x0`. If it is non-zero it must point at readable
/// memory holding a device tree, mapped for the tree's `totalsize` bytes. If it is zero,
/// the 40 bytes at `0x4000_0000` must be readable, and, if they begin with the device
/// tree magic, so must the `totalsize` bytes they declare (at most 2 MiB). Both hold on
/// QEMU's `virt` machine with RAM identity-mapped, which is what this port boots on; a
/// board whose RAM does not start there needs a different probe address, not this one.
pub unsafe fn memory_regions(boot_arg: u64, out: &mut [MemoryRegion]) -> Result<usize, Error> {
    // SAFETY: this function's contract is `device_tree`'s, passed through unchanged.
    let blob = unsafe { device_tree(boot_arg) }?;
    let address = blob.as_ptr().addr() as u64;
    let tree = fdt::Fdt::new(blob).map_err(translate)?;

    let capacity = out.len();
    let (first, rest) = out
        .split_first_mut()
        .ok_or(Error::TooManyRegions { capacity })?;
    *first = MemoryRegion {
        start: address,
        len: u64::from(tree.header().total_size),
        kind: BOOT_DATA,
        _reserved: 0,
    };

    let n = tree.memory_map(rest).map_err(|e| match e {
        fdt::Error::TooManyRegions { .. } => Error::TooManyRegions { capacity },
        other => translate(other),
    })?;
    // `rest` is `out.len() - 1` long and `n` counts slots of it, so this cannot overflow.
    Ok(n.saturating_add(1))
}

/// Copy the kernel command line into `out`, returning its length, or `None` when the tree
/// carries none: `/chosen`'s `bootargs`, which QEMU writes for `-append` and a Linux-style
/// loader writes from its own configuration.
///
/// # Safety
/// As [`memory_regions`].
pub unsafe fn command_line(boot_arg: u64, out: &mut [u8]) -> Result<Option<usize>, Error> {
    // SAFETY: this function's contract is `device_tree`'s, passed through unchanged.
    let blob = unsafe { device_tree(boot_arg) }?;
    let tree = fdt::Fdt::new(blob).map_err(translate)?;
    let Some(line) = tree.bootargs().map_err(translate)? else {
        return Ok(None);
    };
    let slot = out
        .get_mut(..line.len())
        .ok_or(Error::Malformed { offset: 0 })?;
    slot.copy_from_slice(line);
    Ok(Some(line.len()))
}

/// The device tree the platform was booted with, as the bytes of its `totalsize`.
///
/// Found the way [`memory_regions`] describes: at `boot_arg`, or probed at the base of
/// RAM when that is zero. The slice is the loader's memory, which the memory map marks
/// as boot data, so it stays intact for as long as nothing reclaims boot data — which
/// nothing does yet.
///
/// # Errors
/// [`Error::NoLoader`] when no tree is where one was looked for, and
/// [`Error::Malformed`] when its header is unusable or its size is implausible. The rest
/// of the tree is not validated here; `fdt::Fdt::new` does that.
///
/// # Safety
/// As [`memory_regions`]. The returned slice must not be used after the memory it lies
/// in is unmapped or reused.
pub unsafe fn device_tree(boot_arg: u64) -> Result<&'static [u8], Error> {
    let address = if boot_arg != 0 {
        boot_arg
    } else {
        PROBE_ADDRESS
    };
    let base = usize::try_from(address).map_err(|_| Error::NoLoader)?;

    // SAFETY: the caller guarantees that `address` — `boot_arg`, or the probe address
    // when that is zero — is readable for at least the header's 40 bytes. The read is
    // of a byte array, so alignment and validity of the bits are not in question; and
    // it copies, so nothing here holds a reference into memory the loader owns.
    let head: [u8; fdt::HEADER_LEN] = unsafe {
        core::ptr::read_unaligned(core::ptr::with_exposed_provenance::<[u8; fdt::HEADER_LEN]>(base))
    };
    let header = fdt::Header::parse(&head).map_err(|e| match e {
        // Not a device tree at all: nothing handed one over, or nothing was parked.
        fdt::Error::BadMagic(_) => Error::NoLoader,
        other => Error::Malformed {
            offset: other.offset(),
        },
    })?;

    let total = usize::try_from(header.total_size)
        .ok()
        .filter(|&t| t <= MAX_TREE_BYTES)
        .ok_or(Error::Malformed {
            offset: TOTALSIZE_OFFSET,
        })?;
    // `from_raw_parts` requires the length to fit in `isize`, which `MAX_TREE_BYTES` already
    // guarantees, and the range not to wrap. A header read at an address this close to
    // the top would already have faulted, but that is a fact about the hardware, and this
    // is the check that does not depend on it.
    //
    // It once also refused any tree *ending* above `isize::MAX`. On a 64-bit port that
    // never mattered. On riscv32, RAM starts at 2 GiB, QEMU puts the tree at the top of
    // it, and the check turned a valid tree into "no loader".
    if base.checked_add(total).is_none() {
        return Err(Error::NoLoader);
    }

    // SAFETY: the header at `base` carries the device tree magic, and for that case the
    // caller guarantees `totalsize` bytes are readable; `total` is that value, capped at
    // MAX_TREE_BYTES, and the range was just checked not to wrap or exceed `isize`. The
    // slice is of bytes, which have no invalid values. Nothing writes to the tree: it is
    // the loader's, the memory map reports it as boot data so the frame allocator never
    // hands it out, and the caller undertakes not to use the slice once it is unmapped.
    Ok(unsafe {
        core::slice::from_raw_parts(core::ptr::with_exposed_provenance::<u8>(base), total)
    })
}

fn translate(e: fdt::Error) -> Error {
    match e {
        fdt::Error::BadMagic(_) => Error::NoLoader,
        fdt::Error::NoMemory => Error::NoMemoryMap,
        fdt::Error::TooManyRegions { capacity } => Error::TooManyRegions { capacity },
        other => Error::Malformed {
            offset: other.offset(),
        },
    }
}

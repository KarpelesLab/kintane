//! `bootinfo` for platforms with no memory-map source yet.
//!
//! The counterpart to `boot/info-multiboot`. Both provide the unit name `bootinfo`
//! and the configuration selects one, so `kmain` calls the same function on every
//! target and contains no `cfg`.
//!
//! Reporting `NoLoader` is deliberate rather than a stub returning an empty map. An
//! empty map is a lie the frame allocator would act on; an error is a fact the caller
//! can print. On aarch64 the device tree is genuinely there — QEMU parks it at the
//! base of RAM — but locating it without a pointer needs the FDT parser and the
//! device framework from Phase 3.

#![cfg_attr(not(test), no_std)]

use boot_protocol::MemoryRegion;

/// Why a memory map could not be obtained.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Error {
    NoLoader,
    NoMemoryMap,
    Malformed { offset: usize },
    TooManyRegions { capacity: usize },
}

/// How this platform learns its memory layout, for the banner.
pub const SOURCE: &str = "none yet";

/// Always fails: this platform has no memory-map source wired up.
///
/// # Safety
/// Takes the same contract as the other provider so the signatures match; it
/// dereferences nothing.
pub unsafe fn memory_regions(_boot_arg: u64, _out: &mut [MemoryRegion]) -> Result<usize, Error> {
    Err(Error::NoLoader)
}

/// Always fails, for the same reason as [`memory_regions`].
///
/// # Safety
/// As [`memory_regions`]; it dereferences nothing.
pub unsafe fn command_line(_boot_arg: u64, _out: &mut [u8]) -> Result<Option<usize>, Error> {
    Err(Error::NoLoader)
}

/// Whether this handover can carry a module bundle at all. When it cannot, a kernel built
/// with test modules has nothing to load, and says so rather than failing.
pub const MODULE_BUNDLES: bool = false;

/// The boot module bundle a loader passed, as `(physical start, length)`. This loader
/// passes none yet; see docs/modules.md.
///
/// # Safety
/// None required; `unsafe` so every `bootinfo` provider has one signature.
pub unsafe fn module_bundle(_boot_arg: u64) -> Option<(u64, u64)> {
    None
}

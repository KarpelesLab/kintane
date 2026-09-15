//! The IOMMU integration's place on a build without one.
//!
//! Only x86_64 with `IOMMU` confines a disk's DMA in hardware; everywhere else a disk's
//! DMA reaches physical memory directly, as it always has. The calls still exist and do
//! nothing, so `block` reads the same on every port. See `docs/isolation.md`.
//!
//! Every signature here mirrors `iommu.rs`, the slot argument included: the two are chosen by
//! `#[cfg]` in `main.rs`, so one drifting from the other breaks the builds that take this one
//! and no others — which is exactly the failure that is easiest to miss.

#![cfg_attr(
    CONFIG_MM_FLAT,
    expect(
        dead_code,
        reason = "only block.rs calls the IOMMU's stand-ins, and a flat kernel builds block_off.rs"
    )
)]

use hal::EarlyConsole;
use mm::DirectMap;
use vtd::Fault;

/// Nothing to confine.
pub fn confine_disk(
    _c: &dyn EarlyConsole,
    _frames: &mut mm::phys::FrameAllocator<'_, arch::Cpu>,
    _direct: DirectMap,
    _i: usize,
    _dma_phys: u64,
    _dma_len: u64,
) -> bool {
    false
}

/// No domain, so nothing is mapped.
pub fn domain_maps(_i: usize, _iova: u64) -> bool {
    false
}

/// No unit, so no fault log. A fault carries the source id of the device that caused it, so
/// there is nothing to pair with it here either.
pub fn take_fault() -> Option<Fault> {
    None
}

/// No device is attached, so none has a source id the hardware knows it by.
pub fn source_of(_i: usize) -> Option<u16> {
    None
}

/// The changes the IOMMU build makes to a disk's remapping table entry; none apply here.
#[derive(Clone, Copy)]
pub enum Tamper {
    Absent,
    ForeignSource,
    WideDestination,
    Restore,
}

/// No IOMMU to remap through.
pub fn remap_disk_interrupt(
    _c: &dyn EarlyConsole,
    _frames: &mut mm::phys::FrameAllocator<'_, arch::Cpu>,
    _i: usize,
    _line: u32,
) -> bool {
    false
}

/// Nothing is remapped.
pub fn check_disk_interrupt(_i: usize, _line: u32) -> Result<bool, &'static str> {
    Err("NO IOMMU IN THIS BUILD")
}

/// No table entry to change.
pub fn tamper_disk_interrupt(_i: usize, _how: Tamper) -> bool {
    false
}

/// No domain to map a page into.
pub fn grant_page(
    _frames: &mut mm::phys::FrameAllocator<'_, arch::Cpu>,
    _i: usize,
    _phys: u64,
) -> bool {
    false
}

/// Nothing mapped to take away.
pub fn revoke_page(_i: usize, _phys: u64) -> bool {
    false
}

/// Nothing is remapped.
pub fn disk_interrupt_remapped(_i: usize) -> bool {
    false
}

/// No table entry to route an interrupt through.
pub fn route_disk_interrupt(_i: usize, _line: u32, _cpu: usize) -> Result<(), &'static str> {
    Err("NO IOMMU IN THIS BUILD")
}

/// No invalidation queue.
pub fn invalidation_stats() -> Option<vtd::QueueStats> {
    None
}

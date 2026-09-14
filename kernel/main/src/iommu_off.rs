//! The IOMMU integration's place on a build without one.
//!
//! Only x86_64 with `IOMMU` confines the disk's DMA in hardware; everywhere else the disk's
//! DMA reaches physical memory directly, as it always has. The calls still exist and do
//! nothing, so `block` reads the same on every port. See `docs/isolation.md`.

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
    _dma_phys: u64,
    _dma_len: u64,
) -> bool {
    false
}

/// No domain, so nothing is mapped.
pub fn domain_maps(_iova: u64) -> bool {
    false
}

/// No unit, so no fault log.
pub fn take_fault() -> Option<(Fault, u16)> {
    None
}

/// The changes the IOMMU build makes to the disk's remapping table entry; none apply here.
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
    _line: u32,
) -> bool {
    false
}

/// Nothing is remapped.
pub fn check_disk_interrupt(_line: u32) -> Result<bool, &'static str> {
    Err("NO IOMMU IN THIS BUILD")
}

/// No table entry to change.
pub fn tamper_disk_interrupt(_how: Tamper) -> bool {
    false
}

//! The IOMMU integration's place on a build without one.
//!
//! Only x86_64 with `IOMMU` confines the disk's DMA in hardware; everywhere else the disk's
//! DMA reaches physical memory directly, as it always has. The calls still exist and do
//! nothing, so `block` reads the same on every port. See `docs/isolation.md`.

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

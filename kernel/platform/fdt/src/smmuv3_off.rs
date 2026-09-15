//! SMMUv3 discovery's place on a build that did not ask for it.
//!
//! Only aarch64 with `SMMUV3` looks for an Arm SMMUv3. Everywhere else there is no unit to
//! find, so discovery does nothing and there are no facts to report — and `discover` calls it
//! unconditionally, because `cfg` selects modules here rather than lines inside a function
//! (`docs/portability.md`).
//!
//! Every signature mirrors `smmuv3.rs`, the two being chosen by `#[cfg]` in `lib.rs`: one
//! drifting from the other breaks exactly the builds that take this one and no others, which
//! is the failure that is easiest to miss.

use device::DeviceTree;
use hal::EarlyConsole;

/// What discovery would have read. Never built here, so that `platform`'s surface is the same
/// either way and a caller naming it compiles on every port.
#[derive(Clone, Copy)]
pub struct SmmuFacts {
    pub register_base: u64,
    pub register_len: u64,
    pub idr0: u32,
    pub idr1: u32,
    pub idr5: u32,
    pub aidr: u32,
    pub map: Option<(u32, u32, u32)>,
    pub mmio_behind: usize,
    pub mmio_slots: usize,
}

impl SmmuFacts {
    /// No unit, so no stream ids.
    pub fn stream_id_bits(&self) -> u32 {
        0
    }
    /// No unit, so no translation stage.
    pub fn stage1(&self) -> bool {
        false
    }
    /// No unit, so no translation stage.
    pub fn stage2(&self) -> bool {
        false
    }
    /// No unit, so no granule.
    pub fn granule_4k(&self) -> bool {
        false
    }
    /// No unit, so no granule.
    pub fn granule_64k(&self) -> bool {
        false
    }
    /// No unit, so no output address size.
    pub fn output_bits(&self) -> u32 {
        0
    }
}

/// Nothing was discovered, because nothing was looked for.
pub fn facts() -> Option<SmmuFacts> {
    None
}

/// No unit to find.
pub fn discover(_c: &dyn EarlyConsole, _tree: &DeviceTree<'_, '_>) {}

//! PCIe discovery's place on a build that did not ask for it.
//!
//! Only aarch64 with `PCIE` looks for a host bridge. Everywhere else there is none to find,
//! so discovery does nothing and there are no facts to report — and `discover` calls it
//! unconditionally, because `cfg` selects modules here rather than lines inside a function
//! (`docs/portability.md`).
//!
//! Every signature mirrors `pcie.rs`, the two being chosen by `#[cfg]` in `lib.rs`: one
//! drifting from the other breaks exactly the builds that take this one and no others, which
//! is the failure that is easiest to miss.

use device::DeviceTree;
use hal::EarlyConsole;

/// What discovery would have read. Never built here, so that `platform`'s surface is the
/// same either way and a caller naming it compiles on every port.
#[derive(Clone, Copy)]
pub struct PcieFacts {
    pub ecam_base: u64,
    pub ecam_len: u64,
    pub bus_start: u8,
    pub bus_end: u8,
    pub io: Option<(u64, u64)>,
    pub mem32: Option<(u64, u64)>,
    pub mem64: Option<(u64, u64)>,
    pub msi: Option<(u32, u32)>,
}

impl PcieFacts {
    /// Bytes of configuration space one bus occupies, the same number either way.
    pub const BUS_BYTES: u64 = 1 << 20;

    /// No window, so it holds no buses.
    pub fn buses_the_window_holds(&self) -> u64 {
        0
    }

    /// No bridge, so no buses are claimed.
    pub fn buses_claimed(&self) -> u64 {
        0
    }
}

/// Nothing was discovered, because nothing was looked for.
pub fn facts() -> Option<PcieFacts> {
    None
}

/// No bridge to find.
pub fn discover(_c: &dyn EarlyConsole, _tree: &DeviceTree<'_, '_>) {}

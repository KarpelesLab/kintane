//! `platform` for ports that enumerate nothing.
//!
//! One of the units providing this name, alongside `kernel/platform/fdt`; see there for
//! what a platform does. Here the answer to "which devices" is fixed by the architecture,
//! so discovery reports that and the windows are the port's own list.

#![no_std]

use hal::EarlyConsole;
use hal::paging::DeviceWindow;

/// Nothing to discover. Returns `None`, which the banner reports as skipped rather than
/// passed: no claim about devices was checked.
///
/// # Safety
/// None required; `unsafe` only so both providers have one signature.
pub unsafe fn discover(c: &dyn EarlyConsole, _boot_arg: u64) -> Option<bool> {
    c.write_str("fixed by the architecture; nothing to enumerate");
    None
}

/// Device memory the kernel touches after its own tables are installed: whatever the
/// architecture names. Always known here, so never `None`.
pub fn device_windows() -> Option<&'static [DeviceWindow]> {
    Some(arch::kspace::device_windows())
}

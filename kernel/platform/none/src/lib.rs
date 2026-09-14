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

/// No other CPU is started on these ports yet. Returns `None`: nothing was checked.
///
/// # Safety
/// None required; `unsafe` only so both providers have one signature.
pub unsafe fn start_secondaries(c: &dyn EarlyConsole) -> Option<bool> {
    c.write_str("one CPU; this port starts no others yet");
    None
}

/// No secondary CPU is ever online here.
pub fn secondary_online(_cpu: usize) -> bool {
    false
}

/// No secondary CPU to call. Always `None`.
pub fn call_on_secondary(_cpu: usize, _f: fn(u64) -> u64, _arg: u64) -> Option<u64> {
    None
}

/// Device memory the kernel touches after its own tables are installed: whatever the
/// architecture names. Always known here, so never `None`.
pub fn device_windows() -> Option<&'static [DeviceWindow]> {
    Some(arch::kspace::device_windows())
}

/// No window is granted to a driver domain on this port; see `kernel/platform/fdt`.
pub fn isolation_window() -> Option<(u64, u64)> {
    None
}

/// No console on these ports receives on interrupt yet, so there is no line to report.
pub fn console_line() -> Option<u32> {
    None
}

/// No block device is bound on these ports, so there is no line to report.
pub fn block_line() -> Option<u32> {
    None
}

/// No network card is bound on these ports either.
pub fn net_line() -> Option<u32> {
    None
}

/// No interrupt on these ports is message-signalled.
pub fn interrupt_is_msi(_line: u32) -> bool {
    false
}

/// Counted only for message-signalled lines, which these ports do not have.
pub fn interrupts_on_cpu(_line: u32, _cpu: usize) -> u64 {
    0
}

/// No interrupt on these ports can be moved between CPUs.
pub fn route_interrupt(_line: u32, _cpu: usize) -> Result<(), &'static str> {
    Err("no message-signalled interrupts on this platform")
}

/// These ports deliver no message-signalled interrupts.
pub fn delivers_msi() -> bool {
    false
}

/// Nothing received: `(interrupts, bytes)`.
pub fn console_received() -> (u32, u32) {
    (0, 0)
}

/// Nothing to read.
pub fn console_read() -> Option<u8> {
    None
}

/// No device interrupts are dispatched through the device model here: `(dispatched,
/// unhandled)`.
pub fn device_interrupts() -> (u64, u64) {
    (0, 0)
}

/// Nothing bound, so nothing to unbind. `None`: not checked.
///
/// # Safety
/// None required; `unsafe` only so every provider has one signature.
pub unsafe fn rebind_console(_c: &dyn EarlyConsole) -> Option<bool> {
    None
}

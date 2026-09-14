//! Model-specific registers on a target that has none: the host running the tests, and
//! the targets `kbuild portability` compiles for. No CPU here has x2APIC mode, so the
//! driver never reaches the accessors, which answer as an absent register would.

#![allow(unsafe_code)]

/// No x2APIC mode on this target.
pub fn x2apic_supported() -> bool {
    false
}

/// No register to read.
///
/// # Safety
/// None required; `unsafe` so both implementations have one signature.
pub unsafe fn read(_msr: u32) -> u64 {
    0
}

/// No register to write.
///
/// # Safety
/// None required; `unsafe` so both implementations have one signature.
pub unsafe fn write(_msr: u32, _value: u64) {}

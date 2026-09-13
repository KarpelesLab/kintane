//! Model-specific registers and CPUID, on the CPUs that have them.
//!
//! Selected by target architecture at the module boundary; `msr_none.rs` stands in on
//! every other target, where x2APIC mode simply does not exist.

#![allow(unsafe_code)]

#[cfg(target_arch = "x86")]
use core::arch::x86::__cpuid;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::__cpuid;

/// Whether the CPU implements x2APIC mode: CPUID leaf 1, ECX bit 21.
pub fn x2apic_supported() -> bool {
    // Leaf 1 exists on every CPU with a local APIC, which is every CPU this driver binds on.
    __cpuid(1).ecx & (1 << 21) != 0
}

/// Read model-specific register `msr`.
///
/// # Safety
/// `msr` must exist on this CPU, or `rdmsr` raises #GP.
pub unsafe fn read(msr: u32) -> u64 {
    let (lo, hi): (u32, u32);
    // SAFETY: the caller guarantees the register exists; `rdmsr` reads it into EDX:EAX
    // and has no other effect.
    unsafe {
        core::arch::asm!(
            "rdmsr",
            in("ecx") msr,
            out("eax") lo,
            out("edx") hi,
            options(nomem, nostack, preserves_flags)
        );
    }
    (u64::from(hi) << 32) | u64::from(lo)
}

/// Write model-specific register `msr`.
///
/// # Safety
/// `msr` must exist on this CPU and accept `value`, and what the write does is the
/// caller's to justify.
pub unsafe fn write(msr: u32, value: u64) {
    // SAFETY: the caller's contract; `wrmsr` writes EDX:EAX into the register.
    unsafe {
        core::arch::asm!(
            "wrmsr",
            in("ecx") msr,
            in("eax") value as u32,
            in("edx") (value >> 32) as u32,
            options(nomem, nostack, preserves_flags)
        );
    }
}

//! The local APIC: one per CPU, at the same address on every CPU, each CPU seeing its own.
//!
//! # Two ways to reach it
//!
//! **MMIO**, at the address the MADT gives (0xFEE0_0000 on every PC), a page of 32-bit
//! registers. **x2APIC**, where the same registers are model-specific registers at
//! `0x800 + offset / 16`, IDs are 32 bits, and the interrupt command register is one
//! 64-bit MSR instead of two words. x2APIC mode is used when CPUID reports it, because
//! it needs no mapping and cannot be reached by a stray pointer; the MMIO window is
//! claimed either way, so a machine without x2APIC finds it mapped.
//!
//! [`LocalRegisters`] is the seam: everything else in this file is register arithmetic
//! over it, which is what the host tests drive.
//!
//! # The timer
//!
//! A 32-bit down-counter with a divider, and nothing that says how fast it counts. The
//! rate is measured once against the kernel's clock source ([`rate_per_second`]), at
//! divide-by-16, the same on every CPU because they share the bus clock that drives it.
//! QEMU counts one nanosecond per tick before the divider, so a whole count reaches
//! about 68 seconds; real hardware counts slower and reaches further.
//!
//! Reference: Intel SDM Vol. 3A, §11.4 (local APIC registers), §11.5.4 (timer), §11.6.1
//! (interrupt command register), §11.12 (x2APIC).

#![allow(unsafe_code)]

use device::Registers;

use crate::msr;

// Register offsets in the MMIO window. x2APIC reaches the same register at
// `X2APIC_MSR_BASE + offset / 16`.
pub const ID: usize = 0x020;
pub const TPR: usize = 0x080;
pub const EOI: usize = 0x0B0;
pub const SVR: usize = 0x0F0;
pub const ESR: usize = 0x280;
pub const ICR_LOW: usize = 0x300;
pub const ICR_HIGH: usize = 0x310;
pub const LVT_TIMER: usize = 0x320;
pub const LVT_LINT0: usize = 0x350;
pub const LVT_LINT1: usize = 0x360;
pub const LVT_ERROR: usize = 0x370;
pub const TIMER_INITIAL: usize = 0x380;
pub const TIMER_CURRENT: usize = 0x390;
pub const TIMER_DIVIDE: usize = 0x3E0;

/// LVT bit 16: the entry is masked.
pub const MASKED: u32 = 1 << 16;
/// LVT timer bits 17..19: periodic mode. Zero is one-shot.
pub const PERIODIC: u32 = 1 << 17;
/// SVR bit 8: the APIC is software-enabled.
pub const SOFTWARE_ENABLE: u32 = 1 << 8;
/// The divide configuration register's encoding of divide-by-16.
pub const DIVIDE_16: u32 = 0b0011;
/// ICR bit 12: the last command has not been delivered yet (MMIO mode only).
pub const DELIVERY_PENDING: u32 = 1 << 12;
/// ICR bit 14: level assert. Required for INIT and SIPI, harmless for fixed delivery.
pub const ASSERT: u32 = 1 << 14;
/// ICR delivery modes, bits 8..11.
pub const FIXED: u32 = 0b000 << 8;
pub const INIT: u32 = 0b101 << 8;
pub const STARTUP: u32 = 0b110 << 8;

/// `IA32_APIC_BASE`, and its enable bits.
pub const APIC_BASE_MSR: u32 = 0x1B;
pub const APIC_GLOBAL_ENABLE: u64 = 1 << 11;
pub const APIC_X2APIC_ENABLE: u64 = 1 << 10;
/// The first x2APIC register MSR.
pub const X2APIC_MSR_BASE: u32 = 0x800;
/// The x2APIC interrupt command register, one 64-bit MSR.
pub const X2APIC_ICR: u32 = X2APIC_MSR_BASE + (ICR_LOW as u32 >> 4);

/// How long an MMIO interrupt command may stay pending before it is abandoned. A real
/// APIC delivers within microseconds; this bounds a dead one.
const DELIVERY_POLLS: u32 = 100_000;

/// Register access to the calling CPU's local APIC.
pub trait LocalRegisters {
    fn read(&self, offset: usize) -> u32;
    fn write(&self, offset: usize, value: u32);
    /// The calling CPU's APIC ID.
    fn id(&self) -> u32;
    /// Issue an interrupt command `low` to the APIC whose ID is `dest`. Returns whether the
    /// controller accepted it.
    fn command(&self, dest: u32, low: u32) -> bool;
    /// Put the calling CPU's APIC into the mode this access uses. Returns whether it could.
    fn enter_mode(&self) -> bool;
}

/// The local APIC through its memory-mapped window.
pub struct MmioLocal(pub Registers);

impl LocalRegisters for MmioLocal {
    fn read(&self, offset: usize) -> u32 {
        self.0.read32(offset)
    }

    fn write(&self, offset: usize, value: u32) {
        self.0.write32(offset, value)
    }

    fn id(&self) -> u32 {
        self.0.read32(ID) >> 24
    }

    fn command(&self, dest: u32, low: u32) -> bool {
        // The high word first: the write to the low word is what sends.
        self.0.write32(ICR_HIGH, (dest & 0xff) << 24);
        self.0.write32(ICR_LOW, low);
        (0..DELIVERY_POLLS).any(|_| self.0.read32(ICR_LOW) & DELIVERY_PENDING == 0)
    }

    fn enter_mode(&self) -> bool {
        // Enabled at reset, and the window is where the MADT said. Nothing to switch.
        true
    }
}

/// The local APIC through x2APIC model-specific registers.
pub struct X2Local;

impl X2Local {
    fn msr(offset: usize) -> u32 {
        X2APIC_MSR_BASE + (offset as u32 >> 4)
    }
}

impl LocalRegisters for X2Local {
    fn read(&self, offset: usize) -> u32 {
        // SAFETY: an x2APIC exists, which `crate::install` checked before choosing this
        // access, and every offset this driver uses names a register x2APIC mode defines.
        unsafe { msr::read(Self::msr(offset)) as u32 }
    }

    fn write(&self, offset: usize, value: u32) {
        // SAFETY: as `read`; the register's effect is this driver's to justify at the call.
        unsafe { msr::write(Self::msr(offset), u64::from(value)) }
    }

    fn id(&self) -> u32 {
        // In x2APIC mode the ID register is the whole 32-bit ID.
        self.read(ID)
    }

    fn command(&self, dest: u32, low: u32) -> bool {
        // SAFETY: the x2APIC ICR exists in x2APIC mode. One write sends; there is no
        // delivery status to poll.
        unsafe { msr::write(X2APIC_ICR, (u64::from(dest) << 32) | u64::from(low)) };
        true
    }

    fn enter_mode(&self) -> bool {
        // SAFETY: IA32_APIC_BASE exists on every CPU with an APIC. Setting EXTD with the
        // global enable already set is the transition the SDM permits (§11.12.1); the base
        // address bits are written back unchanged.
        unsafe {
            let base = msr::read(APIC_BASE_MSR);
            msr::write(APIC_BASE_MSR, base | APIC_GLOBAL_ENABLE | APIC_X2APIC_ENABLE);
        }
        true
    }
}

/// Prepare the calling CPU's local APIC: accept everything, mask every local source, and
/// software-enable it with `spurious` as the spurious vector. Returns its APIC ID.
///
/// LINT0 is where the legacy 8259A is wired in virtual-wire mode, and LINT1 is NMI.
/// Masking both is what disconnects the old controller from this CPU; its own lines are
/// masked by the architecture separately.
pub fn prepare_cpu(l: &impl LocalRegisters, spurious: u8, timer: u8) -> u32 {
    l.write(TPR, 0);
    l.write(LVT_LINT0, MASKED);
    l.write(LVT_LINT1, MASKED);
    l.write(LVT_ERROR, MASKED);
    l.write(LVT_TIMER, MASKED | u32::from(timer));
    l.write(TIMER_INITIAL, 0);
    l.write(TIMER_DIVIDE, DIVIDE_16);
    // Writing the error status register before reading it is how the SDM says to latch
    // errors; zero is the only value x2APIC mode accepts.
    l.write(ESR, 0);
    l.write(SVR, SOFTWARE_ENABLE | u32::from(spurious));
    l.id()
}

/// Timer counts, at the measured `rate` per second, that cover at least `ns` nanoseconds:
/// rounded up, at least one, and at most what the 32-bit counter holds.
///
/// `ns * rate` cannot overflow for any `ns` within [`reach_ns`], which is the most a
/// caller may usefully ask for: it is at most `u32::MAX * 10^9`.
pub fn count_for(ns: u64, rate: u64) -> u32 {
    let ns = ns.min(reach_ns(rate));
    let count = ns.saturating_mul(rate).div_ceil(1_000_000_000);
    u32::try_from(count).unwrap_or(u32::MAX).max(1)
}

/// The longest delay a whole count reaches at `rate` counts per second, in nanoseconds.
/// Zero for an unmeasured timer.
pub fn reach_ns(rate: u64) -> u64 {
    (u64::from(u32::MAX) * 1_000_000_000)
        .checked_div(rate)
        .unwrap_or(0)
}

/// The delay `count` counts make at `rate` per second, in nanoseconds, rounded down.
pub fn ns_for(count: u32, rate: u64) -> u64 {
    (u64::from(count) * 1_000_000_000)
        .checked_div(rate)
        .unwrap_or(0)
}

/// The timer's rate, from `counted` counts observed over `elapsed` clock ticks of a clock
/// running at `clock_hz`. `None` when the measurement cannot be a rate: nothing counted,
/// no time passed, or a product too large to be a real timer.
pub fn rate_per_second(counted: u64, elapsed: u64, clock_hz: u64) -> Option<u64> {
    if counted == 0 || elapsed == 0 {
        return None;
    }
    let rate = counted.checked_mul(clock_hz)? / elapsed;
    (rate > 0).then_some(rate)
}

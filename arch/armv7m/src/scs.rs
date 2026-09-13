//! The System Control Space: the registers every ARMv7-M core has at the same addresses,
//! whatever the board around it.
//!
//! Only what this port uses is named. Offsets and bit positions are from the ARMv7-M
//! Architecture Reference Manual (DDI 0403E), section B3.

use core::ptr::{read_volatile, write_volatile};

/// SysTick Control and Status.
pub const SYST_CSR: usize = 0xE000_E010;
/// SysTick Reload Value.
pub const SYST_RVR: usize = 0xE000_E014;
/// SysTick Current Value.
pub const SYST_CVR: usize = 0xE000_E018;

/// NVIC Interrupt Set-Enable, first of eight.
pub const NVIC_ISER: usize = 0xE000_E100;
/// NVIC Interrupt Clear-Enable, first of eight.
pub const NVIC_ICER: usize = 0xE000_E180;
/// NVIC Interrupt Clear-Pending, first of eight.
pub const NVIC_ICPR: usize = 0xE000_E280;
/// NVIC Interrupt Priority, one byte per interrupt.
pub const NVIC_IPR: usize = 0xE000_E400;

/// Interrupt Control and State.
pub const ICSR: usize = 0xE000_ED04;
/// Vector Table Offset.
pub const VTOR: usize = 0xE000_ED08;
/// System Handler Priority 3: PendSV in bits 23:16, SysTick in 31:24.
pub const SHPR3: usize = 0xE000_ED20;
/// System Handler Control and State.
pub const SHCSR: usize = 0xE000_ED24;
/// Configurable Fault Status: MemManage in bits 7:0, BusFault 15:8, UsageFault 31:16.
pub const CFSR: usize = 0xE000_ED28;
/// HardFault Status.
pub const HFSR: usize = 0xE000_ED2C;
/// MemManage Fault Address.
pub const MMFAR: usize = 0xE000_ED34;
/// BusFault Address.
pub const BFAR: usize = 0xE000_ED38;

/// MPU Type.
pub const MPU_TYPE: usize = 0xE000_ED90;
/// MPU Control.
pub const MPU_CTRL: usize = 0xE000_ED94;
/// MPU Region Number.
pub const MPU_RNR: usize = 0xE000_ED98;
/// MPU Region Base Address.
pub const MPU_RBAR: usize = 0xE000_ED9C;
/// MPU Region Attribute and Size.
pub const MPU_RASR: usize = 0xE000_EDA0;

/// `ICSR.PENDSVSET`.
pub const ICSR_PENDSVSET: u32 = 1 << 28;
/// `ICSR.PENDSTSET`: the SysTick exception is pending.
pub const ICSR_PENDSTSET: u32 = 1 << 26;

/// `SHCSR`: MemManage, BusFault and UsageFault enabled as exceptions of their own, so a
/// report names the fault rather than a HardFault that escalated.
pub const SHCSR_FAULTS_ENABLED: u32 = (1 << 16) | (1 << 17) | (1 << 18);

/// Read a System Control Space register.
///
/// # Safety
/// `reg` must be one of the addresses above, which every ARMv7-M core decodes; reading
/// none of them has side effects.
pub unsafe fn read(reg: usize) -> u32 {
    // SAFETY: the caller's contract.
    unsafe { read_volatile(reg as *const u32) }
}

/// Write a System Control Space register.
///
/// # Safety
/// `reg` must be one of the addresses above, and the value one its register accepts in
/// the state the caller has put the core in.
pub unsafe fn write(reg: usize, value: u32) {
    // SAFETY: the caller's contract.
    unsafe { write_volatile(reg as *mut u32, value) }
}

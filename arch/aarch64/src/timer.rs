//! The Arm generic timer, used here only as an interrupt source that is guaranteed to
//! be present.
//!
//! Every ARMv8-A CPU has it, it needs no discovery, and it is wired to a fixed private
//! peripheral interrupt — which makes it the one device a Phase 0 kernel can provoke
//! an interrupt from without a device tree. The EL1 physical timer is PPI 30; the
//! secure physical timer is 29, the virtual timer 27 and the EL2 timer 26, and picking
//! the wrong one produces a timer that counts down perfectly and never interrupts.
//!
//! This is not a clocksource. Timekeeping, tick programming and one-shot deadlines are
//! Phase 2 work and will not live in `arch`.
//!
//! Reference: Arm Architecture Reference Manual for A-profile, DDI 0487, D11
//! ("The Generic Timer in AArch64 state").

/// Interrupt ID of the EL1 physical timer, fixed by the Server Base System
/// Architecture and used by every board this port targets, QEMU `virt` included.
pub const PPI: u32 = 30;

/// `CNTP_CTL_EL0.ENABLE`.
const CTL_ENABLE: u64 = 1 << 0;

/// Frequency of the system counter in Hz, as firmware recorded it in `CNTFRQ_EL0`.
///
/// On real hardware this is only as trustworthy as the firmware that set it; there is
/// no way to measure it independently this early.
pub fn frequency() -> u64 {
    let freq: u64;
    // SAFETY: CNTFRQ_EL0 is readable at EL1 and reading it has no side effects.
    unsafe {
        core::arch::asm!(
            "mrs {}, cntfrq_el0",
            out(reg) freq,
            options(nomem, nostack, preserves_flags)
        );
    }
    freq
}

/// The system counter's current value — monotonic, and the only clock available here.
pub fn counter() -> u64 {
    let count: u64;
    // SAFETY: CNTPCT_EL0 is readable at EL1 once CNTHCTL_EL2.EL1PCTEN allows it, which
    // the boot code arranges when it descends from EL2. `isb` before the read is what
    // stops the counter being sampled speculatively early, which would make a timeout
    // computed from it expire sooner than asked.
    unsafe {
        core::arch::asm!(
            "isb",
            "mrs {}, cntpct_el0",
            out(reg) count,
            options(nomem, nostack, preserves_flags)
        );
    }
    count
}

/// Arm the physical timer to fire once, `ticks` counter ticks from now.
///
/// The interrupt is level-sensitive and stays asserted until the timer is reprogrammed
/// or stopped, so a handler that only signals EOI will be re-entered immediately.
/// [`stop`] is what actually silences it.
pub fn arm(ticks: u32) {
    // SAFETY: writing CNTP_TVAL_EL0 sets the down-counter and writing CNTP_CTL_EL0
    // starts it; both are accessible at EL1 and their only effect is on this CPU's own
    // physical timer, which nothing else in the kernel is using. IMASK is left clear so
    // the condition reaches the interrupt controller. `isb` ensures the timer is
    // running before the caller unmasks interrupts and starts waiting for it.
    unsafe {
        core::arch::asm!(
            "msr cntp_tval_el0, {ticks}",
            "msr cntp_ctl_el0, {ctl}",
            "isb",
            ticks = in(reg) ticks as u64,
            ctl = in(reg) CTL_ENABLE,
            options(nomem, nostack, preserves_flags)
        );
    }
}

/// Stop the physical timer, deasserting its interrupt line.
pub fn stop() {
    // SAFETY: clearing CNTP_CTL_EL0 disables this CPU's physical timer and nothing
    // else. Safe to call whether or not the timer was running, which matters because
    // the interrupt handler calls it without knowing.
    unsafe {
        core::arch::asm!(
            "msr cntp_ctl_el0, xzr",
            "isb",
            options(nomem, nostack, preserves_flags)
        );
    }
}

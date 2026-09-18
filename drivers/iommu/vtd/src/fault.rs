//! Reading the fault log (VT-d §10.4.14).
//!
//! When a device reaches an address its domain does not map, the hardware records the fault in
//! a fault-recording register: which device (its source id), which address, and why. This is
//! what turns "the DMA was blocked" from a hope into evidence — a check that a rogue device was
//! stopped reads the fault back and reports the address and device it names.
//!
//! This reads the first fault-recording register, which is where QEMU's single unit records,
//! and clears it. A machine with a deeper log would iterate `CAP.NFR + 1` of them; one is what
//! the demonstration needs and what is host-tested.

use iommu::Fault;

use crate::{Regs, reg};

/// Whether a reason code is an interrupt-remapping fault (VT-d §7.1, reasons 0x20 to 0x26): a
/// message blocked by the remapping table rather than a DMA blocked by a domain.
///
/// This range is VT-d's, so it stays here: what leaves this crate is the decoded index, not a
/// number a caller would have to look up in Intel's table to understand.
fn is_interrupt(reason: u8) -> bool {
    (0x20..=0x26).contains(&reason)
}

/// The fault-recording register block's offset: CAP.FRO (bits [33:24], in 16-byte units).
fn fro(regs: &impl Regs) -> usize {
    let cap = regs.read64(reg::CAP);
    ((cap >> 24) & 0x3ff) as usize * 16
}

/// The next recorded fault, cleared as it is read, or `None` when the log is empty.
pub fn take(regs: &impl Regs) -> Option<Fault> {
    // Nothing pending unless the fault-status register says a primary fault is.
    if regs.read32(reg::FSTS) & reg::fsts::PPF == 0 {
        return None;
    }
    let base = fro(regs);
    // A fault-recording register is 16 bytes. The high qword's bit 63 (F) says it holds a
    // fault; the low qword is the faulting address, its low 12 bits zero.
    let high = regs.read64(base + 8);
    if high & (1 << 63) == 0 {
        // PPF was set but this register is empty: clear the status bit and report nothing, so a
        // stale status does not read as an endless fault.
        clear_status(regs);
        return None;
    }
    let low = regs.read64(base);
    let reason = ((high >> 32) & 0xff) as u8;
    // For a DMA fault this is the address the device named. For an interrupt-remapping fault it
    // is the fault information field instead, whose bits 63:48 are the table index the blocked
    // message named (VT-d §10.4.14) — decoded here, so that nothing above has to know which
    // reason codes mean which.
    let address = low & !0xfff;
    let fault = Fault {
        address,
        source_id: (high & 0xffff) as u16,
        reason,
        // The Type bit is bit 126 of the record, i.e. bit 62 of the high qword: 0 is a write
        // request, 1 is a read (VT-d §10.4.14).
        write: (high >> 62) & 1 == 0,
        interrupt_index: is_interrupt(reason).then_some((address >> 48) as u16),
    };
    // Clear the record by writing 1 to its F bit, then clear the pending-fault status.
    regs.write64(base + 8, 1 << 63);
    clear_status(regs);
    Some(fault)
}

/// Clear the primary-pending and overflow bits by writing 1 to them (write-1-to-clear).
fn clear_status(regs: &impl Regs) {
    regs.write32(reg::FSTS, reg::fsts::PPF | reg::fsts::PFO);
}

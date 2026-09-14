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

use crate::{Regs, reg};

/// One recorded fault: a DMA the device's domain does not allow, or an interrupt the
/// remapping table does not.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Fault {
    /// The device address the device tried to reach. For an interrupt-remapping fault, the
    /// fault information field instead, whose top 16 bits are the table index the blocked
    /// message named; see [`Fault::interrupt_index`].
    pub address: u64,
    /// The faulting device's source id (`bus << 8 | dev << 3 | fn`).
    pub source_id: u16,
    /// The fault reason (VT-d §7.1, Table 7-1): e.g. 5 is "write to a non-writable page", 6 is
    /// "read from a page with no read permission".
    pub reason: u8,
    /// Whether the access was a write.
    pub write: bool,
}

impl Fault {
    /// Whether this is an interrupt-remapping fault (VT-d §7.1, reasons 0x20 to 0x26): a
    /// message blocked by the remapping table rather than a DMA blocked by a domain.
    pub fn is_interrupt(&self) -> bool {
        (0x20..=0x26).contains(&self.reason)
    }

    /// For an interrupt-remapping fault, the table index the blocked message named: bits
    /// 63:48 of the fault information field (VT-d §10.4.14).
    pub fn interrupt_index(&self) -> Option<u16> {
        self.is_interrupt().then_some((self.address >> 48) as u16)
    }
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
    let fault = Fault {
        address: low & !0xfff,
        source_id: (high & 0xffff) as u16,
        reason: ((high >> 32) & 0xff) as u8,
        // The Type bit is bit 126 of the record, i.e. bit 62 of the high qword: 0 is a write
        // request, 1 is a read (VT-d §10.4.14).
        write: (high >> 62) & 1 == 0,
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

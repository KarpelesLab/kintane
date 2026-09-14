//! Models of the three things the hardware provides — the unit's registers, the frames the
//! tables live in, and the physical memory the CPU writes them through — so the whole driver
//! runs as a host test.
//!
//! [`MockRegs`] does what a real unit does to the few registers that have side effects:
//! latching the root-table pointer, completing an invalidation the instant it is asked, and
//! reflecting the translation-enable command in the status register. It also lets a test *plant*
//! a fault, the way a device reaching an unmapped address would, so the fault-log reader can be
//! tested without a device.

use std::cell::RefCell;
use std::collections::HashMap;

use crate::{Frames, PhysMem, Regs, reg};

/// CAP.MGAW: 48-bit guest address width, encoded as 47 in bits [21:16].
const CAP_MGAW: u64 = 47 << 16;
/// CAP.FRO: the fault-recording register block, 0x200 bytes in (0x20 sixteen-byte units).
pub const FRO_UNITS: u64 = 0x20;
const CAP_FRO: u64 = FRO_UNITS << 24;
/// ECAP.IRO: the IOTLB register block, 0x100 bytes in (0x10 sixteen-byte units).
pub const IRO_UNITS: u64 = 0x10;
const ECAP_IRO: u64 = IRO_UNITS << 8;

/// The IOTLB command register this CAP/ECAP places: IRO block + 8.
pub const IOTLB_CMD: usize = (IRO_UNITS as usize) * 16 + 8;
/// The first fault-recording register's high qword: FRO block + 8.
pub const FRCD_HIGH: usize = (FRO_UNITS as usize) * 16 + 8;
pub const FRCD_LOW: usize = (FRO_UNITS as usize) * 16;

/// A modelled register file, with the side effects a real unit has.
pub struct MockRegs {
    words: RefCell<HashMap<usize, u64>>,
}

impl MockRegs {
    /// A unit like QEMU's: 48-bit width, and the fault and IOTLB register blocks the constants
    /// above place. Translation off, no faults.
    pub fn new() -> MockRegs {
        let regs = MockRegs {
            words: RefCell::new(HashMap::new()),
        };
        regs.words.borrow_mut().insert(reg::CAP, CAP_MGAW | CAP_FRO);
        regs.words.borrow_mut().insert(reg::ECAP, ECAP_IRO);
        regs
    }

    /// A unit that reports a narrower address width than any domain here uses.
    pub fn narrow() -> MockRegs {
        let regs = MockRegs::new();
        regs.words
            .borrow_mut()
            .insert(reg::CAP, (38u64 << 16) | CAP_FRO);
        regs
    }

    /// Plant a fault the way the hardware would when a device reached `address`.
    pub fn plant_fault(&self, address: u64, source_id: u16, reason: u8, write: bool) {
        let mut w = self.words.borrow_mut();
        let high = (1u64 << 63)
            | (u64::from(source_id))
            | (u64::from(reason) << 32)
            | (u64::from(!write) << 62);
        w.insert(FRCD_LOW, address & !0xfff);
        w.insert(FRCD_HIGH, high);
        let fsts = w.get(&reg::FSTS).copied().unwrap_or(0);
        w.insert(reg::FSTS, fsts | u64::from(reg::fsts::PPF));
    }

    fn get(&self, offset: usize) -> u64 {
        self.words.borrow().get(&offset).copied().unwrap_or(0)
    }
}

impl Regs for MockRegs {
    fn read32(&self, offset: usize) -> u32 {
        self.get(offset) as u32
    }

    fn read64(&self, offset: usize) -> u64 {
        self.get(offset)
    }

    fn write32(&self, offset: usize, value: u32) {
        let value = u64::from(value);
        match offset {
            reg::GCMD => {
                // GCMD's command bits sit at the same positions as the GSTS status bits they
                // set, so the resulting status is the commanded value latched. SRTP (bit 30)
                // becomes RTPS, TE (bit 31) becomes TES.
                self.words.borrow_mut().insert(reg::GSTS, value);
            }
            reg::FSTS => {
                // Write-1-to-clear.
                let mut w = self.words.borrow_mut();
                let cur = w.get(&reg::FSTS).copied().unwrap_or(0);
                w.insert(reg::FSTS, cur & !value);
            }
            _ => {
                self.words.borrow_mut().insert(offset, value);
            }
        }
    }

    fn write64(&self, offset: usize, value: u64) {
        match offset {
            reg::CCMD if value & (1 << 63) != 0 => {
                // The invalidation completes at once: clear the command bit.
                self.words
                    .borrow_mut()
                    .insert(reg::CCMD, value & !(1 << 63));
            }
            IOTLB_CMD if value & (1 << 63) != 0 => {
                self.words
                    .borrow_mut()
                    .insert(IOTLB_CMD, value & !(1 << 63));
            }
            FRCD_HIGH if value & (1 << 63) != 0 => {
                // Writing 1 to F clears the fault record.
                self.words.borrow_mut().insert(FRCD_HIGH, 0);
            }
            _ => {
                self.words.borrow_mut().insert(offset, value);
            }
        }
    }
}

/// Physical memory as a sparse map of 64-bit words: the table frames, and nothing else.
#[derive(Default)]
pub struct MockMem {
    words: RefCell<HashMap<u64, u64>>,
}

impl PhysMem for MockMem {
    fn read64(&self, phys: u64) -> u64 {
        assert_eq!(phys % 8, 0, "a table entry is a whole aligned u64");
        self.words.borrow().get(&phys).copied().unwrap_or(0)
    }

    fn write64(&self, phys: u64, value: u64) {
        assert_eq!(phys % 8, 0, "a table entry is a whole aligned u64");
        self.words.borrow_mut().insert(phys, value);
    }
}

/// A frame pool that hands out page-aligned addresses in order, up to a cap.
pub struct MockFrames {
    next: u64,
    end: u64,
    /// Every frame handed out, so a test can assert none was reused.
    pub given: Vec<u64>,
}

impl MockFrames {
    /// `count` frames, starting well above where the tests place devices and buffers.
    pub fn new(count: u64) -> MockFrames {
        let base = 0x1_0000_0000;
        MockFrames {
            next: base,
            end: base + count * crate::PAGE_SIZE,
            given: Vec::new(),
        }
    }
}

impl Frames for MockFrames {
    fn alloc(&mut self) -> Option<u64> {
        if self.next >= self.end {
            return None;
        }
        let frame = self.next;
        self.next += crate::PAGE_SIZE;
        self.given.push(frame);
        Some(frame)
    }
}

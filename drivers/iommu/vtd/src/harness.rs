//! Models of the three things the hardware provides — the unit's registers, the frames the
//! tables live in, and the physical memory the CPU writes them through — so the whole driver
//! runs as a host test.
//!
//! [`MockRegs`] does what a real unit does to the few registers that have side effects:
//! latching the root-table pointer, completing an invalidation the instant it is asked, and
//! reflecting the translation-enable command in the status register. It also lets a test *plant*
//! a fault, the way a device reaching an unmapped address would, so the fault-log reader can be
//! tested without a device.
//!
//! A unit built [`MockRegs::with_queue`] shares the memory the driver writes its tables and its
//! invalidation queue into, and processes the queue when its tail moves. It also models the two
//! caches the queue exists to invalidate: the IOTLB, filled by [`MockRegs::device_translate`] the
//! way a device's DMA fills it, and the interrupt entry cache, filled by [`MockRegs::deliver`].
//! Both keep serving what they cached until a descriptor says otherwise, so a test can show a
//! change that was not flushed being ignored.

use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::rc::Rc;

use crate::{Domain, Frames, InterruptTable, Irte, PAGE_SIZE, PhysMem, QUEUE_ENTRIES, Regs, reg};

/// CAP.MGAW: 48-bit guest address width, encoded as 47 in bits [21:16].
const CAP_MGAW: u64 = 47 << 16;
/// CAP.FRO: the fault-recording register block, 0x200 bytes in (0x20 sixteen-byte units).
pub const FRO_UNITS: u64 = 0x20;
const CAP_FRO: u64 = FRO_UNITS << 24;
/// ECAP.IRO: the IOTLB register block, 0x100 bytes in (0x10 sixteen-byte units).
pub const IRO_UNITS: u64 = 0x10;
const ECAP_IRO: u64 = IRO_UNITS << 8;
/// ECAP.IR and ECAP.EIM: interrupt remapping, with extended interrupt mode, as QEMU's
/// `intel-iommu,intremap=on` behind a split irqchip reports.
const ECAP_REMAPPING: u64 = reg::ecap::IR | reg::ecap::EIM;

/// The IOTLB command register this CAP/ECAP places: IRO block + 8.
pub const IOTLB_CMD: usize = (IRO_UNITS as usize) * 16 + 8;
/// The first fault-recording register's high qword: FRO block + 8.
pub const FRCD_HIGH: usize = (FRO_UNITS as usize) * 16 + 8;
pub const FRCD_LOW: usize = (FRO_UNITS as usize) * 16;

/// A modelled register file, with the side effects a real unit has.
pub struct MockRegs {
    words: RefCell<HashMap<usize, u64>>,
    /// The memory the tables and the queue live in, for a unit that processes its queue.
    mem: Option<MockMem>,
    /// Translations devices have used, by domain and page: the IOTLB.
    iotlb: RefCell<HashMap<(u16, u64), (u64, bool)>>,
    /// Interrupt remapping entries the unit has read, by handle: the interrupt entry cache.
    iec: RefCell<HashMap<u16, (u64, u64)>>,
    /// Every descriptor the queue processed, in order, waits included.
    log: RefCell<Vec<(u64, u64)>>,
    /// A descriptor type this unit rejects, as a unit that finds a reserved bit set does.
    reject: Cell<Option<u64>>,
    /// Whether the queue's head never moves.
    stalled: Cell<bool>,
}

impl MockRegs {
    /// A unit like QEMU's: 48-bit width, and the fault and IOTLB register blocks the constants
    /// above place. Translation off, no faults, no invalidation queue.
    pub fn new() -> MockRegs {
        let regs = MockRegs {
            words: RefCell::new(HashMap::new()),
            mem: None,
            iotlb: RefCell::new(HashMap::new()),
            iec: RefCell::new(HashMap::new()),
            log: RefCell::new(Vec::new()),
            reject: Cell::new(None),
            stalled: Cell::new(false),
        };
        regs.words.borrow_mut().insert(reg::CAP, CAP_MGAW | CAP_FRO);
        regs.words
            .borrow_mut()
            .insert(reg::ECAP, ECAP_IRO | ECAP_REMAPPING);
        regs
    }

    /// A unit with an invalidation queue and page-selective invalidation, as QEMU's is, reading
    /// its queue and tables from `mem`.
    pub fn with_queue(mem: &MockMem) -> MockRegs {
        let mut regs = MockRegs::new();
        regs.mem = Some(mem.clone());
        regs.or_word(reg::ECAP, reg::ecap::QI);
        regs.or_word(reg::CAP, reg::cap::PSI);
        regs
    }

    /// [`MockRegs::with_queue`], in caching mode, as `intel-iommu,caching-mode=on` reports.
    pub fn with_caching_mode(mem: &MockMem) -> MockRegs {
        let regs = MockRegs::with_queue(mem);
        regs.or_word(reg::CAP, reg::cap::CM);
        regs
    }

    /// A unit with no interrupt remapping.
    pub fn without_remapping() -> MockRegs {
        let regs = MockRegs::new();
        regs.words.borrow_mut().insert(reg::ECAP, ECAP_IRO);
        regs
    }

    /// A unit that remaps interrupts in xAPIC mode only: 8-bit destinations.
    pub fn xapic_remapping() -> MockRegs {
        let regs = MockRegs::new();
        regs.words
            .borrow_mut()
            .insert(reg::ECAP, ECAP_IRO | reg::ecap::IR);
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

    /// Reject every descriptor of type `kind` from now on, setting `FSTS.IQE`.
    pub fn reject_descriptor(&self, kind: u64) {
        self.reject.set(Some(kind));
    }

    /// Stop processing the queue: a unit that never answers.
    pub fn stall_queue(&self) {
        self.stalled.set(true);
    }

    /// Every descriptor the queue has processed, in order.
    pub fn descriptors(&self) -> Vec<(u64, u64)> {
        self.log.borrow().clone()
    }

    /// A DMA to `iova` by a device in `domain`, resolved the way the hardware resolves it: from
    /// the IOTLB when it holds the page, otherwise from the tables, caching what it found.
    pub fn device_translate(&self, domain: &Domain, iova: u64) -> Option<(u64, bool)> {
        let mem = self.mem.as_ref().expect("a unit modelled over its memory");
        let page = iova & !(PAGE_SIZE - 1);
        let offset = iova & (PAGE_SIZE - 1);
        if let Some(&(phys, write)) = self.iotlb.borrow().get(&(domain.id(), page)) {
            return Some((phys + offset, write));
        }
        let (phys, write) = domain.translate(page, mem)?;
        self.iotlb
            .borrow_mut()
            .insert((domain.id(), page), (phys, write));
        Some((phys + offset, write))
    }

    /// A message naming `handle`, remapped the way the hardware remaps it: from the interrupt
    /// entry cache when it holds the handle, otherwise from `table`, caching a present entry.
    pub fn deliver(&self, table: &InterruptTable, handle: u16) -> Option<Irte> {
        let mem = self.mem.as_ref().expect("a unit modelled over its memory");
        let cached = self.iec.borrow().get(&handle).copied();
        let (low, high) = match cached {
            Some(entry) => entry,
            None => {
                let at = table.phys() + u64::from(handle) * 16;
                let entry = (mem.read64(at), mem.read64(at + 8));
                if entry.0 & 1 != 0 {
                    self.iec.borrow_mut().insert(handle, entry);
                }
                entry
            }
        };
        Irte::decode(low, high, table.extended())
    }

    fn get(&self, offset: usize) -> u64 {
        self.words.borrow().get(&offset).copied().unwrap_or(0)
    }

    fn or_word(&self, offset: usize, bits: u64) {
        let value = self.get(offset) | bits;
        self.words.borrow_mut().insert(offset, value);
    }

    /// Process the queue from its head up to its tail, as the hardware does when the tail moves.
    fn run_queue(&self) {
        let Some(mem) = &self.mem else {
            return;
        };
        if self.get(reg::GSTS) & u64::from(reg::gsts::QIES) == 0 || self.stalled.get() {
            return;
        }
        let base = self.get(reg::IQA) & !0xfff;
        let tail = self.get(reg::IQT) >> 4;
        let mut head = self.get(reg::IQH) >> 4;
        while head != tail {
            let at = base + head * 16;
            let (low, high) = (mem.read64(at), mem.read64(at + 8));
            if !self.process(mem, low, high) {
                self.or_word(reg::FSTS, u64::from(reg::fsts::IQE));
                break;
            }
            self.log.borrow_mut().push((low, high));
            head = (head + 1) % QUEUE_ENTRIES;
        }
        self.words.borrow_mut().insert(reg::IQH, head << 4);
    }

    /// Carry out one descriptor. `false` for one this unit rejects.
    fn process(&self, mem: &MockMem, low: u64, high: u64) -> bool {
        let kind = low & 0xf;
        if self.reject.get() == Some(kind) {
            return false;
        }
        match kind {
            // Context cache: nothing modelled, but the granularity and reserved high qword are.
            1 => high == 0 && (low >> 4) & 0b11 != 0,
            2 => {
                let domain = (low >> 16) as u16;
                match (low >> 4) & 0b11 {
                    0b10 => self.iotlb.borrow_mut().retain(|&(d, _), _| d != domain),
                    0b11 => {
                        let (from, span) = (high & !0xfff, PAGE_SIZE << (high & 0x3f));
                        self.iotlb.borrow_mut().retain(|&(d, page), _| {
                            d != domain || page < from || page >= from + span
                        });
                    }
                    _ => return false,
                }
                true
            }
            4 => {
                if high != 0 {
                    return false;
                }
                if low & (1 << 4) == 0 {
                    self.iec.borrow_mut().clear();
                } else {
                    let (index, mask) = ((low >> 32) & 0xffff, (low >> 27) & 0x1f);
                    self.iec.borrow_mut().retain(|&h, _| {
                        let h = u64::from(h);
                        h < index || h >= index + (1 << mask)
                    });
                }
                true
            }
            5 => {
                if low & (1 << 5) == 0 {
                    return false;
                }
                let at = high & !0b11;
                let old = mem.read64(at);
                mem.write64(at, (old & !0xffff_ffff) | (low >> 32));
                true
            }
            _ => false,
        }
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
                // becomes RTPS, TE (bit 31) becomes TES, QIE (bit 26) becomes QIES.
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
            reg::IQA => {
                // Writing the queue's address resets its head.
                let mut w = self.words.borrow_mut();
                w.insert(reg::IQA, value);
                w.insert(reg::IQH, 0);
            }
            reg::IQT => {
                self.words.borrow_mut().insert(reg::IQT, value);
                self.run_queue();
            }
            _ => {
                self.words.borrow_mut().insert(offset, value);
            }
        }
    }
}

/// Physical memory as a sparse map of 64-bit words: the table frames, and nothing else. Cloning
/// shares it, so a modelled unit reads what the driver writes.
#[derive(Default, Clone)]
pub struct MockMem {
    words: Rc<RefCell<HashMap<u64, u64>>>,
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

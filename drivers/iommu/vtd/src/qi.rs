//! Queued invalidation (VT-d §6.5.2): how software tells the hardware to forget what it cached.
//!
//! A unit caches what it reads from its tables: context entries, translations (the IOTLB), and
//! interrupt remapping entries (the interrupt entry cache, IEC). Changing an entry the hardware
//! may have cached is only half a change. The other half is invalidating the cache, and until
//! that completes the old entry may still be used: a mapping torn down without it can still be
//! reached by DMA, and an interrupt entry changed without it can still deliver where it used to.
//!
//! The register interface (`CCMD`, the IOTLB register) invalidates contexts and translations
//! globally, but it cannot invalidate an interrupt entry at all. The *invalidation queue* can: a
//! ring of 128-bit descriptors in memory, which the hardware reads from `IQH` up to `IQT`.
//! Software appends descriptors, appends an *invalidation wait* descriptor whose status write says
//! everything before it is done, moves the tail, and waits for that write.
//!
//! # What is here
//!
//! - [`Unit::enable_queued_invalidation`]: one frame of [`QUEUE_ENTRIES`] descriptors into `IQA`,
//!   then `QIE`. After translation is on: [`Unit::enable`] still invalidates through the registers,
//!   which the queue closes.
//! - [`Invalidation`], each encoded as §6.5.2 lays it out.
//! - [`Unit::invalidate`]: append, append a wait, move the tail, and wait for the status write
//!   under a bound. A descriptor the hardware rejects (`FSTS.IQE`) is an error, not a hang.
//! - [`Unit::unmap_in_use`] and [`Unit::map_in_use`]: a domain change followed by the flush it
//!   needs. And once remapping is on, [`Unit::set_irte`] flushes the entry it changed.
//!
//! # Not here
//!
//! A rejected descriptor leaves the hardware's head on it, and this driver does not recover the
//! queue: every later wait times out, and says so. Global IOTLB invalidation is not queued; the
//! kernel knows its domains and flushes them by domain or by page. Device-TLB (ATS) invalidation
//! is not built, because nothing here enables ATS.

use crate::pagetable::{Domain, Perm};
use crate::{Error, Frames, PAGE_SIZE, PhysMem, Regs, SPIN_LIMIT, Unit, reg, zero_frame};

/// Descriptors the queue holds: one frame of 16-byte descriptors (`IQA.QS` = 0).
pub const QUEUE_ENTRIES: u64 = 256;

/// The most invalidations one wait covers: the ring, less the wait that follows them and the
/// slot a full ring keeps empty so that a full ring and an empty one differ. A longer list is
/// submitted in batches of this.
const MAX_BATCH: usize = (QUEUE_ENTRIES - 2) as usize;

/// Pages [`Unit::unmap_in_use`] flushes one descriptor each; a longer range flushes the domain.
const PAGE_FLUSH_LIMIT: u64 = 32;

/// Descriptor types (§6.5.2, low four bits of the low qword).
const TYPE_CONTEXT: u64 = 0x1;
const TYPE_IOTLB: u64 = 0x2;
const TYPE_IEC: u64 = 0x4;
const TYPE_WAIT: u64 = 0x5;
/// Invalidation wait: write the status data to the status address when reached.
const WAIT_STATUS_WRITE: u64 = 1 << 5;

/// The queue a unit has turned on: its descriptor frame, the frame its waits write their status
/// into, where the next descriptor goes, and the last wait's cookie.
pub(crate) struct Queue {
    base: u64,
    status: u64,
    tail: u64,
    cookie: u32,
}

/// What one invalidation descriptor tells the hardware to forget.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Invalidation {
    /// Every cached context entry (§6.5.2.1, granularity 01).
    ContextGlobal,
    /// The context entry cached for `source` in `domain` (granularity 11).
    ContextDevice { domain: u16, source: u16 },
    /// Every translation cached for `domain` (§6.5.2.2, granularity 10).
    IotlbDomain { domain: u16 },
    /// The translations cached for `2^order` pages from `iova` in `domain` (granularity 11).
    IotlbPages { domain: u16, iova: u64, order: u8 },
    /// Every cached interrupt remapping entry (§6.5.2.7, granularity 0).
    InterruptGlobal,
    /// The cached interrupt remapping entry at `handle` (granularity 1, index mask 0).
    InterruptEntry { handle: u16 },
}

impl Invalidation {
    /// The descriptor's two qwords, low then high.
    pub fn encode(self) -> (u64, u64) {
        match self {
            Invalidation::ContextGlobal => (TYPE_CONTEXT | (0b01 << 4), 0),
            Invalidation::ContextDevice { domain, source } => (
                TYPE_CONTEXT | (0b11 << 4) | (u64::from(domain) << 16) | (u64::from(source) << 32),
                0,
            ),
            Invalidation::IotlbDomain { domain } => {
                (TYPE_IOTLB | (0b10 << 4) | (u64::from(domain) << 16), 0)
            }
            Invalidation::IotlbPages {
                domain,
                iova,
                order,
            } => (
                TYPE_IOTLB | (0b11 << 4) | (u64::from(domain) << 16),
                (iova & !(PAGE_SIZE - 1)) | u64::from(order & 0x3f),
            ),
            Invalidation::InterruptGlobal => (TYPE_IEC, 0),
            Invalidation::InterruptEntry { handle } => {
                (TYPE_IEC | (1 << 4) | (u64::from(handle) << 32), 0)
            }
        }
    }
}

/// The invalidation wait descriptor that ends a batch: write `cookie` to `status` when reached.
fn wait(status: u64, cookie: u32) -> (u64, u64) {
    (TYPE_WAIT | WAIT_STATUS_WRITE | (u64::from(cookie) << 32), status)
}

/// What the queue has done, for a report.
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct QueueStats {
    /// Invalidation descriptors the hardware completed, waits not counted.
    pub invalidations: u64,
    /// Batches submitted and seen complete: one wait each.
    pub waits: u64,
    /// The most status reads one wait needed before it saw its cookie.
    pub longest_wait: u32,
}

impl<R: Regs, M: PhysMem> Unit<R, M> {
    /// Whether the unit has an invalidation queue (`ECAP.QI`).
    pub fn supports_queued_invalidation(&self) -> bool {
        self.regs.read64(reg::ECAP) & reg::ecap::QI != 0
    }

    /// Turn the invalidation queue on: a descriptor frame and a status frame, the tail at zero,
    /// the queue's address into `IQA`, then `QIE`. From here every invalidation is queued, and
    /// the register interface refuses. Call after [`Unit::enable`]. Doing it again is a no-op.
    pub fn enable_queued_invalidation(&mut self, frames: &mut impl Frames) -> Result<(), Error> {
        if self.queue.is_some() {
            return Ok(());
        }
        if !self.supports_queued_invalidation() {
            return Err(Error::NoQueuedInvalidation);
        }
        let base = frames.alloc().ok_or(Error::NoFrames)?;
        let status = frames.alloc().ok_or(Error::NoFrames)?;
        zero_frame(&self.mem, base);
        zero_frame(&self.mem, status);
        // The tail at zero first: writing `IQA` resets the head to zero, and a tail anywhere else
        // would name descriptors nobody wrote.
        self.regs.write64(reg::IQT, 0);
        // `QS` = 0 (one frame), `DW` = 0 (128-bit descriptors): just the base.
        self.regs.write64(reg::IQA, base);
        self.command(reg::gcmd::QIE, reg::gsts::QIES, "enable queued invalidation")?;
        self.queue = Some(Queue {
            base,
            status,
            tail: 0,
            cookie: 0,
        });
        Ok(())
    }

    /// Whether the queue is on, read from the hardware.
    pub fn queued_invalidation_enabled(&self) -> bool {
        self.regs.read32(reg::GSTS) & reg::gsts::QIES != 0
    }

    /// What the queue has completed since it was turned on.
    pub fn queue_stats(&self) -> QueueStats {
        self.queue_stats
    }

    /// Invalidate `what`, and return once the hardware says it is done: each batch is followed
    /// by a wait descriptor, and its status write is waited for under [`SPIN_LIMIT`] reads.
    pub fn invalidate(&mut self, what: &[Invalidation]) -> Result<(), Error> {
        if self.queue.is_none() {
            return Err(Error::NoQueuedInvalidation);
        }
        for batch in what.chunks(MAX_BATCH) {
            self.submit(batch)?;
        }
        Ok(())
    }

    fn submit(&mut self, batch: &[Invalidation]) -> Result<(), Error> {
        let Some(q) = self.queue.as_mut() else {
            return Err(Error::NoQueuedInvalidation);
        };
        // Never zero, the value a cleared status word holds.
        q.cookie = q.cookie.wrapping_add(1).max(1);
        let (base, status, cookie) = (q.base, q.status, q.cookie);
        let mut tail = q.tail;
        let descriptors = batch.iter().map(|d| d.encode());
        for (low, high) in descriptors.chain(core::iter::once(wait(status, cookie))) {
            self.mem.write64(base + tail * 16, low);
            self.mem.write64(base + tail * 16 + 8, high);
            tail = (tail + 1) % QUEUE_ENTRIES;
        }
        q.tail = tail;
        // Cleared before the tail moves, so the status read below can only be this wait's.
        self.mem.write64(status, 0);
        self.regs.write64(reg::IQT, tail << 4);
        for spins in 0..SPIN_LIMIT {
            // The hardware writes 32 bits of status data; the frame's other bits stay zero.
            if self.mem.read64(status) as u32 == cookie {
                self.queue_stats.invalidations += batch.len() as u64;
                self.queue_stats.waits += 1;
                self.queue_stats.longest_wait = self.queue_stats.longest_wait.max(spins + 1);
                return Ok(());
            }
            if self.regs.read32(reg::FSTS) & reg::fsts::IQE != 0 {
                self.regs.write32(reg::FSTS, reg::fsts::IQE);
                return Err(Error::InvalidationRejected);
            }
        }
        Err(Error::Timeout("queued invalidation"))
    }

    /// Unmap `[iova, iova + len)` from `domain` while a device may be using it, and flush what
    /// the hardware cached of it, so the device faults on its next access rather than reaching
    /// the page through a stale translation.
    pub fn unmap_in_use(&mut self, domain: &Domain, iova: u64, len: u64) -> Result<(), Error> {
        domain.unmap(iova, len, &self.mem)?;
        self.flush_range(domain, iova, len)
    }

    /// Map `[iova, iova + len)` into `domain` while a device may be using it. A new mapping
    /// replaces a not-present entry, which only a unit in caching mode (`CAP.CM`, as an
    /// emulator shadowing the tables reports) may have cached; that unit is flushed too.
    pub fn map_in_use(
        &mut self,
        domain: &Domain,
        iova: u64,
        phys: u64,
        len: u64,
        perm: Perm,
        frames: &mut impl Frames,
    ) -> Result<(), Error> {
        domain.map(iova, phys, len, perm, &self.mem, frames)?;
        if self.regs.read64(reg::CAP) & reg::cap::CM != 0 {
            self.flush_range(domain, iova, len)?;
        }
        Ok(())
    }

    /// Flush `domain`'s cached translations of `[iova, iova + len)`: page by page where the unit
    /// has page-selective invalidation and the range is short, the whole domain otherwise.
    /// Without the queue, through the registers if translation is on, and nothing if it is off,
    /// when nothing can have been cached.
    fn flush_range(&mut self, domain: &Domain, iova: u64, len: u64) -> Result<(), Error> {
        if self.queue.is_none() {
            return if self.enabled() {
                self.invalidate_iotlb()
            } else {
                Ok(())
            };
        }
        let pages = len / PAGE_SIZE;
        let selective = self.regs.read64(reg::CAP) & reg::cap::PSI != 0;
        if selective && pages <= PAGE_FLUSH_LIMIT {
            let mut batch = [Invalidation::IotlbDomain { domain: 0 }; PAGE_FLUSH_LIMIT as usize];
            for (i, slot) in batch.iter_mut().take(pages as usize).enumerate() {
                *slot = Invalidation::IotlbPages {
                    domain: domain.id(),
                    iova: iova + i as u64 * PAGE_SIZE,
                    order: 0,
                };
            }
            self.invalidate(&batch[..pages as usize])
        } else {
            self.invalidate(&[Invalidation::IotlbDomain {
                domain: domain.id(),
            }])
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::harness::{MockFrames, MockMem, MockRegs};
    use crate::{Irte, reg};

    /// A unit with translation and the queue on, over `regs` built on its memory.
    fn queued(regs: impl FnOnce(&MockMem) -> MockRegs) -> (Unit<MockRegs, MockMem>, MockFrames) {
        let mem = MockMem::default();
        let mut pool = MockFrames::new(64);
        let mut unit = Unit::new(regs(&mem), mem, &mut pool).expect("bring-up");
        unit.enable().unwrap();
        unit.enable_queued_invalidation(&mut pool).unwrap();
        (unit, pool)
    }

    const PAGE: u64 = 0x4444_0000;

    #[test]
    fn the_queue_needs_the_capability_and_leaves_translation_on() {
        let mut pool = MockFrames::new(64);
        let mut plain = Unit::new(MockRegs::new(), MockMem::default(), &mut pool).unwrap();
        assert!(!plain.supports_queued_invalidation());
        assert_eq!(plain.enable_queued_invalidation(&mut pool), Err(Error::NoQueuedInvalidation));
        assert_eq!(
            plain.invalidate(&[Invalidation::InterruptGlobal]),
            Err(Error::NoQueuedInvalidation)
        );

        let (unit, _) = queued(MockRegs::with_queue);
        assert!(unit.queued_invalidation_enabled());
        assert!(unit.enabled(), "turning the queue on left translation on");
        assert_eq!(unit.regs_for_test().read64(reg::IQA) & 0xfff, 0, "one frame, 128-bit");
    }

    #[test]
    fn descriptors_are_laid_out_as_the_specification_says() {
        assert_eq!(Invalidation::ContextGlobal.encode(), (0x11, 0));
        assert_eq!(
            Invalidation::ContextDevice {
                domain: 7,
                source: 0x0018
            }
            .encode(),
            (0x31 | (7 << 16) | (0x18 << 32), 0)
        );
        assert_eq!(Invalidation::IotlbDomain { domain: 7 }.encode(), (0x22 | (7 << 16), 0));
        assert_eq!(
            Invalidation::IotlbPages {
                domain: 7,
                iova: 0x4444_5123,
                order: 3
            }
            .encode(),
            (0x32 | (7 << 16), 0x4444_5000 | 3)
        );
        assert_eq!(Invalidation::InterruptGlobal.encode(), (0x4, 0));
        assert_eq!(
            Invalidation::InterruptEntry { handle: 0x1234 }.encode(),
            (0x14 | (0x1234 << 32), 0)
        );
        assert_eq!(wait(0x9000, 0xabcd), (0x25 | (0xabcd << 32), 0x9000));
    }

    #[test]
    fn a_batch_ends_in_a_wait_the_hardware_completes() {
        let (mut unit, _) = queued(MockRegs::with_queue);
        unit.invalidate(&[
            Invalidation::IotlbDomain { domain: 1 },
            Invalidation::InterruptGlobal,
        ])
        .unwrap();
        let log = unit.regs_for_test().descriptors();
        assert_eq!(log.len(), 3);
        assert_eq!(log[2].0 & 0xf, TYPE_WAIT, "the batch ends in a wait");
        let regs = unit.regs_for_test();
        assert_eq!(regs.read64(reg::IQH), regs.read64(reg::IQT), "the queue drained");
        let stats = unit.queue_stats();
        assert_eq!((stats.invalidations, stats.waits), (2, 1));
    }

    #[test]
    fn an_unmap_in_use_flushes_the_translation_a_device_cached() {
        let (mut unit, mut pool) = queued(MockRegs::with_queue);
        let domain = unit.new_domain(1, &mut pool).unwrap();
        domain
            .map(PAGE, PAGE, PAGE_SIZE, Perm::ReadWrite, unit.mem(), &mut pool)
            .unwrap();
        assert_eq!(unit.regs_for_test().device_translate(&domain, PAGE), Some((PAGE, true)));

        // The tables alone: the leaf is gone, and the device still reaches the page through the
        // translation it cached. This is what a missing flush looks like.
        domain.unmap(PAGE, PAGE_SIZE, unit.mem()).unwrap();
        assert_eq!(domain.translate(PAGE, unit.mem()), None);
        assert_eq!(
            unit.regs_for_test().device_translate(&domain, PAGE),
            Some((PAGE, true)),
            "the model shows a stale translation"
        );

        // Unmapped in use: the flush follows the change, and the device faults.
        domain
            .map(PAGE, PAGE, PAGE_SIZE, Perm::ReadWrite, unit.mem(), &mut pool)
            .unwrap();
        unit.unmap_in_use(&domain, PAGE, PAGE_SIZE).unwrap();
        assert_eq!(unit.regs_for_test().device_translate(&domain, PAGE), None);
        assert!(
            unit.regs_for_test()
                .descriptors()
                .iter()
                .any(|&(low, high)| low & 0x3f == 0x32 && high & !0xfff == PAGE),
            "a page-selective flush named the page"
        );
    }

    #[test]
    fn a_range_too_long_for_page_flushes_flushes_the_domain() {
        let (mut unit, mut pool) = queued(MockRegs::with_queue);
        let domain = unit.new_domain(3, &mut pool).unwrap();
        let len = 64 * PAGE_SIZE;
        domain
            .map(PAGE, PAGE, len, Perm::ReadWrite, unit.mem(), &mut pool)
            .unwrap();
        let last = PAGE + len - PAGE_SIZE;
        assert!(
            unit.regs_for_test()
                .device_translate(&domain, PAGE)
                .is_some()
        );
        assert!(
            unit.regs_for_test()
                .device_translate(&domain, last)
                .is_some()
        );
        unit.unmap_in_use(&domain, PAGE, len).unwrap();
        assert_eq!(unit.regs_for_test().device_translate(&domain, PAGE), None);
        assert_eq!(unit.regs_for_test().device_translate(&domain, last), None);
        let log = unit.regs_for_test().descriptors();
        assert_eq!(log[log.len() - 2], (0x22 | (3 << 16), 0), "one domain-selective flush");
    }

    #[test]
    fn with_caching_mode_a_new_mapping_is_flushed_as_well() {
        let (mut unit, mut pool) = queued(MockRegs::with_caching_mode);
        let domain = unit.new_domain(1, &mut pool).unwrap();
        unit.map_in_use(&domain, PAGE, PAGE, PAGE_SIZE, Perm::ReadWrite, &mut pool)
            .unwrap();
        assert!(!unit.regs_for_test().descriptors().is_empty(), "caching mode flushes a map");

        let (mut unit, mut pool) = queued(MockRegs::with_queue);
        let domain = unit.new_domain(1, &mut pool).unwrap();
        unit.map_in_use(&domain, PAGE, PAGE, PAGE_SIZE, Perm::ReadWrite, &mut pool)
            .unwrap();
        assert!(unit.regs_for_test().descriptors().is_empty(), "nothing cached a hole");
    }

    fn disk_entry() -> Irte {
        Irte {
            vector: 48,
            destination: 1,
            level: false,
            source: 0x0018,
        }
    }

    #[test]
    fn changing_an_interrupt_entry_in_use_flushes_the_entry_cache() {
        let (mut unit, mut pool) = queued(MockRegs::with_queue);
        let table = unit.new_interrupt_table(&mut pool).unwrap();
        let entry = disk_entry();
        unit.set_irte(&table, 0, Some(entry)).unwrap();
        unit.enable_interrupt_remapping(&table).unwrap();
        assert_eq!(unit.regs_for_test().deliver(&table, 0), Some(entry));

        // Written behind the driver's back, the change is not seen: the hardware remaps by the
        // entry it cached. This is what a missing flush looks like.
        unit.mem().write64(table.phys(), 0);
        assert_eq!(
            unit.regs_for_test().deliver(&table, 0),
            Some(entry),
            "the model shows a stale entry"
        );

        // Changed through the driver, the next message is remapped by the new entry.
        let moved = Irte {
            destination: 2,
            ..entry
        };
        unit.set_irte(&table, 0, Some(moved)).unwrap();
        assert_eq!(unit.regs_for_test().deliver(&table, 0), Some(moved));
        unit.set_irte(&table, 0, None).unwrap();
        assert_eq!(unit.regs_for_test().deliver(&table, 0), None, "blocked once absent");
    }

    #[test]
    fn an_entry_in_use_is_not_changed_without_a_queue() {
        let mut pool = MockFrames::new(64);
        let mut unit = Unit::new(MockRegs::new(), MockMem::default(), &mut pool).unwrap();
        let table = unit.new_interrupt_table(&mut pool).unwrap();
        let entry = disk_entry();
        unit.set_irte(&table, 0, Some(entry)).unwrap();
        unit.enable_interrupt_remapping(&table).unwrap();
        assert_eq!(unit.set_irte(&table, 0, None), Err(Error::NoQueuedInvalidation));
        assert_eq!(unit.irte(&table, 0), Some(entry), "left as it was");
    }

    #[test]
    fn a_rejected_descriptor_is_an_error_and_a_stalled_queue_times_out() {
        let (mut unit, _) = queued(MockRegs::with_queue);
        unit.regs_for_test().reject_descriptor(TYPE_IEC);
        assert_eq!(
            unit.invalidate(&[Invalidation::InterruptGlobal]),
            Err(Error::InvalidationRejected)
        );
        let (mut unit, _) = queued(MockRegs::with_queue);
        unit.regs_for_test().stall_queue();
        assert_eq!(
            unit.invalidate(&[Invalidation::InterruptGlobal]),
            Err(Error::Timeout("queued invalidation"))
        );
    }

    #[test]
    fn the_queue_wraps_and_closes_the_register_interface() {
        let (mut unit, _) = queued(MockRegs::with_queue);
        for _ in 0..300 {
            unit.invalidate(&[Invalidation::InterruptGlobal]).unwrap();
        }
        assert_eq!(unit.queue_stats().waits, 300);
        assert!(unit.regs_for_test().read64(reg::IQT) >> 4 < QUEUE_ENTRIES);
        // Context invalidation goes through the queue now; the IOTLB register is refused.
        unit.invalidate_context().unwrap();
        let log = unit.regs_for_test().descriptors();
        assert_eq!(log[log.len() - 2], Invalidation::ContextGlobal.encode());
        assert_eq!(unit.invalidate_iotlb(), Err(Error::QueueIsOn));
    }
}

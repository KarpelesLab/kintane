//! Intel VT-d: an IOMMU that translates and confines device DMA.
//!
//! Without an IOMMU a device reads and writes physical memory by physical address, and a
//! driver that programs it wrong — or a driver in an unprivileged domain that programs it on
//! purpose — can reach any byte of RAM. VT-d puts a translation between the device and memory:
//! every device address a descriptor names is looked up in a per-device page table, and an
//! address with no mapping *faults* instead of reaching memory. That is what makes an isolated
//! driver's DMA containable (`docs/isolation.md`).
//!
//! # The structures, from the device inward
//!
//! A DMA from PCI `bus:dev.fn` (its source id, a SID) is translated by walking, in hardware:
//!
//! 1. the **root table** — 256 entries, one per bus, each pointing at that bus's context table;
//! 2. the **context table** — 256 entries per bus, one per dev.fn, each naming a *domain* and the
//!    root of its second-level page table;
//! 3. the **second-level page table** — an ordinary four-level page table (like the CPU's), whose
//!    leaves carry read and write permission bits.
//!
//! A [`Domain`] is one second-level page table. Several devices may share a domain by pointing
//! their context entries at the same table; the kernel gives each isolated device its own, so a
//! fault names exactly which device reached where it should not.
//!
//! # What is here, and where the `unsafe` is
//!
//! Changing an entry the hardware may have cached is followed by an invalidation, through the
//! registers until the invalidation queue ([`qi`]) is on and through the queue after.
//!
//! All of it is plain logic over three traits — [`Regs`] for the unit's registers, [`Frames`]
//! for the page-table frames, and [`PhysMem`] for the entries the hardware reads — so the whole
//! driver is host-tested against models of each. The `unsafe` that turns a physical address into
//! a real load or store lives in the kernel's implementations of those traits, not here.
//!
//! Reference: Intel Virtualization Technology for Directed I/O Architecture Specification,
//! rev 4.1; section numbers below refer to it.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

mod fault;
mod pagetable;
mod qi;
mod regs;
mod remap;

#[cfg(test)]
mod harness;

#[cfg(test)]
mod tests;

// The vocabulary a caller gets back is the kernel's, not this driver's: see `kernel/iommu`.
// Re-exported so that this crate's own surface still reads as a whole.
pub use iommu::{Fault, QueueStats};
pub use pagetable::{Domain, Perm};
pub use qi::{Invalidation, QUEUE_ENTRIES};
pub use regs::reg;
pub use remap::{IRT_ENTRIES, InterruptTable, Irte, message_handle, remappable_message};

/// The unit's memory-mapped registers, at offsets from its register base (VT-d §10.4).
///
/// Reads and writes are 32 or 64 bits. An implementation over real hardware makes these
/// volatile accesses to the mapped register page; the host tests make them accesses to an
/// array.
pub trait Regs {
    fn read32(&self, offset: usize) -> u32;
    fn read64(&self, offset: usize) -> u64;
    fn write32(&self, offset: usize, value: u32);
    fn write64(&self, offset: usize, value: u64);
}

/// Frames for the tables the hardware walks: the root table, the context tables, and the
/// second-level page tables.
///
/// Each is one 4 KiB page. The frame need not be zeroed; the driver zeroes it through
/// [`PhysMem`] before it links it, because a table the hardware reads before the driver has
/// written every entry must read "not present", not whatever the last owner left.
pub trait Frames {
    /// A free 4 KiB frame, by physical address, or `None` when none is left.
    fn alloc(&mut self) -> Option<u64>;
}

/// The physical memory the hardware's tables live in, as the CPU reaches it.
///
/// The tables are written by the CPU and read by the IOMMU, so the driver needs to store 64-bit
/// entries at physical addresses. The kernel implements this over its direct map; the host tests
/// over a flat array. Every access is a whole aligned `u64`.
pub trait PhysMem {
    fn read64(&self, phys: u64) -> u64;
    fn write64(&self, phys: u64, value: u64);
}

/// Bytes in a frame, and the shift of a page offset.
pub const PAGE_SIZE: u64 = 4096;
const PAGE_SHIFT: u64 = 12;

/// Why the IOMMU could not be brought up or programmed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Error {
    /// A hardware register did not report the state the enable sequence expects within the
    /// spin bound: the unit is not answering, or is not a VT-d unit at all.
    Timeout(&'static str),
    /// No frame was left for a table that had to be allocated.
    NoFrames,
    /// A map or unmap named an address or length that is not page-aligned.
    Misaligned,
    /// The hardware's address width is too small for the addresses being mapped.
    AddressWidth,
    /// A source id outside the 0..0x10000 a PCI segment holds.
    BadSource,
    /// The unit cannot remap interrupts (`ECAP.IR` clear).
    NoInterruptRemapping,
    /// An interrupt remapping table index past the table.
    BadHandle,
    /// A destination the table's interrupt mode cannot hold: an APIC ID above 255 without
    /// extended interrupt mode.
    Destination,
    /// A change the hardware may have cached needs flushing, and the unit has no invalidation
    /// queue turned on to flush it with (`ECAP.QI` clear, or never enabled).
    NoQueuedInvalidation,
    /// The hardware rejected a descriptor in the invalidation queue (`FSTS.IQE`).
    InvalidationRejected,
    /// A register-interface invalidation after the queue was turned on, which the
    /// specification forbids (§6.5.2).
    QueueIsOn,
}

/// Reads before a register bit is called stuck. Under QEMU each of these completes at once;
/// the bound is far above that and finite, so a unit that never answers is an error rather
/// than a hang.
const SPIN_LIMIT: u32 = 1_000_000;

/// One DMA remapping hardware unit: its registers, its root table, and the domains whose
/// context entries it holds.
///
/// The kernel builds one per DRHD the DMAR lists (`boot/acpi::dmar`). It owns the frame source
/// and the physical-memory accessor for the unit's life, because the tables it builds are read
/// by the hardware for as long as translation is on.
pub struct Unit<R: Regs, M: PhysMem> {
    regs: R,
    mem: M,
    /// The root table's physical address, once built.
    root: u64,
    /// The address width the hardware reports it can translate, in bits (VT-d §10.4.2).
    max_address_width: u8,
    /// The guest address width chosen for the page tables: 48 bits, four levels, which QEMU
    /// supports and every domain here uses.
    levels: u8,
    /// The invalidation queue, once [`Unit::enable_queued_invalidation`] has turned it on.
    queue: Option<qi::Queue>,
    /// What the queue has completed.
    queue_stats: QueueStats,
}

/// The address width and level count this driver programs: 48-bit, four-level tables. The
/// context entry's AW field encodes it as 2 (VT-d §9.3, Table 9-3).
const AGAW_48: u8 = 2;
const LEVELS_48: u8 = 4;

impl<R: Regs, M: PhysMem> Unit<R, M> {
    /// Read the unit's capabilities and build an empty root table. Translation is *not* yet on;
    /// call [`Unit::enable`] after the domains devices need are attached.
    pub fn new(regs: R, mem: M, frames: &mut impl Frames) -> Result<Unit<R, M>, Error> {
        let cap = regs.read64(reg::CAP);
        // CAP.MGAW field, bits [21:16], is the maximum guest address width minus one.
        let max_address_width = (((cap >> 16) & 0x3f) as u8) + 1;
        if max_address_width < 48 {
            // Every domain here uses 48-bit tables; a unit that cannot translate that many
            // bits is one this driver does not know how to program.
            return Err(Error::AddressWidth);
        }
        let root = frames.alloc().ok_or(Error::NoFrames)?;
        zero_frame(&mem, root);
        Ok(Unit {
            regs,
            mem,
            root,
            max_address_width,
            levels: LEVELS_48,
            queue: None,
            queue_stats: QueueStats::default(),
        })
    }

    /// The widest device address the hardware will translate, in bits.
    pub fn max_address_width(&self) -> u8 {
        self.max_address_width
    }

    /// A fresh, empty translation domain: a second-level page table with nothing mapped, so
    /// every device address faults until something is granted into it.
    pub fn new_domain(&mut self, id: u16, frames: &mut impl Frames) -> Result<Domain, Error> {
        Domain::new(id, self.levels, &self.mem, frames)
    }

    /// Point device `source` (its PCI source id, `bus << 8 | dev << 3 | fn`) at `domain`, so
    /// the hardware translates that device's DMA through the domain's page table.
    ///
    /// Allocates the bus's context table the first time a device on that bus is attached.
    pub fn attach(
        &mut self,
        source: u16,
        domain: &Domain,
        frames: &mut impl Frames,
    ) -> Result<(), Error> {
        let bus = (source >> 8) as u64;
        let devfn = (source & 0xff) as u64;

        // The root entry for the bus: present bit 0, context-table pointer in bits [51:12].
        let root_entry = self.root + bus * 16;
        let low = self.mem.read64(root_entry);
        let context = if low & 1 != 0 {
            low & ADDR_MASK
        } else {
            let frame = frames.alloc().ok_or(Error::NoFrames)?;
            zero_frame(&self.mem, frame);
            self.mem.write64(root_entry, frame | 1);
            self.mem.write64(root_entry + 8, 0);
            frame
        };

        // The context entry for the device: 16 bytes. Low qword: present bit 0, translation
        // type bits [3:2] = 0 (translate through the second level), SLPTPTR in bits [51:12].
        // High qword: AW in bits [2:0], domain id in bits [23:8].
        let entry = context + devfn * 16;
        self.mem.write64(entry, (domain.root() & ADDR_MASK) | 1);
        self.mem
            .write64(entry + 8, u64::from(AGAW_48) | (u64::from(domain.id()) << 8));
        // Attached while translation is on, the device may have a cached context entry, and its
        // new domain may have cached translations from before: flush both.
        if self.enabled() {
            if self.queue.is_some() {
                self.invalidate(&[
                    Invalidation::ContextDevice {
                        domain: domain.id(),
                        source,
                    },
                    Invalidation::IotlbDomain {
                        domain: domain.id(),
                    },
                ])?;
            } else {
                self.invalidate_context()?;
                self.invalidate_iotlb()?;
            }
        }
        Ok(())
    }

    /// Turn translation on: set the root table, invalidate the caches that were empty before
    /// it, and set the translation-enable bit.
    ///
    /// After this every DMA from an attached device is translated, and a DMA from a device with
    /// no context entry, or to an address its domain does not map, faults (VT-d §7).
    pub fn enable(&mut self) -> Result<(), Error> {
        // Set the root-table address, then command the hardware to latch it (SRTP), and wait
        // for it to report it did (RTPS).
        self.regs.write64(reg::RTADDR, self.root);
        self.command(reg::gcmd::SRTP, reg::gsts::RTPS, "set root table pointer")?;

        // The caches were built while translation was off, so they hold nothing; invalidate
        // them anyway, because the spec requires it before enabling and a real unit may hold
        // stale entries from firmware (VT-d §6.5).
        self.invalidate_context()?;
        self.invalidate_iotlb()?;

        self.command(reg::gcmd::TE, reg::gsts::TES, "enable translation")
    }

    /// Turn translation off again, so devices reach memory directly. For a clean shutdown, and
    /// for the falsification that a device blocked with the IOMMU on is *not* blocked with it
    /// off.
    pub fn disable(&mut self) -> Result<(), Error> {
        self.clear_command(reg::gcmd::TE, reg::gsts::TES, "disable translation")
    }

    /// Whether translation is on, read from the hardware.
    pub fn enabled(&self) -> bool {
        self.regs.read32(reg::GSTS) & reg::gsts::TES != 0
    }

    /// Invalidate the context cache globally (VT-d §10.4.7): the hardware may have cached a
    /// device's old context entry, and a newly attached or detached device would otherwise be
    /// translated by a stale one.
    pub fn invalidate_context(&mut self) -> Result<(), Error> {
        // Once the queue is on, the register interface is closed and the queue does it.
        if self.queue.is_some() {
            return self.invalidate(&[Invalidation::ContextGlobal]);
        }
        // CCMD: bit 63 ICC (invalidate context cache), bits [62:61] = 01 global.
        let ccmd = (1u64 << 63) | (0b01 << 61);
        self.regs.write64(reg::CCMD, ccmd);
        self.wait_clear64(reg::CCMD, 1 << 63, "context cache invalidation")
    }

    /// Invalidate the IOTLB globally (VT-d §10.4.8.1): the hardware caches address
    /// translations, so a mapping just changed must be flushed before it is trusted to fault
    /// or to reach its new page.
    ///
    /// Refused once the queue is on: flush by domain or by page through the queue instead.
    pub fn invalidate_iotlb(&mut self) -> Result<(), Error> {
        if self.queue.is_some() {
            return Err(Error::QueueIsOn);
        }
        let iotlb = self.iotlb_reg();
        // IOTLB register: bit 63 IVT (invalidate), bits [61:60] = 01 global.
        let cmd = (1u64 << 63) | (0b01 << 60);
        self.regs.write64(iotlb, cmd);
        self.wait_clear64(iotlb, 1 << 63, "IOTLB invalidation")
    }

    /// The IOTLB command register's offset: ECAP.IRO (bits [17:8], in 16-byte units) names the
    /// register block, and the command register is eight bytes into it (VT-d §10.4.8.1).
    fn iotlb_reg(&self) -> usize {
        let ecap = self.regs.read64(reg::ECAP);
        let iro = ((ecap >> 8) & 0x3ff) as usize * 16;
        iro + 8
    }

    /// Set the bits `set` in GCMD and wait for `expect` to appear in GSTS.
    ///
    /// GCMD is write-only and its bits are one-shot commands; the current enabled state is read
    /// back from GSTS, so a command is issued by writing the whole intended GSTS-shaped value,
    /// not by a read-modify-write of GCMD (VT-d §10.4.4).
    fn command(&mut self, set: u32, expect: u32, what: &'static str) -> Result<(), Error> {
        let current = self.regs.read32(reg::GSTS) & GSTS_STICKY;
        self.regs.write32(reg::GCMD, current | set);
        self.wait_set32(reg::GSTS, expect, what)
    }

    fn clear_command(&mut self, clear: u32, expect: u32, what: &'static str) -> Result<(), Error> {
        let current = self.regs.read32(reg::GSTS) & GSTS_STICKY;
        self.regs.write32(reg::GCMD, current & !clear);
        self.wait_clear32(reg::GSTS, expect, what)
    }

    fn wait_set32(&self, offset: usize, bits: u32, what: &'static str) -> Result<(), Error> {
        for _ in 0..SPIN_LIMIT {
            if self.regs.read32(offset) & bits == bits {
                return Ok(());
            }
        }
        Err(Error::Timeout(what))
    }

    fn wait_clear32(&self, offset: usize, bits: u32, what: &'static str) -> Result<(), Error> {
        for _ in 0..SPIN_LIMIT {
            if self.regs.read32(offset) & bits == 0 {
                return Ok(());
            }
        }
        Err(Error::Timeout(what))
    }

    fn wait_clear64(&self, offset: usize, bits: u64, what: &'static str) -> Result<(), Error> {
        for _ in 0..SPIN_LIMIT {
            if self.regs.read64(offset) & bits == 0 {
                return Ok(());
            }
        }
        Err(Error::Timeout(what))
    }

    /// The next unhandled fault the hardware recorded, cleared as it is read, or `None` when
    /// the fault log is empty. See [`fault`].
    pub fn take_fault(&mut self) -> Option<Fault> {
        fault::take(&self.regs)
    }

    /// The physical-memory accessor, so a host can read back what a domain mapped for a check.
    pub fn mem(&self) -> &M {
        &self.mem
    }
}

/// The bits of a page-table or table pointer entry that hold a physical address: [51:12].
const ADDR_MASK: u64 = 0x000f_ffff_ffff_f000;

/// GSTS bits that reflect state a command must preserve when it issues the next one: every
/// "…enable status" bit. Re-writing GCMD without them would turn those features back off.
const GSTS_STICKY: u32 = reg::gsts::TES | reg::gsts::RTPS | reg::gsts::IRES | reg::gsts::QIES;

/// Zero a freshly allocated table frame through the physical-memory accessor. Every table here
/// fills one frame — 512 eight-byte entries, or 256 sixteen-byte ones for the root and context
/// tables — so that is 512 words, and not a byte past them, which belong to whoever the allocator
/// gave the next frame.
fn zero_frame(mem: &impl PhysMem, phys: u64) {
    for i in 0..PAGE_SIZE / 8 {
        mem.write64(phys + i * 8, 0);
    }
}

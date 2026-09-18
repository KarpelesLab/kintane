//! What an IOMMU reports, independent of whose IOMMU it is.
//!
//! Two facts the kernel needs from any unit that confines device DMA: a [`Fault`] it recorded,
//! and what its invalidation queue has completed ([`QueueStats`]). Neither names a vendor's
//! registers — a driver decodes its own hardware and builds these — so the kernel can name this
//! unit whether it builds a driver or none at all.
//!
//! That last part is the reason this exists. `kernel/main/src/iommu.rs` and its `_off` twin are
//! chosen by `#[cfg]`, and the twin is what a build *without* an IOMMU compiles; while these
//! types lived in `drivers/iommu/vtd`, that twin returned them, and a configuration with no
//! IOMMU at all still named one vendor's crate in its public surface.
//!
//! The split follows the block layer's: the vocabulary is here, the hardware is under
//! `drivers/iommu/`. See `docs/isolation.md`.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

/// One fault a unit recorded: a DMA its tables did not allow, or an interrupt its remapping
/// table did not.
///
/// These are the decoded facts, not a register's bits. Which fault-recording register or event
/// queue they came out of, and how the hardware packed them, is the driver's business and stays
/// there — so nothing here changes when the machine's IOMMU is a different make.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Fault {
    /// The device address the access named.
    pub address: u64,
    /// The faulting device's source id, as its bus numbers it (`bus << 8 | dev << 3 | fn` on PCI).
    pub source_id: u16,
    /// The unit's own reason code, as the hardware gave it.
    ///
    /// Reported, never interpreted: the numbering belongs to the driver, so nothing here — and
    /// nothing above here — can say what a particular value means. A caller prints it.
    pub reason: u8,
    /// Whether the access was a write.
    pub write: bool,
    /// For a blocked interrupt, the remapping-table index the message named; `None` when the
    /// fault was a DMA rather than an interrupt.
    ///
    /// Which reason codes mean "interrupt" is the driver's to know, so the driver decides this
    /// rather than leaving a caller to compare against a vendor's table.
    pub interrupt_index: Option<u16>,
}

/// What a unit's invalidation queue has completed since it was turned on.
///
/// The queue belongs to the hardware unit rather than to any one device, so these count every
/// device behind it.
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct QueueStats {
    /// Invalidation descriptors the hardware completed, waits not counted.
    pub invalidations: u64,
    /// Batches submitted and seen complete: one wait each.
    pub waits: u64,
    /// The most status reads one wait needed before it saw its cookie.
    pub longest_wait: u32,
}

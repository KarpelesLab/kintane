//! Resources a driver owns: memory-mapped register windows and interrupt lines.
//!
//! A driver never takes an address out of the tree and starts writing to it. It asks
//! the [`Resources`] ledger for a claim, through the [`crate::Probe`] token it was
//! handed, and gets back a handle that is not `Copy` or `Clone`. The ledger refuses a
//! claim that overlaps one already granted, so two drivers bound to nodes that describe
//! the same registers — a real mistake in real trees — produce an error naming the
//! holder, instead of two drivers programming one device.
//!
//! The ledger is also what the kernel address space is built from. Every window a
//! bound driver claimed is mapped and nothing else is, so "which device memory does the
//! kernel map" has one answer and it comes from the drivers that will use it.
//!
//! # Owners
//!
//! Every claim is tagged with the probe that made it, not only with the node. A failed
//! probe releases exactly its own claims, and removing a device releases exactly the
//! claims its binding made — so probing a node that is already bound, which fails on its
//! own window, cannot take the existing binding's resources down with it.

use crate::tree::{NodeId, Specifier};

/// One probe's identity in the ledger: the binding a claim belongs to.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Owner(u32);

/// An exclusive claim on a window of device memory.
///
/// Holding one means the ledger has recorded `[phys, phys + len)` as this driver's and
/// no other claim overlaps it. It does not mean the window is mapped; turning a claim
/// into accessible registers is [`crate::Registers::new`], which is where that promise
/// is made.
#[derive(Debug, PartialEq, Eq)]
pub struct Mmio {
    phys: u64,
    len: u64,
    owner: Owner,
    slot: usize,
}

impl Mmio {
    pub fn phys(&self) -> u64 {
        self.phys
    }

    pub fn len(&self) -> u64 {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

/// A claim on one interrupt, as its controller describes it.
///
/// The model cannot turn the specifier into a line number — only the controller's driver
/// knows what the cells mean — so the handle carries the specifier, and the controller
/// translates it when the line is wired up.
#[derive(Debug, PartialEq, Eq)]
pub struct IrqLine {
    spec: Specifier,
    owner: Owner,
    slot: usize,
}

impl IrqLine {
    pub fn specifier(&self) -> &Specifier {
        &self.spec
    }

    pub(crate) fn owner(&self) -> Owner {
        self.owner
    }
}

/// An exclusive claim on a range of I/O ports.
///
/// The PC's second address space, and the same promise as [`Mmio`]: the ledger has
/// recorded `[base, base + len)` as this driver's. [`crate::Ports`] turns it into
/// accesses. Nothing maps it — the port space is addressed by the instruction — so
/// unlike a window it never reaches the kernel's address space.
#[derive(Debug, PartialEq, Eq)]
pub struct PortRange {
    base: u16,
    len: u16,
    owner: Owner,
    slot: usize,
}

impl PortRange {
    pub fn base(&self) -> u16 {
        self.base
    }

    pub fn len(&self) -> u16 {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

/// One granted window, as the ledger records it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct MmioClaim {
    pub phys: u64,
    pub len: u64,
    /// The node whose `reg` it came from.
    pub node: NodeId,
    /// What the driver says lives there, for the address-space report.
    pub what: &'static str,
    owner: Owner,
}

/// One granted interrupt.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct IrqClaim {
    pub spec: Specifier,
    pub node: NodeId,
    owner: Owner,
}

/// One granted range of I/O ports.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PortClaim {
    pub base: u16,
    pub len: u16,
    /// The node whose ports they are.
    pub node: NodeId,
    /// What the driver says answers there, for diagnostics.
    pub what: &'static str,
    owner: Owner,
}

/// Why a claim was refused.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ClaimError {
    /// The window overlaps one already granted to a driver bound to `holder`.
    Overlaps { holder: NodeId, phys: u64, len: u64 },
    /// The interrupt is already claimed by a driver bound to `holder`. Shared lines arrive
    /// with a driver that needs one; until then a second claim is a mistake.
    IrqTaken { holder: NodeId },
    /// The ledger is full.
    NoRoom,
    /// A zero-length window claims nothing and is refused rather than silently granted.
    Empty,
}

/// The ledger of every resource granted.
///
/// Storage comes from the caller, like the tree's, because it is needed before any
/// allocator exists. Released slots are reused.
pub struct Resources<'s> {
    mmio: &'s mut [Option<MmioClaim>],
    irqs: &'s mut [Option<IrqClaim>],
    /// `None` on a machine with no port space, where nothing describes ports and so
    /// nothing can claim one.
    ports: Option<&'s mut [Option<PortClaim>]>,
    next_owner: u32,
}

impl<'s> Resources<'s> {
    pub fn new(mmio: &'s mut [Option<MmioClaim>], irqs: &'s mut [Option<IrqClaim>]) -> Self {
        for s in mmio.iter_mut() {
            *s = None;
        }
        for s in irqs.iter_mut() {
            *s = None;
        }
        Resources {
            mmio,
            irqs,
            ports: None,
            next_owner: 0,
        }
    }

    /// Let drivers claim I/O ports as well, out of `ports`.
    ///
    /// Separate from [`Self::new`] because only the PC has a port space: a platform that
    /// does not pass storage refuses every port claim, which is the right answer on a
    /// machine whose devices have no ports to claim.
    pub fn with_ports(mut self, ports: &'s mut [Option<PortClaim>]) -> Self {
        for s in ports.iter_mut() {
            *s = None;
        }
        self.ports = Some(ports);
        self
    }

    /// Every window currently granted.
    pub fn mmio_claims(&self) -> impl Iterator<Item = &MmioClaim> + '_ {
        self.mmio.iter().flatten()
    }

    /// Every interrupt currently granted.
    pub fn irq_claims(&self) -> impl Iterator<Item = &IrqClaim> + '_ {
        self.irqs.iter().flatten()
    }

    /// Every port range currently granted.
    pub fn port_claims(&self) -> impl Iterator<Item = &PortClaim> + '_ {
        self.ports.iter().flat_map(|p| p.iter().flatten())
    }

    /// A fresh owner for a probe about to run.
    ///
    /// Wraps after four billion probes, which is four billion more than a boot performs;
    /// hot-plug will need to say what reuse means before it gets anywhere near that.
    pub(crate) fn begin(&mut self) -> Owner {
        let owner = Owner(self.next_owner);
        self.next_owner = self.next_owner.wrapping_add(1);
        owner
    }

    pub(crate) fn claim_mmio(
        &mut self,
        owner: Owner,
        node: NodeId,
        phys: u64,
        len: u64,
        what: &'static str,
    ) -> Result<Mmio, ClaimError> {
        if len == 0 {
            return Err(ClaimError::Empty);
        }
        // Inclusive ends, so a window reaching the top of the address space is
        // expressible; the tree has already refused ones whose end overflows.
        let last = phys.saturating_add(len - 1);
        if let Some(held) = self.mmio_claims().find(|h| {
            let held_last = h.phys.saturating_add(h.len.saturating_sub(1));
            phys <= held_last && h.phys <= last
        }) {
            return Err(ClaimError::Overlaps {
                holder: held.node,
                phys: held.phys,
                len: held.len,
            });
        }
        let slot = self
            .mmio
            .iter()
            .position(Option::is_none)
            .ok_or(ClaimError::NoRoom)?;
        if let Some(s) = self.mmio.get_mut(slot) {
            *s = Some(MmioClaim {
                phys,
                len,
                node,
                what,
                owner,
            });
        }
        Ok(Mmio {
            phys,
            len,
            owner,
            slot,
        })
    }

    pub(crate) fn claim_irq(
        &mut self,
        owner: Owner,
        node: NodeId,
        spec: Specifier,
    ) -> Result<IrqLine, ClaimError> {
        if let Some(held) = self.irq_claims().find(|h| h.spec == spec) {
            return Err(ClaimError::IrqTaken { holder: held.node });
        }
        let slot = self
            .irqs
            .iter()
            .position(Option::is_none)
            .ok_or(ClaimError::NoRoom)?;
        if let Some(s) = self.irqs.get_mut(slot) {
            *s = Some(IrqClaim { spec, node, owner });
        }
        Ok(IrqLine { spec, owner, slot })
    }

    pub(crate) fn claim_ports(
        &mut self,
        owner: Owner,
        node: NodeId,
        base: u16,
        len: u16,
        what: &'static str,
    ) -> Result<PortRange, ClaimError> {
        if len == 0 {
            return Err(ClaimError::Empty);
        }
        let last = base.checked_add(len - 1).ok_or(ClaimError::Empty)?;
        if let Some(held) = self.port_claims().find(|h| {
            let held_last = h.base.saturating_add(h.len.saturating_sub(1));
            base <= held_last && h.base <= last
        }) {
            return Err(ClaimError::Overlaps {
                holder: held.node,
                phys: u64::from(held.base),
                len: u64::from(held.len),
            });
        }
        let ports = self.ports.as_deref_mut().ok_or(ClaimError::NoRoom)?;
        let slot = ports
            .iter()
            .position(Option::is_none)
            .ok_or(ClaimError::NoRoom)?;
        if let Some(s) = ports.get_mut(slot) {
            *s = Some(PortClaim {
                base,
                len,
                node,
                what,
                owner,
            });
        }
        Ok(PortRange {
            base,
            len,
            owner,
            slot,
        })
    }

    /// Give a port range back, on the same terms as [`Self::release_mmio`].
    pub fn release_ports(&mut self, range: PortRange) {
        if let Some(s) = self
            .ports
            .as_deref_mut()
            .and_then(|p| p.get_mut(range.slot))
        {
            if s.is_some_and(|c| c.owner == range.owner && c.base == range.base) {
                *s = None;
            }
        }
    }

    /// Give a window back. Consumes the handle, so it cannot be used afterwards.
    ///
    /// The slot is cleared only if it still holds this claim: a probe that failed has had
    /// its claims released already, and a handle it leaked must not free whatever claim
    /// has reused the slot since.
    pub fn release_mmio(&mut self, mmio: Mmio) {
        if let Some(s) = self.mmio.get_mut(mmio.slot) {
            if s.is_some_and(|c| c.owner == mmio.owner && c.phys == mmio.phys) {
                *s = None;
            }
        }
    }

    /// Give an interrupt back, on the same terms as [`Self::release_mmio`].
    pub fn release_irq(&mut self, line: IrqLine) {
        if let Some(s) = self.irqs.get_mut(line.slot) {
            if s.is_some_and(|c| c.owner == line.owner && c.spec == line.spec) {
                *s = None;
            }
        }
    }

    /// Release every claim `owner` made.
    pub(crate) fn release_owner(&mut self, owner: Owner) {
        for s in self.mmio.iter_mut() {
            if s.is_some_and(|c| c.owner == owner) {
                *s = None;
            }
        }
        for s in self.irqs.iter_mut() {
            if s.is_some_and(|c| c.owner == owner) {
                *s = None;
            }
        }
        for s in self.ports.iter_mut().flat_map(|p| p.iter_mut()) {
            if s.is_some_and(|c| c.owner == owner) {
                *s = None;
            }
        }
    }
}

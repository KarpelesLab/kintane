//! Drivers, binding, and the phases a bound device moves through.
//!
//! # Phases as types
//!
//! A device's life is a sequence, and doing a step early is a class of bug that tends
//! to work on the machine it was written on: register an interrupt handler before the
//! registers are claimed and it runs against a device another driver still owns; enable
//! the line before the hardware is initialised and the first interrupt arrives into
//! half-programmed state. Each phase is therefore a token that only the previous step
//! can produce, and the operations of a phase take its token:
//!
//! ```text
//!  probe ──► Bound ──start──► Started ──suspend──► Suspended
//!    │         ▲                │  ▲                   │
//!    │         └──────stop──────┘  └───────resume──────┘
//!    │         │
//!    │       remove ──► claims released
//!  claims made through Probe; released again if probe fails
//! ```
//!
//! - Resources are claimed only through [`Probe`], which exists only during probe.
//! - [`Bound`] is produced only by a probe that succeeded, and is what registering an interrupt
//!   handler requires ([`Handlers::register`]).
//! - [`Started`] is produced only by a successful start, and is what enabling a line requires
//!   ([`Handlers::enable`]).
//!
//! None of the tokens is `Clone` or `Copy`, and their fields are private, so the only
//! way to hold one is to have gone through the step that makes it.
//!
//! Power management and removal are in the interface now, while there is one driver
//! that implements them trivially, because adding them to a driver model that forgot
//! them is the retrofit every kernel regrets.

use hal::IrqNumber;

use crate::resource::{ClaimError, IrqLine, Mmio, Owner, Resources};
use crate::tree::{self, DeviceTree, NodeId};

/// A driver, bound by `compatible` string.
pub trait Driver: Sync {
    fn name(&self) -> &'static str;

    /// The `compatible` strings this driver takes, in no particular order: which one wins
    /// is decided by the node's own list, most specific first.
    fn compatible(&self) -> &'static [&'static str];

    /// Claim what the device needs. Must not touch the hardware: nothing is mapped on
    /// the driver's behalf until every probe has run.
    ///
    /// On error, every claim this probe made is released.
    fn probe(&self, probe: &mut Probe<'_, '_, '_, '_>) -> Result<(), ProbeError>;

    /// Bring the hardware up. Its resources are claimed and mapped.
    ///
    /// Called during boot, on one CPU, with interrupts masked at the CPU. A driver may
    /// rely on that — an interrupt controller's initialisation needs it — until hot-plug
    /// arrives and has to say what replaces it.
    fn start(&self, bound: &Bound) -> Result<(), &'static str>;

    /// Quiesce the hardware so it can be started again. Trivial for a device with no
    /// state worth stopping.
    fn stop(&self, _started: &Started) {}

    /// Save state and let the device lose power.
    fn suspend(&self, _started: &Started) -> Result<(), &'static str> {
        Ok(())
    }

    /// Restore what `suspend` saved.
    fn resume(&self, _suspended: &Suspended) -> Result<(), &'static str> {
        Ok(())
    }

    /// Forget the device. Its claims are released by [`remove`] after this returns.
    fn remove(&self, _bound: &Bound) {}
}

/// Why a probe failed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ProbeError {
    /// The node could not be read.
    Tree(tree::Error),
    /// A resource could not be claimed.
    Claim(ClaimError),
    /// The driver declined, for the stated reason.
    Declined(&'static str),
}

impl From<tree::Error> for ProbeError {
    fn from(e: tree::Error) -> Self {
        ProbeError::Tree(e)
    }
}

impl From<ClaimError> for ProbeError {
    fn from(e: ClaimError) -> Self {
        ProbeError::Claim(e)
    }
}

/// The probe phase: the node, read-only, and the right to claim its resources.
pub struct Probe<'p, 'a, 's, 'r> {
    tree: &'p DeviceTree<'a, 's>,
    node: NodeId,
    owner: Owner,
    resources: &'p mut Resources<'r>,
}

impl<'a, 's> Probe<'_, 'a, 's, '_> {
    pub fn tree(&self) -> &DeviceTree<'a, 's> {
        self.tree
    }

    pub fn node(&self) -> NodeId {
        self.node
    }

    /// Claim the `index`th `reg` window of the node.
    pub fn claim_mmio(&mut self, index: usize, what: &'static str) -> Result<Mmio, ProbeError> {
        let (phys, len) = self.tree.mmio(self.node, index)?;
        Ok(self
            .resources
            .claim_mmio(self.owner, self.node, phys, len, what)?)
    }

    /// Claim the `index`th interrupt of the node.
    pub fn claim_irq(&mut self, index: usize) -> Result<IrqLine, ProbeError> {
        let spec = self.tree.interrupt(self.node, index)?;
        Ok(self.resources.claim_irq(self.owner, self.node, spec)?)
    }
}

/// A device whose driver probed successfully: its resources are claimed.
#[derive(Debug, PartialEq, Eq)]
pub struct Bound {
    node: NodeId,
    owner: Owner,
    driver: &'static str,
}

impl Bound {
    pub fn node(&self) -> NodeId {
        self.node
    }

    pub fn driver(&self) -> &'static str {
        self.driver
    }
}

/// A started device: its hardware is up.
#[derive(Debug, PartialEq, Eq)]
pub struct Started(Bound);

impl Started {
    pub fn bound(&self) -> &Bound {
        &self.0
    }
}

/// A suspended device.
#[derive(Debug, PartialEq, Eq)]
pub struct Suspended(Bound);

impl Suspended {
    pub fn bound(&self) -> &Bound {
        &self.0
    }
}

/// Run `driver`'s probe against `node`.
///
/// # Errors
/// Whatever the probe reported. Every claim it made is released first, so a driver that
/// claimed two windows and failed on the third does not keep the first two — and only
/// those: claims an earlier binding of the same node holds are not this probe's.
pub fn probe(
    driver: &dyn Driver,
    tree: &DeviceTree<'_, '_>,
    node: NodeId,
    resources: &mut Resources<'_>,
) -> Result<Bound, ProbeError> {
    let owner = resources.begin();
    let mut p = Probe {
        tree,
        node,
        owner,
        resources,
    };
    match driver.probe(&mut p) {
        Ok(()) => Ok(Bound {
            node,
            owner,
            driver: driver.name(),
        }),
        Err(e) => {
            resources.release_owner(owner);
            Err(e)
        }
    }
}

/// Start a bound device. On failure the device is still bound and the token comes back.
pub fn start(driver: &dyn Driver, bound: Bound) -> Result<Started, (Bound, &'static str)> {
    match driver.start(&bound) {
        Ok(()) => Ok(Started(bound)),
        Err(e) => Err((bound, e)),
    }
}

/// Stop a started device.
pub fn stop(driver: &dyn Driver, started: Started) -> Bound {
    driver.stop(&started);
    started.0
}

/// Suspend a started device. On failure it is still started.
pub fn suspend(
    driver: &dyn Driver,
    started: Started,
) -> Result<Suspended, (Started, &'static str)> {
    match driver.suspend(&started) {
        Ok(()) => Ok(Suspended(started.0)),
        Err(e) => Err((started, e)),
    }
}

/// Resume a suspended device. On failure it is still suspended.
pub fn resume(
    driver: &dyn Driver,
    suspended: Suspended,
) -> Result<Started, (Suspended, &'static str)> {
    match driver.resume(&suspended) {
        Ok(()) => Ok(Started(suspended.0)),
        Err(e) => Err((suspended, e)),
    }
}

/// Remove a bound device and release everything it claimed. A started device must be
/// stopped first, which the type makes the caller do.
pub fn remove(driver: &dyn Driver, bound: Bound, resources: &mut Resources<'_>) {
    driver.remove(&bound);
    resources.release_owner(bound.owner);
}

/// Which driver takes `node`, and at which of the node's `compatible` entries.
///
/// The node's list is walked in order, so the most specific string any driver knows
/// wins; among drivers that list the same string, the first in `drivers` does. A node
/// whose `status` says it is not available matches nothing.
pub fn best_match(
    tree: &DeviceTree<'_, '_>,
    node: NodeId,
    drivers: &[&dyn Driver],
) -> Option<(usize, usize)> {
    let n = tree.node(node);
    if !n.is_available() {
        return None;
    }
    n.compatible().enumerate().find_map(|(position, compat)| {
        drivers
            .iter()
            .position(|d| d.compatible().iter().any(|c| c.as_bytes() == compat))
            .map(|driver| (driver, position))
    })
}

/// An interrupt handler table, keyed by the line numbers a controller translated.
///
/// Registering takes the [`Bound`] token of the device that claimed the line, and the
/// [`IrqLine`] itself, so a handler cannot be installed for a line nobody claimed or by
/// a device that does not hold it. Enabling takes [`Started`]. Dispatch calls only
/// enabled handlers.
///
/// Nothing dispatches through this yet: the architectures' interrupt paths still know
/// only their timer, and move over when the first interrupt-driven driver arrives.
pub struct Handlers<'h> {
    slots: &'h mut [Option<Handler>],
}

/// One registered handler.
#[derive(Clone, Copy, Debug)]
pub struct Handler {
    number: IrqNumber,
    owner: Owner,
    handler: fn(),
    enabled: bool,
}

/// Why a handler could not be registered or enabled.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum HandlerError {
    /// The line belongs to a different device from the token presented.
    NotOwner,
    /// A handler is already registered for this number.
    Busy,
    /// No handler is registered for this number and device.
    NotRegistered,
    NoRoom,
}

impl<'h> Handlers<'h> {
    pub fn new(slots: &'h mut [Option<Handler>]) -> Self {
        for s in slots.iter_mut() {
            *s = None;
        }
        Handlers { slots }
    }

    /// Register `handler` for `line`, which the controller translated to `number`.
    pub fn register(
        &mut self,
        owner: &Bound,
        line: &IrqLine,
        number: IrqNumber,
        handler: fn(),
    ) -> Result<(), HandlerError> {
        if line.owner() != owner.owner {
            return Err(HandlerError::NotOwner);
        }
        if self.slots.iter().flatten().any(|h| h.number == number) {
            return Err(HandlerError::Busy);
        }
        let slot = self
            .slots
            .iter_mut()
            .find(|s| s.is_none())
            .ok_or(HandlerError::NoRoom)?;
        *slot = Some(Handler {
            number,
            owner: owner.owner,
            handler,
            enabled: false,
        });
        Ok(())
    }

    /// Let `number`'s handler run. Only a started device may.
    pub fn enable(&mut self, started: &Started, number: IrqNumber) -> Result<(), HandlerError> {
        let h = self
            .slots
            .iter_mut()
            .flatten()
            .find(|h| h.number == number && h.owner == started.0.owner)
            .ok_or(HandlerError::NotRegistered)?;
        h.enabled = true;
        Ok(())
    }

    /// Run the handler for `number`, if one is registered and enabled. Returns whether
    /// one ran.
    pub fn dispatch(&self, number: IrqNumber) -> bool {
        match self
            .slots
            .iter()
            .flatten()
            .find(|h| h.number == number && h.enabled)
        {
            Some(h) => {
                (h.handler)();
                true
            }
            None => false,
        }
    }
}

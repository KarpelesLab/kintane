//! virtio-blk in the kernel: the protocol in `virtio-blk-core`, and what only the kernel adds.
//!
//! # What is different about this driver
//!
//! Every driver before it moved bytes through registers. This one hands the device
//! *addresses* and lets it read and write memory on its own, which brings in two things
//! the device model had not needed:
//!
//! * **Device addresses.** A descriptor carries the address the device uses, which is not the one
//!   the CPU uses. [`mem::Dma`] carries both and keeps them apart.
//! * **Memory that outlives a call.** The rings and the bounce buffers are a region the kernel
//!   gives the driver once. It is carved up at bring-up and never grows, so there is nothing to
//!   allocate on the path that serves a request.
//!
//! # One driver, two hosts
//!
//! The virtqueue, the handshake and the requests are `virtio_blk_core`, written over the
//! proxy layer's traits so that the same source runs here and in an unprivileged driver domain
//! (`docs/isolation.md`). This crate is the kernel's host for it: binding through the device
//! model, the block layer's request tickets, a lock so several CPUs can have requests in
//! flight, and the interrupt handler. It speaks none of the protocol itself.
//!
//! # Bring-up is not `Driver::start`
//!
//! Discovery runs before the kernel's own memory management exists — it has to, because
//! the address space is built from what the drivers claim. A virtio device cannot be
//! initialised there: the handshake ends by handing the device queue addresses, and there
//! is no allocator yet to get memory from. So [`VirtioBlkDriver`] claims the window at
//! probe, does nothing at start, and the kernel calls [`VirtioBlk::bring_up`] later, with
//! a DMA region, once memory works. The device is quiescent in between, which is exactly
//! what a virtio device is before its status register is written.
//!
//! # Completion, and requests in flight together
//!
//! Each request owns one of the engine's slots — its own header, status byte and bounce
//! buffer — so several can be outstanding without overwriting each other. A request is
//! submitted under the device's lock and waited for with the lock *released*, because the
//! lock is what [`VirtioBlk::on_interrupt`] takes to collect a completion: held across the
//! wait, it would mask the device's interrupt on the waiting CPU and every completion would
//! be polled.
//!
//! The platform registers `on_interrupt` for the claimed line through
//! [`Driver::interrupt`]. Where a line is wired and interrupts are enabled, completions are
//! collected there; where none is, the waiter drains the used ring itself, to a bounded
//! limit. [`VirtioBlk::set_interrupt_driven`] forbids the second, which is how a check
//! proves the first rather than inferring it.
//!
//! Reference: Virtual I/O Device (VIRTIO) Version 1.1, §2.6 (virtqueues), §4.1 (PCI), §4.2
//! (MMIO), §5.2 (block devices).

#![cfg_attr(not(test), no_std)]
#![deny(unsafe_code)]

pub mod pci;

pub use virtio_blk_core::{
    F_BLK_SIZE, F_FLUSH, F_RO, IN_FLIGHT, QUEUE_SIZE, dma_bytes, mem, mmio, queue, transport,
};

// The core's fake device, compiled into this crate's tests too: the kernel's wrapper is
// tested against the same device the engine is.
#[cfg(test)]
#[allow(dead_code)]
#[path = "../../virtio-blk-core/src/test_support.rs"]
mod test_support;

#[cfg(test)]
mod tests;

use block::{BlockDevice, Error as BlockError, Geometry, Op, Queue as RequestQueue, Ticket};
use device::{BootCell, Bound, Driver, IrqLine, Mmio as MmioClaim, Probe, ProbeError};
use hwproxy::Direct;
use mem::Dma;
use sync::LockFamily;
use sync::lockdep::LockClass;
use transport::{Error, Transport};
use virtio_blk_core::engine::{self, Engine, SubmitError, status_byte};
use virtio_blk_core::{POLL_LIMIT, PROTOCOL_SECTOR};

/// What this driver binds to: a memory-mapped virtio slot, or a PCI function whose vendor
/// and device ID say it is a virtio block device.
///
/// The PCI strings are the ones `device::pci` builds for every function, most specific
/// first. `1af4,1042` is the modern block device and `1af4,1001` the transitional one,
/// which offers the modern interface as well and is driven through it.
pub const COMPATIBLE: &[&str] = &["virtio,mmio", "pci1af4,1042", "pci1af4,1001"];

/// How many requests the block layer's queue tracks.
const REQUESTS: usize = 8;

/// A virtio transport, of whichever kind this machine has, over the kernel's mapping of the
/// claimed window.
pub enum AnyTransport {
    Mmio(mmio::Mmio<Direct>),
    Pci(pci::Pci<Direct>),
}

impl Transport for AnyTransport {
    fn device_id(&self) -> u32 {
        match self {
            AnyTransport::Mmio(t) => t.device_id(),
            AnyTransport::Pci(t) => t.device_id(),
        }
    }
    fn status(&self) -> u8 {
        match self {
            AnyTransport::Mmio(t) => t.status(),
            AnyTransport::Pci(t) => t.status(),
        }
    }
    fn set_status(&self, value: u8) {
        match self {
            AnyTransport::Mmio(t) => t.set_status(value),
            AnyTransport::Pci(t) => t.set_status(value),
        }
    }
    fn device_features(&self, select: u32) -> u32 {
        match self {
            AnyTransport::Mmio(t) => t.device_features(select),
            AnyTransport::Pci(t) => t.device_features(select),
        }
    }
    fn set_driver_features(&self, select: u32, value: u32) {
        match self {
            AnyTransport::Mmio(t) => t.set_driver_features(select, value),
            AnyTransport::Pci(t) => t.set_driver_features(select, value),
        }
    }
    fn queue_max(&self, index: u16) -> u16 {
        match self {
            AnyTransport::Mmio(t) => t.queue_max(index),
            AnyTransport::Pci(t) => t.queue_max(index),
        }
    }
    fn setup_queue(&self, index: u16, size: u16, desc: u64, avail: u64, used: u64) {
        match self {
            AnyTransport::Mmio(t) => t.setup_queue(index, size, desc, avail, used),
            AnyTransport::Pci(t) => t.setup_queue(index, size, desc, avail, used),
        }
    }
    fn notify(&self, index: u16) {
        match self {
            AnyTransport::Mmio(t) => t.notify(index),
            AnyTransport::Pci(t) => t.notify(index),
        }
    }
    fn ack_interrupt(&self) -> u32 {
        match self {
            AnyTransport::Mmio(t) => t.ack_interrupt(),
            AnyTransport::Pci(t) => t.ack_interrupt(),
        }
    }
    fn config_read8(&self, offset: usize) -> u8 {
        match self {
            AnyTransport::Mmio(t) => t.config_read8(offset),
            AnyTransport::Pci(t) => t.config_read8(offset),
        }
    }
    fn config_read32(&self, offset: usize) -> u32 {
        match self {
            AnyTransport::Mmio(t) => t.config_read32(offset),
            AnyTransport::Pci(t) => t.config_read32(offset),
        }
    }
}

/// Everything a request touches, under one lock.
struct Inner {
    /// The rings and the per-request slots.
    engine: Engine,
    requests: RequestQueue<REQUESTS>,
    /// Whether completions are collected only by the interrupt handler; see
    /// [`VirtioBlk::set_interrupt_driven`].
    interrupt_driven: bool,
    /// Interrupts the device raised, completions collected inside them, and completions a
    /// waiting caller collected by draining the ring itself.
    ///
    /// Under the lock rather than in atomics: every reader can take the lock, and the
    /// driver has to build for a machine with no compare-and-swap at all, where an atomic
    /// counter is not something `core` offers.
    interrupts: u64,
    interrupt_completions: u64,
    polled_completions: u64,
    /// The most requests that were outstanding at once, observed at submission. Two or more
    /// is what shows the driver really had requests in flight together, rather than a
    /// concurrent design that happened to be used one request at a time.
    peak_in_flight: usize,
}

/// A started virtio block device.
///
/// Generic over the lock family, as every subsystem that must work on a machine without
/// compare-and-swap is: an SMP kernel gets a spinlock, a uniprocessor one gets interrupt
/// masking, and neither is named here.
pub struct VirtioBlk<L: LockFamily, T: Transport = AnyTransport> {
    transport: T,
    inner: L::Lock<Inner>,
    geometry: Geometry,
    max_transfer: u64,
    read_only: bool,
    flush_supported: bool,
    /// Polls of the used ring before a request is called lost; [`POLL_LIMIT`] unless a
    /// test shortens it.
    poll_limit: u32,
}

/// The lock class of a device's queue, for the lock-order checker.
pub static BLK_LOCK: LockClass = LockClass::new("driver.virtio-blk");

impl<L: LockFamily, T: Transport> VirtioBlk<L, T> {
    /// Bring a device up: the status handshake, feature negotiation, the queue, and the
    /// geometry read out of its configuration space — all the engine's.
    ///
    /// `dma` is memory the device may read and write for as long as the driver lives.
    pub fn bring_up(transport: T, dma: Dma) -> Result<VirtioBlk<L, T>, Error> {
        let engine = Engine::bring_up(&transport, dma)?;
        let facts = engine.facts();
        let geometry = Geometry::new(facts.block_size, facts.capacity).ok_or(Error::BadGeometry)?;
        Ok(VirtioBlk {
            transport,
            inner: L::new(
                Inner {
                    engine,
                    requests: RequestQueue::new(),
                    interrupt_driven: false,
                    interrupts: 0,
                    interrupt_completions: 0,
                    polled_completions: 0,
                    peak_in_flight: 0,
                },
                &BLK_LOCK,
            ),
            geometry,
            max_transfer: facts.max_transfer,
            read_only: facts.read_only,
            flush_supported: facts.flush_supported,
            poll_limit: POLL_LIMIT,
        })
    }

    /// Give up on a request after `polls` empty polls of the used ring. For a test of the
    /// timeout path, which at [`POLL_LIMIT`] would take seconds on a host.
    pub fn with_poll_limit(mut self, polls: u32) -> Self {
        self.poll_limit = polls;
        self
    }

    /// Whether the device was offered read-only.
    pub fn read_only(&self) -> bool {
        self.read_only
    }

    /// Requests issued, completed and still in flight, for an audit that wants to prove
    /// nothing was lost.
    pub fn counters(&self) -> (u64, u64, usize, bool) {
        L::with(&self.inner, |i| {
            (
                i.requests.issued(),
                i.requests.completed(),
                i.requests.in_flight(),
                i.requests.balanced() && i.engine.all_descriptors_free(),
            )
        })
    }

    /// Ask the device for the blocks just past its end, skipping the range check every
    /// other path applies.
    ///
    /// For one purpose: a boot check of the path a *device's* refusal takes. Every other
    /// out-of-range request is stopped by `Geometry::range` before the device sees it, so
    /// without this the status byte's error values would only ever be exercised against
    /// the host tests' fake device. The device must answer with an error status, and the
    /// driver must turn that into an error value and recover.
    pub fn read_past_end_unchecked(&self, into: &mut [u8]) -> Result<(), BlockError> {
        let size = self.geometry.block_size;
        let blocks = (into.len() / size) as u64;
        if blocks == 0 || into.len() % size != 0 || blocks > self.max_transfer {
            return Err(BlockError::Misaligned {
                bytes: into.len(),
                block_size: size,
            });
        }
        self.request(Op::Read, self.geometry.capacity, blocks, None, Some(into))
    }

    /// Acknowledge the device's interrupt and collect what it finished.
    ///
    /// The handler the platform registers for the claimed line. Acknowledging first is
    /// what makes the next completion able to raise a new interrupt: the status register
    /// clears on read, so a completion that arrives while this runs is still reported.
    /// Draining under the same lock a waiter uses is what lets the waiter sleep on its own
    /// slot rather than poll the ring.
    ///
    /// Returns whether the interrupt was this device's, which is how a shared line is
    /// shared.
    pub fn on_interrupt(&self) -> bool {
        let pending = self.transport.ack_interrupt();
        if pending == 0 {
            return false;
        }
        L::with(&self.inner, |inner| {
            let taken = inner.engine.drain();
            inner.interrupts += 1;
            inner.interrupt_completions += u64::from(taken);
        });
        true
    }

    /// One request, submitted and waited for.
    fn request(
        &self,
        op: Op,
        lba: u64,
        blocks: u64,
        write_from: Option<&[u8]>,
        read_into: Option<&mut [u8]>,
    ) -> Result<(), BlockError> {
        let sectors_per_block = (self.geometry.block_size / PROTOCOL_SECTOR) as u64;
        if lba.checked_mul(sectors_per_block).is_none() {
            return Err(BlockError::OutOfRange {
                lba,
                blocks,
                capacity: self.geometry.capacity,
            });
        }
        let kind = match op {
            Op::Read => engine::Op::Read,
            Op::Write => engine::Op::Write,
            Op::Flush => engine::Op::Flush,
        };

        // Submit under the lock: a ticket, then a free slot with its chain published.
        let (ticket, slot) =
            L::with(&self.inner, |inner| -> Result<(Ticket, usize), BlockError> {
                let ticket = inner.requests.submit(op, lba, blocks)?;
                inner.peak_in_flight = inner.peak_in_flight.max(inner.requests.in_flight());
                match inner
                    .engine
                    .submit(&self.transport, kind, lba, blocks, write_from)
                {
                    Ok(slot) => Ok((ticket, slot)),
                    Err(e) => {
                        let why = match e {
                            SubmitError::NoRoom => BlockError::NoRoom,
                            SubmitError::TooLarge => {
                                BlockError::Device("a transfer larger than a request's buffer")
                            }
                            SubmitError::BadChain => {
                                BlockError::Device("a chain the queue cannot take")
                            }
                        };
                        let _ = inner.requests.complete(ticket, Err(why));
                        let _ = inner.requests.take(ticket);
                        Err(why)
                    }
                }
            })?;

        // Wait for *this* slot, with the lock released between looks.
        //
        // Released, because the lock is what an interrupt handler takes to collect a
        // completion: held across the wait, it would mask the device's interrupt on this CPU
        // and every completion would be collected here by polling, however the device
        // signalled it. Waiting on the slot rather than on the next completion, because the
        // device answers in whatever order it likes, and with several requests outstanding
        // the first completion is usually somebody else's.
        //
        // In interrupt-driven mode the waiter never drains the ring itself: a completion
        // can then only be collected by the handler, which is what makes "every completion
        // arrived by interrupt" a fact the counters prove rather than a timing hope.
        let mut polls = 0u32;
        let outcome = loop {
            let status = L::with(&self.inner, |inner| {
                if !inner.engine.is_done(slot) && !inner.interrupt_driven {
                    let taken = inner.engine.drain();
                    inner.polled_completions += u64::from(taken);
                }
                inner.engine.status_of(slot)
            });
            if let Some(status) = status {
                break match status {
                    status_byte::OK => Ok(()),
                    status_byte::IOERR => {
                        Err(BlockError::Device("the device reported an I/O error"))
                    }
                    status_byte::UNSUPP => {
                        Err(BlockError::Device("the device refused the request"))
                    }
                    _ => Err(BlockError::Device("the device left an unknown status")),
                };
            }
            polls += 1;
            if polls >= self.poll_limit {
                break Err(BlockError::Timeout);
            }
            core::hint::spin_loop();
        };

        L::with(&self.inner, |inner| {
            let copy = if outcome.is_ok() { read_into } else { None };
            // A request that timed out keeps its slot; see `Engine::finish`.
            let timed_out = matches!(outcome, Err(BlockError::Timeout));
            inner.engine.finish(slot, copy, timed_out);
            inner.requests.complete(ticket, outcome)?;
            inner.requests.take(ticket)?
        })
    }

    /// Collect completions only in the interrupt handler, never by polling.
    ///
    /// For a caller that knows the device's interrupt is routed and that interrupts are
    /// enabled while it waits. Without both, every request in this mode times out, which
    /// is the correct failure: it means the interrupt did not arrive.
    pub fn set_interrupt_driven(&self, on: bool) {
        L::with(&self.inner, |i| i.interrupt_driven = on);
    }

    /// How many interrupts the device raised, and how many completions were collected
    /// inside them rather than by a polling caller.
    pub fn interrupt_counts(&self) -> (u64, u64) {
        L::with(&self.inner, |i| (i.interrupts, i.interrupt_completions))
    }

    /// How many completions a waiting caller collected by polling rather than the handler.
    /// Zero across a stretch of interrupt-driven requests is what proves they arrived by
    /// interrupt.
    pub fn polled_completions(&self) -> u64 {
        L::with(&self.inner, |i| i.polled_completions)
    }

    /// The most requests that were outstanding at once since bring-up.
    pub fn peak_in_flight(&self) -> usize {
        L::with(&self.inner, |i| i.peak_in_flight)
    }
}

impl<L: LockFamily, T: Transport> BlockDevice for VirtioBlk<L, T> {
    fn geometry(&self) -> Geometry {
        self.geometry
    }

    fn max_transfer_blocks(&self) -> u64 {
        self.max_transfer
    }

    fn read_blocks(&self, lba: u64, into: &mut [u8]) -> Result<(), BlockError> {
        let blocks = self.geometry.range(lba, into.len())?;
        if blocks > self.max_transfer {
            return Err(BlockError::Device("a transfer larger than the device takes"));
        }
        self.request(Op::Read, lba, blocks, None, Some(into))
    }

    fn write_blocks(&self, lba: u64, from: &[u8]) -> Result<(), BlockError> {
        let blocks = self.geometry.range(lba, from.len())?;
        if blocks > self.max_transfer {
            return Err(BlockError::Device("a transfer larger than the device takes"));
        }
        if self.read_only {
            return Err(BlockError::Device("the device is read-only"));
        }
        self.request(Op::Write, lba, blocks, Some(from), None)
    }

    fn flush(&self) -> Result<(), BlockError> {
        if !self.flush_supported {
            // Not an error: a device that does not offer FLUSH has nothing to flush, and
            // a caller that treats that as a failure cannot use such a device at all.
            return Ok(());
        }
        self.request(Op::Flush, 0, 0, None, None)
    }
}

/// What the probe claimed, kept for bring-up.
///
/// `bus` is what the probe learned about where the registers are, which differs by
/// transport: a memory-mapped slot is the claimed window itself, and a PCI function is
/// that window plus the layout its capabilities described, since the driver cannot read
/// configuration space once the enumerator is gone.
struct Claims {
    mmio: MmioClaim,
    irq: Option<IrqLine>,
    bus: Bus,
}

/// Which transport the bound device is on, and what it takes to build it.
enum Bus {
    Mmio,
    Pci {
        layout: pci::Layout,
        bar: u8,
        device_id: u32,
    },
}

static CLAIMS: BootCell<Claims> = BootCell::new();

/// The window the bound device claimed, as a physical `(address, length)`.
pub fn window() -> Option<(u64, u64)> {
    CLAIMS.get().map(|c| (c.mmio.phys(), c.mmio.len()))
}

/// Whether an interrupt line was claimed for the device.
pub fn has_irq() -> bool {
    CLAIMS.get().is_some_and(|c| c.irq.is_some())
}

/// The transport for the bound device, of whichever kind its bus is.
///
/// # Safety
/// The claimed window must be mapped, as device memory, at
/// [`hal::paging::DEVICE_WINDOW_BASE`] above its physical address — the kernel's address
/// space maps every claimed window there — and this must be called once,
/// because two transports for one device would be two drivers for one device.
#[allow(unsafe_code)]
pub unsafe fn transport() -> Option<AnyTransport> {
    let claims = CLAIMS.get()?;
    let (phys, len) = window()?;
    let base = hal::paging::device_virt(phys)?;
    let len = usize::try_from(len).ok()?;
    // SAFETY: the caller's contract; the window is the one the probe claimed.
    let window = unsafe { Direct::new(base, len) };
    match &claims.bus {
        Bus::Mmio => Some(AnyTransport::Mmio(mmio::Mmio::new(window))),
        // Every structure the layout names is checked to be inside the BAR.
        Bus::Pci {
            layout,
            bar,
            device_id,
        } => pci::Pci::new(layout, *bar, window, *device_id)
            .ok()
            .map(AnyTransport::Pci),
    }
}

pub struct VirtioBlkDriver;

pub static DRIVER: VirtioBlkDriver = VirtioBlkDriver;

// Storing the probe's claims into a boot cell.
#[allow(unsafe_code)]
impl Driver for VirtioBlkDriver {
    fn name(&self) -> &'static str {
        "virtio-blk"
    }

    fn compatible(&self) -> &'static [&'static str] {
        COMPATIBLE
    }

    fn probe(&self, p: &mut Probe<'_, '_, '_, '_>) -> Result<(), ProbeError> {
        // Which transport this is comes from the node, not from a guess: a PCI function
        // carries the record enumeration made, and a memory-mapped slot does not.
        let function = match p.tree().node(p.node()).origin() {
            device::Origin::Pci(f) => Some(f),
            _ => None,
        };
        let (mmio, bus) = match function {
            Some(f) => {
                let layout = pci::layout_of(f).map_err(|_| {
                    ProbeError::Declined("no modern virtio structures in the capability list")
                })?;
                // Every structure must be in one BAR, because one window is what a probe
                // claims and therefore what the kernel maps. QEMU's virtio-pci puts all
                // four in the same BAR; a device that spreads them is refused rather than
                // half-driven.
                let bar = layout.single_bar().ok_or(ProbeError::Declined(
                    "the device's structures are spread over several BARs",
                ))?;
                let index = f
                    .memory_bar_index(bar)
                    .ok_or(ProbeError::Declined("the structures' BAR decodes no memory"))?;
                let mmio = p.claim_mmio(index, "virtio-blk registers")?;
                let bus = Bus::Pci {
                    layout,
                    bar,
                    device_id: transport::DEVICE_ID_BLOCK,
                };
                (mmio, bus)
            }
            None => {
                let mmio = p.claim_mmio(0, "virtio-blk registers")?;
                if mmio.len() < mmio::MIN_WINDOW {
                    return Err(ProbeError::Declined("the window is too small for virtio-mmio"));
                }
                (mmio, Bus::Mmio)
            }
        };
        // A device whose interrupt is malformed or taken can still be polled, so an
        // interrupt that cannot be claimed is not a reason to refuse the disk.
        let irq = p.claim_irq(0).ok();
        // SAFETY: probe runs during single-threaded boot.
        unsafe { CLAIMS.set(Claims { mmio, irq, bus }) }
            .map(|_| ())
            .map_err(|_| ProbeError::Declined("one virtio-blk device is supported"))
    }

    fn start(&self, _bound: &Bound) -> Result<(), &'static str> {
        // Nothing: see the module documentation. The device is untouched until the
        // kernel has memory to give it, and an untouched virtio device is quiescent.
        Ok(())
    }

    /// The line claimed at probe, and the handler that drains the used ring.
    ///
    /// The platform registers and enables it after `start`. The device raises nothing
    /// until `bring_up` writes `DRIVER_OK`, which happens later still, so a handler
    /// registered here cannot run before the driver exists to serve it.
    fn interrupt(&self) -> Option<(&'static IrqLine, fn())> {
        let irq = CLAIMS.get()?.irq.as_ref()?;
        Some((irq, on_device_interrupt))
    }
}

/// The registered handler: drain whichever device this kernel brought up.
///
/// A free function because that is what the device model's table holds. It reaches the
/// started device through the kernel's own hook, since the driver does not own it: the
/// kernel brings the device up with memory it provides, and keeps it.
fn on_device_interrupt() {
    if let Some(handler) = HANDLER.get() {
        handler();
    }
}

/// What [`on_device_interrupt`] calls. The kernel installs this once it has brought the
/// device up, because only it holds the started `VirtioBlk`.
static HANDLER: BootCell<fn()> = BootCell::new();

/// Install the function the device's interrupt runs.
///
/// # Safety
/// Once, on the boot path, before the line is enabled.
#[allow(unsafe_code)]
pub unsafe fn set_handler(handler: fn()) -> bool {
    // SAFETY: the caller's contract.
    unsafe { HANDLER.set(handler) }.is_ok()
}

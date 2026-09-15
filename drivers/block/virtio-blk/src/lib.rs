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
use device::{BootCell, Bound, Driver, IrqLine, NodeId, Probe, ProbeError};
use mem::Dma;
use sync::LockFamily;
use sync::lockdep::LockClass;
use transport::{Error, Transport};
use virtio_bind::Claims;
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

/// A virtio transport, of whichever kind this machine has: every virtio driver's, in
/// `drivers/virtio`.
pub use virtio::AnyTransport;

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
    /// Whether the queue signals on an MSI-X vector of its own, in which case the device does
    /// not set the interrupt status register for it and [`Self::on_interrupt`] must not ask.
    msix: bool,
}

/// The lock class of a device's queue, for the lock-order checker.
pub static BLK_LOCK: LockClass = LockClass::new("driver.virtio-blk");

impl<L: LockFamily, T: Transport> VirtioBlk<L, T> {
    /// Bring a device up: the status handshake, feature negotiation, the queue, and the
    /// geometry read out of its configuration space — all the engine's.
    ///
    /// `dma` is memory the device may read and write for as long as the driver lives.
    pub fn bring_up(transport: T, dma: Dma) -> Result<VirtioBlk<L, T>, Error> {
        Self::bring_up_with_vector(transport, dma, None)
    }

    /// [`Self::bring_up`], with the request queue's interrupts on MSI-X table entry `vector`
    /// when it is `Some`.
    ///
    /// For a device whose platform wired that entry: its table programmed, MSI-X enabled
    /// and a handler registered. One vector, for the one queue. The engine writes it after
    /// `negotiate`'s reset, which forgets it, and before the queue is enabled, and reads it
    /// back: a device that refuses one fails bring-up with [`Error::VectorRefused`], because a
    /// queue that silently kept no vector would never interrupt.
    pub fn bring_up_with_vector(
        transport: T,
        dma: Dma,
        vector: Option<u16>,
    ) -> Result<VirtioBlk<L, T>, Error> {
        let engine = Engine::bring_up(&transport, dma, vector)?;
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
            msix: facts.uses_msix,
        })
    }

    /// Whether the queue was given an MSI-X vector at bring-up.
    pub fn uses_msix(&self) -> bool {
        self.msix
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
    ///
    /// On an MSI-X vector there is nothing to acknowledge and nothing to share: the vector is
    /// this queue's alone, and the device does not set the status register for a queue
    /// interrupt it delivers that way (virtio 1.1 §4.1.4.5). Asking would read zero and
    /// throw away every completion the interrupt announced, so the handler does not ask.
    pub fn on_interrupt(&self) -> bool {
        if !self.msix && self.transport.ack_interrupt() == 0 {
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

    /// Point the device at a read of `len` bytes into device address `addr`, and wait a
    /// bounded while for it. Returns whether the device *completed* the read.
    ///
    /// For one purpose: proving an IOMMU stops a device reaching memory outside its grant. A
    /// driver never does this — every buffer it uses is one of its own slots — so it is a
    /// deliberate out-of-grant DMA, exactly what isolation must contain. Behind an IOMMU with
    /// no mapping for `addr`, the device's write faults and never completes, and this returns
    /// `false`; the fault log and the untouched target are the evidence the host checks.
    /// `false` is the expected, safe outcome; `true` means the DMA was *not* blocked.
    pub fn dma_probe(&self, lba: u64, addr: u64, len: u32, poll_limit: u32) -> bool {
        let slot = match L::with(&self.inner, |i| {
            i.engine.submit_raw_read(&self.transport, lba, addr, len)
        }) {
            Ok(slot) => slot,
            Err(_) => return false,
        };
        let mut polls = 0u32;
        loop {
            let done = L::with(&self.inner, |i| {
                if !i.engine.is_done(slot) {
                    i.engine.drain();
                }
                i.engine.is_done(slot)
            });
            if done {
                L::with(&self.inner, |i| i.engine.finish(slot, None, false));
                return true;
            }
            polls += 1;
            if polls >= poll_limit {
                // Leave the slot: its chain is still the device's, and a completion that
                // arrives late must not write into a reused slot.
                L::with(&self.inner, |i| i.engine.finish(slot, None, true));
                return false;
            }
            core::hint::spin_loop();
        }
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

/// How many virtio-blk devices one kernel binds.
///
/// Two, because that is what a machine with a second drive has. A third is declined at
/// probe rather than silently ignored, the way `uart16550` declines a binding too many.
pub const MAX_DISKS: usize = 2;

/// One bound disk: the node it was probed from, what that probe claimed, and the handler
/// the kernel installs once it has brought the device up.
///
/// The node is what ties a slot to a device: [`Driver::interrupt`] is asked about a
/// [`Bound`], and the line it must answer with is the one claimed for *that* device.
struct Disk {
    node: BootCell<NodeId>,
    claims: BootCell<Claims>,
    handler: BootCell<fn()>,
}

impl Disk {
    const fn new() -> Self {
        Disk {
            node: BootCell::new(),
            claims: BootCell::new(),
            handler: BootCell::new(),
        }
    }
}

static DISKS: [Disk; MAX_DISKS] = [const { Disk::new() }; MAX_DISKS];

/// The slot a probe claimed for `node`, if one did.
///
/// Public because every layer above must agree with this numbering rather than keep a
/// counter of its own: a platform wiring a device's interrupt asks which slot claimed it,
/// so `block_line(i)` and `window(i)` name the same disk even if probe order and wiring
/// order differ.
pub fn slot(node: NodeId) -> Option<usize> {
    slot_of(node)
}

/// The slot a probe claimed for `node`, if one did.
fn slot_of(node: NodeId) -> Option<usize> {
    DISKS.iter().position(|d| d.node.get() == Some(&node))
}

/// How many disks this boot bound, in probe order: `disk`, then the second drive.
pub fn bound() -> usize {
    DISKS.iter().filter(|d| d.claims.get().is_some()).count()
}

/// The window disk `i` claimed, as a physical `(address, length)`.
pub fn window(i: usize) -> Option<(u64, u64)> {
    DISKS.get(i)?.claims.get().map(Claims::window)
}

/// The MSI-X table entry disk `i`'s interrupt was claimed as, if it was one: what
/// [`VirtioBlk::bring_up_with_vector`] is given once the platform has wired it.
pub fn msix_entry(i: usize) -> Option<u16> {
    DISKS.get(i)?.claims.get()?.msix_entry()
}

/// The window claimed for disk `i`'s MSI-X table, as a physical `(address, length)`, when
/// it is not the registers' window.
pub fn msix_table_window(i: usize) -> Option<(u64, u64)> {
    DISKS.get(i)?.claims.get()?.msix_table_window()
}

/// Disk `i`'s PCI function's structure layout, BAR and device ID: what a driver domain is
/// told so it can build its own transport over its grant. `None` for a memory-mapped slot.
pub fn pci_layout(i: usize) -> Option<(virtio::pci::Layout, u8, u32)> {
    DISKS.get(i)?.claims.get()?.pci_layout()
}

/// The transport for disk `i`, of whichever kind its bus is.
///
/// # Safety
/// The claimed window must be mapped, as device memory, at
/// [`hal::paging::DEVICE_WINDOW_BASE`] above its physical address — the kernel's address
/// space maps every claimed window there — and this must be called once per disk,
/// because two transports for one device would be two drivers for one device.
#[allow(unsafe_code)]
pub unsafe fn transport(i: usize) -> Option<AnyTransport> {
    // SAFETY: the caller's contract is `Claims::transport`'s.
    unsafe { DISKS.get(i)?.claims.get()?.transport() }
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
        // What a virtio probe claims is the same for every device type, MSI-X included; see
        // `virtio_bind`. A device whose interrupt cannot be claimed is still bound, and
        // polled.
        let claims = Claims::claim(
            p,
            "virtio-blk registers",
            "virtio-blk MSI-X table",
            transport::DEVICE_ID_BLOCK,
        )?;
        // The first free slot, so a second drive binds beside the first rather than being
        // turned away. Which slot a device took is what `interrupt` answers by.
        let node = p.node();
        let slot = DISKS
            .iter()
            .find(|d| d.claims.get().is_none())
            .ok_or(ProbeError::Declined("more virtio-blk devices than slots"))?;
        // SAFETY: probe runs during single-threaded boot.
        unsafe { slot.node.set(node) }
            .map_err(|_| ProbeError::Declined("the disk slot was taken"))?;
        // SAFETY: as above.
        unsafe { slot.claims.set(claims) }
            .map(|_| ())
            .map_err(|_| ProbeError::Declined("the disk slot was taken"))
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
    fn interrupt(&self, bound: &Bound) -> Option<(&'static IrqLine, fn())> {
        // The line claimed for *this* device, and the trampoline that dispatches to it.
        let i = slot_of(bound.node())?;
        let irq = DISKS[i].claims.get()?.irq()?;
        Some((irq, TRAMPOLINES[i]))
    }
}

/// One registered handler per disk: drain whichever device raised the interrupt.
///
/// The device model's table holds a bare `fn()`, with nothing to say which device it is
/// for, so each slot needs a function of its own. They reach the started device through
/// the kernel's hook, since the driver does not own it: the kernel brings the device up
/// with memory it provides, and keeps it.
fn on_disk_0() {
    dispatch(0);
}

fn on_disk_1() {
    dispatch(1);
}

/// A trampoline per slot, indexed the way [`DISKS`] is. A compile error here means
/// [`MAX_DISKS`] grew without a function to dispatch the new slot's interrupt.
static TRAMPOLINES: [fn(); MAX_DISKS] = [on_disk_0, on_disk_1];

/// Run disk `i`'s handler, if the kernel has installed one.
fn dispatch(i: usize) {
    if let Some(handler) = DISKS[i].handler.get() {
        handler();
    }
}

/// Install the function disk `i`'s interrupt runs.
///
/// # Safety
/// Once per disk, on the boot path, before its line is enabled.
#[allow(unsafe_code)]
pub unsafe fn set_handler(i: usize, handler: fn()) -> bool {
    let Some(disk) = DISKS.get(i) else {
        return false;
    };
    // SAFETY: the caller's contract.
    unsafe { disk.handler.set(handler) }.is_ok()
}

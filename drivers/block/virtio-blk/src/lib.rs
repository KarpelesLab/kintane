//! virtio-blk: the first driver with a device that reads and writes memory.
//!
//! # What is different about this driver
//!
//! Every driver before it moved bytes through registers. This one hands the device
//! *addresses* and lets it read and write memory on its own, which brings in two things
//! the device model had not needed:
//!
//! * **Physical addresses.** A descriptor carries the address the device uses, which is not the one
//!   the CPU uses. [`mem::Dma`] carries both and keeps them apart; handing a device a virtual
//!   address is a mistake the host tests catch, because the fake device's memory is at a different
//!   offset.
//! * **Memory that outlives a call.** The rings and the bounce buffer are a region the kernel gives
//!   the driver once. It is carved up at bring-up and never grows, so there is nothing to allocate
//!   on the path that serves a request.
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
//! Each request owns a slot — its own header, status byte and bounce buffer — so several
//! can be outstanding without overwriting each other. A request is submitted under the
//! device's lock and waited for with the lock *released*, because the lock is what
//! [`VirtioBlk::on_interrupt`] takes to collect a completion: held across the wait, it would
//! mask the device's interrupt on the waiting CPU and every completion would be polled.
//!
//! The platform registers `on_interrupt` for the claimed line through
//! [`Driver::interrupt`]. Where a line is wired and interrupts are enabled, completions are
//! collected there; where none is, the waiter drains the used ring itself, to a bounded
//! limit. [`VirtioBlk::set_interrupt_driven`] forbids the second, which is how a check
//! proves the first rather than inferring it.
//!
//! Reference: Virtual I/O Device (VIRTIO) Version 1.1, §2.6 (virtqueues), §4.2 (MMIO),
//! §5.2 (block devices).

#![cfg_attr(not(test), no_std)]
#![deny(unsafe_code)]

pub mod mem;
pub mod mmio;
pub mod pci;
pub mod queue;
pub mod transport;

#[cfg(test)]
mod test_support;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod drain_tests;

use block::{BlockDevice, Error as BlockError, Geometry, Op, Queue as RequestQueue, Ticket};
use device::{BootCell, Bound, Driver, IrqLine, Mmio as MmioClaim, Probe, ProbeError};
use mem::{Dma, Window};
use queue::{Buf, Ring};
use sync::LockFamily;
use sync::lockdep::LockClass;
use transport::{Error, Transport};

/// What this driver binds to: a memory-mapped virtio slot, or a PCI function whose vendor
/// and device ID say it is a virtio block device.
///
/// The PCI strings are the ones `device::pci` builds for every function, most specific
/// first. `1af4,1042` is the modern block device and `1af4,1001` the transitional one,
/// which offers the modern interface as well and is driven through it.
pub const COMPATIBLE: &[&str] = &["virtio,mmio", "pci1af4,1042", "pci1af4,1001"];

/// Descriptors in the device's queue: a power of two, as the split virtqueue requires, and
/// large enough for every request [`IN_FLIGHT`] allows to be outstanding at once.
pub const QUEUE_SIZE: u16 = 16;

/// How many requests the block layer's queue tracks.
const REQUESTS: usize = 8;

/// The device's request queue: virtio-blk has exactly one (virtio 1.1 §5.2.2).
const QUEUE_INDEX: u16 = 0;

/// A virtio-blk request header (virtio 1.1 §5.2.6).
const HEADER_BYTES: usize = 16;

/// The sector size the *protocol* uses, whatever the device's logical block size is.
const PROTOCOL_SECTOR: usize = 512;

/// Request types.
const T_IN: u32 = 0;
const T_OUT: u32 = 1;
const T_FLUSH: u32 = 4;

/// Feature bits of a block device (virtio 1.1 §5.2.3).
const F_BLK_SIZE: u32 = 1 << 6;
const F_FLUSH: u32 = 1 << 9;
const F_RO: u32 = 1 << 5;

/// Device configuration offsets (virtio 1.1 §5.2.4).
const CFG_CAPACITY: usize = 0;
const CFG_BLK_SIZE: usize = 20;

/// Polls of the used ring before a request is called lost.
///
/// A bound rather than a spin for ever: a device that has stopped answering must be an
/// error a caller can report, not a kernel that stops. Under QEMU a request completes in
/// a few hundred polls; the bound is far above that and still finite.
const POLL_LIMIT: u32 = 50_000_000;

/// Requests that may be in flight at once, each with its own header, status byte and
/// bounce buffer.
pub const IN_FLIGHT: usize = 4;

/// Descriptors one request's chain can take: its header, its data, and its status byte.
const DESCRIPTORS_PER_REQUEST: usize = 3;

/// Every slot must be able to publish its chain at once, or a request that found a free slot
/// would be refused by a full ring. Checked at build time, because a queue of eight — what
/// this once was — holds only two full requests, and nothing short of three requests
/// outstanding together would ever show it.
const _: () = assert!(
    IN_FLIGHT * DESCRIPTORS_PER_REQUEST <= QUEUE_SIZE as usize,
    "QUEUE_SIZE cannot hold a full chain for every request IN_FLIGHT allows"
);

/// The bytes of DMA the driver needs: the rings, then a header, a status byte and a
/// bounce buffer for each request that can be outstanding, with room for the alignment
/// between them.
pub const fn dma_bytes(bounce: usize) -> usize {
    transport::queue_bytes(QUEUE_SIZE) + IN_FLIGHT * (HEADER_BYTES + 1 + 32 + bounce)
}

/// A virtio transport, of whichever kind this machine has.
pub enum AnyTransport {
    Mmio(mmio::Mmio),
    Pci(pci::Pci),
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

/// The memory one request owns while it is in flight.
///
/// One set per slot rather than one for the device: two requests that shared a header
/// would each overwrite the other's sector number, and two that shared a status byte
/// could not tell whose error they were reading. The bounce buffer is per slot for the
/// same reason, which is what bounds how many requests can be outstanding.
struct Slot {
    /// The request header the device reads.
    header: Dma,
    /// The status byte the device writes.
    status: Dma,
    /// Data on its way to or from the caller's buffer.
    bounce: Dma,
    /// The head descriptor of the chain this slot is published as, while it is in flight.
    head: Option<u16>,
    /// Set when a completion for this slot's chain has been collected, by whichever of the
    /// interrupt handler and the waiting caller drained the ring first. The waiter reads
    /// its own slot rather than assuming the first completion it sees is its own, because
    /// the device answers in whatever order it likes.
    done: bool,
}

/// Everything a request touches, under one lock.
struct Inner {
    ring: Ring,
    slots: [Slot; IN_FLIGHT],
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

impl Inner {
    /// Take every completion the device has written, marking each slot's request done.
    ///
    /// Completions arrive in the device's order, not the order they were submitted, so
    /// each is matched to its slot by the head descriptor the used element names. One
    /// that matches no slot in flight is counted and dropped: a device that invents a
    /// descriptor id must not make the driver mark somebody else's request complete.
    fn drain(&mut self) -> u32 {
        let mut taken = 0;
        // Bounded by the ring: the device cannot have more outstanding than it was given.
        for _ in 0..self.ring.size() {
            let Some(used) = self.ring.poll_used() else {
                break;
            };
            taken += 1;
            let found = self.slots.iter_mut().find(|s| s.head == Some(used.head));
            if let Some(slot) = found {
                slot.head = None;
                slot.done = true;
            }
        }
        taken
    }
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
    /// geometry read out of its configuration space.
    ///
    /// `dma` is memory the device may read and write for as long as the driver lives.
    pub fn bring_up(transport: T, mut dma: Dma) -> Result<VirtioBlk<L, T>, Error> {
        let wanted = [F_BLK_SIZE | F_FLUSH, transport::VERSION_1_BIT];
        let accepted = transport::negotiate(&transport, transport::DEVICE_ID_BLOCK, wanted)?;

        let ring = transport::carve_ring(&mut dma, QUEUE_SIZE)?;
        transport::setup_queue(&transport, QUEUE_INDEX, &ring)?;

        // One set of buffers per request that may be outstanding. The bounce buffers split
        // what is left of the region evenly, rounded down to whole sectors, so no slot is
        // larger than another and `max_transfer` is the same whichever slot serves.
        let each = (dma.len() / IN_FLIGHT).saturating_sub(HEADER_BYTES + 1 + 32);
        let bounce_len = each & !(PROTOCOL_SECTOR - 1);
        if bounce_len < PROTOCOL_SECTOR {
            return Err(Error::NoRoom);
        }
        let mut slots = [const { None }; IN_FLIGHT];
        for slot in slots.iter_mut() {
            *slot = Some(Slot {
                header: dma.take(HEADER_BYTES, 16).ok_or(Error::NoRoom)?,
                status: dma.take(1, 1).ok_or(Error::NoRoom)?,
                bounce: dma.take(bounce_len, 16).ok_or(Error::NoRoom)?,
                head: None,
                done: false,
            });
        }
        let slots = slots.map(|s| s.expect("every slot was carved above"));

        // The configuration is only meaningful once features are accepted: `blk_size`
        // exists because `VIRTIO_BLK_F_BLK_SIZE` was negotiated.
        let sectors = transport.config_read64(CFG_CAPACITY);
        let block_size = if accepted[0] & F_BLK_SIZE != 0 {
            transport.config_read32(CFG_BLK_SIZE) as usize
        } else {
            PROTOCOL_SECTOR
        };
        let bytes = sectors
            .checked_mul(PROTOCOL_SECTOR as u64)
            .ok_or(Error::BadGeometry)?;
        if block_size == 0 || bytes % (block_size as u64) != 0 {
            return Err(Error::BadGeometry);
        }
        let geometry =
            Geometry::new(block_size, bytes / block_size as u64).ok_or(Error::BadGeometry)?;
        // One slot's bounce buffer, not the whole region: a request is served by a single
        // slot, so what one of them holds is what one request can carry.
        let max_transfer = (bounce_len / block_size) as u64;
        if max_transfer == 0 {
            return Err(Error::NoRoom);
        }

        transport::finish(&transport)?;

        Ok(VirtioBlk {
            transport,
            inner: L::new(
                Inner {
                    ring,
                    slots,
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
            max_transfer,
            read_only: accepted[0] & F_RO != 0,
            flush_supported: accepted[0] & F_FLUSH != 0,
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
                i.requests.balanced() && i.ring.free_descriptors() == QUEUE_SIZE,
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
            let taken = inner.drain();
            inner.interrupts += 1;
            inner.interrupt_completions += u64::from(taken);
        });
        true
    }

    /// One request, submitted and polled to completion.
    fn request(
        &self,
        op: Op,
        lba: u64,
        blocks: u64,
        write_from: Option<&[u8]>,
        read_into: Option<&mut [u8]>,
    ) -> Result<(), BlockError> {
        let sector = lba
            .checked_mul((self.geometry.block_size / PROTOCOL_SECTOR) as u64)
            .ok_or(BlockError::OutOfRange {
                lba,
                blocks,
                capacity: self.geometry.capacity,
            })?;
        let kind = match op {
            Op::Read => T_IN,
            Op::Write => T_OUT,
            Op::Flush => T_FLUSH,
        };
        let bytes = match op {
            Op::Flush => 0,
            _ => (blocks as usize) * self.geometry.block_size,
        };

        // Submit under the lock: a free slot, its buffers filled, its chain published.
        let (ticket, slot) =
            L::with(&self.inner, |inner| -> Result<(Ticket, usize), BlockError> {
                let ticket = inner.requests.submit(op, lba, blocks)?;
                inner.peak_in_flight = inner.peak_in_flight.max(inner.requests.in_flight());

                // A slot nothing else is using. Its buffers are its own, so another request in
                // flight cannot overwrite this one's header, status byte or data.
                let Some(slot) = inner.slots.iter().position(|s| s.head.is_none() && !s.done)
                else {
                    let _ = inner.requests.complete(ticket, Err(BlockError::NoRoom));
                    let _ = inner.requests.take(ticket);
                    return Err(BlockError::NoRoom);
                };
                if bytes > inner.slots[slot].bounce.len() {
                    let why = BlockError::Device("a transfer larger than a request's buffer");
                    let _ = inner.requests.complete(ticket, Err(why));
                    let _ = inner.requests.take(ticket);
                    return Err(why);
                }

                let s = &inner.slots[slot];
                s.header.write32(0, kind);
                s.header.write32(4, 0);
                s.header.write64(8, sector);
                s.status.write8(0, 0xff);
                if let Some(from) = write_from {
                    s.bounce.write_bytes(0, from);
                }

                let mut chain = [Buf {
                    phys: s.header.phys(),
                    len: HEADER_BYTES as u32,
                    device_writes: false,
                }; 3];
                let mut n = 1;
                if bytes > 0 {
                    chain[n] = Buf {
                        phys: s.bounce.phys(),
                        len: bytes as u32,
                        device_writes: op == Op::Read,
                    };
                    n += 1;
                }
                chain[n] = Buf {
                    phys: s.status.phys(),
                    len: 1,
                    device_writes: true,
                };
                n += 1;

                let head = match inner.ring.add(&chain[..n]) {
                    Ok(h) => h,
                    Err(e) => {
                        let why = match e {
                            queue::Error::Full => BlockError::NoRoom,
                            _ => BlockError::Device("a chain the queue cannot take"),
                        };
                        let _ = inner.requests.complete(ticket, Err(why));
                        let _ = inner.requests.take(ticket);
                        return Err(why);
                    }
                };
                inner.slots[slot].head = Some(head);
                if inner.ring.notify_wanted() {
                    self.transport.notify(QUEUE_INDEX);
                }
                Ok((ticket, slot))
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
                if !inner.slots[slot].done && !inner.interrupt_driven {
                    let taken = inner.drain();
                    inner.polled_completions += u64::from(taken);
                }
                inner.slots[slot]
                    .done
                    .then(|| inner.slots[slot].status.read8(0))
            });
            if let Some(status) = status {
                break match status {
                    0 => Ok(()),
                    1 => Err(BlockError::Device("the device reported an I/O error")),
                    2 => Err(BlockError::Device("the device refused the request")),
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
            if outcome.is_ok() {
                if let Some(into) = read_into {
                    inner.slots[slot].bounce.read_bytes(0, into);
                }
            }
            // A request that timed out keeps its slot. Its chain is still the device's, and
            // a completion that arrives late would write into the slot's buffers: reusing
            // them for another request would hand that request someone else's data.
            if !matches!(outcome, Err(BlockError::Timeout)) {
                inner.slots[slot].done = false;
            }
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
    match &claims.bus {
        Bus::Mmio => {
            // SAFETY: the caller's contract.
            let window = unsafe { Window::new(base, len) };
            // SAFETY: as above; one transport for the one device the driver bound.
            Some(AnyTransport::Mmio(unsafe { mmio::Mmio::new(window) }))
        }
        Bus::Pci {
            layout,
            bar,
            device_id,
        } => {
            // SAFETY: the caller's contract; the window is the BAR the probe claimed, and
            // every structure the layout names was checked to be inside it.
            let t = unsafe { pci::Pci::new(layout, *bar, base, len, *device_id) };
            t.ok().map(AnyTransport::Pci)
        }
    }
}

pub struct VirtioBlkDriver;

pub static DRIVER: VirtioBlkDriver = VirtioBlkDriver;

// The only `unsafe` outside `mem`: storing the probe's claims into a boot cell.
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
                let layout = pci::Layout::read(f).map_err(|_| {
                    ProbeError::Declined("no modern virtio structures in the capability list")
                })?;
                // Every structure must be in one BAR, because one window is what a probe
                // claims and therefore what the kernel maps. QEMU's virtio-pci puts all
                // four in the same BAR; a device that spreads them is refused rather than
                // half-driven.
                let bar = layout.common.bar;
                if layout.bars().iter().any(|b| *b != bar) {
                    return Err(ProbeError::Declined(
                        "the device's structures are spread over several BARs",
                    ));
                }
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

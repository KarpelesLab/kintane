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
//! # Completion is polled
//!
//! The interrupt line is claimed so nothing else takes it, and [`VirtioBlk::on_interrupt`]
//! is the handler, but the request path polls the used ring rather than waiting for it.
//! Interrupt dispatch through the device model's handler table does not exist yet;
//! `device::Handlers` says so. When it does, registering `on_interrupt` for the claimed
//! line is the whole change: the polling loop already drains the same ring.
//!
//! Reference: Virtual I/O Device (VIRTIO) Version 1.1, §2.6 (virtqueues), §4.2 (MMIO),
//! §5.2 (block devices).

#![cfg_attr(not(test), no_std)]
#![deny(unsafe_code)]

pub mod mem;
pub mod mmio;
pub mod queue;
pub mod transport;

#[cfg(test)]
mod test_support;

#[cfg(test)]
mod tests;

use block::{BlockDevice, Error as BlockError, Geometry, Op, Queue as RequestQueue};
use device::{BootCell, Bound, Driver, IrqLine, Mmio as MmioClaim, Probe, ProbeError};
use mem::{Dma, Window};
use queue::{Buf, Ring};
use sync::LockFamily;
use sync::lockdep::LockClass;
use transport::{Error, Transport};

/// The `compatible` string of a memory-mapped virtio slot.
pub const COMPATIBLE: &[&str] = &["virtio,mmio"];

/// Requests in flight at once. One is enough for a driver whose requests are polled to
/// completion; the queue is sized larger so the ring's bookkeeping is exercised by more
/// than one outstanding descriptor chain when an interrupt-driven path arrives.
pub const QUEUE_SIZE: u16 = 8;

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

/// The bytes of DMA the driver needs: the rings, a header and status byte per request,
/// and the bounce buffer.
pub const fn dma_bytes(bounce: usize) -> usize {
    transport::queue_bytes(QUEUE_SIZE) + HEADER_BYTES + 1 + 16 + bounce
}

/// A virtio transport, of whichever kind this machine has.
pub enum AnyTransport {
    Mmio(mmio::Mmio),
}

impl Transport for AnyTransport {
    fn device_id(&self) -> u32 {
        match self {
            AnyTransport::Mmio(t) => t.device_id(),
        }
    }
    fn status(&self) -> u8 {
        match self {
            AnyTransport::Mmio(t) => t.status(),
        }
    }
    fn set_status(&self, value: u8) {
        match self {
            AnyTransport::Mmio(t) => t.set_status(value),
        }
    }
    fn device_features(&self, select: u32) -> u32 {
        match self {
            AnyTransport::Mmio(t) => t.device_features(select),
        }
    }
    fn set_driver_features(&self, select: u32, value: u32) {
        match self {
            AnyTransport::Mmio(t) => t.set_driver_features(select, value),
        }
    }
    fn queue_max(&self, index: u16) -> u16 {
        match self {
            AnyTransport::Mmio(t) => t.queue_max(index),
        }
    }
    fn setup_queue(&self, index: u16, size: u16, desc: u64, avail: u64, used: u64) {
        match self {
            AnyTransport::Mmio(t) => t.setup_queue(index, size, desc, avail, used),
        }
    }
    fn notify(&self, index: u16) {
        match self {
            AnyTransport::Mmio(t) => t.notify(index),
        }
    }
    fn ack_interrupt(&self) -> u32 {
        match self {
            AnyTransport::Mmio(t) => t.ack_interrupt(),
        }
    }
    fn config_read8(&self, offset: usize) -> u8 {
        match self {
            AnyTransport::Mmio(t) => t.config_read8(offset),
        }
    }
    fn config_read32(&self, offset: usize) -> u32 {
        match self {
            AnyTransport::Mmio(t) => t.config_read32(offset),
        }
    }
}

/// Everything a request touches, under one lock.
struct Inner {
    ring: Ring,
    /// The request header the device reads.
    header: Dma,
    /// The status byte the device writes.
    status: Dma,
    /// Data on its way to or from the caller's buffer.
    bounce: Dma,
    requests: RequestQueue<REQUESTS>,
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

        let header = dma.take(HEADER_BYTES, 16).ok_or(Error::NoRoom)?;
        let status = dma.take(1, 1).ok_or(Error::NoRoom)?;
        let bounce_len = dma.len() & !(PROTOCOL_SECTOR - 1);
        let bounce = dma.take(bounce_len, 16).ok_or(Error::NoRoom)?;
        if bounce.len() < PROTOCOL_SECTOR {
            return Err(Error::NoRoom);
        }

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
        let max_transfer = (bounce.len() / block_size) as u64;
        if max_transfer == 0 {
            return Err(Error::NoRoom);
        }

        transport::finish(&transport)?;

        Ok(VirtioBlk {
            transport,
            inner: L::new(
                Inner {
                    ring,
                    header,
                    status,
                    bounce,
                    requests: RequestQueue::new(),
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

    /// Acknowledge the device's interrupt. The handler for the claimed line, once the
    /// device model dispatches interrupts; harmless before then.
    pub fn on_interrupt(&self) -> bool {
        self.transport.ack_interrupt() != 0
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

        L::with(&self.inner, |inner| {
            let ticket = inner.requests.submit(op, lba, blocks)?;

            inner.header.write32(0, kind);
            inner.header.write32(4, 0);
            inner.header.write64(8, sector);
            inner.status.write8(0, 0xff);
            if let Some(from) = write_from {
                inner.bounce.write_bytes(0, from);
            }

            let mut chain = [Buf {
                phys: inner.header.phys(),
                len: HEADER_BYTES as u32,
                device_writes: false,
            }; 3];
            let mut n = 1;
            if bytes > 0 {
                chain[n] = Buf {
                    phys: inner.bounce.phys(),
                    len: bytes as u32,
                    device_writes: op == Op::Read,
                };
                n += 1;
            }
            chain[n] = Buf {
                phys: inner.status.phys(),
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
            if inner.ring.notify_wanted() {
                self.transport.notify(QUEUE_INDEX);
            }

            let mut polls = 0u32;
            let outcome = loop {
                match inner.ring.poll_used() {
                    Some(used) if used.head == head => {
                        break match inner.status.read8(0) {
                            0 => Ok(()),
                            1 => Err(BlockError::Device("the device reported an I/O error")),
                            2 => Err(BlockError::Device("the device refused the request")),
                            _ => Err(BlockError::Device("the device left an unknown status")),
                        };
                    }
                    // Another chain finished first. This driver has one request in flight
                    // at a time, so it cannot happen today; when it can, the completion
                    // belongs to another caller and is theirs to collect.
                    Some(_) => continue,
                    None => {
                        polls += 1;
                        if polls >= self.poll_limit {
                            break Err(BlockError::Timeout);
                        }
                        core::hint::spin_loop();
                    }
                }
            };
            if outcome.is_ok() {
                if let Some(into) = read_into {
                    inner.bounce.read_bytes(0, into);
                }
            }
            inner.requests.complete(ticket, outcome)?;
            inner.requests.take(ticket)?
        })
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
struct Claims {
    mmio: MmioClaim,
    irq: Option<IrqLine>,
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

/// The transport for the bound device.
///
/// # Safety
/// The claimed window must be mapped, as device memory, at its physical address — the
/// kernel's address space maps every claimed window — and this must be called once,
/// because two transports for one device would be two drivers for one device.
#[allow(unsafe_code)]
pub unsafe fn transport() -> Option<AnyTransport> {
    let (phys, len) = window()?;
    let base = usize::try_from(phys).ok()?;
    let len = usize::try_from(len).ok()?;
    // SAFETY: the caller's contract.
    let window = unsafe { Window::new(base, len) };
    // SAFETY: as above; one transport for the one device the driver bound.
    Some(AnyTransport::Mmio(unsafe { mmio::Mmio::new(window) }))
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
        let mmio = p.claim_mmio(0, "virtio-blk registers")?;
        if mmio.len() < mmio::MIN_WINDOW {
            return Err(ProbeError::Declined("the window is too small for virtio-mmio"));
        }
        // A device whose interrupt is malformed or taken can still be polled, so an
        // interrupt that cannot be claimed is not a reason to refuse the disk.
        let irq = p.claim_irq(0).ok();
        // SAFETY: probe runs during single-threaded boot.
        unsafe { CLAIMS.set(Claims { mmio, irq }) }
            .map(|_| ())
            .map_err(|_| ProbeError::Declined("one virtio-blk device is supported"))
    }

    fn start(&self, _bound: &Bound) -> Result<(), &'static str> {
        // Nothing: see the module documentation. The device is untouched until the
        // kernel has memory to give it, and an untouched virtio device is quiescent.
        Ok(())
    }
}

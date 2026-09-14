//! One device's requests, with no lock and no allocation: the part of the driver both of
//! its hosts share.
//!
//! [`Engine`] owns the virtqueue and a slot per request that may be outstanding — a header,
//! a status byte and a bounce buffer each — so several requests can be in flight without
//! overwriting each other. It publishes a request ([`Engine::submit`]), collects what the
//! device finished ([`Engine::drain`]), and hands back a finished request's status and data
//! ([`Engine::finish`]). Who calls those, and under what exclusion, is the host's business:
//!
//! * The kernel's `VirtioBlk` calls them under its lock, waits with the lock released so the
//!   interrupt handler can drain, and tracks each request as a block-layer ticket.
//! * A driver domain runs alone on one thread, so it calls [`Engine::read_blocks`] and friends,
//!   which submit and then poll the used ring themselves.
//!
//! # Completions arrive in the device's order
//!
//! With several requests outstanding the device finishes them in whatever order it likes, and
//! each used element names the chain it finished. A completion is matched to its slot by that
//! head descriptor, never by position, which is what keeps one caller from being handed
//! another's result.

use crate::mem::Dma;
use crate::queue::{self, Buf, Ring};
use crate::transport::{self, Error, Transport};
use crate::{
    CFG_BLK_SIZE, CFG_CAPACITY, F_BLK_SIZE, F_FLUSH, F_RO, HEADER_BYTES, IN_FLIGHT, POLL_LIMIT,
    PROTOCOL_SECTOR, QUEUE_INDEX, QUEUE_SIZE, T_FLUSH, T_IN, T_OUT,
};

/// What a request does.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Op {
    Read,
    Write,
    Flush,
}

/// What bring-up learned about the device.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Facts {
    /// Bytes in one of the device's logical blocks.
    pub block_size: usize,
    /// Blocks the device holds.
    pub capacity: u64,
    /// Blocks one request can carry: what one slot's bounce buffer holds, since a request is
    /// served by a single slot.
    pub max_transfer: u64,
    pub read_only: bool,
    pub flush_supported: bool,
    /// Whether `VIRTIO_F_ACCESS_PLATFORM` was negotiated: the device's DMA goes through the
    /// platform's IOMMU rather than straight to physical memory.
    pub platform_iommu: bool,
    /// Whether the request queue was given an MSI-X vector, in which case the device signals
    /// completion on it and does not set the interrupt status register for it.
    pub uses_msix: bool,
}

/// Why a request could not be published.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SubmitError {
    /// Every slot is outstanding, or the ring has no room for the chain.
    NoRoom,
    /// More bytes than a slot's bounce buffer holds.
    TooLarge,
    /// A chain the queue cannot take.
    BadChain,
}

/// Why a request a single-threaded host made did not succeed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RequestError {
    /// Blocks past the end of the device.
    OutOfRange,
    /// A buffer that is not a whole number of blocks.
    Misaligned,
    /// A write to a device offered read-only.
    ReadOnly,
    Submit(SubmitError),
    /// The device finished the request with this status byte, which is not OK.
    Device(u8),
    /// The device did not finish the request within the poll limit.
    Timeout,
}

/// Status bytes a device writes (virtio 1.1 §5.2.6).
pub mod status_byte {
    pub const OK: u8 = 0;
    pub const IOERR: u8 = 1;
    pub const UNSUPP: u8 = 2;
    /// What a slot's status holds before the device writes it, so a request the device
    /// never touched cannot read as success.
    pub const UNWRITTEN: u8 = 0xff;
}

/// The memory one request owns while it is in flight.
///
/// One set per slot rather than one for the device: two requests that shared a header would
/// each overwrite the other's sector number, and two that shared a status byte could not tell
/// whose error they were reading. The bounce buffer is per slot for the same reason, which is
/// what bounds how many requests can be outstanding.
pub(crate) struct Slot {
    /// The request header the device reads.
    pub(crate) header: Dma,
    /// The status byte the device writes.
    pub(crate) status: Dma,
    /// Data on its way to or from the caller's buffer.
    pub(crate) bounce: Dma,
    /// The head descriptor of the chain this slot is published as, while it is in flight.
    pub(crate) head: Option<u16>,
    /// Set when a completion for this slot's chain has been collected, by whichever caller
    /// drained the ring first. A waiter reads its own slot rather than assuming the first
    /// completion it sees is its own, because the device answers in whatever order it likes.
    pub(crate) done: bool,
}

/// A request's data, as the chain names it.
enum Data<'a> {
    /// No data buffer: a flush.
    None,
    /// The slot's own bounce buffer, filled from `fill` first if the device reads it.
    Bounce {
        bytes: usize,
        device_writes: bool,
        fill: Option<&'a [u8]>,
    },
    /// A buffer at a device address the caller names; see [`Engine::submit_raw_read`].
    Raw { addr: u64, len: u32 },
}

/// A started device's requests.
pub struct Engine {
    pub(crate) ring: Ring,
    pub(crate) slots: [Slot; IN_FLIGHT],
    pub(crate) facts: Facts,
}

impl Engine {
    /// Bring a device up: the status handshake, feature negotiation, the queue, and the
    /// geometry read out of its configuration space.
    ///
    /// `dma` is memory the device may read and write for as long as the engine lives.
    ///
    /// When `vector` is `Some`, the request queue's interrupts are put on that MSI-X table
    /// entry, written after `negotiate`'s reset forgets it and before the queue is enabled.
    /// A device that will not take the vector reads back [`transport::NO_VECTOR`], which is
    /// [`Error::VectorRefused`] — a queue that silently kept no vector would never interrupt.
    /// Configuration-change interrupts are given none: the driver reads the configuration once,
    /// here, and never asks again.
    pub fn bring_up<T: Transport + ?Sized>(
        transport: &T,
        mut dma: Dma,
        vector: Option<u16>,
    ) -> Result<Engine, Error> {
        let wanted = [
            F_BLK_SIZE | F_FLUSH,
            transport::VERSION_1_BIT | transport::ACCESS_PLATFORM_BIT,
        ];
        let accepted = transport::negotiate(transport, transport::DEVICE_ID_BLOCK, wanted)?;

        transport.set_config_vector(transport::NO_VECTOR);
        if let Some(v) = vector {
            if transport.set_queue_vector(QUEUE_INDEX, v) != v {
                transport.set_status(transport::status::FAILED);
                return Err(Error::VectorRefused { queue: QUEUE_INDEX });
            }
        }

        let ring = transport::carve_ring(&mut dma, QUEUE_SIZE)?;
        transport::setup_queue(transport, QUEUE_INDEX, &ring)?;

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
        // A block smaller than the protocol's sector, or not a whole number of them, has no
        // sector number a request could name.
        if block_size < PROTOCOL_SECTOR
            || block_size % PROTOCOL_SECTOR != 0
            || bytes % (block_size as u64) != 0
        {
            return Err(Error::BadGeometry);
        }
        let max_transfer = (bounce_len / block_size) as u64;
        if max_transfer == 0 {
            return Err(Error::NoRoom);
        }

        transport::finish(transport)?;

        Ok(Engine {
            ring,
            slots,
            facts: Facts {
                block_size,
                capacity: bytes / block_size as u64,
                max_transfer,
                read_only: accepted[0] & F_RO != 0,
                flush_supported: accepted[0] & F_FLUSH != 0,
                platform_iommu: accepted[1] & transport::ACCESS_PLATFORM_BIT != 0,
                uses_msix: vector.is_some(),
            },
        })
    }

    pub fn facts(&self) -> Facts {
        self.facts
    }

    /// Whether every descriptor is back on the free list: nothing outstanding, nothing leaked.
    pub fn all_descriptors_free(&self) -> bool {
        self.ring.free_descriptors() == QUEUE_SIZE
    }

    /// Publish a request of `blocks` at `lba` in a free slot, and return the slot.
    ///
    /// The caller has already checked the range; this refuses only what the queue itself
    /// cannot take.
    pub fn submit<T: Transport + ?Sized>(
        &mut self,
        transport: &T,
        op: Op,
        lba: u64,
        blocks: u64,
        write_from: Option<&[u8]>,
    ) -> Result<usize, SubmitError> {
        let block_size = self.facts.block_size;
        let sector = lba
            .checked_mul((block_size / PROTOCOL_SECTOR) as u64)
            .ok_or(SubmitError::BadChain)?;
        let bytes = usize::try_from(blocks)
            .ok()
            .and_then(|b| b.checked_mul(block_size))
            .ok_or(SubmitError::TooLarge)?;
        let (kind, data) = match op {
            Op::Read => (
                T_IN,
                Data::Bounce {
                    bytes,
                    device_writes: true,
                    fill: None,
                },
            ),
            Op::Write => (
                T_OUT,
                Data::Bounce {
                    bytes,
                    device_writes: false,
                    fill: write_from,
                },
            ),
            Op::Flush => (T_FLUSH, Data::None),
        };
        self.publish(transport, kind, sector, data)
    }

    /// Publish a read whose data buffer is `len` bytes at device address `addr`, rather than
    /// the slot's own bounce buffer.
    ///
    /// For one purpose: a host proving its IOMMU stops a driver that points a device at memory
    /// outside its grant. A driver never needs it — every buffer it owns is a slot's — and a
    /// driver that uses it is doing exactly what isolation must contain. The device writes the
    /// data, so a successful read is a write to `addr`.
    pub fn submit_raw_read<T: Transport + ?Sized>(
        &mut self,
        transport: &T,
        lba: u64,
        addr: u64,
        len: u32,
    ) -> Result<usize, SubmitError> {
        let sector = lba
            .checked_mul((self.facts.block_size / PROTOCOL_SECTOR) as u64)
            .ok_or(SubmitError::BadChain)?;
        self.publish(transport, T_IN, sector, Data::Raw { addr, len })
    }

    fn publish<T: Transport + ?Sized>(
        &mut self,
        transport: &T,
        kind: u32,
        sector: u64,
        data: Data<'_>,
    ) -> Result<usize, SubmitError> {
        // A slot nothing else is using. Its buffers are its own, so another request in flight
        // cannot overwrite this one's header, status byte or data.
        let slot = self
            .slots
            .iter()
            .position(|s| s.head.is_none() && !s.done)
            .ok_or(SubmitError::NoRoom)?;
        let s = &self.slots[slot];
        let mut chain = [Buf {
            phys: s.header.phys(),
            len: HEADER_BYTES as u32,
            device_writes: false,
        }; 3];
        let mut n = 1;
        match data {
            Data::None => {}
            Data::Bounce {
                bytes,
                device_writes,
                fill,
            } => {
                if bytes > s.bounce.len() || fill.is_some_and(|f| f.len() > s.bounce.len()) {
                    return Err(SubmitError::TooLarge);
                }
                if let Some(from) = fill {
                    s.bounce.write_bytes(0, from);
                }
                chain[n] = Buf {
                    phys: s.bounce.phys(),
                    len: bytes as u32,
                    device_writes,
                };
                n += 1;
            }
            Data::Raw { addr, len } => {
                chain[n] = Buf {
                    phys: addr,
                    len,
                    device_writes: true,
                };
                n += 1;
            }
        }
        chain[n] = Buf {
            phys: s.status.phys(),
            len: 1,
            device_writes: true,
        };
        n += 1;

        s.header.write32(0, kind);
        s.header.write32(4, 0);
        s.header.write64(8, sector);
        s.status.write8(0, status_byte::UNWRITTEN);

        let head = self.ring.add(&chain[..n]).map_err(|e| match e {
            queue::Error::Full => SubmitError::NoRoom,
            _ => SubmitError::BadChain,
        })?;
        self.slots[slot].head = Some(head);
        if self.ring.notify_wanted() {
            transport.notify(QUEUE_INDEX);
        }
        Ok(slot)
    }

    /// Take every completion the device has written, marking each slot's request done.
    /// Returns how many used elements were collected.
    ///
    /// One that matches no slot in flight is counted and dropped: a device that invents a
    /// descriptor id must not make the driver mark somebody else's request complete.
    pub fn drain(&mut self) -> u32 {
        let mut taken = 0;
        // Bounded by the ring: the device cannot have more outstanding than it was given.
        for _ in 0..self.ring.size() {
            let Some(used) = self.ring.poll_used() else {
                break;
            };
            taken += 1;
            if let Some(slot) = self.slots.iter_mut().find(|s| s.head == Some(used.head)) {
                slot.head = None;
                slot.done = true;
            }
        }
        taken
    }

    /// Whether `slot`'s request has been collected.
    pub fn is_done(&self, slot: usize) -> bool {
        self.slots.get(slot).is_some_and(|s| s.done)
    }

    /// The status byte the device left in `slot`, once its request has been collected.
    pub fn status_of(&self, slot: usize) -> Option<u8> {
        let s = self.slots.get(slot)?;
        s.done.then(|| s.status.read8(0))
    }

    /// Release `slot` after its request ended, copying its data into `read_into` if given.
    ///
    /// A request that timed out keeps its slot (`timed_out`). Its chain is still the device's,
    /// and a completion that arrives late would write into the slot's buffers: reusing them
    /// for another request would hand that request someone else's data.
    pub fn finish(&mut self, slot: usize, read_into: Option<&mut [u8]>, timed_out: bool) {
        let Some(s) = self.slots.get_mut(slot) else {
            return;
        };
        if let Some(into) = read_into {
            s.bounce.read_bytes(0, into);
        }
        if !timed_out {
            s.done = false;
        }
    }

    /// How many blocks `len` bytes at `lba` are, if it is a request the device can take whole.
    pub fn range(&self, lba: u64, len: usize) -> Result<u64, RequestError> {
        let size = self.facts.block_size;
        if len == 0 || len % size != 0 {
            return Err(RequestError::Misaligned);
        }
        let blocks = (len / size) as u64;
        let end = lba.checked_add(blocks).ok_or(RequestError::OutOfRange)?;
        if end > self.facts.capacity {
            return Err(RequestError::OutOfRange);
        }
        if blocks > self.facts.max_transfer {
            return Err(RequestError::Submit(SubmitError::TooLarge));
        }
        Ok(blocks)
    }

    /// Wait for `slot` by draining the ring on this thread, then release it.
    ///
    /// For a host with nobody else to drain for it: a driver domain.
    pub fn wait_polled(
        &mut self,
        slot: usize,
        read_into: Option<&mut [u8]>,
        poll_limit: u32,
    ) -> Result<(), RequestError> {
        let mut polls = 0u32;
        let outcome = loop {
            if !self.is_done(slot) {
                self.drain();
            }
            if let Some(status) = self.status_of(slot) {
                break match status {
                    status_byte::OK => Ok(()),
                    other => Err(RequestError::Device(other)),
                };
            }
            polls += 1;
            if polls >= poll_limit {
                break Err(RequestError::Timeout);
            }
            core::hint::spin_loop();
        };
        let copy = if outcome.is_ok() { read_into } else { None };
        self.finish(slot, copy, outcome == Err(RequestError::Timeout));
        outcome
    }

    /// Read whole blocks at `lba` into `into`, waiting on this thread.
    pub fn read_blocks<T: Transport + ?Sized>(
        &mut self,
        transport: &T,
        lba: u64,
        into: &mut [u8],
    ) -> Result<(), RequestError> {
        let blocks = self.range(lba, into.len())?;
        let slot = self
            .submit(transport, Op::Read, lba, blocks, None)
            .map_err(RequestError::Submit)?;
        self.wait_polled(slot, Some(into), POLL_LIMIT)
    }

    /// Write whole blocks at `lba` from `from`, waiting on this thread.
    pub fn write_blocks<T: Transport + ?Sized>(
        &mut self,
        transport: &T,
        lba: u64,
        from: &[u8],
    ) -> Result<(), RequestError> {
        let blocks = self.range(lba, from.len())?;
        if self.facts.read_only {
            return Err(RequestError::ReadOnly);
        }
        let slot = self
            .submit(transport, Op::Write, lba, blocks, Some(from))
            .map_err(RequestError::Submit)?;
        self.wait_polled(slot, None, POLL_LIMIT)
    }

    /// Flush, waiting on this thread. A device that offers no flush has nothing to flush.
    pub fn flush<T: Transport + ?Sized>(&mut self, transport: &T) -> Result<(), RequestError> {
        if !self.facts.flush_supported {
            return Ok(());
        }
        let slot = self
            .submit(transport, Op::Flush, 0, 0, None)
            .map_err(RequestError::Submit)?;
        self.wait_polled(slot, None, POLL_LIMIT)
    }
}

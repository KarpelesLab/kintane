//! virtio-net: a network card that reads and writes frames in memory the kernel gives it.
//!
//! # Two queues, owned buffers
//!
//! Queue 0 is receive and queue 1 is transmit (virtio 1.1 §5.1.2). Every buffer either
//! queue uses is carved from the DMA region at bring-up and never grows:
//!
//! * **Receive.** [`RX_BUFFERS`] buffers, each large enough for the 12-byte header and a whole
//!   Ethernet frame, are posted to the device at bring-up. A completed buffer is *ready* until
//!   [`VirtioNet::recv`] copies its frame out, and is posted again at once. So at rest every
//!   receive buffer is either with the device or ready, which is what [`Counters::balanced`]
//!   checks.
//! * **Transmit.** [`TX_SLOTS`] slots, each holding one header and frame. A send copies into a free
//!   slot and publishes it; the slot is free again once the device reports it used. The send does
//!   not wait for that, so a full queue is an error value, not a stall.
//!
//! Mergeable receive buffers (`VIRTIO_NET_F_MRG_RXBUF`) are not negotiated. Without it a
//! receive buffer must hold a whole frame, which these do; the header is still 12 bytes in
//! virtio 1.x (§5.1.6). Checksum and segmentation offloads are not negotiated either, so the
//! device hands over frames exactly as they were on the wire.
//!
//! # Completion
//!
//! As in virtio-blk: [`VirtioNet::on_interrupt`] is the handler the platform registers for
//! the claimed line, and drains both queues under the device's lock. Where no line is
//! wired, [`VirtioNet::recv`] drains the receive queue itself. [`VirtioNet::set_interrupt_driven`]
//! forbids the second, which is how a check proves receive interrupts arrive rather than
//! inferring it from frames that a poll could have collected.
//!
//! # Bring-up is not `Driver::start`
//!
//! Also as in virtio-blk, and for the same reason: the handshake hands the device queue
//! addresses, and discovery runs before there is memory to hand over. The driver claims at
//! probe and the kernel calls [`VirtioNet::bring_up`] once memory works.
//!
//! Reference: Virtual I/O Device (VIRTIO) Version 1.1, §5.1 (network device).

#![cfg_attr(not(test), no_std)]
#![deny(unsafe_code)]

#[cfg(test)]
mod tests;

use device::{BootCell, Bound, Driver, IrqLine, Probe, ProbeError};
use sync::LockFamily;
use sync::lockdep::LockClass;
use virtio::AnyTransport;
use virtio::mem::Dma;
use virtio::queue::{Buf, Ring};
use virtio::transport::{self, Error, Transport};
use virtio_bind::Claims;

/// What this driver binds to: a memory-mapped virtio slot, or a PCI function whose vendor
/// and device ID say it is a virtio network card (modern `1041`, transitional `1000`).
///
/// A memory-mapped slot's compatible string is the same for every device type, so the
/// platform decides by reading the slot's device ID before it binds anything.
pub const COMPATIBLE: &[&str] = &["virtio,mmio", "pci1af4,1041", "pci1af4,1000"];

/// Descriptors in each queue.
pub const QUEUE_SIZE: u16 = 16;

/// Receive buffers posted to the device.
pub const RX_BUFFERS: usize = 8;

/// Frames that can be on their way out at once.
pub const TX_SLOTS: usize = 8;

const RX_QUEUE: u16 = 0;
const TX_QUEUE: u16 = 1;

/// `struct virtio_net_hdr` in virtio 1.x, `num_buffers` included whatever was negotiated.
pub const HEADER_BYTES: usize = 12;

/// The largest frame: an untagged Ethernet frame without its frame check sequence.
pub const FRAME_MAX: usize = 1514;

/// The smallest frame worth handing to a device: an Ethernet header.
pub const FRAME_MIN: usize = 14;

const BUFFER_BYTES: usize = HEADER_BYTES + FRAME_MAX;

/// `VIRTIO_NET_F_MAC`: the device's configuration holds its address.
const F_MAC: u32 = 1 << 5;

/// Where the address is in the device configuration.
const CFG_MAC: usize = 0;

/// A locally administered address, used when a device offers none of its own.
pub const FALLBACK_MAC: [u8; 6] = [0x02, 0x4b, 0x54, 0x00, 0x00, 0x01];

/// Bytes of DMA the driver needs: both rings, then a buffer per receive buffer and transmit
/// slot, with room for alignment between them.
pub const fn dma_bytes() -> usize {
    2 * transport::queue_bytes(QUEUE_SIZE) + (RX_BUFFERS + TX_SLOTS) * (BUFFER_BYTES + 16)
}

/// Why a frame was not sent.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SendError {
    /// Larger than [`FRAME_MAX`] or smaller than [`FRAME_MIN`].
    BadLength,
    /// Every transmit slot is still with the device.
    Full,
}

/// The driver's books.
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub struct Counters {
    pub rx_frames: u64,
    pub tx_frames: u64,
    pub tx_completed: u64,
    /// Transmit slots still with the device.
    pub tx_in_flight: usize,
    /// Receive buffers with the device.
    pub rx_posted: usize,
    /// Receive buffers holding a frame nobody has collected.
    pub rx_ready: usize,
    /// Completions that could not be a frame: shorter than the header, or claiming more
    /// than the buffer holds.
    pub rx_dropped: u64,
    pub interrupts: u64,
    /// Receive completions collected by the interrupt handler, and by a caller draining the
    /// queue itself.
    pub rx_by_interrupt: u64,
    pub rx_polled: u64,
    pub rx_free_descriptors: u16,
    pub tx_free_descriptors: u16,
}

impl Counters {
    /// Every receive buffer is with the device or holds a frame, and nothing is on its way
    /// out: what a quiet moment must show.
    pub fn balanced(&self) -> bool {
        self.rx_posted + self.rx_ready == RX_BUFFERS
            && self.rx_free_descriptors as usize == QUEUE_SIZE as usize - self.rx_posted
            && self.tx_in_flight == 0
            && self.tx_free_descriptors == QUEUE_SIZE
    }
}

struct RxBuffer {
    buf: Dma,
    /// The head descriptor while the buffer is with the device.
    head: Option<u16>,
}

struct TxSlot {
    buf: Dma,
    head: Option<u16>,
}

struct Inner {
    rx_ring: Ring,
    tx_ring: Ring,
    rx: [RxBuffer; RX_BUFFERS],
    tx: [TxSlot; TX_SLOTS],
    /// Ready receive buffers in the order they completed, with each frame's length: a ring
    /// of `ready_len` entries starting at `ready_head`.
    ready: [(usize, usize); RX_BUFFERS],
    ready_head: usize,
    ready_len: usize,
    interrupt_driven: bool,
    rx_frames: u64,
    tx_frames: u64,
    tx_completed: u64,
    rx_dropped: u64,
    interrupts: u64,
    rx_by_interrupt: u64,
    rx_polled: u64,
}

impl Inner {
    /// Give receive buffer `i` to the device. Returns whether the device wants to be told.
    fn post(&mut self, i: usize) -> bool {
        let Some(rx) = self.rx.get(i) else {
            return false;
        };
        let chain = [Buf {
            phys: rx.buf.phys(),
            len: BUFFER_BYTES as u32,
            device_writes: true,
        }];
        match self.rx_ring.add(&chain) {
            Ok(head) => {
                self.rx[i].head = Some(head);
                self.rx_ring.notify_wanted()
            }
            // Every buffer has a descriptor of its own, so the queue cannot be full while a
            // buffer is off it. A refusal would be a driver bug, and the buffer is simply
            // not posted; the books then show it missing.
            Err(_) => false,
        }
    }

    /// Collect finished receive buffers. Returns how many completed, and whether a buffer
    /// posted again on the way wants the device told.
    fn drain_rx(&mut self) -> (u64, bool) {
        let mut taken = 0;
        let mut notify = false;
        for _ in 0..self.rx_ring.size() {
            let Some(used) = self.rx_ring.poll_used() else {
                break;
            };
            taken += 1;
            // Matched by head descriptor: a device that names a buffer it was not given
            // completes nothing.
            let Some(i) = self.rx.iter().position(|b| b.head == Some(used.head)) else {
                continue;
            };
            self.rx[i].head = None;
            let len = used.len as usize;
            if len < HEADER_BYTES + FRAME_MIN || len > BUFFER_BYTES || self.ready_len == RX_BUFFERS
            {
                self.rx_dropped += 1;
                notify |= self.post(i);
                continue;
            }
            let slot = (self.ready_head + self.ready_len) % RX_BUFFERS;
            self.ready[slot] = (i, len - HEADER_BYTES);
            self.ready_len += 1;
        }
        (taken, notify)
    }

    /// Collect finished transmissions, freeing their slots.
    fn drain_tx(&mut self) {
        for _ in 0..self.tx_ring.size() {
            let Some(used) = self.tx_ring.poll_used() else {
                break;
            };
            if let Some(slot) = self.tx.iter_mut().find(|s| s.head == Some(used.head)) {
                slot.head = None;
                self.tx_completed += 1;
            }
        }
    }

    fn pop_ready(&mut self) -> Option<(usize, usize)> {
        if self.ready_len == 0 {
            return None;
        }
        let entry = self.ready[self.ready_head];
        self.ready_head = (self.ready_head + 1) % RX_BUFFERS;
        self.ready_len -= 1;
        Some(entry)
    }
}

/// A started virtio network card.
///
/// Generic over the lock family, as every driver that must build for a machine without
/// compare-and-swap is.
pub struct VirtioNet<L: LockFamily, T: Transport = AnyTransport> {
    transport: T,
    mac: [u8; 6],
    inner: L::Lock<Inner>,
    /// Whether both queues signal on an MSI-X vector, in which case the device does not set
    /// the interrupt status register for them and [`Self::on_interrupt`] must not ask.
    msix: bool,
}

/// The lock class of a card's queues, for the lock-order checker.
pub static NET_LOCK: LockClass = LockClass::new("driver.virtio-net");

impl<L: LockFamily, T: Transport> VirtioNet<L, T> {
    /// Bring a card up: the handshake, both queues, the address, and every receive buffer
    /// posted.
    pub fn bring_up(transport: T, dma: Dma) -> Result<VirtioNet<L, T>, Error> {
        Self::bring_up_with_vector(transport, dma, None)
    }

    /// [`Self::bring_up`], with both queues' interrupts on MSI-X table entry `vector` when it
    /// is `Some`, as virtio-blk's `bring_up_with_vector` does for its one queue.
    ///
    /// One vector for both queues: the handler drains both whichever finished. None for
    /// configuration changes, which the driver never reads after bring-up. Written after
    /// `negotiate`'s reset, which forgets it, before the queues are enabled, and read back:
    /// a queue that silently kept no vector would never interrupt, so a refusal fails
    /// bring-up with [`Error::VectorRefused`].
    pub fn bring_up_with_vector(
        transport: T,
        mut dma: Dma,
        vector: Option<u16>,
    ) -> Result<VirtioNet<L, T>, Error> {
        let accepted = transport::negotiate(
            &transport,
            transport::DEVICE_ID_NET,
            [F_MAC, transport::VERSION_1_BIT],
        )?;

        transport.set_config_vector(transport::NO_VECTOR);
        if let Some(v) = vector {
            for queue in [RX_QUEUE, TX_QUEUE] {
                if transport.set_queue_vector(queue, v) != v {
                    transport.set_status(transport::status::FAILED);
                    return Err(Error::VectorRefused { queue });
                }
            }
        }

        let rx_ring = transport::carve_ring(&mut dma, QUEUE_SIZE)?;
        let tx_ring = transport::carve_ring(&mut dma, QUEUE_SIZE)?;
        transport::setup_queue(&transport, RX_QUEUE, &rx_ring)?;
        transport::setup_queue(&transport, TX_QUEUE, &tx_ring)?;

        let mut rx = [const { None }; RX_BUFFERS];
        for slot in rx.iter_mut() {
            *slot = Some(RxBuffer {
                buf: dma.take(BUFFER_BYTES, 16).ok_or(Error::NoRoom)?,
                head: None,
            });
        }
        let mut tx = [const { None }; TX_SLOTS];
        for slot in tx.iter_mut() {
            *slot = Some(TxSlot {
                buf: dma.take(BUFFER_BYTES, 16).ok_or(Error::NoRoom)?,
                head: None,
            });
        }
        let rx = rx.map(|s| s.expect("every receive buffer was carved above"));
        let tx = tx.map(|s| s.expect("every transmit slot was carved above"));

        // The address is only in the configuration when the feature was accepted.
        let mac = if accepted[0] & F_MAC != 0 {
            core::array::from_fn(|i| transport.config_read8(CFG_MAC + i))
        } else {
            FALLBACK_MAC
        };

        transport::finish(&transport)?;

        let mut inner = Inner {
            rx_ring,
            tx_ring,
            rx,
            tx,
            ready: [(0, 0); RX_BUFFERS],
            ready_head: 0,
            ready_len: 0,
            interrupt_driven: false,
            rx_frames: 0,
            tx_frames: 0,
            tx_completed: 0,
            rx_dropped: 0,
            interrupts: 0,
            rx_by_interrupt: 0,
            rx_polled: 0,
        };
        for i in 0..RX_BUFFERS {
            inner.post(i);
        }
        // A device may not look at a queue it was never told about.
        transport.notify(RX_QUEUE);

        Ok(VirtioNet {
            transport,
            mac,
            inner: L::new(inner, &NET_LOCK),
            msix: vector.is_some(),
        })
    }

    /// The card's hardware address.
    pub fn mac(&self) -> [u8; 6] {
        self.mac
    }

    /// Whether the queues were given an MSI-X vector at bring-up.
    pub fn uses_msix(&self) -> bool {
        self.msix
    }
    /// Queue a frame for transmission. Does not wait for the device to send it.
    pub fn send(&self, frame: &[u8]) -> Result<(), SendError> {
        if frame.len() > FRAME_MAX || frame.len() < FRAME_MIN {
            return Err(SendError::BadLength);
        }
        let notify = L::with(&self.inner, |inner| {
            inner.drain_tx();
            let slot = inner
                .tx
                .iter()
                .position(|s| s.head.is_none())
                .ok_or(SendError::Full)?;
            let buf = &inner.tx[slot].buf;
            // A zero header: no checksum offload, no segmentation, one buffer.
            if !buf.write_bytes(0, &[0u8; HEADER_BYTES]) || !buf.write_bytes(HEADER_BYTES, frame) {
                return Err(SendError::BadLength);
            }
            let chain = [Buf {
                phys: buf.phys(),
                len: (HEADER_BYTES + frame.len()) as u32,
                device_writes: false,
            }];
            let head = inner.tx_ring.add(&chain).map_err(|_| SendError::Full)?;
            inner.tx[slot].head = Some(head);
            inner.tx_frames += 1;
            Ok(inner.tx_ring.notify_wanted())
        })?;
        if notify {
            self.transport.notify(TX_QUEUE);
        }
        Ok(())
    }

    /// Copy the oldest received frame into `into`, returning its length, or `None` when no
    /// frame is waiting. A frame larger than `into` is dropped and counted.
    pub fn recv(&self, into: &mut [u8]) -> Option<usize> {
        let (got, notify) = L::with(&self.inner, |inner| {
            let mut notify = false;
            if !inner.interrupt_driven {
                let (taken, wanted) = inner.drain_rx();
                inner.rx_polled += taken;
                notify = wanted;
            }
            // Bounded by the buffers: each pass takes one ready frame.
            for _ in 0..RX_BUFFERS {
                let Some((i, len)) = inner.pop_ready() else {
                    break;
                };
                let fits =
                    len <= into.len() && inner.rx[i].buf.read_bytes(HEADER_BYTES, &mut into[..len]);
                notify |= inner.post(i);
                if fits {
                    inner.rx_frames += 1;
                    return (Some(len), notify);
                }
                inner.rx_dropped += 1;
            }
            (None, notify)
        });
        if notify {
            self.transport.notify(RX_QUEUE);
        }
        got
    }

    /// Acknowledge the card's interrupt and collect what it finished on both queues.
    /// Returns whether the interrupt was this card's.
    ///
    /// On an MSI-X vector there is nothing to acknowledge: the vector is this card's alone,
    /// and the device does not set the status register for a queue interrupt delivered that
    /// way (virtio 1.1 §4.1.4.5), so reading it would throw the interrupt away.
    pub fn on_interrupt(&self) -> bool {
        if !self.msix && self.transport.ack_interrupt() == 0 {
            return false;
        }
        let notify = L::with(&self.inner, |inner| {
            let (taken, notify) = inner.drain_rx();
            inner.rx_by_interrupt += taken;
            inner.drain_tx();
            inner.interrupts += 1;
            notify
        });
        if notify {
            self.transport.notify(RX_QUEUE);
        }
        true
    }

    /// Collect receive completions only in the interrupt handler, never in [`recv`](Self::recv).
    pub fn set_interrupt_driven(&self, on: bool) {
        L::with(&self.inner, |inner| inner.interrupt_driven = on);
    }

    /// Collect finished transmissions now, so the books describe the device's state rather
    /// than the last time something drained the queue.
    pub fn settle(&self) {
        L::with(&self.inner, |inner| inner.drain_tx());
    }

    pub fn counters(&self) -> Counters {
        L::with(&self.inner, |inner| Counters {
            rx_frames: inner.rx_frames,
            tx_frames: inner.tx_frames,
            tx_completed: inner.tx_completed,
            tx_in_flight: inner.tx.iter().filter(|s| s.head.is_some()).count(),
            rx_posted: inner.rx.iter().filter(|b| b.head.is_some()).count(),
            rx_ready: inner.ready_len,
            rx_dropped: inner.rx_dropped,
            interrupts: inner.interrupts,
            rx_by_interrupt: inner.rx_by_interrupt,
            rx_polled: inner.rx_polled,
            rx_free_descriptors: inner.rx_ring.free_descriptors(),
            tx_free_descriptors: inner.tx_ring.free_descriptors(),
        })
    }
}

impl<L: LockFamily, T: Transport> net::Nic for VirtioNet<L, T> {
    fn mac(&self) -> net::Mac {
        self.mac
    }

    fn send(&self, frame: &[u8]) -> Result<(), net::NicError> {
        VirtioNet::send(self, frame).map_err(|_| net::NicError)
    }

    fn recv(&self, into: &mut [u8]) -> Option<usize> {
        VirtioNet::recv(self, into)
    }
}

static CLAIMS: BootCell<Claims> = BootCell::new();

/// The window the bound card claimed, as a physical `(address, length)`.
pub fn window() -> Option<(u64, u64)> {
    CLAIMS.get().map(Claims::window)
}

/// Whether an interrupt line was claimed for the card.
pub fn has_irq() -> bool {
    CLAIMS.get().is_some_and(|c| c.irq().is_some())
}

/// The MSI-X table entry the card's interrupt was claimed as, if it was one: what
/// [`VirtioNet::bring_up_with_vector`] is given once the platform has wired it.
pub fn msix_entry() -> Option<u16> {
    CLAIMS.get()?.msix_entry()
}

/// The transport for the bound card.
///
/// # Safety
/// As [`Claims::transport`]: the window mapped at its physical address, and called once.
#[allow(unsafe_code)]
pub unsafe fn transport() -> Option<AnyTransport> {
    // SAFETY: the caller's contract is this function's.
    unsafe { CLAIMS.get()?.transport() }
}

pub struct VirtioNetDriver;

pub static DRIVER: VirtioNetDriver = VirtioNetDriver;

#[allow(unsafe_code)]
impl Driver for VirtioNetDriver {
    fn name(&self) -> &'static str {
        "virtio-net"
    }

    fn compatible(&self) -> &'static [&'static str] {
        COMPATIBLE
    }

    fn probe(&self, p: &mut Probe<'_, '_, '_, '_>) -> Result<(), ProbeError> {
        // An MSI-X vector where the platform delivers messages, otherwise a line; see
        // `virtio::bind`.
        let claims = Claims::claim(
            p,
            "virtio-net registers",
            "virtio-net MSI-X table",
            transport::DEVICE_ID_NET,
        )?;
        // SAFETY: probe runs during single-threaded boot.
        unsafe { CLAIMS.set(claims) }
            .map(|_| ())
            .map_err(|_| ProbeError::Declined("one virtio-net device is supported"))
    }

    fn start(&self, _bound: &Bound) -> Result<(), &'static str> {
        // Nothing: the card is untouched until the kernel has memory to give it.
        Ok(())
    }

    fn interrupt(&self, _bound: &Bound) -> Option<(&'static IrqLine, fn())> {
        // One card: the probe declines a second, so the claims are this device's.
        let irq = CLAIMS.get()?.irq()?;
        Some((irq, on_device_interrupt))
    }
}

/// The registered handler: drain whichever card this kernel brought up.
fn on_device_interrupt() {
    if let Some(handler) = HANDLER.get() {
        handler();
    }
}

static HANDLER: BootCell<fn()> = BootCell::new();

/// Install the function the card's interrupt runs.
///
/// # Safety
/// Once, on the boot path, before the line is enabled.
#[allow(unsafe_code)]
pub unsafe fn set_handler(handler: fn()) -> bool {
    // SAFETY: the caller's contract.
    unsafe { HANDLER.set(handler) }.is_ok()
}

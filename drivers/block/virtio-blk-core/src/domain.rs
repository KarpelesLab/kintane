//! What the kernel and a driver domain hosting this driver say to each other.
//!
//! A domain runs [`crate::Engine`] over a grant; the kernel's block layer is its client. They
//! share three things, and this module is their one definition, so neither side can lay a
//! field out differently from the other:
//!
//! * [`Setup`] — where the kernel put the grant, written on a page the domain reads once at start:
//!   the register window, the DMA buffer, the page requests' data moves through, and the PCI
//!   layout the kernel read from configuration space (which the domain cannot reach).
//! * [`Request`] and [`Reply`] — one block request and its answer, as channel messages. A message is
//!   at most 64 bytes, so data does not travel in it: it moves through the shared data pages.
//! * [`Interrupt`] — the device's interrupt, as a message the kernel forwards: how many have been
//!   taken since the domain started, and when the latest was.
//!
//! Every number here was chosen by the kernel or reported by the device. The kernel checks
//! what comes back from a domain as it would anything else from an unprivileged program:
//! lengths are bounded by what it granted, never by what the domain says.

use virtio::pci::{Layout, Place};

/// Bytes [`Setup::encode`] writes.
pub const SETUP_BYTES: usize = 128;
/// Bytes of a [`Request`] message.
pub const REQUEST_BYTES: usize = 24;
/// Bytes of a [`Reply`] message.
pub const REPLY_BYTES: usize = 64;
/// Bytes of an [`Interrupt`] message.
pub const INTERRUPT_BYTES: usize = 16;

/// Where the kernel placed the grant in the domain's address space, and what the device is.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Setup {
    /// The address the register window is mapped at, and the device's length.
    pub window: u64,
    pub window_len: u64,
    /// The DMA buffer: where the domain reaches it, the address the device uses, its length.
    pub dma_virt: u64,
    pub dma_phys: u64,
    pub dma_len: u64,
    /// The pages a request's data moves through, shared with the kernel.
    pub data_virt: u64,
    pub data_len: u64,
    /// The MSI-X table entry the request queue signals on, or [`NO_VECTOR`].
    pub vector: u16,
    /// The BAR every structure is in, and the PCI device ID.
    pub bar: u8,
    pub device_id: u32,
    pub layout: Layout,
}

/// No MSI-X entry: a device the domain would have to poll, which this host refuses.
pub const NO_VECTOR: u16 = 0xffff;

impl Setup {
    pub fn encode(&self) -> [u8; SETUP_BYTES] {
        let mut out = [0u8; SETUP_BYTES];
        let mut w = Writer::new(&mut out);
        for v in [
            self.window,
            self.window_len,
            self.dma_virt,
            self.dma_phys,
            self.dma_len,
            self.data_virt,
            self.data_len,
        ] {
            w.u64(v);
        }
        w.u16(self.vector);
        w.u8(self.bar);
        w.u8(0);
        w.u32(self.device_id);
        for p in places(&self.layout) {
            w.u8(p.bar);
            w.u8(0);
            w.u16(0);
            w.u32(p.offset);
            w.u32(p.length);
        }
        w.u32(self.layout.notify_multiplier);
        out
    }

    /// The setup `bytes` describe, if they are long enough to hold one.
    pub fn decode(bytes: &[u8]) -> Option<Setup> {
        let mut r = Reader::new(bytes.get(..SETUP_BYTES)?);
        let window = r.u64();
        let window_len = r.u64();
        let dma_virt = r.u64();
        let dma_phys = r.u64();
        let dma_len = r.u64();
        let data_virt = r.u64();
        let data_len = r.u64();
        let vector = r.u16();
        let bar = r.u8();
        let _ = r.u8();
        let device_id = r.u32();
        let mut place = || {
            let bar = r.u8();
            let _ = (r.u8(), r.u16());
            Place {
                bar,
                offset: r.u32(),
                length: r.u32(),
            }
        };
        let (common, notify, isr, device) = (place(), place(), place(), place());
        let notify_multiplier = r.u32();
        Some(Setup {
            window,
            window_len,
            dma_virt,
            dma_phys,
            dma_len,
            data_virt,
            data_len,
            vector,
            bar,
            device_id,
            layout: Layout {
                common,
                notify,
                isr,
                device,
                notify_multiplier,
            },
        })
    }
}

fn places(l: &Layout) -> [Place; 4] {
    [l.common, l.notify, l.isr, l.device]
}

/// What a request asks the domain to do.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u32)]
pub enum Op {
    /// Read `blocks` at `lba` into the data pages.
    Read = 1,
    /// Write `blocks` at `lba` from the data pages.
    Write = 2,
    Flush = 3,
    /// Read `blocks` at the device's capacity, skipping the range check: the device's own
    /// refusal, as the in-kernel host's `read_past_end_unchecked` asks for it.
    ReadPastEnd = 4,
    /// Point the device at a read into device address `addr`, outside the grant. A driver
    /// never does this; a check does, to prove the IOMMU stops a domain that tries.
    RogueDma = 5,
    /// Touch memory outside every grant. The kernel expects to kill the domain for it.
    Fault = 6,
    /// Reply, then exit.
    Stop = 7,
}

impl Op {
    fn from_raw(raw: u32) -> Option<Op> {
        [
            Op::Read,
            Op::Write,
            Op::Flush,
            Op::ReadPastEnd,
            Op::RogueDma,
            Op::Fault,
            Op::Stop,
        ]
        .into_iter()
        .find(|op| *op as u32 == raw)
    }
}

/// One request, kernel to domain.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Request {
    pub op: Op,
    pub blocks: u32,
    pub lba: u64,
    /// Only for [`Op::RogueDma`]: the device address to aim at.
    pub addr: u64,
}

impl Request {
    pub fn encode(&self) -> [u8; REQUEST_BYTES] {
        let mut out = [0u8; REQUEST_BYTES];
        let mut w = Writer::new(&mut out);
        w.u32(self.op as u32);
        w.u32(self.blocks);
        w.u64(self.lba);
        w.u64(self.addr);
        out
    }

    pub fn decode(bytes: &[u8]) -> Option<Request> {
        let mut r = Reader::new(bytes.get(..REQUEST_BYTES)?);
        Some(Request {
            op: Op::from_raw(r.u32())?,
            blocks: r.u32(),
            lba: r.u64(),
            addr: r.u64(),
        })
    }
}

/// How a request ended, as a reply's status.
pub mod status {
    pub const OK: u32 = 0;
    /// The device finished it with a status byte that is not OK; the byte is the detail.
    pub const DEVICE: u32 = 1;
    /// The interrupt announcing its completion never arrived.
    pub const TIMEOUT: u32 = 2;
    /// Blocks past the end, or not a whole number of them.
    pub const RANGE: u32 = 3;
    /// More than a request's bounce buffer, or the data pages, hold.
    pub const TOO_LARGE: u32 = 4;
    /// Every slot or the ring is taken.
    pub const NO_ROOM: u32 = 5;
    /// A write to a read-only device.
    pub const READ_ONLY: u32 = 6;
    /// A message that is not a request, or a chain the queue cannot take.
    pub const BAD_REQUEST: u32 = 7;
    /// The first reply of a domain whose bring-up failed; the detail says which step.
    pub const BRING_UP_FAILED: u32 = 8;
    /// The first reply of a domain whose device is up; the reply carries its [`Facts`].
    pub const READY: u32 = 9;
    /// The rogue DMA's request completed. Behind an IOMMU that confines the device, it
    /// must not have.
    pub const COMPLETED: u32 = 10;
    /// The rogue DMA's request did not complete in the time allowed.
    pub const NOT_COMPLETED: u32 = 11;
}

/// A domain's answer to one request, with its running counts.
///
/// The counts ride on every reply rather than on a separate call, so the kernel always has
/// the latest without asking, and a check of "every completion arrived by interrupt" reads
/// numbers from the same moment as the request it follows.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Reply {
    pub status: u32,
    pub detail: u32,
    /// Interrupt messages received.
    pub messages: u64,
    /// Requests published to the device.
    pub submitted: u64,
    /// Completions collected, every one of them after an interrupt message: the domain
    /// never drains the ring on its own.
    pub completions: u64,
    /// Nanoseconds from the kernel's handler to the domain receiving the message, summed
    /// over `messages`, and the longest.
    pub latency_total: u64,
    pub latency_max: u32,
    /// Whether every descriptor is back on the ring's free list.
    pub clean: bool,
}

impl Reply {
    pub fn encode(&self) -> [u8; REPLY_BYTES] {
        let mut out = [0u8; REPLY_BYTES];
        let mut w = Writer::new(&mut out);
        w.u32(self.status);
        w.u32(self.detail);
        w.u64(self.messages);
        w.u64(self.submitted);
        w.u64(self.completions);
        w.u64(self.latency_total);
        w.u32(self.latency_max);
        w.u32(u32::from(self.clean));
        out
    }

    /// Bytes [`Reply::encode`] fills: status and detail (u32), three counts and a latency
    /// total (u64), the worst latency and the clean flag (u32).
    const ENCODED: usize = 4 + 4 + 8 + 8 + 8 + 8 + 4 + 4;

    pub fn decode(bytes: &[u8]) -> Option<Reply> {
        let mut r = Reader::new(bytes.get(..Self::ENCODED)?);
        Some(Reply {
            status: r.u32(),
            detail: r.u32(),
            messages: r.u64(),
            submitted: r.u64(),
            completions: r.u64(),
            latency_total: r.u64(),
            latency_max: r.u32(),
            clean: r.u32() != 0,
        })
    }
}

/// What a domain's bring-up learned, in its [`status::READY`] reply, in place of the counts.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Facts {
    pub block_size: u32,
    pub capacity: u64,
    pub max_transfer: u64,
    pub read_only: bool,
    pub flush_supported: bool,
    pub platform_iommu: bool,
    pub uses_msix: bool,
}

impl Facts {
    /// The ready reply carrying these facts.
    pub fn encode(&self) -> [u8; REPLY_BYTES] {
        let mut out = [0u8; REPLY_BYTES];
        let mut w = Writer::new(&mut out);
        w.u32(status::READY);
        w.u32(self.block_size);
        w.u64(self.capacity);
        w.u64(self.max_transfer);
        let flags = u32::from(self.read_only)
            | u32::from(self.flush_supported) << 1
            | u32::from(self.platform_iommu) << 2
            | u32::from(self.uses_msix) << 3;
        w.u32(flags);
        out
    }

    /// The facts a ready reply carries; `None` for any other reply.
    pub fn decode(bytes: &[u8]) -> Option<Facts> {
        let mut r = Reader::new(bytes.get(..28)?);
        if r.u32() != status::READY {
            return None;
        }
        let block_size = r.u32();
        let capacity = r.u64();
        let max_transfer = r.u64();
        let flags = r.u32();
        Some(Facts {
            block_size,
            capacity,
            max_transfer,
            read_only: flags & 1 != 0,
            flush_supported: flags & 2 != 0,
            platform_iommu: flags & 4 != 0,
            uses_msix: flags & 8 != 0,
        })
    }
}

/// The device's interrupt, forwarded by the kernel.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Interrupt {
    /// Interrupts the kernel's handler has taken for this domain, all told. A message that
    /// could not be sent is never lost as information: the next one carries the total.
    pub count: u64,
    /// The kernel clock, in nanoseconds, when the handler took the latest.
    pub stamp: u64,
}

impl Interrupt {
    pub fn encode(&self) -> [u8; INTERRUPT_BYTES] {
        let mut out = [0u8; INTERRUPT_BYTES];
        let mut w = Writer::new(&mut out);
        w.u64(self.count);
        w.u64(self.stamp);
        out
    }

    pub fn decode(bytes: &[u8]) -> Option<Interrupt> {
        let mut r = Reader::new(bytes.get(..INTERRUPT_BYTES)?);
        Some(Interrupt {
            count: r.u64(),
            stamp: r.u64(),
        })
    }
}

/// Little-endian fields, front to back, into a buffer sized for them.
struct Writer<'a> {
    out: &'a mut [u8],
    at: usize,
}

impl<'a> Writer<'a> {
    fn new(out: &'a mut [u8]) -> Writer<'a> {
        Writer { out, at: 0 }
    }
    fn put(&mut self, bytes: &[u8]) {
        if let Some(dst) = self.out.get_mut(self.at..self.at + bytes.len()) {
            dst.copy_from_slice(bytes);
        }
        self.at += bytes.len();
    }
    fn u8(&mut self, v: u8) {
        self.put(&[v]);
    }
    fn u16(&mut self, v: u16) {
        self.put(&v.to_le_bytes());
    }
    fn u32(&mut self, v: u32) {
        self.put(&v.to_le_bytes());
    }
    fn u64(&mut self, v: u64) {
        self.put(&v.to_le_bytes());
    }
}

/// Little-endian fields, front to back. The caller has checked the length, so a read past
/// the end cannot happen; it would read zeroes rather than panic if it did.
struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Reader<'a> {
        Reader { bytes, at: 0 }
    }
    fn take<const N: usize>(&mut self) -> [u8; N] {
        let mut out = [0u8; N];
        if let Some(src) = self.bytes.get(self.at..self.at + N) {
            out.copy_from_slice(src);
        }
        self.at += N;
        out
    }
    fn u8(&mut self) -> u8 {
        self.take::<1>()[0]
    }
    fn u16(&mut self) -> u16 {
        u16::from_le_bytes(self.take())
    }
    fn u32(&mut self) -> u32 {
        u32::from_le_bytes(self.take())
    }
    fn u64(&mut self) -> u64 {
        u64::from_le_bytes(self.take())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn layout() -> Layout {
        let p = |bar, offset, length| Place {
            bar,
            offset,
            length,
        };
        Layout {
            common: p(4, 0, 0x38),
            notify: p(4, 0x3000, 0x1000),
            isr: p(4, 0x1000, 0x1000),
            device: p(4, 0x2000, 0x1000),
            notify_multiplier: 4,
        }
    }

    #[test]
    fn setup_round_trips() {
        let s = Setup {
            window: 0x80_6000_0000,
            window_len: 0x4000,
            dma_virt: 0x80_6010_0000,
            dma_phys: 0x25_8000,
            dma_len: 0x8000,
            data_virt: 0x80_6020_1000,
            data_len: 0x3000,
            vector: 0,
            bar: 4,
            device_id: 2,
            layout: layout(),
        };
        let bytes = s.encode();
        assert_eq!(Setup::decode(&bytes), Some(s));
        assert_eq!(Setup::decode(&bytes[..SETUP_BYTES - 1]), None);
    }

    #[test]
    fn requests_round_trip_and_an_unknown_op_is_refused() {
        for op in [
            Op::Read,
            Op::Write,
            Op::Flush,
            Op::ReadPastEnd,
            Op::RogueDma,
            Op::Fault,
            Op::Stop,
        ] {
            let r = Request {
                op,
                blocks: 15,
                lba: 4096,
                addr: 0x26_0000,
            };
            assert_eq!(Request::decode(&r.encode()), Some(r));
        }
        let mut bad = Request {
            op: Op::Read,
            blocks: 1,
            lba: 0,
            addr: 0,
        }
        .encode();
        bad[0] = 0x7f;
        assert_eq!(Request::decode(&bad), None);
        assert_eq!(Request::decode(&bad[..4]), None);
    }

    #[test]
    fn replies_and_facts_round_trip_and_are_told_apart() {
        let r = Reply {
            status: status::DEVICE,
            detail: 1,
            messages: 33,
            submitted: 34,
            completions: 34,
            latency_total: 1_234_567,
            latency_max: 99_000,
            clean: true,
        };
        assert_eq!(Reply::decode(&r.encode()), Some(r));
        assert_eq!(Facts::decode(&r.encode()), None);

        let f = Facts {
            block_size: 512,
            capacity: 12544,
            max_transfer: 15,
            read_only: false,
            flush_supported: true,
            platform_iommu: true,
            uses_msix: true,
        };
        assert_eq!(Facts::decode(&f.encode()), Some(f));
    }

    #[test]
    fn interrupts_round_trip() {
        let i = Interrupt {
            count: 7,
            stamp: u64::MAX - 1,
        };
        assert_eq!(Interrupt::decode(&i.encode()), Some(i));
        assert_eq!(Interrupt::decode(&i.encode()[..8]), None);
    }
}

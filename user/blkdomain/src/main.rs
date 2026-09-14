//! The block driver domain: virtio-blk, running unprivileged, serving the kernel's block layer.
//!
//! The kernel's own host for this driver is `drivers/block/virtio-blk`. This program is the
//! other host for *the same protocol core*, `virtio_blk_core::Engine`, over a grant instead of
//! the kernel's mappings. Neither host speaks the protocol: the engine does, compiled once for
//! each.
//!
//! # What the kernel hands over
//!
//! Three argument registers:
//!
//! 1. a channel handle the kernel's block layer sends requests on and reads replies from,
//! 2. a channel handle the kernel forwards the device's interrupt on,
//! 3. the address of a page describing the grant ([`Setup`]).
//!
//! The grant itself is mappings the kernel made before entering this program: the device's
//! register window, its DMA buffer (which the IOMMU maps for the device and nothing else), and
//! the pages a request's data moves through. There is no call that maps a physical address,
//! so those are all the hardware this program can reach.
//!
//! # Interrupts are messages
//!
//! The device's MSI-X interrupt is taken by the kernel, which forwards it as a message.
//! [`Messages`] is this program's [`hwproxy::Irq`]: it counts the messages. A waiting request
//! drains the used ring only after a message has arrived since the last drain, and never on
//! its own, so every completion this program collects was announced by an interrupt the
//! kernel delivered. A request whose interrupt never arrives times out rather than being
//! polled into looking fine.

#![no_std]
#![no_main]
// The grant arrives as addresses in registers and on a page: turning them into accesses is
// what needs `unsafe` here, and the kernel's mappings are the promise behind each.
#![allow(unsafe_code)]

use core::cell::Cell;

use abi::{Handle, UserPtr, call};
use hwproxy::{Buffer, Direct, Irq, Regs};
use virtio::pci::Pci;
use virtio_blk_core::domain::{
    self, Facts, INTERRUPT_BYTES, Interrupt, Op, REPLY_BYTES, Reply, Request, Setup, status,
};
use virtio_blk_core::engine::{self, RequestError, SubmitError, status_byte};
use virtio_blk_core::mem::Dma;
use virtio_blk_core::transport::Error as BringUpError;
use virtio_blk_core::{Engine, PROTOCOL_SECTOR};

/// Stopped when asked.
const STOPPED: u64 = 0x2a;
/// The setup page did not hold a setup.
const BAD_SETUP: u64 = 0x5301;
/// The access outside every grant *returned*. Reaching this exit is the failure: the kernel
/// is waiting to be told this program was killed.
const NOT_STOPPED: u64 = 0x5302;
/// A channel the kernel gave this program stopped answering.
const CHANNEL_GONE: u64 = 0x5303;
/// The device did not come up; the first reply said why.
const BRING_UP_FAILED: u64 = 0x5304;

/// How long a request waits for the interrupt announcing its completion. Far above what a
/// served request takes, and finite, so a lost interrupt is a reply the kernel can report.
const IRQ_WAIT_NS: u64 = 2_000_000_000;
/// How long the rogue DMA waits. A blocked DMA never completes, so this only bounds it.
const ROGUE_WAIT_NS: u64 = 300_000_000;

const PAGE: usize = 4096;

#[unsafe(no_mangle)]
#[unsafe(link_section = ".text._start")]
pub extern "C" fn _start(requests: usize, interrupts: usize, setup: usize, _: usize) -> ! {
    exit(serve(Handle(requests as u32), Handle(interrupts as u32), setup))
}

/// Bring the device up over the grant, then serve requests until told to stop.
fn serve(requests: Handle, interrupts: Handle, setup_page: usize) -> u64 {
    let mut raw = [0u8; domain::SETUP_BYTES];
    for (i, b) in raw.iter_mut().enumerate() {
        // SAFETY: the kernel mapped a page at `setup_page` and wrote the setup on it before
        // entering this program; `SETUP_BYTES` is less than a page. Volatile, because the
        // writer was another address space.
        *b = unsafe { (setup_page as *const u8).add(i).read_volatile() };
    }
    let Some(setup) = Setup::decode(&raw) else {
        return BAD_SETUP;
    };
    // A device this host cannot hear from would be polled, and polling is exactly what this
    // host exists not to do.
    if setup.vector == domain::NO_VECTOR {
        send(requests, &failed(1));
        return BRING_UP_FAILED;
    }
    // SAFETY: the kernel mapped the granted register window at `window` for at least
    // `window_len` bytes, as device memory, and nothing else here maps it.
    let regs = unsafe { Direct::new(setup.window as usize, setup.window_len as usize) };
    let Ok(transport) = Pci::new(&setup.layout, setup.bar, regs, setup.device_id) else {
        send(requests, &failed(2));
        return BRING_UP_FAILED;
    };
    // SAFETY: the kernel mapped the DMA buffer at `dma_virt`, writable, backed by the
    // memory the device reaches at `dma_phys`, and this is the only region made over it.
    let grant = unsafe {
        Buffer::new(setup.dma_phys, setup.dma_virt as usize, setup.dma_len as usize)
    };
    // SAFETY: as above: the grant's addresses, with no other owner in this program.
    let dma = unsafe { Dma::from_proxy(&grant) };
    let engine = match Engine::bring_up(&transport, dma, Some(setup.vector)) {
        Ok(engine) => engine,
        Err(e) => {
            send(requests, &failed(bring_up_code(e)));
            return BRING_UP_FAILED;
        }
    };
    let f = engine.facts();
    let ready = Facts {
        block_size: f.block_size as u32,
        capacity: f.capacity,
        max_transfer: f.max_transfer,
        read_only: f.read_only,
        flush_supported: f.flush_supported,
        platform_iommu: f.platform_iommu,
        uses_msix: f.uses_msix,
    };
    if !send(requests, &ready.encode()) {
        return CHANNEL_GONE;
    }

    let mut host = Host {
        engine,
        transport,
        irq: Messages::new(interrupts),
        setup,
        submitted: 0,
        completions: 0,
    };
    loop {
        let mut msg = [0u8; 64];
        let got = match call::channel_recv(
            requests,
            UserPtr(msg.as_mut_ptr() as u64),
            msg.len(),
            UserPtr(0),
            0,
            u64::MAX,
        ) {
            Ok(v) => (v as u32 as usize).min(msg.len()),
            Err(_) => return CHANNEL_GONE,
        };
        let (st, detail) = match Request::decode(&msg[..got]) {
            None => (status::BAD_REQUEST, 0),
            Some(r) if r.op == Op::Stop => {
                send(requests, &host.reply(status::OK, 0).encode());
                return STOPPED;
            }
            Some(r) if r.op == Op::Fault => return fault(&host.setup),
            Some(r) => host.handle(r),
        };
        if !send(requests, &host.reply(st, detail).encode()) {
            return CHANNEL_GONE;
        }
    }
}

/// The driver, its transport, and what it has done.
struct Host {
    engine: Engine,
    transport: Pci<Direct>,
    irq: Messages,
    setup: Setup,
    submitted: u64,
    completions: u64,
}

impl Host {
    /// Serve one request, returning a reply's status and detail.
    fn handle(&mut self, r: Request) -> (u32, u32) {
        let facts = self.engine.facts();
        let len = (r.blocks as usize).saturating_mul(facts.block_size);
        if len > self.setup.data_len as usize {
            return (status::TOO_LARGE, 0);
        }
        // SAFETY: the kernel shares `data_len` bytes at `data_virt`, mapped writable, and
        // touches them only while this program waits for a request, so nothing writes them
        // while this slice is used. `len` is within them, checked above.
        let data = unsafe { core::slice::from_raw_parts_mut(self.setup.data_virt as *mut u8, len) };
        match r.op {
            Op::Read => match self.engine.range(r.lba, len) {
                Ok(blocks) => self.request(engine::Op::Read, r.lba, blocks, None, Some(data)),
                Err(e) => request_error(e),
            },
            Op::Write => match self.engine.range(r.lba, len) {
                Ok(_) if facts.read_only => (status::READ_ONLY, 0),
                Ok(blocks) => self.request(engine::Op::Write, r.lba, blocks, Some(data), None),
                Err(e) => request_error(e),
            },
            Op::Flush if !facts.flush_supported => (status::OK, 0),
            Op::Flush => self.request(engine::Op::Flush, 0, 0, None, None),
            // No range check, on purpose: the device's own refusal is what is being asked for.
            Op::ReadPastEnd if len != 0 => self.request(
                engine::Op::Read,
                facts.capacity,
                u64::from(r.blocks),
                None,
                Some(data),
            ),
            Op::RogueDma => self.rogue_dma(r.addr),
            _ => (status::BAD_REQUEST, 0),
        }
    }

    /// Publish a request and wait for it by interrupt.
    fn request(
        &mut self,
        op: engine::Op,
        lba: u64,
        blocks: u64,
        write_from: Option<&[u8]>,
        read_into: Option<&mut [u8]>,
    ) -> (u32, u32) {
        let slot = match self
            .engine
            .submit(&self.transport, op, lba, blocks, write_from)
        {
            Ok(slot) => slot,
            Err(e) => return submit_error(e),
        };
        self.submitted += 1;
        match self.wait(slot, IRQ_WAIT_NS) {
            Some(status_byte::OK) => {
                self.engine.finish(slot, read_into, false);
                (status::OK, 0)
            }
            Some(byte) => {
                self.engine.finish(slot, None, false);
                (status::DEVICE, u32::from(byte))
            }
            None => {
                // The chain is still the device's; see `Engine::finish`.
                self.engine.finish(slot, None, true);
                (status::TIMEOUT, 0)
            }
        }
    }

    /// Point the device at a read into `addr`, which the kernel says is outside the grant.
    ///
    /// Exactly what a driver that has turned hostile would do, and what the IOMMU must stop:
    /// this program's page tables do not map `addr` either, but the device does not use them.
    fn rogue_dma(&mut self, addr: u64) -> (u32, u32) {
        let slot = match self
            .engine
            .submit_raw_read(&self.transport, 0, addr, PROTOCOL_SECTOR as u32)
        {
            Ok(slot) => slot,
            Err(e) => return submit_error(e),
        };
        self.submitted += 1;
        match self.wait(slot, ROGUE_WAIT_NS) {
            Some(byte) => {
                self.engine.finish(slot, None, false);
                (status::COMPLETED, u32::from(byte))
            }
            None => {
                self.engine.finish(slot, None, true);
                (status::NOT_COMPLETED, 0)
            }
        }
    }

    /// Wait for `slot` to complete, draining the ring only after an interrupt message.
    /// The device's status byte, or `None` if no interrupt announced it within `wait_ns`.
    fn wait(&mut self, slot: usize, wait_ns: u64) -> Option<u8> {
        loop {
            let count = self.irq.count();
            if count > self.irq.acknowledged.get() {
                self.completions += u64::from(self.engine.drain());
                self.irq.acknowledge(count);
            }
            if let Some(byte) = self.engine.status_of(slot) {
                return Some(byte);
            }
            if !self.irq.receive(wait_ns) {
                return None;
            }
        }
    }

    fn reply(&self, status: u32, detail: u32) -> Reply {
        Reply {
            status,
            detail,
            messages: self.irq.received.get(),
            submitted: self.submitted,
            completions: self.completions,
            latency_total: self.irq.latency_total.get(),
            latency_max: self.irq.latency_max.get(),
            clean: self.engine.all_descriptors_free(),
        }
    }
}

/// The device's interrupt, as the messages the kernel forwards.
struct Messages {
    channel: Handle,
    /// The highest interrupt count a message has carried.
    count: Cell<u64>,
    /// The count the driver last handled.
    acknowledged: Cell<u64>,
    /// Messages received, and their delivery latency.
    received: Cell<u64>,
    latency_total: Cell<u64>,
    latency_max: Cell<u32>,
}

impl Messages {
    fn new(channel: Handle) -> Messages {
        Messages {
            channel,
            count: Cell::new(0),
            acknowledged: Cell::new(0),
            received: Cell::new(0),
            latency_total: Cell::new(0),
            latency_max: Cell::new(0),
        }
    }

    /// Take one message, waiting up to `timeout_ns` for it. Whether one arrived.
    fn receive(&self, timeout_ns: u64) -> bool {
        let mut buf = [0u8; INTERRUPT_BYTES];
        let Ok(got) = call::channel_recv(
            self.channel,
            UserPtr(buf.as_mut_ptr() as u64),
            buf.len(),
            UserPtr(0),
            0,
            timeout_ns,
        ) else {
            return false;
        };
        let Some(m) = Interrupt::decode(&buf[..(got as u32 as usize).min(buf.len())]) else {
            return false;
        };
        // Read as soon as the message is in hand: the kernel stamped the handler's time, and
        // this is the domain's side of the same clock.
        let now = call::clock_now().unwrap_or(m.stamp);
        let latency = now.saturating_sub(m.stamp);
        self.received.set(self.received.get() + 1);
        self.latency_total
            .set(self.latency_total.get().saturating_add(latency));
        self.latency_max
            .set(self.latency_max.get().max(u32::try_from(latency).unwrap_or(u32::MAX)));
        self.count.set(self.count.get().max(m.count));
        true
    }
}

impl Irq for Messages {
    /// Every message already queued is taken first, without waiting, so the count is the
    /// latest the kernel has sent.
    fn count(&self) -> u64 {
        while self.receive(0) {}
        self.count.get()
    }

    fn acknowledge(&self, count: u64) {
        self.acknowledged.set(count);
    }
}

/// Read the page after the register window: outside every grant, so the MMU must stop it.
///
/// The proxy's own bounds check would refuse this, so the window is rebuilt over the address
/// itself: what is under test is the host's containment, not this program's manners.
fn fault(setup: &Setup) -> u64 {
    let past = (setup.window as usize + setup.window_len as usize).next_multiple_of(PAGE);
    // SAFETY: none is being promised; this is the case the kernel must survive. If the read
    // ever succeeded, the value is discarded and the exit says the boundary did not hold.
    let outside = unsafe { Direct::new(past, 4) };
    core::hint::black_box(outside.read32(0));
    NOT_STOPPED
}

fn failed(step: u32) -> [u8; REPLY_BYTES] {
    Reply {
        status: status::BRING_UP_FAILED,
        detail: step,
        ..Reply::default()
    }
    .encode()
}

/// Which step of bring-up failed, as a reply's detail: 3 and up, after the host's own two.
fn bring_up_code(e: BringUpError) -> u32 {
    match e {
        BringUpError::NotVirtio => 3,
        BringUpError::Legacy => 4,
        BringUpError::WrongDevice { .. } => 5,
        BringUpError::FeaturesRefused => 6,
        BringUpError::Refused { .. } => 7,
        BringUpError::BadQueue { .. } => 8,
        BringUpError::NoRoom => 9,
        BringUpError::BadGeometry => 10,
        BringUpError::Timeout => 11,
        BringUpError::VectorRefused { .. } => 12,
    }
}

fn request_error(e: RequestError) -> (u32, u32) {
    match e {
        RequestError::OutOfRange | RequestError::Misaligned => (status::RANGE, 0),
        RequestError::ReadOnly => (status::READ_ONLY, 0),
        RequestError::Submit(e) => submit_error(e),
        RequestError::Device(byte) => (status::DEVICE, u32::from(byte)),
        RequestError::Timeout => (status::TIMEOUT, 0),
    }
}

fn submit_error(e: SubmitError) -> (u32, u32) {
    match e {
        SubmitError::NoRoom => (status::NO_ROOM, 0),
        SubmitError::TooLarge => (status::TOO_LARGE, 0),
        SubmitError::BadChain => (status::BAD_REQUEST, 0),
    }
}

fn send(channel: Handle, bytes: &[u8]) -> bool {
    call::channel_send(channel, UserPtr(bytes.as_ptr() as u64), bytes.len(), UserPtr(0), 0).is_ok()
}

fn exit(code: u64) -> ! {
    let _ = call::process_exit(code);
    // Unreachable unless the kernel returned from an exit, which its check sees as a domain
    // that never ended.
    loop {
        let _ = call::thread_yield();
    }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    exit(0xdead)
}

//! The driver against a card on the other side of both queues.
//!
//! [`FakeCard`] plays the registers and, through the shared fake device, both queues: it
//! learns the rings from queue setup, collects what the driver transmits, and writes frames
//! into the receive buffers the driver posted, raising an interrupt when it does.

use core::cell::{Cell, RefCell};
use std::collections::VecDeque;

use hal::mock::MockFull;
use sync::Spin;
use virtio::fake::{Backing, FakeDevice, SeenChain, View};
use virtio::transport::{self, Error, Transport, status};

use crate::{
    Counters, FALLBACK_MAC, FRAME_MAX, HEADER_BYTES, QUEUE_SIZE, RX_BUFFERS, SendError, TX_SLOTS,
    VirtioNet, dma_bytes,
};

const MAC: [u8; 6] = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
const F_MAC: u32 = 1 << 5;

struct FakeCard {
    view: View,
    device_id: u32,
    status: Cell<u8>,
    offered: [u32; 2],
    feature_sel: Cell<u32>,
    accepted: Cell<[u32; 2]>,
    rx: RefCell<Option<FakeDevice>>,
    tx: RefCell<Option<FakeDevice>>,
    /// Receive buffers the driver posted and the card has not filled yet.
    posted: RefCell<VecDeque<SeenChain>>,
    /// Frames the driver sent, header stripped.
    sent: RefCell<Vec<Vec<u8>>>,
    pending: Cell<u32>,
    notifies: Cell<u32>,
    /// Complete a transmission as soon as it is published.
    complete_tx: Cell<bool>,
}

impl FakeCard {
    fn new(backing: &Backing) -> FakeCard {
        FakeCard {
            view: backing.view(),
            device_id: transport::DEVICE_ID_NET,
            status: Cell::new(0),
            offered: [F_MAC, transport::VERSION_1_BIT],
            feature_sel: Cell::new(0),
            accepted: Cell::new([0, 0]),
            rx: RefCell::new(None),
            tx: RefCell::new(None),
            posted: RefCell::new(VecDeque::new()),
            sent: RefCell::new(Vec::new()),
            pending: Cell::new(0),
            notifies: Cell::new(0),
            complete_tx: Cell::new(true),
        }
    }

    /// Take every receive buffer the driver has made available.
    fn collect_posted(&self) {
        let mut rx = self.rx.borrow_mut();
        let Some(dev) = rx.as_mut() else { return };
        while let Some(chain) = dev.take_available() {
            self.posted.borrow_mut().push_back(chain);
        }
    }

    /// Write `frame` into a posted receive buffer and complete it, reporting `claimed` bytes.
    fn deliver_claiming(&self, frame: &[u8], claimed: u32) -> bool {
        self.collect_posted();
        let Some(chain) = self.posted.borrow_mut().pop_front() else {
            return false;
        };
        let buf = chain.buffers[0];
        assert!(buf.device_writes, "a receive buffer is the device's to write");
        assert!(
            buf.len as usize >= HEADER_BYTES + FRAME_MAX,
            "a receive buffer holds a whole frame"
        );
        let mut rx = self.rx.borrow_mut();
        let dev = rx.as_mut().expect("the receive queue is set up");
        let region = dev.region(buf.phys, buf.len as usize);
        region.write_bytes(0, &[0u8; HEADER_BYTES]);
        region.write_bytes(HEADER_BYTES, frame);
        dev.complete(chain.head, claimed);
        self.pending.set(1);
        true
    }

    fn deliver(&self, frame: &[u8]) -> bool {
        self.deliver_claiming(frame, (HEADER_BYTES + frame.len()) as u32)
    }

    /// Collect and complete what the driver published for transmission.
    fn serve_tx(&self) {
        let mut tx = self.tx.borrow_mut();
        let Some(dev) = tx.as_mut() else { return };
        while let Some(chain) = dev.take_available() {
            assert_eq!(chain.buffers.len(), 1, "one buffer per frame");
            let buf = chain.buffers[0];
            assert!(!buf.device_writes, "the device reads a frame it sends");
            let region = dev.region(buf.phys, buf.len as usize);
            let mut bytes = vec![0u8; buf.len as usize];
            region.read_bytes(0, &mut bytes);
            assert_eq!(&bytes[..HEADER_BYTES], &[0u8; HEADER_BYTES], "a zero header");
            self.sent.borrow_mut().push(bytes[HEADER_BYTES..].to_vec());
            if self.complete_tx.get() {
                dev.complete(chain.head, 0);
            } else {
                // Put it back unanswered: nothing to do but not complete it.
            }
        }
    }
}

impl Transport for &FakeCard {
    fn device_id(&self) -> u32 {
        self.device_id
    }
    fn status(&self) -> u8 {
        self.status.get()
    }
    fn set_status(&self, value: u8) {
        self.status.set(value);
    }
    fn device_features(&self, select: u32) -> u32 {
        self.feature_sel.set(select);
        self.offered.get(select as usize).copied().unwrap_or(0)
    }
    fn set_driver_features(&self, select: u32, value: u32) {
        let mut a = self.accepted.get();
        if let Some(w) = a.get_mut(select as usize) {
            *w = value;
        }
        self.accepted.set(a);
    }
    fn queue_max(&self, _index: u16) -> u16 {
        256
    }
    fn setup_queue(&self, index: u16, size: u16, desc: u64, avail: u64, used: u64) {
        let dev = FakeDevice::at(self.view, desc, avail, used, size);
        match index {
            0 => *self.rx.borrow_mut() = Some(dev),
            1 => *self.tx.borrow_mut() = Some(dev),
            _ => panic!("virtio-net uses queues 0 and 1 only"),
        }
    }
    fn notify(&self, index: u16) {
        self.notifies.set(self.notifies.get() + 1);
        if index == 1 {
            self.serve_tx();
        }
    }
    fn ack_interrupt(&self) -> u32 {
        self.pending.replace(0)
    }
    fn config_read8(&self, offset: usize) -> u8 {
        MAC.get(offset).copied().unwrap_or(0)
    }
    fn config_read32(&self, _offset: usize) -> u32 {
        0
    }
}

type Net<'a> = VirtioNet<Spin<MockFull>, &'a FakeCard>;

fn started<'a>(backing: &mut Backing, card: &'a FakeCard) -> Result<Net<'a>, Error> {
    let dma = backing.take(dma_bytes(), 16);
    VirtioNet::bring_up(card, dma)
}

fn frame(tag: u8, len: usize) -> Vec<u8> {
    (0..len).map(|i| (i as u8).wrapping_mul(31) ^ tag).collect()
}

#[test]
fn bring_up_reads_the_address_and_posts_every_receive_buffer() {
    let mut backing = Backing::new(512 * 1024);
    let card = FakeCard::new(&backing);
    let net = started(&mut backing, &card).unwrap();
    assert_eq!(net.mac(), MAC);
    assert_ne!(card.status.get() & status::DRIVER_OK, 0);
    card.collect_posted();
    assert_eq!(
        card.posted.borrow().len(),
        RX_BUFFERS,
        "every receive buffer is with the device"
    );
    let c = net.counters();
    assert_eq!((c.rx_posted, c.rx_ready), (RX_BUFFERS, 0));
    assert!(c.balanced(), "{c:?}");
}

#[test]
fn a_card_that_offers_no_address_gets_a_locally_administered_one() {
    let mut backing = Backing::new(512 * 1024);
    let mut card = FakeCard::new(&backing);
    card.offered = [0, transport::VERSION_1_BIT];
    let net = started(&mut backing, &card).unwrap();
    assert_eq!(net.mac(), FALLBACK_MAC);
    assert_eq!(FALLBACK_MAC[0] & 0b10, 0b10, "the locally administered bit is set");
}

#[test]
fn a_legacy_card_is_refused() {
    let mut backing = Backing::new(512 * 1024);
    let mut card = FakeCard::new(&backing);
    card.offered = [F_MAC, 0];
    assert!(matches!(started(&mut backing, &card), Err(Error::Legacy)));
}

#[test]
fn a_block_device_is_not_driven_as_a_card() {
    let mut backing = Backing::new(512 * 1024);
    let mut card = FakeCard::new(&backing);
    card.device_id = transport::DEVICE_ID_BLOCK;
    assert!(matches!(started(&mut backing, &card), Err(Error::WrongDevice { .. })));
}

#[test]
fn a_sent_frame_reaches_the_card_behind_a_zero_header() {
    let mut backing = Backing::new(512 * 1024);
    let card = FakeCard::new(&backing);
    let net = started(&mut backing, &card).unwrap();
    let f = frame(1, 60);
    net.send(&f).unwrap();
    assert_eq!(card.sent.borrow().as_slice(), &[f]);
    net.settle();
    let c = net.counters();
    assert_eq!((c.tx_frames, c.tx_completed, c.tx_in_flight), (1, 1, 0));
    assert!(c.balanced(), "{c:?}");
}

#[test]
fn frames_of_the_wrong_length_are_refused() {
    let mut backing = Backing::new(512 * 1024);
    let card = FakeCard::new(&backing);
    let net = started(&mut backing, &card).unwrap();
    assert_eq!(net.send(&frame(0, FRAME_MAX + 1)), Err(SendError::BadLength));
    assert_eq!(net.send(&frame(0, 13)), Err(SendError::BadLength));
    assert_eq!(card.sent.borrow().len(), 0);
}

#[test]
fn a_full_transmit_queue_is_an_error_until_the_card_catches_up() {
    let mut backing = Backing::new(512 * 1024);
    let card = FakeCard::new(&backing);
    card.complete_tx.set(false);
    let net = started(&mut backing, &card).unwrap();
    for i in 0..TX_SLOTS {
        net.send(&frame(i as u8, 64)).unwrap();
    }
    assert_eq!(net.send(&frame(9, 64)), Err(SendError::Full));
    assert_eq!(net.counters().tx_in_flight, TX_SLOTS);
    // The card completes one; a slot is free again.
    {
        let mut tx = card.tx.borrow_mut();
        let dev = tx.as_mut().unwrap();
        dev.complete(0, 0);
    }
    net.send(&frame(9, 64)).unwrap();
}

#[test]
fn a_received_frame_comes_out_and_its_buffer_goes_back_to_the_card() {
    let mut backing = Backing::new(512 * 1024);
    let card = FakeCard::new(&backing);
    let net = started(&mut backing, &card).unwrap();
    let f = frame(7, 98);
    assert!(card.deliver(&f));
    let mut buf = [0u8; FRAME_MAX];
    assert_eq!(net.recv(&mut buf), Some(98));
    assert_eq!(&buf[..98], f.as_slice());
    assert_eq!(net.recv(&mut buf), None, "one frame, taken once");
    card.collect_posted();
    assert_eq!(card.posted.borrow().len(), RX_BUFFERS, "the buffer was posted again");
    let c = net.counters();
    assert_eq!((c.rx_frames, c.rx_polled), (1, 1));
    assert!(c.balanced(), "{c:?}");
}

#[test]
fn frames_come_out_in_the_order_the_card_completed_them() {
    let mut backing = Backing::new(512 * 1024);
    let card = FakeCard::new(&backing);
    let net = started(&mut backing, &card).unwrap();
    for tag in 0..5u8 {
        assert!(card.deliver(&frame(tag, 60 + tag as usize)));
    }
    let mut buf = [0u8; FRAME_MAX];
    for tag in 0..5u8 {
        let n = net.recv(&mut buf).unwrap();
        assert_eq!(&buf[..n], frame(tag, 60 + tag as usize).as_slice());
    }
}

#[test]
fn a_completion_too_short_to_be_a_frame_is_dropped_and_the_buffer_reposted() {
    let mut backing = Backing::new(512 * 1024);
    let card = FakeCard::new(&backing);
    let net = started(&mut backing, &card).unwrap();
    assert!(card.deliver_claiming(&frame(1, 60), 4));
    let mut buf = [0u8; FRAME_MAX];
    assert_eq!(net.recv(&mut buf), None);
    let c = net.counters();
    assert_eq!(c.rx_dropped, 1);
    assert!(c.balanced(), "the dropped buffer is back with the card: {c:?}");
}

#[test]
fn a_completion_naming_a_buffer_not_given_completes_nothing() {
    let mut backing = Backing::new(512 * 1024);
    let card = FakeCard::new(&backing);
    let net = started(&mut backing, &card).unwrap();
    {
        let mut rx = card.rx.borrow_mut();
        rx.as_mut()
            .unwrap()
            .complete_raw(u32::from(QUEUE_SIZE) + 3, 100);
    }
    let mut buf = [0u8; FRAME_MAX];
    assert_eq!(net.recv(&mut buf), None);
    assert_eq!(net.counters().rx_frames, 0);
}

#[test]
fn in_interrupt_mode_only_the_handler_collects() {
    let mut backing = Backing::new(512 * 1024);
    let card = FakeCard::new(&backing);
    let net = started(&mut backing, &card).unwrap();
    net.set_interrupt_driven(true);
    assert!(card.deliver(&frame(3, 80)));
    let mut buf = [0u8; FRAME_MAX];
    assert_eq!(net.recv(&mut buf), None, "the frame waits for its interrupt");
    assert!(net.on_interrupt());
    assert!(!net.on_interrupt(), "nothing pending: not this card's interrupt");
    assert_eq!(net.recv(&mut buf), Some(80));
    let c: Counters = net.counters();
    assert_eq!((c.interrupts, c.rx_by_interrupt, c.rx_polled), (1, 1, 0));
    assert!(c.balanced(), "{c:?}");
}

#[test]
fn the_stack_resolves_its_gateway_through_the_card() {
    use net::{Config, Stack};
    let mut backing = Backing::new(512 * 1024);
    let card = FakeCard::new(&backing);
    let nic = started(&mut backing, &card).unwrap();
    let mut stack = Box::new(Stack::new(Config {
        ip: [10, 0, 2, 15],
        netmask: [255, 255, 255, 0],
        gateway: [10, 0, 2, 2],
    }));
    assert_eq!(stack.resolve(&nic, [10, 0, 2, 2], 0), None);
    let request = card.sent.borrow()[0].clone();
    assert_eq!(&request[12..14], &[0x08, 0x06], "an ARP request went out through the card");
    // The card delivers the gateway's reply.
    let mut reply = [0u8; 42];
    net::wire::write_ethernet(&mut reply, MAC, [0x52, 0x55, 10, 0, 2, 2], net::wire::ETHERTYPE_ARP)
        .unwrap();
    net::wire::write_arp(
        &mut reply[14..],
        &net::wire::Arp {
            operation: net::wire::ARP_REPLY,
            sender_mac: [0x52, 0x55, 10, 0, 2, 2],
            sender_ip: [10, 0, 2, 2],
            target_mac: MAC,
            target_ip: [10, 0, 2, 15],
        },
    )
    .unwrap();
    assert!(card.deliver(&reply));
    stack.poll(&nic, 1);
    assert_eq!(stack.resolve(&nic, [10, 0, 2, 2], 2), Some([0x52, 0x55, 10, 0, 2, 2]));
    assert!(stack.balanced());
}

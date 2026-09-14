//! The network check: the virtio-net driver, brought up on memory the kernel gives it, and
//! the network stack over it, against QEMU's user-mode network.
//!
//! Bring-up happens in the memory chain, as the disk's does and for the same reason: the
//! handshake hands the card queue addresses, and that needs memory. The check runs later,
//! in the banner after the block interrupt check, because it waits for frames with
//! interrupts enabled. On the real card it proves:
//!
//! * the gateway, 10.0.2.2, is resolved by ARP;
//! * every echo request sent to the gateway is answered, matched by identifier and sequence;
//! * datagrams make the round trip to kbuild and back: kbuild forwards a loopback UDP port to the
//!   guest's [`PORT`] and sends [`PROBE`] to it, the kernel answers the address the probe came from
//!   with numbered [`ECHO`]s, and kbuild's [`ACK`] for each must come back;
//! * TCP carries a request and its reply both ways over two connections to kbuild's TCP service,
//!   whose port kbuild announces alongside its probes ([`TCP_ANNOUNCE`]). QEMU turns a connection
//!   to the gateway's address into one to the host's loopback interface. The first connection is
//!   closed by the kernel first and must pass through FIN-WAIT-1 to TIME-WAIT; the second is closed
//!   by kbuild first and must pass through CLOSE-WAIT and LAST-ACK to CLOSED. kbuild relays every
//!   frame the card sends to QEMU's network and drops the first data segment of each connection
//!   once, so each must have had a data segment retransmitted. After both, the check lingers
//!   [`LINGER_NS`], and nothing the peer sends may arrive twice or be refused: a segment the kernel
//!   failed to acknowledge would come again;
//! * every stack buffer is back in its pool, every receive buffer is with the card or holding a
//!   frame, and nothing is outstanding on the transmit queue;
//! * where the platform wired the card's interrupt, every frame was collected by the handler and
//!   none by polling.
//!
//! The started card and stack outlive the check: the stress run's network workloads use them
//! through [`nic`], [`ping`], [`udp_round`] and [`tcp_round`], and the socket calls through
//! [`with_stack`].
//!
//! # Offline
//!
//! Nothing here needs the host's network. QEMU's user-mode stack answers ARP and echo requests
//! for its gateway itself, and the UDP peer is kbuild on the loopback interface, reached through
//! a `hostfwd` rule. The resolver at 10.0.2.3 is not used: it forwards to the host's, which a
//! machine without a network does not have.
//!
//! # Time
//!
//! The stack's clock is whatever `now` the caller passes, in nanoseconds. The check counts
//! from a clock of its own, since the kernel's timekeeping starts later, with the scheduler,
//! and the stress run counts from that. The two epochs differ, which costs nothing: an ARP
//! entry learned on one expires early or late on the other and is asked for again, and a
//! retry's rate limit only ever holds back a request for an entry that is still live.

use core::cell::SyncUnsafeCell;
use core::sync::atomic::Ordering;

use arch::Cpu;
use hal::{Arch, EarlyConsole, PhysAddr};
use mm::phys::FrameAllocator;
use net::tcp::State;
use net::{Config, Conn, Ipv4Addr, Mac, Stack, TcpError};
use sync::{LockClass, SpinLock};
use time::Clock;
use virtio::mem::Dma;
use virtio_net::VirtioNet;

use crate::{AtomicBool, AtomicU32, Check, Live, Locks, write_usize};

/// The one guest's address on QEMU's user-mode network: the defaults of `-netdev user`.
pub const CONFIG: Config = Config {
    ip: [10, 0, 2, 15],
    netmask: [255, 255, 255, 0],
    gateway: GATEWAY,
};

/// QEMU's user-mode gateway, which answers ARP and echo requests itself.
pub const GATEWAY: Ipv4Addr = [10, 0, 2, 2];

/// The guest port kbuild forwards its datagrams to, and the messages it exchanges with the
/// kernel. `kbuild/src/qemu.rs` has the same four.
pub const PORT: u16 = 5555;
pub const PROBE: &[u8] = b"kintane-udp-probe";
pub const ECHO: &[u8] = b"kintane-udp-echo ";
pub const ACK: &[u8] = b"kintane-udp-ack ";

/// What kbuild's TCP service is told and answers, and the datagram that tells the kernel which
/// port it is on: `kbuild/src/qemu.rs` has the same three. A request is
/// `kintane-tcp-request <mode> <tag>` and a newline, and its reply is the same line with `reply`
/// for `request`. The mode `guest-closes` has kbuild wait for the kernel's close before its own,
/// and `peer-closes` has kbuild close as soon as it has replied.
pub const TCP_ANNOUNCE: &[u8] = b"kintane-tcp-port ";
pub const TCP_REQUEST: &[u8] = b"kintane-tcp-request ";
pub const TCP_REPLY: &[u8] = b"kintane-tcp-reply ";

/// The identifier the kernel's echo requests carry.
pub const PING_ID: u16 = 0x4b54;

/// Echo requests the check sends, and datagram round trips it makes.
const PINGS: u16 = 4;
const ROUNDS: u32 = 3;

const RESOLVE_NS: u64 = 5_000_000_000;
const REPLY_NS: u64 = 3_000_000_000;
/// kbuild probes four times a second from the moment QEMU starts, so a probe is normally
/// already waiting. The bound is for a run with nobody on the other end.
const PROBE_NS: u64 = 15_000_000_000;
/// The longest one TCP round may take: a handshake, a retransmission or two, and a close.
const TCP_NS: u64 = 10_000_000_000;
/// How long the check keeps listening after its TCP rounds, for anything the peer sends again.
/// QEMU's TCP retransmits no sooner than a second.
pub const LINGER_NS: u64 = 3_000_000_000;

/// SAFETY INVARIANT: written once, by [`bring_up`], before `STARTED` is set; read only after
/// it is set, through [`nic`].
static NIC: SyncUnsafeCell<Option<VirtioNet<Locks>>> = SyncUnsafeCell::new(None);
static STARTED: AtomicBool = AtomicBool::new(false);

/// The stack, shared by the check and the stress workload after it. Its buffers are inside
/// it, so it lives here rather than on a 16 KiB boot stack.
///
/// Taken with `lock_irqsave` everywhere, although no handler takes it: a kernel spinlock is
/// held with preemption off, and masking is how a thread gets that. Taken with plain `lock`
/// from the stress workload, a timer interrupt could switch the holder out mid-poll and move
/// it to another CPU, and the stress run hung twice at about 40 s doing exactly that.
static STACK: SpinLock<Stack, Cpu> = SpinLock::with_class(Stack::new(CONFIG), &STACK_CLASS);
static STACK_CLASS: LockClass = LockClass::new("kernel.net");

/// Where kbuild's probe came from, as the guest sees it: the address as a big-endian word,
/// and the port. Zero until the check has heard from it.
static PEER_ADDR: AtomicU32 = AtomicU32::new(0);
static PEER_PORT: AtomicU32 = AtomicU32::new(0);
/// The port kbuild's TCP service listens on, on the host's loopback interface, as its
/// announcement said. Zero until one has arrived.
static TCP_PORT: AtomicU32 = AtomicU32::new(0);

/// kbuild's TCP port, once it has announced it.
pub fn tcp_port() -> Option<u16> {
    let port = TCP_PORT.load(Ordering::Acquire);
    (port != 0).then_some(port as u16)
}

/// Run `f` on the stack, after polling it, on the scheduler's clock: for the socket calls,
/// which run once the check is over. `None` without a started card.
///
/// The stack's lock is held for the poll and `f`, with interrupts masked; see [`STACK`].
#[cfg_attr(
    not(CONFIG_USERSPACE),
    expect(dead_code, reason = "the socket calls are its only users")
)]
pub fn with_stack<R>(f: impl FnOnce(&mut Stack, &VirtioNet<Locks>, u64) -> R) -> Option<R> {
    let card = nic()?;
    let t = crate::timekeeping::now().as_nanos();
    let mut s = STACK.lock_irqsave();
    s.poll(card, t);
    Some(f(&mut s, card, t))
}

/// Remember kbuild's TCP port if `datagram` announces it.
fn note(datagram: &[u8]) {
    let Some(digits) = datagram.strip_prefix(TCP_ANNOUNCE) else {
        return;
    };
    let mut port: u32 = 0;
    for &d in digits {
        if !d.is_ascii_digit() || port > u32::from(u16::MAX) {
            return;
        }
        port = port * 10 + u32::from(d - b'0');
    }
    if port != 0 && port <= u32::from(u16::MAX) {
        TCP_PORT.store(port, Ordering::Release);
    }
}

/// Take every datagram waiting on [`PORT`], remembering an announcement among them.
fn drain(s: &mut Stack) {
    let mut got = [0u8; net::stack::UDP_MAX];
    while let Some((_, _, len)) = s.udp_recv(PORT, &mut got) {
        note(got.get(..len).unwrap_or(&[]));
    }
}

/// The started card, once [`bring_up`] has brought it up.
pub fn nic() -> Option<&'static VirtioNet<Locks>> {
    if !STARTED.load(Ordering::Acquire) {
        return None;
    }
    // SAFETY: `STARTED` is set only after the one write, and nothing writes again.
    unsafe { (*NIC.get()).as_ref() }
}

/// kbuild's address and port, once the check's round trips have found it.
pub fn peer() -> Option<(Ipv4Addr, u16)> {
    let port = PEER_PORT.load(Ordering::Acquire);
    (port != 0).then(|| (PEER_ADDR.load(Ordering::Acquire).to_be_bytes(), port as u16))
}

/// The card's interrupt handler, installed with `virtio_net::set_handler`: as the disk's,
/// it reaches the card through [`nic`], because the kernel owns the started card.
fn on_nic_interrupt() {
    if let Some(n) = nic() {
        n.on_interrupt();
    }
}

/// Bring the card up, and post its receive buffers.
pub fn bring_up(c: &dyn EarlyConsole, frames: &mut FrameAllocator<'_, Cpu>, live: Live) -> Check {
    c.write_str("\n  nic        ");
    if virtio_net::window().is_none() {
        if kconfig::QEMU_NET_TEST {
            c.write_str("NO VIRTIO-NET DEVICE, though the run attached a card");
            return Check::Failed;
        }
        c.write_str("skipped: no network card");
        return Check::Skipped;
    }
    let Some(direct) = live.direct else {
        c.write_str("no kernel address space to map the card's memory through");
        return Check::Failed;
    };

    // Device memory: a contiguous run the card addresses by its physical address.
    let page = <Cpu as hal::Arch>::PAGE_SIZE;
    let pages = virtio_net::dma_bytes().div_ceil(page);
    let Ok(run) = frames.alloc_contiguous(pages) else {
        c.write_str("no run of frames for the card's memory");
        return Check::Failed;
    };
    let phys = run.start().start().raw();
    let len = pages * page;
    let Ok(virt) = direct.to_virt(PhysAddr::new(phys)) else {
        c.write_str("the card's memory is outside the direct map");
        let _ = frames.free_contiguous(run);
        return Check::Failed;
    };
    if !direct.covers_phys(PhysAddr::new(phys + len as u64 - 1)) {
        c.write_str("the card's memory runs past the direct map");
        let _ = frames.free_contiguous(run);
        return Check::Failed;
    }
    // SAFETY: the run was just taken from the frame allocator, so nothing else refers to it,
    // and the direct map maps `[phys, phys + len)` at `virt` writable. It is never freed: the
    // card keeps using it for as long as the kernel runs.
    let dma = unsafe { Dma::new(virt.raw(), phys, len) };

    // SAFETY: the claimed window is mapped by the kernel's address space, which maps every
    // window a bound driver claimed, and this is the one transport made for it.
    let Some(transport) = (unsafe { virtio_net::transport() }) else {
        c.write_str("the card's window is outside the address space");
        return Check::Failed;
    };
    // Both queues on the card's MSI-X entry when that is how the platform wired its
    // interrupt, as the disk's; on a line, or polled, bring-up needs to know nothing.
    let vector = virtio_net::msix_entry()
        .filter(|_| platform::net_line().is_some_and(platform::interrupt_is_msi));
    let card = match VirtioNet::<Locks>::bring_up_with_vector(transport, dma, vector) {
        Ok(n) => n,
        Err(e) => {
            c.write_str("bring-up FAILED: ");
            c.write_str(bring_up_error(e));
            return Check::Failed;
        }
    };

    // Stored, and its handler installed, at once, for the disk's reason (see `block`): the
    // card raises its line for every frame that arrives from here on, and only the handler
    // acknowledges it.
    //
    // SAFETY: the one write to `NIC`, before `STARTED` makes it readable.
    unsafe { *NIC.get() = Some(card) };
    STARTED.store(true, Ordering::Release);
    // SAFETY: once, on the boot path, with interrupts masked.
    let _ = unsafe { virtio_net::set_handler(on_nic_interrupt) };
    let Some(card) = nic() else {
        c.write_str("the card could not be read back after it was stored");
        return Check::Failed;
    };

    c.write_str("virtio-net ");
    write_mac(c, card.mac());
    let counters = card.counters();
    c.write_str(", ");
    write_usize(c, counters.rx_posted);
    c.write_str(" receive buffers posted");
    if counters.rx_posted != virtio_net::RX_BUFFERS {
        c.write_str(", NOT EVERY RECEIVE BUFFER WAS POSTED");
        return Check::Failed;
    }
    c.write_str(" ok");
    Check::Passed
}

/// Resolve, ping and exchange datagrams through the started card, then check the books.
pub fn check(c: &dyn EarlyConsole) -> Check {
    let Some(card) = nic() else {
        // A run that attached a card has already failed at bring-up, saying why.
        c.write_str("skipped: no network card");
        return Check::Skipped;
    };
    let Some(src) = arch::clock_source() else {
        c.write_str("NO CLOCK TO BOUND THE WAIT WITH");
        return Check::Failed;
    };
    let Ok(mut clock) = Clock::from_source(src) else {
        c.write_str("NO CLOCK TO BOUND THE WAIT WITH");
        return Check::Failed;
    };
    let mut now = || clock.advance(src.read()).as_nanos();

    // QEMU's virtio-net-pci has an MSI-X table. On a platform that delivers messages, a card
    // that came up on anything else fell back somewhere, and the interrupt half of this check
    // would pass over a poll.
    if kconfig::QEMU_NET_TEST && platform::delivers_msi() && !card.uses_msix() {
        c.write_str("THE CARD IS NOT ON MSI-X, THOUGH QEMU'S FUNCTION HAS IT");
        return Check::Failed;
    }
    let line = platform::net_line();
    match line {
        Some(l) => {
            c.write_str("line ");
            write_usize(c, l as usize);
            if card.uses_msix() {
                c.write_str(", MSI-X");
            }
        }
        None => c.write_str("polled: no interrupt route on this port"),
    }

    let before = card.counters();
    // Where the card has a line, frames are collected by its handler and nowhere else.
    card.set_interrupt_driven(line.is_some());
    // SAFETY: the interrupt path is up (the interrupt selftest ran), the card's handler is
    // registered and its line enabled where it has one, and the scheduler's hook is not
    // installed yet, so an interrupt taken here returns to this loop.
    unsafe { arch::tick::enable_interrupts() };
    let failure = exchange(c, card, &mut now);
    // Masked again for the rest of bring-up, which runs masked.
    let _ = Cpu::irq_save();
    card.set_interrupt_driven(false);
    card.settle();

    let after = card.counters();
    let (balanced, in_use) = {
        let s = STACK.lock_irqsave();
        (s.balanced(), s.buffers_in_use())
    };
    let polled = after.rx_polled - before.rx_polled;
    c.write_str("; ");
    write_usize(c, (after.rx_frames - before.rx_frames) as usize);
    c.write_str(" frames in, ");
    write_usize(c, (after.tx_frames - before.tx_frames) as usize);
    c.write_str(" out, ");
    write_usize(c, (after.interrupts - before.interrupts) as usize);
    c.write_str(" interrupts, ");
    write_usize(c, polled as usize);
    c.write_str(" polled, ");
    write_usize(c, in_use);
    c.write_str(" stack buffers held");

    if let Some(why) = failure {
        c.write_str(", ");
        c.write_str(why);
        return Check::Failed;
    }
    if !balanced {
        c.write_str(", A STACK BUFFER WAS NOT GIVEN BACK");
        return Check::Failed;
    }
    if !after.balanced() {
        c.write_str(", A RECEIVE BUFFER OR TRANSMIT SLOT IS MISSING");
        return Check::Failed;
    }
    if line.is_some() {
        if polled != 0 {
            c.write_str(", A FRAME WAS COLLECTED WITHOUT ITS INTERRUPT");
            return Check::Failed;
        }
        if after.rx_by_interrupt == before.rx_by_interrupt {
            c.write_str(", NO FRAME ARRIVED BY INTERRUPT");
            return Check::Failed;
        }
    }
    c.write_str(" ok");
    Check::Passed
}

/// The check's exchanges, in order. Returns what failed, if anything did.
fn exchange(
    c: &dyn EarlyConsole,
    card: &VirtioNet<Locks>,
    now: &mut dyn FnMut() -> u64,
) -> Option<&'static str> {
    let spin = core::hint::spin_loop;
    // Forgotten first. QEMU asks for the guest's address before it forwards kbuild's first
    // probe, and the stack learns the gateway from that request. Resolved from that alone,
    // the check passed with a stack whose own requests no gateway could answer, so the
    // gateway counts as resolved only once a reply to one of them has arrived.
    let replies = {
        let mut s = STACK.lock_irqsave();
        s.forget(GATEWAY);
        s.counters().arp_learned
    };
    let resolved = wait(card, RESOLVE_NS, now, spin, |s, t| {
        let mac = s.resolve(card, GATEWAY, t)?;
        if s.counters().arp_learned > replies {
            return Some(mac);
        }
        // Learned again from someone else's request: forget it, so the next try asks.
        s.forget(GATEWAY);
        None
    });
    let Some(mac) = resolved else {
        return Some("THE GATEWAY NEVER ANSWERED AN ARP REQUEST");
    };
    c.write_str("; gateway ");
    write_mac(c, mac);

    for seq in 1..=PINGS {
        if !ping(card, seq, REPLY_NS, now, spin) {
            return Some("AN ECHO REQUEST WAS NEVER ANSWERED");
        }
    }
    c.write_str("; ");
    write_usize(c, PINGS as usize);
    c.write_str(" echo replies; udp port ");
    write_usize(c, PORT as usize);

    let Some(peer) = wait(card, PROBE_NS, now, spin, |s, _| take_probe(s)) else {
        return Some("NO DATAGRAM FROM KBUILD ARRIVED");
    };
    PEER_ADDR.store(u32::from_be_bytes(peer.0), Ordering::Release);
    PEER_PORT.store(u32::from(peer.1), Ordering::Release);
    for n in 1..=ROUNDS {
        if !udp_round(card, peer, n, REPLY_NS, now, spin) {
            return Some("A DATAGRAM ROUND TRIP DID NOT COMPLETE");
        }
    }
    c.write_str(", ");
    write_usize(c, ROUNDS as usize);
    c.write_str(" round trips");

    let Some(port) = wait(card, PROBE_NS, now, spin, |s, _| {
        drain(s);
        tcp_port()
    }) else {
        return Some("KBUILD NEVER ANNOUNCED ITS TCP PORT");
    };
    c.write_str("; tcp port ");
    write_usize(c, port as usize);
    let before = STACK.lock_irqsave().tcp_counters();
    let guest = match tcp_round(card, port, true, 1, TCP_NS, now, spin) {
        Ok(round) => round,
        Err(why) => return Some(why),
    };
    let peer = match tcp_round(card, port, false, 2, TCP_NS, now, spin) {
        Ok(round) => round,
        Err(why) => return Some(why),
    };
    // Anything the peer has to send again, for want of an acknowledgement, arrives in here.
    let _ = wait(card, LINGER_NS, now, spin, |s, _| {
        drain(s);
        None::<()>
    });
    let after = STACK.lock_irqsave().tcp_counters();
    c.write_str(", closed by the kernel [");
    write_states(c, guest.visited);
    c.write_str("] and by kbuild [");
    write_states(c, peer.visited);
    c.write_str("], ");
    write_usize(c, (guest.retransmits + peer.retransmits) as usize);
    c.write_str(" data retransmits");

    let through = |round: &TcpRound, states: &[State]| {
        round.closed && states.iter().all(|s| round.visited & s.bit() != 0)
    };
    if !through(&guest, &[State::Established, State::FinWait1, State::TimeWait]) {
        return Some("THE KERNEL'S CLOSE DID NOT PASS THROUGH FIN-WAIT-1 TO TIME-WAIT");
    }
    if !through(&peer, &[State::Established, State::CloseWait, State::LastAck]) {
        return Some("KBUILD'S CLOSE DID NOT PASS THROUGH CLOSE-WAIT AND LAST-ACK TO CLOSED");
    }
    if guest.retransmits == 0 || peer.retransmits == 0 {
        return Some(
            "A CONNECTION RETRANSMITTED NO DATA, THOUGH KBUILD DROPS THE FIRST SEGMENT OF EACH",
        );
    }
    let again = (after.duplicates - before.duplicates)
        + (after.out_of_order - before.out_of_order)
        + (after.resets_sent - before.resets_sent)
        + (after.resets_received - before.resets_received);
    if again != 0 {
        c.write_str(", ");
        write_usize(c, again as usize);
        c.write_str(" segments repeated or reset");
        return Some(
            "THE PEER SENT A SEGMENT AGAIN OR A RESET WAS EXCHANGED: AN ACKNOWLEDGEMENT WENT MISSING",
        );
    }
    None
}

/// Poll the stack and run `step` on it until `step` has an answer or `timeout_ns` passes,
/// calling `pause` between tries. The stack's lock is held for one try at a time.
fn wait<T>(
    card: &VirtioNet<Locks>,
    timeout_ns: u64,
    now: &mut dyn FnMut() -> u64,
    pause: fn(),
    mut step: impl FnMut(&mut Stack, u64) -> Option<T>,
) -> Option<T> {
    let start = now();
    loop {
        let t = now();
        let got = {
            let mut s = STACK.lock_irqsave();
            s.poll(card, t);
            step(&mut s, t)
        };
        if got.is_some() {
            return got;
        }
        if t.saturating_sub(start) >= timeout_ns {
            return None;
        }
        pause();
    }
}

/// Send the gateway echo request `seq` and wait for the reply that names it.
pub fn ping(
    card: &VirtioNet<Locks>,
    seq: u16,
    timeout_ns: u64,
    now: &mut dyn FnMut() -> u64,
    pause: fn(),
) -> bool {
    let mut sent = false;
    wait(card, timeout_ns, now, pause, |s, t| {
        if !sent {
            // Resolving on the way, which is a request sent rather than a reply awaited.
            sent = s.ping(card, GATEWAY, PING_ID, seq, t).is_ok();
            return None;
        }
        s.take_echo_reply(PING_ID, seq)
            .filter(|from| *from == GATEWAY)
            .map(|_| ())
    })
    .is_some()
}

/// Send `peer` echo `n` from [`PORT`] and wait for its acknowledgement.
pub fn udp_round(
    card: &VirtioNet<Locks>,
    peer: (Ipv4Addr, u16),
    n: u32,
    timeout_ns: u64,
    now: &mut dyn FnMut() -> u64,
    pause: fn(),
) -> bool {
    let mut echo = [0u8; 32];
    let echo_len = numbered(&mut echo, ECHO, n);
    let mut ack = [0u8; 32];
    let ack_len = numbered(&mut ack, ACK, n);
    let mut sent = false;
    wait(card, timeout_ns, now, pause, |s, t| {
        if !sent {
            sent = s
                .udp_send(card, peer.0, PORT, peer.1, &echo[..echo_len], t)
                .is_ok();
            return None;
        }
        let mut got = [0u8; net::stack::UDP_MAX];
        // Whatever else is waiting on the port — probes, an acknowledgement of an earlier
        // try — is taken and dropped on the way to this one.
        while let Some((from, port, len)) = s.udp_recv(PORT, &mut got) {
            if (from, port) == peer && got.get(..len) == ack.get(..ack_len) {
                return Some(());
            }
            note(got.get(..len).unwrap_or(&[]));
        }
        None
    })
    .is_some()
}

/// The source of the first probe waiting on [`PORT`].
fn take_probe(s: &mut Stack) -> Option<(Ipv4Addr, u16)> {
    let mut got = [0u8; net::stack::UDP_MAX];
    while let Some((from, port, len)) = s.udp_recv(PORT, &mut got) {
        if got.get(..len) == Some(PROBE) {
            return Some((from, port));
        }
        note(got.get(..len).unwrap_or(&[]));
    }
    None
}

/// What one TCP round with kbuild showed.
#[derive(Clone, Copy)]
pub struct TcpRound {
    /// Every state the connection was seen in, as `net::tcp::State` bits.
    pub visited: u16,
    /// Data segments sent again during the round.
    pub retransmits: u64,
    /// The connection reached the end its close order leads to: TIME-WAIT for the kernel's
    /// close, CLOSED and reaped for kbuild's.
    pub closed: bool,
}

/// Connect to kbuild's TCP service on `port`, send request `n` in the mode `guest_closes`
/// names, check the reply, and close in that order. The connection is aborted if anything
/// fails, so a failed round holds no buffer.
pub fn tcp_round(
    card: &VirtioNet<Locks>,
    port: u16,
    guest_closes: bool,
    n: u32,
    timeout_ns: u64,
    now: &mut dyn FnMut() -> u64,
    pause: fn(),
) -> Result<TcpRound, &'static str> {
    let mode: &[u8] = if guest_closes {
        b"guest-closes "
    } else {
        b"peer-closes "
    };
    let mut request = [0u8; 64];
    let request_len = line(&mut request, TCP_REQUEST, mode, n);
    let mut reply = [0u8; 64];
    let reply_len = line(&mut reply, TCP_REPLY, mode, n);
    let before = STACK.lock_irqsave().tcp_counters().data_retransmits;
    let t = now();
    let conn = STACK
        .lock_irqsave()
        .tcp_connect(card, GATEWAY, port, t)
        .map_err(|_| "NO TCP CONNECTION COULD BE OPENED")?;
    let result = tcp_exchange(
        card,
        conn,
        guest_closes,
        &request[..request_len],
        &reply[..reply_len],
        timeout_ns,
        now,
        pause,
    );
    if result.is_err() {
        let t = now();
        // Already gone, or closing: either way nothing is left holding a buffer.
        let _ = STACK.lock_irqsave().tcp_abort(card, conn, t);
    }
    let mut round = result?;
    round.retransmits = STACK.lock_irqsave().tcp_counters().data_retransmits - before;
    Ok(round)
}

#[allow(clippy::too_many_arguments)]
fn tcp_exchange(
    card: &VirtioNet<Locks>,
    conn: Conn,
    guest_closes: bool,
    request: &[u8],
    reply: &[u8],
    timeout_ns: u64,
    now: &mut dyn FnMut() -> u64,
    pause: fn(),
) -> Result<TcpRound, &'static str> {
    let mut visited = 0u16;
    let mut queued = 0;
    wait(card, timeout_ns, now, pause, |s, t| {
        let Some(st) = s.tcp_status(conn) else {
            return Some(Err("THE TCP CONNECTION VANISHED BEFORE ITS REQUEST WAS SENT"));
        };
        visited |= st.visited;
        if st.error.is_some() {
            return Some(Err("THE TCP CONNECTION WAS REFUSED, RESET OR TIMED OUT"));
        }
        if st.state != State::Established {
            return None;
        }
        match s.tcp_send(card, conn, request.get(queued..).unwrap_or(&[]), t) {
            Ok(n) => {
                queued += n;
                (queued == request.len()).then_some(Ok(()))
            }
            Err(TcpError::WouldBlock) => None,
            Err(_) => Some(Err("THE TCP REQUEST COULD NOT BE QUEUED")),
        }
    })
    .ok_or("THE TCP CONNECTION WAS NEVER ESTABLISHED")??;

    let mut got = [0u8; 64];
    let mut len = 0;
    wait(card, timeout_ns, now, pause, |s, t| {
        loop {
            if len >= reply.len() {
                return Some(Ok(()));
            }
            let room = got.get_mut(len..reply.len()).unwrap_or(&mut []);
            match s.tcp_recv(card, conn, room, t) {
                Ok(0) => return Some(Err("KBUILD CLOSED BEFORE ITS TCP REPLY WAS COMPLETE")),
                Ok(n) => len += n,
                Err(TcpError::WouldBlock) => return None,
                Err(_) => return Some(Err("THE TCP CONNECTION FAILED BEFORE THE REPLY")),
            }
        }
    })
    .ok_or("NO TCP REPLY ARRIVED")??;
    if got.get(..reply.len()) != Some(reply) {
        return Err("THE TCP REPLY WAS NOT THE ONE ASKED FOR");
    }

    if !guest_closes {
        // kbuild closes once it has replied: the end of the stream comes first.
        wait(card, timeout_ns, now, pause, |s, t| {
            let mut rest = [0u8; 8];
            if let Some(st) = s.tcp_status(conn) {
                visited |= st.visited;
            }
            match s.tcp_recv(card, conn, &mut rest, t) {
                Ok(0) => Some(Ok(())),
                Ok(_) => Some(Err("KBUILD SENT MORE THAN ITS TCP REPLY")),
                Err(TcpError::WouldBlock) => None,
                Err(_) => Some(Err("THE TCP CONNECTION FAILED BEFORE KBUILD CLOSED IT")),
            }
        })
        .ok_or("KBUILD NEVER CLOSED ITS END")??;
    }
    let t = now();
    {
        let mut s = STACK.lock_irqsave();
        s.tcp_close(card, conn, t)
            .map_err(|_| "THE TCP CONNECTION COULD NOT BE CLOSED")?;
        // Seen under the same lock as the close, which sent the FIN: the peer's acknowledgement
        // can arrive before the wait below first looks, and a connection closed and reaped by
        // then would never have been seen in LAST-ACK.
        if let Some(st) = s.tcp_status(conn) {
            visited |= st.visited;
        }
    }
    let mut failed = false;
    let over = wait(card, timeout_ns, now, pause, |s, _| match s.tcp_status(conn) {
        Some(st) => {
            visited |= st.visited;
            failed |= st.error.is_some();
            (guest_closes && st.state == State::TimeWait).then_some(())
        }
        // Reaped: closed, and its buffers given back.
        None => Some(()),
    });
    let closed = over.is_some()
        && !failed
        && if guest_closes {
            visited & State::TimeWait.bit() != 0
        } else {
            visited & State::LastAck.bit() != 0
        };
    Ok(TcpRound {
        visited,
        retransmits: 0,
        closed,
    })
}

/// `prefix`, `mode`, `n` in decimal and a newline. Returns the length written.
fn line(buf: &mut [u8; 64], prefix: &[u8], mode: &[u8], n: u32) -> usize {
    let mut number = [0u8; 32];
    let digits = numbered(&mut number, b"", n);
    let mut at = 0;
    for part in [prefix, mode, &number[..digits], b"\n"] {
        for &b in part {
            if let Some(slot) = buf.get_mut(at) {
                *slot = b;
                at += 1;
            }
        }
    }
    at
}

/// The TCP states in `visited`, in the order a connection passes through them.
fn write_states(c: &dyn EarlyConsole, visited: u16) {
    const NAMES: [(State, &str); 10] = [
        (State::SynSent, "syn-sent"),
        (State::SynReceived, "syn-received"),
        (State::Established, "established"),
        (State::FinWait1, "fin-wait-1"),
        (State::FinWait2, "fin-wait-2"),
        (State::Closing, "closing"),
        (State::TimeWait, "time-wait"),
        (State::CloseWait, "close-wait"),
        (State::LastAck, "last-ack"),
        (State::Closed, "closed"),
    ];
    let mut first = true;
    for (state, name) in NAMES {
        if visited & state.bit() != 0 {
            if !first {
                c.write_str(" ");
            }
            c.write_str(name);
            first = false;
        }
    }
}

/// No TCP connection holds a ring, and the pool's books agree with what connections hold:
/// what a moment with no TCP connection in use must show. A connection in TIME-WAIT holds
/// none, and is allowed.
pub fn tcp_audit() -> Result<(), &'static str> {
    if nic().is_none() {
        return Ok(());
    }
    let s = STACK.lock_irqsave();
    if s.tcp_rings_held() != 0 {
        return Err("a TCP connection holds its buffers with nothing using it (a leak)");
    }
    if !s.books_consistent() {
        return Err("the pool's books do not match the buffers TCP connections hold");
    }
    Ok(())
}

/// The stack's pool full, the card's receive buffers all accounted for and nothing on its
/// way out. What a moment with nothing using the network must show.
pub fn audit() -> Result<(), &'static str> {
    let Some(card) = nic() else {
        return Ok(());
    };
    if !STACK.lock_irqsave().balanced() {
        return Err("a stack buffer is out of its pool with nothing using it (a leak)");
    }
    card.settle();
    let c = card.counters();
    if c.rx_posted + c.rx_ready != virtio_net::RX_BUFFERS {
        return Err("a receive buffer is neither with the card nor holding a frame (a leak)");
    }
    if !c.balanced() {
        return Err("a transmit slot or descriptor is outstanding with nothing sending");
    }
    Ok(())
}

/// `prefix` followed by `n` in decimal. Returns the length written.
fn numbered(buf: &mut [u8; 32], prefix: &[u8], n: u32) -> usize {
    let mut digits = [0u8; 10];
    let mut i = digits.len();
    let mut v = n;
    loop {
        i -= 1;
        digits[i] = b'0' + (v % 10) as u8;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    let len = prefix.len() + digits.len() - i;
    buf[..prefix.len()].copy_from_slice(prefix);
    buf[prefix.len()..len].copy_from_slice(&digits[i..]);
    len
}

fn write_mac(c: &dyn EarlyConsole, mac: Mac) {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    for (i, b) in mac.iter().enumerate() {
        if i != 0 {
            c.write_str(":");
        }
        c.write_bytes(&[DIGITS[usize::from(b >> 4)], DIGITS[usize::from(b & 0xf)]]);
    }
}

fn bring_up_error(e: virtio::transport::Error) -> &'static str {
    use virtio::transport::Error;
    match e {
        Error::NotVirtio => "not a virtio device",
        Error::Legacy => "a legacy virtio device",
        Error::WrongDevice { .. } => "not a network card",
        Error::FeaturesRefused => "the card refused the features",
        Error::Refused { .. } => "the card refused the handshake",
        Error::BadQueue { .. } => "the card's queues are unusable",
        Error::NoRoom => "not enough memory for the rings and buffers",
        Error::BadGeometry => "an unusable configuration",
        Error::Timeout => "the card did not answer",
        Error::VectorRefused { .. } => "the card refused its MSI-X vector",
    }
}

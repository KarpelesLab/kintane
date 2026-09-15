//! A native program that talks datagrams: proof that the datagram socket calls carry one.
//!
//! It is given three things, in its first three argument registers: the console, the address of
//! kbuild's datagram service as the socket calls spell an address, and the address of a port
//! kbuild leaves unbound. With those it
//!
//! 1. sends a request to the service from a socket with no port of its own, and takes the reply,
//!    which must come from the service and name the request;
//! 2. takes a second reply into a buffer too small for it, which must report the length the
//!    datagram had rather than the length that fit;
//! 3. connects a socket to the unbound port, sends from it to the service anyway, and requires that
//!    the service's reply is *not* delivered: a connected socket takes datagrams from the address
//!    it connected to and from nowhere else;
//! 4. sends to the unbound port and requires that nothing answers it.
//!
//! Every failure exits with a code naming its step, and a call that failed adds what the kernel
//! answered in the byte above it, so the kernel's check reports which answer came back wrong
//! rather than that one did.

#![no_std]
#![no_main]

use rt::{Error, Handle, UdpSocket};

/// kbuild's protocol, in `kernel/main/src/net.rs` and `kbuild/src/qemu.rs`. The tag is this
/// program's, so a reply to it is not one to the Linux program's request.
const REQUEST: &[u8] = b"kintane-udp-request native";
const REPLY: &[u8] = b"kintane-udp-reply native";

const SECOND: u64 = 1_000_000_000;
/// How long a reply that must arrive gets, and how long one that must not is waited for.
const ANSWER_NS: u64 = 5 * SECOND;
const SILENCE_NS: u64 = SECOND;

/// Exit codes. `SUCCESS` is what the kernel requires; the rest say where it stopped, with the
/// kernel's answer in the byte above (see [`why`]).
const SUCCESS: u64 = 0x7d;
/// Everything behaved *and* the quiet port was refused rather than silent, which takes a
/// network that sends an ICMP destination-unreachable for it. The kernel's check requires this
/// one where kbuild is the whole network, and accepts either elsewhere.
const REFUSED: u64 = 0x7e;
const NO_ADDRESS: u64 = 0x7d01;
const BIND_FAILED: u64 = 0x7d02;
const SEND_FAILED: u64 = 0x7d03;
const NO_REPLY: u64 = 0x7d04;
const WRONG_REPLY: u64 = 0x7d05;
const WRONG_SOURCE: u64 = 0x7d06;
const TRUNCATION_HIDDEN: u64 = 0x7d07;
const FOREIGN_DATAGRAM_TAKEN: u64 = 0x7d08;
const QUIET_PORT_ANSWERED: u64 = 0x7d09;
const CLOSE_FAILED: u64 = 0x7d0a;

/// What the kernel answered, in the byte above a step's code: a failed step says which error
/// it was, not only that there was one.
fn why(e: Error) -> u64 {
    let n = match e {
        Error::TimedOut => 1,
        Error::ShouldWait => 2,
        Error::InvalidArgument => 3,
        Error::Full => 4,
        Error::Unsupported => 5,
        Error::BadHandle => 6,
        Error::WrongType => 7,
        Error::PeerClosed => 8,
        _ => 9,
    };
    // Above the step's own digits, so a code says both which step and which answer.
    n << 16
}

#[unsafe(no_mangle)]
#[unsafe(link_section = ".text._start")]
pub extern "C" fn _start(console: usize, service: usize, quiet: usize, _: usize) -> ! {
    rt::exit(run(Handle(console as u32), service as u64, quiet as u64))
}

fn run(console: Handle, service: u64, quiet: u64) -> u64 {
    let _ = console;
    let (ip, port) = (abi::socket::ip(service), abi::socket::port(service));
    let (quiet_ip, quiet_port) = (abi::socket::ip(quiet), abi::socket::port(quiet));
    if port == 0 || quiet_port == 0 {
        return NO_ADDRESS;
    }

    // 1. A request and its reply, on a socket the kernel gives a port to at the first send.
    let socket = match UdpSocket::bind(0) {
        Ok(s) => s,
        Err(e) => return BIND_FAILED | why(e),
    };
    if let Err(e) = socket.send_to(ip, port, REQUEST, ANSWER_NS) {
        return SEND_FAILED | why(e);
    }
    let mut buf = [0u8; 128];
    let (whole, from_ip, from_port) = match socket.recv_from(&mut buf, ANSWER_NS) {
        Ok(got) => got,
        Err(e) => return NO_REPLY | why(e),
    };
    if (from_ip, from_port) != (ip, port) {
        return WRONG_SOURCE;
    }
    if whole != REPLY.len() || !rt::starts_with(&buf, whole, REPLY) {
        return WRONG_REPLY;
    }

    // 2. The same reply into four bytes: what it reports is the length it had.
    if let Err(e) = socket.send_to(ip, port, REQUEST, ANSWER_NS) {
        return SEND_FAILED | why(e);
    }
    let mut small = [0u8; 4];
    let truncated = match socket.recv_from(&mut small, ANSWER_NS) {
        Ok((whole, _, _)) => whole,
        Err(e) => return NO_REPLY | why(e),
    };
    if truncated != REPLY.len() {
        return TRUNCATION_HIDDEN;
    }
    if socket.close().is_err() {
        return CLOSE_FAILED;
    }

    // 3. A socket connected to the unbound port, sending to the service anyway: the service answers
    //    the port it came from, and this socket must not take an answer from it.
    let connected = match UdpSocket::bind(0) {
        Ok(s) => s,
        Err(e) => return BIND_FAILED | why(e),
    };
    if let Err(e) = connected.connect(quiet_ip, quiet_port) {
        return SEND_FAILED | why(e);
    }
    if let Err(e) = connected.send_to(ip, port, REQUEST, ANSWER_NS) {
        return SEND_FAILED | why(e);
    }
    match connected.recv(&mut buf, SILENCE_NS) {
        Err(Error::TimedOut) => {}
        _ => return FOREIGN_DATAGRAM_TAKEN,
    }

    // 4. And nothing answers the port nobody listens on.
    if let Err(e) = connected.send(REQUEST, ANSWER_NS) {
        return SEND_FAILED | why(e);
    }
    // Nothing answers it with a datagram. What may come back instead is a refusal: a network
    // that sends an ICMP destination-unreachable for the port turns the silence into
    // `PeerClosed` here. Which of the two happened is not this program's to judge — it depends
    // on the network it was run against — so it is said in the exit code.
    let refused = match connected.recv(&mut buf, SILENCE_NS) {
        Err(Error::TimedOut) => false,
        Err(Error::PeerClosed) => true,
        _ => return QUIET_PORT_ANSWERED,
    };
    if connected.close().is_err() {
        return CLOSE_FAILED;
    }
    if refused { REFUSED } else { SUCCESS }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    rt::exit(0x7dff)
}

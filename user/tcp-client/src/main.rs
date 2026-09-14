//! A native program that talks TCP: proof that the socket calls carry a real connection.
//!
//! It is given two things, in its first two argument registers: the console, and the address
//! of kbuild's TCP service as the socket calls spell an address. With those it
//!
//! 1. checks that a socket that is not connected refuses to send;
//! 2. connects, through QEMU's user network, to kbuild on the host;
//! 3. sends a request asking kbuild to close first once it has replied;
//! 4. reads until the end of the stream, which is kbuild's close, and compares what arrived with
//!    the reply it asked for;
//! 5. closes its socket, which closes this end in order.
//!
//! Every failure exits with a code naming its step, so the kernel's check reports where a wrong
//! answer came from rather than that one arrived.

#![no_std]
#![no_main]

use rt::{Error, Handle, TcpStream, UserPtr, call};

/// What is asked for, and the answer that is expected: kbuild's protocol, in
/// `kernel/main/src/net.rs` and `kbuild/src/qemu.rs`.
const REQUEST: &[u8] = b"kintane-tcp-request peer-closes user\n";
const REPLY: &[u8] = b"kintane-tcp-reply peer-closes user\n";

const SECOND: u64 = 1_000_000_000;

/// Exit codes. `SUCCESS` is what the kernel requires; the rest say where it stopped.
const SUCCESS: u64 = 0x7c;
const NO_ADDRESS: u64 = 0x7c01;
const UNCONNECTED_SEND: u64 = 0x7c02;
const CONNECT_FAILED: u64 = 0x7c03;
const SEND_FAILED: u64 = 0x7c04;
const RECV_FAILED: u64 = 0x7c05;
const NO_END: u64 = 0x7c06;
const WRONG_REPLY: u64 = 0x7c07;
const CLOSE_FAILED: u64 = 0x7c08;

#[unsafe(no_mangle)]
#[unsafe(link_section = ".text._start")]
pub extern "C" fn _start(console: usize, address: usize, _: usize, _: usize) -> ! {
    rt::exit(run(Handle(console as u32), address as u64))
}

fn run(console: Handle, address: u64) -> u64 {
    let (ip, port) = (abi::socket::ip(address), abi::socket::port(address));
    if port == 0 {
        return NO_ADDRESS;
    }
    if !an_unconnected_socket_refuses_to_send() {
        return UNCONNECTED_SEND;
    }
    let Ok(stream) = TcpStream::connect(ip, port, 10 * SECOND) else {
        return CONNECT_FAILED;
    };
    if stream.send_all(REQUEST, 5 * SECOND).is_err() {
        return SEND_FAILED;
    }
    let mut reply = [0u8; 64];
    let mut got = 0;
    loop {
        // `get_mut` rather than a range slice: see the note on slice indexing in `lib/rt`.
        let Some(room) = reply.get_mut(got..) else {
            return WRONG_REPLY;
        };
        if room.is_empty() {
            return WRONG_REPLY;
        }
        match stream.recv(room, 10 * SECOND) {
            Ok(0) => break,
            Ok(n) => got += n,
            Err(_) if rt::starts_with(&reply, got, REPLY) => return NO_END,
            Err(_) => return RECV_FAILED,
        }
    }
    if !rt::starts_with(&reply, got, REPLY) {
        return WRONG_REPLY;
    }
    if stream.close().is_err() {
        return CLOSE_FAILED;
    }
    let _ = rt::print(console, b"tcp-client: reply read to kbuild's close, socket closed\n");
    SUCCESS
}

/// A fresh socket has no connection: sending on it is an invalid argument, not a wait.
fn an_unconnected_socket_refuses_to_send() -> bool {
    let Ok(raw) = call::socket_create(abi::socket::STREAM) else {
        return false;
    };
    let socket = Handle(raw as u32);
    let sent = call::socket_send(socket, UserPtr(REQUEST.as_ptr() as u64), 1, 0);
    let closed = call::handle_close(socket);
    sent == Err(Error::InvalidArgument) && closed.is_ok()
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    rt::exit(0xdead)
}

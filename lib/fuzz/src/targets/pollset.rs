//! The descriptor sets `poll`, `select` and `epoll` take: arrays a program filled in itself.
//!
//! These are the bytes a hostile program controls on the way into a wait: a `struct pollfd`
//! array whose count need not match it, a `select` bitmap that may name more descriptors than
//! the kernel will read, an `epoll_event` whose size differs between the two ABIs, and the
//! `timespec` and `timeval` a timeout comes in. `kernel/linux::poll` decodes all of them, and
//! nothing it does may panic, read past what it was given, or turn a timeout a program wrote
//! into a shorter one.
//!
//! The first byte picks the ABI and the shape; the rest is the set. Half the inputs are built
//! as well-formed arrays and then corrupted, so the decoders are exercised past their length
//! checks rather than only on their rejection of noise.

use alloc::vec::Vec;

use linux::Abi;
use linux::poll::{self, EpollEvent};

use crate::{Mutator, Rng};

fn abi(tag: u8) -> Abi {
    if tag & 1 == 0 {
        Abi::X86_64
    } else {
        Abi::Aarch64
    }
}

/// What the input after the first byte is read as.
fn shape(tag: u8) -> u8 {
    (tag >> 1) & 3
}

pub fn generate(rng: &mut Rng, _seeds: &[Vec<u8>]) -> Vec<u8> {
    let tag = (rng.next_u32() & 7) as u8;
    let mut bytes = alloc::vec![tag];
    if rng.one_in(2) {
        let len = rng.interesting_len(64);
        bytes.extend((0..len).map(|_| rng.next_u32() as u8));
        return bytes;
    }
    match shape(tag) {
        0 => {
            // A pollfd array: descriptors around the table's size, and events in and out of the
            // set a program may ask for.
            for _ in 0..1 + rng.next_u32() % 8 {
                let fd = (rng.next_u32() % 40) as i32 - 4;
                let events = if rng.one_in(3) {
                    rng.next_u32() as u16
                } else {
                    poll::POLLIN | poll::POLLOUT
                };
                bytes.extend(fd.to_le_bytes());
                bytes.extend(events.to_le_bytes());
                bytes.extend(0u16.to_le_bytes());
            }
        }
        1 => {
            // Three bitmaps, as `select` passes them.
            for _ in 0..3 * poll::FD_SET_BYTES {
                bytes.push(rng.next_u32() as u8);
            }
        }
        2 => {
            // `epoll_event`s, at the size this ABI gives them.
            let abi = abi(tag);
            for _ in 0..1 + rng.next_u32() % 4 {
                let event = EpollEvent {
                    events: rng.next_u32(),
                    data: rng.next_u64(),
                };
                let written = poll::write_event(abi, event);
                bytes.extend(&written[..poll::event_bytes(abi)]);
            }
        }
        _ => {
            // Timeouts: seconds and a fraction, including the ones Linux refuses.
            for _ in 0..2 {
                bytes.extend(rng.next_u64().to_le_bytes());
            }
        }
    }
    Mutator::mutate(rng, &mut bytes);
    bytes
}

pub fn run(input: &[u8]) {
    let Some((&tag, rest)) = input.split_first() else {
        return;
    };
    let abi = abi(tag);
    match shape(tag) {
        0 => pollfds(rest),
        1 => bitmaps(rest),
        2 => events(abi, rest),
        _ => timeouts(rest),
    }
}

/// Every whole `struct pollfd` in `bytes`, read as the kernel reads them.
fn pollfds(bytes: &[u8]) {
    for chunk in bytes.chunks_exact(poll::POLLFD_BYTES) {
        let mut entry = [0u8; poll::POLLFD_BYTES];
        entry.copy_from_slice(chunk);
        let parsed = poll::parse_pollfd(&entry);
        // What a program is told never holds an event it did not ask about, except the three
        // it is told about regardless.
        let answer = poll::revents(parsed.events, u16::MAX);
        assert_eq!(
            answer & !(parsed.events | poll::POLL_ALWAYS),
            0,
            "an answer held an event that was not asked for: {parsed:?} -> {answer:#x}"
        );
        // An entry the kernel would refuse is one whose events are not all askable.
        if poll::askable(parsed.events) {
            assert_eq!(parsed.events & !poll::POLL_ASKABLE, 0);
        }
    }
}

/// A `select` bitmap: nothing names a descriptor past the bitmap, whatever the count says.
fn bitmaps(bytes: &[u8]) {
    let mut set = [0u8; poll::FD_SET_BYTES];
    for (slot, byte) in set.iter_mut().zip(bytes) {
        *slot = *byte;
    }
    let nfds = bytes.first().map_or(0, |b| u64::from(*b)) * 7;
    match poll::fd_set_bytes(nfds) {
        Ok(len) => {
            assert!(len <= poll::FD_SET_BYTES, "a set of {nfds} asked for {len} bytes");
            for fd in 0..poll::FD_SET_BITS + 16 {
                // Reading and writing past the bitmap answers rather than panicking.
                let _ = poll::fd_isset(&set, fd);
                poll::fd_set(&mut set, fd);
            }
        }
        Err(_) => assert!(nfds > poll::FD_SET_BITS as u64),
    }
}

/// `epoll_event`s: what is written is what is read back, and a short tail is refused.
fn events(abi: Abi, bytes: &[u8]) {
    let size = poll::event_bytes(abi);
    for chunk in bytes.chunks(size) {
        match poll::parse_event(abi, chunk) {
            Some(event) => {
                assert_eq!(chunk.len(), size, "a short entry was read as a whole one");
                let written = poll::write_event(abi, event);
                assert_eq!(
                    poll::parse_event(abi, &written),
                    Some(event),
                    "{abi:?}: an entry did not survive being written and read back"
                );
            }
            None => assert!(chunk.len() < size, "a whole entry was refused: {chunk:x?}"),
        }
    }
}

/// Timeouts: a value that is accepted is the one the program wrote, and never a shorter one.
fn timeouts(bytes: &[u8]) {
    let mut spec = [0u8; poll::TIMESPEC_BYTES];
    for (slot, byte) in spec.iter_mut().zip(bytes) {
        *slot = *byte;
    }
    let seconds = i64::from_le_bytes([
        spec[0], spec[1], spec[2], spec[3], spec[4], spec[5], spec[6], spec[7],
    ]);
    for ns in [poll::timespec_ns(&spec), poll::timeval_ns(&spec)] {
        if let Ok(ns) = ns {
            assert!(seconds >= 0, "a negative timeout was accepted as {ns}");
            assert!(
                ns >= (seconds as u64).saturating_mul(1_000_000_000),
                "a timeout of {seconds}s came back as {ns}ns"
            );
        }
    }
    // Milliseconds, as plain `poll` and `epoll_wait` take them.
    let ms = u64::from_le_bytes([
        spec[8], spec[9], spec[10], spec[11], spec[12], spec[13], spec[14], spec[15],
    ]);
    match poll::timeout_ms(ms) {
        Some(ns) => assert!((ms as i64) >= 0 && ns >= ms, "{ms} ms became {ns} ns"),
        None => assert!((ms as i64) < 0, "{ms} ms was read as no deadline"),
    }
}

/// An input that holds at least one whole entry of whatever shape it names.
pub fn accepts(input: &[u8]) -> bool {
    match input.split_first() {
        Some((&tag, rest)) => match shape(tag) {
            0 => rest.len() >= poll::POLLFD_BYTES,
            1 => !rest.is_empty(),
            2 => rest.len() >= poll::event_bytes(abi(tag)),
            _ => rest.len() >= poll::TIMESPEC_BYTES,
        },
        None => false,
    }
}

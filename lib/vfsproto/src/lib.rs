//! The VFS service protocol: what a program says to the kernel's file service, and what it
//! hears back.
//!
//! `docs/roadmap.md` asks for the VFS as a service over channels rather than a set of system
//! calls, and this is that service's wire format. A program holds a channel endpoint to the
//! service and nothing else: no path reaches a file except through a service that chose to
//! answer it, which is the ABI's rule that authority comes from handles, applied to files.
//!
//! # One message, one operation
//!
//! Every message fits one channel message: 64 bytes, a four-byte header and up to 60 bytes of
//! payload.
//!
//! | byte | request | reply |
//! |---|---|---|
//! | 0 | operation | status |
//! | 1 | argument `a` (a file number) | argument `a` (the file number `open` issued) |
//! | 2 | argument `b` (bytes wanted) | unused |
//! | 3 | payload length | payload length |
//!
//! * `open`: the payload is a path; the reply's `a` is a file number.
//! * `read`: `a` is the file number and `b` the most bytes wanted; the reply's payload is what was
//!   read, empty at the end of the file.
//! * `close`: `a` is the file number.
//!
//! # No panicking paths
//!
//! A user program is linked where `core`'s panicking index path cannot be reached (see
//! `lib/rt`), and this crate is linked into user programs. So nothing here indexes with `[]` or
//! slices with a range: every read is `get`, every write is an iterator.

#![cfg_attr(not(test), no_std)]
#![deny(unsafe_code)]

#[cfg(test)]
mod tests;

/// Bytes in one message: the channel's own limit.
pub const MESSAGE: usize = 64;
/// Bytes of header before the payload.
pub const HEADER: usize = 4;
/// The most payload one message carries.
pub const PAYLOAD: usize = MESSAGE - HEADER;

/// What a request asks for.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum Op {
    Open = 1,
    Read = 2,
    Close = 3,
}

/// How a request went.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum Status {
    Ok = 0,
    /// No file at that path.
    NotFound = 1,
    /// The file number names no open file.
    BadFile = 2,
    /// The message is not a request this service understands.
    BadRequest = 3,
    /// The filesystem failed to read.
    Io = 4,
    /// Every file number is in use.
    Full = 5,
}

impl Status {
    fn from_byte(b: u8) -> Option<Status> {
        Some(match b {
            0 => Status::Ok,
            1 => Status::NotFound,
            2 => Status::BadFile,
            3 => Status::BadRequest,
            4 => Status::Io,
            5 => Status::Full,
            _ => return None,
        })
    }
}

/// One message as bytes, and how many of them are used.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Message {
    pub bytes: [u8; MESSAGE],
    pub len: usize,
}

impl Message {
    fn new(first: u8, a: u8, b: u8, payload: &[u8]) -> Option<Message> {
        if payload.len() > PAYLOAD {
            return None;
        }
        let mut bytes = [0u8; MESSAGE];
        for (dst, src) in bytes.iter_mut().zip([first, a, b, payload.len() as u8]) {
            *dst = src;
        }
        for (dst, src) in bytes.iter_mut().skip(HEADER).zip(payload) {
            *dst = *src;
        }
        Some(Message {
            bytes,
            len: HEADER + payload.len(),
        })
    }

    /// A message with no payload, which always fits.
    fn bare(first: u8, a: u8, b: u8) -> Message {
        let mut bytes = [0u8; MESSAGE];
        for (dst, src) in bytes.iter_mut().zip([first, a, b, 0]) {
            *dst = src;
        }
        Message { bytes, len: HEADER }
    }

    /// The used bytes.
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.get(..self.len).unwrap_or(&[])
    }
}

/// A request to open `path`. `None` if the path does not fit one message.
pub fn open(path: &[u8]) -> Option<Message> {
    Message::new(Op::Open as u8, 0, 0, path)
}

/// A request for up to `max` bytes from file `file`. A request for more than one message
/// holds asks for exactly that much.
pub fn read(file: u8, max: u8) -> Message {
    let max = if usize::from(max) > PAYLOAD {
        PAYLOAD as u8
    } else {
        max
    };
    Message::bare(Op::Read as u8, file, max)
}

/// A request to close file `file`.
pub fn close(file: u8) -> Message {
    Message::bare(Op::Close as u8, file, 0)
}

/// A reply with `status`, argument `a`, and no payload, which always fits.
pub fn status(status: Status, a: u8) -> Message {
    Message::bare(status as u8, a, 0)
}

/// A reply with `status`, argument `a`, and `data` as payload. `None` if `data` does not fit.
pub fn reply(status: Status, a: u8, data: &[u8]) -> Option<Message> {
    Message::new(status as u8, a, 0, data)
}

/// A request, as the service reads it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Request<'a> {
    Open { path: &'a [u8] },
    Read { file: u8, max: u8 },
    Close { file: u8 },
}

/// A reply, as a program reads it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Reply<'a> {
    pub status: Status,
    pub a: u8,
    pub data: &'a [u8],
}

/// The header and payload of `bytes`, if the header's length agrees with what arrived.
fn split(bytes: &[u8]) -> Option<(u8, u8, u8, &[u8])> {
    let first = *bytes.first()?;
    let a = *bytes.get(1)?;
    let b = *bytes.get(2)?;
    let len = usize::from(*bytes.get(3)?);
    if bytes.len() != HEADER + len {
        return None;
    }
    Some((first, a, b, bytes.get(HEADER..)?))
}

/// Read a request. `None` for anything malformed, which the service answers as a bad request
/// rather than guessing.
pub fn parse_request(bytes: &[u8]) -> Option<Request<'_>> {
    let (op, a, b, payload) = split(bytes)?;
    match op {
        1 if !payload.is_empty() => Some(Request::Open { path: payload }),
        2 if payload.is_empty() => Some(Request::Read { file: a, max: b }),
        3 if payload.is_empty() => Some(Request::Close { file: a }),
        _ => None,
    }
}

/// Read a reply. `None` for anything malformed.
pub fn parse_reply(bytes: &[u8]) -> Option<Reply<'_>> {
    let (status, a, _, data) = split(bytes)?;
    Some(Reply {
        status: Status::from_byte(status)?,
        a,
        data,
    })
}

//! The VFS service protocol: what a program says to the kernel's file service, and what it
//! hears back.
//!
//! `docs/roadmap.md` asks for the VFS as a service over channels rather than a set of system
//! calls, and this is that service's wire format. A program holds a channel endpoint to the
//! service and nothing else: no path reaches a file except through a service that chose to
//! answer it, which is the ABI's rule that authority comes from handles, applied to files.
//! Writing is the same rule again: a connection the kernel made read-only is answered
//! [`Status::ReadOnly`] for every request that would change the volume, whatever it asks.
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
//! | 2 | argument `b` (bytes wanted, or open flags) | argument `b` (bytes written) |
//! | 3 | payload length | payload length |
//!
//! * `open`: the payload is a path and `b` the [`flags`]; the reply's `a` is a file number.
//! * `read`: `a` is the file number and `b` the most bytes wanted; the reply's payload is what was
//!   read, empty at the end of the file.
//! * `write`: `a` is the file number and the payload the bytes; the reply's `b` is how many were
//!   written, at the file's offset, which moves past them.
//! * `seek` and `truncate`: `a` is the file number and the payload an eight-byte little-endian
//!   offset or length.
//! * `unlink` and `mkdir`: the payload is a path.
//! * `rename`: the payload is the old path, a zero byte, and the new path, which may name another
//!   directory of the same filesystem.
//! * `statfs`: the payload is a path; the reply's payload is the filesystem covering it — its
//!   allocation unit, how many units it has, how many are free and the longest name it holds, as
//!   [`statfs_answer`] encodes them. A read-side request, so a read-only connection may ask.
//! * `getdents`: `a` is the file number of an open directory and the payload an eight-byte
//!   little-endian index; the reply's payload is that entry as [`dirent_answer`] encodes it, and
//!   empty once the directory has no more. A read-side request, so a read-only connection may list.
//! * `sync`: nothing; every write so far reaches the disk before the reply.
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
#[cfg(test)]
mod write_tests;

/// Bytes in one message: the channel's own limit.
pub const MESSAGE: usize = 64;
/// Bytes of header before the payload.
pub const HEADER: usize = 4;
/// The most payload one message carries.
pub const PAYLOAD: usize = MESSAGE - HEADER;

/// What an `open` asks for, as bits of its `b` argument. No bits is reading only.
pub mod flags {
    /// Writes through the file number are allowed.
    pub const WRITE: u8 = 1 << 0;
    /// Create the file if nothing has the name.
    pub const CREATE: u8 = 1 << 1;
    /// With `CREATE`, refuse a name that exists.
    pub const EXCLUSIVE: u8 = 1 << 2;
    /// With `WRITE`, empty the file.
    pub const TRUNCATE: u8 = 1 << 3;
    /// With `WRITE`, every write goes at the end.
    pub const APPEND: u8 = 1 << 4;
    /// Every bit this protocol defines; a request with any other is malformed.
    pub const ALL: u8 = WRITE | CREATE | EXCLUSIVE | TRUNCATE | APPEND;
}

/// What a request asks for.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum Op {
    Open = 1,
    Read = 2,
    Close = 3,
    Write = 4,
    Seek = 5,
    Truncate = 6,
    Unlink = 7,
    Mkdir = 8,
    Rename = 9,
    Sync = 10,
    Statfs = 11,
    Getdents = 12,
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
    /// The filesystem failed to read or write.
    Io = 4,
    /// Every file number is in use.
    Full = 5,
    /// The connection, the file number or the volume does not allow writing.
    ReadOnly = 6,
    /// A creation named something that exists.
    Exists = 7,
    /// No room left on the volume.
    NoSpace = 8,
    /// A directory to remove, or to replace, is not empty.
    NotEmpty = 9,
    /// A file operation named a directory, or a directory operation a file.
    WrongKind = 10,
    /// A name the volume cannot hold.
    BadName = 11,
    /// A rename whose two paths are on different filesystems, which no rename can cross.
    CrossDevice = 12,
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
            6 => Status::ReadOnly,
            7 => Status::Exists,
            8 => Status::NoSpace,
            9 => Status::NotEmpty,
            10 => Status::WrongKind,
            11 => Status::BadName,
            12 => Status::CrossDevice,
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
        Message::joined(first, a, b, payload, &[])
    }

    /// A message whose payload is `head` then `tail`.
    fn joined(first: u8, a: u8, b: u8, head: &[u8], tail: &[u8]) -> Option<Message> {
        let len = head.len() + tail.len();
        if len > PAYLOAD {
            return None;
        }
        let mut bytes = [0u8; MESSAGE];
        for (dst, src) in bytes.iter_mut().zip([first, a, b, len as u8]) {
            *dst = src;
        }
        for (dst, src) in bytes.iter_mut().skip(HEADER).zip(head.iter().chain(tail)) {
            *dst = *src;
        }
        Some(Message {
            bytes,
            len: HEADER + len,
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

/// A request to open `path` for reading. `None` if the path does not fit one message.
pub fn open(path: &[u8]) -> Option<Message> {
    open_with(path, 0)
}

/// A request to open `path` with [`flags`]. `None` if the path does not fit one message or
/// a flag is not one this protocol defines.
pub fn open_with(path: &[u8], flags: u8) -> Option<Message> {
    if flags & !flags::ALL != 0 {
        return None;
    }
    Message::new(Op::Open as u8, 0, flags, path)
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

/// A request to write `data` to file `file`. `None` if `data` does not fit one message.
pub fn write(file: u8, data: &[u8]) -> Option<Message> {
    Message::new(Op::Write as u8, file, 0, data)
}

/// A request to move file `file`'s offset to `offset`.
pub fn seek(file: u8, offset: u64) -> Message {
    Message::new(Op::Seek as u8, file, 0, &offset.to_le_bytes()).unwrap_or(Message::bare(0, 0, 0))
}

/// A request to make file `file` `len` bytes long.
pub fn truncate(file: u8, len: u64) -> Message {
    Message::new(Op::Truncate as u8, file, 0, &len.to_le_bytes()).unwrap_or(Message::bare(0, 0, 0))
}

/// A request to remove the file or empty directory at `path`.
pub fn unlink(path: &[u8]) -> Option<Message> {
    Message::new(Op::Unlink as u8, 0, 0, path)
}

/// A request to make a directory at `path`.
pub fn mkdir(path: &[u8]) -> Option<Message> {
    Message::new(Op::Mkdir as u8, 0, 0, path)
}

/// A request to rename `from` to `to`. `None` if the two do not fit one message, or `from`
/// holds the zero byte that separates them.
pub fn rename(from: &[u8], to: &[u8]) -> Option<Message> {
    if from.is_empty() || to.is_empty() || from.contains(&0) || to.contains(&0) {
        return None;
    }
    let mut head = [0u8; PAYLOAD];
    let len = from.len().checked_add(1)?;
    let bytes = head.get_mut(..len)?;
    for (dst, src) in bytes.iter_mut().zip(from.iter().chain(&[0])) {
        *dst = *src;
    }
    Message::joined(Op::Rename as u8, 0, 0, head.get(..len)?, to)
}

/// A request to make every write so far durable.
pub fn sync() -> Message {
    Message::bare(Op::Sync as u8, 0, 0)
}

/// A request for what the filesystem covering `path` is. `None` if the path does not fit one
/// message.
pub fn statfs(path: &[u8]) -> Option<Message> {
    Message::new(Op::Statfs as u8, 0, 0, path)
}

/// Bytes a [`Op::Statfs`] answer takes: three eight-byte counts and a four-byte name length.
pub const STATFS_BYTES: usize = 28;

/// A reply carrying what a filesystem is.
pub fn statfs_answer(block_size: u64, blocks: u64, free: u64, name_max: u32) -> Message {
    let mut payload = [0u8; STATFS_BYTES];
    for (dst, src) in payload.iter_mut().zip(
        block_size
            .to_le_bytes()
            .iter()
            .chain(blocks.to_le_bytes().iter())
            .chain(free.to_le_bytes().iter())
            .chain(name_max.to_le_bytes().iter()),
    ) {
        *dst = *src;
    }
    reply(Status::Ok, 0, &payload).unwrap_or(Message::bare(Status::Io as u8, 0, 0))
}

/// What a [`statfs_answer`] carries: the allocation unit, the units there are, the units free,
/// and the longest name. `None` for a payload that is not one.
pub fn parse_statfs(data: &[u8]) -> Option<(u64, u64, u64, u32)> {
    let eight = |at: usize| -> Option<u64> {
        let bytes: [u8; 8] = data.get(at..at + 8)?.try_into().ok()?;
        Some(u64::from_le_bytes(bytes))
    };
    let four: [u8; 4] = data.get(24..28)?.try_into().ok()?;
    Some((eight(0)?, eight(8)?, eight(16)?, u32::from_le_bytes(four)))
}

/// A request for the `index`th entry of the open directory `file`.
pub fn getdents(file: u8, index: u64) -> Message {
    Message::new(Op::Getdents as u8, file, 0, &index.to_le_bytes())
        .unwrap_or(Message::bare(0, 0, 0))
}

/// A reply carrying one directory entry: what it is, then its name.
pub fn dirent_answer(is_dir: bool, name: &[u8]) -> Option<Message> {
    let mut head = [0u8; 1];
    head[0] = u8::from(is_dir);
    Message::joined(Status::Ok as u8, 0, 0, &head, name)
}

/// What a [`dirent_answer`] carries: whether the entry is a directory, and its name. `None`
/// for a payload that is not one; an empty payload is the end of the directory rather than an
/// entry, and is not one of these.
pub fn parse_dirent(data: &[u8]) -> Option<(bool, &[u8])> {
    let kind = *data.first()?;
    let name = data.get(1..)?;
    if kind > 1 || name.is_empty() {
        return None;
    }
    Some((kind == 1, name))
}

/// A request to close file `file`.
pub fn close(file: u8) -> Message {
    Message::bare(Op::Close as u8, file, 0)
}

/// A reply with `status`, argument `a`, and no payload, which always fits.
pub fn status(status: Status, a: u8) -> Message {
    Message::bare(status as u8, a, 0)
}

/// A reply to a write: `n` bytes of file `file` written.
pub fn written(file: u8, n: u8) -> Message {
    Message::bare(Status::Ok as u8, file, n)
}

/// A reply with `status`, argument `a`, and `data` as payload. `None` if `data` does not fit.
pub fn reply(status: Status, a: u8, data: &[u8]) -> Option<Message> {
    Message::new(status as u8, a, 0, data)
}

/// A request, as the service reads it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Request<'a> {
    Open { path: &'a [u8], flags: u8 },
    Read { file: u8, max: u8 },
    Close { file: u8 },
    Write { file: u8, data: &'a [u8] },
    Seek { file: u8, offset: u64 },
    Truncate { file: u8, len: u64 },
    Unlink { path: &'a [u8] },
    Mkdir { path: &'a [u8] },
    Rename { from: &'a [u8], to: &'a [u8] },
    Sync,
    Statfs { path: &'a [u8] },
    Getdents { file: u8, index: u64 },
}

impl Request<'_> {
    /// Whether the request would change the volume, which a read-only connection refuses.
    pub fn writes(&self) -> bool {
        match *self {
            Request::Open { flags, .. } => {
                flags & (flags::WRITE | flags::CREATE | flags::TRUNCATE) != 0
            }
            Request::Read { .. } | Request::Close { .. } | Request::Seek { .. } => false,
            // Asking what a filesystem is, or what a directory holds, changes nothing, so a
            // read-only connection may.
            Request::Sync | Request::Statfs { .. } | Request::Getdents { .. } => false,
            Request::Write { .. }
            | Request::Truncate { .. }
            | Request::Unlink { .. }
            | Request::Mkdir { .. }
            | Request::Rename { .. } => true,
        }
    }
}

/// A reply, as a program reads it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Reply<'a> {
    pub status: Status,
    pub a: u8,
    pub b: u8,
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

fn u64_of(payload: &[u8]) -> Option<u64> {
    let bytes: [u8; 8] = payload.try_into().ok()?;
    Some(u64::from_le_bytes(bytes))
}

/// Read a request. `None` for anything malformed, which the service answers as a bad request
/// rather than guessing.
pub fn parse_request(bytes: &[u8]) -> Option<Request<'_>> {
    let (op, a, b, payload) = split(bytes)?;
    let bare = payload.is_empty() && b == 0;
    match op {
        1 if !payload.is_empty() && b & !flags::ALL == 0 => Some(Request::Open {
            path: payload,
            flags: b,
        }),
        2 if payload.is_empty() => Some(Request::Read { file: a, max: b }),
        3 if payload.is_empty() => Some(Request::Close { file: a }),
        4 if !payload.is_empty() && b == 0 => Some(Request::Write {
            file: a,
            data: payload,
        }),
        5 if b == 0 => Some(Request::Seek {
            file: a,
            offset: u64_of(payload)?,
        }),
        6 if b == 0 => Some(Request::Truncate {
            file: a,
            len: u64_of(payload)?,
        }),
        7 if !payload.is_empty() && b == 0 => Some(Request::Unlink { path: payload }),
        8 if !payload.is_empty() && b == 0 => Some(Request::Mkdir { path: payload }),
        9 if b == 0 => {
            let zero = payload.iter().position(|&c| c == 0)?;
            let from = payload.get(..zero)?;
            let to = payload.get(zero + 1..)?;
            if from.is_empty() || to.is_empty() || to.contains(&0) {
                return None;
            }
            Some(Request::Rename { from, to })
        }
        10 if bare => Some(Request::Sync),
        11 if !payload.is_empty() && b == 0 => Some(Request::Statfs { path: payload }),
        12 if b == 0 => Some(Request::Getdents {
            file: a,
            index: u64_of(payload)?,
        }),
        _ => None,
    }
}

/// Read a reply. `None` for anything malformed.
pub fn parse_reply(bytes: &[u8]) -> Option<Reply<'_>> {
    let (status, a, b, data) = split(bytes)?;
    Some(Reply {
        status: Status::from_byte(status)?,
        a,
        b,
        data,
    })
}

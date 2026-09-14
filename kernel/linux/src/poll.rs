//! What `poll`, `select` and `epoll` hand the kernel: arrays a program filled in itself.
//!
//! Every one of these calls takes a set of descriptors from user memory, and the set is the
//! program's to write: a count that does not match the array, a descriptor number that names
//! nothing, a `struct epoll_event` whose bytes are noise. Nothing here touches a descriptor or
//! waits for anything. It decodes one entry at a time out of bytes the kernel copied in, and
//! encodes what goes back, so the part that can be fed hostile bytes is a pure function the host
//! tests and the fuzzer can reach ([`crate::poll`] is `lib/fuzz`'s `pollset` target).
//!
//! # The three shapes
//!
//! * **`poll`** takes `nfds` entries of [`POLLFD_BYTES`]: a signed descriptor, the events asked
//!   for, and the events that happened, which the kernel writes back. A negative descriptor is
//!   skipped and answers zero, as Linux does.
//! * **`select`** takes three bitmaps of `nfds` bits each, least significant bit first, and
//!   answers with the same bitmaps holding only what is ready. [`FD_SET_BYTES`] caps how much of
//!   one the kernel reads; a program that asks past it is refused rather than truncated
//!   silently.
//! * **`epoll`** keeps its set in the kernel, and `epoll_wait` writes out `struct epoll_event`s.
//!   That structure is packed on x86_64 and aligned on aarch64, so its size is the ABI's
//!   ([`event_bytes`]) and every field is read and written at the offset that ABI gives it.
//!
//! # Timeouts
//!
//! `poll` takes milliseconds, `ppoll` a `struct timespec`, and `select` a `struct timeval`. All
//! three become nanoseconds, with "wait as long as it takes" spelled as `None`. A negative or
//! out-of-range value is [`Failure::InvalidArgument`]: Linux refuses those too, and a timeout
//! that quietly became zero would turn a wait into a spin.

use super::{Abi, Failure};

// ---- poll ---------------------------------------------------------------------------------

/// Readable, and the end of a stream, which a reader must be told about the same way.
pub const POLLIN: u16 = 0x001;
/// Out-of-band data. Nothing here ever reports it; a program may still ask.
pub const POLLPRI: u16 = 0x002;
/// Writable: room for at least one byte.
pub const POLLOUT: u16 = 0x004;
/// An error on the descriptor. Reported whether or not it was asked for.
pub const POLLERR: u16 = 0x008;
/// The other end is gone. Reported whether or not it was asked for.
pub const POLLHUP: u16 = 0x010;
/// The descriptor names nothing. Reported whether or not it was asked for.
pub const POLLNVAL: u16 = 0x020;
/// What a libc asks for instead of `POLLIN` and `POLLOUT`; the same thing here.
pub const POLLRDNORM: u16 = 0x040;
pub const POLLWRNORM: u16 = 0x100;
/// The peer closed its sending half. Asked for explicitly, like `POLLIN`.
pub const POLLRDHUP: u16 = 0x2000;

/// The events a program may ask for. One it asks for outside this set is refused, rather than
/// waited on and never answered.
pub const POLL_ASKABLE: u16 =
    POLLIN | POLLPRI | POLLOUT | POLLRDNORM | POLLWRNORM | POLLRDHUP | POLLERR | POLLHUP;

/// The events the kernel reports whether or not they were asked for.
pub const POLL_ALWAYS: u16 = POLLERR | POLLHUP | POLLNVAL;

/// `struct pollfd`: `int fd`, `short events`, `short revents`. The same on both ABIs.
pub const POLLFD_BYTES: usize = 8;

/// One entry of a `poll` set, as the program wrote it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PollFd {
    /// The descriptor, signed: a negative one is skipped.
    pub fd: i32,
    /// What the program asked to hear about.
    pub events: u16,
}

impl PollFd {
    /// Whether this entry names a descriptor at all. Linux skips a negative one and answers
    /// zero for it.
    pub const fn is_asked(self) -> bool {
        self.fd >= 0
    }
}

/// The entry `bytes` holds.
pub fn parse_pollfd(bytes: &[u8; POLLFD_BYTES]) -> PollFd {
    let fd = i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let events = u16::from_le_bytes([bytes[4], bytes[5]]);
    PollFd { fd, events }
}

/// The two bytes `revents` occupies in an entry, to be written back at offset 6.
pub const REVENTS_AT: usize = 6;

/// What a program is told for an entry: what happened, narrowed to what it asked for plus the
/// three it is told about regardless.
pub const fn revents(asked: u16, happened: u16) -> u16 {
    happened & (asked | POLL_ALWAYS)
}

/// Whether `events` asks only for things this kernel reports.
pub const fn askable(events: u16) -> bool {
    events & !POLL_ASKABLE == 0
}

// ---- select -------------------------------------------------------------------------------

/// Descriptors one `select` bitmap may name here: the personality's own table is far smaller,
/// and a program that asks about more than this is refused rather than quietly told its high
/// descriptors are idle. Linux's own limit is 1024.
pub const FD_SET_BITS: usize = 64;
/// Bytes of a bitmap that holds [`FD_SET_BITS`].
pub const FD_SET_BYTES: usize = FD_SET_BITS / 8;

/// Whether `set` names `fd`. `false` for a descriptor past the bitmap.
pub fn fd_isset(set: &[u8; FD_SET_BYTES], fd: usize) -> bool {
    match set.get(fd / 8) {
        Some(byte) => byte & (1 << (fd % 8)) != 0,
        None => false,
    }
}

/// Name `fd` in `set`. A descriptor past the bitmap is dropped, which cannot happen for one
/// that came out of the same bitmap.
pub fn fd_set(set: &mut [u8; FD_SET_BYTES], fd: usize) {
    if let Some(byte) = set.get_mut(fd / 8) {
        *byte |= 1 << (fd % 8);
    }
}

/// The bytes of a bitmap `nfds` descriptors need, or a refusal for a count past
/// [`FD_SET_BITS`].
pub fn fd_set_bytes(nfds: u64) -> Result<usize, Failure> {
    let nfds = usize::try_from(nfds).map_err(|_| Failure::InvalidArgument)?;
    if nfds > FD_SET_BITS {
        return Err(Failure::InvalidArgument);
    }
    Ok(nfds.div_ceil(8))
}

/// What `select` asks about a descriptor in each of its three bitmaps, as `poll` events.
pub const SELECT_READ: u16 = POLLIN | POLLHUP | POLLERR;
pub const SELECT_WRITE: u16 = POLLOUT | POLLERR;
pub const SELECT_EXCEPT: u16 = POLLPRI;

// ---- epoll --------------------------------------------------------------------------------

pub const EPOLL_CTL_ADD: u64 = 1;
pub const EPOLL_CTL_DEL: u64 = 2;
pub const EPOLL_CTL_MOD: u64 = 3;

pub const EPOLLIN: u32 = 0x001;
pub const EPOLLPRI: u32 = 0x002;
pub const EPOLLOUT: u32 = 0x004;
pub const EPOLLERR: u32 = 0x008;
pub const EPOLLHUP: u32 = 0x010;
pub const EPOLLRDNORM: u32 = 0x040;
pub const EPOLLWRNORM: u32 = 0x100;
pub const EPOLLRDHUP: u32 = 0x2000;
/// Edge-triggered, and one-shot. Neither is built; a program that asks for either is refused,
/// rather than given level-triggered behaviour under an edge-triggered name.
pub const EPOLLET: u32 = 1 << 31;
pub const EPOLLONESHOT: u32 = 1 << 30;
/// `epoll_create1`'s one flag.
pub const EPOLL_CLOEXEC: u64 = super::O_CLOEXEC;

/// The events `epoll_ctl` accepts.
pub const EPOLL_ASKABLE: u32 =
    EPOLLIN | EPOLLPRI | EPOLLOUT | EPOLLERR | EPOLLHUP | EPOLLRDNORM | EPOLLWRNORM | EPOLLRDHUP;

/// `struct epoll_event`, which x86_64 packs and aarch64 aligns: `u32 events` then `u64 data`,
/// at offset 4 packed and offset 8 aligned.
pub const fn event_bytes(abi: Abi) -> usize {
    match abi {
        Abi::X86_64 => 12,
        Abi::Aarch64 => 16,
    }
}

const fn data_at(abi: Abi) -> usize {
    match abi {
        Abi::X86_64 => 4,
        Abi::Aarch64 => 8,
    }
}

/// The largest an entry is on either ABI, so one buffer holds either.
pub const EVENT_BYTES_MAX: usize = 16;

/// One `epoll` entry: the events, and the word the program gets back untouched.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct EpollEvent {
    pub events: u32,
    pub data: u64,
}

/// The entry the first [`event_bytes`] of `bytes` hold, or `None` if they are not all there.
pub fn parse_event(abi: Abi, bytes: &[u8]) -> Option<EpollEvent> {
    let mut events = [0u8; 4];
    let mut data = [0u8; 8];
    for (i, b) in events.iter_mut().enumerate() {
        *b = *bytes.get(i)?;
    }
    for (i, b) in data.iter_mut().enumerate() {
        *b = *bytes.get(data_at(abi) + i)?;
    }
    Some(EpollEvent {
        events: u32::from_le_bytes(events),
        data: u64::from_le_bytes(data),
    })
}

/// `event` as the [`event_bytes`] a program reads, in a buffer that holds either ABI's.
pub fn write_event(abi: Abi, event: EpollEvent) -> [u8; EVENT_BYTES_MAX] {
    let mut out = [0u8; EVENT_BYTES_MAX];
    for (i, b) in event.events.to_le_bytes().into_iter().enumerate() {
        if let Some(slot) = out.get_mut(i) {
            *slot = b;
        }
    }
    for (i, b) in event.data.to_le_bytes().into_iter().enumerate() {
        if let Some(slot) = out.get_mut(data_at(abi) + i) {
            *slot = b;
        }
    }
    out
}

/// The `poll` events an `epoll` interest asks about. The two sets share Linux's numbering, so
/// this is a cast with the flags this kernel refuses already rejected.
pub const fn poll_events(epoll: u32) -> u16 {
    epoll as u16
}

/// The `epoll` events a `poll` answer reports.
pub const fn epoll_events(poll: u16) -> u32 {
    poll as u32
}

// ---- timeouts -----------------------------------------------------------------------------

/// Nanoseconds in a second, and in a millisecond and a microsecond.
const SECOND: u64 = 1_000_000_000;
const MILLISECOND: u64 = 1_000_000;
const MICROSECOND: u64 = 1_000;

/// `poll`'s timeout: milliseconds, with a negative value meaning no deadline.
pub fn timeout_ms(ms: u64) -> Option<u64> {
    let ms = ms as i64;
    if ms < 0 {
        return None;
    }
    Some((ms as u64).saturating_mul(MILLISECOND))
}

/// `struct timespec` and `struct timeval`: two 64-bit words on both ABIs.
pub const TIMESPEC_BYTES: usize = 16;

/// The nanoseconds a `struct timespec` names, or a refusal for one Linux would refuse: a
/// negative field, or nanoseconds past a second.
pub fn timespec_ns(bytes: &[u8; TIMESPEC_BYTES]) -> Result<u64, Failure> {
    two_words(bytes, SECOND, 1)
}

/// The nanoseconds a `struct timeval` names, refusing one past a second's worth of
/// microseconds.
pub fn timeval_ns(bytes: &[u8; TIMESPEC_BYTES]) -> Result<u64, Failure> {
    two_words(bytes, SECOND / MICROSECOND, MICROSECOND)
}

/// Seconds and a fraction, as `timespec` and `timeval` both spell them: the fraction is
/// refused at `fraction_limit` and scaled by `scale` nanoseconds.
fn two_words(bytes: &[u8; TIMESPEC_BYTES], fraction_limit: u64, scale: u64) -> Result<u64, Failure> {
    let mut seconds = [0u8; 8];
    let mut fraction = [0u8; 8];
    seconds.copy_from_slice(&bytes[..8]);
    fraction.copy_from_slice(&bytes[8..]);
    let seconds = i64::from_le_bytes(seconds);
    let fraction = i64::from_le_bytes(fraction);
    if seconds < 0 || fraction < 0 || fraction as u64 >= fraction_limit {
        return Err(Failure::InvalidArgument);
    }
    Ok((seconds as u64)
        .saturating_mul(SECOND)
        .saturating_add((fraction as u64).saturating_mul(scale)))
}

#[cfg(test)]
mod tests;

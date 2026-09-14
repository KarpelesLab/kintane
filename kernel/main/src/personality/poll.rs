//! `poll`, `select` and `epoll`: waiting on several descriptors at once.
//!
//! A program that has two things to wait for cannot use `read`: whichever it calls first is the
//! one it is deaf to the other on. These three calls are how a Linux program says "tell me which
//! of these is ready", and the first thing anything ported needs.
//!
//! # One wait, whatever the spelling
//!
//! `poll` and `ppoll` take an array of `struct pollfd`; `select` and `pselect6` take three
//! bitmaps; `epoll_wait` takes a set the kernel already holds. All three end in [`wait`], which
//! loops over the set asking each descriptor what it is ready for, and blocks on
//! [`crate::readiness`]'s queue — the one every readiness change wakes — until something is, the
//! deadline passes, the process ends, or a signal with a handler arrives (`EINTR`).
//!
//! Readiness itself is per descriptor and takes nothing: a pipe with bytes stays full, a socket
//! with a segment keeps it. So a program told a descriptor is readable and then reading it is
//! the only thing that consumes anything, and two threads watching one descriptor both get told.
//!
//! # Level-triggered only
//!
//! A descriptor that is ready is reported every time it is asked about, which is what `poll` and
//! `select` mean and what `epoll` does without `EPOLLET`. Edge-triggered (`EPOLLET`) and
//! one-shot (`EPOLLONESHOT`) are refused with `EINVAL` rather than accepted and quietly given
//! level-triggered behaviour, which would be a program waiting for an edge that never comes.
//!
//! # What each descriptor reports
//!
//! | kind | readable | writable | other |
//! |---|---|---|---|
//! | standard input | always: it reads as the end of file | never | |
//! | the console | never | always | |
//! | a file | when open for reading | when open for writing | |
//! | a pipe's read end | bytes queued | never | `POLLHUP` once no writer is left |
//! | a pipe's write end | never | room in the pipe | `POLLERR` once no reader is left |
//! | a socket | bytes queued, the peer's close, or a connection to accept | room in the send ring | `POLLRDHUP`, `POLLERR` |
//! | an `epoll` set | one of its members is ready | never | |
//!
//! A descriptor that names nothing is `POLLNVAL` on that entry, not `EBADF` for the call: Linux
//! reports it per entry, and a set is usually built once and used while descriptors come and go.
//!
//! # The signal mask
//!
//! `ppoll`, `pselect6` and `epoll_pwait` take a mask to wear while they wait. It is applied and
//! restored around the wait, so a signal a program blocked outside the wait can still end it —
//! which is the whole point of those three calls over their plain forms.

use linux::Failure;
use linux::poll::{self, EpollEvent, PollFd};
use sync::SpinLock;
use sync::lockdep::LockClass;
use time::Instant;

use super::{Descriptor, descriptor_of, from_user, locked, to_user};
use crate::{preempt, timekeeping, userproc};

/// `epoll` sets a process can hold at once, and members one set holds.
const SETS: usize = 4;
const MEMBERS: usize = 8;

/// One member of an `epoll` set: the descriptor watched, what it is watched for, and the word
/// the program gets back when it is ready.
#[derive(Clone, Copy, PartialEq, Eq)]
struct Member {
    fd: u64,
    events: u32,
    data: u64,
    used: bool,
}

const NO_MEMBER: Member = Member {
    fd: 0,
    events: 0,
    data: 0,
    used: false,
};

/// One `epoll` set.
#[derive(Clone, Copy)]
struct Set {
    used: bool,
    /// Descriptors naming it, in every process: a `fork`'s copy adds one.
    refs: u32,
    members: [Member; MEMBERS],
}

const NO_SET: Set = Set {
    used: false,
    refs: 0,
    members: [NO_MEMBER; MEMBERS],
};

static SETS_CLASS: LockClass = LockClass::new("linux.epoll");
/// Every `epoll` set. Held only to look at or change one: never while waiting or copying, and
/// nothing is taken inside it.
static TABLE: SpinLock<[Set; SETS], arch::Cpu> = SpinLock::with_class([NO_SET; SETS], &SETS_CLASS);

/// One more descriptor names set `i`: a `fork`'s copy.
pub(super) fn add_ref(i: usize) {
    if let Some(s) = TABLE.lock_irqsave().get_mut(i) {
        s.refs += 1;
    }
}

/// A descriptor naming set `i` is gone; the last one frees it.
pub(super) fn drop_ref(i: usize) {
    let mut table = TABLE.lock_irqsave();
    if let Some(s) = table.get_mut(i) {
        s.refs = s.refs.saturating_sub(1);
        if s.refs == 0 {
            *s = NO_SET;
        }
    }
}

/// Whether every set is free: what a moment with no `epoll` open shows.
pub(super) fn table_empty() -> bool {
    TABLE.lock_irqsave().iter().all(|s| !s.used)
}

// ---- readiness ------------------------------------------------------------------------------

/// What descriptor `fd` of process `slot` is ready for, as `poll` events. A descriptor that
/// names nothing is `POLLNVAL`.
fn ready_of(slot: usize, fd: u64) -> u16 {
    let Ok((d, _)) = descriptor_of(slot, fd) else {
        return poll::POLLNVAL;
    };
    match d {
        // Nothing feeds standard input, so a read answers the end of file at once, which a
        // waiter must be told about as readable.
        Descriptor::Stdin => poll::POLLIN,
        Descriptor::Console(_) => poll::POLLOUT,
        Descriptor::File {
            readable, writable, ..
        } => {
            let mut bits = 0;
            if readable {
                bits |= poll::POLLIN;
            }
            if writable {
                bits |= poll::POLLOUT;
            }
            bits
        }
        Descriptor::PipeRead(pipe) => super::pipe_read_ready(pipe),
        Descriptor::PipeWrite(pipe) => super::pipe_write_ready(pipe),
        Descriptor::Socket(i) => super::socket::ready(i),
        Descriptor::Epoll(i) => {
            if set_ready(slot, i) {
                poll::POLLIN
            } else {
                0
            }
        }
        Descriptor::Closed => poll::POLLNVAL,
    }
}

/// Whether any member of set `i` is ready. A set watching itself is not followed: its members'
/// readiness is what it reports, and a set inside a set reports its own members in turn.
fn set_ready(slot: usize, i: usize) -> bool {
    let members = match TABLE.lock_irqsave().get(i) {
        Some(set) if set.used => set.members,
        _ => return false,
    };
    members
        .iter()
        .any(|m| m.used && poll::revents(poll::poll_events(m.events), ready_of(slot, m.fd)) != 0)
}

// ---- the wait -------------------------------------------------------------------------------

/// Wait until `look` finds something, the deadline passes, the process ends, or a signal with a
/// handler arrives. `look` returns how many members are ready; zero means wait on.
///
/// `timeout_ns` of `None` waits for as long as it takes, and `Some(0)` answers at once, which is
/// how `poll` with a zero timeout and `select` with a zero `timeval` ask "who is ready now".
fn wait(
    slot: usize,
    timeout_ns: Option<u64>,
    mask: Option<u64>,
    mut look: impl FnMut() -> Result<u64, Failure>,
) -> Result<u64, Failure> {
    let restore = mask.and_then(|m| super::signals::wear_mask(slot, m));
    let result = waiting(slot, timeout_ns, &mut look);
    if let Some(old) = restore {
        super::signals::restore_mask(slot, old);
    }
    result
}

fn waiting(
    slot: usize,
    timeout_ns: Option<u64>,
    look: &mut impl FnMut() -> Result<u64, Failure>,
) -> Result<u64, Failure> {
    let found = look()?;
    if found > 0 || timeout_ns == Some(0) {
        return Ok(found);
    }
    let until = timeout_ns.map(|ns| timekeeping::now().as_nanos().saturating_add(ns));
    let queue = crate::readiness::queue();
    loop {
        // A socket in the set can change without a frame arriving — a retransmission, a
        // connection timing out — so a wait looks again at the stack's next TCP timer.
        let due = crate::sockets::next_look();
        let deadline = match (until, due) {
            (Some(until), Some(due)) => Some(until.min(due)),
            (until, due) => until.or(due),
        };
        let got = queue.wait_once(deadline.map(Instant::from_nanos), || {
            if userproc::exiting(slot) {
                return Some(Err(Failure::Io));
            }
            if super::signals::interrupting(slot) {
                super::signals::blocked_call_interrupted();
                return Some(Err(Failure::Interrupted));
            }
            match look() {
                Ok(0) => None,
                other => Some(other),
            }
        });
        if let Some(result) = got {
            return result;
        }
        // Before the scheduler runs nothing can make a descriptor ready, and a wait cannot
        // block: answer with nothing ready rather than spin.
        if !preempt::scheduled() {
            return Ok(0);
        }
        if until.is_some_and(|u| timekeeping::now().as_nanos() >= u) {
            return Ok(0);
        }
    }
}

// ---- poll and ppoll ---------------------------------------------------------------------------

/// `poll`, and with `timeout_at` and `mask_at` `ppoll`: `nfds` entries at `fds`.
pub(super) fn poll_call(
    slot: usize,
    fds: u64,
    nfds: u64,
    timeout: u64,
    timespec: bool,
    mask_at: u64,
) -> Result<u64, Failure> {
    let count = usize::try_from(nfds).map_err(|_| Failure::InvalidArgument)?;
    if count > super::MAX_FDS {
        return Err(Failure::InvalidArgument);
    }
    let timeout_ns = if timespec {
        read_timespec(timeout, false)?
    } else {
        poll::timeout_ms(timeout)
    };
    let mask = read_mask(mask_at)?;
    // Read once: the entries a program asks about are the ones it wrote before the call.
    let mut entries = [PollFd { fd: -1, events: 0 }; super::MAX_FDS];
    for (i, entry) in entries.iter_mut().enumerate().take(count) {
        let mut bytes = [0u8; poll::POLLFD_BYTES];
        from_user(at(fds, i * poll::POLLFD_BYTES)?, &mut bytes)?;
        *entry = poll::parse_pollfd(&bytes);
        if !poll::askable(entry.events) {
            return Err(Failure::InvalidArgument);
        }
    }
    let mut answers = [0u16; super::MAX_FDS];
    let found = wait(slot, timeout_ns, mask, || {
        let mut ready = 0;
        for (i, entry) in entries.iter().enumerate().take(count) {
            let bits = if entry.is_asked() {
                poll::revents(entry.events, ready_of(slot, entry.fd as u64))
            } else {
                0
            };
            if let Some(slot) = answers.get_mut(i) {
                *slot = bits;
            }
            if bits != 0 {
                ready += 1;
            }
        }
        Ok(ready)
    })?;
    for (i, bits) in answers.iter().enumerate().take(count) {
        to_user(at(fds, i * poll::POLLFD_BYTES + poll::REVENTS_AT)?, &bits.to_le_bytes())?;
    }
    Ok(found)
}

// ---- select and pselect6 ------------------------------------------------------------------

/// `select`, and with `timespec` `pselect6`: three bitmaps of `nfds` bits.
pub(super) fn select_call(
    slot: usize,
    nfds: u64,
    read_at: u64,
    write_at: u64,
    except_at: u64,
    timeout: u64,
    timespec: bool,
    mask_at: u64,
) -> Result<u64, Failure> {
    let bytes = poll::fd_set_bytes(nfds)?;
    let count = usize::try_from(nfds).map_err(|_| Failure::InvalidArgument)?;
    let timeout_ns = read_timespec(timeout, !timespec)?;
    let mask = read_mask(mask_at)?;
    let asked = [
        read_set(read_at, bytes)?,
        read_set(write_at, bytes)?,
        read_set(except_at, bytes)?,
    ];
    let wanted = [poll::SELECT_READ, poll::SELECT_WRITE, poll::SELECT_EXCEPT];
    let mut answers = [[0u8; poll::FD_SET_BYTES]; 3];
    let found = wait(slot, timeout_ns, mask, || {
        let mut ready = 0;
        answers = [[0u8; poll::FD_SET_BYTES]; 3];
        for fd in 0..count {
            let asked_here = asked.iter().any(|set| poll::fd_isset(set, fd));
            if !asked_here {
                continue;
            }
            let bits = ready_of(slot, fd as u64);
            for ((set, want), answer) in asked.iter().zip(wanted).zip(answers.iter_mut()) {
                if poll::fd_isset(set, fd) && bits & want != 0 {
                    poll::fd_set(answer, fd);
                    ready += 1;
                }
            }
        }
        Ok(ready)
    })?;
    for (at, answer) in [read_at, write_at, except_at].into_iter().zip(answers) {
        if at != 0 {
            to_user(at, answer.get(..bytes).unwrap_or(&[]))?;
        }
    }
    Ok(found)
}

// ---- epoll ----------------------------------------------------------------------------------

pub(super) fn epoll_create1(slot: usize, flags: u64) -> Result<u64, Failure> {
    if flags & !poll::EPOLL_CLOEXEC != 0 {
        return Err(Failure::InvalidArgument);
    }
    let i = {
        let mut table = TABLE.lock_irqsave();
        let i = table
            .iter()
            .position(|s| !s.used)
            .ok_or(Failure::TooManyOpen)?;
        table[i] = Set {
            used: true,
            refs: 1,
            members: [NO_MEMBER; MEMBERS],
        };
        i
    };
    let placed = locked(slot, |_, s| s.place(Descriptor::Epoll(i), flags));
    if placed.is_err() {
        drop_ref(i);
    }
    placed.map(|fd| fd as u64)
}

pub(super) fn epoll_ctl(
    slot: usize,
    epfd: u64,
    op: u64,
    fd: u64,
    event_at: u64,
) -> Result<u64, Failure> {
    let i = match descriptor_of(slot, epfd)? {
        (Descriptor::Epoll(i), _) => i,
        _ => return Err(Failure::InvalidArgument),
    };
    // A set watching itself would be a set whose readiness is its own: refused, as on Linux.
    if matches!(descriptor_of(slot, fd), Ok((Descriptor::Epoll(j), _)) if j == i) {
        return Err(Failure::InvalidArgument);
    }
    // The descriptor must name something, whatever the operation does with it.
    descriptor_of(slot, fd)?;
    let event = if op == poll::EPOLL_CTL_DEL {
        EpollEvent { events: 0, data: 0 }
    } else {
        let mut bytes = [0u8; poll::EVENT_BYTES_MAX];
        let len = poll::event_bytes(super::ABI);
        from_user(event_at, bytes.get_mut(..len).ok_or(Failure::Fault)?)?;
        let event = poll::parse_event(super::ABI, &bytes).ok_or(Failure::Fault)?;
        if event.events & !poll::EPOLL_ASKABLE != 0 {
            // `EPOLLET` and `EPOLLONESHOT` land here: not built, and not pretended.
            return Err(Failure::InvalidArgument);
        }
        event
    };
    let mut table = TABLE.lock_irqsave();
    let set = table
        .get_mut(i)
        .filter(|s| s.used)
        .ok_or(Failure::BadDescriptor)?;
    let held = set.members.iter().position(|m| m.used && m.fd == fd);
    match op {
        poll::EPOLL_CTL_ADD => {
            if held.is_some() {
                return Err(Failure::Exists);
            }
            let free = set
                .members
                .iter()
                .position(|m| !m.used)
                .ok_or(Failure::NoSpace)?;
            set.members[free] = Member {
                fd,
                events: event.events,
                data: event.data,
                used: true,
            };
        }
        poll::EPOLL_CTL_MOD => {
            let at = held.ok_or(Failure::NotFound)?;
            set.members[at].events = event.events;
            set.members[at].data = event.data;
        }
        poll::EPOLL_CTL_DEL => {
            let at = held.ok_or(Failure::NotFound)?;
            set.members[at] = NO_MEMBER;
        }
        _ => return Err(Failure::InvalidArgument),
    }
    Ok(0)
}

pub(super) fn epoll_wait(
    slot: usize,
    epfd: u64,
    events_at: u64,
    max: u64,
    timeout: u64,
    mask_at: u64,
) -> Result<u64, Failure> {
    let i = match descriptor_of(slot, epfd)? {
        (Descriptor::Epoll(i), _) => i,
        _ => return Err(Failure::InvalidArgument),
    };
    let max = usize::try_from(max)
        .ok()
        .filter(|m| *m > 0)
        .ok_or(Failure::InvalidArgument)?
        .min(MEMBERS);
    let timeout_ns = poll::timeout_ms(timeout);
    let mask = read_mask(mask_at)?;
    let entry_bytes = poll::event_bytes(super::ABI);
    // Written first, so the answer cannot fault once the wait has found something.
    for n in 0..max {
        to_user(at(events_at, n * entry_bytes)?, &[0u8; poll::EVENT_BYTES_MAX][..entry_bytes])?;
    }
    let mut answers = [EpollEvent { events: 0, data: 0 }; MEMBERS];
    let found = wait(slot, timeout_ns, mask, || {
        let members = match TABLE.lock_irqsave().get(i) {
            Some(set) if set.used => set.members,
            _ => return Err(Failure::BadDescriptor),
        };
        let mut ready = 0;
        for member in members.iter().filter(|m| m.used) {
            let bits = poll::revents(poll::poll_events(member.events), ready_of(slot, member.fd));
            if bits == 0 {
                continue;
            }
            if let Some(slot) = answers.get_mut(ready) {
                *slot = EpollEvent {
                    events: poll::epoll_events(bits),
                    data: member.data,
                };
            }
            ready += 1;
            if ready >= max {
                break;
            }
        }
        Ok(ready as u64)
    })?;
    for (n, event) in answers.iter().enumerate().take(found as usize) {
        let bytes = poll::write_event(super::ABI, *event);
        to_user(at(events_at, n * entry_bytes)?, bytes.get(..entry_bytes).unwrap_or(&[]))?;
    }
    Ok(found)
}

// ---- the small readers ------------------------------------------------------------------------

/// The user address `offset` bytes past `base`.
fn at(base: u64, offset: usize) -> Result<u64, Failure> {
    base.checked_add(offset as u64).ok_or(Failure::Fault)
}

/// The bitmap at `at`, or an empty one for a null pointer, which is how `select` says "none".
fn read_set(at: u64, bytes: usize) -> Result<[u8; poll::FD_SET_BYTES], Failure> {
    let mut set = [0u8; poll::FD_SET_BYTES];
    if at != 0 && bytes > 0 {
        from_user(at, set.get_mut(..bytes).ok_or(Failure::InvalidArgument)?)?;
    }
    Ok(set)
}

/// The timeout a `struct timespec` or `struct timeval` at `at` names; a null pointer is no
/// deadline, as both calls spell it.
fn read_timespec(at: u64, timeval: bool) -> Result<Option<u64>, Failure> {
    if at == 0 {
        return Ok(None);
    }
    let mut bytes = [0u8; poll::TIMESPEC_BYTES];
    from_user(at, &mut bytes)?;
    if timeval {
        poll::timeval_ns(&bytes).map(Some)
    } else {
        poll::timespec_ns(&bytes).map(Some)
    }
}

/// The signal mask at `at`, for the `p` forms; a null pointer leaves the thread's mask alone.
fn read_mask(at: u64) -> Result<Option<u64>, Failure> {
    if at == 0 {
        return Ok(None);
    }
    let mut bytes = [0u8; 8];
    from_user(at, &mut bytes)?;
    Ok(Some(u64::from_le_bytes(bytes)))
}

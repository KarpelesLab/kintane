//! The channel: two endpoints, two bounded inboxes, and the rules for moving handles
//! between handle tables through them. See the crate documentation for the model;
//! this file is the mechanism, and the comments at each commit point say why it is
//! all-or-nothing.

use kobject::handle::{self, Entry, Handle, HandleTable};
use kobject::{ObjectId, ObjectIds, ObjectType, Rights};

use crate::inbox::Inbox;
use crate::lock::LockFamily;

/// Which end of a channel.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Side {
    A,
    B,
}

impl Side {
    /// The other end.
    pub const fn peer(self) -> Side {
        match self {
            Side::A => Side::B,
            Side::B => Side::A,
        }
    }
}

/// A handle to move with a message, and the rights it may keep on arrival.
///
/// `mask` can only remove rights: the receiver gets `held.narrow(mask)`. Asking for more
/// than the sender holds yields what the sender holds.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Transfer {
    pub handle: Handle,
    pub mask: Rights,
}

impl Transfer {
    /// Move a handle with every right it has.
    pub const fn whole(handle: Handle) -> Transfer {
        Transfer {
            handle,
            mask: Rights::ALL,
        }
    }

    /// Move a handle, keeping at most `mask`.
    pub const fn narrowed(handle: Handle, mask: Rights) -> Transfer {
        Transfer { handle, mask }
    }
}

/// What a successful receive delivered.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Received {
    /// Bytes written to the front of the caller's byte buffer.
    pub bytes: usize,
    /// Handles written to the front of the caller's handle buffer, in the order sent.
    pub handles: usize,
}

/// An endpoint's observable state.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Status {
    /// Messages waiting to be received on this endpoint.
    pub queued: usize,
    /// A send from this endpoint would find room: the peer is open and its inbox is not
    /// full.
    pub writable: bool,
    /// The peer endpoint's last reference is gone. Nothing more will arrive once
    /// `queued` reaches zero.
    pub peer_closed: bool,
}

/// Why a channel operation failed.
///
/// Every failure leaves every handle table and every queue exactly as it was, with one
/// cosmetic exception noted on [`Error::NoRoom`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Error {
    /// The endpoint handle is invalid, not a channel, or lacks the right the operation
    /// needs (`WRITE` to send, `READ` to receive, `WAIT` to observe, `DUPLICATE` to
    /// duplicate).
    Endpoint(handle::Error),
    /// The handle names a channel endpoint, but not one of this channel's.
    NotThisChannel,
    /// The endpoint's references are all gone. Reachable only through a handle to it
    /// that was created or copied without going through this channel's accounting.
    Closed,
    /// More bytes or handles than one message on this channel may carry.
    TooLarge { bytes: usize, handles: usize },
    /// The handle at `index` in the transfer list is invalid or lacks `TRANSFER`.
    Transfer { index: usize, error: handle::Error },
    /// The handle at `index` already appears earlier in the transfer list.
    DuplicateTransfer { index: usize },
    /// The handle at `index` names an endpoint of this same channel. Refused, because
    /// an endpoint reachable only through its own queue can never be closed.
    WouldCycle { index: usize },
    /// The peer's inbox is at capacity. Nothing was sent and nothing was overwritten.
    Full,
    /// The peer endpoint is closed; nothing sent now could ever be received.
    PeerClosed,
    /// Nothing queued, and the peer is still open: try again later.
    Empty,
    /// The front message needs larger buffers than were supplied. It stays queued.
    BufferTooSmall { bytes: usize, handles: usize },
    /// The receiver's handle table could not hold all `handles` the front message
    /// carries. The message stays queued with every handle; nothing was installed.
    ///
    /// Slots that were filled and then rolled back have had their generation advanced,
    /// exactly as if a handle had been opened and closed there. No handle value was
    /// ever returned for them.
    NoRoom {
        handles: usize,
        error: handle::Error,
    },
    /// The endpoint's reference count is at its maximum.
    TooManyRefs,
    /// A release for an endpoint that holds no references: a double release.
    NotHeld,
}

/// One endpoint's state.
struct End<const D: usize, const B: usize, const H: usize> {
    /// Entries naming this endpoint that exist anywhere — in a handle table, in a queued
    /// message on some channel, or in a caller's hands on their way to one of those.
    refs: u32,
    /// False once `refs` has reached zero. Never becomes true again.
    open: bool,
    /// Messages the peer sent that this endpoint has not received.
    inbox: Inbox<D, B, H>,
}

struct State<const D: usize, const B: usize, const H: usize> {
    a: End<D, B, H>,
    b: End<D, B, H>,
}

impl<const D: usize, const B: usize, const H: usize> State<D, B, H> {
    /// `(this side, the peer)`.
    fn ends(&mut self, side: Side) -> (&mut End<D, B, H>, &mut End<D, B, H>) {
        match side {
            Side::A => (&mut self.a, &mut self.b),
            Side::B => (&mut self.b, &mut self.a),
        }
    }
}

/// Endpoint rights a freshly created channel typically hands out.
pub const ENDPOINT_RIGHTS: Rights = Rights::READ
    .union(Rights::WRITE)
    .union(Rights::TRANSFER)
    .union(Rights::DUPLICATE)
    .union(Rights::WAIT)
    .union(Rights::INSPECT);

/// A channel: `DEPTH` messages per direction, each up to `BYTES` bytes and `HANDLES`
/// handles, protected by lock family `L`.
///
/// All storage is inline and fixed at creation: `2 * DEPTH * (BYTES + HANDLES * 16)`
/// bytes and change. Nothing a sender does can make the channel grow.
pub struct Channel<
    L: LockFamily,
    const DEPTH: usize = 8,
    const BYTES: usize = 128,
    const HANDLES: usize = 4,
> {
    a: ObjectId,
    b: ObjectId,
    state: L::Lock<State<DEPTH, BYTES, HANDLES>>,
}

impl<L: LockFamily, const D: usize, const B: usize, const H: usize> Channel<L, D, B, H> {
    /// Create a channel with both endpoints open.
    ///
    /// Returns one entry per endpoint (`[A, B]`), each carrying `rights` and each
    /// **being** that endpoint's only reference. Install each into a handle table, or
    /// give it back with [`Channel::release`]; an entry that is simply dropped holds its
    /// endpoint open for ever, and the peer will never observe closure.
    #[must_use = "each entry is an endpoint reference that must be installed or released"]
    pub fn new(ids: &ObjectIds, rights: Rights) -> (Self, [Entry; 2]) {
        let a = ids.next();
        let b = ids.next();
        let end = || End {
            refs: 1,
            open: true,
            inbox: Inbox::new(),
        };
        let channel = Channel {
            a,
            b,
            state: L::new(State { a: end(), b: end() }),
        };
        let entry = |object| Entry {
            object,
            kind: ObjectType::Channel,
            rights,
        };
        (channel, [entry(a), entry(b)])
    }

    /// The object identity of one endpoint.
    pub fn id(&self, side: Side) -> ObjectId {
        match side {
            Side::A => self.a,
            Side::B => self.b,
        }
    }

    /// Which endpoint of this channel `object` is, if either.
    pub fn side_of(&self, object: ObjectId) -> Option<Side> {
        if object == self.a {
            Some(Side::A)
        } else if object == self.b {
            Some(Side::B)
        } else {
            None
        }
    }

    fn side_of_entry(&self, entry: Entry) -> Result<Side, Error> {
        if entry.kind != ObjectType::Channel {
            return Err(Error::Endpoint(handle::Error::WrongType {
                expected: ObjectType::Channel,
                found: entry.kind,
            }));
        }
        self.side_of(entry.object).ok_or(Error::NotThisChannel)
    }

    /// Resolve an endpoint handle: live, a channel, carrying `required`, and ours.
    fn endpoint<const N: usize>(
        &self,
        table: &HandleTable<N>,
        endpoint: Handle,
        required: Rights,
    ) -> Result<Side, Error> {
        let entry = table
            .get_checked(endpoint, ObjectType::Channel, required)
            .map_err(Error::Endpoint)?;
        self.side_of(entry.object).ok_or(Error::NotThisChannel)
    }

    /// Send a message from the endpoint `endpoint` names, moving `handles` out of
    /// `table` and into the message.
    ///
    /// **All or nothing.** On success every listed handle has left `table` and is in
    /// the peer's inbox. On any error every listed handle is still in `table` under the
    /// same handle value with the same rights, and the peer's inbox is unchanged.
    ///
    /// Does not block: a full inbox is [`Error::Full`].
    pub fn send<const N: usize>(
        &self,
        table: &mut HandleTable<N>,
        endpoint: Handle,
        bytes: &[u8],
        handles: &[Transfer],
    ) -> Result<(), Error> {
        let side = self.endpoint(table, endpoint, Rights::WRITE)?;
        if bytes.len() > B || handles.len() > H {
            return Err(Error::TooLarge {
                bytes: bytes.len(),
                handles: handles.len(),
            });
        }

        // Phase 1: prove, without changing anything, that every handle can be moved.
        // These are precisely the checks `transfer_out` makes — the handle is live and
        // carries TRANSFER — plus the two it cannot make because it sees one handle at a
        // time: no handle listed twice (the second `transfer_out` would find it gone
        // after the first had succeeded), and no endpoint of this channel.
        for (index, t) in handles.iter().enumerate() {
            let entry = table
                .get(t.handle)
                .map_err(|error| Error::Transfer { index, error })?;
            if !entry.rights.contains(Rights::TRANSFER) {
                return Err(Error::Transfer {
                    index,
                    error: handle::Error::AccessDenied {
                        required: Rights::TRANSFER,
                        held: entry.rights,
                    },
                });
            }
            if handles.iter().take(index).any(|p| p.handle == t.handle) {
                return Err(Error::DuplicateTransfer { index });
            }
            if entry.kind == ObjectType::Channel && self.side_of(entry.object).is_some() {
                return Err(Error::WouldCycle { index });
            }
        }

        L::with(&self.state, |st| {
            let (mine, peer) = st.ends(side);
            if !mine.open {
                return Err(Error::Closed);
            }
            if !peer.open {
                return Err(Error::PeerClosed);
            }
            // The slot is reserved *before* any handle moves, and the lock is held from
            // here to the commit, so the queue cannot fill underneath us. This ordering
            // is the whole reason the queue-full case needs no rollback.
            let Some(mut slot) = peer.inbox.vacant() else {
                return Err(Error::Full);
            };

            // Phase 2: move. `table` has been exclusively borrowed since phase 1, so
            // nothing can have closed, replaced or re-righted any of these handles, and
            // phase 1 ruled out the one way this loop could invalidate its own later
            // input. `transfer_out` therefore cannot fail here.
            //
            // It still returns a `Result`, and kobject has no two-phase transfer that
            // would let the type system know this, so the arm exists. It puts back what
            // it took. Reinstallation gives new handle values, and could itself fail if
            // a slot just vacated was retired — which is why it is asserted unreachable
            // in debug builds rather than trusted as a recovery path.
            let mut moved = 0usize;
            let mut failure = None;
            for (dst, t) in slot.handle_slots().zip(handles) {
                match table.transfer_out(t.handle) {
                    Ok(entry) => {
                        *dst = Some(entry);
                        moved += 1;
                    }
                    Err(error) => {
                        failure = Some(Error::Transfer {
                            index: moved,
                            error,
                        });
                        break;
                    }
                }
            }
            if let Some(err) = failure {
                debug_assert!(false, "transfer_out failed after validation: {err:?}");
                for entry in slot.unstage().into_iter().flatten() {
                    let _ = table.insert(entry.object, entry.kind, entry.rights);
                }
                return Err(err);
            }

            // Narrow last, so that the rollback above would have reinstalled the rights
            // the sender actually held rather than the rights it was sending.
            for (dst, t) in slot.handle_slots().zip(handles) {
                if let Some(entry) = dst {
                    entry.rights = entry.rights.narrow(t.mask);
                }
            }
            slot.commit(bytes);
            Ok(())
        })
    }

    /// Receive the front message on the endpoint `endpoint` names, installing its
    /// handles in `table`.
    ///
    /// **All or nothing.** On success the message has left the queue, its bytes are at
    /// the front of `bytes` and its handles — now live in `table` — at the front of
    /// `handles`. On any error the message is still at the front of the queue with every
    /// handle it carried, and `table` holds no new handle.
    ///
    /// An empty queue is [`Error::Empty`] while the peer is open and
    /// [`Error::PeerClosed`] once it is not.
    pub fn receive<const N: usize>(
        &self,
        table: &mut HandleTable<N>,
        endpoint: Handle,
        bytes: &mut [u8],
        handles: &mut [Handle],
    ) -> Result<Received, Error> {
        let side = self.endpoint(table, endpoint, Rights::READ)?;

        L::with(&self.state, |st| {
            let (mine, peer) = st.ends(side);
            if !mine.open {
                return Err(Error::Closed);
            }
            let Some(msg) = mine.inbox.front() else {
                return Err(if peer.open {
                    Error::Empty
                } else {
                    Error::PeerClosed
                });
            };
            let got = Received {
                bytes: msg.bytes().len(),
                handles: msg.handle_count(),
            };
            if got.bytes > bytes.len() || got.handles > handles.len() {
                return Err(Error::BufferTooSmall {
                    bytes: got.bytes,
                    handles: got.handles,
                });
            }

            // Install, then remove from the queue — never the other way round. Until
            // the `discard_front` below, every entry is still in the message, so a
            // failure part-way has only to undo the installs it made.
            //
            // A `HandleTable` cannot say in advance whether it has room for `k` more
            // (retired slots are invisible from outside), so room is found out by
            // trying. Undoing an install is a `close` of a handle that was created a
            // moment ago under this same exclusive borrow and never returned, so it
            // cannot fail; the arm is asserted rather than trusted.
            let mut installed = 0usize;
            let mut failure = None;
            for (out, entry) in handles.iter_mut().zip(msg.entries()) {
                match table.insert(entry.object, entry.kind, entry.rights) {
                    Ok(h) => {
                        *out = h;
                        installed += 1;
                    }
                    Err(error) => {
                        failure = Some(error);
                        break;
                    }
                }
            }
            if let Some(error) = failure {
                for undo in handles.iter_mut().take(installed) {
                    let closed = table.close(*undo);
                    debug_assert!(closed.is_ok(), "rollback of a fresh insert failed");
                    // Never valid: generation zero is not issued.
                    *undo = Handle::from_raw(0);
                }
                return Err(Error::NoRoom {
                    handles: got.handles,
                    error,
                });
            }
            if let Some(dst) = bytes.get_mut(..got.bytes) {
                dst.copy_from_slice(msg.bytes());
            }

            // Every entry now lives in `table`; the queue gives up its copies.
            mine.inbox.discard_front();
            Ok(got)
        })
    }

    /// Observe an endpoint. Requires `WAIT`.
    pub fn status<const N: usize>(
        &self,
        table: &HandleTable<N>,
        endpoint: Handle,
    ) -> Result<Status, Error> {
        let side = self.endpoint(table, endpoint, Rights::WAIT)?;
        Ok(L::with(&self.state, |st| {
            let (mine, peer) = st.ends(side);
            Status {
                queued: mine.inbox.len(),
                writable: peer.open && !peer.inbox.is_full(),
                peer_closed: !peer.open,
            }
        }))
    }

    /// Duplicate an endpoint handle within `table`, narrowing to `mask`. Requires
    /// `DUPLICATE`.
    ///
    /// The endpoint's reference count rises with the new handle, so the endpoint stays
    /// open until both are closed. Duplicating an endpoint handle with
    /// `HandleTable::duplicate` directly would skip that count; see the crate docs.
    pub fn duplicate<const N: usize>(
        &self,
        table: &mut HandleTable<N>,
        endpoint: Handle,
        mask: Rights,
    ) -> Result<Handle, Error> {
        let side = self.endpoint(table, endpoint, Rights::DUPLICATE)?;
        L::with(&self.state, |st| {
            let (mine, _) = st.ends(side);
            if !mine.open {
                return Err(Error::Closed);
            }
            let refs = mine.refs.checked_add(1).ok_or(Error::TooManyRefs)?;
            // Count and handle change together, under the lock: if the table is full,
            // neither happens.
            let dup = table.duplicate(endpoint, mask).map_err(Error::Endpoint)?;
            mine.refs = refs;
            Ok(dup)
        })
    }

    /// Close an endpoint handle in `table`.
    ///
    /// If it was the endpoint's last reference, the endpoint closes: the peer observes
    /// [`Error::PeerClosed`] once it has drained what was already sent to it, and every
    /// message still waiting in *this* endpoint's inbox — which nobody can now receive —
    /// is taken apart and each entry it carried is passed to `sink`, exactly once.
    ///
    /// `sink` owns those references. It runs with no channel lock held, so it may
    /// release them — including endpoints of other channels, which may in turn close
    /// and produce more entries. It should queue that work rather than recurse, since a
    /// chain of channels each carrying the next is a chain of arbitrary length.
    pub fn close<const N: usize>(
        &self,
        table: &mut HandleTable<N>,
        endpoint: Handle,
        sink: impl FnMut(Entry),
    ) -> Result<(), Error> {
        self.endpoint(table, endpoint, Rights::empty())?;
        let entry = table.close(endpoint).map_err(Error::Endpoint)?;
        self.release(entry, sink)
    }

    /// Give back one reference to an endpoint of this channel that is not in a handle
    /// table: an entry from [`Channel::new`] that could not be installed, or one that a
    /// `sink` received from a message that will never be delivered.
    ///
    /// Behaves as [`Channel::close`] from there on.
    pub fn release(&self, entry: Entry, mut sink: impl FnMut(Entry)) -> Result<(), Error> {
        let side = self.side_of_entry(entry)?;
        let closed_now = L::with(&self.state, |st| {
            let (mine, _) = st.ends(side);
            let refs = mine.refs.checked_sub(1).ok_or(Error::NotHeld)?;
            mine.refs = refs;
            if refs == 0 {
                mine.open = false;
            }
            Ok(refs == 0)
        })?;

        if closed_now {
            // One message per lock acquisition, with the entries handed out after the
            // lock is dropped. Nothing can be added behind us — this endpoint is closed,
            // so the peer's sends are refused — so the loop ends, and no entry is seen
            // by both the queue and `sink` at once.
            while let Some(entries) = L::with(&self.state, |st| st.ends(side).0.inbox.take_front())
            {
                entries.into_iter().flatten().for_each(&mut sink);
            }
        }
        Ok(())
    }

    /// References currently outstanding on one endpoint. For accounting.
    pub fn references(&self, side: Side) -> u32 {
        L::with(&self.state, |st| st.ends(side).0.refs)
    }

    /// Whether an endpoint is still open.
    pub fn is_open(&self, side: Side) -> bool {
        L::with(&self.state, |st| st.ends(side).0.open)
    }

    /// Visit every entry sitting in a queued message, with the side whose inbox holds it.
    /// For accounting and teardown diagnostics.
    ///
    /// `f` runs under the channel's lock and must not call back into this channel.
    pub fn for_each_queued(&self, mut f: impl FnMut(Side, Entry)) {
        L::with(&self.state, |st| {
            for side in [Side::A, Side::B] {
                for msg in st.ends(side).0.inbox.iter() {
                    msg.entries().for_each(|e| f(side, e));
                }
            }
        });
    }
}

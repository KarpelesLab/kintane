//! Kernel-internal channels: the IPC primitive.
//!
//! The kernel's model is capabilities, not ambient authority (`docs/userspace-abi.md`):
//! a process can affect only what it holds handles to, and a channel is how handles
//! move. This unit is that movement, before any userspace exists to use it. Get the
//! semantics right here and a syscall layer on top is argument copying.
//!
//! # The model
//!
//! A [`Channel`] is a pair of endpoints, [`Side::A`] and [`Side::B`], each a kernel
//! object with its own [`kobject::ObjectId`]. A message sent on one endpoint is queued
//! in the other's **inbox** and received there, in order. A message is up to `BYTES`
//! bytes and up to `HANDLES` handles.
//!
//! Handles are the half that matters. Sending a handle **moves** it: it leaves the
//! sender's [`HandleTable`](kobject::HandleTable) (through `transfer_out`, so
//! `TRANSFER` is enforced where it always is), exists only inside the queued message
//! while in flight, and is installed into the receiver's table on receipt. At every
//! instant each reference is in exactly one place. A reference in zero places leaks
//! its object; in two, a process holds authority nobody gave it.
//!
//! Rights narrow in transit ([`Transfer::narrowed`]) and never widen. The endpoint
//! handle itself needs `WRITE` to send, `READ` to receive, `WAIT` to observe, and
//! `DUPLICATE` to duplicate.
//!
//! # Bounded, and why it has to be
//!
//! Each inbox holds at most `DEPTH` messages, and all of that storage is allocated
//! inline when the channel is created. A send never allocates; when the inbox is full
//! it fails with [`Error::Full`], and the sender deals with it.
//!
//! An unbounded queue is not an option because of who pays. If a sender can outrun a
//! receiver without limit, every message it gets ahead by is kernel memory — memory not
//! charged to the sender, taken from the pool every other process and the kernel itself
//! allocate from. A misbehaving (or merely busy) sender could then exhaust the kernel
//! heap and fail allocations in unrelated subsystems: one process's bug becomes the
//! whole machine's denial of service. A bound turns that into backpressure on the only
//! party that can do anything about it. (This tree also has no infallible allocation
//! at all — `docs/decisions.md` D6 — so a growable queue would add a second, less
//! useful way for a send to fail.)
//!
//! The default shape is 8 messages × 128 bytes × 4 handles per direction, a few KiB per
//! channel. It is a const-generic parameter because a 64 KiB microcontroller build and
//! a server want different numbers, and neither should pay for the other's.
//!
//! # Atomicity
//!
//! Every operation is all-or-nothing, and every error leaves every table and queue as
//! it was — the same handle values, the same rights. How:
//!
//! **Send** validates first and moves second. Phase one checks, without changing
//! anything, what `transfer_out` would check for every listed handle (live, has
//! `TRANSFER`) plus what it cannot check one handle at a time (no handle listed twice;
//! no endpoint of this channel). Only then is the channel lock taken, the peer checked
//! for openness and the destination slot **reserved**; only after the reservation do
//! handles move, under the same lock, into the reserved slot. The table has been
//! exclusively borrowed across both phases, so nothing can change between the check and
//! the move. A full queue is discovered before any handle has moved and needs no undo.
//!
//! **Receive** installs first and dequeues second. The handles are inserted into the
//! receiver's table while the message still holds them; if the table fills part-way,
//! the handles already inserted are closed and the message is left untouched at the
//! front of the queue ([`Error::NoRoom`]). Only when every insert has succeeded does the
//! queue drop its copies.
//!
//! What this does **not** achieve, precisely:
//!
//! - The send commit loop calls `transfer_out`, which returns a `Result`. Phase one makes that
//!   failure impossible, but kobject has no two-phase transfer that would let the type system know
//!   it. The failure arm exists, asserts in debug builds, and on release builds reinstalls what it
//!   moved — under *new* handle values, and fallibly if a just-vacated slot retired. An
//!   all-or-nothing `transfer_out_many` (or a validation token whose commit is infallible) in
//!   kobject would remove the arm.
//! - Receive's rollback closes the handles it had installed, which advances those slots'
//!   generations. No handle value was ever returned for them, so nothing observable is lost, but
//!   repeated `NoRoom` failures bring those slots nearer retirement. A `HandleTable::free_slots` in
//!   kobject would let receive check first and remove the churn.
//! - A "receiver's table is full" failure is a **receive** failure, not a send failure. Messages
//!   are queued: the sender cannot know which table will receive them, and by the time it matters
//!   the sender's handles have correctly left it. The guarantee on that path is that the message
//!   and its handles stay intact in the queue.
//!
//! # Endpoint lifetime and peer closure
//!
//! An endpoint counts its references: entries naming it in any handle table, in any
//! queued message on *any* channel, or in a caller's hands between the two. Moving a
//! handle does not change the count; [`Channel::duplicate`] raises it and
//! [`Channel::close`] / [`Channel::release`] lower it. At zero the endpoint closes, for
//! good:
//!
//! - The peer's receive drains whatever was already sent to it, then returns [`Error::PeerClosed`]
//!   — distinct from [`Error::Empty`], so it never waits for a message that cannot come. The peer's
//!   sends fail with `PeerClosed` and move no handles.
//! - The closed endpoint's own inbox can never be received. It is taken apart and **every entry in
//!   it is handed to the caller's `sink`**, exactly once, with no lock held. There is no object
//!   store yet, so the channel cannot release an arbitrary object itself; what it guarantees is
//!   that nothing is dropped on the floor.
//!
//! # Cycles
//!
//! A handle naming either endpoint of a channel cannot be sent on that channel
//! ([`Error::WouldCycle`]). Sending endpoint `X` so that it lands in `X`'s own inbox —
//! or sending `A` into `B`'s inbox and `B` into `A`'s — leaves an endpoint whose only
//! reference is in a queue only it could drain. Its count never reaches zero, and the
//! channel leaks.
//!
//! The same shape across **two or more** channels is not refused and does leak: `C1`'s
//! endpoint queued in `C2`, `C2`'s queued in `C1`, no table holding either. Detecting it
//! locally is impossible; it needs a collector over in-flight references (what Unix
//! domain sockets carry for `SCM_RIGHTS`) or an object store that can walk them. The
//! conservation invariant still holds — nothing duplicated, nothing silently freed — but
//! the objects are unreachable. A test pins this, so that fixing it is a visible change.
//!
//! # Accounting that can be bypassed
//!
//! kobject deliberately has no object store yet, so a handle table does not know which
//! object a handle names beyond its identity. Calling `HandleTable::close` or
//! `HandleTable::duplicate` directly on an endpoint handle skips the reference count: a
//! direct close leaves the endpoint open for ever, a direct duplicate lets it close while a
//! handle still names it (operations through that handle then return [`Error::Closed`]).
//! Endpoint handles must go through [`Channel::close`] and [`Channel::duplicate`] until
//! an object store routes table operations to the object. This is the one place the
//! capability bookkeeping here relies on callers rather than on types.
//!
//! # Locking
//!
//! One lock per channel, over both inboxes and both reference counts. Which lock is a
//! type parameter, [`LockFamily`], selected by architecture capability — see [`lock`]
//! for why a generic subsystem needs that and cannot pick by trait bound. Both families
//! run the critical section with interrupts masked.
//!
//! **Lock order: the caller's handle table, then the channel.** `send`, `receive` and
//! `duplicate` operate on the table while holding the channel lock; the table is passed
//! as `&mut`, so whatever protects it is already held. Nothing in this unit takes a table
//! while holding a channel lock that another path takes in the other order, and nothing
//! calls out to caller code under the lock except [`Channel::for_each_queued`]'s visitor.
//! A close's `sink` runs unlocked.
//!
//! The critical sections copy at most one message's bytes and scan the table once per
//! handle, so the interrupt-masked window is bounded by `BYTES + HANDLES × N`.
//!
//! # Not yet here
//!
//! Blocking and wake-ups (there is no scheduler; `Full` and `Empty` are the would-block
//! answers), signals for waiting on an endpoint, and the object store that would make
//! the bypass above impossible.

#![cfg_attr(not(test), no_std)]
#![deny(unsafe_code)]

mod channel;
mod inbox;
pub mod lock;

#[cfg(test)]
mod tests;

pub use channel::{Channel, ENDPOINT_RIGHTS, Error, Received, Side, Status, Transfer};
#[cfg(target_has_atomic = "32")]
pub use lock::Spin;
pub use lock::{Irq, LockFamily};

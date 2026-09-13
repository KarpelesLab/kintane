//! A set of channels, and the collector for the cycles they can form between them.
//!
//! A channel refuses to carry its own endpoints ([`Error::WouldCycle`]), which rules out
//! every cycle through one channel. Two or more channels can still carry each other's:
//! `C1`'s endpoint queued in `C2`, `C2`'s queued in `C1`, and no handle table holding
//! either. Each endpoint is then kept open by a reference that only the other could ever
//! receive. Neither count reaches zero, and neither channel can be looked at by anyone
//! again. Seeing that needs every channel involved, which no single channel has. A
//! [`ChannelSet`] owns the channels, so it does.
//!
//! # The collector
//!
//! A mark and sweep over the set's queues, the same idea as the one Unix domain sockets use
//! for descriptors in flight:
//!
//! 1. **Count.** For each endpoint in the set: its references, and how many of them are *in
//!    flight*, meaning entries sitting in some queued message on a channel in the set.
//! 2. **Roots.** An open endpoint with more references than copies in flight is held from outside
//!    the set's queues, by a handle table or by a caller. Its inbox can be received from, so it is
//!    reachable.
//! 3. **Mark.** Every endpoint named by an entry queued in a reachable endpoint's inbox is
//!    reachable too, because receiving that message would hand it out.
//! 4. **Sweep.** An open endpoint left unmarked is garbage. Every reference to it sits in an inbox
//!    nobody can receive from. So is a closed endpoint whose inbox still holds messages. Each such
//!    inbox is taken apart. Entries naming the set's endpoints are released, which closes the
//!    garbage ones as their last copies go. Anything else goes to the caller's `sink`, exactly
//!    once, as [`Channel::close`] hands it over.
//!
//! Releasing can close more endpoints, whose inboxes then need taking apart. So sweeping
//! repeats, recounting from the start each round, until a round finds nothing to take apart.
//! Every round removes at least one message, so it ends. The bound is the number of messages
//! queued in the set.
//!
//! # When it runs
//!
//! On every [`ChannelSet::close`] and [`ChannelSet::release`], which is where the last
//! outside reference to a cycle goes away, and whenever [`ChannelSet::collect`] is called.
//! A send can strand a cycle too: moving the last outside handle to an endpoint into a
//! queue only that cycle can drain. That garbage is found by the next close anywhere in the
//! set. A send does not run the collector, so that sending stays O(message).
//!
//! # Exclusion
//!
//! The counts in step 1 only mean something if nothing sends, receives or closes while they
//! are taken. Operations that run the collector take `&mut self`, so the borrow checker
//! guarantees that. Sends and receives go through [`ChannelSet::channel`] with `&self`, and
//! run concurrently with each other as before. The cost of that choice is that closes
//! through a set are serialised with everything else on it. Whoever owns the set decides how
//! (one lock around it, or one set per process). A collector that runs alongside sends would
//! need the in-flight accounting to happen inside every send and receive. This one keeps
//! them untouched.
//!
//! Each channel's lock is taken on its own, never two at once, so the collector adds no lock
//! ordering.

use kobject::handle::{self, Entry, Handle, HandleTable};
use kobject::{IdSource, ObjectId, ObjectType, Rights};
use sync::LockFamily;

use crate::channel::{Channel, Error, Side};

/// What a collection did.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Collected {
    /// Sweep rounds that took something apart.
    pub rounds: usize,
    /// Endpoints that closed because their last references were in unreachable inboxes.
    pub closed: usize,
    /// Messages taken out of unreachable inboxes.
    pub messages: usize,
}

/// Why a channel could not be added to a set.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SetFull;

/// One endpoint, as a collection round sees it.
#[derive(Clone, Copy, Default)]
struct Seen {
    refs: u32,
    open: bool,
    queued: usize,
    in_flight: u32,
    reachable: bool,
}

/// Up to `CAP` channels of one shape, with a collector for cycles among them.
pub struct ChannelSet<
    L: LockFamily,
    const CAP: usize,
    const DEPTH: usize = 8,
    const BYTES: usize = 128,
    const HANDLES: usize = 4,
> {
    channels: [Option<Channel<L, DEPTH, BYTES, HANDLES>>; CAP],
}

impl<L: LockFamily, const CAP: usize, const D: usize, const B: usize, const H: usize> Default
    for ChannelSet<L, CAP, D, B, H>
{
    fn default() -> Self {
        Self::new()
    }
}

impl<L: LockFamily, const CAP: usize, const D: usize, const B: usize, const H: usize>
    ChannelSet<L, CAP, D, B, H>
{
    pub fn new() -> Self {
        ChannelSet {
            channels: core::array::from_fn(|_| None),
        }
    }

    /// Create a channel in the set. Returns its index and one entry per endpoint, as
    /// [`Channel::new`] does.
    ///
    /// A slot is reused only once both endpoints of its previous channel have closed and
    /// its queues are empty.
    #[must_use = "each entry is an endpoint reference that must be installed or released"]
    pub fn create(
        &mut self,
        ids: &impl IdSource,
        rights: Rights,
    ) -> Result<(usize, [Entry; 2]), SetFull> {
        let index = self
            .channels
            .iter()
            .position(|c| c.as_ref().is_none_or(Self::finished))
            .ok_or(SetFull)?;
        let (channel, entries) = Channel::new(ids, rights);
        let slot = self.channels.get_mut(index).ok_or(SetFull)?;
        *slot = Some(channel);
        Ok((index, entries))
    }

    /// The channel at `index`, for sending, receiving and observing.
    pub fn channel(&self, index: usize) -> Option<&Channel<L, D, B, H>> {
        self.channels.get(index)?.as_ref()
    }

    /// The channel and side that `object` is an endpoint of.
    pub fn find(&self, object: ObjectId) -> Option<(usize, Side)> {
        self.channels
            .iter()
            .enumerate()
            .find_map(|(i, c)| c.as_ref().and_then(|c| c.side_of(object)).map(|s| (i, s)))
    }

    /// Close an endpoint handle in `table`, then collect whatever that stranded.
    ///
    /// Behaves as [`Channel::close`] for the endpoint itself. Every entry the closing and
    /// the collection take out of an inbox that nobody can receive from is either released,
    /// if it names an endpoint in this set, or handed to `sink`.
    pub fn close<const N: usize>(
        &mut self,
        table: &mut HandleTable<N>,
        endpoint: Handle,
        sink: impl FnMut(Entry),
    ) -> Result<Collected, Error> {
        let entry = table
            .get_checked(endpoint, ObjectType::Channel, Rights::empty())
            .map_err(Error::Endpoint)?;
        if self.find(entry.object).is_none() {
            return Err(Error::NotThisChannel);
        }
        let entry = table.close(endpoint).map_err(Error::Endpoint)?;
        self.release(entry, sink)
    }

    /// Give back one reference to an endpoint in this set that is not in a handle table,
    /// then collect. See [`Channel::release`].
    pub fn release(&mut self, entry: Entry, sink: impl FnMut(Entry)) -> Result<Collected, Error> {
        if entry.kind != ObjectType::Channel {
            return Err(Error::Endpoint(handle::Error::WrongType {
                expected: ObjectType::Channel,
                found: entry.kind,
            }));
        }
        let (index, _) = self.find(entry.object).ok_or(Error::NotThisChannel)?;
        let channel = self.channel(index).ok_or(Error::NotThisChannel)?;
        channel.release_keeping_inbox(entry)?;
        Ok(self.collect(sink))
    }

    /// Find and take apart every cycle among the set's channels that nothing outside can
    /// reach. See the module documentation.
    pub fn collect(&mut self, mut sink: impl FnMut(Entry)) -> Collected {
        let mut done = Collected::default();
        loop {
            let seen = self.mark();
            let mut dead = [[false; 2]; CAP];
            let mut any = false;
            for (i, ends) in seen.iter().enumerate() {
                for (s, e) in ends.iter().enumerate() {
                    let garbage = e.open && !e.reachable;
                    let orphaned = !e.open && e.queued > 0;
                    if garbage || orphaned {
                        if let Some(d) = dead.get_mut(i).and_then(|d| d.get_mut(s)) {
                            *d = true;
                            any = true;
                        }
                    }
                }
            }
            if !any {
                return done;
            }
            done.rounds += 1;
            let before = (done.messages, done.closed);
            for (i, sides) in dead.iter().enumerate() {
                for (s, &is_dead) in sides.iter().enumerate() {
                    if is_dead {
                        self.take_apart(i, side(s), &mut sink, &mut done);
                    }
                }
            }
            // Every garbage endpoint's references sit in inboxes this round took apart, so a
            // round always removes a message or closes an endpoint. One that did neither
            // means the counts are wrong; stop rather than spin.
            if (done.messages, done.closed) == before {
                debug_assert!(false, "a collection round made no progress");
                return done;
            }
        }
    }

    /// Steps 1 to 3: count references and copies in flight, find the roots, mark.
    fn mark(&self) -> [[Seen; 2]; CAP] {
        let mut seen = [[Seen::default(); 2]; CAP];
        for (i, c) in self.channels.iter().enumerate() {
            let Some(c) = c else { continue };
            for s in [Side::A, Side::B] {
                let (refs, open, queued) = c.end_state(s);
                if let Some(e) = seen.get_mut(i).and_then(|e| e.get_mut(index(s))) {
                    *e = Seen {
                        refs,
                        open,
                        queued,
                        ..Seen::default()
                    };
                }
            }
        }
        for c in self.channels.iter().flatten() {
            c.for_each_queued(|_, entry| {
                if let Some(e) = self.seen_mut(&mut seen, entry) {
                    e.in_flight = e.in_flight.saturating_add(1);
                }
            });
        }
        for e in seen.iter_mut().flatten() {
            // More copies in flight than references would be broken accounting. `!=` treats
            // that endpoint as held, which can only keep something alive, never free it.
            debug_assert!(e.in_flight <= e.refs, "more copies in flight than references");
            e.reachable = e.open && e.refs != e.in_flight;
        }
        // Reachability spreads one queue at a time, so at most one pass per endpoint.
        for _ in 0..(2 * CAP) {
            let mut changed = false;
            for (i, c) in self.channels.iter().enumerate() {
                let Some(c) = c else { continue };
                let holder = seen.get(i).copied().unwrap_or_default();
                c.for_each_queued(|s, entry| {
                    if !holder.get(index(s)).is_some_and(|h| h.reachable && h.open) {
                        return;
                    }
                    if let Some(e) = self.seen_mut(&mut seen, entry) {
                        if !e.reachable {
                            e.reachable = true;
                            changed = true;
                        }
                    }
                });
            }
            if !changed {
                break;
            }
        }
        seen
    }

    /// Step 4 for one inbox.
    fn take_apart(&self, i: usize, s: Side, sink: &mut impl FnMut(Entry), done: &mut Collected) {
        let Some(c) = self.channel(i) else { return };
        while let Some(entries) = c.take_message(s) {
            done.messages += 1;
            for entry in entries.into_iter().flatten() {
                let target = (entry.kind == ObjectType::Channel)
                    .then(|| self.find(entry.object))
                    .flatten()
                    .and_then(|(j, _)| self.channel(j));
                match target {
                    Some(t) => {
                        if t.release_keeping_inbox(entry) == Ok(true) {
                            done.closed += 1;
                        }
                    }
                    None => sink(entry),
                }
            }
        }
    }

    fn seen_mut<'a>(&self, seen: &'a mut [[Seen; 2]; CAP], entry: Entry) -> Option<&'a mut Seen> {
        if entry.kind != ObjectType::Channel {
            return None;
        }
        let (i, s) = self.find(entry.object)?;
        seen.get_mut(i)?.get_mut(index(s))
    }

    /// A channel whose endpoints have both closed and whose queues are empty: nothing can
    /// ever reach it again, so its slot may be reused.
    fn finished(c: &Channel<L, D, B, H>) -> bool {
        [Side::A, Side::B].into_iter().all(|s| {
            let (_, open, queued) = c.end_state(s);
            !open && queued == 0
        })
    }
}

const fn index(s: Side) -> usize {
    match s {
        Side::A => 0,
        Side::B => 1,
    }
}

const fn side(i: usize) -> Side {
    if i == 0 { Side::A } else { Side::B }
}

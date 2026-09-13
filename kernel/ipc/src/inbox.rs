//! The bounded message queue behind one endpoint.
//!
//! A ring of fixed-size message slots, allocated inline when the channel is created.
//! Nothing here knows about handle tables, rights or closure — it holds messages and
//! the entries inside them, and the one invariant it maintains is that **an entry is in
//! a slot exactly while that slot is part of the queue, or while a send is staging into
//! it.** A slot that leaves the queue gives its entries to the caller or clears them;
//! it never keeps a stale copy that accounting could count twice.

use kobject::handle::Entry;

/// One message: up to `B` bytes and up to `H` handle entries.
pub(crate) struct Message<const B: usize, const H: usize> {
    bytes: [u8; B],
    len: usize,
    /// Packed from index 0; the first `None` ends the list.
    handles: [Option<Entry>; H],
}

impl<const B: usize, const H: usize> Message<B, H> {
    const EMPTY: Self = Message {
        bytes: [0; B],
        len: 0,
        handles: [None; H],
    };

    pub(crate) fn bytes(&self) -> &[u8] {
        self.bytes.get(..self.len).unwrap_or(&[])
    }

    pub(crate) fn entries(&self) -> impl Iterator<Item = Entry> + '_ {
        self.handles.iter().map_while(|e| *e)
    }

    pub(crate) fn handle_count(&self) -> usize {
        self.entries().count()
    }
}

/// A slot at the tail of a non-full queue, being filled by a send.
///
/// Not part of the queue until [`Vacant::commit`]. There is deliberately no `Drop`:
/// a staging that is abandoned must hand its entries back explicitly (see
/// [`Vacant::unstage`]), because a destructor that cleared them would be a silent loss
/// of exactly the kind this unit exists to prevent.
pub(crate) struct Vacant<'a, const D: usize, const B: usize, const H: usize> {
    inbox: &'a mut Inbox<D, B, H>,
    index: usize,
}

impl<const D: usize, const B: usize, const H: usize> Vacant<'_, D, B, H> {
    fn slot(&mut self) -> Option<&mut Message<B, H>> {
        self.inbox.slots.get_mut(self.index)
    }

    /// The handle positions, for the send to stage entries into in order.
    pub(crate) fn handle_slots(&mut self) -> impl Iterator<Item = &mut Option<Entry>> {
        self.slot().into_iter().flat_map(|m| m.handles.iter_mut())
    }

    /// Take back every entry staged so far, emptying the slot.
    pub(crate) fn unstage(&mut self) -> [Option<Entry>; H] {
        match self.slot() {
            Some(m) => core::mem::replace(&mut m.handles, [None; H]),
            None => [None; H],
        }
    }

    /// Append the message to the queue. `bytes` must be at most `B` long; the caller
    /// checked, and a longer slice is truncated rather than overrunning the slot.
    pub(crate) fn commit(mut self, bytes: &[u8]) {
        if let Some(m) = self.slot() {
            let len = bytes.len().min(B);
            if let (Some(dst), Some(src)) = (m.bytes.get_mut(..len), bytes.get(..len)) {
                dst.copy_from_slice(src);
            }
            m.len = len;
        }
        self.inbox.len = self.inbox.len.saturating_add(1).min(D);
    }
}

/// `D` message slots in a ring.
pub(crate) struct Inbox<const D: usize, const B: usize, const H: usize> {
    slots: [Message<B, H>; D],
    head: usize,
    len: usize,
}

impl<const D: usize, const B: usize, const H: usize> Inbox<D, B, H> {
    pub(crate) const fn new() -> Self {
        // A zero-depth channel could never carry a message, and `index` divides by `D`.
        // Rejected when the type is instantiated rather than when it is first used.
        const { assert!(D > 0, "a channel needs a queue depth of at least one") };
        Inbox {
            slots: [const { Message::EMPTY }; D],
            head: 0,
            len: 0,
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.len
    }

    pub(crate) fn is_full(&self) -> bool {
        self.len >= D
    }

    fn index(&self, offset: usize) -> usize {
        // `head < D` and `offset <= D`, so the sum cannot wrap; `D > 0` by the
        // assertion in `new`, which every constructed inbox has passed.
        self.head.wrapping_add(offset) % D
    }

    pub(crate) fn front(&self) -> Option<&Message<B, H>> {
        if self.len == 0 {
            return None;
        }
        self.slots.get(self.head)
    }

    /// The next free slot, or `None` if the queue is full.
    pub(crate) fn vacant(&mut self) -> Option<Vacant<'_, D, B, H>> {
        if self.is_full() {
            return None;
        }
        let index = self.index(self.len);
        Some(Vacant { inbox: self, index })
    }

    /// Remove the front message, whose entries the caller has already installed
    /// elsewhere. The slot's entries are cleared, not kept as stale copies.
    pub(crate) fn discard_front(&mut self) {
        let _ = self.take_front();
    }

    /// Remove the front message and hand its entries to the caller.
    pub(crate) fn take_front(&mut self) -> Option<[Option<Entry>; H]> {
        if self.len == 0 {
            return None;
        }
        let head = self.head;
        let taken = self.slots.get_mut(head).map(|m| {
            m.len = 0;
            core::mem::replace(&mut m.handles, [None; H])
        });
        self.head = self.index(1);
        self.len -= 1;
        taken
    }

    /// The queued messages, front first.
    pub(crate) fn iter(&self) -> impl Iterator<Item = &Message<B, H>> + '_ {
        (0..self.len).filter_map(move |i| self.slots.get(self.index(i)))
    }
}

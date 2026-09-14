//! The block layer.
//!
//! One trait a storage driver implements, [`BlockDevice`], and the bookkeeping above it:
//! range and alignment checks that every driver would otherwise write again, splitting a
//! transfer a device cannot do in one go, and a fixed-capacity [`Queue`] of requests in
//! flight.
//!
//! # What is deliberately not here
//!
//! * **No allocation.** A request queue that allocates cannot be used from the paths that need it
//!   most — an interrupt handler completing an I/O, or a driver started before any heap exists.
//!   Storage comes from the caller, as it does in the device model.
//! * **No cache and no scheduler.** Read-ahead, merging and ordering are policy above a device;
//!   they belong with a filesystem's page cache, which does not exist yet. What is here is the part
//!   every one of them needs.
//! * **No blocking.** Nothing here sleeps or spins. A driver's `read` may block internally, but
//!   [`Queue`] is bookkeeping: a submitter gets a [`Ticket`] and asks later.
//!
//! Errors are values everywhere, including the ones a device reports about itself, because
//! a storage stack that panics on a bad disk is a storage stack that cannot report a bad
//! disk.

#![cfg_attr(not(test), no_std)]
#![deny(unsafe_code)]

pub mod testdisk;

/// Why a block operation could not be done.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Error {
    /// The request runs past the end of the device.
    OutOfRange {
        /// The first block asked for.
        lba: u64,
        /// How many blocks were asked for.
        blocks: u64,
        /// How many the device has.
        capacity: u64,
    },
    /// The buffer is not a whole number of blocks, or is empty.
    Misaligned { bytes: usize, block_size: usize },
    /// The device reported a failure. The string is the driver's, and is a fixed
    /// description rather than a code, so it can be printed on a console with no
    /// formatter.
    Device(&'static str),
    /// The device did not answer within its driver's limit.
    Timeout,
    /// The queue is full.
    NoRoom,
    /// The ticket names a slot that has been reused, or was never issued.
    Stale,
    /// The request is still in flight.
    Pending,
}

/// A device's geometry, and the range checking every driver needs.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Geometry {
    /// Bytes per block. Always a power of two for the devices we support, and checked.
    pub block_size: usize,
    /// How many blocks the device holds.
    pub capacity: u64,
}

impl Geometry {
    /// `None` for a block size that is not a power of two, or a device with no blocks:
    /// both describe hardware we cannot address, and both are worth refusing at the one
    /// place that reads them out of a device's configuration space.
    pub fn new(block_size: usize, capacity: u64) -> Option<Geometry> {
        (block_size.is_power_of_two() && capacity > 0).then_some(Geometry {
            block_size,
            capacity,
        })
    }

    pub fn bytes(&self) -> u64 {
        self.capacity.saturating_mul(self.block_size as u64)
    }

    /// How many blocks `bytes` covers, if it covers a whole number of them, and if the
    /// range starting at `lba` is inside the device.
    ///
    /// This is the check that turns a caller's arithmetic mistake into an error rather
    /// than a transfer that runs off the end of a disk into whatever the device does with
    /// out-of-range sectors — which on a real disk is an error, and on some is silence.
    pub fn range(&self, lba: u64, bytes: usize) -> Result<u64, Error> {
        if bytes == 0 || bytes % self.block_size != 0 {
            return Err(Error::Misaligned {
                bytes,
                block_size: self.block_size,
            });
        }
        let blocks = (bytes / self.block_size) as u64;
        let end = lba.checked_add(blocks);
        match end {
            Some(end) if end <= self.capacity => Ok(blocks),
            _ => Err(Error::OutOfRange {
                lba,
                blocks,
                capacity: self.capacity,
            }),
        }
    }
}

/// A device that stores fixed-size blocks.
///
/// `&self`, not `&mut self`: a driver is shared, and what serialises access to the
/// hardware is the driver's own lock, not the caller's borrow. Every method may be called
/// from any thread once the driver is started.
pub trait BlockDevice {
    fn geometry(&self) -> Geometry;

    /// The most blocks the device will move in one request. A transfer larger than this
    /// is split by [`for_each_chunk`]; a driver need not handle one.
    fn max_transfer_blocks(&self) -> u64;

    /// Fill `into` from the device, starting at block `lba`. `into` must be a whole
    /// number of blocks and no more than [`max_transfer_blocks`](Self::max_transfer_blocks).
    fn read_blocks(&self, lba: u64, into: &mut [u8]) -> Result<(), Error>;

    /// Write `from` to the device at block `lba`, with the same rules.
    fn write_blocks(&self, lba: u64, from: &[u8]) -> Result<(), Error>;

    /// Make everything written before this call durable.
    fn flush(&self) -> Result<(), Error>;
}

/// Split a transfer into pieces the device will take, and run `f` on each.
///
/// `f` is given the block the piece starts at and its byte range within the buffer, so a
/// caller can use it for reads and writes alike. The split is the one place that knows a
/// device's per-request limit, so neither a driver nor a caller has to.
pub fn for_each_chunk(
    geometry: Geometry,
    max_transfer: u64,
    lba: u64,
    bytes: usize,
    mut f: impl FnMut(u64, core::ops::Range<usize>) -> Result<(), Error>,
) -> Result<(), Error> {
    let blocks = geometry.range(lba, bytes)?;
    if max_transfer == 0 {
        return Err(Error::Device("the device takes no blocks per request"));
    }
    let mut done = 0u64;
    while done < blocks {
        let take = (blocks - done).min(max_transfer);
        let start = (done as usize) * geometry.block_size;
        let end = start + (take as usize) * geometry.block_size;
        f(lba + done, start..end)?;
        done += take;
    }
    Ok(())
}

/// Read the whole of `into`, splitting the transfer as the device requires.
pub fn read(device: &dyn BlockDevice, lba: u64, into: &mut [u8]) -> Result<(), Error> {
    let geometry = device.geometry();
    let max = device.max_transfer_blocks();
    // The closure cannot borrow `into` mutably and be called repeatedly, so the split is
    // walked here rather than through `for_each_chunk`'s callback.
    let bytes = into.len();
    let blocks = geometry.range(lba, bytes)?;
    if max == 0 {
        return Err(Error::Device("the device takes no blocks per request"));
    }
    let mut done = 0u64;
    while done < blocks {
        let take = (blocks - done).min(max);
        let start = (done as usize) * geometry.block_size;
        let end = start + (take as usize) * geometry.block_size;
        let piece = into.get_mut(start..end).ok_or(Error::Misaligned {
            bytes,
            block_size: geometry.block_size,
        })?;
        device.read_blocks(lba + done, piece)?;
        done += take;
    }
    Ok(())
}

/// Write the whole of `from`, splitting the transfer as the device requires.
pub fn write(device: &dyn BlockDevice, lba: u64, from: &[u8]) -> Result<(), Error> {
    let geometry = device.geometry();
    let max = device.max_transfer_blocks();
    for_each_chunk(geometry, max, lba, from.len(), |at, range| {
        let piece = from.get(range).ok_or(Error::Misaligned {
            bytes: from.len(),
            block_size: geometry.block_size,
        })?;
        device.write_blocks(at, piece)
    })
}

/// What a queued request asks for.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Op {
    Read,
    Write,
    Flush,
}

/// A submitted request's receipt.
///
/// Carries the slot's serial number as well as its index, so a ticket for a request that
/// has been completed and whose slot has been reused names the old request, not its
/// successor — the same rule the handle tables use, for the same reason.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Ticket {
    slot: u16,
    serial: u32,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct Slot {
    serial: u32,
    op: Op,
    lba: u64,
    blocks: u64,
    /// `None` while in flight.
    done: Option<Result<(), Error>>,
}

/// Requests in flight, and their completions.
///
/// Fixed capacity, no allocation, and every operation is `O(1)` except `drain`, which is
/// `O(N)` and is not on any hot path. The counters exist so a caller can prove no request
/// was lost: `issued == completed + in_flight` always holds, and the boot check and the
/// stress audit both assert it.
pub struct Queue<const N: usize> {
    slots: [Option<Slot>; N],
    next_serial: u32,
    issued: u64,
    completed: u64,
    failed: u64,
}

impl<const N: usize> Default for Queue<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> Queue<N> {
    pub const fn new() -> Self {
        Queue {
            slots: [None; N],
            next_serial: 1,
            issued: 0,
            completed: 0,
            failed: 0,
        }
    }

    pub fn capacity(&self) -> usize {
        N
    }

    /// Requests submitted and not yet completed. A request whose outcome is recorded but
    /// not collected is not in flight: the device is done with it, and it holds only a
    /// slot.
    pub fn in_flight(&self) -> usize {
        self.slots
            .iter()
            .flatten()
            .filter(|s| s.done.is_none())
            .count()
    }

    /// Slots held: in flight, plus finished requests nobody has collected.
    pub fn occupied(&self) -> usize {
        self.slots.iter().flatten().count()
    }

    pub fn issued(&self) -> u64 {
        self.issued
    }

    pub fn completed(&self) -> u64 {
        self.completed
    }

    pub fn failed(&self) -> u64 {
        self.failed
    }

    /// Whether the books balance: everything issued is either finished or still in flight.
    pub fn balanced(&self) -> bool {
        self.issued == self.completed + self.in_flight() as u64
    }

    /// Take a slot for a request. [`Error::NoRoom`] when every slot is in flight.
    pub fn submit(&mut self, op: Op, lba: u64, blocks: u64) -> Result<Ticket, Error> {
        let slot = self
            .slots
            .iter()
            .position(Option::is_none)
            .ok_or(Error::NoRoom)?;
        let serial = self.next_serial;
        // Serial numbers are never reused: at one request per nanosecond a 32-bit serial
        // wraps in 4 seconds, so it is widened to the slot's lifetime by never resetting
        // and by refusing to wrap.
        self.next_serial = self.next_serial.checked_add(1).ok_or(Error::NoRoom)?;
        self.slots[slot] = Some(Slot {
            serial,
            op,
            lba,
            blocks,
            done: None,
        });
        self.issued += 1;
        Ok(Ticket {
            slot: slot as u16,
            serial,
        })
    }

    fn find(&self, ticket: Ticket) -> Result<usize, Error> {
        let slot = usize::from(ticket.slot);
        match self.slots.get(slot) {
            Some(Some(s)) if s.serial == ticket.serial => Ok(slot),
            _ => Err(Error::Stale),
        }
    }

    /// What a ticket asked for, for a driver that has forgotten.
    pub fn request(&self, ticket: Ticket) -> Result<(Op, u64, u64), Error> {
        let slot = self.find(ticket)?;
        let s = self.slots[slot].ok_or(Error::Stale)?;
        Ok((s.op, s.lba, s.blocks))
    }

    /// Record a request's outcome. The slot stays until [`take`](Self::take) collects it.
    pub fn complete(&mut self, ticket: Ticket, result: Result<(), Error>) -> Result<(), Error> {
        let slot = self.find(ticket)?;
        let s = self.slots[slot].as_mut().ok_or(Error::Stale)?;
        if s.done.is_some() {
            return Err(Error::Stale);
        }
        s.done = Some(result);
        self.completed += 1;
        if result.is_err() {
            self.failed += 1;
        }
        Ok(())
    }

    /// Whether a request has finished, without collecting it.
    pub fn ready(&self, ticket: Ticket) -> Result<bool, Error> {
        let slot = self.find(ticket)?;
        Ok(self.slots[slot].and_then(|s| s.done).is_some())
    }

    /// Collect a finished request and free its slot. [`Error::Pending`] while it is in
    /// flight, so a caller cannot mistake "not finished" for "finished without error".
    pub fn take(&mut self, ticket: Ticket) -> Result<Result<(), Error>, Error> {
        let slot = self.find(ticket)?;
        let s = self.slots[slot].ok_or(Error::Stale)?;
        let done = s.done.ok_or(Error::Pending)?;
        self.slots[slot] = None;
        Ok(done)
    }

    /// Fail every request in flight, as a driver does when its device is gone. Returns
    /// how many were failed.
    pub fn drain(&mut self, why: Error) -> usize {
        let mut n = 0;
        for slot in self.slots.iter_mut().flatten() {
            if slot.done.is_none() {
                slot.done = Some(Err(why));
                n += 1;
            }
        }
        self.completed += n as u64;
        self.failed += n as u64;
        n
    }
}

#[cfg(test)]
mod tests;

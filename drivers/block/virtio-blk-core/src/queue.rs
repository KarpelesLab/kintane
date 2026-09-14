//! A split virtqueue: the descriptor table, the available ring the driver writes, and the
//! used ring the device writes (virtio 1.1 §2.6).
//!
//! # The two orderings that matter
//!
//! The rings are memory two agents write without a lock between them, so the protocol is
//! carried by two indices and the order of the stores around them:
//!
//! * **Publishing.** The driver fills descriptors and the available ring, then increments
//!   `avail.idx`. The device may read `avail.idx` at any moment; if it sees the new index it must
//!   also see the descriptors, so the descriptor writes are ordered *before* the index store with a
//!   release fence. Without it, a device on a machine that reorders stores may read the new index
//!   and follow a descriptor that is still the previous request's.
//! * **Collecting.** The driver reads `used.idx`, then the used element it names. The element was
//!   written before the index by the device, so the read of the index is ordered *before* the read
//!   of the element with an acquire fence.
//!
//! QEMU does not model weak memory, and the emulated device's accesses are ordinary host
//! stores, so **no test here can fail because a fence is missing.** Both fences are
//! therefore argument, in the sense `docs/memory-model.md` uses: they follow virtio 1.1
//! §2.6.13 and the same reasoning as the kernel's own publication rules, and they are
//! written down so a reader can check the argument. What the tests below *do* cover is the
//! protocol: which index moves when, which descriptor a chain frees, and that a device
//! answering out of order is followed rather than assumed.

use crate::mem::Dma;

/// Descriptor flags (virtio 1.1 §2.6.5).
pub const VIRTQ_DESC_F_NEXT: u16 = 1;
pub const VIRTQ_DESC_F_WRITE: u16 = 2;

/// `used.flags`: the device does not want to be notified.
const VIRTQ_USED_F_NO_NOTIFY: u16 = 1;

/// One buffer of a descriptor chain.
#[derive(Clone, Copy, Debug)]
pub struct Buf {
    /// The address the device uses.
    pub phys: u64,
    pub len: u32,
    /// Whether the device writes it (a read request's data) rather than reads it.
    pub device_writes: bool,
}

/// A finished request.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Used {
    /// The head descriptor of the chain, which is what the driver submitted.
    pub head: u16,
    /// How many bytes the device wrote. Advisory: virtio devices differ in what they
    /// count, so a driver that needs a length should know its own.
    pub len: u32,
}

/// Why a chain could not be submitted.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Error {
    /// The queue has no room for a chain this long.
    Full,
    /// The chain is empty, or longer than the queue.
    BadChain,
    /// The region cannot hold a queue of this size.
    TooSmall,
    /// A queue size the protocol does not allow: zero, over 32768, or not a power of two.
    BadSize,
}

/// A split virtqueue over three regions of device-visible memory.
#[derive(Debug)]
pub struct Ring {
    desc: Dma,
    avail: Dma,
    used: Dma,
    size: u16,
    /// Head of the free-descriptor list, linked through each descriptor's `next`.
    free_head: u16,
    free_count: u16,
    /// The driver's own copy of `avail.idx`, which only it writes.
    avail_idx: u16,
    /// The next `used.idx` the driver has not collected.
    last_used: u16,
}

impl Ring {
    /// Bytes a queue of `size` needs for each of its three parts.
    pub const fn sizes(size: u16) -> (usize, usize, usize) {
        let q = size as usize;
        (16 * q, 6 + 2 * q, 6 + 8 * q)
    }

    /// Lay out a queue over regions that must already be big enough, and zero them.
    ///
    /// Zeroing is not tidiness: the device reads `avail.flags` and the driver reads
    /// `used.idx` before either has been written by its owner, and frames handed over by
    /// the allocator hold whatever the last user left.
    pub fn new(desc: Dma, avail: Dma, used: Dma, size: u16) -> Result<Ring, Error> {
        if size == 0 || size > 32768 || !size.is_power_of_two() {
            return Err(Error::BadSize);
        }
        let (d, a, u) = Ring::sizes(size);
        if desc.len() < d || avail.len() < a || used.len() < u {
            return Err(Error::TooSmall);
        }
        desc.zero();
        avail.zero();
        used.zero();
        let ring = Ring {
            desc,
            avail,
            used,
            size,
            free_head: 0,
            free_count: size,
            avail_idx: 0,
            last_used: 0,
        };
        // The free list: every descriptor points at the next, the last at itself, which
        // is never followed because `free_count` reaches zero first.
        for i in 0..size {
            ring.set_next(i, if i + 1 < size { i + 1 } else { i });
        }
        Ok(ring)
    }

    pub fn size(&self) -> u16 {
        self.size
    }

    pub fn free_descriptors(&self) -> u16 {
        self.free_count
    }

    pub fn desc_phys(&self) -> u64 {
        self.desc.phys()
    }

    pub fn avail_phys(&self) -> u64 {
        self.avail.phys()
    }

    pub fn used_phys(&self) -> u64 {
        self.used.phys()
    }

    fn desc_at(&self, i: u16) -> usize {
        16 * usize::from(i)
    }

    fn set_next(&self, i: u16, next: u16) {
        self.desc.write16(self.desc_at(i) + 14, next);
    }

    fn next_of(&self, i: u16) -> u16 {
        self.desc.read16(self.desc_at(i) + 14)
    }

    fn flags_of(&self, i: u16) -> u16 {
        self.desc.read16(self.desc_at(i) + 12)
    }

    /// Put a chain's descriptors back on the free list. Returns how many were freed.
    fn free_chain(&mut self, head: u16) -> u16 {
        let mut freed = 0;
        let mut i = head;
        // Bounded by the queue size: a device that corrupted `next` into a cycle cannot
        // make this loop for ever.
        while freed < self.size {
            let flags = self.flags_of(i);
            let next = self.next_of(i);
            self.set_next(i, self.free_head);
            self.free_head = i;
            freed += 1;
            if flags & VIRTQ_DESC_F_NEXT == 0 {
                break;
            }
            i = next;
        }
        self.free_count += freed;
        freed
    }

    /// Publish a chain and return its head descriptor.
    ///
    /// The head is what comes back from [`poll_used`](Self::poll_used), so a driver uses it
    /// to find the request the completion belongs to.
    pub fn add(&mut self, chain: &[Buf]) -> Result<u16, Error> {
        let n = u16::try_from(chain.len()).map_err(|_| Error::BadChain)?;
        if n == 0 || n > self.size {
            return Err(Error::BadChain);
        }
        if n > self.free_count {
            return Err(Error::Full);
        }

        let head = self.free_head;
        let mut i = head;
        for (position, buf) in chain.iter().enumerate() {
            let next = self.next_of(i);
            let at = self.desc_at(i);
            self.desc.write64(at, buf.phys);
            self.desc.write32(at + 8, buf.len);
            let last = position + 1 == chain.len();
            let mut flags = 0;
            if buf.device_writes {
                flags |= VIRTQ_DESC_F_WRITE;
            }
            if !last {
                flags |= VIRTQ_DESC_F_NEXT;
            }
            self.desc.write16(at + 12, flags);
            // `next` is left as the free list had it for the last descriptor; the device
            // does not follow it, because NEXT is clear.
            if !last {
                self.desc.write16(at + 14, next);
                i = next;
            }
        }
        // Everything after the chain's last descriptor is the rest of the free list.
        self.free_head = self.next_of(i);
        self.free_count -= n;

        // The available ring's slot for this request, then the index that publishes it.
        let slot = self.avail_idx % self.size;
        self.avail.write16(4 + 2 * usize::from(slot), head);
        // See the module documentation: the descriptors and the ring entry must be
        // visible to the device before the index that points at them.
        core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
        self.avail_idx = self.avail_idx.wrapping_add(1);
        self.avail.write16(2, self.avail_idx);
        Ok(head)
    }

    /// Whether the device asked not to be notified.
    pub fn notify_wanted(&self) -> bool {
        self.used.read16(0) & VIRTQ_USED_F_NO_NOTIFY == 0
    }

    /// Collect one finished request, if the device has finished any.
    ///
    /// Completions are taken in the order the device wrote them, which is not necessarily
    /// the order they were submitted in: the used element names its own head descriptor.
    pub fn poll_used(&mut self) -> Option<Used> {
        let idx = self.used.read16(2);
        if idx == self.last_used {
            return None;
        }
        // See the module documentation: the element was written before the index.
        core::sync::atomic::fence(core::sync::atomic::Ordering::Acquire);
        let slot = usize::from(self.last_used % self.size);
        let at = 4 + 8 * slot;
        let id = self.used.read32(at);
        let len = self.used.read32(at + 4);
        self.last_used = self.last_used.wrapping_add(1);
        let head = u16::try_from(id).ok().filter(|&h| h < self.size)?;
        self.free_chain(head);
        Some(Used { head, len })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{Backing, FakeDevice};

    /// A queue of `size` over host memory, with the device's addresses deliberately
    /// different from the CPU's.
    fn ring(backing: &mut Backing, size: u16) -> Ring {
        let (d, a, u) = Ring::sizes(size);
        let desc = backing.take(d, 16);
        let avail = backing.take(a, 2);
        let used = backing.take(u, 4);
        Ring::new(desc, avail, used, size).unwrap()
    }

    #[test]
    fn a_queue_size_the_protocol_forbids_is_refused() {
        let mut backing = Backing::new(64 * 1024);
        let (d, a, u) = Ring::sizes(8);
        let (desc, avail, used) = (backing.take(d, 16), backing.take(a, 2), backing.take(u, 4));
        assert_eq!(Ring::new(desc, avail, used, 0).unwrap_err(), Error::BadSize);

        let (desc, avail, used) = (backing.take(d, 16), backing.take(a, 2), backing.take(u, 4));
        assert_eq!(Ring::new(desc, avail, used, 6).unwrap_err(), Error::BadSize);

        // Regions too small for the size asked for.
        let (desc, avail, used) = (backing.take(16, 16), backing.take(a, 2), backing.take(u, 4));
        assert_eq!(Ring::new(desc, avail, used, 8).unwrap_err(), Error::TooSmall);
    }

    #[test]
    fn a_chain_is_published_with_the_devices_addresses_not_the_cpus() {
        let mut backing = Backing::new(64 * 1024);
        let mut r = ring(&mut backing, 8);
        let buf = backing.take(512, 16);
        assert_ne!(buf.phys(), buf.virt() as u64, "the test would prove nothing");

        let head = r
            .add(&[Buf {
                phys: buf.phys(),
                len: 512,
                device_writes: true,
            }])
            .unwrap();
        assert_eq!(head, 0);
        assert_eq!(r.free_descriptors(), 7);

        let mut device = FakeDevice::new(&backing, &r);
        let seen = device.take_available().expect("the device sees the chain");
        assert_eq!(seen.head, 0);
        assert_eq!(seen.buffers.len(), 1);
        assert_eq!(seen.buffers[0].phys, buf.phys(), "the descriptor carries phys");
        assert!(seen.buffers[0].device_writes);
    }

    #[test]
    fn a_multi_buffer_chain_is_linked_and_freed_as_one() {
        let mut backing = Backing::new(64 * 1024);
        let mut r = ring(&mut backing, 8);
        let header = backing.take(16, 16);
        let payload = backing.take(512, 16);
        let status = backing.take(1, 1);

        let head = r
            .add(&[
                Buf {
                    phys: header.phys(),
                    len: 16,
                    device_writes: false,
                },
                Buf {
                    phys: payload.phys(),
                    len: 512,
                    device_writes: true,
                },
                Buf {
                    phys: status.phys(),
                    len: 1,
                    device_writes: true,
                },
            ])
            .unwrap();
        assert_eq!(r.free_descriptors(), 5, "three taken");

        let mut device = FakeDevice::new(&backing, &r);
        let seen = device.take_available().unwrap();
        assert_eq!(seen.buffers.len(), 3, "the device walks the whole chain");
        assert_eq!(seen.buffers[1].len, 512);
        assert_eq!(
            seen.buffers
                .iter()
                .map(|b| b.device_writes)
                .collect::<Vec<_>>(),
            vec![false, true, true],
            "only the device-written buffers carry WRITE"
        );

        device.complete(head, 513);
        assert_eq!(r.poll_used(), Some(Used { head, len: 513 }));
        assert_eq!(r.free_descriptors(), 8, "the whole chain came back");
    }

    #[test]
    fn the_queue_can_be_filled_and_emptied_without_losing_descriptors() {
        let mut backing = Backing::new(128 * 1024);
        let mut r = ring(&mut backing, 8);
        let buf = backing.take(512, 16);

        // One device for all rounds: its indices, like the driver's, keep counting.
        let mut device = FakeDevice::new(&backing, &r);
        // Four rounds of filling the queue completely, so descriptor reuse is exercised
        // past the first pass.
        for _ in 0..4 {
            let mut heads = Vec::new();
            for _ in 0..8 {
                heads.push(
                    r.add(&[Buf {
                        phys: buf.phys(),
                        len: 512,
                        device_writes: true,
                    }])
                    .unwrap(),
                );
            }
            assert_eq!(r.free_descriptors(), 0);
            assert_eq!(
                r.add(&[Buf {
                    phys: buf.phys(),
                    len: 512,
                    device_writes: true
                }])
                .unwrap_err(),
                Error::Full,
            );
            for &h in &heads {
                device.take_available().unwrap();
                device.complete(h, 512);
            }
            for &h in &heads {
                assert_eq!(r.poll_used().map(|u| u.head), Some(h));
            }
            assert_eq!(r.free_descriptors(), 8);
            assert_eq!(r.poll_used(), None, "nothing left");
        }
    }

    #[test]
    fn completions_are_followed_in_the_order_the_device_wrote_them() {
        let mut backing = Backing::new(64 * 1024);
        let mut r = ring(&mut backing, 8);
        let buf = backing.take(512, 16);
        let first = r
            .add(&[Buf {
                phys: buf.phys(),
                len: 512,
                device_writes: true,
            }])
            .unwrap();
        let second = r
            .add(&[Buf {
                phys: buf.phys(),
                len: 512,
                device_writes: true,
            }])
            .unwrap();

        let mut device = FakeDevice::new(&backing, &r);
        device.take_available().unwrap();
        device.take_available().unwrap();
        // Out of order, which a real device is allowed to do.
        device.complete(second, 512);
        device.complete(first, 512);
        assert_eq!(r.poll_used().map(|u| u.head), Some(second));
        assert_eq!(r.poll_used().map(|u| u.head), Some(first));
        assert_eq!(r.poll_used(), None);
    }

    #[test]
    fn the_available_index_wraps_without_losing_the_ring_slot() {
        let mut backing = Backing::new(64 * 1024);
        // Size 2, so the ring wraps after two requests and `avail.idx` keeps counting.
        let mut r = ring(&mut backing, 2);
        let buf = backing.take(512, 16);
        let mut device = FakeDevice::new(&backing, &r);
        for round in 0..5 {
            let h = r
                .add(&[Buf {
                    phys: buf.phys(),
                    len: 512,
                    device_writes: true,
                }])
                .unwrap();
            let seen = device.take_available().unwrap_or_else(|| {
                panic!("round {round}: the device did not see the request");
            });
            assert_eq!(seen.head, h);
            device.complete(h, 512);
            assert_eq!(r.poll_used().map(|u| u.head), Some(h));
        }
    }

    #[test]
    fn a_chain_longer_than_the_queue_is_refused_rather_than_overrunning_it() {
        let mut backing = Backing::new(64 * 1024);
        let mut r = ring(&mut backing, 2);
        let buf = backing.take(512, 16);
        let one = Buf {
            phys: buf.phys(),
            len: 16,
            device_writes: false,
        };
        assert_eq!(r.add(&[]).unwrap_err(), Error::BadChain);
        assert_eq!(r.add(&[one, one, one]).unwrap_err(), Error::BadChain);
        assert_eq!(r.free_descriptors(), 2, "nothing was taken");
    }

    #[test]
    fn a_used_element_naming_a_descriptor_that_does_not_exist_is_ignored() {
        let mut backing = Backing::new(64 * 1024);
        let mut r = ring(&mut backing, 4);
        let buf = backing.take(512, 16);
        let head = r
            .add(&[Buf {
                phys: buf.phys(),
                len: 512,
                device_writes: true,
            }])
            .unwrap();
        let mut device = FakeDevice::new(&backing, &r);
        device.take_available().unwrap();
        // A device that answers with nonsense must not send the driver walking a
        // descriptor index it does not have.
        device.complete_raw(99, 512);
        assert_eq!(r.poll_used(), None, "refused");
        assert_eq!(r.free_descriptors(), 3, "the real chain is still outstanding");
        device.complete(head, 512);
        assert_eq!(r.poll_used().map(|u| u.head), Some(head));
    }
}

//! A device on the other side of the rings, so the driver's protocol can be tested on a
//! laptop rather than only under QEMU.
//!
//! [`Backing`] is host memory standing in for the DMA region, with the device's addresses
//! deliberately *different* from the CPU's — a fixed offset apart — so a driver that hands
//! the device a virtual address fails here rather than in an emulator.
//!
//! [`FakeDevice`] does what a virtio device does: take chains from the available ring, walk
//! their descriptors, and write the used ring. What a *particular* device does with a chain
//! belongs to its driver's tests — virtio-blk's answer requests against a RAM disk, and
//! virtio-net's carry frames — which is why this knows nothing about either.
//!
//! Compiled for host builds only (`MOCK_ARCH`, which `kbuild test` sets), so a driver's
//! tests in another crate can use it and no kernel image carries it.

#![allow(unsafe_code)]

use std::vec;
use std::vec::Vec;

use crate::mem::Dma;
use crate::queue::{Ring, VIRTQ_DESC_F_NEXT, VIRTQ_DESC_F_WRITE};

/// Host memory the "device" and the driver share.
pub struct Backing {
    buf: Vec<u8>,
    used: usize,
    /// What the device's addresses are offset by from the CPU's.
    offset: u64,
}

impl Backing {
    pub fn new(len: usize) -> Backing {
        Backing {
            buf: vec![0u8; len],
            used: 0,
            offset: 0x1000_0000,
        }
    }

    /// Carve a region out of the front, as a real driver carves its DMA region.
    pub fn take(&mut self, len: usize, align: usize) -> Dma {
        let base = self.buf.as_ptr() as usize;
        let start = (base + self.used).next_multiple_of(align);
        let offset = start - base;
        assert!(offset + len <= self.buf.len(), "the test's backing is too small");
        self.used = offset + len;
        // SAFETY: the range is inside a buffer that outlives every region carved from it
        // and is never reallocated, and each call hands out a range no other call did.
        // The "physical" address is the fixed translation this type exists to model.
        unsafe { Dma::new(start, start as u64 + self.offset, len) }
    }

    /// What a device needs to know to find its way around this memory.
    pub fn view(&self) -> View {
        View {
            offset: self.offset,
            base: self.buf.as_ptr() as usize,
            len: self.buf.len(),
        }
    }
}

/// The numbers a device translates its addresses with, without borrowing the backing.
#[derive(Clone, Copy, Debug)]
pub struct View {
    offset: u64,
    base: usize,
    len: usize,
}

/// One buffer of a chain, as the device sees it.
#[derive(Clone, Copy, Debug)]
pub struct SeenBuf {
    pub phys: u64,
    pub len: u32,
    pub device_writes: bool,
}

/// A chain the device took off the available ring.
#[derive(Clone, Debug)]
pub struct SeenChain {
    pub head: u16,
    pub buffers: Vec<SeenBuf>,
}

/// The device side of a queue.
pub struct FakeDevice {
    desc: u64,
    avail: u64,
    used: u64,
    size: u16,
    /// The next available index this device has not taken.
    last_avail: u16,
    /// The next used slot it will write.
    used_idx: u16,
    offset: u64,
    base: usize,
    len: usize,
}

impl FakeDevice {
    pub fn new(backing: &Backing, ring: &Ring) -> FakeDevice {
        FakeDevice::at(
            backing.view(),
            ring.desc_phys(),
            ring.avail_phys(),
            ring.used_phys(),
            ring.size(),
        )
    }

    /// A device for rings at these device addresses, as a transport learns them.
    pub fn at(view: View, desc: u64, avail: u64, used: u64, size: u16) -> FakeDevice {
        FakeDevice {
            desc,
            avail,
            used,
            size,
            last_avail: 0,
            used_idx: 0,
            offset: view.offset,
            base: view.base,
            len: view.len,
        }
    }

    /// The memory at device address `phys`, checked to lie inside what the driver shares.
    pub fn region(&self, phys: u64, len: usize) -> Dma {
        let virt = usize::try_from(phys - self.offset).expect("a device address");
        assert!(
            virt >= self.base && virt + len <= self.base + self.len,
            "the device was given an address outside the memory it shares with the driver: \
             {phys:#x} is not in the backing"
        );
        // SAFETY: checked to be inside the backing buffer, which outlives this device.
        unsafe { Dma::new(virt, phys, len) }
    }

    /// Take the next chain off the available ring, if the driver published one.
    pub fn take_available(&mut self) -> Option<SeenChain> {
        let avail = self.region(self.avail, 6 + 2 * usize::from(self.size));
        let idx = avail.read16(2);
        if idx == self.last_avail {
            return None;
        }
        let slot = usize::from(self.last_avail % self.size);
        let head = avail.read16(4 + 2 * slot);
        self.last_avail = self.last_avail.wrapping_add(1);

        let table = self.region(self.desc, 16 * usize::from(self.size));
        let mut buffers = Vec::new();
        let mut i = head;
        loop {
            let at = 16 * usize::from(i);
            let phys = u64::from(table.read32(at)) | (u64::from(table.read32(at + 4)) << 32);
            let len = table.read32(at + 8);
            let flags = table.read16(at + 12);
            buffers.push(SeenBuf {
                phys,
                len,
                device_writes: flags & VIRTQ_DESC_F_WRITE != 0,
            });
            if flags & VIRTQ_DESC_F_NEXT == 0 {
                break;
            }
            i = table.read16(at + 14);
            assert!(buffers.len() <= usize::from(self.size), "a chain that loops");
        }
        Some(SeenChain { head, buffers })
    }

    /// Report a chain finished.
    pub fn complete(&mut self, head: u16, written: u32) {
        self.complete_raw(u32::from(head), written);
    }

    /// Report a completion with whatever descriptor id, including one that does not exist.
    pub fn complete_raw(&mut self, id: u32, written: u32) {
        let used = self.region(self.used, 6 + 8 * usize::from(self.size));
        let slot = usize::from(self.used_idx % self.size);
        used.write32(4 + 8 * slot, id);
        used.write32(4 + 8 * slot + 4, written);
        self.used_idx = self.used_idx.wrapping_add(1);
        used.write16(2, self.used_idx);
    }
}

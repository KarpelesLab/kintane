//! Memory the device reads and writes, and most of the `unsafe` in the crate.
//!
//! The device's *registers* are not here: they are reached through [`hwproxy::Regs`], so the
//! same transports run over the kernel's mapping of a window and over a domain's. What is
//! here is the other kind of memory a driver touches:
//!
//! * [`Dma`] — memory *the device* reads and writes: the virtqueue rings, request headers, and the
//!   bounce buffer. What makes it different from ordinary kernel memory is that the driver must
//!   know the address **the device** uses, because that is the only address the device has. Both
//!   addresses are carried, and the type keeps them apart: [`Dma::phys`] is what goes into a
//!   descriptor, and [`Dma::virt`] is what the CPU dereferences.
//!
//! # With and without an IOMMU
//!
//! Without an IOMMU the device is given physical addresses and can read and write every byte
//! of them — and every other byte of memory too. That is the status quo for a kernel driver.
//! Behind an IOMMU, [`Dma::phys`] is a device address the IOMMU translates, a grant of a
//! specific range to a specific device, and a driver that names memory outside its grant
//! faults in the IOMMU instead of corrupting the kernel (`docs/isolation.md`). Nothing above
//! this module changes between the two, which is why the distinction has been in the type
//! since before it started to bite.

#![allow(unsafe_code)]

use core::ptr::{
    read_volatile, with_exposed_provenance, with_exposed_provenance_mut, write_volatile,
};

/// Memory the device reads and writes, addressed both ways.
///
/// Not `Clone`: a region is owned by whatever is using it, and two owners of one region
/// would be two writers of one descriptor table.
#[derive(Debug)]
pub struct Dma {
    virt: usize,
    phys: u64,
    len: usize,
}

impl Dma {
    /// # Safety
    /// `[virt, virt + len)` must be mapped, writable, and exactly the memory the device
    /// reaches at `[phys, phys + len)`, for as long as the region is used; and no other
    /// reference to it may exist, because the device writes into it.
    pub const unsafe fn new(virt: usize, phys: u64, len: usize) -> Dma {
        Dma { virt, phys, len }
    }

    /// A region over a buffer a host granted, as the proxy layer describes it: how a driver
    /// domain turns the memory the kernel gave it into the rings and buffers it runs on.
    ///
    /// # Safety
    /// As [`Dma::new`], for `d`'s addresses.
    pub unsafe fn from_proxy(d: &impl hwproxy::Dma) -> Dma {
        Dma {
            virt: d.virt(),
            phys: d.phys(),
            len: d.len(),
        }
    }

    /// The address the device uses.
    pub fn phys(&self) -> u64 {
        self.phys
    }

    /// The address the CPU uses.
    pub fn virt(&self) -> usize {
        self.virt
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Take `len` bytes from the front, aligned up to `align`, leaving the rest.
    ///
    /// `None` if the region cannot satisfy it, which is how a driver finds out at
    /// bring-up that its region is too small rather than by running off the end of it.
    pub fn take(&mut self, len: usize, align: usize) -> Option<Dma> {
        debug_assert!(align.is_power_of_two());
        let pad = self.virt.wrapping_neg() & (align - 1);
        let start = self.virt.checked_add(pad)?;
        let end = start.checked_add(len)?;
        if end > self.virt.checked_add(self.len)? {
            return None;
        }
        let taken = Dma {
            virt: start,
            phys: self.phys.checked_add(pad as u64)?,
            len,
        };
        let used = pad + len;
        self.virt += used;
        self.phys += used as u64;
        self.len -= used;
        Some(taken)
    }

    fn at<T>(&self, offset: usize) -> Option<usize> {
        let size = size_of::<T>();
        let end = offset.checked_add(size)?;
        let addr = self.virt.checked_add(offset)?;
        (end <= self.len && addr % size == 0).then_some(addr)
    }

    /// Read a value the device may be writing concurrently.
    pub fn read16(&self, offset: usize) -> u16 {
        match self.at::<u16>(offset) {
            // SAFETY: inside the region, aligned, and the constructor's contract is that
            // the region is mapped and writable. Volatile: the device writes here.
            Some(addr) => unsafe { read_volatile(with_exposed_provenance::<u16>(addr)) },
            None => {
                debug_assert!(false, "DMA read outside the region");
                0
            }
        }
    }

    pub fn read32(&self, offset: usize) -> u32 {
        match self.at::<u32>(offset) {
            // SAFETY: as `read16`.
            Some(addr) => unsafe { read_volatile(with_exposed_provenance::<u32>(addr)) },
            None => {
                debug_assert!(false, "DMA read outside the region");
                0
            }
        }
    }

    pub fn write16(&self, offset: usize, value: u16) {
        match self.at::<u16>(offset) {
            // SAFETY: as `read16`.
            Some(addr) => unsafe {
                write_volatile(with_exposed_provenance_mut::<u16>(addr), value)
            },
            None => debug_assert!(false, "DMA write outside the region"),
        }
    }

    pub fn write32(&self, offset: usize, value: u32) {
        match self.at::<u32>(offset) {
            // SAFETY: as `read16`.
            Some(addr) => unsafe {
                write_volatile(with_exposed_provenance_mut::<u32>(addr), value)
            },
            None => debug_assert!(false, "DMA write outside the region"),
        }
    }

    pub fn write64(&self, offset: usize, value: u64) {
        self.write32(offset, value as u32);
        self.write32(offset + 4, (value >> 32) as u32);
    }

    pub fn write8(&self, offset: usize, value: u8) {
        match self.at::<u8>(offset) {
            // SAFETY: as `read16`.
            Some(addr) => unsafe { write_volatile(with_exposed_provenance_mut::<u8>(addr), value) },
            None => debug_assert!(false, "DMA write outside the region"),
        }
    }

    pub fn read8(&self, offset: usize) -> u8 {
        match self.at::<u8>(offset) {
            // SAFETY: as `read16`.
            Some(addr) => unsafe { read_volatile(with_exposed_provenance::<u8>(addr)) },
            None => {
                debug_assert!(false, "DMA read outside the region");
                0
            }
        }
    }

    /// Copy `bytes` into the region at `offset`. `false` if it does not fit.
    pub fn write_bytes(&self, offset: usize, bytes: &[u8]) -> bool {
        if offset
            .checked_add(bytes.len())
            .is_none_or(|end| end > self.len)
        {
            debug_assert!(false, "DMA write outside the region");
            return false;
        }
        for (i, &b) in bytes.iter().enumerate() {
            self.write8(offset + i, b);
        }
        true
    }

    /// Copy out of the region at `offset` into `bytes`. `false` if it does not fit.
    pub fn read_bytes(&self, offset: usize, bytes: &mut [u8]) -> bool {
        if offset
            .checked_add(bytes.len())
            .is_none_or(|end| end > self.len)
        {
            debug_assert!(false, "DMA read outside the region");
            return false;
        }
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = self.read8(offset + i);
        }
        true
    }

    /// Zero the whole region. The virtqueue layout requires it: a ring the device reads
    /// before the driver has written every field must read zeroes, not whatever the
    /// previous owner of the frames left.
    pub fn zero(&self) {
        for i in 0..self.len {
            self.write8(i, 0);
        }
    }
}

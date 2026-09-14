//! The two kinds of memory a device driver touches, and the only `unsafe` in the crate.
//!
//! * [`Window`] — the device's registers. A claimed MMIO window, accessed at the widths the
//!   register layout uses, with every access checked against the window's bounds.
//!   `device::Registers` does this for 32-bit registers; virtio's PCI common configuration is 8,
//!   16, 32 and 64 bits wide, so this is the same idea with the other widths.
//! * [`Dma`] — memory *the device* reads and writes: the virtqueue rings, request headers, and the
//!   bounce buffer. What makes it different from ordinary kernel memory is that the driver must
//!   know its **physical** address, because that is the only address the device has. Both addresses
//!   are carried, and the type keeps them apart: [`Dma::phys`] is what goes into a descriptor, and
//!   [`Dma::virt`] is what the CPU dereferences.
//!
//! # No IOMMU yet
//!
//! The device is given physical addresses and can read and write every byte of them — and,
//! without an IOMMU, every other byte of memory too. That is the status quo for a kernel
//! driver, and it is what Phase 5's driver isolation is for: with an IOMMU, [`Dma`] becomes
//! a grant of a specific range to a specific device, [`Dma::phys`] becomes a device address
//! rather than a physical one, and a driver that names memory outside its grant faults in
//! the IOMMU instead of corrupting the kernel. Nothing above this module would change,
//! which is why the distinction is in the type today rather than the day it starts to bite.

#![allow(unsafe_code)]

use core::ptr::{
    read_volatile, with_exposed_provenance, with_exposed_provenance_mut, write_volatile,
};

/// A mapped register window, read and written at 8, 16, 32 and 64 bits.
///
/// An access outside the window reads all-ones and writes nothing, as an absent device
/// does on most buses, rather than reaching whatever is mapped next to it.
#[derive(Clone, Copy, Debug)]
pub struct Window {
    base: usize,
    len: usize,
}

macro_rules! accessors {
    ($($read:ident, $write:ident, $ty:ty;)*) => {$(
        /// Read the register at `offset`. Outside the window, all-ones.
        pub fn $read(&self, offset: usize) -> $ty {
            match self.at::<$ty>(offset) {
                Some(addr) => {
                    // SAFETY: `at` checked that a whole, naturally aligned value lies inside
                    // the window, and the constructor's contract is that the window is mapped
                    // as device memory. Volatile, because a device distinguishes accesses the
                    // compiler would merge or drop.
                    unsafe { read_volatile(with_exposed_provenance::<$ty>(addr)) }
                }
                None => {
                    debug_assert!(false, "register read outside the window");
                    <$ty>::MAX
                }
            }
        }

        /// Write the register at `offset`. Outside the window, nothing.
        pub fn $write(&self, offset: usize, value: $ty) {
            match self.at::<$ty>(offset) {
                // SAFETY: as the reader above.
                Some(addr) => unsafe {
                    write_volatile(with_exposed_provenance_mut::<$ty>(addr), value)
                },
                None => debug_assert!(false, "register write outside the window"),
            }
        }
    )*};
}

impl Window {
    /// # Safety
    /// `[base, base + len)` must be mapped at that virtual address, as device memory that
    /// neither caches nor reorders accesses, for as long as the window is used.
    pub const unsafe fn new(base: usize, len: usize) -> Window {
        Window { base, len }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    /// A window over part of this one, or `None` if it does not fit.
    pub fn sub(&self, offset: usize, len: usize) -> Option<Window> {
        let end = offset.checked_add(len)?;
        (end <= self.len).then(|| Window {
            base: self.base.checked_add(offset).unwrap_or(0),
            len,
        })
    }

    /// The address of a naturally aligned `T` at `offset`, if it lies inside the window.
    fn at<T>(&self, offset: usize) -> Option<usize> {
        let size = size_of::<T>();
        let end = offset.checked_add(size)?;
        let addr = self.base.checked_add(offset)?;
        (end <= self.len && addr % size == 0).then_some(addr)
    }

    accessors! {
        read8, write8, u8;
        read16, write16, u16;
        read32, write32, u32;
    }

    /// A 64-bit register, read as two halves.
    ///
    /// virtio's own rule: a 64-bit field of the common configuration may be accessed as two
    /// 32-bit halves (virtio 1.1 §4.1.3.1), and a device whose window is not 64-bit capable
    /// must be. Every 64-bit field this driver touches is written before the device is told
    /// to look at it, so a torn value is never observed.
    pub fn read64(&self, offset: usize) -> u64 {
        u64::from(self.read32(offset)) | (u64::from(self.read32(offset + 4)) << 32)
    }

    pub fn write64(&self, offset: usize, value: u64) {
        self.write32(offset, value as u32);
        self.write32(offset + 4, (value >> 32) as u32);
    }
}

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
    /// `[virt, virt + len)` must be mapped, writable, and exactly the memory at physical
    /// `[phys, phys + len)`, for as long as the region is used; and no other reference to
    /// it may exist, because the device writes into it.
    pub const unsafe fn new(virt: usize, phys: u64, len: usize) -> Dma {
        Dma { virt, phys, len }
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

//! The proxy layer: what a driver is allowed to do to hardware, as traits.
//!
//! `docs/roadmap.md` Phase 5 asks for `Mmio<T>`, `DmaBuffer` and `IrqLine` "implemented
//! over domain crossing, with the same driver source running either way". This is that
//! interface. A driver body takes a [`Hw`] and never names a pointer, a physical address
//! or an interrupt controller, so the same source compiles into the kernel image and into
//! an unprivileged domain program.
//!
//! # The three capabilities
//!
//! * [`Regs`] — the device's registers. Every access is checked against the window, so a driver
//!   whose offset arithmetic is wrong reads all-ones and writes nothing, which is what an absent
//!   device does on most buses, rather than reaching whatever is mapped beside it.
//! * [`Dma`] — memory *the device* reads and writes. The driver needs its physical address, because
//!   that is the only address the device has, and its virtual address, because that is the only one
//!   the CPU has. Both are carried and the type keeps them apart.
//! * [`Irq`] — the device's interrupt, as a count the driver waits on. A handler in the kernel and
//!   a message from the kernel are the same thing to a driver: something happened, how many times.
//!
//! # What isolation actually costs
//!
//! The naive expectation is that an isolated driver pays on every register access. It does
//! not, and the reason is worth stating because it decides the whole design: the kernel
//! *maps the granted window into the domain*, so a register access in a domain is the same
//! load or store it was in the kernel, executed in ring 3 on a page the domain was given.
//! The MMU is the proxy. What isolation adds is at the edges — establishing the grant,
//! and delivering the interrupt as a message — and that is what `docs/isolation.md`
//! measures.
//!
//! So [`Direct`] is not "the in-kernel implementation" and something else the isolated one:
//! it is the accessor *both* modes use for registers, differing only in who mapped the
//! window and what privilege the code runs at. The crossing appears in [`Irq`], where the
//! kernel's implementation reads a counter a handler bumped and the domain's reads messages
//! from a channel.

#![cfg_attr(not(test), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(test)]
mod tests;

/// A window of device registers.
///
/// Offsets are from the window's first byte. An access that does not lie wholly inside the
/// window, or is not naturally aligned, reads all-ones and writes nothing — what an absent
/// device does on most buses.
///
/// A refusal is silent by design. An implementation of this trait may be handed to a driver
/// the host does not trust, so a bad offset has to be something the driver observes, not
/// something that panics whoever granted the window.
pub trait Regs {
    /// Bytes in the window.
    fn len(&self) -> usize;

    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn read8(&self, offset: usize) -> u8;
    fn read16(&self, offset: usize) -> u16;
    fn read32(&self, offset: usize) -> u32;
    fn read64(&self, offset: usize) -> u64;

    fn write8(&self, offset: usize, value: u8);
    fn write16(&self, offset: usize, value: u16);
    fn write32(&self, offset: usize, value: u32);
    fn write64(&self, offset: usize, value: u64);
}

/// Memory the device reads and writes.
///
/// Whoever hosts the driver allocates it: the kernel from its frame allocator, a domain
/// from the grant the kernel gave it. The driver only ever asks where it is.
pub trait Dma {
    /// The address the *device* uses. What goes into a descriptor.
    fn phys(&self) -> u64;

    /// The address the *CPU* uses. What the driver dereferences.
    fn virt(&self) -> usize;

    /// Bytes in the buffer.
    fn len(&self) -> usize;

    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// The device's interrupt.
///
/// A driver does not learn how its interrupt is delivered. In the kernel a handler bumps a
/// counter; in a domain the kernel sends a message. Both answer the only question a driver
/// asks: how many have happened since I last looked.
pub trait Irq {
    /// Interrupts delivered since the device was started.
    fn count(&self) -> u64;

    /// Acknowledge everything up to `count`. A driver that has handled what it saw calls
    /// this so the host can tell a quiet device from a driver that stopped looking.
    fn acknowledge(&self, count: u64);
}

/// Everything a driver may do to its device.
///
/// One parameter rather than three, so a driver body reads `fn start<H: Hw>(hw: &H)` and a
/// host decides all three implementations together.
pub trait Hw {
    type Regs: Regs;
    type Dma: Dma;
    type Irq: Irq;

    fn regs(&self) -> &Self::Regs;
    fn dma(&self) -> &Self::Dma;
    fn irq(&self) -> &Self::Irq;
}

/// Registers reached by ordinary loads and stores, at the address they are mapped at.
///
/// Used by both modes: in the kernel over a window the kernel address space maps, and in a
/// domain over the same physical window mapped into the domain. The difference is who
/// mapped it, which is the point of the design and not visible here.
#[derive(Clone, Copy, Debug)]
pub struct Direct {
    base: usize,
    len: usize,
}

impl Direct {
    /// # Safety
    /// `[base, base + len)` must be mapped at that address, as device memory that neither
    /// caches nor reorders accesses, for as long as this value is used.
    pub const unsafe fn new(base: usize, len: usize) -> Direct {
        Direct { base, len }
    }

    /// The first byte, as the code using it addresses it.
    pub fn base(&self) -> usize {
        self.base
    }

    /// The address of an access of `size` bytes at `offset`, if it fits and is aligned.
    fn at(&self, offset: usize, size: usize) -> Option<usize> {
        let end = offset.checked_add(size)?;
        (offset % size == 0 && end <= self.len)
            .then(|| self.base.checked_add(offset))
            .flatten()
    }
}

/// The accessors, one pair per width. Written once as a macro because the only difference
/// between them is the type, and four hand-written pairs is four places to get a bound
/// check wrong.
macro_rules! direct_accessors {
    ($($read:ident, $write:ident, $ty:ty;)*) => {$(
        fn $read(&self, offset: usize) -> $ty {
            match self.at(offset, size_of::<$ty>()) {
                // SAFETY: `at` checked that a whole, naturally aligned value lies inside
                // the window, and the constructor's contract is that the window is mapped
                // as device memory. Volatile, because a device distinguishes accesses the
                // compiler would merge or drop.
                Some(addr) => unsafe {
                    core::ptr::read_volatile(core::ptr::with_exposed_provenance::<$ty>(addr))
                },
                // Quietly, not with a `debug_assert!` as the device layer's own
                // accessors do. Those refuse a kernel driver's arithmetic mistake, and a
                // panic is the right way to report it. This window may be handed to an
                // isolated driver whose whole premise is that it is not trusted: a bad
                // offset from one must be a refusal it observes, never a way to bring
                // down the host that granted it.
                None => <$ty>::MAX,
            }
        }

        fn $write(&self, offset: usize, value: $ty) {
            match self.at(offset, size_of::<$ty>()) {
                // SAFETY: as the reader above.
                Some(addr) => unsafe {
                    core::ptr::write_volatile(
                        core::ptr::with_exposed_provenance_mut::<$ty>(addr),
                        value,
                    )
                },
                // Refused quietly; see the reader above.
                None => {}
            }
        }
    )*};
}

#[allow(unsafe_code)]
impl Regs for Direct {
    fn len(&self) -> usize {
        self.len
    }

    direct_accessors! {
        read8, write8, u8;
        read16, write16, u16;
        read32, write32, u32;
        read64, write64, u64;
    }
}

/// A buffer at a known physical address, mapped at a known virtual one.
///
/// The kernel builds it from frames it owns; a domain builds it from the grant it was
/// given, whose physical address the kernel told it. Neither can invent one: this type
/// carries two numbers and no authority.
#[derive(Clone, Copy, Debug)]
pub struct Buffer {
    phys: u64,
    virt: usize,
    len: usize,
}

impl Buffer {
    /// # Safety
    /// `[virt, virt + len)` must be mapped, writable, and backed by physical memory
    /// starting at `phys`, for as long as this value is used.
    pub const unsafe fn new(phys: u64, virt: usize, len: usize) -> Buffer {
        Buffer { phys, virt, len }
    }
}

impl Dma for Buffer {
    fn phys(&self) -> u64 {
        self.phys
    }

    fn virt(&self) -> usize {
        self.virt
    }

    fn len(&self) -> usize {
        self.len
    }
}

/// A device with no DMA: a driver that asks for a buffer gets an empty one rather than a
/// pointer into memory nobody granted.
pub const NO_DMA: Buffer = Buffer {
    phys: 0,
    virt: 0,
    len: 0,
};

/// An interrupt that never fires: a polling driver, or a device whose line the host did
/// not wire up.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoIrq;

impl Irq for NoIrq {
    fn count(&self) -> u64 {
        0
    }

    fn acknowledge(&self, _count: u64) {}
}

/// A [`Hw`] assembled from its three parts, for a host that has them in hand.
pub struct Parts<R, D, I> {
    pub regs: R,
    pub dma: D,
    pub irq: I,
}

impl<R: Regs, D: Dma, I: Irq> Hw for Parts<R, D, I> {
    type Regs = R;
    type Dma = D;
    type Irq = I;

    fn regs(&self) -> &R {
        &self.regs
    }

    fn dma(&self) -> &D {
        &self.dma
    }

    fn irq(&self) -> &I {
        &self.irq
    }
}

//! The one place `kalloc` turns a physical address into something dereferenceable.
//!
//! # The problem
//!
//! `mm::FrameAllocator` hands out [`PhysAddr`]. A heap hands out pointers, and a
//! pointer is virtual. Nothing in `mm` bridges that, deliberately — its module
//! documentation says it "never dereferences a physical address", because the frame
//! allocator is one of the things needed to *build* the mapping, so it cannot depend
//! on one existing.
//!
//! The heap is the first subsystem that has to. And today there is no page-table
//! code: the kernel runs on whatever mapping the loader left, which on every target
//! we currently boot is an identity map over low memory. So `virt == phys`, and the
//! shortest correct-today implementation is one cast.
//!
//! # Why the cast is not what this module does
//!
//! `phys.to_usize()? as *mut u8` is right until the kernel moves to the high half,
//! which is the next phase of work, and then it is wrong everywhere at once with no
//! compiler error and no test failure — the kind of thing this project exists to
//! avoid. The assumption is not that physical equals virtual; the assumption is that
//! *some* affine mapping exists, and that the bootstrap knows what it is. So the
//! mapping is a value, constructed once by the code that knows the answer, and the
//! allocators take it as a parameter:
//!
//! ```text
//!     phys_base                    phys_base + len
//!        ├──────────── len bytes ────────────┤        physical
//!        │                                   │
//!        ▼                                   ▼
//!     virt_base                    virt_base + len     kernel virtual
//! ```
//!
//! A window rather than a bare offset, because the window is the part that is
//! actually load bearing. A 64-bit kernel direct-maps all of RAM and the window is
//! "everything", so carrying it costs one comparison. A 32-bit kernel with more
//! physical memory than address space direct-maps *part* of RAM, and a frame outside
//! that part is not reachable through this map at all — [`DirectMap::to_virt`]
//! returns [`AllocError::Unmanaged`] for it rather than producing an address in
//! somebody else's mapping. That is the i686-with-PAE case, and it is the reason
//! [`PhysAddr::to_usize`] is fallible in the first place.
//!
//! # What this type does not promise
//!
//! It is a **claim, not a mapping**. Constructing a `DirectMap` does not program a
//! page table, does not check one, and cannot: there is no page-table code yet, and
//! when there is, the authority will be `mm::paged`. Whoever builds one is asserting
//! that the window is already mapped, readable and writable by the kernel — an
//! assertion the bootstrap can make because it is either relying on the loader's
//! identity map or has just installed the mapping itself.
//!
//! # When this stops being the answer
//!
//! Two ways, both expected:
//!
//! * **The kernel moves to the high half.** Nothing here changes except the argument at the one
//!   construction site, which is the whole point.
//! * **The heap needs memory that is not direct-mapped** — a vmalloc-style region stitched together
//!   from non-adjacent frames, or a target with no direct map at all. Then this type is no longer
//!   sufficient, and the replacement is an `AddressSpace` handle from `mm::paged` that can map a
//!   frame on request. The allocators above take the mapping as a parameter precisely so that
//!   swapping it is a change to a type parameter rather than to their logic.

// Re-enabled for exactly one operation: `KernAddr::as_ptr`, which is `unsafe`
// because forming a pointer is a promise about what may later be done with it. It
// is the narrowest possible seam — one expression, in one function, in this file —
// and the rest of the unit does its address arithmetic in `KernAddr` and `PhysAddr`
// so it never has to come near this.
#![allow(unsafe_code)]

use core::fmt;
use core::ptr::NonNull;

use hal::{KernAddr, PhysAddr};

use crate::{AllocError, narrow, widen};

/// A window of physical memory the kernel can reach through a fixed offset.
///
/// Cheap to copy — it is three integers — so every allocator that needs one holds
/// its own copy rather than borrowing.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct DirectMap {
    phys_base: PhysAddr,
    virt_base: KernAddr,
    len: u64,
}

impl DirectMap {
    /// A window of `len` bytes starting at `phys_base`, visible at `virt_base`.
    ///
    /// Everything that could overflow later is checked here instead, so that
    /// [`Self::to_virt`] and [`Self::to_phys`] fail only for addresses genuinely
    /// outside the window.
    ///
    /// # Errors
    /// [`AllocError::EmptyRequest`] for `len == 0` — a window nothing falls inside
    /// is not a mapping, and accepting one would turn a bootstrap mistake into a
    /// confusing `Unmanaged` at the first allocation. [`AllocError::Overflow`] if
    /// either end of the window leaves its address space, which on a 32-bit target
    /// includes a window larger than the kernel's own address space.
    pub fn new(phys_base: PhysAddr, virt_base: KernAddr, len: u64) -> Result<Self, AllocError> {
        if len == 0 {
            return Err(AllocError::EmptyRequest);
        }
        // The last *byte*, not one past the end: a window ending exactly at the top
        // of an address space is legitimate and must not be refused.
        let last = len.checked_sub(1).ok_or(AllocError::Overflow)?;
        phys_base.checked_add(last)?;
        virt_base.checked_add(narrow(last)?)?;
        Ok(DirectMap {
            phys_base,
            virt_base,
            len,
        })
    }

    /// The mapping in use today: physical `0` visible at virtual `0`, for `len` bytes.
    ///
    /// This is the loader's identity map, named rather than assumed. A caller that
    /// writes `DirectMap::identity(ram_bytes)` has recorded which assumption it is
    /// making, and `grep identity` finds every place that will need revisiting when
    /// the kernel moves to the high half.
    ///
    /// # Errors
    /// As [`Self::new`].
    pub fn identity(len: u64) -> Result<Self, AllocError> {
        Self::new(PhysAddr::ZERO, KernAddr::ZERO, len)
    }

    /// The window `[0, len)` of physical memory, visible `offset` bytes higher.
    ///
    /// The high-half form: `virt = phys + offset`. Equivalent to [`Self::new`] with a
    /// physical base of zero, and spelled separately because that is how a kernel
    /// with a fixed direct-map base thinks about it.
    ///
    /// # Errors
    /// As [`Self::new`]; in particular [`AllocError::Overflow`] if `offset + len`
    /// leaves the kernel's address space, which is the check that catches a 64-bit
    /// direct-map base copied into a 32-bit build.
    pub fn with_offset(offset: usize, len: u64) -> Result<Self, AllocError> {
        Self::new(PhysAddr::ZERO, KernAddr::new(offset), len)
    }

    /// First physical byte of the window.
    pub fn phys_base(self) -> PhysAddr {
        self.phys_base
    }

    /// Where that byte is visible in the kernel's address space.
    pub fn virt_base(self) -> KernAddr {
        self.virt_base
    }

    /// Length of the window in bytes. Never zero.
    ///
    /// `u64` rather than `usize`: a 64-bit kernel's direct map can legitimately be
    /// described in terms wider than a 32-bit build's pointer, and refusing to say so
    /// is how the wide case gets quietly forgotten.
    pub fn len(self) -> u64 {
        self.len
    }

    /// Whether a physical address falls inside the window.
    pub fn covers_phys(self, phys: PhysAddr) -> bool {
        match phys.diff(self.phys_base) {
            Ok(off) => off < self.len,
            Err(_) => false,
        }
    }

    /// Whether a kernel-virtual address falls inside the window.
    pub fn covers_virt(self, virt: KernAddr) -> bool {
        match virt.diff(self.virt_base) {
            Ok(off) => widen(off) < self.len,
            Err(_) => false,
        }
    }

    /// Where `phys` is visible in the kernel's address space.
    ///
    /// # Errors
    /// [`AllocError::Unmanaged`] if `phys` is outside the window — including below
    /// it, which is the common shape on a board whose RAM starts high.
    /// [`AllocError::Overflow`] if the offset does not fit in a pointer. That second
    /// case is the real one: on i686 with PAE a frame above 4 GiB is inside the
    /// machine's memory and outside anything a 32-bit kernel can address directly,
    /// and saying so is better than handing back a truncated pointer.
    pub fn to_virt(self, phys: PhysAddr) -> Result<KernAddr, AllocError> {
        let off = phys
            .diff(self.phys_base)
            .map_err(|_| AllocError::Unmanaged)?;
        if off >= self.len {
            return Err(AllocError::Unmanaged);
        }
        Ok(self.virt_base.checked_add(narrow(off)?)?)
    }

    /// Which physical address a kernel-virtual one refers to.
    ///
    /// The inverse of [`Self::to_virt`], and needed for real work rather than
    /// symmetry: a DMA buffer's owner has a pointer and the device needs the physical
    /// address behind it.
    ///
    /// # Errors
    /// [`AllocError::Unmanaged`] if `virt` is outside the window.
    pub fn to_phys(self, virt: KernAddr) -> Result<PhysAddr, AllocError> {
        let off = virt
            .diff(self.virt_base)
            .map_err(|_| AllocError::Unmanaged)?;
        let off = widen(off);
        if off >= self.len {
            return Err(AllocError::Unmanaged);
        }
        Ok(self.phys_base.checked_add(off)?)
    }

    /// A pointer to the byte at `virt`.
    ///
    /// This is the unsafe seam of the whole unit, and it is one expression wide.
    /// Forming the pointer reads and writes nothing; the obligation it creates is
    /// discharged by the allocators above, which only ever form pointers into frames
    /// they took from a [`crate::FrameSource`] and have not given back.
    ///
    /// # Errors
    /// [`AllocError::Unmanaged`] if `virt` is outside the window, or if the window
    /// places it at virtual zero. The second case is not pedantry: an identity map
    /// makes physical frame zero into a null pointer, and a null pointer is the one
    /// value a `NonNull` may not hold.
    pub fn ptr_at(self, virt: KernAddr) -> Result<NonNull<u8>, AllocError> {
        if !self.covers_virt(virt) {
            return Err(AllocError::Unmanaged);
        }
        // SAFETY: `as_ptr` forms a pointer and does not dereference it, so the
        // obligation is that the address is one the kernel may later access. It is:
        // the check above puts it inside the window, and constructing a `DirectMap`
        // is the bootstrap's assertion that the whole window is mapped into the
        // kernel's address space, readable and writable. This stops being true if a
        // `DirectMap` is ever built for a window that is not mapped — which is why
        // that constructor is documented as a claim and why there is exactly one of
        // it per kernel.
        let raw: *mut u8 = unsafe { virt.as_ptr::<u8>() };
        NonNull::new(raw).ok_or(AllocError::Unmanaged)
    }

    /// A pointer to the byte at physical address `phys`.
    ///
    /// # Errors
    /// As [`Self::to_virt`] and [`Self::ptr_at`].
    pub fn ptr_to_phys(self, phys: PhysAddr) -> Result<NonNull<u8>, AllocError> {
        self.ptr_at(self.to_virt(phys)?)
    }
}

impl fmt::Debug for DirectMap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DirectMap({} -> {}, {:#x} bytes)", self.phys_base, self.virt_base, self.len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[track_caller]
    fn expect<T>(r: Result<T, AllocError>) -> T {
        match r {
            Ok(v) => v,
            Err(e) => panic!("unexpected {e:?}"),
        }
    }

    #[test]
    fn the_identity_map_is_the_assumption_today() {
        let m = expect(DirectMap::identity(0x1_0000));
        assert_eq!(expect(m.to_virt(PhysAddr::new(0x1234))), KernAddr::new(0x1234));
        assert_eq!(expect(m.to_phys(KernAddr::new(0x1234))), PhysAddr::new(0x1234));
    }

    #[test]
    fn an_offset_map_is_the_same_code_with_a_different_argument() {
        // The high-half shape, scaled down so it fits a 32-bit host's pointer too.
        let m = expect(DirectMap::with_offset(0x8000_0000, 0x1000));
        assert_eq!(expect(m.to_virt(PhysAddr::new(0x40))), KernAddr::new(0x8000_0040));
        assert_eq!(expect(m.to_phys(KernAddr::new(0x8000_0040))), PhysAddr::new(0x40));
    }

    #[test]
    fn a_window_that_does_not_start_at_zero_round_trips() {
        // The ARM board shape: RAM at 0x4000_0000, mapped at a low kernel address.
        let m = expect(DirectMap::new(PhysAddr::new(0x4000_0000), KernAddr::new(0x1000), 0x2000));
        assert_eq!(expect(m.to_virt(PhysAddr::new(0x4000_0100))), KernAddr::new(0x1100));
        assert_eq!(expect(m.to_phys(KernAddr::new(0x1100))), PhysAddr::new(0x4000_0100));
        // Below the window is not "offset zero"; it is outside.
        assert_eq!(m.to_virt(PhysAddr::new(0x3FFF_FFFF)), Err(AllocError::Unmanaged));
        assert!(!m.covers_phys(PhysAddr::new(0x3FFF_FFFF)));
    }

    #[test]
    fn addresses_past_the_window_are_refused_rather_than_extrapolated() {
        let m = expect(DirectMap::identity(0x1000));
        assert!(m.covers_phys(PhysAddr::new(0xFFF)));
        assert!(!m.covers_phys(PhysAddr::new(0x1000)));
        assert_eq!(m.to_virt(PhysAddr::new(0x1000)), Err(AllocError::Unmanaged));
        assert_eq!(m.to_phys(KernAddr::new(0x1000)), Err(AllocError::Unmanaged));
        assert_eq!(m.ptr_at(KernAddr::new(0x1000)), Err(AllocError::Unmanaged));
    }

    #[test]
    fn an_empty_window_is_not_a_mapping() {
        assert_eq!(DirectMap::identity(0).err(), Some(AllocError::EmptyRequest));
    }

    #[test]
    fn a_window_that_would_leave_the_address_space_is_refused() {
        assert_eq!(
            DirectMap::new(PhysAddr::new(u64::MAX - 3), KernAddr::new(4096), 8).err(),
            Some(AllocError::Overflow)
        );
        assert_eq!(
            DirectMap::new(PhysAddr::ZERO, KernAddr::new(usize::MAX - 3), 8).err(),
            Some(AllocError::Overflow)
        );
        // A window ending exactly at the top is fine and must not be refused: an
        // off-by-one here would make the last page of memory unreachable.
        assert!(DirectMap::new(PhysAddr::new(u64::MAX - 7), KernAddr::new(4096), 8).is_ok());
        assert!(DirectMap::new(PhysAddr::ZERO, KernAddr::new(usize::MAX - 7), 8).is_ok());
    }

    #[test]
    fn physical_memory_a_pointer_cannot_reach_is_an_overflow_not_a_truncation() {
        // A 36-bit physical window, as i686-with-PAE has. On a 64-bit host every
        // address converts; on a 32-bit one the high half of the window cannot be
        // reached at all, and the conversion must say so rather than wrap.
        let m = expect(DirectMap::new(PhysAddr::ZERO, KernAddr::ZERO, 0x10_0000_0000));
        let high = PhysAddr::new(0xF_0000_0000);
        assert!(m.covers_phys(high), "the memory exists either way");
        if core::mem::size_of::<usize>() == 4 {
            assert_eq!(m.to_virt(high), Err(AllocError::Overflow));
        } else {
            assert_eq!(expect(m.to_virt(high)), KernAddr::new(0xF_0000_0000));
        }
    }

    #[test]
    fn an_identity_map_will_not_hand_back_a_null_pointer() {
        // Physical frame zero is a real frame and a null pointer. `NonNull` may not
        // hold it, so the conversion fails rather than the type system being lied to.
        let m = expect(DirectMap::identity(0x1000));
        assert_eq!(m.ptr_at(KernAddr::ZERO), Err(AllocError::Unmanaged));
        assert!(m.ptr_at(KernAddr::new(1)).is_ok());
    }
}

//! Address types.
//!
//! Physical, kernel-virtual and user-virtual addresses are three distinct types with
//! no implicit conversion between them. Conflating them is one of the most common
//! kernel bug classes, and it is one the type system can simply remove.
//!
//! The important asymmetry: **`PhysAddr` is always 64-bit, never `usize`.** On i686
//! with PAE a physical address is 36 bits behind a 32-bit pointer, so a physical
//! address does not fit in a pointer. Any kernel written 64-bit-first grows the
//! `usize`-as-physical-address assumption within a week; this type is why our i686
//! target exists to catch it. See `docs/targets.md#i686`.

use core::fmt;

/// A physical address. Always 64 bits wide, on every target.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[repr(transparent)]
pub struct PhysAddr(u64);

/// An address in the kernel's own address space.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[repr(transparent)]
pub struct KernAddr(usize);

/// An address in some user process's address space.
///
/// Holding one of these says nothing about which process, and nothing about whether
/// it is mapped. It is never dereferenceable without an explicit, checked access.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[repr(transparent)]
pub struct UserAddr(usize);

/// Arithmetic that would leave the representable range.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct AddrOverflow;

macro_rules! common_ops {
    ($t:ident, $inner:ty, $name:literal) => {
        impl $t {
            pub const ZERO: Self = Self(0);

            #[inline]
            pub const fn raw(self) -> $inner {
                self.0
            }

            /// Round down to a multiple of `align`, which must be a power of two.
            #[inline]
            pub const fn align_down(self, align: $inner) -> Self {
                debug_assert!(align.is_power_of_two());
                Self(self.0 & !(align - 1))
            }

            /// Round up to a multiple of `align`, which must be a power of two.
            ///
            /// Checked in every build: the failure mode here is memory corruption,
            /// not a wrong number, so this is one of the places where address
            /// arithmetic is never allowed to wrap silently.
            #[inline]
            pub fn align_up(self, align: $inner) -> Result<Self, AddrOverflow> {
                debug_assert!(align.is_power_of_two());
                self.0
                    .checked_add(align - 1)
                    .map(|v| Self(v & !(align - 1)))
                    .ok_or(AddrOverflow)
            }

            #[inline]
            pub const fn is_aligned(self, align: $inner) -> bool {
                self.0 & (align - 1) == 0
            }

            /// Offset within the containing block of `size` bytes.
            #[inline]
            pub const fn offset_in(self, size: $inner) -> $inner {
                self.0 & (size - 1)
            }

            #[inline]
            pub fn checked_add(self, n: $inner) -> Result<Self, AddrOverflow> {
                self.0.checked_add(n).map(Self).ok_or(AddrOverflow)
            }

            #[inline]
            pub fn checked_sub(self, n: $inner) -> Result<Self, AddrOverflow> {
                self.0.checked_sub(n).map(Self).ok_or(AddrOverflow)
            }

            /// Distance from `earlier` to `self`.
            #[inline]
            pub fn diff(self, earlier: Self) -> Result<$inner, AddrOverflow> {
                self.0.checked_sub(earlier.0).ok_or(AddrOverflow)
            }
        }

        impl fmt::Debug for $t {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, concat!($name, "({:#x})"), self.0)
            }
        }

        impl fmt::Display for $t {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{:#x}", self.0)
            }
        }
    };
}

common_ops!(PhysAddr, u64, "PhysAddr");
common_ops!(KernAddr, usize, "KernAddr");
common_ops!(UserAddr, usize, "UserAddr");

impl PhysAddr {
    /// Construct from a raw value.
    ///
    /// Deliberately not `From<u64>`: building a physical address is a decision, and
    /// making it explicit keeps it out of inference.
    #[inline]
    pub const fn new(v: u64) -> Self {
        Self(v)
    }

    /// Truncate to `bits`, the architecture's `PHYS_ADDR_BITS`, reporting whether
    /// anything was lost. Used when reading an address out of a page table entry.
    #[inline]
    pub const fn truncate(self, bits: u8) -> (Self, bool) {
        if bits >= 64 {
            return (self, false);
        }
        let mask = (1u64 << bits) - 1;
        (Self(self.0 & mask), self.0 & !mask != 0)
    }

    /// Convert to a `usize`, which **can fail** and does on i686 with PAE.
    #[inline]
    pub fn to_usize(self) -> Result<usize, AddrOverflow> {
        usize::try_from(self.0).map_err(|_| AddrOverflow)
    }
}

impl KernAddr {
    #[inline]
    pub const fn new(v: usize) -> Self {
        Self(v)
    }

    /// # Safety
    /// The address must be mapped, correctly aligned for `T`, and the caller must
    /// uphold Rust's aliasing rules for the lifetime it chooses.
    #[inline]
    pub const unsafe fn as_ptr<T>(self) -> *mut T {
        self.0 as *mut T
    }
}

impl UserAddr {
    #[inline]
    pub const fn new(v: usize) -> Self {
        Self(v)
    }
    // Deliberately no `as_ptr`. A user address is never dereferenced directly; it is
    // accessed through checked copy-in/copy-out, which arrives with the syscall layer.
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alignment_rounds_both_ways() {
        let a = PhysAddr::new(0x1234);
        assert_eq!(a.align_down(0x1000), PhysAddr::new(0x1000));
        assert_eq!(a.align_up(0x1000).unwrap(), PhysAddr::new(0x2000));
        assert!(!a.is_aligned(0x1000));
        assert!(PhysAddr::new(0x2000).is_aligned(0x1000));
        // Already-aligned addresses must not move.
        assert_eq!(
            PhysAddr::new(0x2000).align_up(0x1000).unwrap(),
            PhysAddr::new(0x2000)
        );
    }

    #[test]
    fn align_up_overflow_is_reported_not_wrapped() {
        assert_eq!(PhysAddr::new(u64::MAX).align_up(0x1000), Err(AddrOverflow));
        assert_eq!(KernAddr::new(usize::MAX).align_up(0x1000), Err(AddrOverflow));
    }

    #[test]
    fn physical_addresses_exceed_pointer_width() {
        // The i686-with-PAE case: 36 bits of physical behind a 32-bit pointer.
        let high = PhysAddr::new(0xF_FFFF_F000);
        assert_eq!(high.raw(), 0xF_FFFF_F000);
        // On a 32-bit host this conversion fails, which is the point of it being
        // fallible rather than a cast.
        if core::mem::size_of::<usize>() == 4 {
            assert_eq!(high.to_usize(), Err(AddrOverflow));
        } else {
            assert_eq!(high.to_usize().unwrap(), 0xF_FFFF_F000usize);
        }
    }

    #[test]
    fn truncation_reports_loss() {
        let a = PhysAddr::new(0xFFFF_FFFF_FFFF_F000);
        let (t, lost) = a.truncate(52);
        assert!(lost, "bits above 52 were dropped and must be reported");
        assert_eq!(t, PhysAddr::new(0x000F_FFFF_FFFF_F000));

        let (t, lost) = PhysAddr::new(0x1000).truncate(52);
        assert!(!lost);
        assert_eq!(t, PhysAddr::new(0x1000));
    }

    #[test]
    fn offset_within_a_page() {
        assert_eq!(PhysAddr::new(0x1234).offset_in(0x1000), 0x234);
        assert_eq!(KernAddr::new(0x2000).offset_in(0x1000), 0);
    }

    #[test]
    fn diff_measures_distance() {
        let a = KernAddr::new(0x2000);
        let b = KernAddr::new(0x1000);
        assert_eq!(a.diff(b).unwrap(), 0x1000);
        assert_eq!(b.diff(a), Err(AddrOverflow));
    }
}

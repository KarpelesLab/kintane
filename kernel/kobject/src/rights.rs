//! Rights: what a handle permits.
//!
//! The central rule, from `docs/userspace-abi.md`: **rights can be narrowed when a
//! handle is duplicated or passed, never widened.** That is what makes the
//! capability model hold — a process cannot manufacture authority it was not given,
//! and cannot pass on more than it holds.
//!
//! The rule is enforced by the type, not by review. There is no operation on
//! `Rights` that adds a bit to an existing value: `narrow` intersects, and the only
//! way to obtain a wider set is to construct one from scratch, which only the code
//! creating an object can do.

use core::fmt;

/// A set of permissions on one handle.
#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub struct Rights(u32);

macro_rules! rights {
    ($($name:ident = $bit:expr, $doc:literal;)*) => {
        impl Rights {
            $(
                #[doc = $doc]
                pub const $name: Rights = Rights(1 << $bit);
            )*

            /// Every right this build knows about.
            pub const ALL: Rights = Rights($((1 << $bit))|*);

            fn names(self) -> impl Iterator<Item = &'static str> {
                const TABLE: &[(u32, &str)] = &[$((1 << $bit, stringify!($name))),*];
                TABLE
                    .iter()
                    .filter(move |(bit, _)| self.0 & bit != 0)
                    .map(|(_, name)| *name)
            }
        }
    };
}

rights! {
    READ = 0, "Read from the object, or observe its state.";
    WRITE = 1, "Write to the object, or change its state.";
    EXECUTE = 2, "Execute memory the object describes.";
    DUPLICATE = 3, "Make another handle to the same object.";
    TRANSFER = 4, "Send the handle to another process over a channel.";
    WAIT = 5, "Block until the object signals.";
    SIGNAL = 6, "Raise a signal on the object.";
    MAP = 7, "Map the object into an address space.";
    DESTROY = 8, "Destroy the object, not merely drop this handle.";
    INSPECT = 9, "Read metadata: type, name, accounting.";
}

/// The empty set. A handle with no rights is a handle that permits nothing, which is
/// a meaningful thing to hold: it proves the object exists without granting access.
pub const NONE: Rights = Rights(0);

impl Rights {
    pub const fn empty() -> Rights {
        Rights(0)
    }

    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Construct from raw bits, discarding any this build does not define.
    ///
    /// Unknown bits are dropped rather than preserved: a handle arriving from an
    /// older or newer component must never carry authority this kernel cannot reason
    /// about.
    pub const fn from_bits_truncate(bits: u32) -> Rights {
        Rights(bits & Rights::ALL.0)
    }

    pub const fn contains(self, other: Rights) -> bool {
        self.0 & other.0 == other.0
    }

    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Combine two sets. Only usable where both sets are already held — see `narrow`
    /// for the operation that crossing a trust boundary uses.
    pub const fn union(self, other: Rights) -> Rights {
        Rights(self.0 | other.0)
    }

    /// Restrict to at most `mask`.
    ///
    /// **This is the only operation that crosses a trust boundary**, and it can only
    /// ever remove bits. `narrow` of a right not held is a no-op, not an escalation.
    #[must_use]
    pub const fn narrow(self, mask: Rights) -> Rights {
        Rights(self.0 & mask.0)
    }

    /// Remove specific rights.
    #[must_use]
    pub const fn without(self, remove: Rights) -> Rights {
        Rights(self.0 & !remove.0)
    }
}

impl core::ops::BitOr for Rights {
    type Output = Rights;
    fn bitor(self, rhs: Rights) -> Rights {
        self.union(rhs)
    }
}

impl fmt::Debug for Rights {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_empty() {
            return f.write_str("Rights(none)");
        }
        f.write_str("Rights(")?;
        let mut first = true;
        for n in self.names() {
            if !first {
                f.write_str("|")?;
            }
            f.write_str(n)?;
            first = false;
        }
        f.write_str(")")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn narrowing_can_only_remove() {
        let held = Rights::READ | Rights::WRITE;
        // Asking for more than is held yields only what was held.
        let asked = Rights::READ | Rights::WRITE | Rights::DESTROY;
        assert_eq!(held.narrow(asked), held);
        assert!(!held.narrow(asked).contains(Rights::DESTROY));

        // Asking for less yields less.
        assert_eq!(held.narrow(Rights::READ), Rights::READ);
    }

    #[test]
    fn narrowing_is_idempotent_and_monotonic() {
        let r = Rights::READ | Rights::WRITE | Rights::MAP;
        let once = r.narrow(Rights::READ | Rights::MAP);
        assert_eq!(once.narrow(Rights::READ | Rights::MAP), once);
        // Repeated narrowing never grows the set.
        let twice = once.narrow(Rights::READ);
        assert!(r.contains(twice));
        assert!(once.contains(twice));
    }

    #[test]
    fn unknown_bits_are_discarded_not_carried() {
        // A handle from a component that knows rights we do not must not smuggle
        // authority past us.
        let smuggled = Rights::from_bits_truncate(0xFFFF_FFFF);
        assert_eq!(smuggled, Rights::ALL);
        assert_eq!(smuggled.bits() & !Rights::ALL.bits(), 0);
    }

    #[test]
    fn the_empty_set_permits_nothing() {
        let none = Rights::empty();
        assert!(none.is_empty());
        for r in [Rights::READ, Rights::WRITE, Rights::DESTROY, Rights::MAP] {
            assert!(!none.contains(r));
        }
        // ...and narrowing nothing still yields nothing.
        assert_eq!(none.narrow(Rights::ALL), none);
    }

    #[test]
    fn contains_is_subset_not_intersection() {
        let rw = Rights::READ | Rights::WRITE;
        assert!(rw.contains(Rights::READ));
        assert!(rw.contains(rw));
        assert!(!rw.contains(Rights::READ | Rights::EXECUTE));
    }

    #[test]
    fn debug_names_the_bits() {
        extern crate std;
        let s = std::format!("{:?}", Rights::READ | Rights::MAP);
        assert!(s.contains("READ"), "{s}");
        assert!(s.contains("MAP"), "{s}");
        assert_eq!(std::format!("{:?}", Rights::empty()), "Rights(none)");
    }
}

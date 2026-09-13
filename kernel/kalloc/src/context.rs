//! The questions an allocation has to answer, carried as a parameter.
//!
//! `docs/architecture.md`: *"Allocation also carries a context — GFP-like flags for
//! may this sleep, must this be DMA addressable, which NUMA node — because those
//! questions are unavoidable and hiding them in a global has caused real bugs
//! elsewhere."*
//!
//! The bugs referred to are the ones where the answer lives in an implicit
//! per-thread or per-CPU state: an allocation deep inside a helper sleeps because a
//! caller three frames up set a flag, or does not sleep because an interrupt
//! arrived, and neither is visible at the call site. A parameter cannot do that. It
//! costs a word in a register and it makes the question impossible to forget,
//! because there is nowhere else to get the answer from.
//!
//! # What is honoured today
//!
//! Most of this is not honoured yet, and pretending otherwise would be worse than
//! saying so:
//!
//! | Flag | Today | What honouring it needs |
//! |---|---|---|
//! | [`AllocFlags::ZERO`] | **honoured** — the block is zeroed before it is returned | — |
//! | [`AllocFlags::MAY_SLEEP`] | advisory; every allocation is effectively atomic | a scheduler to sleep on, and a reclaim path worth waiting for |
//! | [`AllocFlags::DMA32`] | advisory | a zoned frame allocator, so the request can be served from below 4 GiB rather than checked afterwards |
//! | [`AllocFlags::DMA_COHERENT`] | advisory | cache maintenance, which is `HasCoherentDma`-shaped and belongs to the device framework |
//! | [`NumaNode`] | advisory | a topology source (ACPI SRAT, device tree) and per-node frame pools |
//!
//! Advisory means *recorded and ignored*: the request is counted in
//! [`crate::HeapStats::constrained`] so that "how much of the kernel is already
//! asking for something we do not provide" is a number rather than a guess, and the
//! allocation proceeds as if the constraint were absent. That is the honest failure
//! mode for a bootstrap heap. It is **not** acceptable for DMA once devices exist —
//! a driver that asks for DMA32 and silently gets memory above 4 GiB corrupts
//! whatever is at the truncated address — so the flag exists now, in the type, so
//! that the day a zone allocator lands the call sites are already written.
//!
//! Putting the flags in before they work is the whole point. Retrofitting a context
//! parameter through a kernel's worth of call sites is the expensive version.

use core::fmt;

/// Constraints on one allocation, as a bit set.
///
/// A plain newtype rather than a `bitflags`-style macro: the set is small, the
/// operations are `|` and `contains`, and `docs/decisions.md` D8 rules out a crate
/// for it.
#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub struct AllocFlags(u32);

impl AllocFlags {
    /// No constraints. The allocation may be served from anywhere, must not sleep,
    /// and arrives holding whatever the previous owner left.
    pub const NONE: Self = AllocFlags(0);

    /// The caller can block. It is not in an interrupt handler, does not hold a
    /// spinlock, and is prepared for the allocator to wait for reclaim.
    ///
    /// Advisory today: nothing sleeps, because there is no scheduler to sleep on.
    /// Its absence will be the constraint that matters — an allocation in an
    /// interrupt handler that sleeps is a deadlock — so the flag is written this way
    /// round, with atomic as the default, so that forgetting it is safe.
    pub const MAY_SLEEP: Self = AllocFlags(1 << 0);

    /// Zero the block before returning it.
    ///
    /// Honoured. Mandatory for anything that will be visible to userspace, and the
    /// reason this is a flag rather than a separate entry point is that the zeroing
    /// wants to move into the allocator's fast path later (a pre-zeroed free list),
    /// which a caller-side `write_bytes` would prevent.
    pub const ZERO: Self = AllocFlags(1 << 1);

    /// The block must be addressable by a device with a 32-bit DMA window.
    ///
    /// Advisory today. See the module documentation: this must become real before
    /// any DMA-capable driver ships, and a build that ships one while this is still
    /// advisory has a bug waiting at the first machine with more than 4 GiB.
    pub const DMA32: Self = AllocFlags(1 << 2);

    /// The block must be coherent with device DMA without explicit cache
    /// maintenance.
    ///
    /// Advisory today. On a `HasCoherentDma` target it is free; elsewhere it implies
    /// uncached or write-through mappings, which needs page-table control this unit
    /// does not have.
    pub const DMA_COHERENT: Self = AllocFlags(1 << 3);

    /// The raw bits, for logging and for tests.
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Whether every flag in `other` is set here.
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// The union of two sets.
    pub const fn union(self, other: Self) -> Self {
        AllocFlags(self.0 | other.0)
    }

    /// The flags this allocator cannot currently act on. See the module docs.
    pub const fn advisory(self) -> Self {
        AllocFlags(self.0 & (Self::MAY_SLEEP.0 | Self::DMA32.0 | Self::DMA_COHERENT.0))
    }
}

impl core::ops::BitOr for AllocFlags {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        self.union(rhs)
    }
}

impl fmt::Debug for AllocFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Named, not hexadecimal: a flag word in a log line that has to be decoded by
        // hand will be decoded wrongly.
        let names = [
            (Self::MAY_SLEEP, "MAY_SLEEP"),
            (Self::ZERO, "ZERO"),
            (Self::DMA32, "DMA32"),
            (Self::DMA_COHERENT, "DMA_COHERENT"),
        ];
        let mut first = true;
        f.write_str("AllocFlags(")?;
        for (flag, name) in names {
            if self.contains(flag) {
                if !first {
                    f.write_str("|")?;
                }
                f.write_str(name)?;
                first = false;
            }
        }
        if first {
            f.write_str("NONE")?;
        }
        f.write_str(")")
    }
}

/// Which memory node the caller would like to be served from.
///
/// Advisory today; there is no topology source and no per-node pool. It is in the
/// type because the alternative — adding a node parameter to every allocation site
/// once NUMA support lands — is the expensive order to do this in.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct NumaNode(u16);

impl NumaNode {
    /// No preference. The only value a uniform-memory machine ever uses, and the
    /// default.
    pub const ANY: Self = NumaNode(u16::MAX);

    /// A specific node.
    pub const fn new(index: u16) -> Self {
        NumaNode(index)
    }

    /// The node index, or `None` for [`Self::ANY`].
    pub const fn index(self) -> Option<u16> {
        if self.0 == u16::MAX {
            None
        } else {
            Some(self.0)
        }
    }
}

impl Default for NumaNode {
    fn default() -> Self {
        Self::ANY
    }
}

/// Everything the allocator needs to know about the caller.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct AllocContext {
    flags: AllocFlags,
    node: NumaNode,
}

impl AllocContext {
    /// Interrupt-safe, no preference, contents unspecified.
    ///
    /// The default, and the one that is always correct: an allocation that may not
    /// sleep is valid in a context that could have. The reverse is a deadlock, which
    /// is why this rather than [`Self::KERNEL`] is what [`Default`] gives you.
    pub const ATOMIC: Self = AllocContext {
        flags: AllocFlags::NONE,
        node: NumaNode::ANY,
    };

    /// Ordinary process-context allocation: the caller can block.
    pub const KERNEL: Self = AllocContext {
        flags: AllocFlags::MAY_SLEEP,
        node: NumaNode::ANY,
    };

    /// Process context, zeroed. What anything userspace-visible wants.
    pub const KERNEL_ZEROED: Self = AllocContext {
        flags: AllocFlags(AllocFlags::MAY_SLEEP.0 | AllocFlags::ZERO.0),
        node: NumaNode::ANY,
    };

    /// An arbitrary combination.
    pub const fn new(flags: AllocFlags, node: NumaNode) -> Self {
        AllocContext { flags, node }
    }

    /// The constraints.
    pub const fn flags(self) -> AllocFlags {
        self.flags
    }

    /// The requested node.
    pub const fn node(self) -> NumaNode {
        self.node
    }

    /// The same context with `extra` also set.
    pub const fn with(self, extra: AllocFlags) -> Self {
        AllocContext {
            flags: self.flags.union(extra),
            node: self.node,
        }
    }

    /// The same context pinned to a node.
    pub const fn on_node(self, node: NumaNode) -> Self {
        AllocContext {
            flags: self.flags,
            node,
        }
    }

    /// Whether the caller said it can block. Advisory; see the module docs.
    pub const fn may_sleep(self) -> bool {
        self.flags.contains(AllocFlags::MAY_SLEEP)
    }

    /// Whether the block must be zeroed. Honoured.
    pub const fn wants_zero(self) -> bool {
        self.flags.contains(AllocFlags::ZERO)
    }

    /// Whether this request asked for something the allocator cannot currently
    /// provide, and is therefore being served on a best-effort basis.
    ///
    /// Counted rather than refused. Refusing would mean no DMA-capable driver could
    /// be written until the zone allocator exists; serving silently would mean
    /// nobody notices that it does not. Counting means
    /// [`crate::HeapStats::constrained`] answers the question at any moment.
    pub const fn is_best_effort(self) -> bool {
        self.flags.advisory().bits() != 0 || self.node.index().is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_context_is_the_safe_one() {
        // An allocation that may not sleep is valid everywhere; the reverse is a
        // deadlock. So forgetting to pick must give the conservative answer.
        assert_eq!(AllocContext::default(), AllocContext::ATOMIC);
        assert!(!AllocContext::default().may_sleep());
        assert!(!AllocContext::default().wants_zero());
    }

    #[test]
    fn flags_combine_and_test() {
        let f = AllocFlags::ZERO | AllocFlags::DMA32;
        assert!(f.contains(AllocFlags::ZERO));
        assert!(f.contains(AllocFlags::DMA32));
        assert!(!f.contains(AllocFlags::MAY_SLEEP));
        assert!(f.contains(AllocFlags::ZERO | AllocFlags::DMA32));
        assert!(!AllocFlags::NONE.contains(AllocFlags::ZERO));
    }

    #[test]
    fn honoured_and_advisory_are_distinguished() {
        // ZERO is honoured, so asking for it is not best-effort.
        let zeroed = AllocContext::ATOMIC.with(AllocFlags::ZERO);
        assert!(!zeroed.is_best_effort());
        assert!(zeroed.wants_zero());

        // Everything else currently is.
        for flag in [
            AllocFlags::MAY_SLEEP,
            AllocFlags::DMA32,
            AllocFlags::DMA_COHERENT,
        ] {
            assert!(
                AllocContext::ATOMIC.with(flag).is_best_effort(),
                "{flag:?} is not honoured yet and must be counted as such"
            );
        }
        assert!(
            AllocContext::ATOMIC
                .on_node(NumaNode::new(1))
                .is_best_effort(),
            "there is no NUMA topology, so a node request is best-effort"
        );
        assert!(!AllocContext::ATOMIC.on_node(NumaNode::ANY).is_best_effort());
    }

    #[test]
    fn node_any_is_distinguishable_from_node_zero() {
        // Node 0 is a real node. If `ANY` were 0, every allocation on a NUMA machine
        // would silently pin to the first node.
        assert_eq!(NumaNode::ANY.index(), None);
        assert_eq!(NumaNode::new(0).index(), Some(0));
        assert_ne!(NumaNode::new(0), NumaNode::ANY);
    }

    #[test]
    fn flags_print_by_name() {
        let s = format!("{:?}", AllocFlags::ZERO | AllocFlags::DMA32);
        assert!(s.contains("ZERO"), "{s}");
        assert!(s.contains("DMA32"), "{s}");
        assert_eq!(format!("{:?}", AllocFlags::NONE), "AllocFlags(NONE)");
    }
}

//! Making allocation fail on purpose, deterministically, so the failure paths run.
//!
//! Every allocation here returns a `Result`, and that proves only that failure *can*
//! be reported. Whether each caller does something sound with it is a different
//! question. On a machine with memory to spare, the error branch of almost every call
//! site never runs. An injector makes chosen allocations fail on request, so those
//! branches run in tests, and once more subsystems allocate, in a kernel test image.
//!
//! # Where failure is injected
//!
//! At each point inside the heap where memory is actually obtained, not only at the
//! front door. A failure at the entry proves the caller copes. A failure at a slab
//! block, a page block or a frame proves the heap's own fallback routes cope. Those
//! are the paths that decide whether a failed internal allocation leaks a descriptor or
//! half-builds a block.
//!
//! | [`Site`] | What fails | What the heap does about it |
//! |---|---|---|
//! | `ENTRY` | the whole request, before any state is touched | reports it |
//! | `SLAB_BLOCK` | getting a new block for a size class | serves the object from the arena instead |
//! | `PAGES` | a buddy block for a large request | serves it from the arena instead |
//! | `FRAMES` | taking frames from the frame source to grow the arena | reports it, or uses what the arena already has |
//!
//! # Policies
//!
//! Every policy is deterministic. A run that failed can be replayed exactly, which is
//! the only kind of randomness worth having in a test:
//!
//! * [`Injector::fail_nth`] fails the Nth armed call, once. Sweeping N from 0 upwards walks a
//!   failure through every allocation a workload makes, one run per N.
//! * [`Injector::fail_from`] fails the Nth armed call and every one after it. That models running
//!   out part of the way through.
//! * [`Injector::random`] fails each armed call with probability 1/`one_in`, from a seeded xorshift
//!   generator. Soak runs use this, and a failure is reported with its seed.
//!
//! # What it costs when it is off
//!
//! [`ENABLED`] is `kconfig::KALLOC_FAULT_INJECT`, or true under this unit's own host
//! tests. When it is false every [`Injector::trip`] is `if false`, which the compiler
//! folds away, so no allocation path does any extra work. The [`Injector`] field is still
//! present in the heap, a few dozen bytes. Removing it would need a `cfg` on a struct
//! field, which `docs/portability.md` forbids for reasons that matter more than those
//! bytes. As with `poison`, the injection code is type-checked in every build, so it
//! cannot rot unseen in a configuration that does not use it.

/// Whether injection can happen in this build.
///
/// True under the host tests regardless of configuration, because the tests exist to
/// drive the failure paths and a test that could be silently disabled by a preset is
/// not one. A kernel image gets it only from `KALLOC_FAULT_INJECT`.
pub const ENABLED: bool = kconfig::KALLOC_FAULT_INJECT || cfg!(test);

/// The places failure can be injected, as a bit set. See the module documentation.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Site(u8);

impl Site {
    /// No sites.
    pub const NONE: Site = Site(0);
    /// The request as a whole.
    pub const ENTRY: Site = Site(1 << 0);
    /// A new slab block.
    pub const SLAB_BLOCK: Site = Site(1 << 1);
    /// A buddy block.
    pub const PAGES: Site = Site(1 << 2);
    /// Frames from the frame source.
    pub const FRAMES: Site = Site(1 << 3);
    /// Every site.
    pub const ALL: Site = Site(0x0F);

    /// The union of two sets.
    pub const fn union(self, other: Site) -> Site {
        Site(self.0 | other.0)
    }

    /// Whether any site in `other` is in this set.
    pub const fn intersects(self, other: Site) -> bool {
        self.0 & other.0 != 0
    }
}

impl core::ops::BitOr for Site {
    type Output = Site;
    fn bitor(self, rhs: Site) -> Site {
        self.union(rhs)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Policy {
    Off,
    /// Fail the call numbered `n`, counting from zero.
    Nth(u64),
    /// Fail the call numbered `n` and every one after it.
    From(u64),
    /// Fail when the generator's next value is divisible by `one_in`.
    Random {
        state: u64,
        one_in: u64,
    },
}

/// A failure policy and its running state.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Injector {
    sites: Site,
    policy: Policy,
    /// Armed calls seen: calls at a site in `sites` while a policy is set.
    calls: u64,
    /// Failures injected.
    trips: u64,
}

impl Default for Injector {
    fn default() -> Self {
        Self::OFF
    }
}

impl Injector {
    /// Never fails. What every heap starts with.
    pub const OFF: Injector = Injector {
        sites: Site::NONE,
        policy: Policy::Off,
        calls: 0,
        trips: 0,
    };

    /// Fail the `n`th call at any of `sites`, counting from zero, and no other.
    pub const fn fail_nth(sites: Site, n: u64) -> Injector {
        Injector {
            sites,
            policy: Policy::Nth(n),
            calls: 0,
            trips: 0,
        }
    }

    /// Fail the `n`th call at any of `sites` and every call after it.
    pub const fn fail_from(sites: Site, n: u64) -> Injector {
        Injector {
            sites,
            policy: Policy::From(n),
            calls: 0,
            trips: 0,
        }
    }

    /// Fail each call at any of `sites` with probability 1/`one_in`, reproducibly from
    /// `seed`. A `one_in` of zero or one fails every call.
    pub const fn random(sites: Site, seed: u64, one_in: u64) -> Injector {
        Injector {
            sites,
            // Xorshift has one fixed point, zero, and a seed of zero would never fail.
            policy: Policy::Random {
                state: if seed == 0 {
                    0x9E37_79B9_7F4A_7C15
                } else {
                    seed
                },
                one_in: if one_in == 0 { 1 } else { one_in },
            },
            calls: 0,
            trips: 0,
        }
    }

    /// Whether this injector would ever fail anything in this build.
    pub fn is_armed(&self) -> bool {
        ENABLED && self.policy != Policy::Off && self.sites != Site::NONE
    }

    /// Calls seen at armed sites.
    pub fn calls(&self) -> u64 {
        self.calls
    }

    /// Failures injected so far.
    pub fn trips(&self) -> u64 {
        self.trips
    }

    /// Consult the policy for one call at `site`. True means "fail this one".
    ///
    /// Folds to `false` when [`ENABLED`] is false.
    pub fn trip(&mut self, site: Site) -> bool {
        if !ENABLED || !self.sites.intersects(site) {
            return false;
        }
        let n = self.calls;
        let fail = match &mut self.policy {
            Policy::Off => return false,
            Policy::Nth(k) => n == *k,
            Policy::From(k) => n >= *k,
            Policy::Random { state, one_in } => {
                *state ^= *state << 13;
                *state ^= *state >> 7;
                *state ^= *state << 17;
                *state % *one_in == 0
            }
        };
        self.calls = self.calls.saturating_add(1);
        if fail {
            self.trips = self.trips.saturating_add(1);
        }
        fail
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_tests_always_have_injection() {
        // The failure-path tests below and in `heap` are meaningless if this is false, so
        // it is asserted rather than assumed.
        const { assert!(ENABLED) };
    }

    #[test]
    fn off_never_fails_and_counts_nothing() {
        let mut i = Injector::OFF;
        assert!(!i.is_armed());
        for _ in 0..100 {
            assert!(!i.trip(Site::ALL));
        }
        assert_eq!((i.calls(), i.trips()), (0, 0));
    }

    #[test]
    fn nth_fails_exactly_once_and_only_at_its_sites() {
        let mut i = Injector::fail_nth(Site::PAGES, 3);
        let mut failed = Vec::new();
        for call in 0..10 {
            // Calls at other sites are not counted and never fail.
            assert!(!i.trip(Site::ENTRY));
            if i.trip(Site::PAGES) {
                failed.push(call);
            }
        }
        assert_eq!(failed, vec![3]);
        assert_eq!((i.calls(), i.trips()), (10, 1));
    }

    #[test]
    fn from_fails_everything_after_the_threshold() {
        let mut i = Injector::fail_from(Site::ALL, 2);
        let results: Vec<bool> = (0..5).map(|_| i.trip(Site::FRAMES)).collect();
        assert_eq!(results, vec![false, false, true, true, true]);
    }

    #[test]
    fn random_is_reproducible_by_seed_and_roughly_calibrated() {
        let run = |seed| {
            let mut i = Injector::random(Site::ALL, seed, 8);
            (0..4000)
                .map(|_| i.trip(Site::ENTRY))
                .collect::<Vec<bool>>()
        };
        assert_eq!(run(42), run(42), "the same seed must give the same failures");
        assert_ne!(run(42), run(43));
        let trips = run(42).iter().filter(|b| **b).count();
        // 1 in 8 of 4000 is 500. Loose bounds, because this checks for a gross mistake
        // (every call, or none), not for the generator's statistical quality.
        assert!((300..700).contains(&trips), "{trips} failures");

        let mut zero = Injector::random(Site::ALL, 0, 0);
        assert!(zero.trip(Site::ENTRY), "one_in of zero means every call");
    }
}

//! Generated configurations: random ones, and the two boundaries.
//!
//! The configuration space is too large to build exhaustively, so it is sampled
//! (`docs/testing.md`, "Configuration coverage"). Every generated configuration must be
//! *valid*: a sample that the resolver would refuse tests nothing, and a sampler that
//! produces them trains everyone to ignore its failures.
//!
//! Validity is guaranteed by construction rather than by hoping. Settable symbols are
//! visited in declaration order, a value is proposed for each, and the proposal is kept
//! only if the whole set of requests so far still resolves. Resolution validates every
//! request each time, so a proposal that would contradict an earlier one — setting off
//! a symbol that an accepted request selects, say — is dropped, and the set only ever
//! grows by valid steps. A second pass revisits symbols that were unavailable the first
//! time, because a dependency declared later may have been switched on since.
//!
//! The same table, base requests and seed always produce the same configuration: the
//! visit order is declaration order and the generator is a fixed algorithm (splitmix64),
//! so a failing seed reproduces anywhere.

use super::resolve::{self, Reason, Request, ResolveError};
use super::*;

/// What to generate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Every settable bool and tristate a coin flip, choices a random usable member, and
    /// each ranged `int` or `hex` biased towards its bounds.
    Random(u64),
    /// Everything on that can be on.
    AllYes,
    /// Everything off that can be off.
    AllNo,
}

impl Mode {
    /// The options that produce this mode, which is also how its requests are attributed.
    pub fn source(self) -> String {
        match self {
            Mode::Random(seed) => format!("--random --seed {seed}"),
            Mode::AllYes => "--allyes".into(),
            Mode::AllNo => "--allno".into(),
        }
    }
}

/// splitmix64: tiny, fast, and the same sequence on every host.
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Rng {
        Rng(seed)
    }

    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// Uniform in `0..n`. `n` must be non-zero.
    pub fn below(&mut self, n: u64) -> u64 {
        // Rejection sampling, so small `n` has no modulo bias.
        let zone = u64::MAX - u64::MAX % n;
        loop {
            let v = self.next_u64();
            if v < zone {
                return v % n;
            }
        }
    }

    /// Uniform in `lo..=hi`.
    fn between(&mut self, lo: i128, hi: i128) -> i128 {
        let span = (hi - lo) as u128 + 1;
        if span > u128::from(u64::MAX) {
            return lo + i128::from(self.next_u64());
        }
        lo + i128::from(self.below(span as u64))
    }
}

/// Extend `base` into a complete configuration by `mode`.
///
/// Returns the resolution and every request it was built from: `base` first, unchanged,
/// then the generated ones. `base` is typically a preset, which fixes the architecture
/// and anything else a sample must not move. An error means `base` itself does not
/// resolve.
pub fn generate(
    table: &SymbolTable,
    base: &[Request],
    mode: Mode,
) -> Result<(Resolution, Vec<Request>), Vec<ResolveError>> {
    let mut res = resolve::resolve(table, base)?;
    let mut requests = base.to_vec();
    let mut rng = Rng::new(match mode {
        Mode::Random(seed) => seed,
        _ => 0,
    });
    let fixed = |name: &str, requests: &[Request]| requests.iter().any(|r| r.symbol == name);

    for _pass in 0..2 {
        let mut choices_seen: Vec<&str> = Vec::new();
        for name in &table.order {
            let sym = &table.symbols[name];
            if fixed(name, &requests) {
                continue;
            }

            let proposal = if let Some(cname) = &sym.choice {
                if choices_seen.contains(&cname.as_str()) {
                    continue;
                }
                choices_seen.push(cname);
                let choice = &table.choices[cname];
                if choice.members.iter().any(|m| fixed(m, &requests)) {
                    continue;
                }
                // The boundaries leave choices at their defaults: neither "on" nor "off"
                // says which member, and the default is the one the author expects.
                let Mode::Random(_) = mode else {
                    continue;
                };
                let usable: Vec<&String> = choice
                    .members
                    .iter()
                    .filter(|m| table.symbols[*m].settable())
                    .filter(|m| !matches!(res.reasons[*m], Reason::DependsUnmet(_)))
                    .collect();
                if usable.is_empty() {
                    continue;
                }
                let pick = usable[rng.below(usable.len() as u64) as usize];
                if res.is_on(pick) {
                    continue; // already the member; a request would say nothing
                }
                (pick.clone(), "y".to_string())
            } else {
                if !sym.settable() || matches!(res.reasons[name], Reason::DependsUnmet(_)) {
                    continue;
                }
                let value = match (sym.kind, mode) {
                    (Kind::Bool | Kind::Tristate, Mode::AllYes) => Val::Tri(Tri::Y),
                    (Kind::Bool | Kind::Tristate, Mode::AllNo) => Val::Tri(Tri::N),
                    (Kind::Bool, Mode::Random(_)) => {
                        Val::Tri(if rng.below(2) == 0 { Tri::N } else { Tri::Y })
                    }
                    (Kind::Tristate, Mode::Random(_)) => {
                        // `m` only where it can resolve; see `resolve` on modules.
                        let modules = res.tri(MODULES) == Tri::Y;
                        let n = if modules { 3 } else { 2 };
                        Val::Tri(match rng.below(n) {
                            0 => Tri::N,
                            1 => Tri::Y,
                            _ => Tri::M,
                        })
                    }
                    (Kind::Int | Kind::Hex, Mode::Random(_)) => {
                        let Some(r) = resolve::active_range(sym, &res) else {
                            continue; // no range, no basis for a value; keep the default
                        };
                        // Bounds are where off-by-one bugs live, so they get half the
                        // samples; the default keeps a quarter so a sample is not all
                        // extremes.
                        let v = match rng.below(4) {
                            0 => r.lo,
                            1 => r.hi,
                            2 => continue,
                            _ => rng.between(r.lo, r.hi),
                        };
                        match sym.kind {
                            Kind::Int => Val::Int(v as i64),
                            _ => Val::Hex(v as u64),
                        }
                    }
                    _ => continue, // strings, and numbers at the boundaries, keep defaults
                };
                if res.values[name] == value {
                    continue; // already so; a request would say nothing
                }
                (name.clone(), value.display().trim_matches('"').to_string())
            };

            let mut trial = requests.clone();
            trial.push(Request {
                symbol: proposal.0,
                text: proposal.1,
                source: mode.source(),
            });
            if let Ok(r) = resolve::resolve(table, &trial) {
                res = r;
                requests = trial;
            }
        }
    }
    Ok((res, requests))
}

#[cfg(test)]
mod tests {
    use super::super::resolve::tests::{req, table};
    use super::*;

    const TREE: &str = r#"
config MODULES
    bool "Modules"

config BEFORE_ITS_DEPENDENCY
    bool "declared before what it depends on"
    depends on AFTER

config AFTER
    bool "after"

config HW
    bool "hardware"

config DRIVER
    tristate "driver"
    depends on HW

config FEATURE
    bool "feature"
    select DRIVER if HW

config LOCKED
    bool "cannot be off while FEATURE is on"
    depends on HW

config NEEDS_FEATURE
    bool "needs the feature"
    depends on FEATURE

choice ARCH
    prompt "arch"
    default A1
    config A1
        bool "a1"
    config A2
        bool "a2"
    config A3
        bool "a3"
        depends on HW
endchoice

config COUNT
    int "count"
    range 2 4 if A2
    range 2 16
    default 3

config ADDR
    hex "addr"
    range 0x1000 0xffffffffffffffff
    default 0x1000

config DERIVED
    bool
    default y if FEATURE

config HARDWARE
    bool
    readonly
    default y
"#;

    #[test]
    fn every_seed_gives_a_configuration_that_resolves_again_from_its_requests() {
        let t = table(TREE);
        for seed in 0..300 {
            let (res, requests) = generate(&t, &[], Mode::Random(seed)).unwrap();
            let again =
                resolve::resolve(&t, &requests).unwrap_or_else(|e| panic!("seed {seed}: {}", e[0]));
            assert_eq!(again.values, res.values, "seed {seed}");
            // And nothing a person could not have asked for.
            for r in &requests {
                assert!(t.symbols[&r.symbol].settable(), "seed {seed} set {}", r.symbol);
            }
        }
    }

    #[test]
    fn the_same_seed_is_the_same_configuration_and_seeds_differ() {
        let t = table(TREE);
        let a = generate(&t, &[], Mode::Random(42)).unwrap().1;
        let b = generate(&t, &[], Mode::Random(42)).unwrap().1;
        assert_eq!(a, b);
        let distinct: std::collections::BTreeSet<String> = (0..50)
            .map(|s| format!("{:?}", generate(&t, &[], Mode::Random(s)).unwrap().0.values))
            .collect();
        assert!(distinct.len() > 20, "only {} distinct configurations", distinct.len());
    }

    #[test]
    fn random_samples_cover_both_values_every_member_modules_and_range_bounds() {
        let t = table(TREE);
        let mut seen = std::collections::BTreeSet::<(String, String)>::new();
        for seed in 0..400 {
            let res = generate(&t, &[], Mode::Random(seed)).unwrap().0;
            for (k, v) in &res.values {
                seen.insert((k.clone(), v.display()));
            }
        }
        for want in [
            ("HW", "y"),
            ("HW", "n"),
            ("DRIVER", "m"),
            ("DRIVER", "y"),
            ("A1", "y"),
            ("A2", "y"),
            ("A3", "y"),
            ("COUNT", "2"),
            ("COUNT", "16"),
            ("COUNT", "4"),
            ("ADDR", "0xffffffffffffffff"),
            ("NEEDS_FEATURE", "y"),
        ] {
            assert!(
                seen.contains(&(want.0.to_string(), want.1.to_string())),
                "never generated {}={}",
                want.0,
                want.1
            );
        }
    }

    #[test]
    fn base_requests_are_kept_and_never_contradicted() {
        let t = table(TREE);
        let base = req(&[("A2", "y"), ("HW", "n")]);
        for seed in 0..100 {
            let (res, requests) = generate(&t, &base, Mode::Random(seed)).unwrap();
            assert_eq!(&requests[..2], &base[..]);
            assert!(res.is_on("A2") && !res.is_on("HW"), "seed {seed}");
            assert!(res.int("COUNT") <= 4, "the A2 range holds, seed {seed}");
        }
    }

    #[test]
    fn allyes_and_allno_reach_the_boundaries() {
        let t = table(TREE);
        let (yes, _) = generate(&t, &[], Mode::AllYes).unwrap();
        // BEFORE_ITS_DEPENDENCY is unavailable when first visited, so it needs the second
        // pass.
        for s in [
            "MODULES",
            "HW",
            "FEATURE",
            "LOCKED",
            "NEEDS_FEATURE",
            "BEFORE_ITS_DEPENDENCY",
        ] {
            assert!(yes.is_on(s), "allyes left {s} off");
        }
        assert_eq!(yes.tri("DRIVER"), Tri::Y, "allyes means built in, not m");
        assert!(yes.is_on("A1"), "a choice keeps its default");

        let (no, _) = generate(&t, &[], Mode::AllNo).unwrap();
        for s in [
            "MODULES",
            "HW",
            "FEATURE",
            "LOCKED",
            "NEEDS_FEATURE",
            "DRIVER",
        ] {
            assert!(!no.is_on(s), "allno left {s} on");
        }
        assert!(no.is_on("HARDWARE"), "readonly symbols are not the generator's");
    }

    #[test]
    fn a_base_that_does_not_resolve_is_an_error_not_a_sample() {
        let t = table(TREE);
        assert!(generate(&t, &req(&[("NOPE", "y")]), Mode::AllNo).is_err());
    }

    #[test]
    fn below_is_in_range_and_between_hits_both_ends() {
        let mut r = Rng::new(7);
        let mut ends = (false, false);
        for _ in 0..1000 {
            assert!(r.below(3) < 3);
            let v = r.between(-2, 2);
            assert!((-2..=2).contains(&v));
            ends.0 |= v == -2;
            ends.1 |= v == 2;
        }
        assert!(ends.0 && ends.1);
    }
}

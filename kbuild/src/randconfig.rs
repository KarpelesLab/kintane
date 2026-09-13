//! `kbuild randconfig-build`: build sampled configurations and report what does not.
//!
//! The configuration space is sampled rather than enumerated (`docs/testing.md`,
//! "Configuration coverage"). Each sample is a preset, which fixes the architecture,
//! extended by `kcfg::random` from one seed. A failure is reported with the exact
//! command that rebuilds it, so a nightly red is something a person can reproduce on
//! their own machine in one step rather than an anecdote.
//!
//! Two kinds of failure are kept apart, because they are different people's bugs:
//!
//! - **The configuration did not resolve.** The generator promises valid configurations, so this is
//!   a kbuild bug.
//! - **The configuration resolved and did not build.** An unbuildable combination: a kernel bug, or
//!   a missing `depends on` in a `.kcfg`. Exactly what the trait approach in `docs/portability.md`
//!   claims should not exist.
//!
//! With `--allyes` or `--allno`, the boundary configurations of every preset are built
//! instead of random ones.

use std::path::Path;

use crate::Opts;
use crate::kcfg::random::{Mode, Rng};

/// A seed for `--random` without `--seed`. It is printed with the configuration, so a
/// run from it is still reproducible.
pub fn fresh_seed() -> u64 {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    Rng::new(nanos ^ u64::from(std::process::id())).next_u64() % 1_000_000_000
}

/// One configuration to build.
#[derive(Debug, PartialEq)]
pub struct Sample {
    pub preset: String,
    pub mode: Mode,
}

/// The configurations a run builds. Random samples pick their preset from their own
/// seed, unless one is given, so each is reproducible from its seed and preset alone.
pub fn plan(
    presets: &[String],
    given: Option<&str>,
    boundary: Option<Mode>,
    seed: u64,
    count: u64,
) -> Vec<Sample> {
    match boundary {
        Some(mode) => match given {
            Some(p) => vec![Sample {
                preset: p.to_string(),
                mode,
            }],
            None => presets
                .iter()
                .map(|p| Sample {
                    preset: p.clone(),
                    mode,
                })
                .collect(),
        },
        None => (0..count)
            .map(|i| {
                let s = seed.wrapping_add(i);
                let preset = match given {
                    Some(p) => p.to_string(),
                    None => presets[Rng::new(s).below(presets.len() as u64) as usize].clone(),
                };
                Sample {
                    preset,
                    mode: Mode::Random(s),
                }
            })
            .collect(),
    }
}

/// The command that rebuilds `sample`.
pub fn repro(sample: &Sample, sets: &[(String, String)]) -> String {
    let mut cmd = format!("kbuild build --preset {} {}", sample.preset, sample.mode.source());
    for (k, v) in sets {
        cmd.push_str(&format!(" --set {k}={v}"));
    }
    cmd
}

pub fn run(root: &Path, opts: &Opts) -> Result<(), String> {
    let boundary = match opts.generate {
        Some(Mode::Random(_)) => {
            return Err("randconfig-build makes its own random configurations: give --seed and \
                        --count, not --random"
                .into());
        }
        other => other,
    };
    let mut presets = crate::list_presets(root);
    presets.sort();
    if presets.is_empty() {
        return Err("no presets in config/presets".into());
    }
    let seed = opts.seed.unwrap_or_else(fresh_seed);
    let samples = plan(&presets, opts.preset.as_deref(), boundary, seed, opts.count);

    let logs = root.join("build/randconfig");
    std::fs::create_dir_all(&logs).map_err(|e| format!("{}: {e}", logs.display()))?;

    let mut invalid = Vec::new();
    let mut unbuildable = Vec::new();
    for (i, sample) in samples.iter().enumerate() {
        let cmd = repro(sample, &opts.sets);
        println!("\n\x1b[36m[{}/{}]\x1b[0m {cmd}", i + 1, samples.len());
        let mut o = opts.clone();
        o.preset = Some(sample.preset.clone());
        o.generate = Some(sample.mode);

        let log = logs.join(format!(
            "{}-{}.log",
            sample.preset,
            sample.mode.source().replace("--", "").replace(' ', "-")
        ));
        if let Err(e) = crate::resolve_config(root, &o) {
            let _ = std::fs::write(&log, &e);
            eprintln!("\x1b[31mDID NOT RESOLVE\x1b[0m (a kbuild bug): {}", first_line(&e));
            invalid.push((cmd, log));
            continue;
        }
        match crate::do_build(root, &o) {
            Ok(_) => println!("\x1b[32mbuilt\x1b[0m"),
            Err(e) => {
                let _ = std::fs::write(&log, &e);
                eprintln!("\x1b[31mDID NOT BUILD\x1b[0m: {}", first_line(&e));
                unbuildable.push((cmd, log));
            }
        }
    }

    println!(
        "\n{} configuration(s): {} built, {} did not build, {} did not resolve",
        samples.len(),
        samples.len() - invalid.len() - unbuildable.len(),
        unbuildable.len(),
        invalid.len()
    );
    for (what, list) in [
        ("did not build", &unbuildable),
        ("did not resolve", &invalid),
    ] {
        for (cmd, log) in list {
            println!("  {what}: {cmd}\n    log: {}", log.display());
        }
    }
    if invalid.is_empty() && unbuildable.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "{} of {} configurations failed",
            invalid.len() + unbuildable.len(),
            samples.len()
        ))
    }
}

/// The most informative line of a build failure: the first rustc or kbuild error, not
/// the "failed to compile" wrapper above it.
fn first_line(e: &str) -> &str {
    e.lines()
        .find(|l| l.starts_with("error"))
        .or_else(|| e.lines().find(|l| !l.trim().is_empty()))
        .unwrap_or("")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn presets() -> Vec<String> {
        ["a", "b", "c"].iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn random_samples_take_consecutive_seeds_and_a_preset_from_each_seed() {
        let p = plan(&presets(), None, None, 100, 30);
        assert_eq!(p.len(), 30);
        assert_eq!(p[0].mode, Mode::Random(100));
        assert_eq!(p[29].mode, Mode::Random(129));
        // Reproducible from the seed alone: planning from that seed picks the same preset.
        for s in &p {
            let Mode::Random(seed) = s.mode else {
                unreachable!()
            };
            assert_eq!(plan(&presets(), None, None, seed, 1)[0], *s);
        }
        let used: std::collections::BTreeSet<&str> = p.iter().map(|s| s.preset.as_str()).collect();
        assert_eq!(used.len(), 3, "30 samples over 3 presets use all of them");
    }

    #[test]
    fn a_given_preset_is_used_for_every_sample() {
        assert!(
            plan(&presets(), Some("b"), None, 0, 5)
                .iter()
                .all(|s| s.preset == "b")
        );
    }

    #[test]
    fn boundaries_build_each_preset_once() {
        let p = plan(&presets(), None, Some(Mode::AllNo), 0, 99);
        assert_eq!(p.len(), 3);
        assert!(p.iter().all(|s| s.mode == Mode::AllNo));
    }

    #[test]
    fn the_reproduction_command_carries_the_sets() {
        let s = Sample {
            preset: "x86_64-qemu".into(),
            mode: Mode::Random(7),
        };
        assert_eq!(
            repro(&s, &[("SMP".into(), "n".into())]),
            "kbuild build --preset x86_64-qemu --random --seed 7 --set SMP=n"
        );
    }
}

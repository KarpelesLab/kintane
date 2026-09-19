//! `kbuild randconfig-build`: build sampled configurations and report what does not.
//!
//! The configuration space is sampled rather than enumerated (`docs/testing.md`,
//! "Configuration coverage"). Each sample is a preset, which fixes the architecture,
//! extended by `kcfg::random` from one seed. A failure is reported with the exact
//! command that rebuilds it, so a nightly red is something a person can reproduce on
//! their own machine in one step rather than an anecdote.
//!
//! Three kinds of failure are kept apart, because they are different people's bugs:
//!
//! - **The configuration did not resolve.** The generator promises valid configurations, so this is
//!   a kbuild bug.
//! - **The configuration resolved and did not build.** An unbuildable combination: a kernel bug, or
//!   a missing `depends on` in a `.kcfg`. Exactly what the trait approach in `docs/portability.md`
//!   claims should not exist.
//! - **The configuration built and did not boot.** A combination that compiles into a kernel that
//!   does not run, which no amount of building finds.
//!
//! # What is booted, and what is not
//!
//! Some samples have no success to report, and are counted apart rather than called failures:
//! see [`not_bootable`] for which and why. A sweep that invents failures is worse than no
//! sweep, so the rule is that a sample is booted only when a passing run is a thing it could
//! have produced.
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
    let mut unbootable = Vec::new();
    let mut booted = 0usize;
    let mut no_channel = 0usize;
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
            Err(e) => {
                let _ = std::fs::write(&log, &e);
                eprintln!("\x1b[31mDID NOT BUILD\x1b[0m: {}", first_line(&e));
                unbuildable.push((cmd, log));
            }
            Ok((image, res)) => {
                println!("\x1b[32mbuilt\x1b[0m");
                if let Some(why) = not_bootable(&res) {
                    println!("  not booted: {why}");
                    no_channel += 1;
                } else {
                    match boot_sample(root, &o, &image, &res) {
                        Ok(code) => {
                            println!("\x1b[32mbooted\x1b[0m (qemu exit {code})");
                            booted += 1;
                        }
                        Err(e) => {
                            let _ = std::fs::write(&log, &e);
                            eprintln!("\x1b[31mDID NOT BOOT\x1b[0m: {}", first_line(&e));
                            unbootable.push((cmd, log));
                        }
                    }
                }
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
    println!(
        "of those that built: {booted} booted, {} did not boot, {no_channel} not booted (no \
         verdict to give)",
        unbootable.len()
    );
    for (what, list) in [
        ("did not build", &unbuildable),
        ("did not boot", &unbootable),
        ("did not resolve", &invalid),
    ] {
        for (cmd, log) in list {
            println!("  {what}: {cmd}\n    log: {}", log.display());
        }
    }
    if invalid.is_empty() && unbuildable.is_empty() && unbootable.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "{} of {} configurations failed",
            invalid.len() + unbuildable.len() + unbootable.len(),
            samples.len()
        ))
    }
}

/// Why this configuration is not booted, or `None` when it can be.
///
/// Two kinds of sample have no success to report, and asking them for one would invent a
/// failure rather than find one:
///
/// * **No result channel.** The verdict of a run is the guest's exit status, and `QEMU_EXIT`
///   is what lets a guest produce one. Without it a boot could end only in a timeout, and
///   since `QEMU_EXIT` is `default n`, every `--allno` sample is one.
/// * **A deliberate crash mode.** `CRASH_PANIC` and `CRASH_FAULT` build a kernel that is
///   *meant* to die after boot. `kbuild run` on one is expected to fail; CI reads the
///   decoded backtrace out of such a run rather than its exit status.
fn not_bootable(res: &crate::kcfg::Resolution) -> Option<&'static str> {
    if !res.is_on("QEMU_EXIT") {
        return Some("without QEMU_EXIT the guest cannot report a verdict");
    }
    if res.is_on("CRASH_PANIC") || res.is_on("CRASH_FAULT") {
        return Some("a deliberate crash mode is meant to die, not to signal success");
    }
    None
}

/// The least a sampled configuration is given to boot, when it is not a stress run.
///
/// CI gives every preset sixty seconds (`kbuild run --preset <name> --timeout 60`), and a
/// sample is never faster than a preset: it may have more CPUs, a larger heap, or a boot menu
/// to sit through. `--timeout` raises this and does not lower it, because a sweep that fails a
/// healthy guest for being slow reports noise, and noise is worse than no sweep at all.
const BOOT_SECONDS: u64 = 60;

/// Boot a sample that has just built, and return the guest's exit status when it passed.
///
/// The caller decides whether a sample is bootable at all; see this module's header for why
/// a configuration without `QEMU_EXIT` is not one.
fn boot_sample(
    root: &Path,
    opts: &Opts,
    image: &Path,
    res: &crate::kcfg::Resolution,
) -> Result<i32, String> {
    let log = root.join("build").join(res.str("TARGET")).join("qemu.log");
    let m = crate::qemu::machine_for(res, image, &log)?;
    // A sample may have turned the stress run on, and that lasts STRESS_SECONDS of guest time,
    // far past the thirty seconds `--timeout` defaults to. Give it the allowance `kbuild
    // stress` gives, so that a long run is not reported as a hang.
    let timeout = if res.is_on("STRESS_TEST") {
        crate::stress::timeout(res.int("STRESS_SECONDS").max(0) as u64)
    } else {
        opts.timeout.max(BOOT_SECONDS)
    };
    let outcome = crate::boot(root, res, &m, timeout, None)?;
    match outcome.code {
        Some(c) if outcome.passed => Ok(c),
        Some(c) => Err(format!("error: guest exited {c}, expected {} for success", m.success_code)),
        None if outcome.timed_out => {
            Err(format!("error: no exit signal from the guest in {timeout}s"))
        }
        None => Err("error: QEMU was terminated by a signal".into()),
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

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
//! # How a built sample is judged
//!
//! What counts as success depends on what the sample was built to do, so there are three
//! verdicts; see [`judge`].
//!
//! - **Built to die.** A deliberate crash mode is *meant* to bring the guest down, so its
//!   verdict is whether the crash report decoded — the same four conditions CI applies, in
//!   [`crash_decoded`]. Two thirds of random samples draw one, because a choice is sampled
//!   uniformly over its members and two of `CRASH_TEST`'s three are crashes, so this is most
//!   of the random half rather than a corner of it.
//! - **No result channel.** The verdict of an ordinary run is the guest's exit status, and
//!   `QEMU_EXIT` is what lets a guest produce one. Without it a boot could only ever end in a
//!   timeout. Counted apart rather than called a failure.
//! - **Everything else** is judged by that exit status.
//!
//! A sweep that invents failures is worse than no sweep, so the rule is that a sample is only
//! ever asked for a verdict that a passing run of it could actually have produced.
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
    let mut undecoded = Vec::new();
    let mut booted = 0usize;
    let mut crashed = 0usize;
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
                match judge(&res) {
                    Judge::Crash(kind) => match crash_sample(root, &o, &image, &res, kind) {
                        Ok(frames) => {
                            println!("\x1b[32mcrashed and decoded\x1b[0m ({frames} frames)");
                            crashed += 1;
                        }
                        Err(e) => {
                            let _ = std::fs::write(&log, &e);
                            eprintln!("\x1b[31mCRASH NOT DECODED\x1b[0m: {}", first_line(&e));
                            undecoded.push((cmd, log));
                        }
                    },
                    Judge::Nothing(why) => {
                        println!("  not judged: {why}");
                        no_channel += 1;
                    }
                    Judge::Exit => match boot_sample(root, &o, &image, &res) {
                        Ok(code) => {
                            println!("\x1b[32mbooted\x1b[0m (qemu exit {code})");
                            booted += 1;
                        }
                        Err(e) => {
                            let _ = std::fs::write(&log, &e);
                            eprintln!("\x1b[31mDID NOT BOOT\x1b[0m: {}", first_line(&e));
                            unbootable.push((cmd, log));
                        }
                    },
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
        "of those that built: {booted} booted, {} did not boot, {crashed} crashed and decoded, \
         {} crashed without a decodable report, {no_channel} not judged (no verdict to give)",
        unbootable.len(),
        undecoded.len()
    );
    for (what, list) in [
        ("did not build", &unbuildable),
        ("did not boot", &unbootable),
        ("crash not decoded", &undecoded),
        ("did not resolve", &invalid),
    ] {
        for (cmd, log) in list {
            println!("  {what}: {cmd}\n    log: {}", log.display());
        }
    }
    if invalid.is_empty() && unbuildable.is_empty() && unbootable.is_empty() && undecoded.is_empty()
    {
        Ok(())
    } else {
        Err(format!(
            "{} of {} configurations failed",
            invalid.len() + unbuildable.len() + unbootable.len() + undecoded.len(),
            samples.len()
        ))
    }
}

/// Which deliberate crash a configuration asks for.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Crash {
    Panic,
    Fault,
}

impl Crash {
    /// The frame a decoded report must name, by kind.
    ///
    /// A panic unwinds from `nested_panic` itself. An undefined instruction traps instead, so
    /// the faulting pc is inside the architecture's trap entry rather than in `nested_fault`.
    /// These are the names CI greps for; see the crash step in `.github/workflows/ci.yml`.
    fn must_name(self) -> &'static str {
        match self {
            Crash::Panic => "kintane::crash::nested_panic",
            Crash::Fault => "arch::backtrace::undefined_instruction",
        }
    }
}

/// What a built sample's success condition is.
#[derive(Debug, PartialEq)]
pub enum Judge {
    /// Built to die: the verdict is whether its crash report decoded.
    Crash(Crash),
    /// The guest reports its own verdict through `QEMU_EXIT`.
    Exit,
    /// No success this sample could produce, and why.
    Nothing(&'static str),
}

/// How this configuration can be judged, once it has built.
///
/// The crash modes are asked about first, deliberately. A kernel built to die does not need
/// `QEMU_EXIT` to say so, because its verdict is the backtrace rather than an exit status;
/// testing the result channel first would send every crash sample that happens to lack
/// `QEMU_EXIT` to [`Judge::Nothing`] over a channel it was never going to use.
pub fn judge(res: &crate::kcfg::Resolution) -> Judge {
    judging(res.is_on("CRASH_PANIC"), res.is_on("CRASH_FAULT"), res.is_on("QEMU_EXIT"))
}

/// [`judge`]'s decision over the three symbols it reads, apart from the resolution that
/// supplies them, because the order they are asked in is the part worth a test.
fn judging(panic: bool, fault: bool, qemu_exit: bool) -> Judge {
    if panic {
        return Judge::Crash(Crash::Panic);
    }
    if fault {
        return Judge::Crash(Crash::Fault);
    }
    if !qemu_exit {
        // `QEMU_EXIT` is `default n`, so every `--allno` sample lands here.
        return Judge::Nothing("without QEMU_EXIT the guest cannot report a verdict");
    }
    Judge::Exit
}

/// The caller every deliberate crash is made from: two frames deep, and never inlined.
const CRASH_CALLER: &str = "kintane::crash::outer";
/// The source a decoded frame must be attributed to, which only `.debug_line` can supply.
const CRASH_SOURCE: &str = "kernel/main/src/crash.rs:";

/// Whether a decoded report is the one this crash mode should have produced.
///
/// The four conditions CI applies, kept in one place so a sweep and CI cannot drift over what
/// a good crash report is. Each can fail on its own, which is the point: a crash that happens
/// is not the same as a crash that reported itself.
///
/// 1. **Something decoded at all.** `symbolize::decode` returns an empty list for a log with
///    no `bt` lines, so a guest that never reached its crash lands here rather than passing
///    for having died in some other way.
/// 2. **The crash's own frame is named.**
/// 3. **Its caller is named too.** A report holding only the faulting pc satisfies (2) and
///    proves nothing about unwinding, which is the whole thing a backtrace is for.
/// 4. **A frame carries a source line.** Names come from the symbol table; files and lines
///    come from `.debug_line`. Without this, a bundle whose line table did not decode would
///    pass on names alone.
fn crash_decoded(frames: &[String], want: &str) -> Result<(), String> {
    if frames.is_empty() {
        return Err("the guest printed no backtrace at all: it never reached its crash".into());
    }
    let has = |s: &str| frames.iter().any(|f| f.contains(s));
    if !has(want) {
        return Err(format!("no decoded frame names {want}"));
    }
    if !has(CRASH_CALLER) {
        return Err(format!(
            "no decoded frame names {CRASH_CALLER}: the report has the crash but nothing above it"
        ));
    }
    if !has(CRASH_SOURCE) {
        return Err(format!(
            "no decoded frame carries a {CRASH_SOURCE} line: names resolved but `.debug_line` did not"
        ));
    }
    Ok(())
}

/// The least a deliberate crash is given to boot and die.
///
/// CI allows twenty seconds. A sample can take longer to get there than a preset does — more
/// CPUs, a larger heap, a boot menu to sit through — and the crash fires from `main` once the
/// kernel is up and before the scheduler takes over, so this is a boot allowance and never a
/// workload one: a crash sample never reaches a stress run. `--timeout` raises it.
const CRASH_SECONDS: u64 = 60;

/// Boot a sample built to crash, and judge the report it left. How many frames it decoded.
///
/// [`crate::boot`]'s own verdict is not the question here: a deliberate crash may take the
/// guest down through `QEMU_EXIT` with a failure code, or leave it spinning until the timeout,
/// and both are what this kernel was built to do. Its error is kept only to explain a report
/// that never arrived.
///
/// The console is read back from `build/<target>/console.log`, which `boot` documents as where
/// it puts one and writes before returning either way. It is removed first, so a log an
/// earlier sample left behind cannot be read as this one's.
fn crash_sample(
    root: &Path,
    opts: &Opts,
    image: &Path,
    res: &crate::kcfg::Resolution,
    kind: Crash,
) -> Result<usize, String> {
    let dir = root.join("build").join(res.str("TARGET"));
    let console = dir.join("console.log");
    let _ = std::fs::remove_file(&console);
    let m = crate::qemu::machine_for(res, image, &dir.join("qemu.log"))?;
    let why = crate::boot(root, res, &m, opts.timeout.max(CRASH_SECONDS), None).err();
    let because = |e: String| match &why {
        Some(w) => format!("error: {e}; the run itself: {}", first_line(w)),
        None => format!("error: {e}"),
    };
    let text = std::fs::read(&console)
        .map_err(|e| because(format!("no console at {}: {e}", console.display())))?;
    let bundle = crate::find_symbol_bundle(&dir.join("out"))?;
    let nm = crate::toolchain::verify(root)?.tool("llvm-nm")?;
    let frames = crate::symbolize::decode(&String::from_utf8_lossy(&text), &bundle, &nm)
        .map_err(|e| because(e))?;
    crash_decoded(&frames, kind.must_name()).map_err(|e| because(e))?;
    Ok(frames.len())
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

    /// A decoded report from a healthy `CRASH_PANIC` run, shaped as `symbolize::decode`
    /// returns one: a function with its offset, two spaces, then the file and line.
    fn panic_frames() -> Vec<String> {
        [
            "kintane::crash::nested_panic+0x20  kernel/main/src/crash.rs:25",
            "kintane::crash::outer+0x8  kernel/main/src/crash.rs:18",
            "kintane::kmain+0x1a4  kernel/main/src/main.rs:267",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect()
    }

    #[test]
    fn a_healthy_crash_report_is_accepted() {
        assert!(crash_decoded(&panic_frames(), Crash::Panic.must_name()).is_ok());
    }

    #[test]
    fn each_of_the_four_conditions_fails_on_its_own() {
        let want = Crash::Panic.must_name();

        // 1. Nothing decoded: the guest never reached its crash. Without this, a sample that
        //    died some other way and printed no `bt` line at all would pass for having died.
        let e = crash_decoded(&[], want).unwrap_err();
        assert!(e.contains("no backtrace at all"), "{e}");

        // 2. The crash's own frame is missing, which is what inlining `nested_panic` does.
        let without: Vec<String> = panic_frames()
            .into_iter()
            .filter(|f| !f.contains(want))
            .collect();
        let e = crash_decoded(&without, want).unwrap_err();
        assert!(e.contains(want), "{e}");

        // 3. The faulting pc alone: the right name, and nothing above it. This satisfies (2)
        //    while proving nothing about unwinding.
        let e = crash_decoded(&panic_frames()[..1], want).unwrap_err();
        assert!(e.contains(CRASH_CALLER), "{e}");

        // 4. Names resolved from the symbol table, `.debug_line` did not: no file:line.
        let names: Vec<String> = panic_frames()
            .iter()
            .map(|f| f.split("  ").next().unwrap_or(f).to_string())
            .collect();
        let e = crash_decoded(&names, want).unwrap_err();
        assert!(e.contains(CRASH_SOURCE), "{e}");
    }

    #[test]
    fn a_panics_report_does_not_satisfy_a_fault() {
        assert_ne!(Crash::Panic.must_name(), Crash::Fault.must_name());
        assert!(crash_decoded(&panic_frames(), Crash::Fault.must_name()).is_err());
    }

    #[test]
    fn a_crash_mode_is_judged_even_with_no_result_channel() {
        // The ordering this rests on: a kernel built to die reports through its backtrace, so
        // asking about QEMU_EXIT first would discard these over a channel they never use.
        assert_eq!(judging(true, false, false), Judge::Crash(Crash::Panic));
        assert_eq!(judging(false, true, false), Judge::Crash(Crash::Fault));
        assert_eq!(judging(true, false, true), Judge::Crash(Crash::Panic));
    }

    #[test]
    fn without_a_crash_or_a_channel_there_is_nothing_to_judge() {
        assert!(matches!(judging(false, false, false), Judge::Nothing(_)));
        assert_eq!(judging(false, false, true), Judge::Exit);
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

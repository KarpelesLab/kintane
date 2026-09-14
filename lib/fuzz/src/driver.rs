//! The fuzzing driver: a host binary `kbuild fuzz` builds and runs.
//!
//! Separate from the library so the library stays `no_std` and free of the host machinery
//! this needs: threads for the watchdog, `catch_unwind` for a panic, and a filesystem for
//! the corpus.
//!
//! # Why a thread per input
//!
//! Two of the three failure modes this looks for stop the process: a panic unwinds, and a
//! loop never returns. `catch_unwind` handles the first. The second needs something outside
//! the iteration to notice, so each input runs on a worker thread and the main thread waits
//! for its answer with a deadline. A worker that has not answered by the deadline is a
//! hang, reported with the seed and iteration that produced it.
//!
//! A hung thread cannot be killed, only abandoned, and a thread per input is what makes
//! abandoning one safe: the campaign stops at its first failure, so the abandoned worker is
//! never joined and the process exits around it.
//!
//! The wait is a channel receive with a timeout rather than a poll. The first version
//! polled a flag every millisecond, which put a floor of a millisecond under every input:
//! every target ran at the same ~800 inputs a second whatever its parser cost, which is the
//! signature of a harness measuring its own sleep.
//!
//! Usage, as `kbuild fuzz` invokes it:
//!
//! ```text
//! driver --target NAME --seed N --iterations K --corpus DIR [--budget-ms MS]
//! driver --target NAME --file PATH       # run one input and stop
//! driver --smoke --corpus DIR            # replay every committed input, then stop
//! driver --list                          # the table, for `kbuild fuzz` with no target
//! ```

use std::io::Write;
use std::panic::{self, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::time::{Duration, Instant};

use fuzz::{Rng, TARGETS, Target, shrink};

/// How long one input may take before it is called a hang. Generous: a parser walking a
/// mutated tree can be slow without being wrong, and a false hang wastes someone's
/// afternoon.
const DEFAULT_BUDGET_MS: u64 = 5_000;

fn main() {
    // Quiet, once, for the whole process: a panic is the expected outcome of a find, and
    // the driver reports it itself. The hook is process-wide, so installing it per worker
    // would race an abandoned worker that is still running.
    panic::set_hook(Box::new(|_| {}));

    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = match run(&args) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("{e}");
            1
        }
    };
    std::process::exit(code);
}

struct Options {
    target: Option<String>,
    seed: u64,
    iterations: u64,
    corpus: PathBuf,
    budget: Duration,
    smoke: bool,
    list: bool,
    /// One file to run and nothing else: how a corpus entry is reproduced by hand.
    file: Option<PathBuf>,
}

fn parse(args: &[String]) -> Result<Options, String> {
    let mut o = Options {
        target: None,
        seed: 1,
        iterations: 1000,
        corpus: PathBuf::from("lib/fuzz/corpus"),
        budget: Duration::from_millis(DEFAULT_BUDGET_MS),
        smoke: false,
        list: false,
        file: None,
    };
    let mut i = 0;
    while i < args.len() {
        let need = |i: usize| -> Result<&String, String> {
            args.get(i + 1)
                .ok_or_else(|| format!("{} needs a value", args[i]))
        };
        match args[i].as_str() {
            "--target" => {
                o.target = Some(need(i)?.clone());
                i += 1;
            }
            "--seed" => {
                o.seed = need(i)?.parse().map_err(|_| "--seed expects a number")?;
                i += 1;
            }
            "--iterations" => {
                o.iterations = need(i)?
                    .parse()
                    .map_err(|_| "--iterations expects a number")?;
                i += 1;
            }
            "--corpus" => {
                o.corpus = PathBuf::from(need(i)?);
                i += 1;
            }
            "--budget-ms" => {
                let ms: u64 = need(i)?
                    .parse()
                    .map_err(|_| "--budget-ms expects a number")?;
                o.budget = Duration::from_millis(ms);
                i += 1;
            }
            "--file" => {
                o.file = Some(PathBuf::from(need(i)?));
                i += 1;
            }
            "--smoke" => o.smoke = true,
            "--list" => o.list = true,
            other => return Err(format!("unknown option `{other}`")),
        }
        i += 1;
    }
    Ok(o)
}

fn run(args: &[String]) -> Result<(), String> {
    let o = parse(args)?;
    if o.list {
        for t in TARGETS {
            println!("{:<12} {}", t.name, t.what);
        }
        return Ok(());
    }
    if o.smoke {
        return smoke(&o.corpus, o.budget);
    }
    let name = o.target.as_deref().ok_or("no --target")?;
    let target = fuzz::target(name).ok_or_else(|| format!("no target `{name}`"))?;

    if let Some(path) = &o.file {
        let bytes = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
        return match run_once(target, &bytes, o.budget) {
            Outcome::Ok { .. } => {
                println!("{}: {} bytes, no failure", target.name, bytes.len());
                Ok(())
            }
            Outcome::Panicked(m) => Err(format!("{}: panicked: {m}", target.name)),
            Outcome::Hung => Err(format!("{}: did not finish within the budget", target.name)),
        };
    }

    campaign(target, &o)
}

/// Replay every committed input. Seconds, not minutes: this is the per-change gate.
fn smoke(corpus: &Path, budget: Duration) -> Result<(), String> {
    let mut files = 0usize;
    let mut failed = 0usize;
    for target in TARGETS {
        let dir = corpus.join(target.name);
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        let mut paths: Vec<PathBuf> = entries
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|e| e == "bin"))
            .collect();
        paths.sort();
        for path in paths {
            let bytes = std::fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))?;
            files += 1;
            match run_once(target, &bytes, budget) {
                Outcome::Ok { .. } => {}
                Outcome::Panicked(m) => {
                    eprintln!("{}: panicked on {}: {m}", target.name, path.display());
                    failed += 1;
                }
                Outcome::Hung => {
                    eprintln!("{}: hung on {}", target.name, path.display());
                    failed += 1;
                }
            }
        }
    }
    println!("replayed {files} corpus input(s)");
    if failed > 0 {
        return Err(format!("{failed} corpus input(s) failed"));
    }
    Ok(())
}

enum Outcome {
    /// The input was answered. `accepted` is whether the target's parser took it past its
    /// top-level check; `None` for a target with no such gate.
    Ok {
        accepted: Option<bool>,
    },
    Panicked(String),
    Hung,
}

/// Run one input on a worker, and wait for it with a deadline.
fn run_once(target: &'static Target, input: &[u8], budget: Duration) -> Outcome {
    let bytes = input.to_vec();
    let (tx, rx) = mpsc::channel::<Result<Option<bool>, String>>();
    std::thread::spawn(move || {
        let result = panic::catch_unwind(AssertUnwindSafe(|| {
            (target.run)(&bytes);
            // Whether the parser accepted it, asked inside the worker: it calls the parser
            // too, so it needs the same watchdog and the same unwind guard.
            target.accepts.map(|accepts| accepts(&bytes))
        }));
        let answer = result.map_err(|e| {
            e.downcast_ref::<&str>()
                .map(|s| (*s).to_string())
                .or_else(|| e.downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "panicked".into())
        });
        // A send fails only once the campaign has given up on this worker as hung, and
        // then nobody is listening for the answer.
        let _ = tx.send(answer);
    });

    match rx.recv_timeout(budget) {
        Ok(Ok(accepted)) => Outcome::Ok { accepted },
        Ok(Err(message)) => Outcome::Panicked(message),
        Err(RecvTimeoutError::Timeout) => Outcome::Hung,
        // The worker ended without sending, which `catch_unwind` should make impossible;
        // reported rather than assumed.
        Err(RecvTimeoutError::Disconnected) => {
            Outcome::Panicked("the worker ended without an answer".into())
        }
    }
}

/// Generate and run, reporting the first failure with everything needed to reproduce it.
fn campaign(target: &'static Target, o: &Options) -> Result<(), String> {
    let dir = o.corpus.join(target.name);
    let seeds = load_seeds(&dir);
    if target.needs_seeds && seeds.is_empty() {
        return Err(format!(
            "{} is seeded, but {} holds no seed-*.bin",
            target.name,
            dir.display()
        ));
    }

    let started = Instant::now();
    let mut accepted = 0u64;
    for iteration in 0..o.iterations {
        // One RNG per iteration, seeded from the campaign seed and the iteration number,
        // so any iteration can be replayed on its own without running the ones before it.
        let mut rng = Rng::new(o.seed ^ iteration.wrapping_mul(0x9e37_79b9_7f4a_7c15));
        let input = (target.generate)(&mut rng, &seeds);

        let outcome = run_once(target, &input, o.budget);
        let what = match &outcome {
            Outcome::Ok { accepted: a } => {
                if *a == Some(true) {
                    accepted += 1;
                }
                continue;
            }
            Outcome::Panicked(m) => m.clone(),
            Outcome::Hung => "did not finish within the budget".to_string(),
        };

        eprintln!(
            "\n{}: {what}\n  seed {} iteration {} ({} bytes)",
            target.name,
            o.seed,
            iteration,
            input.len()
        );
        // A panic is shrunk. A hang is not: every shrink attempt at a hang would itself
        // wait out the whole budget, which turns one find into an hour of waiting.
        let small = match outcome {
            Outcome::Hung => input.clone(),
            _ => {
                let budget = o.budget;
                let mut fails = |candidate: &[u8]| {
                    matches!(run_once(target, candidate, budget), Outcome::Panicked(_))
                };
                shrink(&input, &mut fails)
            }
        };
        let path = save(&dir, target.name, &small, &what, o.seed, iteration)?;
        eprintln!(
            "  saved {} bytes as {}\n  reproduce: kbuild fuzz --target {} --file {}",
            small.len(),
            path.display(),
            target.name,
            path.display()
        );
        return Err(format!("{} failed", target.name));
    }

    // How many inputs got past the parser's first check is what says whether the budget
    // tested the parser or only its rejection of garbage.
    let gate = match target.accepts {
        Some(_) => format!(
            "{accepted} accepted ({:.1}%)",
            accepted as f64 * 100.0 / o.iterations.max(1) as f64
        ),
        None => "no accept gate".to_string(),
    };
    println!(
        "{:<12} {} iterations, seed {}, {:.1}s, {gate}, no failures",
        target.name,
        o.iterations,
        o.seed,
        started.elapsed().as_secs_f64()
    );
    Ok(())
}

fn load_seeds(dir: &Path) -> Vec<Vec<u8>> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut paths: Vec<PathBuf> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.extension().is_some_and(|e| e == "bin")
                && p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.starts_with("seed-"))
        })
        .collect();
    paths.sort();
    paths.iter().filter_map(|p| std::fs::read(p).ok()).collect()
}

/// Write a failing input to the corpus, named by its content so the same failure found
/// twice does not become two files, with a note beside it saying what it was.
fn save(
    dir: &Path,
    target: &str,
    bytes: &[u8],
    what: &str,
    seed: u64,
    iteration: u64,
) -> Result<PathBuf, String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    // FNV-1a over the input: short, stable, and enough to name a file by.
    let hash = bytes.iter().fold(0xcbf2_9ce4_8422_2325u64, |h, &b| {
        (h ^ u64::from(b)).wrapping_mul(0x1000_0000_01b3)
    });
    let path = dir.join(format!("crash-{hash:016x}.bin"));
    std::fs::write(&path, bytes).map_err(|e| format!("{}: {e}", path.display()))?;

    let note = path.with_extension("txt");
    let mut f = std::fs::File::create(&note).map_err(|e| format!("{}: {e}", note.display()))?;
    writeln!(
        f,
        "target: {target}\nfound: {what}\nseed: {seed}\niteration: {iteration}\nbytes: {}\n\n\
         Reproduce:\n  kbuild fuzz --target {target} --file {}\n",
        bytes.len(),
        path.display()
    )
    .map_err(|e| format!("{}: {e}", note.display()))?;
    Ok(path)
}

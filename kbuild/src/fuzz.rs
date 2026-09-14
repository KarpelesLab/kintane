//! `kbuild fuzz`: build the fuzzing harness for the host and run it.
//!
//! The harness is an ordinary host-testable unit (`lib/fuzz`), so this reuses the host
//! build the test runner already has: its dependencies as rlibs, then one binary — the
//! driver — linked against them. Nothing here knows what a target is; the table lives in
//! the unit, and this passes a name through to it.
//!
//! # Why not a `--test` binary
//!
//! A fuzzing run takes a seed, an iteration count and a corpus directory, and reports a
//! failing input by writing it out. The test harness's command line is filters and flags
//! it defines itself; threading these through it would mean encoding them in environment
//! variables and a test name. A binary with a `main` takes arguments, which is what this
//! needs. The unit's *own* tests still run under `kbuild test`, where they belong: the
//! generators and the shrinker are ordinary code.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::Command;

use crate::codegen::Generated;
use crate::graph::Unit;
use crate::hosttest::HostBuild;
use crate::toolchain::Toolchain;

/// The unit that holds the targets, and the driver beside it.
const UNIT: &str = "fuzz";
const DRIVER: &str = "src/driver.rs";

/// What to run: one campaign, every target in turn, or the corpus.
pub struct Run {
    pub target: Option<String>,
    pub seed: Option<u64>,
    pub iterations: u64,
    pub smoke: bool,
    pub file: Option<String>,
    pub corpus: Option<String>,
}

/// Build the driver and run it, once per target when none was named.
pub fn run(
    root: &std::path::Path,
    tc: &Toolchain,
    generated: &Generated,
    ordered: &[Unit],
    r: &Run,
    verbose: bool,
) -> Result<(), String> {
    let out = root.join("build/host/fuzz");
    std::fs::create_dir_all(&out).map_err(|e| format!("{}: {e}", out.display()))?;
    let hb = HostBuild::new(root, tc, out.clone(), generated, verbose);

    let unit = ordered
        .iter()
        .find(|u| u.name == UNIT)
        .ok_or("no `fuzz` unit in this configuration")?;

    // Its dependencies, then the unit itself, as rlibs the driver links against.
    let mut built: BTreeMap<String, PathBuf> = BTreeMap::new();
    built.insert("kconfig".into(), hb.kconfig()?);
    let mut needed: Vec<&Unit> = Vec::new();
    crate::hosttest::collect_deps(unit, ordered, &mut needed);
    for u in &needed {
        if built.contains_key(&u.name) {
            continue;
        }
        let path = hb.rlib(u, &built)?;
        built.insert(u.name.clone(), path);
    }

    let driver = hb.bin(unit, DRIVER, "kintane-fuzz", &built)?;
    let corpus = r
        .corpus
        .clone()
        .unwrap_or_else(|| root.join("lib/fuzz/corpus").display().to_string());

    // A named target runs alone; without one, every target in the table runs in turn, so
    // `kbuild fuzz` on its own is a useful thing to type.
    let targets: Vec<String> = match (&r.target, r.smoke, &r.file) {
        (Some(t), _, _) => vec![t.clone()],
        (None, true, _) => Vec::new(),
        (None, _, _) => list(&driver)?,
    };

    if r.smoke {
        return exec(&driver, &["--smoke".into(), "--corpus".into(), corpus]);
    }

    if let Some(file) = &r.file {
        let target = r
            .target
            .clone()
            .ok_or("--file names one input, so it needs --target")?;
        return exec(
            &driver,
            &[
                "--target".into(),
                target,
                "--file".into(),
                file.clone(),
                "--corpus".into(),
                corpus,
            ],
        );
    }

    // A seed that is not given changes with the clock, so a nightly run samples somewhere
    // new; it is printed by the driver either way, which is what makes a find reproducible.
    let seed = r.seed.unwrap_or_else(fresh_seed);
    let mut failed = 0;
    for target in &targets {
        let args = [
            "--target".to_string(),
            target.clone(),
            "--seed".to_string(),
            seed.to_string(),
            "--iterations".to_string(),
            r.iterations.to_string(),
            "--corpus".to_string(),
            corpus.clone(),
        ];
        if exec(&driver, &args).is_err() {
            failed += 1;
        }
    }
    if failed > 0 {
        return Err(format!("{failed} target(s) found a failure"));
    }
    Ok(())
}

/// The target names, from the driver itself, so this file holds no second list.
fn list(driver: &std::path::Path) -> Result<Vec<String>, String> {
    let out = Command::new(driver)
        .arg("--list")
        .output()
        .map_err(|e| format!("cannot run the fuzz driver: {e}"))?;
    if !out.status.success() {
        return Err("the fuzz driver could not list its targets".into());
    }
    Ok(parse_list(&String::from_utf8_lossy(&out.stdout)))
}

/// The names in the driver's `--list` output: the first word of each non-blank line.
fn parse_list(stdout: &str) -> Vec<String> {
    stdout
        .lines()
        .filter_map(|l| l.split_whitespace().next().map(str::to_string))
        .collect()
}

fn exec(driver: &std::path::Path, args: &[String]) -> Result<(), String> {
    let status = Command::new(driver)
        .args(args)
        .status()
        .map_err(|e| format!("cannot run the fuzz driver: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err("the fuzz driver reported a failure".into())
    }
}

/// A seed from the clock, for a run that did not ask for a particular one.
fn fresh_seed() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0x2545_f491_4f6c_dd1d)
}

#[cfg(test)]
mod tests {
    use super::parse_list;

    #[test]
    fn the_target_list_is_the_first_word_of_each_line() {
        let out =
            "fdt          device tree blobs\nacpi         ACPI tables\n\nvirtio-ring  a ring\n";
        assert_eq!(parse_list(out), ["fdt", "acpi", "virtio-ring"]);
    }

    #[test]
    fn an_empty_list_names_no_targets() {
        assert!(parse_list("").is_empty());
        assert!(parse_list("\n\n").is_empty());
    }
}

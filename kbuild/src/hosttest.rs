//! Host-side testing.
//!
//! Kernel crates that do not touch hardware are compiled for the **host** and run
//! with the ordinary Rust test harness. This is possible only because the upper
//! layers are generic over `hal` traits rather than calling into `arch` directly, so
//! a mock architecture can be substituted — see `docs/testing.md`.
//!
//! Two mock profiles exist with deliberately different capability sets, and a
//! subsystem's tests are expected to run against both. That is the point: a scheduler
//! tested only against a machine with an MMU, SMP and atomics has not been tested
//! against half the targets we claim.
//!
//! A unit opts in with `host-tests = true` in its `kmod.toml`. Opting in is a claim:
//! *this code does not need real hardware*. A subsystem that cannot make that claim
//! has a design problem, which is a conversation worth having at the manifest rather
//! than discovering later.

use crate::codegen::Generated;
use crate::graph::Unit;
use crate::toolchain::Toolchain;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

pub struct Summary {
    pub units: usize,
    pub passed: usize,
    pub failed: usize,
}

struct HostBuild<'a> {
    root: &'a Path,
    tc: &'a Toolchain,
    out: PathBuf,
    generated: &'a Generated,
    verbose: bool,
}

impl HostBuild<'_> {
    /// Arguments shared by host rlibs and host test binaries.
    ///
    /// Note what is absent: no `--target`, so this builds for the host and links
    /// against its `std`; and no `-C panic=abort`, because the test harness reports
    /// a failing test by unwinding.
    fn common(&self) -> Vec<String> {
        let mut a = vec![
            "--edition".into(),
            "2024".into(),
            "-C".into(),
            "debuginfo=2".into(),
        ];
        for c in &self.generated.cfgs {
            a.push("--cfg".into());
            a.push(c.clone());
        }
        a.extend(self.generated.check_cfgs.iter().cloned());
        a.push("--remap-path-prefix".into());
        a.push(format!("{}=/kintane", self.root.display()));
        a
    }

    fn run(&self, args: &[String], what: &str) -> Result<(), String> {
        if self.verbose {
            eprintln!("    rustc {}", args.join(" "));
        }
        let out = Command::new(&self.tc.rustc)
            .args(args)
            .output()
            .map_err(|e| format!("cannot run rustc: {e}"))?;
        let stderr = String::from_utf8_lossy(&out.stderr);
        if !out.status.success() {
            return Err(format!("failed to compile {what} for the host\n\n{stderr}"));
        }
        if !stderr.trim().is_empty() {
            eprint!("{stderr}");
        }
        Ok(())
    }

    fn rlib(&self, unit: &Unit, deps: &BTreeMap<String, PathBuf>) -> Result<PathBuf, String> {
        let name = unit.name.replace('-', "_");
        let dest = self.out.join(format!("lib{name}.rlib"));
        let mut args = self.common();
        args.extend([
            "--crate-type".into(),
            "rlib".into(),
            "--crate-name".into(),
            name,
        ]);
        self.externs(&mut args, unit, deps);
        args.push(unit.root_path().display().to_string());
        args.push("-o".into());
        args.push(dest.display().to_string());
        self.run(&args, &unit.name)?;
        Ok(dest)
    }

    fn test_binary(
        &self,
        unit: &Unit,
        deps: &BTreeMap<String, PathBuf>,
    ) -> Result<PathBuf, String> {
        let name = unit.name.replace('-', "_");
        let dest = self.out.join(format!("test-{name}"));
        let mut args = self.common();
        args.extend(["--test".into(), "--crate-name".into(), name]);
        self.externs(&mut args, unit, deps);
        args.push(unit.root_path().display().to_string());
        args.push("-o".into());
        args.push(dest.display().to_string());
        self.run(&args, &format!("{} (tests)", unit.name))?;
        Ok(dest)
    }

    fn externs(&self, args: &mut Vec<String>, unit: &Unit, deps: &BTreeMap<String, PathBuf>) {
        for d in &unit.deps {
            if let Some(p) = deps.get(d) {
                args.push("--extern".into());
                args.push(format!("{}={}", d.replace('-', "_"), p.display()));
            }
        }
        if let Some(p) = deps.get("kconfig") {
            args.push("--extern".into());
            args.push(format!("kconfig={}", p.display()));
        }
        args.push("-L".into());
        args.push(self.out.display().to_string());
    }
}

/// Build and run every host-testable unit's tests.
pub fn run(
    root: &Path,
    tc: &Toolchain,
    generated: &Generated,
    ordered: &[Unit],
    filter: Option<&str>,
    verbose: bool,
) -> Result<Summary, String> {
    let out = root.join("build/host/out");
    std::fs::create_dir_all(&out).map_err(|e| format!("{}: {e}", out.display()))?;

    let hb = HostBuild {
        root,
        tc,
        out: out.clone(),
        generated,
        verbose,
    };

    // Which units to run tests for, and everything they transitively need.
    let wanted: Vec<&Unit> = ordered
        .iter()
        .filter(|u| u.host_tests)
        .filter(|u| filter.map(|f| u.name.contains(f)).unwrap_or(true))
        .collect();
    if wanted.is_empty() {
        return Err(match filter {
            Some(f) => format!("no host-testable unit matches `{f}`"),
            None => "no unit declares `host-tests = true`".into(),
        });
    }

    let mut needed: Vec<&Unit> = Vec::new();
    for u in &wanted {
        collect_deps(u, ordered, &mut needed);
    }

    // The generated configuration, as a crate the units can read.
    let mut built: BTreeMap<String, PathBuf> = BTreeMap::new();
    let kconfig = out.join("libkconfig.rlib");
    {
        let mut args = hb.common();
        args.extend([
            "--crate-type".into(),
            "rlib".into(),
            "--crate-name".into(),
            "kconfig".into(),
            generated.config_rs.display().to_string(),
            "-o".into(),
            kconfig.display().to_string(),
        ]);
        hb.run(&args, "kconfig")?;
    }
    built.insert("kconfig".into(), kconfig);

    // Dependencies first, as plain rlibs. A unit under test is compiled twice: once
    // as a library for its dependents, once with --test for itself.
    for u in &needed {
        if built.contains_key(&u.name) {
            continue;
        }
        let p = hb.rlib(u, &built)?;
        built.insert(u.name.clone(), p);
    }

    let mut summary = Summary {
        units: 0,
        passed: 0,
        failed: 0,
    };

    for u in &wanted {
        let bin = hb.test_binary(u, &built)?;
        println!("\n\x1b[36m{}\x1b[0m", u.name);
        let status = Command::new(&bin)
            .status()
            .map_err(|e| format!("cannot run {}: {e}", bin.display()))?;
        summary.units += 1;
        if status.success() {
            summary.passed += 1;
        } else {
            summary.failed += 1;
        }
    }

    Ok(summary)
}

/// Depth-first over `unit`'s dependencies, appending each before the unit itself.
fn collect_deps<'a>(unit: &'a Unit, all: &'a [Unit], out: &mut Vec<&'a Unit>) {
    for d in &unit.deps {
        if let Some(dep) = all.iter().find(|u| &u.name == d) {
            if !out.iter().any(|u| u.name == dep.name) {
                collect_deps(dep, all, out);
            }
        }
    }
    if !out.iter().any(|u| u.name == unit.name) {
        out.push(unit);
    }
}

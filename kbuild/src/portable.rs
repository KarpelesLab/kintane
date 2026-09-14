//! The portability check.
//!
//! Every unit that declares `host-tests = true` claims its code does not need real
//! hardware. The host tests check half of that claim. The other half is whether the
//! code *compiles* for the machines the project promises and has not ported yet, and
//! host tests cannot check it. A host has 64-bit atomics with compare-and-swap, so code
//! that uses them passes every host test and still does not build for an rv32i core.
//!
//! One would expect a capability bound to rule this out. `fn f<A: HasCas>()` is never
//! instantiated on a machine without CAS, so it seems the body should not matter. It
//! does matter. Rust type-checks a generic body where it is defined, against the target's
//! own `core`, and on rv32i `AtomicU32::compare_exchange` does not exist. The bound
//! decides who may *call* the code. Only `#[cfg(target_has_atomic = "…")]` decides whether
//! the code is *there*. See `docs/portability.md`.
//!
//! So this compiles those units, with warnings denied, for built-in rustc targets that
//! stand in for the machines no tier-1 port covers. Warnings are denied because an import
//! left unused on a machine without atomics means the gating stopped halfway. A unit that
//! fails is reported and the check moves on, as the host test runner does.

use std::collections::BTreeMap;
use std::path::Path;

use crate::build::{Build, Built, Target};
use crate::cache::Cache;
use crate::codegen;
use crate::graph::{self, Unit};
use crate::hosttest::collect_deps;
use crate::kcfg::{Resolution, SymbolTable};
use crate::toolchain::Toolchain;

/// A machine the portable units must compile for.
pub struct Machine {
    /// A target built into the pinned rustc.
    pub triple: &'static str,
    /// Configuration requests that describe this machine, so the generated `cfg`s and
    /// constants match the target instead of being the defaults for x86-64.
    pub config: &'static [(&'static str, &'static str)],
    /// What this machine lacks that the tier-1 ports have.
    pub why: &'static str,
}

pub const MACHINES: &[Machine] = &[
    Machine {
        triple: "riscv32i-unknown-none-elf",
        config: &[("ARCH_RISCV32", "y")],
        why: "no atomics of any width, so compare-and-swap is unavailable",
    },
    Machine {
        triple: "riscv32imac-unknown-none-elf",
        config: &[("ARCH_RISCV32", "y")],
        why: "compare-and-swap up to 32 bits, but no 64-bit atomics",
    },
    Machine {
        triple: "thumbv7m-none-eabi",
        config: &[("ARCH_ARMV7M", "y")],
        why: "the tier-1 no-MMU target: 32-bit, MPU only",
    },
];

pub struct Report {
    pub checked: usize,
    /// (unit, reason)
    pub broken: Vec<(String, String)>,
}

/// Compile every host-testable unit, plus what it depends on, for `machine`.
pub fn check(
    root: &Path,
    tc: Toolchain,
    machine: &Machine,
    table: &SymbolTable,
    res: &Resolution,
    verbose: bool,
) -> Result<Report, String> {
    let dir = root.join("build/portability").join(machine.triple);
    let out = dir.join("out");
    std::fs::create_dir_all(&out).map_err(|e| format!("{}: {e}", out.display()))?;
    let identity = codegen::identity_text(table, res, &tc.identity(), machine.triple);
    let generated = codegen::emit(table, res, &dir.join("gen"), &identity)?;

    let b = Build {
        root: root.to_path_buf(),
        tc,
        target_name: machine.triple.to_string(),
        target: Target::Builtin(machine.triple.to_string()),
        out,
        gen_dir: dir.join("gen"),
        cache: Cache::new(root.join("build/cache"))?,
        cfgs: generated.cfgs,
        check_cfgs: generated.check_cfgs,
        opt_level: "1".into(),
        link_script: None,
        deny_warnings: true,
        bitcode: false,
        pic: false,
        verbose,
    };

    // Planned from the portable units and their dependencies only. The kernel image
    // needs an `arch` provider, and these machines have none yet; that is not something
    // this check is here to find.
    let ordered = graph::plan(portable_closure(graph::discover(root)?), res)?;
    let mut needed: Vec<&Unit> = Vec::new();
    for u in ordered.iter().filter(|u| u.host_tests) {
        collect_deps(u, &ordered, &mut needed);
    }
    if needed.is_empty() {
        return Err(format!("no host-testable unit is enabled for {}", machine.triple));
    }

    // The same bootstrap as an image build. A failure here is not a finding about one
    // unit: nothing else can be compiled, so it ends the check for this machine.
    let mut built: BTreeMap<String, Built> = BTreeMap::new();
    built.insert("core".into(), b.build_core()?);
    let cb = ordered
        .iter()
        .find(|u| u.name == "compiler_builtins")
        .ok_or("no compiler_builtins unit in this configuration")?;
    built.insert(cb.name.clone(), b.build_unit(cb, &built)?);
    let kconfig = b.build_kconfig(&built["core"], &built["compiler_builtins"])?;
    built.insert("kconfig".into(), kconfig);

    let mut report = Report {
        checked: 0,
        broken: Vec::new(),
    };
    // `needed` is dependency-first, so a unit's dependencies are settled before it.
    for u in needed {
        report.checked += 1;
        let broken_dep = u
            .deps
            .iter()
            .find(|d| report.broken.iter().any(|(n, _)| n == *d));
        if let Some(dep) = broken_dep {
            let why = format!("depends on `{dep}`, which did not build");
            report.broken.push((u.name.clone(), why));
            continue;
        }
        match b.build_unit(u, &built) {
            Ok(artifact) => {
                built.insert(u.name.clone(), artifact);
            }
            Err(e) => report.broken.push((u.name.clone(), e)),
        }
    }
    Ok(report)
}

/// The host-testable units and everything they depend on, by name. Every provider of a
/// name is kept, because which one applies is the configuration's decision, and
/// `graph::plan` makes it.
fn portable_closure(units: Vec<Unit>) -> Vec<Unit> {
    let mut names: Vec<String> = Vec::new();
    let mut stack: Vec<String> = units
        .iter()
        .filter(|u| u.host_tests)
        .map(|u| u.name.clone())
        .collect();
    stack.push("compiler_builtins".into());
    while let Some(name) = stack.pop() {
        if names.contains(&name) {
            continue;
        }
        for u in units.iter().filter(|u| u.name == name) {
            stack.extend(u.deps.iter().cloned());
        }
        names.push(name);
    }
    units
        .into_iter()
        .filter(|u| names.contains(&u.name))
        .collect()
}

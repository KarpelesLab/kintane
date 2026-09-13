//! The build graph: discovering units from `kmod.toml`, filtering them by the
//! resolved configuration, checking layering, and ordering them for compilation.
//!
//! Note what a unit does *not* declare: a list of source files. rustc finds the rest
//! of a crate from `mod` declarations in its root, and those declarations are where
//! `cfg` is allowed to appear (see `docs/portability.md`). So the configuration
//! selects modules inside the source, not file lists in the build manifest — which is
//! the same rule, enforced by there being no other option.

use crate::kcfg::{expr, Resolution, Tri};
use crate::toml;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

/// Layer ranks. A unit may depend only on units of equal or lower rank.
const LAYERS: &[&str] = &["builtins", "hal", "arch", "core", "device", "subsystem", "kernel"];

pub fn layer_rank(name: &str) -> Option<usize> {
    LAYERS.iter().position(|l| *l == name)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Kind {
    /// Compiled to an rlib and linked into something else.
    Lib,
    /// The final linked kernel image.
    Bin,
}

#[derive(Debug, Clone)]
#[allow(dead_code)] // `name` on Symbol-like structs aids debugging output
pub struct Unit {
    pub name: String,
    pub kind: Kind,
    pub dir: PathBuf,
    /// Crate root, relative to `dir`.
    pub root: PathBuf,
    pub deps: Vec<String>,
    pub layer: String,
    /// Built only when this expression holds in the resolved configuration.
    pub requires: Option<expr::Expr>,
    /// Extra rustc arguments, used sparingly (linker scripts, mostly).
    pub rustflags: Vec<String>,
    /// Whether this unit's tests can run on the host against a mock architecture.
    /// Opting in is a claim that the code needs no real hardware.
    pub host_tests: bool,
    pub manifest: PathBuf,
}

impl Unit {
    pub fn root_path(&self) -> PathBuf {
        self.dir.join(&self.root)
    }
    pub fn src_dir(&self) -> PathBuf {
        self.root_path()
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| self.dir.clone())
    }
}

/// Walk the tree for `kmod.toml` files.
pub fn discover(root: &Path) -> Result<Vec<Unit>, String> {
    let mut units = Vec::new();
    // Directories that never contain kernel units.
    let skip: BTreeSet<&str> = ["build", "target", ".git", "docs", "kbuild"].into_iter().collect();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = std::fs::read_dir(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                let name = p.file_name().and_then(|s| s.to_str()).unwrap_or("");
                if !skip.contains(name) && !name.starts_with('.') {
                    stack.push(p);
                }
            } else if p.file_name().and_then(|s| s.to_str()) == Some("kmod.toml") {
                units.push(parse_unit(&p)?);
            }
        }
    }
    units.sort_by(|a, b| (a.name.clone(), a.dir.clone()).cmp(&(b.name.clone(), b.dir.clone())));
    // Duplicate names are checked in `plan`, after the configuration has filtered
    // units out — several may *provide* a name so long as one is selected.
    Ok(units)
}

fn parse_unit(manifest: &Path) -> Result<Unit, String> {
    let src = std::fs::read_to_string(manifest)
        .map_err(|e| format!("{}: {e}", manifest.display()))?;
    let v = toml::parse(&src).map_err(|e| format!("{}: {e}", manifest.display()))?;
    let at = |m: &str| format!("{}: {m}", manifest.display());

    let name = v
        .get_path("unit.name")
        .and_then(|x| x.as_str())
        .ok_or_else(|| at("missing `unit.name`"))?
        .to_string();

    let kind = match v.get_path("unit.kind").and_then(|x| x.as_str()).unwrap_or("lib") {
        "lib" => Kind::Lib,
        "bin" => Kind::Bin,
        other => return Err(at(&format!("unknown unit kind `{other}`"))),
    };

    let root = v
        .get_path("unit.root")
        .and_then(|x| x.as_str())
        .unwrap_or(if kind == Kind::Bin { "src/main.rs" } else { "src/lib.rs" })
        .to_string();

    let layer = v
        .get_path("unit.layer")
        .and_then(|x| x.as_str())
        .ok_or_else(|| at("missing `unit.layer`"))?
        .to_string();
    if layer_rank(&layer).is_none() {
        return Err(at(&format!(
            "unknown layer `{layer}`; expected one of {}",
            LAYERS.join(", ")
        )));
    }

    let requires = match v.get_path("config.requires").and_then(|x| x.as_str()) {
        Some(e) => Some(expr::parse(e).map_err(|m| at(&format!("config.requires: {m}")))?),
        None => None,
    };

    let dir = manifest.parent().unwrap_or(Path::new(".")).to_path_buf();

    Ok(Unit {
        name,
        kind,
        root: PathBuf::from(root),
        deps: v.str_array("deps.units"),
        layer,
        requires,
        rustflags: v.str_array("unit.rustflags"),
        host_tests: v
            .get_path("unit.host-tests")
            .and_then(|x| x.as_bool())
            .unwrap_or(false),
        dir,
        manifest: manifest.to_path_buf(),
    })
}

/// Drop units the configuration excludes, check dependencies and layering, and
/// return the units in an order where every dependency precedes its dependents.
pub fn plan(units: Vec<Unit>, res: &Resolution) -> Result<Vec<Unit>, String> {
    let active: Vec<Unit> = units
        .into_iter()
        .filter(|u| {
            u.requires
                .as_ref()
                .map(|e| e.eval(&|n| res.tri(n), &|n| literal(res, n)) != Tri::N)
                .unwrap_or(true)
        })
        .collect();

    // Exactly one provider per name must survive configuration.
    let mut seen: BTreeMap<&str, &Unit> = BTreeMap::new();
    for u in &active {
        if let Some(prev) = seen.insert(u.name.as_str(), u) {
            return Err(format!(
                "`{}` is provided by two units that are both enabled:\n  {}\n  {}\n  \
                 narrow their `config.requires` so the configuration selects one",
                u.name,
                prev.manifest.display(),
                u.manifest.display()
            ));
        }
    }
    let by_name = seen;

    for u in &active {
        let rank = layer_rank(&u.layer).unwrap();
        for d in &u.deps {
            let Some(dep) = by_name.get(d.as_str()) else {
                return Err(format!(
                    "unit `{}` depends on `{d}`, which is not in this configuration\n  \
                     declared at {}\n  \
                     either it is excluded by `config.requires` or the name is wrong",
                    u.name,
                    u.manifest.display()
                ));
            };
            let drank = layer_rank(&dep.layer).unwrap();
            if drank > rank {
                return Err(format!(
                    "layering violation: `{}` ({}) depends on `{}` ({})\n  \
                     dependencies point downward only\n  \
                     declared at {}",
                    u.name,
                    u.layer,
                    dep.name,
                    dep.layer,
                    u.manifest.display()
                ));
            }
            // Only the final image may name the architecture crate directly;
            // everything else goes through the hal traits.
            if dep.layer == "arch" && u.layer != "kernel" && u.layer != "arch" {
                return Err(format!(
                    "`{}` ({}) depends on architecture unit `{}`\n  \
                     only the kernel image may link arch directly; subsystems use hal traits\n  \
                     declared at {}",
                    u.name,
                    u.layer,
                    dep.name,
                    u.manifest.display()
                ));
            }
        }
    }

    topo_sort(active)
}

fn literal(res: &Resolution, name: &str) -> String {
    res.values
        .get(name)
        .map(|v| match v {
            crate::kcfg::Val::Str(s) => s.clone(),
            crate::kcfg::Val::Int(i) => i.to_string(),
            crate::kcfg::Val::Tri(t) => t.as_str().to_string(),
        })
        .unwrap_or_default()
}

fn topo_sort(units: Vec<Unit>) -> Result<Vec<Unit>, String> {
    let by_name: BTreeMap<String, Unit> = units.into_iter().map(|u| (u.name.clone(), u)).collect();
    let mut out: Vec<Unit> = Vec::new();
    let mut state: BTreeMap<String, u8> = BTreeMap::new(); // 0 unvisited, 1 in progress, 2 done
    let mut stack: Vec<String> = Vec::new();

    // Deterministic order: names are already sorted in the BTreeMap.
    let names: Vec<String> = by_name.keys().cloned().collect();
    for n in names {
        visit(&n, &by_name, &mut state, &mut out, &mut stack)?;
    }
    Ok(out)
}

fn visit(
    name: &str,
    by_name: &BTreeMap<String, Unit>,
    state: &mut BTreeMap<String, u8>,
    out: &mut Vec<Unit>,
    stack: &mut Vec<String>,
) -> Result<(), String> {
    match state.get(name).copied().unwrap_or(0) {
        2 => return Ok(()),
        1 => {
            let at = stack.iter().position(|s| s == name).unwrap_or(0);
            let mut cycle = stack[at..].to_vec();
            cycle.push(name.to_string());
            return Err(format!("dependency cycle: {}", cycle.join(" -> ")));
        }
        _ => {}
    }
    state.insert(name.to_string(), 1);
    stack.push(name.to_string());
    let unit = &by_name[name];
    for d in &unit.deps {
        visit(d, by_name, state, out, stack)?;
    }
    stack.pop();
    state.insert(name.to_string(), 2);
    out.push(unit.clone());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unit(name: &str, layer: &str, deps: &[&str]) -> Unit {
        Unit {
            name: name.into(),
            kind: Kind::Lib,
            dir: PathBuf::from("."),
            root: PathBuf::from("src/lib.rs"),
            deps: deps.iter().map(|s| s.to_string()).collect(),
            layer: layer.into(),
            requires: None,
            rustflags: vec![],
            host_tests: false,
            manifest: PathBuf::from("kmod.toml"),
        }
    }

    #[test]
    fn dependencies_come_first() {
        let units = vec![
            unit("kernel", "kernel", &["mm", "hal"]),
            unit("mm", "core", &["hal"]),
            unit("hal", "hal", &[]),
        ];
        let ordered = plan(units, &Resolution::default()).unwrap();
        let pos = |n: &str| ordered.iter().position(|u| u.name == n).unwrap();
        assert!(pos("hal") < pos("mm"));
        assert!(pos("mm") < pos("kernel"));
    }

    #[test]
    fn upward_dependencies_are_rejected() {
        let units = vec![
            unit("hal", "hal", &["mm"]),
            unit("mm", "core", &[]),
        ];
        let e = plan(units, &Resolution::default()).unwrap_err();
        assert!(e.contains("layering violation"), "{e}");
    }

    #[test]
    fn only_the_image_may_name_arch() {
        let bad = vec![
            unit("mm", "core", &["arch_x86_64"]),
            unit("arch_x86_64", "arch", &[]),
        ];
        let e = plan(bad, &Resolution::default()).unwrap_err();
        assert!(e.contains("only the kernel image may link arch"), "{e}");

        let good = vec![
            unit("kernel", "kernel", &["arch_x86_64"]),
            unit("arch_x86_64", "arch", &[]),
        ];
        assert!(plan(good, &Resolution::default()).is_ok());
    }

    #[test]
    fn cycles_are_named() {
        let units = vec![
            unit("a", "core", &["b"]),
            unit("b", "core", &["a"]),
        ];
        let e = plan(units, &Resolution::default()).unwrap_err();
        assert!(e.contains("dependency cycle"), "{e}");
    }

    #[test]
    fn several_units_may_provide_one_name_if_config_picks_one() {
        // Two arch crates both called "arch": the configuration selects one, and the
        // kernel image depends on the name rather than on a specific architecture.
        let mut a = unit("arch", "arch", &[]);
        a.requires = Some(expr::parse("ARCH_A").unwrap());
        a.dir = PathBuf::from("arch/a");
        let mut b = unit("arch", "arch", &[]);
        b.requires = Some(expr::parse("ARCH_B").unwrap());
        b.dir = PathBuf::from("arch/b");

        // Neither selected: both filtered out, nothing to build.
        assert!(plan(vec![a.clone(), b.clone()], &Resolution::default())
            .unwrap()
            .is_empty());
    }

    #[test]
    fn two_enabled_providers_of_one_name_is_an_error() {
        let a = unit("arch", "arch", &[]);
        let b = unit("arch", "arch", &[]);
        let e = plan(vec![a, b], &Resolution::default()).unwrap_err();
        assert!(e.contains("provided by two units"), "{e}");
    }

    #[test]
    fn missing_dependency_explains_itself() {
        let units = vec![unit("a", "core", &["nope"])];
        let e = plan(units, &Resolution::default()).unwrap_err();
        assert!(e.contains("not in this configuration"), "{e}");
    }

    #[test]
    fn units_excluded_by_config_are_dropped() {
        let mut u = unit("optional", "core", &[]);
        u.requires = Some(expr::parse("FEATURE").unwrap());
        let ordered = plan(vec![u], &Resolution::default()).unwrap();
        assert!(ordered.is_empty(), "FEATURE is off, so the unit is not built");
    }
}

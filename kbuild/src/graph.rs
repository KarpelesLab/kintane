//! The build graph: discovering units from `kmod.toml`, filtering them by the
//! resolved configuration, checking layering, and ordering them for compilation.
//!
//! Note what a unit does *not* declare: a list of source files. rustc finds the rest
//! of a crate from `mod` declarations in its root, and those declarations are where
//! `cfg` is allowed to appear (see `docs/portability.md`). So the configuration
//! selects modules inside the source, not file lists in the build manifest — which is
//! the same rule, enforced by there being no other option.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use crate::kcfg::{Resolution, Tri, expr};
use crate::toml;

/// Layer ranks. A unit may depend only on units of equal or lower rank.
const LAYERS: &[&str] = &[
    "builtins",
    "hal",
    // Bootloaders: images of their own, built for a firmware target, that may link the
    // boot protocol and nothing of the kernel's. Ranked just above `hal` so layering
    // alone keeps arch, core and everything after them out of a loader.
    "loader",
    "arch",
    "core",
    "device",
    "subsystem",
    "kernel",
];

pub fn layer_rank(name: &str) -> Option<usize> {
    LAYERS.iter().position(|l| *l == name)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// Compiled to an rlib and linked into something else.
    Lib,
    /// The final linked kernel image.
    Bin,
    /// A loadable module: built after the kernel, against its configuration, into a
    /// relocatable object the kernel loads at run time. Enabled only by a tristate at `m`;
    /// see `plan` and `kbuild/src/modules.rs`.
    Module,
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
    /// A target built into rustc that this unit is built for instead of the kernel's,
    /// such as `x86_64-unknown-uefi`. Such a unit is a separate image — a bootloader —
    /// built with its own `core` and its own copies of its dependencies.
    pub target: Option<String>,
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
    let skip: BTreeSet<&str> = ["build", "target", ".git", "docs", "kbuild"]
        .into_iter()
        .collect();
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
    let src =
        std::fs::read_to_string(manifest).map_err(|e| format!("{}: {e}", manifest.display()))?;
    let v = toml::parse(&src).map_err(|e| format!("{}: {e}", manifest.display()))?;
    let at = |m: &str| format!("{}: {m}", manifest.display());

    let name = v
        .get_path("unit.name")
        .and_then(|x| x.as_str())
        .ok_or_else(|| at("missing `unit.name`"))?
        .to_string();

    let kind = match v
        .get_path("unit.kind")
        .and_then(|x| x.as_str())
        .unwrap_or("lib")
    {
        "lib" => Kind::Lib,
        "bin" => Kind::Bin,
        "module" => Kind::Module,
        other => return Err(at(&format!("unknown unit kind `{other}`"))),
    };

    let root = v
        .get_path("unit.root")
        .and_then(|x| x.as_str())
        .unwrap_or(if kind == Kind::Bin {
            "src/main.rs"
        } else {
            "src/lib.rs"
        })
        .to_string();

    let layer = v
        .get_path("unit.layer")
        .and_then(|x| x.as_str())
        .ok_or_else(|| at("missing `unit.layer`"))?
        .to_string();
    if layer_rank(&layer).is_none() {
        return Err(at(&format!("unknown layer `{layer}`; expected one of {}", LAYERS.join(", "))));
    }

    let requires = match v.get_path("config.requires").and_then(|x| x.as_str()) {
        Some(e) => Some(expr::parse(e).map_err(|m| at(&format!("config.requires: {m}")))?),
        None => None,
    };

    let dir = manifest.parent().unwrap_or(Path::new(".")).to_path_buf();

    let target = v
        .get_path("unit.target")
        .and_then(|x| x.as_str())
        .map(String::from);
    if kind == Kind::Module && requires.is_none() {
        return Err(at("a module unit needs `config.requires`: the tristate whose `m` builds it"));
    }
    if target.is_some() && kind != Kind::Bin {
        return Err(at("`unit.target` is for images; a library is built for whoever links it"));
    }

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
        target,
        dir,
        manifest: manifest.to_path_buf(),
    })
}

/// Drop units the configuration excludes, check dependencies and layering, and
/// return the units in an order where every dependency precedes its dependents.
pub fn plan(units: Vec<Unit>, res: &Resolution) -> Result<Vec<Unit>, String> {
    let mut active: Vec<Unit> = Vec::new();
    for u in units {
        let level = u
            .requires
            .as_ref()
            .map(|e| e.eval(&|n| res.tri(n), &|n| literal(res, n)))
            .unwrap_or(Tri::Y);
        // `m` means "a loadable module", so it enables exactly the units that can be one.
        // A library at `m` would be linked in as though it were `y`, which is not what was
        // asked for; a module at `y` has no way to be linked into the image at all.
        match (u.kind, level) {
            (_, Tri::N) => continue,
            (Kind::Module, Tri::M) => {}
            (Kind::Module, _) => {
                return Err(format!(
                    "`{}` can only be built as a loadable module, but its condition is y\n  \
                     declared at {}\n  \
                     set the tristate in its `config.requires` to m",
                    u.name,
                    u.manifest.display()
                ));
            }
            (_, Tri::M) => {
                return Err(format!(
                    "`{}` is enabled by an m, but a {} unit cannot be a loadable module\n  \
                     declared at {}\n  \
                     set the tristate in its `config.requires` to y to build it in",
                    u.name,
                    if u.kind == Kind::Bin { "bin" } else { "lib" },
                    u.manifest.display()
                ));
            }
            _ => {}
        }
        active.push(u);
    }

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
            // An image built for another target is not something to link against: its
            // code is for a different machine state, if not a different machine.
            if dep.target.is_some() {
                return Err(format!(
                    "`{}` depends on `{}`, which is built for {} as an image of its own\n  \
                     declared at {}",
                    u.name,
                    dep.name,
                    dep.target.as_deref().unwrap_or_default(),
                    u.manifest.display()
                ));
            }
            // A module is loaded at run time; nothing can link against it. And a module
            // reaches the kernel only through the module interface, so it may not link a
            // copy of the kernel's own crates that hold state: nothing at `arch` or above
            // `core`, where a second copy would be a second, unrelated instance.
            if dep.kind == Kind::Module {
                return Err(format!(
                    "`{}` depends on `{}`, a loadable module, which nothing links against\n  \
                     declared at {}",
                    u.name,
                    dep.name,
                    u.manifest.display()
                ));
            }
            if u.kind == Kind::Module
                && (drank > layer_rank("core").unwrap_or(0) || dep.layer == "arch")
            {
                return Err(format!(
                    "module `{}` depends on `{}` ({}); a module links only units at `core` \
                     or below, and reaches the kernel through its module interface\n  \
                     declared at {}",
                    u.name,
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
            other => other.display(),
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
            target: None,
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
        let units = vec![unit("hal", "hal", &["mm"]), unit("mm", "core", &[])];
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
        let units = vec![unit("a", "core", &["b"]), unit("b", "core", &["a"])];
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
        assert!(
            plan(vec![a.clone(), b.clone()], &Resolution::default())
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn two_enabled_providers_of_one_name_is_an_error() {
        let a = unit("arch", "arch", &[]);
        let b = unit("arch", "arch", &[]);
        let e = plan(vec![a, b], &Resolution::default()).unwrap_err();
        assert!(e.contains("provided by two units"), "{e}");
    }

    #[test]
    fn a_loader_may_link_the_protocol_but_nothing_above_it() {
        let mut loader = unit("kinboot", "loader", &["boot_protocol"]);
        loader.kind = Kind::Bin;
        loader.target = Some("x86_64-unknown-uefi".into());
        let ok = vec![loader.clone(), unit("boot_protocol", "hal", &[])];
        assert!(plan(ok, &Resolution::default()).is_ok());

        let mut greedy = loader;
        greedy.deps.push("mm".into());
        let bad = vec![
            greedy,
            unit("boot_protocol", "hal", &[]),
            unit("mm", "core", &[]),
        ];
        let e = plan(bad, &Resolution::default()).unwrap_err();
        assert!(e.contains("layering violation"), "{e}");
    }

    #[test]
    fn nothing_may_link_an_image_built_for_another_target() {
        let mut loader = unit("kinboot", "loader", &[]);
        loader.kind = Kind::Bin;
        loader.target = Some("x86_64-unknown-uefi".into());
        let units = vec![loader, unit("kernel", "kernel", &["kinboot"])];
        let e = plan(units, &Resolution::default()).unwrap_err();
        assert!(e.contains("image of its own"), "{e}");
    }

    #[test]
    fn missing_dependency_explains_itself() {
        let units = vec![unit("a", "core", &["nope"])];
        let e = plan(units, &Resolution::default()).unwrap_err();
        assert!(e.contains("not in this configuration"), "{e}");
    }

    fn tri(values: &[(&str, Tri)]) -> Resolution {
        let mut r = Resolution::default();
        for (k, v) in values {
            r.values.insert(k.to_string(), crate::kcfg::Val::Tri(*v));
        }
        r
    }

    #[test]
    fn m_enables_exactly_the_units_that_can_be_modules() {
        let mut module = unit("hello", "subsystem", &["api"]);
        module.kind = Kind::Module;
        module.requires = Some(expr::parse("HELLO").unwrap());
        let units = || vec![module.clone(), unit("api", "core", &[])];

        let ordered = plan(units(), &tri(&[("HELLO", Tri::M)])).unwrap();
        assert!(ordered.iter().any(|u| u.name == "hello"));
        assert!(
            plan(units(), &tri(&[("HELLO", Tri::N)]))
                .unwrap()
                .iter()
                .all(|u| u.name != "hello")
        );
        let e = plan(units(), &tri(&[("HELLO", Tri::Y)])).unwrap_err();
        assert!(e.contains("can only be built as a loadable module"), "{e}");

        let mut lib = unit("driver", "device", &[]);
        lib.requires = Some(expr::parse("DRIVER").unwrap());
        let e = plan(vec![lib], &tri(&[("DRIVER", Tri::M)])).unwrap_err();
        assert!(e.contains("a lib unit cannot be a loadable module"), "{e}");
    }

    #[test]
    fn nothing_links_a_module_and_a_module_links_nothing_above_core() {
        let mut module = unit("hello", "subsystem", &[]);
        module.kind = Kind::Module;
        module.requires = Some(expr::parse("HELLO").unwrap());
        let res = tri(&[("HELLO", Tri::M)]);

        let e = plan(vec![module.clone(), unit("kernel", "kernel", &["hello"])], &res).unwrap_err();
        assert!(e.contains("which nothing links against"), "{e}");

        let mut greedy = module;
        greedy.deps.push("sched".into());
        let e = plan(vec![greedy, unit("sched", "subsystem", &[])], &res).unwrap_err();
        assert!(e.contains("a module links only units at `core` or below"), "{e}");
    }

    #[test]
    fn units_excluded_by_config_are_dropped() {
        let mut u = unit("optional", "core", &[]);
        u.requires = Some(expr::parse("FEATURE").unwrap());
        let ordered = plan(vec![u], &Resolution::default()).unwrap();
        assert!(ordered.is_empty(), "FEATURE is off, so the unit is not built");
    }
}

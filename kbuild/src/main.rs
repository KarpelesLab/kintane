//! kbuild — the KinTane build system.
//!
//! Owns configuration resolution, the crate graph, rustc invocation, caching, and
//! running the result. Cargo builds this tool and nothing else in the tree.

mod build;
mod cache;
mod codegen;
mod graph;
mod kcfg;
mod qemu;
mod sha256;
mod toml;
mod toolchain;

use kcfg::resolve::Request;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

const USAGE: &str = "\
kbuild — the KinTane build system

USAGE:
    kbuild <command> [options]

COMMANDS:
    toolchain            verify the pinned toolchain in toolchain.toml
    config               resolve a configuration and write .config
    build                build the kernel image
    run                  build, then boot under QEMU
    clean                remove build outputs (the cache is kept)

OPTIONS:
    --preset <name>      start from config/presets/<name>.preset
    --set SYM=VALUE      override one symbol (repeatable)
    --verbose, -v        show each rustc invocation
    --timeout <secs>     QEMU timeout for `run` (default 30)
";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() || args[0] == "-h" || args[0] == "--help" {
        print!("{USAGE}");
        return ExitCode::SUCCESS;
    }

    match dispatch(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("\x1b[31merror\x1b[0m: {e}");
            ExitCode::FAILURE
        }
    }
}

struct Opts {
    preset: Option<String>,
    sets: Vec<(String, String)>,
    verbose: bool,
    timeout: u64,
}

fn parse_opts(args: &[String]) -> Result<Opts, String> {
    let mut o = Opts {
        preset: None,
        sets: Vec::new(),
        verbose: false,
        timeout: 30,
    };
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--preset" => {
                i += 1;
                o.preset = Some(args.get(i).ok_or("--preset needs a name")?.clone());
            }
            "--set" => {
                i += 1;
                let kv = args.get(i).ok_or("--set needs SYM=VALUE")?;
                let (k, v) = kv.split_once('=').ok_or("--set expects SYM=VALUE")?;
                o.sets.push((k.to_string(), v.to_string()));
            }
            "--timeout" => {
                i += 1;
                o.timeout = args
                    .get(i)
                    .ok_or("--timeout needs seconds")?
                    .parse()
                    .map_err(|_| "--timeout expects a number")?;
            }
            "-v" | "--verbose" => o.verbose = true,
            other => return Err(format!("unknown option `{other}`")),
        }
        i += 1;
    }
    Ok(o)
}

fn dispatch(args: &[String]) -> Result<(), String> {
    let cmd = args[0].as_str();
    let opts = parse_opts(&args[1..])?;
    let root = find_root()?;

    match cmd {
        "toolchain" => {
            let tc = toolchain::verify(&root)?;
            println!("toolchain ok");
            println!("  rustc    {}", tc.rustc.display());
            println!("  release  {}", tc.pin.release);
            println!("  commit   {}", tc.pin.commit_hash);
            println!("  llvm     {}", tc.pin.llvm);
            println!("  baseline rust {} / edition {}", tc.pin.baseline, tc.pin.edition);
            if !tc.pin.features.is_empty() {
                println!("  unstable surface ({}):", tc.pin.features.len());
                for f in &tc.pin.features {
                    println!("    {f}");
                }
            }
            Ok(())
        }
        "config" => {
            let (table, res) = configure(&root, &opts)?;
            let n_on = table.order.iter().filter(|s| res.is_on(s)).count();
            println!(
                "configuration resolved: {} symbols, {} enabled",
                table.order.len(),
                n_on
            );
            println!("  written to {}", root.join(".config").display());
            Ok(())
        }
        "build" => {
            do_build(&root, &opts).map(|_| ())
        }
        "run" => {
            let (image, res) = do_build(&root, &opts)?;
            let log = root.join("build").join(res.str("TARGET")).join("qemu.log");
            let m = qemu::machine_for(&res, &image, &log)?;
            println!("\n\x1b[36mbooting\x1b[0m {} {}\n", m.binary, m.args.join(" "));
            let outcome = qemu::run(&m, opts.timeout).map_err(|e| {
                format!("{e}\n  exception trace: {}", log.display())
            })?;
            println!();
            match outcome.code {
                Some(c) if outcome.passed => {
                    println!("\x1b[32mguest signalled success\x1b[0m (qemu exit {c})");
                    Ok(())
                }
                Some(c) => Err(format!(
                    "guest exited with code {c}, expected {} for success\n  \
                     exception trace: {}",
                    m.success_code,
                    log.display()
                )),
                None => Err("QEMU was terminated by a signal".into()),
            }
        }
        "clean" => {
            let dir = root.join("build");
            if dir.exists() {
                // The cache lives elsewhere and is deliberately preserved.
                for entry in std::fs::read_dir(&dir).map_err(|e| e.to_string())?.flatten() {
                    if entry.file_name() == "cache" {
                        continue;
                    }
                    let p = entry.path();
                    let r = if p.is_dir() {
                        std::fs::remove_dir_all(&p)
                    } else {
                        std::fs::remove_file(&p)
                    };
                    r.map_err(|e| format!("{}: {e}", p.display()))?;
                }
            }
            println!("build outputs removed; cache kept");
            Ok(())
        }
        other => Err(format!("unknown command `{other}`\n\n{USAGE}")),
    }
}

/// Walk up from the current directory to the tree root.
fn find_root() -> Result<PathBuf, String> {
    let mut dir = std::env::current_dir().map_err(|e| e.to_string())?;
    loop {
        if dir.join("toolchain.toml").exists() && dir.join("config").is_dir() {
            return Ok(dir);
        }
        if !dir.pop() {
            return Err("not inside a KinTane tree (no toolchain.toml found)".into());
        }
    }
}

fn configure(root: &Path, opts: &Opts) -> Result<(kcfg::SymbolTable, kcfg::Resolution), String> {
    let entry = root.join("config/main.kcfg");
    let table = kcfg::parse::parse_tree(&entry).map_err(|e| e.to_string())?;

    let mut requests: Vec<Request> = Vec::new();
    if let Some(p) = &opts.preset {
        let path = root.join("config/presets").join(format!("{p}.preset"));
        if !path.exists() {
            let avail = list_presets(root).join(", ");
            return Err(format!(
                "no preset `{p}`\n  available: {avail}"
            ));
        }
        for (k, v) in codegen::read_settings(&path)? {
            requests.push(Request {
                symbol: k,
                text: v,
                source: format!("preset {p}"),
            });
        }
    }
    for (k, v) in &opts.sets {
        requests.retain(|r| &r.symbol != k);
        requests.push(Request {
            symbol: k.clone(),
            text: v.clone(),
            source: "--set".into(),
        });
    }

    let res = kcfg::resolve::resolve(&table, &requests).map_err(|errs| {
        errs.iter()
            .map(|e| e.to_string())
            .collect::<Vec<_>>()
            .join("\n")
    })?;

    codegen::write_dotconfig(&table, &res, &root.join(".config"))?;
    Ok((table, res))
}

fn list_presets(root: &Path) -> Vec<String> {
    std::fs::read_dir(root.join("config/presets"))
        .map(|d| {
            d.flatten()
                .filter_map(|e| {
                    e.path()
                        .file_stem()
                        .and_then(|s| s.to_str())
                        .map(String::from)
                })
                .collect()
        })
        .unwrap_or_default()
}

fn do_build(root: &Path, opts: &Opts) -> Result<(PathBuf, kcfg::Resolution), String> {
    let tc = toolchain::verify(root)?;
    let (table, res) = configure(root, opts)?;

    let target_name = res.str("TARGET").to_string();
    if target_name.is_empty() {
        return Err("configuration does not select a target (TARGET is empty)".into());
    }
    let target_json = root.join("targets").join(format!("{target_name}.json"));
    if !target_json.exists() {
        return Err(format!(
            "missing target specification {}",
            target_json.display()
        ));
    }

    let build_dir = root.join("build").join(&target_name);
    let out = build_dir.join("out");
    let gen_dir = build_dir.join("gen");
    std::fs::create_dir_all(&out).map_err(|e| format!("{}: {e}", out.display()))?;

    let generated = codegen::emit(&table, &res, &gen_dir)?;

    let b = build::Build {
        root: root.to_path_buf(),
        tc,
        target_name: target_name.clone(),
        target_json,
        out: out.clone(),
        gen_dir,
        cache: cache::Cache::new(root.join("build/cache"))?,
        cfgs: generated.cfgs,
        check_cfgs: generated.check_cfgs,
        opt_level: if res.is_on("DEBUG_BUILD") { "1".into() } else { "2".into() },
        link_script: {
            let s = res.str("LINKER_SCRIPT");
            (!s.is_empty()).then(|| root.join(s))
        },
        verbose: opts.verbose,
    };

    println!("\x1b[36mbuilding\x1b[0m {target_name}");

    let units = graph::discover(root)?;
    let ordered = graph::plan(units, &res)?;
    if ordered.is_empty() {
        return Err("no units are enabled in this configuration".into());
    }

    // Bootstrap order is fixed and not a topological question: core comes from the
    // toolchain's own source; compiler_builtins resolves the calls the code
    // generator emits, so every no_std crate needs it — including the generated
    // config crate; and kconfig must exist before any unit that reads its constants.
    let mut built: BTreeMap<String, build::Built> = BTreeMap::new();
    let core = b.build_core()?;
    built.insert("core".into(), core);

    let cb = ordered
        .iter()
        .find(|u| u.name == "compiler_builtins")
        .ok_or("no compiler_builtins unit in this configuration")?;
    let cb_built = b.build_unit(cb, &built)?;
    built.insert(cb.name.clone(), cb_built);

    let kconfig = b.build_kconfig(&built["core"], &built["compiler_builtins"])?;
    built.insert("kconfig".into(), kconfig);

    let mut image = None;
    for unit in &ordered {
        if built.contains_key(&unit.name) {
            continue;
        }
        let b2 = b.build_unit(unit, &built)?;
        if unit.kind == graph::Kind::Bin {
            image = Some(b2.path.clone());
        }
        built.insert(unit.name.clone(), b2);
    }

    println!(
        "  {} units, {} cached, {} compiled",
        ordered.len() + 2,
        b.cache.hits.get(),
        b.cache.misses.get()
    );

    let linked = image.ok_or("no unit of kind `bin` was built; nothing to boot")?;
    let image = b.package(res.str("IMAGE_FORMAT"), &linked)?;
    let size = std::fs::metadata(&image).map(|m| m.len()).unwrap_or(0);
    if image != linked {
        println!("  linked {}", linked.display());
    }
    println!("  image  {} ({} bytes)", image.display(), size);
    Ok((image, res))
}

//! kbuild — the KinTane build system.
//!
//! Owns configuration resolution, the crate graph, rustc invocation, caching, and
//! running the result. Cargo builds this tool and nothing else in the tree.

mod bios;
mod bootcfg;
mod build;
mod buildid;
mod cache;
mod codegen;
mod dwarf;
mod esp;
mod fat16;
mod fuzz;
mod graph;
mod hosttest;
mod kcfg;
mod lint;
mod menuconfig;
mod modules;
mod portable;
mod qemu;
mod qemu_armv7m;
mod randconfig;
mod sha256;
mod size;
mod stress;
mod symbolize;
mod testdisk;
mod toml;
mod toolchain;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use kcfg::resolve::Request;

const USAGE: &str = "\
kbuild — the KinTane build system

USAGE:
    kbuild <command> [options]

COMMANDS:
    toolchain            verify the pinned toolchain in toolchain.toml
    config               resolve a configuration and write .config
    menuconfig           edit a configuration interactively; saves .config and
                         menuconfig.preset
    build                build the kernel image
    randconfig-build     build --count random configurations from --seed, and
                         report each failure with the command that reproduces it
    size                 build, then report section and per-crate sizes against
                         the preset's SIZE_BUDGET_KIB and the size baseline
    test [--host|--target]
                         run tests: on the host against the mocks (default),
                         or in-kernel under QEMU on the real architecture
    lint                 check the in-tree rules rustc cannot express
    portability          compile the hardware-independent units for machines
                         without a port yet (no atomics, no 64-bit atomics, no MMU)
    fuzz [--target T]    fuzz the parsers that read untrusted input; every target
                         when none is named. --smoke replays the committed corpus
    run                  build, then boot under QEMU
    modules              build the kernel and its loadable modules, and the bundle
                         that carries them to it
    sdk                  build, then write the module SDK for this kernel build to
                         build/<target>/sdk
    stress --duration <len>
                         build a stress image and run it for <len> of guest time
                         (e.g. 90s, 10m, 24h), failing if its heartbeat stops
    symbolize [log]      decode the backtrace in a guest console log against the
                         symbol bundle (default: the last `run` or `test --target`)
    clean                remove build outputs (the cache is kept)

OPTIONS:
    --preset <name>      start from config/presets/<name>.preset, or a preset file
                         when <name> is a path (contains `/`)
    --set SYM=VALUE      override one symbol (repeatable)
    --random [--seed N]  extend the configuration randomly; any command. The same
                         seed and preset give the same configuration everywhere
    --allyes, --allno    extend it to everything on, or everything off, that can be
    --count K            `randconfig-build`: how many configurations (default 20)
    --iterations K       `fuzz`: inputs per target (default 1000)
    --corpus DIR         `fuzz`: where seeds and failures live
    --file PATH          `fuzz`: run one input and stop, to reproduce a failure
    --smoke              `fuzz`: replay the committed corpus and stop
    --compare REF|FILE   `size`: baseline to compare with (default: the committed one)
    --save FILE          `size`: also write the report to FILE
    --update-baseline    `size`: rewrite config/size-baseline/<preset>.size
    --verbose, -v        show each rustc invocation
    --timeout <secs>     QEMU timeout for `run` (default 30)
    --only <name>        `test`: only units whose name contains <name>
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

#[derive(Clone)]
struct Opts {
    in_kernel: bool,
    only: Option<String>,
    preset: Option<String>,
    sets: Vec<(String, String)>,
    verbose: bool,
    timeout: u64,
    /// Arguments that are not options. Only `symbolize` takes one.
    positional: Vec<String>,
    /// `--random`, `--allyes` or `--allno`: how to extend the configuration.
    generate: Option<kcfg::random::Mode>,
    /// `--count` and `--seed`, for `randconfig-build`, which derives one seed per
    /// configuration from `--seed`.
    count: u64,
    seed: Option<u64>,
    /// `--compare`, `--save` and `--update-baseline`, for `size`.
    compare: Option<String>,
    save: Option<String>,
    update_baseline: bool,
    /// `stress`: seconds of guest time to run for.
    duration: Option<u64>,
    /// `sdk`: write the module SDK after building.
    sdk: bool,
    /// `fuzz`: which target, how many inputs, where the corpus is, and whether to replay
    /// it rather than generate anything.
    target: Option<String>,
    iterations: u64,
    corpus: Option<String>,
    file: Option<String>,
    smoke: bool,
}

fn parse_opts(args: &[String]) -> Result<Opts, String> {
    let mut o = Opts {
        in_kernel: false,
        only: None,
        preset: None,
        sets: Vec::new(),
        verbose: false,
        timeout: 30,
        positional: Vec::new(),
        generate: None,
        count: 20,
        seed: None,
        compare: None,
        save: None,
        update_baseline: false,
        duration: None,
        sdk: false,
        target: None,
        iterations: 1000,
        corpus: None,
        file: None,
        smoke: false,
    };
    let mut random = false;
    let mut seed: Option<u64> = None;
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
            "--duration" => {
                i += 1;
                let d = args.get(i).ok_or("--duration needs a length, e.g. 10m")?;
                o.duration = Some(stress::parse_duration(d)?);
            }
            "--only" => {
                i += 1;
                o.only = Some(args.get(i).ok_or("--only needs a name")?.clone());
            }
            "--host" => o.in_kernel = false,
            // `test --target` takes no value; `fuzz --target NAME` does. One flag, told
            // apart by whether a name follows it, so neither command grows a second
            // spelling of "which".
            "--target" => match args.get(i + 1) {
                Some(name) if !name.starts_with('-') => {
                    o.target = Some(name.clone());
                    i += 1;
                }
                _ => o.in_kernel = true,
            },
            "-v" | "--verbose" => o.verbose = true,
            "--random" => random = true,
            "--seed" => {
                i += 1;
                let s = args.get(i).ok_or("--seed needs a number")?;
                seed = Some(
                    s.parse()
                        .map_err(|_| format!("--seed expects a number, got `{s}`"))?,
                );
            }
            "--allyes" => o.generate = Some(kcfg::random::Mode::AllYes),
            "--allno" => o.generate = Some(kcfg::random::Mode::AllNo),
            "--count" => {
                i += 1;
                let s = args.get(i).ok_or("--count needs a number")?;
                o.count = s
                    .parse()
                    .map_err(|_| format!("--count expects a number, got `{s}`"))?;
            }
            "--compare" => {
                i += 1;
                o.compare = Some(args.get(i).ok_or("--compare needs a ref or file")?.clone());
            }
            "--save" => {
                i += 1;
                o.save = Some(args.get(i).ok_or("--save needs a file")?.clone());
            }
            "--update-baseline" => o.update_baseline = true,
            "--iterations" => {
                i += 1;
                let v = args.get(i).ok_or("--iterations needs a number")?;
                o.iterations = v
                    .parse()
                    .map_err(|_| format!("--iterations expects a number, got `{v}`"))?;
            }
            "--corpus" => {
                i += 1;
                o.corpus = Some(args.get(i).ok_or("--corpus needs a directory")?.clone());
            }
            "--file" => {
                i += 1;
                o.file = Some(args.get(i).ok_or("--file needs a path")?.clone());
            }
            "--smoke" => o.smoke = true,
            other if !other.starts_with('-') => o.positional.push(other.to_string()),
            other => return Err(format!("unknown option `{other}`")),
        }
        i += 1;
    }
    o.seed = seed;
    if random {
        if o.generate.is_some() {
            return Err("--random, --allyes and --allno are alternatives; give one".into());
        }
        o.generate = Some(kcfg::random::Mode::Random(seed.unwrap_or_else(randconfig::fresh_seed)));
    }
    Ok(o)
}

fn dispatch(args: &[String]) -> Result<(), String> {
    let cmd = args[0].as_str();
    let opts = parse_opts(&args[1..])?;
    if cmd != "symbolize" {
        if let Some(p) = opts.positional.first() {
            return Err(format!("unexpected argument `{p}`"));
        }
    }
    if opts.seed.is_some() && opts.generate.is_none() && cmd != "randconfig-build" && cmd != "fuzz"
    {
        return Err("--seed goes with --random (or with `randconfig-build`)".into());
    }
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
            println!("configuration resolved: {} symbols, {} enabled", table.order.len(), n_on);
            println!("  written to {}", root.join(".config").display());
            Ok(())
        }
        "build" | "modules" => do_build(&root, &opts).map(|_| ()),
        "sdk" => {
            let mut sopts = opts.clone();
            sopts.sdk = true;
            do_build(&root, &sopts).map(|_| ())
        }
        "menuconfig" => menuconfig::run(&root, &opts),
        "randconfig-build" => randconfig::run(&root, &opts),
        "size" => size::run(&root, &opts),
        "test" if opts.in_kernel => {
            // A test image: the real selftest provider is linked in, and the guest's
            // exit status is the verdict. Console output is for a human reading a
            // failure, never for the harness to parse.
            let mut topts = opts.clone();
            topts.sets.push(("QEMU_EXIT".into(), "y".into()));
            topts.sets.push(("INKERNEL_TESTS".into(), "y".into()));
            let (image, res) = do_build(&root, &topts)?;
            let log = root.join("build").join(res.str("TARGET")).join("qemu.log");
            let m = qemu::machine_for(&res, &image, &log)?;
            let outcome = boot(&root, &res, &m, opts.timeout, None)?;
            match outcome.code {
                Some(c) if outcome.passed => {
                    println!("\n\x1b[32min-kernel tests passed\x1b[0m (qemu exit {c})");
                    Ok(())
                }
                Some(c) => Err(format!(
                    "in-kernel tests failed: guest exited {c}, expected {}\n  \
                     the failing checks are in the console output above",
                    m.success_code
                )),
                None => Err("QEMU was terminated by a signal".into()),
            }
        }
        "test" => {
            let tc = toolchain::verify(&root)?;
            // Host tests exist to run against the mocks, so the mock architectures
            // are compiled in regardless of what the preset says.
            let mut topts = opts.clone();
            topts.sets.push(("MOCK_ARCH".into(), "y".into()));
            let (table, res) = configure(&root, &topts)?;
            let identity = codegen::identity_text(&table, &res, &tc.identity(), "host");
            let generated = codegen::emit(&table, &res, &root.join("build/host/gen"), &identity)?;
            let ordered = graph::plan(graph::discover(&root)?, &res)?;
            let s = hosttest::run(
                &root,
                &tc,
                &generated,
                &ordered,
                opts.only.as_deref(),
                opts.verbose,
            )?;
            println!(
                "\n{} unit(s): \x1b[32m{} passed\x1b[0m, {} failed",
                s.units, s.passed, s.failed
            );
            if s.failed > 0 {
                return Err(format!("{} unit(s) had failing tests", s.failed));
            }
            Ok(())
        }
        "fuzz" => {
            let tc = toolchain::verify(&root)?;
            // The mocks, as `test` does: the harness links the same units its tests do.
            let mut fopts = opts.clone();
            fopts.sets.push(("MOCK_ARCH".into(), "y".into()));
            let (table, res) = configure(&root, &fopts)?;
            let identity = codegen::identity_text(&table, &res, &tc.identity(), "host");
            let generated = codegen::emit(&table, &res, &root.join("build/host/gen"), &identity)?;
            let ordered = graph::plan(graph::discover(&root)?, &res)?;
            fuzz::run(
                &root,
                &tc,
                &generated,
                &ordered,
                &fuzz::Run {
                    target: opts.target.clone(),
                    seed: opts.seed,
                    iterations: opts.iterations,
                    smoke: opts.smoke,
                    file: opts.file.clone(),
                    corpus: opts.corpus.clone(),
                },
                opts.verbose,
            )
        }
        "run" => {
            let (image, res) = do_build(&root, &opts)?;
            let log = root.join("build").join(res.str("TARGET")).join("qemu.log");
            let m = qemu::machine_for(&res, &image, &log)?;
            println!("\n\x1b[36mbooting\x1b[0m {} {}\n", m.binary, m.args.join(" "));
            let outcome = boot(&root, &res, &m, opts.timeout, None)
                .map_err(|e| format!("{e}\n  exception trace: {}", log.display()))?;
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
        "stress" => {
            let seconds = opts
                .duration
                .ok_or("stress needs --duration, e.g. --duration 10m")?;
            let mut sopts = opts.clone();
            sopts.sets.push(("QEMU_EXIT".into(), "y".into()));
            sopts.sets.push(("STRESS_TEST".into(), "y".into()));
            sopts
                .sets
                .push(("STRESS_SECONDS".into(), seconds.to_string()));
            let (image, res) = do_build(&root, &sopts)?;
            let log = root.join("build").join(res.str("TARGET")).join("qemu.log");
            let m = stress::quiet(qemu::machine_for(&res, &image, &log)?);
            println!("\n\x1b[36mstress\x1b[0m {seconds}s: {} {}\n", m.binary, m.args.join(" "));
            let outcome = boot(&root, &res, &m, stress::timeout(seconds), Some(stress::watch()))?;
            match outcome.code {
                Some(c) if outcome.passed => {
                    println!("\n\x1b[32mstress passed\x1b[0m (qemu exit {c})");
                    Ok(())
                }
                Some(c) => Err(format!(
                    "stress failed: guest exited {c}, expected {}\n  \
                     the failed audit is in the console output above",
                    m.success_code
                )),
                None => Err("QEMU was terminated by a signal".into()),
            }
        }
        "symbolize" => {
            let (_, res) = resolve_config(&root, &opts)?;
            let dir = root.join("build").join(res.str("TARGET"));
            let log = match opts.positional.as_slice() {
                [] => dir.join("console.log"),
                [one] => PathBuf::from(one),
                _ => return Err("symbolize takes one log file".into()),
            };
            let text = std::fs::read(&log).map_err(|e| format!("{}: {e}", log.display()))?;
            let bundle = find_symbol_bundle(&dir.join("out"))?;
            let tc = toolchain::verify(&root)?;
            let n =
                symbolize::report(&String::from_utf8_lossy(&text), &bundle, &tc.tool("llvm-nm")?)?;
            if n == 0 {
                return Err(format!("no backtrace lines (`bt ...`) in {}", log.display()));
            }
            Ok(())
        }
        "lint" => {
            let violations = lint::check_tree(&root)?;
            if violations.is_empty() {
                println!("lint ok: no `cfg` inside a function body or a type's fields");
                return Ok(());
            }
            for v in &violations {
                eprintln!("{v}\n");
            }
            Err(format!("{} cfg-in-body violation(s)", violations.len()))
        }
        "portability" => {
            let tc = toolchain::verify(&root)?;
            let mut failed = 0;
            for machine in portable::MACHINES {
                println!("\n\x1b[36m{}\x1b[0m  {}", machine.triple, machine.why);
                let mut mopts = opts.clone();
                for (k, v) in machine.config {
                    mopts.sets.push((k.to_string(), v.to_string()));
                }
                let (table, res) = resolve_config(&root, &mopts)?;
                let r = portable::check(&root, tc.clone(), machine, &table, &res, opts.verbose)?;
                for (unit, why) in &r.broken {
                    eprintln!("  \x1b[31m{unit} does not build\x1b[0m: {why}\n");
                }
                println!("  {} of {} units build", r.checked - r.broken.len(), r.checked);
                failed += r.broken.len();
            }
            // The units above are the host-testable ones, which is where this check began and
            // what it could reach with built-in targets. The image that links them into a
            // kernel for a core with no atomics is not among them, and `kernel/main` is where
            // unguarded read-modify-writes most recently hid: it had never been compiled for
            // such a core until the rv32i port tried. So the whole rv32i image is built too.
            // `do_build` records its configuration in `.config`, which this check must not
            // leave pointing at a machine nobody selected, so the file is put back after.
            println!(
                "\n\x1b[36mriscv32i-virt\x1b[0m  the whole kernel image, for a core with no atomics"
            );
            let dotconfig = root.join(".config");
            let saved = std::fs::read(&dotconfig).ok();
            let mut iopts = opts.clone();
            iopts.preset = Some("riscv32i-virt".into());
            let built = do_build(&root, &iopts);
            match &saved {
                Some(bytes) => std::fs::write(&dotconfig, bytes)
                    .map_err(|e| format!("{}: {e}", dotconfig.display()))?,
                None => {
                    let _ = std::fs::remove_file(&dotconfig);
                }
            }
            match built {
                Ok(_) => println!("  kernel image builds"),
                Err(e) => {
                    eprintln!("  \x1b[31mkernel image does not build\x1b[0m: {e}\n");
                    failed += 1;
                }
            }
            if failed > 0 {
                return Err(format!("{failed} build(s) failed the portability check"));
            }
            println!("\nportability ok");
            Ok(())
        }
        "clean" => {
            let dir = root.join("build");
            if dir.exists() {
                // The cache lives elsewhere and is deliberately preserved.
                for entry in std::fs::read_dir(&dir)
                    .map_err(|e| e.to_string())?
                    .flatten()
                {
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

/// Build an image for a target of its own — a bootloader — next to the kernel.
///
/// It gets a build of its own: `core`, `compiler_builtins` and the generated config
/// compiled for its triple, then its dependencies, then itself, all under
/// `build/<kernel target>/<triple>/`. Sharing nothing compiled with the kernel is the
/// point, not a cost: the kernel's `boot_protocol` rlib is for a different target and
/// could not be linked here anyway. The cache keys include the triple, so switching
/// between the two never serves one target's artifact to the other.
fn build_foreign_image(
    kernel: &build::Build,
    unit: &graph::Unit,
    ordered: &[graph::Unit],
) -> Result<PathBuf, String> {
    let triple = unit.target.clone().unwrap_or_default();
    let out = kernel.out.parent().unwrap_or(&kernel.out).join(&triple);
    std::fs::create_dir_all(&out).map_err(|e| format!("{}: {e}", out.display()))?;
    let b = build::Build {
        root: kernel.root.clone(),
        tc: kernel.tc.clone(),
        target_name: triple.clone(),
        target: build::Target::Builtin(triple.clone()),
        out,
        gen_dir: kernel.gen_dir.clone(),
        cache: cache::Cache::new(kernel.root.join("build/cache"))?,
        cfgs: kernel.cfgs.clone(),
        check_cfgs: kernel.check_cfgs.clone(),
        opt_level: kernel.opt_level.clone(),
        link_script: None,
        deny_warnings: false,
        bitcode: false,
        verbose: kernel.verbose,
    };
    println!("\x1b[36mbuilding\x1b[0m {} for {triple}", unit.name);

    let mut built: BTreeMap<String, build::Built> = BTreeMap::new();
    built.insert("core".into(), b.build_core()?);
    let cb = ordered
        .iter()
        .find(|u| u.name == "compiler_builtins")
        .ok_or("no compiler_builtins unit in this configuration")?;
    built.insert(cb.name.clone(), b.build_unit(cb, &built)?);
    let kconfig = b.build_kconfig(&built["core"], &built["compiler_builtins"])?;
    built.insert("kconfig".into(), kconfig);

    let mut needed = Vec::new();
    hosttest::collect_deps(unit, ordered, &mut needed);
    let mut image = None;
    for u in needed {
        if built.contains_key(&u.name) {
            continue;
        }
        let artifact = b.build_unit(u, &built)?;
        if u.name == unit.name {
            image = Some(artifact.path.clone());
        }
        built.insert(u.name.clone(), artifact);
    }
    let image = image.ok_or_else(|| format!("{} was not built", unit.name))?;
    reject_trap_stubs(&image)?;
    let size = std::fs::metadata(&image).map(|m| m.len()).unwrap_or(0);
    println!("  loader  {} ({size} bytes)", image.display());
    Ok(image)
}

/// Refuse a UEFI image that still contains one of `lib/builtins`' trap stubs.
///
/// Those stubs exist only to satisfy lld-link, which demands every symbol in every object
/// it reads, and the linker discards them with the dead code that named them. One that
/// survives is reachable, and would trap the first time the loader ran that path. The
/// marker is the string each stub carries after its trapping instruction; see
/// `lib/builtins/src/uefi_link.rs`.
fn reject_trap_stubs(image: &Path) -> Result<(), String> {
    const MARKER: &[u8] = b"KBUILD-UNREACHABLE-INTRINSIC";
    let bytes = std::fs::read(image).map_err(|e| format!("{}: {e}", image.display()))?;
    if bytes.windows(MARKER.len()).any(|w| w == MARKER) {
        return Err(format!(
            "{} calls a compiler intrinsic that lib/builtins only stubs out\n  \
             the stub traps; implement the intrinsic in lib/builtins, or stop using what \
             needs it (see lib/builtins/src/uefi_link.rs)",
            image.display()
        ));
    }
    Ok(())
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
    let (table, res) = resolve_config(root, opts)?;
    codegen::write_dotconfig(&table, &res, &root.join(".config"))?;
    Ok((table, res))
}

/// Resolve a configuration without recording it in `.config` — for commands that build
/// configurations nobody asked to keep, so a portability check does not leave the tree
/// configured for a machine the user never selected.
fn resolve_config(
    root: &Path,
    opts: &Opts,
) -> Result<(kcfg::SymbolTable, kcfg::Resolution), String> {
    let (table, requests) = base_requests(root, opts)?;
    let describe = |errs: Vec<kcfg::resolve::ResolveError>| {
        errs.iter()
            .map(|e| e.to_string())
            .collect::<Vec<_>>()
            .join("\n")
    };

    let Some(mode) = opts.generate else {
        let res = kcfg::resolve::resolve(&table, &requests).map_err(describe)?;
        return Ok((table, res));
    };
    let (res, all) = kcfg::random::generate(&table, &requests, mode).map_err(describe)?;
    let generated: Vec<String> = all[requests.len()..]
        .iter()
        .map(|r| format!("{}={}", r.symbol, r.text))
        .collect();
    println!(
        "\x1b[36mgenerated\x1b[0m {} ({} requests): {}",
        mode.source(),
        generated.len(),
        generated.join(" ")
    );
    Ok((table, res))
}

/// The symbol table, and the requests the options make before anything is generated:
/// the preset, then `--set`.
fn base_requests(root: &Path, opts: &Opts) -> Result<(kcfg::SymbolTable, Vec<Request>), String> {
    let entry = root.join("config/main.kcfg");
    let table = kcfg::parse::parse_tree(&entry).map_err(|e| e.to_string())?;

    let mut requests: Vec<Request> = Vec::new();
    if let Some(p) = &opts.preset {
        // A name is one of config/presets; a path is a preset file somewhere else, such
        // as the one `menuconfig` saves.
        let path = if p.contains('/') {
            PathBuf::from(p)
        } else {
            root.join("config/presets").join(format!("{p}.preset"))
        };
        if !path.exists() {
            let avail = list_presets(root).join(", ");
            return Err(format!("no preset `{p}`\n  available: {avail}"));
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
    Ok((table, requests))
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

/// Boot under QEMU, keep the console, and decode any backtrace the guest printed.
///
/// The console goes to `build/<target>/console.log`, which is what `kbuild symbolize`
/// reads by default. Decoding is a convenience for whoever reads the failure: if it
/// cannot be done, that is said and the verdict is unchanged.
fn boot(
    root: &Path,
    res: &kcfg::Resolution,
    m: &qemu::Machine,
    timeout: u64,
    watch: Option<qemu::Watch>,
) -> Result<qemu::Outcome, String> {
    let dir = root.join("build").join(res.str("TARGET"));
    let outcome = qemu::run_watched(m, timeout, watch)?;
    let console = dir.join("console.log");
    std::fs::write(&console, &outcome.console)
        .map_err(|e| format!("{}: {e}", console.display()))?;

    let text = String::from_utf8_lossy(&outcome.console);
    if !symbolize::entries(&text).is_empty() {
        let decoded = toolchain::verify(root).and_then(|tc| {
            let bundle = find_symbol_bundle(&dir.join("out"))?;
            symbolize::report(&text, &bundle, &tc.tool("llvm-nm")?)
        });
        if let Err(e) = decoded {
            eprintln!("\n\x1b[33mbacktrace not decoded\x1b[0m: {e}");
        }
    }

    if let Some(why) = &outcome.hung {
        return Err(format!("killed by the heartbeat watchdog: {why}"));
    }
    if outcome.timed_out {
        return Err(format!("timed out after {timeout}s with no exit signal from the guest"));
    }
    Ok(outcome)
}

/// The one symbol bundle a build directory holds.
fn find_symbol_bundle(out: &Path) -> Result<PathBuf, String> {
    let found: Vec<PathBuf> = std::fs::read_dir(out)
        .map_err(|e| format!("{}: {e} (has this configuration been built?)", out.display()))?
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "debug"))
        .collect();
    match found.as_slice() {
        [one] => Ok(one.clone()),
        [] => Err(format!("no symbol bundle (*.debug) in {}", out.display())),
        _ => Err(format!("more than one symbol bundle in {}", out.display())),
    }
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
        return Err(format!("missing target specification {}", target_json.display()));
    }

    let build_dir = root.join("build").join(&target_name);
    let out = build_dir.join("out");
    let gen_dir = build_dir.join("gen");
    std::fs::create_dir_all(&out).map_err(|e| format!("{}: {e}", out.display()))?;

    let identity = codegen::identity_text(
        &table,
        &res,
        &tc.identity(),
        &sha256::hex(&sha256::digest(
            &std::fs::read(&target_json).map_err(|e| format!("{}: {e}", target_json.display()))?,
        )),
    );
    let generated = codegen::emit(&table, &res, &gen_dir, &identity)?;

    let b = build::Build {
        root: root.to_path_buf(),
        tc,
        target_name: target_name.clone(),
        target: build::Target::Spec(target_json),
        out: out.clone(),
        gen_dir,
        cache: cache::Cache::new(root.join("build/cache"))?,
        cfgs: generated.cfgs,
        check_cfgs: generated.check_cfgs,
        opt_level: if res.is_on("OPTIMIZE_FOR_SIZE") {
            "z".into()
        } else if res.is_on("DEBUG_BUILD") {
            "1".into()
        } else {
            "2".into()
        },
        link_script: {
            let s = res.str("LINKER_SCRIPT");
            (!s.is_empty()).then(|| root.join(s))
        },
        deny_warnings: false,
        bitcode: false,
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
        // Units with a target of their own are separate images, and modules are built
        // against the finished configuration afterwards; both below.
        if built.contains_key(&unit.name)
            || unit.target.is_some()
            || unit.kind == graph::Kind::Module
        {
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

    // Each image built for a target of its own, by unit name. The image format decides
    // where each goes, and refuses one it has no place for.
    let mut images: Vec<(String, PathBuf)> = Vec::new();
    for unit in ordered.iter().filter(|u| u.target.is_some()) {
        images.push((unit.name.clone(), build_foreign_image(&b, unit, &ordered)?));
    }

    let linked = image.ok_or("no unit of kind `bin` was built; nothing to boot")?;
    let symbols = b.split_symbols(&linked)?;
    let build_id = buildid::stamp(&b.tc.tool("llvm-objcopy")?, &linked, &symbols)?;
    let entries = bootcfg::entry_list(&res, bootcfg::Chain::File(build::ESP_CHAIN_TEST_ENTRY_PATH));
    let image = b.package(res.str("IMAGE_FORMAT"), &linked, &images, &entries)?;
    // A BIOS disk wraps the packaged image rather than replacing it: the kernel on the
    // disk is byte for byte the one `-kernel` boots.
    let image = if res.is_on(bios::SYMBOL) {
        bios::disk_image(root, b.tc.clone(), &res, &image, opts.verbose)?
    } else {
        image
    };
    // The disk a test build's virtio-blk device reads, beside the image QEMU boots. Its
    // volume carries the user program when this configuration links one, so the kernel can
    // load a program from a disk rather than only from its own image. `userinit` is a
    // provider name: only the real program has a path to embed, and the empty provider a
    // configuration without userspace selects has none.
    if res.is_on(testdisk::SYMBOL) {
        let program = built
            .get("userinit")
            .filter(|b| b.embed.is_some())
            .map(|b| b.path.clone());
        testdisk::write(image.parent().unwrap_or(Path::new(".")), program.as_deref())?;
    }
    // A module asking for another configuration gets this one with its overrides on top.
    // A `--set` the overridden configuration cannot honour is dropped for that build only:
    // `LOCKDEP_ABBA_TEST=y` needs the lock checking a module built for `DEBUG_BUILD=n` does
    // not have. The module still differs from the kernel at the symbol it overrode.
    let resolve = |extra: &[(String, String)]| {
        let mut o = opts.clone();
        o.sets.extend(extra.iter().cloned());
        loop {
            match resolve_config(root, &o) {
                Ok(r) => return Ok(r),
                Err(e) => {
                    let refused = o.sets.iter().position(|(k, v)| {
                        !extra.iter().any(|(ek, _)| ek == k)
                            && e.contains(&format!("cannot set {k}={v}"))
                    });
                    match refused {
                        Some(i) => {
                            o.sets.remove(i);
                        }
                        None => return Err(e),
                    }
                }
            }
        }
    };
    let target_json = root.join("targets").join(format!("{target_name}.json"));
    modules::build_all(&b, &table, &res, &target_json, &ordered, &resolve)?;
    if opts.sdk {
        let dest = root.join("build").join(&target_name).join("sdk");
        modules::write_sdk(&b, &table, &res, &target_json, &ordered, &dest)?;
    }
    let size = std::fs::metadata(&image).map(|m| m.len()).unwrap_or(0);
    println!("  linked  {}", linked.display());
    println!("  symbols {}", symbols.display());
    println!("  build   {build_id}");
    println!("  image   {} ({} bytes)", image.display(), size);
    Ok((image, res))
}

#[cfg(test)]
mod tests {
    use super::parse_opts;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    // `--target` is two options told apart by what follows: alone it asks `test` for the
    // in-kernel suite, as it always has; with a name it names a `fuzz` target. These pin
    // that the older meaning did not change when the newer one arrived.
    #[test]
    fn a_bare_target_flag_still_means_the_in_kernel_suite() {
        let o = parse_opts(&args(&["--target", "--preset", "x86_64-qemu"])).unwrap();
        assert!(o.in_kernel);
        assert!(o.target.is_none());
        assert_eq!(o.preset.as_deref(), Some("x86_64-qemu"));

        let o = parse_opts(&args(&["--target"])).unwrap();
        assert!(o.in_kernel);
        assert!(o.target.is_none());
    }

    #[test]
    fn a_target_followed_by_a_name_names_a_fuzz_target() {
        let o = parse_opts(&args(&["--target", "fdt", "--iterations", "50"])).unwrap();
        assert!(!o.in_kernel, "naming a target is not asking for in-kernel tests");
        assert_eq!(o.target.as_deref(), Some("fdt"));
        assert_eq!(o.iterations, 50);
    }

    #[test]
    fn fuzz_options_parse_and_have_defaults() {
        let o = parse_opts(&args(&["--smoke", "--corpus", "c", "--file", "f"])).unwrap();
        assert!(o.smoke);
        assert_eq!(o.corpus.as_deref(), Some("c"));
        assert_eq!(o.file.as_deref(), Some("f"));
        assert_eq!(parse_opts(&[]).unwrap().iterations, 1000);
        assert!(parse_opts(&args(&["--iterations", "lots"])).is_err());
        assert!(parse_opts(&args(&["--corpus"])).is_err());
    }
}

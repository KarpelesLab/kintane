//! The rustc driver.
//!
//! `kbuild` invokes `rustc` directly, one process per unit, with an explicit
//! `--extern` for every dependency. Nothing is visible to a crate that was not
//! declared. Note that `-Z build-std` never appears: that is a *cargo* feature, and
//! since we call rustc ourselves, compiling `core` is simply compiling a crate.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::cache::{Cache, KeyBuilder};
use crate::graph::{Kind, Unit};
use crate::toolchain::Toolchain;

pub struct Build {
    pub root: PathBuf,
    pub tc: Toolchain,
    #[allow(dead_code)] // carried for diagnostics and future per-target logic
    pub target_name: String,
    pub target_json: PathBuf,
    pub out: PathBuf,
    pub gen_dir: PathBuf,
    pub cache: Cache,
    pub cfgs: Vec<String>,
    pub check_cfgs: Vec<String>,
    pub opt_level: String,
    /// Linker script for `bin` units, from the configuration rather than hardcoded
    /// in a manifest, so the generic kernel unit never names an architecture.
    pub link_script: Option<PathBuf>,
    pub verbose: bool,
}

/// Where a built unit's artifact ended up, and the cache key that produced it.
pub struct Built {
    pub path: PathBuf,
    pub key: String,
}

impl Build {
    /// Flags shared by every kernel crate. Deliberately explicit: reproducibility
    /// depends on nothing being inherited from the environment.
    fn common(&self) -> Vec<String> {
        let mut a: Vec<String> = vec![
            "--edition".into(),
            "2024".into(),
            "-Z".into(),
            "unstable-options".into(),
            "--target".into(),
            self.target_json.display().to_string(),
            "-C".into(),
            "panic=abort".into(),
            "-C".into(),
            format!("opt-level={}", self.opt_level),
            "-C".into(),
            "debuginfo=2".into(),
            "-C".into(),
            "force-frame-pointers=yes".into(),
            "-C".into(),
            "embed-bitcode=no".into(),
        ];
        // No build directory in the binary: same source must produce the same bytes
        // on any machine. See docs/build-system.md#reproducibility.
        a.push("--remap-path-prefix".into());
        a.push(format!("{}=/kintane", self.root.display()));
        a.push("--remap-path-prefix".into());
        a.push(format!("{}=/rust", self.tc.sysroot.display()));
        a
    }

    fn run(&self, args: &[String], what: &str) -> Result<(), String> {
        if self.verbose {
            eprintln!("    rustc {}", args.join(" "));
        }
        let out = Command::new(&self.tc.rustc)
            .args(args)
            // SOURCE_DATE_EPOCH comes from the commit, never the clock.
            .env("SOURCE_DATE_EPOCH", "0")
            .output()
            .map_err(|e| format!("cannot run rustc: {e}"))?;
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            return Err(format!(
                "failed to compile {what}\n\n{}\ncommand was:\n  {} {}",
                stderr,
                self.tc.rustc.display(),
                args.join(" ")
            ));
        }
        let stderr = String::from_utf8_lossy(&out.stderr);
        if !stderr.trim().is_empty() {
            eprint!("{stderr}");
        }
        Ok(())
    }

    /// Build `core` from the pinned toolchain's own source.
    pub fn build_core(&self) -> Result<Built, String> {
        let src = self.tc.core_src();
        let dest = self.out.join("libcore.rlib");

        let mut args = self.common();
        args.extend([
            "--crate-type".into(),
            "rlib".into(),
            "--crate-name".into(),
            "core".into(),
            // The standard library is built with this; without it, core's stability
            // attributes are rejected when it is compiled as an ordinary crate.
            "-Z".into(),
            "force-unstable-if-unmarked".into(),
            src.display().to_string(),
        ]);

        let mut kb = KeyBuilder::new(&self.tc.identity());
        kb.field("unit", "core").args(&args);
        kb.file(&self.target_json)?;
        // core's source is part of the pinned toolchain, so its identity covers it.
        let key = kb.finish();

        if self.cache.restore(&key, "libcore.rlib", &dest) {
            return Ok(Built { path: dest, key });
        }

        args.push("-o".into());
        args.push(dest.display().to_string());
        self.run(&args, "core")?;
        self.cache.store(&key, "libcore.rlib", &dest)?;
        Ok(Built { path: dest, key })
    }

    /// Build one unit against already-built dependencies.
    pub fn build_unit(&self, unit: &Unit, deps: &BTreeMap<String, Built>) -> Result<Built, String> {
        let crate_name = unit.name.replace('-', "_");
        let filename = match unit.kind {
            Kind::Lib => format!("lib{crate_name}.rlib"),
            Kind::Bin => format!("{crate_name}.elf"),
        };
        let dest = self.out.join(&filename);

        let mut args = self.common();
        args.extend([
            "--crate-type".into(),
            match unit.kind {
                Kind::Lib => "rlib".into(),
                Kind::Bin => "bin".into(),
            },
            "--crate-name".into(),
            crate_name.clone(),
        ]);

        for c in &self.cfgs {
            args.push("--cfg".into());
            args.push(c.clone());
        }
        args.extend(self.check_cfgs.iter().cloned());

        // Every dependency named explicitly; nothing transitive is visible.
        for name in dep_order(unit, deps) {
            if let Some(b) = deps.get(&name) {
                args.push("--extern".into());
                args.push(format!("{}={}", name.replace('-', "_"), b.path.display()));
            }
        }
        args.push("-L".into());
        args.push(self.out.display().to_string());

        // The generated config module is available to every unit as `kconfig` —
        // except the units built before it exists, which are the ones it is built
        // from: compiler_builtins and core.
        let kconfig = self.out.join("libkconfig.rlib");
        if kconfig.exists() {
            args.push("--extern".into());
            args.push(format!("kconfig={}", kconfig.display()));
        }

        if unit.kind == Kind::Bin {
            let script = self
                .link_script
                .as_ref()
                .ok_or("this configuration selects no linker script (LINKER_SCRIPT is empty)")?;
            args.push("-C".into());
            args.push(format!("link-arg=-T{}", script.display()));
            // Without this the linker emits a warning and picks its own entry point,
            // which for a multiboot image is silently the wrong address.
            args.push("-C".into());
            args.push("link-arg=--no-warnings".into());
        }

        args.extend(unit.rustflags.iter().map(|f| self.expand(f)));
        args.push(unit.root_path().display().to_string());

        let mut kb = KeyBuilder::new(&self.tc.identity());
        kb.field("unit", &unit.name)
            .field("layer", &unit.layer)
            .args(&args);
        kb.file(&self.target_json)?;
        if unit.kind == Kind::Bin {
            if let Some(script) = &self.link_script {
                kb.file(script)?;
            }
        }
        kb.source_tree(&unit.src_dir())?;
        for (name, b) in deps {
            kb.field(name, &b.key);
        }
        let key = kb.finish();

        if self.cache.restore(&key, &filename, &dest) {
            if self.verbose {
                eprintln!("  {} (cached)", unit.name);
            }
            return Ok(Built { path: dest, key });
        }

        args.push("-o".into());
        args.push(dest.display().to_string());
        self.run(&args, &unit.name)?;
        self.cache.store(&key, &filename, &dest)?;
        Ok(Built { path: dest, key })
    }

    /// Compile the generated `config.rs` into a crate every unit can depend on.
    pub fn build_kconfig(&self, core: &Built, builtins: &Built) -> Result<Built, String> {
        let dest = self.out.join("libkconfig.rlib");
        let src = self.gen_dir.join("config.rs");

        let mut args = self.common();
        args.extend([
            "--crate-type".into(),
            "rlib".into(),
            "--crate-name".into(),
            "kconfig".into(),
            "--extern".into(),
            format!("core={}", core.path.display()),
            "--extern".into(),
            format!("compiler_builtins={}", builtins.path.display()),
            src.display().to_string(),
        ]);

        let mut kb = KeyBuilder::new(&self.tc.identity());
        kb.field("unit", "kconfig").args(&args);
        kb.file(&src)?;
        kb.field("core", &core.key);
        kb.field("compiler_builtins", &builtins.key);
        let key = kb.finish();

        if self.cache.restore(&key, "libkconfig.rlib", &dest) {
            return Ok(Built { path: dest, key });
        }
        args.push("-o".into());
        args.push(dest.display().to_string());
        self.run(&args, "kconfig")?;
        self.cache.store(&key, "libkconfig.rlib", &dest)?;
        Ok(Built { path: dest, key })
    }

    /// `$ROOT` and `$OUT` in a unit's rustflags, so manifests stay path-independent.
    fn expand(&self, flag: &str) -> String {
        flag.replace("$ROOT", &self.root.display().to_string())
            .replace("$OUT", &self.out.display().to_string())
    }
}

/// Dependencies plus the implicit ones every kernel crate gets.
fn dep_order(unit: &Unit, deps: &BTreeMap<String, Built>) -> Vec<String> {
    let mut v: Vec<String> = Vec::new();
    for implicit in ["core", "compiler_builtins"] {
        if deps.contains_key(implicit) {
            v.push(implicit.to_string());
        }
    }
    for d in &unit.deps {
        if !v.contains(d) {
            v.push(d.clone());
        }
    }
    v
}

impl Build {
    /// Package a linked image into something the platform's loader will accept.
    ///
    /// QEMU's multiboot loader refuses an ELF64 outright ("Cannot load x86-64 image,
    /// give a 32bit one"), even though the code inside is exactly what it should be.
    /// Rewriting the container to ELF32 is sound here because the image links at
    /// 1 MiB and every address in it fits in 32 bits; the 64-bit code is untouched.
    ///
    /// The ELF64 stays on disk as the debug artifact. That split is the one the
    /// deliverables in docs/build-system.md describe: a stripped bootable image plus
    /// separately shipped symbols.
    pub fn package(&self, format: &str, linked: &Path) -> Result<PathBuf, String> {
        match format {
            "" | "elf" => Ok(linked.to_path_buf()),
            "multiboot-elf32" => {
                let objcopy = self.tc.tool("llvm-objcopy")?;
                let dest = linked.with_extension("mb32.elf");
                let out = Command::new(&objcopy)
                    .args(["-O", "elf32-i386"])
                    .arg(linked)
                    .arg(&dest)
                    .output()
                    .map_err(|e| format!("cannot run llvm-objcopy: {e}"))?;
                if !out.status.success() {
                    return Err(format!(
                        "packaging as {format} failed:\n{}",
                        String::from_utf8_lossy(&out.stderr)
                    ));
                }
                Ok(dest)
            }
            other => Err(format!("unknown image format `{other}`")),
        }
    }
}

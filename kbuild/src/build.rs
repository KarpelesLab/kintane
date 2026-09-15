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
    pub target: Target,
    pub out: PathBuf,
    pub gen_dir: PathBuf,
    pub cache: Cache,
    pub cfgs: Vec<String>,
    pub check_cfgs: Vec<String>,
    pub opt_level: String,
    /// Linker script for `bin` units, from the configuration rather than hardcoded
    /// in a manifest, so the generic kernel unit never names an architecture.
    pub link_script: Option<PathBuf>,
    /// Kernel units only; `core` is the toolchain's code and its warnings are not ours.
    pub deny_warnings: bool,
    /// Keep LLVM bitcode in every rlib. Module builds need it: a module is linked with
    /// link-time optimisation, which reads the bitcode of `core` and of every crate the
    /// module uses, so that only the code the module reaches ends up in it. The kernel
    /// does not, and bitcode would only make its rlibs larger.
    pub bitcode: bool,
    /// Build position-independent. Set only for the user-program flavor
    /// (`main::build_user_flavor`), never for the kernel or its modules; see `Build::common`.
    pub pic: bool,
    pub verbose: bool,
}

/// What `--target` names.
#[derive(Clone)]
pub enum Target {
    /// One of our specifications in `targets/`. Its contents are part of every cache key.
    Spec(PathBuf),
    /// A target built into the pinned rustc, named by triple. Its definition is part of
    /// the toolchain, so the toolchain identity already covers it. Used by the
    /// portability check, and for units that name their own target: a bootloader for
    /// `x86_64-unknown-uefi` is exactly what rustc's built-in target describes, and the
    /// kernel is never built this way.
    Builtin(String),
}

impl Target {
    fn arg(&self) -> String {
        match self {
            Target::Spec(p) => p.display().to_string(),
            Target::Builtin(t) => t.clone(),
        }
    }

    fn key(&self, kb: &mut KeyBuilder) -> Result<(), String> {
        match self {
            Target::Spec(p) => kb.file(p).map(|_| ()),
            Target::Builtin(t) => {
                kb.field("builtin-target", t);
                Ok(())
            }
        }
    }

    /// The extension of a linked image: UEFI applications are PE/COFF, and firmware
    /// finds them by the `.efi` name.
    fn image_extension(&self) -> &'static str {
        match self {
            Target::Builtin(t) if t.ends_with("-uefi") => "efi",
            _ => "elf",
        }
    }
}

/// Where a built unit's artifact ended up, and the cache key that produced it.
/// A private path to compile into, beside `dest`, for this process alone.
///
/// rustc writes each codegen unit's object next to the path given to `-o`, under a name
/// derived from the crate and its metadata hash -- `libcore.core.<hash>-cgu.00.rcgu.o` --
/// and removes it once the archive is built. Two invocations compiling the same crate
/// with the same flags into one directory therefore race on the *same* intermediate
/// names, and one reports `failed to build archive: No such file or directory` against an
/// object the other has just deleted. Every preset built for one target shares
/// `build/<target>/out/`, and every host test shares `build/host/out`, so this is two
/// ordinary builds side by side rather than a contrived case.
///
/// A directory per process makes those names unique. Taking `dest` rather than a filename
/// keeps the staged name equal to the canonical one by construction. The artifact is moved
/// onto `dest` by `land`.
pub fn stage(dest: &Path) -> Result<PathBuf, String> {
    let parent = dest
        .parent()
        .ok_or_else(|| format!("{}: no parent directory", dest.display()))?;
    let name = dest
        .file_name()
        .ok_or_else(|| format!("{}: no file name", dest.display()))?;
    let dir = parent.join(format!(".build-{}", std::process::id()));
    std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    Ok(dir.join(name))
}

/// Move a staged artifact onto its canonical path, and drop the staging directory.
///
/// `rename` is atomic, so a build running beside this one sees the previous artifact or
/// this one and never a partial write -- the same property the cache's own landings have.
pub fn land(from: &Path, to: &Path) -> Result<(), String> {
    std::fs::rename(from, to)
        .map_err(|e| format!("{} -> {}: {e}", from.display(), to.display()))?;
    if let Some(d) = from.parent() {
        let _ = std::fs::remove_dir(d);
    }
    Ok(())
}

pub struct Built {
    pub path: PathBuf,
    pub key: String,
    /// For a user program: the environment variable its dependents read the linked ELF's
    /// path from. `None` for everything linked with `--extern`.
    pub embed: Option<String>,
}

impl Built {
    fn linked(path: PathBuf, key: String) -> Built {
        Built {
            path,
            key,
            embed: None,
        }
    }
}

/// The variable a dependent reads a user program's path from: `KINTANE_USER_INIT` for
/// the unit `init`.
pub fn embed_var(unit: &str) -> String {
    format!("KINTANE_USER_{}", unit.replace('-', "_").to_ascii_uppercase())
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
            self.target.arg(),
            "-C".into(),
            "panic=abort".into(),
            "-C".into(),
            format!("opt-level={}", self.opt_level),
            "-C".into(),
            "debuginfo=2".into(),
            "-C".into(),
            "force-frame-pointers=yes".into(),
            "-C".into(),
            if self.bitcode {
                "embed-bitcode=yes".into()
            } else {
                "embed-bitcode=no".into()
            },
        ];
        // A user-program flavor is built position-independent (see `Build::pic` and
        // `main::build_user_flavor`): an x86_64 user program links at the user half's 512 GiB,
        // out of reach of the small/static model's 32-bit absolute relocations, and an isolated
        // driver domain that pulls `core`'s slice-bounds and formatting paths cannot otherwise
        // be linked there. The kernel and its modules stay static — the module loader applies
        // absolute relocations, not PIC's GOT-relative ones — so this flavor is separate.
        if self.pic {
            a.push("-C".into());
            a.push("relocation-model=pic".into());
        }
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

    /// A position-independent build for a user program's flavor, into an `out/user`
    /// subdirectory so its artifacts never collide with the static ones. Shares the content
    /// cache, since a build's identity — not its output path — is its cache key.
    pub fn user_flavor(&self) -> Result<Build, String> {
        let out = self.out.join("user");
        std::fs::create_dir_all(&out).map_err(|e| format!("{}: {e}", out.display()))?;
        Ok(Build {
            root: self.root.clone(),
            tc: self.tc.clone(),
            target_name: self.target_name.clone(),
            target: self.target.clone(),
            out,
            gen_dir: self.gen_dir.clone(),
            cache: Cache::new(self.root.join("build/cache"))?,
            cfgs: self.cfgs.clone(),
            check_cfgs: self.check_cfgs.clone(),
            opt_level: self.opt_level.clone(),
            link_script: self.link_script.clone(),
            deny_warnings: self.deny_warnings,
            bitcode: self.bitcode,
            pic: true,
            verbose: self.verbose,
        })
    }

    /// Whether this configuration's user programs need the position-independent flavor: only
    /// x86_64, whose user half sits at 512 GiB beyond the static model's reach. i686's user
    /// half is under 4 GiB and aarch64 addresses PC-relative, so both link user programs as
    /// they build everything else.
    pub fn user_needs_pic(&self) -> bool {
        self.cfgs.iter().any(|c| c == "CONFIG_ARCH_X86_64")
    }

    /// A flavor for user programs that ask for hard float, into an `out/user-hf`
    /// subdirectory, built against `targets/<target>-hf.json` — the same specification as
    /// the kernel's but without `rustc-abi: softfloat`, which is the field that rejects the
    /// floating-point features rather than the feature string itself.
    ///
    /// It is a separate flavor because the target is part of every cache key
    /// (`Target::key`), so this `core` and the soft-float one are distinct entries that can
    /// never be served for one another. The kernel keeps its own target either way: nothing
    /// here changes how a kernel crate or a module is built.
    ///
    /// Position-independent on the same architectures as [`Self::user_flavor`], for the same
    /// reason — the link address, which hard float does not change.
    pub fn hard_float_flavor(&self) -> Result<Build, String> {
        let spec = self
            .root
            .join("targets")
            .join(format!("{}-hf.json", self.target_name));
        if !spec.exists() {
            return Err(format!(
                "a unit asks for `float = \"hard\"`, but this architecture has no hard-float \
                 target specification at {}\n  only x86_64 and aarch64 have one; see \
                 docs/targets.md",
                spec.display()
            ));
        }
        let out = self.out.join("user-hf");
        std::fs::create_dir_all(&out).map_err(|e| format!("{}: {e}", out.display()))?;
        Ok(Build {
            root: self.root.clone(),
            tc: self.tc.clone(),
            target_name: format!("{}-hf", self.target_name),
            target: Target::Spec(spec),
            out,
            gen_dir: self.gen_dir.clone(),
            cache: Cache::new(self.root.join("build/cache"))?,
            cfgs: self.cfgs.clone(),
            check_cfgs: self.check_cfgs.clone(),
            opt_level: self.opt_level.clone(),
            link_script: self.link_script.clone(),
            deny_warnings: self.deny_warnings,
            bitcode: self.bitcode,
            pic: self.user_needs_pic(),
            verbose: self.verbose,
        })
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
        self.target.key(&mut kb)?;
        // core's source is part of the pinned toolchain, so its identity covers it.
        let key = kb.finish();

        if self.cache.restore(&key, "libcore.rlib", &dest) {
            return Ok(Built::linked(dest, key));
        }

        let staged = stage(&dest)?;
        args.push("-o".into());
        args.push(staged.display().to_string());
        self.run(&args, "core")?;
        land(&staged, &dest)?;
        self.cache.store(&key, "libcore.rlib", &dest)?;
        Ok(Built::linked(dest, key))
    }

    /// Every argument rustc is given for `unit`, except the output path. `kbuild sdk`
    /// writes these into its module build script, so a module built from the SDK is built
    /// exactly as one built in the tree.
    pub fn unit_args(
        &self,
        unit: &Unit,
        deps: &BTreeMap<String, Built>,
    ) -> Result<Vec<String>, String> {
        let crate_name = unit.name.replace('-', "_");
        let mut args = self.common();
        args.extend([
            "--crate-type".into(),
            match unit.kind {
                Kind::Lib => "rlib".into(),
                Kind::Bin | Kind::User => "bin".into(),
                // A static library, so rustc links the module's crate with everything it
                // uses from `core` and its dependencies; fat LTO in one codegen unit, so that
                // is only what the module reaches. `modules.rs` turns the archive into one
                // relocatable object.
                Kind::Module => "staticlib".into(),
            },
            "--crate-name".into(),
            crate_name.clone(),
        ]);
        if unit.kind == Kind::Module {
            for flag in ["lto=fat", "codegen-units=1"] {
                args.push("-C".into());
                args.push(flag.into());
            }
            // A module's own sources are named by module, not by where they were built, so
            // one built from the SDK outside the tree has the same bytes as one built in it.
            args.push("--remap-path-prefix".into());
            args.push(format!("{}=/module/{}", unit.dir.display(), unit.name));
        }

        for c in &self.cfgs {
            args.push("--cfg".into());
            args.push(c.clone());
        }
        args.extend(self.check_cfgs.iter().cloned());
        if self.deny_warnings {
            args.push("-D".into());
            args.push("warnings".into());
        }

        // Every dependency named explicitly; nothing transitive is visible.
        for name in dep_order(unit, deps) {
            match deps.get(&name) {
                // A user program is embedded, not linked: its dependent includes the bytes.
                // The dependency's cache key is part of this unit's key below, so a changed
                // program rebuilds everything that embeds it.
                Some(Built {
                    path,
                    embed: Some(var),
                    ..
                }) => {
                    args.push("--env-set".into());
                    args.push(format!("{var}={}", path.display()));
                }
                Some(b) => {
                    args.push("--extern".into());
                    args.push(format!("{}={}", name.replace('-', "_"), b.path.display()));
                }
                None => {}
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

        // Our own target specifications need our linker scripts. A built-in target brings
        // its linker configuration with it — for UEFI, lld-link's entry point and
        // subsystem flags — and a script would be meaningless to it.
        // lld-link stamps a PE with the link time unless told not to; /Brepro replaces the
        // stamp with a hash of the output. That is not enough on its own: the PDB rustc asks
        // for records the path of a temporary directory rustc names at random, the PE's
        // debug directory carries the PDB's identity, and so the hash differs every build.
        // So UEFI images are linked without a PDB. Symbols for the loader, like the
        // kernel's bundle, are a follow-up; see docs/build-system.md#reproducibility.
        if unit.kind == Kind::Bin && self.target.image_extension() == "efi" {
            for flag in ["link-arg=/Brepro", "link-arg=/DEBUG:NONE"] {
                args.push("-C".into());
                args.push(flag.into());
            }
        }
        if unit.kind == Kind::Bin && matches!(self.target, Target::Spec(_)) {
            let script = self
                .link_script
                .as_ref()
                .ok_or("this configuration selects no linker script (LINKER_SCRIPT is empty)")?;
            args.push("-C".into());
            args.push(format!("link-arg=-T{}", script.display()));
            // Where a script finds `sizes.ld`, the configuration's numbers, and `stacks.ld`,
            // the thread-stack geometry derived from them; see `codegen::sizes_ld` and
            // `codegen::stacks`. A script that includes neither is unaffected.
            args.push("-C".into());
            args.push(format!("link-arg=-L{}", self.gen_dir.display()));
            // Without this the linker emits a warning and picks its own entry point,
            // which for a multiboot image is silently the wrong address.
            args.push("-C".into());
            args.push("link-arg=--no-warnings".into());
        }

        args.extend(unit.rustflags.iter().map(|f| self.expand(f)));
        args.push(unit.root_path().display().to_string());
        Ok(args)
    }

    /// Build one unit against already-built dependencies.
    pub fn build_unit(&self, unit: &Unit, deps: &BTreeMap<String, Built>) -> Result<Built, String> {
        let crate_name = unit.name.replace('-', "_");
        let filename = match unit.kind {
            Kind::Lib => format!("lib{crate_name}.rlib"),
            Kind::Bin => format!("{crate_name}.{}", self.target.image_extension()),
            Kind::Module => format!("lib{crate_name}.a"),
            Kind::User => format!("{crate_name}.user.elf"),
        };
        let dest = self.out.join(&filename);

        let mut args = self.unit_args(unit, deps)?;

        let mut kb = KeyBuilder::new(&self.tc.identity());
        kb.field("unit", &unit.name)
            .field("layer", &unit.layer)
            .args(&args);
        self.target.key(&mut kb)?;
        if unit.kind == Kind::Bin {
            if let Some(script) = &self.link_script {
                kb.file(script)?;
                // The sizes a script may `INCLUDE`. Covered already by `kconfig`'s key,
                // since every value is also a constant in `config.rs`, but named here
                // too: the day a script reads something that is not, the key is right.
                let sizes = self.gen_dir.join("sizes.ld");
                if sizes.is_file() {
                    kb.file(&sizes)?;
                }
                // A kernel script includes this, so a changed stack geometry must relink.
                // Keyed only where it exists: a loader such as kinboot-bios is linked
                // through a `Build` of its own, whose generated directory has no thread
                // stacks and no fragment. That is not a way to link a kernel against a
                // stale or missing geometry, because a script that includes an absent
                // `stacks.ld` fails to link.
                let stacks = self.gen_dir.join("stacks.ld");
                if stacks.exists() {
                    kb.file(&stacks)?;
                }
            }
        }
        kb.source_tree(&unit.src_dir())?;
        for (name, b) in deps {
            kb.field(name, &b.key);
        }
        let key = kb.finish();

        let embed = (unit.kind == Kind::User).then(|| embed_var(&unit.name));
        if self.cache.restore(&key, &filename, &dest) {
            if self.verbose {
                eprintln!("  {} (cached)", unit.name);
            }
            return Ok(Built {
                embed,
                ..Built::linked(dest, key)
            });
        }

        let staged = stage(&dest)?;
        args.push("-o".into());
        args.push(staged.display().to_string());
        self.run(&args, &unit.name)?;
        land(&staged, &dest)?;
        self.cache.store(&key, &filename, &dest)?;
        Ok(Built {
            embed,
            ..Built::linked(dest, key)
        })
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
            return Ok(Built::linked(dest, key));
        }
        let staged = stage(&dest)?;
        args.push("-o".into());
        args.push(staged.display().to_string());
        self.run(&args, "kconfig")?;
        land(&staged, &dest)?;
        self.cache.store(&key, "libkconfig.rlib", &dest)?;
        Ok(Built::linked(dest, key))
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

/// Where each image built for the ESP goes, by unit name.
const ESP_IMAGES: &[(&str, &str)] = &[
    ("kinboot_efi", "EFI/BOOT/BOOTX64.EFI"),
    ("kinboot_stub", "EFI/BOOT/BOOTX64.EFI"),
    ("kinboot_efi_chaintest", "EFI/KINTANE/CHAIN.EFI"),
];

/// The chainload test application as a boot entry names it: the ESP path above, the way
/// UEFI spells paths.
pub const ESP_CHAIN_TEST_ENTRY_PATH: &str = "\\EFI\\KINTANE\\CHAIN.EFI";

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
    ///
    /// Either way the bootable image is stripped of symbols and debug info. They are in
    /// the bundle [`Build::split_symbols`] wrote, and the kernel never reads its own
    /// symbol table: a backtrace is printed as raw addresses and decoded off the machine.
    pub fn package(
        &self,
        format: &str,
        linked: &Path,
        images: &[(String, PathBuf)],
        entries: &str,
        command_line: &str,
        reset_on_failure: bool,
    ) -> Result<PathBuf, String> {
        if !matches!(format, "efi-esp" | "efi-stub")
            && let Some((name, _)) = images.first()
        {
            return Err(format!(
                "`{name}` was built, but the {format} image format has no place for it"
            ));
        }
        let (flags, dest): (&[&str], PathBuf) = match format {
            "efi-esp" => return self.package_esp(linked, images, entries),
            "efi-stub" => {
                return self.package_efi_stub(linked, images, command_line, reset_on_failure);
            }
            "" | "elf" => (&["--strip-all"], linked.with_extension("img.elf")),
            "multiboot-elf32" => {
                (&["--strip-all", "-O", "elf32-i386"], linked.with_extension("mb32.elf"))
            }
            other => return Err(format!("unknown image format `{other}`")),
        };
        self.objcopy(flags, linked, &dest)
            .map_err(|e| format!("packaging as {format} failed:\n{e}"))?;
        Ok(dest)
    }

    /// A disk image whose EFI system partition holds the loader, where the firmware's
    /// boot manager looks for a removable medium's default; the boot entries and the
    /// stripped ELF64, where the loader looks for them; and any other image built for
    /// the ESP, such as the chainload test application.
    ///
    /// The ELF64 rather than the ELF32 the multiboot path needs: kinboot-efi reads 64-bit
    /// program headers and enters in long mode.
    /// The EFI stub: one application on the partition, with the kernel inside it.
    ///
    /// The stub is linked knowing nothing about the kernel, which does not exist yet when
    /// it is built and is stamped with its build ID after it does. So the kernel and the
    /// command line are added here, as sections of the stub's own PE, and where they
    /// landed is written into the descriptor the stub declares. The firmware loads every
    /// section it is told about, so both arrive in memory with the stub and it needs no
    /// filesystem to find them.
    fn package_efi_stub(
        &self,
        linked: &Path,
        images: &[(String, PathBuf)],
        command_line: &str,
        reset_on_failure: bool,
    ) -> Result<PathBuf, String> {
        let (_, stub) = images
            .iter()
            .find(|(name, _)| name == "kinboot_stub")
            .ok_or("the efi-stub image format needs kinboot_stub, and it is not enabled")?;
        if let Some((name, _)) = images.iter().find(|(name, _)| name != "kinboot_stub") {
            return Err(format!("`{name}` was built, but an EFI stub image carries only the stub"));
        }
        // The stripped ELF64, as kinboot-efi would have read from the partition: the
        // handover is the same code, so it wants the same bytes.
        let kernel = linked.with_extension("img.elf");
        self.objcopy(&["--strip-all"], linked, &kernel)
            .map_err(|e| format!("stripping the kernel failed:\n{e}"))?;
        let read = |p: &Path| std::fs::read(p).map_err(|e| format!("{}: {e}", p.display()));
        let kernel_bytes = read(&kernel)?;

        let stub_bytes = read(stub)?;
        let (image, kernel_at) =
            crate::pe::add_section(&stub_bytes, ".kernel", &kernel_bytes, crate::pe::DATA_SECTION)?;
        // `.cmdline` is where a unified kernel image carries its arguments, and this is
        // one: a single PE holding the kernel and the line it is booted with.
        let (mut image, cmdline_at) = crate::pe::add_section(
            &image,
            ".cmdline",
            command_line.as_bytes(),
            crate::pe::DATA_SECTION,
        )?;
        crate::pe::stamp(
            &mut image,
            crate::pe::KERNEL_BLOB_MARKER,
            &[
                u64::from(kernel_at),
                kernel_bytes.len() as u64,
                u64::from(cmdline_at),
                command_line.len() as u64,
                u64::from(reset_on_failure),
            ],
        )?;

        // The application on its own, beside the disk, for firmware that is given a file
        // rather than a disk and for `kbuild image`.
        let efi = linked.with_extension("efi");
        std::fs::write(&efi, &image).map_err(|e| format!("{}: {e}", efi.display()))?;
        let disk = crate::esp::disk_image(&[crate::esp::File {
            path: "EFI/BOOT/BOOTX64.EFI",
            data: &image,
        }])?;
        let dest = linked.with_extension("esp.img");
        std::fs::write(&dest, disk).map_err(|e| format!("{}: {e}", dest.display()))?;
        Ok(dest)
    }

    fn package_esp(
        &self,
        linked: &Path,
        images: &[(String, PathBuf)],
        entries: &str,
    ) -> Result<PathBuf, String> {
        let place = |name: &str| {
            ESP_IMAGES
                .iter()
                .find(|(unit, _)| *unit == name)
                .map(|(_, at)| *at)
        };
        if !images.iter().any(|(name, _)| name == "kinboot_efi") {
            return Err("the efi-esp image format needs kinboot_efi, and it is not enabled".into());
        }
        let kernel = linked.with_extension("img.elf");
        self.objcopy(&["--strip-all"], linked, &kernel)
            .map_err(|e| format!("stripping the kernel failed:\n{e}"))?;
        let read = |p: &Path| std::fs::read(p).map_err(|e| format!("{}: {e}", p.display()));
        let mut contents = Vec::new();
        for (name, path) in images {
            let at = place(name)
                .ok_or_else(|| format!("`{name}` was built, but the ESP has no place for it"))?;
            contents.push((at, read(path)?));
        }
        let kernel_bytes = read(&kernel)?;
        let mut files: Vec<crate::esp::File<'_>> = contents
            .iter()
            .map(|(path, data)| crate::esp::File { path, data })
            .collect();
        files.push(crate::esp::File {
            path: "KINTANE/KERNEL.ELF",
            data: &kernel_bytes,
        });
        files.push(crate::esp::File {
            path: "KINTANE/BOOT.CFG",
            data: entries.as_bytes(),
        });
        let disk = crate::esp::disk_image(&files)?;
        let dest = linked.with_extension("esp.img");
        std::fs::write(&dest, disk).map_err(|e| format!("{}: {e}", dest.display()))?;
        Ok(dest)
    }

    /// Write the symbol bundle: the linked image's symbol table and DWARF, without its
    /// code. `<image>.debug`, next to the linked ELF.
    ///
    /// This is what `kbuild symbolize` reads, and the thing to keep from a build whose
    /// crash reports someone may need to decode later.
    pub fn split_symbols(&self, linked: &Path) -> Result<PathBuf, String> {
        let dest = linked.with_extension("debug");
        self.objcopy(&["--only-keep-debug"], linked, &dest)
            .map_err(|e| format!("extracting symbols failed:\n{e}"))?;
        Ok(dest)
    }

    fn objcopy(&self, flags: &[&str], from: &Path, to: &Path) -> Result<(), String> {
        let objcopy = self.tc.tool("llvm-objcopy")?;
        let out = Command::new(&objcopy)
            .args(flags)
            .arg(from)
            .arg(to)
            .output()
            .map_err(|e| format!("cannot run llvm-objcopy: {e}"))?;
        if !out.status.success() {
            return Err(String::from_utf8_lossy(&out.stderr).into_owned());
        }
        Ok(())
    }
}

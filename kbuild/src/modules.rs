//! Building loadable modules, and the bundle that carries them to the kernel.
//!
//! A unit of kind `module` enabled by a tristate at `m` becomes one relocatable ELF object,
//! valid for exactly one kernel build (`docs/modules.md`):
//!
//! 1. Its crate and everything it uses are compiled with bitcode, and the module crate as a
//!    `staticlib` with fat LTO in one codegen unit. Only what the module reaches survives, `core`
//!    included, and nothing is left undefined except the kernel functions it calls.
//! 2. `rust-lld -r` turns the archive into a single relocatable object, without debug information.
//! 3. `llvm-objcopy` adds the `.kintane.identity` section: the build identity of the configuration
//!    it was built against (`codegen::identity_text`), which is the kernel's unless the unit asks
//!    otherwise.
//!
//! The kernel is not given a filesystem to find modules on, so kbuild packs every module it
//! built into one bundle beside the image (`modules.kmb`), and the boot path hands the kernel
//! the bundle: QEMU passes it to a multiboot kernel as a boot module (`-initrd`), which is
//! what GRUB does with a module line. The format is `kernel/module/src/bundle.rs`'s.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::build::{self, Build, Built};
use crate::graph::{Kind, Unit};
use crate::hosttest::collect_deps;
use crate::kcfg::{Resolution, SymbolTable};
use crate::{codegen, sha256, toml};

/// The bundle's file name, beside the kernel image.
pub const BUNDLE: &str = "modules.kmb";

/// Configuration overrides a module unit asks to be built against.
fn overrides(unit: &Unit) -> Result<Vec<(String, String)>, String> {
    let src = std::fs::read_to_string(&unit.manifest)
        .map_err(|e| format!("{}: {e}", unit.manifest.display()))?;
    let v = toml::parse(&src).map_err(|e| format!("{}: {e}", unit.manifest.display()))?;
    v.str_array("module.config-overrides")
        .into_iter()
        .map(|kv| {
            kv.split_once('=')
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .ok_or_else(|| {
                    format!(
                        "{}: config-overrides expects SYM=VALUE, got `{kv}`",
                        unit.manifest.display()
                    )
                })
        })
        .collect()
}

/// Build every module unit in `ordered` and write the bundle. `None` when there are none.
///
/// `resolve` resolves the kernel's configuration with extra settings, for a module that
/// asks to be built against another one.
#[allow(clippy::too_many_arguments)]
pub fn build_all(
    kernel: &Build,
    table: &SymbolTable,
    res: &Resolution,
    target_json: &Path,
    ordered: &[Unit],
    resolve: &dyn Fn(&[(String, String)]) -> Result<(SymbolTable, Resolution), String>,
) -> Result<Option<PathBuf>, String> {
    let units: Vec<&Unit> = ordered.iter().filter(|u| u.kind == Kind::Module).collect();
    if units.is_empty() {
        // A bundle left by an earlier configuration would still be handed to the guest.
        let stale = kernel.out.join(BUNDLE);
        if stale.exists() {
            std::fs::remove_file(&stale).map_err(|e| format!("{}: {e}", stale.display()))?;
        }
        return Ok(None);
    }
    let target_hash = sha256::hex(&sha256::digest(
        &std::fs::read(target_json).map_err(|e| format!("{}: {e}", target_json.display()))?,
    ));
    let base = kernel.out.parent().unwrap_or(&kernel.out).join("modules");
    let mut modules: Vec<(String, PathBuf)> = Vec::new();

    for unit in units {
        let mut extra = overrides(unit)?;
        let (variant, t, r);
        let resolved;
        if extra.is_empty() {
            variant = "kernel".to_string();
            (t, r) = (table, res);
        } else {
            for (k, v) in &mut extra {
                if table.get(k).is_none() {
                    return Err(format!(
                        "{}: overrides unknown symbol {k}",
                        unit.manifest.display()
                    ));
                }
                // `!` is the opposite of the kernel's value, so the module differs from the
                // kernel whichever way the kernel was configured.
                if v == "!" {
                    *v = if res.is_on(k) { "n" } else { "y" }.to_string();
                }
            }
            resolved = resolve(&extra)?;
            variant = unit.name.clone();
            (t, r) = (&resolved.0, &resolved.1);
            if r.values == res.values {
                return Err(format!(
                    "{}: config-overrides change nothing in this configuration, so the module \
                     would be built for the kernel it claims to differ from",
                    unit.manifest.display()
                ));
            }
        }
        let identity = codegen::identity_text(t, r, &kernel.tc.identity(), &target_hash);

        let mb = module_build(kernel, t, r, target_json, &base.join(&variant), &identity)?;
        let built = build_dependencies(&mb, unit, ordered)?;
        let archive = mb.build_unit(unit, &built)?.path;

        let module = kernel
            .out
            .join("modules")
            .join(format!("{}.kmod", unit.name));
        link(&mb, &archive, &identity, &module)?;
        let size = std::fs::metadata(&module).map(|m| m.len()).unwrap_or(0);
        println!(
            "  module  {} ({size} bytes{})",
            module.display(),
            if variant == "kernel" {
                String::new()
            } else {
                format!(
                    ", built for {}",
                    extra
                        .iter()
                        .map(|(k, v)| format!("{k}={v}"))
                        .collect::<Vec<_>>()
                        .join(" ")
                )
            }
        );
        modules.push((unit.name.clone(), module));
    }

    let bundle = kernel.out.join(BUNDLE);
    let mut entries = Vec::new();
    for (name, path) in &modules {
        entries.push((
            name.clone(),
            std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?,
        ));
    }
    let bytes = bundle_bytes(&entries)?;
    std::fs::write(&bundle, &bytes).map_err(|e| format!("{}: {e}", bundle.display()))?;
    println!(
        "  bundle  {} ({} modules, {} bytes)",
        bundle.display(),
        entries.len(),
        bytes.len()
    );
    Ok(Some(bundle))
}

/// The build for one module configuration: everything compiled with bitcode, under
/// `dir/out`, against that configuration's generated crate.
fn module_build(
    kernel: &Build,
    t: &SymbolTable,
    r: &Resolution,
    target_json: &Path,
    dir: &Path,
    identity: &str,
) -> Result<Build, String> {
    let out = dir.join("out");
    std::fs::create_dir_all(&out).map_err(|e| format!("{}: {e}", out.display()))?;
    let generated = codegen::emit(t, r, &dir.join("gen"), identity)?;
    Ok(Build {
        root: kernel.root.clone(),
        tc: kernel.tc.clone(),
        target_name: kernel.target_name.clone(),
        target: build::Target::Spec(target_json.to_path_buf()),
        out,
        gen_dir: dir.join("gen"),
        cache: crate::cache::Cache::new(kernel.root.join("build/cache"))?,
        cfgs: generated.cfgs,
        check_cfgs: generated.check_cfgs,
        opt_level: if r.is_on("DEBUG_BUILD") {
            "1".into()
        } else {
            "2".into()
        },
        link_script: None,
        deny_warnings: false,
        bitcode: true,
        pic: false,
        verbose: kernel.verbose,
    })
}

/// `core`, `compiler_builtins`, `kconfig` and every unit `unit` depends on, built by `mb`.
fn build_dependencies(
    mb: &Build,
    unit: &Unit,
    ordered: &[Unit],
) -> Result<BTreeMap<String, Built>, String> {
    let mut built: BTreeMap<String, Built> = BTreeMap::new();
    built.insert("core".into(), mb.build_core()?);
    let cb = ordered
        .iter()
        .find(|u| u.name == "compiler_builtins")
        .ok_or("no compiler_builtins unit in this configuration")?;
    built.insert(cb.name.clone(), mb.build_unit(cb, &built)?);
    let kconfig = mb.build_kconfig(&built["core"], &built["compiler_builtins"])?;
    built.insert("kconfig".into(), kconfig);
    let mut needed = Vec::new();
    collect_deps(unit, ordered, &mut needed);
    for u in needed {
        if built.contains_key(&u.name) || u.name == unit.name {
            continue;
        }
        let artifact = mb.build_unit(u, &built)?;
        built.insert(u.name.clone(), artifact);
    }
    Ok(built)
}

/// Write the module SDK for this kernel build into `dest`: what an out-of-tree module needs
/// to be built exactly as an in-tree one is, and nothing of the kernel's source but the
/// module interface.
///
/// ```text
/// IDENTITY          the build identity every module is stamped with
/// identity.section  the same, as the section the script adds
/// config.rs         the generated configuration, as the module's `kconfig` crate saw it
/// <target>.json     the target specification, under the name rustc knows it by
/// lib/              core, compiler_builtins, kconfig and module, compiled with bitcode
/// src/module/       the module interface crate's source, for reading
/// example/          a module to start from: the in-tree round-trip test module
/// build-module.sh   SRC NAME OUT: build SRC (a crate root) as module NAME into OUT
/// ```
///
/// The script needs the pinned toolchain and refuses any other. It runs the rustc, rust-lld
/// and llvm-objcopy invocations kbuild runs, with the kernel build's own flags written into
/// it, so the result is byte for byte what kbuild produces from the same source.
pub fn write_sdk(
    kernel: &Build,
    table: &SymbolTable,
    res: &Resolution,
    target_json: &Path,
    ordered: &[Unit],
    dest: &Path,
) -> Result<(), String> {
    let target_hash = sha256::hex(&sha256::digest(
        &std::fs::read(target_json).map_err(|e| format!("{}: {e}", target_json.display()))?,
    ));
    let identity = codegen::identity_text(table, res, &kernel.tc.identity(), &target_hash);
    let base = kernel
        .out
        .parent()
        .unwrap_or(&kernel.out)
        .join("modules")
        .join("kernel");
    let mb = module_build(kernel, table, res, target_json, &base, &identity)?;

    // A stand-in for the out-of-tree module: named and placed by the script's arguments.
    let template = Unit {
        name: "@NAME@".into(),
        kind: Kind::Module,
        dir: PathBuf::from("@DIR@"),
        root: PathBuf::from("@FILE@"),
        deps: vec!["module".into()],
        layer: "subsystem".into(),
        requires: None,
        rustflags: Vec::new(),
        host_tests: false,
        target: None,
        hard_float: false,
        manifest: PathBuf::from("@DIR@/kmod.toml"),
    };
    let built = build_dependencies(&mb, &template, ordered)?;

    if dest.exists() {
        std::fs::remove_dir_all(dest).map_err(|e| format!("{}: {e}", dest.display()))?;
    }
    let lib = dest.join("lib");
    for d in [
        lib.clone(),
        dest.join("src/module"),
        dest.join("example/src"),
    ] {
        std::fs::create_dir_all(&d).map_err(|e| format!("{}: {e}", d.display()))?;
    }
    let copy = |from: &Path, to: &Path| {
        std::fs::copy(from, to)
            .map(|_| ())
            .map_err(|e| format!("copying {} to {}: {e}", from.display(), to.display()))
    };
    for b in built.values() {
        copy(&b.path, &lib.join(b.path.file_name().unwrap_or_default()))?;
    }
    copy(&mb.gen_dir.join("config.rs"), &dest.join("config.rs"))?;
    // Under its own name: rustc names a custom target after its specification's file, and
    // crates built for `x86_64-kintane` are not usable by a build for `target`.
    let spec_name = target_json.file_name().unwrap_or_default();
    copy(target_json, &dest.join(spec_name))?;
    std::fs::write(dest.join("IDENTITY"), &identity).map_err(|e| e.to_string())?;
    std::fs::write(dest.join("identity.section"), identity_section(&identity))
        .map_err(|e| e.to_string())?;
    let module_src = kernel.root.join("kernel/module/src");
    for e in std::fs::read_dir(&module_src).map_err(|e| format!("{}: {e}", module_src.display()))? {
        let p = e.map_err(|e| e.to_string())?.path();
        if p.is_file() {
            copy(
                &p,
                &dest
                    .join("src/module")
                    .join(p.file_name().unwrap_or_default()),
            )?;
        }
    }
    let example = kernel.root.join("modules/test/roundtrip/src/lib.rs");
    copy(&example, &dest.join("example/src/lib.rs"))?;

    let args = mb.unit_args(&template, &built)?;
    let script = sdk_script(&args, &mb, &lib, target_json, &kernel.tc)?;
    let path = dest.join("build-module.sh");
    std::fs::write(&path, script).map_err(|e| format!("{}: {e}", path.display()))?;
    println!("  sdk     {}", dest.display());
    Ok(())
}

/// The SDK's build script. Each rustc argument kbuild would pass, with the kernel tree's
/// paths replaced by the SDK's and the template's by the script's arguments.
fn sdk_script(
    args: &[String],
    mb: &Build,
    lib: &Path,
    target_json: &Path,
    tc: &crate::toolchain::Toolchain,
) -> Result<String, String> {
    let quote = |s: &str| {
        let mut q = String::from("\"");
        for ch in s.chars() {
            if matches!(ch, '"' | '$' | '`' | '\\') {
                q.push('\\');
            }
            q.push(ch);
        }
        q.push('"');
        q
    };
    let out = mb.out.display().to_string();
    let sysroot = tc.sysroot.display().to_string();
    let root = mb.root.display().to_string();
    let spec = target_json.display().to_string();
    let spec_file = target_json
        .file_name()
        .map(|f| f.to_string_lossy().into_owned())
        .unwrap_or_default();
    let mut lines = Vec::new();
    let mut crate_name_next = false;
    for a in args {
        if crate_name_next {
            lines.push("  --crate-name \"$CRATE\"".to_string());
            crate_name_next = false;
            continue;
        }
        if a == "--crate-name" {
            crate_name_next = true;
            continue;
        }
        let mut q = quote(a);
        // Longest first: the module's own build directory is inside the tree's.
        q = q.replace(&out, "$SDK/lib");
        q = q.replace(&spec, &format!("$SDK/{}", spec_file));
        q = q.replace(&sysroot, "$SYSROOT");
        q = q.replace(&root, "$SDK");
        q = q.replace("@DIR@/@FILE@", "$SRC");
        q = q.replace("@DIR@", "$SRCDIR");
        q = q.replace("@NAME@", "$NAME");
        lines.push(format!("  {q}"));
    }
    let _ = lib;
    let release = &tc.pin.release;
    let commit = &tc.pin.commit_hash;
    Ok(format!(
        r#"#!/bin/sh
# Build an out-of-tree KinTane module against this SDK's kernel build.
#
#   build-module.sh SRC NAME OUT
#
# SRC is the module crate's root (src/lib.rs), NAME the module's name, OUT the .kmod to
# write. Generated by `kbuild sdk`; the flags below are the kernel build's own. A module
# is valid for exactly one kernel build: this one (see IDENTITY).
set -eu
if [ $# -ne 3 ]; then
  echo "usage: $0 SRC NAME OUT" >&2
  exit 2
fi
SDK=$(cd "$(dirname "$0")" && pwd)
SRC=$1
NAME=$2
OUT=$3
SRCDIR=$(cd "$(dirname "$SRC")" && pwd)
SRC="$SRCDIR/$(basename "$SRC")"
SRCDIR=$(dirname "$SRCDIR")
CRATE=$(printf '%s' "$NAME" | tr - _)
RUSTC=${{RUSTC:-rustc}}

# The toolchain must be the one the kernel was built with, not a compatible one.
version=$("$RUSTC" -vV)
case "$version" in
  *"commit-hash: {commit}"*) ;;
  *) echo "this SDK needs rustc {release} ({commit}); $RUSTC is not it" >&2; exit 1 ;;
esac
SYSROOT=$("$RUSTC" --print sysroot)
HOST=$(printf '%s\n' "$version" | sed -n 's/^host: //p')
TOOLS="$SYSROOT/lib/rustlib/$HOST/bin"

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
SOURCE_DATE_EPOCH=0 "$RUSTC" \
{args} \
  -o "$WORK/lib$CRATE.a"
"$TOOLS/rust-lld" -flavor gnu -r --whole-archive "$WORK/lib$CRATE.a" -o "$WORK/$NAME.o"
"$TOOLS/llvm-objcopy" --strip-debug --remove-section=.llvmbc --remove-section=.llvmcmd \
  --add-section=.kintane.identity="$SDK/identity.section" \
  --set-section-flags=.kintane.identity=readonly "$WORK/$NAME.o" "$OUT"
"#,
        args = lines.join(" \\\n"),
    ))
}

/// The `.kintane.identity` section's contents for `text`.
pub fn identity_section(text: &str) -> Vec<u8> {
    let mut v = b"KTIDENT1".to_vec();
    v.extend_from_slice(&sha256::digest(text.as_bytes()));
    v.extend_from_slice(&(text.len() as u32).to_le_bytes());
    v.extend_from_slice(text.as_bytes());
    v
}

/// Archive to stamped relocatable object.
fn link(b: &Build, archive: &Path, identity: &str, dest: &Path) -> Result<(), String> {
    let dir = dest.parent().unwrap_or(Path::new("."));
    std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let object = dest.with_extension("o");
    let lld = b.tc.tool("rust-lld")?;
    run(
        Command::new(&lld)
            .args(["-flavor", "gnu", "-r", "--whole-archive"])
            .arg(archive)
            .arg("-o")
            .arg(&object),
        "rust-lld -r",
    )?;
    let section = dest.with_extension("identity");
    std::fs::write(&section, identity_section(identity))
        .map_err(|e| format!("{}: {e}", section.display()))?;
    let objcopy = b.tc.tool("llvm-objcopy")?;
    run(
        Command::new(&objcopy)
            // `rust-lld -r` keeps debug sections whatever it is told; a module's symbols
            // are not shipped in it.
            .arg("--strip-debug")
            // The bitcode LTO read, still embedded in the objects LTO leaves alone.
            .arg("--remove-section=.llvmbc")
            .arg("--remove-section=.llvmcmd")
            .arg(format!("--add-section=.kintane.identity={}", section.display()))
            .arg("--set-section-flags=.kintane.identity=readonly")
            .arg(&object)
            .arg(dest),
        "llvm-objcopy --add-section",
    )
}

fn run(cmd: &mut Command, what: &str) -> Result<(), String> {
    let out = cmd
        .output()
        .map_err(|e| format!("cannot run {what}: {e}"))?;
    if !out.status.success() {
        return Err(format!("{what} failed:\n{}", String::from_utf8_lossy(&out.stderr)));
    }
    Ok(())
}

/// The longest module name a bundle entry holds.
const NAME_LEN: usize = 40;
const ENTRY_LEN: usize = NAME_LEN + 8;

/// A bundle: `KTBUNDL1`, the entry count and total length as little-endian `u32`s, one
/// 48-byte entry per module (NUL-padded name, offset from the bundle's start, length), then
/// the modules, each at an 8-byte boundary.
pub fn bundle_bytes(modules: &[(String, Vec<u8>)]) -> Result<Vec<u8>, String> {
    let header = 16 + modules.len() * ENTRY_LEN;
    let mut data = Vec::new();
    let mut table = Vec::new();
    for (name, bytes) in modules {
        if name.len() > NAME_LEN {
            return Err(format!("module name `{name}` is longer than {NAME_LEN} bytes"));
        }
        while (header + data.len()) % 8 != 0 {
            data.push(0);
        }
        let mut n = [0u8; NAME_LEN];
        n[..name.len()].copy_from_slice(name.as_bytes());
        table.extend_from_slice(&n);
        table.extend_from_slice(&((header + data.len()) as u32).to_le_bytes());
        table.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
        data.extend_from_slice(bytes);
    }
    let mut out = b"KTBUNDL1".to_vec();
    out.extend_from_slice(&(modules.len() as u32).to_le_bytes());
    out.extend_from_slice(&((header + data.len()) as u32).to_le_bytes());
    out.extend_from_slice(&table);
    out.extend_from_slice(&data);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bundle_lays_modules_out_on_8_byte_boundaries() {
        let b = bundle_bytes(&[("a".into(), vec![1, 2, 3]), ("bb".into(), vec![9; 9])]).unwrap();
        assert_eq!(&b[..8], b"KTBUNDL1");
        assert_eq!(u32::from_le_bytes(b[8..12].try_into().unwrap()), 2);
        assert_eq!(u32::from_le_bytes(b[12..16].try_into().unwrap()) as usize, b.len());
        let entry = |i: usize| {
            let e = &b[16 + i * ENTRY_LEN..16 + (i + 1) * ENTRY_LEN];
            let off = u32::from_le_bytes(e[40..44].try_into().unwrap()) as usize;
            let len = u32::from_le_bytes(e[44..48].try_into().unwrap()) as usize;
            (e[..NAME_LEN].iter().take_while(|&&c| c != 0).count(), off, len)
        };
        assert_eq!(entry(0), (1, 112, 3));
        assert_eq!(entry(1), (2, 120, 9));
        assert_eq!(&b[120..129], &[9; 9]);
        assert!(bundle_bytes(&[("x".repeat(41), vec![])]).is_err());
    }

    #[test]
    fn the_identity_section_is_magic_hash_length_text() {
        let s = identity_section("abc");
        assert_eq!(&s[..8], b"KTIDENT1");
        assert_eq!(s[8..40], sha256::digest(b"abc"));
        assert_eq!(&s[40..44], &3u32.to_le_bytes());
        assert_eq!(&s[44..], b"abc");
    }
}

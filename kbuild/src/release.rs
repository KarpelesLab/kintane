//! `kbuild release`: one configuration's deliverables, and a manifest that pins them.
//!
//! `docs/build-system.md` promises a release: the bootable image, the symbol bundle that
//! decodes its crash reports, its modules and the SDK to build more, and the exact
//! configuration. This gathers them for one preset into `build/release/<preset>/`:
//!
//! ```text
//! image/<file>          the bootable image, as the configuration packages it
//! symbols/kintane.debug the symbol bundle `kbuild symbolize` reads
//! config                the resolved configuration, so the build can be repeated
//! modules/              loadable modules and their bundle, when the configuration has any
//! sdk/                  the module SDK, when the configuration has modules
//! MANIFEST              the build ID, the toolchain, and a SHA-256 of every file above
//! ```
//!
//! # Reproducible, and checkable as such
//!
//! The manifest holds nothing that varies between two builds of one tree: no clock, no
//! host path, no build directory. Files are listed by their path inside the release, in
//! sorted order. So two cold builds of the same commit must produce the same manifest,
//! byte for byte, and CI compares exactly that; a difference names the file that differs.

use std::path::{Path, PathBuf};

use crate::sha256;

/// The manifest format's version, first in the file, so a reader can refuse one it does
/// not understand instead of misreading it.
const MANIFEST_VERSION: u32 = 1;

pub fn run(root: &Path, opts: &crate::Opts) -> Result<(), String> {
    let preset = opts
        .preset
        .clone()
        .ok_or("`release` needs --preset: a release is of one configuration")?;
    let (image, res) = crate::do_build(root, opts)?;
    let modules = res.is_on("MODULES");
    if modules {
        // Everything is cached by now; this only writes the SDK beside the build.
        let mut o = opts.clone();
        o.sdk = true;
        crate::do_build(root, &o)?;
    }
    let target = res.str("TARGET").to_string();
    let out = image
        .parent()
        .ok_or("the build wrote its image nowhere")?
        .to_path_buf();
    let build_dir = out.parent().unwrap_or(&out).to_path_buf();

    let dest = root.join("build").join("release").join(&preset);
    // Start empty, so a file from an earlier release of this preset never survives into
    // this one and appears in its manifest.
    if dest.exists() {
        std::fs::remove_dir_all(&dest).map_err(|e| format!("{}: {e}", dest.display()))?;
    }

    let image_name = image
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or("the image has no file name")?
        .to_string();
    copy(&image, &dest.join("image").join(&image_name))?;
    copy(&out.join("kintane.debug"), &dest.join("symbols").join("kintane.debug"))?;
    copy(&root.join(".config"), &dest.join("config"))?;

    let module_dir = out.join("modules");
    if module_dir.is_dir() {
        copy_tree(&module_dir, &dest.join("modules"))?;
        let bundle = out.join("modules.kmb");
        if bundle.is_file() {
            copy(&bundle, &dest.join("modules").join("modules.kmb"))?;
        }
    }
    if modules {
        copy_tree(&build_dir.join("sdk"), &dest.join("sdk"))?;
    }

    let elf = std::fs::read(out.join("kintane.elf"))
        .map_err(|e| format!("{}: {e}", out.join("kintane.elf").display()))?;
    let build_id = sha256::hex(&crate::buildid::compute(&elf)?);
    let toolchain = crate::toolchain::verify(root)?.identity();

    let mut entries = Vec::new();
    for rel in files_under(&dest)? {
        let bytes = std::fs::read(dest.join(&rel)).map_err(|e| format!("{rel}: {e}"))?;
        entries.push((rel, sha256::hash_hex(&bytes)));
    }
    let text = manifest(
        &[
            ("preset", preset.as_str()),
            ("target", target.as_str()),
            ("build-id", build_id.as_str()),
            ("toolchain", toolchain.as_str()),
        ],
        &entries,
    );
    let manifest_path = dest.join("MANIFEST");
    std::fs::write(&manifest_path, &text)
        .map_err(|e| format!("{}: {e}", manifest_path.display()))?;

    println!("  release {} ({} files, build {build_id})", dest.display(), entries.len());
    Ok(())
}

/// The manifest: a version line, `key value` header lines, a blank line, then one
/// `<sha256>  <path>` line per file in sorted path order — the layout `shasum -c` reads.
pub fn manifest(header: &[(&str, &str)], files: &[(String, String)]) -> String {
    let mut out = format!("kintane-release {MANIFEST_VERSION}\n");
    for (k, v) in header {
        out.push_str(&format!("{k} {v}\n"));
    }
    out.push('\n');
    let mut sorted: Vec<&(String, String)> = files.iter().collect();
    sorted.sort_by(|a, b| a.0.cmp(&b.0));
    for (path, hash) in sorted {
        out.push_str(&format!("{hash}  {path}\n"));
    }
    out
}

fn copy(from: &Path, to: &Path) -> Result<(), String> {
    if let Some(parent) = to.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("{}: {e}", parent.display()))?;
    }
    std::fs::copy(from, to).map_err(|e| format!("copying {}: {e}", from.display()))?;
    Ok(())
}

fn copy_tree(from: &Path, to: &Path) -> Result<(), String> {
    for rel in files_under(from)? {
        copy(&from.join(&rel), &to.join(&rel))?;
    }
    Ok(())
}

/// Every file under `dir`, as `/`-separated paths relative to it, sorted.
fn files_under(dir: &Path) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    let mut stack: Vec<PathBuf> = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let read = std::fs::read_dir(&d).map_err(|e| format!("{}: {e}", d.display()))?;
        for entry in read {
            let path = entry.map_err(|e| format!("{}: {e}", d.display()))?.path();
            if path.is_dir() {
                stack.push(path);
            } else {
                let rel = path
                    .strip_prefix(dir)
                    .map_err(|_| format!("{} is outside {}", path.display(), dir.display()))?;
                let parts: Vec<String> = rel
                    .components()
                    .map(|c| c.as_os_str().to_string_lossy().into_owned())
                    .collect();
                out.push(parts.join("/"));
            }
        }
    }
    out.sort();
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_manifest_is_the_same_whatever_order_files_are_found_in() {
        let header = [("preset", "x86_64-qemu"), ("build-id", "abcd")];
        let a = vec![
            ("symbols/kintane.debug".to_string(), "22".to_string()),
            ("config".to_string(), "11".to_string()),
            ("image/kintane.mb32.elf".to_string(), "33".to_string()),
        ];
        let mut b = a.clone();
        b.reverse();
        assert_eq!(manifest(&header, &a), manifest(&header, &b));
    }

    #[test]
    fn a_manifest_reads_as_shasum_check_input() {
        let text = manifest(
            &[("preset", "p"), ("target", "t")],
            &[("config".to_string(), "ab".repeat(32))],
        );
        let mut lines = text.lines();
        assert_eq!(lines.next(), Some("kintane-release 1"));
        assert_eq!(lines.next(), Some("preset p"));
        assert_eq!(lines.next(), Some("target t"));
        assert_eq!(lines.next(), Some(""));
        assert_eq!(lines.next(), Some(format!("{}  config", "ab".repeat(32)).as_str()));
        assert_eq!(lines.next(), None);
    }

    #[test]
    fn files_under_lists_nested_files_relative_and_sorted() {
        let dir = std::env::temp_dir().join(format!("kbuild-release-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("b/c")).unwrap();
        std::fs::write(dir.join("b/c/z"), b"1").unwrap();
        std::fs::write(dir.join("a"), b"2").unwrap();
        std::fs::write(dir.join("b/y"), b"3").unwrap();
        let listed = files_under(&dir).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
        assert_eq!(listed, vec!["a", "b/c/z", "b/y"]);
    }
}

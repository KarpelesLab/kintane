//! Toolchain pin enforcement.
//!
//! The pin is the **commit hash**, not the channel name. A channel like
//! `nightly-2026-08-30` is only a hint for how to install the right compiler; what
//! makes a build reproducible is that `rustc -vV` reports the exact commit and LLVM
//! version recorded in `toolchain.toml`. So we locate a candidate rustc, ask it who it
//! is, and accept it on identity regardless of what it is called locally.

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::toml;

#[derive(Debug, Clone)]
pub struct Pin {
    pub channel: String,
    pub release: String,
    pub commit_hash: String,
    pub llvm: String,
    pub baseline: String,
    pub edition: String,
    pub features: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct Toolchain {
    pub rustc: PathBuf,
    pub sysroot: PathBuf,
    /// Host triple, which is where llvm-tools binaries live under the sysroot.
    pub host: String,
    pub pin: Pin,
    /// `<sysroot>/lib/rustlib/src/rust/library`, needed to build `core` ourselves.
    pub lib_src: PathBuf,
}

impl Toolchain {
    pub fn core_src(&self) -> PathBuf {
        self.lib_src.join("core/src/lib.rs")
    }

    /// An llvm-tools binary such as `llvm-objcopy`, shipped with the toolchain so
    /// that image packaging needs no system binutils.
    pub fn tool(&self, name: &str) -> Result<PathBuf, String> {
        let p = self
            .sysroot
            .join("lib/rustlib")
            .join(&self.host)
            .join("bin")
            .join(name);
        if p.exists() {
            Ok(p)
        } else {
            Err(format!(
                "{name} not found at {}\n  install it with:\n    rustup component add llvm-tools --toolchain {}",
                p.display(),
                self.pin.channel
            ))
        }
    }
    /// Identity string folded into every cache key.
    pub fn identity(&self) -> String {
        format!("{} {} llvm{}", self.pin.release, self.pin.commit_hash, self.pin.llvm)
    }
}

pub fn load_pin(root: &Path) -> Result<Pin, String> {
    let path = root.join("toolchain.toml");
    let src = std::fs::read_to_string(&path)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let v = toml::parse(&src).map_err(|e| format!("{}: {e}", path.display()))?;

    let get = |p: &str| -> Result<String, String> {
        v.get_path(p)
            .and_then(|x| x.as_str())
            .map(String::from)
            .ok_or_else(|| format!("{}: missing `{p}`", path.display()))
    };

    let features = v
        .get_path("features")
        .and_then(|f| f.as_table())
        .map(|t| t.keys().cloned().collect())
        .unwrap_or_default();

    Ok(Pin {
        channel: get("toolchain.channel")?,
        release: get("toolchain.release")?,
        commit_hash: get("toolchain.commit-hash")?,
        llvm: get("toolchain.llvm")?,
        baseline: get("baseline.rust")?,
        edition: get("baseline.edition")?,
        features,
    })
}

/// Find a rustc matching the pin, or explain precisely how it differs.
pub fn verify(root: &Path) -> Result<Toolchain, String> {
    let pin = load_pin(root)?;

    let mut tried = Vec::new();
    let candidates = [pin.channel.clone(), "nightly".to_string()];
    // The pinned channel first; then whatever `nightly` currently is, since a
    // developer who has the right compiler under a different name should not be
    // blocked by the name.
    for candidate in &candidates {
        let candidate = candidate.as_str();
        let Some(rustc) = which_rustc(candidate) else {
            tried.push(format!("{candidate}: not installed"));
            continue;
        };
        let info = version_info(&rustc)?;
        if info.commit_hash == pin.commit_hash {
            if info.llvm != pin.llvm {
                return Err(format!(
                    "toolchain {} has the pinned rustc commit but LLVM {} (pinned: {})\n\
                     LLVM is part of the pin because codegen differs between releases",
                    candidate, info.llvm, pin.llvm
                ));
            }
            let sysroot = sysroot(&rustc)?;
            let lib_src = sysroot.join("lib/rustlib/src/rust/library");
            if !lib_src.join("core/src/lib.rs").exists() {
                return Err(format!(
                    "component `rust-src` is missing from toolchain {candidate}\n\
                     kbuild builds core from source; install it with:\n    \
                     rustup component add rust-src --toolchain {candidate}"
                ));
            }
            return Ok(Toolchain {
                rustc,
                sysroot,
                host: info.host,
                pin,
                lib_src,
            });
        }
        tried.push(format!("{candidate}: {} ({})", info.release, info.commit_hash));
    }

    Err(format!(
        "no installed toolchain matches the pin in toolchain.toml\n\
         pinned:  {} ({}), LLVM {}\n\
         tried:\n  {}\n\n\
         install it with:\n    rustup toolchain install {}\n    \
         rustup component add rust-src --toolchain {}",
        pin.release,
        pin.commit_hash,
        pin.llvm,
        tried.join("\n  "),
        pin.channel,
        pin.channel,
    ))
}

pub struct VersionInfo {
    pub release: String,
    pub commit_hash: String,
    pub llvm: String,
    pub host: String,
}

fn which_rustc(toolchain: &str) -> Option<PathBuf> {
    let out = Command::new("rustup")
        .args(["which", "--toolchain", toolchain, "rustc"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let p = PathBuf::from(String::from_utf8_lossy(&out.stdout).trim().to_string());
    p.exists().then_some(p)
}

pub fn version_info(rustc: &Path) -> Result<VersionInfo, String> {
    let out = Command::new(rustc)
        .arg("-vV")
        .output()
        .map_err(|e| format!("cannot run {}: {e}", rustc.display()))?;
    let text = String::from_utf8_lossy(&out.stdout);
    let field = |k: &str| {
        text.lines()
            .find_map(|l| l.strip_prefix(k))
            .map(|v| v.trim().to_string())
            .unwrap_or_default()
    };
    Ok(VersionInfo {
        release: field("release:"),
        commit_hash: field("commit-hash:"),
        llvm: field("LLVM version:"),
        host: field("host:"),
    })
}

fn sysroot(rustc: &Path) -> Result<PathBuf, String> {
    let out = Command::new(rustc)
        .args(["--print", "sysroot"])
        .output()
        .map_err(|e| format!("cannot run rustc: {e}"))?;
    Ok(PathBuf::from(String::from_utf8_lossy(&out.stdout).trim().to_string()))
}

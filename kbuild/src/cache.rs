//! Content-addressed build cache.
//!
//! The key is a hash of everything that can affect the output: the toolchain
//! identity, the full argument vector, every source file in the unit, and the keys of
//! all dependencies. A hit is a hardlink, so "rebuild all five tier-1 targets" stays
//! cheap — which is what makes gating every merge on every target affordable.

use crate::sha256::{hex, Sha256};
use std::path::{Path, PathBuf};

pub struct Cache {
    dir: PathBuf,
    pub hits: std::cell::Cell<usize>,
    pub misses: std::cell::Cell<usize>,
}

impl Cache {
    pub fn new(dir: PathBuf) -> Result<Self, String> {
        std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        Ok(Cache {
            dir,
            hits: std::cell::Cell::new(0),
            misses: std::cell::Cell::new(0),
        })
    }

    fn slot(&self, key: &str, filename: &str) -> PathBuf {
        self.dir.join(&key[..2]).join(key).join(filename)
    }

    /// Place a cached artifact at `dest` if present.
    pub fn restore(&self, key: &str, filename: &str, dest: &Path) -> bool {
        let slot = self.slot(key, filename);
        if !slot.exists() {
            return false;
        }
        if link_or_copy(&slot, dest).is_err() {
            return false;
        }
        self.hits.set(self.hits.get() + 1);
        true
    }

    /// Store a freshly built artifact, leaving `src` in place.
    pub fn store(&self, key: &str, filename: &str, src: &Path) -> Result<(), String> {
        let slot = self.slot(key, filename);
        if let Some(p) = slot.parent() {
            std::fs::create_dir_all(p).map_err(|e| format!("{}: {e}", p.display()))?;
        }
        // Ignore failure to cache: a build that succeeded must not fail because the
        // cache is full or read-only.
        let _ = link_or_copy(src, &slot);
        self.misses.set(self.misses.get() + 1);
        Ok(())
    }
}

fn link_or_copy(from: &Path, to: &Path) -> std::io::Result<()> {
    if let Some(p) = to.parent() {
        std::fs::create_dir_all(p)?;
    }
    let _ = std::fs::remove_file(to);
    match std::fs::hard_link(from, to) {
        Ok(()) => Ok(()),
        // Across filesystems, or where hardlinks are unavailable.
        Err(_) => std::fs::copy(from, to).map(|_| ()),
    }
}

/// Accumulates everything that affects a unit's output.
pub struct KeyBuilder {
    h: Sha256,
}

impl KeyBuilder {
    pub fn new(toolchain_identity: &str) -> Self {
        let mut h = Sha256::new();
        h.update(b"kintane-cache-v1\0");
        h.update(toolchain_identity.as_bytes());
        h.update(b"\0");
        KeyBuilder { h }
    }

    pub fn field(&mut self, label: &str, value: &str) -> &mut Self {
        self.h.update(label.as_bytes());
        self.h.update(b"=");
        self.h.update(value.as_bytes());
        self.h.update(b"\0");
        self
    }

    pub fn args(&mut self, args: &[String]) -> &mut Self {
        for a in args {
            self.h.update(a.as_bytes());
            self.h.update(b"\0");
        }
        self
    }

    /// Every file under `dir`, in a deterministic order, contents included.
    pub fn source_tree(&mut self, dir: &Path) -> Result<&mut Self, String> {
        let mut files = Vec::new();
        collect(dir, &mut files)?;
        files.sort();
        for f in files {
            let rel = f.strip_prefix(dir).unwrap_or(&f);
            self.h.update(rel.to_string_lossy().as_bytes());
            self.h.update(b"\0");
            let data =
                std::fs::read(&f).map_err(|e| format!("{}: {e}", f.display()))?;
            self.h.update(&(data.len() as u64).to_le_bytes());
            self.h.update(&data);
        }
        Ok(self)
    }

    pub fn file(&mut self, path: &Path) -> Result<&mut Self, String> {
        let data = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
        self.h.update(&(data.len() as u64).to_le_bytes());
        self.h.update(&data);
        Ok(self)
    }

    pub fn finish(self) -> String {
        hex(&self.h.finish())
    }
}

fn collect(dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), String> {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return Ok(()), // a unit with no source directory hashes as empty
    };
    for e in entries.flatten() {
        let p = e.path();
        if p.is_dir() {
            collect(&p, out)?;
        } else {
            out.push(p);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `field` returns `&mut Self` for chaining, so a key is built through a local
    /// rather than a single expression.
    fn key(tc: &str, fields: &[(&str, &str)], args: &[&str]) -> String {
        let mut kb = KeyBuilder::new(tc);
        for (k, v) in fields {
            kb.field(k, v);
        }
        let owned: Vec<String> = args.iter().map(|s| s.to_string()).collect();
        kb.args(&owned);
        kb.finish()
    }

    #[test]
    fn key_changes_with_every_input() {
        let base = key("tc1", &[("name", "mm")], &[]);
        assert_ne!(base, key("tc2", &[("name", "mm")], &[]), "toolchain must affect the key");
        assert_ne!(base, key("tc1", &[("name", "vfs")], &[]), "unit name must affect the key");
    }

    #[test]
    fn key_is_stable_for_identical_input() {
        let a = key("tc", &[("x", "1")], &["-C", "opt-level=2"]);
        let b = key("tc", &[("x", "1")], &["-C", "opt-level=2"]);
        assert_eq!(a, b);
    }

    #[test]
    fn argument_order_matters() {
        assert_ne!(key("tc", &[], &["a", "b"]), key("tc", &[], &["b", "a"]));
    }

    #[test]
    fn field_separators_prevent_collisions() {
        // "ab"+"c" must not hash the same as "a"+"bc".
        let a = key("t", &[("k", "ab"), ("j", "c")], &[]);
        let b = key("t", &[("k", "a"), ("j", "bc")], &[]);
        assert_ne!(a, b);
    }

    #[test]
    fn restore_reports_miss_for_an_unknown_key() {
        let dir = std::env::temp_dir().join(format!("kbuild-cache-test-{}", std::process::id()));
        let c = Cache::new(dir.clone()).unwrap();
        assert!(!c.restore("0".repeat(64).as_str(), "x.rlib", &dir.join("x.rlib")));
        let _ = std::fs::remove_dir_all(&dir);
    }
}

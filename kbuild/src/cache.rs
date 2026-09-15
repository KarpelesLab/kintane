//! Content-addressed build cache.
//!
//! The key is a hash of everything that can affect the output: the toolchain
//! identity, the full argument vector, every source file in the unit, and the keys of
//! all dependencies. A hit is a hardlink, so "rebuild all five tier-1 targets" stays
//! cheap — which is what makes gating every merge on every target affordable.

use std::path::{Path, PathBuf};

use crate::sha256::{Sha256, hex};

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
    // Land the artifact by renaming a temporary sibling over `to`, never by unlinking
    // `to` and then recreating it. Every preset built for one target shares
    // `build/<target>/out/`, and a build running beside this one names these very paths
    // in `--extern`: the gap between an unlink and the link that follows is a moment in
    // which a dependency does not exist, which rustc reports as `E0463: can't find
    // crate` against a crate that was built and is about to be there again. `rename` is
    // atomic, so a concurrent reader sees the old file or the new one and never absence.
    let tmp = to.with_extension(format!("tmp{}", std::process::id()));
    let _ = std::fs::remove_file(&tmp);
    if std::fs::hard_link(from, &tmp).is_err() {
        // Across filesystems, or where hardlinks are unavailable.
        std::fs::copy(from, &tmp)?;
    }
    match std::fs::rename(&tmp, to) {
        Ok(()) => Ok(()),
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            Err(e)
        }
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
            let data = std::fs::read(&f).map_err(|e| format!("{}: {e}", f.display()))?;
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

    /// How long a destination is observed missing while an artifact lands on it, over
    /// `ROUNDS` landings watched by a spinning reader.
    fn absences(tag: &str, land: fn(&Path, &Path)) -> usize {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

        const ROUNDS: usize = 3000;
        let dir = std::env::temp_dir().join(format!("kbuild-land-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let src = dir.join("src.rlib");
        let dest = dir.join("dest.rlib");
        std::fs::write(&src, b"an artifact").unwrap();
        std::fs::write(&dest, b"an artifact").unwrap();

        let watching = Arc::new(AtomicBool::new(true));
        let absent = Arc::new(AtomicUsize::new(0));
        let (w, a, watched) = (watching.clone(), absent.clone(), dest.clone());
        let reader = std::thread::spawn(move || {
            while w.load(Ordering::Relaxed) {
                if !watched.exists() {
                    a.fetch_add(1, Ordering::Relaxed);
                }
            }
        });
        for _ in 0..ROUNDS {
            land(&src, &dest);
        }
        watching.store(false, Ordering::Relaxed);
        reader.join().unwrap();
        let n = absent.load(Ordering::Relaxed);
        let _ = std::fs::remove_dir_all(&dir);
        n
    }

    /// Landing an artifact must never leave the destination absent, even for an instant.
    /// Every preset built for one target shares `build/<target>/out/`, and a build
    /// running beside this one names those paths in `--extern`; a file missing there is
    /// reported as `E0463: can't find crate` against a crate that was just built. The
    /// unsafe strategy is measured too, so a test that cannot detect a window fails
    /// loudly rather than passing for the wrong reason.
    #[test]
    fn landing_an_artifact_never_leaves_the_destination_absent() {
        fn unlink_then_link(from: &Path, to: &Path) {
            let _ = std::fs::remove_file(to);
            let _ = std::fs::hard_link(from, to);
        }
        fn land(from: &Path, to: &Path) {
            link_or_copy(from, to).unwrap();
        }

        assert!(
            absences("unsafe", unlink_then_link) > 0,
            "unlink-then-recreate showed no window, so this test cannot detect one"
        );
        assert_eq!(
            absences("rename", land),
            0,
            "link_or_copy left the destination absent; a build beside this one would see E0463"
        );
    }
}

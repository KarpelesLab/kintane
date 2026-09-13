//! Stamping the build ID into a linked image, and reading it back.
//!
//! The kernel reserves twenty bytes after a marker (`lib/buildid`). After linking, this
//! computes the ID and writes it there, before the image is stripped and packaged, so the
//! bootable image, the linked ELF and the symbol bundle all agree.
//!
//! # What the ID is a hash of
//!
//! SHA-256 over the entry point and every `PT_LOAD` segment, its address, size and flags
//! and its bytes in the file, with the twenty ID bytes read as zero; the first twenty bytes
//! of that hash. Two consequences follow, and both are the point:
//!
//! * The ID cannot depend on itself, so stamping is idempotent. A cached image stamped again gets
//!   the same bytes, and two clean builds of the same tree are still byte-identical.
//! * Only what the machine loads is covered. Debug sections, the symbol table and section names are
//!   not, so a change that alters nothing the CPU would run or read keeps its ID. Two builds with
//!   the same ID therefore run the same bytes at the same addresses, which is what makes their
//!   addresses interchangeable in a backtrace.
//!
//! # Where the symbol bundle keeps it
//!
//! `llvm-objcopy --only-keep-debug` keeps section headers but drops the contents of every
//! loaded section, `.rodata` with the ID included. So the ID is added to the bundle as a
//! section of its own that is not loaded, [`BUNDLE_SECTION`], which `kbuild symbolize`
//! compares against the `bt build` line of the log it is asked to decode.

use std::path::Path;
use std::process::Command;

use crate::sha256::{self, Sha256};

/// Bytes of ID, as `lib/buildid::LEN`.
pub const LEN: usize = 20;

/// What precedes the ID in the image, as `lib/buildid::MARKER`.
pub const MARKER: &[u8; 12] = b"KinTane-BID:";

/// The section of the symbol bundle that records the ID of the image it describes.
pub const BUNDLE_SECTION: &str = ".kintane.build-id";

/// One loadable segment.
struct Load {
    offset: usize,
    filesz: usize,
    vaddr: u64,
    memsz: u64,
    flags: u32,
}

/// The entry point and loadable segments of an ELF image.
fn loads(data: &[u8]) -> Result<(u64, Vec<Load>), String> {
    if data.len() < 0x34 || &data[..4] != b"\x7fELF" {
        return Err("not an ELF file".into());
    }
    let is64 = match data[4] {
        1 => false,
        2 => true,
        c => return Err(format!("unknown ELF class {c}")),
    };
    if data[5] != 1 {
        return Err("only little-endian images are stamped".into());
    }
    let u16_at = |at: usize| -> Result<u64, String> {
        data.get(at..at + 2)
            .map(|b| u64::from(u16::from_le_bytes([b[0], b[1]])))
            .ok_or_else(|| "ELF header truncated".to_string())
    };
    let u32_at = |at: usize| -> Result<u64, String> {
        data.get(at..at + 4)
            .map(|b| u64::from(u32::from_le_bytes([b[0], b[1], b[2], b[3]])))
            .ok_or_else(|| "ELF header truncated".to_string())
    };
    let u64_at = |at: usize| -> Result<u64, String> {
        data.get(at..at + 8)
            .map(|b| u64::from_le_bytes(b.try_into().unwrap()))
            .ok_or_else(|| "ELF header truncated".to_string())
    };
    let (entry, phoff, phentsize, phnum) = if is64 {
        (u64_at(0x18)?, u64_at(0x20)?, u16_at(0x36)?, u16_at(0x38)?)
    } else {
        (u32_at(0x18)?, u32_at(0x1c)?, u16_at(0x2a)?, u16_at(0x2c)?)
    };
    const PT_LOAD: u64 = 1;
    let mut out = Vec::new();
    for i in 0..phnum {
        let h = (phoff + i * phentsize) as usize;
        let (kind, offset, vaddr, filesz, memsz, flags) = if is64 {
            (
                u32_at(h)?,
                u64_at(h + 0x08)?,
                u64_at(h + 0x10)?,
                u64_at(h + 0x20)?,
                u64_at(h + 0x28)?,
                u32_at(h + 0x04)?,
            )
        } else {
            (
                u32_at(h)?,
                u32_at(h + 0x04)?,
                u32_at(h + 0x08)?,
                u32_at(h + 0x10)?,
                u32_at(h + 0x14)?,
                u32_at(h + 0x18)?,
            )
        };
        if kind != PT_LOAD {
            continue;
        }
        let (offset, filesz) = (offset as usize, filesz as usize);
        if offset
            .checked_add(filesz)
            .is_none_or(|end| end > data.len())
        {
            return Err("a loadable segment extends past the end of the file".into());
        }
        out.push(Load {
            offset,
            filesz,
            vaddr,
            memsz,
            flags: flags as u32,
        });
    }
    Ok((entry, out))
}

/// The file offset of the ID: just past the one marker inside a loadable segment.
fn id_offset(data: &[u8], segments: &[Load]) -> Result<usize, String> {
    let mut found = Vec::new();
    for s in segments {
        let bytes = &data[s.offset..s.offset + s.filesz];
        let mut at = 0;
        while let Some(i) = bytes[at..].windows(MARKER.len()).position(|w| w == MARKER) {
            found.push(s.offset + at + i + MARKER.len());
            at += i + 1;
        }
    }
    match found.as_slice() {
        [one] if one + LEN <= data.len() => Ok(*one),
        [] => Err("no build ID marker in the image's loadable segments; \
                   is lib/buildid linked and kept by link.ld?"
            .into()),
        [_] => Err("the build ID marker is at the very end of the image".into()),
        many => Err(format!(
            "the build ID marker occurs {} times in the image; refusing to guess which",
            many.len()
        )),
    }
}

/// The ID `data` should carry, whatever it carries now.
pub fn compute(data: &[u8]) -> Result<[u8; LEN], String> {
    let (entry, segments) = loads(data)?;
    let at = id_offset(data, &segments)?;
    let mut h = Sha256::new();
    h.update(b"kintane-build-id-v1\0");
    h.update(&entry.to_le_bytes());
    for s in &segments {
        h.update(&s.vaddr.to_le_bytes());
        h.update(&s.memsz.to_le_bytes());
        h.update(&s.flags.to_le_bytes());
        h.update(&(s.filesz as u64).to_le_bytes());
        let bytes = &data[s.offset..s.offset + s.filesz];
        // The ID's own bytes read as zero, wherever they fall in this segment.
        let (lo, hi) = (at.max(s.offset), (at + LEN).min(s.offset + s.filesz));
        if lo < hi {
            h.update(&bytes[..lo - s.offset]);
            h.update(&[0u8; LEN][..hi - lo]);
            h.update(&bytes[hi - s.offset..]);
        } else {
            h.update(bytes);
        }
    }
    let digest = h.finish();
    let mut id = [0u8; LEN];
    id.copy_from_slice(&digest[..LEN]);
    Ok(id)
}

/// The ID `data` carries now.
#[cfg(test)]
fn stamped(data: &[u8]) -> Result<[u8; LEN], String> {
    let (_, segments) = loads(data)?;
    let at = id_offset(data, &segments)?;
    let mut id = [0u8; LEN];
    id.copy_from_slice(&data[at..at + LEN]);
    Ok(id)
}

/// Stamp `linked`, and record its ID in the symbol bundle `bundle`. Returns the ID in hex.
///
/// The image is rewritten through a new file and a rename, not in place: the linked ELF
/// may be a hard link into the build cache, and the cached artifact stays as the compiler
/// produced it.
pub fn stamp(objcopy: &Path, linked: &Path, bundle: &Path) -> Result<String, String> {
    let mut data = std::fs::read(linked).map_err(|e| format!("{}: {e}", linked.display()))?;
    let id = compute(&data).map_err(|e| format!("{}: {e}", linked.display()))?;
    let (_, segments) = loads(&data)?;
    let at = id_offset(&data, &segments)?;
    data[at..at + LEN].copy_from_slice(&id);
    let tmp = linked.with_extension("stamping");
    std::fs::write(&tmp, &data).map_err(|e| format!("{}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, linked).map_err(|e| format!("{}: {e}", linked.display()))?;

    let raw = bundle.with_extension("build-id");
    std::fs::write(&raw, id).map_err(|e| format!("{}: {e}", raw.display()))?;
    let out = Command::new(objcopy)
        .arg("--remove-section")
        .arg(BUNDLE_SECTION)
        .arg("--add-section")
        .arg(format!("{BUNDLE_SECTION}={}", raw.display()))
        .arg(bundle)
        .output()
        .map_err(|e| format!("cannot run llvm-objcopy: {e}"))?;
    let _ = std::fs::remove_file(&raw);
    if !out.status.success() {
        return Err(format!(
            "recording the build ID in {} failed:\n{}",
            bundle.display(),
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(sha256::hex(&id))
}

/// Every build ID a console log names, in order, as hex.
pub fn in_log(log: &str) -> Vec<String> {
    log.lines()
        .filter_map(|l| {
            let at = l.find("bt build ")?;
            let word = l[at + 9..].split_whitespace().next()?;
            Some(word.to_string())
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal little-endian ELF32 with one PT_LOAD covering the whole file, holding
    /// `payload` at offset 0x54.
    fn elf32(payload: &[u8]) -> Vec<u8> {
        let mut d = vec![0u8; 0x54];
        d[..4].copy_from_slice(b"\x7fELF");
        d[4] = 1; // class 32
        d[5] = 1; // little-endian
        d[0x18..0x1c].copy_from_slice(&0x100000u32.to_le_bytes()); // entry
        d[0x1c..0x20].copy_from_slice(&0x34u32.to_le_bytes()); // phoff
        d[0x2a..0x2c].copy_from_slice(&0x20u16.to_le_bytes()); // phentsize
        d[0x2c..0x2e].copy_from_slice(&1u16.to_le_bytes()); // phnum
        d.extend_from_slice(payload);
        let len = d.len() as u32;
        let ph = 0x34;
        d[ph..ph + 4].copy_from_slice(&1u32.to_le_bytes()); // PT_LOAD
        d[ph + 0x04..ph + 0x08].copy_from_slice(&0u32.to_le_bytes()); // offset
        d[ph + 0x08..ph + 0x0c].copy_from_slice(&0x100000u32.to_le_bytes()); // vaddr
        d[ph + 0x10..ph + 0x14].copy_from_slice(&len.to_le_bytes()); // filesz
        d[ph + 0x14..ph + 0x18].copy_from_slice(&len.to_le_bytes()); // memsz
        d[ph + 0x18..ph + 0x1c].copy_from_slice(&5u32.to_le_bytes()); // R+X
        d
    }

    fn image(code: &[u8]) -> Vec<u8> {
        let mut p = code.to_vec();
        p.extend_from_slice(MARKER);
        p.extend_from_slice(&[0u8; LEN]);
        p.extend_from_slice(b"tail");
        elf32(&p)
    }

    #[test]
    fn stamping_is_idempotent_and_does_not_hash_itself() {
        let mut img = image(b"some code");
        let id = compute(&img).unwrap();
        assert_ne!(id, [0; LEN]);
        let (_, segs) = loads(&img).unwrap();
        let at = id_offset(&img, &segs).unwrap();
        img[at..at + LEN].copy_from_slice(&id);
        assert_eq!(compute(&img).unwrap(), id, "the stamped image hashes to its own ID");
        assert_eq!(stamped(&img).unwrap(), id);
    }

    #[test]
    fn different_code_gets_a_different_id() {
        assert_ne!(compute(&image(b"some code")).unwrap(), compute(&image(b"other code")).unwrap());
    }

    #[test]
    fn a_marker_that_is_missing_or_repeated_is_refused() {
        let none = elf32(b"no marker here at all, not one");
        assert!(compute(&none).unwrap_err().contains("no build ID marker"));
        let mut twice = MARKER.to_vec();
        twice.extend_from_slice(&[0; LEN]);
        twice.extend_from_slice(MARKER);
        twice.extend_from_slice(&[0; LEN]);
        assert!(compute(&elf32(&twice)).unwrap_err().contains("2 times"));
    }

    #[test]
    fn ids_are_found_in_a_log() {
        let log = "backtrace:\r\n  bt build 0011aabb\r\n  bt pc 0x10\nbt build ffee\n";
        assert_eq!(in_log(log), ["0011aabb", "ffee"]);
    }
}

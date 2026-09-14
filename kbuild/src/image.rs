//! `kbuild image --format`: the bootable artifact, in the shape a machine's firmware wants.
//!
//! `kbuild build` already packages the image the configuration's own boot path needs: a
//! multiboot ELF for QEMU's loader, a disk for a KinTane loader. This asks for one of the
//! other shapes the same kernel can take, from the same linked image, without changing
//! the configuration that built it:
//!
//! | Format   | What it is                                                                 |
//! |----------|----------------------------------------------------------------------------|
//! | `elf`    | the stripped ELF, for anything that loads ELF                               |
//! | `bin`    | a flat binary from the lowest load address, for execute-in-place and ROMs   |
//! | `uki`    | the EFI stub's own PE: kernel and command line in one application           |
//! | `uimage` | a U-Boot legacy header in front of `bin`, for boards whose firmware is U-Boot |
//!
//! Every format is a pure function of the linked image and the configuration, so two runs
//! over one tree write the same bytes.

use std::path::{Path, PathBuf};
use std::process::Command;

/// The formats `kbuild image` writes.
pub const FORMATS: &[&str] = &["elf", "bin", "uki", "uimage"];

/// The largest flat binary written. `objcopy -O binary` fills the gap between the lowest
/// and highest load address with zeros, so an image whose segments are far apart becomes
/// a file of that span: refused rather than written.
const MAX_FLAT: u64 = 256 * 1024 * 1024;

pub fn run(root: &Path, opts: &crate::Opts) -> Result<(), String> {
    let format = opts
        .format
        .as_deref()
        .ok_or_else(|| format!("`image` needs --format, one of {}", FORMATS.join(", ")))?;
    if !FORMATS.contains(&format) {
        return Err(format!("unknown image format `{format}`; one of {}", FORMATS.join(", ")));
    }
    let (packaged, res) = crate::do_build(root, opts)?;
    let out = packaged
        .parent()
        .ok_or("the build wrote its image nowhere")?
        .to_path_buf();
    let linked = out.join("kintane.elf");
    let objcopy = crate::toolchain::verify(root)?.tool("llvm-objcopy")?;

    let dest = match format {
        "elf" => {
            let dest = out.join("kintane.img.elf");
            objcopy_to(&objcopy, &["--strip-all"], &linked, &dest)?;
            dest
        }
        "bin" => flat(&objcopy, &linked, &out.join("kintane.bin"))?,
        "uki" => {
            if !res.is_on("KINBOOT_STUB") {
                return Err("a UKI is the EFI stub's image, and this configuration has no stub; \
                     build with --set KINBOOT_STUB=y (x86_64)"
                    .into());
            }
            let stub = out.join("kintane.efi");
            let dest = out.join("kintane.uki.efi");
            std::fs::copy(&stub, &dest).map_err(|e| format!("{}: {e}", stub.display()))?;
            dest
        }
        "uimage" => {
            let bin = flat(&objcopy, &linked, &out.join("kintane.bin"))?;
            let elf = std::fs::read(&linked).map_err(|e| format!("{}: {e}", linked.display()))?;
            let (entry, load) = entry_and_load(&elf)?;
            let payload = std::fs::read(&bin).map_err(|e| format!("{}: {e}", bin.display()))?;
            let target = res.str("TARGET");
            let header = UImage {
                arch: uimage_arch(target)?,
                load: u32::try_from(load)
                    .map_err(|_| format!("load address {load:#x} does not fit a uImage"))?,
                entry: u32::try_from(entry)
                    .map_err(|_| format!("entry point {entry:#x} does not fit a uImage"))?,
                name: &format!("KinTane {target}"),
            };
            let dest = out.join("kintane.uimage");
            std::fs::write(&dest, uimage(&header, &payload)?)
                .map_err(|e| format!("{}: {e}", dest.display()))?;
            dest
        }
        _ => unreachable!("checked against FORMATS above"),
    };
    let size = std::fs::metadata(&dest).map(|m| m.len()).unwrap_or(0);
    println!("  {format:7} {} ({size} bytes)", dest.display());
    Ok(())
}

fn objcopy_to(objcopy: &Path, flags: &[&str], from: &Path, to: &Path) -> Result<(), String> {
    let out = Command::new(objcopy)
        .args(flags)
        .arg(from)
        .arg(to)
        .output()
        .map_err(|e| format!("cannot run llvm-objcopy: {e}"))?;
    if !out.status.success() {
        return Err(format!("llvm-objcopy failed:\n{}", String::from_utf8_lossy(&out.stderr)));
    }
    Ok(())
}

/// The image as a flat binary starting at its lowest load address.
fn flat(objcopy: &Path, linked: &Path, dest: &Path) -> Result<PathBuf, String> {
    objcopy_to(objcopy, &["-O", "binary"], linked, dest)?;
    let size = std::fs::metadata(dest).map(|m| m.len()).unwrap_or(0);
    if size > MAX_FLAT {
        let _ = std::fs::remove_file(dest);
        return Err(format!(
            "a flat binary of this image would be {size} bytes: its segments are too far apart \
             for `bin`, which fills the gap with zeros. Use `elf`."
        ));
    }
    Ok(dest.to_path_buf())
}

/// The ELF entry point and lowest physical load address, from either class of ELF.
///
/// Physical, because a flat binary starts at the lowest load (physical) address of a
/// section with contents, and a board loads it there.
pub fn entry_and_load(elf: &[u8]) -> Result<(u64, u64), String> {
    let short = || "the kernel image is too short to be an ELF".to_string();
    if elf.get(..4) != Some(b"\x7fELF") {
        return Err("the kernel image is not an ELF".into());
    }
    let le = elf.get(5) == Some(&1);
    if !le {
        return Err("only little-endian ELF images are packaged".into());
    }
    let u16_at = |at: usize| {
        elf.get(at..at + 2)
            .map(|b| u16::from_le_bytes([b[0], b[1]]))
    };
    let u32_at = |at: usize| {
        elf.get(at..at + 4)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    };
    let u64_at = |at: usize| {
        elf.get(at..at + 8)
            .and_then(|b| b.try_into().ok())
            .map(u64::from_le_bytes)
    };
    // (entry, phoff, phentsize, phnum, paddr offset, memsz offset, word)
    let (entry, phoff, phentsize, phnum, paddr_at, memsz_at, wide) = match elf.get(4) {
        Some(1) => (
            u64::from(u32_at(24).ok_or_else(short)?),
            u64::from(u32_at(28).ok_or_else(short)?),
            u16_at(42).ok_or_else(short)?,
            u16_at(44).ok_or_else(short)?,
            12,
            20,
            false,
        ),
        Some(2) => (
            u64_at(24).ok_or_else(short)?,
            u64_at(32).ok_or_else(short)?,
            u16_at(54).ok_or_else(short)?,
            u16_at(56).ok_or_else(short)?,
            24,
            40,
            true,
        ),
        _ => return Err("the kernel image is neither a 32- nor a 64-bit ELF".into()),
    };
    let word = |at: usize| -> Option<u64> {
        if wide {
            u64_at(at)
        } else {
            u32_at(at).map(u64::from)
        }
    };
    let mut load = u64::MAX;
    for i in 0..usize::from(phnum) {
        let ph = usize::try_from(phoff).map_err(|_| short())? + i * usize::from(phentsize);
        const PT_LOAD: u32 = 1;
        if u32_at(ph).ok_or_else(short)? != PT_LOAD {
            continue;
        }
        if word(ph + memsz_at).ok_or_else(short)? == 0 {
            continue;
        }
        load = load.min(word(ph + paddr_at).ok_or_else(short)?);
    }
    if load == u64::MAX {
        return Err("the kernel image has no loadable segment".into());
    }
    Ok((entry, load))
}

/// The fields of a U-Boot legacy image header this writes.
pub struct UImage<'a> {
    pub arch: u8,
    pub load: u32,
    pub entry: u32,
    pub name: &'a str,
}

/// `IH_MAGIC`.
const UIMAGE_MAGIC: u32 = 0x2705_1956;
/// `IH_TYPE_STANDALONE`: U-Boot copies the payload to the load address and jumps to the
/// entry point, handing over nothing. That is what a KinTane image on a board without a
/// KinTane loader expects: its boot information is built into the image at build time.
const IH_TYPE_STANDALONE: u8 = 1;
/// `IH_OS_U_BOOT`: the operating-system field U-Boot's own standalone applications use.
const IH_OS_U_BOOT: u8 = 17;
/// `IH_COMP_NONE`.
const IH_COMP_NONE: u8 = 0;
/// Bytes in the header.
pub const UIMAGE_HEADER: usize = 64;

/// U-Boot's `IH_ARCH_*` for a KinTane target.
pub fn uimage_arch(target: &str) -> Result<u8, String> {
    Ok(match target.split('-').next().unwrap_or("") {
        "armv7m" => 2,                // IH_ARCH_ARM
        "i686" => 3,                  // IH_ARCH_I386
        "aarch64" => 22,              // IH_ARCH_ARM64
        "x86_64" => 24,               // IH_ARCH_X86_64
        "riscv32" | "riscv32i" => 26, // IH_ARCH_RISCV
        other => return Err(format!("no U-Boot architecture is known for target `{other}`")),
    })
}

/// A U-Boot legacy image: the 64-byte big-endian header, then `payload`.
///
/// The timestamp is zero rather than the clock, so the image is reproducible; U-Boot
/// prints it and does not act on it.
pub fn uimage(h: &UImage<'_>, payload: &[u8]) -> Result<Vec<u8>, String> {
    let size = u32::try_from(payload.len())
        .map_err(|_| format!("a {}-byte payload does not fit a uImage", payload.len()))?;
    let mut header = [0u8; UIMAGE_HEADER];
    header[0..4].copy_from_slice(&UIMAGE_MAGIC.to_be_bytes());
    // ih_hcrc stays zero until the rest of the header is written.
    header[8..12].copy_from_slice(&0u32.to_be_bytes());
    header[12..16].copy_from_slice(&size.to_be_bytes());
    header[16..20].copy_from_slice(&h.load.to_be_bytes());
    header[20..24].copy_from_slice(&h.entry.to_be_bytes());
    header[24..28].copy_from_slice(&crate::bios::disk::crc32(payload).to_be_bytes());
    header[28] = IH_OS_U_BOOT;
    header[29] = h.arch;
    header[30] = IH_TYPE_STANDALONE;
    header[31] = IH_COMP_NONE;
    let name = h.name.as_bytes();
    // At most 31 bytes, so the field always ends in the NUL U-Boot's printing expects.
    let n = name.len().min(31);
    header[32..32 + n].copy_from_slice(&name[..n]);
    let hcrc = crate::bios::disk::crc32(&header);
    header[4..8].copy_from_slice(&hcrc.to_be_bytes());

    let mut image = header.to_vec();
    image.extend_from_slice(payload);
    Ok(image)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bios::disk::crc32;

    fn be32(b: &[u8], at: usize) -> u32 {
        u32::from_be_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
    }

    #[test]
    fn a_uimage_header_describes_its_payload_and_checks_itself() {
        let payload: Vec<u8> = (0..300u32).map(|i| i as u8).collect();
        let h = UImage {
            arch: 2,
            load: 0x0000_0000,
            entry: 0x0000_0101,
            name: "KinTane armv7m-kintane",
        };
        let img = uimage(&h, &payload).unwrap();
        assert_eq!(img.len(), UIMAGE_HEADER + payload.len());
        assert_eq!(be32(&img, 0), UIMAGE_MAGIC);
        assert_eq!(be32(&img, 12), payload.len() as u32, "ih_size");
        assert_eq!(be32(&img, 16), 0, "ih_load");
        assert_eq!(be32(&img, 20), 0x101, "ih_ep");
        assert_eq!(be32(&img, 24), crc32(&payload), "ih_dcrc is the payload's CRC");
        assert_eq!((img[28], img[29], img[30], img[31]), (IH_OS_U_BOOT, 2, IH_TYPE_STANDALONE, 0));
        assert_eq!(&img[32..54], b"KinTane armv7m-kintane");
        assert_eq!(img[63], 0, "the name field always ends in NUL");

        // The header CRC is over the header with ih_hcrc zero, as U-Boot recomputes it.
        let mut zeroed = img[..UIMAGE_HEADER].to_vec();
        zeroed[4..8].copy_from_slice(&[0; 4]);
        assert_eq!(be32(&img, 4), crc32(&zeroed));
        assert_eq!(&img[UIMAGE_HEADER..], &payload[..]);
    }

    #[test]
    fn a_corrupt_payload_no_longer_matches_its_header() {
        let img = uimage(
            &UImage {
                arch: 26,
                load: 0x8000_0000,
                entry: 0x8000_0000,
                name: "x",
            },
            b"kernel",
        )
        .unwrap();
        let mut bad = img.clone();
        bad[UIMAGE_HEADER] ^= 1;
        assert_ne!(be32(&bad, 24), crc32(&bad[UIMAGE_HEADER..]));
    }

    #[test]
    fn a_long_name_is_cut_to_fit_with_its_terminator() {
        let long = "K".repeat(80);
        let img = uimage(
            &UImage {
                arch: 2,
                load: 0,
                entry: 0,
                name: &long,
            },
            b"",
        )
        .unwrap();
        assert!(img[32..63].iter().all(|&b| b == b'K'));
        assert_eq!(img[63], 0);
    }

    #[test]
    fn every_kintane_target_has_a_uboot_architecture() {
        for (t, arch) in [
            ("armv7m-kintane", 2),
            ("i686-kintane", 3),
            ("aarch64-kintane", 22),
            ("x86_64-kintane", 24),
            ("riscv32-kintane", 26),
            ("riscv32i-kintane", 26),
        ] {
            assert_eq!(uimage_arch(t).unwrap(), arch, "{t}");
        }
        assert!(uimage_arch("m68k-kintane").is_err());
    }

    /// An ELF with one load segment at `paddr`, of the given class.
    fn elf(class: u8, entry: u64, paddr: u64) -> Vec<u8> {
        let mut v = vec![0u8; 256];
        v[..4].copy_from_slice(b"\x7fELF");
        v[4] = class;
        v[5] = 1;
        if class == 2 {
            v[24..32].copy_from_slice(&entry.to_le_bytes());
            v[32..40].copy_from_slice(&64u64.to_le_bytes());
            v[54..56].copy_from_slice(&56u16.to_le_bytes());
            v[56..58].copy_from_slice(&1u16.to_le_bytes());
            let ph = 64;
            v[ph..ph + 4].copy_from_slice(&1u32.to_le_bytes());
            v[ph + 24..ph + 32].copy_from_slice(&paddr.to_le_bytes());
            v[ph + 40..ph + 48].copy_from_slice(&0x1000u64.to_le_bytes());
        } else {
            v[24..28].copy_from_slice(&(entry as u32).to_le_bytes());
            v[28..32].copy_from_slice(&52u32.to_le_bytes());
            v[42..44].copy_from_slice(&32u16.to_le_bytes());
            v[44..46].copy_from_slice(&1u16.to_le_bytes());
            let ph = 52;
            v[ph..ph + 4].copy_from_slice(&1u32.to_le_bytes());
            v[ph + 12..ph + 16].copy_from_slice(&(paddr as u32).to_le_bytes());
            v[ph + 20..ph + 24].copy_from_slice(&0x1000u32.to_le_bytes());
        }
        v
    }

    #[test]
    fn entry_and_load_read_both_classes_of_elf() {
        assert_eq!(
            entry_and_load(&elf(2, 0x4020_0000, 0x4020_0000)).unwrap(),
            (0x4020_0000, 0x4020_0000)
        );
        assert_eq!(entry_and_load(&elf(1, 0x101, 0x0)).unwrap(), (0x101, 0));
        assert!(entry_and_load(b"not an elf").is_err());
    }
}

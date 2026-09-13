//! `kinboot-bios`: building the BIOS loader and writing a bootable disk image.
//!
//! Selected by `KINBOOT_BIOS`. The kernel is built exactly as for `-kernel` boots, and
//! then this module:
//!
//! 1. builds the loader for its own target, `targets/i686-kinboot.json` (i486, no SSE, no x87),
//!    with its own `core`: the loader must run on machines the kernel's target would fault on
//!    before the first instruction it cares about;
//! 2. turns the linked loader into the flat binary the disk starts with, and checks its layout:
//!    exactly one sector of stage 1 with the table and signature where the disk format puts them,
//!    and stage 2 within its budget;
//! 3. writes `kinboot-bios.img`: stage 1 with its table and a partition entry, stage 2 with its
//!    header, and the kernel image with its CRC-32.
//!
//! The layout constants and the header encoding are not repeated here. They are
//! `boot/kinboot-bios/src/disk.rs`, included below by path, which is also what the
//! loader reads them from.
//!
//! The loader is not a unit of the kernel's graph. Everything in the graph is built for
//! the configuration's target and linked by its script, and the loader needs a different
//! target, a different link address and a different `core`. So it is built here, from a
//! unit description made on the spot, through the same `Build` machinery and cache.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::build::{Build, Built, Target};
use crate::cache::Cache;
use crate::graph::{self, Kind, Unit};
use crate::kcfg::Resolution;
use crate::sha256::Sha256;
use crate::toolchain::Toolchain;

#[allow(dead_code)] // the loader uses parts of the layout the writer does not
#[path = "../../boot/kinboot-bios/src/disk.rs"]
mod disk;

/// The configuration symbol that selects this boot path.
pub const SYMBOL: &str = "KINBOOT_BIOS";

/// Where the loader's sources live, relative to the tree root.
const LOADER_DIR: &str = "boot/kinboot-bios";

/// Build the loader and write the disk image for `kernel`, returning the image's path.
pub fn disk_image(
    root: &Path,
    tc: Toolchain,
    res: &Resolution,
    kernel: &Path,
    verbose: bool,
) -> Result<PathBuf, String> {
    let target_dir = root.join("build").join(res.str("TARGET"));
    let loader_elf = build_loader(root, tc.clone(), &target_dir, verbose)?;

    let flat = target_dir.join("kinboot-bios/kinboot-bios.bin");
    let objcopy = tc.tool("llvm-objcopy")?;
    let out = std::process::Command::new(&objcopy)
        .args(["-O", "binary"])
        .arg(&loader_elf)
        .arg(&flat)
        .output()
        .map_err(|e| format!("cannot run llvm-objcopy: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "flattening kinboot-bios failed:\n{}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    let loader = std::fs::read(&flat).map_err(|e| format!("{}: {e}", flat.display()))?;
    let kernel_bytes = std::fs::read(kernel).map_err(|e| format!("{}: {e}", kernel.display()))?;

    let image = assemble(&loader, &kernel_bytes, b"")?;
    let dest = target_dir.join("out/kinboot-bios.img");
    std::fs::write(&dest, &image).map_err(|e| format!("{}: {e}", dest.display()))?;
    println!(
        "  loader  {} ({} bytes of stage 2)",
        flat.display(),
        loader.len().saturating_sub(disk::SECTOR)
    );
    Ok(dest)
}

/// Compile `core`, `compiler_builtins`, the `kinboot-bios` crate and the loader binary
/// for the loader's target.
fn build_loader(
    root: &Path,
    tc: Toolchain,
    target_dir: &Path,
    verbose: bool,
) -> Result<PathBuf, String> {
    let out = target_dir.join("kinboot-bios");
    std::fs::create_dir_all(&out).map_err(|e| format!("{}: {e}", out.display()))?;
    let dir = root.join(LOADER_DIR);

    let b = Build {
        root: root.to_path_buf(),
        tc,
        target_name: "i686-kinboot".into(),
        target: Target::Spec(root.join("targets/i686-kinboot.json")),
        out: out.clone(),
        gen_dir: out.join("gen"),
        cache: Cache::new(root.join("build/cache"))?,
        // The loader reads no kernel configuration, so it gets none: a `cfg` it could
        // see would be a way for kernel settings to change the boot sector.
        cfgs: Vec::new(),
        check_cfgs: Vec::new(),
        // Size, not speed: stage 2 has a 32 KiB budget and spends its time in the BIOS.
        opt_level: "s".into(),
        link_script: Some(dir.join("loader/link.ld")),
        deny_warnings: true,
        verbose,
    };

    let units = graph::discover(root)?;
    let find = |name: &str| {
        units
            .iter()
            .find(|u| u.name == name)
            .ok_or_else(|| format!("no `{name}` unit in the tree"))
    };

    let mut built: BTreeMap<String, Built> = BTreeMap::new();
    built.insert("core".into(), b.build_core()?);
    let cb = find("compiler_builtins")?;
    built.insert(cb.name.clone(), b.build_unit(cb, &built)?);
    let logic = find("kinboot-bios")?;
    built.insert(logic.name.clone(), b.build_unit(logic, &built)?);

    let loader = Unit {
        name: "kinboot-bios-loader".into(),
        kind: Kind::Bin,
        dir: dir.clone(),
        root: PathBuf::from("loader/main.rs"),
        deps: vec!["kinboot-bios".into()],
        layer: "kernel".into(),
        requires: None,
        rustflags: Vec::new(),
        host_tests: false,
        manifest: dir.join("kmod.toml"),
    };
    Ok(b.build_unit(&loader, &built)?.path)
}

/// Lay out a disk: the flattened loader, then the kernel.
///
/// `loader` is the loader's flat binary: stage 1's sector followed by stage 2.
pub fn assemble(loader: &[u8], kernel: &[u8], cmdline: &[u8]) -> Result<Vec<u8>, String> {
    let sector = disk::SECTOR;
    if loader.len() <= sector {
        return Err("kinboot-bios: the loader has no stage 2".into());
    }
    let (stage1, stage2) = loader.split_at(sector);
    let mut mbr = stage1.to_vec();
    if mbr[510..512] != [0x55, 0xAA] {
        return Err("kinboot-bios: stage 1 does not end in the 0x55AA signature".into());
    }
    if mbr[disk::MBR_CODE_BYTES..510].iter().any(|&b| b != 0) {
        return Err(
            "kinboot-bios: stage 1 writes into the disk signature or partition table".into()
        );
    }

    let stage2_sectors = disk::sectors_for(stage2.len());
    if stage2_sectors > disk::STAGE2_MAX_SECTORS as usize {
        return Err(format!(
            "kinboot-bios: stage 2 is {} bytes, over its {} KiB budget",
            stage2.len(),
            disk::STAGE2_MAX_SECTORS as usize * sector / 1024
        ));
    }
    disk::Stage1Table {
        stage2_lba: disk::STAGE2_LBA,
        stage2_sectors: stage2_sectors as u16,
    }
    .write(&mut mbr)
    .map_err(|e| format!("kinboot-bios: stage 1 table not where the disk format expects: {e:?}"))?;

    let kernel_lba = disk::STAGE2_LBA as usize + stage2_sectors;
    let kernel_len = u32::try_from(kernel.len())
        .map_err(|_| "kinboot-bios: the kernel image is over 4 GiB".to_string())?;
    let mut stage2 = stage2.to_vec();
    stage2.resize(stage2_sectors * sector, 0);
    disk::Header {
        kernel_lba: kernel_lba as u32,
        kernel_bytes: kernel_len,
        kernel_crc32: disk::crc32(kernel),
        cmdline: disk::Header::cmdline_from(cmdline)
            .map_err(|_| "kinboot-bios: command line too long".to_string())?,
    }
    .write(&mut stage2)
    .map_err(|e| {
        format!("kinboot-bios: stage 2 header not where the disk format expects: {e:?}")
    })?;

    // Whole cylinders of 16 heads and 63 sectors: the geometry BIOSes assume for a small
    // LBA disk. An image smaller than one cylinder has zero cylinders, and SeaBIOS on
    // q35 refuses to read such a disk at all ("could not read the boot disk"). Found
    // by booting x86_64-bios, whose first image was 270 sectors.
    const CYLINDER: usize = 16 * 63;
    let total_sectors = (kernel_lba + disk::sectors_for(kernel.len())).next_multiple_of(CYLINDER);

    // A disk signature that is a function of the contents, so the image is reproducible
    // and two different builds do not claim to be the same disk.
    let mut h = Sha256::new();
    h.update(&stage2);
    h.update(kernel);
    let digest = h.finish();
    mbr[disk::DISK_SIGNATURE_OFFSET..disk::DISK_SIGNATURE_OFFSET + 4].copy_from_slice(&digest[..4]);

    // One partition covering stage 2 and the kernel, marked active. CHS fields hold the
    // "use LBA" sentinel, which every partitioning tool of the last 25 years honours.
    let p = &mut mbr[disk::PARTITION_TABLE_OFFSET..disk::PARTITION_TABLE_OFFSET + 16];
    p[0] = 0x80;
    p[1..4].copy_from_slice(&[0xFE, 0xFF, 0xFF]);
    p[4] = disk::PARTITION_TYPE;
    p[5..8].copy_from_slice(&[0xFE, 0xFF, 0xFF]);
    p[8..12].copy_from_slice(&disk::STAGE2_LBA.to_le_bytes());
    p[12..16].copy_from_slice(&((total_sectors - 1) as u32).to_le_bytes());

    let mut image = Vec::with_capacity(total_sectors * sector);
    image.extend_from_slice(&mbr);
    image.extend_from_slice(&stage2);
    image.extend_from_slice(kernel);
    image.resize(total_sectors * sector, 0);
    Ok(image)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A loader image shaped like the real one: stage 1 with its table magic and
    /// signature, stage 2 with its header magic.
    fn loader(stage2_len: usize) -> Vec<u8> {
        let mut l = vec![0u8; 512 + stage2_len];
        l[..4].copy_from_slice(&[0xFA, 0x31, 0xC0, 0x8E]);
        l[disk::STAGE1_TABLE_OFFSET..disk::STAGE1_TABLE_OFFSET + 4]
            .copy_from_slice(&disk::STAGE1_MAGIC);
        l[510] = 0x55;
        l[511] = 0xAA;
        let h = 512 + disk::STAGE2_HEADER_OFFSET;
        l[h..h + 4].copy_from_slice(&disk::STAGE2_MAGIC);
        l
    }

    #[test]
    fn layout_is_what_the_loader_reads() {
        let kernel: Vec<u8> = (0..3000u32).map(|i| i as u8).collect();
        let img = assemble(&loader(1500), &kernel, b"mode=safe").unwrap();

        // Stage 2 is three sectors, so the kernel starts at LBA 4 and takes six; the disk
        // is then padded to one whole cylinder.
        assert_eq!(img.len(), 1008 * 512);
        assert_eq!(&img[424 + 4..424 + 10], &[1, 0, 0, 0, 3, 0]);
        let header = disk::Header::parse(&img[512 + disk::STAGE2_HEADER_OFFSET..]).unwrap();
        assert_eq!(header.kernel_lba, 4);
        assert_eq!(header.kernel_bytes, 3000);
        assert_eq!(header.kernel_crc32, disk::crc32(&kernel));
        assert_eq!(&header.cmdline[..10], b"mode=safe\0");
        assert_eq!(&img[4 * 512..4 * 512 + 3000], &kernel[..]);

        // The partition entry covers everything after the MBR.
        assert_eq!(img[446], 0x80);
        assert_eq!(img[450], disk::PARTITION_TYPE);
        assert_eq!(&img[454..462], &[1, 0, 0, 0, 0xEF, 3, 0, 0]);
        assert!(img[4 * 512 + 3000..].iter().all(|&b| b == 0));
        assert_eq!(&img[510..512], &[0x55, 0xAA]);
    }

    #[test]
    fn identical_inputs_give_identical_disks() {
        let a = assemble(&loader(600), b"kernel", b"").unwrap();
        let b = assemble(&loader(600), b"kernel", b"").unwrap();
        assert_eq!(a, b);
        let c = assemble(&loader(600), b"kernel!", b"").unwrap();
        assert_ne!(a[440..444], c[440..444], "the disk signature follows the contents");
    }

    #[test]
    fn layout_violations_are_refused() {
        let k = b"kernel";
        assert!(
            assemble(&loader(600)[..512], k, b"")
                .unwrap_err()
                .contains("no stage 2")
        );

        let mut l = loader(600);
        l[511] = 0;
        assert!(assemble(&l, k, b"").unwrap_err().contains("0x55AA"));

        let mut l = loader(600);
        l[446] = 1;
        assert!(
            assemble(&l, k, b"")
                .unwrap_err()
                .contains("partition table")
        );

        let mut l = loader(600);
        l[disk::STAGE1_TABLE_OFFSET] = 0;
        assert!(assemble(&l, k, b"").unwrap_err().contains("stage 1 table"));

        let mut l = loader(600);
        l[512 + disk::STAGE2_HEADER_OFFSET] = 0;
        assert!(assemble(&l, k, b"").unwrap_err().contains("stage 2 header"));

        let over = loader(disk::STAGE2_MAX_SECTORS as usize * 512 + 1);
        assert!(assemble(&over, k, b"").unwrap_err().contains("budget"));
        let at_limit = loader(disk::STAGE2_MAX_SECTORS as usize * 512);
        assert!(assemble(&at_limit, k, b"").is_ok());
    }
}

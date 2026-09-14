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
//!    header, the boot entries (`crate::bootcfg`) and the kernel image, each with its CRC-32;
//! 4. with `CHAIN_TEST`, also builds the chainload test record (`loader/chaintest.rs`) and writes
//!    it as partition 2, which the test entry chainloads.
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
pub(crate) mod disk;

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
    let chain_test = res.is_on("CHAIN_TEST");
    let (loader_elf, chain_elf) = build_loader(root, tc.clone(), &target_dir, chain_test, verbose)?;

    let objcopy = tc.tool("llvm-objcopy")?;
    let flatten = |elf: &Path, name: &str| -> Result<Vec<u8>, String> {
        let flat = target_dir.join("kinboot-bios").join(name);
        let out = std::process::Command::new(&objcopy)
            .args(["-O", "binary"])
            .arg(elf)
            .arg(&flat)
            .output()
            .map_err(|e| format!("cannot run llvm-objcopy: {e}"))?;
        if !out.status.success() {
            return Err(format!(
                "flattening {name} failed:\n{}",
                String::from_utf8_lossy(&out.stderr)
            ));
        }
        std::fs::read(&flat).map_err(|e| format!("{}: {e}", flat.display()))
    };
    let loader = flatten(&loader_elf, "kinboot-bios.bin")?;
    let chain = chain_elf
        .map(|elf| flatten(&elf, "chaintest.bin"))
        .transpose()?;
    let kernel_bytes = std::fs::read(kernel).map_err(|e| format!("{}: {e}", kernel.display()))?;
    let entries =
        crate::bootcfg::entry_list(res, crate::bootcfg::Chain::Partition(CHAIN_PARTITION));

    let image = assemble(&loader, &kernel_bytes, entries.as_bytes(), chain.as_deref())?;
    let dest = target_dir.join("out/kinboot-bios.img");
    std::fs::write(&dest, &image).map_err(|e| format!("{}: {e}", dest.display()))?;
    println!(
        "  loader  kinboot-bios ({} bytes of stage 2)",
        loader.len().saturating_sub(disk::SECTOR)
    );
    Ok(dest)
}

/// The partition the chainload test record is written to, and the test entry boots.
const CHAIN_PARTITION: u8 = 2;
/// Partition type for the test record's partition: `0x7F`, reserved for "alternative OS
/// development", so no tool mistakes it for a filesystem.
const CHAIN_PARTITION_TYPE: u8 = 0x7F;
/// The drive the loader is started from under QEMU, which the test record requires in
/// `DL`: the first hard disk.
const CHAIN_TEST_DRIVE: u8 = 0x80;
/// Where the test record's table sits: `"KBCT"`, the expected drive, the expected LBA.
const CHAIN_TABLE_OFFSET: usize = 0x1A0;

/// Compile `core`, `compiler_builtins`, the loader's crates and the loader binary for the
/// loader's target, and with `chain_test` the chainload test record too.
fn build_loader(
    root: &Path,
    tc: Toolchain,
    target_dir: &Path,
    chain_test: bool,
    verbose: bool,
) -> Result<(PathBuf, Option<PathBuf>), String> {
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
        bitcode: false,
        pic: false,
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
    // In dependency order: each is built against the ones before it.
    for name in [
        "compiler_builtins",
        "boot_protocol",
        "cmdline",
        "kinboot-bios",
        "kinboot-menu",
    ] {
        let unit = find(name)?;
        built.insert(unit.name.clone(), b.build_unit(unit, &built)?);
    }

    let loader = Unit {
        name: "kinboot-bios-loader".into(),
        kind: Kind::Bin,
        dir: dir.clone(),
        root: PathBuf::from("loader/main.rs"),
        deps: vec![
            "kinboot-bios".into(),
            "kinboot-menu".into(),
            "cmdline".into(),
            "boot_protocol".into(),
        ],
        layer: "kernel".into(),
        requires: None,
        rustflags: Vec::new(),
        host_tests: false,
        manifest: dir.join("kmod.toml"),
        // Built by the `Build` above for `targets/i686-kinboot.json`, not through the
        // per-unit `target` mechanism, which covers only targets built into rustc.
        target: None,
        hard_float: false,
    };
    let loader = b.build_unit(&loader, &built)?.path;
    if !chain_test {
        return Ok((loader, None));
    }

    // Same target, same `core`, its own link script: one sector at 0x7C00.
    let chain_build = Build {
        link_script: Some(dir.join("loader/chaintest.ld")),
        root: b.root.clone(),
        tc: b.tc.clone(),
        target_name: b.target_name.clone(),
        target: Target::Spec(root.join("targets/i686-kinboot.json")),
        out: b.out.clone(),
        gen_dir: b.gen_dir.clone(),
        cache: Cache::new(root.join("build/cache"))?,
        cfgs: Vec::new(),
        check_cfgs: Vec::new(),
        opt_level: "s".into(),
        deny_warnings: true,
        bitcode: false,
        pic: false,
        verbose,
    };
    let chaintest = Unit {
        name: "kinboot-bios-chaintest".into(),
        kind: Kind::Bin,
        dir: dir.clone(),
        root: PathBuf::from("loader/chaintest.rs"),
        deps: Vec::new(),
        layer: "kernel".into(),
        requires: None,
        rustflags: Vec::new(),
        host_tests: false,
        manifest: dir.join("kmod.toml"),
        target: None,
        hard_float: false,
    };
    let chaintest = chain_build.build_unit(&chaintest, &built)?.path;
    Ok((loader, Some(chaintest)))
}

/// Lay out a disk: the flattened loader, the boot entries, the kernel, and optionally the
/// chainload test record as partition 2.
///
/// `loader` is the loader's flat binary: stage 1's sector followed by stage 2.
pub fn assemble(
    loader: &[u8],
    kernel: &[u8],
    entries: &[u8],
    chain: Option<&[u8]>,
) -> Result<Vec<u8>, String> {
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

    if entries.len() > disk::CONFIG_MAX_BYTES {
        return Err(format!(
            "kinboot-bios: the boot entries are {} bytes, over the {} the loader reads",
            entries.len(),
            disk::CONFIG_MAX_BYTES
        ));
    }
    let config_lba = disk::STAGE2_LBA as usize + stage2_sectors;
    let kernel_lba = config_lba + disk::sectors_for(entries.len());
    let kernel_len = u32::try_from(kernel.len())
        .map_err(|_| "kinboot-bios: the kernel image is over 4 GiB".to_string())?;
    let mut stage2 = stage2.to_vec();
    stage2.resize(stage2_sectors * sector, 0);
    disk::Header {
        kernel_lba: kernel_lba as u32,
        kernel_bytes: kernel_len,
        kernel_crc32: disk::crc32(kernel),
        config_lba: config_lba as u32,
        config_bytes: entries.len() as u32,
        config_crc32: disk::crc32(entries),
    }
    .write(&mut stage2)
    .map_err(|e| {
        format!("kinboot-bios: stage 2 header not where the disk format expects: {e:?}")
    })?;

    let chain_lba = kernel_lba + disk::sectors_for(kernel.len());
    let chain = chain
        .map(|record| chain_record(record, chain_lba as u32))
        .transpose()?;

    // Whole cylinders of 16 heads and 63 sectors: the geometry BIOSes assume for a small
    // LBA disk. An image smaller than one cylinder has zero cylinders, and SeaBIOS on
    // q35 refuses to read such a disk at all ("could not read the boot disk"). Found
    // by booting x86_64-bios, whose first image was 270 sectors.
    const CYLINDER: usize = 16 * 63;
    let used = chain_lba + usize::from(chain.is_some());
    let total_sectors = used.next_multiple_of(CYLINDER);

    // A disk signature that is a function of the contents, so the image is reproducible
    // and two different builds do not claim to be the same disk.
    let mut h = Sha256::new();
    h.update(&stage2);
    h.update(entries);
    h.update(kernel);
    if let Some(record) = &chain {
        h.update(record);
    }
    let digest = h.finish();
    mbr[disk::DISK_SIGNATURE_OFFSET..disk::DISK_SIGNATURE_OFFSET + 4].copy_from_slice(&digest[..4]);

    // One partition covering stage 2, the entries and the kernel, marked active, and with a
    // chain test a second one holding just its record. CHS fields hold the "use LBA"
    // sentinel, which every partitioning tool of the last 25 years honours.
    let mut partition = |index: usize, active: bool, kind: u8, start: u32, sectors: u32| {
        let at = disk::PARTITION_TABLE_OFFSET + index * disk::PARTITION_ENTRY_BYTES;
        let p = &mut mbr[at..at + disk::PARTITION_ENTRY_BYTES];
        p[0] = if active { 0x80 } else { 0 };
        p[1..4].copy_from_slice(&[0xFE, 0xFF, 0xFF]);
        p[4] = kind;
        p[5..8].copy_from_slice(&[0xFE, 0xFF, 0xFF]);
        p[8..12].copy_from_slice(&start.to_le_bytes());
        p[12..16].copy_from_slice(&sectors.to_le_bytes());
    };
    let first_end = if chain.is_some() {
        chain_lba
    } else {
        total_sectors
    };
    partition(0, true, disk::PARTITION_TYPE, disk::STAGE2_LBA, (first_end - 1) as u32);
    if chain.is_some() {
        partition(
            usize::from(CHAIN_PARTITION) - 1,
            false,
            CHAIN_PARTITION_TYPE,
            chain_lba as u32,
            1,
        );
    }

    let mut image = Vec::with_capacity(total_sectors * sector);
    image.extend_from_slice(&mbr);
    image.extend_from_slice(&stage2);
    image.extend_from_slice(entries);
    image.resize(kernel_lba * sector, 0);
    image.extend_from_slice(kernel);
    if let Some(record) = &chain {
        image.resize(chain_lba * sector, 0);
        image.extend_from_slice(record);
    }
    image.resize(total_sectors * sector, 0);
    Ok(image)
}

/// The chain test record with its table filled in: the drive and LBA it must be entered
/// with.
fn chain_record(record: &[u8], lba: u32) -> Result<Vec<u8>, String> {
    if record.len() != disk::SECTOR || record[510..512] != [0x55, 0xAA] {
        return Err("kinboot-bios: the chain test record is not one signed sector".into());
    }
    let mut record = record.to_vec();
    let t = &mut record[CHAIN_TABLE_OFFSET..CHAIN_TABLE_OFFSET + 9];
    if t[..4] != *b"KBCT" {
        return Err(
            "kinboot-bios: the chain test record's table is not where kbuild expects".into()
        );
    }
    t[4] = CHAIN_TEST_DRIVE;
    t[5..9].copy_from_slice(&lba.to_le_bytes());
    Ok(record)
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

    const ENTRIES: &[u8] = b"entry normal\nmode safe\n";

    #[test]
    fn layout_is_what_the_loader_reads() {
        let kernel: Vec<u8> = (0..3000u32).map(|i| i as u8).collect();
        let img = assemble(&loader(1500), &kernel, ENTRIES, None).unwrap();

        // Stage 2 is three sectors (LBA 1-3), the entries one (LBA 4), so the kernel starts
        // at LBA 5 and takes six; the disk is then padded to one whole cylinder.
        assert_eq!(img.len(), 1008 * 512);
        assert_eq!(&img[424 + 4..424 + 10], &[1, 0, 0, 0, 3, 0]);
        let header = disk::Header::parse(&img[512 + disk::STAGE2_HEADER_OFFSET..]).unwrap();
        assert_eq!((header.config_lba, header.config_bytes), (4, ENTRIES.len() as u32));
        assert_eq!(header.config_crc32, disk::crc32(ENTRIES));
        assert_eq!(&img[4 * 512..4 * 512 + ENTRIES.len()], ENTRIES);
        assert_eq!(header.kernel_lba, 5);
        assert_eq!(header.kernel_bytes, 3000);
        assert_eq!(header.kernel_crc32, disk::crc32(&kernel));
        assert_eq!(&img[5 * 512..5 * 512 + 3000], &kernel[..]);

        // The partition entry covers everything after the MBR, and there is no second one.
        assert_eq!(img[446], 0x80);
        assert_eq!(img[450], disk::PARTITION_TYPE);
        assert_eq!(&img[454..462], &[1, 0, 0, 0, 0xEF, 3, 0, 0]);
        assert!(img[462..478].iter().all(|&b| b == 0));
        assert!(img[5 * 512 + 3000..].iter().all(|&b| b == 0));
        assert_eq!(&img[510..512], &[0x55, 0xAA]);
    }

    fn record() -> Vec<u8> {
        let mut r = vec![0u8; 512];
        r[CHAIN_TABLE_OFFSET..CHAIN_TABLE_OFFSET + 4].copy_from_slice(b"KBCT");
        r[510] = 0x55;
        r[511] = 0xAA;
        r
    }

    #[test]
    fn a_chain_test_record_becomes_partition_two_with_its_table_filled() {
        let kernel = vec![7u8; 1000];
        let img = assemble(&loader(600), &kernel, ENTRIES, Some(&record())).unwrap();
        // Stage 2 at LBA 1-2, entries at 3, kernel at 4-5, the record at 6.
        let e2 = 446 + 16;
        assert_eq!(img[e2], 0, "not active");
        assert_eq!(img[e2 + 4], CHAIN_PARTITION_TYPE);
        assert_eq!(&img[e2 + 8..e2 + 16], &[6, 0, 0, 0, 1, 0, 0, 0]);
        assert_eq!(&img[454..458], &[1, 0, 0, 0], "partition 1 still starts at stage 2");
        assert_eq!(&img[458..462], &[5, 0, 0, 0], "and now ends before the record");
        let r = &img[6 * 512..7 * 512];
        assert_eq!(r[CHAIN_TABLE_OFFSET + 4], CHAIN_TEST_DRIVE);
        assert_eq!(&r[CHAIN_TABLE_OFFSET + 5..CHAIN_TABLE_OFFSET + 9], &[6, 0, 0, 0]);

        let mut unsigned = record();
        unsigned[511] = 0;
        assert!(assemble(&loader(600), &kernel, ENTRIES, Some(&unsigned)).is_err());
        let mut moved = record();
        moved[CHAIN_TABLE_OFFSET] = 0;
        assert!(assemble(&loader(600), &kernel, ENTRIES, Some(&moved)).is_err());
    }

    #[test]
    fn identical_inputs_give_identical_disks() {
        let a = assemble(&loader(600), b"kernel", ENTRIES, None).unwrap();
        let b = assemble(&loader(600), b"kernel", ENTRIES, None).unwrap();
        assert_eq!(a, b);
        let c = assemble(&loader(600), b"kernel!", ENTRIES, None).unwrap();
        assert_ne!(a[440..444], c[440..444], "the disk signature follows the contents");
        let d = assemble(&loader(600), b"kernel", b"entry safe\n", None).unwrap();
        assert_ne!(a[440..444], d[440..444], "and follows the entries too");
    }

    #[test]
    fn layout_violations_are_refused() {
        let k = b"kernel";
        assert!(
            assemble(&loader(600)[..512], k, ENTRIES, None)
                .unwrap_err()
                .contains("no stage 2")
        );

        let mut l = loader(600);
        l[511] = 0;
        assert!(
            assemble(&l, k, ENTRIES, None)
                .unwrap_err()
                .contains("0x55AA")
        );

        let mut l = loader(600);
        l[446] = 1;
        assert!(
            assemble(&l, k, ENTRIES, None)
                .unwrap_err()
                .contains("partition table")
        );

        let mut l = loader(600);
        l[disk::STAGE1_TABLE_OFFSET] = 0;
        assert!(
            assemble(&l, k, ENTRIES, None)
                .unwrap_err()
                .contains("stage 1 table")
        );

        let mut l = loader(600);
        l[512 + disk::STAGE2_HEADER_OFFSET] = 0;
        assert!(
            assemble(&l, k, ENTRIES, None)
                .unwrap_err()
                .contains("stage 2 header")
        );

        let over = loader(disk::STAGE2_MAX_SECTORS as usize * 512 + 1);
        assert!(
            assemble(&over, k, ENTRIES, None)
                .unwrap_err()
                .contains("budget")
        );
        let at_limit = loader(disk::STAGE2_MAX_SECTORS as usize * 512);
        assert!(assemble(&at_limit, k, ENTRIES, None).is_ok());
    }
}

//! The test disk after a run: what the kernel wrote to it, read back with kbuild's own FAT
//! reader.
//!
//! Until the kernel wrote files, QEMU attached the test disk with `snapshot=on`, so a run's
//! writes vanished with it. Now each run gets a copy of the pristine image, [`RUN_FILE`], written
//! for real, and kbuild reads that copy after the guest exits. Every run starts from a fresh
//! copy, so the image kbuild builds stays reproducible and no run sees another's writes.
//!
//! After a clean exit ([`after_run`]) the volume must pass the consistency walk with nothing lost
//! and both tables the same, the names the writing checks remove must be gone, and every file a
//! check says it read back must hold what it wrote — kbuild does not take the kernel's word.
//! After a power cut ([`after_crash`]) lost clusters and tables that differ are allowed, since
//! the kernel's write ordering promises no more, but everything else in the walk must hold, and
//! every byte below a crash-test file's size must be one the workload wrote. Both volumes are
//! checked: the workload writes the FAT32 one as well, so a cut lands in a root that is a
//! cluster chain and a table of 28-bit entries as often as in the first volume's.

use std::path::{Path, PathBuf};

use crate::fat16::Volume;
use crate::testdisk;

/// The run's copy of the image, beside the pristine one.
pub const RUN_FILE: &str = "testdisk.run.img";

/// The directory the crash test's workload writes, and the seed of every byte it writes there;
/// mirrors `CRASH_DIR` and `CRASH_SEED` in `kernel/main/src/fs.rs`.
const CRASH_DIR: &str = "CRASH";
const CRASH_SEED: u8 = 0x41;
/// The same directory on the second volume; mirrors `CRASH_DIR32` in `kernel/main/src/fs.rs`.
/// The workload reaches it through its own mount point, so on the volume it is a root entry.
const CRASH_DIR32: &str = "CRASH";

/// Where the run's copy of the image goes, given the kernel image QEMU boots.
pub fn run_copy(image: &Path) -> PathBuf {
    image.parent().unwrap_or(Path::new(".")).join(RUN_FILE)
}

/// Replace the run's copy with the pristine image beside it.
pub fn fresh(run: &Path) -> Result<(), String> {
    let pristine = run.with_file_name(testdisk::FILE);
    std::fs::copy(&pristine, run)
        .map(|_| ())
        .map_err(|e| format!("copying {} to {}: {e}", pristine.display(), run.display()))
}

fn volume_bytes(image: &[u8]) -> Result<&[u8], String> {
    let start = testdisk::FS_START as usize * testdisk::SECTOR;
    let end = testdisk::FS32_START as usize * testdisk::SECTOR;
    image
        .get(start..end)
        .ok_or_else(|| "the disk image is shorter than its first volume".into())
}

/// The second volume's bytes: FAT32, from where the first ends to the end of the image.
fn volume32_bytes(image: &[u8]) -> Result<&[u8], String> {
    image
        .get(testdisk::FS32_START as usize * testdisk::SECTOR..)
        .ok_or_else(|| "the disk image is shorter than its second volume".into())
}

/// The second volume after a run, read with kbuild's own FAT32 reader, which shares no code
/// with the kernel's driver or with the writer that made it. The kernel only reads this one,
/// so nothing it wrote is expected here — but it must still be whole, and the free count in
/// its FSInfo sector must agree with its table.
fn verify_fat32(bytes: &[u8]) -> Result<String, String> {
    let v = crate::fat32::Volume::open(bytes)
        .map_err(|e| format!("the FAT32 volume after the run: {e}"))?;
    let r = v
        .check()
        .map_err(|e| format!("the FAT32 volume after the run is inconsistent: {e}"))?;
    if r.lost != 0 || r.fats_differ != 0 {
        return Err(format!(
            "the FAT32 volume lost {} clusters, and its tables differ in {} entries",
            r.lost, r.fats_differ
        ));
    }
    if r.fsinfo_free != Some(r.free) {
        return Err(format!(
            "the FAT32 volume's FSInfo says {:?} clusters are free where its table says {}",
            r.fsinfo_free, r.free
        ));
    }
    for (path, want) in [
        ("/HELLO32.TXT", testdisk::HELLO32),
        ("/SUB32/NESTED.TXT", testdisk::NESTED32),
    ] {
        match v.read(path)? {
            Some(data) if data == want => {}
            _ => return Err(format!("{path} on the FAT32 volume is not what kbuild wrote")),
        }
    }
    let big = v.read("/BIG32.BIN")?.unwrap_or_default();
    if big.len() != testdisk::BIG32_LEN
        || big
            .iter()
            .enumerate()
            .any(|(i, &b)| b != testdisk::big_byte(i))
    {
        return Err("/BIG32.BIN on the FAT32 volume is not what kbuild wrote".into());
    }
    // The two volumes are not each other. A volume written or mounted at the wrong offset
    // would still walk clean; what tells them apart is which names are on them.
    if v.exists("/KINTANE")? || !v.exists("/SUB32")? {
        return Err("the FAT32 volume does not hold the names kbuild put there".into());
    }
    Ok(format!(
        "FAT32 consistent, {} files, {} directories, {} clusters free, FSInfo agreeing",
        r.files, r.dirs, r.free
    ))
}

/// The volume on the run's copy after a clean exit, checked; `console` is what the guest
/// printed, which says which checks claim to have written their files. A line for the report.
pub fn after_run(run: &Path, console: &[u8]) -> Result<String, String> {
    let image = std::fs::read(run).map_err(|e| format!("{}: {e}", run.display()))?;
    let first = verify_clean(volume_bytes(&image)?, &String::from_utf8_lossy(console))?;
    let second = verify_fat32(volume32_bytes(&image)?)?;
    Ok(format!("{first}; {second}"))
}

fn verify_clean(bytes: &[u8], console: &str) -> Result<String, String> {
    let v = Volume::open(bytes)?;
    let r = v
        .check()
        .map_err(|e| format!("the disk image after the run is inconsistent: {e}"))?;
    if r.lost != 0 || r.fats_differ != 0 {
        return Err(format!(
            "the disk image after a clean exit lost {} clusters, and its tables differ in {} entries",
            r.lost, r.fats_differ
        ));
    }
    let mut read_back = Vec::new();
    for (path, len, seed) in [testdisk::NATIVE_OUT, testdisk::LINUX_OUT] {
        if !console.contains(&format!("/{path} read back")) {
            continue;
        }
        match v.read(path)? {
            Some(data)
                if data.len() == len
                    && data
                        .iter()
                        .enumerate()
                        .all(|(i, &b)| b == testdisk::out_byte(seed, i)) =>
            {
                read_back.push(format!("/{path}"));
            }
            Some(data) => {
                return Err(format!(
                    "/{path} on the disk image is not what the kernel wrote ({} bytes, {len} expected)",
                    data.len()
                ));
            }
            None => {
                return Err(format!(
                    "/{path} is not on the disk image, though the kernel read it back"
                ));
            }
        }
    }
    for name in testdisk::REMOVED {
        if v.exists(name)? {
            return Err(format!(
                "/{name} is still on the disk image, though the kernel removed it"
            ));
        }
    }
    let mut line = format!(
        "disk image: FAT16 consistent, {} files, {} directories, no lost cluster, the tables the same",
        r.files, r.dirs
    );
    if !read_back.is_empty() {
        line.push_str("; kbuild read back ");
        line.push_str(&read_back.join(" and "));
    }
    Ok(line)
}

/// What a power cut left on the run's copy.
#[derive(Debug)]
pub struct Crashed {
    pub files: u32,
    pub lost: u32,
    pub fats_differ: u32,
    /// Files of the crash workload found, and bytes of them checked.
    pub crash_files: usize,
    pub crash_bytes: usize,
    /// The same, counted on the second volume.
    pub lost32: u32,
    pub fats_differ32: u32,
    pub crash_files32: usize,
    pub crash_bytes32: usize,
}

/// The volume on the run's copy after QEMU was killed, checked by the crash rule.
pub fn after_crash(run: &Path) -> Result<Crashed, String> {
    let image = std::fs::read(run).map_err(|e| format!("{}: {e}", run.display()))?;
    let mut crashed = verify_crashed(volume_bytes(&image)?)?;
    let second = verify_crashed32(volume32_bytes(&image)?)?;
    crashed.lost32 = second.0;
    crashed.fats_differ32 = second.1;
    crashed.crash_files32 = second.2;
    crashed.crash_bytes32 = second.3;
    Ok(crashed)
}

/// The second volume after a cut, by the same rule as the first: lost clusters and tables one
/// step apart are what the ordering allows, and everything else must hold. Returns what it
/// counted, as `(lost, tables differing, workload files, bytes checked)`.
///
/// FSInfo's free count is *not* required to match here. It is written at a sync, so a cut
/// between a table change and the next sync leaves it stale by design — which is exactly the
/// case a clean run refuses and a crashed one must tolerate.
fn verify_crashed32(bytes: &[u8]) -> Result<(u32, u32, usize, usize), String> {
    let v = crate::fat32::Volume::open(bytes)
        .map_err(|e| format!("the FAT32 volume after a cut: {e}"))?;
    let r = v
        .check()
        .map_err(|e| format!("the FAT32 volume after a cut is inconsistent: {e}"))?;
    let (mut files, mut bytes_checked) = (0, 0);
    for (name, data) in v.files_in(CRASH_DIR32)?.unwrap_or_default() {
        if let Some(at) = data
            .iter()
            .enumerate()
            .position(|(i, &b)| b != testdisk::out_byte(CRASH_SEED, i))
        {
            return Err(format!(
                "/{CRASH_DIR32}/{name} on the FAT32 volume holds a byte at {at}, below its size \
                 of {}, that the workload never wrote",
                data.len()
            ));
        }
        files += 1;
        bytes_checked += data.len();
    }
    Ok((r.lost, r.fats_differ, files, bytes_checked))
}

fn verify_crashed(bytes: &[u8]) -> Result<Crashed, String> {
    let v = Volume::open(bytes)?;
    let r = v.check()?;
    let mut crashed = Crashed {
        files: r.files,
        lost: r.lost,
        fats_differ: r.fats_differ,
        crash_files: 0,
        crash_bytes: 0,
        // Filled in by `after_crash`, which reads the second volume from the same image.
        lost32: 0,
        fats_differ32: 0,
        crash_files32: 0,
        crash_bytes32: 0,
    };
    // The workload may not have made its directory reach the disk before the cut.
    for (name, data) in v.files_in(CRASH_DIR)?.unwrap_or_default() {
        if let Some(at) = data
            .iter()
            .enumerate()
            .position(|(i, &b)| b != testdisk::out_byte(CRASH_SEED, i))
        {
            return Err(format!(
                "/{CRASH_DIR}/{name} holds a byte at {at}, below its size of {}, that the workload never wrote",
                data.len()
            ));
        }
        crashed.crash_files += 1;
        crashed.crash_bytes += data.len();
    }
    Ok(crashed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fat16::{self, File, Params};

    fn params() -> Params {
        Params {
            sectors: 8192,
            sectors_per_cluster: 1,
            reserved_sectors: 1,
            fats: 2,
            root_entries: 64,
            hidden_sectors: 0,
            label: *b"TEST       ",
            volume_id: 1,
            what: "a test volume",
        }
    }

    fn seeded(seed: u8, len: usize) -> Vec<u8> {
        (0..len).map(|i| testdisk::out_byte(seed, i)).collect()
    }

    #[test]
    fn a_file_the_kernel_claims_is_checked_and_one_it_does_not_is_not() {
        let (path, len, seed) = testdisk::NATIVE_OUT;
        let good = seeded(seed, len);
        let v = fat16::volume(&[File { path, data: &good }], &params()).unwrap();
        let claim = format!("... /{path} read back ...");
        assert!(verify_clean(&v, &claim).unwrap().contains(path));
        let mut bad = good.clone();
        bad[999] ^= 1;
        let v = fat16::volume(&[File { path, data: &bad }], &params()).unwrap();
        assert!(verify_clean(&v, &claim).is_err());
        assert!(verify_clean(&v, "no claim").is_ok(), "no claim, nothing to hold the kernel to");
        let v = fat16::volume(
            &[File {
                path: testdisk::REMOVED[0],
                data: b"x",
            }],
            &params(),
        )
        .unwrap();
        assert!(
            verify_clean(&v, "")
                .unwrap_err()
                .contains("still on the disk image")
        );
    }

    /// The shape of the FAT32 volume the test disk carries: the smallest that is FAT32 by
    /// its cluster count.
    fn params32() -> crate::fat32::Params {
        crate::fat32::Params {
            sectors: 66_600,
            sectors_per_cluster: 1,
            reserved_sectors: 32,
            fats: 2,
            hidden_sectors: 0,
            label: *b"KTFAT32    ",
            volume_id: 0x4654_3332,
            what: "a test volume",
        }
    }

    #[test]
    fn the_second_volume_is_checked_after_a_cut() {
        let good = seeded(CRASH_SEED, 2500);
        let v = crate::fat32::volume(
            &[fat16::File {
                path: "CRASH/G0.BIN",
                data: &good,
            }],
            &params32(),
        )
        .unwrap();
        let (lost, differ, files, bytes) = verify_crashed32(&v).unwrap();
        assert_eq!((lost, differ, files, bytes), (0, 0, 1, 2500));

        // A byte below the file's size that the workload never wrote: what a cut must never
        // leave, whichever volume it lands on.
        let mut hole = good.clone();
        hole[1200..1300].fill(0);
        let v = crate::fat32::volume(
            &[fat16::File {
                path: "CRASH/G0.BIN",
                data: &hole,
            }],
            &params32(),
        )
        .unwrap();
        assert!(
            verify_crashed32(&v).unwrap_err().contains("never wrote"),
            "a hole below a workload file's size must be refused on the second volume too"
        );
    }

    #[test]
    fn a_volume_the_walk_refuses_is_not_reported_clean() {
        // Two live chains claiming one cluster: a cross-link, which the ordering promises a
        // cut can never leave, so the check must refuse it rather than count it as damage.
        let mut v = crate::fat32::volume(
            &[fat16::File {
                path: "CRASH/G0.BIN",
                data: &seeded(CRASH_SEED, 4096),
            }],
            &params32(),
        )
        .unwrap();
        let reserved = u16::from_le_bytes([v[14], v[15]]) as usize;
        let fat_at = reserved * crate::fat32::SECTOR;
        // Entries 3 and 4 both lead to cluster 5.
        v[fat_at + 12..fat_at + 16].copy_from_slice(&5u32.to_le_bytes());
        v[fat_at + 16..fat_at + 20].copy_from_slice(&5u32.to_le_bytes());
        v[fat_at + 20..fat_at + 24].copy_from_slice(&0x0FFF_FFFFu32.to_le_bytes());
        assert!(
            verify_crashed32(&v).is_err(),
            "a FAT32 volume the walk refuses must not pass the crash check"
        );
    }

    #[test]
    fn a_crash_file_is_checked_below_its_size() {
        let good = seeded(CRASH_SEED, 3000);
        let v = fat16::volume(
            &[File {
                path: "CRASH/F1.BIN",
                data: &good,
            }],
            &params(),
        )
        .unwrap();
        let c = verify_crashed(&v).unwrap();
        assert_eq!((c.crash_files, c.crash_bytes), (1, 3000));
        let mut hole = good.clone();
        hole[2000..2100].fill(0);
        let v = fat16::volume(
            &[File {
                path: "CRASH/F1.BIN",
                data: &hole,
            }],
            &params(),
        )
        .unwrap();
        assert!(verify_crashed(&v).unwrap_err().contains("never wrote"));
    }
}

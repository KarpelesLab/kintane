//! `kbuild crashtest`: cut the power on a guest in the middle of writing its disk, again and
//! again, and read what each cut left.
//!
//! The kernel is built with `FS_CRASH_TEST`. Once its filesystem check has mounted the test
//! disk's volume, it writes that volume for ever — files appended to, overwritten, truncated,
//! renamed over each other and removed, a directory made and removed, a sync now and then — and
//! says so on its console. kbuild waits for that line, lets the guest write for a random time,
//! and kills QEMU. No flush, no orderly shutdown: the image holds whatever QEMU had written to
//! it when the signal arrived, which is what a power cut leaves a real disk.
//!
//! Each run starts from a fresh copy of the pristine image and ends with
//! [`diskcheck::after_crash`]: kbuild's own FAT reader walks the volume and must find no chain
//! through a free cluster, no cluster claimed twice, no file longer than its chain, and no byte
//! below a workload file's size that the workload did not write. Lost clusters and tables that
//! differ are counted and reported, since that is what the kernel's write ordering allows a cut
//! to leave.

use std::io::Read;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::diskcheck;
use crate::qemu::Machine;

/// What the kernel prints once it starts writing.
const MARKER: &str = "fscrash: writing";
/// The longest a guest may take to reach the workload.
const START_WITHIN: Duration = Duration::from_secs(120);
/// The longest kbuild lets the workload write before cutting it off.
const MAX_WRITING_MS: u64 = 3000;

/// SplitMix64, so a campaign's cut points are a function of its seed.
fn next(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

/// Run `runs` cuts of the guest `m` describes, whose test disk copy is `disk`.
pub fn campaign(m: &Machine, disk: &Path, runs: u64, seed: u64) -> Result<(), String> {
    let mut rng = seed;
    let mut failures = Vec::new();
    let (mut lost_runs, mut differ_runs, mut max_lost, mut total_ops) = (0, 0, 0, 0u64);
    for run in 1..=runs {
        let delay = next(&mut rng) % (MAX_WRITING_MS + 1);
        diskcheck::fresh(disk)?;
        let console = cut(m, Duration::from_millis(delay))?;
        let ops = ops_seen(&console);
        total_ops += ops;
        match diskcheck::after_crash(disk) {
            Ok(c) => {
                lost_runs += usize::from(c.lost != 0 || c.lost32 != 0);
                differ_runs += usize::from(c.fats_differ != 0 || c.fats_differ32 != 0);
                max_lost = max_lost.max(c.lost.max(c.lost32));
                println!(
                    "  cut {run:>3} after {delay:>4} ms, {ops:>5}+ ops: consistent; {} files, {} lost clusters, \
                     tables differ in {}; {} workload files, {} bytes checked; FAT32: {} lost, \
                     tables differ in {}, {} files, {} bytes",
                    c.files,
                    c.lost,
                    c.fats_differ,
                    c.crash_files,
                    c.crash_bytes,
                    c.lost32,
                    c.fats_differ32,
                    c.crash_files32,
                    c.crash_bytes32
                );
            }
            Err(e) => {
                println!(
                    "  cut {run:>3} after {delay:>4} ms, {ops:>5}+ ops: \x1b[31mINCONSISTENT\x1b[0m: {e}"
                );
                failures.push((run, e));
                // Kept for whoever reads the failure, beside the pristine image.
                let kept = disk.with_file_name(format!("testdisk.crash-{run}.img"));
                let _ = std::fs::copy(disk, &kept);
            }
        }
    }
    println!(
        "\n{runs} cuts, {} inconsistent; {lost_runs} left lost clusters (at most {max_lost}), \
         {differ_runs} left the tables apart; at least {total_ops} operations written",
        failures.len()
    );
    if failures.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "{} of {runs} cuts left an inconsistent volume; the first, cut {}: {}",
            failures.len(),
            failures[0].0,
            failures[0].1
        ))
    }
}

/// The operation count the workload last printed, `fscrash: N ops`.
fn ops_seen(console: &[u8]) -> u64 {
    String::from_utf8_lossy(console)
        .lines()
        .filter_map(|l| {
            l.strip_prefix("fscrash: ")?
                .strip_suffix(" ops")?
                .parse()
                .ok()
        })
        .last()
        .unwrap_or(0)
}

/// Start the guest, wait for the workload, let it write for `delay`, and kill it. What it
/// printed.
fn cut(m: &Machine, delay: Duration) -> Result<Vec<u8>, String> {
    let mut child = Command::new(m.binary)
        .args(&m.args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("cannot start {}: {e}", m.binary))?;
    let mut pipe = child
        .stdout
        .take()
        .ok_or("QEMU's console was not captured")?;
    let console = Arc::new(Mutex::new(Vec::new()));
    let tee = {
        let console = console.clone();
        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            while let Ok(n) = pipe.read(&mut buf) {
                if n == 0 {
                    break;
                }
                if let Ok(mut c) = console.lock() {
                    c.extend_from_slice(&buf[..n]);
                }
            }
        })
    };
    let seen = || {
        console
            .lock()
            .map(|c| String::from_utf8_lossy(&c).contains(MARKER))
            .unwrap_or(false)
    };
    let start = Instant::now();
    let mut started = false;
    while start.elapsed() < START_WITHIN {
        if seen() {
            started = true;
            break;
        }
        if child.try_wait().map_err(|e| e.to_string())?.is_some() {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    if started {
        std::thread::sleep(delay);
    }
    let exited_early = child.try_wait().map_err(|e| e.to_string())?.is_some();
    // SIGKILL: QEMU gets no chance to flush anything the guest wrote.
    let _ = child.kill();
    let _ = child.wait();
    let _ = tee.join();
    let console = console.lock().map(|c| c.clone()).unwrap_or_default();
    if !started {
        return Err(format!(
            "the guest never started its crash workload (no `{MARKER}` within {}s); its console:\n{}",
            START_WITHIN.as_secs(),
            String::from_utf8_lossy(&console)
        ));
    }
    if exited_early {
        return Err(format!(
            "the guest stopped by itself while it should have been writing; its console:\n{}",
            String::from_utf8_lossy(&console)
        ));
    }
    Ok(console)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_last_operation_count_printed_is_the_one_read() {
        let console = b"boot\nfscrash: writing\nfscrash: 64 ops\nfscrash: 128 ops\nfscrash: 1";
        assert_eq!(ops_seen(console), 128);
        assert_eq!(ops_seen(b"nothing"), 0);
    }

    #[test]
    fn cut_points_follow_the_seed() {
        let (mut a, mut b) = (7, 7);
        let xs: Vec<u64> = (0..4).map(|_| next(&mut a) % 3001).collect();
        let ys: Vec<u64> = (0..4).map(|_| next(&mut b) % 3001).collect();
        assert_eq!(xs, ys);
        assert!(xs.windows(2).any(|w| w[0] != w[1]));
    }
}

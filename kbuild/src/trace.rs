//! Bounding QEMU's exception trace.
//!
//! `-d int,guest_errors -D qemu.log` has no cap. `-d` selects *which* items are logged and
//! nothing bounds the file, so a guest that faults in a loop writes until the disk fills: an
//! unacknowledged shared interrupt line once produced 140,096,133 lines of the same
//! `Servicing hardware INT=0x2b` at one unchanging program counter. The diagnosis needed the
//! last few thousand.
//!
//! The trace is bounded *after* the run rather than as it is written. Piping it through a
//! capped filter would mean handing QEMU a FIFO in place of a file, and a FIFO whose reader
//! falls behind blocks the writer — turning a diagnostic into a hang on every port, to bound
//! a file nothing reads while the guest is alive. Cutting afterwards cannot affect the run.
//!
//! Both ends are kept, because the two failures want opposite halves. A boot that dies early
//! leaves its evidence at the *start* and then nothing; a storm leaves it at the *end*, after
//! millions of identical lines. Keeping only the tail would lose the first kind, keeping only
//! the head the second. The cost is that the file is no longer one contiguous trace, which is
//! why the seam says so in the file rather than only in a commit message. Nothing in the tree
//! reads `qemu.log` — it is an artifact for a person — so a marker line breaks no parser.

use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

/// Above this, the trace is cut.
///
/// Set from measurement rather than taste, because a passing run must never be touched and
/// the spread between ports is wide: a plain boot writes 212,772 bytes on `i686-qemu`,
/// 3,412,804 on `x86_64-qemu`, and between 12,353,320 and 16,958,514 across the four aarch64
/// presets, which log an interrupt per frame. A stress run is not the heavy case it looks:
/// `stress::quiet` narrows `-d` to `guest_errors,cpu_reset`, and twenty seconds of it write
/// 6,750 bytes. One preset's own trace moved about four percent across three runs measured
/// here — 16,360,625, then 16,740,118, then 16,958,514 on `aarch64-virt` — so the record is a
/// moving target, and what stands between a passing trace and the knife is deliberately a
/// wide margin rather than a tight multiple of the largest yet seen.
///
/// **The margin is 128 MiB against a worst measured 16,958,514 bytes: nearly eight times.**
/// Its safety deliberately does not rest on having measured every preset, which is not a
/// property anyone can keep — presets arrive faster than a list in a comment is revised, and
/// the next one may well be another aarch64, where traces already run eighty times the
/// smallest port's. A preset whose normal trace is past the bound is therefore never
/// truncated in silence: the file records where its middle went, and `boot` prints that the
/// run which was cut *passed*, naming this constant and [`LARGEST_MEASURED`] as the pair to
/// raise. An unmeasured port degrades to a loud, self-describing report, not a quietly
/// shortened artifact.
pub const BOUND: u64 = 128 * 1024 * 1024;

/// The largest trace a *passing* run has been measured to write: `aarch64-virt`'s plain boot,
/// which took the record from `aarch64-virt-gicv3` on a later run within this same brief.
/// Raise it with the new number when a port beats it — the assertion below then forces
/// [`BOUND`] up with it, rather than letting the margin quietly erode.
pub const LARGEST_MEASURED: u64 = 16_958_514;

/// Kept from the start: enough for a loader, a memory map and an early fault.
pub const HEAD: usize = 4 * 1024 * 1024;

/// Kept from the end, and larger than the head: a storm's evidence is the state it repeats,
/// which sits at the tail, and a run that ends in one is the run this exists for.
pub const TAIL: usize = 12 * 1024 * 1024;

/// The margin over the largest measured run is a build-time guarantee, not merely a test: a
/// bound that stops clearing it should fail to compile rather than wait for someone to run
/// the suite. Raising [`LARGEST_MEASURED`] without raising [`BOUND`] breaks the build here.
const _: () = assert!(BOUND >= LARGEST_MEASURED * 4);

/// A cut must leave a smaller file than it found, or it is not a bound at all.
const _: () = assert!((HEAD + TAIL) as u64 <= BOUND);

/// What a cut removed, for the caller to report.
#[derive(Debug, PartialEq, Eq)]
pub struct Cut {
    /// Bytes the file held before.
    pub was: u64,
    /// Bytes removed from the middle.
    pub removed: u64,
}

/// The line written where the middle was. Deliberately unmistakable, and deliberately not
/// counting the lines it dropped: counting them means reading every byte of the very file
/// whose size is the problem.
fn marker(removed: u64, limit: u64) -> String {
    format!(
        "\n*** kbuild cut {removed} bytes out of the middle of this trace, which passed \
         {limit} bytes. The head and tail are intact and this line marks the seam. ***\n"
    )
}

/// Cut `path` down to its two ends if it has grown past [`BOUND`].
///
/// Returns `Ok(None)` when the file is within the bound or absent — in which case it is not
/// opened, read or rewritten, so a passing run's trace keeps every byte it had. Errors are
/// the caller's to report and never fatal: a trace that could not be cut is still a trace.
pub fn bound(path: &Path) -> Result<Option<Cut>, String> {
    bound_with(path, BOUND, HEAD, TAIL)
}

/// [`bound`] with the limits given, so a test need not write a file the size of the shipped
/// bound to exercise a cut. The shipped constants are held against measurement separately, by
/// the assertions above, which are checked when this compiles rather than when a suite runs.
pub fn bound_with(
    path: &Path,
    limit: u64,
    head_keep: usize,
    tail_keep: usize,
) -> Result<Option<Cut>, String> {
    let Ok(meta) = std::fs::metadata(path) else {
        return Ok(None);
    };
    let was = meta.len();
    if was <= limit {
        return Ok(None);
    }

    let fail = |e: std::io::Error| format!("{}: {e}", path.display());
    let mut f = std::fs::File::open(path).map_err(fail)?;
    let mut head = vec![0u8; head_keep];
    f.read_exact(&mut head).map_err(fail)?;
    f.seek(SeekFrom::End(-(tail_keep as i64))).map_err(fail)?;
    let mut tail = vec![0u8; tail_keep];
    f.read_exact(&mut tail).map_err(fail)?;
    drop(f);

    // Snap both ends to line boundaries, so the seam never splits a line and leaves half of
    // one looking like a whole one. A chunk with no newline at all is kept whole rather than
    // discarded: truncating to nothing would be worse than an unterminated line.
    let head_end = head
        .iter()
        .rposition(|&b| b == b'\n')
        .map_or(head.len(), |i| i + 1);
    let tail_start = tail.iter().position(|&b| b == b'\n').map_or(0, |i| i + 1);
    let head = &head[..head_end];
    let tail = &tail[tail_start..];
    let removed = was - head.len() as u64 - tail.len() as u64;

    // Written beside the original and renamed over it, so an interrupted cut cannot leave the
    // trace half-written: either the whole cut file replaces it, or the original stays.
    let tmp = path.with_extension("log.cut");
    let mut out = std::fs::File::create(&tmp).map_err(fail)?;
    out.write_all(head).map_err(fail)?;
    out.write_all(marker(removed, limit).as_bytes())
        .map_err(fail)?;
    out.write_all(tail).map_err(fail)?;
    out.sync_all().map_err(fail)?;
    drop(out);
    std::fs::rename(&tmp, path).map_err(fail)?;
    Ok(Some(Cut { was, removed }))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Small enough to keep these tests to kilobytes. The shipped constants are held against
    /// measurement by the assertions at the top of this file, which the compiler checks —
    /// writing a fixture the size of the real bound here would buy nothing it does not
    /// already guarantee.
    const LIMIT: u64 = 64 * 1024;
    const KEEP_HEAD: usize = 8 * 1024;
    const KEEP_TAIL: usize = 16 * 1024;

    /// A file of `lines` numbered lines, each padded so the whole is predictably large.
    fn write_lines(path: &Path, lines: usize) -> u64 {
        let mut f = std::fs::File::create(path).unwrap();
        for i in 0..lines {
            writeln!(f, "line {i:08} {}", "x".repeat(80)).unwrap();
        }
        f.sync_all().unwrap();
        std::fs::metadata(path).unwrap().len()
    }

    fn scratch(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("kbuild-trace-{name}-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d.join("qemu.log")
    }

    #[test]
    fn a_trace_within_the_bound_is_not_touched_at_all() {
        let p = scratch("small");
        let n = write_lines(&p, 100);
        assert!(n <= LIMIT, "fixture must be under the limit, is {n}");
        let before = std::fs::read(&p).unwrap();
        assert_eq!(
            bound_with(&p, LIMIT, KEEP_HEAD, KEEP_TAIL).unwrap(),
            None,
            "a small trace reported a cut"
        );
        assert_eq!(std::fs::read(&p).unwrap(), before, "a small trace was rewritten");
    }

    #[test]
    fn a_missing_trace_is_not_an_error() {
        let p = scratch("absent").with_file_name("nothing-here.log");
        assert_eq!(bound_with(&p, LIMIT, KEEP_HEAD, KEEP_TAIL).unwrap(), None);
    }

    #[test]
    fn a_storm_keeps_both_ends_and_says_where_the_middle_went() {
        let p = scratch("storm");
        let lines = 4000;
        let was = write_lines(&p, lines);
        assert!(was > LIMIT, "fixture must exceed the limit, is {was}");
        let first = "line 00000000";
        let last = format!("line {:08}", lines - 1);

        let cut = bound_with(&p, LIMIT, KEEP_HEAD, KEEP_TAIL)
            .unwrap()
            .expect("a trace past the limit reported no cut");
        assert_eq!(cut.was, was);
        let after = std::fs::read_to_string(&p).unwrap();

        assert!(after.starts_with(first), "the head is gone");
        // The last line ends in the fixture's padding, not in its number, so what is checked
        // is the final line's prefix. Asserting `ends_with` on the whole file could never
        // hold — a check that cannot pass is no better than one that cannot fail.
        let last_line = after.lines().last().unwrap_or_default();
        assert!(last_line.starts_with(&last), "the tail is gone: {last_line:?}");
        assert!(after.contains("*** kbuild cut"), "the seam is unmarked");
        assert!(
            after.contains(&format!("cut {} bytes", cut.removed)),
            "the marker does not say how much it removed"
        );
        assert_eq!(
            cut.removed,
            was - (after.len() as u64 - marker(cut.removed, LIMIT).len() as u64),
            "the marker's count disagrees with what the file lost"
        );
        assert!(
            (after.len() as u64) < was / 2,
            "the cut file is not much smaller than the original"
        );
    }

    #[test]
    fn the_seam_never_splits_a_line() {
        let p = scratch("seam");
        write_lines(&p, 4000);
        bound_with(&p, LIMIT, KEEP_HEAD, KEEP_TAIL)
            .unwrap()
            .unwrap();
        let after = std::fs::read_to_string(&p).unwrap();
        for line in after.lines() {
            assert!(
                line.is_empty() || line.starts_with("line ") || line.starts_with("*** kbuild cut"),
                "a half line survived the cut: {line:?}"
            );
        }
    }

    #[test]
    fn cutting_an_already_cut_trace_leaves_it_alone() {
        let p = scratch("twice");
        write_lines(&p, 4000);
        bound_with(&p, LIMIT, KEEP_HEAD, KEEP_TAIL)
            .unwrap()
            .unwrap();
        let once = std::fs::read(&p).unwrap();
        assert_eq!(
            bound_with(&p, LIMIT, KEEP_HEAD, KEEP_TAIL).unwrap(),
            None,
            "a cut trace was cut again"
        );
        assert_eq!(std::fs::read(&p).unwrap(), once);
    }
}

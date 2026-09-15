//! `kbuild stress`: run a stress image for a long time and notice if it hangs.
//!
//! The guest decides whether the run passed, through the exit channel, as every other
//! run does: a failed audit exits with a failure, and the end of the time with success.
//! What the guest cannot report is that it stopped running. A thread that spins with
//! interrupts masked stops the auditor too, and then nothing ever reaches the exit port.
//! So the harness watches for the heartbeat the auditor prints every second of guest
//! time, and kills a guest that goes quiet. That is liveness, read from the console;
//! the verdict is still only the exit code.

use crate::qemu::{Machine, Watch};

/// The auditor's heartbeat line starts with this.
pub const HEARTBEAT: &[u8] = b"stress heartbeat ";

/// Seconds allowed from starting QEMU to the first heartbeat: firmware, boot checks and
/// the first audit. The UEFI preset spends most of it in firmware.
const FIRST_HEARTBEAT_WITHIN: u64 = 180;

/// Seconds allowed between heartbeats. The guest prints one per second of its own time, and
/// under TCG that time is the host's to give: on a machine running several eight-CPU guests
/// at load 18, a healthy soak went more than thirty seconds of wall time between heartbeats
/// and was killed as hung, with its counters still climbing and no audit failed.
///
/// A guest that has really hung never prints again, so a longer allowance costs only how soon
/// that is noticed, never whether it is. Two minutes is four times the worst gap measured on a
/// loaded host, and still a short wait beside a run of hours.
const HEARTBEAT_EVERY_WITHIN: u64 = 120;

pub fn watch() -> Watch {
    Watch {
        marker: HEARTBEAT,
        first_within: FIRST_HEARTBEAT_WITHIN,
        every_within: HEARTBEAT_EVERY_WITHIN,
    }
}

/// The overall timeout for a run of `seconds`: the run itself, the time to the first
/// heartbeat, and as much again as the watchdog's window, so the watchdog and not this
/// catches a slow guest.
pub fn timeout(seconds: u64) -> u64 {
    seconds + FIRST_HEARTBEAT_WITHIN + 2 * HEARTBEAT_EVERY_WITHIN
}

/// The machine without QEMU's per-interrupt log. A stress run takes thousands of timer
/// interrupts a second for as long as it runs, and logging each one fills the disk long
/// before a day is up. Guest errors and resets are still logged.
pub fn quiet(mut m: Machine) -> Machine {
    for arg in m.args.iter_mut() {
        if arg == "int,guest_errors" {
            *arg = "guest_errors,cpu_reset".to_string();
        }
    }
    m
}

/// Parse a run length: plain seconds, or a number with `s`, `m` or `h`.
pub fn parse_duration(text: &str) -> Result<u64, String> {
    let bad = || format!("`{text}` is not a duration; use e.g. 90, 90s, 10m or 24h");
    let (digits, unit) = match text.char_indices().find(|(_, c)| !c.is_ascii_digit()) {
        Some((i, _)) => text.split_at(i),
        None => (text, ""),
    };
    let n: u64 = digits.parse().map_err(|_| bad())?;
    let scale = match unit {
        "" | "s" => 1,
        "m" => 60,
        "h" => 3600,
        _ => return Err(bad()),
    };
    match n.checked_mul(scale) {
        Some(0) | None => Err(bad()),
        Some(s) => Ok(s),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations_parse_with_and_without_units() {
        assert_eq!(parse_duration("90"), Ok(90));
        assert_eq!(parse_duration("90s"), Ok(90));
        assert_eq!(parse_duration("10m"), Ok(600));
        assert_eq!(parse_duration("24h"), Ok(86_400));
    }

    #[test]
    fn nonsense_and_zero_durations_are_refused() {
        for bad in ["", "m", "10x", "1.5h", "-5", "0", "0m", "10mm"] {
            assert!(parse_duration(bad).is_err(), "{bad:?} was accepted");
        }
    }

    #[test]
    fn the_quiet_machine_drops_only_the_interrupt_log() {
        let m = quiet(Machine {
            binary: "qemu",
            args: vec!["-d".into(), "int,guest_errors".into(), "-m".into()],
            success_code: 0,
            input: Vec::new(),
            serial_probe: false,
            net_port: None,
            net_peer: false,
            disk: None,
        });
        assert_eq!(m.args, ["-d", "guest_errors,cpu_reset", "-m"]);
    }
}

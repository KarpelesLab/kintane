//! `kbuild soak`: a stress run long enough to show drift, kept for reading afterwards.
//!
//! A soak is a `stress` run with two differences, both about being unattended. The audit
//! trail — every heartbeat, the verdict, and the failed audit if there was one — is
//! written to a file of its own, so a run that took hours is still readable after the
//! console scrollback is gone. And the trail is compared with itself: the counters in the
//! first minutes against the same counters in the last, because a run that passes every
//! audit can still be leaking. A counter that should be a rate and instead climbs, or a
//! rate that falls away, is the thing a long run is for.
//!
//! The verdict is still the guest's exit status, as it is everywhere else. Nothing here
//! decides whether the run passed; this module reads what the guest said about it.

/// One heartbeat line: the second it reports, and the numbers in it, each labelled by the
/// words in front of it.
#[derive(Debug, PartialEq, Eq)]
pub struct Heartbeat {
    pub second: u64,
    pub fields: Vec<(String, u64)>,
}

/// What a run's console said about itself.
#[derive(Debug, Default)]
pub struct Trail {
    pub heartbeats: Vec<Heartbeat>,
    /// The `stress passed` line, when the run reached it.
    pub verdict: Option<String>,
    /// The `stress AUDIT FAILED` line, when an audit ended the run.
    pub failure: Option<String>,
}

/// Words that follow a number as its unit rather than labelling the next one.
const UNITS: [&str; 6] = ["us", "s", "ms", "kib", "ok", "bytes"];

/// The numbers in one heartbeat's text after `s:`, each with the words before it.
///
/// The line is prose with punctuation — `heap 1036767 (refused 64901), ipc 423238` — so
/// punctuation becomes spaces and the words between two numbers label the second. Units
/// are dropped, because `latest +6479 us), vm 4762` would otherwise label the vm count
/// `us vm`.
fn fields(text: &str) -> Vec<(String, u64)> {
    let spaced: String = text
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { ' ' })
        .collect();
    let mut out = Vec::new();
    let mut label: Vec<&str> = Vec::new();
    for token in spaced.split_whitespace() {
        match token.parse::<u64>() {
            Ok(n) if !label.is_empty() => {
                out.push((label.join(" "), n));
                label.clear();
            }
            // A number with nothing in front of it belongs to whatever came before it,
            // which has already been taken; `32/32` and the like arrive this way.
            Ok(_) => {}
            Err(_) => {
                if !UNITS.contains(&token.to_ascii_lowercase().as_str()) {
                    label.push(token);
                }
            }
        }
    }
    out
}

/// Read a console's heartbeats, its verdict and its failure, in the order they arrived.
pub fn trail(console: &[u8]) -> Trail {
    let text = String::from_utf8_lossy(console);
    let mut t = Trail::default();
    for line in text.lines() {
        let line = line.trim_end_matches('\r').trim();
        if let Some(rest) = line.strip_prefix("stress heartbeat ") {
            let Some((when, body)) = rest.split_once(':') else {
                continue;
            };
            let second = when
                .split('/')
                .next()
                .and_then(|s| s.trim().parse::<u64>().ok());
            if let Some(second) = second {
                t.heartbeats.push(Heartbeat {
                    second,
                    fields: fields(body),
                });
            }
        } else if line.starts_with("stress AUDIT FAILED") {
            t.failure.get_or_insert_with(|| line.to_string());
        } else if line.starts_with("stress passed") {
            t.verdict = Some(line.to_string());
        }
    }
    t
}

/// The trail as a file: one heartbeat per line, then the verdict.
pub fn trail_text(t: &Trail) -> String {
    let mut s = String::new();
    for h in &t.heartbeats {
        s.push_str(&format!("{:>6} s", h.second));
        for (name, value) in &h.fields {
            s.push_str(&format!("  {name}={value}"));
        }
        s.push('\n');
    }
    if let Some(f) = &t.failure {
        s.push_str(f);
        s.push('\n');
    }
    if let Some(v) = &t.verdict {
        s.push_str(v);
        s.push('\n');
    }
    s
}

/// How a counter behaved in the first `window` seconds against the last `window`.
#[derive(Debug, PartialEq)]
pub struct Drift {
    pub name: String,
    /// Its rate per second early and late, for a counter that only climbs.
    pub early_rate: f64,
    pub late_rate: f64,
    /// Its value at the end of each window, for one that is a level rather than a count.
    pub early_value: u64,
    pub late_value: u64,
}

impl Drift {
    /// How much the late rate differs from the early one, as a fraction of the early rate.
    /// `None` when nothing happened early, which no ratio describes.
    pub fn rate_change(&self) -> Option<f64> {
        (self.early_rate > 0.0).then(|| (self.late_rate - self.early_rate) / self.early_rate)
    }
}

/// Compare the first `window` seconds of the trail with its last `window`.
///
/// A counter's rate is what it gained across the window divided by the seconds the window
/// covers, so a run whose heartbeats stopped for a while is described by the seconds it
/// reports, not by how many lines it printed.
pub fn drift(t: &Trail, window: u64) -> Vec<Drift> {
    let (Some(first), Some(last)) = (t.heartbeats.first(), t.heartbeats.last()) else {
        return Vec::new();
    };
    let early_end = t
        .heartbeats
        .iter()
        .take_while(|h| h.second <= first.second.saturating_add(window))
        .last();
    let late_start = t
        .heartbeats
        .iter()
        .rev()
        .take_while(|h| h.second.saturating_add(window) >= last.second)
        .last();
    let (Some(early_end), Some(late_start)) = (early_end, late_start) else {
        return Vec::new();
    };
    let span = |a: &Heartbeat, b: &Heartbeat| (b.second.saturating_sub(a.second)) as f64;
    let (early_span, late_span) = (span(first, early_end), span(late_start, last));
    let value =
        |h: &Heartbeat, name: &str| h.fields.iter().find(|(n, _)| n == name).map(|&(_, v)| v);
    let mut out = Vec::new();
    for (name, _) in &last.fields {
        let (Some(a), Some(b), Some(c), Some(d)) = (
            value(first, name),
            value(early_end, name),
            value(late_start, name),
            value(last, name),
        ) else {
            continue;
        };
        let rate = |from: u64, to: u64, secs: f64| {
            if secs <= 0.0 {
                0.0
            } else {
                to.saturating_sub(from) as f64 / secs
            }
        };
        out.push(Drift {
            name: name.clone(),
            early_rate: rate(a, b, early_span),
            late_rate: rate(c, d, late_span),
            early_value: b,
            late_value: d,
        });
    }
    out
}

/// The drift table, and the lines worth looking at first: every counter whose rate moved
/// by more than `flag_at`, and every level that grew.
pub fn drift_report(drifts: &[Drift], flag_at: f64) -> String {
    let mut s = String::from(
        "  counter                    early/s      late/s     early      late   change\n",
    );
    for d in drifts {
        let change = match d.rate_change() {
            Some(c) => format!("{:+.0}%", c * 100.0),
            None => "-".to_string(),
        };
        let flag = match d.rate_change() {
            Some(c) if c.abs() > flag_at => " <-",
            _ => "",
        };
        s.push_str(&format!(
            "  {:<22} {:>10.2} {:>11.2} {:>9} {:>9} {:>8}{}\n",
            d.name, d.early_rate, d.late_rate, d.early_value, d.late_value, change, flag
        ));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    const ONE: &str = "stress heartbeat 1/60 s: heap 100 (refused 2), ipc 50, sleeps 3 \
                       (latest +900 us), vm 4, pages 5, audits 1 ok";
    const TWO: &str = "stress heartbeat 11/60 s: heap 1100 (refused 22), ipc 550, sleeps 33 \
                       (latest +950 us), vm 44, pages 55, audits 11 ok";

    #[test]
    fn a_heartbeat_labels_every_number_with_the_words_before_it() {
        let t = trail(ONE.as_bytes());
        assert_eq!(t.heartbeats.len(), 1);
        let h = &t.heartbeats[0];
        assert_eq!(h.second, 1);
        assert_eq!(h.fields[0], ("heap".to_string(), 100));
        assert_eq!(h.fields[1], ("refused".to_string(), 2));
        assert_eq!(h.fields[2], ("ipc".to_string(), 50));
        // The unit after `+900` is dropped, so the next number is `vm`, not `us vm`.
        assert!(h.fields.iter().any(|(n, v)| n == "vm" && *v == 4));
        assert!(h.fields.iter().any(|(n, v)| n == "latest" && *v == 900));
    }

    #[test]
    fn the_verdict_and_a_failed_audit_are_kept_apart() {
        let passed = trail(
            b"stress heartbeat 1/1 s: heap 1, audits 1 ok\nstress passed: 1 audits over 1 s\n",
        );
        assert!(passed.failure.is_none());
        assert_eq!(passed.verdict.as_deref(), Some("stress passed: 1 audits over 1 s"));

        let failed = trail(b"stress AUDIT FAILED at 3 s: heap: bytes in use grew\n");
        assert_eq!(
            failed.failure.as_deref(),
            Some("stress AUDIT FAILED at 3 s: heap: bytes in use grew")
        );
        assert!(failed.verdict.is_none());
    }

    #[test]
    fn drift_compares_rates_across_the_run() {
        let console = format!("{ONE}\n{TWO}\n");
        let t = trail(console.as_bytes());
        let d = drift(&t, 0);
        // With a zero window each end is one heartbeat, so no span and no rate; the levels
        // are still the ones reported.
        let heap = d.iter().find(|d| d.name == "heap").expect("heap");
        assert_eq!((heap.early_value, heap.late_value), (100, 1100));
    }

    #[test]
    fn a_counter_that_stops_climbing_shows_a_negative_change() {
        let mut console = String::new();
        // Ten seconds at a hundred a second, then ten at ten a second.
        for i in 0..=10u64 {
            console
                .push_str(&format!("stress heartbeat {i}/20 s: heap {}, audits {i} ok\n", i * 100));
        }
        for i in 11..=20u64 {
            console.push_str(&format!(
                "stress heartbeat {i}/20 s: heap {}, audits {i} ok\n",
                1000 + (i - 10) * 10
            ));
        }
        let t = trail(console.as_bytes());
        let d = drift(&t, 5);
        let heap = d.iter().find(|d| d.name == "heap").expect("heap");
        assert!((heap.early_rate - 100.0).abs() < 1.0, "{heap:?}");
        assert!((heap.late_rate - 10.0).abs() < 1.0, "{heap:?}");
        assert!(heap.rate_change().expect("a rate") < -0.5);
        assert!(drift_report(&d, 0.25).contains("<-"));
    }

    #[test]
    fn a_run_with_no_heartbeats_drifts_nowhere() {
        assert!(drift(&trail(b""), 60).is_empty());
    }
}

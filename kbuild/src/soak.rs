//! `kbuild soak`: a stress run long enough to show drift, kept for reading afterwards.
//!
//! A soak is a `stress` run with two differences, both about being unattended. The audit
//! trail — every heartbeat, the verdict, and the failed audit if there was one — is
//! written to a file of its own, so a run that took hours is still readable after the
//! console scrollback is gone. And the trail is compared with itself: the numbers in the
//! first minutes against the same numbers in the last, because a run that passes every
//! audit can still be leaking.
//!
//! **What the comparison must know.** A heartbeat carries three sorts of number, and one
//! test does not fit them. A *count* only climbs, so its rate compares between windows. A
//! *level* is a high-water mark or a standing value, where a rate means nothing: a worst
//! case that stopped getting worse is good news, and reporting it as a rate that fell to
//! nothing reads as alarm. A *mean* is neither, and compares directly. The kernel says
//! which is which, in the `stress field kinds:` line it prints once, so the knowledge sits
//! beside the printing it describes instead of being guessed from names here.
//!
//! The verdict is still the guest's exit status, as it is everywhere else. Nothing here
//! decides whether the run passed; this module reads what the guest said about it.

use std::collections::BTreeMap;

/// One heartbeat line: the second it reports, and the numbers in it, each labelled by the
/// words in front of it.
#[derive(Debug, PartialEq, Eq)]
pub struct Heartbeat {
    pub second: u64,
    pub fields: Vec<(String, u64)>,
}

/// What a heartbeat number is, and so how two windows of it compare.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// Only climbs; its rate is what compares.
    Count,
    /// A high-water mark or a standing value; its rate means nothing.
    Level,
    /// An average; it compares directly.
    Mean,
}

impl Kind {
    fn from_word(word: &str) -> Option<Kind> {
        match word {
            "count" => Some(Kind::Count),
            "level" | "gauge" => Some(Kind::Level),
            "mean" => Some(Kind::Mean),
            _ => None,
        }
    }

    fn word(self) -> &'static str {
        match self {
            Kind::Count => "count",
            Kind::Level => "level",
            Kind::Mean => "mean",
        }
    }
}

/// What a run's console said about itself.
#[derive(Debug, Default)]
pub struct Trail {
    pub heartbeats: Vec<Heartbeat>,
    /// The kinds the guest named, for every field that is not a plain count.
    pub kinds: BTreeMap<String, Kind>,
    /// The `stress passed` line, when the run reached it.
    pub verdict: Option<String>,
    /// The `stress AUDIT FAILED` line, when an audit ended the run.
    pub failure: Option<String>,
}

impl Trail {
    /// What `name` is. A field the guest did not name is a count: that is the common case,
    /// and it is the safe one, because a count's rate is the test that flags a leak.
    pub fn kind(&self, name: &str) -> Kind {
        self.kinds.get(name).copied().unwrap_or(Kind::Count)
    }

    /// Kinds the guest named that no heartbeat carries. A legend describing a field that
    /// does not exist means the two have drifted apart, and the field it was meant to
    /// describe is being read as a count — so this is reported, not ignored.
    pub fn unmatched_kinds(&self) -> Vec<&str> {
        self.kinds
            .keys()
            .filter(|name| {
                !self
                    .heartbeats
                    .iter()
                    .any(|h| h.fields.iter().any(|(n, _)| n == *name))
            })
            .map(String::as_str)
            .collect()
    }
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
    // A comma or a closing bracket ends a field, so the words after it belong to the next
    // number and not to this one: without that, `late with the CPU elsewhere), vm 4762` labels
    // the vm count `late with the CPU elsewhere vm`.
    let spaced: String = text
        .chars()
        .map(|c| match c {
            c if c.is_ascii_alphanumeric() => c,
            ',' | ')' => '\n',
            _ => ' ',
        })
        .collect();
    let mut out = Vec::new();
    let mut label: Vec<&str> = Vec::new();
    for token in spaced.split_inclusive('\n').flat_map(|piece| {
        let ends = piece.ends_with('\n');
        piece
            .split_whitespace()
            .map(Some)
            .chain(ends.then_some(None))
            .collect::<Vec<_>>()
    }) {
        let Some(token) = token else {
            label.clear();
            continue;
        };
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

/// The kinds in a `stress field kinds:` line: `latest=level; answered in mean=mean`.
///
/// A label is written as the heartbeat's own words, so it is matched against the labels
/// [`fields`] derives — which is what [`Trail::unmatched_kinds`] checks.
fn field_kinds(text: &str) -> Vec<(String, Kind)> {
    text.split(';')
        .filter_map(|entry| {
            let (name, kind) = entry.rsplit_once('=')?;
            let kind = Kind::from_word(kind.trim().to_ascii_lowercase().as_str())?;
            let name = name.split_whitespace().collect::<Vec<_>>().join(" ");
            (!name.is_empty()).then_some((name, kind))
        })
        .collect()
}

/// Read a console's heartbeats, the kinds it named, its verdict and its failure.
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
        } else if let Some(rest) = line.strip_prefix("stress field kinds:") {
            t.kinds.extend(field_kinds(rest));
        } else if line.starts_with("stress AUDIT FAILED") {
            t.failure.get_or_insert_with(|| line.to_string());
        } else if line.starts_with("stress passed") {
            t.verdict = Some(line.to_string());
        }
    }
    t
}

/// The trail as a file: the kinds, one heartbeat per line, then the verdict.
pub fn trail_text(t: &Trail) -> String {
    let mut s = String::new();
    if !t.kinds.is_empty() {
        let named: Vec<String> = t
            .kinds
            .iter()
            .map(|(name, kind)| format!("{name}={}", kind.word()))
            .collect();
        s.push_str(&format!("kinds  {}\n", named.join("; ")));
    }
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

/// Why a number is worth looking at. Each is a sentence about the run, not a threshold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Finding {
    /// A count whose rate moved by more than the threshold.
    RateMoved,
    /// A count that stood still early and climbed late: a leak that began after the first
    /// window, which comparing rates alone never sees, because there is no early rate to
    /// compare against.
    Started,
    /// A count that went backwards, which no count may do.
    WentBackwards,
    /// A level still being pushed at the end: it rose more in the last window than in the
    /// first, so it has not settled.
    StillClimbing,
    /// A mean that moved by more than the threshold.
    MeanMoved,
}

impl Finding {
    pub fn why(self) -> &'static str {
        match self {
            Finding::RateMoved => "its rate moved",
            Finding::Started => "it stood still early and climbed late",
            Finding::WentBackwards => "a count went backwards",
            Finding::StillClimbing => "a level rose more late than early",
            Finding::MeanMoved => "the mean moved",
        }
    }
}

/// How one number behaved in the first `window` seconds against the last `window`.
#[derive(Debug, PartialEq)]
pub struct Drift {
    pub name: String,
    pub kind: Kind,
    /// Its rate per second early and late, for a count.
    pub early_rate: f64,
    pub late_rate: f64,
    /// What it stood at when each window ended.
    pub early_value: u64,
    pub late_value: u64,
    /// How much it rose within each window, which is what judges a level.
    pub early_rise: u64,
    pub late_rise: u64,
    /// Why it is worth looking at, if it is.
    pub finding: Option<Finding>,
}

impl Drift {
    /// How much the late rate differs from the early one, as a fraction of the early rate.
    /// `None` when nothing happened early, which no ratio describes — [`Finding::Started`]
    /// is what covers that case.
    pub fn rate_change(&self) -> Option<f64> {
        (self.early_rate > 0.0).then(|| (self.late_rate - self.early_rate) / self.early_rate)
    }

    /// How much a mean moved, as a fraction of where it started.
    fn mean_change(&self) -> Option<f64> {
        (self.early_value > 0)
            .then(|| (self.late_value as f64 - self.early_value as f64) / self.early_value as f64)
    }

    /// What to say about it in the table's last column.
    fn change_text(&self) -> String {
        match self.kind {
            Kind::Count => match self.rate_change() {
                Some(c) => format!("{:+.0}%", c * 100.0),
                None if self.late_rate > 0.0 => "started".to_string(),
                None => "-".to_string(),
            },
            Kind::Level => match (self.early_rise, self.late_rise) {
                (0, 0) => "settled".to_string(),
                (_, 0) => "settled".to_string(),
                (e, l) => format!("+{l} late, +{e} early"),
            },
            Kind::Mean => match self.mean_change() {
                Some(c) => format!("{:+.0}%", c * 100.0),
                None => "-".to_string(),
            },
        }
    }
}

/// Judge one number against the threshold, by its kind.
fn judge(d: &Drift, flag_at: f64) -> Option<Finding> {
    match d.kind {
        Kind::Count => {
            if d.late_value < d.early_value {
                Some(Finding::WentBackwards)
            } else if let Some(c) = d.rate_change() {
                (c.abs() > flag_at).then_some(Finding::RateMoved)
            } else {
                // No early rate to compare: the only thing worth saying is that it began.
                (d.late_rate > 0.0).then_some(Finding::Started)
            }
        }
        // A high-water mark rises by construction — more samples, a higher worst. What is
        // worth reporting is one that has not settled: still rising at the end as fast as
        // it rose at the start, which is what an unbounded quantity looks like.
        Kind::Level => {
            (d.late_rise > 0 && d.late_rise >= d.early_rise).then_some(Finding::StillClimbing)
        }
        Kind::Mean => d
            .mean_change()
            .and_then(|c| (c.abs() > flag_at).then_some(Finding::MeanMoved)),
    }
}

/// Compare the first `window` seconds of the trail with its last `window`, judging each
/// number by the kind the guest gave it.
///
/// A count's rate is what it gained across the window divided by the seconds the window
/// covers, so a run whose heartbeats stopped for a while is described by the seconds it
/// reports, not by how many lines it printed.
pub fn drift(t: &Trail, window: u64, flag_at: f64) -> Vec<Drift> {
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
        let kind = t.kind(name);
        let rate = |from: u64, to: u64, secs: f64| {
            if secs <= 0.0 {
                0.0
            } else {
                to.saturating_sub(from) as f64 / secs
            }
        };
        let counting = matches!(kind, Kind::Count);
        let mut drift = Drift {
            name: name.clone(),
            kind,
            // A level and a mean have no rate: what is worth reporting is where each stood.
            early_rate: if counting {
                rate(a, b, early_span)
            } else {
                0.0
            },
            late_rate: if counting { rate(c, d, late_span) } else { 0.0 },
            early_value: b,
            late_value: d,
            early_rise: b.saturating_sub(a),
            late_rise: d.saturating_sub(c),
            finding: None,
        };
        drift.finding = judge(&drift, flag_at);
        out.push(drift);
    }
    out
}

/// The drift table. Every number, with the ones worth looking at marked and named.
pub fn drift_report(drifts: &[Drift]) -> String {
    let mut s = String::from(
        "  number                 kind      early/s      late/s     early      late   change\n",
    );
    for d in drifts {
        s.push_str(&format!(
            "  {:<22} {:<5} {:>10.2} {:>11.2} {:>9} {:>9} {:>8}{}\n",
            d.name,
            d.kind.word(),
            d.early_rate,
            d.late_rate,
            d.early_value,
            d.late_value,
            d.change_text(),
            if d.finding.is_some() { " <-" } else { "" }
        ));
    }
    s
}

/// The findings, as sentences: what moved and why that is worth a look. Empty on a healthy
/// run, which is the point — four marks that mean nothing hide the one that does.
pub fn findings(drifts: &[Drift], unmatched: &[&str]) -> Vec<String> {
    let mut out: Vec<String> = drifts
        .iter()
        .filter_map(|d| {
            d.finding
                .map(|f| format!("{}: {} ({})", d.name, f.why(), d.change_text()))
        })
        .collect();
    out.extend(
        unmatched.iter().map(|name| {
            format!("{name}: the guest named a kind for a number no heartbeat carries")
        }),
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const KINDS: &str = "stress field kinds: latest=level; worst=level; answered in mean=mean";
    const ONE: &str = "stress heartbeat 1/60 s: heap 100 (refused 2), ipc 50, sleeps 3 \
                       (latest +900 us), vm 4, pages 5, audits 1 ok";
    const TWO: &str = "stress heartbeat 11/60 s: heap 1100 (refused 22), ipc 550, sleeps 33 \
                       (latest +950 us), vm 44, pages 55, audits 11 ok";

    /// A trail of `n` seconds where `body(i)` is the text after `s:`.
    fn run_of(n: u64, body: impl Fn(u64) -> String) -> Trail {
        let mut console = String::from(KINDS);
        console.push('\n');
        for i in 0..=n {
            console.push_str(&format!("stress heartbeat {i}/{n} s: {}\n", body(i)));
        }
        trail(console.as_bytes())
    }

    fn named<'a>(d: &'a [Drift], name: &str) -> &'a Drift {
        d.iter().find(|d| d.name == name).expect(name)
    }

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
    fn the_guest_says_which_numbers_are_levels_and_which_are_means() {
        let t = trail(format!("{KINDS}\n{ONE}\n").as_bytes());
        assert_eq!(t.kind("latest"), Kind::Level);
        assert_eq!(t.kind("worst"), Kind::Level);
        assert_eq!(t.kind("answered in mean"), Kind::Mean);
        // Anything the guest did not name is a count, which is the test that finds a leak.
        assert_eq!(t.kind("heap"), Kind::Count);
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
        let d = drift(&t, 0, 0.25);
        // With a zero window each end is one heartbeat, so no span and no rate; the levels
        // are still the ones reported.
        assert_eq!((named(&d, "heap").early_value, named(&d, "heap").late_value), (100, 1100));
    }

    #[test]
    fn a_count_whose_rate_moves_is_a_finding() {
        // Ten seconds at a hundred a second, then ten at ten a second.
        let t = run_of(20, |i| {
            let heap = if i <= 10 {
                i * 100
            } else {
                1000 + (i - 10) * 10
            };
            format!("heap {heap}, audits {i} ok")
        });
        let d = drift(&t, 5, 0.25);
        let heap = named(&d, "heap");
        assert!((heap.early_rate - 100.0).abs() < 1.0, "{heap:?}");
        assert!((heap.late_rate - 10.0).abs() < 1.0, "{heap:?}");
        assert_eq!(heap.finding, Some(Finding::RateMoved));
        assert!(drift_report(&d).contains("<-"));
        assert_eq!(findings(&d, &[]).len(), 1);
    }

    #[test]
    fn a_count_that_starts_late_is_a_finding_a_rate_alone_would_miss() {
        // Nothing for the first half, then a steady climb: there is no early rate to
        // compare against, and the old comparison printed `-` and moved on.
        let t = run_of(20, |i| {
            let leaked = i.saturating_sub(10) * 5;
            format!("heap {}, leaked {leaked}, audits {i} ok", i * 100)
        });
        let d = drift(&t, 5, 0.25);
        let leaked = named(&d, "leaked");
        assert_eq!(leaked.rate_change(), None, "no early rate to compare");
        assert_eq!(leaked.finding, Some(Finding::Started));
        assert!(findings(&d, &[]).iter().any(|f| f.starts_with("leaked:")));
    }

    #[test]
    fn a_count_that_goes_backwards_is_a_finding() {
        let t = run_of(20, |i| {
            let heap = if i <= 10 { i * 100 } else { (20 - i) * 100 };
            format!("heap {heap}, audits {i} ok")
        });
        assert_eq!(named(&drift(&t, 5, 0.25), "heap").finding, Some(Finding::WentBackwards));
    }

    #[test]
    fn a_high_water_mark_that_settles_is_not_a_finding() {
        // `latest` is the worst lateness seen so far. It rises early, then stops: the run
        // got no worse, which is good news and must not read as a rate that collapsed.
        let t = run_of(20, |i| {
            let latest = if i <= 5 { 500 + i * 100 } else { 1000 };
            format!("heap {}, sleeps 1 (latest +{latest} us), audits {i} ok", i * 100)
        });
        let d = drift(&t, 5, 0.25);
        let latest = named(&d, "latest");
        assert_eq!(latest.kind, Kind::Level);
        assert_eq!((latest.early_rate, latest.late_rate), (0.0, 0.0));
        assert_eq!(latest.finding, None, "{latest:?}");
        assert!(latest.change_text().contains("settled"));
        // And the count beside it still compares as a rate.
        assert!(named(&d, "heap").early_rate > 0.0);
    }

    #[test]
    fn a_high_water_mark_still_climbing_at_the_end_is_a_finding() {
        // The same level, rising just as fast at the end as at the start: nothing is
        // bounding it, which is what a long run is for.
        let t = run_of(20, |i| {
            format!("heap {}, sleeps 1 (latest +{} us), audits {i} ok", i * 100, 500 + i * 100)
        });
        let d = drift(&t, 5, 0.25);
        assert_eq!(named(&d, "latest").finding, Some(Finding::StillClimbing));
    }

    #[test]
    fn a_mean_that_holds_is_not_a_finding_and_one_that_moves_is() {
        let held = run_of(20, |i| {
            format!("heap {}, shootdowns 5 (answered in mean 135 us), audits {i} ok", i * 100)
        });
        let d = drift(&held, 5, 0.25);
        let mean = named(&d, "answered in mean");
        assert_eq!(mean.kind, Kind::Mean);
        assert_eq!(mean.finding, None, "a mean that never moved: {mean:?}");
        assert!(findings(&d, &[]).is_empty(), "{:?}", findings(&d, &[]));

        let moved = run_of(20, |i| {
            let mean = if i <= 10 { 135 } else { 400 };
            format!("heap {}, shootdowns 5 (answered in mean {mean} us), audits {i} ok", i * 100)
        });
        let d = drift(&moved, 5, 0.25);
        assert_eq!(named(&d, "answered in mean").finding, Some(Finding::MeanMoved));
    }

    #[test]
    fn a_healthy_run_flags_nothing() {
        // Every number climbing at its own steady rate, a level that settles, a mean that
        // holds: the shape of a run that found nothing.
        let t = run_of(60, |i| {
            let latest = if i <= 10 { 500 + i * 10 } else { 600 };
            format!(
                "heap {} (refused {}), ipc {}, sleeps {i} (latest +{latest} us), \
                 shootdowns {} (stalled waits 0, answered in mean 135 us, worst 900 us), \
                 audits {i} ok",
                i * 100,
                i * 7,
                i * 50,
                i * 20
            )
        });
        let d = drift(&t, 10, 0.25);
        assert!(!d.is_empty());
        let found = findings(&d, &t.unmatched_kinds());
        assert!(found.is_empty(), "a healthy run flagged: {found:?}");
        assert!(!drift_report(&d).contains("<-"));
    }

    #[test]
    fn a_kind_for_a_number_no_heartbeat_carries_is_itself_a_finding() {
        // The legend and the prose that it describes are written in two places, so they can
        // drift apart; when they do, the field it meant is being read as a count.
        let t = trail(
            b"stress field kinds: peak in flight=level\n\
              stress heartbeat 1/1 s: heap 1, audits 1 ok\n",
        );
        assert_eq!(t.unmatched_kinds(), ["peak in flight"]);
        let found = findings(&drift(&t, 1, 0.25), &t.unmatched_kinds());
        assert_eq!(found.len(), 1);
        assert!(found[0].contains("no heartbeat carries"), "{found:?}");
    }

    #[test]
    fn a_field_ends_at_its_comma_and_does_not_label_the_next_one() {
        let line = "stress heartbeat 3/9 s: sleeps 7 (latest +900 us, 2 late with the CPU \
                    elsewhere), vm 4, audits 3 ok";
        let h = &trail(line.as_bytes()).heartbeats[0];
        let names: Vec<&str> = h.fields.iter().map(|(n, _)| n.as_str()).collect();
        assert!(names.contains(&"vm"), "{names:?}");
        assert!(!names.iter().any(|n| n.contains("elsewhere vm")), "{names:?}");
    }

    #[test]
    fn a_run_with_no_heartbeats_drifts_nowhere() {
        assert!(drift(&trail(b""), 60, 0.25).is_empty());
    }
}

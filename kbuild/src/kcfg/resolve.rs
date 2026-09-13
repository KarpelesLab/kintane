//! Resolving a symbol table plus a set of requested values into a complete,
//! explicit configuration.
//!
//! Nothing is left implicit: every symbol ends up with a value and a recorded reason
//! for it, so `.config` plus a source tree is a reproducible build, and so a conflict
//! can be explained as a chain rather than as "cannot satisfy constraints".

use super::*;
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq)]
pub enum Reason {
    /// Asked for by the user or a preset.
    Explicit(String),
    /// Forced on by another symbol's `select`.
    SelectedBy(String),
    /// A `default` clause applied.
    Default,
    /// `depends on` was not satisfied, so the symbol is off regardless.
    DependsUnmet(String),
    /// Chosen as the member of a `choice`.
    Chosen(String),
    /// Nothing said anything; the type's zero value.
    Unset,
}

impl Reason {
    pub fn describe(&self, sym: &str) -> String {
        match self {
            Reason::Explicit(src) => format!("{sym} is set by {src}"),
            Reason::SelectedBy(by) => format!("{sym} is selected by {by}"),
            Reason::Default => format!("{sym} takes its default"),
            Reason::DependsUnmet(d) => format!("{sym} requires `{d}`, which is not satisfied"),
            Reason::Chosen(c) => format!("{sym} is the selected member of choice {c}"),
            Reason::Unset => format!("{sym} is unset"),
        }
    }
}

#[derive(Debug)]
pub struct ResolveError {
    pub msg: String,
    pub chain: Vec<String>,
    pub hint: Option<String>,
}

impl std::fmt::Display for ResolveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "{}", self.msg)?;
        for (i, c) in self.chain.iter().enumerate() {
            writeln!(f, "{}{}", "  ".repeat(i + 1), c)?;
        }
        if let Some(h) = &self.hint {
            write!(f, "  {h}")?;
        }
        Ok(())
    }
}

#[derive(Debug, Default)]
pub struct Resolution {
    pub values: BTreeMap<String, Val>,
    pub reasons: BTreeMap<String, Reason>,
}

impl Resolution {
    pub fn tri(&self, name: &str) -> Tri {
        self.values.get(name).map(|v| v.as_tri()).unwrap_or(Tri::N)
    }
    pub fn is_on(&self, name: &str) -> bool {
        self.tri(name) != Tri::N
    }
    // Reads int symbols such as NR_CPUS; used once a subsystem needs one.
    #[allow(dead_code)]
    pub fn int(&self, name: &str) -> i64 {
        match self.values.get(name) {
            Some(Val::Int(i)) => *i,
            _ => 0,
        }
    }
    pub fn str(&self, name: &str) -> &str {
        match self.values.get(name) {
            Some(Val::Str(s)) => s,
            _ => "",
        }
    }
    /// The literal form used for `=` comparisons in expressions.
    fn literal(&self, name: &str) -> String {
        match self.values.get(name) {
            Some(Val::Str(s)) => s.clone(),
            Some(Val::Int(i)) => i.to_string(),
            Some(Val::Tri(t)) => t.as_str().to_string(),
            None => String::new(),
        }
    }
}

/// A requested value: `SMP=y`, `NR_CPUS=8`, together with where it came from.
#[derive(Debug, Clone)]
pub struct Request {
    pub symbol: String,
    pub text: String,
    pub source: String,
}

const MAX_ROUNDS: usize = 100;

pub fn resolve(
    table: &SymbolTable,
    requests: &[Request],
) -> Result<Resolution, Vec<ResolveError>> {
    let mut errors = Vec::new();

    // --- validate and type the requests ---
    let mut explicit: BTreeMap<String, (Val, String)> = BTreeMap::new();
    for r in requests {
        let Some(sym) = table.get(&r.symbol) else {
            errors.push(ResolveError {
                msg: format!("unknown configuration symbol `{}`", r.symbol),
                chain: vec![format!("requested by {}", r.source)],
                hint: nearest(table, &r.symbol)
                    .map(|n| format!("did you mean `{n}`?")),
            });
            continue;
        };
        if sym.readonly {
            errors.push(ResolveError {
                msg: format!("`{}` is not user-settable", r.symbol),
                chain: vec![
                    format!("declared readonly at {}", sym.origin),
                    "it describes what the hardware can do, not what to build".into(),
                ],
                hint: Some("set the architecture instead".into()),
            });
            continue;
        }
        match super::parse::parse_val_pub(&r.text, sym.kind) {
            Ok(v) => {
                explicit.insert(r.symbol.clone(), (v, r.source.clone()));
            }
            Err(m) => errors.push(ResolveError {
                msg: format!("bad value for `{}`: {m}", r.symbol),
                chain: vec![format!(
                    "`{}` is {} ({})",
                    r.symbol,
                    sym.kind.name(),
                    sym.origin
                )],
                hint: None,
            }),
        }
    }
    if !errors.is_empty() {
        return Err(errors);
    }

    // --- fixed point ---
    let mut res = Resolution::default();
    for name in &table.order {
        let sym = &table.symbols[name];
        res.values.insert(name.clone(), Val::zero(sym.kind));
        res.reasons.insert(name.clone(), Reason::Unset);
    }

    // Which symbols are forced on by an active `select`. Declared outside the loop
    // so that validation can consult the converged state.
    let mut selected: BTreeMap<String, String> = BTreeMap::new();

    let mut rounds = 0;
    loop {
        rounds += 1;
        if rounds > MAX_ROUNDS {
            return Err(vec![ResolveError {
                msg: "configuration did not converge".into(),
                chain: vec![format!("gave up after {MAX_ROUNDS} rounds")],
                hint: Some("this indicates a dependency cycle in the .kcfg files".into()),
            }]);
        }

        let snapshot = res.values.clone();

        selected.clear();
        for name in &table.order {
            let sym = &table.symbols[name];
            if !res.is_on(name) {
                continue;
            }
            for sel in &sym.selects {
                let ok = sel
                    .cond
                    .as_ref()
                    .map(|c| eval(c, &res) != Tri::N)
                    .unwrap_or(true);
                if ok {
                    selected.entry(sel.target.clone()).or_insert(name.clone());
                }
            }
        }

        for name in &table.order {
            let sym = &table.symbols[name];

            let visible = sym
                .depends
                .as_ref()
                .map(|d| eval(d, &res))
                .unwrap_or(Tri::Y);

            let (val, reason) = if visible == Tri::N {
                (
                    Val::zero(sym.kind),
                    Reason::DependsUnmet(
                        sym.depends.as_ref().map(|d| d.to_string()).unwrap_or_default(),
                    ),
                )
            } else if sym.choice.is_some() {
                // Choice members are decided below, not here.
                continue;
            } else if let Some((v, src)) = explicit.get(name) {
                (v.clone(), Reason::Explicit(src.clone()))
            } else if let Some(by) = selected.get(name) {
                (Val::Tri(Tri::Y), Reason::SelectedBy(by.clone()))
            } else if let Some(d) = first_matching_default(sym, &res) {
                (d, Reason::Default)
            } else {
                (Val::zero(sym.kind), Reason::Unset)
            };

            res.values.insert(name.clone(), val);
            res.reasons.insert(name.clone(), reason);
        }

        // --- choices: exactly one member on ---
        for (cname, choice) in &table.choices {
            let visible = choice
                .depends
                .as_ref()
                .map(|d| eval(d, &res))
                .unwrap_or(Tri::Y);

            let usable: Vec<&String> = choice
                .members
                .iter()
                .filter(|m| {
                    table.symbols[*m]
                        .depends
                        .as_ref()
                        .map(|d| eval(d, &res) != Tri::N)
                        .unwrap_or(true)
                })
                .collect();

            let picked: Option<String> = if visible == Tri::N {
                None
            } else if let Some(m) = usable
                .iter()
                .find(|m| matches!(explicit.get(**m), Some((Val::Tri(Tri::Y), _))))
            {
                Some((*m).clone())
            } else if let Some(d) = choice.defaults.iter().find(|d| {
                let cond_ok = d.cond.as_ref().map(|c| eval(c, &res) != Tri::N).unwrap_or(true);
                cond_ok
                    && match &d.value {
                        Val::Str(n) => usable.iter().any(|m| *m == n),
                        _ => false,
                    }
            }) {
                match &d.value {
                    Val::Str(n) => Some(n.clone()),
                    _ => None,
                }
            } else {
                usable.first().map(|m| (*m).clone())
            };

            for m in &choice.members {
                let on = picked.as_deref() == Some(m.as_str());
                res.values
                    .insert(m.clone(), Val::Tri(if on { Tri::Y } else { Tri::N }));
                res.reasons.insert(
                    m.clone(),
                    if on {
                        match explicit.get(m) {
                            Some((_, src)) => Reason::Explicit(src.clone()),
                            None => Reason::Chosen(cname.clone()),
                        }
                    } else if visible == Tri::N {
                        Reason::DependsUnmet(
                            choice.depends.as_ref().map(|d| d.to_string()).unwrap_or_default(),
                        )
                    } else {
                        Reason::Chosen(cname.clone())
                    },
                );
            }
        }

        if res.values == snapshot {
            break;
        }
    }

    // --- validate ---
    for name in &table.order {
        let sym = &table.symbols[name];
        let Some((want, _src)) = explicit.get(name) else {
            continue;
        };

        if want.as_tri() == Tri::N {
            if let Some(by) = selected.get(name) {
                errors.push(ResolveError {
                    msg: format!("cannot set {name}={}", want.display()),
                    chain: vec![
                        format!("{name} is selected by {by}"),
                        describe_origin(&res, by),
                    ],
                    hint: Some(format!("to disable {name}, first disable {by}")),
                });
                continue;
            }
        }

        let got = &res.values[name];
        if got == want {
            continue;
        }

        match &res.reasons[name] {
            Reason::SelectedBy(by) => errors.push(ResolveError {
                msg: format!("cannot set {name}={}", want.display()),
                chain: vec![
                    format!("{name} is selected by {by}"),
                    describe_origin(&res, by),
                ],
                hint: Some(format!("to change {name}, first disable {by}")),
            }),
            Reason::DependsUnmet(d) => {
                let mut chain = vec![format!("{name} depends on `{d}`")];
                if let Some(d) = &sym.depends {
                    let mut syms = Vec::new();
                    d.symbols(&mut syms);
                    for s in syms.iter().filter(|s| !res.is_on(s)).take(3) {
                        chain.push(format!("{s} is {}", res.tri(s).as_str()));
                    }
                }
                errors.push(ResolveError {
                    msg: format!("cannot set {name}={}", want.display()),
                    chain,
                    hint: Some(format!(
                        "enable its dependencies first, or leave {name} unset"
                    )),
                })
            }
            Reason::Chosen(c) => errors.push(ResolveError {
                msg: format!("cannot set {name}={}", want.display()),
                chain: vec![format!("{name} belongs to choice {c}, which selected another member")],
                hint: Some(format!("set exactly one member of {c} to y")),
            }),
            other => errors.push(ResolveError {
                msg: format!(
                    "{name} resolved to {} despite being set to {}",
                    got.display(),
                    want.display()
                ),
                chain: vec![other.describe(name)],
                hint: None,
            }),
        }
    }

    // ranges
    for name in &table.order {
        let sym = &table.symbols[name];
        if matches!(res.reasons[name], Reason::DependsUnmet(_)) {
            continue; // forced to zero because it is not part of this build
        }
        if let (Some((lo, hi)), Val::Int(v)) = (sym.range, &res.values[name]) {
            if *v < lo || *v > hi {
                errors.push(ResolveError {
                    msg: format!("{name} = {v} is outside its range {lo}..={hi}"),
                    chain: vec![
                        res.reasons[name].describe(name),
                        format!("declared at {}", sym.origin),
                    ],
                    hint: None,
                });
            }
        }
    }

    // every select target must exist
    for name in &table.order {
        for sel in &table.symbols[name].selects {
            if !table.symbols.contains_key(&sel.target) {
                errors.push(ResolveError {
                    msg: format!("{name} selects unknown symbol `{}`", sel.target),
                    chain: vec![format!("at {}", table.symbols[name].origin)],
                    hint: nearest(table, &sel.target).map(|n| format!("did you mean `{n}`?")),
                });
            }
        }
    }

    if errors.is_empty() {
        Ok(res)
    } else {
        Err(errors)
    }
}

fn describe_origin(res: &Resolution, sym: &str) -> String {
    match res.reasons.get(sym) {
        Some(r) => r.describe(sym),
        None => format!("{sym} is set"),
    }
}

fn eval(e: &Expr, res: &Resolution) -> Tri {
    e.eval(&|n| res.tri(n), &|n| res.literal(n))
}

fn first_matching_default(sym: &Symbol, res: &Resolution) -> Option<Val> {
    sym.defaults
        .iter()
        .find(|d| d.cond.as_ref().map(|c| eval(c, res) != Tri::N).unwrap_or(true))
        .map(|d| d.value.clone())
}

/// Cheap edit-distance suggestion for a misspelled symbol.
fn nearest(table: &SymbolTable, name: &str) -> Option<String> {
    let mut best: Option<(usize, String)> = None;
    for cand in table.symbols.keys() {
        let d = distance(name, cand);
        if d <= 3 && best.as_ref().map(|(bd, _)| d < *bd).unwrap_or(true) {
            best = Some((d, cand.clone()));
        }
    }
    best.map(|(_, n)| n)
}

fn distance(a: &str, b: &str) -> usize {
    let (a, b): (Vec<char>, Vec<char>) = (a.chars().collect(), b.chars().collect());
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    let mut cur = vec![0usize; b.len() + 1];
    for i in 1..=a.len() {
        cur[0] = i;
        for j in 1..=b.len() {
            let cost = usize::from(a[i - 1] != b[j - 1]);
            cur[j] = (prev[j] + 1).min(cur[j - 1] + 1).min(prev[j - 1] + cost);
        }
        std::mem::swap(&mut prev, &mut cur);
    }
    prev[b.len()]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    static SEQ: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

    fn table(src: &str) -> SymbolTable {
        let n = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "kcfg-resolve-{}-{n}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("t.kcfg");
        std::fs::File::create(&p)
            .unwrap()
            .write_all(src.as_bytes())
            .unwrap();
        super::super::parse::parse_tree(&p).unwrap()
    }

    fn req(pairs: &[(&str, &str)]) -> Vec<Request> {
        pairs
            .iter()
            .map(|(s, v)| Request {
                symbol: s.to_string(),
                text: v.to_string(),
                source: "test".into(),
            })
            .collect()
    }

    const BASE: &str = r#"
config ARCH_HAS_MMU
    bool
    readonly
    default y

config ARCH_HAS_SMP
    bool
    readonly
    default y

config SMP
    bool "SMP"
    depends on ARCH_HAS_SMP
    default y if ARCH_HAS_SMP

config NUMA
    bool "NUMA"
    select SMP

config NR_CPUS
    int "CPUs"
    depends on SMP
    range 2 4096
    default 8
"#;

    #[test]
    fn defaults_apply_and_dependencies_propagate() {
        let t = table(BASE);
        let r = resolve(&t, &[]).unwrap();
        assert!(r.is_on("SMP"));
        assert_eq!(r.int("NR_CPUS"), 8);
        assert!(!r.is_on("NUMA"));
    }

    #[test]
    fn select_forces_and_conflicts_are_explained() {
        let t = table(BASE);
        // NUMA selects SMP, so SMP=n is a contradiction, not a silent override.
        let errs = resolve(&t, &req(&[("NUMA", "y"), ("SMP", "n")])).unwrap_err();
        let text = errs.iter().map(|e| e.to_string()).collect::<String>();
        assert!(text.contains("cannot set SMP=n"), "{text}");
        assert!(text.contains("selected by NUMA"), "{text}");
        assert!(text.contains("first disable NUMA"), "{text}");
    }

    #[test]
    fn unmet_dependency_is_reported_with_the_chain() {
        let t = table(BASE);
        let errs = resolve(&t, &req(&[("SMP", "n"), ("NR_CPUS", "64")])).unwrap_err();
        let text = errs.iter().map(|e| e.to_string()).collect::<String>();
        assert!(text.contains("NR_CPUS"), "{text}");
        assert!(text.contains("depends on"), "{text}");
    }

    #[test]
    fn dependent_symbols_are_off_when_parent_is_off() {
        let t = table(BASE);
        let r = resolve(&t, &req(&[("SMP", "n")])).unwrap();
        assert!(!r.is_on("SMP"));
        assert_eq!(r.int("NR_CPUS"), 0);
        assert!(matches!(r.reasons["NR_CPUS"], Reason::DependsUnmet(_)));
    }

    #[test]
    fn range_violations_are_caught() {
        let t = table(BASE);
        let errs = resolve(&t, &req(&[("NR_CPUS", "9000")])).unwrap_err();
        assert!(errs[0].to_string().contains("outside its range"));
    }

    #[test]
    fn readonly_symbols_reject_assignment() {
        let t = table(BASE);
        let errs = resolve(&t, &req(&[("ARCH_HAS_MMU", "n")])).unwrap_err();
        assert!(errs[0].to_string().contains("not user-settable"));
    }

    #[test]
    fn unknown_symbol_suggests_a_neighbour() {
        let t = table(BASE);
        let errs = resolve(&t, &req(&[("NR_CPU", "4")])).unwrap_err();
        let s = errs[0].to_string();
        assert!(s.contains("unknown configuration symbol"), "{s}");
        assert!(s.contains("NR_CPUS"), "{s}");
    }

    #[test]
    fn choice_picks_exactly_one_member() {
        let t = table(
            r#"
config ARCH_HAS_MMU
    bool
    readonly
    default y

choice MM_MODEL
    prompt "Memory model"
    default MM_PAGED if ARCH_HAS_MMU
    default MM_FLAT
    config MM_PAGED
        bool "Paged"
        depends on ARCH_HAS_MMU
    config MM_FLAT
        bool "Flat"
endchoice
"#,
        );
        let r = resolve(&t, &[]).unwrap();
        assert!(r.is_on("MM_PAGED"));
        assert!(!r.is_on("MM_FLAT"));

        let r = resolve(&t, &req(&[("MM_FLAT", "y")])).unwrap();
        assert!(r.is_on("MM_FLAT"));
        assert!(!r.is_on("MM_PAGED"));
    }

    #[test]
    fn choice_falls_back_when_a_member_is_unavailable() {
        // Without an MMU, MM_PAGED is not usable and the choice must pick MM_FLAT.
        let t = table(
            r#"
config ARCH_HAS_MMU
    bool
    readonly
    default n

choice MM_MODEL
    prompt "Memory model"
    default MM_PAGED if ARCH_HAS_MMU
    default MM_FLAT
    config MM_PAGED
        bool "Paged"
        depends on ARCH_HAS_MMU
    config MM_FLAT
        bool "Flat"
endchoice
"#,
        );
        let r = resolve(&t, &[]).unwrap();
        assert!(r.is_on("MM_FLAT"), "must fall back to the flat model");
        assert!(!r.is_on("MM_PAGED"));
    }

    #[test]
    fn every_symbol_gets_a_recorded_reason() {
        let t = table(BASE);
        let r = resolve(&t, &[]).unwrap();
        for name in &t.order {
            assert!(r.reasons.contains_key(name), "{name} has no reason");
            assert!(r.values.contains_key(name), "{name} has no value");
        }
    }
}

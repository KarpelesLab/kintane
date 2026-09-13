//! Resolving a symbol table plus a set of requested values into a complete,
//! explicit configuration.
//!
//! Nothing is left implicit: every symbol ends up with a value and a recorded reason
//! for it, so `.config` plus a source tree is a reproducible build, and so a conflict
//! can be explained as a chain rather than as "cannot satisfy constraints".
//!
//! # Tristates, with and without modules
//!
//! A `tristate` is `n`, `m` (built as a loadable module) or `y` (built in). `m` is
//! only meaningful while [`MODULES`] is `y`, which `config/main.kcfg` allows on x86-64
//! with `MM_PAGED`. Everywhere else the rules are the ones that keep a configuration
//! honest without modules. Which units an `m` builds, and what it may not build, is the
//! crate graph's decision (`graph::plan`), since only it knows which units are modules.
//!
//! - **Asking for `m`** — in a preset, `--set` or `menuconfig` — is an error while modules are off.
//!   A module that silently became built-in code is not what was asked for, and on a small target
//!   the difference is the size budget.
//! - **A `default m` or a `select` from an `m` symbol** is built in, and the reason says so. These
//!   are the `.kcfg` author's "include it, as a module where modules exist", and building it in is
//!   that sentence's meaning on a kernel without modules.
//! - **`depends on`** limits a tristate to the value of its condition: a driver that depends on an
//!   `m` bus can be `m` but not `y`. A `bool` whose condition is `m` may still be `y`, since it has
//!   no module form.
//!
//! # `select` and `depends on`
//!
//! A `select` forces its target on, but it does not override the target's own
//! `depends on`. Selecting a symbol whose dependencies are unmet is an error naming both
//! sides, rather than Kconfig's warning and a symbol that is on without what it needs.
//! Only `bool` and `tristate` symbols can be selected, and never a `choice` member: a
//! choice picks exactly one member, and a `select` from outside would be a second voice
//! in that decision.

use std::collections::BTreeMap;

use super::*;

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
    /// A tristate held below what it would otherwise be by its `depends on`.
    Limited(String),
    /// Would have been `m`, and is built in because this configuration has no modules.
    /// Carries the description of why it would have been `m`.
    BuiltIn(String),
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
            Reason::Limited(d) => format!("{sym} is limited by `{d}`"),
            Reason::BuiltIn(why) => {
                format!("{sym} is built in: it would be m ({why}), and {MODULES} is not y")
            }
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

#[derive(Debug, Default, Clone)]
pub struct Resolution {
    pub values: BTreeMap<String, Val>,
    pub reasons: BTreeMap<String, Reason>,
    /// Which symbols an active `select` forces, and who selects them, as converged.
    pub selected: BTreeMap<String, String>,
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
            Some(v @ (Val::Int(_) | Val::Hex(_) | Val::Tri(_))) => v.display(),
            None => String::new(),
        }
    }

    /// Why `sym` has its value, followed back through whatever forced it: a symbol that
    /// is selected is explained by why its selector is on, and one whose dependency is
    /// unmet by the dependencies that are off. What `menuconfig` shows for "why".
    pub fn explain(&self, table: &SymbolTable, sym: &str) -> Vec<String> {
        let mut out = Vec::new();
        let mut at = sym.to_string();
        let mut seen = Vec::new();
        while !seen.contains(&at) {
            seen.push(at.clone());
            let Some(reason) = self.reasons.get(&at) else {
                break;
            };
            out.push(reason.describe(&at));
            match reason {
                Reason::SelectedBy(by) => at = by.clone(),
                Reason::DependsUnmet(_) | Reason::Limited(_) => {
                    if let Some(d) = table.get(&at).and_then(|s| s.depends.as_ref()) {
                        let mut syms = Vec::new();
                        d.symbols(&mut syms);
                        for s in syms.iter().filter(|s| table.get(s).is_some()) {
                            out.push(format!("  {s} is {}", self.values[s].display()));
                        }
                    }
                    break;
                }
                _ => break,
            }
        }
        out
    }
}

/// A requested value: `SMP=y`, `NR_CPUS=8`, together with where it came from.
#[derive(Debug, Clone, PartialEq)]
pub struct Request {
    pub symbol: String,
    pub text: String,
    pub source: String,
}

const MAX_ROUNDS: usize = 100;

pub fn resolve(table: &SymbolTable, requests: &[Request]) -> Result<Resolution, Vec<ResolveError>> {
    let mut errors = Vec::new();

    // --- validate and type the requests ---
    let mut explicit: BTreeMap<String, (Val, String)> = BTreeMap::new();
    for r in requests {
        let Some(sym) = table.get(&r.symbol) else {
            errors.push(ResolveError {
                msg: format!("unknown configuration symbol `{}`", r.symbol),
                chain: vec![format!("requested by {}", r.source)],
                hint: nearest(table, &r.symbol).map(|n| format!("did you mean `{n}`?")),
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

    // Which symbols are forced by an active `select`, by whom, and to what level: an
    // `m` symbol selects at `m`. Declared outside the loop so that validation can
    // consult the converged state.
    let mut selected: BTreeMap<String, (String, Tri)> = BTreeMap::new();

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
        let modules = res.tri(MODULES) == Tri::Y;

        selected.clear();
        for name in &table.order {
            let sym = &table.symbols[name];
            let level = res.tri(name);
            if level == Tri::N {
                continue;
            }
            for sel in &sym.selects {
                let cond = sel.cond.as_ref().map(|c| eval(c, &res)).unwrap_or(Tri::Y);
                let at = level.and(cond);
                if at == Tri::N {
                    continue;
                }
                let e = selected
                    .entry(sel.target.clone())
                    .or_insert((name.clone(), at));
                if at > e.1 {
                    *e = (name.clone(), at);
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
            let depends_text = || {
                sym.depends
                    .as_ref()
                    .map(|d| d.to_string())
                    .unwrap_or_default()
            };

            let (mut val, mut reason) = if visible == Tri::N {
                (Val::zero(sym.kind), Reason::DependsUnmet(depends_text()))
            } else if sym.choice.is_some() {
                // Choice members are decided below, not here.
                continue;
            } else if let Some((v, src)) = explicit.get(name) {
                (v.clone(), Reason::Explicit(src.clone()))
            } else if let Some((by, level)) = selected.get(name) {
                (Val::Tri(*level), Reason::SelectedBy(by.clone()))
            } else if let Some(d) = first_matching_default(sym, &res) {
                (d, Reason::Default)
            } else {
                (Val::zero(sym.kind), Reason::Unset)
            };

            if let Val::Tri(t) = val {
                let mut t = t;
                match sym.kind {
                    // A bool has no module form; anything that reaches it as `m` is on.
                    Kind::Bool if t == Tri::M => t = Tri::Y,
                    Kind::Tristate => {
                        if t > visible && !matches!(reason, Reason::SelectedBy(_)) {
                            t = visible;
                            reason = Reason::Limited(depends_text());
                        }
                        if t == Tri::M && !modules {
                            t = Tri::Y;
                            // An explicit `m` keeps its reason, so validation reports it.
                            if !matches!(reason, Reason::Explicit(_)) {
                                reason = Reason::BuiltIn(reason.describe(name));
                            }
                        }
                    }
                    _ => {}
                }
                val = Val::Tri(t);
            }

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
                let cond_ok = d
                    .cond
                    .as_ref()
                    .map(|c| eval(c, &res) != Tri::N)
                    .unwrap_or(true);
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
                            choice
                                .depends
                                .as_ref()
                                .map(|d| d.to_string())
                                .unwrap_or_default(),
                        )
                    } else if table.symbols[m]
                        .depends
                        .as_ref()
                        .is_some_and(|d| eval(d, &res) == Tri::N)
                    {
                        Reason::DependsUnmet(
                            table.symbols[m]
                                .depends
                                .as_ref()
                                .map(|d| d.to_string())
                                .unwrap_or_default(),
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

    res.selected = selected
        .iter()
        .map(|(k, (by, _))| (k.clone(), by.clone()))
        .collect();
    let modules = res.tri(MODULES) == Tri::Y;

    // --- validate explicit requests ---
    for name in &table.order {
        let sym = &table.symbols[name];
        let Some((want, _src)) = explicit.get(name) else {
            continue;
        };

        if *want == Val::Tri(Tri::M) && !modules {
            let why = if table.get(MODULES).is_none() {
                format!(
                    "no `{MODULES}` symbol is declared: loadable modules do not exist yet, so \
                     nothing can be built as one"
                )
            } else {
                describe_origin(&res, MODULES)
            };
            errors.push(ResolveError {
                msg: format!("cannot set {name}=m"),
                chain: vec![format!("{name}=m asks for a loadable module"), why],
                hint: Some(format!("set {name}=y to build it in, or {name}=n to leave it out")),
            });
            continue;
        }

        if let (Val::Tri(w), Some((by, level))) = (want, selected.get(name)) {
            if w < level {
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
            Reason::DependsUnmet(d) | Reason::Limited(d) => {
                let mut chain = vec![format!("{name} depends on `{d}`")];
                chain.extend(unmet_parts(sym, &res));
                let limited = matches!(res.reasons[name], Reason::Limited(_));
                errors.push(ResolveError {
                    msg: format!("cannot set {name}={}", want.display()),
                    chain,
                    hint: Some(if limited {
                        format!("its dependencies allow at most {}", got.display())
                    } else {
                        format!("enable its dependencies first, or leave {name} unset")
                    }),
                })
            }
            Reason::Chosen(c) => errors.push(ResolveError {
                msg: format!("cannot set {name}={}", want.display()),
                chain: vec![format!(
                    "{name} belongs to choice {c}, which selected another member"
                )],
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

    // --- validate selects ---
    for (target, (by, _)) in &selected {
        let Some(sym) = table.get(target) else {
            continue; // reported below, from the declaration
        };
        let mut chain = vec![format!("{by} selects {target}"), describe_origin(&res, by)];
        let problem = if !matches!(sym.kind, Kind::Bool | Kind::Tristate) {
            Some((
                format!("{by} selects {target}, which is {}", sym.kind.name()),
                "only bool and tristate symbols can be selected".to_string(),
            ))
        } else if let Some(c) = &sym.choice {
            Some((
                format!("{by} selects {target}, a member of choice {c}"),
                format!("a choice picks its own member; make {c}'s default depend on {by}"),
            ))
        } else if let Reason::DependsUnmet(d) = &res.reasons[target] {
            chain.push(format!("{target} depends on `{d}`"));
            chain.extend(unmet_parts(sym, &res));
            Some((
                format!("{by} selects {target}, whose dependencies are not met"),
                format!("make {by} depend on what {target} needs, or stop selecting it"),
            ))
        } else {
            None
        };
        if let Some((msg, hint)) = problem {
            errors.push(ResolveError {
                msg,
                chain,
                hint: Some(hint),
            });
        }
    }

    // ranges
    for name in &table.order {
        let sym = &table.symbols[name];
        if matches!(res.reasons[name], Reason::DependsUnmet(_)) {
            continue; // forced to zero because it is not part of this build
        }
        let Some(v) = res.values[name].as_int() else {
            continue;
        };
        if let Some(r) = active_range(sym, &res) {
            if v < r.lo || v > r.hi {
                let show = |n: i128| match sym.kind {
                    Kind::Hex => format!("{n:#x}"),
                    _ => n.to_string(),
                };
                let mut chain = vec![
                    res.reasons[name].describe(name),
                    format!("declared at {}", sym.origin),
                ];
                if let Some(c) = &r.cond {
                    chain.push(format!("the range applies because `{c}` holds"));
                }
                errors.push(ResolveError {
                    msg: format!(
                        "{name} = {} is outside its range {}..={}",
                        res.values[name].display(),
                        show(r.lo),
                        show(r.hi)
                    ),
                    chain,
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

/// The first `range` whose condition holds, which is the one that bounds `sym`.
pub fn active_range<'a>(sym: &'a Symbol, res: &Resolution) -> Option<&'a Range> {
    sym.ranges.iter().find(|r| {
        r.cond
            .as_ref()
            .map(|c| eval(c, res) != Tri::N)
            .unwrap_or(true)
    })
}

/// The symbols in `sym`'s `depends on` that are off, for an error chain.
fn unmet_parts(sym: &Symbol, res: &Resolution) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(d) = &sym.depends {
        let mut syms = Vec::new();
        d.symbols(&mut syms);
        for s in syms.iter().filter(|s| !res.is_on(s)).take(3) {
            out.push(format!("{s} is {}", res.tri(s).as_str()));
        }
    }
    out
}

fn describe_origin(res: &Resolution, sym: &str) -> String {
    match res.reasons.get(sym) {
        Some(r) => r.describe(sym),
        None => format!("{sym} is set"),
    }
}

pub fn eval(e: &Expr, res: &Resolution) -> Tri {
    e.eval(&|n| res.tri(n), &|n| res.literal(n))
}

fn first_matching_default(sym: &Symbol, res: &Resolution) -> Option<Val> {
    sym.defaults
        .iter()
        .find(|d| {
            d.cond
                .as_ref()
                .map(|c| eval(c, res) != Tri::N)
                .unwrap_or(true)
        })
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
pub mod tests {
    use std::io::Write;

    use super::*;

    static SEQ: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

    pub fn table(src: &str) -> SymbolTable {
        let n = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("kcfg-resolve-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("t.kcfg");
        std::fs::File::create(&p)
            .unwrap()
            .write_all(src.as_bytes())
            .unwrap();
        super::super::parse::parse_tree(&p).unwrap()
    }

    pub fn req(pairs: &[(&str, &str)]) -> Vec<Request> {
        pairs
            .iter()
            .map(|(s, v)| Request {
                symbol: s.to_string(),
                text: v.to_string(),
                source: "test".into(),
            })
            .collect()
    }

    fn errors(t: &SymbolTable, pairs: &[(&str, &str)]) -> String {
        resolve(t, &req(pairs))
            .unwrap_err()
            .iter()
            .map(|e| e.to_string() + "\n")
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
        let text = errors(&t, &[("NUMA", "y"), ("SMP", "n")]);
        assert!(text.contains("cannot set SMP=n"), "{text}");
        assert!(text.contains("selected by NUMA"), "{text}");
        assert!(text.contains("first disable NUMA"), "{text}");
    }

    #[test]
    fn unmet_dependency_is_reported_with_the_chain() {
        let t = table(BASE);
        let text = errors(&t, &[("SMP", "n"), ("NR_CPUS", "64")]);
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
        assert!(matches!(r.reasons["MM_PAGED"], Reason::DependsUnmet(_)));
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

    // --- tristate ----------------------------------------------------------------------

    const TRI: &str = r#"
config BUS
    tristate "A bus"

config DRIVER
    tristate "A driver on the bus"
    depends on BUS

config HELPER
    tristate "Something drivers select"

config USER
    tristate "Selects the helper"
    select HELPER
    select BOOL_HELPER

config BOOL_HELPER
    bool "A bool the user selects"

config FLAG
    bool "A bool on the bus"
    depends on BUS
"#;

    fn with_modules(src: &str) -> SymbolTable {
        table(&format!("config MODULES\n    bool \"Modules\"\n{src}"))
    }

    #[test]
    fn m_is_refused_while_modules_do_not_exist() {
        let t = table(TRI);
        let text = errors(&t, &[("BUS", "m")]);
        assert!(text.contains("cannot set BUS=m"), "{text}");
        assert!(text.contains("no `MODULES` symbol is declared"), "{text}");
        assert!(text.contains("set BUS=y to build it in"), "{text}");
    }

    #[test]
    fn m_is_refused_while_modules_are_off_and_says_why_they_are() {
        let t = with_modules(TRI);
        let text = errors(&t, &[("MODULES", "n"), ("BUS", "m")]);
        assert!(text.contains("cannot set BUS=m"), "{text}");
        assert!(text.contains("MODULES is set by test"), "{text}");
    }

    #[test]
    fn m_resolves_to_m_when_modules_are_on() {
        let t = with_modules(TRI);
        let r = resolve(&t, &req(&[("MODULES", "y"), ("BUS", "m"), ("DRIVER", "m")])).unwrap();
        assert_eq!(r.tri("BUS"), Tri::M);
        assert_eq!(r.tri("DRIVER"), Tri::M);
    }

    #[test]
    fn a_default_m_is_built_in_without_modules_and_the_reason_says_so() {
        let t = table("config A\n    tristate \"a\"\n    default m\n");
        let r = resolve(&t, &[]).unwrap();
        assert_eq!(r.tri("A"), Tri::Y);
        let why = r.reasons["A"].describe("A");
        assert!(why.contains("built in") && why.contains("default"), "{why}");
    }

    #[test]
    fn depends_limits_a_tristate_but_not_a_bool() {
        let t = with_modules(TRI);
        let r = resolve(&t, &req(&[("MODULES", "y"), ("BUS", "m"), ("FLAG", "y")])).unwrap();
        assert_eq!(r.tri("FLAG"), Tri::Y, "a bool has no module form");

        let text = errors(&t, &[("MODULES", "y"), ("BUS", "m"), ("DRIVER", "y")]);
        assert!(text.contains("cannot set DRIVER=y"), "{text}");
        assert!(text.contains("depends on `BUS`"), "{text}");
        assert!(text.contains("at most m"), "{text}");
    }

    #[test]
    fn a_select_carries_its_selectors_level() {
        let t = with_modules(TRI);
        let r = resolve(&t, &req(&[("MODULES", "y"), ("USER", "m")])).unwrap();
        assert_eq!(r.tri("HELPER"), Tri::M, "selected by an m symbol");
        assert_eq!(r.values["BOOL_HELPER"], Val::Tri(Tri::Y), "a bool selected at m is y");
        let r = resolve(&t, &req(&[("MODULES", "y"), ("USER", "y")])).unwrap();
        assert_eq!(r.tri("HELPER"), Tri::Y);

        let text = errors(&t, &[("MODULES", "y"), ("USER", "y"), ("HELPER", "m")]);
        assert!(text.contains("cannot set HELPER=m"), "{text}");
        assert!(text.contains("selected by USER"), "{text}");
    }

    // --- select and depends --------------------------------------------------------------

    #[test]
    fn selecting_a_symbol_whose_dependencies_are_unmet_is_an_error_naming_both() {
        let t = table(
            r#"
config HW
    bool "hardware"

config DRIVER
    bool "driver"
    depends on HW

config FEATURE
    bool "feature"
    select DRIVER
"#,
        );
        let text = errors(&t, &[("FEATURE", "y")]);
        assert!(
            text.contains("FEATURE selects DRIVER, whose dependencies are not met"),
            "{text}"
        );
        assert!(text.contains("DRIVER depends on `HW`"), "{text}");
        assert!(text.contains("HW is n"), "{text}");
        assert!(text.contains("FEATURE is set by test"), "{text}");
        // Met, it is fine.
        assert!(resolve(&t, &req(&[("FEATURE", "y"), ("HW", "y")])).is_ok());
    }

    #[test]
    fn only_bools_and_tristates_can_be_selected_and_never_choice_members() {
        let t = table(
            r#"
config N
    int "n"
    default 1

choice C
    prompt "c"
    config C1
        bool "c1"
    config C2
        bool "c2"
endchoice

config BAD_INT
    bool "selects an int"
    select N

config BAD_CHOICE
    bool "selects a member"
    select C2
"#,
        );
        let text = errors(&t, &[("BAD_INT", "y")]);
        assert!(text.contains("which is int"), "{text}");
        let text = errors(&t, &[("BAD_CHOICE", "y")]);
        assert!(text.contains("a member of choice C"), "{text}");
    }

    // --- ranges and hex ----------------------------------------------------------------

    #[test]
    fn the_first_range_whose_condition_holds_applies() {
        let t = table(
            r#"
config SMALL
    bool "small"

config HEAP_KIB
    int "heap"
    range 4 64 if SMALL
    range 64 65536
    default 128
"#,
        );
        assert!(resolve(&t, &[]).is_ok());
        let text = errors(&t, &[("SMALL", "y")]);
        assert!(text.contains("HEAP_KIB = 128 is outside its range 4..=64"), "{text}");
        assert!(text.contains("because `SMALL` holds"), "{text}");
        assert!(resolve(&t, &req(&[("SMALL", "y"), ("HEAP_KIB", "32")])).is_ok());
    }

    #[test]
    fn hex_symbols_resolve_compare_and_report_ranges_in_hex() {
        let t = table(
            r#"
config BASE
    hex "base"
    range 0x1000 0xffff
    default 0x2000

config AT_DEFAULT
    bool "at default"
    default y if BASE = 0x2000
"#,
        );
        let r = resolve(&t, &[]).unwrap();
        assert_eq!(r.values["BASE"], Val::Hex(0x2000));
        assert!(r.is_on("AT_DEFAULT"), "`=` compares the hex form");
        let text = errors(&t, &[("BASE", "0x10000")]);
        assert!(text.contains("BASE = 0x10000 is outside its range 0x1000..=0xffff"), "{text}");
        let text = errors(&t, &[("BASE", "4096")]);
        assert!(text.contains("written 0x"), "{text}");
    }

    #[test]
    fn explain_follows_a_select_back_to_what_set_its_selector() {
        let t = table(BASE);
        let r = resolve(&t, &req(&[("NUMA", "y")])).unwrap();
        let why = r.explain(&t, "SMP");
        assert_eq!(why[0], "SMP is selected by NUMA");
        assert_eq!(why[1], "NUMA is set by test");

        let r = resolve(&t, &req(&[("SMP", "n")])).unwrap();
        let why = r.explain(&t, "NR_CPUS").join("\n");
        assert!(why.contains("requires `SMP`") && why.contains("SMP is n"), "{why}");
    }
}

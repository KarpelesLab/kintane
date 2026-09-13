//! Parser for `.kcfg` files.
//!
//! ```text
//! menu "Kernel"
//!     depends on !MINIMAL
//!
//! config SMP
//!     bool "Symmetric multiprocessing"
//!     depends on ARCH_HAS_SMP
//!     default y if ARCH_HAS_SMP
//!     help
//!         Support more than one CPU.
//!
//! config LOAD_ADDR
//!     hex "Load address"
//!     range 0x100000 0xffffffff
//!     range 0x40000000 0x7fffffff if ARCH_AARCH64
//!     default 0x100000
//!
//! choice MM_MODEL
//!     prompt "Memory model"
//!     default MM_PAGED if ARCH_HAS_MMU
//!     config MM_PAGED
//!         bool "Paged virtual memory"
//!         depends on ARCH_HAS_MMU
//! endchoice
//!
//! endmenu
//!
//! source "arch.kcfg"
//! ```

use std::path::{Path, PathBuf};

use super::*;

#[derive(Debug)]
pub struct ParseError {
    pub file: String,
    pub line: usize,
    pub msg: String,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}: {}", self.file, self.line, self.msg)
    }
}

/// Parse `entry` and everything it `source`s, relative to `entry`'s directory.
pub fn parse_tree(entry: &Path) -> Result<SymbolTable, ParseError> {
    let mut table = SymbolTable::default();
    let mut seen = Vec::new();
    let mut menus = Vec::new();
    parse_file(entry, &mut table, &mut seen, &mut menus)?;
    fold_menu_depends(&mut table);
    Ok(table)
}

/// Give every entry inside a menu its menu's conditions, innermost last, so that
/// `depends on` on a menu means what it says without the resolver knowing menus exist.
fn fold_menu_depends(table: &mut SymbolTable) {
    let chain = |menus: &[Menu], mut at: Option<usize>| {
        let mut conds = Vec::new();
        while let Some(i) = at {
            if let Some(d) = &menus[i].depends {
                conds.push(d.clone());
            }
            at = menus[i].parent;
        }
        conds.reverse();
        conds
    };
    let join = |mut conds: Vec<Expr>, own: Option<Expr>| {
        conds.extend(own);
        conds
            .into_iter()
            .reduce(|a, b| Expr::And(Box::new(a), Box::new(b)))
    };
    for sym in table.symbols.values_mut() {
        let conds = chain(&table.menus, sym.menu);
        if !conds.is_empty() {
            sym.depends = join(conds, sym.depends.take());
        }
    }
    for choice in table.choices.values_mut() {
        let conds = chain(&table.menus, choice.menu);
        if !conds.is_empty() {
            choice.depends = join(conds, choice.depends.take());
        }
    }
}

fn parse_file(
    path: &Path,
    table: &mut SymbolTable,
    seen: &mut Vec<PathBuf>,
    menus: &mut Vec<usize>,
) -> Result<(), ParseError> {
    let canonical = path.to_path_buf();
    if seen.contains(&canonical) {
        return Ok(()); // already included; sourcing the same file twice is harmless
    }
    seen.push(canonical);

    let name = path.display().to_string();
    let src = std::fs::read_to_string(path).map_err(|e| ParseError {
        file: name.clone(),
        line: 0,
        msg: format!("cannot read: {e}"),
    })?;

    let lines: Vec<&str> = src.lines().collect();
    let mut i = 0;
    // The symbol or choice currently accumulating attributes.
    let mut cur: Option<String> = None;
    let mut cur_choice: Option<String> = None;
    // A menu whose header lines (`depends on`) are still being read.
    let mut menu_header: Option<usize> = None;
    // Menus opened in this file must be closed in it: a block that straddles `source`
    // boundaries is a layout nobody could read.
    let menus_at_entry = menus.len();

    while i < lines.len() {
        let raw = lines[i];
        let lineno = i + 1;
        let indent = raw.len() - raw.trim_start().len();
        let s = raw.trim();
        i += 1;

        if s.is_empty() || s.starts_with('#') {
            continue;
        }

        let err = |msg: String| ParseError {
            file: name.clone(),
            line: lineno,
            msg,
        };
        let origin = Origin {
            file: name.clone(),
            line: lineno,
        };

        let (kw, rest) = split_word(s);
        match kw {
            "source" => {
                let target = unquote(rest.trim());
                let dir = path.parent().unwrap_or(Path::new("."));
                parse_file(&dir.join(target), table, seen, menus)?;
            }

            "menu" => {
                if cur_choice.is_some() {
                    return Err(err("a `menu` cannot open inside a `choice`".into()));
                }
                let title = unquote(rest.trim()).to_string();
                if title.is_empty() {
                    return Err(err("`menu` needs a title".into()));
                }
                table.menus.push(Menu {
                    title,
                    depends: None,
                    parent: menus.last().copied(),
                    origin,
                });
                let idx = table.menus.len() - 1;
                menus.push(idx);
                menu_header = Some(idx);
                cur = None;
            }

            "endmenu" => {
                if cur_choice.is_some() {
                    return Err(err(
                        "`endmenu` inside a `choice`; close it with `endchoice`".into()
                    ));
                }
                if menus.len() <= menus_at_entry {
                    return Err(err("`endmenu` without `menu` in this file".into()));
                }
                menus.pop();
                menu_header = None;
                cur = None;
            }

            "config" => {
                let sym = rest.trim().to_string();
                if sym.is_empty() {
                    return Err(err("`config` needs a name".into()));
                }
                if table.symbols.contains_key(&sym) {
                    return Err(err(format!("symbol `{sym}` is already defined")));
                }
                let symbol = Symbol {
                    name: sym.clone(),
                    kind: Kind::Bool,
                    prompt: None,
                    depends: None,
                    defaults: Vec::new(),
                    selects: Vec::new(),
                    ranges: Vec::new(),
                    help: None,
                    readonly: false,
                    choice: cur_choice.clone(),
                    menu: menus.last().copied(),
                    origin,
                };
                if let Some(c) = &cur_choice {
                    table
                        .choices
                        .get_mut(c)
                        .expect("choice exists")
                        .members
                        .push(sym.clone());
                }
                table.order.push(sym.clone());
                table.symbols.insert(sym.clone(), symbol);
                cur = Some(sym);
                menu_header = None;
            }

            "choice" => {
                let cname = rest.trim().to_string();
                if cname.is_empty() {
                    return Err(err("`choice` needs a name".into()));
                }
                if cur_choice.is_some() {
                    return Err(err("a `choice` cannot nest inside another".into()));
                }
                table.choices.insert(
                    cname.clone(),
                    Choice {
                        name: cname.clone(),
                        prompt: None,
                        members: Vec::new(),
                        defaults: Vec::new(),
                        depends: None,
                        menu: menus.last().copied(),
                        origin,
                    },
                );
                cur_choice = Some(cname);
                cur = None;
                menu_header = None;
            }

            "endchoice" => {
                if cur_choice.take().is_none() {
                    return Err(err("`endchoice` without `choice`".into()));
                }
                cur = None;
            }

            "bool" | "tristate" | "int" | "hex" | "string" => {
                let sym = cur
                    .as_ref()
                    .ok_or_else(|| err(format!("`{kw}` outside of a `config` block")))?;
                let sy = table.symbols.get_mut(sym).unwrap();
                sy.kind = match kw {
                    "bool" => Kind::Bool,
                    "tristate" => Kind::Tristate,
                    "int" => Kind::Int,
                    "hex" => Kind::Hex,
                    _ => Kind::Str,
                };
                if sy.choice.is_some() && sy.kind != Kind::Bool {
                    return Err(err(format!(
                        "choice member `{sym}` is {kw}; members are bool, since exactly one is on"
                    )));
                }
                let p = rest.trim();
                if !p.is_empty() {
                    sy.prompt = Some(unquote(p).to_string());
                }
            }

            "prompt" => {
                let p = unquote(rest.trim()).to_string();
                if let Some(c) = &cur_choice {
                    if cur.is_none() {
                        table.choices.get_mut(c).unwrap().prompt = Some(p);
                        continue;
                    }
                }
                let sym = cur
                    .as_ref()
                    .ok_or_else(|| err("`prompt` outside a block".into()))?;
                table.symbols.get_mut(sym).unwrap().prompt = Some(p);
            }

            "depends" => {
                let cond = rest
                    .trim()
                    .strip_prefix("on ")
                    .ok_or_else(|| err("expected `depends on <expression>`".into()))?;
                let e = expr::parse(cond).map_err(|m| err(m))?;
                match (&cur, menu_header, &cur_choice) {
                    (Some(sym), _, _) => table.symbols.get_mut(sym).unwrap().depends = Some(e),
                    (None, Some(m), _) => table.menus[m].depends = Some(e),
                    (None, None, Some(c)) => table.choices.get_mut(c).unwrap().depends = Some(e),
                    _ => return Err(err("`depends on` outside a block".into())),
                }
            }

            "select" => {
                let sym = cur
                    .as_ref()
                    .ok_or_else(|| err("`select` outside a `config` block".into()))?;
                let (target, cond) = split_if(rest.trim());
                let cond = match cond {
                    Some(c) => Some(expr::parse(c).map_err(|m| err(m))?),
                    None => None,
                };
                table.symbols.get_mut(sym).unwrap().selects.push(Select {
                    target: target.to_string(),
                    cond,
                });
            }

            "default" => {
                let (value_txt, cond) = split_if(rest.trim());
                let cond = match cond {
                    Some(c) => Some(expr::parse(c).map_err(|m| err(m))?),
                    None => None,
                };
                match (&cur, &cur_choice) {
                    (Some(sym), _) => {
                        let kind = table.symbols[sym].kind;
                        let value = parse_val(value_txt, kind).map_err(|m| err(m))?;
                        table
                            .symbols
                            .get_mut(sym)
                            .unwrap()
                            .defaults
                            .push(Default { value, cond });
                    }
                    (None, Some(c)) => {
                        // A choice's default names one of its members.
                        table.choices.get_mut(c).unwrap().defaults.push(Default {
                            value: Val::Str(value_txt.trim().to_string()),
                            cond,
                        });
                    }
                    _ => return Err(err("`default` outside a block".into())),
                }
            }

            "range" => {
                let sym = cur
                    .as_ref()
                    .ok_or_else(|| err("`range` outside a `config` block".into()))?;
                let kind = table.symbols[sym].kind;
                if !matches!(kind, Kind::Int | Kind::Hex) {
                    return Err(err(format!(
                        "`range` on `{sym}`, which is {}; only int and hex symbols have one \
                         (declare the type before the range)",
                        kind.name()
                    )));
                }
                let (bounds, cond) = split_if(rest.trim());
                let parts: Vec<&str> = bounds.split_whitespace().collect();
                if parts.len() != 2 {
                    return Err(err("expected `range <low> <high> [if <condition>]`".into()));
                }
                let bound = |t: &str, which: &str| {
                    parse_val(t, kind)
                        .ok()
                        .and_then(|v| v.as_int())
                        .ok_or_else(|| {
                            err(format!("bad range {which} `{t}` for a {}", kind.name()))
                        })
                };
                let lo = bound(parts[0], "low")?;
                let hi = bound(parts[1], "high")?;
                if lo > hi {
                    return Err(err(format!("range low {} exceeds high {}", parts[0], parts[1])));
                }
                let cond = match cond {
                    Some(c) => Some(expr::parse(c).map_err(|m| err(m))?),
                    None => None,
                };
                table
                    .symbols
                    .get_mut(sym)
                    .unwrap()
                    .ranges
                    .push(Range { lo, hi, cond });
            }

            "readonly" => {
                let sym = cur
                    .as_ref()
                    .ok_or_else(|| err("`readonly` outside a `config` block".into()))?;
                table.symbols.get_mut(sym).unwrap().readonly = true;
            }

            "help" => {
                let sym = cur
                    .clone()
                    .ok_or_else(|| err("`help` outside a block".into()))?;
                let mut text = String::new();
                while i < lines.len() {
                    let l = lines[i];
                    let li = l.len() - l.trim_start().len();
                    if l.trim().is_empty() {
                        text.push('\n');
                        i += 1;
                        continue;
                    }
                    if li <= indent {
                        break;
                    }
                    text.push_str(l.trim());
                    text.push('\n');
                    i += 1;
                }
                table.symbols.get_mut(&sym).unwrap().help = Some(text.trim().to_string());
            }

            other => {
                return Err(err(format!("unknown keyword `{other}`")));
            }
        }
    }

    if cur_choice.is_some() {
        return Err(ParseError {
            file: name,
            line: lines.len(),
            msg: "`choice` without `endchoice`".into(),
        });
    }
    if menus.len() > menus_at_entry {
        let open = &table.menus[*menus.last().unwrap()];
        return Err(ParseError {
            file: name,
            line: open.origin.line,
            msg: format!("`menu \"{}\"` without `endmenu`", open.title),
        });
    }
    Ok(())
}

fn split_word(s: &str) -> (&str, &str) {
    match s.find(char::is_whitespace) {
        Some(i) => (&s[..i], &s[i..]),
        None => (s, ""),
    }
}

/// Split `VALUE if CONDITION` into its two halves.
fn split_if(s: &str) -> (&str, Option<&str>) {
    // Find ` if ` at the top level; our expressions never contain the bare word.
    if let Some(pos) = find_kw(s, "if") {
        (s[..pos].trim(), Some(s[pos + 2..].trim()))
    } else {
        (s.trim(), None)
    }
}

fn find_kw(s: &str, kw: &str) -> Option<usize> {
    let b = s.as_bytes();
    let mut i = 0;
    while let Some(p) = s[i..].find(kw) {
        let at = i + p;
        let before_ok = at == 0 || b[at - 1].is_ascii_whitespace();
        let after = at + kw.len();
        let after_ok = after >= b.len() || b[after].is_ascii_whitespace();
        if before_ok && after_ok {
            return Some(at);
        }
        i = at + kw.len();
    }
    None
}

/// Parse a value written in a `.kcfg` default, a preset, or `--set`.
pub fn parse_val_pub(txt: &str, kind: Kind) -> Result<Val, String> {
    parse_val(txt, kind)
}

fn parse_val(txt: &str, kind: Kind) -> Result<Val, String> {
    let t = txt.trim();
    match kind {
        Kind::Bool | Kind::Tristate => {
            let tri = Tri::from_str(t).ok_or_else(|| format!("expected y/m/n, found `{t}`"))?;
            if kind == Kind::Bool && tri == Tri::M {
                return Err("`m` is not valid for a bool symbol".into());
            }
            Ok(Val::Tri(tri))
        }
        Kind::Int => {
            let cleaned = t.replace('_', "");
            let v = if let Some(h) = cleaned.strip_prefix("0x") {
                i64::from_str_radix(h, 16)
            } else {
                cleaned.parse()
            };
            Ok(Val::Int(v.map_err(|_| format!("expected an integer, found `{t}`"))?))
        }
        Kind::Hex => {
            // The prefix is required: `100000` read as hex is an address a factor of
            // sixteen away from the one a reader of the preset would assume.
            let cleaned = t.replace('_', "");
            let digits = cleaned
                .strip_prefix("0x")
                .or_else(|| cleaned.strip_prefix("0X"))
                .ok_or_else(|| format!("expected a hex value written 0x..., found `{t}`"))?;
            u64::from_str_radix(digits, 16)
                .map(Val::Hex)
                .map_err(|_| format!("expected a hex value that fits 64 bits, found `{t}`"))
        }
        Kind::Str => Ok(Val::Str(unquote(t).to_string())),
    }
}

fn unquote(s: &str) -> &str {
    s.strip_prefix('"')
        .and_then(|r| r.strip_suffix('"'))
        .unwrap_or(s)
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;

    static SEQ: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

    fn parse_files(files: &[(&str, &str)]) -> Result<SymbolTable, ParseError> {
        // Unique per call: these tests run in parallel and must not share a file.
        let n = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("kcfg-test-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        for (name, src) in files {
            let mut f = std::fs::File::create(dir.join(name)).unwrap();
            f.write_all(src.as_bytes()).unwrap();
        }
        parse_tree(&dir.join(files[0].0))
    }

    fn parse_str(src: &str) -> Result<SymbolTable, ParseError> {
        parse_files(&[("t.kcfg", src)])
    }

    #[test]
    fn parses_a_symbol_with_every_attribute() {
        let t = parse_str(
            r#"
config NR_CPUS
    int "Maximum number of CPUs"
    depends on SMP
    range 2 4096
    default 8
    help
        How many CPUs to support.
        Second line.
"#,
        )
        .unwrap();
        let s = t.get("NR_CPUS").unwrap();
        assert_eq!(s.kind, Kind::Int);
        assert_eq!(s.prompt.as_deref(), Some("Maximum number of CPUs"));
        assert_eq!((s.ranges[0].lo, s.ranges[0].hi), (2, 4096));
        assert!(s.ranges[0].cond.is_none());
        assert_eq!(s.defaults.len(), 1);
        assert_eq!(s.defaults[0].value, Val::Int(8));
        assert!(s.help.as_ref().unwrap().contains("Second line"));
        assert_eq!(s.depends.as_ref().unwrap().to_string(), "SMP");
    }

    #[test]
    fn default_with_condition() {
        let t = parse_str("config A\n    bool\n    default y if B && C\n").unwrap();
        let d = &t.get("A").unwrap().defaults[0];
        assert_eq!(d.value, Val::Tri(Tri::Y));
        assert_eq!(d.cond.as_ref().unwrap().to_string(), "(B && C)");
    }

    #[test]
    fn choice_collects_members() {
        let t = parse_str(
            r#"
choice MM_MODEL
    prompt "Memory model"
    default MM_FLAT
    config MM_PAGED
        bool "Paged"
        depends on ARCH_HAS_MMU
    config MM_FLAT
        bool "Flat"
endchoice
"#,
        )
        .unwrap();
        let c = t.choices.get("MM_MODEL").unwrap();
        assert_eq!(c.members, vec!["MM_PAGED", "MM_FLAT"]);
        assert_eq!(c.prompt.as_deref(), Some("Memory model"));
        assert_eq!(t.get("MM_PAGED").unwrap().choice.as_deref(), Some("MM_MODEL"));
    }

    #[test]
    fn rejects_duplicate_symbols() {
        let e = parse_str("config A\n    bool\nconfig A\n    bool\n").unwrap_err();
        assert!(e.msg.contains("already defined"), "{}", e.msg);
    }

    #[test]
    fn rejects_unterminated_choice() {
        let e = parse_str("choice C\n    config A\n        bool\n").unwrap_err();
        assert!(e.msg.contains("endchoice"), "{}", e.msg);
    }

    #[test]
    fn rejects_m_for_bool() {
        let e = parse_str("config A\n    bool\n    default m\n").unwrap_err();
        assert!(e.msg.contains("not valid for a bool"), "{}", e.msg);
    }

    #[test]
    fn if_splitting_does_not_trip_on_substrings() {
        // "MODIFY" contains "if" but must not be treated as the keyword.
        assert_eq!(split_if("MODIFY"), ("MODIFY", None));
        assert_eq!(split_if("y if A"), ("y", Some("A")));
    }

    #[test]
    fn hex_values_and_ranges_parse_as_unsigned() {
        let t = parse_str(
            r#"
config BASE
    hex "Base"
    range 0x1000 0xffffffffffffffff
    range 0x40000000 0x7fffffff if ARM
    default 0xffff_ffff_8000_0000
"#,
        )
        .unwrap();
        let s = t.get("BASE").unwrap();
        assert_eq!(s.kind, Kind::Hex);
        assert_eq!(s.defaults[0].value, Val::Hex(0xffff_ffff_8000_0000));
        assert_eq!(s.defaults[0].value.display(), "0xffffffff80000000");
        assert_eq!(s.ranges.len(), 2);
        assert_eq!(s.ranges[0].hi, i128::from(u64::MAX), "not a negative number");
        assert_eq!(s.ranges[1].cond.as_ref().unwrap().to_string(), "ARM");
    }

    #[test]
    fn hex_requires_its_prefix() {
        let e = parse_str("config A\n    hex\n    default 100000\n").unwrap_err();
        assert!(e.msg.contains("0x"), "{}", e.msg);
    }

    #[test]
    fn range_is_refused_on_types_that_have_none() {
        let e = parse_str("config A\n    bool\n    range 1 2\n").unwrap_err();
        assert!(e.msg.contains("only int and hex"), "{}", e.msg);
        let e = parse_str("config A\n    int\n    range 9 2\n").unwrap_err();
        assert!(e.msg.contains("exceeds"), "{}", e.msg);
    }

    #[test]
    fn choice_members_must_be_bool() {
        let e = parse_str("choice C\n    config A\n        int\nendchoice\n").unwrap_err();
        assert!(e.msg.contains("members are bool"), "{}", e.msg);
    }

    #[test]
    fn menu_conditions_apply_to_everything_inside_including_nested_menus_and_choices() {
        let t = parse_str(
            r#"
config OUTSIDE
    bool "outside"

menu "Outer"
    depends on A

config ONE
    bool "one"
    depends on B

menu "Inner"
    depends on C

config TWO
    bool "two"

choice PICK
    prompt "pick"
    config P1
        bool "p1"
endchoice

endmenu
endmenu
"#,
        )
        .unwrap();
        assert!(t.get("OUTSIDE").unwrap().depends.is_none());
        assert_eq!(t.get("ONE").unwrap().depends.as_ref().unwrap().to_string(), "(A && B)");
        assert_eq!(t.get("TWO").unwrap().depends.as_ref().unwrap().to_string(), "(A && C)");
        assert_eq!(t.choices["PICK"].depends.as_ref().unwrap().to_string(), "(A && C)");
        assert_eq!(t.menus.len(), 2);
        assert_eq!(t.menus[1].parent, Some(0));
        assert_eq!(t.get("TWO").unwrap().menu, Some(1));
    }

    #[test]
    fn menus_must_balance_within_a_file() {
        let e = parse_str("menu \"M\"\nconfig A\n    bool\n").unwrap_err();
        assert!(e.msg.contains("without `endmenu`"), "{}", e.msg);
        let e = parse_str("endmenu\n").unwrap_err();
        assert!(e.msg.contains("without `menu`"), "{}", e.msg);
        // Opened here, closed in a sourced file: refused, even though the counts balance.
        let e = parse_files(&[
            ("main.kcfg", "menu \"M\"\nsource \"sub.kcfg\"\n"),
            ("sub.kcfg", "endmenu\n"),
        ])
        .unwrap_err();
        assert!(e.msg.contains("without `menu` in this file"), "{}", e.msg);
    }

    #[test]
    fn a_sourced_file_inherits_the_enclosing_menu() {
        let t = parse_files(&[
            ("main.kcfg", "menu \"M\"\n    depends on X\nsource \"sub.kcfg\"\nendmenu\n"),
            ("sub.kcfg", "config A\n    bool \"a\"\n"),
        ])
        .unwrap();
        assert_eq!(t.get("A").unwrap().depends.as_ref().unwrap().to_string(), "X");
    }
}

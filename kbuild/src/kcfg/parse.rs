//! Parser for `.kcfg` files.
//!
//! ```text
//! config SMP
//!     bool "Symmetric multiprocessing"
//!     depends on ARCH_HAS_SMP
//!     default y if ARCH_HAS_SMP
//!     help
//!         Support more than one CPU.
//!
//! choice MM_MODEL
//!     prompt "Memory model"
//!     default MM_PAGED if ARCH_HAS_MMU
//!     config MM_PAGED
//!         bool "Paged virtual memory"
//!         depends on ARCH_HAS_MMU
//! endchoice
//!
//! source "arch.kcfg"
//! ```

use super::*;
use std::path::{Path, PathBuf};

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
    parse_file(entry, &mut table, &mut seen)?;
    Ok(table)
}

fn parse_file(
    path: &Path,
    table: &mut SymbolTable,
    seen: &mut Vec<PathBuf>,
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

        let (kw, rest) = split_word(s);
        match kw {
            "source" => {
                let target = unquote(rest.trim());
                let dir = path.parent().unwrap_or(Path::new("."));
                parse_file(&dir.join(target), table, seen)?;
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
                    range: None,
                    help: None,
                    readonly: false,
                    choice: cur_choice.clone(),
                    origin: Origin {
                        file: name.clone(),
                        line: lineno,
                    },
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
            }

            "choice" => {
                let cname = rest.trim().to_string();
                if cname.is_empty() {
                    return Err(err("`choice` needs a name".into()));
                }
                table.choices.insert(
                    cname.clone(),
                    Choice {
                        name: cname.clone(),
                        prompt: None,
                        members: Vec::new(),
                        defaults: Vec::new(),
                        depends: None,
                        origin: Origin {
                            file: name.clone(),
                            line: lineno,
                        },
                    },
                );
                cur_choice = Some(cname);
                cur = None;
            }

            "endchoice" => {
                if cur_choice.take().is_none() {
                    return Err(err("`endchoice` without `choice`".into()));
                }
                cur = None;
            }

            "bool" | "tristate" | "int" | "string" => {
                let sym = cur.as_ref().ok_or_else(|| {
                    err(format!("`{kw}` outside of a `config` block"))
                })?;
                let sy = table.symbols.get_mut(sym).unwrap();
                sy.kind = match kw {
                    "bool" => Kind::Bool,
                    "tristate" => Kind::Tristate,
                    "int" => Kind::Int,
                    _ => Kind::Str,
                };
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
                let sym = cur.as_ref().ok_or_else(|| err("`prompt` outside a block".into()))?;
                table.symbols.get_mut(sym).unwrap().prompt = Some(p);
            }

            "depends" => {
                let cond = rest.trim().strip_prefix("on ").ok_or_else(|| {
                    err("expected `depends on <expression>`".into())
                })?;
                let e = expr::parse(cond).map_err(|m| err(m))?;
                match (&cur, &cur_choice) {
                    (Some(sym), _) => table.symbols.get_mut(sym).unwrap().depends = Some(e),
                    (None, Some(c)) => table.choices.get_mut(c).unwrap().depends = Some(e),
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
                let parts: Vec<&str> = rest.split_whitespace().collect();
                if parts.len() != 2 {
                    return Err(err("expected `range <low> <high>`".into()));
                }
                let lo = parts[0].parse::<i64>().map_err(|_| err("bad range low".into()))?;
                let hi = parts[1].parse::<i64>().map_err(|_| err("bad range high".into()))?;
                if lo > hi {
                    return Err(err(format!("range low {lo} exceeds high {hi}")));
                }
                table.symbols.get_mut(sym).unwrap().range = Some((lo, hi));
            }

            "readonly" => {
                let sym = cur
                    .as_ref()
                    .ok_or_else(|| err("`readonly` outside a `config` block".into()))?;
                table.symbols.get_mut(sym).unwrap().readonly = true;
            }

            "help" => {
                let sym = cur.clone().ok_or_else(|| err("`help` outside a block".into()))?;
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
                table.symbols.get_mut(&sym).unwrap().help =
                    Some(text.trim().to_string());
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
    use super::*;
    use std::io::Write;

    static SEQ: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

    fn parse_str(src: &str) -> Result<SymbolTable, ParseError> {
        // Unique per call: these tests run in parallel and must not share a file.
        let n = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("kcfg-test-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("t.kcfg");
        let mut f = std::fs::File::create(&p).unwrap();
        f.write_all(src.as_bytes()).unwrap();
        parse_tree(&p)
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
        assert_eq!(s.range, Some((2, 4096)));
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
}

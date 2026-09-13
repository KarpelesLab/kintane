//! A small TOML reader covering the subset our own files use: comments, tables,
//! dotted table headers, strings, integers, booleans, arrays, and inline tables.
//!
//! Deliberately not a complete TOML implementation — it parses files we write and
//! control (`toolchain.toml`, `kmod.toml`), and it reports a line number when it
//! cannot. Anything it rejects is something we should not have written.

use std::collections::BTreeMap;
use std::fmt;

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Str(String),
    Int(i64),
    Bool(bool),
    Array(Vec<Value>),
    Table(Table),
}

pub type Table = BTreeMap<String, Value>;

impl Value {
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::Str(s) => Some(s),
            _ => None,
        }
    }
    // Part of the value API; exercised by the tests and by kcfg int symbols.
    #[allow(dead_code)]
    pub fn as_int(&self) -> Option<i64> {
        match self {
            Value::Int(i) => Some(*i),
            _ => None,
        }
    }
    #[allow(dead_code)]
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(b) => Some(*b),
            _ => None,
        }
    }
    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Value::Array(a) => Some(a),
            _ => None,
        }
    }
    pub fn as_table(&self) -> Option<&Table> {
        match self {
            Value::Table(t) => Some(t),
            _ => None,
        }
    }
    /// Look up a dotted path, e.g. `get_path("toolchain.commit-hash")`.
    pub fn get_path(&self, path: &str) -> Option<&Value> {
        let mut cur = self;
        for seg in path.split('.') {
            cur = cur.as_table()?.get(seg)?;
        }
        Some(cur)
    }
    /// Every string in an array of strings; empty if absent or wrong type.
    pub fn str_array(&self, path: &str) -> Vec<String> {
        self.get_path(path)
            .and_then(|v| v.as_array())
            .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
            .unwrap_or_default()
    }
}

#[derive(Debug)]
pub struct Error {
    pub line: usize,
    pub msg: String,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "line {}: {}", self.line, self.msg)
    }
}

/// Marker meaning "this value continues on the next line", as opposed to a genuine
/// syntax error. Arrays and inline tables in TOML may span lines.
const INCOMPLETE: &str = "\u{0}incomplete";

pub fn parse(src: &str) -> Result<Value, Error> {
    let mut root = Table::new();
    // Path of the table currently being filled by bare `key = value` lines.
    let mut path: Vec<String> = Vec::new();

    let lines: Vec<&str> = src.lines().collect();
    let mut idx = 0;
    while idx < lines.len() {
        let raw = lines[idx];
        let line = idx + 1;
        idx += 1;
        let s = strip_comment(raw).trim();
        if s.is_empty() {
            continue;
        }

        if let Some(header) = s.strip_prefix('[') {
            let header = header.strip_suffix(']').ok_or_else(|| Error {
                line,
                msg: "unterminated table header".into(),
            })?;
            if header.starts_with('[') {
                return Err(Error {
                    line,
                    msg: "arrays of tables are not supported".into(),
                });
            }
            path = header
                .split('.')
                .map(|p| unquote(p.trim()).to_string())
                .collect();
            if path.iter().any(|p| p.is_empty()) {
                return Err(Error {
                    line,
                    msg: "empty segment in table header".into(),
                });
            }
            // Creating the table makes empty sections visible to the caller.
            ensure_table(&mut root, &path).map_err(|m| Error { line, msg: m })?;
            continue;
        }

        let (key, rest) = s.split_once('=').ok_or_else(|| Error {
            line,
            msg: format!("expected `key = value`, found `{s}`"),
        })?;
        let key = unquote(key.trim()).to_string();
        if key.is_empty() {
            return Err(Error {
                line,
                msg: "empty key".into(),
            });
        }
        // Keep appending lines while the value is still open.
        let mut buf = rest.trim().to_string();
        let value = loop {
            match parse_value(&buf) {
                Ok((v, tail)) => {
                    if !tail.trim().is_empty() {
                        return Err(Error {
                            line,
                            msg: format!("trailing text after value: `{}`", tail.trim()),
                        });
                    }
                    break v;
                }
                Err(m) if m == INCOMPLETE => {
                    if idx >= lines.len() {
                        return Err(Error {
                            line,
                            msg: "value is never terminated before end of file".into(),
                        });
                    }
                    buf.push(' ');
                    buf.push_str(strip_comment(lines[idx]).trim());
                    idx += 1;
                }
                Err(m) => return Err(Error { line, msg: m }),
            }
        };
        let table = ensure_table(&mut root, &path).map_err(|m| Error { line, msg: m })?;
        table.insert(key, value);
    }

    Ok(Value::Table(root))
}

fn ensure_table<'a>(root: &'a mut Table, path: &[String]) -> Result<&'a mut Table, String> {
    let mut cur = root;
    for seg in path {
        let entry = cur
            .entry(seg.clone())
            .or_insert_with(|| Value::Table(Table::new()));
        match entry {
            Value::Table(t) => cur = t,
            _ => return Err(format!("`{seg}` is already a value, not a table")),
        }
    }
    Ok(cur)
}

fn strip_comment(s: &str) -> &str {
    let bytes = s.as_bytes();
    let mut in_str = false;
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'"' => in_str = !in_str,
            b'\\' if in_str => i += 1,
            b'#' if !in_str => return &s[..i],
            _ => {}
        }
        i += 1;
    }
    s
}

fn unquote(s: &str) -> &str {
    s.strip_prefix('"')
        .and_then(|r| r.strip_suffix('"'))
        .unwrap_or(s)
}

/// Parse one value, returning it and whatever follows.
fn parse_value(s: &str) -> Result<(Value, &str), String> {
    let s = s.trim_start();
    let first = s.chars().next().ok_or(INCOMPLETE)?;
    match first {
        '"' => {
            let rest = &s[1..];
            let mut out = String::new();
            let mut it = rest.char_indices();
            while let Some((i, c)) = it.next() {
                match c {
                    '"' => return Ok((Value::Str(out), &rest[i + 1..])),
                    '\\' => {
                        let (_, e) = it.next().ok_or("unterminated escape")?;
                        out.push(match e {
                            'n' => '\n',
                            't' => '\t',
                            'r' => '\r',
                            '\\' => '\\',
                            '"' => '"',
                            other => return Err(format!("unknown escape `\\{other}`")),
                        });
                    }
                    c => out.push(c),
                }
            }
            Err(INCOMPLETE.into())
        }
        '[' => {
            let mut rest = &s[1..];
            let mut items = Vec::new();
            loop {
                rest = rest.trim_start();
                if let Some(r) = rest.strip_prefix(']') {
                    return Ok((Value::Array(items), r));
                }
                let (v, r) = parse_value(rest)?;
                items.push(v);
                rest = r.trim_start();
                if let Some(r) = rest.strip_prefix(',') {
                    rest = r;
                } else if rest.is_empty() {
                    return Err(INCOMPLETE.into());
                } else if !rest.starts_with(']') {
                    return Err("expected `,` or `]` in array".into());
                }
            }
        }
        '{' => {
            let mut rest = &s[1..];
            let mut t = Table::new();
            loop {
                rest = rest.trim_start();
                if let Some(r) = rest.strip_prefix('}') {
                    return Ok((Value::Table(t), r));
                }
                let (k, r) = rest
                    .split_once('=')
                    .ok_or_else(|| if rest.is_empty() { INCOMPLETE.into() } else { String::from("expected `key = value` in inline table") })?;
                let (v, r) = parse_value(r)?;
                t.insert(unquote(k.trim()).to_string(), v);
                rest = r.trim_start();
                if let Some(r) = rest.strip_prefix(',') {
                    rest = r;
                } else if rest.is_empty() {
                    return Err(INCOMPLETE.into());
                } else if !rest.starts_with('}') {
                    return Err("expected `,` or `}` in inline table".into());
                }
            }
        }
        _ => {
            let end = s
                .find([',', ']', '}'])
                .unwrap_or(s.len());
            let (tok, rest) = s.split_at(end);
            let tok = tok.trim();
            let v = match tok {
                "true" => Value::Bool(true),
                "false" => Value::Bool(false),
                _ => {
                    let cleaned = tok.replace('_', "");
                    let parsed = if let Some(h) = cleaned.strip_prefix("0x") {
                        i64::from_str_radix(h, 16)
                    } else {
                        cleaned.parse::<i64>()
                    };
                    Value::Int(parsed.map_err(|_| format!("not a value: `{tok}`"))?)
                }
            };
            Ok((v, rest))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_shapes_we_use() {
        let src = r#"
# a comment
[unit]
name = "mm"
level = 3
enabled = true

[deps]
list = ["hal", "kalloc"]

[sources]
paged = { cfg = "MM_PAGED", files = ["src/paged/a.rs", "src/paged/b.rs"] }
"#;
        let v = parse(src).expect("parse");
        assert_eq!(v.get_path("unit.name").unwrap().as_str(), Some("mm"));
        assert_eq!(v.get_path("unit.level").unwrap().as_int(), Some(3));
        assert_eq!(v.get_path("unit.enabled").unwrap().as_bool(), Some(true));
        assert_eq!(v.str_array("deps.list"), vec!["hal", "kalloc"]);
        assert_eq!(
            v.get_path("sources.paged.cfg").unwrap().as_str(),
            Some("MM_PAGED")
        );
        assert_eq!(v.str_array("sources.paged.files").len(), 2);
    }

    #[test]
    fn hash_inside_a_string_is_not_a_comment() {
        let v = parse(r#"a = "x # y""#).unwrap();
        assert_eq!(v.get_path("a").unwrap().as_str(), Some("x # y"));
    }

    #[test]
    fn dotted_headers_nest() {
        let v = parse("[a.b.c]\nd = 1\n").unwrap();
        assert_eq!(v.get_path("a.b.c.d").unwrap().as_int(), Some(1));
    }

    #[test]
    fn empty_table_is_still_present() {
        let v = parse("[dependencies]\n").unwrap();
        assert!(v.get_path("dependencies").unwrap().as_table().is_some());
    }

    #[test]
    fn reports_the_line_of_the_error() {
        let e = parse("a = 1\nb = \n").unwrap_err();
        assert_eq!(e.line, 2);
    }

    #[test]
    fn arrays_may_span_lines_with_comments() {
        let v = parse(
            "[components]\nrequired = [\n    \"rustc\",   # the compiler\n    \"rust-src\",\n]\n",
        )
        .unwrap();
        assert_eq!(v.str_array("components.required"), vec!["rustc", "rust-src"]);
    }

    #[test]
    fn multiline_inline_table() {
        let v = parse("a = {\n  b = 1,\n  c = 2,\n}\n").unwrap();
        assert_eq!(v.get_path("a.c").unwrap().as_int(), Some(2));
    }

    #[test]
    fn genuinely_unterminated_is_an_error_not_a_hang() {
        assert!(parse("a = [1, 2\n").is_err());
    }

    #[test]
    fn hex_and_underscores() {
        let v = parse("a = 0xf4\nb = 1_000\n").unwrap();
        assert_eq!(v.get_path("a").unwrap().as_int(), Some(0xf4));
        assert_eq!(v.get_path("b").unwrap().as_int(), Some(1000));
    }
}

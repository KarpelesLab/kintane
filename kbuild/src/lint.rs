//! In-tree lints that rustc cannot express.
//!
//! Currently one: **`cfg` may not appear inside a function body or a type's fields.**
//!
//! This is the rule that makes the portability claim checkable rather than
//! aspirational (`docs/portability.md`). `cfg` selects which modules and crates enter
//! the build; the moment it appears *inside* a function, the logic of that function
//! becomes interleaved with the question of which machine it is running on, and the
//! set of configurations anyone actually compiles starts shrinking toward one.
//!
//! The check is deliberately textual. A full parse would be more precise, but the
//! rule is about discipline rather than about catching a determined author, and a
//! lint nobody can run is worth nothing. It errs toward reporting: a false positive
//! is a comment away from silence, while a false negative is the bug class this
//! exists to prevent.

use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Block {
    /// A function body — cfg here is the thing we are forbidding.
    Fn,
    /// A struct or enum body: cfg on a field changes a type's layout per config.
    Fields,
    /// `match` arms.
    Match,
    /// `impl`, `mod`, `trait` — item positions, where cfg is fine.
    Items,
    Other,
}

#[derive(Debug)]
pub struct Violation {
    pub file: PathBuf,
    pub line: usize,
    pub context: &'static str,
    pub text: String,
}

impl std::fmt::Display for Violation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}:{}: `cfg` inside {}\n    {}\n    \
             cfg selects modules and crates, never lines inside one \
             (docs/portability.md)",
            self.file.display(),
            self.line,
            self.context,
            self.text.trim()
        )
    }
}

/// Check every `.rs` file under `root`, skipping directories that are not ours.
pub fn check_tree(root: &Path) -> Result<Vec<Violation>, String> {
    let mut files = Vec::new();
    collect(root, &mut files)?;
    files.sort();

    let mut out = Vec::new();
    for f in files {
        let src = std::fs::read_to_string(&f).map_err(|e| format!("{}: {e}", f.display()))?;
        out.extend(check_source(&f, &src));
    }
    Ok(out)
}

fn collect(dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), String> {
    // kbuild is a host tool, not kernel code, and build/ is generated.
    const SKIP: &[&str] = &["build", "target", ".git", "docs", "kbuild", ".github"];
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return Ok(()),
    };
    for e in entries.flatten() {
        let p = e.path();
        let name = p.file_name().and_then(|s| s.to_str()).unwrap_or("");
        if p.is_dir() {
            if !SKIP.contains(&name) && !name.starts_with('.') {
                collect(&p, out)?;
            }
        } else if name.ends_with(".rs") {
            out.push(p);
        }
    }
    Ok(())
}

pub fn check_source(file: &Path, src: &str) -> Vec<Violation> {
    let mut violations = Vec::new();
    let mut stack: Vec<Block> = Vec::new();
    // Text seen since the last brace or semicolon, which is what tells us what kind
    // of block an opening brace is starting.
    let mut pending = String::new();
    // Tests describe the configurations they exercise; cfg there is not the bug.
    let mut in_test_module = None::<usize>;

    for (idx, raw) in src.lines().enumerate() {
        let line = strip_noise(raw);
        let trimmed = line.trim();

        if trimmed.starts_with("#[cfg(test)]") || trimmed.starts_with("#![cfg(test)]") {
            in_test_module = Some(stack.len());
        }

        let is_cfg = trimmed.contains("#[cfg(") || trimmed.contains("#![cfg(");
        if is_cfg && in_test_module.is_none() {
            if let Some(ctx) = offending(&stack) {
                violations.push(Violation {
                    file: file.to_path_buf(),
                    line: idx + 1,
                    context: ctx,
                    text: raw.to_string(),
                });
            }
        }

        for ch in line.chars() {
            match ch {
                '{' => {
                    stack.push(classify(&pending, &stack));
                    pending.clear();
                }
                '}' => {
                    stack.pop();
                    if let Some(depth) = in_test_module {
                        if stack.len() <= depth {
                            in_test_module = None;
                        }
                    }
                    pending.clear();
                }
                ';' => pending.clear(),
                c => pending.push(c),
            }
        }
        pending.push(' ');
    }

    violations
}

/// The innermost enclosing block that forbids `cfg`, if any.
fn offending(stack: &[Block]) -> Option<&'static str> {
    for b in stack.iter().rev() {
        match b {
            Block::Fn => return Some("a function body"),
            Block::Fields => return Some("a type's fields"),
            Block::Match => return Some("a match expression"),
            // An item position: cfg is allowed, and anything further out cannot
            // make it disallowed again.
            Block::Items => return None,
            Block::Other => continue,
        }
    }
    None
}

fn classify(pending: &str, stack: &[Block]) -> Block {
    let p = pending.trim();
    // Inside a function, every nested block is still function body.
    if matches!(stack.last(), Some(Block::Fn)) {
        return if word_before_brace(p, "match") {
            Block::Match
        } else {
            Block::Fn
        };
    }
    if word_before_brace(p, "fn") {
        Block::Fn
    } else if word_before_brace(p, "struct") || word_before_brace(p, "union") {
        Block::Fields
    } else if word_before_brace(p, "enum") {
        Block::Fields
    } else if word_before_brace(p, "match") {
        Block::Match
    } else if word_before_brace(p, "impl")
        || word_before_brace(p, "mod")
        || word_before_brace(p, "trait")
    {
        Block::Items
    } else {
        Block::Other
    }
}

fn word_before_brace(s: &str, kw: &str) -> bool {
    s.split(|c: char| !c.is_alphanumeric() && c != '_')
        .any(|w| w == kw)
}

/// Remove line comments and string literals so their contents cannot be mistaken for
/// code. Crude but adequate: we only need braces and `#[cfg(` to survive intact.
fn strip_noise(s: &str) -> String {
    let b: Vec<char> = s.chars().collect();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    let mut in_str = false;
    let mut in_char = false;
    while i < b.len() {
        let c = b[i];
        if !in_str && !in_char && c == '/' && i + 1 < b.len() && b[i + 1] == '/' {
            break;
        }
        match c {
            '"' if !in_char => in_str = !in_str,
            '\'' if !in_str => {
                // A lifetime is not a character literal.
                let is_lifetime = i + 1 < b.len()
                    && (b[i + 1].is_alphabetic() || b[i + 1] == '_')
                    && !(i + 2 < b.len() && b[i + 2] == '\'');
                if !is_lifetime {
                    in_char = !in_char;
                }
            }
            '\\' if in_str || in_char => i += 1,
            _ => {}
        }
        out.push(if in_str || in_char { ' ' } else { c });
        i += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(src: &str) -> Vec<Violation> {
        check_source(Path::new("t.rs"), src)
    }

    #[test]
    fn cfg_on_a_module_is_allowed() {
        assert!(check("#[cfg(CONFIG_MM_PAGED)]\nmod paged;\n").is_empty());
        assert!(check("#[cfg(CONFIG_SMP)]\npub use smp::*;\n").is_empty());
    }

    #[test]
    fn cfg_inside_a_function_is_rejected() {
        let v = check("fn schedule(&mut self) {\n    #[cfg(CONFIG_SMP)]\n    self.steal();\n}\n");
        assert_eq!(v.len(), 1, "{v:?}");
        assert_eq!(v[0].line, 2);
        assert_eq!(v[0].context, "a function body");
    }

    #[test]
    fn cfg_on_a_struct_field_is_rejected() {
        let v = check("struct Task {\n    #[cfg(CONFIG_SMP)]\n    cpu: u32,\n}\n");
        assert_eq!(v.len(), 1, "{v:?}");
        assert_eq!(v[0].context, "a type's fields");
    }

    #[test]
    fn cfg_on_a_method_in_an_impl_is_allowed() {
        // An impl block is an item position; a whole method may be configured out.
        assert!(check("impl Foo {\n    #[cfg(CONFIG_SMP)]\n    fn bar(&self) {}\n}\n").is_empty());
    }

    #[test]
    fn nested_blocks_inside_a_function_still_count() {
        let v = check("fn f() {\n    if x {\n        #[cfg(CONFIG_SMP)]\n        g();\n    }\n}\n");
        assert_eq!(v.len(), 1, "{v:?}");
        assert_eq!(v[0].context, "a function body");
    }

    #[test]
    fn cfg_in_a_match_arm_is_rejected() {
        let v = check(
            "fn f() {\n    match x {\n        #[cfg(CONFIG_SMP)]\n        A => 1,\n    }\n}\n",
        );
        assert_eq!(v.len(), 1, "{v:?}");
    }

    #[test]
    fn test_modules_are_exempt() {
        // Tests describe which configurations they exercise; that is not the bug.
        assert!(check(
            "#[cfg(test)]\nmod tests {\n    fn t() {\n        #[cfg(CONFIG_SMP)]\n        let x = 1;\n    }\n}\n"
        )
        .is_empty());
    }

    #[test]
    fn exemption_ends_with_the_test_module() {
        let v = check(
            "#[cfg(test)]\nmod tests {\n    fn t() {}\n}\n\nfn real() {\n    #[cfg(CONFIG_SMP)]\n    go();\n}\n",
        );
        assert_eq!(v.len(), 1, "{v:?}");
        assert_eq!(v[0].line, 7);
    }

    #[test]
    fn braces_in_strings_do_not_confuse_the_scanner() {
        // If the scanner counted this brace, the following cfg would look nested.
        assert!(check("const S: &str = \"{\";\n#[cfg(CONFIG_SMP)]\nmod x;\n").is_empty());
    }

    #[test]
    fn braces_in_comments_do_not_confuse_the_scanner() {
        assert!(check("// a stray { here\n#[cfg(CONFIG_SMP)]\nmod x;\n").is_empty());
    }

    #[test]
    fn lifetimes_are_not_character_literals() {
        // A naive quote counter treats 'store as an unterminated char literal and
        // blanks the rest of the file, hiding every later violation.
        let v = check(
            "struct A<'store> { x: &'store u8 }\nfn f() {\n    #[cfg(CONFIG_SMP)]\n    g();\n}\n",
        );
        assert_eq!(v.len(), 1, "{v:?}");
    }

    #[test]
    fn the_real_tree_is_clean() {
        // The rule is only meaningful if the code actually obeys it.
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        let v = check_tree(root).expect("scan the tree");
        assert!(
            v.is_empty(),
            "cfg-in-body violations:\n{}",
            v.iter()
                .map(|x| x.to_string())
                .collect::<Vec<_>>()
                .join("\n")
        );
    }
}

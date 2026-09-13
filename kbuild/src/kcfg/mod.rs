//! The configuration language: parsing `.kcfg` files into a symbol table, and
//! resolving a complete configuration from it.
//!
//! Shaped like Kconfig because that shape is proven and familiar, with stricter typing
//! and better error reporting. See `docs/build-system.md`.

pub mod expr;
pub mod parse;
pub mod resolve;

use std::collections::BTreeMap;

pub use expr::{Expr, Tri};
pub use resolve::Resolution;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Bool,
    Tristate,
    Int,
    Str,
}

impl Kind {
    pub fn name(self) -> &'static str {
        match self {
            Kind::Bool => "bool",
            Kind::Tristate => "tristate",
            Kind::Int => "int",
            Kind::Str => "string",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Val {
    /// Covers both `bool` (N or Y only) and `tristate`.
    Tri(Tri),
    Int(i64),
    Str(String),
}

impl Val {
    pub fn zero(kind: Kind) -> Val {
        match kind {
            Kind::Bool | Kind::Tristate => Val::Tri(Tri::N),
            Kind::Int => Val::Int(0),
            Kind::Str => Val::Str(String::new()),
        }
    }

    pub fn as_tri(&self) -> Tri {
        match self {
            Val::Tri(t) => *t,
            // A non-empty int or string is truthy when named in an expression.
            Val::Int(i) => {
                if *i != 0 {
                    Tri::Y
                } else {
                    Tri::N
                }
            }
            Val::Str(s) => {
                if !s.is_empty() {
                    Tri::Y
                } else {
                    Tri::N
                }
            }
        }
    }

    pub fn is_on(&self) -> bool {
        self.as_tri() != Tri::N
    }

    /// How the value is written in `.config` and in generated Rust.
    pub fn display(&self) -> String {
        match self {
            Val::Tri(t) => t.as_str().to_string(),
            Val::Int(i) => i.to_string(),
            Val::Str(s) => format!("{s:?}"),
        }
    }
}

/// One `default <value> [if <condition>]` clause.
#[derive(Debug, Clone)]
pub struct Default {
    pub value: Val,
    pub cond: Option<Expr>,
}

/// One `select <SYMBOL> [if <condition>]` clause.
#[derive(Debug, Clone)]
pub struct Select {
    pub target: String,
    pub cond: Option<Expr>,
}

#[derive(Debug, Clone)]
#[allow(dead_code)] // name/origin are carried for diagnostics
pub struct Symbol {
    pub name: String,
    pub kind: Kind,
    pub prompt: Option<String>,
    pub depends: Option<Expr>,
    pub defaults: Vec<Default>,
    pub selects: Vec<Select>,
    pub range: Option<(i64, i64)>,
    pub help: Option<String>,
    /// Set for `ARCH_HAS_*` and other symbols the architecture asserts; these
    /// describe hardware and are not user-settable.
    pub readonly: bool,
    /// Name of the enclosing `choice`, if any.
    pub choice: Option<String>,
    pub origin: Origin,
}

#[derive(Debug, Clone)]
pub struct Origin {
    pub file: String,
    pub line: usize,
}

impl std::fmt::Display for Origin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.file, self.line)
    }
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct Choice {
    pub name: String,
    pub prompt: Option<String>,
    pub members: Vec<String>,
    pub defaults: Vec<Default>,
    pub depends: Option<Expr>,
    pub origin: Origin,
}

#[derive(Debug, Default)]
pub struct SymbolTable {
    pub symbols: BTreeMap<String, Symbol>,
    pub choices: BTreeMap<String, Choice>,
    /// Declaration order, which resolution follows so that behaviour is stable.
    pub order: Vec<String>,
}

impl SymbolTable {
    pub fn get(&self, name: &str) -> Option<&Symbol> {
        self.symbols.get(name)
    }
}

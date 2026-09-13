//! The configuration language: parsing `.kcfg` files into a symbol table, and
//! resolving a complete configuration from it.
//!
//! Shaped like Kconfig because that shape is proven and familiar, with stricter typing
//! and better error reporting. See `docs/build-system.md`.

pub mod expr;
pub mod parse;
pub mod random;
pub mod resolve;

use std::collections::BTreeMap;

pub use expr::{Expr, Tri};
pub use resolve::Resolution;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Bool,
    Tristate,
    Int,
    Hex,
    Str,
}

impl Kind {
    pub fn name(self) -> &'static str {
        match self {
            Kind::Bool => "bool",
            Kind::Tristate => "tristate",
            Kind::Int => "int",
            Kind::Hex => "hex",
            Kind::Str => "string",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Val {
    /// Covers both `bool` (N or Y only) and `tristate`.
    Tri(Tri),
    Int(i64),
    /// An integer written and displayed in hexadecimal: addresses and masks. Unsigned,
    /// so an address in the upper half of a 64-bit space is not a negative number.
    Hex(u64),
    Str(String),
}

impl Val {
    pub fn zero(kind: Kind) -> Val {
        match kind {
            Kind::Bool | Kind::Tristate => Val::Tri(Tri::N),
            Kind::Int => Val::Int(0),
            Kind::Hex => Val::Hex(0),
            Kind::Str => Val::Str(String::new()),
        }
    }

    pub fn as_tri(&self) -> Tri {
        match self {
            Val::Tri(t) => *t,
            // A non-empty int or string is truthy when named in an expression.
            Val::Int(_) | Val::Hex(_) => {
                if self.as_int() != Some(0) {
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

    /// The numeric value of an `int` or `hex`.
    pub fn as_int(&self) -> Option<i128> {
        match self {
            Val::Int(i) => Some(i128::from(*i)),
            Val::Hex(h) => Some(i128::from(*h)),
            _ => None,
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
            Val::Hex(i) => format!("{i:#x}"),
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

/// One `range <low> <high> [if <condition>]` clause. The first whose condition holds
/// bounds the value; both bounds are inclusive.
#[derive(Debug, Clone)]
pub struct Range {
    /// Wide enough for every `int` (signed) and every `hex` (unsigned 64-bit).
    pub lo: i128,
    pub hi: i128,
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
    pub ranges: Vec<Range>,
    pub help: Option<String>,
    /// Set for `ARCH_HAS_*` and other symbols the architecture asserts; these
    /// describe hardware and are not user-settable.
    pub readonly: bool,
    /// Name of the enclosing `choice`, if any.
    pub choice: Option<String>,
    /// Index into [`SymbolTable::menus`] of the innermost enclosing `menu`, if any.
    pub menu: Option<usize>,
    pub origin: Origin,
}

impl Symbol {
    /// Whether a person configuring the kernel can set this symbol: not readonly, and
    /// given a prompt. A symbol with no prompt is derived from others and exists to be
    /// read, as in Kconfig.
    pub fn settable(&self) -> bool {
        !self.readonly && self.prompt.is_some()
    }
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
    /// Index into [`SymbolTable::menus`] of the innermost enclosing `menu`, if any.
    pub menu: Option<usize>,
    pub origin: Origin,
}

/// A `menu "title"` ... `endmenu` block. It groups entries for `menuconfig`, and its
/// `depends on` applies to everything inside it. The parser folds that condition into
/// each enclosed entry's own `depends`, so resolution never needs to know menus exist.
#[derive(Debug, Clone)]
#[allow(dead_code)] // origin is carried for diagnostics
pub struct Menu {
    pub title: String,
    pub depends: Option<Expr>,
    pub parent: Option<usize>,
    pub origin: Origin,
}

/// The symbol that switches loadable modules on. A `tristate` may resolve to `m` only
/// while this is `y`; otherwise every `m` is either refused or built in, see `resolve`.
pub const MODULES: &str = "MODULES";

#[derive(Debug, Default)]
pub struct SymbolTable {
    pub symbols: BTreeMap<String, Symbol>,
    pub choices: BTreeMap<String, Choice>,
    pub menus: Vec<Menu>,
    /// Declaration order, which resolution follows so that behaviour is stable.
    pub order: Vec<String>,
}

impl SymbolTable {
    pub fn get(&self, name: &str) -> Option<&Symbol> {
        self.symbols.get(name)
    }
}

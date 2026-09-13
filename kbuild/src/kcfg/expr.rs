//! Condition expressions: `depends on`, `default ... if ...`, `select ... if ...`.
//!
//! Grammar:
//!   or      := and ('||' and)*
//!   and     := unary ('&&' unary)*
//!   unary   := '!' unary | primary
//!   primary := '(' or ')' | literal | IDENT [('='|'!=') (IDENT|literal|string)]

use std::fmt;

/// Three-valued logic, so `tristate` (built in / module / absent) needs no special case.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Tri {
    N,
    M,
    Y,
}

impl Tri {
    pub fn as_str(self) -> &'static str {
        match self {
            Tri::N => "n",
            Tri::M => "m",
            Tri::Y => "y",
        }
    }
    pub fn from_str(s: &str) -> Option<Tri> {
        match s {
            "n" | "N" => Some(Tri::N),
            "m" | "M" => Some(Tri::M),
            "y" | "Y" => Some(Tri::Y),
            _ => None,
        }
    }
    pub fn and(self, other: Tri) -> Tri {
        self.min(other)
    }
    pub fn or(self, other: Tri) -> Tri {
        self.max(other)
    }
    pub fn not(self) -> Tri {
        match self {
            Tri::N => Tri::Y,
            Tri::M => Tri::M,
            Tri::Y => Tri::N,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Expr {
    Const(Tri),
    Sym(String),
    Not(Box<Expr>),
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
    Eq(String, String),
    Ne(String, String),
}

impl Expr {
    /// Evaluate against a lookup that returns a symbol's current tri-value, and a
    /// second that returns its literal form for `=` comparisons.
    pub fn eval(&self, tri: &dyn Fn(&str) -> Tri, lit: &dyn Fn(&str) -> String) -> Tri {
        match self {
            Expr::Const(t) => *t,
            Expr::Sym(s) => tri(s),
            Expr::Not(e) => e.eval(tri, lit).not(),
            Expr::And(a, b) => a.eval(tri, lit).and(b.eval(tri, lit)),
            Expr::Or(a, b) => a.eval(tri, lit).or(b.eval(tri, lit)),
            Expr::Eq(s, v) => {
                if lit(s) == *v {
                    Tri::Y
                } else {
                    Tri::N
                }
            }
            Expr::Ne(s, v) => {
                if lit(s) != *v {
                    Tri::Y
                } else {
                    Tri::N
                }
            }
        }
    }

    /// Every symbol named anywhere in the expression, for dependency ordering and
    /// for explaining why a constraint failed.
    pub fn symbols(&self, out: &mut Vec<String>) {
        match self {
            Expr::Const(_) => {}
            Expr::Sym(s) | Expr::Eq(s, _) | Expr::Ne(s, _) => out.push(s.clone()),
            Expr::Not(e) => e.symbols(out),
            Expr::And(a, b) | Expr::Or(a, b) => {
                a.symbols(out);
                b.symbols(out);
            }
        }
    }
}

impl fmt::Display for Expr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Expr::Const(t) => write!(f, "{}", t.as_str()),
            Expr::Sym(s) => write!(f, "{s}"),
            Expr::Not(e) => write!(f, "!{e}"),
            Expr::And(a, b) => write!(f, "({a} && {b})"),
            Expr::Or(a, b) => write!(f, "({a} || {b})"),
            Expr::Eq(s, v) => write!(f, "{s} = {v}"),
            Expr::Ne(s, v) => write!(f, "{s} != {v}"),
        }
    }
}

// ---- parsing ----

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Ident(String),
    Str(String),
    Not,
    And,
    Or,
    LParen,
    RParen,
    Eq,
    Ne,
}

fn lex(s: &str) -> Result<Vec<Tok>, String> {
    let b: Vec<char> = s.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        match c {
            c if c.is_whitespace() => i += 1,
            '(' => {
                out.push(Tok::LParen);
                i += 1;
            }
            ')' => {
                out.push(Tok::RParen);
                i += 1;
            }
            '!' => {
                if i + 1 < b.len() && b[i + 1] == '=' {
                    out.push(Tok::Ne);
                    i += 2;
                } else {
                    out.push(Tok::Not);
                    i += 1;
                }
            }
            '=' => {
                out.push(Tok::Eq);
                i += 1;
            }
            '&' => {
                if i + 1 < b.len() && b[i + 1] == '&' {
                    out.push(Tok::And);
                    i += 2;
                } else {
                    return Err("expected `&&`".into());
                }
            }
            '|' => {
                if i + 1 < b.len() && b[i + 1] == '|' {
                    out.push(Tok::Or);
                    i += 2;
                } else {
                    return Err("expected `||`".into());
                }
            }
            '"' => {
                let mut v = String::new();
                i += 1;
                while i < b.len() && b[i] != '"' {
                    v.push(b[i]);
                    i += 1;
                }
                if i >= b.len() {
                    return Err("unterminated string".into());
                }
                i += 1;
                out.push(Tok::Str(v));
            }
            c if c.is_alphanumeric() || c == '_' || c == '-' => {
                let mut v = String::new();
                while i < b.len() && (b[i].is_alphanumeric() || b[i] == '_' || b[i] == '-') {
                    v.push(b[i]);
                    i += 1;
                }
                out.push(Tok::Ident(v));
            }
            other => return Err(format!("unexpected character `{other}`")),
        }
    }
    Ok(out)
}

pub fn parse(s: &str) -> Result<Expr, String> {
    let toks = lex(s)?;
    let mut p = Parser { toks, pos: 0 };
    let e = p.or()?;
    if p.pos != p.toks.len() {
        return Err(format!("trailing tokens in expression `{s}`"));
    }
    Ok(e)
}

struct Parser {
    toks: Vec<Tok>,
    pos: usize,
}

impl Parser {
    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.pos)
    }
    fn eat(&mut self, t: &Tok) -> bool {
        if self.peek() == Some(t) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn or(&mut self) -> Result<Expr, String> {
        let mut lhs = self.and()?;
        while self.eat(&Tok::Or) {
            lhs = Expr::Or(Box::new(lhs), Box::new(self.and()?));
        }
        Ok(lhs)
    }

    fn and(&mut self) -> Result<Expr, String> {
        let mut lhs = self.unary()?;
        while self.eat(&Tok::And) {
            lhs = Expr::And(Box::new(lhs), Box::new(self.unary()?));
        }
        Ok(lhs)
    }

    fn unary(&mut self) -> Result<Expr, String> {
        if self.eat(&Tok::Not) {
            return Ok(Expr::Not(Box::new(self.unary()?)));
        }
        self.primary()
    }

    fn primary(&mut self) -> Result<Expr, String> {
        if self.eat(&Tok::LParen) {
            let e = self.or()?;
            if !self.eat(&Tok::RParen) {
                return Err("expected `)`".into());
            }
            return Ok(e);
        }
        match self.peek().cloned() {
            Some(Tok::Ident(name)) => {
                self.pos += 1;
                let cmp = if self.eat(&Tok::Eq) {
                    Some(false)
                } else if self.eat(&Tok::Ne) {
                    Some(true)
                } else {
                    None
                };
                if let Some(negated) = cmp {
                    let rhs = match self.peek().cloned() {
                        Some(Tok::Ident(v)) => v,
                        Some(Tok::Str(v)) => v,
                        _ => return Err("expected a value after comparison".into()),
                    };
                    self.pos += 1;
                    return Ok(if negated {
                        Expr::Ne(name, rhs)
                    } else {
                        Expr::Eq(name, rhs)
                    });
                }
                // A bare y/n/m is a literal, not a symbol reference.
                Ok(match Tri::from_str(&name) {
                    Some(t) if name.len() == 1 => Expr::Const(t),
                    _ => Expr::Sym(name),
                })
            }
            Some(Tok::Str(v)) => {
                self.pos += 1;
                Ok(Expr::Sym(v))
            }
            other => Err(format!("unexpected token in expression: {other:?}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(name: &str) -> Tri {
        match name {
            "A" | "ON" => Tri::Y,
            "M" => Tri::M,
            _ => Tri::N,
        }
    }
    fn l(name: &str) -> String {
        match name {
            "ARCH" => "x86_64".into(),
            _ => String::new(),
        }
    }
    fn ev(s: &str) -> Tri {
        parse(s).unwrap().eval(&t, &l)
    }

    #[test]
    fn basic_logic() {
        assert_eq!(ev("A"), Tri::Y);
        assert_eq!(ev("B"), Tri::N);
        assert_eq!(ev("!B"), Tri::Y);
        assert_eq!(ev("A && B"), Tri::N);
        assert_eq!(ev("A || B"), Tri::Y);
        assert_eq!(ev("!(A && B)"), Tri::Y);
    }

    #[test]
    fn precedence_and_grouping() {
        // && binds tighter than ||
        assert_eq!(ev("B && B || A"), Tri::Y);
        assert_eq!(ev("A || B && B"), Tri::Y);
        assert_eq!(ev("(A || B) && B"), Tri::N);
    }

    #[test]
    fn tristate_is_ordered() {
        assert_eq!(ev("M && A"), Tri::M);
        assert_eq!(ev("M || A"), Tri::Y);
        assert_eq!(ev("!M"), Tri::M);
    }

    #[test]
    fn comparisons() {
        assert_eq!(ev("ARCH = x86_64"), Tri::Y);
        assert_eq!(ev("ARCH = aarch64"), Tri::N);
        assert_eq!(ev("ARCH != aarch64"), Tri::Y);
        assert_eq!(ev(r#"ARCH = "x86_64""#), Tri::Y);
    }

    #[test]
    fn literals_are_not_symbols() {
        assert_eq!(ev("y"), Tri::Y);
        assert_eq!(ev("n"), Tri::N);
        // but a longer identifier starting with y is a symbol
        assert_eq!(parse("yes").unwrap(), Expr::Sym("yes".into()));
    }

    #[test]
    fn collects_symbols() {
        let mut v = Vec::new();
        parse("A && (B || ARCH = x86_64)").unwrap().symbols(&mut v);
        assert_eq!(v, vec!["A", "B", "ARCH"]);
    }
}

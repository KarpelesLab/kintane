//! `kbuild menuconfig`: edit a configuration in the terminal.
//!
//! Two layers, split so the one that matters can be tested without a terminal:
//!
//! - [`Session`] is the editor. It holds the requests (the starting preset, then every change),
//!   navigates menus and choices, and turns a key into a new request. Every change is re-resolved
//!   before it is accepted, so the session can never hold a configuration the resolver would
//!   refuse. A refused change leaves the configuration as it was and shows the resolver's own
//!   explanation. [`Session::render`] draws a screen as a string. Host tests drive both with key
//!   sequences.
//! - [`Terminal`] is the rest: raw mode, the alternate screen, reading keys.
//!
//! Raw mode is set with `stty`, not termios through hand-declared FFI. The `termios`
//! struct's layout differs between macOS and Linux (field widths, `NCCS`, where the
//! speeds live), so declaring it by hand means per-OS struct definitions that nothing
//! checks. A wrong one corrupts the stack of a tool whose job is reproducible builds.
//! `stty` is POSIX, present wherever a terminal is, and `stty -g` saves the exact state
//! to restore. What is given up is a process spawn at start and exit.
//!
//! Saving writes `.config` and `menuconfig.preset`. The preset is what a build uses:
//! `kbuild build --preset ./menuconfig.preset`, since builds resolve from presets and
//! `--set`, never from `.config`.

use std::io::{Read, Write};
use std::path::Path;
use std::process::{Command, Stdio};

use crate::Opts;
use crate::kcfg::resolve::{self, Reason, Request};
use crate::kcfg::{Kind, MODULES, Resolution, SymbolTable, Tri, Val};

/// A container in the menu tree.
#[derive(Clone, Debug, PartialEq)]
pub enum Node {
    Root,
    Menu(usize),
    Choice(String),
}

/// One row of a container.
#[derive(Clone, Debug, PartialEq)]
pub enum Item {
    Symbol(String),
    Menu(usize),
    Choice(String),
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Key {
    Up,
    Down,
    Left,
    Right,
    Enter,
    Esc,
    Backspace,
    Char(char),
}

/// What the terminal layer must do after a key.
#[derive(Debug, PartialEq)]
pub enum Action {
    Continue,
    Save,
    SaveAndQuit,
    Quit,
}

#[derive(Debug, PartialEq)]
enum View {
    List,
    Help(String),
    Why(String),
    Edit { symbol: String, buffer: String },
    ConfirmQuit,
}

pub struct Session<'t> {
    table: &'t SymbolTable,
    base: Vec<Request>,
    changes: Vec<Request>,
    res: Resolution,
    /// Open containers, outermost first, each with its cursor.
    stack: Vec<(Node, usize)>,
    view: View,
    status: Vec<String>,
    dirty: bool,
}

const SOURCE: &str = "menuconfig";

impl<'t> Session<'t> {
    /// Start from `base`, which must resolve.
    pub fn new(table: &'t SymbolTable, base: Vec<Request>) -> Result<Session<'t>, String> {
        let res = resolve::resolve(table, &base).map_err(|e| first_error(&e))?;
        Ok(Session {
            table,
            base,
            changes: Vec::new(),
            res,
            stack: vec![(Node::Root, 0)],
            view: View::List,
            status: Vec::new(),
            dirty: false,
        })
    }

    pub fn resolution(&self) -> &Resolution {
        &self.res
    }

    /// Every request, base first; later ones override earlier ones for a symbol.
    pub fn requests(&self) -> Vec<Request> {
        let mut all = self.base.clone();
        all.extend(self.changes.iter().cloned());
        all
    }

    /// The rows of `node`, in declaration order.
    pub fn items(&self, node: &Node) -> Vec<Item> {
        let mut out: Vec<Item> = Vec::new();
        let mut push = |item: Item| {
            if !out.contains(&item) {
                out.push(item);
            }
        };
        for name in &self.table.order {
            let sym = &self.table.symbols[name];
            // The chain of containers this symbol sits in, outermost first.
            let menu = match &sym.choice {
                Some(c) => self.table.choices[c].menu,
                None => sym.menu,
            };
            let mut chain = Vec::new();
            let mut at = menu;
            while let Some(i) = at {
                chain.push(Item::Menu(i));
                at = self.table.menus[i].parent;
            }
            chain.reverse();
            if let Some(c) = &sym.choice {
                chain.push(Item::Choice(c.clone()));
            }
            chain.push(Item::Symbol(name.clone()));

            let position = match node {
                Node::Root => Some(0),
                Node::Menu(m) => chain
                    .iter()
                    .position(|i| *i == Item::Menu(*m))
                    .map(|p| p + 1),
                Node::Choice(c) => chain
                    .iter()
                    .position(|i| *i == Item::Choice(c.clone()))
                    .map(|p| p + 1),
            };
            if let Some(p) = position {
                push(chain[p].clone());
            }
        }
        out
    }

    fn current(&self) -> Option<Item> {
        let (node, cursor) = self.stack.last()?;
        self.items(node).get(*cursor).cloned()
    }

    pub fn handle(&mut self, key: Key) -> Action {
        match std::mem::replace(&mut self.view, View::List) {
            View::Help(_) | View::Why(_) => Action::Continue,
            View::ConfirmQuit => match key {
                Key::Char('s') => Action::SaveAndQuit,
                Key::Char('q') => Action::Quit,
                _ => {
                    self.status = vec!["not quitting".into()];
                    Action::Continue
                }
            },
            View::Edit { symbol, mut buffer } => {
                match key {
                    Key::Enter => {
                        self.apply(&symbol, &[(symbol.clone(), buffer)]);
                    }
                    Key::Esc => self.status = vec![format!("{symbol} unchanged")],
                    Key::Backspace => {
                        buffer.pop();
                        self.view = View::Edit { symbol, buffer };
                    }
                    Key::Char(c) => {
                        buffer.push(c);
                        self.view = View::Edit { symbol, buffer };
                    }
                    _ => self.view = View::Edit { symbol, buffer },
                }
                Action::Continue
            }
            View::List => self.handle_list(key),
        }
    }

    fn handle_list(&mut self, key: Key) -> Action {
        let len = {
            let (node, _) = self.stack.last().expect("root is never popped");
            self.items(node).len()
        };
        let cursor = &mut self.stack.last_mut().expect("root is never popped").1;
        match key {
            Key::Up | Key::Char('k') => *cursor = cursor.saturating_sub(1),
            Key::Down | Key::Char('j') => *cursor = (*cursor + 1).min(len.saturating_sub(1)),
            Key::Left | Key::Esc | Key::Backspace | Key::Char('h') => {
                if self.stack.len() > 1 {
                    self.stack.pop();
                }
            }
            Key::Right | Key::Enter | Key::Char('l') => match self.current() {
                Some(Item::Menu(m)) => self.stack.push((Node::Menu(m), 0)),
                Some(Item::Choice(c)) => self.stack.push((Node::Choice(c), 0)),
                Some(Item::Symbol(s)) => self.activate(&s),
                None => {}
            },
            Key::Char(' ') => {
                if let Some(Item::Symbol(s)) = self.current() {
                    self.activate(&s);
                }
            }
            Key::Char(c @ ('y' | 'n' | 'm')) => {
                if let Some(Item::Symbol(s)) = self.current() {
                    self.set(&s, &c.to_string());
                }
            }
            Key::Char('?') => {
                if let Some(Item::Symbol(s)) = self.current() {
                    self.view = View::Help(s);
                }
            }
            Key::Char('w') => {
                if let Some(Item::Symbol(s)) = self.current() {
                    self.view = View::Why(s);
                }
            }
            Key::Char('s') => return Action::Save,
            Key::Char('q') => {
                if self.dirty {
                    self.view = View::ConfirmQuit;
                } else {
                    return Action::Quit;
                }
            }
            _ => {}
        }
        Action::Continue
    }

    /// Enter or space on a symbol: toggle a bool, step a tristate, pick a choice member,
    /// or start editing a value.
    fn activate(&mut self, name: &str) {
        let sym = &self.table.symbols[name];
        match sym.kind {
            Kind::Bool => {
                let next = if sym.choice.is_some() || !self.res.is_on(name) {
                    "y"
                } else {
                    "n"
                };
                self.set(name, next);
            }
            Kind::Tristate => {
                let modules = self.res.tri(MODULES) == Tri::Y;
                let next = match (self.res.tri(name), modules) {
                    (Tri::N, true) => "m",
                    (Tri::N, false) | (Tri::M, _) => "y",
                    (Tri::Y, _) => "n",
                };
                self.set(name, next);
            }
            Kind::Int | Kind::Hex | Kind::Str => {
                if let Some(why) = self.unsettable(name) {
                    self.status = vec![why];
                    return;
                }
                let buffer = match &self.res.values[name] {
                    Val::Str(s) => s.clone(),
                    v => v.display(),
                };
                self.view = View::Edit {
                    symbol: name.to_string(),
                    buffer,
                };
            }
        }
    }

    fn unsettable(&self, name: &str) -> Option<String> {
        let sym = &self.table.symbols[name];
        if sym.readonly {
            Some(format!("{name} is readonly: it describes the hardware, not what to build"))
        } else if sym.prompt.is_none() {
            Some(format!("{name} has no prompt: it is derived from other symbols"))
        } else {
            None
        }
    }

    /// Request `name=text`. Picking a choice member also sets `n` on the member that
    /// was requested before, so the new pick is not two voices in one choice.
    pub fn set(&mut self, name: &str, text: &str) {
        let mut sets = vec![(name.to_string(), text.to_string())];
        if let (Some(c), "y") = (&self.table.symbols[name].choice, text) {
            for m in &self.table.choices[c].members {
                let asked = self
                    .requests()
                    .iter()
                    .rev()
                    .find(|r| &r.symbol == m)
                    .is_some_and(|r| r.text == "y");
                if m != name && asked {
                    sets.push((m.clone(), "n".into()));
                }
            }
        }
        self.apply(name, &sets);
    }

    fn apply(&mut self, name: &str, sets: &[(String, String)]) {
        if let Some(why) = self.unsettable(name) {
            self.status = vec![why];
            return;
        }
        let mut changes: Vec<Request> = self
            .changes
            .iter()
            .filter(|r| !sets.iter().any(|(s, _)| *s == r.symbol))
            .cloned()
            .collect();
        for (symbol, text) in sets {
            changes.push(Request {
                symbol: symbol.clone(),
                text: text.clone(),
                source: SOURCE.into(),
            });
        }
        let mut all = self.base.clone();
        all.extend(changes.iter().cloned());
        match resolve::resolve(self.table, &all) {
            Ok(res) => {
                self.res = res;
                self.changes = changes;
                self.dirty = true;
                self.status = vec![format!("{name} = {}", self.res.values[name].display())];
            }
            Err(errs) => {
                self.status = first_error(&errs).lines().map(str::to_string).collect();
            }
        }
    }

    /// The preset a build uses: every request, one per symbol, the last word winning.
    pub fn preset_text(&self, started_from: &str) -> String {
        let mut out = String::from(
            "# Saved by kbuild menuconfig. Build with: kbuild build --preset ./menuconfig.preset\n",
        );
        out.push_str(&format!("# Started from {started_from}.\n"));
        let all = self.requests();
        let mut written: Vec<&str> = Vec::new();
        for r in all.iter().rev() {
            if written.contains(&r.symbol.as_str()) {
                continue;
            }
            written.push(&r.symbol);
        }
        written.reverse();
        for name in written {
            let r = all
                .iter()
                .rev()
                .find(|r| r.symbol == name)
                .expect("just collected");
            match self.table.symbols.get(name).map(|s| s.kind) {
                Some(Kind::Str) => out.push_str(&format!("{name}=\"{}\"\n", r.text)),
                _ => out.push_str(&format!("{name}={}\n", r.text)),
            }
        }
        out
    }

    pub fn saved(&mut self, message: String) {
        self.dirty = false;
        self.status = vec![message];
    }

    fn row(&self, item: &Item) -> String {
        match item {
            Item::Menu(m) => format!("      {}  --->", self.table.menus[*m].title),
            Item::Choice(c) => {
                let choice = &self.table.choices[c];
                let picked = choice
                    .members
                    .iter()
                    .find(|m| self.res.is_on(m))
                    .map(|m| self.label(m))
                    .unwrap_or_else(|| "none available".into());
                format!(
                    "      {} ({picked})  --->",
                    choice.prompt.clone().unwrap_or_else(|| c.clone())
                )
            }
            Item::Symbol(name) => {
                let sym = &self.table.symbols[name];
                let reason = &self.res.reasons[name];
                let unavailable = matches!(reason, Reason::DependsUnmet(_));
                let forced = sym.readonly || matches!(reason, Reason::SelectedBy(_));
                let v = &self.res.values[name];
                let mark = match (sym.kind, v) {
                    _ if unavailable => "   ".to_string(),
                    (Kind::Bool, Val::Tri(t)) if sym.choice.is_some() => {
                        if *t == Tri::Y { "(X)" } else { "( )" }.to_string()
                    }
                    (Kind::Bool, Val::Tri(t)) if forced => {
                        if *t == Tri::Y { "-*-" } else { "- -" }.to_string()
                    }
                    (Kind::Bool, Val::Tri(t)) => {
                        if *t == Tri::Y { "[*]" } else { "[ ]" }.to_string()
                    }
                    (Kind::Tristate, Val::Tri(t)) => match t {
                        Tri::N => "< >",
                        Tri::M => "<M>",
                        Tri::Y if forced => "-*-",
                        Tri::Y => "<*>",
                    }
                    .to_string(),
                    (_, Val::Str(s)) => format!("({s})"),
                    (_, other) => format!("({})", other.display()),
                };
                let changed = if self.changes.iter().any(|r| &r.symbol == name) {
                    "+"
                } else {
                    " "
                };
                let mut line = format!("{changed} {mark} {}  [{name}]", self.label(name));
                if unavailable {
                    if let Some(d) = &sym.depends {
                        line.push_str(&format!("  (needs {d})"));
                    }
                }
                line
            }
        }
    }

    fn label(&self, name: &str) -> String {
        self.table.symbols[name]
            .prompt
            .clone()
            .unwrap_or_else(|| name.to_string())
    }

    fn breadcrumb(&self) -> String {
        let mut parts = vec!["KinTane configuration".to_string()];
        for (node, _) in &self.stack[1..] {
            parts.push(match node {
                Node::Root => continue,
                Node::Menu(m) => self.table.menus[*m].title.clone(),
                Node::Choice(c) => self.table.choices[c]
                    .prompt
                    .clone()
                    .unwrap_or_else(|| c.clone()),
            });
        }
        parts.join(" > ")
    }

    /// The screen, `height` lines of at most `width` characters each.
    pub fn render(&self, width: usize, height: usize) -> String {
        let height = height.max(8);
        let width = width.max(20);
        let mut lines: Vec<String> = vec![
            format!("\x1b[1m{}\x1b[0m", self.breadcrumb()),
            "\x1b[2marrows/hjkl move  enter open or change  space toggle  y/n/m set  ? help  \
             w why  s save  q quit\x1b[0m"
                .to_string(),
            String::new(),
        ];
        let body = height - lines.len() - 5;
        match &self.view {
            View::Help(s) | View::Why(s) => {
                let sym = &self.table.symbols[s];
                let mut text = vec![format!(
                    "{} [{s}]  ({}, {})",
                    self.label(s),
                    sym.kind.name(),
                    sym.origin
                )];
                text.push(String::new());
                if let View::Help(_) = self.view {
                    text.extend(
                        sym.help
                            .as_deref()
                            .unwrap_or("No help text.")
                            .lines()
                            .map(str::to_string),
                    );
                } else {
                    text.push(format!("value: {}", self.res.values[s].display()));
                    text.extend(self.res.explain(self.table, s));
                    if let Some(d) = &sym.depends {
                        text.push(format!("depends on: {d}"));
                    }
                    if let Some(r) = resolve::active_range(sym, &self.res) {
                        text.push(format!("range: {}..={}", r.lo, r.hi));
                    }
                }
                text.push(String::new());
                text.push("\x1b[2many key returns\x1b[0m".into());
                lines.extend(text.into_iter().take(body));
            }
            _ => {
                let (node, cursor) = self.stack.last().expect("root is never popped");
                let items = self.items(node);
                let first = cursor.saturating_sub(body.saturating_sub(1));
                for (i, item) in items.iter().enumerate().skip(first).take(body) {
                    let row = self.row(item);
                    lines.push(if i == *cursor {
                        format!("\x1b[7m{row}\x1b[0m")
                    } else {
                        row
                    });
                }
            }
        }
        while lines.len() < height - 4 {
            lines.push(String::new());
        }
        let mut footer = match &self.view {
            View::Edit { symbol, buffer } => vec![format!(
                "{symbol} = {buffer}_   (enter to apply, esc to cancel)"
            )],
            View::ConfirmQuit => {
                vec!["unsaved changes: s saves and quits, q quits without saving, any other key stays".into()]
            }
            _ => self.status.clone(),
        };
        footer.truncate(4);
        lines.extend(footer);
        lines
            .into_iter()
            .take(height)
            .map(|l| clip(&l, width))
            .collect::<Vec<_>>()
            .join("\r\n")
    }
}

/// Clip to `width` visible characters, not counting ANSI escapes.
fn clip(line: &str, width: usize) -> String {
    let mut out = String::new();
    let mut visible = 0;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            out.push(c);
            for e in chars.by_ref() {
                out.push(e);
                if e.is_ascii_alphabetic() {
                    break;
                }
            }
            continue;
        }
        if visible == width {
            out.push_str("\x1b[0m");
            break;
        }
        out.push(c);
        visible += 1;
    }
    out
}

fn first_error(errs: &[resolve::ResolveError]) -> String {
    errs.first().map(|e| e.to_string()).unwrap_or_default()
}

/// Keys in one read from a raw terminal.
pub fn parse_keys(bytes: &[u8]) -> Vec<Key> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let rest = &bytes[i..];
        let (key, used) = match rest {
            [0x1b, b'[' | b'O', b'A', ..] => (Key::Up, 3),
            [0x1b, b'[' | b'O', b'B', ..] => (Key::Down, 3),
            [0x1b, b'[' | b'O', b'C', ..] => (Key::Right, 3),
            [0x1b, b'[' | b'O', b'D', ..] => (Key::Left, 3),
            [0x1b, b'[', ..] => {
                // An escape sequence we do not use: skip to its final byte.
                let end = rest[2..]
                    .iter()
                    .position(|b| b.is_ascii_alphabetic() || *b == b'~')
                    .map(|p| p + 3)
                    .unwrap_or(rest.len());
                i += end;
                continue;
            }
            [0x1b, ..] => (Key::Esc, 1),
            [b'\r' | b'\n', ..] => (Key::Enter, 1),
            [0x7f | 0x08, ..] => (Key::Backspace, 1),
            // Ctrl-C in raw mode is just a byte; treat it as quit-without-asking's cousin.
            [0x03, ..] => (Key::Char('q'), 1),
            _ => {
                let s = String::from_utf8_lossy(rest);
                let c = s.chars().next().unwrap_or('\u{fffd}');
                (Key::Char(c), c.len_utf8().min(rest.len()))
            }
        };
        out.push(key);
        i += used;
    }
    out
}

/// A terminal in raw mode on the alternate screen, restored when dropped.
struct Terminal {
    saved: String,
}

impl Terminal {
    fn enter() -> Result<Terminal, String> {
        let saved = stty(&["-g"]).map_err(|_| {
            "menuconfig needs a terminal; use `kbuild config --set SYM=VALUE`".to_string()
        })?;
        stty(&["raw", "-echo"])?;
        print!("\x1b[?1049h\x1b[?25l");
        let _ = std::io::stdout().flush();
        Ok(Terminal {
            saved: saved.trim().to_string(),
        })
    }

    fn size(&self) -> (usize, usize) {
        stty(&["size"])
            .ok()
            .and_then(|s| {
                let mut it = s.split_whitespace().map(|n| n.parse::<usize>().ok());
                Some((it.next()??, it.next()??))
            })
            // A pseudo-terminal nobody sized reports `0 0`, which drew every line clipped
            // to nothing the first time this ran under `script`.
            .filter(|(rows, cols)| *rows > 0 && *cols > 0)
            .map(|(rows, cols)| (cols, rows))
            .unwrap_or((80, 24))
    }

    fn draw(&self, screen: &str) {
        print!("\x1b[H\x1b[2J{screen}");
        let _ = std::io::stdout().flush();
    }

    fn keys(&self) -> Result<Vec<Key>, String> {
        let mut buf = [0u8; 32];
        let n = std::io::stdin()
            .read(&mut buf)
            .map_err(|e| format!("reading the terminal: {e}"))?;
        if n == 0 {
            return Ok(vec![Key::Char('q')]);
        }
        Ok(parse_keys(&buf[..n]))
    }
}

impl Drop for Terminal {
    fn drop(&mut self) {
        print!("\x1b[?25h\x1b[?1049l");
        let _ = std::io::stdout().flush();
        let _ = stty(&[self.saved.as_str()]);
    }
}

/// Run `stty` on the terminal this process was started from.
fn stty(args: &[&str]) -> Result<String, String> {
    let out = Command::new("stty")
        .args(args)
        .stdin(Stdio::inherit())
        .stderr(Stdio::null())
        .output()
        .map_err(|e| format!("cannot run stty: {e}"))?;
    if !out.status.success() {
        return Err("stty failed: standard input is not a terminal".into());
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

pub fn run(root: &Path, opts: &Opts) -> Result<(), String> {
    let (table, mut base) = crate::base_requests(root, opts)?;
    if let Some(mode) = opts.generate {
        base = crate::kcfg::random::generate(&table, &base, mode)
            .map_err(|e| first_error(&e))?
            .1;
    }
    let started_from = match &opts.preset {
        Some(p) => format!("preset {p}"),
        None => "the defaults".into(),
    };
    let mut session = Session::new(&table, base)?;
    let term = Terminal::enter()?;
    loop {
        let (w, h) = term.size();
        term.draw(&session.render(w, h));
        for key in term.keys()? {
            let action = session.handle(key);
            if matches!(action, Action::Save | Action::SaveAndQuit) {
                let preset = root.join("menuconfig.preset");
                crate::codegen::write_dotconfig(
                    &table,
                    session.resolution(),
                    &root.join(".config"),
                )?;
                std::fs::write(&preset, session.preset_text(&started_from))
                    .map_err(|e| format!("{}: {e}", preset.display()))?;
                session.saved(
                    "saved .config and menuconfig.preset; build with \
                               `kbuild build --preset ./menuconfig.preset`"
                        .into(),
                );
            }
            if matches!(action, Action::Quit | Action::SaveAndQuit) {
                drop(term);
                return Ok(());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kcfg::resolve::tests::{req, table};

    const TREE: &str = r#"
config ARCH_HAS_SMP
    bool
    readonly
    default y

menu "Kernel"

config SMP
    bool "Symmetric multiprocessing"
    depends on ARCH_HAS_SMP
    default y
    help
        More than one CPU.

config NUMA
    bool "NUMA"
    select SMP

config NR_CPUS
    int "CPUs"
    depends on SMP
    range 2 64
    default 8

config NAME
    string "Name"
    default "kintane"

config DRIVER
    tristate "A driver"

endmenu

choice ARCH
    prompt "Architecture"
    default A1
    config A1
        bool "First"
    config A2
        bool "Second"
endchoice
"#;

    fn keys(s: &mut Session, ks: &[Key]) -> Action {
        let mut last = Action::Continue;
        for k in ks {
            last = s.handle(*k);
        }
        last
    }

    fn down(n: usize) -> Vec<Key> {
        vec![Key::Down; n]
    }

    #[test]
    fn the_tree_follows_menus_and_choices_in_declaration_order() {
        let t = table(TREE);
        let s = Session::new(&t, vec![]).unwrap();
        assert_eq!(
            s.items(&Node::Root),
            vec![
                Item::Symbol("ARCH_HAS_SMP".into()),
                Item::Menu(0),
                Item::Choice("ARCH".into())
            ]
        );
        assert_eq!(s.items(&Node::Menu(0)).len(), 5);
        assert_eq!(
            s.items(&Node::Choice("ARCH".into())),
            vec![Item::Symbol("A1".into()), Item::Symbol("A2".into())]
        );
    }

    #[test]
    fn toggling_goes_through_the_resolver_and_is_recorded_as_a_change() {
        let t = table(TREE);
        let mut s = Session::new(&t, vec![]).unwrap();
        // Into "Kernel", onto SMP, toggle it off: NR_CPUS goes with it.
        keys(&mut s, &[Key::Down, Key::Enter, Key::Char(' ')]);
        assert!(!s.resolution().is_on("SMP"));
        assert_eq!(s.resolution().int("NR_CPUS"), 0);
        assert_eq!(
            s.requests(),
            req(&[("SMP", "n")])
                .into_iter()
                .map(|mut r| {
                    r.source = SOURCE.into();
                    r
                })
                .collect::<Vec<_>>()
        );
        assert!(s.render(100, 30).contains("(needs SMP)"), "{}", s.render(100, 30));
    }

    #[test]
    fn a_change_the_resolver_refuses_is_explained_and_not_applied() {
        let t = table(TREE);
        let mut s = Session::new(&t, req(&[("NUMA", "y")])).unwrap();
        keys(&mut s, &[Key::Down, Key::Enter, Key::Char('n')]);
        assert!(s.resolution().is_on("SMP"), "still on");
        assert_eq!(s.requests(), req(&[("NUMA", "y")]), "and not recorded to be saved");
        let screen = s.render(120, 30);
        assert!(screen.contains("cannot set SMP=n"), "{screen}");
        assert!(screen.contains("selected by NUMA"), "{screen}");
        // The forced symbol is drawn as forced.
        assert!(screen.contains("-*- Symmetric multiprocessing"), "{screen}");
    }

    #[test]
    fn picking_a_choice_member_overrides_the_presets_pick() {
        let t = table(TREE);
        let mut s = Session::new(&t, req(&[("A1", "y")])).unwrap();
        keys(&mut s, &[Key::Down, Key::Down, Key::Enter, Key::Down, Key::Enter]);
        assert!(s.resolution().is_on("A2"));
        assert!(!s.resolution().is_on("A1"));
        assert!(s.render(100, 30).contains("(X) Second"));
    }

    #[test]
    fn values_are_edited_and_ranges_hold() {
        let t = table(TREE);
        let mut s = Session::new(&t, vec![]).unwrap();
        let mut ks = vec![Key::Down, Key::Enter];
        ks.extend(down(2)); // NR_CPUS
        ks.extend([
            Key::Enter,
            Key::Backspace,
            Key::Char('3'),
            Key::Char('2'),
            Key::Enter,
        ]);
        keys(&mut s, &ks);
        assert_eq!(s.resolution().int("NR_CPUS"), 32);

        keys(&mut s, &[Key::Enter, Key::Char('0'), Key::Char('0'), Key::Enter]);
        assert_eq!(s.resolution().int("NR_CPUS"), 32, "3200 is out of range");
        assert!(s.render(120, 30).contains("outside its range"));

        keys(&mut s, &[Key::Down, Key::Enter, Key::Char('!'), Key::Esc]);
        assert_eq!(s.resolution().str("NAME"), "kintane", "escape cancels");
    }

    #[test]
    fn m_without_modules_is_refused_with_the_reason() {
        let t = table(TREE);
        let mut s = Session::new(&t, vec![]).unwrap();
        let mut ks = vec![Key::Down, Key::Enter];
        ks.extend(down(4));
        ks.push(Key::Char('m'));
        keys(&mut s, &ks);
        let screen = s.render(160, 30);
        assert!(screen.contains("cannot set DRIVER=m"), "{screen}");
        assert!(screen.contains("loadable modules do not exist yet"), "{screen}");
        keys(&mut s, &[Key::Char(' ')]);
        assert_eq!(s.resolution().tri("DRIVER"), Tri::Y, "space steps n to y without modules");
    }

    #[test]
    fn readonly_symbols_cannot_be_changed_and_why_explains_a_select() {
        let t = table(TREE);
        let mut s = Session::new(&t, req(&[("NUMA", "y")])).unwrap();
        keys(&mut s, &[Key::Char('n')]);
        assert!(s.render(120, 30).contains("ARCH_HAS_SMP is readonly"));

        keys(&mut s, &[Key::Down, Key::Enter, Key::Char('w')]);
        let screen = s.render(120, 30);
        assert!(screen.contains("SMP is selected by NUMA"), "{screen}");
        assert!(screen.contains("NUMA is set by test"), "{screen}");
        keys(&mut s, &[Key::Char('x')]);
        keys(&mut s, &[Key::Char('?')]);
        assert!(s.render(120, 30).contains("More than one CPU."));
    }

    #[test]
    fn quitting_with_unsaved_changes_asks_first_and_saving_clears_it() {
        let t = table(TREE);
        let mut s = Session::new(&t, vec![]).unwrap();
        assert_eq!(keys(&mut s, &[Key::Char('q')]), Action::Quit, "nothing to lose");
        keys(&mut s, &[Key::Down, Key::Enter, Key::Char('n')]);
        assert_eq!(keys(&mut s, &[Key::Char('q')]), Action::Continue);
        assert!(s.render(120, 30).contains("unsaved changes"));
        assert_eq!(keys(&mut s, &[Key::Char('x')]), Action::Continue, "stays");
        keys(&mut s, &[Key::Char('q')]);
        assert_eq!(keys(&mut s, &[Key::Char('s')]), Action::SaveAndQuit);
        s.saved("saved".into());
        assert_eq!(keys(&mut s, &[Key::Char('q')]), Action::Quit);
    }

    #[test]
    fn the_saved_preset_rebuilds_the_same_configuration() {
        let t = table(TREE);
        let mut s = Session::new(&t, req(&[("A1", "y"), ("NUMA", "y")])).unwrap();
        s.set("A2", "y");
        s.set("NAME", "renamed");
        s.set("NUMA", "n");
        let text = s.preset_text("preset test");

        let dir = std::env::temp_dir().join(format!("menuconfig-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("saved.preset");
        std::fs::write(&path, &text).unwrap();
        let again: Vec<Request> = crate::codegen::read_settings(&path)
            .unwrap()
            .into_iter()
            .map(|(symbol, text)| Request {
                symbol,
                text,
                source: "file".into(),
            })
            .collect();
        let res = resolve::resolve(&t, &again).unwrap();
        assert_eq!(res.values, s.resolution().values, "{text}");
        assert_eq!(text.matches("NUMA=").count(), 1, "one line per symbol: {text}");
        assert!(text.contains("NAME=\"renamed\""), "{text}");
    }

    #[test]
    fn keys_parse_from_raw_bytes_including_several_in_one_read() {
        assert_eq!(
            parse_keys(b"\x1b[A\x1b[Bj\r\x7f\x1bq"),
            vec![
                Key::Up,
                Key::Down,
                Key::Char('j'),
                Key::Enter,
                Key::Backspace,
                Key::Esc,
                Key::Char('q')
            ]
        );
        assert_eq!(parse_keys(b"\x1b[3~x"), vec![Key::Char('x')], "unused sequences are skipped");
    }

    #[test]
    fn a_terminal_that_reports_no_size_still_gets_a_readable_screen() {
        let t = table(TREE);
        let s = Session::new(&t, vec![]).unwrap();
        let screen = s.render(0, 0);
        assert!(screen.contains("KinTane config"), "{screen:?}");
    }

    #[test]
    fn clipping_counts_characters_not_escapes() {
        assert_eq!(clip("\x1b[7mabcdef\x1b[0m", 3), "\x1b[7mabc\x1b[0m");
        assert_eq!(clip("ab", 5), "ab");
    }
}

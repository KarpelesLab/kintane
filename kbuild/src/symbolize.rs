//! Decoding a guest's backtrace against the image's symbol bundle.
//!
//! The kernel prints raw addresses (`lib/unwind`):
//!
//! ```text
//!   bt pc 0x00000000001075f4
//!   bt 0 0x0000000000103869
//! ```
//!
//! This finds those lines, whatever else surrounds them, and names each address:
//! the function from the pinned `llvm-nm`, and the file and line from the bundle's
//! `.debug_line` (see `dwarf.rs` for why not a symbolizer binary).
//!
//! A numbered entry is a return address. It points at the instruction *after* the call,
//! and that instruction can belong to the next line or, after a call that never returns,
//! to the next function entirely. So it is looked up one byte earlier, which lands inside
//! the call. `pc` is the faulting instruction itself and is looked up as it is.

use std::path::Path;
use std::process::Command;

use crate::dwarf::{Elf, LineTable};

/// One backtrace entry found in a log.
#[derive(Debug, PartialEq, Eq)]
pub struct Entry {
    /// `None` for `pc`, otherwise the frame number.
    pub frame: Option<u32>,
    pub addr: u64,
}

impl Entry {
    /// The address whose line explains this entry.
    fn lookup_addr(&self) -> u64 {
        match self.frame {
            None => self.addr,
            Some(_) => self.addr.saturating_sub(1),
        }
    }
}

/// Parse one console line as a backtrace entry, if it is one.
///
/// Tolerant of what serial consoles do to lines: leading noise, a trailing `\r`.
pub fn parse_line(line: &str) -> Option<Entry> {
    let at = line.find("bt ")?;
    let mut words = line[at + 3..].split_whitespace();
    let frame = match words.next()? {
        "pc" => None,
        n => Some(n.parse().ok()?),
    };
    let hex = words.next()?.strip_prefix("0x")?;
    let addr = u64::from_str_radix(hex, 16).ok()?;
    Some(Entry { frame, addr })
}

/// A function symbol.
#[derive(Debug, PartialEq, Eq)]
pub struct Symbol {
    pub start: u64,
    /// Zero for symbols without a size, such as labels in assembly.
    pub size: u64,
    pub name: String,
}

/// Parse `llvm-nm --defined-only -n -S -C` output, keeping code symbols only.
///
/// A line is `ADDR SIZE TYPE NAME` or, for a symbol with no size, `ADDR TYPE NAME`.
/// Demangled names contain spaces (`<T as Trait>::f`), so only the leading fields are
/// split off.
pub fn parse_nm(out: &str) -> Vec<Symbol> {
    let mut syms = Vec::new();
    for line in out.lines() {
        let mut parts = line.splitn(2, ' ');
        let (Some(addr), Some(rest)) = (parts.next(), parts.next()) else {
            continue;
        };
        let Ok(start) = u64::from_str_radix(addr, 16) else {
            continue;
        };
        let (size, rest) = match rest.split_once(' ') {
            Some((s, r)) if s.len() > 1 => match u64::from_str_radix(s, 16) {
                Ok(n) => (n, r),
                Err(_) => continue,
            },
            _ => (0, rest),
        };
        let Some((kind, name)) = rest.split_once(' ') else {
            continue;
        };
        if matches!(kind, "t" | "T" | "w" | "W") {
            syms.push(Symbol {
                start,
                size,
                name: name.to_string(),
            });
        }
    }
    syms.sort_by_key(|s| s.start);
    syms
}

/// The function containing `addr`, and the offset into it.
///
/// A sized symbol must actually cover the address. An unsized one, a label, is taken
/// only when nothing sized does, so a label inside a function never hides its name.
pub fn function_at(syms: &[Symbol], addr: u64) -> Option<(&str, u64)> {
    let i = syms.partition_point(|s| s.start <= addr);
    let below = &syms[..i];
    let sized = below
        .iter()
        .rev()
        .find(|s| s.size > 0 && addr < s.start + s.size);
    let s = sized.or_else(|| below.iter().rev().find(|s| s.size == 0))?;
    Some((&s.name, addr - s.start))
}

/// A symbol bundle, loaded.
pub struct Symbols {
    syms: Vec<Symbol>,
    lines: LineTable,
    /// The tree root as the compiler saw it, to turn `/kintane/x` back into `x`.
    remap: &'static str,
    /// Hex digits in an address of this image, for printing.
    digits: usize,
}

impl Symbols {
    pub fn load(bundle: &Path, nm: &Path) -> Result<Symbols, String> {
        let data = std::fs::read(bundle).map_err(|e| format!("{}: {e}", bundle.display()))?;
        let elf = Elf::parse(&data).map_err(|e| format!("{}: {e}", bundle.display()))?;
        let lines = LineTable::from_elf(&elf).map_err(|e| format!("{}: {e}", bundle.display()))?;
        let out = Command::new(nm)
            .args(["--defined-only", "-n", "-S", "-C"])
            .arg(bundle)
            .output()
            .map_err(|e| format!("cannot run {}: {e}", nm.display()))?;
        if !out.status.success() {
            return Err(format!(
                "llvm-nm failed on {}:\n{}",
                bundle.display(),
                String::from_utf8_lossy(&out.stderr)
            ));
        }
        Ok(Symbols {
            syms: parse_nm(&String::from_utf8_lossy(&out.stdout)),
            lines,
            remap: "/kintane/",
            digits: if elf.is64 { 16 } else { 8 },
        })
    }

    /// `function+0xoff  file:line`, as much of it as is known.
    pub fn describe(&self, e: &Entry) -> String {
        let at = e.lookup_addr();
        let func = match function_at(&self.syms, at) {
            // The offset of the printed address, which is what a disassembly shows,
            // rather than of the byte that was looked up.
            Some((name, off)) => format!("{name}+{:#x}", off + (e.addr - at)),
            None => "??".to_string(),
        };
        match self.lines.lookup(at) {
            Some((file, line)) => {
                let file = file.strip_prefix(self.remap).unwrap_or(file);
                format!("{func}  {file}:{line}")
            }
            None => func,
        }
    }
}

/// Every backtrace entry in `log`, in order.
pub fn entries(log: &str) -> Vec<Entry> {
    log.lines().filter_map(parse_line).collect()
}

/// Print a decoded backtrace for every entry in `log`. Returns how many there were.
pub fn report(log: &str, bundle: &Path, nm: &Path) -> Result<usize, String> {
    let found = entries(log);
    if found.is_empty() {
        return Ok(0);
    }
    let syms = Symbols::load(bundle, nm)?;
    println!("\n\x1b[36msymbolized backtrace\x1b[0m ({})", bundle.display());
    for e in &found {
        let label = match e.frame {
            None => "pc".to_string(),
            Some(n) => format!("#{n}"),
        };
        let width = syms.digits + 2;
        println!("  {label:>3}  {:#0width$x}  {}", e.addr, syms.describe(e));
    }
    Ok(found.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backtrace_lines_are_found_among_other_output() {
        let log = "\
kernel panic: kernel/main/src/crash.rs:26
backtrace:
  bt pc 0x00000000001075f4\r
  bt 0 0x0000000000103869
  bt 12 0x00000000deadbeef
  bt end: null frame
reached kmain
  robot 1 0x10
";
        assert_eq!(
            entries(log),
            [
                Entry {
                    frame: None,
                    addr: 0x1075f4
                },
                Entry {
                    frame: Some(0),
                    addr: 0x103869
                },
                Entry {
                    frame: Some(12),
                    addr: 0xdeadbeef
                },
            ]
        );
    }

    #[test]
    fn return_addresses_are_looked_up_one_byte_back() {
        let pc = parse_line("bt pc 0x1000").unwrap();
        let ra = parse_line("bt 0 0x1000").unwrap();
        assert_eq!(pc.lookup_addr(), 0x1000);
        assert_eq!(ra.lookup_addr(), 0x0fff);
    }

    #[test]
    fn nm_output_with_and_without_sizes() {
        let out = "\
0000000000100000 T _start
0000000000100310 0000000000000120 t kintane::banner
0000000000100430 0000000000000010 T <arch::Serial as hal::EarlyConsole>::write_bytes
0000000000100500 0000000000000008 r some::constant
0000000000100510 W weak_label
";
        let syms = parse_nm(out);
        assert_eq!(syms.len(), 4, "{syms:?}");
        assert_eq!(syms[0].size, 0);
        assert_eq!(syms[1].name, "kintane::banner");
        assert_eq!(syms[2].name, "<arch::Serial as hal::EarlyConsole>::write_bytes");

        assert_eq!(function_at(&syms, 0x100320), Some(("kintane::banner", 0x10)));
        // Past the end of `write_bytes` and before `weak_label`: the nearest label.
        assert_eq!(function_at(&syms, 0x100440), Some(("_start", 0x440)));
        assert_eq!(function_at(&syms, 0xfffff), None);
    }
}

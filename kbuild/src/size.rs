//! `kbuild size`: what the image costs, per section and per crate, against a budget.
//!
//! A 300-byte regression on a Cortex-M matters and is invisible on x86_64
//! (`docs/testing.md`, "Size budgets"). So every preset can declare a budget,
//! `SIZE_BUDGET_KIB`, and a build that exceeds it fails. A change's cost is shown as a
//! delta against a baseline report, so it is visible before it accumulates into a
//! budget failure somebody else inherits.
//!
//! What is measured is the linked kernel ELF, not the packaged image: every allocated
//! section, `.bss` included, because that is what the machine must hold. The per-crate
//! split comes from the symbol table (`llvm-nm --print-size --demangle`): each symbol is
//! charged to the crate its demangled path starts in. A generic is charged to the crate
//! that defines it, not the one that instantiated it, which is the attribution a person
//! looking for the code to shrink wants.
//!
//! The baseline is a report file, `config/size-baseline/<preset>.size`, rewritten by
//! `--update-baseline`. `--compare` takes another report file, or a git revision whose
//! committed baseline is read with `git show`, so comparing with `origin/master` needs no
//! second build.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::Opts;

/// Where a byte of the image lives.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Class {
    Text,
    Rodata,
    Data,
    Bss,
}

impl Class {
    const ALL: [Class; 4] = [Class::Text, Class::Rodata, Class::Data, Class::Bss];

    fn name(self) -> &'static str {
        match self {
            Class::Text => "text",
            Class::Rodata => "rodata",
            Class::Data => "data",
            Class::Bss => "bss",
        }
    }
}

/// A size report: what `kbuild size` prints and what a baseline file holds.
#[derive(Debug, Default, PartialEq)]
pub struct Report {
    /// Allocated sections, by name, in bytes.
    pub sections: BTreeMap<String, u64>,
    /// Bytes per crate, per class.
    pub crates: BTreeMap<String, [u64; 4]>,
    pub total: u64,
}

impl Report {
    /// The text form. Stable and line-oriented, so a baseline diff reads in a review.
    pub fn to_text(&self, preset: &str) -> String {
        let mut out = format!(
            "# kbuild size report for preset {preset}. Rewrite with `kbuild size --preset \
             {preset} --update-baseline`.\n"
        );
        for (name, bytes) in &self.sections {
            out.push_str(&format!("section {name} {bytes}\n"));
        }
        for (name, c) in &self.crates {
            out.push_str(&format!(
                "crate {name} text {} rodata {} data {} bss {}\n",
                c[0], c[1], c[2], c[3]
            ));
        }
        out.push_str(&format!("total {}\n", self.total));
        out
    }

    pub fn parse(text: &str) -> Result<Report, String> {
        let mut r = Report::default();
        for (i, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let bad = || format!("size report line {}: `{line}`", i + 1);
            let words: Vec<&str> = line.split_whitespace().collect();
            let num = |s: &str| s.parse::<u64>().map_err(|_| bad());
            match words.as_slice() {
                ["section", name, bytes] => {
                    r.sections.insert(name.to_string(), num(bytes)?);
                }
                ["crate", name, "text", t, "rodata", ro, "data", d, "bss", b] => {
                    r.crates
                        .insert(name.to_string(), [num(t)?, num(ro)?, num(d)?, num(b)?]);
                }
                ["total", bytes] => r.total = num(bytes)?,
                _ => return Err(bad()),
            }
        }
        Ok(r)
    }
}

/// Allocated sections of an ELF file: `(name, class, size)`. Little-endian ELF32 and
/// ELF64, which is every target the kernel builds for today.
pub fn sections(elf: &[u8]) -> Result<Vec<(String, Class, u64)>, String> {
    const SHF_WRITE: u64 = 1;
    const SHF_ALLOC: u64 = 2;
    const SHF_EXECINSTR: u64 = 4;
    const SHT_NOBITS: u32 = 8;

    let short = || "not a complete ELF file".to_string();
    if elf.len() < 0x34 || &elf[..4] != b"\x7fELF" {
        return Err(short());
    }
    if elf[5] != 1 {
        return Err("big-endian ELF is not supported by the size report yet".into());
    }
    let wide = match elf[4] {
        1 => false,
        2 => true,
        c => return Err(format!("unknown ELF class {c}")),
    };
    let rd = |off: usize, n: usize| -> Result<u64, String> {
        let b = elf.get(off..off + n).ok_or_else(short)?;
        let mut v = [0u8; 8];
        v[..n].copy_from_slice(b);
        Ok(u64::from_le_bytes(v))
    };
    let word = if wide { 8 } else { 4 };
    let (shoff, shentsize, shnum, shstrndx) = if wide {
        (rd(0x28, 8)?, rd(0x3a, 2)?, rd(0x3c, 2)?, rd(0x3e, 2)?)
    } else {
        (rd(0x20, 4)?, rd(0x2e, 2)?, rd(0x30, 2)?, rd(0x32, 2)?)
    };
    let header = |i: u64| -> Result<(u64, u32, u64, u64, u64), String> {
        let at = (shoff + i * shentsize) as usize;
        let name = rd(at, 4)?;
        let kind = rd(at + 4, 4)? as u32;
        let flags = rd(at + 8, word)?;
        let (offset, size) = if wide {
            (rd(at + 0x18, 8)?, rd(at + 0x20, 8)?)
        } else {
            (rd(at + 0x10, 4)?, rd(at + 0x14, 4)?)
        };
        Ok((name, kind, flags, offset, size))
    };
    let (_, _, _, str_off, str_size) = header(shstrndx)?;
    let strtab = elf
        .get(str_off as usize..(str_off + str_size) as usize)
        .ok_or_else(short)?;

    let mut out = Vec::new();
    for i in 0..shnum {
        let (name, kind, flags, _, size) = header(i)?;
        if flags & SHF_ALLOC == 0 || size == 0 {
            continue;
        }
        let name = strtab
            .get(name as usize..)
            .and_then(|s| s.split(|b| *b == 0).next())
            .map(|s| String::from_utf8_lossy(s).into_owned())
            .unwrap_or_default();
        let class = if flags & SHF_EXECINSTR != 0 {
            Class::Text
        } else if kind == SHT_NOBITS {
            Class::Bss
        } else if flags & SHF_WRITE != 0 {
            Class::Data
        } else {
            Class::Rodata
        };
        out.push((name, class, size));
    }
    Ok(out)
}

/// The crate a demangled Rust symbol belongs to: the first path segment that is followed
/// by `::`. `<mm::paged::AddressSpace<arch::X86_64>>::map` is `mm`; `<u8 as
/// core::fmt::Debug>::fmt` is `core`, since `u8` names no crate.
pub fn crate_of(symbol: &str) -> String {
    let b = symbol.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i].is_ascii_alphabetic() || b[i] == b'_' {
            let start = i;
            while i < b.len() && (b[i].is_ascii_alphanumeric() || b[i] == b'_') {
                i += 1;
            }
            if symbol[i..].starts_with("::") {
                return symbol[start..i].to_string();
            }
        } else {
            i += 1;
        }
    }
    // No spaces: a report line is whitespace-separated.
    if symbol.starts_with("anon.") || symbol.starts_with(".L") {
        "(anonymous)".into()
    } else {
        "(unmangled)".into()
    }
}

/// Charge every sized symbol to its crate, from `llvm-nm --print-size --defined-only
/// --demangle` output.
pub fn crates(nm: &str) -> BTreeMap<String, [u64; 4]> {
    let mut out: BTreeMap<String, [u64; 4]> = BTreeMap::new();
    for line in nm.lines() {
        let mut it = line.splitn(4, ' ');
        let (Some(_addr), Some(size), Some(kind), Some(name)) =
            (it.next(), it.next(), it.next(), it.next())
        else {
            continue;
        };
        let Ok(size) = u64::from_str_radix(size, 16) else {
            continue;
        };
        let class = match kind {
            "t" | "T" | "w" | "W" => Class::Text,
            "r" | "R" | "n" | "N" => Class::Rodata,
            "d" | "D" => Class::Data,
            "b" | "B" => Class::Bss,
            _ => continue,
        };
        if size == 0 {
            continue;
        }
        out.entry(crate_of(name)).or_default()[class as usize] += size;
    }
    out
}

pub fn measure(elf: &Path, nm_tool: &Path) -> Result<Report, String> {
    let bytes = std::fs::read(elf).map_err(|e| format!("{}: {e}", elf.display()))?;
    let mut report = Report::default();
    for (name, _, size) in sections(&bytes)? {
        *report.sections.entry(name).or_default() += size;
        report.total += size;
    }
    let out = Command::new(nm_tool)
        .args(["--print-size", "--defined-only", "--demangle"])
        .arg(elf)
        .output()
        .map_err(|e| format!("cannot run llvm-nm: {e}"))?;
    if !out.status.success() {
        return Err(format!("llvm-nm failed: {}", String::from_utf8_lossy(&out.stderr)));
    }
    report.crates = crates(&String::from_utf8_lossy(&out.stdout));
    Ok(report)
}

/// `12,345`.
fn grouped(n: u64) -> String {
    let s = n.to_string();
    let mut out = String::new();
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(c);
    }
    out
}

fn delta(now: u64, then: Option<u64>) -> String {
    match then {
        None => "   (new)".into(),
        Some(t) => {
            let d = now as i128 - t as i128;
            if d == 0 {
                "      +0".into()
            } else {
                format!("{:>+8}", d)
            }
        }
    }
}

/// The printed report, with deltas against `base` and the budget verdict. Returns the
/// text and whether the budget holds.
pub fn render(
    preset: &str,
    now: &Report,
    base: Option<&Report>,
    budget_kib: i64,
) -> (String, bool) {
    let mut out = String::new();
    let budget = (budget_kib > 0).then(|| budget_kib as u64 * 1024);
    out.push_str(&format!(
        "  preset {preset:<20} budget {}\n",
        match budget_kib {
            b if b > 0 => format!("{b} KiB"),
            _ => "none (SIZE_BUDGET_KIB is 0)".into(),
        }
    ));
    for (name, bytes) in &now.sections {
        let then = base.map(|b| b.sections.get(name).copied().unwrap_or(0));
        out.push_str(&format!("    {name:<24} {:>12} {}\n", grouped(*bytes), delta(*bytes, then)));
    }
    let then = base.map(|b| b.total);
    let share = budget
        .map(|b| format!("   ({}% of budget)", now.total * 100 / b.max(1)))
        .unwrap_or_default();
    out.push_str(&format!(
        "    {:<24} {:>12} {}{share}\n",
        "total",
        grouped(now.total),
        delta(now.total, then)
    ));

    // Largest crates, and any crate whose size moved, so a regression is never below
    // the cut.
    out.push_str("  crates (text + rodata + data + bss)\n");
    let sum = |c: &[u64; 4]| c.iter().sum::<u64>();
    let mut rows: Vec<(&String, u64)> = now.crates.iter().map(|(k, c)| (k, sum(c))).collect();
    rows.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
    for (i, (name, bytes)) in rows.iter().enumerate() {
        let then = base.map(|b| b.crates.get(*name).map(sum).unwrap_or(0));
        let moved = then.is_some_and(|t| t != *bytes);
        if i < 12 || moved {
            let parts: Vec<String> = Class::ALL
                .iter()
                .map(|c| format!("{} {}", c.name(), grouped(now.crates[*name][*c as usize])))
                .collect();
            out.push_str(&format!(
                "    {name:<24} {:>12} {}   {}\n",
                grouped(*bytes),
                delta(*bytes, then),
                parts.join(", ")
            ));
        }
    }
    if let Some(b) = base {
        for gone in b.crates.keys().filter(|k| !now.crates.contains_key(*k)) {
            out.push_str(&format!(
                "    {gone:<24} {:>12} {:>8}\n",
                "gone",
                -(sum(&b.crates[gone]) as i128)
            ));
        }
    }

    let ok = budget.is_none_or(|b| now.total <= b);
    if let (Some(b), false) = (budget, ok) {
        out.push_str(&format!(
            "  \x1b[31mover budget\x1b[0m by {} bytes: {} > {}\n",
            grouped(now.total - b),
            grouped(now.total),
            grouped(b)
        ));
    }
    (out, ok)
}

/// The baseline to compare with: `--compare` as a file, `--compare` as a git revision's
/// committed baseline, or the working tree's baseline.
fn baseline(
    root: &Path,
    preset: &str,
    compare: Option<&str>,
) -> Result<Option<(String, Report)>, String> {
    let rel = format!("config/size-baseline/{preset}.size");
    let (label, text) = match compare {
        Some(c) if Path::new(c).is_file() => {
            (c.to_string(), std::fs::read_to_string(c).map_err(|e| format!("{c}: {e}"))?)
        }
        Some(rev) => {
            let out = Command::new("git")
                .arg("-C")
                .arg(root)
                .args(["show", &format!("{rev}:{rel}")])
                .output()
                .map_err(|e| format!("cannot run git: {e}"))?;
            if !out.status.success() {
                return Err(format!(
                    "no baseline for {preset} at `{rev}`: {}",
                    String::from_utf8_lossy(&out.stderr).trim()
                ));
            }
            (format!("{rev}:{rel}"), String::from_utf8_lossy(&out.stdout).into_owned())
        }
        None => match std::fs::read_to_string(root.join(&rel)) {
            Ok(t) => (rel, t),
            Err(_) => return Ok(None),
        },
    };
    Ok(Some((label, Report::parse(&text)?)))
}

pub fn run(root: &Path, opts: &Opts) -> Result<(), String> {
    let preset = opts
        .preset
        .clone()
        .ok_or("size needs --preset: budgets and baselines are per preset")?;
    let (image, res) = crate::do_build(root, opts)?;
    let out_dir = image
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    let bundle = crate::find_symbol_bundle(&out_dir)?;
    let linked = bundle.with_extension("elf");
    let tc = crate::toolchain::verify(root)?;
    let report = measure(&linked, &tc.tool("llvm-nm")?)?;

    let base = match baseline(root, &preset, opts.compare.as_deref()) {
        // An unreadable baseline is an error, except when it is about to be replaced.
        Err(e) if opts.update_baseline => {
            eprintln!("\x1b[33mold baseline ignored\x1b[0m: {e}");
            None
        }
        other => other?,
    };
    println!(
        "\n\x1b[36msize\x1b[0m {} against {}",
        linked.display(),
        base.as_ref()
            .map(|(l, _)| l.as_str())
            .unwrap_or("no baseline")
    );
    let (text, ok) =
        render(&preset, &report, base.as_ref().map(|(_, r)| r), res.int("SIZE_BUDGET_KIB"));
    print!("{text}");

    let name = Path::new(&preset)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or(&preset)
        .to_string();
    if let Some(path) = &opts.save {
        std::fs::write(path, report.to_text(&name)).map_err(|e| format!("{path}: {e}"))?;
    }
    if opts.update_baseline {
        let path = root.join(format!("config/size-baseline/{name}.size"));
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        }
        std::fs::write(&path, report.to_text(&name))
            .map_err(|e| format!("{}: {e}", path.display()))?;
        println!("  baseline written to {}", path.display());
    }
    if ok {
        Ok(())
    } else {
        Err(format!(
            "{preset} is over its size budget of {} KiB",
            res.int("SIZE_BUDGET_KIB")
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crates_come_from_the_first_path_segment_even_through_impls_and_generics() {
        assert_eq!(
            crate_of("<mm::paged::AddressSpace<arch::X86_64>>::map::<kintane::space::Frames>"),
            "mm"
        );
        assert_eq!(crate_of("kintane::space::build_and_verify::<arch::X86_64>"), "kintane");
        assert_eq!(crate_of("<u8 as core::fmt::Debug>::fmt"), "core");
        assert_eq!(crate_of("<[u8] as core::fmt::Debug>::fmt"), "core");
        assert_eq!(crate_of("_start"), "(unmangled)");
        assert_eq!(crate_of("anon.1acbebe3.0.llvm.1176"), "(anonymous)");
    }

    #[test]
    fn every_crate_label_survives_the_text_form() {
        // The first baseline written had a label with spaces in it, and could not be
        // read back.
        let mut r = Report::default();
        for sym in [
            "_start",
            "anon.1.llvm.2",
            "mm::x",
            "<u8 as core::fmt::Debug>::fmt",
        ] {
            r.crates.insert(crate_of(sym), [1, 0, 0, 0]);
        }
        assert_eq!(Report::parse(&r.to_text("p")).unwrap(), r);
    }

    #[test]
    fn nm_lines_are_charged_by_class_and_zero_sizes_and_absolutes_are_skipped() {
        let nm = "\
0000000000105090 000000000000020c t <mm::paged::AddressSpace<arch::X86_64>>::split_leaf
0000000000106300 0000000000000010 T mm::phys::bitmap_bytes::<arch::X86_64>
0000000000122000 0000000000000008 r mm::TABLE
0000000000127000 0000000000000004 d mm::COUNTER
0000000000130000 0000000000001000 B kintane::STACK
0000000000008000 0000000000000000 A THREAD_STACK_SLOT
0000000000100000 0000000000000000 T __kernel_start
";
        let c = crates(nm);
        assert_eq!(c["mm"], [0x20c + 0x10, 8, 4, 0]);
        assert_eq!(c["kintane"], [0, 0, 0, 0x1000]);
        assert_eq!(c.len(), 2);
    }

    #[test]
    fn a_report_survives_its_text_form() {
        let mut r = Report::default();
        r.sections.insert(".text".into(), 1234);
        r.sections.insert(".bss".into(), 99);
        r.crates.insert("mm".into(), [1, 2, 3, 4]);
        r.total = 1333;
        assert_eq!(Report::parse(&r.to_text("p")).unwrap(), r);
        assert!(Report::parse("section .text lots").is_err());
    }

    #[test]
    fn exceeding_the_budget_fails_and_deltas_are_signed() {
        let mut base = Report::default();
        base.sections.insert(".text".into(), 1000);
        base.crates.insert("mm".into(), [1000, 0, 0, 0]);
        base.crates.insert("old".into(), [5, 0, 0, 0]);
        base.total = 1000;
        let mut now = Report::default();
        now.sections.insert(".text".into(), 1100);
        now.crates.insert("mm".into(), [1100, 0, 0, 0]);
        now.total = 1100;

        let (text, ok) = render("p", &now, Some(&base), 2);
        assert!(ok, "1,100 bytes fit 2 KiB: {text}");
        assert!(text.contains("+100"), "{text}");
        assert!(text.contains("gone"), "{text}");

        let mut big = now;
        big.total = 1025;
        let (text, ok) = render("p", &big, None, 1);
        assert!(!ok);
        assert!(text.contains("over budget") && text.contains("by 1 bytes"), "{text}");
        let (_, ok) = render("p", &big, None, 0);
        assert!(ok, "0 means no budget");
    }

    #[test]
    fn sections_of_a_real_elf_classify_as_the_linker_laid_them_out() {
        // A tiny ELF64 written by hand: .text (exec), .rodata, .data (write), .bss (nobits),
        // and a non-allocated .comment that must not count.
        let mut elf = vec![0u8; 0x40];
        elf[..4].copy_from_slice(b"\x7fELF");
        elf[4] = 2;
        elf[5] = 1;
        let strtab = b"\0.text\0.rodata\0.data\0.bss\0.comment\0.shstrtab\0";
        let str_off = elf.len() as u64;
        elf.extend_from_slice(strtab);
        let shoff = elf.len() as u64;
        // (name offset, type, flags, size)
        let shdrs: [(u32, u32, u64, u64); 7] = [
            (0, 0, 0, 0),
            (1, 1, 2 | 4, 0x100),
            (7, 1, 2, 0x20),
            (15, 1, 2 | 1, 0x8),
            (21, 8, 2 | 1, 0x4000),
            (26, 1, 0, 0x30),
            (35, 3, 0, strtab.len() as u64),
        ];
        for (i, (name, kind, flags, size)) in shdrs.iter().enumerate() {
            let mut h = vec![0u8; 0x40];
            h[0..4].copy_from_slice(&name.to_le_bytes());
            h[4..8].copy_from_slice(&kind.to_le_bytes());
            h[8..16].copy_from_slice(&flags.to_le_bytes());
            if i == 6 {
                h[0x18..0x20].copy_from_slice(&str_off.to_le_bytes());
            }
            h[0x20..0x28].copy_from_slice(&size.to_le_bytes());
            elf.extend_from_slice(&h);
        }
        elf[0x28..0x30].copy_from_slice(&shoff.to_le_bytes());
        elf[0x3a..0x3c].copy_from_slice(&0x40u16.to_le_bytes());
        elf[0x3c..0x3e].copy_from_slice(&7u16.to_le_bytes());
        elf[0x3e..0x40].copy_from_slice(&6u16.to_le_bytes());

        let s = sections(&elf).unwrap();
        assert_eq!(
            s,
            vec![
                (".text".to_string(), Class::Text, 0x100),
                (".rodata".to_string(), Class::Rodata, 0x20),
                (".data".to_string(), Class::Data, 0x8),
                (".bss".to_string(), Class::Bss, 0x4000),
            ]
        );
        assert!(sections(&elf[..0x20]).is_err());
    }

    #[test]
    fn numbers_are_grouped() {
        assert_eq!(grouped(0), "0");
        assert_eq!(grouped(999), "999");
        assert_eq!(grouped(1000), "1,000");
        assert_eq!(grouped(1234567), "1,234,567");
    }
}

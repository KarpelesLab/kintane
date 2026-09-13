//! Just enough ELF and DWARF to turn an address into a file and line.
//!
//! The pinned `llvm-tools` component has `llvm-nm` and `llvm-objcopy`, but neither
//! `llvm-symbolizer` nor `llvm-addr2line`. Taking either from the host would make a
//! decoded crash report depend on whichever LLVM that machine has installed, and that is
//! the kind of unpinned input the toolchain policy exists to refuse. Function names still
//! come from the pinned `llvm-nm`, because it can demangle v0 symbols. File and line come
//! from here.
//!
//! This reads `.debug_line` only: the line-number program, versions 2 through 5. It does
//! not read `.debug_info`, so it knows the innermost line an address came from but not
//! the chain of inlined calls that led there. `.debug_line` is also the section
//! `llvm-objcopy --only-keep-debug` keeps intact, so this works on the separate symbol
//! bundle and needs no copy of the code.

use std::collections::BTreeMap;

/// One section header, as much of it as a lookup needs.
struct Section {
    name: String,
    offset: usize,
    size: usize,
    /// `SHT_NOBITS`: the header is present but the contents are not in the file.
    nobits: bool,
}

pub struct Elf<'a> {
    data: &'a [u8],
    pub is64: bool,
    pub little: bool,
    sections: Vec<Section>,
}

impl<'a> Elf<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Elf<'a>, String> {
        if data.len() < 0x34 || &data[..4] != b"\x7fELF" {
            return Err("not an ELF file".into());
        }
        let is64 = match data[4] {
            1 => false,
            2 => true,
            c => return Err(format!("unknown ELF class {c}")),
        };
        let little = match data[5] {
            1 => true,
            2 => false,
            e => return Err(format!("unknown ELF data encoding {e}")),
        };
        let mut elf = Elf {
            data,
            is64,
            little,
            sections: Vec::new(),
        };
        let r = Reader::new(data, little);
        let (shoff, shentsize, shnum, shstrndx) = if is64 {
            (
                r.u64_at(0x28)? as usize,
                r.u16_at(0x3a)? as usize,
                r.u16_at(0x3c)? as usize,
                r.u16_at(0x3e)? as usize,
            )
        } else {
            (
                r.u32_at(0x20)? as usize,
                r.u16_at(0x2e)? as usize,
                r.u16_at(0x30)? as usize,
                r.u16_at(0x32)? as usize,
            )
        };

        let mut raw = Vec::new();
        for i in 0..shnum {
            let h = shoff + i * shentsize;
            let (name, kind, offset, size) = if is64 {
                (
                    r.u32_at(h)?,
                    r.u32_at(h + 4)?,
                    r.u64_at(h + 0x18)? as usize,
                    r.u64_at(h + 0x20)? as usize,
                )
            } else {
                (
                    r.u32_at(h)?,
                    r.u32_at(h + 4)?,
                    r.u32_at(h + 0x10)? as usize,
                    r.u32_at(h + 0x14)? as usize,
                )
            };
            raw.push((name as usize, kind, offset, size));
        }
        let strtab = raw
            .get(shstrndx)
            .ok_or("section name table index out of range")?;
        for &(name, kind, offset, size) in &raw {
            const SHT_NOBITS: u32 = 8;
            let nobits = kind == SHT_NOBITS;
            if !nobits && offset.checked_add(size).is_none_or(|e| e > data.len()) {
                return Err("a section extends past the end of the file".into());
            }
            elf.sections.push(Section {
                name: cstr(data, strtab.2 + name).unwrap_or_default(),
                offset,
                size,
                nobits,
            });
        }
        Ok(elf)
    }

    /// A section's contents, if it has any in this file.
    pub fn section(&self, name: &str) -> Option<&'a [u8]> {
        let s = self.sections.iter().find(|s| s.name == name && !s.nobits)?;
        Some(&self.data[s.offset..s.offset + s.size])
    }
}

/// The address ranges one line-number program row covers.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Span {
    start: u64,
    end: u64,
    file: usize,
    line: u32,
}

/// Every row of every line-number program in an image, as sorted address ranges.
#[derive(Debug, Default)]
pub struct LineTable {
    files: Vec<String>,
    spans: Vec<Span>,
}

impl LineTable {
    pub fn from_elf(elf: &Elf) -> Result<LineTable, String> {
        let line = elf
            .section(".debug_line")
            .ok_or("no .debug_line section: was the image built with debug info?")?;
        let sections = Sections {
            line_str: elf.section(".debug_line_str").unwrap_or(&[]),
            str: elf.section(".debug_str").unwrap_or(&[]),
        };
        parse(line, &sections, elf.little, if elf.is64 { 8 } else { 4 })
    }

    /// The file and line an address was compiled from.
    pub fn lookup(&self, addr: u64) -> Option<(&str, u32)> {
        // Last span starting at or below `addr`, then check it actually covers it.
        let i = self.spans.partition_point(|s| s.start <= addr);
        let s = self.spans[..i]
            .iter()
            .rev()
            .take(8)
            .find(|s| addr < s.end)?;
        Some((&self.files[s.file], s.line))
    }
}

/// The string sections a version 5 header's forms may point into.
pub struct Sections<'a> {
    pub line_str: &'a [u8],
    pub str: &'a [u8],
}

/// Parse a whole `.debug_line` section.
pub fn parse(
    data: &[u8],
    strs: &Sections,
    little: bool,
    default_addr_size: u8,
) -> Result<LineTable, String> {
    let mut table = LineTable::default();
    let mut file_ids: BTreeMap<String, usize> = BTreeMap::new();
    let mut pos = 0;
    while pos < data.len() {
        pos = unit(data, pos, strs, little, default_addr_size, &mut table, &mut file_ids)
            .map_err(|e| format!(".debug_line at offset {pos:#x}: {e}"))?;
    }
    table.spans.sort_by_key(|s| (s.start, s.end));
    Ok(table)
}

const DW_LNS_COPY: u8 = 1;
const DW_LNS_ADVANCE_PC: u8 = 2;
const DW_LNS_ADVANCE_LINE: u8 = 3;
const DW_LNS_SET_FILE: u8 = 4;
const DW_LNS_CONST_ADD_PC: u8 = 8;
const DW_LNS_FIXED_ADVANCE_PC: u8 = 9;
const DW_LNE_END_SEQUENCE: u8 = 1;
const DW_LNE_SET_ADDRESS: u8 = 2;
const DW_LNE_DEFINE_FILE: u8 = 3;

/// One line-number program: header, then opcodes. Returns the offset after it.
fn unit(
    data: &[u8],
    start: usize,
    strs: &Sections,
    little: bool,
    default_addr_size: u8,
    table: &mut LineTable,
    file_ids: &mut BTreeMap<String, usize>,
) -> Result<usize, String> {
    let mut r = Reader::new(data, little);
    r.pos = start;
    let (len, offset64) = match r.u32()? {
        0xffff_ffff => (r.u64()? as usize, true),
        n if n >= 0xffff_fff0 => return Err(format!("reserved unit length {n:#x}")),
        n => (n as usize, false),
    };
    let end = r.pos.checked_add(len).filter(|&e| e <= data.len());
    let end = end.ok_or("unit runs past the end of the section")?;
    let version = r.u16()?;
    if !(2..=5).contains(&version) {
        return Err(format!("line table version {version} is not supported"));
    }
    let mut addr_size = default_addr_size;
    if version >= 5 {
        addr_size = r.u8()?;
        let _segment_selector_size = r.u8()?;
    }
    let header_len = if offset64 {
        r.u64()? as usize
    } else {
        r.u32()? as usize
    };
    let program = r
        .pos
        .checked_add(header_len)
        .ok_or("header length overflows")?;
    let min_inst = u64::from(r.u8()?);
    if version >= 4 {
        let _max_ops = r.u8()?;
    }
    let _default_is_stmt = r.u8()?;
    let line_base = r.u8()? as i8;
    let line_range = r.u8()?;
    let opcode_base = r.u8()?;
    if line_range == 0 {
        return Err("line_range is zero".into());
    }
    let mut std_lengths = Vec::new();
    for _ in 1..opcode_base {
        std_lengths.push(r.u8()?);
    }

    // Per-unit file table, mapped to indices in the image-wide one. Version 5 numbers
    // files from 0; earlier versions from 1, with 0 unused.
    let mut files: Vec<usize> = Vec::new();
    let mut intern = |name: String, table: &mut LineTable| -> usize {
        *file_ids.entry(name.clone()).or_insert_with(|| {
            table.files.push(name);
            table.files.len() - 1
        })
    };

    if version >= 5 {
        let dirs = entries(&mut r, strs, offset64)?;
        let dir_names: Vec<String> = dirs.into_iter().map(|e| e.path).collect();
        for f in entries(&mut r, strs, offset64)? {
            let dir = dir_names
                .get(f.dir as usize)
                .map(String::as_str)
                .unwrap_or("");
            files.push(intern(join(dir, &f.path), table));
        }
    } else {
        let mut dirs = vec![String::new()];
        loop {
            let d = r.cstr()?;
            if d.is_empty() {
                break;
            }
            dirs.push(d);
        }
        files.push(intern(String::from("<file 0>"), table));
        loop {
            let name = r.cstr()?;
            if name.is_empty() {
                break;
            }
            let dir = r.uleb()? as usize;
            let _mtime = r.uleb()?;
            let _size = r.uleb()?;
            let d = dirs.get(dir).map(String::as_str).unwrap_or("");
            files.push(intern(join(d, &name), table));
        }
    }

    r.pos = program;
    // The state machine's initial registers, restored after each sequence.
    let (mut addr, mut file, mut line) = (0u64, 1u64, 1i64);
    // The previous row of the current sequence: its address, file and line.
    let mut prev: Option<(u64, usize, u32)> = None;
    let resolve =
        |files: &[usize], f: u64| -> usize { files.get(f as usize).copied().unwrap_or(0) };
    let emit = |addr: u64,
                file: usize,
                line: i64,
                prev: &mut Option<(u64, usize, u32)>,
                table: &mut LineTable| {
        if let Some((pa, pf, pl)) = *prev {
            if addr > pa {
                table.spans.push(Span {
                    start: pa,
                    end: addr,
                    file: pf,
                    line: pl,
                });
            }
        }
        // Line 0 means the compiler could not attribute the code to any line. Such code
        // still belongs to whatever came before it in the sequence, and "file:0" in a
        // backtrace tells the reader nothing, so it inherits the previous row's line.
        let row = match (*prev, u32::try_from(line).unwrap_or(0)) {
            (Some((_, pf, pl)), 0) if pl != 0 => (pf, pl),
            (_, l) => (file, l),
        };
        *prev = Some((addr, row.0, row.1));
    };

    while r.pos < end {
        let op = r.u8()?;
        if op >= opcode_base {
            let adj = op - opcode_base;
            addr = addr.wrapping_add(u64::from(adj / line_range) * min_inst);
            line += i64::from(line_base) + i64::from(adj % line_range);
            emit(addr, resolve(&files, file), line, &mut prev, table);
            continue;
        }
        match op {
            0 => {
                let len = r.uleb()? as usize;
                let next = r
                    .pos
                    .checked_add(len)
                    .ok_or("extended opcode length overflows")?;
                if len == 0 {
                    continue;
                }
                match r.u8()? {
                    DW_LNE_END_SEQUENCE => {
                        emit(addr, resolve(&files, file), line, &mut prev, table);
                        prev = None;
                        (addr, file, line) = (0, 1, 1);
                    }
                    DW_LNE_SET_ADDRESS => {
                        addr = match len - 1 {
                            8 => r.u64()?,
                            4 => u64::from(r.u32()?),
                            n => {
                                return Err(format!("address of {n} bytes (expected {addr_size})"));
                            }
                        };
                    }
                    DW_LNE_DEFINE_FILE => {
                        let name = r.cstr()?;
                        files.push(intern(name, table));
                    }
                    _ => {}
                }
                r.pos = next;
            }
            DW_LNS_COPY => emit(addr, resolve(&files, file), line, &mut prev, table),
            DW_LNS_ADVANCE_PC => addr = addr.wrapping_add(r.uleb()? * min_inst),
            DW_LNS_ADVANCE_LINE => line += r.sleb()?,
            DW_LNS_SET_FILE => file = r.uleb()?,
            DW_LNS_CONST_ADD_PC => {
                addr = addr.wrapping_add(u64::from((255 - opcode_base) / line_range) * min_inst)
            }
            DW_LNS_FIXED_ADVANCE_PC => addr = addr.wrapping_add(u64::from(r.u16()?)),
            // Everything else — column, statement flags, ISA — does not change which
            // line an address belongs to. Skip its operands by the count the header gave.
            _ => {
                let n = std_lengths.get(op as usize - 1).copied().unwrap_or(0);
                for _ in 0..n {
                    r.uleb()?;
                }
            }
        }
    }
    Ok(end)
}

struct Entry {
    path: String,
    dir: u64,
}

/// A version 5 directory or file table: a format description, then entries.
fn entries(r: &mut Reader, strs: &Sections, offset64: bool) -> Result<Vec<Entry>, String> {
    const DW_LNCT_PATH: u64 = 1;
    const DW_LNCT_DIRECTORY_INDEX: u64 = 2;
    let format_count = r.u8()?;
    let mut format = Vec::new();
    for _ in 0..format_count {
        format.push((r.uleb()?, r.uleb()?));
    }
    let count = r.uleb()?;
    let mut out = Vec::new();
    for _ in 0..count {
        let mut e = Entry {
            path: String::new(),
            dir: 0,
        };
        for &(kind, form) in &format {
            let v = form_value(r, form, strs, offset64)?;
            match (kind, v) {
                (DW_LNCT_PATH, Value::Str(s)) => e.path = s,
                (DW_LNCT_DIRECTORY_INDEX, Value::Int(n)) => e.dir = n,
                _ => {}
            }
        }
        out.push(e);
    }
    Ok(out)
}

enum Value {
    Str(String),
    Int(u64),
    Other,
}

fn form_value(r: &mut Reader, form: u64, strs: &Sections, offset64: bool) -> Result<Value, String> {
    let offset = |r: &mut Reader| -> Result<usize, String> {
        Ok(if offset64 {
            r.u64()? as usize
        } else {
            r.u32()? as usize
        })
    };
    Ok(match form {
        0x08 => Value::Str(r.cstr()?), // string
        0x1f => Value::Str(cstr(strs.line_str, offset(r)?).unwrap_or_default()), // line_strp
        0x0e => Value::Str(cstr(strs.str, offset(r)?).unwrap_or_default()), // strp
        0x0b => Value::Int(u64::from(r.u8()?)), // data1
        0x05 => Value::Int(u64::from(r.u16()?)), // data2
        0x06 => Value::Int(u64::from(r.u32()?)), // data4
        0x07 => Value::Int(r.u64()?),  // data8
        0x0f => Value::Int(r.uleb()?), // udata
        0x1e => {
            r.take(16)?; // data16, an MD5
            Value::Other
        }
        0x09 => {
            let n = r.uleb()? as usize; // block
            r.take(n)?;
            Value::Other
        }
        f => return Err(format!("unsupported form {f:#x} in a file table")),
    })
}

fn join(dir: &str, name: &str) -> String {
    if dir.is_empty() || name.starts_with('/') {
        name.to_string()
    } else {
        format!("{dir}/{name}")
    }
}

fn cstr(data: &[u8], at: usize) -> Option<String> {
    let rest = data.get(at..)?;
    let n = rest.iter().position(|&b| b == 0)?;
    Some(String::from_utf8_lossy(&rest[..n]).into_owned())
}

/// A cursor over bytes of one endianness that reports running off the end.
struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
    little: bool,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8], little: bool) -> Self {
        Reader {
            data,
            pos: 0,
            little,
        }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        let s = self
            .pos
            .checked_add(n)
            .and_then(|e| self.data.get(self.pos..e))
            .ok_or("truncated")?;
        self.pos += n;
        Ok(s)
    }

    fn uint(&mut self, n: usize) -> Result<u64, String> {
        let b = self.take(n)?;
        let mut v = 0u64;
        for i in 0..n {
            let byte = if self.little { b[n - 1 - i] } else { b[i] };
            v = (v << 8) | u64::from(byte);
        }
        Ok(v)
    }

    fn u8(&mut self) -> Result<u8, String> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, String> {
        Ok(self.uint(2)? as u16)
    }
    fn u32(&mut self) -> Result<u32, String> {
        Ok(self.uint(4)? as u32)
    }
    fn u64(&mut self) -> Result<u64, String> {
        self.uint(8)
    }

    fn at(&self, pos: usize, n: usize) -> Result<u64, String> {
        let mut r = Reader::new(self.data, self.little);
        r.pos = pos;
        r.uint(n)
    }
    fn u16_at(&self, pos: usize) -> Result<u16, String> {
        Ok(self.at(pos, 2)? as u16)
    }
    fn u32_at(&self, pos: usize) -> Result<u32, String> {
        Ok(self.at(pos, 4)? as u32)
    }
    fn u64_at(&self, pos: usize) -> Result<u64, String> {
        self.at(pos, 8)
    }

    fn uleb(&mut self) -> Result<u64, String> {
        let mut v = 0u64;
        let mut shift = 0;
        loop {
            let b = self.u8()?;
            if shift < 64 {
                v |= u64::from(b & 0x7f) << shift;
            }
            shift += 7;
            if b & 0x80 == 0 {
                return Ok(v);
            }
        }
    }

    fn sleb(&mut self) -> Result<i64, String> {
        let mut v = 0i64;
        let mut shift = 0;
        loop {
            let b = self.u8()?;
            if shift < 64 {
                v |= i64::from(b & 0x7f) << shift;
            }
            shift += 7;
            if b & 0x80 == 0 {
                if shift < 64 && b & 0x40 != 0 {
                    v |= -1i64 << shift;
                }
                return Ok(v);
            }
        }
    }

    fn cstr(&mut self) -> Result<String, String> {
        let s = cstr(self.data, self.pos).ok_or("unterminated string")?;
        self.pos += s.len() + 1;
        Ok(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn uleb(mut v: u64, out: &mut Vec<u8>) {
        loop {
            let b = (v & 0x7f) as u8;
            v >>= 7;
            if v == 0 {
                out.push(b);
                return;
            }
            out.push(b | 0x80);
        }
    }

    /// The opcodes both test programs share: two rows in `file`, then the end.
    ///
    /// 0x1000 line 10, 0x1004 line 12, sequence ends at 0x1010.
    fn program(file: u64, out: &mut Vec<u8>) {
        out.extend([0, 9, DW_LNE_SET_ADDRESS]);
        out.extend(0x1000u64.to_le_bytes());
        out.push(DW_LNS_SET_FILE);
        uleb(file, out);
        out.push(DW_LNS_ADVANCE_LINE);
        uleb(9, out); // line 1 -> 10
        out.push(DW_LNS_COPY);
        // Special opcode: address += 4, line += 2. With line_base -5, line_range 14,
        // opcode_base 13: (2 - -5) + 14 * 4 + 13 = 76.
        out.push(76);
        out.push(DW_LNS_ADVANCE_PC);
        uleb(12, out);
        out.extend([0, 1, DW_LNE_END_SEQUENCE]);
    }

    /// Standard header fields after `header_length`: min_inst 1, max_ops 1,
    /// default_is_stmt 1, line_base -5, line_range 14, opcode_base 13.
    fn common_fields(out: &mut Vec<u8>) {
        out.extend([1, 1, 1, (-5i8) as u8, 14, 13]);
        out.extend([0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1]);
    }

    fn wrap(version: u16, pre: &[u8], header: &[u8], prog: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend(version.to_le_bytes());
        body.extend(pre);
        body.extend((header.len() as u32).to_le_bytes());
        body.extend(header);
        body.extend(prog);
        let mut unit = (body.len() as u32).to_le_bytes().to_vec();
        unit.extend(body);
        unit
    }

    fn check(t: &LineTable) {
        assert_eq!(t.lookup(0x0fff), None);
        assert_eq!(t.lookup(0x1000), Some(("kernel/main/src/crash.rs", 10)));
        assert_eq!(t.lookup(0x1003), Some(("kernel/main/src/crash.rs", 10)));
        assert_eq!(t.lookup(0x1004), Some(("kernel/main/src/crash.rs", 12)));
        assert_eq!(t.lookup(0x100f), Some(("kernel/main/src/crash.rs", 12)));
        assert_eq!(t.lookup(0x1010), None, "end_sequence is exclusive");
    }

    #[test]
    fn version_4() {
        let mut h = Vec::new();
        common_fields(&mut h);
        h.extend(b"kernel/main/src\0\0");
        h.extend(b"crash.rs\0");
        h.extend([1, 0, 0]); // dir 1, mtime, size
        h.push(0);
        let mut p = Vec::new();
        program(1, &mut p);
        let data = wrap(4, &[], &h, &p);
        let strs = Sections {
            line_str: &[],
            str: &[],
        };
        check(&parse(&data, &strs, true, 8).unwrap());
    }

    #[test]
    fn version_5_with_line_strp() {
        // .debug_line_str: "kernel/main/src\0crash.rs\0"
        let line_str = b"kernel/main/src\0crash.rs\0";
        let mut h = Vec::new();
        common_fields(&mut h);
        // Directories: one format (path, line_strp), two entries.
        h.push(1);
        h.extend([1, 0x1f]);
        h.push(2);
        h.extend(0u32.to_le_bytes()); // comp dir; reuse the same string
        h.extend(0u32.to_le_bytes());
        // Files: (path, line_strp), (directory_index, udata), (MD5, data16).
        h.push(3);
        h.extend([1, 0x1f, 2, 0x0f, 5, 0x1e]);
        h.push(2);
        for _ in 0..2 {
            h.extend(16u32.to_le_bytes());
            h.push(1);
            h.extend([0xaa; 16]);
        }
        let mut p = Vec::new();
        program(1, &mut p);
        let data = wrap(5, &[8, 0], &h, &p);
        let strs = Sections { line_str, str: &[] };
        check(&parse(&data, &strs, true, 8).unwrap());
    }

    #[test]
    fn a_truncated_unit_is_an_error_not_a_panic() {
        let mut h = Vec::new();
        common_fields(&mut h);
        let data = wrap(4, &[], &h, &[]);
        let strs = Sections {
            line_str: &[],
            str: &[],
        };
        for cut in 1..data.len() {
            let _ = parse(&data[..cut], &strs, true, 8);
        }
    }

    #[test]
    fn line_zero_inherits_the_line_before_it() {
        let mut h = Vec::new();
        common_fields(&mut h);
        h.extend(b"\0crash.rs\0\0\0\0\0");
        let mut p = Vec::new();
        p.extend([0, 9, DW_LNE_SET_ADDRESS]);
        p.extend(0x1000u64.to_le_bytes());
        p.push(DW_LNS_ADVANCE_LINE);
        uleb(9, &mut p); // line 10
        p.push(DW_LNS_COPY);
        p.push(DW_LNS_ADVANCE_PC);
        uleb(4, &mut p);
        p.extend([DW_LNS_ADVANCE_LINE, 0x76]); // sleb -10: line 0
        p.push(DW_LNS_COPY);
        p.push(DW_LNS_ADVANCE_PC);
        uleb(4, &mut p);
        p.extend([0, 1, DW_LNE_END_SEQUENCE]);
        let data = wrap(4, &[], &h, &p);
        let strs = Sections {
            line_str: &[],
            str: &[],
        };
        let t = parse(&data, &strs, true, 8).unwrap();
        assert_eq!(t.lookup(0x1001), Some(("crash.rs", 10)));
        assert_eq!(t.lookup(0x1005), Some(("crash.rs", 10)));
    }

    #[test]
    fn unsupported_versions_are_named() {
        let data = wrap(6, &[], &[], &[]);
        let strs = Sections {
            line_str: &[],
            str: &[],
        };
        let e = parse(&data, &strs, true, 8).unwrap_err();
        assert!(e.contains("version 6"), "{e}");
    }
}

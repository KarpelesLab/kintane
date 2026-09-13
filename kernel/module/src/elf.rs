//! Reading a relocatable ELF64 object.
//!
//! Everything a module file says is untrusted: it may be truncated, hand-edited, or built
//! for another machine. Every offset and size is checked against the file before a byte is
//! read through it, every count is bounded by the bytes that would hold it, and a failure
//! is an [`Error`] naming where it happened. Nothing here panics on any input, which the
//! host tests check by corrupting a real module one byte at a time.
//!
//! Only what the loader needs is read: the file header, the section headers, symbols and
//! `RELA` entries. Little-endian only, since every target that loads modules today is.

/// `e_machine` for x86-64.
pub const EM_X86_64: u16 = 62;
/// `e_machine` for AArch64.
pub const EM_AARCH64: u16 = 183;

/// Section types the loader distinguishes.
pub const SHT_PROGBITS: u32 = 1;
pub const SHT_SYMTAB: u32 = 2;
pub const SHT_RELA: u32 = 4;
pub const SHT_NOBITS: u32 = 8;
pub const SHT_REL: u32 = 9;

/// Section flags.
pub const SHF_WRITE: u64 = 0x1;
pub const SHF_ALLOC: u64 = 0x2;
pub const SHF_EXECINSTR: u64 = 0x4;
pub const SHF_TLS: u64 = 0x400;

/// Special section indices a symbol may carry.
pub const SHN_UNDEF: u16 = 0;
pub const SHN_ABS: u16 = 0xfff1;
pub const SHN_COMMON: u16 = 0xfff2;

/// Symbol bindings.
pub const STB_LOCAL: u8 = 0;

const EHDR_LEN: usize = 64;
const SHDR_LEN: usize = 64;
const SYM_LEN: usize = 24;
const RELA_LEN: usize = 24;
const ET_REL: u16 = 1;

/// Why an object could not be read.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Error {
    /// Shorter than an ELF header.
    TooShort,
    /// Not `\x7fELF`, not 64-bit, not little-endian, or not ELF version 1.
    NotElf64Le,
    /// An ELF file, but not a relocatable object.
    NotRelocatable { e_type: u16 },
    /// A header field that cannot be true, such as a section header size other than 64.
    BadHeader,
    /// A section header, or the data it describes, lies outside the file.
    SectionOutOfFile { index: usize },
    /// A string table index or offset that does not reach a terminated string.
    BadString { offset: u64 },
    /// A section index out of range.
    NoSuchSection { index: usize },
    /// A section's entry size does not match its type.
    BadEntrySize { index: usize },
}

/// A validated relocatable object, borrowing the file.
#[derive(Clone, Copy, Debug)]
pub struct Object<'a> {
    bytes: &'a [u8],
    machine: u16,
    shoff: usize,
    shnum: usize,
    shstrndx: usize,
}

/// One section header, as the file gives it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Section {
    pub index: usize,
    pub name: u32,
    pub kind: u32,
    pub flags: u64,
    pub offset: u64,
    pub size: u64,
    pub link: u32,
    pub info: u32,
    pub align: u64,
    pub entsize: u64,
}

impl Section {
    pub fn is_alloc(&self) -> bool {
        self.flags & SHF_ALLOC != 0
    }
}

/// One symbol table entry.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Symbol {
    pub name: u32,
    pub info: u8,
    pub shndx: u16,
    pub value: u64,
    pub size: u64,
}

impl Symbol {
    pub fn binding(&self) -> u8 {
        self.info >> 4
    }
    pub fn kind(&self) -> u8 {
        self.info & 0xf
    }
}

/// One `RELA` entry.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Rela {
    pub offset: u64,
    pub symbol: u32,
    pub kind: u32,
    pub addend: i64,
}

fn u16_at(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(at..at.checked_add(2)?)?.try_into().ok()?))
}
fn u32_at(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(at..at.checked_add(4)?)?.try_into().ok()?))
}
fn u64_at(b: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(b.get(at..at.checked_add(8)?)?.try_into().ok()?))
}

impl<'a> Object<'a> {
    /// Validate the file header and the section header table's place in the file.
    pub fn parse(bytes: &'a [u8]) -> Result<Object<'a>, Error> {
        if bytes.len() < EHDR_LEN {
            return Err(Error::TooShort);
        }
        // Class 2 (64-bit), data 1 (little-endian), version 1.
        if bytes[..4] != *b"\x7fELF" || bytes[4] != 2 || bytes[5] != 1 || bytes[6] != 1 {
            return Err(Error::NotElf64Le);
        }
        let field16 = |at| u16_at(bytes, at).ok_or(Error::TooShort);
        let e_type = field16(16)?;
        if e_type != ET_REL {
            return Err(Error::NotRelocatable { e_type });
        }
        let machine = field16(18)?;
        let shoff = u64_at(bytes, 40).ok_or(Error::TooShort)?;
        let shentsize = field16(58)?;
        let shnum = field16(60)? as usize;
        let shstrndx = field16(62)? as usize;
        if shentsize as usize != SHDR_LEN || shnum == 0 || shstrndx >= shnum {
            return Err(Error::BadHeader);
        }
        let shoff = usize::try_from(shoff).map_err(|_| Error::BadHeader)?;
        let end = shnum
            .checked_mul(SHDR_LEN)
            .and_then(|n| n.checked_add(shoff))
            .ok_or(Error::BadHeader)?;
        if end > bytes.len() {
            return Err(Error::SectionOutOfFile { index: 0 });
        }
        Ok(Object {
            bytes,
            machine,
            shoff,
            shnum,
            shstrndx,
        })
    }

    pub fn machine(&self) -> u16 {
        self.machine
    }

    pub fn section_count(&self) -> usize {
        self.shnum
    }

    /// Section header `index`. The data it describes is checked when it is read.
    pub fn section(&self, index: usize) -> Result<Section, Error> {
        if index >= self.shnum {
            return Err(Error::NoSuchSection { index });
        }
        let at = self.shoff + index * SHDR_LEN;
        let b = self.bytes;
        let bad = Error::SectionOutOfFile { index };
        Ok(Section {
            index,
            name: u32_at(b, at).ok_or(bad)?,
            kind: u32_at(b, at + 4).ok_or(bad)?,
            flags: u64_at(b, at + 8).ok_or(bad)?,
            offset: u64_at(b, at + 24).ok_or(bad)?,
            size: u64_at(b, at + 32).ok_or(bad)?,
            link: u32_at(b, at + 40).ok_or(bad)?,
            info: u32_at(b, at + 44).ok_or(bad)?,
            align: u64_at(b, at + 48).ok_or(bad)?,
            entsize: u64_at(b, at + 56).ok_or(bad)?,
        })
    }

    pub fn sections(&self) -> impl Iterator<Item = Result<Section, Error>> + '_ {
        (0..self.shnum).map(|i| self.section(i))
    }

    /// The bytes a section occupies in the file. Empty for `NOBITS`, which occupies none.
    pub fn data(&self, s: &Section) -> Result<&'a [u8], Error> {
        if s.kind == SHT_NOBITS {
            return Ok(&[]);
        }
        let bad = Error::SectionOutOfFile { index: s.index };
        let start = usize::try_from(s.offset).map_err(|_| bad)?;
        let len = usize::try_from(s.size).map_err(|_| bad)?;
        let end = start.checked_add(len).ok_or(bad)?;
        self.bytes.get(start..end).ok_or(bad)
    }

    /// A NUL-terminated string at `offset` in string table section `table`.
    pub fn string(&self, table: usize, offset: u32) -> Result<&'a [u8], Error> {
        let s = self.section(table)?;
        let data = self.data(&s)?;
        let rest = data.get(offset as usize..).ok_or(Error::BadString {
            offset: offset as u64,
        })?;
        let end = rest.iter().position(|&c| c == 0).ok_or(Error::BadString {
            offset: offset as u64,
        })?;
        Ok(&rest[..end])
    }

    pub fn section_name(&self, s: &Section) -> Result<&'a [u8], Error> {
        self.string(self.shstrndx, s.name)
    }

    /// The first section with this name.
    pub fn section_by_name(&self, name: &str) -> Result<Option<Section>, Error> {
        for s in self.sections() {
            let s = s?;
            if self.section_name(&s)? == name.as_bytes() {
                return Ok(Some(s));
            }
        }
        Ok(None)
    }

    /// The symbol table. An object has at most one; `None` when it has none.
    pub fn symtab(&self) -> Result<Option<Section>, Error> {
        for s in self.sections() {
            let s = s?;
            if s.kind == SHT_SYMTAB {
                if s.entsize as usize != SYM_LEN || s.size % SYM_LEN as u64 != 0 {
                    return Err(Error::BadEntrySize { index: s.index });
                }
                // The table's own bytes and its string table must both be in the file.
                self.data(&s)?;
                self.section(s.link as usize)?;
                return Ok(Some(s));
            }
        }
        Ok(None)
    }

    /// Entry `index` of symbol table `symtab`, or `None` past its end.
    pub fn symbol(&self, symtab: &Section, index: usize) -> Result<Option<Symbol>, Error> {
        let data = self.data(symtab)?;
        let Some(at) = index.checked_mul(SYM_LEN) else {
            return Ok(None);
        };
        let Some(e) = data.get(at..at.saturating_add(SYM_LEN)) else {
            return Ok(None);
        };
        if e.len() != SYM_LEN {
            return Ok(None);
        }
        Ok(Some(Symbol {
            name: u32_at(e, 0).unwrap_or(0),
            info: e[4],
            shndx: u16_at(e, 6).unwrap_or(0),
            value: u64_at(e, 8).unwrap_or(0),
            size: u64_at(e, 16).unwrap_or(0),
        }))
    }

    pub fn symbol_count(&self, symtab: &Section) -> usize {
        (symtab.size / SYM_LEN as u64) as usize
    }

    pub fn symbol_name(&self, symtab: &Section, sym: &Symbol) -> Result<&'a [u8], Error> {
        self.string(symtab.link as usize, sym.name)
    }

    /// The entries of `RELA` section `rela`.
    pub fn relas(&self, rela: &Section) -> Result<impl Iterator<Item = Rela> + 'a, Error> {
        if rela.entsize as usize != RELA_LEN || rela.size % RELA_LEN as u64 != 0 {
            return Err(Error::BadEntrySize { index: rela.index });
        }
        let data = self.data(rela)?;
        Ok(data.chunks_exact(RELA_LEN).map(|e| {
            let info = u64_at(e, 8).unwrap_or(0);
            Rela {
                offset: u64_at(e, 0).unwrap_or(0),
                symbol: (info >> 32) as u32,
                kind: info as u32,
                addend: u64_at(e, 16).unwrap_or(0) as i64,
            }
        }))
    }
}

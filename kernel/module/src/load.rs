//! Loading a module: from a validated object to relocated bytes and entry points.
//!
//! The steps are `docs/modules.md`'s, in its order, each refusing with a [`LoadError`] that
//! names what was wrong:
//!
//! 1. The object is for this kernel's machine.
//! 2. Its build identity is this kernel's ([`crate::identity`]).
//! 3. Every symbol it leaves undefined is one the kernel exports, recorded in its imports section
//!    with the hash the kernel exports it under.
//! 4. Its allocated sections are laid out into three regions: text, read-only data and writable
//!    data. Each region gets the protection it needs from the caller afterwards.
//! 5. The caller supplies memory for the regions ([`Memory`]), writable for now, and the sections
//!    are copied in.
//! 6. Every relocation is applied.
//! 7. The entry points are found.
//!
//! Dependencies between modules, parameters and driver tables from the design are not here
//! yet; a module that needs another module's symbols is refused at step 3, by name.

use crate::elf::{self, Object, SHF_EXECINSTR, SHF_TLS, SHF_WRITE, SHN_ABS, SHN_COMMON, SHN_UNDEF};
use crate::identity::{self, Identity, Mismatch};
use crate::interface::{Export, ImportRecord};
use crate::reloc::{self, RelocError};
use crate::{EXIT_SYMBOL, IDENTITY_SECTION, IMPORTS_SECTION, INIT_SYMBOL};

/// Where a section is placed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Region {
    /// Executable, never writable once sealed.
    Text = 0,
    /// Readable only.
    Rodata = 1,
    /// Readable and writable, never executable. `.bss` included.
    Data = 2,
}

impl Region {
    pub const ALL: [Region; 3] = [Region::Text, Region::Rodata, Region::Data];

    fn of(flags: u64) -> Region {
        if flags & SHF_EXECINSTR != 0 {
            Region::Text
        } else if flags & SHF_WRITE != 0 {
            Region::Data
        } else {
            Region::Rodata
        }
    }
}

/// One section's place: its region and its offset within it. `None` for a section that is
/// not loaded.
pub type Placement = Option<(Region, u64)>;

/// What the kernel offers a module.
#[derive(Clone, Copy, Debug)]
pub struct Kernel<'k> {
    /// The ELF machine this kernel runs.
    pub machine: u16,
    pub identity_hash: &'k [u8; 32],
    pub identity_text: &'k str,
    pub exports: &'k [Export],
}

/// Memory for a module's three regions.
pub trait Memory {
    /// Make `sizes[r]` bytes available for each region, readable and writable, and zeroed.
    /// A zero size needs no memory. Returns each region's address.
    fn allocate(&mut self, sizes: [u64; 3]) -> Result<[u64; 3], LoadError<'static>>;

    /// The bytes of region `r`, as allocated.
    fn bytes(&mut self, r: Region) -> &mut [u8];
}

/// A module, loaded.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Loaded {
    /// Each region's address and size.
    pub regions: [(u64, u64); 3],
    pub init: u64,
    pub exit: Option<u64>,
    pub relocations: usize,
}

/// Why a module was refused.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LoadError<'a> {
    Elf(elf::Error),
    /// Built for another machine.
    WrongMachine {
        module: u16,
        kernel: u16,
    },
    /// Not built for this kernel.
    Identity(Mismatch<'a>),
    /// No symbol table, or no identity section.
    Incomplete(&'static str),
    /// An undefined symbol the kernel does not export.
    Unexported {
        name: &'a [u8],
    },
    /// An undefined symbol the module's imports section does not record.
    Undeclared {
        name: &'a [u8],
    },
    /// An import whose interface is not the kernel's.
    InterfaceMismatch {
        name: &'a [u8],
        module: u64,
        kernel: u64,
    },
    /// A feature the loader refuses: thread-local storage, common symbols, `REL` without
    /// addends.
    Unsupported(&'static str),
    Reloc(RelocError),
    /// A relocation or symbol refers to something that does not exist.
    BadReference,
    /// More sections than the caller's placement table holds, or regions too large.
    TooLarge,
    /// No `kt_module_init` defined in the module's text.
    NoInit,
    /// The caller could not supply memory.
    OutOfMemory,
}

impl From<elf::Error> for LoadError<'_> {
    fn from(e: elf::Error) -> Self {
        LoadError::Elf(e)
    }
}

/// The most a module's regions may occupy, together.
pub const MAX_BYTES: u64 = 64 * 1024 * 1024;

/// Check and load `bytes` into `mem`. `placements` needs one slot per section.
pub fn load<'a, M: Memory>(
    bytes: &'a [u8],
    kernel: &Kernel<'a>,
    placements: &mut [Placement],
    mem: &mut M,
) -> Result<Loaded, LoadError<'a>> {
    let obj = Object::parse(bytes)?;
    if obj.machine() != kernel.machine {
        return Err(LoadError::WrongMachine {
            module: obj.machine(),
            kernel: kernel.machine,
        });
    }

    let identity = obj
        .section_by_name(IDENTITY_SECTION)?
        .ok_or(LoadError::Incomplete("no identity section"))?;
    identity::check(
        Identity::parse(obj.data(&identity)?),
        kernel.identity_hash,
        kernel.identity_text,
    )
    .map_err(LoadError::Identity)?;

    let symtab = obj
        .symtab()?
        .ok_or(LoadError::Incomplete("no symbol table"))?;
    check_imports(&obj, &symtab, kernel)?;

    let sizes = layout(&obj, placements)?;
    let bases = mem.allocate(sizes).map_err(|_| LoadError::OutOfMemory)?;
    copy(&obj, placements, mem)?;
    let relocations = relocate(&obj, &symtab, placements, &bases, kernel, mem)?;

    let entry = |name: &str| -> Result<Option<u64>, LoadError<'a>> {
        for i in 1..obj.symbol_count(&symtab) {
            let Some(sym) = obj.symbol(&symtab, i)? else {
                break;
            };
            if sym.shndx == SHN_UNDEF || obj.symbol_name(&symtab, &sym)? != name.as_bytes() {
                continue;
            }
            let Some(Some((Region::Text, at))) = placements.get(sym.shndx as usize).copied() else {
                return Err(LoadError::BadReference);
            };
            return Ok(Some(bases[Region::Text as usize] + at + sym.value));
        }
        Ok(None)
    };
    let init = entry(INIT_SYMBOL)?.ok_or(LoadError::NoInit)?;
    let exit = entry(EXIT_SYMBOL)?;

    Ok(Loaded {
        regions: [
            (bases[0], sizes[0]),
            (bases[1], sizes[1]),
            (bases[2], sizes[2]),
        ],
        init,
        exit,
        relocations,
    })
}

/// Step 3: every undefined symbol exported, declared, and of the same interface.
fn check_imports<'a>(
    obj: &Object<'a>,
    symtab: &elf::Section,
    kernel: &Kernel<'_>,
) -> Result<(), LoadError<'a>> {
    let records = match obj.section_by_name(IMPORTS_SECTION)? {
        Some(s) => obj.data(&s)?,
        None => &[],
    };
    for i in 1..obj.symbol_count(symtab) {
        let Some(sym) = obj.symbol(symtab, i)? else {
            break;
        };
        if sym.shndx == SHN_COMMON {
            return Err(LoadError::Unsupported("common symbols"));
        }
        if sym.shndx != SHN_UNDEF || sym.binding() == elf::STB_LOCAL {
            continue;
        }
        let name = obj.symbol_name(symtab, &sym)?;
        if name.is_empty() {
            continue;
        }
        let export = kernel
            .exports
            .iter()
            .find(|e| e.name.as_bytes() == name)
            .ok_or(LoadError::Unexported { name })?;
        let record = records
            .chunks_exact(ImportRecord::SIZE)
            .filter_map(ImportRecord::read)
            .find(|r| r.name() == name)
            .ok_or(LoadError::Undeclared { name })?;
        if record.hash != export.hash {
            return Err(LoadError::InterfaceMismatch {
                name,
                module: record.hash,
                kernel: export.hash,
            });
        }
    }
    Ok(())
}

/// Step 4: place every allocated section, and size the regions.
fn layout(obj: &Object<'_>, placements: &mut [Placement]) -> Result<[u64; 3], LoadError<'static>> {
    if placements.len() < obj.section_count() {
        return Err(LoadError::TooLarge);
    }
    let mut sizes = [0u64; 3];
    for s in obj.sections() {
        let s = s?;
        placements[s.index] = None;
        if !s.is_alloc() || s.size == 0 {
            continue;
        }
        if s.flags & SHF_TLS != 0 {
            return Err(LoadError::Unsupported("thread-local storage"));
        }
        let r = Region::of(s.flags);
        let align = s.align.max(1);
        if !align.is_power_of_two() || align > 1 << 21 {
            return Err(LoadError::Elf(elf::Error::BadHeader));
        }
        let at = sizes[r as usize]
            .checked_next_multiple_of(align)
            .ok_or(LoadError::TooLarge)?;
        let end = at.checked_add(s.size).ok_or(LoadError::TooLarge)?;
        if end > MAX_BYTES {
            return Err(LoadError::TooLarge);
        }
        placements[s.index] = Some((r, at));
        sizes[r as usize] = end;
    }
    if sizes.iter().sum::<u64>() > MAX_BYTES {
        return Err(LoadError::TooLarge);
    }
    Ok(sizes)
}

/// Step 5: copy section contents. `NOBITS` stays as allocated, which is zeroed.
fn copy<M: Memory>(
    obj: &Object<'_>,
    placements: &[Placement],
    mem: &mut M,
) -> Result<(), LoadError<'static>> {
    for s in obj.sections() {
        let s = s?;
        let Some((r, at)) = placements[s.index] else {
            continue;
        };
        if s.kind == elf::SHT_NOBITS {
            continue;
        }
        let data = obj.data(&s)?;
        let at = at as usize;
        mem.bytes(r)
            .get_mut(at..at + data.len())
            .ok_or(LoadError::TooLarge)?
            .copy_from_slice(data);
    }
    Ok(())
}

/// Step 6: apply every relocation against a loaded section.
fn relocate<'a, M: Memory>(
    obj: &Object<'a>,
    symtab: &elf::Section,
    placements: &[Placement],
    bases: &[u64; 3],
    kernel: &Kernel<'_>,
    mem: &mut M,
) -> Result<usize, LoadError<'a>> {
    let mut count = 0;
    for s in obj.sections() {
        let s = s?;
        if s.kind == elf::SHT_REL {
            return Err(LoadError::Unsupported("REL relocations without addends"));
        }
        if s.kind != elf::SHT_RELA {
            continue;
        }
        // Relocations for a section that is not loaded, such as debug information, are
        // not needed.
        let Some(Some((target_region, target_at))) = placements.get(s.info as usize).copied()
        else {
            continue;
        };
        if s.link as usize != symtab.index {
            return Err(LoadError::BadReference);
        }
        let target = obj.section(s.info as usize)?;
        let section_addr = bases[target_region as usize] + target_at;
        for rela in obj.relas(&s)? {
            let sym = obj
                .symbol(symtab, rela.symbol as usize)?
                .ok_or(LoadError::BadReference)?;
            let value = match sym.shndx {
                SHN_UNDEF => {
                    let name = obj.symbol_name(symtab, &sym)?;
                    kernel
                        .exports
                        .iter()
                        .find(|e| e.name.as_bytes() == name)
                        .ok_or(LoadError::Unexported { name })?
                        .addr as u64
                }
                SHN_ABS => sym.value,
                index => {
                    let Some(Some((r, at))) = placements.get(index as usize).copied() else {
                        return Err(LoadError::BadReference);
                    };
                    bases[r as usize] + at + sym.value
                }
            };
            // Only the target section's own bytes: `reloc::apply` refuses a place outside
            // them, so a relocation cannot reach into the section laid out next to it.
            let start = target_at as usize;
            let end = start + target.size as usize;
            let bytes = mem
                .bytes(target_region)
                .get_mut(start..end)
                .ok_or(LoadError::TooLarge)?;
            reloc::apply(
                obj.machine(),
                rela.kind,
                bytes,
                section_addr,
                rela.offset,
                value,
                rela.addend,
            )
            .map_err(LoadError::Reloc)?;
            count += 1;
        }
    }
    Ok(count)
}

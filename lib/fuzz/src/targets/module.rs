//! Loadable modules: a relocatable ELF the kernel maps and relocates at run time.
//!
//! The most dangerous parser here. The others read a description of the machine; this one
//! reads *code*, computes addresses from its relocation entries, and writes them into
//! memory the kernel owns. A relocation whose offset is not checked is a write wherever
//! the module's author chose.
//!
//! Seeded with a real module kbuild built, because an object file's sections, symbol table
//! and string tables refer to each other by index and offset. Two layers are driven: the
//! bundle that carries modules to the kernel, and the object itself — sections, symbols
//! and relocations, each walked to the end.
//!
//! `load` is not called. It needs a `Kernel` whose identity hash the module was built
//! against, and a mutated module fails that check before any relocation is applied, so
//! calling it would fuzz the identity comparison over and over and never reach the
//! relocator. What the relocator does with a hostile object is reached through the object
//! API instead, which is what `load` itself walks.

use alloc::vec::Vec;

use module::bundle::Bundle;
use module::elf::Object;

use crate::{Mutator, Rng};

pub fn generate(rng: &mut Rng, seeds: &[Vec<u8>]) -> Vec<u8> {
    if seeds.is_empty() {
        return Vec::new();
    }
    let mut bytes = rng.pick(seeds).clone();
    // Sometimes wrap the module in a bundle, so the bundle's own header, count and offset
    // table are fuzzed as well as the object.
    if rng.one_in(3) {
        bytes = bundle(rng, &bytes);
    }
    Mutator::mutate(rng, &mut bytes);
    bytes
}

/// A bundle holding the module once or twice, built the way kbuild builds one: a magic,
/// a count, then `(name offset, name length, data offset, data length)` per entry.
///
/// Built from the format's description rather than by calling kbuild's writer, because
/// the writer is in kbuild and this is a kernel-side crate. If the two ever disagree the
/// bundle parser's own tests are what pins the format; this only has to be close enough
/// to be worth mutating.
fn bundle(rng: &mut Rng, module: &[u8]) -> Vec<u8> {
    let count = 1 + rng.below(2);
    let mut names: Vec<u8> = Vec::new();
    let mut entries: Vec<(u32, u32, u32, u32)> = Vec::new();
    let header = 8 + count * 16;
    let mut data_at = header + count * 8;

    for i in 0..count {
        let name = if i == 0 {
            &b"test-roundtrip"[..]
        } else {
            &b"other"[..]
        };
        let name_at = header + names.len();
        names.extend_from_slice(name);
        entries.push((name_at as u32, name.len() as u32, data_at as u32, module.len() as u32));
        data_at += module.len();
    }

    let mut out: Vec<u8> = Vec::new();
    out.extend_from_slice(b"KTMB");
    out.extend_from_slice(&(count as u32).to_le_bytes());
    for (n_at, n_len, d_at, d_len) in &entries {
        out.extend_from_slice(&n_at.to_le_bytes());
        out.extend_from_slice(&n_len.to_le_bytes());
        out.extend_from_slice(&d_at.to_le_bytes());
        out.extend_from_slice(&d_len.to_le_bytes());
    }
    out.extend_from_slice(&names);
    while out.len() < entries[0].2 as usize {
        out.push(0);
    }
    for _ in 0..count {
        out.extend_from_slice(module);
    }
    out
}

pub fn run(input: &[u8]) {
    // As a bundle: header, count, and every entry's name and data slice.
    if let Ok(b) = Bundle::parse(input) {
        let _ = (b.len(), b.is_empty());
        for i in 0..b.len().saturating_add(2) {
            let _ = b.entry(i);
        }
        let _ = b.get("test-roundtrip");
    }

    // As an object: every section, every symbol, every relocation.
    let Ok(obj) = Object::parse(input) else {
        return;
    };
    let _ = (obj.machine(), obj.section_count());

    for section in obj.sections() {
        let Ok(s) = section else { break };
        let _ = obj.data(&s);
        let _ = obj.section_name(&s);
        let _ = s.is_alloc();
        // Relocation sections are where an offset becomes a write address.
        if let Ok(relas) = obj.relas(&s) {
            for rela in relas {
                let _ = (rela.offset, rela.addend, rela.symbol, rela.kind);
            }
        }
    }
    let _ = obj.section_by_name(".text");

    let Ok(Some(symtab)) = obj.symtab() else {
        return;
    };
    let count = obj.symbol_count(&symtab);
    for i in 0..count.min(4096) {
        let Ok(Some(sym)) = obj.symbol(&symtab, i) else {
            break;
        };
        let _ = (sym.binding(), sym.kind(), sym.shndx);
        let _ = obj.symbol_name(&symtab, &sym);
    }
    // One past the end, which a relocation's symbol index can name.
    let _ = obj.symbol(&symtab, count);
    let _ = obj.string(0, 0);
}

//! Host tests: objects built here byte by byte, so every field the loader reads is one the
//! test chose, plus relocation arithmetic checked against hand-computed values.

use crate::elf::*;
use crate::identity::{self, Mismatch};
use crate::interface::{Export, ImportRecord, fnv1a64};
use crate::load::{self, Kernel, LoadError, Memory, Placement, Region};
use crate::registry::{Registry, RegistryError};
use crate::reloc::{self, RelocError, aarch64 as a64, x86_64 as x64};

// ---- building objects ------------------------------------------------------------------

struct Sec {
    name: &'static str,
    kind: u32,
    flags: u64,
    data: Vec<u8>,
    size: u64,
    align: u64,
    link: u32,
    info: u32,
    entsize: u64,
}

fn sec(name: &'static str, kind: u32, flags: u64, data: Vec<u8>) -> Sec {
    let size = data.len() as u64;
    Sec {
        name,
        kind,
        flags,
        data,
        size,
        align: 1,
        link: 0,
        info: 0,
        entsize: 0,
    }
}

struct Sym {
    name: &'static str,
    info: u8,
    shndx: u16,
    value: u64,
}

const GLOBAL_FUNC: u8 = 0x12;
const GLOBAL_NOTYPE: u8 = 0x10;
const LOCAL_SECTION: u8 = 0x03;

/// An ELF64 relocatable object. `sections` are numbered from 1; a symbol table, its string
/// table and the section name table are appended after them.
fn object(machine: u16, mut sections: Vec<Sec>, symbols: &[Sym]) -> Vec<u8> {
    let mut strtab = vec![0u8];
    let mut symtab = vec![0u8; 24];
    for s in symbols {
        let name = strtab.len() as u32;
        strtab.extend_from_slice(s.name.as_bytes());
        strtab.push(0);
        symtab.extend_from_slice(&name.to_le_bytes());
        symtab.push(s.info);
        symtab.push(0);
        symtab.extend_from_slice(&s.shndx.to_le_bytes());
        symtab.extend_from_slice(&s.value.to_le_bytes());
        symtab.extend_from_slice(&0u64.to_le_bytes());
    }
    let symtab_index = sections.len() as u32 + 1;
    let mut st = sec(".symtab", SHT_SYMTAB, 0, symtab);
    st.link = symtab_index + 1;
    st.entsize = 24;
    sections.push(st);
    sections.push(sec(".strtab", 3, 0, strtab));
    sections.push(sec(".shstrtab", 3, 0, Vec::new()));

    let mut shstr = vec![0u8];
    let names: Vec<u32> = sections
        .iter()
        .map(|s| {
            let at = shstr.len() as u32;
            shstr.extend_from_slice(s.name.as_bytes());
            shstr.push(0);
            at
        })
        .collect();
    let last = sections.len() - 1;
    sections[last].size = shstr.len() as u64;
    sections[last].data = shstr;

    let mut out = vec![0u8; 64];
    let mut offsets = Vec::new();
    for s in &sections {
        while out.len() % 8 != 0 {
            out.push(0);
        }
        offsets.push(out.len() as u64);
        out.extend_from_slice(&s.data);
    }
    while out.len() % 8 != 0 {
        out.push(0);
    }
    let shoff = out.len() as u64;
    out.extend_from_slice(&[0u8; 64]);
    for (i, s) in sections.iter().enumerate() {
        let mut h = Vec::new();
        h.extend_from_slice(&names[i].to_le_bytes());
        h.extend_from_slice(&s.kind.to_le_bytes());
        h.extend_from_slice(&s.flags.to_le_bytes());
        h.extend_from_slice(&0u64.to_le_bytes());
        h.extend_from_slice(&offsets[i].to_le_bytes());
        h.extend_from_slice(&s.size.to_le_bytes());
        h.extend_from_slice(&s.link.to_le_bytes());
        h.extend_from_slice(&s.info.to_le_bytes());
        h.extend_from_slice(&s.align.to_le_bytes());
        h.extend_from_slice(&s.entsize.to_le_bytes());
        out.extend_from_slice(&h);
    }
    let shnum = sections.len() as u16 + 1;
    out[..4].copy_from_slice(b"\x7fELF");
    out[4] = 2;
    out[5] = 1;
    out[6] = 1;
    out[16..18].copy_from_slice(&1u16.to_le_bytes());
    out[18..20].copy_from_slice(&machine.to_le_bytes());
    out[40..48].copy_from_slice(&shoff.to_le_bytes());
    out[58..60].copy_from_slice(&64u16.to_le_bytes());
    out[60..62].copy_from_slice(&shnum.to_le_bytes());
    out[62..64].copy_from_slice(&(shnum - 1).to_le_bytes());
    out
}

fn rela(entries: &[(u64, u32, u32, i64)]) -> Vec<u8> {
    let mut v = Vec::new();
    for &(offset, sym, kind, addend) in entries {
        v.extend_from_slice(&offset.to_le_bytes());
        v.extend_from_slice(&(((sym as u64) << 32) | kind as u64).to_le_bytes());
        v.extend_from_slice(&addend.to_le_bytes());
    }
    v
}

fn identity_text(debug: &str) -> String {
    format!(
        "kintane-module-identity 1\ntoolchain t1\ntarget abc\nconfig\nARCH_X86_64=y\nDEBUG_BUILD={debug}\nNR_CPUS=8\n"
    )
}

fn sha(text: &str) -> [u8; 32] {
    // Any 32 bytes that differ when the text does; the loader compares, never computes.
    let mut out = [0u8; 32];
    for (i, b) in fnv1a64(text.as_bytes()).to_le_bytes().iter().enumerate() {
        out[i] = *b;
        out[31 - i] = *b;
    }
    out
}

fn identity_section(text: &str) -> Vec<u8> {
    let mut v = identity::MAGIC.to_vec();
    v.extend_from_slice(&sha(text));
    v.extend_from_slice(&(text.len() as u32).to_le_bytes());
    v.extend_from_slice(text.as_bytes());
    v
}

crate::declare_interface! {
    fn kt_log(ptr: *const u8, len: usize);
    fn kt_add(a: u64, b: u64) -> u64;
}

mod other_interface {
    crate::declare_interface! {
        fn kt_log(ptr: *const u8, len: usize);
        fn kt_add(a: u32, b: u32) -> u32;
    }
}

const LOG_AT: usize = 0x0010_2000;
const ADD_AT: usize = 0x0010_3000;

fn exports() -> Vec<Export> {
    vec![
        Export {
            name: "kt_log",
            hash: crate::interface::hash_of(SIGNATURES, "kt_log"),
            addr: LOG_AT,
        },
        Export {
            name: "kt_add",
            hash: crate::interface::hash_of(SIGNATURES, "kt_add"),
            addr: ADD_AT,
        },
    ]
}

fn records(signatures: &[(&str, u64)]) -> Vec<u8> {
    let mut v = Vec::new();
    for (name, hash) in signatures {
        let r = ImportRecord::new(name, *hash);
        v.extend_from_slice(&r.name);
        v.push(r.name_len);
        v.extend_from_slice(&r.hash.to_le_bytes());
    }
    v
}

/// A small but complete x86-64 module:
///
/// * `.text` (section 1): 32 bytes. `kt_module_init` at 0. A call to `kt_log` at 1 (`PLT32`), a
///   reference to the string at 8 (`32S`), a `PC32` to `.data` at 16.
/// * `.rodata` (2): `"hello\0"`.
/// * `.data` (3): an 8-byte pointer to the string (`R_X86_64_64`).
/// * `.bss` (4): 16 bytes.
/// * relocation sections (5, 6), the imports section (7), the identity (8).
struct Parts {
    identity: String,
    signatures: &'static [(&'static str, u64)],
    extra_text_relocs: Vec<(u64, u32, u32, i64)>,
}

impl Default for Parts {
    fn default() -> Self {
        Parts {
            identity: identity_text("y"),
            signatures: SIGNATURES,
            extra_text_relocs: Vec::new(),
        }
    }
}

// Symbol indices below: 1 .text, 2 .rodata, 3 .data, 4 kt_module_init, 5 kt_log.
const SYM_TEXT: u32 = 1;
const SYM_RODATA: u32 = 2;
const SYM_DATA: u32 = 3;
const SYM_LOG: u32 = 5;

fn module(parts: Parts) -> Vec<u8> {
    let exec = SHF_ALLOC | SHF_EXECINSTR;
    let mut text = sec(".text", SHT_PROGBITS, exec, vec![0x90; 32]);
    text.align = 16;
    let rodata = sec(".rodata.str", SHT_PROGBITS, SHF_ALLOC, b"hello\0".to_vec());
    let mut data = sec(".data", SHT_PROGBITS, SHF_ALLOC | SHF_WRITE, vec![0; 8]);
    data.align = 8;
    let mut bss = sec(".bss", SHT_NOBITS, SHF_ALLOC | SHF_WRITE, Vec::new());
    bss.size = 16;
    bss.align = 8;

    let mut text_relocs = vec![
        (1, SYM_LOG, x64::R_PLT32, -4),
        (8, SYM_RODATA, x64::R_32S, 0),
        (16, SYM_DATA, x64::R_PC32, -4),
        (24, SYM_DATA, x64::R_32, 8),
    ];
    text_relocs.extend(parts.extra_text_relocs);
    let symtab = 9; // four sections, two RELA, imports, identity, then .symtab
    let mut rela_text = sec(".rela.text", SHT_RELA, 0, rela(&text_relocs));
    rela_text.info = 1;
    rela_text.link = symtab;
    rela_text.entsize = 24;
    let mut rela_data = sec(".rela.data", SHT_RELA, 0, rela(&[(0, SYM_RODATA, x64::R_64, 2)]));
    rela_data.info = 3;
    rela_data.link = symtab;
    rela_data.entsize = 24;
    let imports = sec(".kintane.imports", SHT_PROGBITS, 0, records(parts.signatures));
    let ident = sec(".kintane.identity", SHT_PROGBITS, 0, identity_section(&parts.identity));

    object(
        EM_X86_64,
        vec![
            text, rodata, data, bss, rela_text, rela_data, imports, ident,
        ],
        &[
            Sym {
                name: "",
                info: LOCAL_SECTION,
                shndx: 1,
                value: 0,
            },
            Sym {
                name: "",
                info: LOCAL_SECTION,
                shndx: 2,
                value: 0,
            },
            Sym {
                name: "",
                info: LOCAL_SECTION,
                shndx: 3,
                value: 0,
            },
            Sym {
                name: "kt_module_init",
                info: GLOBAL_FUNC,
                shndx: 1,
                value: 0,
            },
            Sym {
                name: "kt_log",
                info: GLOBAL_NOTYPE,
                shndx: SHN_UNDEF,
                value: 0,
            },
        ],
    )
}

// ---- memory ----------------------------------------------------------------------------

struct Mem {
    bases: [u64; 3],
    regions: [Vec<u8>; 3],
}

impl Mem {
    fn at(bases: [u64; 3]) -> Mem {
        Mem {
            bases,
            regions: [Vec::new(), Vec::new(), Vec::new()],
        }
    }
    fn low() -> Mem {
        Mem::at([0x6000_0000, 0x6010_0000, 0x6020_0000])
    }
}

impl Memory for Mem {
    fn allocate(&mut self, sizes: [u64; 3]) -> Result<[u64; 3], LoadError<'static>> {
        for (r, s) in self.regions.iter_mut().zip(sizes) {
            *r = vec![0xEE; s as usize];
            r.fill(0);
        }
        Ok(self.bases)
    }
    fn bytes(&mut self, r: Region) -> &mut [u8] {
        &mut self.regions[r as usize]
    }
}

fn kernel<'k>(text: &'k str, hash: &'k [u8; 32], exports: &'k [Export]) -> Kernel<'k> {
    Kernel {
        machine: EM_X86_64,
        identity_hash: hash,
        identity_text: text,
        exports,
    }
}

fn try_load(bytes: &[u8], mem: &mut Mem) -> Result<load::Loaded, String> {
    let text = identity_text("y");
    let hash = sha(&text);
    let exports = exports();
    let mut placements: Vec<Placement> = vec![None; 64];
    load::load(bytes, &kernel(&text, &hash, &exports), &mut placements, mem)
        .map_err(|e| format!("{e:?}"))
}

// ---- the loader ------------------------------------------------------------------------

#[test]
fn a_module_loads_and_every_relocation_holds_the_computed_value() {
    let bytes = module(Parts::default());
    let mut mem = Mem::low();
    let loaded = try_load(&bytes, &mut mem).unwrap();
    let [text, rodata, data] = mem.bases;

    assert_eq!(loaded.init, text, "kt_module_init is at the start of .text");
    assert_eq!(loaded.exit, None);
    assert_eq!(loaded.relocations, 5);
    assert_eq!(loaded.regions[0], (text, 32));
    assert_eq!(loaded.regions[1], (rodata, 6));
    assert_eq!(loaded.regions[2], (data, 8 + 16), ".data then .bss, aligned to 8");

    let t = &mem.regions[0];
    let rd = |b: &[u8], at: usize| i32::from_le_bytes(b[at..at + 4].try_into().unwrap());
    // PLT32 to kt_log: S + A - P.
    assert_eq!(rd(t, 1) as i64, LOG_AT as i64 - 4 - (text as i64 + 1));
    // 32S: the string's address.
    assert_eq!(rd(t, 8) as u64, rodata);
    // PC32 to .data: S + A - P.
    assert_eq!(rd(t, 16) as i64, data as i64 - 4 - (text as i64 + 16));
    // 32 to .bss, which follows .data: S + A.
    assert_eq!(rd(t, 24) as u64, data + 8);
    // R_X86_64_64 in .data: the string's address plus the addend.
    assert_eq!(u64::from_le_bytes(mem.regions[2][..8].try_into().unwrap()), rodata + 2);
    assert_eq!(&mem.regions[1][..], b"hello\0");
    assert!(mem.regions[2][8..].iter().all(|&b| b == 0), ".bss is zeroed");
}

#[test]
fn a_module_for_another_configuration_is_refused_naming_the_symbol() {
    let bytes = module(Parts {
        identity: identity_text("n"),
        ..Parts::default()
    });
    let e = try_load(&bytes, &mut Mem::low()).unwrap_err();
    assert!(
        e.contains(r#"Config { symbol: "DEBUG_BUILD", module: "n", kernel: "y" }"#),
        "{e}"
    );
}

#[test]
fn identity_names_the_toolchain_the_target_and_missing_symbols() {
    let k = identity_text("y");
    assert_eq!(
        identity::explain(&k.replace("toolchain t1", "toolchain t2"), &k),
        Mismatch::Toolchain {
            module: "t2",
            kernel: "t1"
        }
    );
    assert_eq!(identity::explain(&k.replace("target abc", "target abd"), &k), Mismatch::Target);
    assert_eq!(
        identity::explain(&k.replace("NR_CPUS=8\n", ""), &k),
        Mismatch::Config {
            symbol: "NR_CPUS",
            module: "",
            kernel: "8"
        }
    );
    assert_eq!(
        identity::explain(&format!("{k}NEW=y\n"), &k),
        Mismatch::Config {
            symbol: "NEW",
            module: "y",
            kernel: ""
        }
    );
    assert_eq!(identity::explain(&k, &k), Mismatch::Corrupt, "same text, different hash");

    let hash = sha(&k);
    assert_eq!(identity::check(None, &hash, &k), Err(Mismatch::Malformed));
    let section = identity_section(&k);
    let parsed = identity::Identity::parse(&section);
    assert_eq!(identity::check(parsed, &hash, &k), Ok(()));
    for cut in 0..section.len() {
        assert!(identity::Identity::parse(&section[..cut]).is_none(), "truncated at {cut}");
    }
}

#[test]
fn imports_are_checked_against_exports_and_their_recorded_interface() {
    let bytes = module(Parts {
        signatures: other_interface::SIGNATURES,
        ..Parts::default()
    });
    // kt_log's signature is the same in both interfaces; kt_add is not called.
    try_load(&bytes, &mut Mem::low()).expect("an unused differing function does not matter");

    let changed: &'static [(&str, u64)] = Box::leak(Box::new([("kt_log", 1234u64)]));
    let e = try_load(
        &module(Parts {
            signatures: changed,
            ..Parts::default()
        }),
        &mut Mem::low(),
    )
    .unwrap_err();
    assert!(e.starts_with("InterfaceMismatch { name: [107, 116, 95, 108, 111, 103]"), "{e}");

    let e = try_load(
        &module(Parts {
            signatures: &[],
            ..Parts::default()
        }),
        &mut Mem::low(),
    )
    .unwrap_err();
    assert!(e.starts_with("Undeclared"), "{e}");

    let text = identity_text("y");
    let hash = sha(&text);
    let only_add = [exports()[1]];
    let mut placements = vec![None; 64];
    let bytes = module(Parts::default());
    let e = load::load(&bytes, &kernel(&text, &hash, &only_add), &mut placements, &mut Mem::low())
        .unwrap_err();
    assert!(matches!(e, LoadError::Unexported { name: b"kt_log" }), "{e:?}");
}

#[test]
fn the_interface_hash_is_the_signature() {
    let log = crate::interface::hash_of(SIGNATURES, "kt_log");
    assert_eq!(log, crate::interface::hash_of(other_interface::SIGNATURES, "kt_log"));
    assert_ne!(
        crate::interface::hash_of(SIGNATURES, "kt_add"),
        crate::interface::hash_of(other_interface::SIGNATURES, "kt_add")
    );
    assert_eq!(log, fnv1a64(b"fn kt_log(*const u8,usize,)"));
    // The kernel's own interface has distinct hashes for distinct signatures.
    let abi = crate::abi::SIGNATURES;
    assert_eq!(abi.len(), 4);
    for (i, a) in abi.iter().enumerate() {
        for b in &abi[i + 1..] {
            assert_ne!(a.1, b.1, "{} and {}", a.0, b.0);
        }
    }
}

#[test]
fn an_address_that_does_not_fit_32_bits_is_refused_not_truncated() {
    let bytes = module(Parts::default());
    let mut high = Mem::at([0x6000_0000, 0x1_0000_0000, 0x6020_0000]);
    let e = try_load(&bytes, &mut high).unwrap_err();
    assert!(e.contains("Overflow { kind: 11, offset: 8 }"), "{e}");
}

#[test]
fn a_got_relocation_is_refused_by_name() {
    let bytes = module(Parts {
        extra_text_relocs: vec![(28, SYM_LOG, x64::R_REX_GOTPCRELX, -4)],
        ..Parts::default()
    });
    let e = try_load(&bytes, &mut Mem::low()).unwrap_err();
    assert!(e.contains("Unsupported { machine: 62, kind: 42 }"), "{e}");
}

#[test]
fn a_relocation_past_its_section_is_refused() {
    let bytes = module(Parts {
        extra_text_relocs: vec![(30, SYM_TEXT, x64::R_32, 0)],
        ..Parts::default()
    });
    let e = try_load(&bytes, &mut Mem::low()).unwrap_err();
    assert!(e.contains("OutOfSection { offset: 30 }"), "{e}");
}

#[test]
fn wrong_machine_missing_init_and_non_objects_are_refused() {
    let mut bytes = module(Parts::default());
    bytes[18..20].copy_from_slice(&EM_AARCH64.to_le_bytes());
    assert!(
        try_load(&bytes, &mut Mem::low())
            .unwrap_err()
            .starts_with("WrongMachine")
    );

    let mut bytes = module(Parts::default());
    let at = bytes
        .windows(14)
        .position(|w| w == b"kt_module_init")
        .unwrap();
    bytes[at] = b'x';
    assert_eq!(try_load(&bytes, &mut Mem::low()).unwrap_err(), "NoInit");

    let mut bytes = module(Parts::default());
    bytes[16] = 2;
    assert!(
        try_load(&bytes, &mut Mem::low())
            .unwrap_err()
            .contains("NotRelocatable")
    );
    assert!(
        try_load(&bytes[..10], &mut Mem::low())
            .unwrap_err()
            .contains("TooShort")
    );
    assert!(
        try_load(
            b"not an elf file at all, but long enough to have a whole header...",
            &mut Mem::low()
        )
        .unwrap_err()
        .contains("NotElf64Le")
    );
}

#[test]
fn no_corruption_of_a_module_panics_the_loader() {
    let good = module(Parts::default());
    // Every single byte, three ways, and every truncation.
    for i in 0..good.len() {
        for v in [0x00u8, 0xff, good[i] ^ 0x80] {
            let mut bad = good.clone();
            bad[i] = v;
            let _ = try_load(&bad, &mut Mem::low());
        }
    }
    for cut in 0..good.len() {
        assert!(try_load(&good[..cut], &mut Mem::low()).is_err(), "truncated at {cut} loaded");
    }
}

#[test]
fn a_real_module_built_by_kbuild_parses_and_loads() {
    // Captured from `kbuild modules --preset x86_64-qemu`; see testdata/README.
    let bytes = include_bytes!("../testdata/test-x86_64.kmod");
    let obj = Object::parse(bytes).unwrap();
    assert_eq!(obj.machine(), EM_X86_64);
    let ident = obj
        .section_by_name(crate::IDENTITY_SECTION)
        .unwrap()
        .unwrap();
    let ident = identity::Identity::parse(obj.data(&ident).unwrap()).unwrap();
    assert!(ident.text.starts_with("kintane-module-identity 1\n"), "{}", ident.text);

    let exports: Vec<Export> = crate::abi::SIGNATURES
        .iter()
        .enumerate()
        .map(|(i, (name, hash))| Export {
            name,
            hash: *hash,
            addr: 0x0010_0000 + i * 0x100,
        })
        .collect();
    let kernel = Kernel {
        machine: EM_X86_64,
        identity_hash: &ident.hash,
        identity_text: ident.text,
        exports: &exports,
    };
    let mut placements = vec![None; obj.section_count()];
    let mut mem = Mem::low();
    let loaded = load::load(bytes, &kernel, &mut placements, &mut mem).unwrap();
    assert!(loaded.relocations > 0);
    assert!(loaded.exit.is_some(), "module! defines kt_module_exit");
    assert!(loaded.init >= mem.bases[0] && loaded.init < mem.bases[0] + loaded.regions[0].1);

    // Every corruption of the real thing is an error, never a panic.
    for i in (0..bytes.len()).step_by(7) {
        let mut bad = bytes.to_vec();
        bad[i] ^= 0xa5;
        let mut placements = vec![None; 4096];
        let _ = load::load(&bad, &kernel, &mut placements, &mut Mem::low());
    }
}

// ---- relocation arithmetic -------------------------------------------------------------

#[test]
fn aarch64_branches_pages_and_low_12_bits() {
    let apply = |kind, insn: u32, place: u64, target: u64| {
        let mut b = insn.to_le_bytes();
        reloc::apply(EM_AARCH64, kind, &mut b, place, 0, target, 0).map(|()| u32::from_le_bytes(b))
    };
    // bl +0x100: 0x94000040.
    assert_eq!(apply(a64::R_CALL26, 0x9400_0000, 0x1000, 0x1100), Ok(0x9400_0040));
    // b -4: imm26 all ones.
    assert_eq!(apply(a64::R_JUMP26, 0x1400_0000, 0x1000, 0x0ffc), Ok(0x17ff_ffff));
    assert!(matches!(
        apply(a64::R_CALL26, 0x9400_0000, 0, 1 << 27),
        Err(RelocError::Overflow { .. })
    ));
    assert!(apply(a64::R_CALL26, 0x9400_0000, 0, (1 << 27) - 4).is_ok());
    assert!(matches!(
        apply(a64::R_CALL26, 0x9400_0000, 0, 2),
        Err(RelocError::Misaligned { .. })
    ));

    // adrp x0, +2 pages from 0x4000_0123 to 0x4000_2fff: immlo = 2, immhi = 0.
    assert_eq!(
        apply(a64::R_ADR_PREL_PG_HI21, 0x9000_0000, 0x4000_0123, 0x4000_2fff),
        Ok(0xd000_0000)
    );
    // add x0, x0, #0xabc.
    assert_eq!(apply(a64::R_ADD_ABS_LO12_NC, 0x9100_0000, 0, 0x1234_5abc), Ok(0x912a_f000));
    // ldr x0, [x0, #0x10]: scaled by 8.
    assert_eq!(apply(a64::R_LDST64_ABS_LO12_NC, 0xf940_0000, 0, 0x5010), Ok(0xf940_0800));
    assert!(matches!(
        apply(a64::R_LDST64_ABS_LO12_NC, 0xf940_0000, 0, 0x5011),
        Err(RelocError::Misaligned { .. })
    ));

    let mut b = [0u8; 8];
    assert_eq!(reloc::apply(EM_AARCH64, a64::R_PREL32, &mut b, 0x1000, 4, 0x800, 0), Ok(()));
    assert_eq!(i32::from_le_bytes(b[4..8].try_into().unwrap()), 0x800 - 0x1004);
    assert!(matches!(
        reloc::apply(EM_AARCH64, a64::R_ABS32, &mut b, 0, 0, 1 << 33, 0),
        Err(RelocError::Overflow { .. })
    ));
    assert!(matches!(
        reloc::apply(EM_AARCH64, a64::R_ABS64, &mut b, 0, 4, 0, 0),
        Err(RelocError::OutOfSection { .. })
    ));
    assert_eq!(
        reloc::apply(EM_AARCH64, 311, &mut b, 0, 0, 0, 0),
        Err(RelocError::Unsupported {
            machine: EM_AARCH64,
            kind: 311
        })
    );
}

#[test]
fn x86_64_signed_and_unsigned_32_bit_limits() {
    let mut b = [0u8; 8];
    assert!(reloc::apply(EM_X86_64, x64::R_32, &mut b, 0, 0, 0xffff_ffff, 0).is_ok());
    assert!(reloc::apply(EM_X86_64, x64::R_32, &mut b, 0, 0, 0x1_0000_0000, 0).is_err());
    assert!(reloc::apply(EM_X86_64, x64::R_32S, &mut b, 0, 0, 0x7fff_ffff, 0).is_ok());
    assert!(reloc::apply(EM_X86_64, x64::R_32S, &mut b, 0, 0, 0x8000_0000, 0).is_err());
    assert!(reloc::apply(EM_X86_64, x64::R_32S, &mut b, 0, 0, (-1i64) as u64, 0).is_ok());
    assert!(reloc::apply(EM_X86_64, x64::R_PC32, &mut b, 0x1_0000_0000, 0, 0, 0).is_err());
    assert!(reloc::apply(EM_X86_64, x64::R_PC64, &mut b, 0x1_0000_0000, 0, 0, 0).is_ok());
    assert_eq!(i64::from_le_bytes(b), -0x1_0000_0000);
}

// ---- the bundle ------------------------------------------------------------------------

/// The layout kbuild writes; `kbuild/src/modules.rs` has the matching test.
fn bundle(modules: &[(&str, &[u8])]) -> Vec<u8> {
    let header = 16 + modules.len() * 48;
    let (mut table, mut data) = (Vec::new(), Vec::new());
    for (name, bytes) in modules {
        while (header + data.len()) % 8 != 0 {
            data.push(0);
        }
        let mut n = [0u8; 40];
        n[..name.len()].copy_from_slice(name.as_bytes());
        table.extend_from_slice(&n);
        table.extend_from_slice(&((header + data.len()) as u32).to_le_bytes());
        table.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
        data.extend_from_slice(bytes);
    }
    let mut out = b"KTBUNDL1".to_vec();
    out.extend_from_slice(&(modules.len() as u32).to_le_bytes());
    out.extend_from_slice(&((header + data.len()) as u32).to_le_bytes());
    out.extend(table);
    out.extend(data);
    out
}

#[test]
fn a_bundle_hands_out_its_modules_and_refuses_entries_outside_it() {
    use crate::bundle::{Bundle, BundleError};
    let mut b = bundle(&[("one", b"abc"), ("two", b"defgh")]);
    b.extend_from_slice(&[0; 4000]); // a boot module rounded up to a page
    let parsed = Bundle::parse(&b).unwrap();
    assert_eq!(parsed.len(), 2);
    assert_eq!(parsed.get("two"), Some(&b"defgh"[..]));
    assert_eq!(parsed.entry(0).unwrap(), ("one", &b"abc"[..]));
    assert_eq!(parsed.get("three"), None);

    let good = bundle(&[("one", b"abc"), ("two", b"defgh")]);
    for i in 0..good.len() {
        let mut bad = good.clone();
        bad[i] ^= 0xff;
        if let Ok(p) = Bundle::parse(&bad) {
            for j in 0..p.len() {
                let _ = p.entry(j);
            }
        }
    }
    for cut in 0..good.len() {
        assert!(Bundle::parse(&good[..cut]).is_err(), "truncated at {cut}");
    }
    let mut overlap = good.clone();
    overlap[56..60].copy_from_slice(&8u32.to_le_bytes()); // entry 0 points into the table
    assert_eq!(Bundle::parse(&overlap).unwrap_err(), BundleError::BadEntry { index: 0 });
}

// ---- the registry ----------------------------------------------------------------------

#[test]
fn a_referenced_module_cannot_unload_and_a_stale_id_names_nothing() {
    let mut r: Registry<2> = Registry::new();
    let a = r.insert().unwrap();
    r.acquire(a).unwrap();
    r.acquire(a).unwrap();
    assert_eq!(r.begin_unload(a), Err(RegistryError::Busy { refs: 2 }));
    r.release(a).unwrap();
    assert_eq!(r.begin_unload(a), Err(RegistryError::Busy { refs: 1 }));
    r.release(a).unwrap();
    assert_eq!(r.release(a), Err(RegistryError::NotHeld));
    r.begin_unload(a).unwrap();
    assert_eq!(r.acquire(a), Err(RegistryError::Unloading), "no new references while unloading");
    r.remove(a).unwrap();
    assert!(r.is_empty());

    let b = r.insert().unwrap();
    assert_ne!(a, b, "the slot is reused under a new generation");
    assert_eq!(r.acquire(a), Err(RegistryError::NoSuchModule));
    let _c = r.insert().unwrap();
    assert_eq!(r.insert(), Err(RegistryError::Full));
    assert_eq!(r.remove(b), Err(RegistryError::Busy { refs: 0 }), "remove needs begin_unload");
}

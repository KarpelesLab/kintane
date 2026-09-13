//! Host tests for the device tree parser.
//!
//! Most trees here are built byte-for-byte by [`Dtb`], a minimal writer laid out the
//! way `dtc` lays a blob out: header, reservation block, structure block, strings
//! block. Building them rather than checking in binaries is what lets each test say
//! exactly which byte it breaks. One real tree is checked in as well, because a writer
//! written by the same hand as the reader can share its misunderstandings.
//!
//! The writer was checked against `dtc` once, by hand: the blob `machine()` builds,
//! decompiled with `dtc -I dtb -O dts` and recompiled with `dtc -I dts -O dtb`, comes
//! back byte-identical.

use super::*;

// --- a minimal DTB writer ----------------------------------------------------------

/// A device tree under construction.
struct Dtb {
    reservations: Vec<(u64, u64)>,
    structure: Vec<u8>,
    strings: Vec<u8>,
}

impl Dtb {
    fn new() -> Dtb {
        Dtb {
            reservations: Vec::new(),
            structure: Vec::new(),
            strings: Vec::new(),
        }
    }

    fn token(&mut self, t: u32) -> &mut Dtb {
        self.structure.extend_from_slice(&t.to_be_bytes());
        self
    }

    fn pad(&mut self) {
        while self.structure.len() % 4 != 0 {
            self.structure.push(0);
        }
    }

    fn begin(&mut self, name: &str) -> &mut Dtb {
        self.token(FDT_BEGIN_NODE);
        self.structure.extend_from_slice(name.as_bytes());
        self.structure.push(0);
        self.pad();
        self
    }

    fn end(&mut self) -> &mut Dtb {
        self.token(FDT_END_NODE)
    }

    fn nop(&mut self) -> &mut Dtb {
        self.token(FDT_NOP)
    }

    /// Offset of `name` in the strings block, appending it if it is new.
    fn string(&mut self, name: &str) -> u32 {
        let mut needle = name.as_bytes().to_vec();
        needle.push(0);
        let at = self
            .strings
            .windows(needle.len())
            .position(|w| w == needle.as_slice())
            .filter(|&p| p == 0 || self.strings[p - 1] == 0);
        let at = at.unwrap_or_else(|| {
            let p = self.strings.len();
            self.strings.extend_from_slice(&needle);
            p
        });
        u32::try_from(at).unwrap()
    }

    /// A property with an explicit name offset, for tests that break it.
    fn prop_at(&mut self, name_offset: u32, value: &[u8]) -> &mut Dtb {
        self.token(FDT_PROP);
        let len = u32::try_from(value.len()).unwrap();
        self.structure.extend_from_slice(&len.to_be_bytes());
        self.structure.extend_from_slice(&name_offset.to_be_bytes());
        self.structure.extend_from_slice(value);
        self.pad();
        self
    }

    fn prop(&mut self, name: &str, value: &[u8]) -> &mut Dtb {
        let at = self.string(name);
        self.prop_at(at, value)
    }

    fn cells(&mut self, name: &str, cells: &[u32]) -> &mut Dtb {
        let bytes: Vec<u8> = cells.iter().flat_map(|c| c.to_be_bytes()).collect();
        self.prop(name, &bytes)
    }

    fn str_prop(&mut self, name: &str, value: &str) -> &mut Dtb {
        let mut bytes = value.as_bytes().to_vec();
        bytes.push(0);
        self.prop(name, &bytes)
    }

    fn reserve(&mut self, address: u64, size: u64) -> &mut Dtb {
        self.reservations.push((address, size));
        self
    }

    /// The blob, with `FDT_END` appended to the structure block.
    fn finish(&self) -> Vec<u8> {
        let mut s = Dtb {
            reservations: self.reservations.clone(),
            structure: self.structure.clone(),
            strings: self.strings.clone(),
        };
        s.token(FDT_END);
        s.finish_raw()
    }

    /// The blob exactly as built, with no `FDT_END` added.
    fn finish_raw(&self) -> Vec<u8> {
        let rsv_off = HEADER_LEN;
        let rsv_len = (self.reservations.len() + 1) * RESERVATION_LEN;
        let struct_off = rsv_off + rsv_len;
        let strings_off = struct_off + self.structure.len();
        let total = strings_off + self.strings.len();

        let mut b = vec![0u8; HEADER_LEN];
        put(&mut b, FIELD_MAGIC, MAGIC);
        put(&mut b, FIELD_TOTALSIZE, u32::try_from(total).unwrap());
        put(&mut b, FIELD_OFF_STRUCT, u32::try_from(struct_off).unwrap());
        put(&mut b, FIELD_OFF_STRINGS, u32::try_from(strings_off).unwrap());
        put(&mut b, FIELD_OFF_RSVMAP, u32::try_from(rsv_off).unwrap());
        put(&mut b, FIELD_VERSION, 17);
        put(&mut b, FIELD_LAST_COMP, 16);
        put(&mut b, FIELD_BOOT_CPUID, 0);
        put(&mut b, FIELD_SIZE_STRINGS, u32::try_from(self.strings.len()).unwrap());
        put(&mut b, FIELD_SIZE_STRUCT, u32::try_from(self.structure.len()).unwrap());
        for &(a, s) in &self.reservations {
            b.extend_from_slice(&a.to_be_bytes());
            b.extend_from_slice(&s.to_be_bytes());
        }
        b.extend_from_slice(&[0u8; RESERVATION_LEN]);
        b.extend_from_slice(&self.structure);
        b.extend_from_slice(&self.strings);
        assert_eq!(b.len(), total);
        b
    }
}

fn put(b: &mut [u8], at: usize, v: u32) {
    b[at..at + 4].copy_from_slice(&v.to_be_bytes());
}

fn get(b: &[u8], at: usize) -> u32 {
    u32::from_be_bytes(b[at..at + 4].try_into().unwrap())
}

const EMPTY: MemoryRegion = MemoryRegion {
    start: 0,
    len: 0,
    kind: 0,
    _reserved: 0,
};

fn region(start: u64, len: u64, kind: MemoryKind) -> MemoryRegion {
    MemoryRegion {
        start,
        len,
        kind: wire(kind),
        _reserved: 0,
    }
}

/// Parse and extract a memory map, or the first error on the way.
fn map_of(blob: &[u8]) -> Result<Vec<MemoryRegion>, Error> {
    let fdt = Fdt::new(blob)?;
    let mut out = [EMPTY; 32];
    let n = fdt.memory_map(&mut out)?;
    Ok(out[..n].to_vec())
}

/// The shape of QEMU's `virt` tree, reduced to what the memory map depends on, plus a
/// reservation of each kind. Two/two cells at the root, one/one under
/// `/reserved-memory`, as real trees commonly have.
fn machine() -> Dtb {
    let mut d = Dtb::new();
    d.reserve(0x4000_0000, 0x1000)
        .begin("")
        .cells("#size-cells", &[2])
        .cells("#address-cells", &[2])
        .str_prop("compatible", "linux,dummy-virt")
        .begin("psci")
        .str_prop("method", "hvc")
        .end()
        .begin("memory@40000000")
        .cells("reg", &[0, 0x4000_0000, 0, 0x0800_0000])
        .str_prop("device_type", "memory")
        .end()
        .begin("reserved-memory")
        .cells("#address-cells", &[1])
        .cells("#size-cells", &[1])
        .prop("ranges", &[])
        .begin("secmon@41000000")
        .cells("reg", &[0x4100_0000, 0x0010_0000])
        .prop("no-map", &[])
        .end()
        .end()
        .begin("uart@9000000")
        .cells("reg", &[0, 0x0900_0000, 0, 0x1000])
        .end()
        .end();
    d
}

fn expected_machine_map() -> Vec<MemoryRegion> {
    vec![
        region(0x4000_0000, 0x1000, MemoryKind::Reserved),
        region(0x4000_0000, 0x0800_0000, MemoryKind::Usable),
        region(0x4100_0000, 0x0010_0000, MemoryKind::Reserved),
    ]
}

// --- a valid tree ------------------------------------------------------------------

#[test]
fn a_valid_tree_yields_its_memory_and_every_reservation() {
    let blob = machine().finish();
    assert_eq!(map_of(&blob), Ok(expected_machine_map()));
}

#[test]
fn the_header_is_decoded_as_written() {
    let blob = machine().finish();
    let fdt = Fdt::new(&blob).unwrap();
    let h = fdt.header();
    assert_eq!(usize::try_from(h.total_size).unwrap(), blob.len());
    assert_eq!(h.version, 17);
    assert_eq!(h.last_compatible_version, 16);
    assert_eq!(h.reservations_offset, 40);
    assert_eq!(fdt.as_bytes().len(), blob.len());
}

#[test]
fn trailing_bytes_past_totalsize_are_ignored() {
    // A loader hands over a pointer, not a length; what follows the tree in memory is
    // not the tree's business.
    let mut blob = machine().finish();
    blob.extend_from_slice(&[0xff; 64]);
    assert_eq!(map_of(&blob), Ok(expected_machine_map()));
}

#[test]
fn tokens_walk_the_tree_in_order_with_depths() {
    let mut d = Dtb::new();
    d.begin("")
        .nop()
        .begin("a")
        .str_prop("p", "v")
        .end()
        .nop()
        .end();
    let blob = d.finish();
    let fdt = Fdt::new(&blob).unwrap();
    let got: Vec<Token> = fdt.tokens().map(|t| t.unwrap()).collect();
    let shape: Vec<(char, usize, &[u8])> = got
        .iter()
        .map(|t| match *t {
            Token::BeginNode { name, depth, .. } => ('b', depth, name),
            Token::EndNode { depth, .. } => ('e', depth, &[][..]),
            Token::Property { name, depth, .. } => ('p', depth, name),
        })
        .collect();
    assert_eq!(
        shape,
        vec![
            ('b', 1, &b""[..]),
            ('b', 2, &b"a"[..]),
            ('p', 2, &b"p"[..]),
            ('e', 2, &b""[..]),
            ('e', 1, &b""[..]),
        ],
        "NOPs are skipped, and depth counts the root as 1"
    );
    match got[2] {
        Token::Property { value, .. } => assert_eq!(value, b"v\0"),
        _ => panic!("third token is the property"),
    }
}

#[test]
fn the_real_qemu_virt_tree_parses() {
    // Generated by QEMU 11.0.3 and re-serialised by dtc to drop QEMU's 1 MiB of padding:
    //   qemu-system-aarch64 -machine virt,gic-version=3,dumpdtb=virt.dtb -cpu max -m 128M
    //   dtc -I dtb -O dtb -o qemu-virt-gicv3-128m.dtb virt.dtb
    // It exercises what the hand-built trees do not: dozens of nodes, three-cell PCI
    // addresses, stringlists, and a strings block shared by all of them.
    let blob = include_bytes!("testdata/qemu-virt-gicv3-128m.dtb");
    let fdt = Fdt::new(blob).unwrap();
    assert_eq!(fdt.reservations().count(), 0);
    assert!(fdt.tokens().count() > 100, "a real tree, not a stub");
    assert_eq!(map_of(blob), Ok(vec![region(0x4000_0000, 128 << 20, MemoryKind::Usable)]));
}

// --- truncation --------------------------------------------------------------------

#[test]
fn every_truncated_buffer_is_rejected_without_a_fault() {
    let blob = machine().finish();
    for n in 0..blob.len() {
        // Short of the header, the header is what is missing; past it, the header
        // is readable and names the whole blob as what is needed.
        let needed = if n < HEADER_LEN {
            HEADER_LEN
        } else {
            blob.len()
        };
        assert_eq!(
            Fdt::new(&blob[..n]).err(),
            Some(Error::Truncated {
                needed,
                available: n
            }),
            "prefix of {n} bytes"
        );
    }
}

/// Offsets of every token boundary in a structure block, found by walking it.
fn token_boundaries(blob: &[u8]) -> Vec<usize> {
    let fdt = Fdt::new(blob).unwrap();
    let mut v: Vec<usize> = fdt
        .tokens()
        .map(|t| match t.unwrap() {
            Token::BeginNode { offset, .. }
            | Token::EndNode { offset, .. }
            | Token::Property { offset, .. } => offset,
        })
        .collect();
    let h = fdt.header();
    let end = usize::try_from(h.struct_offset + h.struct_size).unwrap();
    v.push(end - 4); // FDT_END
    v
}

#[test]
fn a_structure_block_cut_at_any_byte_is_rejected() {
    // `size_dt_struct` shrunk one byte at a time with everything else intact: the
    // walk must notice at every length, including exactly on a token boundary where
    // what is missing is only the rest of the tree.
    let blob = machine().finish();
    let size = get(&blob, FIELD_SIZE_STRUCT);
    for cut in 0..size {
        let mut b = blob.clone();
        put(&mut b, FIELD_SIZE_STRUCT, cut);
        let e = Fdt::new(&b).err();
        assert!(
            matches!(
                e,
                Some(Error::TruncatedStructure { .. } | Error::MissingEnd { .. })
                    | Some(Error::UnterminatedNodeName { .. })
            ),
            "size_dt_struct {cut} of {size}: {e:?}"
        );
    }
}

#[test]
fn a_cut_at_each_token_boundary_names_the_end_of_the_block() {
    let blob = machine().finish();
    let off = usize::try_from(get(&blob, FIELD_OFF_STRUCT)).unwrap();
    for boundary in token_boundaries(&blob) {
        let mut b = blob.clone();
        put(&mut b, FIELD_SIZE_STRUCT, u32::try_from(boundary - off).unwrap());
        assert_eq!(
            Fdt::new(&b).err(),
            Some(Error::MissingEnd { offset: boundary }),
            "cut at token boundary {boundary:#x}"
        );
    }
}

#[test]
fn a_cut_inside_a_property_value_is_truncation_at_that_property() {
    let mut d = Dtb::new();
    d.begin("").prop("big", &[0xaa; 64]).end();
    let blob = d.finish();
    // The root's FDT_BEGIN_NODE and its padded empty name take eight bytes.
    let prop_at = usize::try_from(get(&blob, FIELD_OFF_STRUCT)).unwrap() + 8;
    // Cut inside the length, inside the name offset, just after it, and mid-value.
    for cut in [12, 16, 20, 48] {
        let mut b = blob.clone();
        put(&mut b, FIELD_SIZE_STRUCT, cut);
        assert_eq!(
            Fdt::new(&b).err(),
            Some(Error::TruncatedStructure { offset: prop_at }),
            "cut at {cut}"
        );
    }
}

#[test]
fn a_strings_block_cut_short_is_rejected() {
    // Every shorter strings block loses at least the final terminator, which some
    // property's name depends on.
    let blob = machine().finish();
    let size = get(&blob, FIELD_SIZE_STRINGS);
    for cut in 0..size {
        let mut b = blob.clone();
        put(&mut b, FIELD_SIZE_STRINGS, cut);
        let e = Fdt::new(&b).err();
        assert!(
            matches!(
                e,
                Some(Error::NameOffsetOutOfRange { .. } | Error::UnterminatedPropertyName { .. })
            ),
            "size_dt_strings {cut} of {size}: {e:?}"
        );
    }
}

#[test]
fn a_reservation_block_without_a_terminator_is_rejected() {
    // A blob whose only reservation data is non-zero all the way to totalsize.
    let mut d = Dtb::new();
    d.begin("").end();
    let mut blob = d.finish();
    // Append 24 bytes of non-zero junk and point the reservation block at it: one
    // whole entry fits, the second runs off the end of totalsize.
    let total = blob.len();
    blob.extend_from_slice(&[0x11; 24]);
    put(&mut blob, FIELD_TOTALSIZE, u32::try_from(total + 24).unwrap());
    put(&mut blob, FIELD_OFF_RSVMAP, u32::try_from(total).unwrap());
    assert_eq!(
        Fdt::new(&blob).err(),
        Some(Error::UnterminatedReservations { offset: total + 16 })
    );
}

// --- header ------------------------------------------------------------------------

#[test]
fn a_bad_magic_is_rejected_first() {
    let mut blob = machine().finish();
    put(&mut blob, FIELD_MAGIC, 0xfeed_d00d);
    assert_eq!(Fdt::new(&blob).err(), Some(Error::BadMagic(0xfeed_d00d)));
    // Little-endian magic is the classic mistake, and it is a different number.
    put(&mut blob, FIELD_MAGIC, MAGIC.swap_bytes());
    assert_eq!(Fdt::new(&blob).err(), Some(Error::BadMagic(0xedfe_0dd0)));
    // Zeroed memory, which is what a probe of an empty base of RAM reads.
    assert_eq!(Fdt::new(&[0u8; 64]).err(), Some(Error::BadMagic(0)));
    assert_eq!(Header::parse(&[0u8; 8]).err(), Some(Error::BadMagic(0)));
}

#[test]
fn unsupported_versions_are_rejected() {
    let blob = machine().finish();
    for (version, last) in [(16, 16), (1, 1), (18, 18), (u32::MAX, u32::MAX)] {
        let mut b = blob.clone();
        put(&mut b, FIELD_VERSION, version);
        put(&mut b, FIELD_LAST_COMP, last);
        assert_eq!(
            Fdt::new(&b).err(),
            Some(Error::UnsupportedVersion {
                version,
                last_compatible: last
            })
        );
    }
    // A newer tree that declares itself readable by a version-17 parser is accepted.
    let mut b = blob.clone();
    put(&mut b, FIELD_VERSION, 18);
    put(&mut b, FIELD_LAST_COMP, 17);
    assert!(Fdt::new(&b).is_ok());
}

#[test]
fn a_totalsize_smaller_than_the_header_is_rejected() {
    let blob = machine().finish();
    for total in [0, 1, 39] {
        let mut b = blob.clone();
        put(&mut b, FIELD_TOTALSIZE, total);
        assert_eq!(Fdt::new(&b).err(), Some(Error::BadTotalSize(total)));
    }
}

#[test]
fn a_totalsize_larger_than_the_buffer_is_truncation() {
    let mut blob = machine().finish();
    let real = blob.len();
    put(&mut blob, FIELD_TOTALSIZE, u32::MAX);
    assert_eq!(
        Fdt::new(&blob).err(),
        Some(Error::Truncated {
            needed: usize::try_from(u32::MAX).unwrap(),
            available: real
        })
    );
}

#[test]
fn block_offsets_outside_totalsize_are_rejected() {
    let blob = machine().finish();
    let total = u32::try_from(blob.len()).unwrap();
    let cases = [
        // (offset field, size field or None, block)
        (FIELD_OFF_STRUCT, Some(FIELD_SIZE_STRUCT), Block::Structure),
        (FIELD_OFF_STRINGS, Some(FIELD_SIZE_STRINGS), Block::Strings),
        (FIELD_OFF_RSVMAP, None, Block::MemoryReservation),
    ];
    for (off_field, size_field, which) in cases {
        let size = size_field.map_or(RESERVATION_LEN_U32, |f| get(&blob, f));
        let original = get(&blob, off_field);
        for bad in [
            total,                                  // starts at the end
            total - size + 1,                       // ends one byte past the end
            u32::MAX,                               // nowhere
            u32::MAX - size + 1,                    // wraps a 32-bit add to zero
            0,                                      // inside the header
            u32::try_from(HEADER_LEN - 1).unwrap(), // overlaps the header's last byte
        ] {
            let mut b = blob.clone();
            put(&mut b, off_field, bad);
            let e = Fdt::new(&b).err();
            assert_eq!(
                e,
                Some(Error::BlockOutOfBounds {
                    block: which,
                    offset: bad,
                    size
                }),
                "{which:?} at {bad:#x} (was {original:#x})"
            );
            assert_eq!(e.unwrap().offset(), off_field);
        }
        if let Some(f) = size_field {
            // And a size that reaches past the end from a valid offset.
            for bad_size in [total - original + 1, u32::MAX] {
                let mut b = blob.clone();
                put(&mut b, f, bad_size);
                assert_eq!(
                    Fdt::new(&b).err(),
                    Some(Error::BlockOutOfBounds {
                        block: which,
                        offset: original,
                        size: bad_size
                    })
                );
            }
        }
    }
}

// --- strings -----------------------------------------------------------------------

#[test]
fn a_property_name_offset_out_of_range_is_rejected() {
    for bad in [u32::MAX, 1 << 20] {
        let mut d = Dtb::new();
        d.begin("").cells("#address-cells", &[2]);
        let prop_at = HEADER_LEN + RESERVATION_LEN + d.structure.len();
        d.prop_at(bad, &[1, 2, 3, 4]).end();
        assert_eq!(
            Fdt::new(&d.finish()).err(),
            Some(Error::NameOffsetOutOfRange {
                offset: prop_at,
                name_offset: bad
            })
        );
    }
    // Exactly the block size: one past the last byte is out of range too.
    let mut d = Dtb::new();
    d.begin("").cells("#address-cells", &[2]);
    let len = u32::try_from(d.strings.len()).unwrap();
    d.prop_at(len, &[]).end();
    assert!(matches!(
        Fdt::new(&d.finish()).err(),
        Some(Error::NameOffsetOutOfRange { name_offset, .. }) if name_offset == len
    ));
}

#[test]
fn a_property_name_running_off_the_strings_block_is_rejected() {
    let mut d = Dtb::new();
    d.begin("").cells("#address-cells", &[2]).end();
    // Replace the strings block's final terminator: the name now runs into the end of
    // the block. The byte is still inside the blob, so this is the strings bound
    // being enforced and not the blob's.
    let mut blob = d.finish();
    let last = blob.len() - 1;
    blob[last] = b'x';
    blob.push(0);
    assert_eq!(
        Fdt::new(&blob).err(),
        Some(Error::UnterminatedPropertyName {
            offset: HEADER_LEN + RESERVATION_LEN + 8,
            name_offset: 0
        })
    );
}

#[test]
fn a_node_name_running_off_the_structure_block_is_rejected() {
    let mut d = Dtb::new();
    d.token(FDT_BEGIN_NODE);
    d.structure.extend_from_slice(b"abcdefgh"); // no NUL
    let blob = d.finish_raw();
    assert_eq!(
        Fdt::new(&blob).err(),
        Some(Error::UnterminatedNodeName {
            offset: HEADER_LEN + RESERVATION_LEN
        })
    );
}

// --- structure ---------------------------------------------------------------------

#[test]
fn nesting_deeper_than_any_real_tree_is_rejected() {
    let deep = |levels: usize| {
        let mut d = Dtb::new();
        for i in 0..levels {
            d.begin(if i == 0 { "" } else { "n" });
        }
        for _ in 0..levels {
            d.end();
        }
        d.finish()
    };
    assert!(Fdt::new(&deep(MAX_DEPTH)).is_ok(), "the cap itself is allowed");
    let blob = deep(MAX_DEPTH + 1);
    // Root BEGIN_NODE is 8 bytes (token + padded empty name); every other is 8 too.
    let offender = HEADER_LEN + RESERVATION_LEN + 8 * MAX_DEPTH;
    assert_eq!(Fdt::new(&blob).err(), Some(Error::NestingTooDeep { offset: offender }));
    // And far deeper, which a fixed-size stack must survive without indexing past it.
    assert!(matches!(Fdt::new(&deep(4096)).err(), Some(Error::NestingTooDeep { .. })));
}

#[test]
fn an_unknown_token_is_rejected() {
    let mut d = Dtb::new();
    d.begin("");
    let at = HEADER_LEN + RESERVATION_LEN + d.structure.len();
    d.token(0x5).end();
    assert_eq!(
        Fdt::new(&d.finish()).err(),
        Some(Error::UnknownToken {
            offset: at,
            token: 5
        })
    );
}

#[test]
fn unbalanced_structure_is_rejected() {
    let base = HEADER_LEN + RESERVATION_LEN;

    let mut d = Dtb::new();
    d.end();
    assert_eq!(Fdt::new(&d.finish()).err(), Some(Error::UnbalancedEndNode { offset: base }));

    let mut d = Dtb::new();
    d.begin("").end().end();
    assert_eq!(
        Fdt::new(&d.finish()).err(),
        Some(Error::UnbalancedEndNode { offset: base + 12 })
    );

    let mut d = Dtb::new();
    d.begin("").begin("a");
    assert_eq!(
        Fdt::new(&d.finish()).err(),
        Some(Error::EndInsideNode {
            offset: base + 16,
            depth: 2
        })
    );

    let d = Dtb::new();
    assert_eq!(Fdt::new(&d.finish()).err(), Some(Error::NoRootNode { offset: base }));

    let mut d = Dtb::new();
    d.nop().nop();
    assert_eq!(Fdt::new(&d.finish()).err(), Some(Error::NoRootNode { offset: base + 8 }));

    let mut d = Dtb::new();
    d.begin("").end().begin("").end();
    assert_eq!(Fdt::new(&d.finish()).err(), Some(Error::MultipleRoots { offset: base + 12 }));
}

#[test]
fn properties_must_belong_to_a_node_and_precede_its_subnodes() {
    let base = HEADER_LEN + RESERVATION_LEN;

    let mut d = Dtb::new();
    d.cells("#address-cells", &[1]).begin("").end();
    assert_eq!(Fdt::new(&d.finish()).err(), Some(Error::PropertyOutsideNode { offset: base }));

    let mut d = Dtb::new();
    d.begin("").end().cells("#address-cells", &[1]);
    assert_eq!(
        Fdt::new(&d.finish()).err(),
        Some(Error::PropertyOutsideNode { offset: base + 12 })
    );

    // The case that matters for cell counts: a parent's #address-cells arriving after
    // a child whose reg would already have been read with the default.
    let mut d = Dtb::new();
    d.begin("").begin("memory").end();
    let at = base + d.structure.len();
    d.cells("#address-cells", &[1]).end();
    assert_eq!(Fdt::new(&d.finish()).err(), Some(Error::PropertyAfterSubnode { offset: at }));

    // Properties of a child after the child's own subnode closes are equally out of
    // order; properties of the parent after one child closed and before the next are
    // too.
    let mut d = Dtb::new();
    d.begin("").begin("a").begin("b").end();
    let at = base + d.structure.len();
    d.str_prop("late", "x").end().end();
    assert_eq!(Fdt::new(&d.finish()).err(), Some(Error::PropertyAfterSubnode { offset: at }));

    // A sibling's properties are not affected by an earlier sibling's children.
    let mut d = Dtb::new();
    d.begin("")
        .begin("a")
        .begin("a1")
        .end()
        .end()
        .begin("b")
        .str_prop("fine", "y")
        .end()
        .end();
    assert!(Fdt::new(&d.finish()).is_ok());
}

#[test]
fn nops_anywhere_are_skipped() {
    let mut d = Dtb::new();
    d.nop()
        .begin("")
        .nop()
        .cells("#address-cells", &[1])
        .cells("#size-cells", &[1])
        .nop()
        .begin("memory@0")
        .nop()
        .str_prop("device_type", "memory")
        .nop()
        .cells("reg", &[0x1000, 0x2000])
        .end()
        .nop()
        .end()
        .nop();
    assert_eq!(map_of(&d.finish()), Ok(vec![region(0x1000, 0x2000, MemoryKind::Usable)]));
}

#[test]
fn a_structure_of_only_nops_ends_at_the_block_not_beyond() {
    let mut d = Dtb::new();
    for _ in 0..16 {
        d.nop();
    }
    let blob = d.finish_raw();
    let end = HEADER_LEN + RESERVATION_LEN + 64;
    assert_eq!(Fdt::new(&blob).err(), Some(Error::MissingEnd { offset: end }));
}

// --- reg and cell counts -----------------------------------------------------------

#[test]
fn a_reg_that_is_not_a_whole_number_of_entries_is_rejected() {
    for (ac, sc, len) in [
        (2u32, 2u32, 12usize),
        (2, 2, 20),
        (1, 1, 4),
        (2, 1, 8),
        (1, 0, 6),
    ] {
        let mut d = Dtb::new();
        d.begin("")
            .cells("#address-cells", &[ac])
            .cells("#size-cells", &[sc])
            .begin("memory@0")
            .str_prop("device_type", "memory");
        let at = HEADER_LEN + RESERVATION_LEN + d.structure.len();
        d.prop("reg", &vec![0u8; len]).end().end();
        let entry = usize::try_from((ac + sc) * 4).unwrap();
        assert_eq!(
            map_of(&d.finish()),
            Err(Error::RegLength {
                offset: at,
                len,
                entry
            }),
            "{ac}/{sc} cells, {len} bytes"
        );
    }
}

/// One memory node under a root with the given cell counts and `reg` cells.
fn memory_with_cells(ac: Option<u32>, sc: Option<u32>, reg: &[u32]) -> Vec<u8> {
    let mut d = Dtb::new();
    d.begin("");
    if let Some(ac) = ac {
        d.cells("#address-cells", &[ac]);
    }
    if let Some(sc) = sc {
        d.cells("#size-cells", &[sc]);
    }
    d.begin("memory")
        .str_prop("device_type", "memory")
        .cells("reg", reg)
        .end()
        .end();
    d.finish()
}

#[test]
fn one_one_cells_as_on_a_raspberry_pi_3() {
    // Two banks, eight bytes an entry. Read with 2/2 this would be one entry at
    // address 0 and size 0x3b400000_00000000, which is what a hardcoded parser gets.
    let blob = memory_with_cells(Some(1), Some(1), &[0, 0x3b40_0000, 0x4000_0000, 0x1000_0000]);
    assert_eq!(
        map_of(&blob),
        Ok(vec![
            region(0, 0x3b40_0000, MemoryKind::Usable),
            region(0x4000_0000, 0x1000_0000, MemoryKind::Usable),
        ])
    );
}

#[test]
fn two_one_cells() {
    let blob = memory_with_cells(Some(2), Some(1), &[0x1, 0x0000_0000, 0x8000_0000]);
    assert_eq!(map_of(&blob), Ok(vec![region(0x1_0000_0000, 0x8000_0000, MemoryKind::Usable)]));
}

#[test]
fn absent_cell_counts_take_the_specification_defaults_of_two_and_one() {
    let blob = memory_with_cells(None, None, &[0x0, 0x4000_0000, 0x0800_0000]);
    assert_eq!(map_of(&blob), Ok(vec![region(0x4000_0000, 0x0800_0000, MemoryKind::Usable)]));
    // Only one of the two given: the other still defaults.
    let blob = memory_with_cells(Some(1), None, &[0x4000_0000, 0x0800_0000]);
    assert_eq!(map_of(&blob), Ok(vec![region(0x4000_0000, 0x0800_0000, MemoryKind::Usable)]));
    let blob = memory_with_cells(None, Some(2), &[0, 0x4000_0000, 0, 0x0800_0000]);
    assert_eq!(map_of(&blob), Ok(vec![region(0x4000_0000, 0x0800_0000, MemoryKind::Usable)]));
}

#[test]
fn wide_cells_are_accepted_when_the_value_fits() {
    let blob = memory_with_cells(Some(3), Some(2), &[0, 0, 0x4000_0000, 0, 0x1000]);
    assert_eq!(map_of(&blob), Ok(vec![region(0x4000_0000, 0x1000, MemoryKind::Usable)]));
    let blob = memory_with_cells(Some(3), Some(2), &[1, 0, 0x4000_0000, 0, 0x1000]);
    assert!(matches!(map_of(&blob), Err(Error::ValueTooWide { .. })));
    // Three size cells holding 4 GiB: the middle cell is the high half, and it fits.
    let blob = memory_with_cells(Some(2), Some(3), &[0, 0x4000_0000, 0, 1, 0]);
    assert_eq!(map_of(&blob), Ok(vec![region(0x4000_0000, 1 << 32, MemoryKind::Usable)]));
    let blob = memory_with_cells(Some(2), Some(3), &[0, 0x4000_0000, 1, 0, 0]);
    assert!(matches!(map_of(&blob), Err(Error::ValueTooWide { .. })));
}

#[test]
fn cell_counts_that_cannot_describe_a_region_are_rejected() {
    let blob = memory_with_cells(Some(0), Some(0), &[]);
    assert!(
        matches!(
            map_of(&blob),
            Err(Error::UnsupportedCells {
                address_cells: 0,
                size_cells: 0,
                ..
            })
        ),
        "zero-width entries must not become an infinite loop"
    );
    let blob = memory_with_cells(Some(MAX_CELLS + 1), Some(1), &[0; 6]);
    assert!(matches!(map_of(&blob), Err(Error::UnsupportedCells { .. })));
    let blob = memory_with_cells(Some(u32::MAX), Some(u32::MAX), &[0; 2]);
    assert!(matches!(map_of(&blob), Err(Error::UnsupportedCells { .. })));
}

#[test]
fn a_zero_size_cell_count_yields_nothing_usable() {
    // Legal for a bus, meaningless for memory: every entry has size zero.
    let blob = memory_with_cells(Some(1), Some(0), &[0x4000_0000]);
    assert_eq!(map_of(&blob), Err(Error::NoMemory));
}

#[test]
fn a_malformed_cell_count_is_reported_only_where_it_is_used() {
    // On a node whose children nobody reads, it does not cost the memory map.
    let mut d = Dtb::new();
    d.begin("")
        .cells("#address-cells", &[1])
        .cells("#size-cells", &[1])
        .begin("memory")
        .str_prop("device_type", "memory")
        .cells("reg", &[0x1000, 0x1000])
        .end()
        .begin("bus")
        .prop("#address-cells", &[0, 1])
        .end()
        .end();
    assert_eq!(map_of(&d.finish()), Ok(vec![region(0x1000, 0x1000, MemoryKind::Usable)]));

    // On the root, it does.
    let mut d = Dtb::new();
    d.begin("");
    let at = HEADER_LEN + RESERVATION_LEN + d.structure.len();
    d.prop("#address-cells", &[0, 0, 0, 1, 0])
        .begin("memory")
        .str_prop("device_type", "memory")
        .cells("reg", &[0, 0x1000, 0x1000])
        .end()
        .end();
    assert_eq!(map_of(&d.finish()), Err(Error::BadCellsProperty { offset: at }));
}

#[test]
fn cells_come_from_the_parent_not_the_root_and_not_the_node_itself() {
    // Root 2/2; /reserved-memory 1/1; the reservation's own node claims 2/2, which
    // must not apply to its own reg.
    let mut d = Dtb::new();
    d.begin("")
        .cells("#address-cells", &[2])
        .cells("#size-cells", &[2])
        .begin("memory@40000000")
        .str_prop("device_type", "memory")
        .cells("reg", &[0, 0x4000_0000, 0, 0x4000_0000])
        .end()
        .begin("reserved-memory")
        .cells("#address-cells", &[1])
        .cells("#size-cells", &[1])
        .begin("fw@48000000")
        .cells("#address-cells", &[2])
        .cells("#size-cells", &[2])
        .cells("reg", &[0x4800_0000, 0x0020_0000, 0x4900_0000, 0x1000])
        .end()
        .end()
        .end();
    assert_eq!(
        map_of(&d.finish()),
        Ok(vec![
            region(0x4000_0000, 0x4000_0000, MemoryKind::Usable),
            region(0x4800_0000, 0x0020_0000, MemoryKind::Reserved),
            region(0x4900_0000, 0x1000, MemoryKind::Reserved),
        ])
    );
}

#[test]
fn a_sibling_does_not_inherit_an_earlier_siblings_cells() {
    let mut d = Dtb::new();
    d.begin("")
        .begin("soc")
        .cells("#address-cells", &[1])
        .cells("#size-cells", &[1])
        .end()
        // /reserved-memory declares nothing, so its children use 2/1, not soc's 1/1.
        .begin("reserved-memory")
        .begin("r")
        .cells("reg", &[0, 0x5000_0000, 0x1000])
        .end()
        .end()
        .begin("memory")
        .str_prop("device_type", "memory")
        .cells("reg", &[0, 0x4000_0000, 0x1000_0000])
        .end()
        .end();
    assert_eq!(
        map_of(&d.finish()),
        Ok(vec![
            region(0x5000_0000, 0x1000, MemoryKind::Reserved),
            region(0x4000_0000, 0x1000_0000, MemoryKind::Usable),
        ])
    );
}

#[test]
fn a_region_past_the_top_of_the_address_space_is_rejected() {
    let blob = memory_with_cells(Some(2), Some(2), &[0xffff_ffff, 0xffff_f000, 0, 0x2000]);
    assert!(matches!(map_of(&blob), Err(Error::RegionOverflow { .. })));

    let mut d = Dtb::new();
    d.reserve(u64::MAX - 10, 11).begin("").end();
    assert_eq!(Fdt::new(&d.finish()).err(), Some(Error::RegionOverflow { offset: HEADER_LEN }));
}

// --- what counts as memory ---------------------------------------------------------

#[test]
fn only_device_type_memory_makes_ram() {
    // Named like memory, but not declared as memory: not RAM.
    let mut d = Dtb::new();
    d.begin("")
        .begin("memory@40000000")
        .cells("reg", &[0, 0x4000_0000, 0x1000])
        .end()
        .begin("sram@0")
        .str_prop("device_type", "memoryx")
        .cells("reg", &[0, 0x1000, 0x1000])
        .end()
        .begin("ram@0")
        .prop("device_type", b"memory") // no terminator: not a string
        .cells("reg", &[0, 0x2000, 0x1000])
        .end()
        .end();
    assert_eq!(map_of(&d.finish()), Err(Error::NoMemory));
}

#[test]
fn device_type_may_follow_reg_within_the_node() {
    // QEMU writes reg before device_type, so the decision is made when the node closes.
    let blob = include_bytes!("testdata/qemu-virt-gicv3-128m.dtb");
    let fdt = Fdt::new(blob).unwrap();
    let mut in_memory = false;
    let mut order = Vec::new();
    for t in fdt.tokens() {
        match t.unwrap() {
            Token::BeginNode { name, .. } => in_memory = name.starts_with(b"memory"),
            Token::Property { name, .. } if in_memory => order.push(name.to_vec()),
            _ => {}
        }
    }
    assert_eq!(order, vec![b"reg".to_vec(), b"device_type".to_vec()]);
}

#[test]
fn a_disabled_memory_node_is_not_ram_but_a_disabled_reservation_still_reserves() {
    let mut d = Dtb::new();
    d.begin("")
        .cells("#address-cells", &[1])
        .cells("#size-cells", &[1])
        .begin("memory@0")
        .str_prop("device_type", "memory")
        .str_prop("status", "disabled")
        .cells("reg", &[0, 0x1000_0000])
        .end()
        .begin("memory@40000000")
        .str_prop("device_type", "memory")
        .str_prop("status", "okay")
        .cells("reg", &[0x4000_0000, 0x1000_0000])
        .end()
        .begin("memory@80000000")
        .str_prop("device_type", "memory")
        .str_prop("status", "ok")
        .cells("reg", &[0x8000_0000, 0x1000])
        .end()
        .begin("reserved-memory")
        .cells("#address-cells", &[1])
        .cells("#size-cells", &[1])
        .begin("r")
        .str_prop("status", "disabled")
        .cells("reg", &[0x4000_0000, 0x1000])
        .end()
        .end()
        .end();
    assert_eq!(
        map_of(&d.finish()),
        Ok(vec![
            region(0x4000_0000, 0x1000_0000, MemoryKind::Usable),
            region(0x8000_0000, 0x1000, MemoryKind::Usable),
            region(0x4000_0000, 0x1000, MemoryKind::Reserved),
        ])
    );
}

#[test]
fn memory_nodes_count_only_as_children_of_the_root() {
    let mut d = Dtb::new();
    d.begin("")
        .cells("#address-cells", &[1])
        .cells("#size-cells", &[1])
        .begin("memory@0")
        .str_prop("device_type", "memory")
        .cells("reg", &[0x1000, 0x1000])
        // A nested node pretending to be memory is not a /memory node.
        .begin("memory@9000")
        .str_prop("device_type", "memory")
        .cells("reg", &[0x9000, 0x1000])
        .end()
        .end()
        .begin("soc")
        .begin("memory@a000")
        .str_prop("device_type", "memory")
        .cells("reg", &[0xa000, 0x1000])
        .end()
        .end()
        .end();
    assert_eq!(map_of(&d.finish()), Ok(vec![region(0x1000, 0x1000, MemoryKind::Usable)]));
}

#[test]
fn a_dynamic_reservation_without_reg_reserves_nothing_fixed() {
    // `size` + `alloc-ranges` asks the OS to choose; there is no fixed range to report.
    let mut d = Dtb::new();
    d.begin("")
        .cells("#address-cells", &[1])
        .cells("#size-cells", &[1])
        .begin("memory")
        .str_prop("device_type", "memory")
        .cells("reg", &[0x4000_0000, 0x1000_0000])
        .end()
        .begin("reserved-memory")
        .cells("#address-cells", &[1])
        .cells("#size-cells", &[1])
        .begin("cma")
        .cells("size", &[0x0400_0000])
        .end()
        .end()
        .end();
    assert_eq!(
        map_of(&d.finish()),
        Ok(vec![region(0x4000_0000, 0x1000_0000, MemoryKind::Usable)])
    );
}

#[test]
fn zero_length_regions_are_omitted_but_nonzero_reservations_kept() {
    let mut d = Dtb::new();
    d.reserve(0x1234, 0) // size zero, address non-zero: not the terminator
        .reserve(0x4000_0000, 0x2000)
        .begin("")
        .cells("#address-cells", &[1])
        .cells("#size-cells", &[1])
        .begin("memory")
        .str_prop("device_type", "memory")
        .cells("reg", &[0x0, 0x0, 0x4000_0000, 0x1000_0000])
        .end()
        .end();
    let blob = d.finish();
    assert_eq!(Fdt::new(&blob).unwrap().reservations().count(), 2);
    assert_eq!(
        map_of(&blob),
        Ok(vec![
            region(0x4000_0000, 0x2000, MemoryKind::Reserved),
            region(0x4000_0000, 0x1000_0000, MemoryKind::Usable),
        ])
    );
}

#[test]
fn a_tree_with_no_memory_is_an_error_not_an_empty_map() {
    let mut d = Dtb::new();
    d.reserve(0x4000_0000, 0x1000).begin("").end();
    assert_eq!(map_of(&d.finish()), Err(Error::NoMemory));
}

#[test]
fn running_out_of_output_is_reported_not_truncated() {
    let blob = machine().finish();
    let fdt = Fdt::new(&blob).unwrap();
    for capacity in 0..3 {
        let mut out = vec![EMPTY; capacity];
        assert_eq!(fdt.memory_map(&mut out), Err(Error::TooManyRegions { capacity }));
    }
    let mut out = [EMPTY; 3];
    assert_eq!(fdt.memory_map(&mut out), Ok(3));
}

// --- robustness --------------------------------------------------------------------

#[test]
fn corrupting_any_single_byte_never_faults() {
    // Not a claim about which error comes back — some corruptions are harmless — only
    // that every one of them is an answer and not a panic. Three corruptions per byte:
    // all ones, all zeros, and a single flipped bit.
    let blob = machine().finish();
    for i in 0..blob.len() {
        let corruptions: [fn(u8) -> u8; 3] = [|_| 0xff, |_| 0x00, |b| b ^ 0x10];
        for f in corruptions {
            let mut b = blob.clone();
            b[i] = f(b[i]);
            if let Ok(fdt) = Fdt::new(&b) {
                let mut out = [EMPTY; 8];
                let _ = fdt.memory_map(&mut out);
                let _ = fdt.reservations().count();
            }
        }
    }
}

#[test]
fn random_corruption_never_faults() {
    // A fixed-seed xorshift, so a failure is reproducible.
    let mut state = 0x9e37_79b9_7f4a_7c15u64;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    let clean = include_bytes!("testdata/qemu-virt-gicv3-128m.dtb").to_vec();
    for _ in 0..2000 {
        let mut b = clean.clone();
        for _ in 0..(next() % 8 + 1) {
            let i = usize::try_from(next() % u64::try_from(b.len()).unwrap()).unwrap();
            b[i] = u8::try_from(next() & 0xff).unwrap();
        }
        if let Ok(fdt) = Fdt::new(&b) {
            let mut out = [EMPTY; 8];
            let _ = fdt.memory_map(&mut out);
        }
    }
}

#[test]
fn every_error_names_an_offset_inside_the_blob() {
    // Only for errors that are about a place; the diagnosis is useless otherwise.
    let blob = machine().finish();
    for i in 0..blob.len() {
        let mut b = blob.clone();
        b[i] ^= 0xff;
        if let Err(e) = Fdt::new(&b) {
            if !matches!(e, Error::Truncated { .. }) {
                assert!(e.offset() <= b.len(), "byte {i}: {e:?} at {}", e.offset());
            }
        }
    }
}

// --- /chosen -------------------------------------------------------------------------

#[test]
fn bootargs_are_read_from_chosen_and_only_from_chosen() {
    // A decoy `chosen` below the root must not count: only `/chosen` is the firmware's.
    let mut with = Dtb::new();
    with.begin("")
        .cells("#size-cells", &[2])
        .cells("#address-cells", &[2])
        .begin("memory@40000000")
        .cells("reg", &[0, 0x4000_0000, 0, 0x0800_0000])
        .str_prop("device_type", "memory")
        .begin("chosen")
        .str_prop("bootargs", "decoy")
        .end()
        .end()
        .begin("chosen")
        .str_prop("stdout-path", "/uart@9000000")
        .str_prop("bootargs", "mode=safe kintane.canary=x")
        .end()
        .end();
    let blob = with.finish();
    assert_eq!(
        Fdt::new(&blob).unwrap().bootargs(),
        Ok(Some(&b"mode=safe kintane.canary=x"[..]))
    );

    let blob = machine().finish();
    assert_eq!(Fdt::new(&blob).unwrap().bootargs(), Ok(None), "no /chosen, no line");

    let mut bad = Dtb::new();
    bad.begin("")
        .begin("chosen")
        .prop("bootargs", b"no terminator")
        .end()
        .end();
    let blob = bad.finish();
    assert!(matches!(Fdt::new(&blob).unwrap().bootargs(), Err(Error::BadString { .. })));
}

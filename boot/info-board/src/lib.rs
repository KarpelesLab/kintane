//! `bootinfo` for boards nothing starts: the memory map and command line, fixed at build
//! time.
//!
//! One of the units providing this name, alongside `boot/info-multiboot`,
//! `boot/info-kinboot`, `boot/info-fdt` and `boot/info-none`. A Cortex-M part is the
//! first code on its machine: the core loads the stack pointer and reset vector from the
//! vector table and runs, with nothing in any register that describes memory. The
//! loader's memory map is therefore a property of the board, and roadmap Phase 4 puts it
//! where properties of a build go. The board's file under `config/boards/` sets
//! `BOARD_MEMORY`; kbuild emits it into the generated configuration; and [`MAP`] parses
//! it **at compile time**, so a description that does not parse is a build error rather
//! than a boot that trusts a wrong map.
//!
//! The command line is built the same way, from the configuration a KinTane loader's
//! default entry would have handed over: `mode=` the configured `BOOT_MODE`, then
//! `CMDLINE`. So `kmain`'s command-line check means the same thing on every port: the
//! line the build meant is the line the kernel got.
//!
//! What this cannot do is notice a board that differs from its description. A loader's
//! map is measured; this one is asserted. The board check that closes that gap is a
//! probe of each region, and is not written.

#![cfg_attr(not(test), no_std)]

use boot_protocol::{MemoryKind, MemoryRegion};

/// Why a memory map could not be obtained. The same shape as every other provider's, so
/// `kmain` reports them alike.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Error {
    NoLoader,
    NoMemoryMap,
    Malformed { offset: usize },
    TooManyRegions { capacity: usize },
}

/// How this platform learns its memory layout, for the banner.
pub const SOURCE: &str = "board description, fixed at build time";

/// The most regions a board description may list.
pub const MAX_REGIONS: usize = 16;

/// Why a board description did not parse, and the byte offset in it where that was found.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ParseError {
    /// A kind other than those [`kind`] knows.
    UnknownKind(usize),
    /// A start or length that is not a `0x` hexadecimal number.
    BadNumber(usize),
    /// An entry with fewer than three fields, or more.
    BadEntry(usize),
    /// A zero length, or a region that runs past the top of a 64-bit address space.
    BadRange(usize),
    /// More than [`MAX_REGIONS`] entries.
    TooMany,
    /// No entries at all.
    Empty,
}

const EMPTY: MemoryRegion = MemoryRegion {
    start: 0,
    len: 0,
    kind: 0,
    _reserved: 0,
};

/// The board's memory map, parsed from `BOARD_MEMORY` when this crate is compiled.
///
/// A `const` item, so the parse runs in the compiler; a description it rejects stops
/// the build here with the reason, the first time anything refers to the map.
pub const MAP: ([MemoryRegion; MAX_REGIONS], usize) = match parse(kconfig::BOARD_MEMORY) {
    Ok(map) => map,
    Err(ParseError::UnknownKind(_)) => {
        panic!("BOARD_MEMORY names a memory kind that does not exist")
    }
    Err(ParseError::BadNumber(_)) => {
        panic!("BOARD_MEMORY has a start or length that is not 0x hex")
    }
    Err(ParseError::BadEntry(_)) => {
        panic!("BOARD_MEMORY has an entry that is not `kind start length`")
    }
    Err(ParseError::BadRange(_)) => panic!("BOARD_MEMORY has an empty or overflowing region"),
    Err(ParseError::TooMany) => panic!("BOARD_MEMORY lists more regions than info-board holds"),
    Err(ParseError::Empty) => panic!("BOARD_MEMORY is empty, but a board description was selected"),
};

/// Fill `out` with the board's memory map, returning how many regions were written.
///
/// # Safety
/// None required: nothing is dereferenced. `unsafe` so every provider has one signature.
pub unsafe fn memory_regions(_boot_arg: u64, out: &mut [MemoryRegion]) -> Result<usize, Error> {
    let (regions, n) = MAP;
    let capacity = out.len();
    let slot = out.get_mut(..n).ok_or(Error::TooManyRegions { capacity })?;
    slot.copy_from_slice(&regions[..n]);
    Ok(n)
}

/// Copy the command line the configuration's default boot entry would pass into `out`,
/// returning its length.
///
/// # Safety
/// None required, as for [`memory_regions`].
pub unsafe fn command_line(_boot_arg: u64, out: &mut [u8]) -> Result<Option<usize>, Error> {
    let mode = if kconfig::BOOT_MODE_SAFE {
        "safe"
    } else if kconfig::BOOT_MODE_RECOVERY {
        "recovery"
    } else {
        "normal"
    };
    compose(mode, kconfig::CMDLINE, out)
        .map(Some)
        .ok_or(Error::Malformed { offset: 0 })
}

/// `mode=<mode>`, then a space and `extra` with its surrounding whitespace trimmed if it
/// is not empty: the line kbuild's `bootcfg::kernel_command_line` writes for a `-kernel`
/// boot. `None` if it does not fit.
pub fn compose(mode: &str, extra: &str, out: &mut [u8]) -> Option<usize> {
    let extra = extra.trim();
    let parts: [&[u8]; 4] = if extra.is_empty() {
        [b"mode=", mode.as_bytes(), b"", b""]
    } else {
        [b"mode=", mode.as_bytes(), b" ", extra.as_bytes()]
    };
    let mut at = 0;
    for part in parts {
        let end = at + part.len();
        out.get_mut(at..end)?.copy_from_slice(part);
        at = end;
    }
    Some(at)
}

/// The boot protocol's kind for a name in a board description.
pub const fn kind(name: &[u8]) -> Option<MemoryKind> {
    match name {
        b"usable" => Some(MemoryKind::Usable),
        b"reserved" => Some(MemoryKind::Reserved),
        b"kernel-image" => Some(MemoryKind::KernelImage),
        b"boot-data" => Some(MemoryKind::BootData),
        b"bad" => Some(MemoryKind::Bad),
        _ => None,
    }
}

/// Parse a board description: `kind start length` entries separated by `;`, numbers in
/// `0x` hexadecimal, whitespace between fields.
///
/// A `const fn`, because [`MAP`] runs it in the compiler. That is also why it is written
/// with index loops rather than iterators.
pub const fn parse(desc: &str) -> Result<([MemoryRegion; MAX_REGIONS], usize), ParseError> {
    let b = desc.as_bytes();
    let mut out = [EMPTY; MAX_REGIONS];
    let mut n = 0;
    let mut i = 0;
    loop {
        // One entry: up to the next `;` or the end.
        let entry = i;
        let mut end = i;
        while end < b.len() && b[end] != b';' {
            end += 1;
        }
        let mut fields = [(0usize, 0usize); 3];
        let mut count = 0;
        let mut j = i;
        while j < end {
            while j < end && is_space(b[j]) {
                j += 1;
            }
            if j == end {
                break;
            }
            let start = j;
            while j < end && !is_space(b[j]) {
                j += 1;
            }
            if count == 3 {
                return Err(ParseError::BadEntry(start));
            }
            fields[count] = (start, j);
            count += 1;
        }
        let last = end >= b.len();
        if count == 0 {
            // An empty entry is allowed only as a trailing `;` or an empty description.
            if !last {
                return Err(ParseError::BadEntry(entry));
            }
        } else {
            if count != 3 {
                return Err(ParseError::BadEntry(entry));
            }
            if n == MAX_REGIONS {
                return Err(ParseError::TooMany);
            }
            let (ks, ke) = fields[0];
            let k = match kind(subslice(b, ks, ke)) {
                Some(k) => k,
                None => return Err(ParseError::UnknownKind(ks)),
            };
            let start = match hex(b, fields[1].0, fields[1].1) {
                Some(v) => v,
                None => return Err(ParseError::BadNumber(fields[1].0)),
            };
            let len = match hex(b, fields[2].0, fields[2].1) {
                Some(v) => v,
                None => return Err(ParseError::BadNumber(fields[2].0)),
            };
            if len == 0 || start.checked_add(len).is_none() {
                return Err(ParseError::BadRange(entry));
            }
            out[n] = MemoryRegion {
                start,
                len,
                kind: k as u32,
                _reserved: 0,
            };
            n += 1;
        }
        if last {
            break;
        }
        i = end + 1;
    }
    if n == 0 {
        return Err(ParseError::Empty);
    }
    Ok((out, n))
}

const fn is_space(c: u8) -> bool {
    c == b' ' || c == b'\t' || c == b'\n' || c == b'\r'
}

/// `b[start..end]`, which a `const fn` cannot write as an index expression on a slice.
const fn subslice(b: &[u8], start: usize, end: usize) -> &[u8] {
    let (head, _) = b.split_at(end);
    let (_, tail) = head.split_at(start);
    tail
}

/// `0x`-prefixed hexadecimal in `b[start..end]`, at most 16 digits.
const fn hex(b: &[u8], start: usize, end: usize) -> Option<u64> {
    if end - start < 3 || b[start] != b'0' || (b[start + 1] != b'x' && b[start + 1] != b'X') {
        return None;
    }
    if end - start - 2 > 16 {
        return None;
    }
    let mut v: u64 = 0;
    let mut i = start + 2;
    while i < end {
        let d = match b[i] {
            c @ b'0'..=b'9' => c - b'0',
            c @ b'a'..=b'f' => c - b'a' + 10,
            c @ b'A'..=b'F' => c - b'A' + 10,
            _ => return None,
        };
        v = (v << 4) | d as u64;
        i += 1;
    }
    Some(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn region(kind: MemoryKind, start: u64, len: u64) -> MemoryRegion {
        MemoryRegion {
            start,
            len,
            kind: kind as u32,
            _reserved: 0,
        }
    }

    #[test]
    fn the_mps2_an385_description_parses_as_its_board() {
        let (map, n) = parse(
            "kernel-image 0x00000000 0x00400000; usable 0x20000000 0x00400000; \
             usable 0x21000000 0x01000000",
        )
        .unwrap();
        assert_eq!(
            &map[..n],
            &[
                region(MemoryKind::KernelImage, 0, 0x40_0000),
                region(MemoryKind::Usable, 0x2000_0000, 0x40_0000),
                region(MemoryKind::Usable, 0x2100_0000, 0x100_0000),
            ]
        );
    }

    #[test]
    fn whitespace_and_a_trailing_separator_are_accepted() {
        let (_, n) = parse("  usable\t0x1000   0x2000 ;\n").unwrap();
        assert_eq!(n, 1);
    }

    #[test]
    fn every_malformed_description_is_refused_with_where() {
        assert_eq!(parse(""), Err(ParseError::Empty));
        assert_eq!(parse(" ; "), Err(ParseError::BadEntry(0)));
        assert_eq!(parse("ram 0x0 0x10"), Err(ParseError::UnknownKind(0)));
        assert_eq!(parse("usable 10 0x10"), Err(ParseError::BadNumber(7)));
        assert_eq!(parse("usable 0x 0x10"), Err(ParseError::BadNumber(7)));
        assert_eq!(parse("usable 0xg 0x10"), Err(ParseError::BadNumber(7)));
        assert_eq!(parse("usable 0x0"), Err(ParseError::BadEntry(0)));
        assert_eq!(parse("usable 0x0 0x1 0x2"), Err(ParseError::BadEntry(15)));
        assert_eq!(parse("usable 0x0 0x0"), Err(ParseError::BadRange(0)));
        assert_eq!(parse("usable 0xffffffffffffffff 0x2"), Err(ParseError::BadRange(0)));
        assert_eq!(parse("usable 0x0 0x10000000000000000"), Err(ParseError::BadNumber(11)));
    }

    #[test]
    fn more_regions_than_the_map_holds_is_an_error_not_a_truncation() {
        let one = "usable 0x0 0x1;";
        let desc = one.repeat(MAX_REGIONS + 1);
        assert_eq!(parse(&desc), Err(ParseError::TooMany));
        assert!(parse(&one.repeat(MAX_REGIONS)).is_ok());
    }

    #[test]
    fn the_command_line_is_the_one_kbuild_passes_a_kernel_boot() {
        let mut buf = [0u8; 64];
        let n = compose("normal", " kintane.canary=cmdline-intact ", &mut buf).unwrap();
        assert_eq!(&buf[..n], b"mode=normal kintane.canary=cmdline-intact");
        let n = compose("safe", "", &mut buf).unwrap();
        assert_eq!(&buf[..n], b"mode=safe");
        assert_eq!(compose("normal", "x", &mut [0u8; 8]), None);
    }

    #[test]
    fn a_short_buffer_is_too_many_regions() {
        let mut out = [EMPTY; 1];
        // SAFETY: nothing is dereferenced.
        let got = unsafe { memory_regions(0, &mut out) };
        if MAP.1 > 1 {
            assert_eq!(got, Err(Error::TooManyRegions { capacity: 1 }));
        }
    }
}

//! Long names: the entries that carry them, and the short name each set aliases.
//!
//! A long name is kept in entries that sit *before* the short one they belong to, each
//! holding thirteen characters and the checksum of that short name. A reader that does not
//! know about them sees entries whose attribute byte has every bit below the directory bit
//! set, and skips them; a reader that does joins their characters and reports the name the
//! file was created with.
//!
//! # What this holds, and what it refuses
//!
//! Characters are stored as UCS-2, as the format requires, but only the printable ASCII a
//! path may hold is accepted: `"*/:<>?\|` are reserved by the format, control characters and
//! anything above 0x7E are refused. A name is refused rather than shortened
//! ([`vfs::Error::BadPath`]), and a name *read* whose characters are outside that range is
//! reported by its short name rather than mangled into one — the bytes are on the disk and
//! this driver will not guess at them.
//!
//! # Where the short name comes from
//!
//! A name that is already eight-and-three needs no long entries at all: it is stored as a
//! short name, with two bits in the entry recording that the base or the extension was
//! written in lower case, which is what every other reader does and what lets `readme.txt`
//! come back as it went in. Anything else gets a long set and an alias: the name's own
//! characters, upper-cased, with what an alias may not hold replaced by `_`, cut to six and
//! followed by `~1`. The number rises until the directory has no such name, so an alias never
//! takes a name something else already answers to.

use vfs::Error;

/// Bytes of one directory entry, long or short.
pub const ENTRY: usize = 32;
/// Characters one long entry carries.
pub const CHARS: usize = 13;
/// The attribute byte of a long entry: every bit below the directory bit.
pub const ATTR_LONG_NAME: u8 = 0x0F;
/// The ordinal bit marking the entry that holds the end of the name, which is the first of
/// the set on disk.
pub const LAST: u8 = 0x40;
/// The most long entries one name may take, which [`vfs::MAX_NAME`] bounds.
pub const MAX_ENTRIES: usize = vfs::MAX_NAME.div_ceil(CHARS);

/// Where a long entry keeps its characters: three runs of two-byte characters.
const RUNS: [(usize, usize); 3] = [(1, 5), (14, 6), (28, 2)];

/// Byte 12 of a short entry: which halves of the name were written in lower case. Not part
/// of the original format, and every reader that matters honours them.
pub const BASE_LOWER: u8 = 0x08;
pub const EXT_LOWER: u8 = 0x10;

/// Characters an alias may hold besides letters and digits; the same set a short name
/// allows, since an alias is one.
const ALIAS_PUNCTUATION: &[u8] = b"_-!#$%&'()@^{}~";

/// The checksum of a short name, which every long entry of its set carries. A set whose
/// checksum does not match the short entry it precedes belongs to a name that was deleted
/// and partly overwritten, and is ignored.
pub fn checksum(short: &[u8; 11]) -> u8 {
    let mut sum = 0u8;
    for &c in short {
        sum = sum.rotate_right(1).wrapping_add(c);
    }
    sum
}

/// Whether `c` may appear in a long name.
///
/// The format reserves `"*/:<>?\|`; a path separator cannot appear in one component anyway.
/// Control characters and anything outside ASCII are refused: this driver stores UCS-2 but
/// only ever puts ASCII in it, so a name it wrote always reads back as it was written.
pub fn is_name_char(c: u8) -> bool {
    (0x20..=0x7E).contains(&c) && !br#""*/:<>?\|"#.contains(&c)
}

/// Whether `name` is one this driver will write.
///
/// Refused: empty, longer than [`vfs::MAX_NAME`], a character outside [`is_name_char`], a
/// trailing dot or space (which every reader strips, so a name ending in one would come back
/// as a different name), and `.` or `..`, which are the directory's own entries.
pub fn writable_name(name: &[u8]) -> Result<(), Error> {
    if name.is_empty() || name.len() > vfs::MAX_NAME || name == b"." || name == b".." {
        return Err(Error::BadPath);
    }
    if !name.iter().all(|&c| is_name_char(c)) {
        return Err(Error::BadPath);
    }
    match name.last() {
        Some(b'.') | Some(b' ') => Err(Error::BadPath),
        _ => Ok(()),
    }
}

/// Long entries `name` needs. Zero when it fits a short entry on its own.
pub fn entries_for(name: &[u8]) -> usize {
    name.len().div_ceil(CHARS)
}

/// The `index`th long entry of `name`'s set, counted from the start of the name, for a short
/// name whose checksum is `sum`.
///
/// On disk the set runs backwards — the entry holding the end of the name comes first — so a
/// caller writes index `total - 1` first. The ordinal is one-based, and the last entry of the
/// name carries [`LAST`].
pub fn entry(name: &[u8], index: usize, sum: u8) -> [u8; ENTRY] {
    let total = entries_for(name);
    let mut bytes = [0u8; ENTRY];
    bytes[0] = (index as u8 + 1) | if index + 1 == total { LAST } else { 0 };
    bytes[11] = ATTR_LONG_NAME;
    bytes[13] = sum;
    // A long entry names no cluster: the short one it belongs to does.
    let mut at = index * CHARS;
    let mut done = 0usize;
    for (start, count) in RUNS {
        for i in 0..count {
            let put = start + i * 2;
            let c = match name.get(at) {
                Some(&c) => u16::from(c),
                // The name ends inside this entry: a zero after the last character, then
                // 0xFFFF in every position left, which is what the format asks for.
                None if at == name.len() && done == 0 => {
                    done = 1;
                    0
                }
                None => 0xFFFF,
            };
            bytes[put..put + 2].copy_from_slice(&c.to_le_bytes());
            at += usize::from(done == 0);
        }
    }
    bytes
}

/// The characters of one long entry, appended to `out` at `at`.
///
/// `None` if the entry holds a character this driver will not report: one outside ASCII, or
/// one the format reserves. The caller falls back to the short name rather than reporting a
/// name it cannot have written.
pub fn chars_of(bytes: &[u8; ENTRY], out: &mut [u8; vfs::MAX_NAME], at: usize) -> Option<usize> {
    let mut len = at;
    for (start, count) in RUNS {
        for i in 0..count {
            let put = start + i * 2;
            let c = u16::from_le_bytes([bytes[put], bytes[put + 1]]);
            match c {
                // The name ended here; everything after is padding.
                0x0000 | 0xFFFF => return Some(len),
                c if c <= 0x7F && is_name_char(c as u8) => {
                    *out.get_mut(len)? = c as u8;
                    len += 1;
                }
                _ => return None,
            }
        }
    }
    Some(len)
}

/// `name` as a short entry's eleven bytes and its case flags, if it is already a short name.
///
/// `None` when it needs a long set: too long a base or extension, a character a short name
/// may not hold, more than one dot, or mixed case within the base or the extension — which a
/// short entry cannot record, since it has one bit for each half and not one per letter.
pub fn short_of(name: &[u8]) -> Option<([u8; 11], u8)> {
    let (base, ext) = match name.iter().position(|&b| b == b'.') {
        Some(dot) => (name.get(..dot)?, name.get(dot + 1..)?),
        None => (name, &[][..]),
    };
    if base.is_empty() || base.len() > 8 || ext.len() > 3 {
        return None;
    }
    if name.contains(&b'.') && ext.is_empty() {
        return None;
    }
    if ext.contains(&b'.') {
        return None;
    }
    let mut flags = 0u8;
    for (half, bit) in [(base, BASE_LOWER), (ext, EXT_LOWER)] {
        let lower = half.iter().any(|c| c.is_ascii_lowercase());
        let upper = half.iter().any(|c| c.is_ascii_uppercase());
        if lower && upper {
            return None;
        }
        if lower {
            flags |= bit;
        }
    }
    let mut out = [b' '; 11];
    for (i, &c) in base.iter().enumerate() {
        *out.get_mut(i)? = short_byte(c)?;
    }
    for (i, &c) in ext.iter().enumerate() {
        *out.get_mut(8 + i)? = short_byte(c)?;
    }
    Some((out, flags))
}

/// A byte a short name may hold, upper-cased.
fn short_byte(c: u8) -> Option<u8> {
    (c.is_ascii_alphanumeric() || ALIAS_PUNCTUATION.contains(&c)).then(|| c.to_ascii_uppercase())
}

/// The alias for `name` with the tail `~n`: its own characters upper-cased, with anything an
/// alias may not hold replaced by `_`, cut to make room for the tail.
///
/// The extension is the characters after the last dot, cut to three, as every other writer
/// does; a name with no dot gets no extension.
pub fn alias(name: &[u8], n: u32) -> [u8; 11] {
    let (base, ext) = match name.iter().rposition(|&b| b == b'.') {
        Some(dot) if dot != 0 => (&name[..dot], name.get(dot + 1..).unwrap_or(&[])),
        _ => (name, &[][..]),
    };
    let mut out = [b' '; 11];
    // The tail: `~` and the number, right after as much of the base as is left.
    let mut tail = [0u8; 8];
    let mut digits = 0;
    let mut left = n;
    loop {
        tail[digits] = b'0' + (left % 10) as u8;
        digits += 1;
        left /= 10;
        if left == 0 || digits == tail.len() - 1 {
            break;
        }
    }
    let keep = 8usize.saturating_sub(digits + 1);
    let mut at = 0;
    for &c in base.iter().filter(|&&c| c != b' ' && c != b'.') {
        if at == keep {
            break;
        }
        out[at] = short_byte(c).unwrap_or(b'_');
        at += 1;
    }
    out[at] = b'~';
    at += 1;
    for i in 0..digits {
        out[at] = tail[digits - 1 - i];
        at += 1;
    }
    for (i, &c) in ext.iter().take(3).enumerate() {
        out[8 + i] = short_byte(c).unwrap_or(b'_');
    }
    out
}

/// A short name rendered as a caller sees it, with its case flags applied: `NAME.EXT`, or
/// `name.ext` for the halves an entry marks lower-case.
pub fn rendered(short: &[u8; 11], flags: u8, out: &mut [u8; 12]) -> usize {
    let mut len = 0;
    for &c in &short[..8] {
        if c == b' ' {
            break;
        }
        out[len] = if flags & BASE_LOWER != 0 {
            c.to_ascii_lowercase()
        } else {
            c
        };
        len += 1;
    }
    if short[8] != b' ' {
        out[len] = b'.';
        len += 1;
        for &c in &short[8..11] {
            if c == b' ' {
                break;
            }
            out[len] = if flags & EXT_LOWER != 0 {
                c.to_ascii_lowercase()
            } else {
                c
            };
            len += 1;
        }
    }
    len
}

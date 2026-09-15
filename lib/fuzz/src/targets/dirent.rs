//! Directory entries: what `getdents64` packs into a program's buffer.
//!
//! The record is the kernel's to lay out, but nothing else about the case is: the name comes
//! from the volume, which may hold the longest name the format allows, and the buffer length
//! comes from the program, which may pass zero, one byte, or a length that stops in the middle
//! of a record. The contract of `linux::dirent64_bytes` is that it writes a whole record or
//! none of one — never a byte past the buffer it was given, never a `d_reclen` that would walk
//! a reader off the end or out of alignment, and never a record at all for a name the format
//! cannot carry.
//!
//! Most inputs put the buffer within a few bytes of the record's length on purpose, because
//! that is where a packer's arithmetic is wrong: an off-by-one in the padding shows up when
//! the buffer is exactly the record, exactly one short, or one long, and almost never when it
//! is roomy. The offset is whatever the input says, including one no directory would produce,
//! since the packer must not read meaning into it.

use alloc::vec::Vec;

use linux::FileKind;

use crate::Rng;

/// The longest name a case builds, and a buffer with room for its record and slack past it.
const MAX_NAME: usize = 255;
const MAX_BUF: usize = linux::DIRENT_HEADER + MAX_NAME + 16;

/// The five kinds a directory entry can name, chosen by a byte so an input can ask for any.
fn kind_of(tag: u8) -> FileKind {
    match tag % 5 {
        0 => FileKind::Regular,
        1 => FileKind::Directory,
        2 => FileKind::Fifo,
        3 => FileKind::CharDevice,
        _ => FileKind::Socket,
    }
}

/// A little-endian word at `at`, reading zero past the end, so no input is too short.
fn word(bytes: &[u8], at: usize) -> u64 {
    let mut w = [0u8; 8];
    for (o, b) in w.iter_mut().enumerate() {
        *b = bytes.get(at + o).copied().unwrap_or(0);
    }
    u64::from_le_bytes(w)
}

/// The case an input describes: a buffer length, an inode, an offset, a kind and a name.
fn case(input: &[u8]) -> (usize, u64, u64, FileKind, Vec<u8>) {
    let byte = |i: usize| input.get(i).copied().unwrap_or(0);
    let buf_len = usize::from(u16::from_le_bytes([byte(0), byte(1)])) % (MAX_BUF + 1);
    let kind = kind_of(byte(2));
    let name_len = usize::from(byte(3));
    let rest = input.get(4..).unwrap_or(&[]);
    let take = name_len.min(rest.len());
    let name = rest.get(..take).unwrap_or(&[]).to_vec();
    let tail = rest.get(take..).unwrap_or(&[]);
    (buf_len, word(tail, 0), word(tail, 8), kind, name)
}

pub fn generate(rng: &mut Rng, _seeds: &[Vec<u8>]) -> Vec<u8> {
    let name_len = 1 + rng.next_u64() as usize % MAX_NAME;
    let exact = linux::dirent64_len(name_len);
    // Three in four buffers sit within four bytes of the record either way; the rest are
    // whatever length the mutator finds interesting, zero among them.
    let buf_len = if rng.one_in(4) {
        rng.interesting_len(MAX_BUF)
    } else {
        (exact + rng.next_u64() as usize % 9).saturating_sub(4)
    };

    let mut bytes = Vec::with_capacity(4 + name_len + 16);
    bytes.extend((buf_len.min(MAX_BUF) as u16).to_le_bytes());
    bytes.push(rng.next_u32() as u8);
    bytes.push(name_len as u8);
    // A name of printable bytes, except that one in eight carries a NUL somewhere inside it:
    // the packer must refuse those rather than write a record a reader would stop early in.
    for _ in 0..name_len {
        bytes.push(b'A' + (rng.next_u32() % 26) as u8);
    }
    if rng.one_in(8) && name_len > 0 {
        let at = 4 + rng.next_u64() as usize % name_len;
        if let Some(b) = bytes.get_mut(at) {
            *b = 0;
        }
    }
    bytes.extend(rng.next_u64().to_le_bytes());
    bytes.extend(rng.next_u64().to_le_bytes());
    bytes
}

/// Whether the case packed a record, rather than being refused by the name or the buffer.
///
/// Not a correctness property: it is how a campaign shows it spent its budget on the packing
/// rather than entirely on names and buffers that are turned away at the door.
pub fn accepts(input: &[u8]) -> bool {
    let (buf_len, ino, off, kind, name) = case(input);
    let mut buf = [0u8; MAX_BUF];
    linux::dirent64_bytes(&mut buf[..buf_len], ino, off, kind, &name).is_some()
}

pub fn run(input: &[u8]) {
    let (buf_len, ino, off, kind, name) = case(input);
    let mut buf = [0u8; MAX_BUF];
    let out = &mut buf[..buf_len];
    let Some(len) = linux::dirent64_bytes(out, ino, off, kind, &name) else {
        return;
    };

    // What the packer wrote must be a record a reader can walk: inside the buffer, aligned so
    // the next record starts where this one ends, and the length the header itself claims.
    assert!(len <= buf_len, "a record was written past the buffer it was given");
    assert!(len % 8 == 0, "a record's length must leave the next one aligned");
    assert_eq!(len, linux::dirent64_len(name.len()), "a record of another length");
    assert_eq!(
        usize::from(u16::from_le_bytes([out[16], out[17]])),
        len,
        "d_reclen is not the length the packer used"
    );

    // And it must carry back what it was given, with the name whole and terminated.
    assert_eq!(word(out, 0), ino, "d_ino came back as something else");
    assert_eq!(word(out, 8), off, "d_off came back as something else");
    assert!(!name.is_empty(), "a record was packed for an empty name");
    assert!(!name.contains(&0), "a record was packed for a name holding a NUL");
    let at = linux::DIRENT_HEADER;
    assert_eq!(out.get(at..at + name.len()), Some(&name[..]), "the name changed");
    assert_eq!(out.get(at + name.len()), Some(&0), "the name does not end in a NUL");

    // Padding is written, not left as whatever the buffer held: a reader that trusts
    // `d_reclen` never looks at it, but a program reading the whole buffer would.
    for b in out.get(at + name.len() + 1..len).unwrap_or(&[]) {
        assert_eq!(*b, 0, "a record's padding carries bytes the packer did not write");
    }
}

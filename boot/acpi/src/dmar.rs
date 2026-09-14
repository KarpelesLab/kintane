//! The DMA Remapping table (Intel Virtualization Technology for Directed I/O, §8), which
//! describes the machine's IOMMUs.
//!
//! What the kernel learns here: how wide a device address the hardware translates, whether
//! interrupt remapping is on, and — the field that matters most — the register base of each
//! DMA remapping hardware unit (a DRHD). A DRHD's registers are how VT-d is programmed;
//! without the DMAR there is no way to find them, because no other table lists them.
//!
//! # What is parsed, and what is not
//!
//! A DMAR holds a list of remapping structures of several kinds (DRHD, RMRR, ATSR, …). This
//! reads the DRHDs, because those are the units a driver programs, and returns every other
//! kind as [`Remapping::Other`] rather than stopping — the table grows kinds, and one it
//! does not know must not hide the DRHDs listed after it. Each DRHD's *device scope* (which
//! endpoints it covers) is stepped over but not decoded: QEMU presents a single unit that
//! covers the whole segment, and which endpoints a real machine's several units cover is
//! more than the kernel needs to confine one device. A malformed structure — one whose
//! length is below its header or runs past the table — ends the walk with an error, because
//! nothing after it can be located.

use crate::{Error, Sdt, u8_at, u16_at, u64_at};

/// Where remapping structures start: the 36-byte header, then the host address width byte,
/// a flags byte, and ten reserved bytes.
const STRUCTURES_OFFSET: usize = 48;

/// `Flags` bit 0: interrupt remapping is supported (VT-d §8.1).
pub const INTR_REMAP: u8 = 1 << 0;

/// A DRHD's `Flags` bit 0: the unit covers every PCI device in its segment not named by an
/// earlier unit's scope (VT-d §8.3).
pub const INCLUDE_PCI_ALL: u8 = 1 << 0;

/// Remapping structure types (VT-d §8.2).
const TYPE_DRHD: u16 = 0;

/// A checked DMAR.
#[derive(Clone, Copy, Debug)]
pub struct Dmar<'a> {
    bytes: &'a [u8],
}

impl<'a> Dmar<'a> {
    pub fn parse(sdt: Sdt<'a>) -> Result<Dmar<'a>, Error> {
        let sdt = sdt.expect(b"DMAR")?;
        if sdt.bytes().len() < STRUCTURES_OFFSET {
            return Err(Error::BadLength {
                signature: *b"DMAR",
                address: sdt.address(),
                len: sdt.bytes().len() as u64,
            });
        }
        Ok(Dmar { bytes: sdt.bytes() })
    }

    /// The width, in bits, of the largest device address the hardware translates: the host
    /// address width byte plus one (VT-d §8.1). A page table must have enough levels to
    /// cover it.
    pub fn host_address_width(&self) -> u8 {
        u8_at(self.bytes, 36).unwrap_or(0).wrapping_add(1)
    }

    /// The DMAR flags byte (VT-d §8.1): [`INTR_REMAP`] and the rest.
    pub fn flags(&self) -> u8 {
        u8_at(self.bytes, 37).unwrap_or(0)
    }

    /// The remapping structures, in table order. An error ends the walk.
    pub fn structures(&self) -> Structures<'a> {
        Structures {
            bytes: self.bytes,
            at: STRUCTURES_OFFSET,
        }
    }

    /// Every DMA remapping hardware unit, the register bases a driver programs.
    pub fn units(&self) -> impl Iterator<Item = Result<Drhd, Error>> + 'a {
        self.structures().filter_map(|s| match s {
            Ok(Remapping::Drhd(d)) => Some(Ok(d)),
            Ok(Remapping::Other { .. }) => None,
            Err(e) => Some(Err(e)),
        })
    }
}

/// One DMA remapping hardware unit (VT-d §8.3).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Drhd {
    /// The PCI segment this unit serves.
    pub segment: u16,
    /// The physical address of the unit's registers, page-aligned.
    pub register_base: u64,
    /// The unit's flags; [`INCLUDE_PCI_ALL`] and the rest.
    pub flags: u8,
}

impl Drhd {
    /// Whether this unit covers every device in its segment not claimed by an earlier one.
    pub fn includes_all(&self) -> bool {
        self.flags & INCLUDE_PCI_ALL != 0
    }
}

/// A remapping structure of a kind this parser knows, or the type and length of one it does
/// not.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Remapping {
    Drhd(Drhd),
    Other { kind: u16, length: u16 },
}

/// An iterator over a DMAR's remapping structures. Bounds every step by the table's length;
/// a malformed structure ends the walk with an error.
pub struct Structures<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl Iterator for Structures<'_> {
    type Item = Result<Remapping, Error>;

    fn next(&mut self) -> Option<Result<Remapping, Error>> {
        if self.at >= self.bytes.len() {
            return None;
        }
        let malformed = Error::Malformed {
            signature: *b"DMAR",
            offset: self.at,
        };
        // A structure is a two-byte type and a two-byte length, then its body.
        let (Some(kind), Some(length)) =
            (u16_at(self.bytes, self.at), u16_at(self.bytes, self.at + 2))
        else {
            self.at = self.bytes.len();
            return Some(Err(malformed));
        };
        // A length below its own header, or one that runs past the table, cannot be
        // trusted to advance the walk.
        let length = length as usize;
        if length < 4 || self.at + length > self.bytes.len() {
            self.at = self.bytes.len();
            return Some(Err(malformed));
        }
        let start = self.at;
        self.at += length;

        if kind == TYPE_DRHD {
            // DRHD: flags at 4, segment at 6, register base at 8, then device scopes to the
            // structure's end, which are not decoded here.
            let (Some(flags), Some(segment), Some(register_base)) = (
                u8_at(self.bytes, start + 4),
                u16_at(self.bytes, start + 6),
                u64_at(self.bytes, start + 8),
            ) else {
                return Some(Err(malformed));
            };
            if length < 16 {
                return Some(Err(malformed));
            }
            Some(Ok(Remapping::Drhd(Drhd {
                segment,
                register_base,
                flags,
            })))
        } else {
            Some(Ok(Remapping::Other {
                kind,
                length: length as u16,
            }))
        }
    }
}

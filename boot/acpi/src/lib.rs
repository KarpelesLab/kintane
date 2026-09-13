//! ACPI table parsing: finding the tables, checking them, and reading the few the kernel
//! needs.
//!
//! On a PC, firmware describes the machine in ACPI tables. The device tree does the
//! same job on most other machines. The format is the ACPI Specification, version 6.5;
//! section numbers below refer to it. This unit reads:
//!
//! - the **RSDP** (§5.2.5): where the tables start. A UEFI loader is handed its address; on a BIOS
//!   machine it is found by scanning.
//! - the **RSDT or XSDT** (§5.2.7, §5.2.8): the list of every other table.
//! - the **MADT** (§5.2.12): processors, I/O APICs, and how legacy interrupts are rerouted. See
//!   [`madt`].
//! - the **MCFG** (PCI Firmware Specification 3.0, §4.1.2): where PCI Express configuration space
//!   is memory-mapped. See [`mcfg`].
//! - the **FADT** (§5.2.9), for the PM timer and the reset register only. See [`fadt`].
//!
//! Nothing here interprets AML. The DSDT's device namespace is a later piece of work,
//! and what it holds, such as interrupt routing for PCI (`_PRT`), is not claimed here.
//!
//! # Untrusted input
//!
//! Firmware tables are large, old and frequently wrong, and one is reached by following
//! a 64-bit address another table wrote. As in `boot/fdt`:
//!
//! - There is no `unsafe`. Physical memory is read through [`PhysMemory`], whose kernel
//!   implementation is the caller's contract. Bytes that cannot be read are an error.
//! - Every table's header is read before its length is believed. The length is capped at
//!   [`MAX_TABLE_BYTES`] and must cover the header, and the checksum over the whole table must be
//!   zero before any field of it is interpreted.
//! - Every walk over entries is bounded by the table's length. Each entry advances by at least its
//!   declared size, which is checked against the minimum its type needs.
//! - Offsets in errors are from the start of the table, so a human can find the byte with
//!   `acpidump` and a hex editor.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

pub mod fadt;
pub mod madt;
pub mod mcfg;

pub use fadt::{AddressSpace, Fadt, GenericAddress};
pub use madt::{Madt, MadtEntry, ProcessorFlags};
pub use mcfg::{EcamSegment, Mcfg};

#[cfg(test)]
mod tests;

/// Size of the header every system description table starts with (§5.2.6).
pub const HEADER_LEN: usize = 36;

/// The largest table believed. QEMU's biggest, the DSDT, is about 12 KiB, and a large
/// server's reaches a few hundred. A header claiming more is corrupt, and nothing is
/// read for megabytes on its word.
pub const MAX_TABLE_BYTES: usize = 16 * 1024 * 1024;

/// The most root-table entries walked. A root table lists one address per table, and
/// machines with more than a few dozen tables are rare.
pub const MAX_TABLES: usize = 256;

/// Physical memory, as the parser sees it.
pub trait PhysMemory {
    /// `len` bytes at physical `address`, or `None` where they cannot be read: not
    /// mapped, not addressable, or not memory at all.
    fn bytes(&self, address: u64, len: usize) -> Option<&[u8]>;
}

/// Why the tables could not be read.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Error {
    /// No RSDP where one was looked for.
    NoRsdp,
    /// A structure's bytes could not be read through [`PhysMemory`].
    Unreadable { address: u64, len: usize },
    /// A checksum did not sum to zero. `signature` is the table's own, or `RSD ` for the
    /// RSDP.
    BadChecksum { signature: [u8; 4], address: u64 },
    /// A table was not the kind that was asked for.
    WrongSignature {
        address: u64,
        expected: [u8; 4],
        found: [u8; 4],
    },
    /// A length that does not cover its own header, that exceeds [`MAX_TABLE_BYTES`], or
    /// that leaves a partial entry.
    BadLength {
        signature: [u8; 4],
        address: u64,
        len: u64,
    },
    /// An entry inside a table is malformed, at `offset` from the table's start.
    Malformed { signature: [u8; 4], offset: usize },
    /// A root table listing more than [`MAX_TABLES`] entries.
    TooManyTables { count: usize },
}

/// A little-endian integer at `offset`, or `None` past the end.
fn le<const N: usize>(bytes: &[u8], offset: usize) -> Option<[u8; N]> {
    bytes.get(offset..offset.checked_add(N)?)?.try_into().ok()
}

fn u8_at(bytes: &[u8], offset: usize) -> Option<u8> {
    bytes.get(offset).copied()
}

fn u16_at(bytes: &[u8], offset: usize) -> Option<u16> {
    le(bytes, offset).map(u16::from_le_bytes)
}

fn u32_at(bytes: &[u8], offset: usize) -> Option<u32> {
    le(bytes, offset).map(u32::from_le_bytes)
}

fn u64_at(bytes: &[u8], offset: usize) -> Option<u64> {
    le(bytes, offset).map(u64::from_le_bytes)
}

/// The byte sum ACPI checksums are defined by: the whole structure must sum to zero.
fn checksum(bytes: &[u8]) -> u8 {
    bytes.iter().fold(0u8, |a, &b| a.wrapping_add(b))
}

const RSDP_SIGNATURE: &[u8; 8] = b"RSD PTR ";
/// How much of the RSDP the ACPI 1.0 checksum covers.
const RSDP_V1_LEN: usize = 20;
/// The ACPI 2.0 RSDP, extended checksum included.
const RSDP_V2_LEN: usize = 36;

/// The Root System Description Pointer (§5.2.5.3).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Rsdp {
    /// Where it was found.
    pub address: u64,
    /// `0` for ACPI 1.0, `2` for everything since.
    pub revision: u8,
    pub oem_id: [u8; 6],
    /// Physical address of the RSDT. Present in every revision.
    pub rsdt: u32,
    /// Physical address of the XSDT, when the revision has one and it is non-zero.
    pub xsdt: Option<u64>,
}

impl Rsdp {
    /// Parse an RSDP from bytes that start at its signature.
    ///
    /// Revision 0 needs only the 20-byte ACPI 1.0 structure. A later revision must also
    /// carry the extended structure, whose length field is believed only when it covers
    /// the 36 bytes it defines and whose extended checksum must hold too.
    pub fn parse(address: u64, bytes: &[u8]) -> Result<Rsdp, Error> {
        let bad = Error::BadChecksum {
            signature: *b"RSD ",
            address,
        };
        let v1 = bytes.get(..RSDP_V1_LEN).ok_or(Error::NoRsdp)?;
        if v1.get(..8) != Some(RSDP_SIGNATURE.as_slice()) {
            return Err(Error::NoRsdp);
        }
        if checksum(v1) != 0 {
            return Err(bad);
        }
        let revision = u8_at(bytes, 15).ok_or(Error::NoRsdp)?;
        let oem_id = le(bytes, 9).ok_or(Error::NoRsdp)?;
        let rsdt = u32_at(bytes, 16).ok_or(Error::NoRsdp)?;
        let mut rsdp = Rsdp {
            address,
            revision,
            oem_id,
            rsdt,
            xsdt: None,
        };
        if revision >= 2 {
            let short = Error::Unreadable {
                address,
                len: RSDP_V2_LEN,
            };
            let len = u32_at(bytes, 20).ok_or(short)? as usize;
            if len < RSDP_V2_LEN {
                return Err(Error::BadLength {
                    signature: *b"RSD ",
                    address,
                    len: len as u64,
                });
            }
            let whole = bytes.get(..len).ok_or(Error::Unreadable { address, len })?;
            if checksum(whole) != 0 {
                return Err(bad);
            }
            rsdp.xsdt = u64_at(bytes, 24).filter(|&x| x != 0);
        }
        Ok(rsdp)
    }

    /// Read and parse the RSDP at `address`, as a loader reported it.
    pub fn read(mem: &impl PhysMemory, address: u64) -> Result<Rsdp, Error> {
        let head = mem.bytes(address, RSDP_V1_LEN).ok_or(Error::Unreadable {
            address,
            len: RSDP_V1_LEN,
        })?;
        if u8_at(head, 15).is_some_and(|r| r >= 2) {
            let len = mem
                .bytes(address, RSDP_V2_LEN)
                .and_then(|b| u32_at(b, 20))
                .map_or(RSDP_V2_LEN, |l| l as usize)
                .clamp(RSDP_V2_LEN, 4096);
            let bytes = mem
                .bytes(address, len)
                .ok_or(Error::Unreadable { address, len })?;
            return Rsdp::parse(address, bytes);
        }
        Rsdp::parse(address, head)
    }

    /// The first valid RSDP on a 16-byte boundary in `[start, start + len)`, which is
    /// where §5.2.5.1 says firmware places it.
    ///
    /// A signature whose checksum fails is skipped rather than reported: eight bytes that
    /// spell `RSD PTR ` inside an option ROM or a copy of the string in firmware code are
    /// not a broken RSDP, and the real one may follow.
    pub fn scan(mem: &impl PhysMemory, start: u64, len: u64) -> Option<Rsdp> {
        let first = start.checked_add(15)? & !15;
        let end = start.checked_add(len)?;
        let mut at = first;
        // Bounded: advances sixteen bytes a pass, towards `end`.
        while at.checked_add(RSDP_V1_LEN as u64)? <= end {
            if let Ok(rsdp) = Rsdp::read(mem, at) {
                return Some(rsdp);
            }
            at += 16;
        }
        None
    }

    /// Find the RSDP the way a BIOS machine publishes it (§5.2.5.1): in the first KiB of
    /// the Extended BIOS Data Area, whose segment is at physical `0x40e`, and then in the
    /// BIOS read-only area `0xe0000..0x100000`.
    pub fn find_bios(mem: &impl PhysMemory) -> Result<Rsdp, Error> {
        const EBDA_POINTER: u64 = 0x40e;
        const BIOS_AREA: (u64, u64) = (0xe_0000, 0x2_0000);
        let ebda = mem
            .bytes(EBDA_POINTER, 2)
            .and_then(|b| u16_at(b, 0))
            .map(|segment| u64::from(segment) << 4)
            // An EBDA outside conventional memory is a garbage pointer, not a place to look.
            .filter(|&base| (0x500..0x10_0000).contains(&base));
        if let Some(rsdp) = ebda.and_then(|base| Rsdp::scan(mem, base, 1024)) {
            return Ok(rsdp);
        }
        Rsdp::scan(mem, BIOS_AREA.0, BIOS_AREA.1).ok_or(Error::NoRsdp)
    }
}

/// A system description table whose header, length and checksum have been checked.
#[derive(Clone, Copy, Debug)]
pub struct Sdt<'a> {
    address: u64,
    bytes: &'a [u8],
}

impl<'a> Sdt<'a> {
    /// Read the table at `address`: header first, then the length it declares, then the
    /// checksum over all of it.
    pub fn read(mem: &'a impl PhysMemory, address: u64) -> Result<Sdt<'a>, Error> {
        let head = mem.bytes(address, HEADER_LEN).ok_or(Error::Unreadable {
            address,
            len: HEADER_LEN,
        })?;
        let signature: [u8; 4] = le(head, 0).ok_or(Error::Unreadable {
            address,
            len: HEADER_LEN,
        })?;
        let len = u32_at(head, 4).ok_or(Error::Unreadable {
            address,
            len: HEADER_LEN,
        })? as usize;
        if !(HEADER_LEN..=MAX_TABLE_BYTES).contains(&len) {
            return Err(Error::BadLength {
                signature,
                address,
                len: len as u64,
            });
        }
        let bytes = mem
            .bytes(address, len)
            .ok_or(Error::Unreadable { address, len })?;
        Sdt::from_bytes(address, bytes)
    }

    /// Check a table already in hand. `bytes` must be exactly the table: its length field
    /// must say how long `bytes` is.
    pub fn from_bytes(address: u64, bytes: &'a [u8]) -> Result<Sdt<'a>, Error> {
        let signature: [u8; 4] = le(bytes, 0).ok_or(Error::Unreadable {
            address,
            len: HEADER_LEN,
        })?;
        let declared = u32_at(bytes, 4).map_or(0, |l| l as usize);
        if bytes.len() < HEADER_LEN || declared != bytes.len() {
            return Err(Error::BadLength {
                signature,
                address,
                len: declared as u64,
            });
        }
        if checksum(bytes) != 0 {
            return Err(Error::BadChecksum { signature, address });
        }
        Ok(Sdt { address, bytes })
    }

    /// Require this table to be a `signature` table.
    pub fn expect(self, signature: &[u8; 4]) -> Result<Sdt<'a>, Error> {
        if &self.signature() == signature {
            Ok(self)
        } else {
            Err(Error::WrongSignature {
                address: self.address,
                expected: *signature,
                found: self.signature(),
            })
        }
    }

    pub fn address(&self) -> u64 {
        self.address
    }

    pub fn signature(&self) -> [u8; 4] {
        le(self.bytes, 0).unwrap_or([0; 4])
    }

    pub fn revision(&self) -> u8 {
        u8_at(self.bytes, 8).unwrap_or(0)
    }

    pub fn oem_id(&self) -> [u8; 6] {
        le(self.bytes, 10).unwrap_or([0; 6])
    }

    /// The whole table, header included.
    pub fn bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// Everything after the header.
    pub fn body(&self) -> &'a [u8] {
        self.bytes.get(HEADER_LEN..).unwrap_or(&[])
    }
}

/// The tables a machine publishes, reached from its RSDP.
pub struct Tables<'m, M: PhysMemory> {
    mem: &'m M,
    rsdp: Rsdp,
    root: Sdt<'m>,
    /// Bytes per entry in the root table: 4 for the RSDT, 8 for the XSDT.
    width: usize,
}

impl<'m, M: PhysMemory> Tables<'m, M> {
    /// Check the root table the RSDP names.
    ///
    /// The XSDT when there is one, as §5.2.5.3 requires of an OS that understands it, and
    /// otherwise the RSDT. An XSDT that is present but broken is an error rather than a
    /// reason to fall back: two roots that disagree are a firmware bug to report, not to
    /// choose between quietly.
    pub fn new(mem: &'m M, rsdp: Rsdp) -> Result<Tables<'m, M>, Error> {
        let (root, width) = match rsdp.xsdt {
            Some(xsdt) => (Sdt::read(mem, xsdt)?.expect(b"XSDT")?, 8),
            None => (Sdt::read(mem, u64::from(rsdp.rsdt))?.expect(b"RSDT")?, 4),
        };
        if root.body().len() % width != 0 {
            return Err(Error::BadLength {
                signature: root.signature(),
                address: root.address,
                len: root.bytes.len() as u64,
            });
        }
        let count = root.body().len() / width;
        if count > MAX_TABLES {
            return Err(Error::TooManyTables { count });
        }
        Ok(Tables {
            mem,
            rsdp,
            root,
            width,
        })
    }

    pub fn rsdp(&self) -> Rsdp {
        self.rsdp
    }

    /// The root table itself.
    pub fn root(&self) -> Sdt<'m> {
        self.root
    }

    /// How many tables the root lists.
    pub fn len(&self) -> usize {
        self.root.body().len() / self.width
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The address of every table the root lists, in its order.
    pub fn addresses(&self) -> impl Iterator<Item = u64> + '_ {
        self.root
            .body()
            .chunks_exact(self.width)
            .map(|entry| match *entry {
                [a, b, c, d] => u64::from(u32::from_le_bytes([a, b, c, d])),
                _ => le(entry, 0).map_or(0, u64::from_le_bytes),
            })
    }

    /// Every table the root lists, each read and checked.
    pub fn tables(&self) -> impl Iterator<Item = Result<Sdt<'m>, Error>> + '_ {
        self.addresses().map(|a| Sdt::read(self.mem, a))
    }

    /// The first table with `signature`.
    ///
    /// Tables are checked as they are passed, so a broken table anywhere before the one
    /// wanted is reported rather than skipped: its signature cannot be trusted either,
    /// and the one wanted may be the broken one.
    pub fn find(&self, signature: &[u8; 4]) -> Result<Option<Sdt<'m>>, Error> {
        for table in self.tables() {
            let table = table?;
            if &table.signature() == signature {
                return Ok(Some(table));
            }
        }
        Ok(None)
    }

    /// Read a table some other table points at, such as the FADT's DSDT.
    pub fn read(&self, address: u64) -> Result<Sdt<'m>, Error> {
        Sdt::read(self.mem, address)
    }
}

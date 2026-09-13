//! The Multiple APIC Description Table (§5.2.12).
//!
//! What the kernel learns here: which processors exist and their local APIC IDs, where
//! the local APIC's registers are, which I/O APICs exist and which global system
//! interrupts each one serves, and how the legacy ISA interrupts were rewired.
//!
//! # Entries that are refused and entries that are skipped
//!
//! Entries of a type this parser does not know are returned as [`MadtEntry::Other`]:
//! the MADT grows a type every few revisions, and a kernel that stopped reading at the
//! first unfamiliar one would lose every processor listed after it. An entry that is
//! *malformed* ends the walk with an error instead. That covers a length below two, a
//! length past the end of the table, or a known type shorter than the fields its type
//! defines. Its length cannot be trusted, so nothing after it can be located.

use crate::{Error, Sdt, u8_at, u16_at, u32_at, u64_at};

/// Where entries start: header, local APIC address, flags.
const ENTRIES_OFFSET: usize = 44;

/// `flags` bit 0: the machine also has dual 8259 PICs, which must be masked before the
/// APICs are used (Table 5.19).
pub const PCAT_COMPAT: u32 = 1;

/// A checked MADT.
#[derive(Clone, Copy, Debug)]
pub struct Madt<'a> {
    bytes: &'a [u8],
}

impl<'a> Madt<'a> {
    pub fn parse(sdt: Sdt<'a>) -> Result<Madt<'a>, Error> {
        let sdt = sdt.expect(b"APIC")?;
        if sdt.bytes().len() < ENTRIES_OFFSET {
            return Err(Error::BadLength {
                signature: *b"APIC",
                address: sdt.address(),
                len: sdt.bytes().len() as u64,
            });
        }
        Ok(Madt { bytes: sdt.bytes() })
    }

    /// The local APIC address in the fixed header, before any override.
    pub fn header_local_apic_address(&self) -> u32 {
        u32_at(self.bytes, 36).unwrap_or(0)
    }

    pub fn flags(&self) -> u32 {
        u32_at(self.bytes, 40).unwrap_or(0)
    }

    /// The physical address of the local APIC registers: the 64-bit override entry if
    /// there is one (§5.2.12.8), otherwise the header's 32-bit field.
    ///
    /// # Errors
    /// Whatever a malformed entry before the override reports: an override that might be
    /// hidden behind it cannot be ruled out.
    pub fn local_apic_address(&self) -> Result<u64, Error> {
        for entry in self.entries() {
            if let MadtEntry::LocalApicAddress { address } = entry? {
                return Ok(address);
            }
        }
        Ok(u64::from(self.header_local_apic_address()))
    }

    /// The entries, in table order. An error ends the walk.
    pub fn entries(&self) -> Entries<'a> {
        Entries {
            bytes: self.bytes,
            offset: ENTRIES_OFFSET,
        }
    }
}

/// The processor flags of a local APIC or x2APIC entry (Table 5.21).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ProcessorFlags(pub u32);

impl ProcessorFlags {
    /// The processor is usable now.
    pub fn enabled(self) -> bool {
        self.0 & 1 != 0
    }

    /// The processor is not usable now but may be brought online. Meaningful only when
    /// [`Self::enabled`] is clear; a processor with neither bit set must not be started.
    pub fn online_capable(self) -> bool {
        self.0 & 2 != 0
    }
}

/// One MADT entry.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MadtEntry {
    /// Type 0 (§5.2.12.2).
    LocalApic {
        processor_uid: u8,
        apic_id: u8,
        flags: ProcessorFlags,
    },
    /// Type 1 (§5.2.12.3).
    IoApic { id: u8, address: u32, gsi_base: u32 },
    /// Type 2 (§5.2.12.5): ISA interrupt `source` is delivered as `gsi`, with the polarity
    /// and trigger mode `flags` describe.
    SourceOverride {
        bus: u8,
        source: u8,
        gsi: u32,
        flags: u16,
    },
    /// Type 3 (§5.2.12.6).
    NmiSource { flags: u16, gsi: u32 },
    /// Type 4 (§5.2.12.7). `processor_uid` `0xff` means every processor.
    LocalApicNmi {
        processor_uid: u8,
        flags: u16,
        lint: u8,
    },
    /// Type 5 (§5.2.12.8).
    LocalApicAddress { address: u64 },
    /// Type 9 (§5.2.12.12).
    LocalX2Apic {
        x2apic_id: u32,
        flags: ProcessorFlags,
        processor_uid: u32,
    },
    /// A type this parser does not interpret, with its length.
    Other { kind: u8, len: u8 },
}

/// The entries of a MADT.
#[derive(Clone, Debug)]
pub struct Entries<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl Iterator for Entries<'_> {
    type Item = Result<MadtEntry, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        let at = self.offset;
        if at >= self.bytes.len() {
            return None;
        }
        let entry = entry(self.bytes, at);
        // Past the end on error, so the walk stops; otherwise past this entry, whose
        // length `entry` has checked is at least two and within the table.
        self.offset = match entry {
            Ok((_, len)) => at + len,
            Err(_) => self.bytes.len(),
        };
        Some(entry.map(|(e, _)| e))
    }
}

/// The entry at `at`, and its length.
fn entry(bytes: &[u8], at: usize) -> Result<(MadtEntry, usize), Error> {
    let malformed = Error::Malformed {
        signature: *b"APIC",
        offset: at,
    };
    let kind = u8_at(bytes, at).ok_or(malformed)?;
    let len = usize::from(u8_at(bytes, at + 1).ok_or(malformed)?);
    let minimum = match kind {
        0 => 8,
        1 => 12,
        2 => 10,
        3 => 8,
        4 => 6,
        5 => 12,
        9 => 16,
        _ => 2,
    };
    if len < minimum || at.checked_add(len).is_none_or(|end| end > bytes.len()) {
        return Err(malformed);
    }
    let e = bytes.get(at..at + len).ok_or(malformed)?;
    let b = |o| u8_at(e, o).ok_or(malformed);
    let w = |o| u16_at(e, o).ok_or(malformed);
    let d = |o| u32_at(e, o).ok_or(malformed);
    let entry = match kind {
        0 => MadtEntry::LocalApic {
            processor_uid: b(2)?,
            apic_id: b(3)?,
            flags: ProcessorFlags(d(4)?),
        },
        1 => MadtEntry::IoApic {
            id: b(2)?,
            address: d(4)?,
            gsi_base: d(8)?,
        },
        2 => MadtEntry::SourceOverride {
            bus: b(2)?,
            source: b(3)?,
            gsi: d(4)?,
            flags: w(8)?,
        },
        3 => MadtEntry::NmiSource {
            flags: w(2)?,
            gsi: d(4)?,
        },
        4 => MadtEntry::LocalApicNmi {
            processor_uid: b(2)?,
            flags: w(3)?,
            lint: b(5)?,
        },
        5 => MadtEntry::LocalApicAddress {
            address: u64_at(e, 4).ok_or(malformed)?,
        },
        9 => MadtEntry::LocalX2Apic {
            x2apic_id: d(4)?,
            flags: ProcessorFlags(d(8)?),
            processor_uid: d(12)?,
        },
        _ => MadtEntry::Other {
            kind,
            len: len as u8,
        },
    };
    Ok((entry, len))
}

//! The PCI Express memory-mapped configuration table (PCI Firmware Specification 3.0,
//! §4.1.2).
//!
//! Each entry is one PCI segment's ECAM window: a base address at which bus `start_bus`
//! function 0 device 0's configuration space begins, one MiB per bus, 4 KiB per
//! function. A machine without an MCFG has no enhanced configuration access, and the
//! legacy I/O-port mechanism is the only way in, which is what QEMU's `pc` machine
//! offers.

use crate::{Error, Sdt, u8_at, u16_at, u64_at};

/// Where entries start: header, then eight reserved bytes.
const ENTRIES_OFFSET: usize = 44;
const ENTRY_LEN: usize = 16;

/// A checked MCFG.
#[derive(Clone, Copy, Debug)]
pub struct Mcfg<'a> {
    bytes: &'a [u8],
}

impl<'a> Mcfg<'a> {
    pub fn parse(sdt: Sdt<'a>) -> Result<Mcfg<'a>, Error> {
        let sdt = sdt.expect(b"MCFG")?;
        let len = sdt.bytes().len();
        if len < ENTRIES_OFFSET || (len - ENTRIES_OFFSET) % ENTRY_LEN != 0 {
            return Err(Error::BadLength {
                signature: *b"MCFG",
                address: sdt.address(),
                len: len as u64,
            });
        }
        Ok(Mcfg { bytes: sdt.bytes() })
    }

    /// Every segment, in table order. An entry whose bus range is inverted or whose window
    /// would not fit in 64 bits is an error, reported at its offset.
    pub fn segments(&self) -> impl Iterator<Item = Result<EcamSegment, Error>> + 'a {
        let bytes = self.bytes;
        (ENTRIES_OFFSET..bytes.len())
            .step_by(ENTRY_LEN)
            .map(move |at| segment(bytes, at))
    }
}

fn segment(bytes: &[u8], at: usize) -> Result<EcamSegment, Error> {
    let malformed = Error::Malformed {
        signature: *b"MCFG",
        offset: at,
    };
    let s = EcamSegment {
        base: u64_at(bytes, at).ok_or(malformed)?,
        segment: u16_at(bytes, at + 8).ok_or(malformed)?,
        start_bus: u8_at(bytes, at + 10).ok_or(malformed)?,
        end_bus: u8_at(bytes, at + 11).ok_or(malformed)?,
    };
    if s.end_bus < s.start_bus || s.base.checked_add(s.len()).is_none() {
        return Err(malformed);
    }
    Ok(s)
}

/// One PCI segment's memory-mapped configuration space.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct EcamSegment {
    /// Physical address of bus `start_bus`, device 0, function 0.
    pub base: u64,
    pub segment: u16,
    pub start_bus: u8,
    pub end_bus: u8,
}

impl EcamSegment {
    /// Bytes of configuration space per bus: 32 devices × 8 functions × 4 KiB.
    pub const BUS_BYTES: u64 = 1 << 20;
    /// Bytes of configuration space per function.
    pub const FUNCTION_BYTES: u64 = 4096;

    /// The whole window, in bytes.
    pub fn len(&self) -> u64 {
        (u64::from(self.end_bus) - u64::from(self.start_bus) + 1) * Self::BUS_BYTES
    }

    pub fn is_empty(&self) -> bool {
        false
    }

    /// Where `bus:device.function`'s configuration space starts, or `None` when the bus
    /// is outside this segment or the device or function number is out of range.
    pub fn function_address(&self, bus: u8, device: u8, function: u8) -> Option<u64> {
        if !(self.start_bus..=self.end_bus).contains(&bus) || device >= 32 || function >= 8 {
            return None;
        }
        let index =
            (u64::from(bus - self.start_bus) << 8) | (u64::from(device) << 3) | u64::from(function);
        self.base.checked_add(index * Self::FUNCTION_BYTES)
    }
}

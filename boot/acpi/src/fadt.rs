//! The Fixed ACPI Description Table (§5.2.9), for the two fields the kernel has a use
//! for without an AML interpreter: the ACPI PM timer and the reset register.
//!
//! The FADT has grown with every revision, and firmware writes whichever length it
//! supports. So a field is read only when the table is long enough to contain it. The
//! length decides this, not the revision byte, which firmware is known to get wrong.

use crate::{Error, Sdt, u8_at, u16_at, u32_at, u64_at};

/// The ACPI 1.0 FADT ends here; every field below this offset is always present.
const V1_LEN: usize = 116;
/// `RESET_REG` and `RESET_VALUE` were added in ACPI 2.0 and end here.
const RESET_END: usize = 129;
/// `X_PM_TMR_BLK` ends here.
const X_PM_TIMER_END: usize = 220;

/// `Flags` bit 8: the PM timer counts 32 bits rather than 24.
const TMR_VAL_EXT: u32 = 1 << 8;
/// `Flags` bit 10: `RESET_REG` is supported.
const RESET_REG_SUP: u32 = 1 << 10;

/// A checked FADT.
#[derive(Clone, Copy, Debug)]
pub struct Fadt<'a> {
    bytes: &'a [u8],
}

impl<'a> Fadt<'a> {
    pub fn parse(sdt: Sdt<'a>) -> Result<Fadt<'a>, Error> {
        let sdt = sdt.expect(b"FACP")?;
        if sdt.bytes().len() < V1_LEN {
            return Err(Error::BadLength {
                signature: *b"FACP",
                address: sdt.address(),
                len: sdt.bytes().len() as u64,
            });
        }
        Ok(Fadt { bytes: sdt.bytes() })
    }

    pub fn flags(&self) -> u32 {
        u32_at(self.bytes, 112).unwrap_or(0)
    }

    /// The interrupt the SCI is wired to, as an ISA or global system interrupt number.
    pub fn sci_interrupt(&self) -> u16 {
        u16_at(self.bytes, 46).unwrap_or(0)
    }

    /// The physical address of the DSDT: `X_DSDT` when the table has it and it is
    /// non-zero, otherwise the 32-bit field.
    pub fn dsdt(&self) -> u64 {
        u64_at(self.bytes, 140)
            .filter(|&x| x != 0)
            .unwrap_or_else(|| u64::from(u32_at(self.bytes, 40).unwrap_or(0)))
    }

    /// The PM timer, and whether it counts 32 bits.
    ///
    /// `X_PM_TMR_BLK` when present and non-zero, otherwise the I/O port `PM_TMR_BLK`. `None`
    /// when neither names a timer, which ACPI 5.0 allows on hardware-reduced machines.
    pub fn pm_timer(&self) -> Option<(GenericAddress, bool)> {
        let wide = self.flags() & TMR_VAL_EXT != 0;
        let extended = (self.bytes.len() >= X_PM_TIMER_END)
            .then(|| GenericAddress::read(self.bytes, 208))
            .flatten()
            .filter(|g| g.address != 0);
        let legacy = u32_at(self.bytes, 76)
            .filter(|&port| port != 0)
            .map(|port| GenericAddress {
                space: AddressSpace::SystemIo,
                bit_width: 32,
                bit_offset: 0,
                access_size: 0,
                address: u64::from(port),
            });
        extended.or(legacy).map(|g| (g, wide))
    }

    /// The reset register and the value to write to it, when the table has one and its
    /// flags say it is supported.
    pub fn reset(&self) -> Option<(GenericAddress, u8)> {
        if self.bytes.len() < RESET_END || self.flags() & RESET_REG_SUP == 0 {
            return None;
        }
        let register = GenericAddress::read(self.bytes, 116)?;
        Some((register, u8_at(self.bytes, 128)?))
    }
}

/// Where a register lives (§5.2.3.2, the Generic Address Structure).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct GenericAddress {
    pub space: AddressSpace,
    pub bit_width: u8,
    pub bit_offset: u8,
    pub access_size: u8,
    pub address: u64,
}

impl GenericAddress {
    fn read(bytes: &[u8], at: usize) -> Option<GenericAddress> {
        Some(GenericAddress {
            space: AddressSpace::from_id(u8_at(bytes, at)?),
            bit_width: u8_at(bytes, at + 1)?,
            bit_offset: u8_at(bytes, at + 2)?,
            access_size: u8_at(bytes, at + 3)?,
            address: u64_at(bytes, at + 4)?,
        })
    }
}

/// The address space a [`GenericAddress`] is in (Table 5.25).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AddressSpace {
    SystemMemory,
    SystemIo,
    PciConfig,
    Other(u8),
}

impl AddressSpace {
    fn from_id(id: u8) -> AddressSpace {
        match id {
            0 => AddressSpace::SystemMemory,
            1 => AddressSpace::SystemIo,
            2 => AddressSpace::PciConfig,
            other => AddressSpace::Other(other),
        }
    }
}

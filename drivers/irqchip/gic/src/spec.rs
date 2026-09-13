//! Interrupt specifiers, as the GIC device tree bindings define them.
//!
//! Three cells: the type, the number within that type, and the trigger flags. The
//! number is not the interrupt ID the controller uses — it is offset by the type, so
//! the same `14` is ID 30 for a PPI and ID 46 for an SPI. Getting that offset wrong is
//! quiet: the driver enables a real, different interrupt, which simply never fires.
//!
//! A fourth cell exists in the GICv3 binding for PPI partitions (big.LITTLE systems
//! whose PPIs differ by cluster). It must be zero here, because partitions are not
//! supported and ignoring one would route a PPI to the wrong CPUs.

use hal::IrqNumber;

/// `GIC_SPI` in the binding: a shared peripheral interrupt, IDs 32..1020.
const SPI: u32 = 0;
/// `GIC_PPI`: a private peripheral interrupt, IDs 16..32.
const PPI: u32 = 1;

const SPI_BASE: u32 = 32;
const SPI_COUNT: u32 = 988;
const PPI_BASE: u32 = 16;
const PPI_COUNT: u32 = 16;

/// Why a specifier names no interrupt this driver can wire up.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Error {
    /// Fewer than three cells.
    TooShort,
    /// A type other than SPI or PPI: extended ranges, or garbage.
    UnknownType(u32),
    /// A number past the end of its type's range.
    OutOfRange { kind: u32, number: u32 },
    /// A PPI partition, which is not supported.
    Partitioned,
}

/// The interrupt ID a GIC specifier names.
pub fn translate(cells: &[u32]) -> Result<IrqNumber, Error> {
    let [kind, number, _flags, rest @ ..] = cells else {
        return Err(Error::TooShort);
    };
    if rest.iter().any(|&c| c != 0) {
        return Err(Error::Partitioned);
    }
    let (base, count) = match *kind {
        SPI => (SPI_BASE, SPI_COUNT),
        PPI => (PPI_BASE, PPI_COUNT),
        other => return Err(Error::UnknownType(other)),
    };
    if *number >= count {
        return Err(Error::OutOfRange {
            kind: *kind,
            number: *number,
        });
    }
    Ok(IrqNumber(base + number))
}

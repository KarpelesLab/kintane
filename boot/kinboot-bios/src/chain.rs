//! Chainloading: handing the machine to another partition's boot record.
//!
//! `docs/bootloader.md` scopes BIOS chainloading to exactly what a classic MBR does:
//! read the selected partition's first sector to `0x7C00`, check its signature, and jump
//! to it in real mode with the boot drive in `DL`. By the same convention `DS:SI` points
//! at the partition's entry in a copy of the partition table, which DOS-era boot records
//! read to learn where their partition starts. The MBR is copied to `0x0600`, where
//! classic MBRs relocate themselves, and `SI` points into that copy.
//!
//! What to read and what to hand over is decided here, with host tests. The loader does
//! the reads and the mode switch.

use crate::disk::{PARTITION_ENTRY_BYTES, PARTITION_TABLE_OFFSET, SECTOR};

/// Where the MBR copy lives while the chainloaded record runs.
pub const MBR_COPY_ADDRESS: u32 = 0x0600;
/// Where the boot record is loaded and entered.
pub const LOAD_ADDRESS: u32 = 0x7C00;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Error {
    /// Partitions are numbered 1 to 4.
    NoSuchPartition(u8),
    /// The entry's type is zero: nothing is there.
    EmptyPartition(u8),
    /// The MBR the entry was read from lacks `0x55AA`.
    BadMbr,
    /// The partition's first sector lacks `0x55AA`: not a boot record.
    NotBootable(u8),
}

/// One primary partition, as the MBR describes it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Partition {
    pub number: u8,
    pub kind: u8,
    pub start_lba: u32,
    pub sectors: u32,
}

impl Partition {
    /// `SI` for the chainloaded record: this entry in the MBR copy.
    pub fn si(&self) -> u16 {
        (MBR_COPY_ADDRESS as usize
            + PARTITION_TABLE_OFFSET
            + (usize::from(self.number) - 1) * PARTITION_ENTRY_BYTES) as u16
    }
}

fn has_signature(sector: &[u8]) -> bool {
    sector.len() == SECTOR && sector[510] == 0x55 && sector[511] == 0xAA
}

/// Read primary partition `number`, 1 to 4, from an MBR.
pub fn partition(mbr: &[u8; SECTOR], number: u8) -> Result<Partition, Error> {
    if !(1..=4).contains(&number) {
        return Err(Error::NoSuchPartition(number));
    }
    if !has_signature(mbr) {
        return Err(Error::BadMbr);
    }
    let at = PARTITION_TABLE_OFFSET + (usize::from(number) - 1) * PARTITION_ENTRY_BYTES;
    let e = &mbr[at..at + PARTITION_ENTRY_BYTES];
    let le = |i: usize| u32::from_le_bytes([e[i], e[i + 1], e[i + 2], e[i + 3]]);
    let p = Partition {
        number,
        kind: e[4],
        start_lba: le(8),
        sectors: le(12),
    };
    if p.kind == 0 || p.sectors == 0 {
        return Err(Error::EmptyPartition(number));
    }
    Ok(p)
}

/// Whether a partition's first sector may be jumped to.
pub fn check_boot_record(p: &Partition, sector: &[u8; SECTOR]) -> Result<(), Error> {
    if has_signature(sector) {
        Ok(())
    } else {
        Err(Error::NotBootable(p.number))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mbr() -> [u8; SECTOR] {
        let mut m = [0u8; SECTOR];
        m[510] = 0x55;
        m[511] = 0xAA;
        let e = PARTITION_TABLE_OFFSET + PARTITION_ENTRY_BYTES;
        m[e + 4] = 0x7F;
        m[e + 8..e + 12].copy_from_slice(&2048u32.to_le_bytes());
        m[e + 12..e + 16].copy_from_slice(&1u32.to_le_bytes());
        m
    }

    #[test]
    fn a_partition_is_read_from_its_entry_and_si_points_at_that_entry() {
        let p = partition(&mbr(), 2).unwrap();
        assert_eq!(
            p,
            Partition {
                number: 2,
                kind: 0x7F,
                start_lba: 2048,
                sectors: 1
            }
        );
        assert_eq!(p.si(), 0x07CE, "0x600 + 0x1BE + one 16-byte entry");
    }

    #[test]
    fn absent_empty_and_unsigned_are_refused_by_name() {
        assert_eq!(partition(&mbr(), 0), Err(Error::NoSuchPartition(0)));
        assert_eq!(partition(&mbr(), 5), Err(Error::NoSuchPartition(5)));
        assert_eq!(partition(&mbr(), 1), Err(Error::EmptyPartition(1)));
        let mut unsigned = mbr();
        unsigned[511] = 0;
        assert_eq!(partition(&unsigned, 2), Err(Error::BadMbr));

        let p = partition(&mbr(), 2).unwrap();
        let mut vbr = [0u8; SECTOR];
        assert_eq!(check_boot_record(&p, &vbr), Err(Error::NotBootable(2)));
        vbr[510] = 0x55;
        vbr[511] = 0xAA;
        assert_eq!(check_boot_record(&p, &vbr), Ok(()));
    }
}

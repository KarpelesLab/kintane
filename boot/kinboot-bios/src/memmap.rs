//! The memory map stage 2 collects from the BIOS, and the questions asked of it.
//!
//! The firmware interfaces are awkward in ways that are easy to get wrong, so the
//! decoding lives here, where it is tested on the host, rather than beside the real-mode
//! call in the loader:
//!
//! - **E820** returns 20-byte entries from older BIOSes and 24-byte entries from ACPI 3.0 ones. The
//!   extra four bytes are extended attributes, and an entry whose "enabled" bit (bit 0) is clear
//!   must be ignored. A 20-byte entry has no attributes and is treated as enabled, which is why the
//!   caller presets that bit before each call.
//! - Zero-length entries exist in the wild and mean nothing.
//! - A BIOS without E820 still answers **E801** on anything from the mid-1990s on. That gives two
//!   sizes, not a map, and [`MemoryMap::from_e801`] turns them into the three regions they imply,
//!   with the ISA hole and the BIOS area left out.

/// A range and its E820 type. `kind` 1 is usable RAM; the rest are passed through for
/// the kernel to interpret. Multiboot uses the same numbering.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Entry {
    pub base: u64,
    pub len: u64,
    pub kind: u32,
}

pub const USABLE: u32 = 1;
/// E820 type 2, used for the ranges E801 implies are not RAM.
pub const RESERVED: u32 = 2;

/// Entries kept. QEMU reports 6–8, real machines 10–30.
pub const MAX_ENTRIES: usize = 64;

/// Bit 0 of the ACPI 3.0 extended attributes: the entry is valid.
const ATTR_ENABLED: u32 = 1;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Error {
    /// More entries than [`MAX_ENTRIES`]. Refused rather than truncated: a truncated map
    /// silently drops RAM or, worse, drops a reservation.
    Full,
    /// The BIOS returned an entry size E820 does not define.
    EntrySize(u32),
    /// The firmware reported nothing usable.
    Empty,
}

/// A memory map with a fixed capacity, filled in firmware order.
#[derive(Clone, Copy)]
pub struct MemoryMap {
    entries: [Entry; MAX_ENTRIES],
    len: usize,
}

impl Default for MemoryMap {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryMap {
    pub const fn new() -> Self {
        MemoryMap {
            entries: [Entry {
                base: 0,
                len: 0,
                kind: 0,
            }; MAX_ENTRIES],
            len: 0,
        }
    }

    pub fn entries(&self) -> &[Entry] {
        &self.entries[..self.len]
    }

    /// Add one E820 result. `returned` is what the BIOS left in `ecx`: the number of
    /// bytes it wrote into the 24-byte buffer.
    pub fn push_e820(&mut self, raw: &[u8; 24], returned: u32) -> Result<(), Error> {
        let le32 = |at: usize| u32::from_le_bytes([raw[at], raw[at + 1], raw[at + 2], raw[at + 3]]);
        let le64 = |at: usize| le32(at) as u64 | (le32(at + 4) as u64) << 32;
        let attrs = match returned {
            20 => ATTR_ENABLED,
            24 => le32(20),
            other => return Err(Error::EntrySize(other)),
        };
        if attrs & ATTR_ENABLED == 0 {
            return Ok(());
        }
        self.push(Entry {
            base: le64(0),
            len: le64(8),
            kind: le32(16),
        })
    }

    pub fn push(&mut self, e: Entry) -> Result<(), Error> {
        if e.len == 0 {
            return Ok(());
        }
        if self.len == MAX_ENTRIES {
            return Err(Error::Full);
        }
        self.entries[self.len] = e;
        self.len += 1;
        Ok(())
    }

    /// The map E801 implies.
    ///
    /// `below_16m_kib` is memory between 1 MiB and 16 MiB in KiB (`ax`/`cx`), and
    /// `above_16m_blocks` is memory above 16 MiB in 64 KiB blocks (`bx`/`dx`).
    /// `conventional_kib` comes from INT 12h. Everything between the end of
    /// conventional memory and 1 MiB is marked reserved: that is where the EBDA, video
    /// memory and the BIOS itself live.
    pub fn from_e801(
        conventional_kib: u16,
        below_16m_kib: u16,
        above_16m_blocks: u16,
    ) -> Result<MemoryMap, Error> {
        let mut m = MemoryMap::new();
        let low = conventional_kib as u64 * 1024;
        m.push(Entry {
            base: 0,
            len: low.min(0xA0000),
            kind: USABLE,
        })?;
        m.push(Entry {
            base: low.min(0xA0000),
            len: 0x10_0000 - low.min(0xA0000),
            kind: RESERVED,
        })?;
        m.push(Entry {
            base: 0x10_0000,
            len: below_16m_kib as u64 * 1024,
            kind: USABLE,
        })?;
        // Memory above 16 MiB is only contiguous with the range below it when that range
        // is full; otherwise there is a hole, commonly the ISA memory hole at 15 MiB.
        m.push(Entry {
            base: 0x100_0000,
            len: above_16m_blocks as u64 * 64 * 1024,
            kind: USABLE,
        })?;
        m.check_nonempty()?;
        Ok(m)
    }

    pub fn check_nonempty(&self) -> Result<(), Error> {
        if self.entries().iter().any(|e| e.kind == USABLE) {
            Ok(())
        } else {
            Err(Error::Empty)
        }
    }

    /// Whether every byte of `[base, base + len)` is usable RAM and no reservation
    /// overlaps it.
    ///
    /// The range may span several adjacent usable entries: firmware splits RAM at
    /// arbitrary points. A reservation wins over a usable entry that overlaps it,
    /// because a map is allowed to be redundant and guessing the other way hands the
    /// kernel memory that belongs to the firmware.
    pub fn is_usable(&self, base: u64, len: u64) -> bool {
        let Some(end) = base.checked_add(len) else {
            return false;
        };
        if len == 0 {
            return true;
        }
        let reserved_overlap = self
            .entries()
            .iter()
            .any(|e| e.kind != USABLE && e.base < end && base < e.base.saturating_add(e.len));
        if reserved_overlap {
            return false;
        }
        // Advance a cursor across usable entries until it reaches `end`. Bounded: each
        // pass either moves the cursor forward or stops.
        let mut cursor = base;
        loop {
            if cursor >= end {
                return true;
            }
            let next = self
                .entries()
                .iter()
                .filter(|e| e.kind == USABLE && e.base <= cursor)
                .map(|e| e.base.saturating_add(e.len))
                .filter(|&e_end| e_end > cursor)
                .max();
            match next {
                Some(e_end) => cursor = e_end,
                None => return false,
            }
        }
    }

    /// Multiboot's `mem_lower`: KiB of usable RAM from address 0, at most 640.
    pub fn mem_lower_kib(&self) -> u32 {
        (self.contiguous_from(0).min(0xA0000) / 1024) as u32
    }

    /// Multiboot's `mem_upper`: KiB of usable RAM from 1 MiB to the first hole,
    /// saturated at the field's width.
    pub fn mem_upper_kib(&self) -> u32 {
        (self.contiguous_from(0x10_0000) / 1024).min(u32::MAX as u64) as u32
    }

    /// Bytes of usable memory contiguous from `start`.
    fn contiguous_from(&self, start: u64) -> u64 {
        let mut cursor = start;
        loop {
            let next = self
                .entries()
                .iter()
                .filter(|e| e.kind == USABLE && e.base <= cursor)
                .map(|e| e.base.saturating_add(e.len))
                .filter(|&e_end| e_end > cursor)
                .max();
            match next {
                Some(e_end) => cursor = e_end,
                None => return cursor - start,
            }
        }
    }

    /// Total bytes of usable memory, for the loader's banner.
    pub fn usable_bytes(&self) -> u64 {
        self.entries()
            .iter()
            .filter(|e| e.kind == USABLE)
            .fold(0u64, |acc, e| acc.saturating_add(e.len))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw(base: u64, len: u64, kind: u32, attrs: u32) -> [u8; 24] {
        let mut r = [0u8; 24];
        r[0..8].copy_from_slice(&base.to_le_bytes());
        r[8..16].copy_from_slice(&len.to_le_bytes());
        r[16..20].copy_from_slice(&kind.to_le_bytes());
        r[20..24].copy_from_slice(&attrs.to_le_bytes());
        r
    }

    /// QEMU's `pc` machine with 128 MiB, as SeaBIOS reports it.
    fn qemu_pc() -> MemoryMap {
        let mut m = MemoryMap::new();
        for (b, l, k) in [
            (0u64, 0x9FC00u64, 1u32),
            (0x9FC00, 0x400, 2),
            (0xF0000, 0x10000, 2),
            (0x10_0000, 0x7EE_0000, 1),
            (0x7FE_0000, 0x2_0000, 2),
            (0xFFFC_0000, 0x4_0000, 2),
        ] {
            m.push_e820(&raw(b, l, k, 1), 20).unwrap();
        }
        m
    }

    #[test]
    fn twenty_byte_entries_are_enabled() {
        let mut m = MemoryMap::new();
        // Garbage where the attributes would be: a 20-byte entry has none.
        m.push_e820(&raw(0, 0x1000, 1, 0), 20).unwrap();
        assert_eq!(m.entries().len(), 1);
    }

    #[test]
    fn disabled_24_byte_entries_are_ignored() {
        let mut m = MemoryMap::new();
        m.push_e820(&raw(0, 0x1000, 1, 0), 24).unwrap();
        m.push_e820(&raw(0x1000, 0x1000, 1, 1), 24).unwrap();
        assert_eq!(
            m.entries(),
            &[Entry {
                base: 0x1000,
                len: 0x1000,
                kind: 1
            }]
        );
    }

    #[test]
    fn odd_entry_sizes_and_empty_entries() {
        let mut m = MemoryMap::new();
        assert_eq!(m.push_e820(&raw(0, 1, 1, 1), 16), Err(Error::EntrySize(16)));
        m.push_e820(&raw(0x5000, 0, 1, 1), 20).unwrap();
        assert!(m.entries().is_empty());
        assert_eq!(m.check_nonempty(), Err(Error::Empty));
    }

    #[test]
    fn a_full_map_is_refused_not_truncated() {
        let mut m = MemoryMap::new();
        for i in 0..MAX_ENTRIES as u64 {
            m.push_e820(&raw(i * 0x1000, 0x1000, 1, 1), 20).unwrap();
        }
        assert_eq!(m.push_e820(&raw(0x100_0000, 0x1000, 1, 1), 20), Err(Error::Full));
    }

    #[test]
    fn usability_spans_split_entries_and_respects_reservations() {
        let m = qemu_pc();
        assert!(m.is_usable(0x10_0000, 0x40_0000));
        assert!(m.is_usable(0x7F0_0000, 0xE_0000));
        assert!(!m.is_usable(0x7F0_0000, 0xF_0001), "runs into the reserved tail");
        assert!(!m.is_usable(0x9F000, 0x2000), "crosses the EBDA");
        assert!(!m.is_usable(0xA0000, 0x1000), "the video hole is in no entry");
        assert!(!m.is_usable(u64::MAX - 5, 10), "overflow is not usable");

        let mut split = MemoryMap::new();
        split
            .push(Entry {
                base: 0x10_0000,
                len: 0x10_0000,
                kind: 1,
            })
            .unwrap();
        split
            .push(Entry {
                base: 0x20_0000,
                len: 0x10_0000,
                kind: 1,
            })
            .unwrap();
        assert!(split.is_usable(0x18_0000, 0x10_0000));

        // A reservation inside a usable entry wins.
        split
            .push(Entry {
                base: 0x28_0000,
                len: 0x1000,
                kind: 2,
            })
            .unwrap();
        assert!(!split.is_usable(0x20_0000, 0x10_0000));
    }

    #[test]
    fn multiboot_sizes() {
        let m = qemu_pc();
        assert_eq!(m.mem_lower_kib(), 639);
        assert_eq!(m.mem_upper_kib(), (0x7EE_0000 / 1024) as u32);
        assert_eq!(m.usable_bytes(), 0x9FC00 + 0x7EE_0000);
    }

    #[test]
    fn e801_implies_three_regions_and_a_hole() {
        // 640 KiB conventional, 15 MiB below 16 MiB, 112 MiB above: a 128 MiB machine.
        let m = MemoryMap::from_e801(640, 15 * 1024, 112 * 16).unwrap();
        assert!(m.is_usable(0, 0xA0000));
        assert!(!m.is_usable(0xA0000, 1));
        assert!(m.is_usable(0x10_0000, 15 * 1024 * 1024));
        assert!(m.is_usable(0x100_0000, 112 * 1024 * 1024));
        assert_eq!(m.mem_upper_kib(), 15 * 1024 + 112 * 1024);

        // With the ISA hole: only 14 MiB below 16 MiB, so the regions do not join.
        let hole = MemoryMap::from_e801(640, 14 * 1024, 16).unwrap();
        assert_eq!(hole.mem_upper_kib(), 14 * 1024);
        assert!(!hole.is_usable(0xF0_0000, 0x10_0000));
    }
}

//! The boot information stage 2 hands the kernel, in the boot protocol's own format.
//!
//! The same structure `kinboot-efi` writes, through the same `boot_protocol` builder, so
//! the kernel reads both with one provider, `boot/info-kinboot`. What differs is where
//! the facts come from: the memory map is E820's, translated here, and the firmware tag
//! says `Bios`.
//!
//! The kernel is entered through its 32-bit entry, the one a Multiboot loader uses, with
//! [`boot_protocol::ENTRY32_MAGIC`] in `EAX` instead of Multiboot's. See
//! `boot_protocol::image` for that contract.

use boot_protocol::tags::Builder;
use boot_protocol::{Error, Firmware, MemoryKind, MemoryRegion};

use crate::memmap::{Entry, MemoryMap};

/// Bytes the loader sets aside for the structure: the header, the firmware and kernel
/// tags, a full memory map of `memmap::MAX_ENTRIES` regions, and the longest command line.
pub const BYTES: usize = 4096;

/// The protocol's kind for an E820 type. Types this loader does not know are reserved,
/// never usable: a region nobody understands is not memory anyone may hand out.
pub fn kind(e820: u32) -> MemoryKind {
    match e820 {
        1 => MemoryKind::Usable,
        3 => MemoryKind::AcpiReclaimable,
        4 => MemoryKind::AcpiNvs,
        5 => MemoryKind::Bad,
        _ => MemoryKind::Reserved,
    }
}

fn region(e: &Entry) -> MemoryRegion {
    MemoryRegion {
        start: e.base,
        len: e.len,
        kind: kind(e.kind) as u32,
        _reserved: 0,
    }
}

/// Write the structure into `buf`, returning its length.
///
/// `kernel` is the physical range the kernel's segments occupy, `(start, len)`.
pub fn write(
    buf: &mut [u8],
    map: &MemoryMap,
    kernel: (u64, u64),
    cmdline: &[u8],
) -> Result<usize, Error> {
    let mut b = Builder::new(buf)?;
    b.firmware(Firmware::Bios)?;
    b.kernel_range(kernel.0, kernel.1)?;
    b.command_line(cmdline)?;
    let mut m = b.memory_map(map.entries().len())?;
    for e in map.entries() {
        m.push(region(e))?;
    }
    m.close();
    Ok(b.finish())
}

#[cfg(test)]
mod tests {
    use boot_protocol::tags;

    use super::*;

    fn map(entries: &[(u64, u64, u32)]) -> MemoryMap {
        let mut m = MemoryMap::new();
        for &(base, len, kind) in entries {
            m.push(Entry { base, len, kind }).unwrap();
        }
        m
    }

    #[test]
    fn the_kernel_reads_back_what_the_bios_reported() {
        let m = map(&[
            (0x10_0000, 0x7EE_0000, 1),
            (0, 0x9_FC00, 1),
            (0x9_FC00, 0x400, 2),
            (0xF_0000, 0x1_0000, 2),
            (0x7FE_0000, 0x2_0000, 3),
            (0xFFFC_0000, 0x4_0000, 9),
        ]);
        let mut buf = [0u8; BYTES];
        let n = write(&mut buf, &m, (0x10_0000, 0x4_2000), b"mode=safe x=1").unwrap();
        let p = tags::parse(&buf[..n]).unwrap();
        assert_eq!(p.firmware().unwrap(), Some(Firmware::Bios as u32));
        assert_eq!(p.kernel_range().unwrap(), Some((0x10_0000, 0x4_2000)));
        assert_eq!(p.command_line().unwrap(), Some(&b"mode=safe x=1"[..]));
        let regions: Vec<_> = p
            .memory_map()
            .unwrap()
            .unwrap()
            .map(|r| (r.start, r.len, r.kind))
            .collect();
        let k = |k: MemoryKind| k as u32;
        assert_eq!(
            regions,
            [
                (0, 0x9_FC00, k(MemoryKind::Usable)),
                (0x9_FC00, 0x400, k(MemoryKind::Reserved)),
                (0xF_0000, 0x1_0000, k(MemoryKind::Reserved)),
                (0x10_0000, 0x7EE_0000, k(MemoryKind::Usable)),
                (0x7FE_0000, 0x2_0000, k(MemoryKind::AcpiReclaimable)),
                (0xFFFC_0000, 0x4_0000, k(MemoryKind::Reserved)),
            ],
            "sorted, and an unknown type is reserved"
        );
    }

    #[test]
    fn the_largest_map_and_longest_line_fit_the_buffer_set_aside() {
        let mut m = MemoryMap::new();
        for i in 0..crate::memmap::MAX_ENTRIES as u64 {
            // Alternate kinds so nothing merges and every entry takes a region.
            m.push(Entry {
                base: i * 0x1000,
                len: 0x1000,
                kind: 1 + (i % 2) as u32,
            })
            .unwrap();
        }
        let line = [b'x'; boot_protocol::tags::MAX_COMMAND_LINE];
        let mut buf = [0u8; BYTES];
        assert!(write(&mut buf, &m, (0x10_0000, 0x1000), &line).is_ok());
    }
}

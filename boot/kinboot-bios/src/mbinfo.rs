//! The Multiboot 1 information structure stage 2 hands the kernel.
//!
//! This is the interim handover. The kernel already understands Multiboot 1 through
//! `boot/info-multiboot`, because QEMU's `-kernel` speaks it, so a BIOS loader that
//! speaks it too boots the unmodified kernel. The native KinTane boot protocol replaces
//! it once a loader produces `BootInfo`; see `docs/bootloader.md`.
//!
//! The structure is built as bytes at offsets the specification fixes, not as a
//! `#[repr(C)]` struct, because the consumer is a different program. Every offset used
//! is pinned by a test against the numbers in the specification (section 3.3, "Boot
//! information format").

use crate::memmap::MemoryMap;

/// What the kernel finds in `eax`.
pub const BOOTLOADER_MAGIC: u32 = 0x2BAD_B002;

/// Bytes of the information structure up to and including `boot_loader_name`.
pub const INFO_BYTES: usize = 68;
/// One `mmap` entry: `size`, `base_addr`, `length`, `type`. `size` excludes itself.
pub const MMAP_ENTRY_BYTES: usize = 24;

const FLAG_MEM: u32 = 1 << 0;
const FLAG_BOOT_DEVICE: u32 = 1 << 1;
const FLAG_CMDLINE: u32 = 1 << 2;
const FLAG_MMAP: u32 = 1 << 6;
const FLAG_LOADER_NAME: u32 = 1 << 9;

/// Offsets from the specification.
mod at {
    pub const FLAGS: usize = 0;
    pub const MEM_LOWER: usize = 4;
    pub const MEM_UPPER: usize = 8;
    pub const BOOT_DEVICE: usize = 12;
    pub const CMDLINE: usize = 16;
    pub const MMAP_LENGTH: usize = 44;
    pub const MMAP_ADDR: usize = 48;
    pub const BOOT_LOADER_NAME: usize = 64;
}

/// Where the pieces the structure points at live. The caller owns this memory and must
/// keep it below the kernel's reserved low-memory boundary.
#[derive(Clone, Copy)]
pub struct Addresses {
    pub mmap: u32,
    pub cmdline: u32,
    pub loader_name: u32,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TooSmall;

/// Write the information structure into `info` and the memory map into `mmap`.
/// Returns the bytes of `mmap` used.
///
/// `drive` is the BIOS drive number the loader was started from. The partition bytes of
/// `boot_device` are all `0xFF`: the kernel was not loaded from a partition's
/// filesystem, it was read from the disk.
pub fn write(
    info: &mut [u8; INFO_BYTES],
    mmap: &mut [u8],
    map: &MemoryMap,
    drive: u8,
    addr: Addresses,
) -> Result<usize, TooSmall> {
    let mut used = 0;
    for e in map.entries() {
        let slot = mmap
            .get_mut(used..used + MMAP_ENTRY_BYTES)
            .ok_or(TooSmall)?;
        slot[0..4].copy_from_slice(&20u32.to_le_bytes());
        slot[4..12].copy_from_slice(&e.base.to_le_bytes());
        slot[12..20].copy_from_slice(&e.len.to_le_bytes());
        slot[20..24].copy_from_slice(&e.kind.to_le_bytes());
        used += MMAP_ENTRY_BYTES;
    }

    info.fill(0);
    let mut put = |at: usize, v: u32| info[at..at + 4].copy_from_slice(&v.to_le_bytes());
    put(
        at::FLAGS,
        FLAG_MEM | FLAG_BOOT_DEVICE | FLAG_CMDLINE | FLAG_MMAP | FLAG_LOADER_NAME,
    );
    put(at::MEM_LOWER, map.mem_lower_kib());
    put(at::MEM_UPPER, map.mem_upper_kib());
    put(at::BOOT_DEVICE, (drive as u32) << 24 | 0x00FF_FFFF);
    put(at::CMDLINE, addr.cmdline);
    put(at::MMAP_LENGTH, used as u32);
    put(at::MMAP_ADDR, addr.mmap);
    put(at::BOOT_LOADER_NAME, addr.loader_name);
    Ok(used)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memmap::Entry;

    fn le32(b: &[u8], at: usize) -> u32 {
        u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
    }

    #[test]
    fn offsets_match_the_specification() {
        let mut map = MemoryMap::new();
        map.push(Entry {
            base: 0,
            len: 0x9FC00,
            kind: 1,
        })
        .unwrap();
        map.push(Entry {
            base: 0x10_0000,
            len: 0x7EE_0000,
            kind: 1,
        })
        .unwrap();
        map.push(Entry {
            base: 0xFFFC_0000,
            len: 0x4_0000,
            kind: 2,
        })
        .unwrap();
        let mut info = [0xAAu8; INFO_BYTES];
        let mut mmap = [0u8; 4 * MMAP_ENTRY_BYTES];
        let used = write(
            &mut info,
            &mut mmap,
            &map,
            0x80,
            Addresses {
                mmap: 0x9000,
                cmdline: 0x8100,
                loader_name: 0x8200,
            },
        )
        .unwrap();

        assert_eq!(used, 72);
        assert_eq!(le32(&info, 0), 0b10_0100_0111);
        assert_eq!(le32(&info, 4), 639);
        assert_eq!(le32(&info, 8), 0x7EE_0000 / 1024);
        assert_eq!(le32(&info, 12), 0x80FF_FFFF);
        assert_eq!(le32(&info, 16), 0x8100);
        // mods_count, mods_addr and the symbol-table union are zero, not left over.
        assert!(info[20..44].iter().all(|&b| b == 0));
        assert_eq!(le32(&info, 44), 72);
        assert_eq!(le32(&info, 48), 0x9000);
        assert_eq!(le32(&info, 64), 0x8200);

        // Entry stride is size + 4 = 24, which is the quirk the kernel's parser relies on.
        assert_eq!(le32(&mmap, 0), 20);
        assert_eq!(u64::from_le_bytes(mmap[28..36].try_into().unwrap()), 0x10_0000);
        assert_eq!(le32(&mmap, 48 + 20), 2);
    }

    #[test]
    fn a_map_that_does_not_fit_is_an_error() {
        let mut map = MemoryMap::new();
        map.push(Entry {
            base: 0,
            len: 1,
            kind: 1,
        })
        .unwrap();
        map.push(Entry {
            base: 1,
            len: 1,
            kind: 1,
        })
        .unwrap();
        let mut info = [0u8; INFO_BYTES];
        let mut mmap = [0u8; MMAP_ENTRY_BYTES + 3];
        let a = Addresses {
            mmap: 0,
            cmdline: 0,
            loader_name: 0,
        };
        assert_eq!(write(&mut info, &mut mmap, &map, 0x80, a), Err(TooSmall));
    }
}

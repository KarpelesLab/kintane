//! A second-level page table: one translation domain (VT-d §9.7).
//!
//! It is an ordinary four-level page table, the same shape as the CPU's, with one difference
//! that is the whole point: the leaf permission bits are the device's, not a program's. An
//! entry with neither read nor write is *not present*, and a device address that reaches one
//! faults in the hardware instead of touching memory.
//!
//! # Superpages where a range allows them
//!
//! A grant is a few pages; an identity map over all of RAM is tens of thousands. So
//! [`Domain::map`] uses a 2 MiB leaf at the middle level when the address, the physical target
//! and the remaining length are all 2 MiB-aligned, and 4 KiB leaves otherwise. An identity map
//! over 128 MiB is then a handful of frames instead of hundreds, and a grant is still exact.

use crate::{ADDR_MASK, Error, Frames, PAGE_SHIFT, PAGE_SIZE, PhysMem};

/// A second-level page-table entry's permission bits (VT-d §9.7).
pub mod pte {
    /// Readable by the device.
    pub const READ: u64 = 1 << 0;
    /// Writable by the device.
    pub const WRITE: u64 = 1 << 1;
    /// A leaf at this level rather than a pointer to the next (bit 7, "page size").
    pub const SUPERPAGE: u64 = 1 << 7;
}

/// What a device may do to a mapped range.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Perm {
    /// The device reads it: a buffer it fetches from (a write request's data), or the rings.
    Read,
    /// The device reads and writes it: a buffer it fills (a read request's data), the used ring.
    ReadWrite,
}

impl Perm {
    fn bits(self) -> u64 {
        match self {
            Perm::Read => pte::READ,
            Perm::ReadWrite => pte::READ | pte::WRITE,
        }
    }
}

/// Bytes a 2 MiB superpage covers, and the level (counting leaves as level 1) it sits at.
const SUPERPAGE_SIZE: u64 = 2 * 1024 * 1024;

/// One translation domain: the root of a second-level page table, and its identifier.
///
/// `Copy`, because it is only two numbers: which frame the table starts at and which domain id
/// the context entry carries. The frames it points at live in the [`PhysMem`] the unit owns.
#[derive(Clone, Copy, Debug)]
pub struct Domain {
    id: u16,
    root: u64,
    levels: u8,
}

impl Domain {
    pub(crate) fn new(
        id: u16,
        levels: u8,
        mem: &impl PhysMem,
        frames: &mut impl Frames,
    ) -> Result<Domain, Error> {
        let root = frames.alloc().ok_or(Error::NoFrames)?;
        crate::zero_frame(mem, root);
        Ok(Domain { id, root, levels })
    }

    pub fn id(&self) -> u16 {
        self.id
    }

    /// The physical address of the table's top level, for the context entry.
    pub fn root(&self) -> u64 {
        self.root
    }

    /// Map `[iova, iova + len)` to `[phys, phys + len)` with `perm`.
    ///
    /// Every address and the length must be page-aligned. Uses 2 MiB leaves where the range
    /// allows and 4 KiB leaves elsewhere.
    pub fn map(
        &self,
        mut iova: u64,
        mut phys: u64,
        len: u64,
        perm: Perm,
        mem: &impl PhysMem,
        frames: &mut impl Frames,
    ) -> Result<(), Error> {
        if iova % PAGE_SIZE != 0 || phys % PAGE_SIZE != 0 || len % PAGE_SIZE != 0 {
            return Err(Error::Misaligned);
        }
        let end = iova.checked_add(len).ok_or(Error::AddressWidth)?;
        while iova < end {
            let remaining = end - iova;
            if iova % SUPERPAGE_SIZE == 0
                && phys % SUPERPAGE_SIZE == 0
                && remaining >= SUPERPAGE_SIZE
            {
                // A 2 MiB leaf lives at level 2 (the level above the 4 KiB leaves).
                let slot = self.walk(iova, 2, mem, frames)?;
                mem.write64(slot, (phys & ADDR_MASK) | perm.bits() | pte::SUPERPAGE);
                iova += SUPERPAGE_SIZE;
                phys += SUPERPAGE_SIZE;
            } else {
                let slot = self.walk(iova, 1, mem, frames)?;
                mem.write64(slot, (phys & ADDR_MASK) | perm.bits());
                iova += PAGE_SIZE;
                phys += PAGE_SIZE;
            }
        }
        Ok(())
    }

    /// Unmap `[iova, iova + len)`, so those device addresses fault again. Only the leaves are
    /// cleared; the intermediate tables are left, because another mapping may share them.
    pub fn unmap(&self, mut iova: u64, len: u64, mem: &impl PhysMem) -> Result<(), Error> {
        if iova % PAGE_SIZE != 0 || len % PAGE_SIZE != 0 {
            return Err(Error::Misaligned);
        }
        let end = iova.checked_add(len).ok_or(Error::AddressWidth)?;
        while iova < end {
            match self.leaf_of(iova, mem) {
                Some((slot, SUPERPAGE_SIZE)) if iova % SUPERPAGE_SIZE == 0 => {
                    mem.write64(slot, 0);
                    iova += SUPERPAGE_SIZE;
                }
                Some((slot, _)) => {
                    mem.write64(slot, 0);
                    iova += PAGE_SIZE;
                }
                None => iova += PAGE_SIZE,
            }
        }
        Ok(())
    }

    /// Translate a device address as the hardware would: the physical address it maps to and
    /// whether it is writable, or `None` where it faults. For a host to check what was granted.
    pub fn translate(&self, iova: u64, mem: &impl PhysMem) -> Option<(u64, bool)> {
        let (slot, size) = self.leaf_of(iova, mem)?;
        let entry = mem.read64(slot);
        if entry & pte::READ == 0 {
            return None;
        }
        let base = entry & ADDR_MASK;
        Some((base + (iova & (size - 1)), entry & pte::WRITE != 0))
    }

    /// The index into the table at `level` for `iova`. Level 4 is the top; level 1 the 4 KiB
    /// leaves. Each level covers nine bits of address.
    fn index(iova: u64, level: u8) -> u64 {
        let shift = PAGE_SHIFT + 9 * (u64::from(level) - 1);
        (iova >> shift) & 0x1ff
    }

    /// Walk to the entry at `target_level` for `iova`, allocating the tables above it. Returns
    /// the physical address of that entry, ready to be written.
    fn walk(
        &self,
        iova: u64,
        target_level: u8,
        mem: &impl PhysMem,
        frames: &mut impl Frames,
    ) -> Result<u64, Error> {
        let mut table = self.root;
        let mut level = self.levels;
        while level > target_level {
            let slot = table + Self::index(iova, level) * 8;
            let entry = mem.read64(slot);
            table = if entry & (pte::READ | pte::WRITE) != 0 {
                entry & ADDR_MASK
            } else {
                let frame = frames.alloc().ok_or(Error::NoFrames)?;
                crate::zero_frame(mem, frame);
                // An intermediate entry is readable and writable; the leaf's own bits decide
                // what the device may do (VT-d §9.7: permissions are checked at every level).
                mem.write64(slot, (frame & ADDR_MASK) | pte::READ | pte::WRITE);
                frame
            };
            level -= 1;
        }
        Ok(table + Self::index(iova, target_level) * 8)
    }

    /// The leaf entry that covers `iova` and the bytes it spans, walking only tables that
    /// already exist. `None` where the walk hits an absent table or a level with nothing mapped.
    fn leaf_of(&self, iova: u64, mem: &impl PhysMem) -> Option<(u64, u64)> {
        let mut table = self.root;
        let mut level = self.levels;
        loop {
            let slot = table + Self::index(iova, level) * 8;
            let entry = mem.read64(slot);
            if entry & (pte::READ | pte::WRITE) == 0 {
                return None;
            }
            if level == 1 {
                return Some((slot, PAGE_SIZE));
            }
            if entry & pte::SUPERPAGE != 0 {
                let size = 1u64 << (PAGE_SHIFT + 9 * (u64::from(level) - 1));
                return Some((slot, size));
            }
            table = entry & ADDR_MASK;
            level -= 1;
        }
    }
}

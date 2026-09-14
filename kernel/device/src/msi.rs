//! Message-signalled interrupts: MSI and MSI-X, a PCI function's interrupts delivered as a
//! write to an address rather than on a pin.
//!
//! A pin has to be routed. On a PC with an I/O APIC, where a PCI pin arrives is written only
//! in the ACPI namespace's `_PRT`, as AML, so a driver that relies on its pin needs an AML
//! interpreter before its first interrupt. A function that signals by message needs none of
//! that: its capability holds the address and data it writes, and the write lands directly on
//! the interrupt controller of the CPU the address names. That is the whole reason this
//! exists.
//!
//! What lives here is the part every such driver shares and no architecture owns:
//!
//! * reading the capabilities enumeration recorded ([`msix`], [`msi`]);
//! * turning them on through configuration space ([`set_msix_enabled`], [`program_msi`]);
//! * the MSI-X table, reached through a window a driver claimed ([`MsixTable`]);
//! * the specifier a claimed vector carries ([`specifier_cell`], [`vector_of`]), so the ledger and
//!   the handler table treat a vector exactly as they treat a line.
//!
//! What a message *says* — the address and data that reach one CPU's controller — belongs to
//! that controller's driver (`apic::msi` on x86). Which CPU, and which vector, is the
//! platform's decision.
//!
//! Reference: PCI Local Bus Specification 3.0, §6.8 (MSI and MSI-X capabilities).

use crate::pci::{Address, Capability, ConfigSpace, Function};
use crate::registers::Registers;

/// The MSI capability's ID.
pub const CAP_MSI: u8 = 0x05;
/// The MSI-X capability's ID.
pub const CAP_MSIX: u8 = 0x11;

/// The bit in a specifier's one cell that says it names a message-signalled vector rather
/// than a line.
///
/// A line's cell is its number, which is small on every controller this model serves; a
/// vector's is its index into the function's table with this bit set. The specifier's
/// controller is the function's own node, so two functions' vector 0 are distinct claims.
pub const VECTOR_TAG: u32 = 0x8000_0000;

/// The cell a claim on vector `index` carries.
pub const fn specifier_cell(index: u16) -> u32 {
    VECTOR_TAG | index as u32
}

/// The vector a specifier's cells name, if they name one: exactly one cell, tagged.
pub fn vector_of(cells: &[u32]) -> Option<u16> {
    match cells {
        [cell] if cell & VECTOR_TAG != 0 => u16::try_from(cell & !VECTOR_TAG).ok(),
        _ => None,
    }
}

/// MSI-X message control, as bits of the capability's first 32-bit word: the 16-bit
/// control register is its upper half.
mod msix_ctl {
    pub const ENABLE: u32 = 1 << 31;
    pub const FUNCTION_MASK: u32 = 1 << 30;
    /// Table size, encoded as N-1.
    pub const TABLE_SIZE: u32 = 0x7ff << 16;
}

/// MSI message control, the same way.
mod msi_ctl {
    pub const ENABLE: u32 = 1 << 16;
    /// How many vectors are enabled, as a power of two. Always zero here: one vector.
    pub const MULTIPLE_ENABLE: u32 = 0b111 << 20;
    pub const ADDRESS_64: u32 = 1 << 23;
    pub const PER_VECTOR_MASK: u32 = 1 << 24;
}

/// Bytes in one MSI-X table entry.
pub const ENTRY_BYTES: usize = 16;

/// Where each field of an MSI-X table entry is.
mod entry {
    pub const ADDRESS_LOW: usize = 0;
    pub const ADDRESS_HIGH: usize = 4;
    pub const DATA: usize = 8;
    pub const CONTROL: usize = 12;
    /// Vector control bit 0: the entry may not signal.
    pub const MASKED: u32 = 1;
}

/// A function's MSI-X capability, as enumeration recorded it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct MsixCapability {
    /// Where the capability is in configuration space.
    pub offset: u16,
    /// Entries in the table: at least one, at most 2048.
    pub table_size: u16,
    /// The number, 0 to 5, of the BAR the table is in, and how far into it.
    pub table_bar: u8,
    pub table_offset: u32,
    /// The same for the pending-bit array.
    pub pba_bar: u8,
    pub pba_offset: u32,
    /// Whether firmware left MSI-X enabled, and the whole function masked.
    pub enabled: bool,
    pub function_masked: bool,
}

impl MsixCapability {
    /// The capability `c` describes, if it is an MSI-X capability naming real BARs.
    ///
    /// A BAR indicator of 6 or 7 is reserved: a table in a BAR that does not exist is
    /// refused rather than programmed through whatever window happens to be claimed.
    pub fn read(c: &Capability) -> Option<MsixCapability> {
        if c.id != CAP_MSIX {
            return None;
        }
        let control = c.word(0);
        let table = c.word(1);
        let pba = c.word(2);
        let table_bar = (table & 7) as u8;
        let pba_bar = (pba & 7) as u8;
        if table_bar > 5 || pba_bar > 5 {
            return None;
        }
        Some(MsixCapability {
            offset: c.offset,
            table_size: (((control & msix_ctl::TABLE_SIZE) >> 16) + 1) as u16,
            table_bar,
            table_offset: table & !7,
            pba_bar,
            pba_offset: pba & !7,
            enabled: control & msix_ctl::ENABLE != 0,
            function_masked: control & msix_ctl::FUNCTION_MASK != 0,
        })
    }

    /// Bytes the table occupies.
    pub fn table_bytes(&self) -> usize {
        usize::from(self.table_size) * ENTRY_BYTES
    }
}

/// A function's MSI capability, as enumeration recorded it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct MsiCapability {
    pub offset: u16,
    /// Whether the message address is 64 bits wide, which moves the data register.
    pub address_64: bool,
    pub per_vector_mask: bool,
    pub enabled: bool,
}

impl MsiCapability {
    pub fn read(c: &Capability) -> Option<MsiCapability> {
        if c.id != CAP_MSI {
            return None;
        }
        let control = c.word(0);
        Some(MsiCapability {
            offset: c.offset,
            address_64: control & msi_ctl::ADDRESS_64 != 0,
            per_vector_mask: control & msi_ctl::PER_VECTOR_MASK != 0,
            enabled: control & msi_ctl::ENABLE != 0,
        })
    }

    /// Where the 16-bit message data register is, in a word of its own.
    fn data_offset(&self) -> u16 {
        self.offset + if self.address_64 { 12 } else { 8 }
    }
}

/// `f`'s MSI-X capability, if enumeration recorded one.
pub fn msix(f: &Function) -> Option<MsixCapability> {
    f.capabilities().iter().find_map(MsixCapability::read)
}

/// `f`'s MSI capability, if enumeration recorded one.
pub fn msi(f: &Function) -> Option<MsiCapability> {
    f.capabilities().iter().find_map(MsiCapability::read)
}

/// Turn MSI-X on or off for the function at `at`.
///
/// On clears the function-wide mask as well, so each entry's own mask is what decides whether
/// it signals; firmware may leave either bit set. Off leaves the function signalling nothing
/// by message. Returns whether the enable bit reads back as asked, which a function that does
/// not implement the capability it advertised will not do.
///
/// The low half of the word is the capability's ID and next pointer, which are read-only and
/// written back as read.
pub fn set_msix_enabled(
    cfg: &(impl ConfigSpace + ?Sized),
    at: Address,
    cap: &MsixCapability,
    on: bool,
) -> bool {
    let word = cfg.read(at, cap.offset);
    let written = if on {
        (word | msix_ctl::ENABLE) & !msix_ctl::FUNCTION_MASK
    } else {
        word & !msix_ctl::ENABLE
    };
    cfg.write(at, cap.offset, written);
    let back = cfg.read(at, cap.offset);
    (back & msix_ctl::ENABLE != 0) == on && (!on || back & msix_ctl::FUNCTION_MASK == 0)
}

/// Program MSI's single message and enable it: the fallback for a function with MSI but no
/// MSI-X.
///
/// Disabled while the address and data change, so the function cannot signal a half-written
/// message, then enabled with one vector. Refuses a 64-bit address on a function whose
/// capability has only 32 bits of it. Returns whether every field and the enable bit read
/// back as written.
///
/// Unlike an MSI-X entry, MSI has no per-message mask on most functions, and moving its target
/// means writing configuration space again; so a platform that wants to move an interrupt
/// between CPUs after bring-up prefers MSI-X.
pub fn program_msi(
    cfg: &(impl ConfigSpace + ?Sized),
    at: Address,
    cap: &MsiCapability,
    address: u64,
    data: u16,
) -> bool {
    if !cap.address_64 && address >> 32 != 0 {
        return false;
    }
    let control = cfg.read(at, cap.offset);
    cfg.write(at, cap.offset, control & !(msi_ctl::ENABLE | msi_ctl::MULTIPLE_ENABLE));
    cfg.write(at, cap.offset + 4, address as u32);
    if cap.address_64 {
        cfg.write(at, cap.offset + 8, (address >> 32) as u32);
    }
    let data_at = cap.data_offset();
    let old = cfg.read(at, data_at);
    cfg.write(at, data_at, (old & !0xffff) | u32::from(data));
    let enabled = (cfg.read(at, cap.offset) & !msi_ctl::MULTIPLE_ENABLE) | msi_ctl::ENABLE;
    cfg.write(at, cap.offset, enabled);

    let address_ok = cfg.read(at, cap.offset + 4) == address as u32
        && (!cap.address_64 || cfg.read(at, cap.offset + 8) == (address >> 32) as u32);
    address_ok
        && cfg.read(at, data_at) & 0xffff == u32::from(data)
        && cfg.read(at, cap.offset) & msi_ctl::ENABLE != 0
}

/// A function's MSI-X table, reached through a window its driver claimed.
///
/// Every entry starts masked (PCI 3.0 §6.8.2.9), and an entry's address and data may only be
/// changed while it is masked: a function is allowed to latch them at any moment it is not.
/// So there is no call here that writes a message to an unmasked entry.
pub struct MsixTable {
    regs: Registers,
    /// Where the table begins in `regs`.
    base: usize,
    entries: u16,
}

impl MsixTable {
    /// The table `entries` long, `offset` bytes into `regs`. `None` when it does not fit the
    /// window, is empty, or does not start on a register boundary.
    pub fn new(regs: Registers, offset: usize, entries: u16) -> Option<MsixTable> {
        let bytes = usize::from(entries).checked_mul(ENTRY_BYTES)?;
        let end = offset.checked_add(bytes)?;
        (entries > 0 && offset % 4 == 0 && end <= regs.len()).then_some(MsixTable {
            regs,
            base: offset,
            entries,
        })
    }

    pub fn entries(&self) -> u16 {
        self.entries
    }

    /// Where field `field` of entry `index` is, if there is such an entry.
    fn at(&self, index: u16, field: usize) -> Option<usize> {
        (index < self.entries).then(|| self.base + usize::from(index) * ENTRY_BYTES + field)
    }

    /// Whether entry `index` is masked. `None` when there is no such entry.
    pub fn is_masked(&self, index: u16) -> Option<bool> {
        let at = self.at(index, entry::CONTROL)?;
        Some(self.regs.read32(at) & entry::MASKED != 0)
    }

    /// Mask entry `index`. Returns whether it reads back masked.
    pub fn mask(&self, index: u16) -> bool {
        let Some(at) = self.at(index, entry::CONTROL) else {
            return false;
        };
        self.regs.write32(at, self.regs.read32(at) | entry::MASKED);
        self.is_masked(index) == Some(true)
    }

    /// Unmask entry `index`. Returns whether it reads back unmasked.
    pub fn unmask(&self, index: u16) -> bool {
        let Some(at) = self.at(index, entry::CONTROL) else {
            return false;
        };
        self.regs.write32(at, self.regs.read32(at) & !entry::MASKED);
        self.is_masked(index) == Some(false)
    }

    /// Entry `index`'s message, `(address, data)`.
    pub fn message(&self, index: u16) -> Option<(u64, u32)> {
        let low = self.regs.read32(self.at(index, entry::ADDRESS_LOW)?);
        let high = self.regs.read32(self.at(index, entry::ADDRESS_HIGH)?);
        let data = self.regs.read32(self.at(index, entry::DATA)?);
        Some((u64::from(low) | (u64::from(high) << 32), data))
    }

    /// Write entry `index`'s message, leaving it masked. Refused — returns `false` and writes
    /// nothing — when the entry is not masked, since the function may be latching it.
    pub fn set_message(&self, index: u16, address: u64, data: u32) -> bool {
        if self.is_masked(index) != Some(true) {
            return false;
        }
        let (Some(low), Some(high), Some(data_at)) = (
            self.at(index, entry::ADDRESS_LOW),
            self.at(index, entry::ADDRESS_HIGH),
            self.at(index, entry::DATA),
        ) else {
            return false;
        };
        self.regs.write32(low, address as u32);
        self.regs.write32(high, (address >> 32) as u32);
        self.regs.write32(data_at, data);
        self.message(index) == Some((address, data))
    }

    /// Point entry `index` somewhere else: mask it, write the message, unmask it. Returns
    /// whether each step read back as asked. A failure leaves the entry masked, which loses
    /// interrupts rather than delivering them to a half-written message.
    pub fn retarget(&self, index: u16, address: u64, data: u32) -> bool {
        self.mask(index) && self.set_message(index, address, data) && self.unmask(index)
    }
}

//! Interrupt remapping (VT-d §5.1, §9.10): the table that says where each device interrupt
//! goes, and from whom it is accepted.
//!
//! With remapping on, a device's MSI no longer names a CPU and a vector itself. Its address
//! carries a *handle*, an index into the interrupt remapping table. The table entry (an IRTE)
//! holds the destination, the vector and the trigger mode, and the source id of the one
//! function allowed to use it. A message whose entry is not present, or which comes from a
//! function other than the one its entry names, is blocked. The hardware records it in the
//! fault log with a reason from 0x20 to 0x26 (§7.1), just as it records a DMA fault.
//!
//! Where an interrupt goes is then the kernel's decision, kept in memory the device cannot
//! write, rather than a value the device holds. And a destination in extended interrupt mode
//! is 32 bits, which is the only way an MSI can name a CPU whose x2APIC ID is above 255.
//!
//! # What is here
//!
//! - [`InterruptTable`]: one frame of [`IRT_ENTRIES`] entries.
//! - [`Irte`], encoded into and decoded from the table.
//! - [`Unit::enable_interrupt_remapping`]: the table address into `IRTA`, `SIRTP`, then `IRE`
//!   (§10.4.4), with extended interrupt mode wherever the unit offers it.
//! - [`remappable_message`] and [`message_handle`]: the MSI address a device is programmed with
//!   (§5.1.2.2), and back.
//!
//! # Changing an entry in use
//!
//! The unit caches the entries it has read (the interrupt entry cache), so once remapping is on
//! an entry is changed in two steps: the table, then an index-selective interrupt entry cache
//! invalidation through the queue (§6.5.2.7), waited for. [`Unit::set_irte`] refuses to change
//! an entry in use on a unit without the queue on, rather than change it half way. QEMU keeps no
//! such cache for an emulated device's messages, so there the flush changes nothing a guest can
//! see; the host tests' model does keep one, and shows a change without the flush being ignored.
//!
//! # Not here
//!
//! Compatibility-format interrupts are left as the unit's reset leaves them.

use crate::{Error, Frames, Invalidation, PAGE_SIZE, PhysMem, Regs, Unit, reg, zero_frame};

/// Entries in a table here: one frame of 16-byte entries.
pub const IRT_ENTRIES: u16 = 256;
/// `IRTA.IRTS`: the table holds `2^(IRTS + 1)` entries.
const IRTS_256: u64 = 7;
/// `IRTA.EIME`: extended interrupt mode, whose destinations are 32 bits.
const IRTA_EIME: u64 = 1 << 11;

/// IRTE low qword: present.
const IRTE_PRESENT: u64 = 1 << 0;
/// IRTE low qword: trigger mode, 1 for level.
const IRTE_LEVEL: u64 = 1 << 4;
/// IRTE high qword: source-id validation type 01, the requester id must match `SID` exactly.
const IRTE_SVT_REQUESTER: u64 = 1 << 18;
/// The bits of the high qword this driver sets: `SID` and `SVT`, the rest reserved or `SQ` 0.
const IRTE_HIGH_USED: u64 = 0xf_ffff;
/// The bits of the low qword this driver sets: present, trigger, vector and destination.
const IRTE_LOW_USED: u64 = 0xffff_ffff_00ff_0011;

/// A remappable-format MSI address's fixed high bits.
const MSI_ADDRESS_BASE: u64 = 0xfee0_0000;
/// Address bit 4: the interrupt format, 1 for remappable.
const MSI_REMAPPABLE: u64 = 1 << 4;

/// One interrupt remapping table entry: fixed delivery to one CPU, by physical destination.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Irte {
    pub vector: u8,
    /// The local APIC ID delivered to: at most 255 unless the table is extended.
    pub destination: u32,
    /// Level-triggered rather than edge. An MSI is edge.
    pub level: bool,
    /// The one requester the entry accepts (`bus << 8 | dev << 3 | fn`).
    pub source: u16,
}

impl Irte {
    /// The entry's two qwords, low then high. `None` for a destination the table's mode cannot
    /// hold: above 255 when it is not extended.
    pub fn encode(&self, extended: bool) -> Option<(u64, u64)> {
        // Extended mode takes the whole 32-bit destination; xAPIC mode takes an 8-bit APIC ID in
        // bits 15:8 of that field (§9.10).
        let destination = if extended {
            u64::from(self.destination)
        } else {
            u64::from(u8::try_from(self.destination).ok()?) << 8
        };
        let mut low = IRTE_PRESENT | (u64::from(self.vector) << 16) | (destination << 32);
        if self.level {
            low |= IRTE_LEVEL;
        }
        let high = u64::from(self.source) | IRTE_SVT_REQUESTER;
        Some((low, high))
    }

    /// The entry two qwords hold, or `None` when it is not present or uses what this driver
    /// never sets.
    pub fn decode(low: u64, high: u64, extended: bool) -> Option<Irte> {
        if low & IRTE_PRESENT == 0 || low & !IRTE_LOW_USED != 0 || high & !IRTE_HIGH_USED != 0 {
            return None;
        }
        let field = (low >> 32) as u32;
        Some(Irte {
            vector: (low >> 16) as u8,
            destination: if extended { field } else { (field >> 8) & 0xff },
            level: low & IRTE_LEVEL != 0,
            source: high as u16,
        })
    }
}

/// An interrupt remapping table: its frame, and whether its destinations are 32 bits.
pub struct InterruptTable {
    phys: u64,
    extended: bool,
}

impl InterruptTable {
    pub fn phys(&self) -> u64 {
        self.phys
    }

    /// Whether the table is in extended interrupt mode, so a destination can exceed 255.
    pub fn extended(&self) -> bool {
        self.extended
    }
}

/// The address and data a device is programmed with to raise the interrupt at table index
/// `handle`: remappable format, no subhandle (§5.1.2.2).
pub fn remappable_message(handle: u16) -> (u64, u32) {
    let h = u64::from(handle);
    let address = MSI_ADDRESS_BASE | ((h & 0x7fff) << 5) | MSI_REMAPPABLE | ((h >> 15) << 2);
    (address, 0)
}

/// The table index a remappable-format MSI address names, or `None` for an address in
/// compatibility format.
pub fn message_handle(address: u64) -> Option<u16> {
    if address & !0xffff_ffff != 0
        || address & 0xfff0_0000 != MSI_ADDRESS_BASE
        || address & MSI_REMAPPABLE == 0
    {
        return None;
    }
    Some((((address >> 5) & 0x7fff) | (((address >> 2) & 1) << 15)) as u16)
}

impl<R: Regs, M: PhysMem> Unit<R, M> {
    /// Whether the unit can remap interrupts.
    pub fn supports_interrupt_remapping(&self) -> bool {
        self.regs.read64(reg::ECAP) & reg::ecap::IR != 0
    }

    /// An empty table: every entry not present, so every remappable message is blocked until an
    /// entry is set. Extended when the unit has extended interrupt mode.
    pub fn new_interrupt_table(
        &mut self,
        frames: &mut impl Frames,
    ) -> Result<InterruptTable, Error> {
        let ecap = self.regs.read64(reg::ECAP);
        if ecap & reg::ecap::IR == 0 {
            return Err(Error::NoInterruptRemapping);
        }
        let phys = frames.alloc().ok_or(Error::NoFrames)?;
        zero_frame(&self.mem, phys);
        Ok(InterruptTable {
            phys,
            extended: ecap & reg::ecap::EIM != 0,
        })
    }

    /// Set entry `handle` to `entry`, or make it not present with `None`.
    ///
    /// The high qword is written before the low one, whose present bit makes the entry usable,
    /// so an entry is never present with another entry's source id. With remapping on, the
    /// hardware may have cached the old entry, so the change is followed by that entry's cache
    /// invalidation, and refused on a unit without the queue on to send it.
    pub fn set_irte(
        &mut self,
        table: &InterruptTable,
        handle: u16,
        entry: Option<Irte>,
    ) -> Result<(), Error> {
        if handle >= IRT_ENTRIES {
            return Err(Error::BadHandle);
        }
        let in_use = self.interrupt_remapping_enabled();
        if in_use && self.queue.is_none() {
            return Err(Error::NoQueuedInvalidation);
        }
        let at = table.phys + u64::from(handle) * 16;
        match entry {
            None => {
                self.mem.write64(at, 0);
                self.mem.write64(at + 8, 0);
            }
            Some(e) => {
                let (low, high) = e.encode(table.extended).ok_or(Error::Destination)?;
                self.mem.write64(at, 0);
                self.mem.write64(at + 8, high);
                self.mem.write64(at, low);
            }
        }
        if in_use {
            self.invalidate(&[Invalidation::InterruptEntry { handle }])?;
        }
        Ok(())
    }

    /// Entry `handle` as the table holds it, if present.
    pub fn irte(&self, table: &InterruptTable, handle: u16) -> Option<Irte> {
        if handle >= IRT_ENTRIES {
            return None;
        }
        let at = table.phys + u64::from(handle) * 16;
        Irte::decode(self.mem.read64(at), self.mem.read64(at + 8), table.extended)
    }

    /// Turn interrupt remapping on with `table`: its address and size into `IRTA`, latched with
    /// `SIRTP`, then `IRE`. Translation, if on, stays on.
    pub fn enable_interrupt_remapping(&mut self, table: &InterruptTable) -> Result<(), Error> {
        debug_assert_eq!(PAGE_SIZE, u64::from(IRT_ENTRIES) * 16);
        let mut irta = table.phys | IRTS_256;
        if table.extended {
            irta |= IRTA_EIME;
        }
        self.regs.write64(reg::IRTA, irta);
        self.command(reg::gcmd::SIRTP, reg::gsts::IRTPS, "set interrupt remapping table pointer")?;
        // A newly latched table makes every cached entry stale (§6.5.2.7).
        if self.queue.is_some() {
            self.invalidate(&[Invalidation::InterruptGlobal])?;
        }
        self.command(reg::gcmd::IRE, reg::gsts::IRES, "enable interrupt remapping")
    }

    /// Whether interrupt remapping is on, read from the hardware.
    pub fn interrupt_remapping_enabled(&self) -> bool {
        self.regs.read32(reg::GSTS) & reg::gsts::IRES != 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::harness::{MockFrames, MockMem, MockRegs};

    fn unit(regs: MockRegs) -> (Unit<MockRegs, MockMem>, MockFrames) {
        let mut pool = MockFrames::new(64);
        let unit = Unit::new(regs, MockMem::default(), &mut pool).expect("bring-up");
        (unit, pool)
    }

    const DISK: u16 = 0x0018;

    #[test]
    fn an_entry_round_trips_in_both_interrupt_modes() {
        let e = Irte {
            vector: 48,
            destination: 3,
            level: false,
            source: DISK,
        };
        for extended in [false, true] {
            let (low, high) = e.encode(extended).unwrap();
            assert_eq!(Irte::decode(low, high, extended), Some(e));
            assert_eq!(low & 1, 1, "present");
            assert_eq!(high & 0xffff, u64::from(DISK));
            assert_eq!((high >> 18) & 3, 1, "the requester id is validated");
        }
        // xAPIC mode puts the 8-bit APIC ID in bits 15:8 of the destination field.
        assert_eq!(e.encode(false).unwrap().0 >> 32, 3 << 8);
        assert_eq!(e.encode(true).unwrap().0 >> 32, 3);
    }

    #[test]
    fn an_x2apic_id_above_255_needs_extended_mode_and_is_kept_whole() {
        let e = Irte {
            vector: 48,
            destination: 0x100,
            level: false,
            source: DISK,
        };
        assert_eq!(e.encode(false), None, "no 8-bit field holds 256");
        let (low, high) = e.encode(true).unwrap();
        assert_eq!(low >> 32, 0x100, "not truncated to APIC ID 0");
        assert_eq!(Irte::decode(low, high, true).unwrap().destination, 0x100);
        let high_id = Irte {
            destination: 0xdead_beef,
            ..e
        };
        let (low, high) = high_id.encode(true).unwrap();
        assert_eq!(Irte::decode(low, high, true), Some(high_id));
    }

    #[test]
    fn a_remappable_message_carries_its_handle() {
        assert_eq!(remappable_message(0), (0xfee0_0010, 0));
        for handle in [0u16, 1, 0x55, 0x7fff, 0x8000, 0xffff] {
            let (address, data) = remappable_message(handle);
            assert_eq!(data, 0);
            assert_eq!(address & 0xfff0_0000, 0xfee0_0000);
            assert_eq!(message_handle(address), Some(handle));
        }
        // A compatibility-format message names an APIC ID, not a handle.
        assert_eq!(message_handle(0xfee0_3000), None);
        assert_eq!(message_handle(0x1_fee0_0010), None);
    }

    #[test]
    fn enabling_latches_the_table_and_keeps_translation_on() {
        let (mut unit, mut pool) = unit(MockRegs::new());
        unit.enable().unwrap();
        let table = unit.new_interrupt_table(&mut pool).unwrap();
        assert!(table.extended());
        unit.enable_interrupt_remapping(&table).unwrap();
        assert!(unit.interrupt_remapping_enabled());
        assert!(unit.enabled(), "turning remapping on left translation on");
        let irta = unit.regs_for_test().read64(reg::IRTA);
        assert_eq!(irta & !0xfff, table.phys());
        assert_eq!(irta & 0xf, 7, "256 entries");
        assert_ne!(irta & IRTA_EIME, 0, "extended interrupt mode");
    }

    #[test]
    fn entries_are_written_where_the_hardware_reads_them() {
        let (mut unit, mut pool) = unit(MockRegs::new());
        let table = unit.new_interrupt_table(&mut pool).unwrap();
        let e = Irte {
            vector: 49,
            destination: 0x100,
            level: false,
            source: DISK,
        };
        assert_eq!(unit.irte(&table, 5), None, "a new table blocks everything");
        unit.set_irte(&table, 5, Some(e)).unwrap();
        let (low, high) = e.encode(true).unwrap();
        assert_eq!(unit.mem().read64(table.phys() + 5 * 16), low);
        assert_eq!(unit.mem().read64(table.phys() + 5 * 16 + 8), high);
        assert_eq!(unit.irte(&table, 5), Some(e));
        unit.set_irte(&table, 5, None).unwrap();
        assert_eq!(unit.irte(&table, 5), None);
        assert_eq!(unit.set_irte(&table, 256, Some(e)), Err(Error::BadHandle));
    }

    #[test]
    fn a_unit_without_remapping_refuses_a_table_and_xapic_mode_refuses_a_wide_id() {
        let (mut unit, mut pool) = unit(MockRegs::without_remapping());
        assert!(!unit.supports_interrupt_remapping());
        assert_eq!(unit.new_interrupt_table(&mut pool).err(), Some(Error::NoInterruptRemapping));
        let (mut unit, mut pool) = unit_xapic();
        let table = unit.new_interrupt_table(&mut pool).unwrap();
        assert!(!table.extended());
        let wide = Irte {
            vector: 48,
            destination: 0x100,
            level: false,
            source: DISK,
        };
        assert_eq!(unit.set_irte(&table, 0, Some(wide)), Err(Error::Destination));
    }

    fn unit_xapic() -> (Unit<MockRegs, MockMem>, MockFrames) {
        unit(MockRegs::xapic_remapping())
    }

    #[test]
    fn a_blocked_interrupt_is_read_from_the_fault_log_with_its_index() {
        let (mut unit, _) = unit(MockRegs::new());
        // Reason 0x26: the requester is not the function the entry names; index 5.
        unit.regs_for_test()
            .plant_fault(5 << 48, 0x0019, 0x26, true);
        let fault = unit.take_fault().unwrap();
        assert!(fault.is_interrupt());
        assert_eq!(fault.interrupt_index(), Some(5));
        assert_eq!(fault.source_id, 0x0019);
        // A DMA fault is not an interrupt fault.
        unit.regs_for_test().plant_fault(0x5000, DISK, 5, true);
        let fault = unit.take_fault().unwrap();
        assert!(!fault.is_interrupt());
        assert_eq!(fault.interrupt_index(), None);
    }
}

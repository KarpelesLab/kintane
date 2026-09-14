//! The I/O APIC: routes global system interrupts to CPUs as vectors.
//!
//! # Registers
//!
//! Two, in a window of 0x20 bytes: `IOREGSEL` at 0x00 selects an internal register and
//! `IOWIN` at 0x10 reads or writes it. Internal register 1 is the version, whose bits
//! 16..24 hold the index of the last redirection entry, and each redirection entry is
//! the pair of internal registers `0x10 + 2n` (low) and `0x11 + 2n` (high).
//!
//! The select-then-access pair is two register accesses with state in between, so the
//! controller must not be used from two places at once. Today every access is on the boot
//! CPU with its interrupts masked; a second CPU that enables lines needs a lock here.
//!
//! # ISA interrupts and source overrides
//!
//! The kernel names a legacy device by its ISA IRQ, and the I/O APIC by global system
//! interrupt. By default ISA IRQ `n` is GSI `n`, edge-triggered, active high. The MADT's
//! interrupt source overrides say where that is not true, and on every PC one of them is
//! the timer: QEMU wires the PIT's IRQ 0 to GSI 2. [`route`] applies them.
//!
//! Reference: Intel 82093AA I/O APIC datasheet; ACPI 6.5 §5.2.12.5 (interrupt source
//! override flags, which are MPS INTI flags).

use device::Registers;

const IOREGSEL: usize = 0x00;
const IOWIN: usize = 0x10;

/// Internal register 1: the version, and the last redirection entry's index.
const VERSION: u32 = 1;
/// Internal register of redirection entry 0's low half.
const REDIRECTION_BASE: u32 = 0x10;

/// Redirection entry bit 13: active low.
pub const ACTIVE_LOW: u64 = 1 << 13;
/// Redirection entry bit 15: level-triggered.
pub const LEVEL: u64 = 1 << 15;
/// Redirection entry bit 16: masked.
pub const MASKED: u64 = 1 << 16;

/// How the kernel's controller reaches one I/O APIC's internal registers.
pub trait IoRegisters {
    fn read(&self, index: u32) -> u32;
    fn write(&self, index: u32, value: u32);
}

/// An I/O APIC through its memory-mapped select and window registers.
pub struct MmioIo(pub Registers);

impl IoRegisters for MmioIo {
    fn read(&self, index: u32) -> u32 {
        self.0.write32(IOREGSEL, index);
        self.0.read32(IOWIN)
    }

    fn write(&self, index: u32, value: u32) {
        self.0.write32(IOREGSEL, index);
        self.0.write32(IOWIN, value);
    }
}

/// An interrupt source override, as the MADT gives it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Override {
    /// The ISA IRQ.
    pub source: u8,
    /// The global system interrupt it arrives on.
    pub gsi: u32,
    /// MPS INTI flags: polarity in bits 0..2, trigger mode in bits 2..4.
    pub flags: u16,
}

impl Override {
    pub const EMPTY: Override = Override {
        source: 0,
        gsi: 0,
        flags: 0,
    };
}

/// Where ISA IRQ `irq` is delivered, and how: `(gsi, active_low, level)`.
///
/// "Conforms to the bus" is edge and active high for ISA, which is what an interrupt with
/// no override gets too.
pub fn route(irq: u8, overrides: &[Override]) -> (u32, bool, bool) {
    let Some(o) = overrides.iter().find(|o| o.source == irq) else {
        return (u32::from(irq), false, false);
    };
    let polarity = o.flags & 0b11;
    let trigger = (o.flags >> 2) & 0b11;
    (o.gsi, polarity == 0b11, trigger == 0b11)
}

/// A redirection entry delivering `vector` to the APIC whose ID is `dest`, in fixed
/// delivery and physical destination mode.
pub fn redirection(vector: u8, dest: u32, active_low: bool, level: bool, masked: bool) -> u64 {
    let mut entry = u64::from(vector) | (u64::from(dest & 0xff) << 56);
    if active_low {
        entry |= ACTIVE_LOW;
    }
    if level {
        entry |= LEVEL;
    }
    if masked {
        entry |= MASKED;
    }
    entry
}

/// One I/O APIC.
pub struct IoApic<R: IoRegisters> {
    regs: R,
    /// The first GSI this controller serves.
    gsi_base: u32,
    /// How many redirection entries it has.
    entries: u32,
}

impl<R: IoRegisters> IoApic<R> {
    /// The controller behind `regs`, serving GSIs from `gsi_base`. Reads how many entries it
    /// has from the controller itself.
    pub fn new(regs: R, gsi_base: u32) -> IoApic<R> {
        let entries = ((regs.read(VERSION) >> 16) & 0xff) + 1;
        IoApic {
            regs,
            gsi_base,
            entries,
        }
    }

    pub fn entries(&self) -> u32 {
        self.entries
    }

    /// The entry index for `gsi`, if this controller serves it.
    pub fn index_of(&self, gsi: u32) -> Option<u32> {
        let i = gsi.checked_sub(self.gsi_base)?;
        (i < self.entries).then_some(i)
    }

    /// Write redirection entry `index`, high half first, so the destination is in place
    /// before an unmasked low half can deliver.
    pub fn set(&self, index: u32, entry: u64) {
        if index >= self.entries {
            return;
        }
        let at = REDIRECTION_BASE + 2 * index;
        self.regs.write(at + 1, (entry >> 32) as u32);
        self.regs.write(at, entry as u32);
    }

    /// Read redirection entry `index`.
    pub fn get(&self, index: u32) -> u64 {
        let at = REDIRECTION_BASE + 2 * index;
        (u64::from(self.regs.read(at + 1)) << 32) | u64::from(self.regs.read(at))
    }

    /// Mask every entry.
    pub fn mask_all(&self) {
        for i in 0..self.entries {
            self.set(i, MASKED);
        }
    }
}

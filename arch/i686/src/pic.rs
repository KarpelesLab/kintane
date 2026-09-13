//! The 8259A programmable interrupt controller pair.
//!
//! An interrupt controller is a *device*, not part of the architecture: the same
//! image must drive this on a machine that has nothing better and an APIC on one that
//! does. So this is a driver behind `dyn IrqChip` rather than an inherent part of
//! `I686`, exactly as `docs/portability.md` describes — the architecture layer is
//! static and generic, the device layer is dynamic.
//!
//! ## Why this is a second copy of `arch/x86_64/src/pic.rs`
//!
//! Because it is the same *device* and the two crates are separate units that may not
//! depend on each other. The chip is a 1976 design on an 8-bit bus; nothing in its
//! programming model knows or cares what mode the CPU is in, so the register
//! sequences below are identical to the 64-bit port's by necessity rather than by
//! copy-paste convenience. That identity is the argument for moving it: this belongs
//! in `drivers/irqchip/` behind the device framework, alongside the GIC drivers that
//! `docs/roadmap.md` already records as living in the wrong place. Sharing it now
//! would mean an "x86 common" crate, which is the first place 64-bit assumptions leak
//! back into the 32-bit build — the same argument `serial.rs` makes.
//!
//! ## Why remapping is not optional
//!
//! After a PC reset the master PIC delivers IRQ 0..8 on vectors 0x08..0x10 and the
//! slave IRQ 8..16 on 0x70..0x78. The master's range sits on top of the CPU's own
//! exception vectors: a timer tick arrives as #DF and a keyboard interrupt as #TS.
//! In real mode nobody noticed, because the BIOS owned both. A protected-mode kernel
//! must move them, and 32..48 is the conventional destination — the first vectors
//! above the architecturally reserved 0..32.
//!
//! ## State
//!
//! The driver holds none. The mask lives in the chip's own IMR, which is readable, so
//! `enable`/`disable` are read-modify-write against the hardware rather than against
//! a cached copy that could drift out of step with it. That also makes the type
//! trivially `Sync` — there is nothing to protect.
//!
//! Reference: Intel 8259A datasheet (ICW/OCW sequences); the initialisation order
//! ICW1 → ICW2 → ICW3 → ICW4 is fixed by the chip, which latches them positionally on
//! consecutive writes to the data port.

use hal::{IrqChip, IrqNumber};

use crate::serial::{inb, outb};

const MASTER_CMD: u16 = 0x20;
const MASTER_DATA: u16 = 0x21;
const SLAVE_CMD: u16 = 0xa0;
const SLAVE_DATA: u16 = 0xa1;

/// ICW1: begin initialisation, edge triggered, cascaded, ICW4 will follow.
const ICW1_INIT: u8 = 0x11;
/// ICW4: 8086/8088 mode, normal EOI.
const ICW4_8086: u8 = 0x01;
/// OCW2: non-specific end of interrupt.
const EOI: u8 = 0x20;
/// OCW3: the next read of the command port returns the in-service register.
const READ_ISR: u8 = 0x0b;

/// The IRQ line the slave is cascaded onto.
const CASCADE_IRQ: u8 = 2;

/// First vector of the master's range. IRQ `n` for `n < 8` arrives on `BASE + n`.
pub const VECTOR_BASE: u8 = 32;
/// First vector of the slave's range. IRQ `n` for `n >= 8` arrives on `BASE + n`.
pub const SLAVE_VECTOR_BASE: u8 = VECTOR_BASE + 8;
/// Number of IRQ lines the pair provides.
pub const LINES: u8 = 16;

/// The legacy 8259A pair, master cascaded to slave on IRQ 2.
pub struct Pic8259;

/// The instance. One per machine by construction — there is exactly one legacy PIC
/// pair on a PC, at fixed port addresses.
pub static PIC: Pic8259 = Pic8259;

/// Give the chip time to accept a command on machines where the ISA bus is slower
/// than the CPU.
///
/// Port 0x80 is the POST diagnostic port: writing it is harmless on every PC and on
/// QEMU, and takes one bus cycle, which is the delay the 8259A wants between writes.
/// More likely to matter here than on x86_64: the machines this port exists for are
/// the ones old enough to have a real ISA bus behind these ports.
fn io_wait() {
    // SAFETY: port 0x80 is the POST code port. Writing it has no effect beyond
    // driving a value onto a diagnostic display that no machine we target has.
    unsafe { outb(0x80, 0) };
}

impl Pic8259 {
    fn data_port(irq: u8) -> u16 {
        if irq < 8 { MASTER_DATA } else { SLAVE_DATA }
    }

    /// Read the in-service register of one chip.
    fn isr(cmd_port: u16) -> u8 {
        // SAFETY: OCW3 selects which register the next command-port read returns; the
        // read itself does not acknowledge anything and does not change chip state.
        unsafe {
            outb(cmd_port, READ_ISR);
            inb(cmd_port)
        }
    }
}

impl IrqChip for Pic8259 {
    /// Remap both chips to 32..48 and mask every line.
    ///
    /// # Safety
    /// Must be called once, with interrupts masked on the CPU. Between ICW1 and ICW4
    /// the chip is mid-sequence and will misinterpret any other access to its ports,
    /// so nothing else may touch them concurrently — which on a uniprocessor means
    /// no interrupt may be delivered in the middle of this function.
    unsafe fn init(&self) {
        // SAFETY: the ICW sequence from the 8259A datasheet, on the two port pairs
        // that the PC architecture fixes at 0x20/0xa0. Each write is a step of that
        // sequence and the order is the one the chip latches on.
        unsafe {
            outb(MASTER_CMD, ICW1_INIT);
            io_wait();
            outb(SLAVE_CMD, ICW1_INIT);
            io_wait();

            // ICW2: vector base of each chip.
            outb(MASTER_DATA, VECTOR_BASE);
            io_wait();
            outb(SLAVE_DATA, SLAVE_VECTOR_BASE);
            io_wait();

            // ICW3: master learns which line the slave hangs off as a bitmask, slave
            // learns the same line as a number. Asymmetric because the chips use it
            // differently, not because one of them is wrong.
            outb(MASTER_DATA, 1 << CASCADE_IRQ);
            io_wait();
            outb(SLAVE_DATA, CASCADE_IRQ);
            io_wait();

            outb(MASTER_DATA, ICW4_8086);
            io_wait();
            outb(SLAVE_DATA, ICW4_8086);
            io_wait();

            // Mask everything. Lines are unmasked one at a time by whoever owns the
            // device behind them; a controller that comes up with lines open is a
            // controller that delivers an interrupt before its handler exists. On a
            // BIOS-booted machine this also shuts off whatever the firmware left
            // enabled, which on i686 is not hypothetical.
            outb(MASTER_DATA, 0xff);
            outb(SLAVE_DATA, 0xff);
        }
    }

    fn enable(&self, irq: IrqNumber) {
        let Ok(line) = u8::try_from(irq.0) else {
            return;
        };
        if line >= LINES {
            return;
        }
        let port = Self::data_port(line);
        // SAFETY: the data port of an initialised 8259A is its interrupt mask
        // register; reading it is free of side effects and writing it only changes
        // which lines are delivered.
        unsafe {
            outb(port, inb(port) & !(1 << (line % 8)));
        }
        // A slave line is delivered through the cascade, so the master's line 2 has
        // to be open as well or the slave's request never reaches the CPU.
        if line >= 8 {
            // SAFETY: as above, on the master's mask register.
            unsafe {
                outb(MASTER_DATA, inb(MASTER_DATA) & !(1 << CASCADE_IRQ));
            }
        }
    }

    fn disable(&self, irq: IrqNumber) {
        let Ok(line) = u8::try_from(irq.0) else {
            return;
        };
        if line >= LINES {
            return;
        }
        let port = Self::data_port(line);
        // SAFETY: as in `enable`; this only sets a mask bit.
        unsafe {
            outb(port, inb(port) | (1 << (line % 8)));
        }
        // The cascade line is deliberately left open even when the last slave line is
        // masked: masking it would also suppress the spurious-IRQ15 indication, which
        // is the one case where we need the master to tell us something about a slave
        // line that is not requesting service.
    }

    /// Which line is currently in service, if any.
    ///
    /// `None` means the CPU was interrupted by a line that is not in service, which
    /// is the 8259A's spurious interrupt: it asserts INTR, the CPU acknowledges, and
    /// by then the request has gone away, so the chip reports its lowest-priority
    /// line (7, or 15 on the slave) without setting the corresponding ISR bit. Such
    /// an interrupt must *not* be acknowledged; see the caller in `interrupt.rs`.
    fn claim(&self) -> Option<IrqNumber> {
        let master = Self::isr(MASTER_CMD);
        if master == 0 {
            return None;
        }
        // The lowest set bit is the highest priority line, which is the one the chip
        // is presenting.
        let line = master.trailing_zeros() as u8;
        if line != CASCADE_IRQ {
            return Some(IrqNumber(u32::from(line)));
        }
        let slave = Self::isr(SLAVE_CMD);
        if slave == 0 {
            // Cascade in service but no slave line is: a spurious slave interrupt.
            return None;
        }
        Some(IrqNumber(u32::from(8 + slave.trailing_zeros() as u8)))
    }

    fn eoi(&self, irq: IrqNumber) {
        let Ok(line) = u8::try_from(irq.0) else {
            return;
        };
        if line >= LINES {
            return;
        }
        // Order matters: the slave is acknowledged first, because acknowledging the
        // master's cascade line before the slave has cleared its own ISR bit would
        // let the master re-present the same request.
        if line >= 8 {
            // SAFETY: OCW2 non-specific EOI on the slave's command port; it clears
            // the highest-priority in-service bit and nothing else.
            unsafe { outb(SLAVE_CMD, EOI) };
        }
        // SAFETY: OCW2 non-specific EOI on the master's command port.
        unsafe { outb(MASTER_CMD, EOI) };
    }

    fn name(&self) -> &'static str {
        "8259A PIC"
    }
}

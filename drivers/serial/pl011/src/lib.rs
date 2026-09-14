//! Arm PrimeCell PL011 UART.
//!
//! Bound by `arm,pl011`. The register window is the node's first `reg`, and the baud
//! rate divisor is computed from the frequency of the node's first clock, `uartclk`, as
//! the binding names it — on QEMU `virt` a 24 MHz fixed clock. The early console in
//! `arch` hardcodes both, which is right for a console that must work before any tree
//! is read, and is exactly what this driver exists to stop depending on.
//!
//! Transmit is polled: a console that must report a fault has nobody to wake it. Receive
//! is interrupt-driven — the line the node names is claimed at probe, and once the
//! platform has wired the handler up, every byte that arrives is taken by
//! [`on_interrupt`] and queued for a reader in [`rx`].
//!
//! Reference: Arm PrimeCell UART (PL011) Technical Reference Manual, DDI 0183, §3.

#![cfg_attr(not(test), no_std)]
#![deny(unsafe_code)]

use device::{BootCell, Bound, Driver, IrqLine, Mmio, Probe, ProbeError, Registers, Started};
use hal::EarlyConsole;

// The receive queue needs atomics to share with the handler; without them the driver
// transmits only. Selected here, at module level.
#[cfg(all(target_has_atomic = "8", target_has_atomic = "32"))]
mod rx;
#[cfg(not(all(target_has_atomic = "8", target_has_atomic = "32")))]
#[path = "rx_none.rs"]
mod rx;

pub const COMPATIBLE: &[&str] = &["arm,pl011"];

/// The rate every console in this tree runs at, and QEMU ignores.
pub const BAUD: u32 = 115_200;

// Register offsets from the programmer's model.
const DR: usize = 0x00;
const FR: usize = 0x18;
const IBRD: usize = 0x24;
const FBRD: usize = 0x28;
const LCR_H: usize = 0x2c;
const CR: usize = 0x30;
const MIS: usize = 0x40;
const IMSC: usize = 0x38;
const ICR: usize = 0x44;

/// FR.RXFE — the receive FIFO is empty.
const FR_RXFE: u32 = 1 << 4;
/// FR.BUSY — still transmitting, FIFO empty or not.
const FR_BUSY: u32 = 1 << 3;
/// FR.TXFF — the transmit FIFO is full.
const FR_TXFF: u32 = 1 << 5;

/// LCR_H: eight data bits, no parity, one stop bit, FIFOs enabled.
const LCR_H_8N1_FIFO: u32 = (3 << 5) | (1 << 4);
/// CR: UARTEN | TXE | RXE.
const CR_ENABLE: u32 = (1 << 0) | (1 << 8) | (1 << 9);

/// IMSC/MIS/ICR bit 4: a byte (or a FIFO's worth) has arrived.
const INT_RX: u32 = 1 << 4;
/// IMSC/MIS/ICR bit 6: bytes are waiting but the FIFO never filled. Without this a
/// keystroke sits in the FIFO unannounced until 31 more arrive, which for a console is
/// for ever.
const INT_RT: u32 = 1 << 6;
/// The receive interrupts this driver takes.
const INT_RECEIVE: u32 = INT_RX | INT_RT;
/// Every interrupt the part can raise, for clearing on the way up.
const INT_ALL: u32 = 0x7ff;

/// Polls of a busy transmitter before reconfiguring anyway. A byte lost at boot is a
/// cosmetic failure; a hang in the console driver is not.
const DRAIN_LIMIT: u32 = 1_000_000;

/// The integer and fractional baud rate divisors for `clock_hz` and `baud`.
///
/// `BAUDDIV = clock / (16 × baud)`, with the fraction in 64ths, rounded to nearest
/// (DDI 0183 §3.3.6). Computed in 64ths throughout so no floating point is needed.
/// `None` when the divisor does not fit the 16-bit integer register or is zero, which a
/// UART cannot be programmed with.
pub fn divisors(clock_hz: u64, baud: u32) -> Option<(u32, u32)> {
    let denominator = 16u64.checked_mul(u64::from(baud))?;
    if denominator == 0 {
        return None;
    }
    // (clock × 64 + denominator / 2) / denominator, i.e. the divisor in 64ths, rounded.
    let sixty_fourths = clock_hz.checked_mul(64)?.checked_add(denominator / 2)? / denominator;
    let integer = u32::try_from(sixty_fourths >> 6).ok()?;
    let fraction = (sixty_fourths & 0x3f) as u32;
    (integer >= 1 && integer <= 0xffff).then_some((integer, fraction))
}

/// A started PL011.
pub struct Pl011 {
    regs: Registers,
}

impl Pl011 {
    /// Take every byte the receive FIFO holds. Returns how many.
    fn drain(&self, into: &rx::Queue) -> usize {
        let mut taken = 0;
        // Bounded by the FIFO's depth and then some: a receiver that is fed faster than
        // this loop drains it must not hold the CPU in an interrupt handler for ever.
        for _ in 0..64 {
            if self.regs.read32(FR) & FR_RXFE != 0 {
                break;
            }
            let byte = self.regs.read32(DR) as u8;
            into.push(byte);
            taken += 1;
        }
        taken
    }

    fn write_byte(&self, b: u8) {
        // Spin until the transmit FIFO has room. Deliberately not bounded: a console that
        // gives up is worse than one that hangs visibly.
        while self.regs.read32(FR) & FR_TXFF != 0 {
            core::hint::spin_loop();
        }
        self.regs.write32(DR, u32::from(b));
    }
}

impl EarlyConsole for Pl011 {
    fn write_bytes(&self, bytes: &[u8]) {
        for &b in bytes {
            if b == b'\n' {
                self.write_byte(b'\r');
            }
            self.write_byte(b);
        }
    }
}

/// What probe found, kept for start.
struct Claims {
    mmio: Mmio,
    irq: Option<IrqLine>,
    divisors: (u32, u32),
}

pub struct Pl011Driver;

pub static DRIVER: Pl011Driver = Pl011Driver;

static CLAIMS: BootCell<Claims> = BootCell::new();
static UART: BootCell<Pl011> = BootCell::new();

/// The started UART, if one was.
pub fn console() -> Option<&'static dyn EarlyConsole> {
    UART.get().map(|u| u as &'static dyn EarlyConsole)
}

/// The window the bound UART claimed, as a physical `(address, length)`.
pub fn window() -> Option<(u64, u64)> {
    CLAIMS.get().map(|c| (c.mmio.phys(), c.mmio.len()))
}

// The only `unsafe` in the driver: storing into boot cells, and the promise that a
// claimed window is mapped.
#[allow(unsafe_code)]
impl Driver for Pl011Driver {
    fn name(&self) -> &'static str {
        "PL011"
    }

    fn compatible(&self) -> &'static [&'static str] {
        COMPATIBLE
    }

    fn probe(&self, p: &mut Probe<'_, '_, '_, '_>) -> Result<(), ProbeError> {
        let node = p.node();
        let clock = p
            .tree()
            .clock(node, 0)
            .and_then(|c| p.tree().node(c).clock_frequency())
            .ok_or(ProbeError::Declined("no uartclk frequency"))?;
        let divisors =
            divisors(clock, BAUD).ok_or(ProbeError::Declined("uartclk cannot make 115200 baud"))?;
        let mmio = p.claim_mmio(0, "PL011 UART")?;
        // A UART without an interrupt still transmits; one whose interrupt is malformed
        // or taken should not be refused a console over it.
        let irq = p.claim_irq(0).ok();
        // SAFETY: probe runs during single-threaded boot.
        unsafe {
            CLAIMS.set(Claims {
                mmio,
                irq,
                divisors,
            })
        }
        .map(|_| ())
        .map_err(|_| ProbeError::Declined("one PL011 is supported"))
    }

    fn start(&self, _bound: &Bound) -> Result<(), &'static str> {
        let claims = CLAIMS.get().ok_or("started without a probe")?;
        // SAFETY: the window was claimed by probe, and every claimed window is mapped at
        // its physical address, by the boot identity map or by the kernel's own space.
        let regs =
            unsafe { Registers::new(&claims.mmio) }.ok_or("window above the address space")?;

        // The early console may be writing through this very UART. Let what it queued
        // leave before the transmitter is disabled, or the tail of the last line is lost.
        let mut spins = 0;
        while regs.read32(FR) & FR_BUSY != 0 && spins < DRAIN_LIMIT {
            spins += 1;
            core::hint::spin_loop();
        }

        // The programmer's model's order: disabled while reconfiguring, and LCR_H after
        // the divisors, because writing LCR_H is what latches all three.
        let (integer, fraction) = claims.divisors;
        regs.write32(CR, 0);
        regs.write32(IMSC, 0);
        regs.write32(ICR, 0x7ff);
        regs.write32(IBRD, integer);
        regs.write32(FBRD, fraction);
        regs.write32(LCR_H, LCR_H_8N1_FIFO);
        regs.write32(CR, CR_ENABLE);
        // The receive interrupts, at the device. Nothing is delivered until the platform
        // has registered the handler and unmasked the line at the controller, so this is
        // the order the phases require: the part is ready before the line is live.
        if claims.irq.is_some() && rx::RECEIVES {
            regs.write32(IMSC, INT_RECEIVE);
        }

        // SAFETY: single-threaded boot, per `Driver::start`'s contract.
        unsafe { UART.set(Pl011 { regs }) }
            .map(|_| ())
            .map_err(|_| "a PL011 is already started")
    }

    /// Stop taking interrupts. The transmitter stays up: this UART is the console, and a
    /// stopped driver still has to let the early console report what happened next.
    fn stop(&self, _started: &Started) {
        if let Some(uart) = UART.get() {
            uart.regs.write32(IMSC, 0);
            uart.regs.write32(ICR, INT_ALL);
        }
    }

    #[cfg(all(target_has_atomic = "8", target_has_atomic = "32"))]
    fn interrupt(&self, _bound: &Bound) -> Option<(&'static IrqLine, fn())> {
        // One UART: the probe declines a second, so the claims are this device's.
        let line = CLAIMS.get()?.irq.as_ref()?;
        Some((line, on_interrupt))
    }
}

/// The receive interrupt: take what arrived, then acknowledge.
///
/// Runs in interrupt context on the CPU the line is routed to, with that CPU's interrupts
/// masked. It touches the UART's registers and the queue's atomics and nothing else, so it
/// needs no lock: the queue has one producer, this, because the line goes to one CPU.
pub fn on_interrupt() {
    let Some(uart) = UART.get() else { return };
    let pending = uart.regs.read32(MIS);
    let taken = uart.drain(&rx::QUEUE);
    // Clear what was pending when this started. A byte that arrived since leaves its
    // interrupt raised, and the controller delivers it again after the EOI.
    uart.regs.write32(ICR, pending & INT_RECEIVE);
    rx::record(taken);
}

/// The oldest byte the receive interrupt queued, if any.
pub fn read_byte() -> Option<u8> {
    rx::pop()
}

/// How many receive interrupts the handler has taken, and how many bytes they carried.
pub fn received() -> (u32, u32) {
    (rx::interrupts(), rx::bytes())
}

/// Bytes that arrived with the queue full.
pub fn dropped() -> u32 {
    rx::dropped()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn divisors_for_the_clocks_boards_use() {
        // DDI 0183's own example: 4 MHz at 230400 is 1.085, so 1 and 5.
        assert_eq!(divisors(4_000_000, 230_400), Some((1, 5)));
        // QEMU virt's 24 MHz clock: 13.0208 → 13 and 1.
        assert_eq!(divisors(24_000_000, 115_200), Some((13, 1)));
        // Raspberry Pi 4's 48 MHz: 26.0417 → 26 and 3.
        assert_eq!(divisors(48_000_000, 115_200), Some((26, 3)));
        // A fraction that rounds up into the next integer carries.
        assert_eq!(divisors(16 * 115_200 * 2 - 1, 115_200), Some((2, 0)));
    }

    #[test]
    fn divisors_that_cannot_be_programmed() {
        assert_eq!(divisors(24_000_000, 0), None);
        assert_eq!(divisors(1_000, 115_200), None, "below 1");
        assert_eq!(divisors(16 * 0x1_0000, 1), None, "past the 16-bit integer register");
        assert_eq!(divisors(u64::MAX, 115_200), None, "overflow is refused, not wrapped");
    }
}

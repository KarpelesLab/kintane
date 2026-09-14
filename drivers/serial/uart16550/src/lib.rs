//! A 16550-compatible UART in the PC's I/O port space.
//!
//! Bound by `ns16550a`, from a node that carries a port range and an interrupt line —
//! on a PC, the one `kernel/platform/acpi` declares for COM1. Probe claims both, and
//! start checks the part is really there through its scratch register, because a
//! platform that declares a device it cannot enumerate owes the machine a check.
//!
//! Transmit is polled, as the PL011's is: the console must be able to report a fault
//! with nothing to wake it. Receive is interrupt-driven, into a queue in [`rx`].
//!
//! # Binding more than once
//!
//! A device that can be removed can be bound again, so a driver's state cannot be
//! write-once for the life of the machine. Each binding takes the next of
//! [`BINDINGS`] slots, and removal retires it. The slots are boot cells, written on the
//! boot path like every other bound driver's, which is what keeps this free of `unsafe`
//! beyond storing into them. Four bindings a boot is a limit a boot check reaches and
//! nothing else does; hot-plug needs a lock-protected table instead and will say so.
//!
//! Reference: National Semiconductor PC16550D datasheet (register map and line status
//! bits); the PC's IRQ gate is modem control bit 3, `OUT2`.

#![cfg_attr(not(test), no_std)]
#![deny(unsafe_code)]

use device::{BootCell, Bound, Driver, IrqLine, PortRange, Ports, Probe, ProbeError, Started};
use hal::EarlyConsole;

// The receive queue needs atomics to share with the handler; without them the driver
// transmits only.
#[cfg(all(target_has_atomic = "8", target_has_atomic = "32"))]
mod rx;
#[cfg(not(all(target_has_atomic = "8", target_has_atomic = "32")))]
#[path = "rx_none.rs"]
mod rx;

pub const COMPATIBLE: &[&str] = &["ns16550a", "ns16550"];

/// Register offsets from the base port. `DLL`/`DLM` share `RBR`/`IER` while `LCR.DLAB` is
/// set.
const RBR_THR_DLL: u16 = 0;
const IER_DLM: u16 = 1;
const IIR_FCR: u16 = 2;
const LCR: u16 = 3;
const MCR: u16 = 4;
const LSR: u16 = 5;
const SCR: u16 = 7;

/// The ports a 16550 occupies.
pub const PORTS: u16 = 8;

/// IER bit 0: interrupt when received data is available.
const IER_RX: u8 = 1 << 0;
/// LCR: eight data bits, no parity, one stop bit.
const LCR_8N1: u8 = 0x03;
/// LCR bit 7: the divisor latch.
const LCR_DLAB: u8 = 0x80;
/// FCR: FIFOs on, both cleared, interrupt at the first byte.
const FCR_ENABLE_CLEAR: u8 = 0x07;
/// MCR: DTR, RTS, and `OUT2`, which on a PC is what connects the UART's interrupt
/// output to the interrupt controller. Without it every interrupt the part raises is
/// lost on the board, whatever the driver enables.
const MCR_DTR_RTS_OUT2: u8 = 0x0b;
/// LSR bit 0: data ready.
const LSR_DATA_READY: u8 = 1 << 0;
/// LSR bit 5: the transmit holding register is empty.
const LSR_THR_EMPTY: u8 = 1 << 5;

/// Baud rate divisor from the part's 1.8432 MHz clock. 3 is 38400, the rate the early
/// console already programmed, so rebinding the console does not change its speed —
/// QEMU ignores the rate, a real terminal does not.
const DIVISOR: u16 = 3;

/// How many bindings a boot may make. See the module documentation.
pub const BINDINGS: usize = 4;

/// Polls of a transmitter that will not drain before giving up.
const DRAIN_LIMIT: u32 = 1_000_000;

/// The divisor latch bytes for a rate, from the part's 115200 × 16 Hz clock.
///
/// `None` for a rate the latch cannot make: zero, above the clock's reach, or needing a
/// divisor that does not fit sixteen bits.
pub fn divisor(baud: u32) -> Option<u16> {
    const CLOCK_RATE: u32 = 115_200;
    if baud == 0 || baud > CLOCK_RATE || CLOCK_RATE % baud != 0 {
        return None;
    }
    u16::try_from(CLOCK_RATE / baud).ok().filter(|&d| d != 0)
}

/// A started 16550.
pub struct Uart {
    ports: Ports,
}

impl Uart {
    fn write_byte(&self, b: u8) {
        // Unbounded for the same reason as the PL011's: a console that gives up is worse
        // than one that hangs visibly.
        while self.ports.read8(LSR) & LSR_THR_EMPTY == 0 {
            core::hint::spin_loop();
        }
        self.ports.write8(RBR_THR_DLL, b);
    }

    /// Take every byte the receiver holds. Returns how many.
    fn drain(&self, into: &rx::Queue) -> usize {
        let mut taken = 0;
        // Bounded: a part fed faster than this drains must not pin the handler.
        for _ in 0..64 {
            if self.ports.read8(LSR) & LSR_DATA_READY == 0 {
                break;
            }
            into.push(self.ports.read8(RBR_THR_DLL));
            taken += 1;
        }
        taken
    }
}

impl EarlyConsole for Uart {
    fn write_bytes(&self, bytes: &[u8]) {
        for &b in bytes {
            if b == b'\n' {
                self.write_byte(b'\r');
            }
            self.write_byte(b);
        }
    }
}

/// What probe claimed, kept for start.
struct Claims {
    ports: PortRange,
    irq: Option<IrqLine>,
}

pub struct Uart16550Driver;

pub static DRIVER: Uart16550Driver = Uart16550Driver;

/// One binding's state: what probe claimed, the part once started, and whether it has
/// been removed since.
struct Binding {
    claims: BootCell<Claims>,
    uart: BootCell<Uart>,
    retired: BootCell<()>,
}

impl Binding {
    const fn new() -> Self {
        Binding {
            claims: BootCell::new(),
            uart: BootCell::new(),
            retired: BootCell::new(),
        }
    }

    fn live(&self) -> bool {
        self.claims.get().is_some() && self.retired.get().is_none()
    }
}

static SLOTS: [Binding; BINDINGS] = [const { Binding::new() }; BINDINGS];

/// The binding in use, if one is.
fn current() -> Option<&'static Binding> {
    SLOTS.iter().find(|b| b.live())
}

/// The started UART, if one is.
pub fn console() -> Option<&'static dyn EarlyConsole> {
    current()
        .and_then(|b| b.uart.get())
        .map(|u| u as &'static dyn EarlyConsole)
}

/// The port range the bound UART claimed, as `(base, length)`.
pub fn ports() -> Option<(u16, u16)> {
    current()
        .and_then(|b| b.claims.get())
        .map(|c| (c.ports.base(), c.ports.len()))
}

/// How many times this boot has bound the driver, removals included.
pub fn bindings() -> usize {
    SLOTS.iter().filter(|b| b.claims.get().is_some()).count()
}

// The only `unsafe` in the driver: storing into boot cells.
#[allow(unsafe_code)]
impl Driver for Uart16550Driver {
    fn name(&self) -> &'static str {
        "16550"
    }

    fn compatible(&self) -> &'static [&'static str] {
        COMPATIBLE
    }

    fn probe(&self, p: &mut Probe<'_, '_, '_, '_>) -> Result<(), ProbeError> {
        if current().is_some() {
            return Err(ProbeError::Declined("one 16550 is bound at a time"));
        }
        let slot = SLOTS
            .iter()
            .find(|b| b.claims.get().is_none())
            .ok_or(ProbeError::Declined("bound too many times this boot"))?;
        let ports = p.claim_ports(0, "16550 UART")?;
        if ports.len() < PORTS {
            return Err(ProbeError::Declined("fewer than eight ports"));
        }
        // A UART without a usable interrupt still transmits.
        let irq = p.claim_irq(0).ok();
        // SAFETY: probe runs during single-threaded boot.
        unsafe { slot.claims.set(Claims { ports, irq }) }
            .map(|_| ())
            .map_err(|_| ProbeError::Declined("the binding slot was taken"))
    }

    fn start(&self, _bound: &Bound) -> Result<(), &'static str> {
        let binding = current().ok_or("started without a probe")?;
        let claims = binding.claims.get().ok_or("started without a probe")?;
        let io = Ports::new(&claims.ports);

        // Declared is not the same as present. The scratch register holds what is written
        // to it on every 16550 and nothing else at these ports does, so two patterns reading
        // back tell a part from an empty bus, which reads 0xff. Here and not in probe,
        // because probe does not touch hardware: a device that is absent is bound, fails to
        // start, and says why.
        let saved = io.read8(SCR);
        let present = [0x5a, 0xa5].iter().all(|&v| {
            io.write8(SCR, v);
            io.read8(SCR) == v
        });
        io.write8(SCR, saved);
        if !present {
            return Err("no 16550 answers at the declared ports");
        }

        // Let whatever the early console queued leave before reprogramming the line.
        let mut spins = 0;
        while io.read8(LSR) & LSR_THR_EMPTY == 0 && spins < DRAIN_LIMIT {
            spins += 1;
            core::hint::spin_loop();
        }

        let [low, high] = DIVISOR.to_le_bytes();
        io.write8(IER_DLM, 0);
        io.write8(LCR, LCR_DLAB);
        io.write8(RBR_THR_DLL, low);
        io.write8(IER_DLM, high);
        io.write8(LCR, LCR_8N1);
        io.write8(IIR_FCR, FCR_ENABLE_CLEAR);
        io.write8(MCR, MCR_DTR_RTS_OUT2);
        // Whatever arrived before the driver existed belongs to no reader: throw it away,
        // so the first byte the handler queues is the first byte sent after start.
        while io.read8(LSR) & LSR_DATA_READY != 0 {
            let _ = io.read8(RBR_THR_DLL);
        }
        // Receive interrupts at the part. Nothing is delivered until the platform has
        // registered the handler and unmasked the line at the controller.
        if claims.irq.is_some() && rx::RECEIVES {
            io.write8(IER_DLM, IER_RX);
        }

        // SAFETY: single-threaded boot, per `Driver::start`'s contract.
        unsafe { binding.uart.set(Uart { ports: io }) }
            .map(|_| ())
            .map_err(|_| "this binding was already started")
    }

    /// Stop taking interrupts; the transmitter stays up for the early console.
    fn stop(&self, _started: &Started) {
        if let Some(uart) = current().and_then(|b| b.uart.get()) {
            uart.ports.write8(IER_DLM, 0);
        }
    }

    /// Retire this binding's slot. Its claims go back to the ledger in `driver::remove`.
    #[allow(unsafe_code)]
    fn remove(&self, _bound: &Bound) {
        if let Some(binding) = current() {
            // SAFETY: removal runs on the boot path, single-threaded, like probe.
            let _ = unsafe { binding.retired.set(()) };
        }
    }

    #[cfg(all(target_has_atomic = "8", target_has_atomic = "32"))]
    fn interrupt(&self) -> Option<(&'static IrqLine, fn())> {
        let line = current()?.claims.get()?.irq.as_ref()?;
        Some((line, on_interrupt))
    }
}

/// The receive interrupt: take what arrived.
///
/// Runs on the CPU the line is routed to, with that CPU's interrupts masked, and touches
/// only the part's ports and the queue's atomics. Reading the data empties the receive
/// interrupt's cause, and the interrupt identification register is read last so the part
/// has nothing left to report.
pub fn on_interrupt() {
    let Some(uart) = current().and_then(|b| b.uart.get()) else {
        rx::record_stray();
        return;
    };
    let taken = uart.drain(&rx::QUEUE);
    // Reading the identification register is what acknowledges a transmitter-empty or
    // modem-status cause; received data was acknowledged by reading it.
    let _ = uart.ports.read8(IIR_FCR);
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

/// Interrupts that arrived when no binding was started: a handler left registered past
/// its device's removal would show up here.
pub fn stray() -> u32 {
    rx::stray()
}

/// Bytes that arrived with the queue full.
pub fn dropped() -> u32 {
    rx::dropped()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn divisors_the_latch_can_make() {
        assert_eq!(divisor(115_200), Some(1));
        assert_eq!(divisor(38_400), Some(3), "the early console's rate");
        assert_eq!(divisor(9_600), Some(12));
        assert_eq!(divisor(50), Some(2304));
    }

    #[test]
    fn divisors_the_latch_cannot_make() {
        assert_eq!(divisor(0), None);
        assert_eq!(divisor(230_400), None, "faster than the clock");
        assert_eq!(divisor(100_000), None, "not an integer division of the clock");
    }

    #[test]
    fn the_chosen_rate_is_the_early_consoles() {
        assert_eq!(divisor(38_400), Some(DIVISOR));
    }

    #[test]
    fn out2_is_set_or_no_interrupt_reaches_the_board() {
        assert_ne!(MCR_DTR_RTS_OUT2 & (1 << 3), 0);
    }
}

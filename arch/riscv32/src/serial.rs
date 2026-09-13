//! The early console: the 16550-compatible UART on QEMU's `virt` machine.
//!
//! The same register set as COM1 on a PC, reached through memory rather than I/O ports,
//! one byte per register (`reg-shift` 0 in the device tree). Polled, never
//! interrupt-driven, so it works before trap handling exists and from inside a fault.
//!
//! The address is `virt`'s, not the device tree's. The tree says the same thing, and
//! following it instead is the device-model work aarch64 already has; here there is no
//! MMU, so nothing has to be mapped and a wrong address fails loudly on the first write.

use core::ptr::{read_volatile, write_volatile};

use hal::EarlyConsole;

/// `uart@10000000` on `virt`.
pub(crate) const UART0: usize = 0x1000_0000;

const THR: usize = 0; // transmit holding
const IER: usize = 1; // interrupt enable
const FCR: usize = 2; // FIFO control
const LCR: usize = 3; // line control
const LSR: usize = 5; // line status

const LSR_THRE: u8 = 1 << 5;

/// # Safety
/// `off` must be one of the register offsets above.
unsafe fn write_reg(off: usize, value: u8) {
    // SAFETY: the UART's registers are always present at `UART0` on `virt`, and there is
    // no translation, so the address is the device.
    unsafe { write_volatile((UART0 + off) as *mut u8, value) };
}

/// # Safety
/// As [`write_reg`].
unsafe fn read_reg(off: usize) -> u8 {
    // SAFETY: as for `write_reg`; reading LSR has no side effects.
    unsafe { read_volatile((UART0 + off) as *const u8) }
}

pub struct Serial;

pub static EARLY: Serial = Serial;

impl Serial {
    /// Put the UART in a known state: no interrupts, 8N1, FIFOs on.
    ///
    /// # Safety
    /// Once, before any other writer exists.
    pub unsafe fn init(&self) {
        // SAFETY: the caller's contract; these are the documented offsets.
        unsafe {
            write_reg(IER, 0);
            write_reg(LCR, 0x03);
            write_reg(FCR, 0x07);
        }
    }

    fn write_byte(&self, b: u8) {
        // SAFETY: LSR and THR are valid offsets.
        while unsafe { read_reg(LSR) } & LSR_THRE == 0 {
            core::hint::spin_loop();
        }
        // SAFETY: as above.
        unsafe { write_reg(THR, b) };
    }
}

impl EarlyConsole for Serial {
    fn write_bytes(&self, bytes: &[u8]) {
        for &b in bytes {
            if b == b'\n' {
                self.write_byte(b'\r');
            }
            self.write_byte(b);
        }
    }
}

// SAFETY: writes are byte-at-a-time to a device register. Interleaving from two contexts
// garbles output but cannot violate memory safety, the same as on every other port.
unsafe impl Sync for Serial {}

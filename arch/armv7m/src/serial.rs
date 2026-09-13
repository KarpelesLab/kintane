//! The early console: UART0 of the MPS2's CMSDK APB peripherals.
//!
//! Arm's Cortex-M System Design Kit UART is five registers and has no FIFO. Polled,
//! never interrupt-driven, so it works before exceptions are configured and from inside
//! a fault handler.
//!
//! The address is the AN385 FPGA image's, which nothing on the board describes; see
//! `config/boards/mps2-an385.kcfg`. There is no MMU, so a wrong address fails on the
//! first write.

use core::ptr::{read_volatile, write_volatile};

use hal::EarlyConsole;

/// UART0 on the AN385 image.
pub(crate) const UART0: usize = 0x4000_4000;

const DATA: usize = 0x00;
const STATE: usize = 0x04;
const CTRL: usize = 0x08;
const BAUDDIV: usize = 0x10;

/// `STATE.TXFULL`: the one-byte transmit buffer is occupied.
const STATE_TXFULL: u32 = 1 << 0;
/// `CTRL.TXEN`.
const CTRL_TXEN: u32 = 1 << 0;

/// The divisor for 115200 baud from the AN385's 25 MHz peripheral clock. The CMSDK UART
/// counts it as the number of clock cycles per bit, and refuses divisors below 16.
const DIVISOR: u32 = 25_000_000 / 115_200;

pub struct Serial;

pub static EARLY: Serial = Serial;

impl Serial {
    /// Enable the transmitter at 115200 baud, with no interrupts.
    ///
    /// # Safety
    /// Once, before any other writer exists.
    pub unsafe fn init(&self) {
        // SAFETY: the caller's contract; BAUDDIV and CTRL are the documented registers,
        // and the divisor is set before the transmitter is enabled, as the CMSDK asks.
        unsafe {
            write_volatile((UART0 + BAUDDIV) as *mut u32, DIVISOR);
            write_volatile((UART0 + CTRL) as *mut u32, CTRL_TXEN);
        }
    }

    fn write_byte(&self, b: u8) {
        // SAFETY: STATE and DATA are the UART's registers; reading STATE has no side
        // effects, and a write to DATA with the buffer free sends one byte.
        unsafe {
            while read_volatile((UART0 + STATE) as *const u32) & STATE_TXFULL != 0 {
                core::hint::spin_loop();
            }
            write_volatile((UART0 + DATA) as *mut u32, u32::from(b));
        }
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

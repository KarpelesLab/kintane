//! PL011 UART, at the address QEMU's `virt` machine puts the first one.
//!
//! The early console: available before the device framework, before the heap, and
//! before anything that could fail. It does no buffering and no locking — on a
//! uniprocessor Phase 0 kernel there is nothing to lock against, and adding a lock
//! before the lock types exist would be the wrong order.
//!
//! The address is hardcoded, which is a real limitation and not an oversight. The
//! console has to work before the device tree can be parsed, so the first one is
//! always a guess; `virt` is the only aarch64 machine this port claims to support,
//! and 0x09000000 is where its PL011 is. A proper port to a second board replaces
//! this constant with an early DTB scan for the `stdout-path` node, which is the same
//! order of work Linux does in its own earlycon.

use core::ptr::{read_volatile, write_volatile};
use hal::EarlyConsole;

/// PL011 #0 on QEMU `virt`. Fixed by the machine model, not discovered.
const UART0: usize = 0x0900_0000;

// Byte offsets from the PL011 programmer's model. Only the handful the early console
// touches are named; the rest belong to the real driver.
const DR: usize = 0x00; // data
const FR: usize = 0x18; // flag
const IBRD: usize = 0x24; // integer baud rate divisor
const FBRD: usize = 0x28; // fractional baud rate divisor
const LCR_H: usize = 0x2c; // line control
const CR: usize = 0x30; // control
const IMSC: usize = 0x38; // interrupt mask set/clear
const ICR: usize = 0x44; // interrupt clear

/// FR.TXFF — the transmit FIFO is full.
const FR_TXFF: u32 = 1 << 5;

/// # Safety
/// `off` must be a register offset of a PL011 that is actually mapped at [`UART0`],
/// and the write must be one the device tolerates in its current state.
unsafe fn write_reg(off: usize, value: u32) {
    // SAFETY: the MMU is off, so 0x09000000 is the device itself and the access is
    // naturally aligned. `write_volatile` is what keeps the compiler from merging or
    // reordering stores that the device distinguishes.
    unsafe { write_volatile((UART0 + off) as *mut u32, value) };
}

/// # Safety
/// `off` must be a register offset of a PL011 mapped at [`UART0`]. Reading some
/// PL011 registers has side effects; the ones used here do not.
unsafe fn read_reg(off: usize) -> u32 {
    // SAFETY: as above — a mapped, naturally aligned device register.
    unsafe { read_volatile((UART0 + off) as *const u32) }
}

pub struct Serial;

/// The early console instance. A unit struct rather than a driver object because at
/// this point there is no device framework to register with.
pub static EARLY: Serial = Serial;

impl Serial {
    /// Configure the UART for 115200 8N1 with FIFOs on.
    ///
    /// # Safety
    /// Must be called once, early, before anything else writes to the UART.
    pub unsafe fn init(&self) {
        // SAFETY: the standard PL011 bring-up sequence. Every write below is to a
        // register of the device at UART0, in the order the programmer's model
        // requires: the UART must be disabled while the baud rate and line control
        // registers are changed, and LCR_H must be written after IBRD/FBRD because
        // writing it is what latches all three.
        unsafe {
            write_reg(CR, 0); // disable while reconfiguring
            write_reg(IMSC, 0); // no interrupts: we poll
            write_reg(ICR, 0x7ff); // clear anything already pending

            // 115200 baud from a 24 MHz UARTCLK: 24e6 / (16 * 115200) = 13.0208,
            // so IBRD = 13 and FBRD = round(0.0208 * 64) = 1. QEMU ignores both and
            // the host terminal has no baud rate at all, but a wrong divisor here
            // would be a silent failure on the first real board.
            write_reg(IBRD, 13);
            write_reg(FBRD, 1);

            write_reg(LCR_H, (3 << 5) | (1 << 4)); // 8 bits, no parity, FIFOs on
            write_reg(CR, (1 << 0) | (1 << 8) | (1 << 9)); // UARTEN | TXE | RXE
        }
    }

    fn write_byte(&self, b: u8) {
        // Spin until the transmit FIFO has room. Bounded in practice by the UART;
        // deliberately not bounded in code, because a console that gives up is worse
        // than one that hangs visibly.
        // SAFETY: reading the flag register has no side effects.
        while unsafe { read_reg(FR) } & FR_TXFF != 0 {
            core::hint::spin_loop();
        }
        // SAFETY: the FIFO has room, so the byte cannot be dropped.
        unsafe { write_reg(DR, b as u32) };
    }
}

impl EarlyConsole for Serial {
    fn write_bytes(&self, bytes: &[u8]) {
        for &b in bytes {
            // A bare LF becomes CRLF so output is readable on a real terminal.
            if b == b'\n' {
                self.write_byte(b'\r');
            }
            self.write_byte(b);
        }
    }
}

// SAFETY: `Serial` holds no state; concurrent writers can interleave bytes but
// cannot corrupt anything. Ordering becomes a real concern when SMP arrives, and the
// console gains a lock then, alongside the lock types themselves.
unsafe impl Sync for Serial {}

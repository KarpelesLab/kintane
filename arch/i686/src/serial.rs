//! 16550 UART at the legacy COM1 address.
//!
//! The early console: available before the device framework, before the heap, and
//! before anything that could fail. It does no buffering and no locking — on a
//! uniprocessor Phase 0 kernel there is nothing to lock against, and adding a lock
//! before the lock types exist would be the wrong order.
//!
//! Byte-for-byte the same device as on x86_64. The two ports keep separate copies
//! rather than sharing one, because a shared "x86" crate would be the first place the
//! 64-bit assumptions leak back into the 32-bit build; when this grows into a real
//! driver it moves to `drivers/` and is shared there, behind the device framework.

use core::arch::asm;

use hal::EarlyConsole;

const COM1: u16 = 0x3F8;

/// # Safety
/// Writing to an arbitrary I/O port can have arbitrary effects. Callers must know
/// what device is behind `port`.
pub unsafe fn outb(port: u16, value: u8) {
    // SAFETY: `out` with a valid port and byte; the caller owns the port's meaning.
    unsafe {
        asm!("out dx, al", in("dx") port, in("al") value, options(nomem, nostack, preserves_flags));
    }
}

/// # Safety
/// Reading a port can have side effects on the device behind it.
pub unsafe fn inb(port: u16) -> u8 {
    let value: u8;
    // SAFETY: `in` with a valid port; the caller owns the port's meaning.
    unsafe {
        asm!("in al, dx", out("al") value, in("dx") port, options(nomem, nostack, preserves_flags));
    }
    value
}

pub struct Serial;

/// The early console instance. A unit struct rather than a driver object because at
/// this point there is no device framework to register with.
pub static EARLY: Serial = Serial;

impl Serial {
    /// Configure COM1 for 38400 8N1 with FIFOs on.
    ///
    /// # Safety
    /// Must be called once, early, before anything else writes to COM1.
    pub unsafe fn init(&self) {
        // SAFETY: the standard 16550 initialisation sequence on the legacy COM1
        // ports, which exist on every PC-compatible machine and on QEMU's `pc`.
        unsafe {
            outb(COM1 + 1, 0x00); // interrupts off: we poll
            outb(COM1 + 3, 0x80); // DLAB on, to reach the divisor registers
            outb(COM1, 0x03); // divisor 3 => 38400 baud
            outb(COM1 + 1, 0x00);
            outb(COM1 + 3, 0x03); // DLAB off, 8 bits, no parity, one stop bit
            outb(COM1 + 2, 0xC7); // FIFO on, cleared, 14-byte threshold
            outb(COM1 + 4, 0x0B); // RTS/DSR set, OUT2 enabled
        }
    }

    fn write_byte(&self, b: u8) {
        // Spin until the transmit holding register is empty. Bounded in practice by
        // the UART; deliberately not bounded in code, because a console that gives up
        // is worse than one that hangs visibly.
        // SAFETY: reading the line status register has no side effects.
        while unsafe { inb(COM1 + 5) } & 0x20 == 0 {
            core::hint::spin_loop();
        }
        // SAFETY: the transmit register is ready.
        unsafe { outb(COM1, b) };
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

const HEX: &[u8; 16] = b"0123456789abcdef";

/// Write `v` as `0x` followed by `digits` hex digits, least significant last.
///
/// Formatting for the console, on paths where `core::fmt` is not wanted: the fault
/// reporter runs inside an exception handler, where the formatting machinery's own
/// panics and unwinds would be a fault inside a fault.
///
/// Takes a `u32` where the x86-64 port takes a `u64`, because every value this port
/// prints through it — a linear address, a control register, an error code — is one
/// machine word wide. The 36-bit physical addresses that make this target interesting
/// are printed by `kernel/main`, which has its own wide formatter.
pub(crate) fn write_hex(c: &dyn EarlyConsole, v: u32, digits: usize) {
    let mut buf = [0u8; 10];
    buf[0] = b'0';
    buf[1] = b'x';
    let n = if digits > 8 { 8 } else { digits };
    for i in 0..n {
        let shift = (n - 1 - i) * 4;
        buf[2 + i] = HEX[((v >> shift) & 0xf) as usize];
    }
    c.write_bytes(&buf[..2 + n]);
}

/// Write `v` in decimal.
pub(crate) fn write_dec(c: &dyn EarlyConsole, mut v: u32) {
    if v == 0 {
        c.write_bytes(b"0");
        return;
    }
    let mut buf = [0u8; 10];
    let mut i = buf.len();
    while v > 0 {
        i -= 1;
        buf[i] = b'0' + (v % 10) as u8;
        v /= 10;
    }
    c.write_bytes(&buf[i..]);
}

// SAFETY: `Serial` holds no state; concurrent writers can interleave bytes but
// cannot corrupt anything. Ordering becomes a real concern when SMP arrives, and the
// console gains a lock then, alongside the lock types themselves.
unsafe impl Sync for Serial {}

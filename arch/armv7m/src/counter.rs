//! A 64-bit count without 64-bit atomics, which ARMv7-M does not have.

use core::cell::UnsafeCell;

use hal::Arch;

use crate::Armv7m;

/// Written only from exception handlers, which never run while `PRIMASK` masks them,
/// and read with `PRIMASK` set. On one core that is exclusion; `Armv7m` asserts
/// `UniProcessor`, and this type is one of the reasons it has to be true.
pub struct Counter(UnsafeCell<u64>);

// SAFETY: see the type's documentation. Every write is from a handler of an exception
// that `PRIMASK` masks, and every read is made with it set, on the only core there is.
unsafe impl Sync for Counter {}

impl Counter {
    pub const fn new() -> Self {
        Counter(UnsafeCell::new(0))
    }

    /// Add one. Called only from the handler of an exception `PRIMASK` masks.
    pub(crate) fn increment(&self) {
        // SAFETY: no reader runs between the read and the write: readers mask the
        // exception this is called from, and there is no other writer.
        unsafe { *self.0.get() = (*self.0.get()).wrapping_add(1) };
    }

    /// The count, when the caller has already masked interrupts.
    ///
    /// # Safety
    /// `PRIMASK` must be set.
    pub(crate) unsafe fn get_masked(&self) -> u64 {
        // SAFETY: the caller's contract excludes the writer.
        unsafe { *self.0.get() }
    }

    /// The count.
    pub fn get(&self) -> u64 {
        let irq = Armv7m::irq_save();
        // SAFETY: masked just above.
        let v = unsafe { self.get_masked() };
        // SAFETY: pairs with the `irq_save` above.
        unsafe { Armv7m::irq_restore(irq) };
        v
    }
}

/// Write `v` in decimal.
pub(crate) fn write_dec(c: &dyn hal::EarlyConsole, mut v: u64) {
    if v == 0 {
        c.write_bytes(b"0");
        return;
    }
    let mut buf = [0u8; 20];
    let mut i = buf.len();
    while v > 0 {
        i -= 1;
        buf[i] = b'0' + (v % 10) as u8;
        v /= 10;
    }
    c.write_bytes(&buf[i..]);
}

/// Write `v` as sixteen hex digits, like every other port's reports.
pub(crate) fn write_hex(c: &dyn hal::EarlyConsole, v: u64) {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut buf = [0u8; 18];
    buf[0] = b'0';
    buf[1] = b'x';
    for i in 0..16 {
        buf[2 + i] = DIGITS[((v >> (60 - i * 4)) & 0xf) as usize];
    }
    c.write_bytes(&buf);
}

//! Access to a claimed range of I/O ports.
//!
//! The PC is the only machine here with a second address space for devices, and its
//! oldest devices live in it: the serial port, the interval timer, the 8259A. A driver
//! for one of them needs `in`/`out` where a driver for memory-mapped registers needs
//! loads and stores, and everything else about it — claiming the range, being refused
//! when another driver holds it, binding by `compatible` — is the same.
//!
//! So ports are a resource like a window, and this is their [`crate::Registers`]: every
//! access is checked against the claimed range, so a driver whose offset arithmetic is
//! wrong reads all-ones and writes nothing instead of programming the interrupt
//! controller by accident.
//!
//! On an architecture with no port space the accessors are that same absent-device
//! behaviour. Nothing can claim a port range there, because nothing describes one, so
//! this is unreachable rather than silently wrong — and a driver written for ports
//! still compiles for every target, which is what `kbuild portability` asks of it.

#![allow(unsafe_code)]

use crate::resource::PortRange;

/// A range of I/O ports a driver may read and write.
#[derive(Debug)]
pub struct Ports {
    base: u16,
    len: u16,
}

impl Ports {
    /// Ports for a claimed range.
    ///
    /// Unlike [`crate::Registers::new`] this makes no promise about mapping: the port
    /// space is not mapped, it is addressed by the instruction. The claim is what says
    /// no other driver is programming the same device.
    pub fn new(range: &PortRange) -> Ports {
        Ports {
            base: range.base(),
            len: range.len(),
        }
    }

    /// Ports for a range nobody claimed: a test's, or a device the platform fixes.
    ///
    /// # Safety
    /// `[base, base + len)` must be this code's to program: no other driver may hold it.
    pub unsafe fn from_raw(base: u16, len: u16) -> Ports {
        Ports { base, len }
    }

    pub fn base(&self) -> u16 {
        self.base
    }

    pub fn len(&self) -> u16 {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The port at `offset`, if it is inside the range.
    fn at(&self, offset: u16) -> Option<u16> {
        (offset < self.len).then(|| self.base.checked_add(offset))?
    }

    /// Read the byte port at `offset`. Outside the range, all-ones, as an absent device
    /// reads on this bus.
    pub fn read8(&self, offset: u16) -> u8 {
        match self.at(offset) {
            Some(port) => inb(port),
            None => {
                debug_assert!(false, "port read at +{offset} outside a {}-port range", self.len);
                u8::MAX
            }
        }
    }

    /// Write the byte port at `offset`. Outside the range, nothing.
    pub fn write8(&self, offset: u16, value: u8) {
        match self.at(offset) {
            Some(port) => outb(port, value),
            None => {
                debug_assert!(false, "port write at +{offset} outside a {}-port range", self.len)
            }
        }
    }
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn inb(port: u16) -> u8 {
    let value: u8;
    // SAFETY: a byte read of an I/O port has no effect on memory, and the port is inside
    // a range the ledger granted this driver.
    unsafe {
        core::arch::asm!("in al, dx", out("al") value, in("dx") port, options(nomem, nostack, preserves_flags));
    }
    value
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn outb(port: u16, value: u8) {
    // SAFETY: as `inb`; the port is inside a granted range.
    unsafe {
        core::arch::asm!("out dx, al", in("dx") port, in("al") value, options(nomem, nostack, preserves_flags));
    }
}

/// No port space: what an absent device reads.
#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
fn inb(_port: u16) -> u8 {
    u8::MAX
}

#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
fn outb(_port: u16, _value: u8) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn access_outside_the_range_is_refused() {
        // SAFETY: the accessors are the no-port-space stubs on the host this runs on, or
        // reads of ports 0x400.. which QEMU's test host does not use; nothing is claimed.
        let p = unsafe { Ports::from_raw(0x400, 8) };
        assert_eq!(p.base(), 0x400);
        assert_eq!(p.len(), 8);
        assert!(!p.is_empty());
        assert_eq!(p.at(0), Some(0x400));
        assert_eq!(p.at(7), Some(0x407));
        assert_eq!(p.at(8), None, "one past the range");
        assert_eq!(p.at(u16::MAX), None);
    }

    #[test]
    fn a_range_at_the_top_of_the_space_does_not_wrap() {
        // SAFETY: as above; nothing is accessed.
        let p = unsafe { Ports::from_raw(0xffff, 4) };
        assert_eq!(p.at(0), Some(0xffff));
        assert_eq!(p.at(1), None, "0xffff + 1 does not wrap to port 0");
    }
}

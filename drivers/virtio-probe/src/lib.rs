//! A driver body that identifies a virtio-mmio slot, written against [`hwproxy`].
//!
//! This is the subject of the driver-isolation prototype. It is small on purpose: what is
//! being tested is not the driver but the claim that *one* driver source runs unchanged in
//! the kernel and inside an isolated domain, and a small body makes the two runs easy to
//! compare byte for byte.
//!
//! What it reads is real hardware. Every `virt` machine describes thirty-two `virtio,mmio`
//! slots whether or not anything is plugged in, and only the slot's own registers say which
//! is which (virtio 1.1 §4.2.2); `drivers/block/virtio-blk`'s `mmio::identify` reads the
//! same four registers to find the disk. Reading them is free of side effects, which is why
//! a slot can be identified from the kernel and from a domain in the same boot without the
//! two runs disturbing each other.
//!
//! # Why the encoding lives here
//!
//! An isolated driver has to *tell* someone what it found, and the kernel has to read it
//! back. If the writer and the reader lived on opposite sides of the boundary they would
//! drift, and a drifted decoder is indistinguishable from a driver that read the wrong
//! register. So both sides use [`Report::encode`] and [`Report::decode`] from this crate,
//! and a host test pins the round trip.

#![cfg_attr(not(test), no_std)]
#![deny(unsafe_code)]

#[cfg(test)]
mod tests;

use hwproxy::{Hw, Regs};

/// Register offsets, virtio 1.1 §4.2.2.
mod reg {
    pub const MAGIC: usize = 0x000;
    pub const VERSION: usize = 0x004;
    pub const DEVICE_ID: usize = 0x008;
    pub const VENDOR_ID: usize = 0x00c;
}

/// `"virt"` little-endian: the first register of every virtio-mmio device.
pub const MAGIC: u32 = 0x7472_6976;

/// The modern register layout. Version 1 is the legacy one, whose queue setup is a
/// different protocol; this body only identifies, so it reports the version rather than
/// refusing it.
pub const VERSION_MODERN: u32 = 2;

/// The bytes the identification registers span. A window smaller than this cannot hold
/// them, and the driver says so rather than reading all-ones and believing it.
pub const MIN_WINDOW: usize = 0x10;

/// `DEVICE_ID` of a block device, for a caller that wants to know which slot is the disk.
pub const DEVICE_ID_BLOCK: u32 = 2;

/// Identifications one measurement run makes, for `docs/isolation.md`.
///
/// Both sides link this crate, so the kernel divides by the same number the domain looped,
/// and neither can be changed without the other. Large on purpose: a domain run also builds
/// and tears down an address space, whose cost jitters by milliseconds under emulation, and
/// the loop has to be long enough that the difference it makes is not lost in that jitter.
/// At the few hundred nanoseconds an identification takes, this is tens of milliseconds.
pub const MEASURE_READS: u32 = 65536;

/// What one slot answered.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Report {
    pub magic: u32,
    pub version: u32,
    pub device_id: u32,
    pub vendor_id: u32,
}

/// Bytes of an encoded [`Report`]: four little-endian `u32`s.
pub const REPORT_BYTES: usize = 16;

impl Report {
    /// Whether the window really holds a virtio device.
    pub fn is_virtio(&self) -> bool {
        self.magic == MAGIC
    }

    /// Whether the slot is occupied. QEMU's unused slots answer `DEVICE_ID` zero.
    pub fn is_occupied(&self) -> bool {
        self.is_virtio() && self.device_id != 0
    }

    /// For the wire between a domain and the kernel; see the module documentation.
    pub fn encode(&self) -> [u8; REPORT_BYTES] {
        let mut out = [0u8; REPORT_BYTES];
        for (slot, value) in
            out.chunks_exact_mut(4)
                .zip([self.magic, self.version, self.device_id, self.vendor_id])
        {
            slot.copy_from_slice(&value.to_le_bytes());
        }
        out
    }

    /// The inverse of [`Report::encode`]. `None` if the message is not a whole report,
    /// which is what a caller sees if it reads a message that is not one.
    pub fn decode(bytes: &[u8]) -> Option<Report> {
        if bytes.len() != REPORT_BYTES {
            return None;
        }
        let word = |i: usize| {
            let mut b = [0u8; 4];
            b.copy_from_slice(&bytes[i * 4..i * 4 + 4]);
            u32::from_le_bytes(b)
        };
        Some(Report {
            magic: word(0),
            version: word(1),
            device_id: word(2),
            vendor_id: word(3),
        })
    }
}

/// Why a slot could not be identified.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Error {
    /// The window is smaller than the identification registers.
    WindowTooSmall,
}

/// Read the slot's identification registers.
///
/// The one entry point, and the reason this crate exists: it takes a [`Hw`], so the kernel
/// and a domain call the same code over the same registers, and neither can tell which it
/// is.
pub fn identify<H: Hw>(hw: &H) -> Result<Report, Error> {
    let regs = hw.regs();
    if regs.len() < MIN_WINDOW {
        return Err(Error::WindowTooSmall);
    }
    Ok(Report {
        magic: regs.read32(reg::MAGIC),
        version: regs.read32(reg::VERSION),
        device_id: regs.read32(reg::DEVICE_ID),
        vendor_id: regs.read32(reg::VENDOR_ID),
    })
}

/// Read the slot's identification registers `times` times, for the measurement in
/// `docs/isolation.md`.
///
/// Returns the last report, so the reads cannot be optimised away: every one of them is a
/// volatile access whose value is carried out of the loop.
pub fn identify_repeatedly<H: Hw>(hw: &H, times: u32) -> Result<Report, Error> {
    let mut last = identify(hw)?;
    for _ in 1..times {
        last = identify(hw)?;
    }
    Ok(last)
}

//! The virtqueue, as a hostile device drives it.
//!
//! Every other target here reads bytes that arrived once. This one reads memory the device
//! is *still writing*: the used ring is written by the device and read by the driver, with
//! no lock between them, and the driver believes what it finds there. A used element names
//! a descriptor head; a device that names one twice makes the driver free a chain twice,
//! and a device that names one out of range makes it index past the table.
//!
//! So the input is not a structure but the device's side of the ring: the used entries and
//! the index it publishes. The driver's own memory is host memory here, the way
//! `Backing` does it in the driver's tests, with the device's addresses deliberately
//! different from the CPU's.
//!
//! # `unsafe` here, and why it is contained
//!
//! `Dma::new` is unsafe: it promises that a range of host memory is exactly the physical
//! range the device sees. The promise is kept by owning the memory in this module and
//! never handing it anywhere else. The crate otherwise denies `unsafe`, so this is the one
//! place that needs the allow, and it needs it for the same reason the driver's own tests
//! do.

// The one module here that needs it: `Dma::new` promises host memory is a physical
// range, and the promise is kept by owning that memory in this file and handing it
// nowhere else. Every other target denies unsafe, as the crate does.
#![allow(unsafe_code)]

use alloc::vec;
use alloc::vec::Vec;

use virtio_blk::mem::Dma;
use virtio_blk::queue::{Buf, Ring, VIRTQ_DESC_F_WRITE};

use crate::{Mutator, Rng};

/// Queue sizes the protocol allows: powers of two up to 32768. Small ones, so the ring's
/// wrap-around is reached within an iteration rather than after thousands.
const SIZES: [u16; 4] = [1, 2, 4, 8];

/// Host memory standing in for the DMA region.
const REGION: usize = 16 * 1024;

/// What the device's addresses are offset by from the CPU's, as in the driver's tests: a
/// driver that hands the device a virtual address is then visibly wrong.
const DEVICE_OFFSET: u64 = 0x1000_0000;

pub fn generate(rng: &mut Rng, _seeds: &[Vec<u8>]) -> Vec<u8> {
    // A short script the device follows: size, then a sequence of (head, len, publish)
    // triples. Structure-aware because the first byte chooses the queue size, which
    // decides what a valid head even is.
    let mut bytes: Vec<u8> = Vec::new();
    bytes.push(rng.below(SIZES.len()) as u8);
    let steps = 1 + rng.below(24);
    for _ in 0..steps {
        // A head that is usually in range, sometimes exactly at the edge, sometimes not.
        let head = match rng.below(6) {
            0 => 0u32,
            1 => 7,
            2 => 8,
            3 => rng.next_u32(),
            4 => 0xffff,
            _ => rng.below(8) as u32,
        };
        bytes.extend_from_slice(&head.to_le_bytes());
        bytes.extend_from_slice(&rng.interesting_u32().to_le_bytes());
        // How far the device advances its index: usually one, sometimes a jump, which is
        // what a device that lost track would do.
        bytes.push(if rng.one_in(4) {
            rng.next_u32() as u8
        } else {
            1
        });
    }
    if !rng.one_in(8) {
        Mutator::mutate(rng, &mut bytes);
    }
    bytes
}

pub fn run(input: &[u8]) {
    let Some(&first) = input.first() else { return };
    let size = SIZES[first as usize % SIZES.len()];

    // The driver's region, owned here for the whole call.
    let mut region = vec![0u8; REGION];
    let base = region.as_mut_ptr() as usize;
    // SAFETY: `region` is host memory, live for this whole function, uniquely owned here,
    // and never aliased: the "device" below writes through the same `Dma` handles rather
    // than through another reference. The physical address is the fixed translation this
    // target models, exactly as the driver's own tests model it.
    let mut whole = unsafe { Dma::new(base, base as u64 + DEVICE_OFFSET, REGION) };

    let (d, a, u) = Ring::sizes(size);
    let (Some(desc), Some(avail), Some(used)) =
        (whole.take(d, 16), whole.take(a, 2), whole.take(u, 4))
    else {
        return;
    };
    // Where the used ring really is, read before the region moves into the ring.
    //
    // The first version recomputed this from `base` and the three sizes, rounded up to
    // their alignments. That is wrong: `Dma::take` pads by the *address's* alignment, not
    // the offset's, so the recomputed view could start a byte or three away from the real
    // ring. Its 32-bit writes then landed misaligned, and `Dma` refused them — which the
    // fuzzer reported, on its first iteration, as "DMA write outside the region". The bug
    // was this harness's, not the driver's.
    let (used_virt, used_phys, used_len) = (used.virt(), used.phys(), used.len());
    let Ok(mut ring) = Ring::new(desc, avail, used, size) else {
        return;
    };
    // The device's handle on the used ring, so it can write there after the driver owns it.
    //
    // SAFETY: exactly the region the ring was given, in the same host allocation, live for
    // this whole function. The only other handle to these bytes is the ring's own, which is
    // precisely the sharing a real device and driver have: the device writes, the driver
    // reads, and neither holds a Rust reference into the other's view.
    let used_view = unsafe { Dma::new(used_virt, used_phys, used_len) };

    // Give the driver something to have in flight, so a used element can name a real
    // chain as well as a wrong one.
    let mut buffer = vec![0u8; 512];
    let buf_at = buffer.as_mut_ptr() as usize;
    for _ in 0..size {
        let _ = ring.add(&[Buf {
            phys: buf_at as u64 + DEVICE_OFFSET,
            len: 512,
            device_writes: true,
        }]);
    }
    let _ = ring.free_descriptors();
    let _ = ring.notify_wanted();
    let _ = (ring.desc_phys(), ring.avail_phys(), ring.used_phys());

    // Now the device's script: write used elements and publish an index, then let the
    // driver collect. Nothing here may panic, whatever the device claims.
    let mut idx: u16 = 0;
    let mut at = 1usize;
    while at + 9 <= input.len() {
        let head = u32::from_le_bytes([input[at], input[at + 1], input[at + 2], input[at + 3]]);
        let len = u32::from_le_bytes([input[at + 4], input[at + 5], input[at + 6], input[at + 7]]);
        let advance = input[at + 8];
        at += 9;

        let slot = usize::from(idx % size);
        used_view.write32(4 + 8 * slot, head);
        used_view.write32(4 + 8 * slot + 4, len);
        idx = idx.wrapping_add(u16::from(advance));
        used_view.write16(2, idx);

        // Collect whatever the device claims to have finished, and put anything it
        // returned back in flight, which is what the request path does.
        while let Some(u) = ring.poll_used() {
            let _ = (u.head, u.len);
            let _ = ring.add(&[Buf {
                phys: buf_at as u64 + DEVICE_OFFSET,
                len: 512,
                device_writes: u.len % 2 == 0,
            }]);
        }
        let _ = ring.free_descriptors();
    }

    // The flags the device writes are read by the driver on every notify.
    used_view.write16(0, u16::from(input.len() as u8));
    let _ = ring.notify_wanted();
    let _ = VIRTQ_DESC_F_WRITE;
}

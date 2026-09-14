//! What the proxy layer promises, on memory a test owns.
//!
//! [`Direct`] is the accessor both modes use, so its bounds and alignment rules are the
//! ones a driver relies on whichever side of the isolation boundary it runs on. A window
//! here is an ordinary aligned buffer: the volatile accesses are the same instructions
//! they are over device memory, and what is being checked is the arithmetic around them.

use crate::{Buffer, Direct, Dma, Hw, Irq, NO_DMA, NoIrq, Parts, Regs};

/// A window over `bytes`, which the caller keeps alive.
fn window(bytes: &mut [u64]) -> Direct {
    // SAFETY: the slice is live for the caller's borrow, aligned to 8 by its element type,
    // and nothing else writes it while the window exists.
    unsafe { Direct::new(bytes.as_mut_ptr() as usize, bytes.len() * 8) }
}

#[test]
fn every_width_round_trips_inside_the_window() {
    let mut store = [0u64; 8];
    let w = window(&mut store);

    w.write8(0, 0xa5);
    w.write16(2, 0xbeef);
    w.write32(4, 0xdead_c0de);
    w.write64(8, 0x0123_4567_89ab_cdef);

    assert_eq!(w.read8(0), 0xa5);
    assert_eq!(w.read16(2), 0xbeef);
    assert_eq!(w.read32(4), 0xdead_c0de);
    assert_eq!(w.read64(8), 0x0123_4567_89ab_cdef);
    assert_eq!(w.len(), 64);
    assert!(!w.is_empty());
}

#[test]
fn an_access_past_the_end_reads_all_ones_and_writes_nothing() {
    let mut store = [0u64; 2];
    let w = window(&mut store);
    let before = store;

    // The last word is at offset 8; offset 16 is one past the window, and a 64-bit read at
    // offset 12 starts inside it and ends outside.
    let w = w;
    assert_eq!(w.read64(16), u64::MAX, "past the end reads as an absent device");
    assert_eq!(w.read64(12), u64::MAX, "an access that straddles the end is refused");
    assert_eq!(w.read32(16), u32::MAX);
    assert_eq!(w.read8(16), u8::MAX);

    w.write64(16, 1);
    w.write32(16, 1);
    w.write8(16, 1);
    assert_eq!(store, before, "a refused write touches nothing");
}

#[test]
fn a_misaligned_access_is_refused() {
    let mut store = [0u64; 4];
    let w = window(&mut store);
    let before = store;

    assert_eq!(w.read32(2), u32::MAX, "a 32-bit read must be 4-aligned");
    assert_eq!(w.read64(4), u64::MAX, "a 64-bit read must be 8-aligned");
    assert_eq!(w.read16(1), u16::MAX, "a 16-bit read must be 2-aligned");

    w.write32(2, 1);
    w.write64(4, 1);
    w.write16(1, 1);
    assert_eq!(store, before, "and neither is a misaligned write");
}

#[test]
fn an_empty_window_refuses_everything() {
    // SAFETY: never dereferenced, because every access is out of bounds of a zero-length
    // window and is refused before the pointer is formed.
    let w = unsafe { Direct::new(0x1000, 0) };
    assert!(w.is_empty());
    assert_eq!(w.read32(0), u32::MAX);
    w.write32(0, 1);
}

#[test]
fn a_buffer_keeps_the_two_addresses_apart() {
    // SAFETY: not dereferenced here; the test reads only the numbers it was given.
    let b = unsafe { Buffer::new(0x4000_0000, 0xffff_8000_0000_0000, 0x1000) };
    assert_eq!(b.phys(), 0x4000_0000, "what the device is told");
    assert_eq!(b.virt(), 0xffff_8000_0000_0000, "what the CPU dereferences");
    assert_eq!(b.len(), 0x1000);
    assert!(!b.is_empty());

    assert!(NO_DMA.is_empty(), "a driver with no grant gets no buffer");
    assert_eq!(NO_DMA.phys(), 0);
}

#[test]
fn a_device_with_no_interrupt_reports_none() {
    let i = NoIrq;
    assert_eq!(i.count(), 0);
    i.acknowledge(0);
}

#[test]
fn parts_assembles_the_three_capabilities() {
    let mut store = [0u64; 2];
    let hw = Parts {
        regs: window(&mut store),
        dma: NO_DMA,
        irq: NoIrq,
    };
    hw.regs().write32(0, 0x1234);
    assert_eq!(hw.regs().read32(0), 0x1234);
    assert!(hw.dma().is_empty());
    assert_eq!(hw.irq().count(), 0);
}

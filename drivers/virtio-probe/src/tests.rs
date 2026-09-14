//! The driver body against a fake slot, so its register offsets and its wire format are
//! checked without a machine.

// The crate itself is free of `unsafe`: a driver body only reads registers through the
// proxy. Building a window over a test's own buffer is the one place that needs it, and
// it is here rather than in the driver.
#![allow(unsafe_code)]

use hwproxy::{Direct, NO_DMA, NoIrq, Parts};

use crate::{DEVICE_ID_BLOCK, Error, MAGIC, REPORT_BYTES, Report, VERSION_MODERN, identify};

/// A slot's registers, as a buffer a test owns: magic, version, device id, vendor id.
fn slot(magic: u32, version: u32, device_id: u32, vendor_id: u32) -> [u32; 0x40] {
    let mut regs = [0u32; 0x40];
    regs[0] = magic;
    regs[1] = version;
    regs[2] = device_id;
    regs[3] = vendor_id;
    regs
}

fn hw(regs: &mut [u32]) -> Parts<Direct, hwproxy::Buffer, NoIrq> {
    // SAFETY: the slice outlives the borrow, is 4-aligned by its element type, and nothing
    // else touches it while the window exists.
    let window = unsafe { Direct::new(regs.as_mut_ptr() as usize, regs.len() * 4) };
    Parts {
        regs: window,
        dma: NO_DMA,
        irq: NoIrq,
    }
}

#[test]
fn it_reads_the_four_identification_registers() {
    let mut regs = slot(MAGIC, VERSION_MODERN, DEVICE_ID_BLOCK, 0x554d_4551);
    let report = identify(&hw(&mut regs)).unwrap();

    assert_eq!(
        report,
        Report {
            magic: MAGIC,
            version: VERSION_MODERN,
            device_id: DEVICE_ID_BLOCK,
            vendor_id: 0x554d_4551,
        }
    );
    assert!(report.is_virtio());
    assert!(report.is_occupied());
}

#[test]
fn an_empty_slot_is_virtio_but_not_occupied() {
    let mut regs = slot(MAGIC, VERSION_MODERN, 0, 0x554d_4551);
    let report = identify(&hw(&mut regs)).unwrap();
    assert!(report.is_virtio(), "the slot exists");
    assert!(!report.is_occupied(), "nothing is plugged into it");
}

#[test]
fn memory_that_is_not_a_slot_is_not_virtio() {
    let mut regs = slot(0xdead_beef, 7, 3, 1);
    let report = identify(&hw(&mut regs)).unwrap();
    assert!(!report.is_virtio());
    assert!(!report.is_occupied());
}

#[test]
fn a_window_too_small_for_the_registers_is_an_error_not_a_guess() {
    // Two registers' worth: reading the other two would be out of bounds, and an
    // out-of-bounds read is all-ones, which is indistinguishable from a device answering.
    let mut regs = [MAGIC, VERSION_MODERN];
    assert_eq!(identify(&hw(&mut regs)), Err(Error::WindowTooSmall));
}

#[test]
fn a_report_survives_the_wire() {
    let report = Report {
        magic: MAGIC,
        version: VERSION_MODERN,
        device_id: DEVICE_ID_BLOCK,
        vendor_id: 0x554d_4551,
    };
    let bytes = report.encode();
    assert_eq!(bytes.len(), REPORT_BYTES);
    assert_eq!(Report::decode(&bytes), Some(report), "the round trip is exact");
    assert_eq!(
        &bytes[..4],
        &MAGIC.to_le_bytes(),
        "little-endian words, as both sides read them"
    );
}

#[test]
fn a_message_that_is_not_a_report_is_refused() {
    assert_eq!(Report::decode(&[]), None);
    assert_eq!(Report::decode(&[0; REPORT_BYTES - 1]), None);
    assert_eq!(Report::decode(&[0; REPORT_BYTES + 1]), None);
}

#[test]
fn repeated_reads_return_the_same_report() {
    let mut regs = slot(MAGIC, VERSION_MODERN, DEVICE_ID_BLOCK, 1);
    let hw = hw(&mut regs);
    let once = identify(&hw).unwrap();
    let many = crate::identify_repeatedly(&hw, 64).unwrap();
    assert_eq!(once, many, "identification has no side effects");
}

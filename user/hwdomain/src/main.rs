//! The isolated driver domain: an unprivileged program that runs a driver body against
//! hardware the kernel granted it, and reports what it found.
//!
//! This is the other half of Phase 5's claim. The kernel runs `virtio_probe::identify`
//! itself, over a window its own address space maps; this program runs *the same function*,
//! over the same physical window, mapped into an address space that contains nothing else.
//! Neither copy knows which it is: both take a [`hwproxy::Hw`].
//!
//! # What the kernel hands over
//!
//! Four argument registers, and nothing else:
//!
//! 1. the mode,
//! 2. the address the granted register window is mapped at,
//! 3. the device window's length — the device's own, not the page the kernel had to map to hold it,
//! 4. the address of a page the kernel shares with this program, to report on.
//!
//! A domain cannot name hardware it was not given: there is no call that maps a physical
//! address, and the only window it knows about is the one whose address it was told. That
//! is what makes [`MODE_ROGUE`] a real test rather than a gesture — the program deliberately
//! reaches past the end of its grant, and the MMU, not a bounds check in the driver, is what
//! must stop it.
//!
//! # Reporting, not grading
//!
//! As `user/init` does, this program says what it observed and the kernel decides whether
//! that is right. A domain that graded itself would be the code under test marking its own
//! work.

#![no_std]
#![no_main]
// The granted window and the report page arrive as numbers in registers: turning them into
// accesses is the one thing here that needs `unsafe`, and the kernel's grant is the promise
// behind both.
#![allow(unsafe_code)]

use abi::call;
use hwproxy::{Direct, NO_DMA, NoIrq, Parts};
use virtio_probe::{MEASURE_READS, REPORT_BYTES};

/// Identify the device once and report it.
const MODE_REPORT: usize = 0;
/// Identify it [`MEASURE_READS`] times, then report, so the kernel can time the loop.
const MODE_MEASURE: usize = 1;
/// Read one word past the end of the grant. The kernel expects to kill this program for it.
const MODE_ROGUE: usize = 2;

/// Reported the device as asked.
const SUCCESS: u64 = 0x2a;
/// The window the kernel described is too small for the registers.
const BAD_WINDOW: u64 = 0x5201;
/// The read past the grant *returned*. Reaching this exit is the failure: the kernel is
/// waiting to be told the domain was killed, so a clean exit with this code says the
/// boundary did not hold.
const NOT_STOPPED: u64 = 0x5202;
/// The mode register held something this program does not implement.
const BAD_MODE: u64 = 0x5204;
/// The granted window does not hold a virtio device. The driver refuses to go on rather
/// than report registers from something it was not built to drive: a host that granted
/// the wrong window gets a refusal, not a plausible-looking answer.
const NOT_VIRTIO: u64 = 0x5205;

/// The page past the one holding the window, for [`MODE_ROGUE`]: the kernel maps the
/// window's page and nothing next to it, so this address is outside every grant.
const PAGE: usize = 4096;

#[unsafe(no_mangle)]
#[unsafe(link_section = ".text._start")]
pub extern "C" fn _start(mode: usize, window: usize, len: usize, shared: usize) -> ! {
    let code = match mode {
        MODE_REPORT => report(window, len, shared, 1),
        MODE_MEASURE => report(window, len, shared, MEASURE_READS),
        MODE_ROGUE => rogue(window),
        _ => BAD_MODE,
    };
    exit(code)
}

/// Identify the device `reads` times and leave the last report on the shared page.
fn report(window: usize, len: usize, shared: usize, reads: u32) -> u64 {
    // SAFETY: the kernel mapped the granted register window at `window` for at least `len`
    // bytes, as device memory, before entering this program, and it is the only mapping of
    // it this address space has. Nothing else here touches it.
    let regs = unsafe { Direct::new(window, len) };
    let hw = Parts {
        regs,
        dma: NO_DMA,
        irq: NoIrq,
    };
    let Ok(report) = virtio_probe::identify_repeatedly(&hw, reads) else {
        return BAD_WINDOW;
    };
    if !report.is_virtio() {
        return NOT_VIRTIO;
    }
    let bytes = report.encode();
    let out = shared as *mut u8;
    for (i, b) in bytes.iter().enumerate().take(REPORT_BYTES) {
        // SAFETY: the kernel mapped a writable page at `shared` for this program to report
        // on, and `REPORT_BYTES` is far less than a page. Volatile, because the reader is
        // the kernel, through another mapping of the same frame.
        unsafe { out.add(i).write_volatile(*b) };
    }
    SUCCESS
}

/// Read one word outside the grant.
///
/// The driver's own bounds check would refuse this, which is exactly why the check is
/// bypassed: what is being tested is the *host's* containment, not the driver's manners. A
/// window is built over the page after the one the kernel mapped and read at offset zero,
/// so the access is in bounds as far as the proxy is concerned and out of bounds as far as
/// the MMU is.
fn rogue(window: usize) -> u64 {
    let past = (window & !(PAGE - 1)).wrapping_add(PAGE);
    // SAFETY: no promise is being made here, and that is the point — this is the case a
    // host must survive. The address is outside everything the kernel granted, so the read
    // below must fault. If the platform ever let it succeed, the value is discarded and the
    // program exits with `NOT_STOPPED`, which fails the kernel's check.
    let outside = unsafe { Direct::new(past, 4) };
    let stolen = <Direct as hwproxy::Regs>::read32(&outside, 0);
    core::hint::black_box(stolen);
    NOT_STOPPED
}

fn exit(code: u64) -> ! {
    let _ = call::process_exit(code);
    // Unreachable unless the kernel returned from an exit, which its check sees as a
    // domain that never ended.
    loop {
        let _ = call::thread_yield();
    }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    exit(0xdead)
}

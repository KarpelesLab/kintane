//! The block check: the virtio-blk driver, brought up on memory the kernel gives it, over
//! the disk kbuild attaches to test builds.
//!
//! Bring-up happens here rather than in discovery because a virtio device's handshake
//! ends by handing it queue addresses, and discovery runs before there is memory to hand
//! over (see `virtio_blk`'s module documentation). The check then proves, on the real
//! device:
//!
//! * the disk's header names the geometry the device reported;
//! * sectors read back the pattern kbuild wrote, including a read larger than the driver's bounce
//!   buffer, which the block layer must split;
//! * a write to the scratch area reads back, and a flush succeeds;
//! * the sector just before the scratch area still holds the pattern, so the write landed where it
//!   was sent;
//! * a read past the end is refused by the driver, and the same read with the driver's check
//!   skipped is refused by the device, which comes back as an error value;
//! * after every request, nothing is in flight and every descriptor is back on the ring.
//!
//! The started device outlives the check: [`disk`] is how the stress run reaches it.

use core::cell::SyncUnsafeCell;
use core::sync::atomic::{AtomicBool, Ordering};

use arch::Cpu;
use block::{BlockDevice, Error as BlockError, testdisk};
use hal::{Arch, EarlyConsole, PhysAddr};
use mm::phys::FrameAllocator;
use virtio_blk::VirtioBlk;
use virtio_blk::mem::Dma;

use crate::{Check, Live, Locks, write_usize};

/// Frames for the rings and for every request that may be in flight: each has its own
/// header, status byte and bounce buffer, so the driver can have several outstanding.
/// Still few enough that the check's 32-sector read cannot fit in one request, so the
/// block layer's split is exercised against the real device.
const DMA_PAGES: usize = 8;

/// Sectors read at once, into [`BUF`].
const READ_SECTORS: usize = 32;

/// Requests repeated after the functional checks, to prove none leaks.
const REPEATS: u64 = 64;

/// A buffer for the check, off the 16 KiB boot stack.
///
/// SAFETY INVARIANT: borrowed only by [`check`], which runs once on the boot path.
static BUF: SyncUnsafeCell<[u8; READ_SECTORS * testdisk::SECTOR]> =
    SyncUnsafeCell::new([0; READ_SECTORS * testdisk::SECTOR]);

/// SAFETY INVARIANT: written once, by [`check`], before `STARTED` is set; read only after
/// it is set, through [`disk`].
static DISK: SyncUnsafeCell<Option<VirtioBlk<Locks>>> = SyncUnsafeCell::new(None);
static STARTED: AtomicBool = AtomicBool::new(false);

/// The started disk, once the check has brought it up.
pub fn disk() -> Option<&'static VirtioBlk<Locks>> {
    if !STARTED.load(Ordering::Acquire) {
        return None;
    }
    // SAFETY: `STARTED` is set only after the one write, and nothing writes again.
    unsafe { (*DISK.get()).as_ref() }
}

/// The disk's interrupt handler, installed with `virtio_blk::set_handler`.
///
/// The device model's table holds a plain function, and the started device belongs to the
/// kernel, which brought it up with memory it provides. So the handler reaches the device
/// through [`disk`], which is readable before the first request is submitted.
fn on_disk_interrupt() {
    if let Some(d) = disk() {
        d.on_interrupt();
    }
}

/// Bring the disk up and check it.
pub fn check(c: &dyn EarlyConsole, frames: &mut FrameAllocator<'_, Cpu>, live: Live) -> Check {
    c.write_str("\n  block      ");
    if virtio_blk::window().is_none() {
        if kconfig::QEMU_BLOCK_TEST {
            c.write_str("NO VIRTIO-BLK DEVICE, though the run attached a disk");
            return Check::Failed;
        }
        c.write_str("skipped: no block device");
        return Check::Skipped;
    }
    let Some(direct) = live.direct else {
        c.write_str("no kernel address space to map the device's memory through");
        return Check::Failed;
    };

    // Device memory: a contiguous run the device will address by its physical address.
    let Ok(run) = frames.alloc_contiguous(DMA_PAGES) else {
        c.write_str("no run of frames for the device's memory");
        return Check::Failed;
    };
    let phys = run.start().start().raw();
    let len = DMA_PAGES * <Cpu as hal::Arch>::PAGE_SIZE;
    let Ok(virt) = direct.to_virt(PhysAddr::new(phys)) else {
        c.write_str("the device's memory is outside the direct map");
        let _ = frames.free_contiguous(run);
        return Check::Failed;
    };
    if !direct.covers_phys(PhysAddr::new(phys + len as u64 - 1)) {
        c.write_str("the device's memory runs past the direct map");
        let _ = frames.free_contiguous(run);
        return Check::Failed;
    }
    // SAFETY: the run was just taken from the frame allocator, so nothing else refers to
    // it, and the direct map maps `[phys, phys + len)` at `virt` writable. It is never
    // freed: the device keeps using it for as long as the kernel runs.
    let dma = unsafe { Dma::new(virt.raw(), phys, len) };

    // SAFETY: the claimed window is mapped by the kernel's address space, which maps
    // every window a bound driver claimed, and this is the one transport made for it.
    let Some(transport) = (unsafe { virtio_blk::transport() }) else {
        c.write_str("the device's window is outside the address space");
        return Check::Failed;
    };
    let blk = match VirtioBlk::<Locks>::bring_up(transport, dma) {
        Ok(b) => b,
        Err(e) => {
            c.write_str("bring-up FAILED: ");
            c.write_str(bring_up_error(e));
            return Check::Failed;
        }
    };

    let geometry = blk.geometry();
    write_usize(c, geometry.capacity as usize);
    c.write_str(" sectors of ");
    write_usize(c, geometry.block_size);
    c.write_str(" bytes, ");
    write_usize(c, blk.max_transfer_blocks() as usize);
    c.write_str(" per request");

    // The device is stored, and its interrupt handler installed, *before* the checks run.
    //
    // The platform registered and enabled the device's line during discovery, and the
    // device raises it for every completion. Its interrupt status is acknowledged only by
    // the handler, not by a caller draining the ring, so a line with a handler that cannot
    // reach the device stays asserted: level-triggered, it would re-enter the interrupt
    // path for good the first time interrupts were unmasked after this check.
    //
    // SAFETY: the one write to `DISK`, before `STARTED` makes it readable.
    unsafe { *DISK.get() = Some(blk) };
    STARTED.store(true, Ordering::Release);
    // SAFETY: once, on the boot path, before any interrupt can be delivered for the line:
    // interrupts are masked here, and the first request is submitted below.
    let _ = unsafe { virtio_blk::set_handler(on_disk_interrupt) };
    let Some(blk) = disk() else {
        c.write_str("; the disk could not be read back after it was stored");
        return Check::Failed;
    };

    // SAFETY: the one borrow of `BUF`; see its invariant.
    let buf = unsafe { &mut *BUF.get() };
    let ok = run_checks(c, blk, buf);
    if ok {
        c.write_str(" ok");
        Check::Passed
    } else {
        Check::Failed
    }
}

fn run_checks(c: &dyn EarlyConsole, blk: &VirtioBlk<Locks>, buf: &mut [u8]) -> bool {
    let g = blk.geometry();
    if g.block_size != testdisk::SECTOR || g.capacity != testdisk::SECTORS {
        c.write_str("; NOT THE TEST DISK'S GEOMETRY");
        return false;
    }

    // Sector 0's header.
    let sector0 = &mut buf[..testdisk::SECTOR];
    if let Err(e) = blk.read_blocks(0, sector0) {
        return failed(c, "reading sector 0", e);
    }
    if testdisk::header(sector0) != Some(testdisk::SECTORS) {
        c.write_str("; SECTOR 0 IS NOT THE TEST DISK'S HEADER");
        return false;
    }

    // A read larger than one request, split by the block layer: sectors 1 to 32.
    if let Err(e) = block::read(blk, 1, buf) {
        return failed(c, "reading sectors 1-32", e);
    }
    for (i, sector) in buf.chunks_exact(testdisk::SECTOR).enumerate() {
        if let Some(at) = testdisk::first_mismatch(1 + i as u64, sector) {
            c.write_str("; SECTOR ");
            write_usize(c, 1 + i);
            c.write_str(" DIFFERS AT BYTE ");
            write_usize(c, at);
            return false;
        }
    }
    c.write_str("; 32 sectors read back the pattern");

    // Write the scratch area with a pattern the disk does not hold, flush, read back.
    let scratch = &mut buf[..8 * testdisk::SECTOR];
    for (i, b) in scratch.iter_mut().enumerate() {
        *b = testdisk::pattern(testdisk::SCRATCH_START ^ 0xa5a5, i);
    }
    if let Err(e) = block::write(blk, testdisk::SCRATCH_START, scratch) {
        return failed(c, "writing the scratch area", e);
    }
    if let Err(e) = blk.flush() {
        return failed(c, "flushing", e);
    }
    scratch.fill(0);
    if let Err(e) = block::read(blk, testdisk::SCRATCH_START, scratch) {
        return failed(c, "reading the scratch area back", e);
    }
    let wrong = scratch
        .iter()
        .enumerate()
        .position(|(i, &b)| b != testdisk::pattern(testdisk::SCRATCH_START ^ 0xa5a5, i));
    if let Some(at) = wrong {
        c.write_str("; THE SCRATCH WRITE DID NOT READ BACK, FIRST AT BYTE ");
        write_usize(c, at);
        return false;
    }
    // The sector before the scratch area still holds the pattern.
    let before = &mut buf[..testdisk::SECTOR];
    if let Err(e) = blk.read_blocks(testdisk::SCRATCH_START - 1, before) {
        return failed(c, "reading below the scratch area", e);
    }
    if testdisk::first_mismatch(testdisk::SCRATCH_START - 1, before).is_some() {
        c.write_str("; THE WRITE LANDED BELOW THE SCRATCH AREA");
        return false;
    }
    c.write_str("; a write read back after a flush");

    // Past the end.
    let probe = &mut buf[..testdisk::SECTOR];
    match blk.read_blocks(testdisk::SECTORS, probe) {
        Err(BlockError::OutOfRange { .. }) => c.write_str("; a read past the end refused"),
        Ok(()) => {
            c.write_str("; A READ PAST THE END SUCCEEDED");
            return false;
        }
        Err(e) => return failed(c, "the read past the end failed the wrong way", e),
    }

    // The same request with the driver's range check skipped: the device itself must
    // refuse it, and its refusal must come back as an error, not a panic or a success.
    let probe = &mut buf[..testdisk::SECTOR];
    match blk.read_past_end_unchecked(probe) {
        Err(BlockError::Device(_)) => c.write_str("; the device's own refusal was an error"),
        Ok(()) => {
            c.write_str("; THE DEVICE ANSWERED A READ PAST ITS END");
            return false;
        }
        Err(e) => return failed(c, "the device's refusal came back the wrong way", e),
    }

    // Nothing leaks: every request back, every descriptor free.
    let (issued_before, _, _, _) = blk.counters();
    for i in 0..REPEATS {
        let piece = &mut buf[..testdisk::SECTOR];
        if let Err(e) = blk.read_blocks(1 + i, piece) {
            return failed(c, "a repeated read", e);
        }
    }
    let (issued, completed, in_flight, clean) = blk.counters();
    c.write_str("; ");
    write_usize(c, (issued - issued_before) as usize);
    c.write_str(" more requests, ");
    write_usize(c, in_flight);
    c.write_str(" in flight");
    if issued != completed || in_flight != 0 || !clean {
        c.write_str(", A REQUEST OR DESCRIPTOR LEAKED");
        return false;
    }
    true
}

/// Requests the interrupt check makes with completions collected only by the handler.
const IRQ_REQUESTS: u64 = 32;

/// The disk's interrupt, proved end to end: the platform wired its line, the controller
/// delivers it, the device model dispatches it, and the driver's handler collects the
/// completion. Nothing else is allowed to.
///
/// The driver is switched to interrupt-driven mode, in which a waiting caller never drains
/// the ring itself, and interrupts are enabled. Each read must then return the pattern, and
/// the counters must show that every completion of these requests was collected in the
/// handler and none by polling. A lost interrupt is a request that times out, which fails
/// the check rather than hanging it.
///
/// Where the platform wired no line — a port whose controller no PCI interrupt route
/// reaches — the check reports the disk as polled and skips, rather than passing a check
/// that measured nothing.
pub fn interrupt_check(c: &dyn EarlyConsole) -> Check {
    let Some(blk) = disk() else {
        c.write_str("skipped: no block device");
        return Check::Skipped;
    };
    let Some(line) = platform::block_line() else {
        c.write_str("skipped: the disk is polled, no interrupt route on this port");
        return Check::Skipped;
    };
    c.write_str("line ");
    write_usize(c, line as usize);

    let (irqs_before, via_irq_before) = blk.interrupt_counts();
    let polled_before = blk.polled_completions();
    let (issued_before, _, _, _) = blk.counters();

    blk.set_interrupt_driven(true);
    // SAFETY: the interrupt path is up (the interrupt selftest ran), the disk's handler is
    // registered and its line enabled, and the scheduler's hook is not installed yet, so an
    // interrupt taken here returns to this loop.
    unsafe { arch::tick::enable_interrupts() };
    let mut sector = [0u8; testdisk::SECTOR];
    let mut failure = None;
    for i in 0..IRQ_REQUESTS {
        match blk.read_blocks(1 + i, &mut sector) {
            Ok(()) if testdisk::first_mismatch(1 + i, &sector).is_none() => {}
            Ok(()) => {
                failure = Some("A SECTOR READ BY INTERRUPT DID NOT HOLD THE PATTERN");
                break;
            }
            Err(BlockError::Timeout) => {
                failure = Some("A REQUEST TIMED OUT: ITS INTERRUPT NEVER ARRIVED");
                break;
            }
            Err(_) => {
                failure = Some("A READ BY INTERRUPT FAILED");
                break;
            }
        }
    }
    // Masked again for the rest of bring-up, which runs masked.
    let _ = Cpu::irq_save();
    blk.set_interrupt_driven(false);

    let (irqs, via_irq) = blk.interrupt_counts();
    let polled = blk.polled_completions() - polled_before;
    let (issued, completed, in_flight, clean) = blk.counters();
    let made = issued - issued_before;
    let by_interrupt = via_irq - via_irq_before;
    c.write_str("; ");
    write_usize(c, made as usize);
    c.write_str(" requests, ");
    write_usize(c, by_interrupt as usize);
    c.write_str(" completions in ");
    write_usize(c, (irqs - irqs_before) as usize);
    c.write_str(" interrupts, ");
    write_usize(c, polled as usize);
    c.write_str(" polled");

    if let Some(why) = failure {
        c.write_str(", ");
        c.write_str(why);
        return Check::Failed;
    }
    if polled != 0 {
        c.write_str(", A COMPLETION WAS COLLECTED WITHOUT ITS INTERRUPT");
        return Check::Failed;
    }
    if by_interrupt != made || irqs == irqs_before {
        c.write_str(", NOT EVERY COMPLETION ARRIVED BY INTERRUPT");
        return Check::Failed;
    }
    if issued != completed || in_flight != 0 || !clean {
        c.write_str(", A REQUEST OR DESCRIPTOR LEAKED");
        return Check::Failed;
    }
    c.write_str(" ok");
    Check::Passed
}

fn failed(c: &dyn EarlyConsole, what: &str, e: BlockError) -> bool {
    c.write_str("; ");
    c.write_str(what);
    c.write_str(" FAILED: ");
    c.write_str(match e {
        BlockError::OutOfRange { .. } => "out of range",
        BlockError::Misaligned { .. } => "misaligned",
        BlockError::Device(why) => why,
        BlockError::Timeout => "the device did not answer",
        BlockError::NoRoom => "no room in the queue",
        BlockError::Stale => "a stale request",
        BlockError::Pending => "still pending",
    });
    false
}

fn bring_up_error(e: virtio_blk::transport::Error) -> &'static str {
    use virtio_blk::transport::Error;
    match e {
        Error::NotVirtio => "not a virtio device",
        Error::Legacy => "a legacy virtio device",
        Error::WrongDevice { .. } => "not a block device",
        Error::FeaturesRefused => "the device refused the features",
        Error::Refused { .. } => "the device refused the handshake",
        Error::BadQueue { .. } => "the device's queue is unusable",
        Error::NoRoom => "not enough memory for the rings",
        Error::BadGeometry => "an unusable geometry",
        Error::Timeout => "the device did not answer",
    }
}

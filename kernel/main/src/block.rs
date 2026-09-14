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

use crate::{Check, Live, Locks, iommu, write_usize};

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

    // With an IOMMU, put the disk behind it *before* it does any DMA: a translation domain
    // that maps exactly this grant and nothing else. `iommu` does nothing on a build without
    // one, and there the disk's DMA reaches memory directly as before.
    let confined = if kconfig::IOMMU {
        if !iommu::confine_disk(c, frames, direct, phys, len as u64) {
            return Check::Failed;
        }
        c.write_str("; ");
        true
    } else {
        false
    };

    // SAFETY: the claimed window is mapped by the kernel's address space, which maps
    // every window a bound driver claimed, and this is the one transport made for it.
    let Some(transport) = (unsafe { virtio_blk::transport() }) else {
        c.write_str("the device's window is outside the address space");
        return Check::Failed;
    };
    // The queue on its MSI-X entry when that is how the platform wired the disk's interrupt;
    // on a line, or polled, bring-up needs to know nothing.
    let vector = virtio_blk::msix_entry()
        .filter(|_| platform::block_line().is_some_and(platform::interrupt_is_msi));
    let blk = match VirtioBlk::<Locks>::bring_up_with_vector(transport, dma, vector) {
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
    let mut ok = run_checks(c, blk, buf);
    // With the IOMMU on, prove the confinement: an out-of-grant DMA is stopped and logged,
    // and the device restarts and serves again. `blk` is re-fetched inside, because a
    // restart replaces the stored device.
    if ok && confined {
        ok = iommu_checks(c, frames, direct, virt.raw(), phys, len, buf);
    }
    if ok {
        c.write_str(" ok");
        Check::Passed
    } else {
        Check::Failed
    }
}

/// Polls the deliberate out-of-grant DMA waits before it is called blocked. A blocked request
/// never completes, so this only bounds the wait; it is far above what a served request takes.
const ROGUE_POLLS: u32 = 2_000_000;

/// The IOMMU confinement checks, run after the functional ones with the device behind the
/// IOMMU: the in-grant DMA that `run_checks` already served, then a deliberate out-of-grant
/// DMA the hardware must stop and log, then a restart that serves again.
fn iommu_checks(
    c: &dyn EarlyConsole,
    frames: &mut FrameAllocator<'_, Cpu>,
    direct: mm::DirectMap,
    virt: usize,
    phys: u64,
    len: usize,
    buf: &mut [u8],
) -> bool {
    let Some(blk) = disk() else {
        return false;
    };
    // A canary frame outside the grant, filled with a sentinel the device will try to
    // overwrite. It is never freed, so nothing reuses the address the fault will name.
    let Ok(canary) = frames.alloc_frame() else {
        c.write_str("\n  iommu      NO CANARY FRAME");
        return false;
    };
    let cphys = canary.start().raw();
    let Ok(cvirt) = direct.to_virt(PhysAddr::new(cphys)) else {
        c.write_str("\n  iommu      CANARY OUTSIDE THE DIRECT MAP");
        return false;
    };
    let cp = cvirt.raw() as *mut u8;
    const SENTINEL: u8 = 0x5a;
    for i in 0..testdisk::SECTOR {
        // SAFETY: `cp` is the canary frame through the direct map, a whole page; writing a
        // sector of it is in bounds. Volatile, because the device may write it behind us.
        unsafe { cp.add(i).write_volatile(SENTINEL) };
    }

    // The grant must translate and the canary must not: the domain maps exactly the grant.
    if !iommu::domain_maps(phys) || iommu::domain_maps(cphys) {
        c.write_str("\n  iommu      THE DOMAIN DOES NOT MAP EXACTLY THE GRANT");
        return false;
    }

    // The rogue DMA: point the device at a read into the canary, outside its grant.
    let completed = blk.dma_probe(0, cphys, testdisk::SECTOR as u32, ROGUE_POLLS);
    let fault = iommu::take_fault();
    let mut untouched = true;
    for i in 0..testdisk::SECTOR {
        // SAFETY: as the fill above.
        if unsafe { cp.add(i).read_volatile() } != SENTINEL {
            untouched = false;
            break;
        }
    }

    c.write_str("\n  iommu      in-grant DMA served behind VT-d");
    let stopped = match fault {
        Some((f, source)) if f.address == cphys && f.write => {
            c.write_str("; out-of-grant DMA stopped at ");
            write_hex(c, f.address);
            c.write_str(" from ");
            write_hex(c, u64::from(source));
            true
        }
        Some((f, _)) => {
            c.write_str("; A FAULT AT ");
            write_hex(c, f.address);
            c.write_str(" BUT NOT THE ROGUE ONE");
            false
        }
        None => {
            let _ = completed;
            c.write_str("; THE ROGUE DMA WAS NOT STOPPED");
            false
        }
    };
    if !untouched {
        c.write_str("; THE CANARY WAS OVERWRITTEN");
    }

    // Restart: the faulted device is reset and a fresh one brought up over the same grant,
    // which the IOMMU domain still maps, so it serves again — and the stress run can use it.
    let served = restart(c, virt, phys, len, buf);
    stopped && untouched && served
}

/// Reset the device after the fault and bring a fresh one up over the same DMA grant and
/// window, then prove it serves a read. Replaces the stored device.
fn restart(c: &dyn EarlyConsole, virt: usize, phys: u64, len: usize, buf: &mut [u8]) -> bool {
    // SAFETY: the single-threaded boot path. The old device is dropped before the new one is
    // built, so the DMA region and the register window have exactly one owner at a time; the
    // new bring-up resets the device (status 0) and re-lays the queue, discarding the faulted
    // request. `virt`/`phys`/`len` are the same region `check` mapped, still direct-mapped.
    unsafe { *DISK.get() = None };
    STARTED.store(false, Ordering::Release);
    let dma = unsafe { Dma::new(virt, phys, len) };
    let Some(transport) = (unsafe { virtio_blk::transport() }) else {
        c.write_str("; NO TRANSPORT ON RESTART");
        return false;
    };
    let blk = match VirtioBlk::<Locks>::bring_up(transport, dma) {
        Ok(b) => b,
        Err(e) => {
            c.write_str("; RESTART BRING-UP FAILED: ");
            c.write_str(bring_up_error(e));
            return false;
        }
    };
    // SAFETY: the one write to `DISK` after the old one was cleared, before `STARTED`.
    unsafe { *DISK.get() = Some(blk) };
    STARTED.store(true, Ordering::Release);
    let Some(blk) = disk() else {
        return false;
    };
    let sector0 = &mut buf[..testdisk::SECTOR];
    if let Err(e) = blk.read_blocks(0, sector0) {
        return failed(c, "reading after the restart", e);
    }
    if testdisk::header(sector0) != Some(testdisk::SECTORS) {
        c.write_str("; THE RESTARTED DEVICE READ WRONG DATA");
        return false;
    }
    c.write_str("; restarted and served a read");
    true
}

/// A 64-bit value in hex, `0x`-prefixed, for the IOMMU report.
fn write_hex(c: &dyn EarlyConsole, value: u64) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut buf = [0u8; 18];
    buf[0] = b'0';
    buf[1] = b'x';
    for i in 0..16 {
        buf[2 + i] = HEX[((value >> (60 - 4 * i)) & 0xf) as usize];
    }
    c.write_bytes(&buf);
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
    // QEMU's virtio-blk-pci has an MSI-X table. On a platform that delivers messages, a test
    // disk that came up on anything else fell back somewhere, and this check and the next
    // would skip where they should have measured.
    if kconfig::QEMU_BLOCK_TEST && platform::delivers_msi() && !blk.uses_msix() {
        c.write_str("THE DISK IS NOT ON MSI-X, THOUGH QEMU'S FUNCTION HAS IT");
        return Check::Failed;
    }
    let Some(line) = platform::block_line() else {
        c.write_str("skipped: the disk is polled, no interrupt route on this port");
        return Check::Skipped;
    };
    c.write_str("line ");
    write_usize(c, line as usize);
    if blk.uses_msix() {
        c.write_str(", MSI-X");
    }

    // SAFETY: the interrupt path is up (the interrupt selftest ran), the disk's handler is
    // registered and its line enabled, and the scheduler's hook is not installed yet, so an
    // interrupt taken here returns to the reads.
    let run = unsafe { reads_by_interrupt(blk, true) };
    if run.report(c) {
        c.write_str(" ok");
        Check::Passed
    } else {
        Check::Failed
    }
}

/// The CPU the disk's interrupt is moved to, and back from.
const ROUTED_CPU: usize = 1;

/// The disk's interrupt, delivered to a CPU other than the one waiting for it.
///
/// Where the platform can move the interrupt — a message-signalled one, whose target CPU is
/// a field of the message — it is pointed at CPU 1, and the interrupt check's reads are made
/// again from the boot CPU with the boot CPU's interrupts left masked. A completion can then
/// be collected only by the handler running on CPU 1. The platform's per-CPU count must
/// show that every interrupt of the run was taken there and none on CPU 0. The interrupt is
/// moved back before the result is reported, pass or fail.
///
/// Skipped where the interrupt is a line, or there is one CPU; failed where QEMU was given a
/// second CPU that is not online, which would otherwise skip what it should prove.
pub fn cpu_check(c: &dyn EarlyConsole) -> Check {
    let Some(blk) = disk() else {
        c.write_str("skipped: no block device");
        return Check::Skipped;
    };
    let Some(line) = platform::block_line().filter(|l| platform::interrupt_is_msi(*l)) else {
        c.write_str("skipped: the disk's interrupt is not one the platform can move");
        return Check::Skipped;
    };
    if !platform::secondary_online(ROUTED_CPU) {
        if kconfig::SMP && kconfig::QEMU_CPUS > ROUTED_CPU {
            c.write_str("CPU 1 IS NOT ONLINE, THOUGH QEMU HAS IT");
            return Check::Failed;
        }
        c.write_str("skipped: no second CPU online");
        return Check::Skipped;
    }
    if let Err(why) = platform::route_interrupt(line, ROUTED_CPU) {
        c.write_str("LINE NOT ROUTED TO CPU 1: ");
        c.write_str(why);
        return Check::Failed;
    }
    c.write_str("line ");
    write_usize(c, line as usize);
    c.write_str(" to CPU 1");

    let taken = |cpu| platform::interrupts_on_cpu(line, cpu);
    let (boot_before, routed_before) = (taken(0), taken(ROUTED_CPU));
    // SAFETY: interrupts stay masked on this CPU, which is the point: the handler has to run
    // on the one the line was routed to.
    let run = unsafe { reads_by_interrupt(blk, false) };
    let (boot, routed) = (taken(0) - boot_before, taken(ROUTED_CPU) - routed_before);
    let back = platform::route_interrupt(line, 0);

    let mut ok = run.report(c);
    c.write_str("; taken on CPU 1: ");
    write_usize(c, routed as usize);
    c.write_str(", on CPU 0: ");
    write_usize(c, boot as usize);
    if routed == 0 || routed != run.interrupts {
        c.write_str(", NOT EVERY INTERRUPT WAS TAKEN ON CPU 1");
        ok = false;
    }
    if boot != 0 {
        c.write_str(", AN INTERRUPT WAS TAKEN ON CPU 0");
        ok = false;
    }
    if let Err(why) = back {
        c.write_str(", NOT ROUTED BACK TO CPU 0: ");
        c.write_str(why);
        ok = false;
    }
    if ok {
        c.write_str(" ok");
        Check::Passed
    } else {
        Check::Failed
    }
}

/// What a run of reads with completions collected only by the handler came to.
struct IrqRun {
    made: u64,
    by_interrupt: u64,
    interrupts: u64,
    polled: u64,
    failure: Option<&'static str>,
    leaked: bool,
}

impl IrqRun {
    /// Write the run's numbers, then whatever is wrong with it. Returns whether nothing is.
    fn report(&self, c: &dyn EarlyConsole) -> bool {
        c.write_str("; ");
        write_usize(c, self.made as usize);
        c.write_str(" requests, ");
        write_usize(c, self.by_interrupt as usize);
        c.write_str(" completions in ");
        write_usize(c, self.interrupts as usize);
        c.write_str(" interrupts, ");
        write_usize(c, self.polled as usize);
        c.write_str(" polled");

        if let Some(why) = self.failure {
            c.write_str(", ");
            c.write_str(why);
            return false;
        }
        if self.polled != 0 {
            c.write_str(", A COMPLETION WAS COLLECTED WITHOUT ITS INTERRUPT");
            return false;
        }
        if self.by_interrupt != self.made || self.interrupts == 0 {
            c.write_str(", NOT EVERY COMPLETION ARRIVED BY INTERRUPT");
            return false;
        }
        if self.leaked {
            c.write_str(", A REQUEST OR DESCRIPTOR LEAKED");
            return false;
        }
        true
    }
}

/// Make [`IRQ_REQUESTS`] reads with the driver in interrupt-driven mode, and count.
///
/// With `enable`, interrupts are enabled on this CPU for the reads and masked again after.
///
/// # Safety
/// With `enable`, the interrupt path must be up, the disk's handler registered and its
/// interrupt enabled, and an interrupt taken on this CPU must return here: the scheduler's
/// hook not yet installed.
unsafe fn reads_by_interrupt(blk: &VirtioBlk<Locks>, enable: bool) -> IrqRun {
    let (irqs_before, via_irq_before) = blk.interrupt_counts();
    let polled_before = blk.polled_completions();
    let (issued_before, _, _, _) = blk.counters();

    blk.set_interrupt_driven(true);
    if enable {
        // SAFETY: the caller's contract.
        unsafe { arch::tick::enable_interrupts() };
    }
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
    if enable {
        // Masked again for the rest of bring-up, which runs masked.
        let _ = Cpu::irq_save();
    }
    blk.set_interrupt_driven(false);

    let (irqs, via_irq) = blk.interrupt_counts();
    let (issued, completed, in_flight, clean) = blk.counters();
    IrqRun {
        made: issued - issued_before,
        by_interrupt: via_irq - via_irq_before,
        interrupts: irqs - irqs_before,
        polled: blk.polled_completions() - polled_before,
        failure,
        leaked: issued != completed || in_flight != 0 || !clean,
    }
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
        Error::VectorRefused { .. } => "the device refused its MSI-X vector",
    }
}

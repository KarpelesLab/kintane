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
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use arch::Cpu;
use block::{BlockDevice, Error as BlockError, testdisk};
use hal::{Arch, EarlyConsole, PhysAddr};
use mm::phys::FrameAllocator;
use virtio_blk::VirtioBlk;
use virtio_blk::mem::Dma;

use crate::{Check, Live, Locks, intx, iommu, timekeeping, write_usize};

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

/// The bound disks, each brought up by [`check`] over a grant of its own.
///
/// SAFETY INVARIANT: a slot is written only by [`check`], or by [`restart`] which clears it
/// first; in both cases before that slot's flag in `STARTED` is set, and it is read only
/// after that flag is set, through [`disk_at`].
static DISKS: [SyncUnsafeCell<Option<VirtioBlk<Locks>>>; virtio_blk::MAX_DISKS] =
    [const { SyncUnsafeCell::new(None) }; virtio_blk::MAX_DISKS];
static STARTED: [AtomicBool; virtio_blk::MAX_DISKS] =
    [const { AtomicBool::new(false) }; virtio_blk::MAX_DISKS];

/// Which bound disk carries the volumes.
///
/// Not assumed to be slot 0. A slot's number is the order the platform enumerated the devices
/// in, which need not be the order the run gave the drives — QEMU fills `virt`'s virtio-mmio
/// slots downwards as devices are created while enumeration walks the tree upwards — so
/// trusting the number would mount whichever disk happened to be enumerated first. [`check`]
/// reads each disk's header and records the slot whose header names the volume-carrying
/// image's length.
static PRIMARY: AtomicUsize = AtomicUsize::new(0);

/// The disk carrying the volumes: what the filesystem, the stress workload and the driver
/// domain all mean by "the disk".
pub fn disk() -> Option<&'static VirtioBlk<Locks>> {
    disk_at(primary())
}

/// Which slot [`disk`] is.
pub fn primary() -> usize {
    PRIMARY.load(Ordering::Acquire)
}

/// The started disk in slot `i`, once the check has brought it up.
pub fn disk_at(i: usize) -> Option<&'static VirtioBlk<Locks>> {
    if !STARTED.get(i)?.load(Ordering::Acquire) {
        return None;
    }
    // SAFETY: the slot's flag is set only after its one write, and nothing writes again
    // except `restart`, which clears the flag first.
    unsafe { (*DISKS.get(i)?.get()).as_ref() }
}

/// The DMA grant each disk runs on: the address the CPU reaches it at, the address the device
/// (and the IOMMU) uses, and its length. The block-domain check reuses exactly this — the
/// IOMMU already maps `[phys, phys + len)` for the device and nothing else — so a domain
/// serving the disk needs no second grant to confine.
///
/// SAFETY INVARIANT: a slot is written once by [`check`], before that slot's flag in
/// `STARTED`; read only after.
static GRANTS: [SyncUnsafeCell<Option<(usize, u64, usize)>>; virtio_blk::MAX_DISKS] =
    [const { SyncUnsafeCell::new(None) }; virtio_blk::MAX_DISKS];

/// `(virt, phys, len)` of the volume-carrying disk's DMA grant, once it is up.
#[cfg_attr(
    not(CONFIG_BLOCK_DOMAIN),
    expect(dead_code, reason = "read only by the block-domain check")
)]
pub fn grant() -> Option<(usize, u64, usize)> {
    grant_at(primary())
}

/// The same for the disk in slot `i`.
fn grant_at(i: usize) -> Option<(usize, u64, usize)> {
    // SAFETY: read after that slot's one write; `disk_at` gates on the flag set after it.
    disk_at(i).and(unsafe { *GRANTS.get(i)?.get() })
}

/// Whether a disk's interrupt is being forwarded to a driver domain instead of collected in
/// the kernel. Set around [`crate::blockdomain`]'s run.
static FORWARDING: [AtomicBool; virtio_blk::MAX_DISKS] =
    [const { AtomicBool::new(false) }; virtio_blk::MAX_DISKS];

/// Hand the volume-carrying disk's interrupt to the domain, or take it back. While
/// forwarding, the handler does not touch the in-kernel `VirtioBlk`, whose engine the domain
/// has reset out from under. Only that disk is served from a domain today, so only its slot
/// is forwarded; the other disk keeps collecting its own completions in the kernel.
#[cfg_attr(
    not(CONFIG_BLOCK_DOMAIN),
    expect(dead_code, reason = "set only by the block-domain check")
)]
pub fn forward_interrupts(on: bool) {
    if let Some(f) = FORWARDING.get(primary()) {
        f.store(on, Ordering::Release);
    }
}

/// A disk's interrupt handler, installed with `virtio_blk::set_handler`.
///
/// The device model's table holds a plain `fn()`, which cannot say which device fired, so
/// each slot is installed with a trampoline of its own from [`TRAMPOLINES`] and the slot is
/// what reaches the right device through [`disk_at`].
///
/// While a disk is served from a driver domain, the completion is the domain's to collect;
/// the handler forwards the interrupt to it as a message instead (see [`crate::blockdomain`]).
fn on_disk_interrupt(i: usize) {
    if FORWARDING.get(i).is_some_and(|f| f.load(Ordering::Acquire))
        && crate::blockdomain::forward_interrupt()
    {
        return;
    }
    if let Some(d) = disk_at(i)
        && d.on_interrupt()
    {
        return;
    }
    // Not this disk's, so try the others: a second PCI function on the same INTx line is
    // refused its own claim (`ClaimError::IrqTaken`) and therefore has no handler of its
    // own. Its status register is acknowledged only by a handler reaching *that* device, so
    // without this the line it shares stays asserted and the interrupt path is re-entered
    // for good the first time interrupts are unmasked.
    for j in 0..virtio_blk::MAX_DISKS {
        if j != i
            && let Some(d) = disk_at(j)
            && d.on_interrupt()
        {
            return;
        }
    }
}

fn on_disk_0() {
    on_disk_interrupt(0);
}

fn on_disk_1() {
    on_disk_interrupt(1);
}

/// One trampoline per slot, because the interrupt table holds a bare `fn()`.
const TRAMPOLINES: [fn(); virtio_blk::MAX_DISKS] = [on_disk_0, on_disk_1];

/// Reset the volume-carrying disk and bring a fresh in-kernel driver up over the same grant,
/// after a driver domain has run on it, so the stress run and the filesystem find a working
/// disk. `false` if the disk was never up or the fresh bring-up fails.
#[cfg_attr(
    not(CONFIG_BLOCK_DOMAIN),
    expect(dead_code, reason = "called only after the block-domain check")
)]
pub fn restart_in_kernel(c: &dyn EarlyConsole) -> bool {
    let i = primary();
    // SAFETY: read after that slot's one write, on the boot path.
    let Some((virt, phys, len)) = (unsafe { *GRANTS[i].get() }) else {
        return false;
    };
    let mut sector = [0u8; testdisk::SECTOR];
    restart(c, i, virt, phys, len, &mut sector)
}

/// Bring the disk up and check it.
pub fn check(c: &dyn EarlyConsole, frames: &mut FrameAllocator<'_, Cpu>, live: Live) -> Check {
    c.write_str("\n  block      ");
    if virtio_blk::window(0).is_none() {
        if kconfig::QEMU_BLOCK_TEST {
            c.write_str("NO VIRTIO-BLK DEVICE, though the run attached a disk");
            return Check::Failed;
        }
        c.write_str("skipped: no block device");
        return Check::Skipped;
    }
    // How many disks this boot bound, reported so a run that attached two and bound one is
    // visible here rather than only as a later check quietly skipping. What the machine
    // attaches varies by preset, so the count is reported, not asserted; the checks that need
    // two devices assert it themselves.
    write_usize(c, virtio_blk::bound());
    c.write_str(" disks bound; ");
    let Some(direct) = live.direct else {
        c.write_str("no kernel address space to map the device's memory through");
        return Check::Failed;
    };

    // Every bound disk is brought up, each over a grant of its own, before any of them is
    // checked: which one carries the volumes is not known until their headers are read, and
    // a slot's number is only the order the platform enumerated the devices in.
    let mut up = 0;
    let mut primary_grant = None;
    for i in 0..virtio_blk::bound().min(virtio_blk::MAX_DISKS) {
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

        // With an IOMMU, put the disk behind it *before* it does any DMA: a translation
        // domain that maps exactly this grant and nothing else. `iommu` does nothing on a
        // build without one, and there the disk's DMA reaches memory directly as before.
        //
        // One confinement, so one disk: the unit's translation is enabled for every device
        // behind it, and a second unconfined function would fault into the same log this
        // check reads. The IOMMU presets therefore attach a single drive, which is why this
        // is slot 0 rather than `i` — the loop runs once there.
        if kconfig::IOMMU {
            if !iommu::confine_disk(c, frames, direct, i, phys, len as u64) {
                return Check::Failed;
            }
            c.write_str("; ");
            // On MSI-X, the disk's interrupt goes through the IOMMU as well: its table
            // entry, not its message, then names the CPU, and only the disk may use it.
            if let Some(line) = platform::block_line(i).filter(|&l| platform::interrupt_is_msi(l)) {
                if !iommu::remap_disk_interrupt(c, frames, i, line) {
                    return Check::Failed;
                }
                c.write_str("; ");
            }
        }

        // SAFETY: the claimed window is mapped by the kernel's address space, which maps
        // every window a bound driver claimed, and this is the one transport made for it.
        let Some(transport) = (unsafe { virtio_blk::transport(i) }) else {
            c.write_str("the device's window is outside the address space");
            return Check::Failed;
        };
        // The queue on its MSI-X entry when that is how the platform wired this disk's
        // interrupt; on a line, or polled, bring-up needs to know nothing.
        let vector = virtio_blk::msix_entry(i)
            .filter(|_| platform::block_line(i).is_some_and(platform::interrupt_is_msi));
        let blk = match VirtioBlk::<Locks>::bring_up_with_vector(transport, dma, vector) {
            Ok(b) => b,
            Err(e) => {
                c.write_str("bring-up FAILED: ");
                c.write_str(bring_up_error(e));
                return Check::Failed;
            }
        };

        let geometry = blk.geometry();
        // The confinement above already ended with "; " for this disk, so a second separator
        // would read as an empty field. Without an IOMMU nothing was written and the disks'
        // geometries are a list.
        if i > 0 && !kconfig::IOMMU {
            c.write_str(", ");
        }
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
        // SAFETY: the one write to this slot, before its flag makes it readable.
        unsafe { *DISKS[i].get() = Some(blk) };
        // The grant this disk runs on, for the block-domain check to reuse: written before
        // the flag, and read only through `grant_at`, which gates on it.
        // SAFETY: the one write, on the boot path before the flag.
        unsafe { *GRANTS[i].get() = Some((virt.raw(), phys, len)) };
        STARTED[i].store(true, Ordering::Release);
        // SAFETY: once per slot, on the boot path, before any interrupt can be delivered for
        // the line: interrupts are masked here, and the first request is submitted below.
        let _ = unsafe { virtio_blk::set_handler(i, TRAMPOLINES[i]) };
        // A disk whose line another device already holds is refused its own claim, so the
        // platform wires nothing for it and it has no handler. Say so here: it is the
        // difference between a disk that is polled by design and one whose completions
        // nothing will ever acknowledge.
        if virtio_blk::irq_refused(i) {
            c.write_str("; disk ");
            write_usize(c, i);
            c.write_str(" SHARES A HELD LINE, serviced through its holder");
        }
        if disk_at(i).is_none() {
            c.write_str("; the disk could not be read back after it was stored");
            return Check::Failed;
        }
        up += 1;
        if primary_grant.is_none() {
            primary_grant = Some((virt.raw(), phys, len));
        }
    }
    if up == 0 {
        c.write_str("NO DISK CAME UP");
        return Check::Failed;
    }

    // Which disk carries the volumes, by its header rather than by its slot number. Each
    // image's header names its own length, so the volume-carrying one identifies itself; a
    // machine whose enumeration order differs from the order the drives were given would
    // otherwise mount whichever disk happened to come first.
    if !choose_primary(c, &mut primary_grant) {
        return Check::Failed;
    }

    let Some(blk) = disk() else {
        c.write_str("; the volume's disk could not be read back");
        return Check::Failed;
    };
    let Some((virt, phys, len)) = primary_grant else {
        c.write_str("; the volume's disk has no grant");
        return Check::Failed;
    };

    // SAFETY: the one borrow of `BUF`; see its invariant.
    let buf = unsafe { &mut *BUF.get() };
    let mut ok = run_checks(c, blk, buf);
    // With the IOMMU on, prove the confinement: an out-of-grant DMA is stopped and logged,
    // and the device restarts and serves again. `blk` is re-fetched inside, because a
    // restart replaces the stored device.
    if ok && kconfig::IOMMU {
        ok = iommu_checks(c, frames, direct, virt, phys, len, buf);
    }
    // With a second disk bound, what having two devices is *for*: that one device's binding
    // reaches only its own disk, and behind an IOMMU that one device's fault is its own.
    if ok && virtio_blk::bound() > 1 {
        ok = two_device_checks(c, frames, direct, buf);
    }
    if ok {
        c.write_str(" ok");
        Check::Passed
    } else {
        Check::Failed
    }
}

/// The sector the two-disk checks read through each device. Below the scratch area, so it is
/// the pattern on both disks and neither check can be satisfied by something a write left.
const PROBE_LBA: u64 = 7;

/// Which *image* the disk in slot `i` carries, which is what its bytes are keyed by.
///
/// Not the slot number. `choose_primary` has already read each disk's header and recorded which
/// slot holds the volumes, so the volume's disk is image 0 and the only other bound disk is
/// image [`testdisk::DISK2`]. On PCI the two numberings agree, because enumeration follows the
/// order the drives were attached; on virtio-mmio they do not, because QEMU fills the slots
/// downwards and the volume's disk lands in the higher one. Keying by slot reads the right bytes
/// on one port and the wrong ones on the other, which is a check that passes where it is written
/// and fails where it is needed.
fn image_of(slot: usize) -> usize {
    if slot == primary() {
        0
    } else {
        testdisk::DISK2
    }
}

/// The slot of a bound disk that is not the volume's, if there is one.
fn other_disk() -> Option<usize> {
    (0..virtio_blk::MAX_DISKS).find(|&i| i != primary() && disk_at(i).is_some())
}

/// What two bound devices make checkable, and one device could not.
///
/// 1. **Each binding reaches its own disk.** The same sector is read through each device and must
///    hold *that disk's* pattern: the images differ in almost every byte ([`pattern_on`] folds the
///    image's index into the hash), so a read served by the wrong device is caught by content
///    rather than by trusting the binding that served it. Without this, a driver that bound one
///    device and read through another would pass every other check here.
/// 2. **A fault is attributed to the device that caused it.** Behind an IOMMU, the *second* disk is
///    pointed at a page outside its own grant. The unit's log is shared, so proving it was stopped
///    is not enough: the fault must name that disk's source id and not the other's.
/// 3. **A fault in one device leaves the other serving.** After the second disk's DMA is stopped,
///    the volume's disk must still read its own data — the devices fail apart.
///
/// [`pattern_on`]: testdisk::pattern_on
fn two_device_checks(
    c: &dyn EarlyConsole,
    frames: &mut FrameAllocator<'_, Cpu>,
    direct: mm::DirectMap,
    buf: &mut [u8],
) -> bool {
    let Some(other) = other_disk() else {
        return true;
    };
    c.write_str("\n  two disks  ");

    // 1. Each device's binding reaches its own disk, proved by content.
    let sector = &mut buf[..testdisk::SECTOR];
    for i in [primary(), other] {
        let Some(blk) = disk_at(i) else {
            c.write_str("A BOUND DISK WENT AWAY");
            return false;
        };
        if blk.read_blocks(PROBE_LBA, sector).is_err() {
            c.write_str("A DISK WOULD NOT SERVE THE READ");
            return false;
        }
        if let Some(at) = testdisk::first_mismatch_on(image_of(i), PROBE_LBA, sector) {
            c.write_str("DISK ");
            write_usize(c, i);
            c.write_str(" DID NOT READ BACK ITS OWN PATTERN, FIRST AT BYTE ");
            write_usize(c, at);
            return false;
        }
        // And it is not the *other* disk's bytes: the two images must actually differ here, or
        // reading through the wrong binding would have passed the check above.
        let twin = if i == primary() { other } else { primary() };
        if testdisk::first_mismatch_on(image_of(twin), PROBE_LBA, sector).is_none() {
            c.write_str("THE TWO DISKS' SECTORS ARE INDISTINGUISHABLE");
            return false;
        }
    }
    c.write_str("each device read its own disk's sector");

    second_disk_confined(c, frames, direct, buf, other)
}

/// Without an IOMMU nothing confines either device, so there is nothing here to check — and
/// none of the code that would check it is built.
///
/// A `#[cfg]` on the item, not on a branch inside one: `kconfig::IOMMU` is a runtime constant,
/// so an `if` on it still links the canary frame, the deliberate DMA and their reporting into
/// images that can never run them. That cost the i686 presets the whole of their remaining
/// 4,096 bytes and hung them at boot.
#[cfg(not(CONFIG_IOMMU))]
fn second_disk_confined(
    _c: &dyn EarlyConsole,
    _frames: &mut FrameAllocator<'_, Cpu>,
    _direct: mm::DirectMap,
    _buf: &mut [u8],
    _other: usize,
) -> bool {
    true
}

/// Behind an IOMMU: the second disk's fault is its own, and the first disk survives it.
#[cfg(CONFIG_IOMMU)]
fn second_disk_confined(
    c: &dyn EarlyConsole,
    frames: &mut FrameAllocator<'_, Cpu>,
    direct: mm::DirectMap,
    buf: &mut [u8],
    other: usize,
) -> bool {
    // 2. The second disk's own rogue DMA, attributed to the second disk.
    let Ok(canary) = frames.alloc_frame() else {
        c.write_str("; NO CANARY FRAME");
        return false;
    };
    let cphys = canary.start().raw();
    let Ok(cvirt) = direct.to_virt(PhysAddr::new(cphys)) else {
        c.write_str("; CANARY OUTSIDE THE DIRECT MAP");
        return false;
    };
    let cp = cvirt.raw() as *mut u8;
    const SENTINEL: u8 = 0xa5;
    for i in 0..testdisk::SECTOR {
        // SAFETY: `cp` is the canary frame through the direct map, a whole page; writing a
        // sector of it is in bounds. Volatile, because the device may write it behind us.
        unsafe { cp.add(i).write_volatile(SENTINEL) };
    }
    if iommu::domain_maps(other, cphys) {
        c.write_str("; THE SECOND DISK'S DOMAIN ALREADY MAPS THE CANARY");
        return false;
    }
    // Drain first, so the fault read below is the one this check caused.
    while iommu::take_fault().is_some() {}

    let Some(second) = disk_at(other) else {
        c.write_str("; THE SECOND DISK WENT AWAY");
        return false;
    };
    let completed = second.dma_probe(0, cphys, testdisk::SECTOR as u32, ROGUE_POLLS);
    let fault = iommu::take_fault();
    let mut untouched = true;
    for i in 0..testdisk::SECTOR {
        // SAFETY: as the fill above.
        if unsafe { cp.add(i).read_volatile() } != SENTINEL {
            untouched = false;
            break;
        }
    }
    let mine = iommu::source_of(other);
    let theirs = iommu::source_of(primary());
    let stopped = match fault {
        Some(f) if f.address == cphys && f.write && Some(f.source_id) == mine => {
            c.write_str("; the second disk's out-of-grant DMA stopped, fault from ");
            write_hex(c, u64::from(f.source_id));
            true
        }
        Some(f) if f.address == cphys && Some(f.source_id) == theirs => {
            c.write_str("; THE FAULT NAMES THE OTHER DISK: ");
            write_hex(c, u64::from(f.source_id));
            false
        }
        Some(f) => {
            c.write_str("; A FAULT AT ");
            write_hex(c, f.address);
            c.write_str(" BUT NOT THE SECOND DISK'S");
            false
        }
        None => {
            let _ = completed;
            c.write_str("; THE SECOND DISK'S ROGUE DMA WAS NOT STOPPED");
            false
        }
    };
    if !untouched {
        c.write_str("; THE CANARY WAS OVERWRITTEN");
    }
    if mine == theirs {
        c.write_str("; BOTH DISKS HAVE THE SAME SOURCE ID");
        return false;
    }

    // 3. The other device is undisturbed: the volume's disk still reads its own data.
    let Some(blk) = disk_at(primary()) else {
        c.write_str("; THE VOLUME'S DISK WENT AWAY WITH THE OTHER'S FAULT");
        return false;
    };
    let sector = &mut buf[..testdisk::SECTOR];
    if blk.read_blocks(PROBE_LBA, sector).is_err()
        || testdisk::first_mismatch_on(image_of(primary()), PROBE_LBA, sector).is_some()
    {
        c.write_str("; THE OTHER DISK STOPPED SERVING AFTER ITS NEIGHBOUR FAULTED");
        return false;
    }
    c.write_str("; the volume's disk served on through it");
    stopped && untouched
}

/// Record which bound disk carries the volumes, by reading each one's header, and set
/// `primary_grant` to that disk's grant.
///
/// The volume-carrying image's header names [`testdisk::SECTORS`]; the second disk's names
/// its own, shorter length. So the disks identify themselves and nothing here trusts a slot
/// number. With one disk this chooses it and says nothing, leaving the single-drive path
/// exactly as it was.
fn choose_primary(c: &dyn EarlyConsole, primary_grant: &mut Option<(usize, u64, usize)>) -> bool {
    let mut sector = [0u8; testdisk::SECTOR];
    let mut found = None;
    for i in 0..virtio_blk::MAX_DISKS {
        let Some(blk) = disk_at(i) else { continue };
        if blk.read_blocks(0, &mut sector).is_err() {
            continue;
        }
        if testdisk::header(&sector) == Some(testdisk::SECTORS) {
            found = Some(i);
            break;
        }
    }
    match found {
        Some(i) => {
            PRIMARY.store(i, Ordering::Release);
            *primary_grant = grant_at(i);
            if i != 0 {
                c.write_str("; the volume is on disk ");
                write_usize(c, i);
            }
            true
        }
        None if kconfig::QEMU_BLOCK_TEST => {
            c.write_str("; NO BOUND DISK CARRIES THE TEST DISK'S HEADER");
            false
        }
        // Without the test disk attached there is no header to match, and slot 0 stands.
        None => true,
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

    // A translation the device has used, taken away while it runs. The canary is mapped into the
    // domain and the device reads a sector into it; then it is unmapped with the flush the unit
    // needs. The unit caches what the device translated, so without that flush the rogue DMA
    // below would reach the canary through the translation it used a moment ago.
    if !iommu::grant_page(frames, primary(), cphys) {
        c.write_str("\n  iommu      THE CANARY COULD NOT BE MAPPED FOR THE DEVICE");
        return false;
    }
    let used = blk.dma_probe(0, cphys, testdisk::SECTOR as u32, ROGUE_POLLS);
    let mut arrived = [0u8; testdisk::SECTOR];
    for (i, b) in arrived.iter_mut().enumerate() {
        // SAFETY: as the fill above.
        *b = unsafe { cp.add(i).read_volatile() };
    }
    if !used || testdisk::header(&arrived) != Some(testdisk::SECTORS) {
        c.write_str("\n  iommu      A READ INTO A PAGE MAPPED FOR THE DEVICE DID NOT ARRIVE");
        return false;
    }
    if !iommu::revoke_page(primary(), cphys) {
        c.write_str("\n  iommu      THE CANARY COULD NOT BE UNMAPPED AND FLUSHED");
        return false;
    }
    for i in 0..testdisk::SECTOR {
        // SAFETY: as the fill above.
        unsafe { cp.add(i).write_volatile(SENTINEL) };
    }

    // The grant must translate and the canary must not: the domain maps exactly the grant.
    if !iommu::domain_maps(primary(), phys) || iommu::domain_maps(primary(), cphys) {
        c.write_str("\n  iommu      THE DOMAIN DOES NOT MAP EXACTLY THE GRANT");
        return false;
    }

    // Drain what the log already holds, so the fault read below is the one this check caused.
    // The log is the unit's and every device behind it records there: a second disk faults
    // once as it is brought up behind its own domain — stopped, as it should be — and that
    // record would otherwise be the one this check reads and reject as "not the rogue one".
    while iommu::take_fault().is_some() {}

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

    c.write_str("\n  iommu      in-grant DMA served behind VT-d; a page the device used was unmapped and flushed");
    // Stopped is not enough: the fault must name *this* device. The log is the unit's and every
    // device behind it records there, so a fault matched only by address would be satisfied by
    // another device's fault at the same page — which is the thing a second confined device
    // makes possible.
    let expected = iommu::source_of(primary());
    let stopped = match fault {
        Some(f) if f.address == cphys && f.write && Some(f.source_id) == expected => {
            c.write_str("; out-of-grant DMA stopped at ");
            write_hex(c, f.address);
            c.write_str(" from ");
            write_hex(c, u64::from(f.source_id));
            true
        }
        Some(f) if f.address == cphys && f.write => {
            c.write_str("; THE ROGUE DMA WAS STOPPED BUT THE FAULT NAMES ANOTHER DEVICE: ");
            write_hex(c, u64::from(f.source_id));
            false
        }
        Some(f) => {
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
    let served = restart(c, primary(), virt, phys, len, buf);
    stopped && untouched && served
}

/// Reset the device after the fault and bring a fresh one up over the same DMA grant and
/// window, then prove it serves a read. Replaces the stored device.
fn restart(
    c: &dyn EarlyConsole,
    i: usize,
    virt: usize,
    phys: u64,
    len: usize,
    buf: &mut [u8],
) -> bool {
    // SAFETY: the single-threaded boot path. The old device is dropped before the new one is
    // built, so the DMA region and the register window have exactly one owner at a time; the
    // new bring-up resets the device (status 0) and re-lays the queue, discarding the faulted
    // request. `virt`/`phys`/`len` are the same region `check` mapped, still direct-mapped.
    unsafe { *DISKS[i].get() = None };
    STARTED[i].store(false, Ordering::Release);
    let dma = unsafe { Dma::new(virt, phys, len) };
    let Some(transport) = (unsafe { virtio_blk::transport(i) }) else {
        c.write_str("; NO TRANSPORT ON RESTART");
        return false;
    };
    // Keep the disk on its MSI-X vector across the restart: the device reset forgot the queue
    // vector, but the platform's MSI-X table entry still stands, so bring-up sets the vector
    // again. Otherwise the restarted disk would drop to polling and the block-irq check fail.
    let vector = virtio_blk::msix_entry(i)
        .filter(|_| platform::block_line(i).is_some_and(platform::interrupt_is_msi));
    let blk = match VirtioBlk::<Locks>::bring_up_with_vector(transport, dma, vector) {
        Ok(b) => b,
        Err(e) => {
            c.write_str("; RESTART BRING-UP FAILED: ");
            c.write_str(bring_up_error(e));
            return false;
        }
    };
    // SAFETY: the one write to this slot after the old one was cleared, before its flag.
    unsafe { *DISKS[i].get() = Some(blk) };
    STARTED[i].store(true, Ordering::Release);
    let Some(blk) = disk_at(i) else {
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
    // QEMU's virtio-blk-pci has an MSI-X table unless it was started with `vectors=0`. On a
    // platform that delivers messages, a test disk whose function has one and came up on
    // anything else fell back somewhere; one whose function has none must be on its pin,
    // routed through `_PRT`. Falling back to polling would turn this check and the next into
    // skips where they should have measured.
    let pin = platform::block_line(primary()).and_then(intx::pin_route);
    if kconfig::QEMU_BLOCK_TEST && platform::delivers_msi() && !blk.uses_msix() {
        if intx::block_has_msix(primary()) {
            c.write_str("THE DISK IS NOT ON MSI-X, THOUGH QEMU'S FUNCTION HAS IT");
            return Check::Failed;
        }
        if pin.is_none() {
            c.write_str("THE DISK HAS NO MSI-X AND IS NOT ON ITS PIN THROUGH _PRT");
            return Check::Failed;
        }
    }
    let Some(line) = platform::block_line(primary()) else {
        c.write_str("skipped: the disk is polled, no interrupt route on this port");
        return Check::Skipped;
    };
    c.write_str("line ");
    write_usize(c, line as usize);
    if blk.uses_msix() {
        c.write_str(", MSI-X");
    }
    if let Some(route) = pin {
        c.write_str(", INTx on GSI ");
        write_usize(c, route.gsi as usize);
        c.write_str(if route.level { " level" } else { " edge" });
        c.write_str(if route.active_low {
            " active low"
        } else {
            " active high"
        });
        // The entry as the I/O APIC holds it, read back: the line's vector, the boot CPU,
        // unmasked, and the trigger and polarity the route gave.
        if let Err(why) = intx::check_pin_entry(line) {
            c.write_str(": ");
            c.write_str(why);
            return Check::Failed;
        }
        // What QEMU's q35 wires a PCI pin to: GSI 16 to 23, level-triggered, active high. A
        // wrong polarity still delivers under QEMU, whose I/O APIC ignores it, so this is
        // where an interpreter or route that got it wrong is caught. A wrong GSI in that range
        // is caught by the reads below, which time out.
        let qemu = (16..=23).contains(&route.gsi) && route.level && !route.active_low;
        if kconfig::QEMU_BLOCK_TEST && !qemu {
            c.write_str(": NOT THE ROUTE QEMU'S Q35 GIVES A PCI PIN");
            return Check::Failed;
        }
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

/// Spins an interrupt that did not arrive is waited for, with interrupts enabled, after its
/// request completed by polling. Far above what a delivered interrupt takes under QEMU.
const BLOCKED_SPINS: u32 = 2_000_000;

/// Interrupt remapping, proved on the disk, where an IOMMU remaps it (`IOMMU`, on MSI-X).
///
/// The disk's MSI-X entry must hold a remappable message naming its table entry, and the entry
/// must be present, for the disk, on the line's vector, to the boot CPU. Then, with interrupts
/// enabled:
///
/// 1. every read by interrupt completes: the remapped message is delivered;
/// 2. with the entry not present, and then present for another function, a read completes by
///    polling, its interrupt never arrives, and the fault log names the disk and the entry: an
///    interrupt the table does not remap, and one from a function it does not name, are blocked and
///    logged;
/// 3. with the entry delivering to x2APIC ID 256, which no CPU here has, the interrupt does not
///    arrive either. Cut to eight bits, the ID would be the boot CPU's 0, which would take it; so
///    the destination is carried whole, as only a remapped interrupt can carry it;
/// 4. restored, every read by interrupt completes again.
/// Changes [`remap_check`] makes to the disk's entry while remapping is on: absent, another
/// function's and a wide destination, each followed by a restore.
const ENTRY_CHANGES: u64 = 6;

/// Entry changes [`remap_check`] times, to report what one flush costs.
const FLUSH_SAMPLES: u64 = 256;

pub fn remap_check(c: &dyn EarlyConsole) -> Check {
    if !kconfig::IOMMU {
        c.write_str("skipped: no IOMMU in this build");
        return Check::Skipped;
    }
    let Some(blk) = disk() else {
        c.write_str("skipped: no block device");
        return Check::Skipped;
    };
    let Some(line) = platform::block_line(primary()).filter(|&l| platform::interrupt_is_msi(l))
    else {
        c.write_str("THE DISK IS NOT ON MSI-X, SO NOTHING IS REMAPPED");
        return Check::Failed;
    };
    let extended = match iommu::check_disk_interrupt(primary(), line) {
        Ok(extended) => extended,
        Err(why) => {
            c.write_str(why);
            return Check::Failed;
        }
    };
    c.write_str("remappable MSI-X through entry 0");
    let queue_before = iommu::invalidation_stats();
    // SAFETY: as `interrupt_check`, which ran before this: the interrupt path is up, the disk's
    // handler registered and its interrupt enabled, and the tick's hook not installed.
    let delivered = unsafe { reads_by_interrupt(blk, true) };
    if !delivered.report(c) {
        return Check::Failed;
    }
    while iommu::take_fault().is_some() {}

    let blocked = [
        (iommu::Tamper::Absent, "; entry absent: "),
        (iommu::Tamper::ForeignSource, "; entry for another function: "),
    ];
    for (how, what) in blocked {
        c.write_str(what);
        if !blocked_and_logged(c, blk, how) {
            let _ = iommu::tamper_disk_interrupt(primary(), iommu::Tamper::Restore);
            return Check::Failed;
        }
    }

    c.write_str("; entry to x2APIC ID 256: ");
    if !extended {
        c.write_str("NO EXTENDED INTERRUPT MODE, SO NO DESTINATION ABOVE 255");
        return Check::Failed;
    }
    if !iommu::tamper_disk_interrupt(primary(), iommu::Tamper::WideDestination) {
        c.write_str("THE ENTRY DID NOT TAKE THE DESTINATION");
        return Check::Failed;
    }
    // SAFETY: as above.
    let taken = unsafe { interrupts_during_polled_read(blk) };
    let _ = iommu::tamper_disk_interrupt(primary(), iommu::Tamper::Restore);
    while iommu::take_fault().is_some() {}
    match taken {
        Ok(0) => c.write_str("not taken by the boot CPU"),
        Ok(_) => {
            c.write_str("DELIVERED TO THE BOOT CPU: THE DESTINATION WAS CUT TO EIGHT BITS");
            return Check::Failed;
        }
        Err(why) => {
            c.write_str(why);
            return Check::Failed;
        }
    }

    // Each tamper and each restore changed the entry in use, and the unit must have completed a
    // flush for every one. QEMU keeps no entry cache that would show a missed flush stale, so
    // what a guest can check is that each was queued and the unit wrote its wait's status; the
    // host tests' model shows the stale entry itself.
    let flushed = iommu::invalidation_stats()
        .zip(queue_before)
        .map(|(after, before)| {
            (after.invalidations - before.invalidations, after.waits - before.waits)
        });
    match flushed {
        Some((flushes, waits)) if flushes >= ENTRY_CHANGES && waits >= ENTRY_CHANGES => {
            c.write_str("; ");
            write_usize(c, flushes as usize);
            c.write_str(" entry-cache flushes completed in ");
            write_usize(c, waits as usize);
            c.write_str(" waits");
        }
        _ => {
            c.write_str("; AN ENTRY CHANGED IN USE WAS NOT FLUSHED");
            return Check::Failed;
        }
    }

    // What a flush costs: the entry rewritten to the same CPU and its cache invalidated through
    // the queue, the wait included, averaged over several.
    c.write_str("; ");
    let flushes_from = timekeeping::now();
    for _ in 0..FLUSH_SAMPLES {
        if let Err(why) = iommu::route_disk_interrupt(primary(), line, 0) {
            c.write_str("; ");
            c.write_str(why);
            return Check::Failed;
        }
    }
    let flushes_ns = timekeeping::now()
        .saturating_duration_since(flushes_from)
        .as_nanos();
    write_usize(c, FLUSH_SAMPLES as usize);
    if flushes_ns == 0 {
        c.write_str(" entry changes flushed below the boot clock's resolution");
    } else {
        c.write_str(" entry changes flushed in ");
        write_usize(c, (flushes_ns / FLUSH_SAMPLES) as usize);
        c.write_str(" ns each");
    }
    if let Some(stats) = iommu::invalidation_stats() {
        c.write_str(" (longest wait ");
        write_usize(c, stats.longest_wait as usize);
        c.write_str(" status reads)");
    }

    c.write_str("; restored");
    // SAFETY: as above.
    let restored = unsafe { reads_by_interrupt(blk, true) };
    if restored.report(c) {
        c.write_str(" ok");
        Check::Passed
    } else {
        Check::Failed
    }
}

/// With the disk's table entry changed as `how` says, a read that completes by polling must
/// take no interrupt, and the fault log must hold an interrupt-remapping fault from the disk
/// for entry 0. The entry is restored afterwards.
fn blocked_and_logged(c: &dyn EarlyConsole, blk: &VirtioBlk<Locks>, how: iommu::Tamper) -> bool {
    let i = primary();
    if !iommu::tamper_disk_interrupt(i, how) {
        c.write_str("THE ENTRY COULD NOT BE CHANGED");
        return false;
    }
    // SAFETY: as `remap_check`'s.
    let taken = unsafe { interrupts_during_polled_read(blk) };
    let fault = iommu::take_fault();
    let restored = iommu::tamper_disk_interrupt(i, iommu::Tamper::Restore);
    while iommu::take_fault().is_some() {}
    match taken {
        Ok(0) => c.write_str("blocked"),
        Ok(_) => {
            c.write_str("THE INTERRUPT WAS DELIVERED");
            return false;
        }
        Err(why) => {
            c.write_str(why);
            return false;
        }
    }
    let source = iommu::source_of(i);
    match fault {
        Some(f) if Some(f.source_id) == source && f.interrupt_index() == Some(i as u16) => {
            c.write_str(", fault ");
            write_hex(c, u64::from(f.reason));
            c.write_str(" from ");
            write_hex(c, u64::from(f.source_id));
        }
        Some(f) => {
            c.write_str(", A FAULT THAT IS NOT THE DISK'S ENTRY: REASON ");
            write_hex(c, u64::from(f.reason));
            return false;
        }
        None => {
            c.write_str(", BUT NOT LOGGED");
            return false;
        }
    }
    if !restored {
        c.write_str("; THE ENTRY COULD NOT BE RESTORED");
    }
    restored
}

/// One read that completes by polling, with interrupts enabled throughout and for
/// [`BLOCKED_SPINS`] after, and how many disk interrupts were taken meanwhile.
///
/// # Safety
/// As [`reads_by_interrupt`] with `enable`.
unsafe fn interrupts_during_polled_read(blk: &VirtioBlk<Locks>) -> Result<u64, &'static str> {
    let (before, _) = blk.interrupt_counts();
    blk.set_interrupt_driven(false);
    // SAFETY: the caller's contract.
    unsafe { arch::tick::enable_interrupts() };
    let mut sector = [0u8; testdisk::SECTOR];
    let read = blk.read_blocks(1, &mut sector);
    for _ in 0..BLOCKED_SPINS {
        core::hint::spin_loop();
    }
    let _ = Cpu::irq_save();
    let (after, _) = blk.interrupt_counts();
    match read {
        Ok(()) if testdisk::first_mismatch(1, &sector).is_none() => Ok(after - before),
        Ok(()) => Err("A POLLED READ DID NOT HOLD THE PATTERN"),
        Err(_) => Err("A POLLED READ FAILED"),
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
    let Some(line) = platform::block_line(primary()).filter(|l| platform::interrupt_is_msi(*l))
    else {
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
    // A remapped interrupt goes where its table entry says, so the entry is changed, with its cache
    // flushed; any other message-signalled interrupt is moved in its MSI-X entry.
    let remapped = iommu::disk_interrupt_remapped(primary());
    let route = |cpu| {
        if remapped {
            iommu::route_disk_interrupt(primary(), line, cpu)
        } else {
            platform::route_interrupt(line, cpu)
        }
    };
    if let Err(why) = route(ROUTED_CPU) {
        c.write_str("LINE NOT ROUTED TO CPU 1: ");
        c.write_str(why);
        return Check::Failed;
    }
    c.write_str("line ");
    write_usize(c, line as usize);
    c.write_str(if remapped {
        " to CPU 1 through its remapping entry"
    } else {
        " to CPU 1"
    });

    let taken = |cpu| platform::interrupts_on_cpu(line, cpu);
    let (boot_before, routed_before) = (taken(0), taken(ROUTED_CPU));
    // SAFETY: interrupts stay masked on this CPU, which is the point: the handler has to run
    // on the one the line was routed to.
    let run = unsafe { reads_by_interrupt(blk, false) };
    let (boot, routed) = (taken(0) - boot_before, taken(ROUTED_CPU) - routed_before);
    let back = route(0);

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

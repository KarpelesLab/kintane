//! Programming the machine's IOMMU to confine each disk's DMA (only with `IOMMU`).
//!
//! A disk is the one kind of device here that reads and writes memory on its own, so it is the
//! one whose reach an IOMMU has to bound. This builds a VT-d translation domain per disk that
//! maps *exactly* the DMA buffer the block check granted that device — the rings, the request
//! headers, the bounce buffers — and nothing else, points the device's context entry at it, and
//! turns translation on. From then on every address a device names in a descriptor is looked up
//! in its own domain; one it does not hold faults in the hardware, and the fault record names
//! the device that caused it.
//!
//! One [`Unit`], many domains. Translation, the root table and the invalidation queue belong to
//! the hardware unit rather than to any device, and a second `Unit` over the same registers
//! would be two drivers for one piece of hardware — so the unit is made once and each device
//! gets a domain under it. The interrupt remapping table is shared the same way: one table,
//! latched once, with an entry per device.
//!
//! The three traits `drivers/iommu/vtd` is written over are given bodies here, and this is where
//! the `unsafe` they abstract lives: [`UnitRegs`] over the unit's register window, [`Mem`] over
//! the direct map, and [`Pool`] over the boot frame allocator. The page tables and the frames
//! they take are never freed — the hardware walks them for as long as the kernel runs, exactly
//! as the DMA buffers themselves are never freed.

use core::cell::SyncUnsafeCell;

use ::iommu::{Fault, QueueStats};
use arch::Cpu;
use hal::{EarlyConsole, PhysAddr};
use mm::DirectMap;
use mm::phys::FrameAllocator;
use vtd::{Domain, Frames, InterruptTable, Irte, Perm, PhysMem, Regs, Unit};

use crate::write_usize;

/// The unit's registers, reached through the kernel's device window.
#[derive(Clone, Copy)]
struct UnitRegs {
    /// The register base's virtual address, `hal::paging::device_virt(register_base)`.
    base: usize,
}

impl UnitRegs {
    fn at(&self, offset: usize) -> *mut u8 {
        core::ptr::with_exposed_provenance_mut(self.base + offset)
    }
}

#[allow(unsafe_code)]
impl Regs for UnitRegs {
    fn read32(&self, offset: usize) -> u32 {
        // SAFETY: `base` is the unit's register window, mapped as device memory by the kernel
        // address space (`platform` recorded it among the device windows), and `offset` is one
        // of the fixed register offsets, all inside the 4 KiB window. Volatile: these registers
        // have side effects and change under the driver.
        unsafe { self.at(offset).cast::<u32>().read_volatile() }
    }
    fn read64(&self, offset: usize) -> u64 {
        // SAFETY: as `read32`.
        unsafe { self.at(offset).cast::<u64>().read_volatile() }
    }
    fn write32(&self, offset: usize, value: u32) {
        // SAFETY: as `read32`.
        unsafe { self.at(offset).cast::<u32>().write_volatile(value) }
    }
    fn write64(&self, offset: usize, value: u64) {
        // SAFETY: as `read32`.
        unsafe { self.at(offset).cast::<u64>().write_volatile(value) }
    }
}

/// The physical memory the hardware's tables live in, reached through the direct map.
#[derive(Clone, Copy)]
struct Mem {
    direct: DirectMap,
}

impl Mem {
    fn ptr(&self, phys: u64) -> Option<*mut u64> {
        self.direct
            .ptr_to_phys(PhysAddr::new(phys))
            .ok()
            .map(|p| p.as_ptr().cast::<u64>())
    }
}

#[allow(unsafe_code)]
impl PhysMem for Mem {
    fn read64(&self, phys: u64) -> u64 {
        // SAFETY: the table frames come from the frame allocator, so they are RAM the direct
        // map covers; a table entry is a whole aligned `u64`. Zero for an address outside the
        // map, which cannot happen for a frame this driver allocated.
        match self.ptr(phys) {
            Some(p) => unsafe { p.read_volatile() },
            None => 0,
        }
    }
    fn write64(&self, phys: u64, value: u64) {
        // SAFETY: as `read64`. Volatile, because the reader is the IOMMU through another view
        // of the same memory.
        if let Some(p) = self.ptr(phys) {
            unsafe { p.write_volatile(value) }
        }
    }
}

/// The boot frame allocator, as a source of page-table frames. Borrowed for the length of
/// bring-up; the frames it hands out are never given back.
struct Pool<'a, 'b> {
    frames: &'a mut FrameAllocator<'b, Cpu>,
}

impl Frames for Pool<'_, '_> {
    fn alloc(&mut self) -> Option<u64> {
        self.frames.alloc_frame().ok().map(|f| f.start().raw())
    }
}

/// One confined device: the domain its DMA is translated through, the source id the hardware
/// knows it by, and the remapping entry its interrupt is delivered through once
/// [`remap_disk_interrupt`] has set one.
struct Device {
    domain: Domain,
    source: u16,
    irte: Option<Irte>,
}

/// The unit and the devices confined behind it, outliving bring-up so the fault log can be read
/// and the domains audited after the devices have run.
struct Iommu {
    unit: Unit<UnitRegs, Mem>,
    /// The interrupt remapping table, shared: one table for the unit, one entry per device.
    table: Option<InterruptTable>,
    devices: [Option<Device>; virtio_blk::MAX_DISKS],
}

/// SAFETY INVARIANT: written only by [`confine_disk`] and [`remap_disk_interrupt`] on the
/// single-threaded boot path, and read only after.
static IOMMU: SyncUnsafeCell<Option<Iommu>> = SyncUnsafeCell::new(None);

/// The remapping table entry a disk's interrupt is delivered through: one per slot, so a
/// message naming another slot's entry is a message for another device.
fn handle(i: usize) -> u16 {
    i as u16
}

/// The domain id a slot's devices get. Zero is reserved by the hardware for "no domain", so
/// slots count from one.
fn domain_id(i: usize) -> u16 {
    1 + i as u16
}

/// The unit, if one has been brought up.
fn iommu() -> Option<&'static mut Iommu> {
    // SAFETY: the boot thread is the only reader and writer; see the invariant on `IOMMU`.
    unsafe { (*IOMMU.get()).as_mut() }
}

/// Slot `i`'s confined device, if it has one.
fn device(i: usize) -> Option<&'static mut Device> {
    iommu()?.devices.get_mut(i)?.as_mut()
}

/// The source id slot `i`'s device was attached with: the name the hardware knows it by, and
/// what a fault must carry for the fault to be that device's.
pub fn source_of(i: usize) -> Option<u16> {
    device(i).map(|d| d.source)
}

/// Put the disk in slot `i` behind the IOMMU: a domain of its own mapping exactly
/// `[dma_phys, dma_phys + dma_len)`, the device attached to it, translation on. Returns whether
/// it was done — `false` when the machine has no IOMMU or a step failed, which the caller
/// reports and treats as fatal only on a build that asked for one.
///
/// The unit itself is brought up by the first call and shared by the rest: a second `Unit` over
/// one register window would be two drivers for one piece of hardware.
pub fn confine_disk(
    c: &dyn EarlyConsole,
    frames: &mut FrameAllocator<'_, Cpu>,
    direct: DirectMap,
    i: usize,
    dma_phys: u64,
    dma_len: u64,
) -> bool {
    if i >= virtio_blk::MAX_DISKS {
        c.write_str("no IOMMU slot for that disk");
        return false;
    }
    let Some(source) = platform::block_source_id(i) else {
        c.write_str("the disk has no PCI source id for the IOMMU to name it by");
        return false;
    };
    let first = iommu().is_none();
    if first {
        let Some(facts) = platform::iommu() else {
            c.write_str("no IOMMU on this machine");
            return false;
        };
        let Some(base) = hal::paging::device_virt(facts.register_base) else {
            c.write_str("the IOMMU register window is outside the device window");
            return false;
        };
        let mem = Mem { direct };
        let mut pool = Pool { frames };
        let unit = match Unit::new(UnitRegs { base }, mem, &mut pool) {
            Ok(u) => u,
            Err(_) => {
                c.write_str("the IOMMU did not bring up");
                return false;
            }
        };
        c.write_str("VT-d on, ");
        write_usize(c, facts.host_address_width as usize);
        c.write_str("-bit");
        // SAFETY: the one write creating the unit, on the boot path before anything reads it.
        unsafe {
            *IOMMU.get() = Some(Iommu {
                unit,
                table: None,
                devices: [const { None }; virtio_blk::MAX_DISKS],
            });
        }
    }
    let Some(iommu) = iommu() else {
        c.write_str("the IOMMU could not be read back after it was brought up");
        return false;
    };
    let mut pool = Pool { frames };
    let domain = match iommu.unit.new_domain(domain_id(i), &mut pool) {
        Ok(d) => d,
        Err(_) => {
            c.write_str("; no frame for the disk's IOMMU domain");
            return false;
        }
    };
    // Map exactly the granted DMA buffer, at an I/O virtual address equal to its physical one:
    // the driver puts physical addresses in descriptors, and the device treats them as device
    // addresses (VIRTIO_F_ACCESS_PLATFORM), so identity here is what makes the rings resolve.
    if domain
        .map(dma_phys, dma_phys, dma_len, Perm::ReadWrite, iommu.unit.mem(), &mut pool)
        .is_err()
    {
        c.write_str("; the disk's DMA grant could not be mapped into its IOMMU domain");
        return false;
    }
    if iommu.unit.attach(source, &domain, &mut pool).is_err() {
        c.write_str("; the disk could not be attached to its IOMMU domain");
        return false;
    }
    if first {
        if iommu.unit.enable().is_err() {
            c.write_str("; the IOMMU did not enable translation");
            return false;
        }
        // The queue next, before anything changes an entry the unit may have cached: every flush
        // from here goes through it and waits for the unit to say it is done.
        if iommu.unit.enable_queued_invalidation(&mut pool).is_err() {
            c.write_str("; the IOMMU did not turn its invalidation queue on");
            return false;
        }
    }
    c.write_str("; disk ");
    write_source(c, source);
    c.write_str(" mapped to its grant only");
    if first {
        c.write_str(", invalidation queued");
    }
    if let Some(slot) = iommu.devices.get_mut(i) {
        *slot = Some(Device {
            domain,
            source,
            irte: None,
        });
    }
    true
}

/// Whether slot `i`'s domain maps `iova`, for the report: that device's grant should translate
/// and an address one page past it should not — and so should another device's grant, which is
/// what makes the domains separate rather than merely present.
pub fn domain_maps(i: usize, iova: u64) -> bool {
    let Some(iommu) = iommu() else {
        return false;
    };
    let mem = iommu.unit.mem();
    let Some(Some(d)) = iommu.devices.get(i) else {
        return false;
    };
    d.domain.translate(iova, mem).is_some()
}

/// The next fault the unit recorded.
///
/// The fault carries the source id of the device that caused it ([`Fault::source_id`]), which is
/// what lets a caller say *which* device was stopped rather than only that something was. The
/// log is the unit's and so is shared by every device behind it.
pub fn take_fault() -> Option<Fault> {
    iommu()?.unit.take_fault()
}

/// How [`tamper_disk_interrupt`] changes a disk's table entry, for the checks that the entry
/// is what decides whether and where the disk's interrupt is delivered.
#[derive(Clone, Copy)]
pub enum Tamper {
    /// Not present: the disk's messages name an entry that does not exist.
    Absent,
    /// Present, but for another function: the disk is not the requester the entry accepts.
    ForeignSource,
    /// Present, for the disk, delivering to x2APIC ID 256, which no CPU here has. Cut to the
    /// eight bits a compatibility-format message holds, it would be the boot CPU's ID 0.
    WideDestination,
    /// Back to what [`remap_disk_interrupt`] set.
    Restore,
}

/// Remap slot `i`'s MSI-X interrupt on `line` through the IOMMU confining it: a remapping table
/// whose entry `i` delivers the line's vector to the boot CPU and accepts only that disk,
/// remapping turned on, and the disk's MSI-X entry rewritten to a remappable message naming that
/// entry. Returns whether it was done.
///
/// After [`confine_disk`], and before the device raises an interrupt: the device is not brought
/// up yet. The table is made and latched by the first call and shared by the rest, so a second
/// device adds an entry rather than a table. Compatibility-format interrupts — the I/O APIC's,
/// and other functions' MSI-X — are left as the unit's reset state has them.
pub fn remap_disk_interrupt(
    c: &dyn EarlyConsole,
    frames: &mut FrameAllocator<'_, Cpu>,
    i: usize,
    line: u32,
) -> bool {
    let Some(iommu) = iommu() else {
        c.write_str("no IOMMU to remap the disk's interrupt through");
        return false;
    };
    let Some(Some(source)) = iommu.devices.get(i).map(|d| d.as_ref().map(|d| d.source)) else {
        c.write_str("that disk is not confined, so its interrupt cannot be remapped");
        return false;
    };
    let Some((vector, destination)) = platform::message_target(line, 0) else {
        c.write_str("the disk's line names no vector on the boot CPU");
        return false;
    };
    let mut pool = Pool { frames };
    let fresh = iommu.table.is_none();
    if fresh {
        match iommu.unit.new_interrupt_table(&mut pool) {
            Ok(t) => iommu.table = Some(t),
            Err(_) => {
                c.write_str("the IOMMU cannot remap interrupts");
                return false;
            }
        }
    }
    let Some(table) = iommu.table.as_ref() else {
        return false;
    };
    let entry = Irte {
        vector,
        destination,
        level: false,
        source,
    };
    // The entry first, then the table latched if it is new: an entry set before remapping is on
    // needs no invalidation queue, and one set after it does.
    if iommu.unit.set_irte(table, handle(i), Some(entry)).is_err() {
        c.write_str("the disk's remapping entry did not take");
        return false;
    }
    if fresh && iommu.unit.enable_interrupt_remapping(table).is_err() {
        c.write_str("interrupt remapping did not enable");
        return false;
    }
    let extended = table.extended();
    let (address, data) = vtd::remappable_message(handle(i));
    if let Err(why) = platform::set_line_message(line, address, data) {
        c.write_str("the disk's MSI-X entry did not take its remappable message: ");
        c.write_str(why);
        return false;
    }
    if fresh {
        c.write_str("interrupts remapped, ");
        c.write_str(if extended {
            "32-bit destinations"
        } else {
            "8-bit destinations"
        });
    } else {
        c.write_str("a second interrupt remapped");
    }
    if let Some(Some(d)) = iommu.devices.get_mut(i) {
        d.irte = Some(entry);
    }
    true
}

/// Check slot `i`'s interrupt as remapping delivers it: its MSI-X entry holds a
/// remappable-format message naming that slot's entry, remapping is on, and the entry is
/// present, for that disk, on the line's vector, to the boot CPU. Returns whether the table's
/// destinations are 32 bits wide.
pub fn check_disk_interrupt(i: usize, line: u32) -> Result<bool, &'static str> {
    let iommu = iommu().ok_or("NO IOMMU CONFINES THE DISK")?;
    let table = iommu
        .table
        .as_ref()
        .ok_or("THE DISK'S INTERRUPT IS NOT REMAPPED")?;
    let Some(Some(d)) = iommu.devices.get(i) else {
        return Err("THAT DISK IS NOT CONFINED");
    };
    let set = d.irte.ok_or("THE DISK'S INTERRUPT IS NOT REMAPPED")?;
    let source = d.source;
    let (address, _) =
        platform::line_message(line).ok_or("THE DISK'S MSI-X ENTRY IS UNREADABLE")?;
    match vtd::message_handle(address) {
        Some(h) if h == handle(i) => {}
        Some(_) => return Err("THE DISK'S MESSAGE NAMES ANOTHER TABLE ENTRY"),
        None => return Err("THE DISK'S MESSAGE IS NOT IN REMAPPABLE FORMAT"),
    }
    if !iommu.unit.interrupt_remapping_enabled() {
        return Err("INTERRUPT REMAPPING IS OFF");
    }
    if iommu.unit.irte(table, handle(i)) != Some(set) {
        return Err("THE TABLE ENTRY IS NOT WHAT WAS SET");
    }
    let target = platform::message_target(line, 0).ok_or("THE LINE NAMES NO VECTOR")?;
    if (set.vector, set.destination) != target || set.source != source {
        return Err("THE TABLE ENTRY IS NOT THE DISK'S, FOR ITS LINE ON THE BOOT CPU");
    }
    Ok(table.extended())
}

/// Change slot `i`'s table entry as `how` says. `false` when there is no entry to change, or
/// when the table's mode cannot hold the change.
pub fn tamper_disk_interrupt(i: usize, how: Tamper) -> bool {
    let Some(iommu) = iommu() else {
        return false;
    };
    let Some(table) = iommu.table.as_ref() else {
        return false;
    };
    let Some(Some(d)) = iommu.devices.get(i) else {
        return false;
    };
    let Some(set) = d.irte else {
        return false;
    };
    let entry = match how {
        Tamper::Absent => None,
        // Function 1 of the disk's device, which does not exist.
        Tamper::ForeignSource => Some(Irte {
            source: d.source ^ 1,
            ..set
        }),
        Tamper::WideDestination => Some(Irte {
            destination: 0x100,
            ..set
        }),
        Tamper::Restore => Some(set),
    };
    iommu.unit.set_irte(table, handle(i), entry).is_ok()
}

/// Map the page at `phys` into slot `i`'s domain, at the same device address, while the disk
/// runs: for the check that has the device use a page and then takes it away. `false` without
/// an IOMMU, or when the map fails.
pub fn grant_page(frames: &mut FrameAllocator<'_, Cpu>, i: usize, phys: u64) -> bool {
    let Some(iommu) = iommu() else {
        return false;
    };
    let Some(Some(domain)) = iommu.devices.get(i).map(|d| d.as_ref().map(|d| d.domain)) else {
        return false;
    };
    let mut pool = Pool { frames };
    iommu
        .unit
        .map_in_use(&domain, phys, phys, vtd::PAGE_SIZE, Perm::ReadWrite, &mut pool)
        .is_ok()
}

/// Unmap the page [`grant_page`] mapped from slot `i`'s domain, and flush the translation the
/// device may have cached of it, returning once the unit says it is gone.
pub fn revoke_page(i: usize, phys: u64) -> bool {
    let Some(iommu) = iommu() else {
        return false;
    };
    let Some(Some(domain)) = iommu.devices.get(i).map(|d| d.as_ref().map(|d| d.domain)) else {
        return false;
    };
    iommu
        .unit
        .unmap_in_use(&domain, phys, vtd::PAGE_SIZE)
        .is_ok()
}

/// Whether slot `i`'s interrupt goes through a remapping table entry, so that the entry, not
/// the MSI-X message, names its CPU.
pub fn disk_interrupt_remapped(i: usize) -> bool {
    device(i).is_some_and(|d| d.irte.is_some())
}

/// Deliver slot `i`'s remapped interrupt on `line` to CPU `cpu` from its next message on: the
/// table entry's destination becomes that CPU's APIC ID, and the entry cache is flushed before
/// this returns, so no message after it is delivered by the old entry.
pub fn route_disk_interrupt(i: usize, line: u32, cpu: usize) -> Result<(), &'static str> {
    let iommu = iommu().ok_or("NO IOMMU CONFINES THE DISK")?;
    let table = iommu
        .table
        .as_ref()
        .ok_or("THE DISK'S INTERRUPT IS NOT REMAPPED")?;
    let Some(Some(d)) = iommu.devices.get(i) else {
        return Err("THAT DISK IS NOT CONFINED");
    };
    let set = d.irte.ok_or("THE DISK'S INTERRUPT IS NOT REMAPPED")?;
    let (vector, destination) =
        platform::message_target(line, cpu).ok_or("THAT CPU HAS NO APIC ID TO NAME")?;
    let entry = Irte {
        vector,
        destination,
        ..set
    };
    iommu
        .unit
        .set_irte(table, handle(i), Some(entry))
        .map_err(|_| "THE TABLE ENTRY DID NOT TAKE THE CPU, OR ITS CACHE WAS NOT FLUSHED")?;
    if let Some(Some(d)) = iommu.devices.get_mut(i) {
        d.irte = Some(entry);
    }
    Ok(())
}

/// What the unit's invalidation queue has completed since it was turned on. The queue is the
/// unit's, shared by every device behind it.
pub fn invalidation_stats() -> Option<QueueStats> {
    iommu().map(|iommu| iommu.unit.queue_stats())
}

fn write_source(c: &dyn EarlyConsole, source: u16) {
    // A source id as bus:dev.fn, the way lspci names it.
    write_hex_byte(c, (source >> 8) as u8);
    c.write_str(":");
    write_hex_byte(c, ((source >> 3) & 0x1f) as u8);
    c.write_str(".");
    write_usize(c, (source & 0x7) as usize);
}

fn write_hex_byte(c: &dyn EarlyConsole, b: u8) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    c.write_bytes(&[HEX[(b >> 4) as usize], HEX[(b & 0xf) as usize]]);
}

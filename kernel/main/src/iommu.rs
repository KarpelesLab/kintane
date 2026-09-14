//! Programming the machine's IOMMU to confine the disk's DMA (only with `IOMMU`).
//!
//! The disk is the one device here that reads and writes memory on its own, so it is the one
//! whose reach an IOMMU has to bound. This builds a VT-d translation domain that maps *exactly*
//! the DMA buffer the block check granted the device — the rings, the request headers, the
//! bounce buffers — and nothing else, points the device's context entry at it, and turns
//! translation on. From then on every address the device names in a descriptor is looked up in
//! that domain; one it does not hold faults in the hardware.
//!
//! The three traits `drivers/iommu/vtd` is written over are given bodies here, and this is where
//! the `unsafe` they abstract lives: [`UnitRegs`] over the unit's register window, [`Mem`] over
//! the direct map, and [`Pool`] over the boot frame allocator. The page tables and the frames
//! they take are never freed — the hardware walks them for as long as the kernel runs, exactly
//! as the DMA buffer itself is never freed.

use core::cell::SyncUnsafeCell;

use arch::Cpu;
use hal::{EarlyConsole, PhysAddr};
use mm::DirectMap;
use mm::phys::FrameAllocator;
use vtd::{Domain, Fault, Frames, InterruptTable, Irte, Perm, PhysMem, Regs, Unit};

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

/// The confinement that outlives bring-up: the unit and the disk's domain, so the fault log
/// can be read and the domain audited after the device has run.
struct Confinement {
    unit: Unit<UnitRegs, Mem>,
    domain: Domain,
    source: u16,
    /// The interrupt remapping table and the entry the disk's MSI-X interrupt was given,
    /// once [`remap_disk_interrupt`] has put it there.
    interrupts: Option<(InterruptTable, Irte)>,
}

/// SAFETY INVARIANT: written once by [`confine_disk`] on the boot path, read only after.
static CONFINEMENT: SyncUnsafeCell<Option<Confinement>> = SyncUnsafeCell::new(None);

/// Put the disk behind the IOMMU: a domain mapping exactly `[dma_phys, dma_phys + dma_len)`,
/// the device attached to it, translation on. Returns whether it was done — `false` when the
/// machine has no IOMMU or a step failed, which the caller reports and treats as fatal only
/// on a build that asked for one.
pub fn confine_disk(
    c: &dyn EarlyConsole,
    frames: &mut FrameAllocator<'_, Cpu>,
    direct: DirectMap,
    dma_phys: u64,
    dma_len: u64,
) -> bool {
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
    let mut unit = match Unit::new(UnitRegs { base }, mem, &mut pool) {
        Ok(u) => u,
        Err(_) => {
            c.write_str("the IOMMU did not bring up");
            return false;
        }
    };
    let domain = match unit.new_domain(1, &mut pool) {
        Ok(d) => d,
        Err(_) => {
            c.write_str("no frame for the disk's IOMMU domain");
            return false;
        }
    };
    // Map exactly the granted DMA buffer, at an I/O virtual address equal to its physical one:
    // the driver puts physical addresses in descriptors, and the device treats them as device
    // addresses (VIRTIO_F_ACCESS_PLATFORM), so identity here is what makes the rings resolve.
    if domain
        .map(dma_phys, dma_phys, dma_len, Perm::ReadWrite, unit.mem(), &mut pool)
        .is_err()
    {
        c.write_str("the disk's DMA grant could not be mapped into its IOMMU domain");
        return false;
    }
    if unit
        .attach(facts.block_source_id, &domain, &mut pool)
        .is_err()
    {
        c.write_str("the disk could not be attached to its IOMMU domain");
        return false;
    }
    if unit.enable().is_err() {
        c.write_str("the IOMMU did not enable translation");
        return false;
    }
    c.write_str("VT-d on, ");
    write_usize(c, facts.host_address_width as usize);
    c.write_str("-bit; disk ");
    write_source(c, facts.block_source_id);
    c.write_str(" mapped to its grant only");
    // SAFETY: the one write, on the single-threaded boot path, before anything reads it.
    unsafe {
        *CONFINEMENT.get() = Some(Confinement {
            unit,
            domain,
            source: facts.block_source_id,
            interrupts: None,
        });
    }
    true
}

/// Whether the disk's domain maps `iova`, for the report: the grant should translate and an
/// address one page past it should not.
pub fn domain_maps(iova: u64) -> bool {
    // SAFETY: read after `confine_disk`'s one write; the boot thread is the only reader.
    let Some(conf) = (unsafe { (*CONFINEMENT.get()).as_ref() }) else {
        return false;
    };
    conf.domain.translate(iova, conf.unit.mem()).is_some()
}

/// The next fault the unit recorded, and the source id the disk was attached with (so the
/// caller can check the fault names the disk).
pub fn take_fault() -> Option<(Fault, u16)> {
    // SAFETY: as `domain_maps`; the boot thread is the only reader and writer.
    let conf = unsafe { (*CONFINEMENT.get()).as_mut() }?;
    conf.unit.take_fault().map(|f| (f, conf.source))
}

/// The remapping table entry the disk's MSI-X interrupt is delivered through.
const DISK_HANDLE: u16 = 0;

/// How [`tamper_disk_interrupt`] changes the disk's table entry, for the checks that the entry
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

/// Remap the disk's MSI-X interrupt on `line` through the IOMMU confining it: a remapping
/// table whose entry 0 delivers the line's vector to the boot CPU and accepts only the disk,
/// remapping turned on, and the disk's MSI-X entry rewritten to a remappable message naming
/// that entry. Returns whether it was done.
///
/// After [`confine_disk`], and before the device raises an interrupt: the device is not
/// brought up yet. Compatibility-format interrupts — the I/O APIC's, and other functions'
/// MSI-X — are left as the unit's reset state has them.
pub fn remap_disk_interrupt(
    c: &dyn EarlyConsole,
    frames: &mut FrameAllocator<'_, Cpu>,
    line: u32,
) -> bool {
    // SAFETY: after `confine_disk`'s one write; the boot thread is the only reader and writer.
    let Some(conf) = (unsafe { (*CONFINEMENT.get()).as_mut() }) else {
        c.write_str("no IOMMU to remap the disk's interrupt through");
        return false;
    };
    let Some((vector, destination)) = platform::message_target(line, 0) else {
        c.write_str("the disk's line names no vector on the boot CPU");
        return false;
    };
    let mut pool = Pool { frames };
    let table = match conf.unit.new_interrupt_table(&mut pool) {
        Ok(t) => t,
        Err(_) => {
            c.write_str("the IOMMU cannot remap interrupts");
            return false;
        }
    };
    let entry = Irte {
        vector,
        destination,
        level: false,
        source: conf.source,
    };
    let enabled = conf.unit.set_irte(&table, DISK_HANDLE, Some(entry)).is_ok()
        && conf.unit.enable_interrupt_remapping(&table).is_ok();
    if !enabled {
        c.write_str("interrupt remapping did not enable");
        return false;
    }
    let (address, data) = vtd::remappable_message(DISK_HANDLE);
    if let Err(why) = platform::set_line_message(line, address, data) {
        c.write_str("the disk's MSI-X entry did not take its remappable message: ");
        c.write_str(why);
        return false;
    }
    c.write_str("interrupts remapped, ");
    c.write_str(if table.extended() {
        "32-bit destinations"
    } else {
        "8-bit destinations"
    });
    conf.interrupts = Some((table, entry));
    true
}

/// Check the disk's interrupt as remapping delivers it: its MSI-X entry holds a
/// remappable-format message naming entry 0, remapping is on, and the entry is present, for
/// the disk, on the line's vector, to the boot CPU. Returns whether the table's destinations
/// are 32 bits wide.
pub fn check_disk_interrupt(line: u32) -> Result<bool, &'static str> {
    // SAFETY: as `domain_maps`; the boot thread is the only reader and writer.
    let conf = unsafe { (*CONFINEMENT.get()).as_ref() }.ok_or("NO IOMMU CONFINES THE DISK")?;
    let (table, set) = conf
        .interrupts
        .as_ref()
        .ok_or("THE DISK'S INTERRUPT IS NOT REMAPPED")?;
    let (address, _) =
        platform::line_message(line).ok_or("THE DISK'S MSI-X ENTRY IS UNREADABLE")?;
    match vtd::message_handle(address) {
        Some(DISK_HANDLE) => {}
        Some(_) => return Err("THE DISK'S MESSAGE NAMES ANOTHER TABLE ENTRY"),
        None => return Err("THE DISK'S MESSAGE IS NOT IN REMAPPABLE FORMAT"),
    }
    if !conf.unit.interrupt_remapping_enabled() {
        return Err("INTERRUPT REMAPPING IS OFF");
    }
    if conf.unit.irte(table, DISK_HANDLE) != Some(*set) {
        return Err("THE TABLE ENTRY IS NOT WHAT WAS SET");
    }
    let target = platform::message_target(line, 0).ok_or("THE LINE NAMES NO VECTOR")?;
    if (set.vector, set.destination) != target || set.source != conf.source {
        return Err("THE TABLE ENTRY IS NOT THE DISK'S, FOR ITS LINE ON THE BOOT CPU");
    }
    Ok(table.extended())
}

/// Change the disk's table entry as `how` says. `false` when there is no entry to change, or
/// when the table's mode cannot hold the change.
pub fn tamper_disk_interrupt(how: Tamper) -> bool {
    // SAFETY: as `domain_maps`; the boot thread is the only reader and writer.
    let Some(conf) = (unsafe { (*CONFINEMENT.get()).as_mut() }) else {
        return false;
    };
    let Confinement {
        unit,
        source,
        interrupts: Some((table, set)),
        ..
    } = conf
    else {
        return false;
    };
    let entry = match how {
        Tamper::Absent => None,
        // Function 1 of the disk's device, which does not exist.
        Tamper::ForeignSource => Some(Irte {
            source: *source ^ 1,
            ..*set
        }),
        Tamper::WideDestination => Some(Irte {
            destination: 0x100,
            ..*set
        }),
        Tamper::Restore => Some(*set),
    };
    unit.set_irte(table, DISK_HANDLE, entry).is_ok()
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

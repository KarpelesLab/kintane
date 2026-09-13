//! `platform` for PCs: ACPI tables and PCI enumeration into the device model.
//!
//! One of the units providing this name, alongside `kernel/platform/fdt`; see there for
//! the two questions boot asks a platform and why discovery comes first. On a PC the
//! answers come from two places:
//!
//! 1. **ACPI.** The RSDP comes from the loader when there is one that records it (`kinboot-efi`),
//!    and otherwise from the BIOS areas. The MADT gives the processors, the local APIC and the I/O
//!    APICs. The MCFG gives the PCI Express configuration windows.
//! 2. **PCI.** Enumerated through ECAM when the MCFG describes it, and through configuration
//!    mechanism #1 otherwise, which is what QEMU's `pc` machine has.
//!
//! Every function becomes a node under its host bridge or behind its bridge. Every MADT
//! device and configuration window becomes a node too. Drivers bind to all of them the
//! way they bind on aarch64. The drivers here are placeholders that claim a window and
//! drive nothing: nothing uses the APICs yet, but claiming their windows now is what
//! makes the kernel address space map them, so the SMP work that drives them starts from
//! a mapped window instead of a constant.
//!
//! # Discovery runs on the boot identity map
//!
//! Tables, the BIOS area and the ECAM window are read at their physical addresses,
//! through the four gigabytes the boot page tables map (`arch::pc::BOOT_IDENTITY_END`).
//! A table or window above that is reported as unreachable, never guessed at.
//!
//! # What discovery checks
//!
//! Always:
//! - every table it reads has a valid checksum and length;
//! - every PCI BAR and decode bit it sized reads back as it was ([`pci::verify_restored`]);
//! - every driver bound and claimed without overlap.
//!
//! With `QEMU_PCI_TEST_DEVICE`, which only QEMU presets set, also what QEMU's machines are
//! known to be:
//! - the host bridge at `00:00.0` is the Q35 MCH when there is an MCFG, and the i440FX otherwise;
//! - the MADT lists exactly `QEMU_CPUS` enabled processors;
//! - `pci-testdev` was found behind a bridge, with its 4 KiB memory BAR and 256-byte I/O BAR sized
//!   exactly.

#![no_std]
#![feature(sync_unsafe_cell)]

use core::cell::SyncUnsafeCell;

use acpi::{EcamSegment, Madt, MadtEntry, Mcfg, PhysMemory, ProcessorFlags, Rsdp, Tables};
use device::driver::{self, best_match};
use device::pci::{self, Address, Bar, ConfigSpace, Function};
use device::table::Kind;
use device::{
    BootCell, Bound, Builder, Described, DeviceTree, Driver, IrqClaim, MmioClaim, Node, NodeId,
    Origin, Probe, ProbeError, Resources,
};
use hal::EarlyConsole;
use hal::paging::DeviceWindow;

/// PCI functions modelled. QEMU's q35 has about ten; a desktop board a few dozen.
const MAX_FUNCTIONS: usize = 128;
/// Described devices: processors, APICs, configuration windows, and the `cpus` group.
const MAX_DESCRIBED: usize = 72;
const MAX_NODES: usize = 1 + MAX_DESCRIBED + MAX_FUNCTIONS;
/// Windows and interrupts bound drivers may claim between them.
const MAX_CLAIMS: usize = 16;
/// Devices bound at once.
const MAX_BOUND: usize = 16;

/// How much of an APIC's register space is claimed. Linux reserves the same: the
/// registers a driver uses are within the first KiB, and a whole page is mapped anyway.
const APIC_WINDOW: u64 = 0x400;

/// `pci-testdev`, QEMU's PCI test device, and the host bridges QEMU's PC machines have.
const QEMU_TESTDEV: (u16, u16) = (0x1b36, 0x0005);
const Q35_MCH: (u16, u16) = (0x8086, 0x29c0);
const I440FX: (u16, u16) = (0x8086, 0x1237);

/// SAFETY INVARIANT: every static below is borrowed mutably exactly once, by
/// [`discover`], which runs once on the single-threaded boot path. Nothing reads them
/// after it returns except through [`WINDOWS`], which is a copy.
static FUNCTIONS: SyncUnsafeCell<[Function; MAX_FUNCTIONS]> =
    SyncUnsafeCell::new([Function::EMPTY; MAX_FUNCTIONS]);
static DESCRIBED: SyncUnsafeCell<[Described; MAX_DESCRIBED]> =
    SyncUnsafeCell::new([Described::EMPTY; MAX_DESCRIBED]);
static NODES: SyncUnsafeCell<[Node<'static>; MAX_NODES]> =
    SyncUnsafeCell::new([Node::EMPTY; MAX_NODES]);
static MMIO: SyncUnsafeCell<[Option<MmioClaim>; MAX_CLAIMS]> =
    SyncUnsafeCell::new([None; MAX_CLAIMS]);
static IRQS: SyncUnsafeCell<[Option<IrqClaim>; MAX_CLAIMS]> =
    SyncUnsafeCell::new([None; MAX_CLAIMS]);

/// What the address space maps, set by [`discover`].
static WINDOWS: BootCell<([DeviceWindow; MAX_CLAIMS], usize)> = BootCell::new();

/// Where this platform's devices come from, for the banner.
pub const SOURCE: &str = "ACPI and PCI";

/// A placeholder driver: claims the node's first window, and drives nothing.
struct Reserve {
    name: &'static str,
    compatible: &'static [&'static str],
    what: &'static str,
}

impl Driver for Reserve {
    fn name(&self) -> &'static str {
        self.name
    }

    fn compatible(&self) -> &'static [&'static str] {
        self.compatible
    }

    fn probe(&self, probe: &mut Probe<'_, '_, '_, '_>) -> Result<(), ProbeError> {
        probe.claim_mmio(0, self.what)?;
        Ok(())
    }

    fn start(&self, _bound: &Bound) -> Result<(), &'static str> {
        Ok(())
    }
}

static LOCAL_APIC: Reserve = Reserve {
    name: "local-apic",
    compatible: &["acpi,local-apic"],
    what: "local APIC",
};
static IO_APIC: Reserve = Reserve {
    name: "io-apic",
    compatible: &["acpi,io-apic"],
    what: "I/O APIC",
};
static ECAM: Reserve = Reserve {
    name: "ecam",
    compatible: &["pci-host-ecam-generic"],
    what: "PCI Express configuration space",
};

/// Every driver this image carries.
static DRIVERS: [&dyn Driver; 3] = [&LOCAL_APIC, &IO_APIC, &ECAM];

/// Physical memory through the boot identity map.
///
/// Constructed only inside [`discover`], whose contract is that the boot identity map
/// is live, which is what `boot_physical` requires; that is what makes the safe trait
/// method sound.
struct BootMemory(());

impl PhysMemory for BootMemory {
    fn bytes(&self, address: u64, len: usize) -> Option<&[u8]> {
        // SAFETY: a `BootMemory` exists only during `discover`, on the boot identity map,
        // and firmware tables are not written while the kernel reads them.
        unsafe { arch::pc::boot_physical(address, len) }
    }
}

/// Memory-mapped configuration space for one segment, through the boot identity map.
///
/// Constructed only inside [`discover`], for a segment it checked lies below
/// `BOOT_IDENTITY_END`.
struct Ecam(EcamSegment);

impl Ecam {
    fn register(&self, at: Address, offset: u16) -> Option<*mut u32> {
        if offset % 4 != 0 || u64::from(offset) >= EcamSegment::FUNCTION_BYTES {
            return None;
        }
        let base = self.0.function_address(at.bus, at.device, at.function)?;
        let address = usize::try_from(base.checked_add(u64::from(offset))?).ok()?;
        Some(core::ptr::with_exposed_provenance_mut(address))
    }
}

impl ConfigSpace for Ecam {
    fn read(&self, at: Address, offset: u16) -> u32 {
        match self.register(at, offset) {
            // SAFETY: an aligned register inside the segment's window, which `discover`
            // checked is identity-mapped while an `Ecam` exists. Reading configuration
            // space has no side effects on the standard header fields enumeration reads.
            Some(p) => unsafe { core::ptr::read_volatile(p) },
            None => u32::MAX,
        }
    }

    fn write(&self, at: Address, offset: u16, value: u32) {
        if let Some(p) = self.register(at, offset) {
            // SAFETY: as for `read`; what the write does is the enumerator's to know.
            unsafe { core::ptr::write_volatile(p, value) }
        }
    }
}

/// Configuration mechanism #1: the two I/O ports.
///
/// Constructed only inside [`discover`], on one CPU with interrupts masked, which is what
/// the port functions require.
struct Ports(());

impl ConfigSpace for Ports {
    fn read(&self, at: Address, offset: u16) -> u32 {
        let Ok(offset) = u8::try_from(offset) else {
            return u32::MAX;
        };
        // SAFETY: a `Ports` exists only during `discover`, single-threaded with interrupts
        // masked, so nothing else uses the ports between the select and the read.
        unsafe { arch::pc::config_read(at.bus, at.device, at.function, offset) }
    }

    fn write(&self, at: Address, offset: u16, value: u32) {
        let Ok(offset) = u8::try_from(offset) else {
            return;
        };
        // SAFETY: as for `read`.
        unsafe { arch::pc::config_write(at.bus, at.device, at.function, offset, value) }
    }
}

/// Records written into caller storage, counted.
struct Records<'s> {
    slots: &'s mut [Described],
    len: usize,
    /// Set when a record did not fit or could not be made.
    overflowed: bool,
}

impl Records<'_> {
    /// Store `record` and return its index.
    fn push(&mut self, record: Option<Described>) -> Option<usize> {
        match (record, self.slots.get_mut(self.len)) {
            (Some(r), Some(slot)) => {
                *slot = r;
                self.len += 1;
                Some(self.len - 1)
            }
            _ => {
                self.overflowed = true;
                None
            }
        }
    }
}

/// Read the ACPI tables, enumerate PCI, bind drivers, and run the checks above.
///
/// Returns whether every check passed. `Some(false)` leaves [`device_windows`] empty,
/// so the kernel space is not built on a half-understood machine.
///
/// # Safety
/// Called once, from `kmain`, with interrupts masked, on the boot identity map, with
/// `boot_arg` as the boot code passed it: `bootinfo::acpi_rsdp`'s contract, plus
/// single-threaded boot for the statics and the configuration ports.
pub unsafe fn discover(c: &dyn EarlyConsole, boot_arg: u64) -> Option<bool> {
    let mem = BootMemory(());

    // SAFETY: the caller passes `boot_arg` as the boot code left it, on the identity map.
    let from_loader = unsafe { bootinfo::acpi_rsdp(boot_arg) };
    let rsdp = match from_loader {
        Some(address) => Rsdp::read(&mem, address),
        None => Rsdp::find_bios(&mem),
    };
    let tables = match rsdp.and_then(|r| Tables::new(&mem, r)) {
        Ok(t) => t,
        Err(e) => {
            c.write_str("NO USABLE ACPI TABLES: ");
            write_acpi_error(c, e);
            return Some(false);
        }
    };
    c.write_str("ACPI rev ");
    write_usize(c, usize::from(tables.rsdp().revision));
    c.write_str(if from_loader.is_some() {
        " from the loader, "
    } else {
        " from a BIOS scan, "
    });
    write_usize(c, tables.len());
    c.write_str(" tables;");

    // SAFETY: the only borrows of these statics, once, on the boot path; see the invariant.
    let (functions, described, nodes, mmio, irqs) = unsafe {
        (
            &mut *FUNCTIONS.get(),
            &mut *DESCRIBED.get(),
            &mut *NODES.get(),
            &mut *MMIO.get(),
            &mut *IRQS.get(),
        )
    };
    let mut records = Records {
        slots: described,
        len: 0,
        overflowed: false,
    };
    let mut ok = true;

    let cpus = match madt_devices(c, &tables, &mut records) {
        Some(cpus) => cpus,
        None => {
            ok = false;
            0
        }
    };
    let (access, host) = config_access(c, &tables, &mut records, &mut ok);
    if records.overflowed {
        c.write_str(" TOO MANY DESCRIBED DEVICES");
        ok = false;
    }

    let n_functions = match &access {
        Access::Ecam(cfg) => enumerate(c, cfg, cfg.0.start_bus, cfg.0.end_bus, functions),
        Access::Ports(cfg) => enumerate(c, cfg, 0, 255, functions),
        Access::None => Some(0),
    };
    let n_functions = n_functions.unwrap_or_else(|| {
        ok = false;
        0
    });

    // From here the records are read-only, and nodes borrow them for the machine's life.
    let n_described = records.len;
    let functions: &'static [Function] = functions.get(..n_functions).unwrap_or(&[]);
    let described: &'static [Described] = described_slice(records.slots, n_described);

    let Some(tree) = build_tree(nodes, described, functions, host) else {
        c.write_str("; TOO MANY NODES TO MODEL");
        return Some(false);
    };
    let mut resources = Resources::new(mmio, irqs);
    ok &= bind(c, &tree, &mut resources);

    if kconfig::QEMU_PCI_TEST_DEVICE {
        ok &= qemu_agrees(c, functions, cpus, matches!(access, Access::Ecam(_)));
    }

    if ok {
        let mut windows = [DeviceWindow {
            phys: 0,
            len: 0,
            what: "",
        }; MAX_CLAIMS];
        let mut count = 0;
        let claimed = resources.mmio_claims().map(|claim| DeviceWindow {
            phys: claim.phys,
            len: claim.len,
            what: claim.what,
        });
        let all = arch::kspace::device_windows()
            .iter()
            .copied()
            .chain(claimed);
        for (slot, w) in windows.iter_mut().zip(all) {
            *slot = w;
            count += 1;
        }
        // SAFETY: once, on the boot path, before anything reads the windows.
        let _ = unsafe { WINDOWS.set((windows, count)) };
        c.write_str("; ");
        write_usize(c, count);
        c.write_str(" windows claimed");
        for w in windows.iter().take(count) {
            c.write_str("\n             ");
            write_hex(c, w.phys);
            c.write_str(" +");
            write_hex(c, w.len);
            c.write_str(" ");
            c.write_str(w.what);
        }
    }
    Some(ok)
}

/// The written records, as a shared slice for the machine's life.
fn described_slice(slots: &'static mut [Described], len: usize) -> &'static [Described] {
    let slots: &'static [Described] = slots;
    slots.get(..len).unwrap_or(&[])
}

/// Record the MADT's processors and interrupt controllers. Returns how many enabled
/// processors it lists, or `None` when the MADT is present but unusable.
fn madt_devices(
    c: &dyn EarlyConsole,
    tables: &Tables<'_, BootMemory>,
    records: &mut Records<'_>,
) -> Option<usize> {
    let madt = match tables.find(b"APIC").map(|t| t.map(Madt::parse)) {
        Ok(Some(Ok(madt))) => madt,
        Ok(None) => {
            c.write_str(" no MADT;");
            return Some(0);
        }
        Ok(Some(Err(e))) | Err(e) => {
            c.write_str(" MADT UNUSABLE: ");
            write_acpi_error(c, e);
            return None;
        }
    };
    records.push(Described::new(Kind::Group, format_args!("cpus"), &[]));
    let (mut cpus, mut ioapics) = (0usize, 0usize);
    for entry in madt.entries() {
        let record = match entry {
            Ok(MadtEntry::LocalApic {
                processor_uid,
                apic_id,
                flags,
            }) => processor(u32::from(apic_id), u32::from(processor_uid), flags),
            Ok(MadtEntry::LocalX2Apic {
                x2apic_id,
                flags,
                processor_uid,
            }) => processor(x2apic_id, processor_uid, flags),
            Ok(MadtEntry::IoApic {
                id,
                address,
                gsi_base,
            }) => {
                ioapics += 1;
                Described::new(
                    Kind::IoInterruptController {
                        id: u32::from(id),
                        gsi_base,
                    },
                    format_args!("io-apic@{address:x}"),
                    &[(u64::from(address), APIC_WINDOW)],
                )
            }
            Ok(_) => continue,
            Err(e) => {
                c.write_str(" MADT MALFORMED: ");
                write_acpi_error(c, e);
                return None;
            }
        };
        if let Some(Described {
            kind: Kind::Processor { enabled: true, .. },
            ..
        }) = record
        {
            cpus += 1;
        }
        records.push(record);
    }
    let local_apic = match madt.local_apic_address() {
        Ok(a) => a,
        Err(e) => {
            c.write_str(" MADT MALFORMED: ");
            write_acpi_error(c, e);
            return None;
        }
    };
    records.push(Described::new(
        Kind::LocalInterruptController,
        format_args!("local-apic@{local_apic:x}"),
        &[(local_apic, APIC_WINDOW)],
    ));
    c.write_str(" ");
    write_usize(c, cpus);
    c.write_str(" CPUs, ");
    write_usize(c, ioapics);
    c.write_str(" I/O APIC;");
    Some(cpus)
}

fn processor(apic_id: u32, processor_uid: u32, flags: ProcessorFlags) -> Option<Described> {
    Described::new(
        Kind::Processor {
            apic_id,
            processor_uid,
            enabled: flags.enabled(),
            online_capable: flags.online_capable(),
        },
        format_args!("cpu@{apic_id:x}"),
        &[],
    )
}

/// How PCI configuration space is reached on this machine.
enum Access {
    Ecam(Ecam),
    Ports(Ports),
    None,
}

/// Record every MCFG segment, and choose how to reach segment 0's configuration space.
/// Returns the access and the index of the record the functions hang under.
fn config_access(
    c: &dyn EarlyConsole,
    tables: &Tables<'_, BootMemory>,
    records: &mut Records<'_>,
    ok: &mut bool,
) -> (Access, Option<usize>) {
    let mcfg = match tables.find(b"MCFG").map(|t| t.map(Mcfg::parse)) {
        Ok(Some(Ok(mcfg))) => mcfg,
        Ok(Some(Err(e))) | Err(e) => {
            c.write_str(" MCFG UNUSABLE: ");
            write_acpi_error(c, e);
            *ok = false;
            return (Access::None, None);
        }
        Ok(None) => {
            // SAFETY: single-threaded boot with interrupts masked; see `Ports`.
            if !unsafe { arch::pc::config_mechanism_1_present() } {
                c.write_str(" no PCI");
                return (Access::None, None);
            }
            let host =
                records.push(Described::new(Kind::PortConfigSpace, format_args!("pci"), &[]));
            c.write_str(" PCI through ports,");
            return (Access::Ports(Ports(())), host);
        }
    };

    let mut chosen = (Access::None, None);
    for segment in mcfg.segments() {
        let segment = match segment {
            Ok(s) => s,
            Err(e) => {
                c.write_str(" MCFG MALFORMED: ");
                write_acpi_error(c, e);
                *ok = false;
                continue;
            }
        };
        let index = records.push(Described::new(
            Kind::EcamConfigSpace {
                segment: segment.segment,
                start_bus: segment.start_bus,
                end_bus: segment.end_bus,
            },
            format_args!("pci@{:x}", segment.base),
            &[(segment.base, segment.len())],
        ));
        // Segment 0 is enumerated. Others are recorded and wait for a `pci::Address` that
        // carries a segment; QEMU's machines have none.
        if segment.segment != 0 || chosen.1.is_some() {
            continue;
        }
        if segment.base.saturating_add(segment.len()) > arch::pc::BOOT_IDENTITY_END {
            c.write_str(" ECAM ABOVE THE BOOT MAP at ");
            write_hex(c, segment.base);
            *ok = false;
            continue;
        }
        c.write_str(" ECAM at ");
        write_hex(c, segment.base);
        c.write_str(",");
        chosen = (Access::Ecam(Ecam(segment)), index);
    }
    chosen
}

/// Enumerate and check the sizing left nothing changed. Returns how many functions, or
/// `None` on any failure, which it has already reported.
fn enumerate(
    c: &dyn EarlyConsole,
    cfg: &impl ConfigSpace,
    first: u8,
    last: u8,
    out: &mut [Function],
) -> Option<usize> {
    let n = match pci::enumerate(cfg, first, last, out) {
        Ok(n) => n,
        Err(pci::Error::TooManyFunctions { .. }) => {
            c.write_str(" TOO MANY PCI FUNCTIONS");
            return None;
        }
        Err(pci::Error::Text) => {
            c.write_str(" A PCI NAME DID NOT FIT");
            return None;
        }
    };
    c.write_str(" ");
    write_usize(c, n);
    c.write_str(" PCI functions");
    match pci::verify_restored(cfg, out.get(..n).unwrap_or(&[])) {
        Ok(()) => Some(n),
        Err(pci::Disturbed::Command { at, was, now }) => {
            c.write_str(" (SIZING LEFT ");
            write_address(c, at);
            c.write_str(" COMMAND ");
            write_hex(c, u64::from(was));
            c.write_str(" AS ");
            write_hex(c, u64::from(now));
            c.write_str(")");
            None
        }
        Err(pci::Disturbed::Bar {
            at,
            index,
            was,
            now,
        }) => {
            c.write_str(" (SIZING LEFT ");
            write_address(c, at);
            c.write_str(" BAR");
            write_usize(c, index);
            c.write_str(" ");
            write_hex(c, u64::from(was));
            c.write_str(" AS ");
            write_hex(c, u64::from(now));
            c.write_str(")");
            None
        }
    }
}

/// The tree: processors under `cpus`, the APICs and configuration windows under the
/// root, and each PCI function under the host configuration node or its bridge.
fn build_tree(
    storage: &'static mut [Node<'static>],
    described: &'static [Described],
    functions: &'static [Function],
    host: Option<usize>,
) -> Option<DeviceTree<'static, 'static>> {
    let mut b = Builder::new(storage).ok()?;
    let mut cpus = NodeId::ROOT;
    let mut host_node = NodeId::ROOT;
    for (i, d) in described.iter().enumerate() {
        let parent = match d.kind {
            Kind::Processor { .. } => cpus,
            _ => NodeId::ROOT,
        };
        let id = b
            .add(parent, d.name(), d.compatible(), Origin::Table(d))
            .ok()?;
        if d.kind == Kind::Group {
            cpus = id;
        }
        if Some(i) == host {
            host_node = id;
        }
    }
    // A function's parent index names an earlier function, so its node already exists.
    let mut ids = [NodeId::ROOT; MAX_FUNCTIONS];
    for (i, f) in functions.iter().enumerate() {
        let parent = match f.parent {
            Some(p) => *ids.get(usize::from(p))?,
            None => host_node,
        };
        let id = b
            .add(parent, f.name(), f.compatible(), Origin::Pci(f))
            .ok()?;
        *ids.get_mut(i)? = id;
    }
    Some(b.finish())
}

/// Probe every node a driver matches, then start every bound device.
fn bind(c: &dyn EarlyConsole, tree: &DeviceTree<'_, '_>, resources: &mut Resources<'_>) -> bool {
    let mut bound: [Option<(usize, Bound)>; MAX_BOUND] = [const { None }; MAX_BOUND];
    let mut ok = true;
    let mut n = 0;
    for id in tree.ids() {
        let Some((d, _)) = best_match(tree, id, &DRIVERS) else {
            continue;
        };
        let Some(&drv) = DRIVERS.get(d) else { continue };
        match driver::probe(drv, tree, id, resources) {
            Ok(b) if n < MAX_BOUND => {
                if let Some(slot) = bound.get_mut(n) {
                    *slot = Some((d, b));
                }
                n += 1;
            }
            Ok(b) => {
                c.write_str("; TOO MANY DEVICES");
                driver::remove(drv, b, resources);
                ok = false;
            }
            Err(_) => {
                c.write_str("; ");
                c.write_str(drv.name());
                c.write_str(" at ");
                c.write_bytes(tree.node(id).name());
                c.write_str(" PROBE FAILED");
                ok = false;
            }
        }
    }
    for (d, b) in bound.iter_mut().filter_map(Option::take) {
        let Some(&drv) = DRIVERS.get(d) else { continue };
        if let Err((_, why)) = driver::start(drv, b) {
            c.write_str("; ");
            c.write_str(drv.name());
            c.write_str(" did not start: ");
            c.write_str(why);
            ok = false;
        }
    }
    c.write_str("; ");
    write_usize(c, n);
    c.write_str(" bound");
    ok
}

/// The checks that hold only on QEMU's PC machines; see the module documentation.
fn qemu_agrees(c: &dyn EarlyConsole, functions: &[Function], cpus: usize, ecam: bool) -> bool {
    let mut ok = true;

    let expected = if ecam { Q35_MCH } else { I440FX };
    match functions
        .iter()
        .find(|f| f.address == Address::new(0, 0, 0))
    {
        Some(f) if (f.vendor, f.device) == expected && f.is_host_bridge() => {}
        Some(f) => {
            c.write_str("; HOST BRIDGE 00:00.0 IS ");
            write_hex(c, u64::from(f.vendor));
            c.write_str(":");
            write_hex(c, u64::from(f.device));
            ok = false;
        }
        None => {
            c.write_str("; NO HOST BRIDGE AT 00:00.0");
            ok = false;
        }
    }

    if cpus != kconfig::QEMU_CPUS {
        c.write_str("; MADT LISTS ");
        write_usize(c, cpus);
        c.write_str(" CPUS, QEMU HAS ");
        write_usize(c, kconfig::QEMU_CPUS);
        ok = false;
    }

    let testdev = functions
        .iter()
        .find(|f| (f.vendor, f.device) == QEMU_TESTDEV);
    match testdev {
        None => {
            c.write_str("; PCI-TESTDEV NOT FOUND");
            ok = false;
        }
        Some(f) if f.address.bus == 0 || f.parent.is_none() => {
            c.write_str("; PCI-TESTDEV NOT BEHIND A BRIDGE");
            ok = false;
        }
        Some(f) => {
            let memory = matches!(f.bars[0], Bar::Memory { size: 0x1000, .. });
            let io = matches!(f.bars[1], Bar::Io { size: 0x100, .. });
            if io && memory {
                c.write_str("; pci-testdev at ");
                write_address(c, f.address);
                c.write_str(" sized ok");
            } else {
                c.write_str("; PCI-TESTDEV BARS SIZED WRONG:");
                for bar in &f.bars[..2] {
                    match *bar {
                        Bar::Io { size, .. } => {
                            c.write_str(" io ");
                            write_hex(c, u64::from(size));
                        }
                        Bar::Memory { size, .. } => {
                            c.write_str(" memory ");
                            write_hex(c, size);
                        }
                        Bar::None => c.write_str(" none"),
                    }
                }
                ok = false;
            }
        }
    }
    ok
}

/// Device memory the kernel touches after its own tables are installed: the port's own
/// windows, and every window a bound driver claimed.
///
/// `None` until [`discover`] has succeeded, so a kernel space is never built without the
/// windows discovery was supposed to find.
pub fn device_windows() -> Option<&'static [DeviceWindow]> {
    WINDOWS.get().and_then(|(windows, n)| windows.get(..*n))
}

fn write_acpi_error(c: &dyn EarlyConsole, e: acpi::Error) {
    let (what, detail) = match e {
        acpi::Error::NoRsdp => ("no RSDP", None),
        acpi::Error::Unreadable { address, .. } => ("unreadable at ", Some(address)),
        acpi::Error::BadChecksum { signature, address } => {
            c.write_bytes(&signature);
            (" bad checksum at ", Some(address))
        }
        acpi::Error::WrongSignature { found, address, .. } => {
            c.write_bytes(&found);
            (" where another table was expected, at ", Some(address))
        }
        acpi::Error::BadLength {
            signature, address, ..
        } => {
            c.write_bytes(&signature);
            (" bad length at ", Some(address))
        }
        acpi::Error::Malformed { signature, offset } => {
            c.write_bytes(&signature);
            (" malformed at offset ", Some(offset as u64))
        }
        acpi::Error::TooManyTables { .. } => ("too many tables", None),
    };
    c.write_str(what);
    if let Some(v) = detail {
        write_hex(c, v);
    }
}

fn write_address(c: &dyn EarlyConsole, at: Address) {
    let digit = |v: u8| b"0123456789abcdef"[usize::from(v & 0xf)];
    c.write_bytes(&[
        digit(at.bus >> 4),
        digit(at.bus),
        b':',
        digit(at.device >> 4),
        digit(at.device),
        b'.',
        digit(at.function),
    ]);
}

fn write_usize(c: &dyn EarlyConsole, mut v: usize) {
    let mut buf = [0u8; 20];
    let mut i = buf.len();
    loop {
        i -= 1;
        buf[i] = b'0' + (v % 10) as u8;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    c.write_bytes(&buf[i..]);
}

fn write_hex(c: &dyn EarlyConsole, v: u64) {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut buf = [0u8; 18];
    buf[0] = b'0';
    buf[1] = b'x';
    for i in 0..16 {
        buf[2 + i] = DIGITS[((v >> (60 - i * 4)) & 0xf) as usize];
    }
    c.write_bytes(&buf);
}

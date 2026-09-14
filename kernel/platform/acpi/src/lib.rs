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
//! way they bind on aarch64.
//!
//! # Interrupt controllers and CPUs
//!
//! Which drivers bind the APICs is the architecture's question, answered at module level:
//!
//! - **x86_64** binds the local APIC and I/O APIC drivers (`drivers/irqchip/apic`), installs the
//!   controller and its timer in the architecture's interrupt path with the MADT's source overrides
//!   applied, and starts every other enabled processor the MADT lists (`apic_x86_64.rs`,
//!   `smp_x86_64.rs`).
//! - **i686** binds placeholders that claim the APIC windows and drive nothing, and stays on the
//!   8259A and the PIT (`apic_i686.rs`). Its interrupt path has no controller seam, and it has no
//!   second CPU to start, so there is nothing yet for an APIC to do there. Claiming the windows
//!   keeps its kernel address space the same shape as x86_64's.
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

#[cfg(CONFIG_ARCH_I686)]
#[path = "apic_i686.rs"]
mod controller;
#[cfg(CONFIG_ARCH_X86_64)]
#[path = "apic_x86_64.rs"]
mod controller;
#[cfg(CONFIG_ARCH_X86_64)]
#[path = "smp_x86_64.rs"]
mod smp;

use core::cell::SyncUnsafeCell;
use core::sync::atomic::{AtomicU64, Ordering};

use acpi::{EcamSegment, Madt, MadtEntry, Mcfg, PhysMemory, ProcessorFlags, Rsdp, Tables};
use apic::Override;
use device::driver::{self, best_match};
use device::msi::{self, MsixCapability, MsixTable};
use device::pci::{self, Address, Bar, ConfigSpace, Function};
use device::table::Kind;
use device::{
    BootCell, Bound, Builder, Described, DeviceTree, Driver, Handlers, IrqClaim, IrqLine,
    MmioClaim, Node, NodeId, Origin, PortClaim, Probe, ProbeError, Registers, Resources, Started,
};
use hal::paging::DeviceWindow;
use hal::{EarlyConsole, IrqChip, IrqNumber};
use sync::{LockClass, SpinLock};

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
static PORTS: SyncUnsafeCell<[Option<PortClaim>; MAX_PORT_CLAIMS]> =
    SyncUnsafeCell::new([None; MAX_PORT_CLAIMS]);

/// I/O port ranges bound drivers may claim between them. The serial port is the only
/// port-mapped device bound today.
const MAX_PORT_CLAIMS: usize = 4;

/// What the address space maps, set by [`discover`].
static WINDOWS: BootCell<([DeviceWindow; MAX_CLAIMS], usize)> = BootCell::new();

/// The device model's interrupt handlers, looked up by [`dispatch`] on whichever CPU took
/// the interrupt. Behind a lock because removing and rebinding a device changes it; see
/// `kernel/platform/fdt` for the same table on aarch64 and `device::Handlers` for why the
/// handler runs with the lock released.
static HANDLERS: SpinLock<Handlers<MAX_BOUND>, arch::Cpu> =
    SpinLock::with_class(Handlers::new(), &HANDLERS_CLASS);
static HANDLERS_CLASS: LockClass = LockClass::new("platform.handlers");

/// The console UART's receive line, once wired. It does not change across a rebind.
static CONSOLE_LINE: BootCell<IrqNumber> = BootCell::new();
/// The block device's interrupt line, once its handler is wired.
static BLOCK_LINE: BootCell<IrqNumber> = BootCell::new();
/// The network card's interrupt line, once its handler is wired.
static NET_LINE: BootCell<IrqNumber> = BootCell::new();

/// Message-signalled lines there can be; `controller::MSI_LINES` is at most this long.
const MAX_MSI_ROUTES: usize = 16;
/// CPUs whose interrupts on a message-signalled line are counted apart.
const MSI_COUNTED_CPUS: usize = 8;

/// Where each message-signalled line is delivered from, indexed from the start of
/// `controller::MSI_LINES`. `None` for a line nothing was wired to.
///
/// Behind a lock because moving an interrupt to another CPU writes the entry after
/// discovery, from whichever CPU asks; see [`route_interrupt`].
static MSI_ROUTES: SpinLock<[Option<MsiRoute>; MAX_MSI_ROUTES], arch::Cpu> =
    SpinLock::with_class([const { None }; MAX_MSI_ROUTES], &MSI_ROUTES_CLASS);
static MSI_ROUTES_CLASS: LockClass = LockClass::new("platform.msi-routes");

/// Interrupts on each message-signalled line whose handler ran on each CPU, counted by
/// [`dispatch`], which runs on the CPU that took the interrupt.
static MSI_TAKEN: [[AtomicU64; MSI_COUNTED_CPUS]; MAX_MSI_ROUTES] =
    [const { [const { AtomicU64::new(0) }; MSI_COUNTED_CPUS] }; MAX_MSI_ROUTES];

/// One wired message-signalled interrupt.
struct MsiRoute {
    /// The MSI-X table and the entry in it, which is what moving the interrupt rewrites.
    /// `None` for MSI, whose message is in configuration space and so is programmed only
    /// during discovery, the one time configuration space is reachable.
    entry: Option<(MsixTable, u16)>,
}

/// The console's binding, kept after discovery so the serial check can take the device
/// away and bind it again: the tree it was bound from, the ledger its claims are in, its
/// node, and its `Started` token.
struct Console {
    tree: DeviceTree<'static, 'static>,
    resources: Resources<'static>,
    node: NodeId,
    started: Option<Started>,
}

/// SAFETY INVARIANT: written once, at the end of [`discover`], and read and written after
/// that only by [`rebind_console`] — both on the single-threaded boot path, with
/// interrupts masked. The interrupt handler never reaches it: it reads the driver's own
/// state.
static CONSOLE: SyncUnsafeCell<Option<Console>> = SyncUnsafeCell::new(None);

/// The PC's first serial port: eight ports from 0x3f8, on ISA IRQ 4. Fixed by the
/// architecture, and described only in AML, which this kernel does not interpret.
const COM1: (u16, u16) = (0x3f8, 8);
const COM1_IRQ: u32 = 4;

/// ISA lines the interrupt path has an entry point for.
const ISA_LINES: u32 = 16;

/// Where this platform's devices come from, for the banner.
pub const SOURCE: &str = "ACPI and PCI";

/// A placeholder driver: claims the node's first window, and drives nothing.
pub(crate) struct Reserve {
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

pub(crate) static ECAM: Reserve = Reserve {
    name: "ecam",
    compatible: &["pci-host-ecam-generic"],
    what: "PCI Express configuration space",
};

/// The processors the MADT lists, as `(APIC ID, enabled)`. More than this are counted and
/// not started.
pub(crate) const MAX_MADT_CPUS: usize = 64;

/// What the MADT says beyond the devices that become nodes: every processor, for starting
/// them, and the ISA interrupt source overrides, for routing.
#[derive(Clone, Copy)]
pub(crate) struct MadtFacts {
    pub cpus: [(u32, bool); MAX_MADT_CPUS],
    /// Every processor entry, including any past `cpus`' capacity.
    pub cpu_count: usize,
    pub overrides: [Override; apic::MAX_OVERRIDES],
    pub override_count: usize,
    /// An override did not fit, or was for a bus other than ISA.
    pub overrides_dropped: bool,
}

impl MadtFacts {
    const EMPTY: MadtFacts = MadtFacts {
        cpus: [(0, false); MAX_MADT_CPUS],
        cpu_count: 0,
        overrides: [Override::EMPTY; apic::MAX_OVERRIDES],
        override_count: 0,
        overrides_dropped: false,
    };

    #[cfg_attr(
        CONFIG_ARCH_I686,
        expect(
            dead_code,
            reason = "the i686 port starts no CPUs and routes nothing through an APIC"
        )
    )]
    pub fn overrides(&self) -> &[Override] {
        self.overrides.get(..self.override_count).unwrap_or(&[])
    }

    #[cfg_attr(
        CONFIG_ARCH_I686,
        expect(
            dead_code,
            reason = "the i686 port starts no CPUs and routes nothing through an APIC"
        )
    )]
    pub fn cpus(&self) -> &[(u32, bool)] {
        self.cpus
            .get(..self.cpu_count.min(MAX_MADT_CPUS))
            .unwrap_or(&[])
    }
}

/// Set by [`discover`] from the MADT.
pub(crate) static MADT: BootCell<MadtFacts> = BootCell::new();

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

/// Memory-mapped configuration space for one segment, through the device window: the boot
/// tables alias the low 4 GiB at `DEVICE_WINDOW_BASE`, and the kernel's own space maps the
/// claimed ECAM window there.
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
        let address = hal::paging::device_virt(base.checked_add(u64::from(offset))?)?;
        Some(core::ptr::with_exposed_provenance_mut(address))
    }
}

impl ConfigSpace for Ecam {
    fn read(&self, at: Address, offset: u16) -> u32 {
        match self.register(at, offset) {
            // SAFETY: an aligned register inside the segment's window, which `discover`
            // checked lies below `BOOT_IDENTITY_END` and so inside the boot tables' device
            // alias, and which the kernel's space maps at the same address. Reading configuration
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
    let (functions, described, nodes, mmio, irqs, ports) = unsafe {
        (
            &mut *FUNCTIONS.get(),
            &mut *DESCRIBED.get(),
            &mut *NODES.get(),
            &mut *MMIO.get(),
            &mut *IRQS.get(),
            &mut *PORTS.get(),
        )
    };
    let mut records = Records {
        slots: described,
        len: 0,
        overflowed: false,
    };
    let mut ok = true;

    let mut facts = MadtFacts::EMPTY;
    let cpus = match madt_devices(c, &tables, &mut records, &mut facts) {
        Some(cpus) => cpus,
        None => {
            ok = false;
            0
        }
    };
    // SAFETY: once, on the single-threaded boot path, before anything reads it.
    let facts = unsafe { MADT.set(facts) }.ok();
    let (access, host) = config_access(c, &tables, &mut records, &mut ok);
    // The serial port no table lists; see `Kind::LegacyUart`. The driver checks the part
    // answers before it drives it, so declaring it on a machine without one fails that
    // driver's start rather than programming an empty bus.
    records.push(
        Described::new(Kind::LegacyUart, format_args!("serial@3f8"), &[])
            .map(|d| d.with_ports(Some(COM1), Some(COM1_IRQ))),
    );
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
    let mut resources = Resources::new(mmio, irqs)
        .with_ports(ports)
        .with_msi(controller::MSI);
    let mut started: [Option<(usize, Started)>; MAX_BOUND] = [const { None }; MAX_BOUND];
    ok &= bind(c, &tree, &mut resources, &mut started);
    if ok {
        // SAFETY: the caller's contract, and the drivers have just probed: `install`'s.
        ok &= unsafe { controller::install(c, facts) };
    }
    // After the controller, so the lines are unmasked at the one that will deliver them.
    let console = if ok {
        // SAFETY: the caller's contract: once, masked, on the boot path.
        let messages = Messages {
            resources: &resources,
            cfg: config_space(&access),
        };
        let (wired, console) = unsafe { wire_all(c, &tree, &messages, &mut started) };
        ok &= wired;
        console
    } else {
        None
    };

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
    if let Some((node, started)) = console {
        // SAFETY: the one write, at the end of discovery on the single-threaded boot path;
        // see `CONSOLE`'s invariant.
        unsafe {
            *CONSOLE.get() = Some(Console {
                tree,
                resources,
                node,
                started: Some(started),
            });
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
    facts: &mut MadtFacts,
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
            }) => {
                record_cpu(facts, u32::from(apic_id), flags);
                processor(u32::from(apic_id), u32::from(processor_uid), flags)
            }
            Ok(MadtEntry::LocalX2Apic {
                x2apic_id,
                flags,
                processor_uid,
            }) => {
                record_cpu(facts, x2apic_id, flags);
                processor(x2apic_id, processor_uid, flags)
            }
            Ok(MadtEntry::SourceOverride {
                bus,
                source,
                gsi,
                flags,
            }) => {
                match facts.overrides.get_mut(facts.override_count) {
                    // Bus 0 is ISA, the only bus ACPI defines overrides for.
                    Some(slot) if bus == 0 => {
                        *slot = Override { source, gsi, flags };
                        facts.override_count += 1;
                    }
                    _ => facts.overrides_dropped = true,
                }
                continue;
            }
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

fn record_cpu(facts: &mut MadtFacts, apic_id: u32, flags: ProcessorFlags) {
    if let Some(slot) = facts.cpus.get_mut(facts.cpu_count) {
        *slot = (apic_id, flags.enabled());
    }
    facts.cpu_count += 1;
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
fn bind(
    c: &dyn EarlyConsole,
    tree: &DeviceTree<'_, '_>,
    resources: &mut Resources<'_>,
    started: &mut [Option<(usize, Started)>; MAX_BOUND],
) -> bool {
    let mut bound: [Option<(usize, Bound)>; MAX_BOUND] = [const { None }; MAX_BOUND];
    let mut ok = true;
    let mut n = 0;
    let drivers = controller::DRIVERS;
    for id in tree.ids() {
        let Some((d, _)) = best_match(tree, id, drivers) else {
            continue;
        };
        let Some(&drv) = drivers.get(d) else { continue };
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
    for (slot, (d, b)) in started
        .iter_mut()
        .zip(bound.iter_mut().filter_map(Option::take))
    {
        let Some(&drv) = drivers.get(d) else { continue };
        match driver::start(drv, b) {
            Ok(s) => *slot = Some((d, s)),
            Err((_, why)) => {
                c.write_str("; ");
                c.write_str(drv.name());
                c.write_str(" did not start: ");
                c.write_str(why);
                ok = false;
            }
        }
    }
    c.write_str("; ");
    write_usize(c, n);
    c.write_str(" bound");
    ok
}

/// What wiring one device's interrupt came to.
enum Wired {
    /// The driver takes no interrupt.
    Nothing,
    Line(IrqNumber),
    Failed,
}

/// Wire every started device's interrupt, and find the console among them. Returns
/// whether all of it worked, and the console's node and token for [`CONSOLE`].
///
/// # Safety
/// Once, from `discover`, with interrupts masked, after the controller is installed.
unsafe fn wire_all(
    c: &dyn EarlyConsole,
    tree: &DeviceTree<'_, '_>,
    messages: &Messages<'_, '_>,
    started: &mut [Option<(usize, Started)>; MAX_BOUND],
) -> (bool, Option<(NodeId, Started)>) {
    // Before any line is unmasked: the first `init` remaps and masks the 8259A, and on
    // i686, where the 8259A is the controller, a line enabled before it would be masked
    // again by whatever called `init` next.
    arch::interrupt::init();
    // SAFETY: the caller's contract: once, masked, before a device line is unmasked below.
    unsafe { arch::interrupt::set_device_dispatch(dispatch) };
    let chip = arch::interrupt::irq_chip();
    let mut ok = true;
    let mut console = None;
    for entry in started.iter_mut() {
        let Some((d, s)) = entry.as_ref() else {
            continue;
        };
        let Some(&drv) = controller::DRIVERS.get(*d) else {
            continue;
        };
        let function = match tree.node(s.bound().node()).origin() {
            Origin::Pci(f) => Some(f),
            _ => None,
        };
        match wire(c, chip, drv, s, function, Some(messages)) {
            Wired::Nothing => {}
            Wired::Failed => ok = false,
            Wired::Line(line) => {
                if drv.name() == virtio_blk::DRIVER.name() {
                    // SAFETY: once, on the single-threaded boot path.
                    let _ = unsafe { BLOCK_LINE.set(line) };
                }
                if drv.name() == virtio_net::DRIVER.name() {
                    // SAFETY: once, on the single-threaded boot path.
                    let _ = unsafe { NET_LINE.set(line) };
                }
                if drv.name() == uart16550::DRIVER.name() && console.is_none() {
                    // SAFETY: once, on the single-threaded boot path.
                    let _ = unsafe { CONSOLE_LINE.set(line) };
                    let node = s.bound().node();
                    console = entry.take().map(|(_, s)| (node, s));
                }
            }
        }
    }
    (ok, console)
}

/// What wiring a message-signalled interrupt needs beyond the device: the ledger, to find
/// the window its MSI-X table is in, and configuration space, to turn the capability on.
struct Messages<'a, 's> {
    resources: &'a Resources<'s>,
    cfg: Option<&'a dyn ConfigSpace>,
}

/// Configuration space as discovery reaches it, if it does.
fn config_space(access: &Access) -> Option<&dyn ConfigSpace> {
    match access {
        Access::Ecam(cfg) => Some(cfg),
        Access::Ports(cfg) => Some(cfg),
        Access::None => None,
    }
}

/// Whether `line` is one of the message-signalled lines and something was wired to it.
fn is_msi_line(line: u32) -> bool {
    msi_slot(line).is_some_and(|slot| MSI_ROUTES.lock_irqsave()[slot].is_some())
}

/// The index of `line` among the message-signalled lines.
fn msi_slot(line: u32) -> Option<usize> {
    if !controller::MSI_LINES.contains(&line) {
        return None;
    }
    let slot = (line - controller::MSI_LINES.start) as usize;
    (slot < MAX_MSI_ROUTES).then_some(slot)
}

/// Wire a PCI function's message-signalled vector `entry`, in the same order as a line: a
/// free line, the handler registered and enabled, then the message written for the boot
/// CPU, and only then the vector unmasked.
///
/// For MSI-X the message goes into the table entry, masked whatever firmware left, through
/// a window the function's own driver claimed ([`msix_table`]); the capability is enabled,
/// clearing any function-wide mask firmware left; then the entry is unmasked. A function
/// with MSI and no MSI-X has its one message programmed in its capability instead.
#[allow(clippy::too_many_arguments)]
fn wire_msi(
    c: &dyn EarlyConsole,
    drv: &dyn Driver,
    started: &Started,
    f: &Function,
    line: &IrqLine,
    handler: fn(),
    entry: u16,
    messages: &Messages<'_, '_>,
) -> Wired {
    let failed = |why: &str| {
        c.write_str("; ");
        c.write_str(drv.name());
        c.write_str(" ");
        c.write_str(why);
        Wired::Failed
    };
    let Some(cfg) = messages.cfg else {
        return failed("HAS A VECTOR BUT NO CONFIGURATION SPACE TO ENABLE IT IN");
    };
    let mut routes = MSI_ROUTES.lock_irqsave();
    let free = routes.iter().position(Option::is_none);
    let Some((slot, number)) = free.and_then(|s| {
        let line = controller::MSI_LINES
            .start
            .checked_add(u32::try_from(s).ok()?)?;
        controller::MSI_LINES
            .contains(&line)
            .then_some((s, IrqNumber(line)))
    }) else {
        return failed("FOUND NO FREE LINE FOR A MESSAGE-SIGNALLED INTERRUPT");
    };
    let Some((address, data)) = controller::msi_message(number.0, 0) else {
        return failed("HAS NO MESSAGE THAT REACHES THE BOOT CPU");
    };
    let registered = {
        let mut table = HANDLERS.lock_irqsave();
        table
            .register(started.bound(), line, number, handler)
            .and_then(|()| table.enable(started, number))
    };
    if registered.is_err() {
        return failed("HANDLER NOT REGISTERED");
    }
    // Before the function is told where to write: a function that is not a bus master sends
    // no message. See `msi::set_bus_master` for how that went unnoticed.
    if !msi::set_bus_master(cfg, f.address) {
        return failed("DID NOT BECOME A BUS MASTER");
    }

    let route = if let Some(cap) = msi::msix(f) {
        let Some(table) = msix_table(f, &cap, started.bound().node(), messages.resources) else {
            return failed("MSI-X TABLE IS IN NO WINDOW ITS DRIVER CLAIMED");
        };
        if !(table.mask(entry) && table.set_message(entry, address, data)) {
            return failed("MSI-X ENTRY DID NOT TAKE ITS MESSAGE");
        }
        if !msi::set_msix_enabled(cfg, f.address, &cap, true) {
            return failed("MSI-X DID NOT ENABLE");
        }
        if !table.unmask(entry) {
            return failed("MSI-X ENTRY DID NOT UNMASK");
        }
        c.write_str("; ");
        c.write_str(drv.name());
        c.write_str(" receives MSI-X entry ");
        write_usize(c, usize::from(entry));
        MsiRoute {
            entry: Some((table, entry)),
        }
    } else if let Some(cap) = msi::msi(f) {
        let Ok(data) = u16::try_from(data) else {
            return failed("HAS MSI DATA WIDER THAN THE CAPABILITY");
        };
        if entry != 0 || !msi::program_msi(cfg, f.address, &cap, address, data) {
            return failed("MSI DID NOT TAKE ITS MESSAGE");
        }
        c.write_str("; ");
        c.write_str(drv.name());
        c.write_str(" receives MSI");
        MsiRoute { entry: None }
    } else {
        return failed("CLAIMED A VECTOR ITS FUNCTION DOES NOT HAVE");
    };
    c.write_str(" on line ");
    write_usize(c, number.0 as usize);
    c.write_str(", vector ");
    write_usize(c, (data & 0xff) as usize);
    routes[slot] = Some(route);
    Wired::Line(number)
}

/// The MSI-X table `cap` describes, through a window `node` claimed that holds it whole.
///
/// `None` when no such window is claimed, or when it is past what discovery can reach. The
/// one place a table's address comes from, and it comes from the ledger: where a claimed
/// window is reached is `Registers::for_claim`'s to decide, through the device window, and
/// nothing here names an address to dereference.
fn msix_table(
    f: &Function,
    cap: &MsixCapability,
    node: NodeId,
    resources: &Resources<'_>,
) -> Option<MsixTable> {
    let (bar_base, bar_len) = f.bar_by_number(cap.table_bar)?;
    let bytes = cap.table_bytes() as u64;
    if u64::from(cap.table_offset).checked_add(bytes)? > bar_len {
        return None;
    }
    let phys = bar_base.checked_add(u64::from(cap.table_offset))?;
    let claim = resources.mmio_claims().find(|w| {
        w.node == node && w.phys <= phys && phys + bytes <= w.phys.saturating_add(w.len)
    })?;
    // The table is written during discovery, on the boot tables, whose device alias covers
    // what they identity-map and no more.
    if claim.phys.checked_add(claim.len)? > arch::pc::BOOT_IDENTITY_END {
        return None;
    }
    // SAFETY: a window the function's driver claimed, which is mapped at the device window
    // above its physical address both by the boot tables' alias discovery runs on (the window
    // lies below `BOOT_IDENTITY_END`, checked above) and by the kernel's own space, which maps
    // every claimed window there. The driver leaves the table to the platform: it claimed
    // the window for it and never touches the table's registers.
    let regs = unsafe { Registers::for_claim(claim) }?;
    MsixTable::new(regs, usize::try_from(phys - claim.phys).ok()?, cap.table_size)
}

/// Wire a started device's interrupt: its ISA line, the handler registered and enabled in
/// the table, then the line unmasked at the controller — in that order, so a line is never
/// live before its handler is.
fn wire(
    c: &dyn EarlyConsole,
    chip: &'static dyn IrqChip,
    drv: &dyn Driver,
    started: &Started,
    function: Option<&Function>,
    messages: Option<&Messages<'_, '_>>,
) -> Wired {
    let Some((line, handler)) = drv.interrupt() else {
        return Wired::Nothing;
    };
    // A message-signalled vector has no route to trust or distrust: the function is told
    // where to deliver. `function` is the node's PCI record, because only the caller holds
    // the tree.
    if let Some(entry) = msi::vector_of(line.specifier().cells()) {
        return match (function, messages) {
            (Some(f), Some(m)) => wire_msi(c, drv, started, f, line, handler, entry, m),
            _ => {
                c.write_str("; ");
                c.write_str(drv.name());
                c.write_str(" CLAIMED A VECTOR THAT CANNOT BE PROGRAMMED HERE");
                Wired::Failed
            }
        };
    }
    // A PCI function's line is what firmware routed, which is the right answer only on the
    // controller firmware routed for; see `controller::PCI_LINE_TRUSTED`. Where it is not,
    // the device is left unwired and its driver polls, rather than being handed a line its
    // interrupts never reach — which would look wired and time out instead.
    if function.is_some() && !controller::PCI_LINE_TRUSTED {
        c.write_str("; ");
        c.write_str(drv.name());
        c.write_str(" polled: no PCI interrupt route on this controller");
        return Wired::Nothing;
    }
    // A declared device's specifier is the ISA line itself.
    let number = match line.specifier().cells() {
        [isa] if *isa < ISA_LINES => IrqNumber(*isa),
        _ => {
            c.write_str("; ");
            c.write_str(drv.name());
            c.write_str(" INTERRUPT IS NOT AN ISA LINE");
            return Wired::Failed;
        }
    };
    let registered = {
        let mut table = HANDLERS.lock_irqsave();
        table
            .register(started.bound(), line, number, handler)
            .and_then(|()| table.enable(started, number))
    };
    if registered.is_err() {
        c.write_str("; ");
        c.write_str(drv.name());
        c.write_str(" HANDLER NOT REGISTERED");
        return Wired::Failed;
    }
    chip.enable(number);
    c.write_str("; ");
    c.write_str(drv.name());
    c.write_str(" receives on IRQ ");
    write_usize(c, number.0 as usize);
    Wired::Line(number)
}

/// Look `number` up in the handler table and run what is registered, with the table's lock
/// released. What the architecture's interrupt path calls for every device line.
fn dispatch(number: IrqNumber) -> bool {
    let handler = HANDLERS.lock_irqsave().lookup(number);
    match handler {
        Some(handler) => {
            if let Some(taken) = msi_taken(number.0, <arch::Cpu as hal::Arch>::cpu_index()) {
                taken.fetch_add(1, Ordering::Relaxed);
            }
            handler();
            true
        }
        None => false,
    }
}

/// The count of `line`'s interrupts taken on `cpu`, if `line` is message-signalled.
fn msi_taken(line: u32, cpu: usize) -> Option<&'static AtomicU64> {
    MSI_TAKEN.get(msi_slot(line)?)?.get(cpu)
}

/// Whether `line` is a message-signalled interrupt's: one [`route_interrupt`] can move and
/// [`interrupts_on_cpu`] counts.
pub fn interrupt_is_msi(line: u32) -> bool {
    is_msi_line(line)
}

/// Interrupts on `line` whose handler ran on CPU `cpu`. Counted for message-signalled lines
/// only, which are the ones whose CPU can be chosen; zero for any other.
pub fn interrupts_on_cpu(line: u32, cpu: usize) -> u64 {
    msi_taken(line, cpu).map_or(0, |t| t.load(Ordering::Relaxed))
}

/// Whether this platform delivers a PCI function's message-signalled interrupts, so that a
/// function with MSI-X is expected to be wired on it.
pub fn delivers_msi() -> bool {
    controller::MSI
}

/// Deliver message-signalled `line` to CPU `cpu` from its next interrupt on.
///
/// Masks the MSI-X entry, writes the message naming that CPU's local APIC, and unmasks it.
/// A function that has an interrupt to raise while its entry is masked sets the entry's
/// pending bit and raises it on unmask (PCI 3.0 §6.8.2.9), so none is lost in the move. The
/// handler table is shared by every CPU, and every CPU loads the same interrupt table, so
/// nothing else has to change for the handler to run there.
pub fn route_interrupt(line: u32, cpu: usize) -> Result<(), &'static str> {
    let slot = msi_slot(line).ok_or("not a message-signalled line")?;
    let routes = MSI_ROUTES.lock_irqsave();
    let route = routes[slot]
        .as_ref()
        .ok_or("nothing is wired to that line")?;
    let Some((table, entry)) = &route.entry else {
        return Err("an MSI route, which only discovery can program");
    };
    let (address, data) =
        controller::msi_message(line, cpu).ok_or("no local APIC a message can name")?;
    if !table.retarget(*entry, address, data) {
        return Err("the MSI-X entry did not take the message");
    }
    Ok(())
}

/// The console UART's receive line, once its handler is wired.
pub fn console_line() -> Option<u32> {
    CONSOLE_LINE.get().map(|n| n.0)
}

/// The block device's interrupt line, once its handler is wired. `None` when the device
/// is polled, including on a port whose controller no PCI interrupt route reaches.
pub fn block_line() -> Option<u32> {
    BLOCK_LINE.get().map(|n| n.0)
}

/// The network card's interrupt line, once its handler is wired. `None` when the card is
/// polled, as for the block device.
pub fn net_line() -> Option<u32> {
    NET_LINE.get().map(|n| n.0)
}

/// Receive interrupts the console driver has taken, and the bytes they carried.
pub fn console_received() -> (u32, u32) {
    uart16550::received()
}

/// The oldest byte the console's receive interrupt queued.
pub fn console_read() -> Option<u8> {
    uart16550::read_byte()
}

/// Device interrupts dispatched to a handler, and ones that reached none.
pub fn device_interrupts() -> (u64, u64) {
    (arch::interrupt::device_irqs(), arch::interrupt::unhandled_irqs())
}

/// Take the console away and bind it again, checking each step of the removal.
///
/// The removal, in the order the phase tokens require: disable the line at the controller
/// and in the table, stop the device, unregister its handler, and remove it, which gives
/// its ports and its line back to the ledger. Then the ledger is asked what the device
/// still holds, which must be nothing. The binding is then made again from the same node,
/// started, and wired, and must come back on the same line.
///
/// `None` when discovery wired no console, so there was nothing to take away. `Some(false)`
/// for any step that did not do what it says.
///
/// # Safety
/// From the boot path, masked, after [`discover`], with nothing else using the console
/// driver's binding: see `CONSOLE`'s invariant.
pub unsafe fn rebind_console(c: &dyn EarlyConsole) -> Option<bool> {
    // SAFETY: the caller's contract is `CONSOLE`'s invariant.
    let console = unsafe { (*CONSOLE.get()).as_mut() }?;
    let line = *CONSOLE_LINE.get()?;
    let started = console.started.take()?;
    let drv: &dyn Driver = &uart16550::DRIVER;
    let chip = arch::interrupt::irq_chip();

    c.write_str("\n             unbinding: ");
    chip.disable(line);
    let disabled = HANDLERS.lock_irqsave().disable(&started, line);
    let bound = driver::stop(drv, started);
    let unregistered = HANDLERS.lock_irqsave().unregister(&bound, line);
    let registered_after = HANDLERS.lock_irqsave().registered(line);
    driver::remove(drv, bound, &mut console.resources);
    let node = console.node;
    let ports_left = console
        .resources
        .port_claims()
        .filter(|p| p.node == node)
        .count();
    let lines_left = console
        .resources
        .irq_claims()
        .filter(|l| l.node == node)
        .count();

    let removed = disabled.is_ok() && unregistered.is_ok() && !registered_after;
    c.write_str(if disabled.is_ok() {
        "line disabled, "
    } else {
        "LINE NOT DISABLED IN THE TABLE, "
    });
    c.write_str(if unregistered.is_ok() && !registered_after {
        "handler unregistered, "
    } else {
        "HANDLER STILL REGISTERED, "
    });
    write_usize(c, ports_left);
    c.write_str(" port ranges and ");
    write_usize(c, lines_left);
    c.write_str(" lines still claimed");
    let released = ports_left == 0 && lines_left == 0;

    c.write_str("\n             rebinding: ");
    let bound = match driver::probe(drv, &console.tree, node, &mut console.resources) {
        Ok(b) => b,
        Err(_) => {
            c.write_str("PROBE FAILED");
            return Some(false);
        }
    };
    let started = match driver::start(drv, bound) {
        Ok(s) => s,
        Err((_, why)) => {
            c.write_str("DID NOT START: ");
            c.write_str(why);
            return Some(false);
        }
    };
    c.write_str("binding ");
    write_usize(c, uart16550::bindings());
    // The console is the 16550 a firmware table declares, never a PCI function.
    let rewired = match wire(c, chip, drv, &started, None, None) {
        Wired::Line(again) if again == line => true,
        Wired::Line(_) => {
            c.write_str(", ON A DIFFERENT LINE");
            false
        }
        Wired::Nothing => {
            c.write_str(", NO INTERRUPT OFFERED");
            false
        }
        Wired::Failed => false,
    };
    console.started = Some(started);
    Some(removed && released && rewired)
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

/// Start every other processor the MADT lists and prove each one that came up is a CPU of
/// its own, on x86_64; on i686, nothing. `None` when nothing was checked.
///
/// # Safety
/// Once, from `kmain`, on the boot CPU with interrupts masked, after the kernel address
/// space and the interrupt controller are installed.
pub unsafe fn start_secondaries(c: &dyn EarlyConsole) -> Option<bool> {
    // SAFETY: forwarded.
    unsafe { controller::start_secondaries(c) }
}

/// Whether secondary CPU `cpu` is online: on x86_64 one [`start_secondaries`] started; on
/// i686, which starts none, never.
pub fn secondary_online(cpu: usize) -> bool {
    controller::secondary_online(cpu)
}

/// Run `f(arg)` on secondary CPU `cpu` from its function-call IPI, waiting up to a second
/// for the result. `None` if that CPU is not online or `f` had not returned in time; see
/// the aarch64 provider's function of the same name for what that leaves running.
pub fn call_on_secondary(cpu: usize, f: fn(u64) -> u64, arg: u64) -> Option<u64> {
    controller::call_on_secondary(cpu, f, arg)
}

/// Device memory the kernel touches after its own tables are installed: the port's own
/// windows, and every window a bound driver claimed.
///
/// `None` until [`discover`] has succeeded, so a kernel space is never built without the
/// windows discovery was supposed to find.
pub fn device_windows() -> Option<&'static [DeviceWindow]> {
    WINDOWS.get().and_then(|(windows, n)| windows.get(..*n))
}

/// No window is granted to a driver domain on the PCs.
///
/// Not a gap in the design but in the machines: a domain is granted a *mapping*, and the
/// PC's own devices are not memory-mapped. COM1 lives in the port space, which cannot be
/// mapped into an address space at all, and the disk reaches x86 only over PCI, which the
/// virtio driver does not speak yet. See `docs/isolation.md`.
pub fn isolation_window() -> Option<(u64, u64)> {
    None
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

pub(crate) fn write_usize(c: &dyn EarlyConsole, mut v: usize) {
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

pub(crate) fn write_hex(c: &dyn EarlyConsole, v: u64) {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut buf = [0u8; 18];
    buf[0] = b'0';
    buf[1] = b'x';
    for i in 0..16 {
        buf[2 + i] = DIGITS[((v >> (60 - i * 4)) & 0xf) as usize];
    }
    c.write_bytes(&buf);
}

//! The APICs on x86_64: the drivers that bind them, and installing the controller they make
//! into the architecture's interrupt path.
//!
//! After [`install`], device lines are routed through the I/O APIC with the MADT's source
//! overrides applied, end-of-interrupt goes to the local APIC, and the scheduler's one-shot
//! tick is the local APIC timer, measured against the TSC. The architecture chose the
//! vectors; this is where they meet the driver.

use core::cell::SyncUnsafeCell;

use acpi::aml::{self, Interpreter, Node, Object, Space, Storage};
use acpi::{Fadt, Tables};
use device::Driver;
use device::pci::{Address, ConfigSpace, Function};
use hal::EarlyConsole;

use crate::{BootMemory, ECAM, MadtFacts, PinRoute, write_address, write_hex, write_usize};

/// Whether a PCI function's interrupt-line register can be wired as its interrupt.
///
/// Not here. Firmware wrote that register for the 8259A, and this port routes interrupts
/// through the I/O APIC, where a PCI pin arrives on a different input altogether — on q35,
/// a global system interrupt from 16 up — and which one is written only in the ACPI
/// namespace's `_PRT`, as AML. Wiring the register's value would program an input nothing
/// drives: the handler would be registered, the line enabled, and no interrupt would ever
/// come. [`pin_routes`] asks `_PRT` instead, and a function it routes nothing for polls. See
/// `docs/architecture.md`, "PCI interrupts".
pub(crate) const PCI_LINE_TRUSTED: bool = false;

/// Namespace nodes, package cells and buffer bytes the AML interpreter works in. QEMU's q35
/// DSDT is a few hundred nodes; routing its pins allocates a buffer per link device read.
const AML_NODES: usize = 768;
const AML_CELLS: usize = 256;
const AML_BYTES: usize = 1024;

struct AmlStorage {
    nodes: [Node; AML_NODES],
    cells: [Object; AML_CELLS],
    bytes: [u8; AML_BYTES],
}

/// SAFETY INVARIANT: borrowed mutably once, by [`pin_routes`], which `discover` calls once on
/// the single-threaded boot path. Nothing refers to it afterwards.
static AML: SyncUnsafeCell<AmlStorage> = SyncUnsafeCell::new(AmlStorage {
    nodes: [Node::EMPTY; AML_NODES],
    cells: [Object::Uninitialized; AML_CELLS],
    bytes: [0; AML_BYTES],
});

/// What firmware's AML reaches on this port: PCI configuration space, through the access
/// discovery enumerated with. Ports and memory are refused. Nothing QEMU's `_PRT` or link
/// devices read is there, and an address firmware names is not dereferenced on the boot path
/// until a machine shows the need.
struct Firmware<'a> {
    cfg: Option<&'a dyn ConfigSpace>,
}

/// The 32-bit configuration register holding `bits` bits at `offset`, and their shift in it.
/// `None` for an access that is wider than a register or spans two.
fn config_register(offset: u64, bits: u8) -> Option<(u16, u32)> {
    let register = offset & !3;
    let shift = (offset - register) * 8;
    if shift + u64::from(bits) > 32 || register >= 0x1000 {
        return None;
    }
    Some((register as u16, shift as u32))
}

impl aml::Host for Firmware<'_> {
    fn read(&mut self, space: Space, address: u64, bits: u8) -> Option<u64> {
        let Space::PciConfig {
            bus,
            device,
            function,
        } = space
        else {
            return None;
        };
        let (register, shift) = config_register(address, bits)?;
        let value = self
            .cfg?
            .read(Address::new(bus, device, function), register)
            >> shift;
        Some(u64::from(value) & ((1u64 << bits) - 1))
    }

    fn write(&mut self, space: Space, address: u64, bits: u8, value: u64) -> Option<()> {
        let Space::PciConfig {
            bus,
            device,
            function,
        } = space
        else {
            return None;
        };
        let (register, shift) = config_register(address, bits)?;
        let cfg = self.cfg?;
        let at = Address::new(bus, device, function);
        let mask = (((1u64 << bits) - 1) as u32) << shift;
        let old = cfg.read(at, register);
        cfg.write(at, register, (old & !mask) | (((value as u32) << shift) & mask));
        Some(())
    }
}

/// Route every PCI function's interrupt pin through the ACPI namespace: load the DSDT and
/// SSDTs, evaluate `\_PIC(1)`, and ask `_PRT` about each function that has a pin. Returns
/// how many routes it wrote into `out`.
///
/// A function `_PRT` routes nothing for is left out, and its driver polls. So is every
/// function on a machine whose AML cannot be loaded or run: that is reported, and it does not
/// fail discovery, since MSI-X and polling still work there.
pub(crate) fn pin_routes(
    c: &dyn EarlyConsole,
    tables: &Tables<'_, BootMemory>,
    cfg: Option<&dyn ConfigSpace>,
    functions: &[Function],
    out: &mut [(Address, PinRoute)],
) -> usize {
    // SAFETY: the one borrow; see `AML`'s invariant.
    let storage = unsafe { &mut *AML.get() };
    let storage = Storage {
        nodes: &mut storage.nodes,
        cells: &mut storage.cells,
        bytes: &mut storage.bytes,
    };
    let Ok(mut aml) = Interpreter::new(storage, Firmware { cfg }) else {
        c.write_str("; AML STORAGE TOO SMALL");
        return 0;
    };
    let dsdt = match tables.find(b"FACP") {
        Ok(Some(sdt)) => Fadt::parse(sdt).ok().map(|f| f.dsdt()),
        _ => None,
    };
    let Some(dsdt) = dsdt.filter(|&a| a != 0).and_then(|a| tables.read(a).ok()) else {
        c.write_str("; no DSDT, so no PCI pin is routed");
        return 0;
    };
    if let Err(e) = aml.load(dsdt) {
        c.write_str("; DSDT NOT LOADED: ");
        write_aml_error(c, e);
        return 0;
    }
    for sdt in tables.tables().flatten() {
        if sdt.signature() == *b"SSDT" {
            if let Err(e) = aml.load(sdt) {
                c.write_str("; SSDT NOT LOADED: ");
                write_aml_error(c, e);
            }
        }
    }
    c.write_str("; AML ");
    write_usize(c, aml.node_count());
    c.write_str(" nodes");
    match aml.select_apic_mode() {
        Ok(true) => c.write_str(", _PIC(1)"),
        Ok(false) => {}
        Err(e) => {
            c.write_str(", _PIC FAILED: ");
            write_aml_error(c, e);
            return 0;
        }
    }
    let mut n = 0;
    for f in functions.iter().filter(|f| f.interrupt_pin != 0) {
        let Some(slot) = out.get_mut(n) else {
            c.write_str(", MORE PINS THAN ROUTES KEPT");
            break;
        };
        let mut path = [(0u8, 0u8); 8];
        let Some((bus, hops)) = pci_path(functions, f, &mut path) else {
            continue;
        };
        match aml.route_pin(bus, &path[..hops], f.interrupt_pin) {
            Ok(r) => {
                let route = PinRoute {
                    gsi: r.gsi,
                    active_low: r.active_low,
                    level: r.level,
                };
                *slot = (f.address, route);
                n += 1;
            }
            Err(aml::Error::NoRoute) => {}
            Err(e) => {
                c.write_str("; ");
                write_address(c, f.address);
                c.write_str(" _PRT FAILED: ");
                write_aml_error(c, e);
            }
        }
    }
    c.write_str(", ");
    write_usize(c, n);
    c.write_str(" pins routed");
    n
}

/// The `(device, function)` of each bridge from the host bridge down to `f`, then `f`'s own,
/// and the bus the first of them is on. `None` past eight levels.
fn pci_path(functions: &[Function], f: &Function, path: &mut [(u8, u8); 8]) -> Option<(u8, usize)> {
    let mut chain = [f.address; 8];
    let mut len = 0;
    let mut at = f;
    loop {
        *chain.get_mut(len)? = at.address;
        len += 1;
        match at.parent {
            Some(parent) => at = functions.get(usize::from(parent))?,
            None => break,
        }
    }
    for (slot, a) in path.iter_mut().zip(chain[..len].iter().rev()) {
        *slot = (a.device, a.function);
    }
    Some((chain[len - 1].bus, len))
}

fn write_aml_error(c: &dyn EarlyConsole, e: aml::Error) {
    let (what, offset) = match e {
        aml::Error::UnknownOpcode { offset, opcode, .. } => {
            c.write_str("unknown opcode ");
            write_hex(c, u64::from(opcode));
            (" at ", Some(offset))
        }
        aml::Error::Unsupported { offset, .. } => ("unsupported construct at ", Some(offset)),
        aml::Error::Truncated { offset, .. } => ("truncated at ", Some(offset)),
        aml::Error::AlreadyExists { offset, .. } => ("a name declared twice at ", Some(offset)),
        aml::Error::NotFound => ("a name that resolves to nothing", None),
        aml::Error::WrongType => ("an object of the wrong type", None),
        aml::Error::BadIndex => ("an index out of range", None),
        aml::Error::DivideByZero => ("a division by zero", None),
        aml::Error::NoNodes => ("out of namespace nodes", None),
        aml::Error::NoMemory => ("out of package and buffer storage", None),
        aml::Error::TooManyTables => ("too many tables", None),
        aml::Error::NotAml => ("not a DSDT or SSDT", None),
        aml::Error::Budget => ("out of steps", None),
        aml::Error::TooDeep => ("nested too deep", None),
        aml::Error::Host => ("a field access refused", None),
        aml::Error::BadResource => ("a malformed resource template", None),
        aml::Error::NoRoute => ("no route", None),
    };
    c.write_str(what);
    if let Some(offset) = offset {
        write_hex(c, u64::from(offset));
    }
}

/// Program the I/O APIC entry for a PCI pin's `route`, delivering on device line `line`'s
/// vector to the boot CPU, masked or not. `false` when the line has no vector, or no I/O APIC
/// entry takes the GSI.
pub(crate) fn route_pin(line: u32, route: &PinRoute, masked: bool) -> bool {
    let (Some(vector), Some(chip)) = (arch::interrupt::msi_vector(line), apic::installed()) else {
        return false;
    };
    chip.route_gsi(route.gsi, vector, route.active_low, route.level, masked)
}

/// Read back the I/O APIC entry [`route_pin`] programmed for `line`, and say what in it is
/// not what `route` asked for.
pub(crate) fn check_pin(line: u32, route: &PinRoute) -> Result<(), &'static str> {
    let chip = apic::installed().ok_or("NO I/O APIC IS INSTALLED")?;
    let vector = arch::interrupt::msi_vector(line).ok_or("THE LINE HAS NO VECTOR")?;
    let entry = chip
        .redirection_entry(route.gsi)
        .ok_or("NO I/O APIC SERVES THE GSI")?;
    if entry.vector != vector {
        return Err("THE I/O APIC ENTRY NAMES ANOTHER VECTOR");
    }
    if u32::from(entry.destination) != chip.boot_id() & 0xff {
        return Err("THE I/O APIC ENTRY NAMES ANOTHER CPU");
    }
    if entry.masked {
        return Err("THE I/O APIC ENTRY IS MASKED");
    }
    if entry.level != route.level {
        return Err("THE I/O APIC ENTRY HAS THE WRONG TRIGGER");
    }
    if entry.active_low != route.active_low {
        return Err("THE I/O APIC ENTRY HAS THE WRONG POLARITY");
    }
    Ok(())
}

/// Whether a PCI function's message-signalled interrupts can be delivered.
///
/// Yes: the message is a write to a local APIC's address naming one CPU and a vector, so it
/// needs no route through the I/O APIC and no `_PRT`.
pub(crate) const MSI: bool = true;

/// The device lines message-signalled interrupts are dispatched on.
pub(crate) const MSI_LINES: core::ops::Range<u32> = arch::interrupt::MSI_LINES;

/// The `(address, data)` that delivers device line `line` to CPU `cpu`: that CPU's local
/// APIC, on the line's vector. `None` for a line that is not a message-signalled one, a CPU
/// that has not reported its APIC ID, or an ID the message format cannot carry.
pub(crate) fn msi_message(line: u32, cpu: usize) -> Option<(u64, u32)> {
    let vector = arch::interrupt::msi_vector(line)?;
    // The boot CPU's ID is the controller's to know; a secondary's is recorded when it
    // reports in.
    let apic_id = if cpu == 0 {
        apic::installed()?.boot_id()
    } else {
        arch::smp::apic_id(cpu)?
    };
    apic::msi::message(apic_id, vector)
}

/// Every driver this image carries.
pub(crate) const DRIVERS: &[&dyn Driver] = &[
    &apic::LOCAL_DRIVER,
    &apic::IO_DRIVER,
    &ECAM,
    &uart16550::DRIVER,
    &virtio_blk::DRIVER,
    &virtio_net::DRIVER,
];

/// Build the controller from what bound and install it and its timer. Returns whether that
/// worked, or whether there was legitimately nothing to install.
///
/// A machine whose firmware has no MADT at all has no APIC to find, and keeps the 8259A.
/// One whose MADT describes APICs that cannot be installed fails the boot: running on the
/// 8259A there would pass every check that does not start a second CPU, and hide why.
///
/// # Safety
/// Once, from `discover`, with interrupts masked on the boot identity map, after the
/// drivers probed. The claimed windows are mapped there and in the kernel's own space.
pub(crate) unsafe fn install(c: &dyn EarlyConsole, facts: Option<&MadtFacts>) -> bool {
    let Some(facts) = facts else {
        c.write_str("; NO MADT RECORD");
        return false;
    };
    if facts.cpu_count == 0 {
        c.write_str("; no processors described, staying on the 8259A");
        return true;
    }
    if facts.overrides_dropped {
        c.write_str("; AN INTERRUPT SOURCE OVERRIDE DID NOT FIT");
        return false;
    }
    let vectors = apic::Vectors {
        irq_base: arch::pic::VECTOR_BASE,
        timer: arch::interrupt::TIMER_VECTOR,
        spurious: arch::interrupt::SPURIOUS_VECTOR,
    };
    // SAFETY: the caller's contract is `install`'s.
    let chip =
        match unsafe { apic::install(facts.overrides(), vectors, arch::clock_source(), true) } {
            Ok(chip) => chip,
            Err(e) => {
                c.write_str("; APIC NOT INSTALLED: ");
                c.write_str(match e {
                    apic::InstallError::NoLocalApic => "no local APIC",
                    apic::InstallError::NoIoApic => "no I/O APIC",
                    apic::InstallError::Unaddressable => "a window is unaddressable",
                    apic::InstallError::Refused => "the local APIC refused its mode",
                    apic::InstallError::Again => "installed twice",
                });
                return false;
            }
        };
    // SAFETY: once, masked, single-threaded, and `chip` is initialised: the contracts of
    // both. Its timer interrupt arrives on `TIMER_VECTOR`, which it was just given.
    unsafe {
        arch::interrupt::set_chip(chip);
        arch::tick::set_event_timer(chip);
    }
    c.write_str("; APIC ");
    c.write_str(if apic::is_x2apic(chip) {
        "x2APIC"
    } else {
        "MMIO"
    });
    c.write_str(", boot ID ");
    write_usize(c, chip.boot_id() as usize);
    c.write_str(", ");
    write_usize(c, facts.override_count);
    c.write_str(" overrides, timer ");
    if chip.rate() == 0 {
        c.write_str("UNCALIBRATED");
        return false;
    }
    write_usize(c, chip.rate() as usize);
    c.write_str("/s");
    true
}

/// Start every other enabled processor, and check each. See `smp_x86_64.rs`.
///
/// # Safety
/// As `crate::start_secondaries`.
pub(crate) unsafe fn start_secondaries(c: &dyn EarlyConsole) -> Option<bool> {
    // SAFETY: forwarded.
    unsafe { crate::smp::start_secondaries(c) }
}

/// Whether secondary CPU `cpu` came up and is running.
pub(crate) fn secondary_online(cpu: usize) -> bool {
    cpu != 0 && arch::smp::is_online(cpu)
}

/// Run `f(arg)` on secondary CPU `cpu` through its function-call IPI. Boot path only, with
/// the boot CPU the only caller: see `arch::smp::call`.
pub(crate) fn call_on_secondary(cpu: usize, f: fn(u64) -> u64, arg: u64) -> Option<u64> {
    if !secondary_online(cpu) {
        return None;
    }
    arch::smp::call(cpu, f, arg)
}

//! `platform` for machines described by a flattened device tree.
//!
//! Boot asks a platform two things, in this order:
//!
//! 1. [`discover`] — before the kernel's own address space is built. Read the tree, bind every
//!    driver this image has to the nodes it matches, let each claim its resources, start them, and
//!    hand the interrupt controller to the architecture's interrupt path.
//! 2. [`device_windows`] — while the address space is built. The windows are exactly what the bound
//!    drivers claimed, so the kernel maps the device memory its drivers use and nothing else, and
//!    none of it is a constant.
//!
//! The ordering is the only subtle part. Discovery runs on the boot identity map, which
//! covers every device on this port, so starting drivers before the kernel's space exists
//! is safe; and it has to run first, because the space is built from its claims. The early
//! console never stops working across the switch because its window is one of the claims —
//! and [`discover`] refuses, visibly, if the tree puts the console somewhere other than
//! where the early console is writing, since the switch would otherwise unmap the only
//! thing that can report the failure.

#![no_std]
#![feature(sync_unsafe_cell)]

mod smp;

use core::cell::SyncUnsafeCell;

use device::driver::{self, best_match};
use device::{
    BootCell, Bound, DeviceTree, Driver, Fdt, Handlers, IrqClaim, MmioClaim, Node, Resources,
    Started,
};
use hal::paging::DeviceWindow;
use hal::{EarlyConsole, IrqChip, IrqNumber};
use sync::{LockClass, SpinLock};

/// Every driver this image carries, in the order ties between equally specific matches go.
///
/// The interrupt-controller drivers are the configuration's, not the architecture's: an
/// image built for one kind of machine can leave the other out, which is what lets
/// `IRQCHIP_STATIC` know there is only one possible answer. Leaving one out also means a
/// tree describing it binds nothing and the boot fails saying so, rather than the image
/// quietly dispatching through the wrong driver.
#[cfg(all(CONFIG_GIC_V2, CONFIG_GIC_V3))]
const DRIVERS: &[&dyn Driver] = &[
    &gic::v2::DRIVER,
    &gic::v3::DRIVER,
    &pl011::DRIVER,
    &virtio_blk::DRIVER,
];
#[cfg(all(CONFIG_GIC_V2, not(CONFIG_GIC_V3)))]
const DRIVERS: &[&dyn Driver] = &[&gic::v2::DRIVER, &pl011::DRIVER, &virtio_blk::DRIVER];
#[cfg(all(CONFIG_GIC_V3, not(CONFIG_GIC_V2)))]
const DRIVERS: &[&dyn Driver] = &[&gic::v3::DRIVER, &pl011::DRIVER, &virtio_blk::DRIVER];

/// The controller one of those drivers started, whichever kinds this image has.
#[cfg(all(CONFIG_GIC_V2, CONFIG_GIC_V3))]
fn started_chip() -> Option<&'static dyn hal::IrqChip> {
    gic::v2::chip().or_else(gic::v3::chip)
}
#[cfg(all(CONFIG_GIC_V2, not(CONFIG_GIC_V3)))]
fn started_chip() -> Option<&'static dyn hal::IrqChip> {
    gic::v2::chip()
}
#[cfg(all(CONFIG_GIC_V3, not(CONFIG_GIC_V2)))]
fn started_chip() -> Option<&'static dyn hal::IrqChip> {
    gic::v3::chip()
}

/// The IRQ vector's dispatch, instantiated for the one controller this image can have.
///
/// `arch` declares this symbol and calls it from the vector; see `arch/aarch64/src/irq.rs`.
/// This is the only place that can write it, because it is the only place that may name a
/// driver's type. A controller that was never started leaves the interrupt unacknowledged,
/// exactly as the dynamic path does with an empty slot.
#[cfg(all(CONFIG_IRQCHIP_STATIC, CONFIG_GIC_V3))]
#[unsafe(no_mangle)]
extern "C" fn kintane_irq_dispatch() {
    if let Some(chip) = gic::v3::chip_concrete() {
        arch::irq::dispatch_with(chip);
    }
}
#[cfg(all(CONFIG_IRQCHIP_STATIC, CONFIG_GIC_V2))]
#[unsafe(no_mangle)]
extern "C" fn kintane_irq_dispatch() {
    if let Some(chip) = gic::v2::chip_concrete() {
        arch::irq::dispatch_with(chip);
    }
}

/// Nodes in the tree. QEMU `virt` has 48; a large SoC tree a few hundred. Running out is
/// an error, never a partly-read tree.
const MAX_NODES: usize = 256;
/// Windows and interrupts bound drivers may claim between them.
const MAX_CLAIMS: usize = 16;
/// Devices bound at once.
const MAX_BOUND: usize = 8;

/// SAFETY INVARIANT: the three ledgers below are borrowed mutably exactly once, by
/// [`discover`], which runs once on the single-threaded boot path before anything else
/// can exist to observe them. Nothing reads them after it returns except through
/// [`WINDOWS`], which is a copy.
static NODES: SyncUnsafeCell<[Node<'static>; MAX_NODES]> =
    SyncUnsafeCell::new([Node::EMPTY; MAX_NODES]);
static MMIO: SyncUnsafeCell<[Option<MmioClaim>; MAX_CLAIMS]> =
    SyncUnsafeCell::new([None; MAX_CLAIMS]);
static IRQS: SyncUnsafeCell<[Option<IrqClaim>; MAX_CLAIMS]> =
    SyncUnsafeCell::new([None; MAX_CLAIMS]);

/// What the address space maps, set by [`discover`].
static WINDOWS: BootCell<([DeviceWindow; MAX_CLAIMS], usize)> = BootCell::new();

/// The register window granted to the isolated driver domain: an unoccupied `virtio,mmio`
/// slot, `(phys, len)`.
///
/// An *unoccupied* one on purpose. The domain is unprivileged code being handed real
/// device registers, and the point of the prototype is that it can reach those and nothing
/// else; granting it the slot the disk lives in would put the machine's storage behind that
/// claim. An empty slot answers the same identification registers (virtio 1.1 §4.2.2), so
/// the driver body reads real hardware either way. See `docs/isolation.md`.
static ISOLATION: BootCell<(u64, u64)> = BootCell::new();

/// The device model's interrupt handlers.
///
/// Registered on the boot path by [`discover`], and read by [`dispatch`] from the IRQ
/// vector on whichever CPU took the interrupt — so behind a lock, not a boot cell, even
/// though today nothing registers after boot: removal and a second binding change it, and
/// a handler table that is only safe while nobody changes it is a trap for the first
/// driver that does. Handlers run with the lock released; see `device::Handlers`.
static HANDLERS: SpinLock<Handlers<MAX_BOUND>, arch::Cpu> =
    SpinLock::with_class(Handlers::new(), &HANDLERS_CLASS);
static HANDLERS_CLASS: LockClass = LockClass::new("platform.handlers");

/// The console UART's receive line, once its handler is wired.
static CONSOLE_LINE: BootCell<IrqNumber> = BootCell::new();

/// Where this platform's devices come from, for the banner.
pub const SOURCE: &str = "device tree";

/// Read the tree, bind and start drivers, and install the interrupt controller.
///
/// Returns whether every check passed: a GIC and the console were both bound and
/// started, the console the tree names is the one the early console writes to, and the
/// timer interrupt the tree names is the one the architecture arms. `Some(false)` leaves
/// [`device_windows`] empty, so the kernel space is not built on a half-understood machine.
///
/// # Safety
/// Called once, from `kmain`, with interrupts masked, on the boot identity map, with
/// `boot_arg` as the boot code passed it — the contract of
/// `bootinfo::device_tree`, plus single-threaded boot for the ledgers and driver cells.
pub unsafe fn discover(c: &dyn EarlyConsole, boot_arg: u64) -> Option<bool> {
    // SAFETY: the caller passes `boot_arg` as the boot code left it, on the identity map.
    let blob = match unsafe { bootinfo::device_tree(boot_arg) } {
        Ok(b) => b,
        Err(_) => {
            c.write_str("no device tree");
            return Some(false);
        }
    };
    let fdt = match Fdt::new(blob) {
        Ok(f) => f,
        Err(e) => {
            c.write_str("malformed device tree at byte ");
            write_hex(c, e.offset() as u64);
            return Some(false);
        }
    };
    // SAFETY: the only borrows of these statics, once, on the boot path; see the invariant.
    let (nodes, mmio, irqs) = unsafe { (&mut *NODES.get(), &mut *MMIO.get(), &mut *IRQS.get()) };
    let tree = match DeviceTree::build(&fdt, nodes) {
        Ok(t) => t,
        Err(_) => {
            c.write_str("device tree too large to model");
            return Some(false);
        }
    };
    let mut resources = Resources::new(mmio, irqs);
    // SAFETY: once, on the boot path, as this function is.
    unsafe { smp::record(&tree) };

    write_usize(c, tree.len());
    c.write_str(" nodes;");

    // Probe everything first and start nothing until every claim is in: a start that ran
    // before a later probe's claim was refused would be driving hardware the ledger never
    // agreed was its.
    // Which memory-mapped virtio slot holds a block device. The tree lists every slot the
    // machine has, occupied or not, and only the slot's own registers say which is which:
    // this is enumeration, done here as `pci::enumerate` is, so that the driver's probe
    // keeps its rule of touching no hardware. See `virtio_blk::mmio`.
    let mut block_slot = None;
    let (mut slots, mut legacy) = (0usize, 0usize);
    for id in tree
        .ids()
        .filter(|&id| tree.node(id).is_compatible("virtio,mmio"))
    {
        slots += 1;
        let Ok((phys, len)) = tree.mmio(id, 0) else {
            continue;
        };
        let (Ok(base), Ok(len)) = (usize::try_from(phys), usize::try_from(len)) else {
            continue;
        };
        use virtio_blk::mmio::Slot;
        // SAFETY: discovery runs on the boot identity map, which maps every device on this
        // port, and the read is of the slot's identification registers only, which no
        // driver owns yet.
        match unsafe { virtio_blk::mmio::identify(base, len) } {
            Slot::Device { device_id } if device_id == virtio_blk::transport::DEVICE_ID_BLOCK => {
                block_slot = block_slot.or(Some(id));
            }
            Slot::Legacy { device_id } if device_id == virtio_blk::transport::DEVICE_ID_BLOCK => {
                legacy += 1;
            }
            // An empty slot is what the driver-isolation prototype is granted. Recorded
            // here because this loop is already reading every slot's registers, and the
            // first empty one is as good as any.
            Slot::Empty if kconfig::DRIVER_ISOLATION && ISOLATION.get().is_none() => {
                // SAFETY: once, on the boot path, before anything reads it.
                let _ = unsafe { ISOLATION.set((base as u64, len as u64)) };
            }
            _ => {}
        }
    }
    if slots > 0 && block_slot.is_none() && legacy > 0 {
        // Not a failure of discovery: the machine has a disk this driver will not drive.
        // Said here, because the block check can only report that no device was bound.
        c.write_str(" (a legacy virtio-blk slot, which the driver does not drive)");
    }

    let mut bound: [Option<(usize, Bound)>; MAX_BOUND] = [const { None }; MAX_BOUND];
    let mut ok = true;
    let mut n = 0;
    for id in tree.ids() {
        let Some((d, _)) = best_match(&tree, id, DRIVERS) else {
            continue;
        };
        // An empty slot, or one holding a device this image has no driver for.
        if tree.node(id).is_compatible("virtio,mmio") && Some(id) != block_slot {
            continue;
        }
        let Some(&drv) = DRIVERS.get(d) else { continue };
        c.write_str(" ");
        c.write_str(drv.name());
        c.write_str(" at ");
        c.write_bytes(tree.node(id).name());
        match driver::probe(drv, &tree, id, &mut resources) {
            Ok(b) if n < MAX_BOUND => {
                if let Some(slot) = bound.get_mut(n) {
                    *slot = Some((d, b));
                }
                n += 1;
            }
            Ok(b) => {
                c.write_str(" (TOO MANY DEVICES)");
                driver::remove(drv, b, &mut resources);
                ok = false;
            }
            Err(_) => {
                c.write_str(" (PROBE FAILED)");
                ok = false;
            }
        }
    }

    // Before anything starts. A console driver started on the tree's word, when the tree
    // disagrees with the early console, writes to an address nothing may be at: under
    // QEMU that is an external abort, reported through the console that just moved. Found
    // by booting a tree whose UART `reg` was edited, which hung rather than reported.
    let console_ok = console_agrees(c, &tree);
    ok &= console_ok;
    let console_node = tree.stdout();

    // Kept past start, because wiring a device's interrupt takes its `Started` token, and
    // the controller the lines are wired at is only installed below.
    let mut started: [Option<(usize, Started)>; MAX_BOUND] = [const { None }; MAX_BOUND];
    for (slot, (d, b)) in started
        .iter_mut()
        .zip(bound.iter_mut().filter_map(Option::take))
    {
        let Some(&drv) = DRIVERS.get(d) else { continue };
        if !console_ok && Some(b.node()) == console_node {
            continue;
        }
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

    // One interrupt controller, started.
    let chip = started_chip();
    match chip {
        Some(chip) => {
            // SAFETY: once, from `discover`'s single call, with interrupts masked, and the
            // controller was initialised by its driver's start — `set_chip`'s contract.
            unsafe { arch::irq::set_chip(chip) };
            // SAFETY: once, masked, and before `wire` enables any device line below.
            unsafe { arch::irq::set_device_dispatch(dispatch) };
            for (d, s) in started.iter().flatten() {
                let Some(&drv) = DRIVERS.get(*d) else {
                    continue;
                };
                let console = Some(s.bound().node()) == console_node;
                ok &= wire(c, chip, drv, s, console);
            }
        }
        None => {
            c.write_str("; NO INTERRUPT CONTROLLER BOUND");
            ok = false;
        }
    }

    ok &= timer_agrees(c, &tree);

    if ok {
        let mut windows = [DeviceWindow {
            phys: 0,
            len: 0,
            what: "",
        }; MAX_CLAIMS];
        let mut count = 0;
        for (slot, claim) in windows.iter_mut().zip(resources.mmio_claims()) {
            *slot = DeviceWindow {
                phys: claim.phys,
                len: claim.len,
                what: claim.what,
            };
            count += 1;
        }
        // The domain's granted window is mapped too: the kernel runs the same driver body
        // over it before handing it to the domain, and a window no driver claimed is in
        // nobody's ledger. It is last, so the claimed windows keep their numbering.
        if let Some(&(phys, len)) = ISOLATION.get() {
            if let Some(slot) = windows.get_mut(count) {
                *slot = DeviceWindow {
                    phys,
                    len,
                    what: "isolation slot",
                };
                count += 1;
            }
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

/// Look `number` up in the handler table and run what is registered, with the table's lock
/// released. What the architecture's interrupt path calls for every device line.
fn dispatch(number: IrqNumber) -> bool {
    let handler = HANDLERS.lock_irqsave().lookup(number);
    match handler {
        Some(handler) => {
            handler();
            true
        }
        None => false,
    }
}

/// Wire a started device's interrupt: translate its specifier with the GIC's binding,
/// register and enable its handler in the table, then unmask the line at the controller.
///
/// In that order, because each step is only meaningful after the one before: a line
/// unmasked before its handler is registered delivers into nothing, and the table refuses a
/// handler for a line the device does not hold.
fn wire(
    c: &dyn EarlyConsole,
    chip: &'static dyn IrqChip,
    drv: &dyn Driver,
    started: &Started,
    console: bool,
) -> bool {
    let Some((line, handler)) = drv.interrupt() else {
        return true;
    };
    let Ok(number) = gic::translate(line.specifier().cells()) else {
        c.write_str("; ");
        c.write_str(drv.name());
        c.write_str(" INTERRUPT NOT TRANSLATABLE");
        return false;
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
        return false;
    }
    chip.enable(number);
    if console {
        // SAFETY: once, on the single-threaded boot path.
        let _ = unsafe { CONSOLE_LINE.set(number) };
    }
    c.write_str("; ");
    c.write_str(drv.name());
    c.write_str(" receives on IRQ ");
    write_usize(c, number.0 as usize);
    true
}

/// The console UART's receive line, once its handler is wired.
pub fn console_line() -> Option<u32> {
    CONSOLE_LINE.get().map(|n| n.0)
}

/// Receive interrupts the console driver has taken, and the bytes they carried.
pub fn console_received() -> (u32, u32) {
    pl011::received()
}

/// The oldest byte the console's receive interrupt queued.
pub fn console_read() -> Option<u8> {
    pl011::read_byte()
}

/// Device interrupts dispatched to a handler, and ones that reached none.
pub fn device_interrupts() -> (u64, u64) {
    (arch::irq::device_irqs(), arch::irq::unhandled_irqs())
}

/// Unbind and rebind the console. `None`: the PL011 driver is the console on this port and
/// its state is write-once for the machine's life, so it is not taken away. The PCs'
/// 16550 driver is the one that is; see `kernel/platform/acpi`.
///
/// # Safety
/// None required; `unsafe` only so every provider has one signature.
pub unsafe fn rebind_console(_c: &dyn EarlyConsole) -> Option<bool> {
    None
}

/// Whether the console the tree names is bound and is the one the early console uses.
fn console_agrees(c: &dyn EarlyConsole, tree: &DeviceTree<'_, '_>) -> bool {
    let early = arch::serial::early_console_base();
    let named = tree
        .stdout()
        .and_then(|id| tree.mmio(id, 0).ok())
        .map(|(phys, _)| phys);
    // The probed window, not the started driver: this runs before anything starts.
    match (named, pl011::window()) {
        (Some(named), Some((bound, _))) if named == early && bound == early => true,
        (named, bound) => {
            c.write_str("; CONSOLE MISMATCH: the early console writes to ");
            write_hex(c, early);
            c.write_str(", the tree's stdout is ");
            match named {
                Some(p) => write_hex(c, p),
                None => c.write_str("not found"),
            }
            c.write_str(", the bound PL011 is ");
            match bound {
                Some((p, _)) => write_hex(c, p),
                None => c.write_str("absent"),
            }
            false
        }
    }
}

/// Whether the timer interrupt the tree names is the one `arch` arms.
fn timer_agrees(c: &dyn EarlyConsole, tree: &DeviceTree<'_, '_>) -> bool {
    let Some(timer) = tree
        .ids()
        .find(|&id| tree.node(id).is_compatible("arm,armv8-timer"))
    else {
        c.write_str("; NO arm,armv8-timer NODE");
        return false;
    };
    // The binding's second entry is the EL1 non-secure physical timer.
    const EL1_PHYSICAL: usize = 1;
    let named = tree
        .interrupt(timer, EL1_PHYSICAL)
        .ok()
        .and_then(|s| gic::translate(s.cells()).ok());
    if named == Some(hal::IrqNumber(arch::timer::PPI)) {
        return true;
    }
    c.write_str("; TIMER MISMATCH: arch arms ");
    write_usize(c, arch::timer::PPI as usize);
    c.write_str(", the tree names ");
    match named {
        Some(n) => write_usize(c, n.0 as usize),
        None => c.write_str("nothing usable"),
    }
    false
}

/// Device memory the kernel touches after its own tables are installed: every window a
/// bound driver claimed.
///
/// `None` until [`discover`] has succeeded. Not an empty list: a kernel space built with
/// no device windows on this port unmaps the console, and the first thing to notice would
/// be the report of it, which could not be printed.
pub fn device_windows() -> Option<&'static [DeviceWindow]> {
    WINDOWS.get().and_then(|(windows, n)| windows.get(..*n))
}

/// The register window the driver-isolation prototype may grant to a domain, `(phys, len)`.
///
/// `None` where nothing was recorded: a machine with no free `virtio,mmio` slot, or a
/// build without `DRIVER_ISOLATION`.
pub fn isolation_window() -> Option<(u64, u64)> {
    ISOLATION.get().copied()
}

/// Start the CPUs the tree lists beyond the boot CPU, and prove each one is a CPU of its
/// own: its own logical number, its own timer interrupts, an IPI answered from it, its own
/// per-CPU counter, and its own lock-order stack.
///
/// `None` on a build without SMP whose tree agrees with the run about how many CPUs there
/// are: nothing was started, so nothing was checked. `Some(false)` for any failure.
///
/// # Safety
/// Once, from `kmain`, on the boot CPU with interrupts masked, after the kernel address
/// space is installed and the interrupt path is up, and with no scheduler tick running.
pub unsafe fn start_secondaries(c: &dyn EarlyConsole) -> Option<bool> {
    // SAFETY: the caller's contract.
    unsafe { smp::start_secondaries(c) }
}

/// Whether CPU `cpu`, other than the boot CPU, came up and takes function calls.
pub fn secondary_online(cpu: usize) -> bool {
    cpu != 0 && arch::smp::is_online(cpu)
}

/// Run `f(arg)` on secondary CPU `cpu` from its function-call IPI, waiting up to a second
/// for the result.
///
/// `None` if that CPU is not online, or if `f` had not returned when the wait ended. A
/// function still running then goes on running, and nobody collects its result. Boot path
/// only, with the boot CPU the only caller: see `arch::smp::call`.
pub fn call_on_secondary(cpu: usize, f: fn(u64) -> u64, arg: u64) -> Option<u64> {
    if !secondary_online(cpu) {
        return None;
    }
    arch::smp::call(cpu, f, arg)
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

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
use device::{BootCell, Bound, DeviceTree, Driver, Fdt, IrqClaim, MmioClaim, Node, Resources};
use hal::EarlyConsole;
use hal::paging::DeviceWindow;

/// Every driver this image carries, in the order ties between equally specific matches go.
const DRIVERS: &[&dyn Driver] = &[&gic::v2::DRIVER, &gic::v3::DRIVER, &pl011::DRIVER];

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
    let mut bound: [Option<(usize, Bound)>; MAX_BOUND] = [const { None }; MAX_BOUND];
    let mut ok = true;
    let mut n = 0;
    for id in tree.ids() {
        let Some((d, _)) = best_match(&tree, id, DRIVERS) else {
            continue;
        };
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

    for (d, b) in bound.iter_mut().filter_map(Option::take) {
        let Some(&drv) = DRIVERS.get(d) else { continue };
        if !console_ok && Some(b.node()) == console_node {
            continue;
        }
        if let Err((_, why)) = driver::start(drv, b) {
            c.write_str("; ");
            c.write_str(drv.name());
            c.write_str(" did not start: ");
            c.write_str(why);
            ok = false;
        }
    }

    // One interrupt controller, started.
    let chip = gic::v2::chip().or_else(gic::v3::chip);
    match chip {
        // SAFETY: once, from `discover`'s single call, with interrupts masked, and the
        // controller was initialised by its driver's start — `set_chip`'s contract.
        Some(chip) => unsafe { arch::irq::set_chip(chip) },
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

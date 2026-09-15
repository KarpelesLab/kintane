//! Finding the PCI Express host bridge in the device tree (only with `PCIE`).
//!
//! Reading, and nothing else. This reports where configuration space is, which buses live
//! behind the bridge, what windows the bridge forwards, and which controller its messages
//! go to. No window is claimed, no register is touched, and nothing is enumerated.
//!
//! # Why reading is a stage of its own
//!
//! On this port configuration space cannot be read when this runs. Discovery happens on the
//! boot tables, which map `0x0000_0000..0x4000_0000` as one device block and
//! `0x4000_0000..0x8000_0000` as RAM — two gigabytes, and nothing above. QEMU's `virt` puts
//! the ECAM window at `0x40_1000_0000`, a quarter of a terabyte up, so the first
//! configuration read here would fault or, worse, alias something else. The PC does not have
//! this problem: its window sits below four gigabytes, inside the boot tables' device alias,
//! which is why `platform/acpi` enumerates during discovery and this cannot.
//!
//! What the tree says is readable now, though, and it is what decides whether enumeration is
//! worth attempting at all. So the bridge is described here and enumerated later, once the
//! kernel's own address space maps the window.
//!
//! # Why this matters beyond PCI
//!
//! The SMMUv3 this port discovers translates for the PCIe root complex and for nothing else
//! (`smmuv3.rs`). Every device on this port is a memory-mapped virtio slot, outside the
//! unit. A disk on PCIe is therefore the first device here whose DMA could be confined, and
//! this is the first step toward one. See `docs/isolation.md`.

use core::cell::SyncUnsafeCell;

use device::pci::{self, Address, ConfigSpace, Function};
use device::{DeviceTree, NodeId};
use hal::EarlyConsole;

use crate::{write_hex, write_usize};

/// What the tree says about the host bridge.
///
/// Every field comes from the tree. Nothing here was read from the hardware, because on this
/// port the hardware is not addressable yet.
#[derive(Clone, Copy)]
pub struct PcieFacts {
    /// The ECAM window, from the node's `reg`: configuration space for every bus in
    /// [`bus_start`](Self::bus_start)`..=`[`bus_end`](Self::bus_end).
    pub ecam_base: u64,
    pub ecam_len: u64,
    /// The buses behind this bridge, from `bus-range`.
    pub bus_start: u8,
    pub bus_end: u8,
    /// The bridge's forwarded windows, from `ranges`, as CPU physical `(base, len)`:
    /// I/O space, 32-bit memory, and 64-bit memory. `None` for a space the bridge does not
    /// forward.
    pub io: Option<(u64, u64)>,
    pub mem32: Option<(u64, u64)>,
    pub mem64: Option<(u64, u64)>,
    /// The phandle of the controller `msi-map` sends this bridge's messages to, and how many
    /// requester ids are mapped. `None` where the tree maps none, which would mean a device
    /// here could raise no message-signalled interrupt.
    pub msi: Option<(u32, u32)>,
}

impl PcieFacts {
    /// Bytes of configuration space one bus occupies: 32 devices x 8 functions x 4 KiB.
    pub const BUS_BYTES: u64 = 1 << 20;

    /// How many buses the window is big enough to address.
    ///
    /// The tree states the bus range and the window size separately, and a window too small
    /// for the range it claims would have enumeration read another bus's space — or nothing.
    pub fn buses_the_window_holds(&self) -> u64 {
        self.ecam_len / Self::BUS_BYTES
    }

    /// How many buses `bus-range` claims.
    pub fn buses_claimed(&self) -> u64 {
        u64::from(self.bus_end).saturating_sub(u64::from(self.bus_start)) + 1
    }
}

/// The facts, once [`discover`] has found a bridge.
///
/// SAFETY INVARIANT: written once by [`discover`] on the single-threaded boot path, read
/// only after.
static FACTS: device::BootCell<PcieFacts> = device::BootCell::new();

/// What discovery found, or `None` when the tree names no ECAM host bridge.
pub fn facts() -> Option<PcieFacts> {
    FACTS.get().copied()
}

/// One big-endian cell at `i` of a property's bytes.
fn cell(bytes: &[u8], i: usize) -> Option<u32> {
    let at = i * 4;
    let four: [u8; 4] = bytes.get(at..at + 4)?.try_into().ok()?;
    Some(u32::from_be_bytes(four))
}

/// Two cells at `i` and `i + 1` as one 64-bit value, most significant first.
fn cell64(bytes: &[u8], i: usize) -> Option<u64> {
    Some((u64::from(cell(bytes, i)?) << 32) | u64::from(cell(bytes, i + 1)?))
}

/// Find the bridge and record what the tree says about it.
///
/// Called from `discover` on the boot identity map. Unlike the SMMU, which is read there
/// because its registers sit in the first gigabyte, nothing here is read from hardware at
/// all — the window this describes is out of reach until the kernel's space exists.
pub fn discover(c: &dyn EarlyConsole, tree: &DeviceTree<'_, '_>) {
    let Some(id) = tree
        .ids()
        .find(|&id| tree.node(id).is_compatible("pci-host-ecam-generic"))
    else {
        return;
    };
    // `reg` is decoded with the *parent's* address cells, which is what `mmio` does: the
    // bridge's own `#address-cells` of three describe its children, not itself.
    let Ok((ecam_base, ecam_len)) = tree.mmio(id, 0) else {
        c.write_str("; a pci-host-ecam-generic node with no readable reg");
        return;
    };
    let (bus_start, bus_end) = match bus_range(tree, id) {
        Some(range) => range,
        None => {
            c.write_str("; a PCIe host bridge with no readable bus-range");
            return;
        }
    };
    let (io, mem32, mem64) = ranges(tree, id);
    let facts = PcieFacts {
        ecam_base,
        ecam_len,
        bus_start,
        bus_end,
        io,
        mem32,
        mem64,
        msi: msi_map(tree, id),
    };
    // SAFETY: once, on the boot path, before anything reads it.
    let _ = unsafe { FACTS.set(facts) };
    c.write_str(" pci-host-ecam-generic at ");
    write_hex(c, ecam_base);
    c.write_str(" (buses ");
    write_usize(c, bus_start as usize);
    c.write_str("-");
    write_usize(c, bus_end as usize);
    c.write_str(")");
}

/// The `bus-range` property: two cells, first and last bus behind the bridge.
fn bus_range(tree: &DeviceTree<'_, '_>, id: NodeId) -> Option<(u8, u8)> {
    let bytes = tree.property(id, b"bus-range")?;
    let first = cell(bytes, 0)?;
    let last = cell(bytes, 1)?;
    // A bus number is eight bits on the wire; a tree naming a wider one is describing
    // something this enumerator could not address.
    Some((u8::try_from(first).ok()?, u8::try_from(last).ok()?))
}

/// The `ranges` property, as `(io, mem32, mem64)` CPU physical windows.
///
/// Each entry is seven cells: three of child address, two of parent address — the root's
/// `#address-cells` — and two of size. The top byte of the child address says which space
/// the entry describes (IEEE 1275 PCI bus binding): `0x01` I/O, `0x02` 32-bit memory,
/// `0x03` 64-bit memory. The parent address is what the CPU uses, and the only part the
/// kernel needs.
fn ranges(
    tree: &DeviceTree<'_, '_>,
    id: NodeId,
) -> (Option<(u64, u64)>, Option<(u64, u64)>, Option<(u64, u64)>) {
    let (mut io, mut mem32, mut mem64) = (None, None, None);
    let Some(bytes) = tree.property(id, b"ranges") else {
        return (io, mem32, mem64);
    };
    const CELLS: usize = 7;
    for entry in 0..bytes.len() / (CELLS * 4) {
        let at = entry * CELLS;
        let (Some(space), Some(base), Some(len)) =
            (cell(bytes, at), cell64(bytes, at + 3), cell64(bytes, at + 5))
        else {
            continue;
        };
        let window = Some((base, len));
        match (space >> 24) & 0x3 {
            1 => io = window,
            2 => mem32 = window,
            3 => mem64 = window,
            _ => {}
        }
    }
    (io, mem32, mem64)
}

/// The `msi-map` entry: four cells, `<rid-base, phandle, msi-base, length>`.
///
/// Reported rather than used. A device here raises a message by writing the controller that
/// phandle names, and knowing the tree maps this bridge's requester ids to one at all is
/// what says an interrupt could be delivered were a device enumerated.
fn msi_map(tree: &DeviceTree<'_, '_>, id: NodeId) -> Option<(u32, u32)> {
    let bytes = tree.property(id, b"msi-map")?;
    Some((cell(bytes, 1)?, cell(bytes, 3)?))
}

/// A claim-only driver for the host bridge.
///
/// It takes the ECAM window and drives nothing, which is the whole job: a window no driver
/// claimed is in nobody's ledger, and the kernel's address space would not map it. The same
/// shape `platform/acpi` uses for the bridge it finds through the MCFG.
pub struct Ecam;

impl device::Driver for Ecam {
    fn name(&self) -> &'static str {
        "ecam"
    }

    fn compatible(&self) -> &'static [&'static str] {
        &["pci-host-ecam-generic"]
    }

    fn probe(
        &self,
        probe: &mut device::driver::Probe<'_, '_, '_, '_>,
    ) -> Result<(), device::driver::ProbeError> {
        probe.claim_mmio(0, "PCI Express configuration space")?;
        Ok(())
    }

    fn start(&self, _bound: &device::Bound) -> Result<(), &'static str> {
        Ok(())
    }
}

pub static DRIVER: Ecam = Ecam;

/// Configuration space through the ECAM window.
///
/// Usable only once the kernel's address space maps the claim above. During discovery this
/// window is a quarter of a terabyte beyond what the boot tables reach, which is why the walk
/// is a later stage than discovery on this port.
struct Window {
    base: u64,
}

impl Window {
    /// The register at `offset` of `at`, as an address in the device window.
    ///
    /// ECAM addressing is the same arithmetic everywhere: a bus is a megabyte, a device
    /// thirty-two kilobytes, a function four.
    fn register(&self, at: Address, offset: u16) -> Option<*mut u32> {
        if offset % 4 != 0 || u64::from(offset) >= 4096 {
            return None;
        }
        let within = (u64::from(at.bus) << 20)
            | (u64::from(at.device) << 15)
            | (u64::from(at.function) << 12)
            | u64::from(offset);
        let virt = hal::paging::device_virt(self.base.checked_add(within)?)?;
        Some(core::ptr::with_exposed_provenance_mut(virt))
    }
}

#[allow(unsafe_code)]
impl ConfigSpace for Window {
    fn read(&self, at: Address, offset: u16) -> u32 {
        match self.register(at, offset) {
            // SAFETY: an aligned register inside the window the bridge's `reg` named and the
            // `ecam` driver claimed, which the kernel's space maps at `DEVICE_WINDOW_BASE`
            // above its physical address. Reading the standard header has no side effects.
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

/// What walking the bus found.
#[derive(Clone, Copy)]
pub struct PcieScan {
    /// Functions found, host bridges included.
    pub functions: usize,
    /// How many of them are host bridges.
    pub bridges: usize,
    /// Functions that are not host bridges: what the command line attached behind it.
    ///
    /// A bridge presents its own function whether or not anything is plugged in, so the
    /// count of functions alone cannot say whether a device is there. This can.
    pub endpoints: usize,
    /// The buffer filled before the walk finished, so there may be more.
    pub truncated: bool,
    /// Every base address register read back as enumeration left it.
    pub restored: bool,
}

/// Room for what `virt` can present: the bridge's own function and whatever the command line
/// attaches. Far more than either, and small enough to sit in the image rather than on the
/// boot stack, which a `Function` array of this width would overrun.
const MAX_FUNCTIONS: usize = 32;

/// SAFETY INVARIANT: written once by [`enumerate`] on the single-threaded boot path.
static FUNCTIONS: SyncUnsafeCell<[Function; MAX_FUNCTIONS]> =
    SyncUnsafeCell::new([Function::EMPTY; MAX_FUNCTIONS]);

/// Walk the buses behind the bridge and report what is there.
///
/// Called from the check phase rather than from `discover`, because only by then does the
/// kernel's address space map the window this reads. `None` where no bridge was found, which
/// is a build that asked for PCIe on a machine without one.
#[allow(unsafe_code)]
pub fn enumerate(c: &dyn EarlyConsole) -> Option<PcieScan> {
    let f = facts()?;
    let cfg = Window { base: f.ecam_base };
    // SAFETY: once, on the boot path, single-threaded, and nothing else reads this.
    let out = unsafe { &mut *FUNCTIONS.get() };
    let (n, truncated) = match pci::enumerate(&cfg, f.bus_start, f.bus_end, out) {
        Ok(n) => (n, false),
        // More functions than the buffer holds is not a failure of the bus: what was found
        // is still what is there, and the report says the rest went unseen.
        Err(pci::Error::TooManyFunctions { .. }) => (out.len(), true),
        Err(_) => {
            c.write_str("; the bus could not be walked");
            return None;
        }
    };
    let found = out.get(..n).unwrap_or(&[]);
    Some(PcieScan {
        functions: n,
        bridges: found.iter().filter(|f| f.is_host_bridge()).count(),
        endpoints: found.iter().filter(|f| !f.is_host_bridge()).count(),
        truncated,
        restored: pci::verify_restored(&cfg, found).is_ok(),
    })
}

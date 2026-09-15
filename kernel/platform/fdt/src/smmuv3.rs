//! Finding an Arm SMMUv3 in the device tree and reading what it can do (only with `SMMUV3`).
//!
//! Discovery, and nothing else. This reports the unit and what the tree says it translates
//! for; it programs no stream table and confines no device.
//!
//! The reason it stops there is a fact about the machine, not a missing piece of code. On
//! QEMU's `virt` the SMMU is wired to the PCIe root complex alone: `iommu-map` appears on
//! `pcie@10000000` and on no other node, and the memory-mapped virtio slots this port's disk
//! lives in carry no `iommus` property at all. So there is no device on this port whose DMA
//! the unit could translate, and confining one would mean first putting it on PCIe. That is
//! recorded here as something the boot *checks* rather than a sentence in a document,
//! because it is the reason the next stage is not built — and because the day QEMU wires a
//! virtio slot behind the SMMU, the check fails and says so. See `docs/isolation.md`.

use device::{DeviceTree, NodeId};
use hal::EarlyConsole;

use crate::{write_hex, write_usize};

/// Register offsets in the unit's page 0, Arm IHI 0070 §6.3.
mod reg {
    /// Features: translation stages, table formats, coherency.
    pub const IDR0: usize = 0x00;
    /// Sizes: the stream id width among them.
    pub const IDR1: usize = 0x04;
    /// Granules the unit supports, and its output address size.
    pub const IDR5: usize = 0x14;
    /// The architecture revision.
    pub const AIDR: usize = 0x1c;
}

/// What the tree and the unit's own registers say about the SMMUv3.
///
/// Read once, at discovery, on the boot identity map — the same way the virtio slots are
/// identified before any driver is bound.
#[derive(Clone, Copy)]
pub struct SmmuFacts {
    /// The unit's register window, from the node's `reg`.
    pub register_base: u64,
    pub register_len: u64,
    /// `IDR0`, `IDR1`, `IDR5` and `AIDR` as they read at discovery.
    pub idr0: u32,
    pub idr1: u32,
    pub idr5: u32,
    pub aidr: u32,
    /// The `iommu-map` entry naming this unit: `(rid_base, stream_base, length)`. `None`
    /// when no node maps stream ids to it, which would mean it translates for nothing.
    pub map: Option<(u32, u32, u32)>,
    /// How many `virtio,mmio` slots the tree puts behind an IOMMU, and how many there are.
    ///
    /// The first number is the one that matters: this port's disk is one of these slots, so
    /// while it is zero, no disk here can be confined however well the unit works.
    pub mmio_behind: usize,
    pub mmio_slots: usize,
}

impl SmmuFacts {
    /// Stream id bits the unit supports, `IDR1.SIDSIZE`.
    pub fn stream_id_bits(&self) -> u32 {
        self.idr1 & 0x3f
    }
    /// Whether stage 1 translation is implemented, `IDR0.S1P`.
    pub fn stage1(&self) -> bool {
        self.idr0 & (1 << 1) != 0
    }
    /// Whether stage 2 translation is implemented, `IDR0.S2P`.
    pub fn stage2(&self) -> bool {
        self.idr0 & 1 != 0
    }
    /// Whether the unit walks tables with the kernel's 4 KiB granule, `IDR5.GRAN4K`.
    pub fn granule_4k(&self) -> bool {
        self.idr5 & (1 << 4) != 0
    }
    /// Whether the unit supports a 64 KiB granule, `IDR5.GRAN64K`.
    pub fn granule_64k(&self) -> bool {
        self.idr5 & (1 << 6) != 0
    }
    /// The output address size `IDR5.OAS` encodes, in bits.
    pub fn output_bits(&self) -> u32 {
        match self.idr5 & 0x7 {
            0 => 32,
            1 => 36,
            2 => 40,
            3 => 42,
            4 => 44,
            5 => 48,
            6 => 52,
            _ => 0,
        }
    }
}

/// The facts, once [`discover`] has found a unit.
///
/// SAFETY INVARIANT: written once by [`discover`] on the single-threaded boot path, read
/// only after.
static FACTS: device::BootCell<SmmuFacts> = device::BootCell::new();

/// What discovery found, or `None` when the tree names no SMMUv3.
pub fn facts() -> Option<SmmuFacts> {
    FACTS.get().copied()
}

/// One big-endian cell at `i` of a property's bytes.
fn cell(bytes: &[u8], i: usize) -> Option<u32> {
    let at = i * 4;
    let four: [u8; 4] = bytes.get(at..at + 4)?.try_into().ok()?;
    Some(u32::from_be_bytes(four))
}

/// A register in the unit's page 0, read on the boot identity map.
#[allow(unsafe_code)]
fn read32(base: usize, offset: usize) -> u32 {
    // SAFETY: discovery runs on the boot tables, whose device alias maps every device on
    // this port at `DEVICE_WINDOW_BASE` above its physical address; `base` is that alias of
    // the window the tree gave, and `offset` is one of the fixed identification registers,
    // all inside its first 4 KiB page. Volatile: these are hardware registers.
    unsafe { core::ptr::with_exposed_provenance_mut::<u32>(base + offset).read_volatile() }
}

/// Find the unit, read it, and report what it covers.
///
/// Called from `discover` on the boot identity map, before the kernel's own address space
/// exists — so no window has to be claimed and no driver bound, exactly as the virtio slots
/// are identified. Nothing is programmed.
pub fn discover(c: &dyn EarlyConsole, tree: &DeviceTree<'_, '_>) {
    let Some(id) = tree
        .ids()
        .find(|&id| tree.node(id).is_compatible("arm,smmu-v3"))
    else {
        return;
    };
    let Ok((register_base, register_len)) = tree.mmio(id, 0) else {
        c.write_str("; an arm,smmu-v3 node with no readable reg");
        return;
    };
    let Some(base) = hal::paging::device_virt(register_base) else {
        c.write_str("; the SMMU register window is outside the device window");
        return;
    };
    let facts = SmmuFacts {
        register_base,
        register_len,
        idr0: read32(base, reg::IDR0),
        idr1: read32(base, reg::IDR1),
        idr5: read32(base, reg::IDR5),
        aidr: read32(base, reg::AIDR),
        map: iommu_map_to(tree, id),
        mmio_behind: mmio_slots_behind(tree),
        mmio_slots: tree
            .ids()
            .filter(|&id| tree.node(id).is_compatible("virtio,mmio"))
            .count(),
    };
    // SAFETY: once, on the boot path, before anything reads it.
    let _ = unsafe { FACTS.set(facts) };
    c.write_str(" arm,smmu-v3 at ");
    write_hex(c, register_base);
    c.write_str(" (");
    write_usize(c, facts.stream_id_bits() as usize);
    c.write_str("-bit stream ids)");
}

/// The `iommu-map` entry naming the unit at `smmu`, from whichever node carries one.
///
/// The property is four cells — `<rid-base, phandle, stream-base, length>` — and lives on
/// the bus whose devices are translated, not on the unit. On `virt` that is the PCIe host
/// bridge and only it.
fn iommu_map_to(tree: &DeviceTree<'_, '_>, smmu: NodeId) -> Option<(u32, u32, u32)> {
    let phandle = tree.node(smmu).phandle()?;
    for id in tree.ids() {
        let Some(bytes) = tree.property(id, b"iommu-map") else {
            continue;
        };
        // One entry is all `virt` writes. A tree with several would need each walked; this
        // reports the one naming our unit, which is what the check asks about.
        let (Some(rid), Some(named), Some(stream), Some(len)) =
            (cell(bytes, 0), cell(bytes, 1), cell(bytes, 2), cell(bytes, 3))
        else {
            continue;
        };
        if named == phandle {
            return Some((rid, stream, len));
        }
    }
    None
}

/// How many `virtio,mmio` slots the tree puts behind an IOMMU.
///
/// Zero on `virt`: QEMU wires the SMMU to the PCIe root complex and leaves the
/// memory-mapped transport alone. The count is taken rather than assumed, because it is the
/// single fact that decides whether a disk on this port could be confined at all.
fn mmio_slots_behind(tree: &DeviceTree<'_, '_>) -> usize {
    tree.ids()
        .filter(|&id| tree.node(id).is_compatible("virtio,mmio"))
        .filter(|&id| tree.property(id, b"iommus").is_some())
        .count()
}

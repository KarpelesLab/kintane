//! The boot's check of the Arm SMMUv3 the platform discovered (only with `SMMUV3`).
//!
//! Discovery is the whole of it: the unit is found, its identification registers are read,
//! and what the tree says it translates for is reported. Nothing is programmed, so nothing
//! here confines a device — `docs/isolation.md` records why, and the last check below is
//! that reason in executable form.
//!
//! The check that matters is the one about coverage. This port's disk is a memory-mapped
//! virtio slot, and on QEMU's `virt` the SMMU is wired to the PCIe root complex alone, so no
//! disk here is behind it however well the unit works. Asserting that keeps the claim honest
//! in both directions: while it holds, the next stage is known to be unreachable; the day
//! QEMU puts a virtio slot behind the SMMU, this check fails and says the topology changed.

use hal::EarlyConsole;

use crate::{Check, write_usize};

/// Report the unit and gate the boot on the discovery being coherent.
///
/// Passes when a unit was found, its registers read back as an SMMUv3 that could translate
/// (a stage, the kernel's granule, stream ids at least as wide as the tree maps), and the
/// tree maps stream ids to it. Fails when a build that asked for an SMMU has none, or when
/// what it reads back could not be programmed.
pub fn check(c: &dyn EarlyConsole) -> Check {
    c.write_str("\n  smmu       ");
    let Some(f) = platform::smmu() else {
        c.write_str("NO arm,smmu-v3 NODE ON A BUILD THAT ASKED FOR ONE");
        return Check::Failed;
    };
    // All ones is an unmapped read on this port; zero would mean a unit implementing no
    // feature at all. Either way the window is not an SMMUv3's.
    if f.idr0 == 0 || f.idr0 == u32::MAX {
        c.write_str("THE SMMU'S REGISTERS DID NOT READ BACK AS AN SMMUv3");
        return Check::Failed;
    }
    if !f.stage1() && !f.stage2() {
        c.write_str("THE SMMU IMPLEMENTS NEITHER TRANSLATION STAGE");
        return Check::Failed;
    }
    if !f.granule_4k() {
        c.write_str("THE SMMU DOES NOT WALK TABLES WITH THE KERNEL'S 4 KiB GRANULE");
        return Check::Failed;
    }
    let Some((_, _, length)) = f.map else {
        c.write_str("NO NODE MAPS STREAM IDS TO THE SMMU, SO IT TRANSLATES FOR NOTHING");
        return Check::Failed;
    };
    // The unit must be able to name every stream id the tree hands it, or the mapping
    // describes devices it could not tell apart.
    if (1u64 << f.stream_id_bits()) < u64::from(length) {
        c.write_str("THE SMMU NAMES FEWER STREAM IDS THAN THE TREE MAPS TO IT");
        return Check::Failed;
    }
    write_usize(c, f.stream_id_bits() as usize);
    c.write_str("-bit stream ids, ");
    c.write_str(if f.granule_64k() {
        "4K and 64K granules, "
    } else {
        "4K granules, "
    });
    write_usize(c, f.output_bits() as usize);
    c.write_str("-bit output; the tree maps ");
    write_usize(c, length as usize);
    c.write_str(" ids to it from the PCIe root complex; ");
    // The coverage fact, and the reason confinement stops here.
    if f.mmio_behind > 0 {
        write_usize(c, f.mmio_behind);
        c.write_str(" of ");
        write_usize(c, f.mmio_slots);
        c.write_str(" virtio-mmio slots ARE BEHIND IT: the machine now translates for the");
        c.write_str(" transport this port's disk uses, so confinement is reachable and this");
        c.write_str(" check is out of date");
        return Check::Failed;
    }
    c.write_str("none of ");
    write_usize(c, f.mmio_slots);
    c.write_str(" virtio-mmio slots is behind it, so no disk here is translated");
    Check::Passed
}

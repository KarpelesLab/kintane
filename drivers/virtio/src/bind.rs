//! What a virtio driver's probe claims, whichever bus the device is on.
//!
//! The same for every device type: the register window, and the interrupt if one can be had
//! (an MSI-X vector where the platform delivers messages, otherwise a line). What those
//! registers become differs by bus, and a PCI function's layout has to be read at probe,
//! while the node still borrows the enumeration record. [`Claims`] keeps all of it, and
//! [`Claims::transport`] builds the transport later, once the kernel has mapped the window.
//!
//! This was virtio-blk's probe, moved unchanged apart from taking the device type and the
//! claims' names as arguments.

use device::{IrqLine, Mmio as MmioClaim, Probe, ProbeError};

use crate::mem::Window;
use crate::{AnyTransport, mmio, pci};

/// What the probe claimed, kept for bring-up.
///
/// `bus` is what the probe learned about where the registers are, which differs by
/// transport: a memory-mapped slot is the claimed window itself, and a PCI function is
/// that window plus the layout its capabilities described, since the driver cannot read
/// configuration space once the enumerator is gone.
pub struct Claims {
    mmio: MmioClaim,
    /// The window the MSI-X table is in, when it is not the registers' BAR. Claimed for the
    /// platform, which programs the table through it.
    table: Option<MmioClaim>,
    irq: Option<IrqLine>,
    bus: Bus,
}

/// Which transport the bound device is on, and what it takes to build it.
enum Bus {
    Mmio,
    Pci {
        layout: pci::Layout,
        bar: u8,
        device_id: u32,
    },
}

impl Claims {
    /// Claim the bound node's register window and interrupt for a device of type
    /// `device_id`, naming the window `what` and an MSI-X table window `table_what`.
    pub fn claim(
        p: &mut Probe<'_, '_, '_, '_>,
        what: &'static str,
        table_what: &'static str,
        device_id: u32,
    ) -> Result<Claims, ProbeError> {
        // Which transport this is comes from the node, not from a guess: a PCI function
        // carries the record enumeration made, and a memory-mapped slot does not.
        let function = match p.tree().node(p.node()).origin() {
            device::Origin::Pci(f) => Some(f),
            _ => None,
        };
        let (mmio, bus) = match function {
            Some(f) => {
                let layout = pci::Layout::read(f).map_err(|_| {
                    ProbeError::Declined("no modern virtio structures in the capability list")
                })?;
                // Every structure must be in one BAR, because one window is what a probe
                // claims and therefore what the kernel maps. QEMU's virtio-pci puts all
                // four in the same BAR; a device that spreads them is refused rather than
                // half-driven.
                let bar = layout.common.bar;
                if layout.bars().iter().any(|b| *b != bar) {
                    return Err(ProbeError::Declined(
                        "the device's structures are spread over several BARs",
                    ));
                }
                let index = f
                    .memory_bar_index(bar)
                    .ok_or(ProbeError::Declined("the structures' BAR decodes no memory"))?;
                let mmio = p.claim_mmio(index, what)?;
                let bus = Bus::Pci {
                    layout,
                    bar,
                    device_id,
                };
                (mmio, bus)
            }
            None => {
                let mmio = p.claim_mmio(0, what)?;
                if mmio.len() < mmio::MIN_WINDOW {
                    return Err(ProbeError::Declined("the window is too small for virtio-mmio"));
                }
                (mmio, Bus::Mmio)
            }
        };
        // The interrupt, best first. MSI-X where the platform delivers messages and the
        // function has a table: it needs no route, and its entry can name any CPU. The table
        // is programmed by the platform through a window this probe claimed, so its BAR is
        // claimed too when it is not the registers' BAR (QEMU puts it in BAR 1, the
        // structures in BAR 4). Otherwise the line.
        //
        // A device whose interrupt is malformed or taken can still be polled, so an
        // interrupt that cannot be claimed is not a reason to refuse the device.
        let mut table = None;
        let mut irq = None;
        if let (Some(f), Bus::Pci { bar, .. }) = (function, &bus) {
            if let Some(cap) = device::msi::msix(f).filter(|_| p.msi_available()) {
                let reachable = if cap.table_bar == *bar {
                    true
                } else if let Some(index) = f.memory_bar_index(cap.table_bar) {
                    table = Some(p.claim_mmio(index, table_what)?);
                    true
                } else {
                    false
                };
                if reachable {
                    irq = p.claim_msi(0).ok();
                }
            }
        }
        let irq = match irq {
            Some(vector) => Some(vector),
            None => p.claim_irq(0).ok(),
        };
        Ok(Claims {
            mmio,
            table,
            irq,
            bus,
        })
    }

    /// The claimed window, as a physical `(address, length)`.
    pub fn window(&self) -> (u64, u64) {
        (self.mmio.phys(), self.mmio.len())
    }

    /// The claimed interrupt, a line or an MSI-X vector, if one was.
    pub fn irq(&self) -> Option<&IrqLine> {
        self.irq.as_ref()
    }

    /// The MSI-X table entry the interrupt was claimed as, if it was one: what a driver's
    /// bring-up is given once the platform has wired it.
    pub fn msix_entry(&self) -> Option<u16> {
        let line = self.irq.as_ref()?;
        device::msi::vector_of(line.specifier().cells())
    }

    /// The window claimed for the MSI-X table, as a physical `(address, length)`, when it
    /// is not the registers' window.
    pub fn msix_table_window(&self) -> Option<(u64, u64)> {
        self.table.as_ref().map(|t| (t.phys(), t.len()))
    }

    /// The transport for the claimed device, of whichever kind its bus is.
    ///
    /// Reached through [`hal::paging::device_virt`] of the window's physical address, never at
    /// the physical address itself.
    ///
    /// # Safety
    /// The claimed window must be mapped, as device memory, at
    /// [`hal::paging::DEVICE_WINDOW_BASE`] above its physical address — the kernel's address
    /// space maps every claimed window there — and this must be called once per device,
    /// because two transports for one device would be two drivers for one device.
    #[allow(unsafe_code)]
    pub unsafe fn transport(&self) -> Option<AnyTransport> {
        let (phys, len) = self.window();
        let base = hal::paging::device_virt(phys)?;
        let len = usize::try_from(len).ok()?;
        match &self.bus {
            Bus::Mmio => {
                // SAFETY: the caller's contract.
                let window = unsafe { Window::new(base, len) };
                // SAFETY: as above; one transport for the one device the driver bound.
                Some(AnyTransport::Mmio(unsafe { mmio::Mmio::new(window) }))
            }
            Bus::Pci {
                layout,
                bar,
                device_id,
            } => {
                // SAFETY: the caller's contract; the window is the BAR the probe claimed, and
                // every structure the layout names was checked to be inside it.
                let t = unsafe { pci::Pci::new(layout, *bar, base, len, *device_id) };
                t.ok().map(AnyTransport::Pci)
            }
        }
    }
}

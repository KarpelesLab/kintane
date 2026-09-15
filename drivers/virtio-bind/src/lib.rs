//! What a virtio driver's probe claims, whichever bus the device is on.
//!
//! The same for every device type: the register window, and the interrupt if one can be had
//! (an MSI-X vector where the platform delivers messages, otherwise a line). What those
//! registers become differs by bus, and a PCI function's layout has to be read at probe,
//! while the node still borrows the enumeration record. [`Claims`] keeps all of it, and
//! [`Claims::transport`] builds the transport later, once the kernel has mapped the window.
//!
//! This was virtio-blk's probe, moved unchanged apart from taking the device type and the
//! claims' names as arguments, with `layout_of` from virtio-blk's PCI glue.

#![no_std]
#![deny(unsafe_code)]

use device::pci::{self as dpci, Function};
use device::{IrqLine, Mmio as MmioClaim, Probe, ProbeError};
use hwproxy::Direct;
use virtio::pci::{Layout, Place, VendorCapability, cap};
use virtio::transport::Error;
use virtio::{AnyTransport, mmio, pci};

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
    /// Set when the node declared an interrupt that could not be claimed, because another
    /// device already holds that line — the second function on a shared INTx line.
    ///
    /// Kept rather than folded into `irq: None`, which cannot tell a device that wants no
    /// interrupt from one that was refused the interrupt it declared. Only the second leaves
    /// a level-triggered line with no handler able to acknowledge it.
    irq_refused: bool,
    bus: Bus,
}

/// Which transport the bound device is on, and what it takes to build it.
enum Bus {
    Mmio,
    Pci {
        layout: Layout,
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
                let layout = layout_of(f).map_err(|_| {
                    ProbeError::Declined("no modern virtio structures in the capability list")
                })?;
                // Every structure must be in one BAR, because one window is what a probe
                // claims and therefore what the kernel maps. QEMU's virtio-pci puts all
                // four in the same BAR; a device that spreads them is refused rather than
                // half-driven.
                let bar = layout.single_bar().ok_or(ProbeError::Declined(
                    "the device's structures are spread over several BARs",
                ))?;
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
        // Not refusing the device is right; discarding *why* was not. `Claim` is a line the
        // node declares and another device holds, `Tree` a node that declares none — folding
        // both into `None` is what let a disk be brought up with no handler in silence.
        let mut irq_refused = false;
        let irq = match irq {
            Some(vector) => Some(vector),
            None => match p.claim_irq(0) {
                Ok(line) => Some(line),
                Err(ProbeError::Claim(_)) => {
                    irq_refused = true;
                    None
                }
                Err(_) => None,
            },
        };
        Ok(Claims {
            mmio,
            table,
            irq,
            irq_refused,
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

    /// Whether the node declared an interrupt that could not be claimed because another
    /// device holds that line. The device is still usable by polling.
    pub fn irq_refused(&self) -> bool {
        self.irq_refused
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

    /// A PCI function's structure layout, the one BAR they are all in, and its device ID:
    /// what a host other than the kernel is told so it can build the transport over its own
    /// mapping of the window, since only the kernel can read configuration space. `None` for
    /// a memory-mapped slot, whose layout is fixed.
    pub fn pci_layout(&self) -> Option<(Layout, u8, u32)> {
        match &self.bus {
            Bus::Pci {
                layout,
                bar,
                device_id,
            } => Some((*layout, *bar, *device_id)),
            Bus::Mmio => None,
        }
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
        // SAFETY: the caller's contract; the window is the one the probe claimed.
        let window = unsafe { Direct::new(base, len) };
        match &self.bus {
            Bus::Mmio => Some(AnyTransport::Mmio(mmio::Mmio::new(window))),
            // Every structure the layout names is checked to be inside the BAR.
            Bus::Pci {
                layout,
                bar,
                device_id,
            } => pci::Pci::new(layout, *bar, window, *device_id)
                .ok()
                .map(AnyTransport::Pci),
        }
    }
}

/// Where `f`'s structures are, from its vendor capabilities.
///
/// `Err(Legacy)` when the device offers no modern structures at all, which is what a
/// pre-1.0 device looks like from here.
pub fn layout_of(f: &Function) -> Result<Layout, Error> {
    Layout::from_capabilities(
        f.capabilities()
            .into_iter()
            .filter(|c| c.id == dpci::CAP_VENDOR)
            .map(|c| VendorCapability {
                cfg_type: c.byte(cap::CFG_TYPE_BYTE),
                place: Place {
                    bar: c.byte(cap::BAR_BYTE),
                    offset: c.word(cap::OFFSET_WORD),
                    length: c.word(cap::LENGTH_WORD),
                },
                notify_multiplier: c.word(cap::NOTIFY_MULTIPLIER_WORD),
            }),
    )
}

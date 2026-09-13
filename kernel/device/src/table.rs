//! Devices a firmware table describes directly, rather than a tree or a bus.
//!
//! An ACPI MADT lists processors and interrupt controllers, and an MCFG lists the
//! windows PCI Express configuration space is mapped at. None of these is a node in a
//! device tree or a function on a bus. Yet a driver for an I/O APIC should bind and claim
//! its window the same way the GIC driver does on aarch64. So each becomes a
//! [`Described`] record, and a node borrows its name, its `compatible` list and its
//! windows from that record.
//!
//! The model does not parse the tables. A platform does, with `boot/acpi`, and fills these
//! records in. That keeps the model free of any one firmware's format, which is the point
//! of having a model.
//!
//! # `compatible` strings
//!
//! Firmware tables carry no strings, so these are chosen here, once. Where a device-tree
//! binding describes the same hardware, its string is used: ECAM configuration space is
//! `pci-host-ecam-generic` on every machine. Where none does, the string is prefixed
//! `acpi,` to say which table the node came from, or `pc,` for what the PC architecture
//! fixes with no table at all, and does not pretend to be a binding.

use crate::text::Text;

/// What a record describes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    /// A processor, with its local interrupt controller ID. Neither enabled nor online
    /// capable means firmware says it must not be started.
    Processor {
        apic_id: u32,
        processor_uid: u32,
        enabled: bool,
        online_capable: bool,
    },
    /// The local interrupt controller's register window, which every processor sees at
    /// the same address.
    LocalInterruptController,
    /// An I/O interrupt controller serving global system interrupts from `gsi_base`.
    IoInterruptController { id: u32, gsi_base: u32 },
    /// Memory-mapped PCI Express configuration space for one segment's buses.
    EcamConfigSpace {
        segment: u16,
        start_bus: u8,
        end_bus: u8,
    },
    /// PCI configuration space reached through I/O ports (configuration mechanism #1).
    /// No window: the ports are the whole interface.
    PortConfigSpace,
    /// A node that exists only to hold other nodes, such as `cpus`.
    Group,
}

/// The most windows a record carries.
pub const MAX_WINDOWS: usize = 2;

/// One described device.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Described {
    pub kind: Kind,
    windows: [(u64, u64); MAX_WINDOWS],
    count: u8,
    name: Text<24>,
}

impl Described {
    pub const EMPTY: Described = Described {
        kind: Kind::Group,
        windows: [(0, 0); MAX_WINDOWS],
        count: 0,
        name: Text::EMPTY,
    };

    /// A record named `name`, with CPU physical `(base, length)` windows in the order a
    /// driver claims them. `None` when the name does not fit or there are more than
    /// [`MAX_WINDOWS`].
    pub fn new(
        kind: Kind,
        name: core::fmt::Arguments<'_>,
        windows: &[(u64, u64)],
    ) -> Option<Described> {
        let mut d = Described {
            kind,
            name: Text::format(name)?,
            count: u8::try_from(windows.len()).ok()?,
            ..Described::EMPTY
        };
        d.windows.get_mut(..windows.len())?.copy_from_slice(windows);
        Some(d)
    }

    pub fn name(&self) -> &[u8] {
        self.name.as_bytes()
    }

    pub fn windows(&self) -> &[(u64, u64)] {
        self.windows.get(..usize::from(self.count)).unwrap_or(&[])
    }

    /// The `compatible` list for this kind: see the module documentation.
    pub fn compatible(&self) -> &'static [u8] {
        match self.kind {
            Kind::Processor { .. } => b"acpi,processor\0",
            Kind::LocalInterruptController => b"acpi,local-apic\0",
            Kind::IoInterruptController { .. } => b"acpi,io-apic\0",
            Kind::EcamConfigSpace { .. } => b"pci-host-ecam-generic\0",
            Kind::PortConfigSpace => b"pc,pci-config-mechanism-1\0",
            Kind::Group => b"",
        }
    }
}

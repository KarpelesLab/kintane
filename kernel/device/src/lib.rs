//! The device model.
//!
//! Firmware describes a machine; drivers drive parts of it. This crate is what sits
//! between the two:
//!
//! * [`tree`] — one node representation that every enumerator fills in: the flattened device tree,
//!   PCI enumeration, and firmware tables. Nodes have names, `compatible` lists, register windows
//!   as CPU addresses, and (for device-tree nodes) interrupts resolved to their controller.
//! * [`pci`] — enumerating PCI and PCI Express buses through whichever configuration access the
//!   platform has, and sizing BARs without disturbing them.
//! * [`table`] — records for devices a firmware table lists directly, such as ACPI's processors and
//!   interrupt controllers.
//! * [`driver`] — binding a driver to a node by `compatible` string, and the phases a bound device
//!   moves through, each a token only the previous step can produce.
//! * [`resource`] — the ledger of claimed register windows and interrupt lines, which refuses
//!   overlapping claims and is what the kernel maps device memory from.
//! * [`registers`] — access to a claimed window, checked against its bounds.
//!
//! Nothing here allocates, and nothing here names an architecture. Storage for nodes
//! and claims comes from the caller, because the model runs before any allocator does.
//!
//! See `docs/architecture.md`, "The device model", for how boot uses it.

#![cfg_attr(not(test), no_std)]
#![deny(unsafe_code)]

pub mod cell;
pub mod driver;
pub mod pci;
pub mod registers;
pub mod resource;
pub mod table;
pub mod text;
pub mod tree;

pub use cell::BootCell;
pub use driver::{
    Bound, Driver, Handler, HandlerError, Handlers, Probe, ProbeError, Started, Suspended,
};
/// The parser the tree is built from, so a consumer of the model does not have to name
/// `boot/fdt` itself.
pub use fdt::Fdt;
pub use registers::Registers;
pub use resource::{ClaimError, IrqClaim, IrqLine, Mmio, MmioClaim, Resources};
pub use table::Described;
pub use tree::{Builder, DeviceTree, Node, NodeId, Origin, Specifier};

#[cfg(test)]
mod tests;

#[cfg(test)]
mod pci_tests;

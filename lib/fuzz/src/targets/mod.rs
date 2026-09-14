//! The targets, and the one table that names them.
//!
//! Everything that reads bytes the kernel did not write should be here. The table is what
//! `kbuild fuzz` lists, what the nightly job iterates, and what the smoke run replays, so a
//! target added here is fuzzed everywhere without another list being updated.
//!
//! A parser this table does not name is a parser nobody fuzzes: that is the reason to keep
//! the list short and the entries honest rather than to grow it with things that do not
//! read untrusted input.

use crate::Target;

pub mod acpi;
pub mod aml;
pub mod bootproto;
pub mod dgram;
pub mod elf;
pub mod fat;
pub mod fdt;
pub mod menu;
pub mod module;
pub mod net;
pub mod pci;
pub mod sigframe;
pub mod syscall;
pub mod virtio_ring;

/// A device tree whose header and blocks validate.
fn fdt_accepts(input: &[u8]) -> bool {
    ::fdt::Fdt::new(input).is_ok()
}

/// An object file whose header validates, or a bundle whose table does.
fn module_accepts(input: &[u8]) -> bool {
    ::module::elf::Object::parse(input).is_ok() || ::module::bundle::Bundle::parse(input).is_ok()
}

/// A boot information structure whose header and tag area validate.
fn bootproto_accepts(input: &[u8]) -> bool {
    boot_protocol::tags::parse(input).is_ok()
}

/// A menu file that parses to a configuration.
fn menu_accepts(input: &[u8]) -> bool {
    kinboot_menu::Config::parse(input).is_ok()
}

/// Every target. Seeded ones (`needs_seeds`) read `corpus/<name>/seed-*.bin`; the rest
/// build their own input and use the corpus only for what has failed before.
pub const TARGETS: &[Target] = &[
    Target {
        name: "fdt",
        what: "device tree blobs, as firmware hands them to every port without ACPI",
        needs_seeds: true,
        generate: fdt::generate,
        run: fdt::run,
        accepts: Some(fdt_accepts),
    },
    Target {
        name: "acpi",
        what: "ACPI tables, as firmware describes a PC with them",
        needs_seeds: true,
        generate: acpi::generate,
        run: acpi::run,
        accepts: Some(acpi::accepts),
    },
    Target {
        name: "aml",
        what: "DSDT and SSDT bytecode, loaded and run as the kernel routes PCI interrupts with it",
        needs_seeds: true,
        generate: aml::generate,
        run: aml::run,
        accepts: Some(aml::accepts),
    },
    Target {
        name: "elf",
        what: "static ELF executables, as a userspace program is loaded from one",
        needs_seeds: false,
        generate: elf::generate,
        run: elf::run,
        accepts: Some(elf::accepts),
    },
    Target {
        name: "fat",
        what: "FAT16 volumes, as a disk holds them, and every write the driver makes to one",
        needs_seeds: true,
        generate: fat::generate,
        run: fat::run,
        accepts: Some(fat::accepts),
    },
    Target {
        name: "module",
        what: "relocatable modules and the bundle that carries them",
        needs_seeds: true,
        generate: module::generate,
        run: module::run,
        accepts: Some(module_accepts),
    },
    Target {
        name: "bootproto",
        what: "the boot protocol's tag stream, as a loader writes it",
        needs_seeds: false,
        generate: bootproto::generate,
        run: bootproto::run,
        accepts: Some(bootproto_accepts),
    },
    Target {
        name: "menu",
        what: "the boot menu's entry list, and the menu the loader drives with it",
        needs_seeds: true,
        generate: menu::generate,
        run: menu::run,
        accepts: Some(menu_accepts),
    },
    Target {
        name: "pci",
        what: "PCI configuration space, as a device answers an enumeration",
        needs_seeds: false,
        generate: pci::generate,
        run: pci::run,
        accepts: None,
    },
    Target {
        name: "virtio-ring",
        what: "a virtqueue's used ring, as a hostile device writes it",
        needs_seeds: false,
        generate: virtio_ring::generate,
        run: virtio_ring::run,
        accepts: None,
    },
    Target {
        name: "net",
        what: "Ethernet frames carrying ARP, IPv4, ICMP, UDP and TCP, as anything on a network sends them",
        needs_seeds: true,
        generate: net::generate,
        run: net::run,
        accepts: Some(net::accepts),
    },
    Target {
        name: "dgram",
        what: "datagrams taken out of the stack's inbox, and the addresses programs hand the socket calls",
        needs_seeds: true,
        generate: dgram::generate,
        run: dgram::run,
        accepts: Some(dgram::accepts),
    },
    Target {
        name: "sigframe",
        what: "Linux signal frames, as a program leaves them on its stack for rt_sigreturn",
        needs_seeds: false,
        generate: sigframe::generate,
        run: sigframe::run,
        accepts: Some(sigframe::accepts),
    },
    Target {
        name: "syscall",
        what: "system call numbers and argument registers, from abi::TABLE",
        needs_seeds: false,
        generate: syscall::generate,
        run: syscall::run,
        accepts: None,
    },
];

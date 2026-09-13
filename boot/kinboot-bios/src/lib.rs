//! `kinboot-bios`: the logic of the BIOS loader, separated from the machine.
//!
//! The loader itself is `boot/kinboot-bios/loader/`: a 440-byte real-mode stage 1 and a
//! stage 2 that switches to protected mode and calls back into the BIOS through a thunk.
//! Everything in it with a decision in it lives here instead, as plain byte-slice code
//! with no `unsafe`, so that it is tested on the host against both the layouts it must
//! produce and the malformed inputs it must refuse:
//!
//! - [`disk`] — the on-disk layout, shared by path with the `kbuild` code that writes it;
//! - [`memmap`] — decoding E820 and E801 into a memory map, and asking it questions;
//! - [`elf`] — validating the kernel and planning its load while streaming it from disk;
//! - [`handover`] — the boot protocol structure handed to the kernel;
//! - [`chain`] — which sector a chainload entry boots, and what it is handed.
//!
//! See `docs/bootloader.md`.

#![cfg_attr(not(test), no_std)]
#![deny(unsafe_code)]

pub mod chain;
pub mod disk;
pub mod elf;
pub mod handover;
pub mod memmap;

//! Loadable modules: the loader, and the interface a module is built against.
//!
//! A module is a relocatable ELF object (`ET_REL`) that kbuild produces from a unit of
//! kind `module` and stamps with the identity of the one kernel build it belongs to. This
//! crate is used from both sides of that boundary:
//!
//! * **The kernel** parses a module with [`elf`], refuses it with [`identity`] unless it was built
//!   for this exact kernel, checks every symbol it imports against the kernel's export table
//!   ([`abi`]), lays its sections out and relocates them ([`load`], [`reloc`]), and tracks who
//!   holds it with [`registry`].
//! * **A module** calls the kernel through the `extern "C"` declarations in [`abi`] and declares
//!   its entry points with [`module!`], which also records the interface hash of every function it
//!   may import.
//!
//! Nothing here maps memory or runs module code. The loader writes relocated bytes into
//! regions the caller supplies through [`load::Memory`], and returns the entry points; the
//! kernel decides how those regions are mapped and when to call them. That split is what
//! keeps every step above testable on the host, against ELF objects built in the tests and
//! against a real module kbuild produced.
//!
//! See `docs/modules.md` for the rules this implements, and for what it does not do yet.

#![cfg_attr(not(test), no_std)]

pub mod abi;
pub mod bundle;
pub mod elf;
pub mod identity;
pub mod interface;
pub mod load;
pub mod registry;
pub mod reloc;

#[cfg(test)]
mod tests;

pub use bundle::{Bundle, BundleError};
pub use identity::Mismatch;
pub use interface::{Export, ImportRecord};
pub use load::{Kernel, LoadError, Loaded, Memory, Placement, Region};
pub use registry::{ModuleId, Registry, RegistryError};

/// The name of the entry point every module must define. Called once after loading, with
/// the module's id; a non-zero return refuses the load.
pub const INIT_SYMBOL: &str = "kt_module_init";

/// The name of the optional exit point, called before unloading.
pub const EXIT_SYMBOL: &str = "kt_module_exit";

/// The section kbuild stamps a module's build identity into.
pub const IDENTITY_SECTION: &str = ".kintane.identity";

/// The section [`module!`] fills with one [`ImportRecord`] per function the module may
/// import.
pub const IMPORTS_SECTION: &str = ".kintane.imports";

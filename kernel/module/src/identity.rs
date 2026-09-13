//! Build identity: which kernel build a module belongs to.
//!
//! kbuild writes the same identity into the kernel (as `kconfig::MODULE_IDENTITY`) and into
//! every module it builds (as the [`crate::IDENTITY_SECTION`] section). It is text, so that
//! a refusal can say what differs rather than only that something does:
//!
//! ```text
//! kintane-module-identity 1
//! toolchain 1.100.0-nightly 90850177… llvm23.1.0
//! target 5f1c…                          (SHA-256 of the target specification)
//! config
//! ARCH_X86_64=y
//! DEBUG_BUILD=y
//! …                                     (every symbol, in declaration order)
//! ```
//!
//! The section is `KTIDENT1`, the SHA-256 of the text, the text's length as a little-endian
//! `u32`, and the text. The hash decides; the text only explains. A module whose hash
//! differs is refused even if its text happens to read the same, and then the text is
//! not believed and the refusal says the identity is corrupt.

/// The section's magic.
pub const MAGIC: &[u8; 8] = b"KTIDENT1";

/// Why a module's identity is not this kernel's.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Mismatch<'a> {
    /// The section is missing, truncated, or not an identity.
    Malformed,
    /// A configuration symbol differs. `module` or `kernel` is empty when the symbol is
    /// absent on that side.
    Config {
        symbol: &'a str,
        module: &'a str,
        kernel: &'a str,
    },
    /// Built by a different compiler.
    Toolchain { module: &'a str, kernel: &'a str },
    /// Built for a different target specification.
    Target,
    /// The hashes differ but the texts agree: the section has been altered.
    Corrupt,
}

/// A parsed identity section.
#[derive(Clone, Copy, Debug)]
pub struct Identity<'a> {
    pub hash: [u8; 32],
    pub text: &'a str,
}

impl<'a> Identity<'a> {
    pub fn parse(section: &'a [u8]) -> Option<Identity<'a>> {
        let hash: [u8; 32] = section.get(8..40)?.try_into().ok()?;
        if section.get(..8)? != MAGIC {
            return None;
        }
        let len = u32::from_le_bytes(section.get(40..44)?.try_into().ok()?) as usize;
        let text = core::str::from_utf8(section.get(44..44usize.checked_add(len)?)?).ok()?;
        Some(Identity { hash, text })
    }
}

/// Compare a module's identity with the kernel's. `Ok` only when the hashes match.
pub fn check<'a>(
    module: Option<Identity<'a>>,
    kernel_hash: &[u8; 32],
    kernel_text: &'a str,
) -> Result<(), Mismatch<'a>> {
    let module = module.ok_or(Mismatch::Malformed)?;
    if module.hash == *kernel_hash {
        return Ok(());
    }
    Err(explain(module.text, kernel_text))
}

/// Name the first thing that differs between two identity texts.
pub fn explain<'a>(module: &'a str, kernel: &'a str) -> Mismatch<'a> {
    let line = |text: &'a str, key: &str| {
        text.lines()
            .find_map(|l| l.strip_prefix(key).and_then(|v| v.strip_prefix(' ')))
            .unwrap_or("")
    };
    let (mt, kt) = (line(module, "toolchain"), line(kernel, "toolchain"));
    if mt != kt {
        return Mismatch::Toolchain {
            module: mt,
            kernel: kt,
        };
    }
    if line(module, "target") != line(kernel, "target") {
        return Mismatch::Target;
    }

    let config = |text: &'a str| {
        text.split_once("\nconfig\n")
            .map(|(_, c)| c)
            .unwrap_or("")
            .lines()
            .filter_map(|l| l.split_once('='))
    };
    let value = |text: &'a str, symbol: &str| {
        config(text)
            .find(|(s, _)| *s == symbol)
            .map(|(_, v)| v)
            .unwrap_or("")
    };
    // In the module's order first, which is declaration order, so the first difference
    // reported is the one nearest the top of the configuration.
    for (symbol, m) in config(module) {
        let k = value(kernel, symbol);
        if m != k {
            return Mismatch::Config {
                symbol,
                module: m,
                kernel: k,
            };
        }
    }
    // A symbol the kernel has and the module does not.
    for (symbol, k) in config(kernel) {
        if value(module, symbol).is_empty() && !k.is_empty() {
            return Mismatch::Config {
                symbol,
                module: "",
                kernel: k,
            };
        }
    }
    Mismatch::Corrupt
}

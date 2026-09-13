//! The image's build ID: which build a console log came from.
//!
//! A crash report is a list of raw addresses, and addresses mean something only against
//! the symbol bundle of the exact build that printed them. Decoded against any other build
//! they still decode, into confident, plausible and wrong function names. So the image
//! carries an ID, prints it in the banner and in every backtrace, and `kbuild symbolize`
//! refuses a log whose ID is not the bundle's.
//!
//! # Where the value comes from
//!
//! Not from here. [`BUILD_ID`] is compiled as a marker followed by zeroes, and kbuild fills
//! in the zeroes after linking (`kbuild/src/buildid.rs`). The ID is a hash of the linked
//! image's loadable content with those twenty bytes treated as zero, so it cannot depend
//! on itself, and stamping an image twice gives the same bytes, which is what keeps builds
//! reproducible. kbuild finds the bytes by the marker, inside the image's loadable
//! segments, and refuses an image in which the marker does not occur exactly once.
//!
//! An image that was never stamped prints twenty zero bytes, and says so.

#![no_std]

/// Bytes of ID. The first 20 bytes of a SHA-256, as a GNU build ID is the first 20 of a SHA-1.
pub const LEN: usize = 20;

/// What kbuild searches the linked image for. The ID follows it immediately.
pub const MARKER: [u8; 12] = *b"KinTane-BID:";

/// The marker and the ID, in the order kbuild expects.
#[repr(C)]
pub struct Stamp {
    pub marker: [u8; 12],
    pub id: [u8; LEN],
}

/// Filled in after linking. `#[used]` so it survives even in an image that never prints it.
///
/// The section is placed inside `.rodata` by each port's `link.ld`, so it is mapped
/// read-only with the constants. The attribute applies only when building for a kernel
/// target: a host test build is a Mach-O or ELF executable with its own section naming
/// rules, and there the ID is simply never stamped.
#[used]
#[cfg_attr(target_os = "none", unsafe(link_section = ".kintane_build_id"))]
pub static BUILD_ID: Stamp = Stamp {
    marker: MARKER,
    id: [0; LEN],
};

/// The ID as stamped into this image.
pub fn get() -> [u8; LEN] {
    // A read of an immutable static is something the compiler is entitled to fold into the
    // zeroes it was compiled with, and a folded read would print an ID the image does not
    // carry, with nothing to say it had happened. Today's code generation does not fold
    // it: with `black_box` removed, x86_64 and aarch64 still printed the stamped ID. Both
    // it and the volatile read stay, because that is an observation about one compiler.
    let at = core::hint::black_box(&raw const BUILD_ID.id);
    // SAFETY: `at` points at a live static of exactly this type, which nothing writes at
    // run time.
    unsafe { at.read_volatile() }
}

/// Write the ID as 40 lowercase hex digits, or `unstamped` if kbuild did not fill it in.
pub fn write(c: &dyn hal::EarlyConsole) {
    let id = get();
    if id == [0; LEN] {
        c.write_str("unstamped");
        return;
    }
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut buf = [0u8; 2 * LEN];
    for (i, b) in id.iter().enumerate() {
        buf[2 * i] = DIGITS[usize::from(b >> 4)];
        buf[2 * i + 1] = DIGITS[usize::from(b & 0xf)];
    }
    c.write_bytes(&buf);
}

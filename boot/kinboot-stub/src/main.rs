//! The EFI stub: the kernel as its own UEFI application.
//!
//! `kinboot-efi` is a loader that reads a kernel off a partition. This is the same
//! handover with nothing to read: the kernel travels inside this image, so the firmware
//! starts one file and there is no second file to keep in step with it, no filesystem to
//! walk in the boot path, and one thing to sign when there is something to sign with.
//!
//! # How the kernel gets in here
//!
//! rustc and lld-link cannot put it here: the kernel is a different link for a different
//! target, built afterwards and stamped with its build ID after that. So kbuild adds it
//! once both exist (`kbuild/src/pe.rs`):
//!
//! 1. the kernel's bytes become one more PE section, which the firmware loads with the rest of this
//!    image;
//! 2. the command line becomes another, named `.cmdline`, which is where a unified kernel image
//!    carries it;
//! 3. where each landed, and the stub's flags, are written into [`BLOB`] after its marker.
//!
//! So this reads a struct rather than parsing its own headers in the boot path. The words
//! are still untrusted: a descriptor that points outside this image is refused against the
//! size the firmware reports, and an unstamped one says so instead of jumping into zeros.
//!
//! # What it does not do
//!
//! No menu, no entry list, no chainloading. A stub is the configuration that says "boot
//! this kernel, these arguments"; `kinboot-efi` is the configuration that says "choose".
//! Keeping the choice out of here is what keeps the boot path short enough to read.

#![no_std]
#![no_main]

use core::convert::Infallible;
use core::mem::offset_of;
use core::{fmt, ptr};

use uefi::handover::{self, fatal, log};
use uefi::{Handle, Status, SystemTable};

/// What precedes the words kbuild stamps. Must match `KERNEL_BLOB_MARKER` in
/// `kbuild/src/pe.rs`.
///
/// Sixteen bytes, a multiple of the words' alignment, so the words follow it with no
/// padding. kbuild writes them straight after the marker; a marker of any other length
/// would put them somewhere this struct does not look.
const MARKER: [u8; 16] = *b"KinTane-KERNEL:\0";

/// Set in the flags word when a failure should reset the machine rather than return to
/// the firmware. Test builds set it: their harness boots with `-no-reboot`, so a reset
/// ends the run at once, where returning would leave the firmware trying its other boot
/// options until the harness timed out. `kinboot-efi`'s test builds do the same through
/// their entry list.
const RESET_ON_FAILURE: u64 = 1;

/// Where the kernel and the command line ended up in this image, filled in after linking.
///
/// The marker is part of the struct on purpose: its bytes are not zero, so the whole
/// struct is initialised data with bytes in the file for kbuild to write, rather than an
/// uninitialised tail with nothing on disk.
#[repr(C)]
struct Blob {
    marker: [u8; 16],
    /// Kernel address relative to the image base, kernel length, command line address,
    /// command line length, flags. A zero kernel length means "not stamped".
    words: [u64; 5],
}

// The first boot of this stub read its words four bytes past where kbuild had written
// them: a twelve-byte marker left padding before the first word, which kbuild knew nothing
// about, and the stub reported a kernel of 2.3 petabytes. This turns that layout into a
// compile error.
const _: () = assert!(offset_of!(Blob, words) == MARKER.len());

#[used]
#[unsafe(no_mangle)]
static BLOB: Blob = Blob {
    marker: MARKER,
    words: [0; 5],
};

/// Why nothing was started.
enum Failure {
    /// kbuild did not finish this image.
    Unstamped,
    /// A stamped range lies outside the image the firmware loaded.
    OutsideImage {
        what: &'static str,
        at: u64,
        len: u64,
        size: u64,
    },
    Handover(handover::Error),
}

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Failure::Unstamped => {
                write!(f, "this image carries no kernel; kbuild did not stamp it")
            }
            Failure::OutsideImage {
                what,
                at,
                len,
                size,
            } => write!(
                f,
                "the {what} is said to be {len} bytes at {at:#x}, outside this {size}-byte image"
            ),
            Failure::Handover(e) => write!(f, "{e}"),
        }
    }
}

impl Failure {
    fn status(&self) -> Status {
        match self {
            Failure::Unstamped | Failure::OutsideImage { .. } => Status::LOAD_ERROR,
            Failure::Handover(e) => e.status(),
        }
    }
}

/// The firmware's entry point.
#[unsafe(no_mangle)]
pub extern "efiapi" fn efi_main(image: Handle, system_table: *mut SystemTable) -> Status {
    // SAFETY: the firmware passes a valid system table, which stays valid until
    // `ExitBootServices`; nothing here uses it past that point.
    let st = unsafe { &*system_table };
    handover::use_console(st.con_out);

    // Volatile, because the words are zero in the object file and kbuild writes them
    // afterwards: a compiler that folded the initialiser would read its own zeros and
    // report an unstamped image forever.
    // SAFETY: `BLOB` is a static of this image, aligned and initialised.
    let words = unsafe { ptr::read_volatile(ptr::addr_of!(BLOB.words)) };
    let flags = words[4];

    // SAFETY: `image` and `st` are what the firmware handed this application.
    let Err(failure) = unsafe { boot(image, st, words) };
    log(format_args!("kinboot-stub: {failure}\n"));
    if flags & RESET_ON_FAILURE != 0 {
        log(format_args!("kinboot-stub: resetting, as this build asks\n"));
        // SAFETY: the firmware's runtime services are live while boot services are, and
        // a cold reset takes no pointers.
        unsafe {
            ((*st.runtime_services).reset_system)(
                uefi::RESET_COLD,
                failure.status(),
                0,
                ptr::null(),
            )
        }
    }
    failure.status()
}

/// Find the kernel this image carries and hand the machine over to it. Returns only on
/// failure, and only while the firmware is still there to return to.
///
/// # Safety
/// `image` and `st` must be this application's handle and system table, with boot
/// services not yet exited.
unsafe fn boot(image: Handle, st: &SystemTable, words: [u64; 5]) -> Result<Infallible, Failure> {
    let [kernel_at, kernel_len, cmdline_at, cmdline_len, _flags] = words;
    if kernel_len == 0 {
        return Err(Failure::Unstamped);
    }
    // SAFETY: as the caller guarantees.
    let (base, size) = unsafe { handover::image_extent(st, image) }.map_err(Failure::Handover)?;
    // SAFETY: each range is checked against the image the firmware loaded, which holds
    // every section kbuild added, before a slice is made of it.
    let kernel = unsafe { slice_in(base, size, "kernel", kernel_at, kernel_len)? };
    // SAFETY: as above.
    let command_line = unsafe { slice_in(base, size, "command line", cmdline_at, cmdline_len)? };
    log(format_args!(
        "kinboot-stub: {} bytes of kernel carried in this image\n",
        kernel.len()
    ));

    // SAFETY: this application's handle and system table, with boot services live.
    unsafe { handover::hand_over(image, st, kernel, command_line) }.map_err(Failure::Handover)
}

/// `len` bytes at `at` within this loaded image, which is `size` bytes from `base`.
///
/// # Safety
/// `base` and `size` must be this image's, as the firmware reported them.
unsafe fn slice_in(
    base: usize,
    size: u64,
    what: &'static str,
    at: u64,
    len: u64,
) -> Result<&'static [u8], Failure> {
    let inside = at.checked_add(len).is_some_and(|end| end <= size);
    let outside = || Failure::OutsideImage {
        what,
        at,
        len,
        size,
    };
    if !inside {
        return Err(outside());
    }
    if len == 0 {
        return Ok(&[]);
    }
    let start = usize::try_from(at).map_err(|_| outside())?;
    let len = usize::try_from(len).map_err(|_| outside())?;
    // SAFETY: `[at, at + len)` lies within `[0, size)` of the image the firmware loaded at
    // `base`, which it keeps loaded while this application runs.
    Ok(unsafe {
        core::slice::from_raw_parts(ptr::with_exposed_provenance::<u8>(base + start), len)
    })
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo<'_>) -> ! {
    fatal(format_args!("kinboot-stub: panic: {}", info.message()))
}

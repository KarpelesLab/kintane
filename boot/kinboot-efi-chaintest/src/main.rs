//! The UEFI chainload test payload.
//!
//! `kinboot-efi` starts this application through `LoadImage` and `StartImage` when the
//! chain test boot entry is chosen. It checks what a chainloaded application may rely on:
//!
//! - its load options are the ones the loader sets, `kinboot-efi` in UCS-2, so it was started by
//!   the loader and not by the firmware's boot manager;
//! - its `FilePath` names the file it was loaded from, `\EFI\KINTANE\CHAIN.EFI`, which is what an
//!   application uses to find the partition it lives on.
//!
//! It exits QEMU through `isa-debug-exit`: `0x10` (exit 33, a pass) if both hold, `0x11`
//! (exit 35, a failure) if either does not.

#![no_std]
#![no_main]

use core::ffi::c_void;
use core::{ptr, slice};

#[allow(dead_code)] // the loader's bindings; this application calls a few of them
#[path = "../../kinboot-efi/src/uefi.rs"]
mod uefi;

use uefi::{Handle, Status, SystemTable};

/// What the loader puts in `LoadOptions`, terminator included.
const EXPECTED_OPTIONS: &str = "kinboot-efi\0";
/// Where the loader loaded this file from.
const EXPECTED_PATH: &str = "\\EFI\\KINTANE\\CHAIN.EFI";

#[unsafe(no_mangle)]
pub extern "efiapi" fn efi_main(image: Handle, system_table: *mut SystemTable) -> Status {
    // SAFETY: the firmware passes a valid system table.
    let st = unsafe { &*system_table };
    say(st, "chain test: EFI application started\r\n");

    // SAFETY: boot services are live while this application runs, and every image
    // carries LoadedImage.
    let loaded = unsafe {
        let mut interface: *mut c_void = ptr::null_mut();
        let s =
            ((*st.boot_services).handle_protocol)(image, &uefi::LOADED_IMAGE_GUID, &mut interface);
        if s.is_error() || interface.is_null() {
            say(st, "chain test: FAILED, no LoadedImage\r\n");
            exit(0x11);
        }
        &*interface.cast::<uefi::LoadedImage>()
    };

    // SAFETY: the loader set `load_options` to a buffer of `load_options_size` bytes,
    // and the firmware leaves them as given.
    let options_ok = !loaded.load_options.is_null()
        && unsafe {
            let units = loaded.load_options_size as usize / 2;
            let got = slice::from_raw_parts(loaded.load_options.cast::<u16>(), units);
            got.iter()
                .copied()
                .eq(EXPECTED_OPTIONS.bytes().map(u16::from))
        };
    if !options_ok {
        say(st, "chain test: FAILED, not started by kinboot-efi (load options)\r\n");
        exit(0x11);
    }
    // SAFETY: the firmware's copy of the device path this image was loaded from.
    if !unsafe { names_file(loaded.file_path.cast()) } {
        say(st, "chain test: FAILED, FilePath does not name this file\r\n");
        exit(0x11);
    }
    say(st, "chain test: started by kinboot-efi, from its own file\r\n");
    exit(0x10)
}

/// Whether a device path contains a media file path node naming [`EXPECTED_PATH`].
///
/// # Safety
/// `path` must be null or a well-formed device path.
unsafe fn names_file(path: *const u8) -> bool {
    if path.is_null() {
        return false;
    }
    let mut at = path;
    for _ in 0..32 {
        // SAFETY: a node header, inside the path the caller vouches for.
        let (kind, sub, len) =
            unsafe { (*at, *at.add(1), usize::from(u16::from_le_bytes([*at.add(2), *at.add(3)]))) };
        if kind == uefi::DEVICE_PATH_END || len < 4 {
            return false;
        }
        if kind == uefi::DEVICE_PATH_MEDIA && sub == uefi::DEVICE_PATH_MEDIA_FILE {
            // SAFETY: a file path node's payload is `len - 4` bytes of UCS-2.
            let name = unsafe { slice::from_raw_parts(at.add(4), len - 4) };
            let units = name
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]));
            let wanted = EXPECTED_PATH
                .bytes()
                .map(u16::from)
                .chain(core::iter::once(0));
            if units.eq(wanted) {
                return true;
            }
        }
        // SAFETY: the next node begins `len` bytes on.
        at = unsafe { at.add(len) };
    }
    false
}

fn say(st: &SystemTable, s: &str) {
    let mut buf = [0u16; 128];
    for (slot, b) in buf.iter_mut().zip(s.bytes().take(127)) {
        *slot = u16::from(b);
    }
    // SAFETY: the firmware console, valid while boot services are; `buf` is terminated.
    unsafe { ((*st.con_out).output_string)(st.con_out, buf.as_ptr()) };
}

/// Report through `isa-debug-exit` and stop.
fn exit(code: u8) -> ! {
    // SAFETY: port 0xF4 is QEMU's isa-debug-exit in the chain test machine; writing it
    // ends the emulator.
    unsafe {
        core::arch::asm!("out dx, al", in("dx") 0xF4u16, in("al") code, options(nostack));
    }
    loop {
        // SAFETY: parking the CPU if the port did nothing.
        unsafe { core::arch::asm!("cli", "hlt", options(nostack)) };
    }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    exit(0x11)
}

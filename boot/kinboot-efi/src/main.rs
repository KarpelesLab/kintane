//! kinboot-efi: KinTane's UEFI loader.
//!
//! The minimal loader `docs/bootloader.md` schedules for Phase 0, and no more:
//!
//! 1. read the kernel image off the partition this loader was started from;
//! 2. place its segments at the physical addresses it was linked for;
//! 3. find the ACPI RSDP while the firmware's tables can still be asked;
//! 4. `ExitBootServices`, retrying with a fresh memory map when the key has gone stale;
//! 5. translate the final memory map into the boot protocol's structure;
//! 6. jump to the entry point the image names in its `KinTane` note.
//!
//! Boot entries and modes, Secure Boot, measured boot, the boot counter and chainloading
//! are all in the design and none of them is here; `docs/bootloader.md` says which phase
//! each belongs to.
//!
//! # Why the order matters
//!
//! Step 5 comes **after** step 4 because the map changes with every allocation, and the
//! kernel must receive the map that is true when the firmware lets go, not one from a few
//! calls earlier. So every allocation the handover needs — the boot information pages,
//! the buffer the map is read into — happens before the first `GetMemoryMap` whose key is
//! used, and nothing between that call and `ExitBootServices` may allocate, print, or
//! otherwise give the firmware a reason to change the map. The translation afterwards
//! calls no firmware at all, which is what makes it possible to do then.
//!
//! The classic bug this avoids is calling `ExitBootServices` once, getting
//! `EFI_INVALID_PARAMETER` because a timer event allocated in between, and giving up —
//! or, worse, retrying with the old key. The specification's answer is to fetch the map
//! again, without allocating, and try once more; the buffer is sized with slack for that.

#![no_std]
#![no_main]

mod uefi;

#[cfg(target_arch = "x86_64")]
#[path = "x86_64.rs"]
mod arch;

use core::convert::Infallible;
use core::ffi::c_void;
use core::fmt::{self, Write};
use core::mem::size_of;
use core::sync::atomic::{AtomicPtr, Ordering};
use core::{ptr, slice};

use boot_protocol::Firmware;
use boot_protocol::image::{Image, ImageError};
use boot_protocol::tags::Builder;
use boot_protocol::uefi::{PAGE_SIZE, memory_type, region};
use uefi::{BootServices, Handle, Status, SystemTable};

/// Where the kernel lives on the EFI system partition. FAT is case-insensitive, and the
/// name is 8.3 so it needs no long-name entries.
const KERNEL_PATH: &str = "\\KINTANE\\KERNEL.ELF";

/// The kernel's bootstrap page tables identity-map the first gigabyte, so the image and
/// the boot information must both lie below it.
const HANDOVER_LIMIT: u64 = 1 << 30;

/// Pages for the boot information structure: 16 KiB, room for [`MAP_CAPACITY`] regions
/// and the few small tags.
const BOOT_INFO_PAGES: usize = 4;

/// Regions the memory map tag can hold after coalescing. OVMF's raw map is around a
/// hundred descriptors and coalesces to a few dozen.
const MAP_CAPACITY: usize = 512;

/// Extra descriptors of room in the map buffer, for what the allocation of the buffer
/// itself and any firmware activity before `ExitBootServices` add.
const MAP_SLACK: usize = 16;

/// How many times `ExitBootServices` is tried with a fresh map before giving up. The
/// specification expects one retry to suffice; more than a few means something is
/// allocating in a loop, and waiting will not fix it.
const EXIT_ATTEMPTS: usize = 4;

/// The firmware console, until boot services exit; null afterwards, which sends output to
/// the serial port instead.
static CON_OUT: AtomicPtr<uefi::SimpleTextOutput> = AtomicPtr::new(ptr::null_mut());

struct Console;

impl Write for Console {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let out = CON_OUT.load(Ordering::Relaxed);
        if out.is_null() {
            return arch::Serial.write_str(s);
        }
        // UCS-2 in chunks, NUL-terminated. Anything outside the basic plane is '?':
        // this console prints loader messages, which are ASCII.
        let mut buf = [0u16; 128];
        let mut n = 0;
        let flush = |buf: &mut [u16; 128], n: &mut usize| {
            buf[*n] = 0;
            // SAFETY: `out` is the firmware's console, valid until boot services exit,
            // after which CON_OUT is null and this branch is not taken. `buf` is
            // NUL-terminated.
            unsafe { ((*out).output_string)(out, buf.as_ptr()) };
            *n = 0;
        };
        for ch in s.chars() {
            if ch == '\n' {
                buf[n] = u16::from(b'\r');
                n += 1;
            }
            buf[n] = u16::try_from(u32::from(ch)).unwrap_or(u16::from(b'?'));
            n += 1;
            if n >= buf.len() - 2 {
                flush(&mut buf, &mut n);
            }
        }
        flush(&mut buf, &mut n);
        Ok(())
    }
}

macro_rules! say {
    ($($t:tt)*) => {{
        let _ = write!(Console, $($t)*);
    }};
}

/// Why the kernel was not started.
enum Failure {
    Firmware(&'static str, Status),
    Image(ImageError),
    /// The image or the boot information would lie above [`HANDOVER_LIMIT`].
    TooHigh(u64),
    ShortRead {
        expected: usize,
        got: usize,
    },
}

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Failure::Firmware(what, s) => write!(f, "{what} failed: status {:#x}", s.0),
            Failure::Image(e) => write!(f, "{KERNEL_PATH} is not a bootable kernel: {e:?}"),
            Failure::TooHigh(at) => {
                write!(f, "the kernel needs memory up to {at:#x}, above the 1 GiB handover limit")
            }
            Failure::ShortRead { expected, got } => {
                write!(f, "read {got} of {expected} bytes of {KERNEL_PATH}")
            }
        }
    }
}

impl Failure {
    fn status(&self) -> Status {
        match self {
            Failure::Firmware(_, s) => *s,
            Failure::ShortRead { .. } | Failure::Image(_) | Failure::TooHigh(_) => {
                Status::LOAD_ERROR
            }
        }
    }
}

fn check(what: &'static str, s: Status) -> Result<(), Failure> {
    s.ok().map_err(|s| Failure::Firmware(what, s))
}

/// The firmware's entry point.
#[unsafe(no_mangle)]
pub extern "efiapi" fn efi_main(image: Handle, system_table: *mut SystemTable) -> Status {
    // SAFETY: the firmware passes a valid system table, which stays valid until
    // `ExitBootServices`; `boot` does not use it past that point.
    let st = unsafe { &*system_table };
    CON_OUT.store(st.con_out, Ordering::Relaxed);
    say!("kinboot-efi: loading {KERNEL_PATH}\n");

    // SAFETY: `image` and `st` are what the firmware handed this application.
    match unsafe { boot(image, st) } {
        Err(failure) => {
            say!("kinboot-efi: {failure}\n");
            failure.status()
        }
    }
}

/// Load the kernel and hand over to it. Returns only on failure, and only while the
/// firmware is still there to return to.
///
/// # Safety
/// `image` and `st` must be this application's handle and system table, with boot
/// services not yet exited.
unsafe fn boot(image: Handle, st: &SystemTable) -> Result<Infallible, Failure> {
    // SAFETY: boot services are live, per the caller.
    let bs = unsafe { &*st.boot_services };

    // SAFETY: as above; the returned slice is a pool allocation nothing else frees.
    let file = unsafe { read_kernel(bs, image)? };
    let kernel = Image::parse(file).map_err(Failure::Image)?;
    if kernel.phys_end > HANDOVER_LIMIT {
        return Err(Failure::TooHigh(kernel.phys_end));
    }

    // One allocation for the whole extent, page-aligned at both ends: segments may share
    // a page, and the gaps between them must be the kernel's too, not the firmware's.
    let start = kernel.phys_start & !(PAGE_SIZE - 1);
    let end = kernel.phys_end.div_ceil(PAGE_SIZE) * PAGE_SIZE;
    let pages = usize::try_from((end - start) / PAGE_SIZE).map_err(|_| Failure::TooHigh(end))?;
    let mut at = start;
    // SAFETY: a boot services call with valid arguments; `at` is written by the firmware.
    check("allocating the kernel's pages", unsafe {
        (bs.allocate_pages)(uefi::ALLOCATE_ADDRESS, memory_type::KINTANE_KERNEL, pages, &mut at)
    })?;
    // SAFETY: the firmware just gave us `[start, end)`, identity-mapped, and nothing else
    // refers to it. Zeroing all of it first is what makes `.bss` zero: its segment has
    // no file bytes.
    unsafe {
        ptr::write_bytes(ptr::with_exposed_provenance_mut::<u8>(start as usize), 0, pages * 4096)
    };
    for seg in kernel.segments() {
        let seg = seg.map_err(Failure::Image)?;
        // SAFETY: every segment lies within `[phys_start, phys_end)`, which `Image::parse`
        // established and the allocation above covers, and `seg.file` is inside the file
        // buffer, which is a different allocation.
        unsafe {
            ptr::copy_nonoverlapping(
                seg.file.as_ptr(),
                ptr::with_exposed_provenance_mut::<u8>(seg.phys as usize),
                seg.file.len(),
            );
        }
    }
    say!(
        "kinboot-efi: kernel at {:#x}..{:#x}, entry {:#x}\n",
        kernel.phys_start,
        kernel.phys_end,
        kernel.entry
    );

    let rsdp = find_rsdp(st);

    let mut info_at = HANDOVER_LIMIT - 1;
    // SAFETY: a boot services call with valid arguments.
    check("allocating the boot information", unsafe {
        (bs.allocate_pages)(
            uefi::ALLOCATE_MAX_ADDRESS,
            memory_type::KINTANE_BOOT_DATA,
            BOOT_INFO_PAGES,
            &mut info_at,
        )
    })?;
    // SAFETY: just allocated for us, identity-mapped, BOOT_INFO_PAGES long.
    let info = unsafe {
        slice::from_raw_parts_mut(
            ptr::with_exposed_provenance_mut::<u8>(info_at as usize),
            BOOT_INFO_PAGES * 4096,
        )
    };

    // SAFETY: boot services are live.
    let map = unsafe { map_buffer(bs)? };

    // The firmware's watchdog would reset the machine five minutes after this loader
    // started. The kernel owns the machine from here and has no idea it is armed.
    // SAFETY: disabling the watchdog is a boot services call with no pointer arguments.
    let _ = unsafe { (bs.set_watchdog_timer)(0, 0, 0, ptr::null()) };

    say!("kinboot-efi: exiting boot services\n");

    let mut attempt = 0;
    let (map_len, descriptor_size) = loop {
        let mut size = map.len();
        let (mut key, mut descriptor_size, mut version) = (0usize, 0usize, 0u32);
        // SAFETY: `map` is a buffer of `size` bytes we own. No allocation happens between
        // this call and ExitBootServices, so the key stays current.
        let s = unsafe {
            (bs.get_memory_map)(
                &mut size,
                map.as_mut_ptr(),
                &mut key,
                &mut descriptor_size,
                &mut version,
            )
        };
        if s.is_error() {
            if attempt == 0 {
                return Err(Failure::Firmware("GetMemoryMap", s));
            }
            // Past a failed ExitBootServices the firmware may be half gone; there is
            // nothing to return to that can be trusted.
            fatal(format_args!("GetMemoryMap failed after ExitBootServices did: {:#x}", s.0));
        }
        // SAFETY: `key` is from the map fetched immediately above.
        let s = unsafe { (bs.exit_boot_services)(image, key) };
        if s == Status::SUCCESS {
            break (size, descriptor_size);
        }
        attempt += 1;
        if attempt == EXIT_ATTEMPTS {
            fatal(format_args!("ExitBootServices failed {attempt} times, last status {:#x}", s.0));
        }
    };
    // Boot services are gone: from here the console is the serial port.
    CON_OUT.store(ptr::null_mut(), Ordering::Relaxed);
    if attempt > 0 {
        say!("kinboot-efi: the map key went stale {attempt} time(s); retried with a fresh map\n");
    }

    build_boot_info(info, &map[..map_len], descriptor_size, &kernel, rsdp)
        .unwrap_or_else(|e| fatal(format_args!("writing the boot information: {e:?}")));

    // SAFETY: boot services have exited; the kernel is loaded at its link addresses and
    // names `kernel.entry` as its protocol entry; the structure is complete; and both lie
    // below 1 GiB, identity-mapped by the firmware's tables, which are still loaded.
    unsafe { arch::enter(kernel.entry, info_at) }
}

/// Report a failure that happened after the firmware stopped being there to return to,
/// and stop.
fn fatal(args: fmt::Arguments<'_>) -> ! {
    let _ = writeln!(Console, "kinboot-efi: {args}");
    arch::halt()
}

/// Read the whole kernel image into a pool allocation.
///
/// # Safety
/// Boot services must be live and `image` this application's handle.
unsafe fn read_kernel(bs: &BootServices, image: Handle) -> Result<&'static [u8], Failure> {
    let mut interface: *mut c_void = ptr::null_mut();
    // SAFETY: HandleProtocol on our own image handle, which always carries LoadedImage.
    check("finding this loader's image", unsafe {
        (bs.handle_protocol)(image, &uefi::LOADED_IMAGE_GUID, &mut interface)
    })?;
    // SAFETY: the firmware returned a LoadedImage interface.
    let loaded = unsafe { &*interface.cast::<uefi::LoadedImage>() };

    // SAFETY: the partition this loader came from; it carries a file system, or the
    // firmware could not have read the loader off it.
    check("finding the boot partition's file system", unsafe {
        (bs.handle_protocol)(loaded.device_handle, &uefi::SIMPLE_FILE_SYSTEM_GUID, &mut interface)
    })?;
    let fs = interface.cast::<uefi::SimpleFileSystem>();
    let mut root: *mut uefi::File = ptr::null_mut();
    // SAFETY: `fs` is a SimpleFileSystem interface the firmware returned.
    check("opening the boot partition", unsafe { ((*fs).open_volume)(fs, &mut root) })?;

    let mut name = [0u16; 64];
    for (slot, ch) in name.iter_mut().zip(KERNEL_PATH.bytes()) {
        *slot = u16::from(ch);
    }
    let mut file: *mut uefi::File = ptr::null_mut();
    // SAFETY: `root` is an open directory; `name` is NUL-terminated (the path is shorter
    // than the buffer, whose tail stays zero).
    let opened = unsafe { ((*root).open)(root, &mut file, name.as_ptr(), uefi::FILE_MODE_READ, 0) };
    // SAFETY: `root` is open and no longer needed whatever happened.
    unsafe { ((*root).close)(root) };
    check("opening the kernel", opened)?;

    let result = (|| {
        // Seeking to the maximum position moves to the end of the file, which is the
        // specification's way to learn a file's size without the FileInfo structure.
        let mut size = 0u64;
        // SAFETY: `file` is open.
        unsafe {
            check("seeking the kernel", ((*file).set_position)(file, u64::MAX))?;
            check("sizing the kernel", ((*file).get_position)(file, &mut size))?;
            check("rewinding the kernel", ((*file).set_position)(file, 0))?;
        }
        let size = usize::try_from(size).map_err(|_| Failure::TooHigh(size))?;
        let mut buffer: *mut u8 = ptr::null_mut();
        // SAFETY: a pool allocation of `size` bytes.
        check("allocating the kernel's file buffer", unsafe {
            (bs.allocate_pool)(memory_type::LOADER_DATA, size, &mut buffer)
        })?;
        let mut done = 0;
        while done < size {
            let mut n = size - done;
            // SAFETY: `buffer` has `size - done` bytes left from `done`.
            check("reading the kernel", unsafe { ((*file).read)(file, &mut n, buffer.add(done)) })?;
            if n == 0 {
                break;
            }
            done += n;
        }
        if done != size {
            return Err(Failure::ShortRead {
                expected: size,
                got: done,
            });
        }
        // SAFETY: `size` bytes were allocated and every one was written. The pool
        // allocation is never freed; it becomes usable memory when boot services exit.
        Ok(unsafe { slice::from_raw_parts(buffer, size) })
    })();
    // SAFETY: `file` is open.
    unsafe { ((*file).close)(file) };
    result
}

/// A buffer for the final memory map, allocated while allocating is still allowed.
///
/// # Safety
/// Boot services must be live.
unsafe fn map_buffer(bs: &BootServices) -> Result<&'static mut [u8], Failure> {
    let mut size = 0usize;
    let (mut key, mut descriptor_size, mut version) = (0usize, 0usize, 0u32);
    // SAFETY: a size query: zero bytes, null buffer, as the specification allows.
    let s = unsafe {
        (bs.get_memory_map)(
            &mut size,
            ptr::null_mut(),
            &mut key,
            &mut descriptor_size,
            &mut version,
        )
    };
    if s != Status::BUFFER_TOO_SMALL {
        return Err(Failure::Firmware("GetMemoryMap (size query)", s));
    }
    // The allocation below adds descriptors of its own, and so may the firmware before
    // ExitBootServices; a map that does not fit then cannot be fetched again.
    let size = size + MAP_SLACK * descriptor_size.max(size_of::<uefi::MemoryDescriptor>());
    let mut buffer: *mut u8 = ptr::null_mut();
    // SAFETY: a pool allocation of `size` bytes.
    check("allocating the memory map buffer", unsafe {
        (bs.allocate_pool)(memory_type::LOADER_DATA, size, &mut buffer)
    })?;
    // SAFETY: `size` bytes, ours; initialised to zero so the slice is of valid bytes.
    unsafe {
        ptr::write_bytes(buffer, 0, size);
        Ok(slice::from_raw_parts_mut(buffer, size))
    }
}

/// The ACPI RSDP, 2.0 preferred, from the firmware's configuration table.
fn find_rsdp(st: &SystemTable) -> Option<u64> {
    if st.configuration_table.is_null() {
        return None;
    }
    // SAFETY: the system table's configuration table has `number_of_table_entries`
    // entries, and boot services are live.
    let tables =
        unsafe { slice::from_raw_parts(st.configuration_table, st.number_of_table_entries) };
    let find = |guid| {
        tables
            .iter()
            .find(|t| t.vendor_guid == guid)
            .map(|t| t.vendor_table.expose_provenance() as u64)
    };
    find(uefi::ACPI_20_TABLE_GUID).or_else(|| find(uefi::ACPI_10_TABLE_GUID))
}

/// Write the boot information: firmware kind, kernel range, RSDP, and the memory map
/// translated from the firmware's final descriptors. Calls no firmware.
fn build_boot_info(
    buf: &mut [u8],
    map: &[u8],
    descriptor_size: usize,
    kernel: &Image<'_>,
    rsdp: Option<u64>,
) -> Result<usize, boot_protocol::Error> {
    use core::mem::offset_of;

    use uefi::MemoryDescriptor as D;
    // A descriptor smaller than the fields read below is not one this loader can walk.
    if descriptor_size < size_of::<D>() {
        return Err(boot_protocol::Error::Malformed { offset: 0 });
    }
    let mut b = Builder::new(buf)?;
    b.firmware(Firmware::Uefi)?;
    b.kernel_range(kernel.phys_start, kernel.phys_end - kernel.phys_start)?;
    if let Some(address) = rsdp {
        b.acpi_rsdp(address)?;
    }
    let mut m = b.memory_map(MAP_CAPACITY)?;
    for d in map.chunks_exact(descriptor_size) {
        let field = |at: usize| u64::from_ne_bytes(d[at..at + 8].try_into().unwrap_or([0; 8]));
        let at = offset_of!(D, kind);
        let kind = u32::from_ne_bytes(d[at..at + 4].try_into().unwrap_or([0; 4]));
        let (start, pages) = (offset_of!(D, physical_start), offset_of!(D, number_of_pages));
        if let Some(r) = region(kind, field(start), field(pages)) {
            m.push(r)?;
        }
    }
    m.close();
    Ok(b.finish())
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo<'_>) -> ! {
    fatal(format_args!("panic: {}", info.message()))
}

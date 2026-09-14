//! Handing a machine over from UEFI firmware to the kernel.
//!
//! Every KinTane UEFI loader ends the same way, whatever it did to find a kernel:
//!
//! 1. place the image's segments at the physical addresses it was linked for;
//! 2. find the ACPI RSDP while the firmware's tables can still be asked;
//! 3. `ExitBootServices`, retrying with a fresh memory map when the key has gone stale;
//! 4. translate the final memory map into the boot protocol's structure;
//! 5. jump to the entry point the image names in its `KinTane` note.
//!
//! That is here, once, because there is more than one loader now: `kinboot-efi` reads the
//! kernel off a partition, and the EFI stub carries it inside itself. What differs is
//! where the bytes came from; what follows is identical, and the part that is easy to get
//! wrong.
//!
//! # Why the order matters
//!
//! Step 3 comes **after** step 2 because the map changes with every allocation, and the
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

use core::convert::Infallible;
use core::fmt::{self, Write};
use core::mem::{offset_of, size_of};
use core::sync::atomic::{AtomicPtr, Ordering};
use core::{ptr, slice};

use boot_protocol::Firmware;
use boot_protocol::image::{Image, ImageError};
use boot_protocol::tags::Builder;
use boot_protocol::uefi::boot_counter::FAILURES_BEFORE_SAFE;
use boot_protocol::uefi::{PAGE_SIZE, Runtime, memory_type, region};

use crate::counter::Attempt;
use crate::{BootServices, Handle, MemoryDescriptor, SimpleTextOutput, Status, SystemTable, arch};

/// The kernel's bootstrap page tables identity-map the first gigabyte, so the image and
/// the boot information must both lie below it.
pub const HANDOVER_LIMIT: u64 = 1 << 30;

/// The firmware call space maps the first 4 GiB, so it, and everything a runtime call
/// touches, must lie below this.
const CALL_SPACE_LIMIT: u64 = 1 << 32;

/// Pages of stack under the kernel's runtime calls: 64 KiB, several times what the variable
/// driver's deepest path, reclaiming a full store, is documented to need.
const CALL_STACK_PAGES: usize = 16;

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
static CON_OUT: AtomicPtr<SimpleTextOutput> = AtomicPtr::new(ptr::null_mut());

/// Print through the firmware's console until [`hand_over`] leaves boot services.
///
/// A loader calls this once, with the system table's `con_out`. It is here rather than in
/// each loader because the handover is what knows when that console stops existing, and a
/// console written to after `ExitBootServices` is a fault in firmware memory that has
/// just been handed to the kernel.
pub fn use_console(out: *mut SimpleTextOutput) {
    CON_OUT.store(out, Ordering::Relaxed);
}

/// The console: the firmware's while it is there, the serial port afterwards.
pub struct Console;

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

/// Write a line to whichever console is current. The loaders' `say!` is this.
pub fn log(args: fmt::Arguments<'_>) {
    let _ = Console.write_fmt(args);
}

/// Report a failure that happened after the firmware stopped being there to return to,
/// and stop.
pub fn fatal(args: fmt::Arguments<'_>) -> ! {
    log(format_args!("{args}\n"));
    arch::halt()
}

/// Where the firmware loaded the calling application, and how many bytes it occupies.
///
/// A UEFI application is relocatable — lld-link emits `.reloc` — so an image that carries
/// something inside itself cannot know where it is until it asks. The EFI stub asks,
/// because the kernel it hands over is at a fixed offset from this base and nowhere else.
/// The size is what lets it refuse an offset that points outside itself, rather than
/// reading wherever a corrupt descriptor says.
///
/// # Safety
/// `image` must be the calling application's handle, with boot services live.
pub unsafe fn image_extent(st: &SystemTable, image: Handle) -> Result<(usize, u64), Error> {
    // SAFETY: boot services are live, per the caller.
    let bs = unsafe { &*st.boot_services };
    let mut interface: *mut core::ffi::c_void = ptr::null_mut();
    // SAFETY: HandleProtocol on our own image handle, which always carries LoadedImage.
    check("finding this image", unsafe {
        (bs.handle_protocol)(image, &crate::LOADED_IMAGE_GUID, &mut interface)
    })?;
    // SAFETY: the firmware returned a LoadedImage interface, valid while this image is.
    let loaded = unsafe { &*interface.cast::<crate::LoadedImage>() };
    Ok((loaded.image_base.expose_provenance(), loaded.image_size))
}

/// Why a handover could not be made.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Error {
    /// A firmware call failed before anything was committed.
    Firmware(&'static str, Status),
    /// The bytes handed over are not a bootable kernel image.
    Image(ImageError),
    /// The image or the boot information would lie above [`HANDOVER_LIMIT`].
    TooHigh(u64),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Firmware(what, s) => write!(f, "{what} failed: status {:#x}", s.0),
            Error::Image(e) => write!(f, "the kernel image is not bootable: {e:?}"),
            Error::TooHigh(at) => {
                write!(f, "the kernel needs memory up to {at:#x}, above the 1 GiB handover limit")
            }
        }
    }
}

impl Error {
    /// The status a loader returns to the firmware for this failure.
    pub fn status(&self) -> Status {
        match self {
            Error::Firmware(_, s) => *s,
            Error::Image(_) | Error::TooHigh(_) => Status::LOAD_ERROR,
        }
    }
}

fn check(what: &'static str, s: Status) -> Result<(), Error> {
    s.ok().map_err(|s| Error::Firmware(what, s))
}

/// Place `kernel`, leave boot services, and enter it with `command_line`.
///
/// With `counter`, this boot's attempt as a counting loader recorded it, the kernel is also
/// given what it needs to confirm the boot later: a firmware call space and the runtime
/// entry points, in a `UefiRuntime` tag. See [`crate::counter`].
///
/// Returns only on a failure that happened while the firmware was still there to return
/// to. Anything that goes wrong after `ExitBootServices` stops the machine with a message,
/// because there is nothing left to return to that can be trusted.
///
/// # Safety
/// `image` and `st` must be the calling application's handle and system table, with boot
/// services not yet exited.
pub unsafe fn hand_over(
    image: Handle,
    st: &SystemTable,
    kernel: &[u8],
    command_line: &[u8],
    counter: Option<Attempt>,
) -> Result<Infallible, Error> {
    // SAFETY: boot services are live, per the caller.
    let bs = unsafe { &*st.boot_services };
    let parsed = Image::parse(kernel).map_err(Error::Image)?;
    if parsed.phys_end > HANDOVER_LIMIT {
        return Err(Error::TooHigh(parsed.phys_end));
    }

    // One allocation for the whole extent, page-aligned at both ends: segments may share
    // a page, and the gaps between them must be the kernel's too, not the firmware's.
    let start = parsed.phys_start & !(PAGE_SIZE - 1);
    let end = parsed.phys_end.div_ceil(PAGE_SIZE) * PAGE_SIZE;
    let pages = usize::try_from((end - start) / PAGE_SIZE).map_err(|_| Error::TooHigh(end))?;
    let mut at = start;
    // SAFETY: a boot services call with valid arguments; `at` is written by the firmware.
    check("allocating the kernel's pages", unsafe {
        (bs.allocate_pages)(crate::ALLOCATE_ADDRESS, memory_type::KINTANE_KERNEL, pages, &mut at)
    })?;
    // SAFETY: the firmware just gave us `[start, end)`, identity-mapped, and nothing else
    // refers to it. Zeroing all of it first is what makes `.bss` zero: its segment has
    // no file bytes.
    unsafe {
        ptr::write_bytes(
            ptr::with_exposed_provenance_mut::<u8>(start as usize),
            0,
            pages * PAGE_SIZE as usize,
        )
    };
    for seg in parsed.segments() {
        let seg = seg.map_err(Error::Image)?;
        // SAFETY: every segment lies within `[phys_start, phys_end)`, which `Image::parse`
        // established and the allocation above covers, and `seg.file` is inside the
        // caller's buffer, which is a different allocation.
        unsafe {
            ptr::copy_nonoverlapping(
                seg.file.as_ptr(),
                ptr::with_exposed_provenance_mut::<u8>(seg.phys as usize),
                seg.file.len(),
            );
        }
    }
    log(format_args!(
        "kinboot: kernel at {:#x}..{:#x}, entry {:#x}\n",
        parsed.phys_start, parsed.phys_end, parsed.entry
    ));

    let rsdp = find_rsdp(st);

    // Allocated while allocating is allowed. The final map, fetched below, then reports the
    // call space as the reserved memory it is.
    let runtime = match counter {
        // SAFETY: boot services are live, per the caller.
        Some(attempt) => Some(unsafe { call_space(st, bs, attempt) }?),
        None => None,
    };

    let mut info_at = HANDOVER_LIMIT - 1;
    // SAFETY: a boot services call with valid arguments.
    check("allocating the boot information", unsafe {
        (bs.allocate_pages)(
            crate::ALLOCATE_MAX_ADDRESS,
            memory_type::KINTANE_BOOT_DATA,
            BOOT_INFO_PAGES,
            &mut info_at,
        )
    })?;
    // SAFETY: just allocated for us, identity-mapped, BOOT_INFO_PAGES long.
    let info = unsafe {
        slice::from_raw_parts_mut(
            ptr::with_exposed_provenance_mut::<u8>(info_at as usize),
            BOOT_INFO_PAGES * PAGE_SIZE as usize,
        )
    };

    // SAFETY: boot services are live.
    let map = unsafe { map_buffer(bs)? };

    // The firmware's watchdog would reset the machine five minutes after the loader
    // started. The kernel owns the machine from here and has no idea it is armed.
    // SAFETY: disabling the watchdog is a boot services call with no pointer arguments.
    let _ = unsafe { (bs.set_watchdog_timer)(0, 0, 0, ptr::null()) };

    log(format_args!("kinboot: exiting boot services\n"));

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
                return Err(Error::Firmware("GetMemoryMap", s));
            }
            // Past a failed ExitBootServices the firmware may be half gone; there is
            // nothing to return to that can be trusted.
            fatal(format_args!(
                "kinboot: GetMemoryMap failed after ExitBootServices did: {:#x}",
                s.0
            ));
        }
        // SAFETY: `key` is from the map fetched immediately above.
        let s = unsafe { (bs.exit_boot_services)(image, key) };
        if s == Status::SUCCESS {
            break (size, descriptor_size);
        }
        attempt += 1;
        if attempt == EXIT_ATTEMPTS {
            fatal(format_args!(
                "kinboot: ExitBootServices failed {attempt} times, last status {:#x}",
                s.0
            ));
        }
    };
    // Boot services are gone: from here the console is the serial port.
    CON_OUT.store(ptr::null_mut(), Ordering::Relaxed);
    if attempt > 0 {
        log(format_args!(
            "kinboot: the map key went stale {attempt} time(s); retried with a fresh map\n"
        ));
    }

    build_boot_info(info, &map[..map_len], descriptor_size, &parsed, rsdp, command_line, runtime)
        .unwrap_or_else(|e| fatal(format_args!("kinboot: writing the boot information: {e:?}")));

    // SAFETY: boot services have exited; the kernel is loaded at its link addresses and
    // names `parsed.entry` as its protocol entry; the structure is complete; and both lie
    // below 1 GiB, identity-mapped by the firmware's tables, which are still loaded.
    unsafe { arch::enter(parsed.entry, info_at) }
}

/// A buffer for the final memory map, allocated while allocating is still allowed.
///
/// # Safety
/// Boot services must be live.
unsafe fn map_buffer(bs: &BootServices) -> Result<&'static mut [u8], Error> {
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
        return Err(Error::Firmware("GetMemoryMap (size query)", s));
    }
    // The allocation below adds descriptors of its own, and so may the firmware before
    // ExitBootServices; a map that does not fit then cannot be fetched again.
    let size = size + MAP_SLACK * descriptor_size.max(size_of::<MemoryDescriptor>());
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
    find(crate::ACPI_20_TABLE_GUID).or_else(|| find(crate::ACPI_10_TABLE_GUID))
}

/// Write the boot information: firmware kind, kernel range, RSDP, command line, the memory
/// map translated from the firmware's final descriptors, and the runtime call space when
/// there is one and the firmware lies inside it. Calls no firmware.
fn build_boot_info(
    buf: &mut [u8],
    map: &[u8],
    descriptor_size: usize,
    kernel: &Image<'_>,
    rsdp: Option<u64>,
    command_line: &[u8],
    runtime: Option<Runtime>,
) -> Result<usize, boot_protocol::Error> {
    use MemoryDescriptor as D;
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
    b.command_line(command_line)?;
    let mut m = b.memory_map(MAP_CAPACITY)?;
    // Whether every region the firmware needs at runtime lies inside the call space.
    let mut reachable = true;
    for d in map.chunks_exact(descriptor_size) {
        let field = |at: usize| u64::from_ne_bytes(d[at..at + 8].try_into().unwrap_or([0; 8]));
        let at = offset_of!(D, kind);
        let kind = u32::from_ne_bytes(d[at..at + 4].try_into().unwrap_or([0; 4]));
        let (start, pages) = (offset_of!(D, physical_start), offset_of!(D, number_of_pages));
        if field(offset_of!(D, attribute)) & crate::MEMORY_RUNTIME != 0 {
            let end = field(start).saturating_add(field(pages).saturating_mul(PAGE_SIZE));
            reachable &= end <= CALL_SPACE_LIMIT;
        }
        if let Some(r) = region(kind, field(start), field(pages)) {
            m.push(r)?;
        }
    }
    m.close();
    if let Some(r) = runtime {
        let entries = [r.get_variable, r.set_variable, r.reset_system];
        if reachable && entries.iter().all(|&e| e < CALL_SPACE_LIMIT) {
            b.uefi_runtime(&r)?;
        } else {
            // The count stands and this boot cannot clear it, so safe mode will come. That
            // is better than a kernel calling firmware its call space does not map.
            log(format_args!(
                "kinboot: the firmware's runtime regions lie above 4 GiB; this boot cannot be \
                 confirmed\n"
            ));
        }
    }
    Ok(b.finish())
}

/// Build what the kernel needs to call runtime services after the handover: an identity map
/// of the first 4 GiB and a stack, in memory the kernel sees as reserved, and the three
/// entry points it calls.
///
/// # Safety
/// Boot services must be live, and `st` and `bs` the calling application's.
unsafe fn call_space(
    st: &SystemTable,
    bs: &BootServices,
    attempt: Attempt,
) -> Result<Runtime, Error> {
    let pages = arch::CALL_TABLE_PAGES + CALL_STACK_PAGES;
    let mut at = CALL_SPACE_LIMIT - 1;
    // SAFETY: a boot services call with valid arguments.
    check("allocating the firmware call space", unsafe {
        (bs.allocate_pages)(
            crate::ALLOCATE_MAX_ADDRESS,
            memory_type::KINTANE_FIRMWARE_CALL,
            pages,
            &mut at,
        )
    })?;
    let len = pages * PAGE_SIZE as usize;
    // SAFETY: just allocated for us, identity-mapped, `len` bytes long.
    let space = unsafe {
        slice::from_raw_parts_mut(ptr::with_exposed_provenance_mut::<u8>(at as usize), len)
    };
    let root = arch::identity_4gib(space, at)
        .ok_or(Error::Firmware("building the firmware call space", Status::OUT_OF_RESOURCES))?;
    // SAFETY: runtime services are live while boot services are.
    let rt = unsafe { &*st.runtime_services };
    Ok(Runtime {
        call_root: root,
        call_stack_top: at + len as u64,
        get_variable: rt.get_variable as usize as u64,
        set_variable: rt.set_variable as usize as u64,
        reset_system: rt.reset_system as usize as u64,
        attempt: attempt.number,
        failures_before_safe: FAILURES_BEFORE_SAFE,
    })
}

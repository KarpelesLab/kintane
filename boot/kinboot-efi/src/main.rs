//! kinboot-efi: KinTane's UEFI loader.
//!
//! In order:
//!
//! 1. read the boot entries, `\KINTANE\BOOT.CFG`, off the partition this loader was started from,
//!    and show the menu (`boot/kinboot-menu`) until a key or the timeout chooses one;
//! 2. for a chainload entry, start the named EFI application with `LoadImage` and `StartImage`, and
//!    stop there;
//! 3. otherwise read the entry's kernel image and place its segments at the physical addresses it
//!    was linked for;
//! 4. find the ACPI RSDP while the firmware's tables can still be asked;
//! 5. `ExitBootServices`, retrying with a fresh memory map when the key has gone stale;
//! 6. translate the final memory map into the boot protocol's structure, with the entry's command
//!    line;
//! 7. jump to the entry point the image names in its `KinTane` note.
//!
//! Secure Boot, measured boot and the boot counter are in the design and not here;
//! `docs/bootloader.md` says which phase each belongs to.
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
use kinboot_menu::{Config, Key, Menu, OnFailure, Step, Target};
use uefi::{BootServices, Handle, Status, SystemTable};

/// Where the kernel lives on the EFI system partition, unless an entry names another.
/// FAT is case-insensitive, and the name is 8.3 so it needs no long-name entries.
const KERNEL_PATH: &str = "\\KINTANE\\KERNEL.ELF";

/// Where the boot entries live.
const CONFIG_PATH: &str = "\\KINTANE\\BOOT.CFG";

/// The entry booted when the partition has no usable list.
const FALLBACK: &[u8] = b"entry normal\ntitle KinTane (built-in default)\n";

/// The load options a chainloaded application is started with, UCS-2 and terminated, so it
/// can tell it was started by this loader and not by the firmware's boot manager.
const CHAIN_OPTIONS: [u16; 12] = {
    let text = b"kinboot-efi\0";
    let mut out = [0u16; 12];
    let mut i = 0;
    while i < text.len() {
        out[i] = text[i] as u16;
        i += 1;
    }
    out
};

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

/// Why nothing was started.
enum Failure {
    Firmware(&'static str, Status),
    /// A file on the boot partition could not be opened.
    Open(&'static str, Status),
    Image(ImageError),
    /// The image or the boot information would lie above [`HANDOVER_LIMIT`].
    TooHigh(u64),
    ShortRead {
        expected: usize,
        got: usize,
    },
    /// A path longer than the loader's name buffer.
    PathTooLong,
    /// An entry's command line does not fit the handover.
    CommandLine,
    /// A BIOS partition chainload entry, which UEFI has no equivalent of here.
    PartitionChain,
    /// A chainloaded application returned to the loader.
    ChainReturned(Status),
}

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Failure::Firmware(what, s) => write!(f, "{what} failed: status {:#x}", s.0),
            Failure::Open(path, s) => write!(f, "cannot open {path}: status {:#x}", s.0),
            Failure::Image(e) => write!(f, "the kernel image is not bootable: {e:?}"),
            Failure::TooHigh(at) => {
                write!(f, "the kernel needs memory up to {at:#x}, above the 1 GiB handover limit")
            }
            Failure::ShortRead { expected, got } => {
                write!(f, "read {got} of {expected} bytes of a file")
            }
            Failure::PathTooLong => write!(f, "a path in the boot entries is too long"),
            Failure::CommandLine => write!(f, "the entry's command line is too long"),
            Failure::PartitionChain => {
                write!(f, "chain-partition needs kinboot-bios; use chain-file")
            }
            Failure::ChainReturned(s) => {
                write!(f, "the chainloaded application returned: status {:#x}", s.0)
            }
        }
    }
}

impl Failure {
    fn status(&self) -> Status {
        match self {
            Failure::Firmware(_, s) | Failure::Open(_, s) | Failure::ChainReturned(s) => *s,
            Failure::ShortRead { .. }
            | Failure::Image(_)
            | Failure::TooHigh(_)
            | Failure::PathTooLong
            | Failure::CommandLine
            | Failure::PartitionChain => Status::LOAD_ERROR,
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

    let mut on_failure = OnFailure::Firmware;
    // SAFETY: `image` and `st` are what the firmware handed this application.
    let Err(failure) = unsafe { boot(image, st, &mut on_failure) };
    say!("kinboot-efi: {failure}\n");
    if on_failure == OnFailure::Reboot {
        say!("kinboot-efi: resetting, as the boot entries ask\n");
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

/// Choose an entry and boot it. Returns only on failure, and only while the firmware is
/// still there to return to.
///
/// # Safety
/// `image` and `st` must be this application's handle and system table, with boot
/// services not yet exited.
unsafe fn boot(
    image: Handle,
    st: &SystemTable,
    on_failure: &mut OnFailure,
) -> Result<Infallible, Failure> {
    // SAFETY: boot services are live, per the caller.
    let bs = unsafe { &*st.boot_services };

    // SAFETY: boot services are live; the file is a pool allocation nothing frees.
    let config = entries(unsafe { read_file(bs, image, CONFIG_PATH) });
    *on_failure = config.on_failure;
    // SAFETY: as above.
    let chosen = unsafe { choose(st, bs, &config) };
    let entry = config
        .entry(chosen)
        .unwrap_or_else(|| fatal(format_args!("the menu chose an entry that does not exist")));
    say!("kinboot-efi: booting {}\n", text(entry.title));

    match entry.target {
        // SAFETY: boot services are live.
        Target::ChainFile(path) => unsafe { chainload(bs, image, path) },
        Target::ChainPartition(_) => Err(Failure::PartitionChain),
        Target::Kernel { path, .. } => {
            let mut line = [0u8; cmdline::MAX_LINE];
            let n =
                kinboot_menu::kernel_command_line(&entry, &mut line).ok_or(Failure::CommandLine)?;
            let path = path.map_or(KERNEL_PATH, text);
            // SAFETY: as above.
            unsafe { boot_kernel(image, st, bs, path, &line[..n]) }
        }
    }
}

/// Bytes from the entry list as text. The parser admits only printable ASCII, so this
/// never falls back in practice.
fn text(bytes: &[u8]) -> &str {
    core::str::from_utf8(bytes).unwrap_or("?")
}

/// The entry list: the partition's, or the built-in default.
fn entries(file: Result<&'static [u8], Failure>) -> Config<'static> {
    let fallback = || {
        Config::parse(FALLBACK)
            .unwrap_or_else(|_| fatal(format_args!("the built-in boot entry does not parse")))
    };
    match file {
        Ok(bytes) => Config::parse(bytes).unwrap_or_else(|e| {
            say!(
                "kinboot-efi: {CONFIG_PATH} is unusable at line {}: {:?}; using the built-in default\n",
                e.line,
                e.kind
            );
            fallback()
        }),
        Err(Failure::Open(_, Status::NOT_FOUND)) => {
            say!("kinboot-efi: no {CONFIG_PATH}; using the built-in default\n");
            fallback()
        }
        Err(e) => {
            say!("kinboot-efi: reading {CONFIG_PATH}: {e}; using the built-in default\n");
            fallback()
        }
    }
}

/// Show the menu and wait for a key or the timeout.
///
/// # Safety
/// Boot services must be live.
unsafe fn choose(st: &SystemTable, bs: &BootServices, config: &Config<'_>) -> usize {
    let mut menu = Menu::new(config);
    kinboot_menu::render(config, &menu, &mut |b| say!("{}", text(b)));
    let mut step = menu.start();
    loop {
        match step {
            Step::Boot(i) => return i,
            Step::Moved(i) => say!("  marked {}\n", i + 1),
            Step::Wait => {}
        }
        // SAFETY: boot services are live, so the console input protocol is.
        step = match unsafe { read_key(st) } {
            Some(key) => menu.key(key),
            None => {
                // SAFETY: a boot services call with no pointer arguments.
                let _ = unsafe { (bs.stall)(1_000_000 / kinboot_menu::TICKS_PER_SECOND as usize) };
                menu.tick()
            }
        };
    }
}

/// A key from the firmware console, if one is waiting. The console includes the serial
/// port under OVMF, so this is also how a harness types at the menu.
///
/// # Safety
/// Boot services must be live.
unsafe fn read_key(st: &SystemTable) -> Option<Key> {
    if st.con_in.is_null() {
        return None;
    }
    let mut key = uefi::InputKey::default();
    // SAFETY: `con_in` is the firmware's console input protocol, valid while boot
    // services are; `key` is ours.
    let s = unsafe { ((*st.con_in).read_key_stroke)(st.con_in, &mut key) };
    if s.is_error() {
        return None;
    }
    Some(match key.scan_code {
        uefi::SCAN_UP => Key::Up,
        uefi::SCAN_DOWN => Key::Down,
        _ => Key::from_ascii(u8::try_from(key.unicode_char).unwrap_or(0)),
    })
}

/// Start another EFI application from the boot partition. Returns only if it cannot be
/// started, or if it returns.
///
/// # Safety
/// Boot services must be live and `image` this application's handle.
unsafe fn chainload(
    bs: &BootServices,
    image: Handle,
    path: &'static [u8],
) -> Result<Infallible, Failure> {
    let path = text(path);
    // SAFETY: as the caller guarantees.
    let file = unsafe { read_file(bs, image, path)? };
    // SAFETY: as above.
    let device_path = unsafe { file_device_path(bs, image, path)? };
    let mut child: Handle = ptr::null_mut();
    // SAFETY: a boot services call; `file` and `device_path` are pool allocations that
    // outlive it, and `child` is written by the firmware.
    check("loading the chainloaded image", unsafe {
        (bs.load_image)(false, image, device_path, file.as_ptr(), file.len(), &mut child)
    })?;
    let mut interface: *mut c_void = ptr::null_mut();
    // SAFETY: every image the firmware loaded carries LoadedImage.
    check("finding the chainloaded image", unsafe {
        (bs.handle_protocol)(child, &uefi::LOADED_IMAGE_GUID, &mut interface)
    })?;
    // SAFETY: the firmware returned the child's LoadedImage interface, which the
    // specification lets the loading application fill in before `StartImage`. The options
    // are a static and outlive the child.
    unsafe {
        let loaded = &mut *interface.cast::<uefi::LoadedImage>();
        loaded.load_options = CHAIN_OPTIONS.as_ptr().cast_mut().cast();
        loaded.load_options_size = size_of_val(&CHAIN_OPTIONS) as u32;
    }
    say!("kinboot-efi: starting {path}\n");
    // SAFETY: `child` was loaded above and has not been started.
    let s = unsafe { (bs.start_image)(child, ptr::null_mut(), ptr::null_mut()) };
    Err(Failure::ChainReturned(s))
}

/// The device path of `path` on the partition this loader came from: that partition's own
/// path with a file path node in place of its end node. `LoadImage` records it as the
/// child's `FilePath`, which is how a chainloaded application finds its own partition.
///
/// # Safety
/// Boot services must be live and `image` this application's handle.
unsafe fn file_device_path(
    bs: &BootServices,
    image: Handle,
    path: &str,
) -> Result<*const uefi::DevicePath, Failure> {
    // SAFETY: as the caller guarantees.
    let loaded = unsafe { loaded_image(bs, image)? };
    let mut interface: *mut c_void = ptr::null_mut();
    // SAFETY: HandleProtocol on the partition's handle.
    check("finding the boot partition's device path", unsafe {
        (bs.handle_protocol)(loaded.device_handle, &uefi::DEVICE_PATH_GUID, &mut interface)
    })?;
    let device = interface.cast::<u8>().cast_const();
    // Walk to the end node. Bounded, so a malformed path from the firmware cannot run on.
    let mut prefix = 0usize;
    for _ in 0..64 {
        // SAFETY: each node header is inside the path the firmware returned, and a node's
        // length says where the next begins.
        let (kind, sub, len) = unsafe {
            let n = device.add(prefix);
            (*n, *n.add(1), usize::from(u16::from_le_bytes([*n.add(2), *n.add(3)])))
        };
        if kind == uefi::DEVICE_PATH_END && sub == uefi::DEVICE_PATH_END_ENTIRE {
            break;
        }
        if len < 4 {
            return Err(Failure::Firmware(
                "walking the boot partition's device path",
                Status::LOAD_ERROR,
            ));
        }
        prefix += len;
    }
    let units = path.len() + 1;
    let node = 4 + units * 2;
    let total = prefix + node + 4;
    let node_len = u16::try_from(node).map_err(|_| Failure::PathTooLong)?;
    let mut buffer: *mut u8 = ptr::null_mut();
    // SAFETY: a pool allocation of `total` bytes.
    check("allocating a device path", unsafe {
        (bs.allocate_pool)(memory_type::LOADER_DATA, total, &mut buffer)
    })?;
    // SAFETY: `buffer` has `total` bytes: the prefix copied from the firmware's path, the
    // file path node, and the end node, written in that order and nowhere else.
    unsafe {
        ptr::copy_nonoverlapping(device, buffer, prefix);
        let n = buffer.add(prefix);
        *n = uefi::DEVICE_PATH_MEDIA;
        *n.add(1) = uefi::DEVICE_PATH_MEDIA_FILE;
        n.add(2)
            .copy_from_nonoverlapping(node_len.to_le_bytes().as_ptr(), 2);
        for (i, ch) in path.bytes().chain(core::iter::once(0)).enumerate() {
            n.add(4 + i * 2)
                .copy_from_nonoverlapping(u16::from(ch).to_le_bytes().as_ptr(), 2);
        }
        let end = n.add(node);
        *end = uefi::DEVICE_PATH_END;
        *end.add(1) = uefi::DEVICE_PATH_END_ENTIRE;
        *end.add(2) = 4;
        *end.add(3) = 0;
    }
    Ok(buffer.cast_const().cast())
}

/// This application's LoadedImage.
///
/// # Safety
/// Boot services must be live and `image` this application's handle.
unsafe fn loaded_image(
    bs: &BootServices,
    image: Handle,
) -> Result<&'static uefi::LoadedImage, Failure> {
    let mut interface: *mut c_void = ptr::null_mut();
    // SAFETY: HandleProtocol on our own image handle, which always carries LoadedImage.
    check("finding this loader's image", unsafe {
        (bs.handle_protocol)(image, &uefi::LOADED_IMAGE_GUID, &mut interface)
    })?;
    // SAFETY: the firmware returned a LoadedImage interface, valid while this image is.
    Ok(unsafe { &*interface.cast::<uefi::LoadedImage>() })
}

/// Load the kernel at `path` and hand over to it with `command_line`. Returns only on
/// failure, and only while the firmware is still there to return to.
///
/// # Safety
/// `image` and `st` must be this application's handle and system table, with boot
/// services not yet exited, and `bs` its boot services.
unsafe fn boot_kernel(
    image: Handle,
    st: &SystemTable,
    bs: &BootServices,
    path: &'static str,
    command_line: &[u8],
) -> Result<Infallible, Failure> {
    say!("kinboot-efi: loading {path}\n");
    // SAFETY: as above; the returned slice is a pool allocation nothing else frees.
    let file = unsafe { read_file(bs, image, path)? };
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

    build_boot_info(info, &map[..map_len], descriptor_size, &kernel, rsdp, command_line)
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

/// Read a whole file from the boot partition into a pool allocation.
///
/// # Safety
/// Boot services must be live and `image` this application's handle.
unsafe fn read_file(
    bs: &BootServices,
    image: Handle,
    path: &'static str,
) -> Result<&'static [u8], Failure> {
    // SAFETY: as the caller guarantees.
    let loaded = unsafe { loaded_image(bs, image)? };
    let mut interface: *mut c_void = ptr::null_mut();

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
    if path.len() >= name.len() {
        return Err(Failure::PathTooLong);
    }
    for (slot, ch) in name.iter_mut().zip(path.bytes()) {
        *slot = u16::from(ch);
    }
    let mut file: *mut uefi::File = ptr::null_mut();
    // SAFETY: `root` is an open directory; `name` is NUL-terminated (the path is shorter
    // than the buffer, whose tail stays zero).
    let opened = unsafe { ((*root).open)(root, &mut file, name.as_ptr(), uefi::FILE_MODE_READ, 0) };
    // SAFETY: `root` is open and no longer needed whatever happened.
    unsafe { ((*root).close)(root) };
    opened.ok().map_err(|s| Failure::Open(path, s))?;

    let result = (|| {
        // Seeking to the maximum position moves to the end of the file, which is the
        // specification's way to learn a file's size without the FileInfo structure.
        let mut size = 0u64;
        // SAFETY: `file` is open.
        unsafe {
            check("seeking a file", ((*file).set_position)(file, u64::MAX))?;
            check("sizing a file", ((*file).get_position)(file, &mut size))?;
            check("rewinding a file", ((*file).set_position)(file, 0))?;
        }
        let size = usize::try_from(size).map_err(|_| Failure::TooHigh(size))?;
        let mut buffer: *mut u8 = ptr::null_mut();
        // SAFETY: a pool allocation of `size` bytes.
        check("allocating a file buffer", unsafe {
            (bs.allocate_pool)(memory_type::LOADER_DATA, size, &mut buffer)
        })?;
        let mut done = 0;
        while done < size {
            let mut n = size - done;
            // SAFETY: `buffer` has `size - done` bytes left from `done`.
            check("reading a file", unsafe { ((*file).read)(file, &mut n, buffer.add(done)) })?;
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

/// Write the boot information: firmware kind, kernel range, RSDP, command line, and the
/// memory map translated from the firmware's final descriptors. Calls no firmware.
fn build_boot_info(
    buf: &mut [u8],
    map: &[u8],
    descriptor_size: usize,
    kernel: &Image<'_>,
    rsdp: Option<u64>,
    command_line: &[u8],
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
    b.command_line(command_line)?;
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

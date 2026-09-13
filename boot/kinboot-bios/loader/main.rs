//! `kinboot-bios` stage 2: from protected mode to a running kernel or another system.
//!
//! `stage2.rs` has switched to protected mode and called [`kinboot_main`] with the boot
//! drive. From here, in order:
//!
//! 1. **A20.** Test it; if the address line is masked, try the BIOS (INT 15h `2401h`), then the
//!    keyboard controller, then the "fast A20" port `0x92`, testing after each. The order is the
//!    conventional one: the BIOS knows its own chipset, and port 0x92 can do damage on the machines
//!    where it is something else.
//! 2. **Memory map.** E820, or E801 on a BIOS without it. The loader's own memory and the bounce
//!    buffer must be usable RAM in that map; otherwise nothing below is safe.
//! 3. **Boot entries.** Read the entry list from the disk and check its CRC-32, then show the menu
//!    on the screen and COM1 and wait for a key or the timeout. A list that does not parse is
//!    reported, and the loader boots its built-in default, normal mode with no arguments, rather
//!    than refusing to boot a machine over a typo.
//! 4. **Kernel.** Read the disk header, then stream the kernel off the disk in 32 KiB chunks
//!    through the bounce buffer. The ELF is validated from its first chunk, every segment's
//!    destination is checked against the memory map before a byte is written, and each chunk is
//!    copied to where it belongs. A CRC-32 of the whole file is checked against the header before
//!    the jump.
//! 5. **Handover.** Write the boot protocol's structure, with the entry's command line, in low
//!    memory and enter the kernel's 32-bit entry with `EAX = ENTRY32_MAGIC` and `EBX` pointing at
//!    it. Or, for a chainload entry, read the partition's boot record to `0x7C00` and jump to it in
//!    real mode.
//!
//! Before an entry is chosen, a failure prints `kinboot-bios: ` and the reason to COM1 and
//! the screen, then returns control to the BIOS with INT 18h. After, the entry list's
//! `on-failure` decides: INT 18h, or a reset.
//!
//! Every decision in that list is made by the `kinboot-bios` and `kinboot-menu` crates,
//! which have host tests. This file does the I/O.
//!
//! The loader runs single-threaded, identity-mapped, with interrupts disabled except
//! inside BIOS calls, and never returns.

#![no_std]
#![no_main]

mod bios;
mod stage1;
mod stage2;

use bios::{Disk, DiskError, MapError, MapSource};
use kinboot_bios::disk::{self, Crc32};
use kinboot_bios::elf::{self, Image};
use kinboot_bios::memmap::MemoryMap;
use kinboot_bios::{chain, handover};
use kinboot_menu::{Config, Menu, OnFailure, Step, Target};

/// Chunk of kernel read per disk request. Half the bounce buffer; the top of the buffer
/// is reserved for request packets.
const CHUNK_SECTORS: u32 = bios::MAX_READ_SECTORS;
const CHUNK_BYTES: usize = CHUNK_SECTORS as usize * disk::SECTOR;

/// Nothing is loaded below 1 MiB: that is the IVT, the loader, its buffers and the BIOS.
const KERNEL_FLOOR: u32 = 0x10_0000;

/// Low memory the loader uses, from the real-mode stack to the end of the bounce buffer.
const LOADER_LOW: u64 = 0x500;
const LOADER_HIGH: u64 = bios::BOUNCE as u64 + 0x1_0000;

const _: () = assert!(disk::CONFIG_MAX_BYTES == kinboot_menu::MAX_FILE);
const _: () = assert!(disk::CONFIG_MAX_BYTES <= CHUNK_BYTES);

unsafe extern "C" {
    static disk_header: u8;
    fn enter_kernel(entry: u32, info: u32, magic: u32) -> !;
    fn chain_boot(drive: u32, si: u32) -> !;
}

/// The handover, the entry list and the command line live in the loader's `.bss`,
/// which the link script keeps below the bounce buffer, inside the kernel's reserved low
/// memory.
static mut INFO: [u8; handover::BYTES] = [0; handover::BYTES];
static mut CONFIG: [u8; disk::CONFIG_MAX_BYTES] = [0; disk::CONFIG_MAX_BYTES];
static mut CMDLINE: [u8; cmdline::MAX_LINE] = [0; cmdline::MAX_LINE];

/// The entry booted when the disk has no usable list.
const FALLBACK: &[u8] = b"entry normal\ntitle KinTane (built-in default)\n";

enum Fatal {
    A20,
    Map(MapError),
    LowMemory,
    Header(disk::LayoutError),
    Disk(DiskError),
    ConfigChecksum,
    EmptyKernel,
    Elf(elf::Error),
    Checksum { expected: u32, actual: u32 },
    Handover,
    OtherKernel,
    ChainFile,
    Chain(chain::Error),
}

#[unsafe(no_mangle)]
pub extern "C" fn kinboot_main(drive: u32) -> ! {
    console::init();
    console::say("\r\nkinboot-bios: stage 2 from drive ");
    console::hex(drive, 2);
    let mut on_failure = OnFailure::Firmware;
    let Err(fatal) = boot(drive as u8, &mut on_failure);
    console::say("\r\nkinboot-bios: ");
    describe(fatal);
    console::say("\r\n");
    match on_failure {
        OnFailure::Firmware => bios::boot_failed(),
        OnFailure::Reboot => bios::reboot(),
    }
}

fn boot(drive: u8, on_failure: &mut OnFailure) -> Result<core::convert::Infallible, Fatal> {
    console::say("\r\n  a20      ");
    console::say(a20::enable().ok_or(Fatal::A20)?);

    let (map, source) = bios::memory_map().map_err(Fatal::Map)?;
    console::say("\r\n  memory   ");
    console::say(match source {
        MapSource::E820 => "e820, ",
        MapSource::E801 => "e801, ",
    });
    console::dec(map.entries().len() as u32);
    console::say(" entries, ");
    console::dec((map.usable_bytes() / (1024 * 1024)) as u32);
    console::say(" MiB usable");
    if !map.is_usable(LOADER_LOW, LOADER_HIGH - LOADER_LOW) {
        return Err(Fatal::LowMemory);
    }

    // SAFETY: `disk_header` is the first byte of the header stage 2 was assembled with,
    // which is `HEADER_BYTES` long and lives in stage 2's loaded image.
    let header = unsafe { core::slice::from_raw_parts(&raw const disk_header, disk::HEADER_BYTES) };
    let header = disk::Header::parse(header).map_err(Fatal::Header)?;

    let disk = Disk::open(drive).map_err(Fatal::Disk)?;
    console::say("\r\n  disk     ");
    console::say(if disk.uses_lba() { "lba" } else { "chs" });
    console::say(", kernel ");
    console::dec(header.kernel_bytes);
    console::say(" bytes at lba ");
    console::dec(header.kernel_lba);

    let config = entries(&disk, &header)?;
    *on_failure = config.on_failure;
    let chosen = choose(&config);
    let entry = config.entry(chosen).unwrap_or_else(|| unreachable_entry());
    console::say("\r\nkinboot-bios: booting ");
    console::bytes(entry.title);

    match entry.target {
        Target::Kernel { path: Some(_), .. } => Err(Fatal::OtherKernel),
        Target::ChainFile(_) => Err(Fatal::ChainFile),
        Target::ChainPartition(n) => chainload(&disk, drive, n),
        Target::Kernel { path: None, .. } => {
            // SAFETY: single-threaded, and this static is written only here, once.
            let line = unsafe { &mut *(&raw mut CMDLINE) };
            let n = kinboot_menu::kernel_command_line(&entry, line).ok_or(Fatal::Handover)?;
            let image = load(&disk, &header, &map)?;
            let info = handover(&map, &image, &line[..n])?;
            console::say("\r\n  cmdline  ");
            console::bytes(&line[..n]);
            console::say("\r\n  entry    ");
            console::hex(image.entry, 8);
            console::say("\r\n");
            // SAFETY: every loadable segment has been copied to RAM the firmware reported
            // free, the file's checksum matched, the structure is complete, and the machine
            // is in the state `boot_protocol::image` requires of a 32-bit entry.
            unsafe { enter_kernel(image.entry, info, boot_protocol::ENTRY32_MAGIC) }
        }
    }
}

/// The entry list: the disk's, or the built-in default if it has none or it is unusable.
fn entries(disk: &Disk, header: &disk::Header) -> Result<Config<'static>, Fatal> {
    let fallback = || Config::parse(FALLBACK).unwrap_or_else(|_| unreachable_entry());
    if header.config_bytes == 0 {
        console::say("\r\n  entries  none on this disk; using the built-in default");
        return Ok(fallback());
    }
    let len = header.config_bytes as usize;
    disk.read(header.config_lba, disk::sectors_for(len) as u32)
        .map_err(Fatal::Disk)?;
    // SAFETY: single-threaded, and this static is written only here, once. The bounce
    // buffer holds at least `len` bytes just read, `len` was bounded by `Header::parse`,
    // and the two do not overlap.
    let file = unsafe {
        let config = &mut *(&raw mut CONFIG);
        core::ptr::copy_nonoverlapping(bios::BOUNCE as *const u8, config.as_mut_ptr(), len);
        &config[..len]
    };
    if disk::crc32(file) != header.config_crc32 {
        return Err(Fatal::ConfigChecksum);
    }
    match Config::parse(file) {
        Ok(config) => Ok(config),
        Err(e) => {
            console::say("\r\nkinboot-bios: the boot entries are unusable at line ");
            console::dec(e.line);
            console::say("; using the built-in default");
            Ok(fallback())
        }
    }
}

/// Show the menu and wait for a choice or the timeout.
fn choose(config: &Config<'_>) -> usize {
    let mut menu = Menu::new(config);
    kinboot_menu::render(config, &menu, &mut console::bytes);
    let mut step = menu.start();
    loop {
        match step {
            Step::Boot(i) => return i,
            Step::Moved(i) => {
                console::say("\r\n  marked ");
                console::dec(i as u32 + 1);
            }
            Step::Wait => {}
        }
        step = match input::poll() {
            Some(key) => menu.key(key),
            None => {
                bios::wait_100ms();
                menu.tick()
            }
        };
    }
}

fn unreachable_entry() -> ! {
    console::say("\r\nkinboot-bios: internal error in the boot entries\r\n");
    bios::boot_failed()
}

fn load(disk: &Disk, header: &disk::Header, map: &MemoryMap) -> Result<Image, Fatal> {
    let total = header.kernel_bytes;
    if total == 0 {
        return Err(Fatal::EmptyKernel);
    }
    // SAFETY: the bounce buffer is RAM checked usable above, owned by the loader, and
    // not aliased: BIOS calls write it only while this slice is not being read.
    let bounce = unsafe { core::slice::from_raw_parts_mut(bios::BOUNCE as *mut u8, CHUNK_BYTES) };

    let first = (total as usize).min(CHUNK_BYTES);
    disk.read(header.kernel_lba, disk::sectors_for(first) as u32)
        .map_err(Fatal::Disk)?;
    let image = Image::parse(&bounce[..first], total, KERNEL_FLOOR).map_err(Fatal::Elf)?;
    image.check_placement(map).map_err(Fatal::Elf)?;

    for s in image.segments() {
        // SAFETY: `check_placement` proved `[paddr, paddr + memsz)` is usable RAM, and
        // `parse` that it is above the loader's floor, so it overlaps nothing in use.
        unsafe { core::ptr::write_bytes(s.paddr as *mut u8, 0, s.memsz as usize) };
    }

    console::say("\r\n  loading  ");
    let mut crc = Crc32::new();
    let mut plan = [elf::Copy {
        from: 0,
        len: 0,
        to: 0,
    }; elf::MAX_SEGMENTS];
    let mut offset = 0u32;
    while offset < total {
        let len = ((total - offset) as usize).min(CHUNK_BYTES);
        let lba = header.kernel_lba + offset / disk::SECTOR as u32;
        disk.read(lba, disk::sectors_for(len) as u32)
            .map_err(Fatal::Disk)?;
        let chunk = &bounce[..len];
        crc.update(chunk);
        let n = image.copy_plan(offset, chunk, &mut plan);
        for c in &plan[..n] {
            // SAFETY: `copy_plan` keeps `from + len` inside the chunk and `to` inside a
            // segment checked above; the bounce buffer is below the floor, so the two
            // ranges cannot overlap.
            unsafe {
                core::ptr::copy_nonoverlapping(chunk.as_ptr().add(c.from), c.to as *mut u8, c.len)
            };
        }
        offset += len as u32;
        console::say(".");
    }
    let actual = crc.finish();
    if actual != header.kernel_crc32 {
        return Err(Fatal::Checksum {
            expected: header.kernel_crc32,
            actual,
        });
    }
    console::say(" crc32 ");
    console::hex(actual, 8);
    Ok(image)
}

fn handover(map: &MemoryMap, image: &Image, cmdline: &[u8]) -> Result<u32, Fatal> {
    // SAFETY: single-threaded, and this static is written only here, once.
    let info = unsafe { &mut *(&raw mut INFO) };
    handover::write(info, map, image.extent(), cmdline).map_err(|_| Fatal::Handover)?;
    Ok(info.as_ptr() as u32)
}

/// Boot a partition's boot record the way a classic MBR does.
fn chainload(disk: &Disk, drive: u8, number: u8) -> Result<core::convert::Infallible, Fatal> {
    // SAFETY: the bounce buffer is RAM checked usable above; each read below fills its
    // first sector, which is copied out before the next read.
    let sector = || unsafe { *(bios::BOUNCE as *const [u8; disk::SECTOR]) };
    disk.read(0, 1).map_err(Fatal::Disk)?;
    let mbr = sector();
    let partition = chain::partition(&mbr, number).map_err(Fatal::Chain)?;
    disk.read(partition.start_lba, 1).map_err(Fatal::Disk)?;
    let record = sector();
    chain::check_boot_record(&partition, &record).map_err(Fatal::Chain)?;

    console::say("\r\n  chain    partition ");
    console::dec(u32::from(number));
    console::say(" at lba ");
    console::dec(partition.start_lba);
    console::say("\r\n");
    // SAFETY: 0x600 and 0x7C00 are conventional memory below the loader's own stage 2 at
    // 0x7E00, and nothing reads them again: stage 1 has done its work, and the real-mode
    // stack used by the switch is below 0x7C00 and above the 0x600 copy's end at 0x800.
    unsafe {
        core::ptr::copy_nonoverlapping(
            mbr.as_ptr(),
            chain::MBR_COPY_ADDRESS as *mut u8,
            disk::SECTOR,
        );
        core::ptr::copy_nonoverlapping(
            record.as_ptr(),
            chain::LOAD_ADDRESS as *mut u8,
            disk::SECTOR,
        );
        chain_boot(u32::from(drive), u32::from(partition.si()))
    }
}

fn describe(f: Fatal) {
    use console::{dec, hex, say};
    match f {
        Fatal::A20 => say("cannot enable the A20 line"),
        Fatal::Map(MapError::Unsupported) => say("the BIOS reports no memory map (E820, E801)"),
        Fatal::Map(MapError::Decode(e)) => {
            say("the BIOS memory map is unusable: ");
            say(match e {
                kinboot_bios::memmap::Error::Full => "too many entries",
                kinboot_bios::memmap::Error::EntrySize(_) => "bad entry size",
                kinboot_bios::memmap::Error::Empty => "no usable memory",
            });
        }
        Fatal::LowMemory => say("the loader's own low memory is not usable RAM"),
        Fatal::Header(e) => {
            say("stage 2 disk header is damaged: ");
            say(match e {
                disk::LayoutError::TooShort => "truncated",
                disk::LayoutError::BadMagic => "bad magic",
                disk::LayoutError::Version(_) => "unknown version",
                disk::LayoutError::HeaderSize(_) => "bad size",
                disk::LayoutError::ConfigTooLarge => "boot entries too large",
            });
        }
        Fatal::Disk(DiskError::Read { lba, status }) => {
            say("disk read failed at lba ");
            dec(lba);
            say(", status ");
            hex(status as u32, 2);
        }
        Fatal::Disk(DiskError::NoGeometry) => say("disk has neither LBA nor a CHS geometry"),
        Fatal::Disk(DiskError::BeyondChs { lba }) => {
            say("kernel is beyond what CHS can address, at lba ");
            dec(lba);
        }
        Fatal::ConfigChecksum => say("boot entries checksum mismatch"),
        Fatal::EmptyKernel => say("the disk carries no kernel"),
        Fatal::Elf(e) => {
            say("kernel image rejected: ");
            say(elf_reason(e));
        }
        Fatal::Checksum { expected, actual } => {
            say("kernel checksum mismatch: expected ");
            hex(expected, 8);
            say(", read ");
            hex(actual, 8);
        }
        Fatal::Handover => say("the boot information does not fit"),
        Fatal::OtherKernel => say("this loader boots only the kernel on its own disk"),
        Fatal::ChainFile => say("chainloading a file needs kinboot-efi; use chain-partition"),
        Fatal::Chain(e) => {
            say("cannot chainload: ");
            match e {
                chain::Error::NoSuchPartition(n) => {
                    say("no partition ");
                    dec(u32::from(n));
                }
                chain::Error::EmptyPartition(n) => {
                    say("partition ");
                    dec(u32::from(n));
                    say(" is empty");
                }
                chain::Error::BadMbr => say("the MBR has no signature"),
                chain::Error::NotBootable(n) => {
                    say("partition ");
                    dec(u32::from(n));
                    say(" has no boot record");
                }
            }
        }
    }
}

fn elf_reason(e: elf::Error) -> &'static str {
    use elf::Error::*;
    match e {
        Truncated => "headers do not fit the first chunk",
        NotElf => "not an ELF file",
        WrongClass => "not 32-bit little-endian",
        WrongMachine(_) => "not an i386 executable",
        NotExecutable(_) => "not an executable",
        BadPhentsize(_) => "bad program header size",
        TooManySegments(_) => "too many program headers",
        SegmentBounds { .. } => "a segment lies outside the file",
        SegmentWraps { .. } => "a segment wraps past 4 GiB",
        BelowFloor { .. } => "a segment loads below 1 MiB",
        NotRam { .. } => "a segment is not in usable RAM",
        NoLoadableSegment => "nothing to load",
        NoMultibootHeader => "no 32-bit entry (multiboot header)",
        MultibootChecksum => "multiboot header checksum",
        MultibootUnsupported(_) => "multiboot header requires an unsupported feature",
    }
}

mod input {
    //! Keys for the boot menu, from the BIOS keyboard and from COM1.

    use kinboot_menu::Key;

    use crate::bios;
    use crate::port::inb;

    const COM1: u16 = 0x3F8;

    /// A key if one is waiting, without blocking.
    pub fn poll() -> Option<Key> {
        // SAFETY: reading the 16550's line status and, when bit 0 says a byte is there,
        // its receive buffer, which consumes exactly that byte.
        unsafe {
            if inb(COM1 + 5) & 1 != 0 {
                return Some(Key::from_ascii(inb(COM1)));
            }
        }
        let (scan, ascii) = bios::key()?;
        Some(match (scan, ascii) {
            (0x48, 0) => Key::Up,
            (0x50, 0) => Key::Down,
            (_, a) => Key::from_ascii(a),
        })
    }
}

mod a20 {
    //! The A20 line: without it, bit 20 of every address is forced to zero, so the
    //! kernel's 1 MiB load address aliases the IVT.

    use crate::bios;
    use crate::port::{inb, outb};

    /// Enable A20, returning the method that worked, or `None`.
    pub fn enable() -> Option<&'static str> {
        if enabled() {
            return Some("already enabled");
        }
        bios::a20_enable();
        if enabled() {
            return Some("enabled by the BIOS");
        }
        keyboard_controller();
        if enabled() {
            return Some("enabled through the keyboard controller");
        }
        // SAFETY: port 0x92 is "system control port A" on every PC since the PS/2. Bit 1
        // is A20; bit 0 resets the machine and is written as zero.
        unsafe { outb(0x92, (inb(0x92) | 2) & !1) };
        if enabled() {
            return Some("enabled through port 0x92");
        }
        None
    }

    /// Whether writing at 1 MiB + x is distinct from writing at x.
    ///
    /// Tests a byte of the BIOS data area's scratch region, restoring both locations, and
    /// repeats the test with two different values so a coincidentally equal byte cannot
    /// pass for an enabled line.
    fn enabled() -> bool {
        const LOW: *mut u8 = 0x0000_0500 as *mut u8;
        const HIGH: *mut u8 = 0x0010_0500 as *mut u8;
        // SAFETY: 0x500 is the DOS scratch area, which the loader does not use, and
        // 1 MiB + 0x500 is either RAM or, with A20 masked, the same byte. Both are
        // restored.
        unsafe {
            let (low, high) = (LOW.read_volatile(), HIGH.read_volatile());
            let mut distinct = true;
            for probe in [0x5Au8, 0xA5] {
                LOW.write_volatile(probe);
                HIGH.write_volatile(!probe);
                distinct &= LOW.read_volatile() == probe;
            }
            HIGH.write_volatile(high);
            LOW.write_volatile(low);
            distinct
        }
    }

    fn keyboard_controller() {
        // SAFETY: the 8042 command sequence for writing its output port, with A20 (bit 1)
        // set and the reset line (bit 0) held high, i.e. not asserted.
        unsafe {
            wait_input_empty();
            outb(0x64, 0xD1);
            wait_input_empty();
            outb(0x60, 0xDF);
            wait_input_empty();
        }
    }

    unsafe fn wait_input_empty() {
        // Bounded: a machine without an 8042 must not hang the loader here.
        for _ in 0..100_000 {
            // SAFETY: reading the 8042 status register has no side effects.
            if unsafe { inb(0x64) } & 2 == 0 {
                return;
            }
        }
    }
}

mod port {
    /// # Safety
    /// Writing an I/O port can do anything the device behind it does.
    pub unsafe fn outb(port: u16, value: u8) {
        // SAFETY: the caller vouches for the port.
        unsafe {
            core::arch::asm!("out dx, al", in("dx") port, in("al") value,
                options(nomem, nostack, preserves_flags))
        };
    }

    /// # Safety
    /// Reading an I/O port can have side effects on the device behind it.
    pub unsafe fn inb(port: u16) -> u8 {
        let value: u8;
        // SAFETY: the caller vouches for the port.
        unsafe {
            core::arch::asm!("in al, dx", in("dx") port, out("al") value,
                options(nomem, nostack, preserves_flags))
        };
        value
    }
}

mod console {
    //! COM1 and the BIOS screen. Serial is what the test harness reads; the screen is
    //! what a person at a real machine reads.

    use crate::bios;
    use crate::port::{inb, outb};

    const COM1: u16 = 0x3F8;

    pub fn init() {
        // SAFETY: the standard 16550 programming sequence on COM1: 115200 8N1, FIFOs on.
        unsafe {
            outb(COM1 + 1, 0x00);
            outb(COM1 + 3, 0x80);
            outb(COM1, 0x01);
            outb(COM1 + 1, 0x00);
            outb(COM1 + 3, 0x03);
            outb(COM1 + 2, 0xC7);
            outb(COM1 + 4, 0x0B);
        }
    }

    fn putc(c: u8) {
        // SAFETY: COM1 was programmed by `init`. Waiting for the transmitter is bounded,
        // so a machine without a UART costs time, not a hang.
        unsafe {
            for _ in 0..10_000 {
                if inb(COM1 + 5) & 0x20 != 0 {
                    break;
                }
            }
            outb(COM1, c);
        }
        bios::teletype(c);
    }

    pub fn bytes(s: &[u8]) {
        for &b in s {
            putc(b);
        }
    }

    pub fn say(s: &str) {
        bytes(s.as_bytes());
    }

    pub fn hex(v: u32, digits: u32) {
        say("0x");
        for i in (0..digits).rev() {
            let nibble = (v >> (i * 4)) & 0xF;
            putc(b"0123456789abcdef"[nibble as usize]);
        }
    }

    pub fn dec(v: u32) {
        let mut buf = [0u8; 10];
        bytes(kinboot_menu::decimal(v, &mut buf));
    }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    // No formatting: the message machinery would cost stage 2 a large part of its
    // budget, and every input a panic could come from has already been validated.
    console::say("\r\nkinboot-bios: internal error\r\n");
    bios::boot_failed()
}

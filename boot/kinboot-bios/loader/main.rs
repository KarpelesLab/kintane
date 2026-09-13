//! `kinboot-bios` stage 2: from protected mode to a running kernel.
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
//! 3. **Kernel.** Read the disk header, then stream the kernel off the disk in 32 KiB chunks
//!    through the bounce buffer. The ELF is validated from its first chunk, every segment's
//!    destination is checked against the memory map before a byte is written, and each chunk is
//!    copied to where it belongs. A CRC-32 of the whole file is checked against the header before
//!    the jump.
//! 4. **Handover.** Build the Multiboot 1 information structure in low memory and jump to the ELF
//!    entry point with `EAX = 0x2BADB002` and `EBX` pointing at it.
//!
//! Any failure prints `kinboot-bios: ` and the reason to COM1 and the screen, then
//! returns control to the BIOS with INT 18h.
//!
//! Every decision in that list is made by the `kinboot-bios` crate, which has host
//! tests. This file does the I/O.
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
use kinboot_bios::mbinfo;
use kinboot_bios::memmap::MemoryMap;

/// Chunk of kernel read per disk request. Half the bounce buffer; the top of the buffer
/// is reserved for request packets.
const CHUNK_SECTORS: u32 = bios::MAX_READ_SECTORS;
const CHUNK_BYTES: usize = CHUNK_SECTORS as usize * disk::SECTOR;

/// Nothing is loaded below 1 MiB: that is the IVT, the loader, its buffers and the BIOS.
const KERNEL_FLOOR: u32 = 0x10_0000;

/// Low memory the loader uses, from the real-mode stack to the end of the bounce buffer.
const LOADER_LOW: u64 = 0x500;
const LOADER_HIGH: u64 = bios::BOUNCE as u64 + 0x1_0000;

unsafe extern "C" {
    static disk_header: u8;
    fn enter_kernel(entry: u32, info: u32) -> !;
}

/// The Multiboot handover lives in the loader's `.bss`, which the link script keeps
/// below the bounce buffer, inside the kernel's reserved low memory.
static mut INFO: [u8; mbinfo::INFO_BYTES] = [0; mbinfo::INFO_BYTES];
static mut MMAP: [u8; kinboot_bios::memmap::MAX_ENTRIES * mbinfo::MMAP_ENTRY_BYTES] =
    [0; kinboot_bios::memmap::MAX_ENTRIES * mbinfo::MMAP_ENTRY_BYTES];
static mut CMDLINE: [u8; disk::CMDLINE_BYTES] = [0; disk::CMDLINE_BYTES];
static LOADER_NAME: [u8; 13] = *b"kinboot-bios\0";

enum Fatal {
    A20,
    Map(MapError),
    LowMemory,
    Header(disk::LayoutError),
    Disk(DiskError),
    EmptyKernel,
    Elf(elf::Error),
    Checksum { expected: u32, actual: u32 },
    Handover,
}

#[unsafe(no_mangle)]
pub extern "C" fn kinboot_main(drive: u32) -> ! {
    console::init();
    console::say("\r\nkinboot-bios: stage 2 from drive ");
    console::hex(drive, 2);
    let Err(fatal) = boot(drive as u8);
    console::say("\r\nkinboot-bios: ");
    describe(fatal);
    console::say("\r\n");
    bios::boot_failed()
}

fn boot(drive: u8) -> Result<core::convert::Infallible, Fatal> {
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

    let image = load(&disk, &header, &map)?;
    let info = handover(&map, drive, &header)?;

    console::say("\r\n  entry    ");
    console::hex(image.entry, 8);
    console::say("\r\n");
    // SAFETY: every loadable segment has been copied to RAM the firmware reported free,
    // the file's checksum matched, and the machine is in the state Multiboot 1 requires.
    unsafe { enter_kernel(image.entry, info) }
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

fn handover(map: &MemoryMap, drive: u8, header: &disk::Header) -> Result<u32, Fatal> {
    // SAFETY: single-threaded, and these statics are written only here, once.
    let (info, mmap, cmdline) =
        unsafe { (&mut *(&raw mut INFO), &mut *(&raw mut MMAP), &mut *(&raw mut CMDLINE)) };
    cmdline.copy_from_slice(&header.cmdline);
    let addresses = mbinfo::Addresses {
        mmap: mmap.as_ptr() as u32,
        cmdline: cmdline.as_ptr() as u32,
        loader_name: LOADER_NAME.as_ptr() as u32,
    };
    mbinfo::write(info, mmap, map, drive, addresses).map_err(|_| Fatal::Handover)?;
    Ok(info.as_ptr() as u32)
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
                disk::LayoutError::CmdlineTooLong => "command line too long",
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
        Fatal::Handover => say("memory map does not fit the handover"),
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
        NoMultibootHeader => "no multiboot header",
        MultibootChecksum => "multiboot header checksum",
        MultibootUnsupported(_) => "multiboot header requires an unsupported feature",
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

    pub fn say(s: &str) {
        for &b in s.as_bytes() {
            putc(b);
        }
    }

    pub fn hex(v: u32, digits: u32) {
        say("0x");
        for i in (0..digits).rev() {
            let nibble = (v >> (i * 4)) & 0xF;
            putc(b"0123456789abcdef"[nibble as usize]);
        }
    }

    pub fn dec(mut v: u32) {
        let mut buf = [0u8; 10];
        let mut i = buf.len();
        loop {
            i -= 1;
            buf[i] = b'0' + (v % 10) as u8;
            v /= 10;
            if v == 0 {
                break;
            }
        }
        for &b in &buf[i..] {
            putc(b);
        }
    }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    // No formatting: the message machinery would cost stage 2 a large part of its
    // budget, and every input a panic could come from has already been validated.
    console::say("\r\nkinboot-bios: internal error\r\n");
    bios::boot_failed()
}

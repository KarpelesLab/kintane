//! BIOS services, called from protected mode through the real-mode thunk in `stage2.rs`.
//!
//! Each function sets up the registers one service documents and interprets what comes
//! back; none of them decides anything beyond that. What to do with a memory map or a
//! failed read is `main.rs`'s business, and decoding the map is tested in the
//! `kinboot-bios` crate.

use kinboot_bios::memmap::{self, MemoryMap};

/// Registers passed to and returned from a BIOS call. The layout is `bios_regs` in
/// `stage2.rs`.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Regs {
    pub eax: u32,
    pub ebx: u32,
    pub ecx: u32,
    pub edx: u32,
    pub esi: u32,
    pub edi: u32,
    pub ebp: u32,
    pub ds: u16,
    pub es: u16,
    pub eflags: u32,
}

const _: () = assert!(core::mem::size_of::<Regs>() == 36);

impl Regs {
    fn carry(&self) -> bool {
        self.eflags & 1 != 0
    }
    fn ah(&self) -> u8 {
        (self.eax >> 8) as u8
    }
}

unsafe extern "C" {
    static mut bios_regs: Regs;
    fn bios_int(vector: u32);
}

/// Call real-mode interrupt `vector`.
pub fn call(vector: u8, regs: Regs) -> Regs {
    // SAFETY: the loader is single-threaded and runs with interrupts off, so nothing
    // else touches `bios_regs` between the write and the read. The thunk preserves the
    // callee-saved registers and returns on the stack it was called on.
    unsafe {
        (&raw mut bios_regs).write(regs);
        bios_int(vector as u32);
        (&raw const bios_regs).read()
    }
}

/// Where real-mode services read and write buffers: the fixed bounce buffer, which is
/// segment `0x2000`. Data is at offset 0; small request packets go at the top.
pub const BOUNCE: u32 = 0x2_0000;
const BOUNCE_SEGMENT: u16 = 0x2000;
const PACKET_OFFSET: u16 = 0xFFF0;

/// A BIOS disk, read by LBA if the BIOS supports it and by CHS otherwise.
pub struct Disk {
    drive: u8,
    geometry: Option<Geometry>,
}

#[derive(Clone, Copy)]
struct Geometry {
    sectors_per_track: u32,
    heads: u32,
}

#[derive(Clone, Copy, Debug)]
pub enum DiskError {
    /// INT 13h failed; the status from `AH`.
    Read { lba: u32, status: u8 },
    /// Neither LBA nor a usable CHS geometry.
    NoGeometry,
    /// A CHS address past cylinder 1023, which CHS cannot express.
    BeyondChs { lba: u32 },
}

/// Sectors per extended read. The limit some BIOSes impose is 127.
pub const MAX_READ_SECTORS: u32 = 64;

impl Disk {
    pub fn open(drive: u8) -> Result<Disk, DiskError> {
        let r = call(
            0x13,
            Regs {
                eax: 0x4100,
                ebx: 0x55AA,
                edx: drive as u32,
                ..Regs::default()
            },
        );
        if !r.carry() && r.ebx & 0xFFFF == 0xAA55 && r.ecx & 1 != 0 {
            return Ok(Disk {
                drive,
                geometry: None,
            });
        }
        let r = call(
            0x13,
            Regs {
                eax: 0x0800,
                edx: drive as u32,
                ..Regs::default()
            },
        );
        let sectors_per_track = r.ecx & 0x3F;
        let heads = ((r.edx >> 8) & 0xFF) + 1;
        if r.carry() || sectors_per_track == 0 {
            return Err(DiskError::NoGeometry);
        }
        Ok(Disk {
            drive,
            geometry: Some(Geometry {
                sectors_per_track,
                heads,
            }),
        })
    }

    pub fn uses_lba(&self) -> bool {
        self.geometry.is_none()
    }

    /// Read `count` sectors (at most [`MAX_READ_SECTORS`]) from `lba` into the bounce
    /// buffer. Each failed request is retried after a controller reset, because floppies
    /// and old drives fail the first read after a motor spin-up as a matter of course.
    pub fn read(&self, lba: u32, count: u32) -> Result<(), DiskError> {
        debug_assert!(count <= MAX_READ_SECTORS);
        match self.geometry {
            None => self.retry(|| self.read_lba(lba, count)),
            Some(g) => {
                for i in 0..count {
                    self.retry(|| self.read_chs(g, lba + i, i))?;
                }
                Ok(())
            }
        }
    }

    fn retry(&self, mut op: impl FnMut() -> Result<(), DiskError>) -> Result<(), DiskError> {
        let mut last = op();
        for _ in 0..2 {
            if last.is_ok() {
                break;
            }
            call(
                0x13,
                Regs {
                    edx: self.drive as u32,
                    ..Regs::default()
                },
            );
            last = op();
        }
        last
    }

    fn read_lba(&self, lba: u32, count: u32) -> Result<(), DiskError> {
        let packet = (BOUNCE + PACKET_OFFSET as u32) as *mut u8;
        let mut dap = [0u8; 16];
        dap[0] = 16;
        dap[2..4].copy_from_slice(&(count as u16).to_le_bytes());
        dap[4..6].copy_from_slice(&0u16.to_le_bytes());
        dap[6..8].copy_from_slice(&BOUNCE_SEGMENT.to_le_bytes());
        dap[8..12].copy_from_slice(&lba.to_le_bytes());
        // SAFETY: the top 16 bytes of the bounce buffer are reserved for request packets
        // and are identity-mapped RAM; `main.rs` checked the buffer is usable.
        unsafe { core::ptr::copy_nonoverlapping(dap.as_ptr(), packet, dap.len()) };
        let r = call(
            0x13,
            Regs {
                eax: 0x4200,
                edx: self.drive as u32,
                ds: BOUNCE_SEGMENT,
                esi: PACKET_OFFSET as u32,
                ..Regs::default()
            },
        );
        if r.carry() {
            return Err(DiskError::Read {
                lba,
                status: r.ah(),
            });
        }
        Ok(())
    }

    fn read_chs(&self, g: Geometry, lba: u32, slot: u32) -> Result<(), DiskError> {
        let sector = lba % g.sectors_per_track + 1;
        let t = lba / g.sectors_per_track;
        let head = t % g.heads;
        let cylinder = t / g.heads;
        if cylinder > 1023 {
            return Err(DiskError::BeyondChs { lba });
        }
        let r = call(
            0x13,
            Regs {
                eax: 0x0201,
                ecx: (cylinder & 0xFF) << 8 | (cylinder >> 8) << 6 | sector,
                edx: head << 8 | self.drive as u32,
                es: BOUNCE_SEGMENT,
                ebx: slot * 512,
                ..Regs::default()
            },
        );
        if r.carry() {
            return Err(DiskError::Read {
                lba,
                status: r.ah(),
            });
        }
        Ok(())
    }
}

/// `SMAP`, which E820 wants in `EDX` and returns in `EAX`.
const SMAP: u32 = 0x534D_4150;

/// Where the memory map came from.
#[derive(Clone, Copy)]
pub enum MapSource {
    E820,
    E801,
}

#[derive(Clone, Copy, Debug)]
pub enum MapError {
    /// Neither E820 nor E801 answered.
    Unsupported,
    /// The firmware's answer did not decode.
    Decode(memmap::Error),
}

/// The firmware's memory map: E820 if the BIOS has it, E801 otherwise.
pub fn memory_map() -> Result<(MemoryMap, MapSource), MapError> {
    match e820() {
        Ok(map) => Ok((map, MapSource::E820)),
        Err(MapError::Unsupported) => e801().map(|m| (m, MapSource::E801)),
        Err(e) => Err(e),
    }
}

fn e820() -> Result<MemoryMap, MapError> {
    let mut map = MemoryMap::new();
    let mut continuation = 0u32;
    let buffer = BOUNCE as *mut [u8; 24];
    // Bounded: real firmware reports a few dozen entries, and a BIOS that never clears
    // the continuation value must not hang the loader.
    for call_index in 0..256 {
        let mut entry = [0u8; 24];
        // The ACPI 3.0 "enabled" bit, preset so that a BIOS returning 20 bytes (and so
        // never writing attributes) leaves an entry that reads as enabled.
        entry[20] = 1;
        // SAFETY: the bounce buffer is RAM the loader owns, checked usable by `main.rs`
        // before any service writes into it.
        unsafe { buffer.write(entry) };
        let r = call(
            0x15,
            Regs {
                eax: 0xE820,
                ebx: continuation,
                ecx: 24,
                edx: SMAP,
                es: BOUNCE_SEGMENT,
                edi: 0,
                ..Regs::default()
            },
        );
        // Carry on the first call means E820 is not implemented; on a later call it
        // means the previous entry was the last.
        if r.carry() || r.eax != SMAP {
            return if call_index == 0 {
                Err(MapError::Unsupported)
            } else {
                finish(map)
            };
        }
        // SAFETY: as above; the BIOS has filled up to 24 bytes.
        let entry = unsafe { buffer.read() };
        map.push_e820(&entry, r.ecx).map_err(MapError::Decode)?;
        continuation = r.ebx;
        if continuation == 0 {
            return finish(map);
        }
    }
    finish(map)
}

fn finish(map: MemoryMap) -> Result<MemoryMap, MapError> {
    map.check_nonempty().map_err(MapError::Decode)?;
    Ok(map)
}

fn e801() -> Result<MemoryMap, MapError> {
    let r = call(
        0x15,
        Regs {
            eax: 0xE801,
            ..Regs::default()
        },
    );
    if r.carry() {
        return Err(MapError::Unsupported);
    }
    // Some BIOSes answer in AX/BX and some in CX/DX; either pair may be the zero one.
    let (low, high) = if r.eax & 0xFFFF != 0 || r.ebx & 0xFFFF != 0 {
        (r.eax as u16, r.ebx as u16)
    } else {
        (r.ecx as u16, r.edx as u16)
    };
    let conventional = call(0x12, Regs::default()).eax as u16;
    MemoryMap::from_e801(conventional, low, high).map_err(MapError::Decode)
}

/// Ask the BIOS to enable A20 (INT 15h, `AX=2401h`).
pub fn a20_enable() {
    call(
        0x15,
        Regs {
            eax: 0x2401,
            ..Regs::default()
        },
    );
}

/// One character to the screen.
pub fn teletype(c: u8) {
    call(
        0x10,
        Regs {
            eax: 0x0E00 | c as u32,
            ebx: 0x0007,
            ..Regs::default()
        },
    );
}

/// Give up: INT 18h tells the BIOS this device did not boot. A real machine tries its
/// next boot device; QEMU with `-boot reboot-timeout=0 -no-reboot` exits.
pub fn boot_failed() -> ! {
    call(0x18, Regs::default());
    loop {
        // SAFETY: halting with interrupts off is the loader's terminal state if the
        // BIOS returns from INT 18h, which the specification does not allow.
        unsafe { core::arch::asm!("cli", "hlt", options(nomem, nostack)) };
    }
}

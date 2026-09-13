//! The kernel image entry point.
//!
//! Phase 0: bring up the early console, say who we are, and stop. Everything the
//! banner prints comes from either the `hal` traits or the generated configuration,
//! so it is a live check that both paths work rather than a hardcoded string.

#![no_std]
#![no_main]
// A shared mutable static with a documented invariant. `static mut` is forbidden by
// docs/coding-standards.md; this is the replacement it names.
#![feature(sync_unsafe_cell)]


use arch::Cpu;
use boot_protocol::{MemoryKind, MemoryRegion};
use core::cell::SyncUnsafeCell;
use hal::{Arch, EarlyConsole, HasMmu};
use mm::phys::{bitmap_bytes, FrameAllocator};

/// Entry from the architecture's boot code, which has already established a stack,
/// whatever execution mode the target needs, and an identity mapping.
///
/// `boot_arg` is whatever the platform's loader left in the first argument register:
/// the multiboot info pointer on x86, a device tree pointer on aarch64. Turning it
/// into a `BootInfo` is the next piece of work.
///
/// # Safety
/// Called exactly once, by `_start`, with interrupts masked.
#[unsafe(no_mangle)]
pub extern "C" fn kmain(boot_arg: u64) -> ! {
    // SAFETY: first and only initialisation of COM1, before any other writer exists.
    unsafe { arch::EARLY.init() };

    banner(boot_arg);
    let c = &arch::EARLY;

    // In a production image this is the no-op provider and folds away entirely; the
    // test image gets the real one. Which is linked is a configuration question, so
    // there is no cfg here.
    let (img_start, img_end) = arch::image_range();
    let reserved = [
        (0, LOW_MEMORY),
        (img_start, img_end.saturating_sub(img_start)),
    ];
    let ok = selftest::run_all::<Cpu>(c, boot_arg, &reserved);
    if selftest::PRESENT {
        c.write_str("\n");
    }

    finish(ok)
}

// How the kernel stops depends on the configuration, so the choice is made once, at
// module level, where `cfg` belongs. Writing it as two `cfg`s inside `kmain` was the
// first thing `kbuild lint` caught — in this file, which is a fair indication that
// the rule needs a checker rather than good intentions.

/// Stop, reporting the outcome through the emulator's result channel.
#[cfg(CONFIG_QEMU_EXIT)]
fn finish(ok: bool) -> ! {
    arch::exit_emulator(ok)
}

/// Stop. A production image has no channel to report through and simply halts.
#[cfg(not(CONFIG_QEMU_EXIT))]
fn finish(_ok: bool) -> ! {
    Cpu::halt()
}

fn banner(boot_arg: u64) {
    let c = &arch::EARLY;
    c.write_str("\nKinTane\n");
    c.write_str("  arch       ");
    c.write_str(Cpu::NAME);
    c.write_str("\n  page size  ");
    write_usize(c, Cpu::PAGE_SIZE);
    c.write_str("\n  paging     ");
    write_usize(c, <Cpu as HasMmu>::LEVELS as usize);
    c.write_str(" levels\n  boot arg   ");
    write_hex(c, boot_arg);

    c.write_str("\n  config     SMP=");
    c.write_str(if kconfig::SMP { "y" } else { "n" });
    c.write_str(" MM_PAGED=");
    c.write_str(if kconfig::MM_PAGED { "y" } else { "n" });
    c.write_str(" DEBUG=");
    c.write_str(if kconfig::DEBUG_BUILD { "y" } else { "n" });
    memory(c, boot_arg);

    c.write_str("\n  pagetable  ");
    let paging_ok = arch::paging_selftest(c);
    c.write_str(if paging_ok { " ok" } else { "" });

    c.write_str("\n  interrupts ");
    // The architecture brings up its own interrupt path; the image only reports the
    // verdict. Nothing here names a machine.
    let irq_ok = arch::interrupt_selftest(c);
    c.write_str(if irq_ok { " ok" } else { "" });

    c.write_str("\n\nreached kmain\n");
}

/// Room for the loader's memory map. QEMU reports a handful of regions; real
/// firmware reports more, and running out is reported rather than silently truncating
/// — a short memory map is one the allocator would act on.
const MAX_REGIONS: usize = 64;

/// Backing store for the frame allocator's bitmaps. 32 KiB covers a 512 MiB usable
/// span at a 4 KiB page (two bits per frame, two arrays). Too small is an error the
/// caller prints, never a truncated pool.
const STORE_BYTES: usize = 32 * 1024;

/// Memory below this is never handed out on a PC: real-mode interrupt vectors, the
/// BIOS data area, and whatever firmware left behind. Reserving it where it is not
/// RAM — aarch64 starts at 0x4000_0000 — costs nothing, because reserving frames
/// outside the pool reserves none.
const LOW_MEMORY: u64 = 1024 * 1024;

/// SAFETY INVARIANT: written only from `memory`, which runs once, on one CPU, before
/// any other task exists. When SMP arrives this becomes a per-CPU or locked
/// allocation and this static goes away.
static STORE: SyncUnsafeCell<[u8; STORE_BYTES]> = SyncUnsafeCell::new([0; STORE_BYTES]);

/// Report what the loader said about memory, then prove the frame allocator works on
/// it by handing out a frame and giving it back.
fn memory(c: &dyn EarlyConsole, boot_arg: u64) {
    c.write_str("\n  memory map ");
    c.write_str(bootinfo::SOURCE);

    let mut regions = [MemoryRegion { start: 0, len: 0, kind: 0, _reserved: 0 }; MAX_REGIONS];
    // SAFETY: `boot_arg` is the value the architecture's boot code passed to `kmain`,
    // which is exactly the contract `memory_regions` states. The structure it names is
    // in loader memory, which is still mapped and not yet reclaimed.
    let n = match unsafe { bootinfo::memory_regions(boot_arg, &mut regions) } {
        Ok(n) => n,
        Err(e) => {
            c.write_str(" (");
            c.write_str(match e {
                bootinfo::Error::NoLoader => "no loader",
                bootinfo::Error::NoMemoryMap => "no map",
                bootinfo::Error::Malformed { .. } => "malformed",
                bootinfo::Error::TooManyRegions { .. } => "too many regions",
            });
            c.write_str(")");
            return;
        }
    };

    let usable: u64 = regions[..n]
        .iter()
        .filter(|r| r.kind == MemoryKind::Usable as u32)
        .map(|r| r.len)
        .sum();
    c.write_str(", ");
    write_usize(c, n);
    c.write_str(" regions, ");
    write_usize(c, (usable / (1024 * 1024)) as usize);
    c.write_str(" MiB usable");

    let needed = match bitmap_bytes::<Cpu>(&regions[..n]) {
        Ok(b) => b,
        Err(_) => {
            c.write_str("\n  frames     unusable map");
            return;
        }
    };
    if needed > STORE_BYTES {
        c.write_str("\n  frames     need ");
        write_usize(c, needed);
        c.write_str(" bytes of bitmap, have ");
        write_usize(c, STORE_BYTES);
        return;
    }

    // SAFETY: the only write to STORE, from the single-threaded boot path before any
    // other execution context exists (see the invariant on the static). `needed` was
    // checked against STORE_BYTES above, so the slice is within the allocation.
    // Built from the raw pointer rather than by indexing through it, which would
    // create a reference to the whole array first.
    let store: &mut [u8] =
        unsafe { core::slice::from_raw_parts_mut(STORE.get().cast::<u8>(), needed) };
    let mut frames = match FrameAllocator::<Cpu>::new(&regions[..n], store) {
        Ok(f) => f,
        Err(_) => {
            c.write_str("\n  frames     allocator rejected the map");
            return;
        }
    };

    // The loader's map describes the machine, not what is already living in it.
    // Nothing in it says "the kernel is here", and the low megabyte on a PC holds the
    // interrupt vector table and BIOS data. Both must be taken out of the pool before
    // a single frame is handed out — without this the allocator's first answer is
    // physical zero, which is exactly what it was before this reservation existed.
    let (img_start, img_end) = arch::image_range();
    let reserved_low = frames.reserve(hal::PhysAddr::new(0), LOW_MEMORY).unwrap_or(0);
    let reserved_img = frames
        .reserve(hal::PhysAddr::new(img_start), img_end.saturating_sub(img_start))
        .unwrap_or(0);

    let stats = frames.stats();
    c.write_str("\n  reserved   ");
    write_usize(c, reserved_low);
    c.write_str(" low + ");
    write_usize(c, reserved_img);
    c.write_str(" image frames");
    c.write_str("\n  frames     ");
    write_usize(c, stats.total);
    c.write_str(" total, ");
    write_usize(c, stats.free);
    c.write_str(" free");

    // Hand out a frame and give it back. Cheap, and it distinguishes "the allocator
    // was constructed" from "the allocator works".
    match frames.alloc_frame() {
        Ok(f) => {
            c.write_str("\n  alloc      ");
            write_hex(c, f.start().raw());
            let after = frames.stats().free;
            match frames.free_frame(f) {
                Ok(()) if frames.stats().free == stats.free && after == stats.free - 1 => {
                    c.write_str(" ok");
                }
                _ => c.write_str(" BOOKKEEPING WRONG"),
            }
        }
        Err(_) => c.write_str("\n  alloc      exhausted"),
    }
}

fn write_usize(c: &dyn EarlyConsole, mut v: usize) {
    if v == 0 {
        c.write_bytes(b"0");
        return;
    }
    let mut buf = [0u8; 20];
    let mut i = buf.len();
    while v > 0 {
        i -= 1;
        buf[i] = b'0' + (v % 10) as u8;
        v /= 10;
    }
    c.write_bytes(&buf[i..]);
}

fn write_hex(c: &dyn EarlyConsole, v: u64) {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut buf = [0u8; 18];
    buf[0] = b'0';
    buf[1] = b'x';
    for i in 0..16 {
        buf[2 + i] = DIGITS[((v >> (60 - i * 4)) & 0xf) as usize];
    }
    c.write_bytes(&buf);
}

/// Panics in the core are fatal. There is no pretending otherwise: print what we can
/// and stop. A symbolized backtrace against the separate symbol bundle is Phase 2.
#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    let c = &arch::EARLY;
    c.write_str("\n\nkernel panic: ");
    if let Some(loc) = info.location() {
        c.write_str(loc.file());
        c.write_str(":");
        write_usize(c, loc.line() as usize);
    } else {
        c.write_str("<no location>");
    }
    c.write_str("\n");
    finish(false)
}

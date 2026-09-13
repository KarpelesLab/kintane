//! The kernel image entry point.
//!
//! Phase 0: bring up the early console, say who we are, and stop. Everything the
//! banner prints comes from either the `hal` traits or the generated configuration,
//! so it is a live check that both paths work rather than a hardcoded string.

#![no_std]
#![no_main]

use arch_x86_64 as arch;
use arch::X86_64 as Cpu;
use hal::{Arch, EarlyConsole, HasMmu};

/// Entry from the architecture's boot code, which has already established long mode,
/// a stack, and an identity mapping.
///
/// `multiboot` is the pointer the loader left in `ebx`. Phase 0 records it without
/// parsing it; turning it into a `BootInfo` is the next piece of work.
///
/// # Safety
/// Called exactly once, by `_start`, with interrupts masked.
#[unsafe(no_mangle)]
pub extern "C" fn kmain(multiboot: u64) -> ! {
    // SAFETY: first and only initialisation of COM1, before any other writer exists.
    unsafe { arch::EARLY.init() };

    banner(multiboot);

    #[cfg(CONFIG_QEMU_EXIT)]
    {
        // The result channel the test protocol uses: a real exit status rather than
        // console output for a harness to scrape. See docs/testing.md.
        arch::qemu_exit(0x10);
    }

    #[cfg(not(CONFIG_QEMU_EXIT))]
    Cpu::halt()
}

fn banner(multiboot: u64) {
    let c = &arch::EARLY;
    c.write_str("\nKinTane\n");
    c.write_str("  arch       ");
    c.write_str(Cpu::NAME);
    c.write_str("\n  page size  ");
    write_usize(c, Cpu::PAGE_SIZE);
    c.write_str("\n  paging     ");
    write_usize(c, <Cpu as HasMmu>::LEVELS as usize);
    c.write_str(" levels\n  multiboot  ");
    write_hex(c, multiboot);

    c.write_str("\n  config     SMP=");
    c.write_str(if kconfig::SMP { "y" } else { "n" });
    c.write_str(" MM_PAGED=");
    c.write_str(if kconfig::MM_PAGED { "y" } else { "n" });
    c.write_str(" DEBUG=");
    c.write_str(if kconfig::DEBUG_BUILD { "y" } else { "n" });
    c.write_str("\n\nreached kmain\n");
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

    #[cfg(CONFIG_QEMU_EXIT)]
    arch::qemu_exit(0x11);

    #[cfg(not(CONFIG_QEMU_EXIT))]
    Cpu::halt()
}

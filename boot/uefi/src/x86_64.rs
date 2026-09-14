//! What the x86_64 handover needs that is not UEFI: a console for after the firmware's
//! is gone, and the jump.

use core::fmt;

/// COM1, written directly.
///
/// After `ExitBootServices` the firmware's console is gone, and nothing is left to report
/// a failure through but hardware. This is the same 16550 the kernel's early console
/// uses, so a message lands in the same log. It does not initialise the UART: the
/// firmware already did, and reprogramming the baud rate under it would garble output
/// rather than improve it.
pub struct Serial;

impl fmt::Write for Serial {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for b in s.bytes() {
            if b == b'\n' {
                put(b'\r');
            }
            put(b);
        }
        Ok(())
    }
}

fn put(b: u8) {
    const COM1: u16 = 0x3F8;
    // Bounded, so a missing UART costs a moment rather than a hang: the transmit-empty
    // bit never sets on a port with nothing behind it.
    for _ in 0..100_000 {
        // SAFETY: reading the line status register of a 16550 has no side effects.
        let lsr: u8 = unsafe {
            let v;
            core::arch::asm!("in al, dx", in("dx") COM1 + 5, out("al") v, options(nostack));
            v
        };
        if lsr & 0x20 != 0 {
            break;
        }
    }
    // SAFETY: writing the transmit holding register sends one byte and nothing else.
    unsafe { core::arch::asm!("out dx, al", in("dx") COM1, in("al") b, options(nostack)) };
}

/// Enter the kernel. Never returns.
///
/// # Safety
/// Boot services must have exited. `entry` must be the kernel's protocol entry point,
/// loaded and identity-mapped, and `boot_info` the physical address of a complete boot
/// information structure, also identity-mapped; both are below 1 GiB, which is all the
/// kernel's bootstrap page tables cover. That is the contract in `boot_protocol::image`.
pub unsafe fn enter(entry: u64, boot_info: u64) -> ! {
    // SAFETY: the caller guarantees the contract above. Interrupts are masked here too,
    // not only by the kernel, because the firmware's IDT is about to point at memory the
    // kernel will reuse, and the stack under this jump is the firmware's.
    unsafe {
        core::arch::asm!(
            "cli",
            "cld",
            "jmp {entry}",
            entry = in(reg) entry,
            in("rdi") boot_info,
            options(noreturn),
        )
    }
}

/// Pages [`identity_4gib`] fills: a PML4, a PDPT and one page directory per gigabyte.
pub const CALL_TABLE_PAGES: usize = 6;

/// Fill `pages`, which lie at physical `base`, with page tables identity-mapping the first
/// 4 GiB in 2 MiB pages, present, writable and executable, and return the root for `CR3`.
///
/// The address space the kernel calls runtime services in: what the firmware ran on, so
/// its runtime code and data and the flash it writes variables to are where it expects
/// them, and the kernel image, below 1 GiB, is mapped where it runs too. `None` if `pages`
/// is shorter than [`CALL_TABLE_PAGES`].
pub fn identity_4gib(pages: &mut [u8], base: u64) -> Option<u64> {
    const PAGE: usize = 4096;
    const PRESENT_WRITABLE: u64 = 0b11;
    const HUGE: u64 = 1 << 7;
    let pages = pages.get_mut(..CALL_TABLE_PAGES * PAGE)?;
    pages.fill(0);
    let (root, rest) = pages.split_at_mut(PAGE);
    let (pdpt, directories) = rest.split_at_mut(PAGE);
    put_entry(root, 0, (base + PAGE as u64) | PRESENT_WRITABLE);
    for (gib, directory) in directories.chunks_exact_mut(PAGE).enumerate() {
        put_entry(pdpt, gib, (base + ((2 + gib) * PAGE) as u64) | PRESENT_WRITABLE);
        for entry in 0..512 {
            let address = ((gib as u64) << 30) | ((entry as u64) << 21);
            put_entry(directory, entry, address | PRESENT_WRITABLE | HUGE);
        }
    }
    Some(base)
}

fn put_entry(table: &mut [u8], index: usize, entry: u64) {
    table[index * 8..index * 8 + 8].copy_from_slice(&entry.to_le_bytes());
}

/// Stop, for good.
pub fn halt() -> ! {
    loop {
        // SAFETY: interrupts are masked first, so hlt parks the CPU until reset.
        unsafe { core::arch::asm!("cli", "hlt", options(nomem, nostack)) };
    }
}

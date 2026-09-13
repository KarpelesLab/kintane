//! x86-64 architecture support.
//!
//! The single implementation of the `hal` traits for this target. One `arch` crate is
//! linked per image, so everything here is statically known and fully monomorphized
//! at every call site in the layers above.

#![no_std]

mod boot;
pub mod serial;

use hal::{Arch, Endian, HasCas, HasCoherentDma, HasFpu, HasMmu, HasSmp};

pub use serial::EARLY;

/// The x86-64 architecture.
pub struct X86_64;

/// The architecture this image is built for, under a name that does not change.
///
/// Upper layers name `Cpu`, never `X86_64`, so that adding an architecture touches
/// no file outside `arch/`, `targets/` and `config/`.
pub type Cpu = X86_64;

impl Arch for X86_64 {
    const NAME: &'static str = "x86_64";
    const PAGE_SIZE: usize = 4096;
    // 4-level paging. 5-level (LA57) is a runtime-detected extension and changes
    // this to 57; it is Phase 1 work, and the constant becomes an associated value
    // on the paging mode rather than on the architecture.
    const PHYS_ADDR_BITS: u8 = 52;
    const ENDIAN: Endian = Endian::Little;
    const UNALIGNED_ACCESS: bool = true;

    type IrqState = bool;

    fn irq_save() -> bool {
        let flags: u64;
        // SAFETY: reading RFLAGS has no side effects; `cli` only masks interrupts,
        // and the caller is responsible for restoring the state we return.
        unsafe {
            core::arch::asm!(
                "pushfq",
                "pop {}",
                "cli",
                out(reg) flags,
                options(nomem, preserves_flags)
            );
        }
        // Bit 9 is IF: whether interrupts were enabled before we masked them.
        flags & (1 << 9) != 0
    }

    unsafe fn irq_restore(was_enabled: bool) {
        if was_enabled {
            // SAFETY: the caller guarantees this pairs with an `irq_save` that
            // observed interrupts enabled, on this CPU.
            unsafe { core::arch::asm!("sti", options(nomem, nostack, preserves_flags)) };
        }
    }

    fn memory_barrier() {
        // SAFETY: `mfence` has no operands and no effect beyond ordering.
        unsafe { core::arch::asm!("mfence", options(nostack, preserves_flags)) };
    }

    fn halt() -> ! {
        loop {
            // SAFETY: `cli; hlt` stops this CPU until an unmaskable event. With
            // interrupts masked it does not return, and the loop covers the case
            // where an NMI wakes us.
            unsafe {
                core::arch::asm!("cli", "hlt", options(nomem, nostack, preserves_flags));
            }
        }
    }
}

impl HasMmu for X86_64 {
    const LEVELS: u8 = 4;
    const HUGE_PAGE_SIZES: &'static [usize] = &[2 * 1024 * 1024, 1024 * 1024 * 1024];
}

impl HasSmp for X86_64 {
    fn cpu_id() -> u32 {
        // Placeholder until the APIC driver exists in Phase 3. Correct for the
        // uniprocessor Phase 0 build and wrong for any other, which is why SMP is
        // off in every preset that exists today.
        0
    }
}

impl HasCas for X86_64 {}
impl HasCoherentDma for X86_64 {}

impl HasFpu for X86_64 {
    // Real save/restore arrives with the context switch in Phase 2.
    type FpuState = ();
}

/// Terminate QEMU through the `isa-debug-exit` device.
///
/// The device reports `(value << 1) | 1` as QEMU's exit status, so the guest can
/// never produce 0 and a stray success is impossible. See `docs/testing.md`.
///
/// Present only when `CONFIG_QEMU_EXIT` is set: it writes to a port that does nothing
/// on real hardware, but it has no business in a production image.
#[cfg(CONFIG_QEMU_EXIT)]
pub fn qemu_exit(code: u8) -> ! {
    // SAFETY: port 0xf4 is the isa-debug-exit device, configured on the QEMU command
    // line by kbuild. On hardware without it, this write is discarded.
    unsafe { serial::outb(0xf4, code) };
    X86_64::halt()
}

/// Terminate the emulator, reporting whether the run passed.
///
/// The status differs by architecture because the channels do: isa-debug-exit
/// reports `(value << 1) | 1`, semihosting reports the value itself. kbuild knows
/// the expected success status per machine, so callers state intent, not a code.
#[cfg(CONFIG_QEMU_EXIT)]
pub fn exit_emulator(ok: bool) -> ! {
    qemu_exit(if ok { 0x10 } else { 0x11 })
}

/// Bring up interrupt handling and prove it works, reporting what happened.
///
/// Exists so that `kmain` can exercise the interrupt path without naming an
/// architecture, and so that adding interrupt support to a port touches only that
/// port. Returns `true` when the path is demonstrably live: a handler ran and
/// control returned.
pub fn interrupt_selftest(c: &dyn hal::EarlyConsole) -> bool {
    c.write_str("not implemented on this port");
    false
}

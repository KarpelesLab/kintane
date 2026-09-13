//! 32-bit x86 (i686) architecture support.
//!
//! The single implementation of the `hal` traits for this target. One `arch` crate is
//! linked per image, so everything here is statically known and fully monomorphized
//! at every call site in the layers above.
//!
//! This port exists to keep one specific assumption out of the kernel: that a
//! physical address fits in a pointer. With PAE enabled — which `boot` does — a
//! physical address here is 36 bits behind a 32-bit `usize`, so `PhysAddr::to_usize`
//! genuinely fails on this target and nowhere else in tier 1. See
//! `docs/targets.md#i686` and `hal/src/addr.rs`.

#![no_std]

mod boot;
pub mod serial;

use hal::{Arch, Endian, HasCas, HasCoherentDma, HasFpu, HasMmu, HasSmp};

pub use serial::EARLY;

/// The 32-bit x86 architecture.
pub struct I686;

/// The architecture this image is built for, under a name that does not change.
///
/// Upper layers name `Cpu`, never `I686`, so that adding an architecture touches
/// no file outside `arch/`, `targets/` and `config/`.
pub type Cpu = I686;

impl Arch for I686 {
    const NAME: &'static str = "i686";
    const PAGE_SIZE: usize = 4096;
    // PAE. Without it a physical address on this target would be 32 bits and would
    // fit in a `usize`, which is exactly the confusion this port is here to prevent;
    // `boot` therefore enables PAE unconditionally and this constant follows from
    // that choice. Larger still on hardware with 40-bit PAE, but 36 is what the
    // architecture guarantees and what QEMU's `pc` machine provides.
    const PHYS_ADDR_BITS: u8 = 36;
    const ENDIAN: Endian = Endian::Little;
    const UNALIGNED_ACCESS: bool = true;

    type IrqState = bool;

    fn irq_save() -> bool {
        let flags: u32;
        // SAFETY: reading EFLAGS has no side effects; `cli` only masks interrupts,
        // and the caller is responsible for restoring the state we return.
        unsafe {
            core::arch::asm!(
                "pushfd",
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
        // SAFETY: `mfence` has no operands and no effect beyond ordering. It is an
        // SSE2 instruction, which the pentium4 baseline in
        // targets/i686-kintane.json guarantees; a genuinely pre-SSE2 i686 would need
        // `lock addl $0, (%esp)` here, and that is a separate CPU baseline rather
        // than a runtime choice.
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

impl HasMmu for I686 {
    // PAE: page directory pointer table, page directory, page table. One level fewer
    // than x86_64, and the top level has four entries rather than 512.
    const LEVELS: u8 = 3;
    // No 1 GiB pages: PDPTE.PS does not exist outside long mode, so 2 MiB leaves in
    // the page directory are the only large page this mode offers.
    const HUGE_PAGE_SIZES: &'static [usize] = &[2 * 1024 * 1024];
}

impl HasSmp for I686 {
    fn cpu_id() -> u32 {
        // Placeholder until the APIC driver exists in Phase 3. Correct for the
        // uniprocessor Phase 0 build and wrong for any other, which is why SMP is
        // off in every preset that exists today.
        0
    }
}

impl HasCas for I686 {}
impl HasCoherentDma for I686 {}

impl HasFpu for I686 {
    // Real save/restore arrives with the context switch in Phase 2. It will be a
    // bigger job here than on x86_64: the i686 ABI returns floats in x87 registers,
    // so the x86_64 trick of building the kernel without an FPU is not available and
    // the state is x87 plus SSE rather than SSE alone. See docs/targets.md#i686.
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
    I686::halt()
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

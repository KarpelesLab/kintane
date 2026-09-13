//! x86-64 architecture support.
//!
//! The single implementation of the `hal` traits for this target. One `arch` crate is
//! linked per image, so everything here is statically known and fully monomorphized
//! at every call site in the layers above.

// IDT entry points. The calling convention differs from every other ABI on the
// machine — the CPU has already pushed a frame the callee must `iret` from, and the
// callee owns every register — so it cannot be expressed as a normal `extern`. There
// is no stable alternative short of hand-written assembly trampolines for 256
// vectors. Listed in toolchain.toml's permitted unstable surface.
#![feature(abi_x86_interrupt)]
#![no_std]

pub mod backtrace;
mod boot;
pub mod clock;
pub mod context;
mod exception;
pub mod fault;
mod gdt;
mod idt;
pub mod interrupt;
pub mod kspace;
pub mod paging;
pub mod pic;
pub mod pit;
pub mod serial;
pub mod tick;

pub use clock::{clock_source, spin_with_timer_interrupts};
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
    interrupt::selftest(c)
}

/// The physical range the kernel image occupies, as `[start, end)`.
///
/// The frame allocator must be told about this before it hands anything out: the
/// loader's memory map describes the machine, not what is already living in it, and
/// nothing in a multiboot map says "the kernel is here".
pub fn image_range() -> (u64, u64) {
    unsafe extern "C" {
        static __kernel_start: u8;
        static __kernel_end: u8;
    }
    // Taking addresses of linker symbols, never reading through them: the symbols
    // mark positions and have no value of their own.
    let start = (&raw const __kernel_start) as usize as u64;
    let end = (&raw const __kernel_end) as usize as u64;
    (start, end)
}

/// Bring up kernel-managed page tables and prove they work, reporting what happened.
///
/// Exists so `kmain` can exercise the paging path without naming an architecture.
/// Returns `true` only when a mapping was demonstrably installed and used.
pub fn paging_selftest(c: &dyn hal::EarlyConsole) -> bool {
    paging::selftest(c)
}

/// The kernel image's sections, as `link.ld` laid them out.
///
/// Every boundary here is page-aligned by the linker script, so no page carries the
/// union of two sections' permissions — which is the only way the split is worth
/// having. The guard page is a hole between `.rodata` and the boot stack that belongs
/// to no output section; leaving it unmapped is what turns a stack overflow from a
/// silent unmapping of the machine into a #PF reported on the double-fault IST.
///
/// `.data` and `.bss` are reported as one range because they are contiguous and want
/// identical permissions; the linker keeps them adjacent so this stays true.
pub fn image_sections() -> hal::ImageSections {
    unsafe extern "C" {
        static __text_start: u8;
        static __text_end: u8;
        static __rodata_start: u8;
        static __rodata_end: u8;
        static __data_start: u8;
        static __data_end: u8;
        static __stack_guard_start: u8;
        static __stack_guard_end: u8;
    }
    // Addresses only, never reads: these symbols mark positions and have no value.
    // `&raw const` rather than a reference for the same reason — there is no object
    // here to borrow, and on the `.bss` and guard-page symbols there is not even a
    // byte to point at.
    let at = |p: *const u8| p as usize as u64;
    hal::ImageSections {
        text: (at(&raw const __text_start), at(&raw const __text_end)),
        rodata: (at(&raw const __rodata_start), at(&raw const __rodata_end)),
        data: (at(&raw const __data_start), at(&raw const __data_end)),
        stack_guard: (at(&raw const __stack_guard_start), at(&raw const __stack_guard_end)),
    }
}

/// Start a second kernel thread, switch to it and back, and prove both directions work.
///
/// Returns `true` only if control reached the new thread *and* came back, with the
/// callee-saved registers the original thread was holding intact.
pub fn context_switch_selftest(c: &dyn hal::EarlyConsole) -> bool {
    context::selftest(c)
}

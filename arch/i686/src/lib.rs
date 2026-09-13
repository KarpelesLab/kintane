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
//!
//! `paging` is where that claim is cashed: it implements the `hal::paging` contract in
//! the 32-bit PAE format, whose entries are 64 bits wide behind 32-bit pointers and
//! whose three levels are indexed by 2, 9 and 9 bits rather than uniformly. Its
//! selftest maps a frame 4 GiB above itself and proves bit 32 survives the trip to the
//! MMU, which is the most direct statement of this port's purpose that exists.
//!
//! Interrupt support lives in `idt`, `exception`, `pic`, `pit` and `interrupt`, and is
//! the same shape as `arch/x86_64`'s without being the same code: the descriptor
//! format and the pushed frame are genuinely different, and the two devices are
//! duplicated because the two `arch` crates are separate units that may not depend on
//! each other. #DF is where the two genuinely diverge: x86-64 gives it an IST stack, and
//! this port, whose gates have no IST field, gives it a task gate (`tss`).
//!
//! `context` implements `hal::context`. Its module comment records a measurement that
//! matters beyond the switch: for this target's LLVM triple the compiler assumes only a
//! 4-byte-aligned stack on entry and realigns wherever it needs more, so the 16-byte
//! alignment the port guarantees is insurance against a target-specification change
//! rather than something today's code generation depends on.

// IDT entry points. The calling convention differs from every other ABI on the
// machine — the CPU has already pushed a frame the callee must `iret` from, and the
// callee owns every register — so it cannot be expressed as a normal `extern`. There
// is no stable alternative short of hand-written assembly trampolines for 256
// vectors. Listed in toolchain.toml's permitted unstable surface, for this target as
// well as x86_64.
#![feature(abi_x86_interrupt)]
#![no_std]

pub mod backtrace;
mod boot;
pub mod clock;
pub mod context;
mod exception;
mod idt;
pub mod interrupt;
pub mod kspace;
pub mod paging;
pub mod pic;
pub mod pit;
pub mod serial;
pub mod tick;
mod tss;

pub use clock::{clock_source, spin_with_timer_interrupts};
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
/// Every boundary below is page-aligned at both ends, because the linker script pads
/// each section to a page before the next one starts. That is what makes the split
/// enforceable rather than merely described: a page can carry only one set of
/// permissions, so a boundary inside a page would force that page to hold the union of
/// both sides' needs and hand the strictest section the weakest of the two.
///
/// The `data` range deliberately spans the guard page: `.data`, `.bss`, the guard hole
/// and `.stack` are one contiguous writable run, and the guard is a page punched back
/// out of it rather than a gap between two ranges. Reporting it any other way would
/// leave the boot stack — which is above the guard — outside the range the caller maps
/// writable, and the first push after the switch would fault.
///
/// # What this buys, per CPU
///
/// The "no-write" half of W^X holds on both i686 presets: `CR0.WP` is set in
/// [`paging::enable_write_protect`], so a clear R/W bit binds supervisor code too, and
/// `.text` and `.rodata` are genuinely unwritable once mapped from these ranges.
///
/// The "no-execute" half depends on the CPU. Bit 63 of a PAE entry is execute-disable,
/// but it is architecturally reserved until `EFER.NXE` is set, and `EFER` need not
/// exist on an i686 at all — so [`paging::enable_nx`] probes CPUID and
/// [`paging::nx_enabled`] reports the answer. On `i686-large` (`-cpu max`) NX is
/// available and `.rodata`, `.data`, `.bss` and the stack are non-executable. On
/// `i686-qemu` (`-cpu qemu32`, the default CI core) it is not: every mapping on that
/// machine is executable no matter what flags are asked for, and this port can enforce
/// only the "no-write" half there. The sections are still split — the split is what
/// makes `.text` read-only — but a W^X claim for this port holds fully on one of the
/// two CI configurations and half on the other.
/// Bytes per kernel thread stack slot: one guard page, then the stack.
///
/// A power of two, which [`hal::StackArray`] requires. `link.ld` reserves whole slots
/// and asserts it agrees with this value.
pub const THREAD_STACK_SLOT: u64 = 32 * 1024;

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
        static __thread_stacks_start: u8;
        static __thread_stacks_end: u8;
    }
    // Taking addresses of linker symbols, never reading through them: the symbols mark
    // positions and have no value of their own.
    let at = |p: *const u8| p as usize as u64;
    hal::ImageSections {
        text: (at(&raw const __text_start), at(&raw const __text_end)),
        rodata: (at(&raw const __rodata_start), at(&raw const __rodata_end)),
        data: (at(&raw const __data_start), at(&raw const __data_end)),
        stack_guard: (at(&raw const __stack_guard_start), at(&raw const __stack_guard_end)),
        thread_stacks: hal::StackArray {
            start: at(&raw const __thread_stacks_start),
            end: at(&raw const __thread_stacks_end),
            slot: THREAD_STACK_SLOT,
            guard: <I686 as hal::Arch>::PAGE_SIZE as u64,
        },
    }
}

/// Start a second kernel thread, switch to it and back, and prove both directions work.
///
/// Returns `true` only if control reached the new thread *and* came back, with the
/// callee-saved registers the original thread was holding intact.
pub fn context_switch_selftest(c: &dyn hal::EarlyConsole) -> bool {
    context::selftest(c)
}

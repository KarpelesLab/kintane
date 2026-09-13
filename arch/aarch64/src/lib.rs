//! AArch64 architecture support.
//!
//! The single implementation of the `hal` traits for this target. One `arch` crate is
//! linked per image, so everything here is statically known and fully monomorphized
//! at every call site in the layers above.

#![no_std]

mod boot;
pub mod exception;
pub mod gic;
pub mod irq;
pub mod paging;
pub mod serial;
pub mod timer;

use hal::{Arch, Endian, HasCas, HasFpu, HasMmu, HasSmp, IrqNumber};

pub use serial::EARLY;

/// The AArch64 architecture.
pub struct Aarch64;

/// The architecture this image is built for, under a name that does not change.
///
/// Upper layers name `Cpu`, never `Aarch64`, so that adding an architecture touches
/// no file outside `arch/`, `targets/` and `config/`.
pub type Cpu = Aarch64;

impl Arch for Aarch64 {
    const NAME: &'static str = "aarch64";
    const PAGE_SIZE: usize = 4096;
    // 4 KiB granule with a 48-bit output address, which is what every
    // implementation supports and what the `virt` machine models. ARMv8.2's 52-bit
    // output is an optional extension; when the paging code learns to detect it this
    // constant moves onto the translation regime rather than onto the architecture,
    // the same way x86_64's LA57 does.
    const PHYS_ADDR_BITS: u8 = 48;
    // AArch64 can be configured big-endian per exception level through SCTLR.EE, but
    // no target we build for does, and the boot code leaves SCTLR at its
    // little-endian reset value.
    const ENDIAN: Endian = Endian::Little;
    // True for normal memory. Device memory is another matter entirely: an unaligned
    // access to a Device-nGnRnE mapping faults regardless of SCTLR.A, which is why
    // the MMIO helpers in `serial` do their own aligned word accesses rather than
    // relying on this being true.
    const UNALIGNED_ACCESS: bool = true;

    /// The four interrupt-mask bits, as DAIF reads them — not a bool, because
    /// restoring has to put all four back exactly as they were.
    type IrqState = u64;

    fn irq_save() -> u64 {
        let daif: u64;
        // SAFETY: reading DAIF has no side effects. `daifset` only sets mask bits,
        // and the caller is responsible for restoring the state we return. The read
        // is ordered before the mask by writing them as one asm block.
        unsafe {
            core::arch::asm!(
                "mrs {}, daif",
                "msr daifset, #0x2",
                out(reg) daif,
                options(nomem, nostack, preserves_flags)
            );
        }
        daif
    }

    unsafe fn irq_restore(state: u64) {
        // SAFETY: the caller guarantees `state` came from a matching `irq_save` on
        // this CPU, so writing it back to DAIF restores exactly the masks that were
        // in effect. Only the DAIF bits of the register are writable; the rest of
        // the value read back is RES0 and writing it is defined.
        unsafe {
            core::arch::asm!(
                "msr daif, {}",
                in(reg) state,
                options(nomem, nostack, preserves_flags)
            );
        }
    }

    fn memory_barrier() {
        // SAFETY: `dsb sy` has no operands and no effect beyond ordering — the
        // strongest barrier the architecture offers, completing every load, store
        // and cache maintenance operation before anything after it is observed.
        unsafe { core::arch::asm!("dsb sy", options(nostack, preserves_flags)) };
    }

    fn halt() -> ! {
        loop {
            // SAFETY: masking DAIF and executing `wfi` stops this CPU until an
            // event it cannot be woken by, since everything that could wake it is
            // masked. `wfi` is architecturally permitted to return spuriously, which
            // is exactly what the loop is for.
            unsafe {
                core::arch::asm!(
                    "msr daifset, #0xf",
                    "wfi",
                    options(nomem, nostack, preserves_flags)
                );
            }
        }
    }
}

impl HasMmu for Aarch64 {
    // 4 KiB granule, 48-bit virtual address: four tables of 9 index bits each.
    const LEVELS: u8 = 4;
    // Beware the numbering: in `hal`'s convention, where level 0 is the leaf, a
    // level-1 block is 2 MiB and a level-2 block is 1 GiB. Arm's own numbering calls
    // those L2 and L1. There is no larger block at this granule — the 512 GiB block
    // exists only with 64 KiB pages, which this port does not use. See
    // `paging`'s module comment for the full translation between the two.
    const HUGE_PAGE_SIZES: &'static [usize] = &[2 * 1024 * 1024, 1024 * 1024 * 1024];
}

impl HasSmp for Aarch64 {
    fn cpu_id() -> u32 {
        let mpidr: u64;
        // SAFETY: MPIDR_EL1 is readable at EL1 and reading it has no side effects.
        unsafe {
            core::arch::asm!(
                "mrs {}, mpidr_el1",
                out(reg) mpidr,
                options(nomem, nostack, preserves_flags)
            );
        }
        // Aff0 is the CPU index on every machine this port targets, including
        // `virt` below sixteen CPUs. It is *not* a dense index in general — real
        // hardware numbers clusters in Aff1 and Aff2 — so this becomes a lookup
        // through a per-CPU table built at bring-up, in Phase 3. Until then the only
        // supported build is uniprocessor and the answer is always zero.
        (mpidr & 0xff) as u32
    }
}

impl HasCas for Aarch64 {}

// Deliberately no `HasCoherentDma`. ARM systems do not guarantee that DMA masters
// see the CPU's caches, and config/arch.kcfg says so by not selecting
// ARCH_HAS_COHERENT_DMA for this architecture. QEMU's memory is always coherent, so
// claiming the capability here would compile, boot, pass, and then corrupt data on
// the first real board — see `docs/testing.md#what-qemu-will-not-catch`.

impl HasFpu for Aarch64 {
    // Real save/restore arrives with the context switch in Phase 2. It is the 32
    // Q registers plus FPCR and FPSR; the boot code has already cleared
    // CPACR_EL1.FPEN so that reaching them does not trap.
    type FpuState = ();
}

/// Terminate QEMU through an ARM semihosting `SYS_EXIT` call.
///
/// This is the result channel for aarch64. There is no `isa-debug-exit` device
/// outside x86, and inventing one would mean adding a device to the machine model;
/// semihosting is already there, costs nothing, and reports an arbitrary status.
///
/// `code` becomes QEMU's own exit status verbatim, which is the one asymmetry with
/// x86: there, `isa-debug-exit` reports `(value << 1) | 1` and the guest therefore
/// cannot produce 0, so "QEMU exited for its own reasons" can never be mistaken for
/// a pass. Here it can — a guest that never calls this at all, and a QEMU that exits
/// cleanly for some other reason, both yield 0. The harness compensates by treating
/// a timeout as a failure and by requiring the banner, not by decorating the status.
///
/// Unlike `qemu_exit` on x86 this is not behind a config symbol: `QEMU_EXIT` depends
/// on `ARCH_X86_64 || ARCH_I686` because it names an ISA device. The instruction
/// below is `HLT #0xF000`, which traps to the debugger or hypervisor when one is
/// attached and is undefined otherwise — so it is not a silent no-op on real
/// hardware the way an ISA port write is, and a production image must not call it.
#[cfg(CONFIG_QEMU_EXIT)]
pub fn semihosting_exit(code: u32) -> ! {
    /// Operation number for `SYS_EXIT`.
    const SYS_EXIT: u64 = 0x18;
    /// `ADP_Stopped_ApplicationExit`: a normal exit with a status, as opposed to
    /// one of the reasons that mean the application stopped on a fault.
    const ADP_STOPPED_APPLICATION_EXIT: u64 = 0x20026;

    // The 64-bit variant of SYS_EXIT takes a pointer to a two-word parameter block
    // rather than passing the reason in x1 directly, which is what lets it carry an
    // exit status at all.
    let block: [u64; 2] = [ADP_STOPPED_APPLICATION_EXIT, code as u64];

    // SAFETY: `HLT #0xF000` is the A64 semihosting call. Its only effect is the
    // semihosting operation selected by x0, which here is SYS_EXIT — a call that
    // does not return. x1 points at a live local that outlives the instruction, and
    // the block is read, not written, by the host. The asm carries no `nomem`, so
    // the stores initialising `block` are ordered before it.
    unsafe {
        core::arch::asm!(
            "hlt #0xf000",
            in("x0") SYS_EXIT,
            in("x1") block.as_ptr(),
            options(nostack)
        );
    }

    // Only reached when semihosting is disabled, in which case the HLT was either
    // ignored or taken as an exception; stopping is the honest response either way.
    Aarch64::halt()
}

/// Terminate the emulator, reporting whether the run passed.
///
/// Semihosting reports the status verbatim, so success is 0 here where it is 33 on
/// x86. Callers state intent and never a number.
#[cfg(CONFIG_QEMU_EXIT)]
pub fn exit_emulator(ok: bool) -> ! {
    semihosting_exit(if ok { 0 } else { 1 })
}

/// Bring up interrupt handling and prove it works, reporting what happened.
///
/// Exists so that `kmain` can exercise the interrupt path without naming an
/// architecture, and so that adding interrupt support to a port touches only that
/// port. Returns `true` when the path is demonstrably live: a handler ran and
/// control returned.
pub fn interrupt_selftest(c: &dyn hal::EarlyConsole) -> bool {
    // SAFETY: `kmain` is documented as calling this once with interrupts masked, and
    // nothing before it has enabled an interrupt source, so this is the first and only
    // installation and nothing can be delivered against a half-built table.
    unsafe { exception::install_vectors() };

    // The one genuinely dynamic decision in the image: which interrupt controller this
    // machine has. Everything after this point talks to it through `dyn IrqChip`.
    //
    // SAFETY: on this machine 0x08000000 is the GIC distributor, and PIDR2 is a
    // read-only identification register — the probe cannot disturb a device that turns
    // out to be something else, and on `virt` there is nothing else it could be.
    let Some(chip) = (unsafe { gic::detect(gic::GICD_BASE) }) else {
        c.write_str("no GIC at 0x08000000");
        return false;
    };
    c.write_str(chip.name());

    // SAFETY: first and only initialisation of this controller, with interrupts still
    // masked, which is exactly the contract `IrqChip::init` states.
    unsafe { chip.init() };
    // SAFETY: called once, before any source is enabled, on an initialised controller.
    unsafe { irq::set_chip(chip) };

    let freq = timer::frequency();
    if freq == 0 {
        c.write_str(", no counter frequency");
        return false;
    }

    chip.enable(IrqNumber(timer::PPI));
    // Ten milliseconds: long enough that arming and unmasking cannot race the
    // deadline, short enough that a boot nobody is watching does not stall on it.
    timer::arm((freq / 100) as u32);

    // SAFETY: the vector table is installed, the controller is initialised, the only
    // enabled source has a handler, and the masks are put back before returning — so
    // the window in which an interrupt can arrive is exactly the loop below.
    unsafe {
        core::arch::asm!("msr daifclr, #2", options(nomem, nostack, preserves_flags));
    }

    // Wait, but not forever. A second of counter ticks is two orders of magnitude more
    // than the timer needs; reaching the deadline means the interrupt never came, which
    // is a result to report rather than a reason to hang.
    let deadline = timer::counter().wrapping_add(freq);
    while irq::timer_ticks() == 0 && timer::counter() < deadline {
        // SAFETY: `wfi` is a hint. With IRQs unmasked the timer wakes it, and the
        // architecture permits it to return for no reason at all, which the loop
        // tolerates.
        unsafe { core::arch::asm!("wfi", options(nomem, nostack, preserves_flags)) };
    }

    // SAFETY: restores the mask this function cleared, leaving DAIF as `kmain` had it.
    unsafe {
        core::arch::asm!("msr daifset, #2", options(nomem, nostack, preserves_flags));
    }
    timer::stop();
    chip.disable(IrqNumber(timer::PPI));

    if irq::timer_ticks() == 0 {
        c.write_str(", timer IRQ never fired");
        return false;
    }
    // The counter is incremented by the handler and read here, on the interrupted
    // side, so a non-zero value is proof of both halves: the handler ran, and control
    // came back through `eret`.
    c.write_str(", timer IRQ taken");
    true
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
///
/// On this port the MMU is already on by the time `kmain` runs — `_start` calls
/// [`paging::aarch64_mmu_init`] before it — so what is left to prove here is that the
/// translation is real rather than merely configured. See [`paging::selftest`].
pub fn paging_selftest(c: &dyn hal::EarlyConsole) -> bool {
    paging::selftest(c)
}

/// The kernel image's sections.
///
/// Currently unsplit: this port maps its whole image one way. Splitting it needs
/// section symbols in `link.ld`, and until then saying so through
/// [`hal::ImageSections::unsplit`] is more honest than inventing boundaries.
pub fn image_sections() -> hal::ImageSections {
    let (start, end) = image_range();
    hal::ImageSections::unsplit(start, end)
}

//! The memory protection unit: what it enforces here, and the probes that prove it.
//!
//! A PMSAv7 MPU has a handful of regions, each a power-of-two size on a boundary of its
//! own size, optionally cut into eight subregions that can be disabled one by one. When
//! regions overlap, the highest-numbered one decides. With `PRIVDEFENA` set, privileged
//! code keeps the default memory map everywhere no region matches, which is how the
//! System Control Space and the peripherals stay reachable without regions of their own.
//!
//! The Cortex-M3 QEMU models has eight. This port spends them as:
//!
//! | region | covers | allows |
//! |---|---|---|
//! | 0 | code memory, 4 MiB at 0 | read and execute: `.text`, `.rodata` and `.data`'s load copy cannot be written |
//! | 1 | SSRAM2/3, 4 MiB | read and write, never execute |
//! | 2 | PSRAM, 16 MiB | read and write, never execute |
//! | 3 | the page below the boot stack | nothing |
//! | 4–7 | two thread-stack slots each | nothing in the two 8 KiB guard subregions; the rest falls through to region 1 |
//!
//! That is W^X over the whole image, and a guard under every stack, on a core with no
//! page tables. Regions 0–2 come from the board's memory, which this port knows as the
//! same constants `config/boards/mps2-an385.kcfg` describes.

use hal::EarlyConsole;

use crate::counter::write_hex;
use crate::scs;

/// `MPU_CTRL.ENABLE` and `.PRIVDEFENA`. `HFNMIENA` stays clear: a HardFault handler runs
/// with the MPU off, so a fault report cannot itself be refused.
const CTRL_ON: u32 = (1 << 0) | (1 << 2);

/// `MPU_RBAR.VALID`: the region number in the low bits selects the region.
const RBAR_VALID: u32 = 1 << 4;

/// `MPU_RASR` fields.
const RASR_ENABLE: u32 = 1;
const RASR_XN: u32 = 1 << 28;
/// `AP` = privileged read-only, unprivileged no access.
const AP_PRIV_RO: u32 = 0b101 << 24;
/// `AP` = privileged read-write, unprivileged no access.
const AP_PRIV_RW: u32 = 0b001 << 24;
/// `AP` = no access at all.
const AP_NONE: u32 = 0;

/// The code memory, SSRAM2/3 and PSRAM of the AN385.
const FLASH: (u32, u32) = (0x0000_0000, 4 << 20);
const SRAM: (u32, u32) = (0x2000_0000, 4 << 20);
const PSRAM: (u32, u32) = (0x2100_0000, 16 << 20);

/// The guard subregions of a two-slot region: the bottom eighth of each 32 KiB slot.
/// `SRD` disables subregions whose bit is set, so every bit but 0 and 4.
const SRD_TWO_GUARDS: u32 = 0b1110_1110 << 8;

/// Why the MPU could not be set up.
pub enum Error {
    /// `MPU_TYPE` reports fewer data regions than the table above needs.
    TooFewRegions(u32),
    /// A region is not a power of two, or not on a boundary of its size.
    BadRegion(u32),
}

/// `RASR.SIZE` for a region of `len` bytes: `log2(len) - 1`. `None` unless `len` is a
/// power of two of at least 32 bytes.
fn size_field(len: u32) -> Option<u32> {
    (len.is_power_of_two() && len >= 32).then(|| (len.trailing_zeros() - 1) << 1)
}

/// Program region `n`.
///
/// # Safety
/// The MPU must be disabled, or the region must not cover code the caller is running.
unsafe fn set(n: u32, base: u32, len: u32, attrs: u32) -> Result<(), Error> {
    let size = size_field(len).ok_or(Error::BadRegion(n))?;
    if base & (len - 1) != 0 {
        return Err(Error::BadRegion(n));
    }
    // SAFETY: the caller's contract; RBAR with VALID selects the region and sets its base
    // in one write, then RASR sets its size and permissions.
    unsafe {
        scs::write(scs::MPU_RBAR, base | RBAR_VALID | n);
        scs::write(scs::MPU_RASR, attrs | size | RASR_ENABLE);
    }
    Ok(())
}

/// How many data regions the MPU has.
pub fn regions() -> u32 {
    // SAFETY: MPU_TYPE is read-only and present on every PMSAv7 core; DREGION is 15:8.
    (unsafe { scs::read(scs::MPU_TYPE) } >> 8) & 0xff
}

/// Program every region in the table and turn the MPU on.
///
/// # Safety
/// Interrupts must be masked. Nothing may afterwards expect to write the code memory or
/// execute RAM.
pub unsafe fn enable() -> Result<(), Error> {
    let have = regions();
    if have < 8 {
        return Err(Error::TooFewRegions(have));
    }
    let s = crate::image_sections();
    let stacks = s.thread_stacks;
    // SAFETY: masked; the MPU is disabled across the programming, so no half-built table
    // is ever enforced.
    unsafe {
        scs::write(scs::MPU_CTRL, 0);
        set(0, FLASH.0, FLASH.1, AP_PRIV_RO)?;
        set(1, SRAM.0, SRAM.1, AP_PRIV_RW | RASR_XN)?;
        set(2, PSRAM.0, PSRAM.1, AP_PRIV_RW | RASR_XN)?;
        set(
            3,
            s.stack_guard.0 as u32,
            (s.stack_guard.1 - s.stack_guard.0) as u32,
            AP_NONE | RASR_XN,
        )?;
        let pair = 2 * stacks.slot as u32;
        for (i, region) in (4..8).enumerate() {
            let base = stacks.start as u32 + i as u32 * pair;
            set(region, base, pair, AP_NONE | RASR_XN | SRD_TWO_GUARDS)?;
        }
        scs::write(scs::MPU_CTRL, CTRL_ON);
    }
    Ok(())
}

core::arch::global_asm!(
    r#"
.syntax unified
.thumb

.section .text.mpu_probe, "ax"

// armv7m_probe_load(addr) -> u32: one load, at `armv7m_probe_load_insn`.
.globl armv7m_probe_load
.type armv7m_probe_load, %function
.thumb_func
armv7m_probe_load:
.globl armv7m_probe_load_insn
armv7m_probe_load_insn:
    ldr     r0, [r0]
    bx      lr

// armv7m_probe_store(addr, value): one store, at `armv7m_probe_store_insn`.
.globl armv7m_probe_store
.type armv7m_probe_store, %function
.thumb_func
armv7m_probe_store:
.globl armv7m_probe_store_insn
armv7m_probe_store_insn:
    str     r1, [r0]
    bx      lr
"#
);

unsafe extern "C" {
    fn armv7m_probe_load(addr: usize) -> u32;
    fn armv7m_probe_store(addr: usize, value: u32);
    static armv7m_probe_load_insn: u8;
    static armv7m_probe_store_insn: u8;
}

/// The address a probe expects to fault on, while one is running; zero otherwise.
static PROBE_ADDR: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
/// Whether the running probe faulted where it expected.
static PROBE_FAULTED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Called by the fault handler for a memory-management fault. If it is the running probe's
/// instruction faulting on the probe's address, record it and return true: the handler
/// skips the instruction. Otherwise false, and the fault is reported.
pub(crate) fn probe_fault(pc: u32, fault_addr: Option<u32>) -> bool {
    use core::sync::atomic::Ordering;
    let want = PROBE_ADDR.load(Ordering::SeqCst);
    if want == 0 {
        return false;
    }
    let load = (&raw const armv7m_probe_load_insn) as usize as u32 & !1;
    let store = (&raw const armv7m_probe_store_insn) as usize as u32 & !1;
    if (pc != load && pc != store) || fault_addr != Some(want as u32) {
        return false;
    }
    PROBE_FAULTED.store(true, Ordering::SeqCst);
    true
}

/// Whether reading `addr` faults.
fn load_faults(addr: usize) -> bool {
    use core::sync::atomic::Ordering;
    PROBE_FAULTED.store(false, Ordering::SeqCst);
    PROBE_ADDR.store(addr, Ordering::SeqCst);
    // SAFETY: a load the MPU is expected to refuse; if it does, the fault handler skips it
    // (see `probe_fault`), and if it does not, it reads memory that exists.
    let _ = unsafe { armv7m_probe_load(addr) };
    PROBE_ADDR.store(0, Ordering::SeqCst);
    PROBE_FAULTED.load(Ordering::SeqCst)
}

/// Whether writing `addr` faults. The value written is what was there, so a store the MPU
/// fails to refuse changes nothing.
fn store_faults(addr: usize) -> bool {
    use core::sync::atomic::Ordering;
    // SAFETY: reading the image's own read-only data.
    let value = unsafe { core::ptr::read_volatile(addr as *const u32) };
    PROBE_FAULTED.store(false, Ordering::SeqCst);
    PROBE_ADDR.store(addr, Ordering::SeqCst);
    // SAFETY: as for `load_faults`; the value is the one already there.
    unsafe { armv7m_probe_store(addr, value) };
    PROBE_ADDR.store(0, Ordering::SeqCst);
    PROBE_FAULTED.load(Ordering::SeqCst)
}

/// Turn the MPU on and prove it enforces: a read of the boot stack's guard and of a
/// thread stack's guard must fault, a write to `.rodata` must fault, and a read of the
/// same `.rodata` must not.
pub fn selftest(c: &dyn EarlyConsole) -> bool {
    let irq = <crate::Armv7m as hal::Arch>::irq_save();
    // SAFETY: masked; the table forbids only what the kernel never does.
    let enabled = unsafe { enable() };
    // SAFETY: pairs with the `irq_save` above.
    unsafe { <crate::Armv7m as hal::Arch>::irq_restore(irq) };
    match enabled {
        Ok(()) => {}
        Err(Error::TooFewRegions(n)) => {
            c.write_str("mpu has ");
            write_hex(c, u64::from(n));
            c.write_str(" regions, needs 8");
            return false;
        }
        Err(Error::BadRegion(n)) => {
            c.write_str("mpu region ");
            write_hex(c, u64::from(n));
            c.write_str(" is not a power of two on its own boundary");
            return false;
        }
    }
    c.write_str("mpu 8 regions");

    let s = crate::image_sections();
    let boot_guard = s.stack_guard.0 as usize;
    let thread_guard = s
        .thread_stacks
        .guard_range(1)
        .map_or(0, |(lo, _)| lo as usize + 16);
    let rodata = s.rodata.0 as usize;
    let mut ok = true;
    for (what, faulted, want) in [
        ("boot stack guard read", load_faults(boot_guard), true),
        ("thread stack guard read", load_faults(thread_guard), true),
        (".rodata write", store_faults(rodata), true),
        (".rodata read", load_faults(rodata), false),
    ] {
        if faulted != want {
            c.write_str(", ");
            c.write_str(what);
            c.write_str(if want { " ALLOWED" } else { " FAULTED" });
            ok = false;
        }
    }
    if ok {
        c.write_str(": guard reads and .rodata writes fault");
    }
    ok
}

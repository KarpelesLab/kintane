//! What this port contributes to kernel memory layout — which, with no MMU, is almost
//! nothing — and to stack protection, which Physical Memory Protection makes possible.
//!
//! There is no kernel address space to build. Physical addresses are the only addresses,
//! every device is reachable the moment the kernel starts, and nothing can be unmapped.
//! Consequences worth stating plainly:
//!
//! * **[`device_windows`] is empty.** It exists so `kernel/platform/none` has one signature on
//!   every port; nothing maps these windows here, because nothing maps anything.
//! * **Stack guards are PMP regions, not unmapped pages.** [`arm_guards`] locks a no-access
//!   Physical Memory Protection region over the page below the boot stack and over the bottom page
//!   of every thread-stack slot. An entry with its lock bit set binds machine mode too — the mode
//!   the kernel runs in — so a load or store there traps. Nothing else is covered, and an access no
//!   entry matches is allowed in machine mode, so the rest of memory is unaffected.
//! * **A guard is proven by a touch, not by an overflow.** A machine-mode trap runs on the stack it
//!   interrupts. A real overflow into a guard would take its trap on the overflowed stack, and
//!   `__trap_entry`'s first store would fault again; there is no separate trap stack here to escape
//!   to, as x86's IST or aarch64's reserved overflow stack provide. So the stack-guard test modes
//!   read a guard from a healthy stack, which is what i686 did before it had a double-fault task
//!   gate. That shows the region faults and is reported as the stack it guards. It does not show a
//!   real overflow is reported, which needs an emergency stack switched in through `mscratch`.

use core::sync::atomic::{AtomicU8, AtomicUsize, Ordering};

use hal::paging::DeviceWindow;
use hal::{Arch, EarlyConsole, KernAddr};

/// Device memory to map once the kernel's own tables are live: none, since there are none.
pub fn device_windows() -> &'static [DeviceWindow] {
    &[]
}

/// Slots handed out so far. A stack is never given back.
///
/// Read and written with interrupts masked rather than with a read-modify-write, because
/// the rv32i variant of this port has no atomic instruction to do it in one. Masking is
/// the whole of exclusion here either way: the port asserts [`hal::UniProcessor`], so
/// nothing else can be running kernel code while this hart's interrupts are off.
static CLAIMED: AtomicUsize = AtomicUsize::new(0);

/// A kernel thread stack from the image's thread-stack array.
///
/// Returns `(slot, top, size)`, or `None` once every slot is taken. The page below the
/// stack is a PMP guard once [`arm_guards`] has run; `_owner` names the thread on the
/// ports whose guard reports print it, which a slot index serves here.
pub fn claim_thread_stack(_owner: &'static str) -> Option<(usize, KernAddr, usize)> {
    let t = crate::image_sections().thread_stacks;
    let irq = crate::Riscv32::irq_save();
    let taken = CLAIMED.load(Ordering::Relaxed);
    let slot = (taken < t.count()).then(|| {
        CLAIMED.store(taken + 1, Ordering::Relaxed);
        taken
    });
    // SAFETY: pairs with the `irq_save` above; nothing between them can block.
    unsafe { crate::Riscv32::irq_restore(irq) };
    let slot = slot?;
    let (bottom, top) = t.stack_range(slot)?;
    Some((slot, KernAddr::new(top as usize), (top - bottom) as usize))
}

// ---- Physical Memory Protection --------------------------------------------------------

/// `pmpcfg` bits: the lock bit, and the address-matching mode for a power-of-two region.
const PMP_L: u8 = 0x80;
const PMP_NAPOT: u8 = 0x18;
/// A locked power-of-two region that grants nothing: no read, write or execute.
const GUARD_CFG: u8 = PMP_L | PMP_NAPOT;

/// The PMP entries RV32 can have (`pmpaddr0`–`pmpaddr15`). An entry the hart does not
/// implement reads back zero, which is how [`arm_guards`] tells.
const PMP_ENTRIES: usize = 16;

/// Write `pmpaddr{index}`.
///
/// # Safety
/// Machine mode. Changes which memory faults, once its entry's configuration is set.
unsafe fn write_pmpaddr(index: usize, value: usize) {
    // SAFETY: the caller's contract. Each CSR write touches no memory and cannot trap in
    // machine mode, so `nomem` holds.
    unsafe {
        match index {
            0 => core::arch::asm!("csrw pmpaddr0, {}", in(reg) value, options(nomem, nostack)),
            1 => core::arch::asm!("csrw pmpaddr1, {}", in(reg) value, options(nomem, nostack)),
            2 => core::arch::asm!("csrw pmpaddr2, {}", in(reg) value, options(nomem, nostack)),
            3 => core::arch::asm!("csrw pmpaddr3, {}", in(reg) value, options(nomem, nostack)),
            4 => core::arch::asm!("csrw pmpaddr4, {}", in(reg) value, options(nomem, nostack)),
            5 => core::arch::asm!("csrw pmpaddr5, {}", in(reg) value, options(nomem, nostack)),
            6 => core::arch::asm!("csrw pmpaddr6, {}", in(reg) value, options(nomem, nostack)),
            7 => core::arch::asm!("csrw pmpaddr7, {}", in(reg) value, options(nomem, nostack)),
            8 => core::arch::asm!("csrw pmpaddr8, {}", in(reg) value, options(nomem, nostack)),
            9 => core::arch::asm!("csrw pmpaddr9, {}", in(reg) value, options(nomem, nostack)),
            10 => core::arch::asm!("csrw pmpaddr10, {}", in(reg) value, options(nomem, nostack)),
            11 => core::arch::asm!("csrw pmpaddr11, {}", in(reg) value, options(nomem, nostack)),
            12 => core::arch::asm!("csrw pmpaddr12, {}", in(reg) value, options(nomem, nostack)),
            13 => core::arch::asm!("csrw pmpaddr13, {}", in(reg) value, options(nomem, nostack)),
            14 => core::arch::asm!("csrw pmpaddr14, {}", in(reg) value, options(nomem, nostack)),
            15 => core::arch::asm!("csrw pmpaddr15, {}", in(reg) value, options(nomem, nostack)),
            _ => {}
        }
    }
}

/// Read `pmpaddr{index}`. Zero for an entry the hart does not implement.
fn read_pmpaddr(index: usize) -> usize {
    let v: usize;
    // SAFETY: a CSR read in machine mode has no side effect and touches no memory.
    unsafe {
        match index {
            0 => core::arch::asm!("csrr {}, pmpaddr0", out(reg) v, options(nomem, nostack)),
            1 => core::arch::asm!("csrr {}, pmpaddr1", out(reg) v, options(nomem, nostack)),
            2 => core::arch::asm!("csrr {}, pmpaddr2", out(reg) v, options(nomem, nostack)),
            3 => core::arch::asm!("csrr {}, pmpaddr3", out(reg) v, options(nomem, nostack)),
            4 => core::arch::asm!("csrr {}, pmpaddr4", out(reg) v, options(nomem, nostack)),
            5 => core::arch::asm!("csrr {}, pmpaddr5", out(reg) v, options(nomem, nostack)),
            6 => core::arch::asm!("csrr {}, pmpaddr6", out(reg) v, options(nomem, nostack)),
            7 => core::arch::asm!("csrr {}, pmpaddr7", out(reg) v, options(nomem, nostack)),
            8 => core::arch::asm!("csrr {}, pmpaddr8", out(reg) v, options(nomem, nostack)),
            9 => core::arch::asm!("csrr {}, pmpaddr9", out(reg) v, options(nomem, nostack)),
            10 => core::arch::asm!("csrr {}, pmpaddr10", out(reg) v, options(nomem, nostack)),
            11 => core::arch::asm!("csrr {}, pmpaddr11", out(reg) v, options(nomem, nostack)),
            12 => core::arch::asm!("csrr {}, pmpaddr12", out(reg) v, options(nomem, nostack)),
            13 => core::arch::asm!("csrr {}, pmpaddr13", out(reg) v, options(nomem, nostack)),
            14 => core::arch::asm!("csrr {}, pmpaddr14", out(reg) v, options(nomem, nostack)),
            15 => core::arch::asm!("csrr {}, pmpaddr15", out(reg) v, options(nomem, nostack)),
            _ => v = 0,
        }
    }
    v
}

/// Write `pmpcfg{index}`, which on RV32 holds the configuration bytes of four entries.
///
/// # Safety
/// As [`write_pmpaddr`]. A byte with [`PMP_L`] set locks that entry until reset.
unsafe fn write_pmpcfg(index: usize, value: u32) {
    // SAFETY: the caller's contract; as `write_pmpaddr`.
    unsafe {
        match index {
            0 => core::arch::asm!("csrw pmpcfg0, {}", in(reg) value, options(nomem, nostack)),
            1 => core::arch::asm!("csrw pmpcfg1, {}", in(reg) value, options(nomem, nostack)),
            2 => core::arch::asm!("csrw pmpcfg2, {}", in(reg) value, options(nomem, nostack)),
            3 => core::arch::asm!("csrw pmpcfg3, {}", in(reg) value, options(nomem, nostack)),
            _ => {}
        }
    }
}

/// Read `pmpcfg{index}`.
fn read_pmpcfg(index: usize) -> u32 {
    let v: u32;
    // SAFETY: as `read_pmpaddr`.
    unsafe {
        match index {
            0 => core::arch::asm!("csrr {}, pmpcfg0", out(reg) v, options(nomem, nostack)),
            1 => core::arch::asm!("csrr {}, pmpcfg1", out(reg) v, options(nomem, nostack)),
            2 => core::arch::asm!("csrr {}, pmpcfg2", out(reg) v, options(nomem, nostack)),
            3 => core::arch::asm!("csrr {}, pmpcfg3", out(reg) v, options(nomem, nostack)),
            _ => v = 0,
        }
    }
    v
}

/// The `pmpaddr` value for the region `[base, base + size)`, or `None` if it cannot be one
/// power-of-two region: `size` must be a power of two of at least 8 bytes, and `base`
/// aligned to it.
///
/// `pmpaddr` holds an address shifted right by two, and a power-of-two region of
/// `2^(n+3)` bytes sets its low `n` bits. Written without `is_power_of_two`, which counts
/// ones through a library call rv32i does not provide.
fn napot(base: u64, size: u64) -> Option<usize> {
    if size < 8 || size & (size - 1) != 0 || base & (size - 1) != 0 {
        return None;
    }
    usize::try_from((base | ((size >> 1) - 1)) >> 2).ok()
}

/// Guard `index`: the page below the boot stack, then the bottom page of each thread-stack
/// slot in order. `None` past the last.
fn guard(index: usize) -> Option<(u64, u64)> {
    let s = crate::image_sections();
    if index == 0 {
        let (lo, hi) = s.stack_guard;
        return (lo < hi).then_some((lo, hi));
    }
    if index - 1 >= s.thread_stacks.count() {
        return None;
    }
    s.thread_stacks.guard_range(index - 1)
}

/// Guards [`arm_guards`] locked and read back. Zero before it has run.
static ARMED: AtomicUsize = AtomicUsize::new(0);

/// Lock a no-access PMP region over every stack guard, and prove each one took.
///
/// Every address is written before any configuration, because locking an entry's
/// configuration also freezes its address. Each entry is then read back: an entry the
/// hart does not implement reads zero, and a region that is not one power-of-two span is
/// refused rather than written approximately. Returns whether every guard is in place.
pub fn arm_guards(c: &dyn EarlyConsole) -> bool {
    let wanted = 1 + crate::image_sections().thread_stacks.count();
    if wanted > PMP_ENTRIES {
        c.write_str("more stack guards than PMP entries");
        return false;
    }
    let mut addrs = [0usize; PMP_ENTRIES];
    for (i, slot) in addrs.iter_mut().enumerate().take(wanted) {
        let Some((lo, hi)) = guard(i) else {
            c.write_str("a stack guard has no range");
            return false;
        };
        let Some(a) = napot(lo, hi - lo) else {
            c.write_str("a stack guard is not one power-of-two region");
            return false;
        };
        *slot = a;
    }

    // SAFETY: machine mode, the only mode this port runs in. Indices are below
    // PMP_ENTRIES. The regions are guard pages nothing is meant to touch, so locking them
    // away changes nothing that runs correctly.
    unsafe {
        for (i, &a) in addrs.iter().enumerate().take(wanted) {
            write_pmpaddr(i, a);
        }
        // Configuration bytes last, four to a register: entry `4n + k` is byte `k` of
        // `pmpcfg{n}`. Shifts rather than multiplication, which rv32i has no instruction for.
        for n in 0..((wanted + 3) >> 2) {
            let mut word = 0u32;
            for k in 0..4 {
                if (n << 2) + k < wanted {
                    word |= u32::from(GUARD_CFG) << (k << 3);
                }
            }
            write_pmpcfg(n, word);
        }
    }

    let mut took = 0usize;
    for (i, &a) in addrs.iter().enumerate().take(wanted) {
        let cfg = (read_pmpcfg(i >> 2) >> ((i & 3) << 3)) as u8;
        if read_pmpaddr(i) == a && cfg == GUARD_CFG {
            took += 1;
        }
    }
    ARMED.store(took, Ordering::Relaxed);

    c.write_str("pmp ");
    write_small(c, took);
    c.write_str(" of ");
    write_small(c, wanted);
    c.write_str(" stack guards locked");
    took == wanted
}

/// Guards [`arm_guards`] has in place, for checks that need to know.
pub fn guards_armed() -> usize {
    ARMED.load(Ordering::Relaxed)
}

/// A count below 100, in decimal, without division: rv32i has no divide instruction and
/// a guard count never needs one.
fn write_small(c: &dyn EarlyConsole, v: usize) {
    if v >= 100 {
        c.write_str("many");
        return;
    }
    let mut tens = 0u8;
    let mut rest = v;
    while rest >= 10 {
        rest -= 10;
        tens += 1;
    }
    if tens > 0 {
        c.write_bytes(&[b'0' + tens]);
    }
    c.write_bytes(&[b'0' + rest as u8]);
}

// ---- Guard faults and the stack-guard test modes ----------------------------------------

/// What a faulting address says about the stacks.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Hit {
    Nothing,
    BootGuard,
    ThreadGuard(usize),
}

fn hit(addr: u64) -> Hit {
    let s = crate::image_sections();
    let (lo, hi) = s.stack_guard;
    if lo < hi && (lo..hi).contains(&addr) {
        return Hit::BootGuard;
    }
    match s.thread_stacks.guard_hit(addr) {
        Some(slot) => Hit::ThreadGuard(slot),
        None => Hit::Nothing,
    }
}

/// Which guard fault a test mode is waiting for, if any.
static EXPECTING: AtomicU8 = AtomicU8::new(EXPECT_NOTHING);

const EXPECT_NOTHING: u8 = 0;
const EXPECT_BOOT_GUARD: u8 = 1;
const EXPECT_THREAD_GUARD: u8 = 2;

/// Called by the trap handler after it has printed a fatal trap.
///
/// An access fault at an address inside a guard is reported as the stack it guards, since
/// "load access fault at some address" is a much less useful sentence. While a test mode
/// is waiting for a guard fault this is also the verdict: the run passes only on the
/// expected guard, and anything else fails at once instead of waiting for a timeout.
pub(crate) fn after_fault_report(c: &dyn EarlyConsole, access_fault: bool, addr: u64) {
    let h = if access_fault {
        hit(addr)
    } else {
        Hit::Nothing
    };
    match h {
        Hit::BootGuard => {
            c.write_str("stack guard: the address is in the PMP region below the boot stack\n")
        }
        Hit::ThreadGuard(slot) => {
            c.write_str("stack guard: the address is in the PMP region below thread stack ");
            write_small(c, slot);
            c.write_str("\n");
        }
        Hit::Nothing => {}
    }
    let want = EXPECTING.load(Ordering::Relaxed);
    if want == EXPECT_NOTHING {
        return;
    }
    let ok = match want {
        EXPECT_BOOT_GUARD => h == Hit::BootGuard,
        EXPECT_THREAD_GUARD => matches!(h, Hit::ThreadGuard(_)),
        _ => false,
    };
    c.write_str(if ok {
        "expected guard fault: observed\n"
    } else {
        "expected guard fault: this was not it\n"
    });
    conclude(ok)
}

/// Read the page below the boot stack.
///
/// With the guards armed this traps, and the trap handler ends the run through
/// [`after_fault_report`]. Returning means the region did not fault, which fails the run.
pub fn provoke_guard_fault() -> ! {
    EXPECTING.store(EXPECT_BOOT_GUARD, Ordering::Relaxed);
    match guard(0) {
        Some((lo, _)) => touch(lo),
        None => conclude(false),
    }
}

/// Read the guard below the first thread-stack slot. See [`provoke_guard_fault`].
pub fn provoke_thread_guard_fault() -> ! {
    EXPECTING.store(EXPECT_THREAD_GUARD, Ordering::Relaxed);
    match guard(1) {
        Some((lo, _)) => touch(lo),
        None => conclude(false),
    }
}

/// Load one byte from `addr`. A guard traps and does not return here.
#[inline(never)]
fn touch(addr: u64) -> ! {
    // SAFETY: a read of a guard region. With the guards armed it traps and never returns;
    // unarmed, it reads a byte of memory nothing uses.
    let byte = unsafe { core::ptr::read_volatile(addr as usize as *const u8) };
    core::hint::black_box(byte);
    conclude(false)
}

/// End a test mode's run through the emulator's result channel.
#[cfg(CONFIG_QEMU_EXIT)]
fn conclude(ok: bool) -> ! {
    crate::exit_emulator(ok)
}

/// Without a result channel there is nobody to report to, so stop.
#[cfg(not(CONFIG_QEMU_EXIT))]
fn conclude(_ok: bool) -> ! {
    <crate::Riscv32 as Arch>::halt()
}

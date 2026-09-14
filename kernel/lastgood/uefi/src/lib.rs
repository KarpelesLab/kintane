//! `lastgood` for the EFI stub: confirming a boot to the loader's counter.
//!
//! One of the units providing this name, alongside `kernel/lastgood/none`. The design is
//! `docs/bootloader.md#failure-handling`: the stub counts every boot in an EFI variable
//! before it hands over (`boot/uefi/src/counter.rs`), and starts safe mode once enough in a
//! row went unconfirmed. The kernel deletes the variable once its bring-up verdict is a
//! pass. So a kernel that fails before that point, however it fails, leaves the count
//! standing, and one that passes resets it.
//!
//! # Calling firmware after the kernel owns the page tables
//!
//! Runtime services outlive `ExitBootServices`, but the kernel's address space is not the
//! firmware's: runtime code lives in memory the kernel never maps, and nothing the kernel
//! maps outside its own text is executable. Rather than punch writable, executable holes
//! into that space, the stub builds a second one before it leaves boot services: page
//! tables identity-mapping the first 4 GiB as the firmware ran on them, and a stack, in
//! memory the kernel sees as reserved. A call loads that root, moves to that stack, calls,
//! and puts both back, so the kernel's own tables never hold a page that is both writable
//! and executable, and their W^X check has nothing new to exempt.
//!
//! `SetVirtualAddressMap` is never called, so the firmware runs at the physical addresses
//! it was built for, which is exactly what an identity map gives it. The stub passes no
//! call space when any runtime region lies above 4 GiB.
//!
//! # Once, and early
//!
//! Called once, on the boot CPU, before the scheduler starts. The firmware is not
//! reentrant, and an interrupt taken under its page tables would run a kernel handler on a
//! stack the kernel does not know, so the call masks interrupts itself as well.

#![no_std]

use boot_protocol::uefi::Runtime;
use boot_protocol::uefi::boot_counter::{ATTRIBUTES, NAME, VENDOR};
use cmdline::{Args, Mode};
use hal::EarlyConsole;

/// `EFI_GUID`, laid out as the firmware reads it.
#[repr(C)]
struct Guid(u32, u16, u16, [u8; 8]);

// Statics, not constants: the firmware is given their addresses, which must be of memory
// that outlives the call and lies inside the call space. The kernel image is both.
static COUNTER_NAME: [u16; NAME.len()] = NAME;
static COUNTER_VENDOR: Guid = Guid(VENDOR.0, VENDOR.1, VENDOR.2, VENDOR.3);

/// `EFI_SUCCESS`.
const SUCCESS: u64 = 0;
/// `EFI_NOT_FOUND`.
const NOT_FOUND: u64 = (1 << 63) | 14;
/// `EfiResetCold`.
const RESET_COLD: u64 = 0;
/// The call space identity-maps this much, so everything a call touches lies below it.
const CALL_SPACE_END: u64 = 1 << 32;

// The one way into firmware. Flags are saved and interrupts masked around the call; the
// loader's root is loaded and its stack taken, then the function is called with the
// Microsoft x64 convention that `efiapi` is on x86_64, and the stack and root are put back.
//
// System V in: rdi root, rsi stack top, rdx function, then rcx, r8, r9 and two stack slots
// for the five arguments. Microsoft out: rcx, rdx, r8, r9 and [rsp + 32], above the 32
// bytes of shadow space the callee may use. rbx and r12 carry what is restored, and both
// conventions preserve them.
core::arch::global_asm!(
    ".pushsection .text.kintane_firmware_call, \"ax\"",
    ".global kintane_firmware_call",
    "kintane_firmware_call:",
    "    push rbp",
    "    mov rbp, rsp",
    "    push rbx",
    "    push r12",
    "    pushfq",
    "    cli",
    "    mov rbx, cr3",
    "    mov r12, rsp",
    "    mov r10, [rbp + 16]",
    "    mov r11, [rbp + 24]",
    "    mov rax, rdx",
    "    mov cr3, rdi",
    "    mov rsp, rsi",
    "    and rsp, -16",
    "    sub rsp, 48",
    "    mov [rsp + 32], r11",
    "    mov rdx, r8",
    "    mov r8, r9",
    "    mov r9, r10",
    "    call rax",
    "    mov rsp, r12",
    "    mov cr3, rbx",
    "    popfq",
    "    pop r12",
    "    pop rbx",
    "    pop rbp",
    "    ret",
    ".popsection",
);

unsafe extern "C" {
    /// Call `function` with five arguments under the call space `root` and `stack_top`
    /// describe. See the assembly above.
    fn kintane_firmware_call(
        root: u64,
        stack_top: u64,
        function: u64,
        a1: u64,
        a2: u64,
        a3: u64,
        a4: u64,
        a5: u64,
    ) -> u64;
}

/// Settle this boot with the loader's counter, and return the verdict to act on.
///
/// A passing boot is confirmed: the count is deleted, then read back to prove it is gone,
/// since a confirmation the firmware silently dropped would put the machine into safe mode
/// a few boots later with nothing in any log to say why. A failing boot is left counted.
/// Either way the verdict also requires that the loader kept its side: a boot past
/// [`Runtime::failures_before_safe`] must have arrived in safe mode.
///
/// With `BOOT_COUNTER_TEST`, every boot the loader did not fall back on fails on purpose
/// and resets the machine through the firmware, and the one it did fall back on passes
/// only if it is the attempt the limit promises.
pub fn settle(c: &dyn EarlyConsole, boot_arg: u64, verdict: bool) -> bool {
    c.write_str("\n  last good  ");
    // SAFETY: `boot_arg` is what the boot code passed `kmain`, and the kernel's address
    // space keeps the boot information reachable, as `bootargs` relies on too.
    let Some(rt) = (unsafe { bootinfo::uefi_runtime(boot_arg) }) else {
        c.write_str("no counter passed, so there is nothing to confirm\n");
        return verdict && !kconfig::BOOT_COUNTER_TEST;
    };
    c.write_str("attempt ");
    write_dec(c, u64::from(rt.attempt));
    c.write_str(" since the last confirmed boot; safe mode after ");
    write_dec(c, u64::from(rt.failures_before_safe));
    c.write_str(" failures");

    let space_ok = rt.call_root != 0
        && rt.call_root & 0xFFF == 0
        && [
            rt.call_root,
            rt.call_stack_top,
            rt.get_variable,
            rt.set_variable,
            rt.reset_system,
        ]
        .iter()
        .all(|&at| at != 0 && at < CALL_SPACE_END);
    if !space_ok {
        c.write_str("\n  last good  FAILED: the call space the loader passed is malformed\n");
        return false;
    }

    let fell_back = rt.attempt > rt.failures_before_safe;
    let mode = boot_mode(boot_arg);
    if fell_back && mode != Some(Mode::Safe) {
        c.write_str("\n  last good  FAILED: past the limit, and not started in safe mode\n");
        return false;
    }

    if kconfig::BOOT_COUNTER_TEST && !fell_back {
        if mode != Some(Mode::Normal) {
            c.write_str("\n  last good  FAILED: not started in normal mode before the limit\n");
            return false;
        }
        c.write_str("\n  last good  failed on purpose (BOOT_COUNTER_TEST); resetting\n");
        // SAFETY: ResetSystem, one of the loader's entry points, asked for a cold reset
        // with no data; on the boot CPU, before the scheduler.
        let _ = unsafe { call(&rt, rt.reset_system, [RESET_COLD, 0, 0, 0, 0]) };
        c.write_str("  last good  FAILED: the firmware did not reset\n");
        return false;
    }

    if !verdict {
        c.write_str(", not confirmed: this boot failed, and stays counted\n");
        return false;
    }

    let name = COUNTER_NAME.as_ptr().expose_provenance() as u64;
    let vendor = core::ptr::addr_of!(COUNTER_VENDOR).expose_provenance() as u64;
    // SAFETY: SetVariable with a terminated name and a GUID in the kernel image, which the
    // call space maps, and no data, which deletes the variable.
    let s = unsafe { call(&rt, rt.set_variable, [name, vendor, u64::from(ATTRIBUTES), 0, 0]) };
    if s != SUCCESS && s != NOT_FOUND {
        c.write_str(", FAILED to clear: SetVariable returned ");
        write_hex(c, s);
        c.write_str("\n");
        return false;
    }
    let mut data = [0u8; 4];
    let mut size = data.len();
    let mut attributes = 0u32;
    // SAFETY: GetVariable into buffers on this stack, which lies in the kernel image and
    // so inside the call space; `size` is how many bytes `data` holds.
    let s = unsafe {
        call(
            &rt,
            rt.get_variable,
            [
                name,
                vendor,
                (&raw mut attributes).expose_provenance() as u64,
                (&raw mut size).expose_provenance() as u64,
                data.as_mut_ptr().expose_provenance() as u64,
            ],
        )
    };
    if s != NOT_FOUND {
        c.write_str(", FAILED: the count still reads back after clearing, status ");
        write_hex(c, s);
        c.write_str("\n");
        return false;
    }
    c.write_str(", confirmed: the count is cleared and reads back as gone");
    if kconfig::BOOT_COUNTER_TEST && rt.attempt != rt.failures_before_safe.saturating_add(1) {
        c.write_str("\n  last good  FAILED: safe mode came on the wrong attempt\n");
        return false;
    }
    c.write_str("\n");
    true
}

/// The mode this boot was started in, as its command line says.
fn boot_mode(boot_arg: u64) -> Option<Mode> {
    let mut line = [0u8; cmdline::MAX_LINE];
    // SAFETY: as in `settle`.
    let n = unsafe { bootinfo::command_line(boot_arg, &mut line) }.ok()??;
    Args::parse(line.get(..n)?).ok().map(|a| a.mode())
}

/// Call one of the firmware's runtime services in the loader's call space.
///
/// # Safety
/// `function` must be one of `rt`'s entry points, given the arguments the specification
/// defines for it, with every pointer among them into memory the call space maps. Only on
/// the boot CPU, before the scheduler starts: the firmware is not reentrant.
unsafe fn call(rt: &Runtime, function: u64, a: [u64; 5]) -> u64 {
    // SAFETY: the caller's guarantees; the root and stack are the loader's, checked by
    // `settle` to lie inside the 4 GiB the root maps.
    unsafe {
        kintane_firmware_call(
            rt.call_root,
            rt.call_stack_top,
            function,
            a[0],
            a[1],
            a[2],
            a[3],
            a[4],
        )
    }
}

fn write_dec(c: &dyn EarlyConsole, mut v: u64) {
    let mut buf = [0u8; 20];
    let mut at = buf.len();
    loop {
        at -= 1;
        buf[at] = b'0' + (v % 10) as u8;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    c.write_bytes(&buf[at..]);
}

fn write_hex(c: &dyn EarlyConsole, v: u64) {
    let mut buf = *b"0x0000000000000000";
    for (i, slot) in buf[2..].iter_mut().enumerate() {
        let nibble = (v >> (60 - 4 * i)) & 0xF;
        *slot = b"0123456789abcdef"[nibble as usize];
    }
    c.write_bytes(&buf);
}
